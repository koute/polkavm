use std::borrow::Cow;
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use core::marker::PhantomData;

use polkavm_common::abi::{
    GuestMemoryConfig, VM_MAXIMUM_EXPORT_COUNT, VM_MAXIMUM_EXTERN_ARG_COUNT, VM_MAXIMUM_IMPORT_COUNT, VM_MAXIMUM_INSTRUCTION_COUNT,
};
use polkavm_common::abi::{VM_ADDR_RETURN_TO_HOST, VM_ADDR_USER_STACK_HIGH};
use polkavm_common::error::Trap;
use polkavm_common::init::GuestProgramInit;
use polkavm_common::program::{ExternFnPrototype, ExternTy, ProgramBlob, ProgramExport, ProgramImport};
use polkavm_common::program::{FrameKind, Opcode, RawInstruction, Reg};
use polkavm_common::utils::{Access, AsUninitSliceMut, Gas};

use crate::caller::{Caller, CallerRaw};
use crate::config::{BackendKind, Config, GasMeteringKind, ModuleConfig, SandboxKind};
use crate::error::{bail, Error, ExecutionError};
use crate::interpreter::{InterpretedAccess, InterpretedInstance, InterpretedModule};
use crate::tracer::Tracer;

if_compiler_is_supported! {
    use crate::sandbox::Sandbox;
    use crate::sandbox::generic::Sandbox as SandboxGeneric;
    use crate::compiler::{CompiledInstance, CompiledModule};

    #[cfg(target_os = "linux")]
    use crate::sandbox::linux::Sandbox as SandboxLinux;
}

struct DisplayFn<'a, Args> {
    name: &'a str,
    args: Args,
    return_ty: Option<ExternTy>,
}

impl<'a, Args> core::fmt::Display for DisplayFn<'a, Args>
where
    Args: Clone + Iterator<Item = ExternTy>,
{
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
        fmt.write_str(self.name)?;
        fmt.write_str("(")?;
        for (index, ty) in self.args.clone().enumerate() {
            if index > 0 {
                fmt.write_str(", ")?;
            }
            ty.fmt(fmt)?;
        }
        fmt.write_str(")")?;
        if let Some(return_ty) = self.return_ty {
            fmt.write_str(" -> ")?;
            return_ty.fmt(fmt)?;
        }

        Ok(())
    }
}

pub(crate) type OnHostcall<'a> = &'a mut dyn for<'r> FnMut(u32, BackendAccess<'r>) -> Result<(), Trap>;

if_compiler_is_supported! {
    {
        use std::sync::atomic::{AtomicUsize, Ordering};

        pub(crate) trait SandboxExt: Sandbox {
            fn as_compiled_module(module: &Module) -> &CompiledModule<Self>;
            fn as_sandbox_vec(sandbox_vec: &SandboxVec) -> &Mutex<Vec<Self>>;
            fn reuse_or_spawn_sandbox(engine_state: &EngineState, module: &Module) -> Result<Self, Error> {
                use crate::sandbox::SandboxConfig;

                let mut sandbox_config = Self::Config::default();
                sandbox_config.enable_logger(cfg!(test) || module.is_debug_trace_execution_enabled());

                if let Some(sandbox) = engine_state.reuse_sandbox::<Self>() {
                    Ok(sandbox)
                } else {
                    Self::spawn(&sandbox_config)
                        .map_err(Error::from_display)
                        .map_err(|error| error.context("instantiation failed: failed to create a sandbox"))
                }
            }

            fn recycle_sandbox(engine_state: &EngineState, get_sandbox: impl FnOnce() -> Option<Self>) {
                let Some(sandbox_cache) = engine_state.sandbox_cache.as_ref() else { return };
                let sandboxes = Self::as_sandbox_vec(&sandbox_cache.sandboxes);

                let mut count = sandbox_cache.available_workers.load(Ordering::Relaxed);
                if count >= sandbox_cache.worker_limit {
                    return;
                }

                loop {
                    if let Err(new_count) = sandbox_cache.available_workers.compare_exchange(count, count + 1, Ordering::Relaxed, Ordering::Relaxed) {
                        if new_count >= sandbox_cache.worker_limit {
                            return;
                        }

                        count = new_count;
                        continue;
                    }

                    break;
                }

                if let Some(sandbox) = get_sandbox() {
                    let mut sandboxes = match sandboxes.lock() {
                        Ok(sandboxes) => sandboxes,
                        Err(poison) => poison.into_inner(),
                    };

                    sandboxes.push(sandbox);
                } else {
                    sandbox_cache.available_workers.fetch_sub(1, Ordering::Relaxed);
                }
            }
        }

        #[cfg(target_os = "linux")]
        impl SandboxExt for SandboxLinux {
            fn as_compiled_module(module: &Module) -> &CompiledModule<Self> {
                match module.0.compiled_module {
                    CompiledModuleKind::Linux(ref module) => module,
                    _ => unreachable!(),
                }
            }

            fn as_sandbox_vec(sandbox_vec: &SandboxVec) -> &Mutex<Vec<Self>> {
                match sandbox_vec {
                    SandboxVec::Linux(vec) => vec,
                    _ => unreachable!(),
                }
            }
        }

        impl SandboxExt for SandboxGeneric {
            fn as_compiled_module(module: &Module) -> &CompiledModule<Self> {
                match module.0.compiled_module {
                    CompiledModuleKind::Generic(ref module) => module,
                    _ => unreachable!(),
                }
            }

            fn as_sandbox_vec(sandbox_vec: &SandboxVec) -> &Mutex<Vec<Self>> {
                match sandbox_vec {
                    SandboxVec::Generic(vec) => vec,
                    #[cfg(target_os = "linux")]
                    SandboxVec::Linux(..) => unreachable!(),
                }
            }
        }

        pub(crate) enum SandboxVec {
            #[cfg(target_os = "linux")]
            Linux(Mutex<Vec<SandboxLinux>>),
            Generic(Mutex<Vec<SandboxGeneric>>),
        }

        struct SandboxCache {
            sandboxes: SandboxVec,
            available_workers: AtomicUsize,
            worker_limit: usize,
        }

        impl EngineState {
            fn reuse_sandbox<S>(&self) -> Option<S> where S: SandboxExt {
                let sandbox_cache = self.sandbox_cache.as_ref()?;
                if sandbox_cache.available_workers.load(Ordering::Relaxed) == 0 {
                    return None;
                }

                let sandboxes = S::as_sandbox_vec(&sandbox_cache.sandboxes);
                let mut sandboxes = match sandboxes.lock() {
                    Ok(sandboxes) => sandboxes,
                    Err(poison) => poison.into_inner(),
                };

                let mut sandbox = sandboxes.pop()?;
                sandbox_cache.available_workers.fetch_sub(1, Ordering::Relaxed);

                if let Err(error) = sandbox.sync() {
                    log::warn!("Failed to reuse a sandbox: {error}");
                    None
                } else {
                    Some(sandbox)
                }
            }
        }

        fn spawn_sandboxes<S>(count: usize, debug_trace_execution: bool) -> Result<Vec<S>, Error> where S: Sandbox {
            use crate::sandbox::SandboxConfig;

            let mut sandbox_config = S::Config::default();
            sandbox_config.enable_logger(cfg!(test) || debug_trace_execution);

            let mut sandboxes = Vec::with_capacity(count);
            for nth in 0..count {
                let sandbox = S::spawn(&sandbox_config)
                    .map_err(crate::Error::from_display)
                    .map_err(|error| error.context(format!("failed to create a worker process ({} out of {})", nth + 1, count)))?;

                sandboxes.push(sandbox);
            }

            Ok(sandboxes)
        }
    } else {
        struct SandboxCache;
    }
}

pub(crate) struct EngineState {
    #[allow(dead_code)]
    sandbox_cache: Option<SandboxCache>,
}

pub struct Engine {
    selected_backend: BackendKind,
    #[allow(dead_code)]
    selected_sandbox: Option<SandboxKind>,
    interpreter_enabled: bool,
    debug_trace_execution: bool,
    state: Arc<EngineState>,
}

impl Engine {
    pub fn new(config: &Config) -> Result<Self, Error> {
        if let Some(backend) = config.backend {
            if !backend.is_supported() {
                bail!("the '{backend}' backend is not supported on this platform")
            }
        }

        if !config.allow_insecure && config.trace_execution {
            bail!("cannot enable trace execution: `set_allow_insecure`/`POLKAVM_ALLOW_INSECURE` is not enabled");
        }

        let debug_trace_execution = config.trace_execution;
        let default_backend = if BackendKind::Compiler.is_supported() && SandboxKind::Linux.is_supported() {
            BackendKind::Compiler
        } else {
            BackendKind::Interpreter
        };

        let selected_backend = config.backend.unwrap_or(default_backend);
        log::debug!("Selected backend: '{selected_backend}'");

        let (selected_sandbox, sandbox_cache) = if_compiler_is_supported! {
            {
                if selected_backend == BackendKind::Compiler {
                    let default_sandbox = if SandboxKind::Linux.is_supported() {
                        SandboxKind::Linux
                    } else {
                        SandboxKind::Generic
                    };

                    let selected_sandbox = config.sandbox.unwrap_or(default_sandbox);
                    log::debug!("Selected sandbox: '{selected_sandbox}'");

                    if !selected_sandbox.is_supported() {
                        bail!("the '{selected_sandbox}' backend is not supported on this platform")
                    }

                    if selected_sandbox == SandboxKind::Generic && !config.allow_insecure {
                        bail!("cannot use the '{selected_sandbox}' sandbox: this sandbox is not secure yet, and `set_allow_insecure`/`POLKAVM_ALLOW_INSECURE` is not enabled");
                    }

                    let sandboxes = match selected_sandbox {
                        SandboxKind::Linux => {
                            #[cfg(target_os = "linux")]
                            {
                                SandboxVec::Linux(Mutex::new(spawn_sandboxes(config.worker_count, debug_trace_execution)?))
                            }

                            #[cfg(not(target_os = "linux"))]
                            {
                                unreachable!()
                            }
                        },
                        SandboxKind::Generic => SandboxVec::Generic(Mutex::new(spawn_sandboxes(config.worker_count, debug_trace_execution)?)),
                    };

                    let sandbox_cache = SandboxCache {
                        sandboxes,
                        available_workers: AtomicUsize::new(config.worker_count),
                        worker_limit: config.worker_count,
                    };

                    (Some(selected_sandbox), Some(sandbox_cache))
                } else {
                    Default::default()
                }
            } else {
                Default::default()
            }
        };

        Ok(Engine {
            selected_backend,
            selected_sandbox,
            interpreter_enabled: debug_trace_execution || selected_backend == BackendKind::Interpreter,
            debug_trace_execution,
            state: Arc::new(EngineState { sandbox_cache }),
        })
    }
}

if_compiler_is_supported! {
    {
        pub(crate) enum CompiledModuleKind {
            #[cfg(target_os = "linux")]
            Linux(CompiledModule<SandboxLinux>),
            Generic(CompiledModule<SandboxGeneric>),
            Unavailable,
        }
    } else {
        pub(crate) enum CompiledModuleKind {
            Unavailable,
        }
    }
}

impl CompiledModuleKind {
    pub fn is_some(&self) -> bool {
        !matches!(self, CompiledModuleKind::Unavailable)
    }
}

struct ModulePrivate {
    debug_trace_execution: bool,
    exports: Vec<ProgramExport<'static>>,
    imports: BTreeMap<u32, ProgramImport<'static>>,
    export_index_by_name: HashMap<String, usize>,
    instructions: Vec<RawInstruction>,

    instruction_by_basic_block: Vec<u32>,
    jump_table_index_by_basic_block: HashMap<u32, u32>,
    basic_block_by_jump_table_index: Vec<u32>,

    blob: Option<ProgramBlob<'static>>,
    compiled_module: CompiledModuleKind,
    interpreted_module: Option<InterpretedModule>,
    memory_config: GuestMemoryConfig,
    gas_metering: Option<GasMeteringKind>,
}

/// A compiled PolkaVM program module.
#[derive(Clone)]
pub struct Module(Arc<ModulePrivate>);

impl Module {
    pub(crate) fn is_debug_trace_execution_enabled(&self) -> bool {
        self.0.debug_trace_execution
    }

    pub(crate) fn instructions(&self) -> &[RawInstruction] {
        &self.0.instructions
    }

    pub(crate) fn compiled_module(&self) -> &CompiledModuleKind {
        &self.0.compiled_module
    }

    pub(crate) fn interpreted_module(&self) -> Option<&InterpretedModule> {
        self.0.interpreted_module.as_ref()
    }

    pub(crate) fn blob(&self) -> Option<&ProgramBlob<'static>> {
        self.0.blob.as_ref()
    }

    pub(crate) fn get_export(&self, export_index: usize) -> Option<&ProgramExport> {
        self.0.exports.get(export_index)
    }

    pub(crate) fn instruction_by_basic_block(&self, nth_basic_block: u32) -> Option<u32> {
        self.0.instruction_by_basic_block.get(nth_basic_block as usize).copied()
    }

    pub(crate) fn jump_table_index_by_basic_block(&self, nth_basic_block: u32) -> Option<u32> {
        self.0.jump_table_index_by_basic_block.get(&nth_basic_block).copied()
    }

    pub(crate) fn basic_block_by_jump_table_index(&self, jump_table_index: u32) -> Option<u32> {
        self.0.basic_block_by_jump_table_index.get(jump_table_index as usize).copied()
    }

    pub(crate) fn memory_config(&self) -> &GuestMemoryConfig {
        &self.0.memory_config
    }

    pub(crate) fn gas_metering(&self) -> Option<GasMeteringKind> {
        self.0.gas_metering
    }

    /// Creates a new module by deserializing the program from the given `bytes`.
    pub fn new(engine: &Engine, config: &ModuleConfig, bytes: impl AsRef<[u8]>) -> Result<Self, Error> {
        let blob = match ProgramBlob::parse(bytes.as_ref()) {
            Ok(blob) => blob,
            Err(error) => {
                bail!("failed to parse blob: {}", error);
            }
        };

        Self::from_blob(engine, config, &blob)
    }

    /// Creates a new module from a deserialized program `blob`.
    pub fn from_blob(engine: &Engine, config: &ModuleConfig, blob: &ProgramBlob) -> Result<Self, Error> {
        log::trace!("Parsing imports...");
        let mut imports = BTreeMap::new();
        for import in blob.imports() {
            let import = import.map_err(Error::from_display)?;
            if import.index() & (1 << 31) != 0 {
                bail!("out of range import index");
            }

            if imports.insert(import.index(), import).is_some() {
                bail!("duplicate import index");
            }

            if imports.len() > VM_MAXIMUM_IMPORT_COUNT as usize {
                bail!(
                    "too many imports; the program contains more than {} imports",
                    VM_MAXIMUM_IMPORT_COUNT
                );
            }
        }

        log::trace!("Parsing jump table...");
        let mut basic_block_by_jump_table_index = Vec::with_capacity(blob.jump_table_upper_bound() + 1);

        // The very first entry is always invalid.
        basic_block_by_jump_table_index.push(u32::MAX);

        let mut maximum_seen_jump_target = 0;
        for nth_basic_block in blob.jump_table() {
            let nth_basic_block = nth_basic_block.map_err(Error::from_display)?;
            maximum_seen_jump_target = core::cmp::max(maximum_seen_jump_target, nth_basic_block);
            basic_block_by_jump_table_index.push(nth_basic_block);
        }

        basic_block_by_jump_table_index.shrink_to_fit();

        let jump_table_index_by_basic_block: HashMap<_, _> = basic_block_by_jump_table_index
            .iter()
            .copied()
            .enumerate()
            .map(|(jump_table_index, nth_basic_block)| (nth_basic_block, jump_table_index as u32))
            .collect();

        let mut gas_cost_for_basic_block: Vec<u32> = Vec::new();
        let mut last_instruction = None;
        let mut jump_count = 0;

        log::trace!("Parsing code...");
        let (instructions, instruction_by_basic_block) = {
            let mut instruction_by_basic_block = Vec::with_capacity(blob.code().len() / 3);
            instruction_by_basic_block.push(0);
            if config.gas_metering.is_some() {
                gas_cost_for_basic_block.push(0);
            }

            let mut instructions = Vec::with_capacity(blob.code().len() / 3);
            for (nth_instruction, instruction) in blob.instructions().enumerate() {
                let nth_instruction = nth_instruction as u32;
                let instruction = instruction.map_err(Error::from_display)?;
                last_instruction = Some(instruction);

                if config.gas_metering.is_some() {
                    // TODO: Come up with a better cost model.
                    *gas_cost_for_basic_block.last_mut().unwrap() += 1;
                }

                match instruction.op() {
                    Opcode::fallthrough => {
                        instruction_by_basic_block.push(nth_instruction + 1);
                        if config.gas_metering.is_some() {
                            gas_cost_for_basic_block.push(0);
                        }
                    }
                    Opcode::jump_and_link_register => {
                        let ra = instruction.reg1();
                        if ra != Reg::Zero {
                            let return_basic_block = instruction_by_basic_block.len() as u32;
                            if !jump_table_index_by_basic_block.contains_key(&return_basic_block) {
                                bail!("found a call instruction where the next basic block is not part of the jump table");
                            }
                        }

                        let base = instruction.reg2();
                        if base == Reg::Zero {
                            maximum_seen_jump_target = core::cmp::max(maximum_seen_jump_target, instruction.raw_imm_or_reg3());
                        }

                        instruction_by_basic_block.push(nth_instruction + 1);
                        if config.gas_metering.is_some() {
                            gas_cost_for_basic_block.push(0);
                        }

                        jump_count += 1;
                    }
                    Opcode::trap => {
                        instruction_by_basic_block.push(nth_instruction + 1);
                        if config.gas_metering.is_some() {
                            gas_cost_for_basic_block.push(0);
                        }
                    }
                    Opcode::branch_less_unsigned
                    | Opcode::branch_less_signed
                    | Opcode::branch_greater_or_equal_unsigned
                    | Opcode::branch_greater_or_equal_signed
                    | Opcode::branch_eq
                    | Opcode::branch_not_eq => {
                        instruction_by_basic_block.push(nth_instruction + 1);
                        maximum_seen_jump_target = core::cmp::max(maximum_seen_jump_target, instruction.raw_imm_or_reg3());

                        if config.gas_metering.is_some() {
                            gas_cost_for_basic_block.push(0);
                        }

                        jump_count += 1;
                    }
                    Opcode::ecalli => {
                        let nr = instruction.raw_imm_or_reg3();
                        if imports.get(&nr).is_none() {
                            bail!("found an unrecognized ecall number: {nr:}");
                        }
                    }
                    _ => {}
                }
                instructions.push(instruction);
            }

            instruction_by_basic_block.shrink_to_fit();
            gas_cost_for_basic_block.shrink_to_fit();
            (instructions, instruction_by_basic_block)
        };

        let basic_block_count = instruction_by_basic_block.len();

        {
            let Some(last_instruction) = last_instruction else {
                bail!("the module contains no code");
            };

            match last_instruction.op() {
                Opcode::fallthrough
                | Opcode::jump_and_link_register
                | Opcode::trap
                | Opcode::branch_less_unsigned
                | Opcode::branch_less_signed
                | Opcode::branch_greater_or_equal_unsigned
                | Opcode::branch_greater_or_equal_signed
                | Opcode::branch_eq
                | Opcode::branch_not_eq => {}
                _ => {
                    bail!("code doesn't end with a control flow instruction")
                }
            }
        }

        if instructions.len() > VM_MAXIMUM_INSTRUCTION_COUNT as usize {
            bail!(
                "too many instructions; the program contains more than {} instructions",
                VM_MAXIMUM_INSTRUCTION_COUNT
            );
        }

        debug_assert!(!instruction_by_basic_block.is_empty());
        let maximum_valid_jump_target = (instruction_by_basic_block.len() - 1) as u32;
        if maximum_seen_jump_target > maximum_valid_jump_target {
            bail!("out of range jump found; found a jump to @{maximum_seen_jump_target:x}, while the very last valid jump target is @{maximum_valid_jump_target:x}");
        }

        log::trace!("Parsing exports...");
        let exports = {
            let mut exports = Vec::with_capacity(1);
            for export in blob.exports() {
                let export = export.map_err(Error::from_display)?;
                if export.address() > maximum_valid_jump_target {
                    bail!(
                        "out of range export found; export '{}' points to @{:x}, while the very last valid jump target is @{maximum_valid_jump_target:x}",
                        export.prototype().name(),
                        export.address()
                    );
                }

                exports.push(export);

                if exports.len() > VM_MAXIMUM_EXPORT_COUNT as usize {
                    bail!(
                        "too many exports; the program contains more than {} exports",
                        VM_MAXIMUM_EXPORT_COUNT
                    );
                }
            }
            exports
        };

        log::trace!("Parsing finished!");

        // Do an early check for memory config validity.
        GuestMemoryConfig::new(
            blob.ro_data().len() as u64,
            blob.rw_data().len() as u64,
            blob.bss_size() as u64,
            blob.stack_size() as u64,
        )
        .map_err(Error::from_static_str)?;

        let init = GuestProgramInit::new()
            .with_ro_data(blob.ro_data())
            .with_rw_data(blob.rw_data())
            .with_bss(blob.bss_size())
            .with_stack(blob.stack_size());

        let compiled_module = if_compiler_is_supported! {
            {
                match engine.selected_sandbox {
                    Some(SandboxKind::Linux) => {
                        #[cfg(target_os = "linux")]
                        {
                            let module = CompiledModule::new(
                                config,
                                &instructions,
                                &exports,
                                &basic_block_by_jump_table_index,
                                &jump_table_index_by_basic_block,
                                &gas_cost_for_basic_block,
                                init,
                                engine.debug_trace_execution,
                                jump_count,
                                basic_block_count,
                            )?;
                            CompiledModuleKind::Linux(module)
                        }

                        #[cfg(not(target_os = "linux"))]
                        {
                            log::debug!("Selected sandbox unavailable!");
                            CompiledModuleKind::Unavailable
                        }
                    },
                    Some(SandboxKind::Generic) => {
                        let module = CompiledModule::new(
                            config,
                            &instructions,
                            &exports,
                            &basic_block_by_jump_table_index,
                            &jump_table_index_by_basic_block,
                            &gas_cost_for_basic_block,
                            init,
                            engine.debug_trace_execution,
                            jump_count,
                            basic_block_count,
                        )?;
                        CompiledModuleKind::Generic(module)
                    }
                    None => CompiledModuleKind::Unavailable
                }
            } else {{
                let _ = jump_count;
                let _ = basic_block_count;
                CompiledModuleKind::Unavailable
            }}
        };

        let interpreted_module = if engine.interpreter_enabled {
            Some(InterpretedModule::new(init, gas_cost_for_basic_block)?)
        } else {
            None
        };

        assert!(compiled_module.is_some() || interpreted_module.is_some());

        if compiled_module.is_some() {
            log::debug!("Backend used: 'compiled'");
        } else {
            log::debug!("Backend used: 'interpreted'");
        }

        let export_index_by_name = exports
            .iter()
            .enumerate()
            .map(|(index, export)| (export.prototype().name().to_owned(), index))
            .collect();
        let exports = exports.into_iter().map(|export| export.into_owned()).collect();
        let imports = imports.into_iter().map(|(index, import)| (index, import.into_owned())).collect();

        let memory_config = init.memory_config().map_err(Error::from_static_str)?;
        log::debug!("Prepared new module:");
        log::debug!(
            "  Memory map: RO data: 0x{:08x}..0x{:08x}",
            memory_config.ro_data_range().start,
            memory_config.ro_data_range().end
        );
        log::debug!(
            "  Memory map:    Heap: 0x{:08x}..0x{:08x}",
            memory_config.heap_range().start,
            memory_config.heap_range().end
        );
        log::debug!(
            "  Memory map:   Stack: 0x{:08x}..0x{:08x}",
            memory_config.stack_range().start,
            memory_config.stack_range().end
        );

        Ok(Module(Arc::new(ModulePrivate {
            debug_trace_execution: engine.debug_trace_execution,
            instructions,
            exports,
            imports,
            export_index_by_name,

            instruction_by_basic_block,
            jump_table_index_by_basic_block,
            basic_block_by_jump_table_index,

            blob: if engine.debug_trace_execution || engine.selected_backend == BackendKind::Interpreter {
                Some(blob.clone().into_owned())
            } else {
                None
            },
            compiled_module,
            interpreted_module,
            memory_config,
            gas_metering: config.gas_metering,
        })))
    }

    /// The address at where the program's stack starts inside of the VM.
    pub fn stack_address_low(&self) -> u32 {
        self.0.memory_config.stack_address_low()
    }

    /// The address at where the program's stack ends inside of the VM.
    pub fn stack_address_high(&self) -> u32 {
        self.0.memory_config.stack_address_high()
    }

    /// The raw machine code of the compiled module.
    ///
    /// Will return `None` when running under an interpreter.
    /// Mostly only useful for debugging.
    pub fn machine_code(&self) -> Option<Cow<[u8]>> {
        if_compiler_is_supported! {
            {
                match self.0.compiled_module {
                    #[cfg(target_os = "linux")]
                    CompiledModuleKind::Linux(ref module) => Some(module.machine_code()),
                    CompiledModuleKind::Generic(ref module) => Some(module.machine_code()),
                    CompiledModuleKind::Unavailable => None,
                }
            } else {
                None
            }
        }
    }

    /// The address at which the raw machine code will be loaded.
    ///
    /// Will return `None` unless compiled for the Linux sandbox.
    /// Mostly only useful for debugging.
    pub fn machine_code_origin(&self) -> Option<u64> {
        if_compiler_is_supported! {
            {
                match self.0.compiled_module {
                    #[cfg(target_os = "linux")]
                    CompiledModuleKind::Linux(..) => Some(polkavm_common::zygote::VM_ADDR_NATIVE_CODE),
                    CompiledModuleKind::Generic(..) => None,
                    CompiledModuleKind::Unavailable => None,
                }
            } else {
                None
            }
        }
    }

    /// A map which makes it possible to map a position within the guest program
    /// into the exact range of native machine code instructions.
    ///
    /// The returned slice has as many elements as there were instructions in the
    /// original guest program, plus one extra to make it possible to figure out
    /// the length of the machine code corresponding to the very last instruction.
    ///
    /// This slice is guaranteed to be sorted, so you can binary search through it.
    ///
    /// Will return `None` when running under an interpreter.
    /// Mostly only useful for debugging.
    pub fn nth_instruction_to_code_offset_map(&self) -> Option<&[u32]> {
        if_compiler_is_supported! {
            {
                match self.0.compiled_module {
                    #[cfg(target_os = "linux")]
                    CompiledModuleKind::Linux(ref module) => Some(module.nth_instruction_to_code_offset_map()),
                    CompiledModuleKind::Generic(ref module) => Some(module.nth_instruction_to_code_offset_map()),
                    CompiledModuleKind::Unavailable => None,
                }
            } else {
                None
            }
        }
    }

    pub(crate) fn debug_print_location(&self, log_level: log::Level, pc: u32) {
        log::log!(log_level, "  At #{pc}:");

        let Some(blob) = self.blob() else {
            log::log!(log_level, "    (no location available)");
            return;
        };

        let Ok(Some(mut line_program)) = blob.get_debug_line_program_at(pc) else {
            log::log!(log_level, "    (no location available)");
            return;
        };

        for _ in 0..128 {
            // Have an upper bound on the number of iterations, just in case.
            let region_info = match line_program.run() {
                Ok(Some(region_info)) => region_info,
                Ok(None) | Err(..) => break,
            };

            if !region_info.instruction_range().contains(&pc) {
                continue;
            }

            for frame in region_info.frames() {
                let kind = match frame.kind() {
                    FrameKind::Enter => 'f',
                    FrameKind::Call => 'c',
                    FrameKind::Line => 'l',
                };

                if let Ok(full_name) = frame.full_name() {
                    if let Ok(Some(location)) = frame.location() {
                        log::log!(log_level, "    ({kind}) '{full_name}' [{location}]");
                    } else {
                        log::log!(log_level, "    ({kind}) '{full_name}'");
                    }
                }
            }
        }
    }
}

#[derive(Clone)]
pub enum ValType {
    I32,
    I64,
}

#[derive(Clone, Debug)]
pub enum Val {
    I32(i32),
    I64(i64),
}

impl core::fmt::Display for Val {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            Val::I32(value) => value.fmt(fmt),
            Val::I64(value) => value.fmt(fmt),
        }
    }
}

impl From<i32> for Val {
    fn from(value: i32) -> Val {
        Val::I32(value)
    }
}

impl From<u32> for Val {
    fn from(value: u32) -> Val {
        Val::I32(value as i32)
    }
}

impl ValType {
    fn extern_ty(&self) -> ExternTy {
        match self {
            ValType::I32 => ExternTy::I32,
            ValType::I64 => ExternTy::I64,
        }
    }
}

impl Val {
    fn extern_ty(&self) -> ExternTy {
        match self {
            Val::I32(_) => ExternTy::I32,
            Val::I64(_) => ExternTy::I64,
        }
    }

    pub fn i32(&self) -> Option<i32> {
        match self {
            Val::I32(value) => Some(*value),
            Val::I64(_) => None,
        }
    }

    pub fn u32(&self) -> Option<u32> {
        self.i32().map(|value| value as u32)
    }
}

impl From<ExternTy> for ValType {
    fn from(ty: ExternTy) -> Self {
        match ty {
            ExternTy::I32 => ValType::I32,
            ExternTy::I64 => ValType::I64,
        }
    }
}

pub struct FuncType {
    args: Vec<ExternTy>,
    return_ty: Option<ExternTy>,
}

impl FuncType {
    pub fn new(params: impl IntoIterator<Item = ValType>, return_ty: Option<ValType>) -> Self {
        FuncType {
            args: params.into_iter().map(|ty| ty.extern_ty()).collect(),
            return_ty: return_ty.map(|ty| ty.extern_ty()),
        }
    }

    pub fn params(&'_ self) -> impl ExactSizeIterator<Item = ValType> + '_ {
        self.args.iter().map(|&ty| ValType::from(ty))
    }

    pub fn return_ty(&self) -> Option<ValType> {
        self.return_ty.map(ValType::from)
    }
}

trait ExternFn<T>: Send + Sync {
    fn call(&self, user_data: &mut T, access: BackendAccess, raw: &mut CallerRaw) -> Result<(), Trap>;
    fn typecheck(&self, prototype: &ExternFnPrototype) -> Result<(), Error>;
}

#[repr(transparent)]
pub struct ExternFnArc<T>(Arc<dyn ExternFn<T>>);

impl<T> Clone for ExternFnArc<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

pub trait IntoExternFn<T, Params, Result>: Send + Sync + 'static {
    #[doc(hidden)]
    fn _into_extern_fn(self) -> ExternFnArc<T>;
}

/// A type which can be marshalled through the VM's FFI boundary.
pub trait AbiTy: Sized + Send + 'static {
    #[doc(hidden)]
    const _PRIVATE_EXTERN_TY: ExternTy;

    #[doc(hidden)]
    const _REGS_REQUIRED: usize;

    #[doc(hidden)]
    fn _get(get_reg: impl FnMut() -> u32) -> Self;

    #[doc(hidden)]
    fn _set(self, set_reg: impl FnMut(u32));
}

impl AbiTy for u32 {
    const _PRIVATE_EXTERN_TY: ExternTy = ExternTy::I32;
    const _REGS_REQUIRED: usize = 1;

    fn _get(mut get_reg: impl FnMut() -> u32) -> Self {
        get_reg()
    }

    fn _set(self, mut set_reg: impl FnMut(u32)) {
        set_reg(self)
    }
}

impl AbiTy for i32 {
    const _PRIVATE_EXTERN_TY: ExternTy = <u32 as AbiTy>::_PRIVATE_EXTERN_TY;
    const _REGS_REQUIRED: usize = <u32 as AbiTy>::_REGS_REQUIRED;

    fn _get(get_reg: impl FnMut() -> u32) -> Self {
        <u32 as AbiTy>::_get(get_reg) as i32
    }

    fn _set(self, set_reg: impl FnMut(u32)) {
        (self as u32)._set(set_reg)
    }
}

impl AbiTy for u64 {
    const _PRIVATE_EXTERN_TY: ExternTy = ExternTy::I64;
    const _REGS_REQUIRED: usize = 2;

    fn _get(mut get_reg: impl FnMut() -> u32) -> Self {
        let value_lo = get_reg();
        let value_hi = get_reg();
        (value_lo as u64) | ((value_hi as u64) << 32)
    }

    fn _set(self, mut set_reg: impl FnMut(u32)) {
        set_reg(self as u32);
        set_reg((self >> 32) as u32);
    }
}

impl AbiTy for i64 {
    const _PRIVATE_EXTERN_TY: ExternTy = <u64 as AbiTy>::_PRIVATE_EXTERN_TY;
    const _REGS_REQUIRED: usize = <u64 as AbiTy>::_REGS_REQUIRED;

    fn _get(get_reg: impl FnMut() -> u32) -> Self {
        <u64 as AbiTy>::_get(get_reg) as i64
    }

    fn _set(self, set_reg: impl FnMut(u32)) {
        (self as u64)._set(set_reg)
    }
}

// `AbiTy` is deliberately not implemented for `usize`.

/// A type which can be returned from a host function.
pub trait ReturnTy: Sized + Send + 'static {
    #[doc(hidden)]
    const _PRIVATE_EXTERN_TY: Option<ExternTy>;
    fn _handle_return(self, set_reg: impl FnMut(u32)) -> Result<(), Trap>;
}

impl<T> ReturnTy for T
where
    T: AbiTy,
{
    const _PRIVATE_EXTERN_TY: Option<ExternTy> = Some(T::_PRIVATE_EXTERN_TY);
    fn _handle_return(self, set_reg: impl FnMut(u32)) -> Result<(), Trap> {
        self._set(set_reg);
        Ok(())
    }
}

impl ReturnTy for () {
    const _PRIVATE_EXTERN_TY: Option<ExternTy> = None;
    fn _handle_return(self, _set_reg: impl FnMut(u32)) -> Result<(), Trap> {
        Ok(())
    }
}

impl ReturnTy for Result<(), Trap> {
    const _PRIVATE_EXTERN_TY: Option<ExternTy> = None;
    fn _handle_return(self, _set_reg: impl FnMut(u32)) -> Result<(), Trap> {
        self
    }
}

impl<T> ReturnTy for Result<T, Trap>
where
    T: AbiTy,
{
    const _PRIVATE_EXTERN_TY: Option<ExternTy> = Some(T::_PRIVATE_EXTERN_TY);
    fn _handle_return(self, set_reg: impl FnMut(u32)) -> Result<(), Trap> {
        self?._set(set_reg);
        Ok(())
    }
}

pub trait FuncArgs: Send {
    #[doc(hidden)]
    const _PRIVATE_EXTERN_TY: &'static [ExternTy];

    #[doc(hidden)]
    fn _set(self, set_reg: impl FnMut(u32));
}

pub trait FuncResult: Send {
    #[doc(hidden)]
    const _PRIVATE_EXTERN_TY: Option<ExternTy>;

    #[doc(hidden)]
    fn _get(get_reg: impl FnMut() -> u32) -> Self;
}

impl FuncResult for () {
    const _PRIVATE_EXTERN_TY: Option<ExternTy> = None;

    fn _get(_: impl FnMut() -> u32) -> Self {}
}

impl<T> FuncResult for T
where
    T: AbiTy,
{
    const _PRIVATE_EXTERN_TY: Option<ExternTy> = Some(<T as AbiTy>::_PRIVATE_EXTERN_TY);

    fn _get(get_reg: impl FnMut() -> u32) -> Self {
        <T as AbiTy>::_get(get_reg)
    }
}

macro_rules! impl_into_extern_fn {
    (@check_reg_count $regs_required:expr) => {
        if $regs_required > Reg::ARG_REGS.len() {
            // TODO: We should probably print out which exact function it is.
            log::error!("External call failed: too many registers required for arguments!");
            return Err(Trap::default());
        }
    };

    (@call $caller:expr, $callback:expr, ) => {{
        catch_hostcall_panic(|| ($callback)($caller))
    }};

    (@get_reg $caller:expr) => {{
        let mut reg_index = 0;
        let caller = &mut $caller;
        move || -> u32 {
            let value = caller.get_reg(Reg::ARG_REGS[reg_index]);
            reg_index += 1;
            value
        }
    }};

    (@call $caller:expr, $callback:expr, $a0:ident) => {{
        impl_into_extern_fn!(@check_reg_count $a0::_REGS_REQUIRED);

        let cb = impl_into_extern_fn!(@get_reg $caller);
        let a0 = $a0::_get(cb);
        catch_hostcall_panic(|| ($callback)($caller, a0))
    }};

    (@call $caller:expr, $callback:expr, $a0:ident, $a1:ident) => {{
        impl_into_extern_fn!(@check_reg_count $a0::_REGS_REQUIRED + $a1::_REGS_REQUIRED);

        let mut cb = impl_into_extern_fn!(@get_reg $caller);
        let a0 = $a0::_get(&mut cb);
        let a1 = $a1::_get(cb);
        catch_hostcall_panic(|| ($callback)($caller, a0, a1))
    }};

    (@call $caller:expr, $callback:expr, $a0:ident, $a1:ident, $a2:ident) => {{
        impl_into_extern_fn!(@check_reg_count $a0::_REGS_REQUIRED + $a1::_REGS_REQUIRED + $a2::_REGS_REQUIRED);

        let mut cb = impl_into_extern_fn!(@get_reg $caller);
        let a0 = $a0::_get(&mut cb);
        let a1 = $a1::_get(&mut cb);
        let a2 = $a2::_get(cb);
        catch_hostcall_panic(|| ($callback)($caller, a0, a1, a2))
    }};

    (@call $caller:expr, $callback:expr, $a0:ident, $a1:ident, $a2:ident, $a3:ident) => {{
        impl_into_extern_fn!(@check_reg_count $a0::_REGS_REQUIRED + $a1::_REGS_REQUIRED + $a2::_REGS_REQUIRED + $a3::_REGS_REQUIRED);

        let mut cb = impl_into_extern_fn!(@get_reg $caller);
        let a0 = $a0::_get(&mut cb);
        let a1 = $a1::_get(&mut cb);
        let a2 = $a2::_get(&mut cb);
        let a3 = $a3::_get(cb);
        catch_hostcall_panic(|| ($callback)($caller, a0, a1, a2, a3))
    }};

    (@call $caller:expr, $callback:expr, $a0:ident, $a1:ident, $a2:ident, $a3:ident, $a4:ident) => {{
        impl_into_extern_fn!(@check_reg_count $a0::_REGS_REQUIRED + $a1::_REGS_REQUIRED + $a2::_REGS_REQUIRED + $a3::_REGS_REQUIRED + $a4::_REGS_REQUIRED);

        let mut cb = impl_into_extern_fn!(@get_reg $caller);
        let a0 = $a0::_get(&mut cb);
        let a1 = $a1::_get(&mut cb);
        let a2 = $a2::_get(&mut cb);
        let a3 = $a3::_get(&mut cb);
        let a4 = $a4::_get(cb);
        catch_hostcall_panic(|| ($callback)($caller, a0, a1, a2, a3, a4))
    }};

    (@call $caller:expr, $callback:expr, $a0:ident, $a1:ident, $a2:ident, $a3:ident, $a4:ident, $a5:ident) => {{
        impl_into_extern_fn!(@check_reg_count $a0::_REGS_REQUIRED + $a1::_REGS_REQUIRED + $a2::_REGS_REQUIRED + $a3::_REGS_REQUIRED + $a4::_REGS_REQUIRED + $a5::_REGS_REQUIRED);

        let mut cb = impl_into_extern_fn!(@get_reg $caller);
        let a0 = $a0::_get(&mut cb);
        let a1 = $a1::_get(&mut cb);
        let a2 = $a2::_get(&mut cb);
        let a3 = $a3::_get(&mut cb);
        let a4 = $a4::_get(&mut cb);
        let a5 = $a5::_get(cb);
        catch_hostcall_panic(|| ($callback)($caller, a0, a1, a2, a3, a4, a5))
    }};

    ($arg_count:tt $($args:ident)*) => {
        impl<T, F, $($args,)* R> ExternFn<T> for (F, UnsafePhantomData<(R, $($args),*)>)
            where
            F: Fn(Caller<'_, T>, $($args),*) -> R + Send + Sync + 'static,
            $($args: AbiTy,)*
            R: ReturnTy,
        {
            fn call(&self, user_data: &mut T, mut access: BackendAccess, raw: &mut CallerRaw) -> Result<(), Trap> {
                #[allow(unused_mut)]
                let result = Caller::wrap(user_data, &mut access, raw, move |mut caller| {
                    impl_into_extern_fn!(@call caller, self.0, $($args),*)
                })?;

                let set_reg = {
                    let mut reg_index = 0;
                    move |value: u32| {
                        let reg = Reg::ARG_REGS[reg_index];
                        access.set_reg(reg, value);

                        if let Some(ref mut tracer) = raw.tracer() {
                            tracer.on_set_reg_in_hostcall(reg, value as u32);
                        }

                        reg_index += 1;
                    }
                };
                result._handle_return(set_reg)
            }

            fn typecheck(&self, prototype: &ExternFnPrototype) -> Result<(), Error> {
                let args: [ExternTy; $arg_count] = [$($args::_PRIVATE_EXTERN_TY,)*];
                if args.len() != prototype.args().len() || args.into_iter().zip(prototype.args()).any(|(lhs, rhs)| lhs != rhs) || R::_PRIVATE_EXTERN_TY != prototype.return_ty() {
                    bail!(
                        "failed to instantiate module: the module wanted to import function '{}', while the function that was registered was '{}'",
                        DisplayFn { name: prototype.name(), args: prototype.args(), return_ty: prototype.return_ty() },
                        DisplayFn { name: prototype.name(), args: args.into_iter(), return_ty: R::_PRIVATE_EXTERN_TY },
                    );
                }

                Ok(())
            }
        }

        impl<T, F, $($args,)* R> IntoExternFn<T, ($($args,)*), R> for F
        where
            F: Fn($($args),*) -> R + Send + Sync + 'static,
            $($args: AbiTy,)*
            R: ReturnTy,
        {
            fn _into_extern_fn(self) -> ExternFnArc<T> {
                #[allow(non_snake_case)]
                let callback = move |_caller: Caller<T>, $($args: $args),*| -> R {
                    self($($args),*)
                };
                ExternFnArc(Arc::new((callback, UnsafePhantomData(PhantomData::<(R, $($args),*)>))))
            }
        }

        impl<T, F, $($args,)* R> IntoExternFn<T, (Caller<'_, T>, $($args,)*), R> for F
        where
            F: Fn(Caller<'_, T>, $($args),*) -> R + Send + Sync + 'static,
            $($args: AbiTy,)*
            R: ReturnTy,
        {
            fn _into_extern_fn(self) -> ExternFnArc<T> {
                ExternFnArc(Arc::new((self, UnsafePhantomData(PhantomData::<(R, $($args),*)>))))
            }
        }

        impl<$($args: Send + AbiTy,)*> FuncArgs for ($($args,)*) {
            const _PRIVATE_EXTERN_TY: &'static [ExternTy] = &[
                $(<$args as AbiTy>::_PRIVATE_EXTERN_TY,)*
            ];

            #[allow(unused_mut)]
            #[allow(unused_variables)]
            #[allow(non_snake_case)]
            fn _set(self, mut set_reg: impl FnMut(u32)) {
                let ($($args,)*) = self;
                $($args._set(&mut set_reg);)*
            }
        }
    };
}

impl_into_extern_fn!(0);
impl_into_extern_fn!(1 A0);
impl_into_extern_fn!(2 A0 A1);
impl_into_extern_fn!(3 A0 A1 A2);
impl_into_extern_fn!(4 A0 A1 A2 A3);
impl_into_extern_fn!(5 A0 A1 A2 A3 A4);
impl_into_extern_fn!(6 A0 A1 A2 A3 A4 A5);

#[repr(transparent)]
struct UnsafePhantomData<T>(PhantomData<T>);

// SAFETY: This is only used to hold a type used exclusively at compile time, so regardless of whether it implements `Send` this will be safe.
unsafe impl<T> Send for UnsafePhantomData<T> {}

// SAFETY: This is only used to hold a type used exclusively at compile time, so regardless of whether it implements `Sync` this will be safe.
unsafe impl<T> Sync for UnsafePhantomData<T> {}

struct DynamicFn<T, F> {
    args: Vec<ExternTy>,
    return_ty: Option<ExternTy>,
    callback: F,
    _phantom: UnsafePhantomData<T>,
}

polkavm_common::static_assert!(Reg::ARG_REGS.len() == VM_MAXIMUM_EXTERN_ARG_COUNT);

fn catch_hostcall_panic<R>(callback: impl FnOnce() -> R) -> Result<R, Trap> {
    std::panic::catch_unwind(core::panic::AssertUnwindSafe(callback)).map_err(|panic| {
        if let Some(message) = panic.downcast_ref::<&str>() {
            log::error!("Hostcall panicked: {message}");
        } else if let Some(message) = panic.downcast_ref::<String>() {
            log::error!("Hostcall panicked: {message}");
        } else {
            log::error!("Hostcall panicked");
        }

        Trap::default()
    })
}

impl<T, F> ExternFn<T> for DynamicFn<T, F>
where
    F: Fn(Caller<'_, T>, &[Val], Option<&mut Val>) -> Result<(), Trap> + Send + Sync + 'static,
    T: 'static,
{
    fn call(&self, user_data: &mut T, mut access: BackendAccess, raw: &mut CallerRaw) -> Result<(), Trap> {
        const DEFAULT: Val = Val::I64(0);
        let mut args = [DEFAULT; VM_MAXIMUM_EXTERN_ARG_COUNT];
        let args = &mut args[..self.args.len()];

        let mut arg_regs = Reg::ARG_REGS.into_iter();
        for (&arg_ty, arg) in self.args.iter().zip(args.iter_mut()) {
            match arg_ty {
                ExternTy::I32 => {
                    let Some(reg) = arg_regs.next() else {
                        log::error!("dynamic host call called with too many arguments");
                        return Err(Trap::default());
                    };

                    *arg = Val::I32(access.get_reg(reg) as i32);
                }
                ExternTy::I64 => {
                    let Some(reg_1) = arg_regs.next() else {
                        log::error!("dynamic host call called with too many arguments");
                        return Err(Trap::default());
                    };

                    let Some(reg_2) = arg_regs.next() else {
                        log::error!("dynamic host call called with too many arguments");
                        return Err(Trap::default());
                    };

                    let lo = access.get_reg(reg_1);
                    let hi = access.get_reg(reg_2);
                    *arg = Val::I64((lo as u64 | ((hi as u64) << 32)) as i64);
                }
            }
        }

        let mut return_value = match self.return_ty.unwrap_or(ExternTy::I32) {
            ExternTy::I32 => Val::I32(0),
            ExternTy::I64 => Val::I64(0),
        };

        {
            let return_value = self.return_ty.map(|_| &mut return_value);
            Caller::wrap(user_data, &mut access, raw, move |caller| {
                catch_hostcall_panic(|| (self.callback)(caller, args, return_value))
            })??;
        }

        if let Some(return_ty) = self.return_ty {
            match return_value {
                Val::I32(value) => {
                    if return_ty != ExternTy::I32 {
                        // TODO: Print out the name of the hostcall.
                        log::error!(
                            "Hostcall return type mismatch: expected a hostcall to return '{}', but it returned 'i32'",
                            return_ty
                        );
                        return Err(Trap::default());
                    }

                    access.set_reg(Reg::A0, value as u32);
                    if let Some(tracer) = raw.tracer() {
                        tracer.on_set_reg_in_hostcall(Reg::A0, value as u32);
                    }
                }
                Val::I64(value) => {
                    if return_ty != ExternTy::I64 {
                        log::error!(
                            "Hostcall return type mismatch: expected a hostcall to return '{}', but it returned 'i64'",
                            return_ty
                        );
                        return Err(Trap::default());
                    }

                    let value = value as u64;
                    access.set_reg(Reg::A0, value as u32);
                    access.set_reg(Reg::A1, (value >> 32) as u32);

                    if let Some(tracer) = raw.tracer() {
                        tracer.on_set_reg_in_hostcall(Reg::A0, value as u32);
                        tracer.on_set_reg_in_hostcall(Reg::A1, (value >> 32) as u32);
                    }
                }
            }
        }

        Ok(())
    }

    fn typecheck(&self, prototype: &ExternFnPrototype) -> Result<(), Error> {
        if self.args.len() != prototype.args().len()
            || self.args.iter().zip(prototype.args()).any(|(lhs, rhs)| *lhs != rhs)
            || self.return_ty != prototype.return_ty()
        {
            bail!(
                "failed to instantiate module: the module wanted to import function '{}', while the function that was registered was '{}'",
                DisplayFn {
                    name: prototype.name(),
                    args: prototype.args(),
                    return_ty: prototype.return_ty()
                },
                DisplayFn {
                    name: prototype.name(),
                    args: self.args.iter().copied(),
                    return_ty: self.return_ty
                },
            );
        }

        Ok(())
    }
}

type FallbackHandlerArc<T> = Arc<dyn Fn(Caller<'_, T>, u32) -> Result<(), Trap> + Send + Sync + 'static>;

pub struct Linker<T> {
    engine_state: Arc<EngineState>,
    host_functions: HashMap<String, ExternFnArc<T>>,
    #[allow(clippy::type_complexity)]
    fallback_handler: Option<FallbackHandlerArc<T>>,
    phantom: PhantomData<T>,
}

impl<T> Linker<T> {
    pub fn new(engine: &Engine) -> Self {
        Self {
            engine_state: engine.state.clone(),
            host_functions: Default::default(),
            fallback_handler: None,
            phantom: PhantomData,
        }
    }

    /// Defines a fallback external call handler, in case no other registered functions match.
    pub fn func_fallback(&mut self, func: impl Fn(Caller<'_, T>, u32) -> Result<(), Trap> + Send + Sync + 'static) {
        self.fallback_handler = Some(Arc::new(func));
    }

    /// Defines a new dynamically typed handler for external calls with a given name.
    pub fn func_new(
        &mut self,
        name: &str,
        ty: FuncType,
        func: impl Fn(Caller<'_, T>, &[Val], Option<&mut Val>) -> Result<(), Trap> + Send + Sync + 'static,
    ) -> Result<&mut Self, Error>
    where
        T: 'static,
    {
        if self.host_functions.contains_key(name) {
            bail!("cannot register host function: host function was already registered: '{}'", name);
        }

        self.host_functions.insert(
            name.to_owned(),
            ExternFnArc(Arc::new(DynamicFn {
                args: ty.args,
                return_ty: ty.return_ty,
                callback: func,
                _phantom: UnsafePhantomData(PhantomData),
            })),
        );

        Ok(self)
    }

    /// Defines a new statically typed handler for external calls with a given name.
    pub fn func_wrap<Params, Args>(&mut self, name: &str, func: impl IntoExternFn<T, Params, Args>) -> Result<&mut Self, Error> {
        if self.host_functions.contains_key(name) {
            bail!("cannot register host function: host function was already registered: '{}'", name);
        }

        self.host_functions.insert(name.to_owned(), func._into_extern_fn());
        Ok(self)
    }

    /// Pre-instantiates a new module, linking it with the external functions previously defined on this object.
    pub fn instantiate_pre(&self, module: &Module) -> Result<InstancePre<T>, Error> {
        let mut host_functions: HashMap<u32, ExternFnArc<T>> = HashMap::new();
        host_functions.reserve(module.0.imports.len());

        for (index, import) in &module.0.imports {
            let prototype = import.prototype();
            let host_fn = match self.host_functions.get(prototype.name()) {
                Some(host_fn) => host_fn,
                None => {
                    if self.fallback_handler.is_some() {
                        continue;
                    }

                    bail!("failed to instantiate module: missing host function: '{}'", prototype.name());
                }
            };

            host_fn.0.typecheck(prototype)?;
            host_functions.insert(*index, host_fn.clone());
        }

        Ok(InstancePre(Arc::new(InstancePrePrivate {
            engine_state: self.engine_state.clone(),
            module: module.clone(),
            host_functions,
            fallback_handler: self.fallback_handler.clone(),
            _private: PhantomData,
        })))
    }
}

struct InstancePrePrivate<T> {
    #[allow(dead_code)]
    engine_state: Arc<EngineState>,
    module: Module,
    host_functions: HashMap<u32, ExternFnArc<T>>,
    fallback_handler: Option<FallbackHandlerArc<T>>,
    _private: PhantomData<T>,
}

pub struct InstancePre<T>(Arc<InstancePrePrivate<T>>);

impl<T> Clone for InstancePre<T> {
    fn clone(&self) -> Self {
        InstancePre(self.0.clone())
    }
}

impl<T> InstancePre<T> {
    /// Instantiates a new module.
    pub fn instantiate(&self) -> Result<Instance<T>, Error> {
        let compiled_module = &self.0.module.0.compiled_module;
        let backend = if_compiler_is_supported! {
            {
                match compiled_module {
                    #[cfg(target_os = "linux")]
                    CompiledModuleKind::Linux(..) => {
                        let compiled_instance = CompiledInstance::new(self.0.engine_state.clone(), self.0.module.clone())?;
                        Some(InstanceBackend::CompiledLinux(compiled_instance))
                    },
                    CompiledModuleKind::Generic(..) => {
                        let compiled_instance = CompiledInstance::new(self.0.engine_state.clone(), self.0.module.clone())?;
                        Some(InstanceBackend::CompiledGeneric(compiled_instance))
                    },
                    CompiledModuleKind::Unavailable => None
                }
            } else {
                match compiled_module {
                    CompiledModuleKind::Unavailable => None
                }
            }
        };

        let backend = match backend {
            Some(backend) => backend,
            None => {
                let interpreted_instance = InterpretedInstance::new(self.0.module.clone())?;
                InstanceBackend::Interpreted(interpreted_instance)
            }
        };

        let tracer = if self.0.module.0.debug_trace_execution {
            Some(Tracer::new(self.0.module.clone()))
        } else {
            None
        };

        Ok(Instance(Arc::new(InstancePrivate {
            instance_pre: self.clone(),
            mutable: Mutex::new(InstancePrivateMut {
                backend,
                raw: CallerRaw::new(tracer),
            }),
        })))
    }
}

if_compiler_is_supported! {
    {
        enum InstanceBackend {
            #[cfg(target_os = "linux")]
            CompiledLinux(CompiledInstance<SandboxLinux>),
            CompiledGeneric(CompiledInstance<SandboxGeneric>),
            Interpreted(InterpretedInstance),
        }
    } else {
        enum InstanceBackend {
            Interpreted(InterpretedInstance),
        }
    }
}

impl InstanceBackend {
    fn call(&mut self, export_index: usize, on_hostcall: OnHostcall, config: &ExecutionConfig) -> Result<(), ExecutionError> {
        if_compiler_is_supported! {
            {
                match self {
                    #[cfg(target_os = "linux")]
                    InstanceBackend::CompiledLinux(ref mut backend) => backend.call(export_index, on_hostcall, config),
                    InstanceBackend::CompiledGeneric(ref mut backend) => backend.call(export_index, on_hostcall, config),
                    InstanceBackend::Interpreted(ref mut backend) => backend.call(export_index, on_hostcall, config),
                }
            } else {
                match self {
                    InstanceBackend::Interpreted(ref mut backend) => backend.call(export_index, on_hostcall, config),
                }
            }
        }
    }

    fn access(&mut self) -> BackendAccess {
        if_compiler_is_supported! {
            {
                match self {
                    #[cfg(target_os = "linux")]
                    InstanceBackend::CompiledLinux(ref mut backend) => BackendAccess::CompiledLinux(backend.access()),
                    InstanceBackend::CompiledGeneric(ref mut backend) => BackendAccess::CompiledGeneric(backend.access()),
                    InstanceBackend::Interpreted(ref mut backend) => BackendAccess::Interpreted(backend.access()),
                }
            } else {
                match self {
                    InstanceBackend::Interpreted(ref mut backend) => BackendAccess::Interpreted(backend.access()),
                }
            }
        }
    }

    fn pid(&self) -> Option<u32> {
        if_compiler_is_supported! {
            {
                match self {
                    #[cfg(target_os = "linux")]
                    InstanceBackend::CompiledLinux(ref backend) => backend.sandbox().pid(),
                    InstanceBackend::CompiledGeneric(ref backend) => backend.sandbox().pid(),
                    InstanceBackend::Interpreted(..) => None,
                }
            } else {
                match self {
                    InstanceBackend::Interpreted(..) => None,
                }
            }
        }
    }
}

#[derive(Debug)]
pub struct MemoryAccessError<T> {
    pub address: u32,
    pub length: u64,
    pub error: T,
}

impl<T> core::fmt::Display for MemoryAccessError<T>
where
    T: core::fmt::Display,
{
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(
            fmt,
            "out of range memory access in 0x{:x}-0x{:x} ({} bytes): {}",
            self.address,
            (self.address as u64) + self.length,
            self.length,
            self.error
        )
    }
}

fn map_access_error<T>(error: MemoryAccessError<T>) -> Trap
where
    T: core::fmt::Display,
{
    log::warn!("{error}");
    Trap::default()
}

if_compiler_is_supported! {
    {
        pub(crate) enum BackendAccess<'a> {
            #[cfg(target_os = "linux")]
            CompiledLinux(<SandboxLinux as Sandbox>::Access<'a>),
            CompiledGeneric(<SandboxGeneric as Sandbox>::Access<'a>),
            Interpreted(InterpretedAccess<'a>),
        }
    } else {
        pub(crate) enum BackendAccess<'a> {
            Interpreted(InterpretedAccess<'a>),
        }
    }
}

if_compiler_is_supported! {
    {
        macro_rules! access_backend {
            ($itself:ident, |$access:ident| $e:expr) => {
                match $itself {
                    #[cfg(target_os = "linux")]
                    BackendAccess::CompiledLinux($access) => $e,
                    BackendAccess::CompiledGeneric($access) => $e,
                    BackendAccess::Interpreted($access) => $e,
                }
            }
        }
    } else {
        macro_rules! access_backend {
            ($itself:ident, |$access:ident| $e:expr) => {
                match $itself {
                    BackendAccess::Interpreted($access) => $e,
                }
            }
        }
    }
}

impl<'a> Access<'a> for BackendAccess<'a> {
    type Error = Trap;

    fn get_reg(&self, reg: Reg) -> u32 {
        access_backend!(self, |access| access.get_reg(reg))
    }

    fn set_reg(&mut self, reg: Reg, value: u32) {
        access_backend!(self, |access| access.set_reg(reg, value))
    }

    fn read_memory_into_slice<'slice, B>(&self, address: u32, buffer: &'slice mut B) -> Result<&'slice mut [u8], Self::Error>
    where
        B: ?Sized + AsUninitSliceMut,
    {
        access_backend!(self, |access| Ok(access
            .read_memory_into_slice(address, buffer)
            .map_err(map_access_error)?))
    }

    fn write_memory(&mut self, address: u32, data: &[u8]) -> Result<(), Self::Error> {
        access_backend!(self, |access| Ok(access.write_memory(address, data).map_err(map_access_error)?))
    }

    fn program_counter(&self) -> Option<u32> {
        access_backend!(self, |access| access.program_counter())
    }

    fn native_program_counter(&self) -> Option<u64> {
        access_backend!(self, |access| access.native_program_counter())
    }

    fn gas_remaining(&self) -> Option<Gas> {
        access_backend!(self, |access| access.gas_remaining())
    }
}

struct InstancePrivateMut {
    backend: InstanceBackend,
    raw: CallerRaw,
}

impl InstancePrivateMut {
    fn tracer(&mut self) -> Option<&mut Tracer> {
        self.raw.tracer()
    }
}

struct InstancePrivate<T> {
    instance_pre: InstancePre<T>,
    mutable: Mutex<InstancePrivateMut>,
}

pub struct Instance<T>(Arc<InstancePrivate<T>>);

impl<T> Clone for Instance<T> {
    fn clone(&self) -> Self {
        Instance(self.0.clone())
    }
}

impl<T> Instance<T> {
    /// Returns a handle to a function of a given name exported by the module.
    pub fn get_func(&self, name: &str) -> Option<Func<T>> {
        let export_index = *self.0.instance_pre.0.module.0.export_index_by_name.get(name)?;
        Some(Func {
            instance: self.clone(),
            export_index,
        })
    }

    /// Returns a handle to a function of a given name exported by the module.
    pub fn get_typed_func<FnArgs, FnResult>(&self, name: &str) -> Result<TypedFunc<T, FnArgs, FnResult>, Error>
    where
        FnArgs: FuncArgs,
        FnResult: FuncResult,
    {
        let Some(&export_index) = self.0.instance_pre.0.module.0.export_index_by_name.get(name) else {
            return Err(Error::from(format!(
                "failed to get function '{}': no such function is exported",
                name
            )));
        };

        let export = &self.0.instance_pre.0.module.0.exports[export_index];
        let prototype = export.prototype();

        let return_ty = FnResult::_PRIVATE_EXTERN_TY;
        let args = FnArgs::_PRIVATE_EXTERN_TY;

        if args.len() != prototype.args().len()
            || args.iter().copied().zip(prototype.args()).any(|(lhs, rhs)| lhs != rhs)
            || return_ty != prototype.return_ty()
        {
            let error = format!(
                "failed to get function: wanted to get function '{}', while the function that was exported was '{}'",
                DisplayFn {
                    name: prototype.name(),
                    args: args.iter().copied(),
                    return_ty
                },
                DisplayFn {
                    name: prototype.name(),
                    args: prototype.args(),
                    return_ty: prototype.return_ty()
                },
            );

            return Err(error.into());
        }

        Ok(TypedFunc {
            instance: self.clone(),
            export_index,
            _phantom: PhantomData,
        })
    }

    pub fn read_memory_into_slice<'slice, B>(&self, address: u32, buffer: &'slice mut B) -> Result<&'slice mut [u8], Trap>
    where
        B: ?Sized + AsUninitSliceMut,
    {
        let mut mutable = match self.0.mutable.lock() {
            Ok(mutable) => mutable,
            Err(poison) => poison.into_inner(),
        };

        mutable.backend.access().read_memory_into_slice(address, buffer)
    }

    pub fn read_memory_into_new_vec(&self, address: u32, length: u32) -> Result<Vec<u8>, Trap> {
        let mut mutable = match self.0.mutable.lock() {
            Ok(mutable) => mutable,
            Err(poison) => poison.into_inner(),
        };

        mutable.backend.access().read_memory_into_new_vec(address, length)
    }

    pub fn write_memory(&self, address: u32, data: &[u8]) -> Result<(), Trap> {
        let mut mutable = match self.0.mutable.lock() {
            Ok(mutable) => mutable,
            Err(poison) => poison.into_inner(),
        };

        mutable.backend.access().write_memory(address, data)
    }

    pub fn get_reg(&self, reg: Reg) -> u32 {
        let mut mutable = match self.0.mutable.lock() {
            Ok(mutable) => mutable,
            Err(poison) => poison.into_inner(),
        };

        mutable.backend.access().get_reg(reg)
    }

    /// Gets the amount of gas remaining, or `None` if gas metering is not enabled for this instance.
    ///
    /// Note that this being zero doesn't necessarily mean that the execution ran out of gas,
    /// if the program ended up consuming *exactly* the amount of gas that it was provided with!
    pub fn gas_remaining(&self) -> Option<Gas> {
        let mut mutable = match self.0.mutable.lock() {
            Ok(mutable) => mutable,
            Err(poison) => poison.into_inner(),
        };

        mutable.backend.access().gas_remaining()
    }

    /// Returns the PID of the sandbox corresponding to this instance.
    ///
    /// Will be `None` if the instance doesn't run in a separate process.
    /// Mostly only useful for debugging.
    pub fn pid(&self) -> Option<u32> {
        let mutable = match self.0.mutable.lock() {
            Ok(mutable) => mutable,
            Err(poison) => poison.into_inner(),
        };

        mutable.backend.pid()
    }
}

pub struct ExecutionConfig {
    pub(crate) reset_memory_after_execution: bool,
    pub(crate) clear_program_after_execution: bool,
    pub(crate) initial_regs: [u32; Reg::ALL_NON_ZERO.len()],
    pub(crate) gas: Option<Gas>,
}

impl Default for ExecutionConfig {
    fn default() -> Self {
        let mut initial_regs = [0; Reg::ALL_NON_ZERO.len()];
        initial_regs[Reg::SP as usize - 1] = VM_ADDR_USER_STACK_HIGH;
        initial_regs[Reg::RA as usize - 1] = VM_ADDR_RETURN_TO_HOST;

        ExecutionConfig {
            reset_memory_after_execution: false,
            clear_program_after_execution: false,
            initial_regs,
            gas: None,
        }
    }
}

impl ExecutionConfig {
    pub fn set_reset_memory_after_execution(&mut self, value: bool) -> &mut Self {
        self.reset_memory_after_execution = value;
        self
    }

    pub fn set_clear_program_after_execution(&mut self, value: bool) -> &mut Self {
        self.clear_program_after_execution = value;
        self
    }

    pub fn set_reg(&mut self, reg: Reg, value: u32) -> &mut Self {
        if !matches!(reg, Reg::Zero) {
            self.initial_regs[reg as usize - 1] = value;
        }

        self
    }

    pub fn set_gas(&mut self, gas: Gas) -> &mut Self {
        self.gas = Some(gas);
        self
    }
}

pub struct Func<T> {
    instance: Instance<T>,
    export_index: usize,
}

impl<T> Clone for Func<T> {
    fn clone(&self) -> Self {
        Self {
            instance: self.instance.clone(),
            export_index: self.export_index,
        }
    }
}

fn on_hostcall<'a, T>(
    user_data: &'a mut T,
    host_functions: &'a HashMap<u32, ExternFnArc<T>>,
    fallback_handler: Option<&'a FallbackHandlerArc<T>>,
    raw: &'a mut CallerRaw,
) -> impl for<'r> FnMut(u32, BackendAccess<'r>) -> Result<(), Trap> + 'a {
    move |hostcall: u32, mut access: BackendAccess| -> Result<(), Trap> {
        if hostcall & (1 << 31) != 0 {
            if hostcall == polkavm_common::HOSTCALL_TRACE {
                if let Some(tracer) = raw.tracer() {
                    return tracer.on_trace(&mut access);
                }

                log::error!("trace hostcall called but no tracer is set");
                return Err(Trap::default());
            }

            log::error!("unknown special hostcall triggered: {}", hostcall);
            return Err(Trap::default());
        }

        let host_fn = match host_functions.get(&hostcall) {
            Some(host_fn) => host_fn,
            None => {
                if let Some(fallback_handler) = fallback_handler {
                    return Caller::wrap(user_data, &mut access, raw, move |caller| fallback_handler(caller, hostcall));
                }

                // This should never happen.
                log::error!("hostcall to a function which doesn't exist: {}", hostcall);
                return Err(Trap::default());
            }
        };

        if let Err(trap) = host_fn.0.call(user_data, access, raw) {
            log::debug!("hostcall failed: {}", trap);
            return Err(trap);
        }

        Ok(())
    }
}

impl<T> Func<T> {
    /// Calls the function.
    pub fn call(&self, user_data: &mut T, args: &[Val]) -> Result<Option<Val>, ExecutionError> {
        self.call_ex(user_data, args, ExecutionConfig::default())
    }

    /// Calls the function with the given configuration.
    pub fn call_ex(&self, user_data: &mut T, args: &[Val], mut config: ExecutionConfig) -> Result<Option<Val>, ExecutionError> {
        let instance_pre = &self.instance.0.instance_pre;
        let export = &instance_pre.0.module.0.exports[self.export_index];
        let prototype = export.prototype();

        if args.len() != prototype.args().len()
            || args
                .iter()
                .map(|value| value.extern_ty())
                .zip(prototype.args())
                .any(|(lhs, rhs)| lhs != rhs)
        {
            let error = format!(
                "failed to call function: wanted to call function '{}', while the function that was exported was '{}'",
                DisplayFn {
                    name: prototype.name(),
                    args: args.iter().map(|value| value.extern_ty()),
                    return_ty: prototype.return_ty()
                },
                DisplayFn {
                    name: prototype.name(),
                    args: prototype.args(),
                    return_ty: prototype.return_ty()
                },
            );

            return Err(ExecutionError::Error(error.into()));
        }

        let mut input_count = 0;
        if prototype.args().len() > 0 {
            let required_count = args
                .iter()
                .map(|arg| match arg {
                    Val::I32(..) => i32::_REGS_REQUIRED,
                    Val::I64(..) => i64::_REGS_REQUIRED,
                })
                .sum::<usize>();

            if required_count > Reg::ARG_REGS.len() {
                return Err(ExecutionError::Error(
                    format!("failed to call function '{}': too many arguments", prototype.name()).into(),
                ));
            }

            let mut cb = |value: u32| {
                assert!(input_count <= VM_MAXIMUM_EXTERN_ARG_COUNT);
                config.initial_regs[Reg::A0 as usize + input_count - 1] = value;
                input_count += 1;
            };

            for arg in args {
                match arg {
                    Val::I32(value) => i32::_set(*value, &mut cb),
                    Val::I64(value) => i64::_set(*value, &mut cb),
                }
            }
        }

        let mutable = &self.instance.0.mutable;
        let mut mutable = match mutable.lock() {
            Ok(mutable) => mutable,
            Err(poison) => poison.into_inner(),
        };

        let mutable = &mut *mutable;
        if let Some(ref mut tracer) = mutable.tracer() {
            tracer.on_before_call(self.export_index, export, &config);
        }

        let mut on_hostcall = on_hostcall(
            user_data,
            &instance_pre.0.host_functions,
            instance_pre.0.fallback_handler.as_ref(),
            &mut mutable.raw,
        );

        let result = mutable.backend.call(self.export_index, &mut on_hostcall, &config);
        core::mem::drop(on_hostcall);

        if let Some(ref mut tracer) = mutable.tracer() {
            tracer.on_after_call();
        }

        match result {
            Ok(()) => {}
            Err(ExecutionError::Error(error)) => {
                return Err(ExecutionError::Error(
                    format!("failed to call function '{}': {}", export.prototype().name(), error).into(),
                ));
            }
            Err(ExecutionError::Trap(trap)) => {
                return Err(ExecutionError::Trap(trap));
            }
            Err(ExecutionError::OutOfGas) => {
                return Err(ExecutionError::OutOfGas);
            }
        }

        if let Some(return_ty) = prototype.return_ty() {
            let mut output_count = 0;
            let get = || {
                let value = mutable.backend.access().get_reg(Reg::ARG_REGS[output_count]);
                output_count += 1;
                value
            };

            match return_ty {
                ExternTy::I32 => {
                    let value = <i32 as AbiTy>::_get(get);
                    Ok(Some(Val::I32(value)))
                }
                ExternTy::I64 => {
                    let value = <i64 as AbiTy>::_get(get);
                    Ok(Some(Val::I64(value)))
                }
            }
        } else {
            Ok(None)
        }
    }
}

pub struct TypedFunc<T, FnArgs, FnResult> {
    instance: Instance<T>,
    export_index: usize,
    _phantom: PhantomData<(FnArgs, FnResult)>,
}

impl<T, FnArgs, FnResult> TypedFunc<T, FnArgs, FnResult>
where
    FnArgs: FuncArgs,
    FnResult: FuncResult,
{
    /// Calls the function.
    pub fn call(&self, user_data: &mut T, args: FnArgs) -> Result<FnResult, ExecutionError> {
        self.call_ex(user_data, args, ExecutionConfig::default())
    }

    /// Calls the function with the given configuration.
    pub fn call_ex(&self, user_data: &mut T, args: FnArgs, mut config: ExecutionConfig) -> Result<FnResult, ExecutionError> {
        let instance_pre = &self.instance.0.instance_pre;
        let export = &instance_pre.0.module.0.exports[self.export_index];

        let mut input_count = 0;
        args._set(|value| {
            assert!(input_count <= VM_MAXIMUM_EXTERN_ARG_COUNT);
            config.initial_regs[Reg::A0 as usize + input_count - 1] = value;
            input_count += 1;
        });

        let mutable = &self.instance.0.mutable;
        let mut mutable = match mutable.lock() {
            Ok(mutable) => mutable,
            Err(poison) => poison.into_inner(),
        };

        let mutable = &mut *mutable;
        if let Some(ref mut tracer) = mutable.tracer() {
            tracer.on_before_call(self.export_index, export, &config);
        }

        let mut on_hostcall = on_hostcall(
            user_data,
            &instance_pre.0.host_functions,
            instance_pre.0.fallback_handler.as_ref(),
            &mut mutable.raw,
        );

        let result = mutable.backend.call(self.export_index, &mut on_hostcall, &config);
        core::mem::drop(on_hostcall);

        if let Some(ref mut tracer) = mutable.tracer() {
            tracer.on_after_call();
        }

        match result {
            Ok(()) => {}
            Err(ExecutionError::Error(error)) => {
                return Err(ExecutionError::Error(
                    format!("failed to call function '{}': {}", export.prototype().name(), error).into(),
                ));
            }
            Err(ExecutionError::Trap(trap)) => {
                return Err(ExecutionError::Trap(trap));
            }
            Err(ExecutionError::OutOfGas) => {
                return Err(ExecutionError::OutOfGas);
            }
        }

        let mut output_count = 0;
        let result = FnResult::_get(|| {
            let access = mutable.backend.access();
            let value = access.get_reg(Reg::ARG_REGS[output_count]);
            output_count += 1;
            value
        });

        Ok(result)
    }
}
