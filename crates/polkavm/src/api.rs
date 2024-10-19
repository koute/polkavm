use alloc::boxed::Box;
use alloc::format;
use alloc::sync::Arc;
use alloc::vec::Vec;

use polkavm_common::abi::{MemoryMap, MemoryMapBuilder, VM_ADDR_RETURN_TO_HOST};
use polkavm_common::program::{
    build_static_dispatch_table, FrameKind, ISA32_V1_NoSbrk, Imports, InstructionSet, Instructions, JumpTable, Opcode, ProgramBlob, Reg,
    ISA32_V1, ISA64_V1,
};
use polkavm_common::utils::{ArcBytes, AsUninitSliceMut};

use crate::config::{BackendKind, Config, GasMeteringKind, ModuleConfig, SandboxKind};
use crate::error::{bail, bail_static, Error};
use crate::interpreter::{InterpretedInstance, InterpretedModule};
use crate::utils::{GuestInit, InterruptKind};
use crate::{Gas, ProgramCounter};

#[cfg(feature = "module-cache")]
use crate::module_cache::{ModuleCache, ModuleKey};

if_compiler_is_supported! {
    {
        use crate::sandbox::{Sandbox, SandboxInstance};
        use crate::compiler::{CompiledModule, CompilerCache};

        #[cfg(target_os = "linux")]
        use crate::sandbox::linux::Sandbox as SandboxLinux;
        #[cfg(feature = "generic-sandbox")]
        use crate::sandbox::generic::Sandbox as SandboxGeneric;

        pub(crate) struct EngineState {
            pub(crate) sandbox_global: Option<crate::sandbox::GlobalStateKind>,
            pub(crate) sandbox_cache: Option<crate::sandbox::WorkerCacheKind>,
            compiler_cache: CompilerCache,
            #[cfg(feature = "module-cache")]
            module_cache: ModuleCache,
        }
    } else {
        pub(crate) struct EngineState {
            #[cfg(feature = "module-cache")]
            module_cache: ModuleCache,
        }
    }
}

trait IntoResult<T> {
    fn into_result(self, message: &str) -> Result<T, Error>;
}

if_compiler_is_supported! {
    #[cfg(target_os = "linux")]
    impl<T> IntoResult<T> for Result<T, polkavm_linux_raw::Error> {
        fn into_result(self, message: &str) -> Result<T, Error> {
            self.map_err(|error| Error::from(error).context(message))
        }
    }
}

impl<T> IntoResult<T> for T {
    fn into_result(self, _message: &str) -> Result<T, Error> {
        Ok(self)
    }
}

pub type RegValue = u32;

#[derive(Copy, Clone)]
pub struct RuntimeInstructionSet {
    allow_sbrk: bool,
    is_64_bit: bool,
}

impl InstructionSet for RuntimeInstructionSet {
    fn opcode_from_u8(self, byte: u8) -> Option<Opcode> {
        if !self.is_64_bit {
            if self.allow_sbrk {
                ISA32_V1.opcode_from_u8(byte)
            } else {
                ISA32_V1_NoSbrk.opcode_from_u8(byte)
            }
        } else {
            ISA64_V1.opcode_from_u8(byte)
        }
    }
}

pub struct Engine {
    selected_backend: BackendKind,
    #[allow(dead_code)]
    selected_sandbox: Option<SandboxKind>,
    interpreter_enabled: bool,
    crosscheck: bool,
    state: Arc<EngineState>,
    allow_dynamic_paging: bool,
}

impl Engine {
    pub fn new(config: &Config) -> Result<Self, Error> {
        if_compiler_is_supported! {
            crate::sandbox::init_native_page_size();
        }

        if let Some(backend) = config.backend {
            if !backend.is_supported() {
                bail!("the '{backend}' backend is not supported on this platform")
            }
        }

        if !config.allow_experimental && config.crosscheck {
            bail!("cannot enable execution cross-checking: `set_allow_experimental`/`POLKAVM_ALLOW_EXPERIMENTAL` is not enabled");
        }

        let crosscheck = config.crosscheck;
        let default_backend = if BackendKind::Compiler.is_supported() && SandboxKind::Linux.is_supported() {
            BackendKind::Compiler
        } else {
            BackendKind::Interpreter
        };

        let selected_backend = config.backend.unwrap_or(default_backend);
        log::debug!("Selected backend: '{selected_backend}'");

        #[cfg(feature = "module-cache")]
        let module_cache = {
            log::debug!("Enabling module cache... (LRU cache size = {})", config.lru_cache_size);
            ModuleCache::new(config.cache_enabled, config.lru_cache_size)
        };

        #[cfg(not(feature = "module-cache"))]
        if config.cache_enabled {
            log::warn!("`cache_enabled` is true, but we were not compiled with the `module-cache` feature; caching will be disabled!");
        }

        let (selected_sandbox, state) = if_compiler_is_supported! {
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

                    if selected_sandbox == SandboxKind::Generic && !config.allow_experimental {
                        bail!("cannot use the '{selected_sandbox}' sandbox: this sandbox is not production ready and may be insecure; you can enabled `set_allow_experimental`/`POLKAVM_ALLOW_EXPERIMENTAL` to be able to use it anyway");
                    }

                    let sandbox_global = crate::sandbox::GlobalStateKind::new(selected_sandbox, config)?;
                    let sandbox_cache = crate::sandbox::WorkerCacheKind::new(selected_sandbox, config);
                    for _ in 0..config.worker_count {
                        sandbox_cache.spawn(&sandbox_global)?;
                    }

                    let state = Arc::new(EngineState {
                        sandbox_global: Some(sandbox_global),
                        sandbox_cache: Some(sandbox_cache),
                        compiler_cache: Default::default(),

                        #[cfg(feature = "module-cache")]
                        module_cache,
                    });

                    (Some(selected_sandbox), state)
                } else {
                    (None, Arc::new(EngineState {
                        sandbox_global: None,
                        sandbox_cache: None,
                        compiler_cache: Default::default(),

                        #[cfg(feature = "module-cache")]
                        module_cache
                    }))
                }
            } else {
                (None, Arc::new(EngineState {
                    #[cfg(feature = "module-cache")]
                    module_cache
                }))
            }
        };

        Ok(Engine {
            selected_backend,
            selected_sandbox,
            interpreter_enabled: crosscheck || selected_backend == BackendKind::Interpreter,
            crosscheck,
            state,
            allow_dynamic_paging: config.allow_dynamic_paging(),
        })
    }

    /// Returns the backend used by the engine.
    pub fn backend(&self) -> BackendKind {
        self.selected_backend
    }
}

if_compiler_is_supported! {
    {
        pub(crate) enum CompiledModuleKind {
            #[cfg(target_os = "linux")]
            Linux(CompiledModule<SandboxLinux>),
            #[cfg(feature = "generic-sandbox")]
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

pub(crate) struct ModulePrivate {
    engine_state: Option<Arc<EngineState>>,
    crosscheck: bool,

    blob: ProgramBlob,
    compiled_module: CompiledModuleKind,
    interpreted_module: Option<InterpretedModule>,
    memory_map: MemoryMap,
    gas_metering: Option<GasMeteringKind>,
    is_strict: bool,
    step_tracing: bool,
    dynamic_paging: bool,
    page_size_mask: u32,
    page_shift: u32,
    instruction_set: RuntimeInstructionSet,
    #[cfg(feature = "module-cache")]
    pub(crate) module_key: Option<ModuleKey>,
}

/// A compiled PolkaVM program module.
#[derive(Clone)]
pub struct Module(pub(crate) Option<Arc<ModulePrivate>>);

impl Drop for Module {
    fn drop(&mut self) {
        #[cfg(feature = "module-cache")]
        if let Some(state) = self.0.take() {
            if let Some(ref engine_state) = state.engine_state {
                let engine_state = Arc::clone(engine_state);
                engine_state.module_cache.on_drop(state);
            }
        }
    }
}

impl Module {
    fn state(&self) -> &ModulePrivate {
        if let Some(ref private) = self.0 {
            private
        } else {
            // SAFETY: self.0 is only ever `None` in the destructor.
            unsafe { core::hint::unreachable_unchecked() }
        }
    }

    pub(crate) fn is_strict(&self) -> bool {
        self.state().is_strict
    }

    pub(crate) fn is_step_tracing(&self) -> bool {
        self.state().step_tracing
    }

    pub(crate) fn is_dynamic_paging(&self) -> bool {
        self.state().dynamic_paging
    }

    pub(crate) fn compiled_module(&self) -> &CompiledModuleKind {
        &self.state().compiled_module
    }

    pub(crate) fn interpreted_module(&self) -> Option<&InterpretedModule> {
        self.state().interpreted_module.as_ref()
    }

    pub(crate) fn blob(&self) -> &ProgramBlob {
        &self.state().blob
    }

    pub(crate) fn code_len(&self) -> u32 {
        self.state().blob.code().len() as u32
    }

    pub(crate) fn instructions_bounded_at(&self, offset: ProgramCounter) -> Instructions<RuntimeInstructionSet> {
        self.state().blob.instructions_bounded_at(self.state().instruction_set, offset)
    }

    pub(crate) fn is_jump_target_valid(&self, offset: ProgramCounter) -> bool {
        self.state().blob.is_jump_target_valid(self.state().instruction_set, offset)
    }

    pub(crate) fn find_start_of_basic_block(&self, offset: ProgramCounter) -> Option<ProgramCounter> {
        polkavm_common::program::find_start_of_basic_block(
            self.state().instruction_set,
            self.state().blob.code(),
            self.state().blob.bitmask(),
            offset.0,
        )
        .map(ProgramCounter)
    }

    pub(crate) fn jump_table(&self) -> JumpTable {
        self.state().blob.jump_table()
    }

    pub fn get_debug_string(&self, offset: u32) -> Result<&str, polkavm_common::program::ProgramParseError> {
        self.state().blob.get_debug_string(offset)
    }

    pub(crate) fn gas_metering(&self) -> Option<GasMeteringKind> {
        self.state().gas_metering
    }

    pub(crate) fn is_multiple_of_page_size(&self, value: u32) -> bool {
        (value & self.state().page_size_mask) == 0
    }

    pub(crate) fn round_to_page_size_down(&self, value: u32) -> u32 {
        value & !self.state().page_size_mask
    }

    pub(crate) fn address_to_page(&self, address: u32) -> u32 {
        address >> self.state().page_shift
    }

    /// Creates a new module by deserializing the program from the given `bytes`.
    pub fn new(engine: &Engine, config: &ModuleConfig, bytes: ArcBytes) -> Result<Self, Error> {
        let blob = match ProgramBlob::parse(bytes) {
            Ok(blob) => blob,
            Err(error) => {
                bail!("failed to parse blob: {}", error);
            }
        };

        Self::from_blob(engine, config, blob)
    }

    /// Creates a new module from a deserialized program `blob`.
    pub fn from_blob(engine: &Engine, config: &ModuleConfig, blob: ProgramBlob) -> Result<Self, Error> {
        if config.dynamic_paging() && !engine.allow_dynamic_paging {
            bail!("dynamic paging was not enabled; use `Config::set_allow_dynamic_paging` to enable it");
        }

        #[cfg(feature = "module-cache")]
        let module_key = {
            let (module_key, module) = engine.state.module_cache.get(config, &blob);
            if let Some(module) = module {
                return Ok(module);
            }
            module_key
        };

        // Do an early check for memory config validity.
        MemoryMapBuilder::new(config.page_size)
            .ro_data_size(blob.ro_data_size())
            .rw_data_size(blob.rw_data_size())
            .stack_size(blob.stack_size())
            .build()
            .map_err(Error::from_static_str)?;

        if config.is_strict || cfg!(debug_assertions) {
            log::trace!("Checking imports...");
            for (nth_import, import) in blob.imports().into_iter().enumerate() {
                if let Some(ref import) = import {
                    log::trace!("  Import #{}: {}", nth_import, import);
                } else {
                    log::trace!("  Import #{}: INVALID", nth_import);
                    if config.is_strict {
                        bail_static!("found an invalid import");
                    }
                }
            }

            log::trace!("Checking jump table...");
            for (nth_entry, code_offset) in blob.jump_table().iter().enumerate() {
                if code_offset.0 as usize >= blob.code().len() {
                    log::trace!(
                        "  Invalid jump table entry #{nth_entry}: {code_offset} (should be less than {})",
                        blob.code().len()
                    );
                    if config.is_strict {
                        bail_static!("out of range jump table entry found");
                    }
                }
            }
        };

        let exports = {
            log::trace!("Parsing exports...");
            let mut exports = Vec::with_capacity(1);
            for export in blob.exports() {
                log::trace!("  Export at {}: {}", export.program_counter(), export.symbol());
                if config.is_strict && export.program_counter().0 as usize >= blob.code().len() {
                    bail!(
                        "out of range export found; export {} points to code offset {}, while the code blob is only {} bytes",
                        export.symbol(),
                        export.program_counter(),
                        blob.code().len(),
                    );
                }

                exports.push(export);
            }
            exports
        };

        let init = GuestInit {
            page_size: config.page_size,
            ro_data: blob.ro_data(),
            rw_data: blob.rw_data(),
            ro_data_size: blob.ro_data_size(),
            rw_data_size: blob.rw_data_size(),
            stack_size: blob.stack_size(),
            aux_data_size: config.aux_data_size(),
        };

        let instruction_set = RuntimeInstructionSet {
            allow_sbrk: config.allow_sbrk,
            is_64_bit: blob.is_64_bit(),
        };

        #[allow(unused_macros)]
        macro_rules! compile_module {
            ($sandbox_kind:ident, $visitor_name:ident, $module_kind:ident) => {{
                type VisitorTy<'a> = crate::compiler::CompilerVisitor<'a, $sandbox_kind>;
                let (mut visitor, aux) = crate::compiler::CompilerVisitor::<$sandbox_kind>::new(
                    &engine.state.compiler_cache,
                    config,
                    instruction_set,
                    blob.jump_table(),
                    blob.code(),
                    blob.bitmask(),
                    &exports,
                    config.step_tracing || engine.crosscheck,
                    blob.code().len() as u32,
                    init,
                )?;

                if config.allow_sbrk {
                    blob.visit(
                        build_static_dispatch_table!($visitor_name, ISA32_V1, VisitorTy<'a>),
                        &mut visitor,
                    );
                } else {
                    blob.visit(
                        build_static_dispatch_table!($visitor_name, ISA32_V1_NoSbrk, VisitorTy<'a>),
                        &mut visitor,
                    );
                }

                let global = $sandbox_kind::downcast_global_state(engine.state.sandbox_global.as_ref().unwrap());
                let module = visitor.finish_compilation(global, &engine.state.compiler_cache, aux)?;
                Some(CompiledModuleKind::$module_kind(module))
            }};
        }

        let compiled_module: Option<CompiledModuleKind> = if_compiler_is_supported! {
            {
                if engine.selected_backend == BackendKind::Compiler {
                    if let Some(selected_sandbox) = engine.selected_sandbox {
                        match selected_sandbox {
                            SandboxKind::Linux => {
                                #[cfg(target_os = "linux")]
                                {
                                    compile_module!(SandboxLinux, COMPILER_VISITOR_LINUX, Linux)
                                }

                                #[cfg(not(target_os = "linux"))]
                                {
                                    log::debug!("Selecetd sandbox unavailable: 'linux'");
                                    None
                                }
                            },
                            SandboxKind::Generic => {
                                #[cfg(feature = "generic-sandbox")]
                                {
                                    compile_module!(SandboxGeneric, COMPILER_VISITOR_GENERIC, Generic)
                                }

                                #[cfg(not(feature = "generic-sandbox"))]
                                {
                                    log::debug!("Selected sandbox unavailable: 'generic'");
                                    None
                                }
                            },
                        }
                    } else {
                        None
                    }
                } else {
                    None
                }
            } else {{
                None
            }}
        };

        let interpreted_module = if engine.interpreter_enabled {
            Some(InterpretedModule::new(init)?)
        } else {
            None
        };

        let compiled_module = compiled_module.unwrap_or(CompiledModuleKind::Unavailable);
        log::trace!("Processing finished!");

        assert!(compiled_module.is_some() || interpreted_module.is_some());
        if compiled_module.is_some() {
            log::debug!("Backend used: 'compiled'");
        } else {
            log::debug!("Backend used: 'interpreted'");
        }

        let memory_map = init.memory_map().map_err(Error::from_static_str)?;
        log::debug!(
            "  Memory map: RO data: 0x{:08x}..0x{:08x} ({}/{} bytes, non-zero until 0x{:08x})",
            memory_map.ro_data_range().start,
            memory_map.ro_data_range().end,
            blob.ro_data().len(),
            memory_map.ro_data_range().len(),
            memory_map.ro_data_range().start as usize + blob.ro_data().len(),
        );
        log::debug!(
            "  Memory map: RW data: 0x{:08x}..0x{:08x} ({}/{} bytes, non-zero until 0x{:08x})",
            memory_map.rw_data_range().start,
            memory_map.rw_data_range().end,
            blob.rw_data().len(),
            memory_map.rw_data_range().len(),
            memory_map.rw_data_range().start as usize + blob.rw_data().len(),
        );
        log::debug!(
            "  Memory map:   Stack: 0x{:08x}..0x{:08x} ({}/{} bytes)",
            memory_map.stack_range().start,
            memory_map.stack_range().end,
            blob.stack_size(),
            memory_map.stack_range().len(),
        );
        log::debug!(
            "  Memory map:     Aux: 0x{:08x}..0x{:08x} ({}/{} bytes requested)",
            memory_map.aux_data_range().start,
            memory_map.aux_data_range().end,
            config.aux_data_size(),
            memory_map.aux_data_range().len(),
        );

        let page_shift = memory_map.page_size().ilog2();
        let page_size_mask = (1 << page_shift) - 1;

        let module = Arc::new(ModulePrivate {
            engine_state: Some(Arc::clone(&engine.state)),

            blob,
            compiled_module,
            interpreted_module,
            memory_map,
            gas_metering: config.gas_metering,
            is_strict: config.is_strict,
            step_tracing: config.step_tracing,
            dynamic_paging: config.dynamic_paging,
            instruction_set,
            crosscheck: engine.crosscheck,
            page_size_mask,
            page_shift,

            #[cfg(feature = "module-cache")]
            module_key,
        });

        #[cfg(feature = "module-cache")]
        if let Some(module_key) = module_key {
            return Ok(engine.state.module_cache.insert(module_key, module));
        }

        Ok(Module(Some(module)))
    }

    /// Fetches a cached module for the given `blob`.
    #[cfg_attr(not(feature = "module-cache"), allow(unused_variables))]
    pub fn from_cache(engine: &Engine, config: &ModuleConfig, blob: &ProgramBlob) -> Option<Self> {
        #[cfg(feature = "module-cache")]
        {
            let (_, module) = engine.state.module_cache.get(config, blob);
            module
        }

        #[cfg(not(feature = "module-cache"))]
        None
    }

    /// Instantiates a new module.
    pub fn instantiate(&self) -> Result<RawInstance, Error> {
        let compiled_module = &self.state().compiled_module;
        let backend = if_compiler_is_supported! {
            {{
                let Some(engine_state) = self.state().engine_state.as_ref() else {
                    return Err(Error::from_static_str("failed to instantiate module: empty module"));
                };

                match compiled_module {
                    #[cfg(target_os = "linux")]
                    CompiledModuleKind::Linux(..) => {
                        let compiled_instance = SandboxInstance::<SandboxLinux>::spawn_and_load_module(Arc::clone(engine_state), self)?;
                        Some(InstanceBackend::CompiledLinux(compiled_instance))
                    },
                    #[cfg(feature = "generic-sandbox")]
                    CompiledModuleKind::Generic(..) => {
                        let compiled_instance = SandboxInstance::<SandboxGeneric>::spawn_and_load_module(Arc::clone(engine_state), self)?;
                        Some(InstanceBackend::CompiledGeneric(compiled_instance))
                    },
                    CompiledModuleKind::Unavailable => None
                }
            }} else {
                match compiled_module {
                    CompiledModuleKind::Unavailable => None
                }
            }
        };

        let backend = match backend {
            Some(backend) => backend,
            None => InstanceBackend::Interpreted(InterpretedInstance::new_from_module(self.clone(), false)),
        };

        let crosscheck_instance = if self.state().crosscheck && !matches!(backend, InstanceBackend::Interpreted(..)) {
            Some(Box::new(InterpretedInstance::new_from_module(self.clone(), true)))
        } else {
            None
        };

        Ok(RawInstance {
            module: self.clone(),
            backend,
            crosscheck_instance,
        })
    }

    /// The program's memory map.
    pub fn memory_map(&self) -> &MemoryMap {
        &self.state().memory_map
    }

    /// The default stack pointer for the module.
    pub fn default_sp(&self) -> RegValue {
        self.memory_map().stack_address_high()
    }

    /// Returns the module's exports.
    pub fn exports(&self) -> impl Iterator<Item = crate::program::ProgramExport<&[u8]>> + Clone {
        self.state().blob.exports()
    }

    /// Returns the module's imports.
    pub fn imports(&self) -> Imports {
        self.state().blob.imports()
    }

    /// The raw machine code of the compiled module.
    ///
    /// Will return `None` when running under an interpreter.
    /// Mostly only useful for debugging.
    pub fn machine_code(&self) -> Option<&[u8]> {
        if_compiler_is_supported! {
            {
                match self.state().compiled_module {
                    #[cfg(target_os = "linux")]
                    CompiledModuleKind::Linux(ref module) => Some(module.machine_code()),
                    #[cfg(feature = "generic-sandbox")]
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
                match self.state().compiled_module {
                    #[cfg(target_os = "linux")]
                    CompiledModuleKind::Linux(..) => Some(polkavm_common::zygote::VM_ADDR_NATIVE_CODE),
                    #[cfg(feature = "generic-sandbox")]
                    CompiledModuleKind::Generic(..) => None,
                    CompiledModuleKind::Unavailable => None,
                }
            } else {
                None
            }
        }
    }

    /// A slice which contains pairs of PolkaVM bytecode offsets and native machine code offsets.
    ///
    /// This makes it possible to map a position within the guest program into the
    /// exact range of native machine code instructions.
    ///
    /// The returned slice has as many elements as there were instructions in the
    /// original guest program, plus one extra to make it possible to figure out
    /// the length of the machine code corresponding to the very last instruction.
    ///
    /// This slice is guaranteed to be sorted, so you can binary search through it.
    ///
    /// Will return `None` when running under an interpreter.
    /// Mostly only useful for debugging.
    pub fn program_counter_to_machine_code_offset(&self) -> Option<&[(ProgramCounter, u32)]> {
        if_compiler_is_supported! {
            {
                match self.state().compiled_module {
                    #[cfg(target_os = "linux")]
                    CompiledModuleKind::Linux(ref module) => Some(module.program_counter_to_machine_code_offset()),
                    #[cfg(feature = "generic-sandbox")]
                    CompiledModuleKind::Generic(ref module) => Some(module.program_counter_to_machine_code_offset()),
                    CompiledModuleKind::Unavailable => None,
                }
            } else {
                None
            }
        }
    }

    /// Calculates the gas cost for a given basic block starting at `code_offset`.
    ///
    /// Will return `None` if the given `code_offset` is invalid.
    /// Mostly only useful for debugging.
    pub fn calculate_gas_cost_for(&self, code_offset: ProgramCounter) -> Option<Gas> {
        if !self.is_jump_target_valid(code_offset) {
            return None;
        }

        let gas = crate::gas::calculate_for_block(self.instructions_bounded_at(code_offset));
        Some(i64::from(gas.0))
    }

    pub(crate) fn debug_print_location(&self, log_level: log::Level, pc: ProgramCounter) {
        log::log!(log_level, "  At #{pc}:");

        let Ok(Some(mut line_program)) = self.state().blob.get_debug_line_program_at(pc) else {
            log::log!(log_level, "    (no location available)");
            return;
        };

        for _ in 0..128 {
            // Have an upper bound on the number of iterations, just in case.
            let Ok(Some(region_info)) = line_program.run() else { break };

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

if_compiler_is_supported! {
    {
        enum InstanceBackend {
            #[cfg(target_os = "linux")]
            CompiledLinux(SandboxInstance<SandboxLinux>),
            #[cfg(feature = "generic-sandbox")]
            CompiledGeneric(SandboxInstance<SandboxGeneric>),
            Interpreted(InterpretedInstance),
        }
    } else {
        enum InstanceBackend {
            Interpreted(InterpretedInstance),
        }
    }
}

/// The host failed to access the guest's memory.
#[derive(Debug)]
pub enum MemoryAccessError {
    OutOfRangeAccess { address: u32, length: u64 },
    Error(Error),
}

#[cfg(feature = "std")]
impl std::error::Error for MemoryAccessError {}

impl core::fmt::Display for MemoryAccessError {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            MemoryAccessError::OutOfRangeAccess { address, length } => {
                write!(
                    fmt,
                    "out of range memory access in 0x{:x}-0x{:x} ({} bytes)",
                    address,
                    u64::from(*address) + length,
                    length
                )
            }
            MemoryAccessError::Error(error) => {
                write!(fmt, "memory access failed: {error}")
            }
        }
    }
}

if_compiler_is_supported! {
    {
        macro_rules! access_backend {
            ($itself:expr, |$backend:ident| $e:expr) => {
                match $itself {
                    #[cfg(target_os = "linux")]
                    InstanceBackend::CompiledLinux(ref $backend) => {
                        let $backend = $backend.sandbox();
                        $e
                    },
                    #[cfg(feature = "generic-sandbox")]
                    InstanceBackend::CompiledGeneric(ref $backend) => {
                        let $backend = $backend.sandbox();
                        $e
                    },
                    InstanceBackend::Interpreted(ref $backend) => $e,
                }
            };

            ($itself:expr, |mut $backend:ident| $e:expr) => {
                match $itself {
                    #[cfg(target_os = "linux")]
                    InstanceBackend::CompiledLinux(ref mut $backend) => {
                        let $backend = $backend.sandbox_mut();
                        $e
                    },
                    #[cfg(feature = "generic-sandbox")]
                    InstanceBackend::CompiledGeneric(ref mut $backend) => {
                        let $backend = $backend.sandbox_mut();
                        $e
                    },
                    InstanceBackend::Interpreted(ref mut $backend) => $e,
                }
            };
        }
    } else {
        macro_rules! access_backend {
            ($itself:expr, |$backend:ident| $e:expr) => {
                match $itself {
                    InstanceBackend::Interpreted(ref $backend) => $e,
                }
            };

            ($itself:expr, |mut $backend:ident| $e:expr) => {
                match $itself {
                    InstanceBackend::Interpreted(ref mut $backend) => $e,
                }
            };
        }
    }
}

pub struct RawInstance {
    module: Module,
    backend: InstanceBackend,
    crosscheck_instance: Option<Box<InterpretedInstance>>,
}

impl RawInstance {
    /// Returns the module from which this instance was created.
    pub fn module(&self) -> &Module {
        &self.module
    }

    /// Starts or resumes the execution.
    pub fn run(&mut self) -> Result<InterruptKind, Error> {
        if self.next_program_counter().is_none() {
            return Err(Error::from_static_str("failed to run: next program counter is not set"));
        }

        if self.gas() < 0 {
            return Ok(InterruptKind::NotEnoughGas);
        }

        loop {
            let interruption = access_backend!(self.backend, |mut backend| backend
                .run()
                .map_err(|error| format!("execution failed: {error}")))?;
            log::trace!("Interrupted: {:?}", interruption);

            if matches!(interruption, InterruptKind::Trap) && log::log_enabled!(log::Level::Debug) {
                if let Some(program_counter) = self.program_counter() {
                    self.module.debug_print_location(log::Level::Debug, program_counter);
                }
            }

            if let Some(ref mut crosscheck) = self.crosscheck_instance {
                let is_step = matches!(interruption, InterruptKind::Step);
                let expected_interruption = crosscheck.run().expect("crosscheck failed");
                if interruption != expected_interruption {
                    panic!("run: crosscheck mismatch, interpreter = {expected_interruption:?}, backend = {interruption:?}");
                }

                let crosscheck_gas = crosscheck.gas();
                let crosscheck_program_counter = crosscheck.program_counter();
                let crosscheck_next_program_counter = crosscheck.next_program_counter();
                if self.module.gas_metering() != Some(GasMeteringKind::Async) {
                    assert_eq!(self.gas(), crosscheck_gas);
                }

                assert_eq!(self.program_counter(), crosscheck_program_counter);
                assert_eq!(self.next_program_counter(), crosscheck_next_program_counter);

                if is_step && !self.module().state().step_tracing {
                    continue;
                }
            }

            if self.gas() < 0 {
                return Ok(InterruptKind::NotEnoughGas);
            }

            break Ok(interruption);
        }
    }

    /// Gets the value of a given register.
    pub fn reg(&self, reg: Reg) -> RegValue {
        access_backend!(self.backend, |backend| backend.reg(reg))
    }

    /// Sets the value of a given register.
    pub fn set_reg(&mut self, reg: Reg, value: RegValue) {
        if let Some(ref mut crosscheck) = self.crosscheck_instance {
            crosscheck.set_reg(reg, value);
        }

        access_backend!(self.backend, |mut backend| backend.set_reg(reg, value))
    }

    /// Gets the amount of gas remaining.
    ///
    /// Note that this being zero doesn't necessarily mean that the execution ran out of gas,
    /// if the program ended up consuming *exactly* the amount of gas that it was provided with!
    pub fn gas(&self) -> Gas {
        access_backend!(self.backend, |backend| backend.gas())
    }

    /// Sets the amount of gas remaining.
    pub fn set_gas(&mut self, gas: Gas) {
        if let Some(ref mut crosscheck) = self.crosscheck_instance {
            crosscheck.set_gas(gas);
        }

        access_backend!(self.backend, |mut backend| backend.set_gas(gas))
    }

    /// Gets the current program counter.
    pub fn program_counter(&self) -> Option<ProgramCounter> {
        access_backend!(self.backend, |backend| backend.program_counter())
    }

    /// Gets the next program counter.
    ///
    /// This is where the program will resume execution when [`RawInstance::run`] is called.
    pub fn next_program_counter(&self) -> Option<ProgramCounter> {
        access_backend!(self.backend, |backend| backend.next_program_counter())
    }

    /// Sets the next program counter.
    pub fn set_next_program_counter(&mut self, pc: ProgramCounter) {
        if let Some(ref mut crosscheck) = self.crosscheck_instance {
            crosscheck.set_next_program_counter(pc);
        }

        access_backend!(self.backend, |mut backend| backend.set_next_program_counter(pc))
    }

    /// A convenience function which sets all of the registers to zero.
    pub fn clear_regs(&mut self) {
        for reg in Reg::ALL {
            self.set_reg(reg, 0);
        }
    }

    /// Resets the VM's memory to its initial state.
    pub fn reset_memory(&mut self) -> Result<(), Error> {
        if let Some(ref mut crosscheck) = self.crosscheck_instance {
            crosscheck.reset_memory();
        }

        access_backend!(self.backend, |mut backend| backend
            .reset_memory()
            .into_result("failed to reset the instance's memory"))
    }

    /// Reads the VM's memory.
    pub fn read_memory_into<'slice, B>(&self, address: u32, buffer: &'slice mut B) -> Result<&'slice mut [u8], MemoryAccessError>
    where
        B: ?Sized + AsUninitSliceMut,
    {
        let slice = buffer.as_uninit_slice_mut();
        if slice.is_empty() {
            // SAFETY: The slice is empty so it's always safe to assume it's initialized.
            unsafe {
                return Ok(polkavm_common::utils::slice_assume_init_mut(slice));
            }
        }

        if address < 0x10000 {
            return Err(MemoryAccessError::OutOfRangeAccess {
                address,
                length: slice.len() as u64,
            });
        }

        if u64::from(address) + slice.len() as u64 > 0x100000000 {
            return Err(MemoryAccessError::OutOfRangeAccess {
                address,
                length: slice.len() as u64,
            });
        }

        let length = slice.len();
        let result = access_backend!(self.backend, |backend| backend.read_memory_into(address, slice));
        if let Some(ref crosscheck) = self.crosscheck_instance {
            let mut expected_data: Vec<core::mem::MaybeUninit<u8>> = alloc::vec![core::mem::MaybeUninit::new(0xfa); length];
            let expected_result = crosscheck.read_memory_into(address, &mut expected_data);
            let expected_success = expected_result.is_ok();
            let success = result.is_ok();
            let results_match = match (&result, &expected_result) {
                (Ok(result), Ok(expected_result)) => result == expected_result,
                (Err(_), Err(_)) => true,
                _ => false,
            };
            if !results_match {
                let address_end = u64::from(address) + length as u64;
                if cfg!(debug_assertions) {
                    if let (Ok(result), Ok(expected_result)) = (result, expected_result) {
                        log::trace!("read_memory result (interpreter): {expected_result:?}");
                        log::trace!("read_memory result (backend):     {result:?}");
                    }
                }
                panic!("read_memory: crosscheck mismatch, range = 0x{address:x}..0x{address_end:x}, interpreter = {expected_success}, backend = {success}");
            }
        }
        result
    }

    /// Writes into the VM's memory.
    ///
    /// When dynamic paging is enabled calling this can be used to resolve a segfault. It can also
    /// be used to preemptively initialize pages for which no segfault is currently triggered.
    pub fn write_memory(&mut self, address: u32, data: &[u8]) -> Result<(), MemoryAccessError> {
        if data.is_empty() {
            return Ok(());
        }

        if address < 0x10000 {
            return Err(MemoryAccessError::OutOfRangeAccess {
                address,
                length: data.len() as u64,
            });
        }

        if u64::from(address) + data.len() as u64 > 0x100000000 {
            return Err(MemoryAccessError::OutOfRangeAccess {
                address,
                length: data.len() as u64,
            });
        }

        let result = access_backend!(self.backend, |mut backend| backend.write_memory(address, data));
        if let Some(ref mut crosscheck) = self.crosscheck_instance {
            let expected_result = crosscheck.write_memory(address, data);
            let expected_success = expected_result.is_ok();
            let success = result.is_ok();
            if success != expected_success {
                let address_end = u64::from(address) + data.len() as u64;
                panic!("write_memory: crosscheck mismatch, range = 0x{address:x}..0x{address_end:x}, interpreter = {expected_success}, backend = {success}");
            }
        }

        result
    }

    /// Reads the VM's memory.
    pub fn read_memory(&self, address: u32, length: u32) -> Result<Vec<u8>, MemoryAccessError> {
        let mut buffer = Vec::new();
        buffer.reserve_exact(length as usize);

        let pointer = buffer.as_ptr();
        let slice = self.read_memory_into(address, buffer.spare_capacity_mut())?;

        // Since `read_memory_into_slice` returns a `&mut [u8]` we can be sure it initialized the buffer
        // we've passed to it, as long as it's actually the same buffer we gave it.
        assert_eq!(slice.as_ptr(), pointer);
        assert_eq!(slice.len(), length as usize);

        #[allow(unsafe_code)]
        // SAFETY: `read_memory_into_slice` initialized this buffer, and we've verified this with `assert`s.
        unsafe {
            buffer.set_len(length as usize);
        }

        Ok(buffer)
    }

    /// A convenience function to read an `u32` from the VM's memory.
    ///
    /// This is equivalent to calling [`RawInstance::read_memory_into`].
    pub fn read_u32(&self, address: u32) -> Result<u32, MemoryAccessError> {
        let mut buffer = [0; 4];
        self.read_memory_into(address, &mut buffer)?;

        Ok(u32::from_le_bytes(buffer))
    }

    /// A convenience function to write an `u32` into the VM's memory.
    ///
    /// This is equivalent to calling [`RawInstance::write_memory`].
    pub fn write_u32(&mut self, address: u32, value: u32) -> Result<(), MemoryAccessError> {
        self.write_memory(address, &value.to_le_bytes())
    }

    /// A convenience function to read an `u16` from the VM's memory.
    ///
    /// This is equivalent to calling [`RawInstance::read_memory_into`].
    pub fn read_u16(&self, address: u32) -> Result<u16, MemoryAccessError> {
        let mut buffer = [0; 2];
        self.read_memory_into(address, &mut buffer)?;

        Ok(u16::from_le_bytes(buffer))
    }

    /// A convenience function to write an `u16` into the VM's memory.
    ///
    /// This is equivalent to calling [`RawInstance::write_memory`].
    pub fn write_u16(&mut self, address: u32, value: u16) -> Result<(), MemoryAccessError> {
        self.write_memory(address, &value.to_le_bytes())
    }

    /// A convenience function to read an `u8` from the VM's memory.
    ///
    /// This is equivalent to calling [`RawInstance::read_memory_into`].
    pub fn read_u8(&self, address: u32) -> Result<u8, MemoryAccessError> {
        let mut buffer = [0; 1];
        self.read_memory_into(address, &mut buffer)?;

        Ok(buffer[0])
    }

    /// A convenience function to write an `u8` into the VM's memory.
    ///
    /// This is equivalent to calling [`RawInstance::write_memory`].
    pub fn write_u8(&mut self, address: u32, value: u8) -> Result<(), MemoryAccessError> {
        self.write_memory(address, &[value])
    }

    /// Fills the given memory region with zeros.
    ///
    /// `address` must be greater or equal to 0x10000 and `address + length` cannot be greater than 0x100000000.
    /// If `length` is zero then this call has no effect and will always succeed.
    ///
    /// When dynamic paging is enabled calling this can be used to resolve a segfault. It can also
    /// be used to preemptively initialize pages for which no segfault is currently triggered.
    pub fn zero_memory(&mut self, address: u32, length: u32) -> Result<(), MemoryAccessError> {
        if length == 0 {
            return Ok(());
        }

        if address < 0x10000 {
            return Err(MemoryAccessError::OutOfRangeAccess {
                address,
                length: u64::from(length),
            });
        }

        if u64::from(address) + u64::from(length) > 0x100000000 {
            return Err(MemoryAccessError::OutOfRangeAccess {
                address,
                length: u64::from(length),
            });
        }

        let result = access_backend!(self.backend, |mut backend| backend.zero_memory(address, length));
        if let Some(ref mut crosscheck) = self.crosscheck_instance {
            let expected_result = crosscheck.zero_memory(address, length);
            let expected_success = expected_result.is_ok();
            let success = result.is_ok();
            if success != expected_success {
                let address_end = u64::from(address) + u64::from(length);
                panic!("zero_memory: crosscheck mismatch, range = 0x{address:x}..0x{address_end:x}, interpreter = {expected_success}, backend = {success}");
            }
        }

        result
    }

    /// Frees the given page(s).
    ///
    /// `address` must be a multiple of the page size. The value of `length` will be rounded up to the nearest multiple of the page size.
    /// If `length` is zero then this call has no effect and will always succeed.
    pub fn free_pages(&mut self, address: u32, length: u32) -> Result<(), Error> {
        if length == 0 {
            return Ok(());
        }

        if !self.module.is_multiple_of_page_size(address) {
            return Err("address not a multiple of page size".into());
        }

        access_backend!(self.backend, |mut backend| backend
            .free_pages(address, length)
            .into_result("free pages failed"))?;
        if let Some(ref mut crosscheck) = self.crosscheck_instance {
            crosscheck.free_pages(address, length);
        }

        Ok(())
    }

    /// Returns the current size of the program's heap.
    pub fn heap_size(&self) -> u32 {
        access_backend!(self.backend, |backend| backend.heap_size())
    }

    pub fn sbrk(&mut self, size: u32) -> Result<Option<u32>, Error> {
        let result = access_backend!(self.backend, |mut backend| backend.sbrk(size).into_result("sbrk failed"))?;
        if let Some(ref mut crosscheck) = self.crosscheck_instance {
            let expected_result = crosscheck.sbrk(size);
            let expected_success = expected_result.is_some();
            let success = result.is_some();
            if success != expected_success {
                panic!("sbrk: crosscheck mismatch, size = {size}, interpreter = {expected_success}, backend = {success}");
            }
        }

        Ok(result)
    }

    /// A convenience function which sets up a fuction call according to the default ABI.
    ///
    /// This function will:
    ///   1) clear all registers to zero,
    ///   2) initialize `RA` to `0xffff0000`,
    ///   3) initialize `SP` to its default value,
    ///   4) set the program counter.
    ///
    /// Will panic if `args` has more than 9 elements.
    pub fn prepare_call_untyped(&mut self, pc: ProgramCounter, args: &[RegValue]) {
        assert!(args.len() <= Reg::ARG_REGS.len(), "too many arguments");

        self.clear_regs();
        self.set_reg(Reg::SP, self.module.default_sp());
        self.set_reg(Reg::RA, VM_ADDR_RETURN_TO_HOST);
        self.set_next_program_counter(pc);

        for (reg, &value) in Reg::ARG_REGS.into_iter().zip(args) {
            self.set_reg(reg, value);
        }
    }

    /// A convenience function which sets up a fuction call according to the default ABI.
    ///
    /// This is equivalent to calling [`RawInstance::prepare_call_untyped`].
    ///
    /// Will panic if marshalling `args` through the FFI boundary requires too many registers.
    pub fn prepare_call_typed<FnArgs>(&mut self, pc: ProgramCounter, args: FnArgs)
    where
        FnArgs: crate::linker::FuncArgs,
    {
        let mut regs = [0; Reg::ARG_REGS.len()];
        let mut input_count = 0;
        args._set(|value| {
            assert!(input_count <= Reg::ARG_REGS.len(), "too many arguments");
            regs[input_count] = value;
            input_count += 1;
        });

        self.prepare_call_untyped(pc, &regs);
    }

    /// Extracts a return value from the argument registers according to the default ABI.
    ///
    /// This is equivalent to manually calling [`RawInstance::reg`].
    pub fn get_result_typed<FnResult>(&self) -> FnResult
    where
        FnResult: crate::linker::FuncResult,
    {
        let mut output_count = 0;
        FnResult::_get(|| {
            let value = access_backend!(self.backend, |backend| backend.reg(Reg::ARG_REGS[output_count]));
            output_count += 1;
            value
        })
    }

    /// Returns the PID of the sandbox corresponding to this instance.
    ///
    /// Will be `None` if the instance doesn't run in a separate process.
    /// Mostly only useful for debugging.
    pub fn pid(&self) -> Option<u32> {
        access_backend!(self.backend, |backend| backend.pid())
    }

    /// Gets the next native program counter.
    ///
    /// Will return `None` when running under an interpreter.
    /// Mostly only useful for debugging.
    pub fn next_native_program_counter(&self) -> Option<usize> {
        access_backend!(self.backend, |backend| backend.next_native_program_counter())
    }
}
