use alloc::borrow::{Cow, ToOwned};
use alloc::format;
use alloc::sync::Arc;
use alloc::vec::Vec;

#[cfg(not(feature = "std"))]
use alloc::collections::BTreeMap as HashMap;
#[cfg(feature = "std")]
use std::collections::HashMap;

use core::marker::PhantomData;

use polkavm_common::abi::MemoryMap;
use polkavm_common::abi::{VM_ADDR_RETURN_TO_HOST, VM_ADDR_USER_STACK_HIGH};
use polkavm_common::error::Trap;
use polkavm_common::program::{FrameKind, Imports, Reg};
use polkavm_common::program::{ProgramBlob, ProgramSymbol};
use polkavm_common::utils::{Access, AsUninitSliceMut, Gas};

use crate::caller::{Caller, CallerRaw};
use crate::config::{BackendKind, Config, GasMeteringKind, ModuleConfig, SandboxKind};
use crate::error::{bail, bail_static, Error, ExecutionError};
use crate::interpreter::{InterpretedAccess, InterpretedInstance, InterpretedModule};
use crate::mutex::Mutex;
use crate::tracer::Tracer;
use crate::utils::GuestInit;

if_compiler_is_supported! {
    use crate::sandbox::{Sandbox, SandboxInstance};
    use crate::sandbox::generic::Sandbox as SandboxGeneric;
    use crate::compiler::CompiledModule;

    #[cfg(target_os = "linux")]
    use crate::sandbox::linux::Sandbox as SandboxLinux;
}

pub type RegValue = u32;

if_compiler_is_supported! {
    {
        impl EngineState {
            pub(crate) fn sandbox_cache(&self) -> Option<&SandboxCache> {
                self.sandbox_cache.as_ref()
            }
        }

        use crate::sandbox::SandboxCache;
        use crate::compiler::CompilerCache;
    } else {
        struct SandboxCache;

        #[derive(Default)]
        struct CompilerCache;
    }
}

pub(crate) struct EngineState {
    #[allow(dead_code)]
    sandbox_cache: Option<SandboxCache>,
    #[allow(dead_code)]
    compiler_cache: CompilerCache,
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

                    let sandbox_cache = SandboxCache::new(selected_sandbox, config.worker_count, debug_trace_execution)?;
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
            state: Arc::new(EngineState {
                sandbox_cache,
                compiler_cache: Default::default(),
            }),
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
    code_offset_by_symbol: HashMap<Vec<u8>, u32>,

    blob: ProgramBlob<'static>,
    compiled_module: CompiledModuleKind,
    interpreted_module: Option<InterpretedModule>,
    memory_map: MemoryMap,
    gas_metering: Option<GasMeteringKind>,
    is_strict: bool,
}

impl ModulePrivate {
    fn empty() -> Self {
        ModulePrivate {
            debug_trace_execution: false,
            code_offset_by_symbol: Default::default(),

            blob: Default::default(),
            compiled_module: CompiledModuleKind::Unavailable,
            interpreted_module: None,
            memory_map: MemoryMap::empty(),
            gas_metering: None,
            is_strict: false,
        }
    }
}

/// A compiled PolkaVM program module.
#[derive(Clone)]
pub struct Module(Arc<ModulePrivate>);

impl Module {
    pub(crate) fn empty() -> Self {
        Module(Arc::new(ModulePrivate::empty()))
    }

    pub(crate) fn is_debug_trace_execution_enabled(&self) -> bool {
        self.0.debug_trace_execution
    }

    pub(crate) fn compiled_module(&self) -> &CompiledModuleKind {
        &self.0.compiled_module
    }

    pub(crate) fn interpreted_module(&self) -> Option<&InterpretedModule> {
        self.0.interpreted_module.as_ref()
    }

    pub(crate) fn blob(&self) -> &ProgramBlob<'static> {
        &self.0.blob
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
        log::debug!("Preparing a module from a blob of length {}...", blob.as_bytes().len());

        // Do an early check for memory config validity.
        MemoryMap::new(config.page_size, blob.ro_data_size(), blob.rw_data_size(), blob.stack_size()).map_err(Error::from_static_str)?;

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
                if code_offset as usize >= blob.code().len() {
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
                log::trace!("  Export at {}: {}", export.target_code_offset(), export.symbol());
                if config.is_strict && export.target_code_offset() as usize >= blob.code().len() {
                    bail!(
                        "out of range export found; export {} points to code offset {}, while the code blob is only {} bytes",
                        export.symbol(),
                        export.target_code_offset(),
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
        };

        #[allow(unused_macros)]
        macro_rules! compile_module {
            ($sandbox_kind:ident, $module_kind:ident, $run:ident) => {{
                let (visitor, aux) = crate::compiler::CompilerVisitor::new::<$sandbox_kind>(
                    &engine.state.compiler_cache,
                    config,
                    blob.jump_table(),
                    blob.code(),
                    blob.bitmask(),
                    &exports,
                    engine.debug_trace_execution,
                    blob.code().len() as u32,
                    init,
                )?;

                let visitor = $run(blob, visitor);
                let module = visitor.finish_compilation(&engine.state.compiler_cache, aux)?;
                Some(CompiledModuleKind::$module_kind(module))
            }};
        }

        let compiled_module: Option<CompiledModuleKind> = if_compiler_is_supported! {
            {
                if engine.selected_backend == BackendKind::Compiler {
                    if let Some(selected_sandbox) = engine.selected_sandbox {
                        type VisitorTy<'a> = crate::compiler::CompilerVisitor<'a>;
                        let run = polkavm_common::program::prepare_visitor!(COMPILER_VISITOR, VisitorTy<'a>);

                        match selected_sandbox {
                            SandboxKind::Linux => {
                                #[cfg(target_os = "linux")]
                                {
                                    compile_module!(SandboxLinux, Linux, run)
                                }

                                #[cfg(not(target_os = "linux"))]
                                {
                                    log::debug!("Selected sandbox unavailable!");
                                    None
                                }
                            },
                            SandboxKind::Generic => {
                                compile_module!(SandboxGeneric, Generic, run)
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

        let code_offset_by_symbol = exports
            .iter()
            .map(|export| (export.symbol().to_vec(), export.target_code_offset()))
            .collect();

        let memory_map = init.memory_map().map_err(Error::from_static_str)?;
        log::debug!(
            "  Memory map: RO data: 0x{:08x}..0x{:08x} ({}/{} bytes)",
            memory_map.ro_data_range().start,
            memory_map.ro_data_range().end,
            blob.ro_data_size(),
            memory_map.ro_data_range().len(),
        );
        log::debug!(
            "  Memory map: RW data: 0x{:08x}..0x{:08x} ({}/{} bytes)",
            memory_map.rw_data_range().start,
            memory_map.rw_data_range().end,
            blob.rw_data_size(),
            memory_map.rw_data_range().len(),
        );
        log::debug!(
            "  Memory map:   Stack: 0x{:08x}..0x{:08x} ({}/{} bytes)",
            memory_map.stack_range().start,
            memory_map.stack_range().end,
            blob.stack_size(),
            memory_map.stack_range().len(),
        );

        Ok(Module(Arc::new(ModulePrivate {
            debug_trace_execution: engine.debug_trace_execution,
            code_offset_by_symbol,

            // TODO: Remove the clone.
            blob: blob.clone().into_owned(),
            compiled_module,
            interpreted_module,
            memory_map,
            gas_metering: config.gas_metering,
            is_strict: config.is_strict,
        })))
    }

    /// The program's memory map.
    pub fn memory_map(&self) -> &MemoryMap {
        &self.0.memory_map
    }

    /// Searches for a given symbol exported by the module.
    pub fn lookup_export(&self, symbol: impl AsRef<[u8]>) -> Option<ExportIndex> {
        let symbol = symbol.as_ref();
        let code_offset = *self.0.code_offset_by_symbol.get(symbol)?;
        Some(ExportIndex(code_offset))
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
    pub fn code_offset_to_native_code_offset(&self) -> Option<&[(u32, u32)]> {
        if_compiler_is_supported! {
            {
                match self.0.compiled_module {
                    #[cfg(target_os = "linux")]
                    CompiledModuleKind::Linux(ref module) => Some(module.code_offset_to_native_code_offset()),
                    CompiledModuleKind::Generic(ref module) => Some(module.code_offset_to_native_code_offset()),
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
    pub fn gas_cost_for_code_offset(&self, code_offset: u32) -> Option<i64> {
        let instructions = self.0.blob.instructions_at(code_offset)?;
        Some(i64::from(crate::gas::calculate_for_block(instructions)))
    }

    pub(crate) fn debug_print_location(&self, log_level: log::Level, pc: u32) {
        log::log!(log_level, "  At #{pc}:");

        let blob = self.blob();
        let Ok(Some(mut line_program)) = blob.get_debug_line_program_at(pc) else {
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

trait CallFn<T>: Send + Sync {
    fn call(&self, user_data: &mut T, access: BackendAccess, raw: &mut CallerRaw) -> Result<(), Trap>;
}

#[repr(transparent)]
pub struct CallFnArc<T>(Arc<dyn CallFn<T>>);

impl<T> Clone for CallFnArc<T> {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

pub trait IntoCallFn<T, Params, Result>: Send + Sync + 'static {
    #[doc(hidden)]
    const _REGS_REQUIRED: usize;

    #[doc(hidden)]
    fn _into_extern_fn(self) -> CallFnArc<T>;
}

/// A type which can be marshalled through the VM's FFI boundary.
pub trait AbiTy: Sized + Send + 'static {
    #[doc(hidden)]
    const _REGS_REQUIRED: usize;

    #[doc(hidden)]
    fn _get(get_reg: impl FnMut() -> RegValue) -> Self;

    #[doc(hidden)]
    fn _set(self, set_reg: impl FnMut(RegValue));
}

impl AbiTy for u32 {
    const _REGS_REQUIRED: usize = 1;

    fn _get(mut get_reg: impl FnMut() -> RegValue) -> Self {
        get_reg()
    }

    fn _set(self, mut set_reg: impl FnMut(RegValue)) {
        set_reg(self)
    }
}

impl AbiTy for i32 {
    const _REGS_REQUIRED: usize = <u32 as AbiTy>::_REGS_REQUIRED;

    fn _get(get_reg: impl FnMut() -> RegValue) -> Self {
        <u32 as AbiTy>::_get(get_reg) as i32
    }

    fn _set(self, set_reg: impl FnMut(RegValue)) {
        (self as u32)._set(set_reg)
    }
}

impl AbiTy for u64 {
    const _REGS_REQUIRED: usize = 2;

    fn _get(mut get_reg: impl FnMut() -> RegValue) -> Self {
        let value_lo = get_reg();
        let value_hi = get_reg();
        u64::from(value_lo) | (u64::from(value_hi) << 32)
    }

    fn _set(self, mut set_reg: impl FnMut(RegValue)) {
        set_reg(self as u32);
        set_reg((self >> 32) as u32);
    }
}

impl AbiTy for i64 {
    const _REGS_REQUIRED: usize = <u64 as AbiTy>::_REGS_REQUIRED;

    fn _get(get_reg: impl FnMut() -> RegValue) -> Self {
        <u64 as AbiTy>::_get(get_reg) as i64
    }

    fn _set(self, set_reg: impl FnMut(RegValue)) {
        (self as u64)._set(set_reg)
    }
}

// `AbiTy` is deliberately not implemented for `usize`.

/// A type which can be returned from a host function.
pub trait ReturnTy: Sized + Send + 'static {
    #[doc(hidden)]
    const _REGS_REQUIRED: usize;

    #[doc(hidden)]
    fn _handle_return(self, set_reg: impl FnMut(RegValue)) -> Result<(), Trap>;
}

impl<T> ReturnTy for T
where
    T: AbiTy,
{
    const _REGS_REQUIRED: usize = <T as AbiTy>::_REGS_REQUIRED;

    fn _handle_return(self, set_reg: impl FnMut(RegValue)) -> Result<(), Trap> {
        self._set(set_reg);
        Ok(())
    }
}

impl ReturnTy for () {
    const _REGS_REQUIRED: usize = 0;

    fn _handle_return(self, _set_reg: impl FnMut(RegValue)) -> Result<(), Trap> {
        Ok(())
    }
}

impl ReturnTy for Result<(), Trap> {
    const _REGS_REQUIRED: usize = 0;

    fn _handle_return(self, _set_reg: impl FnMut(RegValue)) -> Result<(), Trap> {
        self
    }
}

impl<T> ReturnTy for Result<T, Trap>
where
    T: AbiTy,
{
    const _REGS_REQUIRED: usize = <T as AbiTy>::_REGS_REQUIRED;

    fn _handle_return(self, set_reg: impl FnMut(RegValue)) -> Result<(), Trap> {
        self?._set(set_reg);
        Ok(())
    }
}

pub trait FuncArgs: Send {
    #[doc(hidden)]
    const _REGS_REQUIRED: usize;

    #[doc(hidden)]
    fn _set(self, set_reg: impl FnMut(RegValue));
}

pub trait FuncResult: Send {
    #[doc(hidden)]
    const _REGS_REQUIRED: usize;

    #[doc(hidden)]
    fn _get(get_reg: impl FnMut() -> RegValue) -> Self;
}

impl FuncResult for () {
    const _REGS_REQUIRED: usize = 0;

    fn _get(_: impl FnMut() -> RegValue) -> Self {}
}

impl<T> FuncResult for T
where
    T: AbiTy,
{
    const _REGS_REQUIRED: usize = 1;

    fn _get(get_reg: impl FnMut() -> RegValue) -> Self {
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
        move || -> RegValue {
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
        impl<T, F, $($args,)* R> CallFn<T> for (F, UnsafePhantomData<(R, $($args),*)>)
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
                    move |value: RegValue| {
                        let reg = Reg::ARG_REGS[reg_index];
                        access.set_reg(reg, value);

                        if let Some(ref mut tracer) = raw.tracer() {
                            tracer.on_set_reg_in_hostcall(reg, value);
                        }

                        reg_index += 1;
                    }
                };
                result._handle_return(set_reg)
            }
        }

        impl<T, F, $($args,)* R> IntoCallFn<T, ($($args,)*), R> for F
        where
            F: Fn($($args),*) -> R + Send + Sync + 'static,
            $($args: AbiTy,)*
            R: ReturnTy,
        {
            const _REGS_REQUIRED: usize = 0 $(+ $args::_REGS_REQUIRED)*;

            fn _into_extern_fn(self) -> CallFnArc<T> {
                #[allow(non_snake_case)]
                let callback = move |_caller: Caller<T>, $($args: $args),*| -> R {
                    self($($args),*)
                };
                CallFnArc(Arc::new((callback, UnsafePhantomData(PhantomData::<(R, $($args),*)>))))
            }
        }

        impl<T, F, $($args,)* R> IntoCallFn<T, (Caller<'_, T>, $($args,)*), R> for F
        where
            F: Fn(Caller<'_, T>, $($args),*) -> R + Send + Sync + 'static,
            $($args: AbiTy,)*
            R: ReturnTy,
        {
            const _REGS_REQUIRED: usize = 0 $(+ $args::_REGS_REQUIRED)*;

            fn _into_extern_fn(self) -> CallFnArc<T> {
                CallFnArc(Arc::new((self, UnsafePhantomData(PhantomData::<(R, $($args),*)>))))
            }
        }

        impl<$($args: Send + AbiTy,)*> FuncArgs for ($($args,)*) {
            const _REGS_REQUIRED: usize = 0 $(+ $args::_REGS_REQUIRED)*;

            #[allow(unused_mut)]
            #[allow(unused_variables)]
            #[allow(non_snake_case)]
            fn _set(self, mut set_reg: impl FnMut(RegValue)) {
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
    callback: F,
    _phantom: UnsafePhantomData<T>,
}

fn catch_hostcall_panic<R>(callback: impl FnOnce() -> R) -> Result<R, Trap> {
    #[cfg(feature = "std")]
    return std::panic::catch_unwind(core::panic::AssertUnwindSafe(callback)).map_err(|panic| {
        if let Some(message) = panic.downcast_ref::<&str>() {
            log::error!("Hostcall panicked: {message}");
        } else if let Some(message) = panic.downcast_ref::<String>() {
            log::error!("Hostcall panicked: {message}");
        } else {
            log::error!("Hostcall panicked");
        }

        Trap::default()
    });

    #[cfg(not(feature = "std"))]
    {
        Ok(callback())
    }
}

impl<T, F> CallFn<T> for DynamicFn<T, F>
where
    F: Fn(Caller<'_, T>) -> Result<(), Trap> + Send + Sync + 'static,
    T: 'static,
{
    fn call(&self, user_data: &mut T, mut access: BackendAccess, raw: &mut CallerRaw) -> Result<(), Trap> {
        Caller::wrap(user_data, &mut access, raw, move |caller| {
            catch_hostcall_panic(|| (self.callback)(caller))
        })??;

        Ok(())
    }
}

type FallbackHandlerArc<T> = Arc<dyn Fn(Caller<'_, T>, &[u8]) -> Result<(), Trap> + Send + Sync + 'static>;

pub struct Linker<T> {
    engine_state: Arc<EngineState>,
    host_functions: HashMap<Vec<u8>, CallFnArc<T>>,
    #[allow(clippy::type_complexity)]
    fallback_handler: Option<FallbackHandlerArc<T>>,
    phantom: PhantomData<T>,
}

impl<T> Linker<T> {
    pub fn new(engine: &Engine) -> Self {
        Self {
            engine_state: Arc::clone(&engine.state),
            host_functions: Default::default(),
            fallback_handler: None,
            phantom: PhantomData,
        }
    }

    /// Defines a fallback external call handler, in case no other registered functions match.
    pub fn func_fallback(&mut self, func: impl Fn(Caller<'_, T>, &[u8]) -> Result<(), Trap> + Send + Sync + 'static) {
        self.fallback_handler = Some(Arc::new(func));
    }

    /// Defines a new dynamically typed handler for external calls with a given symbol.
    pub fn func_new(
        &mut self,
        symbol: impl AsRef<[u8]>,
        func: impl Fn(Caller<'_, T>) -> Result<(), Trap> + Send + Sync + 'static,
    ) -> Result<&mut Self, Error>
    where
        T: 'static,
    {
        let symbol = symbol.as_ref();
        if self.host_functions.contains_key(symbol) {
            bail!(
                "cannot register host function: host function was already registered: {}",
                ProgramSymbol::from(symbol)
            );
        }

        self.host_functions.insert(
            symbol.to_owned(),
            CallFnArc(Arc::new(DynamicFn {
                callback: func,
                _phantom: UnsafePhantomData(PhantomData),
            })),
        );

        Ok(self)
    }

    /// Defines a new statically typed handler for external calls with a given symbol.
    pub fn func_wrap<Params, Args>(
        &mut self,
        symbol: impl AsRef<[u8]>,
        func: impl IntoCallFn<T, Params, Args>,
    ) -> Result<&mut Self, Error> {
        let symbol = symbol.as_ref();
        if self.host_functions.contains_key(symbol) {
            bail!(
                "cannot register host function: host function was already registered: {}",
                ProgramSymbol::from(symbol)
            );
        }

        self.host_functions.insert(symbol.to_owned(), func._into_extern_fn());
        Ok(self)
    }

    /// Pre-instantiates a new module, linking it with the external functions previously defined on this object.
    pub fn instantiate_pre(&self, module: &Module) -> Result<InstancePre<T>, Error> {
        let mut host_functions: Vec<Option<CallFnArc<T>>> = Vec::with_capacity(module.0.blob.imports().len() as usize);
        for symbol in module.0.blob.imports() {
            let Some(symbol) = symbol else {
                host_functions.push(None);
                continue;
            };

            let host_fn = if let Some(host_fn) = self.host_functions.get(symbol.as_bytes()) {
                Some(host_fn.clone())
            } else if self.fallback_handler.is_some() {
                None
            } else if module.0.is_strict {
                bail!("failed to instantiate module: missing host function: {}", symbol);
            } else {
                log::debug!("Missing host function: {}", symbol);
                None
            };

            host_functions.push(host_fn);
        }

        assert_eq!(host_functions.len(), module.0.blob.imports().len() as usize);
        Ok(InstancePre(Arc::new(InstancePrePrivate {
            engine_state: Arc::clone(&self.engine_state),
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
    host_functions: Vec<Option<CallFnArc<T>>>,
    fallback_handler: Option<FallbackHandlerArc<T>>,
    _private: PhantomData<T>,
}

pub struct InstancePre<T>(Arc<InstancePrePrivate<T>>);

impl<T> Clone for InstancePre<T> {
    fn clone(&self) -> Self {
        InstancePre(Arc::clone(&self.0))
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
                        let compiled_instance = SandboxInstance::<SandboxLinux>::spawn_and_load_module(Arc::clone(&self.0.engine_state), &self.0.module)?;
                        Some(InstanceBackend::CompiledLinux(compiled_instance))
                    },
                    CompiledModuleKind::Generic(..) => {
                        let compiled_instance = SandboxInstance::<SandboxGeneric>::spawn_and_load_module(Arc::clone(&self.0.engine_state), &self.0.module)?;
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
            None => InstanceBackend::Interpreted(InterpretedInstance::new_from_module(self.0.module.clone())),
        };

        let tracer = if self.0.module.0.debug_trace_execution {
            Some(Tracer::new(&self.0.module))
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
            CompiledLinux(SandboxInstance<SandboxLinux>),
            CompiledGeneric(SandboxInstance<SandboxGeneric>),
            Interpreted(InterpretedInstance),
        }
    } else {
        enum InstanceBackend {
            Interpreted(InterpretedInstance),
        }
    }
}

impl InstanceBackend {
    fn execute(&mut self, args: ExecuteArgs) -> Result<(), ExecutionError> {
        if_compiler_is_supported! {
            {
                match self {
                    #[cfg(target_os = "linux")]
                    InstanceBackend::CompiledLinux(ref mut backend) => backend.execute(args),
                    InstanceBackend::CompiledGeneric(ref mut backend) => backend.execute(args),
                    InstanceBackend::Interpreted(ref mut backend) => backend.execute(args),
                }
            } else {
                match self {
                    InstanceBackend::Interpreted(ref mut backend) => backend.execute(args),
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
            u64::from(self.address) + self.length,
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

    fn get_reg(&self, reg: Reg) -> RegValue {
        access_backend!(self, |access| access.get_reg(reg))
    }

    fn set_reg(&mut self, reg: Reg, value: RegValue) {
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

    fn sbrk(&mut self, size: u32) -> Option<u32> {
        access_backend!(self, |access| access.sbrk(size))
    }

    fn heap_size(&self) -> u32 {
        access_backend!(self, |access| access.heap_size())
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

    fn consume_gas(&mut self, gas: u64) {
        access_backend!(self, |access| access.consume_gas(gas))
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
        Instance(Arc::clone(&self.0))
    }
}

impl<T> Instance<T> {
    /// Returns the module from which this instance was created.
    pub fn module(&self) -> &Module {
        &self.0.instance_pre.0.module
    }

    /// Updates the state of the instance according to the `state_args` and calls a given function.
    pub fn call(&self, state_args: StateArgs, call_args: CallArgs<T>) -> Result<(), ExecutionError> {
        self.execute(state_args, Some(call_args))
    }

    /// A conveniance function to call into this particular instance according to the default ABI.
    ///
    /// This is equivalent to calling [`Instance::call`] with an appropriately set up [`CallArgs`].
    pub fn call_typed<FnArgs, FnResult>(
        &self,
        user_data: &mut T,
        symbol: impl AsRef<[u8]>,
        args: FnArgs,
    ) -> Result<FnResult, ExecutionError>
    where
        FnArgs: FuncArgs,
        FnResult: FuncResult,
    {
        let symbol = symbol.as_ref();
        let Some(export_index) = self.module().lookup_export(symbol) else {
            return Err(ExecutionError::Error(
                format!(
                    "failed to call function {}: the module contains no such export",
                    ProgramSymbol::new(symbol.into())
                )
                .into(),
            ));
        };

        let mut call_args = CallArgs::new(user_data, export_index);
        call_args.args_typed::<FnArgs>(args);

        self.call(Default::default(), call_args)?;
        Ok(self.get_result_typed::<FnResult>())
    }

    /// Updates the state of this particular instance.
    pub fn update_state(&self, state_args: StateArgs) -> Result<(), ExecutionError> {
        self.execute(state_args, None)
    }

    /// A conveniance function to reset the instance's memory to its initial state from when it was first instantiated.
    ///
    /// This is equivalent to calling [`Instance::update_state`] with an appropriately set up [`StateArgs`].
    pub fn reset_memory(&self) -> Result<(), Error> {
        let mut args = StateArgs::new();
        args.reset_memory(true);
        self.update_state(args).map_err(Error::from_execution_error)
    }

    /// A conveniance function to increase the size of the program's heap by a given number of bytes, allocating memory if necessary.
    ///
    /// If successful returns a pointer to the end of the guest's heap.
    ///
    /// This is equivalent to manually checking that the `size` bytes can actually be allocated, calling [`Instance::sbrk`] with an appropriately set up [`StateArgs`],
    /// and calculating the new address of the end of the guest's heap.
    pub fn sbrk(&self, size: u32) -> Result<Option<u32>, Error> {
        let mut mutable = self.0.mutable.lock();

        let Some(new_size) = mutable.backend.access().heap_size().checked_add(size) else {
            return Ok(None);
        };

        if new_size > self.module().memory_map().max_heap_size() {
            return Ok(None);
        };

        let mut args = StateArgs::new();
        args.sbrk(size);
        self.execute_impl(&mut mutable, args, None).map_err(Error::from_execution_error)?;

        debug_assert_eq!(mutable.backend.access().heap_size(), new_size);
        Ok(Some(self.module().memory_map().heap_base() + new_size))
    }

    fn execute(&self, state_args: StateArgs, call_args: Option<CallArgs<T>>) -> Result<(), ExecutionError> {
        let mutable = &self.0.mutable;
        let mut mutable = mutable.lock();
        self.execute_impl(&mut mutable, state_args, call_args)
    }

    fn execute_impl(
        &self,
        mutable: &mut InstancePrivateMut,
        state_args: StateArgs,
        mut call_args: Option<CallArgs<T>>,
    ) -> Result<(), ExecutionError> {
        use polkavm_common::{VM_RPC_FLAG_RESET_MEMORY_AFTER_EXECUTION, VM_RPC_FLAG_RESET_MEMORY_BEFORE_EXECUTION};

        let instance_pre = &self.0.instance_pre;
        let module = &instance_pre.0.module;

        if state_args.sbrk > 0 {
            let current_size = if state_args.reset_memory {
                0
            } else {
                mutable.backend.access().heap_size()
            };

            let new_size = current_size.checked_add(state_args.sbrk);
            if !new_size.map_or(false, |new_size| new_size <= module.memory_map().max_heap_size()) {
                return Err(ExecutionError::Error(Error::from_static_str(
                    "execution failed: cannot grow the heap over the maximum",
                )));
            }
        }

        let mut args = ExecuteArgs::new();
        if state_args.reset_memory {
            args.flags |= VM_RPC_FLAG_RESET_MEMORY_BEFORE_EXECUTION;
        }

        args.gas = state_args.gas;
        args.sbrk = state_args.sbrk;

        #[allow(clippy::branches_sharing_code)]
        let result = if let Some(call_args) = call_args.as_mut() {
            args.entry_point = Some(call_args.code_offset);
            args.regs = Some(&call_args.initial_regs);
            if call_args.reset_memory_after_call {
                args.flags |= VM_RPC_FLAG_RESET_MEMORY_AFTER_EXECUTION;
            }

            if log::log_enabled!(log::Level::Trace) {
                if let Some(export) = self
                    .0
                    .instance_pre
                    .0
                    .module
                    .0
                    .blob
                    .exports()
                    .find(|export| export.target_code_offset() == call_args.code_offset)
                {
                    log::trace!(
                        "Calling into {}... (gas limit = {:?})",
                        export.symbol(),
                        module.0.gas_metering.and(args.gas)
                    );
                } else {
                    log::trace!(
                        "Calling into code offset {}... (gas limit = {:?})",
                        call_args.code_offset,
                        module.0.gas_metering.and(args.gas)
                    );
                }
            }

            if let Some(ref mut tracer) = mutable.tracer() {
                tracer.on_before_execute(&args);
            }

            let mut on_hostcall = on_hostcall(
                call_args.user_data,
                &instance_pre.0.host_functions,
                instance_pre.0.module.0.blob.imports(),
                instance_pre.0.fallback_handler.as_ref(),
                &mut mutable.raw,
            );

            args.hostcall_handler = Some(&mut on_hostcall);
            mutable.backend.execute(args)
        } else {
            log::trace!("Updating state...");

            if let Some(ref mut tracer) = mutable.tracer() {
                tracer.on_before_execute(&args);
            }

            mutable.backend.execute(args)
        };

        if let Some(ref mut tracer) = mutable.tracer() {
            tracer.on_after_execute();
        }

        match result {
            Ok(()) => {
                log::trace!(
                    "...execution finished: success, leftover gas = {:?}",
                    mutable.backend.access().gas_remaining()
                );
            }
            Err(ExecutionError::Error(error)) => {
                log::trace!("...execution finished: error: {error}");

                if let Some(export) = call_args.as_ref().and_then(|call_args| {
                    self.0
                        .instance_pre
                        .0
                        .module
                        .0
                        .blob
                        .exports()
                        .find(|export| export.target_code_offset() == call_args.code_offset)
                }) {
                    return Err(ExecutionError::Error(
                        format!("failed to call function {}: {}", export.symbol(), error).into(),
                    ));
                } else {
                    return Err(ExecutionError::Error(format!("execution failed: {error}").into()));
                }
            }
            Err(ExecutionError::Trap(trap)) => {
                log::trace!("...execution finished: trapped");
                return Err(ExecutionError::Trap(trap));
            }
            Err(ExecutionError::OutOfGas) => {
                log::trace!("...execution finished: ran out of gas");
                return Err(ExecutionError::OutOfGas);
            }
        }

        Ok(())
    }

    pub fn read_memory_into_slice<'slice, B>(&self, address: u32, buffer: &'slice mut B) -> Result<&'slice mut [u8], Trap>
    where
        B: ?Sized + AsUninitSliceMut,
    {
        let mut mutable = self.0.mutable.lock();
        mutable.backend.access().read_memory_into_slice(address, buffer)
    }

    pub fn read_memory_into_vec(&self, address: u32, length: u32) -> Result<Vec<u8>, Trap> {
        let mut mutable = self.0.mutable.lock();
        mutable.backend.access().read_memory_into_vec(address, length)
    }

    pub fn write_memory(&self, address: u32, data: &[u8]) -> Result<(), Trap> {
        let mut mutable = self.0.mutable.lock();
        let result = mutable.backend.access().write_memory(address, data);
        if let Some(ref mut tracer) = mutable.tracer() {
            tracer.on_memory_write_in_hostcall(address, data, result.is_ok())?;
        }

        result
    }

    /// Returns the current size of the program's heap.
    pub fn heap_size(&self) -> u32 {
        let mut mutable = self.0.mutable.lock();
        mutable.backend.access().heap_size()
    }

    /// Returns the value of the given register.
    pub fn get_reg(&self, reg: Reg) -> RegValue {
        let mut mutable = self.0.mutable.lock();
        mutable.backend.access().get_reg(reg)
    }

    /// Extracts a return value from the argument registers according to the default ABI.
    ///
    /// This is equivalent to manually calling [`Instance::get_reg`].
    pub fn get_result_typed<FnResult>(&self) -> FnResult
    where
        FnResult: FuncResult,
    {
        let mut mutable = self.0.mutable.lock();
        let mut output_count = 0;
        FnResult::_get(|| {
            let access = mutable.backend.access();
            let value = access.get_reg(Reg::ARG_REGS[output_count]);
            output_count += 1;
            value
        })
    }

    /// Gets the amount of gas remaining, or `None` if gas metering is not enabled for this instance.
    ///
    /// Note that this being zero doesn't necessarily mean that the execution ran out of gas,
    /// if the program ended up consuming *exactly* the amount of gas that it was provided with!
    pub fn gas_remaining(&self) -> Option<Gas> {
        let mut mutable = self.0.mutable.lock();
        mutable.backend.access().gas_remaining()
    }

    /// Returns the PID of the sandbox corresponding to this instance.
    ///
    /// Will be `None` if the instance doesn't run in a separate process.
    /// Mostly only useful for debugging.
    pub fn pid(&self) -> Option<u32> {
        let mutable = self.0.mutable.lock();
        mutable.backend.pid()
    }
}

/// The code offset an exported function to be called.
#[derive(Copy, Clone, Debug)]
pub struct ExportIndex(u32);

/// A helper struct used when calling into a function exported by the guest program.
pub struct CallArgs<'a, T> {
    pub(crate) initial_regs: [RegValue; Reg::ALL.len()],
    pub(crate) user_data: &'a mut T,
    pub(crate) code_offset: u32,
    pub(crate) reset_memory_after_call: bool,
}

impl<'a, T> CallArgs<'a, T> {
    /// Creates a new `CallArgs`.
    pub fn new(user_data: &'a mut T, code_offset: ExportIndex) -> Self {
        let mut initial_regs = [0; Reg::ALL.len()];
        initial_regs[Reg::SP as usize] = VM_ADDR_USER_STACK_HIGH;
        initial_regs[Reg::RA as usize] = VM_ADDR_RETURN_TO_HOST;

        Self {
            initial_regs,
            user_data,
            code_offset: code_offset.0,
            reset_memory_after_call: false,
        }
    }

    /// Decides whether the memory of the instance will be reset after the call.
    ///
    /// Default: `false`
    pub fn reset_memory_after_call(&mut self, value: bool) -> &mut Self {
        self.reset_memory_after_call = value;
        self
    }

    /// Sets a given register to the given value before the call.
    ///
    /// The default value for `SP` and `RA` is 0xffff0000, and for every other register it is zero.
    pub fn reg(&mut self, reg: Reg, value: RegValue) -> &mut Self {
        self.initial_regs[reg as usize] = value;
        self
    }

    /// Sets the argument registers to the given values.
    ///
    /// A shorthand for successively calling `set_reg` with `Reg::A0`, `Reg::A1`, ..., `Reg::A5`.
    ///
    /// Will panic if `args` has more than 6 elements.
    pub fn args_untyped(&mut self, args: &[RegValue]) -> &mut Self {
        self.initial_regs[Reg::A0 as usize..Reg::A0 as usize + args.len()].copy_from_slice(args);
        self
    }

    /// Sets the argument registers to the given values according to the default ABI.
    pub fn args_typed<FnArgs>(&mut self, args: FnArgs) -> &mut Self
    where
        FnArgs: FuncArgs,
    {
        let mut input_count = 0;
        args._set(|value| {
            assert!(input_count <= Reg::MAXIMUM_INPUT_REGS);
            self.initial_regs[Reg::A0 as usize + input_count] = value;
            input_count += 1;
        });

        self
    }
}

pub struct StateArgs {
    pub(crate) reset_memory: bool,
    pub(crate) gas: Option<Gas>,
    pub(crate) sbrk: u32,
}

impl Default for StateArgs {
    fn default() -> Self {
        Self::new()
    }
}

impl StateArgs {
    /// Creates a new `StateArgs`.
    pub fn new() -> Self {
        Self {
            reset_memory: false,
            gas: None,
            sbrk: 0,
        }
    }

    /// Decides whether the memory of the instance will be reset.
    ///
    /// If the memory is already reset this does nothing.
    ///
    /// Default: `false`
    pub fn reset_memory(&mut self, value: bool) -> &mut Self {
        self.reset_memory = value;
        self
    }

    /// Sets the current remaining gas.
    ///
    /// Default: unset (the current value will not be changed)
    pub fn set_gas(&mut self, gas: Gas) -> &mut Self {
        self.gas = Some(gas);
        self
    }

    /// Increments the guest's heap by the given number of bytes.
    ///
    /// Has exactly the same semantics as the guest-side `sbrk` instruction.
    ///
    /// Default: 0
    pub fn sbrk(&mut self, bytes: u32) -> &mut Self {
        self.sbrk = bytes;
        self
    }
}

pub(crate) type HostcallHandler<'a> = &'a mut dyn for<'r> FnMut(u32, BackendAccess<'r>) -> Result<(), Trap>;

pub(crate) struct ExecuteArgs<'a> {
    pub(crate) entry_point: Option<u32>,
    pub(crate) regs: Option<&'a [RegValue; Reg::ALL.len()]>,
    pub(crate) gas: Option<Gas>,
    pub(crate) sbrk: u32,
    pub(crate) flags: u32,
    pub(crate) hostcall_handler: Option<HostcallHandler<'a>>,
    pub(crate) module: Option<&'a Module>,
    pub(crate) is_async: bool,
}

impl<'a> ExecuteArgs<'a> {
    pub(crate) fn new() -> Self {
        ExecuteArgs {
            entry_point: None,
            regs: None,
            gas: None,
            sbrk: 0,
            flags: 0,
            hostcall_handler: None,
            module: None,
            is_async: false,
        }
    }
}

fn on_hostcall<'a, T>(
    user_data: &'a mut T,
    host_functions: &'a [Option<CallFnArc<T>>],
    imports: Imports<'a>,
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

        let Some(host_fn) = host_functions.get(hostcall as usize).and_then(|func| func.as_ref()) else {
            if let Some(fallback_handler) = fallback_handler {
                if let Some(ref symbol) = imports.get(hostcall) {
                    return Caller::wrap(user_data, &mut access, raw, move |caller| fallback_handler(caller, symbol));
                }
            }

            log::debug!("hostcall to a function which doesn't exist: {}", hostcall);
            return Err(Trap::default());
        };

        if let Err(trap) = host_fn.0.call(user_data, access, raw) {
            log::debug!("hostcall failed: {}", trap);
            return Err(trap);
        }

        Ok(())
    }
}
