use alloc::boxed::Box;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;

use polkavm_common::abi::{MemoryMap, MemoryMapBuilder, VM_ADDR_RETURN_TO_HOST};
use polkavm_common::cast::cast;
use polkavm_common::program::{FrameKind, Imports, InstructionSetKind, Instructions, JumpTable, ProgramBlob, Reg};
use polkavm_common::utils::{ArcBytes, AsUninitSliceMut, B32, B64};

use crate::config::{BackendKind, Config, GasMeteringKind, ModuleConfig, SandboxKind};
use crate::error::{bail, Error};
use crate::gas::{CostModel, CostModelKind, GasVisitor};
use crate::interpreter::InterpretedInstance;
use crate::utils::{GuestInit, InterruptKind};
use crate::{Gas, ProgramCounter};

#[cfg(feature = "module-cache")]
use crate::module_cache::{ModuleCache, ModuleKey};

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum MemoryProtection {
    Read,
    ReadWrite,
}

if_compiler_is_supported! {
    {
        use crate::sandbox::{Sandbox, SandboxInstance};
        use crate::compiler::{CompiledModule, CompilerCache};

        #[cfg(target_os = "linux")]
        use crate::sandbox::linux::Sandbox as SandboxLinux;
        #[cfg(feature = "generic-sandbox")]
        use crate::sandbox::generic::Sandbox as SandboxGeneric;

        pub(crate) struct EngineState {
            pub(crate) sandboxing_enabled: bool,
            pub(crate) sandbox_global: Option<crate::sandbox::GlobalStateKind>,
            compiler_cache: CompilerCache,
            imperfect_logger_filtering_workaround: bool,
            #[cfg(feature = "module-cache")]
            module_cache: ModuleCache,
        }
    } else {
        pub(crate) struct EngineState {
            imperfect_logger_filtering_workaround: bool,
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

    #[cfg(feature = "generic-sandbox")]
    use crate::sandbox::generic;

    #[cfg(feature = "generic-sandbox")]
    impl<T> IntoResult<T> for Result<T, generic::Error> {
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

pub type RegValue = u64;

#[allow(clippy::exhaustive_structs)]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct SetCacheSizeLimitArgs {
    pub max_block_size: u32,
    pub max_cache_size_bytes: usize,
}

pub struct Engine {
    selected_backend: BackendKind,
    #[allow(dead_code)]
    selected_sandbox: Option<SandboxKind>,
    interpreter_enabled: bool,
    crosscheck: bool,
    state: Arc<EngineState>,
    allow_dynamic_paging: bool,
    allow_experimental: bool,
    default_cost_model: CostModelKind,
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

        if !config.sandboxing_enabled {
            if !config.allow_experimental {
                bail!("cannot disable security sandboxing: `set_allow_experimental`/`POLKAVM_ALLOW_EXPERIMENTAL` is not enabled");
            } else {
                log::warn!("SECURITY SANDBOXING IS DISABLED; THIS IS UNSUPPORTED; YOU HAVE BEEN WARNED");
            }
        }

        if !matches!(config.default_cost_model, None | Some(CostModelKind::Full(..))) && !config.allow_experimental {
            bail!("cannot override the default gas cost model: `set_allow_experimental`/`POLKAVM_ALLOW_EXPERIMENTAL` is not enabled");
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

                    let state = Arc::new(EngineState {
                        sandboxing_enabled: config.sandboxing_enabled,
                        sandbox_global: Some(sandbox_global),
                        compiler_cache: Default::default(),

                        imperfect_logger_filtering_workaround: config.imperfect_logger_filtering_workaround,
                        #[cfg(feature = "module-cache")]
                        module_cache,
                    });

                    (Some(selected_sandbox), state)
                } else {
                    (None, Arc::new(EngineState {
                        sandboxing_enabled: config.sandboxing_enabled,
                        sandbox_global: None,
                        compiler_cache: Default::default(),

                        imperfect_logger_filtering_workaround: config.imperfect_logger_filtering_workaround,
                        #[cfg(feature = "module-cache")]
                        module_cache
                    }))
                }
            } else {
                (None, Arc::new(EngineState {
                    imperfect_logger_filtering_workaround: config.imperfect_logger_filtering_workaround,
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
            allow_experimental: config.allow_experimental,
            default_cost_model: config
                .default_cost_model
                .clone()
                .unwrap_or(CostModelKind::Simple(CostModel::naive_ref())),
        })
    }

    /// Returns the backend used by the engine.
    pub fn backend(&self) -> BackendKind {
        self.selected_backend
    }

    /// Returns the PIDs of the idle worker processes. Only useful for debugging.
    pub fn idle_worker_pids(&self) -> Vec<u32> {
        if_compiler_is_supported! {
            {
                self.state.sandbox_global.as_ref().map(|global| global.idle_worker_pids()).unwrap_or_default()
            } else {
                Vec::new()
            }
        }
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
    #[allow(dead_code)]
    engine_state: Option<Arc<EngineState>>,
    #[allow(dead_code)]
    crosscheck: bool,

    blob: ProgramBlob,
    compiled_module: CompiledModuleKind,
    memory_map: MemoryMap,
    gas_metering: Option<GasMeteringKind>,
    is_strict: bool,
    step_tracing: bool,
    dynamic_paging: bool,
    page_size_mask: u32,
    page_shift: u32,
    cost_model: CostModelKind,
    #[cfg(feature = "module-cache")]
    pub(crate) module_key: Option<ModuleKey>,

    is_per_instruction_metering: bool,
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

    fn engine_state_pointer(&self) -> *const EngineState {
        self.state().engine_state.as_ref().map(Arc::as_ptr).unwrap_or(core::ptr::null())
    }

    pub(crate) fn is_per_instruction_metering(&self) -> bool {
        self.state().is_per_instruction_metering
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

    if_compiler_is_supported! {
        pub(crate) fn compiled_module(&self) -> &CompiledModuleKind {
            &self.state().compiled_module
        }
    }

    pub(crate) fn blob(&self) -> &ProgramBlob {
        &self.state().blob
    }

    pub(crate) fn code_len(&self) -> u32 {
        cast(self.state().blob.code().len()).to_u32_or_debug_panic()
    }

    pub(crate) fn instructions_bounded_at(&self, offset: ProgramCounter) -> Instructions<InstructionSetKind> {
        self.state().blob.instructions_bounded_at(offset)
    }

    pub(crate) fn instructions_bounded_at_known_boundary(&self, offset: ProgramCounter) -> Instructions<InstructionSetKind> {
        self.state().blob.instructions_bounded_at_known_boundary(offset)
    }

    pub(crate) fn scan_is_jump_target_valid(&self, offset: ProgramCounter) -> bool {
        self.state().blob.scan_is_jump_target_valid(self.state().blob.isa(), offset)
    }

    pub(crate) fn scan_find_start_of_basic_block(&self, offset: ProgramCounter) -> Option<ProgramCounter> {
        polkavm_common::program::scan_find_start_of_basic_block(
            self.state().blob.isa(),
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

    pub(crate) fn round_to_page_size_up(&self, value: u32) -> u32 {
        self.round_to_page_size_down(value) + (u32::from((value & self.state().page_size_mask) != 0) << self.state().page_shift)
    }

    /// Returns the cost model associated with this module.
    pub fn cost_model(&self) -> &CostModelKind {
        &self.state().cost_model
    }

    if_compiler_is_supported! {
        pub(crate) fn address_to_page(&self, address: u32) -> u32 {
            address >> self.state().page_shift
        }
    }

    /// Creates a new module by deserializing the program from the given `bytes`.
    pub fn new(engine: &Engine, config: &ModuleConfig, bytes: ArcBytes) -> Result<Self, CompileError> {
        let blob = ProgramBlob::parse(bytes).map_err(|error| CompileError::ValidationFailed(error.into()))?;
        Self::from_blob(engine, config, blob)
    }

    /// Creates a new module from a deserialized program `blob`.
    pub fn from_blob(engine: &Engine, config: &ModuleConfig, blob: ProgramBlob) -> Result<Self, CompileError> {
        if config.dynamic_paging() && !engine.allow_dynamic_paging {
            return Err(
                Error::from_static_str("dynamic paging was not enabled; use `Config::set_allow_dynamic_paging` to enable it").into(),
            );
        }

        if config.custom_codegen.is_some() && !engine.allow_experimental {
            return Err(Error::from_static_str(
                "cannot use custom codegen: `set_allow_experimental`/`POLKAVM_ALLOW_EXPERIMENTAL` is not enabled",
            )
            .into());
        }

        if config.is_per_instruction_metering && engine.selected_backend == BackendKind::Compiler {
            return Err(Error::from_static_str("per instruction metering is not supported with the recompiler").into());
        }

        log::trace!(
            "Creating new module from a {}-bit program blob",
            if blob.is_64_bit() { 64 } else { 32 }
        );

        let cost_model = config.cost_model.clone().unwrap_or_else(|| engine.default_cost_model.clone());
        if config.is_per_instruction_metering && !cost_model.is_naive() {
            return Err(Error::from_static_str("per instruction metering is not supported with a non-naive gas cost model").into());
        }

        #[cfg(target_arch = "x86_64")]
        if engine.selected_backend == BackendKind::Compiler && !crate::cpuid::is_bmi2_supported() {
            return Err(Error::from_static_str("on AMD64 the recompiler backend requires a CPU with BMI2 support").into());
        }

        #[cfg(target_arch = "x86_64")]
        if matches!(cost_model, CostModelKind::Full(..)) && !crate::cpuid::is_avx2_supported() {
            return Err(Error::from_static_str("on AMD64 the full gas cost model is only supported on CPUs with AVX2 support").into());
        }

        if engine.selected_backend == BackendKind::Interpreter && matches!(blob.isa(), InstructionSetKind::JamV1) {
            if let Err(pc) = blob.validate_code_with_isa(polkavm_common::program::ISA_JamV1) {
                return Err(CompileError::ValidationFailed(format!("validation failed at offset {pc}")));
            }
        }

        #[cfg(feature = "module-cache")]
        let module_key = {
            let (module_key, module) = engine.state.module_cache.get(config, &blob, &cost_model);
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
            .aux_data_size(config.aux_data_size())
            .build()
            .map_err(|error| CompileError::ValidationFailed(error.into()))?;

        if config.is_strict || cfg!(debug_assertions) {
            log::trace!("Checking imports...");
            for (nth_import, import) in blob.imports().into_iter().enumerate() {
                if let Some(ref import) = import {
                    log::trace!("  Import #{}: {}", nth_import, import);
                } else {
                    log::trace!("  Import #{}: INVALID", nth_import);
                    if config.is_strict {
                        return Err(Error::from_static_str("found an invalid import").into());
                    }
                }
            }

            log::trace!("Checking jump table...");
            for (nth_entry, code_offset) in blob.jump_table().iter().enumerate() {
                if cast(code_offset.0).to_usize() >= blob.code().len() {
                    log::trace!(
                        "  Invalid jump table entry #{nth_entry}: {code_offset} (should be less than {})",
                        blob.code().len()
                    );
                    if config.is_strict {
                        return Err(Error::from_static_str("out of range jump table entry found").into());
                    }
                }
            }
        };

        if_compiler_is_supported! {
            let exports = {
                log::trace!("Parsing exports...");
                let mut exports = Vec::with_capacity(1);
                for export in blob.exports() {
                    log::trace!("  Export at {}: {}", export.program_counter(), export.symbol());
                    if config.is_strict && cast(export.program_counter().0).to_usize() >= blob.code().len() {
                        return Err(Error::from_display(format!(
                            "out of range export found; export {} points to code offset {}, while the code blob is only {} bytes",
                            export.symbol(),
                            export.program_counter(),
                            blob.code().len(),
                        )).into());
                    }

                    exports.push(export);
                }
                exports
            };
        }

        let init = GuestInit {
            page_size: config.page_size,
            ro_data: blob.ro_data(),
            rw_data: blob.rw_data(),
            ro_data_size: blob.ro_data_size(),
            rw_data_size: blob.rw_data_size(),
            stack_size: blob.stack_size(),
            aux_data_size: config.aux_data_size(),
        };

        #[allow(unused_macros)]
        macro_rules! compile_module {
            ($sandbox_kind:ident, $bitness_kind:ident, $build_static_dispatch_table:ident, $visitor_name:ident, $module_kind:ident) => {
                match cost_model {
                    CostModelKind::Simple(ref cost_model) => {
                        compile_module!(
                            $sandbox_kind,
                            $bitness_kind,
                            $build_static_dispatch_table,
                            $visitor_name,
                            $module_kind,
                            GasVisitor,
                            GasVisitor,
                            GasVisitor::new(cost_model.clone())
                        )
                    }
                    CostModelKind::Full(cost_model) => {
                        use polkavm_common::simulator::Simulator;
                        let gas_visitor = Simulator::<$bitness_kind, ()>::new(blob.code(), blob.isa(), cost_model, ());
                        compile_module!(
                            $sandbox_kind,
                            $bitness_kind,
                            $build_static_dispatch_table,
                            $visitor_name,
                            $module_kind,
                            Simulator::<'a, $bitness_kind, ()>,
                            Simulator::<$bitness_kind, ()>,
                            gas_visitor
                        )
                    }
                }
            };

            ($sandbox_kind:ident, $bitness_kind:ident, $build_static_dispatch_table:ident, $visitor_name:ident, $module_kind:ident, $gas_kind:ty, $gas_kind_no_lifetime:ty, $gas_visitor:expr) => {{
                type VisitorTy<'a> = crate::compiler::CompilerVisitor<'a, $sandbox_kind, $bitness_kind, $gas_kind>;
                let (mut visitor, aux) = crate::compiler::CompilerVisitor::<$sandbox_kind, $bitness_kind, $gas_kind_no_lifetime>::new(
                    &engine.state.compiler_cache,
                    config,
                    blob.isa(),
                    blob.jump_table(),
                    blob.code(),
                    blob.bitmask(),
                    &exports,
                    config.step_tracing || engine.crosscheck,
                    cast(blob.code().len()).to_u32_or_panic(),
                    init,
                    $gas_visitor,
                )?;

                blob.visit(
                    polkavm_common::program::$build_static_dispatch_table!($visitor_name, VisitorTy<'a>),
                    &mut visitor,
                );

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
                                match blob.isa() {
                                    InstructionSetKind::ReviveV1 => compile_module!(SandboxLinux, B64, build_static_dispatch_table_revive_v1, COMPILER_VISITOR_LINUX, Linux),
                                    InstructionSetKind::JamV1 => compile_module!(SandboxLinux, B64, build_static_dispatch_table_jam_v1, COMPILER_VISITOR_LINUX, Linux),
                                    InstructionSetKind::Latest32 => compile_module!(SandboxLinux, B32, build_static_dispatch_table_latest32, COMPILER_VISITOR_LINUX, Linux),
                                    InstructionSetKind::Latest64 => compile_module!(SandboxLinux, B64, build_static_dispatch_table_latest64, COMPILER_VISITOR_LINUX, Linux),
                                }

                                #[cfg(not(target_os = "linux"))]
                                {
                                    log::debug!("Selecetd sandbox unavailable: 'linux'");
                                    None
                                }
                            },
                            SandboxKind::Generic => {
                                #[cfg(feature = "generic-sandbox")]
                                match blob.isa() {
                                    InstructionSetKind::ReviveV1 => compile_module!(SandboxGeneric, B64, build_static_dispatch_table_revive_v1, COMPILER_VISITOR_GENERIC, Generic),
                                    InstructionSetKind::JamV1 => compile_module!(SandboxGeneric, B64, build_static_dispatch_table_jam_v1, COMPILER_VISITOR_GENERIC, Generic),
                                    InstructionSetKind::Latest32 => compile_module!(SandboxGeneric, B32, build_static_dispatch_table_latest32, COMPILER_VISITOR_GENERIC, Generic),
                                    InstructionSetKind::Latest64 => compile_module!(SandboxGeneric, B64, build_static_dispatch_table_latest64, COMPILER_VISITOR_GENERIC, Generic),
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

        let compiled_module = compiled_module.unwrap_or(CompiledModuleKind::Unavailable);
        log::trace!("Processing finished!");

        assert!(compiled_module.is_some() || engine.interpreter_enabled);
        if compiled_module.is_some() {
            log::debug!("Backend used: 'compiled'");
        } else {
            log::debug!("Backend used: 'interpreted'");
        }

        let memory_map = init.memory_map().map_err(|error| CompileError::ValidationFailed(error.into()))?;
        log::debug!(
            "  Memory map: RO data: 0x{:08x}..0x{:08x} ({}/{} bytes, non-zero until 0x{:08x})",
            memory_map.ro_data_range().start,
            memory_map.ro_data_range().end,
            blob.ro_data().len(),
            memory_map.ro_data_range().len(),
            cast(memory_map.ro_data_range().start).to_usize() + blob.ro_data().len(),
        );
        log::debug!(
            "  Memory map: RW data: 0x{:08x}..0x{:08x} ({}/{} bytes, non-zero until 0x{:08x})",
            memory_map.rw_data_range().start,
            memory_map.rw_data_range().end,
            blob.rw_data().len(),
            memory_map.rw_data_range().len(),
            cast(memory_map.rw_data_range().start).to_usize() + blob.rw_data().len(),
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
            memory_map,
            gas_metering: config.gas_metering,
            is_strict: config.is_strict,
            step_tracing: config.step_tracing,
            dynamic_paging: config.dynamic_paging,
            crosscheck: engine.crosscheck,
            page_size_mask,
            page_shift,
            cost_model,
            is_per_instruction_metering: config.is_per_instruction_metering,

            #[cfg(feature = "module-cache")]
            module_key,
        });

        #[cfg(feature = "module-cache")]
        if let Some(module_key) = module_key {
            return Ok(engine.state.module_cache.insert(module_key, module));
        }

        Ok(Module(Some(module)))
    }

    /// Returns whether the module is 64-bit.
    pub fn is_64_bit(&self) -> bool {
        self.state().blob.is_64_bit()
    }

    /// Fetches a cached module for the given `blob`.
    #[cfg_attr(not(feature = "module-cache"), allow(unused_variables))]
    pub fn from_cache(engine: &Engine, config: &ModuleConfig, blob: &ProgramBlob) -> Option<Self> {
        #[cfg(feature = "module-cache")]
        {
            let cost_model = config.cost_model.clone().unwrap_or_else(|| engine.default_cost_model.clone());
            let (_, module) = engine.state.module_cache.get(config, blob, &cost_model);
            module
        }

        #[cfg(not(feature = "module-cache"))]
        None
    }

    /// Instantiates a new module.
    pub fn instantiate(&self) -> Result<RawInstance, Error> {
        self.instantiate_impl(None)
    }

    /// Instantiates a new module with a given outer instance.
    ///
    /// This should be used over plain `instantiate` in cases where the given `outer_instance`
    /// is going to control the newly spawned instance.
    ///
    /// Currently this makes no functional difference and only affects performance.
    ///
    /// The outer instance *must* come from the same `Engine`.
    pub fn instantiate_nested(&self, outer_instance: &RawInstance) -> Result<RawInstance, Error> {
        self.instantiate_impl(Some(outer_instance))
    }

    fn instantiate_impl(&self, outer_instance: Option<&RawInstance>) -> Result<RawInstance, Error> {
        let compiled_module = &self.state().compiled_module;
        let Some(engine_state) = self.state().engine_state.as_ref() else {
            return Err(Error::from_static_str("failed to instantiate module: empty module"));
        };

        let backend = if_compiler_is_supported! {
            {{
                match compiled_module {
                    #[cfg(target_os = "linux")]
                    CompiledModuleKind::Linux(..) => {
                        let outer_instance = match outer_instance {
                            Some(outer_instance) => {
                                let outer_module = &outer_instance.module;
                                #[allow(clippy::match_wildcard_for_single_variants)]
                                match outer_instance.backend {
                                    InstanceBackend::CompiledLinux(ref outer_instance) if outer_module.engine_state_pointer() == self.engine_state_pointer() => Some(outer_instance),
                                    _ => return Err(Error::from_static_str("failed to instantiate module: received incompatible outer instance")),
                                }
                            },
                            None => None,
                        };
                        let compiled_instance = SandboxInstance::<SandboxLinux>::spawn_and_load_module(Arc::clone(engine_state), self, outer_instance)?;
                        Some(InstanceBackend::CompiledLinux(compiled_instance))
                    },
                    #[cfg(feature = "generic-sandbox")]
                    CompiledModuleKind::Generic(..) => {
                        let outer_instance = match outer_instance {
                            Some(outer_instance) => {
                                let outer_module = &outer_instance.module;
                                #[allow(clippy::match_wildcard_for_single_variants)]
                                match outer_instance.backend {
                                    InstanceBackend::CompiledGeneric(ref outer_instance) if outer_module.engine_state_pointer() == self.engine_state_pointer() => Some(outer_instance),
                                    _ => return Err(Error::from_static_str("failed to instantiate module: received incompatible outer instance")),
                                }
                            },
                            None => None,
                        };
                        let compiled_instance = SandboxInstance::<SandboxGeneric>::spawn_and_load_module(Arc::clone(engine_state), self, outer_instance)?;
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
            None => {
                if let Some(outer_instance) = outer_instance {
                    let outer_module = &outer_instance.module;
                    #[allow(clippy::match_wildcard_for_single_variants)]
                    match outer_instance.backend {
                        InstanceBackend::Interpreted(..) if outer_module.engine_state_pointer() == self.engine_state_pointer() => {}
                        _ => {
                            return Err(Error::from_static_str(
                                "failed to instantiate module: received incompatible outer instance",
                            ))
                        }
                    }
                }

                InstanceBackend::Interpreted(InterpretedInstance::new_from_module(
                    self.clone(),
                    false,
                    engine_state.imperfect_logger_filtering_workaround,
                ))
            }
        };

        let crosscheck_instance = if_compiler_is_supported! {
            {
                if self.state().crosscheck && !matches!(backend, InstanceBackend::Interpreted(..)) {
                    Some(Box::new(InterpretedInstance::new_from_module(self.clone(), true, false)))
                } else {
                    None
                }
            } else {
                None
            }
        };

        Ok(RawInstance {
            module: self.clone(),
            backend,
            crosscheck_instance,
            host_side_aux_write_protect: false,
        })
    }

    /// The program's memory map.
    pub fn memory_map(&self) -> &MemoryMap {
        &self.state().memory_map
    }

    /// The default stack pointer for the module.
    pub fn default_sp(&self) -> RegValue {
        u64::from(self.memory_map().stack_address_high())
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
        if !self.scan_is_jump_target_valid(code_offset) && code_offset.0 < self.code_len() {
            return None;
        }

        let gas = match self.state().cost_model {
            CostModelKind::Simple(ref cost_model) => {
                let gas_visitor = GasVisitor::new(cost_model.clone());
                let instructions = self.instructions_bounded_at(code_offset);
                crate::gas::calculate_for_block(gas_visitor, instructions)
            }
            CostModelKind::Full(cost_model) => {
                use polkavm_common::simulator::Simulator;
                let instructions = self.instructions_bounded_at(code_offset);
                if self.is_64_bit() {
                    let gas_visitor = Simulator::<B64, ()>::new(self.blob().code(), self.blob().isa(), cost_model, ());
                    crate::gas::calculate_for_block(gas_visitor, instructions)
                } else {
                    let gas_visitor = Simulator::<B32, ()>::new(self.blob().code(), self.blob().isa(), cost_model, ());
                    crate::gas::calculate_for_block(gas_visitor, instructions)
                }
            }
        };

        Some(i64::from(gas.0))
    }

    #[cold]
    fn display_instruction_at(&self, program_counter: ProgramCounter) -> impl core::fmt::Display {
        let state = self.state();
        Self::display_instruction_at_impl(
            state.blob.isa(),
            state.blob.code(),
            state.blob.bitmask(),
            state.blob.is_64_bit(),
            program_counter,
        )
    }

    #[cold]
    pub(crate) fn display_instruction_at_impl(
        instruction_set: InstructionSetKind,
        code: &[u8],
        bitmask: &[u8],
        is_64_bit: bool,
        program_counter: ProgramCounter,
    ) -> impl core::fmt::Display {
        struct MaybeInstruction(Option<polkavm_common::program::ParsedInstruction>, bool);
        impl core::fmt::Display for MaybeInstruction {
            fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
                if let Some(instruction) = self.0 {
                    let mut format = polkavm_common::program::InstructionFormat::default();
                    format.is_64_bit = self.1;
                    instruction.display(&format).fmt(fmt)?;
                    Ok(())
                } else {
                    write!(fmt, "<NONE>")
                }
            }
        }

        MaybeInstruction(
            Instructions::new_bounded(instruction_set, code, bitmask, program_counter.0).next(),
            is_64_bit,
        )
    }

    pub(crate) fn debug_print_location(&self, log_level: log::Level, pc: ProgramCounter) {
        log::log!(log_level, "  Location: #{pc}: {}", self.display_instruction_at(pc));

        let Ok(Some(mut line_program)) = self.state().blob.get_debug_line_program_at(pc) else {
            return;
        };

        log::log!(log_level, "  Source location:");
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
    MemoryLimitReached,
    Error(Error),
}

impl core::error::Error for MemoryAccessError {}

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
            MemoryAccessError::MemoryLimitReached => {
                write!(fmt, "memory limit reached")
            }
            MemoryAccessError::Error(error) => {
                write!(fmt, "memory access failed: {error}")
            }
        }
    }
}

impl From<MemoryAccessError> for alloc::string::String {
    fn from(error: MemoryAccessError) -> alloc::string::String {
        alloc::string::ToString::to_string(&error)
    }
}

/// Compilation failed.
#[derive(Debug)]
pub enum CompileError {
    /// The module has failed validation.
    ValidationFailed(String),
    Error(Error),
}

impl From<Error> for CompileError {
    fn from(error: Error) -> Self {
        Self::Error(error)
    }
}

impl From<CompileError> for Error {
    fn from(error: CompileError) -> Self {
        match error {
            CompileError::Error(error) => error,
            error @ CompileError::ValidationFailed(..) => Error::from_display(error),
        }
    }
}

impl From<CompileError> for String {
    fn from(error: CompileError) -> Self {
        error.to_string()
    }
}

impl core::error::Error for CompileError {}

impl core::fmt::Display for CompileError {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            CompileError::ValidationFailed(error) => {
                write!(fmt, "module validation failed: {error}")
            }
            CompileError::Error(error) => error.fmt(fmt),
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
    host_side_aux_write_protect: bool,
}

impl RawInstance {
    /// Returns the module from which this instance was created.
    pub fn module(&self) -> &Module {
        &self.module
    }

    /// Returns whether we're running a 64-bit program.
    pub fn is_64_bit(&self) -> bool {
        self.module.is_64_bit()
    }

    #[cold]
    #[inline(never)]
    fn on_trap(&self) {
        use crate::program::Instruction;

        if !log::log_enabled!(log::Level::Debug) {
            return;
        }

        if let Some(program_counter) = self.program_counter() {
            self.module.debug_print_location(log::Level::Debug, program_counter);
            if let Some(instruction) = self.module.instructions_bounded_at(program_counter).next() {
                let (base, offset, length) = match instruction.kind {
                    Instruction::load_indirect_u8(_, base, offset)
                    | Instruction::load_indirect_i8(_, base, offset)
                    | Instruction::store_indirect_u8(_, base, offset)
                    | Instruction::store_imm_indirect_u8(base, offset, _) => (Some(base), offset, 1),
                    Instruction::load_indirect_u16(_, base, offset)
                    | Instruction::load_indirect_i16(_, base, offset)
                    | Instruction::store_indirect_u16(_, base, offset)
                    | Instruction::store_imm_indirect_u16(base, offset, _) => (Some(base), offset, 2),
                    Instruction::load_indirect_u32(_, base, offset)
                    | Instruction::load_indirect_i32(_, base, offset)
                    | Instruction::store_indirect_u32(_, base, offset)
                    | Instruction::store_imm_indirect_u32(base, offset, _) => (Some(base), offset, 4),
                    Instruction::load_indirect_u64(_, base, offset)
                    | Instruction::store_indirect_u64(_, base, offset)
                    | Instruction::store_imm_indirect_u64(base, offset, _) => (Some(base), offset, 8),
                    Instruction::load_u8(_, offset)
                    | Instruction::load_i8(_, offset)
                    | Instruction::store_u8(_, offset)
                    | Instruction::store_imm_u8(offset, _) => (None, offset, 1),
                    Instruction::load_u16(_, offset)
                    | Instruction::load_i16(_, offset)
                    | Instruction::store_u16(_, offset)
                    | Instruction::store_imm_u16(offset, _) => (None, offset, 2),
                    Instruction::load_u32(_, offset)
                    | Instruction::load_i32(_, offset)
                    | Instruction::store_u32(_, offset)
                    | Instruction::store_imm_u32(offset, _) => (None, offset, 4),
                    Instruction::load_u64(_, offset) | Instruction::store_u64(_, offset) | Instruction::store_imm_u64(offset, _) => {
                        (None, offset, 8)
                    }
                    _ => return,
                };

                let mut offset = cast(i64::from(offset)).bitwise_as_u64();
                if let Some(base) = base {
                    offset = offset.wrapping_add(self.reg(base.get()));
                }

                offset &= 0xffffffff;
                let offset_end = offset.wrapping_add(length) & 0xffffffff;

                log::debug!("Trapped when trying to access address: 0x{offset:08x}-0x{offset_end:08x}");
                if !self.module.is_dynamic_paging() {
                    let aux_address = u64::from(self.module.memory_map().aux_data_address());
                    let aux_size = u64::from(self.module.memory_map().aux_data_size());
                    let stack_address_hi = u64::from(self.module.memory_map().stack_address_high());
                    let stack_address_lo = u64::from(self.module.memory_map().stack_address_low());
                    if offset >= aux_address {
                        if aux_size > 0 {
                            let aux_address_end = aux_address + aux_size;
                            log::debug!("  Auxiliary data range: 0x{aux_address:08x}..0x{aux_address_end:08x}");
                        }
                    } else if offset < stack_address_hi && offset >= stack_address_lo.wrapping_sub(32 * 1024 * 1024) {
                        log::debug!("  Current stack range: 0x{stack_address_lo:08x}-0x{stack_address_hi:08x}");
                        log::debug!("  Hint: try increasing your stack size with: 'polkavm_derive::min_stack_size'");
                    }
                }
            }
        }
    }

    /// Starts or resumes the execution.
    #[inline(always)]
    pub fn run(&mut self) -> Result<InterruptKind, Error> {
        if self.next_program_counter().is_none() {
            return Err(Error::from_static_str("failed to run: next program counter is not set"));
        }

        if self.gas() < 0 {
            return Ok(InterruptKind::NotEnoughGas);
        }

        if self.crosscheck_instance.is_some() || log::log_enabled!(log::Level::Debug) {
            self.run_impl_debug()
        } else {
            self.run_impl::<false>()
        }
    }

    #[inline(never)]
    #[cold]
    fn run_impl_debug(&mut self) -> Result<InterruptKind, Error> {
        self.run_impl::<true>()
    }

    #[inline(always)]
    fn run_impl<const DEBUG: bool>(&mut self) -> Result<InterruptKind, Error> {
        #[allow(clippy::never_loop)]
        loop {
            let (interruption, gas) = access_backend!(self.backend, |mut backend| {
                let interruption = backend.run().map_err(|error| format!("execution failed: {error}"));
                let gas = backend.gas();
                (interruption, gas)
            });

            let mut interruption = interruption?;
            if DEBUG {
                log::trace!("Interrupted: {:?}", interruption);
                if matches!(interruption, InterruptKind::Trap) {
                    self.on_trap();
                }
            }

            if_compiler_is_supported! {
                if DEBUG && self.crosscheck_instance.is_some() {
                    let is_step = matches!(interruption, InterruptKind::Step);
                    self.crosscheck(interruption.clone());

                    if is_step && !self.module().state().step_tracing {
                        continue;
                    }
                }
            }

            if gas < 0 {
                interruption = InterruptKind::NotEnoughGas;
            }

            break Ok(interruption);
        }
    }

    #[allow(dead_code)]
    #[inline(never)]
    #[cold]
    fn crosscheck(&mut self, interruption: InterruptKind) {
        let Some(ref mut crosscheck) = self.crosscheck_instance else {
            unreachable!()
        };
        let expected_interruption = crosscheck.run().expect("crosscheck failed");
        if interruption != expected_interruption {
            panic!("run: crosscheck mismatch, interpreter = {expected_interruption:?}, backend = {interruption:?}");
        }

        if self.module.gas_metering() != Some(GasMeteringKind::Async) {
            for reg in Reg::ALL {
                let value = access_backend!(self.backend, |backend| backend.reg(reg));
                let expected_value = crosscheck.reg(reg);
                if value != expected_value {
                    panic!("run: crosscheck mismatch for {reg}, interpreter = 0x{expected_value:x}, backend = 0x{value:x}");
                }
            }
        }

        let crosscheck_gas = crosscheck.gas();
        let crosscheck_program_counter = crosscheck.program_counter();
        let crosscheck_next_program_counter = crosscheck.next_program_counter();
        if self.module.gas_metering() != Some(GasMeteringKind::Async) {
            let gas = self.gas();
            if gas != crosscheck_gas {
                panic!("run: crosscheck mismatch for gas, interpreter = {crosscheck_gas}, backend = {gas}");
            }
        }

        if self.program_counter() != crosscheck_program_counter {
            panic!(
                "run: crosscheck mismatch for program counter, interpreter = {crosscheck_program_counter:?}, backend = {:?}",
                self.program_counter()
            );
        }

        if self.next_program_counter() != crosscheck_next_program_counter {
            panic!(
                "run: crosscheck mismatch for next program counter, interpreter = {crosscheck_next_program_counter:?}, backend = {:?}",
                self.next_program_counter()
            );
        }

        if !matches!(interruption, InterruptKind::Step | InterruptKind::Segfault(..)) {
            self.crosscheck_memory();
        }
    }

    #[allow(dead_code)]
    #[inline(never)]
    #[cold]
    fn crosscheck_memory(&mut self) {
        let Some(ref mut crosscheck) = self.crosscheck_instance else {
            unreachable!()
        };

        let map = self.module.memory_map();
        let regions: Vec<(u32, u32)> = if self.module.is_dynamic_paging() {
            crosscheck
                .dynamic_memory_page_addresses()
                .map(|address| (address, map.page_size()))
                .collect()
        } else {
            let heap_size = access_backend!(self.backend, |backend| backend.heap_size());
            let expected_heap_size = crosscheck.heap_size();
            if heap_size != expected_heap_size {
                panic!("run: crosscheck mismatch for heap size, interpreter = {expected_heap_size}, backend = {heap_size}");
            }

            let aux_size = access_backend!(self.backend, |backend| backend.accessible_aux_size());
            let expected_aux_size = crosscheck.accessible_aux_size();
            if aux_size != expected_aux_size {
                panic!("run: crosscheck mismatch for accessible aux size, interpreter = {expected_aux_size}, backend = {aux_size}");
            }

            let heap_top = self.module.round_to_page_size_up(map.heap_base() + heap_size);
            [
                map.ro_data_range(),
                map.rw_data_address()..heap_top,
                map.stack_range(),
                map.aux_data_address()..map.aux_data_address() + aux_size,
            ]
            .into_iter()
            .filter(|range| !range.is_empty())
            .map(|range| (range.start, range.end - range.start))
            .collect()
        };

        let capacity = regions.iter().map(|&(_, length)| cast(length).to_usize()).max().unwrap_or(0);
        let mut buffer: Vec<u8> = Vec::with_capacity(capacity);
        let mut expected_buffer: Vec<u8> = Vec::with_capacity(capacity);
        for (address, length) in regions {
            if self.module.is_dynamic_paging() {
                for protection in [MemoryProtection::Read, MemoryProtection::ReadWrite] {
                    let is_accessible = access_backend!(self.backend, |backend| backend.is_memory_accessible(address, length, protection));
                    let expected_is_accessible = crosscheck.is_memory_accessible(address, length, protection);
                    if is_accessible != expected_is_accessible {
                        panic!("run: crosscheck mismatch for {protection:?} access to the page at 0x{address:x}, interpreter = {expected_is_accessible}, backend = {is_accessible}");
                    }
                }
            }

            let length = cast(length).to_usize();
            let result = access_backend!(self.backend, |mut backend| backend
                .read_memory_into(address, &mut buffer.spare_capacity_mut()[..length]));
            let expected_result = crosscheck.read_memory_into(address, &mut expected_buffer.spare_capacity_mut()[..length]);
            match (result, expected_result) {
                (Ok(data), Ok(expected_data)) if data != expected_data => {
                    let offset = data.iter().zip(expected_data.iter()).take_while(|(lhs, rhs)| lhs == rhs).count();
                    panic!(
                        "run: crosscheck mismatch for memory at 0x{:x}, interpreter = 0x{:02x}, backend = 0x{:02x}",
                        u64::from(address) + cast(offset).to_u64(),
                        expected_data[offset],
                        data[offset]
                    );
                }
                (Ok(_), Ok(_)) | (Err(_), Err(_)) => {}
                (result, expected_result) => {
                    let expected_success = expected_result.is_ok();
                    let success = result.is_ok();
                    panic!(
                        "run: crosscheck mismatch for memory read at 0x{address:x}, interpreter = {expected_success}, backend = {success}"
                    );
                }
            }
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

    /// Sets the accessible region of the aux data, rounded up to the nearest page size.
    pub fn set_accessible_aux_size(&mut self, size: u32) -> Result<(), Error> {
        if self.module.is_dynamic_paging() {
            return Err("setting accessible aux size is only possible on modules without dynamic paging".into());
        }

        if size > self.module.memory_map().aux_data_size() {
            return Err(format!(
                "cannot set accessible aux size: the maximum is {}, while tried to set {}",
                self.module.memory_map().aux_data_size(),
                size
            )
            .into());
        }

        let size = self.module.round_to_page_size_up(size);
        if let Some(ref mut crosscheck) = self.crosscheck_instance {
            crosscheck.set_accessible_aux_size(size);
        }

        access_backend!(self.backend, |mut backend| backend
            .set_accessible_aux_size(size)
            .into_result("failed to set accessible aux size"))?;

        debug_assert_eq!(access_backend!(self.backend, |backend| backend.accessible_aux_size()), size);
        Ok(())
    }

    /// Sets whether the aux data region is write-protected on the host-side.
    ///
    /// This affects `write_memory`, `zero_memory` and `is_memory_accessible`.
    ///
    /// Will return an error if called on an instance with dynamic paging enabled.
    /// Infallible otherwise.
    pub fn set_host_side_aux_write_protect(&mut self, is_write_protected: bool) -> Result<(), Error> {
        if self.module.is_dynamic_paging() {
            return Err("write-protecting the aux data region is only possible on modules without dynamic paging".into());
        }

        self.host_side_aux_write_protect = is_write_protected;
        Ok(())
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

    /// Returns whether a given chunk of memory is accessible.
    ///
    /// If `size` is zero then this will always return `true`.
    pub fn is_memory_accessible(&self, address: u32, size: u32, minimum_protection: MemoryProtection) -> bool {
        if size == 0 {
            return true;
        }

        if address < 0x10000 {
            return false;
        }

        let upper_limit = match minimum_protection {
            MemoryProtection::Read => 0x100000000,
            MemoryProtection::ReadWrite => self.get_write_upper_limit(),
        };

        if u64::from(address) + cast(size).to_u64() > upper_limit {
            return false;
        }

        #[inline]
        fn is_within(range: core::ops::Range<u32>, address: u32, size: u32) -> bool {
            let address_end = u64::from(address) + cast(size).to_u64();
            address >= range.start && address_end <= u64::from(range.end)
        }

        if !self.module.is_dynamic_paging() {
            let map = self.module.memory_map();
            if is_within(map.stack_range(), address, size) {
                return true;
            }

            let heap_size = self.heap_size();
            let heap_top = map.heap_base() + heap_size;
            let heap_top = self.module.round_to_page_size_up(heap_top);
            if is_within(map.rw_data_address()..heap_top, address, size) {
                return true;
            }

            let aux_size = access_backend!(self.backend, |backend| backend.accessible_aux_size());
            if is_within(map.aux_data_address()..map.aux_data_address() + aux_size, address, size) {
                return true;
            }

            if matches!(minimum_protection, MemoryProtection::Read) && is_within(map.ro_data_range(), address, size) {
                return true;
            }

            false
        } else {
            access_backend!(self.backend, |backend| backend.is_memory_accessible(
                address,
                size,
                minimum_protection
            ))
        }
    }

    /// Reads the VM's memory.
    ///
    /// The whole memory region must be readable.
    pub fn read_memory_into<'slice, B>(&mut self, address: u32, buffer: &'slice mut B) -> Result<&'slice mut [u8], MemoryAccessError>
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
                length: cast(slice.len()).to_u64(),
            });
        }

        if u64::from(address) + cast(slice.len()).to_u64() > 0x100000000 {
            return Err(MemoryAccessError::OutOfRangeAccess {
                address,
                length: cast(slice.len()).to_u64(),
            });
        }

        let length = slice.len();
        let result = access_backend!(self.backend, |mut backend| backend.read_memory_into(address, slice));
        if let Some(ref mut crosscheck) = self.crosscheck_instance {
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
                let address_end = u64::from(address) + cast(length).to_u64();
                if cfg!(debug_assertions) {
                    if let (Ok(result), Ok(expected_result)) = (result, expected_result) {
                        log::trace!("read_memory result (interpreter): {expected_result:?}");
                        log::trace!("read_memory result (backend):     {result:?}");
                    }
                }
                panic!("read_memory: crosscheck mismatch, range = 0x{address:x}..0x{address_end:x}, interpreter = {expected_success}, backend = {success}");
            }
        }

        if cfg!(debug_assertions) {
            let is_inaccessible = !self.is_memory_accessible(address, cast(length).to_u32_or_panic(), MemoryProtection::Read);
            if is_inaccessible != matches!(result, Err(MemoryAccessError::OutOfRangeAccess { .. })) {
                panic!(
                    "'read_memory_into' doesn't match with 'is_memory_accessible' for 0x{:x}-0x{:x} (read_memory_into = {:?}, is_memory_accessible = {})",
                    address,
                    cast(address).to_usize() + length,
                    result.map(|_| ()),
                    !is_inaccessible,
                );
            }
        }

        result
    }

    fn get_write_upper_limit(&self) -> u64 {
        if self.host_side_aux_write_protect {
            debug_assert!(!self.module.is_dynamic_paging());
            u64::from(self.module.memory_map().stack_address_high())
        } else {
            0x100000000
        }
    }

    /// Writes into the VM's memory.
    ///
    /// The whole memory region must be writable.
    pub fn write_memory(&mut self, address: u32, data: &[u8]) -> Result<(), MemoryAccessError> {
        if data.is_empty() {
            return Ok(());
        }

        if address < 0x10000 {
            return Err(MemoryAccessError::OutOfRangeAccess {
                address,
                length: cast(data.len()).to_u64(),
            });
        }

        if u64::from(address) + cast(data.len()).to_u64() > self.get_write_upper_limit() {
            return Err(MemoryAccessError::OutOfRangeAccess {
                address,
                length: cast(data.len()).to_u64(),
            });
        }

        let result = access_backend!(self.backend, |mut backend| backend.write_memory(address, data));
        if let Some(ref mut crosscheck) = self.crosscheck_instance {
            let expected_result = crosscheck.write_memory(address, data);
            let expected_success = expected_result.is_ok();
            let success = result.is_ok();
            if success != expected_success {
                let address_end = u64::from(address) + cast(data.len()).to_u64();
                panic!("write_memory: crosscheck mismatch, range = 0x{address:x}..0x{address_end:x}, interpreter = {expected_success}, backend = {success}");
            }
        }

        if cfg!(debug_assertions) {
            let is_inaccessible = !self.is_memory_accessible(address, cast(data.len()).to_u32_or_panic(), MemoryProtection::ReadWrite);
            if is_inaccessible != matches!(result, Err(MemoryAccessError::OutOfRangeAccess { .. })) {
                panic!(
                    "'write_memory' doesn't match with 'is_memory_accessible' for 0x{:x}-0x{:x} (write_memory = {:?}, is_memory_accessible = {})",
                    address,
                    cast(address).to_usize() + data.len(),
                    result,
                    !is_inaccessible,
                );
            }
        }

        result
    }

    /// Reads the VM's memory.
    ///
    /// The whole memory region must be readable.
    pub fn read_memory(&mut self, address: u32, length: u32) -> Result<Vec<u8>, MemoryAccessError> {
        let mut buffer = Vec::new();
        buffer.reserve_exact(cast(length).to_usize());

        let pointer = buffer.as_ptr();
        let slice = self.read_memory_into(address, buffer.spare_capacity_mut())?;

        // Since `read_memory_into_slice` returns a `&mut [u8]` we can be sure it initialized the buffer
        // we've passed to it, as long as it's actually the same buffer we gave it.
        assert_eq!(slice.as_ptr(), pointer);
        assert_eq!(slice.len(), cast(length).to_usize());

        #[allow(unsafe_code)]
        // SAFETY: `read_memory_into_slice` initialized this buffer, and we've verified this with `assert`s.
        unsafe {
            buffer.set_len(cast(length).to_usize());
        }

        Ok(buffer)
    }

    /// A convenience function to read an `u64` from the VM's memory.
    ///
    /// This is equivalent to calling [`RawInstance::read_memory_into`].
    pub fn read_u64(&mut self, address: u32) -> Result<u64, MemoryAccessError> {
        let mut buffer = [0; 8];
        self.read_memory_into(address, &mut buffer)?;

        Ok(u64::from_le_bytes(buffer))
    }

    /// A convenience function to write an `u64` into the VM's memory.
    ///
    /// This is equivalent to calling [`RawInstance::write_memory`].
    pub fn write_u64(&mut self, address: u32, value: u64) -> Result<(), MemoryAccessError> {
        self.write_memory(address, &value.to_le_bytes())
    }

    /// A convenience function to read an `u32` from the VM's memory.
    ///
    /// This is equivalent to calling [`RawInstance::read_memory_into`].
    pub fn read_u32(&mut self, address: u32) -> Result<u32, MemoryAccessError> {
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
    pub fn read_u16(&mut self, address: u32) -> Result<u16, MemoryAccessError> {
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
    pub fn read_u8(&mut self, address: u32) -> Result<u8, MemoryAccessError> {
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

    /// Fills the given memory region with zeros and changes memory protection flags. Similar to [`RawInstance::zero_memory`], but can only be called when dynamic paging is enabled.
    ///
    /// `address` must be a multiple of the page size. The value of `length` will be rounded up to the nearest multiple of the page size.
    /// If `length` is zero then this call has no effect.
    ///
    /// Can be used to resolve a segfault. It can also be used to preemptively initialize pages for which no segfault is currently triggered.
    pub fn zero_memory_with_memory_protection(
        &mut self,
        address: u32,
        length: u32,
        memory_protection: MemoryProtection,
    ) -> Result<(), MemoryAccessError> {
        if !self.module.is_dynamic_paging() {
            return Err(MemoryAccessError::Error(
                "'zero_memory_with_memory_protection' is only possible on modules with dynamic paging".into(),
            ));
        }

        if length == 0 {
            return Ok(());
        }

        if !self.module.is_multiple_of_page_size(address) {
            return Err(MemoryAccessError::Error("address not a multiple of page size".into()));
        }

        self.zero_memory_impl(address, length, Some(memory_protection))
    }

    /// Fills the given memory region with zeros.
    ///
    /// The whole memory region must be writable.
    ///
    /// `address` must be greater or equal to 0x10000 and `address + length` cannot be greater than 0x100000000.
    /// If `length` is zero then this call has no effect and will always succeed.
    pub fn zero_memory(&mut self, address: u32, length: u32) -> Result<(), MemoryAccessError> {
        self.zero_memory_impl(address, length, None)
    }

    fn zero_memory_impl(
        &mut self,
        address: u32,
        length: u32,
        memory_protection: Option<MemoryProtection>,
    ) -> Result<(), MemoryAccessError> {
        if length == 0 {
            return Ok(());
        }

        if address < 0x10000 {
            return Err(MemoryAccessError::OutOfRangeAccess {
                address,
                length: u64::from(length),
            });
        }

        if u64::from(address) + u64::from(length) > self.get_write_upper_limit() {
            return Err(MemoryAccessError::OutOfRangeAccess {
                address,
                length: u64::from(length),
            });
        }

        let length = if memory_protection.is_none() {
            length
        } else {
            self.module().round_to_page_size_up(length)
        };

        let result = access_backend!(self.backend, |mut backend| backend.zero_memory(address, length, memory_protection));
        if let Some(ref mut crosscheck) = self.crosscheck_instance {
            let expected_result = crosscheck.zero_memory(address, length, memory_protection);
            let expected_success = expected_result.is_ok();
            let success = result.is_ok();
            if success != expected_success {
                let address_end = u64::from(address) + u64::from(length);
                panic!("zero_memory: crosscheck mismatch, range = 0x{address:x}..0x{address_end:x}, interpreter = {expected_success}, backend = {success}");
            }
        }

        if cfg!(debug_assertions) && memory_protection.is_none() {
            let is_inaccessible = !self.is_memory_accessible(address, length, MemoryProtection::ReadWrite);
            if is_inaccessible != matches!(result, Err(MemoryAccessError::OutOfRangeAccess { .. })) {
                panic!(
                    "'zero_memory' doesn't match with 'is_memory_accessible' for 0x{:x}-0x{:x} (zero_memory = {:?}, is_memory_accessible = {})",
                    address,
                    cast(address).to_usize() + cast(length).to_usize(),
                    result,
                    !is_inaccessible,
                );
            }
        }

        result
    }

    /// Read-only protects a given memory region.
    ///
    /// Is only supported when dynamic paging is enabled.
    pub fn protect_memory(&mut self, address: u32, length: u32) -> Result<(), MemoryAccessError> {
        self.change_memory_protection(address, length, MemoryProtection::Read)
    }

    /// Removes read-only protection from a given memory region.
    ///
    /// Is only supported when dynamic paging is enabled.
    pub fn unprotect_memory(&mut self, address: u32, length: u32) -> Result<(), MemoryAccessError> {
        self.change_memory_protection(address, length, MemoryProtection::ReadWrite)
    }

    fn change_memory_protection(&mut self, address: u32, length: u32, protection: MemoryProtection) -> Result<(), MemoryAccessError> {
        if !self.module.is_dynamic_paging() {
            return Err(MemoryAccessError::Error(
                "protecting/unprotecting memory is only possible on modules with dynamic paging".into(),
            ));
        }

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

        let result = access_backend!(self.backend, |mut backend| backend
            .change_memory_protection(address, length, protection));
        if let Some(ref mut crosscheck) = self.crosscheck_instance {
            let expected_result = crosscheck.change_memory_protection(address, length, protection);
            let expected_success = expected_result.is_ok();
            let success = result.is_ok();
            if success != expected_success {
                let address_end = u64::from(address) + u64::from(length);
                panic!("change_memory_protection: crosscheck mismatch, range = 0x{address:x}..0x{address_end:x}, interpreter = {expected_success}, backend = {success}");
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
        self.set_reg(Reg::RA, u64::from(VM_ADDR_RETURN_TO_HOST));
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
        args._set(self.module().blob().is_64_bit(), |value| {
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
        FnResult::_get(self.module().blob().is_64_bit(), || {
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

    /// Reset cache and therefore reclaim cache backed memory.
    pub fn reset_interpreter_cache(&mut self) {
        if let Some(ref mut crosscheck) = self.crosscheck_instance {
            crosscheck.reset_interpreter_cache();
        }

        #[allow(irrefutable_let_patterns)]
        if let InstanceBackend::Interpreted(ref mut backend) = self.backend {
            backend.reset_interpreter_cache();
        }
    }

    /// Set a tight upper limit on the interpreter cache size (in bytes).
    pub fn set_interpreter_cache_size_limit(&mut self, cache_info: Option<SetCacheSizeLimitArgs>) -> Result<(), Error> {
        #[allow(irrefutable_let_patterns)]
        if let InstanceBackend::Interpreted(ref mut backend) = self.backend {
            backend.set_interpreter_cache_size_limit(cache_info)?
        }
        Ok(())
    }

    /// Sets the maximum size of a single non-read-only guest memory region.
    ///
    /// When set this will enforce a strict single-allocation size limit on the interpreter
    /// for RW data, stack and aux data regions.
    ///
    /// For example, if you set this to 1MB then the guest will be allowed to access at most
    /// 1MB of address space for stack and RW data, regardless of how much space the module
    /// itself has declared that it wants, and any access over this 1MB limit will trap.
    ///
    /// Setting this is *not* retroactive and will only affect new allocations or reallocations.
    ///
    /// Only has an effect on the interpreter, and only for modules which don't use dynamic paging.
    ///
    /// Default: `None`
    pub fn set_interpreter_max_allocation_size(&mut self, value: Option<usize>) {
        #[allow(irrefutable_let_patterns)]
        if let InstanceBackend::Interpreted(ref mut backend) = self.backend {
            backend.set_interpreter_max_allocation_size(value);
        }
    }

    /// Sets the total maximum amount of memory for all of the guest's non-read-only memory regions.
    ///
    /// Setting this is *not* retroactive and will only affect new allocations or reallocations.
    ///
    /// Only has an effect on the interpreter, and only for modules which don't use dynamic paging.
    ///
    /// Default: `None`
    pub fn set_interpreter_guest_memory_limit(&mut self, value: Option<usize>) {
        #[allow(irrefutable_let_patterns)]
        if let InstanceBackend::Interpreted(ref mut backend) = self.backend {
            backend.set_interpreter_guest_memory_limit(value);
        }
    }
}
