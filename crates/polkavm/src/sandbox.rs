use alloc::borrow::Cow;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicUsize, Ordering};

use polkavm_common::{
    error::ExecutionError,
    zygote::{
        AddressTable,
    },
    utils::{Access, Gas}
};

use crate::api::{BackendAccess, EngineState, ExecuteArgs, Module};
use crate::compiler::CompiledModule;
use crate::config::{Config, GasMeteringKind, SandboxKind};
use crate::mutex::Mutex;
use crate::utils::GuestInit;
use crate::error::Error;

macro_rules! get_field_offset {
    ($struct:expr, |$struct_ident:ident| $get_field:expr) => {{
        let $struct_ident = $struct;
        let struct_ref = &$struct_ident;
        let field_ref = $get_field;
        let struct_addr = struct_ref as *const _ as usize;
        let field_addr = field_ref as *const _ as usize;
        field_addr - struct_addr
    }}
}

pub mod generic;

#[cfg(target_os = "linux")]
pub mod linux;

// This is literally the only thing we need from `libc` on Linux, so instead of including
// the whole crate let's just define these ourselves.
#[cfg(target_os = "linux")]
const _SC_PAGESIZE: core::ffi::c_int = 30;

#[cfg(target_os = "linux")]
extern "C" {
    fn sysconf(name: core::ffi::c_int) -> core::ffi::c_long;
}

#[cfg(not(target_os = "linux"))]
use libc::{sysconf, _SC_PAGESIZE};

pub(crate) fn get_native_page_size() -> usize {
    // TODO: Cache this?

    // SAFETY: This function has no safety invariants and should be always safe to call.
    unsafe { sysconf(_SC_PAGESIZE) as usize }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub(crate) struct OutOfGas;

pub trait SandboxConfig: Default {
    fn enable_logger(&mut self, value: bool);
}

pub trait SandboxAddressSpace {
    fn native_code_address(&self) -> u64;
}

pub trait SandboxProgram: Clone {
    fn machine_code(&self) -> Cow<[u8]>;
}

pub(crate) trait Sandbox: Sized {
    const KIND: SandboxKind;

    type Access<'r>: Access<'r> + Into<BackendAccess<'r>> where Self: 'r;
    type Config: SandboxConfig;
    type Error: core::fmt::Debug + core::fmt::Display;
    type Program: SandboxProgram;
    type AddressSpace: SandboxAddressSpace;
    type GlobalState;
    type JumpTable: AsRef<[usize]> + AsMut<[usize]>;

    fn downcast_module(module: &Module) -> &CompiledModule<Self>;
    fn downcast_global_state(global: &GlobalStateKind) -> &Self::GlobalState;
    fn downcast_worker_cache(global: &WorkerCacheKind) -> &WorkerCache<Self>;

    fn allocate_jump_table(global: &Self::GlobalState, count: usize) -> Result<Self::JumpTable, Self::Error>;

    fn reserve_address_space() -> Result<Self::AddressSpace, Self::Error>;
    fn prepare_program(global: &Self::GlobalState, init: SandboxInit<Self>, address_space: Self::AddressSpace) -> Result<Self::Program, Self::Error>;
    fn spawn(global: &Self::GlobalState, config: &Self::Config) -> Result<Self, Self::Error>;
    fn execute(&mut self, global: &Self::GlobalState, args: ExecuteArgs) -> Result<(), ExecutionError<Self::Error>>;
    fn access(&'_ mut self) -> Self::Access<'_>;
    fn pid(&self) -> Option<u32>;
    fn address_table() -> AddressTable;
    fn vmctx_regs_offset() -> usize;
    fn vmctx_gas_offset() -> usize;
    fn vmctx_heap_info_offset() -> usize;
    fn gas_remaining_impl(&self) -> Result<Option<Gas>, OutOfGas>;
    fn sync(&mut self) -> Result<(), Self::Error>;
}

#[derive(Copy, Clone, Default)]
pub struct SandboxInit<'a, S> where S: Sandbox {
    pub guest_init: GuestInit<'a>,
    pub code: &'a [u8],
    pub jump_table: S::JumpTable,
    pub sysreturn_address: u64,
}

pub(crate) fn get_gas(args: &ExecuteArgs, gas_metering: Option<GasMeteringKind>) -> Option<i64> {
    if args.module.is_none() && args.gas.is_none() && gas_metering.is_some() {
        // Keep whatever value was set there previously.
        return None;
    }

    let gas = args.gas.unwrap_or(Gas::MIN);
    if gas_metering.is_some() {
        Some(gas.get() as i64)
    } else {
        Some(0)
    }
}

pub(crate) struct SandboxInstance<S> where S: Sandbox {
    engine_state: Arc<EngineState>,
    sandbox: Option<S>
}

impl<S> SandboxInstance<S> where S: Sandbox {
    pub fn spawn_and_load_module(engine_state: Arc<EngineState>, module: &Module) -> Result<Self, Error> {
        use crate::sandbox::SandboxConfig;

        let mut sandbox_config = S::Config::default();
        sandbox_config.enable_logger(is_sandbox_logging_enabled() || module.is_debug_trace_execution_enabled());

        let sandbox = if let Some(sandbox) = engine_state.sandbox_cache.as_ref().and_then(|cache| S::downcast_worker_cache(cache).reuse_sandbox()) {
            sandbox
        } else {
            let global = S::downcast_global_state(engine_state.sandbox_global.as_ref().unwrap());
            S::spawn(global, &sandbox_config)
                .map_err(Error::from_display)
                .map_err(|error| error.context("instantiation failed: failed to create a sandbox"))?
        };

        let mut sandbox = SandboxInstance {
            sandbox: Some(sandbox),
            engine_state,
        };

        let mut args = ExecuteArgs::new();
        args.module = Some(module);

        sandbox
            .execute(args)
            .map_err(Error::from_display)
            .map_err(|error| error.context("instantiation failed: failed to upload the program into the sandbox"))?;

        Ok(sandbox)
    }

    pub fn execute(&mut self, args: ExecuteArgs) -> Result<(), ExecutionError<Error>> {
        let global = S::downcast_global_state(self.engine_state.sandbox_global.as_ref().unwrap());
        let sandbox = self.sandbox.as_mut().unwrap();
        let result = match sandbox.execute(global, args) {
            Ok(()) => Ok(()),
            Err(ExecutionError::Trap(trap)) => Err(ExecutionError::Trap(trap)),
            Err(ExecutionError::Error(error)) => return Err(ExecutionError::Error(Error::from_display(error))),
            Err(ExecutionError::OutOfGas) => return Err(ExecutionError::OutOfGas),
        };

        if sandbox.gas_remaining_impl().is_err() {
            return Err(ExecutionError::OutOfGas);
        }

        result
    }

    pub fn access(&'_ mut self) -> S::Access<'_> {
        self.sandbox.as_mut().unwrap().access()
    }

    pub fn sandbox(&self) -> &S {
        self.sandbox.as_ref().unwrap()
    }
}

impl<S> Drop for SandboxInstance<S> where S: Sandbox {
    fn drop(&mut self) {
        if let Some(cache) = self.engine_state.sandbox_cache.as_ref() {
            let cache = S::downcast_worker_cache(cache);
            cache.recycle_sandbox(|| {
                let mut sandbox = self.sandbox.take()?;
                let mut args = ExecuteArgs::new();
                args.flags |= polkavm_common::VM_RPC_FLAG_CLEAR_PROGRAM_AFTER_EXECUTION;
                args.gas = Some(polkavm_common::utils::Gas::MIN);
                args.is_async = true;

                let global = S::downcast_global_state(self.engine_state.sandbox_global.as_ref().unwrap());
                if let Err(error) = sandbox.execute(global, args) {
                    log::warn!("Failed to cache a sandbox worker process due to an error: {error}");
                    None
                } else {
                    Some(sandbox)
                }
            })
        }
    }
}

pub(crate) enum GlobalStateKind {
    #[cfg(target_os = "linux")]
    Linux(crate::sandbox::linux::GlobalState),
    Generic(crate::sandbox::generic::GlobalState),
}

impl GlobalStateKind {
    pub(crate) fn new(kind: SandboxKind, config: &Config) -> Result<Self, Error> {
        match kind {
            SandboxKind::Linux => {
                #[cfg(target_os = "linux")]
                {
                    Ok(Self::Linux(crate::sandbox::linux::GlobalState::new(config).map_err(|error| format!("failed to initialize Linux sandbox: {error}"))?))
                }

                #[cfg(not(target_os = "linux"))]
                {
                    unreachable!()
                }
            },
            SandboxKind::Generic => Ok(Self::Generic(crate::sandbox::generic::GlobalState::new(config).map_err(|error| format!("failed to initialize generic sandbox: {error}"))?)),
        }
    }
}

pub(crate) enum WorkerCacheKind {
    #[cfg(target_os = "linux")]
    Linux(WorkerCache<crate::sandbox::linux::Sandbox>),
    Generic(WorkerCache<crate::sandbox::generic::Sandbox>),
}

impl WorkerCacheKind {
    pub(crate) fn new(kind: SandboxKind, config: &Config) -> Self {
        match kind {
            SandboxKind::Linux => {
                #[cfg(target_os = "linux")]
                {
                    Self::Linux(WorkerCache::new(config))
                }

                #[cfg(not(target_os = "linux"))]
                {
                    unreachable!()
                }
            },
            SandboxKind::Generic => Self::Generic(WorkerCache::new(config))
        }
    }

    pub(crate) fn spawn(&self, global: &GlobalStateKind) -> Result<(), Error> {
        match self {
            #[cfg(target_os = "linux")]
            WorkerCacheKind::Linux(ref cache) => {
                cache.spawn(crate::sandbox::linux::Sandbox::downcast_global_state(global))
            },
            WorkerCacheKind::Generic(ref cache) => cache.spawn(crate::sandbox::generic::Sandbox::downcast_global_state(global)),
        }
    }
}

pub(crate) struct WorkerCache<S> {
    sandboxes: Mutex<Vec<S>>,
    available_workers: AtomicUsize,
    worker_limit: usize,
    debug_trace_execution: bool,
}

impl<S> WorkerCache<S> where S: Sandbox {
    pub(crate) fn new(config: &Config) -> Self {
        WorkerCache {
            sandboxes: Mutex::new(Vec::new()),
            available_workers: AtomicUsize::new(0),
            worker_limit: config.worker_count,
            debug_trace_execution: is_sandbox_logging_enabled() || config.trace_execution,
        }
    }

    fn spawn(&self, global: &S::GlobalState) -> Result<(), Error> {
        let mut sandbox_config = S::Config::default();
        sandbox_config.enable_logger(self.debug_trace_execution);

        let sandbox = S::spawn(global, &sandbox_config)
            .map_err(crate::Error::from_display)
            .map_err(|error| error.context(format!("failed to create a worker process ({} already exist)", self.available_workers.load(Ordering::Relaxed))))?;

        let mut sandboxes = self.sandboxes.lock();
        sandboxes.push(sandbox);
        self.available_workers.store(sandboxes.len(), Ordering::Relaxed);

        Ok(())
    }

    fn reuse_sandbox(&self) -> Option<S> {
        if self.available_workers.load(Ordering::Relaxed) == 0 {
            return None;
        }

        let mut sandbox = {
            let mut sandboxes = self.sandboxes.lock();
            let sandbox = sandboxes.pop()?;
            self.available_workers.store(sandboxes.len(), Ordering::Relaxed);

            sandbox
        };

        if let Err(error) = sandbox.sync() {
            log::warn!("Failed to reuse a sandbox: {error}");
            None
        } else {
            Some(sandbox)
        }
    }

    fn recycle_sandbox(&self, get_sandbox: impl FnOnce() -> Option<S>) {
        let mut count = self.available_workers.load(Ordering::Relaxed);
        if count >= self.worker_limit {
            return;
        }

        loop {
            if let Err(new_count) = self.available_workers.compare_exchange(count, count + 1, Ordering::Relaxed, Ordering::Relaxed) {
                if new_count >= self.worker_limit {
                    return;
                }

                count = new_count;
                continue;
            }

            break;
        }

        let sandbox = get_sandbox();
        {
            let mut sandboxes = self.sandboxes.lock();
            if let Some(sandbox) = sandbox {
                sandboxes.push(sandbox);
            }
            self.available_workers.store(sandboxes.len(), Ordering::Relaxed);
        }
    }
}

fn is_sandbox_logging_enabled() -> bool {
    cfg!(test) || log::log_enabled!(target: "polkavm", log::Level::Trace) || log::log_enabled!(target: "polkavm::zygote", log::Level::Trace)
}
