use alloc::borrow::Cow;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicUsize, Ordering};

use polkavm_common::{
    error::ExecutionError,
    zygote::{
        AddressTable,
        SandboxMemoryConfig,
    },
    utils::{Access, Gas, align_to_next_page_usize}
};

use crate::api::{BackendAccess, EngineState, ExecuteArgs, Module};
use crate::compiler::CompiledModule;
use crate::config::{GasMeteringKind, SandboxKind};
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

    fn as_sandbox_vec(sandbox_vec: &SandboxVec) -> &Mutex<Vec<Self>>;
    fn as_compiled_module(module: &Module) -> &CompiledModule<Self>;

    fn reserve_address_space() -> Result<Self::AddressSpace, Self::Error>;
    fn prepare_program(init: SandboxInit, address_space: Self::AddressSpace) -> Result<Self::Program, Self::Error>;
    fn spawn(config: &Self::Config) -> Result<Self, Self::Error>;
    fn execute(&mut self, args: ExecuteArgs) -> Result<(), ExecutionError<Self::Error>>;
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
pub struct SandboxInit<'a> {
    pub guest_init: GuestInit<'a>,
    pub code: &'a [u8],
    pub jump_table: &'a [u8],
    pub sysreturn_address: u64,
}

impl<'a> SandboxInit<'a> {
    fn memory_config(&self, native_page_size: usize) -> Result<SandboxMemoryConfig, &'static str> {
        let memory_map = self.guest_init.memory_map()?;
        let mut ro_data_fd_size = align_to_next_page_usize(native_page_size, self.guest_init.ro_data.len()).unwrap() as u32;
        if memory_map.ro_data_size() - ro_data_fd_size < memory_map.page_size() {
            ro_data_fd_size = memory_map.ro_data_size();
        }

        let rw_data_fd_size = align_to_next_page_usize(native_page_size, self.guest_init.rw_data.len()).unwrap() as u32;
        let code_size = align_to_next_page_usize(native_page_size, self.code.len()).unwrap() as u32;
        let jump_table_size = align_to_next_page_usize(native_page_size, self.jump_table.len()).unwrap() as u32;

        Ok(SandboxMemoryConfig {
            memory_map,
            ro_data_fd_size,
            rw_data_fd_size,
            code_size,
            jump_table_size,
            sysreturn_address: self.sysreturn_address,
        })
    }
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
        let mut sandbox = SandboxInstance {
            sandbox: Some(reuse_or_spawn_sandbox::<S>(&engine_state, module)?),
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
        let sandbox = self.sandbox.as_mut().unwrap();
        let result = match sandbox.execute(args) {
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
        recycle_sandbox::<S>(&self.engine_state, || {
            let mut sandbox = self.sandbox.take()?;
            let mut args = ExecuteArgs::new();
            args.flags |= polkavm_common::VM_RPC_FLAG_CLEAR_PROGRAM_AFTER_EXECUTION;
            args.gas = Some(polkavm_common::utils::Gas::MIN);
            args.is_async = true;

            if let Err(error) = sandbox.execute(args) {
                log::warn!("Failed to cache a sandbox worker process due to an error: {error}");
                None
            } else {
                Some(sandbox)
            }
        })
    }
}

pub(crate) enum SandboxVec {
    #[cfg(target_os = "linux")]
    Linux(Mutex<Vec<crate::sandbox::linux::Sandbox>>),
    Generic(Mutex<Vec<crate::sandbox::generic::Sandbox>>),
}

pub(crate) struct SandboxCache {
    sandboxes: SandboxVec,
    available_workers: AtomicUsize,
    worker_limit: usize,
}

impl SandboxCache {
    pub(crate) fn new(kind: SandboxKind, worker_count: usize, debug_trace_execution: bool) -> Result<Self, Error> {
        let sandboxes = match kind {
            SandboxKind::Linux => {
                #[cfg(target_os = "linux")]
                {
                    SandboxVec::Linux(Mutex::new(spawn_sandboxes(worker_count, debug_trace_execution)?))
                }

                #[cfg(not(target_os = "linux"))]
                {
                    unreachable!()
                }
            },
            SandboxKind::Generic => SandboxVec::Generic(Mutex::new(spawn_sandboxes(worker_count, debug_trace_execution)?)),
        };

        Ok(SandboxCache {
            sandboxes,
            available_workers: AtomicUsize::new(worker_count),
            worker_limit: worker_count,
        })
    }

    fn reuse_sandbox<S>(&self) -> Option<S> where S: Sandbox {
        if self.available_workers.load(Ordering::Relaxed) == 0 {
            return None;
        }

        let sandboxes = S::as_sandbox_vec(&self.sandboxes);
        let mut sandboxes = sandboxes.lock();
        let mut sandbox = sandboxes.pop()?;
        self.available_workers.fetch_sub(1, Ordering::Relaxed);

        if let Err(error) = sandbox.sync() {
            log::warn!("Failed to reuse a sandbox: {error}");
            None
        } else {
            Some(sandbox)
        }
    }
}

fn is_sandbox_logging_enabled() -> bool {
    cfg!(test) || log::log_enabled!(target: "polkavm", log::Level::Trace) || log::log_enabled!(target: "polkavm::zygote", log::Level::Trace)
}

fn spawn_sandboxes<S>(count: usize, debug_trace_execution: bool) -> Result<Vec<S>, Error> where S: Sandbox {
    use crate::sandbox::SandboxConfig;

    let mut sandbox_config = S::Config::default();
    sandbox_config.enable_logger(is_sandbox_logging_enabled() || debug_trace_execution);

    let mut sandboxes = Vec::with_capacity(count);
    for nth in 0..count {
        let sandbox = S::spawn(&sandbox_config)
            .map_err(crate::Error::from_display)
            .map_err(|error| error.context(format!("failed to create a worker process ({} out of {})", nth + 1, count)))?;

        sandboxes.push(sandbox);
    }

    Ok(sandboxes)
}

fn reuse_or_spawn_sandbox<S>(engine_state: &EngineState, module: &Module) -> Result<S, Error> where S: Sandbox {
    use crate::sandbox::SandboxConfig;

    let mut sandbox_config = S::Config::default();
    sandbox_config.enable_logger(is_sandbox_logging_enabled() || module.is_debug_trace_execution_enabled());

    if let Some(sandbox) = engine_state.sandbox_cache().and_then(|cache| cache.reuse_sandbox::<S>()) {
        Ok(sandbox)
    } else {
        S::spawn(&sandbox_config)
            .map_err(Error::from_display)
            .map_err(|error| error.context("instantiation failed: failed to create a sandbox"))
    }
}

fn recycle_sandbox<S>(engine_state: &EngineState, get_sandbox: impl FnOnce() -> Option<S>) where S: Sandbox {
    let Some(sandbox_cache) = engine_state.sandbox_cache() else { return };
    let sandboxes = S::as_sandbox_vec(&sandbox_cache.sandboxes);

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
        let mut sandboxes = sandboxes.lock();
        sandboxes.push(sandbox);
    } else {
        sandbox_cache.available_workers.fetch_sub(1, Ordering::Relaxed);
    }
}
