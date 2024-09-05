use alloc::sync::Arc;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicUsize, Ordering};

use polkavm_common::zygote::AddressTable;

use crate::api::{EngineState, Module};
use crate::compiler::CompiledModule;
use crate::config::{Config, SandboxKind};
use crate::error::Error;
use crate::mutex::Mutex;
use crate::utils::GuestInit;
use crate::{Gas, InterruptKind, MemoryAccessError, ProgramCounter, Reg, RegValue};

macro_rules! get_field_offset {
    ($struct:expr, |$struct_ident:ident| $get_field:expr) => {{
        let $struct_ident = $struct;
        let struct_ref: *const _ = &$struct_ident;
        let field_ptr: *const _ = $get_field;
        let struct_addr = struct_ref as usize;
        let field_addr = field_ptr as usize;
        field_addr - struct_addr
    }};
}

#[cfg(feature = "generic-sandbox")]
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

static NATIVE_PAGE_SIZE: AtomicUsize = AtomicUsize::new(0);

pub(crate) fn init_native_page_size() {
    if NATIVE_PAGE_SIZE.load(Ordering::Relaxed) != 0 {
        return;
    }

    // SAFETY: This function has no safety invariants and should be always safe to call.
    let page_size = unsafe { sysconf(_SC_PAGESIZE) as usize };
    NATIVE_PAGE_SIZE.store(page_size, Ordering::Relaxed);
}

#[inline(always)]
pub(crate) fn get_native_page_size() -> usize {
    let page_size = NATIVE_PAGE_SIZE.load(Ordering::Relaxed);
    debug_assert_ne!(page_size, 0);

    page_size
}

pub trait SandboxConfig: Default {
    fn enable_logger(&mut self, value: bool);
}

pub trait SandboxAddressSpace {
    fn native_code_origin(&self) -> u64;
}

pub trait SandboxProgram: Clone {
    fn machine_code(&self) -> &[u8];
}

pub struct OffsetTable {
    pub arg: usize,
    pub gas: usize,
    pub heap_info: usize,
    pub next_native_program_counter: usize,
    pub next_program_counter: usize,
    pub program_counter: usize,
    pub regs: usize,
}

pub(crate) trait Sandbox: Sized {
    const KIND: SandboxKind;

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
    fn prepare_program(
        global: &Self::GlobalState,
        init: SandboxInit<Self>,
        address_space: Self::AddressSpace,
    ) -> Result<Self::Program, Self::Error>;
    fn spawn(global: &Self::GlobalState, config: &Self::Config) -> Result<Self, Self::Error>;
    fn load_module(&mut self, global: &Self::GlobalState, module: &Module) -> Result<(), Self::Error>;
    fn recycle(&mut self, global: &Self::GlobalState) -> Result<(), Self::Error>;
    fn address_table() -> AddressTable;
    fn offset_table() -> OffsetTable;
    fn sync(&mut self) -> Result<(), Self::Error>;

    fn run(&mut self) -> Result<InterruptKind, Self::Error>;
    fn reg(&self, reg: Reg) -> RegValue;
    fn set_reg(&mut self, reg: Reg, value: u32);
    fn gas(&self) -> Gas;
    fn set_gas(&mut self, gas: Gas);
    fn program_counter(&self) -> Option<ProgramCounter>;
    fn next_program_counter(&self) -> Option<ProgramCounter>;
    fn next_native_program_counter(&self) -> Option<usize>;
    fn set_next_program_counter(&mut self, pc: ProgramCounter);
    fn reset_memory(&mut self) -> Result<(), Self::Error>;
    fn read_memory_into<'slice>(&self, address: u32, slice: &'slice mut [MaybeUninit<u8>]) -> Result<&'slice mut [u8], MemoryAccessError>;
    fn write_memory(&mut self, address: u32, data: &[u8]) -> Result<(), MemoryAccessError>;
    fn zero_memory(&mut self, address: u32, length: u32) -> Result<(), MemoryAccessError>;
    fn free_pages(&mut self, address: u32, length: u32) -> Result<(), Self::Error>;
    fn heap_size(&self) -> u32;
    fn sbrk(&mut self, size: u32) -> Result<Option<u32>, Self::Error>;
    fn pid(&self) -> Option<u32>;
}

#[derive(Copy, Clone, Default)]
pub struct SandboxInit<'a, S>
where
    S: Sandbox,
{
    pub guest_init: GuestInit<'a>,
    pub code: &'a [u8],
    pub jump_table: S::JumpTable,
    pub sysenter_address: u64,
    pub sysreturn_address: u64,
}

pub(crate) struct SandboxInstance<S>
where
    S: Sandbox,
{
    engine_state: Arc<EngineState>,
    sandbox: Option<S>,
}

impl<S> SandboxInstance<S>
where
    S: Sandbox,
{
    pub fn spawn_and_load_module(engine_state: Arc<EngineState>, module: &Module) -> Result<Self, Error> {
        use crate::sandbox::SandboxConfig;

        let mut sandbox_config = S::Config::default();
        sandbox_config.enable_logger(is_sandbox_logging_enabled());

        let global = S::downcast_global_state(engine_state.sandbox_global.as_ref().unwrap());
        let mut sandbox = if let Some(sandbox) = engine_state
            .sandbox_cache
            .as_ref()
            .and_then(|cache| S::downcast_worker_cache(cache).reuse_sandbox())
        {
            sandbox
        } else {
            S::spawn(global, &sandbox_config)
                .map_err(Error::from_display)
                .map_err(|error| error.context("instantiation failed: failed to create a sandbox"))?
        };

        sandbox
            .load_module(global, module)
            .map_err(Error::from_display)
            .map_err(|error| error.context("instantiation failed: failed to upload the program into the sandbox"))?;

        Ok(SandboxInstance {
            sandbox: Some(sandbox),
            engine_state,
        })
    }

    pub fn sandbox(&self) -> &S {
        self.sandbox.as_ref().unwrap()
    }

    pub fn sandbox_mut(&mut self) -> &mut S {
        self.sandbox.as_mut().unwrap()
    }
}

impl<S> Drop for SandboxInstance<S>
where
    S: Sandbox,
{
    fn drop(&mut self) {
        if let Some(cache) = self.engine_state.sandbox_cache.as_ref() {
            let cache = S::downcast_worker_cache(cache);
            cache.recycle_sandbox(|| {
                let mut sandbox = self.sandbox.take()?;
                let global = S::downcast_global_state(self.engine_state.sandbox_global.as_ref().unwrap());
                if let Err(error) = sandbox.recycle(global) {
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
    #[cfg(feature = "generic-sandbox")]
    Generic(crate::sandbox::generic::GlobalState),
}

impl GlobalStateKind {
    pub(crate) fn new(kind: SandboxKind, config: &Config) -> Result<Self, Error> {
        match kind {
            SandboxKind::Linux => {
                #[cfg(target_os = "linux")]
                {
                    Ok(Self::Linux(
                        crate::sandbox::linux::GlobalState::new(config)
                            .map_err(|error| format!("failed to initialize Linux sandbox: {error}"))?,
                    ))
                }

                #[cfg(not(target_os = "linux"))]
                {
                    unreachable!()
                }
            }
            SandboxKind::Generic => {
                #[cfg(feature = "generic-sandbox")]
                {
                    Ok(Self::Generic(
                        crate::sandbox::generic::GlobalState::new(config)
                            .map_err(|error| format!("failed to initialize generic sandbox: {error}"))?,
                    ))
                }

                #[cfg(not(feature = "generic-sandbox"))]
                {
                    unreachable!()
                }
            }
        }
    }
}

pub(crate) enum WorkerCacheKind {
    #[cfg(target_os = "linux")]
    Linux(WorkerCache<crate::sandbox::linux::Sandbox>),
    #[cfg(feature = "generic-sandbox")]
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
            }
            SandboxKind::Generic => {
                #[cfg(feature = "generic-sandbox")]
                {
                    Self::Generic(WorkerCache::new(config))
                }

                #[cfg(not(feature = "generic-sandbox"))]
                {
                    unreachable!()
                }
            }
        }
    }

    pub(crate) fn spawn(&self, global: &GlobalStateKind) -> Result<(), Error> {
        match self {
            #[cfg(target_os = "linux")]
            WorkerCacheKind::Linux(ref cache) => cache.spawn(crate::sandbox::linux::Sandbox::downcast_global_state(global)),
            #[cfg(feature = "generic-sandbox")]
            WorkerCacheKind::Generic(ref cache) => cache.spawn(crate::sandbox::generic::Sandbox::downcast_global_state(global)),
        }
    }
}

pub(crate) struct WorkerCache<S> {
    sandboxes: Mutex<Vec<S>>,
    available_workers: AtomicUsize,
    worker_limit: usize,
}

impl<S> WorkerCache<S>
where
    S: Sandbox,
{
    pub(crate) fn new(config: &Config) -> Self {
        WorkerCache {
            sandboxes: Mutex::new(Vec::new()),
            available_workers: AtomicUsize::new(0),
            worker_limit: config.worker_count,
        }
    }

    fn spawn(&self, global: &S::GlobalState) -> Result<(), Error> {
        let mut sandbox_config = S::Config::default();
        sandbox_config.enable_logger(is_sandbox_logging_enabled());

        let sandbox = S::spawn(global, &sandbox_config)
            .map_err(crate::Error::from_display)
            .map_err(|error| {
                error.context(format!(
                    "failed to create a worker process ({} already exist)",
                    self.available_workers.load(Ordering::Relaxed)
                ))
            })?;

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
            if let Err(new_count) = self
                .available_workers
                .compare_exchange(count, count + 1, Ordering::Relaxed, Ordering::Relaxed)
            {
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
