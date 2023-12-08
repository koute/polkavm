#![allow(clippy::manual_range_contains)]

use polkavm_common::{
    error::{ExecutionError, Trap},
    program::Reg,
    utils::{byte_slice_init, Access, AsUninitSliceMut, Gas},
    zygote::{
        AddressTable,
        AddressTableRaw,
        CacheAligned,
        SandboxMemoryConfig,
        VM_RPC_FLAG_CLEAR_PROGRAM_AFTER_EXECUTION,
        VM_RPC_FLAG_RESET_MEMORY_AFTER_EXECUTION,
        VM_ADDR_JUMP_TABLE,
        VM_ADDR_JUMP_TABLE_RETURN_TO_HOST,
        VM_SANDBOX_MAXIMUM_NATIVE_CODE_SIZE,
        VM_SANDBOX_MAXIMUM_JUMP_TABLE_VIRTUAL_SIZE,
    },
};

use super::ExecuteArgs;

use core::ops::Range;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicUsize, Ordering};
use core::mem::MaybeUninit;
use std::borrow::Cow;
use std::sync::Arc;

use super::{OnHostcall, SandboxKind, SandboxProgramInit, get_native_page_size};
use crate::api::{BackendAccess, MemoryAccessError};
use crate::config::GasMeteringKind;

// On Linux don't depend on the `libc` crate to lower the number of dependencies.
#[cfg(target_os = "linux")]
#[allow(non_camel_case_types)]
mod sys {
    pub use polkavm_linux_raw::{c_void, c_int, size_t, siginfo_t, SIG_IGN, SIG_DFL, ucontext as ucontext_t};
    pub const SIGSEGV: c_int = polkavm_linux_raw::SIGSEGV as c_int;
    pub const SIGILL: c_int = polkavm_linux_raw::SIGILL as c_int;
    pub const PROT_READ: c_int = polkavm_linux_raw::PROT_READ as c_int;
    pub const PROT_WRITE: c_int = polkavm_linux_raw::PROT_WRITE as c_int;
    pub const PROT_EXEC: c_int = polkavm_linux_raw::PROT_EXEC as c_int;
    pub const MAP_ANONYMOUS: c_int = polkavm_linux_raw::MAP_ANONYMOUS as c_int;
    pub const MAP_PRIVATE: c_int = polkavm_linux_raw::MAP_PRIVATE as c_int;
    pub const MAP_FIXED: c_int = polkavm_linux_raw::MAP_FIXED as c_int;
    pub const MAP_FAILED: *mut c_void = !0 as *mut c_void;
    pub const SA_SIGINFO: c_int = polkavm_linux_raw::SA_SIGINFO as c_int;
    pub const SA_NODEFER: c_int = polkavm_linux_raw::SA_NODEFER as c_int;

    pub type sighandler_t = size_t;

    #[repr(C)]
    pub struct sigset_t {
        #[cfg(target_pointer_width = "32")]
        __val: [u32; 32],
        #[cfg(target_pointer_width = "64")]
        __val: [u64; 16],
    }

    #[repr(C)]
    pub struct sigaction {
        pub sa_sigaction: sighandler_t,
        pub sa_mask: sigset_t,
        pub sa_flags: c_int,
        pub sa_restorer: Option<extern "C" fn()>,
    }

    extern "C" {
        pub fn mmap(
            addr: *mut c_void,
            len: size_t,
            prot: c_int,
            flags: c_int,
            fd: c_int,
            offset: i64
        ) -> *mut c_void;

        pub fn munmap(
            addr: *mut c_void,
            len: size_t
        ) -> c_int;

        pub fn mprotect(
            addr: *mut c_void,
            len: size_t,
            prot: c_int
        ) -> c_int;

        pub fn sigaction(
            signum: c_int,
            act: *const sigaction,
            oldact: *mut sigaction
        ) -> c_int;

        pub fn sigemptyset(set: *mut sigset_t) -> c_int;
    }
}

#[cfg(not(target_os = "linux"))]
use libc as sys;

use sys::{c_int, size_t, PROT_READ, PROT_WRITE, PROT_EXEC, MAP_ANONYMOUS, MAP_PRIVATE, MAP_FIXED};
use core::ffi::c_void;

pub(crate) const GUEST_MEMORY_TO_VMCTX_OFFSET: isize = -4096;

fn get_guest_memory_offset() -> usize {
    get_native_page_size()
}

#[derive(Debug)]
pub struct Error(std::io::Error);

impl core::fmt::Display for Error {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
        self.0.fmt(fmt)
    }
}

impl From<&'static str> for Error {
    fn from(value: &'static str) -> Self {
        Self(std::io::Error::new(std::io::ErrorKind::Other, value))
    }
}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Self(error)
    }
}

pub struct Mmap {
    pointer: *mut c_void,
    length: usize,
}

// SAFETY: The ownership of an mmapped piece of memory can be safely transferred to other threads.
unsafe impl Send for Mmap {}

// SAFETY: An mmaped piece of memory can be safely accessed from multiple threads.
unsafe impl Sync for Mmap {}

impl Mmap {
    unsafe fn raw_mmap(
        address: *mut c_void,
        length: usize,
        protection: c_int,
        flags: c_int,
    ) -> Result<Self, Error> {
        let pointer = {
            let pointer = sys::mmap(address, length, protection, flags, -1, 0);
            if pointer == sys::MAP_FAILED {
                return Err(Error(std::io::Error::last_os_error()));
            }
            pointer
        };

        Ok(Self { pointer, length })
    }

    fn mmap_within(&mut self, offset: usize, length: usize, protection: c_int) -> Result<(), Error> {
        if !offset.checked_add(length).map(|end| end <= self.length).unwrap_or(false) {
            return Err("out of bounds mmap".into())
        }

        // SAFETY: The mapping is always within the bounds of the original map.
        unsafe {
            let pointer = self.pointer.cast::<u8>().add(offset).cast();
            core::mem::forget(Self::raw_mmap(pointer, length, protection, MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE)?);
        }

        Ok(())
    }

    fn unmap_inplace(&mut self) -> Result<(), Error> {
        if self.length > 0 {
            // SAFETY: The map is always valid here, so it can be safely unmapped.
            unsafe {
                if sys::munmap(self.pointer, self.length) < 0 {
                    return Err(Error(std::io::Error::last_os_error()));
                }
            }

            self.length = 0;
            self.pointer = core::ptr::NonNull::<u8>::dangling().as_ptr() as *mut c_void;
        }

        Ok(())
    }

    pub fn unmap(mut self) -> Result<(), Error> {
        self.unmap_inplace()
    }

    pub fn reserve_address_space(
        length: size_t
    ) -> Result<Self, Error> {
        // SAFETY: `MAP_FIXED` is not specified, so this is always safe.
        unsafe {
            Mmap::raw_mmap(core::ptr::null_mut(), length, 0, MAP_ANONYMOUS | MAP_PRIVATE)
        }
    }

    pub fn mprotect(&mut self, offset: usize, length: usize, protection: c_int) -> Result<(), Error> {
        if !offset.checked_add(length).map(|end| end <= self.length).unwrap_or(false) {
            return Err("out of bounds mprotect".into())
        }

        // SAFETY: The bounds are always within the range of this map.
        unsafe {
            if sys::mprotect(self.pointer.add(offset), length, protection) < 0 {
                return Err(Error(std::io::Error::last_os_error()));
            }
        }

        Ok(())
    }

    pub fn modify_and_protect(&mut self, offset: usize, length: usize, protection: c_int, callback: impl FnOnce(&mut [u8])) -> Result<(), Error> {
        self.mprotect(offset, length, PROT_READ | PROT_WRITE)?;
        callback(&mut self.as_slice_mut()[offset..offset + length]);
        if protection != PROT_READ | PROT_WRITE {
            self.mprotect(offset, length, protection)?;
        }
        Ok(())
    }

    pub fn as_ptr(&self) -> *const c_void {
        self.pointer
    }

    pub fn as_mut_ptr(&self) -> *mut c_void {
        self.pointer
    }

    pub fn as_slice(&self) -> &[u8] {
        // SAFETY: The pointer is either always valid, or is dangling and the length is zero.
        //
        // The memory might not be mapped as readable, so accessing this slice can still produce
        // a segfault, but this is expected due to the low level nature of this helper, and assuming
        // the signal handler is correct it cannot result in unsoundness, for the same reason as to why
        // the `std::process::abort` is also safe.
        unsafe { core::slice::from_raw_parts(self.as_ptr().cast::<u8>(), self.length) }
    }

    pub fn as_slice_mut(&mut self) -> &mut [u8] {
        // SAFETY: The pointer is either always valid, or is dangling and the length is zero.
        //
        // The memory might not be mapped as readable or writable, so accessing this slice can still produce
        // a segfault, but this is expected due to the low level nature of this helper, and assuming
        // the signal handler is correct it cannot result in unsoundness, for the same reason as to why
        // the `std::process::abort` is also safe.
        unsafe { core::slice::from_raw_parts_mut(self.as_mut_ptr().cast::<u8>(), self.length) }
    }

    pub fn len(&self) -> usize {
        self.length
    }
}

impl Default for Mmap {
    fn default() -> Self {
        Self {
            pointer: core::ptr::NonNull::<u8>::dangling().as_ptr() as *mut c_void,
            length: 0,
        }
    }
}

impl Drop for Mmap {
    fn drop(&mut self) {
        let _ = self.unmap_inplace();
    }
}

static mut OLD_SIGSEGV: MaybeUninit<sys::sigaction> = MaybeUninit::uninit();
static mut OLD_SIGILL: MaybeUninit<sys::sigaction> = MaybeUninit::uninit();

#[cfg(any(target_os = "macos", target_os = "freebsd"))]
static mut OLD_SIGBUS: MaybeUninit<sys::sigaction> = MaybeUninit::uninit();

unsafe extern "C" fn signal_handler(signal: c_int, info: &sys::siginfo_t, context: &sys::ucontext_t) {
    let old = match signal {
        sys::SIGSEGV => &OLD_SIGSEGV,
        sys::SIGILL => &OLD_SIGILL,
        #[cfg(any(target_os = "macos", target_os = "freebsd"))]
        sys::SIGBUS => &OLD_SIGBUS,
        _ => unreachable!("received unknown signal")
    };

    let vmctx = THREAD_VMCTX.with(|thread_ctx| *thread_ctx.get());
    if !vmctx.is_null() {
        let rip;
        #[cfg(target_os = "linux")]
        {
            rip = context.uc_mcontext.rip;
        }
        #[cfg(target_os = "macos")]
        {
            rip = (*context.uc_mcontext).__ss.__rip;
        }
        #[cfg(target_os = "freebsd")]
        {
            rip = context.uc_mcontext.mc_rip as u64;
        }

        let vmctx = &mut *vmctx;
        if vmctx.program_range.contains(&rip) {
            vmctx.native_program_counter = Some(rip);

            log::trace!("Trap triggered at 0x{rip:x}");
            trigger_trap(vmctx);
        }
    }

    // This signal is unrelated to anything the guest program did; proceed normally.

    let old = &*old.as_ptr();
    if old.sa_sigaction == sys::SIG_IGN || old.sa_sigaction == sys::SIG_DFL {
        sys::sigaction(signal, old, core::ptr::null_mut());
        return;
    }

    if old.sa_flags & sys::SA_SIGINFO != 0 {
        let old_handler = core::mem::transmute::<usize, extern "C" fn(c_int, &sys::siginfo_t, &sys::ucontext_t)>(old.sa_sigaction);
        old_handler(signal, info, context);
    } else {
        let old_handler = core::mem::transmute::<usize, extern "C" fn(c_int)>(old.sa_sigaction);
        old_handler(signal);
    }
}

unsafe fn register_signal_handler_for_signal(signal: c_int, old_sa: &mut MaybeUninit<sys::sigaction>) -> Result<(), Error> {
    let mut sa: sys::sigaction = core::mem::zeroed();
    let old_sa = old_sa.write(core::mem::zeroed());

    sa.sa_flags = sys::SA_SIGINFO | sys::SA_NODEFER;
    sa.sa_sigaction = signal_handler as usize;
    sys::sigemptyset(&mut sa.sa_mask);
    if sys::sigaction(signal, &sa, old_sa) < 0 {
        return Err(Error(std::io::Error::last_os_error()));
    }

    Ok(())
}

unsafe fn register_signal_handlers() -> Result<(), Error> {
    register_signal_handler_for_signal(sys::SIGSEGV, &mut OLD_SIGSEGV)?;
    register_signal_handler_for_signal(sys::SIGILL, &mut OLD_SIGILL)?;
    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    register_signal_handler_for_signal(sys::SIGBUS, &mut OLD_SIGBUS)?;
    Ok(())
}

fn register_signal_handlers_if_necessary() -> Result<(), Error> {
    const STATE_UNINITIALIZED: usize = 0;
    const STATE_INITIALIZING: usize = 1;
    const STATE_FINISHED: usize = 2;
    const STATE_ERROR: usize = 3;

    static FLAG: AtomicUsize = AtomicUsize::new(STATE_UNINITIALIZED);
    if FLAG.load(Ordering::Relaxed) == STATE_FINISHED {
        return Ok(());
    }

    match FLAG.compare_exchange(STATE_UNINITIALIZED, STATE_INITIALIZING, Ordering::Acquire, Ordering::Relaxed) {
        Ok(_) => {
            // SAFETY: This can only run once and any parallel invocation will
            // wait for the first one that was triggered, so calling this is safe.
            let result = unsafe { register_signal_handlers() };
            if let Err(error) = result {
                FLAG.store(STATE_ERROR, Ordering::Release);
                Err(error)
            } else {
                FLAG.store(STATE_FINISHED, Ordering::Release);
                Ok(())
            }
        },
        Err(_) => {
            loop {
                match FLAG.load(Ordering::Relaxed) {
                    STATE_INITIALIZING => continue,
                    STATE_FINISHED => return Ok(()),
                    _ => return Err("failed to set up signal handlers".into())
                }
            }
        }
    }
}

thread_local! {
    static THREAD_VMCTX: UnsafeCell<*mut VmCtx> = const { UnsafeCell::new(core::ptr::null_mut()) };
}

unsafe fn sysreturn(vmctx: &mut VmCtx) -> ! {
    debug_assert_ne!(vmctx.return_address, 0);
    debug_assert_ne!(vmctx.return_stack_pointer, 0);

    // SAFETY: This function can only be called while we're executing guest code.
    unsafe {
        core::arch::asm!(r#"
            // Restore the stack pointer to its original value.
            mov rsp, [{vmctx} + 8]

            // Jump back
            jmp [{vmctx}]
        "#,
            vmctx = in(reg) vmctx,
            options(noreturn)
        );
    }
}

unsafe fn trigger_trap(vmctx: &mut VmCtx) -> ! {
    vmctx.trap_triggered = true;
    sysreturn(vmctx);
}

const REG_COUNT: usize = polkavm_common::program::Reg::ALL_NON_ZERO.len();

#[repr(C)]
struct VmCtx {
    // NOTE: These two fields are accessed from inline assembly so they shouldn't be moved!
    return_address: usize,
    return_stack_pointer: usize,

    gas: i64,

    program_range: Range<u64>,
    trap_triggered: bool,

    regs: CacheAligned<[u32; REG_COUNT]>,
    on_hostcall: Option<OnHostcall<'static, Sandbox>>,
    sandbox: *mut Sandbox,
    instruction_number: Option<u32>,
    native_program_counter: Option<u64>,
}

impl VmCtx {
    /// Creates a fresh VM context.
    pub fn new() -> Self {
        VmCtx {
            return_address: 0,
            return_stack_pointer: 0,
            trap_triggered: false,
            program_range: 0..0,

            gas: 0,
            regs: CacheAligned([0; REG_COUNT]),
            on_hostcall: None,
            sandbox: core::ptr::null_mut(),
            instruction_number: None,
            native_program_counter: None,
        }
    }

    #[inline(always)]
    pub const fn regs(&self) -> &[u32; REG_COUNT] {
        &self.regs.0
    }
}

// Make sure it fits within a single page on amd64.
polkavm_common::static_assert!(core::mem::size_of::<VmCtx>() <= 4096);

#[derive(Default)]
pub struct SandboxConfig {
}

impl super::SandboxConfig for SandboxConfig {
    fn enable_logger(&mut self, _value: bool) {
    }
}

unsafe fn vmctx_ptr(memory: &Mmap) -> *const VmCtx {
    memory.as_ptr().cast::<u8>().offset(get_guest_memory_offset() as isize + GUEST_MEMORY_TO_VMCTX_OFFSET).cast()
}

unsafe fn vmctx_mut_ptr(memory: &mut Mmap) -> *mut VmCtx {
    memory.as_mut_ptr().cast::<u8>().offset(get_guest_memory_offset() as isize + GUEST_MEMORY_TO_VMCTX_OFFSET).cast()
}

unsafe fn conjure_vmctx<'a>() -> &'a mut VmCtx {
    &mut *THREAD_VMCTX.with(|thread_ctx| *thread_ctx.get())
}

unsafe extern "C" fn syscall_hostcall(hostcall: u32) {
    // SAFETY: We were called from the inside of the guest program, so vmctx must be valid.
    let vmctx = unsafe { conjure_vmctx() };

    let Some(on_hostcall) = vmctx.on_hostcall.as_mut().take() else {
        trigger_trap(vmctx);
    };

    // SAFETY: We were called from the inside of the guest program, so no other
    // mutable references to the sandbox can be concurrently alive.
    let sandbox = unsafe {
        &mut *vmctx.sandbox
    };

    match on_hostcall(hostcall, super::Sandbox::access(sandbox)) {
        Ok(()) => {}
        Err(_) => trigger_trap(vmctx)
    }
}

unsafe extern "C" fn syscall_trace(instruction_number: u32, rip: u64) {
    // SAFETY: We were called from the inside of the guest program, so vmctx must be valid.
    let vmctx = unsafe { conjure_vmctx() };

    vmctx.instruction_number = Some(instruction_number);
    vmctx.native_program_counter = Some(rip);

    let Some(on_hostcall) = vmctx.on_hostcall.as_mut().take() else {
        return;
    };

    // SAFETY: We were called from the inside of the guest program, so no other
    // mutable references to the sandbox can be concurrently alive.
    let sandbox = unsafe {
        &mut *vmctx.sandbox
    };

    match on_hostcall(polkavm_common::HOSTCALL_TRACE, super::Sandbox::access(sandbox)) {
        Ok(()) => {}
        Err(_) => trigger_trap(vmctx)
    }
}

unsafe extern "C" fn syscall_trap() -> ! {
    // SAFETY: We were called from the inside of the guest program, so vmctx must be valid.
    let vmctx = unsafe { conjure_vmctx() };

    // SAFETY: We were called from the inside of the guest program, so it's safe to trap.
    trigger_trap(vmctx);
}

unsafe extern "C" fn syscall_return() -> ! {
    // SAFETY: We were called from the inside of the guest program, so vmctx must be valid.
    let vmctx = unsafe { conjure_vmctx() };

    // SAFETY: We were called from the inside of the guest program, so it's safe to return.
    sysreturn(vmctx);
}

#[derive(Clone)]
pub struct SandboxProgram(Arc<SandboxProgramInner>);

struct SandboxProgramInner {
    memory_config: SandboxMemoryConfig,
    ro_data: Vec<u8>,
    rw_data: Vec<u8>,

    code_memory: Mmap,
    code_length: usize,

    gas_metering: Option<GasMeteringKind>,
}

impl super::SandboxProgram for SandboxProgram {
    fn machine_code(&self) -> Cow<[u8]> {
        Cow::Borrowed(&self.0.code_memory.as_slice()[..self.0.code_length])
    }
}

enum Poison {
    None,
    Executing,
    Poisoned,
}

pub struct Sandbox {
    poison: Poison,
    program: Option<SandboxProgram>,
    memory: Mmap,
    memory_config: SandboxMemoryConfig,
    guest_memory_offset: usize,
}

impl Drop for Sandbox {
    fn drop(&mut self) {
    }
}

impl Sandbox {
    #[inline]
    fn vmctx(&self) -> &VmCtx {
        // SAFETY: `memory` is always valid and contains a valid `VmCtx`.
        unsafe {
            &*vmctx_ptr(&self.memory)
        }
    }

    #[inline]
    fn vmctx_mut(&mut self) -> &mut VmCtx {
        // SAFETY: `memory` is always valid and contains a valid `VmCtx`.
        unsafe {
            &mut *vmctx_mut_ptr(&mut self.memory)
        }
    }

    fn clear_program(&mut self) -> Result<(), ExecutionError<Error>> {
        let user_memory_region_size = self.memory_config.user_memory_region_size();
        if user_memory_region_size > 0 {
            self.memory.mmap_within(
                self.guest_memory_offset + self.memory_config.user_memory_region_address() as usize,
                self.memory_config.user_memory_region_size() as usize,
                0
            )?;

            self.memory_config.clear_user_memory_sizes();
        }

        if self.memory_config.stack_size() > 0 {
            self.memory.mmap_within(
                self.guest_memory_offset + self.memory_config.stack_address_low() as usize,
                self.memory_config.stack_size() as usize,
                0
            )?;

            self.memory_config.clear_stack_size();
        }

        self.memory_config.clear_code_size();
        self.memory_config.clear_jump_table_size();
        if let Some(program) = self.program.take() {
            if let Some(program) = Arc::into_inner(program.0) {
                program.code_memory.unmap()?;
            }
        }

        Ok(())
    }

    fn reset_memory(&mut self) -> Result<(), ExecutionError<Error>> {
        if let Some(ref program) = self.program {
            let program = &program.0;
            let rw_data_size = self.memory_config.rw_data_size() as usize;
            if rw_data_size > 0 {
                let offset = self.guest_memory_offset + self.memory_config.rw_data_address() as usize;
                assert!(program.rw_data.len() <= rw_data_size);

                self.memory.as_slice_mut()[offset..offset + program.rw_data.len()].copy_from_slice(&program.rw_data);
                self.memory.as_slice_mut()[offset + program.rw_data.len()..offset + self.memory_config.rw_data_size() as usize].fill(0);
            }

            let bss_size = self.memory_config.bss_size() as usize;
            if bss_size > 0 {
                self.memory.mmap_within(
                    self.guest_memory_offset + self.memory_config.bss_address() as usize,
                    bss_size,
                    PROT_READ | PROT_WRITE
                )?;
            }

            let stack_size = self.memory_config.stack_size() as usize;
            if stack_size > 0 {
                self.memory.mmap_within(
                    self.guest_memory_offset + self.memory_config.stack_address_low() as usize,
                    stack_size,
                    PROT_READ | PROT_WRITE
                )?;
            }
        } else {
            assert_eq!(self.memory_config.ro_data_size(), 0);
            assert_eq!(self.memory_config.rw_data_size(), 0);
            assert_eq!(self.memory_config.stack_size(), 0);
        }

        Ok(())
    }

    fn bound_check_access(&self, address: u32, length: u32) -> Result<(), ()> {
        use core::ops::Range;

        #[inline]
        fn check(range: Range<u32>, access_range: Range<u64>) -> Result<bool, ()> {
            let range = range.start as u64..range.end as u64;
            if access_range.end <= range.start || access_range.start >= range.end {
                // No overlap.
                Ok(false)
            } else {
                // There is overlap.
                if access_range.start >= range.start && access_range.end <= range.end {
                    Ok(true)
                } else {
                    Err(())
                }
            }
        }

        let range = address as u64..address as u64 + length as u64;
        if check(self.memory_config.ro_data_range(), range.clone())? || check(self.memory_config.heap_range(), range.clone())? || check(self.memory_config.stack_range(), range)? {
            Ok(())
        } else {
            Err(())
        }
    }

    fn get_memory_slice(&self, address: u32, length: u32) -> Option<&[u8]> {
        self.bound_check_access(address, length).ok()?;
        let range = self.guest_memory_offset + address as usize..self.guest_memory_offset + address as usize + length as usize;
        Some(&self.memory.as_slice()[range])
    }

    fn get_memory_slice_mut(&mut self, address: u32, length: u32) -> Option<&mut [u8]> {
        self.bound_check_access(address, length).ok()?;
        let range = self.guest_memory_offset + address as usize..self.guest_memory_offset + address as usize + length as usize;
        Some(&mut self.memory.as_slice_mut()[range])
    }

    fn execute_impl(&mut self, mut args: ExecuteArgs<Self>) -> Result<(), ExecutionError<Error>> {
        if let Some(SandboxProgram(program)) = args.program {
            log::trace!("Reconfiguring sandbox...");
            self.clear_program()?;

            let current = &mut self.memory_config;
            let new = program.memory_config;
            if new.ro_data_size() > 0 {
                let offset = self.guest_memory_offset + new.ro_data_address() as usize;
                let length = new.ro_data_size() as usize;
                assert!(program.ro_data.len() <= length);

                self.memory.modify_and_protect(offset, length, PROT_READ, |slice| {
                    slice[..program.ro_data.len()].copy_from_slice(&program.ro_data);
                })?;

                let memory_address = self.memory.as_ptr() as usize + offset;
                log::trace!(
                    "  New rodata range: 0x{:x}-0x{:x} (0x{:x}-0x{:x}) (0x{:x})",
                    memory_address,
                    memory_address + length,
                    new.ro_data_address(),
                    new.ro_data_address() + new.ro_data_size(),
                    new.ro_data_size()
                );

                current.set_ro_data_size(new.ro_data_size()).unwrap();
            }

            if new.rw_data_size() > 0 {
                let offset = self.guest_memory_offset + new.rw_data_address() as usize;
                let length = new.rw_data_size() as usize;
                assert!(program.rw_data.len() <= length);

                self.memory.modify_and_protect(offset, length, PROT_READ | PROT_WRITE, |slice| {
                    slice[..program.rw_data.len()].copy_from_slice(&program.rw_data);
                })?;

                let memory_address = self.memory.as_ptr() as usize + offset;
                log::trace!(
                    "  New rwdata range: 0x{:x}-0x{:x} (0x{:x}-0x{:x}) (0x{:x})",
                    memory_address,
                    memory_address + length,
                    new.rw_data_address(),
                    new.rw_data_address() + new.rw_data_size(),
                    new.rw_data_size()
                );

                current.set_rw_data_size(new.rw_data_size()).unwrap();
            }

            if new.bss_size() > 0 {
                let offset = self.guest_memory_offset + new.bss_address() as usize;
                let length = new.bss_size() as usize;

                self.memory.mprotect(offset, length, PROT_READ | PROT_WRITE)?;

                let memory_address = self.memory.as_ptr() as usize + offset;
                log::trace!(
                    "  New bss range: 0x{:x}-0x{:x} (0x{:x}-0x{:x}) (0x{:x})",
                    memory_address,
                    memory_address + length,
                    new.bss_address(),
                    new.bss_address() + new.bss_size(),
                    new.bss_size()
                );

                current.set_bss_size(new.bss_size()).unwrap();
            }

            if new.stack_size() > 0 {
                let offset = self.guest_memory_offset + new.stack_address_low() as usize;
                let length = new.stack_size() as usize;

                self.memory.mprotect(offset, length, PROT_READ | PROT_WRITE)?;

                let memory_address = self.memory.as_ptr() as usize + offset;
                log::trace!(
                    "  New stack range: 0x{:x}-0x{:x} (0x{:x}-0x{:x}) (0x{:x})",
                    memory_address,
                    memory_address + length,
                    new.stack_address_low(),
                    new.stack_address_low() + new.stack_size(),
                    new.stack_size()
                );

                current.set_stack_size(new.stack_size()).unwrap();
            }

            let native_page_size = get_native_page_size();
            current.set_code_size(native_page_size, new.code_size()).unwrap();
            current.set_jump_table_size(native_page_size, new.jump_table_size()).unwrap();
            self.program = Some(SandboxProgram(program.clone()));

            if *current != new {
                panic!("internal error: failed to fully update memory configuration");
            }
        }

        self.vmctx_mut().regs.copy_from_slice(args.initial_regs);
        if let Some(gas) = args.get_gas(self.program.as_ref().and_then(|program| program.0.gas_metering)) {
            self.vmctx_mut().gas = gas;
        }

        let mut trap_triggered = false;
        if args.rpc_address != 0 {
            {
                let Some(program) = self.program.as_ref() else {
                    return Err(ExecutionError::Trap(Trap::default()));
                };

                let code = &program.0.code_memory;
                let address = code.as_ptr() as u64;
                self.vmctx_mut().program_range = address..address + code.len() as u64;
            }
            log::trace!("Jumping to: 0x{:x}", args.rpc_address);

            let on_hostcall: Option<OnHostcall<Sandbox>> = args.on_hostcall.take();
            // SAFETY: Transmuting an arbitrary lifetime into a 'static lifetime is safe as long as the invariants
            // that the shorter lifetime requires are still upheld.
            let on_hostcall: Option<OnHostcall<'static, Sandbox>> = unsafe { core::mem::transmute(on_hostcall) };
            self.vmctx_mut().on_hostcall = on_hostcall;
            self.vmctx_mut().sandbox = self;
            self.vmctx_mut().trap_triggered = false;

            #[allow(clippy::undocumented_unsafe_blocks)]
            unsafe {
                let vmctx = vmctx_mut_ptr(&mut self.memory);
                THREAD_VMCTX.with(|thread_ctx| core::ptr::write(thread_ctx.get(), vmctx));

                let guest_memory = self.memory.as_ptr().cast::<u8>().add(self.guest_memory_offset);

                core::arch::asm!(r#"
                    push rbp
                    push rbx

                    // Fill in the return address.
                    lea rbx, [rip+1f]
                    mov [r14], rbx

                    // Fill in the return stack pointer.
                    mov [r14 + 8], rsp

                    // Align the stack.
                    sub rsp, 8

                    // Call into the guest program.
                    jmp {entry_point}

                    // We will jump here on exit.
                    1:

                    pop rbx
                    pop rbp
                "#,
                    entry_point = in(reg) args.rpc_address,
                    // Mark all of the clobbered registers.
                    //
                    // We need to save and restore rbp and rbx manually since
                    // the inline assembly doesn't support using them as operands.
                    clobber_abi("C"),
                    lateout("rax") _,
                    lateout("rcx") _,
                    lateout("rdx") _,
                    lateout("rsi") _,
                    lateout("rdi") _,
                    lateout("r8") _,
                    lateout("r9") _,
                    lateout("r10") _,
                    lateout("r11") _,
                    lateout("r12") _,
                    lateout("r13") _,
                    inlateout("r14") vmctx => _,
                    in("r15") guest_memory,
                );

                THREAD_VMCTX.with(|thread_ctx| core::ptr::write(thread_ctx.get(), core::ptr::null_mut()));
            }

            trap_triggered = core::mem::replace(&mut self.vmctx_mut().trap_triggered, false);
            self.vmctx_mut().sandbox = core::ptr::null_mut();
            self.vmctx_mut().on_hostcall = None;
            self.vmctx_mut().return_address = 0;
            self.vmctx_mut().return_stack_pointer = 0;
            self.vmctx_mut().program_range = 0..0;
        };

        if args.rpc_flags & VM_RPC_FLAG_CLEAR_PROGRAM_AFTER_EXECUTION != 0 {
            self.clear_program()?;
        } else if args.rpc_flags & VM_RPC_FLAG_RESET_MEMORY_AFTER_EXECUTION != 0 {
            self.reset_memory()?;
        }

        if trap_triggered {
            return Err(ExecutionError::Trap(Trap::default()));
        }

        Ok(())
    }
}

impl super::SandboxAddressSpace for Mmap {
    fn native_code_address(&self) -> u64 {
        self.as_ptr() as u64
    }
}

impl super::Sandbox for Sandbox {
    const KIND: SandboxKind = SandboxKind::Generic;

    type Access<'r> = SandboxAccess<'r>;
    type Config = SandboxConfig;
    type Error = Error;
    type Program = SandboxProgram;
    type AddressSpace = Mmap;

    fn reserve_address_space() -> Result<Self::AddressSpace, Self::Error> {
        Mmap::reserve_address_space(VM_SANDBOX_MAXIMUM_NATIVE_CODE_SIZE as usize + VM_SANDBOX_MAXIMUM_JUMP_TABLE_VIRTUAL_SIZE as usize)
    }

    fn prepare_program(init: SandboxProgramInit, mut map: Self::AddressSpace, gas_metering: Option<GasMeteringKind>) -> Result<Self::Program, Self::Error> {
        let native_page_size = get_native_page_size();
        let cfg = init.memory_config(native_page_size)?;

        assert_eq!(cfg.code_size() % native_page_size, 0);
        assert!(init.code.len() <= cfg.code_size());

        let jump_table_offset = cfg.code_size();
        let sysreturn_offset = jump_table_offset + (VM_ADDR_JUMP_TABLE_RETURN_TO_HOST - VM_ADDR_JUMP_TABLE) as usize;

        map.modify_and_protect(0, cfg.code_size(), PROT_EXEC, |slice| {
            slice[..init.code.len()].copy_from_slice(init.code);
        })?;

        map.modify_and_protect(jump_table_offset, cfg.jump_table_size(), PROT_READ, |slice| {
            slice[..init.jump_table.len()].copy_from_slice(init.jump_table);
        })?;

        map.modify_and_protect(sysreturn_offset, native_page_size, PROT_READ, |slice| {
            slice[..8].copy_from_slice(&init.sysreturn_address.to_le_bytes());
        })?;

        log::trace!(
            "New code range: 0x{:x}-0x{:x} (0x{:x})",
            map.as_ptr() as u64,
            map.as_ptr() as u64 + cfg.code_size() as u64,
            cfg.code_size()
        );

        log::trace!(
            "New jump table range: 0x{:x}-0x{:x} (0x{:x})",
            map.as_ptr() as u64 + jump_table_offset as u64,
            map.as_ptr() as u64 + jump_table_offset as u64 + cfg.jump_table_size() as u64,
            cfg.jump_table_size()
        );

        log::trace!(
            "New sysreturn address: 0x{:x} (set at 0x{:x})",
            init.sysreturn_address,
            map.as_ptr() as u64 + sysreturn_offset as u64
        );

        Ok(SandboxProgram(Arc::new(SandboxProgramInner {
            memory_config: cfg,
            ro_data: init.ro_data().to_vec(),
            rw_data: init.rw_data().to_vec(),
            code_memory: map,
            code_length: init.code.len(),
            gas_metering,
        })))
    }

    fn spawn(_config: &SandboxConfig) -> Result<Self, Error> {
        register_signal_handlers_if_necessary()?;

        let guest_memory_offset = get_guest_memory_offset();
        let mut memory = Mmap::reserve_address_space(guest_memory_offset + 0x100000000)?;

        // Make the space for VmCtx read-write.
        polkavm_common::static_assert!(GUEST_MEMORY_TO_VMCTX_OFFSET < 0);
        memory.mprotect(0, guest_memory_offset, PROT_READ | PROT_WRITE)?;

        // SAFETY: We just mmaped this and made it read-write.
        unsafe {
            core::ptr::write(vmctx_mut_ptr(&mut memory), VmCtx::new());
        }

        Ok(Sandbox {
            poison: Poison::None,
            program: None,
            memory,
            memory_config: SandboxMemoryConfig::empty(),
            guest_memory_offset,
        })
    }

    fn execute(&mut self, args: ExecuteArgs<Self>) -> Result<(), ExecutionError<Error>> {
        if !matches!(self.poison, Poison::None) {
            return Err(ExecutionError::Error("sandbox has been poisoned".into()));
        }

        self.poison = Poison::Executing;
        match self.execute_impl(args) {
            result @ Err(ExecutionError::Error(_)) => {
                self.poison = Poison::Poisoned;
                result
            }
            result @ (Ok(()) | Err(ExecutionError::Trap(_) | ExecutionError::OutOfGas)) => {
                self.poison = Poison::None;
                result
            }
        }
    }

    #[inline]
    fn access(&mut self) -> SandboxAccess {
        SandboxAccess { sandbox: self }
    }

    fn pid(&self) -> Option<u32> {
        None
    }

    fn address_table() -> AddressTable {
        AddressTable::from_raw(AddressTableRaw {
            syscall_hostcall,
            syscall_trap,
            syscall_return,
            syscall_trace,
        })
    }

    fn vmctx_regs_offset() -> usize {
        get_field_offset!(VmCtx::new(), |base| base.regs())
    }

    fn vmctx_gas_offset() -> usize {
        get_field_offset!(VmCtx::new(), |base| &base.gas)
    }

    fn gas_remaining_impl(&self) -> Result<Option<Gas>, super::OutOfGas> {
        let Some(program) = self.program.as_ref() else { return Ok(None) };
        if program.0.gas_metering.is_none() { return Ok(None) };
        let raw_gas = self.vmctx().gas;
        Gas::from_i64(raw_gas).ok_or(super::OutOfGas).map(Some)
    }

    fn sync(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

pub struct SandboxAccess<'a> {
    sandbox: &'a mut Sandbox,
}

impl<'a> From<SandboxAccess<'a>> for BackendAccess<'a> {
    fn from(access: SandboxAccess<'a>) -> Self {
        BackendAccess::CompiledGeneric(access)
    }
}

impl<'a> Access<'a> for SandboxAccess<'a> {
    type Error = MemoryAccessError<&'static str>;

    fn get_reg(&self, reg: Reg) -> u32 {
        if reg == Reg::Zero {
            return 0;
        }

        assert!(!matches!(self.sandbox.poison, Poison::Poisoned), "sandbox has been poisoned");
        self.sandbox.vmctx().regs[reg as usize - 1]
    }

    fn set_reg(&mut self, reg: Reg, value: u32) {
        if reg == Reg::Zero {
            return;
        }

        assert!(!matches!(self.sandbox.poison, Poison::Poisoned), "sandbox has been poisoned");
        self.sandbox.vmctx_mut().regs[reg as usize - 1] = value;
    }

    fn read_memory_into_slice<'slice, T>(&self, address: u32, buffer: &'slice mut T) -> Result<&'slice mut [u8], Self::Error>
    where
        T: ?Sized + AsUninitSliceMut,
    {
        let buffer = buffer.as_uninit_slice_mut();
        log::trace!(
            "Reading memory: 0x{:x}-0x{:x} ({} bytes)",
            address,
            address as usize + buffer.len(),
            buffer.len()
        );

        if matches!(self.sandbox.poison, Poison::Poisoned) {
            return Err(MemoryAccessError {
                address,
                length: buffer.len() as u64,
                error: "read failed: sandbox has been poisoned",
            });
        }

        let Some(slice) = self.sandbox.get_memory_slice(address, buffer.len() as u32) else {
            return Err(MemoryAccessError {
                address,
                length: buffer.len() as u64,
                error: "out of range read",
            });
        };

        Ok(byte_slice_init(buffer, slice))
    }

    fn write_memory(&mut self, address: u32, data: &[u8]) -> Result<(), Self::Error> {
        log::trace!(
            "Writing memory: 0x{:x}-0x{:x} ({} bytes)",
            address,
            address as usize + data.len(),
            data.len()
        );

        if matches!(self.sandbox.poison, Poison::Poisoned) {
            return Err(MemoryAccessError {
                address,
                length: data.len() as u64,
                error: "write failed: sandbox has been poisoned",
            });
        }

        let Some(slice) = self.sandbox.get_memory_slice_mut(address, data.len() as u32) else {
            return Err(MemoryAccessError {
                address,
                length: data.len() as u64,
                error: "out of range write",
            });
        };

        slice.copy_from_slice(data);
        Ok(())
    }

    fn program_counter(&self) -> Option<u32> {
        self.sandbox.vmctx().instruction_number
    }

    fn native_program_counter(&self) -> Option<u64> {
        self.sandbox.vmctx().native_program_counter
    }

    fn gas_remaining(&self) -> Option<Gas> {
        use super::Sandbox;
        self.sandbox.gas_remaining_impl().ok().unwrap_or(Some(Gas::MIN))
    }

    fn consume_gas(&mut self, gas: u64) {
        if self.sandbox.program.as_ref().and_then(|program| program.0.gas_metering).is_none() {
            return;
        }

        let gas_remaining = &mut self.sandbox.vmctx_mut().gas;
        *gas_remaining = gas_remaining.checked_sub_unsigned(gas).unwrap_or(-1);
    }
}
