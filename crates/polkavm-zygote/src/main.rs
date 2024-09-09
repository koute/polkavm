#![no_std]
#![no_main]
#![allow(clippy::missing_safety_doc)]

use core::ptr::addr_of_mut;
use core::sync::atomic::Ordering;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize};

#[rustfmt::skip]
use polkavm_common::{
    utils::align_to_next_page_usize,
    zygote::{
        self,
        AddressTableRaw, ExtTableRaw, VmCtx as VmCtxInner,
        VmMap, VmFd, JmpBuf,
        VM_ADDR_JUMP_TABLE_RETURN_TO_HOST,
        VM_ADDR_JUMP_TABLE,
        VM_ADDR_NATIVE_CODE,
        VM_ADDR_SHARED_MEMORY,
        VM_ADDR_SIGSTACK,
        VM_SANDBOX_MAXIMUM_JUMP_TABLE_SIZE,
        VM_SANDBOX_MAXIMUM_JUMP_TABLE_VIRTUAL_SIZE,
        VM_SANDBOX_MAXIMUM_NATIVE_CODE_SIZE,
        VM_SHARED_MEMORY_SIZE,
        VMCTX_FUTEX_BUSY,
        VMCTX_FUTEX_GUEST_ECALLI,
        VMCTX_FUTEX_GUEST_STEP,
        VMCTX_FUTEX_GUEST_TRAP,
        VMCTX_FUTEX_GUEST_SIGNAL,
        VMCTX_FUTEX_IDLE,
    },
};
use polkavm_linux_raw as linux_raw;

#[cfg(debug_assertions)]
#[no_mangle]
extern "C" fn rust_eh_personality() {
    abort_with_message("rust_eh_personality called");
}

fn write_number_base10(value: u64, write_str: &mut dyn FnMut(&str)) {
    let n = if value >= 10 {
        write_number_base10(value / 10, write_str);
        value % 10
    } else {
        value
    };

    let s = [n as u8 + b'0'];
    let s = unsafe { core::str::from_utf8_unchecked(&s) };
    write_str(s);
}

fn write_number_base16(value: u64, write_str: &mut dyn FnMut(&str)) {
    let n = if value >= 16 {
        write_number_base16(value / 16, write_str);
        value % 16
    } else {
        value
    };

    let s = [if n < 10 { n as u8 + b'0' } else { (n - 10) as u8 + b'a' }];
    let s = unsafe { core::str::from_utf8_unchecked(&s) };
    write_str(s);
}

trait DisplayLite {
    fn fmt_lite(&self, write_str: impl FnMut(&str));
}

impl DisplayLite for &str {
    fn fmt_lite(&self, mut write_str: impl FnMut(&str)) {
        write_str(self)
    }
}

impl DisplayLite for usize {
    fn fmt_lite(&self, write_str: impl FnMut(&str)) {
        (*self as u64).fmt_lite(write_str)
    }
}

impl DisplayLite for u32 {
    fn fmt_lite(&self, write_str: impl FnMut(&str)) {
        u64::from(*self).fmt_lite(write_str)
    }
}

impl DisplayLite for u64 {
    fn fmt_lite(&self, mut write_str: impl FnMut(&str)) {
        write_number_base10(*self, &mut write_str)
    }
}

impl DisplayLite for i64 {
    fn fmt_lite(&self, mut write_str: impl FnMut(&str)) {
        let value = if *self > 0 {
            *self as u64
        } else {
            write_str("-");
            (*self * -1) as u64
        };

        write_number_base10(value, &mut write_str)
    }
}

struct Hex<T>(T);

impl DisplayLite for Hex<usize> {
    fn fmt_lite(&self, write_str: impl FnMut(&str)) {
        Hex(self.0 as u64).fmt_lite(write_str)
    }
}

impl DisplayLite for Hex<u32> {
    fn fmt_lite(&self, write_str: impl FnMut(&str)) {
        Hex(u64::from(self.0)).fmt_lite(write_str)
    }
}

impl DisplayLite for Hex<u64> {
    fn fmt_lite(&self, mut write_str: impl FnMut(&str)) {
        write_str("0x");
        write_number_base16(self.0, &mut write_str)
    }
}

macro_rules! trace {
    ($arg:expr) => {{
        let fd = linux_raw::FdRef::from_raw_unchecked(zygote::FD_LOGGER_STDERR);
        let _ = linux_raw::sys_write(fd, $arg.as_bytes());
        let _ = linux_raw::sys_write(fd, b"\n");
    }};

    ($($arg:expr),+) => {{
        let fd = linux_raw::FdRef::from_raw_unchecked(zygote::FD_LOGGER_STDERR);
        $(
            DisplayLite::fmt_lite(&$arg, |s| {
                let _ = linux_raw::sys_write(fd, s.as_bytes());
            });
        )+
        let _ = linux_raw::sys_write(fd, b"\n");
    }};
}

#[repr(transparent)]
pub struct VmCtx(VmCtxInner);

unsafe impl Sync for VmCtx {}

impl core::ops::Deref for VmCtx {
    type Target = VmCtxInner;

    #[inline(always)]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[no_mangle]
#[link_section = ".vmctx"]
#[used]
// Use the `zeroed` constructor to make sure this doesn't take up any space in the executable.
pub static VMCTX: VmCtx = VmCtx(VmCtxInner::zeroed());

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    abort_with_message("panic triggered in zygote");
}

#[no_mangle]
unsafe fn memset(dst: *mut u8, value: u32, size: usize) -> *mut u8 {
    let mut p = dst;
    let end = dst.add(size);
    while p < end {
        *p = value as u8;
        p = p.add(1);
    }

    dst
}

#[no_mangle]
unsafe fn memcpy(dst: *mut u8, src: *const u8, size: usize) -> *mut u8 {
    core::arch::asm!(
        "rep movsb", inout("rdi") dst => _, inout("rsi") src => _, inout("rcx") size => _,
        options(preserves_flags, nostack)
    );

    dst
}

fn reset_message() {
    unsafe {
        *VMCTX.message_length.get() = 0;
    }
}

#[inline]
fn append_to_message<'a, 'b>(mut input: &[u8])
where
    'a: 'b,
{
    let message_length = unsafe { &mut *VMCTX.message_length.get() };
    let message_buffer = &mut unsafe { &mut *VMCTX.message_buffer.get() }[..];

    while !input.is_empty() && (*message_length as usize) < message_buffer.len() {
        message_buffer[*message_length as usize] = input[0];
        *message_length += 1;
        input = &input[1..];
    }
}

fn graceful_abort() -> ! {
    let in_signal_handler = IN_SIGNAL_HANDLER.swap(true, Ordering::Relaxed);
    let errcode = if in_signal_handler { 101 } else { 100 };
    let _ = linux_raw::sys_exit(errcode);
    linux_raw::abort();
}

#[cold]
fn abort_with_message(error: &str) -> ! {
    let fd = linux_raw::FdRef::from_raw_unchecked(zygote::FD_LOGGER_STDERR);
    let _ = linux_raw::sys_write(fd, b"fatal error: ");
    let _ = linux_raw::sys_write(fd, error.as_bytes());
    let _ = linux_raw::sys_write(fd, b"\n");

    reset_message();
    append_to_message(error.as_bytes());

    core::sync::atomic::fence(Ordering::Release);
    graceful_abort();
}

#[cold]
fn abort_with_error(error: &str, err_obj: linux_raw::Error) -> ! {
    let fd = linux_raw::FdRef::from_raw_unchecked(zygote::FD_LOGGER_STDERR);
    let _ = linux_raw::sys_write(fd, b"fatal error: ");
    let _ = linux_raw::sys_write(fd, error.as_bytes());
    let _ = linux_raw::sys_write(fd, b": ");

    reset_message();
    append_to_message(error.as_bytes());
    append_to_message(b": ");
    err_obj.fmt_to_string(move |s| {
        let _ = linux_raw::sys_write(fd, s.as_bytes());
        append_to_message(s.as_bytes());
    });
    let _ = linux_raw::sys_write(fd, b"\n");

    core::sync::atomic::fence(Ordering::Release);
    graceful_abort();
}

unsafe extern "C" fn entry_point(stack: *mut usize) -> ! {
    trace!("initializing...");
    initialize(stack);
    main_loop();
}

#[inline]
fn shm_fd() -> linux_raw::FdRef<'static> {
    linux_raw::FdRef::from_raw_unchecked(zygote::FD_SHM)
}

#[inline]
fn memory_fd() -> linux_raw::FdRef<'static> {
    linux_raw::FdRef::from_raw_unchecked(zygote::FD_MEM)
}

static IN_SIGNAL_HANDLER: AtomicBool = AtomicBool::new(false);
static NATIVE_PAGE_SIZE: AtomicUsize = AtomicUsize::new(!0);

unsafe extern "C" fn signal_handler(signal: u32, _info: &linux_raw::siginfo_t, context: &linux_raw::ucontext) {
    if IN_SIGNAL_HANDLER.load(Ordering::Relaxed) || signal == linux_raw::SIGIO {
        graceful_abort();
    }

    IN_SIGNAL_HANDLER.store(true, Ordering::Relaxed);
    let rip = context.uc_mcontext.rip;

    trace!(
        "Signal received: ",
        signal,
        ", rip = ",
        Hex(rip),
        ", rax = ",
        Hex(context.uc_mcontext.rax),
        ", rcx = ",
        Hex(context.uc_mcontext.rcx),
        ", rdx = ",
        Hex(context.uc_mcontext.rdx),
        ", rbx = ",
        Hex(context.uc_mcontext.rbx),
        ", rsp = ",
        Hex(context.uc_mcontext.rsp),
        ", rbp = ",
        Hex(context.uc_mcontext.rbp),
        ", rsi = ",
        Hex(context.uc_mcontext.rsi),
        ", rdi = ",
        Hex(context.uc_mcontext.rdi),
        ", r8 = ",
        Hex(context.uc_mcontext.r8),
        ", r9 = ",
        Hex(context.uc_mcontext.r9),
        ", r10 = ",
        Hex(context.uc_mcontext.r10),
        ", r11 = ",
        Hex(context.uc_mcontext.r11),
        ", r12 = ",
        Hex(context.uc_mcontext.r12),
        ", r13 = ",
        Hex(context.uc_mcontext.r13),
        ", r14 = ",
        Hex(context.uc_mcontext.r14),
        ", r15 = ",
        Hex(context.uc_mcontext.r15)
    );

    if rip < VM_ADDR_NATIVE_CODE || rip > VM_ADDR_NATIVE_CODE + VMCTX.shm_code_length.load(Ordering::Relaxed) {
        abort_with_message("segmentation fault")
    }

    use polkavm_common::regmap::NativeReg::*;
    for reg in polkavm_common::program::Reg::ALL {
        #[deny(unreachable_patterns)]
        let value = match polkavm_common::regmap::to_native_reg(reg) {
            rax => context.uc_mcontext.rax,
            rcx => context.uc_mcontext.rcx,
            rdx => context.uc_mcontext.rdx,
            rbx => context.uc_mcontext.rbx,
            rbp => context.uc_mcontext.rbp,
            rsi => context.uc_mcontext.rsi,
            rdi => context.uc_mcontext.rdi,
            r8 => context.uc_mcontext.r8,
            r9 => context.uc_mcontext.r9,
            r10 => context.uc_mcontext.r10,
            r11 => context.uc_mcontext.r11,
            r12 => context.uc_mcontext.r12,
            r13 => context.uc_mcontext.r13,
            r14 => context.uc_mcontext.r14,
            r15 => context.uc_mcontext.r15,
        };

        VMCTX.regs[reg as usize].store(value as u32, Ordering::Relaxed);
    }

    VMCTX.next_native_program_counter.store(rip, Ordering::Relaxed);

    signal_host_and_longjmp(VMCTX_FUTEX_GUEST_SIGNAL);
}

static mut RESUME_MAIN_LOOP_JMPBUF: JmpBuf = JmpBuf {
    rip: AtomicU64::new(0),
    rbx: AtomicU64::new(0),
    rsp: AtomicU64::new(0),
    rbp: AtomicU64::new(0),
    r12: AtomicU64::new(0),
    r13: AtomicU64::new(0),
    r14: AtomicU64::new(0),
    r15: AtomicU64::new(0),
};

extern "C" {
    fn zygote_longjmp(jmpbuf: *mut JmpBuf, return_value: u64) -> !;
    fn zygote_setjmp(jmpbuf: *mut JmpBuf) -> u64;
    fn zygote_signal_restorer();
}

use zygote_longjmp as longjmp;
use zygote_setjmp as setjmp;
use zygote_signal_restorer as signal_restorer;

core::arch::global_asm!(
    include_str!(concat!(env!("OUT_DIR"), "/global_asm.s")),
    entry_point = sym entry_point,
);

#[inline(never)]
unsafe fn initialize(mut stack: *mut usize) {
    /*
        The initial stack contains the following:
            argc: usize,
            argv: [*const u8; argc],
            _: *const c_void, // NULL
            envp: [*const u8; _],
            _: *const c_void, // NULL
            auxv: [(usize, usize); _],
            _: (usize, usize), // (AT_NULL, _)
    */
    let argc = *stack;
    stack = stack.add(1);
    let argv = stack.cast::<*mut *mut u8>();
    let envp = argv.add(argc + 1);
    let auxv = {
        let mut p = envp;
        while !(*p).is_null() {
            p = p.add(1);
        }
        p.add(1).cast::<(usize, usize)>()
    };

    let minsigstksz;
    let mut fsgsbase_supported = false;
    let page_size = {
        let mut page_size_opt = None;
        let mut minsigstksz_opt = None;
        let mut auxv = auxv;
        loop {
            let (kind, value) = *auxv;
            if kind == linux_raw::AT_NULL as usize {
                break;
            }

            if kind == linux_raw::AT_PAGESZ as usize {
                page_size_opt = Some(value);
            }

            if kind == linux_raw::AT_MINSIGSTKSZ as usize {
                minsigstksz_opt = Some(value);
            }

            if kind == linux_raw::AT_HWCAP2 as usize && value & linux_raw::HWCAP2_FSGSBASE != 0 {
                fsgsbase_supported = true;
            }

            auxv = auxv.add(1);
        }

        if let Some(size) = minsigstksz_opt {
            trace!("signal stack size: ", size);
        }

        let base_sigstack_size = core::cmp::max(linux_raw::MINSIGSTKSZ as usize, 4 * 4096);
        minsigstksz = core::cmp::max(base_sigstack_size, minsigstksz_opt.unwrap_or(base_sigstack_size));

        if let Some(page_size) = page_size_opt {
            NATIVE_PAGE_SIZE.store(page_size, Ordering::Relaxed);
            page_size
        } else {
            abort_with_message("AT_PAGESZ not found in auxv");
        }
    };

    let vmctx_memfd = linux_raw::Fd::from_raw_unchecked(zygote::FD_VMCTX);
    linux_raw::sys_mmap(
        &VMCTX as *const VmCtx as *mut core::ffi::c_void,
        page_size,
        linux_raw::PROT_READ | linux_raw::PROT_WRITE,
        linux_raw::MAP_FIXED | linux_raw::MAP_SHARED,
        Some(vmctx_memfd.borrow()),
        0,
    )
    .unwrap_or_else(|error| abort_with_error("failed to mmap vmctx", error));

    let socket = linux_raw::Fd::from_raw_unchecked(zygote::FD_SOCKET);
    let lifetime_pipe = linux_raw::Fd::from_raw_unchecked(zygote::FD_LIFETIME_PIPE);

    // Make sure we're killed when the parent process exits.
    let pid = linux_raw::sys_getpid().unwrap_or_else(|error| abort_with_error("failed to get process PID", error)) as u32;
    linux_raw::sys_fcntl(lifetime_pipe.borrow(), linux_raw::F_SETOWN, pid)
        .unwrap_or_else(|error| abort_with_error("failed to fcntl(F_SETOWN) on the lifetime pipe", error));

    linux_raw::sys_fcntl(
        lifetime_pipe.borrow(),
        linux_raw::F_SETFL,
        linux_raw::O_NONBLOCK | linux_raw::O_ASYNC,
    )
    .unwrap_or_else(|error| abort_with_error("failed to fcntl(F_SETFL) on the lifetime pipe", error));

    lifetime_pipe.leak();

    // Map the shared memory.
    linux_raw::sys_mmap(
        VM_ADDR_SHARED_MEMORY as *mut core::ffi::c_void,
        VM_SHARED_MEMORY_SIZE as usize,
        linux_raw::PROT_READ,
        linux_raw::MAP_FIXED | linux_raw::MAP_SHARED,
        Some(shm_fd()),
        0,
    )
    .unwrap_or_else(|error| abort_with_error("failed to mmap shared memory", error));

    // Wait for the host to fill out vmctx.
    VMCTX.futex.store(VMCTX_FUTEX_IDLE, Ordering::Release);
    futex_wait_until(VMCTX_FUTEX_BUSY);

    // Unmap the original stack.
    linux_raw::sys_munmap(
        VMCTX.init.stack_address.load(Ordering::Relaxed) as *mut core::ffi::c_void,
        VMCTX.init.stack_length.load(Ordering::Relaxed) as usize,
    )
    .unwrap_or_else(|error| abort_with_error("failed to unmap kernel-provided stack", error));

    // We don't need the VDSO, so just unmap it.
    if VMCTX.init.vdso_length.load(Ordering::Relaxed) != 0 {
        linux_raw::sys_munmap(
            VMCTX.init.vdso_address.load(Ordering::Relaxed) as *mut core::ffi::c_void,
            VMCTX.init.vdso_length.load(Ordering::Relaxed) as usize,
        )
        .unwrap_or_else(|error| abort_with_error("failed to unmap [vdso]", error));
    }

    if VMCTX.init.vvar_length.load(Ordering::Relaxed) != 0 {
        linux_raw::sys_munmap(
            VMCTX.init.vvar_address.load(Ordering::Relaxed) as *mut core::ffi::c_void,
            VMCTX.init.vvar_length.load(Ordering::Relaxed) as usize,
        )
        .unwrap_or_else(|error| abort_with_error("failed to unmap [vvar]", error));
    }

    // These are technically unnecessary, but let's do it anyway as a just-in-case
    // failsafe in case there's actually something in memory over there.
    linux_raw::sys_munmap(core::ptr::null_mut(), 0x200000000)
        .unwrap_or_else(|error| abort_with_error("failed to make sure the address space is unmapped", error));

    linux_raw::sys_munmap(
        VM_ADDR_JUMP_TABLE as *mut core::ffi::c_void,
        align_to_next_page_usize(page_size, VM_SANDBOX_MAXIMUM_JUMP_TABLE_VIRTUAL_SIZE as usize)
            .unwrap_or_else(|| abort_with_message("overflow")),
    )
    .unwrap_or_else(|error| abort_with_error("failed to make sure the jump table address space is unmapped", error));

    if VMCTX.init.uffd_available.load(Ordering::Relaxed) {
        // Set up and send the userfaultfd to the host.
        let userfaultfd = linux_raw::sys_userfaultfd(linux_raw::O_CLOEXEC)
            .unwrap_or_else(|error| abort_with_error("failed to create an userfaultfd", error));

        if userfaultfd.raw() <= zygote::LAST_USED_FD {
            // We expect all of the FDs less or equal to `LAST_USED_FD` to be allocated.
            abort_with_message("internal error: userfaultfd is using too low file descriptor")
        }

        linux_raw::sendfd(socket.borrow(), userfaultfd.borrow())
            .unwrap_or_else(|error| abort_with_error("failed to send the userfaultfd to the host", error));

        userfaultfd
            .close()
            .unwrap_or_else(|error| abort_with_error("failed to close the userfaultfd", error));
    }

    // Set up our signal handler.
    let minsigstksz = align_to_next_page_usize(page_size, minsigstksz).unwrap_or_else(|| abort_with_message("overflow"));

    linux_raw::sys_mmap(
        VM_ADDR_SIGSTACK as *mut core::ffi::c_void,
        minsigstksz,
        linux_raw::PROT_READ | linux_raw::PROT_WRITE,
        linux_raw::MAP_FIXED | linux_raw::MAP_PRIVATE | linux_raw::MAP_ANONYMOUS,
        None,
        0,
    )
    .unwrap_or_else(|error| abort_with_error("failed to mmap signal stack", error));

    linux_raw::sys_sigaltstack(
        &linux_raw::stack_t {
            ss_sp: VM_ADDR_SIGSTACK as *mut core::ffi::c_void,
            ss_flags: 0,
            ss_size: minsigstksz,
        },
        None,
    )
    .unwrap_or_else(|error| abort_with_error("failed to set signal stack", error));

    let mut sa: linux_raw::kernel_sigaction = core::mem::zeroed();
    // TODO: Fill in `sa_mask`?
    sa.sa_handler = Some(core::mem::transmute(signal_handler as usize));
    sa.sa_flags |=
        linux_raw::SA_RESTORER as u64 | linux_raw::SA_SIGINFO as u64 | linux_raw::SA_NODEFER as u64 | linux_raw::SA_ONSTACK as u64;
    sa.sa_restorer = Some(signal_restorer);

    linux_raw::sys_rt_sigprocmask(linux_raw::SIG_SETMASK, &0, None)
        .unwrap_or_else(|error| abort_with_error("failed to set sigprocmask", error));

    linux_raw::sys_rt_sigaction(linux_raw::SIGSEGV, &sa, None)
        .unwrap_or_else(|error| abort_with_error("failed to set up a signal handler for SIGSEGV", error));

    linux_raw::sys_rt_sigaction(linux_raw::SIGILL, &sa, None)
        .unwrap_or_else(|error| abort_with_error("failed to set up a signal handler for SIGILL", error));

    linux_raw::sys_rt_sigaction(linux_raw::SIGFPE, &sa, None)
        .unwrap_or_else(|error| abort_with_error("failed to set up a signal handler for SIGFPE", error));

    linux_raw::sys_rt_sigaction(linux_raw::SIGIO, &sa, None)
        .unwrap_or_else(|error| abort_with_error("failed to set up a signal handler for SIGIO", error));

    // Set up the sysreturn jump table.
    linux_raw::sys_mmap(
        VM_ADDR_JUMP_TABLE_RETURN_TO_HOST as *mut core::ffi::c_void,
        page_size,
        linux_raw::PROT_READ | linux_raw::PROT_WRITE,
        linux_raw::MAP_FIXED | linux_raw::MAP_PRIVATE | linux_raw::MAP_ANONYMOUS,
        None,
        0,
    )
    .unwrap_or_else(|error| abort_with_error("failed to map the sysreturn jump table", error));

    if fsgsbase_supported {
        trace!("fsgsbase is supported");
        unsafe {
            core::arch::asm!(
                "wrgsbase {addr}",
                addr = in(reg) VM_ADDR_JUMP_TABLE
            );
        }
    } else {
        trace!("fsgsbase is NOT supported; falling back to arch_prctl");
        linux_raw::sys_arch_prctl_set_gs(VM_ADDR_JUMP_TABLE as usize)
            .unwrap_or_else(|error| abort_with_error("failed to set the %gs register", error));
    }

    // Close all of the FDs we don't need anymore.
    vmctx_memfd
        .close()
        .unwrap_or_else(|error| abort_with_error("failed to close vmctx memfd", error));

    socket
        .close()
        .unwrap_or_else(|error| abort_with_error("failed to close the socket", error));

    linux_raw::Fd::from_raw_unchecked(zygote::FD_DUMMY_STDIN)
        .close()
        .unwrap_or_else(|error| abort_with_error("failed to close dummy stdin", error));

    if !VMCTX.init.logging_enabled.load(Ordering::Relaxed) {
        linux_raw::Fd::from_raw_unchecked(zygote::FD_LOGGER_STDOUT)
            .close()
            .unwrap_or_else(|error| abort_with_error("failed to close stdout logger", error));

        linux_raw::Fd::from_raw_unchecked(zygote::FD_LOGGER_STDERR)
            .close()
            .unwrap_or_else(|error| abort_with_error("failed to close stdin logger", error));
    }

    if !VMCTX.init.sandbox_disabled.load(Ordering::Relaxed) {
        linux_raw::sys_setrlimit(linux_raw::RLIMIT_NOFILE, &linux_raw::rlimit { rlim_cur: 0, rlim_max: 0 })
            .unwrap_or_else(|error| abort_with_error("failed to set RLIMIT_NOFILE", error));

        // Change the name of the process.
        linux_raw::sys_prctl_set_name(b"polkavm-sandbox\0")
            .unwrap_or_else(|error| abort_with_error("failed to set the process name", error));

        // Unmount the filesystem.
        //
        // Previously we did this before `execveat`ing into the zygote but for some
        // ungodly unexplicable reason on *some* Linux distributions (but not all of them!)
        // the `pivot_root` makes the `execveat` fail with an ENOENT error, even if we
        // physically copy the zygote binary into the newly created filesystem and open
        // it immediately before `execveat`ing with an `open`, and even if we also have
        // /proc mounted in the new namespace.
        linux_raw::sys_pivot_root(linux_raw::cstr!("."), linux_raw::cstr!("."))
            .unwrap_or_else(|error| abort_with_error("failed to sandbox the filesystem", error));
        linux_raw::sys_umount2(linux_raw::cstr!("."), linux_raw::MNT_DETACH)
            .unwrap_or_else(|error| abort_with_error("failed to sandbox the filesystem", error));

        linux_raw::sys_prctl_set_securebits(
            // Make UID == 0 have no special privileges.
            linux_raw::SECBIT_NOROOT |
            linux_raw::SECBIT_NOROOT_LOCKED |
            // Calling 'setuid' from/to UID == 0 doesn't change any privileges.
            linux_raw::SECBIT_NO_SETUID_FIXUP |
            linux_raw::SECBIT_NO_SETUID_FIXUP_LOCKED |
            // The process cannot add capabilities to its ambient set.
            linux_raw::SECBIT_NO_CAP_AMBIENT_RAISE |
            linux_raw::SECBIT_NO_CAP_AMBIENT_RAISE_LOCKED,
        )
        .unwrap_or_else(|error| abort_with_error("failed to sandbox the zygote", error));

        // Finally, drop all capabilities.
        linux_raw::sys_capset_drop_all().unwrap_or_else(|error| abort_with_error("failed to sandbox the zygote", error));

        const SECCOMP_FILTER: &[linux_raw::sock_filter] = &linux_raw::bpf! {
            (a = syscall_nr),
            (if a == linux_raw::SYS_futex => jump @1),
            (if a == linux_raw::SYS_mmap => jump @5),
            (if a == linux_raw::SYS_munmap => jump @1),
            (if a == linux_raw::SYS_madvise => jump @4),
            (if a == linux_raw::SYS_close => jump @1),
            (if a == linux_raw::SYS_write => jump @3),
            (if a == linux_raw::SYS_rt_sigreturn => jump @1),
            (if a == linux_raw::SYS_sched_yield => jump @1),
            (if a == linux_raw::SYS_exit => jump @1),
            (seccomp_return_eperm),

            // SYS_write
            ([3]: a = syscall_arg[0]),
            (if a != zygote::FD_LOGGER_STDERR => jump @0),
            (seccomp_allow),

            // SYS_madvise
            ([4]: a = syscall_arg[2]),
            (if a != linux_raw::MADV_DONTNEED => jump @0),
            (seccomp_allow),

            // SYS_mmap
            ([5]: a = syscall_arg[2]),
            (a &= linux_raw::PROT_EXEC),
            (if a != 0 => jump @6),
            (seccomp_allow),

            // SYS_mmap + PROT_EXEC
            ([6]: a = syscall_arg[2]),
            (if a != linux_raw::PROT_EXEC => jump @0),
            (seccomp_allow),

            ([0]: seccomp_return_eperm),
            ([1]: seccomp_allow),
        };

        linux_raw::sys_seccomp_set_mode_filter(SECCOMP_FILTER)
            .unwrap_or_else(|error| abort_with_error("failed to set seccomp filter", error));
    }

    VMCTX.futex.store(VMCTX_FUTEX_IDLE, Ordering::Release);
    linux_raw::sys_futex_wake_one(&VMCTX.futex)
        .unwrap_or_else(|error| abort_with_error("failed to wake up the host process on initialization", error));
}

#[inline]
fn futex_wait_until(target_state: u32) {
    let mut state = VMCTX.futex.load(Ordering::Relaxed);
    'main_loop: loop {
        if state == target_state {
            break;
        }

        // Use a `black_box` to prevent loop unrolling.
        for _ in 0..core::hint::black_box(20) {
            let _ = linux_raw::sys_sched_yield();

            state = VMCTX.futex.load(Ordering::Relaxed);
            if state == target_state {
                break 'main_loop;
            }
        }

        match linux_raw::sys_futex_wait(&VMCTX.futex, state, None) {
            Ok(()) => continue,
            Err(error) if error.errno() == linux_raw::EAGAIN || error.errno() == linux_raw::EINTR => continue,
            Err(error) => {
                abort_with_error("failed to wait for the host process", error);
            }
        }
    }

    core::sync::atomic::fence(Ordering::Acquire);
}

#[inline(never)]
unsafe fn main_loop() -> ! {
    if setjmp(addr_of_mut!(RESUME_MAIN_LOOP_JMPBUF)) != 0 {
        IN_SIGNAL_HANDLER.store(false, Ordering::Relaxed);
    }

    futex_wait_until(VMCTX_FUTEX_BUSY);

    let address = VMCTX.jump_into.load(Ordering::Relaxed);
    trace!("Jumping into: ", Hex(address as usize));

    let callback: extern "C" fn() -> ! = core::mem::transmute(address);
    callback();
}

pub unsafe extern "C" fn ext_sbrk() -> ! {
    trace!("Entry point: ext_sbrk");

    let new_heap_top = *VMCTX.heap_info.heap_top.get() + VMCTX.arg.load(Ordering::Relaxed) as u64;
    let result = syscall_sbrk(new_heap_top);
    VMCTX.arg.store(result, Ordering::Relaxed);

    signal_host_and_longjmp(VMCTX_FUTEX_IDLE);
}

pub unsafe extern "C" fn ext_reset_memory() -> ! {
    trace!("Entry point: ext_reset_memory");

    let memory_map = memory_map();
    for map in memory_map {
        if (map.protection & linux_raw::PROT_WRITE) == 0 {
            continue;
        }

        linux_raw::sys_madvise(map.address as *mut core::ffi::c_void, map.length as usize, linux_raw::MADV_DONTNEED)
            .unwrap_or_else(|error| abort_with_error("failed to clear memory", error));
    }

    let heap_base = u64::from(*VMCTX.heap_base.get());
    let heap_initial_threshold = u64::from(*VMCTX.heap_initial_threshold.get());
    let heap_top = *VMCTX.heap_info.heap_top.get();
    if heap_top > heap_initial_threshold {
        linux_raw::sys_munmap(
            heap_initial_threshold as *mut core::ffi::c_void,
            heap_top as usize - heap_initial_threshold as usize,
        )
        .unwrap_or_else(|error| abort_with_error("failed to unmap the heap", error));
    }

    *VMCTX.heap_info.heap_top.get() = heap_base;
    *VMCTX.heap_info.heap_threshold.get() = heap_initial_threshold;

    signal_host_and_longjmp(VMCTX_FUTEX_IDLE);
}

pub unsafe extern "C" fn ext_zero_memory_chunk() -> ! {
    trace!("Entry point: ext_zero_memory_chunk");

    let address = VMCTX.arg.load(Ordering::Relaxed);
    let length = VMCTX.arg2.load(Ordering::Relaxed);
    core::ptr::write_bytes(address as *mut u8, 0, length as usize);

    signal_host_and_longjmp(VMCTX_FUTEX_IDLE);
}

#[inline(never)]
#[no_mangle]
pub unsafe extern "C" fn syscall_hostcall() -> ! {
    trace!("syscall: hostcall triggered");
    signal_host_and_longjmp(VMCTX_FUTEX_GUEST_ECALLI);
}

#[inline(never)]
#[no_mangle]
pub unsafe extern "C" fn syscall_trap() -> ! {
    trace!("syscall: trap triggered");
    signal_host_and_longjmp(VMCTX_FUTEX_GUEST_TRAP);
}

#[inline(never)]
#[no_mangle]
pub unsafe extern "C" fn syscall_return() -> ! {
    trace!("syscall: return triggered");
    signal_host_and_longjmp(VMCTX_FUTEX_IDLE);
}

// Just for debugging. Normally should never be used.
#[inline(never)]
#[no_mangle]
pub unsafe extern "C" fn syscall_step() -> ! {
    // TODO: Add a fast path for this.
    signal_host_and_longjmp(VMCTX_FUTEX_GUEST_STEP);
}

#[inline(never)]
#[no_mangle]
pub unsafe extern "C" fn syscall_sbrk(pending_heap_top: u64) -> u32 {
    trace!(
        "syscall: sbrk triggered: ",
        Hex(*VMCTX.heap_info.heap_top.get()),
        " -> ",
        Hex(pending_heap_top),
        " (",
        Hex(pending_heap_top - *VMCTX.heap_info.heap_top.get()),
        ")"
    );

    let heap_base = *VMCTX.heap_base.get();
    let heap_max_size = *VMCTX.heap_max_size.get();
    if pending_heap_top > u64::from(heap_base + heap_max_size) {
        trace!("sbrk: heap size overflow; ignoring request");
        return 0;
    }

    let page_size = *VMCTX.page_size.get() as usize;
    let Some(start) = align_to_next_page_usize(page_size, *VMCTX.heap_info.heap_top.get() as usize) else {
        abort_with_message("unreachable")
    };

    let Some(end) = align_to_next_page_usize(page_size, pending_heap_top as usize) else {
        abort_with_message("unreachable")
    };

    let size = end - start;
    if size > 0 {
        linux_raw::sys_mmap(
            start as *mut core::ffi::c_void,
            end - start,
            linux_raw::PROT_READ | linux_raw::PROT_WRITE,
            linux_raw::MAP_FIXED | linux_raw::MAP_PRIVATE | linux_raw::MAP_ANONYMOUS,
            None,
            0,
        )
        .unwrap_or_else(|error| abort_with_error("failed to mmap sbrk increase", error));
    }

    trace!("extended heap: ", Hex(start), "-", Hex(end), " (", Hex(end - start), ")");

    *VMCTX.heap_info.heap_top.get() = pending_heap_top;
    *VMCTX.heap_info.heap_threshold.get() = end as u64;

    pending_heap_top as u32
}

// A table for functions which can be called from *within* the VM (by the guest program).
#[link_section = ".address_table"]
#[no_mangle]
pub static ADDRESS_TABLE: AddressTableRaw = AddressTableRaw {
    syscall_hostcall,
    syscall_trap,
    syscall_return,
    syscall_step,
    syscall_sbrk,
};

// A table for functions which can be called from *outside* the VM (by the host).
#[link_section = ".ext_table"]
#[no_mangle]
pub static EXT_TABLE: ExtTableRaw = ExtTableRaw {
    ext_sbrk,
    ext_reset_memory,
    ext_zero_memory_chunk,
    ext_load_program,
    ext_recycle,
    ext_fetch_idle_regs,
};

#[inline(always)]
fn signal_host_and_longjmp(futex_value_to_set: u32) -> ! {
    VMCTX.futex.store(futex_value_to_set, Ordering::Release);
    linux_raw::sys_futex_wake_one(&VMCTX.futex).unwrap_or_else(|error| abort_with_error("failed to wake up the host process", error));
    unsafe {
        longjmp(addr_of_mut!(RESUME_MAIN_LOOP_JMPBUF), 1);
    }
}

fn memory_map() -> &'static [VmMap] {
    unsafe {
        let shm_memory_map_count = VMCTX.shm_memory_map_count.load(Ordering::Relaxed);
        if shm_memory_map_count > 0 {
            let shm_memory_map_offset = VMCTX.shm_memory_map_offset.load(Ordering::Relaxed);
            core::slice::from_raw_parts(
                (VM_ADDR_SHARED_MEMORY as *const u8)
                    .add(shm_memory_map_offset as usize)
                    .cast::<VmMap>(),
                shm_memory_map_count as usize,
            )
        } else {
            &[]
        }
    }
}

#[cold]
#[inline(never)]
pub unsafe extern "C" fn ext_load_program() -> ! {
    trace!("Entry point: ext_load_program");
    if NATIVE_PAGE_SIZE.load(Ordering::Relaxed) == 0 {
        abort_with_message("assertion failed: native page size is zero");
    }

    recycle();

    let shm_fd = shm_fd();
    let memory_fd = memory_fd();
    let memory_map = memory_map();

    for map in memory_map {
        linux_raw::sys_mmap(
            map.address as *mut core::ffi::c_void,
            map.length as usize,
            map.protection,
            map.flags,
            match map.fd {
                VmFd::None => None,
                VmFd::Shm => Some(shm_fd),
                VmFd::Mem => Some(memory_fd),
            },
            map.fd_offset,
        )
        .unwrap_or_else(|error| abort_with_error("failed to mmap memory", error));

        trace!(
            "Mapped memory (",
            if map.protection == linux_raw::PROT_READ {
                "RO"
            } else if map.protection == linux_raw::PROT_READ | linux_raw::PROT_WRITE {
                "RW"
            } else {
                "??"
            },
            ", ",
            match map.fd {
                VmFd::None => "anon",
                VmFd::Shm => "shm",
                VmFd::Mem => "mem",
            },
            "): ",
            Hex(map.address),
            "-",
            Hex(map.address + map.length),
            " (",
            Hex(map.length),
            ")"
        );
    }

    let shm_code_length = VMCTX.shm_code_length.load(Ordering::Relaxed);
    if shm_code_length > 0 {
        let shm_code_offset = VMCTX.shm_code_offset.load(Ordering::Relaxed);
        linux_raw::sys_mmap(
            VM_ADDR_NATIVE_CODE as *mut core::ffi::c_void,
            shm_code_length as usize,
            linux_raw::PROT_EXEC,
            linux_raw::MAP_FIXED | linux_raw::MAP_PRIVATE,
            Some(shm_fd),
            shm_code_offset,
        )
        .unwrap_or_else(|error| abort_with_error("failed to mmap code", error));

        trace!(
            "new code range: ",
            Hex(VM_ADDR_NATIVE_CODE),
            "-",
            Hex(VM_ADDR_NATIVE_CODE + shm_code_length),
            " (",
            Hex(shm_code_length),
            ")"
        );
    }

    let shm_jump_table_length = VMCTX.shm_jump_table_length.load(Ordering::Relaxed);
    if shm_jump_table_length > 0 {
        let shm_jump_table_offset = VMCTX.shm_jump_table_offset.load(Ordering::Relaxed);
        linux_raw::sys_mmap(
            VM_ADDR_JUMP_TABLE as *mut core::ffi::c_void,
            shm_jump_table_length as usize,
            linux_raw::PROT_READ,
            linux_raw::MAP_FIXED | linux_raw::MAP_PRIVATE,
            Some(shm_fd),
            shm_jump_table_offset,
        )
        .unwrap_or_else(|error| abort_with_error("failed to mmap jump table", error));

        trace!(
            "new jump table range: ",
            Hex(VM_ADDR_JUMP_TABLE),
            "-",
            Hex(VM_ADDR_JUMP_TABLE + shm_jump_table_length),
            " (",
            Hex(shm_jump_table_length),
            ")"
        );
    }

    let sysreturn_address = VMCTX.sysreturn_address.load(Ordering::Relaxed);
    trace!(
        "new sysreturn address: ",
        Hex(sysreturn_address),
        " (set at ",
        Hex(VM_ADDR_JUMP_TABLE_RETURN_TO_HOST),
        ")"
    );
    *(VM_ADDR_JUMP_TABLE_RETURN_TO_HOST as *mut u64) = sysreturn_address;

    signal_host_and_longjmp(VMCTX_FUTEX_IDLE);
}

unsafe fn recycle() {
    polkavm_common::static_assert!(VM_ADDR_NATIVE_CODE + (VM_SANDBOX_MAXIMUM_NATIVE_CODE_SIZE as u64) < 0x200000000);

    linux_raw::sys_munmap(core::ptr::null_mut(), 0x200000000)
        .unwrap_or_else(|error| abort_with_error("failed to unmap user accessible memory", error));

    linux_raw::sys_munmap(
        VM_ADDR_JUMP_TABLE as *mut core::ffi::c_void,
        VM_SANDBOX_MAXIMUM_JUMP_TABLE_SIZE as usize,
    )
    .unwrap_or_else(|error| abort_with_error("failed to unmap jump table", error));

    *(VM_ADDR_JUMP_TABLE_RETURN_TO_HOST as *mut u64) = 0;
}

#[inline(never)]
pub unsafe extern "C" fn ext_recycle() -> ! {
    trace!("Entry point: ext_recycle");
    recycle();
    signal_host_and_longjmp(VMCTX_FUTEX_IDLE);
}

#[inline(never)]
pub unsafe extern "C" fn ext_fetch_idle_regs() -> ! {
    trace!("Entry point: ext_fetch_idle_regs");

    macro_rules! copy_regs {
        ($($name:ident),+) => {
            $(
                VMCTX.init.idle_regs.$name.store(RESUME_MAIN_LOOP_JMPBUF.$name.load(Ordering::Relaxed), Ordering::Relaxed);
            )+
        }
    }

    copy_regs! {
        rip,
        rbp,
        rsp,
        rbp,
        r12,
        r13,
        r14,
        r15
    }

    signal_host_and_longjmp(VMCTX_FUTEX_IDLE);
}
