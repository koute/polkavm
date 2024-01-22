#![feature(naked_functions)]
#![feature(asm_const)]
#![no_std]
#![no_main]
#![allow(clippy::missing_safety_doc)]

use core::sync::atomic::Ordering;
use core::sync::atomic::{AtomicBool, AtomicUsize};
use polkavm_common::{
    abi::{VM_ADDR_USER_MEMORY, VM_ADDR_USER_STACK_HIGH, VM_MAXIMUM_MEMORY_SIZE},
    utils::align_to_next_page_usize,
    zygote::{
        AddressTableRaw, VmCtx as VmCtxInner, SANDBOX_EMPTY_NATIVE_PROGRAM_COUNTER, SANDBOX_EMPTY_NTH_INSTRUCTION, VMCTX_FUTEX_BUSY,
        VMCTX_FUTEX_HOSTCALL, VMCTX_FUTEX_IDLE, VMCTX_FUTEX_INIT, VMCTX_FUTEX_TRAP, VM_ADDR_JUMP_TABLE, VM_ADDR_JUMP_TABLE_RETURN_TO_HOST,
        VM_ADDR_NATIVE_CODE, VM_ADDR_SIGSTACK, VM_RPC_FLAG_CLEAR_PROGRAM_AFTER_EXECUTION, VM_RPC_FLAG_RECONFIGURE,
        VM_RPC_FLAG_RESET_MEMORY_AFTER_EXECUTION, VM_SANDBOX_MAXIMUM_JUMP_TABLE_VIRTUAL_SIZE, VM_SANDBOX_MAXIMUM_NATIVE_CODE_SIZE,
    },
};
use polkavm_linux_raw as linux_raw;

macro_rules! trace {
    ($arg:expr) => {{
        let fd = linux_raw::FdRef::from_raw_unchecked(linux_raw::STDERR_FILENO);
        let _ = linux_raw::sys_write(fd, $arg.as_bytes());
        let _ = linux_raw::sys_write(fd, b"\n");
    }};

    ($($args:expr),+) => {{
        use core::fmt::Write;
        let _ = writeln!(&mut linux_raw::FdRef::from_raw_unchecked(linux_raw::STDERR_FILENO), $($args),+);
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

#[cold]
fn abort_with_message(error: &str) -> ! {
    let fd = linux_raw::FdRef::from_raw_unchecked(linux_raw::STDERR_FILENO);
    let _ = linux_raw::sys_write(fd, b"fatal error: ");
    let _ = linux_raw::sys_write(fd, error.as_bytes());
    let _ = linux_raw::sys_write(fd, b"\n");

    reset_message();
    append_to_message(error.as_bytes());

    core::sync::atomic::fence(Ordering::Release);

    IN_SIGNAL_HANDLER.store(true, Ordering::Relaxed);
    linux_raw::abort();
}

#[cold]
fn abort_with_error(error: &str, err_obj: linux_raw::Error) -> ! {
    let fd = linux_raw::FdRef::from_raw_unchecked(linux_raw::STDERR_FILENO);
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

    IN_SIGNAL_HANDLER.store(true, Ordering::Relaxed);
    linux_raw::abort();
}

#[naked]
#[no_mangle]
#[export_name = "_start"]
pub unsafe extern "C" fn _start() -> ! {
    #[cfg(target_arch = "x86_64")]
    core::arch::asm!(r#"
        // Map ourselves a new stack.
        mov rax, {SYS_mmap}
        mov rdi, {native_stack_low}
        mov rsi, {native_stack_size}
        mov rdx, {protection}
        mov r10, {flags}
        mov r8, -1
        mov r9, 0
        syscall

        mov rdi, rsp
        mov rsp, {native_stack_high}
        push rbp
        jmp {entry_point}
    "#,
        SYS_mmap = const linux_raw::SYS_mmap,
        native_stack_low = const polkavm_common::zygote::VM_ADDR_NATIVE_STACK_LOW,
        native_stack_high = const polkavm_common::zygote::VM_ADDR_NATIVE_STACK_HIGH,
        native_stack_size = const polkavm_common::zygote::VM_ADDR_NATIVE_STACK_SIZE,
        protection = const linux_raw::PROT_READ | linux_raw::PROT_WRITE,
        flags = const linux_raw::MAP_FIXED | linux_raw::MAP_PRIVATE | linux_raw::MAP_ANONYMOUS,
        entry_point = sym entry_point,
        options (noreturn)
    );
}

const HOST_SOCKET_FILENO: linux_raw::c_int = linux_raw::STDIN_FILENO;

unsafe extern "C" fn entry_point(stack: *mut usize) -> ! {
    trace!("initializing...");
    let socket = initialize(stack);
    main_loop(socket);
}

static IN_SIGNAL_HANDLER: AtomicBool = AtomicBool::new(false);
static NATIVE_PAGE_SIZE: AtomicUsize = AtomicUsize::new(!0);

unsafe extern "C" fn signal_handler(signal: u32, _info: &linux_raw::siginfo_t, context: &linux_raw::ucontext) {
    if IN_SIGNAL_HANDLER.load(Ordering::Relaxed) || signal == linux_raw::SIGIO {
        let _ = linux_raw::sys_exit(255);
    }

    IN_SIGNAL_HANDLER.store(true, Ordering::Relaxed);

    let rip = context.uc_mcontext.rip;
    *VMCTX.rip().get() = rip;

    trace!("signal triggered from 0x{:x} (signal = {})", rip, signal);
    trace!(
        "  rax = 0x{:x}, rcx = 0x{:x}, rdx = 0x{:x}, rbx = 0x{:x}\n  rsp = 0x{:x} rbp = 0x{:x} rsi = 0x{:x} rdi = 0x{:x}\n  r8 = 0x{:x} r9 = 0x{:x} r10 = 0x{:x} r11 = 0x{:x}\n  r12 = 0x{:x} r13 = 0x{:x} r14 = 0x{:x} r15 = 0x{:x}",
        context.uc_mcontext.rax,
        context.uc_mcontext.rcx,
        context.uc_mcontext.rdx,
        context.uc_mcontext.rbx,
        context.uc_mcontext.rsp,
        context.uc_mcontext.rbp,
        context.uc_mcontext.rsi,
        context.uc_mcontext.rdi,
        context.uc_mcontext.r8,
        context.uc_mcontext.r9,
        context.uc_mcontext.r10,
        context.uc_mcontext.r11,
        context.uc_mcontext.r12,
        context.uc_mcontext.r13,
        context.uc_mcontext.r14,
        context.uc_mcontext.r15
    );

    let user_code = VM_ADDR_NATIVE_CODE;

    #[allow(clippy::needless_borrow)]
    if rip >= user_code && rip < user_code + (&*VMCTX.memory_config.get()).code_size() as u64 {
        signal_host(VMCTX_FUTEX_TRAP, SignalHostKind::Normal)
            .unwrap_or_else(|error| abort_with_error("failed to wait for the host process (trap)", error));

        *VMCTX.rip().get() = SANDBOX_EMPTY_NATIVE_PROGRAM_COUNTER;
        longjmp(&mut RESUME_IDLE_LOOP_JMPBUF, 1);
    } else {
        abort_with_message("segmentation fault")
    }
}

#[naked]
unsafe extern "C" fn signal_restorer() {
    core::arch::asm!(
        "mov rax, {SYS_rt_sigreturn}",
        "syscall",
        "ud2",
        SYS_rt_sigreturn = const linux_raw::SYS_rt_sigreturn,
        options(noreturn)
    );
}

#[repr(C)]
struct JmpBuf {
    return_address: u64,
    rbx: u64,
    rsp: u64,
    rbp: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
    return_value: u64,
}

static mut RESUME_IDLE_LOOP_JMPBUF: JmpBuf = JmpBuf {
    return_address: 0,
    rbx: 0,
    rsp: 0,
    rbp: 0,
    r12: 0,
    r13: 0,
    r14: 0,
    r15: 0,
    return_value: 0,
};

#[naked]
unsafe extern "C" fn longjmp(_jmpbuf: *mut JmpBuf, _return_value: u64) -> ! {
    core::arch::asm!(
        // Restore registers.
        "mov rbx, [rdi + 8]",
        "mov rsp, [rdi + 16]",
        "mov rbp, [rdi + 24]",
        "mov r12, [rdi + 32]",
        "mov r13, [rdi + 40]",
        "mov r14, [rdi + 48]",
        "mov r15, [rdi + 56]",
        // Set return value.
        "mov rax, rsi",
        // Jump out.
        "mov rdx, [rdi]",
        "jmp rdx",
        options(noreturn)
    );
}

#[naked]
unsafe extern "C" fn setjmp(_jmpbuf: *mut JmpBuf) -> u64 {
    core::arch::asm!(
        // Save the return address.
        "mov rax, [rsp]",
        "mov [rdi], rax",
        // Save the callee-saved registers.
        "mov [rdi + 8], rbx",
        "lea rax, [rsp + 8]", // Get the stack pointer as if it was *after* popping the return address.
        "mov [rdi + 16], rax",
        "mov [rdi + 24], rbp",
        "mov [rdi + 32], r12",
        "mov [rdi + 40], r13",
        "mov [rdi + 48], r14",
        "mov [rdi + 56], r15",
        // Return '0'.
        "xor rax, rax",
        "ret",
        options(noreturn)
    );
}

#[inline(never)]
unsafe fn initialize(mut stack: *mut usize) -> linux_raw::Fd {
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
    let argv = stack.cast::<*mut u8>();
    let envp = argv.add(argc + 1);
    let auxv = {
        let mut p = envp;
        while !(*p).is_null() {
            p = p.add(1);
        }
        p.add(1).cast::<(usize, usize)>()
    };

    let minsigstksz;
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

            auxv = auxv.add(1);
        }

        if let Some(size) = minsigstksz_opt {
            trace!("signal stack size: {}", size);
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

    let socket = linux_raw::Fd::from_raw_unchecked(HOST_SOCKET_FILENO);
    let vmctx_memfd = linux_raw::recvfd(socket.borrow()).unwrap_or_else(|error| abort_with_error("failed to read vmctx fd", error));

    linux_raw::sys_mmap(
        &VMCTX as *const VmCtx as *mut core::ffi::c_void,
        page_size,
        linux_raw::PROT_READ | linux_raw::PROT_WRITE,
        linux_raw::MAP_FIXED | linux_raw::MAP_SHARED,
        Some(vmctx_memfd.borrow()),
        0,
    )
    .unwrap_or_else(|error| abort_with_error("failed to mmap vmctx", error));

    vmctx_memfd
        .close()
        .unwrap_or_else(|error| abort_with_error("failed to close vmctx memfd", error));

    let lifetime_pipe = linux_raw::recvfd(socket.borrow()).unwrap_or_else(|error| abort_with_error("failed to read lifetime pipe", error));

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

    // Wait for the host to fill out vmctx.
    signal_host(VMCTX_FUTEX_INIT, SignalHostKind::Normal)
        .unwrap_or_else(|error| abort_with_error("failed to wait for the host process (init)", error));

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
    linux_raw::sys_munmap(
        VM_ADDR_USER_MEMORY as *mut core::ffi::c_void,
        align_to_next_page_usize(page_size, VM_MAXIMUM_MEMORY_SIZE as usize).unwrap_or_else(|| abort_with_message("overflow")),
    )
    .unwrap_or_else(|error| abort_with_error("failed to make sure the user memory address space is unmapped", error));

    linux_raw::sys_munmap(
        VM_ADDR_NATIVE_CODE as *mut core::ffi::c_void,
        align_to_next_page_usize(page_size, VM_SANDBOX_MAXIMUM_NATIVE_CODE_SIZE as usize).unwrap_or_else(|| abort_with_message("overflow")),
    )
    .unwrap_or_else(|error| abort_with_error("failed to make sure the native code address space is unmapped", error));

    linux_raw::sys_munmap(
        VM_ADDR_JUMP_TABLE as *mut core::ffi::c_void,
        align_to_next_page_usize(page_size, VM_SANDBOX_MAXIMUM_JUMP_TABLE_VIRTUAL_SIZE as usize)
            .unwrap_or_else(|| abort_with_message("overflow")),
    )
    .unwrap_or_else(|error| abort_with_error("failed to make sure the jump table address space is unmapped", error));

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

    unsafe {
        core::arch::asm!(
            "wrgsbase {addr}",
            addr = in(reg) VM_ADDR_JUMP_TABLE
        );
    }

    // Change the name of the process.
    linux_raw::sys_prctl_set_name(b"polkavm-sandbox\0").unwrap_or_else(|error| abort_with_error("failed to set the process name", error));

    const SECCOMP_FILTER: &[linux_raw::sock_filter] = &linux_raw::bpf! {
        (a = syscall_nr),
        (if a == linux_raw::SYS_futex => jump @1),
        (if a == linux_raw::SYS_mmap => jump @5),
        (if a == linux_raw::SYS_munmap => jump @1),
        (if a == linux_raw::SYS_madvise => jump @4),
        (if a == linux_raw::SYS_close => jump @1),
        (if a == linux_raw::SYS_write => jump @3),
        (if a == linux_raw::SYS_recvmsg => jump @2),
        (if a == linux_raw::SYS_rt_sigreturn => jump @1),
        (if a == linux_raw::SYS_sched_yield => jump @1),
        (if a == linux_raw::SYS_exit => jump @1),
        (seccomp_kill_thread),

        // SYS_recvmsg
        ([2]: a = syscall_arg[0]),
        (if a != HOST_SOCKET_FILENO => jump @0),
        (seccomp_allow),

        // SYS_write
        ([3]: a = syscall_arg[0]),
        (if a != linux_raw::STDERR_FILENO => jump @0),
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

        ([0]: seccomp_kill_thread),
        ([1]: seccomp_allow),
    };

    linux_raw::sys_seccomp_set_mode_filter(SECCOMP_FILTER).unwrap_or_else(|error| abort_with_error("failed to set seccomp filter", error));

    VMCTX.futex.store(VMCTX_FUTEX_IDLE, Ordering::Release);
    linux_raw::sys_futex_wake_one(&VMCTX.futex)
        .unwrap_or_else(|error| abort_with_error("failed to wake up the host process on initialization", error));

    socket
}

#[link_section = ".text_hot"]
#[inline(never)]
unsafe fn main_loop(socket: linux_raw::Fd) -> ! {
    if setjmp(&mut RESUME_IDLE_LOOP_JMPBUF) != 0 {
        IN_SIGNAL_HANDLER.store(false, Ordering::Relaxed);

        trace!("returning to idle...");

        let rpc_flags = *VMCTX.rpc_flags.get();
        if rpc_flags & VM_RPC_FLAG_CLEAR_PROGRAM_AFTER_EXECUTION != 0 {
            clear_program();
        } else if rpc_flags & VM_RPC_FLAG_RESET_MEMORY_AFTER_EXECUTION != 0 {
            reset_memory();
        }

        VMCTX.futex.store(VMCTX_FUTEX_IDLE, Ordering::Release);
        linux_raw::sys_futex_wake_one(&VMCTX.futex).unwrap_or_else(|error| abort_with_error("failed to wake up the host process", error));
    }

    loop {
        'wait_loop: while VMCTX.futex.load(Ordering::Relaxed) == VMCTX_FUTEX_IDLE {
            for _ in 0..20 {
                let _ = linux_raw::sys_sched_yield();
                if VMCTX.futex.load(Ordering::Relaxed) != VMCTX_FUTEX_IDLE {
                    break 'wait_loop;
                }
            }

            match linux_raw::sys_futex_wait(&VMCTX.futex, VMCTX_FUTEX_IDLE, None) {
                Ok(()) => continue,
                Err(error) if error.errno() == linux_raw::EAGAIN || error.errno() == linux_raw::EINTR => continue,
                Err(error) => {
                    abort_with_error("failed to wait for the host process", error);
                }
            }
        }

        core::sync::atomic::fence(Ordering::Acquire);
        trace!("work received...");

        let rpc_flags = *VMCTX.rpc_flags.get();
        let rpc_address = *VMCTX.rpc_address.get().cast::<Option<extern "C" fn() -> !>>();

        if rpc_flags & VM_RPC_FLAG_RECONFIGURE != 0 {
            reconfigure(socket.borrow());
        }

        if let Some(rpc_address) = rpc_address {
            trace!("jumping to: 0x{:x}", rpc_address as usize);
            rpc_address();
        } else {
            longjmp(&mut RESUME_IDLE_LOOP_JMPBUF, 1);
        }
    }
}

#[link_section = ".text_hot"]
unsafe fn reset_memory() {
    trace!("resetting memory...");
    let current = &mut *VMCTX.memory_config.get();
    let heap_size = current.heap_size();
    if heap_size > 0 {
        linux_raw::sys_madvise(
            current.heap_address() as *mut core::ffi::c_void,
            heap_size as usize,
            linux_raw::MADV_DONTNEED,
        )
        .unwrap_or_else(|error| abort_with_error("failed to clear user heap", error));
    }

    let stack_size = current.stack_size() as usize;
    if stack_size > 0 {
        linux_raw::sys_madvise(
            (VM_ADDR_USER_STACK_HIGH as usize - stack_size) as *mut core::ffi::c_void,
            stack_size,
            linux_raw::MADV_DONTNEED,
        )
        .unwrap_or_else(|error| abort_with_error("failed to clear user stack", error));
    }
}

#[inline(never)]
#[no_mangle]
pub unsafe extern "C" fn syscall_hostcall(hostcall: u32) {
    trace!("syscall: hostcall triggered");

    *VMCTX.hostcall().get() = hostcall;
    signal_host(VMCTX_FUTEX_HOSTCALL, SignalHostKind::Normal)
        .unwrap_or_else(|error| abort_with_error("failed to wait for the host process (hostcall)", error));

    if *VMCTX.hostcall().get() == polkavm_common::zygote::HOSTCALL_ABORT_EXECUTION {
        longjmp(&mut RESUME_IDLE_LOOP_JMPBUF, 1);
    }
}

#[inline(never)]
#[no_mangle]
pub unsafe extern "C" fn syscall_trap() -> ! {
    trace!("syscall: trap triggered");
    signal_host(VMCTX_FUTEX_TRAP, SignalHostKind::Normal)
        .unwrap_or_else(|error| abort_with_error("failed to wait for the host process (trap)", error));

    longjmp(&mut RESUME_IDLE_LOOP_JMPBUF, 1);
}

#[inline(never)]
#[no_mangle]
pub unsafe extern "C" fn syscall_return() -> ! {
    trace!("syscall: return triggered");
    longjmp(&mut RESUME_IDLE_LOOP_JMPBUF, 1);
}

// Just for debugging. Normally should never be used.
#[inline(never)]
#[no_mangle]
pub unsafe extern "C" fn syscall_trace(nth_instruction: u32, rip: u64) {
    *VMCTX.hostcall().get() = polkavm_common::HOSTCALL_TRACE;
    *VMCTX.nth_instruction().get() = nth_instruction;
    *VMCTX.rip().get() = rip;

    signal_host(VMCTX_FUTEX_HOSTCALL, SignalHostKind::Trace)
        .unwrap_or_else(|error| abort_with_error("failed to wait for the host process (trace)", error));

    *VMCTX.nth_instruction().get() = SANDBOX_EMPTY_NTH_INSTRUCTION;
    *VMCTX.rip().get() = SANDBOX_EMPTY_NATIVE_PROGRAM_COUNTER;

    if *VMCTX.hostcall().get() == polkavm_common::zygote::HOSTCALL_ABORT_EXECUTION {
        longjmp(&mut RESUME_IDLE_LOOP_JMPBUF, 1);
    }
}

#[link_section = ".address_table"]
#[no_mangle]
pub static ADDRESS_TABLE: AddressTableRaw = AddressTableRaw {
    syscall_hostcall,
    syscall_trap,
    syscall_return,
    syscall_trace,
};

enum SignalHostKind {
    Normal,
    Trace,
}

fn signal_host(futex_value_to_set: u32, kind: SignalHostKind) -> Result<(), linux_raw::Error> {
    VMCTX.futex.store(futex_value_to_set, Ordering::Release);
    linux_raw::sys_futex_wake_one(&VMCTX.futex).unwrap_or_else(|error| abort_with_error("failed to wake up the host process", error));

    let spin_target = match kind {
        SignalHostKind::Normal => 64,
        SignalHostKind::Trace => 512,
    };

    'outer: loop {
        unsafe {
            *VMCTX.counters.syscall_wait_loop_start.get() += 1;
        }

        let new_futex_value = VMCTX.futex.load(Ordering::Relaxed);
        if new_futex_value == VMCTX_FUTEX_BUSY {
            break;
        }

        if new_futex_value != futex_value_to_set {
            abort_with_message("unexpected futex value while waiting for the host");
        }

        for _ in 0..spin_target {
            core::hint::spin_loop();
            if VMCTX.futex.load(Ordering::Relaxed) == VMCTX_FUTEX_BUSY {
                break 'outer;
            }
        }

        unsafe {
            *VMCTX.counters.syscall_futex_wait.get() += 1;
        }

        let result = linux_raw::sys_futex_wait(&VMCTX.futex, futex_value_to_set, None);
        match result {
            Ok(()) => {
                continue;
            }
            Err(error) if error.errno() == linux_raw::EAGAIN || error.errno() == linux_raw::EINTR => {
                continue;
            }
            Err(error) => {
                return Err(error);
            }
        }
    }

    core::sync::atomic::fence(Ordering::Acquire);
    Ok(())
}

#[cold]
#[inline(never)]
unsafe fn reconfigure(socket: linux_raw::FdRef) {
    trace!("reconfiguring...");
    assert_ne!(NATIVE_PAGE_SIZE.load(Ordering::Relaxed), 0);

    let fd = linux_raw::recvfd(socket).unwrap_or_else(|_| abort_with_message("failed to receive reconfiguration fd"));

    clear_program();

    let current = &mut *VMCTX.memory_config.get();
    let new = *VMCTX.new_memory_config.get();
    if new.ro_data_size() + new.rw_data_size() > 0 {
        if new.ro_data_size() > 0 {
            linux_raw::sys_mmap(
                new.ro_data_address() as *mut core::ffi::c_void,
                new.ro_data_size() as usize,
                linux_raw::PROT_READ,
                linux_raw::MAP_FIXED | linux_raw::MAP_PRIVATE,
                Some(fd.borrow()),
                0,
            )
            .unwrap_or_else(|error| abort_with_error("failed to mmap user memory (ro data)", error));

            trace!(
                "new rodata range: 0x{:x}-0x{:x} (0x{:x})",
                new.ro_data_address(),
                new.ro_data_address() + new.ro_data_size(),
                new.ro_data_size()
            );
            if let Err(error) = current.set_ro_data_size(new.ro_data_size()) {
                abort_with_message(error);
            }
        }

        if new.rw_data_size() > 0 {
            linux_raw::sys_mmap(
                new.rw_data_address() as *mut core::ffi::c_void,
                new.rw_data_size() as usize,
                linux_raw::PROT_READ | linux_raw::PROT_WRITE,
                linux_raw::MAP_FIXED | linux_raw::MAP_PRIVATE,
                Some(fd.borrow()),
                new.ro_data_size().into(),
            )
            .unwrap_or_else(|error| abort_with_error("failed to mmap user memory (rw data)", error));

            trace!(
                "new rwdata range: 0x{:x}-0x{:x} (0x{:x})",
                new.rw_data_address(),
                new.rw_data_address() + new.rw_data_size(),
                new.rw_data_size()
            );
            if let Err(error) = current.set_rw_data_size(new.rw_data_size()) {
                abort_with_message(error);
            }
        }
    }

    if new.code_size() > 0 {
        linux_raw::sys_mmap(
            VM_ADDR_NATIVE_CODE as *mut core::ffi::c_void,
            new.code_size(),
            linux_raw::PROT_EXEC,
            linux_raw::MAP_FIXED | linux_raw::MAP_PRIVATE,
            Some(fd.borrow()),
            (new.ro_data_size() + new.rw_data_size()).into(),
        )
        .unwrap_or_else(|error| abort_with_error("failed to mmap user code", error));

        trace!(
            "new code range: 0x{:x}-0x{:x} (0x{:x})",
            VM_ADDR_NATIVE_CODE,
            VM_ADDR_NATIVE_CODE + new.code_size() as u64,
            new.code_size()
        );
        if let Err(error) = current.set_code_size(NATIVE_PAGE_SIZE.load(Ordering::Relaxed), new.code_size()) {
            abort_with_message(error);
        }
    }

    if new.jump_table_size() > 0 {
        linux_raw::sys_mmap(
            VM_ADDR_JUMP_TABLE as *mut core::ffi::c_void,
            new.jump_table_size(),
            linux_raw::PROT_READ,
            linux_raw::MAP_FIXED | linux_raw::MAP_PRIVATE,
            Some(fd.borrow()),
            (new.ro_data_size() as usize + new.rw_data_size() as usize + new.code_size()) as linux_raw::c_ulong,
        )
        .unwrap_or_else(|error| abort_with_error("failed to mmap jump table", error));

        trace!(
            "new jump table range: 0x{:x}-0x{:x} (0x{:x})",
            VM_ADDR_JUMP_TABLE,
            VM_ADDR_JUMP_TABLE + new.jump_table_size() as u64,
            new.jump_table_size()
        );
        if let Err(error) = current.set_jump_table_size(NATIVE_PAGE_SIZE.load(Ordering::Relaxed), new.jump_table_size()) {
            abort_with_message(error);
        }
    }

    fd.close()
        .unwrap_or_else(|error| abort_with_error("failed to close user memory fd", error));

    if new.bss_size() > 0 {
        linux_raw::sys_mmap(
            new.bss_address() as *mut core::ffi::c_void,
            new.bss_size() as usize,
            linux_raw::PROT_READ | linux_raw::PROT_WRITE,
            linux_raw::MAP_FIXED | linux_raw::MAP_PRIVATE | linux_raw::MAP_ANONYMOUS,
            None,
            0,
        )
        .unwrap_or_else(|error| abort_with_error("failed to mmap user memory (bss)", error));

        trace!(
            "new bss range: 0x{:x}-0x{:x} (0x{:x})",
            new.bss_address(),
            new.bss_address() + new.bss_size(),
            new.bss_size()
        );
        if let Err(error) = current.set_bss_size(new.bss_size()) {
            abort_with_message(error);
        }
    }

    if new.stack_size() > 0 {
        linux_raw::sys_mmap(
            new.stack_address_low() as *mut core::ffi::c_void,
            new.stack_size() as usize,
            linux_raw::PROT_READ | linux_raw::PROT_WRITE,
            linux_raw::MAP_FIXED | linux_raw::MAP_PRIVATE | linux_raw::MAP_ANONYMOUS,
            None,
            0,
        )
        .unwrap_or_else(|error| abort_with_error("failed to mmap user memory (stack)", error));

        trace!(
            "new stack range: 0x{:x}-0x{:x} (0x{:x})",
            new.stack_address_low(),
            new.stack_address_low() + new.stack_size(),
            new.stack_size()
        );
        if let Err(error) = current.set_stack_size(new.stack_size()) {
            abort_with_message(error);
        }
    }

    if *current != new {
        // This should never happen, but let's check it just in case.
        abort_with_message("internal error: failed to fully update memory configuration");
    }

    let sysreturn = *VMCTX.new_sysreturn_address.get() as usize;
    trace!(
        "new sysreturn address: 0x{:x} (set at 0x{:x})",
        sysreturn,
        VM_ADDR_JUMP_TABLE_RETURN_TO_HOST
    );
    *(VM_ADDR_JUMP_TABLE_RETURN_TO_HOST as *mut usize) = sysreturn;
}

#[inline(never)]
unsafe fn clear_program() {
    let current = &mut *VMCTX.memory_config.get();
    if current.user_memory_region_size() > 0 || current.stack_size() > 0 || current.code_size() > 0 {
        polkavm_common::static_assert!(VM_ADDR_NATIVE_CODE + (VM_SANDBOX_MAXIMUM_NATIVE_CODE_SIZE as u64) < 0x200000000);
        linux_raw::sys_munmap(core::ptr::null_mut(), 0x200000000)
            .unwrap_or_else(|error| abort_with_error("failed to unmap user accessible memory", error));

        current.clear_user_memory_sizes();
        current.clear_stack_size();
        current.clear_code_size();
    }

    if current.jump_table_size() > 0 {
        linux_raw::sys_munmap(VM_ADDR_JUMP_TABLE as *mut core::ffi::c_void, current.jump_table_size())
            .unwrap_or_else(|error| abort_with_error("failed to unmap jump table", error));

        current.clear_jump_table_size();
    }

    *(VM_ADDR_JUMP_TABLE_RETURN_TO_HOST as *mut usize) = 0;
}
