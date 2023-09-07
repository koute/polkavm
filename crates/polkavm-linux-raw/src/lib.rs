#![doc = include_str!("../README.md")]
#![no_std]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::unreachable)]
#![deny(clippy::indexing_slicing)]
#![allow(clippy::collapsible_else_if)]
#![allow(clippy::len_without_is_empty)]
#![allow(clippy::manual_range_contains)]
// This crate mostly contains syscall wrappers. If you use them you should know what you're doing.
#![allow(clippy::missing_safety_doc)]
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

#[cfg(feature = "std")]
extern crate std;

mod syscall;

#[cfg(target_arch = "x86_64")]
#[doc(hidden)]
pub mod arch_amd64_syscall;

#[cfg(target_arch = "x86_64")]
#[allow(dead_code)]
#[allow(non_upper_case_globals)]
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
mod arch_amd64_bindings;

mod mmap;

pub use mmap::Mmap;

#[cfg(target_arch = "x86_64")]
#[doc(hidden)]
pub use arch_amd64_syscall as syscall_impl;

pub use core::ffi::{c_int, c_long, c_uchar, c_uint, c_ulong, c_ushort, c_void};

use core::ffi::CStr;
use core::marker::PhantomData;
use core::mem::MaybeUninit;
use core::sync::atomic::AtomicU32;
use core::time::Duration;

#[cfg(feature = "std")]
use std::borrow::Cow;

// TODO: Remove this once this is stable: https://github.com/rust-lang/rust/issues/88345
#[allow(non_camel_case_types)]
type c_size_t = usize;

// Doesn't appear in public headers.
pub const MNT_FORCE: u32 = 1;
pub const MNT_DETACH: u32 = 2;
pub const MNT_EXPIRE: u32 = 4;

pub use crate::arch_amd64_bindings::{
    __NR_capset as SYS_capset, __NR_chdir as SYS_chdir, __NR_clock_gettime as SYS_clock_gettime, __NR_clone as SYS_clone,
    __NR_clone3 as SYS_clone3, __NR_close as SYS_close, __NR_close_range as SYS_close_range, __NR_dup3 as SYS_dup3,
    __NR_execveat as SYS_execveat, __NR_exit as SYS_exit, __NR_fchdir as SYS_fchdir, __NR_fcntl as SYS_fcntl,
    __NR_ftruncate as SYS_ftruncate, __NR_futex as SYS_futex, __NR_getdents64 as SYS_getdents64, __NR_getgid as SYS_getgid,
    __NR_getpid as SYS_getpid, __NR_getuid as SYS_getuid, __NR_kill as SYS_kill, __NR_madvise as SYS_madvise,
    __NR_memfd_create as SYS_memfd_create, __NR_mmap as SYS_mmap, __NR_mount as SYS_mount, __NR_mprotect as SYS_mprotect,
    __NR_mremap as SYS_mremap, __NR_munmap as SYS_munmap, __NR_open as SYS_open, __NR_openat as SYS_openat,
    __NR_pidfd_send_signal as SYS_pidfd_send_signal, __NR_pipe2 as SYS_pipe2, __NR_pivot_root as SYS_pivot_root, __NR_prctl as SYS_prctl,
    __NR_process_vm_readv as SYS_process_vm_readv, __NR_process_vm_writev as SYS_process_vm_writev, __NR_ptrace as SYS_ptrace,
    __NR_read as SYS_read, __NR_recvmsg as SYS_recvmsg, __NR_rt_sigaction as SYS_rt_sigaction, __NR_rt_sigprocmask as SYS_rt_sigprocmask,
    __NR_rt_sigreturn as SYS_rt_sigreturn, __NR_seccomp as SYS_seccomp, __NR_sendmsg as SYS_sendmsg,
    __NR_set_tid_address as SYS_set_tid_address, __NR_setdomainname as SYS_setdomainname, __NR_sethostname as SYS_sethostname,
    __NR_setrlimit as SYS_setrlimit, __NR_sigaltstack as SYS_sigaltstack, __NR_socketpair as SYS_socketpair, __NR_umount2 as SYS_umount2,
    __NR_unshare as SYS_unshare, __NR_waitid as SYS_waitid, __NR_write as SYS_write, __kernel_gid_t as gid_t, __kernel_pid_t as pid_t,
    __kernel_uid_t as uid_t, __user_cap_data_struct, __user_cap_header_struct, iovec, linux_dirent64, rlimit, rusage,
    sigaction as kernel_sigaction, siginfo_t, sigset_t as kernel_sigset_t, timespec, AT_EMPTY_PATH, AT_MINSIGSTKSZ, AT_NULL, AT_PAGESZ,
    AT_SYSINFO_EHDR, CLOCK_MONOTONIC_RAW, CLONE_CLEAR_SIGHAND, CLONE_NEWCGROUP, CLONE_NEWIPC, CLONE_NEWNET, CLONE_NEWNS, CLONE_NEWPID,
    CLONE_NEWUSER, CLONE_NEWUTS, CLONE_PIDFD, E2BIG, EACCES, EAGAIN, EBADF, EBUSY, ECHILD, EDOM, EEXIST, EFAULT, EFBIG, EINTR, EINVAL, EIO,
    EISDIR, EMFILE, EMLINK, ENFILE, ENODEV, ENOENT, ENOEXEC, ENOMEM, ENOSPC, ENOTBLK, ENOTDIR, ENOTTY, ENXIO, EPERM, EPIPE, ERANGE, EROFS,
    ESPIPE, ESRCH, ETIMEDOUT, ETXTBSY, EXDEV, FUTEX_WAIT, FUTEX_WAKE, F_ADD_SEALS, F_SEAL_GROW, F_SEAL_SEAL, F_SEAL_SHRINK, F_SEAL_WRITE,
    MADV_DONTNEED, MAP_ANONYMOUS, MAP_FIXED, MAP_POPULATE, MAP_PRIVATE, MAP_SHARED, MFD_ALLOW_SEALING, MFD_CLOEXEC, MINSIGSTKSZ,
    MREMAP_FIXED, MREMAP_MAYMOVE, MS_BIND, MS_NODEV, MS_NOEXEC, MS_NOSUID, MS_PRIVATE, MS_RDONLY, MS_REC, O_CLOEXEC, O_DIRECTORY, O_PATH,
    O_RDONLY, O_RDWR, O_WRONLY, PROT_EXEC, PROT_READ, PROT_WRITE, P_ALL, P_PGID, P_PID, P_PIDFD, RLIMIT_DATA, RLIMIT_FSIZE, RLIMIT_LOCKS,
    RLIMIT_MEMLOCK, RLIMIT_MSGQUEUE, RLIMIT_NOFILE, RLIMIT_NPROC, RLIMIT_STACK, SA_NODEFER, SA_ONSTACK, SA_RESTORER, SA_SIGINFO,
    SECCOMP_RET_ALLOW, SECCOMP_RET_KILL_THREAD, SECCOMP_SET_MODE_FILTER, SIGCONT, SIGFPE, SIGILL, SIGKILL, SIGSEGV, SIGSTOP, SIG_BLOCK,
    SIG_SETMASK, SIG_UNBLOCK, WEXITED, WNOHANG, _LINUX_CAPABILITY_VERSION_3, __WALL,
};

impl siginfo_t {
    pub unsafe fn si_signo(&self) -> c_int {
        self.__bindgen_anon_1.__bindgen_anon_1.si_signo
    }

    pub unsafe fn si_pid(&self) -> pid_t {
        self.__bindgen_anon_1.__bindgen_anon_1._sifields._sigchld._pid
    }

    pub unsafe fn si_status(&self) -> c_int {
        self.__bindgen_anon_1.__bindgen_anon_1._sifields._sigchld._status
    }
}

#[allow(non_snake_case)]
pub const fn WIFSIGNALED(status: c_int) -> bool {
    ((status & 0x7f) + 1) as i8 >= 2
}

#[allow(non_snake_case)]
pub const fn WTERMSIG(status: c_int) -> c_int {
    status & 0x7f
}

#[allow(non_snake_case)]
pub const fn WIFEXITED(status: c_int) -> bool {
    (status & 0x7f) == 0
}

#[allow(non_snake_case)]
pub const fn WEXITSTATUS(status: c_int) -> c_int {
    (status >> 8) & 0xff
}

#[allow(non_camel_case_types)]
pub type socklen_t = u32;

// Source: linux/arch/x86/include/uapi/asm/signal.h
#[derive(Debug)]
#[repr(C)]
pub struct stack_t {
    pub ss_sp: *mut c_void,
    pub ss_flags: c_int,
    pub ss_size: usize,
}

// Source: linux/include/uapi/asm-generic/ucontext.h
#[derive(Debug)]
#[repr(C)]
pub struct ucontext {
    pub uc_flags: c_ulong,
    pub uc_link: *mut ucontext,
    pub uc_stack: stack_t,
    pub uc_mcontext: sigcontext,
    pub uc_sigmask: kernel_sigset_t,
}

// Source: linux/arch/x86/include/uapi/asm/sigcontext.h
#[derive(Debug)]
#[repr(C)]
pub struct sigcontext {
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rbp: u64,
    pub rbx: u64,
    pub rdx: u64,
    pub rax: u64,
    pub rcx: u64,
    pub rsp: u64,
    pub rip: u64,
    pub eflags: u64,
    pub cs: u16,
    pub gs: u16,
    pub fs: u16,
    pub ss: u16,
    pub err: u64,
    pub trapno: u64,
    pub oldmask: u64,
    pub cr2: u64,
    pub fpstate: *mut fpstate,
    pub reserved: [u64; 8],
}

#[repr(C)]
pub struct fpstate {
    pub cwd: u16,
    pub swd: u16,
    pub twd: u16,
    pub fop: u16,
    pub rip: u64,
    pub rdp: u64,
    pub mxcsr: u32,
    pub mxcsr_mask: u32,
    pub st_space: [u32; 32],  /*  8x  FP registers, 16 bytes each */
    pub xmm_space: [u32; 64], /* 16x XMM registers, 16 bytes each */
    pub reserved_1: [u32; 12],
    pub sw_reserved: fpx_sw_bytes,
}

#[repr(C)]
pub struct fpx_sw_bytes {
    pub magic1: u32,
    pub extended_size: u32,
    pub xfeatures: u64,
    pub xstate_size: u32,
    pub padding: [u32; 7],
}

#[repr(C)]
pub struct msghdr {
    pub msg_name: *mut c_void,
    pub msg_namelen: socklen_t,
    pub msg_iov: *mut iovec,
    pub msg_iovlen: c_size_t,
    pub msg_control: *mut c_void,
    pub msg_controllen: c_size_t,
    pub msg_flags: c_int,
}

#[repr(C)]
pub struct cmsghdr {
    pub cmsg_len: c_size_t,
    pub cmsg_level: c_int,
    pub cmsg_type: c_int,
}

#[repr(C)]
struct sock_fprog {
    pub length: c_ushort,
    pub filter: *const sock_filter,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(C)]
pub struct sock_filter {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

// BPF instruction classes (3 bits, mask: 0b00111)
pub const BPF_LD: u16 = 0b000;
pub const BPF_LDX: u16 = 0b001;
pub const BPF_ST: u16 = 0b010;
pub const BPF_STX: u16 = 0b011;
pub const BPF_ALU: u16 = 0b100;
pub const BPF_JMP: u16 = 0b101;
pub const BPF_RET: u16 = 0b110;
pub const BPF_MISC: u16 = 0b111;

// BPF LD/LDX/ST/STX width (2 bits, mask: 0b11000)
pub const BPF_W: u16 = 0b00000; // 32-bit
pub const BPF_H: u16 = 0b01000; // 16-bit
pub const BPF_B: u16 = 0b10000; // 8-bit

// BPF LD/LDX/ST/STX addressing mode (3 bits, mask: 0b11100000)
pub const BPF_IMM: u16 = 0b00000000;
pub const BPF_ABS: u16 = 0b00100000;
pub const BPF_IND: u16 = 0b01000000;
pub const BPF_MEM: u16 = 0b01100000;
pub const BPF_LEN: u16 = 0b10000000;
pub const BPF_MSH: u16 = 0b10100000;

// BPF ALU operations (4 bits, mask: 0b11110000)
pub const BPF_ADD: u16 = 0b00000000;
pub const BPF_SUB: u16 = 0b00010000;
pub const BPF_MUL: u16 = 0b00100000;
pub const BPF_DIV: u16 = 0b00110000;
pub const BPF_OR: u16 = 0b01000000;
pub const BPF_AND: u16 = 0b01010000;
pub const BPF_LSH: u16 = 0b01100000;
pub const BPF_RSH: u16 = 0b01110000;
pub const BPF_NEG: u16 = 0b10000000;
pub const BPF_MOD: u16 = 0b10010000;
pub const BPF_XOR: u16 = 0b10100000;

// BPF JMP operations (4 bits, mask: 0b11110000)
pub const BPF_JA: u16 = 0b00000000;
pub const BPF_JEQ: u16 = 0b00010000;
pub const BPF_JGT: u16 = 0b00100000;
pub const BPF_JGE: u16 = 0b00110000;
pub const BPF_JSET: u16 = 0b01000000;

// BPF ALU/JMP source (1 bit, mask: 0b1000)
pub const BPF_K: u16 = 0b0000;
pub const BPF_X: u16 = 0b1000;

pub const SECBIT_NOROOT: u32 = 1;
pub const SECBIT_NOROOT_LOCKED: u32 = 2;
pub const SECBIT_NO_SETUID_FIXUP: u32 = 4;
pub const SECBIT_NO_SETUID_FIXUP_LOCKED: u32 = 8;
pub const SECBIT_KEEP_CAPS: u32 = 16;
pub const SECBIT_KEEP_CAPS_LOCKED: u32 = 32;
pub const SECBIT_NO_CAP_AMBIENT_RAISE: u32 = 64;
pub const SECBIT_NO_CAP_AMBIENT_RAISE_LOCKED: u32 = 128;

#[macro_export]
macro_rules! bpf {
    (@const_one $tok:tt) => {
        1
    };

    (@get_label_or_zero ([$label:expr]: $($tok:tt)+)) => {
        $label
    };

    (@get_label_or_zero ($($tok:tt)+)) => {
        0
    };

    (@count_instructions
        $(
            ($($tok:tt)+)
        ),+
    ) => {{
        let mut count = 0;
        $(
            count += $crate::bpf!(@const_one ($($tok)+));
        )+

        count
    }};

    (@max_label_plus_one
        $(
            ($($tok:tt)+)
        ),+
    ) => {{
        let mut max = -1;
        $(
            let label = $crate::bpf!(@get_label_or_zero ($($tok)+));
            if label > max {
                max = label;
            }
        )+

        if max < 0 {
            0
        } else {
            (max + 1) as usize
        }
    }};

    (@fill_label $labels:expr, $nth_instruction:expr, [$label:expr]: $($tok:tt)+) => {
        $labels[$label] = $nth_instruction;
    };

    (@fill_label $labels:expr, $nth_instruction:expr, $($tok:tt)+) => {};

    (@fill_labels
        $labels:expr,
        $(
            ($($tok:tt)+)
        ),+
    ) => {{
        let mut nth_instruction = 0;
        $(
            $crate::bpf!(@fill_label $labels, nth_instruction, $($tok)+);
            #[allow(unused_assignments)]
            {
                nth_instruction += 1;
            }
        )+
    }};

    (@target $labels:expr, $nth_instruction:expr, $target:expr) => {{
        let target = ($labels[$target] as i32 - $nth_instruction as i32 - 1);
        if target < 0 || target > 255 {
            panic!("invalid jump");
        }

        target as u8
    }};

    (@into_u32 $value:expr) => {{
        let value = $value;
        if value as i128 > core::u32::MAX as i128 || (value as i128) < core::i32::MIN as i128 {
            panic!("out of range value");
        }
        value as u32
    }};

    (@op $labels:expr, $nth_instruction:expr, [$label:expr]: $($tok:tt)+) => { $crate::bpf!(@op $labels, $nth_instruction, $($tok)+) };

    (@op $labels:expr, $nth_instruction:expr, a = *abs[$addr:expr]) => { $crate::sock_filter { code: $crate::BPF_LD | $crate::BPF_W | $crate::BPF_ABS, jt: 0, jf: 0, k: $addr } };
    (@op $labels:expr, $nth_instruction:expr, a &= $value:expr) => { $crate::sock_filter { code: $crate::BPF_ALU | $crate::BPF_AND | $crate::BPF_K, jt: 0, jf: 0, k: $value } };
    (@op $labels:expr, $nth_instruction:expr, if a == $value:expr => jump @$target:expr) => { $crate::sock_filter { code: $crate::BPF_JMP | $crate::BPF_JEQ | $crate::BPF_K, jt: $crate::bpf!(@target $labels, $nth_instruction, $target), jf: 0, k: $crate::bpf!(@into_u32 $value) } };
    (@op $labels:expr, $nth_instruction:expr, if a != $value:expr => jump @$target:expr) => { $crate::sock_filter { code: $crate::BPF_JMP | $crate::BPF_JEQ | $crate::BPF_K, jt: 0, jf: $crate::bpf!(@target $labels, $nth_instruction, $target), k: $crate::bpf!(@into_u32 $value) } };
    (@op $labels:expr, $nth_instruction:expr, jump @$target:expr) => { $crate::sock_filter { code: $crate::BPF_JMP | $crate::BPF_JA, jt: 0, jf: 0, k: $crate::bpf!(@target $labels, $nth_instruction, $target) as u32 } };
    (@op $labels:expr, $nth_instruction:expr, return $value:expr) => { $crate::sock_filter { code: $crate::BPF_RET | $crate::BPF_K, jt: 0, jf: 0, k: $value } };
    (@op $labels:expr, $nth_instruction:expr, seccomp_allow) => { $crate::bpf!(@op $labels, $nth_instruction, return $crate::SECCOMP_RET_ALLOW) };
    (@op $labels:expr, $nth_instruction:expr, seccomp_kill_thread) => { $crate::bpf!(@op $labels, $nth_instruction, return $crate::SECCOMP_RET_KILL_THREAD) };
    (@op $labels:expr, $nth_instruction:expr, a = syscall_nr) => { $crate::bpf!(@op $labels, $nth_instruction, a = *abs[0]) };
    (@op $labels:expr, $nth_instruction:expr, a = syscall_arg[$nth_arg:expr]) => { $crate::bpf!(@op $labels, $nth_instruction, a = *abs[16 + $nth_arg * 8]) };

    (
        $(
            ($($tok:tt)+),
        )+
    ) => {{
        let mut filter = [
            $crate::sock_filter { code: 0, jt: 0, jf: 0, k: 0 };
            { $crate::bpf!(@count_instructions $(($($tok)+)),+) }
        ];

        let mut labels = [
            0;
            { $crate::bpf!(@max_label_plus_one $(($($tok)+)),+) }
        ];

        $crate::bpf!(@fill_labels labels, $(($($tok)+)),+);

        {
            let mut nth_instruction = 0;

            $(
                #[allow(clippy::indexing_slicing)]
                {
                    filter[nth_instruction] = $crate::bpf!(@op labels, nth_instruction, $($tok)+);
                }
                nth_instruction += 1;
            )+

            let _ = nth_instruction;
        }

        filter
    }};
}

#[test]
fn test_bpf_jump() {
    assert_eq!(
        bpf! {
            (if a == 1234 => jump @0),
            (return 10),
            ([0]: return 20),
        },
        [
            sock_filter {
                code: BPF_JMP | BPF_JEQ | BPF_K,
                jt: 1,
                jf: 0,
                k: 1234
            },
            sock_filter {
                code: BPF_RET,
                jt: 0,
                jf: 0,
                k: 10
            },
            sock_filter {
                code: BPF_RET,
                jt: 0,
                jf: 0,
                k: 20
            },
        ]
    );

    assert_eq!(
        bpf! {
            (if a == 20 => jump @2),
            (if a == 10 => jump @2),
            ([0]: return 0),
            ([1]: return 1),
            ([2]: return 2),
        },
        [
            sock_filter {
                code: BPF_JMP | BPF_JEQ | BPF_K,
                jt: 3,
                jf: 0,
                k: 20
            },
            sock_filter {
                code: BPF_JMP | BPF_JEQ | BPF_K,
                jt: 2,
                jf: 0,
                k: 10
            },
            sock_filter {
                code: BPF_RET,
                jt: 0,
                jf: 0,
                k: 0
            },
            sock_filter {
                code: BPF_RET,
                jt: 0,
                jf: 0,
                k: 1
            },
            sock_filter {
                code: BPF_RET,
                jt: 0,
                jf: 0,
                k: 2
            },
        ]
    );
}

pub const STDIN_FILENO: c_int = 0;
pub const STDOUT_FILENO: c_int = 1;
pub const STDERR_FILENO: c_int = 2;

pub const AF_UNIX: u32 = 1;
pub const SOCK_STREAM: u32 = 1;
pub const SOCK_SEQPACKET: u32 = 5;
pub const SOL_SOCKET: c_int = 1;
pub const SCM_RIGHTS: c_int = 1;
pub const MSG_NOSIGNAL: u32 = 0x4000;

#[allow(non_snake_case)]
const fn CMSG_ALIGN(len: usize) -> usize {
    (len + core::mem::size_of::<usize>() - 1) & !(core::mem::size_of::<usize>() - 1)
}

#[allow(non_snake_case)]
pub unsafe fn CMSG_FIRSTHDR(mhdr: *const msghdr) -> *mut cmsghdr {
    if (*mhdr).msg_controllen >= core::mem::size_of::<cmsghdr>() {
        (*mhdr).msg_control as *mut cmsghdr
    } else {
        core::ptr::null_mut()
    }
}

#[allow(non_snake_case)]
pub unsafe fn CMSG_DATA(cmsg: *mut cmsghdr) -> *mut c_uchar {
    cmsg.add(1) as *mut c_uchar
}

#[allow(non_snake_case)]
pub const fn CMSG_SPACE(length: usize) -> usize {
    CMSG_ALIGN(length) + CMSG_ALIGN(core::mem::size_of::<cmsghdr>())
}

#[allow(non_snake_case)]
pub const fn CMSG_LEN(length: usize) -> usize {
    CMSG_ALIGN(core::mem::size_of::<cmsghdr>()) + length
}

// The following was copied from the `cstr_core` crate.
//
// TODO: Remove this once this is stable: https://github.com/rust-lang/rust/issues/105723
#[inline]
#[doc(hidden)]
#[allow(clippy::indexing_slicing)]
pub const fn cstr_is_valid(bytes: &[u8]) -> bool {
    if bytes.is_empty() || bytes[bytes.len() - 1] != 0 {
        return false;
    }

    let mut index = 0;
    while index < bytes.len() - 1 {
        if bytes[index] == 0 {
            return false;
        }
        index += 1;
    }
    true
}

#[macro_export]
macro_rules! cstr {
    ($e:expr) => {{
        const STR: &[u8] = concat!($e, "\0").as_bytes();
        const STR_VALID: bool = $crate::cstr_is_valid(STR);
        let _ = [(); 0 - (!(STR_VALID) as usize)];
        #[allow(unused_unsafe)]
        unsafe {
            core::ffi::CStr::from_bytes_with_nul_unchecked(STR)
        }
    }}
}

#[derive(Clone, Debug)]
pub struct Error {
    #[cfg(not(feature = "std"))]
    message: &'static str,
    #[cfg(feature = "std")]
    message: Cow<'static, str>,
    errno: c_int,
}

impl core::fmt::Display for Error {
    #[cold]
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
        let mut is_err = false;
        self.fmt_to_string(|chunk| {
            if fmt.write_str(chunk).is_err() {
                is_err = true;
            }
        });

        if is_err {
            Err(core::fmt::Error)
        } else {
            Ok(())
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

#[cfg(feature = "std")]
impl From<std::string::String> for Error {
    fn from(message: std::string::String) -> Self {
        Error {
            message: message.into(),
            errno: 0,
        }
    }
}

impl From<&'static str> for Error {
    fn from(message: &'static str) -> Self {
        Error::from_str(message)
    }
}

fn write_number(value: u32, write_str: &mut dyn FnMut(&str)) {
    let n = if value >= 10 {
        write_number(value / 10, write_str);
        value % 10
    } else {
        value
    };

    let s = [n as u8 + b'0'];
    let s = unsafe { core::str::from_utf8_unchecked(&s) };
    write_str(s);
}

impl Error {
    pub fn fmt_to_string(&self, mut write_str: impl FnMut(&str)) {
        self.fmt_to_string_impl(&mut write_str);
    }

    // Avoid pulling in core::fmt machinery to keep the code size low.
    #[cold]
    fn fmt_to_string_impl(&self, write_str: &mut dyn FnMut(&str)) {
        write_str(&self.message);

        if self.errno == 0 {
            return;
        }

        write_str(" (errno = ");
        write_number(self.errno as u32, write_str);

        let errno = match self.errno as u32 {
            EPERM => Some("EPERM"),
            ENOENT => Some("ENOENT"),
            ESRCH => Some("ESRCH"),
            EINTR => Some("EINTR"),
            EIO => Some("EIO"),
            ENXIO => Some("ENXIO"),
            E2BIG => Some("E2BIG"),
            ENOEXEC => Some("ENOEXEC"),
            EBADF => Some("EBADF"),
            ECHILD => Some("ECHILD"),
            EAGAIN => Some("EAGAIN"),
            ENOMEM => Some("ENOMEM"),
            EACCES => Some("EACCES"),
            EFAULT => Some("EFAULT"),
            ENOTBLK => Some("ENOTBLK"),
            EBUSY => Some("EBUSY"),
            EEXIST => Some("EEXIST"),
            EXDEV => Some("EXDEV"),
            ENODEV => Some("ENODEV"),
            ENOTDIR => Some("ENOTDIR"),
            EISDIR => Some("EISDIR"),
            EINVAL => Some("EINVAL"),
            ENFILE => Some("ENFILE"),
            EMFILE => Some("EMFILE"),
            ENOTTY => Some("ENOTTY"),
            ETXTBSY => Some("ETXTBSY"),
            EFBIG => Some("EFBIG"),
            ENOSPC => Some("ENOSPC"),
            ESPIPE => Some("ESPIPE"),
            EROFS => Some("EROFS"),
            EMLINK => Some("EMLINK"),
            EPIPE => Some("EPIPE"),
            EDOM => Some("EDOM"),
            ERANGE => Some("ERANGE"),
            _ => None,
        };

        if let Some(errno) = errno {
            write_str(" (");
            write_str(errno);
            write_str(")");
        }

        write_str(")");
    }

    #[cfg(feature = "std")]
    #[cold]
    pub fn from_os_error(message: &'static str, error: std::io::Error) -> Self {
        Self {
            message: message.into(),
            errno: error.raw_os_error().unwrap_or(0),
        }
    }

    #[cfg(feature = "std")]
    #[cold]
    pub fn from_last_os_error(message: &'static str) -> Self {
        Self {
            message: message.into(),
            errno: std::io::Error::last_os_error().raw_os_error().unwrap_or(0),
        }
    }

    #[cold]
    pub const fn from_errno(message: &'static str, errno: i32) -> Self {
        Self {
            #[cfg(not(feature = "std"))]
            message,
            #[cfg(feature = "std")]
            message: Cow::Borrowed(message),

            errno,
        }
    }

    #[cold]
    pub const fn from_str(message: &'static str) -> Self {
        Self {
            #[cfg(not(feature = "std"))]
            message,
            #[cfg(feature = "std")]
            message: Cow::Borrowed(message),

            errno: 0,
        }
    }

    #[inline]
    pub fn from_syscall(message: &'static str, result: i64) -> Result<(), Self> {
        if result >= -4095 && result < 0 {
            Err(Self::from_syscall_unchecked(message, result))
        } else {
            Ok(())
        }
    }

    #[cold]
    #[inline]
    const fn from_syscall_unchecked(message: &'static str, result: i64) -> Self {
        Self {
            #[cfg(not(feature = "std"))]
            message,
            #[cfg(feature = "std")]
            message: Cow::Borrowed(message),

            errno: -result as i32,
        }
    }

    #[inline]
    pub fn errno(&self) -> u32 {
        self.errno as u32
    }
}

#[cfg(target_arch = "x86_64")]
#[inline(never)]
#[cold]
pub fn abort() -> ! {
    // In practice `core::hint::unreachable_unchecked` emits this,
    // but technically calling it is undefined behavior which could
    // affect unrelated code, so let's just call it through `asm!`.

    unsafe {
        core::arch::asm!("ud2", options(noreturn, nostack));
    }
}

/// An owned file descriptor. Will be automatically closed on drop.
#[repr(transparent)]
#[derive(PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct Fd(c_int);

/// An unowned file descriptor.
#[repr(transparent)]
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct FdRef<'a>(c_int, PhantomData<&'a Fd>);

impl Fd {
    pub fn raw(&self) -> c_int {
        self.0
    }

    #[inline]
    pub const fn from_raw_unchecked(fd: c_int) -> Self {
        Self(fd)
    }

    pub fn borrow(&self) -> FdRef {
        FdRef(self.0, PhantomData)
    }

    pub fn close(mut self) -> Result<(), Error> {
        self.close_inplace()?;
        Ok(())
    }

    pub fn leak(mut self) -> c_int {
        core::mem::replace(&mut self.0, -1)
    }

    fn close_inplace(&mut self) -> Result<(), Error> {
        if self.raw() < 0 {
            return Ok(());
        }

        let result = unsafe { syscall_readonly!(SYS_close, self.raw()) };
        Error::from_syscall("close", result)
    }
}

impl Drop for Fd {
    fn drop(&mut self) {
        let _ = self.close_inplace();
    }
}

impl<'a> FdRef<'a> {
    pub fn raw(&self) -> c_int {
        self.0
    }

    #[inline]
    pub const fn from_raw_unchecked(fd: c_int) -> Self {
        Self(fd, PhantomData)
    }
}

impl<'a> From<&'a Fd> for FdRef<'a> {
    fn from(fd: &'a Fd) -> Self {
        FdRef(fd.0, PhantomData)
    }
}

impl<'a> From<&'a mut Fd> for FdRef<'a> {
    fn from(fd: &'a mut Fd) -> Self {
        FdRef(fd.0, PhantomData)
    }
}

impl core::fmt::Write for Fd {
    fn write_str(&mut self, string: &str) -> core::fmt::Result {
        FdRef::from(self).write_str(string)
    }
}

impl<'a> core::fmt::Write for FdRef<'a> {
    fn write_str(&mut self, string: &str) -> core::fmt::Result {
        let mut bytes = string.as_bytes();
        while !bytes.is_empty() {
            let count = sys_write(*self, bytes).map_err(|_| core::fmt::Error)?;
            if count == 0 {
                return Err(core::fmt::Error);
            }
            bytes = bytes.get(count..).ok_or(core::fmt::Error)?;
        }

        Ok(())
    }
}

fn sys_getdents64(fd: FdRef, buffer: &mut [u8]) -> Result<Option<usize>, Error> {
    let length = buffer.len();
    let bytes_read = unsafe { syscall!(SYS_getdents64, fd.raw(), buffer, length) };
    Error::from_syscall("getdents64", bytes_read)?;

    if bytes_read == 0 {
        Ok(None)
    } else {
        Ok(Some(bytes_read as usize))
    }
}

pub fn sys_socketpair(domain: u32, kind: u32, protocol: u32) -> Result<(Fd, Fd), Error> {
    let mut output: [c_int; 2] = [-1, -1];
    let fd = unsafe { syscall_readonly!(SYS_socketpair, domain, kind, protocol, &mut output[..]) };
    Error::from_syscall("socketpair", fd)?;
    Ok((Fd(output[0] as c_int), Fd(output[1] as c_int)))
}

pub fn sys_pipe2(flags: c_uint) -> Result<(Fd, Fd), Error> {
    let mut pipes: [c_int; 2] = [-1, -1];
    let result = unsafe { syscall_readonly!(SYS_pipe2, pipes.as_mut_ptr(), flags) };
    Error::from_syscall("pipe2", result)?;
    Ok((Fd::from_raw_unchecked(pipes[0]), Fd::from_raw_unchecked(pipes[1])))
}

pub fn sys_open(path: &CStr, flags: c_uint) -> Result<Fd, Error> {
    let fd = unsafe { syscall_readonly!(SYS_open, path.as_ptr(), flags, 0) };
    Error::from_syscall("open", fd)?;
    Ok(Fd(fd as c_int))
}

pub fn sys_openat(dir: FdRef, path: &CStr, flags: c_uint) -> Result<Fd, Error> {
    let fd = unsafe { syscall_readonly!(SYS_openat, dir, path.as_ptr(), flags, 0) };
    Error::from_syscall("openat", fd)?;
    Ok(Fd(fd as c_int))
}

pub fn sys_memfd_create(name: &CStr, flags: c_uint) -> Result<Fd, Error> {
    let fd = unsafe { syscall_readonly!(SYS_memfd_create, name.as_ptr(), flags) };
    Error::from_syscall("memfd_create", fd)?;
    Ok(Fd(fd as c_int))
}

pub fn sys_fcntl(fd: FdRef, cmd: u32, arg: u32) -> Result<(), Error> {
    let result = unsafe { syscall_readonly!(SYS_fcntl, fd, cmd, arg) };
    Error::from_syscall("fcntl", result)?;
    Ok(())
}

pub fn sys_close_range(first_fd: c_int, last_fd: c_int, flags: c_uint) -> Result<(), Error> {
    let result = unsafe { syscall_readonly!(SYS_close_range, first_fd, last_fd, flags) };
    Error::from_syscall("close_range", result)
}

pub fn sys_ftruncate(fd: FdRef, length: c_ulong) -> Result<(), Error> {
    let result = unsafe { syscall!(SYS_ftruncate, fd, length) };
    Error::from_syscall("ftruncate", result)
}

pub fn sys_chdir(path: &CStr) -> Result<(), Error> {
    let result = unsafe { syscall_readonly!(SYS_chdir, path.as_ptr()) };
    Error::from_syscall("chdir", result)
}

pub fn sys_fchdir(fd: FdRef) -> Result<(), Error> {
    let result = unsafe { syscall_readonly!(SYS_fchdir, fd) };
    Error::from_syscall("fchdir", result)
}

pub unsafe fn sys_mmap(
    address: *mut c_void,
    length: c_size_t,
    protection: c_uint,
    flags: c_uint,
    fd: Option<FdRef>,
    offset: c_ulong,
) -> Result<*mut c_void, Error> {
    let result = syscall!(SYS_mmap, address, length, protection, flags, fd, offset);
    Error::from_syscall("mmap", result)?;
    Ok(result as *mut c_void)
}

pub unsafe fn sys_munmap(address: *mut c_void, length: c_size_t) -> Result<(), Error> {
    let result = syscall!(SYS_munmap, address, length);
    Error::from_syscall("munmap", result)
}

pub unsafe fn sys_mremap(
    address: *mut c_void,
    old_length: c_size_t,
    new_length: c_size_t,
    flags: c_uint,
    new_address: *mut c_void,
) -> Result<*mut c_void, Error> {
    let result = syscall!(SYS_mremap, address, old_length, new_length, flags, new_address);
    Error::from_syscall("mremap", result)?;
    Ok(result as *mut c_void)
}

pub unsafe fn sys_mprotect(address: *mut c_void, length: c_size_t, protection: c_uint) -> Result<(), Error> {
    let result = syscall!(SYS_mprotect, address, length, protection);
    Error::from_syscall("mprotect", result)
}

pub unsafe fn sys_madvise(address: *mut c_void, length: c_size_t, advice: c_uint) -> Result<(), Error> {
    let result = syscall!(SYS_madvise, address, length, advice);
    Error::from_syscall("madvise", result)
}

pub fn sys_getpid() -> Result<pid_t, Error> {
    let result = unsafe { syscall_readonly!(SYS_getpid) };
    Error::from_syscall("getpid", result)?;
    Ok(result as pid_t)
}

pub fn sys_getuid() -> Result<uid_t, Error> {
    let result = unsafe { syscall_readonly!(SYS_getuid) };
    Error::from_syscall("getuid", result)?;
    Ok(result as u32)
}

pub fn sys_getgid() -> Result<gid_t, Error> {
    let result = unsafe { syscall_readonly!(SYS_getgid) };
    Error::from_syscall("getgid", result)?;
    Ok(result as u32)
}

pub fn sys_kill(pid: pid_t, signal: c_uint) -> Result<(), Error> {
    let result = unsafe { syscall_readonly!(SYS_kill, pid, signal) };
    Error::from_syscall("kill", result)?;
    Ok(())
}

pub unsafe fn sys_read_raw(fd: FdRef, buffer: *mut u8, length: usize) -> Result<c_size_t, Error> {
    let result = unsafe { syscall!(SYS_read, fd.raw(), buffer, length) };
    Error::from_syscall("read", result)?;
    Ok(result as c_size_t)
}

pub fn sys_read(fd: FdRef, buffer: &mut [u8]) -> Result<c_size_t, Error> {
    unsafe { sys_read_raw(fd, buffer.as_mut_ptr(), buffer.len()) }
}

pub fn sys_write(fd: FdRef, buffer: &[u8]) -> Result<c_size_t, Error> {
    let result = unsafe { syscall_readonly!(SYS_write, fd.raw(), buffer.as_ptr(), buffer.len()) };
    Error::from_syscall("write", result)?;
    Ok(result as c_size_t)
}

pub unsafe fn sys_process_vm_readv(pid: pid_t, local_iovec: &[iovec], remote_iovec: &[iovec]) -> Result<usize, Error> {
    let result = unsafe {
        syscall!(
            SYS_process_vm_readv,
            pid,
            local_iovec,
            local_iovec.len(),
            remote_iovec,
            remote_iovec.len(),
            0
        )
    };
    Error::from_syscall("process_vm_readv", result)?;
    Ok(result as usize)
}

pub unsafe fn sys_process_vm_writev(pid: pid_t, local_iovec: &[iovec], remote_iovec: &[iovec]) -> Result<usize, Error> {
    let result = unsafe {
        syscall!(
            SYS_process_vm_writev,
            pid,
            local_iovec,
            local_iovec.len(),
            remote_iovec,
            remote_iovec.len(),
            0
        )
    };
    Error::from_syscall("process_vm_writev", result)?;
    Ok(result as usize)
}

pub fn sys_sendmsg(fd: FdRef, message: &msghdr, flags: u32) -> Result<usize, Error> {
    let result = unsafe { syscall_readonly!(SYS_sendmsg, fd.raw(), message as *const msghdr, flags) };
    Error::from_syscall("sendmsg", result)?;
    Ok(result as usize)
}

pub fn sys_recvmsg(fd: FdRef, message: &mut msghdr, flags: u32) -> Result<usize, Error> {
    let result = unsafe { syscall!(SYS_recvmsg, fd.raw(), message as *mut msghdr, flags) };
    Error::from_syscall("recvmsg", result)?;
    Ok(result as usize)
}

pub fn sys_exit(errcode: c_int) -> Result<(), Error> {
    let result = unsafe { syscall_readonly!(SYS_exit, errcode) };
    Error::from_syscall("exit", result)?;
    Ok(())
}

pub fn sys_dup3(old_fd: c_int, new_fd: c_int, flags: c_uint) -> Result<(), Error> {
    let result = unsafe { syscall_readonly!(SYS_dup3, old_fd, new_fd, flags) };
    Error::from_syscall("dup3", result)?;
    Ok(())
}

pub unsafe fn sys_execveat(
    dirfd: Option<FdRef>,
    path: &CStr,
    argv: &[*const c_uchar],
    envp: &[*const c_uchar],
    flags: c_uint,
) -> Result<(), Error> {
    let result = unsafe { syscall_readonly!(SYS_execveat, dirfd, path.as_ptr(), argv, envp, flags) };
    Error::from_syscall("execveat", result)?;
    Ok(())
}

pub fn sys_ptrace_traceme() -> Result<(), Error> {
    let result = unsafe { syscall_readonly!(SYS_ptrace, 0, 0, 0) };
    Error::from_syscall("ptrace (PTRACE_TRACEME)", result)?;
    Ok(())
}

pub fn sys_prctl_set_no_new_privs() -> Result<(), Error> {
    const PR_SET_NO_NEW_PRIVS: usize = 38;
    let result = unsafe { syscall_readonly!(SYS_prctl, PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    Error::from_syscall("prctl(PR_SET_NO_NEW_PRIVS)", result)
}

pub fn sys_prctl_cap_ambient_clear_all() -> Result<(), Error> {
    const PR_CAP_AMBIENT: usize = 47;
    const PR_CAP_AMBIENT_CLEAR_ALL: usize = 4;
    let result = unsafe { syscall_readonly!(SYS_prctl, PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) };
    Error::from_syscall("prctl(PR_CAP_AMBIENT)", result)
}

pub fn sys_prctl_set_securebits(bits: u32) -> Result<(), Error> {
    const PR_SET_SECUREBITS: usize = 28;
    let result = unsafe { syscall_readonly!(SYS_prctl, PR_SET_SECUREBITS, bits, 0, 0, 0) };
    Error::from_syscall("prctl(PR_SET_SECUREBITS)", result)
}

pub fn sys_prctl_set_name(name: &[u8; 16]) -> Result<(), Error> {
    const PR_SET_NAME: usize = 15;
    let result = unsafe { syscall_readonly!(SYS_prctl, PR_SET_NAME, name.as_ptr(), 0, 0, 0) };
    Error::from_syscall("prctl(PR_SET_NAME)", result)
}

pub fn sys_capset(header: &__user_cap_header_struct, data: &[__user_cap_data_struct; 2]) -> Result<(), Error> {
    let result = unsafe {
        syscall_readonly!(
            SYS_capset,
            header as *const __user_cap_header_struct,
            data as *const __user_cap_data_struct
        )
    };
    Error::from_syscall("capset", result)
}

pub fn sys_capset_drop_all() -> Result<(), Error> {
    let cap_user_header = __user_cap_header_struct {
        version: _LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let cap_user_data = [__user_cap_data_struct {
        effective: 0,
        inheritable: 0,
        permitted: 0,
    }; 2];

    sys_capset(&cap_user_header, &cap_user_data)
}

pub fn sys_seccomp_set_mode_filter(filter: &[sock_filter]) -> Result<(), Error> {
    let filter = sock_fprog {
        length: if let Ok(length) = c_ushort::try_from(filter.len()) {
            length
        } else {
            return Err(Error::from_errno("seccomp(SECCOMP_SET_MODE_FILTER)", EINVAL as i32));
        },
        filter: filter.as_ptr(),
    };

    let result = unsafe { syscall_readonly!(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &filter as *const sock_fprog) };
    Error::from_syscall("seccomp(SECCOMP_SET_MODE_FILTER)", result)
}

pub fn sys_setrlimit(resource: u32, limit: &rlimit) -> Result<(), Error> {
    let result = unsafe { syscall_readonly!(SYS_setrlimit, resource, limit as *const rlimit) };
    Error::from_syscall("setrlimit", result)
}

pub fn sys_sethostname(name: &str) -> Result<(), Error> {
    let result = unsafe { syscall_readonly!(SYS_sethostname, name.as_ptr(), name.len()) };
    Error::from_syscall("sethostname", result)
}

pub fn sys_setdomainname(name: &str) -> Result<(), Error> {
    let result = unsafe { syscall_readonly!(SYS_setdomainname, name.as_ptr(), name.len()) };
    Error::from_syscall("setdomainname", result)
}

pub fn sys_mount(dev_name: &CStr, dir_name: &CStr, kind: &CStr, flags: u32, data: Option<&CStr>) -> Result<(), Error> {
    let result = unsafe {
        syscall_readonly!(
            SYS_mount,
            dev_name.as_ptr(),
            dir_name.as_ptr(),
            kind.as_ptr(),
            flags,
            data.map(|data| data.as_ptr()).unwrap_or(core::ptr::null())
        )
    };
    Error::from_syscall("mount", result)
}

pub fn sys_umount2(target: &CStr, flags: u32) -> Result<(), Error> {
    let result = unsafe { syscall_readonly!(SYS_umount2, target.as_ptr(), flags) };
    Error::from_syscall("umount2", result)
}

pub fn sys_pivot_root(new_root: &CStr, old_root: &CStr) -> Result<(), Error> {
    let result = unsafe { syscall_readonly!(SYS_pivot_root, new_root.as_ptr(), old_root.as_ptr()) };
    Error::from_syscall("pivot_root", result)
}

pub fn sys_unshare(flags: u32) -> Result<(), Error> {
    let result = unsafe { syscall_readonly!(SYS_unshare, flags) };
    Error::from_syscall("unshare", result)
}

/// Calls the `futex` syscall with FUTEX_WAIT operation.
///
/// This will block *if* the value of the `futex` is equal to the `expected_value`.
///
/// Possible non-fatal errors:
///   - `EAGAIN`: the value of `futex` is not equal to `expected_value`
///   - `EINTR`: the syscall was interrupted by a signal
///   - `ETIMEDOUT`: the specified timeout has elapsed without the futex being woken up
pub fn sys_futex_wait(futex: &AtomicU32, expected_value: u32, timeout: Option<Duration>) -> Result<(), Error> {
    let ts: Option<timespec> = timeout.map(|timeout| timespec {
        tv_sec: timeout.as_secs() as i64,
        tv_nsec: u64::from(timeout.subsec_nanos()) as i64,
    });

    let result = unsafe {
        syscall!(
            SYS_futex,
            futex as *const AtomicU32,
            FUTEX_WAIT,
            expected_value,
            ts.as_ref().map(|ts| ts as *const timespec).unwrap_or(core::ptr::null())
        )
    };
    Error::from_syscall("futex (wait)", result)
}

/// Wakes up at most one thread waiting on `futex`.
///
/// Will return `true` if anybody was woken up.
pub fn sys_futex_wake_one(futex: &AtomicU32) -> Result<bool, Error> {
    let result = unsafe { syscall_readonly!(SYS_futex, futex as *const AtomicU32, FUTEX_WAKE, 1) };
    Error::from_syscall("futex (wake)", result)?;
    Ok(result == 1)
}

pub fn sys_set_tid_address(address: *const u32) -> Result<(), Error> {
    let result = unsafe { syscall_readonly!(SYS_set_tid_address, address) };
    Error::from_syscall("set_tid_address", result)?;
    Ok(())
}

pub unsafe fn sys_rt_sigaction(signal: u32, new_action: &kernel_sigaction, old_action: Option<&mut kernel_sigaction>) -> Result<(), Error> {
    let result = unsafe {
        syscall_readonly!(
            SYS_rt_sigaction,
            signal,
            new_action as *const kernel_sigaction,
            old_action
                .map(|old_action| old_action as *mut kernel_sigaction)
                .unwrap_or(core::ptr::null_mut()),
            core::mem::size_of::<kernel_sigset_t>()
        )
    };
    Error::from_syscall("rt_sigaction", result)?;
    Ok(())
}

pub unsafe fn sys_rt_sigprocmask(how: u32, new_sigset: &kernel_sigset_t, old_sigset: Option<&mut kernel_sigset_t>) -> Result<(), Error> {
    let result = unsafe {
        syscall_readonly!(
            SYS_rt_sigprocmask,
            how,
            new_sigset as *const kernel_sigset_t,
            old_sigset
                .map(|old_sigset| old_sigset as *mut kernel_sigset_t)
                .unwrap_or(core::ptr::null_mut()),
            core::mem::size_of::<kernel_sigset_t>()
        )
    };
    Error::from_syscall("rt_sigprocmask", result)?;
    Ok(())
}

pub unsafe fn sys_sigaltstack(new_stack: &stack_t, old_stack: Option<&mut stack_t>) -> Result<(), Error> {
    let result = unsafe {
        syscall_readonly!(
            SYS_sigaltstack,
            new_stack as *const stack_t,
            old_stack
                .map(|old_stack| old_stack as *mut stack_t)
                .unwrap_or(core::ptr::null_mut())
        )
    };
    Error::from_syscall("sigaltstack", result)?;
    Ok(())
}

pub fn sys_clock_gettime(clock_id: u32) -> Result<Duration, Error> {
    let mut output = timespec { tv_sec: 0, tv_nsec: 0 };

    let result = unsafe { syscall_readonly!(SYS_clock_gettime, clock_id, &mut output as *mut timespec) };
    Error::from_syscall("clock_gettime", result)?;

    let duration = Duration::new(output.tv_sec as u64, output.tv_nsec as u32);
    Ok(duration)
}

pub fn sys_waitid(which: u32, pid: pid_t, info: &mut siginfo_t, options: u32, usage: Option<&mut rusage>) -> Result<(), Error> {
    let result = unsafe {
        syscall_readonly!(
            SYS_waitid,
            which,
            pid,
            info as *mut siginfo_t,
            options,
            usage.map(|usage| usage as *mut rusage).unwrap_or(core::ptr::null_mut())
        )
    };

    Error::from_syscall("waitid", result)?;
    Ok(())
}

pub fn vm_read_memory<const N_LOCAL: usize, const N_REMOTE: usize>(
    pid: pid_t,
    local: [&mut [MaybeUninit<u8>]; N_LOCAL],
    remote: [(usize, usize); N_REMOTE],
) -> Result<usize, Error> {
    let local_iovec = local.map(|slice| iovec {
        iov_base: slice.as_mut_ptr().cast(),
        iov_len: slice.len() as u64,
    });
    let remote_iovec = remote.map(|(address, length)| iovec {
        iov_base: address as *mut c_void,
        iov_len: length as u64,
    });
    unsafe { sys_process_vm_readv(pid, &local_iovec, &remote_iovec) }
}

pub fn vm_write_memory<const N_LOCAL: usize, const N_REMOTE: usize>(
    pid: pid_t,
    local: [&[u8]; N_LOCAL],
    remote: [(usize, usize); N_REMOTE],
) -> Result<usize, Error> {
    let local_iovec = local.map(|slice| iovec {
        iov_base: (slice.as_ptr() as *mut u8).cast(),
        iov_len: slice.len() as u64,
    });
    let remote_iovec = remote.map(|(address, length)| iovec {
        iov_base: address as *mut c_void,
        iov_len: length as u64,
    });
    unsafe { sys_process_vm_writev(pid, &local_iovec, &remote_iovec) }
}

#[inline(always)] // To prevent the buffer from being copied.
pub fn readdir(dirfd: FdRef) -> Dirent64Iter {
    Dirent64Iter {
        dirfd,
        buffer: [0; 1024], // TODO: Use MaybeUninit.
        bytes_available: 0,
        position: 0,
    }
}

#[repr(transparent)]
pub struct Dirent64(linux_dirent64);

impl Dirent64 {
    pub fn d_type(&self) -> c_uchar {
        self.0.d_type
    }

    pub fn d_name(&self) -> &[u8] {
        unsafe {
            let mut p = self.0.d_name.as_ptr();
            while *p != 0 {
                p = p.add(1);
            }

            let length = p as usize - self.0.d_name.as_ptr() as usize;
            core::slice::from_raw_parts(self.0.d_name.as_ptr().cast(), length)
        }
    }
}

pub struct Dirent64Iter<'a> {
    dirfd: FdRef<'a>,
    buffer: [u8; 1024],
    bytes_available: usize,
    position: usize,
}

impl<'a> Iterator for Dirent64Iter<'a> {
    type Item = Result<&'a Dirent64, Error>;
    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.position < self.bytes_available {
                let dirent = unsafe { &*(self.buffer.as_ptr().add(self.position) as *const Dirent64) };

                self.position += usize::from(dirent.0.d_reclen);
                return Some(Ok(dirent));
            }

            match sys_getdents64(self.dirfd, &mut self.buffer) {
                Ok(Some(bytes_available)) => self.bytes_available = bytes_available,
                Ok(None) => return None,
                Err(error) => return Some(Err(error)),
            };
        }
    }
}

pub fn sendfd(socket: FdRef, fd: FdRef) -> Result<(), Error> {
    let mut dummy: c_int = 0;
    let mut buffer = [0; CMSG_SPACE(core::mem::size_of::<c_int>())];

    let mut iov = iovec {
        iov_base: &mut dummy as *mut c_int as *mut c_void,
        iov_len: core::mem::size_of_val(&dummy) as u64,
    };

    let mut header = msghdr {
        msg_name: core::ptr::null_mut(),
        msg_namelen: 0,
        msg_iov: &mut iov,
        msg_iovlen: 1,
        msg_control: buffer.as_mut_ptr().cast::<c_void>(),
        msg_controllen: core::mem::size_of_val(&buffer),
        msg_flags: 0,
    };

    let control_header = cmsghdr {
        cmsg_len: CMSG_LEN(core::mem::size_of::<c_int>()),
        cmsg_level: SOL_SOCKET,
        cmsg_type: SCM_RIGHTS,
    };

    unsafe {
        core::ptr::write_unaligned(CMSG_FIRSTHDR(&header), control_header);
        core::ptr::write_unaligned(CMSG_DATA(buffer.as_mut_ptr() as *mut cmsghdr) as *mut c_int, fd.raw());
    }

    header.msg_controllen = CMSG_LEN(core::mem::size_of::<c_int>());
    sys_sendmsg(socket, &header, MSG_NOSIGNAL)?;

    Ok(())
}

pub fn recvfd(socket: FdRef) -> Result<Fd, Error> {
    let mut dummy: c_int = 0;
    let mut buffer = [0; CMSG_SPACE(core::mem::size_of::<c_int>())];

    let mut iov = iovec {
        iov_base: &mut dummy as *mut c_int as *mut c_void,
        iov_len: core::mem::size_of_val(&dummy) as u64,
    };

    let mut header = msghdr {
        msg_name: core::ptr::null_mut(),
        msg_namelen: 0,
        msg_iov: &mut iov,
        msg_iovlen: 1,
        msg_control: buffer.as_mut_ptr().cast::<c_void>(),
        msg_controllen: core::mem::size_of_val(&buffer),
        msg_flags: 0,
    };

    let count = sys_recvmsg(socket, &mut header, 0)?;
    if count != core::mem::size_of::<c_int>() {
        return Err(Error::from_str("recvfd failed: received unexpected number of bytes"));
    }

    if header.msg_controllen != CMSG_SPACE(core::mem::size_of::<c_int>()) {
        return Err(Error::from_str("recvfd failed: invalid control message size"));
    }

    let control_header = unsafe { &mut *header.msg_control.cast::<cmsghdr>() };

    if control_header.cmsg_level != SOL_SOCKET {
        return Err(Error::from_str("recvfd failed: invalid control message level"));
    }

    if control_header.cmsg_type != SCM_RIGHTS {
        return Err(Error::from_str("recvfd failed: invalid control message type"));
    }

    let fd = unsafe { core::ptr::read_unaligned(CMSG_DATA(control_header) as *mut c_int) };

    Ok(Fd::from_raw_unchecked(fd))
}
