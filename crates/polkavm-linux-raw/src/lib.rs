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
#![allow(clippy::undocumented_unsafe_blocks)]
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
#[allow(clippy::ptr_as_ptr)]
#[allow(clippy::used_underscore_binding)]
#[allow(clippy::transmute_ptr_to_ptr)]
mod arch_amd64_bindings;

mod io_uring;
mod mmap;

pub use io_uring::IoUring;
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

#[allow(non_camel_case_types)]
pub type size_t = c_size_t;

// Doesn't appear in public headers.
pub const MNT_FORCE: u32 = 1;
pub const MNT_DETACH: u32 = 2;
pub const MNT_EXPIRE: u32 = 4;

pub const SIG_DFL: usize = 0;
pub const SIG_IGN: usize = 1;

// Bindgen seems to not want to emit this constant,
// so let's define it manually.
pub const HWCAP2_FSGSBASE: usize = 1 << 1;

pub(crate) use crate::arch_amd64_bindings as arch_bindings;

#[rustfmt::skip]
pub use crate::arch_bindings::{
    __kernel_gid_t as gid_t,
    __kernel_pid_t as pid_t,
    __kernel_uid_t as uid_t,
    __NR_arch_prctl as SYS_arch_prctl,
    __NR_capset as SYS_capset,
    __NR_chdir as SYS_chdir,
    __NR_clock_gettime as SYS_clock_gettime,
    __NR_clone as SYS_clone,
    __NR_clone3 as SYS_clone3,
    __NR_close as SYS_close,
    __NR_close_range as SYS_close_range,
    __NR_dup3 as SYS_dup3,
    __NR_execveat as SYS_execveat,
    __NR_exit as SYS_exit,
    __NR_fallocate as SYS_fallocate,
    __NR_fchdir as SYS_fchdir,
    __NR_fcntl as SYS_fcntl,
    __NR_ftruncate as SYS_ftruncate,
    __NR_futex as SYS_futex,
    __NR_getdents64 as SYS_getdents64,
    __NR_getgid as SYS_getgid,
    __NR_getpid as SYS_getpid,
    __NR_getuid as SYS_getuid,
    __NR_io_uring_enter as SYS_io_uring_enter,
    __NR_io_uring_register as SYS_io_uring_register,
    __NR_io_uring_setup as SYS_io_uring_setup,
    __NR_ioctl as SYS_ioctl,
    __NR_kill as SYS_kill,
    __NR_lseek as SYS_lseek,
    __NR_nanosleep as SYS_nanosleep,
    __NR_madvise as SYS_madvise,
    __NR_memfd_create as SYS_memfd_create,
    __NR_mmap as SYS_mmap,
    __NR_mount as SYS_mount,
    __NR_mprotect as SYS_mprotect,
    __NR_mremap as SYS_mremap,
    __NR_munmap as SYS_munmap,
    __NR_open as SYS_open,
    __NR_openat as SYS_openat,
    __NR_pidfd_send_signal as SYS_pidfd_send_signal,
    __NR_pipe2 as SYS_pipe2,
    __NR_pivot_root as SYS_pivot_root,
    __NR_prctl as SYS_prctl,
    __NR_process_vm_readv as SYS_process_vm_readv,
    __NR_process_vm_writev as SYS_process_vm_writev,
    __NR_ptrace as SYS_ptrace,
    __NR_read as SYS_read,
    __NR_recvmsg as SYS_recvmsg,
    __NR_rt_sigaction as SYS_rt_sigaction,
    __NR_rt_sigprocmask as SYS_rt_sigprocmask,
    __NR_rt_sigreturn as SYS_rt_sigreturn,
    __NR_sched_yield as SYS_sched_yield,
    __NR_seccomp as SYS_seccomp,
    __NR_sendmsg as SYS_sendmsg,
    __NR_set_tid_address as SYS_set_tid_address,
    __NR_setdomainname as SYS_setdomainname,
    __NR_sethostname as SYS_sethostname,
    __NR_setrlimit as SYS_setrlimit,
    __NR_sigaltstack as SYS_sigaltstack,
    __NR_socketpair as SYS_socketpair,
    __NR_umount2 as SYS_umount2,
    __NR_uname as SYS_uname,
    __NR_unshare as SYS_unshare,
    __NR_userfaultfd as SYS_userfaultfd,
    __NR_waitid as SYS_waitid,
    __NR_write as SYS_write,
    __NR_writev as SYS_writev,
    __user_cap_data_struct,
    __user_cap_header_struct,
    __WALL,
    _LINUX_CAPABILITY_VERSION_3,
    ARCH_GET_FS,
    ARCH_GET_GS,
    ARCH_SET_FS,
    ARCH_SET_GS,
    AT_EMPTY_PATH,
    AT_HWCAP2,
    AT_MINSIGSTKSZ,
    AT_NULL,
    AT_PAGESZ,
    AT_SYSINFO_EHDR,
    CLD_CONTINUED,
    CLD_DUMPED,
    CLD_EXITED,
    CLD_KILLED,
    CLD_STOPPED,
    CLD_TRAPPED,
    CLOCK_MONOTONIC_RAW,
    CLONE_CLEAR_SIGHAND,
    CLONE_NEWCGROUP,
    CLONE_NEWIPC,
    CLONE_NEWNET,
    CLONE_NEWNS,
    CLONE_NEWPID,
    CLONE_NEWUSER,
    CLONE_NEWUTS,
    CLONE_PIDFD,
    E2BIG,
    EACCES,
    EAGAIN,
    EBADF,
    EBUSY,
    ECHILD,
    EDOM,
    EEXIST,
    EFAULT,
    EFBIG,
    EINTR,
    EINVAL,
    EIO,
    EISDIR,
    EMFILE,
    EMLINK,
    ENFILE,
    ENODEV,
    ENOENT,
    ENOEXEC,
    ENOMEM,
    ENOSPC,
    ENOTBLK,
    ENOTDIR,
    ENOTTY,
    ENXIO,
    EOPNOTSUPP,
    EPERM,
    EPIPE,
    ERANGE,
    EROFS,
    ESPIPE,
    ESRCH,
    ETIMEDOUT,
    ETOOMANYREFS,
    ETXTBSY,
    EXDEV,
    ERESTARTSYS,
    F_ADD_SEALS,
    F_DUPFD,
    F_GETFD,
    F_SEAL_EXEC,
    F_SEAL_FUTURE_WRITE,
    F_SEAL_GROW,
    F_SEAL_SEAL,
    F_SEAL_SHRINK,
    F_SEAL_WRITE,
    F_SETFD,
    F_SETFL,
    F_SETOWN,
    F_SETSIG,
    FALLOC_FL_COLLAPSE_RANGE,
    FALLOC_FL_INSERT_RANGE,
    FALLOC_FL_KEEP_SIZE,
    FALLOC_FL_NO_HIDE_STALE,
    FALLOC_FL_PUNCH_HOLE,
    FALLOC_FL_UNSHARE_RANGE,
    FALLOC_FL_ZERO_RANGE,
    FUTEX_BITSET_MATCH_ANY,
    FUTEX_WAIT,
    FUTEX_WAKE,
    FUTEX2_SIZE_U32,
    io_cqring_offsets,
    io_sqring_offsets,
    io_uring_buf_reg,
    io_uring_buf_ring,
    io_uring_buf_status,
    io_uring_buf,
    io_uring_cqe,
    io_uring_file_index_range,
    io_uring_files_update,
    io_uring_getevents_arg,
    io_uring_napi,
    io_uring_op_IORING_OP_ACCEPT,
    io_uring_op_IORING_OP_ASYNC_CANCEL,
    io_uring_op_IORING_OP_CLOSE,
    io_uring_op_IORING_OP_CONNECT,
    io_uring_op_IORING_OP_EPOLL_CTL,
    io_uring_op_IORING_OP_FADVISE,
    io_uring_op_IORING_OP_FALLOCATE,
    io_uring_op_IORING_OP_FGETXATTR,
    io_uring_op_IORING_OP_FILES_UPDATE,
    io_uring_op_IORING_OP_FIXED_FD_INSTALL,
    io_uring_op_IORING_OP_FSETXATTR,
    io_uring_op_IORING_OP_FSYNC,
    io_uring_op_IORING_OP_FTRUNCATE,
    io_uring_op_IORING_OP_FUTEX_WAIT,
    io_uring_op_IORING_OP_FUTEX_WAITV,
    io_uring_op_IORING_OP_FUTEX_WAKE,
    io_uring_op_IORING_OP_GETXATTR,
    io_uring_op_IORING_OP_LAST,
    io_uring_op_IORING_OP_LINK_TIMEOUT,
    io_uring_op_IORING_OP_LINKAT,
    io_uring_op_IORING_OP_MADVISE,
    io_uring_op_IORING_OP_MKDIRAT,
    io_uring_op_IORING_OP_MSG_RING,
    io_uring_op_IORING_OP_NOP,
    io_uring_op_IORING_OP_OPENAT,
    io_uring_op_IORING_OP_OPENAT2,
    io_uring_op_IORING_OP_POLL_ADD,
    io_uring_op_IORING_OP_POLL_REMOVE,
    io_uring_op_IORING_OP_PROVIDE_BUFFERS,
    io_uring_op_IORING_OP_READ_FIXED,
    io_uring_op_IORING_OP_READ_MULTISHOT,
    io_uring_op_IORING_OP_READ,
    io_uring_op_IORING_OP_READV,
    io_uring_op_IORING_OP_RECV,
    io_uring_op_IORING_OP_RECVMSG,
    io_uring_op_IORING_OP_REMOVE_BUFFERS,
    io_uring_op_IORING_OP_RENAMEAT,
    io_uring_op_IORING_OP_SEND_ZC,
    io_uring_op_IORING_OP_SEND,
    io_uring_op_IORING_OP_SENDMSG_ZC,
    io_uring_op_IORING_OP_SENDMSG,
    io_uring_op_IORING_OP_SETXATTR,
    io_uring_op_IORING_OP_SHUTDOWN,
    io_uring_op_IORING_OP_SOCKET,
    io_uring_op_IORING_OP_SPLICE,
    io_uring_op_IORING_OP_STATX,
    io_uring_op_IORING_OP_SYMLINKAT,
    io_uring_op_IORING_OP_SYNC_FILE_RANGE,
    io_uring_op_IORING_OP_TEE,
    io_uring_op_IORING_OP_TIMEOUT_REMOVE,
    io_uring_op_IORING_OP_TIMEOUT,
    io_uring_op_IORING_OP_UNLINKAT,
    io_uring_op_IORING_OP_URING_CMD,
    io_uring_op_IORING_OP_WAITID,
    io_uring_op_IORING_OP_WRITE_FIXED,
    io_uring_op_IORING_OP_WRITE,
    io_uring_op_IORING_OP_WRITEV,
    io_uring_params,
    io_uring_probe_op,
    io_uring_probe,
    io_uring_recvmsg_out,
    io_uring_restriction,
    io_uring_rsrc_register,
    io_uring_rsrc_update,
    io_uring_rsrc_update2,
    io_uring_sqe,
    io_uring_sync_cancel_reg,
    IORING_ACCEPT_MULTISHOT,
    IORING_ASYNC_CANCEL_ALL,
    IORING_ASYNC_CANCEL_ANY,
    IORING_ASYNC_CANCEL_FD_FIXED,
    IORING_ASYNC_CANCEL_FD,
    IORING_ASYNC_CANCEL_OP,
    IORING_ASYNC_CANCEL_USERDATA,
    IORING_CQ_EVENTFD_DISABLED,
    IORING_CQE_BUFFER_SHIFT,
    IORING_CQE_F_BUFFER,
    IORING_CQE_F_MORE,
    IORING_CQE_F_NOTIF,
    IORING_CQE_F_SOCK_NONEMPTY,
    IORING_ENTER_EXT_ARG,
    IORING_ENTER_GETEVENTS,
    IORING_ENTER_REGISTERED_RING,
    IORING_ENTER_SQ_WAIT,
    IORING_ENTER_SQ_WAKEUP,
    IORING_FEAT_CQE_SKIP,
    IORING_FEAT_CUR_PERSONALITY,
    IORING_FEAT_EXT_ARG,
    IORING_FEAT_FAST_POLL,
    IORING_FEAT_LINKED_FILE,
    IORING_FEAT_NATIVE_WORKERS,
    IORING_FEAT_NODROP,
    IORING_FEAT_POLL_32BITS,
    IORING_FEAT_REG_REG_RING,
    IORING_FEAT_RSRC_TAGS,
    IORING_FEAT_RW_CUR_POS,
    IORING_FEAT_SINGLE_MMAP,
    IORING_FEAT_SQPOLL_NONFIXED,
    IORING_FEAT_SUBMIT_STABLE,
    IORING_FILE_INDEX_ALLOC,
    IORING_FIXED_FD_NO_CLOEXEC,
    IORING_FSYNC_DATASYNC,
    IORING_LINK_TIMEOUT_UPDATE,
    IORING_MSG_DATA,
    IORING_MSG_RING_CQE_SKIP,
    IORING_MSG_RING_FLAGS_PASS,
    IORING_MSG_SEND_FD,
    IORING_NOTIF_USAGE_ZC_COPIED,
    IORING_OFF_CQ_RING,
    IORING_OFF_MMAP_MASK,
    IORING_OFF_PBUF_RING,
    IORING_OFF_PBUF_SHIFT,
    IORING_OFF_SQ_RING,
    IORING_OFF_SQES,
    IORING_POLL_ADD_LEVEL,
    IORING_POLL_ADD_MULTI,
    IORING_POLL_UPDATE_EVENTS,
    IORING_POLL_UPDATE_USER_DATA,
    IORING_RECV_MULTISHOT,
    IORING_RECVSEND_FIXED_BUF,
    IORING_RECVSEND_POLL_FIRST,
    IORING_REGISTER_BUFFERS_UPDATE,
    IORING_REGISTER_BUFFERS,
    IORING_REGISTER_BUFFERS2,
    IORING_REGISTER_ENABLE_RINGS,
    IORING_REGISTER_EVENTFD_ASYNC,
    IORING_REGISTER_EVENTFD,
    IORING_REGISTER_FILE_ALLOC_RANGE,
    IORING_REGISTER_FILES_SKIP,
    IORING_REGISTER_FILES_UPDATE,
    IORING_REGISTER_FILES_UPDATE2,
    IORING_REGISTER_FILES,
    IORING_REGISTER_FILES2,
    IORING_REGISTER_IOWQ_AFF,
    IORING_REGISTER_IOWQ_MAX_WORKERS,
    IORING_REGISTER_LAST,
    IORING_REGISTER_NAPI,
    IORING_REGISTER_PBUF_RING,
    IORING_REGISTER_PBUF_STATUS,
    IORING_REGISTER_PERSONALITY,
    IORING_REGISTER_PROBE,
    IORING_REGISTER_RESTRICTIONS,
    IORING_REGISTER_RING_FDS,
    IORING_REGISTER_SYNC_CANCEL,
    IORING_REGISTER_USE_REGISTERED_RING,
    IORING_RESTRICTION_LAST,
    IORING_RESTRICTION_REGISTER_OP,
    IORING_RESTRICTION_SQE_FLAGS_ALLOWED,
    IORING_RESTRICTION_SQE_FLAGS_REQUIRED,
    IORING_RESTRICTION_SQE_OP,
    IORING_RSRC_REGISTER_SPARSE,
    IORING_SEND_ZC_REPORT_USAGE,
    IORING_SETUP_ATTACH_WQ,
    IORING_SETUP_CLAMP,
    IORING_SETUP_COOP_TASKRUN,
    IORING_SETUP_CQE32,
    IORING_SETUP_CQSIZE,
    IORING_SETUP_DEFER_TASKRUN,
    IORING_SETUP_IOPOLL,
    IORING_SETUP_NO_MMAP,
    IORING_SETUP_NO_SQARRAY,
    IORING_SETUP_R_DISABLED,
    IORING_SETUP_REGISTERED_FD_ONLY,
    IORING_SETUP_SINGLE_ISSUER,
    IORING_SETUP_SQ_AFF,
    IORING_SETUP_SQE128,
    IORING_SETUP_SQPOLL,
    IORING_SETUP_SUBMIT_ALL,
    IORING_SETUP_TASKRUN_FLAG,
    IORING_SQ_CQ_OVERFLOW,
    IORING_SQ_NEED_WAKEUP,
    IORING_SQ_TASKRUN,
    IORING_TIMEOUT_ABS,
    IORING_TIMEOUT_BOOTTIME,
    IORING_TIMEOUT_CLOCK_MASK,
    IORING_TIMEOUT_ETIME_SUCCESS,
    IORING_TIMEOUT_MULTISHOT,
    IORING_TIMEOUT_REALTIME,
    IORING_TIMEOUT_UPDATE_MASK,
    IORING_TIMEOUT_UPDATE,
    IORING_UNREGISTER_BUFFERS,
    IORING_UNREGISTER_EVENTFD,
    IORING_UNREGISTER_FILES,
    IORING_UNREGISTER_IOWQ_AFF,
    IORING_UNREGISTER_NAPI,
    IORING_UNREGISTER_PBUF_RING,
    IORING_UNREGISTER_PERSONALITY,
    IORING_UNREGISTER_RING_FDS,
    IORING_URING_CMD_FIXED,
    IORING_URING_CMD_MASK,
    IOSQE_ASYNC_BIT,
    IOSQE_BUFFER_SELECT_BIT,
    IOSQE_CQE_SKIP_SUCCESS_BIT,
    IOSQE_FIXED_FILE_BIT,
    IOSQE_IO_DRAIN_BIT,
    IOSQE_IO_HARDLINK_BIT,
    IOSQE_IO_LINK_BIT,
    iovec,
    linux_dirent64,
    MADV_COLD,
    MADV_COLLAPSE,
    MADV_DODUMP,
    MADV_DOFORK,
    MADV_DONTDUMP,
    MADV_DONTFORK,
    MADV_DONTNEED_LOCKED,
    MADV_DONTNEED,
    MADV_FREE,
    MADV_HUGEPAGE,
    MADV_HWPOISON,
    MADV_KEEPONFORK,
    MADV_MERGEABLE,
    MADV_NOHUGEPAGE,
    MADV_NORMAL,
    MADV_PAGEOUT,
    MADV_POPULATE_READ,
    MADV_POPULATE_WRITE,
    MADV_RANDOM,
    MADV_REMOVE,
    MADV_SEQUENTIAL,
    MADV_SOFT_OFFLINE,
    MADV_UNMERGEABLE,
    MADV_WILLNEED,
    MADV_WIPEONFORK,
    MAP_ANONYMOUS,
    MAP_FIXED,
    MAP_POPULATE,
    MAP_PRIVATE,
    MAP_SHARED,
    MFD_ALLOW_SEALING,
    MFD_CLOEXEC,
    MINSIGSTKSZ,
    MREMAP_FIXED,
    MREMAP_MAYMOVE,
    MS_BIND,
    MS_NODEV,
    MS_NOEXEC,
    MS_NOSUID,
    MS_PRIVATE,
    MS_RDONLY,
    MS_REC,
    new_utsname,
    O_CLOEXEC,
    O_DIRECTORY,
    O_NONBLOCK,
    O_PATH,
    O_RDONLY,
    O_RDWR,
    O_WRONLY,
    P_ALL,
    P_PGID,
    P_PID,
    P_PIDFD,
    PROT_EXEC,
    PROT_READ,
    PROT_WRITE,
    RLIMIT_DATA,
    RLIMIT_FSIZE,
    RLIMIT_LOCKS,
    RLIMIT_MEMLOCK,
    RLIMIT_MSGQUEUE,
    RLIMIT_NOFILE,
    RLIMIT_NPROC,
    RLIMIT_STACK,
    rlimit,
    rusage,
    SA_NODEFER,
    SA_ONSTACK,
    SA_RESTORER,
    SA_SIGINFO,
    SECCOMP_RET_ALLOW,
    SECCOMP_RET_ERRNO,
    SECCOMP_RET_KILL_THREAD,
    SECCOMP_SET_MODE_FILTER,
    SIG_BLOCK,
    SIG_SETMASK,
    SIG_UNBLOCK,
    SIGABRT,
    sigaction as kernel_sigaction,
    SIGBUS,
    SIGCHLD,
    SIGCONT,
    SIGFPE,
    SIGHUP,
    SIGILL,
    siginfo_t,
    SIGINT,
    SIGIO,
    SIGKILL,
    SIGPIPE,
    SIGSEGV,
    sigset_t as kernel_sigset_t,
    SIGSTOP,
    SIGSYS,
    SIGTERM,
    SIGTRAP,
    timespec,
    UFFD_EVENT_FORK,
    UFFD_EVENT_PAGEFAULT,
    UFFD_EVENT_REMAP,
    UFFD_EVENT_REMOVE,
    UFFD_EVENT_UNMAP,
    UFFD_FEATURE_EVENT_FORK,
    UFFD_FEATURE_EVENT_REMAP,
    UFFD_FEATURE_EVENT_REMOVE,
    UFFD_FEATURE_EVENT_UNMAP,
    UFFD_FEATURE_EXACT_ADDRESS,
    UFFD_FEATURE_MINOR_HUGETLBFS,
    UFFD_FEATURE_MINOR_SHMEM,
    UFFD_FEATURE_MISSING_HUGETLBFS,
    UFFD_FEATURE_MISSING_SHMEM,
    UFFD_FEATURE_MOVE,
    UFFD_FEATURE_PAGEFAULT_FLAG_WP,
    UFFD_FEATURE_POISON,
    UFFD_FEATURE_SIGBUS,
    UFFD_FEATURE_THREAD_ID,
    UFFD_FEATURE_WP_ASYNC,
    UFFD_FEATURE_WP_HUGETLBFS_SHMEM,
    UFFD_FEATURE_WP_UNPOPULATED,
    uffd_msg,
    UFFD_PAGEFAULT_FLAG_MINOR,
    UFFD_PAGEFAULT_FLAG_WP,
    UFFD_PAGEFAULT_FLAG_WRITE,
    UFFD_USER_MODE_ONLY,
    uffdio_api,
    uffdio_continue,
    uffdio_copy,
    uffdio_move,
    uffdio_poison,
    uffdio_range,
    uffdio_register,
    uffdio_writeprotect,
    uffdio_zeropage,
    WEXITED,
    WNOHANG,
};

// For some reason bindgen just refuses to emit these.
pub const UFFD_API: u64 = 0xaa;
pub const UFFDIO_REGISTER_MODE_MISSING: u64 = 1 << 0;
pub const UFFDIO_REGISTER_MODE_WP: u64 = 1 << 1;
pub const UFFDIO_REGISTER_MODE_MINOR: u64 = 1 << 2;
pub const UFFDIO_COPY_MODE_DONTWAKE: u64 = 1 << 0;
pub const UFFDIO_COPY_MODE_WP: u64 = 1 << 1;
pub const UFFDIO_ZEROPAGE_MODE_DONTWAKE: u64 = 1 << 0;
pub const UFFDIO_WRITEPROTECT_MODE_WP: u64 = 1 << 0;
pub const UFFDIO_WRITEPROTECT_MODE_DONTWAKE: u64 = 1 << 1;
pub const UFFDIO_CONTINUE_MODE_DONTWAKE: u64 = 1 << 0;
pub const UFFDIO_CONTINUE_MODE_WP: u64 = 1 << 1;

macro_rules! ioc {
    ($dir:expr, $type:expr, $nr:expr, $size:expr) => {
        ($dir << $crate::arch_bindings::_IOC_DIRSHIFT)
            | ($type << $crate::arch_bindings::_IOC_TYPESHIFT)
            | ($nr << $crate::arch_bindings::_IOC_NRSHIFT)
            | ($size << $crate::arch_bindings::_IOC_SIZESHIFT)
    };
}

macro_rules! ior {
    ($type:expr, $nr:expr, $size:ty) => {
        ioc!(
            $crate::arch_bindings::_IOC_READ,
            $type,
            $nr,
            core::mem::size_of::<$size>() as $crate::c_uint
        )
    };
}

macro_rules! iowr {
    ($type:expr, $nr:expr, $size:ty) => {
        ioc!(
            $crate::arch_bindings::_IOC_READ | $crate::arch_bindings::_IOC_WRITE,
            $type,
            $nr,
            core::mem::size_of::<$size>() as $crate::c_uint
        )
    };
}

use crate::arch_bindings::UFFDIO;

const UFFDIO_API: c_uint = iowr!(UFFDIO, crate::arch_bindings::_UFFDIO_API, uffdio_api);
const UFFDIO_REGISTER: c_uint = iowr!(UFFDIO, crate::arch_bindings::_UFFDIO_REGISTER, uffdio_register);
const UFFDIO_UNREGISTER: c_uint = ior!(UFFDIO, crate::arch_bindings::_UFFDIO_UNREGISTER, uffdio_range);
const UFFDIO_WAKE: c_uint = ior!(UFFDIO, crate::arch_bindings::_UFFDIO_WAKE, uffdio_range);
const UFFDIO_COPY: c_uint = iowr!(UFFDIO, crate::arch_bindings::_UFFDIO_COPY, uffdio_copy);
const UFFDIO_ZEROPAGE: c_uint = iowr!(UFFDIO, crate::arch_bindings::_UFFDIO_ZEROPAGE, uffdio_zeropage);
const UFFDIO_MOVE: c_uint = iowr!(UFFDIO, crate::arch_bindings::_UFFDIO_MOVE, uffdio_move);
const UFFDIO_WRITEPROTECT: c_uint = iowr!(UFFDIO, crate::arch_bindings::_UFFDIO_WRITEPROTECT, uffdio_writeprotect);
const UFFDIO_CONTINUE: c_uint = iowr!(UFFDIO, crate::arch_bindings::_UFFDIO_CONTINUE, uffdio_continue);
const UFFDIO_POISON: c_uint = iowr!(UFFDIO, crate::arch_bindings::_UFFDIO_POISON, uffdio_poison);

macro_rules! ioctl_wrapper {
    ($(
        ($name:ident, $command:ident, $struct:ident),
    )*) => {
        $(
            pub fn $name(fd: FdRef, arg: &mut $struct) -> Result<(), Error> {
                sys_ioctl(fd, $command, arg as *mut _ as c_ulong)?;
                Ok(())
            }
        )*
    }
}

ioctl_wrapper! {
    (sys_uffdio_api, UFFDIO_API, uffdio_api),
    (sys_uffdio_register, UFFDIO_REGISTER, uffdio_register),
    (sys_uffdio_unregister, UFFDIO_UNREGISTER, uffdio_range),
    (sys_uffdio_wake, UFFDIO_WAKE, uffdio_range),
    (sys_uffdio_copy, UFFDIO_COPY, uffdio_copy),
    (sys_uffdio_zeropage, UFFDIO_ZEROPAGE, uffdio_zeropage),
    (sys_uffdio_move, UFFDIO_MOVE, uffdio_move),
    (sys_uffdio_writeprotect, UFFDIO_WRITEPROTECT, uffdio_writeprotect),
    (sys_uffdio_continue, UFFDIO_CONTINUE, uffdio_continue),
    (sys_uffdio_poison, UFFDIO_POISON, uffdio_poison),
}

macro_rules! unsafe_impl_zeroed_default {
    ($(
        $name:ident,
    )*) => {
        $(
            impl Default for $name {
                #[inline]
                fn default() -> Self {
                    unsafe { core::mem::zeroed() }
                }
            }
        )*
    }
}

unsafe_impl_zeroed_default! {
    uffdio_api,
    uffdio_register,
    uffdio_range,
    uffdio_copy,
    uffdio_zeropage,
    uffdio_move,
    uffdio_writeprotect,
    uffdio_continue,
    uffdio_poison,
    uffd_msg,
    io_uring_params,
    io_uring_sqe,
}

impl siginfo_t {
    pub unsafe fn si_signo(&self) -> c_int {
        self.__bindgen_anon_1.__bindgen_anon_1.si_signo
    }

    pub unsafe fn si_code(&self) -> c_int {
        self.__bindgen_anon_1.__bindgen_anon_1.si_code
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
    (@op $labels:expr, $nth_instruction:expr, seccomp_return_error($errno:expr)) => { $crate::bpf!(@op $labels, $nth_instruction, return $crate::SECCOMP_RET_ERRNO | { let errno: u16 = $errno; errno as u32 }) };
    (@op $labels:expr, $nth_instruction:expr, seccomp_return_eperm) => { $crate::bpf!(@op $labels, $nth_instruction, seccomp_return_error($crate::EPERM as u16)) };
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
pub const SOCK_CLOEXEC: u32 = 0x80000;
pub const SOL_SOCKET: c_int = 1;
pub const SCM_RIGHTS: c_int = 1;
pub const MSG_NOSIGNAL: u32 = 0x4000;

pub const SEEK_SET: u32 = 0;
pub const SEEK_CUR: u32 = 1;
pub const SEEK_END: u32 = 2;

pub const O_ASYNC: u32 = 0x2000;

#[allow(non_snake_case)]
const fn CMSG_ALIGN(len: usize) -> usize {
    (len + core::mem::size_of::<usize>() - 1) & !(core::mem::size_of::<usize>() - 1)
}

#[allow(non_snake_case)]
pub unsafe fn CMSG_FIRSTHDR(mhdr: *const msghdr) -> *mut cmsghdr {
    if (*mhdr).msg_controllen >= core::mem::size_of::<cmsghdr>() {
        (*mhdr).msg_control.cast::<cmsghdr>()
    } else {
        core::ptr::null_mut()
    }
}

#[allow(non_snake_case)]
pub unsafe fn CMSG_DATA(cmsg: *mut cmsghdr) -> *mut c_uchar {
    cmsg.add(1).cast::<c_uchar>()
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

#[derive(Clone)]
pub struct Error {
    #[cfg(not(feature = "std"))]
    message: &'static str,
    #[cfg(feature = "std")]
    message: Cow<'static, str>,
    errno: c_int,
}

impl core::fmt::Debug for Error {
    #[cold]
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
        core::fmt::Display::fmt(self, fmt)
    }
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
            EOPNOTSUPP => Some("EOPNOTSUPP"),
            ETOOMANYREFS => Some("ETOOMANYREFS"),
            ERESTARTSYS => Some("ERESTARTSYS"),
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

        let fd = core::mem::replace(&mut self.0, -1);
        let result = unsafe { syscall_readonly!(SYS_close, fd) };
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

pub fn sys_uname() -> Result<new_utsname, Error> {
    let mut out: new_utsname = unsafe { core::mem::zeroed() };
    let result = unsafe { syscall!(SYS_uname, core::ptr::addr_of_mut!(out)) };
    Error::from_syscall("uname", result)?;
    Ok(out)
}

pub fn sys_io_uring_setup(entries: u32, params: &mut io_uring_params) -> Result<Fd, Error> {
    let fd = unsafe { syscall!(SYS_io_uring_setup, entries, params as *mut io_uring_params) };
    Error::from_syscall("io_uring_setup", fd)?;
    Ok(Fd::from_raw_unchecked(fd as c_int))
}

pub fn sys_io_uring_register(fd: FdRef, opcode: u32, arg: *const c_void, arg_count: u32) -> Result<(), Error> {
    let result = unsafe { syscall!(SYS_io_uring_register, fd, opcode, arg, arg_count) };
    Error::from_syscall("io_uring_register", result)?;
    Ok(())
}

pub unsafe fn sys_io_uring_enter(
    fd: FdRef,
    to_submit: u32,
    min_complete: u32,
    flags: u32,
    arg: *const c_void,
    argsz: usize,
) -> Result<u32, Error> {
    let result = unsafe { syscall!(SYS_io_uring_enter, fd, to_submit, min_complete, flags, arg, argsz) };
    Error::from_syscall("io_uring_enter", result)?;
    Ok(result as u32)
}

pub fn sys_ioctl(fd: FdRef, cmd: c_uint, arg: c_ulong) -> Result<c_int, Error> {
    let result = unsafe { syscall!(SYS_ioctl, fd, cmd, arg) };
    Error::from_syscall("ioctl", result)?;
    Ok(result as c_int)
}

pub fn sys_userfaultfd(flags: c_uint) -> Result<Fd, Error> {
    let fd = unsafe { syscall_readonly!(SYS_userfaultfd, flags) };
    Error::from_syscall("userfaultfd", fd)?;
    Ok(Fd::from_raw_unchecked(fd as c_int))
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

pub unsafe fn sys_arch_prctl_set_gs(value: usize) -> Result<(), Error> {
    let result = syscall_readonly!(SYS_arch_prctl, ARCH_SET_GS, value);
    Error::from_syscall("arch_prctl(ARCH_SET_GS)", result)?;
    Ok(())
}

pub fn sys_sched_yield() -> Result<(), Error> {
    // On Linux this always succeeds, although technically it could fail
    // due to a seccomp sandbox, so let's return an error anyway.
    let result = unsafe { syscall_readonly!(SYS_sched_yield) };
    Error::from_syscall("sched_yield", result)?;
    Ok(())
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

pub fn sys_fcntl(fd: FdRef, cmd: u32, arg: u32) -> Result<i32, Error> {
    let result = unsafe { syscall_readonly!(SYS_fcntl, fd, cmd, arg) };
    Error::from_syscall("fcntl", result)?;
    Ok(result as i32)
}

pub fn sys_fcntl_dupfd(fd: FdRef, min: c_int) -> Result<Fd, Error> {
    let fd = sys_fcntl(fd, F_DUPFD, min as u32)?;
    Ok(Fd::from_raw_unchecked(fd))
}

pub fn sys_close_range(first_fd: c_int, last_fd: c_int, flags: c_uint) -> Result<(), Error> {
    let result = unsafe { syscall_readonly!(SYS_close_range, first_fd, last_fd, flags) };
    Error::from_syscall("close_range", result)
}

pub fn sys_fallocate(fd: FdRef, mode: c_uint, offset: u64, length: u64) -> Result<(), Error> {
    let result = unsafe { syscall!(SYS_fallocate, fd, mode, offset, length) };
    Error::from_syscall("fallocate", result)
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

pub fn sys_lseek(fd: FdRef, offset: i64, whence: u32) -> Result<u64, Error> {
    let result = unsafe { syscall_readonly!(SYS_lseek, fd.raw(), offset, whence) };
    Error::from_syscall("lseek", result)?;
    Ok(result as u64)
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

pub unsafe fn sys_writev(fd: FdRef, iv: &[iovec]) -> Result<usize, Error> {
    let result = unsafe { syscall!(SYS_writev, fd, iv, iv.len()) };
    Error::from_syscall("writev", result)?;
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

pub fn sys_ptrace_interrupt(pid: pid_t) -> Result<(), Error> {
    let result = unsafe { syscall_readonly!(SYS_ptrace, crate::arch_bindings::PTRACE_INTERRUPT, pid, 0, 0) };
    Error::from_syscall("ptrace (PTRACE_INTERRUPT)", result)?;
    Ok(())
}

pub fn sys_ptrace_attach(pid: pid_t) -> Result<(), Error> {
    let result = unsafe { syscall_readonly!(SYS_ptrace, crate::arch_bindings::PTRACE_ATTACH, pid, 0, 0) };
    Error::from_syscall("ptrace (PTRACE_ATTACH)", result)?;
    Ok(())
}

pub fn sys_ptrace_seize(pid: pid_t) -> Result<(), Error> {
    let result = unsafe { syscall_readonly!(SYS_ptrace, crate::arch_bindings::PTRACE_SEIZE, pid, 0, 0) };
    Error::from_syscall("ptrace (PTRACE_SEIZE)", result)?;
    Ok(())
}

pub fn sys_ptrace_continue(pid: pid_t, signal: Option<u32>) -> Result<(), Error> {
    let result = unsafe { syscall_readonly!(SYS_ptrace, crate::arch_bindings::PTRACE_CONT, pid, 0, signal.unwrap_or(0)) };
    Error::from_syscall("ptrace (PTRACE_CONT)", result)?;
    Ok(())
}

pub fn sys_ptrace_detach(pid: pid_t) -> Result<(), Error> {
    let result = unsafe { syscall_readonly!(SYS_ptrace, crate::arch_bindings::PTRACE_DETACH, pid, 0, 0) };
    Error::from_syscall("ptrace (PTRACE_DETACH)", result)?;
    Ok(())
}

#[cfg(target_arch = "x86_64")]
#[repr(C)]
#[derive(Default, Debug)]
pub struct user_regs_struct {
    pub r15: c_ulong,
    pub r14: c_ulong,
    pub r13: c_ulong,
    pub r12: c_ulong,
    pub rbp: c_ulong,
    pub rbx: c_ulong,
    pub r11: c_ulong,
    pub r10: c_ulong,
    pub r9: c_ulong,
    pub r8: c_ulong,
    pub rax: c_ulong,
    pub rcx: c_ulong,
    pub rdx: c_ulong,
    pub rsi: c_ulong,
    pub rdi: c_ulong,
    pub orig_rax: c_ulong,
    pub rip: c_ulong,
    pub cs: c_ulong,
    pub flags: c_ulong,
    pub sp: c_ulong,
    pub ss: c_ulong,
    pub fs_base: c_ulong,
    pub gs_base: c_ulong,
    pub ds: c_ulong,
    pub es: c_ulong,
    pub fs: c_ulong,
    pub gs: c_ulong,
}

pub fn sys_ptrace_getregs(pid: pid_t) -> Result<user_regs_struct, Error> {
    let mut output: MaybeUninit<user_regs_struct> = MaybeUninit::uninit();
    let result = unsafe { syscall!(SYS_ptrace, crate::arch_bindings::PTRACE_GETREGS, pid, 0, output.as_mut_ptr()) };
    Error::from_syscall("ptrace (PTRACE_GETREGS)", result)?;

    unsafe { Ok(output.assume_init()) }
}

pub fn sys_ptrace_setregs(pid: pid_t, regs: &user_regs_struct) -> Result<(), Error> {
    let regs: *const user_regs_struct = regs;
    let result = unsafe { syscall_readonly!(SYS_ptrace, crate::arch_bindings::PTRACE_SETREGS, pid, 0, regs) };
    Error::from_syscall("ptrace (PTRACE_SETREGS)", result)?;
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

pub fn sys_prctl_set_dumpable(value: bool) -> Result<(), Error> {
    const PR_SET_DUMPABLE: usize = 4;
    let value = usize::from(value);
    let result = unsafe { syscall_readonly!(SYS_prctl, PR_SET_DUMPABLE, value, 0, 0, 0) };
    Error::from_syscall("prctl(PR_SET_DUMPABLE)", result)
}

pub fn sys_prctl_get_dumpable() -> Result<bool, Error> {
    const PR_GET_DUMPABLE: usize = 3;
    let result = unsafe { syscall_readonly!(SYS_prctl, PR_GET_DUMPABLE, 0, 0, 0, 0) };
    Error::from_syscall("prctl(PR_GET_DUMPABLE)", result)?;
    if result == 0 {
        Ok(false)
    } else {
        Ok(true)
    }
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

    let result = unsafe { syscall_readonly!(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, core::ptr::addr_of!(filter)) };
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
            data.map_or(core::ptr::null(), |data| data.as_ptr())
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

/// Calls the `futex` syscall with `FUTEX_WAIT` operation.
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
            ts.as_ref().map_or(core::ptr::null(), |ts| ts as *const timespec)
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
            old_action.map_or(core::ptr::null_mut(), |old_action| old_action as *mut kernel_sigaction),
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
            old_sigset.map_or(core::ptr::null_mut(), |old_sigset| old_sigset as *mut kernel_sigset_t),
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
            old_stack.map_or(core::ptr::null_mut(), |old_stack| old_stack as *mut stack_t)
        )
    };
    Error::from_syscall("sigaltstack", result)?;
    Ok(())
}

pub fn sys_clock_gettime(clock_id: u32) -> Result<Duration, Error> {
    let mut output = timespec { tv_sec: 0, tv_nsec: 0 };
    let result = unsafe { syscall_readonly!(SYS_clock_gettime, clock_id, core::ptr::addr_of_mut!(output)) };
    Error::from_syscall("clock_gettime", result)?;

    let duration = Duration::new(output.tv_sec as u64, output.tv_nsec as u32);
    Ok(duration)
}

pub fn sys_nanosleep(duration: Duration) -> Result<Option<Duration>, Error> {
    let duration = timespec {
        tv_sec: duration.as_secs() as i64,
        tv_nsec: u64::from(duration.subsec_nanos()) as i64,
    };

    let mut remaining = timespec { tv_sec: 0, tv_nsec: 0 };
    let result = unsafe { syscall_readonly!(SYS_nanosleep, core::ptr::addr_of!(duration), core::ptr::addr_of_mut!(remaining)) };
    let error = Error::from_syscall("nanosleep", result);
    if let Err(error) = error {
        if error.errno() == EINTR {
            let remaining = Duration::new(remaining.tv_sec as u64, remaining.tv_nsec as u32);
            Ok(Some(remaining))
        } else {
            Err(error)
        }
    } else {
        Ok(None)
    }
}

pub fn sys_waitid(which: u32, pid: pid_t, info: &mut siginfo_t, options: u32, usage: Option<&mut rusage>) -> Result<(), Error> {
    let result = unsafe {
        syscall_readonly!(
            SYS_waitid,
            which,
            pid,
            info as *mut siginfo_t,
            options,
            usage.map_or(core::ptr::null_mut(), |usage| usage as *mut rusage)
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
        iov_base: slice.as_ptr().cast_mut().cast(),
        iov_len: slice.len() as u64,
    });
    let remote_iovec = remote.map(|(address, length)| iovec {
        iov_base: address as *mut c_void,
        iov_len: length as u64,
    });
    unsafe { sys_process_vm_writev(pid, &local_iovec, &remote_iovec) }
}

pub fn writev<const N: usize>(fd: FdRef, list: [&[u8]; N]) -> Result<usize, Error> {
    let iv = list.map(|slice| iovec {
        iov_base: slice.as_ptr().cast_mut().cast(),
        iov_len: slice.len() as u64,
    });
    unsafe { sys_writev(fd, &iv) }
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
pub struct Dirent64<'a> {
    raw: linux_dirent64,
    _lifetime: core::marker::PhantomData<&'a [u8]>,
}

impl<'a> Dirent64<'a> {
    pub fn d_type(&self) -> c_uchar {
        self.raw.d_type
    }

    pub fn d_name(&self) -> &'a [u8] {
        unsafe {
            let name = self.raw.d_name.as_ptr();
            let length = {
                let mut p = self.raw.d_name.as_ptr();
                while *p != 0 {
                    p = p.add(1);
                }

                p as usize - name as usize
            };

            core::slice::from_raw_parts(name.cast(), length)
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
    type Item = Result<Dirent64<'a>, Error>;
    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.position < self.bytes_available {
                let dirent = unsafe { core::ptr::read_unaligned(self.buffer.as_ptr().add(self.position).cast::<Dirent64>()) };

                self.position += usize::from(dirent.raw.d_reclen);
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
        iov_base: core::ptr::addr_of_mut!(dummy).cast::<c_void>(),
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

    #[allow(clippy::cast_ptr_alignment)]
    unsafe {
        core::ptr::write_unaligned(CMSG_FIRSTHDR(&header), control_header);
        core::ptr::write_unaligned(CMSG_DATA(buffer.as_mut_ptr().cast::<cmsghdr>()).cast::<c_int>(), fd.raw());
    }

    header.msg_controllen = CMSG_LEN(core::mem::size_of::<c_int>());
    sys_sendmsg(socket, &header, MSG_NOSIGNAL)?;

    Ok(())
}

pub fn recvfd(socket: FdRef) -> Result<Fd, Error> {
    let mut dummy: c_int = 0;
    let mut buffer = [0; CMSG_SPACE(core::mem::size_of::<c_int>())];

    let mut iov = iovec {
        iov_base: core::ptr::addr_of_mut!(dummy).cast::<c_void>(),
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
    if count == 0 {
        return Err(Error::from_str("recvfd failed: received zero bytes"));
    }

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

    let fd = unsafe { core::ptr::read_unaligned(CMSG_DATA(control_header).cast::<c_int>()) };

    Ok(Fd::from_raw_unchecked(fd))
}
