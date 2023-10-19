#![allow(clippy::undocumented_unsafe_blocks)]
#![allow(clippy::manual_range_contains)]

extern crate polkavm_linux_raw as linux_raw;

use polkavm_common::{
    error::{ExecutionError, Trap},
    program::Reg,
    utils::{align_to_next_page_usize, slice_assume_init_mut, Access, AsUninitSliceMut},
    zygote::{
        SandboxMemoryConfig, VmCtx, SANDBOX_EMPTY_NATIVE_PROGRAM_COUNTER, SANDBOX_EMPTY_NTH_INSTRUCTION, VMCTX_FUTEX_BUSY,
        VMCTX_FUTEX_HOSTCALL, VMCTX_FUTEX_IDLE, VMCTX_FUTEX_INIT, VMCTX_FUTEX_TRAP, VM_ADDR_NATIVE_CODE,
    },
};

use super::ExecuteArgs;

pub use linux_raw::Error;

use core::ffi::{c_int, c_uint};
use core::sync::atomic::Ordering;
use linux_raw::{abort, cstr, syscall_readonly, Fd, Mmap, STDERR_FILENO, STDIN_FILENO};
use std::time::Instant;
use std::sync::Arc;

use super::{OnHostcall, SandboxKind, SandboxProgramInit, get_native_page_size};
use crate::api::{BackendAccess, MemoryAccessError};

pub struct SandboxConfig {
    enable_logger: bool,
}

impl SandboxConfig {
    pub fn new() -> Self {
        SandboxConfig { enable_logger: false }
    }
}

impl super::SandboxConfig for SandboxConfig {
    fn enable_logger(&mut self, value: bool) {
        self.enable_logger = value;
    }
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self::new()
    }
}

#[repr(C)]
struct CloneArgs {
    /// Flags.
    flags: u64,
    /// Where to store PID file descriptor. (int *)
    pidfd: *mut c_int,
    /// Where to store child TID in child's memory. (pid_t *)
    child_tid: u64,
    /// Where to store child TID in parent's memory. (pid_t *)
    parent_tid: u64,
    /// Signal to deliver to parent on child termination.
    exit_signal: u64,
    /// Pointer to lowest byte of stack.
    stack: u64,
    /// Size of the stack.
    stack_size: u64,
    /// Location of the new TLS.
    tls: u64,
}

/// Closes all file descriptors except the ones given.
fn close_other_file_descriptors(preserved_fds: &[c_int]) -> Result<(), Error> {
    let mut start_at = 0;
    for &fd in preserved_fds {
        if start_at == fd {
            start_at = fd + 1;
            continue;
        }

        if start_at > fd {
            // Preserved file descriptors must be sorted.
            return Err(Error::from_str("internal error: preserved file descriptors are not sorted"));
        }

        if linux_raw::sys_close_range(start_at, fd - 1, 0).is_err() {
            return close_other_file_descriptors_legacy(preserved_fds);
        }

        start_at = fd + 1;
    }

    if linux_raw::sys_close_range(start_at, c_int::MAX, 0).is_err() {
        return close_other_file_descriptors_legacy(preserved_fds);
    }

    Ok(())
}

/// Closes all file descriptors except the ones given.
///
/// For compatibility with old versions of Linux.
fn close_other_file_descriptors_legacy(preserved_fds: &[c_int]) -> Result<(), Error> {
    let dirfd = linux_raw::sys_open(
        cstr!("/proc/self/fd"),
        linux_raw::O_RDONLY | linux_raw::O_DIRECTORY | linux_raw::O_CLOEXEC,
    )?;
    for dirent in linux_raw::readdir(dirfd.borrow()) {
        let dirent = dirent?;
        let name = dirent.d_name();
        if !name.iter().all(|&byte| byte >= b'0' && byte <= b'9') {
            continue;
        }

        let name = core::str::from_utf8(name)
            .ok()
            .ok_or_else(|| Error::from_str("entry in '/proc/self/fd' is not valid utf-8"))?;
        let fd: c_int = name
            .parse()
            .ok()
            .ok_or_else(|| Error::from_str("entry in '/proc/self/fd' is not a number"))?;
        if fd == dirfd.raw() || preserved_fds.iter().any(|&pfd| pfd == fd) {
            continue;
        }

        Fd::from_raw_unchecked(fd).close()?;
    }

    dirfd.close()?;
    Ok(())
}

struct Sigmask {
    sigset_original: linux_raw::kernel_sigset_t,
}

impl Sigmask {
    /// Temporarily blocks all signals from being delivered.
    fn block_all_signals() -> Result<Self, Error> {
        let sigset_all: linux_raw::kernel_sigset_t = !0;
        let mut sigset_original: linux_raw::kernel_sigset_t = 0;
        unsafe { linux_raw::sys_rt_sigprocmask(linux_raw::SIG_SETMASK, &sigset_all, Some(&mut sigset_original))? };

        Ok(Sigmask { sigset_original })
    }

    /// Unblocks signal delivery.
    fn unblock(mut self) -> Result<(), Error> {
        let result = self.unblock_inplace();
        core::mem::forget(self);
        result
    }

    /// Unblocks signal delivery.
    fn unblock_inplace(&mut self) -> Result<(), Error> {
        unsafe { linux_raw::sys_rt_sigprocmask(linux_raw::SIG_SETMASK, &self.sigset_original, None) }
    }
}

impl Drop for Sigmask {
    fn drop(&mut self) {
        let _ = self.unblock_inplace();
    }
}

#[derive(Debug)]
struct ChildProcess {
    pid: c_int,
    pidfd: Option<Fd>,
}

#[derive(Debug)]
enum ChildStatus {
    Running,
    NotRunning,
    Exited(c_int),
    ExitedDueToSignal(c_int),
}

impl ChildStatus {
    pub fn is_running(&self) -> bool {
        matches!(self, Self::Running)
    }
}

impl ChildProcess {
    fn waitid(&mut self, flags: u32) -> Result<linux_raw::siginfo_t, Error> {
        let mut siginfo: linux_raw::siginfo_t = unsafe { core::mem::zeroed() };
        let mut result;
        loop {
            result = if let Some(ref pidfd) = self.pidfd {
                linux_raw::sys_waitid(linux_raw::P_PIDFD, pidfd.raw(), &mut siginfo, flags, None)
            } else {
                linux_raw::sys_waitid(linux_raw::P_PID, self.pid, &mut siginfo, flags, None)
            };

            if let Err(error) = result {
                if error.errno() == linux_raw::EINTR {
                    // Should not happen since we should be blocking all signals while this is called, but just in case.
                    continue;
                }

                return Err(error);
            }

            return Ok(siginfo);
        }
    }

    fn check_status(&mut self, non_blocking: bool) -> Result<ChildStatus, Error> {
        // The __WALL here is needed since we're not specifying an exit signal
        // when cloning the child process, so we'd get an ECHILD error without this flag.
        //
        // (And we're not using __WCLONE since that doesn't work for children which ran execve.)
        let mut flags = linux_raw::WEXITED | linux_raw::__WALL;
        if non_blocking {
            flags |= linux_raw::WNOHANG;
        }

        match self.waitid(flags) {
            Ok(ok) => unsafe {
                if ok.si_signo() == 0 && ok.si_pid() == 0 {
                    Ok(ChildStatus::Running)
                } else if linux_raw::WIFSIGNALED(ok.si_status()) {
                    Ok(ChildStatus::ExitedDueToSignal(linux_raw::WTERMSIG(ok.si_status())))
                } else if linux_raw::WIFEXITED(ok.si_status()) {
                    Ok(ChildStatus::Exited(linux_raw::WEXITSTATUS(ok.si_status())))
                } else {
                    Err(Error::from_last_os_error("waitid failed: internal error: unexpected state"))
                }
            },
            Err(error) => {
                if error.errno() == linux_raw::ECHILD {
                    Ok(ChildStatus::NotRunning)
                } else {
                    Err(error)
                }
            }
        }
    }

    fn send_signal(&mut self, signal: c_uint) -> Result<(), Error> {
        unsafe {
            if let Some(ref pidfd) = self.pidfd {
                let errcode = syscall_readonly!(linux_raw::SYS_pidfd_send_signal, pidfd, signal, 0, 0);
                Error::from_syscall("pidfd_send_signal", errcode)
            } else {
                linux_raw::sys_kill(self.pid, signal)
            }
        }
    }
}

impl Drop for ChildProcess {
    fn drop(&mut self) {
        if self.send_signal(linux_raw::SIGKILL).is_ok() {
            // Reap the zombie process.
            let _ = self.check_status(false);
        }
    }
}

#[cfg(polkavm_dev_use_built_zygote)]
static ZYGOTE_BLOB: &[u8] = include_bytes!("../../polkavm-zygote/target/x86_64-unknown-linux-gnu/release/polkavm-zygote");

#[cfg(not(polkavm_dev_use_built_zygote))]
static ZYGOTE_BLOB: &[u8] = include_bytes!("./polkavm-zygote");

fn prepare_sealed_memfd(name: &core::ffi::CStr, length: usize, populate: impl FnOnce(&mut [u8])) -> Result<Fd, Error> {
    let native_page_size = get_native_page_size();
    if length % native_page_size != 0 {
        return Err(Error::from_str("memfd size doesn't end on a page boundary"));
    }

    let memfd = linux_raw::sys_memfd_create(name, linux_raw::MFD_CLOEXEC | linux_raw::MFD_ALLOW_SEALING)?;
    linux_raw::sys_ftruncate(memfd.borrow(), length as linux_raw::c_ulong)?;

    let mut map = unsafe {
        linux_raw::Mmap::map(
            core::ptr::null_mut(),
            length,
            linux_raw::PROT_READ | linux_raw::PROT_WRITE,
            linux_raw::MAP_SHARED,
            Some(memfd.borrow()),
            0,
        )?
    };

    populate(map.as_slice_mut());
    map.unmap()?;

    let timestamp = linux_raw::sys_clock_gettime(linux_raw::CLOCK_MONOTONIC_RAW)?;
    loop {
        if let Err(error) = linux_raw::sys_fcntl(
            memfd.borrow(),
            linux_raw::F_ADD_SEALS,
            linux_raw::F_SEAL_SEAL | linux_raw::F_SEAL_SHRINK | linux_raw::F_SEAL_GROW | linux_raw::F_SEAL_WRITE,
        ) {
            if error.errno() == linux_raw::EBUSY {
                // This will return EBUSY if the fd is still mapped, and since apparently munmap is asynchronous in the presence
                // of multiple threads this can still sometimes randomly fail with EBUSY anyway, even though we did unmap the fd already.
                let elapsed = linux_raw::sys_clock_gettime(linux_raw::CLOCK_MONOTONIC_RAW)? - timestamp;
                if elapsed > core::time::Duration::from_secs(3) {
                    // Just a fail-safe to make sure we don't deadlock.
                    return Err(error);
                }

                continue;
            } else {
                return Err(error);
            }
        }

        break;
    }

    Ok(memfd)
}

fn prepare_zygote() -> Result<Fd, Error> {
    let native_page_size = get_native_page_size();

    #[allow(clippy::unwrap_used)]
    // The size of the zygote blob is always going to be much less than the size of usize, so this never fails.
    let length_aligned = align_to_next_page_usize(native_page_size, ZYGOTE_BLOB.len()).unwrap();

    prepare_sealed_memfd(cstr!("polkavm_zygote"), length_aligned, |buffer| {
        buffer[..ZYGOTE_BLOB.len()].copy_from_slice(ZYGOTE_BLOB);
    })
}

fn prepare_vmctx() -> Result<(Fd, Mmap), Error> {
    let native_page_size = get_native_page_size();

    #[allow(clippy::unwrap_used)] // The size of VmCtx is always going to be much less than the size of usize, so this never fails.
    let length_aligned = align_to_next_page_usize(native_page_size, core::mem::size_of::<VmCtx>()).unwrap();

    let memfd = linux_raw::sys_memfd_create(cstr!("polkavm_vmctx"), linux_raw::MFD_CLOEXEC | linux_raw::MFD_ALLOW_SEALING)?;
    linux_raw::sys_ftruncate(memfd.borrow(), length_aligned as linux_raw::c_ulong)?;
    linux_raw::sys_fcntl(
        memfd.borrow(),
        linux_raw::F_ADD_SEALS,
        linux_raw::F_SEAL_SEAL | linux_raw::F_SEAL_SHRINK | linux_raw::F_SEAL_GROW,
    )?;

    let vmctx = unsafe {
        linux_raw::Mmap::map(
            core::ptr::null_mut(),
            length_aligned,
            linux_raw::PROT_READ | linux_raw::PROT_WRITE,
            linux_raw::MAP_SHARED,
            Some(memfd.borrow()),
            0,
        )?
    };

    unsafe {
        *vmctx.as_mut_ptr().cast::<VmCtx>() = VmCtx::new();
    }

    Ok((memfd, vmctx))
}

unsafe fn child_main(zygote_memfd: Fd, child_socket: Fd, uid_map: &str, gid_map: &str, logging_pipe: Option<Fd>) -> Result<(), Error> {
    // Change the name of the process.
    linux_raw::sys_prctl_set_name(b"polkavm-sandbox\0")?;

    // Overwrite the hostname and domainname.
    linux_raw::sys_sethostname("localhost")?;
    linux_raw::sys_setdomainname("localhost")?;

    // Disable the 'setgroups' syscall. Probably unnecessary since we'll do it though seccomp anyway, but just in case.
    // (See CVE-2014-8989 for more details.)
    let proc_self = linux_raw::sys_open(cstr!("/proc/self"), linux_raw::O_CLOEXEC | linux_raw::O_PATH)?;
    let fd = linux_raw::sys_openat(proc_self.borrow(), cstr!("setgroups"), linux_raw::O_CLOEXEC | linux_raw::O_WRONLY)?;
    linux_raw::sys_write(fd.borrow(), b"deny")?;
    fd.close()?;

    // Set up UID and GID maps. This can only be done once, so if we do it here we'll block the possibility of doing it later.
    let fd = linux_raw::sys_openat(proc_self.borrow(), cstr!("gid_map"), linux_raw::O_CLOEXEC | linux_raw::O_RDWR)?;
    linux_raw::sys_write(fd.borrow(), gid_map.as_bytes())?;
    fd.close()?;

    let fd = linux_raw::sys_openat(proc_self.borrow(), cstr!("uid_map"), linux_raw::O_CLOEXEC | linux_raw::O_RDWR)?;
    linux_raw::sys_write(fd.borrow(), uid_map.as_bytes())?;
    fd.close()?;
    proc_self.close()?;

    // This should never happen in practice, but can in theory if the user closes stdin or stderr manually.
    // TODO: Actually support this?
    for fd in [zygote_memfd.raw(), child_socket.raw()].into_iter().chain(logging_pipe.as_ref().map(|fd| fd.raw())) {
        if fd == STDIN_FILENO {
            return Err(Error::from_str("internal error: fd overlaps with stdin"));
        }

        if fd == STDERR_FILENO {
            return Err(Error::from_str("internal error: fd overlaps with stderr"));
        }
    }

    // Replace the stdin fd (which we don't need).
    linux_raw::sys_dup3(child_socket.raw(), STDIN_FILENO, 0)?;
    child_socket.close()?;

    // Clean up any file descriptors which might have been opened by the host process.
    let mut fds_to_keep = [core::ffi::c_int::MAX; 3];
    let fds_to_keep = {
        let mut index = 1;
        fds_to_keep[0] = STDIN_FILENO;
        if let Some(logging_pipe) = logging_pipe {
            linux_raw::sys_dup3(logging_pipe.raw(), STDERR_FILENO, 0)?;
            logging_pipe.close()?;
            fds_to_keep[index] = STDERR_FILENO;
            index += 1;
        }

        fds_to_keep[index] = zygote_memfd.raw();
        fds_to_keep.sort_unstable(); // Should be a no-op.
        &fds_to_keep[..index + 1]
    };
    close_other_file_descriptors(fds_to_keep)?;

    // Hide the host filesystem.
    let mount_flags = linux_raw::MS_REC | linux_raw::MS_NODEV | linux_raw::MS_NOEXEC | linux_raw::MS_NOSUID | linux_raw::MS_RDONLY;
    linux_raw::sys_mount(cstr!("none"), cstr!("/mnt"), cstr!("tmpfs"), mount_flags, Some(cstr!("size=0")))?;
    linux_raw::sys_chdir(cstr!("/mnt"))?;
    linux_raw::sys_pivot_root(cstr!("."), cstr!("."))?;
    linux_raw::sys_umount2(cstr!("."), linux_raw::MNT_DETACH)?;

    // Clear all of our ambient capabilities.
    linux_raw::sys_prctl_cap_ambient_clear_all()?;

    // Flag ourselves that we won't ever want to acquire any new privileges.
    linux_raw::sys_prctl_set_no_new_privs()?;

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
    )?;

    // Set resource limits.
    let max_memory = 8 * 1024 * 1024 * 1024;
    linux_raw::sys_setrlimit(
        linux_raw::RLIMIT_DATA,
        &linux_raw::rlimit {
            rlim_cur: max_memory,
            rlim_max: max_memory,
        },
    )?;
    linux_raw::sys_setrlimit(
        linux_raw::RLIMIT_STACK,
        &linux_raw::rlimit {
            rlim_cur: 16 * 1024,
            rlim_max: 16 * 1024,
        },
    )?;
    linux_raw::sys_setrlimit(linux_raw::RLIMIT_NOFILE, &linux_raw::rlimit { rlim_cur: 8, rlim_max: 8 })?;
    linux_raw::sys_setrlimit(linux_raw::RLIMIT_NPROC, &linux_raw::rlimit { rlim_cur: 1, rlim_max: 1 })?;
    linux_raw::sys_setrlimit(linux_raw::RLIMIT_FSIZE, &linux_raw::rlimit { rlim_cur: 0, rlim_max: 0 })?;
    linux_raw::sys_setrlimit(linux_raw::RLIMIT_LOCKS, &linux_raw::rlimit { rlim_cur: 0, rlim_max: 0 })?;
    linux_raw::sys_setrlimit(linux_raw::RLIMIT_MEMLOCK, &linux_raw::rlimit { rlim_cur: 0, rlim_max: 0 })?;
    linux_raw::sys_setrlimit(linux_raw::RLIMIT_MSGQUEUE, &linux_raw::rlimit { rlim_cur: 0, rlim_max: 0 })?;

    // Finally, drop all capabilities.
    linux_raw::sys_capset_drop_all()?;

    let child_argv: [*const u8; 2] = [b"polkavm-zygote\0".as_ptr(), core::ptr::null()];
    let child_envp: [*const u8; 1] = [core::ptr::null()];
    linux_raw::sys_execveat(
        Some(zygote_memfd.borrow()),
        cstr!(""),
        &child_argv,
        &child_envp,
        linux_raw::AT_EMPTY_PATH,
    )?;

    // This should never happen, but since the never type is still unstable let's return normally.
    Ok(())
}

#[derive(Clone)]
pub struct SandboxProgram(Arc<SandboxProgramInner>);

struct SandboxProgramInner {
    memfd: Fd,
    memory_config: SandboxMemoryConfig,
    sysreturn_address: u64,
}

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct Map<'a> {
    pub start: u64,
    pub end: u64,
    pub is_readable: bool,
    pub is_writable: bool,
    pub is_executable: bool,
    pub is_shared: bool,
    pub file_offset: u64,
    pub major: u64,
    pub minor: u64,
    pub inode: u64,
    pub name: &'a [u8],
}

fn parse_u64_radix(input: &[u8], radix: u32) -> Option<u64> {
    u64::from_str_radix(core::str::from_utf8(input).ok()?, radix).ok()
}

fn get_until<'a>(p: &mut &'a [u8], delimiter: u8) -> &'a [u8] {
    let mut found = None;
    for (index, ch) in p.iter().enumerate() {
        if *ch == delimiter {
            found = Some(index);
            break;
        }
    }

    if let Some(index) = found {
        let (before, after) = p.split_at(index);
        *p = &after[1..];
        before
    } else {
        let before = *p;
        *p = b"";
        before
    }
}

fn get_char(p: &mut &[u8]) -> Option<u8> {
    let ch = p.first()?;
    *p = &p[1..];
    Some(*ch)
}

fn skip_whitespace(p: &mut &[u8]) {
    while let Some(ch) = p.first() {
        if *ch == b' ' {
            *p = &p[1..];
        } else {
            break;
        }
    }
}

impl<'a> Map<'a> {
    fn parse(mut line: &'a [u8]) -> Option<Self> {
        let start = parse_u64_radix(get_until(&mut line, b'-'), 16)?;
        let end = parse_u64_radix(get_until(&mut line, b' '), 16)?;
        let is_readable = get_char(&mut line)? == b'r';
        let is_writable = get_char(&mut line)? == b'w';
        let is_executable = get_char(&mut line)? == b'x';
        let is_shared = get_char(&mut line)? == b's';
        get_char(&mut line);

        let file_offset = parse_u64_radix(get_until(&mut line, b' '), 16)?;
        let major = parse_u64_radix(get_until(&mut line, b':'), 16)?;
        let minor = parse_u64_radix(get_until(&mut line, b' '), 16)?;
        let inode = parse_u64_radix(get_until(&mut line, b' '), 10)?;
        skip_whitespace(&mut line);
        let name = line;

        Some(Map {
            start,
            end,
            is_readable,
            is_writable,
            is_executable,
            is_shared,
            file_offset,
            major,
            minor,
            inode,
            name,
        })
    }
}

fn get_message(vmctx: &VmCtx) -> Option<String> {
    let message = unsafe {
        let message_length = *vmctx.message_length.get() as usize;
        let message = &*vmctx.message_buffer.get();
        &message[..core::cmp::min(message_length, message.len())]
    };

    if message.is_empty() {
        return None;
    }

    // The message is in shared memory, so clone it first to make sure
    // it doesn't change under us and violate string's invariants.
    let message = message.to_vec();
    match String::from_utf8(message) {
        Ok(message) => Some(message),
        Err(error) => {
            let message = error.into_bytes();
            Some(String::from_utf8_lossy(&message).into_owned())
        }
    }
}

unsafe fn set_message(vmctx: &VmCtx, message: core::fmt::Arguments) {
    struct Adapter<'a>(std::io::Cursor<&'a mut [u8]>);
    impl<'a> core::fmt::Write for Adapter<'a> {
        fn write_str(&mut self, string: &str) -> Result<(), core::fmt::Error> {
            use std::io::Write;
            self.0.write_all(string.as_bytes()).map_err(|_| core::fmt::Error)
        }
    }

    let buffer: &mut [u8] = &mut *vmctx.message_buffer.get();
    let mut cursor = Adapter(std::io::Cursor::new(buffer));
    let _ = core::fmt::write(&mut cursor, message);
    let length = cursor.0.position() as usize;

    *vmctx.message_length.get() = length as u32;
}

pub struct Sandbox {
    vmctx_mmap: Mmap,
    child: ChildProcess,
    socket: Fd,

    count_wait_loop_start: u64,
    count_futex_wait: u64,
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let vmctx = self.vmctx();
        let child_futex_wait = unsafe { *vmctx.counters.syscall_futex_wait.get() };
        let child_loop_start = unsafe { *vmctx.counters.syscall_wait_loop_start.get() };
        log::debug!(
            "Host futex wait count: {}/{} ({:.02}%)",
            self.count_futex_wait,
            self.count_wait_loop_start,
            self.count_futex_wait as f64 / self.count_wait_loop_start as f64 * 100.0
        );
        log::debug!(
            "Child futex wait count: {}/{} ({:.02}%)",
            child_futex_wait,
            child_loop_start,
            child_futex_wait as f64 / child_loop_start as f64 * 100.0
        );
    }
}

impl super::SandboxAddressSpace for () {
    fn native_code_address(&self) -> u64 {
        VM_ADDR_NATIVE_CODE
    }
}

impl super::Sandbox for Sandbox {
    const KIND: SandboxKind = SandboxKind::Linux;

    type Access<'r> = SandboxAccess<'r>;
    type Config = SandboxConfig;
    type Error = Error;
    type Program = SandboxProgram;
    type AddressSpace = ();

    fn reserve_address_space() -> Result<Self::AddressSpace, Self::Error> {
        Ok(())
    }

    fn prepare_program(init: SandboxProgramInit, _: Self::AddressSpace) -> Result<Self::Program, Self::Error> {
        let native_page_size = get_native_page_size();
        let cfg = init.memory_config(native_page_size)?;
        let memfd = prepare_sealed_memfd(
            cstr!("polkavm_program"),
            cfg.ro_data_size() as usize + cfg.rw_data_size() as usize + cfg.code_size() + cfg.jump_table_size(),
            |buffer| {
                let mut offset = 0;
                macro_rules! append {
                    ($slice:expr, $length:expr) => {
                        assert!($slice.len() <= $length as usize);
                        buffer[offset..offset + $slice.len()].copy_from_slice($slice);
                        #[allow(unused_assignments)]
                        {
                            offset += $length as usize;
                        }
                    };
                }

                append!(init.ro_data(), cfg.ro_data_size());
                append!(init.rw_data(), cfg.rw_data_size());
                append!(init.code, cfg.code_size());
                append!(init.jump_table, cfg.jump_table_size());
            },
        )?;

        Ok(SandboxProgram(Arc::new(SandboxProgramInner {
            memfd,
            memory_config: cfg,
            sysreturn_address: init.sysreturn_address,
        })))
    }

    fn spawn(config: &SandboxConfig) -> Result<Self, Error> {
        let sigset = Sigmask::block_all_signals()?;
        let zygote_memfd = prepare_zygote()?;
        let (vmctx_memfd, vmctx_mmap) = prepare_vmctx()?;
        let (socket, child_socket) = linux_raw::sys_socketpair(linux_raw::AF_UNIX, linux_raw::SOCK_SEQPACKET | linux_raw::SOCK_CLOEXEC, 0)?;

        let sandbox_flags = linux_raw::CLONE_NEWCGROUP as u64
            | linux_raw::CLONE_NEWIPC as u64
            | linux_raw::CLONE_NEWNET as u64
            | linux_raw::CLONE_NEWNS as u64
            | linux_raw::CLONE_NEWPID as u64
            | linux_raw::CLONE_NEWUSER as u64
            | linux_raw::CLONE_NEWUTS as u64;

        let mut pidfd: c_int = -1;
        let args = CloneArgs {
            flags: linux_raw::CLONE_CLEAR_SIGHAND | linux_raw::CLONE_PIDFD as u64 | sandbox_flags,
            pidfd: &mut pidfd,
            child_tid: 0,
            parent_tid: 0,
            exit_signal: 0,
            stack: 0,
            stack_size: 0,
            tls: 0,
        };

        let uid = linux_raw::sys_getuid()?;
        let gid = linux_raw::sys_getgid()?;

        let uid_map = format!("0 {} 1\n", uid);
        let gid_map = format!("0 {} 1\n", gid);

        let (logger_rx, logger_tx) = if config.enable_logger {
            let (rx, tx) = linux_raw::sys_pipe2(linux_raw::O_CLOEXEC)?;
            (Some(rx), Some(tx))
        } else {
            (None, None)
        };

        // Fork a new process.
        let mut child_pid =
            unsafe { linux_raw::syscall!(linux_raw::SYS_clone3, &args as *const CloneArgs, core::mem::size_of::<CloneArgs>()) };

        if child_pid < 0 {
            // Fallback for Linux versions older than 5.5.
            let error = Error::from_last_os_error("clone");
            child_pid = unsafe { linux_raw::syscall!(linux_raw::SYS_clone, sandbox_flags, 0, 0, 0, 0) };

            if child_pid < 0 {
                return Err(error);
            }
        }

        if child_pid == 0 {
            // We're in the child.
            //
            // Calling into libc from here risks a deadlock as other threads might have
            // been holding onto internal libc locks while we were cloning ourselves,
            // so from now on we can't use anything from libc anymore.
            core::mem::forget(sigset);

            unsafe {
                match child_main(zygote_memfd, child_socket, &uid_map, &gid_map, logger_tx) {
                    Ok(()) => {
                        // This is impossible.
                        abort();
                    }
                    Err(error) => {
                        let vmctx = &*vmctx_mmap.as_ptr().cast::<VmCtx>();
                        set_message(vmctx, format_args!("fatal error while spawning child: {error}"));

                        abort();
                    }
                }
            }
        }

        if let Some(logger_rx) = logger_rx {
            // Hook up the child process' STDERR to our logger.
            std::thread::Builder::new()
                .name("polkavm-logger".into())
                .spawn(move || {
                    let mut tmp = [0; 4096];
                    let mut buffer = Vec::new();
                    loop {
                        if buffer.len() > 8192 {
                            // Make sure the child can't exhaust our memory by spamming logs.
                            buffer.clear();
                        }

                        match linux_raw::sys_read(logger_rx.borrow(), &mut tmp) {
                            Err(error) if error.errno() == linux_raw::EINTR => continue,
                            Err(error) => {
                                log::warn!("Failed to read from logger: {}", error);
                                break;
                            }
                            Ok(0) => break,
                            Ok(count) => {
                                let mut tmp = &tmp[..count];
                                while !tmp.is_empty() {
                                    if let Some(index) = tmp.iter().position(|&byte| byte == b'\n') {
                                        buffer.extend_from_slice(&tmp[..index]);
                                        tmp = &tmp[index + 1..];

                                        log::trace!(target: "polkavm_zygote", "Child #{}: {}", child_pid, String::from_utf8_lossy(&buffer));
                                        buffer.clear();
                                    } else {
                                        buffer.extend_from_slice(tmp);
                                        break;
                                    }
                                }
                            }
                        }
                    }
                })
                .map_err(|error| Error::from_os_error("failed to spawn logger thread", error))?;
        }

        let mut child = ChildProcess {
            pid: child_pid as c_int,
            pidfd: if pidfd < 0 { None } else { Some(Fd::from_raw_unchecked(pidfd)) },
        };

        // We're in the parent. Restore the signal mask.
        child_socket.close()?;
        sigset.unblock()?;

        fn wait_for_futex(vmctx: &VmCtx, child: &mut ChildProcess, current_state: u32, target_state: u32) -> Result<(), Error> {
            let instant = Instant::now();
            loop {
                let state = vmctx.futex.load(Ordering::Relaxed);
                if state == target_state {
                    return Ok(());
                }

                if state != current_state {
                    return Err(Error::from_str("failed to initialize sandbox process: unexpected futex state"));
                }

                if !child.check_status(true)?.is_running() {
                    let message = get_message(vmctx);
                    if let Some(message) = message {
                        let error = Error::from(format!("failed to initialize sandbox process: {}", message));
                        return Err(error);
                    } else {
                        return Err(Error::from_str(
                            "failed to initialize sandbox process: child process unexpectedly quit",
                        ));
                    }
                }

                if instant.elapsed() > core::time::Duration::from_secs(10) {
                    // This should never happen, but just in case.
                    return Err(Error::from_str("failed to initialize sandbox process: initialization timeout"));
                }

                match linux_raw::sys_futex_wait(&vmctx.futex, state, Some(core::time::Duration::from_millis(100))) {
                    Ok(()) => continue,
                    Err(error)
                        if error.errno() == linux_raw::EAGAIN
                            || error.errno() == linux_raw::EINTR
                            || error.errno() == linux_raw::ETIMEDOUT =>
                    {
                        continue
                    }
                    Err(error) => return Err(error),
                }
            }
        }

        let vmctx = unsafe { &*vmctx_mmap.as_ptr().cast::<VmCtx>() };

        // Send the vmctx memfd to the child process.
        if let Err(error) = linux_raw::sendfd(socket.borrow(), vmctx_memfd.borrow()) {
            let message = get_message(vmctx);
            if let Some(message) = message {
                let error = Error::from(format!("failed to initialize sandbox process: {error} (root cause: {message})"));
                return Err(error);
            }

            return Err(error);
        }

        // Wait until the child process receives the vmctx memfd.
        wait_for_futex(vmctx, &mut child, VMCTX_FUTEX_BUSY, VMCTX_FUTEX_INIT)?;

        // Grab the child process' maps and see what we can unmap.
        //
        // The child process can't do it itself as it's too sandboxed.
        let maps = std::fs::read(format!("/proc/{}/maps", child_pid))
            .map_err(|error| Error::from_errno("failed to read child's maps", error.raw_os_error().unwrap_or(0)))?;

        for line in maps.split(|&byte| byte == b'\n') {
            if line.is_empty() {
                continue;
            }

            let map = Map::parse(line).ok_or_else(|| Error::from_str("failed to parse the maps of the child process"))?;
            match map.name {
                b"[stack]" => {
                    vmctx.init.stack_address.store(map.start, Ordering::Relaxed);
                    vmctx.init.stack_length.store(map.end - map.start, Ordering::Relaxed);
                }
                b"[vdso]" => {
                    vmctx.init.vdso_address.store(map.start, Ordering::Relaxed);
                    vmctx.init.vdso_length.store(map.end - map.start, Ordering::Relaxed);
                }
                b"[vvar]" => {
                    vmctx.init.vvar_address.store(map.start, Ordering::Relaxed);
                    vmctx.init.vvar_length.store(map.end - map.start, Ordering::Relaxed);
                }
                b"[vsyscall]" => {
                    if map.is_readable {
                        return Err(Error::from_str("failed to initialize sandbox process: vsyscall region is readable"));
                    }
                }
                _ => {}
            }
        }

        // Wake the child so that it finishes initialization.
        vmctx.futex.store(VMCTX_FUTEX_BUSY, Ordering::Release);
        linux_raw::sys_futex_wake_one(&vmctx.futex)?;

        // Wait for the child to finish initialization.
        wait_for_futex(vmctx, &mut child, VMCTX_FUTEX_BUSY, VMCTX_FUTEX_IDLE)?;

        Ok(Sandbox {
            vmctx_mmap,
            child,
            socket,

            count_wait_loop_start: 0,
            count_futex_wait: 0,
        })
    }

    fn execute(&mut self, mut args: ExecuteArgs<Self>) -> Result<(), ExecutionError<Error>> {
        self.wait_if_necessary(match args.on_hostcall {
            Some(ref mut on_hostcall) => Some(&mut *on_hostcall),
            None => None,
        })?;

        unsafe {
            *self.vmctx().rpc_address.get() = args.rpc_address;
            *self.vmctx().rpc_flags.get() = args.rpc_flags;
            if let Some(program) = args.program {
                *self.vmctx().new_memory_config.get() = program.0.memory_config;
                *self.vmctx().new_sysreturn_address.get() = program.0.sysreturn_address;
            }

            (*self.vmctx().regs().get()).copy_from_slice(args.initial_regs);
            self.vmctx().futex.store(VMCTX_FUTEX_BUSY, Ordering::Release);
            linux_raw::sys_futex_wake_one(&self.vmctx().futex)?;

            if let Some(program) = args.program {
                // TODO: This can block forever.
                linux_raw::sendfd(self.socket.borrow(), program.0.memfd.borrow())?;
            }
        }

        self.wait_if_necessary(args.on_hostcall)?;
        Ok(())
    }

    #[inline]
    fn access(&mut self) -> SandboxAccess {
        SandboxAccess { sandbox: self }
    }
}

impl Sandbox {
    #[inline]
    fn vmctx(&self) -> &VmCtx {
        unsafe { &*self.vmctx_mmap.as_ptr().cast::<VmCtx>() }
    }

    #[inline(never)]
    #[cold]
    fn wait(&mut self, mut on_hostcall: Option<OnHostcall<Self>>) -> Result<(), ExecutionError<Error>> {
        let mut spin_target = 0;
        'outer: loop {
            self.count_wait_loop_start += 1;

            let state = self.vmctx().futex.load(Ordering::Relaxed);
            if state == VMCTX_FUTEX_IDLE {
                core::sync::atomic::fence(Ordering::Acquire);
                return Ok(());
            }

            if state == VMCTX_FUTEX_TRAP {
                core::sync::atomic::fence(Ordering::Acquire);

                self.vmctx().futex.store(VMCTX_FUTEX_BUSY, Ordering::Release);
                linux_raw::sys_futex_wake_one(&self.vmctx().futex)?;

                return Err(ExecutionError::Trap(Trap::default()));
            }

            if state == VMCTX_FUTEX_HOSTCALL {
                core::sync::atomic::fence(Ordering::Acquire);

                let on_hostcall = match on_hostcall {
                    Some(ref mut on_hostcall) => &mut *on_hostcall,
                    None => {
                        unsafe {
                            *self.vmctx().hostcall().get() = polkavm_common::zygote::HOSTCALL_ABORT_EXECUTION;
                        }
                        self.vmctx().futex.store(VMCTX_FUTEX_BUSY, Ordering::Release);
                        linux_raw::sys_futex_wake_one(&self.vmctx().futex)?;

                        return Err(Error::from_str("hostcall called without any hostcall handler set").into());
                    }
                };

                let hostcall = unsafe { *self.vmctx().hostcall().get() };
                if hostcall == polkavm_common::zygote::HOSTCALL_TRACE {
                    // When tracing aggressively spin to avoid having to call into the kernel.
                    spin_target = 512;
                }

                match on_hostcall(hostcall, super::Sandbox::access(self)) {
                    Ok(()) => {
                        self.vmctx().futex.store(VMCTX_FUTEX_BUSY, Ordering::Release);
                        linux_raw::sys_futex_wake_one(&self.vmctx().futex)?;
                        continue;
                    }
                    Err(trap) => {
                        unsafe {
                            *self.vmctx().hostcall().get() = polkavm_common::zygote::HOSTCALL_ABORT_EXECUTION;
                        }
                        self.vmctx().futex.store(VMCTX_FUTEX_BUSY, Ordering::Release);
                        linux_raw::sys_futex_wake_one(&self.vmctx().futex)?;

                        return Err(ExecutionError::Trap(trap));
                    }
                }
            }

            if state != VMCTX_FUTEX_BUSY {
                return Err(Error::from_str("internal error: unexpected worker process state").into());
            }

            for _ in 0..spin_target {
                core::hint::spin_loop();
                if self.vmctx().futex.load(Ordering::Relaxed) != VMCTX_FUTEX_BUSY {
                    continue 'outer;
                }
            }

            self.count_futex_wait += 1;
            match linux_raw::sys_futex_wait(&self.vmctx().futex, VMCTX_FUTEX_BUSY, Some(core::time::Duration::from_millis(100))) {
                Ok(()) => continue,
                Err(error) if error.errno() == linux_raw::EAGAIN || error.errno() == linux_raw::EINTR => continue,
                Err(error) if error.errno() == linux_raw::ETIMEDOUT => {
                    log::trace!("Timeout expired while waiting for child #{}...", self.child.pid);
                    let status = self.child.check_status(true)?;
                    if !status.is_running() {
                        log::trace!("Child #{} is not running anymore!", self.child.pid);
                        let message = get_message(self.vmctx());
                        if let Some(message) = message {
                            return Err(Error::from(message).into());
                        } else {
                            return Err(Error::from_str("worker process unexpectedly quit").into());
                        }
                    }
                }
                Err(error) => return Err(error.into()),
            }
        }
    }

    #[inline]
    fn wait_if_necessary(&mut self, on_hostcall: Option<OnHostcall<Self>>) -> Result<(), ExecutionError<Error>> {
        if self.vmctx().futex.load(Ordering::Relaxed) != VMCTX_FUTEX_IDLE {
            self.wait(on_hostcall)?;
        }

        Ok(())
    }
}

pub struct SandboxAccess<'a> {
    sandbox: &'a mut Sandbox,
}

impl<'a> From<SandboxAccess<'a>> for BackendAccess<'a> {
    fn from(access: SandboxAccess<'a>) -> Self {
        BackendAccess::CompiledLinux(access)
    }
}

impl<'a> Access<'a> for SandboxAccess<'a> {
    type Error = MemoryAccessError<linux_raw::Error>;

    fn get_reg(&self, reg: Reg) -> u32 {
        if reg == Reg::Zero {
            return 0;
        }

        let regs = unsafe { &*self.sandbox.vmctx().regs().get() };

        regs[reg as usize - 1]
    }

    fn set_reg(&mut self, reg: Reg, value: u32) {
        if reg == Reg::Zero {
            return;
        }

        unsafe {
            (*self.sandbox.vmctx().regs().get())[reg as usize - 1] = value;
        }
    }

    fn read_memory_into_slice<'slice, T>(&self, address: u32, buffer: &'slice mut T) -> Result<&'slice mut [u8], Self::Error>
    where
        T: ?Sized + AsUninitSliceMut,
    {
        let slice = buffer.as_uninit_slice_mut();
        log::trace!(
            "Reading memory: 0x{:x}-0x{:x} ({} bytes)",
            address,
            address as usize + slice.len(),
            slice.len()
        );

        if address as usize + slice.len() > 0xffffffff {
            return Err(MemoryAccessError {
                address,
                length: slice.len() as u64,
                error: Error::from_str("out of range read"),
            });
        }

        let length = slice.len();
        match linux_raw::vm_read_memory(self.sandbox.child.pid, [slice], [(address as usize, length)]) {
            Ok(actual_length) if actual_length == length => {
                unsafe { Ok(slice_assume_init_mut(slice)) }
            },
            Ok(_) => {
                Err(MemoryAccessError {
                    address,
                    length: slice.len() as u64,
                    error: Error::from_str("incomplete read"),
                })
            },
            Err(error) => {
                Err(MemoryAccessError {
                    address,
                    length: slice.len() as u64,
                    error,
                })
            }
        }
    }

    fn write_memory(&mut self, address: u32, data: &[u8]) -> Result<(), Self::Error> {
        log::trace!(
            "Writing memory: 0x{:x}-0x{:x} ({} bytes)",
            address,
            address as usize + data.len(),
            data.len()
        );

        if address as usize + data.len() > 0xffffffff {
            return Err(MemoryAccessError {
                address,
                length: data.len() as u64,
                error: Error::from_str("out of range write"),
            });
        }

        let length = data.len();
        match linux_raw::vm_write_memory(self.sandbox.child.pid, [data], [(address as usize, length)]) {
            Ok(actual_length) if actual_length == length => {
                Ok(())
            },
            Ok(_) => {
                Err(MemoryAccessError {
                    address,
                    length: data.len() as u64,
                    error: Error::from_str("incomplete write"),
                })
            },
            Err(error) => {
                Err(MemoryAccessError {
                    address,
                    length: data.len() as u64,
                    error,
                })
            }
        }
    }

    fn program_counter(&self) -> Option<u32> {
        let value = unsafe { *self.sandbox.vmctx().nth_instruction().get() };

        if value == SANDBOX_EMPTY_NTH_INSTRUCTION {
            None
        } else {
            Some(value)
        }
    }

    fn native_program_counter(&self) -> Option<u64> {
        let value = unsafe { *self.sandbox.vmctx().rip().get() };

        if value == SANDBOX_EMPTY_NATIVE_PROGRAM_COUNTER {
            None
        } else {
            Some(value)
        }
    }
}
