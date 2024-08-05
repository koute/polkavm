#![allow(clippy::undocumented_unsafe_blocks)]
#![allow(clippy::manual_range_contains)]

extern crate polkavm_linux_raw as linux_raw;

use polkavm_common::{
    error::{ExecutionError, Trap},
    program::Reg,
    utils::{align_to_next_page_usize, slice_assume_init_mut, Access, AsUninitSliceMut, Gas},
    zygote::{
        AddressTable, AddressTablePacked,
        VmCtx, VmMap, SANDBOX_EMPTY_NATIVE_PROGRAM_COUNTER, SANDBOX_EMPTY_NTH_INSTRUCTION, VMCTX_FUTEX_BUSY,
        VMCTX_FUTEX_HOSTCALL, VMCTX_FUTEX_IDLE, VMCTX_FUTEX_INIT, VMCTX_FUTEX_TRAP, VM_ADDR_NATIVE_CODE,
    },
};

use super::ExecuteArgs;

pub use linux_raw::Error;

use core::ffi::{c_int, c_uint};
use core::sync::atomic::Ordering;
use core::time::Duration;
use linux_raw::{abort, cstr, syscall_readonly, Fd, Mmap, STDERR_FILENO, STDIN_FILENO};
use std::borrow::Cow;
use std::time::Instant;
use std::sync::Arc;

use super::{SandboxKind, SandboxInit, get_native_page_size, WorkerCache, WorkerCacheKind};
use crate::api::{BackendAccess, CompiledModuleKind, MemoryAccessError, Module, HostcallHandler};
use crate::config::Config;
use crate::compiler::CompiledModule;
use crate::config::GasMeteringKind;
use crate::shm_allocator::{ShmAllocator, ShmAllocation};

pub struct GlobalState {
    shared_memory: ShmAllocator,
    is_sandboxing_enabled: bool,
}

impl GlobalState {
    pub fn new(config: &Config) -> Result<Self, Error> {
        let is_sandboxing_enabled = GlobalState::is_sandboxing_supported();
        if !config.allow_insecure && !is_sandboxing_enabled  {
            return Err(Error::from_str("Sandboxing is not supported on your system. You can enable set_allow_insecure/POLKAVM_ALLOW_INSECURE to run with reduced sandboxing, if you know what you're doing"));
        }

        Ok(GlobalState {
            shared_memory: ShmAllocator::new()?,
            is_sandboxing_enabled,
        })
    }

    fn is_sandboxing_supported() -> bool {
        let child_pid = unsafe { linux_raw::syscall!(linux_raw::SYS_clone, SANDBOX_FLAGS, 0, 0, 0, 0) };
        if child_pid < 0 {
            return false;
        }

        if !cfg!(polkavm_dev_debug_zygote) {
            // Overwrite the hostname and domainname.
            match linux_raw::sys_sethostname("localhost") {
                Ok(()) => {},
                Err(error) => {
                    log::trace!("Failed to call sys_sethostname: {}", error);
                    return false
                },
            }
        }
        true
    }
}

const SANDBOX_FLAGS: u32 = linux_raw::CLONE_NEWCGROUP
    | linux_raw::CLONE_NEWIPC
    | linux_raw::CLONE_NEWNET
    | linux_raw::CLONE_NEWNS
    | linux_raw::CLONE_NEWPID
    | linux_raw::CLONE_NEWUSER
    | linux_raw::CLONE_NEWUTS;

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

struct Signal(c_int);
impl core::fmt::Display for Signal {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
        let name = match self.0 as u32 {
            linux_raw::SIGABRT => "SIGABRT",
            linux_raw::SIGBUS => "SIGBUS",
            linux_raw::SIGCHLD => "SIGCHLD",
            linux_raw::SIGCONT => "SIGCONT",
            linux_raw::SIGFPE => "SIGFPE",
            linux_raw::SIGHUP => "SIGHUP",
            linux_raw::SIGILL => "SIGILL",
            linux_raw::SIGINT => "SIGINT",
            linux_raw::SIGKILL => "SIGKILL",
            linux_raw::SIGPIPE => "SIGPIPE",
            linux_raw::SIGSEGV => "SIGSEGV",
            linux_raw::SIGSTOP => "SIGSTOP",
            linux_raw::SIGSYS => "SIGSYS",
            linux_raw::SIGTERM => "SIGTERM",
            linux_raw::SIGTRAP => "SIGTRAP",
            _ => return write!(fmt, "{}", self.0)
        };

        fmt.write_str(name)
    }
}

impl core::fmt::Display for ChildStatus {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            ChildStatus::Running => fmt.write_str("running"),
            ChildStatus::NotRunning => fmt.write_str("not running"),
            ChildStatus::Exited(code) => write!(fmt, "exited (status = {code})"),
            ChildStatus::ExitedDueToSignal(signum) => write!(fmt, "exited due to signal (signal = {})", Signal(*signum)),
        }
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
                } else if ok.si_signo() as u32 == linux_raw::SIGCHLD && ok.si_code() as u32 == linux_raw::CLD_EXITED {
                    Ok(ChildStatus::Exited(ok.si_status()))
                } else if ok.si_signo() as u32 == linux_raw::SIGCHLD && (ok.si_code() as u32 == linux_raw::CLD_KILLED || ok.si_code() as u32 == linux_raw::CLD_DUMPED) {
                    Ok(ChildStatus::ExitedDueToSignal(linux_raw::WTERMSIG(ok.si_status())))
                } else if ok.si_signo() as u32 == linux_raw::SIGCHLD && ok.si_code() as u32 == linux_raw::CLD_STOPPED {
                    Err(Error::from_last_os_error("waitid failed: unexpected CLD_STOPPED status"))
                } else if ok.si_signo() as u32 == linux_raw::SIGCHLD && ok.si_code() as u32 == linux_raw::CLD_TRAPPED {
                    Err(Error::from_last_os_error("waitid failed: unexpected CLD_TRAPPED status"))
                } else if ok.si_signo() as u32 == linux_raw::SIGCHLD && ok.si_code() as u32 == linux_raw::CLD_CONTINUED {
                    Err(Error::from_last_os_error("waitid failed: unexpected CLD_CONTINUED status"))
                } else if ok.si_signo() != 0 {
                    Ok(ChildStatus::ExitedDueToSignal(ok.si_signo()))
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
        #[cfg(polkavm_dev_debug_zygote)]
        let _ = self.send_signal(linux_raw::SIGINT);

        #[cfg(not(polkavm_dev_debug_zygote))]
        if self.send_signal(linux_raw::SIGKILL).is_ok() {
            // Reap the zombie process.
            let _ = self.check_status(false);
        }
    }
}

const ZYGOTE_BLOB_CONST: &[u8] = include_bytes!("./polkavm-zygote");
static ZYGOTE_BLOB: &[u8] = ZYGOTE_BLOB_CONST;

// Here we extract the necessary addresses directly from the zygote binary at compile time.
const ZYGOTE_ADDRESS_TABLE: AddressTable = {
    const fn starts_with(haystack: &[u8], needle: &[u8]) -> bool {
        if haystack.len() < needle.len() {
            return false;
        }

        let mut index = 0;
        while index < needle.len() {
            if haystack[index] != needle[index] {
                return false;
            }
            index += 1;
        }

        true
    }

    const fn cast_slice<T>(slice: &[u8]) -> &T where T: Copy {
        assert!(slice.len() >= core::mem::size_of::<T>());
        assert!(core::mem::align_of::<T>() == 1);

        // SAFETY: The size and alignment requirements of `T` were `assert`ed,
        //         and it's `Copy` so it's guaranteed not to drop, so this is always safe.
        unsafe {
            &*slice.as_ptr().cast::<T>()
        }
    }

    #[repr(C)]
    #[derive(Copy, Clone)]
    struct U16([u8; 2]);

    impl U16 {
        const fn get(self) -> u16 {
            u16::from_ne_bytes(self.0)
        }
    }

    #[repr(C)]
    #[derive(Copy, Clone)]
    struct U32([u8; 4]);

    impl U32 {
        const fn get(self) -> u32 {
            u32::from_ne_bytes(self.0)
        }
    }

    #[repr(C)]
    #[derive(Copy, Clone)]
    struct U64([u8; 8]);

    impl U64 {
        const fn get(self) -> u64 {
            u64::from_ne_bytes(self.0)
        }
    }

    #[repr(C)]
    #[derive(Copy, Clone)]
    struct ElfIdent {
        magic: [u8; 4],
        class: u8,
        data: u8,
        version: u8,
        os_abi: u8,
        abi_version: u8,
        padding: [u8; 7],
    }

    #[repr(C)]
    #[derive(Copy, Clone)]
    struct ElfHeader {
        e_ident: ElfIdent,
        e_type: U16,
        e_machine: U16,
        e_version: U32,
        e_entry: U64,
        e_phoff: U64,
        e_shoff: U64,
        e_flags: U32,
        e_ehsize: U16,
        e_phentsize: U16,
        e_phnum: U16,
        e_shentsize: U16,
        e_shnum: U16,
        e_shstrndx: U16,
    }

    #[repr(C)]
    #[derive(Copy, Clone)]
    struct ElfSectionHeader {
        sh_name: U32,
        sh_type: U32,
        sh_flags: U64,
        sh_addr: U64,
        sh_offset: U64,
        sh_size: U64,
        sh_link: U32,
        sh_info: U32,
        sh_addralign: U64,
        sh_entsize: U64,
    }

    impl ElfHeader {
        const fn section_header<'a>(&self, blob: &'a [u8], nth_section: u16) -> &'a ElfSectionHeader {
            let size = self.e_shentsize.get() as usize;
            assert!(size == core::mem::size_of::<ElfSectionHeader>());

            let offset = self.e_shoff.get() as usize + nth_section as usize * size;
            cast_slice(blob.split_at(offset).1)
        }
    }

    impl ElfSectionHeader {
        const fn data<'a>(&self, blob: &'a [u8]) -> &'a [u8] {
            blob.split_at(self.sh_offset.get() as usize).1.split_at(self.sh_size.get() as usize).0
        }
    }

    let header: &ElfHeader = cast_slice(ZYGOTE_BLOB_CONST);
    let shstr = header.section_header(ZYGOTE_BLOB_CONST, header.e_shstrndx.get()).data(ZYGOTE_BLOB_CONST);

    let mut address_table = None;
    let mut nth_section = 0;
    while nth_section < header.e_shnum.get() {
        let section_header = header.section_header(ZYGOTE_BLOB_CONST, nth_section);
        if starts_with(shstr.split_at(section_header.sh_name.get() as usize).1, b".address_table") {
            let data = section_header.data(ZYGOTE_BLOB_CONST);
            assert!(data.len() == core::mem::size_of::<AddressTablePacked>());
            address_table = Some(AddressTable::from_packed(cast_slice::<AddressTablePacked>(data)));
            break;
        }
        nth_section += 1;
    }

    let Some(address_table) = address_table else { panic!("broken zygote binary") };
    address_table
};

fn create_empty_memfd(name: &core::ffi::CStr) -> Result<Fd, Error> {
    linux_raw::sys_memfd_create(name, linux_raw::MFD_CLOEXEC | linux_raw::MFD_ALLOW_SEALING)
}

fn prepare_sealed_memfd<const N: usize>(memfd: Fd, length: usize, data: [&[u8]; N]) -> Result<Fd, Error> {
    let native_page_size = get_native_page_size();
    if length % native_page_size != 0 {
        return Err(Error::from_str("memfd size doesn't end on a page boundary"));
    }

    linux_raw::sys_ftruncate(memfd.borrow(), length as linux_raw::c_ulong)?;

    let expected_bytes_written = data.iter().map(|slice| slice.len()).sum::<usize>();
    let bytes_written = linux_raw::writev(memfd.borrow(), data)?;
    if bytes_written != expected_bytes_written {
        return Err(Error::from_str("failed to prepare memfd: incomplete write"));
    }

    linux_raw::sys_fcntl(
        memfd.borrow(),
        linux_raw::F_ADD_SEALS,
        linux_raw::F_SEAL_SEAL | linux_raw::F_SEAL_SHRINK | linux_raw::F_SEAL_GROW | linux_raw::F_SEAL_WRITE,
    )?;

    Ok(memfd)
}

fn prepare_zygote() -> Result<Fd, Error> {
    #[cfg(debug_assertions)]
    if cfg!(polkavm_dev_debug_zygote) {
        let paths = [
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../polkavm-zygote/target/x86_64-unknown-linux-gnu/debug/polkavm-zygote"),
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../polkavm-zygote/target/x86_64-unknown-linux-gnu/release/polkavm-zygote"),
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/sandbox/polkavm-zygote"),
            std::path::PathBuf::from("./polkavm-zygote"),
        ];

        let Some(path) = paths.into_iter().find(|path| {
            path.exists() && std::fs::read(path).map(|data| data == ZYGOTE_BLOB).unwrap_or(false)
        }) else {
            panic!("no matching zygote binary found for debugging");
        };

        let path = std::ffi::CString::new(path.to_str().expect("invalid path to zygote")).expect("invalid path to zygote");
        return Ok(linux_raw::sys_open(&path, linux_raw::O_CLOEXEC | linux_raw::O_PATH).unwrap());
    }

    let native_page_size = get_native_page_size();

    #[allow(clippy::unwrap_used)]
    // The size of the zygote blob is always going to be much less than the size of usize, so this never fails.
    let length_aligned = align_to_next_page_usize(native_page_size, ZYGOTE_BLOB.len()).unwrap();
    prepare_sealed_memfd(create_empty_memfd(cstr!("polkavm_zygote"))?, length_aligned, [ZYGOTE_BLOB])
}

fn prepare_vmctx() -> Result<(Fd, Mmap), Error> {
    let native_page_size = get_native_page_size();

    #[allow(clippy::unwrap_used)] // The size of VmCtx is always going to be much less than the size of usize, so this never fails.
    let length_aligned = align_to_next_page_usize(native_page_size, core::mem::size_of::<VmCtx>()).unwrap();

    let memfd = create_empty_memfd(cstr!("polkavm_vmctx"))?;
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

fn prepare_memory() -> Result<(Fd, Mmap), Error> {
    let memfd = create_empty_memfd(cstr!("polkavm_memory"))?;
    linux_raw::sys_ftruncate(memfd.borrow(), linux_raw::c_ulong::from(u32::MAX))?;
    linux_raw::sys_fcntl(
        memfd.borrow(),
        linux_raw::F_ADD_SEALS,
        linux_raw::F_SEAL_SEAL | linux_raw::F_SEAL_SHRINK | linux_raw::F_SEAL_GROW,
    )?;

    let vmctx = unsafe {
        linux_raw::Mmap::map(
            core::ptr::null_mut(),
            u32::MAX as usize,
            linux_raw::PROT_READ | linux_raw::PROT_WRITE,
            linux_raw::MAP_SHARED,
            Some(memfd.borrow()),
            0,
        )?
    };

    Ok((memfd, vmctx))
}

unsafe fn child_main(zygote_memfd: Fd, child_socket: Fd, uid_map: &str, gid_map: &str, logging_pipe: Option<Fd>) -> Result<(), Error> {
    // Change the name of the process.
    linux_raw::sys_prctl_set_name(b"polkavm-sandbox\0")?;

    if !cfg!(polkavm_dev_debug_zygote) {
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
    }

    let fd_limit = if logging_pipe.is_some() {
        6
    } else {
        5
    };

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
        let mut count = 1;
        fds_to_keep[0] = STDIN_FILENO;
        if let Some(logging_pipe) = logging_pipe {
            linux_raw::sys_dup3(logging_pipe.raw(), STDERR_FILENO, 0)?;
            logging_pipe.close()?;
            fds_to_keep[count] = STDERR_FILENO;
            count += 1;
        }

        fds_to_keep[count] = zygote_memfd.raw();
        count += 1;

        fds_to_keep.sort_unstable(); // Should be a no-op.
        &fds_to_keep[..count]
    };
    close_other_file_descriptors(fds_to_keep)?;

    if !cfg!(polkavm_dev_debug_zygote) {
        // Hide the host filesystem.
        let mount_flags = linux_raw::MS_REC | linux_raw::MS_NODEV | linux_raw::MS_NOEXEC | linux_raw::MS_NOSUID | linux_raw::MS_RDONLY;
        linux_raw::sys_mount(cstr!("none"), cstr!("/tmp"), cstr!("tmpfs"), mount_flags, Some(cstr!("size=0")))?;
        linux_raw::sys_chdir(cstr!("/tmp"))?;
    }

    // Clear all of our ambient capabilities.
    linux_raw::sys_prctl_cap_ambient_clear_all()?;

    // Flag ourselves that we won't ever want to acquire any new privileges.
    linux_raw::sys_prctl_set_no_new_privs()?;

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

    linux_raw::sys_setrlimit(linux_raw::RLIMIT_NOFILE, &linux_raw::rlimit { rlim_cur: fd_limit, rlim_max: fd_limit })?;
    linux_raw::sys_setrlimit(linux_raw::RLIMIT_NPROC, &linux_raw::rlimit { rlim_cur: 1, rlim_max: 1 })?;
    linux_raw::sys_setrlimit(linux_raw::RLIMIT_FSIZE, &linux_raw::rlimit { rlim_cur: 0, rlim_max: 0 })?;
    linux_raw::sys_setrlimit(linux_raw::RLIMIT_LOCKS, &linux_raw::rlimit { rlim_cur: 0, rlim_max: 0 })?;
    linux_raw::sys_setrlimit(linux_raw::RLIMIT_MEMLOCK, &linux_raw::rlimit { rlim_cur: 0, rlim_max: 0 })?;
    linux_raw::sys_setrlimit(linux_raw::RLIMIT_MSGQUEUE, &linux_raw::rlimit { rlim_cur: 0, rlim_max: 0 })?;

    if cfg!(polkavm_dev_debug_zygote) {
        let pid = linux_raw::sys_getpid()?;
        linux_raw::sys_kill(pid, linux_raw::SIGSTOP)?;
    }

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

struct ProgramMap {
    address: u64,
    length: u64,
    is_writable: bool,
    initialize_with: Option<ShmAllocation>,
}

struct SandboxProgramInner {
    memory_map: Vec<ProgramMap>,
    shm_code: ShmAllocation,
    shm_jump_table: ShmAllocation,
    code_length: usize,
    sysreturn_address: u64,
}

impl super::SandboxProgram for SandboxProgram {
    fn machine_code(&self) -> Cow<[u8]> {
        Cow::Borrowed(&unsafe { self.0.shm_code.as_slice() }[..self.0.code_length])
    }
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
    _lifetime_pipe: Fd,
    vmctx_mmap: Mmap,
    #[allow(dead_code)] // TODO: Actually use this.
    memory_mmap: Mmap,
    child: ChildProcess,

    count_wait_loop_start: u64,
    count_futex_wait: u64,

    module: Option<Module>,
    gas_metering: Option<GasMeteringKind>,

    shm_memory_map: Option<ShmAllocation>,
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

#[repr(transparent)]
pub struct JumpTableAllocation(ShmAllocation);

impl AsRef<[usize]> for JumpTableAllocation {
    fn as_ref(&self) -> &[usize] {
        #[allow(clippy::cast_ptr_alignment)] // Allocation is guaranteed to be page aligned.
        unsafe {
            core::slice::from_raw_parts(
                self.0.as_ptr().cast::<usize>(), self.0.len() / core::mem::size_of::<usize>()
            )
        }
    }
}

impl AsMut<[usize]> for JumpTableAllocation {
    fn as_mut(&mut self) -> &mut [usize] {
        #[allow(clippy::cast_ptr_alignment)] // Allocation is guaranteed to be page aligned.
        unsafe {
            core::slice::from_raw_parts_mut(
                self.0.as_mut_ptr().cast::<usize>(), self.0.len() / core::mem::size_of::<usize>()
            )
        }
    }
}

impl super::Sandbox for Sandbox {
    const KIND: SandboxKind = SandboxKind::Linux;

    type Access<'r> = SandboxAccess<'r>;
    type Config = SandboxConfig;
    type Error = Error;
    type Program = SandboxProgram;
    type AddressSpace = ();
    type GlobalState = GlobalState;
    type JumpTable = JumpTableAllocation;

    fn downcast_module(module: &Module) -> &CompiledModule<Self> {
        match module.compiled_module() {
            CompiledModuleKind::Linux(ref module) => module,
            _ => unreachable!(),
        }
    }

    fn downcast_global_state(global: &crate::sandbox::GlobalStateKind) -> &Self::GlobalState {
        #[allow(clippy::match_wildcard_for_single_variants)]
        match global {
            crate::sandbox::GlobalStateKind::Linux(ref global) => global,
            _ => unreachable!(),
        }
    }

    fn downcast_worker_cache(cache: &WorkerCacheKind) -> &WorkerCache<Self> {
        #[allow(clippy::match_wildcard_for_single_variants)]
        match cache {
            crate::sandbox::WorkerCacheKind::Linux(ref cache) => cache,
            _ => unreachable!(),
        }
    }

    fn allocate_jump_table(global: &Self::GlobalState, count: usize) -> Result<Self::JumpTable, Self::Error> {
        let Some(alloc) = global.shared_memory.alloc(count * core::mem::size_of::<usize>()) else {
            return Err(Error::from_str("failed to allocate the jump table: out of shared memory"));
        };

        Ok(JumpTableAllocation(alloc))
    }

    fn reserve_address_space() -> Result<Self::AddressSpace, Self::Error> {
        Ok(())
    }

    fn prepare_program(global: &Self::GlobalState, init: SandboxInit<Self>, (): Self::AddressSpace) -> Result<Self::Program, Self::Error> {
        let cfg = init.guest_init.memory_map()?;

        let Some(shm_ro_data) = global.shared_memory.alloc(init.guest_init.ro_data.len()) else {
            return Err(Error::from_str("failed to prepare the program for the sandbox: out of shared memory"));
        };

        let Some(shm_rw_data) = global.shared_memory.alloc(init.guest_init.rw_data.len()) else {
            return Err(Error::from_str("failed to prepare the program for the sandbox: out of shared memory"));
        };

        let Some(shm_code) = global.shared_memory.alloc(init.code.len()) else {
            return Err(Error::from_str("failed to prepare the program for the sandbox: out of shared memory"));
        };

        unsafe {
            let shm_ro_data = shm_ro_data.as_slice_mut();
            shm_ro_data[..init.guest_init.ro_data.len()].copy_from_slice(init.guest_init.ro_data);
            shm_ro_data[init.guest_init.ro_data.len()..].fill(0);
        }

        unsafe {
            let shm_rw_data = shm_rw_data.as_slice_mut();
            shm_rw_data[..init.guest_init.rw_data.len()].copy_from_slice(init.guest_init.rw_data);
            shm_rw_data[init.guest_init.rw_data.len()..].fill(0);
        }

        let code_length = init.code.len();
        unsafe {
            let shm_code = shm_code.as_slice_mut();
            shm_code[..code_length].copy_from_slice(init.code);
        }

        let mut memory_map = Vec::new();
        if cfg.ro_data_size() > 0 {
            let physical_size = shm_ro_data.len() as u64;
            let virtual_size = u64::from(cfg.ro_data_size());
            if physical_size > 0 {
                memory_map.push(ProgramMap {
                    address: u64::from(cfg.ro_data_address()),
                    length: physical_size,
                    is_writable: false,
                    initialize_with: Some(shm_ro_data),
                });
            }

            let padding = virtual_size - physical_size;
            if padding > 0 {
                memory_map.push(ProgramMap {
                    address: u64::from(cfg.ro_data_address()) + physical_size,
                    length: padding,
                    is_writable: false,
                    initialize_with: None,
                });
            }
        }

        if cfg.rw_data_size() > 0 {
            let physical_size = shm_rw_data.len() as u64;
            let virtual_size = u64::from(cfg.rw_data_size());
            if physical_size > 0 {
                memory_map.push(ProgramMap {
                    address: u64::from(cfg.rw_data_address()),
                    length: physical_size,
                    is_writable: true,
                    initialize_with: Some(shm_rw_data),
                });
            }

            let padding = virtual_size - physical_size;
            if padding > 0 {
                memory_map.push(ProgramMap {
                    address: u64::from(cfg.rw_data_address()) + physical_size,
                    length: padding,
                    is_writable: true,
                    initialize_with: None,
                });
            }
        }

        if cfg.stack_size() > 0 {
            memory_map.push(ProgramMap {
                address: u64::from(cfg.stack_address_low()),
                length: u64::from(cfg.stack_size()),
                is_writable: true,
                initialize_with: None,
            });
        }

        Ok(SandboxProgram(Arc::new(SandboxProgramInner {
            memory_map,
            shm_code,
            shm_jump_table: init.jump_table.0,
            code_length,
            sysreturn_address: init.sysreturn_address,
        })))
    }

    fn spawn(global: &Self::GlobalState, config: &SandboxConfig) -> Result<Self, Error> {
        let sigset = Sigmask::block_all_signals()?;
        let zygote_memfd = prepare_zygote()?;
        let (vmctx_memfd, vmctx_mmap) = prepare_vmctx()?;
        let (memory_memfd, memory_mmap) = prepare_memory()?;
        let (socket, child_socket) = linux_raw::sys_socketpair(linux_raw::AF_UNIX, linux_raw::SOCK_SEQPACKET | linux_raw::SOCK_CLOEXEC, 0)?;
        let (lifetime_pipe_host, lifetime_pipe_child) = linux_raw::sys_pipe2(linux_raw::O_CLOEXEC)?;
        
        let sandbox_flags = if !cfg!(polkavm_dev_debug_zygote) {
            SANDBOX_FLAGS
        } else {
            0
        };

        let mut pidfd: c_int = -1;
        let args = CloneArgs {
            flags: linux_raw::CLONE_CLEAR_SIGHAND | u64::from(linux_raw::CLONE_PIDFD) | u64::from(sandbox_flags),
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
            unsafe { linux_raw::syscall!(linux_raw::SYS_clone3, core::ptr::addr_of!(args), core::mem::size_of::<CloneArgs>()) };

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

                                        log::trace!(target: "polkavm::zygote", "Child #{}: {}", child_pid, String::from_utf8_lossy(&buffer));
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

                let status = child.check_status(true)?;
                if !status.is_running() {
                    let message = get_message(vmctx);
                    if let Some(message) = message {
                        let error = Error::from(format!("failed to initialize sandbox process: {status}: {message}"));
                        return Err(error);
                    } else {
                        return Err(Error::from(format!(
                            "failed to initialize sandbox process: child process unexpectedly quit: {status}",
                        )));
                    }
                }

                if !cfg!(polkavm_dev_debug_zygote) && instant.elapsed() > core::time::Duration::from_secs(10) {
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

        #[cfg(debug_assertions)]
        if cfg!(polkavm_dev_debug_zygote) || !global.is_sandboxing_enabled {
            use core::fmt::Write;
            std::thread::sleep(core::time::Duration::from_millis(200));

            let mut command = String::new();
            // Make sure gdb can actually attach to the worker process.
            if std::fs::read_to_string("/proc/sys/kernel/yama/ptrace_scope").map(|value| value.trim() == "1").unwrap_or(false) {
                command.push_str("echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope ;");
            }

            command.push_str(concat!(
                "gdb",
                " -ex 'set pagination off'",
                " -ex 'layout split'",
                " -ex 'set print asm-demangle on'",
                " -ex 'set debuginfod enabled off'",
                " -ex 'tcatch exec'",
                " -ex 'handle SIGSTOP nostop'",
            ));

            let _ = write!(&mut command, " -ex 'attach {}' -ex 'continue'", child.pid);

            let mut cmd =
                if std::env::var_os("DISPLAY").is_some() {
                    // Running X11; open gdb in a terminal.
                    let mut cmd = std::process::Command::new("urxvt");
                    cmd
                        .args(["-fg", "rgb:ffff/ffff/ffff"])
                        .args(["-bg", "rgba:0000/0000/0000/7777"])
                        .arg("-e")
                        .arg("sh")
                        .arg("-c")
                        .arg(&command);
                    cmd
                } else {
                    // Not running under X11; just run it as-is.
                    let mut cmd = std::process::Command::new("sh");
                    cmd
                        .arg("-c")
                        .arg(&command);
                    cmd
                };

            let mut gdb = match cmd.spawn() {
                Ok(child) => child,
                Err(error) => {
                    panic!("failed to launch: '{cmd:?}': {error}");
                }
            };

            let pid = child.pid;
            std::thread::spawn(move || {
                let _ = gdb.wait();
                let _ = linux_raw::sys_kill(pid, linux_raw::SIGKILL);
            });
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

        linux_raw::sendfd(socket.borrow(), lifetime_pipe_child.borrow())?;
        linux_raw::sendfd(socket.borrow(), global.shared_memory.fd())?;
        linux_raw::sendfd(socket.borrow(), memory_memfd.borrow())?;
        lifetime_pipe_child.close()?;
        socket.close()?;

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
            _lifetime_pipe: lifetime_pipe_host,
            vmctx_mmap,
            memory_mmap,
            child,

            count_wait_loop_start: 0,
            count_futex_wait: 0,

            module: None,
            gas_metering: None,

            shm_memory_map: None,
        })
    }

    fn execute(&mut self, global: &Self::GlobalState, mut args: ExecuteArgs) -> Result<(), ExecutionError<Self::Error>> {
        self.wait_if_necessary(match args.hostcall_handler {
            Some(ref mut hostcall_handler) => Some(&mut *hostcall_handler),
            None => None,
        }, true)?;

        if args.is_async && args.hostcall_handler.is_some() {
            return Err(Error::from_str("requested asynchronous execution with a borrowed hostcall handler").into());
        }

        unsafe {
            if let Some(module) = args.module {
                let compiled_module = Self::downcast_module(module);
                let program = &compiled_module.sandbox_program.0;

                let Some(memory_map) = global.shared_memory.alloc(core::mem::size_of::<VmMap>() * program.memory_map.len()) else {
                    return Err(Error::from_str("out of shared memory").into());
                };

                args.flags |= polkavm_common::zygote::VM_RPC_FLAG_RECONFIGURE;

                for (chunk, vm_map) in program.memory_map.iter().zip(memory_map.as_typed_slice_mut::<VmMap>().iter_mut()) {
                    *vm_map = VmMap {
                        address: chunk.address,
                        length: chunk.length,
                        shm_offset: chunk.initialize_with.as_ref().map_or(u64::MAX, |alloc| alloc.offset() as u64),
                        is_writable: chunk.is_writable,
                    };
                }

                *self.vmctx().heap_info.heap_top.get() = u64::from(module.memory_map().heap_base());
                *self.vmctx().heap_info.heap_threshold.get() = u64::from(module.memory_map().rw_data_range().end);
                *self.vmctx().heap_base.get() = module.memory_map().heap_base();
                *self.vmctx().heap_initial_threshold.get() = module.memory_map().rw_data_range().end;
                *self.vmctx().heap_max_size.get() = module.memory_map().max_heap_size();
                *self.vmctx().page_size.get() = module.memory_map().page_size();
                *self.vmctx().shm_memory_map_offset.get() = memory_map.offset() as u64;
                *self.vmctx().shm_memory_map_count.get() = program.memory_map.len() as u64;
                *self.vmctx().shm_code_offset.get() = program.shm_code.offset() as u64;
                *self.vmctx().shm_code_length.get() = program.shm_code.len() as u64;
                *self.vmctx().shm_jump_table_offset.get() = program.shm_jump_table.offset() as u64;
                *self.vmctx().shm_jump_table_length.get() = program.shm_jump_table.len() as u64;
                *self.vmctx().sysreturn_address.get() = program.sysreturn_address;
                self.gas_metering = module.gas_metering();
                self.module = Some(module.clone());
                self.shm_memory_map = Some(memory_map);
            }

            if let Some(gas) = crate::sandbox::get_gas(&args, self.gas_metering) {
                *self.vmctx().gas().get() = gas;
            }

            *self.vmctx().rpc_address.get() = args.entry_point.map_or(0, |entry_point|
                Self::downcast_module(self.module.as_ref().unwrap()).export_trampolines.get(&entry_point).copied().unwrap_or(0) as usize
            ) as u64;

            *self.vmctx().rpc_flags.get() = args.flags;
            *self.vmctx().rpc_sbrk.get() = args.sbrk;

            if let Some(regs) = args.regs {
                (*self.vmctx().regs().get()).copy_from_slice(regs);
            }

            self.vmctx().futex.store(VMCTX_FUTEX_BUSY, Ordering::Release);
            linux_raw::sys_futex_wake_one(&self.vmctx().futex)?;
        }

        if !args.is_async {
            self.wait_if_necessary(match args.hostcall_handler {
                Some(ref mut hostcall_handler) => Some(&mut *hostcall_handler),
                None => None,
            }, args.entry_point.is_none())?;
        }

        Ok(())
    }

    #[inline]
    fn access(&mut self) -> SandboxAccess {
        SandboxAccess { sandbox: self }
    }

    fn pid(&self) -> Option<u32> {
        Some(self.child.pid as u32)
    }

    fn address_table() -> AddressTable {
        ZYGOTE_ADDRESS_TABLE
    }

    fn vmctx_regs_offset() -> usize {
        get_field_offset!(VmCtx::new(), |base| base.regs().get())
    }

    fn vmctx_gas_offset() -> usize {
        get_field_offset!(VmCtx::new(), |base| base.gas().get())
    }

    fn vmctx_heap_info_offset() -> usize {
        get_field_offset!(VmCtx::new(), |base| base.heap_info())
    }

    fn gas_remaining_impl(&self) -> Result<Option<Gas>, super::OutOfGas> {
        if self.gas_metering.is_none() { return Ok(None) };
        let raw_gas = unsafe { *self.vmctx().gas().get() };
        Gas::from_i64(raw_gas).ok_or(super::OutOfGas).map(Some)
    }

    fn sync(&mut self) -> Result<(), Self::Error> {
        self.wait_if_necessary(None, true).map_err(|error| {
            match error {
                ExecutionError::Trap(..) => Error::from_str("unexpected trap"),
                ExecutionError::OutOfGas => Error::from_str("unexpected out of gas"),
                ExecutionError::Error(error) => error,
            }
        })
    }
}

impl Sandbox {
    #[inline]
    fn vmctx(&self) -> &VmCtx {
        unsafe { &*self.vmctx_mmap.as_ptr().cast::<VmCtx>() }
    }

    #[inline(never)]
    #[cold]
    fn wait(&mut self, mut hostcall_handler: Option<HostcallHandler>, low_latency: bool) -> Result<(), ExecutionError<Error>> {
        let mut spin_target = 0;
        let mut yield_target = 0;
        if low_latency {
            yield_target = 20;
        }

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

                let hostcall_handler = match hostcall_handler {
                    Some(ref mut hostcall_handler) => &mut *hostcall_handler,
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
                if hostcall == polkavm_common::HOSTCALL_TRACE {
                    // When tracing aggressively spin to avoid having to call into the kernel.
                    spin_target = 512;
                }

                match hostcall_handler(hostcall, super::Sandbox::access(self).into()) {
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

            for _ in 0..yield_target {
                let _ = linux_raw::sys_sched_yield();
                if self.vmctx().futex.load(Ordering::Relaxed) != VMCTX_FUTEX_BUSY {
                    continue 'outer;
                }
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
                    self.check_child_status()?;
                }
                Err(error) => return Err(error.into()),
            }
        }
    }

    fn check_child_status(&mut self) -> Result<(), Error> {
        let status = self.child.check_status(true)?;
        if status.is_running() {
            return Ok(());
        }

        log::trace!("Child #{} is not running anymore: {status}", self.child.pid);
        let message = get_message(self.vmctx());
        if let Some(message) = message {
            Err(Error::from(format!("{status}: {message}")))
        } else {
            Err(Error::from(format!("worker process unexpectedly quit: {status}")))
        }
    }

    #[inline]
    fn wait_if_necessary(&mut self, hostcall_handler: Option<HostcallHandler>, low_latency: bool) -> Result<(), ExecutionError<Error>> {
        if self.vmctx().futex.load(Ordering::Relaxed) != VMCTX_FUTEX_IDLE {
            self.wait(hostcall_handler, low_latency)?;
        }

        self.shm_memory_map.take();

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
        let regs = unsafe { &*self.sandbox.vmctx().regs().get() };
        regs[reg as usize]
    }

    fn set_reg(&mut self, reg: Reg, value: u32) {
        unsafe {
            (*self.sandbox.vmctx().regs().get())[reg as usize] = value;
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

        self.sandbox.vmctx().is_memory_dirty.store(true, Ordering::Relaxed);

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

    fn sbrk(&mut self, size: u32) -> Option<u32> {
        if size == 0 {
            return Some(unsafe { *self.sandbox.vmctx().heap_info().heap_top.get() as u32 });
        }

        debug_assert_eq!(self.sandbox.vmctx().futex.load(Ordering::Relaxed), VMCTX_FUTEX_HOSTCALL);

        unsafe {
            *self.sandbox.vmctx().rpc_sbrk.get() = size;
            *self.sandbox.vmctx().hostcall().get() = polkavm_common::zygote::HOSTCALL_SBRK;
        }

        self.sandbox.vmctx().futex.store(VMCTX_FUTEX_BUSY, Ordering::Release);
        if let Err(error) = linux_raw::sys_futex_wake_one(&self.sandbox.vmctx().futex) {
            panic!("sbrk failed: {error}");
        }

        let mut timestamp = Instant::now();
        loop {
            let _ = linux_raw::sys_sched_yield();
            if self.sandbox.vmctx().futex.load(Ordering::Relaxed) == VMCTX_FUTEX_BUSY {
                let new_timestamp = Instant::now();
                let elapsed = new_timestamp - timestamp;
                if elapsed >= Duration::from_millis(100) {
                    timestamp = new_timestamp;
                    if let Err(error) = self.sandbox.check_child_status() {
                        panic!("sbrk failed: {error}");
                    }
                }
                continue;
            }

            core::sync::atomic::fence(Ordering::Acquire);
            break;
        }

        debug_assert_eq!(self.sandbox.vmctx().futex.load(Ordering::Relaxed), VMCTX_FUTEX_HOSTCALL);

        let result = unsafe { *self.sandbox.vmctx().rpc_sbrk.get() };
        if result == 0 {
            None
        } else {
            Some(result)
        }
    }

    fn heap_size(&self) -> u32 {
        let heap_base = unsafe { *self.sandbox.vmctx().heap_base.get() };
        let heap_top = unsafe { *self.sandbox.vmctx().heap_info().heap_top.get() };
        (heap_top - u64::from(heap_base)) as u32
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

    fn gas_remaining(&self) -> Option<Gas> {
        use super::Sandbox;
        self.sandbox.gas_remaining_impl().ok().unwrap_or(Some(Gas::MIN))
    }

    fn consume_gas(&mut self, gas: u64) {
        if self.sandbox.gas_metering.is_none() { return }
        let gas_remaining = unsafe { &mut *self.sandbox.vmctx().gas().get() };
        *gas_remaining = gas_remaining.checked_sub_unsigned(gas).unwrap_or(-1);
    }
}
