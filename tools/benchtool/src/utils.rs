#[cfg(target_os = "linux")]
pub fn restart_with_disabled_aslr() -> Result<(), &'static str> {
    unsafe {
        let personality = libc::personality(0xffffffff);
        if personality & libc::ADDR_NO_RANDOMIZE != 0 {
            return Ok(());
        }

        if libc::personality((personality | libc::ADDR_NO_RANDOMIZE) as _) == -1 {
            return Err("failed to set personality");
        }

        restart_inplace()
    }
}

#[cfg(target_os = "linux")]
pub fn restart_inplace() -> Result<(), &'static str> {
    use std::os::unix::ffi::OsStringExt;

    extern "C" {
        static environ: *const *const libc::c_char;
    }

    unsafe {
        let Ok(exe) = std::fs::read_link("/proc/self/exe") else {
            return Err("failed to read '/proc/self/exe'");
        };

        let exe: std::ffi::OsString = exe.into();
        let mut exe: Vec<u8> = exe.into_vec();
        exe.push(0);

        let Ok(cmdline) = std::fs::read("/proc/self/cmdline") else {
            return Err("failed to read '/proc/self/cmdline'");
        };

        if cmdline.is_empty() {
            return Err("'/proc/self/cmdline' is empty");
        }

        let argv: Vec<_> = cmdline[..cmdline.len() - 1]
            .split(|&byte| byte == 0)
            .map(|slice| slice.as_ptr())
            .chain(std::iter::once(std::ptr::null()))
            .collect();

        libc::execve(exe.as_ptr() as _, argv.as_ptr() as _, environ);
        Err("execve failed")
    }
}
