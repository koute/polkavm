// These functions are based on the ones from `rustix`: https://github.com/bytecodealliance/rustix/blob/2064196e201a574ffa5bc214a065cf6faffbe97c/src/backend/linux_raw/arch/inline/x86_64.rs

use core::arch::asm;
use core::ffi::c_long;
use core::marker::PhantomData;

#[cfg(target_pointer_width = "32")]
compile_error!("x32 is not supported");

#[repr(transparent)]
#[derive(Copy, Clone)]
pub struct SyscallArg<'a>(usize, PhantomData<&'a ()>);

impl From<i32> for SyscallArg<'_> {
    #[inline]
    fn from(value: i32) -> Self {
        SyscallArg(value as isize as usize, PhantomData)
    }
}

impl From<i64> for SyscallArg<'_> {
    #[inline]
    fn from(value: i64) -> Self {
        SyscallArg(value as isize as usize, PhantomData)
    }
}

impl From<isize> for SyscallArg<'_> {
    #[inline]
    fn from(value: isize) -> Self {
        SyscallArg(value as usize, PhantomData)
    }
}

impl From<u32> for SyscallArg<'_> {
    #[inline]
    fn from(value: u32) -> Self {
        SyscallArg(value as usize, PhantomData)
    }
}

impl From<u64> for SyscallArg<'_> {
    #[inline]
    fn from(value: u64) -> Self {
        SyscallArg(value as usize, PhantomData)
    }
}

impl From<usize> for SyscallArg<'_> {
    #[inline]
    fn from(value: usize) -> Self {
        SyscallArg(value, PhantomData)
    }
}

impl<T> From<*const T> for SyscallArg<'_> {
    #[inline]
    fn from(value: *const T) -> Self {
        SyscallArg(value as usize, PhantomData)
    }
}

impl<T> From<*mut T> for SyscallArg<'_> {
    #[inline]
    fn from(value: *mut T) -> Self {
        SyscallArg(value as usize, PhantomData)
    }
}

impl<'a, T> From<&'a [T]> for SyscallArg<'a> {
    #[inline]
    fn from(value: &'a [T]) -> Self {
        SyscallArg::from(value.as_ptr())
    }
}

impl<'a, T, const N: usize> From<&'a [T; N]> for SyscallArg<'a> {
    #[inline]
    fn from(value: &'a [T; N]) -> Self {
        SyscallArg::from(value.as_ptr())
    }
}

impl<'a, T> From<&'a mut [T]> for SyscallArg<'a> {
    #[inline]
    fn from(value: &'a mut [T]) -> Self {
        SyscallArg::from(value.as_mut_ptr())
    }
}

impl<'a> From<crate::FdRef<'a>> for SyscallArg<'a> {
    #[inline]
    fn from(value: crate::FdRef<'a>) -> Self {
        SyscallArg(value.raw() as isize as usize, PhantomData)
    }
}

impl<'a> From<Option<crate::FdRef<'a>>> for SyscallArg<'a> {
    #[inline]
    fn from(value: Option<crate::FdRef<'a>>) -> Self {
        SyscallArg(value.map_or(-1, |fd| fd.raw()) as isize as usize, PhantomData)
    }
}

impl<'a> From<&'a crate::Fd> for SyscallArg<'a> {
    #[inline]
    fn from(value: &'a crate::Fd) -> Self {
        SyscallArg(value.raw() as isize as usize, PhantomData)
    }
}

impl<'a> From<&'a core::ffi::CStr> for SyscallArg<'a> {
    #[inline]
    fn from(value: &'a core::ffi::CStr) -> Self {
        SyscallArg(value.as_ptr() as usize, PhantomData)
    }
}

#[inline]
pub unsafe fn syscall0_readonly(nr: c_long) -> c_long {
    let r0;
    asm!(
        "syscall",
        inlateout("rax") nr => r0,
        lateout("rcx") _,
        lateout("r11") _,
        options(nostack, preserves_flags, readonly)
    );
    r0
}

#[inline]
pub unsafe fn syscall1(nr: c_long, a0: SyscallArg) -> c_long {
    let r0;
    asm!(
        "syscall",
        inlateout("rax") nr => r0,
        in("rdi") a0.0,
        lateout("rcx") _,
        lateout("r11") _,
        options(nostack, preserves_flags)
    );
    r0
}

#[inline]
pub unsafe fn syscall1_readonly(nr: c_long, a0: SyscallArg) -> c_long {
    let r0;
    asm!(
        "syscall",
        inlateout("rax") nr => r0,
        in("rdi") a0.0,
        lateout("rcx") _,
        lateout("r11") _,
        options(nostack, preserves_flags, readonly)
    );
    r0
}

#[inline]
pub unsafe fn syscall1_noreturn(nr: c_long, a0: SyscallArg) -> ! {
    asm!(
        "syscall",
        in("rax") nr,
        in("rdi") a0.0,
        options(noreturn)
    )
}

#[inline]
pub unsafe fn syscall2(nr: c_long, a0: SyscallArg, a1: SyscallArg) -> c_long {
    let r0;
    asm!(
        "syscall",
        inlateout("rax") nr => r0,
        in("rdi") a0.0,
        in("rsi") a1.0,
        lateout("rcx") _,
        lateout("r11") _,
        options(nostack, preserves_flags)
    );
    r0
}

#[inline]
pub unsafe fn syscall2_readonly(nr: c_long, a0: SyscallArg, a1: SyscallArg) -> c_long {
    let r0;
    asm!(
        "syscall",
        inlateout("rax") nr => r0,
        in("rdi") a0.0,
        in("rsi") a1.0,
        lateout("rcx") _,
        lateout("r11") _,
        options(nostack, preserves_flags, readonly)
    );
    r0
}

#[inline]
pub unsafe fn syscall3(nr: c_long, a0: SyscallArg, a1: SyscallArg, a2: SyscallArg) -> c_long {
    let r0;
    asm!(
        "syscall",
        inlateout("rax") nr => r0,
        in("rdi") a0.0,
        in("rsi") a1.0,
        in("rdx") a2.0,
        lateout("rcx") _,
        lateout("r11") _,
        options(nostack, preserves_flags)
    );
    r0
}

#[inline]
pub unsafe fn syscall3_readonly(nr: u64, a0: SyscallArg, a1: SyscallArg, a2: SyscallArg) -> c_long {
    let r0;
    asm!(
        "syscall",
        inlateout("rax") nr => r0,
        in("rdi") a0.0,
        in("rsi") a1.0,
        in("rdx") a2.0,
        lateout("rcx") _,
        lateout("r11") _,
        options(nostack, preserves_flags, readonly)
    );
    r0
}

#[inline]
pub unsafe fn syscall4(nr: c_long, a0: SyscallArg, a1: SyscallArg, a2: SyscallArg, a3: SyscallArg) -> c_long {
    let r0;
    asm!(
        "syscall",
        inlateout("rax") nr => r0,
        in("rdi") a0.0,
        in("rsi") a1.0,
        in("rdx") a2.0,
        in("r10") a3.0,
        lateout("rcx") _,
        lateout("r11") _,
        options(nostack, preserves_flags)
    );
    r0
}

#[inline]
pub unsafe fn syscall4_readonly(nr: c_long, a0: SyscallArg, a1: SyscallArg, a2: SyscallArg, a3: SyscallArg) -> c_long {
    let r0;
    asm!(
        "syscall",
        inlateout("rax") nr => r0,
        in("rdi") a0.0,
        in("rsi") a1.0,
        in("rdx") a2.0,
        in("r10") a3.0,
        lateout("rcx") _,
        lateout("r11") _,
        options(nostack, preserves_flags, readonly)
    );
    r0
}

#[inline]
pub unsafe fn syscall5(nr: c_long, a0: SyscallArg, a1: SyscallArg, a2: SyscallArg, a3: SyscallArg, a4: SyscallArg) -> c_long {
    let r0;
    asm!(
        "syscall",
        inlateout("rax") nr => r0,
        in("rdi") a0.0,
        in("rsi") a1.0,
        in("rdx") a2.0,
        in("r10") a3.0,
        in("r8") a4.0,
        lateout("rcx") _,
        lateout("r11") _,
        options(nostack, preserves_flags)
    );
    r0
}

#[inline]
pub unsafe fn syscall5_readonly(nr: c_long, a0: SyscallArg, a1: SyscallArg, a2: SyscallArg, a3: SyscallArg, a4: SyscallArg) -> c_long {
    let r0;
    asm!(
        "syscall",
        inlateout("rax") nr => r0,
        in("rdi") a0.0,
        in("rsi") a1.0,
        in("rdx") a2.0,
        in("r10") a3.0,
        in("r8") a4.0,
        lateout("rcx") _,
        lateout("r11") _,
        options(nostack, preserves_flags, readonly)
    );
    r0
}

#[inline]
pub unsafe fn syscall6(
    nr: c_long,
    a0: SyscallArg,
    a1: SyscallArg,
    a2: SyscallArg,
    a3: SyscallArg,
    a4: SyscallArg,
    a5: SyscallArg,
) -> c_long {
    let r0;
    asm!(
        "syscall",
        inlateout("rax") nr => r0,
        in("rdi") a0.0,
        in("rsi") a1.0,
        in("rdx") a2.0,
        in("r10") a3.0,
        in("r8") a4.0,
        in("r9") a5.0,
        lateout("rcx") _,
        lateout("r11") _,
        options(nostack, preserves_flags)
    );
    r0
}

#[inline]
pub unsafe fn syscall6_readonly(
    nr: c_long,
    a0: SyscallArg,
    a1: SyscallArg,
    a2: SyscallArg,
    a3: SyscallArg,
    a4: SyscallArg,
    a5: SyscallArg,
) -> c_long {
    let r0;
    asm!(
        "syscall",
        inlateout("rax") nr => r0,
        in("rdi") a0.0,
        in("rsi") a1.0,
        in("rdx") a2.0,
        in("r10") a3.0,
        in("r8") a4.0,
        in("r9") a5.0,
        lateout("rcx") _,
        lateout("r11") _,
        options(nostack, preserves_flags, readonly)
    );
    r0
}
