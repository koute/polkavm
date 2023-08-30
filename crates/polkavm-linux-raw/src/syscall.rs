// These macros are based on the ones from `rustix`: https://github.com/bytecodealliance/rustix/blob/2064196e201a574ffa5bc214a065cf6faffbe97c/src/backend/linux_raw/arch/mod.rs

#[macro_export]
macro_rules! syscall {
    ($nr:expr) => {
        $crate::syscall_impl::syscall0($nr.into())
    };

    ($nr:expr, $a0:expr) => {
        $crate::syscall_impl::syscall1($nr.into(), $a0.into())
    };

    ($nr:expr, $a0:expr, $a1:expr) => {
        $crate::syscall_impl::syscall2($nr.into(), $a0.into(), $a1.into())
    };

    ($nr:expr, $a0:expr, $a1:expr, $a2:expr) => {
        $crate::syscall_impl::syscall3($nr.into(), $a0.into(), $a1.into(), $a2.into())
    };

    ($nr:expr, $a0:expr, $a1:expr, $a2:expr, $a3:expr) => {
        $crate::syscall_impl::syscall4($nr.into(), $a0.into(), $a1.into(), $a2.into(), $a3.into())
    };

    ($nr:expr, $a0:expr, $a1:expr, $a2:expr, $a3:expr, $a4:expr) => {
        $crate::syscall_impl::syscall5($nr.into(), $a0.into(), $a1.into(), $a2.into(), $a3.into(), $a4.into())
    };

    ($nr:expr, $a0:expr, $a1:expr, $a2:expr, $a3:expr, $a4:expr, $a5:expr) => {
        $crate::syscall_impl::syscall6($nr.into(), $a0.into(), $a1.into(), $a2.into(), $a3.into(), $a4.into(), $a5.into())
    };

    ($nr:expr, $a0:expr, $a1:expr, $a2:expr, $a3:expr, $a4:expr, $a5:expr, $a6:expr) => {
        $crate::syscall_impl::syscall7(
            $nr.into(),
            $a0.into(),
            $a1.into(),
            $a2.into(),
            $a3.into(),
            $a4.into(),
            $a5.into(),
            $a6.into(),
        )
    };
}

#[macro_export]
macro_rules! syscall_readonly {
    ($nr:expr) => {
        $crate::syscall_impl::syscall0_readonly($nr.into())
    };

    ($nr:expr, $a0:expr) => {
        $crate::syscall_impl::syscall1_readonly($nr.into(), $a0.into())
    };

    ($nr:expr, $a0:expr, $a1:expr) => {
        $crate::syscall_impl::syscall2_readonly($nr.into(), $a0.into(), $a1.into())
    };

    ($nr:expr, $a0:expr, $a1:expr, $a2:expr) => {
        $crate::syscall_impl::syscall3_readonly($nr.into(), $a0.into(), $a1.into(), $a2.into())
    };

    ($nr:expr, $a0:expr, $a1:expr, $a2:expr, $a3:expr) => {
        $crate::syscall_impl::syscall4_readonly($nr.into(), $a0.into(), $a1.into(), $a2.into(), $a3.into())
    };

    ($nr:expr, $a0:expr, $a1:expr, $a2:expr, $a3:expr, $a4:expr) => {
        $crate::syscall_impl::syscall5_readonly($nr.into(), $a0.into(), $a1.into(), $a2.into(), $a3.into(), $a4.into())
    };

    ($nr:expr, $a0:expr, $a1:expr, $a2:expr, $a3:expr, $a4:expr, $a5:expr) => {
        $crate::syscall_impl::syscall6_readonly($nr.into(), $a0.into(), $a1.into(), $a2.into(), $a3.into(), $a4.into(), $a5.into())
    };

    ($nr:expr, $a0:expr, $a1:expr, $a2:expr, $a3:expr, $a4:expr, $a5:expr, $a6:expr) => {
        $crate::syscall_impl::syscall7_readonly(
            $nr.into(),
            $a0.into(),
            $a1.into(),
            $a2.into(),
            $a3.into(),
            $a4.into(),
            $a5.into(),
            $a6.into(),
        )
    };
}
