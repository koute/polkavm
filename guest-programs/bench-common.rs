#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    #[cfg(target_family = "wasm")]
    {
        core::arch::wasm32::unreachable();
    }

    #[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
    unsafe {
        core::arch::asm!("unimp", options(noreturn));
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    unsafe {
        core::arch::asm!("ud2", options(noreturn));
    }
}

#[cfg(target_ckb_vm)]
#[no_mangle]
unsafe extern "C" fn __entry_point(arg: usize) {
    if arg == 0 {
        initialize();
    } else if arg == 1 {
        run();
    }
}

#[cfg(target_ckb_vm)]
core::arch::global_asm!(
    ".global _start",
    "_start:",
    "call __entry_point",
    "ecall",
);

macro_rules! global_allocator {
    ($memory_size:expr) => {
        #[global_allocator]
        static mut GLOBAL_ALLOC: simplealloc::SimpleAlloc<{ $memory_size }> = simplealloc::SimpleAlloc::new();
    };
}
