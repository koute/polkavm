#![no_std]
#![no_main]

extern crate alloc;
use alloc::vec::Vec;

#[global_allocator]
static mut GLOBAL_ALLOC: simplealloc::SimpleAlloc<{ 1024 * 1024 }> = simplealloc::SimpleAlloc::new();

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe {
        core::arch::asm!("unimp", options(noreturn));
    }
}

static mut VEC: Vec<u8> = Vec::new();

#[polkavm_derive::polkavm_export]
extern "C" fn push_one_to_global_vec() -> u32 {
    unsafe {
        VEC.push(1);
        VEC.len() as u32
    }
}

static mut ATOMIC_GLOBAL: u32 = 0;

#[polkavm_derive::polkavm_export]
extern "C" fn get_atomic_global() -> u32 {
    unsafe { ATOMIC_GLOBAL }
}

#[polkavm_derive::polkavm_export]
extern "C" fn set_atomic_global(value: u32) {
    unsafe {
        ATOMIC_GLOBAL = value;
    }
}

#[polkavm_derive::polkavm_export]
extern "C" fn atomic_fetch_add(value: u32) -> u32 {
    unsafe {
        let output;
        core::arch::asm!(
            "amoadd.w a0, a1, (a0)",
            inout("a0") &mut ATOMIC_GLOBAL => output,
            in("a1") value,
        );
        output
    }
}

#[polkavm_derive::polkavm_export]
extern "C" fn atomic_fetch_swap(value: u32) -> u32 {
    unsafe {
        let output;
        core::arch::asm!(
            "amoswap.w a0, a1, (a0)",
            inout("a0") &mut ATOMIC_GLOBAL => output,
            in("a1") value,
        );
        output
    }
}

#[polkavm_derive::polkavm_export]
extern "C" fn atomic_fetch_max_signed(value: i32) -> i32 {
    unsafe {
        let output;
        core::arch::asm!(
            "amomax.w a0, a1, (a0)",
            inout("a0") &mut ATOMIC_GLOBAL => output,
            in("a1") value,
        );
        output
    }
}

#[polkavm_derive::polkavm_export]
extern "C" fn atomic_fetch_min_signed(value: i32) -> i32 {
    unsafe {
        let output;
        core::arch::asm!(
            "amomin.w a0, a1, (a0)",
            inout("a0") &mut ATOMIC_GLOBAL => output,
            in("a1") value,
        );
        output
    }
}

#[polkavm_derive::polkavm_export]
extern "C" fn atomic_fetch_max_unsigned(value: u32) -> u32 {
    unsafe {
        let output;
        core::arch::asm!(
            "amomaxu.w a0, a1, (a0)",
            inout("a0") &mut ATOMIC_GLOBAL => output,
            in("a1") value,
        );
        output
    }
}

#[polkavm_derive::polkavm_export]
extern "C" fn atomic_fetch_min_unsigned(value: u32) -> u32 {
    unsafe {
        let output;
        core::arch::asm!(
            "amominu.w a0, a1, (a0)",
            inout("a0") &mut ATOMIC_GLOBAL => output,
            in("a1") value,
        );
        output
    }
}
