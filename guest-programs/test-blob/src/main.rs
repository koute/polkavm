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
