#![no_std]
#![no_main]

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe {
        core::arch::asm!("unimp", options(noreturn));
    }
}

#[polkavm_derive::polkavm_import]
extern "C" {
    fn get_third_number() -> u32;
}

#[polkavm_derive::polkavm_export]
extern "C" fn add_numbers(a: u32, b: u32) -> u32 {
    a + b + unsafe { get_third_number() }
}
