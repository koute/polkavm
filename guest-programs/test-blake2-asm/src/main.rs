#![no_std]
#![no_main]

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::arch::asm!("unimp", options(noreturn)) }
}

#[path = "../../bench-blake2-256-asm/src/asm_blake2b.rs"]
mod asm_blake2b;

const MAX_LEN: usize = 1024 * 1024 + 16;

static mut BUFFER: [u8; MAX_LEN] = [0; MAX_LEN];
static mut DIGEST: [u8; 32] = [0; 32];

#[polkavm_derive::polkavm_export]
extern "C" fn buffer_ptr() -> u64 {
    core::ptr::addr_of!(BUFFER) as u64
}

#[polkavm_derive::polkavm_export]
extern "C" fn digest_ptr() -> u64 {
    core::ptr::addr_of!(DIGEST) as u64
}

#[polkavm_derive::polkavm_export]
extern "C" fn hash(len: u64) {
    let input = unsafe { &(*core::ptr::addr_of!(BUFFER))[..len as usize] };
    let digest = asm_blake2b::blake2b_256(input);
    unsafe { (*core::ptr::addr_of_mut!(DIGEST)).copy_from_slice(&digest) };
}
