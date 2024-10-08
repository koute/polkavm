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

static mut GLOBAL: u32 = 0;

#[polkavm_derive::polkavm_export]
extern "C" fn get_global() -> u32 {
    unsafe { GLOBAL }
}

#[polkavm_derive::polkavm_export]
extern "C" fn set_global(value: u32) {
    unsafe {
        GLOBAL = value;
    }
}

#[polkavm_derive::polkavm_export]
extern "C" fn increment_global() {
    unsafe {
        GLOBAL += 1;
    }
}

#[polkavm_derive::polkavm_export]
extern "C" fn get_global_address() -> *mut u32 {
    unsafe { core::ptr::addr_of_mut!(GLOBAL) }
}

#[polkavm_derive::polkavm_export]
extern "C" fn read_u32(address: u32) -> u32 {
    unsafe { *(address as *const u32) }
}

#[polkavm_derive::polkavm_export]
extern "C" fn atomic_fetch_add(value: usize) -> usize {
    unsafe {
        let output;
        core::arch::asm!(
            "amoadd.w a0, a1, (a0)",
            inout("a0") &mut GLOBAL => output,
            in("a1") value,
        );
        output
    }
}

#[polkavm_derive::polkavm_export]
extern "C" fn atomic_fetch_swap(value: usize) -> usize {
    unsafe {
        let output;
        core::arch::asm!(
            "amoswap.w a0, a1, (a0)",
            inout("a0") &mut GLOBAL => output,
            in("a1") value,
        );
        output
    }
}

#[polkavm_derive::polkavm_export]
extern "C" fn atomic_fetch_max_signed(value: isize) -> isize {
    unsafe {
        let output;
        core::arch::asm!(
            "amomax.w a0, a1, (a0)",
            inout("a0") &mut GLOBAL => output,
            in("a1") value,
        );
        output
    }
}

#[polkavm_derive::polkavm_export]
extern "C" fn atomic_fetch_min_signed(value: isize) -> isize {
    unsafe {
        let output;
        core::arch::asm!(
            "amomin.w a0, a1, (a0)",
            inout("a0") &mut GLOBAL => output,
            in("a1") value,
        );
        output
    }
}

#[polkavm_derive::polkavm_export]
extern "C" fn atomic_fetch_max_unsigned(value: usize) -> usize {
    unsafe {
        let output;
        core::arch::asm!(
            "amomaxu.w a0, a1, (a0)",
            inout("a0") &mut GLOBAL => output,
            in("a1") value,
        );
        output
    }
}

#[polkavm_derive::polkavm_export]
extern "C" fn atomic_fetch_min_unsigned(value: usize) -> usize {
    unsafe {
        let output;
        core::arch::asm!(
            "amominu.w a0, a1, (a0)",
            inout("a0") &mut GLOBAL => output,
            in("a1") value,
        );
        output
    }
}

#[polkavm_derive::polkavm_export]
extern "C" fn call_sbrk(size: usize) -> *mut u8 {
    polkavm_derive::sbrk(size)
}

#[polkavm_derive::polkavm_import]
extern "C" {
    fn call_sbrk_indirectly_impl(size: usize) -> usize;
}

#[polkavm_derive::polkavm_export]
extern "C" fn call_sbrk_indirectly(size: usize) -> *mut u8 {
    unsafe { call_sbrk_indirectly_impl(size) as *mut u8 }
}

// Test that an unused import will be stripped.
#[polkavm_derive::polkavm_import]
extern "C" {
    fn unused_import(value: u32) -> u32;
}

// Test duplicate imports.
mod a {
    #[polkavm_derive::polkavm_import]
    extern "C" {
        pub fn multiply_by_2(value: u32) -> u32;
    }
}

mod b {
    #[polkavm_derive::polkavm_import]
    extern "C" {
        pub fn multiply_by_2(value: u32) -> u32;
    }
}

#[polkavm_derive::polkavm_export]
extern "C" fn test_multiply_by_6(value: u32) -> u32 {
    unsafe { a::multiply_by_2(value * 3) }
}

#[polkavm_derive::polkavm_define_abi(allow_extra_input_registers)]
mod test_abi {}

#[cfg(target_pointer_width = "32")]
impl test_abi::FromHost for f32 {
    type Regs = (u32,);
    fn from_host((a0,): Self::Regs) -> Self {
        f32::from_bits(a0)
    }
}

#[cfg(target_pointer_width = "32")]
impl test_abi::IntoHost for f32 {
    type Regs = (u32,);
    type Destructor = ();
    fn into_host(value: f32) -> (Self::Regs, Self::Destructor) {
        ((value.to_bits(),), ())
    }
}

#[cfg(target_pointer_width = "64")]
impl test_abi::FromHost for f32 {
    type Regs = (u64,);
    fn from_host((a0,): Self::Regs) -> Self {
        f32::from_bits(a0 as u32)
    }
}

#[cfg(target_pointer_width = "64")]
impl test_abi::IntoHost for f32 {
    type Regs = (u64,);
    type Destructor = ();
    fn into_host(value: f32) -> (Self::Regs, Self::Destructor) {
        ((u64::from(value.to_bits()),), ())
    }
}

#[polkavm_derive::polkavm_import(abi = self::test_abi)]
extern "C" {
    #[polkavm_import(symbol = "identity")]
    fn identity_f32(value: f32) -> f32;

    #[allow(clippy::too_many_arguments)]
    fn multiply_all_input_registers(a0: u32, a1: u32, a2: u32, a3: u32, a4: u32, a5: u32, t0: u32, t1: u32, t2: u32) -> u32;
}

#[polkavm_derive::polkavm_export]
fn test_define_abi() {
    assert_eq!(unsafe { identity_f32(1.23) }, 1.23);
}

#[polkavm_derive::polkavm_export]
fn test_input_registers() {
    assert_eq!(
        unsafe { multiply_all_input_registers(2, 3, 5, 7, 11, 13, 17, 19, 23) },
        2 * 3 * 5 * 7 * 11 * 13 * 17 * 19 * 23
    );
}
