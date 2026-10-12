extern crate alloc;
use alloc::vec::Vec;

polkavm_derive::min_stack_size!(1);
polkavm_derive::min_stack_size!(65536);
polkavm_derive::min_stack_size!(2);

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
    core::ptr::addr_of_mut!(GLOBAL)
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
extern "C" fn atomic_fetch_swap_with_zero() -> usize {
    unsafe {
        let output;
        core::arch::asm!(
            "amoswap.w.rl a0, zero, (a0)",
            inout("a0") &mut GLOBAL => output
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

#[cfg(any(all(any(target_arch = "riscv32", target_arch = "riscv64"), target_feature = "e"), doc))]
#[inline]
fn sbrk(size: usize) -> *mut u8 {
    // SAFETY: Allocating memory is always safe.
    unsafe {
        let address;
        core::arch::asm!(
            ".insn r 0xb, 1, 0, {dst}, {size}, zero",
            size = in(reg) size,
            dst = lateout(reg) address,
        );
        address
    }
}

#[polkavm_derive::polkavm_export]
extern "C" fn call_sbrk(size: usize) -> *mut u8 {
    sbrk(size)
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

#[polkavm_derive::polkavm_export]
extern "C" fn add_u32(a0: u32, a1: u32) -> u32 {
    a0.wrapping_add(a1)
}

#[cfg(target_pointer_width = "64")]
#[polkavm_derive::polkavm_export]
extern "C" fn add_u32_asm(a0: u32, a1: u32) -> u64 {
    unsafe {
        let output;
        core::arch::asm!(
            "addw a2, a1, a0",
            in("a0") a0,
            in("a1") a1,
            lateout("a2") output,
        );
        output
    }
}

#[polkavm_derive::polkavm_export]
extern "C" fn add_u64(a0: u64, a1: u64) -> u64 {
    a0.wrapping_add(a1)
}

#[polkavm_derive::polkavm_export]
extern "C" fn xor_imm_u32(a0: u32) -> u32 {
    a0 ^ 0xfb8f5c1e
}

#[polkavm_derive::polkavm_export]
extern "C" fn test_branch_less_than_zero() {
    unsafe {
        #[cfg(target_arch = "riscv64")]
        let mut output: usize = 0xff00000000000000;
        #[cfg(target_arch = "riscv32")]
        let mut output: usize = 0xff000000;
        core::arch::asm!(
            "bltz a0, 1f",
            "li a0, 0",
            "j 2f",
            "1:",
            "li a0, 1",
            "2:",
            inout("a0") output,
        );
        assert_eq!(output, 1);
    }
}

static ATOMIC_U64: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

// TODO: The linker should handle this automatically.
#[cfg(target_pointer_width = "32")]
#[no_mangle]
unsafe extern "C" fn __atomic_fetch_add_8(address: *mut u64, new_value: u64) -> u64 {
    unsafe {
        let old_value = *address;
        *address += new_value;
        old_value
    }
}

#[polkavm_derive::polkavm_export]
extern "C" fn fetch_add_atomic_u64(a0: u64) -> u64 {
    ATOMIC_U64.fetch_add(a0, core::sync::atomic::Ordering::Relaxed)
}

#[polkavm_derive::polkavm_export]
extern "C" fn cmov_if_zero_with_zero_reg() {
    unsafe {
        let output: usize;
        core::arch::asm!(
            // th.mveqz
            "li a0, 1",
            "li a1, 2",
            // a0 = a1 if zero == 0
            ".insn r 11, 1, 32, a0, a1, zero",
            out("a0") output,
            out("a1") _,
        );
        assert_eq!(output, 2);
    }
}

#[polkavm_derive::polkavm_export]
extern "C" fn cmov_if_not_zero_with_zero_reg() {
    unsafe {
        let output: usize;
        core::arch::asm!(
            // th.mvnez
            "li a0, 1",
            "li a1, 2",
            // a0 = a1 if zero != 0
            ".insn r 11, 1, 33, a0, a1, zero",
            out("a0") output,
            out("a1") _,
        );
        assert_eq!(output, 1);
    }
}

#[polkavm_derive::polkavm_export]
extern "C" fn negate_and_add(mut a0: isize, a1: isize) -> isize {
    unsafe {
        core::arch::asm!(
            "li a2, 16",
            "sub a0, a2, a1",
            "li a2, 0",
            inout("a0") a0 => a0,
            in("a1") a1,
            out("a2") _,
        );
    }

    a0
}

#[cfg(target_pointer_width = "32")]
#[polkavm_derive::polkavm_import]
extern "C" {
    fn return_tuple_u32() -> (u32, u32);
}

#[cfg(target_pointer_width = "64")]
#[polkavm_derive::polkavm_import]
extern "C" {
    fn return_tuple_u64() -> (u64, u64);
}

#[polkavm_derive::polkavm_import]
extern "C" {
    fn return_tuple_usize() -> (usize, usize);
}

#[polkavm_derive::polkavm_export]
extern "C" fn test_return_tuple() {
    #[cfg(target_pointer_width = "32")]
    {
        assert_eq!(unsafe { return_tuple_u32() }, (0x12345678, 0x9abcdefe));
        assert_eq!(unsafe { return_tuple_usize() }, (0x12345678, 0x9abcdefe));
    }

    #[cfg(target_pointer_width = "64")]
    {
        assert_eq!(unsafe { return_tuple_u64() }, (0x123456789abcdefe, 0x1122334455667788));
        assert_eq!(unsafe { return_tuple_usize() }, (0x123456789abcdefe, 0x1122334455667788));
    }
}

#[cfg(target_pointer_width = "32")]
#[polkavm_derive::polkavm_export]
extern "C" fn export_return_tuple_u32() -> (u32, u32) {
    (0x12345678, 0x9abcdefe)
}

#[cfg(target_pointer_width = "64")]
#[polkavm_derive::polkavm_export]
extern "C" fn export_return_tuple_u64() -> (u64, u64) {
    (0x123456789abcdefe, 0x1122334455667788)
}

#[polkavm_derive::polkavm_export]
extern "C" fn export_return_tuple_usize() -> (usize, usize) {
    #[cfg(target_pointer_width = "32")]
    {
        (0x12345678, 0x9abcdefe)
    }

    #[cfg(target_pointer_width = "64")]
    {
        (0x123456789abcdefe, 0x1122334455667788)
    }
}

#[polkavm_derive::polkavm_export]
extern "C" fn get_heap_base() -> u32 {
    polkavm_derive::heap_base() as u32
}

#[inline(never)]
fn get_self_address_impl() -> usize {
    unsafe { GLOBAL += 1; }
    get_self_address_impl as usize
}

#[polkavm_derive::polkavm_export]
extern "C" fn get_self_address() -> u32 {
    get_self_address_impl() as u32
}

#[unsafe(naked)]
extern "C" fn get_self_address_naked_impl() -> usize {
    core::arch::naked_asm!(
        ".option norvc",
        "nop",
        "auipc a4, 0x0",
        "addi  a0, a4, -4",
        "ret",
        ".option rvc"
    )
}

#[polkavm_derive::polkavm_export]
fn get_self_address_naked() -> u32 {
    let address = get_self_address_naked_impl();
    assert_eq!(get_self_address_naked_impl as usize, address);
    address as u32
}

#[unsafe(naked)]
extern "C" fn infinite_loop_without_relocation() {
    core::arch::naked_asm!(
        ".option norvc",
        "auipc ra, 0",
        "jalr ra",
        ".option rvc"
    )
}

#[polkavm_derive::polkavm_export]
fn get_address_dummy() -> usize {
    // To make sure it's not removed as dead code.
    infinite_loop_without_relocation as usize
}

#[cfg(target_pointer_width = "64")]
#[polkavm_derive::polkavm_export]
extern "C" fn sub_i32_min_64(a0: u64) -> u64 {
    unsafe {
        let output;
        core::arch::asm!(
            "lui a1, 0x80000",
            "sub a0, a0, a1",
            "lui a1, 1",
            inout("a0") a0 => output,
        );
        output
    }
}

#[cfg(target_pointer_width = "64")]
#[polkavm_derive::polkavm_export]
extern "C" fn sub_i32_min_32(a0: u64) -> u64 {
    unsafe {
        let output;
        core::arch::asm!(
            "lui a1, 0x80000",
            "subw a0, a0, a1",
            "lui a1, 1",
            inout("a0") a0 => output,
        );
        output
    }
}

#[cfg(target_pointer_width = "64")]
#[polkavm_derive::polkavm_export]
extern "C" fn orn_zero_const_64() -> u64 {
    unsafe {
        let output;
        core::arch::asm!(
            "lui a0, 0x80000",
            "addi a0, a0, -2",
            "orn a0, zero, a0",
            out("a0") output,
        );
        output
    }
}

#[cfg(target_pointer_width = "64")]
#[polkavm_derive::polkavm_export]
extern "C" fn xnor_zero_const_64() -> u64 {
    unsafe {
        let output;
        core::arch::asm!(
            "lui a0, 0x80000",
            "addi a0, a0, -2",
            "xnor a0, a0, zero",
            out("a0") output,
        );
        output
    }
}

#[cfg(target_pointer_width = "64")]
#[polkavm_derive::polkavm_export]
extern "C" fn min_zero_const_64() -> u64 {
    unsafe {
        let output;
        core::arch::asm!(
            "lui a0, 0x80000",
            "addi a0, a0, -2",
            "min a0, a0, zero",
            out("a0") output,
        );
        output
    }
}

#[cfg(target_pointer_width = "64")]
#[polkavm_derive::polkavm_export]
extern "C" fn max_zero_const_64() -> u64 {
    unsafe {
        let output;
        core::arch::asm!(
            "lui a0, 0x80000",
            "addi a0, a0, -2",
            "max a0, a0, zero",
            out("a0") output,
        );
        output
    }
}

#[polkavm_derive::polkavm_export]
extern "C" fn jump_table_with_constant_index() -> u32 {
    unsafe {
        let output;
        core::arch::asm!(
            ".pushsection .rodata",
            ".p2align 2",
            "2:",
            ".word 3f - 2b",
            ".word 4f - 2b",
            ".popsection",
            "lla a1, 2b",
            "lw a0, 4(a1)",
            "add a0, a0, a1",
            "jr a0",
            "3:",
            "li a0, 1",
            "j 5f",
            "4:",
            "li a0, 2",
            "5:",
            out("a0") output,
            out("a1") _,
        );
        output
    }
}
