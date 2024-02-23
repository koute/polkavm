#![no_std]
#![doc = include_str!("../README.md")]

pub use polkavm_derive_impl_macro::__PRIVATE_DO_NOT_USE_polkavm_define_abi as polkavm_define_abi;
pub use polkavm_derive_impl_macro::__PRIVATE_DO_NOT_USE_polkavm_export as polkavm_export;
pub use polkavm_derive_impl_macro::__PRIVATE_DO_NOT_USE_polkavm_import as polkavm_import;

pub mod default_abi {
    polkavm_derive_impl_macro::__PRIVATE_DO_NOT_USE_polkavm_impl_abi_support!();
}

/// Increases the size of the program's heap by a given number of bytes, allocating memory if necessary.
/// If successful returns a pointer to the *end* of the heap. If unsuccessful returns a null pointer.
///
/// When called with a `size` of 0 this can be used to find the current end of the heap. This will always succeed.
///
/// Memory allocated through this function can only be freed once the program finishes execution and its whole memory is cleared.
#[cfg(any(all(any(target_arch = "riscv32", target_arch = "riscv64"), target_feature = "e"), doc))]
#[inline]
pub fn sbrk(size: usize) -> *mut u8 {
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

/// A basic memory allocator which doesn't support deallocation.
pub struct LeakingAllocator;

#[cfg(any(all(any(target_arch = "riscv32", target_arch = "riscv64"), target_feature = "e"), doc))]
unsafe impl core::alloc::GlobalAlloc for LeakingAllocator {
    #[inline]
    unsafe fn alloc(&self, layout: core::alloc::Layout) -> *mut u8 {
        let pointer = crate::sbrk(0);
        let padding = (-(pointer as isize)) as usize & (layout.align() - 1);
        let size = layout.size().wrapping_add(padding);
        if crate::sbrk(size).is_null() {
            return core::ptr::null_mut();
        }

        pointer.add(padding)
    }

    #[inline]
    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: core::alloc::Layout) {}
}
