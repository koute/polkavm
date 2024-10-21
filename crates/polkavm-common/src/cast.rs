//! This module defines an explicit casting facility to replace Rust's built-in `as` casts.
//! The general idea is:
//!   * Casts should be usable everywhere, including in `const fn`s (which means we can't use traits).
//!   * Casts should fail to compile if a) the source or the target type changes, and b) the cast between the new pair of types would now be incorrect.
//!   * `usize` is assumed to be always at least 32-bit.

#[allow(non_camel_case_types)]
#[repr(transparent)]
pub struct cast<T>(pub T);

impl cast<i8> {
    #[inline(always)]
    pub const fn to_i32_sign_extend(self) -> i32 {
        self.0 as i32
    }
}

impl cast<i16> {
    #[inline(always)]
    pub const fn to_i32_sign_extend(self) -> i32 {
        self.0 as i32
    }
}

impl cast<i32> {
    #[inline(always)]
    pub const fn to_unsigned(self) -> u32 {
        self.0 as u32
    }
}

impl cast<i64> {
    #[inline(always)]
    pub const fn to_unsigned(self) -> u64 {
        self.0 as u64
    }
}

impl cast<u8> {
    #[inline(always)]
    pub const fn to_signed(self) -> i8 {
        self.0 as i8
    }
}

impl cast<u32> {
    #[inline(always)]
    pub const fn to_signed(self) -> i32 {
        self.0 as i32
    }

    #[inline(always)]
    pub const fn to_u64(self) -> u64 {
        self.0 as u64
    }

    #[inline(always)]
    pub const fn to_usize(self) -> usize {
        self.0 as usize
    }

    #[inline(always)]
    pub const fn truncate_to_u8(self) -> u8 {
        self.0 as u8
    }

    #[inline(always)]
    pub const fn truncate_to_u16(self) -> u16 {
        self.0 as u16
    }
}

impl cast<u64> {
    #[inline(always)]
    pub const fn assert_always_fits_in_u32(self) -> u32 {
        debug_assert!(self.0 <= u32::MAX as u64);
        self.0 as u32
    }

    #[inline(always)]
    pub const fn to_signed(self) -> i64 {
        self.0 as i64
    }
}

impl cast<usize> {
    #[inline(always)]
    pub const fn assert_always_fits_in_u32(self) -> u32 {
        debug_assert!(self.0 <= u32::MAX as usize);
        self.0 as u32
    }

    #[inline(always)]
    pub const fn to_u64(self) -> u64 {
        self.0 as u64
    }
}
