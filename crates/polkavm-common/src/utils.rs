use core::mem::MaybeUninit;

#[cfg(feature = "alloc")]
use alloc::{borrow::Cow, string::String, vec::Vec};

use crate::program::Reg;

/// A replacement for `alloc::borrow::Cow<[u8]>` which also works in pure no_std.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
#[repr(transparent)]
pub struct CowBytes<'a>(CowBytesImpl<'a>);

#[cfg(feature = "alloc")]
type CowBytesImpl<'a> = Cow<'a, [u8]>;

#[cfg(not(feature = "alloc"))]
type CowBytesImpl<'a> = &'a [u8];

impl<'a> CowBytes<'a> {
    #[cfg(feature = "alloc")]
    pub fn into_owned(self) -> CowBytes<'static> {
        match self.0 {
            Cow::Borrowed(data) => CowBytes(Cow::Owned(data.into())),
            Cow::Owned(data) => CowBytes(Cow::Owned(data)),
        }
    }
}

impl<'a> core::ops::Deref for CowBytes<'a> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<'a> From<&'a [u8]> for CowBytes<'a> {
    fn from(slice: &'a [u8]) -> Self {
        CowBytes(slice.into())
    }
}

#[cfg(feature = "alloc")]
impl<'a> From<Vec<u8>> for CowBytes<'a> {
    fn from(vec: Vec<u8>) -> Self {
        CowBytes(vec.into())
    }
}

#[cfg(feature = "alloc")]
impl<'a> From<Cow<'a, [u8]>> for CowBytes<'a> {
    fn from(cow: Cow<'a, [u8]>) -> Self {
        CowBytes(cow)
    }
}

/// A replacement for `alloc::borrow::Cow<str>` which also works in pure no_std.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
#[repr(transparent)]
pub struct CowString<'a>(CowStringImpl<'a>);

#[cfg(feature = "alloc")]
type CowStringImpl<'a> = Cow<'a, str>;

#[cfg(not(feature = "alloc"))]
type CowStringImpl<'a> = &'a str;

impl<'a> CowString<'a> {
    #[cfg(feature = "alloc")]
    pub fn into_owned(self) -> CowString<'static> {
        match self.0 {
            Cow::Borrowed(string) => CowString(Cow::Owned(string.into())),
            Cow::Owned(string) => CowString(Cow::Owned(string)),
        }
    }
}

impl<'a> core::ops::Deref for CowString<'a> {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<'a> From<&'a str> for CowString<'a> {
    fn from(slice: &'a str) -> Self {
        CowString(slice.into())
    }
}

#[cfg(feature = "alloc")]
impl<'a> From<String> for CowString<'a> {
    fn from(string: String) -> Self {
        CowString(string.into())
    }
}

#[cfg(feature = "alloc")]
impl<'a> From<Cow<'a, str>> for CowString<'a> {
    fn from(cow: Cow<'a, str>) -> Self {
        CowString(cow)
    }
}

impl<'a> core::fmt::Display for CowString<'a> {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
        fmt.write_str(self)
    }
}

macro_rules! define_align_to_next_page {
    ($name:ident, $type:ty) => {
        /// Aligns the `value` to the next `page_size`, or returns the `value` as-is if it's already aligned.
        #[inline]
        pub const fn $name(page_size: $type, value: $type) -> Option<$type> {
            assert!(
                page_size != 0 && (page_size & (page_size - 1)) == 0,
                "page size is not a power of two"
            );
            if value & page_size - 1 == 0 {
                Some(value)
            } else {
                if value <= <$type>::MAX - page_size {
                    Some((value + page_size) & !(page_size - 1))
                } else {
                    None
                }
            }
        }
    };
}

define_align_to_next_page!(align_to_next_page_u64, u64);
define_align_to_next_page!(align_to_next_page_usize, usize);

#[test]
fn test_align_to_next_page() {
    assert_eq!(align_to_next_page_u64(4096, 0), Some(0));
    assert_eq!(align_to_next_page_u64(4096, 1), Some(4096));
    assert_eq!(align_to_next_page_u64(4096, 4095), Some(4096));
    assert_eq!(align_to_next_page_u64(4096, 4096), Some(4096));
    assert_eq!(align_to_next_page_u64(4096, 4097), Some(8192));
    let max = (0x10000000000000000_u128 - 4096) as u64;
    assert_eq!(align_to_next_page_u64(4096, max), Some(max));
    assert_eq!(align_to_next_page_u64(4096, max + 1), None);
}

pub trait AsUninitSliceMut {
    fn as_uninit_slice_mut(&mut self) -> &mut [MaybeUninit<u8>];
}

impl AsUninitSliceMut for [MaybeUninit<u8>] {
    fn as_uninit_slice_mut(&mut self) -> &mut [MaybeUninit<u8>] {
        self
    }
}

impl AsUninitSliceMut for [u8] {
    fn as_uninit_slice_mut(&mut self) -> &mut [MaybeUninit<u8>] {
        #[allow(unsafe_code)]
        unsafe {
            core::slice::from_raw_parts_mut(self.as_mut_ptr().cast(), self.len())
        }
    }
}

impl<const N: usize> AsUninitSliceMut for MaybeUninit<[u8; N]> {
    fn as_uninit_slice_mut(&mut self) -> &mut [MaybeUninit<u8>] {
        #[allow(unsafe_code)]
        unsafe {
            core::slice::from_raw_parts_mut(self.as_mut_ptr().cast(), N)
        }
    }
}

impl<const N: usize> AsUninitSliceMut for [u8; N] {
    fn as_uninit_slice_mut(&mut self) -> &mut [MaybeUninit<u8>] {
        let slice: &mut [u8] = &mut self[..];
        slice.as_uninit_slice_mut()
    }
}

pub trait Access<'a> {
    type Error: core::fmt::Display;

    fn get_reg(&self, reg: Reg) -> u32;
    fn set_reg(&mut self, reg: Reg, value: u32);
    fn read_memory_into_slice<'slice, T>(&self, address: u32, buffer: &'slice mut T) -> Result<&'slice mut [u8], Self::Error>
    where
        T: ?Sized + AsUninitSliceMut;
    fn write_memory(&mut self, address: u32, data: &[u8]) -> Result<(), Self::Error>;
    fn program_counter(&self) -> Option<u32>;
    fn native_program_counter(&self) -> Option<u64>;

    #[cfg(feature = "alloc")]
    fn read_memory_into_new_vec(&self, address: u32, length: u32) -> Result<Vec<u8>, Self::Error> {
        let mut buffer = Vec::new();
        buffer.reserve_exact(length as usize);

        let pointer = buffer.as_ptr();
        let slice = self.read_memory_into_slice(address, buffer.spare_capacity_mut())?;

        // Since `read_memory_into_slice` returns a `&mut [u8]` we can be sure it initialized the buffer
        // we've passed to it, as long as it's actually the same buffer we gave it.
        assert_eq!(slice.as_ptr(), pointer);
        assert_eq!(slice.len(), length as usize);

        #[allow(unsafe_code)]
        unsafe {
            buffer.set_len(length as usize);
        }

        Ok(buffer)
    }
}

// Copied from `MaybeUninit::slice_assume_init_mut`.
// TODO: Remove this once this API is stabilized.
#[allow(clippy::missing_safety_doc)]
#[allow(unsafe_code)]
pub unsafe fn slice_assume_init_mut<T>(slice: &mut [MaybeUninit<T>]) -> &mut [T] {
    unsafe { &mut *(slice as *mut [MaybeUninit<T>] as *mut [T]) }
}

#[allow(unsafe_code)]
pub fn byte_slice_init<'dst>(dst: &'dst mut [MaybeUninit<u8>], src: &[u8]) -> &'dst mut [u8] {
    assert_eq!(dst.len(), src.len());

    unsafe {
        let length = dst.len();
        let src_ptr: *const u8 = src.as_ptr();
        let dst_ptr: *mut u8 = dst.as_mut_ptr().cast::<u8>();
        core::ptr::copy_nonoverlapping(src_ptr, dst_ptr, length);
        slice_assume_init_mut(dst)
    }
}
