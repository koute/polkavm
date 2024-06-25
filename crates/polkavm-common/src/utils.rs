use core::mem::MaybeUninit;
use core::ops::{Deref, Range};

#[cfg(feature = "alloc")]
use alloc::{borrow::Cow, sync::Arc, vec::Vec};

use crate::program::Reg;

#[derive(Clone, Debug, Default)]
pub struct ArcBytes {
    #[cfg(feature = "alloc")]
    data: Option<Arc<[u8]>>,
    #[cfg(not(feature = "alloc"))]
    data: &'static [u8],
    range: Range<usize>,
}

impl ArcBytes {
    pub(crate) fn subslice(&self, subrange: Range<usize>) -> Self {
        if subrange.start == subrange.end {
            return Default::default();
        }

        let start = self.range.start + subrange.start;
        let end = self.range.start + subrange.end;
        assert!(start <= self.range.end);
        assert!(end <= self.range.end);

        ArcBytes {
            #[allow(noop_method_call)]
            data: self.data.clone(),
            range: start..end,
        }
    }
}

impl Eq for ArcBytes {}

impl PartialEq for ArcBytes {
    fn eq(&self, rhs: &ArcBytes) -> bool {
        self.deref() == rhs.deref()
    }
}

#[cfg(feature = "alloc")]
impl Deref for ArcBytes {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        const EMPTY: &[u8] = &[];
        let slice = self.data.as_ref().map_or(EMPTY, |slice| &slice[..]);
        &slice[self.range.clone()]
    }
}

#[cfg(not(feature = "alloc"))]
impl Deref for ArcBytes {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.data[self.range.clone()]
    }
}

impl AsRef<[u8]> for ArcBytes {
    fn as_ref(&self) -> &[u8] {
        self.deref()
    }
}

#[cfg(feature = "alloc")]
impl<'a> From<&'a [u8]> for ArcBytes {
    fn from(data: &'a [u8]) -> Self {
        ArcBytes {
            data: Some(data.into()),
            range: 0..data.len(),
        }
    }
}

#[cfg(not(feature = "alloc"))]
impl<'a> From<&'static [u8]> for ArcBytes {
    fn from(data: &'static [u8]) -> Self {
        ArcBytes {
            data,
            range: 0..data.len(),
        }
    }
}

#[cfg(feature = "alloc")]
impl From<Vec<u8>> for ArcBytes {
    fn from(data: Vec<u8>) -> Self {
        ArcBytes {
            range: 0..data.len(),
            data: Some(data.into()),
        }
    }
}

#[cfg(feature = "alloc")]
impl From<Arc<[u8]>> for ArcBytes {
    fn from(data: Arc<[u8]>) -> Self {
        ArcBytes {
            range: 0..data.len(),
            data: Some(data),
        }
    }
}

#[cfg(feature = "alloc")]
impl<'a> From<Cow<'a, [u8]>> for ArcBytes {
    fn from(cow: Cow<'a, [u8]>) -> Self {
        match cow {
            Cow::Borrowed(data) => data.into(),
            Cow::Owned(data) => data.into(),
        }
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

define_align_to_next_page!(align_to_next_page_u32, u32);
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
        // SAFETY: `MaybeUnunit<T>` is guaranteed to have the same representation as `T`,
        //         so casting `[T]` into `[MaybeUninit<T>]` is safe.
        unsafe {
            core::slice::from_raw_parts_mut(self.as_mut_ptr().cast(), self.len())
        }
    }
}

impl<const N: usize> AsUninitSliceMut for MaybeUninit<[u8; N]> {
    fn as_uninit_slice_mut(&mut self) -> &mut [MaybeUninit<u8>] {
        #[allow(unsafe_code)]
        // SAFETY: `MaybeUnunit<T>` is guaranteed to have the same representation as `T`,
        //         so casting `[T; N]` into `[MaybeUninit<T>]` is safe.
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

/// A gas value used for gas metering.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default)]
#[repr(transparent)]
pub struct Gas(u64);

impl core::fmt::Display for Gas {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
        self.0.fmt(fmt)
    }
}

impl Gas {
    /// The maximum possible available gas.
    pub const MAX: Self = Gas(i64::MAX as u64);

    /// The minimum possible available gas.
    pub const MIN: Self = Gas(0);

    /// Constructs a new gas value. Alias for [`Gas::from_u64`].
    pub const fn new(gas: u64) -> Option<Self> {
        Self::from_u64(gas)
    }

    /// Constructs a new gas value from an `u64`, checking whether it's in range between [`Gas::MIN`] and [`Gas::MAX`].
    pub const fn from_u64(gas: u64) -> Option<Self> {
        let gas = Self(gas);
        if gas.0 > Self::MAX.0 {
            None
        } else {
            Some(gas)
        }
    }

    /// Constructs a new gas value from an `i64`, checking whether it's in range between [`Gas::MIN`] and [`Gas::MAX`].
    pub const fn from_i64(gas: i64) -> Option<Self> {
        Self::from_u64(gas as u64)
    }

    /// Gets the raw gas value.
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Checks whether there is no gas remaining.
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

impl From<u32> for Gas {
    fn from(gas: u32) -> Self {
        Gas(u64::from(gas))
    }
}

impl TryFrom<u64> for Gas {
    type Error = &'static str;
    fn try_from(gas: u64) -> Result<Self, Self::Error> {
        Self::from_u64(gas).ok_or("out of range gas")
    }
}

impl TryFrom<i64> for Gas {
    type Error = &'static str;
    fn try_from(gas: i64) -> Result<Self, Self::Error> {
        Self::from_i64(gas).ok_or("out of range gas")
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

    fn sbrk(&mut self, size: u32) -> Option<u32>;

    /// Returns the current size of the program's heap.
    fn heap_size(&self) -> u32;

    fn program_counter(&self) -> Option<u32>;
    fn native_program_counter(&self) -> Option<u64>;

    /// Gets the amount of gas remaining, or `None` if gas metering is not enabled for this instance.
    ///
    /// Note that this being zero doesn't necessarily mean that the execution ran out of gas,
    /// if the program ended up consuming *exactly* the amount of gas that it was provided with!
    fn gas_remaining(&self) -> Option<Gas>;

    fn consume_gas(&mut self, gas: u64);

    #[cfg(feature = "alloc")]
    fn read_memory_into_vec(&self, address: u32, length: u32) -> Result<Vec<u8>, Self::Error> {
        let mut buffer = Vec::new();
        buffer.reserve_exact(length as usize);

        let pointer = buffer.as_ptr();
        let slice = self.read_memory_into_slice(address, buffer.spare_capacity_mut())?;

        // Since `read_memory_into_slice` returns a `&mut [u8]` we can be sure it initialized the buffer
        // we've passed to it, as long as it's actually the same buffer we gave it.
        assert_eq!(slice.as_ptr(), pointer);
        assert_eq!(slice.len(), length as usize);

        #[allow(unsafe_code)]
        // SAFETY: `read_memory_into_slice` initialized this buffer, and we've verified this with `assert`s.
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
    // SAFETY: The caller is responsible for making sure the `slice` was properly initialized.
    unsafe { &mut *(slice as *mut [MaybeUninit<T>] as *mut [T]) }
}

#[allow(unsafe_code)]
pub fn byte_slice_init<'dst>(dst: &'dst mut [MaybeUninit<u8>], src: &[u8]) -> &'dst mut [u8] {
    assert_eq!(dst.len(), src.len());

    let length = dst.len();
    let src_ptr: *const u8 = src.as_ptr();
    let dst_ptr: *mut u8 = dst.as_mut_ptr().cast::<u8>();

    // SAFETY: Both pointers are valid and are guaranteed to point to a region of memory
    // at least `length` bytes big.
    unsafe {
        core::ptr::copy_nonoverlapping(src_ptr, dst_ptr, length);
    }

    // SAFETY: We've just initialized this slice.
    unsafe { slice_assume_init_mut(dst) }
}

pub fn parse_imm(text: &str) -> Option<i32> {
    let text = text.trim();
    if let Some(text) = text.strip_prefix("0x") {
        return u32::from_str_radix(text, 16).ok().map(|value| value as i32);
    }

    if let Some(text) = text.strip_prefix("0b") {
        return u32::from_str_radix(text, 2).ok().map(|value| value as i32);
    }

    if let Ok(value) = text.parse::<i32>() {
        Some(value)
    } else if let Ok(value) = text.parse::<u32>() {
        Some(value as i32)
    } else {
        None
    }
}

pub fn parse_reg(text: &str) -> Option<Reg> {
    const REG_NAME_ALT: [&str; 13] = ["r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12"];

    let text = text.trim();
    for (reg, name_alt) in Reg::ALL.into_iter().zip(REG_NAME_ALT) {
        if text == reg.name() || text == name_alt {
            return Some(reg);
        }
    }

    None
}
