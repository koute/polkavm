#![allow(clippy::same_name_method)]

use polkavm_common::cast::cast;

pub trait RawMask:
    Copy
    + core::ops::BitOrAssign<Self>
    + core::ops::BitAndAssign<Self>
    + core::ops::Shl<u32, Output = Self>
    + core::ops::Sub<Output = Self>
    + core::ops::BitAnd<Output = Self>
    + core::ops::Not<Output = Self>
    + PartialEq
    + Eq
    + core::fmt::Debug
{
    const ZERO: Self;
    const ONE: Self;

    fn trailing_zeros(self) -> u32;
    fn lowest_set_bit_after(self, bit_index: u32) -> u32 {
        let mask_before = (Self::ONE << bit_index) - Self::ONE;
        let mask_after = !mask_before;
        let bits_after = self & mask_after;
        if bits_after == Self::ZERO {
            u32::MAX
        } else {
            bits_after.trailing_zeros()
        }
    }
}

macro_rules! impl_traits {
    ($($type:ty),*) => {
        $(
            impl RawMask for $type {
                const ZERO: Self = 0;
                const ONE: Self = 1;

                fn trailing_zeros(self) -> u32 {
                    <$type>::trailing_zeros(self)
                }
            }
        )*
    }
}

impl_traits! {
    u8,
    u16,
    u32,
    u64,
    usize
}

#[derive(Copy, Clone, Debug)]
pub struct BitIndex<Primary, Secondary> {
    index: u32,
    primary: u32,
    secondary: u32,
    _phantom: core::marker::PhantomData<(Primary, Secondary)>,
}

impl<Primary, Secondary> PartialEq for BitIndex<Primary, Secondary> {
    fn eq(&self, rhs: &Self) -> bool {
        let is_equal = self.index == rhs.index;
        debug_assert_eq!(is_equal, self.primary == rhs.primary);
        debug_assert_eq!(is_equal, self.secondary == rhs.secondary);
        is_equal
    }
}

impl<Primary, Secondary> Eq for BitIndex<Primary, Secondary> {}

impl<Primary, Secondary> BitIndex<Primary, Secondary> {
    #[inline]
    pub fn index(&self) -> usize {
        cast(self.index).to_usize()
    }
}

/// A constant-length two-level bitmask.
#[derive(Debug)]
pub struct BitMask<Primary, Secondary, const SECONDARY_LENGTH: usize>
where
    Primary: RawMask,
    Secondary: RawMask,
{
    /// The primary mask. This mask is used to mark which secondary masks are non-empty.
    primary_mask: Primary,

    /// Secondary masks. These contain the actual bits that the `BitMask` stores.
    secondary_masks: [Secondary; SECONDARY_LENGTH],
}

// TODO: Remove this once this is fixed: https://github.com/rust-lang/rust/issues/60551
#[doc(hidden)]
#[macro_export]
macro_rules! _bitmask_type {
    ($primary:ty, $secondary:ty, $bits:expr) => {
        $crate::bit_mask::BitMask<$primary, $secondary, {
            let bits_per_item = ::core::mem::size_of::<$secondary>() * 8;
            let mut items = $bits / bits_per_item;
            if $bits % bits_per_item != 0 {
                items += 1;
            }

            items
        }>
    }
}

pub use _bitmask_type as bitmask_type;

#[test]
fn test_bitmask_basic() {
    // Width deliberately set to '9' to test the rounding up.
    type Mask16 = bitmask_type!(u8, u8, 9);
    let mut mask = Mask16::new();
    mask.set(Mask16::index(0));
    assert_eq!(mask.primary_mask, 0b00000001);
    assert_eq!(mask.secondary_masks, [0b00000001, 0b00000000]);

    mask.set(Mask16::index(7));
    assert_eq!(mask.primary_mask, 0b00000001);
    assert_eq!(mask.secondary_masks, [0b10000001, 0b00000000]);

    mask.set(Mask16::index(8));
    assert_eq!(mask.primary_mask, 0b00000011);
    assert_eq!(mask.secondary_masks, [0b10000001, 0b00000001]);

    mask.unset(Mask16::index(0));
    assert_eq!(mask.primary_mask, 0b00000011);
    assert_eq!(mask.secondary_masks, [0b10000000, 0b00000001]);

    mask.unset(Mask16::index(7));
    assert_eq!(mask.primary_mask, 0b00000010);
    assert_eq!(mask.secondary_masks, [0b00000000, 0b00000001]);

    mask.set(Mask16::index(15));
    assert_eq!(mask.primary_mask, 0b00000010);
    assert_eq!(mask.secondary_masks, [0b00000000, 0b10000001]);

    // The biggest mask we can make when using `u8`s.
    type Mask64 = bitmask_type!(u8, u8, 64);
    let mut mask = Mask64::new();
    assert_eq!(mask.primary_mask, 0b00000000);
    assert_eq!(mask.secondary_masks, [0, 0, 0, 0, 0, 0, 0, 0]);
    mask.set(Mask64::index(63));
    assert_eq!(mask.primary_mask, 0b10000000);
    assert_eq!(mask.secondary_masks, [0, 0, 0, 0, 0, 0, 0, 0b10000000]);
}

#[test]
#[should_panic]
fn test_bitmask_out_of_range() {
    type Mask16 = bitmask_type!(u8, u8, 9);
    let mut mask = Mask16::new();
    mask.set(Mask16::index(16));
}

impl<Primary, Secondary, const SECONDARY_LENGTH: usize> Default for BitMask<Primary, Secondary, SECONDARY_LENGTH>
where
    Primary: RawMask,
    Secondary: RawMask,
{
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl<Primary, Secondary, const SECONDARY_LENGTH: usize> BitMask<Primary, Secondary, SECONDARY_LENGTH>
where
    Primary: RawMask,
    Secondary: RawMask,
{
    const PRIMARY_BIN_SHIFT: u32 = (core::mem::size_of::<Secondary>() * 8).ilog2();
    const SECONDARY_BIN_MASK: u32 = (1 << Self::PRIMARY_BIN_SHIFT) - 1;

    const ASSERT_TYPES_ARE_BIG_ENOUGH_FOR_THE_DESIRED_BIT_WIDTH: () = {
        if SECONDARY_LENGTH > core::mem::size_of::<Primary>() * 8 {
            panic!("the given raw mask types are too narrow to fit a bit mask of the the desired bit length");
        }
    };

    /// Creates a new empty bitmask.
    #[inline]
    pub fn new() -> Self {
        let () = Self::ASSERT_TYPES_ARE_BIG_ENOUGH_FOR_THE_DESIRED_BIT_WIDTH;

        BitMask {
            primary_mask: Primary::ZERO,
            secondary_masks: [Secondary::ZERO; SECONDARY_LENGTH],
        }
    }

    /// Converts a raw `index` into a `BitIndex`.
    #[inline]
    pub fn index(index: u32) -> BitIndex<Primary, Secondary> {
        let primary = index >> Self::PRIMARY_BIN_SHIFT;
        let secondary = index & Self::SECONDARY_BIN_MASK;
        BitIndex {
            index,
            primary,
            secondary,
            _phantom: core::marker::PhantomData,
        }
    }

    /// Sets the bit at `index`.
    #[inline]
    pub fn set(&mut self, index: BitIndex<Primary, Secondary>) {
        self.secondary_masks[cast(index.primary).to_usize()] |= Secondary::ONE << index.secondary;
        self.primary_mask |= Primary::ONE << index.primary;
    }

    /// Clears the bit at `index`.
    #[inline]
    pub fn unset(&mut self, index: BitIndex<Primary, Secondary>) {
        self.secondary_masks[cast(index.primary).to_usize()] &= !(Secondary::ONE << index.secondary);
        if self.secondary_masks[cast(index.primary).to_usize()] == Secondary::ZERO {
            self.primary_mask &= !(Primary::ONE << index.primary);
        }
    }

    /// Finds the first set bit, starting at `min_index`.
    #[inline]
    pub fn find_first(&mut self, min_index: BitIndex<Primary, Secondary>) -> Option<BitIndex<Primary, Secondary>> {
        let mut primary = min_index.primary;
        let mut secondary = u32::MAX;

        if (self.primary_mask & (Primary::ONE << primary)) != Primary::ZERO {
            secondary = self.secondary_masks[cast(primary).to_usize()].lowest_set_bit_after(min_index.secondary);
        }

        if secondary == u32::MAX {
            primary = self.primary_mask.lowest_set_bit_after(min_index.primary + 1);
            if primary == u32::MAX {
                return None;
            }

            secondary = self.secondary_masks[cast(primary).to_usize()].trailing_zeros();
        }

        Some(BitIndex {
            index: (primary << Self::PRIMARY_BIN_SHIFT) | secondary,
            primary,
            secondary,
            _phantom: core::marker::PhantomData,
        })
    }
}
