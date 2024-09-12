use core::mem::replace;

#[rustfmt::skip] // Screws up the formatting otherwise.
macro_rules! define_for_size {
    ($d:tt $Size:ty) => {
        // This is based on: https://github.com/sebbbi/OffsetAllocator/blob/main/offsetAllocator.cpp
        #[doc(hidden)]
        #[inline]
        pub const fn to_bin_index<const MANTISSA_BITS: u32, const ROUND_UP: bool>(size: $Size) -> u32 {
            if size == 0 {
                return 0;
            }

            let mantissa_value = 1 << MANTISSA_BITS;
            if size < mantissa_value {
                // The first 2^MANTISSA_BITS buckets contain only a single element.
                return (size - 1) as u32;
            }

            let mantissa_start_bit: u32 = (core::mem::size_of::<$Size>() as u32 * 8 - 1 - size.leading_zeros()) - MANTISSA_BITS;
            let exponent = mantissa_start_bit + 1;
            let mut mantissa = (size >> mantissa_start_bit) & (mantissa_value - 1);

            if ROUND_UP {
                let low_bits_mask: $Size = (1 << mantissa_start_bit) - 1;
                if (size & low_bits_mask) != 0 {
                    mantissa += 1;
                }
            }

            let out = exponent << MANTISSA_BITS;
            let mantissa = mantissa as u32;
            if ROUND_UP {
                out + mantissa - 1
            } else {
                (out | mantissa) - 1
            }
        }

        #[doc(hidden)]
        pub const fn calculate_optimal_bin_config<PrimaryMask, SecondaryMask>(
            max_allocation_size: $Size,
            mut requested_max_bins: u32,
        ) -> super::AllocatorBinConfig {
            let true_max_bins = (core::mem::size_of::<PrimaryMask>() * 8 * ::core::mem::size_of::<SecondaryMask>() * 8) as u32;
            if true_max_bins < requested_max_bins {
                requested_max_bins = true_max_bins
            }

            macro_rules! try_all {
                ($d($mantissa_bits:expr),+) => {
                    $d(
                        let highest_bin_index = to_bin_index::<$mantissa_bits, true>(max_allocation_size);
                        if highest_bin_index < requested_max_bins {
                            return super::AllocatorBinConfig {
                                mantissa_bits: $mantissa_bits,
                                bin_count: highest_bin_index + 1
                            };
                        }
                    )+
                }
            }

            try_all! {
                8, 7, 6, 5, 4, 3, 2, 1
            }

            panic!("failed to calculate optimal configuration for the allocator");
        }
    };
}

#[cfg(kani)]
#[kani::proof]
fn proof_to_bin_index_rounded_up_is_never_less_than_rounded_down() {
    let size: u64 = kani::any();
    let bin_rounded_down = self::u64::to_bin_index::<8, false>(size);
    let bin_rounded_up = self::u64::to_bin_index::<8, true>(size);
    assert!(bin_rounded_down <= bin_rounded_up);
}

#[cfg(kani)]
#[kani::proof]
fn proof_bin_indexes_never_decrease_with_increasing_size() {
    let size: u64 = kani::any_where(|&size| size < u64::MAX);
    let current_bin = self::u64::to_bin_index::<8, false>(size);
    let next_bin = self::u64::to_bin_index::<8, false>(size + 1);
    assert!(next_bin >= current_bin);
}

#[cfg(kani)]
#[kani::proof]
fn proof_bitness_of_the_size_does_not_matter_when_calculating_the_bin_index() {
    let size: u32 = kani::any();
    let bin32 = self::u32::to_bin_index::<8, false>(size);
    let bin64 = self::u64::to_bin_index::<8, false>(u64::from(size));
    assert!(bin32 == bin64);
}

// Printing out the bucket ranges:
//
// ```rust
// const MANTISSA_BITS: u32 = 3;
// let mut lower_bound = 0;
// let mut bin = to_bin_index::<MANTISSA_BITS, true>(0);
//
// for n in 1..=u32::MAX {
//     let next_bin = to_bin_index::<MANTISSA_BITS, true>(n);
//     if bin != next_bin {
//         println!("{}: {}..={}", bin, lower_bound, n - 1);
//         lower_bound = n;
//         bin = next_bin;
//     }
// }
// println!("{}: {}..", bin, lower_bound);
// ```

#[test]
fn test_to_bin_index() {
    assert_eq!(self::u32::to_bin_index::<3, true>(0), 0);
    assert_eq!(self::u32::to_bin_index::<3, true>(1), 0);
    assert_eq!(self::u32::to_bin_index::<3, true>(2), 1);
}

#[doc(hidden)]
#[cfg_attr(test, derive(PartialEq, Debug))]
pub struct AllocatorBinConfig {
    pub mantissa_bits: u32,
    pub bin_count: u32,
}

#[test]
fn test_calculate_optimal_bin_config() {
    assert_eq!(
        self::u32::calculate_optimal_bin_config::<u64, u64>((i32::MAX as u32) / 4096, u32::MAX),
        AllocatorBinConfig {
            mantissa_bits: 8,
            bin_count: 3072
        }
    );

    assert_eq!(
        self::u32::calculate_optimal_bin_config::<u64, u64>((i32::MAX as u32) / 4096, 3072),
        AllocatorBinConfig {
            mantissa_bits: 8,
            bin_count: 3072
        }
    );

    assert_eq!(
        self::u32::calculate_optimal_bin_config::<u64, u64>((i32::MAX as u32) / 4096, 3071),
        AllocatorBinConfig {
            mantissa_bits: 7,
            bin_count: 1664
        }
    );
}

trait EmptyInit {
    fn empty_init() -> Self;
}

impl<const LENGTH: usize> EmptyInit for [u32; LENGTH] {
    #[inline]
    fn empty_init() -> Self {
        [EMPTY; LENGTH]
    }
}

trait BitIndexT: Copy + core::fmt::Debug {
    fn index(&self) -> usize;
}

trait BitMaskT: Default {
    type Index: BitIndexT;
    fn index(index: u32) -> Self::Index;
    fn set(&mut self, index: Self::Index);
    fn unset(&mut self, index: Self::Index);
    fn find_first(&mut self, min_index: Self::Index) -> Option<Self::Index>;
}

impl<Primary, Secondary> BitIndexT for crate::bit_mask::BitIndex<Primary, Secondary>
where
    Primary: Copy + core::fmt::Debug,
    Secondary: Copy + core::fmt::Debug,
{
    #[inline]
    fn index(&self) -> usize {
        Self::index(self)
    }
}

impl<Primary, Secondary, const SECONDARY_LENGTH: usize> BitMaskT for crate::bit_mask::BitMask<Primary, Secondary, SECONDARY_LENGTH>
where
    Primary: crate::bit_mask::RawMask,
    Secondary: crate::bit_mask::RawMask,
{
    type Index = crate::bit_mask::BitIndex<Primary, Secondary>;

    #[inline]
    fn index(index: u32) -> Self::Index {
        Self::index(index)
    }

    #[inline]
    fn set(&mut self, index: Self::Index) {
        Self::set(self, index)
    }

    #[inline]
    fn unset(&mut self, index: Self::Index) {
        Self::unset(self, index)
    }

    #[inline]
    fn find_first(&mut self, min_index: Self::Index) -> Option<Self::Index> {
        Self::find_first(self, min_index)
    }
}

pub trait SizeT:
    Copy
    + From<u32>
    + Ord
    + core::ops::Add<Output = Self>
    + core::ops::AddAssign
    + core::ops::Sub<Output = Self>
    + core::fmt::LowerHex
    + core::fmt::Debug
    + core::hash::Hash
{
    #[doc(hidden)]
    const ZERO: Self;
}

impl SizeT for u32 {
    const ZERO: Self = 0;
}

impl SizeT for u64 {
    const ZERO: Self = 0;
}

pub trait AllocatorConfig {
    #[doc(hidden)]
    type Size: SizeT;

    #[doc(hidden)]
    const MAX_ALLOCATION_SIZE: Self::Size;

    #[doc(hidden)]
    #[allow(private_bounds)]
    type BitMask: BitMaskT;

    #[doc(hidden)]
    #[allow(private_bounds)]
    type BinArray: core::ops::Index<usize, Output = u32> + core::ops::IndexMut<usize> + EmptyInit;

    #[doc(hidden)]
    fn to_bin_index<const ROUND_UP: bool>(size: Self::Size) -> u32;
}

pub mod u32 {
    define_for_size!($ u32);
}

#[cfg(any(kani, test, feature = "export-internals-for-testing"))]
pub mod u64 {
    define_for_size!($ u64);
}

// TODO: Remove this once this is fixed: https://github.com/rust-lang/rust/issues/60551
#[doc(hidden)]
#[macro_export]
macro_rules! _allocator_config {
    (
        impl AllocatorConfig for $type:ty {
            const MAX_ALLOCATION_SIZE: $Size:ident = $max_allocation_size:expr;
            const MAX_BINS: u32 = $max_bins:expr;
        }
    ) => {
        impl $crate::generic_allocator::AllocatorConfig for $type {
            type Size = $Size;
            const MAX_ALLOCATION_SIZE: $Size = $max_allocation_size;
            type BitMask = $crate::bit_mask::bitmask_type!(
                usize,
                usize,
                $crate::generic_allocator::$Size::calculate_optimal_bin_config::<usize, usize>($max_allocation_size, $max_bins).bin_count
                    as usize
            );
            type BinArray =
                [u32; $crate::generic_allocator::$Size::calculate_optimal_bin_config::<usize, usize>($max_allocation_size, $max_bins)
                    .bin_count as usize];

            fn to_bin_index<const ROUND_UP: bool>(size: $Size) -> u32 {
                const MANTISSA_BITS: u32 =
                    $crate::generic_allocator::$Size::calculate_optimal_bin_config::<usize, usize>($max_allocation_size, $max_bins)
                        .mantissa_bits;
                $crate::generic_allocator::$Size::to_bin_index::<MANTISSA_BITS, ROUND_UP>(size)
            }
        }
    };
}

pub use _allocator_config as allocator_config;

const EMPTY: u32 = u32::MAX;

#[derive(Clone, Debug)]
struct Node<Size> {
    next_by_address: u32,
    prev_by_address: u32,
    next_in_bin: u32,
    prev_in_bin: u32,
    offset: Size,
    size: Size,
    is_allocated: bool,
}

#[derive(Debug)]
pub struct GenericAllocator<C: AllocatorConfig> {
    nodes: Vec<Node<C::Size>>,
    unused_node_slots: Vec<u32>,
    bins_with_free_space: C::BitMask,
    first_unallocated_for_bin: C::BinArray,
}

#[derive(Copy, Clone, Debug)]
pub struct GenericAllocation<Size> {
    node: u32,
    offset: Size,
    size: Size,
}

impl<Size> GenericAllocation<Size>
where
    Size: SizeT,
{
    pub const EMPTY: GenericAllocation<Size> = GenericAllocation {
        node: EMPTY,
        offset: Size::ZERO,
        size: Size::ZERO,
    };

    pub fn is_empty(&self) -> bool {
        self.node == EMPTY
    }

    pub fn offset(&self) -> Size {
        self.offset
    }

    pub fn size(&self) -> Size {
        self.size
    }
}

impl<C> GenericAllocator<C>
where
    C: AllocatorConfig,
{
    pub fn new(total_space: C::Size) -> Self {
        let mut mutable = GenericAllocator {
            bins_with_free_space: C::BitMask::default(),
            first_unallocated_for_bin: C::BinArray::empty_init(),
            nodes: Vec::new(),
            unused_node_slots: Vec::new(),
        };

        mutable.insert_free_node(C::Size::from(0), total_space);
        mutable
    }

    fn size_to_bin_round_down(size: C::Size) -> <C::BitMask as BitMaskT>::Index {
        let size = core::cmp::min(size, C::MAX_ALLOCATION_SIZE);
        C::BitMask::index(C::to_bin_index::<false>(size))
    }

    fn size_to_bin_round_up(size: C::Size) -> <C::BitMask as BitMaskT>::Index {
        let size = core::cmp::min(size, C::MAX_ALLOCATION_SIZE);
        C::BitMask::index(C::to_bin_index::<true>(size))
    }

    fn insert_free_node(&mut self, offset: C::Size, size: C::Size) -> Option<u32> {
        if size == C::Size::from(0) {
            return None;
        }

        // Get the bin index; round down to make sure the node's size is at least as big as what the bin expects.
        let bin = Self::size_to_bin_round_down(size);

        let first_node_in_bin = self.first_unallocated_for_bin[bin.index()];
        let region = Node {
            next_by_address: EMPTY,
            prev_by_address: EMPTY,
            next_in_bin: first_node_in_bin,
            prev_in_bin: EMPTY,
            offset,
            size,
            is_allocated: false,
        };

        let new_node = if let Some(new_node) = self.unused_node_slots.pop() {
            self.nodes[new_node as usize] = region;
            new_node
        } else {
            let new_node = self.nodes.len() as u32;
            self.nodes.push(region);
            new_node
        };

        if let Some(first_node_in_bin) = self.nodes.get_mut(first_node_in_bin as usize) {
            first_node_in_bin.prev_in_bin = new_node
        } else {
            self.bins_with_free_space.set(bin);
        }

        self.first_unallocated_for_bin[bin.index()] = new_node;
        Some(new_node)
    }

    fn remove_node(&mut self, node: u32) {
        let prev_in_bin = self.nodes[node as usize].prev_in_bin;
        if prev_in_bin != EMPTY {
            let next_in_bin = self.nodes[node as usize].next_in_bin;
            self.nodes[prev_in_bin as usize].next_in_bin = next_in_bin;

            if let Some(next) = self.nodes.get_mut(next_in_bin as usize) {
                next.prev_in_bin = prev_in_bin;
            } else {
                debug_assert_eq!(next_in_bin, EMPTY);
            }
        } else {
            let bin = Self::size_to_bin_round_down(self.nodes[node as usize].size);
            self.remove_first_free_node(node, bin);
        }

        self.unused_node_slots.push(node);
    }

    #[inline]
    fn remove_first_free_node(&mut self, node: u32, bin: <C::BitMask as BitMaskT>::Index) {
        debug_assert_eq!(self.first_unallocated_for_bin[bin.index()], node);

        let next_in_bin = self.nodes[node as usize].next_in_bin;
        self.first_unallocated_for_bin[bin.index()] = next_in_bin;
        if let Some(next) = self.nodes.get_mut(next_in_bin as usize) {
            next.prev_in_bin = EMPTY
        } else {
            debug_assert_eq!(next_in_bin, EMPTY);
            self.bins_with_free_space.unset(bin);
        }
    }

    pub fn alloc(&mut self, size: C::Size) -> Option<GenericAllocation<C::Size>> {
        if size == C::Size::from(0) {
            return Some(GenericAllocation::EMPTY);
        }

        if size > C::MAX_ALLOCATION_SIZE {
            return None;
        }

        // Calculate the minimum bin to fit this allocation; round up in case the size doesn't match the bin size exactly.
        let min_bin = Self::size_to_bin_round_up(size);

        // Find a bin with enough free space and allocate a node there.
        let (bin, node) = if let Some(bin) = self.bins_with_free_space.find_first(min_bin) {
            (bin, self.first_unallocated_for_bin[bin.index()])
        } else {
            // No such bin exists; let's try rounding down and see if maybe we can find an oversized region in the previous bin.
            let bin = self.bins_with_free_space.find_first(Self::size_to_bin_round_down(size))?;
            let node = self.first_unallocated_for_bin[bin.index()];

            if self.nodes[node as usize].size < size {
                return None;
            }

            (bin, node)
        };

        let original_size = replace(&mut self.nodes[node as usize].size, size);
        debug_assert!(original_size >= size);
        debug_assert!(!self.nodes[node as usize].is_allocated);
        self.nodes[node as usize].is_allocated = true;

        // Remove the node from the bin's free node list.
        self.remove_first_free_node(node, bin);

        // If we haven't allocated all of the free space then add what's remaining back for later use.
        let offset = self.nodes[node as usize].offset;
        let remaining_free_pages = original_size - size;
        if let Some(new_free_node) = self.insert_free_node(offset + size, remaining_free_pages) {
            // Link the nodes together so that we can later merge them.
            let next_by_address = replace(&mut self.nodes[node as usize].next_by_address, new_free_node);
            if let Some(next) = self.nodes.get_mut(next_by_address as usize) {
                next.prev_by_address = new_free_node;
            } else {
                debug_assert_eq!(next_by_address, EMPTY);
            }
            self.nodes[new_free_node as usize].prev_by_address = node;
            self.nodes[new_free_node as usize].next_by_address = next_by_address;
        }

        Some(GenericAllocation { node, offset, size })
    }

    pub fn free(&mut self, alloc: GenericAllocation<C::Size>) {
        if alloc.is_empty() {
            return;
        }

        let GenericAllocation {
            node,
            mut offset,
            mut size,
        } = alloc;

        // Check if there's a free node before this node with which we can merge.
        {
            let prev_by_address = self.nodes[node as usize].prev_by_address;
            if (prev_by_address != EMPTY) && !self.nodes[prev_by_address as usize].is_allocated {
                offset = self.nodes[prev_by_address as usize].offset;
                size += self.nodes[prev_by_address as usize].size;

                self.remove_node(prev_by_address);

                debug_assert_eq!(self.nodes[prev_by_address as usize].next_by_address, node);
                self.nodes[node as usize].prev_by_address = self.nodes[prev_by_address as usize].prev_by_address;
            }
        }

        // Check if there's a free node after this node with which we can merge.
        {
            let next_by_address = self.nodes[node as usize].next_by_address;
            if (next_by_address != EMPTY) && !self.nodes[next_by_address as usize].is_allocated {
                size += self.nodes[next_by_address as usize].size;

                self.remove_node(next_by_address);

                debug_assert_eq!(self.nodes[next_by_address as usize].prev_by_address, node);
                self.nodes[node as usize].next_by_address = self.nodes[next_by_address as usize].next_by_address;
            }
        }

        let next_by_address = self.nodes[node as usize].next_by_address;
        let prev_by_address = self.nodes[node as usize].prev_by_address;
        self.unused_node_slots.push(node);

        let new_node = self.insert_free_node(offset, size);
        debug_assert!(new_node.is_some());
        if let Some(new_node) = new_node {
            if next_by_address != EMPTY {
                self.nodes[new_node as usize].next_by_address = next_by_address;
                self.nodes[next_by_address as usize].prev_by_address = new_node;
            }

            if prev_by_address != EMPTY {
                self.nodes[new_node as usize].prev_by_address = prev_by_address;
                self.nodes[prev_by_address as usize].next_by_address = new_node;
            }
        }
    }
}

#[cfg(any(test, feature = "export-internals-for-testing"))]
pub mod tests {
    use super::{GenericAllocation, GenericAllocator};
    use std::collections::HashMap;

    pub struct TestAllocator<C>
    where
        C: super::AllocatorConfig,
    {
        allocator: GenericAllocator<C>,
        allocations: HashMap<C::Size, GenericAllocation<C::Size>>,
    }

    impl<C> TestAllocator<C>
    where
        C: super::AllocatorConfig,
    {
        pub fn new(size: C::Size) -> Self {
            Self {
                allocator: GenericAllocator::<C>::new(size),
                allocations: HashMap::new(),
            }
        }

        pub fn alloc(&mut self, size: C::Size) -> Option<C::Size> {
            let allocation = self.allocator.alloc(size)?;
            if size == C::Size::from(0) {
                assert_eq!(allocation.offset(), C::Size::from(0));
                return Some(allocation.offset());
            }

            let pointer = allocation.offset();
            for (&old_pointer, old_allocation) in &self.allocations {
                let is_overlapping = (pointer >= old_pointer && pointer < (old_pointer + old_allocation.size()))
                    || (pointer + allocation.size() > old_pointer && pointer + allocation.size() <= (old_pointer + old_allocation.size()));

                assert!(
                    !is_overlapping,
                    "overlapping allocation: original = 0x{:08x}-0x{:08x}, new = 0x{:08x}-0x{:08x}",
                    old_pointer,
                    old_pointer + old_allocation.size(),
                    pointer,
                    pointer + allocation.size(),
                );
            }

            let offset = allocation.offset();
            assert!(self.allocations.insert(allocation.offset(), allocation).is_none());
            Some(offset)
        }

        pub fn free(&mut self, pointer: C::Size) -> bool {
            if let Some(allocation) = self.allocations.remove(&pointer) {
                self.allocator.free(allocation);
                true
            } else {
                false
            }
        }
    }

    #[cfg(test)]
    struct TestConfig64;

    #[cfg(test)]
    crate::generic_allocator::allocator_config! {
        impl AllocatorConfig for TestConfig64 {
            const MAX_ALLOCATION_SIZE: u64 = 6000000;
            const MAX_BINS: u32 = 4096;
        }
    }

    #[test]
    fn test_allocations_over_the_max_size_fail() {
        let mut allocator = TestAllocator::<TestConfig64>::new(6000000);
        let a0 = allocator.alloc(6000000).unwrap();
        assert_eq!(allocator.alloc(6000000), None);
        assert!(allocator.free(a0));
        let a0 = allocator.alloc(6000000).unwrap();
        assert!(allocator.free(a0));
        assert_eq!(allocator.alloc(6000001), None);
        assert_eq!(allocator.alloc(u64::MAX), None);
    }

    #[test]
    fn test_zero_max_size_allocator_only_gives_out_zero_sized_allocations() {
        let mut allocator = TestAllocator::<TestConfig64>::new(0);
        assert!(allocator.alloc(1).is_none());
        assert!(allocator.alloc(0).is_some());
    }

    #[test]
    fn test_allocator_after_using_up_all_free_space() {
        let mut allocator = TestAllocator::<TestConfig64>::new(3);
        assert!(allocator.alloc(1).is_some());
        assert!(allocator.alloc(1).is_some());
        assert!(allocator.alloc(1).is_some());
        assert!(allocator.alloc(1).is_none());
        assert!(allocator.alloc(0).is_some());
    }
}
