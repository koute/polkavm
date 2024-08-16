use core::mem::replace;

// This is based on: https://github.com/sebbbi/OffsetAllocator/blob/main/offsetAllocator.cpp
#[doc(hidden)]
#[inline]
pub const fn to_bin_index<const MANTISSA_BITS: u32, const ROUND_UP: bool>(size: u32) -> u32 {
    if size == 0 {
        return 0;
    }

    let mantissa_value = 1 << MANTISSA_BITS;
    let mantissa_mask = mantissa_value - 1;

    let exponent;
    let mut mantissa;
    if size < mantissa_value {
        exponent = 0;
        mantissa = size;
    } else {
        let mantissa_start_bit: u32 = (31 - size.leading_zeros()) - MANTISSA_BITS;

        exponent = mantissa_start_bit + 1;
        mantissa = (size >> mantissa_start_bit) & mantissa_mask;

        if ROUND_UP {
            let low_bits_mask: u32 = (1 << mantissa_start_bit) - 1;
            if (size & low_bits_mask) != 0 {
                mantissa += 1;
            }
        }
    }

    let out = exponent << MANTISSA_BITS;
    if ROUND_UP {
        out + mantissa - 1
    } else {
        (out | mantissa) - 1
    }
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
    assert_eq!(to_bin_index::<3, true>(0), 0);
    assert_eq!(to_bin_index::<3, true>(1), 0);
    assert_eq!(to_bin_index::<3, true>(2), 1);
}

#[doc(hidden)]
#[cfg_attr(test, derive(PartialEq, Debug))]
pub struct AllocatorBinConfig {
    pub mantissa_bits: u32,
    pub bin_count: u32,
}

#[doc(hidden)]
pub const fn calculate_optimal_bin_config<PrimaryMask, SecondaryMask>(
    max_allocation_size: u32,
    mut requested_max_bins: u32,
) -> AllocatorBinConfig {
    let true_max_bins = (core::mem::size_of::<PrimaryMask>() * 8 * ::core::mem::size_of::<SecondaryMask>() * 8) as u32;
    if true_max_bins < requested_max_bins {
        requested_max_bins = true_max_bins
    }

    macro_rules! try_all {
        ($($mantissa_bits:expr),+) => {
            $(
                let highest_bin_index = to_bin_index::<$mantissa_bits, true>(max_allocation_size);
                if highest_bin_index < requested_max_bins {
                    return AllocatorBinConfig {
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

#[test]
fn test_calculate_optimal_bin_config() {
    assert_eq!(
        calculate_optimal_bin_config::<u64, u64>((i32::MAX as u32) / 4096, u32::MAX),
        AllocatorBinConfig {
            mantissa_bits: 8,
            bin_count: 3072
        }
    );

    assert_eq!(
        calculate_optimal_bin_config::<u64, u64>((i32::MAX as u32) / 4096, 3072),
        AllocatorBinConfig {
            mantissa_bits: 8,
            bin_count: 3072
        }
    );

    assert_eq!(
        calculate_optimal_bin_config::<u64, u64>((i32::MAX as u32) / 4096, 3071),
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

trait BitIndexT: Copy {
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
    Primary: Copy,
    Secondary: Copy,
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

pub trait AllocatorConfig {
    #[doc(hidden)]
    const MAX_ALLOCATION_SIZE: u32;

    #[doc(hidden)]
    #[allow(private_bounds)]
    type BitMask: BitMaskT;

    #[doc(hidden)]
    #[allow(private_bounds)]
    type BinArray: core::ops::Index<usize, Output = u32> + core::ops::IndexMut<usize> + EmptyInit;

    #[doc(hidden)]
    fn to_bin_index<const ROUND_UP: bool>(size: u32) -> u32;
}

// TODO: Remove this once this is fixed: https://github.com/rust-lang/rust/issues/60551
#[doc(hidden)]
#[macro_export]
macro_rules! _allocator_config {
    (
        impl AllocatorConfig for $type:ty {
            const MAX_ALLOCATION_SIZE: u32 = $max_allocation_size:expr;
            const MAX_BINS: u32 = $max_bins:expr;
        }
    ) => {
        impl $crate::generic_allocator::AllocatorConfig for $type {
            const MAX_ALLOCATION_SIZE: u32 = $max_allocation_size;
            type BitMask = $crate::bit_mask::bitmask_type!(
                usize,
                usize,
                $crate::generic_allocator::calculate_optimal_bin_config::<usize, usize>($max_allocation_size, $max_bins).bin_count as usize
            );
            type BinArray = [u32; $crate::generic_allocator::calculate_optimal_bin_config::<usize, usize>($max_allocation_size, $max_bins)
                .bin_count as usize];

            fn to_bin_index<const ROUND_UP: bool>(size: u32) -> u32 {
                const MANTISSA_BITS: u32 =
                    $crate::generic_allocator::calculate_optimal_bin_config::<usize, usize>($max_allocation_size, $max_bins).mantissa_bits;
                $crate::generic_allocator::to_bin_index::<MANTISSA_BITS, ROUND_UP>(size)
            }
        }
    };
}

pub use _allocator_config as allocator_config;

const EMPTY: u32 = u32::MAX;

#[derive(Clone, Debug)]
struct Node {
    next_by_address: u32,
    prev_by_address: u32,
    next_in_bin: u32,
    prev_in_bin: u32,
    offset: u32,
    size: u32,
    is_allocated: bool,
}

#[derive(Debug)]
pub struct GenericAllocator<C: AllocatorConfig> {
    nodes: Vec<Node>,
    unused_node_slots: Vec<u32>,
    bins_with_free_space: C::BitMask,
    first_unallocated_for_bin: C::BinArray,
}

#[derive(Copy, Clone)]
pub struct GenericAllocation {
    node: u32,
    offset: u32,
    size: u32,
}

impl GenericAllocation {
    pub const EMPTY: GenericAllocation = GenericAllocation {
        node: EMPTY,
        offset: 0,
        size: 0,
    };

    pub fn is_empty(&self) -> bool {
        self.node == EMPTY
    }

    pub fn offset(&self) -> u32 {
        self.offset
    }

    pub fn size(&self) -> u32 {
        self.size
    }
}

impl<C> GenericAllocator<C>
where
    C: AllocatorConfig,
{
    pub fn new(total_space: u32) -> Self {
        let mut mutable = GenericAllocator {
            bins_with_free_space: C::BitMask::default(),
            first_unallocated_for_bin: C::BinArray::empty_init(),
            nodes: Vec::new(),
            unused_node_slots: Vec::new(),
        };

        mutable.insert_free_node(0, total_space);
        mutable
    }

    fn size_to_bin_round_down(size: u32) -> <C::BitMask as BitMaskT>::Index {
        let size = core::cmp::min(size, C::MAX_ALLOCATION_SIZE);
        C::BitMask::index(C::to_bin_index::<false>(size))
    }

    fn size_to_bin_round_up(size: u32) -> <C::BitMask as BitMaskT>::Index {
        let size = core::cmp::min(size, C::MAX_ALLOCATION_SIZE);
        C::BitMask::index(C::to_bin_index::<true>(size))
    }

    fn insert_free_node(&mut self, offset: u32, size: u32) -> u32 {
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
        new_node
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

    pub fn alloc(&mut self, size: u32) -> Option<GenericAllocation> {
        if size == 0 {
            return Some(GenericAllocation::EMPTY);
        }

        // Calculate the minimum bin to fit this allocation; round up in case the size doesn't match the bin size exactly.
        let min_bin = Self::size_to_bin_round_up(size);

        // Find a bin with enough free space and allocate a node there.
        let bin = self.bins_with_free_space.find_first(min_bin)?;
        let node = self.first_unallocated_for_bin[bin.index()];
        let original_size = replace(&mut self.nodes[node as usize].size, size);

        debug_assert!(!self.nodes[node as usize].is_allocated);
        self.nodes[node as usize].is_allocated = true;

        // Remove the node from the bin's free node list.
        self.remove_first_free_node(node, bin);

        let offset = self.nodes[node as usize].offset;
        let remaining_free_pages = original_size - size;
        if remaining_free_pages > 0 {
            // We haven't allocated all of the free space; add what's remaining back for later use.
            let new_free_node = self.insert_free_node(offset + size, remaining_free_pages);

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

    pub fn free(&mut self, alloc: GenericAllocation) {
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

                assert_eq!(self.nodes[prev_by_address as usize].next_by_address, node);
                self.nodes[node as usize].prev_by_address = self.nodes[prev_by_address as usize].prev_by_address;
            }
        }

        // Check if there's a free node after this node with which we can merge.
        {
            let next_by_address = self.nodes[node as usize].next_by_address;
            if (next_by_address != EMPTY) && !self.nodes[next_by_address as usize].is_allocated {
                size += self.nodes[next_by_address as usize].size;

                self.remove_node(next_by_address);

                assert_eq!(self.nodes[next_by_address as usize].prev_by_address, node);
                self.nodes[node as usize].next_by_address = self.nodes[next_by_address as usize].next_by_address;
            }
        }

        let next_by_address = self.nodes[node as usize].next_by_address;
        let prev_by_address = self.nodes[node as usize].prev_by_address;
        self.unused_node_slots.push(node);

        let new_node = self.insert_free_node(offset, size);
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
