//! Everything in this module affects the ABI of the guest programs, either by affecting
//! their observable behavior (no matter how obscure), or changing which programs are accepted by the VM.

use crate::utils::{align_to_next_page_u32, align_to_next_page_u64};
use core::ops::Range;

const ADDRESS_SPACE_SIZE: u64 = 0x100000000_u64;

/// The minimum page size of the VM.
pub const VM_MIN_PAGE_SIZE: u32 = 0x1000;

/// The maximum page size of the VM.
pub const VM_MAX_PAGE_SIZE: u32 = 0x10000;

static_assert!(VM_MIN_PAGE_SIZE <= VM_MAX_PAGE_SIZE);

/// The bottom of the accessible address space inside the VM.
const VM_ADDRESS_SPACE_BOTTOM: u32 = VM_MAX_PAGE_SIZE;

/// The top of the accessible address space inside the VM.
const VM_ADDRESS_SPACE_TOP: u32 = (ADDRESS_SPACE_SIZE - VM_MAX_PAGE_SIZE as u64) as u32;

/// The address which, when jumped to, will return to the host.
///
/// There isn't actually anything there; it's just a virtual address.
pub const VM_ADDR_RETURN_TO_HOST: u32 = 0xffff0000;
static_assert!(VM_ADDR_RETURN_TO_HOST & 0b11 == 0);

/// The maximum byte size of the code blob.
pub const VM_MAXIMUM_CODE_SIZE: u32 = 32 * 1024 * 1024;

/// The maximum number of entries in the jump table.
pub const VM_MAXIMUM_JUMP_TABLE_ENTRIES: u32 = 16 * 1024 * 1024;

/// The maximum number of functions the program can import.
pub const VM_MAXIMUM_IMPORT_COUNT: u32 = 1024;

/// The minimum required alignment of runtime code pointers.
pub const VM_CODE_ADDRESS_ALIGNMENT: u32 = 2;

#[derive(Clone)]
pub struct MemoryMapBuilder {
    page_size: u32,
    ro_data_size: u32,
    rw_data_size: u32,
    stack_size: u32,
    aux_data_size: u32,
}

impl MemoryMapBuilder {
    pub fn new(page_size: u32) -> Self {
        MemoryMapBuilder {
            page_size,
            ro_data_size: 0,
            rw_data_size: 0,
            stack_size: 0,
            aux_data_size: 0,
        }
    }

    pub fn ro_data_size(&mut self, value: u32) -> &mut Self {
        self.ro_data_size = value;
        self
    }

    pub fn rw_data_size(&mut self, value: u32) -> &mut Self {
        self.rw_data_size = value;
        self
    }

    pub fn stack_size(&mut self, value: u32) -> &mut Self {
        self.stack_size = value;
        self
    }

    pub fn aux_data_size(&mut self, value: u32) -> &mut Self {
        self.aux_data_size = value;
        self
    }

    pub fn build(&self) -> Result<MemoryMap, &'static str> {
        let MemoryMapBuilder {
            page_size,
            ro_data_size,
            rw_data_size,
            stack_size,
            aux_data_size,
        } = *self;

        if page_size < VM_MIN_PAGE_SIZE {
            return Err("invalid page size: page size is too small");
        }

        if page_size > VM_MAX_PAGE_SIZE {
            return Err("invalid page size: page size is too big");
        }

        if !page_size.is_power_of_two() {
            return Err("invalid page size: page size is not a power of two");
        }

        let Some(ro_data_address_space) = align_to_next_page_u64(u64::from(VM_MAX_PAGE_SIZE), u64::from(ro_data_size)) else {
            return Err("the size of read-only data is too big");
        };

        let Some(ro_data_size) = align_to_next_page_u32(page_size, ro_data_size) else {
            return Err("the size of read-only data is too big");
        };

        let Some(rw_data_address_space) = align_to_next_page_u64(u64::from(VM_MAX_PAGE_SIZE), u64::from(rw_data_size)) else {
            return Err("the size of read-write data is too big");
        };

        let original_rw_data_size = rw_data_size;
        let Some(rw_data_size) = align_to_next_page_u32(page_size, rw_data_size) else {
            return Err("the size of read-write data is too big");
        };

        let Some(stack_address_space) = align_to_next_page_u64(u64::from(VM_MAX_PAGE_SIZE), u64::from(stack_size)) else {
            return Err("the size of the stack is too big");
        };

        let Some(stack_size) = align_to_next_page_u32(page_size, stack_size) else {
            return Err("the size of the stack is too big");
        };

        let Some(aux_data_address_space) = align_to_next_page_u64(u64::from(VM_MAX_PAGE_SIZE), u64::from(aux_data_size)) else {
            return Err("the size of the aux data is too big");
        };

        let Some(aux_data_size) = align_to_next_page_u32(page_size, aux_data_size) else {
            return Err("the size of the aux data is too big");
        };

        let mut address_low: u64 = 0;

        address_low += u64::from(VM_ADDRESS_SPACE_BOTTOM);
        address_low += ro_data_address_space;
        address_low += u64::from(VM_MAX_PAGE_SIZE);

        let rw_data_address = address_low as u32;
        let heap_base = address_low + u64::from(original_rw_data_size);
        address_low += rw_data_address_space;
        let heap_slack = address_low - heap_base;
        address_low += u64::from(VM_MAX_PAGE_SIZE);

        let mut address_high: i64 = i64::from(VM_ADDRESS_SPACE_TOP);
        address_high -= aux_data_address_space as i64;
        let aux_data_address = address_high as u32;
        address_high -= i64::from(VM_MAX_PAGE_SIZE);
        let stack_address_high = address_high as u32;
        address_high -= stack_address_space as i64;

        if address_low as i64 > address_high {
            return Err("maximum memory size exceeded");
        }

        let max_heap_size = address_high as u64 - address_low + heap_slack;

        Ok(MemoryMap {
            page_size,
            ro_data_size,
            rw_data_address,
            rw_data_size,
            stack_address_high,
            stack_size,
            aux_data_address,
            aux_data_size,
            heap_base: heap_base as u32,
            max_heap_size: max_heap_size as u32,
        })
    }
}

/// The memory map of a given guest program.
#[derive(Clone)]
pub struct MemoryMap {
    page_size: u32,
    ro_data_size: u32,
    rw_data_address: u32,
    rw_data_size: u32,
    stack_address_high: u32,
    stack_size: u32,
    aux_data_address: u32,
    aux_data_size: u32,
    heap_base: u32,
    max_heap_size: u32,
}

impl MemoryMap {
    /// The page size of the program.
    #[inline]
    pub fn page_size(&self) -> u32 {
        self.page_size
    }

    /// The address at which the program's heap starts.
    #[inline]
    pub fn heap_base(&self) -> u32 {
        self.heap_base
    }

    /// The maximum size of the program's heap.
    #[inline]
    pub fn max_heap_size(&self) -> u32 {
        self.max_heap_size
    }

    /// The address at where the program's read-only data starts inside of the VM.
    #[inline]
    pub fn ro_data_address(&self) -> u32 {
        VM_ADDRESS_SPACE_BOTTOM
    }

    /// The size of the program's read-only data.
    #[inline]
    pub fn ro_data_size(&self) -> u32 {
        self.ro_data_size
    }

    /// The range of addresses where the program's read-only data is inside of the VM.
    #[inline]
    pub fn ro_data_range(&self) -> Range<u32> {
        self.ro_data_address()..self.ro_data_address() + self.ro_data_size()
    }

    /// The address at where the program's read-write data starts inside of the VM.
    #[inline]
    pub fn rw_data_address(&self) -> u32 {
        self.rw_data_address
    }

    /// The size of the program's read-write data.
    #[inline]
    pub fn rw_data_size(&self) -> u32 {
        self.rw_data_size
    }

    /// The range of addresses where the program's read-write data is inside of the VM.
    #[inline]
    pub fn rw_data_range(&self) -> Range<u32> {
        self.rw_data_address()..self.rw_data_address() + self.rw_data_size()
    }

    /// The address at where the program's stack starts inside of the VM.
    #[inline]
    pub fn stack_address_low(&self) -> u32 {
        self.stack_address_high() - self.stack_size
    }

    /// The address at where the program's stack ends inside of the VM.
    #[inline]
    pub fn stack_address_high(&self) -> u32 {
        self.stack_address_high
    }

    /// The size of the program's stack.
    #[inline]
    pub fn stack_size(&self) -> u32 {
        self.stack_size
    }

    /// The range of addresses where the program's stack is inside of the VM.
    #[inline]
    pub fn stack_range(&self) -> Range<u32> {
        self.stack_address_low()..self.stack_address_high()
    }

    #[inline]
    pub fn aux_data_address(&self) -> u32 {
        self.aux_data_address
    }

    #[inline]
    pub fn aux_data_size(&self) -> u32 {
        self.aux_data_size
    }

    #[inline]
    pub fn aux_data_range(&self) -> Range<u32> {
        self.aux_data_address()..self.aux_data_address() + self.aux_data_size()
    }
}

#[test]
fn test_memory_map() {
    {
        let map = MemoryMapBuilder::new(0x4000)
            .ro_data_size(1)
            .rw_data_size(1)
            .stack_size(1)
            .build()
            .unwrap();
        assert_eq!(map.ro_data_address(), 0x10000);
        assert_eq!(map.ro_data_size(), 0x4000);
        assert_eq!(map.rw_data_address(), 0x30000);
        assert_eq!(map.rw_data_size(), 0x4000);
        assert_eq!(map.stack_size(), 0x4000);
        assert_eq!(map.stack_address_high(), 0xfffe0000);
        assert_eq!(map.stack_address_low(), 0xfffdc000);

        assert_eq!(map.heap_base(), 0x30001);
        assert_eq!(
            u64::from(map.max_heap_size()),
            ADDRESS_SPACE_SIZE - u64::from(VM_MAX_PAGE_SIZE) * 4 - u64::from(map.heap_base())
        );
    }

    let max_size = (ADDRESS_SPACE_SIZE - u64::from(VM_MAX_PAGE_SIZE) * 5) as u32;

    {
        // Read-only data takes the whole address space.
        let map = MemoryMapBuilder::new(0x4000).ro_data_size(max_size).build().unwrap();
        assert_eq!(map.ro_data_address(), 0x10000);
        assert_eq!(map.ro_data_size(), max_size);
        assert_eq!(map.rw_data_address(), map.ro_data_address() + VM_MAX_PAGE_SIZE + max_size);
        assert_eq!(map.rw_data_size(), 0);
        assert_eq!(map.stack_address_high(), VM_ADDRESS_SPACE_TOP - VM_MAX_PAGE_SIZE);
        assert_eq!(map.stack_address_low(), VM_ADDRESS_SPACE_TOP - VM_MAX_PAGE_SIZE);
        assert_eq!(map.stack_size(), 0);

        assert_eq!(map.heap_base(), map.rw_data_address());
        assert_eq!(map.max_heap_size(), 0);
    }

    assert!(MemoryMapBuilder::new(0x4000).ro_data_size(max_size + 1).build().is_err());
    assert!(MemoryMapBuilder::new(0x4000)
        .ro_data_size(max_size)
        .rw_data_size(1)
        .build()
        .is_err());
    assert!(MemoryMapBuilder::new(0x4000).ro_data_size(max_size).stack_size(1).build().is_err());

    {
        // Read-write data takes the whole address space.
        let map = MemoryMapBuilder::new(0x4000).rw_data_size(max_size).build().unwrap();
        assert_eq!(map.ro_data_address(), VM_MAX_PAGE_SIZE);
        assert_eq!(map.ro_data_size(), 0);
        assert_eq!(map.rw_data_address(), VM_MAX_PAGE_SIZE * 2);
        assert_eq!(map.rw_data_size(), max_size);
        assert_eq!(map.stack_address_high(), VM_ADDRESS_SPACE_TOP - VM_MAX_PAGE_SIZE);
        assert_eq!(map.stack_address_low(), VM_ADDRESS_SPACE_TOP - VM_MAX_PAGE_SIZE);
        assert_eq!(map.stack_size(), 0);

        assert_eq!(map.heap_base(), map.rw_data_address() + map.rw_data_size());
        assert_eq!(map.max_heap_size(), 0);
    }

    {
        // Stack takes the whole address space.
        let map = MemoryMapBuilder::new(0x4000).stack_size(max_size).build().unwrap();
        assert_eq!(map.ro_data_address(), VM_MAX_PAGE_SIZE);
        assert_eq!(map.ro_data_size(), 0);
        assert_eq!(map.rw_data_address(), VM_MAX_PAGE_SIZE * 2);
        assert_eq!(map.rw_data_size(), 0);
        assert_eq!(map.stack_address_high(), VM_ADDRESS_SPACE_TOP - VM_MAX_PAGE_SIZE);
        assert_eq!(map.stack_address_low(), VM_ADDRESS_SPACE_TOP - VM_MAX_PAGE_SIZE - max_size);
        assert_eq!(map.stack_size(), max_size);

        assert_eq!(map.heap_base(), map.rw_data_address());
        assert_eq!(map.max_heap_size(), 0);
    }
}

#[cfg(kani)]
mod kani {
    use super::VM_MAX_PAGE_SIZE;
    use crate::utils::align_to_next_page_u64;

    #[kani::proof]
    fn memory_map() {
        let page_size: u32 = kani::any();
        let ro_data_size: u32 = kani::any();
        let rw_data_size: u32 = kani::any();
        let stack_size: u32 = kani::any();
        let aux_data_size: u32 = kani::any();
        kani::assume(page_size >= super::VM_MIN_PAGE_SIZE);
        kani::assume(page_size <= super::VM_MAX_PAGE_SIZE);
        kani::assume(page_size.is_power_of_two());

        let map = super::MemoryMapBuilder::new(page_size)
            .ro_data_size(ro_data_size)
            .rw_data_size(rw_data_size)
            .stack_size(stack_size)
            .aux_data_size(aux_data_size)
            .build();

        if let Ok(ref map) = map {
            assert_eq!(map.ro_data_address() % VM_MAX_PAGE_SIZE, 0);
            assert_eq!(map.rw_data_address() % VM_MAX_PAGE_SIZE, 0);
            assert_eq!(map.stack_address_high() % VM_MAX_PAGE_SIZE, 0);
            assert_eq!(map.aux_data_address() % VM_MAX_PAGE_SIZE, 0);

            assert_eq!(map.ro_data_address() % page_size, 0);
            assert_eq!(map.ro_data_range().end % page_size, 0);
            assert_eq!(map.rw_data_address() % page_size, 0);
            assert_eq!(map.rw_data_range().end % page_size, 0);
            assert_eq!(map.stack_address_high() % page_size, 0);
            assert_eq!(map.stack_address_low() % page_size, 0);
            assert_eq!(map.aux_data_address() % page_size, 0);
            assert_eq!(map.aux_data_range().end % page_size, 0);

            assert!(map.ro_data_address() < map.rw_data_address());
            assert!(map.rw_data_address() < map.stack_address_low());
            assert!(map.stack_address_low() <= map.stack_address_high());
            assert!(map.stack_address_high() < map.aux_data_address());

            assert!(map.rw_data_address() - map.ro_data_range().end >= VM_MAX_PAGE_SIZE);
            assert!(map.stack_address_low() - map.rw_data_range().end >= VM_MAX_PAGE_SIZE);
            assert!(map.aux_data_address() - map.stack_address_high() >= VM_MAX_PAGE_SIZE);
        }

        let total_size = align_to_next_page_u64(u64::from(VM_MAX_PAGE_SIZE), ro_data_size as u64).unwrap()
            + align_to_next_page_u64(u64::from(VM_MAX_PAGE_SIZE), rw_data_size as u64).unwrap()
            + align_to_next_page_u64(u64::from(VM_MAX_PAGE_SIZE), stack_size as u64).unwrap()
            + align_to_next_page_u64(u64::from(VM_MAX_PAGE_SIZE), aux_data_size as u64).unwrap();

        // [guard] ro_data [guard] rw_data [guard] stack [guard] aux [guard]
        let max_size = 0x100000000 - u64::from(VM_MAX_PAGE_SIZE) * 5;
        assert_eq!(map.is_err(), total_size > max_size);
    }
}
