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

/// The address at which the program's stack starts inside of the VM.
///
/// This is directly accessible by the program running inside of the VM.
pub const VM_ADDR_USER_STACK_HIGH: u32 = (ADDRESS_SPACE_SIZE - VM_MAX_PAGE_SIZE as u64) as u32;

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
// TODO: Support the C extension in the linker and lower this to 2.
pub const VM_CODE_ADDRESS_ALIGNMENT: u32 = 4;

/// The memory map of a given guest program.
#[derive(Clone)]
#[repr(C)] // NOTE: Used on the host <-> zygote boundary.
pub struct MemoryMap {
    page_size: u32,
    ro_data_size: u32,
    rw_data_size: u32,
    stack_size: u32,
    heap_base: u32,
    max_heap_size: u32,
}

impl MemoryMap {
    /// Creates an empty memory map.
    #[inline]
    pub const fn empty() -> Self {
        Self {
            page_size: 0,
            ro_data_size: 0,
            rw_data_size: 0,
            stack_size: 0,
            heap_base: 0,
            max_heap_size: 0,
        }
    }

    /// Calculates the memory map from the given parameters.
    pub fn new(page_size: u32, ro_data_size: u32, rw_data_size: u32, stack_size: u32) -> Result<Self, &'static str> {
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

        let mut address_low: u64 = 0;

        address_low += u64::from(VM_MAX_PAGE_SIZE);
        address_low += ro_data_address_space;
        address_low += u64::from(VM_MAX_PAGE_SIZE);

        let heap_base = address_low + u64::from(original_rw_data_size);
        address_low += rw_data_address_space;
        let heap_slack = address_low - heap_base;
        address_low += u64::from(VM_MAX_PAGE_SIZE);

        let mut address_high: u64 = u64::from(VM_ADDR_USER_STACK_HIGH);
        address_high -= stack_address_space;

        if address_low > address_high {
            return Err("maximum memory size exceeded");
        }

        let max_heap_size = address_high - address_low + heap_slack;

        Ok(Self {
            page_size,
            ro_data_size,
            rw_data_size,
            stack_size,
            heap_base: heap_base as u32,
            max_heap_size: max_heap_size as u32,
        })
    }

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
        VM_MAX_PAGE_SIZE
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
        match align_to_next_page_u32(VM_MAX_PAGE_SIZE, self.ro_data_address() + self.ro_data_size) {
            Some(offset) => offset + VM_MAX_PAGE_SIZE,
            None => unreachable!(),
        }
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
        VM_ADDR_USER_STACK_HIGH
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
}

#[test]
fn test_memory_map() {
    {
        let map = MemoryMap::new(0x4000, 1, 1, 1).unwrap();
        assert_eq!(map.ro_data_address(), 0x10000);
        assert_eq!(map.ro_data_size(), 0x4000);
        assert_eq!(map.rw_data_address(), 0x30000);
        assert_eq!(map.rw_data_size(), 0x4000);
        assert_eq!(map.stack_size(), 0x4000);
        assert_eq!(map.stack_address_high(), 0xffff0000);
        assert_eq!(map.stack_address_low(), 0xfffec000);

        assert_eq!(map.heap_base(), 0x30001);
        assert_eq!(
            u64::from(map.max_heap_size()),
            ADDRESS_SPACE_SIZE - u64::from(VM_MAX_PAGE_SIZE) * 3 - u64::from(map.heap_base())
        );
    }

    let max_size = (ADDRESS_SPACE_SIZE - u64::from(VM_MAX_PAGE_SIZE) * 4) as u32;

    {
        // Read-only data takes the whole address space.
        let map = MemoryMap::new(0x4000, max_size, 0, 0).unwrap();
        assert_eq!(map.ro_data_address(), 0x10000);
        assert_eq!(map.ro_data_size(), max_size);
        assert_eq!(map.rw_data_address(), map.ro_data_address() + VM_MAX_PAGE_SIZE + max_size);
        assert_eq!(map.rw_data_size(), 0);
        assert_eq!(map.stack_address_high(), VM_ADDR_USER_STACK_HIGH);
        assert_eq!(map.stack_address_low(), VM_ADDR_USER_STACK_HIGH);
        assert_eq!(map.stack_size(), 0);

        assert_eq!(map.heap_base(), map.rw_data_address());
        assert_eq!(map.max_heap_size(), 0);
    }

    assert!(MemoryMap::new(0x4000, max_size + 1, 0, 0).is_err());
    assert!(MemoryMap::new(0x4000, max_size, 1, 0).is_err());
    assert!(MemoryMap::new(0x4000, max_size, 0, 1).is_err());

    {
        // Read-write data takes the whole address space.
        let map = MemoryMap::new(0x4000, 0, max_size, 0).unwrap();
        assert_eq!(map.ro_data_address(), VM_MAX_PAGE_SIZE);
        assert_eq!(map.ro_data_size(), 0);
        assert_eq!(map.rw_data_address(), VM_MAX_PAGE_SIZE * 2);
        assert_eq!(map.rw_data_size(), max_size);
        assert_eq!(map.stack_address_high(), VM_ADDR_USER_STACK_HIGH);
        assert_eq!(map.stack_address_low(), VM_ADDR_USER_STACK_HIGH);
        assert_eq!(map.stack_size(), 0);

        assert_eq!(map.heap_base(), map.rw_data_address() + map.rw_data_size());
        assert_eq!(map.max_heap_size(), 0);
    }

    {
        // Stack takes the whole address space.
        let map = MemoryMap::new(0x4000, 0, 0, max_size).unwrap();
        assert_eq!(map.ro_data_address(), VM_MAX_PAGE_SIZE);
        assert_eq!(map.ro_data_size(), 0);
        assert_eq!(map.rw_data_address(), VM_MAX_PAGE_SIZE * 2);
        assert_eq!(map.rw_data_size(), 0);
        assert_eq!(map.stack_address_high(), VM_ADDR_USER_STACK_HIGH);
        assert_eq!(map.stack_address_low(), VM_ADDR_USER_STACK_HIGH - max_size);
        assert_eq!(map.stack_size(), max_size);

        assert_eq!(map.heap_base(), map.rw_data_address());
        assert_eq!(map.max_heap_size(), 0);
    }
}
