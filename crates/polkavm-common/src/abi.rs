//! Everything in this module affects the ABI of the guest programs, either by affecting
//! their observable behavior (no matter how obscure), or changing which programs are accepted by the VM.

use crate::utils::{align_to_next_page_u32, align_to_next_page_u64};
use core::ops::Range;

const ADDRESS_SPACE_SIZE: u64 = 0x100000000_u64;

/// The page size of the VM.
///
/// This is the minimum granularity with which the VM can allocate memory.
pub const VM_PAGE_SIZE: u32 = 0x4000;

/// The maximum page size of the VM.
pub const VM_MAX_PAGE_SIZE: u32 = 0x10000;

static_assert!(VM_PAGE_SIZE <= VM_MAX_PAGE_SIZE);
static_assert!(VM_MAX_PAGE_SIZE % VM_PAGE_SIZE == 0);

/// The address at which the program's memory starts inside of the VM.
///
/// This is directly accessible by the program running inside of the VM.
pub const VM_ADDR_USER_MEMORY: u32 = VM_MAX_PAGE_SIZE;

/// The address at which the program's stack starts inside of the VM.
///
/// This is directly accessible by the program running inside of the VM.
pub const VM_ADDR_USER_STACK_HIGH: u32 = (ADDRESS_SPACE_SIZE - VM_MAX_PAGE_SIZE as u64) as u32;

/// The address which, when jumped to, will return to the host.
///
/// There isn't actually anything there; it's just a virtual address.
pub const VM_ADDR_RETURN_TO_HOST: u32 = 0xffff0000;
static_assert!(VM_ADDR_RETURN_TO_HOST & 0b11 == 0);

/// The total maximum amount of memory a program can use.
///
/// This is the whole 32-bit address space, except:
///   * the guard page at the start,
///   * the guard page between read-only data and read-write data
///   * the guard page between the heap and the stack,
///   * and the guard page at the end.
pub const VM_MAXIMUM_MEMORY_SIZE: u32 = (ADDRESS_SPACE_SIZE - VM_MAX_PAGE_SIZE as u64 * 4) as u32;

/// The maximum number of VM instructions a program can be composed of.
pub const VM_MAXIMUM_INSTRUCTION_COUNT: u32 = 2 * 1024 * 1024;

/// The maximum number of functions the program can import.
pub const VM_MAXIMUM_IMPORT_COUNT: u32 = 1024;

/// The maximum number of functions the program can export.
pub const VM_MAXIMUM_EXPORT_COUNT: u32 = 1024;

/// The minimum required alignment of runtime code pointers.
// TODO: Support the C extension in the linker and lower this to 2.
pub const VM_CODE_ADDRESS_ALIGNMENT: u32 = 4;

/// The memory configuration used by a given guest program.
#[derive(Copy, Clone, PartialEq, Eq)]
#[repr(C)] // NOTE: Used on the host <-> zygote boundary.
pub struct GuestMemoryConfig {
    ro_data_size: u32,
    rw_data_size: u32,
    bss_size: u32,
    stack_size: u32,
}

impl GuestMemoryConfig {
    #[inline]
    pub const fn empty() -> Self {
        Self {
            ro_data_size: 0,
            rw_data_size: 0,
            bss_size: 0,
            stack_size: 0,
        }
    }

    #[inline]
    pub const fn new(ro_data_size: u64, rw_data_size: u64, bss_size: u64, stack_size: u64) -> Result<Self, &'static str> {
        if ro_data_size > VM_MAXIMUM_MEMORY_SIZE as u64 {
            return Err("size of the read-only data exceeded the maximum memory size");
        }

        if rw_data_size > VM_MAXIMUM_MEMORY_SIZE as u64 {
            return Err("size of the read-write data exceeded the maximum memory size");
        }

        if bss_size > VM_MAXIMUM_MEMORY_SIZE as u64 {
            return Err("size of the bss section exceeded the maximum memory size");
        }

        if stack_size > VM_MAXIMUM_MEMORY_SIZE as u64 {
            return Err("size of the stack exceeded the maximum memory size");
        }

        // We already checked that these are less than the maximum memory size, so these cannot fail
        // because the maximum memory size is going to be vastly smaller than what an u64 can hold.
        const _: () = {
            assert!(VM_MAXIMUM_MEMORY_SIZE as u64 + VM_MAX_PAGE_SIZE as u64 <= u32::MAX as u64);
        };

        let Some(ro_data_size) = align_to_next_page_u64(VM_PAGE_SIZE as u64, ro_data_size) else {
            unreachable!()
        };
        let Some(rw_data_size) = align_to_next_page_u64(VM_PAGE_SIZE as u64, rw_data_size) else {
            unreachable!()
        };
        let Some(bss_size) = align_to_next_page_u64(VM_PAGE_SIZE as u64, bss_size) else {
            unreachable!()
        };
        let Some(stack_size) = align_to_next_page_u64(VM_PAGE_SIZE as u64, stack_size) else {
            unreachable!()
        };

        let config = Self {
            ro_data_size: ro_data_size as u32,
            rw_data_size: rw_data_size as u32,
            bss_size: bss_size as u32,
            stack_size: stack_size as u32,
        };

        if let Err(error) = config.check_total_memory_size() {
            Err(error)
        } else {
            Ok(config)
        }
    }

    #[inline]
    const fn check_total_memory_size(self) -> Result<(), &'static str> {
        if self.ro_data_size as u64 + self.rw_data_size as u64 + self.bss_size as u64 + self.stack_size as u64
            > VM_MAXIMUM_MEMORY_SIZE as u64
        {
            Err("maximum memory size exceeded")
        } else {
            Ok(())
        }
    }

    /// The address at where the program memory starts inside of the VM.
    #[inline]
    pub const fn user_memory_region_address(self) -> u32 {
        VM_ADDR_USER_MEMORY
    }

    /// The size of the region in which the program memory resides inside of the VM, excluding the stack.
    ///
    /// This also includes the guard page between the read-only data and read-write data.
    #[inline]
    pub const fn user_memory_region_size(self) -> u32 {
        (self.bss_address() + self.bss_size()) - self.user_memory_region_address()
    }

    /// Resets the size of the program memory to zero, excluding the stack.
    #[inline]
    pub fn clear_user_memory_sizes(&mut self) {
        self.ro_data_size = 0;
        self.rw_data_size = 0;
        self.bss_size = 0;
    }

    /// The address at where the program's read-only data starts inside of the VM.
    #[inline]
    pub const fn ro_data_address(self) -> u32 {
        self.user_memory_region_address()
    }

    /// The size of the program's read-only data.
    #[inline]
    pub const fn ro_data_size(self) -> u32 {
        self.ro_data_size
    }

    /// The range of addresses where the program's read-only data is inside of the VM.
    #[inline]
    pub const fn ro_data_range(self) -> Range<u32> {
        self.ro_data_address()..self.ro_data_address() + self.ro_data_size()
    }

    /// Sets the program's read-only data size.
    pub fn set_ro_data_size(&mut self, ro_data_size: u32) -> Result<(), &'static str> {
        if ro_data_size > VM_MAXIMUM_MEMORY_SIZE {
            return Err("size of the read-only data exceeded the maximum memory size");
        }

        let ro_data_size = match align_to_next_page_u64(u64::from(VM_PAGE_SIZE), u64::from(ro_data_size)) {
            Some(value) => value,
            None => unreachable!(),
        } as u32;

        Self { ro_data_size, ..*self }.check_total_memory_size()?;
        self.ro_data_size = ro_data_size;
        Ok(())
    }

    /// The address at where the program's read-write data starts inside of the VM.
    #[inline]
    pub const fn rw_data_address(self) -> u32 {
        if self.ro_data_size == 0 {
            self.user_memory_region_address()
        } else {
            match align_to_next_page_u32(VM_MAX_PAGE_SIZE, self.ro_data_address() + self.ro_data_size) {
                Some(offset) => offset + VM_MAX_PAGE_SIZE,
                None => unreachable!(),
            }
        }
    }

    pub const fn rw_data_size(self) -> u32 {
        self.rw_data_size
    }

    /// Sets the program's read-write data size.
    pub fn set_rw_data_size(&mut self, rw_data_size: u32) -> Result<(), &'static str> {
        if rw_data_size > VM_MAXIMUM_MEMORY_SIZE {
            return Err("size of the read-write data exceeded the maximum memory size");
        }

        let rw_data_size = match align_to_next_page_u64(u64::from(VM_PAGE_SIZE), u64::from(rw_data_size)) {
            Some(value) => value,
            None => unreachable!(),
        } as u32;

        Self { rw_data_size, ..*self }.check_total_memory_size()?;
        self.rw_data_size = rw_data_size;
        Ok(())
    }

    /// The address at where the program's BSS section starts inside of the VM.
    #[inline]
    pub const fn bss_address(self) -> u32 {
        self.rw_data_address() + self.rw_data_size
    }

    #[inline]
    pub const fn bss_size(self) -> u32 {
        self.bss_size
    }

    /// Sets the program's BSS section size.
    pub fn set_bss_size(&mut self, bss_size: u32) -> Result<(), &'static str> {
        if bss_size > VM_MAXIMUM_MEMORY_SIZE {
            return Err("size of the bss section exceeded the maximum memory size");
        }

        let bss_size = match align_to_next_page_u64(u64::from(VM_PAGE_SIZE), u64::from(bss_size)) {
            Some(value) => value,
            None => unreachable!(),
        } as u32;

        Self { bss_size, ..*self }.check_total_memory_size()?;
        self.bss_size = bss_size;
        Ok(())
    }

    /// The address at where the program's stack starts inside of the VM.
    #[inline]
    pub const fn stack_address_low(self) -> u32 {
        self.stack_address_high() - self.stack_size
    }

    /// The address at where the program's stack ends inside of the VM.
    #[inline]
    pub const fn stack_address_high(self) -> u32 {
        VM_ADDR_USER_STACK_HIGH
    }

    #[inline]
    pub const fn stack_size(self) -> u32 {
        self.stack_size
    }

    #[inline]
    pub const fn stack_range(self) -> Range<u32> {
        self.stack_address_low()..self.stack_address_high()
    }

    /// Sets the program's stack size.
    pub fn set_stack_size(&mut self, stack_size: u32) -> Result<(), &'static str> {
        if stack_size > VM_MAXIMUM_MEMORY_SIZE {
            return Err("size of the stack exceeded the maximum memory size");
        }

        let stack_size = match align_to_next_page_u64(u64::from(VM_PAGE_SIZE), u64::from(stack_size)) {
            Some(value) => value,
            None => unreachable!(),
        } as u32;

        Self { stack_size, ..*self }.check_total_memory_size()?;
        self.stack_size = stack_size;
        Ok(())
    }

    #[inline]
    pub fn clear_stack_size(&mut self) {
        self.stack_size = 0;
    }

    /// The address at where the program's read-write memory starts inside of the VM.
    #[inline]
    pub const fn heap_address(self) -> u32 {
        self.rw_data_address()
    }

    /// The total size of the program's read-write memory, excluding the stack.
    #[inline]
    pub const fn heap_size(self) -> u32 {
        self.rw_data_size + self.bss_size
    }

    #[inline]
    pub const fn heap_range(self) -> Range<u32> {
        self.heap_address()..self.heap_address() + self.heap_size()
    }
}
