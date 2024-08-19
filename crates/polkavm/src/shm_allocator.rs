#![allow(clippy::undocumented_unsafe_blocks)]

use crate::mutex::Mutex;
use crate::sandbox::get_native_page_size;
use alloc::sync::Arc;
use linux_raw::{cstr, Error, Fd};
use polkavm_linux_raw as linux_raw;

use crate::generic_allocator::{GenericAllocation, GenericAllocator};

struct Config;

crate::generic_allocator::allocator_config! {
    impl AllocatorConfig for Config {
        const MAX_ALLOCATION_SIZE: u32 = (i32::MAX as u32) / 4096;
        const MAX_BINS: u32 = 4096;
    }
}

struct ShmAllocatorState {
    page_shift: u32,
    mmap: linux_raw::Mmap,
    fd: Fd,
    mutable: Mutex<GenericAllocator<Config>>,
}

#[derive(Clone)]
pub struct ShmAllocator(Arc<ShmAllocatorState>);

pub struct ShmAllocation {
    allocation: GenericAllocation,
    allocator: ShmAllocator,
}

impl ShmAllocation {
    /// Accesses the allocation as a slice.
    ///
    /// # Safety
    ///
    /// The allocation must not be already mutably borrowed.
    pub unsafe fn as_slice(&self) -> &[u8] {
        core::slice::from_raw_parts(self.as_ptr(), self.len())
    }

    /// Accesses the allocation as a mutable slice.
    ///
    /// # Safety
    ///
    /// The allocation must not be already immutably or mutably borrowed.
    #[allow(clippy::mut_from_ref)]
    pub unsafe fn as_slice_mut(&self) -> &mut [u8] {
        core::slice::from_raw_parts_mut(self.as_mut_ptr(), self.len())
    }

    /// Accesses the allocation as a mutable slice of a given type.
    ///
    /// # Safety
    ///
    /// - The allocation must not be already immutably or mutably borrowed.
    /// - The minimum alignment of `T` must be less than the page size.
    /// - Either the memory must be already initialized with valid values of type `T`,
    ///   or `T` cannot have any niches.
    #[allow(clippy::mut_from_ref)]
    pub unsafe fn as_typed_slice_mut<T>(&self) -> &mut [T] {
        core::slice::from_raw_parts_mut(self.as_mut_ptr().cast(), self.len() / core::mem::size_of::<T>())
    }

    pub fn offset(&self) -> usize {
        (self.allocation.offset() << self.allocator.0.page_shift) as usize
    }

    pub fn as_ptr(&self) -> *const u8 {
        unsafe {
            self.allocator
                .0
                .mmap
                .as_ptr()
                .cast::<u8>()
                .add((self.allocation.offset() << self.allocator.0.page_shift) as usize)
        }
    }

    pub fn as_mut_ptr(&self) -> *mut u8 {
        unsafe {
            self.allocator
                .0
                .mmap
                .as_mut_ptr()
                .cast::<u8>()
                .add((self.allocation.offset() << self.allocator.0.page_shift) as usize)
        }
    }

    pub fn len(&self) -> usize {
        (self.allocation.size() << self.allocator.0.page_shift) as usize
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Drop for ShmAllocation {
    fn drop(&mut self) {
        if self.allocation.is_empty() {
            return;
        }

        let mut mutable = self.allocator.0.mutable.lock();
        mutable.free(self.allocation);
    }
}

impl ShmAllocator {
    pub fn new() -> Result<Self, Error> {
        let page_size = get_native_page_size();
        assert!(page_size.is_power_of_two() && page_size >= 4096);
        let page_shift = page_size.ilog2();

        let fd = linux_raw::sys_memfd_create(cstr!("global"), linux_raw::MFD_CLOEXEC | linux_raw::MFD_ALLOW_SEALING)?;
        linux_raw::sys_ftruncate(fd.borrow(), linux_raw::c_ulong::from(u32::MAX))?;

        let mmap = unsafe {
            linux_raw::Mmap::map(
                core::ptr::null_mut(),
                u32::MAX as usize,
                linux_raw::PROT_READ | linux_raw::PROT_WRITE,
                linux_raw::MAP_SHARED,
                Some(fd.borrow()),
                0,
            )?
        };

        linux_raw::sys_fcntl(
            fd.borrow(),
            linux_raw::F_ADD_SEALS,
            linux_raw::F_SEAL_SEAL | linux_raw::F_SEAL_SHRINK | linux_raw::F_SEAL_GROW | linux_raw::F_SEAL_FUTURE_WRITE,
        )?;

        Ok(ShmAllocator(Arc::new(ShmAllocatorState {
            page_shift,
            mmap,
            fd,
            mutable: Mutex::new(GenericAllocator::<Config>::new(u32::MAX >> page_shift)),
        })))
    }

    pub fn alloc(&self, size: usize) -> Option<ShmAllocation> {
        if size == 0 {
            return Some(ShmAllocation {
                allocation: GenericAllocation::EMPTY,
                allocator: self.clone(),
            });
        }

        if size > ((1 << 31) - 1) {
            return None;
        }

        let mut page_count = (size >> self.0.page_shift) as u32;
        page_count += u32::from((page_count as usize) << self.0.page_shift != size); // Round up.

        Some(ShmAllocation {
            allocation: self.0.mutable.lock().alloc(page_count)?,
            allocator: self.clone(),
        })
    }

    pub fn fd(&self) -> linux_raw::FdRef {
        self.0.fd.borrow()
    }
}

#[test]
fn test_shm_allocator() {
    crate::sandbox::init_native_page_size();
    let page_size = get_native_page_size();
    let shm = ShmAllocator::new().unwrap();
    let allocation = shm.alloc(1).unwrap();
    assert_eq!(allocation.len(), page_size);
    unsafe {
        assert!(allocation.as_slice().iter().all(|&byte| byte == 0));
        allocation.as_slice_mut()[..7].copy_from_slice(b"sausage");
    }
    let address = allocation.as_ptr() as usize;
    core::mem::drop(allocation);

    let allocation = shm.alloc(1).unwrap();
    assert_eq!(allocation.as_ptr() as usize, address);
}
