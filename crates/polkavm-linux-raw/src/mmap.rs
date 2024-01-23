use crate::{c_size_t, c_uint, c_ulong, sys_mmap, sys_munmap, Error, FdRef};
use core::ffi::c_void;

pub struct Mmap {
    pointer: *mut c_void,
    length: usize,
}

unsafe impl Send for Mmap {}
unsafe impl Sync for Mmap {}

impl Mmap {
    pub unsafe fn map(
        address: *mut c_void,
        length: c_size_t,
        protection: c_uint,
        flags: c_uint,
        fd: Option<FdRef>,
        offset: c_ulong,
    ) -> Result<Self, Error> {
        let pointer = sys_mmap(address, length, protection, flags, fd, offset)?;
        Ok(Self { pointer, length })
    }

    fn unmap_inplace(&mut self) -> Result<(), Error> {
        if self.length > 0 {
            unsafe {
                sys_munmap(self.pointer, self.length)?;
            }

            self.length = 0;
            self.pointer = core::ptr::NonNull::<c_void>::dangling().as_ptr();
        }

        Ok(())
    }

    pub fn unmap(mut self) -> Result<(), Error> {
        self.unmap_inplace()
    }

    #[inline]
    pub fn as_ptr(&self) -> *const c_void {
        self.pointer
    }

    #[inline]
    pub fn as_mut_ptr(&self) -> *mut c_void {
        self.pointer
    }

    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self.as_ptr().cast::<u8>(), self.length) }
    }

    #[inline]
    pub fn as_slice_mut(&mut self) -> &mut [u8] {
        unsafe { core::slice::from_raw_parts_mut(self.as_mut_ptr().cast::<u8>(), self.length) }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.length
    }
}

impl Default for Mmap {
    fn default() -> Self {
        Self {
            pointer: core::ptr::NonNull::<u8>::dangling().as_ptr().cast::<c_void>(),
            length: 0,
        }
    }
}

impl Drop for Mmap {
    fn drop(&mut self) {
        let _ = self.unmap_inplace();
    }
}
