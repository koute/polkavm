#![no_std]

extern crate alloc;

#[repr(C, align(16))]
pub struct SimpleAlloc<const N: usize> {
    heap: [u8; N],

    #[cfg(all(feature = "thread-safe", target_has_atomic = "ptr"))]
    capacity_used: core::sync::atomic::AtomicUsize,

    #[cfg(not(all(feature = "thread-safe", target_has_atomic = "ptr")))]
    capacity_used: core::cell::Cell<usize>,
}

impl<const N: usize> SimpleAlloc<N> {
    #[inline]
    pub const fn new() -> Self {
        SimpleAlloc {
            heap: [0; N],

            #[cfg(all(feature = "thread-safe", target_has_atomic = "ptr"))]
            capacity_used: core::sync::atomic::AtomicUsize::new(0),

            #[cfg(not(all(feature = "thread-safe", target_has_atomic = "ptr")))]
            capacity_used: core::cell::Cell::new(0),
        }
    }

    #[inline]
    pub fn capacity_used(&self) -> usize {
        #[cfg(all(feature = "thread-safe", target_has_atomic = "ptr"))]
        {
            self.capacity_used.load(core::sync::atomic::Ordering::Relaxed)
        }

        #[cfg(not(all(feature = "thread-safe", target_has_atomic = "ptr")))]
        {
            self.capacity_used.get()
        }
    }

    #[inline]
    fn try_set_capacity_used(&self, _old_value: usize, value: usize) -> bool {
        #[cfg(all(feature = "thread-safe", target_has_atomic = "ptr"))]
        {
            use core::sync::atomic::Ordering;
            self.capacity_used
                .compare_exchange(_old_value, value, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        }

        #[cfg(not(all(feature = "thread-safe", target_has_atomic = "ptr")))]
        {
            self.capacity_used.set(value);
            true
        }
    }

    pub fn allocate(&self, size: usize, align: usize) -> *mut u8 {
        if align.count_ones() != 1 {
            // The alignment must be non-zero and be a power of two.
            return core::ptr::null_mut();
        }

        loop {
            let old_capacity_used = self.capacity_used();
            let Some(mut new_capacity_used) = old_capacity_used.checked_add(size) else {
                return core::ptr::null_mut();
            };

            if new_capacity_used
                .checked_add(align)
                .map(|length_bound| length_bound > N)
                .unwrap_or(true)
            {
                // Conservatively assume we'll have to align the pointer.
                return core::ptr::null_mut();
            }

            let unaligned_pointer = unsafe { self.heap.as_ptr().add(N - new_capacity_used) };
            let padding = unaligned_pointer as usize - (unaligned_pointer as usize & !(align - 1));
            new_capacity_used += padding;

            if !self.try_set_capacity_used(old_capacity_used, new_capacity_used) {
                continue;
            }

            let aligned_pointer = unsafe { unaligned_pointer.sub(padding) as *mut _ };

            debug_assert!(aligned_pointer as usize >= self.heap.as_ptr() as usize);
            debug_assert!((aligned_pointer as usize) < self.heap.as_ptr() as usize + N);
            debug_assert_eq!(aligned_pointer as usize % align, 0);
            return aligned_pointer;
        }
    }

    pub fn deallocate(&self, pointer: *mut u8, size: usize) {
        if size > N {
            return;
        }

        loop {
            let old_capacity_used = self.capacity_used();
            let mut new_capacity_used = old_capacity_used;

            if pointer as usize != self.heap.as_ptr() as usize + N - new_capacity_used {
                return;
            }

            new_capacity_used -= size;
            if !self.try_set_capacity_used(old_capacity_used, new_capacity_used) {
                continue;
            }

            return;
        }
    }
}

#[cfg(any(feature = "thread-safe", not(target_has_atomic = "ptr")))]
unsafe impl<const N: usize> alloc::alloc::GlobalAlloc for SimpleAlloc<N> {
    #[inline]
    unsafe fn alloc(&self, layout: alloc::alloc::Layout) -> *mut u8 {
        self.allocate(layout.size(), layout.align())
    }

    #[inline]
    unsafe fn dealloc(&self, pointer: *mut u8, layout: alloc::alloc::Layout) {
        self.deallocate(pointer, layout.size())
    }
}

#[test]
fn test_simple_allocator_basics() {
    let alloc = SimpleAlloc::<1024>::new();
    assert_eq!(alloc.allocate(1025, 1), core::ptr::null_mut());

    let p = alloc.allocate(24, 1);
    assert_eq!(p as *const u8, unsafe { alloc.heap.as_ptr().add(1000) });
    assert_eq!(alloc.capacity_used(), 24);
    alloc.deallocate(p, 24);
    assert_eq!(alloc.capacity_used(), 0);

    let p = alloc.allocate(1, 16);
    assert_eq!(p as usize % 16, 0);
    assert_eq!(p as *const u8, unsafe { alloc.heap.as_ptr().add(1008) });
    assert_eq!(alloc.capacity_used(), 16);
}

#[test]
fn test_simple_allocator_length_overflow() {
    let alloc = SimpleAlloc::<1024>::new();
    assert_eq!(alloc.allocate(!0, 0), core::ptr::null_mut());
    assert_eq!(alloc.allocate(0, !0), core::ptr::null_mut());
    assert_eq!(alloc.allocate(!0, !0), core::ptr::null_mut());
}
