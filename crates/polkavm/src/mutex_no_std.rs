use core::cell::UnsafeCell;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicBool, Ordering};

pub struct Mutex<T> {
    pub value: UnsafeCell<T>,
    pub flag: AtomicBool,
}

// SAFETY: It's always safe to send this mutex to another thread.
unsafe impl<T> Send for Mutex<T> where T: Send {}

// SAFETY: It's always safe to access this mutex from multiple threads.
unsafe impl<T> Sync for Mutex<T> where T: Send {}

pub struct MutexGuard<'a, T: 'a>(&'a Mutex<T>);

impl<T> Mutex<T> {
    #[inline]
    pub const fn new(value: T) -> Self {
        Mutex {
            value: UnsafeCell::new(value),
            flag: AtomicBool::new(false),
        }
    }

    #[inline]
    pub fn lock(&self) -> MutexGuard<T> {
        while self
            .flag
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {}

        MutexGuard(self)
    }
}

impl<'a, T> Drop for MutexGuard<'a, T> {
    #[inline]
    fn drop(&mut self) {
        self.0.flag.store(false, Ordering::Release);
    }
}

impl<'a, T> Deref for MutexGuard<'a, T> {
    type Target = T;

    #[inline]
    fn deref(&self) -> &Self::Target {
        // SAFETY: We've locked the mutex, so we can access the data.
        unsafe { &*self.0.value.get() }
    }
}

impl<'a, T> DerefMut for MutexGuard<'a, T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        // SAFETY: We've locked the mutex, so we can access the data.
        unsafe { &mut *self.0.value.get() }
    }
}
