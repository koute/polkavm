use crate::api::BackendAccess;
use crate::tracer::Tracer;
use core::mem::MaybeUninit;
use polkavm_common::error::Trap;
use polkavm_common::program::Reg;
use polkavm_common::utils::{Access, AsUninitSliceMut};
use std::rc::{Rc, Weak};

pub(crate) struct CallerRaw {
    user_data: *mut core::ffi::c_void,
    access: *mut core::ffi::c_void,
    tracer: Option<Tracer>,
}

impl CallerRaw {
    pub(crate) fn new(tracer: Option<Tracer>) -> Self {
        CallerRaw {
            user_data: core::ptr::null_mut(),
            access: core::ptr::null_mut(),
            tracer,
        }
    }

    unsafe fn data<T>(&self) -> &T {
        // SAFETY: The caller will make sure that the invariants hold.
        unsafe { &*(self.user_data as *const T) }
    }

    unsafe fn data_mut<T>(&mut self) -> &mut T {
        // SAFETY: The caller will make sure that the invariants hold.
        unsafe { &mut *(self.user_data as *mut T) }
    }

    unsafe fn access(&self) -> &BackendAccess {
        // SAFETY: The caller will make sure that the invariants hold.
        unsafe { &*(self.access as *mut BackendAccess as *const BackendAccess) }
    }

    unsafe fn access_mut(&mut self) -> &mut BackendAccess {
        // SAFETY: The caller will make sure that the invariants hold.
        unsafe { &mut *(self.access as *mut BackendAccess) }
    }

    pub(crate) fn tracer(&mut self) -> Option<&mut Tracer> {
        self.tracer.as_mut()
    }

    unsafe fn get_reg(&self, reg: Reg) -> u32 {
        // SAFETY: The caller will make sure that the invariants hold.
        let value = unsafe { self.access() }.get_reg(reg);
        log::trace!("Getting register (during hostcall): {reg} = 0x{value:x}");
        value
    }

    unsafe fn set_reg(&mut self, reg: Reg, value: u32) {
        log::trace!("Setting register (during hostcall): {reg} = 0x{value:x}");

        // SAFETY: The caller will make sure that the invariants hold.
        unsafe { self.access_mut() }.set_reg(reg, value);

        if let Some(ref mut tracer) = self.tracer() {
            tracer.on_set_reg_in_hostcall(reg, value);
        }
    }

    unsafe fn read_memory_into_slice<'slice, B>(&self, address: u32, buffer: &'slice mut B) -> Result<&'slice mut [u8], Trap>
    where
        B: ?Sized + AsUninitSliceMut,
    {
        // SAFETY: The caller will make sure that the invariants hold.
        let access = unsafe { self.access() };

        log::trace!(
            "Reading memory (during hostcall): 0x{:x}-0x{:x} ({} bytes)",
            address,
            (address as usize + buffer.as_uninit_slice_mut().len()) as u32,
            buffer.as_uninit_slice_mut().len()
        );
        access.read_memory_into_slice(address, buffer)
    }

    unsafe fn read_memory_into_new_vec(&self, address: u32, length: u32) -> Result<Vec<u8>, Trap> {
        log::trace!(
            "Reading memory (during hostcall): 0x{:x}-0x{:x} ({} bytes)",
            address,
            address.wrapping_add(length),
            length
        );

        // SAFETY: The caller will make sure that the invariants hold.
        unsafe { self.access() }.read_memory_into_new_vec(address, length)
    }

    unsafe fn read_u32(&self, address: u32) -> Result<u32, Trap> {
        let mut buffer: MaybeUninit<[u8; 4]> = MaybeUninit::uninit();

        // SAFETY: The caller will make sure that the invariants hold.
        let slice = unsafe { self.read_memory_into_slice(address, &mut buffer) }?;
        let value = u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]);
        Ok(value)
    }

    unsafe fn write_memory(&mut self, address: u32, data: &[u8]) -> Result<(), Trap> {
        log::trace!(
            "Writing memory (during hostcall): 0x{:x}-0x{:x} ({} bytes)",
            address,
            (address as usize + data.len()) as u32,
            data.len()
        );

        // SAFETY: The caller will make sure that the invariants hold.
        let result = unsafe { self.access_mut() }.write_memory(address, data);

        if let Some(ref mut tracer) = self.tracer() {
            tracer.on_memory_write_in_hostcall(address, data, result.is_ok())?;
        }

        result
    }
}

/// A handle used to access the execution context.
pub struct Caller<'a, T> {
    raw: &'a mut CallerRaw,
    lifetime: *mut Option<Rc<()>>,
    _phantom: core::marker::PhantomData<&'a mut T>,
}

impl<'a, T> Caller<'a, T> {
    pub(crate) fn wrap<R>(
        user_data: &mut T,
        access: &'a mut BackendAccess<'_>,
        raw: &'a mut CallerRaw,
        callback: impl FnOnce(Self) -> R,
    ) -> R
    where
        T: 'a,
    {
        raw.user_data = user_data as *mut T as *mut core::ffi::c_void;
        raw.access = access as *mut BackendAccess as *mut core::ffi::c_void;

        let mut lifetime = None;
        let caller = Caller {
            raw,
            lifetime: &mut lifetime,
            _phantom: core::marker::PhantomData,
        };

        let result = callback(caller);

        core::mem::drop(lifetime);
        result
    }

    /// Creates a caller handle with dynamically checked borrow rules.
    pub fn into_ref(self) -> CallerRef<T> {
        let lifetime = Rc::new(());
        let lifetime_weak = Rc::downgrade(&lifetime);

        // SAFETY: This can only be called from inside of `Caller::wrap` so the pointer to `lifetime` is always valid.
        unsafe {
            *self.lifetime = Some(lifetime);
        }

        CallerRef {
            raw: self.raw,
            lifetime: lifetime_weak,
            _phantom: core::marker::PhantomData,
        }
    }

    pub fn data(&self) -> &T {
        // SAFETY: This can only be called from inside of `Caller::wrap` so this is always valid.
        unsafe { self.raw.data() }
    }

    pub fn data_mut(&mut self) -> &mut T {
        // SAFETY: This can only be called from inside of `Caller::wrap` so this is always valid.
        unsafe { self.raw.data_mut() }
    }

    pub fn get_reg(&self, reg: Reg) -> u32 {
        // SAFETY: This can only be called from inside of `Caller::wrap` so this is always valid.
        unsafe { self.raw.get_reg(reg) }
    }

    pub fn set_reg(&mut self, reg: Reg, value: u32) {
        // SAFETY: This can only be called from inside of `Caller::wrap` so this is always valid.
        unsafe { self.raw.set_reg(reg, value) }
    }

    pub fn read_memory_into_slice<'slice, B>(&self, address: u32, buffer: &'slice mut B) -> Result<&'slice mut [u8], Trap>
    where
        B: ?Sized + AsUninitSliceMut,
    {
        // SAFETY: This can only be called from inside of `Caller::wrap` so this is always valid.
        unsafe { self.raw.read_memory_into_slice(address, buffer) }
    }

    pub fn read_memory_into_new_vec(&self, address: u32, length: u32) -> Result<Vec<u8>, Trap> {
        // SAFETY: This can only be called from inside of `Caller::wrap` so this is always valid.
        unsafe { self.raw.read_memory_into_new_vec(address, length) }
    }

    pub fn read_u32(&self, address: u32) -> Result<u32, Trap> {
        // SAFETY: This can only be called from inside of `Caller::wrap` so this is always valid.
        unsafe { self.raw.read_u32(address) }
    }

    pub fn write_memory(&mut self, address: u32, data: &[u8]) -> Result<(), Trap> {
        // SAFETY: This can only be called from inside of `Caller::wrap` so this is always valid.
        unsafe { self.raw.write_memory(address, data) }
    }
}

/// A handle used to access the execution context, with erased lifetimes for convenience.
///
/// Can only be used from within the handler to which the original [`Caller`] was passed.
/// Will panic if used incorrectly.
pub struct CallerRef<T> {
    raw: *mut CallerRaw,
    lifetime: Weak<()>,
    _phantom: core::marker::PhantomData<T>,
}

impl<T> CallerRef<T> {
    fn check_lifetime_or_panic(&self) {
        assert!(self.lifetime.strong_count() > 0, "CallerRef accessed outside of a hostcall handler");
    }

    pub fn data(&self) -> &T {
        self.check_lifetime_or_panic();

        // SAFETY: We've made sure the lifetime is valid.
        unsafe { (*self.raw).data() }
    }

    pub fn data_mut(&mut self) -> &mut T {
        self.check_lifetime_or_panic();

        // SAFETY: We've made sure the lifetime is valid.
        unsafe { (*self.raw).data_mut() }
    }

    pub fn get_reg(&self, reg: Reg) -> u32 {
        self.check_lifetime_or_panic();

        // SAFETY: We've made sure the lifetime is valid.
        unsafe { (*self.raw).get_reg(reg) }
    }

    pub fn set_reg(&mut self, reg: Reg, value: u32) {
        self.check_lifetime_or_panic();

        // SAFETY: We've made sure the lifetime is valid.
        unsafe { (*self.raw).set_reg(reg, value) }
    }

    pub fn read_memory_into_slice<'slice, B>(&self, address: u32, buffer: &'slice mut B) -> Result<&'slice mut [u8], Trap>
    where
        B: ?Sized + AsUninitSliceMut,
    {
        self.check_lifetime_or_panic();

        // SAFETY: We've made sure the lifetime is valid.
        unsafe { (*self.raw).read_memory_into_slice(address, buffer) }
    }

    pub fn read_memory_into_new_vec(&self, address: u32, length: u32) -> Result<Vec<u8>, Trap> {
        self.check_lifetime_or_panic();

        // SAFETY: We've made sure the lifetime is valid.
        unsafe { (*self.raw).read_memory_into_new_vec(address, length) }
    }

    pub fn read_u32(&self, address: u32) -> Result<u32, Trap> {
        self.check_lifetime_or_panic();

        // SAFETY: We've made sure the lifetime is valid.
        unsafe { (*self.raw).read_u32(address) }
    }

    pub fn write_memory(&mut self, address: u32, data: &[u8]) -> Result<(), Trap> {
        self.check_lifetime_or_panic();

        // SAFETY: We've made sure the lifetime is valid.
        unsafe { (*self.raw).write_memory(address, data) }
    }
}

// Source: https://users.rust-lang.org/t/a-macro-to-assert-that-a-type-does-not-implement-trait-bounds/31179
macro_rules! assert_not_impl {
    ($x:ty, $($t:path),+ $(,)*) => {
        const _: fn() -> () = || {
            struct Check<T: ?Sized>(T);
            trait AmbiguousIfImpl<A> { fn some_item() { } }

            impl<T: ?Sized> AmbiguousIfImpl<()> for Check<T> { }
            impl<T: ?Sized $(+ $t)*> AmbiguousIfImpl<u8> for Check<T> { }

            <Check::<$x> as AmbiguousIfImpl<_>>::some_item()
        };
    };
}

assert_not_impl!(CallerRef<()>, Send);
assert_not_impl!(CallerRef<()>, Sync);
assert_not_impl!(Caller<'static, ()>, Send);
assert_not_impl!(Caller<'static, ()>, Sync);
