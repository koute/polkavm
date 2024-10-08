use crate::api::RegValue;
use crate::error::bail;
use crate::program::ProgramSymbol;
use crate::{Error, InterruptKind, Module, ProgramCounter, RawInstance, Reg};
use alloc::borrow::ToOwned;
use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::marker::PhantomData;

#[cfg(not(feature = "std"))]
use alloc::collections::btree_map::Entry;
#[cfg(not(feature = "std"))]
use alloc::collections::BTreeMap as LookupMap;

#[cfg(feature = "std")]
use std::collections::hash_map::Entry;
#[cfg(feature = "std")]
use std::collections::HashMap as LookupMap;

trait CallFn<UserData, UserError>: Send + Sync {
    fn call(&self, user_data: &mut UserData, instance: &mut RawInstance) -> Result<(), UserError>;
}

#[repr(transparent)]
pub struct CallFnArc<UserData, UserError>(Arc<dyn CallFn<UserData, UserError>>);

type FallbackHandlerArc<UserData, UserError> = Arc<dyn Fn(Caller<UserData>, u32) -> Result<(), UserError> + Send + Sync + 'static>;

impl<UserData, UserError> Clone for CallFnArc<UserData, UserError> {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

pub trait IntoCallFn<UserData, UserError, Params, Result>: Send + Sync + 'static {
    #[doc(hidden)]
    const _REGS_REQUIRED_32: usize;

    #[doc(hidden)]
    const _REGS_REQUIRED_64: usize;

    #[doc(hidden)]
    fn _into_extern_fn(self) -> CallFnArc<UserData, UserError>;
}

/// A type which can be marshalled through the VM's FFI boundary.
pub trait AbiTy: Sized + Send + 'static {
    #[doc(hidden)]
    const _REGS_REQUIRED_32: usize;

    #[doc(hidden)]
    const _REGS_REQUIRED_64: usize;

    #[doc(hidden)]
    fn _get32(get_reg: impl FnMut() -> RegValue) -> Self;

    #[doc(hidden)]
    fn _get64(get_reg: impl FnMut() -> RegValue) -> Self;

    #[doc(hidden)]
    fn _set32(self, set_reg: impl FnMut(RegValue));

    #[doc(hidden)]
    fn _set64(self, set_reg: impl FnMut(RegValue));
}

impl AbiTy for u32 {
    const _REGS_REQUIRED_32: usize = 1;
    const _REGS_REQUIRED_64: usize = 1;

    fn _get32(mut get_reg: impl FnMut() -> RegValue) -> Self {
        get_reg() as u32
    }

    fn _get64(mut get_reg: impl FnMut() -> RegValue) -> Self {
        get_reg() as u32
    }

    fn _set32(self, mut set_reg: impl FnMut(RegValue)) {
        set_reg(u64::from(self))
    }

    fn _set64(self, mut set_reg: impl FnMut(RegValue)) {
        set_reg(u64::from(self))
    }
}

impl AbiTy for i32 {
    const _REGS_REQUIRED_32: usize = <u32 as AbiTy>::_REGS_REQUIRED_32;
    const _REGS_REQUIRED_64: usize = <u32 as AbiTy>::_REGS_REQUIRED_64;

    fn _get32(get_reg: impl FnMut() -> RegValue) -> Self {
        <u32 as AbiTy>::_get32(get_reg) as i32
    }

    fn _get64(get_reg: impl FnMut() -> RegValue) -> Self {
        <u32 as AbiTy>::_get64(get_reg) as i32
    }

    fn _set32(self, set_reg: impl FnMut(RegValue)) {
        (self as u32)._set32(set_reg)
    }

    fn _set64(self, set_reg: impl FnMut(RegValue)) {
        i64::from(self)._set64(set_reg)
    }
}

impl AbiTy for u64 {
    const _REGS_REQUIRED_32: usize = 2;
    const _REGS_REQUIRED_64: usize = 1;

    fn _get32(mut get_reg: impl FnMut() -> RegValue) -> Self {
        let value_lo = get_reg();
        let value_hi = get_reg();
        debug_assert!(value_lo <= u64::from(u32::MAX));
        debug_assert!(value_hi <= u64::from(u32::MAX));
        value_lo | (value_hi << 32)
    }

    fn _get64(mut get_reg: impl FnMut() -> RegValue) -> Self {
        get_reg()
    }

    fn _set32(self, mut set_reg: impl FnMut(RegValue)) {
        set_reg(self);
        set_reg(self >> 32);
    }

    fn _set64(self, mut set_reg: impl FnMut(RegValue)) {
        set_reg(self);
    }
}

impl AbiTy for i64 {
    const _REGS_REQUIRED_32: usize = <u64 as AbiTy>::_REGS_REQUIRED_32;
    const _REGS_REQUIRED_64: usize = <u64 as AbiTy>::_REGS_REQUIRED_64;

    fn _get32(get_reg: impl FnMut() -> RegValue) -> Self {
        <u64 as AbiTy>::_get32(get_reg) as i64
    }

    fn _get64(get_reg: impl FnMut() -> RegValue) -> Self {
        <u64 as AbiTy>::_get64(get_reg) as i64
    }

    fn _set32(self, set_reg: impl FnMut(RegValue)) {
        (self as u64)._set32(set_reg)
    }

    fn _set64(self, set_reg: impl FnMut(RegValue)) {
        (self as u64)._set64(set_reg)
    }
}

// `AbiTy` is deliberately not implemented for `usize`.

/// A type which can be returned from a host function.
pub trait ReturnTy<UserError>: Sized + 'static {
    #[doc(hidden)]
    const _REGS_REQUIRED_32: usize;

    #[doc(hidden)]
    const _REGS_REQUIRED_64: usize;

    #[doc(hidden)]
    fn _handle_return32(self, set_reg: impl FnMut(RegValue)) -> Result<(), UserError>;

    #[doc(hidden)]
    fn _handle_return64(self, set_reg: impl FnMut(RegValue)) -> Result<(), UserError>;
}

impl<UserError, T> ReturnTy<UserError> for T
where
    T: AbiTy,
{
    const _REGS_REQUIRED_32: usize = <T as AbiTy>::_REGS_REQUIRED_32;
    const _REGS_REQUIRED_64: usize = <T as AbiTy>::_REGS_REQUIRED_64;

    fn _handle_return32(self, set_reg: impl FnMut(RegValue)) -> Result<(), UserError> {
        self._set32(set_reg);
        Ok(())
    }

    fn _handle_return64(self, set_reg: impl FnMut(RegValue)) -> Result<(), UserError> {
        self._set64(set_reg);
        Ok(())
    }
}

impl<UserError> ReturnTy<UserError> for () {
    const _REGS_REQUIRED_32: usize = 0;
    const _REGS_REQUIRED_64: usize = 0;

    fn _handle_return32(self, _set_reg: impl FnMut(RegValue)) -> Result<(), UserError> {
        Ok(())
    }

    fn _handle_return64(self, _set_reg: impl FnMut(RegValue)) -> Result<(), UserError> {
        Ok(())
    }
}

impl<UserError, E> ReturnTy<UserError> for Result<(), E>
where
    UserError: From<E>,
    E: 'static,
{
    const _REGS_REQUIRED_32: usize = 0;
    const _REGS_REQUIRED_64: usize = 0;

    fn _handle_return32(self, _set_reg: impl FnMut(RegValue)) -> Result<(), UserError> {
        Ok(self?)
    }

    fn _handle_return64(self, _set_reg: impl FnMut(RegValue)) -> Result<(), UserError> {
        Ok(self?)
    }
}

impl<UserError, T, E> ReturnTy<UserError> for Result<T, E>
where
    UserError: From<E>,
    E: 'static,
    T: AbiTy,
{
    const _REGS_REQUIRED_32: usize = <T as AbiTy>::_REGS_REQUIRED_32;
    const _REGS_REQUIRED_64: usize = <T as AbiTy>::_REGS_REQUIRED_64;

    fn _handle_return32(self, set_reg: impl FnMut(RegValue)) -> Result<(), UserError> {
        self?._set32(set_reg);
        Ok(())
    }

    fn _handle_return64(self, set_reg: impl FnMut(RegValue)) -> Result<(), UserError> {
        self?._set64(set_reg);
        Ok(())
    }
}

pub trait FuncArgs: Send {
    #[doc(hidden)]
    const _REGS_REQUIRED_32: usize;
    #[doc(hidden)]
    const _REGS_REQUIRED_64: usize;

    #[doc(hidden)]
    fn _set(self, is_64_bit: bool, set_reg: impl FnMut(RegValue)) where Self: Sized {
        if is_64_bit {
            self._set64(set_reg);
        } else {
            self._set32(set_reg);
        }
    }

    #[doc(hidden)]
    fn _set32(self, set_reg: impl FnMut(RegValue));

    #[doc(hidden)]
    fn _set64(self, set_reg: impl FnMut(RegValue));
}

pub trait FuncResult: Send + Sized {
    #[doc(hidden)]
    const _REGS_REQUIRED_32: usize;
    #[doc(hidden)]
    const _REGS_REQUIRED_64: usize;

    #[doc(hidden)]
    fn _get(is_64_bit: bool, get_reg: impl FnMut() -> RegValue) -> Self {
        if is_64_bit {
            Self::_get64(get_reg)
        } else {
            Self::_get32(get_reg)
        }
    }

    #[doc(hidden)]
    fn _get32(get_reg: impl FnMut() -> RegValue) -> Self;

    #[doc(hidden)]
    fn _get64(get_reg: impl FnMut() -> RegValue) -> Self;
}

impl FuncResult for () {
    const _REGS_REQUIRED_32: usize = 0;
    const _REGS_REQUIRED_64: usize = 0;

    fn _get32(_: impl FnMut() -> RegValue) -> Self {}
    fn _get64(_: impl FnMut() -> RegValue) -> Self {}
}

impl<T> FuncResult for T
where
    T: AbiTy,
{
    const _REGS_REQUIRED_32: usize = <T as AbiTy>::_REGS_REQUIRED_32;
    const _REGS_REQUIRED_64: usize = <T as AbiTy>::_REGS_REQUIRED_64;

    fn _get32(get_reg: impl FnMut() -> RegValue) -> Self {
        <T as AbiTy>::_get32(get_reg)
    }

    fn _get64(get_reg: impl FnMut() -> RegValue) -> Self {
        <T as AbiTy>::_get64(get_reg)
    }
}

macro_rules! impl_into_extern_fn {
    (@check_reg_count $regs_required:expr) => {
        if $regs_required > Reg::ARG_REGS.len() {
            // TODO: We should probably print out which exact function it is.
            panic!("external call failed: too many registers required for arguments!");
        }
    };

    (@call $is_64_bit:expr, $caller:expr, $callback:expr, ) => {{
        ($callback)($caller)
    }};

    (@get_reg $caller:expr) => {{
        let mut reg_index = 0;
        let caller = &mut $caller;
        move || -> RegValue {
            let value = caller.instance.reg(Reg::ARG_REGS[reg_index]);
            reg_index += 1;
            value
        }
    }};

    (@call $is_64_bit:expr, $caller:expr, $callback:expr, $a0:ident) => {{
        let cb = impl_into_extern_fn!(@get_reg $caller);
        let a0;
        if $is_64_bit {
            impl_into_extern_fn!(@check_reg_count $a0::_REGS_REQUIRED_64);
            a0 = $a0::_get64(cb);
        } else {
            impl_into_extern_fn!(@check_reg_count $a0::_REGS_REQUIRED_32);
            a0 = $a0::_get32(cb);
        }

        ($callback)($caller, a0)
    }};

    (@call $is_64_bit:expr, $caller:expr, $callback:expr, $a0:ident, $a1:ident) => {{
        let mut cb = impl_into_extern_fn!(@get_reg $caller);
        let a0;
        let a1;
        if $is_64_bit {
            impl_into_extern_fn!(@check_reg_count $a0::_REGS_REQUIRED_64 + $a1::_REGS_REQUIRED_64);
            a0 = $a0::_get64(&mut cb);
            a1 = $a1::_get64(cb);
        } else {
            impl_into_extern_fn!(@check_reg_count $a0::_REGS_REQUIRED_32 + $a1::_REGS_REQUIRED_32);
            a0 = $a0::_get32(&mut cb);
            a1 = $a1::_get32(cb);
        }

        ($callback)($caller, a0, a1)
    }};

    (@call $is_64_bit:expr, $caller:expr, $callback:expr, $a0:ident, $a1:ident, $a2:ident) => {{
        let mut cb = impl_into_extern_fn!(@get_reg $caller);
        let a0;
        let a1;
        let a2;
        if $is_64_bit {
            impl_into_extern_fn!(@check_reg_count $a0::_REGS_REQUIRED_64 + $a1::_REGS_REQUIRED_64 + $a2::_REGS_REQUIRED_64);
            a0 = $a0::_get64(&mut cb);
            a1 = $a1::_get64(&mut cb);
            a2 = $a2::_get64(cb);
        } else {
            impl_into_extern_fn!(@check_reg_count $a0::_REGS_REQUIRED_32 + $a1::_REGS_REQUIRED_32 + $a2::_REGS_REQUIRED_32);
            a0 = $a0::_get32(&mut cb);
            a1 = $a1::_get32(&mut cb);
            a2 = $a2::_get32(cb);
        }

        ($callback)($caller, a0, a1, a2)
    }};

    (@call $is_64_bit:expr, $caller:expr, $callback:expr, $a0:ident, $a1:ident, $a2:ident, $a3:ident) => {{
        let mut cb = impl_into_extern_fn!(@get_reg $caller);
        let a0;
        let a1;
        let a2;
        let a3;
        if $is_64_bit {
            impl_into_extern_fn!(@check_reg_count $a0::_REGS_REQUIRED_64 + $a1::_REGS_REQUIRED_64 + $a2::_REGS_REQUIRED_64 + $a3::_REGS_REQUIRED_64);
            a0 = $a0::_get64(&mut cb);
            a1 = $a1::_get64(&mut cb);
            a2 = $a2::_get64(&mut cb);
            a3 = $a3::_get64(cb);
        } else {
            impl_into_extern_fn!(@check_reg_count $a0::_REGS_REQUIRED_32 + $a1::_REGS_REQUIRED_32 + $a2::_REGS_REQUIRED_32 + $a3::_REGS_REQUIRED_32);
            a0 = $a0::_get32(&mut cb);
            a1 = $a1::_get32(&mut cb);
            a2 = $a2::_get32(&mut cb);
            a3 = $a3::_get32(cb);
        }

        ($callback)($caller, a0, a1, a2, a3)
    }};

    (@call $is_64_bit:expr, $caller:expr, $callback:expr, $a0:ident, $a1:ident, $a2:ident, $a3:ident, $a4:ident) => {{
        let mut cb = impl_into_extern_fn!(@get_reg $caller);
        let a0;
        let a1;
        let a2;
        let a3;
        let a4;
        if $is_64_bit {
            impl_into_extern_fn!(@check_reg_count $a0::_REGS_REQUIRED_64 + $a1::_REGS_REQUIRED_64 + $a2::_REGS_REQUIRED_64 + $a3::_REGS_REQUIRED_64 + $a4::_REGS_REQUIRED_64);
            a0 = $a0::_get64(&mut cb);
            a1 = $a1::_get64(&mut cb);
            a2 = $a2::_get64(&mut cb);
            a3 = $a3::_get64(&mut cb);
            a4 = $a4::_get64(cb);
        } else {
            impl_into_extern_fn!(@check_reg_count $a0::_REGS_REQUIRED_32 + $a1::_REGS_REQUIRED_32 + $a2::_REGS_REQUIRED_32 + $a3::_REGS_REQUIRED_32 + $a4::_REGS_REQUIRED_32);
            a0 = $a0::_get32(&mut cb);
            a1 = $a1::_get32(&mut cb);
            a2 = $a2::_get32(&mut cb);
            a3 = $a3::_get32(&mut cb);
            a4 = $a4::_get32(cb);
        }

        ($callback)($caller, a0, a1, a2, a3, a4)
    }};

    (@call $is_64_bit:expr, $caller:expr, $callback:expr, $a0:ident, $a1:ident, $a2:ident, $a3:ident, $a4:ident, $a5:ident) => {{
        let mut cb = impl_into_extern_fn!(@get_reg $caller);
        let a0;
        let a1;
        let a2;
        let a3;
        let a4;
        let a5;
        if $is_64_bit {
            impl_into_extern_fn!(@check_reg_count $a0::_REGS_REQUIRED_64 + $a1::_REGS_REQUIRED_64 + $a2::_REGS_REQUIRED_64 + $a3::_REGS_REQUIRED_64 + $a4::_REGS_REQUIRED_64 + $a5::_REGS_REQUIRED_64);
            a0 = $a0::_get64(&mut cb);
            a1 = $a1::_get64(&mut cb);
            a2 = $a2::_get64(&mut cb);
            a3 = $a3::_get64(&mut cb);
            a4 = $a4::_get64(&mut cb);
            a5 = $a5::_get64(cb);
        } else {
            impl_into_extern_fn!(@check_reg_count $a0::_REGS_REQUIRED_32 + $a1::_REGS_REQUIRED_32 + $a2::_REGS_REQUIRED_32 + $a3::_REGS_REQUIRED_32 + $a4::_REGS_REQUIRED_32 + $a5::_REGS_REQUIRED_32);
            a0 = $a0::_get32(&mut cb);
            a1 = $a1::_get32(&mut cb);
            a2 = $a2::_get32(&mut cb);
            a3 = $a3::_get32(&mut cb);
            a4 = $a4::_get32(&mut cb);
            a5 = $a5::_get32(cb);
        }

        ($callback)($caller, a0, a1, a2, a3, a4, a5)
    }};

    ($arg_count:tt $($args:ident)*) => {
        impl<UserData, UserError, F, $($args,)* R> CallFn<UserData, UserError> for (F, UnsafePhantomData<(R, $($args),*)>)
            where
            F: Fn(Caller<'_, UserData>, $($args),*) -> R + Send + Sync + 'static,
            $($args: AbiTy,)*
            R: ReturnTy<UserError>,
        {
            fn call(&self, user_data: &mut UserData, instance: &mut RawInstance) -> Result<(), UserError> {
                let is_64_bit = instance.module().blob().is_64_bit();
                let result = {
                    #[allow(unused_mut)]
                    let mut caller = Caller {
                        user_data,
                        instance
                    };

                    impl_into_extern_fn!(@call is_64_bit, caller, self.0, $($args),*)
                };

                let set_reg = {
                    let mut reg_index = 0;
                    move |value: RegValue| {
                        let reg = Reg::ARG_REGS[reg_index];
                        instance.set_reg(reg, value);
                        reg_index += 1;
                    }
                };

                if is_64_bit {
                    result._handle_return64(set_reg)
                } else {
                    result._handle_return32(set_reg)
                }
            }
        }

        impl<UserData, UserError, F, $($args,)* R> IntoCallFn<UserData, UserError, ($($args,)*), R> for F
        where
            F: Fn($($args),*) -> R + Send + Sync + 'static,
            $($args: AbiTy,)*
            R: ReturnTy<UserError>,
        {
            const _REGS_REQUIRED_32: usize = 0 $(+ $args::_REGS_REQUIRED_32)*;
            const _REGS_REQUIRED_64: usize = 0 $(+ $args::_REGS_REQUIRED_64)*;

            fn _into_extern_fn(self) -> CallFnArc<UserData, UserError> {
                #[allow(non_snake_case)]
                let callback = move |_caller: Caller<UserData>, $($args: $args),*| -> R {
                    self($($args),*)
                };
                CallFnArc(Arc::new((callback, UnsafePhantomData(PhantomData::<(R, $($args),*)>))))
            }
        }

        impl<UserData, UserError, F, $($args,)* R> IntoCallFn<UserData, UserError, (Caller<'_, UserData>, $($args,)*), R> for F
        where
            F: Fn(Caller<'_, UserData>, $($args),*) -> R + Send + Sync + 'static,
            $($args: AbiTy,)*
            R: ReturnTy<UserError>,
        {
            const _REGS_REQUIRED_32: usize = 0 $(+ $args::_REGS_REQUIRED_32)*;
            const _REGS_REQUIRED_64: usize = 0 $(+ $args::_REGS_REQUIRED_64)*;

            fn _into_extern_fn(self) -> CallFnArc<UserData, UserError> {
                CallFnArc(Arc::new((self, UnsafePhantomData(PhantomData::<(R, $($args),*)>))))
            }
        }

        impl<$($args: Send + AbiTy,)*> FuncArgs for ($($args,)*) {
            const _REGS_REQUIRED_32: usize = 0 $(+ $args::_REGS_REQUIRED_32)*;
            const _REGS_REQUIRED_64: usize = 0 $(+ $args::_REGS_REQUIRED_64)*;

            #[allow(unused_mut)]
            #[allow(unused_variables)]
            #[allow(non_snake_case)]
            fn _set32(self, mut set_reg: impl FnMut(RegValue)) {
                let ($($args,)*) = self;
                $($args._set32(&mut set_reg);)*
            }

            #[allow(unused_mut)]
            #[allow(unused_variables)]
            #[allow(non_snake_case)]
            fn _set64(self, mut set_reg: impl FnMut(RegValue)) {
                let ($($args,)*) = self;
                $($args._set64(&mut set_reg);)*
            }
        }
    };
}

impl_into_extern_fn!(0);
impl_into_extern_fn!(1 A0);
impl_into_extern_fn!(2 A0 A1);
impl_into_extern_fn!(3 A0 A1 A2);
impl_into_extern_fn!(4 A0 A1 A2 A3);
impl_into_extern_fn!(5 A0 A1 A2 A3 A4);
impl_into_extern_fn!(6 A0 A1 A2 A3 A4 A5);

#[repr(transparent)]
struct UnsafePhantomData<T>(PhantomData<T>);

// SAFETY: This is only used to hold a type used exclusively at compile time, so regardless of whether it implements `Send` this will be safe.
unsafe impl<T> Send for UnsafePhantomData<T> {}

// SAFETY: This is only used to hold a type used exclusively at compile time, so regardless of whether it implements `Sync` this will be safe.
unsafe impl<T> Sync for UnsafePhantomData<T> {}

struct DynamicFn<T, F> {
    callback: F,
    _phantom: UnsafePhantomData<T>,
}

impl<UserData, UserError, F> CallFn<UserData, UserError> for DynamicFn<UserData, F>
where
    F: Fn(Caller<'_, UserData>) -> Result<(), UserError> + Send + Sync + 'static,
    UserData: 'static,
{
    fn call(&self, user_data: &mut UserData, instance: &mut RawInstance) -> Result<(), UserError> {
        let caller = Caller { user_data, instance };

        (self.callback)(caller)
    }
}

#[non_exhaustive]
pub struct Caller<'a, UserData = ()> {
    pub user_data: &'a mut UserData,
    pub instance: &'a mut RawInstance,
}

pub struct Linker<UserData = (), UserError = core::convert::Infallible> {
    host_functions: LookupMap<Vec<u8>, CallFnArc<UserData, UserError>>,
    #[allow(clippy::type_complexity)]
    fallback_handler: Option<FallbackHandlerArc<UserData, UserError>>,
    phantom: PhantomData<(UserData, UserError)>,
}

impl<UserData, UserError> Default for Linker<UserData, UserError> {
    fn default() -> Self {
        Self::new()
    }
}

impl<UserData, UserError> Linker<UserData, UserError> {
    pub fn new() -> Self {
        Self {
            host_functions: Default::default(),
            fallback_handler: None,
            phantom: PhantomData,
        }
    }

    /// Defines a fallback external call handler, in case no other registered functions match.
    pub fn define_fallback(&mut self, func: impl Fn(Caller<UserData>, u32) -> Result<(), UserError> + Send + Sync + 'static) {
        self.fallback_handler = Some(Arc::new(func));
    }

    /// Defines a new untyped handler for external calls with a given symbol.
    pub fn define_untyped(
        &mut self,
        symbol: impl AsRef<[u8]>,
        func: impl Fn(Caller<UserData>) -> Result<(), UserError> + Send + Sync + 'static,
    ) -> Result<&mut Self, Error>
    where
        UserData: 'static,
    {
        let symbol = symbol.as_ref();
        if self.host_functions.contains_key(symbol) {
            bail!(
                "cannot register host function: host function was already registered: {}",
                ProgramSymbol::new(symbol)
            );
        }

        self.host_functions.insert(
            symbol.to_owned(),
            CallFnArc(Arc::new(DynamicFn {
                callback: func,
                _phantom: UnsafePhantomData(PhantomData),
            })),
        );

        Ok(self)
    }

    /// Defines a new statically typed handler for external calls with a given symbol.
    pub fn define_typed<Params, Args>(
        &mut self,
        symbol: impl AsRef<[u8]>,
        func: impl IntoCallFn<UserData, UserError, Params, Args>,
    ) -> Result<&mut Self, Error> {
        let symbol = symbol.as_ref();
        if self.host_functions.contains_key(symbol) {
            bail!(
                "cannot register host function: host function was already registered: {}",
                ProgramSymbol::new(symbol)
            );
        }

        self.host_functions.insert(symbol.to_owned(), func._into_extern_fn());
        Ok(self)
    }

    /// Pre-instantiates a new module, resolving its imports and exports.
    pub fn instantiate_pre(&self, module: &Module) -> Result<InstancePre<UserData, UserError>, Error> {
        let mut exports = LookupMap::new();
        for export in module.exports() {
            match exports.entry(export.symbol().as_bytes().to_owned()) {
                Entry::Occupied(_) => {
                    if module.is_strict() {
                        return Err(format!("duplicate export: {}", export.symbol()).into());
                    } else {
                        log::debug!("Duplicate export: {}", export.symbol());
                        continue;
                    }
                }
                Entry::Vacant(entry) => {
                    entry.insert(export.program_counter());
                }
            }
        }

        let mut imports: Vec<Option<CallFnArc<UserData, UserError>>> = Vec::with_capacity(module.imports().len() as usize);
        for symbol in module.imports() {
            let Some(symbol) = symbol else {
                if module.is_strict() {
                    return Err("failed to parse an import".into());
                } else {
                    imports.push(None);
                    continue;
                }
            };

            let host_fn = if let Some(host_fn) = self.host_functions.get(symbol.as_bytes()) {
                Some(host_fn.clone())
            } else if self.fallback_handler.is_some() {
                None
            } else if module.is_strict() {
                return Err(format!("missing host function: {}", symbol).into());
            } else {
                log::debug!("Missing host function: {}", symbol);
                None
            };

            imports.push(host_fn);
        }

        assert_eq!(imports.len(), module.imports().len() as usize);
        Ok(InstancePre(Arc::new(InstancePreState {
            module: module.clone(),
            imports,
            exports,
            fallback_handler: self.fallback_handler.clone(),
        })))
    }
}

struct InstancePreState<UserData, UserError> {
    module: Module,
    imports: Vec<Option<CallFnArc<UserData, UserError>>>,
    exports: LookupMap<Vec<u8>, ProgramCounter>,
    fallback_handler: Option<FallbackHandlerArc<UserData, UserError>>,
}

pub struct InstancePre<UserData = (), UserError = core::convert::Infallible>(Arc<InstancePreState<UserData, UserError>>);

impl<UserData, UserError> Clone for InstancePre<UserData, UserError> {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

pub struct Instance<UserData = (), UserError = core::convert::Infallible> {
    instance: RawInstance,
    pre: InstancePre<UserData, UserError>,
}

impl<UserData, UserError> core::ops::Deref for Instance<UserData, UserError> {
    type Target = RawInstance;
    fn deref(&self) -> &Self::Target {
        &self.instance
    }
}

impl<UserData, UserError> core::ops::DerefMut for Instance<UserData, UserError> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.instance
    }
}

#[derive(Debug)]
pub enum CallError<UserError = core::convert::Infallible> {
    /// The execution finished abnormally with a trap.
    Trap,

    /// The execution ran out of gas.
    NotEnoughGas,

    /// The execution failed.
    Error(Error),

    /// The execution failed with a custom user error.
    User(UserError),
}

impl<UserData, UserError> InstancePre<UserData, UserError> {
    pub fn instantiate(&self) -> Result<Instance<UserData, UserError>, Error> {
        Ok(Instance {
            instance: self.0.module.instantiate()?,
            pre: self.clone(),
        })
    }
}

pub trait EntryPoint {
    #[doc(hidden)]
    fn get(self, exports: &LookupMap<Vec<u8>, ProgramCounter>) -> Result<ProgramCounter, String>;
}

impl<'a> EntryPoint for &'a str {
    fn get(self, exports: &LookupMap<Vec<u8>, ProgramCounter>) -> Result<ProgramCounter, String> {
        exports
            .get(self.as_bytes())
            .copied()
            .ok_or_else(|| format!("export not found: '{self}'"))
    }
}

impl EntryPoint for String {
    fn get(self, exports: &LookupMap<Vec<u8>, ProgramCounter>) -> Result<ProgramCounter, String> {
        EntryPoint::get(self.as_str(), exports)
    }
}

impl EntryPoint for ProgramCounter {
    fn get(self, _: &LookupMap<Vec<u8>, ProgramCounter>) -> Result<ProgramCounter, String> {
        Ok(self)
    }
}

impl<UserData, UserError> Instance<UserData, UserError> {
    /// Calls a given exported function with the given arguments.
    pub fn call_typed<FnArgs>(
        &mut self,
        user_data: &mut UserData,
        entry_point: impl EntryPoint,
        args: FnArgs,
    ) -> Result<(), CallError<UserError>>
    where
        FnArgs: FuncArgs,
    {
        let entry_point = entry_point
            .get(&self.pre.0.exports)
            .map_err(|error| CallError::Error(Error::from_display(error)))?;
        self.instance.prepare_call_typed(entry_point, args);

        loop {
            let interrupt = self.instance.run().map_err(CallError::Error)?;
            match interrupt {
                InterruptKind::Finished => break,
                InterruptKind::Trap => return Err(CallError::Trap),
                InterruptKind::Ecalli(hostcall) => {
                    if let Some(host_fn) = self.pre.0.imports.get(hostcall as usize).and_then(|host_fn| host_fn.as_ref()) {
                        host_fn.0.call(user_data, &mut self.instance).map_err(CallError::User)?;
                    } else if let Some(ref fallback_handler) = self.pre.0.fallback_handler {
                        let caller = Caller {
                            user_data,
                            instance: &mut self.instance,
                        };

                        fallback_handler(caller, hostcall).map_err(CallError::User)?;
                    } else {
                        log::debug!("Called a missing host function with ID = {}", hostcall);
                        return Err(CallError::Trap);
                    };
                }
                InterruptKind::NotEnoughGas => return Err(CallError::NotEnoughGas),
                InterruptKind::Segfault(segfault) => {
                    let module = self.instance.module().clone();
                    if segfault.page_address >= module.memory_map().stack_address_low()
                        && segfault.page_address + segfault.page_size <= module.memory_map().stack_address_high()
                    {
                        self.instance
                            .zero_memory(segfault.page_address, segfault.page_size)
                            .map_err(|error| {
                                CallError::Error(Error::from_display(format!(
                                    "failed to zero memory when handling a segfault at 0x{:x}: {error}",
                                    segfault.page_address
                                )))
                            })?;

                        continue;
                    }

                    macro_rules! handle {
                        ($range:ident, $data:ident) => {{
                            if segfault.page_address >= module.memory_map().$range().start
                                && segfault.page_address + segfault.page_size <= module.memory_map().$range().end
                            {
                                let data_offset = (segfault.page_address - module.memory_map().$range().start) as usize;
                                let data = module.blob().$data();
                                if let Some(chunk_length) = data.len().checked_sub(data_offset) {
                                    let chunk_length = core::cmp::min(chunk_length, segfault.page_size as usize);
                                    self.instance
                                        .write_memory(segfault.page_address, &data[data_offset..data_offset + chunk_length])
                                        .map_err(|error| {
                                            CallError::Error(Error::from_display(format!(
                                                "failed to write memory when handling a segfault at 0x{:x}: {error}",
                                                segfault.page_address
                                            )))
                                        })?;
                                } else {
                                    self.instance
                                        .zero_memory(segfault.page_address, segfault.page_size)
                                        .map_err(|error| {
                                            CallError::Error(Error::from_display(format!(
                                                "failed to zero memory when handling a segfault at 0x{:x}: {error}",
                                                segfault.page_address
                                            )))
                                        })?;
                                };

                                continue;
                            }
                        }};
                    }

                    handle!(ro_data_range, ro_data);
                    handle!(rw_data_range, rw_data);

                    log::debug!("Unexpected segfault: 0x{:x}", segfault.page_address);
                    return Err(CallError::Trap);
                }
                InterruptKind::Step => {}
            }
        }

        Ok(())
    }

    /// A conveniance function to call [`Instance::call_typed`] and [`RawInstance::get_result_typed`] in a single function call.
    pub fn call_typed_and_get_result<FnResult, FnArgs>(
        &mut self,
        user_data: &mut UserData,
        entry_point: impl EntryPoint,
        args: FnArgs,
    ) -> Result<FnResult, CallError<UserError>>
    where
        FnArgs: FuncArgs,
        FnResult: FuncResult,
    {
        self.call_typed(user_data, entry_point, args)?;
        Ok(self.instance.get_result_typed::<FnResult>())
    }
}
