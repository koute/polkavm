#[cfg(target_pointer_width = "32")]
impl IntoHost for u32 {
    type Regs = (u32,);
    type Destructor = ();

    #[inline(always)]
    fn into_host(value: Self) -> (Self::Regs, ()) {
        ((value,), ())
    }
}

#[cfg(target_pointer_width = "32")]
impl IntoHost for i32 {
    type Regs = (u32,);
    type Destructor = ();

    #[inline(always)]
    fn into_host(value: Self) -> (Self::Regs, ()) {
        IntoHost::into_host((value as u32))
    }
}

#[cfg(target_pointer_width = "32")]
impl IntoHost for usize {
    type Regs = (u32,);
    type Destructor = ();

    #[inline(always)]
    fn into_host(value: Self) -> (Self::Regs, ()) {
        IntoHost::into_host((value as u32))
    }
}

#[cfg(target_pointer_width = "32")]
impl IntoHost for isize {
    type Regs = (u32,);
    type Destructor = ();

    #[inline(always)]
    fn into_host(value: Self) -> (Self::Regs, ()) {
        IntoHost::into_host((value as u32))
    }
}

#[cfg(target_pointer_width = "32")]
impl IntoHost for u64 {
    type Regs = (u32, u32);
    type Destructor = ();

    #[inline(always)]
    fn into_host(value: Self) -> (Self::Regs, ()) {
        ((value as u32, (value >> 32) as u32), ())
    }
}

#[cfg(target_pointer_width = "32")]
impl IntoHost for i64 {
    type Regs = (u32, u32);
    type Destructor = ();

    #[inline(always)]
    fn into_host(value: Self) -> (Self::Regs, ()) {
        IntoHost::into_host((value as u64))
    }
}

#[cfg(target_pointer_width = "32")]
impl FromHost for u32 {
    type Regs = (u32,);

    #[inline(always)]
    fn from_host((a0,): Self::Regs) -> Self {
        a0
    }
}

#[cfg(target_pointer_width = "32")]
impl FromHost for i32 {
    type Regs = <u32 as FromHost>::Regs;

    #[inline(always)]
    fn from_host(regs: Self::Regs) -> Self {
        u32::from_host(regs) as i32
    }
}

#[cfg(target_pointer_width = "32")]
impl FromHost for usize {
    type Regs = <u32 as FromHost>::Regs;

    #[inline(always)]
    fn from_host(regs: Self::Regs) -> Self {
        u32::from_host(regs) as usize
    }
}

#[cfg(target_pointer_width = "32")]
impl FromHost for isize {
    type Regs = <u32 as FromHost>::Regs;

    #[inline(always)]
    fn from_host(regs: Self::Regs) -> Self {
        u32::from_host(regs) as isize
    }
}

#[cfg(target_pointer_width = "32")]
impl FromHost for u64 {
    type Regs = (u32, u32);

    #[inline(always)]
    fn from_host((a0, a1): Self::Regs) -> Self {
        ((a0 as u64) | ((a1 as u64) << 32))
    }
}

#[cfg(target_pointer_width = "32")]
impl FromHost for i64 {
    type Regs = <u64 as FromHost>::Regs;

    #[inline(always)]
    fn from_host(regs: Self::Regs) -> Self {
        u64::from_host(regs) as i64
    }
}

#[cfg(target_pointer_width = "32")]
impl<T> IntoHost for *const T {
    type Regs = (u32,);
    type Destructor = ();

    #[inline(always)]
    fn into_host(value: Self) -> (Self::Regs, ()) {
        ((value as u32,), ())
    }
}

#[cfg(target_pointer_width = "32")]
impl<T> IntoHost for *mut T {
    type Regs = (u32,);
    type Destructor = ();

    #[inline(always)]
    fn into_host(value: Self) -> (Self::Regs, ()) {
        ((value as u32,), ())
    }
}
