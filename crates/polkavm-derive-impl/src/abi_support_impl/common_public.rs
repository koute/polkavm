pub trait IntoHost {
    type Regs;
    type Destructor;

    fn into_host(value: Self) -> (Self::Regs, Self::Destructor);
}

impl IntoHost for () {
    type Regs = ();
    type Destructor = ();

    #[inline(always)]
    fn into_host((): Self) -> (Self::Regs, Self::Destructor) {
        ((), ())
    }
}

pub trait FromHost {
    type Regs;
    fn from_host(value: Self::Regs) -> Self;
}

impl FromHost for () {
    type Regs = ();

    #[inline(always)]
    fn from_host((): ()) -> Self {}
}
