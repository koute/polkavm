pub trait JoinTuple {
    type Out;
    fn join_tuple(value: Self) -> Self::Out;
}

impl<A> JoinTuple for ((A,),) {
    type Out = (A,);
    fn join_tuple(value: Self) -> Self::Out {
        value.0
    }
}

impl<A, B> JoinTuple for ((A, B),) {
    type Out = (A, B);
    fn join_tuple(value: Self) -> Self::Out {
        value.0
    }
}

impl<A, B, C> JoinTuple for ((A, B, C),) {
    type Out = (A, B, C);
    fn join_tuple(value: Self) -> Self::Out {
        value.0
    }
}

impl<A, B, C, D> JoinTuple for ((A, B, C, D),) {
    type Out = (A, B, C, D);
    fn join_tuple(value: Self) -> Self::Out {
        value.0
    }
}

impl<A, B, C, D, E> JoinTuple for ((A, B, C, D, E),) {
    type Out = (A, B, C, D, E);
    fn join_tuple(value: Self) -> Self::Out {
        value.0
    }
}

impl<A, B, C, D, E, F> JoinTuple for ((A, B, C, D, E, F),) {
    type Out = (A, B, C, D, E, F);
    fn join_tuple(value: Self) -> Self::Out {
        value.0
    }
}

pub trait CountTuple {
    const COUNT: u8;
}

impl CountTuple for () {
    const COUNT: u8 = 0;
}

impl<A> CountTuple for (A,) {
    const COUNT: u8 = 1;
}

impl<A, B> CountTuple for (A, B) {
    const COUNT: u8 = 2;
}

impl<A, B, C> CountTuple for (A, B, C) {
    const COUNT: u8 = 3;
}

impl<A, B, C, D> CountTuple for (A, B, C, D) {
    const COUNT: u8 = 4;
}

impl<A, B, C, D, E> CountTuple for (A, B, C, D, E) {
    const COUNT: u8 = 5;
}

impl<A, B, C, D, E, F> CountTuple for (A, B, C, D, E, F) {
    const COUNT: u8 = 6;
}

impl<A, B, C, D, E, F, G> CountTuple for (A, B, C, D, E, F, G) {
    const COUNT: u8 = 7;
}

impl<A, B, C, D, E, F, G, H> CountTuple for (A, B, C, D, E, F, G, H) {
    const COUNT: u8 = 8;
}

impl<A, B, C, D, E, F, G, H, I> CountTuple for (A, B, C, D, E, F, G, H, I) {
    const COUNT: u8 = 9;
}

impl<A, B, C, D, E, F, G, H, I, J> CountTuple for (A, B, C, D, E, F, G, H, I, J) {
    const COUNT: u8 = 10;
}

impl<A, B, C, D, E, F, G, H, I, J, K> CountTuple for (A, B, C, D, E, F, G, H, I, J, K) {
    const COUNT: u8 = 11;
}

impl<A, B, C, D, E, F, G, H, I, J, K, L> CountTuple for (A, B, C, D, E, F, G, H, I, J, K, L) {
    const COUNT: u8 = 12;
}

pub trait SplitTuple<Target> {
    type Remainder;
    fn split_tuple(tuple: Self) -> (Target, Self::Remainder);
}

#[cfg(all(target_arch = "riscv32", target_feature = "e"))]
pub type Reg = u32;

#[cfg(all(target_arch = "riscv64", target_feature = "e"))]
pub type Reg = u64;

#[cfg(all(target_arch = "riscv32", target_feature = "e"))]
pub type ReturnTy = u64;

#[cfg(all(target_arch = "riscv64", target_feature = "e"))]
pub type ReturnTy = u128;

#[cfg(all(any(target_arch = "riscv32", target_arch = "riscv64"), target_feature = "e"))]
#[inline(always)]
pub extern fn pack_return_ty(a0: Reg, a1: Reg) -> ReturnTy {
    const SHIFT: usize = core::mem::size_of::<Reg>() * 8;
    (a0 as ReturnTy) | ((a1 as ReturnTy) << SHIFT)
}

#[cfg(all(any(target_arch = "riscv32", target_arch = "riscv64"), target_feature = "e"))]
pub trait IntoTuple {
    fn into_tuple(a0: Reg, a1: Reg) -> Self;
}

#[cfg(all(any(target_arch = "riscv32", target_arch = "riscv64"), target_feature = "e"))]
impl IntoTuple for () {
    #[inline(always)]
    fn into_tuple(_: Reg, _: Reg) -> Self {}
}

#[cfg(all(any(target_arch = "riscv32", target_arch = "riscv64"), target_feature = "e"))]
impl IntoTuple for (Reg,) {
    #[inline(always)]
    fn into_tuple(a0: Reg, _: Reg) -> Self {
        (a0,)
    }
}

#[cfg(all(any(target_arch = "riscv32", target_arch = "riscv64"), target_feature = "e"))]
impl IntoTuple for (Reg, Reg) {
    #[inline(always)]
    fn into_tuple(a0: Reg, a1: Reg) -> Self {
        (a0, a1)
    }
}

#[cfg(all(any(target_arch = "riscv32", target_arch = "riscv64"), target_feature = "e"))]
pub trait ImportSymbol {
    extern fn trampoline(a0: Reg, a1: Reg, a2: Reg, a3: Reg, a4: Reg, a5: Reg);
}

#[cfg(all(any(target_arch = "riscv32", target_arch = "riscv64"), target_feature = "e"))]
pub trait CallImport {
    fn call_import<F>(self) -> (Reg, Reg) where F: ImportSymbol;
}

#[cfg(all(any(target_arch = "riscv32", target_arch = "riscv64"), target_feature = "e"))]
impl CallImport for () {
    #[inline(always)]
    fn call_import<F>(mut self) -> (Reg, Reg) where F: ImportSymbol {
        let a0;
        let a1;

        unsafe {
            core::arch::asm!(
                "call {address}",
                address = sym F::trampoline,
                lateout("a0") a0,
                lateout("a1") a1,
                lateout("a2") _,
                lateout("a3") _,
                lateout("a4") _,
                lateout("a5") _,
                lateout("t0") _,
                lateout("t1") _,
                lateout("t2") _,
                lateout("ra") _,
            );
        }

        (a0, a1)
    }
}

#[cfg(all(any(target_arch = "riscv32", target_arch = "riscv64"), target_feature = "e"))]
impl CallImport for (Reg,) {
    #[inline(always)]
    fn call_import<F>(mut self) -> (Reg, Reg) where F: ImportSymbol {
        let a1;

        unsafe {
            core::arch::asm!(
                "call {address}",
                address = sym F::trampoline,
                inlateout("a0") self.0,
                lateout("a1") a1,
                lateout("a2") _,
                lateout("a3") _,
                lateout("a4") _,
                lateout("a5") _,
                lateout("t0") _,
                lateout("t1") _,
                lateout("t2") _,
                lateout("ra") _,
            );
        }

        (self.0, a1)
    }
}

#[cfg(all(any(target_arch = "riscv32", target_arch = "riscv64"), target_feature = "e"))]
impl CallImport for (Reg, Reg) {
    #[inline(always)]
    fn call_import<F>(mut self) -> (Reg, Reg) where F: ImportSymbol {
        unsafe {
            core::arch::asm!(
                "call {address}",
                address = sym F::trampoline,
                inlateout("a0") self.0,
                inlateout("a1") self.1,
                lateout("a2") _,
                lateout("a3") _,
                lateout("a4") _,
                lateout("a5") _,
                lateout("t0") _,
                lateout("t1") _,
                lateout("t2") _,
                lateout("ra") _,
            );
        }

        (self.0, self.1)
    }
}

#[cfg(all(any(target_arch = "riscv32", target_arch = "riscv64"), target_feature = "e"))]
impl CallImport for (Reg, Reg, Reg) {
    #[inline(always)]
    fn call_import<F>(mut self) -> (Reg, Reg) where F: ImportSymbol {
        unsafe {
            core::arch::asm!(
                "call {address}",
                address = sym F::trampoline,
                inlateout("a0") self.0,
                inlateout("a1") self.1,
                inlateout("a2") self.2 => _,
                lateout("a3") _,
                lateout("a4") _,
                lateout("a5") _,
                lateout("t0") _,
                lateout("t1") _,
                lateout("t2") _,
                lateout("ra") _,
            );
        }

        (self.0, self.1)
    }
}

#[cfg(all(any(target_arch = "riscv32", target_arch = "riscv64"), target_feature = "e"))]
impl CallImport for (Reg, Reg, Reg, Reg) {
    #[inline(always)]
    fn call_import<F>(mut self) -> (Reg, Reg) where F: ImportSymbol {
        unsafe {
            core::arch::asm!(
                "call {address}",
                address = sym F::trampoline,
                inlateout("a0") self.0,
                inlateout("a1") self.1,
                inlateout("a2") self.2 => _,
                inlateout("a3") self.3 => _,
                lateout("a4") _,
                lateout("a5") _,
                lateout("t0") _,
                lateout("t1") _,
                lateout("t2") _,
                lateout("ra") _,
            );
        }

        (self.0, self.1)
    }
}

#[cfg(all(any(target_arch = "riscv32", target_arch = "riscv64"), target_feature = "e"))]
impl CallImport for (Reg, Reg, Reg, Reg, Reg) {
    #[inline(always)]
    fn call_import<F>(mut self) -> (Reg, Reg) where F: ImportSymbol {
        unsafe {
            core::arch::asm!(
                "call {address}",
                address = sym F::trampoline,
                inlateout("a0") self.0,
                inlateout("a1") self.1,
                inlateout("a2") self.2 => _,
                inlateout("a3") self.3 => _,
                inlateout("a4") self.4 => _,
                lateout("a5") _,
                lateout("t0") _,
                lateout("t1") _,
                lateout("t2") _,
                lateout("ra") _,
            );
        }

        (self.0, self.1)
    }
}

#[cfg(all(any(target_arch = "riscv32", target_arch = "riscv64"), target_feature = "e"))]
impl CallImport for (Reg, Reg, Reg, Reg, Reg, Reg) {
    #[inline(always)]
    fn call_import<F>(mut self) -> (Reg, Reg) where F: ImportSymbol {
        unsafe {
            core::arch::asm!(
                "call {address}",
                address = sym F::trampoline,
                inlateout("a0") self.0,
                inlateout("a1") self.1,
                inlateout("a2") self.2 => _,
                inlateout("a3") self.3 => _,
                inlateout("a4") self.4 => _,
                inlateout("a5") self.5 => _,
                lateout("t0") _,
                lateout("t1") _,
                lateout("t2") _,
                lateout("ra") _,
            );
        }

        (self.0, self.1)
    }
}

#[cfg(all(any(target_arch = "riscv32", target_arch = "riscv64"), target_feature = "e"))]
pub trait PackReturnTy {
    fn pack_return_ty(value: Self) -> ReturnTy;
}

#[cfg(all(any(target_arch = "riscv32", target_arch = "riscv64"), target_feature = "e"))]
impl PackReturnTy for () {
    #[inline(always)]
    fn pack_return_ty(_: Self) -> ReturnTy {
        let a0;
        let a1;
        unsafe {
            core::arch::asm!(
                "/* NOP */",
                lateout("a0") a0,
                lateout("a1") a1,
            );
        }

        pack_return_ty(a0, a1)
    }
}

#[cfg(all(any(target_arch = "riscv32", target_arch = "riscv64"), target_feature = "e"))]
impl PackReturnTy for (Reg,) {
    #[inline(always)]
    fn pack_return_ty(value: Self) -> ReturnTy {
        let mut a0 = value.0;
        let a1;
        unsafe {
            core::arch::asm!(
                "/* NOP */",
                inlateout("a0") a0,
                lateout("a1") a1,
            );
        }

        pack_return_ty(a0, a1)
    }
}

#[cfg(all(any(target_arch = "riscv32", target_arch = "riscv64"), target_feature = "e"))]
impl PackReturnTy for (Reg, Reg) {
    #[inline(always)]
    fn pack_return_ty(value: Self) -> ReturnTy {
        pack_return_ty(value.0, value.1)
    }
}

#[repr(transparent)]
pub struct MetadataPointer(pub *const u8);
unsafe impl Sync for MetadataPointer {}

#[repr(packed)]
pub struct ExternMetadataV1 {
    pub version: u8,
    pub flags: u32,
    pub symbol_length: u32,
    pub symbol: MetadataPointer,
    pub input_regs: u8,
    pub output_regs: u8,
}

#[repr(packed)]
pub struct ExternMetadataV2 {
    pub version: u8,
    pub flags: u32,
    pub symbol_length: u32,
    pub symbol: MetadataPointer,
    pub input_regs: u8,
    pub output_regs: u8,
    pub has_index: bool,
    pub index: u32,
}
