#[cfg(all(any(target_arch = "riscv32", target_arch = "riscv64"), target_feature = "e"))]
impl CallImport for (Reg, Reg, Reg, Reg, Reg, Reg, Reg) {
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
                inlateout("t0") self.6 => _,
                lateout("t1") _,
                lateout("t2") _,
                lateout("ra") _,
            );
        }

        (self.0, self.1)
    }
}

#[cfg(all(any(target_arch = "riscv32", target_arch = "riscv64"), target_feature = "e"))]
impl CallImport for (Reg, Reg, Reg, Reg, Reg, Reg, Reg, Reg) {
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
                inlateout("t0") self.6 => _,
                inlateout("t1") self.7 => _,
                lateout("t2") _,
                lateout("ra") _,
            );
        }

        (self.0, self.1)
    }
}

#[cfg(all(any(target_arch = "riscv32", target_arch = "riscv64"), target_feature = "e"))]
impl CallImport for (Reg, Reg, Reg, Reg, Reg, Reg, Reg, Reg, Reg) {
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
                inlateout("t0") self.6 => _,
                inlateout("t1") self.7 => _,
                inlateout("t2") self.8 => _,
                lateout("ra") _,
            );
        }

        (self.0, self.1)
    }
}
