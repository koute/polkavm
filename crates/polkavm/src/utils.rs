use polkavm_common::program::Reg;

#[derive(Copy, Clone)]
pub enum RegImm {
    Reg(Reg),
    Imm(u32),
}

impl From<Reg> for RegImm {
    #[inline]
    fn from(reg: Reg) -> Self {
        RegImm::Reg(reg)
    }
}

impl From<u32> for RegImm {
    #[inline]
    fn from(value: u32) -> Self {
        RegImm::Imm(value)
    }
}
