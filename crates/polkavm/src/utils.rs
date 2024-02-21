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

#[derive(Copy, Clone, Default)]
pub struct GuestInit<'a> {
    pub page_size: u32,
    pub ro_data: &'a [u8],
    pub rw_data: &'a [u8],
    pub ro_data_size: u32,
    pub rw_data_size: u32,
    pub stack_size: u32,
}

impl<'a> GuestInit<'a> {
    pub fn memory_map(&self) -> Result<polkavm_common::abi::MemoryMap, &'static str> {
        polkavm_common::abi::MemoryMap::new(self.page_size, self.ro_data_size, self.rw_data_size, self.stack_size)
    }
}
