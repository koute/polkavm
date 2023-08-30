use crate::abi::GuestMemoryConfig;

#[derive(Copy, Clone)]
pub struct GuestProgramInit<'a> {
    ro_data: &'a [u8],
    rw_data: &'a [u8],
    bss_size: u32,
    stack_size: u32,
}

impl<'a> Default for GuestProgramInit<'a> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> GuestProgramInit<'a> {
    pub fn new() -> Self {
        Self {
            ro_data: &[],
            rw_data: &[],
            bss_size: 0,
            stack_size: 0,
        }
    }

    pub fn ro_data(self) -> &'a [u8] {
        self.ro_data
    }

    pub fn with_ro_data(mut self, ro_data: &'a [u8]) -> Self {
        self.ro_data = ro_data;
        self
    }

    pub fn rw_data(self) -> &'a [u8] {
        self.rw_data
    }

    pub fn with_rw_data(mut self, rw_data: &'a [u8]) -> Self {
        self.rw_data = rw_data;
        self
    }

    pub fn bss_size(self) -> u32 {
        self.bss_size
    }

    pub fn with_bss(mut self, size: u32) -> Self {
        self.bss_size = size;
        self
    }

    pub fn stack_size(self) -> u32 {
        self.stack_size
    }

    pub fn with_stack(mut self, size: u32) -> Self {
        self.stack_size = size;
        self
    }

    pub fn memory_config(&self) -> Result<GuestMemoryConfig, &'static str> {
        GuestMemoryConfig::new(
            self.ro_data.len() as u64,
            self.rw_data.len() as u64,
            self.bss_size as u64,
            self.stack_size as u64,
        )
    }
}
