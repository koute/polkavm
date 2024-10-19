use alloc::vec::Vec;
use polkavm_common::program::RawReg;

#[derive(Copy, Clone)]
pub enum RegImm {
    Reg(RawReg),
    Imm(u32),
}

impl From<RawReg> for RegImm {
    #[inline]
    fn from(reg: RawReg) -> Self {
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
    pub aux_data_size: u32,
}

impl<'a> GuestInit<'a> {
    pub fn memory_map(&self) -> Result<polkavm_common::abi::MemoryMap, &'static str> {
        polkavm_common::abi::MemoryMapBuilder::new(self.page_size)
            .ro_data_size(self.ro_data_size)
            .rw_data_size(self.rw_data_size)
            .stack_size(self.stack_size)
            .aux_data_size(self.aux_data_size)
            .build()
    }
}

pub(crate) struct FlatMap<T> {
    inner: Vec<Option<T>>,
}

impl<T> FlatMap<T>
where
    T: Copy,
{
    #[inline]
    pub fn new(capacity: u32) -> Self {
        let mut inner = Vec::new();
        inner.resize_with(capacity as usize, || None);

        Self { inner }
    }

    #[inline]
    pub fn new_reusing_memory(mut memory: Self, capacity: u32) -> Self {
        memory.inner.clear();
        memory.inner.resize_with(capacity as usize, || None);
        memory
    }

    #[inline]
    pub fn get(&self, key: u32) -> Option<T> {
        self.inner.get(key as usize).and_then(|value| *value)
    }

    #[inline]
    pub fn len(&self) -> u32 {
        self.inner.len() as u32
    }

    #[inline]
    pub fn insert(&mut self, key: u32, value: T) {
        self.inner[key as usize] = Some(value);
    }

    #[inline]
    pub fn clear(&mut self) {
        self.inner.clear();
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub struct Segfault {
    /// The address of the page which was accessed.
    pub page_address: u32,

    /// The size of the page.
    pub page_size: u32,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum InterruptKind {
    /// The execution finished normally.
    ///
    /// This happens when the program jumps to the address `0xffff0000`.
    Finished,

    /// The execution finished abnormally with a trap.
    ///
    /// This can happen for a few reasons:
    ///   - if the `trap` instruction is executed,
    ///   - if an invalid instruction is executed,
    ///   - if a jump to an invalid address is made,
    ///   - if a segmentation fault is triggered (when dynamic paging is not enabled for this VM)
    Trap,

    /// The execution triggered an external call with an `ecalli` instruction.
    Ecalli(u32),

    /// The execution triggered a segmentation fault.
    ///
    /// This happens when a program accesses a memory page that is not mapped,
    /// or tries to write to a read-only page.
    ///
    /// Requires dynamic paging to be enabled with [`ModuleConfig::set_dynamic_paging`](crate::ModuleConfig::set_dynamic_paging), otherwise is never emitted.
    Segfault(Segfault),

    /// The execution ran out of gas.
    ///
    /// Requires gas metering to be enabled with [`ModuleConfig::set_gas_metering`](crate::ModuleConfig::set_gas_metering), otherwise is never emitted.
    NotEnoughGas,

    /// Executed a single instruction.
    ///
    /// Requires execution step-tracing to be enabled with [`ModuleConfig::set_step_tracing`](crate::ModuleConfig::set_step_tracing), otherwise is never emitted.
    Step,
}
