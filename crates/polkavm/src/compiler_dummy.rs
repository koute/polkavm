use crate::api::{ExecutionConfig, Module, OnHostcall};
use crate::error::Error;
use polkavm_common::error::{ExecutionError, Trap};
use polkavm_common::init::GuestProgramInit;
use polkavm_common::program::{ProgramExport, RawInstruction, Reg};
use polkavm_common::utils::{Access, AsUninitSliceMut};

pub const IS_SUPPORTED: bool = false;

pub struct CompiledModule {
    _dummy: (),
}

impl CompiledModule {
    pub fn new(
        _instructions: &[RawInstruction],
        _exports: &[ProgramExport],
        _init: GuestProgramInit,
        _debug_trace_execution: bool,
    ) -> Result<Self, Error> {
        unreachable!("the compiler is not supported on this platform")
    }
}

pub struct CompiledAccess<'a> {
    _dummy: &'a (),
}

impl<'a> Access<'a> for CompiledAccess<'a> {
    type Error = Trap;

    fn get_reg(&self, _reg: Reg) -> u32 {
        unimplemented!();
    }

    fn set_reg(&mut self, _reg: Reg, _value: u32) {
        unimplemented!();
    }

    fn read_memory_into_slice<'slice, T>(&self, _address: u32, _buffer: &'slice mut T) -> Result<&'slice mut [u8], Self::Error>
    where
        T: ?Sized + AsUninitSliceMut,
    {
        unimplemented!();
    }

    fn write_memory(&mut self, _address: u32, _data: &[u8]) -> Result<(), Self::Error> {
        unimplemented!();
    }

    fn program_counter(&self) -> Option<u32> {
        unimplemented!();
    }

    fn native_program_counter(&self) -> Option<u64> {
        unimplemented!();
    }
}

pub(crate) struct CompiledInstance {
    _dummy: (),
}

impl CompiledInstance {
    pub fn new(_: Module) -> Result<CompiledInstance, Error> {
        unimplemented!();
    }

    pub fn call(
        &mut self,
        _export_index: usize,
        _on_hostcall: OnHostcall,
        _args: &[u32],
        _config: &ExecutionConfig,
    ) -> Result<(), ExecutionError<Error>> {
        unimplemented!();
    }

    pub fn access(&mut self) -> CompiledAccess {
        unimplemented!()
    }
}
