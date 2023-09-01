use crate::Module;
use polkavm_common::program::RawInstruction;

pub struct Disassembler;
impl<'a> Disassembler {
    pub fn from_module(module: &'a Module) -> impl Iterator<Item = &RawInstruction> {
        module.instructions().iter()
    }
}
