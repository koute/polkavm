#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]
#![deny(unused_must_use)]

mod dwarf;
mod program_from_elf;
mod riscv;

pub use crate::program_from_elf::{program_from_elf, Config, ProgramFromElfError};
pub use polkavm_common::program::ProgramBlob;
