#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

pub mod amd64;
mod assembler;

pub use crate::assembler::{Assembler, Instruction, Label};
