#![doc = include_str!("../README.md")]
#![no_std]

// NOTE: The `#[inline(always)]` in this crate were put strategically and actually make a difference; do not remove them!

pub mod amd64;

#[cfg(feature = "alloc")]
mod assembler;
mod misc;

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
pub use crate::assembler::{Assembler, NonZero, ReservedAssembler, U0, U1, U2, U3, U4, U5, U6};
pub use crate::misc::{Instruction, Label};
