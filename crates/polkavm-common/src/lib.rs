#![doc = include_str!("../README.md")]
#![no_std]
#![deny(unsafe_code)]
#![forbid(unused_must_use)]
#![allow(clippy::get_first)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

#[macro_export]
macro_rules! static_assert {
    ($condition:expr) => {
        const _: () = assert!($condition);
    };
}

#[cfg(feature = "alloc")]
pub mod assembler;

pub mod abi;
#[cfg(feature = "alloc")]
pub mod elf;
pub mod operation;
pub mod program;
pub mod utils;
pub mod varint;

#[cfg(feature = "alloc")]
pub mod writer;

#[cfg(target_arch = "x86_64")]
pub mod zygote;

#[cfg(feature = "regmap")]
pub mod regmap;

pub mod hasher;

#[cfg(not(feature = "blake3"))]
mod blake3;

pub mod cast;
