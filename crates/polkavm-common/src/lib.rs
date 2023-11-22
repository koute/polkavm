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

pub mod abi;
#[cfg(feature = "alloc")]
pub mod elf;
pub mod error;
pub mod init;
pub mod program;
pub mod utils;
pub mod varint;

#[cfg(target_arch = "x86_64")]
pub mod zygote;

/// A special hostcall number set by the *guest* to trigger a trace.
pub const HOSTCALL_TRACE: u32 = 0x80000000;
