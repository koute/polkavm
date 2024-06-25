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
pub mod error;
pub mod operation;
pub mod program;
pub mod utils;
pub mod varint;

#[cfg(feature = "alloc")]
pub mod writer;

#[cfg(target_arch = "x86_64")]
pub mod zygote;

/// A special hostcall number set by the *guest* to trigger a trace.
pub const HOSTCALL_TRACE: u32 = 0x80000000;

/// A flag which will trigger the sandbox to reset its memory after execution.
pub const VM_RPC_FLAG_RESET_MEMORY_AFTER_EXECUTION: u32 = 1 << 1;

/// A flag which will trigger the sandbox to unload its program after execution.
pub const VM_RPC_FLAG_CLEAR_PROGRAM_AFTER_EXECUTION: u32 = 1 << 2;

/// A flag which will trigger the sandbox to reset its memory before execution.
pub const VM_RPC_FLAG_RESET_MEMORY_BEFORE_EXECUTION: u32 = 1 << 3;
