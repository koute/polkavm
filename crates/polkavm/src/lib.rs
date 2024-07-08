#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unused_must_use)]
#![forbid(clippy::missing_safety_doc)]
#![deny(clippy::undocumented_unsafe_blocks)]
#![deny(clippy::exhaustive_structs)]

#[cfg(all(
    not(miri),
    target_arch = "x86_64",
    any(target_os = "linux", all(feature = "generic-sandbox", any(target_os = "macos", target_os = "freebsd"))),
    feature = "std",
))]
macro_rules! if_compiler_is_supported {
    ({
        $($if_true:tt)*
    } else {
        $($if_false:tt)*
    }) => {
        // $($if_true)*
        $($if_false)*
    };

    ($($if_true:tt)*) => {
        // $($if_true)*
    }
}

#[cfg(not(all(
    not(miri),
    target_arch = "x86_64",
    any(target_os = "linux", all(feature = "generic-sandbox", any(target_os = "macos", target_os = "freebsd"))),
    feature = "std",
)))]
macro_rules! if_compiler_is_supported {
    ({
        $($if_true:tt)*
    } else {
        $($if_false:tt)*
    }) => {
        $($if_false)*
    };

    ($($if_true:tt)*) => {}
}

extern crate alloc;

mod error;

mod api;
mod config;
mod gas;
mod interpreter;
#[cfg(feature = "std")]
mod source_cache;
mod tracer;
mod utils;
mod linker;

#[cfg(feature = "std")]
mod mutex_std;

#[cfg(feature = "std")]
pub(crate) use mutex_std as mutex;

#[cfg(not(feature = "std"))]
mod mutex_no_std;

#[cfg(not(feature = "std"))]
pub(crate) use mutex_no_std as mutex;

if_compiler_is_supported! {
    mod bit_mask;
    mod compiler;
    mod sandbox;

    #[cfg(target_os = "linux")]
    mod generic_allocator;

    #[cfg(target_os = "linux")]
    mod shm_allocator;
}

pub use polkavm_common::{
    abi::MemoryMap,
    program::{ProgramBlob, ProgramCounter, ProgramExport, ProgramParseError, ProgramSymbol, Reg},
    utils::{ArcBytes, AsUninitSliceMut},
};

pub type Gas = i64;

pub use crate::api::{Engine, RawInstance, Module, MemoryAccessError, RegValue};
pub use crate::config::{BackendKind, Config, GasMeteringKind, ModuleConfig, SandboxKind};
pub use crate::error::Error;
pub use crate::utils::{InterruptKind, Segfault, Trap};
pub use crate::linker::{Caller, Linker, CallError, InstancePre, Instance};

pub const RETURN_TO_HOST: u32 = polkavm_common::abi::VM_ADDR_RETURN_TO_HOST;

#[cfg(test)]
mod tests;

#[doc(hidden)]
pub mod _for_testing {
    #[cfg(target_os = "linux")]
    if_compiler_is_supported! {
        pub use crate::shm_allocator::{ShmAllocation, ShmAllocator};
    }
}
