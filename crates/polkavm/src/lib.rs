#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unused_must_use)]
#![forbid(clippy::missing_safety_doc)]
#![deny(clippy::undocumented_unsafe_blocks)]
#![deny(clippy::exhaustive_structs)]

#[cfg(all(
    not(miri),
    target_arch = "x86_64",
    any(target_os = "linux", target_os = "macos", target_os = "freebsd"),
    feature = "std",
))]
macro_rules! if_compiler_is_supported {
    ({
        $($if_true:tt)*
    } else {
        $($if_false:tt)*
    }) => {
        $($if_true)*
    };

    ($($if_true:tt)*) => {
        $($if_true)*
    }
}

#[cfg(not(all(
    not(miri),
    target_arch = "x86_64",
    any(target_os = "linux", target_os = "macos", target_os = "freebsd"),
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
mod caller;
mod config;
mod gas;
mod interpreter;
#[cfg(feature = "std")]
mod source_cache;
mod tracer;
mod utils;

#[cfg(feature = "std")]
mod mutex_std;

#[cfg(feature = "std")]
pub(crate) use mutex_std as mutex;

#[cfg(not(feature = "std"))]
mod mutex_no_std;

#[cfg(not(feature = "std"))]
pub(crate) use mutex_no_std as mutex;

if_compiler_is_supported! {
    mod compiler;
    mod sandbox;
}

pub use polkavm_common::{
    abi::MemoryMap,
    error::{ExecutionError, Trap},
    program::{ProgramBlob, ProgramParseError, Reg},
    utils::{AsUninitSliceMut, Gas},
};

pub use crate::api::{CallArgs, Engine, ExportIndex, Instance, InstancePre, Linker, Module, StateArgs};
pub use crate::caller::{Caller, CallerRef};
pub use crate::config::{BackendKind, Config, GasMeteringKind, ModuleConfig, SandboxKind};
pub use crate::error::Error;

#[cfg(test)]
mod tests;
