#![forbid(unused_must_use)]
#![forbid(clippy::missing_safety_doc)]
#![deny(clippy::undocumented_unsafe_blocks)]

#[cfg(all(
    not(miri),
    target_arch = "x86_64",
    any(target_os = "linux", target_os = "macos", target_os = "freebsd")
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
    any(target_os = "linux", target_os = "macos", target_os = "freebsd")
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

mod error;

mod api;
mod caller;
mod config;
mod interpreter;
mod source_cache;
mod tracer;
mod utils;

if_compiler_is_supported! {
    mod compiler;
    mod sandbox;
}

pub use polkavm_common::{
    error::{ExecutionError, Trap},
    program::{ProgramBlob, Reg},
    utils::{AsUninitSliceMut, Gas},
};

pub use crate::api::{
    Engine, ExecutionConfig, Func, FuncType, Instance, InstancePre, IntoExternFn, Linker, Module, TypedFunc, Val, ValType,
};
pub use crate::caller::{Caller, CallerRef};
pub use crate::config::{BackendKind, Config, GasMeteringKind, ModuleConfig, SandboxKind};
pub use crate::error::Error;

#[cfg(test)]
mod tests;
