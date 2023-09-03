#![forbid(unsafe_code)]
#![forbid(unused_must_use)]

mod error;

mod api;
mod config;
mod interpreter;
mod source_cache;
mod tracer;

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
mod compiler;

#[cfg(not(all(target_arch = "x86_64", target_os = "linux")))]
mod compiler_dummy;

#[cfg(not(all(target_arch = "x86_64", target_os = "linux")))]
use compiler_dummy as compiler;

pub use polkavm_common::{
    error::Trap,
    program::{ProgramBlob, Reg},
    utils::AsUninitSliceMut,
};

pub use crate::api::{Caller, Engine, Func, FuncType, Instance, InstancePre, IntoExternFn, Linker, Module, TypedFunc, Val, ValType};
pub use crate::config::Config;
pub use crate::error::Error;
