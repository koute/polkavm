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

pub use polkavm_common::program::ProgramBlob;
pub use polkavm_common::utils::AsUninitSliceMut;

pub use crate::api::{Engine, FuncType, Instance, InstancePre, Linker, Module, Val, ValType};
pub use crate::config::Config;
