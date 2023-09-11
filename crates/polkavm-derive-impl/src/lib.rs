#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

#[macro_use]
mod common;

mod export;
mod import;

pub use crate::export::polkavm_export;
pub use crate::import::polkavm_import;
