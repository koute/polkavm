#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

#[macro_use]
mod common;

mod abi_support;
mod define_abi;
mod export;
mod import;

pub use crate::abi_support::{polkavm_impl_abi_support, AbiSupportAttributes};
pub use crate::define_abi::polkavm_define_abi;
pub use crate::export::{polkavm_export, ExportBlockAttributes};
pub use crate::import::{polkavm_import, ImportBlockAttributes};
