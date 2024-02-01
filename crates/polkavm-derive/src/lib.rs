#![no_std]
#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

pub use polkavm_derive_impl_macro::__PRIVATE_DO_NOT_USE_polkavm_define_abi as polkavm_define_abi;
pub use polkavm_derive_impl_macro::__PRIVATE_DO_NOT_USE_polkavm_export as polkavm_export;
pub use polkavm_derive_impl_macro::__PRIVATE_DO_NOT_USE_polkavm_import as polkavm_import;

pub mod default_abi {
    polkavm_derive_impl_macro::__PRIVATE_DO_NOT_USE_polkavm_impl_abi_support!();
}
