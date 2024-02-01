#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

extern crate proc_macro;

use proc_macro::TokenStream;

#[allow(non_snake_case)]
#[proc_macro_attribute]
pub fn __PRIVATE_DO_NOT_USE_polkavm_import(args: TokenStream, input: TokenStream) -> TokenStream {
    syn::parse_macro_input!(args as syn::parse::Nothing);
    let input = syn::parse_macro_input!(input as syn::ItemForeignMod);
    match polkavm_derive_impl::polkavm_import(input) {
        Ok(result) => result.into(),
        Err(error) => error.into_compile_error().into(),
    }
}

#[allow(non_snake_case)]
#[proc_macro_attribute]
pub fn __PRIVATE_DO_NOT_USE_polkavm_export(args: TokenStream, input: TokenStream) -> TokenStream {
    syn::parse_macro_input!(args as syn::parse::Nothing);
    let input = syn::parse_macro_input!(input as syn::ItemFn);
    match polkavm_derive_impl::polkavm_export(input) {
        Ok(result) => result.into(),
        Err(error) => error.into_compile_error().into(),
    }
}
