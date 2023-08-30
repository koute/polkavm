#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

extern crate proc_macro;

// A copy of BLAKE3 reference implementation to keep the number of dependencies low.
#[allow(dead_code)]
#[allow(clippy::explicit_counter_loop)]
#[rustfmt::skip]
mod blake3;

#[macro_use]
mod common;

mod export;
mod import;

use proc_macro::TokenStream;

#[proc_macro_attribute]
pub fn polkavm_import(args: TokenStream, input: TokenStream) -> TokenStream {
    syn::parse_macro_input!(args as syn::parse::Nothing);
    let input = syn::parse_macro_input!(input as syn::ItemForeignMod);
    match crate::import::polkavm_import(input) {
        Ok(result) => result,
        Err(error) => error.into_compile_error().into(),
    }
}

#[proc_macro_attribute]
pub fn polkavm_export(args: TokenStream, input: TokenStream) -> TokenStream {
    syn::parse_macro_input!(args as syn::parse::Nothing);
    let input = syn::parse_macro_input!(input as syn::ItemFn);
    match crate::export::polkavm_export(input) {
        Ok(result) => result,
        Err(error) => error.into_compile_error().into(),
    }
}
