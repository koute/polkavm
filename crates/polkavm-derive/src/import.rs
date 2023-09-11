use polkavm_common::elf::INSTRUCTION_ECALLI;
use proc_macro::*;
use quote::quote;
use std::fmt::Write;
use syn::spanned::Spanned;
use syn::Token;

use crate::common::{bytes_to_asm, create_fn_prototype, is_cfg, is_doc, is_path_eq, is_rustfmt, Bitness};

mod kw {
    syn::custom_keyword!(index);
}

enum ImportAttribute {
    Index(u32),
}

impl syn::parse::Parse for ImportAttribute {
    fn parse(input: syn::parse::ParseStream) -> syn::parse::Result<Self> {
        let lookahead = input.lookahead1();
        if lookahead.peek(kw::index) {
            input.parse::<kw::index>()?;
            let _: Token![=] = input.parse()?;
            let value: syn::LitInt = input.parse()?;
            let value = value.base10_parse::<u32>().map_err(|err| syn::Error::new(value.span(), err))?;
            Ok(ImportAttribute::Index(value))
        } else {
            Err(lookahead.error())
        }
    }
}

fn generate_import_assembly(index: Option<u32>, sig: &syn::Signature, bitness: Bitness) -> Result<proc_macro2::TokenStream, syn::Error> {
    let prototype = create_fn_prototype(sig, bitness)?;
    let mut metadata_bytes = Vec::new();
    prototype.serialize(|slice| metadata_bytes.extend_from_slice(slice));

    let mut assembly = String::new();
    macro_rules! gen_asm {
        ($(
            ($($tok:tt)+)
        )+) => {
            $(
                writeln!(&mut assembly, $($tok)+).unwrap();
            )+
        }
    }

    let import_symbol = syn::Ident::new(&format!("__polkavm_import_{}", sig.ident), sig.ident.span());
    let name = &sig.ident;
    gen_asm! {
        (".pushsection .polkavm_imports.{},\"a\",@progbits", name)
        (".globl {}", import_symbol)
        (".hidden {}", import_symbol)
        ("{}:", import_symbol)
        (".byte 1") // Version.
    }

    if let Some(index) = index {
        gen_asm! {
            (".byte 1")
            (".4byte 0x{:08x}", index)
        }
    } else {
        gen_asm! {
            (".byte 0")
        }
    }

    assembly.push_str(&bytes_to_asm(&metadata_bytes));

    gen_asm! {
        (".popsection")
        (".pushsection .text.{},\"ax\",@progbits", name)
        (".globl {}", name)
        (".hidden {}", name)
        (".balign 4")
        (".type {},@function", name)
        ("{}:", name)
        (".4byte 0x{:08x}", INSTRUCTION_ECALLI)
        (".4byte {}", import_symbol)
        ("ret")
        (".size {}, . - {}", name, name)
        (".popsection")
    }

    Ok(quote! { ::core::arch::global_asm!(#assembly); })
}

fn parse_import_attributes(attr: &syn::Attribute) -> Result<Option<Vec<ImportAttribute>>, syn::Error> {
    if !is_path_eq(attr.meta.path(), "polkavm_import") {
        return Ok(None);
    }

    let list = attr.meta.require_list()?;
    let parsed_attrs = syn::parse::Parser::parse2(
        syn::punctuated::Punctuated::<ImportAttribute, Token![,]>::parse_terminated,
        list.tokens.clone(),
    )?;

    Ok(Some(parsed_attrs.into_iter().collect()))
}

pub fn polkavm_import(input: syn::ItemForeignMod) -> Result<TokenStream, syn::Error> {
    let mut outer_cfg_attributes = Vec::new();
    for attr in input.attrs {
        if is_cfg(&attr) {
            outer_cfg_attributes.push(attr);
        } else {
            unsupported!(attr);
        }
    }

    if let Some(abi) = input.abi.name {
        if abi.value() != "C" {
            unsupported!(abi);
        }
    }

    let mut output = Vec::new();
    for item in input.items {
        match item {
            syn::ForeignItem::Fn(syn::ForeignItemFn { attrs, sig, vis, .. }) => {
                let mut inner_cfg_attributes = Vec::new();
                let mut inner_doc_attributes = Vec::new();
                let mut import_index = None;
                for attr in attrs {
                    if is_rustfmt(&attr) {
                        continue;
                    }

                    if is_cfg(&attr) {
                        inner_cfg_attributes.push(attr);
                        continue;
                    }

                    if is_doc(&attr) {
                        inner_doc_attributes.push(attr);
                        continue;
                    }

                    if let Some(attributes) = parse_import_attributes(&attr)? {
                        for attribute in attributes {
                            match attribute {
                                ImportAttribute::Index(index) => {
                                    import_index = Some(index);
                                }
                            }
                        }

                        continue;
                    }

                    unsupported!(attr);
                }

                unsupported_if_some!(sig.constness);
                unsupported_if_some!(sig.asyncness);
                unsupported_if_some!(sig.unsafety);
                unsupported_if_some!(sig.abi);
                unsupported_if_some!(sig.generics.lt_token);
                unsupported_if_some!(sig.generics.params.first());
                unsupported_if_some!(sig.generics.gt_token);
                unsupported_if_some!(sig.generics.where_clause);
                unsupported_if_some!(sig.variadic);

                let assembly_b32 = generate_import_assembly(import_index, &sig, Bitness::B32)?;
                let assembly_b64 = generate_import_assembly(import_index, &sig, Bitness::B64)?;

                let ident = &sig.ident;
                let args = &sig.inputs;
                let return_ty = &sig.output;

                output.push(quote! {
                    #(#outer_cfg_attributes)*
                    #(#inner_cfg_attributes)*
                    #[cfg(target_arch = "riscv32")]
                    #assembly_b32

                    #(#outer_cfg_attributes)*
                    #(#inner_cfg_attributes)*
                    #[cfg(target_arch = "riscv64")]
                    #assembly_b64

                    #(#outer_cfg_attributes)*
                    extern "C" {
                        #(#inner_doc_attributes)*
                        #(#inner_cfg_attributes)*
                        #vis fn #ident(#args) #return_ty;
                    }
                });
            }
            item => unsupported!(item),
        }
    }

    Ok(quote! {
        #(#output)*
    }
    .into())
}
