use quote::quote;
use syn::spanned::Spanned;

use crate::abi_support::AbiSupportAttributes;
use crate::common::{is_cfg, is_doc, is_rustfmt};

pub fn polkavm_define_abi(attributes: AbiSupportAttributes, input: syn::ItemMod) -> Result<proc_macro2::TokenStream, syn::Error> {
    let mut outer_cfg_attributes = Vec::new();
    let mut outer_doc_attributes = Vec::new();

    let Some(content) = input.content else {
        return Err(syn::Error::new(input.ident.span(), "the module must have curly braces"));
    };

    if !content.1.is_empty() {
        return Err(syn::Error::new(input.ident.span(), "the module must be empty"));
    }

    for attr in input.attrs {
        if is_rustfmt(&attr) {
            continue;
        }

        if is_cfg(&attr) {
            outer_cfg_attributes.push(attr);
            continue;
        }

        if is_doc(&attr) {
            outer_doc_attributes.push(attr);
            continue;
        }

        unsupported!(attr);
    }

    unsupported_if_some!(input.unsafety);
    unsupported_if_some!(content.1.first());

    let mod_token = input.mod_token;
    let visibility = input.vis;
    let ident = input.ident;
    let support_code = crate::abi_support::polkavm_impl_abi_support(attributes);

    Ok(quote! {
        #(#outer_cfg_attributes)*
        #(#outer_doc_attributes)*
        #visibility #mod_token #ident {
            #support_code
        }
    })
}
