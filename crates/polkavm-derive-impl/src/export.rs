use quote::quote;
use syn::spanned::Spanned;

use crate::common::{bytes_to_asm, create_fn_prototype, is_cfg, is_doc, is_path_eq, is_rustfmt, Bitness};

fn generate_export_assembly(sig: &syn::Signature, bitness: Bitness) -> Result<proc_macro2::TokenStream, syn::Error> {
    let prototype = create_fn_prototype(sig, bitness)?;
    let mut metadata_bytes = Vec::new();
    prototype.serialize(|slice| metadata_bytes.extend_from_slice(slice));

    let mut assembly = String::new();
    assembly.push_str(".pushsection .polkavm_exports,\"\",@progbits\n");
    assembly.push_str(".byte 1\n"); // Version.
    assembly.push_str(".4byte {address}\n");
    assembly.push_str(&bytes_to_asm(&metadata_bytes));
    assembly.push_str(".popsection\n");

    let ident = &sig.ident;
    Ok(quote! { ::core::arch::global_asm!(#assembly, address = sym #ident); })
}

pub fn is_no_mangle(attr: &syn::Attribute) -> bool {
    if let syn::Meta::Path(ref path) = attr.meta {
        is_path_eq(path, "no_mangle")
    } else {
        false
    }
}

pub fn polkavm_export(input: syn::ItemFn) -> Result<proc_macro2::TokenStream, syn::Error> {
    let mut cfg_attributes = Vec::new();
    let mut fn_attributes = Vec::new();
    let mut no_mangle_found = false;
    for attr in input.attrs {
        if is_rustfmt(&attr) {
            continue;
        }

        if is_cfg(&attr) {
            cfg_attributes.push(attr);
            continue;
        }

        if is_doc(&attr) {
            fn_attributes.push(attr);
            continue;
        }

        if is_no_mangle(&attr) {
            no_mangle_found = true;
            fn_attributes.push(attr.clone());
            continue;
        }

        unsupported!(attr);
    }

    if !matches!(input.vis, syn::Visibility::Public(..)) {
        return Err(syn::Error::new(input.sig.ident.span(), "must be marked as 'pub'"));
    }

    if !no_mangle_found {
        return Err(syn::Error::new(input.sig.ident.span(), "must be marked as '#[no_mangle]'"));
    }

    let sig = input.sig;

    unsupported_if_some!(sig.constness);
    unsupported_if_some!(sig.asyncness);
    unsupported_if_some!(sig.unsafety);
    unsupported_if_some!(sig.generics.lt_token);
    unsupported_if_some!(sig.generics.params.first());
    unsupported_if_some!(sig.generics.gt_token);
    unsupported_if_some!(sig.generics.where_clause);
    unsupported_if_some!(sig.variadic);

    if let Some(ref abi) = sig.abi {
        if let Some(ref abi_name) = abi.name {
            if abi_name.value() != "C" {
                unsupported!(abi_name);
            }
        }
    } else {
        return Err(syn::Error::new(sig.ident.span(), "must be marked as 'extern' or 'extern \"C\"'"));
    }

    let assembly_b32 = generate_export_assembly(&sig, Bitness::B32)?;
    let assembly_b64 = generate_export_assembly(&sig, Bitness::B64)?;

    let ident = &sig.ident;
    let args = &sig.inputs;
    let return_ty = &sig.output;
    let vis = &input.vis;
    let body = &input.block;

    Ok(quote! {
        #(#cfg_attributes)*
        #[cfg(target_arch = "riscv32")]
        #assembly_b32

        #(#cfg_attributes)*
        #[cfg(target_arch = "riscv64")]
        #assembly_b64

        #(#cfg_attributes)*
        #(#fn_attributes)*
        #[link_section = ".text.polkavm_export"]
        #vis fn #ident(#args) #return_ty #body
    })
}
