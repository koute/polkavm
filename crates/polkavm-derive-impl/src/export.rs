use quote::quote;
use syn::spanned::Spanned;

use crate::common::{is_cfg, is_doc, is_path_eq, is_rustfmt};

mod kw {
    syn::custom_keyword!(abi);
}

#[derive(Default)]
pub struct ExportBlockAttributes {
    abi: Option<syn::Path>,
}

impl ExportBlockAttributes {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_abi(&mut self, abi: Option<syn::Path>) {
        self.abi = abi;
    }
}

impl syn::parse::Parse for ExportBlockAttributes {
    fn parse(input: syn::parse::ParseStream) -> syn::parse::Result<Self> {
        let mut attributes = ExportBlockAttributes::new();

        if input.is_empty() {
            return Ok(attributes);
        }

        enum ImportBlockAttribute {
            Abi(syn::Path),
        }

        let list = input.parse_terminated(
            |input| {
                let lookahead = input.lookahead1();
                if lookahead.peek(kw::abi) {
                    input.parse::<kw::abi>()?;
                    let _: syn::Token![=] = input.parse()?;
                    let path: syn::Path = input.parse()?;
                    Ok(ImportBlockAttribute::Abi(path))
                } else {
                    Err(lookahead.error())
                }
            },
            syn::Token![,],
        )?;

        for attribute in list {
            match attribute {
                ImportBlockAttribute::Abi(path) => {
                    if attributes.abi.is_some() {
                        return Err(syn::Error::new(path.span(), "duplicate 'abi' attribute"));
                    }
                    attributes.abi = Some(path);
                }
            }
        }

        Ok(attributes)
    }
}

pub fn is_no_mangle(attr: &syn::Attribute) -> bool {
    if let syn::Meta::Path(ref path) = attr.meta {
        is_path_eq(path, "no_mangle")
    } else {
        false
    }
}

pub fn polkavm_export(attributes: ExportBlockAttributes, input: syn::ItemFn) -> Result<proc_macro2::TokenStream, syn::Error> {
    let mut cfg_attributes = Vec::new();
    let mut fn_attributes = Vec::new();
    for attr in input.attrs {
        if is_rustfmt(&attr) {
            continue;
        }

        if is_cfg(&attr) {
            cfg_attributes.push(attr);
            continue;
        }

        if is_doc(&attr) || is_no_mangle(&attr) {
            fn_attributes.push(attr);
            continue;
        }

        unsupported!(attr);
    }

    let sig = input.sig;

    unsupported_if_some!(sig.constness);
    unsupported_if_some!(sig.asyncness);
    unsupported_if_some!(sig.generics.lt_token);
    unsupported_if_some!(sig.generics.params.first());
    unsupported_if_some!(sig.generics.gt_token);
    unsupported_if_some!(sig.generics.where_clause);
    unsupported_if_some!(sig.variadic);

    let ident = &sig.ident;
    let args = &sig.inputs;
    let unsafety = &sig.unsafety;
    let vis = &input.vis;
    let body = &input.block.stmts;
    let output = &sig.output;
    let return_ty = match output {
        syn::ReturnType::Default => syn::Type::Tuple(syn::TypeTuple {
            paren_token: Default::default(),
            elems: Default::default(),
        }),
        syn::ReturnType::Type(_, ty) => (**ty).clone(),
    };

    let abi_path = attributes.abi.unwrap_or_else(crate::common::default_abi_path);

    let mut remaining_variables = ["a", "b", "c", "d", "e", "f"]
        .into_iter()
        .map(|ident| crate::common::expr_from_ident(syn::Ident::new(ident, proc_macro2::Span::call_site())));

    let mut arg_variables = Vec::new();
    let mut args_split = Vec::new();
    let mut args_from_host = Vec::new();
    let mut args_joined_regs_ty = quote! { () };
    for arg in args {
        let syn::FnArg::Typed(arg) = arg else {
            unsupported!(arg);
        };

        let Some(arg_ident) = remaining_variables.next() else {
            return Err(syn::Error::new(sig.ident.span(), "too many arguments"));
        };

        let arg_ty = &arg.ty;
        args_split.push(quote! {
            let (#arg_ident, regs) = #abi_path::private::SplitTuple::<<#arg_ty as #abi_path::FromHost>::Regs>::split_tuple(regs);
        });

        args_from_host.push(quote! {
            let #arg_ident = #abi_path::FromHost::from_host(#arg_ident);
        });

        args_joined_regs_ty = quote! {
            <(#args_joined_regs_ty, <#arg_ty as #abi_path::FromHost>::Regs) as #abi_path::private::JoinTuple>::Out
        };

        arg_variables.push(arg_ident);
    }

    let symbol = syn::LitStr::new(&ident.to_string(), ident.span());
    let section_name = syn::LitStr::new(&format!(".text.polkavm_export.{}", ident), ident.span());

    Ok(quote! {
        #(#cfg_attributes)*
        #(#fn_attributes)*
        #vis #unsafety fn #ident(#args) #output {
            #[cfg(all(any(target_arch = "riscv32", target_arch = "riscv64"), target_feature = "e"))]
            #[doc(hidden)]
            mod __polkavm_export {
                use #abi_path::private::Reg;

                #[link_section = #section_name]
                extern fn trampoline(a0: Reg, a1: Reg, a2: Reg, a3: Reg, a4: Reg, a5: Reg) -> #abi_path::private::ReturnTy {
                    let result = {
                        let regs = (a0, a1, a2, a3, a4, a5);
                        #(#args_split)*
                        let _ = regs;

                        #(#args_from_host)*
                        let result = #unsafety {
                            super::#ident(#(#arg_variables),*)
                        };
                        let (result, destructor) = #abi_path::IntoHost::into_host(result);

                        #[allow(forgetting_copy_types)]
                        core::mem::forget(destructor);
                        result
                    };

                    #abi_path::private::PackReturnTy::pack_return_ty(result)
                }

                #[link_section = ".polkavm_metadata"]
                static METADATA_SYMBOL: &str = #symbol;

                #[link_section = ".polkavm_metadata"]
                static METADATA: #abi_path::private::ExternMetadataV1 = #abi_path::private::ExternMetadataV1 {
                    version: 1,
                    flags: 0,
                    symbol_length: METADATA_SYMBOL.len() as u32,
                    symbol: #abi_path::private::MetadataPointer(METADATA_SYMBOL.as_ptr()),
                    input_regs: <#args_joined_regs_ty as #abi_path::private::CountTuple>::COUNT,
                    output_regs: <<#return_ty as #abi_path::IntoHost>::Regs as #abi_path::private::CountTuple>::COUNT,
                };

                #[cfg(target_arch = "riscv32")]
                ::core::arch::global_asm!(
                    ".pushsection .polkavm_exports,\"R\",@note\n",
                    ".byte 1\n", // Version.
                    ".4byte {metadata}",
                    ".4byte {function}",
                    ".popsection\n",
                    metadata = sym METADATA,
                    function = sym trampoline,
                );
            }

            #(#body)*
        }
    })
}
