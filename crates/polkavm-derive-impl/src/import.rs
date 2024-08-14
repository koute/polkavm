use quote::quote;
use syn::spanned::Spanned;
use syn::Token;

use crate::common::{is_cfg, is_doc, is_path_eq, is_rustfmt};

mod kw {
    syn::custom_keyword!(symbol);
    syn::custom_keyword!(abi);
    syn::custom_keyword!(index);
}

fn ident_from_pattern_strict(syn::PatType { attrs, pat, .. }: &syn::PatType) -> Result<Option<syn::Ident>, syn::Error> {
    unsupported_if_some!(attrs.first());
    match &**pat {
        syn::Pat::Ident(pat) => {
            unsupported_if_some!(pat.attrs.first());
            unsupported_if_some!(pat.by_ref);
            unsupported_if_some!(pat.mutability);
            if let Some((_, ref subpat)) = pat.subpat {
                unsupported!(subpat);
            }

            Ok(Some(pat.ident.clone()))
        }
        syn::Pat::Wild(..) => Ok(None),
        _ => unsupported!(pat),
    }
}

#[derive(Default)]
pub struct ImportBlockAttributes {
    abi: Option<syn::Path>,
}

impl ImportBlockAttributes {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_abi(&mut self, abi: Option<syn::Path>) {
        self.abi = abi;
    }
}

impl syn::parse::Parse for ImportBlockAttributes {
    fn parse(input: syn::parse::ParseStream) -> syn::parse::Result<Self> {
        let mut attributes = ImportBlockAttributes::new();

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
                    let _: Token![=] = input.parse()?;
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

enum ImportAttribute {
    Symbol(syn::LitByteStr),
    Index(u32),
}

impl syn::parse::Parse for ImportAttribute {
    fn parse(input: syn::parse::ParseStream) -> syn::parse::Result<Self> {
        let lookahead = input.lookahead1();
        if lookahead.peek(kw::symbol) {
            input.parse::<kw::symbol>()?;
            let _: Token![=] = input.parse()?;
            let lookahead = input.lookahead1();
            if lookahead.peek(syn::LitInt) {
                let lit: syn::LitInt = input.parse()?;
                let value = match lit.suffix() {
                    "u32" => {
                        let value = lit.base10_parse::<u32>().map_err(|err| syn::Error::new(lit.span(), err))?;
                        value.to_le_bytes().to_vec()
                    }
                    "u16" => {
                        let value = lit.base10_parse::<u16>().map_err(|err| syn::Error::new(lit.span(), err))?;
                        value.to_le_bytes().to_vec()
                    }
                    "u8" => {
                        let value = lit.base10_parse::<u8>().map_err(|err| syn::Error::new(lit.span(), err))?;
                        value.to_le_bytes().to_vec()
                    }
                    _ => {
                        return Err(syn::Error::new(
                            lit.span(),
                            "invalid or missing suffix; one of the following suffixes is required: 'u32', 'u16' or 'u8'",
                        ));
                    }
                };
                let value = syn::LitByteStr::new(&value, lit.span());
                Ok(ImportAttribute::Symbol(value))
            } else if lookahead.peek(syn::LitByteStr) {
                let value: syn::LitByteStr = input.parse()?;
                Ok(ImportAttribute::Symbol(value))
            } else if lookahead.peek(syn::LitStr) {
                let value: syn::LitStr = input.parse()?;
                let value = syn::LitByteStr::new(value.value().as_bytes(), value.span());
                Ok(ImportAttribute::Symbol(value))
            } else {
                Err(lookahead.error())
            }
        } else if lookahead.peek(kw::index) {
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

pub fn polkavm_import(attributes: ImportBlockAttributes, input: syn::ItemForeignMod) -> Result<proc_macro2::TokenStream, syn::Error> {
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

    let mut passthrough_tokens = Vec::new();
    let mut tokens = Vec::new();
    for item in input.items {
        match item {
            syn::ForeignItem::Fn(syn::ForeignItemFn { attrs, sig, vis, .. }) => {
                let mut inner_cfg_attributes = Vec::new();
                let mut inner_doc_attributes = Vec::new();
                let mut symbol = None;
                let mut index = None;

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
                                ImportAttribute::Symbol(bytes) => {
                                    symbol = Some(bytes);
                                }
                                ImportAttribute::Index(value) => {
                                    index = Some(value);
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

                let ident = &sig.ident;
                let args = &sig.inputs;
                let output = &sig.output;
                let return_ty = match output {
                    syn::ReturnType::Default => syn::Type::Tuple(syn::TypeTuple {
                        paren_token: Default::default(),
                        elems: Default::default(),
                    }),
                    syn::ReturnType::Type(_, ty) => (**ty).clone(),
                };

                let symbol = symbol.unwrap_or_else(|| syn::LitByteStr::new(ident.to_string().as_bytes(), ident.span()));
                let abi_path = attributes.abi.clone().unwrap_or_else(crate::common::default_abi_path);

                let mut args_into_host = Vec::new();
                let mut args_join = Vec::new();
                let mut args_joined_regs_ty = quote! { () };
                for arg in args {
                    let syn::FnArg::Typed(arg) = arg else {
                        unsupported!(arg);
                    };

                    unsupported_if_some!(arg.attrs.first());
                    let Some(arg_ident) = ident_from_pattern_strict(arg)? else {
                        unsupported!(arg.ty);
                    };

                    args_into_host.push(quote! {
                        let (#arg_ident, _destructor) = #abi_path::IntoHost::into_host(#arg_ident);
                    });

                    let arg_ident = crate::common::expr_from_ident(arg_ident);
                    let arg_ty = &arg.ty;

                    args_join.push(quote! {
                        let regs = #abi_path::private::JoinTuple::join_tuple((regs, #arg_ident));
                    });

                    args_joined_regs_ty = quote! {
                        <(#args_joined_regs_ty, <#arg_ty as #abi_path::IntoHost>::Regs) as #abi_path::private::JoinTuple>::Out
                    };
                }

                passthrough_tokens.push(quote! {
                    #(#inner_doc_attributes)*
                    #(#inner_cfg_attributes)*
                    #vis fn #ident(#args) #output;
                });

                let assert_message = syn::LitStr::new(
                    &format!("too many registers required by the arguments to the imported function '{ident}'"),
                    ident.span(),
                );

                let (has_index, index) = index.map_or((false, 0), |index| (true, index));

                tokens.push(quote! {
                    #(#outer_cfg_attributes)*
                    #(#inner_cfg_attributes)*
                    #[cfg(all(any(target_arch = "riscv32", target_arch = "riscv64"), target_feature = "e"))]
                    #[link_section = ".text.polkavm_import"]
                    #vis unsafe fn #ident(#args) #output {
                        const _: () = {
                            assert!(<#args_joined_regs_ty as #abi_path::private::CountTuple>::COUNT <= #abi_path::private::MAXIMUM_INPUT_REGS, #assert_message);
                        };

                        #(#args_into_host)*
                        let regs = ();
                        #(#args_join)*

                        #[link_section = ".polkavm_metadata"]
                        static METADATA_SYMBOL: &[u8] = #symbol;

                        #[link_section = ".polkavm_metadata"]
                        static METADATA: #abi_path::private::ExternMetadataV2 = #abi_path::private::ExternMetadataV2 {
                            version: 2,
                            flags: 0,
                            symbol_length: METADATA_SYMBOL.len() as u32,
                            symbol: #abi_path::private::MetadataPointer(METADATA_SYMBOL.as_ptr()),
                            input_regs: <#args_joined_regs_ty as #abi_path::private::CountTuple>::COUNT,
                            output_regs: <<#return_ty as #abi_path::FromHost>::Regs as #abi_path::private::CountTuple>::COUNT,
                            has_index: #has_index,
                            index: #index,
                        };

                        struct Sym;

                        #[cfg(target_arch = "riscv32")]
                        impl #abi_path::private::ImportSymbol for Sym {
                            extern fn trampoline(a0: u32, a1: u32, a2: u32, a3: u32, a4: u32, a5: u32) {
                                unsafe {
                                    core::arch::asm!(
                                        ".insn r 0xb, 0, 0, zero, zero, zero\n",
                                        ".4byte {metadata}\n",
                                        "ret\n",
                                        in("a0") a0,
                                        in("a1") a1,
                                        in("a2") a2,
                                        in("a3") a3,
                                        in("a4") a4,
                                        in("a5") a5,
                                        options(noreturn),
                                        metadata = sym METADATA,
                                    );
                                }
                            }
                        }

                        let result = #abi_path::private::CallImport::call_import::<Sym>(regs);
                        let result = #abi_path::private::IntoTuple::into_tuple(result.0, result.1);
                        #abi_path::FromHost::from_host(result)
                    }
                });
            }
            item => unsupported!(item),
        }
    }

    tokens.push(quote! {
        #[cfg(not(all(any(target_arch = "riscv32", target_arch = "riscv64"), target_feature = "e")))]
        #(#outer_cfg_attributes)*
        extern "C" {
            #(#passthrough_tokens)*
        }
    });

    Ok(quote! {
        #(#tokens)*
    })
}
