use polkavm_common::abi::VM_MAXIMUM_EXTERN_ARG_COUNT;
use polkavm_common::elf::FnMetadata;
use polkavm_common::program::ExternTy;
use syn::spanned::Spanned;

macro_rules! unsupported {
    ($value: expr) => {
        return Err(syn::Error::new($value.span(), "unsupported by #[polkavm_*]"))
    };
}

macro_rules! unsupported_if_some {
    ($value:expr) => {
        if let Some(value) = $value {
            return Err(syn::Error::new(value.span(), "unsupported by #[polkavm_*]"));
        }
    };
}

pub fn is_path_eq(path: &syn::Path, ident: &str) -> bool {
    let segments: Vec<_> = ident.split("::").collect();
    path.segments.len() == segments.len()
        && path
            .segments
            .iter()
            .zip(segments.iter())
            .all(|(segment, expected)| segment.ident == expected && segment.arguments.is_none())
}

pub fn is_doc(attr: &syn::Attribute) -> bool {
    if let syn::Meta::NameValue(syn::MetaNameValue { ref path, .. }) = attr.meta {
        is_path_eq(path, "doc")
    } else {
        false
    }
}

pub fn is_cfg(attr: &syn::Attribute) -> bool {
    if let syn::Meta::List(syn::MetaList { ref path, .. }) = attr.meta {
        is_path_eq(path, "cfg") || is_path_eq(path, "cfg_attr") || is_path_eq(path, "allow") || is_path_eq(path, "deny")
    } else {
        false
    }
}

pub fn is_rustfmt(attr: &syn::Attribute) -> bool {
    if let syn::Meta::Path(ref path) = attr.meta {
        is_path_eq(path, "rustfmt::skip")
    } else {
        false
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum SimpleTy {
    U8,
    U16,
    U32,
    U64,
    I8,
    I16,
    I32,
    I64,
    Usize,
    Isize,
    Pointer,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Bitness {
    B32,
    B64,
}

pub fn conv_ty(ty: SimpleTy, bitness: Bitness) -> ExternTy {
    match ty {
        SimpleTy::U8 | SimpleTy::U16 | SimpleTy::U32 | SimpleTy::I8 | SimpleTy::I16 | SimpleTy::I32 => ExternTy::I32,

        SimpleTy::U64 | SimpleTy::I64 => ExternTy::I64,

        SimpleTy::Usize | SimpleTy::Isize | SimpleTy::Pointer => match bitness {
            Bitness::B32 => ExternTy::I32,
            Bitness::B64 => ExternTy::I64,
        },
    }
}

pub fn parse_ty(ty: &syn::Type) -> Option<SimpleTy> {
    match ty {
        syn::Type::Path(syn::TypePath {
            qself: None,
            path: syn::Path {
                leading_colon: None,
                segments,
            },
        }) => {
            if segments.len() != 1 {
                return None;
            }

            let segment = &segments[0];
            let ident = segment.ident.to_string();
            match ident.as_str() {
                "u8" => Some(SimpleTy::U8),
                "u16" => Some(SimpleTy::U16),
                "u32" => Some(SimpleTy::U32),
                "u64" => Some(SimpleTy::U64),
                "i8" => Some(SimpleTy::I8),
                "i16" => Some(SimpleTy::I16),
                "i32" => Some(SimpleTy::I32),
                "i64" => Some(SimpleTy::I64),
                "usize" => Some(SimpleTy::Usize),
                "isize" => Some(SimpleTy::Isize),
                _ => None,
            }
        }
        syn::Type::Ptr(syn::TypePtr { .. }) => Some(SimpleTy::Pointer),
        _ => None,
    }
}

pub fn bytes_to_asm(bytes: &[u8]) -> String {
    use std::fmt::Write;

    let mut out = String::with_capacity(bytes.len() * 11);
    for &byte in bytes {
        writeln!(&mut out, ".byte 0x{:02x}", byte).unwrap();
    }

    out
}

fn used_regs(ty: SimpleTy, bitness: Bitness) -> usize {
    use SimpleTy::*;
    match ty {
        U8 | U16 | U32 | I8 | I16 | I32 | Usize | Isize | Pointer => 1,
        U64 | I64 => match bitness {
            Bitness::B32 => 2,
            Bitness::B64 => 1,
        },
    }
}

pub fn create_fn_prototype(sig: &syn::Signature, bitness: Bitness) -> Result<FnMetadata, syn::Error> {
    let mut available_regs: isize = 6;
    assert!(available_regs <= polkavm_common::abi::VM_MAXIMUM_EXTERN_ARG_COUNT as isize);

    let mut parsed_args = Vec::new();
    for arg in &sig.inputs {
        match arg {
            syn::FnArg::Receiver(..) => {
                unsupported!(arg);
            }
            syn::FnArg::Typed(syn::PatType { attrs, pat, ty, .. }) => {
                #[allow(clippy::never_loop)]
                for attr in attrs {
                    unsupported!(attr);
                }

                match &**pat {
                    syn::Pat::Ident(pat) => {
                        #[allow(clippy::never_loop)]
                        for attr in &pat.attrs {
                            unsupported!(attr);
                        }

                        unsupported_if_some!(pat.by_ref);
                        unsupported_if_some!(pat.mutability);

                        if let Some((_, ref subpat)) = pat.subpat {
                            unsupported!(subpat);
                        }
                    }
                    _ => unsupported!(pat),
                }

                let ty = match parse_ty(ty) {
                    Some(ty) => ty,
                    None => {
                        unsupported!(ty);
                    }
                };

                available_regs -= used_regs(ty, bitness) as isize;
                parsed_args.push(ty);
            }
        }
    }

    if available_regs < 0 {
        return Err(syn::Error::new(sig.span(), "too many arguments"));
    }

    let parsed_return_ty = match sig.output {
        syn::ReturnType::Default => None,
        syn::ReturnType::Type(_, ref ty) => {
            if let syn::Type::Tuple(syn::TypeTuple { ref elems, .. }) = **ty {
                if elems.is_empty() {
                    None
                } else {
                    unsupported!(ty);
                }
            } else {
                match parse_ty(ty) {
                    Some(ty) => Some(ty),
                    None => unsupported!(ty),
                }
            }
        }
    };

    let name = sig.ident.to_string();
    Ok(FnMetadata {
        name: name.into(),
        args: {
            let mut args = [None; VM_MAXIMUM_EXTERN_ARG_COUNT];
            for (arg_in, arg_out) in parsed_args.into_iter().zip(args.iter_mut()) {
                *arg_out = Some(conv_ty(arg_in, bitness));
            }
            args
        },
        return_ty: parsed_return_ty.map(|ty| conv_ty(ty, bitness)),
    })
}
