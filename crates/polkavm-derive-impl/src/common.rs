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

pub fn default_abi_path() -> syn::Path {
    syn::Path {
        leading_colon: Some(Default::default()),
        segments: vec![
            syn::PathSegment {
                ident: syn::Ident::new("polkavm_derive", proc_macro2::Span::call_site()),
                arguments: syn::PathArguments::None,
            },
            syn::PathSegment {
                ident: syn::Ident::new("default_abi", proc_macro2::Span::call_site()),
                arguments: syn::PathArguments::None,
            },
        ]
        .into_iter()
        .collect(),
    }
}

pub fn expr_from_ident(ident: syn::Ident) -> syn::ExprPath {
    syn::ExprPath {
        attrs: Default::default(),
        qself: None,
        path: syn::Path {
            leading_colon: None,
            segments: vec![syn::PathSegment {
                ident,
                arguments: syn::PathArguments::None,
            }]
            .into_iter()
            .collect(),
        },
    }
}
