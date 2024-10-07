use core::fmt::Write;
use quote::quote;

struct Args {
    upper: bool,
    range: core::ops::Range<usize>,
}

impl core::fmt::Display for Args {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
        for nth in self.range.clone() {
            fmt.write_char(char::from(if self.upper { b'A' } else { b'a' } + nth as u8))?;
            fmt.write_char(',')?;
        }
        Ok(())
    }
}

fn generate_tuple_joins() -> proc_macro2::TokenStream {
    const COUNT: usize = 10;
    let mut code = String::new();
    for lhs in 0..=COUNT {
        for rhs in 0..=COUNT {
            let all = lhs + rhs;
            if all > COUNT {
                continue;
            }

            // Special case to get rid of Clippy's 'unused_unit' warning.
            let all_lower_tuple = if all != 0 {
                format!(
                    "({})",
                    Args {
                        range: 0..all,
                        upper: false
                    }
                )
            } else {
                String::new()
            };

            #[rustfmt::skip]
            writeln!(&mut code,
                concat!(
                    "impl<{all_upper}> self::private::JoinTuple for (({lhs_upper}), ({rhs_upper})) {{\n",
                    "    type Out = ({all_upper});\n",
                    "    #[inline(always)]\n",
                    "    fn join_tuple((({lhs_lower}), ({rhs_lower})): Self) -> Self::Out {{\n",
                    "        {all_lower_tuple}",
                    "    }}\n",
                    "}}\n",
                ),
                all_upper = Args { range: 0..all, upper: true },
                all_lower_tuple = all_lower_tuple,
                lhs_upper = Args { range: 0..lhs, upper: true },
                lhs_lower = Args { range: 0..lhs, upper: false },
                rhs_upper = Args { range: lhs..all, upper: true },
                rhs_lower = Args { range: lhs..all, upper: false },
            ).unwrap();
        }
    }

    code.parse().unwrap()
}

fn generate_tuple_splits() -> proc_macro2::TokenStream {
    let mut code = String::new();
    for target in 0..=6 {
        for source in 0..=6 {
            if target > source {
                continue;
            }

            writeln!(
                &mut code,
                concat!(
                    "impl<{source_upper}> self::private::SplitTuple<({target_upper})> for ({source_upper}) {{\n",
                    "    type Remainder = ({remainder_upper});\n",
                    "    #[inline(always)]\n",
                    "    fn split_tuple(({source_lower}): Self) -> (({target_upper}), Self::Remainder) {{\n",
                    "        (({target_lower}), ({remainder_lower}))\n",
                    "    }}\n",
                    "}}\n",
                ),
                source_upper = Args {
                    range: 0..source,
                    upper: true
                },
                source_lower = Args {
                    range: 0..source,
                    upper: false
                },
                target_upper = Args {
                    range: 0..target,
                    upper: true
                },
                target_lower = Args {
                    range: 0..target,
                    upper: false
                },
                remainder_upper = Args {
                    range: target..source,
                    upper: true
                },
                remainder_lower = Args {
                    range: target..source,
                    upper: false
                },
            )
            .unwrap();
        }
    }

    code.parse().unwrap()
}

const ABI_SUPPORT_COMMON_PUBLIC_RS: &str = include_str!("abi_support_impl/common_public.rs");
const ABI_SUPPORT_COMMON_PRIVATE_RS: &str = include_str!("abi_support_impl/common_private.rs");
const ABI_SUPPORT_COMMON_PRIVATE_EXTERA_REGISTERS_RS: &str = include_str!("abi_support_impl/common_private_extra_registers.rs");
const ABI_SUPPORT_RISCV32_RS: &str = include_str!("abi_support_impl/riscv32.rs");
const ABI_SUPPORT_RISCV64_RS: &str = include_str!("abi_support_impl/riscv64.rs");

mod kw {
    syn::custom_keyword!(allow_extra_input_registers);
}

#[derive(Default)]
pub struct AbiSupportAttributes {
    allow_extra_input_registers: bool,
}

impl AbiSupportAttributes {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_allow_extra_input_registers(&mut self, value: bool) {
        self.allow_extra_input_registers = value;
    }
}

impl syn::parse::Parse for AbiSupportAttributes {
    fn parse(input: syn::parse::ParseStream) -> syn::parse::Result<Self> {
        let mut attributes = AbiSupportAttributes::new();

        if input.is_empty() {
            return Ok(attributes);
        }

        enum ImportBlockAttribute {
            AllowExtraInputRegisters,
        }

        let list = input.parse_terminated(
            |input| {
                let lookahead = input.lookahead1();
                if lookahead.peek(kw::allow_extra_input_registers) {
                    input.parse::<kw::allow_extra_input_registers>()?;
                    Ok(ImportBlockAttribute::AllowExtraInputRegisters)
                } else {
                    Err(lookahead.error())
                }
            },
            syn::Token![,],
        )?;

        for attribute in list {
            match attribute {
                ImportBlockAttribute::AllowExtraInputRegisters => {
                    attributes.allow_extra_input_registers = true;
                }
            }
        }

        Ok(attributes)
    }
}

pub fn polkavm_impl_abi_support(attributes: AbiSupportAttributes) -> proc_macro2::TokenStream {
    let common_public_code: proc_macro2::TokenStream = ABI_SUPPORT_COMMON_PUBLIC_RS.parse().unwrap();
    let common_private_code: proc_macro2::TokenStream = ABI_SUPPORT_COMMON_PRIVATE_RS.parse().unwrap();
    let common_private_extra_registers_code: proc_macro2::TokenStream = ABI_SUPPORT_COMMON_PRIVATE_EXTERA_REGISTERS_RS.parse().unwrap();
    let riscv32_code: proc_macro2::TokenStream = ABI_SUPPORT_RISCV32_RS.parse().unwrap();
    let riscv64_code: proc_macro2::TokenStream = ABI_SUPPORT_RISCV64_RS.parse().unwrap();
    let tuple_joins = generate_tuple_joins();
    let tuple_splits = generate_tuple_splits();
    let (maximum_input_regs, extra_registers_code) = if !attributes.allow_extra_input_registers {
        // This will allow the following: a0, a1, a2, a3, a4, a5
        (6_u8, quote! {})
    } else {
        // This will allow the following: a0, a1, a2, a3, a4, a5, t0, t1, t2
        (9_u8, common_private_extra_registers_code)
    };

    assert!(maximum_input_regs as usize <= polkavm_common::program::Reg::MAXIMUM_INPUT_REGS);
    quote! {
        #common_public_code

        #[doc(hidden)]
        pub mod private {
            pub const MAXIMUM_INPUT_REGS: u8 = #maximum_input_regs;
            #common_private_code
            #extra_registers_code
        }

        #riscv32_code
        #riscv64_code
        #tuple_joins
        #tuple_splits
    }
}
