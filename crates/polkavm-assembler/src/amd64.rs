#![allow(non_camel_case_types)]

use crate::assembler::{EncInst, Label};

/// The REX prefix.
const REX: u8 = 0x40;
const REX_64B_OP: u8 = REX | (1 << 3);
const REX_EXT_MODRM_REG: u8 = REX | (1 << 2);
const REX_EXT_MODRM_RM: u8 = REX | (1 << 0);

const PREFIX_OVERRIDE_OP_SIZE: u8 = 0x66;
const PREFIX_OVERRIDE_ADDR_SIZE: u8 = 0x67;

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Reg {
    rax = 0,
    rcx = 1,
    rdx = 2,
    rbx = 3,
    rsp = 4,
    rbp = 5,
    rsi = 6,
    rdi = 7,
    r8 = 8,
    r9 = 9,
    r10 = 10,
    r11 = 11,
    r12 = 12,
    r13 = 13,
    r14 = 14,
    r15 = 15,
}

impl Reg {
    pub const fn is_reg_preserved(self) -> bool {
        // See page 23 from: https://raw.githubusercontent.com/wiki/hjl-tools/x86-psABI/x86-64-psABI-1.0.pdf
        use Reg::*;
        match self {
            rbx | rsp | rbp | r12 | r13 | r14 | r15 => true,
            rax | rcx | rdx | rsi | rdi | r8 | r9 | r10 | r11 => false,
        }
    }

    pub const fn needs_rex(self) -> bool {
        self as usize >= Reg::r8 as usize
    }

    pub const fn modrm_rm_bits(self) -> u8 {
        (self as usize & 0b111) as u8
    }

    pub const fn modrm_reg_bits(self) -> u8 {
        (((self as usize) << 3) & 0b111000) as u8
    }

    pub const fn rex_bit(self) -> u8 {
        if self as usize >= Reg::r8 as usize {
            REX_EXT_MODRM_RM
        } else {
            0
        }
    }

    pub const fn rex_modrm_reg(self) -> u8 {
        if self as usize >= Reg::r8 as usize {
            REX_EXT_MODRM_REG
        } else {
            0
        }
    }

    pub const fn name_from(self, size: RegSize) -> &'static str {
        match size {
            RegSize::R64 => self.name(),
            RegSize::R32 => self.name32(),
        }
    }
}

impl core::fmt::Display for Reg {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
        fmt.write_str(self.name())
    }
}

macro_rules! impl_regs {
    ($(($r64:ident, $r32:ident, $r16:ident, $r8:ident)),+) => {
        impl Reg {
            pub const fn name(self) -> &'static str {
                match self {
                    $(
                        Reg::$r64 => stringify!($r64),
                    )+
                }
            }

            pub const fn name32(self) -> &'static str {
                match self {
                    $(
                        Reg::$r64 => stringify!($r32),
                    )+
                }
            }

            pub const fn name16(self) -> &'static str {
                match self {
                    $(
                        Reg::$r64 => stringify!($r16),
                    )+
                }
            }

            pub const fn name8(self) -> &'static str {
                match self {
                    $(
                        Reg::$r64 => stringify!($r8),
                    )+
                }
            }
        }
    };
}

impl_regs! {
    (rax, eax, ax, al),
    (rcx, ecx, cx, cl),
    (rdx, edx, dx, dl),
    (rbx, ebx, bx, bl),
    (rsp, esp, sp, spl),
    (rbp, ebp, bp, bpl),
    (rsi, esi, si, sil),
    (rdi, edi, di, dil),
    (r8, r8d, r8w, r8b),
    (r9, r9d, r9w, r9b),
    (r10, r10d, r10w, r10b),
    (r11, r11d, r11w, r11b),
    (r12, r12d, r12w, r12b),
    (r13, r13d, r13w, r13b),
    (r14, r14d, r14w, r14b),
    (r15, r15d, r15w, r15b)
}

#[derive(Copy, Clone)]
enum Imm {
    Imm8(i8),
    Imm32(i32),
}

impl Imm {
    const fn append_into(self, enc: EncInst) -> EncInst {
        match self {
            Imm::Imm8(value) => enc.append(value as u8),
            Imm::Imm32(value) => {
                let xs = value.to_le_bytes();
                enc.append_array([xs[0], xs[1], xs[2], xs[3]])
            }
        }
    }
}

struct Inst {
    override_op_size: bool,
    override_addr_size: bool,
    op_alt: bool,
    enable_modrm: bool,
    rex: u8,
    opcode: u8,
    modrm: u8,
    sib: u8,
    imm: Option<Imm>,
}

// See: https://www-user.tu-chemnitz.de/~heha/hsn/chm/x86.chm/x64.htm
impl Inst {
    const fn new(opcode: u8) -> Self {
        Inst {
            override_op_size: false,
            override_addr_size: false,
            op_alt: false,
            enable_modrm: false,
            rex: 0,
            opcode,
            modrm: 0,
            sib: 0,
            imm: None,
        }
    }

    const fn with_reg_in_op(opcode: u8, reg: Reg) -> Self {
        Inst::new(opcode | reg.modrm_rm_bits()).rex_from_reg(reg)
    }

    const fn override_op_size(mut self) -> Self {
        self.override_op_size = true;
        self
    }

    const fn override_addr_size_if(mut self, cond: bool) -> Self {
        if cond {
            self.override_addr_size = true;
        }
        self
    }

    const fn op_alt(mut self) -> Self {
        self.op_alt = true;
        self
    }

    const fn rex(mut self) -> Self {
        self.rex |= REX;
        self
    }

    const fn rex_if(mut self, cond: bool) -> Self {
        if cond {
            self = self.rex();
        }
        self
    }

    const fn rex_from_reg(mut self, reg: Reg) -> Self {
        if reg.needs_rex() {
            self.rex |= REX_EXT_MODRM_RM;
        }
        self
    }

    const fn rex_64b(mut self) -> Self {
        self.rex |= REX_64B_OP;
        self
    }

    const fn rex_64b_if(mut self, cond: bool) -> Self {
        if cond {
            self.rex |= REX_64B_OP;
        }
        self
    }

    const fn modrm_rm_direct(mut self, value: Reg) -> Self {
        if value.needs_rex() {
            self.rex |= REX_EXT_MODRM_RM;
        }
        self.modrm |= value.modrm_rm_bits() | 0b11000000;
        self.enable_modrm = true;
        self
    }

    const fn modrm_rm_indirect(mut self, value: Reg, offset: i32) -> Self {
        if matches!(value, Reg::rsp | Reg::r12) {
            if value.needs_rex() {
                self.rex |= REX_EXT_MODRM_RM;
            }
            self.modrm |= 0b00000100;
            self.sib = 0b00100100;
        } else if matches!(value, Reg::rbp | Reg::r13) && offset == 0 {
            if value.needs_rex() {
                self.rex |= REX_EXT_MODRM_RM;
            }
            self.modrm |= 0b01000101;
            self.sib = 0b00101101;
            self.imm = Some(Imm::Imm8(0));
        } else {
            if value.needs_rex() {
                self.rex |= REX_EXT_MODRM_RM;
            }
            self.modrm |= value.modrm_rm_bits();
        }

        if offset != 0 {
            if offset <= i8::MAX as i32 && offset >= i8::MIN as i32 {
                self.modrm |= 0b01000000;
                self.imm = Some(Imm::Imm8(offset as i8));
            } else {
                self.modrm |= 0b10000000;
                self.imm = Some(Imm::Imm32(offset));
            }
        }

        self.enable_modrm = true;
        self
    }

    const fn modrm_rm_rip(mut self, offset: i32) -> Self {
        self.modrm |= 0b101;
        self.imm = Some(Imm::Imm32(offset));
        self.enable_modrm = true;
        self
    }

    const fn modrm_rm_abs32(mut self, displacement: i32) -> Self {
        self.modrm |= 0b00000100;
        self.enable_modrm = true;
        self.sib = 0b00100101;
        self.imm = Some(Imm::Imm32(displacement));
        self
    }

    const fn modrm_reg(mut self, value: Reg) -> Self {
        if value.needs_rex() {
            self.rex |= REX_EXT_MODRM_REG;
        }
        self.modrm |= value.modrm_reg_bits();
        self.enable_modrm = true;
        self
    }

    const fn modrm_opext(mut self, ext: u8) -> Self {
        self.modrm |= ext << 3;
        self.enable_modrm = true;
        self
    }

    const fn imm8(mut self, value: i8) -> Self {
        self.imm = Some(Imm::Imm8(value));
        self
    }

    const fn imm32(mut self, value: i32) -> Self {
        self.imm = Some(Imm::Imm32(value));
        self
    }

    const fn encode(self) -> EncInst {
        let mut enc = EncInst::new();
        if self.override_op_size {
            enc = enc.append(PREFIX_OVERRIDE_OP_SIZE);
        }
        if self.override_addr_size {
            enc = enc.append(PREFIX_OVERRIDE_ADDR_SIZE);
        }
        if self.rex != 0 {
            enc = enc.append(self.rex);
        }
        if self.op_alt {
            enc = enc.append(0x0f);
        }
        enc = enc.append(self.opcode);
        if self.enable_modrm {
            enc = enc.append(self.modrm);
            if self.modrm & 0b11000000 != 0b11000000 && self.modrm & 0b111 == 0b100 {
                enc = enc.append(self.sib);
            }
        }
        if let Some(imm) = self.imm {
            enc = imm.append_into(enc);
        }
        enc
    }
}

macro_rules! impl_inst {
    (@generate_test_values $cb:expr, $name:ident, $arg0:ty, $arg1:ty, $arg2:ty, $arg3:ty, $arg4:ty) => {
        <$arg0 as super::tests::GenerateTestValues>::generate_test_values(|arg0|
            <$arg1 as super::tests::GenerateTestValues>::generate_test_values(|arg1|
                <$arg2 as super::tests::GenerateTestValues>::generate_test_values(|arg2|
                    <$arg3 as super::tests::GenerateTestValues>::generate_test_values(|arg3|
                        <$arg4 as super::tests::GenerateTestValues>::generate_test_values(|arg4|
                            $cb($name(arg0, arg1, arg2, arg3, arg4))
                        )
                    )
                )
            )
        )
    };

    (@generate_test_values $cb:expr, $name:ident, $arg0:ty, $arg1:ty, $arg2:ty, $arg3:ty) => {
        <$arg0 as super::tests::GenerateTestValues>::generate_test_values(|arg0|
            <$arg1 as super::tests::GenerateTestValues>::generate_test_values(|arg1|
                <$arg2 as super::tests::GenerateTestValues>::generate_test_values(|arg2|
                    <$arg3 as super::tests::GenerateTestValues>::generate_test_values(|arg3|
                        $cb($name(arg0, arg1, arg2, arg3))
                    )
                )
            )
        )
    };

    (@generate_test_values $cb:expr, $name:ident, $arg0:ty, $arg1:ty, $arg2:ty) => {
        <$arg0 as super::tests::GenerateTestValues>::generate_test_values(|arg0|
            <$arg1 as super::tests::GenerateTestValues>::generate_test_values(|arg1|
                <$arg2 as super::tests::GenerateTestValues>::generate_test_values(|arg2|
                    $cb($name(arg0, arg1, arg2))
                )
            )
        )
    };

    (@generate_test_values $cb:expr, $name:ident, $arg0:ty, $arg1:ty) => {
        <$arg0 as super::tests::GenerateTestValues>::generate_test_values(|arg0|
            <$arg1 as super::tests::GenerateTestValues>::generate_test_values(|arg1|
                $cb($name(arg0, arg1))
            )
        )
    };

    (@generate_test_values $cb:expr, $name:ident, $arg0:ty) => {
        <$arg0 as super::tests::GenerateTestValues>::generate_test_values(|arg0|
            $cb($name(arg0))
        )
    };

    (@generate_test_values $cb:expr, $name:ident,) => {
        $cb($name())
    };

    (|$self:ident, $fmt:ident| $($name:ident($($arg:ty),*) => $body:expr, ($fmt_body:expr),)+) => {
        $(
            #[derive(Copy, Clone, PartialEq, Eq, Debug)]
            pub struct $name($(pub $arg),*);
            impl $name {
                const fn encode_const($self) -> EncInst {
                    $body
                }
            }

            impl core::fmt::Display for $name {
                fn fmt(&$self, $fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
                    $fmt_body
                }
            }

            impl crate::Instruction for $name {
                fn encode(self) -> EncInst {
                    self.encode_const()
                }

                fn target_fixup(self) -> Option<(Label, u8, u8)> {
                    None
                }
            }

            #[cfg(test)]
            impl super::tests::GenerateTestValues for $name {
                fn generate_test_values(mut cb: impl FnMut(Self)) {
                    impl_inst!(@generate_test_values cb, $name, $($arg),*);
                }
            }
        )+
    };
}

pub mod inst {
    use super::*;
    use crate::assembler::EncInst;

    const fn alu_imm(size: RegSize, reg: Reg, imm: i32, opext: u8) -> EncInst {
        let inst = if imm <= i8::MAX as i32 && imm >= i8::MIN as i32 {
            Inst::new(0x83).imm8(imm as i8)
        } else {
            Inst::new(0x81).imm32(imm)
        };

        inst.rex_64b_if(matches!(size, RegSize::R64))
            .modrm_opext(opext)
            .modrm_rm_direct(reg)
            .encode()
    }

    impl_inst! { |self, fmt|
        ud2() =>
            EncInst::from_array([0x0f, 0x0b]),
            (fmt.write_str("ud2")),

        // https://www.felixcloutier.com/x86/endbr64
        endbr64() =>
            EncInst::from_array([0xf3, 0x0f, 0x1e, 0xfa]),
            (fmt.write_str("endbr64")),

        // https://www.felixcloutier.com/x86/syscall
        syscall() =>
            EncInst::from_array([0x0f, 0x05]),
            (fmt.write_str("syscall")),

        // https://www.felixcloutier.com/x86/push
        push(Reg) =>
            Inst::with_reg_in_op(0x50, self.0).encode(),
            (fmt.write_fmt(core::format_args!("push {}", self.0))),

        // https://www.felixcloutier.com/x86/pop
        pop(Reg) =>
            Inst::with_reg_in_op(0x58, self.0).encode(),
            (fmt.write_fmt(core::format_args!("pop {}", self.0))),

        // https://www.felixcloutier.com/x86/nop
        nop() =>
            EncInst::from_array([0x90]),
            (fmt.write_str("nop")),

        nop2() =>
            EncInst::from_array([0x66, 0x90]),
            (fmt.write_str("xchg ax, ax")),

        nop3() =>
            EncInst::from_array([0x0f, 0x1f, 0x00]),
            (fmt.write_str("nop dword [rax]")),

        nop4() =>
            EncInst::from_array([0x0f, 0x1f, 0x40, 0x00]),
            (fmt.write_str("nop dword [rax]")),

        nop5() =>
            EncInst::from_array([0x0f, 0x1f, 0x44, 0x00, 0x00]),
            (fmt.write_str("nop dword [rax+rax]")),

        nop6() =>
            EncInst::from_array([0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00]),
            (fmt.write_str("nop word [rax+rax]")),

        nop7() =>
            EncInst::from_array([0x0f, 0x1f, 0x80, 0x00, 0x00, 0x00, 0x00]),
            (fmt.write_str("nop dword [rax]")), //

        nop8() =>
            EncInst::from_array([0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00]),
            (fmt.write_str("nop dword [rax+rax]")),

        nop9() =>
            EncInst::from_array([0x66, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00]),
            (fmt.write_str("nop word [rax+rax]")), //

        nop10() =>
            EncInst::from_array([0x66, 0x2e, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00]),
            (fmt.write_str("nop word [cs:rax+rax]")),

        nop11() =>
            EncInst::from_array([0x66, 0x66, 0x2e, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00]),
            (fmt.write_str("nop word [cs:rax+rax]")),

        // https://www.felixcloutier.com/x86/ret
        ret() =>
            EncInst::from_array([0xc3]),
            (fmt.write_str("ret")),

        // https://www.felixcloutier.com/x86/mov
        // https://www.felixcloutier.com/x86/movzx
        // https://www.felixcloutier.com/x86/movsx:movsxd
        load64_imm(Reg, u64) =>
            {
                if self.1 <= 0x7fffffff {
                    let xs = (self.1 as u32).to_le_bytes();
                    EncInst::from_array([
                        REX_64B_OP | self.0.rex_bit(),
                        0xc7,
                        0xc0 | self.0.modrm_rm_bits(),
                        xs[0], xs[1], xs[2], xs[3]
                    ])
                } else {
                    let xs = self.1.to_le_bytes();
                    EncInst::from_array([
                        REX_64B_OP | self.0.rex_bit(),
                        0xb8 | self.0.modrm_rm_bits(),
                        xs[0], xs[1], xs[2], xs[3], xs[4], xs[5], xs[6], xs[7]
                    ])
                }
            },
            (fmt.write_fmt(core::format_args!("mov {}, 0x{:x}", self.0, self.1))),

        load32_imm(Reg, u32) =>
            Inst::with_reg_in_op(0xb8, self.0).imm32(self.1 as i32).encode(),
            (fmt.write_fmt(core::format_args!("mov {}, 0x{:x}", self.0.name32(), self.1))),

        mov(RegSize, Reg, Reg) =>
            Inst::new(0x89).rex_64b_if(matches!(self.0, RegSize::R64)).modrm_rm_direct(self.1).modrm_reg(self.2).encode(),
            (fmt.write_fmt(core::format_args!("mov {}, {}", self.1.name_from(self.0), self.2.name_from(self.0)))),

        movsxd_32_to_64(Reg, Reg) =>
            Inst::new(0x63).rex_64b().modrm_rm_direct(self.1).modrm_reg(self.0).encode(),
            (fmt.write_fmt(core::format_args!("movsxd {}, {}", self.0.name(), self.1.name32()))),

        store_indirect(RegSize, Reg, i32, Reg, StoreKind) =>
            {
                let inst = match self.4 {
                    StoreKind::U8 => Inst::new(0x88).rex_if(!matches!(self.3, Reg::rax | Reg::rcx | Reg::rdx | Reg::rbx)),
                    StoreKind::U16 => Inst::new(0x89).override_op_size(),
                    StoreKind::U32 => Inst::new(0x89),
                    StoreKind::U64 => Inst::new(0x89).rex_64b(),
                };

                inst
                    .override_addr_size_if(matches!(self.0, RegSize::R32))
                    .modrm_rm_indirect(self.1, self.2)
                    .modrm_reg(self.3)
                    .encode()
            },
            ({
                let reg = match self.4 {
                    StoreKind::U64 => self.3.name(),
                    StoreKind::U32 => self.3.name32(),
                    StoreKind::U16 => self.3.name16(),
                    StoreKind::U8 => self.3.name8(),
                };

                fmt.write_fmt(core::format_args!("mov [{}", self.1.name_from(self.0)))?;
                if self.2 != 0 {
                    if self.2 > 0 {
                        fmt.write_fmt(core::format_args!("+0x{:x}", self.2))?;
                    } else {
                        fmt.write_fmt(core::format_args!("-0x{:x}", -(self.2 as i64)))?;
                    }
                }
                fmt.write_fmt(core::format_args!("], {}", reg))
            }),

        store_abs(i32, Reg, StoreKind) =>
            {
                let inst = match self.2 {
                    StoreKind::U64 => Inst::new(0x89).rex_64b(),
                    StoreKind::U32 => Inst::new(0x89),
                    StoreKind::U16 => Inst::new(0x89).override_op_size(),
                    StoreKind::U8 => Inst::new(0x88).rex_if(!matches!(self.1, Reg::rax | Reg::rcx | Reg::rdx | Reg::rbx))
                };

                inst
                    .modrm_rm_abs32(self.0)
                    .modrm_reg(self.1)
                    .encode()
            },
            ({
                let reg = match self.2 {
                    StoreKind::U64 => self.1.name(),
                    StoreKind::U32 => self.1.name32(),
                    StoreKind::U16 => self.1.name16(),
                    StoreKind::U8 => self.1.name8(),
                };

                fmt.write_fmt(core::format_args!("mov [0x{:x}], {}", self.0 as i64, reg))
            }),

        store8_abs_imm(i32, u8) =>
            {
                Inst::new(0xc6)
                    .modrm_rm_abs32(self.0)
                    .encode()
                    .append_array(self.1.to_le_bytes())
            },
            (fmt.write_fmt(core::format_args!("mov byte [0x{:x}], 0x{:x}", self.0 as i64, self.1))),

        store16_abs_imm(i32, u16) =>
            {
                Inst::new(0xc7)
                    .override_op_size()
                    .modrm_rm_abs32(self.0)
                    .encode()
                    .append_array(self.1.to_le_bytes())
            },
            (fmt.write_fmt(core::format_args!("mov word [0x{:x}], 0x{:x}", self.0 as i64, self.1))),

        store32_abs_imm(i32, u32) =>
            {
                Inst::new(0xc7)
                    .modrm_rm_abs32(self.0)
                    .encode()
                    .append_array(self.1.to_le_bytes())
            },
            (fmt.write_fmt(core::format_args!("mov dword [0x{:x}], 0x{:x}", self.0 as i64, self.1))),

        store8_indirect_imm(RegSize, Reg, i32, u8) =>
            {
                Inst::new(0xc6)
                    .override_op_size()
                    .override_addr_size_if(matches!(self.0, RegSize::R32))
                    .modrm_rm_indirect(self.1, self.2)
                    .encode()
                    .append_array(self.3.to_le_bytes())
            },
            ({
                fmt.write_fmt(core::format_args!("mov byte [{}", self.1.name_from(self.0)))?;
                if self.2 != 0 {
                    if self.2 > 0 {
                        fmt.write_fmt(core::format_args!("+0x{:x}", self.2))?;
                    } else {
                        fmt.write_fmt(core::format_args!("-0x{:x}", -(self.2 as i64)))?;
                    }
                }
                fmt.write_fmt(core::format_args!("], 0x{:x}", self.3))
            }),

        store16_indirect_imm(RegSize, Reg, i32, u16) =>
            {
                Inst::new(0xc7)
                    .override_op_size()
                    .override_addr_size_if(matches!(self.0, RegSize::R32))
                    .modrm_rm_indirect(self.1, self.2)
                    .encode()
                    .append_array(self.3.to_le_bytes())
            },
            ({
                fmt.write_fmt(core::format_args!("mov word [{}", self.1.name_from(self.0)))?;
                if self.2 != 0 {
                    if self.2 > 0 {
                        fmt.write_fmt(core::format_args!("+0x{:x}", self.2))?;
                    } else {
                        fmt.write_fmt(core::format_args!("-0x{:x}", -(self.2 as i64)))?;
                    }
                }
                fmt.write_fmt(core::format_args!("], 0x{:x}", self.3))
            }),

        store32_indirect_imm(RegSize, Reg, i32, u32) =>
            {
                Inst::new(0xc7)
                    .override_addr_size_if(matches!(self.0, RegSize::R32))
                    .modrm_rm_indirect(self.1, self.2)
                    .encode()
                    .append_array(self.3.to_le_bytes())
            },
            ({
                fmt.write_fmt(core::format_args!("mov dword [{}", self.1.name_from(self.0)))?;
                if self.2 != 0 {
                    if self.2 > 0 {
                        fmt.write_fmt(core::format_args!("+0x{:x}", self.2))?;
                    } else {
                        fmt.write_fmt(core::format_args!("-0x{:x}", -(self.2 as i64)))?;
                    }
                }
                fmt.write_fmt(core::format_args!("], 0x{:x}", self.3))
            }),

        load_indirect(Reg, RegSize, Reg, i32, LoadKind) =>
            {
                let inst = match self.4 {
                    LoadKind::U8 | LoadKind::U16 | LoadKind::I8 | LoadKind::I16 => {
                        let op = match self.4 {
                            LoadKind::U8 => 0xb6,
                            LoadKind::I8 => 0xbe,
                            LoadKind::U16 => 0xb7,
                            LoadKind::I16 => 0xbf,
                            | LoadKind::I32
                            | LoadKind::U32
                            | LoadKind::U64
                                => unreachable!()
                        };

                        Inst::new(op).op_alt().rex_64b()
                    },
                    LoadKind::I32 => Inst::new(0x63).rex_64b(),
                    LoadKind::U32 => Inst::new(0x8b),
                    LoadKind::U64 => Inst::new(0x8b).rex_64b()
                };

                inst
                    .override_addr_size_if(matches!(self.1, RegSize::R32))
                    .modrm_rm_indirect(self.2, self.3)
                    .modrm_reg(self.0)
                    .encode()
            },
            ({
                let (name, kind, size) = match self.4 {
                    LoadKind::U8 => (self.0.name(), "zx", "byte "),
                    LoadKind::I8 => (self.0.name(), "sx", "byte "),
                    LoadKind::U16 => (self.0.name(), "zx", "word "),
                    LoadKind::U32 => (self.0.name32(), "", ""),
                    LoadKind::I16 => (self.0.name(), "sx", "word "),
                    LoadKind::I32 => (self.0.name(), "sxd", ""),
                    LoadKind::U64 => (self.0.name(), "", ""),
                };

                fmt.write_fmt(core::format_args!("mov{} {}, {}[{}", kind, name, size, self.2.name_from(self.1)))?;
                if self.3 != 0 {
                    if self.3 > 0 {
                        fmt.write_fmt(core::format_args!("+0x{:x}", self.3))?;
                    } else {
                        fmt.write_fmt(core::format_args!("-0x{:x}", -(self.3 as i64)))?;
                    }
                }
                fmt.write_str("]")
            }),

        load_abs(Reg, i32, LoadKind) =>
            {
                let inst = if matches!(self.2, LoadKind::U64) {
                    Inst::new(0x8b).rex_64b()
                } else if matches!(self.2, LoadKind::U32) {
                    Inst::new(0x8b)
                } else if matches!(self.2, LoadKind::U8 | LoadKind::U16) && !self.0.needs_rex() {
                    // Use a 32-bit register as that's 1 byte shorter if we don't need the REX prefix.
                    let op = if matches!(self.2, LoadKind::U8) {
                        0xb6
                    } else {
                        0xb7
                    };

                    Inst::new(op).op_alt()
                } else if matches!(self.2, LoadKind::I32) {
                    Inst::new(0x63).rex_64b()
                } else {
                    let op = match self.2 {
                        LoadKind::U8 => 0xb6,
                        LoadKind::I8 => 0xbe,
                        LoadKind::U16 => 0xb7,
                        LoadKind::I16 => 0xbf,
                        | LoadKind::I32
                        | LoadKind::U32
                        | LoadKind::U64
                            => unreachable!()
                    };

                    Inst::new(op).op_alt().rex_64b()
                };

                inst
                    .modrm_rm_abs32(self.1)
                    .modrm_reg(self.0)
                    .encode()
            },
            ({
                let (reg, kind, size) = match self.2 {
                    LoadKind::U8 if !self.0.needs_rex() => (self.0.name32(), "zx", "byte "),
                    LoadKind::U16 if !self.0.needs_rex() => (self.0.name32(), "zx", "word "),
                    LoadKind::U8 => (self.0.name(), "zx", "byte "),
                    LoadKind::U16 => (self.0.name(), "zx", "word "),
                    LoadKind::U32 => (self.0.name32(), "", ""),
                    LoadKind::U64 => (self.0.name(), "", ""),
                    LoadKind::I8 => (self.0.name(), "sx", "byte "),
                    LoadKind::I16 => (self.0.name(), "sx", "word "),
                    LoadKind::I32 => (self.0.name(), "sxd", ""),
                };
                fmt.write_fmt(core::format_args!("mov{} {}, {}[0x{:x}]", kind, reg, size, self.1 as i64))
            }),

        // https://www.felixcloutier.com/x86/add
        add(RegSize, Reg, Reg) =>
            Inst::new(0x01).rex_64b_if(matches!(self.0, RegSize::R64)).modrm_rm_direct(self.1).modrm_reg(self.2).encode(),
            (fmt.write_fmt(core::format_args!("add {}, {}", self.1.name_from(self.0), self.2.name_from(self.0)))),

        add_imm(RegSize, Reg, i32) =>
            alu_imm(self.0, self.1, self.2, 0b000),
            ({
                match self.0 {
                    RegSize::R64 => fmt.write_fmt(core::format_args!("add {}, 0x{:x}", self.1, self.2 as i64)),
                    RegSize::R32 => fmt.write_fmt(core::format_args!("add {}, 0x{:x}", self.1.name32(), self.2)),
                }
            }),

        // https://www.felixcloutier.com/x86/inc
        inc(RegSize, Reg) =>
            Inst::new(0xff).rex_64b_if(matches!(self.0, RegSize::R64)).modrm_rm_direct(self.1).encode(),
            (fmt.write_fmt(core::format_args!("inc {}", self.1.name_from(self.0)))),

        // https://www.felixcloutier.com/x86/sub
        sub(RegSize, Reg, Reg) =>
            Inst::new(0x29).rex_64b_if(matches!(self.0, RegSize::R64)).modrm_rm_direct(self.1).modrm_reg(self.2).encode(),
            (fmt.write_fmt(core::format_args!("sub {}, {}", self.1.name_from(self.0), self.2.name_from(self.0)))),

        sub_imm(RegSize, Reg, i32) =>
            alu_imm(self.0, self.1, self.2, 0b101),
            ({
                match self.0 {
                    RegSize::R64 => fmt.write_fmt(core::format_args!("sub {}, 0x{:x}", self.1, self.2 as i64)),
                    RegSize::R32 => fmt.write_fmt(core::format_args!("sub {}, 0x{:x}", self.1.name32(), self.2)),
                }
            }),

        // https://www.felixcloutier.com/x86/or
        or(RegSize, Reg, Reg) =>
            Inst::new(0x09).rex_64b_if(matches!(self.0, RegSize::R64)).modrm_rm_direct(self.1).modrm_reg(self.2).encode(),
            (fmt.write_fmt(core::format_args!("or {}, {}", self.1.name_from(self.0), self.2.name_from(self.0)))),

        or_imm(RegSize, Reg, i32) =>
            alu_imm(self.0, self.1, self.2, 0b001),
            ({
                match self.0 {
                    RegSize::R64 => fmt.write_fmt(core::format_args!("or {}, 0x{:x}", self.1, self.2 as i64)),
                    RegSize::R32 => fmt.write_fmt(core::format_args!("or {}, 0x{:x}", self.1.name32(), self.2)),
                }
            }),

        // https://www.felixcloutier.com/x86/and
        and(RegSize, Reg, Reg) =>
            Inst::new(0x21).rex_64b_if(matches!(self.0, RegSize::R64)).modrm_rm_direct(self.1).modrm_reg(self.2).encode(),
            (fmt.write_fmt(core::format_args!("and {}, {}", self.1.name_from(self.0), self.2.name_from(self.0)))),

        and_imm(RegSize, Reg, i32) =>
            alu_imm(self.0, self.1, self.2, 0b100),
            ({
                match self.0 {
                    RegSize::R64 => fmt.write_fmt(core::format_args!("and {}, 0x{:x}", self.1, self.2 as i64)),
                    RegSize::R32 => fmt.write_fmt(core::format_args!("and {}, 0x{:x}", self.1.name32(), self.2)),
                }
            }),

        // https://www.felixcloutier.com/x86/xor
        xor(RegSize, Reg, Reg) =>
            Inst::new(0x31).rex_64b_if(matches!(self.0, RegSize::R64)).modrm_rm_direct(self.1).modrm_reg(self.2).encode(),
            (fmt.write_fmt(core::format_args!("xor {}, {}", self.1.name_from(self.0), self.2.name_from(self.0)))),

        xor_imm(RegSize, Reg, i32) =>
            alu_imm(self.0, self.1, self.2, 0b110),
            ({
                match self.0 {
                    RegSize::R64 => fmt.write_fmt(core::format_args!("xor {}, 0x{:x}", self.1, self.2 as i64)),
                    RegSize::R32 => fmt.write_fmt(core::format_args!("xor {}, 0x{:x}", self.1.name32(), self.2)),
                }
            }),

        // https://www.felixcloutier.com/x86/bts
        bts(RegSize, Reg, u8) =>
            Inst::new(0xba).op_alt().modrm_opext(0b101).rex_64b_if(matches!(self.0, RegSize::R64)).modrm_rm_direct(self.1).imm8(self.2 as i8).encode(),
            ({
                match self.0 {
                    RegSize::R64 => fmt.write_fmt(core::format_args!("bts {}, 0x{:x}", self.1, self.2 as i64)),
                    RegSize::R32 => fmt.write_fmt(core::format_args!("bts {}, 0x{:x}", self.1.name32(), self.2)),
                }
            }),

        // https://www.felixcloutier.com/x86/neg
        neg(RegSize, Reg) =>
            Inst::new(0xf7).rex_64b_if(matches!(self.0, RegSize::R64)).modrm_rm_direct(self.1).modrm_opext(0b011).encode(),
            (fmt.write_fmt(core::format_args!("neg {}", self.1.name_from(self.0)))),

        // https://www.felixcloutier.com/x86/not
        not(RegSize, Reg) =>
            Inst::new(0xf7).rex_64b_if(matches!(self.0, RegSize::R64)).modrm_rm_direct(self.1).modrm_opext(0b010).encode(),
            (fmt.write_fmt(core::format_args!("not {}", self.1.name_from(self.0)))),

        // https://www.felixcloutier.com/x86/cmp
        cmp(RegSize, Reg, Reg) =>
            Inst::new(0x39).rex_64b_if(matches!(self.0, RegSize::R64)).modrm_rm_direct(self.1).modrm_reg(self.2).encode(),
            (fmt.write_fmt(core::format_args!("cmp {}, {}", self.1.name_from(self.0), self.2.name_from(self.0)))),

        cmp_imm(RegSize, Reg, i32) =>
            alu_imm(self.0, self.1, self.2, 0b111),
            ({
                match self.0 {
                    RegSize::R64 => fmt.write_fmt(core::format_args!("cmp {}, 0x{:x}", self.1, self.2 as i64)),
                    RegSize::R32 => fmt.write_fmt(core::format_args!("cmp {}, 0x{:x}", self.1.name32(), self.2)),
                }
            }),

        // https://www.felixcloutier.com/x86/sal:sar:shl:shr
        sar_cl(RegSize, Reg) =>
            Inst::new(0xD3).rex_64b_if(matches!(self.0, RegSize::R64)).modrm_rm_direct(self.1).modrm_opext(0b111).encode(),
            (fmt.write_fmt(core::format_args!("sar {}, cl", self.1.name_from(self.0)))),

        sar_imm(RegSize, Reg, u8) =>
            Inst::new(0xc1).rex_64b_if(matches!(self.0, RegSize::R64)).modrm_rm_direct(self.1).modrm_opext(0b111).imm8(self.2 as i8).encode(),
            (fmt.write_fmt(core::format_args!("sar {}, 0x{:x}", self.1.name_from(self.0), self.2))),

        shl_cl(RegSize, Reg) =>
            Inst::new(0xd3).rex_64b_if(matches!(self.0, RegSize::R64)).modrm_rm_direct(self.1).modrm_opext(0b100).encode(),
            (fmt.write_fmt(core::format_args!("shl {}, cl", self.1.name_from(self.0)))),

        shl_imm(RegSize, Reg, u8) =>
            Inst::new(0xc1).rex_64b_if(matches!(self.0, RegSize::R64)).modrm_rm_direct(self.1).modrm_opext(0b100).imm8(self.2 as i8).encode(),
            (fmt.write_fmt(core::format_args!("shl {}, 0x{:x}", self.1.name_from(self.0), self.2))),

        shr_cl(RegSize, Reg) =>
            Inst::new(0xd3).rex_64b_if(matches!(self.0, RegSize::R64)).modrm_rm_direct(self.1).modrm_opext(0b101).encode(),
            (fmt.write_fmt(core::format_args!("shr {}, cl", self.1.name_from(self.0)))),

        shr_imm(RegSize, Reg, u8) =>
            Inst::new(0xc1).rex_64b_if(matches!(self.0, RegSize::R64)).modrm_rm_direct(self.1).modrm_opext(0b101).imm8(self.2 as i8).encode(),
            (fmt.write_fmt(core::format_args!("shr {}, 0x{:x}", self.1.name_from(self.0), self.2))),

        // https://www.felixcloutier.com/x86/rcl:rcr:rol:ror
        ror_imm(RegSize, Reg, u8) =>
            Inst::new(0xc1).rex_64b_if(matches!(self.0, RegSize::R64)).modrm_rm_direct(self.1).modrm_opext(0b001).imm8(self.2 as i8).encode(),
            (fmt.write_fmt(core::format_args!("ror {}, 0x{:x}", self.1.name_from(self.0), self.2))),

        // https://www.felixcloutier.com/x86/test
        test(RegSize, Reg, Reg) =>
            Inst::new(0x85).rex_64b_if(matches!(self.0, RegSize::R64)).modrm_rm_direct(self.1).modrm_reg(self.2).encode(),
            (fmt.write_fmt(core::format_args!("test {}, {}", self.1.name_from(self.0), self.2.name_from(self.0)))),

        test_imm(RegSize, Reg, i32) =>
            Inst::new(0xf7).imm32(self.2).rex_64b_if(matches!(self.0, RegSize::R64)).modrm_rm_direct(self.1).encode(),
            ({
                match self.0 {
                    RegSize::R64 => fmt.write_fmt(core::format_args!("test {}, 0x{:x}", self.1, self.2 as i64)),
                    RegSize::R32 => fmt.write_fmt(core::format_args!("test {}, 0x{:x}", self.1.name32(), self.2)),
                }
            }),

        // https://www.felixcloutier.com/x86/imul
        imul(RegSize, Reg, Reg) =>
            Inst::new(0xaf).op_alt().rex_64b_if(matches!(self.0, RegSize::R64)).modrm_reg(self.1).modrm_rm_direct(self.2).encode(),
            (fmt.write_fmt(core::format_args!("imul {}, {}", self.1.name_from(self.0), self.2.name_from(self.0)))),

        // https://www.felixcloutier.com/x86/div
        div(RegSize, Reg) =>
            Inst::new(0xf7).modrm_opext(0b110).rex_64b_if(matches!(self.0, RegSize::R64)).modrm_rm_direct(self.1).encode(),
            (fmt.write_fmt(core::format_args!("div {}", self.1.name_from(self.0)))),

        // https://www.felixcloutier.com/x86/div
        idiv(RegSize, Reg) =>
            Inst::new(0xf7).modrm_opext(0b111).rex_64b_if(matches!(self.0, RegSize::R64)).modrm_rm_direct(self.1).encode(),
            (fmt.write_fmt(core::format_args!("idiv {}", self.1.name_from(self.0)))),

        // https://www.felixcloutier.com/x86/setcc
        setcc(Condition, Reg) =>
            {
                Inst::new(0x90 | self.0 as u8)
                    .rex_if(!matches!(self.1, Reg::rax | Reg::rcx | Reg::rdx | Reg::rbx))
                    .op_alt()
                    .modrm_rm_direct(self.1)
                    .encode()
            },
            (fmt.write_fmt(core::format_args!("set{} {}", self.0.suffix(), self.1.name8()))),

        // https://www.felixcloutier.com/x86/lea
        lea(RegSize, Reg, RegSize, Reg, i32) =>
            {
                Inst::new(0x8d)
                    .rex_64b_if(matches!(self.0, RegSize::R64))
                    .override_addr_size_if(matches!(self.2, RegSize::R32))
                    .modrm_rm_indirect(self.3, self.4)
                    .modrm_reg(self.1)
                    .encode()
            },
            ({
                fmt.write_fmt(core::format_args!("lea {}, [{}", self.1.name_from(self.0), self.3.name_from(self.2)))?;
                if self.4 != 0 {
                    if self.4 > 0 {
                        fmt.write_fmt(core::format_args!("+0x{:x}", self.4))?;
                    } else {
                        fmt.write_fmt(core::format_args!("-0x{:x}", -(self.4 as i64)))?;
                    }
                }
                fmt.write_fmt(core::format_args!("]"))
            }),

        lea_rip(RegSize, Reg, i32) =>
            {
                Inst::new(0x8d)
                    .rex_64b_if(matches!(self.0, RegSize::R64))
                    .modrm_rm_rip(self.2)
                    .modrm_reg(self.1)
                    .encode()
            },
            ({
                fmt.write_fmt(core::format_args!("lea {}, [rip", self.1.name_from(self.0)))?;
                if self.2 != 0 {
                    if self.2 > 0 {
                        fmt.write_fmt(core::format_args!("+0x{:x}", self.2))?;
                    } else {
                        fmt.write_fmt(core::format_args!("-0x{:x}", -(self.2 as i64)))?;
                    }
                }
                fmt.write_fmt(core::format_args!("]"))
            }),

        // https://www.felixcloutier.com/x86/call
        call_reg(Reg) =>
            Inst::new(0xff).modrm_rm_direct(self.0).modrm_opext(0b010).encode(),
            (fmt.write_fmt(core::format_args!("call {}", self.0))),

        call_rel32(i32) =>
            Inst::new(0xe8).imm32(self.0).encode(),
            (fmt.write_fmt(core::format_args!("call 0x{:x}", (self.0 as i64).wrapping_add(5)))),

        // https://www.felixcloutier.com/x86/jmp
        jmp_reg(Reg) =>
            Inst::new(0xff).modrm_rm_direct(self.0).modrm_opext(0b100).encode(),
            (fmt.write_fmt(core::format_args!("jmp {}", self.0))),

        jmp_rel8(i8) =>
            Inst::new(0xeb).imm8(self.0).encode(),
            (fmt.write_fmt(core::format_args!("jmp short 0x{:x}", (self.0 as i64).wrapping_add(2)))),

        jmp_rel32(i32) =>
            Inst::new(0xe9).imm32(self.0).encode(),
            (fmt.write_fmt(core::format_args!("jmp 0x{:x}", (self.0 as i64).wrapping_add(5)))),

        // https://www.felixcloutier.com/x86/jcc
        jcc_rel8(Condition, i8) =>
            Inst::new(0x70 | self.0 as u8).imm8(self.1).encode(),
            (fmt.write_fmt(core::format_args!("j{} short 0x{:x}", self.0.suffix(), (self.1 as i64).wrapping_add(2)))),

        jcc_rel32(Condition, i32) =>
            Inst::new(0x80 | self.0 as u8).op_alt().imm32(self.1).encode(),
            (fmt.write_fmt(core::format_args!("j{} near 0x{:x}", self.0.suffix(), (self.1 as i64).wrapping_add(6)))),
    }

    #[derive(Copy, Clone, PartialEq, Eq, Debug)]
    pub struct jmp_label8(pub Label);
    impl jmp_label8 {
        const fn encode_const(self) -> EncInst {
            jmp_rel8(0).encode_const()
        }
    }

    impl core::fmt::Display for jmp_label8 {
        fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
            fmt.write_fmt(core::format_args!("jmp {}", self.0))
        }
    }

    impl crate::Instruction for jmp_label8 {
        fn encode(self) -> EncInst {
            self.encode_const()
        }

        fn target_fixup(self) -> Option<(Label, u8, u8)> {
            Some((self.0, 1, 1))
        }
    }

    #[derive(Copy, Clone, PartialEq, Eq, Debug)]
    pub struct jmp_label32(pub Label);
    impl jmp_label32 {
        const fn encode_const(self) -> EncInst {
            jmp_rel32(0).encode_const()
        }
    }

    impl core::fmt::Display for jmp_label32 {
        fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
            fmt.write_fmt(core::format_args!("jmp {}", self.0))
        }
    }

    impl crate::Instruction for jmp_label32 {
        fn encode(self) -> EncInst {
            self.encode_const()
        }

        fn target_fixup(self) -> Option<(Label, u8, u8)> {
            Some((self.0, 1, 4))
        }
    }

    #[derive(Copy, Clone, PartialEq, Eq, Debug)]
    pub struct call_label32(pub Label);
    impl call_label32 {
        const fn encode_const(self) -> EncInst {
            call_rel32(0).encode_const()
        }
    }

    impl core::fmt::Display for call_label32 {
        fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
            fmt.write_fmt(core::format_args!("call {}", self.0))
        }
    }

    impl crate::Instruction for call_label32 {
        fn encode(self) -> EncInst {
            self.encode_const()
        }

        fn target_fixup(self) -> Option<(Label, u8, u8)> {
            Some((self.0, 1, 4))
        }
    }

    #[derive(Copy, Clone, PartialEq, Eq, Debug)]
    pub struct jcc_label8(pub Condition, pub Label);
    impl jcc_label8 {
        const fn encode_const(self) -> EncInst {
            jcc_rel8(self.0, 0).encode_const()
        }
    }

    impl core::fmt::Display for jcc_label8 {
        fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
            fmt.write_fmt(core::format_args!("j{} {}", self.0.suffix(), self.1))
        }
    }

    impl crate::Instruction for jcc_label8 {
        fn encode(self) -> EncInst {
            self.encode_const()
        }

        fn target_fixup(self) -> Option<(Label, u8, u8)> {
            Some((self.1, 1, 1))
        }
    }

    #[derive(Copy, Clone, PartialEq, Eq, Debug)]
    pub struct jcc_label32(pub Condition, pub Label);
    impl jcc_label32 {
        const fn encode_const(self) -> EncInst {
            jcc_rel32(self.0, 0).encode_const()
        }
    }

    impl core::fmt::Display for jcc_label32 {
        fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
            fmt.write_fmt(core::format_args!("j{} {}", self.0.suffix(), self.1))
        }
    }

    impl crate::Instruction for jcc_label32 {
        fn encode(self) -> EncInst {
            self.encode_const()
        }

        fn target_fixup(self) -> Option<(Label, u8, u8)> {
            Some((self.1, 2, 4))
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Condition {
    Overflow = 0,
    NotOverflow = 1,
    Below = 2,        // For unsigned values.
    AboveOrEqual = 3, // For unsigned values.
    Equal = 4,
    NotEqual = 5,
    BelowOrEqual = 6, // For unsigned values.
    Above = 7,        // For unsigned values.
    Sign = 8,
    NotSign = 9,
    Parity = 10,
    NotParity = 11,
    Less = 12,           // For signed values.
    GreaterOrEqual = 13, // For signed values.
    LessOrEqual = 14,    // For signed values.
    Greater = 15,        // For signed values.
}

impl Condition {
    const fn suffix(self) -> &'static str {
        use Condition::*;
        match self {
            Overflow => "o",
            NotOverflow => "no",
            Below => "b",
            AboveOrEqual => "ae",
            Equal => "e",
            NotEqual => "ne",
            BelowOrEqual => "be",
            Above => "a",
            Sign => "s",
            NotSign => "ns",
            Parity => "p",
            NotParity => "np",
            Less => "l",
            GreaterOrEqual => "ge",
            LessOrEqual => "le",
            Greater => "g",
        }
    }
}

#[cfg(test)]
impl tests::GenerateTestValues for Condition {
    fn generate_test_values(cb: impl FnMut(Self)) {
        use Condition::*;
        [
            Overflow,
            NotOverflow,
            Below,
            AboveOrEqual,
            Equal,
            NotEqual,
            BelowOrEqual,
            Above,
            Sign,
            NotSign,
            Parity,
            NotParity,
            Less,
            GreaterOrEqual,
            LessOrEqual,
            Greater,
        ]
        .into_iter()
        .for_each(cb);
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum RegSize {
    R32,
    R64,
}

#[cfg(test)]
impl tests::GenerateTestValues for RegSize {
    fn generate_test_values(cb: impl FnMut(Self)) {
        use RegSize::*;
        [R32, R64].into_iter().for_each(cb);
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub enum LoadKind {
    U8,
    U16,
    U32,
    #[default]
    U64,
    I8,
    I16,
    I32,
}

#[cfg(test)]
impl tests::GenerateTestValues for LoadKind {
    fn generate_test_values(cb: impl FnMut(Self)) {
        use LoadKind::*;
        [U8, U16, U32, U64, I8, I16, I32].into_iter().for_each(cb);
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub enum StoreKind {
    U8,
    U16,
    U32,
    #[default]
    U64,
}

#[cfg(test)]
impl tests::GenerateTestValues for StoreKind {
    fn generate_test_values(cb: impl FnMut(Self)) {
        use StoreKind::*;
        [U8, U16, U32, U64].into_iter().for_each(cb);
    }
}

#[cfg(test)]
mod tests {
    #[cfg(test)]
    pub trait GenerateTestValues: Copy {
        fn generate_test_values(cb: impl FnMut(Self));
    }

    #[cfg(test)]
    impl GenerateTestValues for super::Reg {
        fn generate_test_values(cb: impl FnMut(Self)) {
            use super::Reg::*;
            [rax, rcx, rdx, rbx, rsp, rbp, rsi, rdi, r8, r9, r10, r11, r12, r13, r14, r15]
                .into_iter()
                .for_each(cb);
        }
    }

    #[cfg(test)]
    impl<T> GenerateTestValues for Option<T>
    where
        T: GenerateTestValues,
    {
        fn generate_test_values(mut cb: impl FnMut(Self)) {
            cb(None);
            T::generate_test_values(move |value| cb(Some(value)))
        }
    }

    #[cfg(test)]
    impl GenerateTestValues for u8 {
        fn generate_test_values(cb: impl FnMut(Self)) {
            [0, 0x7f, 0x80, 0xff].into_iter().for_each(cb);
        }
    }

    #[cfg(test)]
    impl GenerateTestValues for i8 {
        fn generate_test_values(cb: impl FnMut(Self)) {
            [0, 0x1, 0x7f, -0x1, -127, -128].into_iter().for_each(cb);
        }
    }

    #[cfg(test)]
    impl GenerateTestValues for u16 {
        fn generate_test_values(cb: impl FnMut(Self)) {
            [0, 0x7f, 0x80, 0xff, 0x7fff, 0x8000, 0xffff].into_iter().for_each(cb);
        }
    }

    #[cfg(test)]
    impl GenerateTestValues for u32 {
        fn generate_test_values(cb: impl FnMut(Self)) {
            [0, 0x7f, 0x80, 0xff, 0x7fff, 0x8000, 0xffff, 0x7fffffff, 0x80000000, 0xffffffff]
                .into_iter()
                .for_each(cb);
        }
    }

    #[cfg(test)]
    impl GenerateTestValues for i32 {
        fn generate_test_values(cb: impl FnMut(Self)) {
            [
                0,
                0x1,
                0x7f,
                0x80,
                0xff,
                0x7fff,
                0x8000,
                0xffff,
                0x7fffffff,
                -0x1,
                -128,
                -129,
                -255,
                -256,
                -32768,
                -32769,
                -2147483648,
            ]
            .into_iter()
            .for_each(cb);
        }
    }

    #[cfg(test)]
    impl GenerateTestValues for u64 {
        fn generate_test_values(cb: impl FnMut(Self)) {
            [
                0,
                0x7f,
                0x80,
                0xff,
                0x7fff,
                0x8000,
                0xffff,
                0x7fffffff,
                0x80000000,
                0xffffffff,
                0x7fffffffffffffff,
                0x8000000000000000,
                0xffffffffffffffff,
            ]
            .into_iter()
            .for_each(cb);
        }
    }

    fn disassemble(mut code: &[u8]) -> String {
        use iced_x86::Formatter;
        use std::fmt::Write;

        let mut output = String::new();
        let mut formatter = iced_x86::NasmFormatter::new();
        formatter.options_mut().set_space_after_operand_separator(true);
        formatter.options_mut().set_hex_prefix("0x");
        formatter.options_mut().set_hex_suffix("");
        formatter.options_mut().set_uppercase_hex(false);
        formatter.options_mut().set_small_hex_numbers_in_decimal(false);
        formatter.options_mut().set_show_useless_prefixes(true);
        formatter.options_mut().set_branch_leading_zeros(false);
        formatter.options_mut().set_rip_relative_addresses(true);
        let code_origin = 0;
        let mut position = 0;
        loop {
            let mut decoder = iced_x86::Decoder::with_ip(64, code, code_origin, iced_x86::DecoderOptions::NONE);
            if !decoder.can_decode() {
                break;
            }
            let mut instruction = iced_x86::Instruction::default();
            decoder.decode_out(&mut instruction);

            write!(&mut output, "{:08x} ", position).unwrap();
            let start_index = (instruction.ip() - code_origin) as usize;
            let instr_bytes = &code[start_index..start_index + instruction.len()];
            for b in instr_bytes.iter() {
                write!(&mut output, "{:02x}", b).unwrap();
            }
            write!(&mut output, " ").unwrap();

            formatter.format(&instruction, &mut output);
            writeln!(&mut output).unwrap();
            code = &code[instruction.len()..];
            position += instruction.len();
        }

        output.pop();
        output
    }

    macro_rules! test_asm {
        ($($inst:expr),+) => {{
            use core::fmt::Write;
            let mut asm = crate::Assembler::new();
            let mut ranges = Vec::new();
            $(
                {
                    let inst = $inst;
                    let position = asm.len();
                    asm.push(inst);
                    let range = position..asm.len();
                    ranges.push((inst, range));
                }
            )+

            let code = asm.finalize();
            let mut disassembly_1 = String::new();
            let mut position = 0;
            for (inst, range) in ranges {
                write!(&mut disassembly_1, "{:08x} ", position).unwrap();
                for &b in &code[range.clone()] {
                    write!(&mut disassembly_1, "{:02x}", b).unwrap();
                }
                position += range.len();
                writeln!(&mut disassembly_1, " {}", inst).unwrap();
            }

            disassembly_1.pop();
            let disassembly_2 = disassemble(&code);

            assert_eq!(disassembly_1, disassembly_2);
        }};
    }

    macro_rules! generate_tests {
        ($($inst_name:ident,)+) => {
            $(
                #[test]
                fn $inst_name() {
                    <super::inst::$inst_name as GenerateTestValues>::generate_test_values(|inst| test_asm!(inst));
                }
            )+
        }
    }

    generate_tests! {
        add_imm,
        add,
        and_imm,
        and,
        bts,
        call_reg,
        call_rel32,
        cmp_imm,
        cmp,
        div,
        endbr64,
        idiv,
        imul,
        inc,
        jcc_rel32,
        jcc_rel8,
        jmp_reg,
        jmp_rel32,
        jmp_rel8,
        lea_rip,
        lea,
        load_abs,
        load_indirect,
        load32_imm,
        load64_imm,
        mov,
        movsxd_32_to_64,
        neg,
        nop,
        nop10,
        nop11,
        nop2,
        nop3,
        nop4,
        nop5,
        nop6,
        nop7,
        nop8,
        nop9,
        not,
        or_imm,
        or,
        pop,
        push,
        ret,
        ror_imm,
        sar_cl,
        sar_imm,
        setcc,
        shl_cl,
        shl_imm,
        shr_cl,
        shr_imm,
        store_abs,
        store_indirect,
        store16_abs_imm,
        store16_indirect_imm,
        store32_abs_imm,
        store32_indirect_imm,
        store8_abs_imm,
        store8_indirect_imm,
        sub_imm,
        sub,
        syscall,
        test_imm,
        test,
        ud2,
        xor_imm,
        xor,
    }

    #[test]
    fn jmp_label8_infinite_loop() {
        use super::inst::*;
        let mut asm = crate::Assembler::new();
        let label = asm.forward_declare_label();
        asm.push_with_label(label, jmp_label8(label));
        let disassembly = disassemble(asm.finalize());
        assert_eq!(disassembly, "00000000 ebfe jmp short 0x0");
    }

    #[test]
    fn jmp_label32_infinite_loop() {
        use super::inst::*;
        let mut asm = crate::Assembler::new();
        let label = asm.forward_declare_label();
        asm.push_with_label(label, jmp_label32(label));
        let disassembly = disassemble(asm.finalize());
        assert_eq!(disassembly, "00000000 e9fbffffff jmp 0x0");
    }

    #[test]
    fn call_label32_infinite_loop() {
        use super::inst::*;
        let mut asm = crate::Assembler::new();
        let label = asm.forward_declare_label();
        asm.push_with_label(label, call_label32(label));
        let disassembly = disassemble(asm.finalize());
        assert_eq!(disassembly, "00000000 e8fbffffff call 0x0");
    }

    #[test]
    fn jcc_label8_infinite_loop() {
        use super::inst::*;
        super::Condition::generate_test_values(|cond| {
            let mut asm = crate::Assembler::new();
            let label = asm.forward_declare_label();
            asm.push_with_label(label, jcc_label8(cond, label));
            let disassembly = disassemble(asm.finalize());
            assert_eq!(
                disassembly,
                format!("00000000 {:02x}fe j{} short 0x0", 0x70 + cond as u8, cond.suffix())
            );
        });
    }

    #[test]
    fn jcc_label8_jump_forward() {
        use super::inst::*;
        super::Condition::generate_test_values(|cond| {
            let mut asm = crate::Assembler::new();
            let label = asm.forward_declare_label();
            asm.push(jcc_label8(cond, label));
            asm.push_with_label(label, nop());
            let disassembly = disassemble(asm.finalize());
            assert_eq!(
                disassembly,
                format!(
                    concat!("00000000 {:02x}00 j{} short 0x2\n", "00000002 90 nop",),
                    0x70 + cond as u8,
                    cond.suffix()
                )
            );
        })
    }

    #[test]
    fn jcc_label8_jump_backward() {
        use super::inst::*;
        super::Condition::generate_test_values(|cond| {
            let mut asm = crate::Assembler::new();
            let label = asm.forward_declare_label();
            asm.push_with_label(label, nop());
            asm.push(jcc_label8(cond, label));
            let disassembly = disassemble(asm.finalize());
            assert_eq!(
                disassembly,
                format!(
                    concat!("00000000 90 nop\n", "00000001 {:02x}fd j{} short 0xffffffffffffffff",),
                    0x70 + cond as u8,
                    cond.suffix()
                )
            );
        });
    }

    #[test]
    fn jcc_label32_jump_forward() {
        use super::inst::*;
        super::Condition::generate_test_values(|cond| {
            let mut asm = crate::Assembler::new();
            let label = asm.forward_declare_label();
            asm.push(jcc_label32(cond, label));
            asm.push_with_label(label, nop());
            let disassembly = disassemble(asm.finalize());
            assert_eq!(
                disassembly,
                format!(
                    concat!("00000000 0f{:02x}00000000 j{} near 0x6\n", "00000006 90 nop",),
                    0x80 + cond as u8,
                    cond.suffix()
                )
            );
        });
    }
}
