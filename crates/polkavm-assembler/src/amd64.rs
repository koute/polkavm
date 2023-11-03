#![allow(non_camel_case_types)]

use crate::assembler::{EncInst, Label};

/// The REX prefix.
const REX: u8 = 0x40;
const REX_64B_OP: u8 = REX | (1 << 3);
const REX_EXT_MODRM_REG: u8 = REX | (1 << 2);
const REX_EXT_MODRM_SIB_INDEX: u8 = REX | (1 << 1);
const REX_EXT_MODRM_RM: u8 = REX | (1 << 0);

const PREFIX_OVERRIDE_SEGMENT_FS: u8 = 0x64;
const PREFIX_OVERRIDE_SEGMENT_GS: u8 = 0x65;
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

    pub const fn name_from_size(self, kind: Size) -> &'static str {
        match kind {
            Size::U64 => self.name(),
            Size::U32 => self.name32(),
            Size::U16 => self.name16(),
            Size::U8 => self.name8(),
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

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum RegIndex {
    rax = 0,
    rcx = 1,
    rdx = 2,
    rbx = 3,
    // No `rsp`.
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

impl From<RegIndex> for Reg {
    fn from(reg: RegIndex) -> Reg {
        reg.into_reg()
    }
}

impl RegIndex {
    pub const fn into_reg(self) -> Reg {
        match self {
            RegIndex::rax => Reg::rax,
            RegIndex::rcx => Reg::rcx,
            RegIndex::rdx => Reg::rdx,
            RegIndex::rbx => Reg::rbx,
            RegIndex::rbp => Reg::rbp,
            RegIndex::rsi => Reg::rsi,
            RegIndex::rdi => Reg::rdi,
            RegIndex::r8 => Reg::r8,
            RegIndex::r9 => Reg::r9,
            RegIndex::r10 => Reg::r10,
            RegIndex::r11 => Reg::r11,
            RegIndex::r12 => Reg::r12,
            RegIndex::r13 => Reg::r13,
            RegIndex::r14 => Reg::r14,
            RegIndex::r15 => Reg::r15,
        }
    }
    pub const fn name(self) -> &'static str {
        self.into_reg().name()
    }

    pub const fn name32(self) -> &'static str {
        self.into_reg().name32()
    }

    pub const fn name16(self) -> &'static str {
        self.into_reg().name16()
    }

    pub const fn name8(self) -> &'static str {
        self.into_reg().name8()
    }

    pub const fn name_from(self, size: RegSize) -> &'static str {
        match size {
            RegSize::R64 => self.name(),
            RegSize::R32 => self.name32(),
        }
    }
}

impl core::fmt::Display for RegIndex {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
        let reg: Reg = (*self).into();
        reg.fmt(fmt)
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum SegReg {
    fs,
    gs,
}

impl core::fmt::Display for SegReg {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
        let name = match self {
            Self::fs => "fs",
            Self::gs => "gs",
        };
        fmt.write_str(name)
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Scale {
    x1 = 0,
    x2 = 1,
    x4 = 2,
    x8 = 3,
}

#[derive(Copy, Clone)]
enum RawImm {
    Imm8(u8),
    Imm16(u16),
    Imm32(u32),
}

impl RawImm {
    const fn append_into(self, enc: EncInst) -> EncInst {
        match self {
            RawImm::Imm8(value) => enc.append(value),
            RawImm::Imm16(value) => {
                let xs = value.to_le_bytes();
                enc.append_array([xs[0], xs[1]])
            }
            RawImm::Imm32(value) => {
                let xs = value.to_le_bytes();
                enc.append_array([xs[0], xs[1], xs[2], xs[3]])
            }
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum MemOp {
    /// [segment:base + offset]
    BaseOffset(Option<SegReg>, RegSize, Reg, i32),
    /// [segment:base + index * scale + offset]
    BaseIndexScaleOffset(Option<SegReg>, RegSize, Reg, RegIndex, Scale, i32),
    /// [segment:base * scale + offset]
    IndexScaleOffset(Option<SegReg>, RegSize, RegIndex, Scale, i32),
    /// [segment:offset]
    Offset(Option<SegReg>, i32),
    /// [segment:rip + offset]
    RipRelative(Option<SegReg>, i32),
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum RegMem {
    Reg(Reg),
    Mem(MemOp),
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Operands {
    RegMem_Reg(Size, RegMem, Reg),
    Reg_RegMem(Size, Reg, RegMem),
    RegMem_Imm(RegMem, ImmKind),
}

impl MemOp {
    const fn needs_rex(self) -> bool {
        match self {
            MemOp::BaseOffset(_, _, base, _) => base.needs_rex(),
            MemOp::BaseIndexScaleOffset(_, _, base, index, _, _) => base.needs_rex() || index.into_reg().needs_rex(),
            MemOp::IndexScaleOffset(_, _, index, _, _) => index.into_reg().needs_rex(),
            MemOp::Offset(..) => false,
            MemOp::RipRelative(..) => false,
        }
    }

    const fn simplify(self) -> Self {
        match self {
            // Use a more compact encoding if possible.
            MemOp::IndexScaleOffset(segment, reg_size, index, Scale::x1, offset) => {
                MemOp::BaseOffset(segment, reg_size, index.into_reg(), offset)
            }
            operand => operand,
        }
    }
}

impl core::fmt::Display for MemOp {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
        let (segment, base, index, offset) = match self.simplify() {
            MemOp::BaseOffset(segment, reg_size, base, offset) => (segment, Some((reg_size, base)), None, offset),
            MemOp::BaseIndexScaleOffset(segment, reg_size, base, index, scale, offset) => {
                (segment, Some((reg_size, base)), Some((reg_size, index, scale)), offset)
            }
            MemOp::IndexScaleOffset(segment, reg_size, index, scale, offset) => (segment, None, Some((reg_size, index, scale)), offset),
            MemOp::Offset(segment, offset) => (segment, None, None, offset),
            MemOp::RipRelative(segment, offset) => {
                fmt.write_str("[")?;
                if let Some(segment) = segment {
                    fmt.write_fmt(core::format_args!("{}:", segment))?;
                }

                fmt.write_str("rip")?;
                if offset != 0 {
                    if offset > 0 {
                        fmt.write_fmt(core::format_args!("+0x{:x}", offset))?;
                    } else {
                        fmt.write_fmt(core::format_args!("-0x{:x}", -(offset as i64)))?;
                    }
                }

                return fmt.write_str("]");
            }
        };

        fmt.write_str("[")?;
        if let Some(segment) = segment {
            fmt.write_fmt(core::format_args!("{}:", segment))?;
        }

        if let Some((reg_size, base)) = base {
            base.name_from(reg_size).fmt(fmt)?;
        }

        if let Some((reg_size, index, scale)) = index {
            if base.is_some() {
                fmt.write_str("+")?;
            }

            index.name_from(reg_size).fmt(fmt)?;
            match scale {
                Scale::x1 if base.is_some() => {}
                Scale::x1 => fmt.write_str("*1")?,
                Scale::x2 => fmt.write_str("*2")?,
                Scale::x4 => fmt.write_str("*4")?,
                Scale::x8 => fmt.write_str("*8")?,
            }
        }

        if offset != 0 || (base.is_none() && index.is_none()) {
            if base.is_some() || index.is_some() {
                if offset > 0 {
                    fmt.write_fmt(core::format_args!("+0x{:x}", offset))?;
                } else {
                    fmt.write_fmt(core::format_args!("-0x{:x}", -(offset as i64)))?;
                }
            } else {
                fmt.write_fmt(core::format_args!("0x{:x}", offset as i64))?;
            }
        }

        fmt.write_str("]")
    }
}

impl RegMem {
    fn display_without_prefix(self, size: Size) -> impl core::fmt::Display {
        struct Impl(Size, RegMem);

        impl core::fmt::Display for Impl {
            fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
                match self.1 {
                    RegMem::Reg(reg) => fmt.write_fmt(core::format_args!("{}", reg.name_from_size(self.0))),
                    RegMem::Mem(mem) => fmt.write_fmt(core::format_args!("{}", mem)),
                }
            }
        }

        Impl(size, self)
    }

    fn display(self, size: Size) -> impl core::fmt::Display {
        struct Impl(Size, RegMem);

        impl core::fmt::Display for Impl {
            fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
                match self.1 {
                    RegMem::Reg(reg) => fmt.write_fmt(core::format_args!("{}", reg.name_from_size(self.0))),
                    RegMem::Mem(mem) => fmt.write_fmt(core::format_args!("{} {}", self.0.name(), mem)),
                }
            }
        }

        Impl(size, self)
    }
}

impl From<Reg> for RegMem {
    fn from(reg: Reg) -> Self {
        RegMem::Reg(reg)
    }
}

impl From<MemOp> for RegMem {
    fn from(mem: MemOp) -> Self {
        RegMem::Mem(mem)
    }
}

struct Inst {
    override_op_size: bool,
    override_addr_size: bool,
    op_alt: bool,
    force_enable_modrm: bool,
    rex: u8,
    opcode: u8,
    modrm: u8,
    sib: u8,
    displacement: Option<RawImm>,
    immediate: Option<RawImm>,
    override_segment: Option<SegReg>,
}

// See: https://www-user.tu-chemnitz.de/~heha/hsn/chm/x86.chm/x64.htm
impl Inst {
    const fn new(opcode: u8) -> Self {
        Inst {
            override_op_size: false,
            override_addr_size: false,
            op_alt: false,
            force_enable_modrm: false,
            rex: 0,
            opcode,
            modrm: 0,
            sib: 0,
            displacement: None,
            immediate: None,
            override_segment: None,
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
        self
    }

    const fn regmem(self, operand: RegMem) -> Self {
        match operand {
            RegMem::Reg(reg) => self.modrm_rm_direct(reg),
            RegMem::Mem(mem) => self.mem(mem),
        }
    }

    const fn mem(mut self, operand: MemOp) -> Self {
        match operand.simplify() {
            MemOp::BaseOffset(segment, reg_size, base, offset) => {
                self.force_enable_modrm = true;

                if base.needs_rex() {
                    self.rex |= REX_EXT_MODRM_RM;
                }

                if matches!(base, Reg::rsp | Reg::r12) {
                    self.sib = 0b00100100;
                }

                self.modrm |= base.modrm_rm_bits();

                if offset != 0 || matches!(base, Reg::rbp | Reg::r13) {
                    if offset <= i8::MAX as i32 && offset >= i8::MIN as i32 {
                        self.modrm |= 0b01000000;
                        self.displacement = Some(RawImm::Imm8(offset as u8));
                    } else {
                        self.modrm |= 0b10000000;
                        self.displacement = Some(RawImm::Imm32(offset as u32));
                    }
                }

                self.override_segment = segment;
                self.override_addr_size_if(matches!(reg_size, RegSize::R32))
            }
            MemOp::BaseIndexScaleOffset(segment, reg_size, base, index, scale, offset) => {
                if base.needs_rex() {
                    self.rex |= REX_EXT_MODRM_RM;
                }

                if index.into_reg().needs_rex() {
                    self.rex |= REX_EXT_MODRM_SIB_INDEX;
                }

                self.modrm |= 0b00000100;
                self.sib |= index.into_reg().modrm_reg_bits();
                self.sib |= base.modrm_rm_bits();
                self.sib |= ((scale as usize) << 6) as u8;

                if offset != 0 || matches!(base, Reg::rbp | Reg::r13) {
                    if offset <= i8::MAX as i32 && offset >= i8::MIN as i32 {
                        self.modrm |= 0b01000000;
                        self.displacement = Some(RawImm::Imm8(offset as u8));
                    } else {
                        self.modrm |= 0b10000000;
                        self.displacement = Some(RawImm::Imm32(offset as u32));
                    }
                }

                self.override_segment = segment;
                self.override_addr_size_if(matches!(reg_size, RegSize::R32))
            }
            MemOp::IndexScaleOffset(segment, reg_size, index, scale, offset) => {
                if index.into_reg().needs_rex() {
                    self.rex |= REX_EXT_MODRM_SIB_INDEX;
                }

                self.modrm |= 0b00000100;
                self.sib |= index.into_reg().modrm_reg_bits();
                self.sib |= 0b00000101;
                self.sib |= ((scale as usize) << 6) as u8;
                self.displacement = Some(RawImm::Imm32(offset as u32));
                self.override_segment = segment;
                self.override_addr_size_if(matches!(reg_size, RegSize::R32))
            }
            MemOp::Offset(segment, offset) => {
                self.modrm |= 0b00000100;
                self.sib |= 0b00100101;
                self.displacement = Some(RawImm::Imm32(offset as u32));
                self.override_segment = segment;
                self
            }
            MemOp::RipRelative(segment, offset) => {
                self.modrm |= 0b00000101;
                self.displacement = Some(RawImm::Imm32(offset as u32));
                self.override_segment = segment;
                self
            }
        }
    }

    const fn modrm_reg(mut self, value: Reg) -> Self {
        if value.needs_rex() {
            self.rex |= REX_EXT_MODRM_REG;
        }
        self.modrm |= value.modrm_reg_bits();
        self.force_enable_modrm = true;
        self
    }

    const fn modrm_opext(mut self, ext: u8) -> Self {
        self.modrm |= ext << 3;
        self.force_enable_modrm = true;
        self
    }

    const fn imm8(mut self, value: u8) -> Self {
        self.immediate = Some(RawImm::Imm8(value));
        self
    }

    const fn imm16(mut self, value: u16) -> Self {
        self.immediate = Some(RawImm::Imm16(value));
        self
    }

    const fn imm32(mut self, value: u32) -> Self {
        self.immediate = Some(RawImm::Imm32(value));
        self
    }

    const fn encode(self) -> EncInst {
        let mut enc = EncInst::new();
        match self.override_segment {
            Some(SegReg::fs) => enc = enc.append(PREFIX_OVERRIDE_SEGMENT_FS),
            Some(SegReg::gs) => enc = enc.append(PREFIX_OVERRIDE_SEGMENT_GS),
            None => {}
        }

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

        if self.modrm != 0 || self.force_enable_modrm {
            enc = enc.append(self.modrm);
            if self.modrm & 0b11000000 != 0b11000000 && self.modrm & 0b111 == 0b100 {
                enc = enc.append(self.sib);
            }
        }

        if let Some(displacement) = self.displacement {
            enc = displacement.append_into(enc);
        }

        if let Some(immediate) = self.immediate {
            enc = immediate.append_into(enc);
        }

        enc
    }
}

macro_rules! impl_inst {
    (@generate_test_values $cb:expr, $name:ident, $arg0:ty, $arg1:ty, $arg2:ty, $arg3:ty, $arg4:ty, $arg5:ty) => {
        <$arg0 as super::tests::GenerateTestValues>::generate_test_values(|arg0|
            <$arg1 as super::tests::GenerateTestValues>::generate_test_values(|arg1|
                <$arg2 as super::tests::GenerateTestValues>::generate_test_values(|arg2|
                    <$arg3 as super::tests::GenerateTestValues>::generate_test_values(|arg3|
                        <$arg4 as super::tests::GenerateTestValues>::generate_test_values(|arg4|
                            <$arg5 as super::tests::GenerateTestValues>::generate_test_values(|arg5|
                                $cb($name(arg0, arg1, arg2, arg3, arg4, arg5))
                            )
                        )
                    )
                )
            )
        )
    };

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

    (@impl |$self:ident, $fmt:ident| $($name:ident($($arg:ty),*) => $body:expr, ($fmt_body:expr),)+) => {
        pub(crate) mod types {
            use super::*;
            $(
                #[derive(Copy, Clone, PartialEq, Eq, Debug)]
                pub struct $name($(pub $arg),*);
                impl $name {
                    pub(crate) const fn encode_const($self) -> EncInst {
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
        }
    };

    (@conv_ty i8) => {
        i8
    };

    (@conv_ty i32) => {
        i32
    };

    (@conv_ty $type:ty) => {
        impl Into<$type>
    };

    (@ctor_impl $name:ident, $(($arg_name:ident: $arg_ty:tt)),*) => {
        pub fn $name($($arg_name: impl_inst!(@conv_ty $arg_ty)),*) -> types::$name {
            self::types::$name($($arg_name.into()),*)
        }
    };

    (@ctor $name:ident,) => {
        impl_inst!(@ctor_impl $name,);
    };

    (@ctor $name:ident, $a0:tt) => {
        impl_inst!(@ctor_impl $name, (a0: $a0));
    };

    (@ctor $name:ident, $a0:tt, $a1:tt) => {
        impl_inst!(@ctor_impl $name, (a0: $a0), (a1: $a1));
    };

    (@ctor $name:ident, $a0:tt, $a1:tt, $a2:tt) => {
        impl_inst!(@ctor_impl $name, (a0: $a0), (a1: $a1), (a2: $a2));
    };

    (@ctor $name:ident, $a0:tt, $a1:tt, $a2:tt, $a3:tt) => {
        impl_inst!(@ctor_impl $name, (a0: $a0), (a1: $a1), (a2: $a2), (a3: $a3));
    };

    (|$self:ident, $fmt:ident| $($name:ident($($arg:tt),*) => $body:expr, ($fmt_body:expr),)+) => {
        impl_inst!(@impl |$self, $fmt| $($name($($arg),*) => $body, ($fmt_body),)+);
        $(
            impl_inst!(@ctor $name, $($arg),*);
        )+
    };
}

pub mod addr {
    use super::*;

    impl core::ops::Add<i32> for Reg {
        type Output = (Reg, i32);
        fn add(self, offset: i32) -> Self::Output {
            (self, offset)
        }
    }

    impl core::ops::Sub<i32> for Reg {
        type Output = (Reg, i32);
        fn sub(self, offset: i32) -> Self::Output {
            (self, -offset)
        }
    }

    pub trait IntoMemOp {
        #[doc(hidden)]
        fn into_mem_op(self, segment: Option<SegReg>, reg_size: RegSize) -> MemOp;
    }

    impl IntoMemOp for Reg {
        #[doc(hidden)]
        fn into_mem_op(self, segment: Option<SegReg>, reg_size: RegSize) -> MemOp {
            MemOp::BaseOffset(segment, reg_size, self, 0)
        }
    }

    impl IntoMemOp for (Reg, i32) {
        #[doc(hidden)]
        fn into_mem_op(self, segment: Option<SegReg>, reg_size: RegSize) -> MemOp {
            MemOp::BaseOffset(segment, reg_size, self.0, self.1)
        }
    }

    pub fn reg_indirect(reg_size: RegSize, op: impl IntoMemOp) -> MemOp {
        op.into_mem_op(None, reg_size)
    }

    pub fn abs(offset: i32) -> MemOp {
        MemOp::Offset(None, offset)
    }

    impl From<(RegSize, Reg, Reg)> for Operands {
        fn from((reg_size, dst, src): (RegSize, Reg, Reg)) -> Self {
            Self::RegMem_Reg(reg_size.into(), RegMem::Reg(dst), src)
        }
    }

    impl From<(Reg, ImmKind)> for Operands {
        fn from((dst, imm): (Reg, ImmKind)) -> Self {
            Self::RegMem_Imm(RegMem::Reg(dst), imm)
        }
    }

    pub fn imm8(value: u8) -> ImmKind {
        ImmKind::I8(value)
    }

    pub fn imm16(value: u16) -> ImmKind {
        ImmKind::I16(value)
    }

    pub fn imm32(value: u32) -> ImmKind {
        ImmKind::I32(value)
    }

    pub fn imm64(value: i32) -> ImmKind {
        ImmKind::I64(value)
    }
}

pub mod inst {
    use super::*;
    use crate::assembler::EncInst;

    const fn new_rm(op: u8, size: Size, regmem: RegMem, reg: Option<Reg>) -> Inst {
        let inst = match size {
            Size::U8 => {
                let force_rex = (match regmem {
                    RegMem::Mem(_) => false,
                    RegMem::Reg(reg) => !matches!(reg, Reg::rax | Reg::rcx | Reg::rdx | Reg::rbx),
                }) || (if let Some(reg) = reg {
                    !matches!(reg, Reg::rax | Reg::rcx | Reg::rdx | Reg::rbx)
                } else {
                    false
                });
                Inst::new(op).rex_if(force_rex)
            }
            Size::U16 => Inst::new(op + 1).override_op_size(),
            Size::U32 => Inst::new(op + 1),
            Size::U64 => Inst::new(op + 1).rex_64b(),
        }
        .regmem(regmem);

        if let Some(reg) = reg {
            inst.modrm_reg(reg)
        } else {
            inst
        }
    }

    const fn new_rm_imm(op: u8, regmem: RegMem, imm: ImmKind) -> Inst {
        let inst = new_rm(op, imm.size(), regmem, None);
        match imm {
            ImmKind::I8(imm) => inst.imm8(imm),
            ImmKind::I16(imm) => inst.imm16(imm),
            ImmKind::I32(imm) => inst.imm32(imm),
            ImmKind::I64(imm) => inst.imm32(imm as u32),
        }
    }

    const fn alu_impl(op_reg2rm: u8, op_rm2reg: u8, opext: u8, operands: Operands) -> EncInst {
        match operands {
            Operands::RegMem_Reg(size, dst, src) => new_rm(op_reg2rm, size, dst, Some(src)).encode(),
            Operands::Reg_RegMem(size, dst, src) => new_rm(op_rm2reg, size, src, Some(dst)).encode(),
            Operands::RegMem_Imm(dst, imm) => match imm {
                ImmKind::I8(imm) => Inst::new(0x80)
                    .rex_if(!matches!(dst, RegMem::Reg(Reg::rax | Reg::rcx | Reg::rdx | Reg::rbx)))
                    .imm8(imm),

                ImmKind::I16(value) => {
                    // These instructions have a special variant which sign extends the immediate,
                    // so we can get away with using a shorter immediate if possible.
                    if value as i16 <= i8::MAX as i16 && value as i16 >= i8::MIN as i16 {
                        Inst::new(0x83).imm8(value as u8)
                    } else {
                        Inst::new(0x81).imm16(value)
                    }
                    .override_op_size()
                }
                ImmKind::I32(value) => {
                    if value as i32 <= i8::MAX as i32 && value as i32 >= i8::MIN as i32 {
                        Inst::new(0x83).imm8(value as u8)
                    } else {
                        Inst::new(0x81).imm32(value)
                    }
                }
                ImmKind::I64(value) => if value <= i8::MAX as i32 && value >= i8::MIN as i32 {
                    Inst::new(0x83).imm8(value as u8)
                } else {
                    Inst::new(0x81).imm32(value as u32)
                }
                .rex_64b(),
            }
            .modrm_opext(opext)
            .regmem(dst)
            .encode(),
        }
    }

    fn display_with_operands(fmt: &mut core::fmt::Formatter, inst_name: &str, operands: Operands) -> core::fmt::Result {
        fmt.write_str(inst_name)?;
        fmt.write_str(" ")?;

        match operands {
            Operands::RegMem_Reg(reg_size, dst, src) => match dst {
                RegMem::Mem(mem) => fmt.write_fmt(core::format_args!("{}, {}", mem, src.name_from_size(reg_size))),
                RegMem::Reg(reg) => fmt.write_fmt(core::format_args!(
                    "{}, {}",
                    reg.name_from_size(reg_size),
                    src.name_from_size(reg_size)
                )),
            },
            Operands::Reg_RegMem(reg_size, dst, src) => match src {
                RegMem::Mem(mem) => fmt.write_fmt(core::format_args!("{}, {}", dst.name_from_size(reg_size), mem)),
                RegMem::Reg(reg) => fmt.write_fmt(core::format_args!(
                    "{}, {}",
                    dst.name_from_size(reg_size),
                    reg.name_from_size(reg_size)
                )),
            },
            Operands::RegMem_Imm(dst, imm) => {
                if matches!(dst, RegMem::Mem(..)) {
                    fmt.write_str(imm.size().name())?;
                    fmt.write_str(" ")?;
                }

                fmt.write_fmt(core::format_args!("{}, {imm}", dst.display_without_prefix(imm.size())))
            }
        }
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
        mov(RegSize, Reg, Reg) =>
            Inst::new(0x89).rex_64b_if(matches!(self.0, RegSize::R64)).modrm_rm_direct(self.1).modrm_reg(self.2).encode(),
            (fmt.write_fmt(core::format_args!("mov {}, {}", self.1.name_from(self.0), self.2.name_from(self.0)))),

        movsxd_32_to_64(Reg, Reg) =>
            Inst::new(0x63).rex_64b().modrm_rm_direct(self.1).modrm_reg(self.0).encode(),
            (fmt.write_fmt(core::format_args!("movsxd {}, {}", self.0.name(), self.1.name32()))),

        mov_imm64(Reg, u64) =>
            {
                if self.1 <= 0x7fffffff {
                    mov_imm(RegMem::Reg(self.0), ImmKind::I32(self.1 as u32)).encode_const()
                } else {
                    let xs = self.1.to_le_bytes();
                    EncInst::from_array([
                        REX_64B_OP | self.0.rex_bit(),
                        0xb8 | self.0.modrm_rm_bits(),
                        xs[0], xs[1], xs[2], xs[3], xs[4], xs[5], xs[6], xs[7]
                    ])
                }
            },
            ({
                if self.1 <= 0x7fffffff {
                    mov_imm(RegMem::Reg(self.0), ImmKind::I32(self.1 as u32)).fmt(fmt)
                } else {
                    fmt.write_fmt(core::format_args!("mov {}, 0x{:x}", self.0, self.1))
                }
            }),

        mov_imm(RegMem, ImmKind) =>
            {
                match self.0 {
                    RegMem::Mem(..) => new_rm_imm(0xc6, self.0, self.1).encode(),
                    RegMem::Reg(reg) => {
                        match self.1 {
                            ImmKind::I8(value) => Inst::with_reg_in_op(0xb0, reg).imm8(value).rex_if(!matches!(reg, Reg::rax | Reg::rcx | Reg::rdx | Reg::rbx)),
                            ImmKind::I16(value) => Inst::with_reg_in_op(0xb8, reg).imm16(value).override_op_size(),
                            ImmKind::I32(value) => Inst::with_reg_in_op(0xb8, reg).imm32(value),
                            ImmKind::I64(..) => new_rm_imm(0xc6, self.0, self.1),
                        }.encode()
                    }
                }
            },
            (display_with_operands(fmt, "mov", Operands::RegMem_Imm(self.0, self.1))),

        store(Size, MemOp, Reg) =>
            new_rm(0x88, self.0, RegMem::Mem(self.1), Some(self.2)).encode(),
            (fmt.write_fmt(core::format_args!("mov {}, {}", self.1, self.2.name_from_size(self.0)))),

        load(LoadKind, Reg, MemOp) =>
            {
                let inst = match self.0 {
                    LoadKind::U8 | LoadKind::U16 | LoadKind::I8 | LoadKind::I16 => {
                        let op = match self.0 {
                            LoadKind::U8 => 0xb6,
                            LoadKind::I8 => 0xbe,
                            LoadKind::U16 => 0xb7,
                            LoadKind::I16 => 0xbf,
                            | LoadKind::I32
                            | LoadKind::U32
                            | LoadKind::U64
                                => unreachable!()
                        };

                        Inst::new(op)
                            .op_alt()
                            // Use a 32-bit register as that's 1 byte shorter if we don't need the REX prefix.
                            .rex_64b_if(!(matches!(self.0, LoadKind::U8 | LoadKind::U16) && !self.1.needs_rex() && !self.2.needs_rex()))
                    },
                    LoadKind::I32 => Inst::new(0x63).rex_64b(),
                    LoadKind::U32 => Inst::new(0x8b),
                    LoadKind::U64 => Inst::new(0x8b).rex_64b()
                };

                inst
                    .modrm_reg(self.1)
                    .mem(self.2)
                    .encode()
            },
            ({
                let (name, kind, size) = match self.0 {
                    LoadKind::U8 if !self.1.needs_rex() && !self.2.needs_rex() => (self.1.name32(), "zx", "byte "),
                    LoadKind::U16 if !self.1.needs_rex() && !self.2.needs_rex() => (self.1.name32(), "zx", "word "),
                    LoadKind::U8 => (self.1.name(), "zx", "byte "),
                    LoadKind::I8 => (self.1.name(), "sx", "byte "),
                    LoadKind::U16 => (self.1.name(), "zx", "word "),
                    LoadKind::U32 => (self.1.name32(), "", ""),
                    LoadKind::I16 => (self.1.name(), "sx", "word "),
                    LoadKind::I32 => (self.1.name(), "sxd", ""),
                    LoadKind::U64 => (self.1.name(), "", ""),
                };

                fmt.write_fmt(core::format_args!("mov{} {}, {}{}", kind, name, size, self.2))
            }),

        // https://www.felixcloutier.com/x86/cmovcc
        cmov(Condition, RegSize, Reg, RegMem) =>
            {
                Inst::new(0x40 | self.0 as u8)
                    .op_alt()
                    .rex_64b_if(matches!(self.1, RegSize::R64))
                    .modrm_reg(self.2)
                    .regmem(self.3)
                    .encode()
            },
            (fmt.write_fmt(core::format_args!("cmov{} {}, {}", self.0.suffix(), self.2.name_from(self.1), self.3.display_without_prefix(Size::from(self.1))))),

        // https://www.felixcloutier.com/x86/add
        add(Operands) =>
            alu_impl(0x00, 0x02, 0b000, self.0),
            (display_with_operands(fmt, "add", self.0)),

        // https://www.felixcloutier.com/x86/inc
        inc(Size, RegMem) =>
            new_rm(0xfe, self.0, self.1, None).encode(),
            (fmt.write_fmt(core::format_args!("inc {}", self.1.display(self.0)))),

        // https://www.felixcloutier.com/x86/sub
        sub(Operands) =>
            alu_impl(0x28, 0x2a, 0b101, self.0),
            (display_with_operands(fmt, "sub", self.0)),

        // https://www.felixcloutier.com/x86/or
        or(Operands) =>
            alu_impl(0x08, 0x0a, 0b001, self.0),
            (display_with_operands(fmt, "or", self.0)),

        // https://www.felixcloutier.com/x86/and
        and(Operands) =>
            alu_impl(0x20, 0x22, 0b100, self.0),
            (display_with_operands(fmt, "and", self.0)),

        // https://www.felixcloutier.com/x86/xor
        xor(Operands) =>
            alu_impl(0x30, 0x32, 0b110, self.0),
            (display_with_operands(fmt, "xor", self.0)),

        // https://www.felixcloutier.com/x86/bts
        bts(RegSize, RegMem, u8) =>
            Inst::new(0xba).op_alt().modrm_opext(0b101).rex_64b_if(matches!(self.0, RegSize::R64)).regmem(self.1).imm8(self.2).encode(),
            ({
                match self.0 {
                    RegSize::R64 => fmt.write_fmt(core::format_args!("bts {}, 0x{:x}", self.1.display(Size::from(self.0)), self.2 as i64)),
                    RegSize::R32 => fmt.write_fmt(core::format_args!("bts {}, 0x{:x}", self.1.display(Size::from(self.0)), self.2)),
                }
            }),

        // https://www.felixcloutier.com/x86/neg
        neg(Size, RegMem) =>
            new_rm(0xf6, self.0, self.1, None).modrm_opext(0b011).encode(),
            (fmt.write_fmt(core::format_args!("neg {}", self.1.display(self.0)))),

        // https://www.felixcloutier.com/x86/not
        not(Size, RegMem) =>
            new_rm(0xf6, self.0, self.1, None).modrm_opext(0b010).encode(),
            (fmt.write_fmt(core::format_args!("not {}", self.1.display(self.0)))),

        // https://www.felixcloutier.com/x86/cmp
        cmp(Operands) =>
            alu_impl(0x38, 0x3a, 0b111, self.0),
            (display_with_operands(fmt, "cmp", self.0)),

        // https://www.felixcloutier.com/x86/sal:sar:shl:shr
        sar_cl(RegSize, RegMem) =>
            Inst::new(0xd3).rex_64b_if(matches!(self.0, RegSize::R64)).regmem(self.1).modrm_opext(0b111).encode(),
            (fmt.write_fmt(core::format_args!("sar {}, cl", self.1.display(Size::from(self.0))))),

        sar_imm(RegSize, RegMem, u8) =>
            Inst::new(0xc1).rex_64b_if(matches!(self.0, RegSize::R64)).regmem(self.1).modrm_opext(0b111).imm8(self.2).encode(),
            (fmt.write_fmt(core::format_args!("sar {}, 0x{:x}", self.1.display(Size::from(self.0)), self.2))),

        shl_cl(RegSize, RegMem) =>
            Inst::new(0xd3).rex_64b_if(matches!(self.0, RegSize::R64)).regmem(self.1).modrm_opext(0b100).encode(),
            (fmt.write_fmt(core::format_args!("shl {}, cl", self.1.display(Size::from(self.0))))),

        shl_imm(RegSize, RegMem, u8) =>
            Inst::new(0xc1).rex_64b_if(matches!(self.0, RegSize::R64)).regmem(self.1).modrm_opext(0b100).imm8(self.2).encode(),
            (fmt.write_fmt(core::format_args!("shl {}, 0x{:x}", self.1.display(Size::from(self.0)), self.2))),

        shr_cl(RegSize, RegMem) =>
            Inst::new(0xd3).rex_64b_if(matches!(self.0, RegSize::R64)).regmem(self.1).modrm_opext(0b101).encode(),
            (fmt.write_fmt(core::format_args!("shr {}, cl", self.1.display(Size::from(self.0))))),

        shr_imm(RegSize, RegMem, u8) =>
            Inst::new(0xc1).rex_64b_if(matches!(self.0, RegSize::R64)).regmem(self.1).modrm_opext(0b101).imm8(self.2).encode(),
            (fmt.write_fmt(core::format_args!("shr {}, 0x{:x}", self.1.display(Size::from(self.0)), self.2))),

        // https://www.felixcloutier.com/x86/rcl:rcr:rol:ror
        ror_imm(RegSize, RegMem, u8) =>
            Inst::new(0xc1).rex_64b_if(matches!(self.0, RegSize::R64)).regmem(self.1).modrm_opext(0b001).imm8(self.2).encode(),
            (fmt.write_fmt(core::format_args!("ror {}, 0x{:x}", self.1.display(Size::from(self.0)), self.2))),

        // https://www.felixcloutier.com/x86/test
        test(Operands) =>
            {
                match self.0 {
                    Operands::RegMem_Reg(size, regmem, reg) |
                    Operands::Reg_RegMem(size, reg, regmem) => new_rm(0x84, size, regmem, Some(reg)).encode(),
                    Operands::RegMem_Imm(regmem, imm) => new_rm_imm(0xf6, regmem, imm).encode(),
                }
            },
            ({
                let operands = match self.0 {
                    Operands::Reg_RegMem(size, reg, regmem) => Operands::RegMem_Reg(size, regmem, reg),
                    operands => operands
                };

                display_with_operands(fmt, "test", operands)
            }),

        // https://www.felixcloutier.com/x86/imul
        imul(RegSize, Reg, RegMem) =>
            Inst::new(0xaf).op_alt().rex_64b_if(matches!(self.0, RegSize::R64)).modrm_reg(self.1).regmem(self.2).encode(),
            (fmt.write_fmt(core::format_args!("imul {}, {}", self.1.name_from(self.0), self.2.display_without_prefix(Size::from(self.0))))),

        // https://www.felixcloutier.com/x86/div
        div(RegSize, RegMem) =>
            Inst::new(0xf7).modrm_opext(0b110).rex_64b_if(matches!(self.0, RegSize::R64)).regmem(self.1).encode(),
            (fmt.write_fmt(core::format_args!("div {}", self.1.display(Size::from(self.0))))),

        // https://www.felixcloutier.com/x86/idiv
        idiv(RegSize, RegMem) =>
            Inst::new(0xf7).modrm_opext(0b111).rex_64b_if(matches!(self.0, RegSize::R64)).regmem(self.1).encode(),
            (fmt.write_fmt(core::format_args!("idiv {}", self.1.display(Size::from(self.0))))),

        // https://www.felixcloutier.com/x86/cwd:cdq:cqo
        cdq() =>
            Inst::new(0x99).encode(),
            (fmt.write_str("cdq")),

        // https://www.felixcloutier.com/x86/setcc
        setcc(Condition, RegMem) =>
            {
                Inst::new(0x90 | self.0 as u8)
                    .rex_if(!matches!(self.1, RegMem::Reg(Reg::rax | Reg::rcx | Reg::rdx | Reg::rbx)))
                    .op_alt()
                    .regmem(self.1)
                    .encode()
            },
            (fmt.write_fmt(core::format_args!("set{} {}", self.0.suffix(), self.1.display_without_prefix(Size::U8)))),

        // https://www.felixcloutier.com/x86/lea
        lea(RegSize, Reg, MemOp) =>
            Inst::new(0x8d)
                .rex_64b_if(matches!(self.0, RegSize::R64))
                .modrm_reg(self.1)
                .mem(self.2).encode(),
            (fmt.write_fmt(core::format_args!("lea {}, {}", self.1.name_from(self.0), self.2))),

        // https://www.felixcloutier.com/x86/call
        call(RegMem) => {
            Inst::new(0xff).modrm_opext(0b010).regmem(self.0).encode()
        },
        ({
            match self.0 {
                RegMem::Reg(reg) => fmt.write_fmt(core::format_args!("call {}", reg)),
                RegMem::Mem(mem) => fmt.write_fmt(core::format_args!("call qword {}", mem)),
            }
        }),

        call_rel32(i32) =>
            Inst::new(0xe8).imm32(self.0 as u32).encode(),
            (fmt.write_fmt(core::format_args!("call 0x{:x}", (self.0 as i64).wrapping_add(5)))),

        // https://www.felixcloutier.com/x86/jmp
        jmp(RegMem) => {
            Inst::new(0xff).modrm_opext(0b100).regmem(self.0).encode()
        },
        ({
            match self.0 {
                RegMem::Reg(reg) => fmt.write_fmt(core::format_args!("jmp {}", reg)),
                RegMem::Mem(mem) => fmt.write_fmt(core::format_args!("jmp qword {}", mem)),
            }
        }),

        jmp_rel8(i8) =>
            Inst::new(0xeb).imm8(self.0 as u8).encode(),
            (fmt.write_fmt(core::format_args!("jmp short 0x{:x}", (self.0 as i64).wrapping_add(2)))),

        jmp_rel32(i32) =>
            Inst::new(0xe9).imm32(self.0 as u32).encode(),
            (fmt.write_fmt(core::format_args!("jmp 0x{:x}", (self.0 as i64).wrapping_add(5)))),

        // https://www.felixcloutier.com/x86/jcc
        jcc_rel8(Condition, i8) =>
            Inst::new(0x70 | self.0 as u8).imm8(self.1 as u8).encode(),
            (fmt.write_fmt(core::format_args!("j{} short 0x{:x}", self.0.suffix(), (self.1 as i64).wrapping_add(2)))),

        jcc_rel32(Condition, i32) =>
            Inst::new(0x80 | self.0 as u8).op_alt().imm32(self.1 as u32).encode(),
            (fmt.write_fmt(core::format_args!("j{} near 0x{:x}", self.0.suffix(), (self.1 as i64).wrapping_add(6)))),
    }

    #[derive(Copy, Clone, PartialEq, Eq, Debug)]
    pub struct jmp_label8(pub Label);
    impl jmp_label8 {
        const fn encode_const(self) -> EncInst {
            types::jmp_rel8(0).encode_const()
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
            types::jmp_rel32(0).encode_const()
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
            types::call_rel32(0).encode_const()
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
            types::jcc_rel8(self.0, 0).encode_const()
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
            types::jcc_rel32(self.0, 0).encode_const()
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

    #[derive(Copy, Clone, PartialEq, Eq, Debug)]
    pub struct lea_rip_label(pub Reg, pub Label);
    impl lea_rip_label {
        const fn encode_const(self) -> EncInst {
            types::lea(RegSize::R64, self.0, MemOp::RipRelative(None, 0)).encode_const()
        }
    }

    impl core::fmt::Display for lea_rip_label {
        fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
            fmt.write_fmt(core::format_args!("lea {}, [{}]", self.0, self.1))
        }
    }

    impl crate::Instruction for lea_rip_label {
        fn encode(self) -> EncInst {
            self.encode_const()
        }

        fn target_fixup(self) -> Option<(Label, u8, u8)> {
            Some((self.1, 3, 4))
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
pub enum Size {
    U8,
    U16,
    U32,
    #[default]
    U64,
}

impl Size {
    fn name(self) -> &'static str {
        match self {
            Size::U8 => "byte",
            Size::U16 => "word",
            Size::U32 => "dword",
            Size::U64 => "qword",
        }
    }
}

impl From<RegSize> for Size {
    fn from(reg_size: RegSize) -> Size {
        match reg_size {
            RegSize::R32 => Size::U32,
            RegSize::R64 => Size::U64,
        }
    }
}

#[cfg(test)]
impl tests::GenerateTestValues for Size {
    fn generate_test_values(cb: impl FnMut(Self)) {
        use Size::*;
        [U8, U16, U32, U64].into_iter().for_each(cb);
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum ImmKind {
    I8(u8),
    I16(u16),
    I32(u32),
    I64(i32),
}

impl core::fmt::Display for ImmKind {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
        match *self {
            ImmKind::I64(value) => fmt.write_fmt(core::format_args!("0x{:x}", value as i64)),
            ImmKind::I32(value) => fmt.write_fmt(core::format_args!("0x{:x}", value)),
            ImmKind::I16(value) => fmt.write_fmt(core::format_args!("0x{:x}", value)),
            ImmKind::I8(value) => fmt.write_fmt(core::format_args!("0x{:x}", value)),
        }
    }
}

impl ImmKind {
    const fn size(self) -> Size {
        match self {
            ImmKind::I8(..) => Size::U8,
            ImmKind::I16(..) => Size::U16,
            ImmKind::I32(..) => Size::U32,
            ImmKind::I64(..) => Size::U64,
        }
    }
}

#[cfg(test)]
impl tests::GenerateTestValues for ImmKind {
    fn generate_test_values(mut cb: impl FnMut(Self)) {
        use ImmKind::*;
        u8::generate_test_values(|imm| cb(I8(imm)));
        u16::generate_test_values(|imm| cb(I16(imm)));
        u32::generate_test_values(|imm| cb(I32(imm)));
        i32::generate_test_values(|imm| cb(I64(imm)));
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

    impl GenerateTestValues for super::RegIndex {
        fn generate_test_values(cb: impl FnMut(Self)) {
            use super::RegIndex::*;
            [rax, rcx, rdx, rbx, rbp, rsi, rdi, r8, r9, r10, r11, r12, r13, r14, r15]
                .into_iter()
                .for_each(cb);
        }
    }

    impl GenerateTestValues for super::SegReg {
        fn generate_test_values(cb: impl FnMut(Self)) {
            use super::SegReg::*;
            [fs, gs].into_iter().for_each(cb);
        }
    }

    impl GenerateTestValues for super::Scale {
        fn generate_test_values(cb: impl FnMut(Self)) {
            use super::Scale::*;
            [x1, x2, x4, x8].into_iter().for_each(cb);
        }
    }

    impl GenerateTestValues for super::MemOp {
        fn generate_test_values(mut cb: impl FnMut(Self)) {
            Option::<super::SegReg>::generate_test_values(|seg_reg| {
                super::RegSize::generate_test_values(|reg_size| {
                    super::Reg::generate_test_values(|base| {
                        i32::generate_test_values(|offset| cb(super::MemOp::BaseOffset(seg_reg, reg_size, base, offset)))
                    })
                })
            });

            Option::<super::SegReg>::generate_test_values(|seg_reg| {
                super::RegSize::generate_test_values(|reg_size| {
                    super::Reg::generate_test_values(|base| {
                        super::RegIndex::generate_test_values(|index| {
                            super::Scale::generate_test_values(|scale| {
                                i32::generate_test_values(|offset| {
                                    cb(super::MemOp::BaseIndexScaleOffset(seg_reg, reg_size, base, index, scale, offset))
                                })
                            })
                        })
                    })
                })
            });

            Option::<super::SegReg>::generate_test_values(|seg_reg| {
                super::RegSize::generate_test_values(|reg_size| {
                    super::RegIndex::generate_test_values(|base| {
                        super::Scale::generate_test_values(|scale| {
                            i32::generate_test_values(|offset| cb(super::MemOp::IndexScaleOffset(seg_reg, reg_size, base, scale, offset)))
                        })
                    })
                })
            });

            Option::<super::SegReg>::generate_test_values(|seg_reg| {
                i32::generate_test_values(|offset| cb(super::MemOp::Offset(seg_reg, offset)))
            });

            Option::<super::SegReg>::generate_test_values(|seg_reg| {
                i32::generate_test_values(|offset| cb(super::MemOp::RipRelative(seg_reg, offset)))
            });
        }
    }

    impl GenerateTestValues for super::RegMem {
        fn generate_test_values(mut cb: impl FnMut(Self)) {
            super::Reg::generate_test_values(|reg| cb(super::RegMem::Reg(reg)));
            super::MemOp::generate_test_values(|mem| cb(super::RegMem::Mem(mem)));
        }
    }

    impl GenerateTestValues for super::Operands {
        fn generate_test_values(mut cb: impl FnMut(Self)) {
            super::RegMem::generate_test_values(|regmem| {
                super::Size::generate_test_values(|size| {
                    super::Reg::generate_test_values(|reg| {
                        cb(super::Operands::RegMem_Reg(size, regmem, reg));
                        cb(super::Operands::Reg_RegMem(size, reg, regmem));
                    });
                });

                super::ImmKind::generate_test_values(|imm| {
                    cb(super::Operands::RegMem_Imm(regmem, imm));
                });
            });
        }
    }

    impl GenerateTestValues for () {
        fn generate_test_values(mut cb: impl FnMut(Self)) {
            cb(())
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
            [0, 0x7f, 0x80, 0x81, 0xfe, 0xff].into_iter().for_each(cb);
        }
    }

    #[cfg(test)]
    impl GenerateTestValues for i8 {
        fn generate_test_values(mut cb: impl FnMut(Self)) {
            u8::generate_test_values(|value| cb(value as i8))
        }
    }

    #[cfg(test)]
    impl GenerateTestValues for u16 {
        fn generate_test_values(cb: impl FnMut(Self)) {
            [
                0, 0x7f, 0x80, 0x81, 0xfe, 0xff, 0x100, 0x101, 0x7fff, 0x8000, 0x8001, 0xfffe, 0xffff,
            ]
            .into_iter()
            .for_each(cb);
        }
    }

    #[cfg(test)]
    impl GenerateTestValues for i16 {
        fn generate_test_values(mut cb: impl FnMut(Self)) {
            u16::generate_test_values(|value| cb(value as i16))
        }
    }

    #[cfg(test)]
    impl GenerateTestValues for u32 {
        fn generate_test_values(cb: impl FnMut(Self)) {
            [
                0, 0x7f, 0x80, 0x81, 0xfe, 0xff, 0x100, 0x101, 0x7fff, 0x8000, 0x8001, 0xfffe, 0xffff, 0x10000, 0x10001, 0x7fffffff,
                0x80000000, 0x80000001, 0xfffffffe, 0xffffffff,
            ]
            .into_iter()
            .for_each(cb);
        }
    }

    #[cfg(test)]
    impl GenerateTestValues for i32 {
        fn generate_test_values(mut cb: impl FnMut(Self)) {
            u32::generate_test_values(|value| cb(value as i32))
        }
    }

    #[cfg(test)]
    impl GenerateTestValues for u64 {
        fn generate_test_values(cb: impl FnMut(Self)) {
            [
                0,
                0x7f,
                0x80,
                0x81,
                0xfe,
                0xff,
                0x100,
                0x101,
                0x7fff,
                0x8000,
                0x8001,
                0xfffe,
                0xffff,
                0x10000,
                0x10001,
                0x7fffffff,
                0x80000000,
                0x80000001,
                0xfffffffe,
                0xffffffff,
                0x100000000,
                0x100000001,
                0x7fffffffffffffff,
                0x8000000000000000,
                0x8000000000000001,
                0xfffffffffffffffe,
                0xffffffffffffffff,
            ]
            .into_iter()
            .for_each(cb);
        }
    }

    fn disassemble(code: &[u8]) -> String {
        let mut output = String::new();
        disassemble_into(code, &mut output);
        output
    }

    fn disassemble_into(mut code: &[u8], output: &mut String) {
        use iced_x86::Formatter;
        use std::fmt::Write;

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

            write!(output, "{:08x} ", position).unwrap();
            let start_index = (instruction.ip() - code_origin) as usize;
            let instr_bytes = &code[start_index..start_index + instruction.len()];
            for b in instr_bytes.iter() {
                write!(output, "{:02x}", b).unwrap();
            }

            output.push(' ');
            formatter.format(&instruction, output);
            output.push('\n');
            code = &code[instruction.len()..];
            position += instruction.len();
        }

        output.pop();
    }

    struct TestAsm {
        asm: crate::Assembler,
        disassembly_1: String,
        disassembly_2: String,
    }

    impl TestAsm {
        fn new() -> Self {
            Self {
                asm: crate::Assembler::new(),
                disassembly_1: String::new(),
                disassembly_2: String::new(),
            }
        }

        fn run(&mut self, inst: impl crate::Instruction + core::fmt::Debug) {
            use core::fmt::Write;

            self.asm.clear();
            self.disassembly_1.clear();
            self.disassembly_2.clear();

            let position = self.asm.len();
            self.asm.push(inst);
            let ranges = [(inst, position..self.asm.len())];

            let code = self.asm.finalize();
            let mut position = 0;
            for (inst, range) in ranges {
                write!(&mut self.disassembly_1, "{:08x} ", position).unwrap();
                for &b in &code[range.clone()] {
                    write!(&mut self.disassembly_1, "{:02x}", b).unwrap();
                }
                position += range.len();
                writeln!(&mut self.disassembly_1, " {}", inst).unwrap();
            }

            self.disassembly_1.pop();
            disassemble_into(code, &mut self.disassembly_2);
            assert_eq!(self.disassembly_1, self.disassembly_2, "broken encoding for: {inst:?}");
        }
    }

    macro_rules! generate_tests {
        ($($inst_name:ident,)+) => {
            $(
                #[test]
                fn $inst_name() {
                    let mut test = TestAsm::new();
                    <super::inst::types::$inst_name as GenerateTestValues>::generate_test_values(|inst| test.run(inst));
                }
            )+
        }
    }

    generate_tests! {
        add,
        and,
        bts,
        call_rel32,
        call,
        cdq,
        cmov,
        cmp,
        div,
        endbr64,
        idiv,
        imul,
        inc,
        jcc_rel32,
        jcc_rel8,
        jmp_rel32,
        jmp_rel8,
        jmp,
        lea,
        load,
        mov_imm,
        mov_imm64,
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
        store,
        sub,
        syscall,
        test,
        ud2,
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

    #[test]
    fn lea_rip_label_infinite_loop() {
        use super::inst::*;
        let mut asm = crate::Assembler::new();
        let label = asm.forward_declare_label();
        asm.push_with_label(label, lea_rip_label(super::Reg::rax, label));
        let disassembly = disassemble(asm.finalize());
        assert_eq!(disassembly, "00000000 488d05f9ffffff lea rax, [rip-0x7]");
    }

    #[test]
    fn lea_rip_label_next_instruction() {
        use super::inst::*;
        let mut asm = crate::Assembler::new();
        let label = asm.forward_declare_label();
        asm.push(lea_rip_label(super::Reg::rax, label));
        asm.push_with_label(label, nop());
        let disassembly = disassemble(asm.finalize());
        assert_eq!(disassembly, "00000000 488d0500000000 lea rax, [rip]\n00000007 90 nop");
    }
}
