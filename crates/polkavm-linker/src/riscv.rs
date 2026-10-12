#![allow(clippy::unusual_byte_groupings)]

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
#[repr(u8)]
pub enum Reg {
    Zero = 0,
    RA,
    SP,
    GP,
    TP,
    T0,
    T1,
    T2,
    S0,
    S1,
    A0,
    A1,
    A2,
    A3,
    A4,
    A5,
    A6,
    A7,
    S2,
    S3,
    S4,
    S5,
    S6,
    S7,
    S8,
    S9,
    S10,
    S11,
    T3,
    T4,
    T5,
    T6,
}

pub struct DecoderConfig {
    pub(crate) rv64: bool,
}

impl DecoderConfig {
    pub fn new_32bit() -> Self {
        DecoderConfig { rv64: false }
    }

    #[cfg(test)]
    pub fn new_64bit() -> Self {
        DecoderConfig { rv64: true }
    }

    pub fn set_rv64(&mut self, rv64: bool) -> &mut Self {
        self.rv64 = rv64;
        self
    }
}

impl Reg {
    pub const NAMES: &'static [&'static str] = &[
        "zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2", "s0", "s1", "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7", "s2", "s3", "s4",
        "s5", "s6", "s7", "s8", "s9", "s10", "s11", "t3", "t4", "t5", "t6",
    ];

    pub fn name(self) -> &'static str {
        Self::NAMES[self as usize]
    }
}

impl core::fmt::Display for Reg {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
        fmt.write_str(self.name())
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Hash)]
pub enum BranchKind {
    Eq32,
    Eq64,
    NotEq32,
    NotEq64,
    LessSigned32,
    LessSigned64,
    GreaterOrEqualSigned32,
    GreaterOrEqualSigned64,
    LessUnsigned32,
    LessUnsigned64,
    GreaterOrEqualUnsigned32,
    GreaterOrEqualUnsigned64,
}

impl BranchKind {
    #[inline(always)]
    const fn decode(value: u32, rv64: bool) -> Option<Self> {
        match value & 0b111 {
            0b000 if rv64 => Some(BranchKind::Eq64),
            0b001 if rv64 => Some(BranchKind::NotEq64),
            0b100 if rv64 => Some(BranchKind::LessSigned64),
            0b101 if rv64 => Some(BranchKind::GreaterOrEqualSigned64),
            0b110 if rv64 => Some(BranchKind::LessUnsigned64),
            0b111 if rv64 => Some(BranchKind::GreaterOrEqualUnsigned64),
            0b000 => Some(BranchKind::Eq32),
            0b001 => Some(BranchKind::NotEq32),
            0b100 => Some(BranchKind::LessSigned32),
            0b101 => Some(BranchKind::GreaterOrEqualSigned32),
            0b110 => Some(BranchKind::LessUnsigned32),
            0b111 => Some(BranchKind::GreaterOrEqualUnsigned32),
            _ => None,
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Hash)]
#[repr(u8)]
pub enum LoadKind {
    I8 = 0b000,
    I16 = 0b001,
    U32 = 0b110,
    U8 = 0b100,
    U16 = 0b101,
    I32 = 0b010,
    U64 = 0b011,
}

impl LoadKind {
    #[inline(always)]
    const fn decode(value: u32, rv64: bool) -> Option<Self> {
        match value & 0b111 {
            0b000 => Some(LoadKind::I8),          // LB
            0b001 => Some(LoadKind::I16),         // LH
            0b010 => Some(LoadKind::I32),         // LW
            0b100 => Some(LoadKind::U8),          // LBU
            0b101 => Some(LoadKind::U16),         // LBH
            0b110 if rv64 => Some(LoadKind::U32), // LWU
            0b011 if rv64 => Some(LoadKind::U64), // LD
            _ => None,
        }
    }

    pub(crate) const fn size(self) -> u64 {
        match self {
            LoadKind::I8 | LoadKind::U8 => 1,
            LoadKind::I16 | LoadKind::U16 => 2,
            LoadKind::I32 | LoadKind::U32 => 4,
            LoadKind::U64 => 8,
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Hash)]
#[repr(u8)]
pub enum StoreKind {
    U8 = 0b000,
    U16 = 0b001,
    U32 = 0b010,
    U64 = 0b011,
}

impl StoreKind {
    #[inline(always)]
    const fn decode(value: u32) -> Option<Self> {
        match value & 0b111 {
            0b000 => Some(StoreKind::U8),
            0b001 => Some(StoreKind::U16),
            0b010 => Some(StoreKind::U32),
            0b011 => Some(StoreKind::U64),
            _ => None,
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Hash)]
pub enum RegKind {
    CountLeadingZeroBits32,
    CountLeadingZeroBits64,
    CountSetBits32,
    CountSetBits64,
    CountTrailingZeroBits32,
    CountTrailingZeroBits64,
    OrCombineByte,
    ReverseByte,
    SignExtend8,
    SignExtend16,
    ZeroExtend16,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Hash)]
pub enum RegImmKind {
    Add32,
    Add32AndSignExtend,
    Add64,
    SetLessThanSigned32,
    SetLessThanSigned64,
    SetLessThanUnsigned32,
    SetLessThanUnsigned64,
    Xor32,
    Xor64,
    Or32,
    Or64,
    And32,
    And64,
    ShiftLogicalLeft32,
    ShiftLogicalLeft32AndSignExtend,
    ShiftLogicalLeft64,
    ShiftLogicalRight32,
    ShiftLogicalRight32AndSignExtend,
    ShiftLogicalRight64,
    ShiftArithmeticRight32,
    ShiftArithmeticRight32AndSignExtend,
    ShiftArithmeticRight64,

    RotateRight32,
    RotateRight32AndSignExtend,
    RotateRight64,
}

enum Bitness {
    B32,
    B64,
    Both,
}

impl RegImmKind {
    #[inline(always)]
    const fn decode(value: u32, rv64: bool) -> Option<Self> {
        match value & 0b111 {
            0b000 if rv64 => Some(Self::Add64),
            0b010 if rv64 => Some(Self::SetLessThanSigned64),
            0b011 if rv64 => Some(Self::SetLessThanUnsigned64),
            0b100 if rv64 => Some(Self::Xor64),
            0b110 if rv64 => Some(Self::Or64),
            0b111 if rv64 => Some(Self::And64),
            0b000 => Some(Self::Add32),
            0b010 => Some(Self::SetLessThanSigned32),
            0b011 => Some(Self::SetLessThanUnsigned32),
            0b100 => Some(Self::Xor32),
            0b110 => Some(Self::Or32),
            0b111 => Some(Self::And32),
            _ => None,
        }
    }

    fn bitness(self) -> Bitness {
        use RegImmKind::*;
        match self {
            Add32
            | SetLessThanSigned32
            | SetLessThanUnsigned32
            | Xor32
            | Or32
            | And32
            | ShiftLogicalLeft32
            | ShiftLogicalRight32
            | ShiftArithmeticRight32
            | RotateRight32 => Bitness::B32,

            Add32AndSignExtend
            | Add64
            | SetLessThanSigned64
            | SetLessThanUnsigned64
            | Xor64
            | Or64
            | And64
            | ShiftLogicalLeft32AndSignExtend
            | ShiftLogicalLeft64
            | ShiftLogicalRight32AndSignExtend
            | ShiftLogicalRight64
            | ShiftArithmeticRight32AndSignExtend
            | ShiftArithmeticRight64
            | RotateRight32AndSignExtend
            | RotateRight64 => Bitness::B64,
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Hash)]
pub enum RegRegKind {
    Add32,
    Add32AndSignExtend,
    Add64,
    Sub32,
    Sub32AndSignExtend,
    Sub64,
    SetLessThanSigned32,
    SetLessThanSigned64,
    SetLessThanUnsigned32,
    SetLessThanUnsigned64,
    Xor32,
    Xor64,
    ShiftLogicalLeft32,
    ShiftLogicalLeft32AndSignExtend,
    ShiftLogicalLeft64,
    ShiftLogicalRight32,
    ShiftLogicalRight32AndSignExtend,
    ShiftLogicalRight64,
    ShiftArithmeticRight32,
    ShiftArithmeticRight32AndSignExtend,
    ShiftArithmeticRight64,
    Or32,
    Or64,
    And32,
    And64,
    Mul32,
    Mul32AndSignExtend,
    Mul64,
    MulUpperSignedSigned32,
    MulUpperSignedSigned64,
    MulUpperSignedUnsigned32,
    MulUpperSignedUnsigned64,
    MulUpperUnsignedUnsigned32,
    MulUpperUnsignedUnsigned64,
    Div32,
    Div32AndSignExtend,
    Div64,
    DivUnsigned32,
    DivUnsigned32AndSignExtend,
    DivUnsigned64,
    Rem32,
    Rem32AndSignExtend,
    Rem64,
    RemUnsigned32,
    RemUnsigned32AndSignExtend,
    RemUnsigned64,

    AndInverted,
    OrInverted,
    Xnor,
    Maximum,
    MaximumUnsigned,
    Minimum,
    MinimumUnsigned,
    RotateLeft32,
    RotateLeft32AndSignExtend,
    RotateLeft64,
    RotateRight32,
    RotateRight32AndSignExtend,
    RotateRight64,
}

impl RegRegKind {
    fn bitness(self) -> Bitness {
        use RegRegKind::*;
        match self {
            Add32
            | Sub32
            | SetLessThanSigned32
            | SetLessThanUnsigned32
            | Xor32
            | ShiftLogicalLeft32
            | ShiftLogicalRight32
            | ShiftArithmeticRight32
            | Or32
            | And32
            | Mul32
            | MulUpperSignedSigned32
            | MulUpperSignedUnsigned32
            | MulUpperUnsignedUnsigned32
            | Div32
            | DivUnsigned32
            | Rem32
            | RemUnsigned32
            | RotateLeft32
            | RotateRight32 => Bitness::B32,

            Add32AndSignExtend
            | Add64
            | Sub32AndSignExtend
            | Sub64
            | SetLessThanSigned64
            | SetLessThanUnsigned64
            | Xor64
            | ShiftLogicalLeft32AndSignExtend
            | ShiftLogicalLeft64
            | ShiftLogicalRight32AndSignExtend
            | ShiftLogicalRight64
            | ShiftArithmeticRight32AndSignExtend
            | ShiftArithmeticRight64
            | Or64
            | And64
            | Mul32AndSignExtend
            | Mul64
            | MulUpperSignedSigned64
            | MulUpperSignedUnsigned64
            | MulUpperUnsignedUnsigned64
            | Div32AndSignExtend
            | Div64
            | DivUnsigned32AndSignExtend
            | DivUnsigned64
            | Rem32AndSignExtend
            | Rem64
            | RemUnsigned32AndSignExtend
            | RemUnsigned64
            | RotateLeft32AndSignExtend
            | RotateLeft64
            | RotateRight32AndSignExtend
            | RotateRight64 => Bitness::B64,

            AndInverted | OrInverted | Xnor | Maximum | MaximumUnsigned | Minimum | MinimumUnsigned => Bitness::Both,
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Hash)]
pub struct FenceFlags {
    input: bool,
    output: bool,
    read: bool,
    write: bool,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Hash)]
#[repr(u32)]
pub enum Inst {
    LoadUpperImmediate {
        dst: Reg,
        value: u32,
    },
    AddUpperImmediateToPc {
        dst: Reg,
        value: u32,
    },
    JumpAndLink {
        dst: Reg,
        target: u32,
    },
    JumpAndLinkRegister {
        dst: Reg,
        base: Reg,
        value: i32,
    },
    Branch {
        kind: BranchKind,
        src1: Reg,
        src2: Reg,
        target: u32,
    },
    Load {
        kind: LoadKind,
        dst: Reg,
        base: Reg,
        offset: i32,
    },
    Store {
        kind: StoreKind,
        src: Reg,
        base: Reg,
        offset: i32,
    },
    RegImm {
        kind: RegImmKind,
        dst: Reg,
        src: Reg,
        imm: i32,
    },
    Reg {
        kind: RegKind,
        dst: Reg,
        src: Reg,
    },
    RegReg {
        kind: RegRegKind,
        dst: Reg,
        src1: Reg,
        src2: Reg,
    },
    Ecall,
    Unimplemented,
    Fence {
        kind: u8,
        predecessor: FenceFlags,
        successor: FenceFlags,
    },
    FenceI,
    LoadReserved32 {
        acquire: bool,
        release: bool,
        dst: Reg,
        src: Reg,
    },
    StoreConditional32 {
        acquire: bool,
        release: bool,
        addr: Reg,
        dst: Reg,
        src: Reg,
    },
    LoadReserved64 {
        acquire: bool,
        release: bool,
        dst: Reg,
        src: Reg,
    },
    StoreConditional64 {
        acquire: bool,
        release: bool,
        addr: Reg,
        dst: Reg,
        src: Reg,
    },
    Atomic {
        acquire: bool,
        release: bool,
        kind: AtomicKind,
        dst: Reg,
        addr: Reg,
        src: Reg,
    },
    Cmov {
        kind: CmovKind,
        dst: Reg,
        src: Reg,
        cond: Reg,
    },
    MipsCmov {
        dst: Reg,
        src_true: Reg,
        src_false: Reg,
        cond: Reg,
    },
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Hash)]
pub enum AtomicKind {
    Swap32,
    Swap64,
    Add32,
    Add64,
    And32,
    And64,
    Or32,
    Or64,
    Xor32,
    Xor64,
    MaxSigned32,
    MaxSigned64,
    MinSigned32,
    MinSigned64,
    MaxUnsigned32,
    MaxUnsigned64,
    MinUnsigned32,
    MinUnsigned64,
}

impl From<AtomicKind> for u32 {
    fn from(value: AtomicKind) -> Self {
        match value {
            AtomicKind::Add32 | AtomicKind::Add64 => 0b00000,
            AtomicKind::Swap32 | AtomicKind::Swap64 => 0b00001,
            AtomicKind::And32 | AtomicKind::And64 => 0b01100,
            AtomicKind::Or32 | AtomicKind::Or64 => 0b01000,
            AtomicKind::Xor32 | AtomicKind::Xor64 => 0b00100,
            AtomicKind::MaxSigned32 | AtomicKind::MaxSigned64 => 0b10100,
            AtomicKind::MinSigned32 | AtomicKind::MinSigned64 => 0b10000,
            AtomicKind::MaxUnsigned32 | AtomicKind::MaxUnsigned64 => 0b11100,
            AtomicKind::MinUnsigned32 | AtomicKind::MinUnsigned64 => 0b11000,
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Hash)]
pub enum CmovKind {
    EqZero = 0,
    NotEqZero = 1,
}

impl Reg {
    #[inline(always)]
    pub const fn decode_compressed(reg: u32) -> Self {
        Self::decode((reg & 0b111) | 0b1000)
    }

    #[inline(always)]
    pub const fn decode(reg: u32) -> Self {
        match reg & 0b11111 {
            0 => Self::Zero,
            1 => Self::RA,
            2 => Self::SP,
            3 => Self::GP,
            4 => Self::TP,
            5 => Self::T0,
            6 => Self::T1,
            7 => Self::T2,
            8 => Self::S0,
            9 => Self::S1,
            10 => Self::A0,
            11 => Self::A1,
            12 => Self::A2,
            13 => Self::A3,
            14 => Self::A4,
            15 => Self::A5,
            16 => Self::A6,
            17 => Self::A7,
            18 => Self::S2,
            19 => Self::S3,
            20 => Self::S4,
            21 => Self::S5,
            22 => Self::S6,
            23 => Self::S7,
            24 => Self::S8,
            25 => Self::S9,
            26 => Self::S10,
            27 => Self::S11,
            28 => Self::T3,
            29 => Self::T4,
            30 => Self::T5,
            31 => Self::T6,
            _ => unreachable!(),
        }
    }
}

#[inline(always)]
const fn sign_ext(value: u32, bits: u32) -> i32 {
    let mask = 1 << (bits - 1);
    (value ^ mask) as i32 - mask as i32
}

#[cfg(test)]
#[inline(always)]
fn sign_unext(imm: u32, bits: u32) -> Option<u32> {
    if bits == 0 {
        return None;
    }

    let mask = (1 << bits) - 1;
    let sign_bit = (imm & (1 << (bits - 1))) != 0;
    let high_sign_bits = imm & !mask;
    if sign_bit {
        if high_sign_bits != !mask {
            return None;
        }
    } else if high_sign_bits != 0 {
        return None;
    }

    Some(imm & mask)
}

#[test]
fn test_sign_ext() {
    assert_eq!(sign_ext(0b0101, 4), 0b0101);
    assert_eq!(sign_ext(0b101, 3) as u32, 0b11111111111111111111111111111101);
    assert_eq!(sign_ext(0b001, 3) as u32, 0b001);

    assert_eq!(sign_unext(0b0101, 4), Some(0b0101));
    assert_eq!(sign_unext(0b10101, 4), None);
    assert_eq!(sign_unext(0b100101, 4), None);
    assert_eq!(sign_unext(0b11111111111111111111111111111101, 3), Some(0b101));
    assert_eq!(sign_unext(0b11111111111111111111111111111001, 3), None);
    assert_eq!(sign_unext(0b11111111111111111111111111110101, 3), None);
    assert_eq!(sign_unext(0b01111111111111111111111111111101, 3), None);
    assert_eq!(sign_unext(0b001, 3), Some(0b001));
}

#[inline(always)]
const fn bits(start: u32, end: u32, value: u32, position: u32) -> u32 {
    let mask = (1 << (end - start + 1)) - 1;
    ((value >> position) & mask) << start
}

#[cfg(test)]
#[inline(always)]
const fn unbits(start: u32, end: u32, value: u32, position: u32) -> u32 {
    let mask = (1 << (end - start + 1)) - 1;
    ((value >> start) & mask) << position
}

#[test]
fn test_bits() {
    assert_eq!(bits(0, 2, 0b01010, 1), 0b101);
    assert_eq!(bits(0, 2, 0b10101, 1), 0b010);
    assert_eq!(bits(4, 6, 0b01010, 1), 0b1010000);
    assert_eq!(bits(4, 6, 0b10101, 1), 0b0100000);

    assert_eq!(unbits(0, 2, 0b101, 1), 0b01010);
    assert_eq!(unbits(4, 6, 0b1010000, 1), 0b01010);

    assert_eq!(unbits(5, 10, 2048, 25), 0);
}

/// Decodes immediates for C.J / C.JAL according to the RISC-V spec.
#[inline(always)]
const fn bits_imm_c_jump(op: u32) -> u32 {
    let value = bits(11, 11, op, 12)
        | bits(4, 4, op, 11)
        | bits(8, 9, op, 9)
        | bits(10, 10, op, 8)
        | bits(6, 6, op, 7)
        | bits(7, 7, op, 6)
        | bits(1, 3, op, 3)
        | bits(5, 5, op, 2);
    sign_ext(value, 12) as u32
}

#[derive(Copy, Clone)]
pub struct R(pub u32);

// See chapter 19 of the RISC-V spec.
pub const OPCODE_CUSTOM_0: u32 = 0b0001011;

impl R {
    pub fn opcode(self) -> u32 {
        self.0 & 0b1111111
    }

    pub fn func3(self) -> u32 {
        (self.0 >> 12) & 0b111
    }

    pub fn func7(self) -> u32 {
        (self.0 >> 25) & 0b1111111
    }

    pub fn dst(self) -> Reg {
        Reg::decode(self.0 >> 7)
    }

    pub fn src1(self) -> Reg {
        Reg::decode(self.0 >> 15)
    }

    pub fn src2(self) -> Reg {
        Reg::decode(self.0 >> 20)
    }

    // This matches the order of the `.insn` described here: https://sourceware.org/binutils/docs-2.31/as/RISC_002dV_002dFormats.html
    pub fn unpack(self) -> (u32, u32, u32, Reg, Reg, Reg) {
        (self.opcode(), self.func3(), self.func7(), self.dst(), self.src1(), self.src2())
    }
}

macro_rules! ctx {
    ($is_rv64:expr) => {
        macro_rules! xlen {
            ($path:tt, $variant_32:ident, $variant_64:ident) => {
                if $is_rv64 {
                    <$path>::$variant_64
                } else {
                    <$path>::$variant_32
                }
            };
        }
    };
}

impl Inst {
    pub const fn is_compressed(op: u8) -> bool {
        op & 0b00000011 < 0b00000011
    }

    fn decode_compressed(config: &DecoderConfig, op: u32) -> Option<Self> {
        ctx!(config.rv64);

        let quadrant = op & 0b11;
        let funct3 = (op >> 13) & 0b111;

        match (quadrant, funct3) {
            // Considered the unimplemented instruction by the asm manual:
            // https://github.com/riscv-non-isa/riscv-asm-manual/blob/main/src/asm-manual.adoc#instruction-aliases
            (0b00, 0b000) if op & 0b11111111_11111111 == 0 => Some(Inst::Unimplemented),

            // RVC, Quadrant 0
            // C.ADDI4SPN expands to addi rd′, x2, nzuimm[9:2]
            (0b00, 0b000) if op & 0b00011111_11100000 != 0 => Some(Inst::RegImm {
                kind: xlen!(RegImmKind, Add32, Add64),
                dst: Reg::decode_compressed(op >> 2),
                src: Reg::SP,
                imm: (bits(4, 5, op, 11) | bits(6, 9, op, 7) | bits(2, 2, op, 6) | bits(3, 3, op, 5)) as i32,
            }),
            // C.LW expands to lw rd′, offset[6:2](rs1′)
            (0b00, 0b010) => Some(Inst::Load {
                kind: LoadKind::I32,
                dst: Reg::decode_compressed(op >> 2),
                base: Reg::decode_compressed(op >> 7),
                offset: (bits(3, 5, op, 10) | bits(2, 2, op, 6) | bits(6, 6, op, 5)) as i32,
            }),
            // C.LD expands ld rd′, offset[7:3](rs1′)
            (0b00, 0b011) if config.rv64 => Some(Inst::Load {
                kind: LoadKind::U64,
                dst: Reg::decode_compressed(op >> 2),
                base: Reg::decode_compressed(op >> 7),
                offset: (bits(3, 5, op, 10) | bits(6, 7, op, 5)) as i32,
            }),
            // C.SW expands to sw rs2′, offset[6:2](rs1′)
            (0b00, 0b110) => Some(Inst::Store {
                kind: StoreKind::U32,
                src: Reg::decode_compressed(op >> 2),
                base: Reg::decode_compressed(op >> 7),
                offset: (bits(3, 5, op, 10) | bits(2, 2, op, 6) | bits(6, 6, op, 5)) as i32,
            }),
            // C.SD expands to sd rs2′, offset[7:3](rs1′)
            (0b00, 0b111) if config.rv64 => Some(Inst::Store {
                kind: StoreKind::U64,
                src: Reg::decode_compressed(op >> 2),
                base: Reg::decode_compressed(op >> 7),
                offset: (bits(3, 5, op, 10) | bits(6, 7, op, 5)) as i32,
            }),

            // RVC, Quadrant 1
            // C.NOP expands to addi x0, x0, 0
            (0b01, 0b000) if op & 0b11111111_11111110 == 0 => Some(Inst::RegImm {
                kind: xlen!(RegImmKind, Add32, Add64),
                dst: Reg::Zero,
                src: Reg::Zero,
                imm: 0,
            }),
            // C.ADDI expands into addi rd, rd, nzimm[5:0]
            (0b01, 0b000) => {
                let imm = bits(5, 5, op, 12) | bits(0, 4, op, 2);

                (imm != 0).then(|| {
                    let rd = Reg::decode(op >> 7);
                    Inst::RegImm {
                        kind: if config.rv64 { RegImmKind::Add64 } else { RegImmKind::Add32 },
                        dst: rd,
                        src: rd,
                        imm: sign_ext(imm, 6),
                    }
                })
            }
            // C.JAL expands to jal x1, offset[11:1]
            (0b01, 0b001) if !config.rv64 => Some(Inst::JumpAndLink {
                dst: Reg::RA,
                target: bits_imm_c_jump(op),
            }),
            // C.ADDIW extends to addiw rd, rd, imm[5:0]
            (0b01, 0b001) => {
                let imm = bits(5, 5, op, 12) | bits(0, 4, op, 2);
                let rd = Reg::decode(op >> 7);
                Some(Inst::RegImm {
                    kind: RegImmKind::Add32AndSignExtend,
                    dst: rd,
                    src: rd,
                    imm: sign_ext(imm, 6),
                })
            }
            // C.LI expands into addi rd, x0, imm[5:0]
            (0b01, 0b010) if op & 0b00001111_10000000 != 0 => Some(Inst::RegImm {
                kind: xlen!(RegImmKind, Add32, Add64),
                dst: Reg::decode(op >> 7),
                src: Reg::Zero,
                imm: sign_ext(bits(5, 5, op, 12) | bits(0, 4, op, 2), 6),
            }),
            // C.ADDI16SP expands into addi x2, x2, nzimm[9:4]
            (0b01, 0b011) if Reg::decode(op >> 7) == Reg::SP && op & 0b00010000_01111100 != 0 => Some(Inst::RegImm {
                kind: xlen!(RegImmKind, Add32, Add64),
                dst: Reg::SP,
                src: Reg::SP,
                imm: sign_ext(
                    bits(9, 9, op, 12) | bits(4, 4, op, 6) | bits(6, 6, op, 5) | bits(7, 8, op, 3) | bits(5, 5, op, 2),
                    10,
                ),
            }),
            // C.LUI expands into lui rd, nzuimm[17:12]
            (0b01, 0b011) if Reg::decode(op >> 7) != Reg::Zero && op & 0b00010000_01111100 != 0 => Some(Inst::LoadUpperImmediate {
                dst: Reg::decode(op >> 7),
                value: sign_ext(bits(17, 17, op, 12) | bits(12, 16, op, 2), 18) as u32,
            }),
            (0b01, 0b100) => {
                let rd = Reg::decode_compressed(op >> 7);

                match ((op >> 10) & 0b00000111, (op >> 2) & 0b00011111) {
                    (0b000, 0) | (0b001, 0) => None,
                    // C.SRLI expands into srli rd′, rd′, shamt[5:0]
                    (0b000, shamt) => Some(Inst::RegImm {
                        kind: xlen!(RegImmKind, ShiftLogicalRight32, ShiftLogicalRight64),
                        dst: rd,
                        src: rd,
                        imm: shamt as i32,
                    }),
                    (0b100, shamt) if config.rv64 => Some(Inst::RegImm {
                        kind: RegImmKind::ShiftLogicalRight64,
                        dst: rd,
                        src: rd,
                        imm: ((1 << 5) | shamt) as i32,
                    }),
                    // C.SRAI expands into srai rd′, rd′, shamt[5:0]
                    (0b001, shamt) => Some(Inst::RegImm {
                        kind: xlen!(RegImmKind, ShiftArithmeticRight32, ShiftArithmeticRight64),
                        dst: rd,
                        src: rd,
                        imm: shamt as i32,
                    }),
                    (0b101, shamt) if config.rv64 => Some(Inst::RegImm {
                        kind: RegImmKind::ShiftArithmeticRight64,
                        dst: rd,
                        src: rd,
                        imm: ((1 << 5) | shamt) as i32,
                    }),
                    // C.ANDI expands to andi rd′, rd′, imm[5:0]
                    (0b110, imm4_0) | (0b010, imm4_0) => Some(Inst::RegImm {
                        kind: xlen!(RegImmKind, And32, And64),
                        dst: rd,
                        src: rd,
                        imm: sign_ext(bits(5, 5, op, 12) | imm4_0, 6),
                    }),
                    // C.SUB expands into sub rd′, rd′, rs2′
                    // C.XOR expands into xor rd′, rd′, rs2′
                    // C.OR expands into or rd′, rd′, rs2′
                    // C.AND expands into and rd′, rd′, rs2′
                    // C.ADDW expands into addw rd′, rd′, rs2′
                    // C.SUBW expands into subw rd′, rd′, rs2′
                    (0b011, _) | (0b111, _) => Some(Inst::RegReg {
                        kind: match ((op >> 12) & 0b1, (op >> 5) & 0b11) {
                            (0b0, 0b00) => xlen!(RegRegKind, Sub32, Sub64),
                            (0b0, 0b01) => xlen!(RegRegKind, Xor32, Xor64),
                            (0b0, 0b10) => xlen!(RegRegKind, Or32, Or64),
                            (0b0, 0b11) => xlen!(RegRegKind, And32, And64),
                            (0b1, 0b00) if config.rv64 => RegRegKind::Sub32AndSignExtend,
                            (0b1, 0b01) if config.rv64 => RegRegKind::Add32AndSignExtend,
                            _ => return None,
                        },
                        dst: rd,
                        src1: rd,
                        src2: Reg::decode_compressed(op >> 2),
                    }),
                    _ => None,
                }
            }
            // C.J expands to jal x0, offset[11:1]
            (0b01, 0b101) => Some(Inst::JumpAndLink {
                dst: Reg::Zero,
                target: bits_imm_c_jump(op),
            }),
            // C.BEQZ expands to beq rs1′, x0, offset[8:1]
            // C.BNEZ expands to bne rs1′, x0, offset[8:1]
            (0b01, funct3 @ 0b110) | (0b01, funct3 @ 0b111) => Some(Inst::Branch {
                kind: if funct3 == 0b110 {
                    xlen!(BranchKind, Eq32, Eq64)
                } else {
                    xlen!(BranchKind, NotEq32, NotEq64)
                },
                src1: Reg::decode_compressed(op >> 7),
                src2: Reg::Zero,
                target: sign_ext(
                    bits(8, 8, op, 12) | bits(3, 4, op, 10) | bits(6, 7, op, 5) | bits(1, 2, op, 3) | bits(5, 5, op, 2),
                    9,
                ) as u32,
            }),

            // RVC, Quadrant 2
            // C.SLLI expands to slli rd, rd, shamt[5:0]
            (0b10, 0b000) => match ((op >> 12) & 0b1, Reg::decode(op >> 7), bits(0, 4, op, 2)) {
                (_, Reg::Zero, _) | (0b0, _, 0) => None,
                (0b0, rd, shamt) => Some(Inst::RegImm {
                    kind: xlen!(RegImmKind, ShiftLogicalLeft32, ShiftLogicalLeft64),
                    dst: rd,
                    src: rd,
                    imm: shamt as i32,
                }),
                (0b1, rd, shamt) if config.rv64 => Some(Inst::RegImm {
                    kind: RegImmKind::ShiftLogicalLeft64,
                    dst: rd,
                    src: rd,
                    imm: ((1 << 5) | shamt) as i32,
                }),
                _ => None,
            },

            // C.LWSP expands to lw rd, offset[7:2](x2)
            (0b10, 0b010) => match Reg::decode(op >> 7) {
                Reg::Zero => None,
                rd => Some(Inst::Load {
                    kind: LoadKind::I32,
                    dst: rd,
                    base: Reg::SP,
                    offset: (bits(5, 5, op, 12) | bits(2, 4, op, 4) | bits(6, 7, op, 2)) as i32,
                }),
            },
            // C.LDSP expands to ld rd, offset[8:3](x2)
            (0b10, 0b011) if config.rv64 => match Reg::decode(op >> 7) {
                Reg::Zero => None,
                rd => Some(Inst::Load {
                    kind: LoadKind::U64,
                    dst: rd,
                    base: Reg::SP,
                    offset: (bits(5, 5, op, 12) | bits(3, 4, op, 5) | bits(6, 8, op, 2)) as i32,
                }),
            },
            (0b10, 0b100) => match ((op >> 12) & 0b1, Reg::decode(op >> 7), Reg::decode(op >> 2)) {
                (0b0, Reg::Zero, _) | (0b1, Reg::Zero, _) => None,
                // C.JR expands to jalr x0, rs1, 0
                (0b0, rs1, Reg::Zero) => Some(Inst::JumpAndLinkRegister {
                    dst: Reg::Zero,
                    base: rs1,
                    value: 0,
                }),
                // C.MV expands to add rd, x0, rs2
                (0b0, rd, rs2) => Some(Inst::RegReg {
                    kind: xlen!(RegRegKind, Add32, Add64),
                    dst: rd,
                    src1: Reg::Zero,
                    src2: rs2,
                }),
                // C.JALR expands to jalr x1, rs1, 0
                (0b1, rs1, Reg::Zero) => Some(Inst::JumpAndLinkRegister {
                    dst: Reg::RA,
                    base: rs1,
                    value: 0,
                }),
                // C.ADD expands to add rd, rd, rs2
                (0b1, rd, rs2) => Some(Inst::RegReg {
                    kind: xlen!(RegRegKind, Add32, Add64),
                    dst: rd,
                    src1: rd,
                    src2: rs2,
                }),
                _ => unreachable!(),
            },
            // C.SWSP expands to sw rs2, offset[7:2](x2)
            (0b10, 0b110) => Some(Inst::Store {
                kind: StoreKind::U32,
                src: Reg::decode(op >> 2),
                base: Reg::SP,
                offset: (bits(2, 5, op, 9) | bits(6, 7, op, 7)) as i32,
            }),
            // C.SDSP expands to sd rs2, offset[8:3](x2)
            (0b10, 0b111) if config.rv64 => Some(Inst::Store {
                kind: StoreKind::U64,
                src: Reg::decode(op >> 2),
                base: Reg::SP,
                offset: (bits(3, 5, op, 10) | bits(6, 8, op, 7)) as i32,
            }),

            // F, D, ebreak, reserved, hint, NSE and illegal instructions
            _ => None,
        }
    }

    pub fn decode(config: &DecoderConfig, op: u32) -> Option<Self> {
        let instruction = Self::decode_impl(config, op)?;
        let bitness = match instruction {
            Inst::RegImm { kind, .. } => kind.bitness(),
            Inst::RegReg { kind, .. } => kind.bitness(),
            _ => return Some(instruction),
        };

        match bitness {
            Bitness::B32 => assert!(
                !config.rv64,
                "internal error: emitted RV32-exclusive instruction in RV64 mode: {op:#x} -> {instruction:?}"
            ),
            Bitness::B64 => assert!(
                config.rv64,
                "internal error: emitted RV64-exclusive instruction in RV32 mode: {op:#x} -> {instruction:?}"
            ),
            Bitness::Both => {}
        }

        Some(instruction)
    }

    fn decode_impl(config: &DecoderConfig, op: u32) -> Option<Self> {
        ctx!(config.rv64);

        if Inst::is_compressed((op & 0xff) as u8) {
            return Self::decode_compressed(config, op);
        }

        // This is mostly unofficial, but it's a defacto standard used by both LLVM and GCC.
        // https://github.com/riscv-non-isa/riscv-asm-manual/blob/main/src/asm-manual.adoc#instruction-aliases
        if op == 0xc0001073 {
            return Some(Inst::Unimplemented);
        }

        match op & 0b1111111 {
            0b0110111 => {
                // LUI
                Some(Inst::LoadUpperImmediate {
                    dst: Reg::decode(op >> 7),
                    value: op & 0xfffff000,
                })
            }
            0b0010111 => {
                // AUIPC
                Some(Inst::AddUpperImmediateToPc {
                    dst: Reg::decode(op >> 7),
                    value: op & 0xfffff000,
                })
            }
            0b1101111 => {
                // JAL
                Some(Inst::JumpAndLink {
                    dst: Reg::decode(op >> 7),
                    target: sign_ext(
                        bits(1, 10, op, 21) | bits(11, 11, op, 20) | bits(12, 19, op, 12) | bits(20, 20, op, 31),
                        21,
                    ) as u32,
                })
            }
            0b1100111 => {
                // JALR
                match (op >> 12) & 0b111 {
                    0b000 => Some(Inst::JumpAndLinkRegister {
                        dst: Reg::decode(op >> 7),
                        base: Reg::decode(op >> 15),
                        value: sign_ext(op >> 20, 12),
                    }),
                    _ => None,
                }
            }
            0b1100011 => Some(Inst::Branch {
                kind: BranchKind::decode(op >> 12, config.rv64)?,
                src1: Reg::decode(op >> 15),
                src2: Reg::decode(op >> 20),
                target: sign_ext(
                    bits(1, 4, op, 8) | bits(5, 10, op, 25) | bits(11, 11, op, 7) | bits(12, 12, op, 31),
                    13,
                ) as u32,
            }),
            0b0000011 => Some(Inst::Load {
                kind: LoadKind::decode(op >> 12, config.rv64)?,
                dst: Reg::decode(op >> 7),
                base: Reg::decode(op >> 15),
                offset: sign_ext(bits(0, 11, op, 20), 12),
            }),
            0b0100011 => Some(Inst::Store {
                kind: StoreKind::decode(op >> 12)?,
                base: Reg::decode(op >> 15),
                src: Reg::decode(op >> 20),
                offset: sign_ext(bits(0, 4, op, 7) | bits(5, 11, op, 25), 12),
            }),
            0b0010011 => match (op >> 12) & 0b111 {
                0b001 => {
                    let op1 = (op >> 25) & 0b1111111;
                    let op2 = (op >> 20) & 0b11111;
                    let dst = Reg::decode(op >> 7);
                    let src1 = Reg::decode(op >> 15);

                    match (op1, op2) {
                        (0b0000000, _) if !config.rv64 => Some(Inst::RegImm {
                            kind: xlen!(RegImmKind, ShiftLogicalLeft32, ShiftLogicalLeft64),
                            dst,
                            src: src1,
                            imm: bits(0, 4, op, 20) as i32,
                        }),
                        (0b0000000, _) | (0b0000001, _) if config.rv64 => Some(Inst::RegImm {
                            kind: xlen!(RegImmKind, ShiftLogicalLeft32, ShiftLogicalLeft64),
                            dst,
                            src: src1,
                            imm: bits(0, 5, op, 20) as i32,
                        }),
                        (0b0110000, 0b00000) => Some(Inst::Reg {
                            kind: xlen!(RegKind, CountLeadingZeroBits32, CountLeadingZeroBits64),
                            dst,
                            src: src1,
                        }),
                        (0b0110000, 0b00001) => Some(Inst::Reg {
                            kind: xlen!(RegKind, CountTrailingZeroBits32, CountTrailingZeroBits64),
                            dst,
                            src: src1,
                        }),
                        (0b0110000, 0b00010) => Some(Inst::Reg {
                            kind: xlen!(RegKind, CountSetBits32, CountSetBits64),
                            dst,
                            src: src1,
                        }),
                        (0b0110000, 0b00100) => Some(Inst::Reg {
                            kind: RegKind::SignExtend8,
                            dst,
                            src: src1,
                        }),
                        (0b0110000, 0b00101) => Some(Inst::Reg {
                            kind: RegKind::SignExtend16,
                            dst,
                            src: src1,
                        }),
                        _ => None,
                    }
                }
                0b101 => {
                    let op1 = (op >> 25) & 0b1111111;
                    let op2 = (op >> 20) & 0b11111;
                    let dst = Reg::decode(op >> 7);
                    let src = Reg::decode(op >> 15);

                    match (op1, op2) {
                        (0b0000000, _) if !config.rv64 => Some(Inst::RegImm {
                            kind: RegImmKind::ShiftLogicalRight32,
                            dst,
                            src,
                            imm: bits(0, 4, op, 20) as i32,
                        }),
                        (0b0000000, _) | (0b0000001, _) if config.rv64 => Some(Inst::RegImm {
                            kind: RegImmKind::ShiftLogicalRight64,
                            dst,
                            src,
                            imm: bits(0, 5, op, 20) as i32,
                        }),
                        (0b0100000, _) if !config.rv64 => Some(Inst::RegImm {
                            kind: RegImmKind::ShiftArithmeticRight32,
                            dst,
                            src,
                            imm: bits(0, 4, op, 20) as i32,
                        }),
                        (0b0100000, _) | (0b0100001, _) if config.rv64 => Some(Inst::RegImm {
                            kind: RegImmKind::ShiftArithmeticRight64,
                            dst,
                            src,
                            imm: bits(0, 5, op, 20) as i32,
                        }),
                        (0b0110000, _) if !config.rv64 => Some(Inst::RegImm {
                            kind: RegImmKind::RotateRight32,
                            dst,
                            src,
                            imm: bits(0, 4, op, 20) as i32,
                        }),
                        (0b0110000, _) | (0b0110001, _) if config.rv64 => Some(Inst::RegImm {
                            kind: RegImmKind::RotateRight64,
                            dst,
                            src,
                            imm: bits(0, 5, op, 20) as i32,
                        }),
                        (0b0010100, 0b00111) => Some(Inst::Reg {
                            kind: RegKind::OrCombineByte,
                            dst,
                            src,
                        }),
                        (0b0110100, 0b11000) if !config.rv64 => Some(Inst::Reg {
                            kind: RegKind::ReverseByte,
                            dst,
                            src,
                        }),
                        (0b0110101, 0b11000) if config.rv64 => Some(Inst::Reg {
                            kind: RegKind::ReverseByte,
                            dst,
                            src,
                        }),
                        _ => None,
                    }
                }
                _ => Some(Inst::RegImm {
                    kind: RegImmKind::decode(op >> 12, config.rv64)?,
                    dst: Reg::decode(op >> 7),
                    src: Reg::decode(op >> 15),
                    imm: sign_ext(op >> 20, 12),
                }),
            },
            0b0011011 => match (op >> 12) & 0b111 {
                0b000 if config.rv64 => Some(Inst::RegImm {
                    kind: RegImmKind::Add32AndSignExtend,
                    dst: Reg::decode(op >> 7),
                    src: Reg::decode(op >> 15),
                    imm: sign_ext(op >> 20, 12),
                }),
                0b001 if config.rv64 => {
                    let op1 = (op >> 25) & 0b1111111;
                    let op2 = (op >> 20) & 0b11111;
                    let dst = Reg::decode(op >> 7);
                    let src = Reg::decode(op >> 15);

                    match (op1, op2) {
                        (0b0000000, _) => Some(Inst::RegImm {
                            kind: RegImmKind::ShiftLogicalLeft32AndSignExtend,
                            dst,
                            src,
                            imm: bits(0, 5, op, 20) as i32,
                        }),
                        (0b0110000, 0b00000) => Some(Inst::Reg {
                            kind: RegKind::CountLeadingZeroBits32,
                            dst,
                            src,
                        }),
                        (0b0110000, 0b00001) => Some(Inst::Reg {
                            kind: RegKind::CountTrailingZeroBits32,
                            dst,
                            src,
                        }),
                        (0b0110000, 0b00010) => Some(Inst::Reg {
                            kind: RegKind::CountSetBits32,
                            dst,
                            src,
                        }),

                        _ => None,
                    }
                }
                0b101 => match (op >> 25) & 0b1111111 {
                    0b0000000 if config.rv64 => Some(Inst::RegImm {
                        kind: RegImmKind::ShiftLogicalRight32AndSignExtend,
                        dst: Reg::decode(op >> 7),
                        src: Reg::decode(op >> 15),
                        imm: bits(0, 5, op, 20) as i32,
                    }),
                    0b0100000 if config.rv64 => Some(Inst::RegImm {
                        kind: RegImmKind::ShiftArithmeticRight32AndSignExtend,
                        dst: Reg::decode(op >> 7),
                        src: Reg::decode(op >> 15),
                        imm: bits(0, 5, op, 20) as i32,
                    }),
                    0b0110000 => Some(Inst::RegImm {
                        kind: RegImmKind::RotateRight32AndSignExtend,
                        dst: Reg::decode(op >> 7),
                        src: Reg::decode(op >> 15),
                        imm: bits(0, 5, op, 20) as i32,
                    }),
                    _ => None,
                },
                _ => None,
            },
            0b0110011 => {
                let dst = Reg::decode(op >> 7);
                let src1 = Reg::decode(op >> 15);
                let src2 = Reg::decode(op >> 20);

                if !config.rv64 && (op & 0xfff07000) == 0x8004000 {
                    return Some(Inst::Reg {
                        kind: RegKind::ZeroExtend16,
                        dst,
                        src: src1,
                    });
                }

                let kind = match op & 0b1111111_00000_00000_111_00000_0000000 {
                    0b0000000_00000_00000_000_00000_0000000 => xlen!(RegRegKind, Add32, Add64),
                    0b0100000_00000_00000_000_00000_0000000 => xlen!(RegRegKind, Sub32, Sub64),
                    0b0000000_00000_00000_001_00000_0000000 => xlen!(RegRegKind, ShiftLogicalLeft32, ShiftLogicalLeft64),
                    0b0000000_00000_00000_010_00000_0000000 => xlen!(RegRegKind, SetLessThanSigned32, SetLessThanSigned64),
                    0b0000000_00000_00000_011_00000_0000000 => xlen!(RegRegKind, SetLessThanUnsigned32, SetLessThanUnsigned64),
                    0b0000000_00000_00000_100_00000_0000000 => xlen!(RegRegKind, Xor32, Xor64),
                    0b0000000_00000_00000_101_00000_0000000 => xlen!(RegRegKind, ShiftLogicalRight32, ShiftLogicalRight64),
                    0b0100000_00000_00000_101_00000_0000000 => xlen!(RegRegKind, ShiftArithmeticRight32, ShiftArithmeticRight64),
                    0b0000000_00000_00000_110_00000_0000000 => xlen!(RegRegKind, Or32, Or64),
                    0b0000000_00000_00000_111_00000_0000000 => xlen!(RegRegKind, And32, And64),
                    0b0000001_00000_00000_000_00000_0000000 => xlen!(RegRegKind, Mul32, Mul64),
                    0b0000001_00000_00000_001_00000_0000000 => xlen!(RegRegKind, MulUpperSignedSigned32, MulUpperSignedSigned64),
                    0b0000001_00000_00000_010_00000_0000000 => xlen!(RegRegKind, MulUpperSignedUnsigned32, MulUpperSignedUnsigned64),
                    0b0000001_00000_00000_011_00000_0000000 => xlen!(RegRegKind, MulUpperUnsignedUnsigned32, MulUpperUnsignedUnsigned64),
                    0b0000001_00000_00000_100_00000_0000000 => xlen!(RegRegKind, Div32, Div64),
                    0b0000001_00000_00000_101_00000_0000000 => xlen!(RegRegKind, DivUnsigned32, DivUnsigned64),
                    0b0000001_00000_00000_110_00000_0000000 => xlen!(RegRegKind, Rem32, Rem64),
                    0b0000001_00000_00000_111_00000_0000000 => xlen!(RegRegKind, RemUnsigned32, RemUnsigned64),

                    0b0000101_00000_00000_100_00000_0000000 => RegRegKind::Minimum,
                    0b0000101_00000_00000_101_00000_0000000 => RegRegKind::MinimumUnsigned,
                    0b0000101_00000_00000_110_00000_0000000 => RegRegKind::Maximum,
                    0b0000101_00000_00000_111_00000_0000000 => RegRegKind::MaximumUnsigned,

                    0b0100000_00000_00000_100_00000_0000000 => RegRegKind::Xnor,
                    0b0100000_00000_00000_110_00000_0000000 => RegRegKind::OrInverted,
                    0b0100000_00000_00000_111_00000_0000000 => RegRegKind::AndInverted,

                    0b0110000_00000_00000_001_00000_0000000 => xlen!(RegRegKind, RotateLeft32, RotateLeft64),
                    0b0110000_00000_00000_101_00000_0000000 => xlen!(RegRegKind, RotateRight32, RotateRight64),

                    _ => return None,
                };

                Some(Inst::RegReg { kind, dst, src1, src2 })
            }
            0b0111011 => {
                let dst = Reg::decode(op >> 7);
                let src1 = Reg::decode(op >> 15);
                let src2 = Reg::decode(op >> 20);

                if config.rv64 && (op & 0xfff07000) == 0x8004000 {
                    return Some(Inst::Reg {
                        kind: RegKind::ZeroExtend16,
                        dst,
                        src: src1,
                    });
                }

                let kind = match op & 0b1111111_00000_00000_111_00000_0000000 {
                    0b0000000_00000_00000_000_00000_0000000 if config.rv64 => RegRegKind::Add32AndSignExtend,
                    0b0000000_00000_00000_001_00000_0000000 if config.rv64 => RegRegKind::ShiftLogicalLeft32AndSignExtend,
                    0b0000000_00000_00000_101_00000_0000000 if config.rv64 => RegRegKind::ShiftLogicalRight32AndSignExtend,

                    0b0000001_00000_00000_000_00000_0000000 if config.rv64 => RegRegKind::Mul32AndSignExtend,
                    0b0000001_00000_00000_100_00000_0000000 if config.rv64 => RegRegKind::Div32AndSignExtend,
                    0b0000001_00000_00000_101_00000_0000000 if config.rv64 => RegRegKind::DivUnsigned32AndSignExtend,
                    0b0000001_00000_00000_110_00000_0000000 if config.rv64 => RegRegKind::Rem32AndSignExtend,
                    0b0000001_00000_00000_111_00000_0000000 if config.rv64 => RegRegKind::RemUnsigned32AndSignExtend,

                    0b0100000_00000_00000_000_00000_0000000 if config.rv64 => RegRegKind::Sub32AndSignExtend,
                    0b0100000_00000_00000_101_00000_0000000 if config.rv64 => RegRegKind::ShiftArithmeticRight32AndSignExtend,

                    0b0110000_00000_00000_001_00000_0000000 => RegRegKind::RotateLeft32AndSignExtend,
                    0b0110000_00000_00000_101_00000_0000000 => RegRegKind::RotateRight32AndSignExtend,

                    _ => return None,
                };

                Some(Inst::RegReg { kind, dst, src1, src2 })
            }
            0b1110011 => {
                if op == 0b000000000000_00000_000_00000_1110011 {
                    Some(Inst::Ecall)
                } else {
                    None
                }
            }
            0b0001111 => {
                if op == 0x0000100f {
                    Some(Inst::FenceI)
                } else if (op & !(0xfff << 20)) == 0x0000000f {
                    Some(Inst::Fence {
                        kind: (op >> 28) as u8,
                        predecessor: FenceFlags {
                            input: ((op >> 27) & 1) != 0,
                            output: ((op >> 26) & 1) != 0,
                            read: ((op >> 25) & 1) != 0,
                            write: ((op >> 24) & 1) != 0,
                        },
                        successor: FenceFlags {
                            input: ((op >> 23) & 1) != 0,
                            output: ((op >> 22) & 1) != 0,
                            read: ((op >> 21) & 1) != 0,
                            write: ((op >> 20) & 1) != 0,
                        },
                    })
                } else {
                    None
                }
            }
            0b0101111 => {
                let dst = Reg::decode(op >> 7);
                let src1 = Reg::decode(op >> 15);
                let src2 = Reg::decode(op >> 20);
                let kind = op >> 27;
                let release = ((op >> 25) & 1) != 0;
                let acquire = ((op >> 26) & 1) != 0;
                let funct3 = (op >> 12) & 0b111;
                let is_64_bit = match funct3 {
                    0b011 if config.rv64 => true,
                    0b010 => false,
                    _ => return None,
                };

                match (kind, is_64_bit) {
                    (0b00010, true) if src2 == Reg::Zero => Some(Inst::LoadReserved64 {
                        acquire,
                        release,
                        dst,
                        src: src1,
                    }),
                    (0b00011, true) => Some(Inst::StoreConditional64 {
                        acquire,
                        release,
                        addr: src1,
                        dst,
                        src: src2,
                    }),
                    (0b00010, false) if src2 == Reg::Zero => Some(Inst::LoadReserved32 {
                        acquire,
                        release,
                        dst,
                        src: src1,
                    }),
                    (0b00011, false) => Some(Inst::StoreConditional32 {
                        acquire,
                        release,
                        addr: src1,
                        dst,
                        src: src2,
                    }),
                    _ => {
                        let kind = match (kind, is_64_bit) {
                            (0b00000, true) => AtomicKind::Add64,
                            (0b00001, true) => AtomicKind::Swap64,
                            (0b00100, true) => AtomicKind::Xor64,
                            (0b01100, true) => AtomicKind::And64,
                            (0b01000, true) => AtomicKind::Or64,
                            (0b10000, true) => AtomicKind::MinSigned64,
                            (0b10100, true) => AtomicKind::MaxSigned64,
                            (0b11000, true) => AtomicKind::MinUnsigned64,
                            (0b11100, true) => AtomicKind::MaxUnsigned64,
                            (0b00000, false) => AtomicKind::Add32,
                            (0b00001, false) => AtomicKind::Swap32,
                            (0b00100, false) => AtomicKind::Xor32,
                            (0b01100, false) => AtomicKind::And32,
                            (0b01000, false) => AtomicKind::Or32,
                            (0b10000, false) => AtomicKind::MinSigned32,
                            (0b10100, false) => AtomicKind::MaxSigned32,
                            (0b11000, false) => AtomicKind::MinUnsigned32,
                            (0b11100, false) => AtomicKind::MaxUnsigned32,
                            _ => return None,
                        };

                        Some(Inst::Atomic {
                            acquire,
                            release,
                            kind,
                            dst,
                            addr: src1,
                            src: src2,
                        })
                    }
                }
            }
            // https://github.com/llvm/llvm-project/blob/e30e644266fbc9ba638ee2c6aa23b5691397163f/llvm/lib/Target/RISCV/RISCVInstrInfoXMips.td#L150
            // https://github.com/llvm/llvm-project/blob/e30e644266fbc9ba638ee2c6aa23b5691397163f/llvm/lib/Target/RISCV/RISCVInstrFormats.td#L388
            0b0001011 if ((op >> 25) & 0b11) == 0b11 && ((op >> 12) & 0b111) == 0b011 => {
                let dst = Reg::decode(op >> 7);
                let src1 = Reg::decode(op >> 15);
                let src2 = Reg::decode(op >> 20);
                let src3 = Reg::decode(op >> 27);

                Some(Inst::MipsCmov {
                    dst,
                    src_true: src1,
                    src_false: src3,
                    cond: src2,
                })
            }
            0b0001011 => {
                // OPCODE_CUSTOM_0
                let dst = Reg::decode(op >> 7);
                let src1 = Reg::decode(op >> 15);
                let src2 = Reg::decode(op >> 20);
                let hi = op >> 25;
                let lo = (op >> 12) & 0b111;
                if lo == 0b001 {
                    if hi == 0b0100000 {
                        //  th.mveqz
                        return Some(Inst::Cmov {
                            kind: CmovKind::EqZero,
                            dst,
                            src: src1,
                            cond: src2,
                        });
                    } else if hi == 0b0100001 {
                        //  th.mvnez
                        return Some(Inst::Cmov {
                            kind: CmovKind::NotEqZero,
                            dst,
                            src: src1,
                            cond: src2,
                        });
                    }
                }

                None
            }
            _ => None,
        }
    }
}

#[test]
fn test_decode_jump_and_link() {
    let config = DecoderConfig::new_32bit();
    assert_eq!(
        Inst::decode(&config, 0xd6dff06f).unwrap(),
        Inst::JumpAndLink {
            dst: Reg::Zero,
            target: 0x9f40_u32.wrapping_sub(0xa1d4)
        }
    );
}

#[test]
fn test_decode_branch() {
    let config = DecoderConfig::new_32bit();
    assert_eq!(
        Inst::decode(&config, 0x00c5fe63).unwrap(),
        Inst::Branch {
            kind: BranchKind::GreaterOrEqualUnsigned32,
            src1: Reg::A1,
            src2: Reg::A2,
            target: 0x8c - 0x70
        }
    );

    assert_eq!(
        Inst::decode(&config, 0xfeb96ce3).unwrap(),
        Inst::Branch {
            kind: BranchKind::LessUnsigned32,
            src1: Reg::S2,
            src2: Reg::A1,
            target: 0xccbc_u32.wrapping_sub(0xccc4)
        }
    );
}

#[test]
fn test_decode_multiply() {
    let config = DecoderConfig::new_32bit();

    assert_eq!(
        // 02f333b3                mulhu   t2,t1,a5
        Inst::decode(&config, 0x02f333b3).unwrap(),
        Inst::RegReg {
            kind: RegRegKind::MulUpperUnsignedUnsigned32,
            dst: Reg::T2,
            src1: Reg::T1,
            src2: Reg::A5,
        }
    );

    assert_eq!(
        // 029426b3                mulhsu  a3,s0,s1
        Inst::decode(&config, 0x029426b3).unwrap(),
        Inst::RegReg {
            kind: RegRegKind::MulUpperSignedUnsigned32,
            dst: Reg::A3,
            src1: Reg::S0,
            src2: Reg::S1,
        }
    );

    assert_eq!(
        // 02941633                mulh    a2,s0,s1
        Inst::decode(&config, 0x02941633).unwrap(),
        Inst::RegReg {
            kind: RegRegKind::MulUpperSignedSigned32,
            dst: Reg::A2,
            src1: Reg::S0,
            src2: Reg::S1,
        }
    );
}

#[test]
fn test_decode_cmov() {
    let config = DecoderConfig::new_32bit();

    assert_eq!(
        Inst::decode(&config, 0x42a6158b).unwrap(),
        Inst::Cmov {
            kind: CmovKind::NotEqZero,
            dst: Reg::A1,
            src: Reg::A2,
            cond: Reg::A0
        }
    );
}

#[test]
fn test_decode_srliw() {
    let mut config = DecoderConfig::new_32bit();
    config.set_rv64(true);

    assert_eq!(
        // srliw   a0,a0,0x18
        Inst::decode(&config, 0x0185551b).unwrap(),
        Inst::RegImm {
            kind: RegImmKind::ShiftLogicalRight32AndSignExtend,
            dst: Reg::A0,
            src: Reg::A0,
            imm: 0x18,
        }
    );
}

#[test]
fn test_decode_sraiw() {
    let config = DecoderConfig::new_64bit();

    assert_eq!(
        // sraiw   a0,a1,0xc
        Inst::decode(&config, 0x40c5d51b).unwrap(),
        Inst::RegImm {
            kind: RegImmKind::ShiftArithmeticRight32AndSignExtend,
            dst: Reg::A0,
            src: Reg::A1,
            imm: 0xc,
        }
    );
}

#[cfg(test)]
mod test_decode_compressed {
    use proptest::bits::BitSetStrategy;

    use super::*;

    #[test]
    fn registers() {
        for (encoded, expected) in [Reg::S0, Reg::S1, Reg::A0, Reg::A1, Reg::A2, Reg::A3, Reg::A4, Reg::A5]
            .iter()
            .enumerate()
        {
            assert_eq!(Reg::decode_compressed(encoded as u32), *expected);
        }
    }

    #[test]
    fn illegal_instruction() {
        let config = DecoderConfig::new_32bit();
        let config64 = DecoderConfig::new_64bit();

        assert_eq!(Inst::decode_compressed(&config, 1 << 16), Some(Inst::Unimplemented));

        assert_eq!(Inst::decode_compressed(&config64, 1 << 16), Some(Inst::Unimplemented));
    }

    #[test]
    fn test_bits_imm_c_jump() {
        assert_eq!(bits_imm_c_jump(0b001_10101010101_01), 0b11111111_11111111_11111110_10100100);
        assert_eq!(bits_imm_c_jump(0b001_00010000000_01), 1 << 8);
    }

    #[test]
    fn c_addi4spn() {
        let op = 0b000_10101010_111_00;
        let config = DecoderConfig::new_32bit();
        let config64 = DecoderConfig::new_64bit();

        assert_eq!(
            Inst::decode_compressed(&config, op),
            Some(Inst::RegImm {
                kind: RegImmKind::Add32,
                dst: Reg::decode_compressed(0b111),
                src: Reg::SP,
                imm: 0b1010100100
            })
        );

        assert_eq!(
            Inst::decode_compressed(&config64, op),
            Some(Inst::RegImm {
                kind: RegImmKind::Add64,
                dst: Reg::decode_compressed(0b111),
                src: Reg::SP,
                imm: 0b1010100100
            })
        );

        let op = 0b000_00000000_111_00;
        // RES, nzuimm=0
        assert_eq!(Inst::decode_compressed(&config, op), None);
        assert_eq!(Inst::decode_compressed(&config64, op), None);
    }

    #[test]
    fn c_lw() {
        let op = 0b010_101_010_01_111_00;
        let config = DecoderConfig::new_32bit();
        let config64 = DecoderConfig::new_64bit();

        assert_eq!(
            Inst::decode_compressed(&config, op),
            Some(Inst::Load {
                kind: LoadKind::I32,
                dst: Reg::decode_compressed(0b111),
                base: Reg::decode_compressed(0b010),
                offset: 0b1101000
            })
        );

        assert_eq!(
            Inst::decode_compressed(&config64, op),
            Some(Inst::Load {
                kind: LoadKind::I32,
                dst: Reg::decode_compressed(0b111),
                base: Reg::decode_compressed(0b010),
                offset: 0b1101000
            })
        );
    }

    #[test]
    fn c_ld() {
        let op = 0b011_110_110_10_101_00;
        let config = DecoderConfig::new_32bit();
        let config64 = DecoderConfig::new_64bit();

        assert_eq!(
            Inst::decode_compressed(&config64, op),
            Some(Inst::Load {
                kind: LoadKind::U64,
                dst: Reg::A3,
                base: Reg::A4,
                offset: 0b10110000
            })
        );

        assert_eq!(Inst::decode_compressed(&config, op), None);
    }

    #[test]
    fn c_sw() {
        let op = 0b110_101_010_01_111_00;
        let config = DecoderConfig::new_32bit();
        let config64 = DecoderConfig::new_64bit();

        assert_eq!(
            Inst::decode_compressed(&config, op),
            Some(Inst::Store {
                kind: StoreKind::U32,
                src: Reg::decode_compressed(0b111),
                base: Reg::decode_compressed(0b010),
                offset: 0b1101000
            })
        );

        assert_eq!(
            Inst::decode_compressed(&config64, op),
            Some(Inst::Store {
                kind: StoreKind::U32,
                src: Reg::decode_compressed(0b111),
                base: Reg::decode_compressed(0b010),
                offset: 0b1101000
            })
        );
    }

    #[test]
    fn c_sd() {
        let op = 0b111_101_010_01_111_00;
        let config = DecoderConfig::new_32bit();
        let config64 = DecoderConfig::new_64bit();

        assert_eq!(
            Inst::decode_compressed(&config64, op),
            Some(Inst::Store {
                kind: StoreKind::U64,
                src: Reg::decode_compressed(0b111),
                base: Reg::decode_compressed(0b010),
                offset: 0b01101000
            })
        );

        assert_eq!(Inst::decode_compressed(&config, op), None);
    }

    #[test]
    fn c_nop() {
        let op = 0b000_0_00000_00000_01;
        let config = DecoderConfig::new_32bit();

        assert_eq!(
            Inst::decode_compressed(&config, op),
            Some(Inst::RegImm {
                kind: RegImmKind::Add32,
                dst: Reg::Zero,
                src: Reg::Zero,
                imm: 0,
            })
        );
    }

    #[test]
    fn c_addi() {
        let op = 0b000_1_01000_11011_01;
        let config = DecoderConfig::new_32bit();
        let config64 = DecoderConfig::new_64bit();

        assert_eq!(
            Inst::decode_compressed(&config, op),
            Some(Inst::RegImm {
                kind: RegImmKind::Add32,
                dst: Reg::S0,
                src: Reg::S0,
                imm: -5
            })
        );

        assert_eq!(
            Inst::decode_compressed(&config64, op),
            Some(Inst::RegImm {
                kind: RegImmKind::Add64,
                dst: Reg::S0,
                src: Reg::S0,
                imm: -5
            })
        );

        let op = 0b000_0_01000_00000_01;
        // HINT, nzimm=0
        assert_eq!(Inst::decode_compressed(&config, op), None);
        assert_eq!(Inst::decode_compressed(&config64, op), None);
    }

    #[test]
    fn c_jal() {
        let op = 0b001_10101010101_01;
        let config = DecoderConfig::new_32bit();

        assert_eq!(
            Inst::decode_compressed(&config, op),
            Some(Inst::JumpAndLink {
                dst: Reg::RA,
                target: bits_imm_c_jump(op)
            })
        );
    }

    #[test]
    fn c_addiw() {
        let op = 0b001_10101010101_01;
        let config64 = DecoderConfig::new_64bit();

        assert_eq!(
            Inst::decode_compressed(&config64, op),
            Some(Inst::RegImm {
                kind: RegImmKind::Add32AndSignExtend,
                dst: Reg::A0,
                src: Reg::A0,
                imm: 0b11111111_11111111_11111111_11110101u32 as i32
            })
        );
    }

    #[test]
    fn c_j() {
        let op = 0b101_01010101010_01;
        let config = DecoderConfig::new_32bit();
        let config64 = DecoderConfig::new_64bit();
        let insn = Some(Inst::JumpAndLink {
            dst: Reg::Zero,
            target: bits_imm_c_jump(op),
        });

        assert_eq!(Inst::decode_compressed(&config, op), insn);
        assert_eq!(Inst::decode_compressed(&config64, op), insn);
    }

    #[test]
    fn c_li() {
        let op = 0b010_1_01000_10101_01;
        let config = DecoderConfig::new_32bit();
        let config64 = DecoderConfig::new_64bit();

        assert_eq!(
            Inst::decode_compressed(&config, op),
            Some(Inst::RegImm {
                kind: RegImmKind::Add32,
                dst: Reg::decode(0b01000),
                src: Reg::Zero,
                imm: -11
            })
        );

        assert_eq!(
            Inst::decode_compressed(&config64, op),
            Some(Inst::RegImm {
                kind: RegImmKind::Add64,
                dst: Reg::decode(0b01000),
                src: Reg::Zero,
                imm: -11
            })
        );

        let op = 0b010_0_00000_10101_01;
        // HINT, rd=0
        assert_eq!(Inst::decode_compressed(&config, op), None);
        assert_eq!(Inst::decode_compressed(&config64, op), None);
    }

    #[test]
    fn c_addi16sp() {
        let op = 0b011_1_00010_01010_01;
        let imm = 0b11111111_11111111_11111110_11000000u32 as i32;
        let config = DecoderConfig::new_32bit();
        let config64 = DecoderConfig::new_64bit();

        assert_eq!(
            Inst::decode_compressed(&config, op),
            Some(Inst::RegImm {
                kind: RegImmKind::Add32,
                dst: Reg::SP,
                src: Reg::SP,
                imm,
            })
        );

        assert_eq!(
            Inst::decode_compressed(&config64, op),
            Some(Inst::RegImm {
                kind: RegImmKind::Add64,
                dst: Reg::SP,
                src: Reg::SP,
                imm,
            })
        );

        let op = 0b011_0_00010_00000_01;
        // RES, nzimm=0
        assert_eq!(Inst::decode(&config, op), None);
        assert_eq!(Inst::decode(&config64, op), None);
    }

    #[test]
    fn c_lui() {
        let op = 0b011_1_01100_10101_01;
        let value = 0b11111111_11111111_01010000_00000000;
        let config = DecoderConfig::new_32bit();
        let config64 = DecoderConfig::new_64bit();

        assert_eq!(
            Inst::decode_compressed(&config, op),
            Some(Inst::LoadUpperImmediate { dst: Reg::A2, value })
        );

        assert_eq!(
            Inst::decode_compressed(&config64, op),
            Some(Inst::LoadUpperImmediate { dst: Reg::A2, value })
        );

        let op = 0b011_0_01100_00000_01;
        // RES, nzimm=0
        assert_eq!(Inst::decode(&config, op), None);
        assert_eq!(Inst::decode(&config64, op), None);

        let op = 0b011_1_00000_10101_01;
        // HINT, rd=0
        assert_eq!(Inst::decode(&config, op), None);
        assert_eq!(Inst::decode(&config64, op), None);
    }

    #[test]
    fn c_srli() {
        let op = 0b100_0_00_100_10000_01;
        let config = DecoderConfig::new_32bit();
        let config64 = DecoderConfig::new_64bit();

        assert_eq!(
            Inst::decode_compressed(&config, op),
            Some(Inst::RegImm {
                kind: RegImmKind::ShiftLogicalRight32,
                dst: Reg::A2,
                src: Reg::A2,
                imm: 0b10000
            })
        );

        assert_eq!(
            Inst::decode_compressed(&config64, op),
            Some(Inst::RegImm {
                kind: RegImmKind::ShiftLogicalRight64,
                dst: Reg::A2,
                src: Reg::A2,
                imm: 0b10000
            })
        );

        let op = 0b100_1_00_100_10000_01;
        // RV32 NSE, nzuimm[5]=1
        assert_eq!(Inst::decode_compressed(&config, op), None);
        assert_eq!(
            Inst::decode_compressed(&config64, op),
            Some(Inst::RegImm {
                kind: RegImmKind::ShiftLogicalRight64,
                dst: Reg::A2,
                src: Reg::A2,
                imm: 0b110000
            })
        );

        let op = 0b100_0_00_100_00000_01;
        // non-zero imm
        assert_eq!(Inst::decode_compressed(&config, op), None);
        assert_eq!(Inst::decode_compressed(&config64, op), None);
    }

    #[test]
    fn c_srai() {
        let op = 0b100_0_01_100_10000_01;
        let config = DecoderConfig::new_32bit();
        let config64 = DecoderConfig::new_64bit();

        assert_eq!(
            Inst::decode_compressed(&config, op),
            Some(Inst::RegImm {
                kind: RegImmKind::ShiftArithmeticRight32,
                dst: Reg::A2,
                src: Reg::A2,
                imm: 0b10000
            })
        );

        assert_eq!(
            Inst::decode_compressed(&config64, op),
            Some(Inst::RegImm {
                kind: RegImmKind::ShiftArithmeticRight64,
                dst: Reg::A2,
                src: Reg::A2,
                imm: 0b10000
            })
        );

        let op = 0b100_1_01_100_10000_01;
        // RV32 NSE, nzuimm[5]=1
        assert_eq!(Inst::decode_compressed(&config, op), None);
        assert_eq!(
            Inst::decode_compressed(&config64, op),
            Some(Inst::RegImm {
                kind: RegImmKind::ShiftArithmeticRight64,
                dst: Reg::A2,
                src: Reg::A2,
                imm: 0b110000
            })
        );

        let op = 0b100_0_01_100_00000_01;
        // non-zero imm
        assert_eq!(Inst::decode_compressed(&config, op), None);
        assert_eq!(Inst::decode_compressed(&config64, op), None);
    }

    #[test]
    fn c_andi() {
        let op = 0b100_1_10_100_10101_01;
        let config = DecoderConfig::new_32bit();
        let config64 = DecoderConfig::new_64bit();

        assert_eq!(
            Inst::decode_compressed(&config, op),
            Some(Inst::RegImm {
                kind: RegImmKind::And32,
                dst: Reg::A2,
                src: Reg::A2,
                imm: -11
            })
        );

        assert_eq!(
            Inst::decode_compressed(&config64, op),
            Some(Inst::RegImm {
                kind: RegImmKind::And64,
                dst: Reg::A2,
                src: Reg::A2,
                imm: -11
            })
        );
    }

    #[test]
    fn c_sub() {
        let op = 0b100_0_11_111_00_100_01;
        let config = DecoderConfig::new_32bit();
        let config64 = DecoderConfig::new_64bit();

        assert_eq!(
            Inst::decode_compressed(&config, op),
            Some(Inst::RegReg {
                kind: RegRegKind::Sub32,
                dst: Reg::A5,
                src1: Reg::A5,
                src2: Reg::A2
            })
        );

        assert_eq!(
            Inst::decode_compressed(&config64, op),
            Some(Inst::RegReg {
                kind: RegRegKind::Sub64,
                dst: Reg::A5,
                src1: Reg::A5,
                src2: Reg::A2
            })
        );

        let op = 0b100_1_11010_00000_01;
        assert_eq!(Inst::decode_compressed(&config, op), None);
        assert_eq!(
            Inst::decode_compressed(&config64, op),
            Some(Inst::RegReg {
                kind: RegRegKind::Sub32AndSignExtend,
                dst: Reg::A0,
                src1: Reg::A0,
                src2: Reg::S0
            })
        );
    }

    #[test]
    fn c_subw() {
        // 9c89 c.subw  s1,a0
        assert_eq!(
            Inst::decode_compressed(&DecoderConfig::new_64bit(), 0x9c89),
            Some(Inst::RegReg {
                kind: RegRegKind::Sub32AndSignExtend,
                dst: Reg::S1,
                src1: Reg::S1,
                src2: Reg::A0
            })
        );
    }

    #[test]
    fn c_xor() {
        let op = 0b100_0_11_111_01_100_01;
        let config = DecoderConfig::new_32bit();
        let config64 = DecoderConfig::new_64bit();

        assert_eq!(
            Inst::decode_compressed(&config, op),
            Some(Inst::RegReg {
                kind: RegRegKind::Xor32,
                dst: Reg::A5,
                src1: Reg::A5,
                src2: Reg::A2
            })
        );

        assert_eq!(
            Inst::decode_compressed(&config64, op),
            Some(Inst::RegReg {
                kind: RegRegKind::Xor64,
                dst: Reg::A5,
                src1: Reg::A5,
                src2: Reg::A2
            })
        );
    }

    #[test]
    fn c_or() {
        let op = 0b100_0_11_111_10_100_01;
        let config = DecoderConfig::new_32bit();
        let config64 = DecoderConfig::new_64bit();

        assert_eq!(
            Inst::decode_compressed(&config, op),
            Some(Inst::RegReg {
                kind: RegRegKind::Or32,
                dst: Reg::A5,
                src1: Reg::A5,
                src2: Reg::A2
            })
        );

        assert_eq!(
            Inst::decode_compressed(&config64, op),
            Some(Inst::RegReg {
                kind: RegRegKind::Or64,
                dst: Reg::A5,
                src1: Reg::A5,
                src2: Reg::A2
            })
        );
    }

    #[test]
    fn c_and() {
        let op = 0b100_0_11_111_11_100_01;
        let config = DecoderConfig::new_32bit();
        let config64 = DecoderConfig::new_64bit();

        assert_eq!(
            Inst::decode_compressed(&config, op),
            Some(Inst::RegReg {
                kind: RegRegKind::And32,
                dst: Reg::A5,
                src1: Reg::A5,
                src2: Reg::A2
            })
        );

        assert_eq!(
            Inst::decode_compressed(&config64, op),
            Some(Inst::RegReg {
                kind: RegRegKind::And64,
                dst: Reg::A5,
                src1: Reg::A5,
                src2: Reg::A2
            })
        );
    }

    #[test]
    fn c_beqz() {
        let op = 0b110_101_100_01010_01;
        let config = DecoderConfig::new_32bit();

        assert_eq!(
            Inst::decode_compressed(&config, op),
            Some(Inst::Branch {
                kind: BranchKind::Eq32,
                src1: Reg::A2,
                src2: Reg::Zero,
                target: 0b11111111_11111111_11111111_01001010
            })
        );
    }

    #[test]
    fn c_bnez() {
        let op = 0b111_001_100_10101_01;
        let config = DecoderConfig::new_32bit();

        assert_eq!(
            Inst::decode_compressed(&config, op),
            Some(Inst::Branch {
                kind: BranchKind::NotEq32,
                src1: Reg::A2,
                src2: Reg::Zero,
                target: 0b010101100
            })
        );
    }

    #[test]
    fn c_slli() {
        let op = 0b000_0_01100_10101_10;
        let config = DecoderConfig::new_32bit();
        let config64 = DecoderConfig::new_64bit();

        assert_eq!(
            Inst::decode_compressed(&config, op),
            Some(Inst::RegImm {
                kind: RegImmKind::ShiftLogicalLeft32,
                dst: Reg::A2,
                src: Reg::A2,
                imm: 0b10101
            })
        );

        assert_eq!(
            Inst::decode_compressed(&config64, op),
            Some(Inst::RegImm {
                kind: RegImmKind::ShiftLogicalLeft64,
                dst: Reg::A2,
                src: Reg::A2,
                imm: 0b10101
            })
        );

        let op = 0b000_0_00000_10101_10;
        // HINT, rd=0
        assert_eq!(Inst::decode_compressed(&config, op), None);
        assert_eq!(Inst::decode_compressed(&config64, op), None);

        let op = 0b000_1_01100_10101_10;
        // RV32 NSE, nzuimm[5]=1
        assert_eq!(Inst::decode_compressed(&config, op), None);
        assert_eq!(
            Inst::decode_compressed(&config64, op),
            Some(Inst::RegImm {
                kind: RegImmKind::ShiftLogicalLeft64,
                dst: Reg::A2,
                src: Reg::A2,
                imm: 0b110101
            })
        );

        let op = 0b000_0_01100_00000_10;
        // non-zero shamt
        assert_eq!(Inst::decode_compressed(&config, op), None);
        assert_eq!(Inst::decode_compressed(&config64, op), None);

        let op = 0b000_1_01010_00000_10;
        assert_eq!(Inst::decode_compressed(&config, op), None);
        assert_eq!(
            Inst::decode_compressed(&config64, op),
            Some(Inst::RegImm {
                kind: RegImmKind::ShiftLogicalLeft64,
                dst: Reg::A0,
                src: Reg::A0,
                imm: 0b100000
            })
        );
    }

    #[test]
    fn c_lwsp() {
        let op = 0b010_1_01100_01010_10;
        let config = DecoderConfig::new_32bit();

        assert_eq!(
            Inst::decode_compressed(&config, op),
            Some(Inst::Load {
                kind: LoadKind::I32,
                dst: Reg::A2,
                base: Reg::SP,
                offset: 0b10101000
            })
        );

        let op = 0b010_1_00000_01010_10;
        // RES, rd=0
        assert_eq!(Inst::decode_compressed(&config, op), None);
    }

    #[test]
    fn c_ldsp() {
        let op = 0b011_1_01100_01010_10;
        let config = DecoderConfig::new_32bit();
        let config64 = DecoderConfig::new_64bit();

        assert_eq!(
            Inst::decode_compressed(&config64, op),
            Some(Inst::Load {
                kind: LoadKind::U64,
                dst: Reg::A2,
                base: Reg::SP,
                offset: 0b010101000
            })
        );

        assert_eq!(Inst::decode_compressed(&config, op), None);

        let op = 0b011_1_00000_01010_10;
        // RES, rd=0
        assert_eq!(Inst::decode_compressed(&config64, op), None);
    }

    #[test]
    fn c_jr() {
        let op = 0b100_0_01100_00000_10;
        let config = DecoderConfig::new_32bit();

        assert_eq!(
            Inst::decode_compressed(&config, op),
            Some(Inst::JumpAndLinkRegister {
                dst: Reg::Zero,
                base: Reg::A2,
                value: 0
            })
        );

        let op = 0b100_0_00000_00000_10;
        // RES, rs1=0
        assert_eq!(Inst::decode_compressed(&config, op), None);
    }

    #[test]
    fn c_mv() {
        let op = 0b100_0_01100_01101_10;
        let config = DecoderConfig::new_32bit();
        let config64 = DecoderConfig::new_64bit();

        assert_eq!(
            Inst::decode_compressed(&config, op),
            Some(Inst::RegReg {
                kind: RegRegKind::Add32,
                dst: Reg::A2,
                src1: Reg::Zero,
                src2: Reg::A3
            })
        );

        assert_eq!(
            Inst::decode_compressed(&config64, op),
            Some(Inst::RegReg {
                kind: RegRegKind::Add64,
                dst: Reg::A2,
                src1: Reg::Zero,
                src2: Reg::A3
            })
        );

        let op = 0b100_0_00000_01101_10;
        // HINT, rd=0
        assert_eq!(Inst::decode_compressed(&config, op), None);
        assert_eq!(Inst::decode_compressed(&config64, op), None);
    }

    #[test]
    fn c_ebreak() {
        let op = 0b100_1_00000_00000_10;
        let config = DecoderConfig::new_32bit();
        let config64 = DecoderConfig::new_64bit();

        // ebreak is not supported
        assert_eq!(Inst::decode_compressed(&config, op), None);
        assert_eq!(Inst::decode_compressed(&config64, op), None);
    }

    #[test]
    fn c_jalr() {
        let op = 0b100_1_01100_00000_10;
        let config = DecoderConfig::new_32bit();
        let config64 = DecoderConfig::new_64bit();

        assert_eq!(
            Inst::decode_compressed(&config, op),
            Some(Inst::JumpAndLinkRegister {
                dst: Reg::RA,
                base: Reg::A2,
                value: 0
            })
        );

        assert_eq!(
            Inst::decode_compressed(&config64, op),
            Some(Inst::JumpAndLinkRegister {
                dst: Reg::RA,
                base: Reg::A2,
                value: 0
            })
        );
    }

    #[test]
    fn c_add() {
        let op = 0b100_1_01100_01101_10;
        let config = DecoderConfig::new_32bit();
        let config64 = DecoderConfig::new_64bit();

        assert_eq!(
            Inst::decode_compressed(&config, op),
            Some(Inst::RegReg {
                kind: RegRegKind::Add32,
                dst: Reg::A2,
                src1: Reg::A2,
                src2: Reg::A3
            })
        );

        assert_eq!(
            Inst::decode_compressed(&config64, op),
            Some(Inst::RegReg {
                kind: RegRegKind::Add64,
                dst: Reg::A2,
                src1: Reg::A2,
                src2: Reg::A3
            })
        );

        let op = 0b100_1_00000_01101_10;
        // HINT, rd=0
        assert_eq!(Inst::decode_compressed(&config, op), None);
        assert_eq!(Inst::decode_compressed(&config64, op), None);

        let op = 0b100_1_11010_01000_01;
        assert_eq!(Inst::decode_compressed(&config, op), None);
        assert_eq!(
            Inst::decode_compressed(&config64, op),
            Some(Inst::RegReg {
                kind: RegRegKind::Add32AndSignExtend,
                dst: Reg::A0,
                src1: Reg::A0,
                src2: Reg::S0
            })
        );
    }

    #[test]
    fn c_swsp() {
        let op = 0b110_101010_01100_10;
        let config = DecoderConfig::new_32bit();

        assert_eq!(
            Inst::decode_compressed(&config, op),
            Some(Inst::Store {
                kind: StoreKind::U32,
                src: Reg::A2,
                base: Reg::SP,
                offset: 0b10101000
            })
        )
    }

    #[test]
    fn c_sdsp() {
        let op = 0b111_101010_01100_10;
        let config = DecoderConfig::new_32bit();
        let config64 = DecoderConfig::new_64bit();

        assert_eq!(
            Inst::decode_compressed(&config64, op),
            Some(Inst::Store {
                kind: StoreKind::U64,
                src: Reg::A2,
                base: Reg::SP,
                offset: 0b010101000
            })
        );

        assert_eq!(Inst::decode_compressed(&config, op), None);
    }

    proptest::proptest! {
        #[test]
        fn c_invalid_q0(value in BitSetStrategy::masked(0b000_111_111_11_111_00)) {
            let op = 0b001_000_000_00_000_00 | value;
            let config = DecoderConfig::new_32bit();

            // C.FLD; C.LQ
            assert_eq!(Inst::decode_compressed(&config, op), None);

            let op = 0b011_000_000_00_000_00 | value;
            // C.FLW; C.LD
            assert_eq!(Inst::decode_compressed(&config, op), None);

            let op = 0b100_000_000_00_000_00 | value;
            // reserved
            assert_eq!(Inst::decode_compressed(&config, op), None);

            let op = 0b101_000_000_00_000_00 | value;
            // C.FSD; C.SQ
            assert_eq!(Inst::decode_compressed(&config, op), None);

            let op = 0b111_000_000_00_000_00 | value;
            // C.FSw; C.SD
            assert_eq!(Inst::decode_compressed(&config, op), None);
        }

        #[test]
        fn c_invalid_q1(value in BitSetStrategy::masked(0b000_0_00_111_00_000_00)) {
            let op = 0b100_1_11_000_00_000_01 | value;
            let config = DecoderConfig::new_32bit();

            // C.SUBW
            assert_eq!(Inst::decode_compressed(&config, op), None);

            let op = 0b100_1_11_000_01_000_01 | value;
            // C.ADDW
            assert_eq!(Inst::decode_compressed(&config, op), None);

            let op = 0b100_1_11_000_10_000_01 | value;
            // reserved
            assert_eq!(Inst::decode_compressed(&config, op), None);

            let op = 0b100_1_11_000_11_000_01 | value;
            // reserved
            assert_eq!(Inst::decode_compressed(&config, op), None);
        }

        #[test]
        fn c_invalid_q2(value in BitSetStrategy::masked(0b000_1_11111_11111_00)) {
            let op = 0b001_0_00000_00000_10 | value;
            let config = DecoderConfig::new_32bit();

            // C.FLDSP; C.LQSP
            assert_eq!(Inst::decode_compressed(&config, op), None);

            let op = 0b011_0_00000_00000_10 | value;
            // C.FLWSP; C.LDSP
            assert_eq!(Inst::decode_compressed(&config, op), None);

            let op = 0b101_0_00000_00000_10 | value;
            // C.FSDSP; C.SQSP
            assert_eq!(Inst::decode_compressed(&config, op), None);
        }

        #[test]
        fn c_reserved(value in BitSetStrategy::masked(0b000_0_00_111_00_111_00)) {
            let op = 0b100_1_11_000_10_000_01 | value;
            let config = DecoderConfig::new_32bit();

            // reserved
            assert_eq!(Inst::decode_compressed(&config, op), None);

            let op = 0b100_1_11_000_11_000_01 | value;
            // reserved
            assert_eq!(Inst::decode_compressed(&config, op), None);
        }
    }

    #[test]
    fn enumerate_all_compressed_32bit() {
        for op in 0..u16::MAX {
            super::Inst::decode(&DecoderConfig::new_32bit(), u32::from(op));
        }
    }

    #[test]
    fn enumerate_all_compressed_64bit() {
        for op in 0..u16::MAX {
            super::Inst::decode(&DecoderConfig::new_64bit(), u32::from(op));
        }
    }
}
