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
#[repr(u8)]
pub enum BranchKind {
    Eq = 0b000,
    NotEq = 0b001,
    LessSigned = 0b100,
    GreaterOrEqualSigned = 0b101,
    LessUnsigned = 0b110,
    GreaterOrEqualUnsigned = 0b111,
}

impl BranchKind {
    #[inline(always)]
    const fn decode(value: u32) -> Option<Self> {
        match value & 0b111 {
            0b000 => Some(BranchKind::Eq),
            0b001 => Some(BranchKind::NotEq),
            0b100 => Some(BranchKind::LessSigned),
            0b101 => Some(BranchKind::GreaterOrEqualSigned),
            0b110 => Some(BranchKind::LessUnsigned),
            0b111 => Some(BranchKind::GreaterOrEqualUnsigned),
            _ => None,
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Hash)]
#[repr(u8)]
pub enum LoadKind {
    I8 = 0b000,
    I16 = 0b001,
    U32 = 0b010,
    U8 = 0b100,
    U16 = 0b101,
}

impl LoadKind {
    #[inline(always)]
    const fn decode(value: u32) -> Option<Self> {
        match value & 0b111 {
            0b000 => Some(LoadKind::I8),
            0b001 => Some(LoadKind::I16),
            0b010 => Some(LoadKind::U32),
            0b100 => Some(LoadKind::U8),
            0b101 => Some(LoadKind::U16),
            _ => None,
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Hash)]
#[repr(u8)]
pub enum StoreKind {
    U8 = 0b000,
    U16 = 0b001,
    U32 = 0b010,
}

impl StoreKind {
    #[inline(always)]
    const fn decode(value: u32) -> Option<Self> {
        match value & 0b111 {
            0b000 => Some(StoreKind::U8),
            0b001 => Some(StoreKind::U16),
            0b010 => Some(StoreKind::U32),
            _ => None,
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Hash)]
#[repr(u8)]
pub enum RegImmKind {
    Add = 0b000,                 // ADDI
    SetLessThanSigned = 0b010,   // SLTI
    SetLessThanUnsigned = 0b011, // SLTIU
    Xor = 0b100,                 // XORI
    Or = 0b110,                  // ORI
    And = 0b111,                 // ANDI

    ShiftLogicalLeft,
    ShiftLogicalRight,
    ShiftArithmeticRight,
}

impl RegImmKind {
    #[inline(always)]
    const fn decode(value: u32) -> Option<Self> {
        match value & 0b111 {
            0b000 => Some(Self::Add),
            0b010 => Some(Self::SetLessThanSigned),
            0b011 => Some(Self::SetLessThanUnsigned),
            0b100 => Some(Self::Xor),
            0b110 => Some(Self::Or),
            0b111 => Some(Self::And),
            _ => None,
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Hash)]
#[repr(u8)]
pub enum RegRegKind {
    Add = 0b00000,
    Sub = 0b10000,
    ShiftLogicalLeft = 0b00001,
    SetLessThanSigned = 0b00010,
    SetLessThanUnsigned = 0b00011,
    Xor = 0b00100,
    ShiftLogicalRight = 0b00101,
    ShiftArithmeticRight = 0b10101,
    Or = 0b00110,
    And = 0b00111,
    Mul = 0b01000,
    MulUpperSignedSigned = 0b01001,
    MulUpperSignedUnsigned = 0b01010,
    MulUpperUnsignedUnsigned = 0b01011,
    Div = 0b01100,
    DivUnsigned = 0b01101,
    Rem = 0b01110,
    RemUnsigned = 0b01111,
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
    RegReg {
        kind: RegRegKind,
        dst: Reg,
        src1: Reg,
        src2: Reg,
    },
    Ecall,
    Unimplemented,
    Fence {
        predecessor: FenceFlags,
        successor: FenceFlags,
    },
    FenceI,
    LoadReserved {
        acquire: bool,
        release: bool,
        dst: Reg,
        src: Reg,
    },
    StoreConditional {
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
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Hash)]
pub enum AtomicKind {
    Swap = 0b00001,
    Add = 0b00000,
    And = 0b01100,
    Or = 0b01000,
    Xor = 0b00100,
    MaxSigned = 0b10100,
    MinSigned = 0b10000,
    MaxUnsigned = 0b11100,
    MinUnsigned = 0b11000,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Hash)]
pub enum CmovKind {
    EqZero = 0b111,
    NotEqZero = 0b101,
}

impl Reg {
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

impl Inst {
    pub fn decode(op: u32) -> Option<Self> {
        // This is mostly unofficial, but it's a defacto standard used by both LLVM and GCC.
        // https://github.com/riscv-non-isa/riscv-asm-manual/blob/master/riscv-asm.md#instruction-aliases
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
                kind: BranchKind::decode(op >> 12)?,
                src1: Reg::decode(op >> 15),
                src2: Reg::decode(op >> 20),
                target: sign_ext(
                    bits(1, 4, op, 8) | bits(5, 10, op, 25) | bits(11, 11, op, 7) | bits(12, 12, op, 31),
                    13,
                ) as u32,
            }),
            0b0000011 => Some(Inst::Load {
                kind: LoadKind::decode(op >> 12)?,
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
                    if op & 0xfe000000 != 0 {
                        return None;
                    }

                    Some(Inst::RegImm {
                        kind: RegImmKind::ShiftLogicalLeft,
                        dst: Reg::decode(op >> 7),
                        src: Reg::decode(op >> 15),
                        imm: bits(0, 4, op, 20) as i32,
                    })
                }
                0b101 => {
                    let kind = match (op & 0xfe000000) >> 24 {
                        0b00000000 => RegImmKind::ShiftLogicalRight,
                        0b01000000 => RegImmKind::ShiftArithmeticRight,
                        _ => return None,
                    };

                    Some(Inst::RegImm {
                        kind,
                        dst: Reg::decode(op >> 7),
                        src: Reg::decode(op >> 15),
                        imm: bits(0, 4, op, 20) as i32,
                    })
                }
                _ => Some(Inst::RegImm {
                    kind: RegImmKind::decode(op >> 12)?,
                    dst: Reg::decode(op >> 7),
                    src: Reg::decode(op >> 15),
                    imm: sign_ext(op >> 20, 12),
                }),
            },
            0b0110011 => {
                let dst = Reg::decode(op >> 7);
                let src1 = Reg::decode(op >> 15);
                let src2 = Reg::decode(op >> 20);
                let kind = match op & 0b1111111_00000_00000_111_00000_0000000 {
                    0b0000000_00000_00000_000_00000_0000000 => RegRegKind::Add,
                    0b0100000_00000_00000_000_00000_0000000 => RegRegKind::Sub,
                    0b0000000_00000_00000_001_00000_0000000 => RegRegKind::ShiftLogicalLeft,
                    0b0000000_00000_00000_010_00000_0000000 => RegRegKind::SetLessThanSigned,
                    0b0000000_00000_00000_011_00000_0000000 => RegRegKind::SetLessThanUnsigned,
                    0b0000000_00000_00000_100_00000_0000000 => RegRegKind::Xor,
                    0b0000000_00000_00000_101_00000_0000000 => RegRegKind::ShiftLogicalRight,
                    0b0100000_00000_00000_101_00000_0000000 => RegRegKind::ShiftArithmeticRight,
                    0b0000000_00000_00000_110_00000_0000000 => RegRegKind::Or,
                    0b0000000_00000_00000_111_00000_0000000 => RegRegKind::And,

                    0b0000001_00000_00000_000_00000_0000000 => RegRegKind::Mul,
                    0b0000001_00000_00000_001_00000_0000000 => RegRegKind::MulUpperSignedSigned,
                    0b0000001_00000_00000_010_00000_0000000 => RegRegKind::MulUpperSignedUnsigned,
                    0b0000001_00000_00000_011_00000_0000000 => RegRegKind::MulUpperUnsignedUnsigned,
                    0b0000001_00000_00000_100_00000_0000000 => RegRegKind::Div,
                    0b0000001_00000_00000_101_00000_0000000 => RegRegKind::DivUnsigned,
                    0b0000001_00000_00000_110_00000_0000000 => RegRegKind::Rem,
                    0b0000001_00000_00000_111_00000_0000000 => RegRegKind::RemUnsigned,

                    0b0000111_00000_00000_101_00000_0000000 => {
                        return Some(Inst::Cmov {
                            kind: CmovKind::NotEqZero,
                            dst,
                            src: src1,
                            cond: src2,
                        });
                    }
                    0b0000111_00000_00000_111_00000_0000000 => {
                        return Some(Inst::Cmov {
                            kind: CmovKind::EqZero,
                            dst,
                            src: src1,
                            cond: src2,
                        });
                    }

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
                } else if (op & !(0xff << 20)) == 0x0000000f {
                    Some(Inst::Fence {
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
            0b0101111 if (op >> 12) & 0b111 == 0b010 => {
                let dst = Reg::decode(op >> 7);
                let src1 = Reg::decode(op >> 15);
                let src2 = Reg::decode(op >> 20);
                let kind = op >> 27;
                let release = ((op >> 25) & 1) != 0;
                let acquire = ((op >> 26) & 1) != 0;
                match kind {
                    0b00010 if src2 == Reg::Zero => Some(Inst::LoadReserved {
                        acquire,
                        release,
                        dst,
                        src: src1,
                    }),
                    0b00011 => Some(Inst::StoreConditional {
                        acquire,
                        release,
                        addr: src1,
                        dst,
                        src: src2,
                    }),
                    _ => {
                        let kind = match kind {
                            0b00000 => AtomicKind::Add,
                            0b00001 => AtomicKind::Swap,
                            0b00100 => AtomicKind::Xor,
                            0b01100 => AtomicKind::And,
                            0b01000 => AtomicKind::Or,
                            0b10000 => AtomicKind::MinSigned,
                            0b10100 => AtomicKind::MaxSigned,
                            0b11000 => AtomicKind::MinUnsigned,
                            0b11100 => AtomicKind::MaxUnsigned,
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
            _ => None,
        }
    }

    #[cfg(test)]
    pub fn encode(self) -> Option<u32> {
        match self {
            Inst::LoadUpperImmediate { dst, value } => {
                if value & 0xfff != 0 {
                    return None;
                }

                Some(0b0110111 | ((dst as u32) << 7) | value)
            }
            Inst::AddUpperImmediateToPc { dst, value } => {
                if value & 0xfff != 0 {
                    return None;
                }

                Some(0b0010111 | ((dst as u32) << 7) | value)
            }
            Inst::JumpAndLink { dst, target } => {
                let imm = sign_unext(target, 21)?;
                Some(
                    0b1101111
                        | ((dst as u32) << 7)
                        | unbits(1, 10, imm, 21)
                        | unbits(11, 11, imm, 20)
                        | unbits(12, 19, imm, 12)
                        | unbits(20, 20, imm, 31),
                )
            }
            Inst::JumpAndLinkRegister { dst, base, value } => {
                Some(0b1100111 | ((dst as u32) << 7) | ((base as u32) << 15) | (sign_unext(value as u32, 12)? << 20))
            }
            Inst::Load { kind, dst, base, offset } => {
                Some(0b0000011 | ((kind as u32) << 12) | ((dst as u32) << 7) | ((base as u32) << 15) | sign_unext(offset as u32, 12)? << 20)
            }
            Inst::Store { kind, src, base, offset } => {
                let imm = sign_unext(offset as u32, 12)?;
                Some(
                    0b0100011
                        | ((kind as u32) << 12)
                        | ((base as u32) << 15)
                        | ((src as u32) << 20)
                        | unbits(0, 4, imm, 7)
                        | unbits(5, 11, imm, 25),
                )
            }
            Inst::Branch { kind, src1, src2, target } => {
                let imm = sign_unext(target, 13)?;
                Some(
                    0b1100011
                        | ((kind as u32) << 12)
                        | ((src1 as u32) << 15)
                        | ((src2 as u32) << 20)
                        | unbits(1, 4, imm, 8)
                        | unbits(5, 10, imm, 25)
                        | unbits(11, 11, imm, 7)
                        | unbits(12, 12, imm, 31),
                )
            }
            Inst::RegImm { kind, dst, src, mut imm } => match kind {
                RegImmKind::ShiftLogicalLeft | RegImmKind::ShiftLogicalRight | RegImmKind::ShiftArithmeticRight => {
                    if imm > 32 {
                        imm = 32;
                    } else if imm < 0 {
                        imm = 0;
                    }

                    Some(
                        0b0010011
                            | match kind {
                                RegImmKind::ShiftLogicalLeft => 0b001 << 12,
                                RegImmKind::ShiftLogicalRight => 0b101 << 12,
                                RegImmKind::ShiftArithmeticRight => (0b101 << 12) | (1 << 30),
                                _ => unreachable!(),
                            }
                            | ((dst as u32) << 7)
                            | ((src as u32) << 15)
                            | unbits(0, 4, imm as u32, 20),
                    )
                }
                _ => {
                    Some(0b0010011 | ((kind as u32) << 12) | ((dst as u32) << 7) | ((src as u32) << 15) | sign_unext(imm as u32, 12)? << 20)
                }
            },

            Inst::RegReg { kind, dst, src1, src2 } => Some(
                0b0110011
                    | ((kind as u32 & 0b00111) << 12)
                    | ((kind as u32 & 0b01000) << 22)
                    | ((kind as u32 & 0b10000) << 26)
                    | ((dst as u32) << 7)
                    | ((src1 as u32) << 15)
                    | ((src2 as u32) << 20),
            ),
            Inst::Ecall => Some(0x00000073),
            Inst::FenceI => Some(0x0000100f),
            Inst::Fence { predecessor, successor } => Some(
                0b00001111
                    | (u32::from(predecessor.input) << 27)
                    | (u32::from(predecessor.output) << 26)
                    | (u32::from(predecessor.read) << 25)
                    | (u32::from(predecessor.write) << 24)
                    | (u32::from(successor.input) << 23)
                    | (u32::from(successor.output) << 22)
                    | (u32::from(successor.read) << 21)
                    | (u32::from(successor.write) << 20),
            ),
            Inst::Unimplemented => Some(0xc0001073),
            Inst::LoadReserved {
                acquire,
                release,
                dst,
                src,
            } => Some(
                0b0101111
                    | (0b010 << 12)
                    | ((dst as u32) << 7)
                    | ((src as u32) << 15)
                    | (u32::from(release) << 25)
                    | (u32::from(acquire) << 26)
                    | (0b00010 << 27),
            ),
            Inst::StoreConditional {
                acquire,
                release,
                addr,
                dst,
                src,
            } => Some(
                0b0101111
                    | (0b010 << 12)
                    | ((dst as u32) << 7)
                    | ((addr as u32) << 15)
                    | ((src as u32) << 20)
                    | (u32::from(release) << 25)
                    | (u32::from(acquire) << 26)
                    | (0b00011 << 27),
            ),
            Inst::Atomic {
                acquire,
                release,
                kind,
                dst,
                addr,
                src,
            } => Some(
                0b0101111
                    | (0b010 << 12)
                    | ((dst as u32) << 7)
                    | ((addr as u32) << 15)
                    | ((src as u32) << 20)
                    | (u32::from(release) << 25)
                    | (u32::from(acquire) << 26)
                    | ((kind as u32) << 27),
            ),
            Inst::Cmov { kind, dst, src, cond } => {
                Some(0b0110011 | ((kind as u32) << 12) | ((dst as u32) << 7) | ((src as u32) << 15) | ((cond as u32) << 20) | (0b111 << 25))
            }
        }
    }
}

#[test]
fn test_decode_jump_and_link() {
    assert_eq!(
        Inst::decode(0xd6dff06f).unwrap(),
        Inst::JumpAndLink {
            dst: Reg::Zero,
            target: 0x9f40_u32.wrapping_sub(0xa1d4)
        }
    );
}

#[test]
fn test_decode_branch() {
    assert_eq!(
        Inst::decode(0x00c5fe63).unwrap(),
        Inst::Branch {
            kind: BranchKind::GreaterOrEqualUnsigned,
            src1: Reg::A1,
            src2: Reg::A2,
            target: 0x8c - 0x70
        }
    );

    assert_eq!(
        Inst::decode(0xfeb96ce3).unwrap(),
        Inst::Branch {
            kind: BranchKind::LessUnsigned,
            src1: Reg::S2,
            src2: Reg::A1,
            target: 0xccbc_u32.wrapping_sub(0xccc4)
        }
    );
}

#[test]
fn test_decode_multiply() {
    assert_eq!(
        // 02f333b3                mulhu   t2,t1,a5
        Inst::decode(0x02f333b3).unwrap(),
        Inst::RegReg {
            kind: RegRegKind::MulUpperUnsignedUnsigned,
            dst: Reg::T2,
            src1: Reg::T1,
            src2: Reg::A5,
        }
    );

    assert_eq!(
        // 029426b3                mulhsu  a3,s0,s1
        Inst::decode(0x029426b3).unwrap(),
        Inst::RegReg {
            kind: RegRegKind::MulUpperSignedUnsigned,
            dst: Reg::A3,
            src1: Reg::S0,
            src2: Reg::S1,
        }
    );

    assert_eq!(
        // 02941633                mulh    a2,s0,s1
        Inst::decode(0x02941633).unwrap(),
        Inst::RegReg {
            kind: RegRegKind::MulUpperSignedSigned,
            dst: Reg::A2,
            src1: Reg::S0,
            src2: Reg::S1,
        }
    );
}

#[test]
fn test_decode_cmov() {
    assert_eq!(
        Inst::decode(0xec5f5b3).unwrap(),
        Inst::Cmov {
            kind: CmovKind::EqZero,
            dst: Reg::A1,
            src: Reg::A1,
            cond: Reg::A2
        }
    );

    assert_eq!(
        Inst::decode(0xec55533).unwrap(),
        Inst::Cmov {
            kind: CmovKind::NotEqZero,
            dst: Reg::A0,
            src: Reg::A0,
            cond: Reg::A2
        }
    );
}

#[cfg_attr(debug_assertions, ignore)]
#[test]
fn test_encode() {
    for op in 0..=0xFFFFFFFF_u32 {
        if let Some(inst) = Inst::decode(op) {
            let encoded = inst.encode();
            if encoded != Some(op) {
                panic!(
                    "failed to encode instruction: {inst:?}, expected = 0x{expected:08x} (0b{expected:b}, {expected}), actual = {actual} ({actual_binary}, {actual_dec})",
                    inst = inst,
                    expected = op,
                    actual = encoded.map_or_else(|| "None".to_owned(), |encoded| format!("0x{:08x}", encoded)),
                    actual_binary = encoded.map_or_else(|| "None".to_owned(), |encoded| format!("{:b}", encoded)),
                    actual_dec = encoded.map_or_else(|| "None".to_owned(), |encoded| format!("{}", encoded)),
                );
            }
        }
    }
}
