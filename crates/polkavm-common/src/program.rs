use crate::utils::{CowBytes, CowString};
use crate::varint::{read_varint, write_varint, MAX_VARINT_LENGTH};
use core::ops::Range;

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum ExternTy {
    I32 = 1,
    I64 = 2,
}

impl core::fmt::Display for ExternTy {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
        let name = match *self {
            ExternTy::I32 => "i32",
            ExternTy::I64 => "i64",
        };

        fmt.write_str(name)
    }
}

impl ExternTy {
    pub fn try_deserialize(value: u8) -> Option<Self> {
        use ExternTy::*;
        match value {
            1 => Some(I32),
            2 => Some(I64),
            _ => None,
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Hash)]
#[repr(u8)]
pub enum Reg {
    Zero = 0,
    RA = 1,
    SP = 2,
    T0 = 3,
    T1 = 4,
    T2 = 5,
    S0 = 6,
    S1 = 7,
    A0 = 8,
    A1 = 9,
    A2 = 10,
    A3 = 11,
    A4 = 12,
    A5 = 13,
}

impl Reg {
    #[inline]
    pub const fn from_u8(value: u8) -> Option<Reg> {
        match value {
            0 => Some(Reg::Zero),
            1 => Some(Reg::RA),
            2 => Some(Reg::SP),
            3 => Some(Reg::T0),
            4 => Some(Reg::T1),
            5 => Some(Reg::T2),
            6 => Some(Reg::S0),
            7 => Some(Reg::S1),
            8 => Some(Reg::A0),
            9 => Some(Reg::A1),
            10 => Some(Reg::A2),
            11 => Some(Reg::A3),
            12 => Some(Reg::A4),
            13 => Some(Reg::A5),
            _ => None,
        }
    }

    pub const fn name(self) -> &'static str {
        use Reg::*;
        match self {
            Zero => "zero",
            RA => "ra",
            SP => "sp",
            T0 => "t0",
            T1 => "t1",
            T2 => "t2",
            S0 => "s0",
            S1 => "s1",
            A0 => "a0",
            A1 => "a1",
            A2 => "a2",
            A3 => "a3",
            A4 => "a4",
            A5 => "a5",
        }
    }

    /// List of all of the VM's registers, except the zero register.
    pub const ALL_NON_ZERO: [Reg; 13] = {
        use Reg::*;
        [RA, SP, T0, T1, T2, S0, S1, A0, A1, A2, A3, A4, A5]
    };

    /// List of all argument registers.
    pub const ARG_REGS: [Reg; 6] = [Reg::A0, Reg::A1, Reg::A2, Reg::A3, Reg::A4, Reg::A5];
}

impl core::fmt::Display for Reg {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
        fmt.write_str(self.name())
    }
}

macro_rules! define_opcodes {
    (@impl_shared $($name:ident = $value:expr,)+) => {
        #[allow(non_camel_case_types)]
        #[derive(Copy, Clone, PartialEq, Eq, Debug, Hash)]
        #[repr(u8)]
        pub enum Opcode {
            $(
                $name = $value,
            )+
        }

        impl Opcode {
            pub fn from_u8(byte: u8) -> Option<Opcode> {
                match byte {
                    $($value => Some(Opcode::$name),)+
                    _ => None
                }
            }
        }

        const IS_INSTRUCTION_VALID_CONST: [bool; 256] = {
            let mut is_valid = [false; 256];
            $(
                is_valid[$value] = true;
            )+
            is_valid
        };

        #[cfg(feature = "alloc")]
        static IS_INSTRUCTION_VALID: [bool; 256] = IS_INSTRUCTION_VALID_CONST;

        #[cfg(not(feature = "alloc"))]
        use IS_INSTRUCTION_VALID_CONST as IS_INSTRUCTION_VALID;
    };

    (
        [$($name_argless:ident = $value_argless:expr,)+]
        [$($name_with_imm:ident = $value_with_imm:expr,)+]
        [$($name_with_regs3:ident = $value_with_regs3:expr,)+]
        [$($name_with_regs2_imm:ident = $value_with_regs2_imm:expr,)+]
    ) => {
        pub trait InstructionVisitor {
            type ReturnTy;
            $(fn $name_argless(&mut self) -> Self::ReturnTy;)+
            $(fn $name_with_imm(&mut self, imm: u32) -> Self::ReturnTy;)+
            $(fn $name_with_regs3(&mut self, reg1: Reg, reg2: Reg, reg3: Reg) -> Self::ReturnTy;)+
            $(fn $name_with_regs2_imm(&mut self, reg1: Reg, reg2: Reg, imm: u32) -> Self::ReturnTy;)+
        }

        impl RawInstruction {
            pub fn visit<T>(self, visitor: &mut T) -> T::ReturnTy where T: InstructionVisitor {
                match self.op {
                    $($value_argless => visitor.$name_argless(),)+
                    $($value_with_imm => visitor.$name_with_imm(self.imm_or_reg),)+
                    $($value_with_regs3 => visitor.$name_with_regs3(self.reg1(), self.reg2(), self.reg3()),)+
                    $($value_with_regs2_imm => visitor.$name_with_regs2_imm(self.reg1(), self.reg2(), self.imm_or_reg),)+
                    _ => unreachable!()
                }
            }
        }

        impl core::fmt::Display for RawInstruction {
            fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
                self.visit(fmt)
            }
        }

        define_opcodes!(
            @impl_shared
            $($name_argless = $value_argless,)+
            $($name_with_imm = $value_with_imm,)+
            $($name_with_regs3 = $value_with_regs3,)+
            $($name_with_regs2_imm = $value_with_regs2_imm,)+
        );
    }
}

define_opcodes! {
    // 1 byte instructions
    // Instructions with no args.
    [
        trap                            = 0b00_000000,
    ]

    // 1-6 byte instructions
    // Instructions with args: imm
    [
        jump_target                     = 0b01_000000,
        ecalli                          = 0b01_111111,
    ]

    // 3 byte instructions
    // Instructions with args: reg, reg, reg
    [
        set_less_than_unsigned          = 0b10_000000,
        set_less_than_signed            = 0b10_000001,
        shift_logical_right             = 0b10_000010,
        shift_arithmetic_right          = 0b10_000011,
        shift_logical_left              = 0b10_000100,
        or                              = 0b10_000101,
        and                             = 0b10_000110,
        xor                             = 0b10_000111,
        add                             = 0b10_001000,
        sub                             = 0b10_001001,

        mul                             = 0b10_010000,
        mul_upper_signed_signed         = 0b10_010001,
        mul_upper_unsigned_unsigned     = 0b10_010010,
        mul_upper_signed_unsigned       = 0b10_010011,
        div_unsigned                    = 0b10_010100,
        div_signed                      = 0b10_010101,
        rem_unsigned                    = 0b10_010110,
        rem_signed                      = 0b10_010111,
    ]

    // 2-7 byte instructions
    // Instructions with args: reg, reg, imm
    [
        set_less_than_unsigned_imm      = 0b11_000000,
        set_less_than_signed_imm        = 0b11_000001,
        shift_logical_right_imm         = 0b11_000010,
        shift_arithmetic_right_imm      = 0b11_000011,
        shift_logical_left_imm          = 0b11_000100,
        or_imm                          = 0b11_000101,
        and_imm                         = 0b11_000110,
        xor_imm                         = 0b11_000111,
        add_imm                         = 0b11_001000,

        store_u8                        = 0b11_010000,
        store_u16                       = 0b11_010010,
        store_u32                       = 0b11_010100,

        load_u8                         = 0b11_100000,
        load_i8                         = 0b11_100001,
        load_u16                        = 0b11_100010,
        load_i16                        = 0b11_100011,
        load_u32                        = 0b11_100100,

        branch_less_unsigned            = 0b11_110000,
        branch_less_signed              = 0b11_110001,
        branch_greater_or_equal_unsigned= 0b11_110010,
        branch_greater_or_equal_signed  = 0b11_110011,
        branch_eq                       = 0b11_110100,
        branch_not_eq                   = 0b11_110101,

        jump_and_link_register          = 0b11_111111,
    ]
}

pub const MAX_INSTRUCTION_LENGTH: usize = MAX_VARINT_LENGTH + 2;

#[derive(Copy, Clone, PartialEq, Eq)]
pub struct RawInstruction {
    op: u8,
    regs: u8,
    imm_or_reg: u32,
}

impl core::fmt::Debug for RawInstruction {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(fmt, "({:02x} {:02x} {:08x}) {}", self.op, self.regs, self.imm_or_reg, self)
    }
}

impl<'a> InstructionVisitor for core::fmt::Formatter<'a> {
    type ReturnTy = core::fmt::Result;

    fn trap(&mut self) -> Self::ReturnTy {
        write!(self, "trap")
    }

    fn jump_target(&mut self, pcrel: u32) -> Self::ReturnTy {
        write!(self, "@{:x}:", pcrel * 4)
    }

    fn ecalli(&mut self, imm: u32) -> Self::ReturnTy {
        write!(self, "ecalli {}", imm)
    }

    fn set_less_than_unsigned(&mut self, d: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        write!(self, "{} = {} <u {}", d, s1, s2)
    }

    fn set_less_than_signed(&mut self, d: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        write!(self, "{} = {} <s {}", d, s1, s2)
    }

    fn shift_logical_right(&mut self, d: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        write!(self, "{} = {} >> {}", d, s1, s2)
    }

    fn shift_arithmetic_right(&mut self, d: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        write!(self, "{} = {} >>a {}", d, s1, s2)
    }

    fn shift_logical_left(&mut self, d: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        write!(self, "{} = {} << {}", d, s1, s2)
    }

    fn xor(&mut self, d: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        write!(self, "{} = {} ^ {}", d, s1, s2)
    }

    fn and(&mut self, d: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        write!(self, "{} = {} & {}", d, s1, s2)
    }

    fn or(&mut self, d: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        write!(self, "{} = {} | {}", d, s1, s2)
    }

    fn add(&mut self, d: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        write!(self, "{} = {} + {}", d, s1, s2)
    }

    fn sub(&mut self, d: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        write!(self, "{} = {} - {}", d, s1, s2)
    }

    fn mul(&mut self, d: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        write!(self, "{} = {} * {}", d, s1, s2)
    }

    fn mul_upper_signed_signed(&mut self, d: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        write!(self, "{} = ({} as i64 * {} as i64) >> 32", d, s1, s2)
    }

    fn mul_upper_unsigned_unsigned(&mut self, d: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        write!(self, "{} = ({} as u64 * {} as u64) >> 32", d, s1, s2)
    }

    fn mul_upper_signed_unsigned(&mut self, d: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        write!(self, "{} = ({} as i64 * {} as u64) >> 32", d, s1, s2)
    }

    fn div_unsigned(&mut self, d: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        write!(self, "{} = {} /u {}", d, s1, s2)
    }

    fn div_signed(&mut self, d: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        write!(self, "{} = {} /s {}", d, s1, s2)
    }

    fn rem_unsigned(&mut self, d: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        write!(self, "{} = {} %u {}", d, s1, s2)
    }

    fn rem_signed(&mut self, d: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        write!(self, "{} = {} %s {}", d, s1, s2)
    }

    fn set_less_than_unsigned_imm(&mut self, dst: Reg, src: Reg, imm: u32) -> Self::ReturnTy {
        write!(self, "{} = {} <u 0x{:x}", dst, src, imm)
    }

    fn set_less_than_signed_imm(&mut self, dst: Reg, src: Reg, imm: u32) -> Self::ReturnTy {
        write!(self, "{} = {} <s {}", dst, src, imm as i32)
    }

    fn shift_logical_right_imm(&mut self, d: Reg, s: Reg, imm: u32) -> Self::ReturnTy {
        write!(self, "{} = {} >> {}", d, s, imm)
    }

    fn shift_arithmetic_right_imm(&mut self, d: Reg, s: Reg, imm: u32) -> Self::ReturnTy {
        write!(self, "{} = {} >>a {}", d, s, imm)
    }

    fn shift_logical_left_imm(&mut self, d: Reg, s: Reg, imm: u32) -> Self::ReturnTy {
        write!(self, "{} = {} << {}", d, s, imm)
    }

    fn or_imm(&mut self, d: Reg, s: Reg, imm: u32) -> Self::ReturnTy {
        write!(self, "{} = {} | 0x{:x}", d, s, imm)
    }

    fn and_imm(&mut self, d: Reg, s: Reg, imm: u32) -> Self::ReturnTy {
        write!(self, "{} = {} & 0x{:x}", d, s, imm)
    }

    fn xor_imm(&mut self, d: Reg, s: Reg, imm: u32) -> Self::ReturnTy {
        write!(self, "{} = {} ^ 0x{:x}", d, s, imm)
    }

    fn add_imm(&mut self, d: Reg, s: Reg, imm: u32) -> Self::ReturnTy {
        if d == Reg::Zero && s == Reg::Zero && imm == 0 {
            write!(self, "nop")
        } else if imm == 0 {
            write!(self, "{} = {}", d, s)
        } else if (imm as i32) < 0 && (imm as i32) > -4096 {
            let imm_s = -(imm as i32);
            if s == Reg::Zero {
                write!(self, "{} = -{}", d, imm_s)
            } else {
                write!(self, "{} = {} - {}", d, s, imm_s)
            }
        } else if s == Reg::Zero {
            write!(self, "{} = 0x{:x}", d, imm)
        } else {
            write!(self, "{} = {} + 0x{:x}", d, s, imm)
        }
    }

    fn store_u8(&mut self, src: Reg, base: Reg, offset: u32) -> Self::ReturnTy {
        if base != Reg::Zero {
            if offset != 0 {
                write!(self, "u8 [{} + {}] = {}", base, offset, src)
            } else {
                write!(self, "u8 [{}] = {}", base, src)
            }
        } else {
            write!(self, "u8 [0x{:x}] = {}", offset, src)
        }
    }

    fn store_u16(&mut self, src: Reg, base: Reg, offset: u32) -> Self::ReturnTy {
        if base != Reg::Zero {
            if offset != 0 {
                write!(self, "u16 [{} + {}] = {}", base, offset, src)
            } else {
                write!(self, "u16 [{}] = {}", base, src)
            }
        } else {
            write!(self, "u16 [0x{:x}] = {}", offset, src)
        }
    }

    fn store_u32(&mut self, src: Reg, base: Reg, offset: u32) -> Self::ReturnTy {
        if base != Reg::Zero {
            if offset != 0 {
                write!(self, "u32 [{} + {}] = {}", base, offset, src)
            } else {
                write!(self, "u32 [{}] = {}", base, src)
            }
        } else {
            write!(self, "u32 [0x{:x}] = {}", offset, src)
        }
    }

    fn load_u8(&mut self, dst: Reg, base: Reg, offset: u32) -> Self::ReturnTy {
        if base != Reg::Zero {
            if offset != 0 {
                write!(self, "{} = u8 [{} + {}]", dst, base, offset)
            } else {
                write!(self, "{} = u8 [{}]", dst, base)
            }
        } else {
            write!(self, "{} = u8 [0x{:x}]", dst, offset)
        }
    }

    fn load_i8(&mut self, dst: Reg, base: Reg, offset: u32) -> Self::ReturnTy {
        if base != Reg::Zero {
            if offset != 0 {
                write!(self, "{} = i8 [{} + {}]", dst, base, offset)
            } else {
                write!(self, "{} = i8 [{}]", dst, base)
            }
        } else {
            write!(self, "{} = i8 [0x{:x}]", dst, offset)
        }
    }

    fn load_u16(&mut self, dst: Reg, base: Reg, offset: u32) -> Self::ReturnTy {
        if base != Reg::Zero {
            if offset != 0 {
                write!(self, "{} = u16 [{} + {}]", dst, base, offset)
            } else {
                write!(self, "{} = u16 [{} ]", dst, base)
            }
        } else {
            write!(self, "{} = u16 [0x{:x}]", dst, offset)
        }
    }

    fn load_i16(&mut self, dst: Reg, base: Reg, offset: u32) -> Self::ReturnTy {
        if base != Reg::Zero {
            if offset != 0 {
                write!(self, "{} = i16 [{} + {}]", dst, base, offset)
            } else {
                write!(self, "{} = i16 [{}]", dst, base)
            }
        } else {
            write!(self, "{} = i16 [0x{:x}]", dst, offset)
        }
    }

    fn load_u32(&mut self, dst: Reg, base: Reg, offset: u32) -> Self::ReturnTy {
        if base != Reg::Zero {
            if offset != 0 {
                write!(self, "{} = u32 [{} + {}]", dst, base, offset)
            } else {
                write!(self, "{} = u32 [{}]", dst, base)
            }
        } else {
            write!(self, "{} = u32 [0x{:x}]", dst, offset)
        }
    }

    fn branch_less_unsigned(&mut self, s1: Reg, s2: Reg, imm: u32) -> Self::ReturnTy {
        write!(self, "if {} <u {}: jump @{:x}", s1, s2, imm * 4)
    }

    fn branch_less_signed(&mut self, s1: Reg, s2: Reg, imm: u32) -> Self::ReturnTy {
        write!(self, "if {} <s {}: jump @{:x}", s1, s2, imm * 4)
    }

    fn branch_greater_or_equal_unsigned(&mut self, s1: Reg, s2: Reg, imm: u32) -> Self::ReturnTy {
        write!(self, "if {} >=u {}: jump @{:x}", s1, s2, imm * 4)
    }

    fn branch_greater_or_equal_signed(&mut self, s1: Reg, s2: Reg, imm: u32) -> Self::ReturnTy {
        write!(self, "if {} >=s {}: jump @{:x}", s1, s2, imm * 4)
    }

    fn branch_eq(&mut self, s1: Reg, s2: Reg, imm: u32) -> Self::ReturnTy {
        write!(self, "if {} == {}: jump @{:x}", s1, s2, imm * 4)
    }

    fn branch_not_eq(&mut self, s1: Reg, s2: Reg, imm: u32) -> Self::ReturnTy {
        write!(self, "if {} != {}: jump @{:x}", s1, s2, imm * 4)
    }

    fn jump_and_link_register(&mut self, ra: Reg, base: Reg, offset: u32) -> Self::ReturnTy {
        use Reg::*;
        match (ra, base, offset) {
            (Zero, RA, 0) => write!(self, "ret"),
            (Zero, Zero, _) => write!(self, "jump @{:x}", offset * 4),
            (Zero, _, 0) => write!(self, "jump [{}]", base),
            (Zero, _, _) => write!(self, "jump [{} + {}]", base, offset * 4),
            (RA, Zero, _) => write!(self, "call @{:x}", offset * 4),
            (RA, _, 0) => write!(self, "call [{}]", base),
            (RA, _, _) => write!(self, "call [{} + {}]", base, offset * 4),
            (_, Zero, _) => write!(self, "call @{:x}, {}", offset * 4, ra),
            (_, _, 0) => write!(self, "call [{}], {}", base, ra),
            (_, _, _) => write!(self, "call [{} + {}], {}", base, offset * 4, ra),
        }
    }
}

impl RawInstruction {
    #[inline]
    pub fn new_argless(op: Opcode) -> Self {
        assert_eq!(op as u8 & 0b11_000000, 0b00_000000);
        RawInstruction {
            op: op as u8,
            regs: 0,
            imm_or_reg: 0,
        }
    }

    #[inline]
    pub fn new_with_imm(op: Opcode, imm: u32) -> Self {
        assert_eq!(op as u8 & 0b11_000000, 0b01_000000);
        RawInstruction {
            op: op as u8,
            regs: 0,
            imm_or_reg: imm,
        }
    }

    #[inline]
    pub fn new_with_regs3(op: Opcode, reg1: Reg, reg2: Reg, reg3: Reg) -> Self {
        assert_eq!(op as u8 & 0b11_000000, 0b10_000000);
        RawInstruction {
            op: op as u8,
            regs: reg1 as u8 | (reg2 as u8) << 4,
            imm_or_reg: reg3 as u32,
        }
    }

    #[inline]
    pub fn new_with_regs2_imm(op: Opcode, reg1: Reg, reg2: Reg, imm: u32) -> Self {
        assert_eq!(op as u8 & 0b11_000000, 0b11_000000);
        RawInstruction {
            op: op as u8,
            regs: reg1 as u8 | (reg2 as u8) << 4,
            imm_or_reg: imm,
        }
    }

    #[inline]
    pub fn op(self) -> Opcode {
        if let Some(op) = Opcode::from_u8(self.op) {
            op
        } else {
            unreachable!()
        }
    }

    #[inline]
    fn reg1(self) -> Reg {
        Reg::from_u8(self.regs & 0b00001111).unwrap_or_else(|| unreachable!())
    }

    #[inline]
    fn reg2(self) -> Reg {
        Reg::from_u8(self.regs >> 4).unwrap_or_else(|| unreachable!())
    }

    #[inline]
    fn reg3(self) -> Reg {
        Reg::from_u8(self.imm_or_reg as u8).unwrap_or_else(|| unreachable!())
    }

    #[inline]
    pub fn raw_op(self) -> u8 {
        self.op
    }

    #[inline]
    pub fn raw_imm_or_reg(self) -> u32 {
        self.imm_or_reg
    }

    pub fn deserialize(input: &[u8]) -> Option<(usize, Self)> {
        let op = *input.get(0)?;
        if !IS_INSTRUCTION_VALID[op as usize] {
            return None;
        }

        let mut position = 1;
        let mut output = RawInstruction {
            op,
            regs: 0,
            imm_or_reg: 0,
        };

        // Should we load the registers mask?
        if op & 0b10000000 != 0 {
            output.regs = *input.get(position)?;
            if matches!(output.regs & 0b1111, 14 | 15) || matches!(output.regs >> 4, 14 | 15) {
                // Invalid register.
                return None;
            }
            position += 1;
        }

        // Is there at least another byte to load?
        if op & 0b11000000 != 0 {
            let first_byte = *input.get(position)?;
            position += 1;

            if op & 0b11_000000 == 0b10_000000 {
                // It's the third register.
                if first_byte > 13 {
                    // Invalid register.
                    return None;
                }

                output.imm_or_reg = first_byte as u32;
            } else {
                // It's an immediate.
                let (length, imm_or_reg) = read_varint(&input[position..], first_byte)?;
                position += length;
                output.imm_or_reg = imm_or_reg;
            }
        }

        Some((position, output))
    }

    #[inline]
    pub fn serialize_into(self, buffer: &mut [u8]) -> usize {
        assert!(buffer.len() >= MAX_INSTRUCTION_LENGTH);
        buffer[0] = self.op;

        let mut length = 1;
        if self.op & 0b10000000 != 0 {
            buffer[1] = self.regs;
            length += 1;
        }

        if self.op & 0b11000000 != 0 {
            length += write_varint(self.imm_or_reg, &mut buffer[length..]);
        }

        length
    }
}

macro_rules! test_serde {
    ($($serialized:expr => $deserialized:expr,)+) => {
        #[test]
        fn test_deserialize_raw_instruction() {
            $(
                assert_eq!(
                    RawInstruction::deserialize(&$serialized).unwrap(),
                    ($serialized.len(), $deserialized),
                    "failed to deserialize: {:?}", $serialized
                );
            )+
        }

        #[test]
        fn test_serialize_raw_instruction() {
            $(
                {
                    let mut buffer = [0; MAX_INSTRUCTION_LENGTH];
                    let byte_count = $deserialized.serialize_into(&mut buffer);
                    assert_eq!(byte_count, $serialized.len());
                    assert_eq!(&buffer[..byte_count], $serialized);
                    assert!(buffer[byte_count..].iter().all(|&byte| byte == 0));
                }
            )+
        }
    };
}

test_serde! {
    [0b01_111111, 0b01111111] => RawInstruction { op: 0b01_111111, regs: 0, imm_or_reg: 0b01111111 },
    [0b01_111111, 0b10111111, 0b00000000] => RawInstruction { op: 0b01_111111, regs: 0, imm_or_reg: 0b00111111_00000000 },
    [0b01_111111, 0b10111111, 0b10101010] => RawInstruction { op: 0b01_111111, regs: 0, imm_or_reg: 0b00111111_10101010 },
    [0b01_111111, 0b10111111, 0b01010101] => RawInstruction { op: 0b01_111111, regs: 0, imm_or_reg: 0b00111111_01010101 },
    [0b01_111111, 0b10000001, 0b11111111] => RawInstruction { op: 0b01_111111, regs: 0, imm_or_reg: 0b00000001_11111111 },
    [0b01_111111, 0b11000001, 0b10101010, 0b01010101] => RawInstruction { op: 0b01_111111, regs: 0, imm_or_reg: 0b00000001_01010101_10101010 },

    [0b00_000000] => RawInstruction { op: 0b00_000000, regs: 0, imm_or_reg: 0 },

    [0b10_000000, 0b00100001, 0b00000100] => RawInstruction { op: 0b10_000000, regs: 0b00100001, imm_or_reg: 0b00000100 },

    [0b11_000000, 0b00100001, 0b10111111, 0b00000000] => RawInstruction { op: 0b11_000000, regs: 0b00100001, imm_or_reg: 0b00111111_00000000 },
}

#[derive(Debug)]
pub struct ProgramParseError(ProgramParseErrorKind);

#[derive(Debug)]
enum ProgramParseErrorKind {
    FailedToReadVarint {
        offset: usize,
    },
    FailedToReadStringNonUtf {
        offset: usize,
    },
    UnexpectedSection {
        offset: usize,
        section: u8,
    },
    UnexpectedInstruction {
        offset: usize,
    },
    UnexpectedEnd {
        offset: usize,
        expected_count: usize,
        actual_count: usize,
    },
    UnsupportedVersion {
        version: u8,
    },
    Other(&'static str),
}

impl core::fmt::Display for ProgramParseError {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self.0 {
            ProgramParseErrorKind::FailedToReadVarint { offset } => {
                write!(
                    fmt,
                    "failed to parse program blob: failed to parse a varint at offset 0x{:x}",
                    offset
                )
            }
            ProgramParseErrorKind::FailedToReadStringNonUtf { offset } => {
                write!(
                    fmt,
                    "failed to parse program blob: failed to parse a string at offset 0x{:x} (not valid UTF-8)",
                    offset
                )
            }
            ProgramParseErrorKind::UnexpectedSection { offset, section } => {
                write!(
                    fmt,
                    "failed to parse program blob: found unexpected section as offset 0x{:x}: 0x{:x}",
                    offset, section
                )
            }
            ProgramParseErrorKind::UnexpectedInstruction { offset } => {
                write!(
                    fmt,
                    "failed to parse program blob: failed to parse instruction at offset 0x{:x}",
                    offset
                )
            }
            ProgramParseErrorKind::UnexpectedEnd {
                offset,
                expected_count,
                actual_count,
            } => {
                write!(fmt, "failed to parse program blob: unexpected end of file at offset 0x{:x}: expected to be able to read at least {} bytes, found {} bytes", offset, expected_count, actual_count)
            }
            ProgramParseErrorKind::UnsupportedVersion { version } => {
                write!(fmt, "failed to parse program blob: unsupported version: {}", version)
            }
            ProgramParseErrorKind::Other(error) => {
                write!(fmt, "failed to parse program blob: {}", error)
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ProgramParseError {}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ProgramExport<'a> {
    address: u32,
    prototype: ExternFnPrototype<'a>,
}

impl<'a> ProgramExport<'a> {
    pub fn address(&self) -> u32 {
        self.address
    }

    pub fn prototype(&self) -> &ExternFnPrototype<'a> {
        &self.prototype
    }

    #[cfg(feature = "alloc")]
    pub fn into_owned(self) -> ProgramExport<'static> {
        ProgramExport {
            address: self.address,
            prototype: self.prototype.into_owned(),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ProgramImport<'a> {
    index: u32,
    prototype: ExternFnPrototype<'a>,
}

impl<'a> ProgramImport<'a> {
    pub fn index(&self) -> u32 {
        self.index
    }

    pub fn prototype(&self) -> &ExternFnPrototype<'a> {
        &self.prototype
    }

    #[cfg(feature = "alloc")]
    pub fn into_owned(self) -> ProgramImport<'static> {
        ProgramImport {
            index: self.index,
            prototype: self.prototype.into_owned(),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ExternFnPrototype<'a> {
    name: CowString<'a>,
    arg_count: u32,
    args: [Option<ExternTy>; crate::abi::VM_MAXIMUM_EXTERN_ARG_COUNT],
    return_ty: Option<ExternTy>,
}

impl<'a> ExternFnPrototype<'a> {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn args(&'_ self) -> impl ExactSizeIterator<Item = ExternTy> + Clone + '_ {
        #[derive(Clone)]
        struct ArgIter<'r> {
            position: usize,
            length: usize,
            args: &'r [Option<ExternTy>; crate::abi::VM_MAXIMUM_EXTERN_ARG_COUNT],
        }

        impl<'r> Iterator for ArgIter<'r> {
            type Item = ExternTy;

            fn next(&mut self) -> Option<Self::Item> {
                if self.position >= self.length {
                    None
                } else {
                    let ty = self.args[self.position].unwrap();
                    self.position += 1;
                    Some(ty)
                }
            }

            fn size_hint(&self) -> (usize, Option<usize>) {
                let remaining = self.length - self.position;
                (remaining, Some(remaining))
            }
        }

        impl<'r> ExactSizeIterator for ArgIter<'r> {}

        ArgIter {
            position: 0,
            length: self.arg_count as usize,
            args: &self.args,
        }
    }

    pub fn return_ty(&self) -> Option<ExternTy> {
        self.return_ty
    }

    #[cfg(feature = "alloc")]
    pub fn into_owned(self) -> ExternFnPrototype<'static> {
        ExternFnPrototype {
            name: self.name.into_owned(),
            arg_count: self.arg_count,
            args: self.args,
            return_ty: self.return_ty,
        }
    }
}

/// A partially deserialized PolkaVM program.
#[derive(Clone, Default)]
pub struct ProgramBlob<'a> {
    blob: CowBytes<'a>,

    bss_size: u32,
    stack_size: u32,

    ro_data: Range<usize>,
    rw_data: Range<usize>,
    exports: Range<usize>,
    imports: Range<usize>,
    code: Range<usize>,

    debug_strings: Range<usize>,
    debug_line_program_ranges: Range<usize>,
    debug_line_programs: Range<usize>,
}

#[derive(Clone)]
struct Reader<'a> {
    blob: &'a [u8],
    position: usize,
    previous_position: usize,
}

impl<'a> Reader<'a> {
    fn skip(&mut self, count: u32) -> Result<(), ProgramParseError> {
        self.read_slice_as_range(count).map(|_| ())
    }

    fn read_byte(&mut self) -> Result<u8, ProgramParseError> {
        Ok(self.blob[self.read_slice_as_range(1)?][0])
    }

    fn read_varint(&mut self) -> Result<u32, ProgramParseError> {
        let first_byte = self.read_byte()?;
        let (length, value) =
            read_varint(&self.blob[self.position..], first_byte).ok_or(ProgramParseError(ProgramParseErrorKind::FailedToReadVarint {
                offset: self.previous_position,
            }))?;
        self.position += length;
        Ok(value)
    }

    fn read_string_with_length(&mut self) -> Result<&'a str, ProgramParseError> {
        let length = self.read_varint()?;
        let range = self.read_slice_as_range(length)?;
        let slice = &self.blob[range];
        core::str::from_utf8(slice)
            .ok()
            .ok_or(ProgramParseError(ProgramParseErrorKind::FailedToReadStringNonUtf {
                offset: self.previous_position,
            }))
    }

    fn read_slice_as_range(&mut self, count: u32) -> Result<Range<usize>, ProgramParseError> {
        let range = self.position..self.position + count as usize;
        if self.blob.get(range.clone()).is_none() {
            return Err(ProgramParseError(ProgramParseErrorKind::UnexpectedEnd {
                offset: self.position,
                expected_count: count as usize,
                actual_count: self.blob.len() - self.position,
            }));
        };
        self.previous_position = core::mem::replace(&mut self.position, range.end);
        Ok(range)
    }

    fn is_eof(&self) -> bool {
        self.position >= self.blob.len()
    }

    fn read_section_range_into(
        &mut self,
        out_section: &mut u8,
        out_range: &mut Range<usize>,
        expected_section: u8,
    ) -> Result<(), ProgramParseError> {
        if *out_section == expected_section {
            let section_length = self.read_varint()?;
            *out_range = self.read_slice_as_range(section_length)?;
            *out_section = self.read_byte()?;
        }

        Ok(())
    }

    fn read_extern_fn_prototype(&mut self) -> Result<ExternFnPrototype<'a>, ProgramParseError> {
        let name = self.read_string_with_length()?;
        let arg_count = self.read_varint()?;
        if arg_count > crate::abi::VM_MAXIMUM_EXTERN_ARG_COUNT as u32 {
            return Err(ProgramParseError(ProgramParseErrorKind::Other(
                "found a function prototype which accepts more than the maximum allowed number of arguments",
            )));
        }

        let mut args: [Option<ExternTy>; crate::abi::VM_MAXIMUM_EXTERN_ARG_COUNT] = [None; crate::abi::VM_MAXIMUM_EXTERN_ARG_COUNT];
        for nth_arg in 0..arg_count {
            let ty = ExternTy::try_deserialize(self.read_byte()?).ok_or(ProgramParseError(ProgramParseErrorKind::Other(
                "found a function prototype with an unrecognized argument type",
            )))?;
            args[nth_arg as usize] = Some(ty);
        }

        let return_ty = match self.read_byte()? {
            0 => None,
            return_ty => {
                let ty = ExternTy::try_deserialize(return_ty).ok_or(ProgramParseError(ProgramParseErrorKind::Other(
                    "found a function prototype with an unrecognized return type",
                )))?;
                Some(ty)
            }
        };

        Ok(ExternFnPrototype {
            name: name.into(),
            arg_count,
            args,
            return_ty,
        })
    }
}

impl<'a> ProgramBlob<'a> {
    /// Parses the given bytes into a program blob.
    pub fn parse(bytes: impl Into<CowBytes<'a>>) -> Result<Self, ProgramParseError> {
        Self::parse_impl(bytes.into())
    }

    /// Returns the original bytes from which this program blob was created from.
    pub fn as_bytes(&self) -> &[u8] {
        &self.blob
    }

    #[inline(never)]
    fn parse_impl(blob: CowBytes<'a>) -> Result<Self, ProgramParseError> {
        if !blob.starts_with(&BLOB_MAGIC) {
            return Err(ProgramParseError(ProgramParseErrorKind::Other(
                "blob doesn't start with the expected magic bytes",
            )));
        }

        let mut program = ProgramBlob {
            blob,
            ..ProgramBlob::default()
        };

        let mut reader = Reader {
            blob: &program.blob,
            position: BLOB_MAGIC.len(),
            previous_position: 0,
        };

        let blob_version = reader.read_byte()?;
        if blob_version != BLOB_VERSION_V1 {
            return Err(ProgramParseError(ProgramParseErrorKind::UnsupportedVersion {
                version: blob_version,
            }));
        }

        let mut section = reader.read_byte()?;
        if section == SECTION_MEMORY_CONFIG {
            let section_length = reader.read_varint()?;
            let position = reader.position;
            program.bss_size = reader.read_varint()?;
            program.stack_size = reader.read_varint()?;
            if position + section_length as usize != reader.position {
                return Err(ProgramParseError(ProgramParseErrorKind::Other(
                    "the memory config section contains more data than expected",
                )));
            }
            section = reader.read_byte()?;
        }

        reader.read_section_range_into(&mut section, &mut program.ro_data, SECTION_RO_DATA)?;
        reader.read_section_range_into(&mut section, &mut program.rw_data, SECTION_RW_DATA)?;
        reader.read_section_range_into(&mut section, &mut program.imports, SECTION_IMPORTS)?;
        reader.read_section_range_into(&mut section, &mut program.exports, SECTION_EXPORTS)?;
        reader.read_section_range_into(&mut section, &mut program.code, SECTION_CODE)?;
        reader.read_section_range_into(&mut section, &mut program.debug_strings, SECTION_OPT_DEBUG_STRINGS)?;
        reader.read_section_range_into(&mut section, &mut program.debug_line_programs, SECTION_OPT_DEBUG_LINE_PROGRAMS)?;
        reader.read_section_range_into(
            &mut section,
            &mut program.debug_line_program_ranges,
            SECTION_OPT_DEBUG_LINE_PROGRAM_RANGES,
        )?;

        while (section & 0b10000000) != 0 {
            // We don't know this section, but it's optional, so just skip it.
            #[cfg(feature = "logging")]
            log::debug!("Skipping unsupported optional section: {}", section);
            let section_length = reader.read_varint()?;
            reader.skip(section_length)?;
            section = reader.read_byte()?;
        }

        if section == SECTION_END_OF_FILE {
            return Ok(program);
        }

        Err(ProgramParseError(ProgramParseErrorKind::UnexpectedSection {
            offset: reader.previous_position,
            section,
        }))
    }

    /// Returns the contents of the read-only data section.
    pub fn ro_data(&self) -> &[u8] {
        &self.blob[self.ro_data.clone()]
    }

    /// Returns the contents of the read-write data section.
    pub fn rw_data(&self) -> &[u8] {
        &self.blob[self.rw_data.clone()]
    }

    /// Returns the initial size of the BSS section.
    pub fn bss_size(&self) -> u32 {
        self.bss_size
    }

    /// Returns the initial size of the stack.
    pub fn stack_size(&self) -> u32 {
        self.stack_size
    }

    /// Returns the program code in its raw form.
    pub fn code(&self) -> &[u8] {
        &self.blob[self.code.clone()]
    }

    fn get_section_reader(&self, range: Range<usize>) -> Reader {
        Reader {
            blob: &self.blob[..range.end],
            position: range.start,
            previous_position: 0,
        }
    }

    /// Returns an iterator over program imports.
    pub fn imports(&'_ self) -> impl Iterator<Item = Result<ProgramImport, ProgramParseError>> + Clone + '_ {
        #[derive(Clone)]
        enum State {
            Uninitialized,
            Pending(u32),
            Finished,
        }

        #[derive(Clone)]
        struct ImportIterator<'a> {
            state: State,
            reader: Reader<'a>,
        }

        impl<'a> ImportIterator<'a> {
            fn read_next(&mut self) -> Result<Option<ProgramImport<'a>>, ProgramParseError> {
                let remaining = match core::mem::replace(&mut self.state, State::Finished) {
                    State::Uninitialized => self.reader.read_varint()?,
                    State::Pending(remaining) => remaining,
                    State::Finished => return Ok(None),
                };

                if remaining == 0 {
                    if !self.reader.is_eof() {
                        return Err(ProgramParseError(ProgramParseErrorKind::Other(
                            "the import section contains more data than expected",
                        )));
                    }

                    return Ok(None);
                }

                let index = self.reader.read_varint()?;
                let prototype = self.reader.read_extern_fn_prototype()?;
                let import = ProgramImport { index, prototype };

                self.state = State::Pending(remaining - 1);
                Ok(Some(import))
            }
        }

        impl<'a> Iterator for ImportIterator<'a> {
            type Item = Result<ProgramImport<'a>, ProgramParseError>;
            fn next(&mut self) -> Option<Self::Item> {
                self.read_next().transpose()
            }
        }

        ImportIterator {
            state: if self.imports != (0_usize..0_usize) {
                State::Uninitialized
            } else {
                State::Finished
            },
            reader: self.get_section_reader(self.imports.clone()),
        }
    }

    /// Returns an iterator over program exports.
    pub fn exports(&'_ self) -> impl Iterator<Item = Result<ProgramExport, ProgramParseError>> + Clone + '_ {
        #[derive(Clone)]
        enum State {
            Uninitialized,
            Pending(u32),
            Finished,
        }

        #[derive(Clone)]
        struct ExportIterator<'a> {
            state: State,
            reader: Reader<'a>,
        }

        impl<'a> ExportIterator<'a> {
            fn read_next(&mut self) -> Result<Option<ProgramExport<'a>>, ProgramParseError> {
                let remaining = match core::mem::replace(&mut self.state, State::Finished) {
                    State::Uninitialized => self.reader.read_varint()?,
                    State::Pending(remaining) => remaining,
                    State::Finished => return Ok(None),
                };

                if remaining == 0 {
                    if !self.reader.is_eof() {
                        return Err(ProgramParseError(ProgramParseErrorKind::Other(
                            "the export section contains more data than expected",
                        )));
                    }

                    return Ok(None);
                }

                let address = self.reader.read_varint()?;
                let prototype = self.reader.read_extern_fn_prototype()?;
                let export = ProgramExport { address, prototype };

                self.state = State::Pending(remaining - 1);
                Ok(Some(export))
            }
        }

        impl<'a> Iterator for ExportIterator<'a> {
            type Item = Result<ProgramExport<'a>, ProgramParseError>;
            fn next(&mut self) -> Option<Self::Item> {
                self.read_next().transpose()
            }
        }

        ExportIterator {
            state: if self.exports != (0_usize..0_usize) {
                State::Uninitialized
            } else {
                State::Finished
            },
            reader: self.get_section_reader(self.exports.clone()),
        }
    }

    /// Returns an iterator over program instructions.
    pub fn instructions(&'_ self) -> impl Iterator<Item = Result<RawInstruction, ProgramParseError>> + Clone + '_ {
        #[derive(Clone)]
        struct CodeIterator<'a> {
            code_section_position: usize,
            position: usize,
            code: &'a [u8],
        }

        impl<'a> Iterator for CodeIterator<'a> {
            type Item = Result<RawInstruction, ProgramParseError>;
            fn next(&mut self) -> Option<Self::Item> {
                let slice = &self.code[self.position..];
                if slice.is_empty() {
                    return None;
                }

                if let Some((bytes_consumed, instruction)) = RawInstruction::deserialize(slice) {
                    self.position += bytes_consumed;
                    return Some(Ok(instruction));
                }

                let offset = self.code_section_position + self.position;
                self.position = self.code.len();

                Some(Err(ProgramParseError(ProgramParseErrorKind::UnexpectedInstruction { offset })))
            }
        }

        CodeIterator {
            code_section_position: self.code.start,
            position: 0,
            code: self.code(),
        }
    }

    /// Returns the debug string for the given relative offset.
    pub fn get_debug_string(&self, offset: u32) -> Result<&str, ProgramParseError> {
        let mut reader = self.get_section_reader(self.debug_strings.clone());
        reader.skip(offset)?;
        reader.read_string_with_length()
    }

    /// Returns the line program for the given instruction.
    pub fn get_debug_line_program_at(&self, nth_instruction: u32) -> Result<Option<LineProgram>, ProgramParseError> {
        if self.debug_line_program_ranges.is_empty() || self.debug_line_programs.is_empty() {
            return Ok(None);
        }

        if self.blob[self.debug_line_programs.start] != VERSION_DEBUG_LINE_PROGRAM_V1 {
            return Err(ProgramParseError(ProgramParseErrorKind::Other(
                "the debug line programs section has an unsupported version",
            )));
        }

        const ENTRY_SIZE: usize = 12;

        let slice = &self.blob[self.debug_line_program_ranges.clone()];
        if slice.len() % ENTRY_SIZE != 0 {
            return Err(ProgramParseError(ProgramParseErrorKind::Other(
                "the debug function ranges section has an invalid size",
            )));
        }

        let offset = binary_search(slice, ENTRY_SIZE, |xs| {
            let begin = u32::from_le_bytes([xs[0], xs[1], xs[2], xs[3]]);
            if nth_instruction < begin {
                return core::cmp::Ordering::Greater;
            }

            let end = u32::from_le_bytes([xs[4], xs[5], xs[6], xs[7]]);
            if nth_instruction >= end {
                return core::cmp::Ordering::Less;
            }

            core::cmp::Ordering::Equal
        });

        let Ok(offset) = offset else { return Ok(None) };

        let xs = &slice[offset..offset + ENTRY_SIZE];
        let index_begin = u32::from_le_bytes([xs[0], xs[1], xs[2], xs[3]]);
        let index_end = u32::from_le_bytes([xs[4], xs[5], xs[6], xs[7]]);
        let info_offset = u32::from_le_bytes([xs[8], xs[9], xs[10], xs[11]]);

        if nth_instruction < index_begin || nth_instruction >= index_end {
            return Err(ProgramParseError(ProgramParseErrorKind::Other(
                "binary search for function debug info failed",
            )));
        }

        let mut reader = self.get_section_reader(self.debug_line_programs.clone());
        reader.skip(info_offset)?;

        Ok(Some(LineProgram {
            entry_index: offset / ENTRY_SIZE,
            region_counter: 0,
            blob: self,
            reader,
            is_finished: false,
            program_counter: index_begin,
            stack: Default::default(),
            stack_depth: 0,
            mutation_depth: 0,
        }))
    }

    /// Returns an owned program blob, possibly cloning it if it was deserialized in a zero-copy fashion.
    #[cfg(feature = "alloc")]
    pub fn into_owned(self) -> ProgramBlob<'static> {
        ProgramBlob {
            blob: self.blob.into_owned(),

            bss_size: self.bss_size,
            stack_size: self.stack_size,

            ro_data: self.ro_data,
            rw_data: self.rw_data,
            exports: self.exports,
            imports: self.imports,
            code: self.code,

            debug_strings: self.debug_strings,
            debug_line_program_ranges: self.debug_line_program_ranges,
            debug_line_programs: self.debug_line_programs,
        }
    }
}

/// The source location.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum SourceLocation<'a> {
    Path { path: &'a str },
    PathAndLine { path: &'a str, line: u32 },
    Full { path: &'a str, line: u32, column: u32 },
}

impl<'a> SourceLocation<'a> {
    /// The path to the original source file.
    pub fn path(&self) -> &'a str {
        match *self {
            Self::Path { path, .. } => path,
            Self::PathAndLine { path, .. } => path,
            Self::Full { path, .. } => path,
        }
    }

    /// The line in the original source file.
    pub fn line(&self) -> Option<u32> {
        match *self {
            Self::Path { .. } => None,
            Self::PathAndLine { line, .. } => Some(line),
            Self::Full { line, .. } => Some(line),
        }
    }

    /// The column in the original source file.
    pub fn column(&self) -> Option<u32> {
        match *self {
            Self::Path { .. } => None,
            Self::PathAndLine { .. } => None,
            Self::Full { column, .. } => Some(column),
        }
    }
}

impl<'a> core::fmt::Display for SourceLocation<'a> {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            Self::Path { path } => fmt.write_str(path),
            Self::PathAndLine { path, line } => write!(fmt, "{}:{}", path, line),
            Self::Full { path, line, column } => write!(fmt, "{}:{}:{}", path, line, column),
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Hash)]
pub enum FrameKind {
    Enter,
    Call,
    Line,
}

pub struct FrameInfo<'a> {
    blob: &'a ProgramBlob<'a>,
    inner: &'a LineProgramFrame,
}

impl<'a> FrameInfo<'a> {
    /// Returns the namespace of this location, if available.
    pub fn namespace(&self) -> Result<Option<&str>, ProgramParseError> {
        let namespace = self.blob.get_debug_string(self.inner.namespace_offset)?;
        if namespace.is_empty() {
            Ok(None)
        } else {
            Ok(Some(namespace))
        }
    }

    /// Returns the function name of location without the namespace, if available.
    pub fn function_name_without_namespace(&self) -> Result<Option<&str>, ProgramParseError> {
        let function_name = self.blob.get_debug_string(self.inner.function_name_offset)?;
        if function_name.is_empty() {
            Ok(None)
        } else {
            Ok(Some(function_name))
        }
    }

    /// Returns the offset into the debug strings section containing the source code path of this location, if available.
    pub fn path_debug_string_offset(&self) -> Option<u32> {
        if self.inner.path_offset == 0 {
            None
        } else {
            Some(self.inner.path_offset)
        }
    }

    /// Returns the source code path of this location, if available.
    pub fn path(&self) -> Result<Option<&str>, ProgramParseError> {
        let path = self.blob.get_debug_string(self.inner.path_offset)?;
        if path.is_empty() {
            Ok(None)
        } else {
            Ok(Some(path))
        }
    }

    /// Returns the source code line of this location, if available.
    pub fn line(&self) -> Option<u32> {
        if self.inner.line == 0 {
            None
        } else {
            Some(self.inner.line)
        }
    }

    /// Returns the source code column of this location, if available.
    pub fn column(&self) -> Option<u32> {
        if self.inner.column == 0 {
            None
        } else {
            Some(self.inner.column)
        }
    }

    pub fn kind(&self) -> FrameKind {
        self.inner.kind.unwrap_or(FrameKind::Line)
    }

    /// Returns the full name of the function.
    pub fn full_name(&'_ self) -> Result<impl core::fmt::Display + '_, ProgramParseError> {
        Ok(DisplayName {
            prefix: self.namespace()?.unwrap_or(""),
            suffix: self.function_name_without_namespace()?.unwrap_or(""),
        })
    }

    /// Returns the source location of where this frame comes from.
    pub fn location(&self) -> Result<Option<SourceLocation>, ProgramParseError> {
        if let Some(path) = self.path()? {
            if let Some(line) = self.line() {
                if let Some(column) = self.column() {
                    Ok(Some(SourceLocation::Full { path, line, column }))
                } else {
                    Ok(Some(SourceLocation::PathAndLine { path, line }))
                }
            } else {
                Ok(Some(SourceLocation::Path { path }))
            }
        } else {
            Ok(None)
        }
    }
}

/// Debug information about a given region of bytecode.
pub struct RegionInfo<'a> {
    entry_index: usize,
    blob: &'a ProgramBlob<'a>,
    range: Range<u32>,
    frames: &'a [LineProgramFrame],
}

impl<'a> RegionInfo<'a> {
    /// Returns the entry index of this region info within the parent line program object.
    pub fn entry_index(&self) -> usize {
        self.entry_index
    }

    /// The range of instructions this region covers.
    pub fn instruction_range(&self) -> Range<u32> {
        self.range.clone()
    }

    /// Returns an iterator over the frames this region covers.
    pub fn frames(&self) -> impl ExactSizeIterator<Item = FrameInfo> {
        self.frames.iter().map(|inner| FrameInfo { blob: self.blob, inner })
    }
}

#[derive(Default)]
struct LineProgramFrame {
    kind: Option<FrameKind>,
    namespace_offset: u32,
    function_name_offset: u32,
    path_offset: u32,
    line: u32,
    column: u32,
}

/// A line program state machine.
pub struct LineProgram<'a> {
    entry_index: usize,
    region_counter: usize,
    blob: &'a ProgramBlob<'a>,
    reader: Reader<'a>,
    is_finished: bool,
    program_counter: u32,
    // Support inline call stacks ~16 frames deep. Picked entirely arbitrarily.
    stack: [LineProgramFrame; 16],
    stack_depth: u32,
    mutation_depth: u32,
}

impl<'a> LineProgram<'a> {
    /// Returns the entry index of this line program object.
    pub fn entry_index(&self) -> usize {
        self.entry_index
    }

    /// Runs the line program until the next region becomes available, or until the program ends.
    pub fn run(&mut self) -> Result<Option<RegionInfo>, ProgramParseError> {
        struct SetTrueOnDrop<'a>(&'a mut bool);
        impl<'a> Drop for SetTrueOnDrop<'a> {
            fn drop(&mut self) {
                *self.0 = true;
            }
        }

        if self.is_finished {
            return Ok(None);
        }

        // Put an upper limit to how many instructions we'll process.
        const INSTRUCTION_LIMIT_PER_REGION: usize = 256;

        let mark_as_finished_on_drop = SetTrueOnDrop(&mut self.is_finished);
        for _ in 0..INSTRUCTION_LIMIT_PER_REGION {
            let byte = match self.reader.read_byte() {
                Ok(byte) => byte,
                Err(error) => {
                    return Err(error);
                }
            };

            let Some(opcode) = LineProgramOp::from_u8(byte) else {
                return Err(ProgramParseError(ProgramParseErrorKind::Other(
                    "found an unrecognized line program opcode",
                )));
            };

            let (count, stack_depth) = match opcode {
                LineProgramOp::FinishProgram => {
                    return Ok(None);
                }
                LineProgramOp::SetMutationDepth => {
                    self.mutation_depth = self.reader.read_varint()?;
                    continue;
                }
                LineProgramOp::SetKindEnter => {
                    if let Some(frame) = self.stack.get_mut(self.mutation_depth as usize) {
                        frame.kind = Some(FrameKind::Enter);
                    }
                    continue;
                }
                LineProgramOp::SetKindCall => {
                    if let Some(frame) = self.stack.get_mut(self.mutation_depth as usize) {
                        frame.kind = Some(FrameKind::Call);
                    }
                    continue;
                }
                LineProgramOp::SetKindLine => {
                    if let Some(frame) = self.stack.get_mut(self.mutation_depth as usize) {
                        frame.kind = Some(FrameKind::Line);
                    }
                    continue;
                }
                LineProgramOp::SetNamespace => {
                    let value = self.reader.read_varint()?;
                    if let Some(frame) = self.stack.get_mut(self.mutation_depth as usize) {
                        frame.namespace_offset = value;
                    }
                    continue;
                }
                LineProgramOp::SetFunctionName => {
                    let value = self.reader.read_varint()?;
                    if let Some(frame) = self.stack.get_mut(self.mutation_depth as usize) {
                        frame.function_name_offset = value;
                    }
                    continue;
                }
                LineProgramOp::SetPath => {
                    let value = self.reader.read_varint()?;
                    if let Some(frame) = self.stack.get_mut(self.mutation_depth as usize) {
                        frame.path_offset = value;
                    }
                    continue;
                }
                LineProgramOp::SetLine => {
                    let value = self.reader.read_varint()?;
                    if let Some(frame) = self.stack.get_mut(self.mutation_depth as usize) {
                        frame.line = value;
                    }
                    continue;
                }
                LineProgramOp::SetColumn => {
                    let value = self.reader.read_varint()?;
                    if let Some(frame) = self.stack.get_mut(self.mutation_depth as usize) {
                        frame.column = value;
                    }
                    continue;
                }
                LineProgramOp::SetStackDepth => {
                    self.stack_depth = self.reader.read_varint()?;
                    continue;
                }
                LineProgramOp::IncrementLine => {
                    if let Some(frame) = self.stack.get_mut(self.mutation_depth as usize) {
                        frame.line += 1;
                    }
                    continue;
                }
                LineProgramOp::AddLine => {
                    let value = self.reader.read_varint()?;
                    if let Some(frame) = self.stack.get_mut(self.mutation_depth as usize) {
                        frame.line = frame.line.wrapping_add(value);
                    }
                    continue;
                }
                LineProgramOp::SubLine => {
                    let value = self.reader.read_varint()?;
                    if let Some(frame) = self.stack.get_mut(self.mutation_depth as usize) {
                        frame.line = frame.line.wrapping_sub(value);
                    }
                    continue;
                }
                LineProgramOp::FinishInstruction => (1, self.stack_depth),
                LineProgramOp::FinishMultipleInstructions => {
                    let count = self.reader.read_varint()?;
                    (count, self.stack_depth)
                }
                LineProgramOp::FinishInstructionAndIncrementStackDepth => {
                    let depth = self.stack_depth;
                    self.stack_depth = self.stack_depth.saturating_add(1);
                    (1, depth)
                }
                LineProgramOp::FinishMultipleInstructionsAndIncrementStackDepth => {
                    let count = self.reader.read_varint()?;
                    let depth = self.stack_depth;
                    self.stack_depth = self.stack_depth.saturating_add(1);
                    (count, depth)
                }
                LineProgramOp::FinishInstructionAndDecrementStackDepth => {
                    let depth = self.stack_depth;
                    self.stack_depth = self.stack_depth.saturating_sub(1);
                    (1, depth)
                }
                LineProgramOp::FinishMultipleInstructionsAndDecrementStackDepth => {
                    let count = self.reader.read_varint()?;
                    let depth = self.stack_depth;
                    self.stack_depth = self.stack_depth.saturating_sub(1);
                    (count, depth)
                }
            };

            let range = self.program_counter..self.program_counter + count;
            self.program_counter += count;

            let frames = &self.stack[..core::cmp::min(stack_depth as usize, self.stack.len())];
            core::mem::forget(mark_as_finished_on_drop);

            let entry_index = self.region_counter;
            self.region_counter += 1;
            return Ok(Some(RegionInfo {
                entry_index,
                blob: self.blob,
                range,
                frames,
            }));
        }

        Err(ProgramParseError(ProgramParseErrorKind::Other(
            "found a line program with too many instructions",
        )))
    }
}

struct DisplayName<'a> {
    prefix: &'a str,
    suffix: &'a str,
}

impl<'a> core::fmt::Display for DisplayName<'a> {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
        fmt.write_str(self.prefix)?;
        if !self.prefix.is_empty() {
            fmt.write_str("::")?;
        }
        fmt.write_str(self.suffix)
    }
}

/// A binary search implementation which can work on chunks of items, and guarantees that it
/// will always return the first item if there are multiple identical consecutive items.
fn binary_search(slice: &[u8], chunk_size: usize, compare: impl Fn(&[u8]) -> core::cmp::Ordering) -> Result<usize, usize> {
    let mut size = slice.len() / chunk_size;
    if size == 0 {
        return Err(0);
    }

    let mut base = 0_usize;
    while size > 1 {
        let half = size / 2;
        let mid = base + half;
        let item = &slice[mid * chunk_size..(mid + 1) * chunk_size];
        match compare(item) {
            core::cmp::Ordering::Greater => {
                // The value we're looking for is to the left of the midpoint.
                size -= half;
            }
            core::cmp::Ordering::Less => {
                // The value we're looking for is to the right of the midpoint.
                size -= half;
                base = mid;
            }
            core::cmp::Ordering::Equal => {
                // We've found the value, but it might not be the first value.
                let previous_item = &slice[(mid - 1) * chunk_size..mid * chunk_size];
                if compare(previous_item) != core::cmp::Ordering::Equal {
                    // It is the first value.
                    return Ok(mid * chunk_size);
                }

                // It's not the first value. Let's continue.
                //
                // We could do a linear search here which in the average case
                // would probably be faster, but keeping it as a binary search
                // will avoid a worst-case O(n) scenario.
                size -= half;
            }
        }
    }

    let item = &slice[base * chunk_size..(base + 1) * chunk_size];
    let ord = compare(item);
    if ord == core::cmp::Ordering::Equal {
        Ok(base * chunk_size)
    } else {
        Err((base + (ord == core::cmp::Ordering::Less) as usize) * chunk_size)
    }
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
proptest::proptest! {
    #![proptest_config(proptest::prelude::ProptestConfig::with_cases(20000))]
    #[test]
    fn test_binary_search(needle: u8, mut xs: std::vec::Vec<u8>) {
        xs.sort();
        let binary_result = binary_search(&xs, 1, |slice| slice[0].cmp(&needle));
        let mut linear_result = Err(0);
        for (index, value) in xs.iter().copied().enumerate() {
            #[allow(clippy::comparison_chain)]
            if value == needle {
                linear_result = Ok(index);
                break;
            } else if value < needle {
                linear_result = Err(index + 1);
                continue;
            } else {
                break;
            }
        }

        assert_eq!(binary_result, linear_result, "linear search = {:?}, binary search = {:?}, needle = {}, xs = {:?}", linear_result, binary_result, needle, xs);
    }
}

/// The magic bytes with which every program blob must start with.
pub const BLOB_MAGIC: [u8; 4] = [b'P', b'V', b'M', b'\0'];

pub const SECTION_MEMORY_CONFIG: u8 = 1;
pub const SECTION_RO_DATA: u8 = 2;
pub const SECTION_RW_DATA: u8 = 3;
pub const SECTION_IMPORTS: u8 = 4;
pub const SECTION_EXPORTS: u8 = 5;
pub const SECTION_CODE: u8 = 6;
pub const SECTION_OPT_DEBUG_STRINGS: u8 = 128;
pub const SECTION_OPT_DEBUG_LINE_PROGRAMS: u8 = 129;
pub const SECTION_OPT_DEBUG_LINE_PROGRAM_RANGES: u8 = 130;
pub const SECTION_END_OF_FILE: u8 = 0;

pub const BLOB_VERSION_V1: u8 = 1;

pub const VERSION_DEBUG_LINE_PROGRAM_V1: u8 = 1;

#[derive(Copy, Clone, Debug)]
pub enum LineProgramOp {
    FinishProgram = 0,
    SetMutationDepth = 1,
    SetKindEnter = 2,
    SetKindCall = 3,
    SetKindLine = 4,
    SetNamespace = 5,
    SetFunctionName = 6,
    SetPath = 7,
    SetLine = 8,
    SetColumn = 9,
    SetStackDepth = 10,
    IncrementLine = 11,
    AddLine = 12,
    SubLine = 13,
    FinishInstruction = 14,
    FinishMultipleInstructions = 15,
    FinishInstructionAndIncrementStackDepth = 16,
    FinishMultipleInstructionsAndIncrementStackDepth = 17,
    FinishInstructionAndDecrementStackDepth = 18,
    FinishMultipleInstructionsAndDecrementStackDepth = 19,
}

impl LineProgramOp {
    #[inline]
    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::FinishProgram),
            1 => Some(Self::SetMutationDepth),
            2 => Some(Self::SetKindEnter),
            3 => Some(Self::SetKindCall),
            4 => Some(Self::SetKindLine),
            5 => Some(Self::SetNamespace),
            6 => Some(Self::SetFunctionName),
            7 => Some(Self::SetPath),
            8 => Some(Self::SetLine),
            9 => Some(Self::SetColumn),
            10 => Some(Self::SetStackDepth),
            11 => Some(Self::IncrementLine),
            12 => Some(Self::AddLine),
            13 => Some(Self::SubLine),
            14 => Some(Self::FinishInstruction),
            15 => Some(Self::FinishMultipleInstructions),
            16 => Some(Self::FinishInstructionAndIncrementStackDepth),
            17 => Some(Self::FinishMultipleInstructionsAndIncrementStackDepth),
            18 => Some(Self::FinishInstructionAndDecrementStackDepth),
            19 => Some(Self::FinishMultipleInstructionsAndDecrementStackDepth),
            _ => None,
        }
    }
}
