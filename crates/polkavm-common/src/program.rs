use crate::abi::{VM_CODE_ADDRESS_ALIGNMENT, VM_MAXIMUM_CODE_SIZE, VM_MAXIMUM_IMPORT_COUNT, VM_MAXIMUM_JUMP_TABLE_ENTRIES};
use crate::utils::CowBytes;
use crate::varint::{read_simple_varint_fast, read_varint, read_varint_fast, write_simple_varint, write_varint, MAX_VARINT_LENGTH};
use core::ops::Range;

#[derive(Copy, Clone, PartialEq, Eq, Debug, Hash)]
#[repr(u32)]
pub enum Reg {
    RA = 0,
    SP = 1,
    T0 = 2,
    T1 = 3,
    T2 = 4,
    S0 = 5,
    S1 = 6,
    A0 = 7,
    A1 = 8,
    A2 = 9,
    A3 = 10,
    A4 = 11,
    A5 = 12,
}

impl Reg {
    #[inline]
    pub const fn from_u8(value: u8) -> Option<Reg> {
        match value {
            0 => Some(Reg::RA),
            1 => Some(Reg::SP),
            2 => Some(Reg::T0),
            3 => Some(Reg::T1),
            4 => Some(Reg::T2),
            5 => Some(Reg::S0),
            6 => Some(Reg::S1),
            7 => Some(Reg::A0),
            8 => Some(Reg::A1),
            9 => Some(Reg::A2),
            10 => Some(Reg::A3),
            11 => Some(Reg::A4),
            12 => Some(Reg::A5),
            _ => None,
        }
    }

    pub const fn name(self) -> &'static str {
        use Reg::*;
        match self {
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

    /// List of all of the VM's registers.
    pub const ALL: [Reg; 13] = {
        use Reg::*;
        [RA, SP, T0, T1, T2, S0, S1, A0, A1, A2, A3, A4, A5]
    };

    /// List of all input/output argument registers.
    pub const ARG_REGS: [Reg; 9] = [Reg::A0, Reg::A1, Reg::A2, Reg::A3, Reg::A4, Reg::A5, Reg::T0, Reg::T1, Reg::T2];

    pub const MAXIMUM_INPUT_REGS: usize = 9;
    pub const MAXIMUM_OUTPUT_REGS: usize = 2;
}

impl core::fmt::Display for Reg {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
        fmt.write_str(self.name())
    }
}

#[allow(clippy::partial_pub_fields)]
#[doc(hidden)]
pub struct VisitorHelper<T> {
    chunk: u128,
    pub visitor: T,
    args_length: usize,
    instruction_offset: u32,
    opcode: u8,
}

macro_rules! skip {
    ($chunk:expr, $count:expr) => {
        $chunk >> ($count << 3)
    };
}

macro_rules! read_reg {
    ($chunk:ident) => {{
        let reg = Reg::from_u8($chunk as u8)?;
        (reg, skip!($chunk, 1))
    }};
}

macro_rules! read_reg2 {
    ($chunk:ident) => {{
        let value = $chunk as u8;
        let reg1 = Reg::from_u8(value & 0b1111)?;
        let reg2 = Reg::from_u8(value >> 4)?;
        (reg1, reg2, skip!($chunk, 1))
    }};
}

macro_rules! read_simple_varint {
    ($chunk:expr, $length:expr) => {{
        let imm = read_simple_varint_fast($chunk as u32, $length as u32);
        (imm, skip!($chunk, $length))
    }};
}

macro_rules! read_varint {
    ($chunk:ident) => {{
        let (imm_length, imm) = read_varint_fast($chunk as u64)?;
        let imm_length = imm_length as usize;
        (imm, skip!($chunk, imm_length), imm_length)
    }};
}

impl<T> VisitorHelper<T> {
    #[allow(clippy::type_complexity)]
    #[inline(never)]
    #[cold]
    fn step_slow(
        &mut self,
        code: &[u8],
        instruction_offset: usize,
        instruction_length: usize,
        decode_table: &[fn(state: &mut Self) -> <T as InstructionVisitor>::ReturnTy],
    ) -> Option<<T as InstructionVisitor>::ReturnTy>
    where
        T: ParsingVisitor,
    {
        let chunk = code.get(instruction_offset..instruction_offset + instruction_length)?;
        let opcode = chunk[0];
        let args = &chunk[1..instruction_length];
        let mut t: [u8; 16] = [0; 16];
        t[..instruction_length].copy_from_slice(chunk);
        self.chunk = u128::from_le_bytes([
            t[0], t[1], t[2], t[3], t[4], t[5], t[6], t[7], t[8], t[9], t[10], t[11], t[12], t[13], t[14], t[15],
        ]) >> 8;

        self.opcode = opcode;
        self.args_length = args.len();
        self.instruction_offset = instruction_offset as u32;

        self.visitor.on_pre_visit(instruction_offset, opcode);
        Some(decode_table[opcode as usize](self))
    }

    #[allow(clippy::type_complexity)]
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn step(
        &mut self,
        code: &[u8],
        bitmask: &[u8],
        offset: &mut usize,
        decode_table: &[fn(state: &mut Self) -> <T as InstructionVisitor>::ReturnTy],
    ) -> Option<<T as InstructionVisitor>::ReturnTy>
    where
        T: ParsingVisitor,
    {
        let instruction_offset = *offset;
        let args_length = parse_bitmask(bitmask, offset)?;
        let instruction_length = args_length + 1;

        let padded_length = core::cmp::max(instruction_length, 16);
        let Some(chunk) = code.get(instruction_offset..instruction_offset + padded_length) else {
            return self.step_slow(code, instruction_offset, instruction_length, decode_table);
        };

        assert!(chunk.len() >= 16);
        let opcode = chunk[0];

        // NOTE: This should produce the same assembly as the unsafe `read_unaligned`.
        self.chunk = u128::from_le_bytes([
            chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6], chunk[7], chunk[8], chunk[9], chunk[10], chunk[11],
            chunk[12], chunk[13], chunk[14], chunk[15],
        ]) >> 8;

        self.opcode = opcode;
        self.args_length = instruction_length - 1;
        self.instruction_offset = instruction_offset as u32;

        self.visitor.on_pre_visit(instruction_offset, opcode);
        Some(decode_table[opcode as usize](self))
    }

    #[inline]
    pub fn new(visitor: T) -> Self {
        VisitorHelper {
            chunk: 0,
            visitor,
            args_length: 0,
            instruction_offset: 0,
            opcode: 0,
        }
    }

    #[inline]
    pub fn run(mut self, blob: &ProgramBlob, decode_table: &[fn(&mut Self) -> <T as InstructionVisitor>::ReturnTy; 256]) -> T
    where
        T: ParsingVisitor<ReturnTy = ()>,
    {
        let code = blob.code();
        let bitmask = blob.bitmask();
        debug_assert_eq!(bitmask[0] & 0b1, 1);

        let mut offset = 0;
        while self.step(code, bitmask, &mut offset, decode_table).is_some() {}
        self.visitor
    }

    #[inline]
    pub fn opcode(&self) -> u8 {
        self.opcode
    }

    #[inline(always)]
    pub fn read_args_offset(&mut self) -> Option<u32> {
        let (imm, _) = read_simple_varint!(self.chunk, self.args_length);
        Some(self.instruction_offset.wrapping_add(imm))
    }

    #[inline(always)]
    pub fn read_args_imm(&mut self) -> Option<u32> {
        let (imm, _) = read_simple_varint!(self.chunk, self.args_length);
        Some(imm)
    }

    #[inline(always)]
    pub fn read_args_imm2(&mut self) -> Option<(u32, u32)> {
        let chunk = self.chunk;
        let (imm1, chunk, imm1_length) = read_varint!(chunk);
        let (imm2, _) = read_simple_varint!(chunk, self.args_length - imm1_length);
        Some((imm1, imm2))
    }

    #[inline(always)]
    pub fn read_args_reg_imm(&mut self) -> Option<(Reg, u32)> {
        let chunk = self.chunk;
        let (reg, chunk) = read_reg!(chunk);
        let (imm, _) = read_simple_varint!(chunk, self.args_length - 1);
        Some((reg, imm))
    }

    #[inline(always)]
    pub fn read_args_reg_imm_offset(&mut self) -> Option<(Reg, u32, u32)> {
        let chunk = self.chunk;
        let (reg, chunk) = read_reg!(chunk);
        let (imm1, chunk, imm1_length) = read_varint!(chunk);
        let (imm2, _) = read_simple_varint!(chunk, self.args_length - 1 - imm1_length);
        let imm2 = self.instruction_offset.wrapping_add(imm2);
        Some((reg, imm1, imm2))
    }

    #[inline(always)]
    pub fn read_args_reg_imm2(&mut self) -> Option<(Reg, u32, u32)> {
        let chunk = self.chunk;
        let (reg, chunk) = read_reg!(chunk);
        let (imm1, chunk, imm1_length) = read_varint!(chunk);
        let (imm2, _) = read_simple_varint!(chunk, self.args_length - 1 - imm1_length);
        Some((reg, imm1, imm2))
    }

    #[inline(always)]
    pub fn read_args_regs2_imm2(&mut self) -> Option<(Reg, Reg, u32, u32)> {
        let chunk = self.chunk;
        let (reg1, reg2, chunk) = read_reg2!(chunk);
        let (imm1, chunk, imm1_length) = read_varint!(chunk);
        let (imm2, _) = read_simple_varint!(chunk, self.args_length - 1 - imm1_length);
        Some((reg1, reg2, imm1, imm2))
    }

    #[inline(always)]
    pub fn read_args_regs2_imm(&mut self) -> Option<(Reg, Reg, u32)> {
        let chunk = self.chunk;
        let (reg1, reg2, chunk) = read_reg2!(chunk);
        let (imm, _) = read_simple_varint!(chunk, self.args_length - 1);
        Some((reg1, reg2, imm))
    }

    #[inline(always)]
    pub fn read_args_regs3(&mut self) -> Option<(Reg, Reg, Reg)> {
        let chunk = self.chunk;
        let (reg1, reg2, chunk) = read_reg2!(chunk);
        let (reg3, _) = read_reg!(chunk);
        Some((reg1, reg2, reg3))
    }

    #[inline(always)]
    pub fn read_args_regs2(&mut self) -> Option<(Reg, Reg)> {
        let chunk = self.chunk;
        let (reg1, reg2, _) = read_reg2!(chunk);
        Some((reg1, reg2))
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
            #[cfg_attr(feature = "alloc", inline)]
            pub fn from_u8(byte: u8) -> Option<Opcode> {
                if !IS_INSTRUCTION_VALID[byte as usize] {
                    return None;
                }

                #[allow(unsafe_code)]
                // SAFETY: We already checked that this opcode is valid, so this is safe.
                unsafe {
                    Some(core::mem::transmute(byte))
                }
            }
        }

        #[test]
        fn test_opcode_from_u8() {
            fn from_u8_naive(byte: u8) -> Option<Opcode> {
                match byte {
                    $($value => Some(Opcode::$name),)+
                    _ => None
                }
            }

            for byte in 0..=255 {
                assert_eq!(from_u8_naive(byte), Opcode::from_u8(byte));
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
        $d:tt

        [$($name_argless:ident = $value_argless:expr,)+]
        [$($name_reg_imm:ident = $value_reg_imm:expr,)+]
        [$($name_reg_imm_offset:ident = $value_reg_imm_offset:expr,)+]
        [$($name_reg_imm_imm:ident = $value_reg_imm_imm:expr,)+]
        [$($name_reg_reg_imm:ident = $value_reg_reg_imm:expr,)+]
        [$($name_reg_reg_reg:ident = $value_reg_reg_reg:expr,)+]
        [$($name_offset:ident = $value_offset:expr,)+]
        [$($name_imm:ident = $value_imm:expr,)+]
        [$($name_imm_imm:ident = $value_imm_imm:expr,)+]
        [$($name_reg_reg:ident = $value_reg_reg:expr,)+]
        [$($name_reg_reg_imm_imm:ident = $value_reg_reg_imm_imm:expr,)+]
    ) => {
        pub trait ParsingVisitor: InstructionVisitor {
            fn on_pre_visit(&mut self, _offset: usize, _opcode: u8);
        }

        pub trait InstructionVisitor {
            type ReturnTy;

            $(fn $name_argless(&mut self) -> Self::ReturnTy;)+
            $(fn $name_reg_imm(&mut self, reg: Reg, imm: u32) -> Self::ReturnTy;)+
            $(fn $name_reg_imm_offset(&mut self, reg: Reg, imm1: u32, imm2: u32) -> Self::ReturnTy;)+
            $(fn $name_reg_imm_imm(&mut self, reg: Reg, imm1: u32, imm2: u32) -> Self::ReturnTy;)+
            $(fn $name_reg_reg_imm(&mut self, reg1: Reg, reg2: Reg, imm: u32) -> Self::ReturnTy;)+
            $(fn $name_reg_reg_reg(&mut self, reg1: Reg, reg2: Reg, reg3: Reg) -> Self::ReturnTy;)+
            $(fn $name_offset(&mut self, imm: u32) -> Self::ReturnTy;)+
            $(fn $name_imm(&mut self, imm: u32) -> Self::ReturnTy;)+
            $(fn $name_imm_imm(&mut self, imm1: u32, imm2: u32) -> Self::ReturnTy;)+
            $(fn $name_reg_reg(&mut self, reg1: Reg, reg2: Reg) -> Self::ReturnTy;)+
            $(fn $name_reg_reg_imm_imm(&mut self, reg1: Reg, reg2: Reg, imm1: u32, imm2: u32) -> Self::ReturnTy;)+

            #[inline(never)]
            #[cold]
            fn invalid(&mut self, _opcode: u8) -> Self::ReturnTy {
                self.trap()
            }
        }

        #[macro_export]
        macro_rules! implement_instruction_visitor {
            (impl<$d($visitor_ty_params:tt),*> $visitor_ty:ty, $method:ident) => {
                impl<$d($visitor_ty_params),*> polkavm_common::program::InstructionVisitor for $visitor_ty {
                    type ReturnTy = ();

                    $(fn $name_argless(&mut self) -> Self::ReturnTy {
                        self.$method(polkavm_common::program::Instruction::$name_argless);
                    })+
                    $(fn $name_reg_imm(&mut self, reg: Reg, imm: u32) -> Self::ReturnTy {
                        self.$method(polkavm_common::program::Instruction::$name_reg_imm(reg, imm));
                    })+
                    $(fn $name_reg_imm_offset(&mut self, reg: Reg, imm1: u32, imm2: u32) -> Self::ReturnTy {
                        self.$method(polkavm_common::program::Instruction::$name_reg_imm_offset(reg, imm1, imm2));
                    })+
                    $(fn $name_reg_imm_imm(&mut self, reg: Reg, imm1: u32, imm2: u32) -> Self::ReturnTy {
                        self.$method(polkavm_common::program::Instruction::$name_reg_imm_imm(reg, imm1, imm2));
                    })+
                    $(fn $name_reg_reg_imm(&mut self, reg1: Reg, reg2: Reg, imm: u32) -> Self::ReturnTy {
                        self.$method(polkavm_common::program::Instruction::$name_reg_reg_imm(reg1, reg2, imm));
                    })+
                    $(fn $name_reg_reg_reg(&mut self, reg1: Reg, reg2: Reg, reg3: Reg) -> Self::ReturnTy {
                        self.$method(polkavm_common::program::Instruction::$name_reg_reg_reg(reg1, reg2, reg3));
                    })+
                    $(fn $name_offset(&mut self, imm: u32) -> Self::ReturnTy {
                        self.$method(polkavm_common::program::Instruction::$name_offset(imm));
                    })+
                    $(fn $name_imm(&mut self, imm: u32) -> Self::ReturnTy {
                        self.$method(polkavm_common::program::Instruction::$name_imm(imm));
                    })+
                    $(fn $name_imm_imm(&mut self, imm1: u32, imm2: u32) -> Self::ReturnTy {
                        self.$method(polkavm_common::program::Instruction::$name_imm_imm(imm1, imm2));
                    })+
                    $(fn $name_reg_reg(&mut self, reg1: Reg, reg2: Reg) -> Self::ReturnTy {
                        self.$method(polkavm_common::program::Instruction::$name_reg_reg(reg1, reg2));
                    })+
                    $(fn $name_reg_reg_imm_imm(&mut self, reg1: Reg, reg2: Reg, imm1: u32, imm2: u32) -> Self::ReturnTy {
                        self.$method(polkavm_common::program::Instruction::$name_reg_reg_imm_imm(reg1, reg2, imm1, imm2));
                    })+
                }
            }
        }

        pub use implement_instruction_visitor;

        #[derive(Copy, Clone, PartialEq, Eq, Debug)]
        #[allow(non_camel_case_types)]
        #[repr(u32)]
        pub enum Instruction {
            $($name_argless = $value_argless,)+
            $($name_reg_imm(Reg, u32) = $value_reg_imm,)+
            $($name_reg_imm_offset(Reg, u32, u32) = $value_reg_imm_offset,)+
            $($name_reg_imm_imm(Reg, u32, u32) = $value_reg_imm_imm,)+
            $($name_reg_reg_imm(Reg, Reg, u32) = $value_reg_reg_imm,)+
            $($name_reg_reg_reg(Reg, Reg, Reg) = $value_reg_reg_reg,)+
            $($name_offset(u32) = $value_offset,)+
            $($name_imm(u32) = $value_imm,)+
            $($name_imm_imm(u32, u32) = $value_imm_imm,)+
            $($name_reg_reg(Reg, Reg) = $value_reg_reg,)+
            $($name_reg_reg_imm_imm(Reg, Reg, u32, u32) = $value_reg_reg_imm_imm,)+
            invalid(u8) = 88,
        }

        impl Instruction {
            pub fn visit<T>(self, visitor: &mut T) -> T::ReturnTy where T: InstructionVisitor {
                match self {
                    $(Self::$name_argless => visitor.$name_argless(),)+
                    $(Self::$name_reg_imm(reg, imm) => visitor.$name_reg_imm(reg, imm),)+
                    $(Self::$name_reg_imm_offset(reg, imm1, imm2) => visitor.$name_reg_imm_offset(reg, imm1, imm2),)+
                    $(Self::$name_reg_imm_imm(reg, imm1, imm2) => visitor.$name_reg_imm_imm(reg, imm1, imm2),)+
                    $(Self::$name_reg_reg_imm(reg1, reg2, imm) => visitor.$name_reg_reg_imm(reg1, reg2, imm),)+
                    $(Self::$name_reg_reg_reg(reg1, reg2, reg3) => visitor.$name_reg_reg_reg(reg1, reg2, reg3),)+
                    $(Self::$name_offset(imm) => visitor.$name_offset(imm),)+
                    $(Self::$name_imm(imm) => visitor.$name_imm(imm),)+
                    $(Self::$name_imm_imm(imm1, imm2) => visitor.$name_imm_imm(imm1, imm2),)+
                    $(Self::$name_reg_reg(reg1, reg2) => visitor.$name_reg_reg(reg1, reg2),)+
                    $(Self::$name_reg_reg_imm_imm(reg1, reg2, imm1, imm2) => visitor.$name_reg_reg_imm_imm(reg1, reg2, imm1, imm2),)+
                    Self::invalid(opcode) => visitor.invalid(opcode),
                }
            }

            pub fn serialize_into(self, position: u32, buffer: &mut [u8]) -> usize {
                match self {
                    $(Self::$name_argless => Self::serialize_argless(buffer, Opcode::$name_argless),)+
                    $(Self::$name_reg_imm(reg, imm) => Self::serialize_reg_imm(buffer, Opcode::$name_reg_imm, reg, imm),)+
                    $(Self::$name_reg_imm_offset(reg, imm1, imm2) => Self::serialize_reg_imm_offset(buffer, position, Opcode::$name_reg_imm_offset, reg, imm1, imm2),)+
                    $(Self::$name_reg_imm_imm(reg, imm1, imm2) => Self::serialize_reg_imm_imm(buffer, Opcode::$name_reg_imm_imm, reg, imm1, imm2),)+
                    $(Self::$name_reg_reg_imm(reg1, reg2, imm) => Self::serialize_reg_reg_imm(buffer, Opcode::$name_reg_reg_imm, reg1, reg2, imm),)+
                    $(Self::$name_reg_reg_reg(reg1, reg2, reg3) => Self::serialize_reg_reg_reg(buffer, Opcode::$name_reg_reg_reg, reg1, reg2, reg3),)+
                    $(Self::$name_offset(imm) => Self::serialize_offset(buffer, position, Opcode::$name_offset, imm),)+
                    $(Self::$name_imm(imm) => Self::serialize_imm(buffer, Opcode::$name_imm, imm),)+
                    $(Self::$name_imm_imm(imm1, imm2) => Self::serialize_imm_imm(buffer, Opcode::$name_imm_imm, imm1, imm2),)+
                    $(Self::$name_reg_reg(reg1, reg2) => Self::serialize_reg_reg(buffer, Opcode::$name_reg_reg, reg1, reg2),)+
                    $(Self::$name_reg_reg_imm_imm(reg1, reg2, imm1, imm2) => Self::serialize_reg_reg_imm_imm(buffer, Opcode::$name_reg_reg_imm_imm, reg1, reg2, imm1, imm2),)+
                    Self::invalid(..) => Self::serialize_argless(buffer, Opcode::trap),

                }
            }

            pub fn opcode(self) -> Opcode {
                match self {
                    $(Self::$name_argless => Opcode::$name_argless,)+
                    $(Self::$name_reg_imm(..) => Opcode::$name_reg_imm,)+
                    $(Self::$name_reg_imm_offset(..) => Opcode::$name_reg_imm_offset,)+
                    $(Self::$name_reg_imm_imm(..) => Opcode::$name_reg_imm_imm,)+
                    $(Self::$name_reg_reg_imm(..) => Opcode::$name_reg_reg_imm,)+
                    $(Self::$name_reg_reg_reg(..) => Opcode::$name_reg_reg_reg,)+
                    $(Self::$name_offset(..) => Opcode::$name_offset,)+
                    $(Self::$name_imm(..) => Opcode::$name_imm,)+
                    $(Self::$name_imm_imm(..) => Opcode::$name_imm_imm,)+
                    $(Self::$name_reg_reg(..) => Opcode::$name_reg_reg,)+
                    $(Self::$name_reg_reg_imm_imm(..) => Opcode::$name_reg_reg_imm_imm,)+
                    Self::invalid(..) => Opcode::trap,
                }
            }
        }

        impl core::fmt::Display for Instruction {
            fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
                self.visit(fmt)
            }
        }

        pub mod asm {
            use super::{Instruction, Reg};

            $(
                pub fn $name_argless() -> Instruction {
                    Instruction::$name_argless
                }
            )+

            $(
                pub fn $name_reg_imm(reg: Reg, imm: u32) -> Instruction {
                    Instruction::$name_reg_imm(reg, imm)
                }
            )+

            $(
                pub fn $name_reg_imm_offset(reg: Reg, imm1: u32, imm2: u32) -> Instruction {
                    Instruction::$name_reg_imm_offset(reg, imm1, imm2)
                }
            )+

            $(
                pub fn $name_reg_imm_imm(reg: Reg, imm1: u32, imm2: u32) -> Instruction {
                    Instruction::$name_reg_imm_imm(reg, imm1, imm2)
                }
            )+

            $(
                pub fn $name_reg_reg_imm(reg1: Reg, reg2: Reg, imm: u32) -> Instruction {
                    Instruction::$name_reg_reg_imm(reg1, reg2, imm)
                }
            )+

            $(
                pub fn $name_reg_reg_reg(reg1: Reg, reg2: Reg, reg3: Reg) -> Instruction {
                    Instruction::$name_reg_reg_reg(reg1, reg2, reg3)
                }
            )+

            $(
                pub fn $name_offset(imm: u32) -> Instruction {
                    Instruction::$name_offset(imm)
                }
            )+

            $(
                pub fn $name_imm(imm: u32) -> Instruction {
                    Instruction::$name_imm(imm)
                }
            )+

            $(
                pub fn $name_imm_imm(imm1: u32, imm2: u32) -> Instruction {
                    Instruction::$name_imm_imm(imm1, imm2)
                }
            )+

            $(
                pub fn $name_reg_reg(reg1: Reg, reg2: Reg) -> Instruction {
                    Instruction::$name_reg_reg(reg1, reg2)
                }
            )+

            $(
                pub fn $name_reg_reg_imm_imm(reg1: Reg, reg2: Reg, imm1: u32, imm2: u32) -> Instruction {
                    Instruction::$name_reg_reg_imm_imm(reg1, reg2, imm1, imm2)
                }
            )+

            pub fn ret() -> Instruction {
                jump_indirect(Reg::RA, 0)
            }
        }

        #[macro_export]
        macro_rules! prepare_visitor {
            (@define_table $table_name:ident, $visitor_ty:ident<$d($visitor_ty_params:tt),*>) => {
                use $crate::program::{
                    InstructionVisitor,
                    VisitorHelper,
                };

                type ReturnTy<$d($visitor_ty_params),*> = <$visitor_ty<$d($visitor_ty_params),*> as InstructionVisitor>::ReturnTy;
                type VisitFn<$d($visitor_ty_params),*> = fn(state: &mut VisitorHelper<$visitor_ty<$d($visitor_ty_params),*>>) -> ReturnTy<$d($visitor_ty_params),*>;

                #[allow(unsafe_code)]
                static $table_name: [VisitFn; 256] = {
                    let mut table = [invalid_instruction as VisitFn; 256];
                    $({
                        // Putting all of the handlers in a single link section can make a big difference
                        // when it comes to performance, even up to 10% in some cases. This will force the
                        // compiler and the linker to put all of this code near each other, minimizing
                        // instruction cache misses.
                        #[cfg_attr(target_os = "linux", link_section = concat!(".text.", stringify!($table_name)))]
                        fn $name_argless<$d($visitor_ty_params),*>(state: &mut VisitorHelper<$visitor_ty<$d($visitor_ty_params),*>>) -> ReturnTy<$d($visitor_ty_params),*>{
                            state.visitor.$name_argless()
                        }

                        table[$value_argless] = $name_argless;
                    })*

                    $({
                        #[cfg_attr(target_os = "linux", link_section = concat!(".text.", stringify!($table_name)))]
                        fn $name_reg_imm<$d($visitor_ty_params),*>(state: &mut VisitorHelper<$visitor_ty<$d($visitor_ty_params),*>>) -> ReturnTy<$d($visitor_ty_params),*>{
                            if let Some((reg, imm)) = state.read_args_reg_imm() {
                                return state.visitor.$name_reg_imm(reg, imm);
                            };

                            state.visitor.invalid($value_reg_imm)
                        }

                        table[$value_reg_imm] = $name_reg_imm;
                    })*

                    $({
                        #[cfg_attr(target_os = "linux", link_section = concat!(".text.", stringify!($table_name)))]
                        fn $name_reg_imm_offset<$d($visitor_ty_params),*>(state: &mut VisitorHelper<$visitor_ty<$d($visitor_ty_params),*>>) -> ReturnTy<$d($visitor_ty_params),*>{
                            if let Some((reg, imm1, imm2)) = state.read_args_reg_imm_offset() {
                                return state.visitor.$name_reg_imm_offset(reg, imm1, imm2);
                            }

                            state.visitor.invalid($value_reg_imm_offset)
                        }

                        table[$value_reg_imm_offset] = $name_reg_imm_offset;
                    })*

                    $({
                        #[cfg_attr(target_os = "linux", link_section = concat!(".text.", stringify!($table_name)))]
                        fn $name_reg_imm_imm<$d($visitor_ty_params),*>(state: &mut VisitorHelper<$visitor_ty<$d($visitor_ty_params),*>>) -> ReturnTy<$d($visitor_ty_params),*>{
                            if let Some((reg, imm1, imm2)) = state.read_args_reg_imm2() {
                                return state.visitor.$name_reg_imm_imm(reg, imm1, imm2);
                            }

                            state.visitor.invalid($value_reg_imm_imm)
                        }

                        table[$value_reg_imm_imm] = $name_reg_imm_imm;
                    })*

                    $({
                        #[cfg_attr(target_os = "linux", link_section = concat!(".text.", stringify!($table_name)))]
                        fn $name_reg_reg_imm<$d($visitor_ty_params),*>(state: &mut VisitorHelper<$visitor_ty<$d($visitor_ty_params),*>>) -> ReturnTy<$d($visitor_ty_params),*>{
                            if let Some((reg1, reg2, imm)) = state.read_args_regs2_imm() {
                                return state.visitor.$name_reg_reg_imm(reg1, reg2, imm);
                            }

                            state.visitor.invalid($value_reg_reg_imm)
                        }

                        table[$value_reg_reg_imm] = $name_reg_reg_imm;
                    })*

                    $({
                        #[cfg_attr(target_os = "linux", link_section = concat!(".text.", stringify!($table_name)))]
                        fn $name_reg_reg_reg<$d($visitor_ty_params),*>(state: &mut VisitorHelper<$visitor_ty<$d($visitor_ty_params),*>>) -> ReturnTy<$d($visitor_ty_params),*>{
                            if let Some((reg1, reg2, reg3)) = state.read_args_regs3() {
                                return state.visitor.$name_reg_reg_reg(reg1, reg2, reg3);
                            }

                            state.visitor.invalid($value_reg_reg_reg)
                        }

                        table[$value_reg_reg_reg] = $name_reg_reg_reg;
                    })*

                    $({
                        #[cfg_attr(target_os = "linux", link_section = concat!(".text.", stringify!($table_name)))]
                        fn $name_offset<$d($visitor_ty_params),*>(state: &mut VisitorHelper<$visitor_ty<$d($visitor_ty_params),*>>) -> ReturnTy<$d($visitor_ty_params),*>{
                            if let Some(imm) = state.read_args_offset() {
                                return state.visitor.$name_offset(imm);
                            }

                            state.visitor.invalid($value_offset)
                        }

                        table[$value_offset] = $name_offset;
                    })*

                    $({
                        #[cfg_attr(target_os = "linux", link_section = concat!(".text.", stringify!($table_name)))]
                        fn $name_imm<$d($visitor_ty_params),*>(state: &mut VisitorHelper<$visitor_ty<$d($visitor_ty_params),*>>) -> ReturnTy<$d($visitor_ty_params),*>{
                            if let Some(imm) = state.read_args_imm() {
                                return state.visitor.$name_imm(imm);
                            }

                            state.visitor.invalid($value_imm)
                        }

                        table[$value_imm] = $name_imm;
                    })*

                    $({
                        #[cfg_attr(target_os = "linux", link_section = concat!(".text.", stringify!($table_name)))]
                        fn $name_imm_imm<$d($visitor_ty_params),*>(state: &mut VisitorHelper<$visitor_ty<$d($visitor_ty_params),*>>) -> ReturnTy<$d($visitor_ty_params),*>{
                            if let Some((imm1, imm2)) = state.read_args_imm2() {
                                return state.visitor.$name_imm_imm(imm1, imm2);
                            }

                            state.visitor.invalid($value_imm_imm)
                        }

                        table[$value_imm_imm] = $name_imm_imm;
                    })*

                    $({
                        #[cfg_attr(target_os = "linux", link_section = concat!(".text.", stringify!($table_name)))]
                        fn $name_reg_reg<$d($visitor_ty_params),*>(state: &mut VisitorHelper<$visitor_ty<$d($visitor_ty_params),*>>) -> ReturnTy<$d($visitor_ty_params),*>{
                            if let Some((reg1, reg2)) = state.read_args_regs2() {
                                return state.visitor.$name_reg_reg(reg1, reg2);
                            }

                            state.visitor.invalid($value_reg_reg)
                        }

                        table[$value_reg_reg] = $name_reg_reg;
                    })*

                    $({
                        #[cfg_attr(target_os = "linux", link_section = concat!(".text.", stringify!($table_name)))]
                        fn $name_reg_reg_imm_imm<$d($visitor_ty_params),*>(state: &mut VisitorHelper<$visitor_ty<$d($visitor_ty_params),*>>) -> ReturnTy<$d($visitor_ty_params),*>{
                            if let Some((reg1, reg2, imm1, imm2)) = state.read_args_regs2_imm2() {
                                return state.visitor.$name_reg_reg_imm_imm(reg1, reg2, imm1, imm2);
                            }

                            state.visitor.invalid($value_reg_reg_imm_imm)
                        }

                        table[$value_reg_reg_imm_imm] = $name_reg_reg_imm_imm;
                    })*

                    #[cfg_attr(target_os = "linux", link_section = concat!(".text.", stringify!($table_name)))]
                    #[cold]
                    fn invalid_instruction<$d($visitor_ty_params),*>(state: &mut VisitorHelper<$visitor_ty<$d($visitor_ty_params),*>>) -> ReturnTy<$d($visitor_ty_params),*>{
                        state.visitor.invalid(state.opcode())
                    }

                    table
                };
            };

            ($table_name:ident, $visitor_ty:ident<$d($visitor_ty_params:tt),*>) => {{
                $crate::program::prepare_visitor!(@define_table $table_name, $visitor_ty<$d($visitor_ty_params),*>);

                #[inline]
                fn run<$d($visitor_ty_params),*>(
                    blob: &ProgramBlob,
                    visitor: $visitor_ty<$d($visitor_ty_params),*>,
                )
                    -> $visitor_ty<$d($visitor_ty_params),*>
                {
                    let decode_table: &'static [VisitFn; 256] = &$table_name;

                    #[allow(unsafe_code)]
                    // SAFETY: Here we transmute the lifetimes which were unnecessarily extended to be 'static due to the table here being a `static`.
                    let decode_table: &[VisitFn; 256] = unsafe { core::mem::transmute(decode_table) };

                    VisitorHelper::new(visitor).run(blob, decode_table)
                }

                run
            }};
        }

        pub use prepare_visitor;

        struct ToEnumVisitor<'a>(core::marker::PhantomData<&'a ()>);

        impl<'a> ParsingVisitor for ToEnumVisitor<'a> {
            fn on_pre_visit(&mut self, _offset: usize, _opcode: u8) {}
        }

        impl<'a> InstructionVisitor for ToEnumVisitor<'a> {
            type ReturnTy = Instruction;

            $(fn $name_argless(&mut self) -> Self::ReturnTy {
                Instruction::$name_argless
            })+
            $(fn $name_reg_imm(&mut self, reg: Reg, imm: u32) -> Self::ReturnTy {
                Instruction::$name_reg_imm(reg, imm)
            })+
            $(fn $name_reg_imm_offset(&mut self, reg: Reg, imm1: u32, imm2: u32) -> Self::ReturnTy {
                Instruction::$name_reg_imm_offset(reg, imm1, imm2)
            })+
            $(fn $name_reg_imm_imm(&mut self, reg: Reg, imm1: u32, imm2: u32) -> Self::ReturnTy {
                Instruction::$name_reg_imm_imm(reg, imm1, imm2)
            })+
            $(fn $name_reg_reg_imm(&mut self, reg1: Reg, reg2: Reg, imm: u32) -> Self::ReturnTy {
                Instruction::$name_reg_reg_imm(reg1, reg2, imm)
            })+
            $(fn $name_reg_reg_reg(&mut self, reg1: Reg, reg2: Reg, reg3: Reg) -> Self::ReturnTy {
                Instruction::$name_reg_reg_reg(reg1, reg2, reg3)
            })+
            $(fn $name_offset(&mut self, imm: u32) -> Self::ReturnTy {
                Instruction::$name_offset(imm)
            })+
            $(fn $name_imm(&mut self, imm: u32) -> Self::ReturnTy {
                Instruction::$name_imm(imm)
            })+
            $(fn $name_imm_imm(&mut self, imm1: u32, imm2: u32) -> Self::ReturnTy {
                Instruction::$name_imm_imm(imm1, imm2)
            })+
            $(fn $name_reg_reg(&mut self, reg1: Reg, reg2: Reg) -> Self::ReturnTy {
                Instruction::$name_reg_reg(reg1, reg2)
            })+
            $(fn $name_reg_reg_imm_imm(&mut self, reg1: Reg, reg2: Reg, imm1: u32, imm2: u32) -> Self::ReturnTy {
                Instruction::$name_reg_reg_imm_imm(reg1, reg2, imm1, imm2)
            })+
        }

        #[inline]
        fn parse_instruction(code: &[u8], bitmask: &[u8], offset: &mut usize) -> Option<ParsedInstruction> {
            prepare_visitor!(@define_table TO_ENUM_VISITOR, ToEnumVisitor<'a>);

            let decode_table: &[VisitFn; 256] = &TO_ENUM_VISITOR;

            #[allow(unsafe_code)]
            // SAFETY: Here we transmute the lifetimes which were unnecessarily extended to be 'static due to the table here being a `static`.
            let decode_table: &[VisitFn; 256] = unsafe { core::mem::transmute(decode_table) };

            let mut helper = VisitorHelper::new(ToEnumVisitor(core::marker::PhantomData));
            let origin = *offset;
            let instruction = helper.step(code, bitmask, offset, decode_table)?;
            let length = helper.args_length + 1;

            Some(ParsedInstruction {
                kind: instruction,
                offset: origin as u32,
                length: length as u32,
            })
        }

        define_opcodes!(
            @impl_shared
            $($name_argless = $value_argless,)+
            $($name_reg_imm = $value_reg_imm,)+
            $($name_reg_imm_offset = $value_reg_imm_offset,)+
            $($name_reg_imm_imm = $value_reg_imm_imm,)+
            $($name_reg_reg_imm = $value_reg_reg_imm,)+
            $($name_reg_reg_reg = $value_reg_reg_reg,)+
            $($name_offset = $value_offset,)+
            $($name_imm = $value_imm,)+
            $($name_imm_imm = $value_imm_imm,)+
            $($name_reg_reg = $value_reg_reg,)+
            $($name_reg_reg_imm_imm = $value_reg_reg_imm_imm,)+
        );
    }
}

// NOTE: The opcodes here are assigned roughly in the order of how common a given instruction is,
// except the `trap` which is deliberately hardcoded as zero.
define_opcodes! {
    $

    // Instructions with args: none
    [
        trap                                     = 0,
        fallthrough                              = 17,
    ]

    // Instructions with args: reg, imm
    [
        jump_indirect                            = 19,
        load_imm                                 = 4,
        load_u8                                  = 60,
        load_i8                                  = 74,
        load_u16                                 = 76,
        load_i16                                 = 66,
        load_u32                                 = 10,
        store_u8                                 = 71,
        store_u16                                = 69,
        store_u32                                = 22,
    ]

    // Instructions with args: reg, imm, offset
    [
        load_imm_and_jump                        = 6,
        branch_eq_imm                            = 7,
        branch_not_eq_imm                        = 15,
        branch_less_unsigned_imm                 = 44,
        branch_less_signed_imm                   = 32,
        branch_greater_or_equal_unsigned_imm     = 52,
        branch_greater_or_equal_signed_imm       = 45,
        branch_less_or_equal_signed_imm          = 46,
        branch_less_or_equal_unsigned_imm        = 59,
        branch_greater_signed_imm                = 53,
        branch_greater_unsigned_imm              = 50,
    ]

    // Instructions with args: reg, imm, imm
    [
        store_imm_indirect_u8                    = 26,
        store_imm_indirect_u16                   = 54,
        store_imm_indirect_u32                   = 13,
    ]

    // Instructions with args: reg, reg, imm
    [
        store_indirect_u8                        = 16,
        store_indirect_u16                       = 29,
        store_indirect_u32                       = 3,
        load_indirect_u8                         = 11,
        load_indirect_i8                         = 21,
        load_indirect_u16                        = 37,
        load_indirect_i16                        = 33,
        load_indirect_u32                        = 1,
        add_imm                                  = 2,
        and_imm                                  = 18,
        xor_imm                                  = 31,
        or_imm                                   = 49,
        mul_imm                                  = 35,
        mul_upper_signed_signed_imm              = 65,
        mul_upper_unsigned_unsigned_imm          = 63,
        set_less_than_unsigned_imm               = 27,
        set_less_than_signed_imm                 = 56,
        shift_logical_left_imm                   = 9,
        shift_logical_right_imm                  = 14,
        shift_arithmetic_right_imm               = 25,
        negate_and_add_imm                       = 40,
        set_greater_than_unsigned_imm            = 39,
        set_greater_than_signed_imm              = 61,
        shift_logical_right_imm_alt              = 72,
        shift_arithmetic_right_imm_alt           = 80,
        shift_logical_left_imm_alt               = 75,
        branch_eq                                = 24,
        branch_not_eq                            = 30,
        branch_less_unsigned                     = 47,
        branch_less_signed                       = 48,
        branch_greater_or_equal_unsigned         = 41,
        branch_greater_or_equal_signed           = 43,

        cmov_if_zero_imm                         = 85,
        cmov_if_not_zero_imm                     = 86,
    ]

    // Instructions with args: reg, reg, reg
    [
        add                                      = 8,
        sub                                      = 20,
        and                                      = 23,
        xor                                      = 28,
        or                                       = 12,
        mul                                      = 34,
        mul_upper_signed_signed                  = 67,
        mul_upper_unsigned_unsigned              = 57,
        mul_upper_signed_unsigned                = 81,
        set_less_than_unsigned                   = 36,
        set_less_than_signed                     = 58,
        shift_logical_left                       = 55,
        shift_logical_right                      = 51,
        shift_arithmetic_right                   = 77,
        div_unsigned                             = 68,
        div_signed                               = 64,
        rem_unsigned                             = 73,
        rem_signed                               = 70,

        cmov_if_zero                             = 83,
        cmov_if_not_zero                         = 84,
    ]

    // Instructions with args: offset
    [
        jump                                     = 5,
    ]

    // Instructions with args: imm
    [
        ecalli                                   = 78,
    ]

    // Instructions with args: imm, imm
    [
        store_imm_u8                             = 62,
        store_imm_u16                            = 79,
        store_imm_u32                            = 38,
    ]

    // Instructions with args: reg, reg
    [
        move_reg                                 = 82,
        sbrk                                     = 87,
    ]

    // Instructions with args: reg, reg, imm, imm
    [
        load_imm_and_jump_indirect               = 42,
    ]
}

impl Opcode {
    pub fn starts_new_basic_block(self) -> bool {
        matches!(
            self,
            Self::trap
                | Self::fallthrough
                | Self::jump
                | Self::jump_indirect
                | Self::load_imm_and_jump
                | Self::load_imm_and_jump_indirect
                | Self::branch_eq
                | Self::branch_eq_imm
                | Self::branch_greater_or_equal_signed
                | Self::branch_greater_or_equal_signed_imm
                | Self::branch_greater_or_equal_unsigned
                | Self::branch_greater_or_equal_unsigned_imm
                | Self::branch_greater_signed_imm
                | Self::branch_greater_unsigned_imm
                | Self::branch_less_or_equal_signed_imm
                | Self::branch_less_or_equal_unsigned_imm
                | Self::branch_less_signed
                | Self::branch_less_signed_imm
                | Self::branch_less_unsigned
                | Self::branch_less_unsigned_imm
                | Self::branch_not_eq
                | Self::branch_not_eq_imm
        )
    }
}

impl Instruction {
    pub fn starts_new_basic_block(self) -> bool {
        self.opcode().starts_new_basic_block()
    }

    fn serialize_argless(buffer: &mut [u8], opcode: Opcode) -> usize {
        buffer[0] = opcode as u8;
        1
    }

    fn serialize_reg_imm_offset(buffer: &mut [u8], position: u32, opcode: Opcode, reg: Reg, imm1: u32, imm2: u32) -> usize {
        let imm2 = imm2.wrapping_sub(position);
        buffer[0] = opcode as u8;
        buffer[1] = reg as u8;
        let mut position = 2;
        position += write_varint(imm1, &mut buffer[position..]);
        position += write_simple_varint(imm2, &mut buffer[position..]);
        position
    }

    fn serialize_reg_imm_imm(buffer: &mut [u8], opcode: Opcode, reg: Reg, imm1: u32, imm2: u32) -> usize {
        buffer[0] = opcode as u8;
        buffer[1] = reg as u8;
        let mut position = 2;
        position += write_varint(imm1, &mut buffer[position..]);
        position += write_simple_varint(imm2, &mut buffer[position..]);
        position
    }
    fn serialize_reg_reg_imm_imm(buffer: &mut [u8], opcode: Opcode, reg1: Reg, reg2: Reg, imm1: u32, imm2: u32) -> usize {
        buffer[0] = opcode as u8;
        buffer[1] = reg1 as u8 | (reg2 as u8) << 4;
        let mut position = 2;
        position += write_varint(imm1, &mut buffer[position..]);
        position += write_simple_varint(imm2, &mut buffer[position..]);
        position
    }

    fn serialize_reg_reg_reg(buffer: &mut [u8], opcode: Opcode, reg1: Reg, reg2: Reg, reg3: Reg) -> usize {
        buffer[0] = opcode as u8;
        buffer[1] = reg1 as u8 | (reg2 as u8) << 4;
        buffer[2] = reg3 as u8;
        3
    }

    fn serialize_reg_reg_imm(buffer: &mut [u8], opcode: Opcode, reg1: Reg, reg2: Reg, imm: u32) -> usize {
        buffer[0] = opcode as u8;
        buffer[1] = reg1 as u8 | (reg2 as u8) << 4;
        write_simple_varint(imm, &mut buffer[2..]) + 2
    }

    fn serialize_reg_imm(buffer: &mut [u8], opcode: Opcode, reg: Reg, imm: u32) -> usize {
        buffer[0] = opcode as u8;
        buffer[1] = reg as u8;
        write_simple_varint(imm, &mut buffer[2..]) + 2
    }

    fn serialize_offset(buffer: &mut [u8], position: u32, opcode: Opcode, imm: u32) -> usize {
        let imm = imm.wrapping_sub(position);
        buffer[0] = opcode as u8;
        write_simple_varint(imm, &mut buffer[1..]) + 1
    }

    fn serialize_imm(buffer: &mut [u8], opcode: Opcode, imm: u32) -> usize {
        buffer[0] = opcode as u8;
        write_simple_varint(imm, &mut buffer[1..]) + 1
    }

    fn serialize_imm_imm(buffer: &mut [u8], opcode: Opcode, imm1: u32, imm2: u32) -> usize {
        buffer[0] = opcode as u8;
        let mut position = 1;
        position += write_varint(imm1, &mut buffer[position..]);
        position += write_simple_varint(imm2, &mut buffer[position..]);
        position
    }

    fn serialize_reg_reg(buffer: &mut [u8], opcode: Opcode, reg1: Reg, reg2: Reg) -> usize {
        buffer[0] = opcode as u8;
        buffer[1] = reg1 as u8 | (reg2 as u8) << 4;
        2
    }
}

pub const MAX_INSTRUCTION_LENGTH: usize = 2 + MAX_VARINT_LENGTH * 2;

impl<'a> InstructionVisitor for core::fmt::Formatter<'a> {
    type ReturnTy = core::fmt::Result;

    fn trap(&mut self) -> Self::ReturnTy {
        write!(self, "trap")
    }

    fn fallthrough(&mut self) -> Self::ReturnTy {
        write!(self, "fallthrough")
    }

    fn sbrk(&mut self, d: Reg, s: Reg) -> Self::ReturnTy {
        write!(self, "{d} = sbrk {s}")
    }

    fn ecalli(&mut self, nth_import: u32) -> Self::ReturnTy {
        write!(self, "ecalli {nth_import}")
    }

    fn set_less_than_unsigned(&mut self, d: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        write!(self, "{d} = {s1} <u {s2}")
    }

    fn set_less_than_signed(&mut self, d: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        write!(self, "{d} = {s1} <s {s2}")
    }

    fn shift_logical_right(&mut self, d: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        write!(self, "{d} = {s1} >> {s2}")
    }

    fn shift_arithmetic_right(&mut self, d: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        write!(self, "{d} = {s1} >>a {s2}")
    }

    fn shift_logical_left(&mut self, d: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        write!(self, "{d} = {s1} << {s2}")
    }

    fn xor(&mut self, d: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        write!(self, "{d} = {s1} ^ {s2}")
    }

    fn and(&mut self, d: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        write!(self, "{d} = {s1} & {s2}")
    }

    fn or(&mut self, d: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        write!(self, "{d} = {s1} | {s2}")
    }

    fn add(&mut self, d: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        write!(self, "{d} = {s1} + {s2}")
    }

    fn sub(&mut self, d: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        write!(self, "{d} = {s1} - {s2}")
    }

    fn mul(&mut self, d: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        write!(self, "{d} = {s1} * {s2}")
    }

    fn mul_imm(&mut self, d: Reg, s1: Reg, s2: u32) -> Self::ReturnTy {
        write!(self, "{d} = {s1} * {s2}")
    }

    fn mul_upper_signed_signed(&mut self, d: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        write!(self, "{d} = ({s1} as i64 * {s2} as i64) >> 32")
    }

    fn mul_upper_signed_signed_imm(&mut self, d: Reg, s1: Reg, s2: u32) -> Self::ReturnTy {
        write!(self, "{d} = ({s1} as i64 * {s2} as i64) >> 32", s2 = s2 as i32)
    }

    fn mul_upper_unsigned_unsigned(&mut self, d: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        write!(self, "{d} = ({s1} as u64 * {s2} as u64) >> 32")
    }

    fn mul_upper_unsigned_unsigned_imm(&mut self, d: Reg, s1: Reg, s2: u32) -> Self::ReturnTy {
        write!(self, "{d} = ({s1} as u64 * {s2} as u64) >> 32")
    }

    fn mul_upper_signed_unsigned(&mut self, d: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        write!(self, "{d} = ({s1} as i64 * {s2} as u64) >> 32")
    }

    fn div_unsigned(&mut self, d: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        write!(self, "{d} = {s1} /u {s2}")
    }

    fn div_signed(&mut self, d: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        write!(self, "{d} = {s1} /s {s2}")
    }

    fn rem_unsigned(&mut self, d: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        write!(self, "{d} = {s1} %u {s2}")
    }

    fn rem_signed(&mut self, d: Reg, s1: Reg, s2: Reg) -> Self::ReturnTy {
        write!(self, "{d} = {s1} %s {s2}")
    }

    fn set_less_than_unsigned_imm(&mut self, d: Reg, s1: Reg, s2: u32) -> Self::ReturnTy {
        write!(self, "{d} = {s1} <u 0x{s2:x}")
    }

    fn set_greater_than_unsigned_imm(&mut self, d: Reg, s1: Reg, s2: u32) -> Self::ReturnTy {
        write!(self, "{d} = {s1} >u 0x{s2:x}")
    }

    fn set_less_than_signed_imm(&mut self, d: Reg, s1: Reg, s2: u32) -> Self::ReturnTy {
        write!(self, "{d} = {s1} <s {s2}", s2 = s2 as i32)
    }

    fn set_greater_than_signed_imm(&mut self, d: Reg, s1: Reg, s2: u32) -> Self::ReturnTy {
        write!(self, "{d} = {s1} >s {s2}", s2 = s2 as i32)
    }

    fn shift_logical_right_imm(&mut self, d: Reg, s1: Reg, s2: u32) -> Self::ReturnTy {
        write!(self, "{d} = {s1} >> {s2}")
    }

    fn shift_logical_right_imm_alt(&mut self, d: Reg, s2: Reg, s1: u32) -> Self::ReturnTy {
        write!(self, "{d} = {s1} >> {s2}")
    }

    fn shift_arithmetic_right_imm(&mut self, d: Reg, s1: Reg, s2: u32) -> Self::ReturnTy {
        write!(self, "{d} = {s1} >>a {s2}")
    }

    fn shift_arithmetic_right_imm_alt(&mut self, d: Reg, s2: Reg, s1: u32) -> Self::ReturnTy {
        write!(self, "{d} = {s1} >>a {s2}")
    }

    fn shift_logical_left_imm(&mut self, d: Reg, s1: Reg, s2: u32) -> Self::ReturnTy {
        write!(self, "{d} = {s1} << {s2}")
    }

    fn shift_logical_left_imm_alt(&mut self, d: Reg, s2: Reg, s1: u32) -> Self::ReturnTy {
        write!(self, "{d} = {s1} << {s2}")
    }

    fn or_imm(&mut self, d: Reg, s1: Reg, s2: u32) -> Self::ReturnTy {
        write!(self, "{d} = {s1} | 0x{s2:x}")
    }

    fn and_imm(&mut self, d: Reg, s1: Reg, s2: u32) -> Self::ReturnTy {
        write!(self, "{d} = {s1} & 0x{s2:x}")
    }

    fn xor_imm(&mut self, d: Reg, s1: Reg, s2: u32) -> Self::ReturnTy {
        write!(self, "{d} = {s1} ^ 0x{s2:x}")
    }

    fn load_imm(&mut self, d: Reg, a: u32) -> Self::ReturnTy {
        write!(self, "{d} = 0x{a:x}")
    }

    fn move_reg(&mut self, d: Reg, s: Reg) -> Self::ReturnTy {
        write!(self, "{d} = {s}")
    }

    fn cmov_if_zero(&mut self, d: Reg, s: Reg, c: Reg) -> Self::ReturnTy {
        write!(self, "{d} = {s} if {c} == 0")
    }

    fn cmov_if_not_zero(&mut self, d: Reg, s: Reg, c: Reg) -> Self::ReturnTy {
        write!(self, "{d} = {s} if {c} != 0")
    }

    fn cmov_if_zero_imm(&mut self, d: Reg, c: Reg, s: u32) -> Self::ReturnTy {
        write!(self, "{d} = {s} if {c} == 0")
    }

    fn cmov_if_not_zero_imm(&mut self, d: Reg, c: Reg, s: u32) -> Self::ReturnTy {
        write!(self, "{d} = {s} if {c} != 0")
    }

    fn add_imm(&mut self, d: Reg, s1: Reg, s2: u32) -> Self::ReturnTy {
        if (s2 as i32) < 0 && (s2 as i32) > -4096 {
            write!(self, "{d} = {s1} - {s2}", s2 = -(s2 as i32))
        } else {
            write!(self, "{d} = {s1} + 0x{s2:x}")
        }
    }

    fn negate_and_add_imm(&mut self, d: Reg, s1: Reg, s2: u32) -> Self::ReturnTy {
        if s2 == 0 {
            write!(self, "{d} = -{s1}")
        } else {
            write!(self, "{d} = -{s1} + {s2}")
        }
    }

    fn store_imm_indirect_u8(&mut self, base: Reg, offset: u32, value: u32) -> Self::ReturnTy {
        write!(self, "u8 [{base} + {offset}] = {value}")
    }

    fn store_imm_indirect_u16(&mut self, base: Reg, offset: u32, value: u32) -> Self::ReturnTy {
        write!(self, "u16 [{base} + {offset}] = {value}")
    }

    fn store_imm_indirect_u32(&mut self, base: Reg, offset: u32, value: u32) -> Self::ReturnTy {
        write!(self, "u32 [{base} + {offset}] = {value}")
    }

    fn store_indirect_u8(&mut self, src: Reg, base: Reg, offset: u32) -> Self::ReturnTy {
        if offset != 0 {
            write!(self, "u8 [{base} + {offset}] = {src}")
        } else {
            write!(self, "u8 [{base}] = {src}")
        }
    }

    fn store_indirect_u16(&mut self, src: Reg, base: Reg, offset: u32) -> Self::ReturnTy {
        if offset != 0 {
            write!(self, "u16 [{base} + {offset}] = {src}")
        } else {
            write!(self, "u16 [{base}] = {src}")
        }
    }

    fn store_indirect_u32(&mut self, src: Reg, base: Reg, offset: u32) -> Self::ReturnTy {
        if offset != 0 {
            write!(self, "u32 [{base} + {offset}] = {src}")
        } else {
            write!(self, "u32 [{base}] = {src}")
        }
    }

    fn store_imm_u8(&mut self, value: u32, offset: u32) -> Self::ReturnTy {
        write!(self, "u8 [0x{offset:x}] = {value}")
    }

    fn store_imm_u16(&mut self, value: u32, offset: u32) -> Self::ReturnTy {
        write!(self, "u16 [0x{offset:x}] = {value}")
    }

    fn store_imm_u32(&mut self, value: u32, offset: u32) -> Self::ReturnTy {
        write!(self, "u32 [0x{offset:x}] = {value}")
    }

    fn store_u8(&mut self, src: Reg, offset: u32) -> Self::ReturnTy {
        write!(self, "u8 [0x{offset:x}] = {src}")
    }

    fn store_u16(&mut self, src: Reg, offset: u32) -> Self::ReturnTy {
        write!(self, "u16 [0x{offset:x}] = {src}")
    }

    fn store_u32(&mut self, src: Reg, offset: u32) -> Self::ReturnTy {
        write!(self, "u32 [0x{offset:x}] = {src}")
    }

    fn load_indirect_u8(&mut self, dst: Reg, base: Reg, offset: u32) -> Self::ReturnTy {
        if offset != 0 {
            write!(self, "{} = u8 [{} + {}]", dst, base, offset)
        } else {
            write!(self, "{} = u8 [{}]", dst, base)
        }
    }

    fn load_indirect_i8(&mut self, dst: Reg, base: Reg, offset: u32) -> Self::ReturnTy {
        if offset != 0 {
            write!(self, "{} = i8 [{} + {}]", dst, base, offset)
        } else {
            write!(self, "{} = i8 [{}]", dst, base)
        }
    }

    fn load_indirect_u16(&mut self, dst: Reg, base: Reg, offset: u32) -> Self::ReturnTy {
        if offset != 0 {
            write!(self, "{} = u16 [{} + {}]", dst, base, offset)
        } else {
            write!(self, "{} = u16 [{} ]", dst, base)
        }
    }

    fn load_indirect_i16(&mut self, dst: Reg, base: Reg, offset: u32) -> Self::ReturnTy {
        if offset != 0 {
            write!(self, "{} = i16 [{} + {}]", dst, base, offset)
        } else {
            write!(self, "{} = i16 [{}]", dst, base)
        }
    }

    fn load_indirect_u32(&mut self, dst: Reg, base: Reg, offset: u32) -> Self::ReturnTy {
        if offset != 0 {
            write!(self, "{} = u32 [{} + {}]", dst, base, offset)
        } else {
            write!(self, "{} = u32 [{}]", dst, base)
        }
    }

    fn load_u8(&mut self, dst: Reg, offset: u32) -> Self::ReturnTy {
        write!(self, "{} = u8 [0x{:x}]", dst, offset)
    }

    fn load_i8(&mut self, dst: Reg, offset: u32) -> Self::ReturnTy {
        write!(self, "{} = i8 [0x{:x}]", dst, offset)
    }

    fn load_u16(&mut self, dst: Reg, offset: u32) -> Self::ReturnTy {
        write!(self, "{} = u16 [0x{:x}]", dst, offset)
    }

    fn load_i16(&mut self, dst: Reg, offset: u32) -> Self::ReturnTy {
        write!(self, "{} = i16 [0x{:x}]", dst, offset)
    }

    fn load_u32(&mut self, dst: Reg, offset: u32) -> Self::ReturnTy {
        write!(self, "{} = u32 [0x{:x}]", dst, offset)
    }

    fn branch_less_unsigned(&mut self, s1: Reg, s2: Reg, imm: u32) -> Self::ReturnTy {
        write!(self, "jump {} if {} <u {}", imm, s1, s2)
    }

    fn branch_less_signed(&mut self, s1: Reg, s2: Reg, imm: u32) -> Self::ReturnTy {
        write!(self, "jump {} if {} <s {}", imm, s1, s2)
    }

    fn branch_less_unsigned_imm(&mut self, s1: Reg, s2: u32, imm: u32) -> Self::ReturnTy {
        write!(self, "jump {} if {} <u {}", imm, s1, s2)
    }

    fn branch_less_signed_imm(&mut self, s1: Reg, s2: u32, imm: u32) -> Self::ReturnTy {
        write!(self, "jump {} if {} <s {}", imm, s1, s2)
    }

    fn branch_greater_or_equal_unsigned(&mut self, s1: Reg, s2: Reg, imm: u32) -> Self::ReturnTy {
        write!(self, "jump {} if {} >=u {}", imm, s1, s2)
    }

    fn branch_greater_or_equal_signed(&mut self, s1: Reg, s2: Reg, imm: u32) -> Self::ReturnTy {
        write!(self, "jump {} if {} >=s {}", imm, s1, s2)
    }

    fn branch_greater_or_equal_unsigned_imm(&mut self, s1: Reg, s2: u32, imm: u32) -> Self::ReturnTy {
        write!(self, "jump {} if {} >=u {}", imm, s1, s2)
    }

    fn branch_greater_or_equal_signed_imm(&mut self, s1: Reg, s2: u32, imm: u32) -> Self::ReturnTy {
        write!(self, "jump {} if {} >=s {}", imm, s1, s2)
    }

    fn branch_eq(&mut self, s1: Reg, s2: Reg, imm: u32) -> Self::ReturnTy {
        write!(self, "jump {} if {} == {}", imm, s1, s2)
    }

    fn branch_not_eq(&mut self, s1: Reg, s2: Reg, imm: u32) -> Self::ReturnTy {
        write!(self, "jump {} if {} != {}", imm, s1, s2)
    }

    fn branch_eq_imm(&mut self, s1: Reg, s2: u32, imm: u32) -> Self::ReturnTy {
        write!(self, "jump {} if {} == {}", imm, s1, s2)
    }

    fn branch_not_eq_imm(&mut self, s1: Reg, s2: u32, imm: u32) -> Self::ReturnTy {
        write!(self, "jump {} if {} != {}", imm, s1, s2)
    }

    fn branch_less_or_equal_unsigned_imm(&mut self, s1: Reg, s2: u32, imm: u32) -> Self::ReturnTy {
        write!(self, "jump {} if {} <=u {}", imm, s1, s2)
    }

    fn branch_less_or_equal_signed_imm(&mut self, s1: Reg, s2: u32, imm: u32) -> Self::ReturnTy {
        write!(self, "jump {} if {} <=s {}", imm, s1, s2)
    }

    fn branch_greater_unsigned_imm(&mut self, s1: Reg, s2: u32, imm: u32) -> Self::ReturnTy {
        write!(self, "jump {} if {} >u {}", imm, s1, s2)
    }

    fn branch_greater_signed_imm(&mut self, s1: Reg, s2: u32, imm: u32) -> Self::ReturnTy {
        write!(self, "jump {} if {} >s {}", imm, s1, s2)
    }

    fn jump(&mut self, target: u32) -> Self::ReturnTy {
        write!(self, "jump {}", target)
    }

    fn load_imm_and_jump(&mut self, ra: Reg, value: u32, target: u32) -> Self::ReturnTy {
        write!(self, "{ra} = {value}, jump {target}")
    }

    fn jump_indirect(&mut self, base: Reg, offset: u32) -> Self::ReturnTy {
        use Reg::*;
        match (base, offset) {
            (RA, 0) => write!(self, "ret"),
            (_, 0) => write!(self, "jump [{}]", base),
            (_, _) => write!(self, "jump [{} + {}]", base, offset),
        }
    }

    fn load_imm_and_jump_indirect(&mut self, ra: Reg, base: Reg, value: u32, offset: u32) -> Self::ReturnTy {
        if offset == 0 {
            write!(self, "jump [{base}], {ra} = {value}")
        } else {
            write!(self, "jump [{base} + {offset}], {ra} = {value}")
        }
    }

    fn invalid(&mut self, opcode: u8) -> Self::ReturnTy {
        write!(self, "invalid 0x{opcode:02x}")
    }
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

impl ProgramParseError {
    #[cold]
    #[inline]
    fn failed_to_read_varint(offset: usize) -> ProgramParseError {
        ProgramParseError(ProgramParseErrorKind::FailedToReadVarint { offset })
    }

    #[cold]
    #[inline]
    fn unexpected_end_of_file(offset: usize, expected_count: usize, actual_count: usize) -> ProgramParseError {
        ProgramParseError(ProgramParseErrorKind::UnexpectedEnd {
            offset,
            expected_count,
            actual_count,
        })
    }
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
    target_code_offset: u32,
    symbol: ProgramSymbol<'a>,
}

impl<'a> ProgramExport<'a> {
    pub fn new(target_code_offset: u32, symbol: ProgramSymbol<'a>) -> Self {
        Self {
            target_code_offset,
            symbol,
        }
    }

    pub fn target_code_offset(&self) -> u32 {
        self.target_code_offset
    }

    pub fn symbol(&self) -> &ProgramSymbol<'a> {
        &self.symbol
    }

    #[cfg(feature = "alloc")]
    pub fn into_owned(self) -> ProgramExport<'static> {
        ProgramExport {
            target_code_offset: self.target_code_offset,
            symbol: self.symbol.into_owned(),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ProgramSymbol<'a>(CowBytes<'a>);

impl<'a> ProgramSymbol<'a> {
    pub fn new(bytes: CowBytes<'a>) -> Self {
        Self(bytes)
    }

    pub fn into_inner(self) -> CowBytes<'a> {
        self.0
    }

    pub fn as_bytes(&'a self) -> &'a [u8] {
        &self.0
    }

    #[cfg(feature = "alloc")]
    pub fn into_owned(self) -> ProgramSymbol<'static> {
        ProgramSymbol(self.0.into_owned())
    }
}

impl<'a> From<&'a [u8]> for ProgramSymbol<'a> {
    fn from(symbol: &'a [u8]) -> Self {
        ProgramSymbol(symbol.into())
    }
}

impl<'a> From<&'a str> for ProgramSymbol<'a> {
    fn from(symbol: &'a str) -> Self {
        ProgramSymbol(symbol.into())
    }
}

#[cfg(feature = "alloc")]
impl<'a> From<alloc::vec::Vec<u8>> for ProgramSymbol<'a> {
    fn from(symbol: alloc::vec::Vec<u8>) -> Self {
        ProgramSymbol(symbol.into())
    }
}

impl<'a> core::ops::Deref for ProgramSymbol<'a> {
    type Target = CowBytes<'a>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<'a> core::fmt::Display for ProgramSymbol<'a> {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
        if let Ok(ident) = core::str::from_utf8(&self.0) {
            fmt.write_str("'")?;
            fmt.write_str(ident)?;
            fmt.write_str("'")?;
        } else {
            fmt.write_str("0x")?;
            for &byte in self.0.iter() {
                core::write!(fmt, "{:02x}", byte)?;
            }
        }

        Ok(())
    }
}

/// A partially deserialized PolkaVM program.
#[derive(Clone, Default)]
pub struct ProgramBlob<'a> {
    blob: CowBytes<'a>,

    ro_data_size: u32,
    rw_data_size: u32,
    stack_size: u32,

    ro_data: Range<usize>,
    rw_data: Range<usize>,
    exports: Range<usize>,
    import_offsets: Range<usize>,
    import_symbols: Range<usize>,
    code: Range<usize>,
    jump_table: Range<usize>,
    jump_table_entry_size: u8,
    bitmask: Range<usize>,

    debug_strings: Range<usize>,
    debug_line_program_ranges: Range<usize>,
    debug_line_programs: Range<usize>,
}

#[derive(Clone)]
struct Reader<'a> {
    blob: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    fn skip(&mut self, count: usize) -> Result<(), ProgramParseError> {
        self.read_slice_as_range(count).map(|_| ())
    }

    #[inline(always)]
    fn read_byte(&mut self) -> Result<u8, ProgramParseError> {
        Ok(self.read_slice(1)?[0])
    }

    #[inline(always)]
    fn read_slice(&mut self, length: usize) -> Result<&'a [u8], ProgramParseError> {
        let Some(slice) = self.blob.get(..length) else {
            return Err(ProgramParseError::unexpected_end_of_file(self.position, length, self.blob.len()));
        };

        self.position += length;
        self.blob = &self.blob[length..];
        Ok(slice)
    }

    #[inline(always)]
    fn read_varint(&mut self) -> Result<u32, ProgramParseError> {
        let first_byte = self.read_byte()?;
        let Some((length, value)) = read_varint(self.blob, first_byte) else {
            return Err(ProgramParseError::failed_to_read_varint(self.position - 1));
        };

        self.position += length;
        self.blob = &self.blob[length..];
        Ok(value)
    }

    fn read_bytes_with_length(&mut self) -> Result<&'a [u8], ProgramParseError> {
        let length = self.read_varint()? as usize;
        self.read_slice(length)
    }

    fn read_string_with_length(&mut self) -> Result<&'a str, ProgramParseError> {
        let offset = self.position;
        let slice = self.read_bytes_with_length()?;

        core::str::from_utf8(slice)
            .ok()
            .ok_or(ProgramParseError(ProgramParseErrorKind::FailedToReadStringNonUtf { offset }))
    }

    fn read_slice_as_range(&mut self, count: usize) -> Result<Range<usize>, ProgramParseError> {
        if self.blob.len() < count {
            return Err(ProgramParseError::unexpected_end_of_file(self.position, count, self.blob.len()));
        };

        let range = self.position..self.position + count;
        self.position += count;
        self.blob = &self.blob[count..];
        Ok(range)
    }

    fn read_section_range_into(
        &mut self,
        out_section: &mut u8,
        out_range: &mut Range<usize>,
        expected_section: u8,
    ) -> Result<(), ProgramParseError> {
        if *out_section == expected_section {
            let section_length = self.read_varint()? as usize;
            *out_range = self.read_slice_as_range(section_length)?;
            *out_section = self.read_byte()?;
        }

        Ok(())
    }
}

#[derive(Copy, Clone)]
pub struct Imports<'a> {
    offsets: &'a [u8],
    symbols: &'a [u8],
}

impl<'a> Imports<'a> {
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn len(&self) -> u32 {
        (self.offsets.len() / 4) as u32
    }

    pub fn get(&self, index: u32) -> Option<ProgramSymbol<'a>> {
        let offset_start = index.checked_mul(4)?;
        let offset_end = offset_start.checked_add(4)?;
        let xs = self.offsets.get(offset_start as usize..offset_end as usize)?;
        let offset = u32::from_le_bytes([xs[0], xs[1], xs[2], xs[3]]) as usize;
        let next_offset = offset_end
            .checked_add(4)
            .and_then(|next_offset_end| self.offsets.get(offset_end as usize..next_offset_end as usize))
            .map_or(self.symbols.len(), |xs| u32::from_le_bytes([xs[0], xs[1], xs[2], xs[3]]) as usize);

        let symbol = self.symbols.get(offset..next_offset)?;
        Some(ProgramSymbol::new(symbol.into()))
    }

    pub fn iter(&self) -> ImportsIter<'a> {
        ImportsIter { imports: *self, index: 0 }
    }
}

impl<'a> IntoIterator for Imports<'a> {
    type Item = Option<ProgramSymbol<'a>>;
    type IntoIter = ImportsIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<'a> IntoIterator for &'a Imports<'a> {
    type Item = Option<ProgramSymbol<'a>>;
    type IntoIter = ImportsIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

pub struct ImportsIter<'a> {
    imports: Imports<'a>,
    index: u32,
}

impl<'a> Iterator for ImportsIter<'a> {
    type Item = Option<ProgramSymbol<'a>>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.imports.len() {
            None
        } else {
            let value = self.imports.get(self.index);
            self.index += 1;
            Some(value)
        }
    }
}

#[derive(Copy, Clone)]
pub struct JumpTable<'a> {
    blob: &'a [u8],
    entry_size: u32,
}

impl<'a> JumpTable<'a> {
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn len(&self) -> u32 {
        if self.entry_size == 0 {
            0
        } else {
            self.blob.len() as u32 / self.entry_size
        }
    }

    pub fn get_by_address(&self, address: u32) -> Option<u32> {
        if address & (VM_CODE_ADDRESS_ALIGNMENT - 1) != 0 || address == 0 {
            return None;
        }

        self.get_by_index((address - VM_CODE_ADDRESS_ALIGNMENT) / VM_CODE_ADDRESS_ALIGNMENT)
    }

    pub fn get_by_index(&self, index: u32) -> Option<u32> {
        if self.entry_size == 0 {
            return None;
        }

        let start = index.checked_mul(self.entry_size)?;
        let end = start.checked_add(self.entry_size)?;
        self.blob.get(start as usize..end as usize).map(|xs| match xs.len() {
            1 => u32::from(xs[0]),
            2 => u32::from(u16::from_le_bytes([xs[0], xs[1]])),
            3 => u32::from_le_bytes([xs[0], xs[1], xs[2], 0]),
            4 => u32::from_le_bytes([xs[0], xs[1], xs[2], xs[3]]),
            _ => unreachable!(),
        })
    }

    pub fn iter(&self) -> JumpTableIter<'a> {
        JumpTableIter {
            jump_table: *self,
            index: 0,
        }
    }
}

impl<'a> IntoIterator for JumpTable<'a> {
    type Item = u32;
    type IntoIter = JumpTableIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<'a> IntoIterator for &'a JumpTable<'a> {
    type Item = u32;
    type IntoIter = JumpTableIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

pub struct JumpTableIter<'a> {
    jump_table: JumpTable<'a>,
    index: u32,
}

impl<'a> Iterator for JumpTableIter<'a> {
    type Item = u32;
    fn next(&mut self) -> Option<Self::Item> {
        let value = self.jump_table.get_by_index(self.index)?;
        self.index += 1;
        Some(value)
    }
}

#[inline(never)]
#[cold]
fn parse_bitmask_slow(bitmask: &[u8], code_offset: &mut usize) -> Option<usize> {
    if bitmask.is_empty() {
        return None;
    }

    let mut offset = *code_offset + 1;
    let mut args_length = 0;
    while let Some(&byte) = bitmask.get(offset >> 3) {
        let shift = offset & 7;
        let mask = byte >> shift;

        if mask == 0 {
            args_length += 8 - shift;
            offset += 8 - shift;
            continue;
        }

        let length = mask.trailing_zeros() as usize;
        if length == 0 {
            break;
        }

        args_length += length;
        offset += length;
    }

    *code_offset = offset;
    Some(args_length)
}

#[cfg_attr(not(debug_assertions), inline(always))]
pub(crate) fn parse_bitmask(bitmask: &[u8], code_offset: &mut usize) -> Option<usize> {
    let mut offset = *code_offset + 1;
    let Some(bitmask) = bitmask.get(offset >> 3..(offset >> 3) + 4) else {
        return parse_bitmask_slow(bitmask, code_offset);
    };

    let shift = offset & 7;
    let mask = u32::from_le_bytes([bitmask[0], bitmask[1], bitmask[2], bitmask[3]]) >> shift;

    if mask == 0 {
        return parse_bitmask_slow(bitmask, code_offset);
    }

    let args_length = mask.trailing_zeros() as usize;
    offset += args_length;
    *code_offset = offset;

    Some(args_length)
}

#[test]
fn test_parse_bitmask() {
    fn p(bitmask: &[u8]) -> (Option<usize>, usize) {
        let mut offset = 0;
        (parse_bitmask(bitmask, &mut offset), offset)
    }

    assert_eq!(p(&[0b00000001, 0, 0, 0]), (Some(31), 32));
    assert_eq!(p(&[0b00000001, 0, 0]), (Some(23), 24));
    assert_eq!(p(&[0b00000001, 0]), (Some(15), 16));
    assert_eq!(p(&[0b00000001]), (Some(7), 8));
    assert_eq!(p(&[0b00000011]), (Some(0), 1));
    assert_eq!(p(&[0b00000011, 0]), (Some(0), 1));
    assert_eq!(p(&[0b00000101]), (Some(1), 2));
    assert_eq!(p(&[0b10000001]), (Some(6), 7));
    assert_eq!(p(&[0b00000001, 1]), (Some(7), 8));
}

#[derive(Clone)]
pub struct Instructions<'a> {
    code: &'a [u8],
    bitmask: &'a [u8],
    offset: usize,
}

#[derive(Copy, Clone, Debug)]
pub struct ParsedInstruction {
    pub kind: Instruction,
    pub offset: u32,
    pub length: u32,
}

impl core::ops::Deref for ParsedInstruction {
    type Target = Instruction;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.kind
    }
}

impl core::fmt::Display for ParsedInstruction {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(fmt, "{:>7}: {}", self.offset, self.kind)
    }
}

impl<'a> Instructions<'a> {
    #[inline]
    pub fn new(code: &'a [u8], bitmask: &'a [u8], offset: u32) -> Self {
        Self {
            code,
            bitmask,
            offset: offset as usize,
        }
    }

    #[inline]
    pub fn offset(&self) -> u32 {
        self.offset as u32
    }

    #[inline]
    pub fn visit<T>(&mut self, visitor: &mut T) -> Option<<T as InstructionVisitor>::ReturnTy>
    where
        T: InstructionVisitor,
    {
        // TODO: Make this directly dispatched?
        Some(self.next()?.visit(visitor))
    }
}

impl<'a> Iterator for Instructions<'a> {
    type Item = ParsedInstruction;
    #[inline(always)]
    fn next(&mut self) -> Option<Self::Item> {
        parse_instruction(self.code, self.bitmask, &mut self.offset)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, Some(self.code.len() - core::cmp::min(self.offset, self.code.len())))
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
            blob: &program.blob[BLOB_MAGIC.len()..],
            position: BLOB_MAGIC.len(),
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
            program.ro_data_size = reader.read_varint()?;
            program.rw_data_size = reader.read_varint()?;
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

        if section == SECTION_IMPORTS {
            let section_length = reader.read_varint()? as usize;
            let section_start = reader.position;
            let import_count = reader.read_varint()?;
            if import_count > VM_MAXIMUM_IMPORT_COUNT {
                return Err(ProgramParseError(ProgramParseErrorKind::Other("too many imports")));
            }

            let Some(import_offsets_size) = import_count.checked_mul(4) else {
                return Err(ProgramParseError(ProgramParseErrorKind::Other("the imports section is invalid")));
            };

            program.import_offsets = reader.read_slice_as_range(import_offsets_size as usize)?;
            let Some(import_symbols_size) = section_length.checked_sub(reader.position - section_start) else {
                return Err(ProgramParseError(ProgramParseErrorKind::Other("the imports section is invalid")));
            };

            program.import_symbols = reader.read_slice_as_range(import_symbols_size)?;
            section = reader.read_byte()?;
        }

        reader.read_section_range_into(&mut section, &mut program.exports, SECTION_EXPORTS)?;

        if program.ro_data.len() > program.ro_data_size as usize {
            return Err(ProgramParseError(ProgramParseErrorKind::Other(
                "size of the read-only data payload exceeds the declared size of the section",
            )));
        }

        if program.rw_data.len() > program.rw_data_size as usize {
            return Err(ProgramParseError(ProgramParseErrorKind::Other(
                "size of the read-write data payload exceeds the declared size of the section",
            )));
        }

        if section == SECTION_CODE {
            let section_length = reader.read_varint()?;
            let initial_position = reader.position;
            let jump_table_entry_count = reader.read_varint()?;
            if jump_table_entry_count > VM_MAXIMUM_JUMP_TABLE_ENTRIES {
                return Err(ProgramParseError(ProgramParseErrorKind::Other(
                    "the jump table section is too long",
                )));
            }

            let jump_table_entry_size = reader.read_byte()?;
            let code_length = reader.read_varint()?;
            if code_length > VM_MAXIMUM_CODE_SIZE {
                return Err(ProgramParseError(ProgramParseErrorKind::Other("the code section is too long")));
            }

            let header_size = (reader.position - initial_position) as u32;
            if section_length < header_size {
                return Err(ProgramParseError(ProgramParseErrorKind::Other("the code section is too short")));
            }

            if !matches!(jump_table_entry_size, 0..=4) {
                return Err(ProgramParseError(ProgramParseErrorKind::Other("invalid jump table entry size")));
            }

            let Some(jump_table_length) = jump_table_entry_count.checked_mul(u32::from(jump_table_entry_size)) else {
                return Err(ProgramParseError(ProgramParseErrorKind::Other("the jump table is too long")));
            };

            program.jump_table = reader.read_slice_as_range(jump_table_length as usize)?;
            program.jump_table_entry_size = jump_table_entry_size;
            program.code = reader.read_slice_as_range(code_length as usize)?;

            let bitmask_length = section_length - (reader.position - initial_position) as u32;
            program.bitmask = reader.read_slice_as_range(bitmask_length as usize)?;

            section = reader.read_byte()?;
        }

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
            reader.skip(section_length as usize)?;
            section = reader.read_byte()?;
        }

        if section != SECTION_END_OF_FILE {
            return Err(ProgramParseError(ProgramParseErrorKind::UnexpectedSection {
                offset: reader.position - 1,
                section,
            }));
        }

        let mut expected_bitmask_length = program.code.len() / 8;
        if program.code.len() % 8 != 0 {
            expected_bitmask_length += 1;
        }

        if program.bitmask.len() != expected_bitmask_length {
            return Err(ProgramParseError(ProgramParseErrorKind::Other(
                "the bitmask length doesn't match the code length",
            )));
        }

        if !program.bitmask.is_empty() && program.blob[program.bitmask.clone()][0] & 1 != 1 {
            return Err(ProgramParseError(ProgramParseErrorKind::Other(
                "the bitmask doesn't start with a 1",
            )));
        }

        Ok(program)
    }

    /// Returns the contents of the read-only data section.
    ///
    /// This only covers the initial non-zero portion of the section; use `ro_data_size` to get the full size.
    pub fn ro_data(&self) -> &[u8] {
        &self.blob[self.ro_data.clone()]
    }

    /// Returns the size of the read-only data section.
    ///
    /// This can be larger than the length of `ro_data`, in which case the rest of the space is assumed to be filled with zeros.
    pub fn ro_data_size(&self) -> u32 {
        self.ro_data_size
    }

    /// Returns the contents of the read-write data section.
    ///
    /// This only covers the initial non-zero portion of the section; use `rw_data_size` to get the full size.
    pub fn rw_data(&self) -> &[u8] {
        &self.blob[self.rw_data.clone()]
    }

    /// Returns the size of the read-write data section.
    ///
    /// This can be larger than the length of `rw_data`, in which case the rest of the space is assumed to be filled with zeros.
    pub fn rw_data_size(&self) -> u32 {
        self.rw_data_size
    }

    /// Returns the initial size of the stack.
    pub fn stack_size(&self) -> u32 {
        self.stack_size
    }

    /// Returns the program code in its raw form.
    pub fn code(&self) -> &[u8] {
        &self.blob[self.code.clone()]
    }

    /// Returns the code bitmask in its raw form.
    pub fn bitmask(&self) -> &[u8] {
        &self.blob[self.bitmask.clone()]
    }

    fn get_section_reader(&self, range: Range<usize>) -> Reader {
        Reader {
            blob: &self.blob[range.start..range.end],
            position: range.start,
        }
    }

    pub fn imports(&self) -> Imports {
        Imports {
            offsets: &self.blob[self.import_offsets.clone()],
            symbols: &self.blob[self.import_symbols.clone()],
        }
    }

    /// Returns an iterator over program exports.
    pub fn exports(&'_ self) -> impl Iterator<Item = ProgramExport> + Clone + '_ {
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

        impl<'a> Iterator for ExportIterator<'a> {
            type Item = ProgramExport<'a>;
            fn next(&mut self) -> Option<Self::Item> {
                let remaining = match core::mem::replace(&mut self.state, State::Finished) {
                    State::Uninitialized => self.reader.read_varint().ok()?,
                    State::Pending(remaining) => remaining,
                    State::Finished => return None,
                };

                if remaining == 0 {
                    return None;
                }

                let target_code_offset = self.reader.read_varint().ok()?;
                let symbol = self.reader.read_bytes_with_length().ok()?;
                let export = ProgramExport {
                    target_code_offset,
                    symbol: symbol.into(),
                };

                self.state = State::Pending(remaining - 1);
                Some(export)
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

    #[inline]
    pub fn instructions(&'a self) -> Instructions<'a> {
        Instructions {
            code: self.code(),
            bitmask: self.bitmask(),
            offset: 0,
        }
    }

    #[inline]
    pub fn instructions_at(&'a self, offset: u32) -> Option<Instructions<'a>> {
        let bitmask = self.bitmask();
        if (bitmask.get(offset as usize >> 3)? >> (offset as usize & 7)) & 1 == 0 {
            None
        } else {
            Some(Instructions {
                code: self.code(),
                bitmask,
                offset: offset as usize,
            })
        }
    }

    /// Returns a jump table.
    pub fn jump_table(&self) -> JumpTable {
        JumpTable {
            blob: if self.jump_table_entry_size == 0 {
                &[]
            } else {
                &self.blob[self.jump_table.clone()]
            },
            entry_size: u32::from(self.jump_table_entry_size),
        }
    }

    /// Returns the debug string for the given relative offset.
    pub fn get_debug_string(&self, offset: u32) -> Result<&str, ProgramParseError> {
        let mut reader = self.get_section_reader(self.debug_strings.clone());
        reader.skip(offset as usize)?;
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
        reader.skip(info_offset as usize)?;

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

            ro_data_size: self.ro_data_size,
            rw_data_size: self.rw_data_size,
            stack_size: self.stack_size,

            ro_data: self.ro_data,
            rw_data: self.rw_data,
            exports: self.exports,
            import_symbols: self.import_symbols,
            import_offsets: self.import_offsets,
            code: self.code,
            jump_table: self.jump_table,
            jump_table_entry_size: self.jump_table_entry_size,
            bitmask: self.bitmask,

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
        match *self {
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
        const INSTRUCTION_LIMIT_PER_REGION: usize = 512;

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
        Err((base + usize::from(ord == core::cmp::Ordering::Less)) * chunk_size)
    }
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
proptest::proptest! {
    #![proptest_config(proptest::prelude::ProptestConfig::with_cases(20000))]
    #[allow(clippy::ignored_unit_patterns)]
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
