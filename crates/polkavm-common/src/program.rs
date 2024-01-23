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

    /// List of all argument registers.
    pub const ARG_REGS: [Reg; 6] = [Reg::A0, Reg::A1, Reg::A2, Reg::A3, Reg::A4, Reg::A5];
}

impl core::fmt::Display for Reg {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
        fmt.write_str(self.name())
    }
}

#[allow(clippy::partial_pub_fields)]
#[doc(hidden)]
pub struct VisitorHelper<'a, T> {
    pub visitor: T,
    reader: Reader<'a>,
}

impl<'a, T> VisitorHelper<'a, T> {
    #[inline]
    pub fn run<E>(
        blob: &'a ProgramBlob<'a>,
        visitor: T,
        decode_table: &[fn(&mut Self) -> <T as InstructionVisitor>::ReturnTy; 256],
    ) -> (T, <T as InstructionVisitor>::ReturnTy)
    where
        T: ParsingVisitor<E>,
    {
        let mut state = VisitorHelper {
            visitor,
            reader: blob.get_section_reader(blob.code.clone()),
        };

        let mut result = Ok(());
        loop {
            let Ok(opcode) = state.reader.read_byte() else { break };
            result = state.visitor.on_pre_visit(state.reader.position - 1 - blob.code.start, opcode);
            if result.is_err() {
                break;
            }

            result = decode_table[opcode as usize](&mut state);
            if result.is_err() {
                break;
            }

            result = state.visitor.on_post_visit();
            if result.is_err() {
                break;
            }
        }

        (state.visitor, result)
    }

    #[cold]
    pub fn unknown_opcode<U, E>(&mut self) -> <T as InstructionVisitor>::ReturnTy
    where
        T: InstructionVisitor<ReturnTy = Result<U, E>>,
        E: From<ProgramParseError>,
    {
        let error = ProgramParseError::unexpected_instruction(self.reader.position - 1);
        Err(error.into())
    }

    #[inline(always)]
    pub fn read_args_imm(&mut self) -> Result<u32, ProgramParseError> {
        self.reader.read_varint()
    }

    #[inline(always)]
    pub fn read_args_imm2(&mut self) -> Result<(u32, u32), ProgramParseError> {
        let imm1 = self.reader.read_varint()?;
        let imm2 = self.reader.read_varint()?;
        Ok((imm1, imm2))
    }

    #[inline(always)]
    pub fn read_args_reg_imm(&mut self) -> Result<(Reg, u32), ProgramParseError> {
        let reg = self.reader.read_reg()?;
        let imm = self.reader.read_varint()?;
        Ok((reg, imm))
    }

    #[inline(always)]
    pub fn read_args_reg_imm2(&mut self) -> Result<(Reg, u32, u32), ProgramParseError> {
        let reg = self.reader.read_reg()?;
        let imm1 = self.reader.read_varint()?;
        let imm2 = self.reader.read_varint()?;
        Ok((reg, imm1, imm2))
    }

    #[inline(always)]
    pub fn read_args_regs2_imm(&mut self) -> Result<(Reg, Reg, u32), ProgramParseError> {
        let (reg1, reg2) = self.reader.read_regs2()?;
        let imm = self.reader.read_varint()?;
        Ok((reg1, reg2, imm))
    }

    #[inline(always)]
    pub fn read_args_regs3(&mut self) -> Result<(Reg, Reg, Reg), ProgramParseError> {
        self.reader.read_regs3()
    }

    #[inline(always)]
    pub fn read_args_regs2(&mut self) -> Result<(Reg, Reg), ProgramParseError> {
        self.reader.read_regs2()
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
        [$($name_reg_imm_imm:ident = $value_reg_imm_imm:expr,)+]
        [$($name_reg_reg_imm:ident = $value_reg_reg_imm:expr,)+]
        [$($name_reg_reg_reg:ident = $value_reg_reg_reg:expr,)+]
        [$($name_imm:ident = $value_imm:expr,)+]
        [$($name_imm_imm:ident = $value_imm_imm:expr,)+]
        [$($name_reg_reg:ident = $value_reg_reg:expr,)+]
    ) => {
        pub trait ParsingVisitor<E>: InstructionVisitor<ReturnTy = Result<(), E>> {
            fn on_pre_visit(&mut self, _offset: usize, _opcode: u8) -> Self::ReturnTy {
                Ok(())
            }

            fn on_post_visit(&mut self) -> Self::ReturnTy {
                Ok(())
            }
        }

        pub trait InstructionVisitor {
            type ReturnTy;

            $(fn $name_argless(&mut self) -> Self::ReturnTy;)+
            $(fn $name_reg_imm(&mut self, reg: Reg, imm: u32) -> Self::ReturnTy;)+
            $(fn $name_reg_imm_imm(&mut self, reg: Reg, imm1: u32, imm2: u32) -> Self::ReturnTy;)+
            $(fn $name_reg_reg_imm(&mut self, reg1: Reg, reg2: Reg, imm: u32) -> Self::ReturnTy;)+
            $(fn $name_reg_reg_reg(&mut self, reg1: Reg, reg2: Reg, reg3: Reg) -> Self::ReturnTy;)+
            $(fn $name_imm(&mut self, imm: u32) -> Self::ReturnTy;)+
            $(fn $name_imm_imm(&mut self, imm1: u32, imm2: u32) -> Self::ReturnTy;)+
            $(fn $name_reg_reg(&mut self, reg1: Reg, reg2: Reg) -> Self::ReturnTy;)+

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
                    $(fn $name_reg_imm_imm(&mut self, reg: Reg, imm1: u32, imm2: u32) -> Self::ReturnTy {
                        self.$method(polkavm_common::program::Instruction::$name_reg_imm_imm(reg, imm1, imm2));
                    })+
                    $(fn $name_reg_reg_imm(&mut self, reg1: Reg, reg2: Reg, imm: u32) -> Self::ReturnTy {
                        self.$method(polkavm_common::program::Instruction::$name_reg_reg_imm(reg1, reg2, imm));
                    })+
                    $(fn $name_reg_reg_reg(&mut self, reg1: Reg, reg2: Reg, reg3: Reg) -> Self::ReturnTy {
                        self.$method(polkavm_common::program::Instruction::$name_reg_reg_reg(reg1, reg2, reg3));
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
                }
            }
        }

        pub use implement_instruction_visitor;

        #[derive(Copy, Clone, PartialEq, Eq, Debug)]
        #[allow(non_camel_case_types)]
        pub enum Instruction {
            $($name_argless,)+
            $($name_reg_imm(Reg, u32),)+
            $($name_reg_imm_imm(Reg, u32, u32),)+
            $($name_reg_reg_imm(Reg, Reg, u32),)+
            $($name_reg_reg_reg(Reg, Reg, Reg),)+
            $($name_imm(u32),)+
            $($name_imm_imm(u32, u32),)+
            $($name_reg_reg(Reg, Reg),)+
        }

        impl Instruction {
            pub fn visit<T>(self, visitor: &mut T) -> T::ReturnTy where T: InstructionVisitor {
                match self {
                    $(Self::$name_argless => visitor.$name_argless(),)+
                    $(Self::$name_reg_imm(reg, imm) => visitor.$name_reg_imm(reg, imm),)+
                    $(Self::$name_reg_imm_imm(reg, imm1, imm2) => visitor.$name_reg_imm_imm(reg, imm1, imm2),)+
                    $(Self::$name_reg_reg_imm(reg1, reg2, imm) => visitor.$name_reg_reg_imm(reg1, reg2, imm),)+
                    $(Self::$name_reg_reg_reg(reg1, reg2, reg3) => visitor.$name_reg_reg_reg(reg1, reg2, reg3),)+
                    $(Self::$name_imm(imm) => visitor.$name_imm(imm),)+
                    $(Self::$name_imm_imm(imm1, imm2) => visitor.$name_imm_imm(imm1, imm2),)+
                    $(Self::$name_reg_reg(reg1, reg2) => visitor.$name_reg_reg(reg1, reg2),)+
                }
            }

            pub fn serialize_into(self, buffer: &mut [u8]) -> usize {
                match self {
                    $(Self::$name_argless => Self::serialize_argless(buffer, Opcode::$name_argless),)+
                    $(Self::$name_reg_imm(reg, imm) => Self::serialize_reg_imm(buffer, Opcode::$name_reg_imm, reg, imm),)+
                    $(Self::$name_reg_imm_imm(reg, imm1, imm2) => Self::serialize_reg_imm_imm(buffer, Opcode::$name_reg_imm_imm, reg, imm1, imm2),)+
                    $(Self::$name_reg_reg_imm(reg1, reg2, imm) => Self::serialize_reg_reg_imm(buffer, Opcode::$name_reg_reg_imm, reg1, reg2, imm),)+
                    $(Self::$name_reg_reg_reg(reg1, reg2, reg3) => Self::serialize_reg_reg_reg(buffer, Opcode::$name_reg_reg_reg, reg1, reg2, reg3),)+
                    $(Self::$name_imm(imm) => Self::serialize_imm(buffer, Opcode::$name_imm, imm),)+
                    $(Self::$name_imm_imm(imm1, imm2) => Self::serialize_imm_imm(buffer, Opcode::$name_imm_imm, imm1, imm2),)+
                    $(Self::$name_reg_reg(reg1, reg2) => Self::serialize_reg_reg(buffer, Opcode::$name_reg_reg, reg1, reg2),)+

                }
            }

            pub fn opcode(self) -> Opcode {
                match self {
                    $(Self::$name_argless => Opcode::$name_argless,)+
                    $(Self::$name_reg_imm(..) => Opcode::$name_reg_imm,)+
                    $(Self::$name_reg_imm_imm(..) => Opcode::$name_reg_imm_imm,)+
                    $(Self::$name_reg_reg_imm(..) => Opcode::$name_reg_reg_imm,)+
                    $(Self::$name_reg_reg_reg(..) => Opcode::$name_reg_reg_reg,)+
                    $(Self::$name_imm(..) => Opcode::$name_imm,)+
                    $(Self::$name_imm_imm(..) => Opcode::$name_imm_imm,)+
                    $(Self::$name_reg_reg(..) => Opcode::$name_reg_reg,)+
                }
            }
        }

        impl core::fmt::Display for Instruction {
            fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
                self.visit(fmt)
            }
        }

        fn parse_instruction_impl(opcode: u8, reader: &mut Reader) -> Result<Instruction, ProgramParseError> {
            Ok(match opcode {
                $($value_argless => Instruction::$name_argless,)+
                $($value_reg_imm => {
                    let reg = reader.read_reg()?;
                    let imm = reader.read_varint()?;
                    Instruction::$name_reg_imm(reg, imm)
                },)+
                $($value_reg_imm_imm => {
                    let reg = reader.read_reg()?;
                    let imm1 = reader.read_varint()?;
                    let imm2 = reader.read_varint()?;
                    Instruction::$name_reg_imm_imm(reg, imm1, imm2)
                },)+
                $($value_reg_reg_imm => {
                    let (reg1, reg2) = reader.read_regs2()?;
                    let imm = reader.read_varint()?;
                    Instruction::$name_reg_reg_imm(reg1, reg2, imm)
                },)+
                $($value_reg_reg_reg => {
                    let (reg1, reg2) = reader.read_regs2()?;
                    let reg3 = reader.read_reg()?;
                    Instruction::$name_reg_reg_reg(reg1, reg2, reg3)
                },)+
                $($value_imm => {
                    Instruction::$name_imm(reader.read_varint()?)
                },)+
                $($value_imm_imm => {
                    let imm1 = reader.read_varint()?;
                    let imm2 = reader.read_varint()?;
                    Instruction::$name_imm_imm(imm1, imm2)
                },)+
                $($value_reg_reg => {
                    let (reg1, reg2) = reader.read_regs2()?;
                    Instruction::$name_reg_reg(reg1, reg2)
                },)+
                _ => return Err(ProgramParseError::unexpected_instruction(reader.position - 1))
            })
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

            pub fn ret() -> Instruction {
                jump_indirect(Reg::RA, 0)
            }
        }

        #[macro_export]
        macro_rules! prepare_visitor {
            ($table_name:ident, $visitor_ty:ident<$d($visitor_ty_params:tt),*>) => {{
                use polkavm_common::program::{
                    InstructionVisitor,
                    VisitorHelper,
                };

                type ReturnTy<$d($visitor_ty_params),*> = <$visitor_ty<$d($visitor_ty_params),*> as InstructionVisitor>::ReturnTy;
                type VisitFn<'_code, $d($visitor_ty_params),*> = fn(state: &mut VisitorHelper<'_code, $visitor_ty<$d($visitor_ty_params),*>>) -> ReturnTy<$d($visitor_ty_params),*>;

                static $table_name: [VisitFn; 256] = {
                    let mut table = [VisitorHelper::unknown_opcode as VisitFn; 256];
                    $({
                        // Putting all of the handlers in a single link section can make a big difference
                        // when it comes to performance, even up to 10% in some cases. This will force the
                        // compiler and the linker to put all of this code near each other, minimizing
                        // instruction cache misses.
                        #[cfg_attr(target_os = "linux", link_section = concat!(".text.", stringify!($table_name)))]
                        fn $name_argless<'_code, $d($visitor_ty_params),*>(state: &mut VisitorHelper<'_code, $visitor_ty<$d($visitor_ty_params),*>>) -> ReturnTy<$d($visitor_ty_params),*>{
                            state.visitor.$name_argless()
                        }

                        table[$value_argless] = $name_argless;
                    })*

                    $({
                        #[cfg_attr(target_os = "linux", link_section = concat!(".text.", stringify!($table_name)))]
                        fn $name_reg_imm<'_code, $d($visitor_ty_params),*>(state: &mut VisitorHelper<'_code, $visitor_ty<$d($visitor_ty_params),*>>) -> ReturnTy<$d($visitor_ty_params),*>{
                            let (reg, imm) = state.read_args_reg_imm()?;
                            state.visitor.$name_reg_imm(reg, imm)
                        }

                        table[$value_reg_imm] = $name_reg_imm;
                    })*

                    $({
                        #[cfg_attr(target_os = "linux", link_section = concat!(".text.", stringify!($table_name)))]
                        fn $name_reg_imm_imm<'_code, $d($visitor_ty_params),*>(state: &mut VisitorHelper<'_code, $visitor_ty<$d($visitor_ty_params),*>>) -> ReturnTy<$d($visitor_ty_params),*>{
                            let (reg, imm1, imm2) = state.read_args_reg_imm2()?;
                            state.visitor.$name_reg_imm_imm(reg, imm1, imm2)
                        }

                        table[$value_reg_imm_imm] = $name_reg_imm_imm;
                    })*

                    $({
                        #[cfg_attr(target_os = "linux", link_section = concat!(".text.", stringify!($table_name)))]
                        fn $name_reg_reg_imm<'_code, $d($visitor_ty_params),*>(state: &mut VisitorHelper<'_code, $visitor_ty<$d($visitor_ty_params),*>>) -> ReturnTy<$d($visitor_ty_params),*>{
                            let (reg1, reg2, imm) = state.read_args_regs2_imm()?;
                            state.visitor.$name_reg_reg_imm(reg1, reg2, imm)
                        }

                        table[$value_reg_reg_imm] = $name_reg_reg_imm;
                    })*

                    $({
                        #[cfg_attr(target_os = "linux", link_section = concat!(".text.", stringify!($table_name)))]
                        fn $name_reg_reg_reg<'_code, $d($visitor_ty_params),*>(state: &mut VisitorHelper<'_code, $visitor_ty<$d($visitor_ty_params),*>>) -> ReturnTy<$d($visitor_ty_params),*>{
                            let (reg1, reg2, reg3) = state.read_args_regs3()?;
                            state.visitor.$name_reg_reg_reg(reg1, reg2, reg3)
                        }

                        table[$value_reg_reg_reg] = $name_reg_reg_reg;
                    })*

                    $({
                        #[cfg_attr(target_os = "linux", link_section = concat!(".text.", stringify!($table_name)))]
                        fn $name_imm<'_code, $d($visitor_ty_params),*>(state: &mut VisitorHelper<'_code, $visitor_ty<$d($visitor_ty_params),*>>) -> ReturnTy<$d($visitor_ty_params),*>{
                            let imm = state.read_args_imm()?;
                            state.visitor.$name_imm(imm)
                        }

                        table[$value_imm] = $name_imm;
                    })*

                    $({
                        #[cfg_attr(target_os = "linux", link_section = concat!(".text.", stringify!($table_name)))]
                        fn $name_imm_imm<'_code, $d($visitor_ty_params),*>(state: &mut VisitorHelper<'_code, $visitor_ty<$d($visitor_ty_params),*>>) -> ReturnTy<$d($visitor_ty_params),*>{
                            let (imm1, imm2) = state.read_args_imm2()?;
                            state.visitor.$name_imm_imm(imm1, imm2)
                        }

                        table[$value_imm_imm] = $name_imm_imm;
                    })*

                    $({
                        #[cfg_attr(target_os = "linux", link_section = concat!(".text.", stringify!($table_name)))]
                        fn $name_reg_reg<'_code, $d($visitor_ty_params),*>(state: &mut VisitorHelper<'_code, $visitor_ty<$d($visitor_ty_params),*>>) -> ReturnTy<$d($visitor_ty_params),*>{
                            let (reg1, reg2) = state.read_args_regs2()?;
                            state.visitor.$name_reg_reg(reg1, reg2)
                        }

                        table[$value_reg_reg] = $name_reg_reg;
                    })*

                    table
                };

                #[inline]
                fn run<$d($visitor_ty_params),*>(
                    blob: &ProgramBlob,
                    visitor: $visitor_ty<$d($visitor_ty_params),*>,
                )
                    -> ($visitor_ty<$d($visitor_ty_params),*>, <$visitor_ty<$d($visitor_ty_params),*> as InstructionVisitor>::ReturnTy)
                {
                    let decode_table: &[VisitFn; 256] = &$table_name;
                    // SAFETY: Here we transmute the lifetimes which were unnecessarily extended to be 'static due to the table here being a `static`.
                    let decode_table: &[VisitFn; 256] = unsafe { core::mem::transmute(decode_table) };

                    VisitorHelper::run(blob, visitor, decode_table)
                }

                run
            }};
        }

        pub use prepare_visitor;

        define_opcodes!(
            @impl_shared
            $($name_argless = $value_argless,)+
            $($name_reg_imm = $value_reg_imm,)+
            $($name_reg_imm_imm = $value_reg_imm_imm,)+
            $($name_reg_reg_imm = $value_reg_reg_imm,)+
            $($name_reg_reg_reg = $value_reg_reg_reg,)+
            $($name_imm = $value_imm,)+
            $($name_imm_imm = $value_imm_imm,)+
            $($name_reg_reg = $value_reg_reg,)+
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
        call                                     = 6,
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

    // Instructions with args: reg, imm, imm
    [
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
        call_indirect                            = 42,
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

    // Instructions with args: imm
    [
        jump                                     = 5,
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
                | Self::call
                | Self::call_indirect
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
    pub fn deserialize(input: &[u8]) -> Option<(usize, Self)> {
        let mut reader = Reader { blob: input, position: 0 };

        let opcode = reader.read_byte().ok()?;
        let instruction = parse_instruction_impl(opcode, &mut reader).ok()?;
        Some((reader.position, instruction))
    }

    fn serialize_argless(buffer: &mut [u8], opcode: Opcode) -> usize {
        buffer[0] = opcode as u8;
        1
    }

    fn serialize_reg_imm_imm(buffer: &mut [u8], opcode: Opcode, reg: Reg, imm1: u32, imm2: u32) -> usize {
        buffer[0] = opcode as u8;
        buffer[1] = reg as u8;
        let mut position = 2;
        position += write_varint(imm1, &mut buffer[position..]);
        position += write_varint(imm2, &mut buffer[position..]);
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
        write_varint(imm, &mut buffer[2..]) + 2
    }

    fn serialize_reg_imm(buffer: &mut [u8], opcode: Opcode, reg: Reg, imm: u32) -> usize {
        buffer[0] = opcode as u8;
        buffer[1] = reg as u8;
        write_varint(imm, &mut buffer[2..]) + 2
    }

    fn serialize_imm(buffer: &mut [u8], opcode: Opcode, imm: u32) -> usize {
        buffer[0] = opcode as u8;
        write_varint(imm, &mut buffer[1..]) + 1
    }

    fn serialize_imm_imm(buffer: &mut [u8], opcode: Opcode, imm1: u32, imm2: u32) -> usize {
        buffer[0] = opcode as u8;
        let mut position = 1;
        position += write_varint(imm1, &mut buffer[position..]);
        position += write_varint(imm2, &mut buffer[position..]);
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
        write!(self, "@:")
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
        write!(self, "{d} = ({c} == 0) ? {s} : 0")
    }

    fn cmov_if_not_zero(&mut self, d: Reg, s: Reg, c: Reg) -> Self::ReturnTy {
        write!(self, "{d} = ({c} != 0) ? {s} : 0")
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
        write!(self, "if {} <u {}: jump @{:x}", s1, s2, imm)
    }

    fn branch_less_signed(&mut self, s1: Reg, s2: Reg, imm: u32) -> Self::ReturnTy {
        write!(self, "if {} <s {}: jump @{:x}", s1, s2, imm)
    }

    fn branch_less_unsigned_imm(&mut self, s1: Reg, s2: u32, imm: u32) -> Self::ReturnTy {
        write!(self, "if {} <u {}: jump @{:x}", s1, s2, imm)
    }

    fn branch_less_signed_imm(&mut self, s1: Reg, s2: u32, imm: u32) -> Self::ReturnTy {
        write!(self, "if {} <s {}: jump @{:x}", s1, s2, imm)
    }

    fn branch_greater_or_equal_unsigned(&mut self, s1: Reg, s2: Reg, imm: u32) -> Self::ReturnTy {
        write!(self, "if {} >=u {}: jump @{:x}", s1, s2, imm)
    }

    fn branch_greater_or_equal_signed(&mut self, s1: Reg, s2: Reg, imm: u32) -> Self::ReturnTy {
        write!(self, "if {} >=s {}: jump @{:x}", s1, s2, imm)
    }

    fn branch_greater_or_equal_unsigned_imm(&mut self, s1: Reg, s2: u32, imm: u32) -> Self::ReturnTy {
        write!(self, "if {} >=u {}: jump @{:x}", s1, s2, imm)
    }

    fn branch_greater_or_equal_signed_imm(&mut self, s1: Reg, s2: u32, imm: u32) -> Self::ReturnTy {
        write!(self, "if {} >=s {}: jump @{:x}", s1, s2, imm)
    }

    fn branch_eq(&mut self, s1: Reg, s2: Reg, imm: u32) -> Self::ReturnTy {
        write!(self, "if {} == {}: jump @{:x}", s1, s2, imm)
    }

    fn branch_not_eq(&mut self, s1: Reg, s2: Reg, imm: u32) -> Self::ReturnTy {
        write!(self, "if {} != {}: jump @{:x}", s1, s2, imm)
    }

    fn branch_eq_imm(&mut self, s1: Reg, s2: u32, imm: u32) -> Self::ReturnTy {
        write!(self, "if {} == {}: jump @{:x}", s1, s2, imm)
    }

    fn branch_not_eq_imm(&mut self, s1: Reg, s2: u32, imm: u32) -> Self::ReturnTy {
        write!(self, "if {} != {}: jump @{:x}", s1, s2, imm)
    }

    fn branch_less_or_equal_unsigned_imm(&mut self, s1: Reg, s2: u32, imm: u32) -> Self::ReturnTy {
        write!(self, "if {} <=u {}: jump @{:x}", s1, s2, imm)
    }

    fn branch_less_or_equal_signed_imm(&mut self, s1: Reg, s2: u32, imm: u32) -> Self::ReturnTy {
        write!(self, "if {} <=s {}: jump @{:x}", s1, s2, imm)
    }

    fn branch_greater_unsigned_imm(&mut self, s1: Reg, s2: u32, imm: u32) -> Self::ReturnTy {
        write!(self, "if {} >u {}: jump @{:x}", s1, s2, imm)
    }

    fn branch_greater_signed_imm(&mut self, s1: Reg, s2: u32, imm: u32) -> Self::ReturnTy {
        write!(self, "if {} >s {}: jump @{:x}", s1, s2, imm)
    }

    fn jump(&mut self, target: u32) -> Self::ReturnTy {
        write!(self, "jump @{:x}", target)
    }

    fn call(&mut self, ra: Reg, target: u32) -> Self::ReturnTy {
        match ra {
            Reg::RA => write!(self, "call @{:x}", target),
            _ => write!(self, "call @{:x}, {}", target, ra),
        }
    }

    fn jump_indirect(&mut self, base: Reg, offset: u32) -> Self::ReturnTy {
        use Reg::*;
        match (base, offset) {
            (RA, 0) => write!(self, "ret"),
            (_, 0) => write!(self, "jump [{}]", base),
            (_, _) => write!(self, "jump [{} + {}]", base, offset),
        }
    }

    fn call_indirect(&mut self, ra: Reg, base: Reg, offset: u32) -> Self::ReturnTy {
        use Reg::*;
        match (ra, base, offset) {
            (RA, _, 0) => write!(self, "call [{}]", base),
            (RA, _, _) => write!(self, "call [{} + {}]", base, offset),
            (_, _, 0) => write!(self, "call [{}], {}", base, ra),
            (_, _, _) => write!(self, "call [{} + {}], {}", base, offset, ra),
        }
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
    FailedToReadInstructionArguments {
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

impl ProgramParseError {
    #[cold]
    #[inline]
    fn unexpected_instruction(offset: usize) -> ProgramParseError {
        ProgramParseError(ProgramParseErrorKind::UnexpectedInstruction { offset })
    }

    #[cold]
    #[inline]
    fn failed_to_read_instruction_arguments(offset: usize) -> ProgramParseError {
        ProgramParseError(ProgramParseErrorKind::FailedToReadInstructionArguments { offset })
    }

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
            ProgramParseErrorKind::FailedToReadInstructionArguments { offset } => {
                write!(
                    fmt,
                    "failed to parse program blob: failed to parse instruction arguments at offset 0x{:x}",
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
    jump_table: Range<usize>,

    debug_strings: Range<usize>,
    debug_line_program_ranges: Range<usize>,
    debug_line_programs: Range<usize>,

    instruction_count: u32,
    basic_block_count: u32,
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

    fn finish(&mut self) {
        self.position += self.blob.len();
        self.blob = b"";
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

    #[inline(always)]
    fn read_regs3(&mut self) -> Result<(Reg, Reg, Reg), ProgramParseError> {
        let data = self.read_slice(2)?;
        let reg1 = data[0] & 0b1111;
        let reg2 = data[0] >> 4;
        let reg3 = data[1];
        if let Some(reg1) = Reg::from_u8(reg1) {
            if let Some(reg2) = Reg::from_u8(reg2) {
                if let Some(reg3) = Reg::from_u8(reg3) {
                    return Ok((reg1, reg2, reg3));
                }
            }
        }

        Err(ProgramParseError::failed_to_read_instruction_arguments(self.position - 2))
    }

    #[inline(always)]
    fn read_reg(&mut self) -> Result<Reg, ProgramParseError> {
        let reg = self.read_byte()?;
        if let Some(reg) = Reg::from_u8(reg) {
            return Ok(reg);
        }

        Err(ProgramParseError::failed_to_read_instruction_arguments(self.position - 1))
    }

    #[inline(always)]
    fn read_regs2(&mut self) -> Result<(Reg, Reg), ProgramParseError> {
        let regs = self.read_byte()?;
        let reg1 = regs & 0b1111;
        let reg2 = regs >> 4;
        if let Some(reg1) = Reg::from_u8(reg1) {
            if let Some(reg2) = Reg::from_u8(reg2) {
                return Ok((reg1, reg2));
            }
        }

        Err(ProgramParseError::failed_to_read_instruction_arguments(self.position - 1))
    }

    fn read_string_with_length(&mut self) -> Result<&'a str, ProgramParseError> {
        let offset = self.position;
        let length = self.read_varint()? as usize;
        let slice = self.read_slice(length)?;
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

    fn is_eof(&self) -> bool {
        self.blob.is_empty()
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
        reader.read_section_range_into(&mut section, &mut program.jump_table, SECTION_JUMP_TABLE)?;

        if section == SECTION_CODE {
            let section_length = reader.read_varint()?;
            let initial_position = reader.position;
            let instruction_count = reader.read_varint()?;
            let basic_block_count = reader.read_varint()?;
            let header_size = (reader.position - initial_position) as u32;
            if section_length < header_size {
                return Err(ProgramParseError(ProgramParseErrorKind::Other("the code section is too short")));
            }

            let body_length = section_length - header_size;
            if instruction_count > body_length {
                return Err(ProgramParseError(ProgramParseErrorKind::Other("invalid instruction count")));
            }

            if basic_block_count > body_length {
                return Err(ProgramParseError(ProgramParseErrorKind::Other("invalid basic block count")));
            }

            program.instruction_count = instruction_count;
            program.basic_block_count = basic_block_count;
            program.code = reader.read_slice_as_range(body_length as usize)?;
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

        if section == SECTION_END_OF_FILE {
            return Ok(program);
        }

        Err(ProgramParseError(ProgramParseErrorKind::UnexpectedSection {
            offset: reader.position - 1,
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

    /// Returns the number of instructions the code section should contain.
    ///
    /// NOTE: It is safe to preallocate memory based on this value as we make sure
    /// that it is no larger than the the physical size of the code section, however
    /// we do not verify that it is actually true, so it should *not* be blindly trusted!
    pub fn instruction_count(&self) -> u32 {
        self.instruction_count
    }

    /// Returns the number of basic blocks the code section should contain.
    ///
    /// NOTE: It is safe to preallocate memory based on this value as we make sure
    /// that it is no larger than the the physical size of the code section, however
    /// we do not verify that it is actually true, so it should *not* be blindly trusted!
    pub fn basic_block_count(&self) -> u32 {
        self.basic_block_count
    }

    fn get_section_reader(&self, range: Range<usize>) -> Reader {
        Reader {
            blob: &self.blob[range.start..range.end],
            position: range.start,
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
    pub fn instructions(&'_ self) -> impl Iterator<Item = Result<Instruction, ProgramParseError>> + Clone + '_ {
        #[derive(Clone)]
        struct CodeIterator<'a> {
            reader: Reader<'a>,
        }

        impl<'a> Iterator for CodeIterator<'a> {
            type Item = Result<Instruction, ProgramParseError>;
            fn next(&mut self) -> Option<Self::Item> {
                if self.reader.is_eof() {
                    return None;
                }

                let result = (|| -> Result<Instruction, ProgramParseError> {
                    let opcode = self.reader.read_byte()?;
                    parse_instruction_impl(opcode, &mut self.reader)
                })();

                if result.is_err() {
                    self.reader.finish();
                }

                Some(result)
            }
        }

        CodeIterator {
            reader: self.get_section_reader(self.code.clone()),
        }
    }

    /// The upper bound of how many entries there might be in this program's jump table, excluding the very first implicit entry.
    pub fn jump_table_upper_bound(&self) -> usize {
        self.jump_table.len()
    }

    /// Returns an iterator over the jump table entries, excluding the very first implicit entry.
    pub fn jump_table(&'_ self) -> impl Iterator<Item = Result<u32, ProgramParseError>> + Clone + '_ {
        #[derive(Clone)]
        struct JumpTableIterator<'a> {
            reader: Reader<'a>,
        }

        impl<'a> Iterator for JumpTableIterator<'a> {
            type Item = Result<u32, ProgramParseError>;
            fn next(&mut self) -> Option<Self::Item> {
                if self.reader.is_eof() {
                    return None;
                }

                Some(self.reader.read_varint())
            }
        }

        JumpTableIterator {
            reader: self.get_section_reader(self.jump_table.clone()),
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

            bss_size: self.bss_size,
            stack_size: self.stack_size,

            ro_data: self.ro_data,
            rw_data: self.rw_data,
            exports: self.exports,
            imports: self.imports,
            code: self.code,
            jump_table: self.jump_table,

            debug_strings: self.debug_strings,
            debug_line_program_ranges: self.debug_line_program_ranges,
            debug_line_programs: self.debug_line_programs,

            instruction_count: self.instruction_count,
            basic_block_count: self.basic_block_count,
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
pub const SECTION_JUMP_TABLE: u8 = 6;
pub const SECTION_CODE: u8 = 7;
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
