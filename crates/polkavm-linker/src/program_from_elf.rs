use polkavm_common::abi::{MemoryMapBuilder, VM_CODE_ADDRESS_ALIGNMENT, VM_MAX_PAGE_SIZE, VM_MIN_PAGE_SIZE};
use polkavm_common::program::{
    self, FrameKind, Instruction, InstructionSet, LineProgramOp, Opcode, ProgramBlob, ProgramCounter, ProgramSymbol,
};
use polkavm_common::utils::{align_to_next_page_u32, align_to_next_page_u64};
use polkavm_common::varint;
use polkavm_common::writer::{ProgramBlobBuilder, Writer};

use core::ops::Range;
use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::Arc;

use crate::dwarf::Location;
use crate::elf::{Elf, Section, SectionIndex};
use crate::riscv::DecoderConfig;
use crate::riscv::Reg as RReg;
use crate::riscv::{AtomicKind, BranchKind, CmovKind, Inst, LoadKind, RegImmKind, StoreKind};

#[derive(Copy, Clone, PartialEq, Eq, Debug, Hash)]
#[repr(u8)]
enum Reg {
    // The registers supported by the VM.
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

    // Extra fake registers. These will be stripped away before the final codegen pass.
    E0 = 13,
    E1 = 14,
    E2 = 15,
}

impl From<polkavm_common::program::Reg> for Reg {
    fn from(reg: polkavm_common::program::Reg) -> Reg {
        use polkavm_common::program::Reg as R;
        match reg {
            R::RA => Reg::RA,
            R::SP => Reg::SP,
            R::T0 => Reg::T0,
            R::T1 => Reg::T1,
            R::T2 => Reg::T2,
            R::S0 => Reg::S0,
            R::S1 => Reg::S1,
            R::A0 => Reg::A0,
            R::A1 => Reg::A1,
            R::A2 => Reg::A2,
            R::A3 => Reg::A3,
            R::A4 => Reg::A4,
            R::A5 => Reg::A5,
        }
    }
}

impl From<polkavm_common::program::RawReg> for Reg {
    fn from(reg: polkavm_common::program::RawReg) -> Reg {
        reg.get().into()
    }
}

impl From<polkavm_common::program::RawReg> for RegImm {
    fn from(reg: polkavm_common::program::RawReg) -> RegImm {
        RegImm::Reg(reg.get().into())
    }
}

impl Reg {
    pub const fn from_usize(value: usize) -> Option<Reg> {
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
            13 => Some(Reg::E0),
            14 => Some(Reg::E1),
            15 => Some(Reg::E2),
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

            E0 => "e0",
            E1 => "e1",
            E2 => "e2",
        }
    }

    fn fake_register_index(self) -> Option<usize> {
        match self {
            Reg::E0 => Some(0),
            Reg::E1 => Some(1),
            Reg::E2 => Some(2),
            _ => None,
        }
    }

    const ALL: [Reg; 16] = {
        use Reg::*;
        [RA, SP, T0, T1, T2, S0, S1, A0, A1, A2, A3, A4, A5, E0, E1, E2]
    };

    const FAKE: [Reg; 3] = { [Reg::E0, Reg::E1, Reg::E2] };
    const INPUT_REGS: [Reg; 9] = [Reg::A0, Reg::A1, Reg::A2, Reg::A3, Reg::A4, Reg::A5, Reg::T0, Reg::T1, Reg::T2];
    const OUTPUT_REGS: [Reg; 2] = [Reg::A0, Reg::A1];
}

polkavm_common::static_assert!(Reg::INPUT_REGS.len() == polkavm_common::program::Reg::MAXIMUM_INPUT_REGS);
polkavm_common::static_assert!(Reg::OUTPUT_REGS.len() == polkavm_common::program::Reg::MAXIMUM_OUTPUT_REGS);

#[derive(Debug)]
pub enum ProgramFromElfErrorKind {
    FailedToParseElf(object::read::Error),
    FailedToParseDwarf(gimli::Error),
    FailedToParseProgram(program::ProgramParseError),
    UnsupportedSection(String),
    UnsupportedInstruction { section: String, offset: u64, instruction: u32 },
    UnsupportedRegister { reg: RReg },

    Other(Cow<'static, str>),
}

impl From<object::read::Error> for ProgramFromElfError {
    fn from(error: object::read::Error) -> Self {
        ProgramFromElfError(ProgramFromElfErrorKind::FailedToParseElf(error))
    }
}

impl From<gimli::Error> for ProgramFromElfError {
    fn from(error: gimli::Error) -> Self {
        ProgramFromElfError(ProgramFromElfErrorKind::FailedToParseDwarf(error))
    }
}

impl From<program::ProgramParseError> for ProgramFromElfError {
    fn from(error: program::ProgramParseError) -> Self {
        ProgramFromElfError(ProgramFromElfErrorKind::FailedToParseProgram(error))
    }
}

#[derive(Debug)]
pub struct ProgramFromElfError(ProgramFromElfErrorKind);

impl From<ProgramFromElfErrorKind> for ProgramFromElfError {
    fn from(kind: ProgramFromElfErrorKind) -> Self {
        Self(kind)
    }
}

impl ProgramFromElfError {
    pub(crate) fn other(error: impl Into<Cow<'static, str>>) -> Self {
        Self(ProgramFromElfErrorKind::Other(error.into()))
    }
}

impl std::error::Error for ProgramFromElfError {}

impl core::fmt::Display for ProgramFromElfError {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
        match &self.0 {
            ProgramFromElfErrorKind::FailedToParseElf(error) => write!(fmt, "failed to parse ELF file: {}", error),
            ProgramFromElfErrorKind::FailedToParseDwarf(error) => write!(fmt, "failed to parse DWARF: {}", error),
            ProgramFromElfErrorKind::FailedToParseProgram(error) => write!(fmt, "{}", error),
            ProgramFromElfErrorKind::UnsupportedSection(section) => write!(fmt, "unsupported section: {}", section),
            ProgramFromElfErrorKind::UnsupportedInstruction {
                section,
                offset,
                instruction,
            } => {
                write!(
                    fmt,
                    "unsupported instruction in section '{section}' at offset 0x{offset:x}: 0x{instruction:08x}"
                )
            }
            ProgramFromElfErrorKind::UnsupportedRegister { reg } => write!(fmt, "unsupported register: {reg}"),
            ProgramFromElfErrorKind::Other(message) => fmt.write_str(message),
        }
    }
}

fn cast_reg_non_zero(reg: RReg) -> Result<Option<Reg>, ProgramFromElfError> {
    use RReg::*;
    match reg {
        Zero => Ok(None),
        RA => Ok(Some(Reg::RA)),
        SP => Ok(Some(Reg::SP)),
        T0 => Ok(Some(Reg::T0)),
        T1 => Ok(Some(Reg::T1)),
        T2 => Ok(Some(Reg::T2)),
        S0 => Ok(Some(Reg::S0)),
        S1 => Ok(Some(Reg::S1)),
        A0 => Ok(Some(Reg::A0)),
        A1 => Ok(Some(Reg::A1)),
        A2 => Ok(Some(Reg::A2)),
        A3 => Ok(Some(Reg::A3)),
        A4 => Ok(Some(Reg::A4)),
        A5 => Ok(Some(Reg::A5)),
        GP | TP | A6 | A7 | S2 | S3 | S4 | S5 | S6 | S7 | S8 | S9 | S10 | S11 | T3 | T4 | T5 | T6 => {
            Err(ProgramFromElfErrorKind::UnsupportedRegister { reg }.into())
        }
    }
}

fn cast_reg_any(reg: RReg) -> Result<RegImm, ProgramFromElfError> {
    Ok(cast_reg_non_zero(reg)?.map_or(RegImm::Imm(0), RegImm::Reg))
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub(crate) struct Source {
    pub(crate) section_index: SectionIndex,
    pub(crate) offset_range: AddressRange,
}

impl core::fmt::Display for Source {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(
            fmt,
            "<{}+{}..{}>",
            self.section_index, self.offset_range.start, self.offset_range.end
        )
    }
}

impl Source {
    fn begin(&self) -> SectionTarget {
        SectionTarget {
            section_index: self.section_index,
            offset: self.offset_range.start,
        }
    }

    fn iter(&'_ self) -> impl Iterator<Item = SectionTarget> + '_ {
        (self.offset_range.start..self.offset_range.end)
            .step_by(2)
            .map(|offset| SectionTarget {
                section_index: self.section_index,
                offset,
            })
    }
}

// TODO: Use smallvec.
#[derive(Clone, Debug)]
struct SourceStack(Vec<Source>);

impl core::fmt::Display for SourceStack {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
        fmt.write_str("[")?;
        let mut is_first = true;
        for source in &self.0 {
            if is_first {
                is_first = false;
            } else {
                fmt.write_str(", ")?;
            }
            source.fmt(fmt)?;
        }
        fmt.write_str("]")
    }
}

impl SourceStack {
    fn as_slice(&self) -> &[Source] {
        &self.0
    }

    fn top(&self) -> &Source {
        &self.0[0]
    }

    fn overlay_on_top_of(&self, stack: &SourceStack) -> Self {
        let mut vec = Vec::with_capacity(self.0.len() + stack.0.len());
        vec.extend(self.0.iter().copied());
        vec.extend(stack.0.iter().copied());

        SourceStack(vec)
    }

    fn overlay_on_top_of_inplace(&mut self, stack: &SourceStack) {
        self.0.extend(stack.0.iter().copied());
    }
}

impl From<Source> for SourceStack {
    fn from(source: Source) -> Self {
        SourceStack(vec![source])
    }
}

#[derive(Clone, Debug)]
struct EndOfBlock<T> {
    source: SourceStack,
    instruction: ControlInst<T>,
}

impl<T> EndOfBlock<T> {
    fn map_target<U, E>(self, map: impl Fn(T) -> Result<U, E>) -> Result<EndOfBlock<U>, E> {
        Ok(EndOfBlock {
            source: self.source,
            instruction: self.instruction.map_target(map)?,
        })
    }
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct AddressRange {
    pub(crate) start: u64,
    pub(crate) end: u64,
}

impl AddressRange {
    pub(crate) fn is_empty(&self) -> bool {
        self.end == self.start
    }
}

impl core::fmt::Display for AddressRange {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(fmt, "0x{:x}-0x{:x}", self.start, self.end)
    }
}

impl core::fmt::Debug for AddressRange {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(fmt, "0x{:x}-0x{:x}", self.start, self.end)
    }
}

impl From<Range<u64>> for AddressRange {
    fn from(range: Range<u64>) -> Self {
        AddressRange {
            start: range.start,
            end: range.end,
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct SectionTarget {
    pub(crate) section_index: SectionIndex,
    pub(crate) offset: u64,
}

impl core::fmt::Display for SectionTarget {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(fmt, "<{}+{}>", self.section_index, self.offset)
    }
}

impl core::fmt::Debug for SectionTarget {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(fmt, "<{}+{}>", self.section_index, self.offset)
    }
}

impl From<SectionTarget> for SectionIndex {
    fn from(target: SectionTarget) -> Self {
        target.section_index
    }
}

fn i32_to_i64(x: i32) -> i64 {
    i64::from(x)
}

fn extract_delimited<'a>(str: &mut &'a str, prefix: &str, suffix: &str) -> Option<(&'a str, &'a str)> {
    let original = *str;
    let start_of_prefix = str.find(prefix)?;
    let start = start_of_prefix + prefix.len();
    let end = str[start..].find(suffix)? + start;
    *str = &str[end + suffix.len()..];
    Some((&original[..start_of_prefix], &original[start..end]))
}

#[test]
fn test_extract_delimited() {
    let mut str = "foo <section #1234+567> bar";
    assert_eq!(extract_delimited(&mut str, "<section #", ">").unwrap(), ("foo ", "1234+567"));
    assert_eq!(str, " bar");
}

impl SectionTarget {
    fn fmt_human_readable<H>(&self, elf: &Elf<H>) -> String
    where
        H: object::read::elf::FileHeader<Endian = object::LittleEndian>,
    {
        Self::make_human_readable_in_debug_string(elf, &self.to_string())
    }

    fn make_human_readable_in_debug_string<H>(elf: &Elf<H>, mut str: &str) -> String
    where
        H: object::read::elf::FileHeader<Endian = object::LittleEndian>,
    {
        // A hack-ish way to make nested `Debug` error messages more readable by replacing
        // raw section indexes and offsets with a more human readable string.

        let mut output = String::new();
        while let Some((prefix, chunk)) = extract_delimited(&mut str, "<section #", ">") {
            output.push_str(prefix);

            let mut iter = chunk.split('+');
            if let Some(section_index) = iter.next().and_then(|s| s.parse::<usize>().ok()) {
                if let Some(offset) = iter.next().and_then(|s| s.parse::<u64>().ok()) {
                    if let Some(section) = elf.section_by_raw_index(section_index) {
                        use core::fmt::Write;

                        let symbol = elf.symbols().find(|symbol| {
                            let Ok((symbol_section, symbol_offset)) = symbol.section_and_offset() else {
                                return false;
                            };
                            symbol_section.index().raw() == section_index
                                && offset >= symbol_offset
                                && offset < (symbol_offset + symbol.size())
                        });

                        let section_name = section.name();
                        write!(&mut output, "<section #{section_index}+{offset} ('{section_name}'").unwrap();
                        if let Some(symbol) = symbol {
                            if let Some(symbol_name) = symbol.name() {
                                write!(
                                    &mut output,
                                    ": '{}'+{}",
                                    symbol_name,
                                    offset - symbol.section_and_offset().unwrap().1
                                )
                                .unwrap();
                            }
                        }
                        output.push_str(")>");
                        continue;
                    }
                }
            }
            output.push_str(chunk);
        }

        output.push_str(str);
        output
    }

    fn add(self, offset: u64) -> Self {
        SectionTarget {
            section_index: self.section_index,
            offset: self.offset + offset,
        }
    }

    fn map_offset_i32(self, cb: impl FnOnce(i32) -> i32) -> Self {
        let offset: u32 = self.offset.try_into().expect("section offset is too large");
        SectionTarget {
            section_index: self.section_index,
            offset: u64::from(cb(offset as i32) as u32),
        }
    }

    fn map_offset_i64(self, cb: impl FnOnce(i64) -> i64) -> Self {
        let offset = self.offset as i64;
        SectionTarget {
            section_index: self.section_index,
            offset: cb(offset) as u64,
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
#[repr(transparent)]
struct BlockTarget {
    block_index: usize,
}

impl BlockTarget {
    fn from_raw(block_index: usize) -> Self {
        BlockTarget { block_index }
    }

    fn index(self) -> usize {
        self.block_index
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Hash)]
enum AnyTarget {
    Data(SectionTarget),
    Code(BlockTarget),
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Hash)]
enum RegImm {
    Reg(Reg),
    Imm(u32),
}

impl RegImm {
    fn map_register(self, mut map: impl FnMut(Reg) -> Reg) -> RegImm {
        match self {
            RegImm::Reg(reg) => RegImm::Reg(map(reg)),
            RegImm::Imm(value) => RegImm::Imm(value),
        }
    }
}

impl From<Reg> for RegImm {
    fn from(reg: Reg) -> Self {
        RegImm::Reg(reg)
    }
}

impl From<u32> for RegImm {
    fn from(value: u32) -> Self {
        RegImm::Imm(value)
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
enum BasicInst<T> {
    LoadAbsolute {
        kind: LoadKind,
        dst: Reg,
        target: SectionTarget,
    },
    StoreAbsolute {
        kind: StoreKind,
        src: RegImm,
        target: SectionTarget,
    },
    LoadIndirect {
        kind: LoadKind,
        dst: Reg,
        base: Reg,
        offset: i32,
    },
    StoreIndirect {
        kind: StoreKind,
        src: RegImm,
        base: Reg,
        offset: i32,
    },
    LoadAddress {
        dst: Reg,
        target: T,
    },
    // This is supposed to load the address from the GOT, instead of loading it directly as an immediate.
    LoadAddressIndirect {
        dst: Reg,
        target: T,
    },
    LoadImmediate {
        dst: Reg,
        imm: i32,
    },
    LoadImmediate64 {
        dst: Reg,
        imm: i64,
    },
    MoveReg {
        dst: Reg,
        src: Reg,
    },
    RegReg {
        kind: RegRegKind,
        dst: Reg,
        src1: Reg,
        src2: Reg,
    },
    AnyAny {
        kind: AnyAnyKind,
        dst: Reg,
        src1: RegImm,
        src2: RegImm,
    },
    Cmov {
        kind: CmovKind,
        dst: Reg,
        src: RegImm,
        cond: Reg,
    },
    Ecalli {
        nth_import: usize,
    },
    Sbrk {
        dst: Reg,
        size: Reg,
    },
    Nop,
}

#[derive(Copy, Clone)]
enum OpKind {
    Read,
    Write,
    ReadWrite,
}

impl<T> BasicInst<T> {
    fn is_nop(&self) -> bool {
        match self {
            BasicInst::MoveReg { dst, src } => dst == src,
            BasicInst::Nop => true,
            _ => false,
        }
    }

    fn src_mask(&self, imports: &[Import]) -> RegMask {
        match *self {
            BasicInst::Nop
            | BasicInst::LoadImmediate { .. }
            | BasicInst::LoadImmediate64 { .. }
            | BasicInst::LoadAbsolute { .. }
            | BasicInst::LoadAddress { .. }
            | BasicInst::LoadAddressIndirect { .. } => RegMask::empty(),
            BasicInst::MoveReg { src, .. } => RegMask::from(src),
            BasicInst::StoreAbsolute { src, .. } => RegMask::from(src),
            BasicInst::LoadIndirect { base, .. } => RegMask::from(base),
            BasicInst::StoreIndirect { src, base, .. } => RegMask::from(src) | RegMask::from(base),
            BasicInst::RegReg { src1, src2, .. } => RegMask::from(src1) | RegMask::from(src2),
            BasicInst::AnyAny { src1, src2, .. } => RegMask::from(src1) | RegMask::from(src2),
            BasicInst::Cmov { dst, src, cond, .. } => RegMask::from(dst) | RegMask::from(src) | RegMask::from(cond),
            BasicInst::Ecalli { nth_import } => imports[nth_import].src_mask(),
            BasicInst::Sbrk { size, .. } => RegMask::from(size),
        }
    }

    fn dst_mask(&self, imports: &[Import]) -> RegMask {
        match *self {
            BasicInst::Nop | BasicInst::StoreAbsolute { .. } | BasicInst::StoreIndirect { .. } => RegMask::empty(),
            BasicInst::MoveReg { dst, .. }
            | BasicInst::LoadImmediate { dst, .. }
            | BasicInst::LoadImmediate64 { dst, .. }
            | BasicInst::LoadAbsolute { dst, .. }
            | BasicInst::LoadAddress { dst, .. }
            | BasicInst::LoadAddressIndirect { dst, .. }
            | BasicInst::LoadIndirect { dst, .. }
            | BasicInst::RegReg { dst, .. }
            | BasicInst::Cmov { dst, .. }
            | BasicInst::AnyAny { dst, .. } => RegMask::from(dst),
            BasicInst::Ecalli { nth_import } => imports[nth_import].dst_mask(),
            BasicInst::Sbrk { dst, .. } => RegMask::from(dst),
        }
    }

    fn has_side_effects(&self, config: &Config) -> bool {
        match *self {
            BasicInst::Sbrk { .. } | BasicInst::Ecalli { .. } | BasicInst::StoreAbsolute { .. } | BasicInst::StoreIndirect { .. } => true,
            BasicInst::LoadAbsolute { .. } | BasicInst::LoadIndirect { .. } => !config.elide_unnecessary_loads,
            BasicInst::Nop
            | BasicInst::MoveReg { .. }
            | BasicInst::LoadImmediate { .. }
            | BasicInst::LoadImmediate64 { .. }
            | BasicInst::LoadAddress { .. }
            | BasicInst::LoadAddressIndirect { .. }
            | BasicInst::RegReg { .. }
            | BasicInst::Cmov { .. }
            | BasicInst::AnyAny { .. } => false,
        }
    }

    fn map_register(self, mut map: impl FnMut(Reg, OpKind) -> Reg) -> Option<Self> {
        // Note: ALWAYS map the inputs first; otherwise `regalloc2` might break!
        match self {
            BasicInst::LoadImmediate { dst, imm } => Some(BasicInst::LoadImmediate {
                dst: map(dst, OpKind::Write),
                imm,
            }),
            BasicInst::LoadImmediate64 { dst, imm } => Some(BasicInst::LoadImmediate64 {
                dst: map(dst, OpKind::Write),
                imm,
            }),
            BasicInst::LoadAbsolute { kind, dst, target } => Some(BasicInst::LoadAbsolute {
                kind,
                dst: map(dst, OpKind::Write),
                target,
            }),
            BasicInst::StoreAbsolute { kind, src, target } => Some(BasicInst::StoreAbsolute {
                kind,
                src: src.map_register(|reg| map(reg, OpKind::Read)),
                target,
            }),
            BasicInst::LoadAddress { dst, target } => Some(BasicInst::LoadAddress {
                dst: map(dst, OpKind::Write),
                target,
            }),
            BasicInst::LoadAddressIndirect { dst, target } => Some(BasicInst::LoadAddressIndirect {
                dst: map(dst, OpKind::Write),
                target,
            }),
            BasicInst::LoadIndirect { kind, dst, base, offset } => Some(BasicInst::LoadIndirect {
                kind,
                base: map(base, OpKind::Read),
                dst: map(dst, OpKind::Write),
                offset,
            }),
            BasicInst::StoreIndirect { kind, src, base, offset } => Some(BasicInst::StoreIndirect {
                kind,
                src: src.map_register(|reg| map(reg, OpKind::Read)),
                base: map(base, OpKind::Read),
                offset,
            }),
            BasicInst::RegReg { kind, dst, src1, src2 } => Some(BasicInst::RegReg {
                kind,
                src1: map(src1, OpKind::Read),
                src2: map(src2, OpKind::Read),
                dst: map(dst, OpKind::Write),
            }),
            BasicInst::AnyAny { kind, dst, src1, src2 } => Some(BasicInst::AnyAny {
                kind,
                src1: src1.map_register(|reg| map(reg, OpKind::Read)),
                src2: src2.map_register(|reg| map(reg, OpKind::Read)),
                dst: map(dst, OpKind::Write),
            }),
            BasicInst::MoveReg { dst, src } => Some(BasicInst::MoveReg {
                src: map(src, OpKind::Read),
                dst: map(dst, OpKind::Write),
            }),
            BasicInst::Cmov { kind, dst, src, cond } => Some(BasicInst::Cmov {
                kind,
                src: src.map_register(|reg| map(reg, OpKind::Read)),
                cond: map(cond, OpKind::Read),
                dst: map(dst, OpKind::ReadWrite),
            }),
            BasicInst::Ecalli { .. } => None,
            BasicInst::Sbrk { dst, size } => Some(BasicInst::Sbrk {
                size: map(size, OpKind::Read),
                dst: map(dst, OpKind::Write),
            }),
            BasicInst::Nop => Some(BasicInst::Nop),
        }
    }

    fn operands(&self, imports: &[Import]) -> impl Iterator<Item = (Reg, OpKind)>
    where
        T: Clone,
    {
        let mut list = [None, None, None, None, None, None, None, None];
        let mut length = 0;
        // Abuse the `map_register` to avoid matching on everything again.
        let is_special_instruction = self
            .clone()
            .map_register(|reg, kind| {
                list[length] = Some((reg, kind));
                length += 1;
                reg
            })
            .is_none();

        if is_special_instruction {
            assert_eq!(length, 0);

            let BasicInst::Ecalli { nth_import } = *self else { unreachable!() };
            let import = &imports[nth_import];

            for reg in import.src_mask() {
                list[length] = Some((reg, OpKind::Read));
                length += 1;
            }

            for reg in import.dst_mask() {
                list[length] = Some((reg, OpKind::Write));
                length += 1;
            }
        };

        let mut seen_dst = false;
        list.into_iter().take_while(|reg| reg.is_some()).flatten().map(move |(reg, kind)| {
            let is_dst = matches!(kind, OpKind::Write | OpKind::ReadWrite);

            // Sanity check to make sure inputs always come before outputs, so that `regalloc2` doesn't break.
            if seen_dst {
                assert!(is_dst);
            }
            seen_dst |= is_dst;

            (reg, kind)
        })
    }

    fn map_target<U, E>(self, map: impl Fn(T) -> Result<U, E>) -> Result<BasicInst<U>, E> {
        Ok(match self {
            BasicInst::MoveReg { dst, src } => BasicInst::MoveReg { dst, src },
            BasicInst::LoadImmediate { dst, imm } => BasicInst::LoadImmediate { dst, imm },
            BasicInst::LoadImmediate64 { dst, imm } => BasicInst::LoadImmediate64 { dst, imm },
            BasicInst::LoadAbsolute { kind, dst, target } => BasicInst::LoadAbsolute { kind, dst, target },
            BasicInst::StoreAbsolute { kind, src, target } => BasicInst::StoreAbsolute { kind, src, target },
            BasicInst::LoadAddress { dst, target } => BasicInst::LoadAddress { dst, target: map(target)? },
            BasicInst::LoadAddressIndirect { dst, target } => BasicInst::LoadAddressIndirect { dst, target: map(target)? },
            BasicInst::LoadIndirect { kind, dst, base, offset } => BasicInst::LoadIndirect { kind, dst, base, offset },
            BasicInst::StoreIndirect { kind, src, base, offset } => BasicInst::StoreIndirect { kind, src, base, offset },
            BasicInst::RegReg { kind, dst, src1, src2 } => BasicInst::RegReg { kind, dst, src1, src2 },
            BasicInst::AnyAny { kind, dst, src1, src2 } => BasicInst::AnyAny { kind, dst, src1, src2 },
            BasicInst::Cmov { kind, dst, src, cond } => BasicInst::Cmov { kind, dst, src, cond },
            BasicInst::Ecalli { nth_import } => BasicInst::Ecalli { nth_import },
            BasicInst::Sbrk { dst, size } => BasicInst::Sbrk { dst, size },
            BasicInst::Nop => BasicInst::Nop,
        })
    }

    fn target(&self) -> (Option<SectionTarget>, Option<T>)
    where
        T: Copy,
    {
        match self {
            BasicInst::LoadAbsolute { target, .. } | BasicInst::StoreAbsolute { target, .. } => (Some(*target), None),
            BasicInst::LoadAddress { target, .. } | BasicInst::LoadAddressIndirect { target, .. } => (None, Some(*target)),
            BasicInst::Nop
            | BasicInst::MoveReg { .. }
            | BasicInst::LoadImmediate { .. }
            | BasicInst::LoadImmediate64 { .. }
            | BasicInst::LoadIndirect { .. }
            | BasicInst::StoreIndirect { .. }
            | BasicInst::RegReg { .. }
            | BasicInst::AnyAny { .. }
            | BasicInst::Cmov { .. }
            | BasicInst::Sbrk { .. }
            | BasicInst::Ecalli { .. } => (None, None),
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
enum ControlInst<T> {
    Jump {
        target: T,
    },
    Call {
        ra: Reg,
        target: T,
        target_return: T,
    },
    JumpIndirect {
        base: Reg,
        offset: i64,
    },
    CallIndirect {
        ra: Reg,
        base: Reg,
        offset: i64,
        target_return: T,
    },
    Branch {
        kind: BranchKind,
        src1: RegImm,
        src2: RegImm,
        target_true: T,
        target_false: T,
    },
    Unimplemented,
}

impl<T> ControlInst<T> {
    fn src_mask(&self) -> RegMask {
        match *self {
            ControlInst::Jump { .. } | ControlInst::Call { .. } | ControlInst::Unimplemented => RegMask::empty(),
            ControlInst::JumpIndirect { base, .. } | ControlInst::CallIndirect { base, .. } => RegMask::from(base),
            ControlInst::Branch { src1, src2, .. } => RegMask::from(src1) | RegMask::from(src2),
        }
    }

    fn dst_mask(&self) -> RegMask {
        match *self {
            ControlInst::Jump { .. } | ControlInst::JumpIndirect { .. } | ControlInst::Branch { .. } | ControlInst::Unimplemented => {
                RegMask::empty()
            }
            ControlInst::Call { ra, .. } | ControlInst::CallIndirect { ra, .. } => RegMask::from(ra),
        }
    }

    fn map_target<U, E>(self, map: impl Fn(T) -> Result<U, E>) -> Result<ControlInst<U>, E> {
        Ok(match self {
            ControlInst::Jump { target } => ControlInst::Jump { target: map(target)? },
            ControlInst::Call { ra, target, target_return } => ControlInst::Call {
                ra,
                target: map(target)?,
                target_return: map(target_return)?,
            },
            ControlInst::JumpIndirect { base, offset } => ControlInst::JumpIndirect { base, offset },
            ControlInst::CallIndirect {
                ra,
                base,
                offset,
                target_return,
            } => ControlInst::CallIndirect {
                ra,
                base,
                offset,
                target_return: map(target_return)?,
            },
            ControlInst::Branch {
                kind,
                src1,
                src2,
                target_true,
                target_false,
            } => ControlInst::Branch {
                kind,
                src1,
                src2,
                target_true: map(target_true)?,
                target_false: map(target_false)?,
            },
            ControlInst::Unimplemented => ControlInst::Unimplemented,
        })
    }

    fn targets(&self) -> [Option<&T>; 2] {
        match self {
            ControlInst::Jump { target, .. } => [Some(target), None],
            ControlInst::Call { target, target_return, .. } => [Some(target), Some(target_return)],
            ControlInst::CallIndirect { target_return, .. } => [Some(target_return), None],
            ControlInst::Branch {
                target_true, target_false, ..
            } => [Some(target_true), Some(target_false)],
            ControlInst::JumpIndirect { .. } | ControlInst::Unimplemented => [None, None],
        }
    }

    fn fallthrough_target(&self) -> Option<T>
    where
        T: Copy,
    {
        match self {
            ControlInst::Jump { .. } | ControlInst::JumpIndirect { .. } | ControlInst::Unimplemented => None,
            ControlInst::Branch { target_false: target, .. }
            | ControlInst::Call { target_return: target, .. }
            | ControlInst::CallIndirect { target_return: target, .. } => Some(*target),
        }
    }

    fn fallthrough_target_mut(&mut self) -> Option<&mut T> {
        match self {
            ControlInst::Jump { .. } | ControlInst::JumpIndirect { .. } | ControlInst::Unimplemented => None,
            ControlInst::Branch { target_false: target, .. }
            | ControlInst::Call { target_return: target, .. }
            | ControlInst::CallIndirect { target_return: target, .. } => Some(target),
        }
    }
}

#[derive(Copy, Clone, Debug)]
enum InstExt<BasicT, ControlT> {
    Basic(BasicInst<BasicT>),
    Control(ControlInst<ControlT>),
}

impl<BasicT, ControlT> InstExt<BasicT, ControlT> {
    fn nop() -> Self {
        InstExt::Basic(BasicInst::Nop)
    }
}

impl<BasicT, ControlT> From<BasicInst<BasicT>> for InstExt<BasicT, ControlT> {
    fn from(inst: BasicInst<BasicT>) -> Self {
        InstExt::Basic(inst)
    }
}

impl<BasicT, ControlT> From<ControlInst<ControlT>> for InstExt<BasicT, ControlT> {
    fn from(inst: ControlInst<ControlT>) -> Self {
        InstExt::Control(inst)
    }
}

#[derive(Debug)]
struct BasicBlock<BasicT, ControlT> {
    target: BlockTarget,
    source: Source,
    ops: Vec<(SourceStack, BasicInst<BasicT>)>,
    next: EndOfBlock<ControlT>,
}

impl<BasicT, ControlT> BasicBlock<BasicT, ControlT> {
    fn new(target: BlockTarget, source: Source, ops: Vec<(SourceStack, BasicInst<BasicT>)>, next: EndOfBlock<ControlT>) -> Self {
        Self { target, source, ops, next }
    }
}

fn split_function_name(name: &str) -> (String, String) {
    let (with_hash, without_hash) = if let Ok(name) = rustc_demangle::try_demangle(name) {
        (name.to_string(), format!("{:#}", name))
    } else {
        (name.to_owned(), name.to_owned())
    };

    // Ideally we'd parse the symbol into an actual AST and use that,
    // but that's a lot of work, so for now let's just do it like this.
    //
    // Here we want to split the symbol into two parts: the namespace, and the name + hash.
    // The idea being that multiple symbols most likely share the namespcae, allowing us to
    // deduplicate those strings in the output blob.
    //
    // For example, this symbol:
    //   _ZN5alloc7raw_vec19RawVec$LT$T$C$A$GT$7reserve21do_reserve_and_handle17hddecba91f804dbebE
    // can be demangled into these:
    //   with_hash    = "alloc::raw_vec::RawVec<T,A>::reserve::do_reserve_and_handle::hddecba91f804dbeb"
    //   without_hash = "alloc::raw_vec::RawVec<T,A>::reserve::do_reserve_and_handle"
    //
    // So what we want is to split it in two like this:
    //   prefix = "alloc::raw_vec::RawVec<T,A>::reserve"
    //   suffix = "do_reserve_and_handle::hddecba91f804dbeb"

    if with_hash.contains("::") {
        let suffix_index = {
            let mut found = None;
            let mut depth = 0;
            let mut last = '\0';
            let mut index = without_hash.len();
            for ch in without_hash.chars().rev() {
                if ch == '>' {
                    depth += 1;
                } else if ch == '<' {
                    depth -= 1;
                } else if ch == ':' && depth == 0 && last == ':' {
                    found = Some(index + 1);
                    break;
                }

                last = ch;
                index -= ch.len_utf8();
            }

            found
        };

        if let Some(suffix_index) = suffix_index {
            let prefix = &with_hash[..suffix_index - 2];
            let suffix = &with_hash[suffix_index..];
            return (prefix.to_owned(), suffix.to_owned());
        } else {
            log::warn!("Failed to split symbol: {:?}", with_hash);
        }
    }

    (String::new(), with_hash)
}

#[derive(Clone, Debug)]
enum DataRef {
    Section { section_index: SectionIndex, range: Range<usize> },
    Padding(usize),
}

impl DataRef {
    fn size(&self) -> usize {
        match self {
            Self::Section { range, .. } => range.len(),
            Self::Padding(size) => *size,
        }
    }
}

#[derive(Debug)]
struct MemoryConfig {
    ro_data: Vec<DataRef>,
    rw_data: Vec<DataRef>,
    ro_data_size: u32,
    rw_data_size: u32,
    min_stack_size: u32,
}

fn get_padding(memory_end: u64, align: u64) -> Option<u64> {
    let misalignment = memory_end % align;
    if misalignment == 0 {
        None
    } else {
        Some(align - misalignment)
    }
}

fn process_sections<H>(
    elf: &Elf<H>,
    current_address: &mut u64,
    chunks: &mut Vec<DataRef>,
    base_address_for_section: &mut HashMap<SectionIndex, u64>,
    sections: impl IntoIterator<Item = SectionIndex>,
) -> u64
where
    H: object::read::elf::FileHeader<Endian = object::LittleEndian>,
{
    for section_index in sections {
        let section = elf.section_by_index(section_index);
        assert!(section.size() >= section.data().len() as u64);

        if let Some(padding) = get_padding(*current_address, section.align()) {
            *current_address += padding;
            chunks.push(DataRef::Padding(padding as usize));
        }

        let section_name = section.name();
        let section_base_address = *current_address;
        base_address_for_section.insert(section.index(), section_base_address);

        *current_address += section.size();
        if !section.data().is_empty() {
            chunks.push(DataRef::Section {
                section_index: section.index(),
                range: 0..section.data().len(),
            });
        }

        let padding = section.size() - section.data().len() as u64;
        if padding > 0 {
            chunks.push(DataRef::Padding(padding.try_into().expect("overflow")))
        }

        log::trace!(
            "Found section: '{}', original range = 0x{:x}..0x{:x} (relocated to: 0x{:x}..0x{:x}), size = 0x{:x}/0x{:x}",
            section_name,
            section.original_address(),
            section.original_address() + section.size(),
            section_base_address,
            section_base_address + section.size(),
            section.data().len(),
            section.size(),
        );
    }

    let size_in_memory: u64 = chunks.iter().map(|chunk| chunk.size() as u64).sum();
    while let Some(DataRef::Padding(..)) = chunks.last() {
        chunks.pop();
    }

    *current_address = align_to_next_page_u64(u64::from(VM_MAX_PAGE_SIZE), *current_address).expect("overflow");
    // Add a guard page between this section and the next one.
    *current_address += u64::from(VM_MAX_PAGE_SIZE);

    size_in_memory
}

#[allow(clippy::too_many_arguments)]
fn extract_memory_config<H>(
    elf: &Elf<H>,
    sections_ro_data: &[SectionIndex],
    sections_rw_data: &[SectionIndex],
    sections_bss: &[SectionIndex],
    sections_min_stack_size: &[SectionIndex],
    base_address_for_section: &mut HashMap<SectionIndex, u64>,
) -> Result<MemoryConfig, ProgramFromElfError>
where
    H: object::read::elf::FileHeader<Endian = object::LittleEndian>,
{
    let mut current_address = u64::from(VM_MAX_PAGE_SIZE);

    let mut ro_data = Vec::new();
    let mut rw_data = Vec::new();
    let ro_data_address = current_address;
    let ro_data_size = process_sections(
        elf,
        &mut current_address,
        &mut ro_data,
        base_address_for_section,
        sections_ro_data.iter().copied(),
    );
    let rw_data_address = current_address;
    let rw_data_size = process_sections(
        elf,
        &mut current_address,
        &mut rw_data,
        base_address_for_section,
        sections_rw_data.iter().copied().chain(sections_bss.iter().copied()),
    );

    let mut min_stack_size = VM_MIN_PAGE_SIZE;
    for &section_index in sections_min_stack_size {
        let section = elf.section_by_index(section_index);
        let data = section.data();
        if data.len() % 4 != 0 {
            return Err(ProgramFromElfError::other(format!("section '{}' has invalid size", section.name())));
        }

        for xs in data.chunks_exact(4) {
            let value = u32::from_le_bytes([xs[0], xs[1], xs[2], xs[3]]);
            min_stack_size = core::cmp::max(min_stack_size, value);
        }
    }

    let min_stack_size =
        align_to_next_page_u32(VM_MIN_PAGE_SIZE, min_stack_size).ok_or(ProgramFromElfError::other("out of range size for the stack"))?;

    log::trace!("Configured minimum stack size: 0x{min_stack_size:x}");

    let ro_data_size = u32::try_from(ro_data_size).expect("overflow");
    let rw_data_size = u32::try_from(rw_data_size).expect("overflow");

    // Sanity check that the memory configuration is actually valid.
    {
        let rw_data_size_physical: u64 = rw_data.iter().map(|x| x.size() as u64).sum();
        let rw_data_size_physical = u32::try_from(rw_data_size_physical).expect("overflow");
        assert!(rw_data_size_physical <= rw_data_size);

        let config = match MemoryMapBuilder::new(VM_MAX_PAGE_SIZE)
            .ro_data_size(ro_data_size)
            .rw_data_size(rw_data_size)
            .stack_size(min_stack_size)
            .build()
        {
            Ok(config) => config,
            Err(error) => {
                return Err(ProgramFromElfError::other(error));
            }
        };

        assert_eq!(u64::from(config.ro_data_address()), ro_data_address);
        assert_eq!(u64::from(config.rw_data_address()), rw_data_address);
    }

    let memory_config = MemoryConfig {
        ro_data,
        rw_data,
        ro_data_size,
        rw_data_size,
        min_stack_size,
    };

    Ok(memory_config)
}

#[derive(Clone, PartialEq, Eq, Debug)]
struct ExternMetadata {
    index: Option<u32>,
    symbol: Vec<u8>,
    input_regs: u8,
    output_regs: u8,
}

#[derive(Clone, PartialEq, Eq, Debug)]
struct Export {
    location: SectionTarget,
    metadata: ExternMetadata,
}

fn extract_exports<H>(
    elf: &Elf<H>,
    relocations: &BTreeMap<SectionTarget, RelocationKind>,
    section: &Section,
) -> Result<Vec<Export>, ProgramFromElfError>
where
    H: object::read::elf::FileHeader<Endian = object::LittleEndian>,
{
    let mut b = polkavm_common::elf::Reader::from(section.data());
    let mut exports = Vec::new();
    loop {
        let Ok(version) = b.read_byte() else { break };

        if version != 1 {
            return Err(ProgramFromElfError::other(format!(
                "failed to parse export metadata: unsupported export metadata version: {}",
                version
            )));
        }

        let metadata = {
            let location = SectionTarget {
                section_index: section.index(),
                offset: b.offset() as u64,
            };

            // Ignore the address as written; we'll just use the relocations instead.
            let error = if elf.is_64() { b.read_u64().err() } else { b.read_u32().err() };

            if let Some(error) = error {
                return Err(ProgramFromElfError::other(format!("failed to parse export metadata: {}", error)));
            }

            let Some(relocation) = relocations.get(&location) else {
                return Err(ProgramFromElfError::other(format!(
                    "found an export without a relocation for a pointer to the metadata at {location}"
                )));
            };

            let target = match relocation {
                RelocationKind::Abs {
                    target,
                    size: RelocationSize::U64,
                } if elf.is_64() => target,
                RelocationKind::Abs {
                    target,
                    size: RelocationSize::U32,
                } if !elf.is_64() => target,
                _ => {
                    return Err(ProgramFromElfError::other(format!(
                        "found an export with an unexpected relocation at {location}: {relocation:?}"
                    )));
                }
            };

            parse_extern_metadata(elf, relocations, *target)?
        };

        let location = SectionTarget {
            section_index: section.index(),
            offset: b.offset() as u64,
        };

        // Ignore the address as written; we'll just use the relocations instead.
        let error = if elf.is_64() { b.read_u64().err() } else { b.read_u32().err() };

        if let Some(error) = error {
            return Err(ProgramFromElfError::other(format!("failed to parse export metadata: {}", error)));
        }

        let Some(relocation) = relocations.get(&location) else {
            return Err(ProgramFromElfError::other(format!(
                "found an export without a relocation for a pointer to the code at {location}"
            )));
        };

        let target = match relocation {
            RelocationKind::Abs {
                target,
                size: RelocationSize::U64,
            } if elf.is_64() => target,
            RelocationKind::Abs {
                target,
                size: RelocationSize::U32,
            } if !elf.is_64() => target,
            _ => {
                return Err(ProgramFromElfError::other(format!(
                    "found an export with an unexpected relocation at {location}: {relocation:?}"
                )));
            }
        };

        exports.push(Export {
            location: *target,
            metadata,
        });
    }

    Ok(exports)
}

#[derive(Clone, Debug)]
struct Import {
    metadata: ExternMetadata,
}

impl core::ops::Deref for Import {
    type Target = ExternMetadata;
    fn deref(&self) -> &Self::Target {
        &self.metadata
    }
}

impl Import {
    fn src(&'_ self) -> impl Iterator<Item = Reg> + '_ {
        assert!(self.metadata.input_regs as usize <= Reg::INPUT_REGS.len());
        Reg::INPUT_REGS
            .into_iter()
            .take(self.metadata.input_regs as usize)
            .chain(core::iter::once(Reg::SP))
    }

    fn src_mask(&self) -> RegMask {
        let mut mask = RegMask::empty();
        for reg in self.src() {
            mask.insert(reg);
        }

        mask
    }

    #[allow(clippy::unused_self)]
    fn dst(&self) -> impl Iterator<Item = Reg> {
        assert!(self.metadata.output_regs as usize <= Reg::OUTPUT_REGS.len());
        [Reg::T0, Reg::T1, Reg::T2, Reg::A0, Reg::A1, Reg::A2, Reg::A3, Reg::A4, Reg::A5].into_iter()
    }

    fn dst_mask(&self) -> RegMask {
        let mut mask = RegMask::empty();
        for reg in self.dst() {
            mask.insert(reg);
        }

        mask
    }
}

fn parse_extern_metadata_impl<H>(
    elf: &Elf<H>,
    relocations: &BTreeMap<SectionTarget, RelocationKind>,
    target: SectionTarget,
) -> Result<ExternMetadata, String>
where
    H: object::read::elf::FileHeader<Endian = object::LittleEndian>,
{
    let section = elf.section_by_index(target.section_index);
    let mut b = polkavm_common::elf::Reader::from(section.data());
    let _ = b.read(target.offset as usize)?;

    let version = b.read_byte()?;
    if version != 1 && version != 2 {
        return Err(format!("unsupported extern metadata version: '{version}' (expected '1' or '2')"));
    }

    let flags = b.read_u32()?;
    let symbol_length = b.read_u32()?;
    let Some(symbol_relocation) = relocations.get(&SectionTarget {
        section_index: section.index(),
        offset: b.offset() as u64,
    }) else {
        return Err("missing relocation for the symbol".into());
    };

    // Ignore the address as written; we'll just use the relocations instead.
    if elf.is_64() {
        b.read_u64()?;
    } else {
        b.read_u32()?;
    };

    let symbol_location = match symbol_relocation {
        RelocationKind::Abs {
            target,
            size: RelocationSize::U64,
        } if elf.is_64() => target,
        RelocationKind::Abs {
            target,
            size: RelocationSize::U32,
        } if !elf.is_64() => target,
        _ => return Err(format!("unexpected relocation for the symbol: {symbol_relocation:?}")),
    };

    let Some(symbol) = elf
        .section_by_index(symbol_location.section_index)
        .data()
        .get(symbol_location.offset as usize..symbol_location.offset.saturating_add(u64::from(symbol_length)) as usize)
    else {
        return Err("symbol out of bounds".into());
    };

    let input_regs = b.read_byte()?;
    if input_regs as usize > Reg::INPUT_REGS.len() {
        return Err(format!("too many input registers: {input_regs}"));
    }

    let output_regs = b.read_byte()?;
    if output_regs as usize > Reg::OUTPUT_REGS.len() {
        return Err(format!("too many output registers: {output_regs}"));
    }

    let index = if version >= 2 {
        let has_index = b.read_byte()?;
        let index = b.read_u32()?;
        if has_index > 0 {
            Some(index)
        } else {
            None
        }
    } else {
        None
    };

    if flags != 0 {
        return Err(format!("found unsupported flags: 0x{flags:x}"));
    }

    Ok(ExternMetadata {
        index,
        symbol: symbol.to_owned(),
        input_regs,
        output_regs,
    })
}

fn parse_extern_metadata<H>(
    elf: &Elf<H>,
    relocations: &BTreeMap<SectionTarget, RelocationKind>,
    target: SectionTarget,
) -> Result<ExternMetadata, ProgramFromElfError>
where
    H: object::read::elf::FileHeader<Endian = object::LittleEndian>,
{
    parse_extern_metadata_impl(elf, relocations, target)
        .map_err(|error| ProgramFromElfError::other(format!("failed to parse extern metadata: {}", error)))
}

fn check_imports_and_assign_indexes(imports: &mut Vec<Import>, used_imports: &HashSet<usize>) -> Result<(), ProgramFromElfError> {
    let mut import_by_symbol: HashMap<Vec<u8>, usize> = HashMap::new();
    for (nth_import, import) in imports.iter().enumerate() {
        if let Some(&old_nth_import) = import_by_symbol.get(&import.metadata.symbol) {
            let old_import = &imports[old_nth_import];
            if import.metadata == old_import.metadata {
                continue;
            }

            return Err(ProgramFromElfError::other(format!(
                "duplicate imports with the same symbol yet different prototype: {}",
                ProgramSymbol::new(&*import.metadata.symbol)
            )));
        }

        import_by_symbol.insert(import.metadata.symbol.clone(), nth_import);
    }

    if imports.iter().any(|import| import.metadata.index.is_some()) {
        let mut import_by_index: HashMap<u32, ExternMetadata> = HashMap::new();
        let mut max_index = 0;
        for import in &*imports {
            if let Some(index) = import.index {
                if let Some(old_metadata) = import_by_index.get(&index) {
                    if *old_metadata != import.metadata {
                        return Err(ProgramFromElfError::other(format!(
                            "duplicate imports with the same index yet different prototypes: {}, {}",
                            ProgramSymbol::new(&*old_metadata.symbol),
                            ProgramSymbol::new(&*import.metadata.symbol)
                        )));
                    }
                } else {
                    import_by_index.insert(index, import.metadata.clone());
                }

                max_index = core::cmp::max(max_index, index);
            } else {
                return Err(ProgramFromElfError::other(format!(
                    "import without a specified index: {}",
                    ProgramSymbol::new(&*import.metadata.symbol)
                )));
            }
        }

        // If there are any holes in the indexes then insert dummy imports.
        for index in 0..max_index {
            if !import_by_index.contains_key(&index) {
                imports.push(Import {
                    metadata: ExternMetadata {
                        index: Some(index),
                        symbol: Vec::new(),
                        input_regs: 0,
                        output_regs: 0,
                    },
                })
            }
        }
    } else {
        let mut ordered: Vec<_> = used_imports.iter().copied().collect();
        ordered.sort_by(|&a, &b| imports[a].metadata.symbol.cmp(&imports[b].metadata.symbol));

        for (assigned_index, &nth_import) in ordered.iter().enumerate() {
            imports[nth_import].metadata.index = Some(assigned_index as u32);
        }
    }

    for import in imports {
        log::trace!("Import: {:?}", import.metadata);
    }

    Ok(())
}

fn get_relocation_target<H>(elf: &Elf<H>, relocation: &object::read::Relocation) -> Result<Option<SectionTarget>, ProgramFromElfError>
where
    H: object::read::elf::FileHeader<Endian = object::LittleEndian>,
{
    match relocation.target() {
        object::RelocationTarget::Absolute => {
            if let object::RelocationFlags::Elf { r_type } = relocation.flags() {
                if r_type == object::elf::R_RISCV_NONE {
                    // GNU ld apparently turns R_RISCV_ALIGN and R_RISCV_RELAX into these.
                    return Ok(None);
                }
            }
            // Example of such relocation:
            //   Offset     Info    Type                Sym. Value  Symbol's Name + Addend
            //   00060839  00000001 R_RISCV_32                        0
            //
            // So far I've only seen these emitted for `.debug_info`.
            //
            // I'm not entirely sure what's the point of those, as they don't point to any symbol
            // and have an addend of zero.
            assert_eq!(relocation.addend(), 0);
            assert!(!relocation.has_implicit_addend());
            Ok(None)
        }
        object::RelocationTarget::Symbol(target_symbol_index) => {
            let target_symbol = elf
                .symbol_by_index(target_symbol_index)
                .map_err(|error| ProgramFromElfError::other(format!("failed to fetch relocation target: {}", error)))?;

            let (section, offset) = target_symbol.section_and_offset()?;
            log::trace!(
                "Fetched relocation target: target section = \"{}\", target symbol = \"{}\" ({}), symbol offset = 0x{:x} + 0x{:x}",
                section.name(),
                target_symbol.name().unwrap_or(""),
                target_symbol_index.0,
                offset,
                relocation.addend(),
            );

            let Some(offset) = offset.checked_add_signed(relocation.addend()) else {
                return Err(ProgramFromElfError::other(
                    "failed to add addend to the symbol's offset due to overflow",
                ));
            };

            Ok(Some(SectionTarget {
                section_index: section.index(),
                offset,
            }))
        }
        _ => Err(ProgramFromElfError::other(format!(
            "unsupported target for relocation: {:?}",
            relocation
        ))),
    }
}

enum MinMax {
    MaxSigned,
    MinSigned,
    MaxUnsigned,
    MinUnsigned,

    MaxSigned64,
    MinSigned64,
    MaxUnsigned64,
    MinUnsigned64,
}

fn emit_minmax(
    kind: MinMax,
    dst: Reg,
    src1: Option<Reg>,
    src2: Option<Reg>,
    tmp: Reg,
    mut emit: impl FnMut(InstExt<SectionTarget, SectionTarget>),
) {
    // This is supposed to emit something like this:
    //   tmp = src1 ? src2
    //   dst = src1
    //   dst = src2 if tmp == 0

    assert_ne!(dst, tmp);
    assert_ne!(Some(tmp), src1);
    assert_ne!(Some(tmp), src2);
    assert_ne!(Some(dst), src2);

    let (cmp_src1, cmp_src2, cmp_kind) = match kind {
        MinMax::MinUnsigned => (src1, src2, AnyAnyKind::SetLessThanUnsigned),
        MinMax::MaxUnsigned => (src2, src1, AnyAnyKind::SetLessThanUnsigned),
        MinMax::MinSigned => (src1, src2, AnyAnyKind::SetLessThanSigned),
        MinMax::MaxSigned => (src2, src1, AnyAnyKind::SetLessThanSigned),

        MinMax::MinUnsigned64 => (src1, src2, AnyAnyKind::SetLessThanUnsigned64),
        MinMax::MaxUnsigned64 => (src2, src1, AnyAnyKind::SetLessThanUnsigned64),
        MinMax::MinSigned64 => (src1, src2, AnyAnyKind::SetLessThanSigned64),
        MinMax::MaxSigned64 => (src2, src1, AnyAnyKind::SetLessThanSigned64),
    };

    emit(InstExt::Basic(BasicInst::AnyAny {
        kind: cmp_kind,
        dst: tmp,
        src1: cmp_src1.map_or(RegImm::Imm(0), RegImm::Reg),
        src2: cmp_src2.map_or(RegImm::Imm(0), RegImm::Reg),
    }));

    if let Some(src1) = src1 {
        emit(InstExt::Basic(BasicInst::MoveReg { dst, src: src1 }));
    } else {
        emit(InstExt::Basic(BasicInst::LoadImmediate { dst: tmp, imm: 0 }));
    }

    emit(InstExt::Basic(BasicInst::Cmov {
        kind: CmovKind::EqZero,
        dst,
        src: src2.map_or(RegImm::Imm(0), RegImm::Reg),
        cond: tmp,
    }));
}

fn convert_instruction(
    section: &Section,
    current_location: SectionTarget,
    instruction: Inst,
    instruction_size: u64,
    rv64: bool,
    mut emit: impl FnMut(InstExt<SectionTarget, SectionTarget>),
) -> Result<(), ProgramFromElfError> {
    match instruction {
        Inst::LoadUpperImmediate { dst, value } => {
            let Some(dst) = cast_reg_non_zero(dst)? else {
                emit(InstExt::nop());
                return Ok(());
            };

            emit(InstExt::Basic(BasicInst::LoadImmediate { dst, imm: value as i32 }));
            Ok(())
        }
        Inst::JumpAndLink { dst, target } => {
            let target = SectionTarget {
                section_index: section.index(),
                offset: current_location.offset.wrapping_add_signed(i64::from(target as i32)),
            };

            if target.offset > section.size() {
                return Err(ProgramFromElfError::other("out of range JAL instruction"));
            }

            let next = if let Some(dst) = cast_reg_non_zero(dst)? {
                let target_return = current_location.add(instruction_size);
                ControlInst::Call {
                    ra: dst,
                    target,
                    target_return,
                }
            } else {
                ControlInst::Jump { target }
            };

            emit(InstExt::Control(next));
            Ok(())
        }
        Inst::Branch { kind, src1, src2, target } => {
            let src1 = cast_reg_any(src1)?;
            let src2 = cast_reg_any(src2)?;

            let target_true = SectionTarget {
                section_index: section.index(),
                offset: current_location.offset.wrapping_add_signed(i64::from(target as i32)),
            };

            if target_true.offset > section.size() {
                return Err(ProgramFromElfError::other("out of range unrelocated branch"));
            }

            let target_false = current_location.add(instruction_size);
            emit(InstExt::Control(ControlInst::Branch {
                kind,
                src1,
                src2,
                target_true,
                target_false,
            }));
            Ok(())
        }
        Inst::JumpAndLinkRegister { dst, base, value } => {
            let Some(base) = cast_reg_non_zero(base)? else {
                return Err(ProgramFromElfError::other("found an unrelocated JALR instruction"));
            };

            let next = if let Some(dst) = cast_reg_non_zero(dst)? {
                let target_return = current_location.add(instruction_size);
                ControlInst::CallIndirect {
                    ra: dst,
                    base,
                    offset: value.into(),
                    target_return,
                }
            } else {
                ControlInst::JumpIndirect {
                    base,
                    offset: value.into(),
                }
            };

            emit(InstExt::Control(next));
            Ok(())
        }
        Inst::Unimplemented => {
            emit(InstExt::Control(ControlInst::Unimplemented));
            Ok(())
        }
        Inst::FenceI | Inst::Fence { .. } => {
            emit(InstExt::Basic(BasicInst::Nop));
            Ok(())
        }
        Inst::Load { kind, dst, base, offset } => {
            let Some(base) = cast_reg_non_zero(base)? else {
                return Err(ProgramFromElfError::other("found an unrelocated absolute load"));
            };

            // LLVM riscv-enable-dead-defs pass may rewrite dst to the zero register.
            match cast_reg_non_zero(dst)? {
                Some(dst) => emit(InstExt::Basic(BasicInst::LoadIndirect { kind, dst, base, offset })),
                None => emit(InstExt::Basic(BasicInst::Nop)),
            }

            Ok(())
        }
        Inst::Store { kind, src, base, offset } => {
            let Some(base) = cast_reg_non_zero(base)? else {
                return Err(ProgramFromElfError::other("found an unrelocated absolute store"));
            };

            let src = cast_reg_any(src)?;
            emit(InstExt::Basic(BasicInst::StoreIndirect { kind, src, base, offset }));
            Ok(())
        }
        Inst::RegImm { kind, dst, src, imm } => {
            let Some(dst) = cast_reg_non_zero(dst)? else {
                emit(InstExt::nop());
                return Ok(());
            };

            let src = cast_reg_any(src)?;
            let kind = match kind {
                RegImmKind::Add => AnyAnyKind::Add,
                RegImmKind::Add64 => AnyAnyKind::Add64,
                RegImmKind::And => AnyAnyKind::And,
                RegImmKind::And64 => AnyAnyKind::And64,
                RegImmKind::Or => AnyAnyKind::Or,
                RegImmKind::Or64 => AnyAnyKind::Or64,
                RegImmKind::Xor => AnyAnyKind::Xor,
                RegImmKind::Xor64 => AnyAnyKind::Xor64,
                RegImmKind::SetLessThanUnsigned => AnyAnyKind::SetLessThanUnsigned,
                RegImmKind::SetLessThanUnsigned64 => AnyAnyKind::SetLessThanUnsigned64,
                RegImmKind::SetLessThanSigned => AnyAnyKind::SetLessThanSigned,
                RegImmKind::SetLessThanSigned64 => AnyAnyKind::SetLessThanSigned64,
                RegImmKind::ShiftLogicalLeft => AnyAnyKind::ShiftLogicalLeft,
                RegImmKind::ShiftLogicalLeft64 => AnyAnyKind::ShiftLogicalLeft64,
                RegImmKind::ShiftLogicalRight => AnyAnyKind::ShiftLogicalRight,
                RegImmKind::ShiftLogicalRight64 => AnyAnyKind::ShiftLogicalRight64,
                RegImmKind::ShiftArithmeticRight => AnyAnyKind::ShiftArithmeticRight,
                RegImmKind::ShiftArithmeticRight64 => AnyAnyKind::ShiftArithmeticRight64,
            };

            match src {
                RegImm::Imm(0) => {
                    // The optimizer can take care of this later, but doing it early here is more efficient.
                    emit(InstExt::Basic(BasicInst::LoadImmediate {
                        dst,
                        imm: OperationKind::from(kind)
                            .apply_const(0, i32_to_i64(imm))
                            .try_into()
                            .expect("load immediate overflow"),
                    }));
                }
                RegImm::Reg(src) if imm == 0 && ((!rv64 && kind == AnyAnyKind::Add) || (rv64 && kind == AnyAnyKind::Add64)) => {
                    emit(InstExt::Basic(BasicInst::MoveReg { dst, src }));
                }
                _ => {
                    emit(InstExt::Basic(BasicInst::AnyAny {
                        kind,
                        dst,
                        src1: src,
                        src2: (imm as u32).into(),
                    }));
                }
            }

            Ok(())
        }
        Inst::RegReg { kind, dst, src1, src2 } => {
            let Some(dst) = cast_reg_non_zero(dst)? else {
                emit(InstExt::nop());
                return Ok(());
            };

            macro_rules! anyany {
                ($kind:ident) => {
                    BasicInst::AnyAny {
                        kind: AnyAnyKind::$kind,
                        dst,
                        src1: cast_reg_any(src1)?,
                        src2: cast_reg_any(src2)?,
                    }
                };
            }

            macro_rules! regreg {
                ($kind:ident) => {
                    match (cast_reg_non_zero(src1)?, cast_reg_non_zero(src2)?) {
                        (Some(src1), Some(src2)) => BasicInst::RegReg {
                            kind: RegRegKind::$kind,
                            dst,
                            src1,
                            src2,
                        },
                        (lhs, rhs) => {
                            let lhs = lhs
                                .map(|reg| RegValue::InputReg(reg, BlockTarget::from_raw(0)))
                                .unwrap_or(RegValue::Constant(0));

                            let rhs = rhs
                                .map(|reg| RegValue::InputReg(reg, BlockTarget::from_raw(0)))
                                .unwrap_or(RegValue::Constant(0));

                            match OperationKind::from(RegRegKind::$kind).apply(lhs, rhs) {
                                Some(RegValue::Constant(imm)) => {
                                    let imm: i32 = imm.try_into().expect("immediate operand overflow");
                                    BasicInst::LoadImmediate { dst, imm }
                                }
                                _ => {
                                    return Err(ProgramFromElfError::other(format!(
                                        "found a {:?} instruction using a zero register",
                                        kind
                                    )))
                                }
                            }
                        }
                    }
                };
            }

            use crate::riscv::RegRegKind as K;
            let instruction = match kind {
                K::Add => anyany!(Add),
                K::Add64 => anyany!(Add64),
                K::Sub => anyany!(Sub),
                K::Sub64 => anyany!(Sub64),
                K::And => anyany!(And),
                K::And64 => anyany!(And64),
                K::Or => anyany!(Or),
                K::Or64 => anyany!(Or64),
                K::Xor => anyany!(Xor),
                K::Xor64 => anyany!(Xor64),
                K::SetLessThanUnsigned => anyany!(SetLessThanUnsigned),
                K::SetLessThanUnsigned64 => anyany!(SetLessThanUnsigned64),
                K::SetLessThanSigned => anyany!(SetLessThanSigned),
                K::SetLessThanSigned64 => anyany!(SetLessThanSigned64),
                K::ShiftLogicalLeft => anyany!(ShiftLogicalLeft),
                K::ShiftLogicalLeft64 => anyany!(ShiftLogicalLeft64),
                K::ShiftLogicalRight => anyany!(ShiftLogicalRight),
                K::ShiftLogicalRight64 => anyany!(ShiftLogicalRight64),
                K::ShiftArithmeticRight => anyany!(ShiftArithmeticRight),
                K::ShiftArithmeticRight64 => anyany!(ShiftArithmeticRight64),
                K::Mul => anyany!(Mul),
                K::Mul64 => anyany!(Mul64),
                K::MulUpperSignedSigned => anyany!(MulUpperSignedSigned),
                K::MulUpperSignedSigned64 => anyany!(MulUpperSignedSigned64),
                K::MulUpperUnsignedUnsigned => anyany!(MulUpperUnsignedUnsigned),
                K::MulUpperUnsignedUnsigned64 => anyany!(MulUpperUnsignedUnsigned64),

                K::MulUpperSignedUnsigned => regreg!(MulUpperSignedUnsigned),
                K::MulUpperSignedUnsigned64 => regreg!(MulUpperSignedUnsigned64),
                K::Div => regreg!(Div),
                K::Div64 => regreg!(Div64),
                K::DivUnsigned => regreg!(DivUnsigned),
                K::DivUnsigned64 => regreg!(DivUnsigned64),
                K::Rem => regreg!(Rem),
                K::Rem64 => regreg!(Rem64),
                K::RemUnsigned => regreg!(RemUnsigned),
                K::RemUnsigned64 => regreg!(RemUnsigned64),
            };

            emit(InstExt::Basic(instruction));
            Ok(())
        }
        Inst::AddUpperImmediateToPc { .. } => Err(ProgramFromElfError::other(format!(
            "found an unrelocated auipc instruction at offset {} in section '{}'; is the program compiled with relocations?",
            current_location.offset,
            section.name()
        ))),
        Inst::Ecall => Err(ProgramFromElfError::other(
            "found a bare ecall instruction; those are not supported",
        )),
        Inst::Cmov { kind, dst, src, cond, .. } => {
            let Some(dst) = cast_reg_non_zero(dst)? else {
                emit(InstExt::Basic(BasicInst::Nop));
                return Ok(());
            };

            let Some(cond) = cast_reg_non_zero(cond)? else {
                return Err(ProgramFromElfError::other(
                    "found a conditional move with a zero register as the condition",
                ));
            };

            emit(InstExt::Basic(BasicInst::Cmov {
                kind,
                dst,
                src: cast_reg_any(src)?,
                cond,
            }));
            Ok(())
        }
        Inst::LoadReserved { dst, src, .. } => {
            let Some(dst) = cast_reg_non_zero(dst)? else {
                return Err(ProgramFromElfError::other(
                    "found an atomic load with a zero register as the destination",
                ));
            };

            let Some(src) = cast_reg_non_zero(src)? else {
                return Err(ProgramFromElfError::other(
                    "found an atomic load with a zero register as the source",
                ));
            };

            emit(InstExt::Basic(BasicInst::LoadIndirect {
                kind: if rv64 { LoadKind::I32 } else { LoadKind::U32 },
                dst,
                base: src,
                offset: 0,
            }));

            Ok(())
        }
        Inst::LoadReserved64 { dst, src, .. } if rv64 => {
            let Some(dst) = cast_reg_non_zero(dst)? else {
                return Err(ProgramFromElfError::other(
                    "found an atomic load with a zero register as the destination",
                ));
            };

            let Some(src) = cast_reg_non_zero(src)? else {
                return Err(ProgramFromElfError::other(
                    "found an atomic load with a zero register as the source",
                ));
            };

            emit(InstExt::Basic(BasicInst::LoadIndirect {
                kind: LoadKind::U64,
                dst,
                base: src,
                offset: 0,
            }));

            Ok(())
        }
        Inst::StoreConditional { src, addr, dst, .. } => {
            let Some(addr) = cast_reg_non_zero(addr)? else {
                return Err(ProgramFromElfError::other(
                    "found an atomic store with a zero register as the address",
                ));
            };

            let src = cast_reg_any(src)?;
            emit(InstExt::Basic(BasicInst::StoreIndirect {
                kind: StoreKind::U32,
                src,
                base: addr,
                offset: 0,
            }));

            if let Some(dst) = cast_reg_non_zero(dst)? {
                // The store always succeeds, so write zero here.
                emit(InstExt::Basic(BasicInst::LoadImmediate { dst, imm: 0 }));
            }

            Ok(())
        }
        Inst::StoreConditional64 { src, addr, dst, .. } if rv64 => {
            let Some(addr) = cast_reg_non_zero(addr)? else {
                return Err(ProgramFromElfError::other(
                    "found an atomic store with a zero register as the address",
                ));
            };

            let src = cast_reg_any(src)?;
            emit(InstExt::Basic(BasicInst::StoreIndirect {
                kind: StoreKind::U64,
                src,
                base: addr,
                offset: 0,
            }));

            if let Some(dst) = cast_reg_non_zero(dst)? {
                // The store always succeeds, so write zero here.
                emit(InstExt::Basic(BasicInst::LoadImmediate { dst, imm: 0 }));
            }

            Ok(())
        }
        Inst::LoadReserved64 { .. } | Inst::StoreConditional64 { .. } => {
            Err(ProgramFromElfError::other("found a 64bit instruction in a 32bit binary"))
        }
        Inst::Atomic {
            kind,
            dst: old_value,
            addr,
            src: operand,
            ..
        } => {
            let Some(addr) = cast_reg_non_zero(addr)? else {
                return Err(ProgramFromElfError::other(
                    "found an atomic operation with a zero register as the address",
                ));
            };

            let operand = cast_reg_non_zero(operand)?;
            let operand_regimm = operand.map_or(RegImm::Imm(0), RegImm::Reg);
            let (old_value, new_value, output) = match cast_reg_non_zero(old_value)? {
                None => (Reg::E0, Reg::E0, None),
                Some(old_value) if old_value == addr => (Reg::E0, Reg::E1, Some(old_value)),
                Some(old_value) => (old_value, Reg::E0, None),
            };

            emit(InstExt::Basic(BasicInst::LoadIndirect {
                kind: LoadKind::U32,
                dst: old_value,
                base: addr,
                offset: 0,
            }));

            match kind {
                AtomicKind::Swap64 => {
                    emit(InstExt::Basic(BasicInst::AnyAny {
                        kind: AnyAnyKind::Add64,
                        dst: new_value,
                        src1: operand_regimm,
                        src2: RegImm::Imm(0),
                    }));
                }
                AtomicKind::Swap => {
                    emit(InstExt::Basic(BasicInst::AnyAny {
                        kind: AnyAnyKind::Add,
                        dst: new_value,
                        src1: operand_regimm,
                        src2: RegImm::Imm(0),
                    }));
                }
                AtomicKind::Add64 => {
                    emit(InstExt::Basic(BasicInst::AnyAny {
                        kind: AnyAnyKind::Add64,
                        dst: new_value,
                        src1: old_value.into(),
                        src2: operand_regimm,
                    }));
                }
                AtomicKind::Add => {
                    emit(InstExt::Basic(BasicInst::AnyAny {
                        kind: AnyAnyKind::Add,
                        dst: new_value,
                        src1: old_value.into(),
                        src2: operand_regimm,
                    }));
                }
                AtomicKind::And64 => {
                    emit(InstExt::Basic(BasicInst::AnyAny {
                        kind: AnyAnyKind::And64,
                        dst: new_value,
                        src1: old_value.into(),
                        src2: operand_regimm,
                    }));
                }
                AtomicKind::And => {
                    emit(InstExt::Basic(BasicInst::AnyAny {
                        kind: AnyAnyKind::And,
                        dst: new_value,
                        src1: old_value.into(),
                        src2: operand_regimm,
                    }));
                }
                AtomicKind::Or64 => {
                    emit(InstExt::Basic(BasicInst::AnyAny {
                        kind: AnyAnyKind::Or64,
                        dst: new_value,
                        src1: old_value.into(),
                        src2: operand_regimm,
                    }));
                }
                AtomicKind::Or => {
                    emit(InstExt::Basic(BasicInst::AnyAny {
                        kind: AnyAnyKind::Or,
                        dst: new_value,
                        src1: old_value.into(),
                        src2: operand_regimm,
                    }));
                }
                AtomicKind::Xor64 => {
                    emit(InstExt::Basic(BasicInst::AnyAny {
                        kind: AnyAnyKind::Xor64,
                        dst: new_value,
                        src1: old_value.into(),
                        src2: operand_regimm,
                    }));
                }
                AtomicKind::Xor => {
                    emit(InstExt::Basic(BasicInst::AnyAny {
                        kind: AnyAnyKind::Xor,
                        dst: new_value,
                        src1: old_value.into(),
                        src2: operand_regimm,
                    }));
                }
                AtomicKind::MaxSigned => {
                    emit_minmax(MinMax::MaxSigned, new_value, Some(old_value), operand, Reg::E2, &mut emit);
                }
                AtomicKind::MinSigned => {
                    emit_minmax(MinMax::MinSigned, new_value, Some(old_value), operand, Reg::E2, &mut emit);
                }
                AtomicKind::MaxUnsigned => {
                    emit_minmax(MinMax::MaxUnsigned, new_value, Some(old_value), operand, Reg::E2, &mut emit);
                }
                AtomicKind::MinUnsigned => {
                    emit_minmax(MinMax::MinUnsigned, new_value, Some(old_value), operand, Reg::E2, &mut emit);
                }

                AtomicKind::MaxSigned64 => {
                    emit_minmax(MinMax::MaxSigned64, new_value, Some(old_value), operand, Reg::E2, &mut emit);
                }
                AtomicKind::MinSigned64 => {
                    emit_minmax(MinMax::MinSigned64, new_value, Some(old_value), operand, Reg::E2, &mut emit);
                }
                AtomicKind::MaxUnsigned64 => {
                    emit_minmax(MinMax::MaxUnsigned64, new_value, Some(old_value), operand, Reg::E2, &mut emit);
                }
                AtomicKind::MinUnsigned64 => {
                    emit_minmax(MinMax::MinUnsigned64, new_value, Some(old_value), operand, Reg::E2, &mut emit);
                }
            }

            emit(InstExt::Basic(BasicInst::StoreIndirect {
                kind: StoreKind::U32,
                src: new_value.into(),
                base: addr,
                offset: 0,
            }));

            if let Some(output) = output {
                emit(InstExt::Basic(BasicInst::MoveReg {
                    dst: output,
                    src: old_value,
                }));
            }

            Ok(())
        }
    }
}

/// Read `n` bytes in `text` at `relative_offset` where `n` is
/// the length of the instruction at `relative_offset`.
///
/// # Panics
/// - Valid RISC-V instructions can be 2 or 4 bytes. Misaligned
///   `relative_offset` are considered an internal error.
/// - `relative_offset` is expected to be inbounds.
///
/// # Returns
/// The instruction length and the raw instruction.
fn read_instruction_bytes(text: &[u8], relative_offset: usize) -> (u64, u32) {
    assert!(
        relative_offset % VM_CODE_ADDRESS_ALIGNMENT as usize == 0,
        "internal error: misaligned instruction read: 0x{relative_offset:08x}"
    );

    if Inst::is_compressed(text[relative_offset]) {
        (2, u32::from(u16::from_le_bytes([text[relative_offset], text[relative_offset + 1]])))
    } else {
        (
            4,
            u32::from_le_bytes([
                text[relative_offset],
                text[relative_offset + 1],
                text[relative_offset + 2],
                text[relative_offset + 3],
            ]),
        )
    }
}

fn parse_code_section<H>(
    elf: &Elf<H>,
    section: &Section,
    decoder_config: &DecoderConfig,
    relocations: &BTreeMap<SectionTarget, RelocationKind>,
    imports: &mut Vec<Import>,
    instruction_overrides: &mut HashMap<SectionTarget, InstExt<SectionTarget, SectionTarget>>,
    output: &mut Vec<(Source, InstExt<SectionTarget, SectionTarget>)>,
) -> Result<(), ProgramFromElfError>
where
    H: object::read::elf::FileHeader<Endian = object::LittleEndian>,
{
    let section_index = section.index();
    let section_name = section.name();
    let text = &section.data();

    if text.len() % VM_CODE_ADDRESS_ALIGNMENT as usize != 0 {
        return Err(ProgramFromElfError::other(format!(
            "size of section '{section_name}' is not divisible by 2"
        )));
    }

    output.reserve(text.len() / 4);
    let mut relative_offset = 0;
    while relative_offset < text.len() {
        let current_location = SectionTarget {
            section_index: section.index(),
            offset: relative_offset.try_into().expect("overflow"),
        };

        let (inst_size, raw_inst) = read_instruction_bytes(text, relative_offset);

        const FUNC3_ECALLI: u32 = 0b000;
        const FUNC3_SBRK: u32 = 0b001;

        if crate::riscv::R(raw_inst).unpack() == (crate::riscv::OPCODE_CUSTOM_0, FUNC3_ECALLI, 0, RReg::Zero, RReg::Zero, RReg::Zero) {
            let initial_offset = relative_offset as u64;
            let pointer_size = if elf.is_64() { 8 } else { 4 };

            // `ret` can be 2 bytes long, so (on 32-bit): 4 (ecalli) + 4 (pointer) + 2 (ret) = 10
            if relative_offset + pointer_size + 6 > text.len() {
                return Err(ProgramFromElfError::other("truncated ecalli instruction"));
            }

            let target_location = current_location.add(4);
            relative_offset += 4 + pointer_size;

            let Some(relocation) = relocations.get(&target_location) else {
                return Err(ProgramFromElfError::other(format!(
                    "found an external call without a relocation for a pointer to metadata at {current_location}"
                )));
            };

            let metadata_location = match relocation {
                RelocationKind::Abs {
                    target,
                    size: RelocationSize::U64,
                } if elf.is_64() => target,
                RelocationKind::Abs {
                    target,
                    size: RelocationSize::U32,
                } if !elf.is_64() => target,
                _ => {
                    return Err(ProgramFromElfError::other(format!(
                        "found an external call with an unexpected relocation at {current_location}: {relocation:?}"
                    )));
                }
            };

            let metadata = parse_extern_metadata(elf, relocations, *metadata_location)?;
            let nth_import = imports.len();
            imports.push(Import { metadata });

            output.push((
                Source {
                    section_index,
                    offset_range: AddressRange::from(initial_offset..relative_offset as u64),
                },
                InstExt::Basic(BasicInst::Ecalli { nth_import }),
            ));

            const INST_RET: Inst = Inst::JumpAndLinkRegister {
                dst: RReg::Zero,
                base: RReg::RA,
                value: 0,
            };

            let (next_inst_size, next_raw_inst) = read_instruction_bytes(text, relative_offset);

            if Inst::decode(decoder_config, next_raw_inst) != Some(INST_RET) {
                return Err(ProgramFromElfError::other("external call shim doesn't end with a 'ret'"));
            }

            output.push((
                Source {
                    section_index,
                    offset_range: AddressRange::from(relative_offset as u64..relative_offset as u64 + next_inst_size),
                },
                InstExt::Control(ControlInst::JumpIndirect { base: Reg::RA, offset: 0 }),
            ));

            relative_offset += next_inst_size as usize;
            continue;
        }

        if let (crate::riscv::OPCODE_CUSTOM_0, FUNC3_SBRK, 0, dst, size, RReg::Zero) = crate::riscv::R(raw_inst).unpack() {
            let Some(dst) = cast_reg_non_zero(dst)? else {
                return Err(ProgramFromElfError::other(
                    "found an 'sbrk' instruction with the zero register as the destination",
                ));
            };

            let Some(size) = cast_reg_non_zero(size)? else {
                return Err(ProgramFromElfError::other(
                    "found an 'sbrk' instruction with the zero register as the size",
                ));
            };

            output.push((
                Source {
                    section_index,
                    offset_range: (relative_offset as u64..relative_offset as u64 + inst_size).into(),
                },
                InstExt::Basic(BasicInst::Sbrk { dst, size }),
            ));

            relative_offset += inst_size as usize;
            continue;
        }

        let source = Source {
            section_index,
            offset_range: AddressRange::from(relative_offset as u64..relative_offset as u64 + inst_size),
        };

        relative_offset += inst_size as usize;

        let Some(original_inst) = Inst::decode(decoder_config, raw_inst) else {
            return Err(ProgramFromElfErrorKind::UnsupportedInstruction {
                section: section.name().into(),
                offset: current_location.offset,
                instruction: raw_inst,
            }
            .into());
        };

        if let Some(inst) = instruction_overrides.remove(&current_location) {
            output.push((source, inst));
        } else {
            // For some reason (compiler bug?) *very rarely* we have those AUIPC instructions
            // without any relocation attached to them, so let's deal with them traditionally.
            if let Inst::AddUpperImmediateToPc {
                dst: base_upper,
                value: value_upper,
            } = original_inst
            {
                if relative_offset < text.len() {
                    let (next_inst_size, next_inst) = read_instruction_bytes(text, relative_offset);
                    let next_inst = Inst::decode(decoder_config, next_inst);

                    if let Some(Inst::JumpAndLinkRegister { dst: ra_dst, base, value }) = next_inst {
                        if base == ra_dst && base == base_upper {
                            if let Some(ra) = cast_reg_non_zero(ra_dst)? {
                                let offset = (relative_offset as i32 - next_inst_size as i32)
                                    .wrapping_add(value)
                                    .wrapping_add(value_upper as i32);
                                if offset >= 0 && offset < section.data().len() as i32 {
                                    output.push((
                                        source,
                                        InstExt::Control(ControlInst::Call {
                                            ra,
                                            target: SectionTarget {
                                                section_index,
                                                offset: u64::from(offset as u32),
                                            },
                                            target_return: current_location.add(inst_size + next_inst_size),
                                        }),
                                    ));

                                    relative_offset += inst_size as usize;
                                    continue;
                                }
                            }
                        }
                    }
                }
            }

            let original_length = output.len();
            convert_instruction(section, current_location, original_inst, inst_size, elf.is_64(), |inst| {
                output.push((source, inst));
            })?;

            // We need to always emit at least one instruction (even if it's a NOP) to handle potential jumps.
            assert_ne!(
                output.len(),
                original_length,
                "internal error: no instructions were emitted for instruction {original_inst:?} in section {section_name}"
            );
        }
    }

    Ok(())
}

fn split_code_into_basic_blocks<H>(
    elf: &Elf<H>,
    jump_targets: &HashSet<SectionTarget>,
    instructions: Vec<(Source, InstExt<SectionTarget, SectionTarget>)>,
) -> Result<Vec<BasicBlock<SectionTarget, SectionTarget>>, ProgramFromElfError>
where
    H: object::read::elf::FileHeader<Endian = object::LittleEndian>,
{
    #[cfg(test)]
    let _ = elf;

    let mut blocks: Vec<BasicBlock<SectionTarget, SectionTarget>> = Vec::new();
    let mut current_block: Vec<(SourceStack, BasicInst<SectionTarget>)> = Vec::new();
    let mut block_start_opt = None;
    let mut last_source_in_block = None;
    for (source, op) in instructions {
        // TODO: This panics because we use a dummy ELF in tests; fix it.
        #[cfg(not(test))]
        log::trace!(
            "Instruction at {source} (0x{:x}): {op:?}",
            elf.section_by_index(source.section_index).original_address() + source.offset_range.start
        );

        if let Some(last_source_in_block) = last_source_in_block {
            // Handle the case where we've emitted multiple instructions from a single RISC-V instruction.
            if source == last_source_in_block {
                let InstExt::Basic(instruction) = op else { unreachable!() };
                current_block.push((source.into(), instruction));
                continue;
            }
        }

        assert!(source.offset_range.start < source.offset_range.end);

        let is_jump_target = jump_targets.contains(&source.begin());
        let (block_section, block_start) = if !is_jump_target {
            // Make sure nothing wants to jump into the middle of this instruction.
            assert!((source.offset_range.start..source.offset_range.end)
                .step_by(2)
                .skip(1)
                .all(|offset| !jump_targets.contains(&SectionTarget {
                    section_index: source.section_index,
                    offset
                })));

            if let Some((block_section, block_start)) = block_start_opt {
                // We're in a block that's reachable by a jump.
                (block_section, block_start)
            } else {
                // Nothing can possibly jump here, so just skip this instruction.
                log::trace!("Skipping dead instruction at {}: {:?}", source.begin(), op);
                continue;
            }
        } else {
            // Control flow can jump to this instruction.
            if let Some((block_section, block_start)) = block_start_opt.take() {
                // End the current basic block to prevent a jump into the middle of it.
                if !current_block.is_empty() {
                    let block_index = BlockTarget::from_raw(blocks.len());
                    let block_source = Source {
                        section_index: block_section,
                        offset_range: (block_start..source.offset_range.start).into(),
                    };

                    let last_instruction_source = current_block.last().unwrap().0.as_slice()[0];
                    assert_eq!(last_instruction_source.section_index, block_section);

                    let end_of_block_source = Source {
                        section_index: block_section,
                        offset_range: (last_instruction_source.offset_range.start..source.offset_range.start).into(),
                    };

                    assert!(block_source.offset_range.start < block_source.offset_range.end);
                    assert!(end_of_block_source.offset_range.start < end_of_block_source.offset_range.end);

                    log::trace!("Emitting block (due to a potential jump): {}", block_source.begin());
                    blocks.push(BasicBlock::new(
                        block_index,
                        block_source,
                        core::mem::take(&mut current_block),
                        EndOfBlock {
                            source: end_of_block_source.into(),
                            instruction: ControlInst::Jump { target: source.begin() },
                        },
                    ));
                }
            }

            block_start_opt = Some((source.section_index, source.offset_range.start));
            (source.section_index, source.offset_range.start)
        };

        match op {
            InstExt::Control(instruction) => {
                last_source_in_block = None;
                block_start_opt = None;

                let block_index = BlockTarget::from_raw(blocks.len());
                let block_source = Source {
                    section_index: block_section,
                    offset_range: (block_start..source.offset_range.end).into(),
                };

                log::trace!("Emitting block (due to a control instruction): {}", block_source.begin());
                blocks.push(BasicBlock::new(
                    block_index,
                    block_source,
                    core::mem::take(&mut current_block),
                    EndOfBlock {
                        source: source.into(),
                        instruction,
                    },
                ));

                if let ControlInst::Branch { target_false, .. } = instruction {
                    if !cfg!(test) {
                        if source.section_index != target_false.section_index {
                            return Err(ProgramFromElfError::other("found a branch with a fallthrough to another section"));
                        }
                        assert_eq!(source.offset_range.end, target_false.offset);
                    }
                    block_start_opt = Some((block_section, source.offset_range.end));
                }
            }
            InstExt::Basic(instruction) => {
                last_source_in_block = Some(source);
                current_block.push((source.into(), instruction));
            }
        }
    }

    if !current_block.is_empty() {
        return Err(ProgramFromElfError::other(
            "code doesn't end with a control-flow affecting instruction",
        ));
    }

    Ok(blocks)
}

fn build_section_to_block_map(
    blocks: &[BasicBlock<SectionTarget, SectionTarget>],
) -> Result<HashMap<SectionTarget, BlockTarget>, ProgramFromElfError> {
    let mut section_to_block = HashMap::new();
    for (block_index, block) in blocks.iter().enumerate() {
        let section_target = block.source.begin();
        let block_target = BlockTarget::from_raw(block_index);
        if section_to_block.insert(section_target, block_target).is_some() {
            return Err(ProgramFromElfError::other("found two or more basic blocks with the same location"));
        }
    }

    Ok(section_to_block)
}

fn resolve_basic_block_references(
    data_sections_set: &HashSet<SectionIndex>,
    section_to_block: &HashMap<SectionTarget, BlockTarget>,
    blocks: &[BasicBlock<SectionTarget, SectionTarget>],
) -> Result<Vec<BasicBlock<AnyTarget, BlockTarget>>, ProgramFromElfError> {
    let mut output = Vec::with_capacity(blocks.len());
    for block in blocks {
        let mut ops = Vec::with_capacity(block.ops.len());
        for (source, op) in &block.ops {
            let map = |target: SectionTarget| {
                if data_sections_set.contains(&target.section_index) {
                    Ok(AnyTarget::Data(target))
                } else if let Some(&target) = section_to_block.get(&target) {
                    Ok(AnyTarget::Code(target))
                } else {
                    return Err(ProgramFromElfError::other(format!(
                        "found basic instruction which doesn't point to a data section nor resolve to any basic block: {source:?}, {op:?}",
                    )));
                }
            };

            let op = op.map_target(map)?;
            ops.push((source.clone(), op));
        }

        let Ok(next) = block
            .next
            .clone()
            .map_target(|section_target| section_to_block.get(&section_target).copied().ok_or(()))
        else {
            return Err(ProgramFromElfError::other(format!(
                "found control instruction at the end of block at {block_source} whose target doesn't resolve to any basic block: {next:?}",
                block_source = block.source,
                next = block.next.instruction,
            )));
        };

        output.push(BasicBlock::new(block.target, block.source, ops, next));
    }

    Ok(output)
}

fn garbage_collect_reachability(all_blocks: &[BasicBlock<AnyTarget, BlockTarget>], reachability_graph: &mut ReachabilityGraph) -> bool {
    let mut queue_code = VecSet::new();
    let mut queue_data = VecSet::new();
    for (block_target, reachability) in &reachability_graph.for_code {
        if reachability.always_reachable_or_exported() {
            queue_code.push(*block_target);
        }
    }

    for (data_target, reachability) in &reachability_graph.for_data {
        if reachability.always_reachable_or_exported() {
            queue_data.push(*data_target);
        }
    }

    while !queue_code.is_empty() || !queue_data.is_empty() {
        while let Some(block_target) = queue_code.pop_unique() {
            each_reference(&all_blocks[block_target.index()], |ext| match ext {
                ExtRef::Jump(target) | ExtRef::Address(target) => queue_code.push(target),
                ExtRef::DataAddress(target) => queue_data.push(target),
            });
        }

        while let Some(data_target) = queue_data.pop_unique() {
            if let Some(list) = reachability_graph.code_references_in_data_section.get(&data_target) {
                for &target in list {
                    queue_code.push(target);
                }
            }

            if let Some(list) = reachability_graph.data_references_in_data_section.get(&data_target) {
                for &target in list {
                    queue_data.push(target);
                }
            }
        }
    }

    let set_code = queue_code.into_set();
    let set_data = queue_data.into_set();
    if set_code.len() == reachability_graph.for_code.len() && set_data.len() == reachability_graph.for_data.len() {
        return false;
    }

    log::debug!(
        "Code reachability garbage collection: {} -> {}",
        reachability_graph.for_code.len(),
        set_code.len()
    );
    reachability_graph.for_code.retain(|block_target, reachability| {
        reachability.reachable_from.retain(|inner_key| set_code.contains(inner_key));
        reachability.address_taken_in.retain(|inner_key| set_code.contains(inner_key));
        reachability.referenced_by_data.retain(|inner_key| set_data.contains(inner_key));
        if !set_code.contains(block_target) {
            assert!(!reachability.always_reachable);
            log::trace!("  Garbage collected: {block_target:?}");
            false
        } else {
            true
        }
    });

    assert_eq!(reachability_graph.for_code.len(), set_code.len());

    log::debug!(
        "Data reachability garbage collection: {} -> {}",
        reachability_graph.for_data.len(),
        set_data.len()
    );
    reachability_graph.for_data.retain(|data_target, reachability| {
        assert!(reachability.reachable_from.is_empty());
        reachability.address_taken_in.retain(|inner_key| set_code.contains(inner_key));
        reachability.referenced_by_data.retain(|inner_key| set_data.contains(inner_key));
        if !set_data.contains(data_target) {
            assert!(!reachability.always_reachable);
            log::trace!("  Garbage collected: {data_target:?}");
            false
        } else {
            true
        }
    });

    reachability_graph.code_references_in_data_section.retain(|data_target, list| {
        if !set_data.contains(data_target) {
            false
        } else {
            assert!(list.iter().all(|block_target| set_code.contains(block_target)));
            true
        }
    });

    reachability_graph.data_references_in_data_section.retain(|data_target, list| {
        if !set_data.contains(data_target) {
            false
        } else {
            assert!(list.iter().all(|next_data_target| set_data.contains(next_data_target)));
            true
        }
    });

    assert_eq!(reachability_graph.for_data.len(), set_data.len());
    true
}

fn remove_unreachable_code_impl(
    all_blocks: &[BasicBlock<AnyTarget, BlockTarget>],
    reachability_graph: &mut ReachabilityGraph,
    mut optimize_queue: Option<&mut VecSet<BlockTarget>>,
    queue_code: &mut VecSet<BlockTarget>,
    queue_data: &mut VecSet<SectionIndex>,
    current: BlockTarget,
) {
    assert!(reachability_graph.for_code.get(&current).unwrap().is_unreachable());
    log::trace!("Removing {current:?} from the graph...");

    each_reference(&all_blocks[current.index()], |ext| match ext {
        ExtRef::Jump(target) => {
            log::trace!("{target:?} is not reachable from {current:?} anymore");
            let reachability = reachability_graph.for_code.get_mut(&target).unwrap();
            reachability.reachable_from.remove(&current);
            if reachability.is_unreachable() {
                log::trace!("{target:?} is now unreachable!");
                queue_code.push(target)
            } else if let Some(ref mut optimize_queue) = optimize_queue {
                optimize_queue.push(target);
            }
        }
        ExtRef::Address(target) => {
            log::trace!("{target:?}'s address is not taken in {current:?} anymore");
            let reachability = reachability_graph.for_code.get_mut(&target).unwrap();
            reachability.address_taken_in.remove(&current);
            if reachability.is_unreachable() {
                log::trace!("{target:?} is now unreachable!");
                queue_code.push(target)
            } else if let Some(ref mut optimize_queue) = optimize_queue {
                optimize_queue.push(target);
            }
        }
        ExtRef::DataAddress(target) => {
            log::trace!("{target:?}'s address is not taken in {current:?} anymore");
            let reachability = reachability_graph.for_data.get_mut(&target).unwrap();
            reachability.address_taken_in.remove(&current);
            if reachability.is_unreachable() {
                log::trace!("{target:?} is now unreachable!");
                queue_data.push(target);
            }
        }
    });

    reachability_graph.for_code.remove(&current);
}

fn remove_unreachable_data_impl(
    reachability_graph: &mut ReachabilityGraph,
    mut optimize_queue: Option<&mut VecSet<BlockTarget>>,
    queue_code: &mut VecSet<BlockTarget>,
    queue_data: &mut VecSet<SectionIndex>,
    current: SectionIndex,
) {
    assert!(reachability_graph.for_data.get(&current).unwrap().is_unreachable());
    log::trace!("Removing {current:?} from the graph...");

    let code_refs = reachability_graph.code_references_in_data_section.remove(&current);
    let data_refs = reachability_graph.data_references_in_data_section.remove(&current);

    if let Some(list) = code_refs {
        for target in list {
            log::trace!("{target:?} is not reachable from {current:?} anymore");
            let reachability = reachability_graph.for_code.get_mut(&target).unwrap();
            reachability.referenced_by_data.remove(&current);
            if reachability.is_unreachable() {
                log::trace!("{target:?} is now unreachable!");
                queue_code.push(target)
            } else if let Some(ref mut optimize_queue) = optimize_queue {
                optimize_queue.push(target);
            }
        }
    }

    if let Some(list) = data_refs {
        for target in list {
            log::trace!("{target:?} is not reachable from {current:?} anymore");
            let reachability = reachability_graph.for_data.get_mut(&target).unwrap();
            reachability.referenced_by_data.remove(&current);
            if reachability.is_unreachable() {
                log::trace!("{target:?} is now unreachable!");
                queue_data.push(target)
            }
        }
    }

    reachability_graph.for_data.remove(&current);
}

fn remove_code_if_globally_unreachable(
    all_blocks: &[BasicBlock<AnyTarget, BlockTarget>],
    reachability_graph: &mut ReachabilityGraph,
    mut optimize_queue: Option<&mut VecSet<BlockTarget>>,
    block_target: BlockTarget,
) {
    let Some(reachability) = reachability_graph.for_code.get(&block_target) else {
        return;
    };
    if !reachability.is_unreachable() {
        return;
    }

    // The inner block is now globally unreachable.
    let mut queue_code = VecSet::new();
    let mut queue_data = VecSet::new();
    remove_unreachable_code_impl(
        all_blocks,
        reachability_graph,
        optimize_queue.as_deref_mut(),
        &mut queue_code,
        &mut queue_data,
        block_target,
    );

    // If there are other dependencies which are now unreachable then remove them too.
    while !queue_code.is_empty() || !queue_data.is_empty() {
        while let Some(next) = queue_code.pop_unique() {
            remove_unreachable_code_impl(
                all_blocks,
                reachability_graph,
                optimize_queue.as_deref_mut(),
                &mut queue_code,
                &mut queue_data,
                next,
            );
        }

        while let Some(next) = queue_data.pop_unique() {
            remove_unreachable_data_impl(
                reachability_graph,
                optimize_queue.as_deref_mut(),
                &mut queue_code,
                &mut queue_data,
                next,
            );
        }
    }
}

fn remove_if_data_is_globally_unreachable(
    all_blocks: &[BasicBlock<AnyTarget, BlockTarget>],
    reachability_graph: &mut ReachabilityGraph,
    mut optimize_queue: Option<&mut VecSet<BlockTarget>>,
    data_target: SectionIndex,
) {
    let Some(reachability) = reachability_graph.for_data.get(&data_target) else {
        return;
    };
    if !reachability.is_unreachable() {
        return;
    }

    let mut queue_code = VecSet::new();
    let mut queue_data = VecSet::new();
    remove_unreachable_data_impl(
        reachability_graph,
        optimize_queue.as_deref_mut(),
        &mut queue_code,
        &mut queue_data,
        data_target,
    );

    // If there are other dependencies which are now unreachable then remove them too.
    while !queue_code.is_empty() || !queue_data.is_empty() {
        while let Some(next) = queue_code.pop_unique() {
            remove_unreachable_code_impl(
                all_blocks,
                reachability_graph,
                optimize_queue.as_deref_mut(),
                &mut queue_code,
                &mut queue_data,
                next,
            );
        }

        while let Some(next) = queue_data.pop_unique() {
            remove_unreachable_data_impl(
                reachability_graph,
                optimize_queue.as_deref_mut(),
                &mut queue_code,
                &mut queue_data,
                next,
            );
        }
    }
}

fn add_to_optimize_queue(
    all_blocks: &[BasicBlock<AnyTarget, BlockTarget>],
    reachability_graph: &ReachabilityGraph,
    optimize_queue: &mut VecSet<BlockTarget>,
    block_target: BlockTarget,
) {
    let Some(reachability) = reachability_graph.for_code.get(&block_target) else {
        return;
    };
    if reachability.is_unreachable() {
        return;
    }

    optimize_queue.push(block_target);

    for &previous in &reachability.reachable_from {
        optimize_queue.push(previous);
    }

    for &previous in &reachability.address_taken_in {
        optimize_queue.push(previous);
    }

    for &next in all_blocks[block_target.index()].next.instruction.targets().into_iter().flatten() {
        optimize_queue.push(next);
    }

    each_reference(&all_blocks[block_target.index()], |ext| match ext {
        ExtRef::Jump(target) => optimize_queue.push(target),
        ExtRef::Address(target) => optimize_queue.push(target),
        ExtRef::DataAddress(..) => {}
    });
}

fn perform_nop_elimination(all_blocks: &mut [BasicBlock<AnyTarget, BlockTarget>], current: BlockTarget) {
    all_blocks[current.index()].ops.retain(|(_, instruction)| !instruction.is_nop());
}

fn perform_inlining(
    all_blocks: &mut [BasicBlock<AnyTarget, BlockTarget>],
    reachability_graph: &mut ReachabilityGraph,
    exports: &mut [Export],
    optimize_queue: Option<&mut VecSet<BlockTarget>>,
    inline_history: &mut HashSet<(BlockTarget, BlockTarget)>,
    inline_threshold: usize,
    current: BlockTarget,
) -> bool {
    fn is_infinite_loop(all_blocks: &[BasicBlock<AnyTarget, BlockTarget>], current: BlockTarget) -> bool {
        all_blocks[current.index()].next.instruction == ControlInst::Jump { target: current }
    }

    fn inline(
        all_blocks: &mut [BasicBlock<AnyTarget, BlockTarget>],
        reachability_graph: &mut ReachabilityGraph,
        mut optimize_queue: Option<&mut VecSet<BlockTarget>>,
        outer: BlockTarget,
        inner: BlockTarget,
    ) {
        log::trace!("Inlining {inner:?} into {outer:?}...");
        log::trace!("  {outer:?} will now end with: {:?}", all_blocks[inner.index()].next.instruction);

        if let Some(ref mut optimize_queue) = optimize_queue {
            add_to_optimize_queue(all_blocks, reachability_graph, optimize_queue, outer);
            add_to_optimize_queue(all_blocks, reachability_graph, optimize_queue, inner);
        }

        // Inlining into ourselves doesn't make sense.
        assert_ne!(outer, inner);

        // No infinite loops.
        assert!(!is_infinite_loop(all_blocks, inner));

        // Make sure this block actually goes to the block we're inlining.
        assert_eq!(all_blocks[outer.index()].next.instruction, ControlInst::Jump { target: inner });

        // The inner block is not reachable from here anymore.
        // NOTE: This needs to be done *before* adding the references below,
        //       as the inner block might be an infinite loop.
        reachability_graph.for_code.get_mut(&inner).unwrap().reachable_from.remove(&outer);

        // Everything which the inner block accesses will be reachable from here, so update reachability.
        each_reference(&all_blocks[inner.index()], |ext| match ext {
            ExtRef::Jump(target) => {
                reachability_graph.for_code.entry(target).or_default().reachable_from.insert(outer);
            }
            ExtRef::Address(target) => {
                reachability_graph
                    .for_code
                    .entry(target)
                    .or_default()
                    .address_taken_in
                    .insert(outer);
            }
            ExtRef::DataAddress(target) => {
                reachability_graph
                    .for_data
                    .entry(target)
                    .or_default()
                    .address_taken_in
                    .insert(outer);
            }
        });

        // Remove it from the graph if it's globally unreachable now.
        remove_code_if_globally_unreachable(all_blocks, reachability_graph, optimize_queue, inner);

        let outer_source = all_blocks[outer.index()].next.source.clone();
        let inner_source = all_blocks[inner.index()].next.source.clone();
        let inner_code: Vec<_> = all_blocks[inner.index()]
            .ops
            .iter()
            .map(|(inner_source, op)| (outer_source.overlay_on_top_of(inner_source), *op))
            .collect();

        all_blocks[outer.index()].ops.extend(inner_code);
        all_blocks[outer.index()].next.source.overlay_on_top_of_inplace(&inner_source);
        all_blocks[outer.index()].next.instruction = all_blocks[inner.index()].next.instruction;
    }

    fn should_inline(
        all_blocks: &[BasicBlock<AnyTarget, BlockTarget>],
        reachability_graph: &ReachabilityGraph,
        current: BlockTarget,
        target: BlockTarget,
        inline_threshold: usize,
    ) -> bool {
        // Don't inline if it's an infinite loop.
        if target == current || is_infinite_loop(all_blocks, target) {
            return false;
        }

        if let Some(fallthrough_target) = all_blocks[target.index()].next.instruction.fallthrough_target() {
            if fallthrough_target.index() == target.index() + 1 {
                // Do not inline if we'd need to inject a new fallthrough basic block.
                return false;
            }
        }

        // Inline if the target block is small enough.
        if all_blocks[target.index()].ops.len() <= inline_threshold {
            return true;
        }

        // Inline if the target block is only reachable from here.
        if let Some(reachability) = reachability_graph.for_code.get(&target) {
            if reachability.is_only_reachable_from(current) {
                return true;
            }
        }

        false
    }

    if !reachability_graph.is_code_reachable(current) {
        return false;
    }

    let block = &all_blocks[current.index()];
    match block.next.instruction {
        ControlInst::Jump { target } => {
            if all_blocks[current.index()].ops.is_empty() && inline_history.insert((current, target)) {
                let reachability = reachability_graph.for_code.get_mut(&current).unwrap();
                if !reachability.exports.is_empty() {
                    let export_indexes = core::mem::take(&mut reachability.exports);
                    for &export_index in &export_indexes {
                        exports[export_index].location = all_blocks[target.index()].source.begin();
                    }
                    reachability_graph.for_code.get_mut(&target).unwrap().exports.extend(export_indexes);
                    remove_code_if_globally_unreachable(all_blocks, reachability_graph, optimize_queue, current);
                    return true;
                }
            }

            if should_inline(all_blocks, reachability_graph, current, target, inline_threshold) && inline_history.insert((current, target))
            {
                inline(all_blocks, reachability_graph, optimize_queue, current, target);
                return true;
            }
        }
        ControlInst::Branch {
            kind,
            src1,
            src2,
            target_true,
            target_false,
        } => {
            if let ControlInst::Jump { target } = all_blocks[target_true.index()].next.instruction {
                if target != target_true && all_blocks[target_true.index()].ops.is_empty() {
                    // We're branching to another block which immediately jumps somewhere else.
                    // So skip the middle-man and just jump where we want to go directly.
                    assert!(reachability_graph
                        .for_code
                        .get_mut(&target_true)
                        .unwrap()
                        .reachable_from
                        .remove(&current));

                    reachability_graph.for_code.get_mut(&target).unwrap().reachable_from.insert(current);
                    all_blocks[current.index()].next.instruction = ControlInst::Branch {
                        kind,
                        src1,
                        src2,
                        target_true: target,
                        target_false,
                    };

                    remove_code_if_globally_unreachable(all_blocks, reachability_graph, optimize_queue, target_true);
                    return true;
                }
            }
        }
        ControlInst::Call { .. } => unreachable!(),
        _ => {}
    }

    false
}

fn gather_references(block: &BasicBlock<AnyTarget, BlockTarget>) -> BTreeSet<ExtRef> {
    let mut references = BTreeSet::new();
    each_reference(block, |ext| {
        references.insert(ext);
    });
    references
}

fn update_references(
    all_blocks: &[BasicBlock<AnyTarget, BlockTarget>],
    reachability_graph: &mut ReachabilityGraph,
    mut optimize_queue: Option<&mut VecSet<BlockTarget>>,
    block_target: BlockTarget,
    mut old_references: BTreeSet<ExtRef>,
) {
    let mut new_references = gather_references(&all_blocks[block_target.index()]);
    new_references.retain(|ext| !old_references.remove(ext));

    for ext in &old_references {
        match ext {
            ExtRef::Jump(target) => {
                log::trace!("{target:?} is not reachable from {block_target:?} anymore");
                reachability_graph
                    .for_code
                    .get_mut(target)
                    .unwrap()
                    .reachable_from
                    .remove(&block_target);
            }
            ExtRef::Address(target) => {
                log::trace!("{target:?}'s address is not taken in {block_target:?} anymore");
                reachability_graph
                    .for_code
                    .get_mut(target)
                    .unwrap()
                    .address_taken_in
                    .remove(&block_target);
            }
            ExtRef::DataAddress(target) => {
                log::trace!("{target:?}'s address is not taken in {block_target:?} anymore");
                reachability_graph
                    .for_data
                    .get_mut(target)
                    .unwrap()
                    .address_taken_in
                    .remove(&block_target);
            }
        }
    }

    for ext in &new_references {
        match ext {
            ExtRef::Jump(target) => {
                log::trace!("{target:?} is reachable from {block_target:?}");
                reachability_graph
                    .for_code
                    .get_mut(target)
                    .unwrap()
                    .reachable_from
                    .insert(block_target);
            }
            ExtRef::Address(target) => {
                log::trace!("{target:?}'s address is taken in {block_target:?}");
                reachability_graph
                    .for_code
                    .get_mut(target)
                    .unwrap()
                    .address_taken_in
                    .insert(block_target);
            }
            ExtRef::DataAddress(target) => {
                log::trace!("{target:?}'s address is taken in {block_target:?}");
                reachability_graph
                    .for_data
                    .get_mut(target)
                    .unwrap()
                    .address_taken_in
                    .insert(block_target);
            }
        }
    }

    for ext in old_references.into_iter().chain(new_references.into_iter()) {
        match ext {
            ExtRef::Jump(target) => {
                remove_code_if_globally_unreachable(all_blocks, reachability_graph, optimize_queue.as_deref_mut(), target);
            }
            ExtRef::Address(target) => {
                remove_code_if_globally_unreachable(all_blocks, reachability_graph, optimize_queue.as_deref_mut(), target);
            }
            ExtRef::DataAddress(target) => {
                remove_if_data_is_globally_unreachable(all_blocks, reachability_graph, optimize_queue.as_deref_mut(), target);
            }
        }
    }
}

fn perform_dead_code_elimination(
    config: &Config,
    imports: &[Import],
    all_blocks: &mut [BasicBlock<AnyTarget, BlockTarget>],
    registers_needed_for_block: &mut [RegMask],
    reachability_graph: &mut ReachabilityGraph,
    mut optimize_queue: Option<&mut VecSet<BlockTarget>>,
    block_target: BlockTarget,
) -> bool {
    #[allow(clippy::too_many_arguments)]
    fn perform_dead_code_elimination_on_block(
        config: &Config,
        imports: &[Import],
        all_blocks: &mut [BasicBlock<AnyTarget, BlockTarget>],
        reachability_graph: &mut ReachabilityGraph,
        mut optimize_queue: Option<&mut VecSet<BlockTarget>>,
        modified: &mut bool,
        mut registers_needed: RegMask,
        block_target: BlockTarget,
    ) -> RegMask {
        let next_instruction = &all_blocks[block_target.index()].next.instruction;
        registers_needed.remove(next_instruction.dst_mask());
        registers_needed.insert(next_instruction.src_mask());

        let mut dead_code = Vec::new();
        for (nth_instruction, (_, op)) in all_blocks[block_target.index()].ops.iter().enumerate().rev() {
            let dst_mask = op.dst_mask(imports);
            if !op.has_side_effects(config) && (dst_mask & registers_needed) == RegMask::empty() {
                // This instruction has no side effects and its result is not used; it's dead.
                dead_code.push(nth_instruction);
                continue;
            }

            // If the register was overwritten it means it wasn't needed later.
            registers_needed.remove(dst_mask);
            // ...unless it was used as a source.
            registers_needed.insert(op.src_mask(imports));
        }

        if dead_code.is_empty() {
            return registers_needed;
        }

        *modified = true;
        if let Some(ref mut optimize_queue) = optimize_queue {
            add_to_optimize_queue(all_blocks, reachability_graph, optimize_queue, block_target);
        }

        let references = gather_references(&all_blocks[block_target.index()]);
        for nth_instruction in dead_code {
            // Replace it with a NOP.
            all_blocks[block_target.index()].ops[nth_instruction].1 = BasicInst::Nop;
        }

        all_blocks[block_target.index()]
            .ops
            .retain(|(_, instruction)| !instruction.is_nop());

        update_references(all_blocks, reachability_graph, optimize_queue, block_target, references);
        registers_needed
    }

    if !reachability_graph.is_code_reachable(block_target) {
        return false;
    }

    let mut previous_blocks = Vec::new();
    for &previous_block in &reachability_graph.for_code.get(&block_target).unwrap().reachable_from {
        if previous_block == block_target {
            continue;
        }

        let ControlInst::Jump { target } = all_blocks[previous_block.index()].next.instruction else {
            continue;
        };
        if target == block_target {
            previous_blocks.push(previous_block);
        }
    }

    let registers_needed_for_next_block = match all_blocks[block_target.index()].next.instruction {
        // If it's going to trap then it's not going to need any of the register values.
        ControlInst::Unimplemented => RegMask::empty(),
        // If it's a jump then we'll need whatever registers the jump target needs.
        ControlInst::Jump { target } => registers_needed_for_block[target.index()],
        ControlInst::Branch {
            target_true, target_false, ..
        } => registers_needed_for_block[target_true.index()] | registers_needed_for_block[target_false.index()],
        // ...otherwise assume it'll need all of them.
        ControlInst::Call { .. } => unreachable!(),
        ControlInst::CallIndirect { .. } | ControlInst::JumpIndirect { .. } => RegMask::all(),
    };

    let mut modified = false;
    let registers_needed_for_this_block = perform_dead_code_elimination_on_block(
        config,
        imports,
        all_blocks,
        reachability_graph,
        optimize_queue.as_deref_mut(),
        &mut modified,
        registers_needed_for_next_block,
        block_target,
    );

    if registers_needed_for_block[block_target.index()] != registers_needed_for_this_block {
        registers_needed_for_block[block_target.index()] = registers_needed_for_this_block;
        if let Some(ref mut optimize_queue) = optimize_queue {
            for previous_block in previous_blocks {
                add_to_optimize_queue(all_blocks, reachability_graph, optimize_queue, previous_block);
            }
        }
    }

    modified
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum AnyAnyKind {
    Add,
    Add64,
    Sub,
    Sub64,
    And,
    And64,
    Or,
    Or64,
    Xor,
    Xor64,
    SetLessThanUnsigned,
    SetLessThanSigned,
    SetLessThanUnsigned64,
    SetLessThanSigned64,
    ShiftLogicalLeft,
    ShiftLogicalRight,
    ShiftArithmeticRight,
    ShiftLogicalLeft64,
    ShiftLogicalRight64,
    ShiftArithmeticRight64,

    Mul,
    Mul64,
    MulUpperSignedSigned,
    MulUpperSignedSigned64,
    MulUpperUnsignedUnsigned,
    MulUpperUnsignedUnsigned64,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum RegRegKind {
    MulUpperSignedUnsigned,
    MulUpperSignedUnsigned64,
    Div,
    Div64,
    DivUnsigned,
    DivUnsigned64,
    Rem,
    Rem64,
    RemUnsigned,
    RemUnsigned64,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
enum OperationKind {
    Add,
    Add64,
    Sub,
    Sub64,
    And,
    And64,
    Or,
    Or64,
    Xor,
    Xor64,
    SetLessThanUnsigned,
    SetLessThanUnsigned64,
    SetLessThanSigned,
    SetLessThanSigned64,
    ShiftLogicalLeft,
    ShiftLogicalLeft64,
    ShiftLogicalRight,
    ShiftLogicalRight64,
    ShiftArithmeticRight,
    ShiftArithmeticRight64,

    Mul,
    Mul64,
    MulUpperSignedSigned,
    MulUpperSignedSigned64,
    MulUpperSignedUnsigned,
    MulUpperSignedUnsigned64,
    MulUpperUnsignedUnsigned,
    MulUpperUnsignedUnsigned64,
    Div,
    Div64,
    DivUnsigned,
    DivUnsigned64,
    Rem,
    Rem64,
    RemUnsigned,
    RemUnsigned64,

    Eq,
    NotEq,
    SetGreaterOrEqualSigned,
    SetGreaterOrEqualUnsigned,
}

impl From<AnyAnyKind> for OperationKind {
    fn from(kind: AnyAnyKind) -> Self {
        match kind {
            AnyAnyKind::Add => Self::Add,
            AnyAnyKind::Add64 => Self::Add64,
            AnyAnyKind::Sub => Self::Sub,
            AnyAnyKind::Sub64 => Self::Sub64,
            AnyAnyKind::And => Self::And,
            AnyAnyKind::And64 => Self::And64,
            AnyAnyKind::Or => Self::Or,
            AnyAnyKind::Or64 => Self::Or64,
            AnyAnyKind::Xor => Self::Xor,
            AnyAnyKind::Xor64 => Self::Xor64,
            AnyAnyKind::SetLessThanUnsigned => Self::SetLessThanUnsigned,
            AnyAnyKind::SetLessThanUnsigned64 => Self::SetLessThanUnsigned64,
            AnyAnyKind::SetLessThanSigned => Self::SetLessThanSigned,
            AnyAnyKind::SetLessThanSigned64 => Self::SetLessThanSigned64,
            AnyAnyKind::ShiftLogicalLeft => Self::ShiftLogicalLeft,
            AnyAnyKind::ShiftLogicalLeft64 => Self::ShiftLogicalLeft64,
            AnyAnyKind::ShiftLogicalRight => Self::ShiftLogicalRight,
            AnyAnyKind::ShiftLogicalRight64 => Self::ShiftLogicalRight64,
            AnyAnyKind::ShiftArithmeticRight => Self::ShiftArithmeticRight,
            AnyAnyKind::ShiftArithmeticRight64 => Self::ShiftArithmeticRight64,
            AnyAnyKind::Mul => Self::Mul,
            AnyAnyKind::Mul64 => Self::Mul64,
            AnyAnyKind::MulUpperSignedSigned => Self::MulUpperSignedSigned,
            AnyAnyKind::MulUpperSignedSigned64 => Self::MulUpperSignedSigned64,
            AnyAnyKind::MulUpperUnsignedUnsigned => Self::MulUpperUnsignedUnsigned,
            AnyAnyKind::MulUpperUnsignedUnsigned64 => Self::MulUpperUnsignedUnsigned64,
        }
    }
}

impl From<RegRegKind> for OperationKind {
    fn from(kind: RegRegKind) -> Self {
        match kind {
            RegRegKind::MulUpperSignedUnsigned => Self::MulUpperSignedUnsigned,
            RegRegKind::MulUpperSignedUnsigned64 => Self::MulUpperSignedUnsigned64,
            RegRegKind::Div => Self::Div,
            RegRegKind::Div64 => Self::Div64,
            RegRegKind::DivUnsigned => Self::DivUnsigned,
            RegRegKind::DivUnsigned64 => Self::DivUnsigned64,
            RegRegKind::Rem => Self::Rem,
            RegRegKind::Rem64 => Self::Rem64,
            RegRegKind::RemUnsigned => Self::RemUnsigned,
            RegRegKind::RemUnsigned64 => Self::RemUnsigned64,
        }
    }
}

impl From<BranchKind> for OperationKind {
    fn from(kind: BranchKind) -> Self {
        match kind {
            BranchKind::Eq => Self::Eq,
            BranchKind::NotEq => Self::NotEq,
            BranchKind::LessSigned => Self::SetLessThanSigned,
            BranchKind::GreaterOrEqualSigned => Self::SetGreaterOrEqualSigned,
            BranchKind::LessUnsigned => Self::SetLessThanUnsigned,
            BranchKind::GreaterOrEqualUnsigned => Self::SetGreaterOrEqualUnsigned,
        }
    }
}

impl OperationKind {
    fn apply_const(self, lhs: i64, rhs: i64) -> i64 {
        use polkavm_common::operation::*;
        #[allow(clippy::unnecessary_cast)]
        match self {
            Self::Add => {
                let lhs: i32 = lhs.try_into().expect("add operand overflow");
                let rhs: i32 = rhs.try_into().expect("add operand overflow");
                i32_to_i64(lhs.wrapping_add(rhs))
            }
            Self::Sub => {
                let lhs: i32 = lhs.try_into().expect("sub operand overflow");
                let rhs: i32 = rhs.try_into().expect("sub operand overflow");
                i32_to_i64(lhs.wrapping_sub(rhs))
            }
            Self::And => {
                let lhs: i32 = lhs.try_into().expect("and operand overflow");
                let rhs: i32 = rhs.try_into().expect("and operand overflow");
                i32_to_i64(lhs & rhs)
            }
            Self::Or => {
                let lhs: i32 = lhs.try_into().expect("or operand overflow");
                let rhs: i32 = rhs.try_into().expect("or operand overflow");
                i32_to_i64(lhs | rhs)
            }
            Self::Xor => {
                let lhs: i32 = lhs.try_into().expect("xor operand overflow");
                let rhs: i32 = rhs.try_into().expect("xor operand overflow");
                i32_to_i64(lhs ^ rhs)
            }
            Self::SetLessThanUnsigned => i64::from((lhs as u64) < (rhs as u64)),
            Self::SetLessThanSigned => i64::from((lhs as i64) < (rhs as i64)),
            Self::ShiftLogicalLeft => {
                let lhs: i32 = lhs.try_into().expect("shl operand overflow");
                let rhs: i32 = rhs.try_into().expect("shl operand overflow");
                i32_to_i64((lhs as u32).wrapping_shl(rhs as u32) as i32)
            }
            Self::ShiftLogicalRight => {
                let lhs: i32 = lhs.try_into().expect("shr operand overflow");
                let rhs: i32 = rhs.try_into().expect("shr operand overflow");
                i32_to_i64((lhs as u32).wrapping_shr(rhs as u32) as i32)
            }
            Self::ShiftArithmeticRight => {
                let lhs: i32 = lhs.try_into().expect("sha operand overflow");
                let rhs: i32 = rhs.try_into().expect("sha operand overflow");
                i32_to_i64((lhs as i32).wrapping_shr(rhs as u32))
            }

            Self::Mul => {
                let lhs: i32 = lhs.try_into().expect("mul operand overflow");
                let rhs: i32 = rhs.try_into().expect("mul operand overflow");
                i32_to_i64((lhs as i32).wrapping_mul(rhs as i32))
            }
            Self::MulUpperSignedSigned => {
                let lhs: i32 = lhs.try_into().expect("mulh operand overflow");
                let rhs: i32 = rhs.try_into().expect("mulh operand overflow");
                i32_to_i64(mulh(lhs, rhs))
            }
            Self::MulUpperSignedUnsigned => {
                let lhs: i32 = lhs.try_into().expect("mulhsu operand overflow");
                let rhs: i32 = rhs.try_into().expect("mulhsu operand overflow");
                i32_to_i64(mulhsu(lhs, rhs as u32))
            }
            Self::MulUpperUnsignedUnsigned => {
                let lhs: i32 = lhs.try_into().expect("mulhu operand overflow");
                let rhs: i32 = rhs.try_into().expect("mulhu operand overflow");
                i32_to_i64(mulhu(lhs as u32, rhs as u32) as i32)
            }
            Self::Div => {
                let lhs: i32 = lhs.try_into().expect("div operand overflow");
                let rhs: i32 = rhs.try_into().expect("div operand overflow");
                i32_to_i64(div(lhs, rhs))
            }
            Self::DivUnsigned => {
                let lhs: i32 = lhs.try_into().expect("divu operand overflow");
                let rhs: i32 = rhs.try_into().expect("divu operand overflow");
                i32_to_i64(divu(lhs as u32, rhs as u32) as i32)
            }
            Self::Rem => {
                let lhs: i32 = lhs.try_into().expect("rem operand overflow");
                let rhs: i32 = rhs.try_into().expect("rem operand overflow");
                i32_to_i64(rem(lhs, rhs))
            }
            Self::RemUnsigned => {
                let lhs: i32 = lhs.try_into().expect("remu operand overflow");
                let rhs: i32 = rhs.try_into().expect("remu operand overflow");
                i32_to_i64(remu(lhs as u32, rhs as u32) as i32)
            }

            Self::Eq => i64::from(lhs == rhs),
            Self::NotEq => i64::from(lhs != rhs),
            Self::SetGreaterOrEqualUnsigned => i64::from((lhs as u64) >= (rhs as u64)),
            Self::SetGreaterOrEqualSigned => i64::from((lhs as i64) >= (rhs as i64)),

            //
            // 64-bit instructions
            // TODO: Merge 64-bit and 32-bit flavours of Bitwise and Set instructions.
            //
            Self::Add64 => lhs.wrapping_add(rhs),
            Self::Sub64 => lhs.wrapping_sub(rhs),
            Self::And64 => lhs & rhs,
            Self::Or64 => lhs | rhs,
            Self::Xor64 => lhs ^ rhs,
            Self::SetLessThanUnsigned64 => i64::from((lhs as u64) < (rhs as u64)),
            Self::SetLessThanSigned64 => i64::from((lhs as i64) < (rhs as i64)),
            Self::ShiftLogicalLeft64 => (lhs as u64).wrapping_shl(rhs as u32) as i64,
            Self::ShiftLogicalRight64 => (lhs as u64).wrapping_shr(rhs as u32) as i64,
            Self::ShiftArithmeticRight64 => (lhs as i64).wrapping_shr(rhs as u32) as i64,
            Self::Mul64 => lhs.wrapping_mul(rhs),
            Self::MulUpperSignedSigned64 => mulh64(lhs, rhs),
            Self::MulUpperSignedUnsigned64 => mulhsu64(lhs, rhs as u64),
            Self::MulUpperUnsignedUnsigned64 => mulhu64(lhs as u64, rhs as u64) as i64,
            Self::Div64 => div64(lhs, rhs),
            Self::DivUnsigned64 => divu64(lhs as u64, rhs as u64) as i64,
            Self::Rem64 => rem64(lhs, rhs),
            Self::RemUnsigned64 => remu64(lhs as u64, rhs as u64) as i64,
        }
    }

    fn apply(self, lhs: RegValue, rhs: RegValue) -> Option<RegValue> {
        use OperationKind as O;
        use RegValue::Constant as C;

        #[rustfmt::skip]
        let value = match (self, lhs, rhs) {
            (_, C(lhs), C(rhs)) => {
                C(self.apply_const(lhs, rhs))
            },
            (O::Add | O::Sub, RegValue::DataAddress(lhs), C(rhs)) => {
                RegValue::DataAddress(lhs.map_offset_i64(|lhs| self.apply_const(lhs, rhs)))
            }

            // (x == x) = 1
            (O::Eq,                     lhs, rhs) if lhs == rhs => C(1),
            // (x != x) = 0
            (O::NotEq,                  lhs, rhs) if lhs == rhs => C(0),
            // x & x = x
            (O::And,                    lhs, rhs) if lhs == rhs => lhs,
            // x | x = x
            (O::Or,                     lhs, rhs) if lhs == rhs => lhs,

            // x + 0 = x
            (O::Add,                    lhs, C(0)) => lhs,
            // 0 + x = x
            (O::Add,                    C(0), rhs) => rhs,
            // x | 0 = x
            (O::Or,                     lhs, C(0)) => lhs,
            // 0 | x = x
            (O::Or,                     C(0), rhs) => rhs,
            // x ^ 0 = x
            (O::Xor,                    lhs, C(0)) => lhs,
            // 0 ^ x = x
            (O::Xor,                    C(0), rhs) => rhs,

            // x - 0 = x
            (O::Sub,                    lhs, C(0)) => lhs,
            // x << 0 = x
            (O::ShiftLogicalLeft,       lhs, C(0)) => lhs,
            // x >> 0 = x
            (O::ShiftLogicalRight,      lhs, C(0)) => lhs,
            // x >> 0 = x
            (O::ShiftArithmeticRight,   lhs, C(0)) => lhs,
            // x % 0 = x
            (O::Rem,                    lhs, C(0)) => lhs,
            // x % 0 = x
            (O::RemUnsigned,            lhs, C(0)) => lhs,

            // x & 0 = 0
            (O::And,                      _, C(0)) => C(0),
            // 0 & x = 0
            (O::And,                      C(0), _) => C(0),
            // x * 0 = 0
            (O::Mul,                      _, C(0)) => C(0),
            // 0 * x = 0
            (O::Mul,                      C(0), _) => C(0),

            // x / 0 = -1
            (O::Div,                      _, C(0)) => C(-1),
            (O::DivUnsigned,              _, C(0)) => C(-1),

            _ => return None,
        };

        Some(value)
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
enum RegValue {
    InputReg(Reg, BlockTarget),
    CodeAddress(BlockTarget),
    DataAddress(SectionTarget),
    Constant(i64),
    OutputReg {
        reg: Reg,
        source_block: BlockTarget,
        bits_used: u64,
    },
    Unknown {
        unique: u64,
        bits_used: u64,
    },
}

impl RegValue {
    fn to_instruction(self, dst: Reg, is_rv64: bool) -> Option<BasicInst<AnyTarget>> {
        match self {
            RegValue::CodeAddress(target) => Some(BasicInst::LoadAddress {
                dst,
                target: AnyTarget::Code(target),
            }),
            RegValue::DataAddress(target) => Some(BasicInst::LoadAddress {
                dst,
                target: AnyTarget::Data(target),
            }),
            RegValue::Constant(imm) => {
                let Ok(imm) = i32::try_from(imm) else {
                    if is_rv64 {
                        return Some(BasicInst::LoadImmediate64 { dst, imm });
                    } else {
                        panic!("load operand overflow")
                    }
                };
                Some(BasicInst::LoadImmediate { dst, imm })
            }
            _ => None,
        }
    }

    fn bits_used(self) -> u64 {
        match self {
            RegValue::InputReg(..) | RegValue::CodeAddress(..) | RegValue::DataAddress(..) => u64::MAX,
            RegValue::Constant(value) => value as u64,
            RegValue::Unknown { bits_used, .. } | RegValue::OutputReg { bits_used, .. } => bits_used,
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
struct BlockRegs {
    bitness: Bitness,
    regs: [RegValue; Reg::ALL.len()],
}

impl BlockRegs {
    fn new_input(bitness: Bitness, source_block: BlockTarget) -> Self {
        BlockRegs {
            bitness,
            regs: Reg::ALL.map(|reg| RegValue::InputReg(reg, source_block)),
        }
    }

    fn new_output(bitness: Bitness, source_block: BlockTarget) -> Self {
        BlockRegs {
            bitness,
            regs: Reg::ALL.map(|reg| RegValue::OutputReg {
                reg,
                source_block,
                bits_used: bitness.bits_used_mask(),
            }),
        }
    }

    fn get_reg(&self, reg: impl Into<RegImm>) -> RegValue {
        match reg.into() {
            RegImm::Imm(imm) => RegValue::Constant(i32_to_i64(imm as i32)),
            RegImm::Reg(reg) => self.regs[reg as usize],
        }
    }

    fn set_reg(&mut self, reg: Reg, value: RegValue) {
        self.regs[reg as usize] = value;
    }

    fn simplify_control_instruction(&self, instruction: ControlInst<BlockTarget>) -> Option<ControlInst<BlockTarget>> {
        match instruction {
            ControlInst::JumpIndirect { base, offset: 0 } => {
                if let RegValue::CodeAddress(target) = self.get_reg(base) {
                    return Some(ControlInst::Jump { target });
                }
            }
            ControlInst::Branch {
                kind,
                src1,
                src2,
                target_true,
                target_false,
            } => {
                if target_true == target_false {
                    return Some(ControlInst::Jump { target: target_true });
                }

                let src1_value = self.get_reg(src1);
                let src2_value = self.get_reg(src2);
                if let Some(value) = OperationKind::from(kind).apply(src1_value, src2_value) {
                    match value {
                        RegValue::Constant(0) => {
                            return Some(ControlInst::Jump { target: target_false });
                        }
                        RegValue::Constant(1) => {
                            return Some(ControlInst::Jump { target: target_true });
                        }
                        _ => unreachable!("internal error: constant evaluation of branch operands returned a non-boolean value"),
                    }
                }

                if let RegValue::Constant(imm) = src1_value {
                    let new_src = RegImm::Imm(imm as u32);
                    if new_src != src1 {
                        return Some(ControlInst::Branch {
                            kind,
                            src1: new_src,
                            src2,
                            target_true,
                            target_false,
                        });
                    }
                }

                if let RegValue::Constant(imm) = src2_value {
                    let new_src = RegImm::Imm(imm as u32);
                    if new_src != src2 {
                        return Some(ControlInst::Branch {
                            kind,
                            src1,
                            src2: new_src,
                            target_true,
                            target_false,
                        });
                    }
                }
            }
            _ => {}
        }

        None
    }

    fn simplify_instruction(&self, instruction: BasicInst<AnyTarget>) -> Option<BasicInst<AnyTarget>> {
        let is_rv64 = self.bitness == Bitness::B64;

        match instruction {
            BasicInst::RegReg { kind, dst, src1, src2 } => {
                let src1_value = self.get_reg(src1);
                let src2_value = self.get_reg(src2);
                if let Some(value) = OperationKind::from(kind).apply(src1_value, src2_value) {
                    if let Some(new_instruction) = value.to_instruction(dst, is_rv64) {
                        if new_instruction != instruction {
                            return Some(new_instruction);
                        }
                    }
                }
            }
            BasicInst::AnyAny { kind, dst, src1, src2 } => {
                let src1_value = self.get_reg(src1);
                let src2_value = self.get_reg(src2);
                if let Some(value) = OperationKind::from(kind).apply(src1_value, src2_value) {
                    if value == self.get_reg(dst) {
                        return Some(BasicInst::Nop);
                    }

                    if let Some(new_instruction) = value.to_instruction(dst, is_rv64) {
                        if new_instruction != instruction {
                            return Some(new_instruction);
                        }
                    }
                }

                if let RegValue::Constant(value) = src1_value {
                    if matches!(src1, RegImm::Reg(_)) {
                        return Some(BasicInst::AnyAny {
                            kind,
                            dst,
                            src1: RegImm::Imm(value as u32),
                            src2,
                        });
                    }
                }

                if let RegValue::Constant(value) = src2_value {
                    if matches!(src2, RegImm::Reg(_)) {
                        return Some(BasicInst::AnyAny {
                            kind,
                            dst,
                            src1,
                            src2: RegImm::Imm(value as u32),
                        });
                    }
                }

                if (!is_rv64 && kind == AnyAnyKind::Add) || (is_rv64 && kind == AnyAnyKind::Add64) {
                    if src1_value == RegValue::Constant(0) {
                        if let RegImm::Reg(src) = src2 {
                            return Some(BasicInst::MoveReg { dst, src });
                        }
                    } else if src2_value == RegValue::Constant(0) {
                        if let RegImm::Reg(src) = src1 {
                            return Some(BasicInst::MoveReg { dst, src });
                        }
                    }
                }

                if !is_rv64
                    && kind == AnyAnyKind::Add
                    && src1_value != RegValue::Constant(0)
                    && src2_value != RegValue::Constant(0)
                    && (src1_value.bits_used() & src2_value.bits_used()) == 0
                {
                    // Replace an `add` with an `or` if it's safe to do so.
                    //
                    // Curiously LLVM's RISC-V backend doesn't do this even though its AMD64 backend does.
                    return Some(BasicInst::AnyAny {
                        kind: AnyAnyKind::Or,
                        dst,
                        src1,
                        src2,
                    });
                }
            }
            BasicInst::Cmov {
                kind,
                dst,
                src: RegImm::Reg(src),
                cond,
            } => {
                if let RegValue::Constant(src_value) = self.get_reg(src) {
                    return Some(BasicInst::Cmov {
                        kind,
                        dst,
                        src: RegImm::Imm(src_value as u32),
                        cond,
                    });
                }
            }
            BasicInst::LoadIndirect { kind, dst, base, offset } => {
                if let RegValue::DataAddress(base) = self.get_reg(base) {
                    return Some(BasicInst::LoadAbsolute {
                        kind,
                        dst,
                        target: base.map_offset_i32(|base| base.wrapping_add(offset)),
                    });
                }
            }
            BasicInst::StoreIndirect { kind, src, base, offset } => {
                if let RegValue::DataAddress(base) = self.get_reg(base) {
                    return Some(BasicInst::StoreAbsolute {
                        kind,
                        src,
                        target: base.map_offset_i32(|base| base.wrapping_add(offset)),
                    });
                }

                let src_value = self.get_reg(src);
                if let RegValue::Constant(imm) = src_value {
                    let new_src = RegImm::Imm(imm as u32);
                    if new_src != src {
                        return Some(BasicInst::StoreIndirect {
                            kind,
                            src: new_src,
                            base,
                            offset,
                        });
                    }
                }
            }
            BasicInst::StoreAbsolute { kind, src, target } => {
                let src_value = self.get_reg(src);
                if let RegValue::Constant(imm) = src_value {
                    let new_src = RegImm::Imm(imm as u32);
                    if new_src != src {
                        return Some(BasicInst::StoreAbsolute {
                            kind,
                            src: new_src,
                            target,
                        });
                    }
                }
            }
            BasicInst::LoadImmediate { dst, imm } => {
                if self.get_reg(dst) == RegValue::Constant(i32_to_i64(imm)) {
                    return Some(BasicInst::Nop);
                }
            }
            BasicInst::MoveReg { dst, src } => {
                if dst == src {
                    return Some(BasicInst::Nop);
                }
            }
            _ => {}
        }

        None
    }

    fn set_reg_unknown(&mut self, dst: Reg, unknown_counter: &mut u64, bits_used: u64) {
        let bits_used_masked = bits_used & self.bitness.bits_used_mask();
        if bits_used_masked == 0 {
            self.set_reg(dst, RegValue::Constant(0));
            return;
        }

        self.set_reg(
            dst,
            RegValue::Unknown {
                unique: *unknown_counter,
                bits_used: bits_used_masked,
            },
        );
        *unknown_counter += 1;
    }

    fn set_reg_from_instruction(&mut self, imports: &[Import], unknown_counter: &mut u64, instruction: BasicInst<AnyTarget>) {
        match instruction {
            BasicInst::LoadImmediate { dst, imm } => {
                self.set_reg(dst, RegValue::Constant(i32_to_i64(imm)));
            }
            BasicInst::LoadImmediate64 { dst, imm } => {
                self.set_reg(dst, RegValue::Constant(imm));
            }
            BasicInst::LoadAddress {
                dst,
                target: AnyTarget::Code(target),
            }
            | BasicInst::LoadAddressIndirect {
                dst,
                target: AnyTarget::Code(target),
            } => {
                self.set_reg(dst, RegValue::CodeAddress(target));
            }
            BasicInst::LoadAddress {
                dst,
                target: AnyTarget::Data(target),
            }
            | BasicInst::LoadAddressIndirect {
                dst,
                target: AnyTarget::Data(target),
            } => {
                self.set_reg(dst, RegValue::DataAddress(target));
            }
            BasicInst::MoveReg { dst, src } => {
                self.set_reg(dst, self.get_reg(src));
            }
            BasicInst::AnyAny {
                kind: AnyAnyKind::Add | AnyAnyKind::Or,
                dst,
                src1,
                src2: RegImm::Imm(0),
            } => {
                self.set_reg(dst, self.get_reg(src1));
            }
            BasicInst::AnyAny {
                kind: AnyAnyKind::Add | AnyAnyKind::Or,
                dst,
                src1: RegImm::Imm(0),
                src2,
            } => {
                self.set_reg(dst, self.get_reg(src2));
            }
            BasicInst::AnyAny {
                kind: AnyAnyKind::Add,
                dst,
                src1,
                src2,
            } => {
                let src1_value = self.get_reg(src1);
                let src2_value = self.get_reg(src2);
                let bits_used =
                    src1_value.bits_used() | src2_value.bits_used() | (src1_value.bits_used() << 1) | (src2_value.bits_used() << 1);

                self.set_reg_unknown(dst, unknown_counter, bits_used);
            }
            BasicInst::AnyAny {
                kind: AnyAnyKind::And,
                dst,
                src1,
                src2,
            } => {
                let src1_value = self.get_reg(src1);
                let src2_value = self.get_reg(src2);
                let bits_used = src1_value.bits_used() & src2_value.bits_used();
                self.set_reg_unknown(dst, unknown_counter, bits_used);
            }
            BasicInst::AnyAny {
                kind: AnyAnyKind::Or,
                dst,
                src1,
                src2,
            } => {
                let src1_value = self.get_reg(src1);
                let src2_value = self.get_reg(src2);
                let bits_used = src1_value.bits_used() | src2_value.bits_used();
                self.set_reg_unknown(dst, unknown_counter, bits_used);
            }
            BasicInst::AnyAny {
                kind: AnyAnyKind::ShiftLogicalRight,
                dst,
                src1,
                src2: RegImm::Imm(src2),
            } => {
                let src1_value = self.get_reg(src1);
                let bits_used = src1_value.bits_used() >> src2;
                self.set_reg_unknown(dst, unknown_counter, bits_used);
            }
            BasicInst::AnyAny {
                kind: AnyAnyKind::ShiftLogicalLeft,
                dst,
                src1,
                src2: RegImm::Imm(src2),
            } => {
                let src1_value = self.get_reg(src1);
                let bits_used = src1_value.bits_used() << src2;
                self.set_reg_unknown(dst, unknown_counter, bits_used);
            }
            BasicInst::AnyAny {
                kind: AnyAnyKind::SetLessThanSigned | AnyAnyKind::SetLessThanUnsigned,
                dst,
                ..
            } => {
                self.set_reg_unknown(dst, unknown_counter, 1);
            }
            BasicInst::LoadAbsolute {
                kind: LoadKind::U8, dst, ..
            }
            | BasicInst::LoadIndirect {
                kind: LoadKind::U8, dst, ..
            } => {
                self.set_reg_unknown(dst, unknown_counter, u64::from(u8::MAX));
            }
            BasicInst::LoadAbsolute {
                kind: LoadKind::U16, dst, ..
            }
            | BasicInst::LoadIndirect {
                kind: LoadKind::U16, dst, ..
            } => {
                self.set_reg_unknown(dst, unknown_counter, u64::from(u16::MAX));
            }
            _ => {
                for dst in instruction.dst_mask(imports) {
                    self.set_reg_unknown(dst, unknown_counter, self.bitness.bits_used_mask());
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn perform_constant_propagation<H>(
    imports: &[Import],
    elf: &Elf<H>,
    all_blocks: &mut [BasicBlock<AnyTarget, BlockTarget>],
    input_regs_for_block: &mut [BlockRegs],
    output_regs_for_block: &mut [BlockRegs],
    unknown_counter: &mut u64,
    reachability_graph: &mut ReachabilityGraph,
    mut optimize_queue: Option<&mut VecSet<BlockTarget>>,
    current: BlockTarget,
) -> bool
where
    H: object::read::elf::FileHeader<Endian = object::LittleEndian>,
{
    let is_rv64 = elf.is_64();

    let Some(reachability) = reachability_graph.for_code.get(&current) else {
        return false;
    };

    if reachability.is_unreachable() {
        return false;
    }

    let mut modified = false;
    if !reachability.is_dynamically_reachable()
        && !reachability.always_reachable_or_exported()
        && !reachability.reachable_from.is_empty()
        && reachability.reachable_from.len() < 64
    {
        for reg in Reg::ALL {
            let mut common_value_opt = None;
            for &source in &reachability.reachable_from {
                let value = output_regs_for_block[source.index()].get_reg(reg);
                if value == RegValue::InputReg(reg, current) {
                    continue;
                }

                if let Some(common_value) = common_value_opt {
                    if common_value == value {
                        continue;
                    }

                    common_value_opt = None;
                    break;
                } else {
                    common_value_opt = Some(value);
                }
            }

            if let Some(value) = common_value_opt {
                let old_value = input_regs_for_block[current.index()].get_reg(reg);
                if value != old_value {
                    input_regs_for_block[current.index()].set_reg(reg, value);
                    modified = true;
                }
            }
        }
    }

    let mut regs = input_regs_for_block[current.index()].clone();
    let mut references = BTreeSet::new();
    let mut modified_this_block = false;
    for nth_instruction in 0..all_blocks[current.index()].ops.len() {
        let mut instruction = all_blocks[current.index()].ops[nth_instruction].1;
        if instruction.is_nop() {
            continue;
        }

        while let Some(new_instruction) = regs.simplify_instruction(instruction) {
            if !modified_this_block {
                references = gather_references(&all_blocks[current.index()]);
                modified_this_block = true;
                modified = true;
            }

            instruction = new_instruction;
            all_blocks[current.index()].ops[nth_instruction].1 = new_instruction;
        }

        if let BasicInst::LoadAbsolute { kind, dst, target } = instruction {
            let section = elf.section_by_index(target.section_index);
            if section.is_allocated() && !section.is_writable() {
                let value = match kind {
                    LoadKind::U64 => section
                        .data()
                        .get(target.offset as usize..target.offset as usize + 8)
                        .map(|xs| u64::from_le_bytes([xs[0], xs[1], xs[2], xs[3], xs[4], xs[5], xs[6], xs[7]]))
                        .map(|xs| xs as i64),
                    LoadKind::U32 => section
                        .data()
                        .get(target.offset as usize..target.offset as usize + 4)
                        .map(|xs| u32::from_le_bytes([xs[0], xs[1], xs[2], xs[3]]) as i32)
                        .map(i32_to_i64),
                    LoadKind::I32 => section
                        .data()
                        .get(target.offset as usize..target.offset as usize + 4)
                        .map(|xs| i32::from_le_bytes([xs[0], xs[1], xs[2], xs[3]]))
                        .map(i32_to_i64),
                    LoadKind::U16 => section
                        .data()
                        .get(target.offset as usize..target.offset as usize + 2)
                        .map(|xs| u32::from(u16::from_le_bytes([xs[0], xs[1]])) as i32)
                        .map(i32_to_i64),
                    LoadKind::I16 => section
                        .data()
                        .get(target.offset as usize..target.offset as usize + 2)
                        .map(|xs| i32::from(i16::from_le_bytes([xs[0], xs[1]])))
                        .map(i32_to_i64),
                    LoadKind::I8 => section
                        .data()
                        .get(target.offset as usize)
                        .map(|&x| i32::from(x as i8))
                        .map(i32_to_i64),
                    LoadKind::U8 => section
                        .data()
                        .get(target.offset as usize)
                        .map(|&x| u32::from(x) as i32)
                        .map(i32_to_i64),
                };

                if let Some(imm) = value {
                    if !modified_this_block {
                        references = gather_references(&all_blocks[current.index()]);
                        modified_this_block = true;
                        modified = true;
                    }

                    if let Ok(imm) = i32::try_from(imm) {
                        instruction = BasicInst::LoadImmediate { dst, imm };
                    } else if is_rv64 {
                        instruction = BasicInst::LoadImmediate64 { dst, imm };
                    } else {
                        unreachable!("load immediate overflow in 32-bit");
                    }

                    all_blocks[current.index()].ops[nth_instruction].1 = instruction;
                }
            }
        }

        regs.set_reg_from_instruction(imports, unknown_counter, instruction);
    }

    for reg in Reg::ALL {
        if let RegValue::Unknown { bits_used, .. } = regs.get_reg(reg) {
            regs.set_reg(
                reg,
                RegValue::OutputReg {
                    reg,
                    source_block: current,
                    bits_used,
                },
            )
        }
    }

    let output_regs_modified = output_regs_for_block[current.index()] != regs;
    if output_regs_modified {
        output_regs_for_block[current.index()] = regs.clone();
        modified = true;
    }

    if let ControlInst::CallIndirect {
        ra,
        base,
        offset: 0,
        target_return,
    } = all_blocks[current.index()].next.instruction
    {
        if let RegValue::CodeAddress(target) = regs.get_reg(base) {
            if !modified_this_block {
                references = gather_references(&all_blocks[current.index()]);
                modified_this_block = true;
                modified = true;
            }

            all_blocks[current.index()].ops.push((
                all_blocks[current.index()].next.source.clone(),
                BasicInst::LoadAddress {
                    dst: ra,
                    target: AnyTarget::Code(target_return),
                },
            ));

            all_blocks[current.index()].next.instruction = ControlInst::Jump { target };
        }
    }

    while let Some(new_instruction) = regs.simplify_control_instruction(all_blocks[current.index()].next.instruction) {
        log::trace!(
            "Simplifying end of {current:?}: {:?} -> {:?}",
            all_blocks[current.index()].next.instruction,
            new_instruction
        );

        if !modified_this_block {
            references = gather_references(&all_blocks[current.index()]);
            modified_this_block = true;
            modified = true;
        }

        all_blocks[current.index()].next.instruction = new_instruction;
    }

    if modified_this_block {
        update_references(all_blocks, reachability_graph, optimize_queue.as_deref_mut(), current, references);
        if reachability_graph.is_code_reachable(current) {
            if let Some(ref mut optimize_queue) = optimize_queue {
                add_to_optimize_queue(all_blocks, reachability_graph, optimize_queue, current);
            }
        }
    }

    if let Some(ref mut optimize_queue) = optimize_queue {
        if output_regs_modified {
            match all_blocks[current.index()].next.instruction {
                ControlInst::Jump { target } => add_to_optimize_queue(all_blocks, reachability_graph, optimize_queue, target),
                ControlInst::Branch {
                    target_true, target_false, ..
                } => {
                    add_to_optimize_queue(all_blocks, reachability_graph, optimize_queue, target_true);
                    add_to_optimize_queue(all_blocks, reachability_graph, optimize_queue, target_false);
                }
                ControlInst::Call { .. } => unreachable!(),
                _ => {}
            }
        }
    }

    modified
}

fn perform_load_address_and_jump_fusion(all_blocks: &mut [BasicBlock<AnyTarget, BlockTarget>], reachability_graph: &ReachabilityGraph) {
    let used_blocks: Vec<_> = (0..all_blocks.len())
        .map(BlockTarget::from_raw)
        .filter(|&block_target| reachability_graph.is_code_reachable(block_target))
        .collect();

    for window in used_blocks.windows(2) {
        let (current, next) = (window[0], window[1]);
        let Some(&(
            _,
            BasicInst::LoadAddress {
                dst,
                target: AnyTarget::Code(target_return),
            },
        )) = all_blocks[current.index()].ops.last()
        else {
            continue;
        };

        if target_return != next {
            continue;
        }

        all_blocks[current.index()].next.instruction = match all_blocks[current.index()].next.instruction {
            ControlInst::Jump { target } => ControlInst::Call {
                target,
                target_return,
                ra: dst,
            },
            ControlInst::JumpIndirect { base, offset } if dst != base => ControlInst::CallIndirect {
                base,
                offset,
                target_return,
                ra: dst,
            },
            _ => {
                continue;
            }
        };

        all_blocks[current.index()].ops.pop();
    }
}

fn optimize_program<H>(
    config: &Config,
    elf: &Elf<H>,
    imports: &[Import],
    all_blocks: &mut [BasicBlock<AnyTarget, BlockTarget>],
    reachability_graph: &mut ReachabilityGraph,
    exports: &mut [Export],
) where
    H: object::read::elf::FileHeader<Endian = object::LittleEndian>,
{
    let bitness = if elf.is_64() { Bitness::B64 } else { Bitness::B32 };

    let mut optimize_queue = VecSet::new();
    for current in (0..all_blocks.len()).map(BlockTarget::from_raw) {
        if !reachability_graph.is_code_reachable(current) {
            all_blocks[current.index()].ops.clear();
            all_blocks[current.index()].next.instruction = ControlInst::Unimplemented;
            continue;
        }

        perform_nop_elimination(all_blocks, current);

        let block = &mut all_blocks[current.index()];
        block.next.instruction = match block.next.instruction {
            ControlInst::Call { ra, target, target_return } => {
                block.ops.push((
                    block.next.source.clone(),
                    BasicInst::LoadAddress {
                        dst: ra,
                        target: AnyTarget::Code(target_return),
                    },
                ));
                ControlInst::Jump { target }
            }
            ControlInst::CallIndirect {
                ra,
                target_return,
                base,
                offset,
            } if ra != base => {
                block.ops.push((
                    block.next.source.clone(),
                    BasicInst::LoadAddress {
                        dst: ra,
                        target: AnyTarget::Code(target_return),
                    },
                ));
                ControlInst::JumpIndirect { base, offset }
            }
            instruction => instruction,
        };

        optimize_queue.push(current);
    }

    optimize_queue.vec.sort_by_key(|current| all_blocks[current.index()].ops.len());
    optimize_queue.vec.reverse();

    let mut unknown_counter = 0;
    let mut input_regs_for_block = Vec::with_capacity(all_blocks.len());
    let mut output_regs_for_block = Vec::with_capacity(all_blocks.len());
    for current in (0..all_blocks.len()).map(BlockTarget::from_raw) {
        input_regs_for_block.push(BlockRegs::new_input(bitness, current));
        output_regs_for_block.push(BlockRegs::new_output(bitness, current));
    }

    let mut registers_needed_for_block = Vec::with_capacity(all_blocks.len());
    for _ in 0..all_blocks.len() {
        registers_needed_for_block.push(RegMask::all())
    }

    let opt_minimum_iteration_count = reachability_graph.reachable_block_count();
    let mut opt_iteration_count = 0;
    let mut inline_history = HashSet::new(); // Necessary to prevent infinite loops.
    while let Some(current) = optimize_queue.pop_non_unique() {
        if !reachability_graph.is_code_reachable(current) {
            continue;
        }

        opt_iteration_count += 1;
        perform_nop_elimination(all_blocks, current);
        perform_inlining(
            all_blocks,
            reachability_graph,
            exports,
            Some(&mut optimize_queue),
            &mut inline_history,
            config.inline_threshold,
            current,
        );
        perform_dead_code_elimination(
            config,
            imports,
            all_blocks,
            &mut registers_needed_for_block,
            reachability_graph,
            Some(&mut optimize_queue),
            current,
        );
        perform_constant_propagation(
            imports,
            elf,
            all_blocks,
            &mut input_regs_for_block,
            &mut output_regs_for_block,
            &mut unknown_counter,
            reachability_graph,
            Some(&mut optimize_queue),
            current,
        );
    }

    log::debug!(
        "Optimizing the program took {} iteration(s)",
        opt_iteration_count - opt_minimum_iteration_count
    );
    garbage_collect_reachability(all_blocks, reachability_graph);

    inline_history.clear();
    let mut opt_brute_force_iterations = 0;
    let mut modified = true;
    while modified {
        opt_brute_force_iterations += 1;
        modified = false;
        for current in (0..all_blocks.len()).map(BlockTarget::from_raw) {
            if !reachability_graph.is_code_reachable(current) {
                continue;
            }

            modified |= perform_inlining(
                all_blocks,
                reachability_graph,
                exports,
                None,
                &mut inline_history,
                config.inline_threshold,
                current,
            );
            modified |= perform_dead_code_elimination(
                config,
                imports,
                all_blocks,
                &mut registers_needed_for_block,
                reachability_graph,
                None,
                current,
            );
            modified |= perform_constant_propagation(
                imports,
                elf,
                all_blocks,
                &mut input_regs_for_block,
                &mut output_regs_for_block,
                &mut unknown_counter,
                reachability_graph,
                None,
                current,
            );
        }

        if modified {
            garbage_collect_reachability(all_blocks, reachability_graph);
        }
    }

    perform_load_address_and_jump_fusion(all_blocks, reachability_graph);

    log::debug!(
        "Optimizing the program took {} brute force iteration(s)",
        opt_brute_force_iterations - 1
    );
}

#[cfg(test)]
mod test {
    use super::*;
    use polkavm::Reg;

    struct ProgramBuilder {
        data_section: SectionIndex,
        current_section: SectionIndex,
        next_free_section: SectionIndex,
        next_offset_for_section: HashMap<SectionIndex, u64>,
        instructions: Vec<(Source, InstExt<SectionTarget, SectionTarget>)>,
        exports: Vec<Export>,
    }

    struct TestProgram {
        disassembly: String,
        instance: polkavm::RawInstance,
    }

    impl ProgramBuilder {
        fn new() -> Self {
            ProgramBuilder {
                data_section: SectionIndex::new(0),
                current_section: SectionIndex::new(1),
                next_free_section: SectionIndex::new(1),
                next_offset_for_section: HashMap::default(),
                instructions: Vec::new(),
                exports: Vec::new(),
            }
        }

        fn from_assembly(assembly: &str) -> Self {
            let mut b = Self::new();
            b.append_assembly(assembly);
            b
        }

        fn add_export(&mut self, name: impl AsRef<[u8]>, input_regs: u8, output_regs: u8, location: SectionTarget) {
            self.exports.push(Export {
                location,
                metadata: ExternMetadata {
                    index: None,
                    symbol: name.as_ref().to_owned(),
                    input_regs,
                    output_regs,
                },
            })
        }

        fn add_section(&mut self) -> SectionTarget {
            let index = self.next_free_section;
            self.next_offset_for_section.insert(index, 0);
            self.next_free_section = SectionIndex::new(index.raw() + 1);
            SectionTarget {
                section_index: index,
                offset: 0,
            }
        }

        fn switch_section(&mut self, section_index: impl Into<SectionIndex>) {
            self.current_section = section_index.into();
        }

        fn current_source(&self) -> Source {
            let next_offset = self.next_offset_for_section.get(&self.current_section).copied().unwrap_or(0);
            Source {
                section_index: self.current_section,
                offset_range: (next_offset..next_offset + 4).into(),
            }
        }

        fn push(&mut self, inst: impl Into<InstExt<SectionTarget, SectionTarget>>) -> SectionTarget {
            let source = self.current_source();
            *self.next_offset_for_section.get_mut(&self.current_section).unwrap() += 4;
            self.instructions.push((source, inst.into()));
            source.begin()
        }

        fn append_assembly(&mut self, assembly: &str) {
            let raw_blob = polkavm_common::assembler::assemble(assembly).unwrap();
            let blob = ProgramBlob::parse(raw_blob.into()).unwrap();
            let mut program_counter_to_section_target = HashMap::new();
            let mut program_counter_to_instruction_index = HashMap::new();
            let mut in_new_block = true;
            for instruction in blob.instructions(Bitness::B32) {
                if in_new_block {
                    let block = self.add_section();
                    self.switch_section(block);
                    program_counter_to_section_target.insert(instruction.offset, block);
                    in_new_block = false;
                }

                program_counter_to_instruction_index.insert(instruction.offset, self.instructions.len());
                self.push(BasicInst::Nop);

                if instruction.kind.starts_new_basic_block() {
                    in_new_block = true;
                }
            }

            for instruction in blob.instructions(Bitness::B32) {
                let out = &mut self.instructions[*program_counter_to_instruction_index.get(&instruction.offset).unwrap()].1;
                match instruction.kind {
                    Instruction::fallthrough => {
                        let target = *program_counter_to_section_target.get(&instruction.next_offset).unwrap();
                        *out = ControlInst::Jump { target }.into();
                    }
                    Instruction::jump(target) => {
                        let target = *program_counter_to_section_target.get(&polkavm::ProgramCounter(target)).unwrap();
                        *out = ControlInst::Jump { target }.into();
                    }
                    Instruction::load_imm(dst, imm) => {
                        *out = BasicInst::LoadImmediate {
                            dst: dst.into(),
                            imm: imm as i32,
                        }
                        .into();
                    }
                    Instruction::add_imm(dst, src, imm) => {
                        *out = BasicInst::AnyAny {
                            kind: AnyAnyKind::Add,
                            dst: dst.into(),
                            src1: src.into(),
                            src2: imm.into(),
                        }
                        .into();
                    }
                    Instruction::add(dst, src1, src2) => {
                        *out = BasicInst::AnyAny {
                            kind: AnyAnyKind::Add,
                            dst: dst.into(),
                            src1: src1.into(),
                            src2: src2.into(),
                        }
                        .into();
                    }
                    Instruction::branch_less_unsigned_imm(src1, src2, target) | Instruction::branch_eq_imm(src1, src2, target) => {
                        let target_true = *program_counter_to_section_target.get(&polkavm::ProgramCounter(target)).unwrap();
                        let target_false = *program_counter_to_section_target.get(&instruction.next_offset).unwrap();
                        *out = ControlInst::Branch {
                            kind: match instruction.kind {
                                Instruction::branch_less_unsigned_imm(..) => BranchKind::LessUnsigned,
                                Instruction::branch_eq_imm(..) => BranchKind::Eq,
                                _ => unreachable!(),
                            },
                            src1: src1.into(),
                            src2: src2.into(),
                            target_true,
                            target_false,
                        }
                        .into();
                    }
                    Instruction::jump_indirect(base, 0) => {
                        *out = ControlInst::JumpIndirect {
                            base: base.into(),
                            offset: 0,
                        }
                        .into();
                    }
                    Instruction::trap => {
                        *out = ControlInst::Unimplemented.into();
                    }
                    Instruction::store_u32(src, address) => {
                        *out = BasicInst::StoreAbsolute {
                            kind: StoreKind::U32,
                            src: src.into(),
                            target: SectionTarget {
                                section_index: self.data_section,
                                offset: u64::from(address),
                            },
                        }
                        .into();
                    }
                    Instruction::store_indirect_u32(src, base, offset) => {
                        *out = BasicInst::StoreIndirect {
                            kind: StoreKind::U32,
                            src: src.into(),
                            base: base.into(),
                            offset: offset as i32,
                        }
                        .into();
                    }
                    _ => unimplemented!("{instruction:?}"),
                }
            }

            for export in blob.exports() {
                let input_regs = 1;
                let output_regs = 1;
                let target = program_counter_to_section_target.get(&export.program_counter()).unwrap();
                self.add_export(export.symbol().as_bytes(), input_regs, output_regs, *target);
            }
        }

        fn build(&self, config: Config) -> TestProgram {
            let elf: Elf<object::elf::FileHeader32<object::endian::LittleEndian>> = Elf::default();
            let data_sections_set: HashSet<_> = core::iter::once(self.data_section).collect();
            let code_sections_set: HashSet<_> = self.next_offset_for_section.keys().copied().collect();
            let relocations = BTreeMap::default();
            let imports = [];
            let mut exports = self.exports.clone();

            // TODO: Refactor the main code so that we don't have to copy-paste this here.
            let all_jump_targets = harvest_all_jump_targets(
                &elf,
                &data_sections_set,
                &code_sections_set,
                &self.instructions,
                &relocations,
                &exports,
            )
            .unwrap();

            let all_blocks = split_code_into_basic_blocks(&elf, &all_jump_targets, self.instructions.clone()).unwrap();
            let mut section_to_block = build_section_to_block_map(&all_blocks).unwrap();
            let mut all_blocks = resolve_basic_block_references(&data_sections_set, &section_to_block, &all_blocks).unwrap();
            let mut reachability_graph =
                calculate_reachability(&section_to_block, &all_blocks, &data_sections_set, &exports, &relocations).unwrap();
            if config.optimize {
                optimize_program(&config, &elf, &imports, &mut all_blocks, &mut reachability_graph, &mut exports);
            }
            let mut used_blocks = collect_used_blocks(&all_blocks, &reachability_graph);

            if config.optimize {
                used_blocks = add_missing_fallthrough_blocks(&mut all_blocks, &mut reachability_graph, used_blocks);
                merge_consecutive_fallthrough_blocks(&mut all_blocks, &mut reachability_graph, &mut section_to_block, &mut used_blocks);
                replace_immediates_with_registers(&mut all_blocks, &imports, &used_blocks);
            }

            let expected_reachability_graph =
                calculate_reachability(&section_to_block, &all_blocks, &data_sections_set, &exports, &relocations).unwrap();
            assert!(reachability_graph == expected_reachability_graph);

            let used_imports = HashSet::new();
            let mut base_address_for_section = HashMap::new();
            base_address_for_section.insert(self.data_section, 0);
            let section_got = self.next_free_section;
            let target_to_got_offset = HashMap::new();

            let (jump_table, jump_target_for_block) = build_jump_table(all_blocks.len(), &used_blocks, &reachability_graph);
            let code = emit_code(
                &imports,
                &base_address_for_section,
                section_got,
                &target_to_got_offset,
                &all_blocks,
                &used_blocks,
                &used_imports,
                &jump_target_for_block,
                true,
                false,
            )
            .unwrap();

            let mut builder = ProgramBlobBuilder::new();

            let mut export_count = 0;
            for current in used_blocks {
                for &export_index in &reachability_graph.for_code.get(&current).unwrap().exports {
                    let export = &exports[export_index];
                    let jump_target = jump_target_for_block[current.index()]
                        .expect("internal error: export metadata points to a block without a jump target assigned");

                    builder.add_export_by_basic_block(jump_target.static_target, &export.metadata.symbol);
                    export_count += 1;
                }
            }
            assert_eq!(export_count, exports.len());

            let mut raw_code = Vec::with_capacity(code.len());
            for (_, inst) in code {
                raw_code.push(inst);
            }

            builder.set_code(&raw_code, &jump_table);
            builder.set_rw_data_size(1);

            let blob = ProgramBlob::parse(builder.to_vec().into()).unwrap();
            let mut disassembler = polkavm_disassembler::Disassembler::new(&blob, polkavm_disassembler::DisassemblyFormat::Guest).unwrap();
            disassembler.emit_header(false);
            disassembler.show_offsets(false);
            let mut buf = Vec::new();
            disassembler.disassemble_into(&mut buf).unwrap();
            let disassembly = String::from_utf8(buf).unwrap();

            let mut config = polkavm::Config::from_env().unwrap();
            config.set_backend(Some(polkavm::BackendKind::Interpreter));
            let engine = polkavm::Engine::new(&config).unwrap();
            let mut module_config = polkavm::ModuleConfig::default();
            module_config.set_gas_metering(Some(polkavm::GasMeteringKind::Sync));
            let module = polkavm::Module::from_blob(&engine, &module_config, blob).unwrap();
            let mut instance = module.instantiate().unwrap();
            instance.set_gas(10000);
            instance.set_reg(polkavm::Reg::RA, polkavm::RETURN_TO_HOST);
            let pc = module.exports().find(|export| export.symbol() == "main").unwrap().program_counter();
            instance.set_next_program_counter(pc);

            TestProgram { disassembly, instance }
        }

        fn test_optimize(
            &self,
            mut run: impl FnMut(&mut polkavm::RawInstance),
            mut check: impl FnMut(&mut polkavm::RawInstance, &mut polkavm::RawInstance),
            expected_disassembly: &str,
        ) {
            let mut unopt = self.build(Config {
                optimize: false,
                ..Config::default()
            });
            let mut opt = self.build(Config {
                optimize: true,
                ..Config::default()
            });

            log::info!("Unoptimized disassembly:\n{}", unopt.disassembly);
            log::info!("Optimized disassembly:\n{}", opt.disassembly);

            run(&mut unopt.instance);
            run(&mut opt.instance);

            check(&mut opt.instance, &mut unopt.instance);

            fn normalize(s: &str) -> String {
                let mut out = String::new();
                for line in s.trim().lines() {
                    if !line.trim().starts_with('@') {
                        out.push_str("    ");
                    }
                    out.push_str(line.trim());
                    out.push('\n');
                }
                out
            }

            let is_todo = expected_disassembly.trim() == "TODO";
            let actual_normalized = normalize(&opt.disassembly);
            let expected_normalized = normalize(expected_disassembly);
            if actual_normalized != expected_normalized && !is_todo {
                use core::fmt::Write;
                let mut output_actual = String::new();
                let mut output_expected = String::new();
                for diff in diff::lines(&actual_normalized, &expected_normalized) {
                    match diff {
                        diff::Result::Left(line) => {
                            writeln!(&mut output_actual, "{}", yansi::Paint::red(line)).unwrap();
                        }
                        diff::Result::Both(line, _) => {
                            writeln!(&mut output_actual, "{}", line).unwrap();
                            writeln!(&mut output_expected, "{}", line).unwrap();
                        }
                        diff::Result::Right(line) => {
                            writeln!(&mut output_expected, "{}", line).unwrap();
                        }
                    }
                }

                {
                    use std::io::Write;
                    let stderr = std::io::stderr();
                    let mut stderr = stderr.lock();

                    writeln!(&mut stderr, "Optimization test failed!\n").unwrap();
                    writeln!(&mut stderr, "Expected optimized:").unwrap();
                    writeln!(&mut stderr, "{output_expected}").unwrap();
                    writeln!(&mut stderr, "Actual optimized:").unwrap();
                    writeln!(&mut stderr, "{output_actual}").unwrap();
                }

                panic!("optimized program is not what we've expected")
            }

            if is_todo {
                todo!();
            }
        }

        fn test_optimize_oneshot(
            assembly: &str,
            expected_disassembly: &str,
            run: impl FnMut(&mut polkavm::RawInstance),
            check: impl FnMut(&mut polkavm::RawInstance, &mut polkavm::RawInstance),
        ) {
            let _ = env_logger::try_init();
            let b = ProgramBuilder::from_assembly(assembly);
            b.test_optimize(run, check, expected_disassembly);
        }
    }

    fn expect_finished(i: &mut polkavm::RawInstance) {
        assert!(matches!(i.run().unwrap(), polkavm::InterruptKind::Finished));
    }

    fn expect_regs(regs: impl IntoIterator<Item = (Reg, u32)> + Clone) -> impl FnMut(&mut polkavm::RawInstance, &mut polkavm::RawInstance) {
        move |a: &mut polkavm::RawInstance, b: &mut polkavm::RawInstance| {
            for (reg, value) in regs.clone() {
                assert_eq!(b.reg(reg), value);
                assert_eq!(a.reg(reg), b.reg(reg));
            }
        }
    }

    #[test]
    fn test_optimize_01_empty_block_elimination() {
        ProgramBuilder::test_optimize_oneshot(
            "
            pub @main:
                jump @loop
            @before_loop:
                jump @loop
            @loop:
                a0 = a0 + 0x1
                jump @before_loop if a0 <u 10
                ret
            ",
            "
            @0 [export #0: 'main']
                a0 = a0 + 0x1
                jump @0 if a0 <u 10
            @1
                ret
            ",
            expect_finished,
            expect_regs([(Reg::A0, 10)]),
        )
    }

    #[test]
    fn test_optimize_02_simple_constant_propagation() {
        ProgramBuilder::test_optimize_oneshot(
            "
            pub @main:
                a1 = 1
            @loop:
                a0 = a0 + a1
                jump @loop if a0 <u 10
                ret
            ",
            "
            @0 [export #0: 'main']
                a1 = 0x1
                fallthrough
            @1
                a0 = a0 + 0x1
                jump @1 if a0 <u 10
            @2
                ret
            ",
            expect_finished,
            expect_regs([(Reg::A0, 10), (Reg::A1, 1)]),
        )
    }

    #[test]
    fn test_optimize_03_simple_dead_code_elimination() {
        ProgramBuilder::test_optimize_oneshot(
            "
            pub @main:
                a1 = a1 + 100
                a1 = 8
                a2 = a2 + 0
                a0 = a0 + 1
                jump @main if a0 <u 10
                ret
            ",
            "
            @0 [export #0: 'main']
                a1 = 0x8
                a0 = a0 + 0x1
                jump @0 if a0 <u 10
            @1
                ret
            ",
            expect_finished,
            expect_regs([(Reg::A0, 10), (Reg::A1, 8)]),
        )
    }
}

fn collect_used_blocks(all_blocks: &[BasicBlock<AnyTarget, BlockTarget>], reachability_graph: &ReachabilityGraph) -> Vec<BlockTarget> {
    let mut used_blocks = Vec::new();
    for block in all_blocks {
        if !reachability_graph.is_code_reachable(block.target) {
            continue;
        }

        used_blocks.push(block.target);
    }

    used_blocks
}

fn add_missing_fallthrough_blocks(
    all_blocks: &mut Vec<BasicBlock<AnyTarget, BlockTarget>>,
    reachability_graph: &mut ReachabilityGraph,
    used_blocks: Vec<BlockTarget>,
) -> Vec<BlockTarget> {
    let mut new_used_blocks = Vec::new();
    let can_fallthrough_to_next_block = calculate_whether_can_fallthrough(all_blocks, &used_blocks);
    for current in used_blocks {
        new_used_blocks.push(current);
        if can_fallthrough_to_next_block.contains(&current) {
            continue;
        }

        let Some(target) = all_blocks[current.index()].next.instruction.fallthrough_target_mut().copied() else {
            continue;
        };

        let inline_target = target != current
            && all_blocks[target.index()].ops.is_empty()
            && all_blocks[target.index()].next.instruction.fallthrough_target_mut().is_none();

        let new_block_index = BlockTarget::from_raw(all_blocks.len());
        all_blocks.push(BasicBlock {
            target: new_block_index,
            source: all_blocks[current.index()].source,
            ops: Default::default(),
            next: if inline_target {
                all_blocks[target.index()].next.clone()
            } else {
                EndOfBlock {
                    source: all_blocks[current.index()].next.source.clone(),
                    instruction: ControlInst::Jump { target },
                }
            },
        });

        new_used_blocks.push(new_block_index);

        reachability_graph
            .for_code
            .entry(new_block_index)
            .or_insert(Reachability::default())
            .always_reachable = true;
        update_references(all_blocks, reachability_graph, None, new_block_index, Default::default());
        reachability_graph.for_code.get_mut(&new_block_index).unwrap().always_reachable = false;

        let references = gather_references(&all_blocks[current.index()]);
        *all_blocks[current.index()].next.instruction.fallthrough_target_mut().unwrap() = new_block_index;
        update_references(all_blocks, reachability_graph, None, current, references);
    }

    new_used_blocks
}

fn merge_consecutive_fallthrough_blocks(
    all_blocks: &mut [BasicBlock<AnyTarget, BlockTarget>],
    reachability_graph: &mut ReachabilityGraph,
    section_to_block: &mut HashMap<SectionTarget, BlockTarget>,
    used_blocks: &mut Vec<BlockTarget>,
) {
    if used_blocks.len() < 2 {
        return;
    }

    let mut removed = HashSet::new();
    for nth_block in 0..used_blocks.len() - 1 {
        let current = used_blocks[nth_block];
        let next = used_blocks[nth_block + 1];
        if !all_blocks[current.index()].ops.is_empty() {
            continue;
        }

        {
            let ControlInst::Jump { target } = all_blocks[current.index()].next.instruction else {
                continue;
            };
            if target != next {
                continue;
            }
        }

        let current_reachability = reachability_graph.for_code.get_mut(&current).unwrap();
        if current_reachability.always_reachable_or_exported() {
            continue;
        }

        let referenced_by_code: BTreeSet<BlockTarget> = current_reachability
            .reachable_from
            .iter()
            .copied()
            .chain(current_reachability.address_taken_in.iter().copied())
            .collect();

        let referenced_by_data: BTreeSet<SectionIndex> = if !current_reachability.referenced_by_data.is_empty() {
            let section_targets: Vec<SectionTarget> = section_to_block
                .iter()
                .filter(|&(_, block_target)| *block_target == current)
                .map(|(section_target, _)| *section_target)
                .collect();
            for section_target in section_targets {
                section_to_block.insert(section_target, next);
            }

            let referenced_by_data = core::mem::take(&mut current_reachability.referenced_by_data);
            for section_index in &referenced_by_data {
                if let Some(list) = reachability_graph.code_references_in_data_section.get_mut(section_index) {
                    list.retain(|&target| target != current);
                }
            }

            remove_code_if_globally_unreachable(all_blocks, reachability_graph, None, current);

            reachability_graph
                .for_code
                .get_mut(&next)
                .unwrap()
                .referenced_by_data
                .extend(referenced_by_data.iter().copied());

            referenced_by_data
        } else {
            Default::default()
        };

        for dep in referenced_by_code {
            let references = gather_references(&all_blocks[dep.index()]);
            for (_, op) in &mut all_blocks[dep.index()].ops {
                *op = op
                    .map_target(|target| {
                        Ok::<_, ()>(if target == AnyTarget::Code(current) {
                            AnyTarget::Code(next)
                        } else {
                            target
                        })
                    })
                    .unwrap();
            }

            all_blocks[dep.index()].next.instruction = all_blocks[dep.index()]
                .next
                .instruction
                .map_target(|target| Ok::<_, ()>(if target == current { next } else { target }))
                .unwrap();

            update_references(all_blocks, reachability_graph, None, dep, references);
        }

        for section_index in referenced_by_data {
            remove_if_data_is_globally_unreachable(all_blocks, reachability_graph, None, section_index);
        }

        assert!(
            !reachability_graph.is_code_reachable(current),
            "block {current:?} still reachable: {:#?}",
            reachability_graph.for_code.get(&current)
        );
        removed.insert(current);
    }

    used_blocks.retain(|current| !removed.contains(current));
}

fn spill_fake_registers(
    section_regspill: SectionIndex,
    all_blocks: &mut [BasicBlock<AnyTarget, BlockTarget>],
    reachability_graph: &mut ReachabilityGraph,
    imports: &[Import],
    used_blocks: &[BlockTarget],
    regspill_size: &mut usize,
    is_rv64: bool,
) {
    struct RegAllocBlock<'a> {
        instructions: &'a [Vec<regalloc2::Operand>],
        num_vregs: usize,
    }

    impl<'a> regalloc2::Function for RegAllocBlock<'a> {
        fn num_insts(&self) -> usize {
            self.instructions.len()
        }

        fn num_blocks(&self) -> usize {
            1
        }

        fn entry_block(&self) -> regalloc2::Block {
            regalloc2::Block(0)
        }

        fn block_insns(&self, _block: regalloc2::Block) -> regalloc2::InstRange {
            regalloc2::InstRange::forward(regalloc2::Inst(0), regalloc2::Inst(self.instructions.len() as u32))
        }

        fn block_succs(&self, _block: regalloc2::Block) -> &[regalloc2::Block] {
            &[]
        }

        fn block_preds(&self, _block: regalloc2::Block) -> &[regalloc2::Block] {
            &[]
        }

        fn block_params(&self, _block: regalloc2::Block) -> &[regalloc2::VReg] {
            &[]
        }

        fn is_ret(&self, insn: regalloc2::Inst) -> bool {
            insn.0 as usize + 1 == self.instructions.len()
        }

        fn is_branch(&self, _insn: regalloc2::Inst) -> bool {
            false
        }

        fn branch_blockparams(&self, _block: regalloc2::Block, _insn: regalloc2::Inst, _succ_idx: usize) -> &[regalloc2::VReg] {
            unimplemented!();
        }

        fn inst_operands(&self, insn: regalloc2::Inst) -> &[regalloc2::Operand] {
            &self.instructions[insn.0 as usize]
        }

        fn inst_clobbers(&self, _insn: regalloc2::Inst) -> regalloc2::PRegSet {
            regalloc2::PRegSet::empty()
        }

        fn num_vregs(&self) -> usize {
            self.num_vregs
        }

        fn spillslot_size(&self, _regclass: regalloc2::RegClass) -> usize {
            1
        }
    }

    let fake_mask = RegMask::fake();
    for current in used_blocks {
        let block = &mut all_blocks[current.index()];
        let Some(start_at) = block
            .ops
            .iter()
            .position(|(_, instruction)| !((instruction.src_mask(imports) | instruction.dst_mask(imports)) & fake_mask).is_empty())
        else {
            continue;
        };

        let end_at = {
            let mut end_at = start_at + 1;
            for index in start_at..block.ops.len() {
                let instruction = block.ops[index].1;
                if !((instruction.src_mask(imports) | instruction.dst_mask(imports)) & fake_mask).is_empty() {
                    end_at = index + 1;
                }
            }
            end_at
        };

        // This block uses one or more "fake" registers which are not supported by the VM.
        //
        // So we have to spill those register into memory and modify the block in such a way
        // that it only uses "real" registers natively supported by the VM.
        //
        // This is not going to be particularily pretty nor very fast at run time, but it is done only as the last restort.

        let mut counter = 0;
        let mut reg_to_value_index: [usize; Reg::ALL.len()] = Default::default();
        let mut instructions = Vec::new();

        let mut prologue = Vec::new();
        for reg in RegMask::all() {
            let value_index = counter;
            counter += 1;
            reg_to_value_index[reg as usize] = value_index;
            prologue.push(regalloc2::Operand::new(
                regalloc2::VReg::new(value_index, regalloc2::RegClass::Int),
                regalloc2::OperandConstraint::FixedReg(regalloc2::PReg::new(reg as usize, regalloc2::RegClass::Int)),
                regalloc2::OperandKind::Def,
                regalloc2::OperandPos::Late,
            ));
        }

        instructions.push(prologue);

        for nth_instruction in start_at..end_at {
            let (_, instruction) = &block.ops[nth_instruction];
            let mut operands = Vec::new();

            for (reg, kind) in instruction.operands(imports) {
                match kind {
                    OpKind::Write => {
                        let value_index = counter;
                        counter += 1;
                        reg_to_value_index[reg as usize] = value_index;
                        operands.push(regalloc2::Operand::new(
                            regalloc2::VReg::new(value_index, regalloc2::RegClass::Int),
                            if reg.fake_register_index().is_none() {
                                regalloc2::OperandConstraint::FixedReg(regalloc2::PReg::new(reg as usize, regalloc2::RegClass::Int))
                            } else {
                                regalloc2::OperandConstraint::Reg
                            },
                            regalloc2::OperandKind::Def,
                            regalloc2::OperandPos::Late,
                        ));
                    }
                    OpKind::Read => {
                        let value_index = reg_to_value_index[reg as usize];
                        operands.push(regalloc2::Operand::new(
                            regalloc2::VReg::new(value_index, regalloc2::RegClass::Int),
                            if reg.fake_register_index().is_none() {
                                regalloc2::OperandConstraint::FixedReg(regalloc2::PReg::new(reg as usize, regalloc2::RegClass::Int))
                            } else {
                                regalloc2::OperandConstraint::Reg
                            },
                            regalloc2::OperandKind::Use,
                            regalloc2::OperandPos::Early,
                        ));
                    }
                    OpKind::ReadWrite => {
                        let value_index_read = reg_to_value_index[reg as usize];
                        operands.push(regalloc2::Operand::new(
                            regalloc2::VReg::new(value_index_read, regalloc2::RegClass::Int),
                            if reg.fake_register_index().is_none() {
                                regalloc2::OperandConstraint::FixedReg(regalloc2::PReg::new(reg as usize, regalloc2::RegClass::Int))
                            } else {
                                regalloc2::OperandConstraint::Reg
                            },
                            regalloc2::OperandKind::Use,
                            regalloc2::OperandPos::Early,
                        ));

                        let value_index_write = counter;
                        counter += 1;

                        reg_to_value_index[reg as usize] = value_index_write;
                        operands.push(regalloc2::Operand::new(
                            regalloc2::VReg::new(value_index_write, regalloc2::RegClass::Int),
                            regalloc2::OperandConstraint::Reuse(operands.len() - 1),
                            regalloc2::OperandKind::Def,
                            regalloc2::OperandPos::Late,
                        ));
                    }
                }
            }

            instructions.push(operands);
        }

        let mut epilogue = Vec::new();
        for reg in RegMask::all() & !RegMask::fake() {
            let value_index = reg_to_value_index[reg as usize];
            epilogue.push(regalloc2::Operand::new(
                regalloc2::VReg::new(value_index, regalloc2::RegClass::Int),
                regalloc2::OperandConstraint::FixedReg(regalloc2::PReg::new(reg as usize, regalloc2::RegClass::Int)),
                regalloc2::OperandKind::Use,
                regalloc2::OperandPos::Early,
            ));
        }

        instructions.push(epilogue);

        let alloc_block = RegAllocBlock {
            instructions: &instructions,
            num_vregs: counter,
        };

        let env = regalloc2::MachineEnv {
            preferred_regs_by_class: [
                [Reg::T0, Reg::T1, Reg::T2]
                    .map(|reg| regalloc2::PReg::new(reg as usize, regalloc2::RegClass::Int))
                    .into(),
                vec![],
                vec![],
            ],
            non_preferred_regs_by_class: [
                [Reg::S0, Reg::S1]
                    .map(|reg| regalloc2::PReg::new(reg as usize, regalloc2::RegClass::Int))
                    .into(),
                vec![],
                vec![],
            ],
            scratch_by_class: [None, None, None],
            fixed_stack_slots: vec![],
        };

        let opts = regalloc2::RegallocOptions {
            validate_ssa: true,
            ..regalloc2::RegallocOptions::default()
        };

        let output = match regalloc2::run(&alloc_block, &env, &opts) {
            Ok(output) => output,
            Err(regalloc2::RegAllocError::SSA(vreg, inst)) => {
                let nth_instruction: isize = inst.index() as isize - 1 + start_at as isize;
                let instruction = block.ops.get(nth_instruction as usize).map(|(_, instruction)| instruction);
                panic!("internal error: register allocation failed because of invalid SSA for {vreg} for instruction {instruction:?}");
            }
            Err(error) => {
                panic!("internal error: register allocation failed: {error}")
            }
        };

        let mut buffer = Vec::new();
        let mut edits = output.edits.into_iter().peekable();
        for nth_instruction in start_at..=end_at {
            while let Some((next_edit_at, edit)) = edits.peek() {
                let target_nth_instruction: isize = next_edit_at.inst().index() as isize - 1 + start_at as isize;
                if target_nth_instruction < 0
                    || target_nth_instruction > nth_instruction as isize
                    || (target_nth_instruction == nth_instruction as isize && next_edit_at.pos() == regalloc2::InstPosition::After)
                {
                    break;
                }

                let target_nth_instruction = target_nth_instruction as usize;
                let regalloc2::Edit::Move { from: src, to: dst } = edit.clone();

                // Advance the iterator so that we can use `continue` later.
                edits.next();

                let reg_size = if is_rv64 { 8 } else { 4 };
                let src_reg = src.as_reg();
                let dst_reg = dst.as_reg();
                let new_instruction = match (dst_reg, src_reg) {
                    (Some(dst_reg), None) => {
                        let dst_reg = Reg::from_usize(dst_reg.hw_enc()).unwrap();
                        let src_slot = src.as_stack().unwrap();
                        let offset = src_slot.index() * reg_size;
                        *regspill_size = core::cmp::max(*regspill_size, offset + reg_size);
                        BasicInst::LoadAbsolute {
                            kind: if is_rv64 { LoadKind::U64 } else { LoadKind::U32 },
                            dst: dst_reg,
                            target: SectionTarget {
                                section_index: section_regspill,
                                offset: offset as u64,
                            },
                        }
                    }
                    (None, Some(src_reg)) => {
                        let src_reg = Reg::from_usize(src_reg.hw_enc()).unwrap();
                        let dst_slot = dst.as_stack().unwrap();
                        let offset = dst_slot.index() * reg_size;
                        *regspill_size = core::cmp::max(*regspill_size, offset + reg_size);
                        BasicInst::StoreAbsolute {
                            kind: if is_rv64 { StoreKind::U64 } else { StoreKind::U32 },
                            src: src_reg.into(),
                            target: SectionTarget {
                                section_index: section_regspill,
                                offset: offset as u64,
                            },
                        }
                    }
                    (Some(dst_reg), Some(src_reg)) => {
                        let dst_reg = Reg::from_usize(dst_reg.hw_enc()).unwrap();
                        let src_reg = Reg::from_usize(src_reg.hw_enc()).unwrap();
                        if src_reg == dst_reg {
                            continue;
                        }
                        BasicInst::MoveReg {
                            dst: dst_reg,
                            src: src_reg,
                        }
                    }
                    // Won't be emitted according to `regalloc2` docs.
                    (None, None) => unreachable!(),
                };

                log::trace!("Injected:\n     {new_instruction:?}");

                let source = block.ops.get(target_nth_instruction).or(block.ops.last()).unwrap().0.clone();
                buffer.push((source, new_instruction));
            }

            if nth_instruction == end_at {
                assert!(edits.next().is_none());
                break;
            }

            let (source, instruction) = &block.ops[nth_instruction];
            let mut alloc_index = output.inst_alloc_offsets[nth_instruction - start_at + 1];
            let new_instruction = instruction
                .map_register(|reg, _| {
                    let alloc = &output.allocs[alloc_index as usize];
                    alloc_index += 1;

                    assert_eq!(alloc.kind(), regalloc2::AllocationKind::Reg);
                    let allocated_reg = Reg::from_usize(alloc.as_reg().unwrap().hw_enc() as usize).unwrap();
                    if reg.fake_register_index().is_none() {
                        assert_eq!(reg, allocated_reg);
                    } else {
                        assert_ne!(reg, allocated_reg);
                        assert!(allocated_reg.fake_register_index().is_none());
                    }

                    allocated_reg
                })
                .unwrap_or(*instruction);

            if *instruction == new_instruction {
                log::trace!("Unmodified:\n     {instruction:?}");
            } else {
                log::trace!("Replaced:\n     {instruction:?}\n  -> {new_instruction:?}");
            }

            buffer.push((source.clone(), new_instruction));
        }

        assert!(edits.next().is_none());

        reachability_graph
            .for_data
            .entry(section_regspill)
            .or_default()
            .address_taken_in
            .insert(*current);

        block.ops.splice(start_at..end_at, buffer);
    }

    for current in used_blocks {
        if all_blocks[current.index()]
            .ops
            .iter()
            .any(|(_, instruction)| !((instruction.src_mask(imports) | instruction.dst_mask(imports)) & fake_mask).is_empty())
        {
            panic!("internal error: not all fake registers were removed")
        }
    }
}

fn replace_immediates_with_registers(
    all_blocks: &mut [BasicBlock<AnyTarget, BlockTarget>],
    imports: &[Import],
    used_blocks: &[BlockTarget],
) {
    let mut imm_to_reg: HashMap<u32, RegMask> = HashMap::new();
    for block_target in used_blocks {
        let mut reg_to_imm: [Option<u32>; Reg::ALL.len()] = [None; Reg::ALL.len()];
        imm_to_reg.clear();

        // If there already exists a register which contains a given immediate value
        // then there's no point in duplicating it here again; just use that register.
        macro_rules! replace {
            ($src:ident) => {
                if let RegImm::Imm(imm) = $src {
                    if *imm != 0 {
                        let mask = imm_to_reg.get(imm).copied().unwrap_or(RegMask::empty());
                        if let Some(reg) = mask.into_iter().next() {
                            *$src = RegImm::Reg(reg);
                        }
                    }
                }
            };
        }

        for (_, op) in &mut all_blocks[block_target.index()].ops {
            match op {
                BasicInst::LoadImmediate { dst, imm } => {
                    imm_to_reg.entry(*imm as u32).or_insert(RegMask::empty()).insert(*dst);
                    reg_to_imm[*dst as usize] = Some(*imm as u32);
                    continue;
                }
                BasicInst::AnyAny {
                    kind,
                    ref mut src1,
                    ref mut src2,
                    ..
                } => {
                    replace!(src1);
                    if !matches!(
                        kind,
                        AnyAnyKind::ShiftLogicalLeft | AnyAnyKind::ShiftLogicalRight | AnyAnyKind::ShiftArithmeticRight
                    ) {
                        replace!(src2);
                    }
                }
                BasicInst::StoreAbsolute { src, .. } => {
                    replace!(src);
                }
                BasicInst::StoreIndirect { src, .. } => {
                    replace!(src);
                }
                BasicInst::Cmov { src, .. } => {
                    replace!(src);
                }
                _ => {}
            }

            for reg in op.dst_mask(imports) {
                if let Some(imm) = reg_to_imm[reg as usize].take() {
                    imm_to_reg.get_mut(&imm).unwrap().remove(reg);
                }
            }
        }

        if let ControlInst::Branch {
            ref mut src1,
            ref mut src2,
            ..
        } = all_blocks[block_target.index()].next.instruction
        {
            replace!(src1);
            replace!(src2);
        }
    }
}

fn harvest_all_jump_targets<H>(
    elf: &Elf<H>,
    data_sections_set: &HashSet<SectionIndex>,
    code_sections_set: &HashSet<SectionIndex>,
    instructions: &[(Source, InstExt<SectionTarget, SectionTarget>)],
    relocations: &BTreeMap<SectionTarget, RelocationKind>,
    exports: &[Export],
) -> Result<HashSet<SectionTarget>, ProgramFromElfError>
where
    H: object::read::elf::FileHeader<Endian = object::LittleEndian>,
{
    let mut all_jump_targets = HashSet::new();
    for (_, instruction) in instructions {
        match instruction {
            InstExt::Basic(instruction) => {
                let (data_target, code_or_data_target) = instruction.target();
                if let Some(target) = data_target {
                    if !data_sections_set.contains(&target.section_index) {
                        return Err(ProgramFromElfError::other(
                            "found basic instruction which refers to a non-data section",
                        ));
                    }
                }

                if let Some(target) = code_or_data_target {
                    if code_sections_set.contains(&target.section_index) {
                        if all_jump_targets.insert(target) {
                            log::trace!("Adding jump target: {target} (referenced indirectly by code)");
                        }
                    } else if !data_sections_set.contains(&target.section_index) {
                        return Err(ProgramFromElfError::other(
                            "found basic instruction which refers to neither a data nor a text section",
                        ));
                    }
                }
            }
            InstExt::Control(instruction) => {
                for target in instruction.targets().into_iter().flatten() {
                    if !code_sections_set.contains(&target.section_index) {
                        return Err(ProgramFromElfError::other(
                            "found control instruction which refers to a non-text section",
                        ));
                    }

                    if all_jump_targets.insert(*target) {
                        log::trace!("Adding jump target: {target} (referenced by a control instruction)");
                    }
                }
            }
        }
    }

    for (source_location, relocation) in relocations {
        if !data_sections_set.contains(&source_location.section_index) {
            continue;
        }

        for target in relocation.targets().into_iter().flatten() {
            #[allow(clippy::collapsible_if)]
            if code_sections_set.contains(&target.section_index) {
                if all_jump_targets.insert(target) {
                    log::trace!(
                        "Adding jump target: {target} (referenced by relocation from {source_location} in '{}')",
                        elf.section_by_index(source_location.section_index).name()
                    );
                }
            }
        }
    }

    for export in exports {
        let target = export.location;
        if !code_sections_set.contains(&target.section_index) {
            return Err(ProgramFromElfError::other("export points to a non-code section"));
        }

        if all_jump_targets.insert(target) {
            log::trace!("Adding jump target: {target} (referenced by export)");
        }
    }

    Ok(all_jump_targets)
}

struct VecSet<T> {
    vec: Vec<T>,
    set: HashSet<T>,
}

impl<T> VecSet<T> {
    fn new() -> Self {
        Self {
            vec: Vec::new(),
            set: HashSet::new(),
        }
    }

    fn pop_unique(&mut self) -> Option<T> {
        self.vec.pop()
    }

    fn pop_non_unique(&mut self) -> Option<T>
    where
        T: core::hash::Hash + Eq,
    {
        let value = self.vec.pop()?;
        self.set.remove(&value);
        Some(value)
    }

    fn push(&mut self, value: T)
    where
        T: core::hash::Hash + Eq + Clone,
    {
        if self.set.insert(value.clone()) {
            self.vec.push(value);
        }
    }

    fn is_empty(&self) -> bool {
        self.vec.is_empty()
    }

    fn into_set(self) -> HashSet<T> {
        self.set
    }
}

#[derive(PartialEq, Eq, Debug, Default)]
struct ReachabilityGraph {
    for_code: BTreeMap<BlockTarget, Reachability>,
    for_data: BTreeMap<SectionIndex, Reachability>,
    code_references_in_data_section: BTreeMap<SectionIndex, Vec<BlockTarget>>,
    data_references_in_data_section: BTreeMap<SectionIndex, Vec<SectionIndex>>,
}

impl ReachabilityGraph {
    fn reachable_block_count(&self) -> usize {
        self.for_code.len()
    }

    fn is_code_reachable(&self, block_target: BlockTarget) -> bool {
        if let Some(reachability) = self.for_code.get(&block_target) {
            assert!(
                !reachability.is_unreachable(),
                "Block {block_target:?} is unreachable and yet it wasn't removed from the graph!"
            );
            true
        } else {
            false
        }
    }

    fn is_data_section_reachable(&self, section_index: SectionIndex) -> bool {
        if let Some(reachability) = self.for_data.get(&section_index) {
            assert!(!reachability.is_unreachable());
            true
        } else {
            false
        }
    }

    fn mark_data_section_reachable(&mut self, section_index: SectionIndex) {
        self.for_data.entry(section_index).or_default().always_reachable = true;
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Default)]
struct Reachability {
    reachable_from: BTreeSet<BlockTarget>,
    address_taken_in: BTreeSet<BlockTarget>,
    referenced_by_data: BTreeSet<SectionIndex>,
    always_reachable: bool,
    always_dynamically_reachable: bool,
    exports: Vec<usize>,
}

impl Reachability {
    fn is_only_reachable_from(&self, block_target: BlockTarget) -> bool {
        !self.always_reachable
            && !self.always_dynamically_reachable
            && self.referenced_by_data.is_empty()
            && self.address_taken_in.is_empty()
            && self.reachable_from.len() == 1
            && self.reachable_from.contains(&block_target)
            && self.exports.is_empty()
    }

    fn is_unreachable(&self) -> bool {
        self.reachable_from.is_empty()
            && self.address_taken_in.is_empty()
            && self.referenced_by_data.is_empty()
            && !self.always_reachable
            && !self.always_dynamically_reachable
            && self.exports.is_empty()
    }

    fn is_dynamically_reachable(&self) -> bool {
        !self.address_taken_in.is_empty() || !self.referenced_by_data.is_empty() || self.always_dynamically_reachable
    }

    fn always_reachable_or_exported(&self) -> bool {
        self.always_reachable || !self.exports.is_empty()
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
enum ExtRef {
    Address(BlockTarget),
    Jump(BlockTarget),
    DataAddress(SectionIndex),
}

fn each_reference_for_basic_instruction(instruction: &BasicInst<AnyTarget>, mut cb: impl FnMut(ExtRef)) {
    let (data_target, code_or_data_target) = instruction.target();
    if let Some(target) = data_target {
        cb(ExtRef::DataAddress(target.section_index));
    }

    if let Some(target) = code_or_data_target {
        match target {
            AnyTarget::Code(target) => {
                cb(ExtRef::Address(target));
            }
            AnyTarget::Data(target) => {
                cb(ExtRef::DataAddress(target.section_index));
            }
        }
    }
}

fn each_reference_for_control_instruction(instruction: &ControlInst<BlockTarget>, mut cb: impl FnMut(ExtRef)) {
    match *instruction {
        ControlInst::Jump { target } => {
            cb(ExtRef::Jump(target));
        }
        ControlInst::Call { target, target_return, .. } => {
            cb(ExtRef::Jump(target));
            cb(ExtRef::Address(target_return));
        }
        ControlInst::CallIndirect { target_return, .. } => {
            cb(ExtRef::Address(target_return));
        }
        ControlInst::Branch {
            target_true, target_false, ..
        } => {
            cb(ExtRef::Jump(target_true));
            cb(ExtRef::Jump(target_false));
        }
        ControlInst::JumpIndirect { .. } | ControlInst::Unimplemented => {}
    }
}

fn each_reference(block: &BasicBlock<AnyTarget, BlockTarget>, mut cb: impl FnMut(ExtRef)) {
    for (_, instruction) in &block.ops {
        each_reference_for_basic_instruction(instruction, &mut cb);
    }

    each_reference_for_control_instruction(&block.next.instruction, cb);
}

fn calculate_reachability(
    section_to_block: &HashMap<SectionTarget, BlockTarget>,
    all_blocks: &[BasicBlock<AnyTarget, BlockTarget>],
    data_sections_set: &HashSet<SectionIndex>,
    exports: &[Export],
    relocations: &BTreeMap<SectionTarget, RelocationKind>,
) -> Result<ReachabilityGraph, ProgramFromElfError> {
    let mut graph = ReachabilityGraph::default();
    let mut data_queue: VecSet<SectionTarget> = VecSet::new();
    let mut block_queue: VecSet<BlockTarget> = VecSet::new();
    let mut section_queue: VecSet<SectionIndex> = VecSet::new();
    let mut relocations_per_section: HashMap<SectionIndex, Vec<&RelocationKind>> = HashMap::new();
    for (relocation_location, relocation) in relocations.iter() {
        relocations_per_section
            .entry(relocation_location.section_index)
            .or_insert_with(Vec::new)
            .push(relocation);
    }

    for (export_index, export) in exports.iter().enumerate() {
        let Some(&block_target) = section_to_block.get(&export.location) else {
            return Err(ProgramFromElfError::other("export points to a non-block"));
        };

        graph.for_code.entry(block_target).or_default().exports.push(export_index);
        block_queue.push(block_target);
    }

    while !block_queue.is_empty() || !data_queue.is_empty() {
        while let Some(current_block) = block_queue.pop_unique() {
            each_reference(&all_blocks[current_block.index()], |ext| match ext {
                ExtRef::Jump(target) => {
                    graph.for_code.entry(target).or_default().reachable_from.insert(current_block);
                    block_queue.push(target);
                }
                ExtRef::Address(target) => {
                    graph.for_code.entry(target).or_default().address_taken_in.insert(current_block);
                    block_queue.push(target)
                }
                ExtRef::DataAddress(target) => {
                    graph.for_data.entry(target).or_default().address_taken_in.insert(current_block);
                    section_queue.push(target)
                }
            });
        }

        while let Some(target) = data_queue.pop_unique() {
            assert!(!section_to_block.contains_key(&target));
            assert!(data_sections_set.contains(&target.section_index));
            section_queue.push(target.section_index);
        }

        while let Some(section_index) = section_queue.pop_unique() {
            let Some(local_relocations) = relocations_per_section.get(&section_index) else {
                continue;
            };
            for relocation in local_relocations {
                for relocation_target in relocation.targets().into_iter().flatten() {
                    if let Some(&block_target) = section_to_block.get(&relocation_target) {
                        graph
                            .code_references_in_data_section
                            .entry(section_index)
                            .or_default()
                            .push(block_target);

                        graph
                            .for_code
                            .entry(block_target)
                            .or_default()
                            .referenced_by_data
                            .insert(section_index);

                        block_queue.push(block_target);
                    } else {
                        graph
                            .data_references_in_data_section
                            .entry(section_index)
                            .or_default()
                            .push(relocation_target.section_index);

                        graph
                            .for_data
                            .entry(relocation_target.section_index)
                            .or_default()
                            .referenced_by_data
                            .insert(section_index);

                        data_queue.push(relocation_target);
                    }
                }
            }
        }
    }

    for list in graph.code_references_in_data_section.values_mut() {
        list.sort_unstable();
        list.dedup();
    }

    for list in graph.data_references_in_data_section.values_mut() {
        list.sort_unstable();
        list.dedup();
    }

    for reachability in graph.for_code.values() {
        assert!(!reachability.is_unreachable());
    }

    for reachability in graph.for_data.values() {
        assert!(!reachability.is_unreachable());
    }

    assert_eq!(block_queue.set.len(), graph.for_code.len());
    Ok(graph)
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Default)]
struct RegMask(u32);

impl core::fmt::Debug for RegMask {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
        fmt.write_str("(")?;
        let mut is_first = true;
        for (nth, reg) in Reg::ALL.iter().enumerate() {
            if self.0 & (1 << nth) != 0 {
                if is_first {
                    is_first = false;
                } else {
                    fmt.write_str("|")?;
                }
                fmt.write_str(reg.name())?;
            }
        }
        fmt.write_str(")")?;
        Ok(())
    }
}

struct RegMaskIter {
    mask: u32,
    remaining: &'static [Reg],
}

impl Iterator for RegMaskIter {
    type Item = Reg;
    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let reg = *self.remaining.get(0)?;
            let is_set = (self.mask & 1) != 0;
            self.remaining = &self.remaining[1..];
            self.mask >>= 1;

            if is_set {
                return Some(reg);
            }
        }
    }
}

impl IntoIterator for RegMask {
    type Item = Reg;
    type IntoIter = RegMaskIter;

    fn into_iter(self) -> Self::IntoIter {
        RegMaskIter {
            mask: self.0,
            remaining: &Reg::ALL,
        }
    }
}

impl RegMask {
    fn all() -> Self {
        RegMask((1 << Reg::ALL.len()) - 1)
    }

    fn fake() -> Self {
        let mut mask = RegMask(0);
        for reg in Reg::FAKE {
            mask.insert(reg);
        }
        mask
    }

    fn empty() -> Self {
        RegMask(0)
    }

    fn is_empty(self) -> bool {
        self == Self::empty()
    }

    fn remove(&mut self, mask: impl Into<RegMask>) {
        *self &= !mask.into();
    }

    fn insert(&mut self, mask: impl Into<RegMask>) {
        *self |= mask.into();
    }
}

impl From<Reg> for RegMask {
    fn from(reg: Reg) -> Self {
        RegMask(1 << (reg as usize))
    }
}

impl From<RegImm> for RegMask {
    fn from(rm: RegImm) -> Self {
        match rm {
            RegImm::Reg(reg) => reg.into(),
            RegImm::Imm(_) => Self::empty(),
        }
    }
}

impl core::ops::Not for RegMask {
    type Output = Self;
    fn not(self) -> Self {
        RegMask(!self.0)
    }
}

impl core::ops::BitAnd for RegMask {
    type Output = Self;
    fn bitand(self, rhs: RegMask) -> Self {
        RegMask(self.0 & rhs.0)
    }
}

impl core::ops::BitAnd<Reg> for RegMask {
    type Output = Self;
    fn bitand(self, rhs: Reg) -> Self {
        self & RegMask::from(rhs)
    }
}

impl core::ops::BitAndAssign for RegMask {
    fn bitand_assign(&mut self, rhs: RegMask) {
        self.0 &= rhs.0;
    }
}

impl core::ops::BitAndAssign<Reg> for RegMask {
    fn bitand_assign(&mut self, rhs: Reg) {
        self.bitand_assign(RegMask::from(rhs));
    }
}

impl core::ops::BitOr for RegMask {
    type Output = Self;
    fn bitor(self, rhs: RegMask) -> Self {
        RegMask(self.0 | rhs.0)
    }
}

impl core::ops::BitOr<Reg> for RegMask {
    type Output = Self;
    fn bitor(self, rhs: Reg) -> Self {
        self | RegMask::from(rhs)
    }
}

impl core::ops::BitOrAssign for RegMask {
    fn bitor_assign(&mut self, rhs: RegMask) {
        self.0 |= rhs.0;
    }
}

impl core::ops::BitOrAssign<Reg> for RegMask {
    fn bitor_assign(&mut self, rhs: Reg) {
        self.bitor_assign(RegMask::from(rhs));
    }
}

#[test]
fn test_all_regs_indexes() {
    for (index, reg) in Reg::ALL.iter().enumerate() {
        assert_eq!(index, *reg as usize);
    }
}

#[derive(Copy, Clone)]
struct JumpTarget {
    static_target: u32,
    dynamic_target: Option<u32>,
}

fn build_jump_table(
    total_block_count: usize,
    used_blocks: &[BlockTarget],
    reachability_graph: &ReachabilityGraph,
) -> (Vec<u32>, Vec<Option<JumpTarget>>) {
    let mut jump_target_for_block: Vec<Option<JumpTarget>> = Vec::new();
    jump_target_for_block.resize(total_block_count, None);

    let mut jump_table = Vec::new();
    for (static_target, current) in used_blocks.iter().enumerate() {
        let reachability = reachability_graph.for_code.get(current).unwrap();
        assert!(!reachability.is_unreachable());

        let dynamic_target = if reachability.is_dynamically_reachable() {
            let dynamic_target: u32 = (jump_table.len() + 1).try_into().expect("jump table index overflow");
            jump_table.push(static_target.try_into().expect("jump table index overflow"));
            Some(dynamic_target)
        } else {
            None
        };

        jump_target_for_block[current.index()] = Some(JumpTarget {
            static_target: static_target.try_into().expect("jump table index overflow"),
            dynamic_target,
        });
    }

    (jump_table, jump_target_for_block)
}

fn calculate_whether_can_fallthrough(
    all_blocks: &[BasicBlock<AnyTarget, BlockTarget>],
    used_blocks: &[BlockTarget],
) -> HashSet<BlockTarget> {
    let mut can_fallthrough_to_next_block: HashSet<BlockTarget> = HashSet::new();
    for window in used_blocks.windows(2) {
        match all_blocks[window[0].index()].next.instruction {
            ControlInst::Jump { target }
            | ControlInst::Branch { target_false: target, .. }
            | ControlInst::Call { target_return: target, .. }
            | ControlInst::CallIndirect { target_return: target, .. } => {
                if target == window[1] {
                    can_fallthrough_to_next_block.insert(window[0]);
                }
            }

            ControlInst::JumpIndirect { .. } | ControlInst::Unimplemented => {}
        }
    }

    can_fallthrough_to_next_block
}

#[allow(clippy::too_many_arguments)]
fn emit_code(
    imports: &[Import],
    base_address_for_section: &HashMap<SectionIndex, u64>,
    section_got: SectionIndex,
    target_to_got_offset: &HashMap<AnyTarget, u64>,
    all_blocks: &[BasicBlock<AnyTarget, BlockTarget>],
    used_blocks: &[BlockTarget],
    used_imports: &HashSet<usize>,
    jump_target_for_block: &[Option<JumpTarget>],
    is_optimized: bool,
    is_rv64: bool,
) -> Result<Vec<(SourceStack, Instruction)>, ProgramFromElfError> {
    use polkavm_common::program::Reg as PReg;
    fn conv_reg(reg: Reg) -> polkavm_common::program::RawReg {
        match reg {
            Reg::RA => PReg::RA,
            Reg::SP => PReg::SP,
            Reg::T0 => PReg::T0,
            Reg::T1 => PReg::T1,
            Reg::T2 => PReg::T2,
            Reg::S0 => PReg::S0,
            Reg::S1 => PReg::S1,
            Reg::A0 => PReg::A0,
            Reg::A1 => PReg::A1,
            Reg::A2 => PReg::A2,
            Reg::A3 => PReg::A3,
            Reg::A4 => PReg::A4,
            Reg::A5 => PReg::A5,
            Reg::E0 | Reg::E1 | Reg::E2 => {
                unreachable!("internal error: temporary register was not spilled into memory");
            }
        }
        .into()
    }

    let can_fallthrough_to_next_block = calculate_whether_can_fallthrough(all_blocks, used_blocks);
    let get_data_address = |target: SectionTarget| -> Result<u32, ProgramFromElfError> {
        if let Some(base_address) = base_address_for_section.get(&target.section_index) {
            let Some(address) = base_address.checked_add(target.offset) else {
                return Err(ProgramFromElfError::other("address overflow when relocating"));
            };

            let Ok(address) = address.try_into() else {
                return Err(ProgramFromElfError::other("address overflow when casting"));
            };

            Ok(address)
        } else {
            Err(ProgramFromElfError::other("internal error: section with no base address"))
        }
    };

    let get_jump_target = |target: BlockTarget| -> Result<JumpTarget, ProgramFromElfError> {
        let Some(jump_target) = jump_target_for_block[target.index()] else {
            return Err(ProgramFromElfError::other("out of range jump target"));
        };

        Ok(jump_target)
    };

    let mut basic_block_delimited = true;
    let mut code: Vec<(SourceStack, Instruction)> = Vec::new();
    for block_target in used_blocks {
        let block = &all_blocks[block_target.index()];

        if !basic_block_delimited {
            basic_block_delimited = true;
            code.push((
                Source {
                    section_index: block.source.section_index,
                    offset_range: (block.source.offset_range.start..block.source.offset_range.start + 4).into(),
                }
                .into(),
                Instruction::fallthrough,
            ));
        }

        macro_rules! codegen {
            (
                args = $args:tt,
                kind = $kind:expr,

                {
                    $($p:pat => $inst:ident,)+
                }
            ) => {
                match $kind {
                    $(
                        $p => Instruction::$inst $args
                    ),+
                }
            }
        }

        for (source, op) in &block.ops {
            let op = match *op {
                BasicInst::LoadImmediate { dst, imm } => Instruction::load_imm(conv_reg(dst), imm as u32),
                BasicInst::LoadImmediate64 { dst, imm } => {
                    if !is_rv64 {
                        unreachable!("internal error: load_imm64 found when processing 32-bit binary")
                    }
                    // todo: change this to load_imm64
                    Instruction::load_imm(conv_reg(dst), imm as u32)
                }
                BasicInst::LoadAbsolute { kind, dst, target } => {
                    codegen! {
                        args = (conv_reg(dst), get_data_address(target)?),
                        kind = kind,
                        {
                            LoadKind::I8 => load_i8,
                            LoadKind::I16 => load_i16,
                            LoadKind::I32 => load_i32,
                            LoadKind::U8 => load_u8,
                            LoadKind::U16 => load_u16,
                            LoadKind::U32 => load_u32,
                            LoadKind::U64 => load_u64,
                        }
                    }
                }
                BasicInst::StoreAbsolute { kind, src, target } => {
                    let target = get_data_address(target)?;
                    match src {
                        RegImm::Reg(src) => {
                            codegen! {
                                args = (conv_reg(src), target),
                                kind = kind,
                                {
                                    StoreKind::U64 => store_u64,
                                    StoreKind::U32 => store_u32,
                                    StoreKind::U16 => store_u16,
                                    StoreKind::U8 => store_u8,
                                }
                            }
                        }
                        RegImm::Imm(value) => {
                            codegen! {
                                args = (target, value),
                                kind = kind,
                                {
                                    StoreKind::U64 => store_imm_u64,
                                    StoreKind::U32 => store_imm_u32,
                                    StoreKind::U16 => store_imm_u16,
                                    StoreKind::U8 => store_imm_u8,
                                }
                            }
                        }
                    }
                }
                BasicInst::LoadIndirect { kind, dst, base, offset } => {
                    codegen! {
                        args = (conv_reg(dst), conv_reg(base), offset as u32),
                        kind = kind,
                        {
                            LoadKind::I8 => load_indirect_i8,
                            LoadKind::I16 => load_indirect_i16,
                            LoadKind::I32 => load_indirect_i32,
                            LoadKind::U8 => load_indirect_u8,
                            LoadKind::U16 => load_indirect_u16,
                            LoadKind::U32 => load_indirect_u32,
                            LoadKind::U64 => load_indirect_u64,
                        }
                    }
                }
                BasicInst::StoreIndirect { kind, src, base, offset } => match src {
                    RegImm::Reg(src) => {
                        codegen! {
                            args = (conv_reg(src), conv_reg(base), offset as u32),
                            kind = kind,
                            {
                                StoreKind::U64 => store_indirect_u64,
                                StoreKind::U32 => store_indirect_u32,
                                StoreKind::U16 => store_indirect_u16,
                                StoreKind::U8 => store_indirect_u8,
                            }
                        }
                    }
                    RegImm::Imm(value) => {
                        codegen! {
                            args = (conv_reg(base), offset as u32, value),
                            kind = kind,
                            {
                                StoreKind::U64 => store_imm_indirect_u64,
                                StoreKind::U32 => store_imm_indirect_u32,
                                StoreKind::U16 => store_imm_indirect_u16,
                                StoreKind::U8 => store_imm_indirect_u8,
                            }
                        }
                    }
                },
                BasicInst::LoadAddress { dst, target } => {
                    let value = match target {
                        AnyTarget::Code(target) => {
                            let value = get_jump_target(target)?.dynamic_target.expect("missing jump target for address");
                            let Some(value) = value.checked_mul(VM_CODE_ADDRESS_ALIGNMENT) else {
                                return Err(ProgramFromElfError::other("overflow when emitting an address load"));
                            };
                            value
                        }
                        AnyTarget::Data(target) => get_data_address(target)?,
                    };

                    Instruction::load_imm(conv_reg(dst), value)
                }
                BasicInst::LoadAddressIndirect { dst, target } => {
                    let Some(&offset) = target_to_got_offset.get(&target) else {
                        return Err(ProgramFromElfError::other(
                            "indirect address load without a corresponding GOT entry",
                        ));
                    };

                    let target = SectionTarget {
                        section_index: section_got,
                        offset,
                    };

                    let value = get_data_address(target)?;
                    Instruction::load_u32(conv_reg(dst), value)
                }
                BasicInst::RegReg { kind, dst, src1, src2 } => {
                    use RegRegKind as K;
                    codegen! {
                        args = (conv_reg(dst), conv_reg(src1), conv_reg(src2)),
                        kind = kind,
                        {
                            K::MulUpperSignedUnsigned => mul_upper_signed_unsigned,
                            K::MulUpperSignedUnsigned64 => mul_upper_signed_unsigned_64,
                            K::Div => div_signed,
                            K::Div64 => div_signed_64,
                            K::DivUnsigned => div_unsigned,
                            K::DivUnsigned64 => div_unsigned_64,
                            K::Rem => rem_signed,
                            K::Rem64 => rem_signed_64,
                            K::RemUnsigned => rem_unsigned,
                            K::RemUnsigned64 => rem_unsigned_64,
                        }
                    }
                }
                BasicInst::MoveReg { dst, src } => Instruction::move_reg(conv_reg(dst), conv_reg(src)),
                BasicInst::AnyAny { kind, dst, src1, src2 } => {
                    use AnyAnyKind as K;
                    use Instruction as I;
                    let dst = conv_reg(dst);
                    match (src1, src2) {
                        (RegImm::Reg(src1), RegImm::Reg(src2)) => {
                            codegen! {
                                args = (dst, conv_reg(src1), conv_reg(src2)),
                                kind = kind,
                                {
                                    K::Add => add,
                                    K::Add64 => add_64,
                                    K::Sub => sub,
                                    K::Sub64 => sub_64,
                                    K::ShiftLogicalLeft => shift_logical_left,
                                    K::ShiftLogicalLeft64 => shift_logical_left_64,
                                    K::SetLessThanSigned => set_less_than_signed,
                                    K::SetLessThanSigned64 => set_less_than_signed_64,
                                    K::SetLessThanUnsigned => set_less_than_unsigned,
                                    K::SetLessThanUnsigned64 => set_less_than_unsigned_64,
                                    K::Xor => xor,
                                    K::Xor64 => xor_64,
                                    K::ShiftLogicalRight => shift_logical_right,
                                    K::ShiftLogicalRight64 => shift_logical_right_64,
                                    K::ShiftArithmeticRight => shift_arithmetic_right,
                                    K::ShiftArithmeticRight64 => shift_arithmetic_right_64,
                                    K::Or => or,
                                    K::Or64 => or_64,
                                    K::And => and,
                                    K::And64 => and_64,
                                    K::Mul => mul,
                                    K::Mul64 => mul_64,
                                    K::MulUpperSignedSigned => mul_upper_signed_signed,
                                    K::MulUpperSignedSigned64 => mul_upper_signed_signed_64,
                                    K::MulUpperUnsignedUnsigned => mul_upper_unsigned_unsigned,
                                    K::MulUpperUnsignedUnsigned64 => mul_upper_unsigned_unsigned_64,
                                }
                            }
                        }
                        (RegImm::Reg(src1), RegImm::Imm(src2)) => {
                            let src1 = conv_reg(src1);
                            match kind {
                                K::Add => I::add_imm(dst, src1, src2),
                                K::Add64 => I::add_64_imm(dst, src1, src2),
                                K::Sub => I::add_imm(dst, src1, (-(src2 as i32)) as u32),
                                K::Sub64 => I::add_64_imm(dst, src1, (-(src2 as i32)) as u32),
                                K::ShiftLogicalLeft => I::shift_logical_left_imm(dst, src1, src2),
                                K::ShiftLogicalLeft64 => I::shift_logical_left_64_imm(dst, src1, src2),
                                K::SetLessThanSigned => I::set_less_than_signed_imm(dst, src1, src2),
                                K::SetLessThanSigned64 => I::set_less_than_signed_64_imm(dst, src1, src2),
                                K::SetLessThanUnsigned => I::set_less_than_unsigned_imm(dst, src1, src2),
                                K::SetLessThanUnsigned64 => I::set_less_than_unsigned_64_imm(dst, src1, src2),
                                K::Xor => I::xor_imm(dst, src1, src2),
                                K::Xor64 => I::xor_64_imm(dst, src1, src2),
                                K::ShiftLogicalRight => I::shift_logical_right_imm(dst, src1, src2),
                                K::ShiftLogicalRight64 => I::shift_logical_right_64_imm(dst, src1, src2),
                                K::ShiftArithmeticRight => I::shift_arithmetic_right_imm(dst, src1, src2),
                                K::ShiftArithmeticRight64 => I::shift_arithmetic_right_64_imm(dst, src1, src2),
                                K::Or => I::or_imm(dst, src1, src2),
                                K::Or64 => I::or_64_imm(dst, src1, src2),
                                K::And => I::and_imm(dst, src1, src2),
                                K::And64 => I::and_64_imm(dst, src1, src2),
                                K::Mul => I::mul_imm(dst, src1, src2),
                                K::Mul64 => I::mul_imm(dst, src1, src2),
                                K::MulUpperSignedSigned => I::mul_upper_signed_signed_imm(dst, src1, src2),
                                K::MulUpperSignedSigned64 => I::mul_upper_signed_signed_imm_64(dst, src1, src2),
                                K::MulUpperUnsignedUnsigned => I::mul_upper_unsigned_unsigned_imm(dst, src1, src2),
                                K::MulUpperUnsignedUnsigned64 => I::mul_upper_unsigned_unsigned_imm_64(dst, src1, src2),
                            }
                        }
                        (RegImm::Imm(src1), RegImm::Reg(src2)) => {
                            let src2 = conv_reg(src2);
                            match kind {
                                K::Add => I::add_imm(dst, src2, src1),
                                K::Add64 => I::add_64_imm(dst, src2, src1),
                                K::Xor => I::xor_imm(dst, src2, src1),
                                K::Xor64 => I::xor_64_imm(dst, src2, src1),
                                K::Or => I::or_imm(dst, src2, src1),
                                K::Or64 => I::or_64_imm(dst, src2, src1),
                                K::And => I::and_imm(dst, src2, src1),
                                K::And64 => I::and_64_imm(dst, src2, src1),
                                K::Mul => I::mul_imm(dst, src2, src1),
                                K::Mul64 => I::mul_imm(dst, src2, src1),
                                K::MulUpperSignedSigned => I::mul_upper_signed_signed_imm(dst, src2, src1),
                                K::MulUpperSignedSigned64 => I::mul_upper_signed_signed_imm_64(dst, src2, src1),
                                K::MulUpperUnsignedUnsigned => I::mul_upper_unsigned_unsigned_imm(dst, src2, src1),
                                K::MulUpperUnsignedUnsigned64 => I::mul_upper_unsigned_unsigned_imm_64(dst, src2, src1),

                                K::Sub => I::negate_and_add_imm(dst, src2, src1),
                                K::Sub64 => I::negate_and_add_imm(dst, src2, src1),
                                K::ShiftLogicalLeft => I::shift_logical_left_imm_alt(dst, src2, src1),
                                K::ShiftLogicalLeft64 => I::shift_logical_left_64_imm_alt(dst, src2, src1),
                                K::SetLessThanSigned => I::set_greater_than_signed_imm(dst, src2, src1),
                                K::SetLessThanSigned64 => I::set_greater_than_signed_64_imm(dst, src2, src1),
                                K::SetLessThanUnsigned => I::set_greater_than_unsigned_imm(dst, src2, src1),
                                K::SetLessThanUnsigned64 => I::set_greater_than_unsigned_64_imm(dst, src2, src1),
                                K::ShiftLogicalRight => I::shift_logical_right_imm_alt(dst, src2, src1),
                                K::ShiftLogicalRight64 => I::shift_logical_right_imm_alt(dst, src2, src1),
                                K::ShiftArithmeticRight => I::shift_arithmetic_right_imm_alt(dst, src2, src1),
                                K::ShiftArithmeticRight64 => I::shift_arithmetic_right_64_imm_alt(dst, src2, src1),
                            }
                        }
                        (RegImm::Imm(src1), RegImm::Imm(src2)) => {
                            if is_optimized {
                                unreachable!("internal error: instruction with only constant operands: {op:?}")
                            } else {
                                let imm: u32 = OperationKind::from(kind)
                                    .apply_const(i32_to_i64(src1 as i32), i32_to_i64(src2 as i32))
                                    .try_into()
                                    .expect("load immediate overflow");
                                I::load_imm(dst, imm)
                            }
                        }
                    }
                }
                BasicInst::Cmov { kind, dst, src, cond } => match src {
                    RegImm::Reg(src) => {
                        codegen! {
                            args = (conv_reg(dst), conv_reg(src), conv_reg(cond)),
                            kind = kind,
                            {
                                CmovKind::EqZero => cmov_if_zero,
                                CmovKind::NotEqZero => cmov_if_not_zero,
                            }
                        }
                    }
                    RegImm::Imm(imm) => {
                        codegen! {
                            args = (conv_reg(dst), conv_reg(cond), imm),
                            kind = kind,
                            {
                                CmovKind::EqZero => cmov_if_zero_imm,
                                CmovKind::NotEqZero => cmov_if_not_zero_imm,
                            }
                        }
                    }
                },
                BasicInst::Ecalli { nth_import } => {
                    assert!(used_imports.contains(&nth_import));
                    let import = &imports[nth_import];
                    Instruction::ecalli(import.metadata.index.expect("internal error: no index was assigned to an ecall"))
                }
                BasicInst::Sbrk { dst, size } => Instruction::sbrk(conv_reg(dst), conv_reg(size)),
                BasicInst::Nop => unreachable!("internal error: a nop instruction was not removed"),
            };

            code.push((source.clone(), op));
        }

        fn unconditional_jump(target: JumpTarget) -> Instruction {
            Instruction::jump(target.static_target)
        }

        match block.next.instruction {
            ControlInst::Jump { target } => {
                let target = get_jump_target(target)?;
                if can_fallthrough_to_next_block.contains(block_target) {
                    assert!(basic_block_delimited);
                    basic_block_delimited = false;
                } else {
                    code.push((block.next.source.clone(), unconditional_jump(target)));
                }
            }
            ControlInst::Call { ra, target, target_return } => {
                assert!(can_fallthrough_to_next_block.contains(block_target));

                let target = get_jump_target(target)?;
                let target_return = get_jump_target(target_return)?
                    .dynamic_target
                    .expect("missing jump target for address");
                let Some(target_return) = target_return.checked_mul(VM_CODE_ADDRESS_ALIGNMENT) else {
                    return Err(ProgramFromElfError::other("overflow when emitting an indirect call"));
                };

                code.push((
                    block.next.source.clone(),
                    Instruction::load_imm_and_jump(conv_reg(ra), target_return, target.static_target),
                ));
            }
            ControlInst::JumpIndirect { base, offset } => {
                code.push((block.next.source.clone(), Instruction::jump_indirect(conv_reg(base), offset as u32)));
            }
            ControlInst::CallIndirect {
                ra,
                base,
                offset,
                target_return,
            } => {
                assert!(can_fallthrough_to_next_block.contains(block_target));

                let target_return = get_jump_target(target_return)?
                    .dynamic_target
                    .expect("missing jump target for address");
                let Some(target_return) = target_return.checked_mul(VM_CODE_ADDRESS_ALIGNMENT) else {
                    return Err(ProgramFromElfError::other("overflow when emitting an indirect call"));
                };

                code.push((
                    block.next.source.clone(),
                    Instruction::load_imm_and_jump_indirect(conv_reg(ra), conv_reg(base), target_return, offset as u32),
                ));
            }
            ControlInst::Branch {
                kind,
                src1,
                src2,
                target_true,
                target_false,
            } => {
                assert!(can_fallthrough_to_next_block.contains(block_target));

                let target_true = get_jump_target(target_true)?;
                get_jump_target(target_false)?;

                let instruction = match (src1, src2) {
                    (RegImm::Reg(src1), RegImm::Reg(src2)) => {
                        codegen! {
                            args = (conv_reg(src1), conv_reg(src2), target_true.static_target),
                            kind = kind,
                            {
                                BranchKind::Eq => branch_eq,
                                BranchKind::NotEq => branch_not_eq,
                                BranchKind::GreaterOrEqualUnsigned => branch_greater_or_equal_unsigned,
                                BranchKind::GreaterOrEqualSigned => branch_greater_or_equal_signed,
                                BranchKind::LessSigned => branch_less_signed,
                                BranchKind::LessUnsigned => branch_less_unsigned,
                            }
                        }
                    }
                    (RegImm::Imm(src1), RegImm::Reg(src2)) => {
                        codegen! {
                            args = (conv_reg(src2), src1, target_true.static_target),
                            kind = kind,
                            {
                                BranchKind::Eq => branch_eq_imm,
                                BranchKind::NotEq => branch_not_eq_imm,
                                BranchKind::GreaterOrEqualUnsigned => branch_less_or_equal_unsigned_imm,
                                BranchKind::GreaterOrEqualSigned => branch_less_or_equal_signed_imm,
                                BranchKind::LessSigned => branch_greater_signed_imm,
                                BranchKind::LessUnsigned => branch_greater_unsigned_imm,
                            }
                        }
                    }
                    (RegImm::Reg(src1), RegImm::Imm(src2)) => {
                        codegen! {
                            args = (conv_reg(src1), src2, target_true.static_target),
                            kind = kind,
                            {
                                BranchKind::Eq => branch_eq_imm,
                                BranchKind::NotEq => branch_not_eq_imm,
                                BranchKind::LessSigned => branch_less_signed_imm,
                                BranchKind::LessUnsigned => branch_less_unsigned_imm,
                                BranchKind::GreaterOrEqualSigned => branch_greater_or_equal_signed_imm,
                                BranchKind::GreaterOrEqualUnsigned => branch_greater_or_equal_unsigned_imm,
                            }
                        }
                    }
                    (RegImm::Imm(src1), RegImm::Imm(src2)) => {
                        if is_optimized {
                            unreachable!("internal error: branch with only constant operands")
                        } else {
                            match OperationKind::from(kind).apply_const(i32_to_i64(src1 as i32), i32_to_i64(src2 as i32)) {
                                1 => unconditional_jump(target_true),
                                0 => {
                                    assert!(can_fallthrough_to_next_block.contains(block_target));
                                    Instruction::fallthrough
                                }
                                _ => unreachable!(),
                            }
                        }
                    }
                };

                code.push((block.next.source.clone(), instruction));
            }
            ControlInst::Unimplemented => {
                code.push((block.next.source.clone(), Instruction::trap));
            }
        }
    }

    Ok(code)
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
enum Bitness {
    B32,
    B64,
}

impl Bitness {
    fn bits_used_mask(self) -> u64 {
        match self {
            Bitness::B32 => u64::from(u32::MAX),
            Bitness::B64 => u64::MAX,
        }
    }
}

impl InstructionSet for Bitness {
    fn opcode_from_u8(self, byte: u8) -> Option<Opcode> {
        match self {
            Bitness::B32 => polkavm_common::program::ISA32_V1.opcode_from_u8(byte),
            Bitness::B64 => polkavm_common::program::ISA64_V1.opcode_from_u8(byte),
        }
    }
}

impl From<Bitness> for u64 {
    fn from(value: Bitness) -> Self {
        match value {
            Bitness::B32 => 4,
            Bitness::B64 => 8,
        }
    }
}

impl From<Bitness> for RelocationSize {
    fn from(value: Bitness) -> Self {
        match value {
            Bitness::B32 => RelocationSize::U32,
            Bitness::B64 => RelocationSize::U64,
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub(crate) enum RelocationSize {
    U8,
    U16,
    U32,
    U64,
}

#[derive(Copy, Clone, Debug)]
pub(crate) enum SizeRelocationSize {
    SixBits,
    Uleb128,
    Generic(RelocationSize),
}

#[derive(Copy, Clone, Debug)]
pub(crate) enum RelocationKind {
    Abs {
        target: SectionTarget,
        size: RelocationSize,
    },
    JumpTable {
        target_code: SectionTarget,
        target_base: SectionTarget,
    },

    Size {
        section_index: SectionIndex,
        range: AddressRange,
        size: SizeRelocationSize,
    },
}

impl RelocationKind {
    fn targets(&self) -> [Option<SectionTarget>; 2] {
        match self {
            RelocationKind::Abs { target, .. } => [Some(*target), None],
            RelocationKind::Size { section_index, range, .. } => [
                Some(SectionTarget {
                    section_index: *section_index,
                    offset: range.start,
                }),
                Some(SectionTarget {
                    section_index: *section_index,
                    offset: range.end,
                }),
            ],
            RelocationKind::JumpTable { target_code, target_base } => [Some(*target_code), Some(*target_base)],
        }
    }
}

fn harvest_data_relocations<H>(
    elf: &Elf<H>,
    code_sections_set: &HashSet<SectionIndex>,
    section: &Section,
    relocations: &mut BTreeMap<SectionTarget, RelocationKind>,
) -> Result<(), ProgramFromElfError>
where
    H: object::read::elf::FileHeader<Endian = object::LittleEndian>,
{
    #[derive(Debug)]
    enum MutOp {
        Add,
        Sub,
    }

    #[derive(Debug)]
    enum Kind {
        Set(RelocationKind),
        Mut(MutOp, RelocationSize, SectionTarget),

        Set6 { target: SectionTarget },
        Sub6 { target: SectionTarget },

        SetUleb128 { target: SectionTarget },
        SubUleb128 { target: SectionTarget },
    }

    if elf.relocations(section).next().is_none() {
        return Ok(());
    }

    let section_name = section.name();
    log::trace!("Harvesting data relocations from section: {}", section_name);

    let mut for_address = BTreeMap::new();
    for (absolute_address, relocation) in elf.relocations(section) {
        let Some(relative_address) = absolute_address.checked_sub(section.original_address()) else {
            return Err(ProgramFromElfError::other("invalid relocation offset"));
        };

        if relocation.has_implicit_addend() {
            // AFAIK these should never be emitted for RISC-V.
            return Err(ProgramFromElfError::other(format!("unsupported relocation: {:?}", relocation)));
        }

        let Some(target) = get_relocation_target(elf, &relocation)? else {
            continue;
        };

        let (relocation_name, kind) = match (relocation.kind(), relocation.flags()) {
            (object::RelocationKind::Absolute, _)
                if relocation.encoding() == object::RelocationEncoding::Generic && relocation.size() == 32 =>
            {
                (
                    "R_RISCV_32",
                    Kind::Set(RelocationKind::Abs {
                        target,
                        size: RelocationSize::U32,
                    }),
                )
            }
            (object::RelocationKind::Absolute, _)
                if relocation.encoding() == object::RelocationEncoding::Generic && relocation.size() == 64 =>
            {
                (
                    "R_RISCV_64",
                    Kind::Set(RelocationKind::Abs {
                        target,
                        size: RelocationSize::U64,
                    }),
                )
            }

            (_, object::RelocationFlags::Elf { r_type: reloc_kind }) => match reloc_kind {
                object::elf::R_RISCV_SET6 => ("R_RISCV_SET6", Kind::Set6 { target }),
                object::elf::R_RISCV_SUB6 => ("R_RISCV_SUB6", Kind::Sub6 { target }),
                object::elf::R_RISCV_SET8 => (
                    "R_RISCV_SET8",
                    Kind::Set(RelocationKind::Abs {
                        target,
                        size: RelocationSize::U8,
                    }),
                ),
                object::elf::R_RISCV_SET16 => (
                    "R_RISCV_SET16",
                    Kind::Set(RelocationKind::Abs {
                        target,
                        size: RelocationSize::U16,
                    }),
                ),
                object::elf::R_RISCV_ADD8 => ("R_RISCV_ADD8", Kind::Mut(MutOp::Add, RelocationSize::U8, target)),
                object::elf::R_RISCV_SUB8 => ("R_RISCV_SUB8", Kind::Mut(MutOp::Sub, RelocationSize::U8, target)),
                object::elf::R_RISCV_ADD16 => ("R_RISCV_ADD16", Kind::Mut(MutOp::Add, RelocationSize::U16, target)),
                object::elf::R_RISCV_SUB16 => ("R_RISCV_SUB16", Kind::Mut(MutOp::Sub, RelocationSize::U16, target)),
                object::elf::R_RISCV_ADD32 => ("R_RISCV_ADD32", Kind::Mut(MutOp::Add, RelocationSize::U32, target)),
                object::elf::R_RISCV_ADD64 => ("R_RISCV_ADD64", Kind::Mut(MutOp::Add, RelocationSize::U64, target)),
                object::elf::R_RISCV_SUB32 => ("R_RISCV_SUB32", Kind::Mut(MutOp::Sub, RelocationSize::U32, target)),
                object::elf::R_RISCV_SUB64 => ("R_RISCV_SUB64", Kind::Mut(MutOp::Sub, RelocationSize::U64, target)),
                object::elf::R_RISCV_SET_ULEB128 => ("R_RISCV_SET_ULEB128", Kind::SetUleb128 { target }),
                object::elf::R_RISCV_SUB_ULEB128 => ("R_RISCV_SUB_ULEB128", Kind::SubUleb128 { target }),

                _ => {
                    return Err(ProgramFromElfError::other(format!(
                        "unsupported relocation in data section '{section_name}': {relocation:?}"
                    )))
                }
            },
            _ => {
                return Err(ProgramFromElfError::other(format!(
                    "unsupported relocation in data section '{section_name}': {relocation:?}"
                )))
            }
        };

        log::trace!("  {relocation_name}: {section_name}[0x{relative_address:x}] (0x{absolute_address:x}): -> {target}");
        for_address
            .entry(relative_address)
            .or_insert_with(Vec::new)
            .push((relocation_name, kind));
    }

    for (relative_address, list) in for_address {
        let current_location = SectionTarget {
            section_index: section.index(),
            offset: relative_address,
        };

        struct ErrorToken; // To make sure we don't forget a `continue` anywhere.
        let _: ErrorToken = match &*list {
            [(_, Kind::Set(kind))] => {
                relocations.insert(current_location, *kind);
                continue;
            }
            [(_, Kind::Mut(MutOp::Add, size_1, target_1)), (_, Kind::Mut(MutOp::Sub, size_2, target_2))]
                if size_1 == size_2 && (target_1.section_index == target_2.section_index && target_1.offset >= target_2.offset) =>
            {
                relocations.insert(
                    current_location,
                    RelocationKind::Size {
                        section_index: target_1.section_index,
                        range: (target_2.offset..target_1.offset).into(),
                        size: SizeRelocationSize::Generic(*size_1),
                    },
                );
                continue;
            }
            [(
                _,
                Kind::Set(RelocationKind::Abs {
                    target: target_1,
                    size: size_1,
                }),
            ), (_, Kind::Mut(MutOp::Sub, size_2, target_2))]
                if size_1 == size_2 && target_1.section_index == target_2.section_index && target_1.offset >= target_2.offset =>
            {
                relocations.insert(
                    current_location,
                    RelocationKind::Size {
                        section_index: target_1.section_index,
                        range: (target_2.offset..target_1.offset).into(),
                        size: SizeRelocationSize::Generic(*size_1),
                    },
                );
                continue;
            }
            [(_, Kind::Set6 { target: target_1 }), (_, Kind::Sub6 { target: target_2 })]
                if target_1.section_index == target_2.section_index && target_1.offset >= target_2.offset =>
            {
                relocations.insert(
                    current_location,
                    RelocationKind::Size {
                        section_index: target_1.section_index,
                        range: (target_2.offset..target_1.offset).into(),
                        size: SizeRelocationSize::SixBits,
                    },
                );
                continue;
            }
            [(_, Kind::SetUleb128 { target: target_1 }), (_, Kind::SubUleb128 { target: target_2 })]
                if target_1.section_index == target_2.section_index && target_1.offset >= target_2.offset =>
            {
                relocations.insert(
                    current_location,
                    RelocationKind::Size {
                        section_index: target_1.section_index,
                        range: (target_2.offset..target_1.offset).into(),
                        size: SizeRelocationSize::Uleb128,
                    },
                );
                continue;
            }
            [(_, Kind::Mut(MutOp::Add, size_1, target_1)), (_, Kind::Mut(MutOp::Sub, size_2, target_2))]
                if size_1 == size_2
                    && *size_1 == RelocationSize::U32
                    && code_sections_set.contains(&target_1.section_index)
                    && !code_sections_set.contains(&target_2.section_index) =>
            {
                relocations.insert(
                    current_location,
                    RelocationKind::JumpTable {
                        target_code: *target_1,
                        target_base: *target_2,
                    },
                );
                continue;
            }
            _ => ErrorToken,
        };

        return Err(ProgramFromElfError::other(format!(
            "unsupported relocations for '{section_name}'[{relative_address:x}] (0x{absolute_address:08x}): {list}",
            absolute_address = section.original_address() + relative_address,
            list = SectionTarget::make_human_readable_in_debug_string(elf, &format!("{list:?}")),
        )));
    }

    Ok(())
}

fn read_u32(data: &[u8], relative_address: u64) -> Result<u32, ProgramFromElfError> {
    let target_range = relative_address as usize..relative_address as usize + 4;
    let value = data
        .get(target_range)
        .ok_or(ProgramFromElfError::other("out of range relocation"))?;
    Ok(u32::from_le_bytes([value[0], value[1], value[2], value[3]]))
}

fn read_u16(data: &[u8], relative_address: u64) -> Result<u16, ProgramFromElfError> {
    let target_range = relative_address as usize..relative_address as usize + 2;
    let value = data
        .get(target_range)
        .ok_or(ProgramFromElfError::other("out of range relocation"))?;
    Ok(u16::from_le_bytes([value[0], value[1]]))
}

fn read_u8(data: &[u8], relative_address: u64) -> Result<u8, ProgramFromElfError> {
    data.get(relative_address as usize)
        .ok_or(ProgramFromElfError::other("out of range relocation"))
        .copied()
}

/// ULEB128 encode `value` and overwrite the existing value at `data_offset`, keeping the length.
///
/// See the [ELF ABI spec] and [LLD implementation] for reference.
///
/// [ELF ABI spec]: https://github.com/riscv-non-isa/riscv-elf-psabi-doc/blob/fbf3cbbac00ef1860ae60302a9afedb98fd31109/riscv-elf.adoc#uleb128-note
/// [LLD implementation]: https://github.com/llvm/llvm-project/blob/release/18.x/lld/ELF/Target.h#L310
fn overwrite_uleb128(data: &mut [u8], mut data_offset: usize, mut value: u64) -> Result<(), ProgramFromElfError> {
    loop {
        let Some(byte) = data.get_mut(data_offset) else {
            return Err(ProgramFromElfError::other("ULEB128 relocation target offset out of bounds"));
        };
        data_offset += 1;

        if *byte & 0x80 != 0 {
            *byte = 0x80 | (value as u8 & 0x7f);
            value >>= 7;
        } else {
            *byte = value as u8;
            return if value > 0x80 {
                Err(ProgramFromElfError::other("ULEB128 relocation overflow"))
            } else {
                Ok(())
            };
        }
    }
}

#[test]
fn test_overwrite_uleb128() {
    let value = 624485;
    let encoded_value = vec![0xE5u8, 0x8E, 0x26];
    let mut data = vec![0x80, 0x80, 0x00];

    overwrite_uleb128(&mut data, 0, value).unwrap();

    assert_eq!(data, encoded_value);
}

fn write_u64(data: &mut [u8], relative_address: u64, value: u64) -> Result<(), ProgramFromElfError> {
    let value = value.to_le_bytes();
    data[relative_address as usize + 7] = value[7];
    data[relative_address as usize + 6] = value[6];
    data[relative_address as usize + 5] = value[5];
    data[relative_address as usize + 4] = value[4];
    data[relative_address as usize + 3] = value[3];
    data[relative_address as usize + 2] = value[2];
    data[relative_address as usize + 1] = value[1];
    data[relative_address as usize] = value[0];
    Ok(())
}

fn write_u32(data: &mut [u8], relative_address: u64, value: u32) -> Result<(), ProgramFromElfError> {
    let value = value.to_le_bytes();
    data[relative_address as usize + 3] = value[3];
    data[relative_address as usize + 2] = value[2];
    data[relative_address as usize + 1] = value[1];
    data[relative_address as usize] = value[0];
    Ok(())
}

fn write_u16(data: &mut [u8], relative_address: u64, value: u16) -> Result<(), ProgramFromElfError> {
    let value = value.to_le_bytes();
    data[relative_address as usize + 1] = value[1];
    data[relative_address as usize] = value[0];
    Ok(())
}

fn harvest_code_relocations<H>(
    elf: &Elf<H>,
    section: &Section,
    decoder_config: &DecoderConfig,
    instruction_overrides: &mut HashMap<SectionTarget, InstExt<SectionTarget, SectionTarget>>,
    data_relocations: &mut BTreeMap<SectionTarget, RelocationKind>,
) -> Result<(), ProgramFromElfError>
where
    H: object::read::elf::FileHeader<Endian = object::LittleEndian>,
{
    fn jump_or_call<T>(ra: RReg, target: T, target_return: T) -> Result<ControlInst<T>, ProgramFromElfError> {
        if let Some(ra) = cast_reg_non_zero(ra)? {
            Ok(ControlInst::Call { ra, target, target_return })
        } else {
            Ok(ControlInst::Jump { target })
        }
    }

    #[derive(Copy, Clone)]
    enum HiRelocKind {
        PcRel,
        Got,
    }

    impl core::fmt::Display for HiRelocKind {
        fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
            match self {
                HiRelocKind::PcRel => fmt.write_str("R_RISCV_PCREL_HI20"),
                HiRelocKind::Got => fmt.write_str("R_RISCV_GOT_HI20"),
            }
        }
    }

    #[derive(Default)]
    struct RelocPairs {
        reloc_pcrel_hi20: BTreeMap<u64, (HiRelocKind, SectionTarget)>,
        reloc_pcrel_lo12: BTreeMap<u64, (&'static str, u64)>,
    }

    if elf.relocations(section).next().is_none() {
        return Ok(());
    }

    let mut pcrel_relocations = RelocPairs::default();

    let section_name = section.name();
    log::trace!("Harvesting code relocations from section: {}", section_name);

    let section_data = section.data();
    for (absolute_address, relocation) in elf.relocations(section) {
        let Some(relative_address) = absolute_address.checked_sub(section.original_address()) else {
            return Err(ProgramFromElfError::other("invalid relocation offset"));
        };

        if relocation.has_implicit_addend() {
            // AFAIK these should never be emitted for RISC-V.
            return Err(ProgramFromElfError::other(format!(
                "unsupported relocation in section '{section_name}': {relocation:?}"
            )));
        }

        let current_location = SectionTarget {
            section_index: section.index(),
            offset: relative_address,
        };

        let relative_address = current_location.offset;
        let Some(target) = get_relocation_target(elf, &relocation)? else {
            continue;
        };

        match (relocation.kind(), relocation.flags()) {
            (object::RelocationKind::Absolute, _)
                if relocation.encoding() == object::RelocationEncoding::Generic && relocation.size() == 32 =>
            {
                data_relocations.insert(
                    current_location,
                    RelocationKind::Abs {
                        target,
                        size: RelocationSize::U32,
                    },
                );
            }
            (object::RelocationKind::Absolute, _)
                if relocation.encoding() == object::RelocationEncoding::Generic && relocation.size() == 64 =>
            {
                data_relocations.insert(
                    current_location,
                    RelocationKind::Abs {
                        target,
                        size: RelocationSize::U64,
                    },
                );
            }
            (_, object::RelocationFlags::Elf { r_type: reloc_kind }) => {
                // https://github.com/riscv-non-isa/riscv-elf-psabi-doc/releases
                match reloc_kind {
                    object::elf::R_RISCV_CALL_PLT => {
                        // This relocation is for a pair of instructions, namely AUIPC + JALR, where we're allowed to delete the AUIPC if it's unnecessary.
                        let Some(xs) = section_data.get(current_location.offset as usize..current_location.offset as usize + 8) else {
                            return Err(ProgramFromElfError::other("invalid R_RISCV_CALL_PLT relocation"));
                        };

                        let hi_inst_raw = u32::from_le_bytes([xs[0], xs[1], xs[2], xs[3]]);
                        let Some(hi_inst) = Inst::decode(decoder_config, hi_inst_raw) else {
                            return Err(ProgramFromElfError::other(format!(
                                "R_RISCV_CALL_PLT for an unsupported instruction (1st): 0x{hi_inst_raw:08}"
                            )));
                        };

                        let lo_inst_raw = u32::from_le_bytes([xs[4], xs[5], xs[6], xs[7]]);
                        let Some(lo_inst) = Inst::decode(decoder_config, lo_inst_raw) else {
                            return Err(ProgramFromElfError::other(format!(
                                "R_RISCV_CALL_PLT for an unsupported instruction (2nd): 0x{lo_inst_raw:08}"
                            )));
                        };

                        let Inst::AddUpperImmediateToPc { dst: hi_reg, value: _ } = hi_inst else {
                            return Err(ProgramFromElfError::other(format!(
                                "R_RISCV_CALL_PLT for an unsupported instruction (1st): 0x{hi_inst_raw:08} ({hi_inst:?})"
                            )));
                        };

                        let Inst::JumpAndLinkRegister {
                            dst: lo_dst,
                            base: lo_reg,
                            value: _,
                        } = lo_inst
                        else {
                            return Err(ProgramFromElfError::other(format!(
                                "R_RISCV_CALL_PLT for an unsupported instruction (2nd): 0x{lo_inst_raw:08} ({lo_inst:?})"
                            )));
                        };

                        if hi_reg != lo_reg {
                            return Err(ProgramFromElfError::other(
                                "R_RISCV_CALL_PLT for a pair of instructions with different destination registers",
                            ));
                        }

                        let target_return = current_location.add(8);
                        instruction_overrides.insert(current_location, InstExt::nop());
                        instruction_overrides.insert(
                            current_location.add(4),
                            InstExt::Control(jump_or_call(lo_dst, target, target_return)?),
                        );

                        log::trace!(
                            "  R_RISCV_CALL_PLT: {}[0x{relative_address:x}] (0x{absolute_address:x}): -> {}",
                            section.name(),
                            target
                        );
                    }
                    object::elf::R_RISCV_PCREL_HI20 => {
                        // This relocation is for an AUIPC.
                        pcrel_relocations
                            .reloc_pcrel_hi20
                            .insert(relative_address, (HiRelocKind::PcRel, target));
                        log::trace!(
                            "  R_RISCV_PCREL_HI20: {}[0x{relative_address:x}] (0x{absolute_address:x}): -> {}",
                            section.name(),
                            target
                        );
                    }
                    object::elf::R_RISCV_GOT_HI20 => {
                        pcrel_relocations
                            .reloc_pcrel_hi20
                            .insert(relative_address, (HiRelocKind::Got, target));
                        log::trace!(
                            "  R_RISCV_GOT_HI20: {}[0x{relative_address:x}] (0x{absolute_address:x}): -> {}",
                            section.name(),
                            target
                        );
                    }
                    object::elf::R_RISCV_PCREL_LO12_I => {
                        if target.section_index != section.index() {
                            return Err(ProgramFromElfError::other(
                                "R_RISCV_PCREL_LO12_I relocation points to a different section",
                            ));
                        }

                        pcrel_relocations
                            .reloc_pcrel_lo12
                            .insert(relative_address, ("R_RISCV_PCREL_LO12_I", target.offset));
                        log::trace!(
                            "  R_RISCV_PCREL_LO12_I: {}[0x{relative_address:x}] (0x{absolute_address:x}): -> {}",
                            section.name(),
                            target
                        );
                    }
                    object::elf::R_RISCV_PCREL_LO12_S => {
                        if target.section_index != section.index() {
                            return Err(ProgramFromElfError::other(
                                "R_RISCV_PCREL_LO12_I relocation points to a different section",
                            ));
                        }

                        pcrel_relocations
                            .reloc_pcrel_lo12
                            .insert(relative_address, ("R_RISCV_PCREL_LO12_S", target.offset));
                        log::trace!(
                            "  R_RISCV_PCREL_LO12_S: {}[0x{relative_address:x}] (0x{absolute_address:x}): -> {}",
                            section.name(),
                            target
                        );
                    }
                    object::elf::R_RISCV_JAL => {
                        let inst_raw = read_u32(section_data, relative_address)?;
                        let Some(inst) = Inst::decode(decoder_config, inst_raw) else {
                            return Err(ProgramFromElfError::other(format!(
                                "R_RISCV_JAL for an unsupported instruction: 0x{inst_raw:08}"
                            )));
                        };

                        let Inst::JumpAndLink { dst, .. } = inst else {
                            return Err(ProgramFromElfError::other(format!(
                                "R_RISCV_JAL for an unsupported instruction: 0x{inst_raw:08} ({inst:?})"
                            )));
                        };

                        let target_return = current_location.add(4);
                        instruction_overrides.insert(current_location, InstExt::Control(jump_or_call(dst, target, target_return)?));

                        log::trace!(
                            "  R_RISCV_JAL: {}[0x{relative_address:x}] (0x{absolute_address:x} -> {}",
                            section.name(),
                            target
                        );
                    }
                    object::elf::R_RISCV_BRANCH => {
                        let inst_raw = read_u32(section_data, relative_address)?;
                        let Some(inst) = Inst::decode(decoder_config, inst_raw) else {
                            return Err(ProgramFromElfError::other(format!(
                                "R_RISCV_BRANCH for an unsupported instruction: 0x{inst_raw:08}"
                            )));
                        };

                        let Inst::Branch { kind, src1, src2, .. } = inst else {
                            return Err(ProgramFromElfError::other(format!(
                                "R_RISCV_BRANCH for an unsupported instruction: 0x{inst_raw:08} ({inst:?})"
                            )));
                        };

                        let target_false = current_location.add(4);
                        instruction_overrides.insert(
                            current_location,
                            InstExt::Control(ControlInst::Branch {
                                kind,
                                src1: cast_reg_any(src1)?,
                                src2: cast_reg_any(src2)?,
                                target_true: target,
                                target_false,
                            }),
                        );

                        log::trace!(
                            "  R_RISCV_BRANCH: {}[0x{relative_address:x}] (0x{absolute_address:x} -> {}",
                            section.name(),
                            target
                        );
                    }
                    object::elf::R_RISCV_HI20 => {
                        // This relocation is for a LUI.
                        let inst_raw = read_u32(section_data, relative_address)?;
                        let Some(inst) = Inst::decode(decoder_config, inst_raw) else {
                            return Err(ProgramFromElfError::other(format!(
                                "R_RISCV_HI20 for an unsupported instruction: 0x{inst_raw:08}"
                            )));
                        };

                        let Inst::LoadUpperImmediate { dst, value: _ } = inst else {
                            return Err(ProgramFromElfError::other(format!(
                                "R_RISCV_HI20 for an unsupported instruction: 0x{inst_raw:08} ({inst:?})"
                            )));
                        };

                        let Some(dst) = cast_reg_non_zero(dst)? else {
                            return Err(ProgramFromElfError::other("R_RISCV_HI20 with a zero destination register"));
                        };

                        instruction_overrides.insert(current_location, InstExt::Basic(BasicInst::LoadAddress { dst, target }));

                        log::trace!(
                            "  R_RISCV_HI20: {}[0x{relative_address:x}] (0x{absolute_address:x}): -> {}",
                            section.name(),
                            target
                        );

                        continue;
                    }
                    object::elf::R_RISCV_LO12_I => {
                        let inst_raw = read_u32(section_data, relative_address)?;
                        let Some(inst) = Inst::decode(decoder_config, inst_raw) else {
                            return Err(ProgramFromElfError::other(format!(
                                "R_RISCV_LO12_I for an unsupported instruction: 0x{inst_raw:08}"
                            )));
                        };

                        let new_instruction = match inst {
                            Inst::RegImm {
                                kind: RegImmKind::Add,
                                dst,
                                src: _,
                                imm: _,
                            } => {
                                let Some(dst) = cast_reg_non_zero(dst)? else {
                                    return Err(ProgramFromElfError::other("R_RISCV_LO12_I with a zero destination register"));
                                };

                                InstExt::Basic(BasicInst::LoadAddress { dst, target })
                            }
                            Inst::Load {
                                kind,
                                dst,
                                base: _,
                                offset: _,
                            } => {
                                let Some(dst) = cast_reg_non_zero(dst)? else {
                                    return Err(ProgramFromElfError::other("R_RISCV_LO12_I with a zero destination register"));
                                };

                                InstExt::Basic(BasicInst::LoadAbsolute { kind, dst, target })
                            }
                            _ => {
                                return Err(ProgramFromElfError::other(format!(
                                    "R_RISCV_LO12_I for an unsupported instruction: 0x{inst_raw:08} ({inst:?}) (at {loc})",
                                    loc = current_location.fmt_human_readable(elf),
                                )));
                            }
                        };

                        instruction_overrides.insert(current_location, new_instruction);

                        log::trace!(
                            "  R_RISCV_LO12_I: {}[0x{relative_address:x}] (0x{absolute_address:x}): -> {}",
                            section.name(),
                            target
                        );
                    }
                    object::elf::R_RISCV_LO12_S => {
                        let inst_raw = read_u32(section_data, relative_address)?;
                        let Some(inst) = Inst::decode(decoder_config, inst_raw) else {
                            return Err(ProgramFromElfError::other(format!(
                                "R_RISCV_LO12_S for an unsupported instruction: 0x{inst_raw:08}"
                            )));
                        };

                        let new_instruction = match inst {
                            Inst::Store {
                                kind,
                                src,
                                base: _,
                                offset: _,
                            } => InstExt::Basic(BasicInst::StoreAbsolute {
                                kind,
                                src: cast_reg_any(src)?,
                                target,
                            }),
                            _ => {
                                return Err(ProgramFromElfError::other(format!(
                                    "R_RISCV_LO12_S for an unsupported instruction: 0x{inst_raw:08} ({inst:?}) (at {loc})",
                                    loc = current_location.fmt_human_readable(elf),
                                )));
                            }
                        };

                        instruction_overrides.insert(current_location, new_instruction);

                        log::trace!(
                            "  R_RISCV_LO12_S: {}[0x{relative_address:x}] (0x{absolute_address:x}): -> {}",
                            section.name(),
                            target
                        );
                    }
                    object::elf::R_RISCV_RVC_JUMP => {
                        let inst_raw = read_u16(section_data, relative_address)?;
                        let Some(inst) = Inst::decode(decoder_config, inst_raw.into()) else {
                            return Err(ProgramFromElfError::other(format!(
                                "R_RISCV_RVC_JUMP for an unsupported instruction: 0x{inst_raw:04}"
                            )));
                        };

                        let (Inst::JumpAndLink { dst, .. } | Inst::JumpAndLinkRegister { dst, .. }) = inst else {
                            return Err(ProgramFromElfError::other(format!(
                                "R_RISCV_RVC_JUMP for an unsupported instruction: 0x{inst_raw:04} ({inst:?})"
                            )));
                        };

                        let target_return = current_location.add(2);
                        instruction_overrides.insert(current_location, InstExt::Control(jump_or_call(dst, target, target_return)?));

                        log::trace!(
                            "  R_RISCV_RVC_JUMP: {}[0x{relative_address:x}] (0x{absolute_address:x} -> {}",
                            section.name(),
                            target
                        );
                    }
                    object::elf::R_RISCV_RVC_BRANCH => {
                        let inst_raw = read_u16(section_data, relative_address)?;
                        let Some(inst) = Inst::decode(decoder_config, inst_raw.into()) else {
                            return Err(ProgramFromElfError::other(format!(
                                "R_RISCV_RVC_BRANCH for an unsupported instruction: 0x{inst_raw:04}"
                            )));
                        };

                        let Inst::Branch { kind, src1, src2, .. } = inst else {
                            return Err(ProgramFromElfError::other(format!(
                                "R_RISCV_BRANCH for an unsupported instruction: 0x{inst_raw:04} ({inst:?})"
                            )));
                        };

                        let target_false = current_location.add(2);
                        instruction_overrides.insert(
                            current_location,
                            InstExt::Control(ControlInst::Branch {
                                kind,
                                src1: cast_reg_any(src1)?,
                                src2: cast_reg_any(src2)?,
                                target_true: target,
                                target_false,
                            }),
                        );

                        log::trace!(
                            "  R_RISCV_RVC_BRANCH: {}[0x{relative_address:x}] (0x{absolute_address:x} -> {}",
                            section.name(),
                            target
                        );
                    }
                    object::elf::R_RISCV_RELAX => {}
                    _ => {
                        return Err(ProgramFromElfError::other(format!(
                            "unsupported relocation type in section '{}': 0x{:08x}",
                            section.name(),
                            reloc_kind
                        )));
                    }
                }
            }
            _ => {
                return Err(ProgramFromElfError::other(format!(
                    "unsupported relocation in code section '{}': {:?}",
                    section.name(),
                    relocation
                )))
            }
        }
    }

    for (relative_lo, (lo_rel_name, relative_hi)) in pcrel_relocations.reloc_pcrel_lo12 {
        let lo_inst_raw = &section_data[relative_lo as usize..][..4];
        let lo_inst_raw = u32::from_le_bytes([lo_inst_raw[0], lo_inst_raw[1], lo_inst_raw[2], lo_inst_raw[3]]);
        let lo_inst = Inst::decode(decoder_config, lo_inst_raw);
        let hi_inst_raw = &section_data[relative_hi as usize..][..4];
        let hi_inst_raw = u32::from_le_bytes([hi_inst_raw[0], hi_inst_raw[1], hi_inst_raw[2], hi_inst_raw[3]]);
        let hi_inst = Inst::decode(decoder_config, hi_inst_raw);

        let Some((hi_kind, target)) = pcrel_relocations.reloc_pcrel_hi20.get(&relative_hi).copied() else {
            return Err(ProgramFromElfError::other(format!("{lo_rel_name} relocation at '{section_name}'0x{relative_lo:x} targets '{section_name}'0x{relative_hi:x} which doesn't have a R_RISCV_PCREL_HI20 or R_RISCV_GOT_HI20 relocation")));
        };

        let Some(hi_inst) = hi_inst else {
            return Err(ProgramFromElfError::other(format!(
                "{hi_kind} relocation for an unsupported instruction at '{section_name}'0x{relative_hi:x}: 0x{hi_inst_raw:08x}"
            )));
        };

        let Inst::AddUpperImmediateToPc { dst: hi_reg, .. } = hi_inst else {
            return Err(ProgramFromElfError::other(format!(
                "{hi_kind} relocation for an unsupported instruction at '{section_name}'[0x{relative_hi:x}]: {hi_inst:?}"
            )));
        };

        let Some(lo_inst) = lo_inst else {
            return Err(ProgramFromElfError::other(format!(
                "{lo_rel_name} relocation for an unsupported instruction: 0x{lo_inst_raw:08x}"
            )));
        };

        let (lo_reg, new_instruction) = if matches!(hi_kind, HiRelocKind::Got) {
            // For these relocations the target address points to the symbol that the code wants to reference,
            // but the actual address that's in the code shouldn't point to the symbol directly, but to a place
            // where the symbol's address can be found.

            match lo_inst {
                Inst::Load {
                    kind: LoadKind::U64,
                    base,
                    dst,
                    ..
                } if elf.is_64() => {
                    let Some(dst) = cast_reg_non_zero(dst)? else {
                        return Err(ProgramFromElfError::other(format!(
                            "{lo_rel_name} with a zero destination register: 0x{lo_inst_raw:08x} in {section_name}[0x{relative_lo:08x}]"
                        )));
                    };

                    (base, InstExt::Basic(BasicInst::LoadAddressIndirect { dst, target }))
                }
                Inst::Load {
                    kind: LoadKind::U32,
                    base,
                    dst,
                    ..
                } => {
                    let Some(dst) = cast_reg_non_zero(dst)? else {
                        return Err(ProgramFromElfError::other(format!(
                            "{lo_rel_name} with a zero destination register: 0x{lo_inst_raw:08x} in {section_name}[0x{relative_lo:08x}]"
                        )));
                    };

                    (base, InstExt::Basic(BasicInst::LoadAddressIndirect { dst, target }))
                }
                _ => {
                    return Err(ProgramFromElfError::other(format!(
                        "{lo_rel_name} relocation (with {hi_kind} as the upper relocation) for an unsupported instruction: {lo_inst:?}"
                    )));
                }
            }
        } else {
            match lo_inst {
                Inst::RegImm {
                    kind: RegImmKind::Add,
                    src,
                    dst,
                    ..
                } if !elf.is_64() => {
                    let Some(dst) = cast_reg_non_zero(dst)? else {
                        return Err(ProgramFromElfError::other(format!(
                            "{lo_rel_name} with a zero destination register: 0x{lo_inst_raw:08x} in {section_name}[0x{relative_lo:08x}]"
                        )));
                    };

                    (src, InstExt::Basic(BasicInst::LoadAddress { dst, target }))
                }
                Inst::RegImm {
                    kind: RegImmKind::Add64,
                    src,
                    dst,
                    ..
                } if elf.is_64() => {
                    let Some(dst) = cast_reg_non_zero(dst)? else {
                        return Err(ProgramFromElfError::other(format!(
                            "{lo_rel_name} with a zero destination register: 0x{lo_inst_raw:08x} in {section_name}[0x{relative_lo:08x}]"
                        )));
                    };

                    (src, InstExt::Basic(BasicInst::LoadAddress { dst, target }))
                }
                Inst::Load { kind, base, dst, .. } => {
                    let Some(dst) = cast_reg_non_zero(dst)? else {
                        // The instruction will be translated to a NOP.
                        continue;
                    };

                    (base, InstExt::Basic(BasicInst::LoadAbsolute { kind, dst, target }))
                }
                Inst::Store { kind, base, src, .. } => (
                    base,
                    InstExt::Basic(BasicInst::StoreAbsolute {
                        kind,
                        src: cast_reg_any(src)?,
                        target,
                    }),
                ),
                _ => {
                    return Err(ProgramFromElfError::other(format!(
                        "{lo_rel_name} relocation (with {hi_kind} as the upper relocation) for an unsupported instruction: {lo_inst:?}"
                    )));
                }
            }
        };

        if lo_reg != hi_reg {
            // NOTE: These *can* apparently be sometimes different, so it's not an error if this happens.
            //
            // I've seen a case where the whole thing looked roughly like this:
            //
            //   auipc   a1,0x2057        # HI
            //   sw      a1,4(sp)         # Stash the HI part on the stack
            //   lw      a1,-460(a1)      # LO (1)
            //   ... a bunch of code ...
            //   lw      a2,4(sp)         # Reload the HI port from the stack (note different register)
            //   sw      a0,-460(a2)      # LO (2)
            log::trace!(
                "{lo_rel_name} + {hi_kind} relocation pair in '{section_name}' [+0x{relative_lo:x}, +0x{relative_hi:x}] uses different destination registers ({lo_reg:?} and {hi_reg:?})",
            );
        }

        let location_hi = SectionTarget {
            section_index: section.index(),
            offset: relative_hi,
        };
        let location_lo = SectionTarget {
            section_index: section.index(),
            offset: relative_lo,
        };

        // Since we support full length immediates just turn the upper instructions into a NOP.
        instruction_overrides.insert(location_hi, InstExt::nop());
        instruction_overrides.insert(location_lo, new_instruction);
    }

    Ok(())
}

fn parse_function_symbols<H>(elf: &Elf<H>) -> Result<Vec<(Source, String)>, ProgramFromElfError>
where
    H: object::read::elf::FileHeader<Endian = object::LittleEndian>,
{
    let mut functions = Vec::new();
    for sym in elf.symbols() {
        match sym.kind() {
            object::elf::STT_FUNC => {
                let (section, offset) = sym.section_and_offset()?;
                let Some(name) = sym.name() else { continue };

                if name.is_empty() {
                    continue;
                }

                let source = Source {
                    section_index: section.index(),
                    offset_range: (offset..offset + sym.size()).into(),
                };

                functions.push((source, name.to_owned()));
            }
            object::elf::STT_NOTYPE | object::elf::STT_OBJECT | object::elf::STT_SECTION | object::elf::STT_FILE => {}
            kind => return Err(ProgramFromElfError::other(format!("unsupported symbol type: {}", kind))),
        }
    }

    functions.sort_unstable_by_key(|(source, _)| *source);
    functions.dedup_by_key(|(source, _)| *source);

    Ok(functions)
}

pub struct Config {
    strip: bool,
    optimize: bool,
    inline_threshold: usize,
    elide_unnecessary_loads: bool,
    dispatch_table: Vec<Vec<u8>>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            strip: false,
            optimize: true,
            inline_threshold: 2,
            elide_unnecessary_loads: true,
            dispatch_table: Vec::new(),
        }
    }
}

impl Config {
    pub fn set_strip(&mut self, value: bool) -> &mut Self {
        self.strip = value;
        self
    }

    pub fn set_optimize(&mut self, value: bool) -> &mut Self {
        self.optimize = value;
        self
    }

    pub fn set_inline_threshold(&mut self, value: usize) -> &mut Self {
        self.inline_threshold = value;
        self
    }

    pub fn set_elide_unnecessary_loads(&mut self, value: bool) -> &mut Self {
        self.elide_unnecessary_loads = value;
        self
    }

    pub fn set_dispatch_table(&mut self, dispatch_table: Vec<Vec<u8>>) -> &mut Self {
        self.dispatch_table = dispatch_table;
        self
    }
}

pub fn program_from_elf(config: Config, data: &[u8]) -> Result<Vec<u8>, ProgramFromElfError> {
    match Elf::<object::elf::FileHeader32<object::endian::LittleEndian>>::parse(data) {
        Ok(elf) => program_from_elf_internal(config, elf),
        Err(ProgramFromElfError(ProgramFromElfErrorKind::FailedToParseElf(e))) if e.to_string() == "Unsupported ELF header" => {
            let elf = Elf::<object::elf::FileHeader64<object::endian::LittleEndian>>::parse(data)?;
            program_from_elf_internal(config, elf)
        }
        Err(e) => Err(e),
    }
}

fn program_from_elf_internal<H>(config: Config, mut elf: Elf<H>) -> Result<Vec<u8>, ProgramFromElfError>
where
    H: object::read::elf::FileHeader<Endian = object::LittleEndian>,
{
    let is_rv64 = elf.is_64();
    let bitness = if is_rv64 { Bitness::B64 } else { Bitness::B32 };

    if elf.section_by_name(".got").next().is_none() {
        elf.add_empty_data_section(".got");
    }

    let mut decoder_config = DecoderConfig::new_32bit();
    decoder_config.set_rv64(elf.is_64());

    let mut sections_ro_data = Vec::new();
    let mut sections_rw_data = Vec::new();
    let mut sections_bss = Vec::new();
    let mut sections_code = Vec::new();
    let mut sections_metadata = Vec::new();
    let mut sections_exports = Vec::new();
    let mut sections_min_stack_size = Vec::new();
    let mut sections_other = Vec::new();

    for section in elf.sections() {
        let name = section.name();
        let is_writable = section.is_writable();
        if name == ".rodata"
            || name.starts_with(".rodata.")
            || name == ".data.rel.ro"
            || name.starts_with(".data.rel.ro.")
            || name == ".got"
            || name == ".got.plt"
            || name == ".relro_padding"
        {
            if name == ".rodata" && is_writable {
                return Err(ProgramFromElfError::other(format!(
                    "expected section '{name}' to be read-only, yet it is writable"
                )));
            }

            sections_ro_data.push(section.index());
        } else if name == ".data" || name.starts_with(".data.") || name == ".sdata" || name.starts_with(".sdata.") {
            if !is_writable {
                return Err(ProgramFromElfError::other(format!(
                    "expected section '{name}' to be writable, yet it is read-only"
                )));
            }

            sections_rw_data.push(section.index());
        } else if name == ".bss" || name.starts_with(".bss.") || name == ".sbss" || name.starts_with(".sbss.") {
            if !is_writable {
                return Err(ProgramFromElfError::other(format!(
                    "expected section '{name}' to be writable, yet it is read-only"
                )));
            }

            sections_bss.push(section.index());
        } else if name == ".text" || name.starts_with(".text.") {
            if is_writable {
                return Err(ProgramFromElfError::other(format!(
                    "expected section '{name}' to be read-only, yet it is writable"
                )));
            }

            sections_code.push(section.index());
        } else if name == ".polkavm_metadata" {
            sections_metadata.push(section.index());
        } else if name == ".polkavm_exports" {
            sections_exports.push(section.index());
        } else if name == ".polkavm_min_stack_size" {
            sections_min_stack_size.push(section.index());
        } else if name == ".eh_frame" || name == ".got" {
            continue;
        } else if section.is_allocated() {
            // We're supposed to load this section into memory at runtime, but we don't know what it is.
            return Err(ProgramFromElfErrorKind::UnsupportedSection(name.to_owned()).into());
        } else {
            sections_other.push(section.index());
        }
    }

    if sections_code.is_empty() {
        return Err(ProgramFromElfError::other(
            "the program contains no code (linking empty programs is not supported!)",
        ));
    }

    let section_regspill = elf.add_empty_data_section(".regspill");
    sections_rw_data.insert(0, section_regspill);

    let code_sections_set: HashSet<SectionIndex> = sections_code.iter().copied().collect();
    let data_sections = sections_ro_data
        .iter()
        .chain(sections_rw_data.iter())
        .chain(sections_bss.iter()) // Shouldn't need relocations, but just in case.
        .chain(sections_other.iter())
        .chain(sections_metadata.iter())
        .chain(sections_exports.iter())
        .copied();

    let mut relocations = BTreeMap::new();
    for section_index in data_sections {
        let section = elf.section_by_index(section_index);
        harvest_data_relocations(&elf, &code_sections_set, section, &mut relocations)?;
    }

    let mut instruction_overrides = HashMap::new();
    for &section_index in &sections_code {
        let section = elf.section_by_index(section_index);
        harvest_code_relocations(&elf, section, &decoder_config, &mut instruction_overrides, &mut relocations)?;
    }

    let exports = sections_exports
        .iter()
        .map(|&section_index| {
            let section = elf.section_by_index(section_index);
            extract_exports(&elf, &relocations, section)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut exports: Vec<_> = exports.into_iter().flatten().collect();

    let mut instructions = Vec::new();
    let mut imports = Vec::new();

    for &section_index in &sections_code {
        let section = elf.section_by_index(section_index);
        let initial_instruction_count = instructions.len();
        parse_code_section(
            &elf,
            section,
            &decoder_config,
            &relocations,
            &mut imports,
            &mut instruction_overrides,
            &mut instructions,
        )?;

        if instructions.len() > initial_instruction_count {
            // Sometimes a section ends with a `call`, which (considering sections can be reordered) would put
            // the return address out of bounds of the section, so let's inject an `unimp` here to make sure this doesn't happen.
            //
            // If it ends up being unnecessary the optimizer will remove it anyway.
            let last_source = instructions.last().unwrap().0;
            let source = Source {
                section_index: last_source.section_index,
                offset_range: (last_source.offset_range.end..last_source.offset_range.end + 4).into(),
            };
            instructions.push((source, InstExt::Control(ControlInst::Unimplemented)));
        }
    }

    if !instruction_overrides.is_empty() {
        return Err(ProgramFromElfError::other("internal error: instruction overrides map is not empty"));
    }

    core::mem::drop(instruction_overrides);

    assert!(instructions
        .iter()
        .all(|(source, _)| source.offset_range.start < source.offset_range.end));

    {
        let strip_relocations_for_sections: HashSet<_> =
            sections_metadata.iter().copied().chain(sections_exports.iter().copied()).collect();

        relocations.retain(|relocation_target, _| !strip_relocations_for_sections.contains(&relocation_target.section_index));
    }

    let data_sections_set: HashSet<SectionIndex> = sections_ro_data
        .iter()
        .chain(sections_rw_data.iter())
        .chain(sections_bss.iter()) // Shouldn't need relocations, but just in case.
        .copied()
        .collect();

    let all_jump_targets = harvest_all_jump_targets(&elf, &data_sections_set, &code_sections_set, &instructions, &relocations, &exports)?;
    let all_blocks = split_code_into_basic_blocks(&elf, &all_jump_targets, instructions)?;
    for block in &all_blocks {
        for source in block.next.source.as_slice() {
            assert!(source.offset_range.start < source.offset_range.end);
        }
    }

    let mut section_to_block = build_section_to_block_map(&all_blocks)?;
    let mut all_blocks = resolve_basic_block_references(&data_sections_set, &section_to_block, &all_blocks)?;
    let mut reachability_graph;
    let mut used_blocks;

    let mut regspill_size = 0;
    if config.optimize {
        reachability_graph = calculate_reachability(&section_to_block, &all_blocks, &data_sections_set, &exports, &relocations)?;
        optimize_program(&config, &elf, &imports, &mut all_blocks, &mut reachability_graph, &mut exports);
        used_blocks = collect_used_blocks(&all_blocks, &reachability_graph);
        spill_fake_registers(
            section_regspill,
            &mut all_blocks,
            &mut reachability_graph,
            &imports,
            &used_blocks,
            &mut regspill_size,
            is_rv64,
        );
        used_blocks = add_missing_fallthrough_blocks(&mut all_blocks, &mut reachability_graph, used_blocks);
        merge_consecutive_fallthrough_blocks(&mut all_blocks, &mut reachability_graph, &mut section_to_block, &mut used_blocks);
        replace_immediates_with_registers(&mut all_blocks, &imports, &used_blocks);

        let expected_reachability_graph =
            calculate_reachability(&section_to_block, &all_blocks, &data_sections_set, &exports, &relocations)?;
        if reachability_graph != expected_reachability_graph {
            panic!("internal error: inconsistent reachability after optimization; this is a bug, please report it!");
        }
    } else {
        for current in (0..all_blocks.len()).map(BlockTarget::from_raw) {
            perform_nop_elimination(&mut all_blocks, current);
        }

        reachability_graph = ReachabilityGraph::default();
        for current in (0..all_blocks.len()).map(BlockTarget::from_raw) {
            let reachability = reachability_graph.for_code.entry(current).or_default();

            reachability.always_reachable = true;
            reachability.always_dynamically_reachable = true;
        }

        for &section_index in sections_ro_data.iter().chain(sections_rw_data.iter()) {
            let reachability = reachability_graph.for_data.entry(section_index).or_default();

            reachability.always_reachable = true;
            reachability.always_dynamically_reachable = true;
        }

        for (export_index, export) in exports.iter().enumerate() {
            let Some(&block_target) = section_to_block.get(&export.location) else {
                return Err(ProgramFromElfError::other("export points to a non-block"));
            };

            reachability_graph
                .for_code
                .entry(block_target)
                .or_default()
                .exports
                .push(export_index);
        }

        used_blocks = (0..all_blocks.len()).map(BlockTarget::from_raw).collect();
        spill_fake_registers(
            section_regspill,
            &mut all_blocks,
            &mut reachability_graph,
            &imports,
            &used_blocks,
            &mut regspill_size,
            is_rv64,
        );
    }

    elf.extend_section_to_at_least(section_regspill, regspill_size);

    for &section_index in &sections_other {
        if reachability_graph.is_data_section_reachable(section_index) {
            return Err(ProgramFromElfError::other(format!(
                "unsupported section used in program graph: '{name}'",
                name = elf.section_by_index(section_index).name(),
            )));
        }
    }

    log::debug!("Exports found: {}", exports.len());

    {
        let mut count_dynamic = 0;
        for reachability in reachability_graph.for_code.values() {
            if reachability.is_dynamically_reachable() {
                count_dynamic += 1;
            }
        }
        log::debug!(
            "Blocks used: {}/{} ({} dynamically reachable, {} statically reachable)",
            reachability_graph.for_code.len(),
            all_blocks.len(),
            count_dynamic,
            reachability_graph.for_code.len() - count_dynamic
        );
    }

    let section_got = elf.add_empty_data_section(".got");
    sections_ro_data.push(section_got);
    reachability_graph.mark_data_section_reachable(section_got);

    let mut target_to_got_offset: HashMap<AnyTarget, u64> = HashMap::new();
    let mut got_size = 0;

    let mut used_imports = HashSet::new();
    for block in &all_blocks {
        if !reachability_graph.is_code_reachable(block.target) {
            continue;
        }

        for (_, instruction) in &block.ops {
            match instruction {
                BasicInst::LoadAddressIndirect { target, .. } => {
                    if target_to_got_offset.contains_key(target) {
                        continue;
                    }

                    let offset = target_to_got_offset.len() as u64 * u64::from(bitness);
                    target_to_got_offset.insert(*target, offset);
                    got_size = offset + u64::from(bitness);

                    let target = match target {
                        AnyTarget::Data(target) => *target,
                        AnyTarget::Code(target) => all_blocks[target.index()].source.begin(),
                    };

                    relocations.insert(
                        SectionTarget {
                            section_index: section_got,
                            offset,
                        },
                        RelocationKind::Abs {
                            target,
                            size: bitness.into(),
                        },
                    );
                }
                BasicInst::Ecalli { nth_import } => {
                    used_imports.insert(*nth_import);
                }
                _ => {}
            }
        }
    }

    elf.extend_section_to_at_least(section_got, got_size.try_into().expect("overflow"));
    check_imports_and_assign_indexes(&mut imports, &used_imports)?;

    let mut base_address_for_section = HashMap::new();
    let sections_ro_data: Vec<_> = sections_ro_data
        .into_iter()
        .filter(|section_index| reachability_graph.is_data_section_reachable(*section_index))
        .collect();

    let sections_rw_data: Vec<_> = sections_rw_data
        .into_iter()
        .filter(|section_index| reachability_graph.is_data_section_reachable(*section_index))
        .collect();

    let memory_config = extract_memory_config(
        &elf,
        &sections_ro_data,
        &sections_rw_data,
        &sections_bss,
        &sections_min_stack_size,
        &mut base_address_for_section,
    )?;

    log::trace!("Memory configuration: {:#?}", memory_config);

    let (jump_table, jump_target_for_block) = build_jump_table(all_blocks.len(), &used_blocks, &reachability_graph);
    let code = emit_code(
        &imports,
        &base_address_for_section,
        section_got,
        &target_to_got_offset,
        &all_blocks,
        &used_blocks,
        &used_imports,
        &jump_target_for_block,
        config.optimize,
        is_rv64,
    )?;

    {
        // Assign dummy base addresses to all other sections.
        //
        // This is mostly used for debug info.
        for &section_index in &sections_other {
            let address = elf.section_by_index(section_index).original_address();
            assert!(!reachability_graph.is_data_section_reachable(section_index));
            assert!(base_address_for_section.insert(section_index, address).is_none());
        }
    }

    for (&relocation_target, &relocation) in &relocations {
        let section = elf.section_by_index(relocation_target.section_index);
        if !reachability_graph.is_data_section_reachable(relocation_target.section_index) {
            continue;
        }

        log::trace!(
            "Applying relocation to '{}'[0x{:x}] {relocation_target}: {:?}",
            section.name(),
            relocation_target.offset,
            relocation
        );

        fn write_generic(size: RelocationSize, data: &mut [u8], relative_address: u64, value: u64) -> Result<(), ProgramFromElfError> {
            match size {
                RelocationSize::U64 => write_u64(data, relative_address, value),
                RelocationSize::U32 => {
                    let Ok(value) = u32::try_from(value) else {
                        return Err(ProgramFromElfError::other(
                            "overflow when applying relocations: value doesn't fit in an u32",
                        ));
                    };

                    write_u32(data, relative_address, value)
                }
                RelocationSize::U16 => {
                    let Ok(value) = u16::try_from(value) else {
                        return Err(ProgramFromElfError::other(
                            "overflow when applying relocations: value doesn't fit in an u16",
                        ));
                    };

                    write_u16(data, relative_address, value)
                }
                RelocationSize::U8 => {
                    let Ok(value) = u8::try_from(value) else {
                        return Err(ProgramFromElfError::other(
                            "overflow when applying relocations: value doesn't fit in an u8",
                        ));
                    };

                    data[relative_address as usize] = value;
                    Ok(())
                }
            }
        }

        match relocation {
            RelocationKind::Size {
                section_index: _,
                range,
                size,
            } => {
                // These relocations should only be used in debug info sections.
                if reachability_graph.is_data_section_reachable(section.index()) {
                    return Err(ProgramFromElfError::other(format!(
                        "relocation was not expected in section '{name}': {relocation:?}",
                        name = section.name(),
                    )));
                }

                let data = elf.section_data_mut(relocation_target.section_index);
                let value = range.end - range.start;
                match size {
                    SizeRelocationSize::Uleb128 => {
                        overwrite_uleb128(data, relocation_target.offset as usize, value)?;
                    }
                    SizeRelocationSize::SixBits => {
                        let mask = 0b00111111;
                        if value > mask {
                            return Err(ProgramFromElfError::other("six bit relocation overflow"));
                        }

                        let output = (u64::from(read_u8(data, relocation_target.offset)?) & (!mask)) | (value & mask);
                        data[relocation_target.offset as usize] = output as u8;
                    }
                    SizeRelocationSize::Generic(size) => {
                        write_generic(size, data, relocation_target.offset, value)?;
                    }
                }
            }
            RelocationKind::Abs { target, size } => {
                if let Some(&block_target) = section_to_block.get(&target) {
                    let Some(jump_target) = jump_target_for_block[block_target.index()] else {
                        if !reachability_graph.is_data_section_reachable(relocation_target.section_index) {
                            // Most likely debug info for something that was stripped out.
                            let data = elf.section_data_mut(relocation_target.section_index);
                            write_generic(size, data, relocation_target.offset, 0)?;
                            continue;
                        }

                        return Err(ProgramFromElfError::other(format!(
                            "absolute relocation in section '{location_name}' targets section '{target_name}'[0x{target_offset:x}] which has no associated basic block",
                            location_name = elf.section_by_index(relocation_target.section_index).name(),
                            target_name = elf.section_by_index(target.section_index).name(),
                            target_offset = target.offset,
                        )));
                    };

                    let jump_target = jump_target.dynamic_target.expect("missing jump target for address");
                    let Some(jump_target) = jump_target.checked_mul(VM_CODE_ADDRESS_ALIGNMENT) else {
                        return Err(ProgramFromElfError::other("overflow when applying a jump target relocation"));
                    };

                    let data = elf.section_data_mut(relocation_target.section_index);
                    write_generic(size, data, relocation_target.offset, jump_target.into())?;
                } else {
                    let Some(section_base) = base_address_for_section.get(&target.section_index) else {
                        if !reachability_graph.is_data_section_reachable(relocation_target.section_index) {
                            let data = elf.section_data_mut(relocation_target.section_index);
                            write_generic(size, data, relocation_target.offset, 0)?;
                            continue;
                        }

                        return Err(ProgramFromElfError::other(format!(
                            "absolute relocation in section '{location_name}' targets section '{target_name}'[0x{target_offset:x}] which has no relocated base address assigned",
                            location_name = elf.section_by_index(relocation_target.section_index).name(),
                            target_name = elf.section_by_index(target.section_index).name(),
                            target_offset = target.offset,
                        )));
                    };

                    let Some(value) = section_base.checked_add(target.offset) else {
                        return Err(ProgramFromElfError::other("overflow when applying an absolute relocation"));
                    };

                    let data = elf.section_data_mut(relocation_target.section_index);
                    write_generic(size, data, relocation_target.offset, value)?;
                }
            }
            RelocationKind::JumpTable { target_code, target_base } => {
                let Some(&block_target) = section_to_block.get(&target_code) else {
                    return Err(ProgramFromElfError::other(
                        "jump table relocation doesn't refers to a start of a basic block",
                    ));
                };

                let Some(jump_target) = jump_target_for_block[block_target.index()] else {
                    return Err(ProgramFromElfError::other(
                        "no jump target for block was found when applying a jump table relocation",
                    ));
                };

                let Some(section_base) = base_address_for_section.get(&target_base.section_index) else {
                    return Err(ProgramFromElfError::other(
                        "no base address for section when applying a jump table relocation",
                    ));
                };

                let Some(base_address) = section_base.checked_add(target_base.offset) else {
                    return Err(ProgramFromElfError::other(
                        "overflow when applying a jump table relocation: section base and offset cannot be added together",
                    ));
                };

                let Ok(base_address) = u32::try_from(base_address) else {
                    return Err(ProgramFromElfError::other(
                        "overflow when applying a jump table relocation: base address doesn't fit in a u32",
                    ));
                };

                let jump_target = jump_target.dynamic_target.expect("missing jump target for address");
                let Some(jump_target) = jump_target.checked_mul(VM_CODE_ADDRESS_ALIGNMENT) else {
                    return Err(ProgramFromElfError::other(
                        "overflow when applying a jump table relocation: jump target is too big",
                    ));
                };

                let value = jump_target.wrapping_sub(base_address);
                let data = elf.section_data_mut(relocation_target.section_index);
                write_u32(data, relocation_target.offset, value)?;
            }
        }
    }

    let mut location_map: HashMap<SectionTarget, Arc<[Location]>> = HashMap::new();
    if !config.strip {
        let mut string_cache = crate::utils::StringCache::default();
        let dwarf_info = crate::dwarf::load_dwarf(&mut string_cache, &elf, &relocations)?;
        location_map = dwarf_info.location_map;

        // If there is no DWARF info present try to use the symbol table as a fallback.
        for (source, name) in parse_function_symbols(&elf)? {
            if location_map.contains_key(&source.begin()) {
                continue;
            }

            let (namespace, function_name) = split_function_name(&name);
            let namespace = if namespace.is_empty() {
                None
            } else {
                Some(string_cache.dedup(&namespace))
            };

            let location = Location {
                kind: FrameKind::Enter,
                namespace,
                function_name: Some(string_cache.dedup(&function_name)),
                source_code_location: None,
            };

            let location_stack: Arc<[Location]> = vec![location].into();
            for target in source.iter() {
                location_map.insert(target, Arc::clone(&location_stack));
            }
        }
    }

    log::trace!("Instruction count: {}", code.len());

    let mut builder = if elf.is_64() {
        ProgramBlobBuilder::new_64bit()
    } else {
        ProgramBlobBuilder::new()
    };

    builder.set_ro_data_size(memory_config.ro_data_size);
    builder.set_rw_data_size(memory_config.rw_data_size);
    builder.set_stack_size(memory_config.min_stack_size);

    let [ro_data, rw_data] = {
        [memory_config.ro_data, memory_config.rw_data].map(|ranges| {
            let mut buffer = Vec::new();
            for range in ranges {
                match range {
                    DataRef::Section { section_index, range } => {
                        let slice = &elf.section_by_index(section_index).data()[range];
                        buffer.extend_from_slice(slice);
                    }
                    DataRef::Padding(bytes) => {
                        let new_size = buffer.len() + bytes;
                        buffer.resize(new_size, 0);
                    }
                }
            }
            buffer
        })
    };

    builder.set_ro_data(ro_data);
    builder.set_rw_data(rw_data);

    {
        let mut sorted_imports = imports.clone();
        sorted_imports.sort_by(|a, b| {
            a.metadata
                .index
                .cmp(&b.metadata.index)
                .then_with(|| a.metadata.symbol.cmp(&b.metadata.symbol))
        });

        let mut next_index = 0;
        for import in sorted_imports {
            let Some(index) = import.index else {
                continue;
            };

            assert_eq!(index, next_index);
            next_index += 1;

            builder.add_import(&import.metadata.symbol);
        }
    }

    let mut export_count = 0;
    for current in used_blocks {
        for &export_index in &reachability_graph.for_code.get(&current).unwrap().exports {
            let export = &exports[export_index];
            let jump_target = jump_target_for_block[current.index()]
                .expect("internal error: export metadata points to a block without a jump target assigned");

            builder.add_export_by_basic_block(jump_target.static_target, &export.metadata.symbol);
            export_count += 1;
        }
    }
    assert_eq!(export_count, exports.len());

    let mut locations_for_instruction: Vec<Option<Arc<[Location]>>> = Vec::with_capacity(code.len());
    let mut raw_code = Vec::with_capacity(code.len());

    for (nth_inst, (source_stack, inst)) in code.into_iter().enumerate() {
        raw_code.push(inst);

        let mut function_name = None;
        if !config.strip {
            // Two or more addresses can point to the same instruction (e.g. in case of macro op fusion).
            // Two or more instructions can also have the same address (e.g. in case of jump targets).

            // TODO: Use a smallvec.
            let mut list = Vec::new();
            for source in source_stack.as_slice() {
                for offset in (source.offset_range.start..source.offset_range.end).step_by(2) {
                    let target = SectionTarget {
                        section_index: source.section_index,
                        offset,
                    };

                    if let Some(locations) = location_map.get(&target) {
                        if let Some(last) = list.last() {
                            if locations == last {
                                // If we inlined a basic block from the same function do not repeat the same location.
                                break;
                            }
                        } else {
                            function_name = locations[0].function_name.as_deref();
                        }

                        list.push(Arc::clone(locations));
                        break;
                    }
                }

                if list.is_empty() {
                    // If the toplevel source doesn't have a location don't try the lower ones.
                    break;
                }
            }

            if list.is_empty() {
                locations_for_instruction.push(None);
            } else if list.len() == 1 {
                locations_for_instruction.push(list.into_iter().next())
            } else {
                let mut new_list = Vec::new();
                for sublist in list {
                    new_list.extend(sublist.iter().cloned());
                }

                locations_for_instruction.push(Some(new_list.into()));
            }
        }

        log::trace!(
            "Code: 0x{source_address:x} [{function_name}] -> {source_stack} -> #{nth_inst}: {inst}",
            source_address = {
                elf.section_by_index(source_stack.top().section_index)
                    .original_address()
                    .wrapping_add(source_stack.top().offset_range.start)
            },
            function_name = function_name.unwrap_or("")
        );
    }

    for symbol in config.dispatch_table {
        builder.add_dispatch_table_entry(symbol);
    }

    builder.set_code(&raw_code, &jump_table);

    let mut offsets = Vec::new();
    if !config.strip {
        let blob = ProgramBlob::parse(builder.to_vec().into())?;
        offsets = blob
            .instructions(bitness)
            .map(|instruction| (instruction.offset, instruction.next_offset))
            .collect();
        assert_eq!(offsets.len(), locations_for_instruction.len());

        emit_debug_info(&mut builder, &locations_for_instruction, &offsets);
    }

    let raw_blob = builder.to_vec();

    log::debug!("Built a program of {} bytes", raw_blob.len());
    let blob = ProgramBlob::parse(raw_blob[..].into())?;

    // Sanity check that our debug info was properly emitted and can be parsed.
    if cfg!(debug_assertions) && !config.strip {
        'outer: for (nth_instruction, locations) in locations_for_instruction.iter().enumerate() {
            let (program_counter, _) = offsets[nth_instruction];
            let line_program = blob.get_debug_line_program_at(program_counter).unwrap();
            let Some(locations) = locations else {
                assert!(line_program.is_none());
                continue;
            };

            let mut line_program = line_program.unwrap();
            while let Some(region_info) = line_program.run().unwrap() {
                if !region_info.instruction_range().contains(&program_counter) {
                    continue;
                }

                assert!(region_info.frames().len() <= locations.len());
                for (actual, expected) in region_info.frames().zip(locations.iter()) {
                    assert_eq!(actual.kind(), expected.kind);
                    assert_eq!(actual.namespace().unwrap(), expected.namespace.as_deref());
                    assert_eq!(actual.function_name_without_namespace().unwrap(), expected.function_name.as_deref());
                    assert_eq!(
                        actual.path().unwrap().map(Cow::Borrowed),
                        expected
                            .source_code_location
                            .as_ref()
                            .map(|location| simplify_path(location.path()))
                    );
                    assert_eq!(
                        actual.line(),
                        expected
                            .source_code_location
                            .as_ref()
                            .and_then(|location| location.line())
                            .and_then(|line| if line != 0 { Some(line) } else { None })
                    );
                    assert_eq!(
                        actual.column(),
                        expected
                            .source_code_location
                            .as_ref()
                            .and_then(|location| location.column())
                            .and_then(|column| if column != 0 { Some(column) } else { None })
                    );
                }

                continue 'outer;
            }

            panic!("internal error: region not found for instruction");
        }
    }

    Ok(raw_blob)
}

fn simplify_path(path: &str) -> Cow<str> {
    // TODO: Sanitize macOS and Windows paths.
    if let Some(p) = path.strip_prefix("/home/") {
        if let Some(index) = p.bytes().position(|byte| byte == b'/') {
            return format!("~{}", &p[index..]).into();
        }
    }

    path.into()
}

fn emit_debug_info(
    builder: &mut ProgramBlobBuilder,
    locations_for_instruction: &[Option<Arc<[Location]>>],
    offsets: &[(ProgramCounter, ProgramCounter)],
) {
    #[derive(Default)]
    struct DebugStringsBuilder<'a> {
        map: HashMap<Cow<'a, str>, u32>,
        section: Vec<u8>,
        write_protected: bool,
    }

    impl<'a> DebugStringsBuilder<'a> {
        fn dedup_cow(&mut self, s: Cow<'a, str>) -> u32 {
            if let Some(offset) = self.map.get(&s) {
                return *offset;
            }

            assert!(!self.write_protected);

            let offset = self.section.len();
            let mut buffer = [0xff_u8; varint::MAX_VARINT_LENGTH];
            let length = varint::write_varint(s.len().try_into().expect("debug string length overflow"), &mut buffer);
            self.section.extend_from_slice(&buffer[..length]);
            self.section.extend_from_slice(s.as_bytes());
            let offset: u32 = offset.try_into().expect("debug string section length overflow");
            self.map.insert(s, offset);
            offset
        }

        fn dedup(&mut self, s: &'a str) -> u32 {
            self.dedup_cow(s.into())
        }
    }

    let mut dbg_strings = DebugStringsBuilder::default();
    let empty_string_id = dbg_strings.dedup("");

    struct Group<'a> {
        namespace: Option<Arc<str>>,
        function_name: Option<Arc<str>>,
        path: Option<Cow<'a, str>>,
        instruction_position: usize,
        instruction_count: usize,
        program_counter_start: ProgramCounter,
        program_counter_end: ProgramCounter,
    }

    impl<'a> Group<'a> {
        fn key(&self) -> (Option<&str>, Option<&str>, Option<&str>) {
            (self.namespace.as_deref(), self.function_name.as_deref(), self.path.as_deref())
        }
    }

    let mut groups: Vec<Group> = Vec::new();
    for (instruction_position, locations) in locations_for_instruction.iter().enumerate() {
        let group = if let Some(locations) = locations {
            for location in locations.iter() {
                if let Some(ref namespace) = location.namespace {
                    dbg_strings.dedup(namespace);
                }

                if let Some(ref name) = location.function_name {
                    dbg_strings.dedup(name);
                }

                if let Some(ref location) = location.source_code_location {
                    dbg_strings.dedup_cow(simplify_path(location.path()));
                }
            }

            let location = &locations[0];
            Group {
                namespace: location.namespace.clone(),
                function_name: location.function_name.clone(),
                path: location.source_code_location.as_ref().map(|target| simplify_path(target.path())),
                instruction_position,
                instruction_count: 1,
                program_counter_start: offsets[instruction_position].0,
                program_counter_end: offsets[instruction_position].1,
            }
        } else {
            Group {
                namespace: None,
                function_name: None,
                path: None,
                instruction_position,
                instruction_count: 1,
                program_counter_start: offsets[instruction_position].0,
                program_counter_end: offsets[instruction_position].1,
            }
        };

        if let Some(last_group) = groups.last_mut() {
            if last_group.key() == group.key() {
                assert_eq!(last_group.instruction_position + last_group.instruction_count, instruction_position);
                last_group.instruction_count += 1;
                last_group.program_counter_end = group.program_counter_end;
                continue;
            }
        }

        groups.push(group);
    }

    groups.retain(|group| group.function_name.is_some() || group.path.is_some());

    log::trace!("Location groups: {}", groups.len());
    dbg_strings.write_protected = true;

    let mut section_line_programs = Vec::new();
    let mut info_offsets = Vec::with_capacity(groups.len());
    {
        let mut writer = Writer::new(&mut section_line_programs);
        let writer = &mut writer;

        let offset_base = writer.len();
        writer.push_byte(program::VERSION_DEBUG_LINE_PROGRAM_V1);
        for group in &groups {
            let info_offset: u32 = (writer.len() - offset_base).try_into().expect("function info offset overflow");
            info_offsets.push(info_offset);

            #[derive(Default)]
            struct LineProgramFrame {
                kind: Option<FrameKind>,
                namespace: Option<Arc<str>>,
                function_name: Option<Arc<str>>,
                path: Option<Arc<str>>,
                line: Option<u32>,
                column: Option<u32>,
            }

            #[derive(Default)]
            struct LineProgramState {
                stack: Vec<LineProgramFrame>,
                stack_depth: usize,
                mutation_depth: usize,

                queued_count: u32,
            }

            impl LineProgramState {
                fn flush_if_any_are_queued(&mut self, writer: &mut Writer) {
                    if self.queued_count == 0 {
                        return;
                    }

                    if self.queued_count == 1 {
                        writer.push_byte(LineProgramOp::FinishInstruction as u8);
                    } else {
                        writer.push_byte(LineProgramOp::FinishMultipleInstructions as u8);
                        writer.push_varint(self.queued_count);
                    }

                    self.queued_count = 0;
                }

                fn set_mutation_depth(&mut self, writer: &mut Writer, depth: usize) {
                    self.flush_if_any_are_queued(writer);

                    if depth == self.mutation_depth {
                        return;
                    }

                    writer.push_byte(LineProgramOp::SetMutationDepth as u8);
                    writer.push_varint(depth as u32);
                    self.mutation_depth = depth;
                }

                fn set_stack_depth(&mut self, writer: &mut Writer, depth: usize) {
                    if self.stack_depth == depth {
                        return;
                    }

                    while depth > self.stack.len() {
                        self.stack.push(LineProgramFrame::default());
                    }

                    self.flush_if_any_are_queued(writer);

                    writer.push_byte(LineProgramOp::SetStackDepth as u8);
                    writer.push_varint(depth as u32);
                    self.stack_depth = depth;
                }

                fn finish_instruction(&mut self, writer: &mut Writer, next_depth: usize, instruction_length: u32) {
                    self.queued_count += instruction_length;

                    enum Direction {
                        GoDown,
                        GoUp,
                    }

                    let dir = if next_depth == self.stack_depth + 1 {
                        Direction::GoDown
                    } else if next_depth + 1 == self.stack_depth {
                        Direction::GoUp
                    } else {
                        return;
                    };

                    while next_depth > self.stack.len() {
                        self.stack.push(LineProgramFrame::default());
                    }

                    match (self.queued_count == 1, dir) {
                        (true, Direction::GoDown) => {
                            writer.push_byte(LineProgramOp::FinishInstructionAndIncrementStackDepth as u8);
                        }
                        (false, Direction::GoDown) => {
                            writer.push_byte(LineProgramOp::FinishMultipleInstructionsAndIncrementStackDepth as u8);
                            writer.push_varint(self.queued_count);
                        }
                        (true, Direction::GoUp) => {
                            writer.push_byte(LineProgramOp::FinishInstructionAndDecrementStackDepth as u8);
                        }
                        (false, Direction::GoUp) => {
                            writer.push_byte(LineProgramOp::FinishMultipleInstructionsAndDecrementStackDepth as u8);
                            writer.push_varint(self.queued_count);
                        }
                    }

                    self.stack_depth = next_depth;
                    self.queued_count = 0;
                }
            }

            let mut state = LineProgramState::default();
            for nth_instruction in group.instruction_position..group.instruction_position + group.instruction_count {
                let locations = locations_for_instruction[nth_instruction].as_ref().unwrap();
                state.set_stack_depth(writer, locations.len());

                for (depth, location) in locations.iter().enumerate() {
                    let new_path = location
                        .source_code_location
                        .as_ref()
                        .map(|location| simplify_path(location.path()));
                    let new_line = location.source_code_location.as_ref().and_then(|location| location.line());
                    let new_column = location.source_code_location.as_ref().and_then(|location| location.column());

                    let changed_kind = state.stack[depth].kind != Some(location.kind);
                    let changed_namespace = state.stack[depth].namespace != location.namespace;
                    let changed_function_name = state.stack[depth].function_name != location.function_name;
                    let changed_path = state.stack[depth].path.as_deref().map(Cow::Borrowed) != new_path;
                    let changed_line = state.stack[depth].line != new_line;
                    let changed_column = state.stack[depth].column != new_column;

                    if changed_kind {
                        state.set_mutation_depth(writer, depth);
                        state.stack[depth].kind = Some(location.kind);
                        let kind = match location.kind {
                            FrameKind::Enter => LineProgramOp::SetKindEnter,
                            FrameKind::Call => LineProgramOp::SetKindCall,
                            FrameKind::Line => LineProgramOp::SetKindLine,
                        };
                        writer.push_byte(kind as u8);
                    }

                    if changed_namespace {
                        state.set_mutation_depth(writer, depth);
                        writer.push_byte(LineProgramOp::SetNamespace as u8);
                        state.stack[depth].namespace = location.namespace.clone();

                        let namespace_offset = location
                            .namespace
                            .as_ref()
                            .map_or(empty_string_id, |string| dbg_strings.dedup(string));
                        writer.push_varint(namespace_offset);
                    }

                    if changed_function_name {
                        state.set_mutation_depth(writer, depth);
                        writer.push_byte(LineProgramOp::SetFunctionName as u8);
                        state.stack[depth].function_name = location.function_name.clone();

                        let function_name_offset = location
                            .function_name
                            .as_ref()
                            .map_or(empty_string_id, |string| dbg_strings.dedup(string));
                        writer.push_varint(function_name_offset);
                    }

                    if changed_path {
                        state.set_mutation_depth(writer, depth);
                        writer.push_byte(LineProgramOp::SetPath as u8);
                        state.stack[depth].path =
                            location
                                .source_code_location
                                .as_ref()
                                .map(|location| match simplify_path(location.path()) {
                                    Cow::Borrowed(_) => Arc::clone(location.path()),
                                    Cow::Owned(path) => path.into(),
                                });

                        let path_offset = location
                            .source_code_location
                            .as_ref()
                            .map_or(empty_string_id, |location| dbg_strings.dedup_cow(simplify_path(location.path())));
                        writer.push_varint(path_offset);
                    }

                    if changed_line {
                        state.set_mutation_depth(writer, depth);
                        match (state.stack[depth].line, new_line) {
                            (Some(old_value), Some(new_value)) if old_value + 1 == new_value => {
                                writer.push_byte(LineProgramOp::IncrementLine as u8);
                            }
                            (Some(old_value), Some(new_value)) if new_value > old_value => {
                                writer.push_byte(LineProgramOp::AddLine as u8);
                                writer.push_varint(new_value - old_value);
                            }
                            (Some(old_value), Some(new_value)) if new_value < old_value => {
                                writer.push_byte(LineProgramOp::SubLine as u8);
                                writer.push_varint(old_value - new_value);
                            }
                            _ => {
                                writer.push_byte(LineProgramOp::SetLine as u8);
                                writer.push_varint(new_line.unwrap_or(0));
                            }
                        }
                        state.stack[depth].line = new_line;
                    }

                    if changed_column {
                        state.set_mutation_depth(writer, depth);
                        writer.push_byte(LineProgramOp::SetColumn as u8);
                        state.stack[depth].column = new_column;
                        writer.push_varint(new_column.unwrap_or(0));
                    }
                }

                let next_depth = locations_for_instruction
                    .get(nth_instruction + 1)
                    .and_then(|next_locations| next_locations.as_ref().map(|xs| xs.len()))
                    .unwrap_or(0);
                state.finish_instruction(writer, next_depth, (offsets[nth_instruction].1).0 - (offsets[nth_instruction].0).0);
            }

            state.flush_if_any_are_queued(writer);
            writer.push_byte(LineProgramOp::FinishProgram as u8);
        }
    }

    assert_eq!(info_offsets.len(), groups.len());

    let mut section_line_program_ranges = Vec::new();
    {
        let mut writer = Writer::new(&mut section_line_program_ranges);
        for (group, info_offset) in groups.iter().zip(info_offsets.into_iter()) {
            writer.push_u32(group.program_counter_start.0);
            writer.push_u32(group.program_counter_end.0);
            writer.push_u32(info_offset);
        }
    }

    builder.add_custom_section(program::SECTION_OPT_DEBUG_STRINGS, dbg_strings.section);
    builder.add_custom_section(program::SECTION_OPT_DEBUG_LINE_PROGRAMS, section_line_programs);
    builder.add_custom_section(program::SECTION_OPT_DEBUG_LINE_PROGRAM_RANGES, section_line_program_ranges);
}
