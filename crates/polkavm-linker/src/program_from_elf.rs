use polkavm_common::abi::{GuestMemoryConfig, VM_ADDR_USER_MEMORY, VM_PAGE_SIZE};
use polkavm_common::elf::{FnMetadata, ImportMetadata, INSTRUCTION_ECALLI};
use polkavm_common::program::Reg as PReg;
use polkavm_common::program::{self, FrameKind, LineProgramOp, Opcode, ProgramBlob, RawInstruction};
use polkavm_common::utils::align_to_next_page_u64;
use polkavm_common::varint;

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::ops::Range;
use std::sync::Arc;

use crate::dwarf::Location;
use crate::elf::{Elf, Section, SectionIndex};
use crate::riscv::{BranchKind, Inst, LoadKind, Reg, RegImmKind, RegRegKind, ShiftKind, StoreKind};

const JUMP_TARGET_MULTIPLIER: u32 = 4;

#[derive(Debug)]
pub enum ProgramFromElfErrorKind {
    FailedToParseElf(object::read::Error),
    FailedToParseDwarf(gimli::Error),
    FailedToParseProgram(program::ProgramParseError),
    UnsupportedSection(String),
    UnsupportedInstruction { section: String, offset: u64, instruction: u32 },
    UnsupportedRegister { reg: Reg },

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
            ProgramFromElfErrorKind::UnsupportedRegister { reg } => write!(fmt, "unsupported register: {:?}", reg),
            ProgramFromElfErrorKind::Other(message) => fmt.write_str(message),
        }
    }
}

fn check_reg(reg: Reg) -> Result<(), ProgramFromElfError> {
    use Reg::*;
    match reg {
        Zero | RA | SP | T0 | T1 | T2 | S0 | S1 | A0 | A1 | A2 | A3 | A4 | A5 => Ok(()),

        GP | TP | A6 | A7 | S2 | S3 | S4 | S5 | S6 | S7 | S8 | S9 | S10 | S11 | T3 | T4 | T5 | T6 => {
            Err(ProgramFromElfErrorKind::UnsupportedRegister { reg }.into())
        }
    }
}

fn decode_inst(raw_inst: u32) -> Result<Option<Inst>, ProgramFromElfError> {
    let Some(op) = Inst::decode(raw_inst) else {
        return Ok(None);
    };

    match op {
        Inst::LoadUpperImmediate { dst, .. } | Inst::AddUpperImmediateToPc { dst, .. } | Inst::JumpAndLink { dst, .. } => {
            check_reg(dst)?;
        }
        Inst::JumpAndLinkRegister { dst, base, .. } | Inst::Load { dst, base, .. } => {
            check_reg(dst)?;
            check_reg(base)?;
        }
        Inst::Store { src, base, .. } => {
            check_reg(src)?;
            check_reg(base)?;
        }
        Inst::Branch { src1, src2, .. } => {
            check_reg(src1)?;
            check_reg(src2)?;
        }
        Inst::RegImm { dst, src, .. } | Inst::Shift { dst, src, .. } => {
            check_reg(dst)?;
            check_reg(src)?;
        }

        Inst::RegReg { dst, src1, src2, .. } => {
            check_reg(dst)?;
            check_reg(src1)?;
            check_reg(src2)?;
        }
        Inst::Ecall | Inst::Unimplemented => {}
    }

    Ok(Some(op))
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
            .step_by(4)
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
        vec.extend(self.0.iter().cloned());
        vec.extend(stack.0.iter().cloned());

        SourceStack(vec)
    }

    fn overlay_on_top_of_inplace(&mut self, stack: &SourceStack) {
        self.0.extend(stack.0.iter().cloned());
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

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub(crate) struct SectionTarget {
    pub(crate) section_index: SectionIndex,
    pub(crate) offset: u64,
}

impl core::fmt::Display for SectionTarget {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(fmt, "<{}+{}>", self.section_index, self.offset)
    }
}

impl SectionTarget {
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
            offset: cb(offset as i32) as u32 as u64,
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

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
enum BasicInst<T> {
    LoadAbsolute { kind: LoadKind, dst: Reg, target: SectionTarget },
    StoreAbsolute { kind: StoreKind, src: Reg, target: SectionTarget },
    LoadIndirect { kind: LoadKind, dst: Reg, base: Reg, offset: i32 },
    StoreIndirect { kind: StoreKind, src: Reg, base: Reg, offset: i32 },
    LoadAddress { dst: Reg, target: T },
    // This is supposed to load the address from the GOT, instead of loading it directly as an immediate.
    LoadAddressIndirect { dst: Reg, target: T },
    RegImm { kind: RegImmKind, dst: Reg, src: Reg, imm: i32 },
    Shift { kind: ShiftKind, dst: Reg, src: Reg, amount: u8 },
    RegReg { kind: RegRegKind, dst: Reg, src1: Reg, src2: Reg },
    Ecalli { syscall: u32 },
}

impl<T> BasicInst<T> {
    fn is_nop(&self) -> bool {
        if let BasicInst::RegImm {
            kind: RegImmKind::Add,
            dst,
            src,
            imm: 0,
        } = self
        {
            if dst == src {
                return true;
            }
        }

        match *self {
            BasicInst::RegImm { dst, .. }
            | BasicInst::Shift { dst, .. }
            | BasicInst::RegReg { dst, .. }
            | BasicInst::LoadAddress { dst, .. }
            | BasicInst::LoadAddressIndirect { dst, .. } => dst == Reg::Zero,
            BasicInst::LoadAbsolute { .. }
            | BasicInst::LoadIndirect { .. }
            | BasicInst::StoreAbsolute { .. }
            | BasicInst::StoreIndirect { .. }
            | BasicInst::Ecalli { .. } => false,
        }
    }

    fn src_mask(&self, imports: &[Import]) -> RegMask {
        match *self {
            BasicInst::LoadAbsolute { .. } | BasicInst::LoadAddress { .. } | BasicInst::LoadAddressIndirect { .. } => RegMask::empty(),
            BasicInst::StoreAbsolute { src, .. } | BasicInst::RegImm { src, .. } | BasicInst::Shift { src, .. } => RegMask::from(src),
            BasicInst::LoadIndirect { base, .. } => RegMask::from(base),
            BasicInst::StoreIndirect { src, base, .. } => RegMask::from(src) | RegMask::from(base),
            BasicInst::RegReg { src1, src2, .. } => RegMask::from(src1) | RegMask::from(src2),
            BasicInst::Ecalli { syscall } => imports
                .iter()
                .find(|import| import.metadata.index.unwrap() == syscall)
                .expect("internal error: import not found")
                .src_mask(),
        }
    }

    fn dst_mask(&self, imports: &[Import]) -> RegMask {
        match *self {
            BasicInst::StoreAbsolute { .. } | BasicInst::StoreIndirect { .. } => RegMask::empty(),
            BasicInst::LoadAbsolute { dst, .. }
            | BasicInst::LoadAddress { dst, .. }
            | BasicInst::LoadAddressIndirect { dst, .. }
            | BasicInst::LoadIndirect { dst, .. }
            | BasicInst::RegImm { dst, .. }
            | BasicInst::Shift { dst, .. }
            | BasicInst::RegReg { dst, .. } => RegMask::from(dst),

            BasicInst::Ecalli { syscall } => imports
                .iter()
                .find(|import| import.metadata.index.unwrap() == syscall)
                .expect("internal error: import not found")
                .dst_mask(),
        }
    }

    fn has_side_effects(&self, config: &Config) -> bool {
        match *self {
            BasicInst::Ecalli { .. } | BasicInst::StoreAbsolute { .. } | BasicInst::StoreIndirect { .. } => true,
            BasicInst::LoadAbsolute { .. } | BasicInst::LoadIndirect { .. } => !config.elide_unnecessary_loads,
            BasicInst::LoadAddress { .. }
            | BasicInst::LoadAddressIndirect { .. }
            | BasicInst::RegImm { .. }
            | BasicInst::Shift { .. }
            | BasicInst::RegReg { .. } => false,
        }
    }

    fn map_target<U, E>(self, map: impl Fn(T) -> Result<U, E>) -> Result<BasicInst<U>, E> {
        Ok(match self {
            BasicInst::LoadAbsolute { kind, dst, target } => BasicInst::LoadAbsolute { kind, dst, target },
            BasicInst::StoreAbsolute { kind, src, target } => BasicInst::StoreAbsolute { kind, src, target },
            BasicInst::LoadAddress { dst, target } => BasicInst::LoadAddress { dst, target: map(target)? },
            BasicInst::LoadAddressIndirect { dst, target } => BasicInst::LoadAddressIndirect { dst, target: map(target)? },
            BasicInst::LoadIndirect { kind, dst, base, offset } => BasicInst::LoadIndirect { kind, dst, base, offset },
            BasicInst::StoreIndirect { kind, src, base, offset } => BasicInst::StoreIndirect { kind, src, base, offset },
            BasicInst::RegImm { kind, dst, src, imm } => BasicInst::RegImm { kind, dst, src, imm },
            BasicInst::Shift { kind, dst, src, amount } => BasicInst::Shift { kind, dst, src, amount },
            BasicInst::RegReg { kind, dst, src1, src2 } => BasicInst::RegReg { kind, dst, src1, src2 },
            BasicInst::Ecalli { syscall } => BasicInst::Ecalli { syscall },
        })
    }

    fn target(&self) -> (Option<SectionTarget>, Option<T>)
    where
        T: Copy,
    {
        match self {
            BasicInst::LoadAbsolute { target, .. } | BasicInst::StoreAbsolute { target, .. } => (Some(*target), None),
            BasicInst::LoadAddress { target, .. } | BasicInst::LoadAddressIndirect { target, .. } => (None, Some(*target)),
            BasicInst::LoadIndirect { .. }
            | BasicInst::StoreIndirect { .. }
            | BasicInst::RegImm { .. }
            | BasicInst::Shift { .. }
            | BasicInst::RegReg { .. }
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
        src1: Reg,
        src2: Reg,
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
}

#[derive(Copy, Clone, Debug)]
enum InstExt<BasicT, ControlT> {
    Basic(BasicInst<BasicT>),
    Control(ControlInst<ControlT>),
}

impl<BasicT, ControlT> InstExt<BasicT, ControlT> {
    fn nop() -> Self {
        InstExt::Basic(BasicInst::RegImm {
            kind: RegImmKind::Add,
            dst: Reg::Zero,
            src: Reg::Zero,
            imm: 0,
        })
    }
}

impl<T> ControlInst<T> {
    fn jump_or_call(ra: Reg, target: T, target_return: T) -> Self {
        if ra == Reg::Zero {
            ControlInst::Jump { target }
        } else {
            ControlInst::Call { ra, target, target_return }
        }
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
    let name = rustc_demangle::try_demangle(name)
        .ok()
        .map(|name| name.to_string())
        .unwrap_or_else(|| name.to_string());

    // Ideally we'd parse the symbol into an actual AST and use that,
    // but that's a lot of work, so for now let's just do it like this.
    let with_hash = name.to_string();
    let without_hash = format!("{:#}", name);

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

#[derive(Clone)]
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

struct MemoryConfig {
    ro_data: Vec<DataRef>,
    rw_data: Vec<DataRef>,
    bss_size: u32,
    stack_size: u32,
}

fn get_padding(memory_end: u64, align: u64) -> Option<u64> {
    let misalignment = memory_end % align;
    if misalignment == 0 {
        None
    } else {
        Some(align - misalignment)
    }
}

#[allow(clippy::too_many_arguments)]
fn extract_memory_config(
    elf: &Elf,
    sections_ro_data: &[SectionIndex],
    sections_rw_data: &[SectionIndex],
    sections_bss: &[SectionIndex],
    section_min_stack_size: Option<SectionIndex>,
    base_address_for_section: &mut HashMap<SectionIndex, u64>,
) -> Result<MemoryConfig, ProgramFromElfError> {
    let mut memory_end = VM_ADDR_USER_MEMORY as u64;
    let mut ro_data = Vec::new();
    let mut ro_data_size = 0;

    fn align_if_necessary(memory_end: &mut u64, output_size: &mut u64, output_chunks: &mut Vec<DataRef>, section: &Section) {
        if let Some(padding) = get_padding(*memory_end, section.align()) {
            *memory_end += padding;
            *output_size += padding;
            output_chunks.push(DataRef::Padding(padding as usize));
        }
    }

    assert_eq!(memory_end % VM_PAGE_SIZE as u64, 0);

    let ro_data_address = memory_end;
    for &section_index in sections_ro_data {
        let section = elf.section_by_index(section_index);
        align_if_necessary(&mut memory_end, &mut ro_data_size, &mut ro_data, section);

        let section_name = section.name();
        let base_address = memory_end;
        base_address_for_section.insert(section.index(), base_address);

        memory_end += section.size();
        ro_data.push(DataRef::Section {
            section_index: section.index(),
            range: 0..section.data().len(),
        });

        ro_data_size += section.data().len() as u64;
        let padding = section.size() - section.data().len() as u64;
        if padding > 0 {
            ro_data.push(DataRef::Padding(padding.try_into().expect("overflow")))
        }

        log::trace!(
            "Found read-only section: '{}', original range = 0x{:x}..0x{:x} (relocated to: 0x{:x}..0x{:x}), size = 0x{:x}",
            section_name,
            section.original_address(),
            section.original_address() + section.size(),
            base_address,
            base_address + section.size(),
            section.size(),
        );
    }

    {
        let ro_data_size_unaligned = ro_data_size;

        assert_eq!(ro_data_address % VM_PAGE_SIZE as u64, 0);
        ro_data_size = align_to_next_page_u64(VM_PAGE_SIZE as u64, ro_data_size)
            .ok_or(ProgramFromElfError::other("out of range size for read-only sections"))?;

        memory_end += ro_data_size - ro_data_size_unaligned;
    }

    assert_eq!(memory_end % VM_PAGE_SIZE as u64, 0);

    if ro_data_size > 0 {
        // Add a guard page between read-only data and read-write data.
        memory_end += u64::from(VM_PAGE_SIZE);
    }

    let mut rw_data = Vec::new();
    let mut rw_data_size = 0;
    let rw_data_address = memory_end;
    for &section_index in sections_rw_data {
        let section = elf.section_by_index(section_index);
        align_if_necessary(&mut memory_end, &mut rw_data_size, &mut rw_data, section);

        let section_name = section.name();
        let base_address = memory_end;
        base_address_for_section.insert(section.index(), memory_end);

        memory_end += section.size();
        rw_data.push(DataRef::Section {
            section_index: section.index(),
            range: 0..section.data().len(),
        });

        rw_data_size += section.data().len() as u64;
        let padding = section.size() - section.data().len() as u64;
        if padding > 0 {
            rw_data.push(DataRef::Padding(padding.try_into().expect("overflow")))
        }

        log::trace!(
            "Found read-write section: '{}', original range = 0x{:x}..0x{:x} (relocated to: 0x{:x}..0x{:x}), size = 0x{:x}",
            section_name,
            section.original_address(),
            section.original_address() + section.size(),
            base_address,
            base_address + section.size(),
            section.size(),
        );
    }

    let bss_explicit_address = {
        let rw_data_size_unaligned = rw_data_size;

        assert_eq!(rw_data_address % VM_PAGE_SIZE as u64, 0);
        rw_data_size = align_to_next_page_u64(VM_PAGE_SIZE as u64, rw_data_size)
            .ok_or(ProgramFromElfError::other("out of range size for read-write sections"))?;

        memory_end + (rw_data_size - rw_data_size_unaligned)
    };

    for &section_index in sections_bss {
        let section = elf.section_by_index(section_index);
        if let Some(padding) = get_padding(memory_end, section.align()) {
            memory_end += padding;
        }

        let section_name = section.name();
        let base_address = memory_end;
        base_address_for_section.insert(section.index(), memory_end);

        memory_end += section.size();

        log::trace!(
            "Found BSS section: '{}', original range = 0x{:x}..0x{:x} (relocated to: 0x{:x}..0x{:x}), size = 0x{:x}",
            section_name,
            section.original_address(),
            section.original_address() + section.size(),
            base_address,
            base_address + section.size(),
            section.size(),
        );
    }

    let mut bss_size = if memory_end > bss_explicit_address {
        memory_end - bss_explicit_address
    } else {
        0
    };

    bss_size =
        align_to_next_page_u64(VM_PAGE_SIZE as u64, bss_size).ok_or(ProgramFromElfError::other("out of range size for BSS sections"))?;

    let stack_size = if let Some(section_index) = section_min_stack_size {
        let section = elf.section_by_index(section_index);
        let data = section.data();
        if data.len() % 4 != 0 {
            return Err(ProgramFromElfError::other(format!("section '{}' has invalid size", section.name())));
        }

        let mut stack_size = 0;
        for xs in data.chunks_exact(4) {
            let value = u32::from_le_bytes([xs[0], xs[1], xs[2], xs[3]]);
            stack_size = core::cmp::max(stack_size, value);
        }

        align_to_next_page_u64(VM_PAGE_SIZE as u64, stack_size as u64)
            .ok_or(ProgramFromElfError::other("out of range size for the stack"))?
    } else {
        VM_PAGE_SIZE as u64
    };

    log::trace!("Configured stack size: 0x{stack_size:x}");

    // Sanity check that the memory configuration is actually valid.
    {
        let ro_data_size_physical: u64 = ro_data.iter().map(|x| x.size() as u64).sum();
        let rw_data_size_physical: u64 = rw_data.iter().map(|x| x.size() as u64).sum();

        assert!(ro_data_size_physical <= ro_data_size);
        assert!(rw_data_size_physical <= rw_data_size);

        let config = match GuestMemoryConfig::new(ro_data_size, rw_data_size, bss_size, stack_size) {
            Ok(config) => config,
            Err(error) => {
                return Err(ProgramFromElfError::other(error));
            }
        };

        assert_eq!(config.ro_data_address() as u64, ro_data_address);
        assert_eq!(config.rw_data_address() as u64, rw_data_address);
    }

    let memory_config = MemoryConfig {
        ro_data,
        rw_data,
        bss_size: bss_size as u32,
        stack_size: stack_size as u32,
    };

    Ok(memory_config)
}

#[derive(Clone, PartialEq, Eq, Debug)]
struct ExportMetadata {
    location: SectionTarget,
    prototype: FnMetadata,
}

fn extract_export_metadata(
    relocations: &BTreeMap<SectionTarget, RelocationKind>,
    section: &Section,
) -> Result<Vec<ExportMetadata>, ProgramFromElfError> {
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

        let metadata_location = SectionTarget {
            section_index: section.index(),
            offset: b.offset() as u64,
        };

        let Some(relocation) = relocations.get(&metadata_location) else {
            return Err(ProgramFromElfError::other(format!(
                "found an export without a relocation for a pointer to code at {metadata_location}"
            )));
        };

        let RelocationKind::Abs {
            target: code_location,
            size: RelocationSize::U32,
        } = relocation
        else {
            return Err(ProgramFromElfError::other(format!(
                "found an export with an unexpected relocation at {metadata_location}: {relocation:?}"
            )));
        };

        // Ignore the address as written; later we'll just use the relocations instead.
        if let Err(error) = b.read_u32() {
            return Err(ProgramFromElfError::other(format!("failed to parse export metadata: {}", error)));
        };

        let prototype = match polkavm_common::elf::FnMetadata::try_deserialize(&mut b) {
            Ok(prototype) => prototype,
            Err(error) => {
                return Err(ProgramFromElfError::other(format!("failed to parse export metadata: {}", error)));
            }
        };

        exports.push(ExportMetadata {
            location: *code_location,
            prototype,
        });
    }

    Ok(exports)
}

#[derive(Debug)]
struct Import {
    metadata_locations: Vec<SectionTarget>,
    metadata: ImportMetadata,
}

impl Import {
    fn src(&'_ self) -> impl Iterator<Item = Reg> + '_ {
        use polkavm_common::program::ExternTy;
        let arg_regs = [Reg::A0, Reg::A1, Reg::A2, Reg::A3, Reg::A4, Reg::A5];
        assert_eq!(PReg::ARG_REGS.len(), arg_regs.len()); // TODO: Use ARG_REGS here directly.

        let mut arg_regs = arg_regs.into_iter();
        self.metadata.args().flat_map(move |arg| {
            let mut chunk = [None, None];
            let count = match arg {
                ExternTy::I32 => 1,
                ExternTy::I64 => 2,
            };

            for slot in chunk.iter_mut().take(count) {
                *slot = Some(arg_regs.next().expect("internal error: import with too many arguments"));
            }
            chunk.into_iter().flatten()
        })
    }

    fn src_mask(&self) -> RegMask {
        let mut mask = RegMask::empty();
        for reg in self.src() {
            mask.insert(reg);
        }

        mask
    }

    fn dst(&self) -> impl Iterator<Item = Reg> {
        use polkavm_common::program::ExternTy;
        match self.metadata.return_ty() {
            None => [None, None],
            Some(ExternTy::I32) => [Some(Reg::A0), None],
            Some(ExternTy::I64) => [Some(Reg::A0), Some(Reg::A1)],
        }
        .into_iter()
        .flatten()
    }

    fn dst_mask(&self) -> RegMask {
        let mut mask = RegMask::empty();
        for reg in self.dst() {
            mask.insert(reg);
        }

        mask
    }
}

fn extract_import_metadata(elf: &Elf, sections: &[SectionIndex]) -> Result<Vec<Import>, ProgramFromElfError> {
    let mut imports: Vec<Import> = Vec::new();
    let mut import_by_index: BTreeMap<u32, usize> = BTreeMap::new();
    let mut import_by_name: HashMap<String, usize> = HashMap::new();
    let mut indexless: Vec<usize> = Vec::new();

    for &section_index in sections {
        let section = elf.section_by_index(section_index);
        let mut offset = 0;
        while offset < section.data().len() {
            match ImportMetadata::try_deserialize(&section.data()[offset..]) {
                Ok((bytes_consumed, metadata)) => {
                    let location = SectionTarget {
                        section_index: section.index(),
                        offset: offset as u64,
                    };

                    offset += bytes_consumed;

                    if let Some(&old_nth_import) = import_by_name.get(metadata.name()) {
                        let old_import = &mut imports[old_nth_import];
                        if metadata == old_import.metadata {
                            old_import.metadata_locations.push(location);
                            continue;
                        }

                        return Err(ProgramFromElfError::other(format!(
                            "duplicate imports with the same name yet different prototype: {}",
                            metadata.name()
                        )));
                    }

                    let nth_import = imports.len();
                    if let Some(index) = metadata.index {
                        if let Some(&old_nth_import) = import_by_index.get(&index) {
                            let old_import = &mut imports[old_nth_import];
                            if metadata == old_import.metadata {
                                old_import.metadata_locations.push(location);
                                continue;
                            }

                            let old_name = old_import.metadata.name();
                            let new_name = metadata.name();
                            return Err(ProgramFromElfError::other(format!(
                                "duplicate imports with the same index: index = {index}, names = [{old_name:?}, {new_name:?}]"
                            )));
                        }

                        import_by_index.insert(index, nth_import);
                    } else {
                        indexless.push(nth_import);
                    }

                    import_by_name.insert(metadata.name().to_owned(), nth_import);

                    let import = Import {
                        metadata_locations: vec![location],
                        metadata,
                    };

                    imports.push(import);
                }
                Err(error) => {
                    return Err(ProgramFromElfError::other(format!("failed to parse import metadata: {}", error)));
                }
            }
        }
    }

    indexless.sort_by(|&a, &b| imports[a].metadata.name().cmp(imports[b].metadata.name()));
    indexless.dedup();

    let mut next_index = 0;
    for nth_import in indexless {
        while import_by_index.contains_key(&next_index) {
            next_index += 1;
        }

        imports[nth_import].metadata.index = Some(next_index);
        import_by_index.insert(next_index, nth_import);
        next_index += 1;
    }

    for import in &imports {
        log::trace!("Import: {:?}", import.metadata);
        for location in &import.metadata_locations {
            log::trace!("  {}", location);
        }
    }

    Ok(imports)
}

fn get_relocation_target(elf: &Elf, relocation: &object::read::Relocation) -> Result<Option<SectionTarget>, ProgramFromElfError> {
    match relocation.target() {
        object::RelocationTarget::Absolute => {
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

fn parse_code_section(
    section: &Section,
    import_by_location: &HashMap<SectionTarget, &Import>,
    relocations: &BTreeMap<SectionTarget, RelocationKind>,
    instruction_overrides: &mut HashMap<SectionTarget, InstExt<SectionTarget, SectionTarget>>,
    output: &mut Vec<(Source, InstExt<SectionTarget, SectionTarget>)>,
) -> Result<(), ProgramFromElfError> {
    let section_index = section.index();
    let section_name = section.name();
    let text = &section.data();

    if text.len() % 4 != 0 {
        return Err(ProgramFromElfError::other(format!(
            "size of section '{section_name}' is not divisible by 4"
        )));
    }

    output.reserve(text.len() / 4);
    let mut relative_offset = 0;
    while relative_offset < text.len() {
        let current_location = SectionTarget {
            section_index: section.index(),
            offset: relative_offset.try_into().expect("overflow"),
        };

        let raw_inst = u32::from_le_bytes([
            text[relative_offset],
            text[relative_offset + 1],
            text[relative_offset + 2],
            text[relative_offset + 3],
        ]);

        if raw_inst == INSTRUCTION_ECALLI {
            let initial_offset = relative_offset as u64;
            if relative_offset + 12 > text.len() {
                return Err(ProgramFromElfError::other("truncated ecalli instruction"));
            }

            let target_location = current_location.add(4);
            relative_offset += 8;

            let Some(relocation) = relocations.get(&target_location) else {
                return Err(ProgramFromElfError::other(format!(
                    "found an external call without a relocation for a pointer to metadata at {current_location}"
                )));
            };

            let RelocationKind::Abs {
                target: metadata_location,
                size: RelocationSize::U32,
            } = relocation
            else {
                return Err(ProgramFromElfError::other(format!(
                    "found an external call with an unexpected relocation at {current_location}"
                )));
            };

            let Some(import) = import_by_location.get(metadata_location) else {
                return Err(ProgramFromElfError::other(format!(
                    "found an external call with a relocation to something that isn't import metadata at {current_location}"
                )));
            };

            output.push((
                Source {
                    section_index,
                    offset_range: AddressRange::from(initial_offset..relative_offset as u64),
                },
                InstExt::Basic(BasicInst::Ecalli {
                    syscall: import.metadata.index.expect("internal error: no index assigned to import"),
                }),
            ));

            const INST_RET: Inst = Inst::JumpAndLinkRegister {
                dst: Reg::Zero,
                base: Reg::RA,
                value: 0,
            };

            let next_raw_inst = u32::from_le_bytes([
                text[relative_offset],
                text[relative_offset + 1],
                text[relative_offset + 2],
                text[relative_offset + 3],
            ]);

            if decode_inst(next_raw_inst)? != Some(INST_RET) {
                return Err(ProgramFromElfError::other("external call shim doesn't end with a 'ret'"));
            }

            output.push((
                Source {
                    section_index,
                    offset_range: AddressRange::from(relative_offset as u64..relative_offset as u64 + 4),
                },
                InstExt::Control(ControlInst::JumpIndirect { base: Reg::RA, offset: 0 }),
            ));

            relative_offset += 4;
            continue;
        }

        let source = Source {
            section_index,
            offset_range: AddressRange::from(relative_offset as u64..relative_offset as u64 + 4),
        };

        relative_offset += 4;

        // Shadow the `relative_offset` to make sure it's not accidentally used again.
        #[allow(clippy::let_unit_value)]
        #[allow(unused_variables)]
        let relative_offset = ();

        let Some(original_inst) = decode_inst(raw_inst)? else {
            return Err(ProgramFromElfErrorKind::UnsupportedInstruction {
                section: section.name().into(),
                offset: current_location.offset,
                instruction: raw_inst,
            }
            .into());
        };

        let op = if let Some(inst) = instruction_overrides.remove(&current_location) {
            inst
        } else {
            match original_inst {
                Inst::LoadUpperImmediate { dst, value } => InstExt::Basic(BasicInst::RegImm {
                    kind: RegImmKind::Add,
                    dst,
                    src: Reg::Zero,
                    imm: value as i32,
                }),
                Inst::JumpAndLink { dst, target } => {
                    let target = SectionTarget {
                        section_index: section.index(),
                        offset: current_location.offset.wrapping_add_signed(target as i32 as i64),
                    };

                    if target.offset > section.size() {
                        return Err(ProgramFromElfError::other("out of range JAL instruction"));
                    }

                    let next = if dst != Reg::Zero {
                        let target_return = current_location.add(4);
                        ControlInst::Call {
                            ra: dst,
                            target,
                            target_return,
                        }
                    } else {
                        ControlInst::Jump { target }
                    };

                    InstExt::Control(next)
                }
                Inst::Branch { kind, src1, src2, target } => {
                    let target_true = SectionTarget {
                        section_index: section.index(),
                        offset: current_location.offset.wrapping_add_signed(target as i32 as i64),
                    };

                    if target_true.offset > section.size() {
                        return Err(ProgramFromElfError::other("out of range unrelocated branch"));
                    }

                    let target_false = current_location.add(4);
                    let next = ControlInst::Branch {
                        kind,
                        src1,
                        src2,
                        target_true,
                        target_false,
                    };

                    InstExt::Control(next)
                }
                Inst::JumpAndLinkRegister { dst, base, value } => {
                    if base == Reg::Zero {
                        return Err(ProgramFromElfError::other("found an unrelocated JALR instruction"));
                    }

                    let next = if dst != Reg::Zero {
                        let target_return = current_location.add(4);
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

                    InstExt::Control(next)
                }
                Inst::Unimplemented => InstExt::Control(ControlInst::Unimplemented),
                Inst::Load { kind, dst, base, offset } => {
                    if base == Reg::Zero {
                        return Err(ProgramFromElfError::other("found an unrelocated absolute load"));
                    }

                    InstExt::Basic(BasicInst::LoadIndirect { kind, dst, base, offset })
                }
                Inst::Store { kind, src, base, offset } => {
                    if base == Reg::Zero {
                        return Err(ProgramFromElfError::other("found an unrelocated absolute store"));
                    }

                    InstExt::Basic(BasicInst::StoreIndirect { kind, src, base, offset })
                }
                Inst::RegImm { kind, dst, src, imm } => InstExt::Basic(BasicInst::RegImm { kind, dst, src, imm }),
                Inst::Shift { kind, dst, src, amount } => InstExt::Basic(BasicInst::Shift { kind, dst, src, amount }),
                Inst::RegReg { kind, dst, src1, src2 } => InstExt::Basic(BasicInst::RegReg { kind, dst, src1, src2 }),
                Inst::AddUpperImmediateToPc { .. } => {
                    return Err(ProgramFromElfError::other(
                        format!("found an unrelocated auipc instruction at offset {} in section '{section_name}'; is the program compiled with relocations?", current_location.offset)
                    ));
                }
                Inst::Ecall => {
                    return Err(ProgramFromElfError::other(
                        "found a bare ecall instruction; those are not supported",
                    ));
                }
            }
        };

        output.push((source, op));
    }

    Ok(())
}

fn split_code_into_basic_blocks(
    jump_targets: &HashSet<SectionTarget>,
    instructions: Vec<(Source, InstExt<SectionTarget, SectionTarget>)>,
) -> Result<Vec<BasicBlock<SectionTarget, SectionTarget>>, ProgramFromElfError> {
    let mut blocks: Vec<BasicBlock<SectionTarget, SectionTarget>> = Vec::new();
    let mut current_block: Vec<(SourceStack, BasicInst<SectionTarget>)> = Vec::new();
    let mut block_start_opt = None;
    for (source, op) in instructions {
        assert!(source.offset_range.start < source.offset_range.end);

        let is_jump_target = jump_targets.contains(&source.begin());
        let (block_section, block_start) = if !is_jump_target {
            // Make sure nothing wants to jump into the middle of this instruction.
            assert!((source.offset_range.start..source.offset_range.end)
                .step_by(4)
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
                        std::mem::take(&mut current_block),
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
                    std::mem::take(&mut current_block),
                    EndOfBlock {
                        source: source.into(),
                        instruction,
                    },
                ));

                if let ControlInst::Branch { target_false, .. } = instruction {
                    assert_eq!(source.section_index, target_false.section_index);
                    assert_eq!(source.offset_range.end, target_false.offset);
                    block_start_opt = Some((block_section, source.offset_range.end));
                }
            }
            InstExt::Basic(instruction) => {
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
        let section_target = SectionTarget {
            section_index: block.source.section_index,
            offset: block.source.offset_range.start,
        };

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
                block_source = block.source.begin(),
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
        if reachability.always_reachable {
            queue_code.push(*block_target);
        }
    }

    for (data_target, reachability) in &reachability_graph.for_data {
        if reachability.always_reachable {
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
    if !reachability_graph.for_code.get(&block_target).unwrap().is_unreachable() {
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
    if !reachability_graph.for_data.get(&data_target).unwrap().is_unreachable() {
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
    optimize_queue: Option<&mut VecSet<BlockTarget>>,
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
                reachability_graph
                    .for_code
                    .entry(target)
                    .or_insert_with(Default::default)
                    .reachable_from
                    .insert(outer);
            }
            ExtRef::Address(target) => {
                reachability_graph
                    .for_code
                    .entry(target)
                    .or_insert_with(Default::default)
                    .address_taken_in
                    .insert(outer);
            }
            ExtRef::DataAddress(target) => {
                reachability_graph
                    .for_data
                    .entry(target)
                    .or_insert_with(Default::default)
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

    match all_blocks[current.index()].next.instruction {
        ControlInst::Jump { target } => {
            if should_inline(all_blocks, reachability_graph, current, target, inline_threshold) {
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
        ControlInst::Call { .. } | ControlInst::CallIndirect { .. } => unreachable!(),
        _ => {}
    }

    false
}

fn gather_references(block: &BasicBlock<AnyTarget, BlockTarget>) -> HashSet<ExtRef> {
    let mut references = HashSet::new();
    each_reference(block, |ext| {
        references.insert(ext);
    });
    references
}

fn update_references(
    all_blocks: &mut [BasicBlock<AnyTarget, BlockTarget>],
    reachability_graph: &mut ReachabilityGraph,
    mut optimize_queue: Option<&mut VecSet<BlockTarget>>,
    block_target: BlockTarget,
    mut old_references: HashSet<ExtRef>,
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
            all_blocks[block_target.index()].ops[nth_instruction].1 = BasicInst::RegImm {
                kind: RegImmKind::Add,
                dst: Reg::Zero,
                src: Reg::Zero,
                imm: 0,
            };
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

    let initial_registers_needed = match all_blocks[block_target.index()].next.instruction {
        // If it's going to trap then it's not going to need any of the register values.
        ControlInst::Unimplemented => RegMask::empty(),
        // If it's a jump then we'll need whatever registers the jump target needs.
        ControlInst::Jump { target } => registers_needed_for_block[target.index()],
        ControlInst::Branch {
            target_true, target_false, ..
        } => registers_needed_for_block[target_true.index()] | registers_needed_for_block[target_false.index()],
        // ...otherwise assume it'll need all of them.
        ControlInst::Call { .. } | ControlInst::CallIndirect { .. } => unreachable!(),
        _ => !RegMask::empty() & !RegMask::from(Reg::Zero),
    };

    let mut modified = false;
    let registers_needed = perform_dead_code_elimination_on_block(
        config,
        imports,
        all_blocks,
        reachability_graph,
        optimize_queue.as_deref_mut(),
        &mut modified,
        initial_registers_needed,
        block_target,
    );

    registers_needed_for_block[block_target.index()] = registers_needed;

    for previous_block in previous_blocks {
        if !reachability_graph.is_code_reachable(previous_block) {
            continue;
        }

        perform_dead_code_elimination_on_block(
            config,
            imports,
            all_blocks,
            reachability_graph,
            optimize_queue.as_deref_mut(),
            &mut modified,
            registers_needed,
            previous_block,
        );
    }

    modified
}

enum OperationKind {
    Add,
    Sub,
    And,
    Or,
    Xor,
    SetLessThanUnsigned,
    SetLessThanSigned,
    ShiftLogicalLeft,
    ShiftLogicalRight,
    ShiftArithmeticRight,
}

impl From<RegImmKind> for OperationKind {
    fn from(kind: RegImmKind) -> Self {
        match kind {
            RegImmKind::Add => Self::Add,
            RegImmKind::And => Self::And,
            RegImmKind::Or => Self::Or,
            RegImmKind::Xor => Self::Xor,
            RegImmKind::SetLessThanUnsigned => Self::SetLessThanUnsigned,
            RegImmKind::SetLessThanSigned => Self::SetLessThanSigned,
        }
    }
}

impl OperationKind {
    fn from_reg_reg(kind: RegRegKind) -> Option<Self> {
        Some(match kind {
            RegRegKind::Add => Self::Add,
            RegRegKind::Sub => Self::Sub,
            RegRegKind::And => Self::And,
            RegRegKind::Or => Self::Or,
            RegRegKind::Xor => Self::Xor,
            RegRegKind::SetLessThanUnsigned => Self::SetLessThanUnsigned,
            RegRegKind::SetLessThanSigned => Self::SetLessThanSigned,
            RegRegKind::ShiftLogicalLeft => Self::ShiftLogicalLeft,
            RegRegKind::ShiftLogicalRight => Self::ShiftLogicalRight,
            RegRegKind::ShiftArithmeticRight => Self::ShiftArithmeticRight,
            _ => return None,
        })
    }

    fn apply_const(self, lhs: i32, rhs: i32) -> i32 {
        #[allow(clippy::unnecessary_cast)]
        match self {
            Self::Add => lhs.wrapping_add(rhs),
            Self::Sub => lhs.wrapping_sub(rhs),
            Self::And => lhs & rhs,
            Self::Or => lhs | rhs,
            Self::Xor => lhs ^ rhs,
            Self::SetLessThanUnsigned => ((lhs as u32) < (rhs as u32)) as i32,
            Self::SetLessThanSigned => ((lhs as i32) < (rhs as i32)) as i32,
            Self::ShiftLogicalLeft => ((lhs as u32).wrapping_shl(rhs as u32)) as i32,
            Self::ShiftLogicalRight => ((lhs as u32).wrapping_shr(rhs as u32)) as i32,
            Self::ShiftArithmeticRight => (lhs as i32).wrapping_shr(rhs as u32),
        }
    }

    fn apply(self, lhs: RegValue, rhs: RegValue) -> Option<RegValue> {
        match (lhs, rhs) {
            (RegValue::Constant(lhs), RegValue::Constant(rhs)) => Some(RegValue::Constant(self.apply_const(lhs, rhs))),
            (RegValue::DataAddress(lhs), RegValue::Constant(rhs)) if matches!(self, Self::Add | Self::Sub) => {
                Some(RegValue::DataAddress(lhs.map_offset_i32(|lhs| self.apply_const(lhs, rhs))))
            }
            (lhs, RegValue::Constant(0))
                if matches!(
                    self,
                    OperationKind::Add
                        | OperationKind::Sub
                        | OperationKind::Or
                        | OperationKind::ShiftLogicalLeft
                        | OperationKind::ShiftLogicalRight
                        | OperationKind::ShiftArithmeticRight
                ) =>
            {
                Some(lhs)
            }
            _ => None,
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
enum RegValue {
    InputReg(Reg),
    CodeAddress(BlockTarget),
    DataAddress(SectionTarget),
    Constant(i32),
    Unknown(u64),
}

impl RegValue {
    fn to_instruction(self, dst: Reg) -> Option<BasicInst<AnyTarget>> {
        assert_ne!(dst, Reg::Zero);
        match self {
            RegValue::CodeAddress(target) => Some(BasicInst::LoadAddress {
                dst,
                target: AnyTarget::Code(target),
            }),
            RegValue::DataAddress(target) => Some(BasicInst::LoadAddress {
                dst,
                target: AnyTarget::Data(target),
            }),
            RegValue::Constant(imm) => Some(BasicInst::RegImm {
                kind: RegImmKind::Add,
                dst,
                src: Reg::Zero,
                imm,
            }),
            _ => None,
        }
    }
}

#[derive(Clone)]
struct BlockRegs {
    regs: [RegValue; 16],
}

impl BlockRegs {
    fn new() -> Self {
        let mut regs = ALL_REGS.map(RegValue::InputReg);
        regs[0] = RegValue::Constant(0);

        BlockRegs { regs }
    }

    fn get_reg(&self, reg: Reg) -> RegValue {
        self.regs[reg as usize]
    }

    fn set_reg(&mut self, reg: Reg, value: RegValue) {
        self.regs[reg as usize] = value;
    }

    fn simplify_instruction(&self, instruction: BasicInst<AnyTarget>) -> Option<BasicInst<AnyTarget>> {
        match instruction {
            BasicInst::RegReg { kind, dst, src1, src2 } => {
                if let RegValue::Constant(mut imm) = self.get_reg(src2) {
                    let kind = match kind {
                        RegRegKind::Add => Some(RegImmKind::Add),
                        RegRegKind::Sub => {
                            imm = -imm;
                            Some(RegImmKind::Add)
                        }
                        RegRegKind::And => Some(RegImmKind::And),
                        RegRegKind::Or => Some(RegImmKind::Or),
                        RegRegKind::Xor => Some(RegImmKind::Xor),
                        RegRegKind::SetLessThanUnsigned => Some(RegImmKind::SetLessThanUnsigned),
                        RegRegKind::SetLessThanSigned => Some(RegImmKind::SetLessThanSigned),
                        _ => None,
                    };

                    if let Some(kind) = kind {
                        return Some(BasicInst::RegImm { kind, dst, src: src1, imm });
                    }
                }

                if let RegValue::Constant(imm) = self.get_reg(src1) {
                    let kind = match kind {
                        RegRegKind::Add => Some(RegImmKind::Add),
                        RegRegKind::And => Some(RegImmKind::And),
                        RegRegKind::Or => Some(RegImmKind::Or),
                        RegRegKind::Xor => Some(RegImmKind::Xor),
                        _ => None,
                    };

                    if let Some(kind) = kind {
                        return Some(BasicInst::RegImm { kind, dst, src: src2, imm });
                    }
                }

                if let Some(kind) = OperationKind::from_reg_reg(kind) {
                    if let Some(value) = kind.apply(self.get_reg(src1), self.get_reg(src2)) {
                        if let Some(new_instruction) = value.to_instruction(dst) {
                            if new_instruction != instruction {
                                return Some(new_instruction);
                            }
                        }
                    }
                }
            }
            BasicInst::RegImm { kind, dst, src, imm } => {
                if let Some(value) = OperationKind::from(kind).apply(self.get_reg(src), RegValue::Constant(imm)) {
                    if let Some(new_instruction) = value.to_instruction(dst) {
                        if new_instruction != instruction {
                            return Some(new_instruction);
                        }
                    }
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
            }
            _ => {}
        }

        None
    }

    fn set_reg_from_instruction(&mut self, imports: &[Import], unknown_counter: &mut u64, instruction: BasicInst<AnyTarget>) {
        match instruction {
            BasicInst::RegImm {
                kind: RegImmKind::Add,
                dst,
                src: Reg::Zero,
                imm,
            } => {
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
            BasicInst::RegImm {
                kind: RegImmKind::Add,
                dst,
                src,
                imm: 0,
            } => {
                self.set_reg(dst, self.get_reg(src));
            }
            _ => {
                for reg in instruction.dst_mask(imports) {
                    self.set_reg(reg, RegValue::Unknown(*unknown_counter));
                    *unknown_counter += 1;
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn perform_constant_propagation(
    imports: &[Import],
    elf: &Elf,
    all_blocks: &mut [BasicBlock<AnyTarget, BlockTarget>],
    regs_for_block: &mut [BlockRegs],
    unknown_counter: &mut u64,
    reachability_graph: &mut ReachabilityGraph,
    mut optimize_queue: Option<&mut VecSet<BlockTarget>>,
    mut current: BlockTarget,
) -> bool {
    let mut regs = regs_for_block[current.index()].clone();
    let mut modified = false;
    let mut seen = HashSet::new();
    loop {
        if !seen.insert(current) {
            // Prevent an infinite loop.
            break;
        }

        if !reachability_graph.is_code_reachable(current) {
            break;
        }

        let mut references = HashSet::new();
        let mut modified_this_block = false;
        for nth_instruction in 0..all_blocks[current.index()].ops.len() {
            let mut instruction = all_blocks[current.index()].ops[nth_instruction].1;
            assert_eq!(regs.get_reg(Reg::Zero), RegValue::Constant(0));

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
                        LoadKind::U32 => section
                            .data()
                            .get(target.offset as usize..target.offset as usize + 4)
                            .map(|xs| u32::from_le_bytes([xs[0], xs[1], xs[2], xs[3]]) as i32),
                        LoadKind::U16 => section
                            .data()
                            .get(target.offset as usize..target.offset as usize + 2)
                            .map(|xs| u16::from_le_bytes([xs[0], xs[1]]) as u32 as i32),
                        LoadKind::I16 => section
                            .data()
                            .get(target.offset as usize..target.offset as usize + 2)
                            .map(|xs| i16::from_le_bytes([xs[0], xs[1]]) as i32),
                        LoadKind::I8 => section.data().get(target.offset as usize).map(|&x| x as i8 as i32),
                        LoadKind::U8 => section.data().get(target.offset as usize).map(|&x| x as u32 as i32),
                    };

                    if let Some(imm) = value {
                        if !modified_this_block {
                            references = gather_references(&all_blocks[current.index()]);
                            modified_this_block = true;
                            modified = true;
                        }

                        instruction = BasicInst::RegImm {
                            kind: RegImmKind::Add,
                            dst,
                            src: Reg::Zero,
                            imm,
                        };
                        all_blocks[current.index()].ops[nth_instruction].1 = instruction;
                    }
                }
            }

            regs.set_reg_from_instruction(imports, unknown_counter, instruction);
        }

        match all_blocks[current.index()].next.instruction {
            ControlInst::JumpIndirect { base, offset } if offset == 0 => {
                if let RegValue::CodeAddress(target) = regs.get_reg(base) {
                    if !modified_this_block {
                        references = gather_references(&all_blocks[current.index()]);
                        modified_this_block = true;
                        modified = true;
                    }

                    all_blocks[current.index()].next.instruction = ControlInst::Jump { target };
                }
            }
            ControlInst::Branch {
                kind,
                src1,
                src2,
                target_true,
                target_false,
            } if target_true != target_false => {
                let values = match (regs.get_reg(src1), regs.get_reg(src2)) {
                    (src1_value, src2_value) if src1_value == src2_value => Some((0, 0)),
                    (RegValue::Constant(lhs), RegValue::Constant(rhs)) => Some((lhs, rhs)),
                    _ => None,
                };

                if let Some((lhs, rhs)) = values {
                    let is_true = match kind {
                        BranchKind::Eq => lhs == rhs,
                        BranchKind::NotEq => lhs != rhs,
                        #[allow(clippy::unnecessary_cast)]
                        BranchKind::LessSigned => (lhs as i32) < (rhs as i32),
                        #[allow(clippy::unnecessary_cast)]
                        BranchKind::GreaterOrEqualSigned => (lhs as i32) >= (rhs as i32),
                        BranchKind::LessUnsigned => (lhs as u32) < (rhs as u32),
                        BranchKind::GreaterOrEqualUnsigned => (lhs as u32) >= (rhs as u32),
                    };

                    if !modified_this_block {
                        references = gather_references(&all_blocks[current.index()]);
                        modified_this_block = true;
                        modified = true;
                    }

                    all_blocks[current.index()].next.instruction = ControlInst::Jump {
                        target: if is_true { target_true } else { target_false },
                    };
                }
            }
            _ => {}
        }

        if modified_this_block {
            update_references(all_blocks, reachability_graph, optimize_queue.as_deref_mut(), current, references);
            if let Some(ref mut optimize_queue) = optimize_queue {
                add_to_optimize_queue(all_blocks, reachability_graph, optimize_queue, current);
            }
        }

        match all_blocks[current.index()].next.instruction {
            ControlInst::Jump { target }
                if current != target && reachability_graph.for_code.get(&target).unwrap().is_only_reachable_from(current) =>
            {
                current = target;
                regs_for_block[current.index()] = regs.clone();
                continue;
            }
            ControlInst::Branch {
                target_true, target_false, ..
            } => {
                let true_only_reachable_from_here = current != target_true
                    && reachability_graph
                        .for_code
                        .get(&target_true)
                        .unwrap()
                        .is_only_reachable_from(current);

                let false_only_reachable_from_here = current != target_false
                    && reachability_graph
                        .for_code
                        .get(&target_false)
                        .unwrap()
                        .is_only_reachable_from(current);

                if true_only_reachable_from_here {
                    regs_for_block[target_true.index()] = regs.clone();
                }

                if false_only_reachable_from_here {
                    regs_for_block[target_false.index()] = regs.clone();
                }

                if true_only_reachable_from_here {
                    current = target_true;
                    continue;
                }

                if false_only_reachable_from_here {
                    current = target_false;
                    continue;
                }
            }
            ControlInst::Call { .. } | ControlInst::CallIndirect { .. } => unreachable!(),
            _ => {}
        }

        break;
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
            ControlInst::JumpIndirect { base, offset } => ControlInst::CallIndirect {
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

fn optimize_program(
    config: &Config,
    elf: &Elf,
    imports: &[Import],
    all_blocks: &mut [BasicBlock<AnyTarget, BlockTarget>],
    reachability_graph: &mut ReachabilityGraph,
) {
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
            } => {
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
    let mut regs_for_block = Vec::with_capacity(all_blocks.len());
    for _ in 0..all_blocks.len() {
        regs_for_block.push(BlockRegs::new())
    }

    let mut registers_needed_for_block = Vec::with_capacity(all_blocks.len());
    for _ in 0..all_blocks.len() {
        registers_needed_for_block.push(!RegMask::empty() & !RegMask::from(Reg::Zero))
    }

    let opt_minimum_iteration_count = reachability_graph.reachable_block_count();
    let mut opt_iteration_count = 0;
    while let Some(current) = optimize_queue.pop_non_unique() {
        if !reachability_graph.is_code_reachable(current) {
            continue;
        }

        opt_iteration_count += 1;
        perform_nop_elimination(all_blocks, current);
        perform_inlining(
            all_blocks,
            reachability_graph,
            Some(&mut optimize_queue),
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
            &mut regs_for_block,
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

    let mut opt_brute_force_iterations = 0;
    let mut modified = true;
    while modified {
        opt_brute_force_iterations += 1;
        modified = false;
        for current in (0..all_blocks.len()).map(BlockTarget::from_raw) {
            if !reachability_graph.is_code_reachable(current) {
                continue;
            }

            modified |= perform_inlining(all_blocks, reachability_graph, None, config.inline_threshold, current);
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
                &mut regs_for_block,
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

fn add_missing_fallthrough_blocks(
    all_blocks: &mut Vec<BasicBlock<AnyTarget, BlockTarget>>,
    reachability_graph: &mut ReachabilityGraph,
) -> Vec<BlockTarget> {
    let mut used_blocks = Vec::new();
    for block in &*all_blocks {
        if !reachability_graph.is_code_reachable(block.target) {
            continue;
        }

        used_blocks.push(block.target);
    }

    let mut new_used_blocks = Vec::new();
    let can_fallthrough_to_next_block = calculate_whether_can_fallthrough(all_blocks, &used_blocks);
    for current in used_blocks {
        new_used_blocks.push(current);
        if can_fallthrough_to_next_block.contains(&current) {
            continue;
        }

        let references = gather_references(&all_blocks[current.index()]);
        let new_fallthrough_target = BlockTarget::from_raw(all_blocks.len());
        let old_fallthrough_target = match &mut all_blocks[current.index()].next.instruction {
            ControlInst::Jump { .. } | ControlInst::JumpIndirect { .. } | ControlInst::Unimplemented => continue,
            ControlInst::Branch { target_false: target, .. }
            | ControlInst::Call { target_return: target, .. }
            | ControlInst::CallIndirect { target_return: target, .. } => core::mem::replace(target, new_fallthrough_target),
        };

        all_blocks.push(BasicBlock {
            target: new_fallthrough_target,
            source: all_blocks[current.index()].source,
            ops: Default::default(),
            next: EndOfBlock {
                source: all_blocks[current.index()].next.source.clone(),
                instruction: ControlInst::Jump {
                    target: old_fallthrough_target,
                },
            },
        });

        reachability_graph
            .for_code
            .get_mut(&old_fallthrough_target)
            .unwrap()
            .reachable_from
            .insert(new_fallthrough_target);

        reachability_graph.for_code.insert(new_fallthrough_target, Reachability::default());
        update_references(all_blocks, reachability_graph, None, current, references);

        new_used_blocks.push(new_fallthrough_target);
    }

    new_used_blocks
}

fn harvest_all_jump_targets(
    elf: &Elf,
    data_sections_set: &HashSet<SectionIndex>,
    code_sections_set: &HashSet<SectionIndex>,
    instructions: &[(Source, InstExt<SectionTarget, SectionTarget>)],
    relocations: &BTreeMap<SectionTarget, RelocationKind>,
) -> Result<HashSet<SectionTarget>, ProgramFromElfError> {
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
            assert!(!reachability.is_unreachable());
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
        self.for_data.entry(section_index).or_insert_with(Default::default).always_reachable = true;
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Default)]
struct Reachability {
    reachable_from: BTreeSet<BlockTarget>,
    address_taken_in: BTreeSet<BlockTarget>,
    referenced_by_data: BTreeSet<SectionIndex>,
    always_reachable: bool,
}

impl Reachability {
    fn is_only_reachable_from(&self, block_target: BlockTarget) -> bool {
        !self.always_reachable
            && self.referenced_by_data.is_empty()
            && self.address_taken_in.is_empty()
            && self.reachable_from.len() == 1
            && self.reachable_from.contains(&block_target)
    }

    fn is_unreachable(&self) -> bool {
        self.reachable_from.is_empty() && self.address_taken_in.is_empty() && self.referenced_by_data.is_empty() && !self.always_reachable
    }
}

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
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
    export_metadata: &[ExportMetadata],
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

    for export in export_metadata {
        let Some(&block_target) = section_to_block.get(&export.location) else {
            return Err(ProgramFromElfError::other("export points to a non-block"));
        };

        graph.for_code.entry(block_target).or_insert_with(Default::default).always_reachable = true;
        block_queue.push(block_target);
    }

    while !block_queue.is_empty() || !data_queue.is_empty() {
        while let Some(current_block) = block_queue.pop_unique() {
            each_reference(&all_blocks[current_block.index()], |ext| match ext {
                ExtRef::Jump(target) => {
                    graph
                        .for_code
                        .entry(target)
                        .or_insert_with(Default::default)
                        .reachable_from
                        .insert(current_block);
                    block_queue.push(target);
                }
                ExtRef::Address(target) => {
                    graph
                        .for_code
                        .entry(target)
                        .or_insert_with(Default::default)
                        .address_taken_in
                        .insert(current_block);
                    block_queue.push(target)
                }
                ExtRef::DataAddress(target) => {
                    graph
                        .for_data
                        .entry(target)
                        .or_insert_with(Default::default)
                        .address_taken_in
                        .insert(current_block);
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
                            .or_insert_with(Default::default)
                            .push(block_target);

                        graph
                            .for_code
                            .entry(block_target)
                            .or_insert_with(Default::default)
                            .referenced_by_data
                            .insert(section_index);

                        block_queue.push(block_target);
                    } else {
                        graph
                            .data_references_in_data_section
                            .entry(section_index)
                            .or_insert_with(Default::default)
                            .push(relocation_target.section_index);

                        graph
                            .for_data
                            .entry(relocation_target.section_index)
                            .or_insert_with(Default::default)
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
        for (nth, name) in Reg::NAMES.iter().enumerate() {
            if self.0 & (1 << nth) != 0 {
                if is_first {
                    is_first = false;
                } else {
                    fmt.write_str("|")?;
                }
                fmt.write_str(name)?;
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
            remaining: &ALL_REGS,
        }
    }
}

impl RegMask {
    fn empty() -> Self {
        RegMask(0)
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

const ALL_REGS: [Reg; 16] = [
    Reg::Zero,
    Reg::RA,
    Reg::SP,
    Reg::GP,
    Reg::TP,
    Reg::T0,
    Reg::T1,
    Reg::T2,
    Reg::S0,
    Reg::S1,
    Reg::A0,
    Reg::A1,
    Reg::A2,
    Reg::A3,
    Reg::A4,
    Reg::A5,
];

#[test]
fn test_all_regs_indexes() {
    for (index, reg) in ALL_REGS.iter().enumerate() {
        assert_eq!(index, *reg as usize);
    }
}

fn cast_reg(reg: Reg) -> PReg {
    use Reg::*;
    match reg {
        Zero => PReg::Zero,
        RA => PReg::RA,
        SP => PReg::SP,
        T0 => PReg::T0,
        T1 => PReg::T1,
        T2 => PReg::T2,
        S0 => PReg::S0,
        S1 => PReg::S1,
        A0 => PReg::A0,
        A1 => PReg::A1,
        A2 => PReg::A2,
        A3 => PReg::A3,
        A4 => PReg::A4,
        A5 => PReg::A5,
        _ => unreachable!(),
    }
}

fn assign_jump_targets(all_blocks: &[BasicBlock<AnyTarget, BlockTarget>], used_blocks: &[BlockTarget]) -> Vec<Option<u32>> {
    let mut jump_target_for_block: Vec<Option<u32>> = Vec::new();
    jump_target_for_block.resize(all_blocks.len(), None);

    for (nth, block_target) in used_blocks.iter().enumerate() {
        jump_target_for_block[block_target.index()] = Some(nth as u32 + 1);
    }

    jump_target_for_block
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

fn emit_code(
    base_address_for_section: &HashMap<SectionIndex, u64>,
    section_got: SectionIndex,
    target_to_got_offset: &HashMap<AnyTarget, u64>,
    all_blocks: &[BasicBlock<AnyTarget, BlockTarget>],
    used_blocks: &[BlockTarget],
    used_imports: &HashSet<u32>,
    jump_target_for_block: &[Option<u32>],
) -> Result<Vec<(SourceStack, RawInstruction)>, ProgramFromElfError> {
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

    let get_jump_target = |target: BlockTarget| -> Result<u32, ProgramFromElfError> {
        let Some(jump_target) = jump_target_for_block[target.index()] else {
            return Err(ProgramFromElfError::other("out of range jump target"));
        };

        Ok(jump_target)
    };

    let mut code: Vec<(SourceStack, RawInstruction)> = Vec::new();
    for block_target in used_blocks {
        let block = &all_blocks[block_target.index()];
        let jump_target = jump_target_for_block[block.target.index()].unwrap();

        code.push((
            Source {
                section_index: block.source.section_index,
                offset_range: (block.source.offset_range.start..block.source.offset_range.start + 4).into(),
            }
            .into(),
            RawInstruction::new_with_imm(Opcode::jump_target, jump_target),
        ));

        fn conv_load_kind(kind: LoadKind) -> Opcode {
            match kind {
                LoadKind::I8 => Opcode::load_i8,
                LoadKind::I16 => Opcode::load_i16,
                LoadKind::U32 => Opcode::load_u32,
                LoadKind::U8 => Opcode::load_u8,
                LoadKind::U16 => Opcode::load_u16,
            }
        }

        fn conv_store_kind(kind: StoreKind) -> Opcode {
            match kind {
                StoreKind::U32 => Opcode::store_u32,
                StoreKind::U8 => Opcode::store_u8,
                StoreKind::U16 => Opcode::store_u16,
            }
        }

        for (source, op) in &block.ops {
            let op = match *op {
                BasicInst::LoadAbsolute { kind, dst, target } => {
                    RawInstruction::new_with_regs2_imm(conv_load_kind(kind), cast_reg(dst), cast_reg(Reg::Zero), get_data_address(target)?)
                }
                BasicInst::StoreAbsolute { kind, src, target } => {
                    RawInstruction::new_with_regs2_imm(conv_store_kind(kind), cast_reg(src), cast_reg(Reg::Zero), get_data_address(target)?)
                }
                BasicInst::LoadIndirect { kind, dst, base, offset } => {
                    RawInstruction::new_with_regs2_imm(conv_load_kind(kind), cast_reg(dst), cast_reg(base), offset as u32)
                }
                BasicInst::StoreIndirect { kind, src, base, offset } => {
                    RawInstruction::new_with_regs2_imm(conv_store_kind(kind), cast_reg(src), cast_reg(base), offset as u32)
                }
                BasicInst::LoadAddress { dst, target } => {
                    let value = match target {
                        AnyTarget::Code(target) => {
                            let value = get_jump_target(target)?;
                            let Some(value) = value.checked_mul(JUMP_TARGET_MULTIPLIER) else {
                                return Err(ProgramFromElfError::other("overflow when emitting an address load"));
                            };
                            value
                        }
                        AnyTarget::Data(target) => get_data_address(target)?,
                    };

                    RawInstruction::new_with_regs2_imm(Opcode::add_imm, cast_reg(dst), cast_reg(Reg::Zero), value)
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
                    RawInstruction::new_with_regs2_imm(conv_load_kind(LoadKind::U32), cast_reg(dst), cast_reg(Reg::Zero), value)
                }
                BasicInst::RegImm { kind, dst, src, imm } => {
                    let kind = match kind {
                        RegImmKind::Add => Opcode::add_imm,
                        RegImmKind::SetLessThanSigned => Opcode::set_less_than_signed_imm,
                        RegImmKind::SetLessThanUnsigned => Opcode::set_less_than_unsigned_imm,
                        RegImmKind::Xor => Opcode::xor_imm,
                        RegImmKind::Or => Opcode::or_imm,
                        RegImmKind::And => Opcode::and_imm,
                    };
                    RawInstruction::new_with_regs2_imm(kind, cast_reg(dst), cast_reg(src), imm as u32)
                }
                BasicInst::Shift { kind, dst, src, amount } => {
                    let kind = match kind {
                        ShiftKind::LogicalLeft => Opcode::shift_logical_left_imm,
                        ShiftKind::LogicalRight => Opcode::shift_logical_right_imm,
                        ShiftKind::ArithmeticRight => Opcode::shift_arithmetic_right_imm,
                    };
                    RawInstruction::new_with_regs2_imm(kind, cast_reg(dst), cast_reg(src), amount as u32)
                }
                BasicInst::RegReg { kind, dst, src1, src2 } => {
                    let kind = match kind {
                        RegRegKind::Add => Opcode::add,
                        RegRegKind::Sub => Opcode::sub,
                        RegRegKind::ShiftLogicalLeft => Opcode::shift_logical_left,
                        RegRegKind::SetLessThanSigned => Opcode::set_less_than_signed,
                        RegRegKind::SetLessThanUnsigned => Opcode::set_less_than_unsigned,
                        RegRegKind::Xor => Opcode::xor,
                        RegRegKind::ShiftLogicalRight => Opcode::shift_logical_right,
                        RegRegKind::ShiftArithmeticRight => Opcode::shift_arithmetic_right,
                        RegRegKind::Or => Opcode::or,
                        RegRegKind::And => Opcode::and,
                        RegRegKind::Mul => Opcode::mul,
                        RegRegKind::MulUpperSignedSigned => Opcode::mul_upper_signed_signed,
                        RegRegKind::MulUpperUnsignedUnsigned => Opcode::mul_upper_unsigned_unsigned,
                        RegRegKind::MulUpperSignedUnsigned => Opcode::mul_upper_signed_unsigned,
                        RegRegKind::Div => Opcode::div_signed,
                        RegRegKind::DivUnsigned => Opcode::div_unsigned,
                        RegRegKind::Rem => Opcode::rem_signed,
                        RegRegKind::RemUnsigned => Opcode::rem_unsigned,
                    };
                    RawInstruction::new_with_regs3(kind, cast_reg(dst), cast_reg(src1), cast_reg(src2))
                }
                BasicInst::Ecalli { syscall } => {
                    assert!(used_imports.contains(&syscall));
                    RawInstruction::new_with_imm(Opcode::ecalli, syscall)
                }
            };

            code.push((source.clone(), op));
        }

        fn unconditional_jump(target: u32) -> RawInstruction {
            RawInstruction::new_with_regs2_imm(Opcode::jump_and_link_register, cast_reg(Reg::Zero), cast_reg(Reg::Zero), target)
        }

        match block.next.instruction {
            ControlInst::Jump { target } => {
                let target = get_jump_target(target)?;
                if !can_fallthrough_to_next_block.contains(block_target) {
                    code.push((block.next.source.clone(), unconditional_jump(target)));
                }
            }
            ControlInst::Call { ra, target, target_return } => {
                assert!(can_fallthrough_to_next_block.contains(block_target));

                let target = get_jump_target(target)?;
                get_jump_target(target_return)?;

                code.push((
                    block.next.source.clone(),
                    RawInstruction::new_with_regs2_imm(Opcode::jump_and_link_register, cast_reg(ra), cast_reg(Reg::Zero), target),
                ));
            }
            ControlInst::JumpIndirect { base, offset } => {
                if offset % 4 != 0 {
                    return Err(ProgramFromElfError::other(
                        "found an indirect jump with an offset that isn't aligned",
                    ));
                }

                code.push((
                    block.next.source.clone(),
                    RawInstruction::new_with_regs2_imm(
                        Opcode::jump_and_link_register,
                        cast_reg(Reg::Zero),
                        cast_reg(base),
                        offset as u32 / 4,
                    ),
                ));
            }
            ControlInst::CallIndirect {
                ra,
                base,
                offset,
                target_return,
            } => {
                assert!(can_fallthrough_to_next_block.contains(block_target));

                if offset % 4 != 0 {
                    return Err(ProgramFromElfError::other(
                        "found an indirect call with a target that isn't aligned",
                    ));
                }

                get_jump_target(target_return)?;
                code.push((
                    block.next.source.clone(),
                    RawInstruction::new_with_regs2_imm(Opcode::jump_and_link_register, cast_reg(ra), cast_reg(base), offset as u32 / 4),
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

                let kind = match kind {
                    BranchKind::Eq => Opcode::branch_eq,
                    BranchKind::NotEq => Opcode::branch_not_eq,
                    BranchKind::LessSigned => Opcode::branch_less_signed,
                    BranchKind::GreaterOrEqualSigned => Opcode::branch_greater_or_equal_signed,
                    BranchKind::LessUnsigned => Opcode::branch_less_unsigned,
                    BranchKind::GreaterOrEqualUnsigned => Opcode::branch_greater_or_equal_unsigned,
                };

                code.push((
                    block.next.source.clone(),
                    RawInstruction::new_with_regs2_imm(kind, cast_reg(src1), cast_reg(src2), target_true),
                ));
            }
            ControlInst::Unimplemented => {
                code.push((block.next.source.clone(), RawInstruction::new_argless(Opcode::trap)));
            }
        }
    }

    Ok(code)
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
enum Bitness {
    B32,
}

impl From<Bitness> for u64 {
    fn from(value: Bitness) -> Self {
        match value {
            Bitness::B32 => 4,
        }
    }
}

impl From<Bitness> for RelocationSize {
    fn from(value: Bitness) -> Self {
        match value {
            Bitness::B32 => RelocationSize::U32,
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub(crate) enum RelocationSize {
    U8,
    U16,
    U32,
}

#[derive(Copy, Clone, Debug)]
pub(crate) enum SizeRelocationSize {
    SixBits,
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

fn harvest_data_relocations(
    elf: &Elf,
    code_sections_set: &HashSet<SectionIndex>,
    section: &Section,
    relocations: &mut BTreeMap<SectionTarget, RelocationKind>,
) -> Result<(), ProgramFromElfError> {
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

        let (relocation_name, kind) = match relocation.kind() {
            object::RelocationKind::Absolute if relocation.encoding() == object::RelocationEncoding::Generic && relocation.size() == 32 => {
                (
                    "R_RISCV_32",
                    Kind::Set(RelocationKind::Abs {
                        target,
                        size: RelocationSize::U32,
                    }),
                )
            }
            object::RelocationKind::Elf(reloc_kind) => match reloc_kind {
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
                object::elf::R_RISCV_SUB32 => ("R_RISCV_SUB32", Kind::Mut(MutOp::Sub, RelocationSize::U32, target)),
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
            "unsupported relocations for '{section_name}'[{relative_address:x}] (0x{absolute_address:08x}): {list:?}",
            absolute_address = section.original_address() + relative_address
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

fn read_u8(data: &[u8], relative_address: u64) -> Result<u8, ProgramFromElfError> {
    data.get(relative_address as usize)
        .ok_or(ProgramFromElfError::other("out of range relocation"))
        .copied()
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

fn harvest_code_relocations(
    elf: &Elf,
    section: &Section,
    instruction_overrides: &mut HashMap<SectionTarget, InstExt<SectionTarget, SectionTarget>>,
    data_relocations: &mut BTreeMap<SectionTarget, RelocationKind>,
) -> Result<(), ProgramFromElfError> {
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
    let mut skip_lo12: HashSet<SectionTarget> = Default::default();

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

        match relocation.kind() {
            object::RelocationKind::Absolute if relocation.encoding() == object::RelocationEncoding::Generic && relocation.size() == 32 => {
                data_relocations.insert(
                    current_location,
                    RelocationKind::Abs {
                        target,
                        size: RelocationSize::U32,
                    },
                );
            }
            object::RelocationKind::Elf(reloc_kind) => {
                // https://github.com/riscv-non-isa/riscv-elf-psabi-doc/releases
                match reloc_kind {
                    object::elf::R_RISCV_CALL_PLT => {
                        // This relocation is for a pair of instructions, namely AUIPC + JALR, where we're allowed to delete the AUIPC if it's unnecessary.
                        let Some(xs) = section_data.get(current_location.offset as usize..current_location.offset as usize + 8) else {
                            return Err(ProgramFromElfError::other("invalid R_RISCV_CALL_PLT relocation"));
                        };

                        let hi_inst_raw = u32::from_le_bytes([xs[0], xs[1], xs[2], xs[3]]);
                        let Some(hi_inst) = decode_inst(hi_inst_raw)? else {
                            return Err(ProgramFromElfError::other(format!(
                                "R_RISCV_CALL_PLT for an unsupported instruction (1st): 0x{hi_inst_raw:08}"
                            )));
                        };

                        let lo_inst_raw = u32::from_le_bytes([xs[4], xs[5], xs[6], xs[7]]);
                        let Some(lo_inst) = decode_inst(lo_inst_raw)? else {
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
                            InstExt::Control(ControlInst::jump_or_call(lo_dst, target, target_return)),
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
                        let Some(inst) = decode_inst(inst_raw)? else {
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
                        instruction_overrides.insert(
                            current_location,
                            InstExt::Control(ControlInst::jump_or_call(dst, target, target_return)),
                        );

                        log::trace!(
                            "  R_RISCV_JAL: {}[0x{relative_address:x}] (0x{absolute_address:x} -> {}",
                            section.name(),
                            target
                        );
                    }
                    object::elf::R_RISCV_BRANCH => {
                        let inst_raw = read_u32(section_data, relative_address)?;
                        let Some(inst) = decode_inst(inst_raw)? else {
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
                                src1,
                                src2,
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
                        // This relocation is for a LUI + ADDI.
                        let Some(xs) = section_data.get(relative_address as usize..relative_address as usize + 8) else {
                            return Err(ProgramFromElfError::other("invalid R_RISCV_HI20 relocation"));
                        };

                        let hi_inst_raw = u32::from_le_bytes([xs[0], xs[1], xs[2], xs[3]]);
                        let Some(hi_inst) = decode_inst(hi_inst_raw)? else {
                            return Err(ProgramFromElfError::other(format!(
                                "R_RISCV_HI20 for an unsupported instruction (1st): 0x{hi_inst_raw:08}"
                            )));
                        };

                        let lo_inst_raw = u32::from_le_bytes([xs[4], xs[5], xs[6], xs[7]]);
                        let Some(lo_inst) = decode_inst(lo_inst_raw)? else {
                            return Err(ProgramFromElfError::other(format!(
                                "R_RISCV_HI20 for an unsupported instruction (2nd): 0x{lo_inst_raw:08}"
                            )));
                        };

                        let Inst::LoadUpperImmediate { dst: hi_reg, value: _ } = hi_inst else {
                            return Err(ProgramFromElfError::other(format!(
                                "R_RISCV_HI20 for an unsupported instruction (1st): 0x{hi_inst_raw:08} ({hi_inst:?})"
                            )));
                        };

                        let Inst::RegImm {
                            kind: RegImmKind::Add,
                            dst: lo_dst,
                            src: lo_src,
                            imm: _,
                        } = lo_inst
                        else {
                            return Err(ProgramFromElfError::other(format!(
                                "R_RISCV_HI20 for an unsupported instruction (2nd): 0x{lo_inst_raw:08} ({lo_inst:?})"
                            )));
                        };

                        if hi_reg != lo_dst || lo_dst != lo_src {
                            return Err(ProgramFromElfError::other(
                                "R_RISCV_HI20 for a pair of instructions with different destination registers",
                            ));
                        }

                        instruction_overrides.insert(current_location, InstExt::nop());
                        instruction_overrides.insert(
                            current_location.add(4),
                            InstExt::Basic(BasicInst::LoadAddress { dst: hi_reg, target }),
                        );

                        skip_lo12.insert(current_location.add(4));

                        log::trace!(
                            "  R_RISCV_HI20: {}[0x{relative_address:x}] (0x{absolute_address:x}): -> {}",
                            section.name(),
                            target
                        );

                        continue;
                    }
                    object::elf::R_RISCV_LO12_I => {
                        if skip_lo12.contains(&current_location) {
                            continue;
                        }

                        return Err(ProgramFromElfError::other(format!(
                            "found a R_RISCV_LO12_I relocation in '{}' without a R_RISCV_HI20 preceding it",
                            section.name()
                        )));
                    }
                    object::elf::R_RISCV_LO12_S => {
                        if skip_lo12.contains(&current_location) {
                            continue;
                        }

                        return Err(ProgramFromElfError::other(format!(
                            "found a R_RISCV_LO12_S relocation in '{}' without a R_RISCV_HI20 preceding it",
                            section.name()
                        )));
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
        let lo_inst = decode_inst(lo_inst_raw)?;
        let hi_inst_raw = &section_data[relative_hi as usize..][..4];
        let hi_inst_raw = u32::from_le_bytes([hi_inst_raw[0], hi_inst_raw[1], hi_inst_raw[2], hi_inst_raw[3]]);
        let hi_inst = decode_inst(hi_inst_raw)?;

        let Some((hi_kind, target)) = pcrel_relocations.reloc_pcrel_hi20.get(&relative_hi).copied() else {
            return Err(ProgramFromElfError::other(format!("{lo_rel_name} relocation at '{section_name}'0x{relative_lo:x} targets '{section_name}'0x{relative_hi:x} which doesn't have a R_RISCV_PCREL_HI20 or R_RISCV_GOT_HI20 relocation")));
        };

        let Some(hi_inst) = hi_inst else {
            return Err(ProgramFromElfError::other(format!(
                "{hi_kind} relocation for an unsupported instruction at '{section_name}'0x{relative_hi:x}: 0x{hi_inst_raw:08x}"
            )));
        };

        let hi_reg = match hi_inst {
            Inst::AddUpperImmediateToPc { dst, .. } => dst,
            _ => {
                return Err(ProgramFromElfError::other(format!(
                    "{hi_kind} relocation for an unsupported instruction at '{section_name}'[0x{relative_hi:x}]: {hi_inst:?}"
                )))
            }
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
                    kind: LoadKind::U32,
                    base,
                    dst,
                    ..
                } => (base, InstExt::Basic(BasicInst::LoadAddressIndirect { dst, target })),
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
                } => (src, InstExt::Basic(BasicInst::LoadAddress { dst, target })),
                Inst::Load { kind, base, dst, .. } => (base, InstExt::Basic(BasicInst::LoadAbsolute { kind, dst, target })),
                Inst::Store { kind, base, src, .. } => (base, InstExt::Basic(BasicInst::StoreAbsolute { kind, src, target })),
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

fn parse_function_symbols(elf: &Elf) -> Result<Vec<(Source, String)>, ProgramFromElfError> {
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
}

impl Default for Config {
    fn default() -> Self {
        Config {
            strip: false,
            optimize: true,
            inline_threshold: 2,
            elide_unnecessary_loads: true,
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
}

pub fn program_from_elf(config: Config, data: &[u8]) -> Result<ProgramBlob, ProgramFromElfError> {
    let mut elf = Elf::parse(data)?;

    if elf.section_by_name(".got").is_none() {
        elf.add_empty_data_section(".got");
    }

    // TODO: 64-bit support.
    let bitness = Bitness::B32;

    let mut sections_ro_data = Vec::new();
    let mut sections_rw_data = Vec::new();
    let mut sections_bss = Vec::new();
    let mut sections_code = Vec::new();
    let mut sections_import_metadata = Vec::new();
    let mut section_export_metadata = None;
    let mut section_min_stack_size = None;
    let mut sections_other = Vec::new();

    for section in elf.sections() {
        let name = section.name();
        let is_writable = section.is_writable();
        if name == ".rodata"
            || name.starts_with(".rodata.")
            || name == ".data.rel.ro"
            || name.starts_with(".data.rel.ro.")
            || name == ".got"
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
        } else if name == ".polkavm_imports" || name.starts_with(".polkavm_imports.") {
            sections_import_metadata.push(section.index());
        } else if name == ".polkavm_exports" {
            section_export_metadata = Some(section.index());
        } else if name == ".polkavm_min_stack_size" {
            section_min_stack_size = Some(section.index());
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
        return Err(ProgramFromElfError::other("missing '.text' section"));
    }

    let code_sections_set: HashSet<SectionIndex> = sections_code.iter().copied().collect();
    let data_sections = sections_ro_data
        .iter()
        .chain(sections_rw_data.iter())
        .chain(sections_bss.iter()) // Shouldn't need relocations, but just in case.
        .chain(sections_import_metadata.iter())
        .chain(section_export_metadata.iter())
        .chain(sections_other.iter())
        .copied();

    let mut relocations = BTreeMap::new();
    for section_index in data_sections {
        let section = elf.section_by_index(section_index);
        harvest_data_relocations(&elf, &code_sections_set, section, &mut relocations)?;
    }

    let mut instruction_overrides = HashMap::new();
    for &section_index in &sections_code {
        let section = elf.section_by_index(section_index);
        harvest_code_relocations(&elf, section, &mut instruction_overrides, &mut relocations)?;
    }

    let import_metadata = extract_import_metadata(&elf, &sections_import_metadata)?;
    let export_metadata = if let Some(section_index) = section_export_metadata {
        let section = elf.section_by_index(section_index);
        extract_export_metadata(&relocations, section)?
    } else {
        Default::default()
    };

    let mut instructions = Vec::new();
    {
        let import_by_location: HashMap<SectionTarget, &Import> = import_metadata
            .iter()
            .flat_map(|import| import.metadata_locations.iter().map(move |&location| (location, import)))
            .collect();

        for &section_index in &sections_code {
            let section = elf.section_by_index(section_index);
            parse_code_section(
                section,
                &import_by_location,
                &relocations,
                &mut instruction_overrides,
                &mut instructions,
            )?;
        }

        if !instruction_overrides.is_empty() {
            return Err(ProgramFromElfError::other("internal error: instruction overrides map is not empty"));
        }
    }

    assert!(instructions
        .iter()
        .all(|(source, _)| source.offset_range.start < source.offset_range.end));

    let data_sections_set: HashSet<SectionIndex> = sections_ro_data
        .iter()
        .chain(sections_rw_data.iter())
        .chain(sections_bss.iter()) // Shouldn't need relocations, but just in case.
        .chain(sections_import_metadata.iter())
        .chain(section_export_metadata.iter())
        .copied()
        .collect();

    let all_jump_targets = harvest_all_jump_targets(&elf, &data_sections_set, &code_sections_set, &instructions, &relocations)?;
    let all_blocks = split_code_into_basic_blocks(&all_jump_targets, instructions)?;
    for block in &all_blocks {
        for source in block.next.source.as_slice() {
            assert!(source.offset_range.start < source.offset_range.end);
        }
    }

    let section_to_block = build_section_to_block_map(&all_blocks)?;
    let mut all_blocks = resolve_basic_block_references(&data_sections_set, &section_to_block, &all_blocks)?;
    let mut reachability_graph;
    let used_blocks;

    if config.optimize {
        reachability_graph = calculate_reachability(&section_to_block, &all_blocks, &data_sections_set, &export_metadata, &relocations)?;
        optimize_program(&config, &elf, &import_metadata, &mut all_blocks, &mut reachability_graph);
        used_blocks = add_missing_fallthrough_blocks(&mut all_blocks, &mut reachability_graph);

        let expected_reachability_graph =
            calculate_reachability(&section_to_block, &all_blocks, &data_sections_set, &export_metadata, &relocations)?;
        if reachability_graph != expected_reachability_graph {
            panic!("internal error: inconsistent reachability after optimization; this is a bug, please report it!");
        }
    } else {
        reachability_graph = ReachabilityGraph::default();
        for current in (0..all_blocks.len()).map(BlockTarget::from_raw) {
            reachability_graph
                .for_code
                .entry(current)
                .or_insert_with(Default::default)
                .always_reachable = true;
        }

        for &section_index in sections_ro_data.iter().chain(sections_rw_data.iter()) {
            reachability_graph
                .for_data
                .entry(section_index)
                .or_insert_with(Default::default)
                .always_reachable = true;
        }

        used_blocks = (0..all_blocks.len()).map(BlockTarget::from_raw).collect();
    }

    for &section_index in &sections_other {
        if reachability_graph.is_data_section_reachable(section_index) {
            return Err(ProgramFromElfError::other(format!(
                "unsupported section used in program graph: '{name}'",
                name = elf.section_by_index(section_index).name(),
            )));
        }
    }

    log::debug!("Exports found: {}", export_metadata.len());

    {
        let mut count_dynamic = 0;
        for reachability in reachability_graph.for_code.values() {
            if reachability.always_reachable || !reachability.referenced_by_data.is_empty() || !reachability.address_taken_in.is_empty() {
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
                BasicInst::Ecalli { syscall } => {
                    used_imports.insert(*syscall);
                }
                _ => {}
            }
        }
    }

    elf.extend_section_to_at_least(section_got, got_size.try_into().expect("overflow"));

    let import_metadata = {
        let mut import_metadata = import_metadata;
        import_metadata.retain(|import| used_imports.contains(&import.metadata.index.unwrap()));
        import_metadata
    };

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
        section_min_stack_size,
        &mut base_address_for_section,
    )?;

    let jump_target_for_block = assign_jump_targets(&all_blocks, &used_blocks);
    let code = emit_code(
        &base_address_for_section,
        section_got,
        &target_to_got_offset,
        &all_blocks,
        &used_blocks,
        &used_imports,
        &jump_target_for_block,
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
                    SizeRelocationSize::SixBits => {
                        let mask = 0b00111111;
                        if value > mask {
                            return Err(ProgramFromElfError::other("six bit relocation overflow"));
                        }

                        let output = ((read_u8(data, relocation_target.offset)? as u64) & (!mask)) | (value & mask);
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

                    let Some(jump_target) = jump_target.checked_mul(JUMP_TARGET_MULTIPLIER) else {
                        return Err(ProgramFromElfError::other("overflow when applying a jump target relocation"));
                    };

                    let data = elf.section_data_mut(relocation_target.section_index);
                    write_generic(size, data, relocation_target.offset, jump_target.into())?;
                } else {
                    if sections_import_metadata.contains(&target.section_index) {
                        // TODO: Make this check unnecessary by removing these relocations before we get here.
                        continue;
                    }

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

                let Some(jump_target) = jump_target.checked_mul(JUMP_TARGET_MULTIPLIER) else {
                    return Err(ProgramFromElfError::other(
                        "overflow when applying a jump table relocation: jump target is too big",
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
                location_map.insert(target, location_stack.clone());
            }
        }
    }

    log::trace!("Instruction count: {}", code.len());

    let mut writer = Writer::default();
    writer.push_raw_bytes(&program::BLOB_MAGIC);
    writer.push_byte(program::BLOB_VERSION_V1);

    writer.push_section(program::SECTION_MEMORY_CONFIG, |writer| {
        writer.push_varint(memory_config.bss_size);
        writer.push_varint(memory_config.stack_size);
    });

    writer.push_section(program::SECTION_RO_DATA, |writer| {
        for range in memory_config.ro_data {
            match range {
                DataRef::Section { section_index, range } => {
                    let slice = &elf.section_by_index(section_index).data()[range];
                    writer.push_raw_bytes(slice);
                }
                DataRef::Padding(bytes) => {
                    for _ in 0..bytes {
                        writer.push_byte(0);
                    }
                }
            }
        }
    });

    writer.push_section(program::SECTION_RW_DATA, |writer| {
        for range in memory_config.rw_data {
            match range {
                DataRef::Section { section_index, range } => {
                    let slice = &elf.section_by_index(section_index).data()[range];
                    writer.push_raw_bytes(slice);
                }
                DataRef::Padding(bytes) => {
                    for _ in 0..bytes {
                        writer.push_byte(0);
                    }
                }
            }
        }
    });

    writer.push_section(program::SECTION_IMPORTS, |writer| {
        if import_metadata.is_empty() {
            return;
        }

        let mut import_metadata = import_metadata;
        import_metadata.sort_by(|a, b| {
            a.metadata
                .index
                .cmp(&b.metadata.index)
                .then_with(|| a.metadata.name().cmp(b.metadata.name()))
        });

        writer.push_varint(import_metadata.len() as u32);
        for import in import_metadata {
            writer.push_varint(import.metadata.index.expect("internal error: no index assigned to import"));
            writer.push_function_prototype(import.metadata.prototype());
        }
    });

    writer.push_section(program::SECTION_EXPORTS, |writer| {
        if export_metadata.is_empty() {
            return;
        }

        writer.push_varint(export_metadata.len() as u32);
        for meta in export_metadata {
            let &block_target = section_to_block
                .get(&meta.location)
                .expect("internal error: export metadata has a non-block target location");
            let jump_target = jump_target_for_block[block_target.index()]
                .expect("internal error: export metadata points to a block without a jump target assigned");
            writer.push_varint(jump_target);
            writer.push_function_prototype(&meta.prototype);
        }
    });

    let mut locations_for_instruction: Vec<Option<Arc<[Location]>>> = Vec::with_capacity(code.len());
    writer.push_section(program::SECTION_CODE, |writer| {
        let mut buffer = [0; program::MAX_INSTRUCTION_LENGTH];
        for (nth_inst, (source_stack, inst)) in code.into_iter().enumerate() {
            let length = inst.serialize_into(&mut buffer);
            writer.push_raw_bytes(&buffer[..length]);

            let mut function_name = None;
            if !config.strip {
                // Two or more addresses can point to the same instruction (e.g. in case of macro op fusion).
                // Two or more instructions can also have the same address (e.g. in case of jump targets).

                // TODO: Use a smallvec.
                let mut list = Vec::new();
                for source in source_stack.as_slice() {
                    for offset in (source.offset_range.start..source.offset_range.end).step_by(4) {
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

                            list.push(locations.clone());
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
    });

    if !config.strip {
        emit_debug_info(&mut writer, &locations_for_instruction);
    }

    writer.push_raw_bytes(&[program::SECTION_END_OF_FILE]);

    log::debug!("Built a program of {} bytes", writer.blob.len());
    let blob = ProgramBlob::parse(writer.blob)?;

    // Sanity check that our debug info was properly emitted and can be parsed.
    if cfg!(debug_assertions) && !config.strip {
        'outer: for (instruction_position, locations) in locations_for_instruction.iter().enumerate() {
            let instruction_position = instruction_position as u32;
            let line_program = blob.get_debug_line_program_at(instruction_position).unwrap();
            let Some(locations) = locations else {
                assert!(line_program.is_none());
                continue;
            };

            let mut line_program = line_program.unwrap();
            while let Some(region_info) = line_program.run().unwrap() {
                if !region_info.instruction_range().contains(&instruction_position) {
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

    Ok(blob)
}

#[derive(Default)]
struct Writer {
    blob: Vec<u8>,
}

impl Writer {
    fn push_raw_bytes(&mut self, slice: &[u8]) {
        self.blob.extend_from_slice(slice);
    }

    fn push_byte(&mut self, byte: u8) {
        self.blob.push(byte);
    }

    fn push_section(&mut self, section: u8, callback: impl FnOnce(&mut Self)) -> Range<usize> {
        let section_position = self.blob.len();
        self.blob.push(section);

        // Reserve the space for the length varint.
        let length_position = self.blob.len();
        self.push_raw_bytes(&[0xff_u8; varint::MAX_VARINT_LENGTH]);

        let payload_position = self.blob.len();
        callback(self);

        let payload_length: u32 = (self.blob.len() - payload_position).try_into().expect("section size overflow");
        if payload_length == 0 {
            // Nothing was written by the callback. Skip writing the section.
            self.blob.truncate(section_position);
            return 0..0;
        }

        // Write the length varint.
        let length_length = varint::write_varint(payload_length, &mut self.blob[length_position..]);

        // Drain any excess length varint bytes.
        self.blob
            .drain(length_position + length_length..length_position + varint::MAX_VARINT_LENGTH);
        length_position + length_length..self.blob.len()
    }

    fn push_varint(&mut self, value: u32) {
        let mut buffer = [0xff_u8; varint::MAX_VARINT_LENGTH];
        let length = varint::write_varint(value, &mut buffer);
        self.push_raw_bytes(&buffer[..length]);
    }

    fn push_u32(&mut self, value: u32) {
        self.push_raw_bytes(&value.to_le_bytes());
    }

    fn push_bytes_with_length(&mut self, slice: &[u8]) {
        self.push_varint(slice.len().try_into().expect("length overflow"));
        self.push_raw_bytes(slice);
    }

    fn push_function_prototype(&mut self, meta: &FnMetadata) {
        self.push_bytes_with_length(meta.name().as_bytes());
        self.push_varint(meta.args().count() as u32);
        for arg_ty in meta.args() {
            self.push_byte(arg_ty as u8);
        }
        self.push_byte(meta.return_ty().map(|ty| ty as u8).unwrap_or(0));
    }

    fn len(&self) -> usize {
        self.blob.len()
    }
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

fn emit_debug_info(writer: &mut Writer, locations_for_instruction: &[Option<Arc<[Location]>>]) {
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
            }
        } else {
            Group {
                namespace: None,
                function_name: None,
                path: None,
                instruction_position,
                instruction_count: 1,
            }
        };

        if let Some(last_group) = groups.last_mut() {
            if last_group.key() == group.key() {
                assert_eq!(last_group.instruction_position + last_group.instruction_count, instruction_position);
                last_group.instruction_count += 1;
                continue;
            }
        }

        groups.push(group);
    }

    groups.retain(|group| group.function_name.is_some() || group.path.is_some());

    log::trace!("Location groups: {}", groups.len());
    dbg_strings.write_protected = true;

    writer.push_section(program::SECTION_OPT_DEBUG_STRINGS, |writer| {
        writer.push_raw_bytes(&dbg_strings.section);
    });

    let mut info_offsets = Vec::with_capacity(groups.len());
    writer.push_section(program::SECTION_OPT_DEBUG_LINE_PROGRAMS, |writer| {
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

                fn finish_instruction(&mut self, writer: &mut Writer, next_depth: usize) {
                    self.queued_count += 1;

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
                            .map(|string| dbg_strings.dedup(string))
                            .unwrap_or(empty_string_id);
                        writer.push_varint(namespace_offset);
                    }

                    if changed_function_name {
                        state.set_mutation_depth(writer, depth);
                        writer.push_byte(LineProgramOp::SetFunctionName as u8);
                        state.stack[depth].function_name = location.function_name.clone();

                        let function_name_offset = location
                            .function_name
                            .as_ref()
                            .map(|string| dbg_strings.dedup(string))
                            .unwrap_or(empty_string_id);
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
                                    Cow::Borrowed(_) => location.path().clone(),
                                    Cow::Owned(path) => path.into(),
                                });

                        let path_offset = location
                            .source_code_location
                            .as_ref()
                            .map(|location| dbg_strings.dedup_cow(simplify_path(location.path())))
                            .unwrap_or(empty_string_id);
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
                state.finish_instruction(writer, next_depth);
            }

            state.flush_if_any_are_queued(writer);
            writer.push_byte(LineProgramOp::FinishProgram as u8);
        }
    });

    assert_eq!(info_offsets.len(), groups.len());
    writer.push_section(program::SECTION_OPT_DEBUG_LINE_PROGRAM_RANGES, |writer| {
        for (group, info_offset) in groups.iter().zip(info_offsets.into_iter()) {
            writer.push_u32(group.instruction_position.try_into().expect("overflow"));
            writer.push_u32((group.instruction_position + group.instruction_count).try_into().expect("overflow"));
            writer.push_u32(info_offset);
        }
    });
}
