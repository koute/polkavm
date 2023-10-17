use polkavm_common::abi::{GuestMemoryConfig, VM_ADDR_USER_MEMORY, VM_PAGE_SIZE};
use polkavm_common::elf::{FnMetadata, ImportMetadata, INSTRUCTION_ECALLI};
use polkavm_common::program::Reg as PReg;
use polkavm_common::program::{self, FrameKind, LineProgramOp, Opcode, ProgramBlob, RawInstruction};
use polkavm_common::utils::align_to_next_page_u64;
use polkavm_common::varint;

use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap, HashSet};
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

#[derive(Copy, Clone, Debug)]
struct EndOfBlock<T> {
    source: Source,
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
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Hash)]
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

#[derive(Copy, Clone, Debug)]
enum BasicInst<T> {
    LoadAbsolute { kind: LoadKind, dst: Reg, target: SectionTarget },
    StoreAbsolute { kind: StoreKind, src: Reg, target: SectionTarget },
    LoadIndirect { kind: LoadKind, dst: Reg, base: Reg, offset: i32 },
    StoreIndirect { kind: StoreKind, src: Reg, base: Reg, offset: i32 },
    LoadAddress { dst: Reg, target: T },
    // This is supposed to load the address of a location which contains the `target` address,
    // not the `target` address directly.
    LoadAddressIndirect { dst: Reg, target: T },
    RegImm { kind: RegImmKind, dst: Reg, src: Reg, imm: i32 },
    Shift { kind: ShiftKind, dst: Reg, src: Reg, amount: u8 },
    RegReg { kind: RegRegKind, dst: Reg, src1: Reg, src2: Reg },
    Ecalli { syscall: u32 },
}

impl<T> BasicInst<T> {
    fn is_nop(&self) -> bool {
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

#[derive(Copy, Clone, Debug)]
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
    ops: Vec<(Source, BasicInst<BasicT>)>,
    next: EndOfBlock<ControlT>,
}

impl<BasicT, ControlT> BasicBlock<BasicT, ControlT> {
    fn new(target: BlockTarget, source: Source, ops: Vec<(Source, BasicInst<BasicT>)>, next: EndOfBlock<ControlT>) -> Self {
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
    let mut current_block = Vec::new();
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

                    log::trace!("Emitting block (due to a potential jump): {}", block_source.begin());
                    blocks.push(BasicBlock::new(
                        block_index,
                        block_source,
                        std::mem::take(&mut current_block),
                        EndOfBlock {
                            source: Source {
                                section_index: block_section,
                                offset_range: (source.offset_range.start..source.offset_range.start).into(),
                            },
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
                    EndOfBlock { source, instruction },
                ));

                if let ControlInst::Branch { target_false, .. } = instruction {
                    assert_eq!(source.section_index, target_false.section_index);
                    assert_eq!(source.offset_range.end, target_false.offset);
                    block_start_opt = Some((block_section, source.offset_range.end));
                }
            }
            InstExt::Basic(instruction) => {
                current_block.push((source, instruction));
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
            ops.push((*source, op));
        }

        let Ok(next) = block
            .next
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

fn delete_nop_instructions_in_blocks(all_blocks: &mut Vec<BasicBlock<AnyTarget, BlockTarget>>) {
    for block in all_blocks {
        for index in 0..block.ops.len() {
            let &(source, instruction) = &block.ops[index];
            if !instruction.is_nop() {
                continue;
            }

            // We're going to delete this instruction, so let's extend the source region of the next instruction to cover it.
            if index + 1 < block.ops.len() {
                let next_source = &mut block.ops[index + 1].0;
                assert_eq!(source.section_index, next_source.section_index);
                next_source.offset_range.start = source.offset_range.start;
            }
        }

        block.ops.retain(|(_, instruction)| !instruction.is_nop());
    }
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

struct UniqueQueue<T> {
    vec: Vec<T>,
    seen: HashSet<T>,
}

impl<T> UniqueQueue<T> {
    fn new() -> Self {
        Self {
            vec: Vec::new(),
            seen: HashSet::new(),
        }
    }

    fn pop(&mut self) -> Option<T> {
        self.vec.pop()
    }

    fn push(&mut self, value: T)
    where
        T: core::hash::Hash + Eq + Clone,
    {
        if self.seen.insert(value.clone()) {
            self.vec.push(value);
        }
    }

    fn is_empty(&self) -> bool {
        self.vec.is_empty()
    }
}

fn find_reachable(
    section_to_block: &HashMap<SectionTarget, BlockTarget>,
    all_blocks: &[BasicBlock<AnyTarget, BlockTarget>],
    data_sections_set: &HashSet<SectionIndex>,
    export_metadata: &[ExportMetadata],
    relocations: &BTreeMap<SectionTarget, RelocationKind>,
) -> Result<(HashSet<BlockTarget>, HashSet<SectionIndex>), ProgramFromElfError> {
    let mut data_section_queue: UniqueQueue<SectionIndex> = UniqueQueue::new();
    let mut section_queue: UniqueQueue<SectionTarget> = UniqueQueue::new();
    let mut block_queue: UniqueQueue<BlockTarget> = UniqueQueue::new();
    for export in export_metadata {
        if !section_to_block.contains_key(&export.location) {
            return Err(ProgramFromElfError::other("export points to a non-block"));
        }

        section_queue.push(export.location);
    }

    while !section_queue.is_empty() || !block_queue.is_empty() || !data_section_queue.is_empty() {
        while let Some(target) = section_queue.pop() {
            if let Some(block_target) = section_to_block.get(&target) {
                block_queue.push(*block_target);
                continue;
            }

            if data_sections_set.contains(&target.section_index) {
                data_section_queue.push(target.section_index);
            }
        }

        while let Some(block_target) = block_queue.pop() {
            let block = &all_blocks[block_target.index()];
            for (_, instruction) in &block.ops {
                let (data_target, code_or_data_target) = instruction.target();
                if let Some(target) = data_target {
                    section_queue.push(target);
                }

                if let Some(target) = code_or_data_target {
                    match target {
                        AnyTarget::Code(target) => block_queue.push(target),
                        AnyTarget::Data(target) => {
                            if data_sections_set.contains(&target.section_index) {
                                data_section_queue.push(target.section_index);
                            }
                            section_queue.push(target);
                        }
                    }
                }
            }

            match block.next.instruction {
                ControlInst::Jump { target } => {
                    block_queue.push(target);
                }
                ControlInst::Call { target, target_return, .. } => {
                    block_queue.push(target);
                    block_queue.push(target_return);
                }
                ControlInst::CallIndirect { target_return, .. } => {
                    block_queue.push(target_return);
                }
                ControlInst::Branch {
                    target_true, target_false, ..
                } => {
                    block_queue.push(target_true);
                    block_queue.push(target_false);
                }

                ControlInst::JumpIndirect { .. } | ControlInst::Unimplemented => {}
            }
        }

        while let Some(section_index) = data_section_queue.pop() {
            // TODO: Can we skip some parts of the data sections?
            for (relocation_location, relocation) in relocations.iter() {
                // TOOD: Make this more efficient?
                if relocation_location.section_index != section_index {
                    continue;
                }

                for relocation_target in relocation.targets().into_iter().flatten() {
                    section_queue.push(relocation_target);
                }
            }
        }
    }

    Ok((block_queue.seen, data_section_queue.seen))
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

fn emit_code(
    base_address_for_section: &HashMap<SectionIndex, u64>,
    section_got: SectionIndex,
    target_to_got_offset: &HashMap<AnyTarget, u64>,
    all_blocks: &[BasicBlock<AnyTarget, BlockTarget>],
    used_blocks: &[BlockTarget],
    used_imports: &HashSet<u32>,
    jump_target_for_block: &[Option<u32>],
) -> Result<Vec<(Source, RawInstruction)>, ProgramFromElfError> {
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

    let mut code: Vec<(Source, RawInstruction)> = Vec::new();
    for block_target in used_blocks {
        let block = &all_blocks[block_target.index()];
        let jump_target = jump_target_for_block[block.target.index()].unwrap();

        code.push((
            Source {
                section_index: block.source.section_index,
                offset_range: (block.source.offset_range.start..block.source.offset_range.start + 4).into(),
            },
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

        for &(source, op) in &block.ops {
            let op = match op {
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

            code.push((source, op));
        }

        fn unconditional_jump(target: u32) -> RawInstruction {
            RawInstruction::new_with_regs2_imm(Opcode::jump_and_link_register, cast_reg(Reg::Zero), cast_reg(Reg::Zero), target)
        }

        match block.next.instruction {
            ControlInst::Jump { target } => {
                let target = get_jump_target(target)?;
                if !can_fallthrough_to_next_block.contains(block_target) {
                    code.push((block.next.source, unconditional_jump(target)));
                }
            }
            ControlInst::Call { ra, target, target_return } => {
                let target = get_jump_target(target)?;
                let target_return = get_jump_target(target_return)?;

                code.push((
                    block.next.source,
                    RawInstruction::new_with_regs2_imm(Opcode::jump_and_link_register, cast_reg(ra), cast_reg(Reg::Zero), target),
                ));

                if !can_fallthrough_to_next_block.contains(block_target) {
                    // TODO: This could be more efficient if we'd just directly set the return address to where we want to return.
                    code.push((block.next.source, unconditional_jump(target_return)));
                }
            }
            ControlInst::JumpIndirect { base, offset } => {
                if offset % 4 != 0 {
                    return Err(ProgramFromElfError::other(
                        "found an indirect jump with an offset that isn't aligned",
                    ));
                }

                code.push((
                    block.next.source,
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
                if offset % 4 != 0 {
                    return Err(ProgramFromElfError::other(
                        "found an indirect call with a target that isn't aligned",
                    ));
                }

                let target_return = get_jump_target(target_return)?;
                code.push((
                    block.next.source,
                    RawInstruction::new_with_regs2_imm(Opcode::jump_and_link_register, cast_reg(ra), cast_reg(base), offset as u32 / 4),
                ));

                if !can_fallthrough_to_next_block.contains(block_target) {
                    // TODO: This could be more efficient if we'd just directly set the return address to where we want to return.
                    code.push((block.next.source, unconditional_jump(target_return)));
                }
            }
            ControlInst::Branch {
                kind,
                src1,
                src2,
                target_true,
                target_false,
            } => {
                let target_true = get_jump_target(target_true)?;
                let target_false = get_jump_target(target_false)?;

                let kind = match kind {
                    BranchKind::Eq => Opcode::branch_eq,
                    BranchKind::NotEq => Opcode::branch_not_eq,
                    BranchKind::LessSigned => Opcode::branch_less_signed,
                    BranchKind::GreaterOrEqualSigned => Opcode::branch_greater_or_equal_signed,
                    BranchKind::LessUnsigned => Opcode::branch_less_unsigned,
                    BranchKind::GreaterOrEqualUnsigned => Opcode::branch_greater_or_equal_unsigned,
                };

                code.push((
                    block.next.source,
                    RawInstruction::new_with_regs2_imm(kind, cast_reg(src1), cast_reg(src2), target_true),
                ));

                if !can_fallthrough_to_next_block.contains(block_target) {
                    code.push((block.next.source, unconditional_jump(target_false)));
                }
            }
            ControlInst::Unimplemented => {
                code.push((block.next.source, RawInstruction::new_argless(Opcode::trap)));
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

#[derive(Default)]
pub struct Config {
    strip: bool,
}

impl Config {
    pub fn set_strip(&mut self, value: bool) -> &mut Self {
        self.strip = value;
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
    let section_to_block = build_section_to_block_map(&all_blocks)?;
    let mut all_blocks = resolve_basic_block_references(&data_sections_set, &section_to_block, &all_blocks)?;
    delete_nop_instructions_in_blocks(&mut all_blocks);
    let (used_block_set, mut used_data_sections) =
        find_reachable(&section_to_block, &all_blocks, &data_sections_set, &export_metadata, &relocations)?;

    for &section_index in &sections_other {
        if used_data_sections.contains(&section_index) {
            return Err(ProgramFromElfError::other(format!(
                "unsupported section used in program graph: '{name}'",
                name = elf.section_by_index(section_index).name(),
            )));
        }
    }

    log::debug!("Exports found: {}", export_metadata.len());
    log::debug!("Blocks used: {}/{}", used_block_set.len(), all_blocks.len());

    let section_got = elf.add_empty_data_section(".got");
    sections_ro_data.push(section_got);
    used_data_sections.insert(section_got);

    let mut target_to_got_offset: HashMap<AnyTarget, u64> = HashMap::new();
    let mut got_size = 0;

    let mut used_blocks = Vec::new();
    let mut used_imports = HashSet::new();
    for block in &all_blocks {
        if !used_block_set.contains(&block.target) {
            continue;
        }

        used_blocks.push(block.target);

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
        .filter(|section_index| used_data_sections.contains(section_index))
        .collect();

    let sections_rw_data: Vec<_> = sections_rw_data
        .into_iter()
        .filter(|section_index| used_data_sections.contains(section_index))
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
            assert!(!used_data_sections.contains(&section_index));
            assert!(base_address_for_section.insert(section_index, address).is_none());
        }
    }

    for (&relocation_target, &relocation) in &relocations {
        let section = elf.section_by_index(relocation_target.section_index);
        if !used_data_sections.contains(&relocation_target.section_index) {
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
                if used_data_sections.contains(&section.index()) {
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
                        if !used_data_sections.contains(&relocation_target.section_index) {
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
                        if !used_data_sections.contains(&relocation_target.section_index) {
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

    let mut locations_for_instruction = Vec::with_capacity(code.len());
    writer.push_section(program::SECTION_CODE, |writer| {
        let mut buffer = [0; program::MAX_INSTRUCTION_LENGTH];
        for (nth_inst, (source, inst)) in code.into_iter().enumerate() {
            let length = inst.serialize_into(&mut buffer);
            writer.push_raw_bytes(&buffer[..length]);

            let mut function_name = None;
            if !config.strip {
                // Two or more addresses can point to the same instruction (e.g. in case of macro op fusion).
                // Two or more instructions can also have the same address (e.g. in case of jump targets).
                let mut found = None;
                for offset in (source.offset_range.start..source.offset_range.end).step_by(4) {
                    let target = SectionTarget {
                        section_index: source.section_index,
                        offset,
                    };

                    if let Some(locations) = location_map.get(&target) {
                        function_name = locations[0].function_name.as_deref();
                        found = Some(locations.clone());
                        break;
                    }
                }

                locations_for_instruction.push(found);
            }

            log::trace!(
                "Code: 0x{source_address:x} [{function_name}] -> {source} -> #{nth_inst}: {inst}",
                source_address = {
                    elf.section_by_index(source.section_index)
                        .original_address()
                        .wrapping_add(source.offset_range.start)
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
                        actual.path().unwrap(),
                        expected.source_code_location.as_ref().map(|location| &**location.path())
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

    fn simplify_path(path: &str) -> Cow<str> {
        // TODO: Sanitize macOS and Windows paths.
        if let Some(p) = path.strip_prefix("/home/") {
            if let Some(index) = p.bytes().position(|byte| byte == b'/') {
                return format!("~{}", &p[index..]).into();
            }
        }

        path.into()
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
                    let new_path = location.source_code_location.as_ref().map(|location| location.path());
                    let new_line = location.source_code_location.as_ref().and_then(|location| location.line());
                    let new_column = location.source_code_location.as_ref().and_then(|location| location.column());

                    let changed_kind = state.stack[depth].kind != Some(location.kind);
                    let changed_namespace = state.stack[depth].namespace != location.namespace;
                    let changed_function_name = state.stack[depth].function_name != location.function_name;
                    let changed_path = state.stack[depth].path.as_ref() != new_path;
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
                        state.stack[depth].path = location.source_code_location.as_ref().map(|location| location.path().clone());

                        let path_offset = location
                            .source_code_location
                            .as_ref()
                            .map(|location| dbg_strings.dedup(location.path()))
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
