use polkavm_common::abi::{GuestMemoryConfig, VM_ADDR_USER_MEMORY, VM_PAGE_SIZE};
use polkavm_common::elf::{ExportMetadata, FnMetadata, ImportMetadata, INSTRUCTION_ECALLI};
use polkavm_common::program::Reg as PReg;
use polkavm_common::program::{self, Opcode, ProgramBlob, RawInstruction};
use polkavm_common::utils::align_to_next_page_u64;
use polkavm_common::varint;

use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::ops::Range;

use crate::dwarf::DwarfInfo;
use crate::riscv::{BranchKind, Inst, LoadKind, Reg, RegImmKind, RegRegKind, ShiftKind, StoreKind};

use object::{LittleEndian, Object, ObjectSection, ObjectSymbol, SectionIndex};

pub(crate) type Elf<'a> = object::read::elf::ElfFile<'a, object::elf::FileHeader32<object::endian::LittleEndian>, &'a [u8]>;
type ElfSection<'a, 'b> = object::read::elf::ElfSection<'a, 'b, object::elf::FileHeader32<object::endian::LittleEndian>, &'a [u8]>;

#[derive(Debug)]
pub enum ProgramFromElfErrorKind {
    FailedToParseElf(object::read::Error),
    FailedToParseDwarf(gimli::Error),
    FailedToParseProgram(program::ProgramParseError),
    UnsupportedSection(String),
    UnsupportedInstruction { pc: u64, instruction: u32 },
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

impl core::fmt::Display for ProgramFromElfError {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
        match &self.0 {
            ProgramFromElfErrorKind::FailedToParseElf(error) => write!(fmt, "failed to parse ELF file: {}", error),
            ProgramFromElfErrorKind::FailedToParseDwarf(error) => write!(fmt, "failed to parse DWARF: {}", error),
            ProgramFromElfErrorKind::FailedToParseProgram(error) => write!(fmt, "{}", error),
            ProgramFromElfErrorKind::UnsupportedSection(section) => write!(fmt, "unsupported section: {}", section),
            ProgramFromElfErrorKind::UnsupportedInstruction { pc, instruction } => {
                write!(fmt, "unsupported instruction at 0x{:x}: 0x{:08x}", pc, instruction)
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

#[derive(Copy, Clone, Debug)]
enum EndOfBlock {
    Fallthrough { target: u64 },
    Control { source: AddressRange, instruction: ControlInst },
}

#[derive(Copy, Clone, PartialEq, Eq)]
struct AddressRange {
    start: u64,
    end: u64,
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

#[derive(Copy, Clone, Debug)]
enum BasicInst {
    Load { kind: LoadKind, dst: Reg, base: Reg, offset: i32 },
    Store { kind: StoreKind, src: Reg, base: Reg, offset: i32 },
    RegImm { kind: RegImmKind, dst: Reg, src: Reg, imm: i32 },
    Shift { kind: ShiftKind, dst: Reg, src: Reg, amount: u8 },
    RegReg { kind: RegRegKind, dst: Reg, src1: Reg, src2: Reg },
    Ecalli { syscall: u32 },
}

impl BasicInst {
    fn is_nop(self) -> bool {
        match self {
            BasicInst::RegImm { dst, .. } | BasicInst::Shift { dst, .. } | BasicInst::RegReg { dst, .. } => dst == Reg::Zero,
            BasicInst::Load { .. } | BasicInst::Store { .. } | BasicInst::Ecalli { .. } => false,
        }
    }
}

#[derive(Copy, Clone, Debug)]
enum ControlInst {
    Jump {
        target: u64,
    },
    Call {
        ra: Reg,
        target: u64,
        return_address: u64,
    },
    JumpIndirect {
        base: Reg,
        offset: i64,
    },
    CallIndirect {
        ra: Reg,
        base: Reg,
        offset: i64,
        return_address: u64,
    },
    Branch {
        kind: BranchKind,
        src1: Reg,
        src2: Reg,
        target_true: u64,
        target_false: u64,
    },
    Unimplemented,
}

#[derive(Copy, Clone, Debug)]
enum InstExt {
    Basic(BasicInst),
    Control(ControlInst),
}

#[derive(Debug)]
struct BasicBlock {
    source: AddressRange,
    ops: Vec<(AddressRange, BasicInst)>,
    next: EndOfBlock,
}

impl BasicBlock {
    fn new(source: AddressRange, ops: Vec<(AddressRange, BasicInst)>, next: EndOfBlock) -> Self {
        Self { source, ops, next }
    }
}

struct Fn<'a> {
    name: Option<&'a str>,
    range: AddressRange,
    frames: Vec<crate::dwarf::Frame>,
    blocks: Vec<usize>,
}

impl<'a> Fn<'a> {
    fn namespace_and_name(&self) -> Option<(String, String)> {
        let name = self.name?;
        let name = rustc_demangle::try_demangle(name).ok()?;

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
                return Some((prefix.to_owned(), suffix.to_owned()));
            } else {
                log::warn!("Failed to split symbol: {:?}", with_hash);
            }
        }

        Some((String::new(), with_hash))
    }
}

#[derive(Clone)]
enum RangeOrPadding {
    Range(Range<usize>),
    Padding(usize),
}

impl RangeOrPadding {
    fn size(&self) -> usize {
        match self {
            RangeOrPadding::Range(range) => range.len(),
            RangeOrPadding::Padding(size) => *size,
        }
    }
}

impl From<Range<usize>> for RangeOrPadding {
    fn from(range: Range<usize>) -> Self {
        RangeOrPadding::Range(range)
    }
}

struct MemoryConfig {
    ro_data: Vec<RangeOrPadding>,
    rw_data: Vec<RangeOrPadding>,
    bss_size: u32,
    stack_size: u32,
}

fn get_padding(memory_end: u64, section: &ElfSection) -> Option<u64> {
    let misalignment = memory_end % section.align();
    if misalignment == 0 {
        None
    } else {
        Some(section.align() - misalignment)
    }
}

#[allow(clippy::too_many_arguments)]
fn extract_memory_config(
    data: &[u8],
    sections_ro_data: &[&ElfSection],
    sections_rw_data: &[&ElfSection],
    sections_bss: &[&ElfSection],
    relocation_for_section: &mut HashMap<SectionIndex, i64>,
) -> Result<MemoryConfig, ProgramFromElfError> {
    let mut memory_end = VM_ADDR_USER_MEMORY as u64;
    let mut ro_data = Vec::new();
    let mut ro_data_size = 0;

    fn align_if_necessary(memory_end: &mut u64, output_size: &mut u64, output_chunks: &mut Vec<RangeOrPadding>, section: &ElfSection) {
        if let Some(padding) = get_padding(*memory_end, section) {
            *memory_end += padding;
            *output_size += padding;
            output_chunks.push(RangeOrPadding::Padding(padding as usize));
        }
    }

    assert_eq!(memory_end % VM_PAGE_SIZE as u64, 0);

    let ro_data_address = memory_end;
    for section in sections_ro_data.iter() {
        align_if_necessary(&mut memory_end, &mut ro_data_size, &mut ro_data, section);

        let section_name = section.name().expect("failed to get section name");
        let relocation_offset = (memory_end as i64).wrapping_sub(section.address() as i64);
        relocation_for_section.insert(section.index(), relocation_offset);

        let initial_ro_data_size = ro_data_size;
        let section_range = get_section_range(data, section)?;
        memory_end += section_range.len() as u64;
        ro_data.push(section_range.clone().into());
        ro_data_size += section_range.len() as u64;

        log::trace!(
            "Found read-only section: '{}', address = 0x{:x}..0x{:x} (relocated to: 0x{:x}..0x{:x}), size = 0x{:x}",
            section_name,
            section.address(),
            section.address() + section_range.len() as u64,
            section.address() as i64 + relocation_offset,
            section.address() as i64 + relocation_offset + (ro_data_size - initial_ro_data_size) as i64,
            section_range.len(),
        );

        if section.size() > (ro_data_size - initial_ro_data_size) {
            // Technically we can work around this, but until something actually hits this let's not bother.
            return Err(ProgramFromElfError::other(format!(
                "internal error: size of section '{section_name}' covers more than what the file contains"
            )));
        }
    }

    {
        let ro_data_size_unaligned = ro_data_size;

        assert_eq!(ro_data_address % VM_PAGE_SIZE as u64, 0);
        ro_data_size = align_to_next_page_u64(VM_PAGE_SIZE as u64, ro_data_size)
            .ok_or(ProgramFromElfError::other("out of range size for read-only sections"))?;

        memory_end += ro_data_size - ro_data_size_unaligned;
    }

    assert_eq!(memory_end % VM_PAGE_SIZE as u64, 0);

    let mut rw_data = Vec::new();
    let mut rw_data_size = 0;
    let rw_data_address = memory_end;
    for section in sections_rw_data.iter() {
        align_if_necessary(&mut memory_end, &mut rw_data_size, &mut rw_data, section);

        let section_name = section.name().expect("failed to get section name");
        let relocation_offset = (memory_end as i64).wrapping_sub(section.address() as i64);
        relocation_for_section.insert(section.index(), relocation_offset);

        let initial_rw_data_size = rw_data_size;
        let section_range = get_section_range(data, section)?;
        memory_end += section_range.len() as u64;
        rw_data.push(section_range.clone().into());
        rw_data_size += section_range.len() as u64;

        log::trace!(
            "Found read-write section: '{}', address = 0x{:x}..0x{:x} (relocated to: 0x{:x}..0x{:x}), size = 0x{:x}",
            section_name,
            section.address(),
            section.address() + section_range.len() as u64,
            section.address() as i64 + relocation_offset,
            section.address() as i64 + relocation_offset + (rw_data_size - initial_rw_data_size) as i64,
            section_range.len(),
        );

        if section.size() > (rw_data_size - initial_rw_data_size) {
            return Err(ProgramFromElfError::other(format!(
                "internal error: size of section '{section_name}' covers more than what the file contains"
            )));
        }
    }

    let bss_explicit_address = {
        let rw_data_size_unaligned = rw_data_size;

        assert_eq!(rw_data_address % VM_PAGE_SIZE as u64, 0);
        rw_data_size = align_to_next_page_u64(VM_PAGE_SIZE as u64, rw_data_size)
            .ok_or(ProgramFromElfError::other("out of range size for read-write sections"))?;

        memory_end + (rw_data_size - rw_data_size_unaligned)
    };

    for section in sections_bss {
        if let Some(padding) = get_padding(memory_end, section) {
            memory_end += padding;
        }

        let section_name = section.name().expect("failed to get section name");
        let relocation_offset = (memory_end as i64).wrapping_sub(section.address() as i64);
        relocation_for_section.insert(section.index(), relocation_offset);

        log::trace!(
            "Found BSS section: '{}', address = 0x{:x}..0x{:x} (relocated to: 0x{:x}..0x{:x}), size = 0x{:x}",
            section_name,
            section.address(),
            section.address() + section.size(),
            section.address() as i64 + relocation_offset,
            section.address() as i64 + relocation_offset + section.size() as i64,
            section.size(),
        );

        memory_end += section.size();
    }

    let mut bss_size = if memory_end > bss_explicit_address {
        memory_end - bss_explicit_address
    } else {
        0
    };

    bss_size =
        align_to_next_page_u64(VM_PAGE_SIZE as u64, bss_size).ok_or(ProgramFromElfError::other("out of range size for BSS sections"))?;

    // TODO: This should be configurable.
    let stack_size = VM_PAGE_SIZE as u64;

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

fn extract_export_metadata<'a>(data: &'a [u8], section: &ElfSection) -> Result<Vec<ExportMetadata<'a>>, ProgramFromElfError> {
    let section_range = get_section_range(data, section)?;
    let mut contents = &data[section_range];
    let mut exports = Vec::new();
    while !contents.is_empty() {
        match ExportMetadata::try_deserialize(contents) {
            Ok((bytes_consumed, metadata)) => {
                contents = &contents[bytes_consumed..];
                exports.push(metadata);
            }
            Err(error) => {
                return Err(ProgramFromElfError::other(format!("failed to parse export metadata: {}", error)));
            }
        }
    }

    Ok(exports)
}

fn extract_import_metadata<'a>(data: &'a [u8], section: &ElfSection) -> Result<BTreeMap<u32, ImportMetadata<'a>>, ProgramFromElfError> {
    let section_range = get_section_range(data, section)?;
    let mut contents = &data[section_range];
    let mut import_by_index = BTreeMap::new();
    let mut indexless = Vec::new();
    while !contents.is_empty() {
        match ImportMetadata::try_deserialize(contents) {
            Ok((bytes_consumed, metadata)) => {
                contents = &contents[bytes_consumed..];

                if let Some(index) = metadata.index {
                    if let Some(old_metadata) = import_by_index.insert(index, metadata.clone()) {
                        if old_metadata == metadata {
                            continue;
                        }

                        let old_name = old_metadata.name();
                        let new_name = metadata.name();
                        return Err(ProgramFromElfError::other(format!(
                            "duplicate imports with the same index: index = {index}, names = [{old_name:?}, {new_name:?}]"
                        )));
                    }
                } else {
                    indexless.push(metadata);
                }
            }
            Err(error) => {
                return Err(ProgramFromElfError::other(format!("failed to parse import metadata: {}", error)));
            }
        }
    }

    indexless.sort_by(|a, b| a.name().cmp(b.name()));
    indexless.dedup();

    let mut next_index = 0;
    for metadata in indexless {
        while import_by_index.contains_key(&next_index) {
            next_index += 1;
        }

        import_by_index.insert(
            next_index,
            ImportMetadata {
                index: Some(next_index),
                ..metadata
            },
        );
        next_index += 1;
    }

    let mut import_by_name = HashMap::new();
    for metadata in import_by_index.values() {
        if let Some(old_metadata) = import_by_name.insert(metadata.name(), metadata) {
            if old_metadata.prototype() != metadata.prototype() {
                return Err(ProgramFromElfError::other(format!(
                    "duplicate imports with the same name yet different prototype: {}",
                    metadata.name()
                )));
            }
        }
    }

    Ok(import_by_index)
}

#[derive(Debug)]
struct RelocTarget {
    relative_address: u64,
    relocated_address: u64,
    delta: i64,
    target_section_index: Option<SectionIndex>,
}

fn get_relocation_target(
    elf: &Elf,
    relocation_for_section: &HashMap<SectionIndex, i64>,
    relocation: &object::read::Relocation,
) -> Result<RelocTarget, ProgramFromElfError> {
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
            Ok(RelocTarget {
                relative_address: 0,
                relocated_address: relocation.addend() as u64,
                delta: 0,
                target_section_index: None,
            })
        }
        object::RelocationTarget::Symbol(target_symbol_index) => {
            let target_symbol = elf
                .symbol_by_index(target_symbol_index)
                .map_err(|error| ProgramFromElfError::other(format!("failed to fetch relocation target: {}", error)))?;
            let target_section_index = match target_symbol.section() {
                object::read::SymbolSection::Section(section_index) => section_index,
                section => {
                    return Err(ProgramFromElfError::other(format!(
                        "relocation refers to a symbol in an unhandled section: {:?}",
                        section
                    )));
                }
            };

            let target_section = elf
                .section_by_index(target_section_index)
                .expect("target section for relocation was not found");

            let delta = match relocation_for_section.get(&target_section_index) {
                Some(delta) => *delta,
                None => {
                    let section = elf.section_by_index(target_section_index)?;
                    return Err(ProgramFromElfError::other(format!(
                        "relocation targets unsupported section: {}",
                        section.name()?
                    )));
                }
            };

            let original_address = target_symbol.address();
            let relocated_address = (original_address as i64).wrapping_add(relocation.addend()).wrapping_add(delta) as u64;

            log::trace!(
                "Fetched relocation target: target section = \"{}\", target symbol = \"{}\" ({}), delta = {:08x}, addend = 0x{:x}, symbol address = 0x{:08x}, relocated = 0x{:08x}",
                elf.section_by_index(target_section_index)?.name()?,
                target_symbol.name()?,
                target_symbol_index.0,
                delta,
                relocation.addend(),
                original_address,
                relocated_address,
            );

            Ok(RelocTarget {
                relative_address: original_address - target_section.address(),
                relocated_address,
                delta,
                target_section_index: Some(target_section_index),
            })
        }
        _ => Err(ProgramFromElfError::other(format!(
            "unsupported target for relocation: {:?}",
            relocation
        ))),
    }
}

fn parse_text_section(
    data: &[u8],
    section_text: &ElfSection,
    import_metadata: &BTreeMap<u32, ImportMetadata>,
    relocation_for_section: &HashMap<SectionIndex, i64>,
    instruction_overrides: &mut HashMap<u64, Inst>,
    output: &mut Vec<(AddressRange, InstExt)>,
) -> Result<(), ProgramFromElfError> {
    let hostcall_by_hash: HashMap<[u8; 16], u32> = import_metadata.iter().map(|(index, metadata)| (metadata.hash, *index)).collect();

    let section_name = section_text.name().expect("failed to get section name");
    let text_range = get_section_range(data, section_text)?;
    let text = &data[text_range];

    if text.len() % 4 != 0 {
        return Err(ProgramFromElfError::other(format!(
            "size of section '{section_name}' is not divisible by 4"
        )));
    }

    let section_relocation_delta = *relocation_for_section
        .get(&section_text.index())
        .ok_or_else(|| ProgramFromElfError::other(format!("internal error: no relocation offset for section '{}'", section_name)))?;

    let relocated_base = section_text.address().wrapping_add(section_relocation_delta as u64);

    output.reserve(text.len() / 4);
    let mut relative_offset = 0;
    while relative_offset < text.len() {
        let op = u32::from_le_bytes([
            text[relative_offset],
            text[relative_offset + 1],
            text[relative_offset + 2],
            text[relative_offset + 3],
        ]);

        if op == INSTRUCTION_ECALLI {
            let initial_offset = relative_offset as u64;
            if relative_offset + 24 < text.len() {
                return Err(ProgramFromElfError::other("truncated ecalli instruction"));
            }

            relative_offset += 4;

            let h = &text[relative_offset..relative_offset + 16];
            let hash = [
                h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7], h[8], h[9], h[10], h[11], h[12], h[13], h[14], h[15],
            ];
            relative_offset += 16;

            let hostcall_index = match hostcall_by_hash.get(&hash) {
                Some(index) => *index,
                None => {
                    return Err(ProgramFromElfError::other(format!(
                        "external call with a hash that doesn't match any metadata: {:?}",
                        hash
                    )));
                }
            };

            output.push((
                AddressRange::from(relocated_base + initial_offset..relocated_base + relative_offset as u64),
                InstExt::Basic(BasicInst::Ecalli { syscall: hostcall_index }),
            ));

            const INST_RET: Inst = Inst::JumpAndLinkRegister {
                dst: Reg::Zero,
                base: Reg::RA,
                value: 0,
            };

            let op = u32::from_le_bytes([
                text[relative_offset],
                text[relative_offset + 1],
                text[relative_offset + 2],
                text[relative_offset + 3],
            ]);

            if Inst::decode(op) != Some(INST_RET) {
                return Err(ProgramFromElfError::other("external call shim doesn't end with a 'ret'"));
            }

            output.push((
                AddressRange::from(relocated_base + relative_offset as u64..relocated_base + relative_offset as u64 + 4),
                InstExt::Control(ControlInst::JumpIndirect { base: Reg::RA, offset: 0 }),
            ));

            relative_offset += 4;
            continue;
        }

        let absolute_address = section_text.address() + relative_offset as u64;
        let relocated_address = relocated_base + relative_offset as u64;
        relative_offset += 4;

        // Shadow the `relative_offset` to make sure it's not accidentally used again.
        #[allow(clippy::let_unit_value)]
        #[allow(unused_variables)]
        let relative_offset = ();

        let op = match Inst::decode(op) {
            Some(op) => instruction_overrides.remove(&absolute_address).unwrap_or(op),
            None => {
                return Err(ProgramFromElfErrorKind::UnsupportedInstruction {
                    pc: absolute_address,
                    instruction: op,
                }
                .into());
            }
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

        let op = match op {
            Inst::LoadUpperImmediate { dst, value } => InstExt::Basic(BasicInst::RegImm {
                kind: RegImmKind::Add,
                dst,
                src: Reg::Zero,
                imm: value as i32,
            }),
            Inst::JumpAndLink { dst, target } => {
                let target = (relocated_address as i64).wrapping_add(target as i32 as i64) as u64;
                let next = if dst != Reg::Zero {
                    ControlInst::Call {
                        ra: dst,
                        target,
                        return_address: relocated_address.wrapping_add(4),
                    }
                } else {
                    ControlInst::Jump { target }
                };

                InstExt::Control(next)
            }
            Inst::JumpAndLinkRegister { dst, base, value } => {
                let next = if dst != Reg::Zero {
                    ControlInst::CallIndirect {
                        ra: dst,
                        base,
                        offset: value.into(),
                        return_address: relocated_address.wrapping_add(4),
                    }
                } else {
                    ControlInst::JumpIndirect {
                        base,
                        offset: value.into(),
                    }
                };

                InstExt::Control(next)
            }
            Inst::Branch { kind, src1, src2, target } => {
                let target = (relocated_address as i64).wrapping_add(target as i32 as i64) as u64;
                let next = ControlInst::Branch {
                    kind,
                    src1,
                    src2,
                    target_true: target,
                    target_false: relocated_address.wrapping_add(4),
                };

                InstExt::Control(next)
            }
            Inst::Unimplemented => InstExt::Control(ControlInst::Unimplemented),
            Inst::Load { kind, dst, base, offset } => InstExt::Basic(BasicInst::Load { kind, dst, base, offset }),
            Inst::Store { kind, src, base, offset } => InstExt::Basic(BasicInst::Store { kind, src, base, offset }),
            Inst::RegImm { kind, dst, src, imm } => InstExt::Basic(BasicInst::RegImm { kind, dst, src, imm }),
            Inst::Shift { kind, dst, src, amount } => InstExt::Basic(BasicInst::Shift { kind, dst, src, amount }),
            Inst::RegReg { kind, dst, src1, src2 } => InstExt::Basic(BasicInst::RegReg { kind, dst, src1, src2 }),
            Inst::AddUpperImmediateToPc { .. } => {
                return Err(ProgramFromElfError::other(
                    "found an unrelocated auipc instruction; is the program compiled with relocations?",
                ));
            }
            Inst::Ecall => {
                return Err(ProgramFromElfError::other(
                    "found a bare ecall instruction; those are not supported",
                ));
            }
        };

        let source = AddressRange::from(relocated_address..relocated_address + 4);
        output.push((source, op));
    }

    Ok(())
}

fn split_code_into_basic_blocks(
    jump_targets: &HashSet<u64>,
    instructions: Vec<(AddressRange, InstExt)>,
) -> Result<Vec<BasicBlock>, ProgramFromElfError> {
    let mut blocks = Vec::new();
    let mut current_block = Vec::new();
    let mut block_start_opt = None;
    for (source, op) in instructions {
        assert!(source.start < source.end);
        let is_jump_target = jump_targets.contains(&source.start);
        let block_start = if !is_jump_target {
            // Make sure nothing wants to jump into the middle of this instruction.
            assert!((source.start..source.end)
                .step_by(4)
                .skip(1)
                .all(|address| !jump_targets.contains(&address)));

            if let Some(block_start) = block_start_opt {
                // We're in a block that's reachable by a jump.
                block_start
            } else {
                // Nothing can possibly jump here, so just skip this instruction.
                continue;
            }
        } else {
            // Control flow can jump to this instruction.
            if let Some(block_start) = block_start_opt.take() {
                // End the current basic block to prevent a jump into the middle of it.
                if !current_block.is_empty() {
                    blocks.push(BasicBlock::new(
                        (block_start..source.start).into(),
                        std::mem::take(&mut current_block),
                        EndOfBlock::Fallthrough { target: source.start },
                    ));
                }
            }

            block_start_opt = Some(source.start);
            source.start
        };

        match op {
            InstExt::Control(instruction) => {
                block_start_opt = None;
                blocks.push(BasicBlock::new(
                    (block_start..source.end).into(),
                    std::mem::take(&mut current_block),
                    EndOfBlock::Control { source, instruction },
                ));

                if let ControlInst::Branch { target_false, .. } = instruction {
                    assert_eq!(source.end, target_false);
                    block_start_opt = Some(source.end);
                }
            }
            InstExt::Basic(instruction) => {
                if instruction.is_nop() {
                    continue;
                }

                current_block.push((source, instruction));
            }
        }
    }

    if !current_block.is_empty() {
        return Err(ProgramFromElfError::other(
            "code doesn't end with a control-flow affecting instruction",
        ));
    }

    blocks.sort_unstable_by_key(|block| (block.source.start, block.source.end));
    let mut last_address = 0;
    for block in &blocks {
        if last_address > block.source.start {
            return Err(ProgramFromElfError::other("found overlapping basic blocks"));
        }
        last_address = block.source.end;
    }

    Ok(blocks)
}

fn retain_only_non_empty_functions(blocks: &[BasicBlock], functions: &mut Vec<Fn>) -> Result<(), ProgramFromElfError> {
    let iter = iterate_in_tandem(
        blocks.iter().enumerate().map(|(index, block)| (block.source, (index, block))),
        functions.iter_mut().map(|func| (func.range, func)),
    );

    for ((block_index, block), function) in iter {
        if block.source.start < function.range.start || block.source.end > function.range.end {
            return Err(ProgramFromElfError::other("found inconsistent basic block <-> function overlap"));
        }

        function.blocks.push(block_index);
    }

    let initial_length = functions.len();
    functions.retain(|func| !func.blocks.is_empty());
    log::trace!(
        "Number of functions removed due to dead code elimination: {}",
        initial_length - functions.len()
    );

    Ok(())
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

fn harvest_jump_targets(jump_targets: &mut HashSet<u64>, instructions: &[(AddressRange, InstExt)]) {
    for (source, instruction) in instructions {
        let InstExt::Control(instruction) = instruction else { continue };
        match *instruction {
            ControlInst::Jump { target, .. } => {
                jump_targets.insert(target);
            }
            ControlInst::Call {
                target, return_address, ..
            } => {
                jump_targets.insert(target);
                jump_targets.insert(return_address);
            }
            ControlInst::JumpIndirect { .. } => {}
            ControlInst::CallIndirect { return_address, .. } => {
                jump_targets.insert(return_address);
            }
            ControlInst::Branch {
                target_true, target_false, ..
            } => {
                jump_targets.insert(target_true);
                assert_eq!(target_false, source.end);
            }
            ControlInst::Unimplemented { .. } => {}
        }
    }
}

fn emit_code(jump_targets: HashSet<u64>, blocks: &[BasicBlock]) -> Result<Vec<(AddressRange, RawInstruction)>, ProgramFromElfError> {
    let mut code: Vec<(AddressRange, RawInstruction)> = Vec::new();
    {
        let mut set = HashSet::new();
        for block in blocks {
            assert!(set.insert(block.source.start), "duplicate jump target: {:x}", block.source.start);
        }
    }

    for block in blocks {
        if jump_targets.contains(&block.source.start) {
            assert_eq!(block.source.start % 4, 0);
            let Ok(target) = u32::try_from(block.source.start) else {
                return Err(ProgramFromElfError::other("basic block start address overflow"));
            };
            code.push((
                (block.source.start..block.source.start + 4).into(),
                RawInstruction::new_with_imm(Opcode::jump_target, target / 4),
            ));
        }

        for &(source, op) in &block.ops {
            let op = match op {
                BasicInst::Load { kind, dst, base, offset } => {
                    let kind = match kind {
                        LoadKind::I8 => Opcode::load_i8,
                        LoadKind::I16 => Opcode::load_i16,
                        LoadKind::U32 => Opcode::load_u32,
                        LoadKind::U8 => Opcode::load_u8,
                        LoadKind::U16 => Opcode::load_u16,
                    };
                    RawInstruction::new_with_regs2_imm(kind, cast_reg(dst), cast_reg(base), offset as u32)
                }
                BasicInst::Store { kind, src, base, offset } => {
                    let kind = match kind {
                        StoreKind::U32 => Opcode::store_u32,
                        StoreKind::U8 => Opcode::store_u8,
                        StoreKind::U16 => Opcode::store_u16,
                    };
                    RawInstruction::new_with_regs2_imm(kind, cast_reg(src), cast_reg(base), offset as u32)
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
                BasicInst::Ecalli { syscall } => RawInstruction::new_with_imm(Opcode::ecalli, syscall),
            };

            code.push((source, op));
        }

        match block.next {
            EndOfBlock::Fallthrough { target } => {
                assert_eq!(target, block.source.end);
            }
            EndOfBlock::Control {
                source,
                instruction: ControlInst::Jump { target },
            } => {
                if target % 4 != 0 {
                    return Err(ProgramFromElfError::other("found a jump with a target that isn't aligned"));
                }
                let Ok(target) = u32::try_from(target) else {
                    return Err(ProgramFromElfError::other("jump target address overflow"));
                };

                code.push((
                    source,
                    RawInstruction::new_with_regs2_imm(
                        Opcode::jump_and_link_register,
                        cast_reg(Reg::Zero),
                        cast_reg(Reg::Zero),
                        target / 4,
                    ),
                ));
            }
            EndOfBlock::Control {
                source,
                instruction:
                    ControlInst::Call {
                        ra,
                        target,
                        return_address,
                    },
            } => {
                if target % 4 != 0 {
                    return Err(ProgramFromElfError::other("found a call with a target that isn't aligned"));
                }

                let Ok(target) = u32::try_from(target) else {
                    return Err(ProgramFromElfError::other("call target address overflow"));
                };

                code.push((
                    source,
                    RawInstruction::new_with_regs2_imm(Opcode::jump_and_link_register, cast_reg(ra), cast_reg(Reg::Zero), target / 4),
                ));
                assert_eq!(return_address, block.source.end);
            }
            EndOfBlock::Control {
                source,
                instruction: ControlInst::JumpIndirect { base, offset },
            } => {
                if offset % 4 != 0 {
                    return Err(ProgramFromElfError::other(
                        "found an indirect jump with a target that isn't aligned",
                    ));
                }

                code.push((
                    source,
                    RawInstruction::new_with_regs2_imm(
                        Opcode::jump_and_link_register,
                        cast_reg(Reg::Zero),
                        cast_reg(base),
                        offset as u32 / 4,
                    ),
                ));
            }
            EndOfBlock::Control {
                source,
                instruction:
                    ControlInst::CallIndirect {
                        ra,
                        base,
                        offset,
                        return_address,
                    },
            } => {
                if offset % 4 != 0 {
                    return Err(ProgramFromElfError::other(
                        "found an indirect call with a target that isn't aligned",
                    ));
                }
                code.push((
                    source,
                    RawInstruction::new_with_regs2_imm(Opcode::jump_and_link_register, cast_reg(ra), cast_reg(base), offset as u32 / 4),
                ));
                assert_eq!(return_address, block.source.end);
            }
            EndOfBlock::Control {
                source,
                instruction:
                    ControlInst::Branch {
                        kind,
                        src1,
                        src2,
                        target_true,
                        target_false,
                    },
            } => {
                if target_true % 4 != 0 {
                    return Err(ProgramFromElfError::other("found a branch with a target that isn't aligned"));
                }

                let Ok(target_true) = u32::try_from(target_true) else {
                    return Err(ProgramFromElfError::other("branch target address overflow"));
                };

                let kind = match kind {
                    BranchKind::Eq => Opcode::branch_eq,
                    BranchKind::NotEq => Opcode::branch_not_eq,
                    BranchKind::LessSigned => Opcode::branch_less_signed,
                    BranchKind::GreaterOrEqualSigned => Opcode::branch_greater_or_equal_signed,
                    BranchKind::LessUnsigned => Opcode::branch_less_unsigned,
                    BranchKind::GreaterOrEqualUnsigned => Opcode::branch_greater_or_equal_unsigned,
                };
                code.push((
                    source,
                    RawInstruction::new_with_regs2_imm(kind, cast_reg(src1), cast_reg(src2), target_true / 4),
                ));
                assert_eq!(target_false, block.source.end);
            }
            EndOfBlock::Control {
                source,
                instruction: ControlInst::Unimplemented,
            } => {
                code.push((source, RawInstruction::new_argless(Opcode::trap)));
            }
        }
    }

    Ok(code)
}

#[derive(Copy, Clone)]
enum HiRelocKind {
    PcRel,
    Got,
}

impl core::fmt::Display for HiRelocKind {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            HiRelocKind::PcRel => fmt.write_str(".rela"),
            HiRelocKind::Got => fmt.write_str(".got"),
        }
    }
}

#[derive(Default)]
struct RelocPairs {
    reloc_pcrel_hi20: HashMap<u64, (HiRelocKind, u64)>,
    reloc_pcrel_lo12: HashMap<u64, u64>,
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

#[allow(clippy::too_many_arguments)]
fn relocate(
    elf: &Elf,
    sections_text_indexes: &HashSet<SectionIndex>,
    sections_text: &[&ElfSection],
    section_got: Option<&ElfSection>,
    relocation_for_section: &HashMap<SectionIndex, i64>,
    section: &ElfSection,
    data: &mut [u8],
    mut jump_targets: Option<&mut HashSet<u64>>,
    instruction_overrides: &mut HashMap<u64, Inst>,
) -> Result<(), ProgramFromElfError> {
    if section.relocations().next().is_none() {
        return Ok(());
    }

    let mut pairs_for_section: HashMap<SectionIndex, RelocPairs> = Default::default();

    let section_name = section.name()?;
    log::trace!("Relocating section: {}", section_name);

    let section_relocation_delta = *relocation_for_section
        .get(&section.index())
        .ok_or_else(|| ProgramFromElfError::other(format!("internal error: no relocation offset for section '{}'", section_name)))?;
    let section_range = section.file_range().unwrap_or((0, 0));
    for (absolute_address, relocation) in section.relocations() {
        let section_data = &mut data[section_range.0 as usize..][..section_range.1 as usize];

        if absolute_address < section.address() {
            return Err(ProgramFromElfError::other("invalid relocation offset"));
        }

        if relocation.has_implicit_addend() {
            // AFAIK these should never be emitted for RISC-V.
            return Err(ProgramFromElfError::other(format!("unsupported relocation: {:?}", relocation)));
        }

        let relative_address = absolute_address - section.address();
        let relocated_address = absolute_address.wrapping_add(section_relocation_delta as u64);
        let target = get_relocation_target(elf, relocation_for_section, &relocation)?;

        let source_section_is_text = sections_text_indexes.contains(&section.index());
        let target_section_is_text = target
            .target_section_index
            .map(|index| sections_text_indexes.contains(&index))
            .unwrap_or(false);
        if !source_section_is_text && target_section_is_text {
            if let Some(jump_targets) = jump_targets.as_mut() {
                jump_targets.insert(target.relocated_address);
            }
        }

        match relocation.kind() {
            object::RelocationKind::Absolute => {
                match (relocation.encoding(), relocation.size()) {
                    (object::RelocationEncoding::Generic, 32) => {}
                    _ => return Err(ProgramFromElfError::other(format!("unsupported relocation: {:?}", relocation))),
                }

                log::trace!(
                    "  Absolute: {}[0x{relative_address:x}] (0x{absolute_address:x}): 0x{:x} -> 0x{:x}",
                    section_name,
                    read_u32(section_data, relative_address)?,
                    target.relocated_address as u32,
                );
                write_u32(section_data, relative_address, target.relocated_address as u32)?;
            }
            object::RelocationKind::Elf(reloc_kind) => {
                // https://github.com/riscv-non-isa/riscv-elf-psabi-doc/releases
                match reloc_kind {
                    object::elf::R_RISCV_SUB6 => {
                        if jump_targets.is_some() {
                            return Err(ProgramFromElfError::other(
                                "found a R_RISCV_SUB6 relocation in an unexpected section",
                            ));
                        }

                        let old_value = read_u8(section_data, relative_address)?;
                        let arg = (target.delta as i8).wrapping_add(relocation.addend() as i8) as u8;
                        let new_value = (old_value & 0b1100_0000) | (old_value.wrapping_sub(arg) & 0b0011_1111);
                        section_data[relative_address as usize] = new_value;

                        log::trace!(
                            "  R_RISCV_SUB6: {}[0x{relative_address:x}] (0x{absolute_address:x}): 0x{:02x} -> 0x{:02x}",
                            section.name()?,
                            old_value,
                            new_value
                        );
                    }
                    object::elf::R_RISCV_SET6 => {
                        if jump_targets.is_some() {
                            return Err(ProgramFromElfError::other(
                                "found a R_RISCV_SET6 relocation in an unexpected section",
                            ));
                        }

                        let old_value = read_u8(section_data, relative_address)?;
                        let new_value = (old_value & 0b1100_0000) | ((target.relocated_address as u8) & 0b0011_1111);
                        section_data[relative_address as usize] = new_value;

                        log::trace!(
                            "  R_RISCV_SET6: {}[0x{relative_address:x}] (0x{absolute_address:x}): 0x{:02x} -> 0x{:02x}",
                            section.name()?,
                            old_value,
                            new_value
                        );
                    }
                    object::elf::R_RISCV_SET8 => {
                        if jump_targets.is_some() {
                            return Err(ProgramFromElfError::other(
                                "found a R_RISCV_SET8 relocation in an unexpected section",
                            ));
                        }

                        let old_value = read_u8(section_data, relative_address)?;
                        let new_value = target.relocated_address as u8;
                        section_data[relative_address as usize] = new_value;

                        log::trace!(
                            "  R_RISCV_SET8: {}[0x{relative_address:x}] (0x{absolute_address:x}): 0x{:02x} -> 0x{:02x}",
                            section.name()?,
                            old_value,
                            new_value
                        );
                    }
                    object::elf::R_RISCV_SET16 => {
                        if jump_targets.is_some() {
                            return Err(ProgramFromElfError::other(
                                "found a R_RISCV_SET16 relocation in an unexpected section",
                            ));
                        }

                        let old_value = read_u16(section_data, relative_address)?;
                        let new_value = target.relocated_address as u16;
                        write_u16(section_data, relative_address, new_value)?;

                        log::trace!(
                            "  R_RISCV_SET16: {}[0x{relative_address:x}] (0x{absolute_address:x}): 0x{:04x} -> 0x{:04x}",
                            section.name()?,
                            old_value,
                            new_value
                        );
                    }
                    object::elf::R_RISCV_ADD8 => {
                        if jump_targets.is_some() {
                            return Err(ProgramFromElfError::other(
                                "found a R_RISCV_ADD8 relocation in an unexpected section",
                            ));
                        }

                        let old_value = read_u8(section_data, relative_address)?;
                        let arg = (target.delta as i8).wrapping_add(relocation.addend() as i8);
                        let new_value = (old_value as i8).wrapping_add(arg) as u8;
                        section_data[relative_address as usize] = new_value;

                        log::trace!(
                            "  R_RISCV_ADD8: {}[0x{relative_address:x}] (0x{absolute_address:x}): 0x{:02x} -> 0x{:02x}",
                            section.name()?,
                            old_value,
                            new_value
                        );
                    }
                    object::elf::R_RISCV_SUB8 => {
                        if jump_targets.is_some() {
                            return Err(ProgramFromElfError::other(
                                "found a R_RISCV_SUB8 relocation in an unexpected section",
                            ));
                        }

                        let old_value = read_u8(section_data, relative_address)?;
                        let arg = (target.delta as i8).wrapping_add(relocation.addend() as i8);
                        let new_value = (old_value as i8).wrapping_sub(arg) as u8;
                        section_data[relative_address as usize] = new_value;

                        log::trace!(
                            "  R_RISCV_SUB8: {}[0x{relative_address:x}] (0x{absolute_address:x}): 0x{:02x} -> 0x{:02x}",
                            section.name()?,
                            old_value,
                            new_value
                        );
                    }
                    object::elf::R_RISCV_ADD16 => {
                        if jump_targets.is_some() {
                            return Err(ProgramFromElfError::other(
                                "found a R_RISCV_ADD16 relocation in an unexpected section",
                            ));
                        }

                        let old_value = read_u16(section_data, relative_address)?;
                        let arg = (target.delta as i16).wrapping_add(relocation.addend() as i16);
                        let new_value = (old_value as i16).wrapping_add(arg) as u16;
                        write_u16(section_data, relative_address, new_value)?;

                        log::trace!(
                            "  R_RISCV_ADD16: {}[0x{relative_address:x}] (0x{absolute_address:x}): 0x{:04x} -> 0x{:04x}",
                            section.name()?,
                            old_value,
                            new_value
                        );
                    }
                    object::elf::R_RISCV_SUB16 => {
                        if jump_targets.is_some() {
                            return Err(ProgramFromElfError::other(
                                "found a R_RISCV_SUB16 relocation in an unexpected section",
                            ));
                        }

                        let old_value = read_u16(section_data, relative_address)?;
                        let arg = (target.delta as i16).wrapping_add(relocation.addend() as i16);
                        let new_value = (old_value as i16).wrapping_sub(arg) as u16;
                        write_u16(section_data, relative_address, new_value)?;

                        log::trace!(
                            "  R_RISCV_SUB16: {}[0x{relative_address:x}] (0x{absolute_address:x}): 0x{:04x} -> 0x{:04x}",
                            section.name()?,
                            old_value,
                            new_value
                        );
                    }
                    object::elf::R_RISCV_ADD32 => {
                        let old_value = read_u32(section_data, relative_address)?;
                        let arg = (target.delta as i32).wrapping_add(relocation.addend() as i32);
                        let new_value = (old_value as i32).wrapping_add(arg) as u32;
                        write_u32(section_data, relative_address, new_value)?;

                        log::trace!(
                            "  R_RISCV_ADD32: {}[0x{relative_address:x}] (0x{absolute_address:x}): 0x{:08x} -> 0x{:08x}",
                            section.name()?,
                            old_value,
                            new_value
                        );
                    }
                    object::elf::R_RISCV_SUB32 => {
                        let old_value = read_u32(section_data, relative_address)?;
                        let arg = (target.delta as i32).wrapping_add(relocation.addend() as i32);
                        let new_value = (old_value as i32).wrapping_sub(arg) as u32;
                        write_u32(section_data, relative_address, new_value)?;

                        log::trace!(
                            "  R_RISCV_SUB32: {}[0x{relative_address:x}] (0x{absolute_address:x}): 0x{:08x} -> 0x{:08x}",
                            section.name()?,
                            old_value,
                            new_value
                        );
                    }
                    object::elf::R_RISCV_CALL_PLT => {
                        // This relocation is for a pair of instructions, namely AUIPC + JALR, where we're allowed to delete the AUIPC if it's unnecessary.
                        if !sections_text_indexes.contains(&section.index()) {
                            return Err(ProgramFromElfError::other(format!(
                                "found a R_RISCV_CALL_PLT relocation in an unexpected section: '{}'",
                                section.name()?
                            )));
                        };

                        let data_text = get_section_data(data, section)?;
                        let Some(xs) = data_text.get(relative_address as usize..relative_address as usize + 8) else {
                            return Err(ProgramFromElfError::other("invalid R_RISCV_CALL_PLT relocation"));
                        };

                        let hi_inst_raw = u32::from_le_bytes([xs[0], xs[1], xs[2], xs[3]]);
                        let Some(hi_inst) = Inst::decode(hi_inst_raw) else {
                            return Err(ProgramFromElfError::other(format!(
                                "R_RISCV_CALL_PLT for an unsupported instruction (1st): 0x{hi_inst_raw:08}"
                            )));
                        };

                        let lo_inst_raw = u32::from_le_bytes([xs[4], xs[5], xs[6], xs[7]]);
                        let Some(lo_inst) = Inst::decode(lo_inst_raw) else {
                            return Err(ProgramFromElfError::other(format!(
                                "R_RISCV_CALL_PLT for an unsupported instruction (2st): 0x{lo_inst_raw:08}"
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
                                "R_RISCV_CALL_PLT for an unsupported instruction (2st): 0x{lo_inst_raw:08} ({lo_inst:?})"
                            )));
                        };

                        if hi_reg != lo_reg {
                            return Err(ProgramFromElfError::other(
                                "R_RISCV_CALL_PLT for a pair of instructions with different destination registers",
                            ));
                        }

                        let new_target = (target.relocated_address as u32).wrapping_sub(relocated_address as u32 + 4);

                        instruction_overrides.insert(
                            absolute_address,
                            Inst::RegImm {
                                kind: RegImmKind::Add,
                                dst: Reg::Zero,
                                src: Reg::Zero,
                                imm: 0,
                            },
                        );
                        instruction_overrides.insert(
                            absolute_address + 4,
                            Inst::JumpAndLink {
                                dst: lo_dst,
                                target: new_target,
                            },
                        );

                        log::trace!(
                            "  R_RISCV_CALL_PLT: {}[0x{relative_address:x}] (0x{absolute_address:x}): -> 0x{:08x}",
                            section.name()?,
                            target.relocated_address
                        );
                    }
                    object::elf::R_RISCV_PCREL_HI20 => {
                        // This relocation is for an AUIPC.

                        if !sections_text_indexes.contains(&section.index()) {
                            return Err(ProgramFromElfError::other(format!(
                                "found a R_RISCV_PCREL_HI20 relocation in an unexpected section: '{}'",
                                section.name()?
                            )));
                        }

                        let p = pairs_for_section.entry(section.index()).or_insert_with(Default::default);
                        p.reloc_pcrel_hi20
                            .insert(relative_address, (HiRelocKind::PcRel, target.relocated_address));
                        log::trace!(
                            "  R_RISCV_PCREL_HI20: {}[0x{relative_address:x}] (0x{absolute_address:x}): -> 0x{:08x}",
                            section.name()?,
                            target.relocated_address
                        );
                    }
                    object::elf::R_RISCV_GOT_HI20 => {
                        if !sections_text_indexes.contains(&section.index()) {
                            return Err(ProgramFromElfError::other(format!(
                                "found a R_RISCV_GOT_HI20 relocation in an unexpected section: '{}'",
                                section.name()?
                            )));
                        };

                        let p = pairs_for_section.entry(section.index()).or_insert_with(Default::default);
                        p.reloc_pcrel_hi20
                            .insert(relative_address, (HiRelocKind::Got, target.relocated_address));
                        log::trace!(
                            "  R_RISCV_GOT_HI20: {}[0x{relative_address:x}] (0x{absolute_address:x}): -> 0x{:08x}",
                            section.name()?,
                            target.relocated_address
                        );
                    }
                    object::elf::R_RISCV_PCREL_LO12_I => {
                        if !sections_text_indexes.contains(&section.index()) {
                            return Err(ProgramFromElfError::other(format!(
                                "found a R_RISCV_PCREL_LO12_I relocation in an unexpected section: '{}'",
                                section.name()?
                            )));
                        };

                        if !target_section_is_text {
                            return Err(ProgramFromElfError::other(
                                "R_RISCV_PCREL_LO12_I relocation points to a non '.text' section",
                            ));
                        }

                        let p = pairs_for_section.entry(section.index()).or_insert_with(Default::default);
                        p.reloc_pcrel_lo12.insert(relative_address, target.relative_address);
                        log::trace!(
                            "  R_RISCV_PCREL_LO12_I: {}[0x{relative_address:x}] (0x{absolute_address:x}): -> 0x{:08x}",
                            section.name()?,
                            target.relocated_address
                        );
                    }
                    object::elf::R_RISCV_PCREL_LO12_S => {
                        if !sections_text_indexes.contains(&section.index()) {
                            return Err(ProgramFromElfError::other(format!(
                                "found a R_RISCV_PCREL_LO12_S relocation in an unexpected section: '{}'",
                                section.name()?
                            )));
                        };

                        if !target_section_is_text {
                            return Err(ProgramFromElfError::other(
                                "R_RISCV_PCREL_LO12_S relocation points to a non '.text' section",
                            ));
                        }

                        let p = pairs_for_section.entry(section.index()).or_insert_with(Default::default);
                        p.reloc_pcrel_lo12.insert(relative_address, target.relative_address);
                        log::trace!(
                            "  R_RISCV_PCREL_LO12_S: {}[0x{relative_address:x}] (0x{absolute_address:x}): -> 0x{:08x}",
                            section.name()?,
                            target.relocated_address
                        );
                    }
                    _ => {
                        return Err(ProgramFromElfError::other(format!(
                            "unsupported relocation type in section '{}': 0x{:08x}",
                            section.name()?,
                            reloc_kind
                        )));
                    }
                }
            }
            _ => {
                return Err(ProgramFromElfError::other(format!(
                    "unsupported relocation in section '{}': {:?}",
                    section.name()?,
                    relocation
                )))
            }
        }
    }

    for (section_index, pairs) in pairs_for_section {
        let section_text = sections_text.iter().find(|section| section.index() == section_index).unwrap();
        process_pcrel_pairs(
            data,
            section_got,
            section_text,
            pairs,
            relocation_for_section,
            instruction_overrides,
        )?;
    }

    Ok(())
}

fn process_pcrel_pairs(
    data: &mut [u8],
    section_got: Option<&ElfSection>,
    section_text: &ElfSection,
    pairs: RelocPairs,
    relocation_for_section: &HashMap<SectionIndex, i64>,
    instruction_overrides: &mut HashMap<u64, Inst>,
) -> Result<(), ProgramFromElfError> {
    let text_range = get_section_range(data, section_text)?;
    for (relative_lo, relative_hi) in pairs.reloc_pcrel_lo12 {
        let data_text = &mut data[text_range.clone()];
        let lo_inst_raw = &data_text[relative_lo as usize..][..4];
        let mut lo_inst = Inst::decode(u32::from_le_bytes([lo_inst_raw[0], lo_inst_raw[1], lo_inst_raw[2], lo_inst_raw[3]]));
        let hi_inst_raw = &data_text[relative_hi as usize..][..4];
        let hi_inst = Inst::decode(u32::from_le_bytes([hi_inst_raw[0], hi_inst_raw[1], hi_inst_raw[2], hi_inst_raw[3]]));

        let Some((hi_kind, target_address)) = pairs.reloc_pcrel_hi20.get(&relative_hi).copied() else {
            return Err(ProgramFromElfError::other(format!("R_RISCV_PCREL_LO12_* relocation at 0x{relative_lo:x} targets 0x{relative_hi:x} which doesn't have a R_RISCV_PCREL_HI20/R_RISCV_GOT_HI20 relocation")));
        };

        let target_address = u32::try_from(target_address).expect("R_RISCV_PCREL_HI20/R_RISCV_GOT_HI20 target address overflow");

        let (hi_reg, hi_value) = match hi_inst {
            Some(Inst::AddUpperImmediateToPc { dst, value }) => (dst, value),
            _ => {
                return Err(ProgramFromElfError::other(format!("R_RISCV_PCREL_HI20/R_RISCV_GOT_HI20 relocation for an unsupported instruction at .text[0x{relative_hi:x}]: {hi_inst:?}")));
            }
        };

        let (lo_reg, lo_value) = match lo_inst {
            Some(Inst::RegImm {
                kind: RegImmKind::Add,
                ref mut src,
                ref mut imm,
                ..
            }) => (src, imm),
            Some(Inst::Load {
                ref mut base,
                ref mut offset,
                ..
            }) => (base, offset),
            Some(Inst::Store {
                ref mut base,
                ref mut offset,
                ..
            }) => (base, offset),
            _ => {
                return Err(ProgramFromElfError::other(format!(
                    "R_RISCV_PCREL_LO12_* relocation for an unsupported instruction: {lo_inst:?}"
                )));
            }
        };

        if *lo_reg != hi_reg {
            return Err(ProgramFromElfError::other(
                "HI + LO relocation pair uses a different destination register",
            ));
        }

        let old_lo_value = *lo_value;
        let hi_original = section_text.address().wrapping_add(relative_hi);
        let old_merged = hi_original.wrapping_add(hi_value as u64).wrapping_add(old_lo_value as u32 as u64) as u32;
        let new_merged;

        if matches!(hi_kind, HiRelocKind::Got) {
            // For these relocations the target address still points to the symbol that the code wants to reference,
            // but the actual address that's in the code shouldn't point to the symbol directly, but to a place where
            // the symbol's address can be found.

            let Some(section_got) = section_got else {
                return Err(ProgramFromElfError::other(
                    "found a R_RISCV_GOT_HI20 relocation but no '.got' section",
                ));
            };

            // First make sure the '.got' section itself is relocated.
            let got_delta = *relocation_for_section
                .get(&section_got.index())
                .expect("internal error: no relocation offset for the '.got' section");
            let old_got_address = old_merged;
            let new_got_address = (old_got_address as i64).wrapping_add(got_delta) as u64;
            new_merged = new_got_address as u32;

            // And then fix the address inside of the GOT table itself.
            let relative_got_offset = old_got_address as u64 - section_got.address();

            let section_got_range = section_got.file_range().unwrap_or((0, 0));
            let section_got_data = &mut data[section_got_range.0 as usize..][..section_got_range.1 as usize];
            let old_target_address = read_u32(section_got_data, relative_got_offset)?;
            write_u32(section_got_data, relative_got_offset, target_address)?;

            log::trace!(
                "  (GOT): {}[0x{relative_got_offset:x}] (0x{old_got_address:x}): 0x{:08x} -> 0x{:08x}",
                section_got.name()?,
                old_target_address,
                target_address
            );
        } else {
            new_merged = target_address;
        }

        *lo_value = new_merged as i32;
        *lo_reg = Reg::Zero;

        // Since we support full length immediates just turn the upper instructions into a NOP.
        instruction_overrides.insert(
            section_text.address() + relative_hi,
            Inst::RegImm {
                kind: RegImmKind::Add,
                dst: Reg::Zero,
                src: Reg::Zero,
                imm: 0,
            },
        );
        instruction_overrides.insert(section_text.address() + relative_lo, lo_inst.unwrap());

        log::trace!("Replaced and merged 0x{hi_original:08x} (pc) + 0x{hi_value:08x} (hi) + 0x{old_lo_value:08x} (lo) = 0x{old_merged:08x} to point to 0x{new_merged:08x} (from {hi_kind}, 0x{relative_hi:x} (rel hi), 0x{relative_lo:x} (rel lo))");
    }

    Ok(())
}

fn parse_symbols<'a>(elf: &'a Elf, relocation_for_section: &HashMap<SectionIndex, i64>) -> Result<Vec<Fn<'a>>, ProgramFromElfError> {
    let mut functions = Vec::new();
    for sym in elf.symbols() {
        let kind = sym.raw_symbol().st_type();
        match kind {
            object::elf::STT_FUNC => {
                let section_index = sym.section().index().ok_or_else(|| {
                    ProgramFromElfError::other(format!(
                        "failed to process symbol table: symbol is for unsupported section: {:?}",
                        sym.section()
                    ))
                })?;

                let section = elf.section_by_index(section_index).map_err(|error| {
                    ProgramFromElfError::other(format!("failed to process symbol table: failed to fetch section: {}", error))
                })?;

                let section_relocation_delta = *relocation_for_section.get(&section_index).ok_or_else(|| {
                    ProgramFromElfError::other(format!(
                        "failed to process symbol table: no relocation offset for section {:?}",
                        section.name().ok()
                    ))
                })?;

                let name = sym.name()?;
                let name = if name.is_empty() { None } else { Some(name) };

                let relocated_address = sym.address().wrapping_add(section_relocation_delta as u64);
                functions.push(Fn {
                    name,
                    range: (relocated_address..relocated_address + sym.size()).into(),
                    frames: Vec::new(),
                    blocks: Vec::new(),
                });
            }
            object::elf::STT_NOTYPE | object::elf::STT_OBJECT | object::elf::STT_SECTION | object::elf::STT_FILE => {}
            _ => return Err(ProgramFromElfError::other(format!("unsupported symbol type: {}", kind))),
        }
    }

    functions.sort_unstable_by_key(|func| (func.range.start, func.range.end));
    functions.dedup_by_key(|func| func.range);

    Ok(functions)
}

fn iterate_in_tandem<T, U>(
    iter_1: impl IntoIterator<Item = (AddressRange, T)>,
    iter_2: impl IntoIterator<Item = (AddressRange, U)>,
) -> impl Iterator<Item = (T, U)> {
    struct Iter<T, U, TI, UI>
    where
        TI: Iterator<Item = (AddressRange, T)>,
        UI: Iterator<Item = (AddressRange, U)>,
    {
        iter_1: core::iter::Peekable<TI>,
        iter_2: core::iter::Peekable<UI>,
    }

    impl<T, U, TI, UI> Iterator for Iter<T, U, TI, UI>
    where
        TI: Iterator<Item = (AddressRange, T)>,
        UI: Iterator<Item = (AddressRange, U)>,
    {
        type Item = (T, U);
        fn next(&mut self) -> Option<Self::Item> {
            loop {
                let (range_1, _) = self.iter_1.peek()?;
                let (range_2, _) = self.iter_2.peek()?;

                use core::cmp::Ordering;
                match range_1.start.cmp(&range_2.start) {
                    Ordering::Less => {
                        if range_1.end > range_2.start {
                            // There is overlap.
                            break;
                        } else {
                            self.iter_1.next();
                            continue;
                        }
                    }
                    Ordering::Greater => {
                        self.iter_2.next();
                        continue;
                    }
                    Ordering::Equal => break,
                }
            }

            let (_, value_1) = self.iter_1.next().unwrap();
            let (_, value_2) = self.iter_2.next().unwrap();

            Some((value_1, value_2))
        }
    }

    Iter {
        iter_1: iter_1.into_iter().peekable(),
        iter_2: iter_2.into_iter().peekable(),
    }
}

#[allow(clippy::single_range_in_vec_init)]
#[test]
fn test_iterate_in_tandem() {
    fn overlaps(first: impl IntoIterator<Item = Range<u64>>, second: impl IntoIterator<Item = Range<u64>>) -> Vec<(usize, usize)> {
        let first: Vec<_> = first
            .into_iter()
            .map(AddressRange::from)
            .enumerate()
            .map(|(index, range)| (range, index))
            .collect();
        let second: Vec<_> = second
            .into_iter()
            .map(AddressRange::from)
            .enumerate()
            .map(|(index, range)| (range, index))
            .collect();
        iterate_in_tandem(first, second).collect()
    }

    assert_eq!(overlaps([], []), vec![]);
    assert_eq!(overlaps([0..4], [4..8]), vec![]);
    assert_eq!(overlaps([0..5], [4..8]), vec![(0, 0)]);
    assert_eq!(overlaps([0..4], [3..8]), vec![(0, 0)]);
    assert_eq!(overlaps([0..1, 1..2, 2..3], [1..2]), vec![(1, 0)]);
    assert_eq!(overlaps([1..2], [0..1, 1..2, 2..3]), vec![(0, 1)]);
}

fn merge_functions_with_dwarf(functions: &mut [Fn], dwarf_info: DwarfInfo) -> Result<(), ProgramFromElfError> {
    let iter = iterate_in_tandem(
        functions.iter_mut().map(|func| (func.range, func)),
        dwarf_info.frames.into_iter().map(|dwarf| {
            let range: AddressRange = (dwarf.0..dwarf.1).into();
            (range, (range, dwarf.2))
        }),
    );

    for (function, (dwarf_range, frames)) in iter {
        if function.range != dwarf_range {
            return Err(ProgramFromElfError::other(
                "a function defined in DWARF info has inconsistent bounds with the same function in the symbol table",
            ));
        }

        function.frames = frames;
    }

    Ok(())
}

#[derive(Default)]
pub struct Config {
    _private: (),
}

fn get_section_range(data: &[u8], section: &ElfSection) -> Result<Range<usize>, ProgramFromElfError> {
    let name = section.name()?;
    let section_range = section.file_range().unwrap_or((0, 0));
    let section_start =
        usize::try_from(section_range.0).map_err(|_| ProgramFromElfError::other(format!("out of range offset for '{name}' section")))?;
    let section_size =
        usize::try_from(section_range.1).map_err(|_| ProgramFromElfError::other(format!("out of range size for '{name}' section")))?;
    let section_end = section_start
        .checked_add(section_size)
        .ok_or_else(|| ProgramFromElfError::other(format!("out of range '{name}' section (overflow)")))?;
    data.get(section_start..section_end)
        .ok_or_else(|| ProgramFromElfError::other(format!("out of range '{name}' section (out of bounds of ELF file)")))?;
    Ok(section_start..section_end)
}

fn get_section_data<'a>(data: &'a [u8], section: &ElfSection) -> Result<&'a [u8], ProgramFromElfError> {
    Ok(&data[get_section_range(data, section)?])
}

pub fn program_from_elf(_config: Config, data: &[u8]) -> Result<ProgramBlob, ProgramFromElfError> {
    let elf = Elf::parse(data)?;

    if elf.raw_header().e_ident.data != object::elf::ELFDATA2LSB {
        return Err(ProgramFromElfError::other("file is not a little endian ELF file"));
    }

    if elf.raw_header().e_ident.os_abi != object::elf::ELFOSABI_SYSV {
        return Err(ProgramFromElfError::other("file doesn't use the System V ABI"));
    }

    if !matches!(
        elf.raw_header().e_type.get(LittleEndian),
        object::elf::ET_EXEC | object::elf::ET_REL
    ) {
        return Err(ProgramFromElfError::other("file is not a supported ELF file (ET_EXEC or ET_REL)"));
    }

    if elf.raw_header().e_machine.get(LittleEndian) != object::elf::EM_RISCV {
        return Err(ProgramFromElfError::other("file is not a RISC-V file (EM_RISCV)"));
    }

    let mut sections_ro_data = Vec::new();
    let mut sections_rw_data = Vec::new();
    let mut sections_bss = Vec::new();
    let mut sections_text = Vec::new();
    let mut section_got = None;
    let mut section_import_metadata = None;
    let mut section_export_metadata = None;

    // Relocate code to 0x00000004.
    let mut text_end = 0x00000004;

    let mut relocation_for_section = HashMap::new();
    let sections: Vec<_> = elf.sections().collect();
    for section in &sections {
        // Make sure the data is accessible.
        get_section_data(data, section)?;

        let flags = match section.flags() {
            object::SectionFlags::Elf { sh_flags } => sh_flags,
            _ => unreachable!(),
        };

        let is_writable = flags & object::elf::SHF_WRITE as u64 != 0;
        let name = section.name()?;
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

            if name == ".got" {
                section_got = Some(section);
            }

            sections_ro_data.push(section);
        } else if name == ".data" || name.starts_with(".data.") || name == ".sdata" || name.starts_with(".sdata.") {
            if !is_writable {
                return Err(ProgramFromElfError::other(format!(
                    "expected section '{name}' to be writable, yet it is read-only"
                )));
            }

            sections_rw_data.push(section);
        } else if name == ".bss" || name.starts_with(".bss.") || name == ".sbss" || name.starts_with(".sbss.") {
            if !is_writable {
                return Err(ProgramFromElfError::other(format!(
                    "expected section '{name}' to be writable, yet it is read-only"
                )));
            }

            sections_bss.push(section);
        } else if name == ".text" || name.starts_with(".text.") {
            if is_writable {
                return Err(ProgramFromElfError::other(format!(
                    "expected section '{name}' to be read-only, yet it is writable"
                )));
            }

            if let Some(padding) = get_padding(text_end, section) {
                text_end += padding;
            }

            #[allow(clippy::neg_multiply)]
            relocation_for_section.insert(section.index(), (section.address() as i64 * -1).wrapping_add(text_end as i64));
            text_end += section.size();

            sections_text.push(section);
        } else {
            match name {
                ".polkavm_imports" => section_import_metadata = Some(section),
                ".polkavm_exports" => {
                    relocation_for_section.insert(section.index(), 0);
                    section_export_metadata = Some(section);
                }
                _ => {
                    if name != ".eh_frame" && flags & object::elf::SHF_ALLOC as u64 != 0 {
                        // We're supposed to load this section into memory at runtime, but we don't know what it is.
                        return Err(ProgramFromElfErrorKind::UnsupportedSection(name.to_owned()).into());
                    }

                    // For sections which will not be in memory at runtime we just don't relocate them.
                    relocation_for_section.insert(section.index(), 0);
                    continue;
                }
            }
        }
    }

    if sections_text.is_empty() {
        return Err(ProgramFromElfError::other("missing '.text' section"));
    }

    let memory_config = extract_memory_config(
        data,
        &sections_ro_data,
        &sections_rw_data,
        &sections_bss,
        &mut relocation_for_section,
    )?;

    for (index, offset) in &relocation_for_section {
        if *offset == 0 {
            continue;
        }
        let section = elf.section_by_index(*index).unwrap();
        let name = section.name().unwrap();
        log::trace!("Relocation offset: '{name}': 0x{offset:x} ({offset})");
    }

    let mut jump_targets = HashSet::new();
    if let Some(section) = section_got {
        let section_range = get_section_range(data, section)?;
        if section_range.len() % 4 != 0 {
            return Err(ProgramFromElfError::other("size of the '.got' section is not divisible by 4"));
        }

        let section_data = &data[section_range];
        for (index, xs) in section_data.chunks_exact(4).enumerate() {
            let relative_address = index * 4;
            let absolute_address = section.address() + relative_address as u64;
            let target_address = u32::from_le_bytes([xs[0], xs[1], xs[2], xs[3]]) as u64;
            log::trace!("GOT entry: #{index}: .got[0x{relative_address:x}] (0x{absolute_address:08x}) = 0x{target_address:08x}");
        }
    }

    let sections_text_indexes: HashSet<_> = sections_text.iter().map(|section| section.index()).collect();

    let mut instruction_overrides = HashMap::new();
    let mut data = data.to_vec();
    for section in elf.sections() {
        if section.name().expect("failed to get section name") == ".eh_frame" {
            continue;
        }

        let is_data_section = sections_ro_data
            .iter()
            .chain(sections_rw_data.iter())
            .any(|s| s.index() == section.index());

        let jump_targets = if is_data_section {
            // If it's one of the data sections then harvest the jump targets from it.
            Some(&mut jump_targets)
        } else {
            // If it's not one of the data sections then the relocations can point to various other stuff, so don't treat those as jump targets.
            None
        };

        relocate(
            &elf,
            &sections_text_indexes,
            &sections_text,
            section_got,
            &relocation_for_section,
            &section,
            &mut data,
            jump_targets,
            &mut instruction_overrides,
        )?;
    }

    let import_metadata = if let Some(section) = section_import_metadata {
        extract_import_metadata(&data, section)?
    } else {
        Default::default()
    };

    let export_metadata = if let Some(section) = section_export_metadata {
        extract_export_metadata(&data, section)?
    } else {
        Default::default()
    };

    for export in &export_metadata {
        jump_targets.insert(export.address.into());
    }

    let dwarf = crate::dwarf::load_dwarf(&elf, &data)?;
    let mut functions = parse_symbols(&elf, &relocation_for_section)?;
    merge_functions_with_dwarf(&mut functions, dwarf)?;

    let mut instructions = Vec::new();
    for section_text in sections_text {
        parse_text_section(
            &data,
            section_text,
            &import_metadata,
            &relocation_for_section,
            &mut instruction_overrides,
            &mut instructions,
        )?;
    }

    if !instruction_overrides.is_empty() {
        return Err(ProgramFromElfError::other("internal error: instruction overrides map is not empty"));
    }

    harvest_jump_targets(&mut jump_targets, &instructions);
    let blocks = split_code_into_basic_blocks(&jump_targets, instructions)?;
    retain_only_non_empty_functions(&blocks, &mut functions)?;

    let code = emit_code(jump_targets, &blocks)?;

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
                RangeOrPadding::Range(range) => {
                    writer.push_raw_bytes(&data[range]);
                }
                RangeOrPadding::Padding(bytes) => {
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
                RangeOrPadding::Range(range) => {
                    writer.push_raw_bytes(&data[range]);
                }
                RangeOrPadding::Padding(bytes) => {
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

        writer.push_varint(import_metadata.len() as u32);
        for (index, meta) in import_metadata {
            writer.push_varint(index);
            writer.push_function_prototype(meta.prototype());
        }
    });

    writer.push_section(program::SECTION_EXPORTS, |writer| {
        if export_metadata.is_empty() {
            return;
        }

        writer.push_varint(export_metadata.len() as u32);
        for meta in export_metadata {
            assert_eq!(meta.address % 4, 0);
            writer.push_varint(meta.address / 4);
            writer.push_function_prototype(meta.prototype());
        }
    });

    let mut start_address_to_instruction_index: BTreeMap<u64, u32> = Default::default();
    let mut end_address_to_instruction_index: BTreeMap<u64, u32> = Default::default();
    writer.push_section(program::SECTION_CODE, |writer| {
        let mut buffer = [0; program::MAX_INSTRUCTION_LENGTH];
        for (nth_inst, (source, inst)) in code.into_iter().enumerate() {
            let length = inst.serialize_into(&mut buffer);
            writer.push_raw_bytes(&buffer[..length]);

            // Two or more addresses can point to the same instruction (e.g. in case of macro op fusion).
            // Two or more instructions can also have the same address (e.g. in case of jump targets).

            assert_ne!(source.start, source.end);
            for address in (source.start..source.end).step_by(4) {
                if start_address_to_instruction_index.contains_key(&address) {
                    continue;
                }

                start_address_to_instruction_index.insert(address, nth_inst.try_into().expect("instruction count overflow"));
            }
            end_address_to_instruction_index.insert(source.end, (nth_inst + 1).try_into().expect("instruction count overflow"));
        }
    });

    #[derive(Default)]
    struct DebugStringsBuilder<'a> {
        buffer: String,
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

        fn dedup_namespace(&mut self, chunks: &[impl AsRef<str>]) -> u32 {
            assert!(self.buffer.is_empty());
            for (index, chunk) in chunks.iter().enumerate() {
                if index != 0 {
                    self.buffer.push_str("::");
                }

                let chunk = chunk.as_ref();
                self.buffer.push_str(chunk);
            }

            let offset = self.dedup_cow(self.buffer.clone().into());
            self.buffer.clear();
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

    for function in &functions {
        for frame in &function.frames {
            dbg_strings.dedup_namespace(&frame.location.namespace);

            if let Some(s) = frame.location.function_name.as_ref() {
                dbg_strings.dedup(s);
            }

            if let Some(s) = frame.location.path.as_ref() {
                dbg_strings.dedup_cow(simplify_path(s));
            }

            for (_, _, _, location) in &frame.inline_frames {
                dbg_strings.dedup_namespace(&location.namespace);

                if let Some(s) = location.function_name.as_ref() {
                    dbg_strings.dedup(s);
                }

                if let Some(s) = location.path.as_ref() {
                    dbg_strings.dedup_cow(simplify_path(s));
                }
            }
        }

        if function.frames.is_empty() {
            if let Some((prefix, suffix)) = function.namespace_and_name() {
                dbg_strings.dedup_cow(prefix.into());
                dbg_strings.dedup_cow(suffix.into());
            }
        }
    }

    dbg_strings.write_protected = true;

    writer.push_section(program::SECTION_OPT_DEBUG_STRINGS, |writer| {
        writer.push_raw_bytes(&dbg_strings.section);
    });

    let mut function_ranges = Vec::with_capacity(functions.len());
    writer.push_section(program::SECTION_OPT_DEBUG_FUNCTION_INFO, |writer| {
        let offset_base = writer.len();
        writer.push_byte(program::VERSION_DEBUG_FUNCTION_INFO_V1);
        let mut last_range = AddressRange { start: 0, end: 0 };
        for function in &functions {
            assert!(function.range.start >= last_range.end || function.range == last_range);

            let info_offset: u32 = (writer.len() - offset_base).try_into().expect("function info offset overflow");

            // TODO: These should be handled more intelligently instead of panicking.
            let function_start_index = *start_address_to_instruction_index
                .get(&function.range.start)
                .expect("function start address has no matching instructions");
            let function_end_index = *end_address_to_instruction_index
                .get(&function.range.end)
                .expect("function end address has no matching instructions");

            let mut written = false;
            for frame in &function.frames {
                let Some(name_offset) = frame.location.function_name.as_ref().map(|s| dbg_strings.dedup(s)) else {
                    continue;
                };
                let namespace_offset = dbg_strings.dedup_namespace(&frame.location.namespace);
                let file_offset = frame
                    .location
                    .path
                    .as_ref()
                    .map(|s| dbg_strings.dedup_cow(simplify_path(s)))
                    .unwrap_or(empty_string_id);

                written = true;
                writer.push_varint(namespace_offset);
                writer.push_varint(name_offset);
                writer.push_varint(file_offset);
                writer.push_varint(frame.location.line.unwrap_or(0) as u32);
                writer.push_varint(frame.location.column.unwrap_or(0) as u32);
                writer.push_varint(frame.inline_frames.len().try_into().expect("function inline frames overflow"));
                for &(inline_start_address, inline_end_address, inline_depth, ref inline_location) in &frame.inline_frames {
                    let inline_name_offset = dbg_strings.dedup(inline_location.function_name.as_deref().unwrap_or(""));
                    let inline_namespace_offset = dbg_strings.dedup_namespace(&inline_location.namespace);
                    let inline_file_offset = inline_location
                        .path
                        .as_ref()
                        .map(|s| dbg_strings.dedup_cow(simplify_path(s)))
                        .unwrap_or(empty_string_id);

                    // TODO: These should be handled more intelligently instead of panicking.
                    let (&next_inline_start_address, &inline_start_index) = start_address_to_instruction_index
                        .range(inline_start_address..)
                        .next()
                        .expect("inline function start address has no matching instructions");
                    if next_inline_start_address >= inline_end_address {
                        todo!();
                    }
                    let inline_end_index = *end_address_to_instruction_index
                        .get(&inline_end_address)
                        .expect("inline function end address has no matching instructions");

                    assert!(inline_start_index <= inline_end_index);
                    assert!(inline_start_index >= function_start_index);
                    assert!(inline_end_index <= function_end_index);

                    writer.push_varint(inline_start_index - function_start_index);
                    writer.push_varint(inline_end_index - function_start_index);
                    writer.push_varint(inline_depth);
                    writer.push_varint(inline_namespace_offset);
                    writer.push_varint(inline_name_offset);
                    writer.push_varint(inline_file_offset);
                    writer.push_varint(inline_location.line.unwrap_or(0) as u32);
                    writer.push_varint(inline_location.column.unwrap_or(0) as u32);
                }
            }

            if function.frames.is_empty() {
                if let Some((prefix, suffix)) = function.namespace_and_name() {
                    written = true;
                    let prefix_id = dbg_strings.dedup_cow(prefix.into());
                    let suffix_id = dbg_strings.dedup_cow(suffix.into());
                    writer.push_varint(prefix_id);
                    writer.push_varint(suffix_id);
                    writer.push_varint(empty_string_id); // File path.
                    writer.push_varint(0); // Line.
                    writer.push_varint(0); // Column.
                    writer.push_varint(0); // Inline frame count.
                }
            }

            if written {
                function_ranges.push((function_start_index, function_end_index, info_offset));
            }

            last_range = function.range;
        }
    });

    writer.push_section(program::SECTION_OPT_DEBUG_FUNCTION_RANGES, |writer| {
        for (function_start_index, function_end_index, info_offset) in function_ranges {
            writer.push_u32(function_start_index);
            writer.push_u32(function_end_index);
            writer.push_u32(info_offset);
        }
    });

    writer.push_raw_bytes(&[program::SECTION_END_OF_FILE]);

    log::trace!("Built a program of {} bytes", writer.blob.len());
    Ok(ProgramBlob::parse(writer.blob)?)
}
