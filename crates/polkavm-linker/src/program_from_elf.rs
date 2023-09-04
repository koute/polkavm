use polkavm_common::abi::{VM_ADDR_USER_MEMORY, VM_MAXIMUM_MEMORY_SIZE, VM_PAGE_SIZE};
use polkavm_common::elf::{ExportMetadata, FnMetadata, ImportMetadata, INSTRUCTION_ECALLI};
use polkavm_common::program::Reg as PReg;
use polkavm_common::program::{self, Opcode, ProgramBlob, RawInstruction};
use polkavm_common::utils::align_to_next_page_u64;
use polkavm_common::varint;

use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::ops::Range;

use crate::riscv::{BranchKind, Inst, Reg, RegImmKind};

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

// TODO: Enable this again.
// fn is_nop(op: InstExt) -> bool {
//     match op {
//         | InstExt::Inst(Inst::LoadUpperImmediate { dst, .. })
//         | InstExt::Inst(Inst::AddUpperImmediateToPc { dst, .. })
//         | InstExt::Inst(Inst::RegImm { dst, .. })
//         | InstExt::Inst(Inst::Shift { dst, .. })
//         | InstExt::Inst(Inst::RegReg { dst, .. })
//             => dst == Reg::Zero,
//         | InstExt::Inst(Inst::JumpAndLink { .. })
//         | InstExt::Inst(Inst::JumpAndLinkRegister { .. })
//         | InstExt::Inst(Inst::Load { .. })
//         | InstExt::Inst(Inst::Store { .. })
//         | InstExt::Inst(Inst::Branch { .. })
//         | InstExt::Inst(Inst::Ecall)
//         | InstExt::Inst(Inst::Unimplemented)
//         | InstExt::Ecalli { .. }
//             => false,
//     }
// }

#[derive(Debug)]
enum EndOfBlock {
    Fallthrough {
        target: u32,
    },
    Jump {
        source: AddressRange,
        target: u32,
    },
    Call {
        source: AddressRange,
        ra: Reg,
        target: u32,
        return_address: u32,
    },
    JumpIndirect {
        source: AddressRange,
        base: Reg,
        offset: i32,
    },
    CallIndirect {
        source: AddressRange,
        ra: Reg,
        base: Reg,
        offset: i32,
        return_address: u32,
    },
    Branch {
        source: AddressRange,
        kind: BranchKind,
        src1: Reg,
        src2: Reg,
        target_true: u32,
        target_false: u32,
    },
    Unimplemented {
        source: AddressRange,
    },
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
struct AddressRange {
    start: u32,
    end: u32,
}

impl From<Range<u32>> for AddressRange {
    fn from(range: Range<u32>) -> Self {
        AddressRange {
            start: range.start,
            end: range.end,
        }
    }
}

#[derive(Copy, Clone, Debug)]
enum InstExt {
    Inst(Inst),
    Ecalli { syscall: u32 },
}

#[derive(Debug)]
struct BasicBlock {
    source: AddressRange,
    ops: Vec<(AddressRange, InstExt)>,
    next: EndOfBlock,
}

struct Fn<'a> {
    name: Option<&'a str>,
    range: AddressRange,
    body: Vec<usize>,
}

#[derive(Clone)]
enum RangeOrPadding {
    Range(Range<usize>),
    Padding(usize),
}

impl From<Range<usize>> for RangeOrPadding {
    fn from(range: Range<usize>) -> Self {
        RangeOrPadding::Range(range)
    }
}

struct MemoryConfig {
    ro_data: Vec<RangeOrPadding>,
    rw_data: Option<Range<usize>>,
    bss_size: u32,
    stack_size: u32,
}

#[allow(clippy::too_many_arguments)]
fn extract_memory_config(
    data: &[u8],
    section_rodata: Option<&ElfSection>,
    section_data: Option<&ElfSection>,
    section_data_rel_ro: Option<&ElfSection>,
    section_bss: Option<&ElfSection>,
    section_got: Option<&ElfSection>,
    relocation_for_section: &mut HashMap<SectionIndex, i64>,
) -> Result<MemoryConfig, ProgramFromElfError> {
    let mut memory_end = VM_ADDR_USER_MEMORY as u64;
    let mut ro_data = Vec::new();
    let mut ro_data_size = 0;
    let mut rw_data = None;
    let mut rw_data_size = 0;
    let mut bss_size_implicit = 0;
    let mut bss_size = 0;
    let stack_size = VM_PAGE_SIZE as u64;

    assert_eq!(memory_end % VM_PAGE_SIZE as u64, 0);
    for section in [section_rodata, section_data_rel_ro, section_got].into_iter().flatten() {
        let section_name = section.name().expect("failed to get section name");
        if section.address() != memory_end {
            // TODO: Lift this requirement.
            return Err(ProgramFromElfError::other(format!(
                "the '{section_name}' section doesn't start at 0x{memory_end:x}"
            )));
        }

        assert_eq!(section.address() % 4, 0);

        relocation_for_section.insert(section.index(), (memory_end as i64).wrapping_sub(section.address() as i64));

        let section_range = get_section_range(data, section)?;
        memory_end += section_range.len() as u64;
        ro_data.push(section_range.clone().into());
        ro_data_size += section_range.len() as u64;

        // If the section's size is not aligned then pad it.
        let padding = if section_range.len() % 4 != 0 {
            4 - (section_range.len() & 0b11)
        } else {
            0
        };
        log::trace!(
            "Found read-only section: '{}', address = 0x{:x}, size = 0x{:x}, extra padding = {}",
            section_name,
            section.address(),
            section_range.len(),
            padding
        );
        if padding > 0 {
            memory_end += padding as u64;
            ro_data_size += padding as u64;
            ro_data.push(RangeOrPadding::Padding(padding));
        }
    }

    let ro_data_size_unaligned = ro_data_size;
    ro_data_size = align_to_next_page_u64(VM_PAGE_SIZE as u64, ro_data_size)
        .ok_or(ProgramFromElfError::other("out of range size for read-only sections"))?;
    memory_end += ro_data_size - ro_data_size_unaligned;

    if let Some(section) = section_data {
        assert_eq!(memory_end % VM_PAGE_SIZE as u64, 0);
        if section.address() != memory_end {
            // TODO: Lift this requirement.
            return Err(ProgramFromElfError::other(format!(
                "the '.data' section doesn't start at 0x{:x}",
                memory_end
            )));
        }

        relocation_for_section.insert(section.index(), (memory_end as i64).wrapping_sub(section.address() as i64));

        let section_range = get_section_range(data, section)?;
        memory_end += section_range.len() as u64;
        rw_data = Some(section_range.clone());
        rw_data_size = align_to_next_page_u64(VM_PAGE_SIZE as u64, section_range.len() as u64)
            .ok_or(ProgramFromElfError::other("out of range size for '.data' section"))?;
        bss_size_implicit = rw_data_size - section_range.len() as u64;
    }

    if let Some(section) = section_bss {
        if section.address() != memory_end {
            // TODO: Lift this requirement.
            return Err(ProgramFromElfError::other(format!(
                "the '.bss' section doesn't start at 0x{:x}",
                memory_end
            )));
        }

        relocation_for_section.insert(section.index(), (memory_end as i64).wrapping_sub(section.address() as i64));

        let section_size = section.size();
        if section_size > bss_size_implicit {
            bss_size = align_to_next_page_u64(VM_PAGE_SIZE as u64, section_size - bss_size_implicit)
                .ok_or(ProgramFromElfError::other("out of range size for '.bss' section"))?;
        }
    }

    if ro_data_size > VM_MAXIMUM_MEMORY_SIZE as u64 {
        return Err(ProgramFromElfError::other(
            "size of read-only sections exceeded the maximum memory size",
        ));
    }

    if rw_data_size > VM_MAXIMUM_MEMORY_SIZE as u64 {
        return Err(ProgramFromElfError::other(
            "size of `.data` section exceeded the maximum memory size",
        ));
    }

    if bss_size > VM_MAXIMUM_MEMORY_SIZE as u64 {
        return Err(ProgramFromElfError::other(
            "size of `.bss` section exceeded the maximum memory size",
        ));
    }

    if stack_size > VM_MAXIMUM_MEMORY_SIZE as u64 {
        return Err(ProgramFromElfError::other("size of the stack exceeded the maximum memory size"));
    }

    if ro_data_size + rw_data_size + bss_size + stack_size > VM_MAXIMUM_MEMORY_SIZE as u64 {
        return Err(ProgramFromElfError::other("maximum memory size exceeded"));
    }

    let memory_config = MemoryConfig {
        ro_data,
        rw_data,
        bss_size: bss_size as u32,
        stack_size: stack_size as u32,
    };

    Ok(memory_config)
}

fn extract_export_metadata<'a>(data: &'a [u8], section: ElfSection) -> Result<Vec<ExportMetadata<'a>>, ProgramFromElfError> {
    let section_range = get_section_range(data, &section)?;
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

fn extract_import_metadata<'a>(data: &'a [u8], section: ElfSection) -> Result<BTreeMap<u32, ImportMetadata<'a>>, ProgramFromElfError> {
    let section_range = get_section_range(data, &section)?;
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

fn extract_functions<'a>(
    data: &'a [u8],
    elf: &'a Elf,
    section_text: ElfSection,
    import_metadata: &BTreeMap<u32, ImportMetadata>,
    jump_targets: &mut HashSet<u32>,
    relocation_for_section: &HashMap<SectionIndex, i64>,
    mut instruction_overrides: HashMap<u64, Inst>,
) -> Result<(Vec<Fn<'a>>, Vec<BasicBlock>), ProgramFromElfError> {
    let hostcall_by_hash: HashMap<[u8; 16], u32> = import_metadata.iter().map(|(index, metadata)| (metadata.hash, *index)).collect();

    let text_range = section_text.file_range().unwrap_or((0, 0));
    let text_start = usize::try_from(text_range.0).map_err(|_| ProgramFromElfError::other("out of range offset for '.text' section"))?;
    let text_size = usize::try_from(text_range.1).map_err(|_| ProgramFromElfError::other("out of range size for '.text' section"))?;
    let text_end = text_start
        .checked_add(text_size)
        .ok_or(ProgramFromElfError::other("out of range '.text' section"))?;
    let text = &data[text_start..text_end];

    let mut functions = Vec::new();
    for sym in elf.symbols() {
        let kind = sym.raw_symbol().st_type();
        match kind {
            object::elf::STT_FUNC => {
                let name = sym.name()?;
                let name = if name.is_empty() { None } else { Some(name) };

                let start = u32::try_from(sym.address()).map_err(|_| ProgramFromElfError::other("function has out of range address"))?;
                let end = u32::try_from(sym.address() + sym.size())
                    .map_err(|_| ProgramFromElfError::other("function has out of range end address"))?;
                let range = (start..end).into();
                functions.push(Fn {
                    name,
                    range,
                    body: Default::default(),
                });
            }
            object::elf::STT_NOTYPE | object::elf::STT_OBJECT | object::elf::STT_SECTION | object::elf::STT_FILE => {}
            _ => return Err(ProgramFromElfError::other(format!("unsupported symbol type: {}", kind))),
        }
    }

    functions.sort_unstable_by_key(|func| (func.range.start, func.range.end));
    functions.dedup_by_key(|func| func.range);

    if functions.is_empty() {
        return Err(ProgramFromElfError::other("no functions found in the symbol table"));
    }

    if functions[0].range.start as u64 != section_text.address() {
        return Err(ProgramFromElfError::other(
            "incomplete symbol table: first function doesn't match the start of the '.text' section",
        ));
    }

    if functions[functions.len() - 1].range.end as u64 != section_text.address() + section_text.size() {
        return Err(ProgramFromElfError::other(
            "incomplete symbol table: last function doesn't match the end of the '.text' section",
        ));
    }

    for xs in functions.windows(2) {
        if xs[0].range.end != xs[1].range.start {
            return Err(ProgramFromElfError::other(
                "incomplete symbol table: the whole '.text' section is not covered",
            ));
        }
    }

    let text_relocation_delta = *relocation_for_section
        .get(&section_text.index())
        .expect("internal error: no relocation offset for the '.text' section");

    let mut blocks = Vec::new();
    for func in &mut functions {
        // The range of addresses for this function before relocation.
        let original_range = func.range.start as u64..func.range.end as u64;

        // The range of addresses for this function after relocation.
        let relocated_start = (original_range.start.wrapping_add(text_relocation_delta as u64)) as usize;
        let relocated_end = (original_range.end.wrapping_add(text_relocation_delta as u64)) as usize;

        // The range of addresses for this function relative to the start of the section.
        let relative_start = (original_range.start - section_text.address()) as usize;
        let relative_end = (original_range.end - section_text.address()) as usize;

        let fn_code = &text[relative_start..relative_end];
        if fn_code.len() % 4 != 0 {
            return Err(ProgramFromElfError::other("function's size is not divisible by 4"));
        }

        let relocated_start = u32::try_from(relocated_start).map_err(|_| ProgramFromElfError::other("program counter overflow"))?;
        let relocated_end = u32::try_from(relocated_end).map_err(|_| ProgramFromElfError::other("program counter overflow"))?;
        let mut pc_offset: u32 = 0;

        func.range = (relocated_start..relocated_end).into();

        let mut body: Vec<(AddressRange, InstExt)> = Vec::with_capacity(fn_code.len());
        while (pc_offset as usize) < fn_code.len() {
            let op = u32::from_le_bytes([
                fn_code[pc_offset as usize],
                fn_code[pc_offset as usize + 1],
                fn_code[pc_offset as usize + 2],
                fn_code[pc_offset as usize + 3],
            ]);
            let relative_pc = relative_start as u64 + pc_offset as u64;
            let relocated_pc = relocated_start
                .checked_add(pc_offset)
                .ok_or(ProgramFromElfError::other("program counter overflow"))?;
            let source = AddressRange::from(relocated_pc..relocated_pc + 4);

            if op == INSTRUCTION_ECALLI {
                if pc_offset != 0 {
                    return Err(ProgramFromElfError::other(
                        "hostcall instruction is not the first instruction in the function",
                    ));
                }
                if fn_code.len() != 24 {
                    return Err(ProgramFromElfError::other("hostcall function has unexpected length"));
                }

                let h = &fn_code[4..20];
                let hash = [
                    h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7], h[8], h[9], h[10], h[11], h[12], h[13], h[14], h[15],
                ];
                pc_offset += 20;

                const INST_RET: Inst = Inst::JumpAndLinkRegister {
                    dst: Reg::Zero,
                    base: Reg::RA,
                    value: 0,
                };

                let op = u32::from_le_bytes([
                    fn_code[pc_offset as usize],
                    fn_code[pc_offset as usize + 1],
                    fn_code[pc_offset as usize + 2],
                    fn_code[pc_offset as usize + 3],
                ]);
                if Inst::decode(op) != Some(INST_RET) {
                    return Err(ProgramFromElfError::other("hostcall function doesn't end with a 'ret'"));
                }

                let hostcall_index = match hostcall_by_hash.get(&hash) {
                    Some(index) => *index,
                    None => {
                        return Err(ProgramFromElfError::other(format!(
                            "hostcall with hash that doesn't match any metadata: {:?}",
                            hash
                        )));
                    }
                };

                body.push((
                    AddressRange::from(relocated_pc..relocated_pc + 20),
                    InstExt::Ecalli { syscall: hostcall_index },
                ));
                body.push((AddressRange::from(relocated_pc + 20..relocated_pc + 24), InstExt::Inst(INST_RET)));
                break;
            }

            pc_offset += 4;

            let op = match Inst::decode(op) {
                Some(op) => instruction_overrides.remove(&relative_pc).unwrap_or(op),
                None => {
                    return Err(ProgramFromElfErrorKind::UnsupportedInstruction {
                        pc: original_range.start.wrapping_add(pc_offset as u64),
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
                Inst::LoadUpperImmediate { dst, value } => InstExt::Inst(Inst::RegImm {
                    kind: RegImmKind::Add,
                    dst,
                    src: Reg::Zero,
                    imm: value as i32,
                }),
                Inst::JumpAndLink { dst, target } => {
                    let target = (relocated_pc as i32 + target as i32) as u32;
                    if u64::from(target) >= section_text.size() {
                        return Err(ProgramFromElfError::other("out of range jump (JAL)"));
                    }

                    jump_targets.insert(target);
                    if dst != Reg::Zero {
                        if relocated_pc + 4 >= relocated_end {
                            return Err(ProgramFromElfError::other("out of range return address"));
                        }
                        jump_targets.insert(relocated_pc + 4);
                    }
                    InstExt::Inst(Inst::JumpAndLink { dst, target })
                }
                Inst::Branch { kind, src1, src2, target } => {
                    let target = (relocated_pc as i32 + target as i32) as u32;
                    if target < relocated_start || target >= relocated_end {
                        // These are not supposed to be used across functions.
                        return Err(ProgramFromElfError::other("found a branch jumping out of its function"));
                    }
                    jump_targets.insert(target);
                    InstExt::Inst(Inst::Branch { kind, src1, src2, target })
                }
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
                _ => InstExt::Inst(op),
            };

            body.push((source, op));
        }

        // Split the function into basic blocks.
        let mut local_blocks = Vec::new();
        let mut current_block = Vec::new();
        let mut block_start = 0;
        for (source, op) in body {
            if current_block.is_empty() {
                block_start = source.start;
            }

            if !current_block.is_empty() && jump_targets.contains(&source.start) {
                local_blocks.push(blocks.len());
                blocks.push(BasicBlock {
                    source: (block_start..source.start).into(),
                    ops: std::mem::take(&mut current_block),
                    next: EndOfBlock::Fallthrough { target: source.start },
                });
                block_start = source.start;
            }

            if let InstExt::Inst(Inst::JumpAndLink { dst, target }) = op {
                let next = if dst != Reg::Zero {
                    EndOfBlock::Call {
                        source,
                        ra: dst,
                        target,
                        return_address: source.end,
                    }
                } else {
                    EndOfBlock::Jump { source, target }
                };

                local_blocks.push(blocks.len());
                blocks.push(BasicBlock {
                    source: (block_start..source.end).into(),
                    ops: std::mem::take(&mut current_block),
                    next,
                });
                block_start = source.start;
            } else if let InstExt::Inst(Inst::JumpAndLinkRegister { dst, base, value }) = op {
                let next = if dst != Reg::Zero {
                    EndOfBlock::CallIndirect {
                        source,
                        ra: dst,
                        base,
                        offset: value,
                        return_address: source.end,
                    }
                } else {
                    EndOfBlock::JumpIndirect {
                        source,
                        base,
                        offset: value,
                    }
                };

                local_blocks.push(blocks.len());
                blocks.push(BasicBlock {
                    source: (block_start..source.end).into(),
                    ops: std::mem::take(&mut current_block),
                    next,
                });
                block_start = source.start;
            } else if let InstExt::Inst(Inst::Branch { kind, src1, src2, target }) = op {
                local_blocks.push(blocks.len());
                blocks.push(BasicBlock {
                    source: (block_start..source.end).into(),
                    ops: std::mem::take(&mut current_block),
                    next: EndOfBlock::Branch {
                        source,
                        kind,
                        src1,
                        src2,
                        target_true: target,
                        target_false: source.end,
                    },
                });
                block_start = source.start;
            } else if let InstExt::Inst(Inst::Unimplemented) = op {
                local_blocks.push(blocks.len());
                blocks.push(BasicBlock {
                    source: (block_start..source.end).into(),
                    ops: std::mem::take(&mut current_block),
                    next: EndOfBlock::Unimplemented { source },
                });
                block_start = source.start;
            } else {
                current_block.push((source, op));
            }
        }

        // TODO: Enable this again.
        // for block in &mut blocks {
        //     block.ops.retain(|(_, op)| !is_nop(*op));
        // }

        if !current_block.is_empty() {
            return Err(ProgramFromElfError::other(
                "function doesn't end with a control-flow affecting instruction",
            ));
        }

        func.body = local_blocks;
    }

    if !instruction_overrides.is_empty() {
        return Err(ProgramFromElfError::other("internal error: instruction overrides map is not empty"));
    }

    Ok((functions, blocks))
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

fn emit_code(
    mut jump_targets: HashSet<u32>,
    functions: &[Fn],
    blocks: &[BasicBlock],
) -> Result<Vec<(AddressRange, RawInstruction)>, ProgramFromElfError> {
    for func in functions {
        jump_targets.insert(blocks[func.body[0]].source.start);
        for &block_index in &func.body {
            let block = &blocks[block_index];
            match block.next {
                EndOfBlock::Fallthrough { .. } => {}
                EndOfBlock::Jump { target, .. } => {
                    jump_targets.insert(target);
                }
                EndOfBlock::Call {
                    target, return_address, ..
                } => {
                    jump_targets.insert(target);
                    jump_targets.insert(return_address);
                }
                EndOfBlock::JumpIndirect { .. } => {}
                EndOfBlock::CallIndirect { return_address, .. } => {
                    jump_targets.insert(return_address);
                }
                EndOfBlock::Branch { target_true, .. } => {
                    jump_targets.insert(target_true);
                }
                EndOfBlock::Unimplemented { .. } => {}
            }
        }
    }

    let mut code: Vec<(AddressRange, RawInstruction)> = Vec::new();
    for func in functions {
        for &block_index in &func.body {
            let block = &blocks[block_index];
            if jump_targets.contains(&block.source.start) {
                assert_eq!(block.source.start % 4, 0);
                code.push((
                    (block.source.start..block.source.start + 4).into(),
                    RawInstruction::new_with_imm(Opcode::jump_target, block.source.start / 4),
                ));
            }

            for &(source, op) in &block.ops {
                let op = match op {
                    InstExt::Inst(Inst::Load { kind, dst, base, offset }) => {
                        use crate::riscv::LoadKind;
                        let kind = match kind {
                            LoadKind::I8 => Opcode::load_i8,
                            LoadKind::I16 => Opcode::load_i16,
                            LoadKind::U32 => Opcode::load_u32,
                            LoadKind::U8 => Opcode::load_u8,
                            LoadKind::U16 => Opcode::load_u16,
                        };
                        RawInstruction::new_with_regs2_imm(kind, cast_reg(dst), cast_reg(base), offset as u32)
                    }
                    InstExt::Inst(Inst::Store { kind, src, base, offset }) => {
                        use crate::riscv::StoreKind;
                        let kind = match kind {
                            StoreKind::U32 => Opcode::store_u32,
                            StoreKind::U8 => Opcode::store_u8,
                            StoreKind::U16 => Opcode::store_u16,
                        };
                        RawInstruction::new_with_regs2_imm(kind, cast_reg(src), cast_reg(base), offset as u32)
                    }
                    InstExt::Inst(Inst::RegImm { kind, dst, src, imm }) => {
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
                    InstExt::Inst(Inst::Shift { kind, dst, src, amount }) => {
                        use crate::riscv::ShiftKind;
                        let kind = match kind {
                            ShiftKind::LogicalLeft => Opcode::shift_logical_left_imm,
                            ShiftKind::LogicalRight => Opcode::shift_logical_right_imm,
                            ShiftKind::ArithmeticRight => Opcode::shift_arithmetic_right_imm,
                        };
                        RawInstruction::new_with_regs2_imm(kind, cast_reg(dst), cast_reg(src), amount as u32)
                    }
                    InstExt::Inst(Inst::RegReg { kind, dst, src1, src2 }) => {
                        use crate::riscv::RegRegKind;
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
                    InstExt::Ecalli { syscall } => RawInstruction::new_with_imm(Opcode::ecalli, syscall),

                    InstExt::Inst(Inst::JumpAndLink { .. })
                    | InstExt::Inst(Inst::JumpAndLinkRegister { .. })
                    | InstExt::Inst(Inst::Branch { .. })
                    | InstExt::Inst(Inst::AddUpperImmediateToPc { .. })
                    | InstExt::Inst(Inst::LoadUpperImmediate { .. })
                    | InstExt::Inst(Inst::Unimplemented)
                    | InstExt::Inst(Inst::Ecall) => unreachable!(),
                };

                code.push((source, op));
            }

            match block.next {
                EndOfBlock::Fallthrough { target } => {
                    assert_eq!(target, block.source.end);
                }
                EndOfBlock::Jump { source, target } => {
                    if target % 4 != 0 {
                        return Err(ProgramFromElfError::other("found a jump with a target that isn't aligned"));
                    }
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
                EndOfBlock::Call {
                    source,
                    ra,
                    target,
                    return_address,
                } => {
                    if target % 4 != 0 {
                        return Err(ProgramFromElfError::other("found a call with a target that isn't aligned"));
                    }
                    code.push((
                        source,
                        RawInstruction::new_with_regs2_imm(Opcode::jump_and_link_register, cast_reg(ra), cast_reg(Reg::Zero), target / 4),
                    ));
                    assert_eq!(return_address, block.source.end);
                }
                EndOfBlock::JumpIndirect { source, base, offset } => {
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
                EndOfBlock::CallIndirect {
                    source,
                    ra,
                    base,
                    offset,
                    return_address,
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
                EndOfBlock::Branch {
                    source,
                    kind,
                    src1,
                    src2,
                    target_true,
                    target_false,
                } => {
                    if target_true % 4 != 0 {
                        return Err(ProgramFromElfError::other("found a branch with a target that isn't aligned"));
                    }
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
                EndOfBlock::Unimplemented { source } => {
                    code.push((source, RawInstruction::new_argless(Opcode::trap)));
                }
            }
        }
    }

    Ok(code)
}

#[allow(clippy::too_many_arguments)]
fn relocate(
    elf: &Elf,
    section_text: &ElfSection,
    section_got: Option<&ElfSection>,
    relocation_for_section: &HashMap<SectionIndex, i64>,
    section: &ElfSection,
    data: &mut [u8],
    mut jump_targets: Option<&mut HashSet<u32>>,
    instruction_overrides: &mut HashMap<u64, Inst>,
) -> Result<(), ProgramFromElfError> {
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

    if section.relocations().next().is_none() {
        return Ok(());
    }

    let mut reloc_pcrel_hi20: HashMap<u64, (HiRelocKind, u64)> = HashMap::new();
    let mut reloc_pcrel_lo12: HashMap<u64, u64> = HashMap::new();

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
                        if target.target_section_index == Some(section_text.index()) {
                            if let Some(jump_targets) = jump_targets.as_mut() {
                                jump_targets.insert(target.relocated_address as u32);
                            }
                        }

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
                        if target.target_section_index == Some(section_text.index()) {
                            if let Some(jump_targets) = jump_targets.as_mut() {
                                jump_targets.insert(target.relocated_address as u32);
                            }
                        }

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
                        if section.index() != section_text.index() {
                            return Err(ProgramFromElfError::other(format!(
                                "found a R_RISCV_CALL_PLT relocation in an unexpected section: '{}'",
                                section.name()?
                            )));
                        };

                        let data_text = get_section_data(data, section_text)?;
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
                            relative_address,
                            Inst::RegImm {
                                kind: RegImmKind::Add,
                                dst: Reg::Zero,
                                src: Reg::Zero,
                                imm: 0,
                            },
                        );
                        instruction_overrides.insert(
                            relative_address + 4,
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

                        if section.index() != section_text.index() {
                            return Err(ProgramFromElfError::other(format!(
                                "found a R_RISCV_PCREL_HI20 relocation in an unexpected section: '{}'",
                                section.name()?
                            )));
                        }

                        reloc_pcrel_hi20.insert(relative_address, (HiRelocKind::PcRel, target.relocated_address));
                        log::trace!(
                            "  R_RISCV_PCREL_HI20: {}[0x{relative_address:x}] (0x{absolute_address:x}): -> 0x{:08x}",
                            section.name()?,
                            target.relocated_address
                        );
                    }
                    object::elf::R_RISCV_GOT_HI20 => {
                        if section.index() != section_text.index() {
                            return Err(ProgramFromElfError::other(format!(
                                "found a R_RISCV_GOT_HI20 relocation in an unexpected section: '{}'",
                                section.name()?
                            )));
                        };

                        reloc_pcrel_hi20.insert(relative_address, (HiRelocKind::Got, target.relocated_address));
                        log::trace!(
                            "  R_RISCV_GOT_HI20: {}[0x{relative_address:x}] (0x{absolute_address:x}): -> 0x{:08x}",
                            section.name()?,
                            target.relocated_address
                        );
                    }
                    object::elf::R_RISCV_PCREL_LO12_I => {
                        if section.index() != section_text.index() {
                            return Err(ProgramFromElfError::other(format!(
                                "found a R_RISCV_PCREL_LO12_I relocation in an unexpected section: '{}'",
                                section.name()?
                            )));
                        };

                        if target.target_section_index != Some(section_text.index()) {
                            return Err(ProgramFromElfError::other(
                                "R_RISCV_PCREL_LO12_I relocation points to a non '.text' section",
                            ));
                        }

                        reloc_pcrel_lo12.insert(relative_address, target.relative_address);
                        log::trace!(
                            "  R_RISCV_PCREL_LO12_I: {}[0x{relative_address:x}] (0x{absolute_address:x}): -> 0x{:08x}",
                            section.name()?,
                            target.relocated_address
                        );
                    }
                    object::elf::R_RISCV_PCREL_LO12_S => {
                        if section.index() != section_text.index() {
                            return Err(ProgramFromElfError::other(format!(
                                "found a R_RISCV_PCREL_LO12_S relocation in an unexpected section: '{}'",
                                section.name()?
                            )));
                        };

                        if target.target_section_index != Some(section_text.index()) {
                            return Err(ProgramFromElfError::other(
                                "R_RISCV_PCREL_LO12_S relocation points to a non '.text' section",
                            ));
                        }

                        reloc_pcrel_lo12.insert(relative_address, target.relative_address);
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

    let text_range = get_section_range(data, section_text)?;
    for (relative_lo, relative_hi) in reloc_pcrel_lo12 {
        let data_text = &mut data[text_range.clone()];
        let lo_inst_raw = &data_text[relative_lo as usize..][..4];
        let mut lo_inst = Inst::decode(u32::from_le_bytes([lo_inst_raw[0], lo_inst_raw[1], lo_inst_raw[2], lo_inst_raw[3]]));
        let hi_inst_raw = &data_text[relative_hi as usize..][..4];
        let hi_inst = Inst::decode(u32::from_le_bytes([hi_inst_raw[0], hi_inst_raw[1], hi_inst_raw[2], hi_inst_raw[3]]));

        let Some((hi_kind, target_address)) = reloc_pcrel_hi20.get(&relative_hi).copied() else {
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
            relative_hi,
            Inst::RegImm {
                kind: RegImmKind::Add,
                dst: Reg::Zero,
                src: Reg::Zero,
                imm: 0,
            },
        );
        instruction_overrides.insert(relative_lo, lo_inst.unwrap());

        log::trace!("Replaced and merged 0x{hi_original:08x} (pc) + 0x{hi_value:08x} (hi) + 0x{old_lo_value:08x} (lo) = 0x{old_merged:08x} to point to 0x{new_merged:08x} (from {hi_kind}, 0x{relative_hi:x} (rel hi), 0x{relative_lo:x} (rel lo))");
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

    if elf.raw_header().e_type.get(LittleEndian) != object::elf::ET_EXEC {
        return Err(ProgramFromElfError::other("file is not an executable file (ET_EXEC)"));
    }

    if elf.raw_header().e_machine.get(LittleEndian) != object::elf::EM_RISCV {
        return Err(ProgramFromElfError::other("file is not a RISC-V file (EM_RISCV)"));
    }

    let mut section_rodata = None;
    let mut section_data = None;
    let mut section_data_rel_ro = None;
    let mut section_got = None;
    let mut section_bss = None;
    let mut section_text = None;
    let mut section_import_metadata = None;
    let mut section_export_metadata = None;

    let mut relocation_for_section = HashMap::new();
    for section in elf.sections() {
        // Make sure the data is accessible.
        get_section_data(data, &section)?;

        let name = section.name()?;
        match name {
            ".rodata" => section_rodata = Some(section),
            ".data" => section_data = Some(section),
            ".data.rel.ro" => section_data_rel_ro = Some(section),
            ".got" => section_got = Some(section),
            ".bss" => section_bss = Some(section),
            ".text" => {
                // Relocate code to 0x00000004.
                #[allow(clippy::neg_multiply)]
                relocation_for_section.insert(section.index(), (section.address() as i64 * -1).wrapping_add(0x4));
                section_text = Some(section);
            }
            ".polkavm_imports" => section_import_metadata = Some(section),
            ".polkavm_exports" => {
                relocation_for_section.insert(section.index(), 0);
                section_export_metadata = Some(section);
            }
            _ => {
                let flags = match section.flags() {
                    object::SectionFlags::Elf { sh_flags } => sh_flags,
                    _ => unreachable!(),
                };

                if flags & object::elf::SHF_ALLOC as u64 != 0 {
                    // We're supposed to load this section into memory at runtime, but we don't know what it is.
                    return Err(ProgramFromElfErrorKind::UnsupportedSection(name.to_owned()).into());
                }

                // For sections which will not be in memory at runtime we just don't relocate them.
                relocation_for_section.insert(section.index(), 0);
                continue;
            }
        }
    }

    let section_text = section_text.ok_or(ProgramFromElfError::other("missing '.text' section"))?;

    let memory_config = extract_memory_config(
        data,
        section_rodata.as_ref(),
        section_data.as_ref(),
        section_data_rel_ro.as_ref(),
        section_bss.as_ref(),
        section_got.as_ref(),
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
    if let Some(ref section) = section_got {
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

    let mut instruction_overrides = HashMap::new();
    let mut data = data.to_vec();
    for section in elf.sections() {
        let is_data_section = [
            section_rodata.as_ref(),
            section_data.as_ref(),
            section_data_rel_ro.as_ref(),
            section_bss.as_ref(),
            section_got.as_ref(),
        ]
        .into_iter()
        .flatten()
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
            &section_text,
            section_got.as_ref(),
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
        jump_targets.insert(export.address);
    }

    let dwarf = crate::dwarf::load_dwarf(&elf, &data)?;

    let (functions, blocks) = extract_functions(
        &data,
        &elf,
        section_text,
        &import_metadata,
        &mut jump_targets,
        &relocation_for_section,
        instruction_overrides,
    )?;

    let code = emit_code(jump_targets, &functions, &blocks)?;

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
        if let Some(range) = memory_config.rw_data {
            writer.push_raw_bytes(&data[range]);
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

    let mut start_address_to_instruction_index: BTreeMap<u32, u32> = Default::default();
    let mut end_address_to_instruction_index: BTreeMap<u32, u32> = Default::default();
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

    enum FunctionInfoKind<'a> {
        Full(&'a crate::dwarf::Frame),
        SymbolOnly(u32, u32),
    }

    let mut dbg_strings = DebugStringsBuilder::default();
    let empty_string_id = dbg_strings.dedup("");

    let mut function_info_list = Vec::new();
    let mut addresses_with_dwarf_info = HashSet::new();
    for &(function_start_address, function_end_address, ref frames) in &dwarf.frames {
        let function_start_address = function_start_address.try_into().expect("function address overflow");
        let function_end_address = function_end_address.try_into().expect("function address overflow");

        addresses_with_dwarf_info.insert(function_start_address);
        for frame in frames {
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

            function_info_list.push((
                AddressRange {
                    start: function_start_address,
                    end: function_end_address,
                },
                FunctionInfoKind::Full(frame),
            ));
        }
    }

    // Not everything might have debug info linked in, so as a backup add symbols from the symbol table.
    //
    // This can happen for e.g. the symbols from the standard library, if the standard library wasn't recompiled.
    for func in &functions {
        let source = blocks[func.body[0]].source;
        if addresses_with_dwarf_info.contains(&source.start) {
            continue;
        }

        if let Some(name) = func.name {
            if let Ok(name) = rustc_demangle::try_demangle(name) {
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

                if !with_hash.contains("::") {
                    let string_id = dbg_strings.dedup_cow(with_hash.into());
                    function_info_list.push((source, FunctionInfoKind::SymbolOnly(empty_string_id, string_id)));
                } else {
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
                        let prefix_id = dbg_strings.dedup_cow(prefix.to_owned().into());
                        let suffix_id = dbg_strings.dedup_cow(suffix.to_owned().into());
                        function_info_list.push((source, FunctionInfoKind::SymbolOnly(prefix_id, suffix_id)));
                    } else {
                        log::warn!("Failed to split symbol: {:?}", with_hash);

                        let string_id = dbg_strings.dedup_cow(with_hash.into());
                        function_info_list.push((source, FunctionInfoKind::SymbolOnly(empty_string_id, string_id)));
                    }
                }
            }
        }
    }

    function_info_list.sort_by_key(|(source, _)| (source.start, !source.end));

    dbg_strings.write_protected = true;

    writer.push_section(program::SECTION_OPT_DEBUG_STRINGS, |writer| {
        writer.push_raw_bytes(&dbg_strings.section);
    });

    let mut function_ranges = Vec::with_capacity(dwarf.frames.len());
    writer.push_section(program::SECTION_OPT_DEBUG_FUNCTION_INFO, |writer| {
        let offset_base = writer.len();
        writer.push_byte(program::VERSION_DEBUG_FUNCTION_INFO_V1);
        let mut last_range = AddressRange { start: 0, end: 0 };
        for (function_range, kind) in function_info_list {
            assert!(function_range.start >= last_range.end || function_range == last_range);

            let info_offset: u32 = (writer.len() - offset_base).try_into().expect("function info offset overflow");
            // TODO: These should be handled more intelligently instead of panicking.
            let function_start_index = *start_address_to_instruction_index
                .get(&function_range.start)
                .expect("function start address has no matching instructions");
            let function_end_index = *end_address_to_instruction_index
                .get(&function_range.end)
                .expect("function end address has no matching instructions");
            function_ranges.push((function_start_index, function_end_index, info_offset));

            match kind {
                FunctionInfoKind::Full(frame) => {
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
                        let inline_start_address: u32 = inline_start_address.try_into().expect("function inline frame address overflow");
                        let inline_end_address = inline_end_address.try_into().expect("function inline frame address overflow");

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
                FunctionInfoKind::SymbolOnly(prefix_id, suffix_id) => {
                    writer.push_varint(prefix_id);
                    writer.push_varint(suffix_id);
                    writer.push_varint(empty_string_id); // File path.
                    writer.push_varint(0); // Line.
                    writer.push_varint(0); // Column.
                    writer.push_varint(0); // Inline frame count.
                }
            }

            last_range = function_range;
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
