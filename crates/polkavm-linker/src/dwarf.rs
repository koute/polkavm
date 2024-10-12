use crate::elf::{Elf, Section, SectionIndex};
use crate::fast_range_map::RangeMap;
use crate::program_from_elf::{AddressRange, RelocationKind, RelocationSize, SectionTarget, SizeRelocationSize, Source};
use crate::reader_wrapper::ReaderWrapper;
use crate::utils::StringCache;
use crate::ProgramFromElfError;
use gimli::{LineInstruction, Reader, ReaderOffset};
use polkavm_common::program::FrameKind;
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

fn find_unit<R>(
    units: &[Unit<R>],
    target_offset: gimli::DebugInfoOffset<R::Offset>,
) -> Result<(&Unit<R>, gimli::UnitOffset<R::Offset>), ProgramFromElfError>
where
    R: gimli::Reader,
{
    let target_unit = units.binary_search_by_key(&target_offset.0, |target_unit| target_unit.offset.0);
    let target_unit = match target_unit {
        Ok(index) => &units[index],
        Err(0) => {
            return Err(ProgramFromElfError::other(format!(
                "failed to process DWARF: failed to find a unit for offset: {:x}",
                target_offset.0.into_u64()
            )));
        }
        Err(index) => &units[index - 1],
    };
    let unit_offset = target_offset.to_unit_offset(&target_unit.raw_unit.header).ok_or_else(|| {
        ProgramFromElfError::other(format!(
            "failed to process DWARF: found a unit for offset={:x} but couldn't compute a relative offset",
            target_offset.0.into_u64()
        ))
    })?;

    Ok((target_unit, unit_offset))
}

struct AttributeParser<R: gimli::Reader> {
    depth: usize,
    low_pc: Option<SectionTarget>,
    high_pc: Option<SectionTarget>,
    size: Option<u64>,
    ranges_offset: Option<gimli::RangeListsOffset<<R as gimli::Reader>::Offset>>,
    linkage_name: Option<gimli::AttributeValue<R>>,
    name: Option<gimli::AttributeValue<R>>,
    abstract_origin: Option<gimli::DebugInfoOffset<R::Offset>>,
    decl_file: Option<usize>,
    decl_line: Option<u32>,
    call_file: Option<usize>,
    call_line: Option<u32>,
    call_column: Option<u32>,
    is_declaration: bool,
    recursion_limit: usize,
    is_64bit: bool,
}

fn parse_ranges<R>(
    sections: &Sections,
    relocations: &BTreeMap<SectionTarget, RelocationKind>,
    unit: &gimli::Unit<R>,
    mut base: Option<SectionTarget>,
    ranges_offset: gimli::RangeListsOffset<<R as gimli::Reader>::Offset>,
    mut callback: impl FnMut(Source),
    is_64bit: bool,
) -> Result<(), ProgramFromElfError>
where
    R: gimli::Reader,
{
    if unit.encoding().version <= 4 {
        let Some(section) = sections.debug_ranges else {
            return Err(ProgramFromElfError::other(
                "failed to process DWARF: missing '.debug_ranges' section",
            ));
        };

        let mut reader = gimli::read::EndianSlice::new(section.data(), gimli::LittleEndian);
        let start = reader;
        reader.skip(ranges_offset.0.into_u64() as usize)?;

        let address_size = unit.encoding().address_size;
        let offset_start = reader.offset_from(start);
        let _ = reader.read_address(address_size)?;
        let offset_end = reader.offset_from(start);
        let _ = reader.read_address(address_size)?;

        let relocation_start = SectionTarget {
            section_index: section.index(),
            offset: offset_start.into_u64(),
        };

        let relocation_end = SectionTarget {
            section_index: section.index(),
            offset: offset_end.into_u64(),
        };

        if let Some((start_section, start_range)) = try_fetch_size_relocation(relocations, relocation_start, is_64bit)? {
            let (end_section, end_range) = fetch_size_relocation(relocations, relocation_end, is_64bit)?;

            if start_section != end_section {
                return Err(ProgramFromElfError::other(
                    "failed to process DWARF: '.debug_ranges' has a pair of relocations pointing to different sections",
                ));
            }

            let source = Source {
                section_index: start_section,
                offset_range: (start_range.end..end_range.end).into(),
            };

            log::trace!("  Range from debug ranges: {}", source);
            callback(source);
        }
    } else {
        let Some(section) = sections.debug_rnglists else {
            return Err(ProgramFromElfError::other(
                "failed to process DWARF: missing '.debug_rnglists' section",
            ));
        };

        let mut reader = gimli::read::EndianSlice::new(section.data(), gimli::LittleEndian);
        reader.skip(ranges_offset.0.into_u64() as usize)?;

        loop {
            let kind = gimli::constants::DwRle(reader.read_u8()?);
            match kind {
                gimli::constants::DW_RLE_end_of_list => break,
                gimli::constants::DW_RLE_offset_pair => {
                    let offset_start = reader.read_uleb128()?;
                    let offset_end = reader.read_uleb128()?;
                    if let Some(base) = base {
                        let source = Source {
                            section_index: base.section_index,
                            offset_range: (base.offset + offset_start..base.offset + offset_end).into(),
                        };

                        log::trace!("  Range from low_pc + high_pc (rel): {}", source);
                        callback(source);
                    } else if false {
                        return Err(ProgramFromElfError::other(
                            "failed to process DWARF: found DW_RLE_offset_pair yet we have no base address",
                        ));
                    }
                }
                gimli::constants::DW_RLE_startx_length => {
                    let begin = gimli::DebugAddrIndex(reader.read_uleb128().and_then(R::Offset::from_u64)?);
                    let length = reader.read_uleb128()?;
                    if let Some(target) = resolve_debug_addr_index(sections.debug_addr, relocations, unit, begin, is_64bit)? {
                        let source = Source {
                            section_index: target.section_index,
                            offset_range: (target.offset..target.offset + length).into(),
                        };
                        callback(source)
                    }
                }
                gimli::constants::DW_RLE_base_addressx => {
                    let begin = gimli::DebugAddrIndex(reader.read_uleb128().and_then(R::Offset::from_u64)?);
                    base = resolve_debug_addr_index(sections.debug_addr, relocations, unit, begin, is_64bit)?;
                }
                _ => {
                    return Err(ProgramFromElfError::other(format!(
                        "failed to process DWARF: unhandled entry kind in '.debug_rnglists': {kind}"
                    )));
                }
            }
        }
    }

    Ok(())
}

impl<R: gimli::Reader> AttributeParser<R> {
    fn new(depth: usize, is_64bit: bool) -> Self {
        AttributeParser {
            depth,
            low_pc: None,
            high_pc: None,
            size: None,
            ranges_offset: None,
            linkage_name: None,
            name: None,
            abstract_origin: None,
            decl_file: None,
            decl_line: None,
            call_file: None,
            call_line: None,
            call_column: None,
            is_declaration: false,
            recursion_limit: 32,
            is_64bit,
        }
    }

    fn for_each_range(
        &self,
        sections: &Sections,
        relocations: &BTreeMap<SectionTarget, RelocationKind>,
        unit: &Unit<R>,
        mut callback: impl FnMut(Source),
    ) -> Result<(), ProgramFromElfError> {
        if let Some(ranges_offset) = self.ranges_offset {
            parse_ranges::<R>(
                sections,
                relocations,
                &unit.raw_unit,
                unit.low_pc,
                ranges_offset,
                callback,
                self.is_64bit,
            )?;
        } else if let (Some(low_pc), Some(high_pc)) = (self.low_pc, self.high_pc) {
            if low_pc.section_index != high_pc.section_index {
                return Err(ProgramFromElfError::other(
                    "failed to process DWARF: DW_AT_low_pc and DW_AT_high_pc point to different sections",
                ));
            }

            let source = Source {
                section_index: low_pc.section_index,
                offset_range: (low_pc.offset..high_pc.offset).into(),
            };

            log::trace!("  Range from low_pc + high_pc (abs): {}", source);
            callback(source);
        } else if let (Some(low_pc), Some(size)) = (self.low_pc, self.size) {
            let source = Source {
                section_index: low_pc.section_index,
                offset_range: (low_pc.offset..low_pc.offset + size).into(),
            };

            log::trace!("  Range from low_pc + high_pc (rel): {}", source);
            callback(source);
        }

        Ok(())
    }

    fn try_match(
        &mut self,
        sections: &Sections,
        relocations: &BTreeMap<SectionTarget, RelocationKind>,
        dwarf: &gimli::Dwarf<R>,
        unit: &Unit<R>,
        offset: gimli::UnitOffset<R::Offset>,
    ) -> Result<(), ProgramFromElfError> {
        for pair in iter_attributes(dwarf, &unit.raw_unit, offset)? {
            let (name, value) = pair?;
            self.try_match_attribute(sections, relocations, dwarf, unit, name, value)?;
        }

        Ok(())
    }

    fn try_match_attribute(
        &mut self,
        sections: &Sections,
        relocations: &BTreeMap<SectionTarget, RelocationKind>,
        dwarf: &gimli::Dwarf<R>,
        unit: &Unit<R>,
        name: gimli::constants::DwAt,
        value: AttributeValue<R>,
    ) -> Result<(), ProgramFromElfError> {
        log::trace!("{:->depth$}{name}", ">", depth = self.depth);

        struct UnsupportedValue<R>(AttributeValue<R>)
        where
            R: gimli::Reader;
        match name {
            gimli::DW_AT_low_pc => match value.clone() {
                AttributeValue { offset: Some(offset), .. } => {
                    let relocation_target = SectionTarget {
                        section_index: sections.debug_info.index(),
                        offset: offset.into_u64(),
                    };

                    if let Some(target) = try_fetch_relocation(relocations, relocation_target, self.is_64bit)? {
                        log::trace!("  = {target} (address)");
                        self.low_pc = Some(target);
                    }

                    Ok(())
                }
                AttributeValue {
                    value: gimli::AttributeValue::DebugAddrIndex(index),
                    ..
                } => {
                    self.low_pc = resolve_debug_addr_index(sections.debug_addr, relocations, &unit.raw_unit, index, self.is_64bit)?;
                    if let Some(value) = self.low_pc {
                        log::trace!("  = {value} ({index:?})");
                    } else {
                        log::trace!("  = None ({index:?})");
                    }

                    Ok(())
                }
                _ => Err(UnsupportedValue(value)),
            },
            gimli::DW_AT_high_pc => match value {
                AttributeValue { offset: Some(offset), .. } => {
                    let relocation_target = SectionTarget {
                        section_index: sections.debug_info.index(),
                        offset: offset.into_u64(),
                    };

                    if let Some(target) = try_fetch_relocation(relocations, relocation_target, self.is_64bit)? {
                        log::trace!("  = {target} (address)");
                        self.high_pc = Some(target);
                    }

                    Ok(())
                }
                AttributeValue {
                    value: gimli::AttributeValue::DebugAddrIndex(index),
                    ..
                } => {
                    self.high_pc = resolve_debug_addr_index(sections.debug_addr, relocations, &unit.raw_unit, index, self.is_64bit)?;
                    if let Some(value) = self.high_pc {
                        log::trace!("  = {value} ({index:?})");
                    } else {
                        log::trace!("  = None ({index:?})");
                    }

                    Ok(())
                }
                AttributeValue {
                    value: gimli::AttributeValue::Udata(value),
                    ..
                } => {
                    log::trace!("  = DW_AT_low_pc + {value} (size/udata)");
                    self.size = Some(value);
                    Ok(())
                }
                AttributeValue {
                    value: gimli::AttributeValue::Data4(value),
                    ..
                } => {
                    log::trace!("  = DW_AT_low_pc + {value} (size/data4)");
                    self.size = Some(u64::from(value));
                    Ok(())
                }
                _ => Err(UnsupportedValue(value)),
            },
            gimli::DW_AT_ranges => match value {
                AttributeValue {
                    value: gimli::AttributeValue::RangeListsRef(offset),
                    ..
                } => {
                    self.ranges_offset = Some(dwarf.ranges_offset_from_raw(&unit.raw_unit, offset));
                    Ok(())
                }
                AttributeValue {
                    value: gimli::AttributeValue::DebugRngListsIndex(index),
                    ..
                } => {
                    self.ranges_offset = Some(dwarf.ranges_offset(&unit.raw_unit, index)?);
                    Ok(())
                }
                AttributeValue {
                    value: gimli::AttributeValue::SecOffset(offset),
                    ..
                } => {
                    self.ranges_offset = Some(dwarf.ranges_offset_from_raw(&unit.raw_unit, gimli::RawRangeListsOffset(offset)));
                    Ok(())
                }
                _ => Err(UnsupportedValue(value)),
            },
            gimli::DW_AT_linkage_name | gimli::DW_AT_MIPS_linkage_name => {
                if let AttributeValue { value, offset: None } = value {
                    self.linkage_name = Some(value);
                    Ok(())
                } else {
                    Err(UnsupportedValue(value))
                }
            }
            gimli::DW_AT_name => {
                if let AttributeValue { value, offset: None } = value {
                    self.name = Some(value);
                    Ok(())
                } else {
                    Err(UnsupportedValue(value))
                }
            }
            gimli::DW_AT_abstract_origin | gimli::DW_AT_specification => {
                let value = value;
                log::trace!("  = {:?}", value);

                match value {
                    AttributeValue {
                        value: gimli::AttributeValue::UnitRef(offset),
                        ..
                    } => {
                        self.abstract_origin = Some(offset.to_debug_info_offset(&unit.raw_unit.header).unwrap());
                        Ok(())
                    }
                    AttributeValue {
                        value: gimli::AttributeValue::DebugInfoRef(target_offset),
                        ..
                    } => {
                        self.abstract_origin = Some(target_offset);
                        Ok(())
                    }
                    _ => Err(UnsupportedValue(value)),
                }
            }
            gimli::DW_AT_decl_file => match value {
                AttributeValue {
                    value: gimli::AttributeValue::FileIndex(index),
                    ..
                } => {
                    self.decl_file = Some(index as usize);
                    Ok(())
                }
                AttributeValue {
                    value: gimli::AttributeValue::Data1(index),
                    ..
                } => {
                    self.decl_file = Some(index as usize);
                    Ok(())
                }
                _ => Err(UnsupportedValue(value)),
            },
            gimli::DW_AT_call_file => match value {
                AttributeValue {
                    value: gimli::AttributeValue::FileIndex(index),
                    ..
                } => {
                    self.call_file = Some(index as usize);
                    Ok(())
                }
                AttributeValue {
                    value: gimli::AttributeValue::Data1(index),
                    ..
                } => {
                    self.call_file = Some(index as usize);
                    Ok(())
                }
                _ => Err(UnsupportedValue(value)),
            },
            gimli::DW_AT_decl_line => {
                if let AttributeValue {
                    value: ref inner,
                    offset: None,
                } = value
                {
                    if let Some(value) = inner.udata_value() {
                        self.decl_line = Some(value as u32);
                        Ok(())
                    } else {
                        Err(UnsupportedValue(value))
                    }
                } else {
                    Err(UnsupportedValue(value))
                }
            }
            gimli::DW_AT_call_line => {
                if let AttributeValue {
                    value: ref inner,
                    offset: None,
                } = value
                {
                    if let Some(value) = inner.udata_value() {
                        self.call_line = Some(value as u32);
                        Ok(())
                    } else {
                        Err(UnsupportedValue(value))
                    }
                } else {
                    Err(UnsupportedValue(value))
                }
            }
            gimli::DW_AT_call_column => {
                if let AttributeValue {
                    value: ref inner,
                    offset: None,
                } = value
                {
                    if let Some(value) = inner.udata_value() {
                        self.call_column = Some(value as u32);
                        Ok(())
                    } else {
                        Err(UnsupportedValue(value))
                    }
                } else {
                    Err(UnsupportedValue(value))
                }
            }
            gimli::DW_AT_declaration => match value {
                AttributeValue {
                    value: gimli::AttributeValue::Flag(value),
                    ..
                } => {
                    self.is_declaration = value;
                    Ok(())
                }
                _ => Err(UnsupportedValue(value)),
            },
            _ => Ok(()),
        }
        .map_err(move |UnsupportedValue(value): UnsupportedValue<R>| {
            ProgramFromElfError::other(format!("failed to process DWARF: unsupported value for {name}: {value:?}"))
        })
    }

    fn name(
        &self,
        dwarf: &gimli::Dwarf<R>,
        unit: &Unit<R>,
        string_cache: &mut StringCache,
    ) -> Result<Option<Arc<str>>, ProgramFromElfError> {
        let Some(value) = self.name.as_ref().or(self.linkage_name.as_ref()) else {
            return Ok(None);
        };

        let name = dwarf.attr_string(&unit.raw_unit, value.clone())?;
        let name = name.to_string_lossy()?;
        let name = string_cache.dedup(&name);
        Ok(Some(name))
    }

    fn resolve_abstract_origin<'a>(
        &self,
        sections: &Sections,
        relocations: &BTreeMap<SectionTarget, RelocationKind>,
        dwarf: &gimli::Dwarf<R>,
        units: &'a [Unit<R>],
    ) -> Result<Option<(&'a Unit<R>, Self)>, ProgramFromElfError> {
        if self.recursion_limit == 0 {
            return Err(ProgramFromElfError::other(
                "failed to process DWARF: recursion limit reached when resolving a name",
            ));
        }

        let Some(value) = self.abstract_origin else {
            return Ok(None);
        };

        let (target_unit, target_offset) = find_unit(units, value)?;
        let mut parser = AttributeParser::new(self.depth + 1, self.is_64bit);
        parser.recursion_limit = self.recursion_limit - 1;
        parser.try_match(sections, relocations, dwarf, target_unit, target_offset)?;

        Ok(Some((target_unit, parser)))
    }

    fn resolve_while(
        &self,
        sections: &Sections,
        relocations: &BTreeMap<SectionTarget, RelocationKind>,
        dwarf: &gimli::Dwarf<R>,
        units: &[Unit<R>],
        unit: &Unit<R>,
        mut callback: impl FnMut(&Unit<R>, &Self) -> Result<bool, ProgramFromElfError>,
    ) -> Result<(), ProgramFromElfError> {
        if self.recursion_limit == 0 {
            return Err(ProgramFromElfError::other(
                "failed to process DWARF: recursion limit reached when resolving abstract origins",
            ));
        }

        if callback(unit, self)? {
            if let Some((target_unit, parser)) = self.resolve_abstract_origin(sections, relocations, dwarf, units)? {
                return parser.resolve_while(sections, relocations, dwarf, units, target_unit, callback);
            }
        }

        Ok(())
    }
}

struct Sections<'a> {
    debug_info: &'a Section<'a>,
    debug_addr: Option<&'a Section<'a>>,
    debug_ranges: Option<&'a Section<'a>>,
    debug_rnglists: Option<&'a Section<'a>>,
    debug_line: Option<&'a Section<'a>>,
}

fn try_fetch_relocation(
    relocations: &BTreeMap<SectionTarget, RelocationKind>,
    relocation_target: SectionTarget,
    is_64bit: bool,
) -> Result<Option<SectionTarget>, ProgramFromElfError> {
    let Some(relocation) = relocations.get(&relocation_target) else {
        return Ok(None);
    };

    let target = match relocation {
        RelocationKind::Abs {
            target,
            size: RelocationSize::U64,
        } if is_64bit => target,
        RelocationKind::Abs {
            target,
            size: RelocationSize::U32,
        } => target,
        _ => {
            return Err(ProgramFromElfError::other(format!(
                "failed to process DWARF: unexpected relocation at {relocation_target}: {relocation:?}"
            )));
        }
    };

    Ok(Some(*target))
}

fn try_fetch_size_relocation(
    relocations: &BTreeMap<SectionTarget, RelocationKind>,
    relocation_target: SectionTarget,
    is_64bit: bool,
) -> Result<Option<(SectionIndex, AddressRange)>, ProgramFromElfError> {
    let Some(relocation) = relocations.get(&relocation_target) else {
        return Ok(None);
    };

    match relocation {
        RelocationKind::Size {
            section_index,
            range,
            size: SizeRelocationSize::Generic(..),
        } => Ok(Some((*section_index, *range))),
        RelocationKind::Abs {
            target,
            size: RelocationSize::U32,
        } => Ok(Some((target.section_index, (target.offset..target.offset).into()))),
        RelocationKind::Abs {
            target,
            size: RelocationSize::U64,
        } if is_64bit => Ok(Some((target.section_index, (target.offset..target.offset).into()))),
        _ => Err(ProgramFromElfError::other(format!(
            "failed to process DWARF: unexpected relocation at {relocation_target}: {relocation:?}"
        ))),
    }
}

fn fetch_size_relocation(
    relocations: &BTreeMap<SectionTarget, RelocationKind>,
    relocation_target: SectionTarget,
    is_64bit: bool,
) -> Result<(SectionIndex, AddressRange), ProgramFromElfError> {
    if let Some(target) = try_fetch_size_relocation(relocations, relocation_target, is_64bit)? {
        Ok(target)
    } else {
        Err(ProgramFromElfError::other(format!(
            "failed to process DWARF: {relocation_target} has no relocation"
        )))
    }
}

fn resolve_debug_addr_index<R>(
    debug_addr: Option<&Section>,
    relocations: &BTreeMap<SectionTarget, RelocationKind>,
    unit: &gimli::Unit<R>,
    index: gimli::DebugAddrIndex<R::Offset>,
    is_64bit: bool,
) -> Result<Option<SectionTarget>, ProgramFromElfError>
where
    R: gimli::Reader,
{
    if let Some(section) = debug_addr {
        let address = unit.addr_base.0 + R::Offset::from_u64(index.0.into_u64() * u64::from(unit.encoding().address_size))?;
        let offset = address.into_u64().checked_sub(section.original_address()).expect("underflow");
        let relocation_target = SectionTarget {
            section_index: section.index(),
            offset,
        };

        try_fetch_relocation(relocations, relocation_target, is_64bit)
    } else {
        Err(ProgramFromElfError::other("failed to process DWARF: missing '.debug_addr' section"))
    }
}

fn extract_paths<R>(
    dwarf: &gimli::Dwarf<R>,
    string_cache: &mut StringCache,
    raw_unit: &gimli::Unit<R>,
) -> Result<Vec<Arc<str>>, ProgramFromElfError>
where
    R: gimli::Reader,
{
    let mut output = Vec::new();
    let Some(program) = raw_unit.line_program.as_ref() else {
        return Ok(output);
    };

    let header = program.header();

    let mut dirs = Vec::new();
    let compilation_directory = if let Some(ref comp_dir) = raw_unit.comp_dir {
        comp_dir.to_string_lossy()?.into_owned()
    } else {
        String::new()
    };

    if header.version() < 5 {
        // Quoting section 6.2.4 of the DWARF standard:
        //   > Prior to DWARF Version 5, the current directory was not represented in the
        //   > directories field and a directory index of 0 implicitly referred to that directory as found
        //   > in the DW_AT_comp_dir attribute of the compilation unit debugging information
        //   > entry. In DWARF Version 5, the current directory is explicitly present in the
        //   > directories field.
        // ...
        //   > Prior to DWARF Version 5, the current compilation file name was not represented in
        //   > the file_names field. In DWARF Version 5, the current compilation file name is
        //   > explicitly present and has index 0.
        dirs.push(compilation_directory.clone());

        let empty = string_cache.dedup("");
        output.push(empty);
    }

    for dir in header.include_directories() {
        let value = dwarf.attr_string(raw_unit, dir.clone())?.to_string_lossy()?.into_owned();
        dirs.push(value);
    }

    for file in header.file_names().iter() {
        let filename = dwarf.attr_string(raw_unit, file.path_name())?.to_string_lossy()?.into_owned();
        let Some(directory) = dirs.get(file.directory_index() as usize) else {
            return Err(ProgramFromElfError::other(
                "failed to process DWARF: file refers to a directory index which doesn't exist",
            ));
        };

        fn has_unix_root(p: &str) -> bool {
            p.starts_with('/')
        }

        fn has_windows_root(p: &str) -> bool {
            p.starts_with('\\') || p.get(1..3) == Some(":\\")
        }

        let separator = if has_windows_root(&filename) || has_windows_root(directory) || has_windows_root(&compilation_directory) {
            '\\'
        } else {
            '/'
        };

        let mut path = String::new();
        if has_unix_root(&filename) || has_windows_root(&filename) {
            path = filename;
        } else {
            if file.directory_index() != 0 && !has_unix_root(directory) && !has_windows_root(directory) {
                path.push_str(&compilation_directory);
                if !path.is_empty() && !path.ends_with(separator) {
                    path.push(separator);
                }
            }

            path.push_str(directory);
            if !path.is_empty() && !path.ends_with(separator) {
                path.push(separator);
            }
            path.push_str(&filename);
        }

        let path = string_cache.dedup(&path);
        output.push(path);
    }

    Ok(output)
}

struct Unit<R>
where
    R: gimli::Reader,
{
    offset: gimli::DebugInfoOffset<R::Offset>,
    raw_unit: gimli::Unit<R>,
    low_pc: Option<SectionTarget>,
    paths: Vec<Arc<str>>,
}

fn extract_lines<R>(
    section_index: SectionIndex,
    relocations: &BTreeMap<SectionTarget, RelocationKind>,
    unit: &Unit<ReaderWrapper<R>>,
    is_64bit: bool,
) -> Result<Vec<LineEntry>, ProgramFromElfError>
where
    R: gimli::Reader,
{
    let mut lines = Vec::new();
    if let Some(mut program) = unit.raw_unit.line_program.clone() {
        let mut row = gimli::LineRow::new(program.header());
        let mut iter = program.header().instructions();

        let input = program.header().raw_program_buf();
        let mut target = None;
        loop {
            row.reset(program.header());
            let tracker = input.start_tracking();
            let Some(instruction) = iter.next_instruction(program.header())? else {
                break;
            };

            match instruction {
                LineInstruction::Special(..)
                | LineInstruction::Copy
                | LineInstruction::AdvanceLine(..)
                | LineInstruction::SetFile(..)
                | LineInstruction::SetColumn(..)
                | LineInstruction::NegateStatement
                | LineInstruction::SetBasicBlock
                | LineInstruction::SetPrologueEnd
                | LineInstruction::SetEpilogueBegin
                | LineInstruction::SetIsa(..)
                | LineInstruction::EndSequence
                | LineInstruction::DefineFile(..)
                | LineInstruction::SetDiscriminator(..)
                | LineInstruction::UnknownStandard0(..)
                | LineInstruction::UnknownStandard1(..)
                | LineInstruction::UnknownStandardN(..)
                | LineInstruction::UnknownExtended(..) => {}

                LineInstruction::AdvancePc(..) | LineInstruction::ConstAddPc => {
                    return Err(ProgramFromElfError::other(
                        "failed to process DWARF: unsupported line program instruction: {instruction:?}",
                    ));
                }

                LineInstruction::SetAddress(..) => {
                    let relocation_target = SectionTarget {
                        section_index,
                        offset: *tracker.list().last().unwrap(),
                    };

                    target = try_fetch_relocation(relocations, relocation_target, is_64bit)?;
                }

                LineInstruction::FixedAddPc(..) => {
                    let relocation_target = SectionTarget {
                        section_index,
                        offset: *tracker.list().last().unwrap(),
                    };

                    target =
                        try_fetch_size_relocation(relocations, relocation_target, is_64bit)?.map(|(target_section_index, target_range)| {
                            SectionTarget {
                                section_index: target_section_index,
                                offset: target_range.end,
                            }
                        });
                }
            }

            if !row.execute(instruction, &mut program)? {
                continue;
            }

            let tombstone_address = !0 >> (64 - program.header().encoding().address_size * 8);
            if row.address() == tombstone_address {
                continue;
            }

            let Some(path) = unit.paths.get(row.file_index() as usize) else {
                return Err(ProgramFromElfError::other(
                    "failed to process DWARF: out of bounds file index encountered when processing line programs",
                ));
            };

            let location = match (row.line(), row.column()) {
                (None, _) => SourceCodeLocation::Path { path: Arc::clone(path) },
                (Some(line), gimli::ColumnType::LeftEdge) => SourceCodeLocation::Line {
                    path: Arc::clone(path),
                    line: line.get() as u32,
                },
                (Some(line), gimli::ColumnType::Column(column)) => SourceCodeLocation::Column {
                    path: Arc::clone(path),
                    line: line.get() as u32,
                    column: column.get() as u32,
                },
            };

            struct Flags<'a>(&'a gimli::LineRow);
            impl<'a> core::fmt::Display for Flags<'a> {
                fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
                    let mut dirty = false;
                    if self.0.is_stmt() {
                        fmt.write_str("[stmt")?;
                        dirty = true;
                    }
                    if self.0.end_sequence() {
                        if dirty {
                            fmt.write_str(", ")?;
                        } else {
                            fmt.write_str("[")?;
                        }
                        fmt.write_str("end_seq")?;
                        dirty = true;
                    }
                    if self.0.prologue_end() {
                        if dirty {
                            fmt.write_str(", ")?;
                        } else {
                            fmt.write_str("[")?;
                        }
                        fmt.write_str("prologue_end")?;
                        dirty = true;
                    }
                    if self.0.epilogue_begin() {
                        if dirty {
                            fmt.write_str(", ")?;
                        } else {
                            fmt.write_str("[")?;
                        }
                        fmt.write_str("epilogue_begin")?;
                        dirty = true;
                    }
                    if dirty {
                        fmt.write_str("]")?;
                    }
                    Ok(())
                }
            }

            let Some(target) = target else {
                // Sometimes the entries seem to not have any relocation attached to them
                // and have all zeros set by the compiler, e.g. I've seen this as the end
                // of the line program:
                //
                //   0x0009b494  [ 197,26] NS
                //   0x0009b49c  [ 215,36] NS
                //   0x0009b4a0  [ 215, 5]
                //   0x0009b4a4  [ 215, 5] ET
                //   0x00000000  [2046, 0] NS uri: "libs/libcxx/include/string"
                //   0x00000000  [2047, 9] NS PE
                //   0x00000000  [2047, 9] NS ET
                //   0x00000000  [ 259, 0] NS uri: "libs/libcxx/include/stdexcept"
                //   0x00000000  [ 263, 5] NS PE
                //   0x00000000  [ 263, 5] NS ET
                log::trace!("Line entry without a relocation: {row:?}");
                continue;
            };

            log::trace!(
                "Line entry: 0x{:x} (0x{offset:x}) {location:?} {}",
                row.address(),
                Flags(&row),
                offset = target.offset
            );
            let entry = LineEntry { target, location };
            lines.push(entry);
        }
    }

    // These should already be sorted, but sort them anyway.
    lines.sort_by_key(|entry| entry.target.offset);

    Ok(lines)
}

fn finalize_inline_frames<R>(
    subprogram_offset_to_namespace: &HashMap<gimli::DebugInfoOffset<R::Offset>, Option<Arc<str>>>,
    inlined: &mut Inlined<R>,
) -> Result<(), ProgramFromElfError>
where
    R: gimli::Reader,
{
    for child in &mut inlined.inlined {
        let Some(namespace) = subprogram_offset_to_namespace.get(&inlined.abstract_origin) else {
            return Err(ProgramFromElfError::other(format!(
                "failed to process DWARF: inline subroutine '{}' found with no corresponding subprogram (abstract origin = {:?})",
                inlined.function_name.as_deref().unwrap_or(""),
                inlined.abstract_origin
            )));
        };

        child.namespace = namespace.clone();
        finalize_inline_frames::<R>(subprogram_offset_to_namespace, child)?;
    }

    Ok(())
}

fn get_function_line_region_id(
    function_line_boundaries_for_file: &BTreeMap<Arc<str>, Vec<u32>>,
    location: &SourceCodeLocation,
) -> Option<(usize, isize)> {
    let (path, line) = match location {
        SourceCodeLocation::Path { .. } => return None,
        SourceCodeLocation::Line { path, line } | SourceCodeLocation::Column { path, line, .. } => (path, line),
    };

    let boundaries = function_line_boundaries_for_file.get(path)?;
    let index = match boundaries.binary_search(line) {
        Ok(index) => index as isize + 1,
        Err(index) => index as isize,
    };

    Some((boundaries.as_ptr() as usize, index))
}

struct DwarfWalker<'a, R>
where
    R: gimli::Reader,
{
    sections: Sections<'a>,
    relocations: &'a BTreeMap<SectionTarget, RelocationKind>,
    dwarf: &'a gimli::Dwarf<ReaderWrapper<R>>,
    units: &'a [Unit<ReaderWrapper<R>>],
    depth: usize,
    inline_depth: usize,
    namespace_buffer: Vec<String>,
    subprograms: Vec<SubProgram<R>>,
    strings: &'a mut StringCache,
    is_64bit: bool,
}

impl<'a, R> DwarfWalker<'a, R>
where
    R: gimli::Reader,
{
    fn run(mut self) -> Result<HashMap<SectionTarget, Arc<[Location]>>, ProgramFromElfError> {
        let mut lines_for_unit: Vec<Vec<LineEntry>> = Vec::new();
        let mut subprograms_for_unit: Vec<Vec<SubProgram<R>>> = Vec::new();
        let mut subprogram_offset_to_namespace: HashMap<gimli::DebugInfoOffset<R::Offset>, Option<Arc<str>>> = Default::default();
        let mut function_line_boundaries_for_file: BTreeMap<Arc<str>, Vec<u32>> = BTreeMap::new();
        for unit in self.units {
            let mut subprograms = self.parse_tree(unit)?;
            subprograms.retain(|subprogram| {
                subprogram_offset_to_namespace.insert(subprogram.offset, subprogram.namespace.clone());

                if !subprogram.is_declaration {
                    // If it's just a declaration (e.g. `extern int foobar();`) then skip it, as that
                    // can also be defined inside of function bodies.
                    match subprogram.decl_location {
                        None | Some(SourceCodeLocation::Path { .. }) => {}
                        Some(SourceCodeLocation::Line { ref path, line } | SourceCodeLocation::Column { ref path, line, .. }) => {
                            function_line_boundaries_for_file
                                .entry(Arc::clone(path))
                                .or_insert_with(Vec::new)
                                .push(line);
                        }
                    }
                }

                !subprogram.sources.is_empty()
            });
            subprograms_for_unit.push(subprograms);

            let lines = if let Some(debug_line) = self.sections.debug_line {
                extract_lines(debug_line.index(), self.relocations, unit, self.is_64bit)?
            } else {
                Default::default()
            };

            lines_for_unit.push(lines);
        }

        for subprograms in &mut subprograms_for_unit {
            for subprogram in subprograms {
                for inlined in &mut subprogram.inlined {
                    finalize_inline_frames::<R>(&subprogram_offset_to_namespace, inlined)?;
                }
            }
        }

        for (filename, boundaries) in &mut function_line_boundaries_for_file {
            boundaries.sort();
            boundaries.dedup();

            log::trace!("Function line boundaries for '{filename}':");
            for window in boundaries.windows(2) {
                log::trace!("  {} - {}", window[0], window[1]);
            }
        }

        enum LocationKindRef<'a, R>
        where
            R: gimli::Reader,
        {
            InlineCall(&'a Inlined<R>),
            InlineDecl(&'a Inlined<R>),
            Line {
                namespace: Option<Arc<str>>,
                function_name: Option<Arc<str>>,
                entry: &'a LineEntry,
            },
        }

        impl<'a, R> PartialEq for LocationKindRef<'a, R>
        where
            R: gimli::Reader,
        {
            fn eq(&self, rhs: &Self) -> bool {
                match (self, rhs) {
                    (Self::InlineCall(lhs), Self::InlineCall(rhs)) => core::ptr::eq(*lhs, *rhs),
                    (Self::InlineDecl(lhs), Self::InlineDecl(rhs)) => core::ptr::eq(*lhs, *rhs),
                    (Self::Line { entry: lhs, .. }, Self::Line { entry: rhs, .. }) => core::ptr::eq(*lhs, *rhs),
                    _ => false,
                }
            }
        }

        impl<'a, R> Eq for LocationKindRef<'a, R> where R: gimli::Reader {}

        type LocationsForOffset<'a, R> = BTreeMap<u64, Vec<LocationKindRef<'a, R>>>;
        fn gather_inline<'a, R>(output: &mut LocationsForOffset<'a, R>, inlined: &'a Inlined<R>)
        where
            R: gimli::Reader,
        {
            let inline_source = inlined.source;
            for offset in (inline_source.offset_range.start..inline_source.offset_range.end).step_by(2) {
                let list = output.get_mut(&offset).unwrap();
                if inlined.call_location.is_some() {
                    list.push(LocationKindRef::InlineCall(inlined));
                }

                if inlined.decl_location.is_some() {
                    list.push(LocationKindRef::InlineDecl(inlined));
                }
            }

            for child in &inlined.inlined {
                gather_inline(output, child);
            }
        }

        let mut location_map: HashMap<SectionTarget, Arc<[Location]>> = HashMap::new();
        for (subprograms, all_lines) in subprograms_for_unit.into_iter().zip(lines_for_unit.into_iter()) {
            let mut lines_for_section: HashMap<SectionIndex, Vec<&LineEntry>> = HashMap::new();
            for entry in &all_lines {
                lines_for_section
                    .entry(entry.target.section_index)
                    .or_insert_with(Vec::new)
                    .push(entry);
            }

            let line_range_map_for_section: HashMap<SectionIndex, RangeMap<&LineEntry>> = lines_for_section
                .into_iter()
                .map(|(section_index, local_lines)| {
                    let line_boundaries: Vec<u64> = local_lines.iter().map(|entry| entry.target.offset).collect();
                    let line_ranges = line_boundaries.windows(2).map(|w| w[0]..w[1]);
                    let line_range_map: RangeMap<&LineEntry> = line_ranges.zip(local_lines.into_iter()).collect();
                    (section_index, line_range_map)
                })
                .collect();

            for subprogram in subprograms {
                let source = subprogram.sources[0];
                let section_index = source.section_index;
                let line_range_map = line_range_map_for_section.get(&section_index).unwrap();
                log::trace!("  Frame: {}", source);

                let mut map: LocationsForOffset<R> = BTreeMap::new();
                for offset in (source.offset_range.start..source.offset_range.end).step_by(2) {
                    map.insert(offset, Vec::new());
                }

                for inlined in &subprogram.inlined {
                    gather_inline(&mut map, inlined);
                }

                #[allow(clippy::type_complexity)]
                let mut last_emitted: Option<(Vec<LocationKindRef<R>>, Arc<[Location]>)> = None;
                for offset in (source.offset_range.start..source.offset_range.end).step_by(2) {
                    let mut list = map.remove(&offset).unwrap();
                    let mut fallback = false;
                    if let Some(line_entry) = line_range_map.get_value(offset) {
                        let target_position = {
                            // I'm not entirely sure if this is actually necessary; are the line entries always guaranteed
                            // to be part of the innermost last frame or not? But just in case let's do this anyway.
                            if let Some(line_entry_region) =
                                get_function_line_region_id(&function_line_boundaries_for_file, &line_entry.location)
                            {
                                // Find the position where it'll be the most appropriate to insert the line entry.
                                let mut target_position = None;
                                for (position, kind) in list.iter().enumerate() {
                                    match kind {
                                        LocationKindRef::InlineCall(inlined) => {
                                            let call_location = inlined.call_location.as_ref().unwrap();
                                            if Some(line_entry_region)
                                                == get_function_line_region_id(&function_line_boundaries_for_file, call_location)
                                            {
                                                if line_entry.location < *call_location {
                                                    target_position =
                                                        Some((position, inlined.namespace.clone(), inlined.function_name.clone()));
                                                } else {
                                                    target_position =
                                                        Some((position + 1, inlined.namespace.clone(), inlined.function_name.clone()));
                                                }

                                                break;
                                            }
                                        }
                                        LocationKindRef::InlineDecl(inlined) => {
                                            let decl_location = inlined.decl_location.as_ref().unwrap();
                                            if Some(line_entry_region)
                                                == get_function_line_region_id(&function_line_boundaries_for_file, decl_location)
                                            {
                                                target_position =
                                                    Some((position + 1, inlined.namespace.clone(), inlined.function_name.clone()));
                                                break;
                                            }
                                        }
                                        LocationKindRef::Line { .. } => unreachable!(),
                                    }
                                }
                                if target_position.is_none() {
                                    if let Some(ref subprogram_decl_location) = subprogram.decl_location {
                                        let subprogram_region =
                                            get_function_line_region_id(&function_line_boundaries_for_file, subprogram_decl_location);
                                        if Some(line_entry_region) == subprogram_region {
                                            target_position = Some((0, subprogram.namespace.clone(), subprogram.function_name.clone()));
                                        }
                                    }
                                }
                                target_position
                            } else {
                                None
                            }
                        };

                        // If there's no line number then these are useless, so skip them if that's the case.
                        if !matches!(line_entry.location, SourceCodeLocation::Path { .. }) {
                            if let Some((target_position, namespace, function_name)) = target_position {
                                let entry = LocationKindRef::Line {
                                    entry: line_entry,
                                    namespace,
                                    function_name,
                                };
                                list.insert(target_position, entry);
                            } else {
                                log::warn!("No matching DWARF subprogram found for line at {:?}", line_entry.location);
                                fallback = true;

                                let (namespace, function_name) = match list.last() {
                                    Some(LocationKindRef::InlineCall(inlined) | LocationKindRef::InlineDecl(inlined)) => {
                                        (inlined.namespace.clone(), inlined.function_name.clone())
                                    }
                                    Some(LocationKindRef::Line { .. }) => unreachable!(),
                                    None => (subprogram.namespace.clone(), subprogram.function_name.clone()),
                                };

                                let entry = LocationKindRef::Line {
                                    entry: line_entry,
                                    namespace,
                                    function_name,
                                };
                                list.push(entry);
                            }
                        }
                    }

                    log::trace!("    +{}:", offset);
                    log::trace!(
                        "      entr: region={:?}, depth=0, fn={:?}, decl_location={:?}",
                        subprogram
                            .decl_location
                            .as_ref()
                            .and_then(|location| get_function_line_region_id(&function_line_boundaries_for_file, location)),
                        subprogram.function_name,
                        subprogram.decl_location,
                    );

                    for kind in &list {
                        match kind {
                            LocationKindRef::InlineCall(inlined) => {
                                let call_region = inlined
                                    .call_location
                                    .as_ref()
                                    .and_then(|location| get_function_line_region_id(&function_line_boundaries_for_file, location));
                                log::trace!(
                                    "      call: region={:?}, depth={}, fn={:?}, call_location={:?}",
                                    call_region,
                                    inlined.depth - 1,
                                    inlined.function_name,
                                    inlined.call_location,
                                );
                            }
                            LocationKindRef::InlineDecl(inlined) => {
                                let decl_region = inlined
                                    .decl_location
                                    .as_ref()
                                    .and_then(|location| get_function_line_region_id(&function_line_boundaries_for_file, location));
                                log::trace!(
                                    "      entr: region={:?}, depth={} -> {}, fn={:?}, decl_location={:?}",
                                    decl_region,
                                    inlined.depth - 1,
                                    inlined.depth,
                                    inlined.function_name,
                                    inlined.decl_location,
                                );
                            }
                            LocationKindRef::Line {
                                entry: line_entry,
                                function_name,
                                ..
                            } => {
                                let region = get_function_line_region_id(&function_line_boundaries_for_file, &line_entry.location);
                                log::trace!(
                                    "      line: region={:?}, fn={:?}, location={:?}",
                                    region,
                                    function_name,
                                    line_entry.location
                                );
                                if fallback {
                                    log::trace!("      (FALLBACK)");
                                }
                            }
                        }
                    }

                    let target = SectionTarget { section_index, offset };

                    if let Some((ref last_list, ref last_arc_list)) = last_emitted {
                        if list == *last_list {
                            location_map.insert(target, Arc::clone(last_arc_list));
                            continue;
                        }
                    }

                    let mut arc_list = Vec::new();
                    arc_list.reserve_exact(list.len() + 1);
                    arc_list.push(Location {
                        kind: FrameKind::Enter,
                        namespace: subprogram.namespace.clone(),
                        function_name: subprogram.function_name.clone(),
                        source_code_location: subprogram.decl_location.clone(),
                    });

                    for kind in &list {
                        let location = match kind {
                            LocationKindRef::InlineCall(inlined) => Location {
                                kind: FrameKind::Call,
                                namespace: inlined.namespace.clone(),
                                function_name: inlined.function_name.clone(),
                                source_code_location: inlined.call_location.clone(),
                            },
                            LocationKindRef::InlineDecl(inlined) => Location {
                                kind: FrameKind::Enter,
                                namespace: inlined.namespace.clone(),
                                function_name: inlined.function_name.clone(),
                                source_code_location: inlined.decl_location.clone(),
                            },
                            LocationKindRef::Line {
                                entry: line_entry,
                                namespace,
                                function_name,
                            } => Location {
                                kind: FrameKind::Line,
                                namespace: namespace.clone(),
                                function_name: function_name.clone(),
                                source_code_location: Some(line_entry.location.clone()),
                            },
                        };

                        arc_list.push(location);
                    }

                    let arc_list: Arc<[Location]> = arc_list.into();
                    location_map.insert(target, Arc::clone(&arc_list));
                    last_emitted = Some((list, arc_list));
                }
            }
        }

        Ok(location_map)
    }

    fn parse_tree(&mut self, unit: &Unit<ReaderWrapper<R>>) -> Result<Vec<SubProgram<R>>, ProgramFromElfError> {
        assert!(self.namespace_buffer.is_empty());
        assert!(self.subprograms.is_empty());
        assert_eq!(self.depth, 0);
        assert_eq!(self.inline_depth, 0);

        let mut tree = unit.raw_unit.entries_tree(None)?;
        let node = tree.root()?;
        self.walk(unit, node)?;
        self.subprograms.sort_by_key(|subprogram| subprogram.sources.get(0).copied());

        Ok(self.subprograms.drain(..).collect())
    }

    fn resolve_namespace(&mut self) -> Option<Arc<str>> {
        if self.namespace_buffer.is_empty() {
            None
        } else {
            Some(self.strings.dedup(&self.namespace_buffer.join("::")))
        }
    }

    fn walk(
        &mut self,
        unit: &Unit<ReaderWrapper<R>>,
        node: gimli::EntriesTreeNode<ReaderWrapper<R>>,
    ) -> Result<Vec<Inlined<R>>, ProgramFromElfError> {
        let buffer_initial_length = self.namespace_buffer.len();
        let node_entry = node.entry();
        let Some(node_offset) = node_entry.offset().to_debug_info_offset(&unit.raw_unit.header) else {
            return Ok(Default::default());
        };

        log::trace!(
            "{:08x} {:->depth$}{name} ({node_offset:?})",
            node_entry.offset().0.into_u64(),
            ">",
            depth = self.depth,
            name = node_entry.tag()
        );

        let node_tag = node_entry.tag();
        if node_tag == gimli::DW_TAG_inlined_subroutine {
            self.inline_depth += 1;
        }

        let mut current_subprogram = None;
        let mut current_inlined = Vec::new();
        match node_tag {
            gimli::DW_TAG_namespace | gimli::DW_TAG_structure_type | gimli::DW_TAG_enumeration_type => {
                let mut attrs = node_entry.attrs();
                while let Some(attribute) = attrs.next()? {
                    #[allow(clippy::single_match)]
                    match attribute.name() {
                        gimli::DW_AT_name => {
                            let name = self
                                .dwarf
                                .attr_string(&unit.raw_unit, attribute.value())?
                                .to_string_lossy()?
                                .into_owned();
                            self.namespace_buffer.push(name);
                            log::trace!("  Namespace: {:?}", self.namespace_buffer);
                        }
                        _ => {}
                    }
                }
            }
            gimli::DW_TAG_subprogram => {
                if self.inline_depth > 0 {
                    return Err(ProgramFromElfError::other(
                        "failed to process DWARF: found a DW_TAG_subprogram while inline depth is greater than zero",
                    ));
                }

                let mut parser = AttributeParser::new(self.depth + 1, self.is_64bit);
                for pair in iter_attributes(self.dwarf, &unit.raw_unit, node_entry.offset())? {
                    let (name, value) = pair?;
                    parser.try_match_attribute(&self.sections, self.relocations, self.dwarf, unit, name, value)?;
                }

                let namespace = self.resolve_namespace();
                let mut name = None;
                let mut path = None;
                let mut line = None;
                parser.resolve_while(
                    &self.sections,
                    self.relocations,
                    self.dwarf,
                    self.units,
                    unit,
                    |parser_unit, parser| {
                        if name.is_none() {
                            name = parser.name(self.dwarf, unit, self.strings)?;
                        }

                        if path.is_none() {
                            path = parser.decl_file.and_then(|index| parser_unit.paths.get(index)).cloned();
                        }

                        if line.is_none() {
                            line = parser.decl_line;
                        }

                        Ok(name.is_none() || path.is_none() || line.is_none())
                    },
                )?;

                log::trace!("  In namespace: {:?}", self.namespace_buffer);
                log::trace!("  Subprogram name: {:?}", name);
                log::trace!("  Subprogram decl location: {:?} {:?}", path, line);

                let decl_location = match (path, line) {
                    (Some(path), Some(line)) => Some(SourceCodeLocation::Line { path, line }),
                    (Some(path), None) => Some(SourceCodeLocation::Path { path }),
                    (None, None) => None,
                    (None, Some(_)) => {
                        return Err(ProgramFromElfError::other(
                            "failed to process DWARF: subprogram has a decl line but no decl file",
                        ));
                    }
                };

                if decl_location.is_some() && name.is_none() {
                    return Err(ProgramFromElfError::other(
                        "failed to process DWARF: subprogram has a decl location but no name",
                    ));
                }

                let mut subprogram = SubProgram::<R> {
                    sources: Vec::new(),
                    offset: node_offset,
                    inlined: Vec::new(),
                    namespace,
                    function_name: name,
                    decl_location,
                    is_declaration: parser.is_declaration,
                };

                parser.for_each_range(&self.sections, self.relocations, unit, |source| {
                    if !source.offset_range.is_empty() {
                        subprogram.sources.push(source);
                    }
                })?;

                if subprogram.sources.len() > 1 {
                    return Err(ProgramFromElfError::other(
                        "failed to process DWARF: found a subprogram with multiple sources",
                    ));
                }

                current_subprogram = Some(subprogram);
            }
            gimli::DW_TAG_inlined_subroutine => {
                let mut parser = AttributeParser::new(self.depth + 1, self.is_64bit);
                for pair in iter_attributes(self.dwarf, &unit.raw_unit, node_entry.offset())? {
                    let (name, value) = pair?;
                    parser.try_match_attribute(&self.sections, self.relocations, self.dwarf, unit, name, value)?;
                }

                let mut name = None;
                let mut decl_path = None;
                let mut decl_line = None;
                let mut call_path = None;
                let mut call_line = None;
                let mut call_column = None;
                parser.resolve_while(
                    &self.sections,
                    self.relocations,
                    self.dwarf,
                    self.units,
                    unit,
                    |parser_unit, parser| {
                        if name.is_none() {
                            name = parser.name(self.dwarf, unit, self.strings)?;
                        }

                        if decl_path.is_none() {
                            decl_path = parser.decl_file.and_then(|index| parser_unit.paths.get(index)).cloned();
                        }

                        if decl_line.is_none() {
                            decl_line = parser.decl_line;
                        }

                        if call_path.is_none() {
                            call_path = parser.call_file.and_then(|index| parser_unit.paths.get(index)).cloned();
                        }

                        if call_line.is_none() {
                            call_line = parser.call_line;
                        }

                        if call_column.is_none() {
                            call_column = parser.call_column;
                        }

                        Ok(name.is_none()
                            || decl_path.is_none()
                            || decl_line.is_none()
                            || call_path.is_none()
                            || call_line.is_none()
                            || call_column.is_none())
                    },
                )?;

                log::trace!("  Inlined depth: {}", self.inline_depth);
                log::trace!("  Inlined subroutine name: {:?}", name);
                log::trace!("  Inlined subroutine decl location: {:?} {:?}", decl_path, decl_line);
                log::trace!(
                    "  Inlined subroutine call location: {:?} {:?} {:?}",
                    call_path,
                    call_line,
                    call_column
                );
                log::trace!("  Inlined subroutine abstract origin: {:?}", parser.abstract_origin);

                if decl_line.is_some() && decl_path.is_none() {
                    return Err(ProgramFromElfError::other(
                        "failed to process DWARF: subprogram has a decl line but no decl file",
                    ));
                }

                if decl_path.is_some() && name.is_none() {
                    return Err(ProgramFromElfError::other(
                        "failed to process DWARF: subprogram has a decl file but no name",
                    ));
                }

                if call_column.is_some() && call_line.is_none() {
                    return Err(ProgramFromElfError::other(
                        "failed to process DWARF: inline subroutine has a call column but no call line",
                    ));
                }

                if call_line.is_some() && call_path.is_none() {
                    return Err(ProgramFromElfError::other(
                        "failed to process DWARF: inline subroutine has a call line but no call file",
                    ));
                }

                if call_path.is_some() && name.is_none() {
                    return Err(ProgramFromElfError::other(
                        "failed to process DWARF: inline subroutine has a call file but no name",
                    ));
                }

                let call_location = match (call_path, call_line, call_column) {
                    (Some(path), Some(line), Some(column)) => Some(SourceCodeLocation::Column { path, line, column }),
                    (Some(path), Some(line), None) => Some(SourceCodeLocation::Line { path, line }),
                    (Some(path), None, None) => Some(SourceCodeLocation::Path { path }),
                    (None, None, None) => None,
                    (None, Some(_), _) => {
                        return Err(ProgramFromElfError::other(
                            "failed to process DWARF: inline subroutine has a call line but no call file",
                        ));
                    }
                    (_, None, Some(_)) => {
                        return Err(ProgramFromElfError::other(
                            "failed to process DWARF: inline subroutine has a call column but no call line",
                        ));
                    }
                };

                let decl_location = match (decl_path, decl_line) {
                    (Some(path), Some(line)) => Some(SourceCodeLocation::Line { path, line }),
                    (Some(path), None) => Some(SourceCodeLocation::Path { path }),
                    (None, None) => None,
                    (None, Some(_)) => {
                        return Err(ProgramFromElfError::other(
                            "failed to process DWARF: inline subroutine has a decl line but no decl file",
                        ));
                    }
                };

                let Some(abstract_origin) = parser.abstract_origin else {
                    return Err(ProgramFromElfError::other(
                        "failed to process DWARF: inline subroutine has no abstract origin",
                    ));
                };

                parser.for_each_range(&self.sections, self.relocations, unit, |source| {
                    let inlined = Inlined {
                        source,
                        inlined: Vec::new(),
                        depth: self.inline_depth as u32,
                        namespace: Default::default(),
                        abstract_origin,
                        function_name: name.clone(),
                        call_location: call_location.clone(),
                        decl_location: decl_location.clone(),
                    };

                    current_inlined.push(inlined);
                })?;

                if current_inlined.is_empty() {
                    log::trace!("Found inline subroutine with no source! (name = {name:?})");
                }
            }
            _ => {}
        }

        self.depth += 1;
        let mut children = node.children();
        let mut child_inlined = Vec::new();
        while let Some(child) = children.next()? {
            child_inlined.extend(self.walk(unit, child)?);
        }
        self.depth -= 1;
        self.namespace_buffer.truncate(buffer_initial_length);

        child_inlined.sort_by_key(|inlined| (inlined.source.offset_range.start, inlined.depth, !inlined.source.offset_range.end));
        for inlined in &child_inlined {
            log::trace!(
                "  Inline frame: depth={}, fn={:?}, decl_location={:?}",
                inlined.depth,
                inlined.function_name,
                inlined.decl_location,
            );
        }

        if node_tag == gimli::DW_TAG_subprogram {
            assert!(current_inlined.is_empty());

            let mut subprogram = current_subprogram.unwrap();
            assert!(subprogram.inlined.is_empty());

            for parent_source in &subprogram.sources {
                let mut previous: Option<Source> = None;
                for inlined in &child_inlined {
                    let inline_source = inlined.source;
                    if inline_source.section_index != parent_source.section_index {
                        return Err(ProgramFromElfError::other(
                            "failed to process DWARF: found inline subroutine with a different target section than its parent subprogram",
                        ));
                    }

                    if inline_source.offset_range.start < parent_source.offset_range.start
                        || inline_source.offset_range.end > parent_source.offset_range.end
                    {
                        return Err(ProgramFromElfError::other(
                            format!(
                                "failed to process DWARF: found inline subroutine which exceedes the bounds of its parent subprogram (parent = {}, inline = {})",
                                parent_source, inline_source
                            )
                        ));
                    }

                    if let Some(last_source) = previous {
                        if inline_source.offset_range.start < last_source.offset_range.end {
                            return Err(ProgramFromElfError::other(
                                "failed to process DWARF: found overlapping inline subroutines in a parent subprogram",
                            ));
                        }
                    }

                    previous = Some(inline_source);
                }
            }

            subprogram.inlined = child_inlined;
            child_inlined = Default::default();
            self.subprograms.push(subprogram);
        } else if node_tag == gimli::DW_TAG_inlined_subroutine {
            assert!(current_subprogram.is_none());
            self.inline_depth -= 1;

            for inlined in &mut current_inlined {
                assert!(inlined.inlined.is_empty());

                let mut previous: Option<Source> = None;
                for child in &child_inlined {
                    if child.source.offset_range.end <= inlined.source.offset_range.start
                        || child.source.offset_range.start >= inlined.source.offset_range.end
                    {
                        continue;
                    }

                    let mut child = child.clone();
                    child.source.offset_range.start = core::cmp::max(child.source.offset_range.start, inlined.source.offset_range.start);
                    child.source.offset_range.end = core::cmp::min(child.source.offset_range.end, inlined.source.offset_range.end);

                    if let Some(last_source) = previous {
                        if child.source.offset_range.start < last_source.offset_range.end {
                            return Err(ProgramFromElfError::other(
                                "failed to process DWARF: found overlapping inline subroutines in a parent inline subroutine",
                            ));
                        }
                    }

                    previous = Some(child.source);
                    inlined.inlined.push(child);
                }
            }

            child_inlined = current_inlined;
        }

        Ok(child_inlined)
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum SourceCodeLocation {
    Path { path: Arc<str> },
    Line { path: Arc<str>, line: u32 },
    Column { path: Arc<str>, line: u32, column: u32 },
}

impl SourceCodeLocation {
    pub(crate) fn path(&self) -> &Arc<str> {
        match self {
            Self::Path { path } | Self::Line { path, .. } | Self::Column { path, .. } => path,
        }
    }

    pub(crate) fn line(&self) -> Option<u32> {
        match self {
            Self::Path { .. } => None,
            Self::Line { line, .. } | Self::Column { line, .. } => Some(*line),
        }
    }

    pub(crate) fn column(&self) -> Option<u32> {
        match self {
            Self::Path { .. } | Self::Line { .. } => None,
            Self::Column { column, .. } => Some(*column),
        }
    }
}

impl core::fmt::Debug for SourceCodeLocation {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            Self::Path { path } => write!(fmt, "{path}"),
            Self::Line { path, line } => write!(fmt, "{path}:{line}"),
            Self::Column { path, line, column } => write!(fmt, "{path}:{line}:{column}"),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Hash)]
pub(crate) struct Location {
    pub kind: FrameKind,
    pub namespace: Option<Arc<str>>,
    pub function_name: Option<Arc<str>>,
    pub source_code_location: Option<SourceCodeLocation>,
}

struct SubProgram<R>
where
    R: gimli::Reader,
{
    offset: gimli::DebugInfoOffset<R::Offset>,
    sources: Vec<Source>,
    inlined: Vec<Inlined<R>>,
    namespace: Option<Arc<str>>,
    function_name: Option<Arc<str>>,
    decl_location: Option<SourceCodeLocation>,
    is_declaration: bool,
}

#[derive(Clone)]
struct Inlined<R>
where
    R: gimli::Reader,
{
    source: Source,
    inlined: Vec<Inlined<R>>,
    depth: u32,
    abstract_origin: gimli::DebugInfoOffset<R::Offset>,
    namespace: Option<Arc<str>>,
    function_name: Option<Arc<str>>,
    decl_location: Option<SourceCodeLocation>,
    call_location: Option<SourceCodeLocation>,
}

#[derive(Clone, PartialEq, Eq)]
struct LineEntry {
    target: SectionTarget,
    location: SourceCodeLocation,
}

#[derive(Default)]
pub(crate) struct DwarfInfo {
    // This is not the most efficient representation, but it's invariant
    // to any transformations that might be applied to the code.
    pub location_map: HashMap<SectionTarget, Arc<[Location]>>,
}

struct AttributeValue<R>
where
    R: gimli::Reader,
{
    value: gimli::AttributeValue<R>,
    offset: Option<R::Offset>,
}

impl<R> Clone for AttributeValue<R>
where
    R: gimli::Reader,
{
    fn clone(&self) -> Self {
        AttributeValue {
            value: self.value.clone(),
            offset: self.offset,
        }
    }
}

impl<R> core::fmt::Debug for AttributeValue<R>
where
    R: gimli::Reader,
{
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
        fmt.debug_struct("AttributeValue")
            .field("value", &self.value)
            .field("offset", &self.offset)
            .finish()
    }
}

// This is mostly copied verbatim from gimli.
fn parse_attribute<R>(
    input_base: &R,
    input: &mut R,
    encoding: gimli::Encoding,
    attribute: gimli::AttributeSpecification,
) -> Result<AttributeValue<R>, ProgramFromElfError>
where
    R: gimli::Reader,
{
    use gimli::{
        AttributeValue, DebugAddrIndex, DebugInfoOffset, DebugLineStrOffset, DebugLocListsIndex, DebugRngListsIndex, DebugStrOffset,
        DebugStrOffsetsIndex, DebugTypeSignature, Expression, UnitOffset,
    };

    fn length_u8_value<R: Reader>(input: &mut R) -> gimli::Result<R> {
        let len = input.read_u8().map(R::Offset::from_u8)?;
        input.split(len)
    }

    fn length_u16_value<R: Reader>(input: &mut R) -> gimli::Result<R> {
        let len = input.read_u16().map(R::Offset::from_u16)?;
        input.split(len)
    }

    fn length_u32_value<R: Reader>(input: &mut R) -> gimli::Result<R> {
        let len = input.read_u32().map(R::Offset::from_u32)?;
        input.split(len)
    }

    fn length_uleb128_value<R: Reader>(input: &mut R) -> gimli::Result<R> {
        let len = input.read_uleb128().and_then(R::Offset::from_u64)?;
        input.split(len)
    }

    fn allow_section_offset(name: gimli::constants::DwAt, version: u16) -> bool {
        match name {
            gimli::constants::DW_AT_location
            | gimli::constants::DW_AT_stmt_list
            | gimli::constants::DW_AT_string_length
            | gimli::constants::DW_AT_return_addr
            | gimli::constants::DW_AT_start_scope
            | gimli::constants::DW_AT_frame_base
            | gimli::constants::DW_AT_macro_info
            | gimli::constants::DW_AT_macros
            | gimli::constants::DW_AT_segment
            | gimli::constants::DW_AT_static_link
            | gimli::constants::DW_AT_use_location
            | gimli::constants::DW_AT_vtable_elem_location
            | gimli::constants::DW_AT_ranges => true,
            gimli::constants::DW_AT_data_member_location => version == 2 || version == 3,
            _ => false,
        }
    }

    let mut form = attribute.form();
    loop {
        let value = match form {
            gimli::constants::DW_FORM_indirect => {
                let dynamic_form = input.read_uleb128_u16()?;
                form = gimli::constants::DwForm(dynamic_form);
                continue;
            }
            gimli::constants::DW_FORM_addr => {
                let offset = input.offset_from(input_base);
                let value = AttributeValue::Addr(input.read_address(encoding.address_size)?);
                break Ok(self::AttributeValue {
                    value,
                    offset: Some(offset),
                });
            }
            gimli::constants::DW_FORM_block1 => {
                let block = length_u8_value(input)?;
                AttributeValue::Block(block)
            }
            gimli::constants::DW_FORM_block2 => {
                let block = length_u16_value(input)?;
                AttributeValue::Block(block)
            }
            gimli::constants::DW_FORM_block4 => {
                let block = length_u32_value(input)?;
                AttributeValue::Block(block)
            }
            gimli::constants::DW_FORM_block => {
                let block = length_uleb128_value(input)?;
                AttributeValue::Block(block)
            }
            gimli::constants::DW_FORM_data1 => {
                let data = input.read_u8()?;
                AttributeValue::Data1(data)
            }
            gimli::constants::DW_FORM_data2 => {
                let data = input.read_u16()?;
                AttributeValue::Data2(data)
            }
            gimli::constants::DW_FORM_data4 => {
                if encoding.format == gimli::Format::Dwarf32 && allow_section_offset(attribute.name(), encoding.version) {
                    let offset = input.read_offset(gimli::Format::Dwarf32)?;
                    AttributeValue::SecOffset(offset)
                } else {
                    let data = input.read_u32()?;
                    AttributeValue::Data4(data)
                }
            }
            gimli::constants::DW_FORM_data8 => {
                if encoding.format == gimli::Format::Dwarf64 && allow_section_offset(attribute.name(), encoding.version) {
                    let offset = input.read_offset(gimli::Format::Dwarf64)?;
                    AttributeValue::SecOffset(offset)
                } else {
                    let data = input.read_u64()?;
                    AttributeValue::Data8(data)
                }
            }
            gimli::constants::DW_FORM_data16 => {
                let block = input.split(R::Offset::from_u8(16))?;
                AttributeValue::Block(block)
            }
            gimli::constants::DW_FORM_udata => {
                let data = input.read_uleb128()?;
                AttributeValue::Udata(data)
            }
            gimli::constants::DW_FORM_sdata => {
                let data = input.read_sleb128()?;
                AttributeValue::Sdata(data)
            }
            gimli::constants::DW_FORM_exprloc => {
                let block = length_uleb128_value(input)?;
                AttributeValue::Exprloc(Expression(block))
            }
            gimli::constants::DW_FORM_flag => {
                let present = input.read_u8()?;
                AttributeValue::Flag(present != 0)
            }
            gimli::constants::DW_FORM_flag_present => AttributeValue::Flag(true),
            gimli::constants::DW_FORM_sec_offset => {
                let offset = input.read_offset(encoding.format)?;
                AttributeValue::SecOffset(offset)
            }
            gimli::constants::DW_FORM_ref1 => {
                let reference = input.read_u8().map(R::Offset::from_u8)?;
                AttributeValue::UnitRef(UnitOffset(reference))
            }
            gimli::constants::DW_FORM_ref2 => {
                let reference = input.read_u16().map(R::Offset::from_u16)?;
                AttributeValue::UnitRef(UnitOffset(reference))
            }
            gimli::constants::DW_FORM_ref4 => {
                let reference = input.read_u32().map(R::Offset::from_u32)?;
                AttributeValue::UnitRef(UnitOffset(reference))
            }
            gimli::constants::DW_FORM_ref8 => {
                let reference = input
                    .read_u64()
                    .and_then(|offset| R::Offset::from_u64(offset).map_err(|_| gimli::Error::OffsetOutOfBounds))?;
                AttributeValue::UnitRef(UnitOffset(reference))
            }
            gimli::constants::DW_FORM_ref_udata => {
                let reference = input
                    .read_uleb128()
                    .and_then(|offset| R::Offset::from_u64(offset).map_err(|_| gimli::Error::OffsetOutOfBounds))?;
                AttributeValue::UnitRef(UnitOffset(reference))
            }
            gimli::constants::DW_FORM_ref_addr => {
                let offset = if encoding.version == 2 {
                    input.read_sized_offset(encoding.address_size)?
                } else {
                    input.read_offset(encoding.format)?
                };
                AttributeValue::DebugInfoRef(DebugInfoOffset(offset))
            }
            gimli::constants::DW_FORM_ref_sig8 => {
                let signature = input.read_u64()?;
                AttributeValue::DebugTypesRef(DebugTypeSignature(signature))
            }
            gimli::constants::DW_FORM_ref_sup4 => {
                let offset = input.read_u32().map(R::Offset::from_u32)?;
                AttributeValue::DebugInfoRefSup(DebugInfoOffset(offset))
            }
            gimli::constants::DW_FORM_ref_sup8 => {
                let offset = input
                    .read_u64()
                    .and_then(|offset| R::Offset::from_u64(offset).map_err(|_| gimli::Error::OffsetOutOfBounds))?;
                AttributeValue::DebugInfoRefSup(DebugInfoOffset(offset))
            }
            gimli::constants::DW_FORM_GNU_ref_alt => {
                let offset = input.read_offset(encoding.format)?;
                AttributeValue::DebugInfoRefSup(DebugInfoOffset(offset))
            }
            gimli::constants::DW_FORM_string => {
                let string = input.read_null_terminated_slice()?;
                AttributeValue::String(string)
            }
            gimli::constants::DW_FORM_strp => {
                let offset = input.read_offset(encoding.format)?;
                AttributeValue::DebugStrRef(DebugStrOffset(offset))
            }
            gimli::constants::DW_FORM_strp_sup | gimli::constants::DW_FORM_GNU_strp_alt => {
                let offset = input.read_offset(encoding.format)?;
                AttributeValue::DebugStrRefSup(DebugStrOffset(offset))
            }
            gimli::constants::DW_FORM_line_strp => {
                let offset = input.read_offset(encoding.format)?;
                AttributeValue::DebugLineStrRef(DebugLineStrOffset(offset))
            }
            gimli::constants::DW_FORM_implicit_const => {
                let data = attribute.implicit_const_value().ok_or(gimli::Error::InvalidImplicitConst)?;
                AttributeValue::Sdata(data)
            }
            gimli::constants::DW_FORM_strx | gimli::constants::DW_FORM_GNU_str_index => {
                let index = input
                    .read_uleb128()
                    .and_then(|offset| R::Offset::from_u64(offset).map_err(|_| gimli::Error::OffsetOutOfBounds))?;
                AttributeValue::DebugStrOffsetsIndex(DebugStrOffsetsIndex(index))
            }
            gimli::constants::DW_FORM_strx1 => {
                let index = input.read_u8().map(R::Offset::from_u8)?;
                AttributeValue::DebugStrOffsetsIndex(DebugStrOffsetsIndex(index))
            }
            gimli::constants::DW_FORM_strx2 => {
                let index = input.read_u16().map(R::Offset::from_u16)?;
                AttributeValue::DebugStrOffsetsIndex(DebugStrOffsetsIndex(index))
            }
            gimli::constants::DW_FORM_strx3 => {
                let index = input
                    .read_uint(3)
                    .and_then(|offset| R::Offset::from_u64(offset).map_err(|_| gimli::Error::OffsetOutOfBounds))?;
                AttributeValue::DebugStrOffsetsIndex(DebugStrOffsetsIndex(index))
            }
            gimli::constants::DW_FORM_strx4 => {
                let index = input.read_u32().map(R::Offset::from_u32)?;
                AttributeValue::DebugStrOffsetsIndex(DebugStrOffsetsIndex(index))
            }
            gimli::constants::DW_FORM_addrx | gimli::constants::DW_FORM_GNU_addr_index => {
                let index = input
                    .read_uleb128()
                    .and_then(|offset| R::Offset::from_u64(offset).map_err(|_| gimli::Error::OffsetOutOfBounds))?;
                AttributeValue::DebugAddrIndex(DebugAddrIndex(index))
            }
            gimli::constants::DW_FORM_addrx1 => {
                let index = input.read_u8().map(R::Offset::from_u8)?;
                AttributeValue::DebugAddrIndex(DebugAddrIndex(index))
            }
            gimli::constants::DW_FORM_addrx2 => {
                let index = input.read_u16().map(R::Offset::from_u16)?;
                AttributeValue::DebugAddrIndex(DebugAddrIndex(index))
            }
            gimli::constants::DW_FORM_addrx3 => {
                let index = input
                    .read_uint(3)
                    .and_then(|offset| R::Offset::from_u64(offset).map_err(|_| gimli::Error::OffsetOutOfBounds))?;
                AttributeValue::DebugAddrIndex(DebugAddrIndex(index))
            }
            gimli::constants::DW_FORM_addrx4 => {
                let index = input.read_u32().map(R::Offset::from_u32)?;
                AttributeValue::DebugAddrIndex(DebugAddrIndex(index))
            }
            gimli::constants::DW_FORM_loclistx => {
                let index = input
                    .read_uleb128()
                    .and_then(|offset| R::Offset::from_u64(offset).map_err(|_| gimli::Error::OffsetOutOfBounds))?;
                AttributeValue::DebugLocListsIndex(DebugLocListsIndex(index))
            }
            gimli::constants::DW_FORM_rnglistx => {
                let index = input
                    .read_uleb128()
                    .and_then(|offset| R::Offset::from_u64(offset).map_err(|_| gimli::Error::OffsetOutOfBounds))?;
                AttributeValue::DebugRngListsIndex(DebugRngListsIndex(index))
            }
            _ => {
                return Err(ProgramFromElfError::other(format!(
                    "failed to process DWARF: unsupported attribute form when reading unit's attributes: {}",
                    form,
                )));
            }
        };

        break Ok(self::AttributeValue { value, offset: None });
    }
}

fn iter_attributes<'a, R>(
    dwarf: &gimli::Dwarf<R>,
    unit: &'a gimli::Unit<R>,
    entry_offset: gimli::UnitOffset<R::Offset>,
) -> Result<impl Iterator<Item = Result<(gimli::constants::DwAt, AttributeValue<R>), ProgramFromElfError>> + 'a, ProgramFromElfError>
where
    R: gimli::Reader,
{
    let mut input = gimli::Section::reader(&dwarf.debug_info).clone();
    let section_base = input.clone();
    input.skip(unit.header.offset().as_debug_info_offset().unwrap().0)?;
    input.skip(entry_offset.0)?;

    let mut attributes = &[][..];
    let code = input.read_uleb128()?;
    if code != 0 {
        let abbrev = unit.abbreviations.get(code).ok_or(gimli::Error::UnknownAbbreviation(code))?;
        attributes = abbrev.attributes();
    }

    let encoding = unit.encoding();
    let iterator = core::iter::from_fn(move || {
        if attributes.is_empty() {
            return None;
        }

        let attribute = attributes[0];
        attributes = &attributes[1..];

        Some(parse_attribute(&section_base, &mut input, encoding, attribute).map(|value| (attribute.name(), value)))
    });

    Ok(iterator)
}

fn extract_symbolic_low_pc<R>(
    dwarf: &gimli::Dwarf<R>,
    sections: &Sections,
    relocations: &BTreeMap<SectionTarget, RelocationKind>,
    unit: &gimli::Unit<R>,
    is_64bit: bool,
) -> Result<Option<SectionTarget>, ProgramFromElfError>
where
    R: gimli::Reader,
{
    let mut cursor = unit.entries();
    cursor.next_dfs()?;

    let entry = cursor.current().ok_or(gimli::Error::MissingUnitDie)?;
    let entry_offset = entry.offset();

    log::trace!("Extracting low PC for unit at offset {entry_offset:?}...");
    for pair in iter_attributes(dwarf, unit, entry_offset)? {
        let (name, value) = pair?;
        if name != gimli::constants::DW_AT_low_pc {
            continue;
        }
        match value {
            AttributeValue {
                value: gimli::AttributeValue::DebugAddrIndex(gimli::DebugAddrIndex(index)),
                ..
            } => {
                let index = gimli::DebugAddrIndex(index);
                return resolve_debug_addr_index(sections.debug_addr, relocations, unit, index, is_64bit);
            }
            AttributeValue {
                value: gimli::AttributeValue::Addr(address),
                offset: Some(offset),
            } => {
                let relocation_target = SectionTarget {
                    section_index: sections.debug_info.index(),
                    offset: offset.into_u64(),
                };

                let Some(relocation) = relocations.get(&relocation_target) else {
                    if address == 0 {
                        // Clang likes to emit these when compiling C++.
                        continue;
                    }

                    return Err(ProgramFromElfError::other(format!(
                        "failed to process DWARF: failed to fetch DW_AT_low_pc for a unit: {relocation_target} has no relocation"
                    )));
                };

                let target = match relocation {
                    RelocationKind::Abs {
                        target,
                        size: RelocationSize::U64,
                    } if is_64bit => target,
                    RelocationKind::Abs {
                        target,
                        size: RelocationSize::U32,
                    } => target,
                    _ => {
                        return Err(ProgramFromElfError::other(format!(
                            "failed to process DWARF: failed to fetch DW_AT_low_pc for a unit: unexpected relocation at {relocation_target}: {relocation:?}"
                        )));
                    }
                };

                return Ok(Some(*target));
            }
            value => {
                return Err(ProgramFromElfError::other(format!(
                    "failed to process DWARF: unsupported attribute for unit's {name}: {value:?}"
                )));
            }
        }
    }

    Ok(None)
}

pub(crate) fn load_dwarf<H>(
    string_cache: &mut StringCache,
    elf: &Elf<H>,
    relocations: &BTreeMap<SectionTarget, RelocationKind>,
) -> Result<DwarfInfo, ProgramFromElfError>
where
    H: object::read::elf::FileHeader<Endian = object::LittleEndian>,
{
    log::trace!("Loading DWARF...");

    let Some(debug_info) = elf.section_by_name(".debug_info").next() else {
        return Ok(Default::default());
    };

    let is_64bit = elf.is_64();

    let sections = Sections {
        debug_info,
        debug_addr: elf.section_by_name(".debug_addr").next(),
        debug_ranges: elf.section_by_name(".debug_ranges").next(),
        debug_rnglists: elf.section_by_name(".debug_rnglists").next(),
        debug_line: elf.section_by_name(".debug_line").next(),
    };

    let mut load_section = |id: gimli::SectionId| -> Result<_, ProgramFromElfError> {
        let name = id.name();
        let data = match elf.section_by_name(name).next() {
            Some(section) => section.data().to_owned(),
            None => Vec::with_capacity(1),
        };

        let data: std::rc::Rc<[u8]> = data.into();
        let reader = gimli::read::EndianRcSlice::new(data, gimli::LittleEndian);
        let reader = ReaderWrapper::wrap(reader);
        Ok(reader)
    };

    let dwarf: gimli::Dwarf<ReaderWrapper<gimli::read::EndianRcSlice<gimli::LittleEndian>>> = gimli::Dwarf::load(&mut load_section)?;
    let mut units = Vec::new();
    {
        let mut iter = dwarf.units();
        while let Some(header) = iter.next()? {
            let Some(offset) = header.offset().as_debug_info_offset() else {
                continue;
            };
            let unit = match dwarf.unit(header) {
                Ok(unit) => unit,
                Err(error @ gimli::Error::UnexpectedEof(reader_offset_id)) => {
                    if let Some((_, section_id, offset)) = dwarf.lookup_offset_id(reader_offset_id) {
                        return Err(ProgramFromElfError::other(format!(
                            "unexpected end of file while parsing DWARF info in section '{}'+{}",
                            section_id.name(),
                            offset
                        )));
                    } else {
                        return Err(error.into());
                    }
                }
                Err(error) => {
                    return Err(error.into());
                }
            };

            log::trace!("Processing unit: {offset:?}");
            let low_pc = extract_symbolic_low_pc(&dwarf, &sections, relocations, &unit, is_64bit)?;
            let paths = extract_paths(&dwarf, string_cache, &unit)?;
            units.push(Unit {
                low_pc,
                offset,
                raw_unit: unit,
                paths,
            });
        }
    }

    units.sort_by_key(|unit| unit.offset);

    let walker = DwarfWalker {
        sections,
        relocations,
        depth: 0,
        inline_depth: 0,
        namespace_buffer: Default::default(),
        dwarf: &dwarf,
        units: &units[..],
        subprograms: Default::default(),
        strings: string_cache,
        is_64bit,
    };

    let location_map = walker.run()?;
    Ok(DwarfInfo { location_map })
}
