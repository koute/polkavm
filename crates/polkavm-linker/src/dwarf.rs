use crate::program_from_elf::Elf;
use crate::ProgramFromElfError;
use gimli::ReaderOffset;
use object::{Object, ObjectSection};
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::Arc;

struct AttributeParser<R: gimli::Reader> {
    depth: usize,
    low_pc: Option<u64>,
    high_pc: Option<u64>,
    size: Option<u64>,
    ranges_offset: Option<gimli::RangeListsOffset<<R as gimli::Reader>::Offset>>,
    linkage_name: Option<gimli::AttributeValue<R>>,
    name: Option<gimli::AttributeValue<R>>,
    abstract_origin: Option<gimli::AttributeValue<R>>,
    decl_file: Option<u64>,
    decl_line: Option<u64>,
    call_file: Option<u64>,
    call_line: Option<u64>,
    call_column: Option<u64>,
    recursion_limit: usize,
}

impl<R: gimli::Reader> AttributeParser<R> {
    fn new(depth: usize) -> Self {
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
            recursion_limit: 32,
        }
    }

    fn for_each_range(
        &self,
        dwarf: &gimli::Dwarf<R>,
        unit: &gimli::Unit<R>,
        mut callback: impl FnMut(gimli::Range),
    ) -> Result<(), ProgramFromElfError> {
        if let Some(ranges_offset) = self.ranges_offset {
            let mut range_list = dwarf.ranges(unit, ranges_offset)?;
            while let Some(range) = range_list.next()? {
                log::trace!("  Range from list: 0x{:x} - 0x{:x}", range.begin, range.end);
                callback(range);
            }
        } else if let (Some(begin), Some(end)) = (self.low_pc, self.high_pc) {
            log::trace!("  Range from low_pc + high_pc (abs): 0x{:x} - 0x{:x}", begin, end);
            callback(gimli::Range { begin, end });
        } else if let (Some(begin), Some(size)) = (self.low_pc, self.size) {
            log::trace!("  Range from low_pc + high_pc (rel): 0x{:x} - 0x{:x}", begin, begin + size);
            callback(gimli::Range { begin, end: begin + size });
        }

        Ok(())
    }

    fn try_match(
        &mut self,
        dwarf: &gimli::Dwarf<R>,
        unit: &gimli::Unit<R>,
        offset: Option<gimli::UnitOffset<R::Offset>>,
    ) -> Result<(), ProgramFromElfError> {
        let mut entries = unit.entries_raw(offset)?;
        let abbreviation = if let Some(abbreviation) = entries.read_abbreviation()? {
            abbreviation
        } else {
            return Err(gimli::Error::NoEntryAtGivenOffset.into());
        };

        for attribute in abbreviation.attributes() {
            let attribute = entries.read_attribute(*attribute)?;
            self.try_match_attribute(dwarf, unit, &attribute)?;
        }

        Ok(())
    }

    fn try_match_attribute(
        &mut self,
        dwarf: &gimli::Dwarf<R>,
        unit: &gimli::Unit<R>,
        attribute: &gimli::Attribute<R>,
    ) -> Result<(), ProgramFromElfError> {
        log::trace!("{:->depth$}{name}", ">", depth = self.depth, name = attribute.name());
        match attribute.name() {
            gimli::DW_AT_low_pc => match attribute.value() {
                gimli::AttributeValue::Addr(val) => {
                    log::trace!("  = 0x{:x} (address)", val);
                    self.low_pc = Some(val)
                }
                gimli::AttributeValue::DebugAddrIndex(index) => {
                    log::trace!("  = 0x{:x} ({:?})", dwarf.address(unit, index)?, index);
                    self.low_pc = Some(dwarf.address(unit, index)?);
                }
                value => {
                    return Err(ProgramFromElfError::other(format!(
                        "failed to process DWARF: unsupported value for DW_AT_low_pc: {:?}",
                        value
                    )));
                }
            },
            gimli::DW_AT_high_pc => match attribute.value() {
                gimli::AttributeValue::Addr(val) => {
                    log::trace!("  = 0x{:x} (address)", val);
                    self.high_pc = Some(val)
                }
                gimli::AttributeValue::DebugAddrIndex(index) => {
                    log::trace!("  = 0x{:x} ({:?})", dwarf.address(unit, index)?, index);
                    self.high_pc = Some(dwarf.address(unit, index)?);
                }
                gimli::AttributeValue::Udata(val) => {
                    log::trace!("  = DW_AT_low_pc + {val} (size)");
                    self.size = Some(val)
                }
                value => {
                    return Err(ProgramFromElfError::other(format!(
                        "failed to process DWARF: unsupported value for DW_AT_high_pc: {:?}",
                        value
                    )));
                }
            },
            gimli::DW_AT_ranges => {
                self.ranges_offset = dwarf.attr_ranges_offset(unit, attribute.value())?;
            }
            gimli::DW_AT_linkage_name | gimli::DW_AT_MIPS_linkage_name => {
                self.linkage_name = Some(attribute.value());
            }
            gimli::DW_AT_name => {
                self.name = Some(attribute.value());
            }
            gimli::DW_AT_abstract_origin | gimli::DW_AT_specification => {
                let value = attribute.value();
                log::trace!("  = {:?}", value);
                self.abstract_origin = Some(value);
            }
            gimli::DW_AT_decl_file => match attribute.value() {
                gimli::AttributeValue::FileIndex(index) => {
                    self.decl_file = Some(index);
                }
                value => {
                    return Err(ProgramFromElfError::other(format!(
                        "failed to process DWARF: DW_AT_decl_file has unsupported value: {:?}",
                        value
                    )))
                }
            },
            gimli::DW_AT_decl_line => {
                self.decl_line = attribute.udata_value();
            }
            gimli::DW_AT_call_file => match attribute.value() {
                gimli::AttributeValue::FileIndex(index) => {
                    self.call_file = Some(index);
                }
                value => {
                    return Err(ProgramFromElfError::other(format!(
                        "failed to process DWARF: DW_AT_call_file has unsupported value: {:?}",
                        value
                    )))
                }
            },
            gimli::DW_AT_call_line => {
                self.call_line = attribute.udata_value();
            }
            gimli::DW_AT_call_column => {
                self.call_column = attribute.udata_value();
            }
            _ => {}
        }
        Ok(())
    }

    fn resolve_name(
        &self,
        dwarf: &gimli::Dwarf<R>,
        units: &[(gimli::DebugInfoOffset<R::Offset>, gimli::Unit<R>)],
        unit: &gimli::Unit<R>,
        strings: &mut HashSet<Arc<str>>,
    ) -> Result<Option<Arc<str>>, ProgramFromElfError> {
        if self.recursion_limit == 0 {
            return Err(ProgramFromElfError::other(
                "failed to process DWARF: recursion limit reached when resolving a name",
            ));
        }

        if let Some(value) = self.name.as_ref().or(self.linkage_name.as_ref()) {
            let name = dwarf.attr_string(unit, value.clone())?;
            let name = name.to_string_lossy()?;
            let name = dedup_string(strings, &name);
            return Ok(Some(name));
        }

        if let Some(ref value) = self.abstract_origin {
            let (target_unit, target_offset) = match value {
                gimli::AttributeValue::UnitRef(offset) => (unit, *offset),
                gimli::AttributeValue::DebugInfoRef(absolute_target_offset) => {
                    let target_unit = units.binary_search_by_key(&absolute_target_offset.0, |target_unit| target_unit.0 .0);
                    let target_unit = match target_unit {
                        Ok(index) => &units[index].1,
                        Err(0) => {
                            return Err(ProgramFromElfError::other(format!(
                                "failed to process DWARF: failed to find a unit for offset: {:x}",
                                absolute_target_offset.0.into_u64()
                            )));
                        }
                        Err(index) => &units[index - 1].1,
                    };
                    let target_offset = absolute_target_offset.to_unit_offset(&target_unit.header).ok_or_else(|| {
                        ProgramFromElfError::other(format!(
                            "failed to process DWARF: found a unit for offset={:x} but couldn't compute a relative offset",
                            absolute_target_offset.0.into_u64()
                        ))
                    })?;
                    (target_unit, target_offset)
                }
                _ => {
                    return Err(ProgramFromElfError::other(format!(
                        "failed to process DWARF: DW_AT_abstract_origin/DW_AT_specification has unsupported value: {:?}",
                        value
                    )))
                }
            };

            let mut parser = AttributeParser::new(self.depth + 1);
            parser.recursion_limit = self.recursion_limit - 1;
            parser.try_match(dwarf, target_unit, Some(target_offset))?;
            return parser.resolve_name(dwarf, units, target_unit, strings);
        }

        Ok(None)
    }
}

struct DwarfWalker<'a, R>
where
    R: gimli::Reader,
{
    strings: HashSet<Arc<str>>,
    dwarf: &'a gimli::Dwarf<R>,
    units: &'a [(gimli::DebugInfoOffset<R::Offset>, gimli::Unit<R>)],
    depth: usize,
    inline_depth: usize,
    paths: Vec<Arc<str>>,
    namespace_buffer: Vec<String>,
    frames: HashMap<(u64, u64), Vec<Frame>>,
    inline_frames: Vec<(u64, u64, usize, Location)>,
}

fn dedup_string(strings: &mut HashSet<Arc<str>>, string: &str) -> Arc<str> {
    if let Some(string) = strings.get(string) {
        return string.clone();
    }

    let string: Arc<str> = string.into();
    strings.insert(string.clone());
    string
}

impl<'a, R> DwarfWalker<'a, R>
where
    R: gimli::Reader,
{
    fn run(&mut self, unit: &gimli::Unit<R>) -> Result<(), ProgramFromElfError> {
        assert!(self.namespace_buffer.is_empty());
        assert_eq!(self.depth, 0);
        assert_eq!(self.inline_depth, 0);

        self.paths.clear();

        let program = match unit.line_program.as_ref() {
            Some(program) => program,
            None => return Ok(()),
        };

        let header = program.header();

        let mut dirs = Vec::new();
        let compilation_directory = if let Some(ref comp_dir) = unit.comp_dir {
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

            let empty = dedup_string(&mut self.strings, "");
            self.paths.push(empty);
        }

        for dir in header.include_directories() {
            let value = self.dwarf.attr_string(unit, dir.clone())?.to_string_lossy()?.into_owned();
            dirs.push(value);
        }

        for file in header.file_names().iter() {
            let filename = self.dwarf.attr_string(unit, file.path_name())?.to_string_lossy()?.into_owned();
            let directory = match dirs.get(file.directory_index() as usize) {
                Some(directory) => directory,
                None => {
                    return Err(ProgramFromElfError::other(
                        "failed to process DWARF: file refers to a directory index which doesn't exist",
                    ))
                }
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

            let path = dedup_string(&mut self.strings, &path);
            self.paths.push(path);
        }

        let mut tree = unit.entries_tree(None)?;
        let node = tree.root()?;
        self.walk(unit, node)
    }

    fn resolve_namespace(&mut self) -> Vec<Arc<str>> {
        let mut buf = Vec::new();
        for chunk in &self.namespace_buffer {
            let chunk = dedup_string(&mut self.strings, chunk);
            buf.push(chunk);
        }

        buf
    }

    fn walk(&mut self, unit: &gimli::Unit<R>, node: gimli::EntriesTreeNode<R>) -> Result<(), ProgramFromElfError> {
        let buffer_initial_length = self.namespace_buffer.len();
        let node_entry = node.entry();
        log::trace!(
            "{:08x} {:->depth$}{name}",
            node_entry.offset().0.into_u64(),
            ">",
            depth = self.depth,
            name = node_entry.tag()
        );

        let node_tag = node_entry.tag();
        if node_tag == gimli::DW_TAG_inlined_subroutine {
            self.inline_depth += 1;
        }

        let mut frame_entries = Vec::new();
        match node_tag {
            gimli::DW_TAG_structure_type | gimli::DW_TAG_enumeration_type => {
                return Ok(());
            }
            gimli::DW_TAG_namespace => {
                let mut attrs = node_entry.attrs();
                while let Some(attribute) = attrs.next()? {
                    #[allow(clippy::single_match)]
                    match attribute.name() {
                        gimli::DW_AT_name => {
                            let name = self.dwarf.attr_string(unit, attribute.value())?.to_string_lossy()?.into_owned();
                            self.namespace_buffer.push(name);
                            log::trace!("  Namespace: {:?}", self.namespace_buffer);
                        }
                        _ => {}
                    }
                }
            }
            gimli::DW_TAG_subprogram => {
                if !self.inline_frames.is_empty() {
                    return Err(ProgramFromElfError::other(
                        "failed to process DWARF: found a DW_TAG_subprogram while there are still pending inline frames",
                    ));
                }

                if self.inline_depth > 0 {
                    return Err(ProgramFromElfError::other(
                        "failed to process DWARF: found a DW_TAG_subprogram while inline depth is greater than zero",
                    ));
                }

                let mut parser = AttributeParser::new(self.depth + 1);
                let mut attrs = node_entry.attrs();
                while let Some(attribute) = attrs.next()? {
                    parser.try_match_attribute(self.dwarf, unit, &attribute)?;
                }

                let namespace = self.resolve_namespace();
                let name = parser.resolve_name(self.dwarf, self.units, unit, &mut self.strings)?;
                let path = parser.decl_file.and_then(|index| self.paths.get(index as usize));
                let line = parser.decl_line;

                log::trace!("  In namespace: {:?}", self.namespace_buffer);
                log::trace!("  Subprogram name: {:?}", name);
                log::trace!("  Subprogram decl location: {:?} {:?}", path, line);

                if line.is_some() && path.is_none() {
                    return Err(ProgramFromElfError::other(
                        "failed to process DWARF: subprogram has a decl line but no decl file",
                    ));
                }

                if path.is_some() && name.is_none() {
                    return Err(ProgramFromElfError::other(
                        "failed to process DWARF: subprogram has a decl file but no name",
                    ));
                }

                let original_entry_count = frame_entries.len();
                parser.for_each_range(self.dwarf, unit, |range| {
                    if range.begin == 0 {
                        // The linker sometimes likes to emit those when it has stripped away the original
                        // function, but it still leaves the DWARF info behind. So let's just skip those.
                        return;
                    }

                    let location = Location {
                        namespace: namespace.clone(),
                        function_name: name.clone(),
                        path: path.cloned(),
                        line,
                        column: None,
                    };

                    frame_entries.push((
                        range.begin,
                        range.end,
                        Frame {
                            location,
                            inline_frames: Default::default(),
                        },
                    ));
                })?;

                if frame_entries.len() == original_entry_count {
                    // Skip the whole subtree.
                    return Ok(());
                }
            }
            gimli::DW_TAG_inlined_subroutine => {
                let mut parser = AttributeParser::new(self.depth + 1);
                let mut attrs = node_entry.attrs();
                while let Some(attribute) = attrs.next()? {
                    parser.try_match_attribute(self.dwarf, unit, &attribute)?;
                }

                let namespace = self.resolve_namespace();
                let name = parser.resolve_name(self.dwarf, self.units, unit, &mut self.strings)?;
                let path = parser.call_file.and_then(|index| self.paths.get(index as usize));
                let line = parser.call_line;
                let column = parser.call_column;

                log::trace!("  In namespace: {:?}", self.namespace_buffer);
                log::trace!("  Inlined subroutine name: {:?}", name);
                log::trace!("  Inlined subroutine call location: {:?} {:?} {:?}", path, line, column);

                if column.is_some() && line.is_none() {
                    return Err(ProgramFromElfError::other(
                        "failed to process DWARF: inline subroutine has a call column but no call line",
                    ));
                }

                if line.is_some() && path.is_none() {
                    return Err(ProgramFromElfError::other(
                        "failed to process DWARF: inline subroutine has a call line but no call file",
                    ));
                }

                if path.is_some() && name.is_none() {
                    return Err(ProgramFromElfError::other(
                        "failed to process DWARF: inline subroutine has a call file but no name",
                    ));
                }

                parser.for_each_range(self.dwarf, unit, |range| {
                    let location = Location {
                        namespace: namespace.clone(),
                        function_name: name.clone(),
                        path: path.cloned(),
                        line,
                        column,
                    };

                    self.inline_frames.push((range.begin, range.end, self.inline_depth, location));
                })?;
            }
            _ => {}
        }

        self.depth += 1;
        let mut children = node.children();
        while let Some(child) = children.next()? {
            self.walk(unit, child)?;
        }
        self.depth -= 1;
        self.namespace_buffer.truncate(buffer_initial_length);

        if node_tag == gimli::DW_TAG_inlined_subroutine {
            self.inline_depth -= 1;
        }

        if node_tag == gimli::DW_TAG_subprogram {
            if frame_entries.len() > 1 {
                return Err(ProgramFromElfError::other(
                    "failed to process DWARF: found multiple ranges for a single subprogram",
                ));
            }

            if let Some((begin, end, mut frame)) = frame_entries.into_iter().next() {
                assert!(frame.inline_frames.is_empty());
                self.inline_frames
                    .sort_by_key(|(inline_begin, inline_end, inline_depth, _)| (*inline_begin, *inline_depth, !*inline_end));

                let mut transitions: BTreeMap<u64, (Vec<usize>, Vec<usize>)> = BTreeMap::new();
                for (nth_inline_frame, (inline_begin, inline_end, _, _)) in self.inline_frames.iter().enumerate() {
                    if *inline_begin < begin || *inline_end > end {
                        return Err(ProgramFromElfError::other(
                            format!(
                                "failed to process DWARF: found inline subroutine which exceedes the bounds of its parent subprogram (parent = 0x{:x}-0x{:x}, inline = 0x{:x}-0x{:x})",
                                begin,
                                end,
                                inline_begin,
                                inline_end,
                            )
                        ));
                    }

                    transitions
                        .entry(*inline_begin)
                        .or_insert_with(Default::default)
                        .0
                        .push(nth_inline_frame);
                    transitions
                        .entry(*inline_end)
                        .or_insert_with(Default::default)
                        .1
                        .push(nth_inline_frame);
                }

                for (address, (enter_list, mut exit_list)) in transitions {
                    exit_list.reverse();

                    log::trace!("Inline frame transitions for 0x{:x}:", address);
                    for &nth_inline_frame in &exit_list {
                        let &(inline_begin, inline_end, inline_depth, ref location) = &self.inline_frames[nth_inline_frame];
                        log::trace!(
                            "  Exit: 0x{:x}-0x{:x} depth={}, fn={:?}, source={:?}:{:?}:{:?}",
                            inline_begin,
                            inline_end,
                            inline_depth,
                            location.function_name,
                            location.path,
                            location.line,
                            location.column
                        );
                    }

                    for nth_inline_frame in enter_list {
                        let &(inline_begin, inline_end, inline_depth, ref location) = &self.inline_frames[nth_inline_frame];
                        log::trace!(
                            "  Enter: 0x{:x}-0x{:x}, depth={}, fn={:?}, source={:?}:{:?}:{:?}",
                            inline_begin,
                            inline_end,
                            inline_depth,
                            location.function_name,
                            location.path,
                            location.line,
                            location.column
                        );

                        frame
                            .inline_frames
                            .push((inline_begin, inline_end, inline_depth as u32, location.clone()));
                    }
                }

                self.frames.entry((begin, end)).or_insert_with(Vec::new).push(frame);
            } else if !self.inline_frames.is_empty() {
                return Err(ProgramFromElfError::other(
                    "failed to process DWARF: found no ranges for a subprogram and yet it had inline frames",
                ));
            }

            self.inline_frames.clear();
        }

        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) struct Location {
    pub namespace: Vec<Arc<str>>,
    pub function_name: Option<Arc<str>>,
    pub path: Option<Arc<str>>,
    pub line: Option<u64>,
    pub column: Option<u64>,
}

pub(crate) struct Frame {
    pub location: Location,
    pub inline_frames: Vec<(u64, u64, u32, Location)>,
}

pub(crate) struct DwarfInfo {
    pub frames: Vec<(u64, u64, Vec<Frame>)>,
}

pub(crate) fn load_dwarf(elf: &Elf, data: &[u8]) -> Result<DwarfInfo, ProgramFromElfError> {
    log::trace!("Loading DWARF...");

    let mut load_section = |id: gimli::SectionId| -> Result<_, ProgramFromElfError> {
        let name = id.name();
        let data = match elf.section_by_name(name) {
            Some(section) => {
                let section_range = section.file_range().unwrap_or((0, 0));
                let section_start =
                    usize::try_from(section_range.0).map_err(|_| ProgramFromElfError::other("out of range offset for section"))?;
                let section_size =
                    usize::try_from(section_range.1).map_err(|_| ProgramFromElfError::other("out of range size for section"))?;
                let section_end = section_start
                    .checked_add(section_size)
                    .ok_or(ProgramFromElfError::other("out of range section"))?;
                data.get(section_start..section_end)
                    .ok_or(ProgramFromElfError::other("out of range section"))?
                    .to_vec()
            }
            None => Vec::with_capacity(1),
        };

        let data: std::rc::Rc<[u8]> = data.into();
        Ok(gimli::read::EndianRcSlice::new(data, gimli::LittleEndian))
    };

    let dwarf: gimli::Dwarf<gimli::read::EndianRcSlice<gimli::LittleEndian>> = gimli::Dwarf::load(&mut load_section)?;
    let mut units = Vec::new();
    {
        let mut iter = dwarf.units();
        while let Some(header) = iter.next()? {
            let offset = match header.offset().as_debug_info_offset() {
                Some(offset) => offset,
                None => continue,
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
            units.push((offset, unit));
        }
    }

    units.sort_by_key(|(offset, _)| *offset);

    let mut walker = DwarfWalker {
        depth: 0,
        inline_depth: 0,
        paths: Default::default(),
        namespace_buffer: Default::default(),
        dwarf: &dwarf,
        units: &units[..],
        frames: Default::default(),
        inline_frames: Default::default(),
        strings: Default::default(),
    };

    let mut iter = dwarf.units();
    while let Some(header) = iter.next()? {
        let unit = dwarf.unit(header)?;
        walker.run(&unit)?;
    }

    let mut frames: Vec<_> = walker.frames.into_iter().map(|((begin, end), frame)| (begin, end, frame)).collect();
    frames.sort_by_key(|(begin, end, _)| (*begin, !*end));

    log::trace!("Found {} frame(s) in total", frames.len());
    let mut last_end = 0;
    for (begin, end, frames) in &frames {
        log::trace!("  0x{:x}-0x{:x}", begin, end);
        for frame in frames {
            let location = &frame.location;
            log::trace!(
                "    fn={:?}, source={:?}:{:?}:{:?}",
                location.function_name,
                location.path,
                location.line,
                location.column
            );
        }

        if *begin < last_end {
            return Err(ProgramFromElfError::other("failed to process DWARF: found overlapping frames"));
        }
        last_end = *end;
    }

    Ok(DwarfInfo { frames })
}
