use crate::program::{self, Instruction, ProgramExport, ProgramImport};
use alloc::vec::Vec;
use core::ops::Range;

#[derive(Default)]
pub struct ProgramBlobBuilder {
    ro_data_size: u32,
    rw_data_size: u32,
    stack_size: u32,
    ro_data: Vec<u8>,
    rw_data: Vec<u8>,
    imports: Vec<ProgramImport<'static>>,
    exports: Vec<ProgramExport<'static>>,
    jump_table: Vec<u8>,
    code: Vec<u8>,
    custom: Vec<(u8, Vec<u8>)>,
    instruction_count: u32,
    basic_block_count: u32,
}

impl ProgramBlobBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_ro_data_size(&mut self, size: u32) {
        self.ro_data_size = size;
    }

    pub fn set_rw_data_size(&mut self, size: u32) {
        self.rw_data_size = size;
    }

    pub fn set_stack_size(&mut self, size: u32) {
        self.stack_size = size;
    }

    pub fn set_ro_data(&mut self, data: Vec<u8>) {
        self.ro_data = data;
    }

    pub fn set_rw_data(&mut self, data: Vec<u8>) {
        self.rw_data = data;
    }

    pub fn add_import(&mut self, import: ProgramImport) {
        self.imports.push(import.into_owned());
    }

    pub fn add_export(&mut self, export: ProgramExport) {
        self.exports.push(export.into_owned());
    }

    pub fn set_jump_table(&mut self, jump_table: &[u32]) {
        self.jump_table.clear();
        let mut writer = Writer::new(&mut self.jump_table);
        for &target in jump_table {
            writer.push_varint(target);
        }
    }

    pub fn set_code(&mut self, code: &[Instruction]) {
        self.instruction_count = 0;
        self.basic_block_count = 0;
        for instruction in code {
            let mut buffer = [0; program::MAX_INSTRUCTION_LENGTH];
            let length = instruction.serialize_into(&mut buffer);
            self.code.extend_from_slice(&buffer[..length]);
            self.instruction_count += 1;

            if instruction.opcode().starts_new_basic_block() {
                self.basic_block_count += 1;
            }
        }
    }

    pub fn add_custom_section(&mut self, section: u8, contents: Vec<u8>) {
        self.custom.push((section, contents));
    }

    pub fn into_vec(self) -> Vec<u8> {
        let mut output = Vec::new();
        let mut writer = Writer::new(&mut output);

        writer.push_raw_bytes(&program::BLOB_MAGIC);
        writer.push_byte(program::BLOB_VERSION_V1);

        if self.ro_data_size > 0 || self.rw_data_size > 0 || self.stack_size > 0 {
            writer.push_section_inplace(program::SECTION_MEMORY_CONFIG, |writer| {
                writer.push_varint(self.ro_data_size);
                writer.push_varint(self.rw_data_size);
                writer.push_varint(self.stack_size);
            });
        }

        writer.push_section(program::SECTION_RO_DATA, &self.ro_data);
        writer.push_section(program::SECTION_RW_DATA, &self.rw_data);
        if !self.imports.is_empty() {
            writer.push_section_inplace(program::SECTION_IMPORTS, |writer| {
                writer.push_varint(self.imports.len().try_into().expect("too many imports"));
                for import in self.imports {
                    writer.push_bytes_with_length(import.symbol());
                }
            });
        }

        if !self.exports.is_empty() {
            writer.push_section_inplace(program::SECTION_EXPORTS, |writer| {
                writer.push_varint(self.exports.len().try_into().expect("too many exports"));
                for export in self.exports {
                    writer.push_varint(export.jump_target());
                    writer.push_bytes_with_length(export.symbol());
                }
            });
        }

        writer.push_section(program::SECTION_JUMP_TABLE, &self.jump_table);
        writer.push_section_inplace(program::SECTION_CODE, |writer| {
            writer.push_varint(self.instruction_count);
            writer.push_varint(self.basic_block_count);
            writer.push_raw_bytes(&self.code);
        });

        for (section, contents) in self.custom {
            writer.push_section(section, &contents);
        }

        writer.push_raw_bytes(&[program::SECTION_END_OF_FILE]);
        output
    }
}

pub struct Writer<'a> {
    buffer: &'a mut Vec<u8>,
}

impl<'a> Writer<'a> {
    pub fn new(buffer: &'a mut Vec<u8>) -> Self {
        Self { buffer }
    }

    fn push_section_inplace(&mut self, section: u8, callback: impl FnOnce(&mut Self)) -> Range<usize> {
        let section_position = self.buffer.len();
        self.buffer.push(section);

        // Reserve the space for the length varint.
        let length_position = self.buffer.len();
        self.push_raw_bytes(&[0xff_u8; crate::varint::MAX_VARINT_LENGTH]);

        let payload_position = self.buffer.len();
        callback(self);

        let payload_length: u32 = (self.buffer.len() - payload_position).try_into().expect("section size overflow");
        if payload_length == 0 {
            // Nothing was written by the callback. Skip writing the section.
            self.buffer.truncate(section_position);
            return 0..0;
        }

        // Write the length varint.
        let length_length = crate::varint::write_varint(payload_length, &mut self.buffer[length_position..]);

        // Drain any excess length varint bytes.
        self.buffer
            .drain(length_position + length_length..length_position + crate::varint::MAX_VARINT_LENGTH);

        length_position + length_length..self.buffer.len()
    }

    fn push_section(&mut self, section: u8, contents: &[u8]) {
        if contents.is_empty() {
            return;
        }

        self.push_byte(section);
        self.push_varint(contents.len().try_into().expect("section size overflow"));
        self.push_raw_bytes(contents);
    }

    pub fn push_raw_bytes(&mut self, slice: &[u8]) {
        self.buffer.extend_from_slice(slice);
    }

    pub fn push_byte(&mut self, byte: u8) {
        self.buffer.push(byte);
    }

    pub fn push_u32(&mut self, value: u32) {
        self.push_raw_bytes(&value.to_le_bytes());
    }

    pub fn push_varint(&mut self, value: u32) {
        let mut buffer = [0xff_u8; crate::varint::MAX_VARINT_LENGTH];
        let length = crate::varint::write_varint(value, &mut buffer);
        self.push_raw_bytes(&buffer[..length]);
    }

    pub fn push_bytes_with_length(&mut self, slice: &[u8]) {
        self.push_varint(slice.len().try_into().expect("length overflow"));
        self.push_raw_bytes(slice);
    }

    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }
}
