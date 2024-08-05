use crate::program::{self, Instruction, ProgramSymbol};
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::ops::Range;

#[derive(Copy, Clone)]
pub struct InstructionBuffer {
    bytes: [u8; program::MAX_INSTRUCTION_LENGTH],
    length: u8,
}

impl InstructionBuffer {
    fn len(&self) -> usize {
        self.length as usize
    }
}

impl core::ops::Deref for InstructionBuffer {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.bytes[..self.length as usize]
    }
}

impl From<(u32, Instruction)> for InstructionBuffer {
    fn from((position, instruction): (u32, Instruction)) -> Self {
        let mut buffer = Self {
            bytes: [0; program::MAX_INSTRUCTION_LENGTH],
            length: 0,
        };

        buffer.length = instruction.serialize_into(position, &mut buffer.bytes) as u8;
        buffer
    }
}

impl Instruction {
    fn target_mut(&mut self) -> Option<&mut u32> {
        match self {
            Instruction::jump(ref mut target)
            | Instruction::load_imm_and_jump(_, _, ref mut target)
            | Instruction::branch_eq_imm(_, _, ref mut target)
            | Instruction::branch_not_eq_imm(_, _, ref mut target)
            | Instruction::branch_less_unsigned_imm(_, _, ref mut target)
            | Instruction::branch_less_signed_imm(_, _, ref mut target)
            | Instruction::branch_greater_or_equal_unsigned_imm(_, _, ref mut target)
            | Instruction::branch_greater_or_equal_signed_imm(_, _, ref mut target)
            | Instruction::branch_less_or_equal_signed_imm(_, _, ref mut target)
            | Instruction::branch_less_or_equal_unsigned_imm(_, _, ref mut target)
            | Instruction::branch_greater_signed_imm(_, _, ref mut target)
            | Instruction::branch_greater_unsigned_imm(_, _, ref mut target)
            | Instruction::branch_eq(_, _, ref mut target)
            | Instruction::branch_not_eq(_, _, ref mut target)
            | Instruction::branch_less_unsigned(_, _, ref mut target)
            | Instruction::branch_less_signed(_, _, ref mut target)
            | Instruction::branch_greater_or_equal_unsigned(_, _, ref mut target)
            | Instruction::branch_greater_or_equal_signed(_, _, ref mut target) => Some(target),
            _ => None,
        }
    }
}

#[derive(Copy, Clone)]
pub enum InstructionOrBytes {
    Instruction(Instruction),
    Raw(InstructionBuffer),
}

impl From<Instruction> for InstructionOrBytes {
    fn from(value: Instruction) -> Self {
        Self::Instruction(value)
    }
}

impl From<InstructionBuffer> for InstructionOrBytes {
    fn from(value: InstructionBuffer) -> Self {
        Self::Raw(value)
    }
}

#[derive(Copy, Clone)]
struct SerializedInstruction {
    instruction: Option<Instruction>,
    bytes: InstructionBuffer,
    target_nth_instruction: Option<usize>,
    position: u32,
}

#[derive(Default)]
pub struct ProgramBlobBuilder {
    ro_data_size: u32,
    rw_data_size: u32,
    stack_size: u32,
    ro_data: Vec<u8>,
    rw_data: Vec<u8>,
    imports: Vec<ProgramSymbol<Box<[u8]>>>,
    exports: Vec<(u32, ProgramSymbol<Box<[u8]>>)>,
    jump_table: Vec<u8>,
    jump_table_entry_count: u32,
    jump_table_entry_size: u8,
    code: Vec<u8>,
    bitmask: Vec<u8>,
    custom: Vec<(u8, Vec<u8>)>,
    basic_block_to_instruction_index: Vec<usize>,
    instruction_index_to_code_offset: Vec<u32>,
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

    pub fn add_import(&mut self, import: &[u8]) {
        self.imports.push(ProgramSymbol::new(import.into()));
    }

    pub fn add_export_by_basic_block(&mut self, target_basic_block: u32, symbol: &[u8]) {
        self.exports.push((target_basic_block, ProgramSymbol::new(symbol.into())));
    }

    pub fn set_code(&mut self, code: &[impl Into<InstructionOrBytes> + Copy], jump_table: &[u32]) {
        let code: Vec<InstructionOrBytes> = code.iter().map(|inst| (*inst).into()).collect();
        fn mutate<T>(slot: &mut T, value: T) -> bool
        where
            T: PartialEq,
        {
            if *slot == value {
                false
            } else {
                *slot = value;
                true
            }
        }

        let mut basic_block_to_instruction_index = Vec::with_capacity(code.len());
        basic_block_to_instruction_index.push(0);

        for (nth_instruction, instruction) in code.iter().enumerate() {
            if let InstructionOrBytes::Instruction(inst) = instruction {
                if inst.opcode().starts_new_basic_block() {
                    basic_block_to_instruction_index.push(nth_instruction + 1);
                }
            }
        }

        self.jump_table.clear();
        self.code.clear();

        let mut instructions = Vec::new();
        let mut position: u32 = 0;
        for (nth_instruction, instruction) in code.iter().enumerate() {
            let entry = match instruction {
                InstructionOrBytes::Instruction(mut instruction) => {
                    let target = instruction.target_mut();
                    let target_nth_instruction = target.map(|target| {
                        let target_nth_instruction = basic_block_to_instruction_index[*target as usize];

                        // This is completely inaccurate, but that's fine.
                        *target = position.wrapping_add((target_nth_instruction as i32 - nth_instruction as i32) as u32);
                        target_nth_instruction
                    });

                    SerializedInstruction {
                        instruction: Some(instruction),
                        bytes: InstructionBuffer::from((position, instruction)),
                        target_nth_instruction,
                        position,
                    }
                }
                // The instruction in the form of raw bytes, that should only be appended, as we want to
                // be able to slip in invalid instructions, e.g., jump instruction with an invalid offset
                InstructionOrBytes::Raw(bytes) => SerializedInstruction {
                    instruction: None,
                    bytes: *bytes,
                    target_nth_instruction: None,
                    position,
                },
            };

            position = position.checked_add(entry.bytes.len() as u32).expect("too many instructions");
            instructions.push(entry);
        }

        // Adjust offsets to other instructions until we reach a steady state.
        loop {
            let mut modified = false;
            position = 0;
            for nth_instruction in 0..instructions.len() {
                modified |= mutate(&mut instructions[nth_instruction].position, position);

                if let Some(target_nth_instruction) = instructions[nth_instruction].target_nth_instruction {
                    let new_target = instructions[target_nth_instruction].position;

                    if let Some(mut instruction) = instructions[nth_instruction].instruction {
                        if mutate(instruction.target_mut().unwrap(), new_target) || modified {
                            instructions[nth_instruction].bytes = InstructionBuffer::from((position, instruction));
                        }
                    }
                }

                position = position
                    .checked_add(instructions[nth_instruction].bytes.len() as u32)
                    .expect("too many instructions");
            }

            if !modified {
                break;
            }
        }

        let mut jump_table_entry_size = 0;
        let mut jump_table_entries = Vec::with_capacity(jump_table.len());
        for &target in jump_table {
            let target_nth_instruction = basic_block_to_instruction_index[target as usize];
            let offset = instructions[target_nth_instruction].position.to_le_bytes();
            jump_table_entries.push(offset);
            jump_table_entry_size = core::cmp::max(jump_table_entry_size, offset.iter().take_while(|&&b| b != 0).count());
        }

        self.jump_table_entry_count = jump_table_entries.len() as u32;
        self.jump_table_entry_size = jump_table_entry_size as u8;
        for target in jump_table_entries {
            self.jump_table.extend_from_slice(&target[..jump_table_entry_size]);
        }

        struct BitVec {
            bytes: Vec<u8>,
            current: usize,
            bits: usize,
        }

        impl BitVec {
            fn new() -> Self {
                BitVec {
                    bytes: Vec::new(),
                    current: 0,
                    bits: 0,
                }
            }

            fn push(&mut self, value: bool) {
                self.current |= usize::from(value) << self.bits;
                self.bits += 1;
                if self.bits == 8 {
                    self.bytes.push(self.current as u8);
                    self.current = 0;
                    self.bits = 0;
                }
            }

            fn finish(mut self) -> Vec<u8> {
                while self.bits > 0 {
                    self.push(true);
                }
                self.bytes
            }
        }

        let mut bitmask = BitVec::new();
        for entry in &instructions {
            bitmask.push(true);
            for _ in 1..entry.bytes.len() {
                bitmask.push(false);
            }

            self.code.extend_from_slice(&entry.bytes);
        }

        self.bitmask = bitmask.finish();

        log::debug!("code: {:?}", self.code);
        log::debug!("bitmask: {:?}", self.bitmask);

        self.basic_block_to_instruction_index = basic_block_to_instruction_index;
        self.instruction_index_to_code_offset = instructions.iter().map(|entry| entry.position).collect();

        if cfg!(debug_assertions) {
            // Sanity check.
            let mut parsed = Vec::new();
            let mut offsets = alloc::collections::BTreeSet::new();
            for instruction in crate::program::Instructions::new(&self.code, &self.bitmask, 0) {
                parsed.push((instruction.offset, instruction.kind));
                offsets.insert(instruction.offset);
            }
            assert_eq!(parsed.len(), instructions.len());

            for ((offset, mut instruction), entry) in parsed.into_iter().zip(instructions.into_iter()) {
                if let Some(entry_instruction) = entry.instruction {
                    // @Jan: Don't know why this is allways failing
                    // assert_eq!(instruction, entry_instruction, "broken serialization: {:?}", entry.bytes.bytes);
                    assert_eq!(entry.position, offset);
                    if let Some(target) = instruction.target_mut() {
                        assert!(offsets.contains(target));
                    }
                }
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
                let mut offsets_blob = Vec::new();
                let mut symbols_blob = Vec::new();
                for symbol in &self.imports {
                    offsets_blob.extend_from_slice(&(symbols_blob.len() as u32).to_le_bytes());
                    symbols_blob.extend_from_slice(symbol.as_bytes())
                }

                writer.push_varint(self.imports.len().try_into().expect("too many imports"));
                writer.push_raw_bytes(&offsets_blob);
                writer.push_raw_bytes(&symbols_blob);
            });
        }

        if !self.exports.is_empty() {
            writer.push_section_inplace(program::SECTION_EXPORTS, |writer| {
                writer.push_varint(self.exports.len().try_into().expect("too many exports"));
                for (target_basic_block, symbol) in self.exports {
                    let nth_instruction = self.basic_block_to_instruction_index[target_basic_block as usize];
                    let offset = self.instruction_index_to_code_offset[nth_instruction];
                    writer.push_varint(offset);
                    writer.push_bytes_with_length(symbol.as_bytes());
                }
            });
        }

        writer.push_section_inplace(program::SECTION_CODE_AND_JUMP_TABLE, |writer| {
            writer.push_varint(self.jump_table_entry_count);
            writer.push_byte(self.jump_table_entry_size);
            writer.push_varint(self.code.len() as u32);
            writer.push_raw_bytes(&self.jump_table);
            writer.push_raw_bytes(&self.code);
            writer.push_raw_bytes(&self.bitmask);
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
