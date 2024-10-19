use crate::program::{self, Instruction, ProgramCounter, ProgramSymbol, BLOB_LEN_OFFSET, BLOB_LEN_SIZE};
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::ops::Range;

#[derive(Copy, Clone, Default)]
struct InstructionBuffer {
    bytes: [u8; program::MAX_INSTRUCTION_LENGTH],
    length: u8,
}

impl InstructionBuffer {
    fn len(&self) -> usize {
        self.length as usize
    }

    fn new(position: u32, minimum_size: u8, instruction: Instruction) -> Self {
        let mut buffer = Self {
            bytes: [0; program::MAX_INSTRUCTION_LENGTH],
            length: 0,
        };

        let minimum_size = minimum_size as usize;
        let mut length = instruction.serialize_into(position, &mut buffer.bytes);
        if length < minimum_size {
            let Instruction::jump(target) = instruction else {
                // We currently only need this for jumps.
                unreachable!();
            };
            assert!(minimum_size >= 1 && minimum_size <= 5);

            buffer.bytes[1..minimum_size].copy_from_slice(&u32::to_le_bytes(target.wrapping_sub(position))[..minimum_size - 1]);
            length = minimum_size;
        }

        buffer.length = length as u8;
        buffer
    }
}

impl core::ops::Deref for InstructionBuffer {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.bytes[..self.length as usize]
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
struct SerializedInstruction {
    instruction: Instruction,
    bytes: InstructionBuffer,
    target_nth_instruction: Option<usize>,
    position: u32,
    minimum_size: u8,
}

#[derive(Default)]
pub struct ProgramBlobBuilder {
    is_64: bool,
    ro_data_size: u32,
    rw_data_size: u32,
    stack_size: u32,
    ro_data: Vec<u8>,
    rw_data: Vec<u8>,
    imports: Vec<ProgramSymbol<Box<[u8]>>>,
    exports: Vec<(u32, ProgramSymbol<Box<[u8]>>)>,
    code: Vec<Instruction>,
    jump_table: Vec<u32>,
    custom: Vec<(u8, Vec<u8>)>,
    dispatch_table: Vec<Vec<u8>>,
}

struct SerializedCode {
    jump_table: Vec<u8>,
    jump_table_entry_count: u32,
    jump_table_entry_size: u8,
    code: Vec<u8>,
    bitmask: Vec<u8>,
    exports: Vec<(u32, Vec<u8>)>,
}

impl ProgramBlobBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn new_64bit() -> Self {
        let mut builder = Self::new();
        builder.is_64 = true;
        builder
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

    pub fn add_dispatch_table_entry(&mut self, symbol: impl Into<Vec<u8>>) {
        self.dispatch_table.push(symbol.into());
    }

    pub fn set_code(&mut self, code: &[Instruction], jump_table: &[u32]) {
        self.code = code.to_vec();
        self.jump_table = jump_table.to_vec();
    }

    fn serialize_code(&self) -> SerializedCode {
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

        // We will need to shift all of the basic block indexes by how many entries are in our injected dispatch table.
        let basic_block_shift = self.dispatch_table.len() as u32;

        let mut instructions = Vec::with_capacity(self.dispatch_table.len() + self.code.len());
        for (nth, symbol) in self.dispatch_table.iter().enumerate() {
            let Some(&(target_basic_block, _)) = self.exports.iter().find(|(_, export_symbol)| symbol == export_symbol.as_bytes()) else {
                // TODO: Return an error.
                panic!("failed to build a dispatch table: symbol not found: {}", ProgramSymbol::new(symbol));
            };

            let minimum_size = if nth + 1 == self.dispatch_table.len() {
                // The last entry doesn't have to be padded.
                0
            } else {
                5
            };

            instructions.push(SerializedInstruction {
                instruction: Instruction::jump(target_basic_block + basic_block_shift),
                bytes: InstructionBuffer::default(),
                target_nth_instruction: None,
                position: 0,
                minimum_size,
            });
        }

        for instruction in &self.code {
            let mut instruction = *instruction;
            if let Some(target_basic_block) = instruction.target_mut() {
                *target_basic_block += basic_block_shift;
            }

            instructions.push(SerializedInstruction {
                instruction,
                bytes: InstructionBuffer::default(),
                target_nth_instruction: None,
                position: 0,
                minimum_size: 0,
            });
        }

        let mut basic_block_to_instruction_index = Vec::with_capacity(self.code.len());
        basic_block_to_instruction_index.push(0);

        for (nth_instruction, entry) in instructions.iter().enumerate() {
            if entry.instruction.opcode().starts_new_basic_block() {
                basic_block_to_instruction_index.push(nth_instruction + 1);
            }
        }

        let mut position: u32 = 0;
        for (nth_instruction, entry) in instructions.iter_mut().enumerate() {
            entry.target_nth_instruction = entry.instruction.target_mut().map(|target| {
                let target_nth_instruction = basic_block_to_instruction_index[*target as usize];
                // Here we change the target from a basic block index into a byte offset.
                // This is completely inaccurate, but that's fine. This is just a guess, and we'll correct it in the next loop.
                *target = position.wrapping_add((target_nth_instruction as i32 - nth_instruction as i32) as u32);
                target_nth_instruction
            });

            entry.position = position;
            entry.bytes = InstructionBuffer::new(position, entry.minimum_size, entry.instruction);
            position = position.checked_add(entry.bytes.len() as u32).expect("too many instructions");
        }

        // Adjust offsets to other instructions until we reach a steady state.
        loop {
            let mut any_modified = false;
            position = 0;
            for nth_instruction in 0..instructions.len() {
                let mut self_modified = mutate(&mut instructions[nth_instruction].position, position);
                if let Some(target_nth_instruction) = instructions[nth_instruction].target_nth_instruction {
                    let new_target = instructions[target_nth_instruction].position;
                    let old_target = instructions[nth_instruction].instruction.target_mut().unwrap();
                    self_modified |= mutate(old_target, new_target);

                    if self_modified {
                        instructions[nth_instruction].bytes = InstructionBuffer::new(
                            position,
                            instructions[nth_instruction].minimum_size,
                            instructions[nth_instruction].instruction,
                        );
                    }
                }

                position = position
                    .checked_add(instructions[nth_instruction].bytes.len() as u32)
                    .expect("too many instructions");

                any_modified |= self_modified;
            }

            if !any_modified {
                break;
            }
        }

        let mut jump_table_entry_size = 0;
        let mut jump_table_entries = Vec::with_capacity(self.jump_table.len());
        for &target in &self.jump_table {
            let target = target + basic_block_shift;
            let target_nth_instruction = basic_block_to_instruction_index[target as usize];
            let offset = instructions[target_nth_instruction].position.to_le_bytes();
            jump_table_entries.push(offset);
            jump_table_entry_size = core::cmp::max(jump_table_entry_size, offset.iter().take_while(|&&b| b != 0).count());
        }

        let mut output = SerializedCode {
            jump_table_entry_count: jump_table_entries.len() as u32,
            jump_table_entry_size: jump_table_entry_size as u8,
            jump_table: Vec::with_capacity(jump_table_entry_size * jump_table_entries.len()),
            code: Vec::with_capacity(instructions.iter().map(|entry| entry.bytes.len()).sum()),
            bitmask: Vec::new(),
            exports: Vec::with_capacity(self.exports.len()),
        };

        for target in jump_table_entries {
            output.jump_table.extend_from_slice(&target[..jump_table_entry_size]);
        }

        struct BitVec {
            bytes: Vec<u8>,
            current: usize,
            bits: usize,
        }

        impl BitVec {
            fn with_capacity(capacity: usize) -> Self {
                BitVec {
                    bytes: Vec::with_capacity(capacity),
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
                    self.push(false);
                }
                self.bytes
            }
        }

        let mut bitmask = BitVec::with_capacity(output.code.capacity() / 8 + 1);
        for entry in &instructions {
            bitmask.push(true);
            for _ in 1..entry.bytes.len() {
                bitmask.push(false);
            }

            output.code.extend_from_slice(&entry.bytes);
        }

        output.bitmask = bitmask.finish();

        for (target_basic_block, symbol) in &self.exports {
            let target_basic_block = *target_basic_block as usize + basic_block_shift as usize;
            let nth_instruction = basic_block_to_instruction_index[target_basic_block];
            let offset = instructions[nth_instruction].position;
            output.exports.push((offset, symbol.as_bytes().to_vec()));
        }

        if cfg!(debug_assertions) {
            // Sanity check.
            let mut parsed = Vec::new();
            let mut offsets = alloc::collections::BTreeSet::new();

            let parsed_instructions: Vec<_> = if self.is_64 {
                crate::program::Instructions::new_unbounded(crate::program::ISA64_V1, &output.code, &output.bitmask, 0).collect()
            } else {
                crate::program::Instructions::new_unbounded(crate::program::ISA32_V1, &output.code, &output.bitmask, 0).collect()
            };

            for instruction in parsed_instructions {
                if instruction.offset.0 as usize == output.code.len() {
                    // Implicit trap.
                    debug_assert!(matches!(instruction.kind, Instruction::invalid));
                    break;
                }
                parsed.push(instruction);
                offsets.insert(instruction.offset);
            }

            assert_eq!(parsed.len(), instructions.len());
            for (nth_instruction, (mut parsed, entry)) in parsed.into_iter().zip(instructions.into_iter()).enumerate() {
                let parsed_length = parsed.next_offset.0 - parsed.offset.0;
                if parsed.kind != entry.instruction || entry.position != parsed.offset.0 || u32::from(entry.bytes.length) != parsed_length {
                    panic!(
                        concat!(
                            "Broken serialization for instruction #{}:\n",
                            "  Serialized:\n",
                            "    Instruction: {:?}\n",
                            "    Offset:      {}\n",
                            "    Length:      {}\n",
                            "    Bytes:       {:?}\n",
                            "  Deserialized:\n",
                            "    Instruction: {:?}\n",
                            "    Offset:      {}\n",
                            "    Length:      {}\n",
                            "    Bytes:       {:?}\n",
                        ),
                        nth_instruction,
                        entry.instruction,
                        entry.position,
                        entry.bytes.len(),
                        &entry.bytes.bytes[..entry.bytes.length as usize],
                        parsed.kind,
                        parsed.offset.0,
                        parsed_length,
                        &output.code[parsed.offset.0 as usize..parsed.offset.0 as usize + parsed_length as usize],
                    );
                }

                if let Some(target) = parsed.kind.target_mut() {
                    assert!(offsets.contains(&ProgramCounter(*target)));
                }
            }
        }

        output
    }

    pub fn add_custom_section(&mut self, section: u8, contents: Vec<u8>) {
        self.custom.push((section, contents));
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.to_vec()
    }

    pub fn to_vec(&self) -> Vec<u8> {
        let code = self.serialize_code();
        let mut output = Vec::new();
        let mut writer = Writer::new(&mut output);

        writer.push_raw_bytes(&program::BLOB_MAGIC);
        if self.is_64 {
            writer.push_byte(program::BLOB_VERSION_V1_64);
        } else {
            writer.push_byte(program::BLOB_VERSION_V1_32);
        }
        writer.push_raw_bytes(&[0; BLOB_LEN_SIZE]);

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

        if !code.exports.is_empty() {
            writer.push_section_inplace(program::SECTION_EXPORTS, |writer| {
                writer.push_varint(code.exports.len().try_into().expect("too many exports"));
                for (offset, symbol) in code.exports {
                    writer.push_varint(offset);
                    writer.push_bytes_with_length(&symbol);
                }
            });
        }

        writer.push_section_inplace(program::SECTION_CODE_AND_JUMP_TABLE, |writer| {
            writer.push_varint(code.jump_table_entry_count);
            writer.push_byte(code.jump_table_entry_size);
            writer.push_varint(code.code.len() as u32);
            writer.push_raw_bytes(&code.jump_table);
            writer.push_raw_bytes(&code.code);
            writer.push_raw_bytes(&code.bitmask);
        });

        for (section, contents) in &self.custom {
            writer.push_section(*section, contents);
        }

        writer.push_raw_bytes(&[program::SECTION_END_OF_FILE]);

        let blob_len = (writer.len() as u64).to_le_bytes();
        output[BLOB_LEN_OFFSET..BLOB_LEN_OFFSET + BLOB_LEN_SIZE].copy_from_slice(&blob_len);

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
