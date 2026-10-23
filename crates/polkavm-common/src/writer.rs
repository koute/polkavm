use crate::program::{
    self, Instruction, InstructionSet, InstructionSetKind, ProgramCounter, ProgramSymbol, BLOB_LEN_OFFSET, BLOB_LEN_SIZE,
};
use alloc::boxed::Box;
use alloc::string::String;
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

    fn new(isa: InstructionSetKind, position: u32, minimum_size: u8, instruction: Instruction) -> Self {
        let mut buffer = Self {
            bytes: [0; program::MAX_INSTRUCTION_LENGTH],
            length: 0,
        };

        let minimum_size = minimum_size as usize;
        let mut length = instruction.serialize_into(isa, position, &mut buffer.bytes);
        if length < minimum_size {
            let Instruction::jump(target) = instruction else {
                // We currently only need this for jumps.
                unreachable!();
            };
            assert!(minimum_size >= 1 && minimum_size <= 5);

            if isa.is_legacy() {
                buffer.bytes[1..minimum_size].copy_from_slice(&u32::to_le_bytes(target.wrapping_sub(position))[..minimum_size - 1]);
                length = minimum_size;
            } else {
                for minimum_imm_length in 1..=4 {
                    length = program::Instruction::serialize_offset_with_minimum_imm_length(
                        isa,
                        &mut buffer.bytes,
                        position,
                        program::Opcode::jump,
                        target,
                        minimum_imm_length,
                    );
                    if length == minimum_size {
                        break;
                    }
                }

                assert_eq!(length, minimum_size, "internal error: failed to serialize a fixed-size jump");
            }
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
    pub fn target_mut(&mut self) -> Option<&mut u32> {
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

#[derive(Clone)]
pub struct ProgramBlobBuilder {
    isa: InstructionSetKind,
    ro_data_size: u32,
    rw_data_size: u32,
    stack_size: u32,
    ro_data: Vec<u8>,
    rw_data: Vec<u8>,
    imports: Vec<ProgramSymbol<Box<[u8]>>>,
    exports: Vec<(Export, ProgramSymbol<Box<[u8]>>)>,
    code: Vec<Instruction>,
    jump_table: Vec<u32>,
    custom: Vec<(u8, Vec<u8>)>,
    dispatch_table: Vec<Vec<u8>>,
    ignore_instruction_set_incompatibility: bool,
}

struct SerializedCode {
    jump_table: Vec<u8>,
    jump_table_entry_count: u32,
    jump_table_entry_size: u8,
    code: Vec<u8>,
    bitmask: Vec<u8>,
    exports: Vec<(u32, Vec<u8>)>,
    instruction_offsets: Vec<(ProgramCounter, ProgramCounter)>,
}

#[derive(Copy, Clone)]
enum Export {
    ByBlock(u32),
    ByInstruction(u32),
}

impl ProgramBlobBuilder {
    pub fn new(isa: InstructionSetKind) -> Self {
        Self {
            isa,
            ro_data_size: Default::default(),
            rw_data_size: Default::default(),
            stack_size: Default::default(),
            ro_data: Default::default(),
            rw_data: Default::default(),
            imports: Default::default(),
            exports: Default::default(),
            code: Default::default(),
            jump_table: Default::default(),
            custom: Default::default(),
            dispatch_table: Default::default(),
            ignore_instruction_set_incompatibility: false,
        }
    }

    pub fn set_ignore_instruction_set_incompatibility(&mut self, value: bool) {
        self.ignore_instruction_set_incompatibility = value;
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
        self.exports
            .push((Export::ByBlock(target_basic_block), ProgramSymbol::new(symbol.into())));
    }

    pub fn add_export_by_instruction(&mut self, target_instruction: u32, symbol: &[u8]) {
        self.exports
            .push((Export::ByInstruction(target_instruction), ProgramSymbol::new(symbol.into())));
    }

    pub fn add_dispatch_table_entry(&mut self, symbol: impl Into<Vec<u8>>) {
        self.dispatch_table.push(symbol.into());
    }

    pub fn set_code(&mut self, code: &[Instruction], jump_table: &[u32]) {
        self.code = code.to_vec();
        self.jump_table = jump_table.to_vec();
    }

    fn serialize_code(&self, collect_instruction_offsets: bool) -> Result<SerializedCode, String> {
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
            let Some(&(target, _)) = self.exports.iter().find(|(_, export_symbol)| symbol == export_symbol.as_bytes()) else {
                return Err(alloc::format!(
                    "failed to build a dispatch table: symbol not found: {}",
                    ProgramSymbol::new(symbol)
                ));
            };

            let minimum_size = if nth + 1 == self.dispatch_table.len() {
                // The last entry doesn't have to be padded.
                0
            } else {
                5
            };

            let target_basic_block = match target {
                Export::ByBlock(target) => target,
                Export::ByInstruction(..) => {
                    return Err(alloc::format!(
                        "failed to build a dispatch table: points to a symbol which is not basic block based: {}",
                        ProgramSymbol::new(symbol)
                    ));
                }
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

            if !self.ignore_instruction_set_incompatibility {
                let opcode = instruction.opcode();
                if !self.isa.supports_opcode(opcode) {
                    return Err(alloc::format!(
                        "failed to build a program: the instruction '{}' is not available in the '{}' instruction set",
                        opcode.name(),
                        self.isa.name(),
                    ));
                }
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

        let is_legacy = self.isa.is_legacy();
        if !is_legacy && self.dispatch_table.len() * 5 > program::CODE_BLOCK_SIZE {
            return Err("the dispatch table is too big to fit in a single code block".into());
        }

        let original_instruction_count = instructions.len();
        if !is_legacy
            && instructions
                .last()
                .is_some_and(|entry| !entry.instruction.opcode().starts_new_basic_block())
        {
            // The end of the code is a macro block boundary, so the last instruction has to end
            // a basic block; if it doesn't then it would be decoded as a trap and never run.
            instructions.push(SerializedInstruction {
                instruction: Instruction::trap,
                bytes: InstructionBuffer::default(),
                target_nth_instruction: None,
                position: 0,
                minimum_size: 0,
            });
        }

        let padded_position = |position: u32, length: u32, ends_block: bool| -> u32 {
            if is_legacy || length == 0 {
                return position;
            }

            let next_boundary = program::next_block_boundary(position as usize) as u32;
            if position + length <= next_boundary - u32::from(!ends_block) {
                position
            } else {
                // Instructions cannot cross a macro block, so start it in the new block.
                next_boundary
            }
        };

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
            entry.bytes = InstructionBuffer::new(self.isa, position, entry.minimum_size, entry.instruction);
            let ends_block = entry.instruction.opcode().starts_new_basic_block();
            let new_position = padded_position(position, entry.bytes.len() as u32, ends_block);
            if new_position != position {
                entry.position = new_position;
                entry.bytes = InstructionBuffer::new(self.isa, new_position, entry.minimum_size, entry.instruction);
            }

            position = entry.position.checked_add(entry.bytes.len() as u32).expect("too many instructions");
        }

        // Adjust offsets to other instructions until we reach a steady state.
        let mut remaining_iterations = 1024; // Limit the iteration count, just in case.
        loop {
            let mut any_modified = false;
            position = 0;
            for nth_instruction in 0..instructions.len() {
                let has_target = instructions[nth_instruction].target_nth_instruction.is_some();
                let mut target_modified = false;
                if let Some(target_nth_instruction) = instructions[nth_instruction].target_nth_instruction {
                    let new_target = instructions[target_nth_instruction].position;
                    let old_target = instructions[nth_instruction].instruction.target_mut().unwrap();
                    target_modified = mutate(old_target, new_target);
                }

                // Only instructions with a target have position-dependent bytes, so only
                // they need re-serialization when their position changes.
                if target_modified || (has_target && instructions[nth_instruction].position != position) {
                    instructions[nth_instruction].bytes = InstructionBuffer::new(
                        self.isa,
                        position,
                        instructions[nth_instruction].minimum_size,
                        instructions[nth_instruction].instruction,
                    );
                }

                let ends_block = instructions[nth_instruction].instruction.opcode().starts_new_basic_block();
                let new_position = padded_position(position, instructions[nth_instruction].bytes.len() as u32, ends_block);
                if new_position != position && has_target {
                    instructions[nth_instruction].bytes = InstructionBuffer::new(
                        self.isa,
                        new_position,
                        instructions[nth_instruction].minimum_size,
                        instructions[nth_instruction].instruction,
                    );

                    debug_assert_eq!(
                        padded_position(new_position, instructions[nth_instruction].bytes.len() as u32, ends_block),
                        new_position
                    );
                }

                let position_modified = mutate(&mut instructions[nth_instruction].position, new_position);
                position = new_position
                    .checked_add(instructions[nth_instruction].bytes.len() as u32)
                    .expect("too many instructions");

                any_modified |= target_modified | position_modified;
            }

            if !any_modified {
                break;
            }

            remaining_iterations -= 1;
            if remaining_iterations == 0 {
                return Err("internal error: failed to build a program: the code layout did not reach a steady state".into());
            }
        }

        let mut jump_table_entry_size = 0;
        let mut jump_table_entries = Vec::with_capacity(self.jump_table.len());
        for &target in &self.jump_table {
            let target = target + basic_block_shift;
            let target_nth_instruction = basic_block_to_instruction_index[target as usize];
            let position = instructions[target_nth_instruction].position;
            jump_table_entries.push(position.to_le_bytes());
            jump_table_entry_size = core::cmp::max(jump_table_entry_size, 4 - position.leading_zeros() as usize / 8);
        }

        let mut output = SerializedCode {
            jump_table_entry_count: jump_table_entries.len() as u32,
            jump_table_entry_size: jump_table_entry_size as u8,
            jump_table: Vec::with_capacity(jump_table_entry_size * jump_table_entries.len()),
            code: Vec::with_capacity(instructions.iter().map(|entry| entry.bytes.len()).sum()),
            bitmask: Vec::new(),
            exports: Vec::with_capacity(self.exports.len()),
            instruction_offsets: if collect_instruction_offsets {
                (0..original_instruction_count)
                    .map(|nth_instruction| {
                        let entry = &instructions[nth_instruction];
                        let end = match instructions.get(nth_instruction + 1) {
                            Some(next_entry) => next_entry.position,
                            // Extend the range to the next instruction, so that debug info works as expected.
                            None => entry.position + entry.bytes.len() as u32,
                        };

                        (ProgramCounter(entry.position), ProgramCounter(end))
                    })
                    .collect()
            } else {
                Vec::new()
            },
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

        if is_legacy {
            let mut bitmask = BitVec::with_capacity(output.code.capacity() / 8 + 1);
            for entry in &instructions {
                bitmask.push(true);
                for _ in 1..entry.bytes.len() {
                    bitmask.push(false);
                }

                output.code.extend_from_slice(&entry.bytes);
            }

            output.bitmask = bitmask.finish();
        } else {
            let to_single_byte_opcode = |instruction: Instruction| -> u8 {
                let mut buffer = [0; program::MAX_INSTRUCTION_LENGTH];
                let length = instruction.serialize_into(self.isa, 0, &mut buffer);
                assert_eq!(length, 1, "internal error: {instruction:?} is not a single byte instruction");
                buffer[0]
            };

            let fallthrough_byte = to_single_byte_opcode(Instruction::fallthrough);
            let unlikely_byte = to_single_byte_opcode(Instruction::unlikely);
            for entry in &instructions {
                let Some(gap) = entry.position.checked_sub(output.code.len() as u32) else {
                    return Err("internal error: failed to build a program: the code layout produced overlapping instructions".into());
                };

                if gap > 0 {
                    debug_assert_eq!(entry.position as usize % program::CODE_BLOCK_SIZE, 0);
                    debug_assert!(gap < program::CODE_BLOCK_SIZE as u32);

                    // The padding has to end with an instruction which ends a basic block.
                    output.code.resize(entry.position as usize - 1, unlikely_byte);
                    output.code.push(fallthrough_byte);
                }

                output.code.extend_from_slice(&entry.bytes);
            }
        }

        for (target, symbol) in &self.exports {
            let nth_instruction = match target {
                Export::ByBlock(target_basic_block) => {
                    let target_basic_block = *target_basic_block as usize + basic_block_shift as usize;
                    basic_block_to_instruction_index[target_basic_block]
                }
                Export::ByInstruction(nth_instruction) => *nth_instruction as usize,
            };

            let offset = instructions[nth_instruction].position;
            output.exports.push((offset, symbol.as_bytes().to_vec()));
        }

        if cfg!(debug_assertions) {
            // Sanity check.
            let mut parsed = Vec::new();
            let mut offsets = alloc::collections::BTreeSet::new();

            let parsed_instructions: Vec<_> =
                crate::program::Instructions::new_unbounded(self.isa, &output.code, &output.bitmask, 0).collect();
            for instruction in parsed_instructions {
                if instruction.offset.0 as usize == output.code.len() {
                    // Implicit trap.
                    debug_assert!(matches!(instruction.kind, Instruction::invalid));
                    break;
                }
                parsed.push(instruction);
                offsets.insert(instruction.offset);
            }

            let mut nth_instruction = 0;
            let mut previous_ends_block = true;
            for mut parsed in parsed {
                assert!(
                    nth_instruction < instructions.len(),
                    "parsed more instructions than were serialized"
                );

                if !is_legacy {
                    // A macro block boundary must always start a new basic block.
                    if parsed.offset.0 as usize % program::CODE_BLOCK_SIZE == 0 && parsed.offset.0 != 0 {
                        assert!(
                            previous_ends_block,
                            "instruction at the macro block boundary {} is not preceded by a basic block terminator",
                            parsed.offset
                        );
                    }

                    previous_ends_block = parsed.kind.opcode().starts_new_basic_block();
                }

                let entry = &instructions[nth_instruction];
                if !is_legacy && parsed.offset.0 < entry.position {
                    // Macro block padding.
                    assert!(
                        matches!(parsed.kind, Instruction::fallthrough | Instruction::unlikely),
                        "macro block padding decoded as something else than a padding instruction: {:?}",
                        parsed.kind
                    );
                    continue;
                }

                let parsed_length = parsed.next_offset.0 - parsed.offset.0;
                let opcode_mismatch = parsed.kind != entry.instruction && !self.ignore_instruction_set_incompatibility;
                if opcode_mismatch || entry.position != parsed.offset.0 || u32::from(entry.bytes.length) != parsed_length {
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

                nth_instruction += 1;
            }

            assert_eq!(nth_instruction, instructions.len());
        }

        Ok(output)
    }

    pub fn add_custom_section(&mut self, section: u8, contents: Vec<u8>) {
        self.custom.push((section, contents));
    }

    pub fn into_vec(self) -> Result<Vec<u8>, String> {
        self.to_vec()
    }

    pub fn to_vec(&self) -> Result<Vec<u8>, String> {
        self.blob_from_code(self.serialize_code(false)?)
    }

    pub fn to_vec_with_instruction_offsets(
        &mut self,
        emit_extra_sections: impl FnOnce(&mut Self, &[(ProgramCounter, ProgramCounter)]),
    ) -> Result<Vec<u8>, String> {
        let mut code = self.serialize_code(true)?;
        let instruction_offsets = core::mem::take(&mut code.instruction_offsets);
        emit_extra_sections(self, &instruction_offsets);
        self.blob_from_code(code)
    }

    fn blob_from_code(&self, code: SerializedCode) -> Result<Vec<u8>, String> {
        let mut output = Vec::new();
        let mut writer = Writer::new(&mut output);

        writer.push_raw_bytes(&program::BLOB_MAGIC);
        writer.push_byte(self.isa.blob_version());
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
            if self.isa.is_legacy() {
                writer.push_varint(code.code.len() as u32);
            }
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

        Ok(output)
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

#[cfg(test)]
mod tests {
    use super::ProgramBlobBuilder;
    use crate::program::{Instruction, InstructionSetKind, ProgramBlob, SECTION_OPT_METADATA_HASH};

    fn build_minimal(metadata_hash: Option<&[u8]>) -> ProgramBlob {
        let mut builder = ProgramBlobBuilder::new(InstructionSetKind::ReviveV1);
        builder.set_code(&[Instruction::trap], &[]);
        if let Some(metadata_hash) = metadata_hash {
            builder.add_custom_section(SECTION_OPT_METADATA_HASH, metadata_hash.to_vec());
        }
        ProgramBlob::parse(builder.to_vec().unwrap().into()).unwrap()
    }

    #[test]
    fn metadata_hash_section_round_trips() {
        let metadata_hash = [0xab_u8; 32];
        let blob = build_minimal(Some(&metadata_hash));
        assert_eq!(blob.metadata_hash(), metadata_hash);
    }

    #[test]
    fn metadata_hash_is_empty_when_absent() {
        let blob = build_minimal(None);
        assert!(blob.metadata_hash().is_empty());
    }

    #[test]
    fn program_which_doesnt_end_a_basic_block_gets_a_trap_appended() {
        use crate::program::{asm, Reg};

        let build = |code: &[Instruction]| -> alloc::vec::Vec<Instruction> {
            let mut builder = ProgramBlobBuilder::new(InstructionSetKind::Latest64);
            builder.set_code(code, &[]);
            let blob = ProgramBlob::parse(builder.to_vec().unwrap().into()).unwrap();
            blob.instructions().map(|instruction| instruction.kind).collect()
        };

        let unterminated = [asm::load_imm(Reg::A0, 1), asm::load_imm(Reg::A0, 2)];
        assert_eq!(build(&unterminated), [unterminated[0], unterminated[1], Instruction::trap]);

        let terminated = [asm::load_imm(Reg::A0, 1), asm::ret()];
        assert_eq!(build(&terminated), terminated);
    }

    #[test]
    fn oversized_basic_block_is_split_at_macro_block_boundaries() {
        use crate::program::{asm, Opcode, Reg, CODE_BLOCK_SIZE};

        let isa = InstructionSetKind::Latest64;
        let mut code = alloc::vec::Vec::new();
        for nth in 0..CODE_BLOCK_SIZE as i32 {
            code.push(asm::load_imm(Reg::A0, 0x12345678 + nth));
        }
        code.push(asm::ret());

        let mut builder = ProgramBlobBuilder::new(isa);
        builder.set_code(&code, &[]);
        let blob = ProgramBlob::parse(builder.to_vec().unwrap().into()).unwrap();
        assert!(blob.code().len() > CODE_BLOCK_SIZE);

        let mut previous_ends_block = true;
        let mut original = code.iter().copied();
        for parsed in blob.instructions() {
            if parsed.offset.0 as usize % CODE_BLOCK_SIZE == 0 && parsed.offset.0 != 0 {
                assert!(
                    previous_ends_block,
                    "instruction at the macro block boundary {} is not preceded by a basic block terminator",
                    parsed.offset
                );
            }

            previous_ends_block = parsed.kind.opcode().starts_new_basic_block();
            if matches!(parsed.kind.opcode(), Opcode::fallthrough | Opcode::unlikely) {
                continue;
            }

            assert_eq!(Some(parsed.kind), original.next());
        }

        assert_eq!(original.next(), None);
    }

    #[test]
    fn jump_heavy_code_layout_reaches_a_steady_state() {
        use crate::program::{asm, InstructionSetKind, Reg};

        let mut state: u64 = 0x853c49e6748fea9b;
        let mut rng = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };

        for _ in 0..100 {
            let mut code = alloc::vec::Vec::new();
            for nth in 0..200 + rng() % 2000 {
                code.push(match rng() % 8 {
                    0 => asm::jump(rng() as u32),
                    1 => asm::branch_eq(Reg::A0, Reg::A1, rng() as u32),
                    2 => asm::load_imm64(Reg::A0, rng()),
                    3 => asm::load_imm(Reg::A0, rng() as u32 as i32),
                    4 => asm::add_imm_64(Reg::A0, Reg::A1, (rng() & 0xffff) as i32),
                    5 => asm::store_imm_u64(rng() as u32 as i32, nth as i32),
                    _ => asm::add_64(Reg::A0, Reg::A1, Reg::A2),
                });
            }
            code.push(asm::trap());

            // The very last basic block is empty, so it's not a legal jump target.
            let block_count = code
                .iter()
                .filter(|instruction| instruction.opcode().starts_new_basic_block())
                .count() as u32;
            for instruction in code.iter_mut() {
                if let Some(target) = instruction.target_mut() {
                    *target %= block_count;
                }
            }

            let mut builder = ProgramBlobBuilder::new(InstructionSetKind::Latest64);
            builder.set_code(&code, &[]);
            if let Err(error) = builder.to_vec() {
                panic!("failed to build a program with {} instructions: {error}", code.len());
            }
        }
    }
}
