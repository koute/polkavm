use std::{collections::HashMap, io::Write};

use polkavm_common::program::{ParsedInstruction, ProgramBlob, ProgramCounter, ISA32_V1, ISA64_V1};

#[derive(Copy, Clone, Debug, clap::ValueEnum)]
pub enum DisassemblyFormat {
    Guest,
    GuestAndNative,
    Native,
    DiffFriendly,
}

struct NativeCode {
    machine_code_origin: u64,
    machine_code: Vec<u8>,
    instruction_map: Vec<(ProgramCounter, u32)>,
}

impl TryFrom<&'_ ProgramBlob> for NativeCode {
    type Error = polkavm::Error;

    fn try_from(blob: &'_ ProgramBlob) -> Result<Self, Self::Error> {
        if !cfg!(target_arch = "x86_64") {
            return Err("the selected disassembly format is not supported on this architecture".into());
        }

        let mut config = polkavm::Config::from_env()?;
        config.set_worker_count(0);

        let engine = polkavm::Engine::new(&config)?;
        let module = polkavm::Module::from_blob(&engine, &Default::default(), blob.clone())?;

        let Some(machine_code) = module.machine_code() else {
            return Err("currently selected VM backend doesn't provide raw machine code".into());
        };

        let Some(instruction_map) = module.program_counter_to_machine_code_offset() else {
            return Err("currently selected VM backend doesn't provide a machine code map".into());
        };

        Ok(Self {
            machine_code_origin: module.machine_code_origin().unwrap_or(0),
            machine_code: machine_code.into(),
            instruction_map: instruction_map.to_vec(),
        })
    }
}

#[derive(Default)]
struct AssemblyFormatter {
    buffer: String,
}

impl AssemblyFormatter {
    fn emit(
        &mut self,
        indent: bool,
        code_origin: u64,
        mut code: &[u8],
        mut position: usize,
        writer: &mut impl Write,
    ) -> Result<(), std::io::Error> {
        use iced_x86::Formatter;

        let mut formatter = iced_x86::NasmFormatter::new();
        formatter.options_mut().set_space_after_operand_separator(true);
        formatter.options_mut().set_hex_prefix("0x");
        formatter.options_mut().set_hex_suffix("");
        formatter.options_mut().set_uppercase_hex(false);
        formatter.options_mut().set_small_hex_numbers_in_decimal(false);
        formatter.options_mut().set_show_useless_prefixes(true);
        formatter.options_mut().set_branch_leading_zeros(false);
        formatter.options_mut().set_rip_relative_addresses(true);

        loop {
            let mut decoder = iced_x86::Decoder::with_ip(64, code, code_origin, iced_x86::DecoderOptions::NONE);
            if !decoder.can_decode() {
                break;
            }
            let mut instruction = iced_x86::Instruction::default();
            decoder.decode_out(&mut instruction);

            if indent {
                write!(writer, "                                       ")?;
            }
            write!(writer, "{:8x}: ", position as u64 + code_origin)?;

            let start_index = (instruction.ip() - code_origin) as usize;
            let instr_bytes = &code[start_index..start_index + instruction.len()];
            let mut count = 0;
            for b in instr_bytes.iter() {
                write!(writer, "{:02x} ", b)?;
                count += 3;
            }
            while count < 34 {
                write!(writer, " ")?;
                count += 1;
            }

            self.buffer.clear();
            formatter.format(&instruction, &mut self.buffer);
            write!(writer, "{}", self.buffer)?;
            writeln!(writer)?;

            code = &code[instruction.len()..];
            position += instruction.len();
        }

        Ok(())
    }
}

pub struct Disassembler<'a> {
    blob: &'a ProgramBlob,
    format: DisassemblyFormat,
    gas_cost_map: Option<HashMap<ProgramCounter, i64>>,
    native: Option<NativeCode>,
    show_raw_bytes: bool,
    prefer_non_abi_reg_names: bool,
    prefer_unaliased: bool,
    prefer_offset_jump_targets: bool,
    emit_header: bool,
    emit_exports: bool,
    show_offsets: bool,
}

impl<'a> Disassembler<'a> {
    pub fn new(blob: &'a ProgramBlob, format: DisassemblyFormat) -> Result<Self, polkavm::Error> {
        let native = if matches!(format, DisassemblyFormat::Native | DisassemblyFormat::GuestAndNative) {
            Some(NativeCode::try_from(blob)?)
        } else {
            None
        };

        Ok(Self {
            blob,
            format,
            gas_cost_map: None,
            native,
            show_raw_bytes: false,
            prefer_non_abi_reg_names: false,
            prefer_unaliased: false,
            prefer_offset_jump_targets: false,
            emit_header: true,
            emit_exports: true,
            show_offsets: true,
        })
    }

    pub fn show_raw_bytes(&mut self, value: bool) {
        self.show_raw_bytes = value;
    }

    pub fn prefer_non_abi_reg_names(&mut self, value: bool) {
        self.prefer_non_abi_reg_names = value;
    }

    pub fn prefer_unaliased(&mut self, value: bool) {
        self.prefer_unaliased = value;
    }

    pub fn prefer_offset_jump_targets(&mut self, value: bool) {
        self.prefer_offset_jump_targets = value;
    }

    pub fn emit_header(&mut self, value: bool) {
        self.emit_header = value;
    }

    pub fn emit_exports(&mut self, value: bool) {
        self.emit_exports = value;
    }

    pub fn show_offsets(&mut self, value: bool) {
        self.show_offsets = value;
    }

    fn instructions(&self) -> Vec<ParsedInstruction> {
        if self.blob.is_64_bit() {
            self.blob.instructions(ISA64_V1).collect()
        } else {
            self.blob.instructions(ISA32_V1).collect()
        }
    }

    pub fn display_gas(&mut self) -> Result<(), polkavm::Error> {
        let mut config = polkavm::Config::from_env()?;
        config.set_worker_count(0);
        config.set_backend(Some(polkavm::BackendKind::Interpreter));

        let engine = polkavm::Engine::new(&config)?;

        let mut config = polkavm::ModuleConfig::default();
        config.set_gas_metering(Some(polkavm::GasMeteringKind::Sync));

        let module = polkavm::Module::from_blob(&engine, &config, self.blob.clone())?;

        let mut in_new_block = true;
        let mut gas_cost_map = HashMap::new();
        for instruction in self.instructions() {
            if in_new_block {
                in_new_block = false;
                if let Some(cost) = module.calculate_gas_cost_for(instruction.offset) {
                    gas_cost_map.insert(instruction.offset, cost);
                }
            }

            if instruction.starts_new_basic_block() {
                in_new_block = true;
            }
        }
        self.gas_cost_map = Some(gas_cost_map);

        Ok(())
    }

    pub fn disassemble_into(&self, mut writer: impl Write) -> Result<(), polkavm::Error> {
        let mut instructions = Vec::new();
        let mut instruction_offset_to_basic_block = HashMap::new();
        {
            let mut basic_block_counter = 0;
            let mut basic_block_started = true;
            for instruction in self.instructions() {
                if basic_block_started {
                    instruction_offset_to_basic_block.insert(instruction.offset, basic_block_counter);
                    basic_block_started = false;
                }

                if instruction.starts_new_basic_block() {
                    basic_block_started = true;
                    basic_block_counter += 1;
                }
                instructions.push(instruction);
            }
        }

        let mut exports_for_code_offset = HashMap::new();
        for (nth_export, export) in self.blob.exports().enumerate() {
            exports_for_code_offset
                .entry(export.program_counter())
                .or_insert_with(Vec::new)
                .push((nth_export, export));
        }

        let mut jump_table_map = HashMap::new();
        let mut jump_table = Vec::new();
        for target_code_offset in self.blob.jump_table() {
            let jump_table_index = jump_table.len() + 1;
            jump_table.push(target_code_offset);
            assert!(jump_table_map.insert(target_code_offset, jump_table_index).is_none());
        }

        macro_rules! w {
            (@no_newline $($arg:tt)*) => {{
                if let Err(error) = write!(&mut writer, $($arg)*) {
                    return Err(format!("failed to write to output: {error}").into());
                }
            }};

            ($($arg:tt)*) => {{
                if let Err(error) = writeln!(&mut writer, $($arg)*) {
                    return Err(format!("failed to write to output: {error}").into());
                }
            }};
        }

        if self.emit_header {
            w!("// RO data = {}/{} bytes", self.blob.ro_data().len(), self.blob.ro_data_size());
            w!("// RW data = {}/{} bytes", self.blob.rw_data().len(), self.blob.rw_data_size());
            w!("// Stack size = {} bytes", self.blob.stack_size());
            w!();
            w!("// Instructions = {}", instructions.len());
            w!("// Code size = {} bytes", self.blob.code().len());
            w!();
        }

        let format_jump_target = |target_offset: ProgramCounter, basic_block_counter: u32| {
            use core::fmt::Write;

            let mut buf = String::new();
            if !matches!(self.format, DisassemblyFormat::DiffFriendly) {
                write!(&mut buf, "@{basic_block_counter}").unwrap()
            } else {
                buf.push_str("@_:");
            }

            if let Some(jump_table_index) = jump_table_map.get(&target_offset) {
                if !matches!(self.format, DisassemblyFormat::DiffFriendly) {
                    write!(&mut buf, " [@dyn {jump_table_index}]").unwrap()
                } else {
                    buf.push_str(" [_]");
                }
            }

            if self.emit_exports {
                if let Some(exports) = exports_for_code_offset.get(&target_offset) {
                    for (nth_export, export) in exports {
                        write!(&mut buf, " [export #{}: {}]", nth_export, export.symbol()).unwrap()
                    }
                }
            }

            if let Some(gas_cost) = self.gas_cost_map.as_ref().and_then(|map| map.get(&target_offset)) {
                write!(&mut buf, " (gas: {})", gas_cost).unwrap();
            }

            buf
        };

        let prefer_offset_jump_targets = self.prefer_offset_jump_targets;
        let mut disassembly_format = polkavm_common::program::InstructionFormat::default();
        disassembly_format.prefer_non_abi_reg_names = self.prefer_non_abi_reg_names;
        disassembly_format.prefer_unaliased = self.prefer_unaliased;

        let jump_target_formatter = |target: u32, fmt: &mut core::fmt::Formatter| {
            if prefer_offset_jump_targets {
                write!(fmt, "{}", target)
            } else if let Some(basic_block_index) = instruction_offset_to_basic_block.get(&polkavm::ProgramCounter(target)) {
                write!(fmt, "@{basic_block_index}")
            } else {
                write!(fmt, "{}", target)
            }
        };
        disassembly_format.jump_target_formatter = Some(&jump_target_formatter);

        let mut fmt = AssemblyFormatter::default();
        let mut last_line_program_entry = None;
        let mut last_full_name = String::new();
        let mut basic_block_counter = 0;
        let mut pending_label = true;
        for (nth_instruction, instruction) in instructions.iter().copied().enumerate() {
            let offset = instruction.offset;
            let length = core::cmp::min(instruction.next_offset.0, self.blob.code().len() as u32) - offset.0;
            let instruction = instruction.kind;
            let raw_bytes = &self.blob.code()[offset.0 as usize..offset.0 as usize + length as usize];

            let instruction_s = instruction.display(&disassembly_format);
            let instruction_s = if let polkavm_common::program::Instruction::ecalli(nth_import) = instruction {
                if let Some(import) = self.blob.imports().get(nth_import) {
                    format!("{instruction_s} // {}", import)
                } else {
                    format!("{instruction_s} // INVALID")
                }
            } else {
                instruction_s.to_string()
            };

            let line_program = self.blob.get_debug_line_program_at(offset)?;

            if let Some(mut line_program) = line_program {
                if last_line_program_entry != Some(line_program.entry_index()) {
                    if nth_instruction != 0 {
                        if let Err(error) = writeln!(&mut writer) {
                            return Err(format!("failed to write to output: {error}").into());
                        }
                    }

                    last_line_program_entry = Some(line_program.entry_index());
                    loop {
                        let region = match line_program.run() {
                            Ok(Some(region)) => region,
                            Ok(None) => break,
                            Err(error) => {
                                return Err(format!("failed to parse line program: {error}").into());
                            }
                        };

                        if region.instruction_range().contains(&offset) {
                            let frame = region.frames().next().unwrap();
                            let full_name = match frame.full_name() {
                                Ok(full_name) => full_name,
                                Err(error) => {
                                    return Err(format!("failed to parse line program: {error}").into());
                                }
                            }
                            .to_string();

                            if last_full_name != full_name {
                                w!("<{}>:", full_name);
                                last_full_name = full_name;
                            }

                            break;
                        }
                    }
                }
            } else {
                if !last_full_name.is_empty() {
                    if let Err(error) = writeln!(&mut writer) {
                        return Err(format!("failed to write to output: {error}").into());
                    }
                }

                last_line_program_entry = None;
                last_full_name.clear();
            }

            if pending_label {
                pending_label = false;
                if !matches!(self.format, DisassemblyFormat::DiffFriendly) {
                    if self.show_offsets {
                        w!(@no_newline "      : ");
                    }

                    if self.show_raw_bytes {
                        w!("{:24} {}", "", format_jump_target(offset, basic_block_counter))
                    } else {
                        w!("{}", format_jump_target(offset, basic_block_counter))
                    }
                } else {
                    w!("    {}", format_jump_target(offset, basic_block_counter))
                }
            }

            if matches!(self.format, DisassemblyFormat::DiffFriendly) {
                let mut string = instruction_s;
                if let polkavm_common::program::Instruction::load_imm(dst, _) = instruction {
                    string = format!("{} = _", dst);
                }

                if let Some(index) = string.find('@') {
                    let length = string[index + 1..]
                        .chars()
                        .take_while(|character| character.is_ascii_digit() || matches!(character, 'a' | 'b' | 'c' | 'd' | 'e' | 'f'))
                        .count();
                    string.replace_range(index + 1..index + 1 + length, "_");
                }

                if let Some(index_1) = string.find("[0x") {
                    let index_2 = string[index_1..].find(']').unwrap() + index_1;
                    string.replace_range(index_1..=index_2, "[_]");
                }

                w!("    {}", string);
            } else if matches!(self.format, DisassemblyFormat::Guest | DisassemblyFormat::GuestAndNative) {
                if self.show_offsets {
                    w!(@no_newline "{offset:6}: ");
                }
                if self.show_raw_bytes {
                    let raw_bytes = raw_bytes.iter().map(|byte| format!("{byte:02x}")).collect::<Vec<_>>().join(" ");
                    w!("{raw_bytes:24} {instruction_s}")
                } else {
                    w!("{instruction_s}")
                }
            }

            if matches!(self.format, DisassemblyFormat::Native | DisassemblyFormat::GuestAndNative) {
                let native = self.native.as_ref().unwrap();
                assert_eq!(offset.0, native.instruction_map[nth_instruction].0 .0);

                let machine_code_position = native.instruction_map[nth_instruction].1 as usize;
                let machine_next_code_position = native.instruction_map[nth_instruction + 1].1 as usize;
                let length = machine_next_code_position - machine_code_position;
                if length != 0 {
                    let machine_code_chunk = &native.machine_code[machine_code_position..machine_next_code_position];
                    if let Err(error) = fmt.emit(
                        matches!(self.format, DisassemblyFormat::GuestAndNative),
                        native.machine_code_origin,
                        machine_code_chunk,
                        machine_code_position,
                        &mut writer,
                    ) {
                        return Err(format!("failed to write to output: {error}").into());
                    }
                }
            }

            if instruction.opcode().starts_new_basic_block() {
                if nth_instruction + 1 != instructions.len() {
                    pending_label = true;
                }
                basic_block_counter += 1;
            }
        }

        if let Err(error) = writer.flush() {
            return Err(format!("failed to write to output: {error}").into());
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use polkavm::Reg::*;
    use polkavm_common::abi::MemoryMapBuilder;
    use polkavm_common::program::asm;
    use polkavm_common::writer::ProgramBlobBuilder;

    use super::*;

    fn test_all_formats(blob: &ProgramBlob) {
        for format in [
            DisassemblyFormat::Guest,
            DisassemblyFormat::DiffFriendly,
            #[cfg(target_arg = "x86_84")]
            DisassemblyFormat::GuestAndNative,
            #[cfg(target_arg = "x86_84")]
            DisassemblyFormat::Native,
        ] {
            assert!(!disassemble_with_gas(blob, format).is_empty());
        }
    }

    fn disassemble_with_gas(blob: &ProgramBlob, format: DisassemblyFormat) -> Vec<u8> {
        let mut disassembler = Disassembler::new(blob, format).unwrap();
        disassembler.display_gas().unwrap();

        let mut buffer = Vec::with_capacity(1 << 20);
        disassembler.disassemble_into(&mut buffer).unwrap();
        buffer
    }

    #[test]
    fn simple() {
        let memory_map = MemoryMapBuilder::new(0x4000).rw_data_size(0x4000).build().unwrap();
        let mut builder = ProgramBlobBuilder::new();
        builder.set_rw_data_size(0x4000);
        builder.add_export_by_basic_block(0, b"main");
        builder.add_import(b"hostcall");
        builder.set_code(
            &[
                asm::store_imm_u32(memory_map.rw_data_address(), 0x12345678),
                asm::add_32(S0, A0, A1),
                asm::ecalli(0),
                asm::add_32(A0, A0, S0),
                asm::ret(),
            ],
            &[],
        );
        let blob = ProgramBlob::parse(builder.into_vec().into()).unwrap();

        test_all_formats(&blob);

        let assembly_bytes = disassemble_with_gas(&blob, DisassemblyFormat::Guest);
        let assembly_text = String::from_utf8(assembly_bytes).unwrap();
        let expected = &[
            "// RO data = 0/0 bytes",
            "// RW data = 0/16384 bytes",
            "// Stack size = 0 bytes",
            "",
            "// Instructions = 5",
            "// Code size = 18 bytes",
            "",
            "      : @0 [export #0: 'main'] (gas: 5)",
            "     0: u32 [0x20000] = 305419896",
            "     9: s0 = a0 + a1",
            "    12: ecalli 0 // 'hostcall'",
            "    13: a0 = a0 + s0",
            "    16: ret",
            "",
        ]
        .join("\n");

        assert_eq!(&assembly_text, expected);
    }
}
