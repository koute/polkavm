use std::{collections::HashMap, io::Write};

use polkavm_common::program::ProgramBlob;

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
    instruction_map: Vec<(u32, u32)>,
}

impl TryFrom<&'_ ProgramBlob<'_>> for NativeCode {
    type Error = polkavm::Error;

    fn try_from(blob: &'_ ProgramBlob<'_>) -> Result<Self, Self::Error> {
        if !cfg!(target_arch = "x86_64") {
            return Err("the selected disassembly format is not supported on this architecture".into());
        }

        let mut config = polkavm::Config::from_env()?;
        config.set_worker_count(0);

        let engine = polkavm::Engine::new(&config)?;

        let module = polkavm::Module::from_blob(&engine, &Default::default(), blob)?;

        let Some(machine_code) = module.machine_code() else {
            return Err("currently selected VM backend doesn't provide raw machine code".into());
        };

        let Some(instruction_map) = module.code_offset_to_native_code_offset() else {
            return Err("currently selected VM backend doesn't provide a machine code map".into());
        };

        Ok(Self {
            machine_code_origin: module.machine_code_origin().unwrap_or(0),
            machine_code: machine_code.into_owned(),
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

pub struct Disassembler<'a, 'blob> {
    blob: &'a ProgramBlob<'blob>,
    format: DisassemblyFormat,
    gas_cost_map: Option<HashMap<u32, i64>>,
    native: Option<NativeCode>,
}

impl<'a, 'blob> Disassembler<'a, 'blob> {
    pub fn new(blob: &'a ProgramBlob<'blob>, format: DisassemblyFormat) -> Result<Self, polkavm::Error> {
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
        })
    }

    pub fn display_gas(&mut self) -> Result<(), polkavm::Error> {
        let mut config = polkavm::Config::from_env()?;
        config.set_worker_count(0);
        config.set_backend(Some(polkavm::BackendKind::Interpreter));

        let engine = polkavm::Engine::new(&config)?;

        let mut config = polkavm::ModuleConfig::default();
        config.set_gas_metering(Some(polkavm::GasMeteringKind::Sync));

        let module = polkavm::Module::from_blob(&engine, &config, self.blob)?;

        let mut in_new_block = true;
        let mut gas_cost_map = HashMap::new();
        for instruction in self.blob.instructions() {
            if in_new_block {
                in_new_block = false;
                if let Some(cost) = module.gas_cost_for_code_offset(instruction.offset) {
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
        for instruction in self.blob.instructions() {
            instructions.push((instruction.offset, instruction.kind));
        }

        let mut exports_for_code_offset = HashMap::new();
        for (nth_export, export) in self.blob.exports().enumerate() {
            exports_for_code_offset
                .entry(export.target_code_offset())
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

        let format_jump_target = |target_offset: u32, basic_block_counter: u32| {
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

            if let Some(exports) = exports_for_code_offset.get(&target_offset) {
                for (nth_export, export) in exports {
                    write!(&mut buf, " [export #{}: {}]", nth_export, export.symbol()).unwrap()
                }
            }

            if let Some(gas_cost) = self.gas_cost_map.as_ref().and_then(|map| map.get(&target_offset)) {
                write!(&mut buf, " (gas: {})", gas_cost).unwrap();
            }

            buf
        };

        let mut fmt = AssemblyFormatter::default();
        let mut last_line_program_entry = None;
        let mut last_full_name = String::new();
        let mut basic_block_counter = 0;
        let mut pending_label = true;
        for (nth_instruction, (offset, instruction)) in instructions.iter().copied().enumerate() {
            let instruction_s = if let polkavm_common::program::Instruction::ecalli(nth_import) = instruction {
                if let Some(import) = self.blob.imports().get(nth_import) {
                    format!("{instruction} // {}", import)
                } else {
                    format!("{instruction} // INVALID")
                }
            } else {
                instruction.to_string()
            };

            let line_program = self.blob.get_debug_line_program_at(nth_instruction as u32)?;

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

                        if region.instruction_range().contains(&(nth_instruction as u32)) {
                            let frame = region.frames().next().unwrap();
                            let full_name = match frame.full_name() {
                                Ok(full_name) => full_name,
                                Err(error) => {
                                    return Err(format!("failed to parse line program: {error}").into());
                                }
                            }
                            .to_string();

                            if last_full_name != full_name {
                                if let Err(error) = writeln!(&mut writer, "<{}>:", full_name) {
                                    return Err(format!("failed to write to output: {error}").into());
                                }

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
                let result = if !matches!(self.format, DisassemblyFormat::DiffFriendly) {
                    writeln!(&mut writer, "      : {}", format_jump_target(offset, basic_block_counter))
                } else {
                    writeln!(&mut writer, "    {}", format_jump_target(offset, basic_block_counter))
                };

                if let Err(error) = result {
                    return Err(format!("failed to write to output: {error}").into());
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

                if let Err(error) = writeln!(&mut writer, "    {}", string) {
                    return Err(format!("failed to write to output: {error}").into());
                }
            } else if matches!(self.format, DisassemblyFormat::Guest | DisassemblyFormat::GuestAndNative) {
                if let Err(error) = writeln!(&mut writer, "{offset:6}: {instruction_s}") {
                    return Err(format!("failed to write to output: {error}").into());
                }
            }

            if matches!(self.format, DisassemblyFormat::Native | DisassemblyFormat::GuestAndNative) {
                let native = self.native.as_ref().unwrap();
                assert_eq!(offset, native.instruction_map[nth_instruction].0);

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
    use std::sync::Mutex;

    use super::*;

    static BLOB_MAP: Mutex<Option<HashMap<&'static [u8], ProgramBlob>>> = Mutex::new(None);

    fn decompress_zstd(mut bytes: &[u8]) -> Vec<u8> {
        use std::io::Read;
        let mut output = Vec::new();
        ruzstd::streaming_decoder::StreamingDecoder::new(&mut bytes)
            .unwrap()
            .read_to_end(&mut output)
            .unwrap();
        output
    }

    fn get_blob(elf: &'static [u8]) -> ProgramBlob {
        let mut blob_map = match BLOB_MAP.lock() {
            Ok(blob_map) => blob_map,
            Err(error) => error.into_inner(),
        };

        let blob_map = blob_map.get_or_insert_with(HashMap::new);
        blob_map
            .entry(elf)
            .or_insert_with(|| {
                // This is slow, so cache it.
                let elf = decompress_zstd(elf);
                let blob = polkavm_linker::program_from_elf(Default::default(), &elf).unwrap();
                blob.into_owned()
            })
            .clone()
    }

    fn test_all_formats(blob: ProgramBlob) {
        for format in [
            DisassemblyFormat::Guest,
            DisassemblyFormat::DiffFriendly,
            #[cfg(target_arg = "x86_84")]
            DisassemblyFormat::GuestAndNative,
            #[cfg(target_arg = "x86_84")]
            DisassemblyFormat::Native,
        ] {
            let mut disassembler = Disassembler::new(&blob, format).unwrap();
            disassembler.display_gas().unwrap();

            let mut buffer = Vec::with_capacity(1 << 20);
            disassembler.disassemble_into(&mut buffer).unwrap();

            assert!(!buffer.is_empty());
        }
    }

    #[test]
    fn pinky() {
        let blob = get_blob(include_bytes!("../../../test-data/bench-pinky.elf.zst"));
        test_all_formats(blob);
    }

    #[test]
    fn doom() {
        let blob = get_blob(include_bytes!("../../../test-data/doom_O3_dwarf5.elf.zst"));
        test_all_formats(blob);
    }
}
