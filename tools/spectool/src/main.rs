#![allow(clippy::exit)]
#![allow(clippy::print_stdout)]
#![allow(clippy::print_stderr)]
#![allow(clippy::use_debug)]

use clap::Parser;
use core::fmt::Write;
use polkavm::{Engine, InterruptKind, Module, ModuleConfig, ProgramBlob, Reg};
use polkavm_common::assembler::assemble;
use polkavm_common::program::ProgramParts;
use std::path::Path;

#[derive(Parser, Debug)]
#[clap(version)]
enum Args {
    Generate,
    Test,
}

fn main() {
    env_logger::init();

    let args = Args::parse();
    match args {
        Args::Generate => main_generate(),
        Args::Test => main_test(),
    }
}

struct Testcase {
    disassembly: String,
    json: TestcaseJson,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
struct Page {
    address: u32,
    length: u32,
    is_writable: bool,
}

#[derive(PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
struct MemoryChunk {
    address: u32,
    contents: Vec<u8>,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
struct TestcaseJson {
    name: String,
    initial_regs: [u32; 13],
    initial_pc: u32,
    initial_page_map: Vec<Page>,
    initial_memory: Vec<MemoryChunk>,
    initial_gas: i64,
    program: Vec<u8>,
    expected_status: String,
    expected_regs: Vec<u32>,
    expected_pc: u32,
    expected_memory: Vec<MemoryChunk>,
    expected_gas: i64,
}

fn extract_chunks(base_address: u32, slice: &[u8]) -> Vec<MemoryChunk> {
    let mut output = Vec::new();
    let mut position = 0;
    while let Some(next_position) = slice[position..].iter().position(|&byte| byte != 0).map(|offset| position + offset) {
        position = next_position;
        let length = slice[position..].iter().take_while(|&&byte| byte != 0).count();
        output.push(MemoryChunk {
            address: base_address + position as u32,
            contents: slice[position..position + length].into(),
        });
        position += length;
    }

    output
}

fn main_generate() {
    let mut tests = Vec::new();

    let mut config = polkavm::Config::new();
    config.set_backend(Some(polkavm::BackendKind::Interpreter));

    let engine = Engine::new(&config).unwrap();
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("spec");
    for entry in std::fs::read_dir(root.join("src")).unwrap() {
        let mut initial_regs = [0; 13];
        let mut initial_gas = 10000;

        let path = entry.unwrap().path();
        let name = path.file_stem().unwrap().to_string_lossy();

        let input = std::fs::read_to_string(&path).unwrap();
        let mut input_lines = Vec::new();
        for line in input.lines() {
            if let Some(line) = line.strip_prefix("pre:") {
                let line = line.trim();
                let index = line.find('=').expect("invalid 'pre' directive: no '=' found");
                let lhs = line[..index].trim();
                let rhs = line[index + 1..].trim();
                if lhs == "gas" {
                    initial_gas = rhs.parse::<i64>().expect("invalid 'pre' directive: failed to parse rhs");
                } else {
                    let lhs = polkavm_common::utils::parse_reg(lhs).expect("invalid 'pre' directive: failed to parse lhs");
                    let rhs = polkavm_common::utils::parse_imm(rhs).expect("invalid 'pre' directive: failed to parse rhs");
                    initial_regs[lhs as usize] = rhs as u32;
                }
                input_lines.push(""); // Insert dummy line to not mess up the line count.
                continue;
            }

            input_lines.push(line);
        }

        let input = input_lines.join("\n");
        let blob = match assemble(&input) {
            Ok(blob) => blob,
            Err(error) => {
                eprintln!("Failed to assemble {path:?}: {error}");
                continue;
            }
        };

        let parts = ProgramParts::from_bytes(blob.into()).unwrap();
        let blob = ProgramBlob::from_parts(parts.clone()).unwrap();

        let mut module_config = ModuleConfig::default();
        module_config.set_strict(true);
        module_config.set_gas_metering(Some(polkavm::GasMeteringKind::Sync));

        let module = Module::from_blob(&engine, &module_config, blob.clone()).unwrap();
        let mut instance = module.instantiate().unwrap();

        let mut initial_page_map = Vec::new();
        let mut initial_memory = Vec::new();

        if module.memory_map().ro_data_size() > 0 {
            initial_page_map.push(Page {
                address: module.memory_map().ro_data_address(),
                length: module.memory_map().ro_data_size(),
                is_writable: false,
            });

            initial_memory.extend(extract_chunks(module.memory_map().ro_data_address(), blob.ro_data()));
        }

        if module.memory_map().rw_data_size() > 0 {
            initial_page_map.push(Page {
                address: module.memory_map().rw_data_address(),
                length: module.memory_map().rw_data_size(),
                is_writable: true,
            });

            initial_memory.extend(extract_chunks(module.memory_map().rw_data_address(), blob.rw_data()));
        }

        if module.memory_map().stack_size() > 0 {
            initial_page_map.push(Page {
                address: module.memory_map().stack_address_low(),
                length: module.memory_map().stack_size(),
                is_writable: true,
            });
        }

        let initial_pc = blob
            .exports()
            .find(|export| export.symbol() == "main")
            .unwrap()
            .program_counter();

        #[allow(clippy::map_unwrap_or)]
        let expected_final_pc = blob
            .exports()
            .find(|export| export.symbol() == "expected_exit")
            .map(|export| export.program_counter().0)
            .unwrap_or(blob.code().len() as u32);

        instance.set_gas(initial_gas);
        instance.set_program_counter(initial_pc);

        for (reg, value) in Reg::ALL.into_iter().zip(initial_regs) {
            instance.set_reg(reg, value);
        }

        let expected_status = match instance.run().unwrap() {
            InterruptKind::Finished => "halt",
            InterruptKind::Trap(..) => "trap",
            InterruptKind::Ecalli(..) => todo!(),
            InterruptKind::NotEnoughGas => "out-of-gas",
            InterruptKind::Segfault(..) => todo!(),
            InterruptKind::Step => unreachable!(),
        };

        let final_pc = instance.program_counter().unwrap();
        if final_pc.0 != expected_final_pc {
            eprintln!("Unexpected final program counter for {path:?}: expected {expected_final_pc}, is {final_pc}");
            continue;
        }

        let mut expected_regs = Vec::new();
        for reg in Reg::ALL {
            let value = instance.reg(reg);
            expected_regs.push(value);
        }

        let mut expected_memory = Vec::new();
        for page in &initial_page_map {
            let memory = instance.read_memory(page.address, page.length).unwrap();
            expected_memory.extend(extract_chunks(page.address, &memory));
        }

        let expected_gas = instance.gas();

        let mut disassembler = polkavm_disassembler::Disassembler::new(&blob, polkavm_disassembler::DisassemblyFormat::Guest).unwrap();
        disassembler.show_raw_bytes(true);
        disassembler.prefer_non_abi_reg_names(true);
        disassembler.prefer_unaliased(true);
        disassembler.emit_header(false);
        disassembler.emit_exports(false);

        let mut disassembly = Vec::new();
        disassembler.disassemble_into(&mut disassembly).unwrap();
        let disassembly = String::from_utf8(disassembly).unwrap();

        tests.push(Testcase {
            disassembly,
            json: TestcaseJson {
                name: name.into(),
                initial_regs,
                initial_pc: initial_pc.0,
                initial_page_map,
                initial_memory,
                initial_gas,
                program: parts.code_and_jump_table.to_vec(),
                expected_status: expected_status.to_owned(),
                expected_regs,
                expected_pc: expected_final_pc,
                expected_memory,
                expected_gas,
            },
        });
    }

    tests.sort_by_key(|test| test.json.name.clone());

    let output_programs_root = root.join("output").join("programs");
    std::fs::create_dir_all(&output_programs_root).unwrap();

    let mut index_md = String::new();
    writeln!(&mut index_md, "# Testcases\n").unwrap();
    writeln!(&mut index_md, "This file contains a human-readable index of all of the testcases,").unwrap();
    writeln!(&mut index_md, "along with their disassemblies and other relevant information.\n\n").unwrap();

    for test in tests {
        let payload = serde_json::to_string_pretty(&test.json).unwrap();
        let output_path = output_programs_root.join(format!("{}.json", test.json.name));
        if !std::fs::read(&output_path)
            .map(|old_payload| old_payload == payload.as_bytes())
            .unwrap_or(false)
        {
            println!("Generating {output_path:?}...");
            std::fs::write(output_path, payload).unwrap();
        }

        writeln!(&mut index_md, "## {}\n", test.json.name).unwrap();

        if !test.json.initial_page_map.is_empty() {
            writeln!(&mut index_md, "Initial page map:").unwrap();
            for page in &test.json.initial_page_map {
                let access = if page.is_writable { "RW" } else { "RO" };

                writeln!(
                    &mut index_md,
                    "   * {access}: 0x{:x}-0x{:x} (0x{:x} bytes)",
                    page.address,
                    page.address + page.length,
                    page.length
                )
                .unwrap();
            }

            writeln!(&mut index_md).unwrap();
        }

        if !test.json.initial_memory.is_empty() {
            writeln!(&mut index_md, "Initial non-zero memory chunks:").unwrap();
            for chunk in &test.json.initial_memory {
                let contents: Vec<_> = chunk.contents.iter().map(|byte| format!("0x{:02x}", byte)).collect();
                let contents = contents.join(", ");
                writeln!(
                    &mut index_md,
                    "   * 0x{:x}-0x{:x} (0x{:x} bytes) = [{}]",
                    chunk.address,
                    chunk.address + chunk.contents.len() as u32,
                    chunk.contents.len(),
                    contents
                )
                .unwrap();
            }

            writeln!(&mut index_md).unwrap();
        }

        if test.json.initial_regs.iter().any(|value| *value != 0) {
            writeln!(&mut index_md, "Initial non-zero registers:").unwrap();
            for reg in Reg::ALL {
                let value = test.json.initial_regs[reg as usize];
                if value != 0 {
                    writeln!(&mut index_md, "   * {} = 0x{:x}", reg.name_non_abi(), value).unwrap();
                }
            }

            writeln!(&mut index_md).unwrap();
        }

        writeln!(&mut index_md, "```\n{}```\n", test.disassembly).unwrap();

        if test
            .json
            .initial_regs
            .iter()
            .zip(test.json.expected_regs.iter())
            .any(|(old_value, new_value)| *old_value != *new_value)
        {
            writeln!(&mut index_md, "Registers after execution (only changed registers):").unwrap();
            for reg in Reg::ALL {
                let value_before = test.json.initial_regs[reg as usize];
                let value_after = test.json.expected_regs[reg as usize];
                if value_before != value_after {
                    writeln!(
                        &mut index_md,
                        "   * {} = 0x{:x} (initially was 0x{:x})",
                        reg.name_non_abi(),
                        value_after,
                        value_before
                    )
                    .unwrap();
                }
            }

            writeln!(&mut index_md).unwrap();
        }

        if !test.json.expected_memory.is_empty() {
            if test.json.expected_memory == test.json.initial_memory {
                writeln!(&mut index_md, "The memory contents after execution should be unchanged.").unwrap();
            } else {
                writeln!(&mut index_md, "Final non-zero memory chunks:").unwrap();
                for chunk in &test.json.expected_memory {
                    let contents: Vec<_> = chunk.contents.iter().map(|byte| format!("0x{:02x}", byte)).collect();
                    let contents = contents.join(", ");
                    writeln!(
                        &mut index_md,
                        "   * 0x{:x}-0x{:x} (0x{:x} bytes) = [{}]",
                        chunk.address,
                        chunk.address + chunk.contents.len() as u32,
                        chunk.contents.len(),
                        contents
                    )
                    .unwrap();
                }
            }

            writeln!(&mut index_md).unwrap();
        }

        writeln!(&mut index_md, "Program should end with: {}\n", test.json.expected_status).unwrap();
        writeln!(&mut index_md, "Final value of the program counter: {}\n", test.json.expected_pc).unwrap();
        writeln!(
            &mut index_md,
            "Gas consumed: {} -> {}\n",
            test.json.initial_gas, test.json.expected_gas
        )
        .unwrap();
        writeln!(&mut index_md).unwrap();
    }

    std::fs::write(root.join("output").join("TESTCASES.md"), index_md).unwrap();
}

fn main_test() {
    todo!();
}
