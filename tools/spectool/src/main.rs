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

#[derive(Default)]
struct PrePost {
    gas: Option<i64>,
    regs: [Option<u32>; 13],
    pc: Option<(String, u32)>,
}

fn parse_pre_post(line: &str, output: &mut PrePost) {
    let line = line.trim();
    let index = line.find('=').expect("invalid 'pre' / 'post' directive: no '=' found");
    let lhs = line[..index].trim();
    let rhs = line[index + 1..].trim();
    if lhs == "gas" {
        output.gas = Some(rhs.parse::<i64>().expect("invalid 'pre' / 'post' directive: failed to parse rhs"));
    } else if lhs == "pc" {
        let rhs = rhs
            .strip_prefix('@')
            .expect("invalid 'pre' / 'post' directive: failed to parse 'pc': no '@' found")
            .trim();
        let index = rhs
            .find('[')
            .expect("invalid 'pre' / 'post' directive: failed to parse 'pc': no '[' found");
        let label = &rhs[..index];
        let rhs = &rhs[index + 1..];
        let index = rhs
            .find(']')
            .expect("invalid 'pre' / 'post' directive: failed to parse 'pc': no ']' found");
        let offset = rhs[..index]
            .parse::<u32>()
            .expect("invalid 'pre' / 'post' directive: failed to parse 'pc': invalid offset");
        if !rhs[index + 1..].trim().is_empty() {
            panic!("invalid 'pre' / 'post' directive: failed to parse 'pc': junk after ']'");
        }

        output.pc = Some((label.to_owned(), offset));
    } else {
        let lhs = polkavm_common::utils::parse_reg(lhs).expect("invalid 'pre' / 'post' directive: failed to parse lhs");
        let rhs = polkavm_common::utils::parse_imm(rhs).expect("invalid 'pre' / 'post' directive: failed to parse rhs");
        output.regs[lhs as usize] = Some(rhs as u32);
    }
}

fn main_generate() {
    let mut tests = Vec::new();

    let mut config = polkavm::Config::new();
    config.set_backend(Some(polkavm::BackendKind::Interpreter));

    let engine = Engine::new(&config).unwrap();
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("spec");
    let mut found_errors = false;

    for entry in std::fs::read_dir(root.join("src")).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_stem().unwrap().to_string_lossy();

        let mut pre = PrePost::default();
        let mut post = PrePost::default();

        let input = std::fs::read_to_string(&path).unwrap();
        let mut input_lines = Vec::new();
        for line in input.lines() {
            if let Some(line) = line.strip_prefix("pre:") {
                parse_pre_post(line, &mut pre);
                input_lines.push(""); // Insert dummy line to not mess up the line count.
                continue;
            }

            if let Some(line) = line.strip_prefix("post:") {
                parse_pre_post(line, &mut post);
                input_lines.push(""); // Insert dummy line to not mess up the line count.
                continue;
            }

            input_lines.push(line);
        }

        let initial_gas = pre.gas.unwrap_or(10000);
        let initial_regs = pre.regs.map(|value| value.unwrap_or(0));
        assert!(pre.pc.is_none(), "'pre: pc = ...' is currently unsupported");

        let input = input_lines.join("\n");
        let blob = match assemble(&input) {
            Ok(blob) => blob,
            Err(error) => {
                eprintln!("Failed to assemble {path:?}: {error}");
                found_errors = true;
                continue;
            }
        };

        let parts = ProgramParts::from_bytes(blob.into()).unwrap();
        let blob = ProgramBlob::from_parts(parts.clone()).unwrap();

        let mut module_config = ModuleConfig::default();
        module_config.set_strict(true);
        module_config.set_gas_metering(Some(polkavm::GasMeteringKind::Sync));
        module_config.set_step_tracing(true);

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

        let initial_pc = blob.exports().find(|export| export.symbol() == "main").unwrap().program_counter();

        let expected_final_pc = if let Some(export) = blob.exports().find(|export| export.symbol() == "expected_exit") {
            assert!(
                post.pc.is_none(),
                "'@expected_exit' label and 'post: pc = ...' should not be used together"
            );
            export.program_counter().0
        } else if let Some((label, nth_instruction)) = post.pc {
            let Some(export) = blob.exports().find(|export| export.symbol().as_bytes() == label.as_bytes()) else {
                panic!("label specified in 'post: pc = ...' is missing: @{label}");
            };

            let instructions: Vec<_> = blob
                .instructions(polkavm_common::program::DefaultInstructionSet::default())
                .collect();
            let index = instructions
                .iter()
                .position(|inst| inst.offset == export.program_counter())
                .expect("failed to find label specified in 'post: pc = ...'");
            let instruction = instructions
                .get(index + nth_instruction as usize)
                .expect("invalid 'post: pc = ...': offset goes out of bounds of the basic block");
            instruction.offset.0
        } else {
            blob.code().len() as u32
        };

        instance.set_gas(initial_gas);
        instance.set_next_program_counter(initial_pc);

        for (reg, value) in Reg::ALL.into_iter().zip(initial_regs) {
            instance.set_reg(reg, value);
        }

        let mut final_pc = initial_pc;
        let expected_status = loop {
            match instance.run().unwrap() {
                InterruptKind::Finished => break "halt",
                InterruptKind::Trap => break "trap",
                InterruptKind::Ecalli(..) => todo!(),
                InterruptKind::NotEnoughGas => break "out-of-gas",
                InterruptKind::Segfault(..) => todo!(),
                InterruptKind::Step => {
                    final_pc = instance.program_counter().unwrap();
                    continue;
                }
            }
        };

        if expected_status != "halt" {
            final_pc = instance.program_counter().unwrap();
        }

        if final_pc.0 != expected_final_pc {
            eprintln!("Unexpected final program counter for {path:?}: expected {expected_final_pc}, is {final_pc}");
            found_errors = true;
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

        let mut found_post_check_errors = false;

        for ((final_value, reg), required_value) in expected_regs.iter().zip(Reg::ALL).zip(post.regs.iter()) {
            if let Some(required_value) = required_value {
                if final_value != required_value {
                    eprintln!("{path:?}: unexpected {reg}: {final_value} (expected: {required_value})");
                    found_post_check_errors = true;
                }
            }
        }

        if let Some(post_gas) = post.gas {
            if expected_gas != post_gas {
                eprintln!("{path:?}: unexpected gas: {expected_gas} (expected: {post_gas})");
                found_post_check_errors = true;
            }
        }

        if found_post_check_errors {
            found_errors = true;
            continue;
        }

        let mut disassembler = polkavm_disassembler::Disassembler::new(&blob, polkavm_disassembler::DisassemblyFormat::Guest).unwrap();
        disassembler.show_raw_bytes(true);
        disassembler.prefer_non_abi_reg_names(true);
        disassembler.prefer_unaliased(true);
        disassembler.prefer_offset_jump_targets(true);
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

    if found_errors {
        std::process::exit(1);
    }
}

fn main_test() {
    todo!();
}
