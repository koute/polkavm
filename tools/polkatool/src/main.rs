#![allow(clippy::print_stdout)]
#![allow(clippy::print_stderr)]
#![allow(clippy::exit)]

use clap::Parser;
use polkavm_common::program::{Opcode, ProgramBlob};
use polkavm_disassembler::DisassemblyFormat;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

#[derive(Parser, Debug)]
#[clap(version)]
enum Args {
    /// Links a given ELF file into a `.polkavm` program blob.
    Link {
        /// The output file.
        #[clap(short = 'o', long)]
        output: PathBuf,

        #[clap(short = 's', long)]
        strip: bool,

        /// Will only run if the output file doesn't exist, or the input is newer.
        #[clap(long)]
        run_only_if_newer: bool,

        /// The input file.
        input: PathBuf,
    },

    /// Disassembles a .polkavm blob into its human-readable assembly.
    Disassemble {
        /// The output file.
        #[clap(short = 'o', long)]
        output: Option<PathBuf>,

        #[clap(short = 'f', long, value_enum, default_value_t = DisassemblyFormat::Guest)]
        format: DisassemblyFormat,

        #[clap(long)]
        display_gas: bool,

        /// The input file.
        input: PathBuf,
    },

    /// Calculates various statistics for given program blobs.
    Stats {
        /// The input files.
        inputs: Vec<PathBuf>,
    },
}

macro_rules! bail {
    ($($arg:tt)*) => {
        return Err(format!($($arg)*))
    }
}

fn main() {
    env_logger::init();

    let args = Args::parse();
    let result = match args {
        Args::Link {
            output,
            input,
            strip,
            run_only_if_newer,
        } => main_link(input, output, strip, run_only_if_newer),
        Args::Disassemble {
            output,
            format,
            display_gas,
            input,
        } => main_disassemble(input, format, display_gas, output),
        Args::Stats { inputs } => main_stats(inputs),
    };

    if let Err(error) = result {
        eprintln!("ERROR: {}", error);
        std::process::exit(1);
    }
}

fn main_link(input: PathBuf, output: PathBuf, strip: bool, run_only_if_newer: bool) -> Result<(), String> {
    if run_only_if_newer {
        if let Ok(output_mtime) = std::fs::metadata(&output).and_then(|m| m.modified()) {
            if let Ok(input_mtime) = std::fs::metadata(&input).and_then(|m| m.modified()) {
                if output_mtime >= input_mtime {
                    return Ok(());
                }
            }
        }
    }

    let mut config = polkavm_linker::Config::default();
    config.set_strip(strip);

    let data = match std::fs::read(&input) {
        Ok(data) => data,
        Err(error) => {
            bail!("failed to read {input:?}: {error}");
        }
    };

    let blob = match polkavm_linker::program_from_elf(config, &data) {
        Ok(blob) => blob,
        Err(error) => {
            bail!("failed to link {input:?}: {error}");
        }
    };

    if let Err(error) = std::fs::write(&output, blob.as_bytes()) {
        bail!("failed to write the program blob to {output:?}: {error}");
    }

    Ok(())
}

fn load_blob(input: &Path) -> Result<ProgramBlob<'static>, String> {
    let data = match std::fs::read(input) {
        Ok(data) => data,
        Err(error) => {
            bail!("failed to read {input:?}: {error}");
        }
    };

    let blob = match polkavm_linker::ProgramBlob::parse(&data[..]) {
        Ok(blob) => blob,
        Err(error) => {
            bail!("failed to parse {input:?}: {error}");
        }
    };

    Ok(blob.into_owned())
}

fn main_stats(inputs: Vec<PathBuf>) -> Result<(), String> {
    let mut map = HashMap::new();
    for opcode in 0..=255 {
        if let Some(opcode) = Opcode::from_u8(opcode) {
            map.insert(opcode, 0);
        }
    }

    for input in inputs {
        let blob = load_blob(&input)?;
        for instruction in blob.instructions() {
            *map.get_mut(&instruction.opcode()).unwrap() += 1;
        }
    }

    let mut list: Vec<_> = map.into_iter().collect();
    list.sort_by_key(|(_, count)| core::cmp::Reverse(*count));

    println!("Instruction distribution:");
    for (opcode, count) in list {
        println!("{opcode:>40}: {count}", opcode = format!("{:?}", opcode));
    }

    Ok(())
}

fn main_disassemble(input: PathBuf, format: DisassemblyFormat, display_gas: bool, output: Option<PathBuf>) -> Result<(), String> {
    let blob = load_blob(&input)?;

    let mut disassembler = polkavm_disassembler::Disassembler::new(&blob, format).map_err(|error| error.to_string())?;
    if display_gas {
        disassembler.display_gas().map_err(|error| error.to_string())?;
    }

    match output {
        Some(output) => {
            let fp = match std::fs::File::create(&output) {
                Ok(fp) => fp,
                Err(error) => {
                    bail!("failed to create output file {output:?}: {error}");
                }
            };

            disassembler.disassemble_into(std::io::BufWriter::new(fp))
        }
        None => {
            let stdout = std::io::stdout();
            disassembler.disassemble_into(std::io::BufWriter::new(stdout))
        }
    }
    .map_err(|error| error.to_string())
}
