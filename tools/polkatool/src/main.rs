use clap::Parser;
use std::{io::Write, path::PathBuf};

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

        /// The input file.
        input: PathBuf,
    },

    /// Disassembles a .polkavm blob into its human-readable assembly.
    Disassemble {
        /// The output file.
        #[clap(short = 'o', long)]
        output: Option<PathBuf>,

        /// The input file.
        input: PathBuf,
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
        Args::Link { output, input, strip } => main_link(input, output, strip),
        Args::Disassemble { output, input } => main_disassemble(input, output),
    };

    if let Err(error) = result {
        eprintln!("ERROR: {}", error);
        std::process::exit(1);
    }
}

fn main_link(input: PathBuf, output: PathBuf, strip: bool) -> Result<(), String> {
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

fn main_disassemble(input: PathBuf, output: Option<PathBuf>) -> Result<(), String> {
    let data = match std::fs::read(&input) {
        Ok(data) => data,
        Err(error) => {
            bail!("failed to read {input:?}: {error}");
        }
    };
    let blob = match polkavm_linker::ProgramBlob::parse(&data[..]) {
        Ok(b) => b,
        Err(error) => {
            bail!("failed to parse {input:?}: {error}");
        }
    };

    match output {
        Some(output) => {
            let fp = match std::fs::File::create(&output) {
                Ok(fp) => fp,
                Err(error) => {
                    bail!("failed to create output file {output:?}: {error}");
                }
            };

            disassemble_into(&blob, std::io::BufWriter::new(fp))
        }
        None => {
            let stdout = std::io::stdout();
            disassemble_into(&blob, std::io::BufWriter::new(stdout))
        }
    }
}

fn disassemble_into(blob: &polkavm_linker::ProgramBlob, mut writer: impl Write) -> Result<(), String> {
    for (nth_instruction, maybe_instruction) in blob.instructions().enumerate() {
        match maybe_instruction {
            Ok(instruction) => {
                if let Err(error) = writeln!(&mut writer, "{nth_instruction}: {instruction}") {
                    bail!("failed to write to output: {error}");
                }
            }
            Err(error) => {
                bail!("failed to parse instruction #{nth_instruction}: {error}");
            }
        };
    }

    if let Err(error) = writer.flush() {
        bail!("failed to write to output: {error}");
    }

    Ok(())
}
