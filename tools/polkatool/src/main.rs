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

fn main() {
    let args = Args::parse();
    match args {
        Args::Link { output, input } => {
            let config = polkavm_linker::Config::default();
            let data = match std::fs::read(&input) {
                Ok(data) => data,
                Err(error) => {
                    eprintln!("ERROR: failed to read {:?}: {}", input, error);
                    std::process::exit(1);
                }
            };

            let blob = match polkavm_linker::program_from_elf(config, &data) {
                Ok(blob) => blob,
                Err(error) => {
                    eprintln!("ERROR: failed to link {:?}: {}", input, error);
                    std::process::exit(1);
                }
            };

            if let Err(error) = std::fs::write(&output, blob.as_bytes()) {
                eprintln!("ERROR: failed to write the program blob to {:?}: {}", output, error);
                std::process::exit(1);
            }
        }

        Args::Disassemble { output, input } => {
            let data = match std::fs::read(&input) {
                Ok(data) => data,
                Err(error) => {
                    eprintln!("ERROR: failed to read {:?}: {}", input, error);
                    std::process::exit(1);
                }
            };
            let blob = match polkavm::ProgramBlob::parse(&data[..]) {
                Ok(b) => b,
                Err(error) => {
                    eprintln!("ERROR: failed to parse the raw data into a blob {:?}: {}", input, error);
                    std::process::exit(1);
                }
            };

            let std_out = std::io::stdout();
            let mut bw: Box<dyn Write> = match output {
                Some(out) => {
                    let fp = match std::fs::File::create(&out) {
                        Ok(fp) => fp,
                        Err(error) => {
                            eprintln!("ERROR: failed to create output file {:?}: {}", out, error);
                            std::process::exit(1);
                        }
                    };
                    Box::new(std::io::BufWriter::new(fp))
                }
                None => Box::new(std::io::BufWriter::new(std_out)),
            };

            for (nth_instruction, maybe_instruction) in blob.instructions().enumerate() {
                let instruction = match maybe_instruction {
                    Ok(instruction) => format!("{}: {}", nth_instruction, instruction),
                    Err(error) => {
                        eprintln!(
                            "ERROR: failed to parse raw instruction from blob. {:?}: {}. nth:{} ",
                            input, error, nth_instruction
                        );
                        std::process::exit(1);
                    }
                };
                if let Err(error) = writeln!(&mut bw, "{}", instruction) {
                    eprintln!("ERROR: failed to write instruction from buffer. {:?} {}.", error, instruction);
                    std::process::exit(1);
                }
            }
            bw.flush().unwrap();
        }
    }
}
