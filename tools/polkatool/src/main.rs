use clap::Parser;
use std::path::PathBuf;

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

    /// Disassembles a .polkavmm blob into its human-readable assembly.
    Disassemble {
        /// The output file.
        #[clap(short = 'o', long)]
        output: PathBuf,

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
q/*  */
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
            let out = blob
                .instructions()
                .enumerate()
                .map(|(nth, maybe_ri)|{
                    match maybe_ri {
                        Ok(ri) => format!("{}: {}", nth, ri),
                        Err(error) => {
                            eprintln!("ERROR: failed to parse raw instruction from blob. {:?}: {}. nth:{} ", input, error, nth);
                            std::process::exit(1);
                        }
                    }
                })
                .collect::<Vec<String>>()
                .join("\n");

            if let Err(error) = std::fs::write(&output, out) {
                eprintln!("ERROR: failed to write the bytecode to {:?}: {}", output, error);
                std::process::exit(1);
     
            }
        }
    }
}
