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

    /// Disassembles any .polkavmm blob into its equivelant bytecode.
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

            if let Err(error) = std::fs::write(&output, blob.as_bytes()) {
                eprintln!("ERROR: failed to write the program blob to {:?}: {}", output, error);
                std::process::exit(1);
            }
        },

        Args::Disassemble {output, input} => {
            let config = polkavm::Config::default();
            let engine = polkavm::Engine::new(&config).unwrap();
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
            let module = match polkavm::Module::from_blob(&engine, &blob) {
                Ok(m) => m,
                Err(error) => { 
                    eprintln!("ERROR: failed to instantiate a Module from the blob {:?}: {}", input, error);
                    std::process::exit(1);
                }
            };
            let out = module.display_instructions().join("\n");
            
            if let Err(error) = std::fs::write(&output, out) { 
                eprintln!("ERROR: failed to write the bytecode to {:?}: {}", output, error);
                std::process::exit(1);
            }
        }
    }
}
