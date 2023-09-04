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
            
            let fp = match File::open(output) {
                Ok(fp) => fp,
                Err(e) => {
                    eprintln!("ERROR: failed to open output file {:?}: {}", output, error);
                    std::process::exit(1);
                },
            };
            
            let mut fp = BufWriter::new(fp);
            for (nth_instruction, maybe_instruction) in blob.instructions().enumerate() {
                let instruction = match maybe_instruction {
                    Ok(ri) => format!("{}: {}", nth, ri),
                    Err(error) => {
                        eprintln!(
                            "ERROR: failed to parse raw instruction from blob. {:?}: {}. nth:{} ",
                            input, error, nth_instruction
                        );
                    }
                }
                writeln!(&mut fp, instruction).unwrap();
            }

        }
    }
}
