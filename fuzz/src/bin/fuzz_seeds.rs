use std::io::Read;
use std::path::Path;

use arbitrary::Unstructured;
use polkavm_common::program::{InstructionSet, InstructionSetKind, ProgramBlob, CODE_BLOCK_SIZE};
use polkavm_fuzz::{encode_raw_container, generate_structured_code, RawProgram, SETUP_LENGTH};
use polkavm_linker::{Config, TargetInstructionSet};

const MAX_WINDOWS_PER_PROGRAM: usize = 64;
const MIN_WINDOW_SIZE: u32 = 256;
const MAX_CONTAINER_SEEDS: usize = 64;
const MAX_SEED_LENGTH: usize = 4096;
const CONTAINER_SOURCE_LENGTH: usize = 1024;

fn read(path: &Path) -> Vec<u8> {
    let data = std::fs::read(path).unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
    if path.extension().is_some_and(|extension| extension == "zst") {
        let mut output = Vec::new();
        ruzstd::StreamingDecoder::new(&mut &data[..])
            .unwrap()
            .read_to_end(&mut output)
            .unwrap();
        output
    } else {
        data
    }
}

fn windows(blob: &ProgramBlob) -> Vec<core::ops::Range<u32>> {
    let code_length = blob.code().len() as u32;
    if !blob.isa().is_legacy() {
        let block_size = CODE_BLOCK_SIZE as u32;
        return (0..code_length.div_ceil(block_size))
            .map(|nth| nth * block_size..((nth + 1) * block_size).min(code_length))
            .collect();
    }

    let mut output = Vec::new();
    let mut start = 0;
    for instruction in blob.instructions() {
        let end = instruction.next_offset.0;
        let size = end - start;
        if size >= CODE_BLOCK_SIZE as u32 || (size >= MIN_WINDOW_SIZE && instruction.kind.opcode().starts_new_basic_block()) {
            output.push(start..end);
            start = end;
        }
    }

    if start < code_length {
        output.push(start..code_length);
    }

    output
}

fn window_to_raw_program(blob: &ProgramBlob, window: core::ops::Range<u32>) -> RawProgram {
    let code = blob.code()[window.start as usize..window.end as usize].to_vec();
    let mut bitmask = vec![0; code.len().div_ceil(8)];
    if blob.isa().is_legacy() {
        for offset in 0..code.len() {
            let source = window.start as usize + offset;
            if blob.bitmask()[source / 8] & (1 << (source % 8)) != 0 {
                bitmask[offset / 8] |= 1 << (offset % 8);
            }
        }
    }

    let jump_table = blob
        .jump_table()
        .iter()
        .filter(|target| window.contains(&target.0))
        .map(|target| target.0 - window.start)
        .collect();

    RawProgram {
        isa: blob.isa(),
        jump_table,
        code,
        bitmask,
    }
}

fn main() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let output_directory = root.join("fuzz/corpus/fuzz_polkavm_raw");
    std::fs::create_dir_all(&output_directory).unwrap();

    let inputs = [
        (
            "revive-transfer-example",
            "test-data/revive-transfer-example.zst",
            TargetInstructionSet::ReviveV1,
        ),
        ("doom", "test-data/doom_64.elf.zst", TargetInstructionSet::Latest),
    ];

    for (name, path, isa) in inputs {
        let elf = read(&root.join(path));
        let blob =
            polkavm_linker::program_from_elf(Config::default(), isa, &elf).unwrap_or_else(|error| panic!("failed to link {path}: {error}"));
        let blob = ProgramBlob::parse(blob.into()).unwrap();
        assert!(matches!(blob.isa(), InstructionSetKind::ReviveV1 | InstructionSetKind::Latest64));

        let windows = windows(&blob);
        let step = windows.len().div_ceil(MAX_WINDOWS_PER_PROGRAM).max(1);
        let mut count = 0;
        for (nth, window) in windows.into_iter().enumerate().step_by(step) {
            let raw = window_to_raw_program(&blob, window);
            let seed = raw.encode(&[0; SETUP_LENGTH]);
            let roundtrip = RawProgram::decode(&seed);
            assert_eq!(roundtrip.code, raw.code);
            assert_eq!(roundtrip.jump_table, raw.jump_table[..raw.jump_table.len().min(255)]);
            std::fs::write(output_directory.join(format!("{name}-{nth:05}")), seed).unwrap();
            count += 1;
        }

        println!("{name}: {} bytes of code, {count} seeds", blob.code().len());
    }

    let mut state = 0x2545f4914f6cdd1d_u64;
    let mut count = 0;
    for nth in 0..MAX_CONTAINER_SEEDS {
        let data: Vec<u8> = (0..CONTAINER_SOURCE_LENGTH)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state as u8
            })
            .collect();

        let Ok((setup, code, _)) = generate_structured_code(&mut Unstructured::new(&data)) else {
            continue;
        };

        let seed = encode_raw_container(setup.isa, &[0; SETUP_LENGTH], &code.to_bytes(&setup));
        if seed.len() <= MAX_SEED_LENGTH {
            std::fs::write(output_directory.join(format!("container-{nth:05}")), seed).unwrap();
            count += 1;
        }
    }

    println!("containers: {count} seeds");
}
