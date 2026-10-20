//! Executes bench-blake2-256-asm's RISC-V assembly blake2b inside a real PVM
//! instance (interpreter backend) and compares every digest against
//! `blake2b_simd` computed on the host. Sizes cover every block-boundary
//! neighborhood, where blake2b implementations typically break.
//!
//! The guest (`guest-programs/test-blake2-asm`) is built by this test with
//! the same toolchain/target the benchmarks use, mirroring how
//! crates/polkavm's own tests build their test blobs.

use std::path::PathBuf;
use std::process::Command;

fn build_guest_blob() -> Vec<u8> {
    let guest_programs = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../guest-programs");

    let mut args = polkavm_linker::TargetJsonArgs::default();
    args.is_64_bit = true;
    args.rustc_version = polkavm_linker::RustcVersion::Legacy;
    let target_json = polkavm_linker::target_json_path(args).unwrap();

    let mut cmd = Command::new("cargo");
    // Scrub the outer invocation's toolchain pins so the guest builds with
    // the toolchain pinned by guest-programs/rust-toolchain.toml (a nightly
    // with rust-src, required by -Zbuild-std).
    for (key, _) in std::env::vars() {
        if key.contains("CARGO") || key.contains("RUSTC") || key == "RUSTUP_TOOLCHAIN" {
            cmd.env_remove(&key);
        }
    }
    let output = cmd
        .args(["build", "-q", "--release", "-p", "test-blake2-asm", "--bin", "test-blake2-asm"])
        .arg("--target")
        .arg(&target_json)
        .arg("-Zbuild-std=core,alloc")
        .current_dir(&guest_programs)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "guest build failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let elf = std::fs::read(guest_programs.join("target/riscv64emac-unknown-none-polkavm/release/test-blake2-asm")).unwrap();
    polkavm_linker::program_from_elf(
        polkavm_linker::Config::default(),
        polkavm_linker::TargetInstructionSet::Latest,
        &elf,
    )
    .unwrap()
}

/// Deterministic pseudo-random input, different for every size.
fn input_for(size: usize) -> Vec<u8> {
    let mut state = 0x9e3779b97f4a7c15u64 ^ (size as u64);
    (0..size)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state as u8
        })
        .collect()
}

#[test]
fn asm_blake2b_in_pvm_matches_blake2b_simd() {
    let blob = build_guest_blob();

    let mut config = polkavm::Config::from_env().unwrap();
    // Deterministic and available everywhere (no sandbox requirements).
    config.set_backend(Some(polkavm::BackendKind::Interpreter));
    let engine = polkavm::Engine::new(&config).unwrap();
    let blob = polkavm::ProgramBlob::parse(blob.into()).unwrap();
    let module = polkavm::Module::from_blob(&engine, &polkavm::ModuleConfig::default(), blob).unwrap();
    let linker = polkavm::Linker::<()>::new();
    let mut instance = linker.instantiate_pre(&module).unwrap().instantiate().unwrap();

    let buffer_ptr: u64 = instance.call_typed_and_get_result(&mut (), "buffer_ptr", ()).unwrap();
    let digest_ptr: u64 = instance.call_typed_and_get_result(&mut (), "digest_ptr", ()).unwrap();

    // The full range up to 512, plus every power-of-two neighborhood
    // (2^n - 16 ..= 2^n + 16) up to the buffer size - the boundaries where
    // hash implementations typically break.
    let mut sizes = std::collections::BTreeSet::new();
    sizes.extend(1..=512usize);
    for n in 10..=20u32 {
        let power = 1usize << n;
        sizes.extend(power - 16..=power + 16);
    }

    for size in sizes {
        let input = input_for(size);
        if size > 0 {
            instance.write_memory(buffer_ptr as u32, &input).unwrap();
        }
        instance.call_typed(&mut (), "hash", (size as u64,)).unwrap();
        let digest = instance.read_memory(digest_ptr as u32, 32).unwrap();

        let expected = blake2b_simd::Params::new().hash_length(32).hash(&input);
        assert_eq!(digest, expected.as_bytes(), "mismatch at size {size}");
    }
}
