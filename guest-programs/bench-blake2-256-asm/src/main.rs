#![no_std]
#![no_main]

include!("../../bench-common.rs");
include!("../../hash-bench-common.rs");

mod asm_blake2b;

// blake2b-256 with a hand-scheduled RISC-V assembly compression function on
// riscv64; other targets fall back to a plain Rust implementation (see
// `asm_blake2b.rs`). Compare against `bench-blake2-256` (blake2b_simd) to see
// what hand-tuned codegen buys under the recompiler.
fn hash_once(input: &[u8], out: &mut [u8; 64]) -> usize {
    out[..32].copy_from_slice(&asm_blake2b::blake2b_256(input));
    32
}
