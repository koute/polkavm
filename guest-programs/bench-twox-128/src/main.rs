#![no_std]
#![no_main]

include!("../../bench-common.rs");
include!("../../hash-bench-common.rs");

// 2 seeded XxHash64 pass(es), like `sp_core::hashing::twox_128`.
fn hash_once(input: &[u8], out: &mut [u8; 64]) -> usize {
    use core::hash::Hasher;
    for seed in 0..2u64 {
        let mut hasher = twox_hash::XxHash64::with_seed(seed);
        hasher.write(input);
        out[seed as usize * 8..(seed as usize + 1) * 8].copy_from_slice(&hasher.finish().to_le_bytes());
    }
    2 * 8
}
