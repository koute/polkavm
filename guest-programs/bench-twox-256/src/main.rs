#![no_std]
#![no_main]

include!("../../bench-common.rs");
include!("../../hash-bench-common.rs");

// 4 seeded XxHash64 pass(es), like `sp_core::hashing::twox_256`.
fn hash_once(input: &[u8], out: &mut [u8; 64]) -> usize {
    use core::hash::Hasher;
    for seed in 0..4u64 {
        let mut hasher = twox_hash::XxHash64::with_seed(seed);
        hasher.write(input);
        out[seed as usize * 8..(seed as usize + 1) * 8].copy_from_slice(&hasher.finish().to_le_bytes());
    }
    4 * 8
}
