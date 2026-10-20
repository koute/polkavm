#![no_std]
#![no_main]

include!("../../bench-common.rs");
include!("../../hash-bench-common.rs");

// 16-byte blake2b, as `sp_io::hashing::blake2_128`.
fn hash_once(input: &[u8], out: &mut [u8; 64]) -> usize {
    let hash = blake2b_simd::Params::new().hash_length(16).hash(input);
    out[..16].copy_from_slice(hash.as_bytes());
    16
}
