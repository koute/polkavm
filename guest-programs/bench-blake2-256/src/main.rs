#![no_std]
#![no_main]

include!("../../bench-common.rs");
include!("../../hash-bench-common.rs");

// 32-byte blake2b, as `sp_io::hashing::blake2_256`.
fn hash_once(input: &[u8], out: &mut [u8; 64]) -> usize {
    let hash = blake2b_simd::Params::new().hash_length(32).hash(input);
    out[..32].copy_from_slice(hash.as_bytes());
    32
}
