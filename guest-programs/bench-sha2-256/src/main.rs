#![no_std]
#![no_main]

include!("../../bench-common.rs");
include!("../../hash-bench-common.rs");

// As `sp_io::hashing::sha2_256`.
fn hash_once(input: &[u8], out: &mut [u8; 64]) -> usize {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(input);
    out[..32].copy_from_slice(&hasher.finalize());
    32
}
