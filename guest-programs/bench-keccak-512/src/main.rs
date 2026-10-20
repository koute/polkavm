#![no_std]
#![no_main]

include!("../../bench-common.rs");
include!("../../hash-bench-common.rs");

// As `sp_io::hashing::keccak_512`.
fn hash_once(input: &[u8], out: &mut [u8; 64]) -> usize {
    use sha3::Digest;
    let mut hasher = sha3::Keccak512::new();
    hasher.update(input);
    out[..64].copy_from_slice(&hasher.finalize());
    64
}
