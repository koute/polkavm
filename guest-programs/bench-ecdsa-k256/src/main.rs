#![no_std]
#![no_main]

include!("../../bench-common.rs");

// secp256k1 arithmetic needs more than the default 8 KiB of stack.
#[cfg(target_env = "polkavm")]
polkavm_derive::min_stack_size!(128 * 1024);

struct State;
define_benchmark! {
    heap_size = 16 * 1024,
    state = State,
}

// Classic ECDSA verification (blake2_256 of the message + `verify_prehash`)
// with `k256`, the crate sp_core::ecdsa uses in no_std runtimes.
//
// Note: `sp_io::crypto::ecdsa_verify` is actually implemented as
// recover-public-key-and-compare (see sp_core `verify_prehashed`) — that
// operation is measured by the `recover-k256` benchmark; this one measures
// classic verification for comparison. The std host side of sp_io uses the
// C `secp256k1` crate, which is not buildable for the PVM target.
//
#[path = "../../ecdsa-fixtures.rs"]
mod fixtures;
use fixtures::{MESSAGE, PUBLIC_KEY, SIGNATURE};

fn benchmark_initialize(_state: &mut State) {}

fn benchmark_run(_state: &mut State) {
    use core::hint::black_box;
    use k256::ecdsa::signature::hazmat::PrehashVerifier;

    let hash = blake2b_simd::Params::new().hash_length(32).hash(black_box(&MESSAGE));
    let key = k256::ecdsa::VerifyingKey::from_sec1_bytes(black_box(&PUBLIC_KEY)).unwrap();
    let signature = k256::ecdsa::Signature::from_slice(black_box(&SIGNATURE[..64])).unwrap();
    black_box(key.verify_prehash(hash.as_bytes(), &signature)).unwrap();
}
