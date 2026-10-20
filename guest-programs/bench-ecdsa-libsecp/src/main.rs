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

// Classic ECDSA verification (blake2_256 of the message + `verify`) with the
// pure-Rust `libsecp256k1` — same operation and same fixture as
// bench-ecdsa-k256, so the two implementations are directly comparable.
// The std host side of sp_io uses the C `secp256k1` crate, which is not
// buildable for the PVM target.

#[path = "../../ecdsa-fixtures.rs"]
mod fixtures;
use fixtures::{MESSAGE, PUBLIC_KEY, SIGNATURE};

fn benchmark_initialize(_state: &mut State) {}

fn benchmark_run(_state: &mut State) {
    use core::hint::black_box;

    let hash: [u8; 32] = blake2b_simd::Params::new()
        .hash_length(32)
        .hash(black_box(&MESSAGE))
        .as_bytes()
        .try_into()
        .unwrap();
    let message = libsecp256k1::Message::parse(&hash);
    let signature = libsecp256k1::Signature::parse_standard_slice(black_box(&SIGNATURE[..64])).unwrap();
    let public = libsecp256k1::PublicKey::parse_compressed(black_box(&PUBLIC_KEY)).unwrap();
    assert!(black_box(libsecp256k1::verify(&message, &signature, &public)));
}
