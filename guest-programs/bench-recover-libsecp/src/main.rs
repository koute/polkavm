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

// `sp_io::crypto::secp256k1_ecdsa_recover` semantics with the pure-Rust
// `libsecp256k1` — same operation and same fixture as bench-recover-k256,
// so the two implementations are directly comparable.

#[path = "../../ecdsa-fixtures.rs"]
mod fixtures;
use fixtures::{HASH, PUBLIC_KEY, SIGNATURE};

fn benchmark_initialize(_state: &mut State) {}

fn benchmark_run(_state: &mut State) {
    use core::hint::black_box;

    let message = libsecp256k1::Message::parse(black_box(&HASH));
    let signature = libsecp256k1::Signature::parse_standard_slice(black_box(&SIGNATURE[..64])).unwrap();
    let recovery_id = libsecp256k1::RecoveryId::parse(black_box(SIGNATURE[64])).unwrap();
    let recovered = libsecp256k1::recover(&message, &signature, &recovery_id).unwrap();
    assert_eq!(recovered.serialize_compressed(), PUBLIC_KEY);
}
