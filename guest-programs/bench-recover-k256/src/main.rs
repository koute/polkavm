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

// `sp_io::crypto::secp256k1_ecdsa_recover` semantics with `k256`: recover the
// public key from a 65-byte recoverable signature and a 32-byte prehash, then
// compare with the expected key. This recover-and-compare is also exactly how
// `sp_io::crypto::ecdsa_verify` is implemented (sp_core `verify_prehashed`).

#[path = "../../ecdsa-fixtures.rs"]
mod fixtures;
use fixtures::{HASH, PUBLIC_KEY, SIGNATURE};

fn benchmark_initialize(_state: &mut State) {}

fn benchmark_run(_state: &mut State) {
    use core::hint::black_box;

    let recovery_id = k256::ecdsa::RecoveryId::from_byte(black_box(SIGNATURE[64])).unwrap();
    let signature = k256::ecdsa::Signature::from_slice(black_box(&SIGNATURE[..64])).unwrap();
    let recovered =
        k256::ecdsa::VerifyingKey::recover_from_prehash(black_box(&HASH), &signature, recovery_id)
            .unwrap();
    assert_eq!(recovered.to_encoded_point(true).as_bytes(), &PUBLIC_KEY[..]);
}
