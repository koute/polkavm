// Shared implementation for the bench-<hash-algorithm> guest benchmarks.
//
// Each crate defines `hash_once(input, out) -> digest_len` and includes this
// file. `run()` hashes `buffer[..size]` once, feeding up to 32 bytes of the
// digest back into the buffer so consecutive runs never hash identical
// input. The size defaults to `DEFAULT_SIZE`; the harness can override it
// through the optional `benchmark_set_size` export (`--size`).

const MAX_LEN: usize = 1024 * 1024;
const DEFAULT_SIZE: usize = 4096;

// One run() hashes at least this many bytes (in max(1, ITER_BYTES / size)
// chained iterations), so the harness's per-call overhead (e.g. the VM
// call entry) is amortized even for tiny input sizes. Result processing
// divides by the same formula to recover the per-hash time; per-row
// PVM-vs-native ratios are unaffected (the factor is identical on both
// sides).
const ITER_BYTES: usize = 64 * 1024;

struct State {
    memory: alloc::vec::Vec<u8>,
    size: usize,
}

define_benchmark! {
    heap_size = MAX_LEN + 64 * 1024,
    state = State {
        memory: alloc::vec::Vec::new(),
        size: DEFAULT_SIZE,
    },
}

fn benchmark_initialize(state: &mut State) {
    state.memory.resize(MAX_LEN, 0);
    for (index, byte) in state.memory.iter_mut().enumerate() {
        *byte = index as u8;
    }
}

fn benchmark_run(state: &mut State) {
    let iterations = (ITER_BYTES / state.size).max(1);
    let mut out = [0u8; 64];
    for _ in 0..iterations {
        let out_len = hash_once(&state.memory[..state.size], &mut out);
        let feedback = state.size.min(out_len).min(32);
        state.memory[..feedback].copy_from_slice(&out[..feedback]);
    }
    core::hint::black_box(&out);
}

#[cfg_attr(target_env = "polkavm", polkavm_derive::polkavm_export)]
#[no_mangle]
pub extern "C" fn benchmark_set_size(size: u64) {
    assert!(size > 0 && size as usize <= MAX_LEN);
    let state = unsafe { &mut *core::ptr::addr_of_mut!(STATE) };
    state.size = size as usize;
}
