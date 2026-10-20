// blake2b-256 with a hand-scheduled RISC-V assembly compression function
// (`blake2b_compress.S`, generated).
//
// Rationale: the recompiled output of the portable Rust implementation is
// issue-bound — LLVM's register allocation for the 13-register rv64e target
// spills far more than necessary and its 3-operand code forces the
// recompiler to emit register-copy `mov`s. The assembly version pins the
// state's a/b rows (v0..v7) in registers, streams the c/d rows through a
// 64-byte stack frame, uses strictly two-operand form (no recompiler movs),
// and bakes the message schedule into constant load offsets.
//
// On non-riscv64 targets (host builds, riscv32) this falls back to a plain
// Rust implementation (a rounds loop; merged from the former
// `compact_blake2b` module) so the export exists everywhere and outputs
// stay comparable.

const IV: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

#[cfg(target_arch = "riscv64")]
core::arch::global_asm!(include_str!("blake2b_compress.S"));

#[cfg(target_arch = "riscv64")]
extern "C" {
    /// Processes `nblocks` consecutive 128-byte blocks; the byte counter for
    /// block k is `t_base + 128*k` (wrapping). `last != 0` finalizes every
    /// block in the batch, so callers pass `nblocks = 1` for the last block.
    fn blake2b_compress_many(h: *mut u64, data: *const u8, nblocks: u64, t_base: u64, iv: *const u64, last: u64);
}

#[cfg(target_arch = "riscv64")]
pub fn blake2b_256(input: &[u8]) -> [u8; 32] {
    let mut h = IV;
    h[0] ^= 0x0101_0000 ^ 32;

    // All full blocks except a full last block (the last block is always
    // finalized separately below).
    let full = input.len().saturating_sub(1) / 128;
    if full > 0 {
        unsafe { blake2b_compress_many(h.as_mut_ptr(), input.as_ptr(), full as u64, 0, IV.as_ptr(), 0) };
    }

    let rem = &input[full * 128..];
    let mut block = [0u8; 128];
    block[..rem.len()].copy_from_slice(rem);
    let t_base = (input.len() as u64).wrapping_sub(128);
    unsafe { blake2b_compress_many(h.as_mut_ptr(), block.as_ptr(), 1, t_base, IV.as_ptr(), 1) };

    let mut out = [0u8; 32];
    for i in 0..4 {
        out[i * 8..][..8].copy_from_slice(&h[i].to_le_bytes());
    }
    out
}

#[cfg(not(target_arch = "riscv64"))]
const SIGMA: [[u8; 16]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];

#[cfg(not(target_arch = "riscv64"))]
#[inline(always)]
fn g(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize, x: u64, y: u64) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
    v[d] = (v[d] ^ v[a]).rotate_right(32);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(24);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(63);
}

#[cfg(not(target_arch = "riscv64"))]
fn compress(h: &mut [u64; 8], block: &[u8; 128], t: u128, last: bool) {
    let mut m = [0u64; 16];
    for (i, chunk) in block.chunks_exact(8).enumerate() {
        m[i] = u64::from_le_bytes(chunk.try_into().unwrap());
    }

    let mut v = [0u64; 16];
    v[..8].copy_from_slice(h);
    v[8..].copy_from_slice(&IV);
    v[12] ^= t as u64;
    v[13] ^= (t >> 64) as u64;
    if last {
        v[14] = !v[14];
    }

    let mut s_idx = 0;
    for _ in 0..12 {
        let s = &SIGMA[s_idx];
        s_idx += 1;
        if s_idx == 10 {
            s_idx = 0;
        }
        g(&mut v, 0, 4, 8, 12, m[s[0] as usize & 15], m[s[1] as usize & 15]);
        g(&mut v, 1, 5, 9, 13, m[s[2] as usize & 15], m[s[3] as usize & 15]);
        g(&mut v, 2, 6, 10, 14, m[s[4] as usize & 15], m[s[5] as usize & 15]);
        g(&mut v, 3, 7, 11, 15, m[s[6] as usize & 15], m[s[7] as usize & 15]);
        g(&mut v, 0, 5, 10, 15, m[s[8] as usize & 15], m[s[9] as usize & 15]);
        g(&mut v, 1, 6, 11, 12, m[s[10] as usize & 15], m[s[11] as usize & 15]);
        g(&mut v, 2, 7, 8, 13, m[s[12] as usize & 15], m[s[13] as usize & 15]);
        g(&mut v, 3, 4, 9, 14, m[s[14] as usize & 15], m[s[15] as usize & 15]);
    }

    for i in 0..8 {
        h[i] ^= v[i] ^ v[i + 8];
    }
}

/// Plain-Rust fallback (a rounds loop; merged from the former
/// `compact_blake2b` module) for targets without the assembly.
#[cfg(not(target_arch = "riscv64"))]
pub fn blake2b_256(input: &[u8]) -> [u8; 32] {
    let mut h = IV;
    h[0] ^= 0x0101_0000 ^ 32; // digest_length = 32, key = 0, fanout = 1, depth = 1

    let mut t: u128 = 0;
    let mut offset = 0;
    while input.len() - offset > 128 {
        let block: &[u8; 128] = input[offset..offset + 128].try_into().unwrap();
        t += 128;
        compress(&mut h, block, t, false);
        offset += 128;
    }

    let rem = &input[offset..];
    let mut block = [0u8; 128];
    block[..rem.len()].copy_from_slice(rem);
    t += rem.len() as u128;
    compress(&mut h, &block, t, true);

    let mut out = [0u8; 32];
    for i in 0..4 {
        out[i * 8..][..8].copy_from_slice(&h[i].to_le_bytes());
    }
    out
}
