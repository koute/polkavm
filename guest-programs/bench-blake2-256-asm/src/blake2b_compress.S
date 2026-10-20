// Hand-scheduled blake2b compression loop for PVM (rv64e + zbb).
// Generated - see the report / bench-hash sources for context.
// fn blake2b_compress_many(h: *mut u64 [a0], data: *const u8 [a1],
//                          nblocks: u64 [a2], t_base: u64 [a3],
//                          iv: *const u64 [a4], last: u64 [a5])
//
// Processes `nblocks` consecutive 128-byte blocks; the byte counter for
// block k is t_base + 128*k (wrapping, so a short/empty last block passes
// t_base = total_len - 128). If `last` != 0 every block in the batch is
// finalized (callers pass nblocks = 1 for the last block).
// h is kept in the pinned registers across blocks; the a/b rows of the
// state (v0..v7) never touch memory inside a block.
.section .text.blake2b_compress_many,"ax"
.globl blake2b_compress_many
blake2b_compress_many:
    addi sp, sp, -240
    sd   ra, 216(sp)
    sd   s0, 224(sp)
    sd   s1, 232(sp)
    sd   a0, 208(sp)
    sd   a3, 192(sp)
    sd   a2, 200(sp)
    // IV copy; IV[6] pre-masked with the finalization flag
    ld   t1, 0(a4)
    sd   t1, 64(sp)
    ld   t1, 8(a4)
    sd   t1, 72(sp)
    ld   t1, 16(a4)
    sd   t1, 80(sp)
    ld   t1, 24(a4)
    sd   t1, 88(sp)
    ld   t1, 32(a4)
    sd   t1, 96(sp)
    ld   t1, 40(a4)
    sd   t1, 104(sp)
    ld   t1, 48(a4)
    sd   t1, 112(sp)
    ld   t1, 56(a4)
    sd   t1, 120(sp)
    ld   t1, 112(sp)
    neg  t2, a5
    xor  t1, t1, t2
    sd   t1, 112(sp)
    mv   t0, a1
    // v0..v7 = h[0..7] (a0 loaded last - it is the source pointer)
    ld   s1, 56(a0)
    ld   s0, 48(a0)
    ld   a5, 40(a0)
    ld   a4, 32(a0)
    ld   a3, 24(a0)
    ld   a2, 16(a0)
    ld   a1, 8(a0)
    ld   a0, 0(a0)
.Lblock:
    // save h_old; the pinned registers become the working state v0..v7
    sd   a0, 128(sp)
    sd   a1, 136(sp)
    sd   a2, 144(sp)
    sd   a3, 152(sp)
    sd   a4, 160(sp)
    sd   a5, 168(sp)
    sd   s0, 176(sp)
    sd   s1, 184(sp)
    // t += 128; v8..v15 = IV copy, v12 ^= t
    ld   t1, 192(sp)
    addi t1, t1, 128
    sd   t1, 192(sp)
    ld   t2, 96(sp)
    xor  t2, t2, t1
    sd   t2, 32(sp)
    ld   t1, 64(sp)
    sd   t1, 0(sp)
    ld   t1, 72(sp)
    sd   t1, 8(sp)
    ld   t1, 80(sp)
    sd   t1, 16(sp)
    ld   t1, 88(sp)
    sd   t1, 24(sp)
    ld   t1, 104(sp)
    sd   t1, 40(sp)
    ld   t1, 112(sp)
    sd   t1, 48(sp)
    ld   t1, 120(sp)
    sd   t1, 56(sp)
    // round 0
    ld   t1, 0(t0)
    add  a0, a0, a4
    add  a0, a0, t1
    ld   t2, 32(sp)
    xor  t2, t2, a0
    rori t2, t2, 32
    ld   t1, 0(sp)
    add  t1, t1, t2
    xor  a4, a4, t1
    rori a4, a4, 24
    ld   ra, 8(t0)
    add  a0, a0, a4
    add  a0, a0, ra
    xor  t2, t2, a0
    rori t2, t2, 16
    sd   t2, 32(sp)
    add  t1, t1, t2
    sd   t1, 0(sp)
    xor  a4, a4, t1
    rori a4, a4, 63
    ld   t1, 16(t0)
    add  a1, a1, a5
    add  a1, a1, t1
    ld   t2, 40(sp)
    xor  t2, t2, a1
    rori t2, t2, 32
    ld   t1, 8(sp)
    add  t1, t1, t2
    xor  a5, a5, t1
    rori a5, a5, 24
    ld   ra, 24(t0)
    add  a1, a1, a5
    add  a1, a1, ra
    xor  t2, t2, a1
    rori t2, t2, 16
    sd   t2, 40(sp)
    add  t1, t1, t2
    sd   t1, 8(sp)
    xor  a5, a5, t1
    rori a5, a5, 63
    ld   t1, 32(t0)
    add  a2, a2, s0
    add  a2, a2, t1
    ld   t2, 48(sp)
    xor  t2, t2, a2
    rori t2, t2, 32
    ld   t1, 16(sp)
    add  t1, t1, t2
    xor  s0, s0, t1
    rori s0, s0, 24
    ld   ra, 40(t0)
    add  a2, a2, s0
    add  a2, a2, ra
    xor  t2, t2, a2
    rori t2, t2, 16
    sd   t2, 48(sp)
    add  t1, t1, t2
    sd   t1, 16(sp)
    xor  s0, s0, t1
    rori s0, s0, 63
    ld   t1, 48(t0)
    add  a3, a3, s1
    add  a3, a3, t1
    ld   t2, 56(sp)
    xor  t2, t2, a3
    rori t2, t2, 32
    ld   t1, 24(sp)
    add  t1, t1, t2
    xor  s1, s1, t1
    rori s1, s1, 24
    ld   ra, 56(t0)
    add  a3, a3, s1
    add  a3, a3, ra
    xor  t2, t2, a3
    rori t2, t2, 16
    sd   t2, 56(sp)
    add  t1, t1, t2
    sd   t1, 24(sp)
    xor  s1, s1, t1
    rori s1, s1, 63
    ld   t1, 64(t0)
    add  a0, a0, a5
    add  a0, a0, t1
    ld   t2, 56(sp)
    xor  t2, t2, a0
    rori t2, t2, 32
    ld   t1, 16(sp)
    add  t1, t1, t2
    xor  a5, a5, t1
    rori a5, a5, 24
    ld   ra, 72(t0)
    add  a0, a0, a5
    add  a0, a0, ra
    xor  t2, t2, a0
    rori t2, t2, 16
    sd   t2, 56(sp)
    add  t1, t1, t2
    sd   t1, 16(sp)
    xor  a5, a5, t1
    rori a5, a5, 63
    ld   t1, 80(t0)
    add  a1, a1, s0
    add  a1, a1, t1
    ld   t2, 32(sp)
    xor  t2, t2, a1
    rori t2, t2, 32
    ld   t1, 24(sp)
    add  t1, t1, t2
    xor  s0, s0, t1
    rori s0, s0, 24
    ld   ra, 88(t0)
    add  a1, a1, s0
    add  a1, a1, ra
    xor  t2, t2, a1
    rori t2, t2, 16
    sd   t2, 32(sp)
    add  t1, t1, t2
    sd   t1, 24(sp)
    xor  s0, s0, t1
    rori s0, s0, 63
    ld   t1, 96(t0)
    add  a2, a2, s1
    add  a2, a2, t1
    ld   t2, 40(sp)
    xor  t2, t2, a2
    rori t2, t2, 32
    ld   t1, 0(sp)
    add  t1, t1, t2
    xor  s1, s1, t1
    rori s1, s1, 24
    ld   ra, 104(t0)
    add  a2, a2, s1
    add  a2, a2, ra
    xor  t2, t2, a2
    rori t2, t2, 16
    sd   t2, 40(sp)
    add  t1, t1, t2
    sd   t1, 0(sp)
    xor  s1, s1, t1
    rori s1, s1, 63
    ld   t1, 112(t0)
    add  a3, a3, a4
    add  a3, a3, t1
    ld   t2, 48(sp)
    xor  t2, t2, a3
    rori t2, t2, 32
    ld   t1, 8(sp)
    add  t1, t1, t2
    xor  a4, a4, t1
    rori a4, a4, 24
    ld   ra, 120(t0)
    add  a3, a3, a4
    add  a3, a3, ra
    xor  t2, t2, a3
    rori t2, t2, 16
    sd   t2, 48(sp)
    add  t1, t1, t2
    sd   t1, 8(sp)
    xor  a4, a4, t1
    rori a4, a4, 63
    // round 1
    ld   t1, 112(t0)
    add  a0, a0, a4
    add  a0, a0, t1
    ld   t2, 32(sp)
    xor  t2, t2, a0
    rori t2, t2, 32
    ld   t1, 0(sp)
    add  t1, t1, t2
    xor  a4, a4, t1
    rori a4, a4, 24
    ld   ra, 80(t0)
    add  a0, a0, a4
    add  a0, a0, ra
    xor  t2, t2, a0
    rori t2, t2, 16
    sd   t2, 32(sp)
    add  t1, t1, t2
    sd   t1, 0(sp)
    xor  a4, a4, t1
    rori a4, a4, 63
    ld   t1, 32(t0)
    add  a1, a1, a5
    add  a1, a1, t1
    ld   t2, 40(sp)
    xor  t2, t2, a1
    rori t2, t2, 32
    ld   t1, 8(sp)
    add  t1, t1, t2
    xor  a5, a5, t1
    rori a5, a5, 24
    ld   ra, 64(t0)
    add  a1, a1, a5
    add  a1, a1, ra
    xor  t2, t2, a1
    rori t2, t2, 16
    sd   t2, 40(sp)
    add  t1, t1, t2
    sd   t1, 8(sp)
    xor  a5, a5, t1
    rori a5, a5, 63
    ld   t1, 72(t0)
    add  a2, a2, s0
    add  a2, a2, t1
    ld   t2, 48(sp)
    xor  t2, t2, a2
    rori t2, t2, 32
    ld   t1, 16(sp)
    add  t1, t1, t2
    xor  s0, s0, t1
    rori s0, s0, 24
    ld   ra, 120(t0)
    add  a2, a2, s0
    add  a2, a2, ra
    xor  t2, t2, a2
    rori t2, t2, 16
    sd   t2, 48(sp)
    add  t1, t1, t2
    sd   t1, 16(sp)
    xor  s0, s0, t1
    rori s0, s0, 63
    ld   t1, 104(t0)
    add  a3, a3, s1
    add  a3, a3, t1
    ld   t2, 56(sp)
    xor  t2, t2, a3
    rori t2, t2, 32
    ld   t1, 24(sp)
    add  t1, t1, t2
    xor  s1, s1, t1
    rori s1, s1, 24
    ld   ra, 48(t0)
    add  a3, a3, s1
    add  a3, a3, ra
    xor  t2, t2, a3
    rori t2, t2, 16
    sd   t2, 56(sp)
    add  t1, t1, t2
    sd   t1, 24(sp)
    xor  s1, s1, t1
    rori s1, s1, 63
    ld   t1, 8(t0)
    add  a0, a0, a5
    add  a0, a0, t1
    ld   t2, 56(sp)
    xor  t2, t2, a0
    rori t2, t2, 32
    ld   t1, 16(sp)
    add  t1, t1, t2
    xor  a5, a5, t1
    rori a5, a5, 24
    ld   ra, 96(t0)
    add  a0, a0, a5
    add  a0, a0, ra
    xor  t2, t2, a0
    rori t2, t2, 16
    sd   t2, 56(sp)
    add  t1, t1, t2
    sd   t1, 16(sp)
    xor  a5, a5, t1
    rori a5, a5, 63
    ld   t1, 0(t0)
    add  a1, a1, s0
    add  a1, a1, t1
    ld   t2, 32(sp)
    xor  t2, t2, a1
    rori t2, t2, 32
    ld   t1, 24(sp)
    add  t1, t1, t2
    xor  s0, s0, t1
    rori s0, s0, 24
    ld   ra, 16(t0)
    add  a1, a1, s0
    add  a1, a1, ra
    xor  t2, t2, a1
    rori t2, t2, 16
    sd   t2, 32(sp)
    add  t1, t1, t2
    sd   t1, 24(sp)
    xor  s0, s0, t1
    rori s0, s0, 63
    ld   t1, 88(t0)
    add  a2, a2, s1
    add  a2, a2, t1
    ld   t2, 40(sp)
    xor  t2, t2, a2
    rori t2, t2, 32
    ld   t1, 0(sp)
    add  t1, t1, t2
    xor  s1, s1, t1
    rori s1, s1, 24
    ld   ra, 56(t0)
    add  a2, a2, s1
    add  a2, a2, ra
    xor  t2, t2, a2
    rori t2, t2, 16
    sd   t2, 40(sp)
    add  t1, t1, t2
    sd   t1, 0(sp)
    xor  s1, s1, t1
    rori s1, s1, 63
    ld   t1, 40(t0)
    add  a3, a3, a4
    add  a3, a3, t1
    ld   t2, 48(sp)
    xor  t2, t2, a3
    rori t2, t2, 32
    ld   t1, 8(sp)
    add  t1, t1, t2
    xor  a4, a4, t1
    rori a4, a4, 24
    ld   ra, 24(t0)
    add  a3, a3, a4
    add  a3, a3, ra
    xor  t2, t2, a3
    rori t2, t2, 16
    sd   t2, 48(sp)
    add  t1, t1, t2
    sd   t1, 8(sp)
    xor  a4, a4, t1
    rori a4, a4, 63
    // round 2
    ld   t1, 88(t0)
    add  a0, a0, a4
    add  a0, a0, t1
    ld   t2, 32(sp)
    xor  t2, t2, a0
    rori t2, t2, 32
    ld   t1, 0(sp)
    add  t1, t1, t2
    xor  a4, a4, t1
    rori a4, a4, 24
    ld   ra, 64(t0)
    add  a0, a0, a4
    add  a0, a0, ra
    xor  t2, t2, a0
    rori t2, t2, 16
    sd   t2, 32(sp)
    add  t1, t1, t2
    sd   t1, 0(sp)
    xor  a4, a4, t1
    rori a4, a4, 63
    ld   t1, 96(t0)
    add  a1, a1, a5
    add  a1, a1, t1
    ld   t2, 40(sp)
    xor  t2, t2, a1
    rori t2, t2, 32
    ld   t1, 8(sp)
    add  t1, t1, t2
    xor  a5, a5, t1
    rori a5, a5, 24
    ld   ra, 0(t0)
    add  a1, a1, a5
    add  a1, a1, ra
    xor  t2, t2, a1
    rori t2, t2, 16
    sd   t2, 40(sp)
    add  t1, t1, t2
    sd   t1, 8(sp)
    xor  a5, a5, t1
    rori a5, a5, 63
    ld   t1, 40(t0)
    add  a2, a2, s0
    add  a2, a2, t1
    ld   t2, 48(sp)
    xor  t2, t2, a2
    rori t2, t2, 32
    ld   t1, 16(sp)
    add  t1, t1, t2
    xor  s0, s0, t1
    rori s0, s0, 24
    ld   ra, 16(t0)
    add  a2, a2, s0
    add  a2, a2, ra
    xor  t2, t2, a2
    rori t2, t2, 16
    sd   t2, 48(sp)
    add  t1, t1, t2
    sd   t1, 16(sp)
    xor  s0, s0, t1
    rori s0, s0, 63
    ld   t1, 120(t0)
    add  a3, a3, s1
    add  a3, a3, t1
    ld   t2, 56(sp)
    xor  t2, t2, a3
    rori t2, t2, 32
    ld   t1, 24(sp)
    add  t1, t1, t2
    xor  s1, s1, t1
    rori s1, s1, 24
    ld   ra, 104(t0)
    add  a3, a3, s1
    add  a3, a3, ra
    xor  t2, t2, a3
    rori t2, t2, 16
    sd   t2, 56(sp)
    add  t1, t1, t2
    sd   t1, 24(sp)
    xor  s1, s1, t1
    rori s1, s1, 63
    ld   t1, 80(t0)
    add  a0, a0, a5
    add  a0, a0, t1
    ld   t2, 56(sp)
    xor  t2, t2, a0
    rori t2, t2, 32
    ld   t1, 16(sp)
    add  t1, t1, t2
    xor  a5, a5, t1
    rori a5, a5, 24
    ld   ra, 112(t0)
    add  a0, a0, a5
    add  a0, a0, ra
    xor  t2, t2, a0
    rori t2, t2, 16
    sd   t2, 56(sp)
    add  t1, t1, t2
    sd   t1, 16(sp)
    xor  a5, a5, t1
    rori a5, a5, 63
    ld   t1, 24(t0)
    add  a1, a1, s0
    add  a1, a1, t1
    ld   t2, 32(sp)
    xor  t2, t2, a1
    rori t2, t2, 32
    ld   t1, 24(sp)
    add  t1, t1, t2
    xor  s0, s0, t1
    rori s0, s0, 24
    ld   ra, 48(t0)
    add  a1, a1, s0
    add  a1, a1, ra
    xor  t2, t2, a1
    rori t2, t2, 16
    sd   t2, 32(sp)
    add  t1, t1, t2
    sd   t1, 24(sp)
    xor  s0, s0, t1
    rori s0, s0, 63
    ld   t1, 56(t0)
    add  a2, a2, s1
    add  a2, a2, t1
    ld   t2, 40(sp)
    xor  t2, t2, a2
    rori t2, t2, 32
    ld   t1, 0(sp)
    add  t1, t1, t2
    xor  s1, s1, t1
    rori s1, s1, 24
    ld   ra, 8(t0)
    add  a2, a2, s1
    add  a2, a2, ra
    xor  t2, t2, a2
    rori t2, t2, 16
    sd   t2, 40(sp)
    add  t1, t1, t2
    sd   t1, 0(sp)
    xor  s1, s1, t1
    rori s1, s1, 63
    ld   t1, 72(t0)
    add  a3, a3, a4
    add  a3, a3, t1
    ld   t2, 48(sp)
    xor  t2, t2, a3
    rori t2, t2, 32
    ld   t1, 8(sp)
    add  t1, t1, t2
    xor  a4, a4, t1
    rori a4, a4, 24
    ld   ra, 32(t0)
    add  a3, a3, a4
    add  a3, a3, ra
    xor  t2, t2, a3
    rori t2, t2, 16
    sd   t2, 48(sp)
    add  t1, t1, t2
    sd   t1, 8(sp)
    xor  a4, a4, t1
    rori a4, a4, 63
    // round 3
    ld   t1, 56(t0)
    add  a0, a0, a4
    add  a0, a0, t1
    ld   t2, 32(sp)
    xor  t2, t2, a0
    rori t2, t2, 32
    ld   t1, 0(sp)
    add  t1, t1, t2
    xor  a4, a4, t1
    rori a4, a4, 24
    ld   ra, 72(t0)
    add  a0, a0, a4
    add  a0, a0, ra
    xor  t2, t2, a0
    rori t2, t2, 16
    sd   t2, 32(sp)
    add  t1, t1, t2
    sd   t1, 0(sp)
    xor  a4, a4, t1
    rori a4, a4, 63
    ld   t1, 24(t0)
    add  a1, a1, a5
    add  a1, a1, t1
    ld   t2, 40(sp)
    xor  t2, t2, a1
    rori t2, t2, 32
    ld   t1, 8(sp)
    add  t1, t1, t2
    xor  a5, a5, t1
    rori a5, a5, 24
    ld   ra, 8(t0)
    add  a1, a1, a5
    add  a1, a1, ra
    xor  t2, t2, a1
    rori t2, t2, 16
    sd   t2, 40(sp)
    add  t1, t1, t2
    sd   t1, 8(sp)
    xor  a5, a5, t1
    rori a5, a5, 63
    ld   t1, 104(t0)
    add  a2, a2, s0
    add  a2, a2, t1
    ld   t2, 48(sp)
    xor  t2, t2, a2
    rori t2, t2, 32
    ld   t1, 16(sp)
    add  t1, t1, t2
    xor  s0, s0, t1
    rori s0, s0, 24
    ld   ra, 96(t0)
    add  a2, a2, s0
    add  a2, a2, ra
    xor  t2, t2, a2
    rori t2, t2, 16
    sd   t2, 48(sp)
    add  t1, t1, t2
    sd   t1, 16(sp)
    xor  s0, s0, t1
    rori s0, s0, 63
    ld   t1, 88(t0)
    add  a3, a3, s1
    add  a3, a3, t1
    ld   t2, 56(sp)
    xor  t2, t2, a3
    rori t2, t2, 32
    ld   t1, 24(sp)
    add  t1, t1, t2
    xor  s1, s1, t1
    rori s1, s1, 24
    ld   ra, 112(t0)
    add  a3, a3, s1
    add  a3, a3, ra
    xor  t2, t2, a3
    rori t2, t2, 16
    sd   t2, 56(sp)
    add  t1, t1, t2
    sd   t1, 24(sp)
    xor  s1, s1, t1
    rori s1, s1, 63
    ld   t1, 16(t0)
    add  a0, a0, a5
    add  a0, a0, t1
    ld   t2, 56(sp)
    xor  t2, t2, a0
    rori t2, t2, 32
    ld   t1, 16(sp)
    add  t1, t1, t2
    xor  a5, a5, t1
    rori a5, a5, 24
    ld   ra, 48(t0)
    add  a0, a0, a5
    add  a0, a0, ra
    xor  t2, t2, a0
    rori t2, t2, 16
    sd   t2, 56(sp)
    add  t1, t1, t2
    sd   t1, 16(sp)
    xor  a5, a5, t1
    rori a5, a5, 63
    ld   t1, 40(t0)
    add  a1, a1, s0
    add  a1, a1, t1
    ld   t2, 32(sp)
    xor  t2, t2, a1
    rori t2, t2, 32
    ld   t1, 24(sp)
    add  t1, t1, t2
    xor  s0, s0, t1
    rori s0, s0, 24
    ld   ra, 80(t0)
    add  a1, a1, s0
    add  a1, a1, ra
    xor  t2, t2, a1
    rori t2, t2, 16
    sd   t2, 32(sp)
    add  t1, t1, t2
    sd   t1, 24(sp)
    xor  s0, s0, t1
    rori s0, s0, 63
    ld   t1, 32(t0)
    add  a2, a2, s1
    add  a2, a2, t1
    ld   t2, 40(sp)
    xor  t2, t2, a2
    rori t2, t2, 32
    ld   t1, 0(sp)
    add  t1, t1, t2
    xor  s1, s1, t1
    rori s1, s1, 24
    ld   ra, 0(t0)
    add  a2, a2, s1
    add  a2, a2, ra
    xor  t2, t2, a2
    rori t2, t2, 16
    sd   t2, 40(sp)
    add  t1, t1, t2
    sd   t1, 0(sp)
    xor  s1, s1, t1
    rori s1, s1, 63
    ld   t1, 120(t0)
    add  a3, a3, a4
    add  a3, a3, t1
    ld   t2, 48(sp)
    xor  t2, t2, a3
    rori t2, t2, 32
    ld   t1, 8(sp)
    add  t1, t1, t2
    xor  a4, a4, t1
    rori a4, a4, 24
    ld   ra, 64(t0)
    add  a3, a3, a4
    add  a3, a3, ra
    xor  t2, t2, a3
    rori t2, t2, 16
    sd   t2, 48(sp)
    add  t1, t1, t2
    sd   t1, 8(sp)
    xor  a4, a4, t1
    rori a4, a4, 63
    // round 4
    ld   t1, 72(t0)
    add  a0, a0, a4
    add  a0, a0, t1
    ld   t2, 32(sp)
    xor  t2, t2, a0
    rori t2, t2, 32
    ld   t1, 0(sp)
    add  t1, t1, t2
    xor  a4, a4, t1
    rori a4, a4, 24
    ld   ra, 0(t0)
    add  a0, a0, a4
    add  a0, a0, ra
    xor  t2, t2, a0
    rori t2, t2, 16
    sd   t2, 32(sp)
    add  t1, t1, t2
    sd   t1, 0(sp)
    xor  a4, a4, t1
    rori a4, a4, 63
    ld   t1, 40(t0)
    add  a1, a1, a5
    add  a1, a1, t1
    ld   t2, 40(sp)
    xor  t2, t2, a1
    rori t2, t2, 32
    ld   t1, 8(sp)
    add  t1, t1, t2
    xor  a5, a5, t1
    rori a5, a5, 24
    ld   ra, 56(t0)
    add  a1, a1, a5
    add  a1, a1, ra
    xor  t2, t2, a1
    rori t2, t2, 16
    sd   t2, 40(sp)
    add  t1, t1, t2
    sd   t1, 8(sp)
    xor  a5, a5, t1
    rori a5, a5, 63
    ld   t1, 16(t0)
    add  a2, a2, s0
    add  a2, a2, t1
    ld   t2, 48(sp)
    xor  t2, t2, a2
    rori t2, t2, 32
    ld   t1, 16(sp)
    add  t1, t1, t2
    xor  s0, s0, t1
    rori s0, s0, 24
    ld   ra, 32(t0)
    add  a2, a2, s0
    add  a2, a2, ra
    xor  t2, t2, a2
    rori t2, t2, 16
    sd   t2, 48(sp)
    add  t1, t1, t2
    sd   t1, 16(sp)
    xor  s0, s0, t1
    rori s0, s0, 63
    ld   t1, 80(t0)
    add  a3, a3, s1
    add  a3, a3, t1
    ld   t2, 56(sp)
    xor  t2, t2, a3
    rori t2, t2, 32
    ld   t1, 24(sp)
    add  t1, t1, t2
    xor  s1, s1, t1
    rori s1, s1, 24
    ld   ra, 120(t0)
    add  a3, a3, s1
    add  a3, a3, ra
    xor  t2, t2, a3
    rori t2, t2, 16
    sd   t2, 56(sp)
    add  t1, t1, t2
    sd   t1, 24(sp)
    xor  s1, s1, t1
    rori s1, s1, 63
    ld   t1, 112(t0)
    add  a0, a0, a5
    add  a0, a0, t1
    ld   t2, 56(sp)
    xor  t2, t2, a0
    rori t2, t2, 32
    ld   t1, 16(sp)
    add  t1, t1, t2
    xor  a5, a5, t1
    rori a5, a5, 24
    ld   ra, 8(t0)
    add  a0, a0, a5
    add  a0, a0, ra
    xor  t2, t2, a0
    rori t2, t2, 16
    sd   t2, 56(sp)
    add  t1, t1, t2
    sd   t1, 16(sp)
    xor  a5, a5, t1
    rori a5, a5, 63
    ld   t1, 88(t0)
    add  a1, a1, s0
    add  a1, a1, t1
    ld   t2, 32(sp)
    xor  t2, t2, a1
    rori t2, t2, 32
    ld   t1, 24(sp)
    add  t1, t1, t2
    xor  s0, s0, t1
    rori s0, s0, 24
    ld   ra, 96(t0)
    add  a1, a1, s0
    add  a1, a1, ra
    xor  t2, t2, a1
    rori t2, t2, 16
    sd   t2, 32(sp)
    add  t1, t1, t2
    sd   t1, 24(sp)
    xor  s0, s0, t1
    rori s0, s0, 63
    ld   t1, 48(t0)
    add  a2, a2, s1
    add  a2, a2, t1
    ld   t2, 40(sp)
    xor  t2, t2, a2
    rori t2, t2, 32
    ld   t1, 0(sp)
    add  t1, t1, t2
    xor  s1, s1, t1
    rori s1, s1, 24
    ld   ra, 64(t0)
    add  a2, a2, s1
    add  a2, a2, ra
    xor  t2, t2, a2
    rori t2, t2, 16
    sd   t2, 40(sp)
    add  t1, t1, t2
    sd   t1, 0(sp)
    xor  s1, s1, t1
    rori s1, s1, 63
    ld   t1, 24(t0)
    add  a3, a3, a4
    add  a3, a3, t1
    ld   t2, 48(sp)
    xor  t2, t2, a3
    rori t2, t2, 32
    ld   t1, 8(sp)
    add  t1, t1, t2
    xor  a4, a4, t1
    rori a4, a4, 24
    ld   ra, 104(t0)
    add  a3, a3, a4
    add  a3, a3, ra
    xor  t2, t2, a3
    rori t2, t2, 16
    sd   t2, 48(sp)
    add  t1, t1, t2
    sd   t1, 8(sp)
    xor  a4, a4, t1
    rori a4, a4, 63
    // round 5
    ld   t1, 16(t0)
    add  a0, a0, a4
    add  a0, a0, t1
    ld   t2, 32(sp)
    xor  t2, t2, a0
    rori t2, t2, 32
    ld   t1, 0(sp)
    add  t1, t1, t2
    xor  a4, a4, t1
    rori a4, a4, 24
    ld   ra, 96(t0)
    add  a0, a0, a4
    add  a0, a0, ra
    xor  t2, t2, a0
    rori t2, t2, 16
    sd   t2, 32(sp)
    add  t1, t1, t2
    sd   t1, 0(sp)
    xor  a4, a4, t1
    rori a4, a4, 63
    ld   t1, 48(t0)
    add  a1, a1, a5
    add  a1, a1, t1
    ld   t2, 40(sp)
    xor  t2, t2, a1
    rori t2, t2, 32
    ld   t1, 8(sp)
    add  t1, t1, t2
    xor  a5, a5, t1
    rori a5, a5, 24
    ld   ra, 80(t0)
    add  a1, a1, a5
    add  a1, a1, ra
    xor  t2, t2, a1
    rori t2, t2, 16
    sd   t2, 40(sp)
    add  t1, t1, t2
    sd   t1, 8(sp)
    xor  a5, a5, t1
    rori a5, a5, 63
    ld   t1, 0(t0)
    add  a2, a2, s0
    add  a2, a2, t1
    ld   t2, 48(sp)
    xor  t2, t2, a2
    rori t2, t2, 32
    ld   t1, 16(sp)
    add  t1, t1, t2
    xor  s0, s0, t1
    rori s0, s0, 24
    ld   ra, 88(t0)
    add  a2, a2, s0
    add  a2, a2, ra
    xor  t2, t2, a2
    rori t2, t2, 16
    sd   t2, 48(sp)
    add  t1, t1, t2
    sd   t1, 16(sp)
    xor  s0, s0, t1
    rori s0, s0, 63
    ld   t1, 64(t0)
    add  a3, a3, s1
    add  a3, a3, t1
    ld   t2, 56(sp)
    xor  t2, t2, a3
    rori t2, t2, 32
    ld   t1, 24(sp)
    add  t1, t1, t2
    xor  s1, s1, t1
    rori s1, s1, 24
    ld   ra, 24(t0)
    add  a3, a3, s1
    add  a3, a3, ra
    xor  t2, t2, a3
    rori t2, t2, 16
    sd   t2, 56(sp)
    add  t1, t1, t2
    sd   t1, 24(sp)
    xor  s1, s1, t1
    rori s1, s1, 63
    ld   t1, 32(t0)
    add  a0, a0, a5
    add  a0, a0, t1
    ld   t2, 56(sp)
    xor  t2, t2, a0
    rori t2, t2, 32
    ld   t1, 16(sp)
    add  t1, t1, t2
    xor  a5, a5, t1
    rori a5, a5, 24
    ld   ra, 104(t0)
    add  a0, a0, a5
    add  a0, a0, ra
    xor  t2, t2, a0
    rori t2, t2, 16
    sd   t2, 56(sp)
    add  t1, t1, t2
    sd   t1, 16(sp)
    xor  a5, a5, t1
    rori a5, a5, 63
    ld   t1, 56(t0)
    add  a1, a1, s0
    add  a1, a1, t1
    ld   t2, 32(sp)
    xor  t2, t2, a1
    rori t2, t2, 32
    ld   t1, 24(sp)
    add  t1, t1, t2
    xor  s0, s0, t1
    rori s0, s0, 24
    ld   ra, 40(t0)
    add  a1, a1, s0
    add  a1, a1, ra
    xor  t2, t2, a1
    rori t2, t2, 16
    sd   t2, 32(sp)
    add  t1, t1, t2
    sd   t1, 24(sp)
    xor  s0, s0, t1
    rori s0, s0, 63
    ld   t1, 120(t0)
    add  a2, a2, s1
    add  a2, a2, t1
    ld   t2, 40(sp)
    xor  t2, t2, a2
    rori t2, t2, 32
    ld   t1, 0(sp)
    add  t1, t1, t2
    xor  s1, s1, t1
    rori s1, s1, 24
    ld   ra, 112(t0)
    add  a2, a2, s1
    add  a2, a2, ra
    xor  t2, t2, a2
    rori t2, t2, 16
    sd   t2, 40(sp)
    add  t1, t1, t2
    sd   t1, 0(sp)
    xor  s1, s1, t1
    rori s1, s1, 63
    ld   t1, 8(t0)
    add  a3, a3, a4
    add  a3, a3, t1
    ld   t2, 48(sp)
    xor  t2, t2, a3
    rori t2, t2, 32
    ld   t1, 8(sp)
    add  t1, t1, t2
    xor  a4, a4, t1
    rori a4, a4, 24
    ld   ra, 72(t0)
    add  a3, a3, a4
    add  a3, a3, ra
    xor  t2, t2, a3
    rori t2, t2, 16
    sd   t2, 48(sp)
    add  t1, t1, t2
    sd   t1, 8(sp)
    xor  a4, a4, t1
    rori a4, a4, 63
    // round 6
    ld   t1, 96(t0)
    add  a0, a0, a4
    add  a0, a0, t1
    ld   t2, 32(sp)
    xor  t2, t2, a0
    rori t2, t2, 32
    ld   t1, 0(sp)
    add  t1, t1, t2
    xor  a4, a4, t1
    rori a4, a4, 24
    ld   ra, 40(t0)
    add  a0, a0, a4
    add  a0, a0, ra
    xor  t2, t2, a0
    rori t2, t2, 16
    sd   t2, 32(sp)
    add  t1, t1, t2
    sd   t1, 0(sp)
    xor  a4, a4, t1
    rori a4, a4, 63
    ld   t1, 8(t0)
    add  a1, a1, a5
    add  a1, a1, t1
    ld   t2, 40(sp)
    xor  t2, t2, a1
    rori t2, t2, 32
    ld   t1, 8(sp)
    add  t1, t1, t2
    xor  a5, a5, t1
    rori a5, a5, 24
    ld   ra, 120(t0)
    add  a1, a1, a5
    add  a1, a1, ra
    xor  t2, t2, a1
    rori t2, t2, 16
    sd   t2, 40(sp)
    add  t1, t1, t2
    sd   t1, 8(sp)
    xor  a5, a5, t1
    rori a5, a5, 63
    ld   t1, 112(t0)
    add  a2, a2, s0
    add  a2, a2, t1
    ld   t2, 48(sp)
    xor  t2, t2, a2
    rori t2, t2, 32
    ld   t1, 16(sp)
    add  t1, t1, t2
    xor  s0, s0, t1
    rori s0, s0, 24
    ld   ra, 104(t0)
    add  a2, a2, s0
    add  a2, a2, ra
    xor  t2, t2, a2
    rori t2, t2, 16
    sd   t2, 48(sp)
    add  t1, t1, t2
    sd   t1, 16(sp)
    xor  s0, s0, t1
    rori s0, s0, 63
    ld   t1, 32(t0)
    add  a3, a3, s1
    add  a3, a3, t1
    ld   t2, 56(sp)
    xor  t2, t2, a3
    rori t2, t2, 32
    ld   t1, 24(sp)
    add  t1, t1, t2
    xor  s1, s1, t1
    rori s1, s1, 24
    ld   ra, 80(t0)
    add  a3, a3, s1
    add  a3, a3, ra
    xor  t2, t2, a3
    rori t2, t2, 16
    sd   t2, 56(sp)
    add  t1, t1, t2
    sd   t1, 24(sp)
    xor  s1, s1, t1
    rori s1, s1, 63
    ld   t1, 0(t0)
    add  a0, a0, a5
    add  a0, a0, t1
    ld   t2, 56(sp)
    xor  t2, t2, a0
    rori t2, t2, 32
    ld   t1, 16(sp)
    add  t1, t1, t2
    xor  a5, a5, t1
    rori a5, a5, 24
    ld   ra, 56(t0)
    add  a0, a0, a5
    add  a0, a0, ra
    xor  t2, t2, a0
    rori t2, t2, 16
    sd   t2, 56(sp)
    add  t1, t1, t2
    sd   t1, 16(sp)
    xor  a5, a5, t1
    rori a5, a5, 63
    ld   t1, 48(t0)
    add  a1, a1, s0
    add  a1, a1, t1
    ld   t2, 32(sp)
    xor  t2, t2, a1
    rori t2, t2, 32
    ld   t1, 24(sp)
    add  t1, t1, t2
    xor  s0, s0, t1
    rori s0, s0, 24
    ld   ra, 24(t0)
    add  a1, a1, s0
    add  a1, a1, ra
    xor  t2, t2, a1
    rori t2, t2, 16
    sd   t2, 32(sp)
    add  t1, t1, t2
    sd   t1, 24(sp)
    xor  s0, s0, t1
    rori s0, s0, 63
    ld   t1, 72(t0)
    add  a2, a2, s1
    add  a2, a2, t1
    ld   t2, 40(sp)
    xor  t2, t2, a2
    rori t2, t2, 32
    ld   t1, 0(sp)
    add  t1, t1, t2
    xor  s1, s1, t1
    rori s1, s1, 24
    ld   ra, 16(t0)
    add  a2, a2, s1
    add  a2, a2, ra
    xor  t2, t2, a2
    rori t2, t2, 16
    sd   t2, 40(sp)
    add  t1, t1, t2
    sd   t1, 0(sp)
    xor  s1, s1, t1
    rori s1, s1, 63
    ld   t1, 64(t0)
    add  a3, a3, a4
    add  a3, a3, t1
    ld   t2, 48(sp)
    xor  t2, t2, a3
    rori t2, t2, 32
    ld   t1, 8(sp)
    add  t1, t1, t2
    xor  a4, a4, t1
    rori a4, a4, 24
    ld   ra, 88(t0)
    add  a3, a3, a4
    add  a3, a3, ra
    xor  t2, t2, a3
    rori t2, t2, 16
    sd   t2, 48(sp)
    add  t1, t1, t2
    sd   t1, 8(sp)
    xor  a4, a4, t1
    rori a4, a4, 63
    // round 7
    ld   t1, 104(t0)
    add  a0, a0, a4
    add  a0, a0, t1
    ld   t2, 32(sp)
    xor  t2, t2, a0
    rori t2, t2, 32
    ld   t1, 0(sp)
    add  t1, t1, t2
    xor  a4, a4, t1
    rori a4, a4, 24
    ld   ra, 88(t0)
    add  a0, a0, a4
    add  a0, a0, ra
    xor  t2, t2, a0
    rori t2, t2, 16
    sd   t2, 32(sp)
    add  t1, t1, t2
    sd   t1, 0(sp)
    xor  a4, a4, t1
    rori a4, a4, 63
    ld   t1, 56(t0)
    add  a1, a1, a5
    add  a1, a1, t1
    ld   t2, 40(sp)
    xor  t2, t2, a1
    rori t2, t2, 32
    ld   t1, 8(sp)
    add  t1, t1, t2
    xor  a5, a5, t1
    rori a5, a5, 24
    ld   ra, 112(t0)
    add  a1, a1, a5
    add  a1, a1, ra
    xor  t2, t2, a1
    rori t2, t2, 16
    sd   t2, 40(sp)
    add  t1, t1, t2
    sd   t1, 8(sp)
    xor  a5, a5, t1
    rori a5, a5, 63
    ld   t1, 96(t0)
    add  a2, a2, s0
    add  a2, a2, t1
    ld   t2, 48(sp)
    xor  t2, t2, a2
    rori t2, t2, 32
    ld   t1, 16(sp)
    add  t1, t1, t2
    xor  s0, s0, t1
    rori s0, s0, 24
    ld   ra, 8(t0)
    add  a2, a2, s0
    add  a2, a2, ra
    xor  t2, t2, a2
    rori t2, t2, 16
    sd   t2, 48(sp)
    add  t1, t1, t2
    sd   t1, 16(sp)
    xor  s0, s0, t1
    rori s0, s0, 63
    ld   t1, 24(t0)
    add  a3, a3, s1
    add  a3, a3, t1
    ld   t2, 56(sp)
    xor  t2, t2, a3
    rori t2, t2, 32
    ld   t1, 24(sp)
    add  t1, t1, t2
    xor  s1, s1, t1
    rori s1, s1, 24
    ld   ra, 72(t0)
    add  a3, a3, s1
    add  a3, a3, ra
    xor  t2, t2, a3
    rori t2, t2, 16
    sd   t2, 56(sp)
    add  t1, t1, t2
    sd   t1, 24(sp)
    xor  s1, s1, t1
    rori s1, s1, 63
    ld   t1, 40(t0)
    add  a0, a0, a5
    add  a0, a0, t1
    ld   t2, 56(sp)
    xor  t2, t2, a0
    rori t2, t2, 32
    ld   t1, 16(sp)
    add  t1, t1, t2
    xor  a5, a5, t1
    rori a5, a5, 24
    ld   ra, 0(t0)
    add  a0, a0, a5
    add  a0, a0, ra
    xor  t2, t2, a0
    rori t2, t2, 16
    sd   t2, 56(sp)
    add  t1, t1, t2
    sd   t1, 16(sp)
    xor  a5, a5, t1
    rori a5, a5, 63
    ld   t1, 120(t0)
    add  a1, a1, s0
    add  a1, a1, t1
    ld   t2, 32(sp)
    xor  t2, t2, a1
    rori t2, t2, 32
    ld   t1, 24(sp)
    add  t1, t1, t2
    xor  s0, s0, t1
    rori s0, s0, 24
    ld   ra, 32(t0)
    add  a1, a1, s0
    add  a1, a1, ra
    xor  t2, t2, a1
    rori t2, t2, 16
    sd   t2, 32(sp)
    add  t1, t1, t2
    sd   t1, 24(sp)
    xor  s0, s0, t1
    rori s0, s0, 63
    ld   t1, 64(t0)
    add  a2, a2, s1
    add  a2, a2, t1
    ld   t2, 40(sp)
    xor  t2, t2, a2
    rori t2, t2, 32
    ld   t1, 0(sp)
    add  t1, t1, t2
    xor  s1, s1, t1
    rori s1, s1, 24
    ld   ra, 48(t0)
    add  a2, a2, s1
    add  a2, a2, ra
    xor  t2, t2, a2
    rori t2, t2, 16
    sd   t2, 40(sp)
    add  t1, t1, t2
    sd   t1, 0(sp)
    xor  s1, s1, t1
    rori s1, s1, 63
    ld   t1, 16(t0)
    add  a3, a3, a4
    add  a3, a3, t1
    ld   t2, 48(sp)
    xor  t2, t2, a3
    rori t2, t2, 32
    ld   t1, 8(sp)
    add  t1, t1, t2
    xor  a4, a4, t1
    rori a4, a4, 24
    ld   ra, 80(t0)
    add  a3, a3, a4
    add  a3, a3, ra
    xor  t2, t2, a3
    rori t2, t2, 16
    sd   t2, 48(sp)
    add  t1, t1, t2
    sd   t1, 8(sp)
    xor  a4, a4, t1
    rori a4, a4, 63
    // round 8
    ld   t1, 48(t0)
    add  a0, a0, a4
    add  a0, a0, t1
    ld   t2, 32(sp)
    xor  t2, t2, a0
    rori t2, t2, 32
    ld   t1, 0(sp)
    add  t1, t1, t2
    xor  a4, a4, t1
    rori a4, a4, 24
    ld   ra, 120(t0)
    add  a0, a0, a4
    add  a0, a0, ra
    xor  t2, t2, a0
    rori t2, t2, 16
    sd   t2, 32(sp)
    add  t1, t1, t2
    sd   t1, 0(sp)
    xor  a4, a4, t1
    rori a4, a4, 63
    ld   t1, 112(t0)
    add  a1, a1, a5
    add  a1, a1, t1
    ld   t2, 40(sp)
    xor  t2, t2, a1
    rori t2, t2, 32
    ld   t1, 8(sp)
    add  t1, t1, t2
    xor  a5, a5, t1
    rori a5, a5, 24
    ld   ra, 72(t0)
    add  a1, a1, a5
    add  a1, a1, ra
    xor  t2, t2, a1
    rori t2, t2, 16
    sd   t2, 40(sp)
    add  t1, t1, t2
    sd   t1, 8(sp)
    xor  a5, a5, t1
    rori a5, a5, 63
    ld   t1, 88(t0)
    add  a2, a2, s0
    add  a2, a2, t1
    ld   t2, 48(sp)
    xor  t2, t2, a2
    rori t2, t2, 32
    ld   t1, 16(sp)
    add  t1, t1, t2
    xor  s0, s0, t1
    rori s0, s0, 24
    ld   ra, 24(t0)
    add  a2, a2, s0
    add  a2, a2, ra
    xor  t2, t2, a2
    rori t2, t2, 16
    sd   t2, 48(sp)
    add  t1, t1, t2
    sd   t1, 16(sp)
    xor  s0, s0, t1
    rori s0, s0, 63
    ld   t1, 0(t0)
    add  a3, a3, s1
    add  a3, a3, t1
    ld   t2, 56(sp)
    xor  t2, t2, a3
    rori t2, t2, 32
    ld   t1, 24(sp)
    add  t1, t1, t2
    xor  s1, s1, t1
    rori s1, s1, 24
    ld   ra, 64(t0)
    add  a3, a3, s1
    add  a3, a3, ra
    xor  t2, t2, a3
    rori t2, t2, 16
    sd   t2, 56(sp)
    add  t1, t1, t2
    sd   t1, 24(sp)
    xor  s1, s1, t1
    rori s1, s1, 63
    ld   t1, 96(t0)
    add  a0, a0, a5
    add  a0, a0, t1
    ld   t2, 56(sp)
    xor  t2, t2, a0
    rori t2, t2, 32
    ld   t1, 16(sp)
    add  t1, t1, t2
    xor  a5, a5, t1
    rori a5, a5, 24
    ld   ra, 16(t0)
    add  a0, a0, a5
    add  a0, a0, ra
    xor  t2, t2, a0
    rori t2, t2, 16
    sd   t2, 56(sp)
    add  t1, t1, t2
    sd   t1, 16(sp)
    xor  a5, a5, t1
    rori a5, a5, 63
    ld   t1, 104(t0)
    add  a1, a1, s0
    add  a1, a1, t1
    ld   t2, 32(sp)
    xor  t2, t2, a1
    rori t2, t2, 32
    ld   t1, 24(sp)
    add  t1, t1, t2
    xor  s0, s0, t1
    rori s0, s0, 24
    ld   ra, 56(t0)
    add  a1, a1, s0
    add  a1, a1, ra
    xor  t2, t2, a1
    rori t2, t2, 16
    sd   t2, 32(sp)
    add  t1, t1, t2
    sd   t1, 24(sp)
    xor  s0, s0, t1
    rori s0, s0, 63
    ld   t1, 8(t0)
    add  a2, a2, s1
    add  a2, a2, t1
    ld   t2, 40(sp)
    xor  t2, t2, a2
    rori t2, t2, 32
    ld   t1, 0(sp)
    add  t1, t1, t2
    xor  s1, s1, t1
    rori s1, s1, 24
    ld   ra, 32(t0)
    add  a2, a2, s1
    add  a2, a2, ra
    xor  t2, t2, a2
    rori t2, t2, 16
    sd   t2, 40(sp)
    add  t1, t1, t2
    sd   t1, 0(sp)
    xor  s1, s1, t1
    rori s1, s1, 63
    ld   t1, 80(t0)
    add  a3, a3, a4
    add  a3, a3, t1
    ld   t2, 48(sp)
    xor  t2, t2, a3
    rori t2, t2, 32
    ld   t1, 8(sp)
    add  t1, t1, t2
    xor  a4, a4, t1
    rori a4, a4, 24
    ld   ra, 40(t0)
    add  a3, a3, a4
    add  a3, a3, ra
    xor  t2, t2, a3
    rori t2, t2, 16
    sd   t2, 48(sp)
    add  t1, t1, t2
    sd   t1, 8(sp)
    xor  a4, a4, t1
    rori a4, a4, 63
    // round 9
    ld   t1, 80(t0)
    add  a0, a0, a4
    add  a0, a0, t1
    ld   t2, 32(sp)
    xor  t2, t2, a0
    rori t2, t2, 32
    ld   t1, 0(sp)
    add  t1, t1, t2
    xor  a4, a4, t1
    rori a4, a4, 24
    ld   ra, 16(t0)
    add  a0, a0, a4
    add  a0, a0, ra
    xor  t2, t2, a0
    rori t2, t2, 16
    sd   t2, 32(sp)
    add  t1, t1, t2
    sd   t1, 0(sp)
    xor  a4, a4, t1
    rori a4, a4, 63
    ld   t1, 64(t0)
    add  a1, a1, a5
    add  a1, a1, t1
    ld   t2, 40(sp)
    xor  t2, t2, a1
    rori t2, t2, 32
    ld   t1, 8(sp)
    add  t1, t1, t2
    xor  a5, a5, t1
    rori a5, a5, 24
    ld   ra, 32(t0)
    add  a1, a1, a5
    add  a1, a1, ra
    xor  t2, t2, a1
    rori t2, t2, 16
    sd   t2, 40(sp)
    add  t1, t1, t2
    sd   t1, 8(sp)
    xor  a5, a5, t1
    rori a5, a5, 63
    ld   t1, 56(t0)
    add  a2, a2, s0
    add  a2, a2, t1
    ld   t2, 48(sp)
    xor  t2, t2, a2
    rori t2, t2, 32
    ld   t1, 16(sp)
    add  t1, t1, t2
    xor  s0, s0, t1
    rori s0, s0, 24
    ld   ra, 48(t0)
    add  a2, a2, s0
    add  a2, a2, ra
    xor  t2, t2, a2
    rori t2, t2, 16
    sd   t2, 48(sp)
    add  t1, t1, t2
    sd   t1, 16(sp)
    xor  s0, s0, t1
    rori s0, s0, 63
    ld   t1, 8(t0)
    add  a3, a3, s1
    add  a3, a3, t1
    ld   t2, 56(sp)
    xor  t2, t2, a3
    rori t2, t2, 32
    ld   t1, 24(sp)
    add  t1, t1, t2
    xor  s1, s1, t1
    rori s1, s1, 24
    ld   ra, 40(t0)
    add  a3, a3, s1
    add  a3, a3, ra
    xor  t2, t2, a3
    rori t2, t2, 16
    sd   t2, 56(sp)
    add  t1, t1, t2
    sd   t1, 24(sp)
    xor  s1, s1, t1
    rori s1, s1, 63
    ld   t1, 120(t0)
    add  a0, a0, a5
    add  a0, a0, t1
    ld   t2, 56(sp)
    xor  t2, t2, a0
    rori t2, t2, 32
    ld   t1, 16(sp)
    add  t1, t1, t2
    xor  a5, a5, t1
    rori a5, a5, 24
    ld   ra, 88(t0)
    add  a0, a0, a5
    add  a0, a0, ra
    xor  t2, t2, a0
    rori t2, t2, 16
    sd   t2, 56(sp)
    add  t1, t1, t2
    sd   t1, 16(sp)
    xor  a5, a5, t1
    rori a5, a5, 63
    ld   t1, 72(t0)
    add  a1, a1, s0
    add  a1, a1, t1
    ld   t2, 32(sp)
    xor  t2, t2, a1
    rori t2, t2, 32
    ld   t1, 24(sp)
    add  t1, t1, t2
    xor  s0, s0, t1
    rori s0, s0, 24
    ld   ra, 112(t0)
    add  a1, a1, s0
    add  a1, a1, ra
    xor  t2, t2, a1
    rori t2, t2, 16
    sd   t2, 32(sp)
    add  t1, t1, t2
    sd   t1, 24(sp)
    xor  s0, s0, t1
    rori s0, s0, 63
    ld   t1, 24(t0)
    add  a2, a2, s1
    add  a2, a2, t1
    ld   t2, 40(sp)
    xor  t2, t2, a2
    rori t2, t2, 32
    ld   t1, 0(sp)
    add  t1, t1, t2
    xor  s1, s1, t1
    rori s1, s1, 24
    ld   ra, 96(t0)
    add  a2, a2, s1
    add  a2, a2, ra
    xor  t2, t2, a2
    rori t2, t2, 16
    sd   t2, 40(sp)
    add  t1, t1, t2
    sd   t1, 0(sp)
    xor  s1, s1, t1
    rori s1, s1, 63
    ld   t1, 104(t0)
    add  a3, a3, a4
    add  a3, a3, t1
    ld   t2, 48(sp)
    xor  t2, t2, a3
    rori t2, t2, 32
    ld   t1, 8(sp)
    add  t1, t1, t2
    xor  a4, a4, t1
    rori a4, a4, 24
    ld   ra, 0(t0)
    add  a3, a3, a4
    add  a3, a3, ra
    xor  t2, t2, a3
    rori t2, t2, 16
    sd   t2, 48(sp)
    add  t1, t1, t2
    sd   t1, 8(sp)
    xor  a4, a4, t1
    rori a4, a4, 63
    // round 10
    ld   t1, 0(t0)
    add  a0, a0, a4
    add  a0, a0, t1
    ld   t2, 32(sp)
    xor  t2, t2, a0
    rori t2, t2, 32
    ld   t1, 0(sp)
    add  t1, t1, t2
    xor  a4, a4, t1
    rori a4, a4, 24
    ld   ra, 8(t0)
    add  a0, a0, a4
    add  a0, a0, ra
    xor  t2, t2, a0
    rori t2, t2, 16
    sd   t2, 32(sp)
    add  t1, t1, t2
    sd   t1, 0(sp)
    xor  a4, a4, t1
    rori a4, a4, 63
    ld   t1, 16(t0)
    add  a1, a1, a5
    add  a1, a1, t1
    ld   t2, 40(sp)
    xor  t2, t2, a1
    rori t2, t2, 32
    ld   t1, 8(sp)
    add  t1, t1, t2
    xor  a5, a5, t1
    rori a5, a5, 24
    ld   ra, 24(t0)
    add  a1, a1, a5
    add  a1, a1, ra
    xor  t2, t2, a1
    rori t2, t2, 16
    sd   t2, 40(sp)
    add  t1, t1, t2
    sd   t1, 8(sp)
    xor  a5, a5, t1
    rori a5, a5, 63
    ld   t1, 32(t0)
    add  a2, a2, s0
    add  a2, a2, t1
    ld   t2, 48(sp)
    xor  t2, t2, a2
    rori t2, t2, 32
    ld   t1, 16(sp)
    add  t1, t1, t2
    xor  s0, s0, t1
    rori s0, s0, 24
    ld   ra, 40(t0)
    add  a2, a2, s0
    add  a2, a2, ra
    xor  t2, t2, a2
    rori t2, t2, 16
    sd   t2, 48(sp)
    add  t1, t1, t2
    sd   t1, 16(sp)
    xor  s0, s0, t1
    rori s0, s0, 63
    ld   t1, 48(t0)
    add  a3, a3, s1
    add  a3, a3, t1
    ld   t2, 56(sp)
    xor  t2, t2, a3
    rori t2, t2, 32
    ld   t1, 24(sp)
    add  t1, t1, t2
    xor  s1, s1, t1
    rori s1, s1, 24
    ld   ra, 56(t0)
    add  a3, a3, s1
    add  a3, a3, ra
    xor  t2, t2, a3
    rori t2, t2, 16
    sd   t2, 56(sp)
    add  t1, t1, t2
    sd   t1, 24(sp)
    xor  s1, s1, t1
    rori s1, s1, 63
    ld   t1, 64(t0)
    add  a0, a0, a5
    add  a0, a0, t1
    ld   t2, 56(sp)
    xor  t2, t2, a0
    rori t2, t2, 32
    ld   t1, 16(sp)
    add  t1, t1, t2
    xor  a5, a5, t1
    rori a5, a5, 24
    ld   ra, 72(t0)
    add  a0, a0, a5
    add  a0, a0, ra
    xor  t2, t2, a0
    rori t2, t2, 16
    sd   t2, 56(sp)
    add  t1, t1, t2
    sd   t1, 16(sp)
    xor  a5, a5, t1
    rori a5, a5, 63
    ld   t1, 80(t0)
    add  a1, a1, s0
    add  a1, a1, t1
    ld   t2, 32(sp)
    xor  t2, t2, a1
    rori t2, t2, 32
    ld   t1, 24(sp)
    add  t1, t1, t2
    xor  s0, s0, t1
    rori s0, s0, 24
    ld   ra, 88(t0)
    add  a1, a1, s0
    add  a1, a1, ra
    xor  t2, t2, a1
    rori t2, t2, 16
    sd   t2, 32(sp)
    add  t1, t1, t2
    sd   t1, 24(sp)
    xor  s0, s0, t1
    rori s0, s0, 63
    ld   t1, 96(t0)
    add  a2, a2, s1
    add  a2, a2, t1
    ld   t2, 40(sp)
    xor  t2, t2, a2
    rori t2, t2, 32
    ld   t1, 0(sp)
    add  t1, t1, t2
    xor  s1, s1, t1
    rori s1, s1, 24
    ld   ra, 104(t0)
    add  a2, a2, s1
    add  a2, a2, ra
    xor  t2, t2, a2
    rori t2, t2, 16
    sd   t2, 40(sp)
    add  t1, t1, t2
    sd   t1, 0(sp)
    xor  s1, s1, t1
    rori s1, s1, 63
    ld   t1, 112(t0)
    add  a3, a3, a4
    add  a3, a3, t1
    ld   t2, 48(sp)
    xor  t2, t2, a3
    rori t2, t2, 32
    ld   t1, 8(sp)
    add  t1, t1, t2
    xor  a4, a4, t1
    rori a4, a4, 24
    ld   ra, 120(t0)
    add  a3, a3, a4
    add  a3, a3, ra
    xor  t2, t2, a3
    rori t2, t2, 16
    sd   t2, 48(sp)
    add  t1, t1, t2
    sd   t1, 8(sp)
    xor  a4, a4, t1
    rori a4, a4, 63
    // round 11
    ld   t1, 112(t0)
    add  a0, a0, a4
    add  a0, a0, t1
    ld   t2, 32(sp)
    xor  t2, t2, a0
    rori t2, t2, 32
    ld   t1, 0(sp)
    add  t1, t1, t2
    xor  a4, a4, t1
    rori a4, a4, 24
    ld   ra, 80(t0)
    add  a0, a0, a4
    add  a0, a0, ra
    xor  t2, t2, a0
    rori t2, t2, 16
    sd   t2, 32(sp)
    add  t1, t1, t2
    sd   t1, 0(sp)
    xor  a4, a4, t1
    rori a4, a4, 63
    ld   t1, 32(t0)
    add  a1, a1, a5
    add  a1, a1, t1
    ld   t2, 40(sp)
    xor  t2, t2, a1
    rori t2, t2, 32
    ld   t1, 8(sp)
    add  t1, t1, t2
    xor  a5, a5, t1
    rori a5, a5, 24
    ld   ra, 64(t0)
    add  a1, a1, a5
    add  a1, a1, ra
    xor  t2, t2, a1
    rori t2, t2, 16
    sd   t2, 40(sp)
    add  t1, t1, t2
    sd   t1, 8(sp)
    xor  a5, a5, t1
    rori a5, a5, 63
    ld   t1, 72(t0)
    add  a2, a2, s0
    add  a2, a2, t1
    ld   t2, 48(sp)
    xor  t2, t2, a2
    rori t2, t2, 32
    ld   t1, 16(sp)
    add  t1, t1, t2
    xor  s0, s0, t1
    rori s0, s0, 24
    ld   ra, 120(t0)
    add  a2, a2, s0
    add  a2, a2, ra
    xor  t2, t2, a2
    rori t2, t2, 16
    sd   t2, 48(sp)
    add  t1, t1, t2
    sd   t1, 16(sp)
    xor  s0, s0, t1
    rori s0, s0, 63
    ld   t1, 104(t0)
    add  a3, a3, s1
    add  a3, a3, t1
    ld   t2, 56(sp)
    xor  t2, t2, a3
    rori t2, t2, 32
    ld   t1, 24(sp)
    add  t1, t1, t2
    xor  s1, s1, t1
    rori s1, s1, 24
    ld   ra, 48(t0)
    add  a3, a3, s1
    add  a3, a3, ra
    xor  t2, t2, a3
    rori t2, t2, 16
    sd   t2, 56(sp)
    add  t1, t1, t2
    sd   t1, 24(sp)
    xor  s1, s1, t1
    rori s1, s1, 63
    ld   t1, 8(t0)
    add  a0, a0, a5
    add  a0, a0, t1
    ld   t2, 56(sp)
    xor  t2, t2, a0
    rori t2, t2, 32
    ld   t1, 16(sp)
    add  t1, t1, t2
    xor  a5, a5, t1
    rori a5, a5, 24
    ld   ra, 96(t0)
    add  a0, a0, a5
    add  a0, a0, ra
    xor  t2, t2, a0
    rori t2, t2, 16
    sd   t2, 56(sp)
    add  t1, t1, t2
    sd   t1, 16(sp)
    xor  a5, a5, t1
    rori a5, a5, 63
    ld   t1, 0(t0)
    add  a1, a1, s0
    add  a1, a1, t1
    ld   t2, 32(sp)
    xor  t2, t2, a1
    rori t2, t2, 32
    ld   t1, 24(sp)
    add  t1, t1, t2
    xor  s0, s0, t1
    rori s0, s0, 24
    ld   ra, 16(t0)
    add  a1, a1, s0
    add  a1, a1, ra
    xor  t2, t2, a1
    rori t2, t2, 16
    sd   t2, 32(sp)
    add  t1, t1, t2
    sd   t1, 24(sp)
    xor  s0, s0, t1
    rori s0, s0, 63
    ld   t1, 88(t0)
    add  a2, a2, s1
    add  a2, a2, t1
    ld   t2, 40(sp)
    xor  t2, t2, a2
    rori t2, t2, 32
    ld   t1, 0(sp)
    add  t1, t1, t2
    xor  s1, s1, t1
    rori s1, s1, 24
    ld   ra, 56(t0)
    add  a2, a2, s1
    add  a2, a2, ra
    xor  t2, t2, a2
    rori t2, t2, 16
    sd   t2, 40(sp)
    add  t1, t1, t2
    sd   t1, 0(sp)
    xor  s1, s1, t1
    rori s1, s1, 63
    ld   t1, 40(t0)
    add  a3, a3, a4
    add  a3, a3, t1
    ld   t2, 48(sp)
    xor  t2, t2, a3
    rori t2, t2, 32
    ld   t1, 8(sp)
    add  t1, t1, t2
    xor  a4, a4, t1
    rori a4, a4, 24
    ld   ra, 24(t0)
    add  a3, a3, a4
    add  a3, a3, ra
    xor  t2, t2, a3
    rori t2, t2, 16
    sd   t2, 48(sp)
    add  t1, t1, t2
    sd   t1, 8(sp)
    xor  a4, a4, t1
    rori a4, a4, 63
    // h ^= v[0..7] ^ v[8..15]; the result stays pinned for the next block
    ld   t1, 128(sp)
    ld   t2, 0(sp)
    xor  a0, a0, t1
    xor  a0, a0, t2
    ld   t1, 136(sp)
    ld   t2, 8(sp)
    xor  a1, a1, t1
    xor  a1, a1, t2
    ld   t1, 144(sp)
    ld   t2, 16(sp)
    xor  a2, a2, t1
    xor  a2, a2, t2
    ld   t1, 152(sp)
    ld   t2, 24(sp)
    xor  a3, a3, t1
    xor  a3, a3, t2
    ld   t1, 160(sp)
    ld   t2, 32(sp)
    xor  a4, a4, t1
    xor  a4, a4, t2
    ld   t1, 168(sp)
    ld   t2, 40(sp)
    xor  a5, a5, t1
    xor  a5, a5, t2
    ld   t1, 176(sp)
    ld   t2, 48(sp)
    xor  s0, s0, t1
    xor  s0, s0, t2
    ld   t1, 184(sp)
    ld   t2, 56(sp)
    xor  s1, s1, t1
    xor  s1, s1, t2
    // next block
    addi t0, t0, 128
    ld   t1, 200(sp)
    addi t1, t1, -1
    sd   t1, 200(sp)
    beqz t1, .Ldone
    j    .Lblock
.Ldone:
    ld   t1, 208(sp)
    sd   a0, 0(t1)
    sd   a1, 8(t1)
    sd   a2, 16(t1)
    sd   a3, 24(t1)
    sd   a4, 32(t1)
    sd   a5, 40(t1)
    sd   s0, 48(t1)
    sd   s1, 56(t1)
    ld   ra, 216(sp)
    ld   s0, 224(sp)
    ld   s1, 232(sp)
    addi sp, sp, 240
    ret
