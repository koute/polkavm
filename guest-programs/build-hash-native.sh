#!/bin/sh

# Builds each hash benchmark's host library in two variants:
#   libbench_<algo>.so        - host portable: runs on any x86-64; crates may
#                               still runtime-dispatch to fast paths (e.g. sha2
#                               uses SHA-NI via cpufeatures when available)
#   libbench_<algo>_native.so - host native: -C target-cpu=native, all ISA
#                               extensions of the BUILD machine enabled
#                               unconditionally
#
# Both land in target/x86_64-unknown-linux-gnu/release/, where benchtool
# auto-discovers them as "<algo>" and "<algo>-native".
#
# WARNING: never copy *_native.so between machines - they are compiled for the
# exact CPU they were built on and will crash (SIGILL) on CPUs lacking any of
# their instruction-set extensions. Always rebuild locally.
#
# Host baselines are toolchain-sensitive - see the note in
# build-benchmarks.sh. Override: NATIVE_TOOLCHAIN="+1.86.0" ./build-hash-native.sh

set -ex
cd "${0%/*}"

native_toolchain="${NATIVE_TOOLCHAIN:-+nightly-2026-08-01}"

out=target/x86_64-unknown-linux-gnu/release

for crate in bench-blake2-128 bench-blake2-256 bench-blake2-256-asm bench-keccak-256 bench-keccak-512 \
             bench-sha2-256 bench-twox-64 bench-twox-128 bench-twox-256; do
    lib=$(echo "$crate" | tr - _)
    RUSTFLAGS="-C target-cpu=native" cargo $native_toolchain build --target=x86_64-unknown-linux-gnu --release --lib -p "$crate"
    cp "$out/lib$lib.so" "$out/lib${lib}_native.so"
done

# Rebuild without the CPU features; overwrites the portable variants.
for crate in bench-blake2-128 bench-blake2-256 bench-blake2-256-asm bench-keccak-256 bench-keccak-512 \
             bench-sha2-256 bench-twox-64 bench-twox-128 bench-twox-256; do
    cargo $native_toolchain build --target=x86_64-unknown-linux-gnu --release --lib -p "$crate"
done
