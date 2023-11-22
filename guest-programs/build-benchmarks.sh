#!/bin/bash

set -euo pipefail

function build_benchmark() {
    current_dir=$(pwd)
    extra_flags="${extra_flags:-}"

    echo "> Building: '$1' (polkavm)"
    RUSTFLAGS="-C relocation-model=pie -C link-arg=--emit-relocs -C link-arg=-T.cargo/memory.ld $extra_flags" cargo build -q --release --bin $1 -p $1
    cd ..
    cargo run -q -p polkatool link guest-programs/target/riscv32em-unknown-none-elf/release/$1 -o guest-programs/target/riscv32em-unknown-none-elf/release/$1.polkavm
    cd $current_dir

    echo "> Building: '$1' (wasm)"
    RUSTFLAGS="-C target-cpu=mvp -C target-feature=-sign-ext $extra_flags" rustup run 1.72.1 cargo build -q --target=wasm32-unknown-unknown --release --bin $1 -p $1

    echo "> Building: '$1' (native, x86_64)"
    RUSTFLAGS="$extra_flags" rustup run 1.72.1 cargo build -q --target=x86_64-unknown-linux-gnu --release --lib -p $1

    echo "> Building: '$1' (native, i686)"
    RUSTFLAGS="$extra_flags" rustup run 1.72.1 cargo build -q --target=i686-unknown-linux-gnu --release --lib -p $1

    echo "> Building: '$1' (CKB VM)"
    RUSTFLAGS="$extra_flags -C link-arg=-s --cfg=target_ckb_vm" rustup run 1.72.1 cargo build -q --target=riscv64imac-unknown-none-elf --release --bin $1 -p $1
}

build_benchmark "bench-pinky"
build_benchmark "bench-prime-sieve"
