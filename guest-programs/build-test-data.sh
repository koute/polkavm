#!/bin/bash

set -euo pipefail

function build_test_data() {
    output_path="../test-data/$1.elf.zst"

    echo "> Building: '$1' (-> $output_path)"
    RUSTFLAGS="-C relocation-model=pie -C link-arg=--emit-relocs -C link-arg=-T.cargo/memory.ld --remap-path-prefix=$(pwd)= --remap-path-prefix=$HOME=~" cargo build -q --release --bin $1 -p $1
    zstd -f -q -19 -o $output_path target/riscv32em-unknown-none-elf/release/$1
    chmod -x $output_path
}

build_test_data "bench-pinky"
