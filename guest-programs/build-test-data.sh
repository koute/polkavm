#!/bin/bash

set -euo pipefail

function build_test_data() {
    output_path="../test-data/$1.elf.zst"

    echo "> Building: '$1' (-> $output_path)"
    RUSTFLAGS="-C target-feature=+lui-addi-fusion,+fast-unaligned-access,+xtheadcondmov,+c -C relocation-model=pie -C link-arg=--emit-relocs -C link-arg=--unique --remap-path-prefix=$(pwd)= --remap-path-prefix=$HOME=~" cargo build -q --profile $2 --bin $1 -p $1
    zstd -f -q -19 -o $output_path target/riscv32ema-unknown-none-elf/$2/$1
    chmod -x $output_path
}

build_test_data "bench-pinky" "release"
build_test_data "test-blob" "no-lto"
