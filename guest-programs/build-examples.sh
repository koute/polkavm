#!/bin/bash

set -euo pipefail

function build_example () {
    output_path="output/$1.polkavm"
    current_dir=$(pwd)

    echo "> Building: '$1' (-> $output_path)"
    RUSTFLAGS="-C relocation-model=pie -C link-arg=--emit-relocs -C link-arg=-T.cargo/memory.ld --remap-path-prefix=$(pwd)= --remap-path-prefix=$HOME=~" cargo build -q --release --bin $1 -p $1
    cd ..
    cargo run -q -p polkatool link -s guest-programs/target/riscv32em-unknown-none-elf/release/$1 -o guest-programs/$output_path
    cd $current_dir
}

build_example "example-hello-world"
