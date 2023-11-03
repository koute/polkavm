#!/bin/bash

set -euo pipefail

function build () {
    output_path="output/$1.polkavm"
    current_dir=$(pwd)

    echo "> Building: '$1' (-> $output_path)"
    cargo build -q --release -p $1
    cd ..
    cargo run -q -p polkatool link -s guest-programs/target/riscv32em-unknown-none-elf/release/$1 -o guest-programs/$output_path
    cd $current_dir
}

build "example-hello-world"
