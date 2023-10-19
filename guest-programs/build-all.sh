#!/bin/bash

set -euo pipefail

function build () {
    echo "> Building program: '$1'"

    echo ">> Compiling..."
    cargo build --release -p $1

    echo ">> Linking..."
    cd ..

    output_path="guest-programs/output/$1.polkavm"
    cargo run -p polkatool link -s guest-programs/target/riscv32em-unknown-none-elf/release/$1 -o $output_path

    echo ">> Program ready in: $(realpath $output_path)"
    stat $output_path | grep -o -E "Size: [0-9]+"

    echo ""
}

build "example-hello-world"
