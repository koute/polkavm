#!/bin/bash

set -euo pipefail

function build () {
    echo "> Building example: '$1'"

    echo ">> Compiling..."
    cargo build --release -p $1-guest

    echo ">> Linking..."
    cd ../..

    output_path="examples/hosts/$1/src/guest.polkavm"
    cargo run -p polkatool link examples/guests/target/riscv32em-unknown-none-elf/release/$1-guest -o $output_path

    echo ">> Program ready in: $(realpath $output_path)"
    stat $output_path | grep -o -E "Size: [0-9]+"

    echo ""
}

build "hello-world"
