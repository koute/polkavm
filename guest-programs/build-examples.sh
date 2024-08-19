#!/bin/bash

set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"

source ../ci/jobs/detect-or-install-riscv-toolchain.sh

if [ "${RV32E_TOOLCHAIN:-}" == "" ]; then
    echo "ERROR: rv32e toolchain is missing; PolkaVM binaries can't be built!"
    exit 1
fi

function build_example () {
    output_path="output/$1.polkavm"
    current_dir=$(pwd)

    echo "> Building: '$1' (-> $output_path)"
    RUSTFLAGS="-C target-feature=+c -C relocation-model=pie -C link-arg=--emit-relocs -C link-arg=--unique --remap-path-prefix=$(pwd)= --remap-path-prefix=$HOME=~" cargo build -q --release --bin $1 -p $1
    cd ..
    cargo run -q -p polkatool link --run-only-if-newer -s guest-programs/target/riscv32ema-unknown-none-elf/release/$1 -o guest-programs/$output_path
    cd $current_dir
}

build_example "example-hello-world"
