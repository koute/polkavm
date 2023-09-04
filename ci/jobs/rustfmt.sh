#!/bin/bash

set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
cd ../..

echo ">> cargo fmt"
cargo fmt --check --all

echo ">> cargo fmt (zygote)"
cd crates/polkavm-zygote
cargo fmt --check --all
cd ../..

if [ "${CI_RV32E_TOOLCHAIN_AVAILABLE:-}" == 1 ]; then
    echo ">> cargo fmt (example guests)"
    cd examples/guests
    cargo fmt --check --all
    cd ../..
fi
