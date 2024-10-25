#!/usr/bin/env bash

set -euo pipefail

cd "${0%/*}/"
cd ../..

echo ">> cargo clippy"
RUSTFLAGS="-D warnings" cargo clippy --all

echo ">> cargo clippy (zygote)"
cd crates/polkavm-zygote
RUSTFLAGS="-D warnings" cargo clippy --all
cd ../..

echo ">> cargo clippy (guests)"

cd guest-programs
RUSTFLAGS="-D warnings" \
cargo clippy  \
    -Z build-std=core,alloc \
    --target "$PWD/riscv32emac-unknown-none-polkavm.json" \
    --all

cd ../..
