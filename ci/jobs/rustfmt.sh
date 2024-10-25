#!/usr/bin/env bash

set -euo pipefail

cd "${0%/*}/"
cd ../..

echo ">> cargo fmt"
cargo fmt --check --all

echo ">> cargo fmt (zygote)"
cd crates/polkavm-zygote
cargo fmt --check --all
cd ../..

echo ">> cargo fmt (guests)"
cd guest-programs

cargo fmt --check --all

cd ../..
