#!/bin/bash

set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
cd ../..

echo ">> cargo clippy"
RUSTFLAGS="-D warnings" cargo clippy --all

echo ">> cargo clippy (zygote)"
cd crates/polkavm-zygote
RUSTFLAGS="-D warnings" cargo clippy --all
cd ../..

if [ "${CI_RV32E_TOOLCHAIN_AVAILABLE:-}" == 1 ]; then
    echo ">> cargo clippy (guests)"
    cd guest-programs
    RUSTFLAGS="-D warnings" cargo clippy --all
    cd ../..
fi
