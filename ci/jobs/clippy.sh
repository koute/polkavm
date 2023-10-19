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

source ./ci/jobs/detect-or-install-riscv-toolchain.sh
if [ "${RV32E_TOOLCHAIN:-}" != "" ]; then
    echo ">> cargo clippy (guests)"
    cd guest-programs
    RUSTFLAGS="-D warnings" rustup run $RV32E_TOOLCHAIN cargo clippy --all
    cd ../..
fi
