#!/bin/bash

set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
cd ../..

echo ">> cargo fmt"
cargo fmt --check --all
# https://github.com/rust-lang/rustfmt/issues/3253
cargo fmt --check -- $(find crates/polkavm -name *.rs)

echo ">> cargo fmt (zygote)"
cd crates/polkavm-zygote
cargo fmt --check --all
cd ../..

source ./ci/jobs/detect-or-install-riscv-toolchain.sh
if [ "${RV32E_TOOLCHAIN:-}" != "" ]; then
    echo ">> cargo fmt (guests)"
    cd guest-programs
    rustup run $RV32E_TOOLCHAIN cargo fmt --check --all
    cd ../..
fi
