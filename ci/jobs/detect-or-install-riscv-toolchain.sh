#!/bin/bash

set -euo pipefail

case "$OSTYPE" in
  linux*)
    if [[ "$(rustup toolchain list)" =~ "riscv32em-nightly-2024-01-05-r0-x86_64-unknown-linux-gnu" ]]; then
        export RV32E_TOOLCHAIN="riscv32em-nightly-2024-01-05-r0-x86_64-unknown-linux-gnu"
    else
        curl -L --output /tmp/rust-riscv32em-nightly-2024-01-05-r0-x86_64-unknown-linux-gnu.tar.xz "https://github.com/koute/rustc-rv32e/releases/download/nightly-2024-01-05-r0/rust-riscv32em-nightly-2024-01-05-r0-x86_64-unknown-linux-gnu.tar.xz"
        tar -C /tmp -xf /tmp/rust-riscv32em-nightly-2024-01-05-r0-x86_64-unknown-linux-gnu.tar.xz
        mkdir -p ~/.rustup/toolchains
        mv /tmp/rust-riscv32em-x86_64-unknown-linux-gnu/riscv32em-nightly-2024-01-05-r0-x86_64-unknown-linux-gnu ~/.rustup/toolchains/
        export RV32E_TOOLCHAIN="riscv32em-nightly-2024-01-05-r0-x86_64-unknown-linux-gnu"
    fi
  ;;
esac
