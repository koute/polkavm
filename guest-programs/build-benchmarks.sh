#!/bin/bash

set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"

source ../ci/jobs/detect-or-install-riscv-toolchain.sh

if [ "${RV32E_TOOLCHAIN:-}" == "" ]; then
    echo "WARN: rv32e toolchain is missing; PolkaVM binaries won't be built!"
fi

TOOLCHAIN_VERSION="1.72.1"

BUILD_WASM=0
BUILD_CKBVM=0
BUILD_NATIVE_X86_64=0
BUILD_NATIVE_X86=0

if [[ "$(rustup toolchain list)" =~ "$TOOLCHAIN_VERSION" ]]; then
    if [[ "$(rustup run $TOOLCHAIN_VERSION rustup target list --installed)" =~ "wasm32-unknown-unknown" ]]; then
        BUILD_WASM=1
    else
        echo "WARN: the wasm32-unknown-unknown target is not installed; WASM binaries won't be built!"
        echo "      You can add it with: rustup run $TOOLCHAIN_VERSION rustup target add wasm32-unknown-unknown"
    fi

    if [[ "$(rustup run $TOOLCHAIN_VERSION rustup target list --installed)" =~ "riscv64imac-unknown-none-elf" ]]; then
        BUILD_CKBVM=1
    else
        echo "WARN: the riscv64imac-unknown-none-elf target is not installed; CKBVM binaries won't be built!"
        echo "      You can add it with: rustup run $TOOLCHAIN_VERSION rustup target add riscv64imac-unknown-none-elf"
    fi

    if [[ "$(rustup run $TOOLCHAIN_VERSION rustc --print cfg)" =~ "target_os=\"linux\"" ]]; then
        if [[ "$(rustup run $TOOLCHAIN_VERSION rustc --print cfg)" =~ "target_arch=\"x86_64\"" ]]; then
            BUILD_NATIVE_X86_64=1
            if [[ "$(rustup run $TOOLCHAIN_VERSION rustup target list --installed)" =~ "i686-unknown-linux-gnu" ]]; then
                BUILD_NATIVE_X86=1
            fi
        fi
    fi
else
    echo "WARN: Rust $TOOLCHAIN_VERSION is not installed; non-PolkaVM binaries won't be built!"
    echo "      You can add it with: rustup toolchain install $TOOLCHAIN_VERSION"
fi

function build_benchmark() {
    current_dir=$(pwd)
    extra_flags="${extra_flags:-}"

    if [ "${RV32E_TOOLCHAIN:-}" != "" ]; then
        echo "> Building: '$1' (polkavm)"
        RUSTFLAGS="-C relocation-model=pie -C link-arg=--emit-relocs -C link-arg=-T.cargo/memory.ld $extra_flags" rustup run $RV32E_TOOLCHAIN cargo build -q --release --bin $1 -p $1
        cd ..
        cargo run -q -p polkatool link --run-only-if-newer guest-programs/target/riscv32em-unknown-none-elf/release/$1 -o guest-programs/target/riscv32em-unknown-none-elf/release/$1.polkavm
        cd $current_dir
    fi

    if [ "${BUILD_WASM}" == "1" ]; then
        echo "> Building: '$1' (wasm)"
        RUSTFLAGS="-C target-cpu=mvp -C target-feature=-sign-ext $extra_flags" rustup run $TOOLCHAIN_VERSION cargo build -q --target=wasm32-unknown-unknown --release --bin $1 -p $1
    fi

    if [ "${BUILD_NATIVE_X86_64}" == "1" ]; then
        echo "> Building: '$1' (native, x86_64)"
        RUSTFLAGS="$extra_flags" rustup run $TOOLCHAIN_VERSION cargo build -q --target=x86_64-unknown-linux-gnu --release --lib -p $1
    fi

    if [ "${BUILD_NATIVE_X86}" == "1" ]; then
        echo "> Building: '$1' (native, i686)"
        RUSTFLAGS="$extra_flags" rustup run $TOOLCHAIN_VERSION cargo build -q --target=i686-unknown-linux-gnu --release --lib -p $1
    fi

    if [ "${BUILD_CKBVM}" == "1" ]; then
        echo "> Building: '$1' (CKB VM)"
        RUSTFLAGS="$extra_flags -C target-feature=+zba,+zbb,+zbc,+zbs -C link-arg=-s --cfg=target_ckb_vm" rustup run $TOOLCHAIN_VERSION cargo build -q --target=riscv64imac-unknown-none-elf --release --bin $1 -p $1
    fi
}

build_benchmark "bench-pinky"
build_benchmark "bench-prime-sieve"
