#!/bin/bash

set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"

POLKAVM_CRATES_ROOT="$(pwd)/proxy-crates"

cd ../..

mkdir -p target/test-pallet-revive
cd target/test-pallet-revive

if [ ! -d "polkadot-sdk" ]; then
    git clone --depth 1 "https://github.com/paritytech/polkadot-sdk.git"
fi
cd polkadot-sdk
COMMIT=8c548eb6af3ac277575591a076f4e33b150bdc11
git fetch --depth=1 origin $COMMIT
git checkout $COMMIT

echo '[toolchain]' > rust-toolchain.toml
echo 'channel = "nightly-2024-07-10"' >> rust-toolchain.toml

PALLET_REVIVE_FIXTURES_RUSTUP_TOOLCHAIN=riscv32em-nightly-2024-01-05-r0-x86_64-unknown-linux-gnu \
PALLET_REVIVE_FIXTURES_STRIP=0 \
PALLET_REVIVE_FIXTURES_OPTIMIZE=1 \
cargo test \
    --config "patch.crates-io.polkavm010.path='$POLKAVM_CRATES_ROOT/polkavm010'" --config "patch.crates-io.polkavm010.package='polkavm'" \
    --config "patch.crates-io.polkavm-derive010.path='$POLKAVM_CRATES_ROOT/polkavm-derive010'" --config "patch.crates-io.polkavm-derive010.package='polkavm-derive'" \
    --config "patch.crates-io.polkavm-linker010.path='$POLKAVM_CRATES_ROOT/polkavm-linker010'" --config "patch.crates-io.polkavm-linker010.package='polkavm-linker'" \
    --features riscv -p pallet-revive
