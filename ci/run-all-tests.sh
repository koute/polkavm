#!/bin/bash

set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
cd ..

source ./ci/jobs/detect-or-install-riscv-toolchain.sh
if [[ "$(rustup toolchain list)" =~ "riscv32em-nightly-2023-04-05-r0-x86_64-unknown-linux-gnu" ]]; then
    export CI_RV32E_TOOLCHAIN_AVAILABLE=1
fi

./ci/jobs/build-guests.sh
./ci/jobs/build-and-test.sh

case "$OSTYPE" in
  linux*)
    ./ci/jobs/build-and-test-linux.sh
    ./ci/jobs/fuzz.sh
  ;;
  darwin*)
    ./ci/jobs/build-and-test-macos.sh
    ./ci/jobs/fuzz.sh
  ;;
esac

./ci/jobs/check-freebsd.sh
./ci/jobs/kani.sh

./ci/jobs/clippy.sh
./ci/jobs/rustfmt.sh

./ci/jobs/build-and-test-pallet-revive.sh

echo "----------------------------------------"
echo "All tests finished!"
