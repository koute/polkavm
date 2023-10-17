#!/bin/bash

set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
cd ..

if [[ "$(rustup toolchain list)" =~ "rv32e-nightly-2023-04-05-x86_64-unknown-linux-gnu" ]]; then
    export CI_RV32E_TOOLCHAIN_AVAILABLE=1
fi

./ci/jobs/build-guests.sh
./ci/jobs/build-and-test.sh

case "$OSTYPE" in
  linux*)
    ./ci/jobs/build-and-test-linux.sh
  ;;
  darwin*)
    ./ci/jobs/build-and-test-macos.sh
  ;;
esac
./ci/jobs/clippy.sh
./ci/jobs/rustfmt.sh

echo "----------------------------------------"
echo "All tests finished!"
