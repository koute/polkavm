#!/usr/bin/env bash

set -euo pipefail

cd "${0%/*}/"
cd ..

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
