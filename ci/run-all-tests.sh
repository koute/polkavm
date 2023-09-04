#!/bin/bash

set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
cd ..

./ci/jobs/build-and-test.sh

case "$OSTYPE" in
  linux*)
    ./ci/jobs/build-and-test-linux.sh
esac

./ci/jobs/build-guests.sh
./ci/jobs/clippy.sh
./ci/jobs/rustfmt.sh

echo "----------------------------------------"
echo "All tests finished!"
