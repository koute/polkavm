#!/bin/bash

set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
cd ../..

source ./ci/jobs/detect-or-install-riscv-toolchain.sh
if [ "${RV32E_TOOLCHAIN:-}" != "" ]; then
    echo ">> cargo build (guests)"
    cd guest-programs
    ./build-examples.sh
    cd ..
fi
