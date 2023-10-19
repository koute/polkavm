#!/bin/bash

set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
cd ../..

if [ "${CI_RV32E_TOOLCHAIN_AVAILABLE:-}" == 1 ]; then
    echo ">> cargo build (guests)"
    cd guest-programs
    ./build-all.sh
    cd ..
fi
