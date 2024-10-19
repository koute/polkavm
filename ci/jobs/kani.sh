#!/bin/bash

set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
cd ../..

echo ">> cargo kani (polkavm-common)"
cargo kani -p polkavm-common

echo ">> cargo kani (polkavm)"
cargo kani -p polkavm
