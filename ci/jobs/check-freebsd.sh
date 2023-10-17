#!/bin/bash

set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
cd ../..

echo ">> cargo check (freebsd)"
cd crates/polkavm
cargo check --target=x86_64-unknown-freebsd
cd ../..
