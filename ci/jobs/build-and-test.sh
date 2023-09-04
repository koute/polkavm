#!/bin/bash

set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
cd ../..

echo ">> cargo test (debug)"
cargo test --all

echo ">> cargo test (release)"
cargo test --all --release

echo ">> cargo run (examples)"
POLKAVM_TRACE_EXECUTION=1 POLKAVM_ALLOW_INSECURE=1 cargo run -p hello-world-host
