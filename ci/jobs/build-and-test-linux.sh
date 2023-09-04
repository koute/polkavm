#!/bin/bash

set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
cd ../..

echo ">> cargo build (zygote)"
cd crates/polkavm-zygote
cargo build --release
cd ../..

echo ">> cargo run (examples, musl)"
POLKAVM_TRACE_EXECUTION=1 POLKAVM_ALLOW_INSECURE=1 cargo run --target=i686-unknown-linux-musl -p hello-world-host
