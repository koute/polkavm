#!/bin/bash

set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
cd ../..

echo ">> cargo build (zygote)"
cd crates/polkavm-zygote
cargo build --release
cd ../..

echo ">> cargo run (examples, interpreter, i686-unknown-linux-musl)"
POLKAVM_TRACE_EXECUTION=1 POLKAVM_ALLOW_INSECURE=1 POLKAVM_BACKEND=interpreter cargo run --target=i686-unknown-linux-musl -p hello-world-host

echo ">> cargo run (examples, interpreter, x86_64-unknown-linux-gnu)"
POLKAVM_TRACE_EXECUTION=1 POLKAVM_ALLOW_INSECURE=1 POLKAVM_BACKEND=interpreter cargo run --target=x86_64-unknown-linux-gnu -p hello-world-host

echo ">> cargo run (examples, compiler, linux, x86_64-unknown-linux-gnu)"
POLKAVM_TRACE_EXECUTION=1 POLKAVM_ALLOW_INSECURE=1 POLKAVM_BACKEND=compiler POLKAVM_SANDBOX=linux cargo run --target=x86_64-unknown-linux-gnu -p hello-world-host

# echo ">> cargo run (examples, compiler, generic, x86_64-unknown-linux-gnu)"
# POLKAVM_TRACE_EXECUTION=1 POLKAVM_ALLOW_INSECURE=1 POLKAVM_BACKEND=compiler POLKAVM_SANDBOX=generic cargo run --target=x86_64-unknown-linux-gnu -p hello-world-host

echo ">> cargo check (polkatool, i686-unknown-linux-musl)"
cargo check --target=i686-unknown-linux-musl -p polkatool

echo ">> cargo check (benchtool, all features)"
cd tools/benchtool
cargo check --all-features
