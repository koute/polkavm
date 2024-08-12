#!/bin/bash

set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
cd ../..

rustup target add x86_64-apple-darwin

echo ">> cargo run (examples, interpreter, x86_64-apple-darwin)"
POLKAVM_TRACE_EXECUTION=1 POLKAVM_ALLOW_INSECURE=1 POLKAVM_BACKEND=interpreter cargo run --target=x86_64-apple-darwin -p hello-world-host

# echo ">> cargo run (examples, compiler, generic, x86_64-apple-darwin)"
# POLKAVM_TRACE_EXECUTION=1 POLKAVM_ALLOW_INSECURE=1 POLKAVM_BACKEND=compiler POLKAVM_SANDBOX=generic cargo run --target=x86_64-apple-darwin -p hello-world-host

echo ">> cargo run (examples, interpreter, aarch64-apple-darwin)"
POLKAVM_TRACE_EXECUTION=1 POLKAVM_ALLOW_INSECURE=1 POLKAVM_BACKEND=interpreter cargo run --target=aarch64-apple-darwin -p hello-world-host
