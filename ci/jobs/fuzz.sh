#!/bin/bash

set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
cd ../..

cd fuzz

echo ">> cargo fuzz run (fuzz_generic_allocator)"
cargo fuzz run fuzz_generic_allocator -- -runs=1000000

echo ">> cargo fuzz run (fuzz_shm_allocator)"
cargo fuzz run fuzz_shm_allocator -- -runs=1000000
