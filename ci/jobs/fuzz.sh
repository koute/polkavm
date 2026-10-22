#!/bin/bash

set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
cd ../..

cd fuzz

# Each of these is run as a separate CI job; keep this in sync with `.github/workflows/rust.yml`.
ALL_TARGETS="fuzz_generic_allocator fuzz_shm_allocator fuzz_linker fuzz_polkavm fuzz_polkavm_raw fuzz_program_blob fuzz_extended_decode fuzz_page_set"

for target in ${@:-$ALL_TARGETS}; do
    case "$target" in
        fuzz_generic_allocator|fuzz_shm_allocator|fuzz_page_set) runs=1000000 ;;
        fuzz_linker|fuzz_polkavm|fuzz_polkavm_raw|fuzz_program_blob) runs=10000 ;;
        fuzz_extended_decode) runs=200000 ;;
        *)
            echo "unknown fuzz target: $target" >&2
            exit 1
        ;;
    esac

    if [ "$target" = "fuzz_polkavm_raw" ]; then
        echo ">> cargo run (fuzz_seeds)"
        cargo run --release --features tools --bin fuzz_seeds
    fi

    echo ">> cargo fuzz run ($target)"

    case "$target" in
        fuzz_polkavm|fuzz_polkavm_raw) length_flags="-len_control=0 -max_len=4096" ;;
        *) length_flags="" ;;
    esac

    cargo fuzz run "$target" -- -runs="$runs" -max_total_time=600 $length_flags
done
