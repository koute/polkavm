#!/bin/bash

set -euo pipefail

cargo build --release
cp target/x86_64-unknown-linux-gnu/release/polkavm-zygote ../polkavm/src/sandbox/
