#!/bin/bash

set -euo pipefail

cargo build
cp target/x86_64-unknown-linux-gnu/debug/polkavm-zygote ../polkavm/src/sandbox/
