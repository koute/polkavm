#!/usr/bin/env bash

set -euo pipefail

cd "${0%/*}/"
cd ../..

echo ">> cargo build (guests)"
cd guest-programs
./build-examples.sh
cd ..
