#!/bin/sh

set -euo pipefail

export BUILD_BENCHMARKS_INSTALL_ALL_TOOLCHAINS=1
../../guest-programs/build-benchmarks.sh
