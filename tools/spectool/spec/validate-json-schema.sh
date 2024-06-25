#!/bin/sh

# Requires yajsv to be installed. You can install it with:
#   go install github.com/neilpa/yajsv@latest

set -euo pipefail
~/go/bin/yajsv -s schema.json output/programs/*.json
