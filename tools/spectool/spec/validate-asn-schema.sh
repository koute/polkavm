#!/bin/sh

set -euo pipefail

source ~/.rye/env

if [ ! -d ".venv" ]; then

    rye sync
fi

source .venv/bin/activate
rye run python validate-asn-schema.py
