#!/bin/bash

export extra_flags="-C llvm-args=-inline-threshold=0"
source build-benchmarks.sh
