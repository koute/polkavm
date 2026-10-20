#!/bin/sh

# Turns the generic-harness output of run-crypto-benches into a markdown
# summary table: per benchmark, host vs PVM (64-bit, compiler, sync gas).
#
# Roles (same naming as the report / process-hash-results.sh):
#   host portable = <bench>        with the native backend (plain build)
#   host native   = <bench>-native with the native backend
#                   (-C target-cpu=native, built by build-crypto-native.sh;
#                   column shows "-" when those libraries are absent)
#   pvm           = <bench>        with the polkavm64_compiler_sync_gas backend
#
# Usage:
#   ./run-crypto-benches > crypto.txt
#   ./process-crypto-results.sh crypto.txt > crypto-table.md

set -eu

awk '
# lines look like: runtime/<bench>/<backend>: ...runtime/<bench>/<backend>: 355.61us
$1 ~ /^runtime\// {
    split($1, path, "/")
    bench = path[2]
    backend = path[3]; sub(/:$/, "", backend)
    time = $NF

    # normalize to nanoseconds
    ns = time
    if (time ~ /ns$/)      { sub(/ns$/, "", ns); ns += 0 }
    else if (time ~ /us$/) { sub(/us$/, "", ns); ns *= 1000 }
    else if (time ~ /ms$/) { sub(/ms$/, "", ns); ns *= 1000000 }
    else if (time ~ /s$/)  { sub(/s$/,  "", ns); ns *= 1000000000 }
    else next

    if (bench ~ /-native$/) {
        base = bench; sub(/-native$/, "", base)
        if (backend == "native") hostnative[base] = ns
        next
    }

    if (!(bench in seen)) { seen[bench] = ++count; benches[count] = bench }
    if (backend == "native")                       portable[bench] = ns
    if (backend == "polkavm64_compiler_sync_gas")  pvm[bench] = ns
}

function fmt(ns) {
    if (ns == "") return "-"
    if (ns < 1000) return sprintf("%.0f ns", ns)
    if (ns < 1000000) return sprintf("%.2f µs", ns / 1000)
    return sprintf("%.2f ms", ns / 1000000)
}

function ratio(a, b) {
    return (a != "" && b != "") ? sprintf("%.2fx", a / b) : "-"
}

END {
    print "| benchmark | host portable | host native | PVM (64-bit, sync gas) | pvm/portable | pvm/native |"
    print "|---|---:|---:|---:|---:|---:|"
    for (i = 1; i <= count; i++) {
        b = benches[i]
        printf "| %s | %s | %s | %s | %s | %s |\n", b, fmt(portable[b]), fmt(hostnative[b]), fmt(pvm[b]), ratio(pvm[b], portable[b]), ratio(pvm[b], hostnative[b])
    }
}
' "$@"