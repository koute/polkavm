#!/bin/sh

# Turns `run-hash-benches` output into per-algorithm markdown tables.
#
# Usage:
#   ./run-hash-benches > hash.txt
#   ./process-hash-results.sh hash.txt > hash-table.md
#
# Parses the generic harness output; parameterized rows carry the size as a
# fourth path segment:
#   runtime/<bench>/<backend>/<size>: ... : 1.07us
#
# One guest run() performs max(1, 65536 / size) chained hashes (see
# guest-programs/hash-bench-common.rs) to amortize the harness's per-call
# overhead; times are divided by the same iteration count to report
# per-hash values.
#
# Roles per algorithm (naming as established in the report):
#   pvm      = <algo>        with the polkavm64_compiler_sync_gas backend
#   native   = <algo>-native benchmark = host native build (-C target-cpu=native)
#   portable = <algo>        with the native backend = host portable build

set -eu

awk '
$1 ~ /^runtime\// {
    n = split($1, path, "/")
    if (n < 3) next
    bench = path[2]
    backend = path[3]; sub(/:$/, "", backend)
    size = (n >= 4) ? path[4] : "-"
    sub(/:$/, "", size)
    time = $NF

    ns = time
    if (time ~ /ns$/)      { sub(/ns$/, "", ns); ns += 0 }
    else if (time ~ /us$/) { sub(/us$/, "", ns); ns *= 1000 }
    else if (time ~ /ms$/) { sub(/ms$/, "", ns); ns *= 1000000 }
    else if (time ~ /s$/)  { sub(/s$/,  "", ns); ns *= 1000000000 }
    else next

    # Undo the guest-side amortization loop (see header).
    bytes = (size == "-") ? 4096 : size
    iterations = int(65536 / bytes)
    if (iterations < 1) iterations = 1
    ns /= iterations

    algo = bench
    tuned_artifact = sub(/-native$/, "", algo)

    if (!(algo in algo_seen)) { algo_seen[algo] = ++algo_count; algos[algo_count] = algo }
    if (!((algo, size) in size_seen)) {
        size_seen[algo, size] = 1
        sizes_for[algo] = sizes_for[algo] " " size
    }

    if (tuned_artifact && backend == "native")                 native[algo, size] = ns
    else if (backend == "native")                              portable[algo, size] = ns
    else if (backend == "polkavm64_compiler_sync_gas")         pvm[algo, size] = ns
}

function fmt(ns) {
    if (ns == "") return "-"
    if (ns < 1000) return sprintf("%.0f ns", ns)
    if (ns < 1000000) return sprintf("%.2f µs", ns / 1000)
    return sprintf("%.2f ms", ns / 1000000)
}

function ratio(a, b) {
    if (a == "" || b == "" || b == 0) return "-"
    return sprintf("%.2fx", a / b)
}

function fmt_size(bytes) {
    if (bytes == "-") return "default"
    if (bytes < 1024) return bytes " B"
    if (bytes < 1048576) return (bytes / 1024) " KiB"
    return (bytes / 1048576) " MiB"
}

END {
    print "*pvm* = PVM guest blob (recompiler, sync gas) · *native* = host native"
    print "build (`-C target-cpu=native`, build machine only) · *portable* = host"
    print "portable build (runs on any x86-64; crates may runtime-dispatch, e.g."
    print "sha2 uses SHA-NI where available)"
    print ""
    for (a = 1; a <= algo_count; a++) {
        algo = algos[a]
        printf "## %s\n\n", algo
        print "| size | pvm | native | portable | pvm/native | pvm/portable | native/portable |"
        print "|---:|---:|---:|---:|---:|---:|---:|"
        n = split(sizes_for[algo], size_list, " ")
        for (i = 1; i <= n; i++) {
            size = size_list[i]
            t_pvm = pvm[algo, size]; t_nat = native[algo, size]; t_por = portable[algo, size]
            printf "| %s | %s | %s | %s | %s | %s | %s |\n", \
                fmt_size(size), fmt(t_pvm), fmt(t_nat), fmt(t_por), \
                ratio(t_pvm, t_nat), ratio(t_pvm, t_por), ratio(t_nat, t_por)
        }
        printf "\n"
    }
}
' "$@"
