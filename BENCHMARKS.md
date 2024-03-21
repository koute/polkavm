# Benchmark: pinky

This benchmark is a cycle-accurate NES emulator, running a real, homebrew NES game. ([source code](https://github.com/koute/polkavm/blob/af63824a1929f8b1ae2c3e790c2a4807a9a17144/guest-programs/bench-pinky/src/main.rs))

## Oneshot execution (for pinky)

These benchmarks measure the end-to-end time that it takes to run the program a single time, including compilation and initialization.

| VM                                       |                 Time | vs fastest |
|------------------------------------------|----------------------|------------|
| (bare metal)                             |  39.003ms ±  0.052ms |      1.00x |
| **PolkaVM (recompiler)**                 |  58.425ms ±  0.184ms |      1.50x |
| PolkaVM (recompiler, async gas)          |  63.575ms ±  0.177ms |      1.63x |
| PolkaVM (recompiler, sync gas)           |  73.333ms ±  0.136ms |      1.88x |
| Wasmtime (winch)                         | 122.738ms ±  0.899ms |      3.15x |
| Wasmtime (cranelift)                     | 127.711ms ±  0.293ms |      3.27x |
| wazero                                   | 134.183ms ±  5.796ms |      3.44x |
| Wasmtime (cranelift, epoch interruption) | 153.187ms ±  1.146ms |      3.93x |
| Wasmer (singlepass)                      | 156.030ms ±  1.030ms |      4.00x |
| Wasmtime (cranelift, fuel metering)      | 176.693ms ±  0.301ms |      4.53x |
| Solana RBPF                              | 776.309ms ±  3.500ms |     19.90x |
| Wasm3                                    |   1.150 s ±   0.001s |     29.50x |
| Wasmi (eager)                            |   1.179 s ±   0.002s |     30.23x |
| Wasmi (lazy translation)                 |   1.181 s ±   0.001s |     30.29x |
| Wasmi (lazy)                             |   1.183 s ±   0.002s |     30.33x |
| CKB VM (ASM)                             |   1.538 s ±   0.001s |     39.44x |
| PolkaVM (interpreter)                    |   2.230 s ±   0.000s |     57.18x |
| CKB VM (non-ASM)                         |  11.956 s ±   0.007s |    306.54x |

## Execution time (for pinky)

These benchmarks measure the execution time of the benchmark, *without* time it takes to compile or initialize it.

| VM                                       |                 Time | vs fastest |
|------------------------------------------|----------------------|------------|
| (bare metal)                             |   4.295ms ±  0.003ms |      1.00x |
| **PolkaVM (recompiler)**                 |   6.522ms ±  0.013ms |      1.52x |
| Wasmtime (cranelift)                     |   7.023ms ±  0.003ms |      1.64x |
| PolkaVM (recompiler, async gas)          |   7.184ms ±  0.013ms |      1.67x |
| PolkaVM (recompiler, sync gas)           |   8.192ms ±  0.171ms |      1.91x |
| Wasmtime (cranelift, epoch interruption) |   8.374ms ±  0.002ms |      1.95x |
| Wasmtime (cranelift, fuel metering)      |   9.866ms ±  0.034ms |      2.30x |
| Wasmtime (winch)                         |  12.484ms ±  0.281ms |      2.91x |
| wazero                                   |  13.429ms ±  0.021ms |      3.13x |
| Wasmer (singlepass)                      |  16.301ms ±  0.229ms |      3.80x |
| Solana RBPF                              |  80.072ms ±  0.424ms |     18.64x |
| Wasm3                                    | 123.743ms ±  0.063ms |     28.81x |
| Wasmi (lazy translation)                 | 127.722ms ±  0.216ms |     29.74x |
| Wasmi (lazy)                             | 130.821ms ±  0.306ms |     30.46x |
| Wasmi (eager)                            | 130.947ms ±  0.342ms |     30.49x |
| CKB VM (ASM)                             | 164.443ms ±  0.041ms |     38.29x |
| PolkaVM (interpreter)                    | 241.175ms ±  0.072ms |     56.15x |
| CKB VM (non-ASM)                         |   1.302 s ±   0.002s |    303.02x |

## Compilation time (for pinky)

These benchmarks measure the time it takes to compile a given program by the VM.

| VM                                       |                 Time | vs fastest |
|------------------------------------------|----------------------|------------|
| Wasmi (lazy)                             |  97.929µs ±  0.344µs |      1.00x |
| PolkaVM (interpreter)                    | 246.039µs ±  0.549µs |      2.51x |
| **PolkaVM (recompiler)**                 | 335.052µs ±  0.171µs |      3.42x |
| PolkaVM (recompiler, async gas)          | 357.722µs ±  0.823µs |      3.65x |
| PolkaVM (recompiler, sync gas)           | 377.115µs ±  0.510µs |      3.85x |
| Wasmi (lazy translation)                 | 395.634µs ±  0.627µs |      4.04x |
| Solana RBPF                              | 598.010µs ±  0.346µs |      6.11x |
| Wasmi (eager)                            | 975.353µs ±  1.714µs |      9.96x |
| wazero                                   |   1.539ms ±  0.110ms |     15.72x |
| Wasmer (singlepass)                      |   3.736ms ±  0.004ms |     38.15x |
| Wasmtime (winch)                         |   6.852ms ±  0.006ms |     69.97x |
| Wasmtime (cranelift)                     |  62.933ms ±  0.368ms |    642.64x |
| Wasmtime (cranelift, epoch interruption) |  74.570ms ±  0.059ms |    761.47x |
| Wasmtime (cranelift, fuel metering)      |  84.926ms ±  0.035ms |    867.23x |


# Benchmark: prime-sieve

This benchmark is a prime sieve, searching for subsequent prime numbers. ([source code](https://github.com/koute/polkavm/tree/af63824a1929f8b1ae2c3e790c2a4807a9a17144/guest-programs/bench-prime-sieve))

## Oneshot execution (for prime-sieve)

These benchmarks measure the end-to-end time that it takes to run the program a single time, including compilation and initialization.

| VM                                       |                 Time | vs fastest |
|------------------------------------------|----------------------|------------|
| (bare metal)                             |  10.787ms ±  0.006ms |      1.00x |
| **PolkaVM (recompiler)**                 |  19.103ms ±  0.043ms |      1.77x |
| PolkaVM (recompiler, async gas)          |  21.965ms ±  0.019ms |      2.04x |
| PolkaVM (recompiler, sync gas)           |  28.087ms ±  0.061ms |      2.60x |
| wazero                                   |  45.305ms ±  5.194ms |      4.20x |
| Wasmer (singlepass)                      |  52.152ms ±  0.049ms |      4.83x |
| Wasmtime (winch)                         |  56.976ms ±  0.098ms |      5.28x |
| Wasmtime (cranelift)                     | 108.193ms ±  0.226ms |     10.03x |
| Wasmtime (cranelift, epoch interruption) | 130.627ms ±  0.319ms |     12.11x |
| Wasmtime (cranelift, fuel metering)      | 169.620ms ±  0.203ms |     15.72x |
| Wasm3                                    | 247.270ms ±  0.883ms |     22.92x |
| CKB VM (ASM)                             | 294.185ms ±  2.110ms |     27.27x |
| Wasmi (lazy translation)                 | 320.970ms ±  2.782ms |     29.76x |
| Wasmi (eager)                            | 321.276ms ±  0.636ms |     29.78x |
| Wasmi (lazy)                             | 321.391ms ±  0.709ms |     29.79x |
| Solana RBPF                              | 407.462ms ±  0.314ms |     37.77x |
| PolkaVM (interpreter)                    | 638.592ms ±  0.600ms |     59.20x |
| CKB VM (non-ASM)                         |   2.477 s ±   0.003s |    229.58x |

## Execution time (for prime-sieve)

These benchmarks measure the execution time of the benchmark, *without* time it takes to compile or initialize it.

| VM                                       |                 Time | vs fastest |
|------------------------------------------|----------------------|------------|
| (bare metal)                             |   1.584ms ±  0.002ms |      1.00x |
| Wasmtime (cranelift)                     |   2.160ms ±  0.002ms |      1.36x |
| **PolkaVM (recompiler)**                 |   2.364ms ±  0.006ms |      1.49x |
| PolkaVM (recompiler, async gas)          |   2.463ms ±  0.003ms |      1.55x |
| Wasmtime (cranelift, fuel metering)      |   2.472ms ±  0.003ms |      1.56x |
| PolkaVM (recompiler, sync gas)           |   2.498ms ±  0.011ms |      1.58x |
| Wasmtime (cranelift, epoch interruption) |   2.673ms ±  0.004ms |      1.69x |
| wazero                                   |   4.735ms ±  0.013ms |      2.99x |
| Wasmtime (winch)                         |   5.330ms ±  0.003ms |      3.36x |
| Wasmer (singlepass)                      |   6.095ms ±  0.010ms |      3.85x |
| CKB VM (ASM)                             |  26.500ms ±  0.016ms |     16.73x |
| Wasm3                                    |  28.609ms ±  0.018ms |     18.06x |
| Wasmi (eager)                            |  33.076ms ±  0.137ms |     20.88x |
| Wasmi (lazy)                             |  33.301ms ±  0.048ms |     21.02x |
| Wasmi (lazy translation)                 |  33.705ms ±  0.723ms |     21.27x |
| PolkaVM (interpreter)                    |  84.675ms ±  0.110ms |     53.45x |
| Solana RBPF                              | 162.503ms ±  0.130ms |    102.57x |
| CKB VM (non-ASM)                         | 366.227ms ±  0.470ms |    231.16x |

## Compilation time (for prime-sieve)

These benchmarks measure the time it takes to compile a given program by the VM.

| VM                                       |                 Time | vs fastest |
|------------------------------------------|----------------------|------------|
| Wasmi (lazy)                             |  87.280µs ±  1.615µs |      1.00x |
| Wasmi (lazy translation)                 | 669.850µs ±  1.897µs |      7.67x |
| PolkaVM (interpreter)                    | 677.561µs ±  0.339µs |      7.76x |
| **PolkaVM (recompiler)**                 | 851.639µs ±  3.264µs |      9.76x |
| PolkaVM (recompiler, async gas)          | 914.962µs ±  5.154µs |     10.48x |
| PolkaVM (recompiler, sync gas)           | 955.179µs ±  6.275µs |     10.94x |
| Solana RBPF                              |   1.449ms ±  0.001ms |     16.60x |
| Wasmi (eager)                            |   2.085ms ±  0.002ms |     23.89x |
| wazero                                   |   4.371ms ±  0.776ms |     50.08x |
| Wasmer (singlepass)                      |   9.650ms ±  0.038ms |    110.57x |
| Wasmtime (winch)                         |  10.085ms ±  0.009ms |    115.55x |
| Wasmtime (cranelift)                     |  93.418ms ±  0.097ms |   1070.32x |
| Wasmtime (cranelift, epoch interruption) | 106.631ms ±  0.332ms |   1221.70x |
| Wasmtime (cranelift, fuel metering)      | 144.623ms ±  0.349ms |   1656.99x |


# Benchmark: minimal

This benchmark is a tiny, minimal program which doesn't do much work; it just increments a global variable and returns immediately. It is a good test case for measuring constant-time overhead. ([source code](https://github.com/koute/polkavm/blob/af63824a1929f8b1ae2c3e790c2a4807a9a17144/guest-programs/bench-minimal/src/main.rs))

## Oneshot execution (for minimal)

These benchmarks measure the end-to-end time that it takes to run the program a single time, including compilation and initialization.

| VM                                       |                 Time | vs fastest |
|------------------------------------------|----------------------|------------|
| PolkaVM (interpreter)                    |   2.444µs ±  0.002µs |      1.00x |
| CKB VM (non-ASM)                         |   7.081µs ±  0.003µs |      2.90x |
| Solana RBPF                              |  16.800µs ±  0.064µs |      6.87x |
| Wasm3                                    |  24.265µs ±  0.030µs |      9.93x |
| (bare metal)                             |  28.157µs ±  0.012µs |     11.52x |
| Wasmi (lazy)                             |  28.426µs ±  0.232µs |     11.63x |
| Wasmi (lazy translation)                 |  29.003µs ±  0.066µs |     11.87x |
| Wasmi (eager)                            |  29.438µs ±  0.386µs |     12.05x |
| CKB VM (ASM)                             |  66.107µs ±  0.441µs |     27.05x |
| **PolkaVM (recompiler)**                 |  95.033µs ±  0.165µs |     38.88x |
| wazero                                   |  95.100µs ± 20.554µs |     38.91x |
| PolkaVM (recompiler, sync gas)           |  95.173µs ±  0.263µs |     38.94x |
| PolkaVM (recompiler, async gas)          |  95.314µs ±  0.213µs |     39.00x |
| Wasmer (singlepass)                      | 104.873µs ±  2.653µs |     42.91x |
| Wasmtime (winch)                         | 184.367µs ±  0.508µs |     75.44x |
| Wasmtime (cranelift)                     | 707.082µs ±  1.228µs |    289.32x |
| Wasmtime (cranelift, epoch interruption) | 854.033µs ±  9.982µs |    349.45x |
| Wasmtime (cranelift, fuel metering)      | 888.159µs ±  1.711µs |    363.41x |

## Execution time (for minimal)

These benchmarks measure the execution time of the benchmark, *without* time it takes to compile or initialize it.

| VM                                       |                 Time | vs fastest |
|------------------------------------------|----------------------|------------|
| (bare metal)                             |   0.044µs ±  0.000µs |      1.00x |
| Wasm3                                    |   0.138µs ±  0.000µs |      3.15x |
| Wasmer (singlepass)                      |   0.140µs ±  0.002µs |      3.21x |
| Wasmtime (cranelift)                     |   0.158µs ±  0.001µs |      3.63x |
| Wasmtime (cranelift, epoch interruption) |   0.159µs ±  0.001µs |      3.63x |
| Wasmtime (winch)                         |   0.160µs ±  0.002µs |      3.66x |
| Wasmtime (cranelift, fuel metering)      |   0.160µs ±  0.001µs |      3.66x |
| Solana RBPF                              |   0.166µs ±  0.001µs |      3.80x |
| PolkaVM (interpreter)                    |   0.171µs ±  0.000µs |      3.92x |
| Wasmi (lazy translation)                 |   0.183µs ±  0.002µs |      4.18x |
| Wasmi (eager)                            |   0.183µs ±  0.000µs |      4.19x |
| Wasmi (lazy)                             |   0.185µs ±  0.000µs |      4.24x |
| wazero                                   |   0.225µs ±  0.004µs |      5.16x |
| CKB VM (ASM)                             |   2.704µs ±  0.002µs |     61.92x |
| CKB VM (non-ASM)                         |   3.514µs ±  0.002µs |     80.48x |
| PolkaVM (recompiler, async gas)          |   6.906µs ±  0.020µs |    158.17x |
| **PolkaVM (recompiler)**                 |   6.916µs ±  0.017µs |    158.40x |
| PolkaVM (recompiler, sync gas)           |   6.975µs ±  0.043µs |    159.75x |

## Compilation time (for minimal)

These benchmarks measure the time it takes to compile a given program by the VM.

| VM                                       |                 Time | vs fastest |
|------------------------------------------|----------------------|------------|
| PolkaVM (interpreter)                    |   1.339µs ±  0.001µs |      1.00x |
| Wasmi (lazy)                             |   8.577µs ±  0.117µs |      6.40x |
| Wasmi (lazy translation)                 |   9.818µs ±  0.021µs |      7.33x |
| Wasmi (eager)                            |  11.628µs ±  0.134µs |      8.68x |
| **PolkaVM (recompiler)**                 |  14.028µs ±  0.058µs |     10.48x |
| PolkaVM (recompiler, sync gas)           |  14.375µs ±  0.157µs |     10.73x |
| PolkaVM (recompiler, async gas)          |  14.386µs ±  0.206µs |     10.74x |
| Solana RBPF                              |  15.478µs ±  0.013µs |     11.56x |
| wazero                                   |  20.861µs ±  0.045µs |     15.58x |
| Wasmtime (winch)                         | 135.206µs ±  0.131µs |    100.97x |
| Wasmtime (cranelift)                     | 649.177µs ±  0.343µs |    484.78x |
| Wasmtime (cranelift, epoch interruption) | 800.618µs ±  1.132µs |    597.87x |
| Wasmtime (cranelift, fuel metering)      | 843.816µs ±  1.618µs |    630.13x |


---------------------------------------------------------------------------

# Supplemental information

CPU: AMD Ryzen Threadripper 3970X 32-Core Processor

Platform: x86_64-linux

Commit: [af63824a1929f8b1ae2c3e790c2a4807a9a17144](https://github.com/koute/polkavm/tree/af63824a1929f8b1ae2c3e790c2a4807a9a17144)

Timestamp: 2024-03-24 13:12:58 UTC

---------------------------------------------------------------------------

# Replication

You can replicate these benchmarks as follows:

```
$ git clone https://github.com/koute/polkavm.git
$ cd polkavm
$ git checkout af63824a1929f8b1ae2c3e790c2a4807a9a17144
$ cd tools/benchtool
$ ./01-build-benchmarks.sh
$ ./02-run-benchmarks.rb
$ ./03-analyze-benchmarks.rb
```

Only running the benchmarks on Linux is officially supported.

WARNING: The `02-run-benchmarks.rb` script uses a couple of system-level tricks to make benchmarking more consistent and requires 'sudo' and 'schedtool' to be installed. If you're uncomfortable with that or if you're running a non-Linux OS you can also run the benchmarks with `cargo run --release` instead.

