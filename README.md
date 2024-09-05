## PolkaVM

PolkaVM is a general purpose user-level RISC-V based virtual machine.

**This project is still unfinished and is a very heavy work-in-progress! Do not use it in production!**

[See current benchmark results here](./BENCHMARKS.md).

## Design goals

(**Note: not all of these are currently true!**)

- Secure and sandboxed by default. The code running in the VM should run in a separate process, and should not be able to access the host system, even in the presence of an attacker with full remote code execution privileges inside of the VM.
- Fast to execute. The runtime performance of the code running in the VM should be competitive with state-of-art WebAssembly VMs, at least within the same order of magnitude.
- Fast to compile, with guaranteed single-pass O(n) compilation. Loading new code into the VM should be near instanteneous.
- Low memory footprint. Each concurrent instance of the VM should have a baseline memory overhead of no more than 128KB.
- Small binaries. Programs compiled for this VM should take up as little space as possible.
- No wasted virtual address space. The VM should not preallocate gigabytes of virtual address space for sandboxing purposes.
- Fully deterministic. Given the same inputs and the same code the execution should always return exactly the same output.
- Support for high performance asynchronous gas metering. Gas metering should be cheap, deterministic, and reasonably accurate.
- Simple. It should be possible for a single programmer to write an interpreter fully compatible with this VM in less than a week.
- Versioned operational semantics. Any future changes to the semantics that are observable by a guest program will be versioned, and will be explicitly opt-in.
- Standardized. There should be a spec fully describing the guest-observable operational semantics of this VM.
- Cross-platform. On unsupported OSes and platforms the VM will run in an interpreted mode.
- Minimum external dependencies. The VM should be mostly self-contained, fast to compile, and resistant to supply-chain attacks.
- Built-in tooling for debugging and performance profiling.

## Non-goals

- System level emulation. This VM will never be able to run a normal operating system.
- Full support for architectures other than amd64 (also known as x86_64) and aarch64 (also known as arm64). Anything else will run in an interpreted mode.
- Full support for operating systems other than Linux, macOS and Windows. On any other OS the VM will run in an interpreted mode.
- Floating point support, SIMD, and other more niche RISC-V extensions. These could be added as an opt-in feature in the future if necessary, but this is not currently planned.
- Support for full 32-register RISC-V ISA. This VM currently only targets the RV32EM.

## Getting started

Reproducible on Debian 12.7
```sh
## enable unprivileged userfaultfd
sudo sysctl -w vm.unprivileged_userfaultfd=1

## install dependencies
sudo apt-get install -y curl git build-essential

## install rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
. "$HOME/.cargo/env"

## install riscv toolchain
curl -L --output /tmp/rust-riscv32em-nightly-2024-01-05-r0-x86_64-unknown-linux-gnu.tar.xz "https://github.com/koute/rustc-rv32e/releases/download/nightly-2024-01-05-r0/rust-riscv32em-nightly-2024-01-05-r0-x86_64-unknown-linux-gnu.tar.xz"
tar -C /tmp -xf /tmp/rust-riscv32em-nightly-2024-01-05-r0-x86_64-unknown-linux-gnu.tar.xz
mkdir -p ~/.rustup/toolchains
mv /tmp/rust-riscv32em-x86_64-unknown-linux-gnu/riscv32em-nightly-2024-01-05-r0-x86_64-unknown-linux-gnu ~/.rustup/toolchains/

## workaround for old libssl
wget http://nz2.archive.ubuntu.com/ubuntu/pool/main/o/openssl/libssl1.1_1.1.1f-1ubuntu2_amd64.deb
sudo dpkg -i libssl1.1_1.1.1f-1ubuntu2_amd64.deb
rm libssl1.1_1.1.1f-1ubuntu2_amd64.deb

## clone polkavm and clean up of existing guest program we want to compile here
git clone --depth 1 https://github.com/koute/polkavm.git
rm polkavm/guest-programs/output/example-hello-world.polkavm

## compile our guest program
cd polkavm/guest-programs
RV32E_TOOLCHAIN="riscv32em-nightly-2024-01-05-r0-x86_64-unknown-linux-gnu" RUSTFLAGS="-C target-feature=+c -C relocation-model=pie -C link-arg=--emit-relocs -C link-arg=--unique --remap-path-prefix=$(pwd)= --remap-path-prefix=$HOME=~" cargo build -q --release --bin example-hello-world -p example-hello-world
cd ..
cargo run -q -p polkatool link --run-only-if-newer -s guest-programs/target/riscv32ema-unknown-none-elf/release/example-hello-world -o guest-programs/output/example-hello-world.polkavm

## compile and run our host program
cargo build --release --manifest-path examples/hello-world/Cargo.toml
./target/release/hello-world-host
```

## License

Licensed under either of

  * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
  * MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
