# DOOM for PolkaVM

This is a port of DOOM which runs under PolkaVM.

You can find the source code of the guest program [here](https://github.com/koute/polkadoom).

## Running on Linux

Make sure to have SDL2 installed, and then run:

```
cargo run --release --no-default-features
```

## Running on macOS

```
LIBRARY_PATH="$LIBRARY_PATH:$(brew --prefix)/lib" POLKAVM_ALLOW_INSECURE=1 POLKAVM_SANDBOX=generic POLKAVM_BACKEND=compiler cargo run --target=x86_64-apple-darwin --release
```

## Running on other operating systems

It will run, but it will use an interpreter, which at this moment is *very* slow and won't run full speed.
