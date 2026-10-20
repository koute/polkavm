# DOOM for PolkaVM

This is a port of DOOM which runs under PolkaVM.

You can find the source code of the guest program [here](https://github.com/koute/polkadoom).

## Running on Linux

Make sure to have SDL2 installed, and then run:

```
cargo run --release --no-default-features
```

## Running on macOS

Install the correct target:

```bash
rustup target add x86_64-apple-darwin      
```

Install `SDL` dependencies:

```bash
brew install SDL2
brew install SDL2_ttf
brew install SDL2_image
```

Run the game:

```bash
cargo run --target=x86_64-apple-darwin --release       
```

## Running on other operating systems

It will run, but it will use an interpreter, which at this moment is *very* slow and won't run full speed.
