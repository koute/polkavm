This is a simple bindgen-based tool to generate the Linux kernel bindings we need.

Technically we could use the `linux-raw-sys` crate instead (which also uses bindgen),
but it has over 150k+ lines of code in total (granted, a lot of it is just duplicate
architecture-specific code that's `cfg`'d away, but still), which seems like a total
overkill compared to what we actually need.

Run `prepare-sources.sh` to download Linux sources, and then just run `cargo run` to regenerate the bindings.
