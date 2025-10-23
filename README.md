# runqlat

Example showing how to continuously track specific processes (e.g., those belonging to target containers) and obtain their run queue latencies.

Inspired by the C version of runqlat described in [Eunomia's tutorial](https://eunomia.dev/en/tutorials/9-runqlat/). This implementation is written in Rust and [Aya](https://aya-rs.dev/) and extended for continuous profiling of selected processes. For example, it can be extended to retrieve all containers from containerd, collect their PIDs, periodically update the tracked PIDs in the eBPF program, and periodically fetch latency statistics for metric export.

## CO-RE (Compile Once - Run Everywhere)

At the moment, the combination of Aya and rustc does not fully support CO-RE [aya/issues/349](https://github.com/aya-rs/aya/issues/349). Therefore, when generating bindings with aya-tool, you must use the `/sys/kernel/btf/vmlinux` file from a kernel of the **same version** as the one where the eBPF program will run. Otherwise, the fields in the generated task_struct may not align correctly with those on a different kernel.

## Prerequisites

1. stable rust toolchains: `rustup toolchain install stable`
1. nightly rust toolchains: `rustup toolchain install nightly --component rust-src`
1. (if cross-compiling) rustup target: `rustup target add ${ARCH}-unknown-linux-musl`
1. (if cross-compiling) LLVM: (e.g.) `brew install llvm` (on macOS)
1. (if cross-compiling) C toolchain: (e.g.) [`brew install filosottile/musl-cross/musl-cross`](https://github.com/FiloSottile/homebrew-musl-cross) (on macOS)
1. bpf-linker: `cargo install bpf-linker` (`--no-default-features` on macOS)

## Build & Run

Use `cargo build`, `cargo check`, etc. as normal. Run your program with:

```shell
cargo run --release
```

Cargo build scripts are used to automatically build the eBPF correctly and include it in the
program.

## Cross-compiling on macOS

Cross compilation should work on both Intel and Apple Silicon Macs.

```shell
CC=${ARCH}-linux-musl-gcc cargo build --package runqlat --release \
  --target=${ARCH}-unknown-linux-musl \
  --config=target.${ARCH}-unknown-linux-musl.linker=\"${ARCH}-linux-musl-gcc\"
```

The cross-compiled program `target/${ARCH}-unknown-linux-musl/release/runqlat` can be
copied to a Linux server or VM and run there.

## License

With the exception of eBPF code, runqlat is distributed under the terms
of either the [MIT license] or the [Apache License] (version 2.0), at your
option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this crate by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.

### eBPF

All eBPF code is distributed under either the terms of the
[GNU General Public License, Version 2] or the [MIT license], at your
option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this project by you, as defined in the GPL-2 license, shall be
dual licensed as above, without any additional terms or conditions.

[Apache license]: LICENSE-APACHE
[MIT license]: LICENSE-MIT
[GNU General Public License, Version 2]: LICENSE-GPL2
