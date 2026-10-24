# coretriage-core

[![crates.io](https://img.shields.io/crates/v/coretriage-core?style=flat-square)](https://crates.io/crates/coretriage-core)
[![docs.rs](https://img.shields.io/docsrs/coretriage-core?style=flat-square)](https://docs.rs/coretriage-core)

The library behind [`coretriage`](https://crates.io/crates/coretriage). It triages raw Linux
ELF core dumps offline - crashes and hangs alike:

- parse the core (`PT_LOAD` memory image, `NT_PRSTATUS` threads, `NT_FILE` module map);
- build the module map from the core plus `--exe` / `--sysroot` overrides;
- unwind each thread's stack with DWARF call-frame info (`framehop`);
- symbolicate frames via `addr2line` (function, file, line; Rust and C++ demangled);
- normalize the crashing backtrace and hash it (BLAKE3) into a stable signature;
- bucket many cores by signature to surface distinct crashes.

Most users want the [`coretriage`](https://crates.io/crates/coretriage) binary; this crate is
the engine it is built on. The entry points are `triage` (one core) and `triage_batch` (a
directory), over the types in the `model` module.

See the [repository README](https://github.com/rolandjitsu/coretriage) for the design and
scope.

## License

Apache-2.0.
