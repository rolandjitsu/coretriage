# coretriage

[![CI](https://img.shields.io/github/actions/workflow/status/rolandjitsu/coretriage/ci.yml?branch=main&style=flat-square&label=CI)](https://github.com/rolandjitsu/coretriage/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/codecov/c/github/rolandjitsu/coretriage/main?style=flat-square)](https://codecov.io/gh/rolandjitsu/coretriage)
[![crates.io](https://img.shields.io/crates/v/coretriage?style=flat-square)](https://crates.io/crates/coretriage)
[![docs.rs](https://img.shields.io/docsrs/coretriage?style=flat-square)](https://docs.rs/coretriage)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue?style=flat-square)](./LICENSE)

Triage raw Linux ELF core dumps offline: parse the core, unwind every thread, symbolicate the
frames, compute a stable crash signature, and bucket a pile of cores into distinct crashes.
Handles both crashes (a fatal signal) and hangs (a core taken from a live, stuck process with
`gcore`). No debugger session, no live process, no network.

It ships as two crates: the [`coretriage-core`](./crates/coretriage-core) library and the
[`coretriage`](./crates/coretriage) CLI built on it.

## Install

```sh
cargo install coretriage    # from crates.io
cargo binstall coretriage   # prebuilt binary, no compile
```

Prebuilt binaries for Linux and macOS are attached to each
[release](https://github.com/rolandjitsu/coretriage/releases).

## Usage

Triage a single core. A core records the path of each mapped file as it was on the machine that
crashed, and coretriage looks those paths up on the local filesystem. When you triage the core
somewhere else (your laptop, a CI box), that path may not exist or may hold a different build, so
point `--exe` at the matching executable and `--sysroot` at a tree of its shared objects:

```sh
coretriage core.1234
coretriage --exe ./target/release/app --sysroot ./sysroot core.1234
```

A crash core (a fatal signal) and a hang core (captured with `gcore`) triage the same way; the
report's fault is `Signal(n)` for the former and `Hang` for the latter:

```sh
kill -SEGV "$pid"          # or let it crash; produces core.<pid>
coretriage core."$pid"

gcore "$pid"               # snapshot a stuck process without killing it
coretriage core."$pid"
```

Batch a directory of cores. Each core is triaged in parallel, grouped by signature, and the
distinct crashes are reported with their counts and a representative backtrace:

```sh
coretriage cores/                 # text report, ranked buckets
coretriage cores/ --json          # machine-readable
coretriage cores/ --top 32        # keep more frames per thread
```

## How it works

The pipeline runs in stages, each a module in `coretriage-core`:

1. **Parse the core** (`core`). Read the ELF core with `object`: the `PT_LOAD` segments are the
   saved memory image, and the `PT_NOTE` segment carries `NT_PRSTATUS` (one per thread, with its
   register set) and `NT_FILE` (the file-backed mapping table). The core is mmap'd, so memory is
   read lazily rather than loaded in full.
2. **Build the module map** (`maps`). Turn the `NT_FILE` entries, plus any `--exe` and
   `--sysroot` overrides, into resolved modules with load biases and, where present, GNU
   build-ids.
3. **Unwind** (`unwind`). Starting from each thread's `NT_PRSTATUS` registers, walk the stack
   with DWARF call-frame information via `framehop`, reading stack and register memory from the
   core image.
4. **Symbolicate** (`symbolize`). Map each return address back to its module and resolve
   function name and source file/line from the module's DWARF with `addr2line` (an
   `addr2line::Context` cached per build-id), demangling Rust (`rustc-demangle`) and C++
   (`cpp_demangle`) symbols.
5. **Signature** (`signature`). Normalize the crashing thread's backtrace - drop offsets and
   non-deterministic frames - and hash it with BLAKE3 into a stable fingerprint, so the same bug
   yields the same signature across cores.
6. **Aggregate and report** (`aggregate`, `report`). Group reports by signature with a
   representative and a count (the batch runs cores in parallel with `rayon`), then render as
   text or JSON.

## Scope

v0.1 targets **Linux x86_64 ELF cores**. Modules are resolved from the core's `NT_FILE` table
and from explicit `--exe` / `--sysroot` paths you provide; automatic build-id lookup and
`debuginfod` fetching come later. Other architectures (aarch64) and split-debuginfo stores are
on the roadmap, not in v0.1.

## License

Apache-2.0.
