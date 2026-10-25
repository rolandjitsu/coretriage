# coretriage

[![CI](https://img.shields.io/github/actions/workflow/status/rolandjitsu/coretriage/ci.yml?branch=main&style=flat-square&label=CI)](https://github.com/rolandjitsu/coretriage/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/codecov/c/github/rolandjitsu/coretriage/main?style=flat-square)](https://codecov.io/gh/rolandjitsu/coretriage)
[![crates.io](https://img.shields.io/crates/v/coretriage?style=flat-square)](https://crates.io/crates/coretriage)
[![docs.rs](https://img.shields.io/docsrs/coretriage-core?style=flat-square&label=docs.rs)](https://docs.rs/coretriage-core)
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
report's fault is a `signal` (with its number and faulting address) for the former and a `hang`
for the latter:

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
coretriage cores/ --format json   # machine-readable
coretriage cores/ --top 32        # keep more frames per thread
```

## Example

A single crash core, pointing `--exe` at the matching binary:

```text
$ coretriage core.1234 --exe ./app
fault: signal 11 (SIGSEGV) at 0x0
signature: 6ae8cbf38275b439  SIGSEGV in app!render_widget
* thread 4213
    #0 app!render_widget (src/widget.c:88)
    #1 app!tick          (src/app.c:120)
    #2 app!main          (src/main.c:42)
    #3 libc.so.6!<unknown>
```

`#0` is the innermost frame (where it crashed); each line below is its caller, out to `main`.
`signature` is a stable hash of the normalized stack, so the same bug groups together.

A directory of cores collapses to ranked, deduplicated crashes:

```text
$ coretriage cores/
[1] 312 cores  6ae8cbf38275b439  SIGSEGV in app!render_widget
[2]  71 cores  a1b0ff45c3d2e817  SIGABRT in app!check_invariant
[3]   4 cores  c9d2e8107f4a1b60  hang: 12 threads in pthread_cond_wait
```

`--format json` gives the same data machine-readably on stdout (logs go to stderr), ready to
pipe into `jq`, a dashboard, or CI.

## When to use coretriage

Use **coretriage** when you have many cores or want automation:

- **A pile of cores** - CI dumped 500 overnight and you want the handful of distinct bugs,
  ranked by frequency, not 500 debugger sessions.
- **Tracking crashes over time** - the stable signature lets you dedup, count, and alert when a
  new signature appears or one spikes.
- **Automation** - headless, no debugger, clean JSON on stdout for CI, a dashboard, or (soon)
  OpenTelemetry. It is also a library you can embed.
- **Hangs** - `gcore` a stuck process and get an all-thread fingerprint of where it is parked.

Use **gdb** / lldb / `coredumpctl` / Breakpad / Sentry when:

- **Debugging one core deeply** - inspecting variables, memory, and registers, evaluating
  expressions, or stepping is a debugger's job; coretriage only reports backtraces.
- **You already collect minidumps** - if you ship a Breakpad/Crashpad client, use that
  pipeline; coretriage reads raw ELF cores, not minidumps.
- **A quick one-off** - for a single core in front of you, `gdb ./app core` is hard to beat.

In short: coretriage is for **triage and aggregation across many cores**; gdb is for **deep,
interactive debugging of one**.

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

See [docs/architecture.md](./docs/architecture.md) for a flow diagram, the address model, and a
concepts glossary.

## Roadmap

**Today (v0.1).** coretriage handles **Linux x86_64 ELF cores**, for both crashes (a fatal
signal) and hangs. Modules are resolved from the core's `NT_FILE` table and from explicit
`--exe` / `--sysroot` paths you give it, and output is text or JSON.

Planned, roughly in order:

- **Automatic debug-info resolution** - look binaries up by GNU build-id (a local debug store
  and `debuginfod`), so stripped production binaries symbolicate without `--exe`.
- **More architectures and split debuginfo** - aarch64 cores (the unwinder already handles the
  arch) and separate `.debug` stores keyed by build-id.
- **More output formats.** Output is layered: the pipeline produces the data model and the
  `report` module renders it through an `Emitter`, so a new format is one more emitter, not a
  change to the pipeline.
  - **Folded stacks / flame graph** - Brendan Gregg folded format to pipe into `inferno` or any
    flame-graph tool; a crash flame graph shows where crashes concentrate, and for a hang an
    all-thread merged graph shows where every thread is parked.
  - **pprof** - a bucket is a weighted stack sample, exactly what pprof encodes, so crash
    frequency can be explored in Pyroscope, Parca, or Grafana (also the natural OpenTelemetry
    fit, since its profiling signal is pprof-based).
  - **OpenTelemetry events and metrics** - emit each bucket as a structured event or counter
    (signature, signal, top frame, build-id, count) to track crash signatures over time and
    alert when a new one appears or a rate spikes.
- **A crash-watcher agent** - a node-level service (systemd or a k8s DaemonSet) that consumes
  captured cores, triages them, and emits the above to your observability stack.

The CLI stays offline: it writes files other tools ingest rather than embedding an exporter; a
direct `--otel <endpoint>` exporter may come later behind a feature flag. Traces and spans are
not a target - a backtrace has no causal or temporal structure to map onto a span tree.

## License

Apache-2.0.
