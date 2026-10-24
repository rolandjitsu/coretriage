# coretriage

[![crates.io](https://img.shields.io/crates/v/coretriage?style=flat-square)](https://crates.io/crates/coretriage)
[![docs.rs](https://img.shields.io/docsrs/coretriage?style=flat-square)](https://docs.rs/coretriage)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue?style=flat-square)](https://github.com/rolandjitsu/coretriage/blob/main/LICENSE)

Triage Linux ELF core dumps offline: unwind every thread, symbolicate the frames, compute a
stable crash signature, and bucket a pile of cores into distinct crashes. Handles both crashes
(a fatal signal) and hangs (a core captured from a live, stuck process with `gcore`).

## Install

```sh
cargo install coretriage    # from crates.io
cargo binstall coretriage   # prebuilt binary, no compile
```

Prebuilt binaries for Linux and macOS are attached to each
[release](https://github.com/rolandjitsu/coretriage/releases).

## Use

```sh
coretriage core.1234                      # triage one core
coretriage --exe ./target/release/app core.1234
coretriage cores/ --format json           # batch a directory, bucket, emit JSON
```

Full design, pipeline, and scope are in the
[repository README](https://github.com/rolandjitsu/coretriage).

## License

Apache-2.0.
