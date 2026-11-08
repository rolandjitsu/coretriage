# Core-dump fixtures

Golden Linux ELF core dumps for the parser tests, with the binaries that produced them. The
files below are x86_64; the aarch64 equivalents live in `aarch64/`. Cores are stored gzipped
(they are mostly zero pages) and decompressed by the test helper in `src/testutil.rs`.

| file | what it is |
| --- | --- |
| `segv.core.gz` | single-threaded SIGSEGV (`crasher segv`): main -> alpha -> beta -> gamma_segv |
| `abort.core.gz` | single-threaded SIGABRT (`crasher abort`) |
| `hang.core.gz` | 4 threads parked in `pthread_cond_wait`, captured live with `gcore` (no signal) |
| `crasher` | the binary behind `segv.core.gz` and `abort.core.gz` (build-id `2d498445...`) |
| `hang` | the binary behind `hang.core.gz` (build-id `3c4f5082...`) |

The split-debug variants below model a stripped production binary plus its separate debuginfo,
for the build-id resolution tests. Regenerate them with `generate.sh` on x86_64 Linux (see below)
whenever the fixtures change.

| file | what it is |
| --- | --- |
| `crasher.stripped`, `hang.stripped` | the binaries with `strip --strip-debug` (keep `.eh_frame`, `.symtab`, and the build-id; no DWARF) |
| `crasher.debug`, `hang.debug` | the separated DWARF (`objcopy --only-keep-debug`) |
| `debugstore/` | an elfutils debug store: `.build-id/<ab>/<rest>` is the stripped executable and `.build-id/<ab>/<rest>.debug` its DWARF, for both build-ids |

## aarch64

`aarch64/` holds the aarch64 equivalents, for the cross-architecture parser and unwinder tests:

| file | what it is |
| --- | --- |
| `aarch64/segv.core.gz` | single-threaded SIGSEGV from the same `crasher`, built for aarch64 |
| `aarch64/crasher` | the aarch64 binary behind it (unstripped; build-id `e15b7d42...`) |

## Regenerating

`generate.sh` builds the fixtures for the architecture it runs on and packs
`coretriage-fixtures-<arch>.tar.gz`. Copy it back, unpack (x86_64 here, aarch64 into `aarch64/`),
and re-gzip the cores. The binaries, their split-debug variants, and the cores are a matched set
(shared build-ids), so replace them together.

- **x86_64:** run `./generate.sh` on an x86_64 Linux host (do not emulate it on Apple Silicon -
  the cores come out arm64, not x86_64).
- **aarch64:** run it in a native arm64 Linux container, e.g. on Apple Silicon with podman:
  `podman run --rm -v "$PWD":/w -w /w docker.io/library/debian:bookworm-slim bash -c 'apt-get update && apt-get install -y gcc gdb binutils file && bash generate.sh'`
