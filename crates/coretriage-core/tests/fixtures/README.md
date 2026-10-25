# Core-dump fixtures

Golden x86_64 Linux ELF core dumps for the parser tests, with the binaries that produced
them. Cores are stored gzipped (they are mostly zero pages) and decompressed by the test
helper in `src/testutil.rs`.

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

## Regenerating

Run `./generate.sh` on an **x86_64 Linux** host (cores cannot be produced on Apple Silicon:
emulation yields arm64 cores). It writes the sources, compiles, dumps the cores, builds the
stripped + split-debug variants and the `debugstore/` tree, verifies everything, and packs
`coretriage-fixtures.tar.gz`. Copy that back, unpack here, and re-gzip the cores. The binaries,
their split-debug variants, and the cores are a matched set (shared build-ids), so replace them
together.
