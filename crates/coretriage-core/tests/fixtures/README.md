# Core-dump fixtures

Golden x86_64 Linux ELF core dumps for the parser tests, with the binaries that produced
them. Cores are stored gzipped (they are mostly zero pages) and decompressed by the test
helper in `src/testutil.rs`.

| file | what it is |
| --- | --- |
| `segv.core.gz` | single-threaded SIGSEGV (`crasher segv`): main -> alpha -> beta -> gamma_segv |
| `abort.core.gz` | single-threaded SIGABRT (`crasher abort`) |
| `hang.core.gz` | 4 threads parked in `pthread_cond_wait`, captured live with `gcore` (no signal) |
| `crasher` | the binary behind `segv.core.gz` and `abort.core.gz` (build-id `d16533ec...`) |
| `hang` | the binary behind `hang.core.gz` (build-id `62d4761a...`) |

## Regenerating

Run `./generate.sh` on an **x86_64 Linux** host (cores cannot be produced on Apple Silicon:
emulation yields arm64 cores). It writes the sources, compiles, dumps the cores, verifies
them, and packs `coretriage-fixtures.tar.gz`. Copy that back, unpack here, and re-gzip the
cores. The binaries and cores are a matched set (shared build-ids), so replace them together.
