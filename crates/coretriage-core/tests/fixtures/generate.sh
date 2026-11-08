#!/usr/bin/env bash
# Generate golden ELF core fixtures for coretriage, for the architecture it runs on.
#
# x86_64: run on a Linux x86_64 host. aarch64: run in a NATIVE arm64 Linux
# container - on Apple Silicon, e.g.:
#   podman run --rm -v "$PWD":/w -w /w docker.io/library/debian:bookworm-slim bash -c \
#     'apt-get update && apt-get install -y gcc gdb binutils file && bash generate.sh'
# Do not emulate the other arch (x86_64 under Rosetta/qemu-user): the cores come
# out as the host arch, not the guest.
#
# It writes the C sources, compiles them, produces a crash core per fault mode and
# a hang core, builds stripped + split-debug variants and an elfutils debug store,
# verifies them, and packs everything into coretriage-fixtures-<arch>.tar.gz next to
# where you ran it. Unpack x86_64 into tests/fixtures/, aarch64 into
# tests/fixtures/aarch64/, and re-gzip the cores (the test helper reads them gzipped).
#
# Needs: gcc, gdb, binutils (readelf, strip, objcopy), file, tar. The crash cores set
# kernel.core_pattern, which needs root; the script saves and restores the
# original and prompts for sudo. Without sudo it falls back to gdb-generated
# cores (slightly different from kernel cores, but fine as fixtures).
set -euo pipefail

ARCH="$(uname -m)"

need() { command -v "$1" >/dev/null || { echo "missing tool: $1 (install gcc gdb binutils file)"; exit 1; }; }
need gcc; need gdb; need readelf; need strip; need objcopy; need file; need tar

START="$PWD"
OUT="$(mktemp -d)"
cd "$OUT"
echo "work dir: $OUT"

cat > crasher.c <<'EOF'
/* A multi-frame call chain so the core has a meaningful backtrace:
   main -> alpha -> beta -> gamma -> fault. argv[1] selects the fault mode. */
#include <stdlib.h>
#include <string.h>

static void gamma_segv(void) {
    volatile int *p = (volatile int *)0;
    *p = 42;            /* SIGSEGV */
}

static void gamma_abort(void) {
    abort();            /* SIGABRT */
}

static void beta(const char *mode) {
    if (strcmp(mode, "abort") == 0) {
        gamma_abort();
    } else {
        gamma_segv();
    }
}

static void alpha(const char *mode) {
    beta(mode);
}

int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "segv";
    alpha(mode);
    return 0;
}
EOF

cat > hang.c <<'EOF'
/* Several threads park forever on a condvar that is never signaled, so a
   gcore snapshot shows multiple threads stuck in futex. */
#include <pthread.h>
#include <unistd.h>

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t never = PTHREAD_COND_INITIALIZER;

static void *worker(void *arg) {
    (void)arg;
    pthread_mutex_lock(&lock);
    pthread_cond_wait(&never, &lock);   /* never returns */
    pthread_mutex_unlock(&lock);
    return 0;
}

int main(void) {
    pthread_t t[3];
    for (int i = 0; i < 3; i++) {
        pthread_create(&t[i], 0, worker, 0);
    }
    pause();                             /* main parks too */
    return 0;
}
EOF

echo "=== compile ==="
gcc -g -O0 -fno-omit-frame-pointer -o crasher crasher.c
gcc -g -O0 -fno-omit-frame-pointer -pthread -o hang hang.c

echo "=== split-debug variants + debug store ==="
# For each binary, split the DWARF into a .debug file and strip the binary of it
# (strip --strip-debug keeps .eh_frame, .symtab, and the build-id), then lay both
# out in an elfutils debug store keyed by build-id:
#   debugstore/.build-id/<ab>/<rest>        the stripped executable (for unwinding)
#   debugstore/.build-id/<ab>/<rest>.debug  the separated DWARF (for symbolication)
mkdir -p debugstore/.build-id
make_split() {
    local bin="$1" bid ab rest
    bid="$(readelf -n "$bin" | awk '/Build ID/ {print $NF; exit}')"
    [ -n "$bid" ] || { echo "no build-id for $bin"; exit 1; }
    objcopy --only-keep-debug "$bin" "$bin.debug"
    cp "$bin" "$bin.stripped"
    strip --strip-debug "$bin.stripped"
    ab="${bid:0:2}"; rest="${bid:2}"
    mkdir -p "debugstore/.build-id/$ab"
    cp "$bin.stripped" "debugstore/.build-id/$ab/$rest"
    cp "$bin.debug"    "debugstore/.build-id/$ab/$rest.debug"
    echo "  $bin ($bid) -> $bin.stripped, $bin.debug, debugstore/.build-id/$ab/{$rest,$rest.debug}"
}
make_split crasher
make_split hang

echo "=== crash cores ==="
if ORIG="$(cat /proc/sys/kernel/core_pattern)" \
   && echo 'core.%e.%p' | sudo tee /proc/sys/kernel/core_pattern >/dev/null 2>&1; then
    trap 'printf "%s\n" "$ORIG" | sudo tee /proc/sys/kernel/core_pattern >/dev/null 2>&1 || true' EXIT
    ulimit -c unlimited
    ( ./crasher segv )  || true; mv core.crasher.* segv.core
    ( ./crasher abort ) || true; mv core.crasher.* abort.core
    echo "(kernel cores via core_pattern)"
else
    echo "(no sudo for core_pattern; using gdb generate-core-file)"
    gdb -q -batch -ex run -ex 'generate-core-file segv.core'  --args ./crasher segv  >/dev/null 2>&1 || true
    gdb -q -batch -ex run -ex 'generate-core-file abort.core' --args ./crasher abort >/dev/null 2>&1 || true
fi

echo "=== hang core (gcore; no root) ==="
./hang & HPID=$!
sleep 1
gcore -o hangcore "$HPID" >/dev/null 2>&1 || { echo "gcore failed (check kernel.yama.ptrace_scope)"; kill -9 "$HPID" 2>/dev/null || true; exit 1; }
kill -9 "$HPID" 2>/dev/null || true
mv hangcore.* hang.core

echo "=== verify ==="
file segv.core abort.core hang.core
for c in segv abort hang; do
    echo "--- $c.core ---"
    echo "threads (NT_PRSTATUS): $(readelf -n "$c.core" | grep -c NT_PRSTATUS)"
    readelf -n "$c.core" | grep -Ei 'NT_FILE|SIGINFO|signal' | head -5 || true
done
echo "=== build-ids ==="
readelf -n crasher | grep -A1 'Build ID' || true
readelf -n hang    | grep -A1 'Build ID' || true
echo "=== segv backtrace (expect main -> alpha -> beta -> gamma_segv) ==="
gdb -batch -ex bt crasher segv.core 2>/dev/null | head -20

echo "=== sizes ==="
ls -la crasher.c hang.c crasher hang segv.core abort.core hang.core
ls -la crasher.stripped crasher.debug hang.stripped hang.debug
find debugstore -type f -exec ls -la {} +

echo "=== pack ==="
TARBALL="$START/coretriage-fixtures-${ARCH}.tar.gz"
tar czf "$TARBALL" \
    crasher.c hang.c crasher hang \
    crasher.stripped crasher.debug hang.stripped hang.debug debugstore \
    segv.core abort.core hang.core
echo
case "$ARCH" in
    x86_64)  DEST="tests/fixtures/" ;;
    aarch64) DEST="tests/fixtures/aarch64/" ;;
    *)       DEST="tests/fixtures/$ARCH/" ;;
esac
echo "DONE ($ARCH). Copy back: $TARBALL -> unpack into $DEST and re-gzip the cores."
ls -la "$TARBALL"
