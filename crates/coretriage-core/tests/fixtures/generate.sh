#!/usr/bin/env bash
# Generate golden x86_64 ELF core fixtures for coretriage.
#
# Run on a Linux x86_64 host. It cannot run on Apple Silicon: emulated cores
# come out arm64 (Rosetta/qemu-user dump the translator, not the guest).
#
# It writes the C sources, compiles them, produces a crash core per fault mode
# and a hang core, verifies them, and packs everything into
# coretriage-fixtures.tar.gz next to where you ran it, ready to copy back.
#
# Needs: gcc, gdb, binutils (readelf), file, tar. The crash cores set
# kernel.core_pattern, which needs root; the script saves and restores the
# original and prompts for sudo. Without sudo it falls back to gdb-generated
# cores (slightly different from kernel cores, but fine as fixtures).
set -euo pipefail

need() { command -v "$1" >/dev/null || { echo "missing tool: $1 (install gcc gdb binutils file)"; exit 1; }; }
need gcc; need gdb; need readelf; need file; need tar

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

echo "=== pack ==="
TARBALL="$START/coretriage-fixtures.tar.gz"
tar czf "$TARBALL" crasher.c hang.c crasher hang segv.core abort.core hang.core
echo
echo "DONE. Copy this back to your Mac: $TARBALL"
ls -la "$TARBALL"
