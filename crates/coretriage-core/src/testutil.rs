//! Test-only helpers for loading the gzipped core fixtures.

use std::io::Read;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

use flate2::read::GzDecoder;

/// Decompress a named core fixture (e.g. "segv" loads `tests/fixtures/segv.core.gz`).
pub(crate) fn load_core(name: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(format!("{name}.core.gz"));
    let file = std::fs::File::open(&path)
        .unwrap_or_else(|e| panic!("open fixture {}: {e}", path.display()));
    let mut buf = Vec::new();
    GzDecoder::new(file)
        .read_to_end(&mut buf)
        .expect("decompress core fixture");
    buf
}

/// Path to a committed fixture file by name, e.g. the `crasher` and `hang` binaries.
pub(crate) fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

/// A unique temporary directory, removed on drop, for tests that need core files on disk
/// (the entry points take paths, and the fixtures are stored gzipped).
pub(crate) struct TempDir {
    /// The directory's path.
    pub path: PathBuf,
}

impl TempDir {
    /// Create a fresh, uniquely named temporary directory tagged for readability.
    pub fn new(tag: &str) -> Self {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("coretriage-{tag}-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&path).expect("create temp dir");
        Self { path }
    }

    /// Decompress a core fixture into this directory as `<name>.core`, returning its path.
    pub fn put_core(&self, name: &str) -> PathBuf {
        let dest = self.path.join(format!("{name}.core"));
        std::fs::write(&dest, load_core(name)).expect("write temp core");
        dest
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}
