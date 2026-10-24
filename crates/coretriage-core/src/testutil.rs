//! Test-only helpers for loading the gzipped core fixtures.

use std::io::Read;
use std::path::PathBuf;

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
