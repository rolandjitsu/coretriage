//! `coretriage-core` triages raw Linux ELF core dumps offline: it parses a core, unwinds
//! every thread's stack, symbolicates the frames, computes a stable crash signature, and
//! groups many cores into buckets by that signature. It handles both crashes (a fatal
//! signal) and hangs (a core captured from a live, stuck process).
//!
//! The pipeline is split across private modules - `core` (ELF core parsing), `maps`
//! (module map), `unwind` (stack unwinding), `symbolize` (symbolication), `signature`
//! (normalization and hashing), `aggregate` (bucketing), and `report` (rendering). The
//! public surface is the data model in [`model`], the [`error`] type, and two entry
//! points, [`triage`] and [`triage_batch`]. See the repository README for how the stages
//! fit together.
//!
//! Unwinding and symbolication are not wired up yet, so [`triage`] returns threads without
//! frames, and [`triage_batch`] returns [`Error::Unimplemented`].

#![warn(missing_docs)]

use std::path::{Path, PathBuf};

pub mod error;
pub mod model;

mod aggregate;
mod core;
mod maps;
pub mod report;
mod signature;
mod symbolize;
mod unwind;

#[cfg(test)]
mod testutil;

pub use error::{Error, Result};
pub use model::{Bucket, CrashReport, FaultKind, Frame, Module, Signature, ThreadReport};
pub use report::{Emitter, JsonEmitter, TextEmitter};

/// Inputs that control a triage run.
#[derive(Debug, Clone, Default)]
pub struct TriageOptions {
    /// The crashing executable, when it cannot be located from the core itself.
    pub exe: Option<PathBuf>,
    /// Extra roots to resolve recorded module paths against (sysroots, debug stores).
    pub sysroot: Vec<PathBuf>,
    /// Maximum number of frames to keep per thread; 0 means keep all.
    pub top: usize,
}

/// Triage a single core dump into a [`CrashReport`].
///
/// Reads the core at `core_path` and recovers its threads and fault. Frames are empty until
/// unwinding and symbolication land; `opts` takes effect then.
///
/// # Errors
///
/// Returns an error if `core_path` cannot be read or is not a parseable ELF core.
pub fn triage(core_path: &Path, opts: &TriageOptions) -> Result<CrashReport> {
    // exe/sysroot/top are consumed once module resolution, unwinding, and symbolication land.
    let _ = opts;
    let data = std::fs::read(core_path)?;
    let parsed = crate::core::parse(&data)?;
    let threads = parsed
        .threads
        .iter()
        .map(|t| ThreadReport {
            tid: t.tid,
            name: None,
            frames: Vec::new(),
        })
        .collect();
    Ok(CrashReport {
        fault: parsed.fault,
        threads,
        crashing_tid: parsed.crashing_tid,
    })
}

/// Triage every core under `dir` and group the reports into [`Bucket`]s by signature.
///
/// # Errors
///
/// Returns [`Error::Unimplemented`] until the pipeline lands.
pub fn triage_batch(_dir: &Path, _opts: &TriageOptions) -> Result<Vec<Bucket>> {
    Err(Error::Unimplemented)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn triage_errors_on_missing_core() {
        let opts = TriageOptions::default();
        let result = triage(Path::new("/nonexistent/core"), &opts);
        assert!(matches!(result, Err(Error::Io(_))));
    }
}
