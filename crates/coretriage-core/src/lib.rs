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
//! The pipeline is not implemented yet; both entry points return [`Error::Unimplemented`].

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
/// # Errors
///
/// Returns [`Error::Unimplemented`] until the pipeline lands.
pub fn triage(_core_path: &Path, _opts: &TriageOptions) -> Result<CrashReport> {
    Err(Error::Unimplemented)
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
    fn triage_is_unimplemented_for_now() {
        let opts = TriageOptions::default();
        let result = triage(Path::new("/nonexistent/core"), &opts);
        assert!(matches!(result, Err(Error::Unimplemented)));
    }
}
