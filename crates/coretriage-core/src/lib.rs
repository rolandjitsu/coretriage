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
//! [`triage`] is fully wired: its frames carry module, function, and source location.
//! [`triage_batch`] returns [`Error::Unimplemented`] until bucketing lands.

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
/// Reads the core at `core_path`, recovers its threads and fault, unwinds each thread, and
/// symbolicates the frames using the modules resolved from `opts`.
///
/// # Errors
///
/// Returns an error if `core_path` cannot be read or is not a parseable ELF core.
pub fn triage(core_path: &Path, opts: &TriageOptions) -> Result<CrashReport> {
    let data = std::fs::read(core_path)?;
    let parsed = crate::core::parse(&data)?;

    let map = crate::maps::build(&parsed, &data, opts);
    for m in &map.modules {
        tracing::debug!(
            module = %m.name,
            recorded = ?m.recorded_path,
            range = ?m.avma_range,
            base = m.base_avma,
            load_bias = m.load_bias,
            on_disk = ?m.on_disk,
            build_id = ?m.build_id,
            "resolved module",
        );
    }

    let stacks = crate::unwind::unwind(&parsed, &data, &map);
    let symbolizer = crate::symbolize::Symbolizer::new();
    let threads = parsed
        .threads
        .iter()
        .zip(stacks)
        .map(|(t, mut addrs)| {
            if opts.top > 0 {
                addrs.truncate(opts.top);
            }
            ThreadReport {
                tid: t.tid,
                name: None,
                frames: symbolizer.symbolize_thread(&map, &addrs),
            }
        })
        .collect();
    let report = CrashReport {
        fault: parsed.fault,
        threads,
        crashing_tid: parsed.crashing_tid,
    };
    let signature = crate::signature::compute(&report, opts.top);
    tracing::debug!(hex = %signature.hex, label = %signature.label, "crash signature");
    Ok(report)
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
    use crate::testutil::{TempDir, fixture_path};

    #[test]
    fn triage_errors_on_missing_core() {
        let opts = TriageOptions::default();
        let result = triage(Path::new("/nonexistent/core"), &opts);
        assert!(matches!(result, Err(Error::Io(_))));
    }

    #[test]
    fn segv_backtrace_resolves_c_source_frames() {
        let dir = TempDir::new("segv");
        let core = dir.put_core("segv");
        let opts = TriageOptions {
            exe: Some(fixture_path("crasher")),
            top: 0,
            ..Default::default()
        };
        let report = triage(&core, &opts).expect("triage segv core");

        let tid = report.crashing_tid.expect("a crashing thread");
        let thread = report
            .threads
            .iter()
            .find(|t| t.tid == tid)
            .expect("crashing thread in report");

        let top: Vec<(&str, u32)> = thread
            .frames
            .iter()
            .take(4)
            .map(|f| (f.function.as_deref().unwrap_or("?"), f.line.unwrap_or(0)))
            .collect();
        assert_eq!(
            top,
            vec![("gamma_segv", 8), ("beta", 19), ("alpha", 24), ("main", 29),]
        );
        for frame in thread.frames.iter().take(4) {
            assert_eq!(frame.module.as_deref(), Some("crasher"));
            assert!(
                frame
                    .file
                    .as_deref()
                    .is_some_and(|f| f.ends_with("crasher.c")),
                "unexpected file: {:?}",
                frame.file
            );
        }
    }
}
