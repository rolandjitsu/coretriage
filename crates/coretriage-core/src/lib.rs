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
//! Both entry points are fully wired: [`triage`]'s frames carry module, function, and source
//! location, and [`triage_batch`] triages a directory in parallel and ranks the buckets.

#![warn(missing_docs)]

use std::path::{Path, PathBuf};

use rayon::prelude::*;

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
    let symbolizer = crate::symbolize::Symbolizer::new();
    let report = triage_with(&data, opts, &symbolizer)?;
    let signature = crate::signature::compute(&report, opts.top);
    tracing::debug!(hex = %signature.hex, label = %signature.label, "crash signature");
    Ok(report)
}

/// Triage every core under `dir` and group the reports into [`Bucket`]s by signature.
///
/// Cores are triaged in parallel and bucketed by signature, ranked most-frequent first. A
/// core that fails to parse is logged and skipped rather than failing the whole batch.
///
/// # Errors
///
/// Returns an error only if `dir` cannot be read.
pub fn triage_batch(dir: &Path, opts: &TriageOptions) -> Result<Vec<Bucket>> {
    let mut paths = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_file() {
            paths.push(path);
        }
    }

    // One symbolizer shared across cores so each module's DWARF is parsed once for the batch.
    let symbolizer = crate::symbolize::Symbolizer::new();
    let reports: Vec<(Signature, CrashReport)> = paths
        .par_iter()
        .filter_map(|path| match std::fs::read(path) {
            Ok(data) => match triage_with(&data, opts, &symbolizer) {
                Ok(report) => {
                    let signature = crate::signature::compute(&report, opts.top);
                    Some((signature, report))
                }
                Err(err) => {
                    tracing::warn!(core = %path.display(), %err, "skipping core that failed to parse");
                    None
                }
            },
            Err(err) => {
                tracing::warn!(core = %path.display(), %err, "skipping unreadable core");
                None
            }
        })
        .collect();

    Ok(crate::aggregate::bucket(reports))
}

/// Shared pipeline for one core's bytes: parse, resolve modules, unwind, and symbolicate into
/// a [`CrashReport`]. `symbolizer` carries the cross-core symbol cache.
fn triage_with(
    data: &[u8],
    opts: &TriageOptions,
    symbolizer: &crate::symbolize::Symbolizer,
) -> Result<CrashReport> {
    let parsed = crate::core::parse(data)?;

    let map = crate::maps::build(&parsed, data, opts);
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

    let stacks = crate::unwind::unwind(&parsed, data, &map);
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
    Ok(CrashReport {
        fault: parsed.fault,
        threads,
        crashing_tid: parsed.crashing_tid,
    })
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

    #[test]
    fn batch_buckets_distinct_crashes_and_counts() {
        let dir = TempDir::new("batch");
        dir.put_core("segv");
        dir.put_core("abort");
        dir.put_core("hang");
        // A second segv core (same crash) must land in the same bucket, giving it count 2.
        std::fs::copy(dir.path.join("segv.core"), dir.path.join("segv-dup.core"))
            .expect("duplicate segv core");

        let opts = TriageOptions {
            exe: Some(fixture_path("crasher")),
            ..Default::default()
        };
        let buckets = triage_batch(&dir.path, &opts).expect("triage batch");

        // Three distinct signatures: the segv (x2), the abort, and the hang.
        assert_eq!(buckets.len(), 3, "buckets: {buckets:#?}");
        // Ranked most-frequent first, so the duplicated segv leads with count 2.
        assert_eq!(buckets[0].count, 2);
        assert!(
            buckets[0]
                .signature
                .label
                .starts_with("SIGSEGV in crasher!"),
            "label: {}",
            buckets[0].signature.label
        );

        let labels: Vec<&str> = buckets.iter().map(|b| b.signature.label.as_str()).collect();
        assert!(
            labels.iter().any(|l| l.starts_with("SIGABRT in ")),
            "labels: {labels:?}"
        );
        assert!(
            labels.iter().any(|l| l.starts_with("hang:")),
            "labels: {labels:?}"
        );
        let abort = buckets
            .iter()
            .find(|b| b.signature.label.starts_with("SIGABRT in "))
            .expect("abort bucket");
        assert_eq!(abort.count, 1);
    }
}
