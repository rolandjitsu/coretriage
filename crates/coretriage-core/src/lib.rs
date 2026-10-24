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

/// Triage a single core dump at `core_path` into a [`CrashReport`].
///
/// Reads the core, recovers its threads and fault, unwinds each thread, and symbolicates the
/// frames using the modules resolved from `opts`. A convenience wrapper over [`triage_bytes`].
///
/// # Errors
///
/// Returns an error if `core_path` cannot be read or is not a parseable ELF core.
pub fn triage(core_path: &Path, opts: &TriageOptions) -> Result<CrashReport> {
    let data = std::fs::read(core_path)?;
    triage_bytes(&data, opts)
}

/// Triage a core dump already held in memory into a [`CrashReport`].
///
/// Identical to [`triage`] but takes the core's bytes directly, for in-memory cores and for
/// fuzzing the parser. Malformed input returns an error; it never panics.
///
/// # Errors
///
/// Returns an error if `data` is not a parseable ELF core.
pub fn triage_bytes(data: &[u8], opts: &TriageOptions) -> Result<CrashReport> {
    let symbolizer = crate::symbolize::Symbolizer::new();
    let report = triage_with(data, opts, &symbolizer)?;
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
    use crate::testutil::{TempDir, fixture_path, load_core};

    #[test]
    fn triage_errors_on_missing_core() {
        let opts = TriageOptions::default();
        let result = triage(Path::new("/nonexistent/core"), &opts);
        assert!(matches!(result, Err(Error::Io(_))));
    }

    #[test]
    fn truncated_cores_error_without_panic() {
        let core = load_core("segv");
        let opts = TriageOptions::default();
        // Every prefix of a real core must return, never panic. A prefix that still holds
        // intact notes may legitimately parse (truncating only the memory image is tolerated),
        // so the sweep only asserts the absence of panics.
        for len in (0..core.len()).step_by(997) {
            let _ = triage_bytes(&core[..len], &opts);
        }
        // Prefixes that cut the ELF header or the program-header table must error.
        assert!(triage_bytes(&core[..8], &opts).is_err());
        assert!(triage_bytes(&core[..256], &opts).is_err());
    }

    #[test]
    fn bogus_nt_file_count_is_rejected_without_ooming() {
        // A hostile NT_FILE claims u64::MAX mappings in a 16-byte descriptor. The parser must
        // reject it (here the whole core also lacks NT_PRSTATUS) without allocating on the
        // count; completing this test without OOM or panic is the robustness check.
        let core = core_with_bogus_nt_file();
        assert!(triage_bytes(&core, &TriageOptions::default()).is_err());
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

    // Helpers after the tests that use them, per the house rules.

    /// A minimal ELF core carrying one PT_NOTE with a single NT_FILE note that claims
    /// `u64::MAX` mappings. Used to check the parser bounds the count rather than allocating.
    fn core_with_bogus_nt_file() -> Vec<u8> {
        const NT_FILE: u32 = 0x4649_4c45;
        // Note: name "CORE\0" padded to 8 bytes, then a 16-byte descriptor.
        let mut note = Vec::new();
        note.extend_from_slice(&5u32.to_le_bytes()); // n_namesz
        note.extend_from_slice(&16u32.to_le_bytes()); // n_descsz
        note.extend_from_slice(&NT_FILE.to_le_bytes()); // n_type
        note.extend_from_slice(b"CORE\0\0\0\0"); // name, padded to 4 bytes
        note.extend_from_slice(&u64::MAX.to_le_bytes()); // count
        note.extend_from_slice(&4096u64.to_le_bytes()); // page_size

        let mut core = vec![0u8; 64 + 56];
        core[0..4].copy_from_slice(b"\x7fELF");
        core[4] = 2; // ELFCLASS64
        core[5] = 1; // ELFDATA2LSB
        core[6] = 1; // EI_VERSION
        core[16..18].copy_from_slice(&4u16.to_le_bytes()); // e_type = ET_CORE
        core[18..20].copy_from_slice(&0x3eu16.to_le_bytes()); // e_machine = x86_64
        core[20..24].copy_from_slice(&1u32.to_le_bytes()); // e_version
        core[32..40].copy_from_slice(&64u64.to_le_bytes()); // e_phoff
        core[52..54].copy_from_slice(&64u16.to_le_bytes()); // e_ehsize
        core[54..56].copy_from_slice(&56u16.to_le_bytes()); // e_phentsize
        core[56..58].copy_from_slice(&1u16.to_le_bytes()); // e_phnum

        let ph = 64;
        core[ph..ph + 4].copy_from_slice(&4u32.to_le_bytes()); // p_type = PT_NOTE
        core[ph + 8..ph + 16].copy_from_slice(&120u64.to_le_bytes()); // p_offset
        core[ph + 32..ph + 40].copy_from_slice(&(note.len() as u64).to_le_bytes()); // p_filesz
        core[ph + 48..ph + 56].copy_from_slice(&1u64.to_le_bytes()); // p_align

        core.extend_from_slice(&note);
        core
    }
}
