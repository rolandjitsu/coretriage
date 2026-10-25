//! Compute a crash signature. Normalizes the crashing thread's backtrace (strip offsets,
//! inlining noise, and non-deterministic frames) and hashes it with BLAKE3 into a stable
//! fingerprint, so the same bug produces the same [`crate::model::Signature`] across cores.

use std::collections::BTreeMap;

use crate::model::{CrashReport, FaultKind, Frame, Signature, ThreadReport};

/// Frames that appear on every stack and carry no root-cause information. Dropping them keeps
/// a signature stable when the runtime below `main`, or the signal-delivery path above the
/// fault, differs between builds.
const NOISE: &[&str] = &[
    "__libc_start_main",
    "__libc_start_call_main",
    "_start",
    "abort",
    "raise",
    "__pthread_kill",
    "__restore_rt",
];

/// Length of the hex signature. 16 hex chars (64 bits of BLAKE3) make collisions negligible
/// for any realistic pile of cores while staying short enough to read and group by.
const HEX_LEN: usize = 16;

/// Compute the signature for a report: a crash is keyed on its crashing thread's normalized
/// backtrace; a hang is keyed on the set of threads' stall sites, independent of thread order.
pub(crate) fn compute(report: &CrashReport, top: usize) -> Signature {
    match report.fault {
        FaultKind::Signal { number, .. } => crash_signature(report, number, top),
        FaultKind::Hang => hang_signature(report),
    }
}

/// Signature of a fatal signal: hash the crashing thread's top-N non-noise frames.
fn crash_signature(report: &CrashReport, number: i32, top: usize) -> Signature {
    let frames = crashing_thread(report)
        .map(|t| t.frames.as_slice())
        .unwrap_or(&[]);
    let mut keys: Vec<String> = frames
        .iter()
        .filter(|f| !is_noise(f))
        .map(frame_key)
        .collect();
    if top > 0 {
        keys.truncate(top);
    }
    let hex = hash_hex(&keys);
    let signal = signal_label(number);
    let label = match keys.first() {
        Some(top) => format!("{signal} in {top}"),
        None => signal,
    };
    Signature { hex, label }
}

/// Signature of a hang: hash the sorted multiset of each thread's top non-noise frame, so the
/// fingerprint does not depend on the order the core lists threads in.
fn hang_signature(report: &CrashReport) -> Signature {
    let tops: Vec<&Frame> = report.threads.iter().filter_map(top_nonnoise).collect();
    let mut keys: Vec<String> = tops.iter().map(|f| frame_key(f)).collect();
    keys.sort();
    let hex = hash_hex(&keys);
    let label = match most_common(tops.iter().map(|f| display_name(f))) {
        Some(name) => format!("hang: {} threads in {}", report.threads.len(), name),
        None => format!("hang: {} threads", report.threads.len()),
    };
    Signature { hex, label }
}

/// The thread the fault is attributed to, or the first thread when none is marked.
fn crashing_thread(report: &CrashReport) -> Option<&ThreadReport> {
    match report.crashing_tid {
        Some(tid) => report.threads.iter().find(|t| t.tid == tid),
        None => report.threads.first(),
    }
}

/// The innermost frame of a thread that is not runtime noise.
fn top_nonnoise(thread: &ThreadReport) -> Option<&Frame> {
    thread.frames.iter().find(|f| !is_noise(f))
}

/// Whether a frame is a well-known noise frame to drop before hashing.
fn is_noise(frame: &Frame) -> bool {
    frame
        .function
        .as_deref()
        .is_some_and(|name| NOISE.contains(&name))
}

/// Normalized hash key for a frame: `module!function`, with placeholders when either is
/// unknown. Addresses and source lines are deliberately excluded so the key is build-stable.
fn frame_key(frame: &Frame) -> String {
    format!(
        "{}!{}",
        frame.module.as_deref().unwrap_or("?"),
        frame.function.as_deref().unwrap_or("<unknown>"),
    )
}

/// Human-friendly name for a frame in a label: its function, or the full key when unresolved.
fn display_name(frame: &Frame) -> String {
    frame.function.clone().unwrap_or_else(|| frame_key(frame))
}

/// BLAKE3 over the newline-joined keys, as the first [`HEX_LEN`] hex chars.
fn hash_hex(keys: &[String]) -> String {
    let mut hasher = blake3::Hasher::new();
    for (i, key) in keys.iter().enumerate() {
        if i > 0 {
            hasher.update(b"\n");
        }
        hasher.update(key.as_bytes());
    }
    hasher.finalize().to_hex().as_str()[..HEX_LEN].to_string()
}

/// The most frequent name, breaking ties on the smallest name for determinism.
fn most_common(names: impl Iterator<Item = String>) -> Option<String> {
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for name in names {
        *counts.entry(name).or_insert(0) += 1;
    }
    counts
        .into_iter()
        .max_by(|a, b| a.1.cmp(&b.1).then_with(|| b.0.cmp(&a.0)))
        .map(|(name, _)| name)
}

/// Signal name (e.g. `SIGSEGV`), or `signal N` for an uncommon one.
fn signal_label(number: i32) -> String {
    crate::report::signal_name(number)
        .map(str::to_string)
        .unwrap_or_else(|| format!("signal {number}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn crash_signature_labels_the_top_frame_and_drops_noise() {
        let report = signal_report(
            11,
            vec![
                frame("crasher", "gamma_segv"),
                frame("crasher", "beta"),
                frame("libc.so.6", "__libc_start_main"),
                frame("crasher", "_start"),
            ],
        );
        let sig = compute(&report, 0);
        assert_eq!(sig.label, "SIGSEGV in crasher!gamma_segv");
        assert_eq!(sig.hex.len(), 16);

        // Removing the noise frames by hand must not change the hash.
        let trimmed = signal_report(
            11,
            vec![frame("crasher", "gamma_segv"), frame("crasher", "beta")],
        );
        assert_eq!(compute(&trimmed, 0).hex, sig.hex);
    }

    #[test]
    fn crash_signature_honors_top_depth() {
        let deep = signal_report(
            11,
            vec![frame("app", "a"), frame("app", "b"), frame("app", "c")],
        );
        let shallow = signal_report(11, vec![frame("app", "a"), frame("app", "b")]);
        assert_eq!(compute(&deep, 2).hex, compute(&shallow, 0).hex);
        assert_ne!(compute(&deep, 0).hex, compute(&shallow, 0).hex);
    }

    #[test]
    fn hang_signature_is_thread_order_independent() {
        let a = thread(1, vec![frame("libc.so.6", "pthread_cond_wait")]);
        let b = thread(2, vec![frame("libc.so.6", "pthread_cond_wait")]);
        let c = thread(3, vec![frame("app", "poll_loop")]);
        let forward = hang_report(vec![a.clone(), b.clone(), c.clone()]);
        let shuffled = hang_report(vec![c, a, b]);
        assert_eq!(compute(&forward, 0).hex, compute(&shuffled, 0).hex);
        assert!(
            compute(&forward, 0)
                .label
                .starts_with("hang: 3 threads in ")
        );
    }

    proptest! {
        #[test]
        fn signature_is_deterministic(frames in frame_strategy()) {
            let a = signal_report(11, frames.clone());
            let b = signal_report(11, frames);
            prop_assert_eq!(compute(&a, 0).hex, compute(&b, 0).hex);
        }

        #[test]
        fn hang_fingerprint_ignores_thread_order(
            mut stacks in proptest::collection::vec(frame_strategy(), 1..6)
        ) {
            let threads: Vec<ThreadReport> = stacks
                .iter()
                .enumerate()
                .map(|(i, f)| thread(i as i32, f.clone()))
                .collect();
            let forward = hang_report(threads);
            stacks.reverse();
            let reversed: Vec<ThreadReport> = stacks
                .iter()
                .enumerate()
                .map(|(i, f)| thread(i as i32, f.clone()))
                .collect();
            prop_assert_eq!(compute(&forward, 0).hex, compute(&hang_report(reversed), 0).hex);
        }
    }

    // Helpers after the tests that use them, per the house rules.
    fn frame(module: &str, function: &str) -> Frame {
        Frame {
            module: Some(module.to_string()),
            function: Some(function.to_string()),
            file: None,
            line: None,
        }
    }

    fn thread(tid: i32, frames: Vec<Frame>) -> ThreadReport {
        ThreadReport {
            tid,
            name: None,
            frames,
        }
    }

    fn signal_report(number: i32, frames: Vec<Frame>) -> CrashReport {
        CrashReport {
            fault: FaultKind::Signal {
                number,
                address: None,
            },
            crashing_tid: Some(1),
            threads: vec![thread(1, frames)],
            signature: Signature::default(),
        }
    }

    fn hang_report(threads: Vec<ThreadReport>) -> CrashReport {
        CrashReport {
            fault: FaultKind::Hang,
            crashing_tid: None,
            threads,
            signature: Signature::default(),
        }
    }

    fn frame_strategy() -> impl Strategy<Value = Vec<Frame>> {
        proptest::collection::vec(
            ("[a-z]{1,6}", "[a-z_]{1,8}").prop_map(|(m, f)| frame(&m, &f)),
            1..8,
        )
    }
}
