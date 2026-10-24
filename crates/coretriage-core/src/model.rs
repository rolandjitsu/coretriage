//! The domain model: the types that describe a parsed core and its triage result.
//!
//! These types are the public contract between the pipeline stages and any consumer
//! (the CLI, a service, a test). They are serializable so a report can be emitted as
//! JSON and a bucket set can be persisted.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// A module (the executable or a shared object) mapped into the crashed process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Module {
    /// Path of the module on the origin system, as recorded in the core's `NT_FILE` note.
    pub path: PathBuf,
    /// Virtual address the module's text segment was loaded at (its load bias).
    pub load_bias: u64,
    /// GNU build-id as lowercase hex, when the module carries one.
    pub build_id: Option<String>,
}

/// A single stack frame in a thread's backtrace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Frame {
    /// Name of the [`Module`] the instruction pointer falls in, if it was attributed.
    pub module: Option<String>,
    /// Demangled function name, if symbolication resolved one.
    pub function: Option<String>,
    /// Source file, if debug info resolved one.
    pub file: Option<String>,
    /// 1-based source line, if debug info resolved one.
    pub line: Option<u32>,
}

/// One thread recovered from the core, with its unwound frames.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThreadReport {
    /// Kernel thread id (TID).
    pub tid: i32,
    /// Thread name, when the core records one.
    pub name: Option<String>,
    /// Frames ordered innermost first (the crash or stall site is `frames[0]`).
    pub frames: Vec<Frame>,
}

/// What took the process down.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FaultKind {
    /// Terminated by a fatal signal (SIGSEGV, SIGABRT, ...); carries the signal number.
    Signal(i32),
    /// No fatal signal: a core captured from a live, hung process (e.g. via `gcore`).
    Hang,
}

/// The triage result for a single core.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrashReport {
    /// The fault that produced the core.
    pub fault: FaultKind,
    /// Every thread recovered from the core.
    pub threads: Vec<ThreadReport>,
    /// TID of the crashing (or stalled) thread, when one can be identified.
    pub crashing_tid: Option<i32>,
}

/// A stable fingerprint of a crash, used to group cores that share a root cause.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature {
    /// Hex-encoded hash of the normalized crashing backtrace.
    pub hex: String,
    /// Short human-readable label, e.g. the top resolved frame.
    pub label: String,
}

/// A group of cores that hash to the same [`Signature`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bucket {
    /// The signature every core in this bucket shares.
    pub signature: Signature,
    /// How many cores fell into this bucket.
    pub count: usize,
    /// A representative report for the bucket, e.g. the first core seen.
    pub representative: CrashReport,
}
