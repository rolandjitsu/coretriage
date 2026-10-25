//! Render triage results for output. A [`CrashReport`] or a set of [`Bucket`]s is written
//! through an [`Emitter`], so each output format is one implementor and new formats are added
//! without touching the pipeline. v0.1 ships [`TextEmitter`] and [`JsonEmitter`]; folded-stack,
//! pprof, and OpenTelemetry emitters are on the roadmap (see the repository README).

use std::io::Write;

use serde::Serialize;

use crate::Result;
use crate::model::{Bucket, CrashReport, FaultKind, Frame};

/// A way to render triage results to a writer.
///
/// Each implementor is one output format. The pipeline produces the data model in
/// [`crate::model`]; emitters are the only place that knows how to serialize it, so adding a
/// format (folded stacks, pprof, OpenTelemetry) is a new implementor, not a change to callers.
pub trait Emitter {
    /// Render a single core's [`CrashReport`].
    fn emit_report(&self, report: &CrashReport, out: &mut dyn Write) -> Result<()>;

    /// Render a bucketed batch result. Buckets are expected most-frequent first.
    fn emit_buckets(&self, buckets: &[Bucket], out: &mut dyn Write) -> Result<()>;
}

/// Human-readable text: a fault line, then each thread and its frames.
#[derive(Debug, Default, Clone, Copy)]
pub struct TextEmitter;

impl Emitter for TextEmitter {
    fn emit_report(&self, report: &CrashReport, out: &mut dyn Write) -> Result<()> {
        write_report(report, out)
    }

    fn emit_buckets(&self, buckets: &[Bucket], out: &mut dyn Write) -> Result<()> {
        for (rank, bucket) in buckets.iter().enumerate() {
            let count = bucket.count;
            let noun = if count == 1 { "core" } else { "cores" };
            writeln!(
                out,
                "[{rank}] {count} {noun}  {hex}  {label}",
                rank = rank + 1,
                hex = bucket.signature.hex,
                label = bucket.signature.label,
            )?;
        }
        Ok(())
    }
}

/// JSON, for machine consumption. `pretty` selects indented output over compact.
#[derive(Debug, Default, Clone, Copy)]
pub struct JsonEmitter {
    /// Indent the output when true; emit compact single-line JSON when false.
    pub pretty: bool,
}

impl Emitter for JsonEmitter {
    fn emit_report(&self, report: &CrashReport, out: &mut dyn Write) -> Result<()> {
        self.write_json(report, out)
    }

    fn emit_buckets(&self, buckets: &[Bucket], out: &mut dyn Write) -> Result<()> {
        self.write_json(buckets, out)
    }
}

impl JsonEmitter {
    fn write_json<T: Serialize + ?Sized>(&self, value: &T, out: &mut dyn Write) -> Result<()> {
        if self.pretty {
            serde_json::to_writer_pretty(&mut *out, value)?;
        } else {
            serde_json::to_writer(&mut *out, value)?;
        }
        writeln!(out)?;
        Ok(())
    }
}

fn write_report(report: &CrashReport, out: &mut dyn Write) -> Result<()> {
    match &report.fault {
        FaultKind::Signal { number, address } => {
            let number = *number;
            match (signal_name(number), *address) {
                (Some(name), Some(addr)) => {
                    writeln!(out, "fault: signal {number} ({name}) at {addr:#x}")?
                }
                (Some(name), None) => writeln!(out, "fault: signal {number} ({name})")?,
                (None, Some(addr)) => writeln!(out, "fault: signal {number} at {addr:#x}")?,
                (None, None) => writeln!(out, "fault: signal {number}")?,
            }
        }
        FaultKind::Hang => writeln!(out, "fault: hang (no fatal signal)")?,
    }
    writeln!(
        out,
        "signature: {}  {}",
        report.signature.hex, report.signature.label
    )?;
    for thread in &report.threads {
        let marker = if Some(thread.tid) == report.crashing_tid {
            "* "
        } else {
            "  "
        };
        match &thread.name {
            Some(name) => writeln!(out, "{marker}thread {} ({name})", thread.tid)?,
            None => writeln!(out, "{marker}thread {}", thread.tid)?,
        }
        for (depth, frame) in thread.frames.iter().enumerate() {
            writeln!(out, "    #{depth} {}", format_frame(frame))?;
        }
    }
    Ok(())
}

fn format_frame(frame: &Frame) -> String {
    let module = frame.module.as_deref().unwrap_or("?");
    let function = frame.function.as_deref().unwrap_or("<unknown>");
    match (&frame.file, frame.line) {
        (Some(file), Some(line)) => format!("{module}!{function} ({file}:{line})"),
        (Some(file), None) => format!("{module}!{function} ({file})"),
        (None, _) => format!("{module}!{function}"),
    }
}

/// Name of a common fatal signal, for the human-readable fault line.
pub(crate) fn signal_name(signal: i32) -> Option<&'static str> {
    match signal {
        4 => Some("SIGILL"),
        6 => Some("SIGABRT"),
        7 => Some("SIGBUS"),
        8 => Some("SIGFPE"),
        11 => Some("SIGSEGV"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Signature, ThreadReport};

    #[test]
    fn text_report_marks_the_crashing_thread_and_names_the_signal() {
        let report = sample_report();
        let out = render(|w| TextEmitter.emit_report(&report, w));
        assert!(out.contains("signal 11 (SIGSEGV) at 0x0"), "{out}");
        assert!(
            out.contains("signature: 7f3a9c2e  SIGSEGV in app!Widget::render"),
            "{out}"
        );
        assert!(out.contains("* thread 42 (worker)"), "{out}");
        assert!(
            out.contains("#0 app!Widget::render (src/widget.rs:88)"),
            "{out}"
        );
        assert!(out.contains("#1 app!main"), "{out}");
    }

    #[test]
    fn json_report_round_trips() {
        let report = sample_report();
        let out = render(|w| JsonEmitter { pretty: false }.emit_report(&report, w));
        let parsed: CrashReport = serde_json::from_str(&out).expect("parse");
        assert_eq!(parsed, report);
    }

    #[test]
    fn text_buckets_rank_from_one() {
        let buckets = vec![Bucket {
            signature: Signature {
                hex: "7f3a9c2e".to_string(),
                label: "SIGSEGV in Widget::render".to_string(),
            },
            count: 312,
            representative: sample_report(),
        }];
        let out = render(|w| TextEmitter.emit_buckets(&buckets, w));
        assert!(
            out.contains("[1] 312 cores  7f3a9c2e  SIGSEGV in Widget::render"),
            "{out}"
        );
    }

    #[test]
    fn text_buckets_say_core_for_a_count_of_one() {
        let buckets = vec![Bucket {
            signature: Signature {
                hex: "abc".to_string(),
                label: "SIGSEGV in app!boom".to_string(),
            },
            count: 1,
            representative: sample_report(),
        }];
        let out = render(|w| TextEmitter.emit_buckets(&buckets, w));
        assert!(out.contains("[1] 1 core  "), "{out}");
    }

    // Helpers after the tests that use them, per the house rules.
    fn sample_report() -> CrashReport {
        CrashReport {
            fault: FaultKind::Signal {
                number: 11,
                address: Some(0),
            },
            crashing_tid: Some(42),
            threads: vec![ThreadReport {
                tid: 42,
                name: Some("worker".to_string()),
                frames: vec![
                    Frame {
                        module: Some("app".to_string()),
                        function: Some("Widget::render".to_string()),
                        file: Some("src/widget.rs".to_string()),
                        line: Some(88),
                    },
                    Frame {
                        module: Some("app".to_string()),
                        function: Some("main".to_string()),
                        file: None,
                        line: None,
                    },
                ],
            }],
            signature: Signature {
                hex: "7f3a9c2e".to_string(),
                label: "SIGSEGV in app!Widget::render".to_string(),
            },
        }
    }

    fn render<F>(f: F) -> String
    where
        F: FnOnce(&mut Vec<u8>) -> Result<()>,
    {
        let mut buf = Vec::new();
        f(&mut buf).expect("emit");
        String::from_utf8(buf).expect("utf8")
    }
}
