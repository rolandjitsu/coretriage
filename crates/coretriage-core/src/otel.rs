//! Encode triage results as OpenTelemetry OTLP/JSON (opentelemetry.io/docs/specs/otlp): a pile of
//! cores becomes a monotonic fault counter (metrics) and one event per distinct fault (logs). The
//! output is a single `ExportMetricsServiceRequest` or `ExportLogsServiceRequest` object, ready to
//! POST to an OTLP/HTTP `/v1/metrics` or `/v1/logs` endpoint or feed to an OTel Collector.
//!
//! coretriage is offline, so there is no exporter and no SDK here: it serializes the OTLP/JSON
//! shape directly with `serde_json`. Timestamps are 0 so the Collector stamps arrival time, which
//! also keeps the output deterministic for tests.

use serde_json::{Value, json};

use crate::model::{Bucket, CrashReport, FaultKind, Frame, ThreadReport};
use crate::report::signal_name;

/// Instrumentation scope name and resource `service.name`.
const SCOPE: &str = "coretriage";
/// Scope version, tracking the crate version.
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// OTLP/JSON metrics for a batch: a `coretriage.faults` counter with one data point per bucket.
pub(crate) fn encode_metrics_buckets(buckets: &[Bucket]) -> Value {
    let points = buckets
        .iter()
        .map(|b| number_point(&b.representative, b.count))
        .collect();
    metrics_envelope(points)
}

/// OTLP/JSON metrics for a single core: the counter with one data point of value 1.
pub(crate) fn encode_metrics_report(report: &CrashReport) -> Value {
    metrics_envelope(vec![number_point(report, 1)])
}

/// OTLP/JSON logs for a batch: one `LogRecord` per bucket.
pub(crate) fn encode_logs_buckets(buckets: &[Bucket]) -> Value {
    let records = buckets
        .iter()
        .map(|b| log_record(&b.representative, b.count))
        .collect();
    logs_envelope(records)
}

/// OTLP/JSON logs for a single core: one `LogRecord` of count 1.
pub(crate) fn encode_logs_report(report: &CrashReport) -> Value {
    logs_envelope(vec![log_record(report, 1)])
}

/// A monotonic cumulative `Sum` named `coretriage.faults`, unit `{core}`.
fn metrics_envelope(data_points: Vec<Value>) -> Value {
    json!({
        "resourceMetrics": [{
            "resource": { "attributes": [string_kv("service.name", SCOPE)] },
            "scopeMetrics": [{
                "scope": { "name": SCOPE, "version": VERSION },
                "metrics": [{
                    "name": "coretriage.faults",
                    "description": "Cores grouped by fault signature.",
                    "unit": "{core}",
                    "sum": {
                        "aggregationTemporality": 2, // CUMULATIVE
                        "isMonotonic": true,
                        "dataPoints": data_points,
                    }
                }]
            }]
        }]
    })
}

/// One `NumberDataPoint`: the core count as an integer, attributed by fault signature.
fn number_point(report: &CrashReport, count: usize) -> Value {
    json!({
        "asInt": count.to_string(), // OTLP/JSON encodes int64 as a string
        "startTimeUnixNano": "0",
        "timeUnixNano": "0",
        "attributes": fault_attributes(report),
    })
}

fn logs_envelope(log_records: Vec<Value>) -> Value {
    json!({
        "resourceLogs": [{
            "resource": { "attributes": [string_kv("service.name", SCOPE)] },
            "scopeLogs": [{
                "scope": { "name": SCOPE, "version": VERSION },
                "logRecords": log_records,
            }]
        }]
    })
}

/// One `LogRecord` for a fault: ERROR for a signal, WARN for a hang; the signature label as the
/// body; the fault attributes plus `event.name` and the core `fault.count`.
fn log_record(report: &CrashReport, count: usize) -> Value {
    let (severity_number, severity_text) = match report.fault {
        FaultKind::Signal { .. } => (17, "ERROR"), // SEVERITY_NUMBER_ERROR
        FaultKind::Hang => (13, "WARN"),           // SEVERITY_NUMBER_WARN
    };
    let mut attributes = fault_attributes(report);
    attributes.insert(0, string_kv("event.name", "coretriage.fault"));
    attributes.push(int_kv("fault.count", count as i64));
    json!({
        "timeUnixNano": "0",
        "observedTimeUnixNano": "0",
        "severityNumber": severity_number,
        "severityText": severity_text,
        "body": { "stringValue": report.signature.label },
        "attributes": attributes,
    })
}

/// Attributes shared by a metric data point and a log record: what the fault was and where.
fn fault_attributes(report: &CrashReport) -> Vec<Value> {
    let mut attrs = vec![string_kv("fault.signature", &report.signature.hex)];
    match &report.fault {
        FaultKind::Signal { number, .. } => {
            attrs.push(string_kv("fault.kind", "signal"));
            attrs.push(int_kv("fault.signal", i64::from(*number)));
            if let Some(name) = signal_name(*number) {
                attrs.push(string_kv("fault.signal.name", name));
            }
        }
        FaultKind::Hang => attrs.push(string_kv("fault.kind", "hang")),
    }
    if let Some(frame) = top_frame(report) {
        attrs.push(string_kv("fault.function", &frame_name(frame)));
        if let Some(id) = top_build_id(report, frame) {
            attrs.push(string_kv("fault.build_id", id));
        }
    }
    attrs
}

/// The innermost frame of the crashing (or, for a hang, the first) thread.
fn top_frame(report: &CrashReport) -> Option<&Frame> {
    crashing_thread(report).and_then(|t| t.frames.first())
}

/// The thread a fault is attributed to, or the first thread when none is marked.
fn crashing_thread(report: &CrashReport) -> Option<&ThreadReport> {
    match report.crashing_tid {
        Some(tid) => report.threads.iter().find(|t| t.tid == tid),
        None => report.threads.first(),
    }
}

/// The build-id of the module the top frame falls in, matched by module name, when known.
fn top_build_id<'a>(report: &'a CrashReport, frame: &Frame) -> Option<&'a str> {
    let module = frame.module.as_deref()?;
    report
        .modules
        .iter()
        .find(|m| m.path.file_name().and_then(|n| n.to_str()) == Some(module))
        .and_then(|m| m.build_id.as_deref())
}

fn frame_name(frame: &Frame) -> String {
    let module = frame.module.as_deref().unwrap_or("?");
    let function = frame.function.as_deref().unwrap_or("<unknown>");
    format!("{module}!{function}")
}

/// An OTLP `KeyValue` with a string value.
fn string_kv(key: &str, value: &str) -> Value {
    json!({ "key": key, "value": { "stringValue": value } })
}

/// An OTLP `KeyValue` with an int value (OTLP/JSON encodes int64 as a string).
fn int_kv(key: &str, value: i64) -> Value {
    json!({ "key": key, "value": { "intValue": value.to_string() } })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Module, Signature};

    #[test]
    fn metrics_are_a_monotonic_counter_with_a_point_per_bucket() {
        let buckets = vec![bucket(312, segv_report()), bucket(4, hang_report())];
        let v = encode_metrics_buckets(&buckets);

        let sum = &v["resourceMetrics"][0]["scopeMetrics"][0]["metrics"][0]["sum"];
        assert_eq!(sum["isMonotonic"], true);
        assert_eq!(sum["aggregationTemporality"], 2);
        let points = sum["dataPoints"].as_array().expect("dataPoints");
        assert_eq!(points.len(), 2);
        // int64 is a JSON string in OTLP/JSON.
        assert_eq!(points[0]["asInt"], "312");
        assert_eq!(
            attr(&points[0], "fault.signal.name"),
            Some("SIGSEGV".into())
        );
        assert_eq!(
            attr(&points[0], "fault.function"),
            Some("app!render".into())
        );
        // The hang point carries no signal, just the kind.
        assert_eq!(attr(&points[1], "fault.kind"), Some("hang".into()));
        assert_eq!(attr(&points[1], "fault.signal.name"), None);
    }

    #[test]
    fn a_log_record_is_an_error_event_carrying_the_build_id() {
        let v = encode_logs_report(&segv_report());
        let rec = &v["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0];
        assert_eq!(rec["severityText"], "ERROR");
        assert_eq!(rec["severityNumber"], 17);
        assert_eq!(rec["body"]["stringValue"], "SIGSEGV in app!render");
        assert_eq!(attr(rec, "event.name"), Some("coretriage.fault".into()));
        assert_eq!(attr(rec, "fault.count"), Some("1".into())); // intValue, as a string
        assert_eq!(attr(rec, "fault.build_id"), Some("deadbeef".into()));
    }

    #[test]
    fn a_hang_log_record_is_a_warning_without_a_signal() {
        let v = encode_logs_buckets(&[bucket(2, hang_report())]);
        let rec = &v["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0];
        assert_eq!(rec["severityText"], "WARN");
        assert_eq!(attr(rec, "fault.kind"), Some("hang".into()));
        assert_eq!(attr(rec, "fault.signal"), None);
        assert_eq!(attr(rec, "fault.count"), Some("2".into()));
    }

    #[test]
    fn a_fault_without_frames_still_carries_its_signature() {
        let mut r = segv_report();
        r.threads = Vec::new(); // top_frame() is None, so there is no function attribute
        let v = encode_metrics_report(&r);
        let point =
            &v["resourceMetrics"][0]["scopeMetrics"][0]["metrics"][0]["sum"]["dataPoints"][0];
        assert_eq!(point["asInt"], "1");
        assert_eq!(attr(point, "fault.signature"), Some("6ae8cbf3".into()));
        assert_eq!(attr(point, "fault.function"), None);
    }

    // --- helpers, after the tests that use them ---

    /// The string/int value of attribute `key` in an OTLP object, or `None` if absent.
    fn attr(obj: &Value, key: &str) -> Option<String> {
        obj["attributes"].as_array()?.iter().find_map(|kv| {
            if kv["key"] == key {
                let v = &kv["value"];
                v["stringValue"]
                    .as_str()
                    .or_else(|| v["intValue"].as_str())
                    .map(String::from)
            } else {
                None
            }
        })
    }

    fn bucket(count: usize, representative: CrashReport) -> Bucket {
        Bucket {
            signature: representative.signature.clone(),
            count,
            representative,
        }
    }

    fn segv_report() -> CrashReport {
        CrashReport {
            fault: FaultKind::Signal {
                number: 11,
                address: Some(0),
            },
            crashing_tid: Some(1),
            modules: vec![Module {
                path: "/opt/app/bin/app".into(),
                load_bias: 0,
                build_id: Some("deadbeef".to_string()),
                symbols: true,
            }],
            threads: vec![ThreadReport {
                tid: 1,
                name: None,
                frames: vec![Frame {
                    module: Some("app".to_string()),
                    function: Some("render".to_string()),
                    file: Some("src/app.c".to_string()),
                    line: Some(88),
                }],
            }],
            signature: Signature {
                hex: "6ae8cbf3".to_string(),
                label: "SIGSEGV in app!render".to_string(),
            },
        }
    }

    fn hang_report() -> CrashReport {
        CrashReport {
            fault: FaultKind::Hang,
            crashing_tid: None,
            modules: Vec::new(),
            threads: vec![ThreadReport {
                tid: 1,
                name: None,
                frames: vec![Frame {
                    module: Some("libc.so.6".to_string()),
                    function: Some("pthread_cond_wait".to_string()),
                    file: None,
                    line: None,
                }],
            }],
            signature: Signature {
                hex: "c9d2e810".to_string(),
                label: "hang: 1 thread in pthread_cond_wait".to_string(),
            },
        }
    }
}
