//! Encode triage results as a pprof profile (github.com/google/pprof): a protobuf of weighted
//! stack samples - one sample per bucket, its value the number of cores - for Pyroscope, Parca,
//! Grafana, or `go tool pprof`. A bucket is exactly a weighted stack sample, so a pile of cores
//! becomes a profile of where crashes concentrate.
//!
//! The `profile.proto` subset we emit (string table, functions, locations, samples) is small and
//! protobuf's wire format is simple, so this is hand-encoded rather than pulling in a protobuf
//! dependency. Field numbers follow `profile.proto`.

use std::collections::HashMap;

use crate::model::{Bucket, CrashReport, FaultKind, Frame, ThreadReport};

/// Encode a single report as a pprof profile (the crashing thread, or every thread for a hang).
pub(crate) fn encode_report(report: &CrashReport) -> Vec<u8> {
    let mut profile = Profile::new();
    profile.add_report(report, 1);
    profile.encode()
}

/// Encode a batch's buckets as a pprof profile, each sample weighted by its core count.
pub(crate) fn encode_buckets(buckets: &[Bucket]) -> Vec<u8> {
    let mut profile = Profile::new();
    for bucket in buckets {
        profile.add_report(&bucket.representative, bucket.count as i64);
    }
    profile.encode()
}

/// One `Function` row: `id`, and `name`/`filename` as string-table indices.
struct Function {
    id: u64,
    name: i64,
    filename: i64,
}

/// One `Location` row: `id`, and a single `Line` (`function_id`, source `line`).
struct Location {
    id: u64,
    function_id: u64,
    line: i64,
}

/// A pprof profile under construction, interning strings, functions, and locations so each is
/// emitted once and referenced by id.
struct Profile {
    strings: Vec<String>,
    string_ids: HashMap<String, i64>,
    functions: Vec<Function>,
    function_ids: HashMap<(i64, i64), u64>,
    locations: Vec<Location>,
    location_ids: HashMap<(u64, i64), u64>,
    samples: Vec<(Vec<u64>, i64)>,
    sample_type: (i64, i64),
}

impl Profile {
    fn new() -> Self {
        let mut p = Profile {
            strings: Vec::new(),
            string_ids: HashMap::new(),
            functions: Vec::new(),
            function_ids: HashMap::new(),
            locations: Vec::new(),
            location_ids: HashMap::new(),
            samples: Vec::new(),
            sample_type: (0, 0),
        };
        p.intern(""); // string_table[0] must be the empty string
        p.sample_type = (p.intern("cores"), p.intern("count"));
        p
    }

    /// Add the stacks of one report at `weight`: the crashing thread for a signal fault, every
    /// thread for a hang.
    fn add_report(&mut self, report: &CrashReport, weight: i64) {
        match report.fault {
            FaultKind::Signal { .. } => {
                if let Some(thread) = crashing_thread(report) {
                    self.add_sample(&thread.frames, weight);
                }
            }
            FaultKind::Hang => {
                for thread in &report.threads {
                    self.add_sample(&thread.frames, weight);
                }
            }
        }
    }

    /// Add one sample: the stack's locations (leaf-first, as pprof expects) and its value.
    fn add_sample(&mut self, frames: &[Frame], value: i64) {
        if frames.is_empty() {
            return;
        }
        let location_ids = frames.iter().map(|f| self.location_for(f)).collect();
        self.samples.push((location_ids, value));
    }

    fn location_for(&mut self, frame: &Frame) -> u64 {
        let module = frame.module.as_deref().unwrap_or("?");
        let function = frame.function.as_deref().unwrap_or("<unknown>");
        let name = self.intern(&format!("{module}!{function}"));
        let filename = self.intern(frame.file.as_deref().unwrap_or(""));
        let function_id = self.function(name, filename);
        let line = frame.line.map(i64::from).unwrap_or(0);
        self.location(function_id, line)
    }

    fn intern(&mut self, s: &str) -> i64 {
        if let Some(&id) = self.string_ids.get(s) {
            return id;
        }
        let id = self.strings.len() as i64;
        self.strings.push(s.to_string());
        self.string_ids.insert(s.to_string(), id);
        id
    }

    fn function(&mut self, name: i64, filename: i64) -> u64 {
        *self
            .function_ids
            .entry((name, filename))
            .or_insert_with(|| {
                let id = self.functions.len() as u64 + 1;
                self.functions.push(Function { id, name, filename });
                id
            })
    }

    fn location(&mut self, function_id: u64, line: i64) -> u64 {
        *self
            .location_ids
            .entry((function_id, line))
            .or_insert_with(|| {
                let id = self.locations.len() as u64 + 1;
                self.locations.push(Location {
                    id,
                    function_id,
                    line,
                });
                id
            })
    }

    /// Serialize to the pprof protobuf wire format.
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();

        // Profile.sample_type (field 1): one ValueType { type (1), unit (2) }.
        let mut vt = Vec::new();
        put_varint_field(&mut vt, 1, self.sample_type.0 as u64);
        put_varint_field(&mut vt, 2, self.sample_type.1 as u64);
        put_len_field(&mut out, 1, &vt);

        // Profile.sample (field 2, repeated): location_id[] (1) leaf-first, value[] (2).
        for (location_ids, value) in &self.samples {
            let mut s = Vec::new();
            for &id in location_ids {
                put_varint_field(&mut s, 1, id);
            }
            put_varint_field(&mut s, 2, *value as u64);
            put_len_field(&mut out, 2, &s);
        }

        // Profile.location (field 4, repeated): id (1), one Line (4) { function_id (1), line (2) }.
        for loc in &self.locations {
            let mut l = Vec::new();
            put_varint_field(&mut l, 1, loc.id);
            let mut line = Vec::new();
            put_varint_field(&mut line, 1, loc.function_id);
            put_varint_field(&mut line, 2, loc.line as u64);
            put_len_field(&mut l, 4, &line);
            put_len_field(&mut out, 4, &l);
        }

        // Profile.function (field 5, repeated): id (1), name (2), filename (4).
        for f in &self.functions {
            let mut fb = Vec::new();
            put_varint_field(&mut fb, 1, f.id);
            put_varint_field(&mut fb, 2, f.name as u64);
            put_varint_field(&mut fb, 4, f.filename as u64);
            put_len_field(&mut out, 5, &fb);
        }

        // Profile.string_table (field 6, repeated string).
        for s in &self.strings {
            put_len_field(&mut out, 6, s.as_bytes());
        }

        out
    }
}

/// The thread a fault is attributed to, or the first thread when none is marked.
fn crashing_thread(report: &CrashReport) -> Option<&ThreadReport> {
    match report.crashing_tid {
        Some(tid) => report.threads.iter().find(|t| t.tid == tid),
        None => report.threads.first(),
    }
}

/// Append a base-128 varint.
fn put_varint(buf: &mut Vec<u8>, mut v: u64) {
    loop {
        let byte = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            buf.push(byte);
            break;
        }
        buf.push(byte | 0x80);
    }
}

/// Append a varint field: tag (field, wire type 0) then the value.
fn put_varint_field(buf: &mut Vec<u8>, field: u32, value: u64) {
    put_varint(buf, u64::from(field) << 3); // wire type 0
    put_varint(buf, value);
}

/// Append a length-delimited field: tag (field, wire type 2), length, then the bytes.
fn put_len_field(buf: &mut Vec<u8>, field: u32, bytes: &[u8]) {
    put_varint(buf, (u64::from(field) << 3) | 2);
    put_varint(buf, bytes.len() as u64);
    buf.extend_from_slice(bytes);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{FaultKind, Frame, Signature, ThreadReport};

    fn frame(module: &str, function: &str, line: u32) -> Frame {
        Frame {
            module: Some(module.to_string()),
            function: Some(function.to_string()),
            file: Some("crasher.c".to_string()),
            line: Some(line),
        }
    }

    fn report(frames: Vec<Frame>) -> CrashReport {
        CrashReport {
            fault: FaultKind::Signal {
                number: 11,
                address: Some(0),
            },
            threads: vec![ThreadReport {
                tid: 1,
                name: None,
                frames,
            }],
            modules: Vec::new(),
            crashing_tid: Some(1),
            signature: Signature::default(),
        }
    }

    #[test]
    fn buckets_become_weighted_samples_with_interned_names() {
        let buckets = vec![
            Bucket {
                signature: Signature::default(),
                count: 7,
                representative: report(vec![
                    frame("crasher", "gamma_segv", 3),
                    frame("crasher", "main", 7),
                ]),
            },
            Bucket {
                signature: Signature::default(),
                count: 2,
                representative: report(vec![
                    frame("crasher", "gamma_abort", 4),
                    frame("crasher", "main", 7),
                ]),
            },
        ];
        let pb = encode_buckets(&buckets);

        // Two samples, carrying the core counts as values.
        let samples: Vec<&[u8]> = top_fields(&pb, 2);
        assert_eq!(samples.len(), 2);
        let values: Vec<u64> = samples.iter().map(|s| field_varint(s, 2)).collect();
        assert_eq!(values, vec![7, 2]);

        // The string table carries the interned frame names and the sample type.
        let strings = string_table(&pb);
        assert!(strings.contains(&"cores".to_string()));
        assert!(strings.contains(&"crasher!gamma_segv".to_string()));
        assert!(strings.contains(&"crasher!gamma_abort".to_string()));
        assert!(strings.contains(&"crasher!main".to_string()));

        // `main` is shared, so it is interned once across both samples.
        assert_eq!(strings.iter().filter(|s| *s == "crasher!main").count(), 1);
    }

    #[test]
    fn empty_stack_adds_no_sample() {
        let pb = encode_report(&report(Vec::new()));
        assert!(
            top_fields(&pb, 2).is_empty(),
            "no samples for an empty stack"
        );
    }

    #[test]
    fn hang_adds_a_sample_per_thread() {
        let hang = CrashReport {
            fault: FaultKind::Hang,
            threads: vec![
                thread(1, vec![frame("libc.so.6", "pthread_cond_wait", 0)]),
                thread(2, vec![frame("app", "poll_loop", 0)]),
            ],
            modules: Vec::new(),
            crashing_tid: None,
            signature: Signature::default(),
        };
        let pb = encode_report(&hang);
        assert_eq!(top_fields(&pb, 2).len(), 2, "one sample per hung thread");
    }

    #[test]
    fn signal_without_crashing_tid_falls_back_to_first_thread() {
        let mut r = report(vec![frame("app", "boom", 1)]);
        r.crashing_tid = None; // crashing_thread() then uses the first thread
        let pb = encode_report(&r);
        assert_eq!(top_fields(&pb, 2).len(), 1);
    }

    #[test]
    fn large_count_round_trips_as_multibyte_varint() {
        let pb = encode_buckets(&[Bucket {
            signature: Signature::default(),
            count: 300, // >= 128 forces a continuation byte in the varint
            representative: report(vec![frame("crasher", "boom", 1)]),
        }]);
        let sample = top_fields(&pb, 2)[0];
        assert_eq!(field_varint(sample, 2), 300);
    }

    #[test]
    fn reader_skips_varint_and_absent_fields() {
        let pb = encode_buckets(&[Bucket {
            signature: Signature::default(),
            count: 1,
            representative: report(vec![frame("crasher", "main", 7)]),
        }]);
        let sample = top_fields(&pb, 2)[0];
        // A sample holds only varint fields, so it has no length-delimited field 1.
        assert!(top_fields(sample, 1).is_empty());
        // A field absent from the profile reads back as 0.
        assert_eq!(field_varint(&pb, 99), 0);
    }

    // --- a minimal protobuf reader, enough to verify what we wrote ---

    fn read_varint(b: &[u8], i: &mut usize) -> u64 {
        let mut v = 0u64;
        let mut shift = 0;
        loop {
            let byte = b[*i];
            *i += 1;
            v |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                break;
            }
            shift += 7;
        }
        v
    }

    /// Every length-delimited (wire type 2) value of `field` at the top level of `buf`. Our output
    /// uses only wire types 2 and 0, so anything that is not wire 2 is a varint we skip over.
    fn top_fields(buf: &[u8], field: u64) -> Vec<&[u8]> {
        let mut out = Vec::new();
        let mut i = 0;
        while i < buf.len() {
            let tag = read_varint(buf, &mut i);
            let (f, wire) = (tag >> 3, tag & 7);
            if wire == 2 {
                let len = read_varint(buf, &mut i) as usize;
                if f == field {
                    out.push(&buf[i..i + len]);
                }
                i += len;
            } else {
                read_varint(buf, &mut i); // a varint field: skip its value
            }
        }
        out
    }

    /// The first varint value of `field` within a message, or 0 if absent (skipping any
    /// length-delimited fields along the way).
    fn field_varint(buf: &[u8], field: u64) -> u64 {
        let mut i = 0;
        while i < buf.len() {
            let tag = read_varint(buf, &mut i);
            let (f, wire) = (tag >> 3, tag & 7);
            if wire == 2 {
                let len = read_varint(buf, &mut i) as usize;
                i += len;
            } else {
                let v = read_varint(buf, &mut i);
                if f == field {
                    return v;
                }
            }
        }
        0
    }

    fn string_table(buf: &[u8]) -> Vec<String> {
        top_fields(buf, 6)
            .iter()
            .map(|b| String::from_utf8_lossy(b).into_owned())
            .collect()
    }

    fn thread(tid: i32, frames: Vec<Frame>) -> ThreadReport {
        ThreadReport {
            tid,
            name: None,
            frames,
        }
    }
}
