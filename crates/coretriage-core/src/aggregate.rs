//! Aggregate many reports into buckets. Groups [`crate::model::CrashReport`]s by their
//! signature, counts each group, and keeps a representative, so a directory of cores
//! collapses to a ranked set of distinct crashes.

use std::collections::HashMap;

use crate::model::{Bucket, CrashReport};

/// Group reports into buckets by their signature hash, ranked most-frequent first. The first
/// report seen for a signature is kept as that bucket's representative. Ties in count are
/// broken by signature hash so the ranking is deterministic across runs.
pub(crate) fn bucket(reports: Vec<CrashReport>) -> Vec<Bucket> {
    let mut by_hex: HashMap<String, Bucket> = HashMap::new();
    for report in reports {
        let hex = report.signature.hex.clone();
        by_hex
            .entry(hex)
            .and_modify(|b| b.count += 1)
            .or_insert_with(|| Bucket {
                signature: report.signature.clone(),
                count: 1,
                representative: report,
            });
    }
    let mut buckets: Vec<Bucket> = by_hex.into_values().collect();
    buckets.sort_by(|a, b| {
        b.count
            .cmp(&a.count)
            .then_with(|| a.signature.hex.cmp(&b.signature.hex))
    });
    buckets
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{FaultKind, Signature};

    #[test]
    fn buckets_rank_by_count_then_hash() {
        let reports = vec![
            report_with("bbbb"),
            report_with("aaaa"),
            report_with("bbbb"),
            report_with("cccc"),
            report_with("aaaa"),
            report_with("aaaa"),
        ];
        let buckets = bucket(reports);
        assert_eq!(buckets.len(), 3);
        // aaaa (3) > bbbb (2) > cccc (1).
        assert_eq!(buckets[0].signature.hex, "aaaa");
        assert_eq!(buckets[0].count, 3);
        assert_eq!(buckets[1].signature.hex, "bbbb");
        assert_eq!(buckets[1].count, 2);
        assert_eq!(buckets[2].signature.hex, "cccc");
        assert_eq!(buckets[2].count, 1);
    }

    #[test]
    fn ties_break_on_hash() {
        let buckets = bucket(vec![report_with("zzzz"), report_with("aaaa")]);
        assert_eq!(buckets[0].signature.hex, "aaaa");
        assert_eq!(buckets[1].signature.hex, "zzzz");
    }

    // Helpers after the tests that use them, per the house rules.
    fn report_with(hex: &str) -> CrashReport {
        CrashReport {
            fault: FaultKind::Signal {
                number: 11,
                address: None,
            },
            threads: Vec::new(),
            crashing_tid: None,
            signature: Signature {
                hex: hex.to_string(),
                label: format!("SIGSEGV ({hex})"),
            },
        }
    }
}
