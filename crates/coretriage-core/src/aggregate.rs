//! Aggregate many reports into buckets. Groups [`crate::model::CrashReport`]s by their
//! signature, counts each group, and keeps a representative, so a directory of cores
//! collapses to a ranked set of distinct crashes.
