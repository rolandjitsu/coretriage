//! Compute a crash signature. Normalizes the crashing thread's backtrace (strip offsets,
//! inlining noise, and non-deterministic frames) and hashes it with BLAKE3 into a stable
//! fingerprint, so the same bug produces the same [`crate::model::Signature`] across cores.
