//! Fuzz the core-dump parser: feed arbitrary bytes to `triage_bytes` and require that it
//! never panics, aborts, or runs out of memory. Malformed input must return an error.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = coretriage_core::triage_bytes(data, &Default::default());
});
