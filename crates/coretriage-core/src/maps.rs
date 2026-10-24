//! Build the process module map. Turns the core's `NT_FILE` entries, plus any `--exe` and
//! `--sysroot` overrides, into resolved [`crate::model::Module`]s with load biases and,
//! where available, GNU build-ids - the inputs the unwinder and the symbolizer both need.
