//! Symbolicate frame addresses. Maps each return address back to its module, then uses an
//! `addr2line::Context` (cached per build-id) to resolve function names and source
//! file/line from the module's DWARF, demangling Rust and C++ symbols for readable frames.
