//! The crate error type and its `Result` alias.

/// An error produced while triaging a core dump.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// An I/O error reading a core, an executable, or a sysroot path.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// The core, or an auxiliary file it references, could not be parsed.
    #[error("parse error: {0}")]
    Parse(String),
    /// Output could not be serialized to the requested format.
    #[error("serialize error: {0}")]
    Serialize(#[from] serde_json::Error),
    /// The requested operation is not implemented yet.
    #[error("not implemented")]
    Unimplemented,
}

/// A `Result` whose error is this crate's [`Error`].
pub type Result<T> = std::result::Result<T, Error>;
