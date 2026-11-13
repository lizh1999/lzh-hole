use std::path::PathBuf;

/// Control-plane setup, I/O and protocol failures.
#[derive(Debug, thiserror::Error)]
pub enum ControlError {
    /// Invalid control ownership/configuration.
    #[error("control configuration: {0}")]
    Invalid(String),
    /// Unsafe control directory.
    #[error("control directory {path}: {detail}")]
    UnsafeDirectory {
        /// Offending directory.
        path: PathBuf,
        /// Failed property.
        detail: String,
    },
    /// An existing path is never automatically unlinked.
    #[error("control socket {0}: path already exists; refusing to remove or replace it")]
    AlreadyExists(PathBuf),
    /// Socket/filesystem I/O failure.
    #[error("control socket {path}: {source}")]
    Io {
        /// Associated path.
        path: PathBuf,
        /// Underlying error.
        source: std::io::Error,
    },
    /// Bounded local protocol failure.
    #[error("control protocol: {0}")]
    Protocol(String),
    /// Bounded wait expired.
    #[error("control operation timed out: {0}")]
    Timeout(&'static str),
}

pub(crate) fn io(path: &std::path::Path, source: std::io::Error) -> ControlError {
    ControlError::Io {
        path: path.to_path_buf(),
        source,
    }
}
