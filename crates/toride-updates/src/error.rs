//! Unified error types for the `toride-updates` crate.
//!
//! Every subsystem returns [`Error`] through the crate-level [`Result`] alias.
//! The enum is marked `#[non_exhaustive]` so new variants can be added without
//! a semver break.

// ---------------------------------------------------------------------------
// Error enum -- single source of truth for the entire crate
// ---------------------------------------------------------------------------

/// Crate-level error type covering all update subsystems.
///
/// Uses [`thiserror`] for `Display` and `std::error::Error` impls.
/// Marked `#[non_exhaustive]` so downstream crates must handle future
/// variants with a wildcard match arm.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// An I/O error propagated from `std::io`.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// A required binary was not found on `$PATH`.
    #[error("binary not found: {0}")]
    BinaryNotFound(String),

    /// An external command exited with a non-zero status.
    #[error("command failed: {0}")]
    CommandFailed(String),

    /// An external command timed out before completing.
    #[error("command timed out after {0:?}")]
    CommandTimeout(std::time::Duration),

    /// A configuration file could not be parsed.
    #[error("config parse error: {0}")]
    ConfigParse(String),

    /// A configuration file could not be written.
    #[error("config write error: {0}")]
    ConfigWrite(String),

    /// Package detection failed (neither apt nor dnf found).
    #[error("package detection failed: {0}")]
    PackageDetection(String),

    /// Schedule configuration is invalid or unsupported.
    #[error("schedule config error: {0}")]
    ScheduleConfig(String),

    /// A generic or unexpected error.
    #[error("{0}")]
    Other(String),
}

// ---------------------------------------------------------------------------
// Cross-crate conversions
// ---------------------------------------------------------------------------

/// Convert a [`toride_runner::Error`] into [`Error::CommandFailed`].
///
/// This lets the whole crate use `?` on `Runner::run` / `Runner::run_checked`
/// without per-call `map_err` boilerplate. The runner error is stringified so
/// its `Display` (program, args, exit code, redacted stderr) is preserved.
impl From<toride_runner::Error> for Error {
    fn from(err: toride_runner::Error) -> Self {
        // Honour the explicit timeout variant so callers can match on it.
        match err {
            toride_runner::Error::CommandTimeout { timeout, .. } => {
                Error::CommandTimeout(timeout)
            }
            toride_runner::Error::BinaryNotFound(program) => Error::BinaryNotFound(program),
            other => Error::CommandFailed(other.to_string()),
        }
    }
}

// ---------------------------------------------------------------------------
// Crate-level result alias
// ---------------------------------------------------------------------------

/// Crate-level result alias used throughout the library.
pub type Result<T> = std::result::Result<T, Error>;
