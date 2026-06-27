//! Unified error types for the `toride-monitor` crate.
//!
//! Every subsystem returns [`Error`] through the crate-level [`Result`] alias.
//! The enum is marked `#[non_exhaustive]` so new variants can be added without
//! a semver break.

// ---------------------------------------------------------------------------
// Error enum -- single source of truth for the entire crate
// ---------------------------------------------------------------------------

/// Crate-level error type covering all monitor subsystems.
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

    /// A required system binary was not found on `$PATH`.
    #[error("binary not found: {0}")]
    BinaryNotFound(String),

    /// An external command exited with a non-zero status.
    #[error("command failed: {0}")]
    CommandFailed(String),

    /// An error occurred while reading or parsing iptables log output.
    #[error("logging error: {0}")]
    LoggingError(String),

    /// An error occurred while reading or parsing conntrack data.
    #[error("conntrack error: {0}")]
    ConntrackError(String),

    /// An anomaly threshold value is invalid or out of range.
    #[error("anomaly threshold error: {0}")]
    AnomalyThreshold(String),

    /// An error occurred during port/socket inspection.
    #[error("ports error: {0}")]
    PortsError(String),

    /// A generic or unexpected error.
    #[error("{0}")]
    Other(String),

    /// An error propagated from the underlying command runner
    /// ([`toride_runner`]).
    #[error("runner error: {0}")]
    Runner(#[from] toride_runner::Error),

    /// An error propagated from the service-management layer
    /// ([`toride_service`]). Only present when the `service` feature is on.
    #[cfg(feature = "service")]
    #[error("service error: {0}")]
    Service(String),
}

#[cfg(feature = "service")]
impl From<toride_service::Error> for Error {
    fn from(err: toride_service::Error) -> Self {
        Self::Service(err.to_string())
    }
}

// ---------------------------------------------------------------------------
// Crate-level result alias
// ---------------------------------------------------------------------------

/// Crate-level result alias used throughout the library.
pub type Result<T> = std::result::Result<T, Error>;
