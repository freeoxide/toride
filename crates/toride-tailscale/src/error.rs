//! Unified error types for the `toride-tailscale` crate.
//!
//! Every subsystem returns [`Error`] through the crate-level [`Result`] alias.
//! The enum is marked `#[non_exhaustive]` so new variants can be added without
//! a semver break.

// ---------------------------------------------------------------------------
// Error enum -- single source of truth for the entire crate
// ---------------------------------------------------------------------------

/// Crate-level error type covering all Tailscale subsystems.
///
/// Uses [`thiserror`] for `Display` and `std::error::Error` impls.
/// Marked `#[non_exhaustive]` so downstream crates must handle future
/// variants with a wildcard match arm.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    // =======================================================================
    // I/O subsystem
    // =======================================================================

    /// An I/O error propagated from `std::io`.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    // =======================================================================
    // Binary / command subsystem
    // =======================================================================

    /// The `tailscale` binary was not found on `$PATH`.
    #[error("tailscale binary not found: {0}")]
    BinaryNotFound(String),

    /// An external command exited with a non-zero status.
    #[error("command failed: {program} exited with status {code:?}")]
    CommandFailed {
        /// The program that was invoked (e.g. `tailscale`).
        program: String,
        /// Exit code, or `None` if the process was killed / could not start.
        code: Option<i32>,
        /// Captured standard error (may be empty).
        stderr: String,
    },

    // =======================================================================
    // API subsystem
    // =======================================================================

    /// The Tailscale local HTTP API returned an error.
    #[error("API error: {0}")]
    ApiError(String),

    // =======================================================================
    // Connection subsystem
    // =======================================================================

    /// Tailscale is not connected to the tailnet.
    #[error("not connected to tailnet")]
    NotConnected,

    // =======================================================================
    // ACL subsystem
    // =======================================================================

    /// An ACL policy error (invalid syntax, conflicting rules, etc.).
    #[error("ACL error: {0}")]
    AclError(String),

    // =======================================================================
    // DNS subsystem
    // =======================================================================

    /// A DNS configuration error.
    #[error("DNS error: {0}")]
    DnsError(String),

    // =======================================================================
    // Service subsystem
    // =======================================================================

    /// An error from the shared service-management layer
    /// ([`toride_service`]).
    #[error("service error: {0}")]
    Service(String),

    // =======================================================================
    // Catch-all
    // =======================================================================

    /// A generic error that does not fit into any specific category.
    #[error("{0}")]
    Other(String),
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
