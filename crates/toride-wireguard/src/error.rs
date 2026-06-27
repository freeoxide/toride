//! Unified error types for the `toride-wireguard` crate.
//!
//! Every subsystem returns [`Error`] through the crate-level [`Result`] alias.
//! The enum is marked `#[non_exhaustive]` so new variants can be added without
//! a semver break.

// ---------------------------------------------------------------------------
// Error enum
// ---------------------------------------------------------------------------

/// Crate-level error type covering all WireGuard subsystems.
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

    /// Required WireGuard binary (`wg` or `wg-quick`) not found on `$PATH`.
    #[error("WireGuard binary not found: {0}")]
    BinaryNotFound(String),

    /// A command runner error (spawn failure, timeout, output-limit, etc.).
    ///
    /// Produced by the `toride-runner` execution layer.
    #[error("runner error: {0}")]
    Runner(#[from] toride_runner::Error),

    /// An external command returned a non-zero exit code.
    #[error("command failed: {0}")]
    CommandFailed(String),

    /// Failed to parse a WireGuard configuration file.
    #[error("config parse error: {0}")]
    ConfigParse(String),

    /// Failed to write a WireGuard configuration file.
    #[error("config write error: {0}")]
    ConfigWrite(String),

    /// No WireGuard interface with the given name was found.
    #[error("interface not found: {0}")]
    InterfaceNotFound(String),

    /// No WireGuard peer matching the given public key was found.
    #[error("peer not found: {0}")]
    PeerNotFound(String),

    /// Key generation failed.
    #[error("key generation failed: {0}")]
    KeyGeneration(String),

    /// An IP address or CIDR range is invalid.
    #[error("invalid address: {0}")]
    InvalidAddress(String),

    /// A catch-all error for cases that don't fit a specific variant.
    #[error("{0}")]
    Other(String),
}

// ---------------------------------------------------------------------------
// Crate-level result alias
// ---------------------------------------------------------------------------

/// Crate-level result alias used throughout the library.
pub type Result<T> = std::result::Result<T, Error>;
