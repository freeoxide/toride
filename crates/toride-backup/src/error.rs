//! Unified error types for the `toride-backup` crate.
//!
//! Every subsystem returns [`Error`] through the crate-level [`Result`] alias.
//! The enum is marked `#[non_exhaustive]` so new variants can be added without
//! a semver break.

/// Crate-level error type covering all backup subsystems.
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

    /// Required binary (restic or borg) not found on `$PATH`.
    #[error("binary not found: {0}")]
    BinaryNotFound(String),

    /// An external command exited with a non-zero status or could not be
    /// spawned.
    #[error("command failed: {0}")]
    CommandFailed(String),

    /// Failed to initialize a backup repository.
    #[error("repository init failed: {0}")]
    RepositoryInit(String),

    /// Failed to access or open an existing repository.
    #[error("repository access failed: {0}")]
    RepositoryAccess(String),

    /// Requested snapshot was not found in the repository.
    #[error("snapshot not found: {0}")]
    SnapshotNotFound(String),

    /// Restore operation failed.
    #[error("restore failed: {0}")]
    RestoreFailed(String),

    /// Scheduling error (cron expression, systemd timer, etc.).
    #[error("schedule error: {0}")]
    ScheduleError(String),

    /// Configuration file could not be parsed.
    #[error("config parse error: {0}")]
    ConfigParse(String),

    /// A JSON serialization/deserialization error from `serde_json`.
    ///
    /// Only present when the `serde` feature is enabled, so the various
    /// `serde_json::from_str(...)?` / `serde_json::to_string(...)?` sites
    /// throughout the crate can use the `?` operator.
    #[cfg(feature = "serde")]
    #[error("json error: {0}")]
    Serde(#[from] serde_json::Error),

    /// A generic error for cases that do not warrant a dedicated variant.
    #[error("{0}")]
    Other(String),
}

/// Crate-level result alias used throughout the library.
pub type Result<T> = std::result::Result<T, Error>;
