//! Unified error types for the `toride-fail2ban` crate.
//!
//! Every subsystem returns [`Error`] through the crate-level [`Result`] alias.
//! The enum is marked `#[non_exhaustive]` so new variants can be added without
//! a semver break.
//!
//! # Serialization
//!
//! When the `serde` feature is enabled, errors serialize as a two-field map:
//!
//! ```json
//! {"type": "invalid_config", "detail": "missing bantime"}
//! ```

#[cfg(feature = "serde")]
use std::fmt;

/// Crate-level error type covering all subsystems.
///
/// Uses [`thiserror`] for `Display` and `std::error::Error` impls.
/// Marked `#[non_exhaustive]` so downstream crates must handle future
/// variants with a wildcard match arm.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// An I/O error propagated from `std::io` or `fs-err`.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// A JSON serialization or deserialization error.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Configuration file missing at expected path.
    #[error("Config file not found: {0}")]
    ConfigNotFound(String),

    /// A configuration value is missing, malformed, or otherwise invalid.
    #[error("Invalid config value: {0}")]
    InvalidConfig(String),

    /// Invalid IP address or CIDR notation.
    #[error("Invalid IP or CIDR: {0}")]
    InvalidIp(String),

    /// IP address is already banned.
    #[error("IP already banned: {0}")]
    AlreadyBanned(String),

    /// IP address is not currently banned.
    #[error("IP not banned: {0}")]
    NotBanned(String),

    /// Invalid regular expression pattern.
    #[error("Invalid regex pattern: {0}")]
    InvalidRegex(String),

    /// Log file could not be read.
    #[error("Log file error: {0}")]
    LogFileError(String),

    /// Command execution failed.
    #[error("Command execution failed: {0}")]
    CommandFailed(String),

    /// Command execution timed out after the given duration.
    #[error("Command timed out after {0:?}")]
    CommandTimeout(std::time::Duration),

    /// Jail with the given name already exists.
    #[error("Jail already exists: {0}")]
    JailAlreadyExists(String),

    /// Jail with the given name not found.
    #[error("Jail not found: {0}")]
    JailNotFound(String),

    /// Required binary not found on `$PATH`, or a requested resource was not
    /// found.
    #[error("not found: {0}")]
    NotFound(String),

    /// A spec or input value failed validation rules.
    #[error("validation error: {0}")]
    Validation(String),

    /// Advisory file lock could not be acquired for config write coordination.
    #[error("lock error: {0}")]
    LockFailed(String),
}

/// Crate-level result alias used throughout the library.
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(feature = "serde")]
impl serde::Serialize for Error {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;

        let mut s = serializer.serialize_struct("Error", 2)?;
        s.serialize_field("type", self.tag())?;
        s.serialize_field("detail", &<dyn fmt::Display>::to_string(self))?;
        s.end()
    }
}

#[cfg(feature = "serde")]
impl Error {
    /// Returns the short variant tag used as the `type` field in JSON output.
    fn tag(&self) -> &'static str {
        match self {
            Self::Io(_) => "io",
            Self::Json(_) => "json",
            Self::ConfigNotFound(_) => "config_not_found",
            Self::InvalidConfig(_) => "invalid_config",
            Self::InvalidIp(_) => "invalid_ip",
            Self::AlreadyBanned(_) => "already_banned",
            Self::NotBanned(_) => "not_banned",
            Self::InvalidRegex(_) => "invalid_regex",
            Self::LogFileError(_) => "log_file_error",
            Self::CommandFailed(_) => "command_failed",
            Self::CommandTimeout(_) => "command_timeout",
            Self::JailAlreadyExists(_) => "jail_already_exists",
            Self::JailNotFound(_) => "jail_not_found",
            Self::NotFound(_) => "not_found",
            Self::Validation(_) => "validation",
            Self::LockFailed(_) => "lock_failed",
            // The `_` wildcard is required for `#[non_exhaustive]`
            // forward compatibility with external callers. Within this crate
            // it is unreachable, so suppress the lint.
            #[allow(unreachable_patterns)]
            _ => "unknown",
        }
    }
}

#[cfg(test)]
#[path = "error.test.rs"]
mod tests;
