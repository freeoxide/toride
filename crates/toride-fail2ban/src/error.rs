//! Unified error types for the `toride-fail2ban` crate.
//!
//! Every subsystem returns [`Error`] through the crate-level [`Result`] alias.
//! The enum is marked `#[non_exhaustive]` so new variants can be added without
//! a semver break.
//!
//! # Variant naming convention
//!
//! Simple string-based errors use tuple variants (e.g. `Config(String)`).
//! Structured errors that carry multiple fields use struct variants
//! (e.g. `Command { program, code, stderr }`).
//!
//! # Serialization
//!
//! When the `serde` feature is enabled, errors serialize as a two-field map:
//!
//! ```json
//! {"type": "config", "detail": "missing bantime"}
//! ```

#[cfg(feature = "serde")]
use std::fmt;

// ---------------------------------------------------------------------------
// Error enum -- single source of truth for the entire crate
// ---------------------------------------------------------------------------

/// Crate-level error type covering all subsystems.
///
/// Uses [`thiserror`] for `Display` and `std::error::Error` impls.
/// Marked `#[non_exhaustive]` so downstream crates must handle future
/// variants with a wildcard match arm.
///
/// This enum is the *unified* source of truth: it merges the legacy
/// variants that were previously defined in `lib.rs` with the newer
/// structured variants, so all existing `crate::Error::SomeVariant`
/// references throughout the codebase compile without changes.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    // =======================================================================
    // I/O subsystem
    // =======================================================================
    /// An I/O error propagated from `std::io` or `fs-err`.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    // =======================================================================
    // Serialization subsystem
    // =======================================================================
    /// A JSON serialization or deserialization error.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    // =======================================================================
    // Configuration subsystem
    // =======================================================================
    /// Configuration file missing at expected path.
    #[error("Config file not found: {0}")]
    ConfigNotFound(String),

    /// A configuration value is missing, malformed, or otherwise invalid.
    #[error("Invalid config value: {0}")]
    InvalidConfig(String),

    /// A generic configuration error (used by newer subsystems).
    #[error("config error: {0}")]
    Config(String),

    // =======================================================================
    // Ban subsystem
    // =======================================================================
    /// Invalid IP address or CIDR notation.
    #[error("Invalid IP or CIDR: {0}")]
    InvalidIp(String),

    /// IP address is already banned.
    #[error("IP already banned: {0}")]
    AlreadyBanned(String),

    /// IP address is not currently banned.
    #[error("IP not banned: {0}")]
    NotBanned(String),

    // =======================================================================
    // Log parsing subsystem
    // =======================================================================
    /// Invalid regular expression pattern.
    #[error("Invalid regex pattern: {0}")]
    InvalidRegex(String),

    /// A regular expression pattern is invalid or incompatible with Fail2Ban
    /// (structured variant used by newer subsystems).
    #[error("regex error: {0}")]
    Regex(String),

    /// Log file could not be read.
    #[error("Log file error: {0}")]
    LogFileError(String),

    // =======================================================================
    // Command / action subsystem
    // =======================================================================
    /// Command execution failed (string-based variant).
    #[error("Command execution failed: {0}")]
    CommandFailed(String),

    /// An external command exited with a non-zero status or could not be
    /// spawned (structured variant).
    #[error("{msg}", msg = format_command_error(program, *code, stderr))]
    Command {
        /// The program that was invoked (e.g. `fail2ban-client`).
        program: String,
        /// Exit code, or `None` if the process was killed / could not start.
        code: Option<i32>,
        /// Captured standard error (may be empty).
        stderr: String,
    },

    /// Command execution timed out (duration-only variant).
    #[error("Command timed out after {0:?}")]
    CommandTimeout(std::time::Duration),

    /// A command timed out before completing (structured variant).
    #[error("command `{program}` timed out after {}", humantime::format_duration(*duration))]
    Timeout {
        /// The program that was invoked.
        program: String,
        /// Wall-clock duration before the timeout fired.
        duration: std::time::Duration,
    },

    // =======================================================================
    // Jail subsystem
    // =======================================================================
    /// Jail with the given name already exists.
    #[error("Jail already exists: {0}")]
    JailAlreadyExists(String),

    /// Jail with the given name not found.
    #[error("Jail not found: {0}")]
    JailNotFound(String),

    // =======================================================================
    // Lookup subsystem
    // =======================================================================
    /// Required binary not found on `$PATH`, or a requested resource was not
    /// found.
    #[error("not found: {0}")]
    NotFound(String),

    // =======================================================================
    // Validation subsystem
    // =======================================================================
    /// A spec or input value failed validation rules.
    #[error("validation error: {0}")]
    Validation(String),

    // =======================================================================
    // Doctor subsystem
    // =======================================================================
    /// A doctor check produced an error (distinct from a *finding*).
    #[error("doctor error: {0}")]
    Doctor(String),

    // =======================================================================
    // Permission subsystem
    // =======================================================================
    /// A permission check failed (file mode, ownership, or OS capability).
    #[error("permission denied: {0}")]
    PermissionDenied(String),

    // =======================================================================
    // Locking subsystem
    // =======================================================================
    /// Advisory file lock could not be acquired for config write coordination.
    #[error("lock error: {0}")]
    LockFailed(String),

    // =======================================================================
    // Parsing subsystem
    // =======================================================================
    /// A string could not be parsed into the expected type.
    #[error("parse error: {0}")]
    Parse(String),
}

// ---------------------------------------------------------------------------
// Crate-level result alias
// ---------------------------------------------------------------------------

/// Crate-level result alias used throughout the library.
pub type Result<T> = std::result::Result<T, Error>;

// ---------------------------------------------------------------------------
// Serialize helper (gated behind the `serde` feature)
// ---------------------------------------------------------------------------

#[cfg(feature = "serde")]
impl serde::Serialize for Error {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;

        // Two-field map: { "type": "<variant>", "detail": "<message>" }
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
            Self::Config(_) => "config",
            Self::InvalidIp(_) => "invalid_ip",
            Self::AlreadyBanned(_) => "already_banned",
            Self::NotBanned(_) => "not_banned",
            Self::InvalidRegex(_) => "invalid_regex",
            Self::Regex(_) => "regex",
            Self::LogFileError(_) => "log_file_error",
            Self::CommandFailed(_) => "command_failed",
            Self::Command { .. } => "command",
            Self::CommandTimeout(_) => "command_timeout",
            Self::Timeout { .. } => "timeout",
            Self::JailAlreadyExists(_) => "jail_already_exists",
            Self::JailNotFound(_) => "jail_not_found",
            Self::NotFound(_) => "not_found",
            Self::Validation(_) => "validation",
            Self::Doctor(_) => "doctor",
            Self::PermissionDenied(_) => "permission_denied",
            Self::LockFailed(_) => "lock_failed",
            Self::Parse(_) => "parse",
            // NOTE: The `_` wildcard is required for `#[non_exhaustive]`
            // forward compatibility with external callers. Within this crate
            // it is unreachable, so suppress the lint.
            #[allow(unreachable_patterns)]
            _ => "unknown",
        }
    }
}

// ---------------------------------------------------------------------------
// Private helpers for Display formatting
// ---------------------------------------------------------------------------

/// Builds the full display message for [`Error::Command`].
fn format_command_error(program: &str, code: Option<i32>, stderr: &str) -> String {
    let status = match code {
        Some(c) => format!("exited with status {c}"),
        None => "could not be started".to_owned(),
    };
    let suffix = if stderr.is_empty() {
        String::new()
    } else {
        format!(" \u{2014} {}", stderr.trim())
    };
    format!("command `{program}` failed: {status}{suffix}")
}

#[cfg(test)]
#[path = "error.test.rs"]
mod tests;
