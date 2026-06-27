//! Unified error types for the `toride-users` crate.
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
//! {"type": "user_not_found", "detail": "user \"deployer\" not found in /etc/passwd"}
//! ```

// ---------------------------------------------------------------------------
// Error enum -- single source of truth for the entire crate
// ---------------------------------------------------------------------------

/// Crate-level error type covering all subsystems.
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

    /// A required binary (e.g. `useradd`, `passwd`) was not found on `$PATH`.
    #[error("binary not found: {0}")]
    BinaryNotFound(String),

    /// An external command returned a non-zero exit code.
    #[error("command failed: {program} exited with status {code:?}")]
    CommandFailed {
        /// The program that was invoked.
        program: String,
        /// Exit code, or `None` if the process could not start.
        code: Option<i32>,
        /// Captured standard error (may be empty).
        stderr: String,
    },

    /// User account not found in `/etc/passwd`.
    #[error("user not found: {0}")]
    UserNotFound(String),

    /// User account already exists.
    #[error("user already exists: {0}")]
    UserExists(String),

    /// Group not found in `/etc/group`.
    #[error("group not found: {0}")]
    GroupNotFound(String),

    /// Group already exists.
    #[error("group already exists: {0}")]
    GroupExists(String),

    /// Sudoers configuration error (syntax, permissions, etc.).
    #[error("sudoers error: {0}")]
    SudoError(String),

    /// PAM configuration error.
    #[error("PAM error: {0}")]
    PamError(String),

    /// TOTP/2FA enrollment or verification error.
    #[error("TOTP error: {0}")]
    TotpError(String),

    /// Password policy violation.
    #[error("password policy violation: {0}")]
    PasswordPolicy(String),

    /// A spec or input value failed validation rules.
    #[error("validation error: {0}")]
    Validation(String),

    /// A catch-all for errors that do not fit other variants.
    #[error("{0}")]
    Other(String),
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

        let mut s = serializer.serialize_struct("Error", 2)?;
        s.serialize_field("type", self.tag())?;
        s.serialize_field("detail", &self.to_string())?;
        s.end()
    }
}

#[cfg(feature = "serde")]
impl Error {
    /// Returns the short variant tag used as the `type` field in JSON output.
    fn tag(&self) -> &'static str {
        match self {
            Self::Io(_) => "io",
            Self::BinaryNotFound(_) => "binary_not_found",
            Self::CommandFailed { .. } => "command_failed",
            Self::UserNotFound(_) => "user_not_found",
            Self::UserExists(_) => "user_exists",
            Self::GroupNotFound(_) => "group_not_found",
            Self::GroupExists(_) => "group_exists",
            Self::SudoError(_) => "sudo_error",
            Self::PamError(_) => "pam_error",
            Self::TotpError(_) => "totp_error",
            Self::PasswordPolicy(_) => "password_policy",
            Self::Validation(_) => "validation",
            Self::Other(_) => "other",
            #[allow(unreachable_patterns)]
            _ => "unknown",
        }
    }
}
