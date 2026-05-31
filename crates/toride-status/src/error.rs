//! Error types for the toride status module.
//!
//! Defines [`StatusError`] — the unified error enum for all status-collection
//! operations. Each variant represents a distinct failure mode encountered
//! while gathering system, daemon, or SSH health data.
//!
//! The companion type alias [`StatusResult<T>`] is provided for convenience
//! throughout the status subsystem.
//!
//! # Error handling examples
//!
//! Using the `?` operator with I/O errors:
//!
//! ```
//! use toride_status::error::{StatusError, StatusResult};
//!
//! fn read_pid_file(path: &str) -> StatusResult<u32> {
//!     let content = std::fs::read_to_string(path)?;
//!     content.trim().parse::<u32>().map_err(|e| {
//!         StatusError::ParseError(format!("invalid PID: {e}"))
//!     })
//! }
//! ```
//!
//! Matching on specific error variants:
//!
//! ```
//! use toride_status::error::StatusError;
//!
//! fn handle_error(err: StatusError) {
//!     match err {
//!         StatusError::PermissionDenied(path) => {
//!             eprintln!("Cannot access {path}: permission denied");
//!         }
//!         StatusError::CommandNotFound(cmd) => {
//!             eprintln!("Install {cmd} or add it to PATH");
//!         }
//!         StatusError::CommandFailed { command, code, stderr } => {
//!             eprintln!("{command} exited {code}: {stderr}");
//!         }
//!         StatusError::CommandTimeout(cmd) => {
//!             eprintln!("{cmd} timed out");
//!         }
//!         StatusError::ParseError(msg) => {
//!             eprintln!("Parse error: {msg}");
//!         }
//!         StatusError::Io(e) => {
//!             eprintln!("I/O error: {e}");
//!         }
//!         StatusError::Unsupported(platform) => {
//!             eprintln!("Not supported on {platform}");
//!         }
//!         StatusError::DataUnavailable(msg) => {
//!             eprintln!("Data unavailable: {msg}");
//!         }
//!         StatusError::MissingProvider(name) => {
//!             eprintln!("Missing provider: {name}");
//!         }
//!         StatusError::StaleSample(msg) => {
//!             eprintln!("Stale sample: {msg}");
//!         }
//!         StatusError::RedactedData(msg) => {
//!             eprintln!("Redacted data: {msg}");
//!         }
//!         StatusError::OsApiError(msg) => {
//!             eprintln!("OS API error: {msg}");
//!         }
//!     }
//! }
//! ```
//!
//! Collecting results into a vector:
//!
//! ```
//! use toride_status::error::{StatusError, StatusResult};
//!
//! fn collect_metrics() -> Vec<StatusResult<String>> {
//!     vec![
//!         Ok("cpu: 45%".into()),
//!         Err(StatusError::DataUnavailable("swap not configured".into())),
//!         Ok("memory: 8GB".into()),
//!     ]
//! }
//! ```

/// Unified error type for status-collection operations.
///
/// Covers all failure modes that can occur while probing OS metrics,
/// daemon liveness, and SSH health. Variants are ordered roughly by
/// how likely they are to surface during normal operation.
#[derive(Debug, thiserror::Error)]
pub enum StatusError {
    /// A command or file access was denied by the OS.
    ///
    /// This typically means the current user lacks the privileges needed
    /// to read a resource (e.g., a PID file in a protected directory or
    /// another user's process information).
    #[error("permission denied: {0}")]
    PermissionDenied(String),

    /// A required external command could not be found on `PATH`.
    ///
    /// Raised when a status collector tries to invoke a binary (e.g.,
    /// `ssh`, `pgrep`) that is not installed or not on the search path.
    #[error("command not found: {0}")]
    CommandNotFound(String),

    /// An external command exited with a non-zero status code.
    ///
    /// Carries the command string, exit code, and any stderr output so
    /// callers can log or display the root cause without re-running the
    /// command.
    #[error("command failed: {command} exited {code}: {stderr}")]
    CommandFailed {
        /// The command and arguments that were executed.
        command: String,
        /// The process exit code.
        code: i32,
        /// Contents of the process's stderr stream.
        stderr: String,
    },

    /// An external command did not produce output within the allowed time.
    ///
    /// The inner string identifies which command timed out so callers can
    /// surface a meaningful message to the user.
    #[error("command timed out: {0}")]
    CommandTimeout(String),

    /// Output from a command or file could not be parsed into the expected
    /// structure.
    ///
    /// Covers malformed `/proc` entries, unexpected `sysctl` output, or any
    /// other data that does not match the expected format.
    #[error("parse error: {0}")]
    ParseError(String),

    /// A standard I/O error occurred.
    ///
    /// Transparently wraps [`std::io::Error`] so callers can propagate I/O
    /// failures with the `?` operator without additional boilerplate.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// The current platform or OS variant is not supported by a collector.
    ///
    /// Raised when a status probe is invoked on an operating system that
    /// does not expose the required interface (e.g., reading `/proc` on
    /// macOS).
    #[error("unsupported platform: {0}")]
    Unsupported(String),

    /// Expected data was not available from the OS or a subsystem.
    ///
    /// Raised when a collector runs successfully but the underlying data
    /// source returned empty or unavailable results (e.g., hostname could
    /// not be determined, memory info returned zero).
    #[error("data unavailable: {0}")]
    DataUnavailable(String),

    /// A required provider was not registered or available.
    #[error("missing provider: {0}")]
    MissingProvider(String),

    /// A sample is stale and should not be used for rate calculations.
    #[error("stale sample: {0}")]
    StaleSample(String),

    /// Data was redacted due to privacy constraints.
    #[error("redacted data: {0}")]
    RedactedData(String),

    /// The OS-level API returned an error.
    #[error("OS API error: {0}")]
    OsApiError(String),
}

impl Clone for StatusError {
    fn clone(&self) -> Self {
        match self {
            Self::PermissionDenied(s) => Self::PermissionDenied(s.clone()),
            Self::CommandNotFound(s) => Self::CommandNotFound(s.clone()),
            Self::CommandFailed { command, code, stderr } => Self::CommandFailed {
                command: command.clone(),
                code: *code,
                stderr: stderr.clone(),
            },
            Self::CommandTimeout(s) => Self::CommandTimeout(s.clone()),
            Self::ParseError(s) => Self::ParseError(s.clone()),
            Self::Io(e) => Self::Io(std::io::Error::new(e.kind(), e.to_string())),
            Self::Unsupported(s) => Self::Unsupported(s.clone()),
            Self::DataUnavailable(s) => Self::DataUnavailable(s.clone()),
            Self::MissingProvider(s) => Self::MissingProvider(s.clone()),
            Self::StaleSample(s) => Self::StaleSample(s.clone()),
            Self::RedactedData(s) => Self::RedactedData(s.clone()),
            Self::OsApiError(s) => Self::OsApiError(s.clone()),
        }
    }
}

/// Convenience alias for `Result<T, StatusError>`.
///
/// Used throughout the status subsystem to avoid repeating the error type
/// in every function signature.
pub type StatusResult<T> = Result<T, StatusError>;

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Display formatting tests ----

    #[test]
    fn permission_denied_display() {
        let err = StatusError::PermissionDenied("/etc/shadow".into());
        assert_eq!(err.to_string(), "permission denied: /etc/shadow");
    }

    #[test]
    fn command_not_found_display() {
        let err = StatusError::CommandNotFound("pgrep".into());
        assert_eq!(err.to_string(), "command not found: pgrep");
    }

    #[test]
    fn command_failed_display() {
        let err = StatusError::CommandFailed {
            command: "ssh -O check".into(),
            code: 255,
            stderr: "Connection refused".into(),
        };
        assert_eq!(
            err.to_string(),
            "command failed: ssh -O check exited 255: Connection refused"
        );
    }

    #[test]
    fn command_timeout_display() {
        let err = StatusError::CommandTimeout("ssh-keygen -l".into());
        assert_eq!(err.to_string(), "command timed out: ssh-keygen -l");
    }

    #[test]
    fn parse_error_display() {
        let err = StatusError::ParseError("unexpected cpu line".into());
        assert_eq!(err.to_string(), "parse error: unexpected cpu line");
    }

    #[test]
    fn data_unavailable_display() {
        let err = StatusError::DataUnavailable("hostname".into());
        assert_eq!(err.to_string(), "data unavailable: hostname");
    }

    #[test]
    fn io_display() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file missing");
        let err = StatusError::from(io_err);
        assert_eq!(err.to_string(), "io error: file missing");
    }

    #[test]
    fn unsupported_display() {
        let err = StatusError::Unsupported("windows".into());
        assert_eq!(err.to_string(), "unsupported platform: windows");
    }

    // ---- Send + Sync bounds ----

    #[test]
    fn error_is_send() {
        fn assert_send<T: Send>() {}
        assert_send::<StatusError>();
    }

    #[test]
    fn error_is_sync() {
        fn assert_sync<T: Sync>() {}
        assert_sync::<StatusError>();
    }

    // ---- ? operator / From conversion ----

    #[test]
    fn io_error_converts_via_from() {
        fn make_error() -> StatusResult<()> {
            let _f = std::fs::File::open("/nonexistent/path/that/should/not/exist")?;
            Ok(())
        }

        let result = make_error();
        assert!(result.is_err());
        match result.unwrap_err() {
            StatusError::Io(e) => {
                assert_eq!(e.kind(), std::io::ErrorKind::NotFound);
            }
            other => panic!("expected Io variant, got: {other:?}"),
        }
    }
}
