//! Crate-wide error types for toride-harden.

/// Convenience alias for `Result<T, Error>`.
pub type Result<T> = std::result::Result<T, Error>;

/// All errors produced by toride-harden.
#[derive(Debug, Clone, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Generic I/O error.
    #[error("io error: {0}")]
    Io(String),

    /// A required system binary could not be located.
    #[error("binary not found: {0}")]
    BinaryNotFound(String),

    /// Command exited with a non-zero status.
    #[error("command failed (exit {exit_code:?}): {program} {args}\nstderr: {stderr}")]
    CommandFailed {
        /// Program name.
        program: String,
        /// Arguments passed.
        args: String,
        /// Exit code, if available.
        exit_code: Option<i32>,
        /// Standard error output.
        stderr: String,
    },

    /// Command execution timed out.
    #[error("command timed out after {timeout_secs}s: {program}")]
    CommandTimeout {
        /// Program that timed out.
        program: String,
        /// Timeout in seconds.
        timeout_secs: u64,
    },

    /// Sysctl output could not be parsed.
    #[error("sysctl parse error: {0}")]
    SysctlParse(String),

    /// Sysctl write failed.
    #[error("sysctl write failed: {0}")]
    SysctlWrite(String),

    /// Config file parse error.
    #[error("config parse error: {0}")]
    ConfigParse(String),

    /// Config file write error.
    #[error("config write error: {0}")]
    ConfigWrite(String),

    /// Mount operation failed.
    #[error("mount failed: {0}")]
    MountFailed(String),

    /// Unknown hardening profile name.
    #[error("unknown hardening profile: {0}")]
    ProfileUnknown(String),

    /// Catch-all for other errors.
    #[error("{0}")]
    Other(String),
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err.to_string())
    }
}

impl From<toride_runner::Error> for Error {
    fn from(err: toride_runner::Error) -> Self {
        match err {
            toride_runner::Error::CommandFailed {
                program,
                args,
                exit_code,
                stderr,
            } => Self::CommandFailed {
                program,
                args,
                exit_code,
                stderr,
            },
            toride_runner::Error::CommandTimeout {
                program, timeout, ..
            } => Self::CommandTimeout {
                program,
                timeout_secs: timeout.as_secs(),
            },
            toride_runner::Error::BinaryNotFound(name) => Self::BinaryNotFound(name),
            toride_runner::Error::Io(msg) => Self::Io(msg),
            other => Self::Other(other.to_string()),
        }
    }
}

impl From<toride_fs::Error> for Error {
    fn from(err: toride_fs::Error) -> Self {
        Self::Io(err.to_string())
    }
}
