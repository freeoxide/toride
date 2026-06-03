//! Crate-wide error types for toride-runner.

use std::time::Duration;

/// Convenience alias for `Result<T, Error>`.
pub type Result<T> = std::result::Result<T, Error>;

/// All errors produced by toride-runner.
#[derive(Debug, Clone, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// An I/O error occurred.
    #[error("io error: {0}")]
    Io(String),

    /// A required binary could not be found on the system.
    #[error("binary not found: {0}")]
    BinaryNotFound(String),

    /// A command exited with a non-zero status.
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
    #[error("command timed out: {program} (timeout: {}s)", .timeout.as_secs())]
    CommandTimeout {
        /// Program that timed out.
        program: String,
        /// Arguments that were passed.
        args: Vec<String>,
        /// The timeout duration that was exceeded.
        timeout: Duration,
    },

    /// Failed to spawn a child process.
    #[error("failed to spawn '{program}': {detail}")]
    SpawnFailed {
        /// Program name.
        program: String,
        /// Underlying error message.
        detail: String,
    },

    /// Failed to wait for a child process.
    #[error("failed to wait for '{program}': {detail}")]
    WaitFailed {
        /// Program name.
        program: String,
        /// Underlying error message.
        detail: String,
    },

    /// Failed to write to the child's stdin.
    #[error("failed to write stdin for '{program}': {detail}")]
    StdinFailed {
        /// Program name.
        program: String,
        /// Underlying error message.
        detail: String,
    },

    /// Command output could not be parsed.
    #[error("failed to parse command output: {0}")]
    OutputParse(String),

    /// Catch-all for other errors.
    #[error("{0}")]
    Other(String),
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err.to_string())
    }
}
