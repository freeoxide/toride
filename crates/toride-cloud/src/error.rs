//! Unified error types for the `toride-cloud` crate.
//!
//! Every subsystem returns [`Error`] through the crate-level [`Result`] alias.
//! The enum is marked `#[non_exhaustive]` so new variants can be added without
//! a semver break.

use std::fmt::Write as _;

// ---------------------------------------------------------------------------
// Error enum -- single source of truth for the entire crate
// ---------------------------------------------------------------------------

/// Crate-level error type covering all cloud provider subsystems.
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

    /// Required binary not found on `$PATH`.
    #[error("binary not found: {0}")]
    BinaryNotFound(String),

    /// An external command exited with a non-zero status.
    #[error("command `{program}` failed: {message}")]
    CommandFailed {
        /// The program that was invoked.
        program: String,
        /// Human-readable error message.
        message: String,
    },

    /// The cloud provider could not be detected or is not supported.
    #[error("cloud provider not found: {0}")]
    ProviderNotFound(String),

    /// A firewall rule conflicts with an existing rule.
    #[error("firewall rule conflict: {0}")]
    FirewallRuleConflict(String),

    /// A configuration file could not be parsed.
    #[error("config parse error: {0}")]
    ConfigParse(String),

    /// A catch-all error for cases that don't fit other variants.
    #[error("{0}")]
    Other(String),
}

// ---------------------------------------------------------------------------
// Crate-level result alias
// ---------------------------------------------------------------------------

/// Crate-level result alias used throughout the library.
pub type Result<T> = std::result::Result<T, Error>;

// ---------------------------------------------------------------------------
// Conversion from toride_runner::Error
// ---------------------------------------------------------------------------

/// Single, shared translation of [`toride_runner::Error`] into the cloud
/// [`Error`].
///
/// Every cloud provider (`aws`, `gcp`, `hetzner`, `digitalocean`) routes its
/// runner failures through this impl so the mapping cannot drift between
/// providers. Callers that need to inspect a structured failure (for example,
/// promoting a "duplicate rule" message to [`Error::FirewallRuleConflict`])
/// match on [`toride_runner::Error`] *before* it is mapped, then delegate the
/// remaining variants to this conversion via `?` / `.map_err(Error::from)`.
///
/// Behaviour:
///
/// - [`toride_runner::Error::BinaryNotFound`] is preserved verbatim.
/// - [`toride_runner::Error::SpawnFailed`] is folded into
///   [`Error::BinaryNotFound`] (the most common cause is a missing binary).
/// - [`toride_runner::Error::CommandFailed`] folds its structured fields
///   (`args`, `exit_code`, `stderr`) into a single human-readable `message`,
///   so callers can string-match sentinels (e.g. `InvalidPermission.Duplicate`)
///   without unpacking individual fields.
/// - The timeout / wait / stdin / output-limit variants each map to
///   [`Error::CommandFailed`] keyed on the offending program.
/// - Everything else becomes [`Error::Other`].
impl From<toride_runner::Error> for Error {
    fn from(err: toride_runner::Error) -> Self {
        match err {
            toride_runner::Error::BinaryNotFound(program) => Error::BinaryNotFound(program),
            toride_runner::Error::SpawnFailed { program, detail } => {
                Error::BinaryNotFound(format!("{program}: {detail}"))
            }
            toride_runner::Error::Io(msg)
            | toride_runner::Error::OutputParse(msg)
            | toride_runner::Error::Other(msg) => Error::Other(msg),
            toride_runner::Error::CommandFailed {
                program,
                args,
                exit_code,
                stderr,
            } => {
                // Fold the structured fields into a single human-readable
                // message so callers can string-match sentinels (e.g. the AWS
                // `InvalidPermission.Duplicate` marker) without unpacking each
                // field individually.
                let mut message = format!("args: {args}");
                if let Some(code) = exit_code {
                    let _ = write!(message, "\nexit: {code}");
                }
                let stderr = stderr.trim();
                if !stderr.is_empty() {
                    let _ = write!(message, "\nstderr: {stderr}");
                }
                Error::CommandFailed { program, message }
            }
            toride_runner::Error::CommandTimeout {
                program,
                timeout,
                args,
            } => {
                let mut message = format!("command timed out after {}s", timeout.as_secs().max(1));
                if !args.is_empty() {
                    let _ = write!(message, "\nargs: {}", args.join(" "));
                }
                Error::CommandFailed { program, message }
            }
            toride_runner::Error::OutputLimitExceeded {
                program,
                limit,
                observed,
                args,
            } => {
                let mut message = format!("output limit exceeded ({limit} bytes, saw {observed})");
                if !args.is_empty() {
                    let _ = write!(message, "\nargs: {args}");
                }
                Error::CommandFailed { program, message }
            }
            toride_runner::Error::WaitFailed { program, detail } => Error::CommandFailed {
                program,
                message: format!("failed to wait: {detail}"),
            },
            toride_runner::Error::StdinFailed { program, detail } => Error::CommandFailed {
                program,
                message: format!("failed to write stdin: {detail}"),
            },
            // `toride_runner::Error` is `#[non_exhaustive]`; map any future
            // variant onto `Error::Other` so this impl never breaks.
            other => Error::Other(other.to_string()),
        }
    }
}
