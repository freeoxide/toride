#![warn(missing_docs)]
#![expect(
    clippy::must_use_candidate,
    reason = "service methods are call-and-forget; callers rarely use return"
)]
#![expect(
    clippy::doc_markdown,
    reason = "SSH-specific terms like ed25519 trigger false positives"
)]

//! `toride-ssh-core` — shared types, error definitions, path resolution,
//! CLI runner abstraction, and undo mechanism used by all `toride-ssh` sub-crates.

pub mod paths;
mod types;

pub mod privilege;
pub mod runner;
pub mod undo;

pub use paths::SshPaths;
pub use privilege::{PrivilegedOp, is_root, run_privileged};
pub use runner::{CliRunner, DefaultCliRunner, MockCliRunner};
pub use types::*;

// ---------------------------------------------------------------------------
// Error & Result
// ---------------------------------------------------------------------------

/// Errors returned by `toride-ssh` operations.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// User home directory could not be resolved.
    #[error("home directory not found")]
    HomeNotFound,

    // Key subsystem
    /// No key found at the specified path or name.
    #[error("key not found: {0}")]
    KeyNotFound(String),
    /// A key already exists at the target path.
    #[error("key already exists: {0}")]
    KeyExists(String),
    /// Failed to parse a key file.
    #[error("key parse failed: {0}")]
    KeyParseFailed(String),
    /// Key generation failed.
    #[error("key generation failed: {0}")]
    KeyGenerationFailed(String),
    /// Key name validation failed (empty, path traversal, etc.).
    #[error("invalid key name: {0}")]
    InvalidKeyName(String),
    /// The key requires a passphrase but none was provided.
    #[error("passphrase required")]
    PassphraseRequired,
    /// Key format is not supported (e.g. SEC1, legacy PEM).
    #[error("unsupported key format: {0}")]
    UnsupportedKeyFormat(String),

    // Config subsystem
    /// Failed to parse `~/.ssh/config`.
    #[error("config parse failed: {0}")]
    ConfigParseFailed(String),
    /// Managed block not found in config.
    #[error("managed block not found: {0}")]
    ManagedBlockNotFound(String),
    /// Failed to write `~/.ssh/config`.
    #[error("config write failed: {0}")]
    ConfigWriteFailed(String),
    /// No `Host` block matches the given alias.
    #[error("host not found: {0}")]
    HostNotFound(String),
    /// Multiple `Host` blocks share the same alias.
    #[error("duplicate host alias: {0}")]
    DuplicateHost(String),
    /// An `Include` chain forms a cycle.
    #[error("config include cycle detected: {0}")]
    ConfigIncludeCycle(String),
    /// Token (`%h`, `%d`, etc.) could not be expanded.
    #[error("token expansion failed for {token}: {reason}")]
    TokenExpansionFailed {
        /// The token that failed to expand.
        token: Box<str>,
        /// Why expansion failed.
        reason: Box<str>,
    },

    // Known hosts
    /// Failed to parse `known_hosts`.
    #[error("known_hosts parse failed: {0}")]
    KnownHostsParseFailed(String),
    /// Host not present in `known_hosts`.
    #[error("host not known: {0}")]
    HostNotKnown(String),

    // Authorized keys
    /// Failed to parse `authorized_keys`.
    #[error("authorized_keys parse failed: {0}")]
    AuthorizedKeysParseFailed(String),
    /// Failed to write `authorized_keys`.
    #[error("authorized_keys write failed: {0}")]
    AuthorizedKeysWriteFailed(String),

    // Agent subsystem
    /// SSH agent socket not found or unreachable.
    #[error("SSH agent not available")]
    AgentNotAvailable,
    /// Agent rejected the operation.
    #[error("agent operation failed: {0}")]
    AgentOperationFailed(String),
    /// Key not loaded in the agent.
    #[error("agent key not found: {0}")]
    AgentKeyNotFound(String),

    // Doctor
    /// A diagnostic check itself failed.
    #[error("check failed: {0}")]
    CheckFailed(String),

    // Certificate
    /// Failed to parse an SSH certificate.
    #[error("certificate parse failed: {0}")]
    CertificateParseFailed(String),
    /// Certificate has expired.
    #[error("certificate expired: {0}")]
    CertificateExpired(String),
    /// Certificate is not yet valid.
    #[error("certificate not yet valid: {0}")]
    CertificateNotYetValid(String),
    /// Failed to parse a Key Revocation List.
    #[error("KRL parse failed: {0}")]
    KrlParseFailed(String),

    // Forward
    /// Port forwarding setup failed.
    #[error("port forward failed: {0}")]
    ForwardFailed(String),
    /// No matching port forward found.
    #[error("port forward not found: {0}")]
    ForwardNotFound(String),

    // CLI tool execution
    /// Required CLI tool not found in `PATH`.
    #[error("tool not found in PATH: {0}")]
    ToolNotFound(String),
    /// External command returned a non-zero exit code.
    #[error("command failed: {0}")]
    CommandFailed(String),
    /// Could not parse external command output.
    #[error("command output parse failed: {0}")]
    CommandParseFailed(String),

    /// Filesystem permission error.
    #[error("permission denied: {0}")]
    PermissionDenied(String),

    /// A privileged command (run via `sudo -n` or as root) failed.
    ///
    /// Includes the command's stderr so the UI can surface a useful message
    /// (e.g. "sudo: a password is required").
    #[error("privileged operation failed: {0}")]
    SudoFailed(String),

    /// The new `sshd_config` was rejected by `sshd -t`.
    ///
    /// Carries `sshd`'s diagnostic output explaining why the config is invalid.
    /// The write is aborted before the live config is touched.
    #[error("sshd_config validation failed: {0}")]
    SshdConfigInvalid(String),

    /// The `sshd` binary could not be found, so the new config could not be
    /// validated.
    ///
    /// We fail closed rather than installing an unvalidatable config: a bad
    /// `sshd_config` can lock the user out of SSH, so we never install one we
    /// could not check. Carries the detail we observed (e.g. the privileged
    /// invocation's stderr).
    #[error("sshd binary not found; cannot validate sshd_config: {0}")]
    SshdNotFound(String),

    /// Underlying I/O error.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// Background task panicked or was cancelled.
    #[error("background task failed: {0}")]
    TaskFailed(String),
}

/// Alias for results in this crate.
pub type Result<T> = std::result::Result<T, Error>;
