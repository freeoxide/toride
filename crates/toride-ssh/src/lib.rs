#![warn(missing_docs)]
#![expect(dead_code, reason = "scaffolding for modules under active development")]
#![expect(
    clippy::unused_async,
    reason = "async fns are scaffolding for future async operations"
)]
#![expect(
    clippy::must_use_candidate,
    reason = "service methods are call-and-forget; callers rarely use return"
)]
#![expect(
    clippy::missing_errors_doc,
    reason = "error docs added incrementally; tracked for full coverage"
)]
#![expect(
    clippy::doc_markdown,
    reason = "SSH-specific terms like ed25519 trigger false positives"
)]
#![expect(
    clippy::struct_excessive_bools,
    reason = "AuthorizedKeyOptions models an external SSH format with many boolean flags"
)]

//! `toride-ssh` — async SSH manager library wrapping `ssh-key`, `ssh2-config-rs`,
//! `ssh-agent-lib`, and OpenSSH CLI tools behind a unified API.

mod paths;
mod types;

/// SSH agent management (listing, adding, removing keys).
pub mod agent;
/// `authorized_keys` file parsing and management.
pub mod authorized_keys;
/// SSH certificate and CA operations.
#[cfg(feature = "certificate")]
pub mod certificate;
/// SSH config file parsing, editing, and resolution.
pub mod config;
/// SSH diagnostic checks (local and remote).
pub mod doctor;
/// Port forwarding management via ControlMaster.
pub mod forward;
/// SSH key management (inventory, generation, repair).
pub mod key;
/// `known_hosts` file management and host key scanning.
pub mod known_hosts;
/// Helpers for running external SSH tools (`ssh-keygen`, `ssh-keyscan`, etc.).
pub mod runner;

pub use paths::SshPaths;
pub use types::*;

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
    #[cfg(feature = "certificate")]
    #[error("certificate parse failed: {0}")]
    CertificateParseFailed(String),
    /// Certificate has expired.
    #[cfg(feature = "certificate")]
    #[error("certificate expired: {0}")]
    CertificateExpired(String),
    /// Certificate is not yet valid.
    #[cfg(feature = "certificate")]
    #[error("certificate not yet valid: {0}")]
    CertificateNotYetValid(String),

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

    /// Underlying I/O error.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// Background task panicked or was cancelled.
    #[error("background task failed: {0}")]
    TaskFailed(String),
}

/// Alias for results in this crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Entry point for all SSH management operations.
///
/// `SshManager` is cheaply [`Clone`](Clone)-able and safe to share
/// across async tasks.
#[derive(Clone)]
pub struct SshManager {
    paths: SshPaths,
}

impl SshManager {
    /// Create a new manager resolving `~/.ssh` from the user's home directory.
    pub fn new() -> Result<Self> {
        let paths = SshPaths::new()?;
        Ok(Self { paths })
    }

    /// Key management operations.
    pub fn keys(&self) -> key::KeyService<'_> {
        key::KeyService::new(&self.paths)
    }

    /// SSH config operations.
    pub fn config(&self) -> config::ConfigService<'_> {
        config::ConfigService::new(&self.paths)
    }

    /// SSH agent operations.
    pub fn agent(&self) -> agent::AgentService<'_> {
        agent::AgentService::new(&self.paths)
    }

    /// Diagnostic checks.
    pub fn doctor(&self) -> doctor::DoctorService<'_> {
        doctor::DoctorService::new(&self.paths)
    }

    /// Known hosts management (listing, scanning, adding, removing).
    pub fn known_hosts(&self) -> known_hosts::KnownHostsService<'_> {
        known_hosts::KnownHostsService::new(&self.paths)
    }

    /// SSH certificate and CA operations (inspection, validity, KRL).
    #[cfg(feature = "certificate")]
    pub fn certificate(&self) -> certificate::CertificateService {
        certificate::CertificateService::new()
    }

    /// Port forwarding management via ControlMaster.
    pub fn forward(&self) -> forward::ForwardService<'_> {
        forward::ForwardService::new(&self.paths)
    }
}
