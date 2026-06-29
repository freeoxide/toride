//! Crate-wide error types for ufw-kit.

/// Convenience alias for `Result<T, Error>`.
pub type Result<T> = std::result::Result<T, Error>;

/// All errors produced by ufw-kit.
#[derive(Debug, Clone, thiserror::Error)]
pub enum Error {
    // ── Command runner ────────────────────────────────────────────────
    /// The `ufw` binary could not be located on the system.
    #[error("ufw binary not found: {0}")]
    UfwNotFound(String),

    /// A required system binary could not be located.
    #[error("binary not found: {0}")]
    BinaryNotFound(String),

    /// Command execution timed out.
    #[error("command timed out after {timeout_secs}s: {program}")]
    CommandTimeout {
        /// Program that timed out.
        program: String,
        /// Timeout in seconds.
        timeout_secs: u64,
    },

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

    /// Command could not be spawned.
    #[error("failed to spawn command: {0}")]
    CommandSpawnFailed(String),

    // ── Validation ────────────────────────────────────────────────────
    /// Port number out of valid range.
    #[error("invalid port: {0} (port 0 is not valid)")]
    InvalidPort(u16),

    /// Port range has start > end.
    #[error("invalid port range: start {start} > end {end}")]
    InvalidPortRange {
        /// Start of the range.
        start: u16,
        /// End of the range.
        end: u16,
    },

    /// Invalid protocol for the given context.
    #[error("invalid protocol: {0}")]
    InvalidProtocol(String),

    /// Protocol must not be combined with a port clause.
    #[error("protocol {0} cannot be combined with port specifications")]
    ProtocolNoPorts(String),

    /// Invalid IP address or CIDR.
    #[error("invalid address: {0}")]
    InvalidAddress(String),

    /// Invalid network interface name.
    #[error("invalid interface name: {0}")]
    InvalidInterface(String),

    /// Comment contains forbidden characters.
    #[error("invalid comment: {0}")]
    InvalidComment(String),

    /// App profile name contains forbidden characters.
    #[error("invalid app profile name: {0}")]
    InvalidAppName(String),

    /// Generic validation failure.
    #[error("validation error: {0}")]
    Validation(String),

    // ── Rule operations ───────────────────────────────────────────────
    /// Could not add a rule.
    #[error("failed to add rule: {0}")]
    RuleAddFailed(String),

    /// Could not delete a rule.
    #[error("failed to delete rule: {0}")]
    RuleDeleteFailed(String),

    /// Could not insert a rule.
    #[error("failed to insert rule: {0}")]
    RuleInsertFailed(String),

    // ── Status parsing ────────────────────────────────────────────────
    /// Status output could not be parsed.
    #[error("failed to parse UFW status: {0}")]
    StatusParseFailed(String),

    /// Show report output could not be parsed.
    #[error("failed to parse show report: {0}")]
    ShowParseFailed(String),

    // ── Policy operations ─────────────────────────────────────────────
    /// Could not set default policy.
    #[error("failed to set default policy: {0}")]
    PolicySetFailed(String),

    /// Could not set logging level.
    #[error("failed to set logging level: {0}")]
    LoggingSetFailed(String),

    // ── Enable / disable ──────────────────────────────────────────────
    /// SSH lockout risk detected; refusing to enable.
    #[error("refusing to enable UFW: {0}\nAdd an allow rule first or pass explicit override.")]
    SshLockoutRisk(String),

    /// UFW enable failed.
    #[error("failed to enable UFW: {0}")]
    EnableFailed(String),

    /// UFW disable requires explicit confirmation.
    #[error(
        "UFW disable requires explicit confirmation (set require_explicit_confirmation = true)"
    )]
    DisableRequiresConfirmation,

    /// UFW disable failed.
    #[error("failed to disable UFW: {0}")]
    DisableFailed(String),

    /// UFW reload failed.
    #[error("failed to reload UFW: {0}")]
    ReloadFailed(String),

    /// UFW reset requires explicit force.
    #[error("UFW reset requires force = true")]
    ResetRequiresForce,

    /// UFW reset failed.
    #[error("failed to reset UFW: {0}")]
    ResetFailed(String),

    // ── App profiles ──────────────────────────────────────────────────
    /// App profile not found.
    #[error("app profile not found: {0}")]
    AppProfileNotFound(String),

    /// App profile file write failed.
    #[error("failed to write app profile: {0}")]
    AppProfileWriteFailed(String),

    /// App update command failed.
    #[error("app update failed: {0}")]
    AppUpdateFailed(String),

    // ── Config files ──────────────────────────────────────────────────
    /// Config file not found.
    #[error("config file not found: {0}")]
    ConfigNotFound(String),

    /// Config file parse error.
    #[error("config parse error: {0}")]
    ConfigParseFailed(String),

    /// Config file write error.
    #[error("config write error: {0}")]
    ConfigWriteFailed(String),

    // ── Framework ─────────────────────────────────────────────────────
    /// Framework file not found.
    #[error("framework file not found: {0}")]
    FrameworkNotFound(String),

    /// Framework managed block error.
    #[error("framework block error: {0}")]
    FrameworkBlockError(String),

    // ── Backup ────────────────────────────────────────────────────────
    /// Backup failed.
    #[error("backup failed: {0}")]
    BackupFailed(String),

    /// Restore failed.
    #[error("restore failed: {0}")]
    RestoreFailed(String),

    // ── IO ────────────────────────────────────────────────────────────
    /// Generic I/O error.
    #[error("io error: {0}")]
    Io(String),

    // ── Doctor ────────────────────────────────────────────────────────
    /// Doctor check encountered an error.
    #[error("doctor check failed: {0}")]
    DoctorCheckFailed(String),

    // ── Generic ───────────────────────────────────────────────────────
    /// Catch-all for other errors.
    #[error("{0}")]
    Other(String),
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err.to_string())
    }
}
