//! Error types for the toride-mise crate.

// ---------------------------------------------------------------------------
// FailureKind — classified from stderr text patterns
// ---------------------------------------------------------------------------

/// Broad category of failure extracted from mise stderr output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FailureKind {
    /// A required binary could not be found on `$PATH`.
    BinaryMissing,
    /// The requested tool is not recognised by mise.
    ToolUnknown,
    /// The requested tool version does not exist.
    VersionUnknown,
    /// A network / download / fetch failure.
    Network,
    /// A checksum or hash verification failure.
    Checksum,
    /// Permission was denied for an operation.
    Permission,
    /// A system dependency (library, compiler, etc.) is missing.
    DependencyMissing,
    /// The configuration file is not trusted.
    ConfigUntrusted,
    /// The configuration file is invalid or could not be parsed.
    ConfigInvalid,
    /// A lockfile is missing or corrupt.
    LockfileMissing,
    /// A command exited with a non-zero status (generic).
    CommandFailed,
    /// Could not determine a more specific failure kind.
    Unknown,
}

/// Examine stderr text and return the best-matching [`FailureKind`].
///
/// The heuristics are intentionally ordered from most specific to least
/// specific so that the first match wins.  Keyword-specific checks (lockfile,
/// dependency, network, checksum, permission, config) are placed **before**
/// the broad "not found" / "unknown tool" catch-all so that compound messages
/// like `"lockfile not found"` are classified correctly.
pub fn classify_stderr(stderr: &str) -> FailureKind {
    let lower = stderr.to_ascii_lowercase();

    // Version-specific "not found" — must come before the generic checks.
    if (lower.contains("version") && lower.contains("not found"))
        || lower.contains("version not found")
        || lower.contains("version not available")
    {
        return FailureKind::VersionUnknown;
    }

    // Binary / command not found — also ordered before generic tool checks.
    if (lower.contains("binary") && lower.contains("not found"))
        || lower.contains("command not found")
    {
        return FailureKind::BinaryMissing;
    }

    // Network / download failures.
    if lower.contains("network")
        || lower.contains("fetch")
        || lower.contains("download")
        || lower.contains("timeout")
    {
        return FailureKind::Network;
    }

    // Checksum / hash mismatches.
    if lower.contains("checksum") || lower.contains("hash") || lower.contains("mismatch") {
        return FailureKind::Checksum;
    }

    // Permission denied.
    if lower.contains("permission denied") || lower.contains("permissiondenied") {
        return FailureKind::Permission;
    }

    // Missing system dependencies.
    if lower.contains("dependency")
        || (lower.contains("missing") && (lower.contains("library") || lower.contains("compile")))
    {
        return FailureKind::DependencyMissing;
    }

    // Untrusted config.
    if lower.contains("untrusted") || lower.contains("trust") {
        return FailureKind::ConfigUntrusted;
    }

    // Invalid / unparseable config.
    if (lower.contains("invalid") && lower.contains("config")) || lower.contains("parse error") {
        return FailureKind::ConfigInvalid;
    }

    // Lockfile issues — checked before the generic "not found" catch-all so
    // that "lockfile not found" maps to LockfileMissing, not ToolUnknown.
    if lower.contains("lockfile") {
        return FailureKind::LockfileMissing;
    }

    // Tool not found / unknown tool — broad catch-all, must come last.
    if lower.contains("not found") || lower.contains("unknown tool") {
        return FailureKind::ToolUnknown;
    }

    FailureKind::Unknown
}

/// Convenience alias for `Result<T, MiseError>`.
pub type MiseResult<T> = std::result::Result<T, MiseError>;

/// Errors that can occur when interacting with mise.
#[derive(Debug, thiserror::Error)]
pub enum MiseError {
    /// A required binary (e.g. `mise`) could not be found on `$PATH`.
    #[error("binary not found: mise")]
    BinaryNotFound,

    /// The installed mise version is not supported.
    #[error("unsupported mise version: {version_output}")]
    UnsupportedVersion {
        /// Full output of `mise --version`.
        version_output: String,
    },

    /// A mise command exited with a non-zero status.
    #[error("command failed: {command} (exit {exit_code:?})\nstdout: {stdout}\nstderr: {stderr}")]
    CommandFailed {
        /// The command that was run.
        command: String,
        /// Exit code, if captured.
        exit_code: Option<i32>,
        /// Standard output.
        stdout: String,
        /// Standard error.
        stderr: String,
    },

    /// Output from a mise command could not be parsed as JSON.
    #[error("failed to parse JSON output from `{command}`: {source}")]
    JsonParse {
        /// The command whose output was being parsed.
        command: String,
        /// The underlying serde error.
        #[source]
        source: serde_json::Error,
        /// The raw stdout that could not be parsed.
        stdout: String,
    },

    /// An I/O error occurred.
    #[error("io error: {0}")]
    Io(#[source] std::io::Error),

    /// A configuration file error.
    #[error(transparent)]
    Config(#[from] ConfigError),

    /// A command timed out.
    #[error("command timed out: {command}")]
    Timeout {
        /// The command that timed out.
        command: String,
    },

    /// The requested tool is not recognised by mise.
    #[error("tool not found: {tool}")]
    ToolNotFound {
        /// Tool name.
        tool: String,
    },

    /// The requested tool version does not exist.
    #[error("version not found: {tool}@{version}")]
    VersionNotFound {
        /// Tool name.
        tool: String,
        /// Requested version.
        version: String,
    },

    /// A tool spec string could not be parsed.
    #[error("invalid tool spec `{raw}`: {reason}")]
    InvalidToolSpec {
        /// The raw spec string.
        raw: String,
        /// Why it is invalid.
        reason: String,
    },

    /// Bootstrap/installation hint returned when `mise` is not present.
    #[error("{message}")]
    BootstrapHint {
        /// Human-readable installation instructions.
        message: String,
    },

    /// A bootstrap/installation attempt failed.
    #[error("bootstrap failed: {reason}")]
    BootstrapFailed {
        /// Why the bootstrap failed.
        reason: String,
    },

    /// A tool installation error occurred.
    #[error(transparent)]
    Install(Box<ToolInstallError>),
}

/// Errors that can occur during tool installation.
#[derive(Debug, thiserror::Error)]
pub enum ToolInstallError {
    /// The requested tool is not recognised.
    #[error("tool not found: {tool}")]
    ToolNotFound {
        /// Tool name.
        tool: String,
    },

    /// The requested tool version does not exist.
    #[error("version not found: {tool}@{version}")]
    VersionNotFound {
        /// Tool name.
        tool: String,
        /// Requested version.
        version: String,
    },

    /// A network failure occurred while installing a tool.
    #[error("network failure while installing {tool}: {reason}")]
    NetworkFailed {
        /// Tool name.
        tool: String,
        /// Underlying reason.
        reason: String,
    },

    /// A checksum verification failure occurred.
    #[error("checksum verification failed for {tool}@{version}")]
    ChecksumFailed {
        /// Tool name.
        tool: String,
        /// Version being installed.
        version: String,
    },

    /// A required system dependency is missing.
    #[error("missing dependency `{dependency}` required by {tool}")]
    DependencyMissing {
        /// Tool name.
        tool: String,
        /// Missing dependency.
        dependency: String,
    },

    /// Permission was denied while installing a tool.
    #[error("permission denied while installing {tool}: {path}")]
    PermissionDenied {
        /// Tool name.
        tool: String,
        /// Path that was denied.
        path: String,
    },

    /// An underlying mise error occurred during installation.
    #[error(transparent)]
    MiseFailed(Box<MiseError>),
}

/// Errors related to reading or writing mise configuration files.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// Could not read a config file.
    #[error("failed to read config `{path}`: {reason}")]
    ReadFailed {
        /// File path.
        path: String,
        /// Underlying reason.
        reason: String,
    },

    /// Could not write a config file.
    #[error("failed to write config `{path}`: {reason}")]
    WriteFailed {
        /// File path.
        path: String,
        /// Underlying reason.
        reason: String,
    },

    /// A config file could not be parsed.
    #[error("failed to parse config `{path}`: {reason}")]
    ParseFailed {
        /// File path.
        path: String,
        /// Underlying reason.
        reason: String,
    },

    /// A required key was missing from the config.
    #[error("config key not found: {key}")]
    KeyNotFound {
        /// The missing key.
        key: String,
    },

    /// A config value was invalid.
    #[error("invalid value for config key `{key}`: {value}")]
    InvalidValue {
        /// Key name.
        key: String,
        /// The invalid value.
        value: String,
    },
}

// ---------------------------------------------------------------------------
// From implementations
// ---------------------------------------------------------------------------

impl From<std::io::Error> for MiseError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

impl From<serde_json::Error> for MiseError {
    fn from(err: serde_json::Error) -> Self {
        Self::JsonParse {
            command: String::new(),
            source: err,
            stdout: String::new(),
        }
    }
}

impl From<toride_runner::Error> for MiseError {
    fn from(err: toride_runner::Error) -> Self {
        // Delegate to the canonical mapping in command::mapping so there is
        // a single source of truth for toride_runner::Error -> MiseError.
        crate::command::mapping::map_runner_error(err, "")
    }
}

impl From<ToolInstallError> for MiseError {
    fn from(err: ToolInstallError) -> Self {
        Self::Install(Box::new(err))
    }
}

impl From<MiseError> for ToolInstallError {
    fn from(err: MiseError) -> Self {
        Self::MiseFailed(Box::new(err))
    }
}

// ---------------------------------------------------------------------------
// MiseError methods
// ---------------------------------------------------------------------------

impl MiseError {
    /// Return the classified [`FailureKind`] for this error.
    ///
    /// Only the [`CommandFailed`](MiseError::CommandFailed) variant produces a
    /// meaningful classification; all other variants return [`None`].
    pub fn command_failure_kind(&self) -> Option<FailureKind> {
        match self {
            Self::CommandFailed { stderr, .. } => Some(classify_stderr(stderr)),
            _ => None,
        }
    }

    /// Classify the stderr of a [`CommandFailed`](MiseError::CommandFailed)
    /// variant, returning [`FailureKind::Unknown`] for all other variants.
    pub fn classify(&self) -> FailureKind {
        self.command_failure_kind().unwrap_or(FailureKind::Unknown)
    }
}

// ---------------------------------------------------------------------------
// Tests for classify_stderr and FailureKind
// ---------------------------------------------------------------------------

#[cfg(test)]
mod failure_kind_tests {
    use super::*;

    #[test]
    fn tool_unknown_not_found() {
        assert_eq!(classify_stderr("mise: not found"), FailureKind::ToolUnknown);
    }

    #[test]
    fn tool_unknown_unknown_tool() {
        assert_eq!(
            classify_stderr("error: unknown tool foo"),
            FailureKind::ToolUnknown
        );
    }

    #[test]
    fn version_unknown() {
        assert_eq!(
            classify_stderr("version 22.0.0 not found"),
            FailureKind::VersionUnknown
        );
    }

    #[test]
    fn network_fetch() {
        assert_eq!(
            classify_stderr("failed to fetch the release"),
            FailureKind::Network
        );
    }

    #[test]
    fn network_download() {
        assert_eq!(classify_stderr("download timed out"), FailureKind::Network);
    }

    #[test]
    fn network_timeout() {
        assert_eq!(classify_stderr("timeout after 30s"), FailureKind::Network);
    }

    #[test]
    fn checksum_mismatch() {
        assert_eq!(
            classify_stderr("checksum mismatch for tarball"),
            FailureKind::Checksum
        );
    }

    #[test]
    fn permission_denied() {
        assert_eq!(
            classify_stderr("permission denied: /usr/local/bin"),
            FailureKind::Permission
        );
    }

    #[test]
    fn dependency_missing() {
        assert_eq!(
            classify_stderr("missing C library: openssl"),
            FailureKind::DependencyMissing
        );
    }

    #[test]
    fn dependency_missing_compile() {
        assert_eq!(
            classify_stderr("missing compile dependency"),
            FailureKind::DependencyMissing
        );
    }

    #[test]
    fn config_untrusted() {
        assert_eq!(
            classify_stderr("untrusted config file"),
            FailureKind::ConfigUntrusted
        );
    }

    #[test]
    fn config_untrusted_trust() {
        assert_eq!(
            classify_stderr("run mise trust to trust this config"),
            FailureKind::ConfigUntrusted
        );
    }

    #[test]
    fn config_invalid() {
        assert_eq!(
            classify_stderr("invalid config: bad value"),
            FailureKind::ConfigInvalid
        );
    }

    #[test]
    fn config_invalid_parse_error() {
        assert_eq!(
            classify_stderr("parse error at line 5"),
            FailureKind::ConfigInvalid
        );
    }

    #[test]
    fn lockfile_missing() {
        assert_eq!(
            classify_stderr("lockfile is missing"),
            FailureKind::LockfileMissing
        );
    }

    #[test]
    fn lockfile_not_found_classified_correctly() {
        // "lockfile not found" must map to LockfileMissing, not ToolUnknown.
        assert_eq!(
            classify_stderr("lockfile not found"),
            FailureKind::LockfileMissing
        );
    }

    #[test]
    fn dependency_not_found_classified_correctly() {
        // "dependency not found" must map to DependencyMissing, not ToolUnknown.
        assert_eq!(
            classify_stderr("dependency not found: libssl"),
            FailureKind::DependencyMissing
        );
    }

    #[test]
    fn binary_missing() {
        assert_eq!(
            classify_stderr("binary not found: node"),
            FailureKind::BinaryMissing
        );
    }

    #[test]
    fn binary_missing_command_not_found() {
        assert_eq!(
            classify_stderr("sh: command not found: mise"),
            FailureKind::BinaryMissing
        );
    }

    #[test]
    fn unknown_garbage() {
        assert_eq!(classify_stderr("something else"), FailureKind::Unknown);
    }

    #[test]
    fn unknown_empty() {
        assert_eq!(classify_stderr(""), FailureKind::Unknown);
    }

    #[test]
    fn mise_error_command_failure_kind_command_failed() {
        let err = MiseError::CommandFailed {
            command: "mise install node".into(),
            exit_code: Some(1),
            stdout: String::new(),
            stderr: "checksum mismatch for node-22.tar.gz".into(),
        };
        assert_eq!(err.command_failure_kind(), Some(FailureKind::Checksum));
    }

    #[test]
    fn mise_error_command_failure_kind_other_variant() {
        let err = MiseError::BinaryNotFound;
        assert_eq!(err.command_failure_kind(), None);
    }

    #[test]
    fn mise_error_classify_command_failed() {
        let err = MiseError::CommandFailed {
            command: "mise install node".into(),
            exit_code: Some(1),
            stdout: String::new(),
            stderr: "network error while downloading".into(),
        };
        assert_eq!(err.classify(), FailureKind::Network);
    }

    #[test]
    fn mise_error_classify_other_variant_returns_unknown() {
        let err = MiseError::Timeout {
            command: "mise install node".into(),
        };
        assert_eq!(err.classify(), FailureKind::Unknown);
    }

    #[test]
    fn version_takes_priority_over_tool_not_found() {
        // "not found" matches ToolUnknown, but "version" + "not found" should win.
        assert_eq!(
            classify_stderr("version 3.12 not found for python"),
            FailureKind::VersionUnknown
        );
    }

    #[test]
    fn binary_takes_priority_over_tool_not_found() {
        assert_eq!(
            classify_stderr("binary not found: gcc"),
            FailureKind::BinaryMissing
        );
    }
}
