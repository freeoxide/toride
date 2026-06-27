//! Typed specification module for backup configuration.
//!
//! Defines [`BackupSpec`] which describes a complete backup job: the
//! repository location, source paths, schedule, retention policy, and
//! encryption settings. Each field is validated on construction.

use std::fmt;
use std::path::PathBuf;
use std::str::FromStr;

use crate::{Error, Result};

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

/// Supported backup backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "lowercase"))]
pub enum Backend {
    /// Restic backup backend (default).
    #[default]
    Restic,
    /// Borg Backup backend.
    Borg,
}

impl fmt::Display for Backend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Restic => write!(f, "restic"),
            Self::Borg => write!(f, "borg"),
        }
    }
}

impl FromStr for Backend {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "restic" => Ok(Self::Restic),
            "borg" => Ok(Self::Borg),
            other => Err(Error::ConfigParse(format!(
                "unknown backup backend: {other:?} (expected \"restic\" or \"borg\")"
            ))),
        }
    }
}

// ---------------------------------------------------------------------------
// Retention policy
// ---------------------------------------------------------------------------

/// Retention policy defining how many snapshots to keep for each time period.
///
/// Maps directly to restic's `forget --keep-*` flags or Borg's prune
/// `--keep-*` flags.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RetentionPolicy {
    /// Number of hourly snapshots to retain.
    pub keep_hourly: Option<u32>,
    /// Number of daily snapshots to retain.
    pub keep_daily: Option<u32>,
    /// Number of weekly snapshots to retain.
    pub keep_weekly: Option<u32>,
    /// Number of monthly snapshots to retain.
    pub keep_monthly: Option<u32>,
    /// Number of yearly snapshots to retain.
    pub keep_yearly: Option<u32>,
}

impl RetentionPolicy {
    /// Create a default retention policy with sensible values.
    ///
    /// Defaults: 7 daily, 4 weekly, 6 monthly.
    #[must_use]
    pub fn default_policy() -> Self {
        Self {
            keep_hourly: None,
            keep_daily: Some(7),
            keep_weekly: Some(4),
            keep_monthly: Some(6),
            keep_yearly: None,
        }
    }

    /// Validate that at least one retention count is set.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ConfigParse`] if no retention counts are configured.
    pub fn validate(&self) -> Result<()> {
        if self.keep_hourly.is_none()
            && self.keep_daily.is_none()
            && self.keep_weekly.is_none()
            && self.keep_monthly.is_none()
            && self.keep_yearly.is_none()
        {
            return Err(Error::ConfigParse(
                "retention policy must have at least one keep-* value".into(),
            ));
        }
        Ok(())
    }

    /// Returns `true` if this policy has at least one retention count set.
    #[must_use]
    pub fn has_any(&self) -> bool {
        self.keep_hourly.is_some()
            || self.keep_daily.is_some()
            || self.keep_weekly.is_some()
            || self.keep_monthly.is_some()
            || self.keep_yearly.is_some()
    }
}

impl Default for RetentionPolicy {
    fn default() -> Self {
        Self::default_policy()
    }
}

// ---------------------------------------------------------------------------
// Schedule
// ---------------------------------------------------------------------------

/// Backup schedule specification.
///
/// Supports cron expressions for flexible scheduling.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Schedule {
    /// Cron expression (e.g. `"0 2 * * *"` for daily at 2am).
    pub cron: String,
    /// Optional human-readable description of the schedule.
    pub description: Option<String>,
}

impl Schedule {
    /// Create a schedule from a cron expression.
    pub fn new(cron: impl Into<String>) -> Self {
        Self {
            cron: cron.into(),
            description: None,
        }
    }

    /// Attach a human-readable description.
    #[must_use]
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }

    /// Validate the cron expression is well-formed.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ScheduleError`] if the cron expression is invalid.
    pub fn validate(&self) -> Result<()> {
        let parts: Vec<&str> = self.cron.split_whitespace().collect();
        if parts.len() != 5 {
            return Err(Error::ScheduleError(format!(
                "cron expression must have exactly 5 fields, got {}: {:?}",
                parts.len(),
                self.cron,
            )));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Encryption
// ---------------------------------------------------------------------------

/// Encryption configuration for backup repositories.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
pub enum Encryption {
    /// No encryption (not recommended).
    None,
    /// Repo-key encryption (restic default; key stored in repo, password required).
    RepoKey,
    /// AES-256-CTR encryption with HMAC-SHA-256 (Borg default).
    KeyFile,
    /// Blake2 encryption (Borg).
    Blake2,
    /// Authenticated encryption (Borg, since 1.1).
    Authenticated,
}

impl fmt::Display for Encryption {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => write!(f, "none"),
            Self::RepoKey => write!(f, "repo-key"),
            Self::KeyFile => write!(f, "keyfile"),
            Self::Blake2 => write!(f, "blake2"),
            Self::Authenticated => write!(f, "authenticated"),
        }
    }
}

// ---------------------------------------------------------------------------
// BackupSpec
// ---------------------------------------------------------------------------

/// Complete specification for a backup job.
///
/// A [`BackupSpec`] captures everything needed to create, schedule, and
/// manage a backup: the repository location, which paths to back up, how
/// often to run, how many snapshots to keep, and whether to encrypt.
///
/// # Example
///
/// ```ignore
/// use toride_backup::spec::{BackupSpec, Backend, RetentionPolicy, Schedule, Encryption};
///
/// let spec = BackupSpec {
///     name: "my-server".into(),
///     backend: Backend::Restic,
///     repository: "/mnt/backups/my-server".into(),
///     sources: vec!["/etc".into(), "/home".into()],
///     schedule: Schedule::new("0 2 * * *"),
///     retention: RetentionPolicy::default_policy(),
///     encryption: Encryption::RepoKey,
///     password_command: Some("cat /etc/restic/password".into()),
///     exclude_patterns: vec!["*.tmp".into(), ".cache".into()],
///     tags: vec!["auto".into()],
///     extra_env: std::collections::HashMap::new(),
/// };
/// spec.validate()?;
/// ```
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct BackupSpec {
    /// Name of this backup job (used for logging, scheduling, and reporting).
    pub name: String,
    /// Which backup backend to use.
    pub backend: Backend,
    /// Repository path or URL (e.g. `/mnt/backups/my-server` or `sftp:user@host:/path`).
    pub repository: PathBuf,
    /// Source paths to back up.
    pub sources: Vec<PathBuf>,
    /// When to run the backup.
    pub schedule: Schedule,
    /// How many snapshots to keep.
    pub retention: RetentionPolicy,
    /// Encryption mode for the repository.
    pub encryption: Encryption,
    /// Command to retrieve the repository password (e.g. `"cat /etc/restic/password"`).
    pub password_command: Option<String>,
    /// Glob patterns for files to exclude from backups.
    pub exclude_patterns: Vec<String>,
    /// Tags to apply to snapshots.
    pub tags: Vec<String>,
    /// Extra environment variables to pass to the backup command.
    pub extra_env: std::collections::HashMap<String, String>,
}

impl BackupSpec {
    /// Validates cross-field constraints on this backup specification.
    ///
    /// Checks:
    /// - `name` is non-empty
    /// - `sources` is non-empty
    /// - `repository` is non-empty
    /// - `schedule.cron` is valid
    /// - `retention` has at least one keep-* value
    /// - if `encryption` is not `None`, `password_command` should be set
    ///
    /// # Errors
    ///
    /// Returns [`Error`] with details on the first failing check.
    pub fn validate(&self) -> Result<()> {
        if self.name.trim().is_empty() {
            return Err(Error::ConfigParse(
                "backup spec name must not be empty".into(),
            ));
        }

        if self.sources.is_empty() {
            return Err(Error::ConfigParse(format!(
                "backup spec {:?}: sources must not be empty",
                self.name,
            )));
        }

        if self.repository.as_os_str().is_empty() {
            return Err(Error::ConfigParse(format!(
                "backup spec {:?}: repository path must not be empty",
                self.name,
            )));
        }

        self.schedule.validate()?;
        self.retention.validate()?;

        if self.encryption != Encryption::None && self.password_command.is_none() {
            return Err(Error::ConfigParse(format!(
                "backup spec {:?}: encryption is {:?} but no password_command is set",
                self.name, self.encryption,
            )));
        }

        Ok(())
    }
}
