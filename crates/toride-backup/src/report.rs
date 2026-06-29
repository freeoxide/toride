//! Structured report types for backup operations and diagnostics.
//!
//! Every backup, restore, or prune operation returns a typed report so that
//! callers can inspect results programmatically and produce human-readable
//! output independently.

use std::time::SystemTime;

// ---------------------------------------------------------------------------
// BackupStatus
// ---------------------------------------------------------------------------

/// Status of a backup snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackupStatus {
    /// Backup completed successfully.
    Ok,
    /// Backup completed with warnings.
    Warning,
    /// Backup failed.
    Failed,
    /// Backup has never been run.
    NeverRun,
}

// ---------------------------------------------------------------------------
// IntegrityStatus
// ---------------------------------------------------------------------------

/// Result of a repository integrity check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntegrityStatus {
    /// Integrity check passed.
    Ok,
    /// Integrity check detected errors.
    Errors,
    /// Integrity check has not been run.
    NotChecked,
}

// ---------------------------------------------------------------------------
// BackupReport
// ---------------------------------------------------------------------------

/// Report summarising the state of a backup job.
///
/// Includes the last run time, snapshot counts, integrity status, and any
/// findings from the last operation.
#[derive(Debug, Clone)]
pub struct BackupReport {
    /// Name of the backup job.
    pub name: String,
    /// Timestamp of the last successful backup, if any.
    pub last_run: Option<SystemTime>,
    /// Status of the last backup run.
    pub status: BackupStatus,
    /// Number of snapshots in the repository.
    pub snapshot_count: u64,
    /// Total size of the repository in bytes.
    pub repo_size_bytes: u64,
    /// Result of the last integrity check.
    pub integrity: IntegrityStatus,
    /// Output or error message from the last operation.
    pub last_message: Option<String>,
}

impl BackupReport {
    /// Create an empty report for a backup that has never been run.
    #[must_use]
    pub fn never_run(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            last_run: None,
            status: BackupStatus::NeverRun,
            snapshot_count: 0,
            repo_size_bytes: 0,
            integrity: IntegrityStatus::NotChecked,
            last_message: None,
        }
    }

    /// Returns `true` if the last backup completed successfully.
    #[must_use]
    pub fn is_ok(&self) -> bool {
        self.status == BackupStatus::Ok
    }

    /// Returns `true` if the backup has never been run.
    #[must_use]
    pub fn is_never_run(&self) -> bool {
        self.status == BackupStatus::NeverRun
    }
}

// ---------------------------------------------------------------------------
// RestoreReport
// ---------------------------------------------------------------------------

/// Report returned after a restore operation.
#[derive(Debug, Clone)]
pub struct RestoreReport {
    /// Snapshot ID that was restored.
    pub snapshot_id: String,
    /// Target path where files were restored.
    pub target_path: String,
    /// Number of files restored.
    pub files_restored: u64,
    /// Total bytes restored.
    pub bytes_restored: u64,
    /// Whether the restore completed successfully.
    pub success: bool,
    /// Any warnings or errors encountered.
    pub messages: Vec<String>,
}

impl RestoreReport {
    /// Create a successful restore report.
    #[must_use]
    pub fn success(snapshot_id: impl Into<String>, target_path: impl Into<String>) -> Self {
        Self {
            snapshot_id: snapshot_id.into(),
            target_path: target_path.into(),
            files_restored: 0,
            bytes_restored: 0,
            success: true,
            messages: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// PruneReport
// ---------------------------------------------------------------------------

/// Report returned after a prune (retention) operation.
#[derive(Debug, Clone)]
pub struct PruneReport {
    /// Number of snapshots removed.
    pub snapshots_removed: u64,
    /// Number of snapshots kept.
    pub snapshots_kept: u64,
    /// Bytes freed by the prune operation.
    pub bytes_freed: u64,
    /// Whether the prune completed successfully.
    pub success: bool,
}

impl PruneReport {
    /// Create an empty prune report.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            snapshots_removed: 0,
            snapshots_kept: 0,
            bytes_freed: 0,
            success: true,
        }
    }
}
