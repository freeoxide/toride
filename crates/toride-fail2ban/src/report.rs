//! Structured report types for doctor findings, apply/rollback workflows,
//! regex testing, and jail status.
//!
//! Every mutating or diagnostic workflow in the crate returns one of these
//! report types so that callers can inspect results programmatically and
//! produce human-readable output independently.
//!
//! # Shared crate re-exports
//!
//! This module re-exports types from `toride-diagnostic-types` for use by
//! callers that need the shared types. The local `Severity`, `Finding`, and
//! `DoctorReport` remain the primary public API for backward compatibility.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Re-exports from toride-diagnostic-types
// ---------------------------------------------------------------------------

/// Re-export of the shared [`toride_diagnostic_types::Severity`] type.
///
/// The shared type uses `Important` where this crate uses `Error`. See
/// [`Severity::Error`] for the local variant.
pub use toride_diagnostic_types::Severity as SharedSeverity;

/// Re-export of the shared [`toride_diagnostic_types::Finding`] type.
///
/// The shared type uses `message` where this crate uses `title`, and
/// `fix_hint` where this crate uses `fix`. See the local [`Finding`] for the
/// fail2ban-specific API.
pub use toride_diagnostic_types::Finding as SharedFinding;

/// Re-export of the shared [`toride_diagnostic_types::DoctorReport`] type.
///
/// The shared type has a different API (requires `domain` and `checked_at`).
/// See the local [`DoctorReport`] for the fail2ban-specific API.
pub use toride_diagnostic_types::DoctorReport as SharedDoctorReport;

// ---------------------------------------------------------------------------
// Severity
// ---------------------------------------------------------------------------

/// Diagnostic severity level for doctor findings.
///
/// Ordered from least severe ([`Severity::Ok`]) to most severe
/// ([`Severity::Critical`]) so that reports can be sorted and filtered by
/// severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// No issue detected.
    Ok,
    /// Informational note; no action required.
    Info,
    /// Non-critical issue that may cause problems later.
    Warning,
    /// An error that should be addressed before proceeding.
    Error,
    /// A critical problem that blocks normal operation.
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ok => write!(f, "OK"),
            Self::Info => write!(f, "INFO"),
            Self::Warning => write!(f, "WARNING"),
            Self::Error => write!(f, "ERROR"),
            Self::Critical => write!(f, "CRITICAL"),
        }
    }
}

// ---------------------------------------------------------------------------
// Finding
// ---------------------------------------------------------------------------

/// A single structured finding produced by the doctor or returned in an
/// apply/rollback report.
///
/// Use [`Finding::new`] to construct the mandatory fields, then chain the
/// `.detail()` and `.fix()` builder methods for optional context.
///
/// # Example
///
/// ```
/// use toride_fail2ban::report::{Finding, Severity};
///
/// let f = Finding::new(
///     "binary.fail2ban-client.missing",
///     Severity::Critical,
///     "fail2ban-client not found",
/// )
/// .detail("The fail2ban-client binary could not be located on $PATH.")
/// .fix("Install fail2ban: apt install fail2ban");
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Machine-readable dot-separated identifier,
    /// e.g. `"binary.fail2ban-client.missing"`.
    pub id: String,
    /// How severe this finding is.
    pub severity: Severity,
    /// Short human-readable title (one line).
    pub title: String,
    /// Longer description of the finding.
    pub detail: String,
    /// Suggested remediation action, if applicable.
    pub fix: Option<String>,
}

impl Finding {
    /// Create a new finding with the mandatory fields.
    ///
    /// The `detail` and `fix` fields default to empty / `None` and can be
    /// filled in via the `.detail()` and `.fix()` chain methods.
    #[must_use]
    pub fn new(id: impl Into<String>, severity: Severity, title: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            severity,
            title: title.into(),
            detail: String::new(),
            fix: None,
        }
    }

    /// Attach a longer description, replacing any previous detail text.
    #[must_use]
    pub fn detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = detail.into();
        self
    }

    /// Attach a suggested fix action, replacing any previous fix.
    #[must_use]
    pub fn fix(mut self, fix: impl Into<String>) -> Self {
        self.fix = Some(fix.into());
        self
    }

    /// Convert this local finding into the shared [`SharedFinding`] type.
    ///
    /// Maps `Severity::Error` to `SharedSeverity::Important`.
    /// Maps `.title` to `.message`, `.fix` to `.fix_hint`.
    pub fn to_shared(&self) -> SharedFinding {
        let shared_severity = match self.severity {
            Severity::Ok => SharedSeverity::Ok,
            Severity::Info => SharedSeverity::Info,
            Severity::Warning => SharedSeverity::Warning,
            Severity::Error => SharedSeverity::Important,
            Severity::Critical => SharedSeverity::Critical,
        };
        let mut f = SharedFinding::new(&self.id, shared_severity, &self.title).domain("fail2ban");
        if !self.detail.is_empty() {
            f = f.detail(&self.detail);
        }
        if let Some(ref fix) = self.fix {
            f = f.fix_hint(fix);
        }
        f
    }
}

impl From<&Finding> for SharedFinding {
    fn from(f: &Finding) -> Self {
        f.to_shared()
    }
}

// ---------------------------------------------------------------------------
// ApplyReport
// ---------------------------------------------------------------------------

/// Report returned after successfully applying configuration changes.
///
/// Contains every file that was written or removed, paths to backups created,
/// whether the post-apply config test passed, the result of the reload
/// operation, and any findings generated during the apply process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplyReport {
    /// Configuration files written to disk.
    pub files_written: Vec<String>,
    /// Configuration files removed from disk.
    pub files_removed: Vec<String>,
    /// Backup file paths created before writing.
    pub backup_paths: Vec<String>,
    /// Whether `fail2ban-client --test` passed after the apply.
    pub test_passed: bool,
    /// Result of `fail2ban-client reload` (stdout/stderr or error message).
    pub reload_result: Option<String>,
    /// Additional findings produced during the apply.
    pub findings: Vec<Finding>,
}

impl ApplyReport {
    /// Create an empty (successful) report.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            files_written: Vec::new(),
            files_removed: Vec::new(),
            backup_paths: Vec::new(),
            test_passed: true,
            reload_result: None,
            findings: Vec::new(),
        }
    }

    /// Returns `true` when the apply wrote no files, removed no files, and
    /// has no findings.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.files_written.is_empty() && self.files_removed.is_empty() && self.findings.is_empty()
    }
}

// ---------------------------------------------------------------------------
// RollbackReport
// ---------------------------------------------------------------------------

/// Report returned after a rollback triggered by a failed apply.
///
/// Lists the files that were restored from backups, whether the config test
/// passed after restoration, and any findings generated during the rollback.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RollbackReport {
    /// Files restored from backup.
    pub restored_files: Vec<String>,
    /// Whether `fail2ban-client --test` passed after rollback.
    pub test_passed: bool,
    /// Result of `fail2ban-client reload` after rollback.
    pub reload_result: Option<String>,
    /// Findings produced during the rollback.
    pub findings: Vec<Finding>,
}

impl RollbackReport {
    /// Create a report indicating a successful rollback with no findings.
    #[must_use]
    pub fn success(restored_files: Vec<String>) -> Self {
        Self {
            restored_files,
            test_passed: true,
            reload_result: None,
            findings: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// DoctorReport
// ---------------------------------------------------------------------------

/// Aggregated doctor report containing all findings from a diagnostic run.
///
/// Provides convenience methods for summarising findings by severity and
/// checking for blocking issues.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DoctorReport {
    /// All findings collected during the doctor run.
    pub findings: Vec<Finding>,
}

impl DoctorReport {
    /// Create an empty report.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            findings: Vec::new(),
        }
    }

    /// Add a finding to the report.
    pub fn push(&mut self, finding: Finding) {
        self.findings.push(finding);
    }

    /// Returns the number of findings in this report.
    #[must_use]
    pub fn len(&self) -> usize {
        self.findings.len()
    }

    /// Returns `true` if this report contains no findings.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.findings.is_empty()
    }

    /// Group findings by severity level.
    ///
    /// The returned map uses [`Severity`] as the key. Only severity levels
    /// that have at least one finding are included.
    #[must_use]
    pub fn summary_by_severity(&self) -> BTreeMap<Severity, Vec<&Finding>> {
        let mut map: BTreeMap<Severity, Vec<&Finding>> = BTreeMap::new();
        for finding in &self.findings {
            map.entry(finding.severity).or_default().push(finding);
        }
        map
    }

    /// Returns `true` if any finding has severity [`Severity::Error`] or
    /// higher.
    #[must_use]
    pub fn has_errors(&self) -> bool {
        self.findings.iter().any(|f| f.severity >= Severity::Error)
    }

    /// Returns `true` if any finding has severity [`Severity::Critical`].
    #[must_use]
    pub fn has_critical(&self) -> bool {
        self.findings
            .iter()
            .any(|f| f.severity == Severity::Critical)
    }

    /// Convert this report into a shared [`SharedDoctorReport`].
    ///
    /// Maps all local findings to shared findings. The `domain` is set to
    /// `"fail2ban"` and `checked_at` is set to a placeholder timestamp.
    pub fn to_shared(&self) -> SharedDoctorReport {
        let shared_findings: Vec<SharedFinding> =
            self.findings.iter().map(Finding::to_shared).collect();
        SharedDoctorReport::new("fail2ban", shared_findings)
    }
}

// ---------------------------------------------------------------------------
// RegexTestResult
// ---------------------------------------------------------------------------

/// Result of running `fail2ban-regex` to validate a filter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegexTestResult {
    /// Number of lines that matched the failregex pattern.
    pub lines_matched: usize,
    /// Total number of lines processed.
    pub lines_processed: usize,
    /// Raw output from `fail2ban-regex`.
    pub output: String,
    /// Whether the regex test was considered successful.
    pub success: bool,
}

impl RegexTestResult {
    /// Create a new regex test result.
    #[must_use]
    pub fn new(
        lines_matched: usize,
        lines_processed: usize,
        output: impl Into<String>,
        success: bool,
    ) -> Self {
        Self {
            lines_matched,
            lines_processed,
            output: output.into(),
            success,
        }
    }

    /// Returns the match rate as a value between 0.0 and 1.0.
    ///
    /// Returns 0.0 when no lines were processed.
    #[must_use]
    pub fn match_rate(&self) -> f64 {
        if self.lines_processed == 0 {
            0.0
        } else {
            // Line counts are bounded well below 2^52 (f64 mantissa width).
            #[expect(
                clippy::cast_precision_loss,
                reason = "line counts never approach 2^52"
            )]
            {
                (self.lines_matched as f64) / (self.lines_processed as f64)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// StatusReport
// ---------------------------------------------------------------------------

/// Status report for a single jail, typically derived from
/// `fail2ban-client status <jail>`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusReport {
    /// Name of the jail.
    pub jail_name: String,
    /// Whether the jail is currently running.
    pub is_running: bool,
    /// IP addresses currently banned in this jail.
    pub banned_ips: Vec<String>,
    /// Number of log files associated with this jail.
    pub file_count: u64,
    /// Total number of bans performed by this jail since start.
    pub ban_count: u64,
}

impl StatusReport {
    /// Create a minimal status report for a stopped jail.
    #[must_use]
    pub fn stopped(jail_name: impl Into<String>) -> Self {
        Self {
            jail_name: jail_name.into(),
            is_running: false,
            banned_ips: Vec::new(),
            file_count: 0,
            ban_count: 0,
        }
    }

    /// Returns `true` if this jail has any banned IPs.
    #[must_use]
    pub fn has_bans(&self) -> bool {
        !self.banned_ips.is_empty()
    }
}

#[cfg(test)]
#[path = "report.test.rs"]
mod tests;
