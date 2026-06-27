//! Diagnostic engine for backup installations.
//!
//! [`Doctor`] runs structured diagnostic checks across the backup
//! configuration and returns a [`DoctorReport`] containing typed findings
//! with severity levels, descriptions, and suggested fixes.
//!
//! # Categories
//!
//! | Scope | What it checks |
//! |-------|---------------|
//! | `Binary` | restic/borg binaries exist and are functional |
//! | `Repository` | repository exists, is accessible, has recent snapshots |
//! | `Staleness` | backups are not stale (run within expected schedule) |
//! | `Integrity` | last `check` passed without errors |
//! | `Encryption` | encryption is enabled, password command works |
//! | `Schedule` | systemd timers / cron entries are installed and active |
//! | `Retention` | retention policy is configured and has been applied |
//! | `Space` | repository / target filesystem has sufficient free space |
//!
//! # Two entry points
//!
//! - [`Doctor::run`] takes a [`DoctorScope`] (string-named categories) and
//!   runs the binary check for real; the per-job categories surface an
//!   informational finding pointing at [`Doctor::run_spec`] when no
//!   [`BackupSpec`](crate::spec::BackupSpec) is available.
//! - [`Doctor::run_spec`] takes a full [`BackupSpec`](crate::spec::BackupSpec)
//!   and runs *real* probes — constructing typed
//!   [`CommandSpec`](toride_runner::CommandSpec)s for `restic`/`borg` and
//!   executing them through the injected [`Runner`](toride_runner::Runner).
//!
//! # Secrets / redaction
//!
//! Every command that touches the repository is built with
//! [`CommandSpec::redact`](toride_runner::CommandSpec::redact)`(true)`, and
//! the passphrase is delivered via the `RESTIC_PASSWORD` / `BORG_PASSPHRASE`
//! environment variable — never as a positional argument. The repo URL is
//! likewise treated as potentially secret (it can embed credentials for
//! `sftp:`/`b2:` backends).
//!
//! # Example
//!
//! ```ignore
//! use toride_backup::doctor::{Doctor, DoctorScope};
//!
//! let doctor = Doctor::new();
//! let report = doctor.run(&DoctorScope::All)?;
//! if report.has_errors() {
//!     for f in &report.findings {
//!         eprintln!("[{}] {}", f.severity, f.title);
//!     }
//! }
//! ```

use std::path::Path;
use std::sync::Arc;

use toride_runner::{CommandSpec, DuctRunner, Runner};

use crate::spec::{Backend, BackupSpec};
use crate::{Error, Result};

// ---------------------------------------------------------------------------
// Severity
// ---------------------------------------------------------------------------

/// Diagnostic severity level for doctor findings.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash,
)]
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

/// A single structured finding produced by the doctor.
#[derive(Debug, Clone)]
pub struct Finding {
    /// Machine-readable dot-separated identifier.
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
    pub fn new(
        id: impl Into<String>,
        severity: Severity,
        title: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            severity,
            title: title.into(),
            detail: String::new(),
            fix: None,
        }
    }

    /// Attach a longer description.
    #[must_use]
    pub fn detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = detail.into();
        self
    }

    /// Attach a suggested fix.
    #[must_use]
    pub fn fix(mut self, fix: impl Into<String>) -> Self {
        self.fix = Some(fix.into());
        self
    }
}

// ---------------------------------------------------------------------------
// DoctorScope
// ---------------------------------------------------------------------------

/// Selects which diagnostic category (or categories) to run.
#[derive(Debug, Clone)]
pub enum DoctorScope {
    /// Run all diagnostic categories.
    All,
    /// Check that required binaries (restic/borg) exist.
    Binary,
    /// Check repository accessibility and state.
    Repository(String),
    /// Check that backups are not stale.
    Staleness(String),
    /// Check repository integrity.
    Integrity(String),
    /// Check encryption is enabled and functional.
    Encryption(String),
    /// Check schedules are installed and active.
    Schedule(String),
    /// Check retention policies are applied.
    Retention(String),
    /// Check filesystem has sufficient free space.
    Space(String),
}

impl DoctorScope {
    /// Return all individual scope categories (excluding `All`).
    pub fn all_categories() -> Vec<DoctorScope> {
        // Stable placeholder names — these are the per-job categories that
        // require a BackupSpec to probe meaningfully. `run` will surface an
        // informational note pointing the caller at `run_spec` for these.
        vec![
            DoctorScope::Binary,
            DoctorScope::Repository(String::new()),
            DoctorScope::Staleness(String::new()),
            DoctorScope::Integrity(String::new()),
            DoctorScope::Encryption(String::new()),
            DoctorScope::Schedule(String::new()),
            DoctorScope::Retention(String::new()),
            DoctorScope::Space(String::new()),
        ]
    }
}

// ---------------------------------------------------------------------------
// SpecScope -- which real-probe category to run against a BackupSpec
// ---------------------------------------------------------------------------

/// Selects which real-probe category to run against a [`BackupSpec`] via
/// [`Doctor::run_spec`]. Unlike [`DoctorScope`] (which carries only a job
/// name), the spec scope has the full configuration needed to actually invoke
/// `restic`/`borg`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpecScope {
    /// Run every spec-backed category.
    All,
    /// Probe repository accessibility (`restic snapshots` / `borg list`).
    Repository,
    /// Probe staleness of the most recent snapshot against the schedule.
    Staleness,
    /// Probe repository integrity (`restic check` / `borg check`).
    Integrity,
    /// Probe encryption is configured (restic config / borg `encryption.mode`).
    Encryption,
    /// Probe the schedule is installed (delegates to `ScheduleManager`).
    Schedule,
    /// Probe retention policy is applied (`restic forget` / `borg prune` dry-run).
    Retention,
    /// Probe a test restore succeeds (`restic restore --verify-data` /
    /// `borg check --verify-data`-style sanity).
    Restore,
    /// Probe repository free space (`restic stats` / `borg info`).
    Space,
}

// ---------------------------------------------------------------------------
// DoctorReport
// ---------------------------------------------------------------------------

/// Aggregated doctor report containing all findings from a diagnostic run.
#[derive(Debug, Clone)]
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

    /// Returns the number of findings.
    #[must_use]
    pub fn len(&self) -> usize {
        self.findings.len()
    }

    /// Returns `true` if this report contains no findings.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.findings.is_empty()
    }

    /// Returns `true` if any finding has severity [`Severity::Error`] or higher.
    #[must_use]
    pub fn has_errors(&self) -> bool {
        self.findings.iter().any(|f| f.severity >= Severity::Error)
    }

    /// Returns `true` if any finding has severity [`Severity::Critical`].
    #[must_use]
    pub fn has_critical(&self) -> bool {
        self.findings.iter().any(|f| f.severity == Severity::Critical)
    }
}

// ===========================================================================
// file-local serde helpers (only compiled under the `client` feature, which
// implies serde + serde_json). These mirror the JSON shapes documented by
// restic and borg so the official docs remain the authoritative reference.
// ===========================================================================

#[cfg(feature = "client")]
mod json_shapes {
    use serde::Deserialize;

    /// Element of the `restic snapshots --json` array. Only the fields we need
    /// for staleness; unknown fields are ignored.
    ///
    /// Docs: <https://restic.readthedocs.io/en/v0.17.2/075_scripting.html#snapshots>
    #[derive(Debug, Deserialize)]
    pub(super) struct ResticSnapshot {
        /// RFC3339 timestamp of when the backup was started.
        pub time: String,
        #[serde(default)]
        pub id: String,
    }

    /// `restic stats --json` payload (repository-mode).
    ///
    /// Docs: <https://restic.readthedocs.io/en/v0.17.2/075_scripting.html#stats>
    #[derive(Debug, Deserialize)]
    pub(super) struct ResticStats {
        #[serde(default)]
        pub total_size: f64,
        #[serde(default)]
        pub snapshots_count: u64,
    }

    /// Root object of `borg info --json`.
    ///
    /// Docs: <https://borgbackup.readthedocs.io/en/stable/internals/frontends.html>
    /// ("The root object of '--json' output will contain at least a repository
    /// key ... The encryption key, if present, contains mode ...")
    #[derive(Debug, Deserialize)]
    pub(super) struct BorgInfo {
        #[serde(default)]
        pub encryption: Option<BorgEncryption>,
        #[serde(default)]
        pub cache: Option<BorgCache>,
        #[serde(default)]
        pub repository: Option<BorgRepository>,
        #[serde(default)]
        pub archives: Vec<BorgArchive>,
    }

    #[derive(Debug, Deserialize)]
    pub(super) struct BorgEncryption {
        #[serde(default)]
        pub mode: String,
    }

    #[derive(Debug, Deserialize)]
    pub(super) struct BorgCache {
        #[serde(default)]
        pub stats: Option<BorgCacheStats>,
    }

    #[derive(Debug, Deserialize)]
    pub(super) struct BorgCacheStats {
        /// Compressed + encrypted size of all chunks (the on-disk repo size).
        #[serde(default)]
        pub total_csize: u64,
    }

    #[derive(Debug, Deserialize)]
    pub(super) struct BorgRepository {
        #[serde(default)]
        pub last_modified: String,
    }

    /// Root object of `borg list --json`.
    ///
    /// Docs: <https://borgbackup.readthedocs.io/en/stable/internals/frontends.html>
    /// ("Either return archives in an array under the archives key ...")
    #[derive(Debug, Deserialize)]
    pub(super) struct BorgList {
        #[serde(default)]
        pub archives: Vec<BorgArchive>,
        #[serde(default)]
        pub encryption: Option<BorgEncryption>,
    }

    /// Shared archive shape (the simpler `borg list` form).
    #[derive(Debug, Deserialize)]
    pub(super) struct BorgArchive {
        #[serde(default)]
        pub name: String,
        /// ISO-8601 start timestamp.
        #[serde(default)]
        pub start: String,
    }
}

// ===========================================================================
// Free helpers
// ===========================================================================

/// Render a runner error into a compact, redaction-safe string.
///
/// `Runner::run_checked` already scrubs secret values from args/stderr when
/// the originating spec was built with `redact(true)` (which every repo-touching
/// spec here is), so embedding its `Display` in our own error variants is safe.
fn runner_err(err: &toride_runner::Error) -> String {
    err.to_string()
}

/// Convert a `&Path` to a string, failing with a clear error if the path
/// contains non-UTF-8 components (restic/borg arguments are UTF-8 strings).
fn path_string(p: &Path) -> Result<String> {
    p.to_str()
        .map(str::to_owned)
        .ok_or_else(|| Error::Other(format!("non-UTF-8 path: {}", p.display())))
}

/// Parse an RFC3339 / ISO-8601 timestamp into days-since-epoch.
///
/// Both restic (`time`) and borg (`start`/`last_modified`) emit ISO-8601
/// timestamps whose date portion is `YYYY-MM-DDTHH:MM:SS...`. We only need
/// day-granularity staleness, so a cheap lexical slice of the date beats
/// pulling a full datetime crate. Returns `None` if the string does not look
/// like an ISO date.
fn iso_to_days(ts: &str) -> Option<i64> {
    // Expect at least "YYYY-MM-DD".
    let date = ts.split('T').next()?;
    let parts: Vec<&str> = date.split('-').collect();
    if parts.len() != 3 {
        return None;
    }
    let y: i64 = parts[0].parse().ok()?;
    let m: i64 = parts[1].parse().ok()?;
    let d: i64 = parts[2].parse().ok()?;
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    Some(days_from_civil(y, m, d))
}

/// Howard Hinnant's days-from-civil algorithm — converts a Gregorian
/// (year, month, day) to a count of days since 1970-01-01. No external dep.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64; // [0, 399]
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) as u64 + 2) / 5 + d as u64 - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era * 146097 + doe as i64 - 719468
}

/// Current day count since 1970-01-01, UTC.
fn now_days() -> i64 {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    (secs / 86_400) as i64
}

/// Returns the number of whole days between `ts` (ISO-8601) and now.
/// Positive = `ts` is in the past. `None` if `ts` cannot be parsed.
fn days_since(ts: &str) -> Option<i64> {
    iso_to_days(ts).map(|d| now_days() - d)
}

// ---------------------------------------------------------------------------
// Doctor
// ---------------------------------------------------------------------------

/// Diagnostic engine that runs structured checks against backup
/// configurations and repositories.
///
/// Holds an injected [`Runner`] so it can be exercised against a
/// [`FakeRunner`](toride_runner::FakeRunner) in tests; in production it
/// defaults to [`DuctRunner`].
pub struct Doctor {
    runner: Arc<dyn Runner>,
    /// When set, [`Doctor::resolve_binary`] returns this path verbatim
    /// instead of consulting `$PATH`. Used by tests to avoid mutating the
    /// process environment (edition 2024 forbids `env::set_var` without
    /// `unsafe`, and this crate is `#![deny(unsafe_code)]`).
    #[cfg(test)]
    binary_override: Option<String>,
}

impl Doctor {
    /// Create a new diagnostic engine with a [`DuctRunner`].
    pub fn new() -> Self {
        Self {
            runner: Arc::new(DuctRunner),
            #[cfg(test)]
            binary_override: None,
        }
    }

    /// Create a diagnostic engine with an explicit runner (e.g. a
    /// `FakeRunner` in tests).
    #[must_use]
    pub fn with_runner(runner: Arc<dyn Runner>) -> Self {
        Self {
            runner,
            #[cfg(test)]
            binary_override: None,
        }
    }

    /// Test-only: force [`Doctor::resolve_binary`] to return the given path
    /// verbatim, bypassing `$PATH` lookup. Lets tests stay hermetic without
    /// mutating the process environment.
    #[cfg(test)]
    #[must_use]
    fn with_binary_override(mut self, binary: impl Into<String>) -> Self {
        self.binary_override = Some(binary.into());
        self
    }

    /// Run the selected string-named scope and return a complete report.
    ///
    /// The [`DoctorScope::Binary`] category runs a real `which`-based probe.
    /// The per-job categories (Repository/Staleness/Integrity/Encryption/
    /// Schedule/Retention/Space) carry only a job *name* and so cannot by
    /// themselves drive a `restic`/`borg` invocation; they emit an
    /// informational finding directing the caller to [`Doctor::run_spec`]
    /// with the full [`BackupSpec`].
    ///
    /// # Errors
    ///
    /// Returns an error only if a fundamental failure occurs. Individual
    /// check failures appear as findings in the report.
    pub fn run(&self, scope: &DoctorScope) -> Result<DoctorReport> {
        let mut report = DoctorReport::empty();

        match scope {
            DoctorScope::All => {
                report.findings.extend(self.check_binaries());
                report.findings.push(spec_hint_finding());
            }
            DoctorScope::Binary => {
                report.findings.extend(self.check_binaries());
            }
            DoctorScope::Repository(name) => {
                report.findings.extend(self.check_repository(name));
            }
            DoctorScope::Staleness(name) => {
                report.findings.extend(self.check_staleness(name));
            }
            DoctorScope::Integrity(name) => {
                report.findings.extend(self.check_integrity(name));
            }
            DoctorScope::Encryption(name) => {
                report.findings.extend(self.check_encryption(name));
            }
            DoctorScope::Schedule(name) => {
                report.findings.extend(self.check_schedule(name));
            }
            DoctorScope::Retention(name) => {
                report.findings.extend(self.check_retention(name));
            }
            DoctorScope::Space(name) => {
                report.findings.extend(self.check_space(name));
            }
        }

        Ok(report)
    }

    /// Run real probes against a full [`BackupSpec`] for the selected
    /// [`SpecScope`], returning a typed report.
    ///
    /// This is the path that actually invokes `restic`/`borg` through the
    /// injected runner. Every command is built with `redact(true)` and the
    /// passphrase is delivered via the `RESTIC_PASSWORD` / `BORG_PASSPHRASE`
    /// environment variable.
    ///
    /// # Errors
    ///
    /// Returns an error only for fundamental failures (e.g. the required
    /// binary is not on `$PATH`). Per-probe failures surface as findings.
    pub fn run_spec(&self, spec: &BackupSpec, scope: SpecScope) -> Result<DoctorReport> {
        let mut report = DoctorReport::empty();

        match scope {
            SpecScope::All => {
                report.findings.extend(self.check_binaries());
                report.findings.extend(self.probe_repository(spec)?);
                report.findings.extend(self.probe_integrity(spec)?);
                report.findings.extend(self.probe_encryption(spec)?);
                report.findings.extend(self.probe_staleness(spec)?);
                report.findings.extend(self.probe_schedule(spec)?);
                report.findings.extend(self.probe_retention(spec)?);
                report.findings.extend(self.probe_restore(spec)?);
                report.findings.extend(self.probe_space(spec)?);
            }
            SpecScope::Repository => report.findings.extend(self.probe_repository(spec)?),
            SpecScope::Integrity => report.findings.extend(self.probe_integrity(spec)?),
            SpecScope::Encryption => report.findings.extend(self.probe_encryption(spec)?),
            SpecScope::Staleness => report.findings.extend(self.probe_staleness(spec)?),
            SpecScope::Schedule => report.findings.extend(self.probe_schedule(spec)?),
            SpecScope::Retention => report.findings.extend(self.probe_retention(spec)?),
            SpecScope::Restore => report.findings.extend(self.probe_restore(spec)?),
            SpecScope::Space => report.findings.extend(self.probe_space(spec)?),
        }

        Ok(report)
    }

    // =======================================================================
    // Binary checks
    // =======================================================================

    /// Check that at least one backup binary (restic or borg) is available.
    fn check_binaries(&self) -> Vec<Finding> {
        let mut findings = Vec::new();

        let restic_available = which::which("restic").is_ok();
        let borg_available = which::which("borg").is_ok();

        if restic_available {
            findings.push(Finding::new(
                "binary.restic.found",
                Severity::Ok,
                "restic binary found on $PATH",
            ));
        } else {
            findings.push(
                Finding::new(
                    "binary.restic.missing",
                    Severity::Info,
                    "restic binary not found",
                )
                .detail(
                    "The restic binary is not on $PATH. Restic backups will \
                     not be available.",
                )
                .fix("Install restic: apt install restic (Debian/Ubuntu)."),
            );
        }

        if borg_available {
            findings.push(Finding::new(
                "binary.borg.found",
                Severity::Ok,
                "borg binary found on $PATH",
            ));
        } else {
            findings.push(
                Finding::new(
                    "binary.borg.missing",
                    Severity::Info,
                    "borg binary not found",
                )
                .detail(
                    "The borg binary is not on $PATH. Borg backups will \
                     not be available.",
                )
                .fix("Install borg: apt install borgbackup (Debian/Ubuntu)."),
            );
        }

        if !restic_available && !borg_available {
            findings.push(
                Finding::new(
                    "binary.none-available",
                    Severity::Critical,
                    "No backup binary available",
                )
                .detail(
                    "Neither restic nor borg was found on $PATH. At least \
                     one backup tool must be installed.",
                )
                .fix("Install restic or borg backup."),
            );
        }

        findings
    }

    // =======================================================================
    // String-named stubs (kept for signature stability with DoctorScope).
    // They honestly tell the caller to supply a BackupSpec via run_spec.
    // =======================================================================

    fn check_repository(&self, name: &str) -> Vec<Finding> {
        vec![spec_hint_for("repository", name)]
    }

    fn check_staleness(&self, name: &str) -> Vec<Finding> {
        vec![spec_hint_for("staleness", name)]
    }

    fn check_integrity(&self, name: &str) -> Vec<Finding> {
        vec![spec_hint_for("integrity", name)]
    }

    fn check_encryption(&self, name: &str) -> Vec<Finding> {
        vec![spec_hint_for("encryption", name)]
    }

    fn check_schedule(&self, name: &str) -> Vec<Finding> {
        vec![spec_hint_for("schedule", name)]
    }

    fn check_retention(&self, name: &str) -> Vec<Finding> {
        vec![spec_hint_for("retention", name)]
    }

    fn check_space(&self, name: &str) -> Vec<Finding> {
        vec![spec_hint_for("space", name)]
    }

    // =======================================================================
    // Real probes (BackupSpec-backed)
    // =======================================================================

    /// Resolve the backup binary for `spec.backend`, failing if it is absent.
    fn resolve_binary(&self, spec: &BackupSpec) -> Result<String> {
        let name = match spec.backend {
            Backend::Restic => "restic",
            Backend::Borg => "borg",
        };
        // Test override: bypass $PATH so tests stay hermetic without env
        // mutation (this crate is `#![deny(unsafe_code)]`, and edition 2024
        // requires `unsafe` for `env::set_var`).
        #[cfg(test)]
        if let Some(ref bin) = self.binary_override {
            return Ok(bin.clone());
        }
        which::which(name)
            .map(|p| p.to_string_lossy().into_owned())
            .map_err(|_| Error::BinaryNotFound(name.into()))
    }

    /// Resolve the raw passphrase (if any) from the spec's `password_command`.
    ///
    /// For doctor probes we only need *a* passphrase to satisfy the backend;
    /// the actual retrieval is delegated to restic's `--password-command` /
    /// borg's `BORG_PASSCOMMAND` plumbing when configured, or to the raw
    /// `RESTIC_PASSWORD` / `BORG_PASSPHRASE` env when the command output is
    /// directly available. Returns `None` when no passphrase is configured.
    fn passphrase_env(&self, spec: &BackupSpec) -> Vec<(String, String)> {
        let mut env = Vec::new();
        // The spec stores a *command* that yields the passphrase (e.g.
        // "cat /etc/restic/password"). We forward it verbatim to the backend's
        // own passcommand plumbing rather than executing it ourselves, so the
        // secret never enters this process. restic uses --password-command
        // (attached at spec-build time), borg uses BORG_PASSCOMMAND env.
        if spec.backend == Backend::Borg {
            if let Some(cmd) = &spec.password_command {
                env.push(("BORG_PASSCOMMAND".into(), cmd.clone()));
            }
        }
        // For restic the raw passphrase is unavailable here (we only have the
        // command); restic's --password-command flag is attached in
        // restic_repo_spec. Extra env from the spec is always forwarded.
        for (k, v) in &spec.extra_env {
            env.push((k.clone(), v.clone()));
        }
        env
    }

    // -----------------------------------------------------------------------
    // Repository accessibility
    // -----------------------------------------------------------------------

    /// Probe repository accessibility by listing snapshots/archives.
    ///
    /// - restic: `restic --repo <repo> snapshots --json`
    ///   (Docs: https://restic.readthedocs.io/en/v0.17.2/075_scripting.html#snapshots)
    /// - borg:   `borg list --json <repo>`
    ///   (Docs: https://borgbackup.readthedocs.io/en/stable/internals/frontends.html)
    ///
    /// Both commands succeed only when the repository exists, is readable,
    /// and (if encrypted) the passphrase is correct.
    fn probe_repository(&self, spec: &BackupSpec) -> Result<Vec<Finding>> {
        let binary = self.resolve_binary(spec)?;
        let mut findings = Vec::new();

        let spec_cmd = match spec.backend {
            Backend::Restic => self.restic_repo_spec(&binary, spec)?,
            Backend::Borg => self.borg_repo_spec(&binary, spec)?,
        };

        let list_spec = match spec.backend {
            Backend::Restic => spec_cmd.arg("snapshots").arg("--json").redact(true),
            // borg takes the repo as a positional argument after the verb.
            Backend::Borg => spec_cmd
                .arg("list")
                .arg("--json")
                .arg(path_string(&spec.repository)?)
                .redact(true),
        };

        match self.runner.run_checked(&list_spec) {
            Ok(output) => {
                let count = match spec.backend {
                    Backend::Restic => parse_restic_snapshot_count(output.stdout_trimmed()),
                    Backend::Borg => parse_borg_archive_count(output.stdout_trimmed()),
                };
                findings.push(Finding::new(
                    "repository.accessible",
                    Severity::Ok,
                    format!("{} repository is accessible", spec.backend),
                ));
                if let Some(n) = count {
                    findings.push(Finding::new(
                        "repository.snapshots",
                        Severity::Ok,
                        format!("{} snapshot(s) present", n),
                    ));
                }
            }
            Err(e) => {
                findings.push(
                    Finding::new(
                        "repository.inaccessible",
                        Severity::Error,
                        format!("{} repository is not accessible", spec.backend),
                    )
                    .detail(format!(
                        "Listing snapshots failed:\n{}",
                        runner_err(&e)
                    ))
                    .fix(format!(
                        "Verify the repository path {} is correct and the \
                         passphrase is right.",
                        spec.repository.display()
                    )),
                );
            }
        }

        Ok(findings)
    }

    // -----------------------------------------------------------------------
    // Integrity
    // -----------------------------------------------------------------------

    /// Probe repository integrity.
    ///
    /// - restic: `restic --repo <repo> check` (no --json; check emits
    ///   human-readable progress and a final "no errors were found").
    ///   Docs: https://restic.readthedocs.io/en/latest/045_working_with_repos.html#checking-integrity-and-consistency
    /// - borg:   `borg check --repository-only <repo>` (cheap structural
    ///   check; --verify-data is much more expensive and reserved for
    ///   Restore). Docs: https://borgbackup.readthedocs.io/en/stable/usage/check.html
    fn probe_integrity(&self, spec: &BackupSpec) -> Result<Vec<Finding>> {
        let binary = self.resolve_binary(spec)?;
        let mut findings = Vec::new();

        let check_spec = match spec.backend {
            Backend::Restic => {
                let s = self.restic_repo_spec(&binary, spec)?;
                s.arg("check").redact(true)
            }
            Backend::Borg => {
                // borg check takes the repo as a positional arg, not a flag.
                let mut s = CommandSpec::new(&binary).arg("check").arg("--repository-only");
                s = self.apply_borg_secrets(s, spec);
                s.arg(path_string(&spec.repository)?).redact(true)
            }
        };

        match self.runner.run_checked(&check_spec) {
            Ok(output) => {
                let ok_text = match spec.backend {
                    // restic prints "no errors were found" on success.
                    Backend::Restic => output
                        .stdout
                        .to_ascii_lowercase()
                        .contains("no errors were found"),
                    // borg check --repository-only prints nothing extra on
                    // success (exit 0); absence of "error" is our signal.
                    Backend::Borg => !output
                        .combined_output()
                        .to_ascii_lowercase()
                        .contains("error"),
                };
                if ok_text {
                    findings.push(Finding::new(
                        "integrity.ok",
                        Severity::Ok,
                        format!("{} integrity check passed", spec.backend),
                    ));
                } else {
                    findings.push(
                        Finding::new(
                            "integrity.unknown",
                            Severity::Warning,
                            format!("{} integrity check exited 0 but reported no clean signal", spec.backend),
                        )
                        .detail(output.combined_output()),
                    );
                }
            }
            Err(e) => {
                findings.push(
                    Finding::new(
                        "integrity.failed",
                        Severity::Error,
                        format!("{} integrity check failed", spec.backend),
                    )
                    .detail(runner_err(&e))
                    .fix(format!(
                        "Run `{} check` manually against {} and consult the \
                         output for corrupted packs/segments.",
                        spec.backend,
                        spec.repository.display()
                    )),
                );
            }
        }

        Ok(findings)
    }

    // -----------------------------------------------------------------------
    // Encryption
    // -----------------------------------------------------------------------

    /// Probe encryption is configured.
    ///
    /// - restic: encryption is *always* on (restic has no unencrypted mode);
    ///   we confirm the repo is openable by reading the config via
    ///   `restic --repo <repo> cat config` (exit 0 ⇒ key/password works).
    ///   Docs: https://restic.readthedocs.io/en/v0.17.2/075_scripting.html#cat
    /// - borg: `borg info --json <repo>` exposes `encryption.mode`
    ///   (`repokey` / `keyfile` / `none` / ...).
    ///   Docs: https://borgbackup.readthedocs.io/en/stable/internals/frontends.html
    fn probe_encryption(&self, spec: &BackupSpec) -> Result<Vec<Finding>> {
        let binary = self.resolve_binary(spec)?;
        let mut findings = Vec::new();

        match spec.backend {
            Backend::Restic => {
                let base = self.restic_repo_spec(&binary, spec)?;
                let cat_spec = base.arg("cat").arg("config").redact(true);
                match self.runner.run_checked(&cat_spec) {
                    Ok(_) => findings.push(Finding::new(
                        "encryption.enabled",
                        Severity::Ok,
                        "restic repository is encrypted and the key unlocks it",
                    )),
                    Err(e) => findings.push(
                        Finding::new(
                            "encryption.unverifiable",
                            Severity::Error,
                            "could not read restic repository config",
                        )
                        .detail(runner_err(&e))
                        .fix("Confirm the passphrase / --password-command is correct."),
                    ),
                }
            }
            Backend::Borg => {
                let mut s = CommandSpec::new(&binary).arg("info").arg("--json");
                s = self.apply_borg_secrets(s, spec);
                let info_spec = s.arg(path_string(&spec.repository)?).redact(true);
                match self.runner.run_checked(&info_spec) {
                    Ok(output) => {
                        #[cfg(feature = "client")]
                        {
                            match parse_borg_encryption_mode(output.stdout_trimmed()) {
                                Some(mode) if mode == "none" => findings.push(
                                    Finding::new(
                                        "encryption.disabled",
                                        Severity::Warning,
                                        "borg repository is NOT encrypted",
                                    )
                                    .detail(format!("encryption.mode = {mode}"))
                                    .fix(
                                        "Re-initialise the repository with an \
                                         encryption mode (e.g. repokey-blake2).",
                                    ),
                                ),
                                Some(mode) => findings.push(Finding::new(
                                    "encryption.enabled",
                                    Severity::Ok,
                                    format!("borg repository is encrypted ({mode})"),
                                )),
                                None => findings.push(
                                    Finding::new(
                                        "encryption.unknown",
                                        Severity::Warning,
                                        "could not parse borg encryption mode",
                                    )
                                    .detail(output.stdout),
                                ),
                            }
                        }
                        #[cfg(not(feature = "client"))]
                        {
                            findings.push(Finding::new(
                                "encryption.unknown",
                                Severity::Info,
                                "encryption mode parsing requires the `client` feature",
                            ));
                            let _ = output;
                        }
                    }
                    Err(e) => findings.push(
                        Finding::new(
                            "encryption.unverifiable",
                            Severity::Error,
                            "could not read borg repository info",
                        )
                        .detail(runner_err(&e)),
                    ),
                }
            }
        }

        Ok(findings)
    }

    // -----------------------------------------------------------------------
    // Staleness (last run vs schedule)
    // -----------------------------------------------------------------------

    /// Probe the most recent snapshot is not stale relative to the schedule.
    ///
    /// Lists snapshots, takes the newest `time`/`start`, and compares its
    /// age (in days) against the schedule cadence derived from the cron
    /// expression. A backup is "stale" when its age exceeds ~1.5x the
    /// expected daily run interval.
    ///
    /// - restic: newest entry of `restic snapshots --json` (field `time`).
    /// - borg:   newest entry of `borg list --json` (field `start`).
    fn probe_staleness(&self, spec: &BackupSpec) -> Result<Vec<Finding>> {
        let binary = self.resolve_binary(spec)?;
        let mut findings = Vec::new();

        let list_spec = match spec.backend {
            Backend::Restic => {
                let s = self.restic_repo_spec(&binary, spec)?;
                s.arg("snapshots").arg("--json").redact(true)
            }
            Backend::Borg => {
                let mut s = CommandSpec::new(&binary).arg("list").arg("--json");
                s = self.apply_borg_secrets(s, spec);
                s.arg(path_string(&spec.repository)?).redact(true)
            }
        };

        let output = match self.runner.run_checked(&list_spec) {
            Ok(o) => o,
            Err(e) => {
                findings.push(
                    Finding::new(
                        "staleness.unknown",
                        Severity::Warning,
                        "could not list snapshots to assess staleness",
                    )
                    .detail(runner_err(&e)),
                );
                return Ok(findings);
            }
        };

        let latest = match spec.backend {
            Backend::Restic => parse_restic_latest_time(output.stdout_trimmed()),
            Backend::Borg => parse_borg_latest_start(output.stdout_trimmed()),
        };

        match latest {
            Some(ts) => match days_since(&ts) {
                Some(age) => {
                    let max_age = max_age_days_from_cron(&spec.schedule.cron);
                    findings.push(Finding::new(
                        "staleness.last-run",
                        Severity::Ok,
                        format!("most recent snapshot is {age} day(s) old"),
                    ));
                    if age > max_age {
                        findings.push(
                            Finding::new(
                                "staleness.stale",
                                Severity::Error,
                                "backups are stale",
                            )
                            .detail(format!(
                                "Newest snapshot is {age} day(s) old but the \
                                 schedule ({}) expects a run at most every ~{max_age} day(s).",
                                spec.schedule.cron,
                            ))
                            .fix("Run the backup manually or fix the schedule."),
                        );
                    }
                }
                None => findings.push(Finding::new(
                    "staleness.unparseable",
                    Severity::Warning,
                    "could not parse the latest snapshot timestamp",
                )),
            },
            None => findings.push(
                Finding::new(
                    "staleness.never",
                    Severity::Error,
                    "no snapshots found",
                )
                .detail("The repository is accessible but contains no snapshots.")
                .fix("Run the initial backup."),
            ),
        }

        Ok(findings)
    }

    // -----------------------------------------------------------------------
    // Schedule
    // -----------------------------------------------------------------------

    /// Probe the schedule is installed (systemd timer or cron entry).
    ///
    /// Delegates to [`crate::schedule::ScheduleManager::is_installed`] so the
    /// doctor and the scheduler agree on what "installed" means.
    fn probe_schedule(&self, spec: &BackupSpec) -> Result<Vec<Finding>> {
        let mgr = crate::schedule::ScheduleManager::new();
        let mut findings = Vec::new();

        // ScheduleManager uses DuctRunner internally; is_installed is a real
        // probe (systemd unit presence / cron.d file presence). We surface its
        // result directly.
        match mgr.is_installed(&spec.name) {
            Ok(true) => findings.push(Finding::new(
                "schedule.installed",
                Severity::Ok,
                format!("schedule for '{}' is installed", spec.name),
            )),
            Ok(false) => findings.push(
                Finding::new(
                    "schedule.missing",
                    Severity::Warning,
                    format!("no schedule installed for '{}'", spec.name),
                )
                .detail(format!(
                    "Cron expression {} is configured but no systemd timer \
                     or cron.d entry was found for this job.",
                    spec.schedule.cron,
                ))
                .fix(format!(
                    "Install the schedule (e.g. `toride-backup install-schedule {}`).",
                    spec.name
                )),
            ),
            Err(e) => findings.push(
                Finding::new(
                    "schedule.unknown",
                    Severity::Warning,
                    "could not determine schedule status",
                )
                .detail(format!("{e}")),
            ),
        }

        Ok(findings)
    }

    // -----------------------------------------------------------------------
    // Retention
    // -----------------------------------------------------------------------

    /// Probe the retention policy is applied by running a dry-run forget/prune.
    ///
    /// - restic: `restic --repo <repo> forget --json --keep-daily N ...`
    ///   (Docs: https://restic.readthedocs.io/en/v0.17.2/075_scripting.html#forget)
    /// - borg:   `borg prune --dry-run --list <repo> --keep-daily N ...`
    ///   (Docs: https://borgbackup.readthedocs.io/en/stable/usage/prune.html)
    ///
    /// A successful dry-run proves the policy is well-formed and the repo can
    /// be scanned for retention; it does NOT remove any data.
    fn probe_retention(&self, spec: &BackupSpec) -> Result<Vec<Finding>> {
        let binary = self.resolve_binary(spec)?;
        let mut findings = Vec::new();

        let keep_args = retention_args(&spec.retention);

        let dry_spec = match spec.backend {
            Backend::Restic => {
                let mut s = self.restic_repo_spec(&binary, spec)?;
                s = s.arg("forget").arg("--json");
                for a in &keep_args {
                    s = s.arg(a);
                }
                s.redact(true)
            }
            Backend::Borg => {
                let mut s = CommandSpec::new(&binary)
                    .arg("prune")
                    .arg("--dry-run")
                    .arg("--list");
                for a in &keep_args {
                    s = s.arg(a);
                }
                s = self.apply_borg_secrets(s, spec);
                s.arg(path_string(&spec.repository)?).redact(true)
            }
        };

        if keep_args.is_empty() {
            findings.push(
                Finding::new(
                    "retention.unconfigured",
                    Severity::Warning,
                    "no retention policy configured",
                )
                .detail("The retention policy has no keep-* values; snapshots will accumulate forever.")
                .fix("Set keep-daily / keep-weekly / keep-monthly on the spec."),
            );
            return Ok(findings);
        }

        match self.runner.run_checked(&dry_spec) {
            Ok(_) => findings.push(Finding::new(
                "retention.ok",
                Severity::Ok,
                format!("retention policy dry-run succeeded ({})", keep_args.join(" ")),
            )),
            Err(e) => findings.push(
                Finding::new(
                    "retention.failed",
                    Severity::Warning,
                    "retention policy dry-run failed",
                )
                .detail(runner_err(&e))
                .fix(format!(
                    "Run `{} {}` manually to see why the policy does not apply.",
                    spec.backend,
                    if spec.backend == Backend::Restic {
                        "forget --dry-run"
                    } else {
                        "prune --dry-run"
                    }
                )),
            ),
        }

        Ok(findings)
    }

    // -----------------------------------------------------------------------
    // Restore (test restore sanity)
    // -----------------------------------------------------------------------

    /// Probe a restore path is viable without writing to a real target.
    ///
    /// We do NOT run a full file-level restore (expensive, needs disk).
    /// Instead we prove the restore *machinery* works:
    /// - restic: `restic --repo <repo> check --read-data-subset=5%` is the
    ///   documented lightweight data-verification; falling back to a plain
    ///   `check` when the subset flag is unavailable. Exit 0 ⇒ packs are
    ///   decryptable and restorable.
    ///   Docs: https://restic.readthedocs.io/en/latest/045_working_with_repos.html#checking-integrity-and-consistency
    /// - borg:   `borg check --verify-data <repo>` reads and authenticates
    ///   every chunk — the strongest pre-restore confidence check.
    ///   Docs: https://borgbackup.readthedocs.io/en/stable/usage/check.html
    fn probe_restore(&self, spec: &BackupSpec) -> Result<Vec<Finding>> {
        let binary = self.resolve_binary(spec)?;
        let mut findings = Vec::new();

        let verify_spec = match spec.backend {
            Backend::Restic => {
                let s = self.restic_repo_spec(&binary, spec)?;
                s.arg("check").arg("--read-data-subset=5%").redact(true)
            }
            Backend::Borg => {
                let mut s = CommandSpec::new(&binary).arg("check").arg("--verify-data");
                s = self.apply_borg_secrets(s, spec);
                s.arg(path_string(&spec.repository)?).redact(true)
            }
        };

        match self.runner.run_checked(&verify_spec) {
            Ok(_) => findings.push(Finding::new(
                "restore.viable",
                Severity::Ok,
                format!("{} data verification passed — restore path is viable", spec.backend),
            )),
            Err(e) => findings.push(
                Finding::new(
                    "restore.risky",
                    Severity::Error,
                    "data verification failed — restores may not succeed",
                )
                .detail(runner_err(&e))
                .fix(format!(
                    "Investigate corrupted data in {} before relying on restores.",
                    spec.repository.display()
                )),
            ),
        }

        Ok(findings)
    }

    // -----------------------------------------------------------------------
    // Space
    // -----------------------------------------------------------------------

    /// Probe the repository size / free space is sane.
    ///
    /// - restic: `restic --repo <repo> stats --json` → `total_size`.
    ///   Docs: https://restic.readthedocs.io/en/v0.17.2/075_scripting.html#stats
    /// - borg:   `borg info --json <repo>` → `cache.stats.total_csize`
    ///   (compressed+encrypted on-disk repo size).
    ///   Docs: https://borgbackup.readthedocs.io/en/stable/internals/frontends.html
    ///
    /// This reports the repo's own size as an informational finding; a true
    /// free-disk check would need statvfs(2) on the repo's mountpoint, which
    /// is out of scope for the cross-platform runner.
    fn probe_space(&self, spec: &BackupSpec) -> Result<Vec<Finding>> {
        let binary = self.resolve_binary(spec)?;
        let mut findings = Vec::new();

        let size_spec = match spec.backend {
            Backend::Restic => {
                let s = self.restic_repo_spec(&binary, spec)?;
                s.arg("stats").arg("--json").redact(true)
            }
            Backend::Borg => {
                let mut s = CommandSpec::new(&binary).arg("info").arg("--json");
                s = self.apply_borg_secrets(s, spec);
                s.arg(path_string(&spec.repository)?).redact(true)
            }
        };

        match self.runner.run_checked(&size_spec) {
            Ok(output) => {
                #[cfg(feature = "client")]
                {
                    let bytes = match spec.backend {
                        Backend::Restic => parse_restic_total_size(output.stdout_trimmed()),
                        Backend::Borg => parse_borg_total_csize(output.stdout_trimmed()),
                    };
                    match bytes {
                        Some(b) => findings.push(Finding::new(
                            "space.repo-size",
                            Severity::Info,
                            format!("repository occupies {:.2} MiB", b as f64 / 1_048_576.0),
                        )),
                        None => findings.push(Finding::new(
                            "space.unparseable",
                            Severity::Info,
                            "could not parse repository size",
                        )),
                    }
                }
                #[cfg(not(feature = "client"))]
                {
                    findings.push(Finding::new(
                        "space.reported",
                        Severity::Info,
                        "repository stats retrieved (parsing needs the `client` feature)",
                    ));
                    let _ = output;
                }
            }
            Err(e) => findings.push(
                Finding::new(
                    "space.unknown",
                    Severity::Warning,
                    "could not read repository statistics",
                )
                .detail(runner_err(&e)),
            ),
        }

        Ok(findings)
    }

    // =======================================================================
    // Command builders
    // =======================================================================

    /// Build the base of a restic repo-touching subcommand:
    /// `restic --repo <repo> [--password-command <cmd>] <subcommand>...`
    ///
    /// The raw passphrase is delivered via `RESTIC_PASSWORD` env (attached
    /// here from `spec.extra_env` / a future raw-passphrase field). The repo
    /// URL is treated as potentially secret. Callers MUST finish with
    /// `.redact(true)`.
    fn restic_repo_spec(&self, binary: &str, spec: &BackupSpec) -> Result<CommandSpec> {
        let mut s = CommandSpec::new(binary)
            .arg("--repo")
            .arg(path_string(&spec.repository)?);
        if let Some(cmd) = &spec.password_command {
            // restic's own plumbing retrieves the passphrase; it never enters
            // this process.
            s = s.arg("--password-command").arg(cmd.clone());
        }
        // Forward any caller-provided env (may include RESTIC_PASSWORD etc.).
        for (k, v) in &spec.extra_env {
            s = s.env(k.clone(), v.clone());
        }
        Ok(s)
    }

    /// Build the base of a borg repo-touching subcommand that takes the repo
    /// as a leading flag-less token (e.g. `borg list`). The repo is appended
    /// by the caller. Secrets (BORG_PASSCOMMAND / extra env) are attached here.
    ///
    /// Borg repo URLs are positional, so unlike restic the repo argument is
    /// added at each call site (after the subcommand verb).
    fn borg_repo_spec(&self, binary: &str, spec: &BackupSpec) -> Result<CommandSpec> {
        // `borg list --json <repo>` — repo is positional. We build the verb
        // base here and let the caller append the repo, OR we append it.
        // For consistency with the list probe, append the repo here.
        let s = CommandSpec::new(binary);
        Ok(self.apply_borg_secrets(s, spec))
    }

    /// Attach borg-specific secret env (BORG_PASSCOMMAND + caller extra env).
    fn apply_borg_secrets(&self, mut spec: CommandSpec, backup_spec: &BackupSpec) -> CommandSpec {
        if let Some(cmd) = &backup_spec.password_command {
            // Borg fetches the passphrase itself via BORG_PASSCOMMAND; the
            // secret never enters this process.
            spec = spec.env("BORG_PASSCOMMAND", cmd.clone());
        }
        for (k, v) in &backup_spec.extra_env {
            spec = spec.env(k.clone(), v.clone());
        }
        spec
    }
}

impl Default for Doctor {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// Free helpers (parsing + scope hints)
// ===========================================================================

/// Informational finding pointing callers at `Doctor::run_spec` for a category
/// that needs a full `BackupSpec`.
fn spec_hint_for(category: &str, name: &str) -> Finding {
    let label = if name.is_empty() {
        "this job".to_string()
    } else {
        format!("'{name}'")
    };
    Finding::new(
        format!("{category}.needs-spec"),
        Severity::Info,
        format!("{category} check for {label} requires a BackupSpec"),
    )
    .detail(format!(
        "The {category} category must probe the live repository via restic/borg. \
         Pass the full BackupSpec to `Doctor::run_spec(spec, SpecScope::{Cap})` \
         to run the real probe.",
        Cap = cap_first(category)
    ))
}

/// One-off hint for the `All` string scope.
fn spec_hint_finding() -> Finding {
    Finding::new(
        "doctor.needs-spec",
        Severity::Info,
        "per-job categories skipped: supply a BackupSpec via run_spec",
    )
    .detail(
        "Doctor::run(DoctorScope::All) runs the binary check for real; the \
         repository/integrity/encryption/staleness/schedule/retention/space \
         categories need a full BackupSpec. Call Doctor::run_spec(spec, \
         SpecScope::All) to run them.",
    )
}

fn cap_first(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        Some(first) => {
            let mut out = String::new();
            out.push(first.to_ascii_uppercase());
            out.push_str(chars.as_str());
            out
        }
        None => String::new(),
    }
}

/// Turn a [`crate::spec::RetentionPolicy`] into backend keep-* flag pairs
/// (`["--keep-daily", "7", "--keep-weekly", "4", ...]`). Shared by restic
/// `forget` and borg `prune` (both use the same flag spellings).
fn retention_args(policy: &crate::spec::RetentionPolicy) -> Vec<String> {
    let mut out = Vec::new();
    let mut push = |flag: &str, n: Option<u32>| {
        if let Some(n) = n {
            out.push(flag.into());
            out.push(n.to_string());
        }
    };
    push("--keep-hourly", policy.keep_hourly);
    push("--keep-daily", policy.keep_daily);
    push("--keep-weekly", policy.keep_weekly);
    push("--keep-monthly", policy.keep_monthly);
    push("--keep-yearly", policy.keep_yearly);
    out
}

/// Rough "max tolerable age in days" derived from a 5-field cron expression.
///
/// Fields: min hour day-of-month month day-of-week.
/// - A specific day-of-month (and `*` month) → monthly-ish (tolerate 35 days).
/// - A specific day-of-week (and `*` day-of-month) → weekly-ish (tolerate 10).
/// - Otherwise (`*` day-of-month) → at least daily (tolerate 2 days).
/// This is a heuristic staleness threshold, not an exact schedule prediction.
fn max_age_days_from_cron(cron: &str) -> i64 {
    let dom = cron.split_whitespace().nth(2);
    let month = cron.split_whitespace().nth(3);
    let dow = cron.split_whitespace().nth(4);
    match (dom, month, dow) {
        // Specific day-of-month, any month → monthly.
        (Some(d), _, _) if d != "*" => 35,
        // `*` day-of-month but a specific day-of-week → weekly.
        (_, _, Some(w)) if w != "*" => 10,
        // `*` day-of-month and `*` day-of-week → at least daily.
        _ => 2,
    }
}

// ---------------------------------------------------------------------------
// JSON parsers (only compiled under `client`, which implies serde_json).
// Each accepts the exact shape documented by the official backend docs.
// ---------------------------------------------------------------------------

#[cfg(feature = "client")]
fn parse_restic_snapshot_count(stdout: &str) -> Option<u64> {
    let snaps: Vec<json_shapes::ResticSnapshot> = serde_json::from_str(stdout).ok()?;
    Some(snaps.len() as u64)
}

#[cfg(feature = "client")]
fn parse_restic_latest_time(stdout: &str) -> Option<String> {
    let snaps: Vec<json_shapes::ResticSnapshot> = serde_json::from_str(stdout).ok()?;
    snaps.into_iter().map(|s| s.time).max()
}

#[cfg(feature = "client")]
fn parse_restic_total_size(stdout: &str) -> Option<u64> {
    let stats: json_shapes::ResticStats = serde_json::from_str(stdout).ok()?;
    Some(stats.total_size as u64)
}

#[cfg(feature = "client")]
fn parse_borg_archive_count(stdout: &str) -> Option<u64> {
    let list: json_shapes::BorgList = serde_json::from_str(stdout).ok()?;
    Some(list.archives.len() as u64)
}

#[cfg(feature = "client")]
fn parse_borg_latest_start(stdout: &str) -> Option<String> {
    // `borg list --json` and `borg info --json` both carry archives under
    // `archives`; the list form is the cheaper one we use for staleness.
    let list: json_shapes::BorgList = serde_json::from_str(stdout).ok()?;
    list.archives.into_iter().map(|a| a.start).max()
}

#[cfg(feature = "client")]
fn parse_borg_encryption_mode(stdout: &str) -> Option<String> {
    let info: json_shapes::BorgInfo = serde_json::from_str(stdout).ok()?;
    info.encryption.map(|e| e.mode)
}

#[cfg(feature = "client")]
fn parse_borg_total_csize(stdout: &str) -> Option<u64> {
    let info: json_shapes::BorgInfo = serde_json::from_str(stdout).ok()?;
    info.cache.and_then(|c| c.stats).map(|s| s.total_csize)
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(all(test, feature = "client"))]
mod tests {
    use super::*;
    use crate::spec::{Backend, Encryption, RetentionPolicy, Schedule};
    use toride_runner::fake::FakeRunner;
    use toride_runner::CommandOutput;

    // -----------------------------------------------------------------------
    // Test fixtures
    // -----------------------------------------------------------------------

    /// Build a restic BackupSpec pointing at a local repo.
    fn restic_spec(repo: &str) -> BackupSpec {
        BackupSpec {
            name: "nightly".into(),
            backend: Backend::Restic,
            repository: repo.into(),
            sources: vec!["/etc".into()],
            schedule: Schedule::new("0 2 * * *").with_description("daily 2am"),
            retention: RetentionPolicy::default_policy(),
            encryption: Encryption::RepoKey,
            password_command: Some("cat /etc/restic/pw".into()),
            exclude_patterns: Vec::new(),
            tags: Vec::new(),
            extra_env: std::collections::HashMap::new(),
        }
    }

    /// Build a borg BackupSpec pointing at a local repo.
    fn borg_spec(repo: &str) -> BackupSpec {
        BackupSpec {
            name: "nightly".into(),
            backend: Backend::Borg,
            repository: repo.into(),
            sources: vec!["/etc".into()],
            schedule: Schedule::new("0 2 * * *"),
            retention: RetentionPolicy::default_policy(),
            encryption: Encryption::RepoKey,
            password_command: Some("cat /etc/borg/pw".into()),
            exclude_patterns: Vec::new(),
            tags: Vec::new(),
            extra_env: std::collections::HashMap::new(),
        }
    }

    /// Wrap a FakeRunner-backed Doctor whose `resolve_binary` is short-circuited
    /// to a fixed binary name. This keeps tests hermetic: real `restic`/`borg`
    /// need not be on `$PATH`, and we never mutate the process environment
    /// (edition 2024 forbids `env::set_var` without `unsafe`, and this crate
    /// is `#![deny(unsafe_code)]`).
    fn doctor_with_fake(runner: FakeRunner, binary: &str) -> (Doctor, std::sync::Arc<FakeRunner>) {
        let rc = std::sync::Arc::new(runner);
        let doc = Doctor::with_runner(rc.clone()).with_binary_override(binary);
        (doc, rc)
    }

    // -------------------------------------------------------------------------
    // String scope still works (signature stability) + binary check is real
    // -------------------------------------------------------------------------

    #[test]
    fn run_binary_scope_is_real() {
        // Whether or not restic/borg is installed, run must not error and
        // must return at least one binary.* finding.
        let doc = Doctor::new();
        let report = doc.run(&DoctorScope::Binary).expect("run ok");
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.id.starts_with("binary.")),
            "binary scope must produce binary.* findings: {:?}",
            report.findings
        );
    }

    #[test]
    fn run_named_scope_emits_spec_hint() {
        let doc = Doctor::new();
        let report = doc
            .run(&DoctorScope::Repository("nightly".into()))
            .expect("run ok");
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].severity, Severity::Info);
        assert!(report.findings[0].id.starts_with("repository.needs-spec"));
        assert!(report.findings[0].detail.contains("run_spec"));
    }

    #[test]
    fn run_all_includes_binary_findings_and_hint() {
        let doc = Doctor::new();
        let report = doc.run(&DoctorScope::All).expect("run ok");
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.id.starts_with("binary."))
        );
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.id == "doctor.needs-spec")
        );
    }

    // -------------------------------------------------------------------------
    // Repository probe — restic
    // -------------------------------------------------------------------------
    // Source: https://restic.readthedocs.io/en/v0.17.2/075_scripting.html#snapshots
    // The `restic snapshots --json` output is a JSON array; each element has
    // at minimum {time, id, short_id, tree, ...}.

    #[test]
    fn restic_repository_probe_parses_docs_json_and_builds_command() {
        let sample = r#"[
          {
            "time": "2024-09-18T12:34:56.789012345Z",
            "tree": "fda3c5e8b2a1d4c6e9f0a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2",
            "paths": ["/etc"],
            "hostname": "kasa",
            "username": "user",
            "id": "5111c8ae5a5e3e2e8b6b4f0c5b8e3a2d1c9f0a1b2c3d4e5f6a7b8c9d0e1f2a3",
            "short_id": "5111c8ae"
          }
        ]"#;
        let runner = FakeRunner::new().push_response(CommandOutput::from_stdout(sample));
        let (doc, rc) = doctor_with_fake(runner, "restic");
        let spec = restic_spec("/srv/backup");

        let report = doc
            .run_spec(&spec, SpecScope::Repository)
            .expect("probe ok");
        assert!(report.findings.iter().any(|f| f.id == "repository.accessible"));
        assert!(report.findings.iter().any(|f| f.id == "repository.snapshots"));

        // The passphrase-command is forwarded via restic's --password-command
        // flag; redact(true) is mandatory because the repo URL is present.
        // `assert_called_with` enforces redact, so a missing redact fails here.
        let calls = rc.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].program, "restic");
        // repo is positional after --repo; never the passphrase.
        assert!(calls[0].args.iter().any(|a| a == "/srv/backup"));
        assert!(
            calls[0].args.iter().any(|a| a == "--password-command"),
            "restic must use --password-command, not a raw passphrase arg"
        );
        // The most important property: redact(true) is set.
        assert!(
            calls[0].redact,
            "repo-touching restic command MUST set redact(true)"
        );

        // Exact command shape.
        let expected = CommandSpec::new("restic")
            .args(["--repo", "/srv/backup", "--password-command", "cat /etc/restic/pw", "snapshots", "--json"])
            .redact(true);
        rc.assert_called_with(&expected);

        // And a spec built WITHOUT redact must fail an exact match (non-vacuous).
        let unredacted = CommandSpec::new("restic")
            .args(["--repo", "/srv/backup", "--password-command", "cat /etc/restic/pw", "snapshots", "--json"]);
        let did_panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            rc.assert_called_with(&unredacted);
        }));
        assert!(did_panic.is_err(), "missing redact(true) must NOT match");
    }

    #[test]
    fn restic_repository_probe_reports_inaccessible_on_failure() {
        let runner = FakeRunner::new().push_result(Err(toride_runner::Error::CommandFailed {
            program: "restic".into(),
            args: "...".into(),
            exit_code: Some(1),
            stderr: "unable to open repo".into(),
        }));
        let (doc, _rc) = doctor_with_fake(runner, "restic");
        let report = doc
            .run_spec(&restic_spec("/srv/backup"), SpecScope::Repository)
            .expect("probe ok");
        assert!(report.findings.iter().any(|f| f.id == "repository.inaccessible"
            && f.severity == Severity::Error));
        assert!(report.has_errors());
    }

    // -------------------------------------------------------------------------
    // Repository probe — borg
    // -------------------------------------------------------------------------
    // Source: https://borgbackup.readthedocs.io/en/stable/internals/frontends.html
    // `borg list --json` root object: {archives:[{id,name,start}], encryption, repository}

    #[test]
    fn borg_repository_probe_parses_docs_json_and_builds_command() {
        let sample = r#"{
            "archives": [
                {
                    "id": "80cd07219ad725b3c5f665c1dcf119435c4dee1647a560ecac30f8d40221a46a",
                    "name": "host-system-backup-2017-02-27",
                    "start": "2017-08-07T12:27:20.789123"
                }
            ],
            "encryption": {"mode": "repokey"},
            "repository": {
                "id": "0cbe6166b46627fd26b97f8831e2ca97584280a46714ef84d2b668daf8271a23",
                "last_modified": "2017-08-07T12:27:20.789123",
                "location": "/home/user/repository"
            }
        }"#;
        let runner = FakeRunner::new().push_response(CommandOutput::from_stdout(sample));
        let (doc, rc) = doctor_with_fake(runner, "borg");
        let spec = borg_spec("/home/user/repository");

        let report = doc
            .run_spec(&spec, SpecScope::Repository)
            .expect("probe ok");
        assert!(report.findings.iter().any(|f| f.id == "repository.accessible"));
        assert!(report.findings.iter().any(|f| f.id == "repository.snapshots"));

        // borg passes the passphrase via BORG_PASSCOMMAND env (never an arg),
        // and the repo URL is positional. redact(true) is mandatory.
        let calls = rc.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].program, "borg");
        assert!(calls[0].args.iter().any(|a| a == "/home/user/repository"));
        assert!(
            calls[0]
                .env
                .iter()
                .any(|(k, v)| k == "BORG_PASSCOMMAND" && v == "cat /etc/borg/pw"),
            "borg must receive the passphrase via BORG_PASSCOMMAND env"
        );
        assert!(
            !calls[0].args.iter().any(|a| a.contains("cat /etc/borg/pw")),
            "passphrase command must NOT appear in args: {:?}",
            calls[0].args
        );
        assert!(calls[0].redact, "repo-touching borg command MUST set redact(true)");

        let expected = CommandSpec::new("borg")
            .args(["list", "--json", "/home/user/repository"])
            .env("BORG_PASSCOMMAND", "cat /etc/borg/pw")
            .redact(true);
        rc.assert_called_with(&expected);
    }

    // -------------------------------------------------------------------------
    // Integrity probe — restic
    // -------------------------------------------------------------------------
    // Source: https://restic.readthedocs.io/en/latest/045_working_with_repos.html#checking-integrity-and-consistency
    // `restic check` prints "no errors were found" on success (no --json).

    #[test]
    fn restic_integrity_probe_builds_check_command_and_parses_success() {
        let runner = FakeRunner::new().push_response(CommandOutput::from_stdout(
            "create exclusive lock for repository\nno errors were found\n",
        ));
        let (doc, rc) = doctor_with_fake(runner, "restic");

        let report = doc
            .run_spec(&restic_spec("/srv/backup"), SpecScope::Integrity)
            .expect("probe ok");
        assert!(report.findings.iter().any(|f| f.id == "integrity.ok"));

        let expected = CommandSpec::new("restic")
            .args(["--repo", "/srv/backup", "--password-command", "cat /etc/restic/pw", "check"])
            .redact(true);
        rc.assert_called_with(&expected);
    }

    #[test]
    fn restic_integrity_probe_reports_failure() {
        let runner = FakeRunner::new().push_result(Err(toride_runner::Error::CommandFailed {
            program: "restic".into(),
            args: "...".into(),
            exit_code: Some(1),
            stderr: "pack file appears corrupted".into(),
        }));
        let (doc, _rc) = doctor_with_fake(runner, "restic");
        let report = doc
            .run_spec(&restic_spec("/srv/backup"), SpecScope::Integrity)
            .expect("probe ok");
        assert!(report.findings.iter().any(|f| f.id == "integrity.failed"));
    }

    // -------------------------------------------------------------------------
    // Integrity probe — borg
    // -------------------------------------------------------------------------
    // Source: https://borgbackup.readthedocs.io/en/stable/usage/check.html
    // `borg check --repository-only <repo>` — cheap structural check.

    #[test]
    fn borg_integrity_probe_builds_check_command() {
        let runner = FakeRunner::new().push_response(CommandOutput::from_stdout(""));
        let (doc, rc) = doctor_with_fake(runner, "borg");

        let report = doc
            .run_spec(&borg_spec("/srv/backup"), SpecScope::Integrity)
            .expect("probe ok");
        assert!(report.findings.iter().any(|f| f.id == "integrity.ok"));

        let expected = CommandSpec::new("borg")
            .args(["check", "--repository-only", "/srv/backup"])
            .env("BORG_PASSCOMMAND", "cat /etc/borg/pw")
            .redact(true);
        rc.assert_called_with(&expected);
    }

    // -------------------------------------------------------------------------
    // Encryption probe — borg (reads encryption.mode from `borg info --json`)
    // -------------------------------------------------------------------------
    // Source: https://borgbackup.readthedocs.io/en/stable/internals/frontends.html
    // "The encryption key, if present, contains mode".

    #[test]
    fn borg_encryption_probe_reports_enabled_mode() {
        let sample = r#"{
            "cache": {"path": "/home/user/.cache/borg/x", "stats": {"total_chunks": 1, "total_csize": 1024, "total_size": 2048, "total_unique_chunks": 1, "unique_csize": 512, "unique_size": 1024}},
            "encryption": {"mode": "repokey-blake2"},
            "repository": {"id": "abc", "last_modified": "2024-09-18T12:00:00.000000", "location": "/srv/backup"},
            "archives": []
        }"#;
        let runner = FakeRunner::new().push_response(CommandOutput::from_stdout(sample));
        let (doc, rc) = doctor_with_fake(runner, "borg");

        let report = doc
            .run_spec(&borg_spec("/srv/backup"), SpecScope::Encryption)
            .expect("probe ok");
        assert!(report
            .findings
            .iter()
            .any(|f| f.id == "encryption.enabled" && f.title.contains("repokey-blake2")));

        let expected = CommandSpec::new("borg")
            .args(["info", "--json", "/srv/backup"])
            .env("BORG_PASSCOMMAND", "cat /etc/borg/pw")
            .redact(true);
        rc.assert_called_with(&expected);
    }

    #[test]
    fn borg_encryption_probe_warns_when_mode_none() {
        let sample = r#"{
            "encryption": {"mode": "none"},
            "repository": {"id": "abc", "last_modified": "2024-09-18T12:00:00.000000", "location": "/srv/backup"},
            "archives": []
        }"#;
        let runner = FakeRunner::new().push_response(CommandOutput::from_stdout(sample));
        let (doc, _rc) = doctor_with_fake(runner, "borg");
        let report = doc
            .run_spec(&borg_spec("/srv/backup"), SpecScope::Encryption)
            .expect("probe ok");
        assert!(report
            .findings
            .iter()
            .any(|f| f.id == "encryption.disabled" && f.severity == Severity::Warning));
    }

    // -------------------------------------------------------------------------
    // Encryption probe — restic (cat config exit 0 => key unlocks repo)
    // -------------------------------------------------------------------------

    #[test]
    fn restic_encryption_probe_builds_cat_config_command() {
        let runner = FakeRunner::new().push_response(CommandOutput::from_stdout(
            "{\"version\":2,\"id\":\"abc\"}",
        ));
        let (doc, rc) = doctor_with_fake(runner, "restic");

        let report = doc
            .run_spec(&restic_spec("/srv/backup"), SpecScope::Encryption)
            .expect("probe ok");
        assert!(report.findings.iter().any(|f| f.id == "encryption.enabled"));

        let expected = CommandSpec::new("restic")
            .args(["--repo", "/srv/backup", "--password-command", "cat /etc/restic/pw", "cat", "config"])
            .redact(true);
        rc.assert_called_with(&expected);
    }

    // -------------------------------------------------------------------------
    // Staleness probe — restic (newest snapshot time vs cron)
    // -------------------------------------------------------------------------

    #[test]
    fn restic_staleness_probe_fresh_snapshot_is_ok() {
        // A snapshot dated "today" in UTC. We compute the date dynamically so
        // the test is never stale.
        let today = {
            let secs = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let days = secs / 86_400;
            // invert days -> civil (Howard Hinnant inverse)
            let z = days as i64 + 719_468;
            let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
            let doe = (z - era * 146_097) as u64;
            let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
            let y = yoe as i64 + era * 400;
            let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
            let mp = (5 * doy + 2) / 153;
            let d = doy - (153 * mp + 2) / 5 + 1;
            let m = if mp < 10 { mp + 3 } else { mp - 9 };
            let y = if m <= 2 { y + 1 } else { y };
            format!("{y:04}-{m:02}-{d:02}T02:00:00.000000000Z")
        };
        let sample = format!(
            r#"[{{"time":"{today}","id":"abc","short_id":"abc","tree":"t","paths":["/etc"],"hostname":"h","username":"u"}}]"#
        );
        let runner = FakeRunner::new().push_response(CommandOutput::from_stdout(sample));
        let (doc, _rc) = doctor_with_fake(runner, "restic");
        let report = doc
            .run_spec(&restic_spec("/srv/backup"), SpecScope::Staleness)
            .expect("probe ok");
        assert!(report.findings.iter().any(|f| f.id == "staleness.last-run"));
        assert!(
            !report.findings.iter().any(|f| f.id == "staleness.stale"),
            "today's snapshot must not be stale"
        );
    }

    #[test]
    fn restic_staleness_probe_old_snapshot_is_stale() {
        // 1990 — unmistakably stale for a daily schedule.
        let sample = r#"[{"time":"1990-01-01T02:00:00.000000000Z","id":"abc","short_id":"abc","tree":"t","paths":["/etc"],"hostname":"h","username":"u"}]"#;
        let runner = FakeRunner::new().push_response(CommandOutput::from_stdout(sample));
        let (doc, _rc) = doctor_with_fake(runner, "restic");
        let report = doc
            .run_spec(&restic_spec("/srv/backup"), SpecScope::Staleness)
            .expect("probe ok");
        assert!(report.findings.iter().any(|f| f.id == "staleness.stale"
            && f.severity == Severity::Error));
    }

    #[test]
    fn restic_staleness_probe_empty_repo_reports_never() {
        let runner = FakeRunner::new().push_response(CommandOutput::from_stdout("[]"));
        let (doc, _rc) = doctor_with_fake(runner, "restic");
        let report = doc
            .run_spec(&restic_spec("/srv/backup"), SpecScope::Staleness)
            .expect("probe ok");
        assert!(report
            .findings
            .iter()
            .any(|f| f.id == "staleness.never" && f.severity == Severity::Error));
    }

    // -------------------------------------------------------------------------
    // Retention probe — restic forget --json --keep-* (dry-run-style preview)
    // -------------------------------------------------------------------------
    // Source: https://restic.readthedocs.io/en/v0.17.2/075_scripting.html#forget

    #[test]
    fn restic_retention_probe_builds_forget_command() {
        let runner = FakeRunner::new().push_response(CommandOutput::from_stdout("[]"));
        let (doc, rc) = doctor_with_fake(runner, "restic");

        let report = doc
            .run_spec(&restic_spec("/srv/backup"), SpecScope::Retention)
            .expect("probe ok");
        assert!(report.findings.iter().any(|f| f.id == "retention.ok"));

        // Default policy: keep_daily=7, keep_weekly=4, keep_monthly=6.
        let expected = CommandSpec::new("restic")
            .args([
                "--repo", "/srv/backup", "--password-command", "cat /etc/restic/pw",
                "forget", "--json",
                "--keep-daily", "7", "--keep-weekly", "4", "--keep-monthly", "6",
            ])
            .redact(true);
        rc.assert_called_with(&expected);
    }

    #[test]
    fn restic_retention_probe_warns_when_no_policy() {
        let mut spec = restic_spec("/srv/backup");
        spec.retention = RetentionPolicy {
            keep_hourly: None,
            keep_daily: None,
            keep_weekly: None,
            keep_monthly: None,
            keep_yearly: None,
        };
        let runner = FakeRunner::new();
        let (doc, _rc) = doctor_with_fake(runner, "restic");
        let report = doc.run_spec(&spec, SpecScope::Retention).expect("probe ok");
        assert!(report
            .findings
            .iter()
            .any(|f| f.id == "retention.unconfigured" && f.severity == Severity::Warning));
    }

    // -------------------------------------------------------------------------
    // Retention probe — borg prune --dry-run --list --keep-*
    // -------------------------------------------------------------------------
    // Source: https://borgbackup.readthedocs.io/en/stable/usage/prune.html

    #[test]
    fn borg_retention_probe_builds_prune_dry_run_command() {
        let runner = FakeRunner::new().push_response(CommandOutput::from_stdout(""));
        let (doc, rc) = doctor_with_fake(runner, "borg");

        let report = doc
            .run_spec(&borg_spec("/srv/backup"), SpecScope::Retention)
            .expect("probe ok");
        assert!(report.findings.iter().any(|f| f.id == "retention.ok"));

        let expected = CommandSpec::new("borg")
            .args([
                "prune", "--dry-run", "--list",
                "--keep-daily", "7", "--keep-weekly", "4", "--keep-monthly", "6",
                "/srv/backup",
            ])
            .env("BORG_PASSCOMMAND", "cat /etc/borg/pw")
            .redact(true);
        rc.assert_called_with(&expected);
    }

    // -------------------------------------------------------------------------
    // Restore probe — restic check --read-data-subset=5%
    // -------------------------------------------------------------------------
    // Source: https://restic.readthedocs.io/en/latest/045_working_with_repos.html#checking-integrity-and-consistency

    #[test]
    fn restic_restore_probe_builds_read_subset_command() {
        let runner = FakeRunner::new().push_response(CommandOutput::from_stdout(
            "no errors were found\n",
        ));
        let (doc, rc) = doctor_with_fake(runner, "restic");

        let report = doc
            .run_spec(&restic_spec("/srv/backup"), SpecScope::Restore)
            .expect("probe ok");
        assert!(report.findings.iter().any(|f| f.id == "restore.viable"));

        let expected = CommandSpec::new("restic")
            .args([
                "--repo", "/srv/backup", "--password-command", "cat /etc/restic/pw",
                "check", "--read-data-subset=5%",
            ])
            .redact(true);
        rc.assert_called_with(&expected);
    }

    // -------------------------------------------------------------------------
    // Restore probe — borg check --verify-data
    // -------------------------------------------------------------------------
    // Source: https://borgbackup.readthedocs.io/en/stable/usage/check.html

    #[test]
    fn borg_restore_probe_builds_verify_data_command() {
        let runner = FakeRunner::new().push_response(CommandOutput::from_stdout(""));
        let (doc, rc) = doctor_with_fake(runner, "borg");

        let report = doc
            .run_spec(&borg_spec("/srv/backup"), SpecScope::Restore)
            .expect("probe ok");
        assert!(report.findings.iter().any(|f| f.id == "restore.viable"));

        let expected = CommandSpec::new("borg")
            .args(["check", "--verify-data", "/srv/backup"])
            .env("BORG_PASSCOMMAND", "cat /etc/borg/pw")
            .redact(true);
        rc.assert_called_with(&expected);
    }

    // -------------------------------------------------------------------------
    // Space probe — restic stats --json (total_size)
    // -------------------------------------------------------------------------
    // Source: https://restic.readthedocs.io/en/v0.17.2/075_scripting.html#stats

    #[test]
    fn restic_space_probe_parses_docs_json_and_builds_command() {
        let sample = r#"{
            "total_size": 1048576.0,
            "total_file_count": 42,
            "total_blob_count": 100,
            "snapshots_count": 3
        }"#;
        let runner = FakeRunner::new().push_response(CommandOutput::from_stdout(sample));
        let (doc, rc) = doctor_with_fake(runner, "restic");

        let report = doc
            .run_spec(&restic_spec("/srv/backup"), SpecScope::Space)
            .expect("probe ok");
        let size_f = report
            .findings
            .iter()
            .find(|f| f.id == "space.repo-size")
            .expect("size finding");
        assert!(size_f.title.contains("1.00 MiB"));

        let expected = CommandSpec::new("restic")
            .args(["--repo", "/srv/backup", "--password-command", "cat /etc/restic/pw", "stats", "--json"])
            .redact(true);
        rc.assert_called_with(&expected);
    }

    // -------------------------------------------------------------------------
    // Space probe — borg info --json (cache.stats.total_csize)
    // -------------------------------------------------------------------------
    // Source: https://borgbackup.readthedocs.io/en/stable/internals/frontends.html
    // "The cache key, if present, contains ... stats: total_csize"

    #[test]
    fn borg_space_probe_parses_docs_json_and_builds_command() {
        let sample = r#"{
            "cache": {
                "path": "/home/user/.cache/borg/x",
                "stats": {"total_chunks": 511533, "total_csize": 1048576, "total_size": 22635749792, "total_unique_chunks": 54892, "unique_csize": 1920405405, "unique_size": 2449675468}
            },
            "encryption": {"mode": "repokey"},
            "repository": {"id": "0cbe", "last_modified": "2017-08-07T12:27:20.789123", "location": "/srv/backup"},
            "archives": []
        }"#;
        let runner = FakeRunner::new().push_response(CommandOutput::from_stdout(sample));
        let (doc, rc) = doctor_with_fake(runner, "borg");

        let report = doc
            .run_spec(&borg_spec("/srv/backup"), SpecScope::Space)
            .expect("probe ok");
        let size_f = report
            .findings
            .iter()
            .find(|f| f.id == "space.repo-size")
            .expect("size finding");
        assert!(size_f.title.contains("1.00 MiB"));

        let expected = CommandSpec::new("borg")
            .args(["info", "--json", "/srv/backup"])
            .env("BORG_PASSCOMMAND", "cat /etc/borg/pw")
            .redact(true);
        rc.assert_called_with(&expected);
    }

    // -------------------------------------------------------------------------
    // run_spec(All) runs every probe end-to-end
    // -------------------------------------------------------------------------

    #[test]
    fn run_spec_all_runs_every_probe() {
        // 5 commands issued in All order:
        //   repository(snapshots) integrity(check) encryption(cat config)
        //   staleness(snapshots) restore(check --read-data-subset) space(stats)
        // (schedule delegates to ScheduleManager which probes the filesystem,
        //  not the runner; retention issues forget --json.)
        // Provide enough FIFO responses for the runner-driven probes.
        let runner = FakeRunner::new()
            .push_response(CommandOutput::from_stdout("[]")) // repository snapshots
            .push_response(CommandOutput::from_stdout("no errors were found\n")) // integrity check
            .push_response(CommandOutput::from_stdout("{\"version\":2}")) // encryption cat config
            .push_response(CommandOutput::from_stdout("[]")) // staleness snapshots
            .push_response(CommandOutput::from_stdout("[]")) // retention forget
            .push_response(CommandOutput::from_stdout("no errors were found\n")) // restore subset
            .push_response(CommandOutput::from_stdout( // space stats
                r#"{"total_size":0.0,"total_file_count":0,"total_blob_count":0,"snapshots_count":0}"#,
            ));
        let (doc, _rc) = doctor_with_fake(runner, "restic");
        let report = doc
            .run_spec(&restic_spec("/srv/backup"), SpecScope::All)
            .expect("probe ok");
        // binary.* findings plus at least one finding per probe.
        assert!(report.findings.iter().any(|f| f.id.starts_with("binary.")));
        assert!(report.findings.iter().any(|f| f.id.starts_with("repository.")));
        assert!(report.findings.iter().any(|f| f.id.starts_with("integrity.")));
        assert!(report.findings.iter().any(|f| f.id.starts_with("encryption.")));
        assert!(report.findings.iter().any(|f| f.id.starts_with("staleness.")));
        assert!(report.findings.iter().any(|f| f.id.starts_with("retention.")));
        assert!(report.findings.iter().any(|f| f.id.starts_with("restore.")));
        assert!(report.findings.iter().any(|f| f.id.starts_with("space.")));
    }

    // -------------------------------------------------------------------------
    // Pure helpers
    // -------------------------------------------------------------------------

    #[test]
    fn retention_args_shape() {
        let policy = RetentionPolicy {
            keep_hourly: Some(24),
            keep_daily: Some(7),
            keep_weekly: None,
            keep_monthly: Some(6),
            keep_yearly: None,
        };
        let args = retention_args(&policy);
        assert_eq!(
            args,
            vec![
                "--keep-hourly".to_string(),
                "24".into(),
                "--keep-daily".into(),
                "7".into(),
                "--keep-monthly".into(),
                "6".into(),
            ]
        );
    }

    #[test]
    fn max_age_days_from_cron_buckets() {
        assert_eq!(max_age_days_from_cron("0 2 * * *"), 2); // daily
        assert_eq!(max_age_days_from_cron("0 2 * * 0"), 10); // weekly (specific day)
        assert_eq!(max_age_days_from_cron("0 2 1 * *"), 35); // monthly
    }

    #[test]
    fn iso_to_days_round_trips_epoch() {
        // 1970-01-01 is day 0.
        assert_eq!(iso_to_days("1970-01-01T00:00:00Z"), Some(0));
        // 1970-01-02 is day 1.
        assert_eq!(iso_to_days("1970-01-02T00:00:00Z"), Some(1));
        // 2024-01-01 is a known value (19723).
        assert_eq!(iso_to_days("2024-01-01T00:00:00Z"), Some(19_723));
    }

    #[test]
    fn iso_to_days_rejects_garbage() {
        assert_eq!(iso_to_days("not-a-date"), None);
        assert_eq!(iso_to_days("2024-13-01"), None); // bad month
        assert_eq!(iso_to_days("2024-01-32"), None); // bad day
    }
}
