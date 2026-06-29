//! Diagnostic types and doctor commands for the toride-mise crate.
//!
//! This module provides:
//!
//! - [`Diagnostic`] and [`DiagnosticKind`] for classifying mise health issues.
//! - [`DoctorReport`] summarising the result of a `mise doctor` invocation.
//! - Trust-management methods ([`Mise::doctor`], [`Mise::doctor_path`],
//!   [`Mise::trust`], [`Mise::untrust`]) on the [`Mise`](crate::Mise) client.
//!
//! # Example
//!
//! ```rust,ignore
//! use toride_mise::Mise;
//!
//! let mise = Mise::builder().build()?;
//! let report = mise.doctor().await?;
//! if report.ok {
//!     println!("mise is healthy");
//! } else {
//!     for err in &report.errors {
//!         eprintln!("error: {err}");
//!     }
//! }
//! ```

use crate::client::Mise;
use crate::error::MiseResult;

// ---------------------------------------------------------------------------
// DiagnosticKind
// ---------------------------------------------------------------------------

/// Classification of a mise diagnostic finding.
///
/// Each variant maps to a category of issue that `mise doctor` (or related
/// commands) can surface.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DiagnosticKind {
    /// The `mise` binary cannot be found on `$PATH`.
    BinaryMissing,
    /// The installed mise version is too old (or too new) to be supported.
    VersionUnsupported,
    /// A required directory or file path does not exist.
    PathMissing,
    /// A mise configuration file could not be located.
    ConfigNotFound,
    /// A configuration file has not been trusted.
    ConfigUntrusted,
    /// The mise lockfile is missing.
    LockfileMissing,
    /// One or more declared tools are not installed.
    MissingTools,
    /// One or more installed tools are out of date.
    OutdatedTools,
    /// A configuration value is syntactically or semantically invalid.
    InvalidConfig,
    /// A network issue prevented an operation.
    NetworkIssue,
    /// A filesystem permission issue was detected.
    PermissionIssue,
    /// An issue that does not fit any of the above categories.
    Other,
}

// ---------------------------------------------------------------------------
// Diagnostic
// ---------------------------------------------------------------------------

/// A single diagnostic finding from a mise health check.
///
/// Combines a [`DiagnosticKind`] classification with a human-readable message
/// and an optional detail string.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Diagnostic {
    /// What kind of issue was found.
    pub kind: DiagnosticKind,
    /// A short, human-readable description of the issue.
    pub message: String,
    /// Optional additional context or remediation hint.
    pub detail: Option<String>,
}

impl Diagnostic {
    /// Create a new diagnostic with the given kind and message.
    pub fn new(kind: DiagnosticKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            detail: None,
        }
    }

    /// Attach additional detail to this diagnostic.
    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }
}

impl std::fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", kind_label(&self.kind), self.message)?;
        if let Some(ref detail) = self.detail {
            write!(f, "\n  {detail}")?;
        }
        Ok(())
    }
}

/// Return a short label for a [`DiagnosticKind`], suitable for display.
fn kind_label(kind: &DiagnosticKind) -> &'static str {
    match kind {
        DiagnosticKind::BinaryMissing => "BINARY_MISSING",
        DiagnosticKind::VersionUnsupported => "VERSION_UNSUPPORTED",
        DiagnosticKind::PathMissing => "PATH_MISSING",
        DiagnosticKind::ConfigNotFound => "CONFIG_NOT_FOUND",
        DiagnosticKind::ConfigUntrusted => "CONFIG_UNTRUSTED",
        DiagnosticKind::LockfileMissing => "LOCKFILE_MISSING",
        DiagnosticKind::MissingTools => "MISSING_TOOLS",
        DiagnosticKind::OutdatedTools => "OUTDATED_TOOLS",
        DiagnosticKind::InvalidConfig => "INVALID_CONFIG",
        DiagnosticKind::NetworkIssue => "NETWORK_ISSUE",
        DiagnosticKind::PermissionIssue => "PERMISSION_ISSUE",
        DiagnosticKind::Other => "OTHER",
    }
}

// ---------------------------------------------------------------------------
// DoctorReport
// ---------------------------------------------------------------------------

/// The result of running `mise doctor`.
///
/// Summarises overall health (`ok`), the raw command output, and any warnings
/// or errors parsed from the output.
#[derive(Debug, Clone)]
pub struct DoctorReport {
    /// `true` when no errors were found; `false` otherwise.
    pub ok: bool,
    /// The raw stdout from `mise doctor`.
    pub raw_output: String,
    /// Non-fatal issues reported by mise.
    pub warnings: Vec<Diagnostic>,
    /// Fatal or blocking issues reported by mise.
    pub errors: Vec<Diagnostic>,
}

impl DoctorReport {
    /// Return `true` if there are no warnings and no errors.
    pub fn is_clean(&self) -> bool {
        self.warnings.is_empty() && self.errors.is_empty()
    }

    /// Return an iterator over all diagnostics (warnings then errors).
    pub fn all_diagnostics(&self) -> impl Iterator<Item = &Diagnostic> {
        self.warnings.iter().chain(self.errors.iter())
    }

    /// Build a [`DoctorReport`] from a parsed [`DoctorOutput`](crate::serde_utils::json_outputs::DoctorOutput).
    fn from_json(parsed: &crate::serde_utils::json_outputs::DoctorOutput, raw: String) -> Self {
        let mut warnings = Vec::new();
        let mut errors = Vec::new();

        // Convert top-level warnings to diagnostics.
        if let Some(ref warns) = parsed.warnings {
            for w in warns {
                warnings.push(Diagnostic::new(DiagnosticKind::Other, w));
            }
        }

        // Extract errors from the doctor output if present.
        // DoctorOutput currently uses warnings only; if a future version adds
        // an `errors` field we will pick it up here. For now, classify warnings
        // that contain error-like patterns as errors instead.
        if let Some(ref warns) = parsed.warnings {
            for w in warns {
                let lower = w.to_ascii_lowercase();
                if lower.contains("error") || lower.contains("failed") || lower.contains("fatal") {
                    errors.push(Diagnostic::new(DiagnosticKind::Other, w));
                }
            }
        }

        let ok = errors.is_empty();
        Self {
            ok,
            raw_output: raw,
            warnings,
            errors,
        }
    }
}

// ---------------------------------------------------------------------------
// DiagnosticsBuilder
// ---------------------------------------------------------------------------

/// Fluent builder for running a selective set of diagnostic checks against a
/// [`Mise`] client.
///
/// Construct via [`Mise::diagnostics`], chain `check_*` methods to select
/// which checks to run, then call [`DiagnosticsBuilder::run`] to execute them
/// all and produce a [`DoctorReport`].
///
/// # Example
///
/// ```rust,ignore
/// let report = mise.diagnostics()
///     .check_binary()
///     .check_missing_tools()
///     .check_outdated()
///     .run()
///     .await?;
/// ```
pub struct DiagnosticsBuilder<'a> {
    mise: &'a Mise,
    checks: Vec<DiagnosticKind>,
}

impl<'a> DiagnosticsBuilder<'a> {
    /// Create a new builder borrowing the given [`Mise`] client.
    pub(crate) fn new(mise: &'a Mise) -> Self {
        Self {
            mise,
            checks: Vec::new(),
        }
    }

    /// Check that the `mise` binary is present on `$PATH`.
    pub fn check_binary(mut self) -> Self {
        self.checks.push(DiagnosticKind::BinaryMissing);
        self
    }

    /// Check that the mise configuration files can be located and parsed.
    pub fn check_config(mut self) -> Self {
        self.checks.push(DiagnosticKind::ConfigNotFound);
        self
    }

    /// Check that all declared tools are installed.
    pub fn check_missing_tools(mut self) -> Self {
        self.checks.push(DiagnosticKind::MissingTools);
        self
    }

    /// Check that no installed tools are outdated.
    pub fn check_outdated(mut self) -> Self {
        self.checks.push(DiagnosticKind::OutdatedTools);
        self
    }

    /// Check that the lockfile exists and is valid.
    pub fn check_lockfile(mut self) -> Self {
        self.checks.push(DiagnosticKind::LockfileMissing);
        self
    }

    /// Check that the installed mise version is supported.
    pub fn check_version(mut self) -> Self {
        self.checks.push(DiagnosticKind::VersionUnsupported);
        self
    }

    /// Execute the selected checks and return a combined [`DoctorReport`].
    ///
    /// Each selected check is run in order. If no checks were selected, this
    /// runs `mise doctor` as a fallback and returns the parsed report.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError`] if any underlying mise command fails in a way
    /// that prevents building the report.
    #[allow(clippy::too_many_lines)]
    pub async fn run(self) -> MiseResult<DoctorReport> {
        // If no specific checks were selected, fall back to `mise doctor`.
        if self.checks.is_empty() {
            return self.mise.doctor().await;
        }

        let mut warnings = Vec::new();
        let mut errors = Vec::new();

        for kind in &self.checks {
            match kind {
                DiagnosticKind::BinaryMissing => {
                    // Try discovering the binary.
                    if Mise::discover().is_err() {
                        errors.push(Diagnostic::new(
                            DiagnosticKind::BinaryMissing,
                            "mise binary not found on PATH",
                        ).with_detail("Install mise via your package manager or run `mise --version` to verify"));
                    }
                }
                DiagnosticKind::VersionUnsupported => {
                    // Try reading the version.
                    match self.mise.version_json().await {
                        Ok(v) => {
                            let parsed = crate::binary::MiseVersion::parse(
                                v.version.as_deref().unwrap_or("0.0.0"),
                            );
                            if !parsed.is_at_least(&semver::Version::new(2024, 1, 0)) {
                                warnings.push(Diagnostic::new(
                                    DiagnosticKind::VersionUnsupported,
                                    format!("mise version {} may be too old", parsed.raw),
                                ));
                            }
                        }
                        Err(e) => {
                            errors.push(Diagnostic::new(
                                DiagnosticKind::VersionUnsupported,
                                format!("failed to query mise version: {e}"),
                            ));
                        }
                    }
                }
                DiagnosticKind::MissingTools => match self.mise.list_missing().await {
                    Ok(tools) => {
                        for tool in &tools {
                            warnings.push(Diagnostic::new(
                                DiagnosticKind::MissingTools,
                                format!("tool `{}` is referenced but not installed", tool.name),
                            ));
                        }
                    }
                    Err(e) => {
                        errors.push(Diagnostic::new(
                            DiagnosticKind::MissingTools,
                            format!("failed to list missing tools: {e}"),
                        ));
                    }
                },
                DiagnosticKind::OutdatedTools => match self.mise.list_outdated().await {
                    Ok(tools) => {
                        for tool in &tools {
                            warnings.push(Diagnostic::new(
                                DiagnosticKind::OutdatedTools,
                                format!("tool `{}` has an update available", tool.name),
                            ));
                        }
                    }
                    Err(e) => {
                        errors.push(Diagnostic::new(
                            DiagnosticKind::OutdatedTools,
                            format!("failed to list outdated tools: {e}"),
                        ));
                    }
                },
                DiagnosticKind::LockfileMissing => {
                    // Check if .mise.lock or mise.lock exists in cwd.
                    // Fall back to std::env::current_dir() when no cwd is configured.
                    let cwd = self.mise.cwd.clone().or_else(|| {
                        std::env::current_dir()
                            .ok()
                            .and_then(|p| camino::Utf8PathBuf::from_path_buf(p).ok())
                    });
                    let has_lockfile = cwd.as_ref().is_some_and(|cwd| {
                        cwd.join(".mise.lock").is_file() || cwd.join("mise.lock").is_file()
                    });
                    if !has_lockfile {
                        warnings.push(
                            Diagnostic::new(
                                DiagnosticKind::LockfileMissing,
                                "no lockfile found in project directory",
                            )
                            .with_detail("Run `mise lock` to generate one"),
                        );
                    }
                }
                DiagnosticKind::ConfigNotFound => match self.mise.config_path().await {
                    Ok(path) => {
                        if !path.as_std_path().exists() {
                            warnings.push(Diagnostic::new(
                                DiagnosticKind::ConfigNotFound,
                                format!("config file not found at {path}"),
                            ));
                        }
                    }
                    Err(e) => {
                        errors.push(Diagnostic::new(
                            DiagnosticKind::ConfigNotFound,
                            format!("failed to locate config: {e}"),
                        ));
                    }
                },
                _ => {
                    // For unrecognised checks, just run doctor and extract.
                    let report = self.mise.doctor().await?;
                    warnings.extend(report.warnings);
                    errors.extend(report.errors);
                }
            }
        }

        let ok = errors.is_empty();
        Ok(DoctorReport {
            ok,
            raw_output: String::new(),
            warnings,
            errors,
        })
    }
}

// ---------------------------------------------------------------------------
// Parsing helpers
// ---------------------------------------------------------------------------

/// Parse the raw `mise doctor` output into a structured [`DoctorReport`].
///
/// The parser looks for common mise warning/error line patterns. Lines that
/// are not recognised are ignored (they still appear in `raw_output`).
fn parse_doctor_output(raw: String) -> DoctorReport {
    let mut warnings = Vec::new();
    let mut errors = Vec::new();

    for line in raw.lines() {
        let trimmed = line.trim();

        // Error lines: "ERROR ..." or "error: ..."
        if let Some(rest) = trimmed
            .strip_prefix("ERROR ")
            .or_else(|| trimmed.strip_prefix("error: "))
        {
            errors.push(classify_line(rest.trim()));
            continue;
        }

        // Warning lines: "WARN ..." or "warning: ..."
        if let Some(rest) = trimmed
            .strip_prefix("WARN ")
            .or_else(|| trimmed.strip_prefix("warning: "))
        {
            warnings.push(classify_line(rest.trim()));
        }
    }

    let ok = errors.is_empty();
    DoctorReport {
        ok,
        raw_output: raw,
        warnings,
        errors,
    }
}

/// Classify a single mise output line into a [`Diagnostic`].
fn classify_line(text: &str) -> Diagnostic {
    let lower = text.to_ascii_lowercase();

    let kind = if lower.contains("binary not found")
        || lower.contains("mise not found")
        || lower.contains("no such file")
        || lower.contains("command not found")
    {
        DiagnosticKind::BinaryMissing
    } else if lower.contains("unsupported version")
        || lower.contains("version")
            && (lower.contains("too old") || lower.contains("not supported"))
    {
        DiagnosticKind::VersionUnsupported
    } else if lower.contains("path")
        && (lower.contains("not found") || lower.contains("does not exist"))
    {
        DiagnosticKind::PathMissing
    } else if lower.contains("config") && lower.contains("not found") {
        DiagnosticKind::ConfigNotFound
    } else if lower.contains("untrusted")
        || lower.contains("not trusted")
        || lower.contains("trust")
    {
        DiagnosticKind::ConfigUntrusted
    } else if lower.contains("lockfile") && lower.contains("missing") {
        DiagnosticKind::LockfileMissing
    } else if lower.contains("missing tool") || lower.contains("not installed") {
        DiagnosticKind::MissingTools
    } else if lower.contains("outdated") || lower.contains("update available") {
        DiagnosticKind::OutdatedTools
    } else if lower.contains("invalid config")
        || lower.contains("parse error")
        || lower.contains("syntax error")
    {
        DiagnosticKind::InvalidConfig
    } else if lower.contains("network")
        || lower.contains("timeout")
        || lower.contains("connection")
        || lower.contains("fetch")
    {
        DiagnosticKind::NetworkIssue
    } else if lower.contains("permission") || lower.contains("denied") || lower.contains("eacces") {
        DiagnosticKind::PermissionIssue
    } else {
        DiagnosticKind::Other
    };

    Diagnostic::new(kind, text)
}

// ---------------------------------------------------------------------------
// Mise impl — doctor & trust methods
// ---------------------------------------------------------------------------

impl Mise {
    /// Run `mise doctor` and return a parsed report.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`] if the command exits non-zero in a
    /// way that does not produce output.
    /// Returns [`MiseError::BinaryNotFound`] if the binary cannot be found.
    pub async fn doctor(&self) -> MiseResult<DoctorReport> {
        // Try JSON first, fall back to text parsing.
        // `mise doctor --json` may not be supported in all versions, so we
        // gracefully fall back to text parsing if JSON fails.
        let json_output = self.run(["doctor", "--json"]).await;
        match json_output {
            Ok(output) if !output.stdout_trimmed().is_empty() => {
                let raw = output.stdout_trimmed();
                // Try parsing as JSON DoctorOutput first.
                if let Ok(parsed) =
                    serde_json::from_str::<crate::serde_utils::json_outputs::DoctorOutput>(raw)
                {
                    return Ok(DoctorReport::from_json(&parsed, raw.to_owned()));
                }
                // If JSON parse fails, fall through to text parsing.
                Ok(parse_doctor_output(raw.to_owned()))
            }
            _ => {
                // JSON path failed; use plain text.
                let output = self.run(["doctor"]).await?;
                let raw = output.stdout_trimmed().to_owned();
                Ok(parse_doctor_output(raw))
            }
        }
    }

    /// Run `mise doctor --path` and return the raw output without parsing.
    ///
    /// Useful when the caller wants to inspect the full text directly.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::BinaryNotFound`] if the binary cannot be found.
    pub async fn doctor_path(&self) -> MiseResult<String> {
        let output = self.run(["doctor", "--path"]).await?;
        Ok(output.stdout_trimmed().to_owned())
    }

    /// Trust a config file at the given path.
    ///
    /// Runs `mise trust <path>`.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`] if the command exits non-zero.
    /// Returns [`MiseError::BinaryNotFound`] if the binary cannot be found.
    pub async fn trust(&self, path: impl AsRef<str>) -> MiseResult<()> {
        self.run_checked(["trust", path.as_ref()]).await?;
        Ok(())
    }

    /// Remove trust for a config file at the given path.
    ///
    /// Runs `mise trust --untrust <path>`.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`] if the command exits non-zero.
    /// Returns [`MiseError::BinaryNotFound`] if the binary cannot be found.
    pub async fn untrust(&self, path: impl AsRef<str>) -> MiseResult<()> {
        self.run_checked(["trust", "--untrust", path.as_ref()])
            .await?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_empty_output() {
        let report = parse_doctor_output(String::new());
        assert!(report.ok);
        assert!(report.warnings.is_empty());
        assert!(report.errors.is_empty());
        assert!(report.is_clean());
    }

    #[test]
    fn parse_error_lines() {
        let raw =
            "ERROR mise not found on PATH\nSome info line\nerror: config not found at .mise.toml\n"
                .to_owned();
        let report = parse_doctor_output(raw);
        assert!(!report.ok);
        assert!(report.warnings.is_empty());
        assert_eq!(report.errors.len(), 2);
        assert_eq!(report.errors[0].kind, DiagnosticKind::BinaryMissing);
        assert_eq!(report.errors[1].kind, DiagnosticKind::ConfigNotFound);
    }

    #[test]
    fn parse_warning_lines() {
        let raw = "WARN outdated: node@18.0.0\nwarning: permission denied on /tmp\n".to_owned();
        let report = parse_doctor_output(raw);
        assert!(report.ok);
        assert_eq!(report.warnings.len(), 2);
        assert_eq!(report.warnings[0].kind, DiagnosticKind::OutdatedTools);
        assert_eq!(report.warnings[1].kind, DiagnosticKind::PermissionIssue);
    }

    #[test]
    fn parse_mixed_output() {
        let raw = "WARN outdated: python@3.11\nERROR mise not found on PATH\nAll good otherwise\n"
            .to_owned();
        let report = parse_doctor_output(raw);
        assert!(!report.ok);
        assert_eq!(report.warnings.len(), 1);
        assert_eq!(report.errors.len(), 1);
        assert!(!report.is_clean());
        let all: Vec<_> = report.all_diagnostics().collect();
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn diagnostic_display() {
        let d = Diagnostic::new(DiagnosticKind::BinaryMissing, "mise not found")
            .with_detail("Install mise via your package manager");
        let s = d.to_string();
        assert!(s.contains("BINARY_MISSING"));
        assert!(s.contains("mise not found"));
        assert!(s.contains("Install mise via your package manager"));
    }

    #[test]
    fn classify_unknown_as_other() {
        let d = classify_line("something completely unexpected happened");
        assert_eq!(d.kind, DiagnosticKind::Other);
    }
}
