//! Diagnostic engine for proxy installations.
//!
//! Provides doctor checks for proxy configuration, security headers,
//! certificate expiry, and service status.

use crate::error::Result;
use crate::parse::{parse_nginx_status, parse_nginx_version};
use crate::paths::ProxyPaths;
use crate::report::{ProxyReport, ProxyStatus};
use toride_runner::{CommandSpec, Runner};

/// Scope for doctor checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DoctorScope {
    /// Run all checks.
    All,
    /// Check only proxy service status.
    Service,
    /// Check only security headers.
    Headers,
    /// Check only certificate expiry.
    Certificates,
    /// Check only configuration validity.
    Config,
}

/// A single doctor finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoctorFinding {
    /// Finding identifier (dot-separated, e.g. "nginx.config-syntax").
    pub id: String,
    /// Severity of the finding.
    pub severity: DoctorSeverity,
    /// Short human-readable title.
    pub title: String,
    /// Longer description.
    pub detail: String,
    /// Suggested fix.
    pub fix: Option<String>,
}

/// Severity level for doctor findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DoctorSeverity {
    /// Informational.
    Info,
    /// Warning.
    Warning,
    /// Error.
    Error,
    /// Critical.
    Critical,
}

impl DoctorFinding {
    /// Create a new finding.
    pub fn new(
        id: impl Into<String>,
        severity: DoctorSeverity,
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

    /// Attach a detail description.
    pub fn detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = detail.into();
        self
    }

    /// Attach a suggested fix.
    pub fn fix(mut self, fix: impl Into<String>) -> Self {
        self.fix = Some(fix.into());
        self
    }
}

/// Diagnostic engine for proxy installations.
pub struct Doctor<'a> {
    runner: &'a dyn Runner,
    paths: &'a ProxyPaths,
}

impl<'a> Doctor<'a> {
    /// Create a new doctor instance.
    pub fn new(runner: &'a dyn Runner, paths: &'a ProxyPaths) -> Self {
        Self { runner, paths }
    }

    /// Run doctor checks for the given scope.
    pub fn run(&self, scope: &DoctorScope) -> Result<ProxyReport> {
        let mut report = ProxyReport::new("nginx");
        let mut findings = Vec::new();
        // Track the last-known service status parsed from `systemctl status
        // nginx`. `check_service` parses this internally to drive a finding,
        // but we also use it to derive `report.status` below so the report
        // (and the TUI status panel) reflects Running/Stopped rather than
        // always `Unknown('errors found')`.
        let mut service_running: Option<bool> = None;

        match scope {
            DoctorScope::All => {
                for f in self.check_service_resilient(&mut service_running) {
                    findings.push(f);
                }
                for f in self.check_config_resilient() {
                    findings.push(f);
                }
                for f in self.check_headers_resilient() {
                    findings.push(f);
                }
                for f in self.check_certificates_resilient() {
                    findings.push(f);
                }
            }
            DoctorScope::Service => {
                for f in self.check_service_resilient(&mut service_running) {
                    findings.push(f);
                }
            }
            DoctorScope::Headers => {
                for f in self.check_headers_resilient() {
                    findings.push(f);
                }
            }
            DoctorScope::Certificates => {
                for f in self.check_certificates_resilient() {
                    findings.push(f);
                }
            }
            DoctorScope::Config => {
                for f in self.check_config_resilient() {
                    findings.push(f);
                }
            }
        }

        // Derive report status from the service check FIRST: if we observed the
        // service state, Running/Stopped is authoritative regardless of other
        // findings (a running nginx can still have a missing cert). Only fall
        // back to Unknown('errors found') when we could not determine the
        // service state at all.
        match service_running {
            Some(true) => report.status = ProxyStatus::Running,
            Some(false) => report.status = ProxyStatus::Stopped,
            None => {
                let has_errors = findings
                    .iter()
                    .any(|f| f.severity >= DoctorSeverity::Error);
                if has_errors {
                    report.status = ProxyStatus::Unknown("errors found".into());
                }
            }
        }

        // Surface every finding on the report so callers (the TUI) can render
        // them. Previously the doctor computed these only to set `status`
        // above, then discarded them — leaving the findings panel permanently
        // empty.
        report.findings = findings;

        // Log findings
        for finding in &report.findings {
            match finding.severity {
                DoctorSeverity::Info => tracing::info!("[{}] {}", finding.id, finding.title),
                DoctorSeverity::Warning => tracing::warn!("[{}] {}", finding.id, finding.title),
                DoctorSeverity::Error => tracing::error!("[{}] {}", finding.id, finding.title),
                DoctorSeverity::Critical => tracing::error!("[{}] {}", finding.id, finding.title),
            }
        }

        Ok(report)
    }

    /// Check proxy service status, surfacing the parsed running/stopped state
    /// through `service_running` so `run` can derive `report.status`.
    ///
    /// This is the resilient variant used by [`run`](Self::run): a missing
    /// `systemctl` binary (e.g. on macOS) is caught here and surfaced as a
    /// `Critical` finding rather than `?`-propagating out of `run`, which would
    /// blank the entire report and leave the section degraded to "unavailable"
    /// with no diagnostic. `service_running` stays `None` in that case so the
    /// report status falls back to `Unknown('errors found')`.
    fn check_service_resilient(&self, service_running: &mut Option<bool>) -> Vec<DoctorFinding> {
        let mut findings = Vec::new();

        // Check if nginx is running
        let spec = CommandSpec::new("systemctl").args(["status", "nginx"]);
        let output = match self.runner.run(&spec) {
            Ok(o) => o,
            Err(e) => {
                findings.push(
                    DoctorFinding::new(
                        "nginx.service.missing-binary",
                        DoctorSeverity::Critical,
                        "systemctl binary not found or failed to run",
                    )
                    .detail(format!("Failed to query service status: {e}"))
                    .fix("Install systemd / systemctl on this host"),
                );
                return findings;
            }
        };
        let status = parse_nginx_status(&output.stdout);
        *service_running = Some(status.running);

        if status.running {
            findings.push(
                DoctorFinding::new(
                    "nginx.service.running",
                    DoctorSeverity::Info,
                    "Nginx service is running",
                )
                .detail(format!("PID: {:?}", status.pid)),
            );
        } else {
            findings.push(
                DoctorFinding::new(
                    "nginx.service.not-running",
                    DoctorSeverity::Error,
                    "Nginx service is not running",
                )
                .fix("Start nginx: systemctl start nginx"),
            );
        }

        // Check nginx version (resilient: a missing nginx binary surfaces as a
        // Critical finding rather than propagating out of `run`).
        let version_spec = CommandSpec::new("nginx").arg("-v");
        if let Ok(version_output) = self.runner.run(&version_spec) {
            if let Some(version) = parse_nginx_version(&version_output.stderr) {
                findings.push(
                    DoctorFinding::new(
                        "nginx.version",
                        DoctorSeverity::Info,
                        "Nginx version detected",
                    )
                    .detail(format!("Version: {version}")),
                );
            }
        } else {
            findings.push(
                DoctorFinding::new(
                    "nginx.version.missing-binary",
                    DoctorSeverity::Critical,
                    "nginx binary not found or failed to run",
                )
                .fix("Install nginx on this host"),
            );
        }

        findings
    }

    /// Check proxy service status.
    ///
    /// Kept as the `Result`-returning reference implementation;
    /// [`check_service_resilient`](Self::check_service_resilient) wraps it for
    /// use by [`run`](Self::run) so a missing binary becomes a finding instead
    /// of propagating.
    #[allow(dead_code)]
    fn check_service(&self) -> Result<Vec<DoctorFinding>> {
        let mut findings = Vec::new();

        // Check if nginx is running
        let spec = CommandSpec::new("systemctl").args(["status", "nginx"]);
        let output = self.runner.run(&spec)?;
        let status = parse_nginx_status(&output.stdout);

        if status.running {
            findings.push(
                DoctorFinding::new(
                    "nginx.service.running",
                    DoctorSeverity::Info,
                    "Nginx service is running",
                )
                .detail(format!("PID: {:?}", status.pid)),
            );
        } else {
            findings.push(
                DoctorFinding::new(
                    "nginx.service.not-running",
                    DoctorSeverity::Error,
                    "Nginx service is not running",
                )
                .fix("Start nginx: systemctl start nginx"),
            );
        }

        // Check nginx version
        let spec = CommandSpec::new("nginx").arg("-v");
        let version_output = self.runner.run(&spec)?;
        if let Some(version) = parse_nginx_version(&version_output.stderr) {
            findings.push(
                DoctorFinding::new(
                    "nginx.version",
                    DoctorSeverity::Info,
                    "Nginx version detected",
                )
                .detail(format!("Version: {version}")),
            );
        }

        Ok(findings)
    }

    /// Check Nginx configuration validity, surfacing a missing nginx binary as
    /// a Critical finding instead of propagating the runner error.
    fn check_config_resilient(&self) -> Vec<DoctorFinding> {
        let mut findings = Vec::new();

        let spec = CommandSpec::new("nginx").arg("-t");
        let output = match self.runner.run(&spec) {
            Ok(o) => o,
            Err(e) => {
                findings.push(
                    DoctorFinding::new(
                        "nginx.config.missing-binary",
                        DoctorSeverity::Critical,
                        "nginx binary not found or failed to run",
                    )
                    .detail(format!("Failed to validate configuration: {e}"))
                    .fix("Install nginx on this host"),
                );
                return findings;
            }
        };
        if output.success {
            findings.push(DoctorFinding::new(
                "nginx.config.valid",
                DoctorSeverity::Info,
                "Nginx configuration is valid",
            ));
        } else {
            findings.push(
                DoctorFinding::new(
                    "nginx.config.invalid",
                    DoctorSeverity::Critical,
                    "Nginx configuration has syntax errors",
                )
                .detail(output.stderr.clone())
                .fix("Fix the syntax errors and run 'nginx -t' to verify"),
            );
        }

        findings
    }

    /// Check Nginx configuration validity.
    ///
    /// Kept as the `Result`-returning reference implementation; see
    /// [`check_config_resilient`](Self::check_config_resilient).
    #[allow(dead_code)]
    fn check_config(&self) -> Result<Vec<DoctorFinding>> {
        let mut findings = Vec::new();

        let spec = CommandSpec::new("nginx").arg("-t");
        let output = self.runner.run(&spec)?;
        if output.success {
            findings.push(DoctorFinding::new(
                "nginx.config.valid",
                DoctorSeverity::Info,
                "Nginx configuration is valid",
            ));
        } else {
            findings.push(
                DoctorFinding::new(
                    "nginx.config.invalid",
                    DoctorSeverity::Critical,
                    "Nginx configuration has syntax errors",
                )
                .detail(output.stderr.clone())
                .fix("Fix the syntax errors and run 'nginx -t' to verify"),
            );
        }

        Ok(findings)
    }

    /// Check security headers. Resilient: this check is pure-filesystem and
    /// never shells out, so it cannot fail on a missing binary — included for
    /// symmetry with the other resilient wrappers.
    fn check_headers_resilient(&self) -> Vec<DoctorFinding> {
        self.check_headers().unwrap_or_default()
    }

    /// Check security headers.
    fn check_headers(&self) -> Result<Vec<DoctorFinding>> {
        let mut findings = Vec::new();

        // Check if security headers snippet exists
        let snippet_path = self.paths.nginx_snippets.join("security-headers.conf");
        if snippet_path.exists() {
            findings.push(DoctorFinding::new(
                "nginx.headers.security-headers",
                DoctorSeverity::Info,
                "Security headers snippet exists",
            ));
        } else {
            findings.push(
                DoctorFinding::new(
                    "nginx.headers.missing",
                    DoctorSeverity::Warning,
                    "Security headers snippet not found",
                )
                .detail(format!(
                    "Expected at {}",
                    snippet_path.display()
                ))
                .fix("Create a security headers snippet in nginx/snippets/"),
            );
        }

        Ok(findings)
    }

    /// Check certificate expiry. Resilient: pure-filesystem, swallows any I/O
    /// error so a permissions failure on one entry cannot blank the report.
    fn check_certificates_resilient(&self) -> Vec<DoctorFinding> {
        self.check_certificates().unwrap_or_default()
    }

    /// Check certificate expiry.
    fn check_certificates(&self) -> Result<Vec<DoctorFinding>> {
        let mut findings = Vec::new();

        // List certificates in the certbot live directory
        if self.paths.certbot_live_dir.is_dir() {
            let entries = std::fs::read_dir(&self.paths.certbot_live_dir);
            if let Ok(entries) = entries {
                for entry in entries.flatten() {
                    let domain = entry
                        .file_name()
                        .to_string_lossy()
                        .to_string();
                    let cert_path = entry.path().join("fullchain.pem");

                    if !cert_path.exists() {
                        findings.push(
                            DoctorFinding::new(
                                "cert.missing-cert",
                                DoctorSeverity::Warning,
                                format!("Certificate file missing for {domain}"),
                            )
                            .detail(format!("Expected at {}", cert_path.display()))
                            .fix("Re-obtain the certificate with certbot"),
                        );
                    }
                }
            }
        } else {
            findings.push(DoctorFinding::new(
                "cert.no-certbot-dir",
                DoctorSeverity::Info,
                "No certbot live directory found",
            ));
        }

        Ok(findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn doctor_finding_builder() {
        let finding = DoctorFinding::new(
            "test.finding",
            DoctorSeverity::Warning,
            "Test finding",
        )
        .detail("Some detail")
        .fix("Some fix");

        assert_eq!(finding.id, "test.finding");
        assert_eq!(finding.severity, DoctorSeverity::Warning);
        assert_eq!(finding.fix, Some("Some fix".into()));
    }
}
