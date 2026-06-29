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
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
    pub fn new(id: impl Into<String>, severity: DoctorSeverity, title: impl Into<String>) -> Self {
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
        // Collect real cert expiry here so we can populate report.certificates
        // (previously the cert check only emitted findings, leaving the
        // report's certificates field permanently empty and
        // has_expired_certs() always false).
        let mut certs: Vec<crate::report::CertInfo> = Vec::new();
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
                for f in self.check_certificates_resilient(&mut certs) {
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
                for f in self.check_certificates_resilient(&mut certs) {
                    findings.push(f);
                }
            }
            DoctorScope::Config => {
                for f in self.check_config_resilient() {
                    findings.push(f);
                }
            }
        }

        // Populate the report's structured fields. These were previously dead:
        // the doctor computed findings only. Now report.certificates carries
        // real expiry and report.server_blocks reflects the parsed nginx.conf
        // (when the `config` feature is on).
        report.certificates = certs;

        // Server blocks: only meaningful for the All / Config scopes. Gate on
        // the `config` feature because ConfigManager lives there.
        #[cfg(feature = "config")]
        {
            if matches!(scope, DoctorScope::All | DoctorScope::Config) {
                self.collect_server_blocks(&mut report);
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
                let has_errors = findings.iter().any(|f| f.severity >= DoctorSeverity::Error);
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
        self.check_headers()
    }

    /// Check security headers.
    fn check_headers(&self) -> Vec<DoctorFinding> {
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
                .detail(format!("Expected at {}", snippet_path.display()))
                .fix("Create a security headers snippet in nginx/snippets/"),
            );
        }

        findings
    }

    /// Check certificate expiry. Resilient: pure-filesystem, swallows any I/O
    /// error so a permissions failure on one entry cannot blank the report.
    /// Populates `certs_out` with real expiry data so the report's
    /// `certificates` field is no longer dead.
    fn check_certificates_resilient(
        &self,
        certs_out: &mut Vec<crate::report::CertInfo>,
    ) -> Vec<DoctorFinding> {
        self.check_certificates(certs_out)
    }

    /// Check certificate expiry.
    ///
    /// For each live certbot certificate, shells out to `openssl x509 -enddate`
    /// to read real expiry and pushes a [`CertInfo`] into `certs_out`. This is
    /// what makes [`ProxyReport::certificates`] (and
    /// [`ProxyReport::has_expired_certs`]) reflect reality instead of staying
    /// empty. Findings are still emitted for missing cert files and for certs
    /// that are expired or near expiry.
    fn check_certificates(
        &self,
        certs_out: &mut Vec<crate::report::CertInfo>,
    ) -> Vec<DoctorFinding> {
        use crate::certs_parse::read_cert_expiry;
        use std::time::SystemTime;

        let mut findings = Vec::new();

        // List certificates in the certbot live directory
        if self.paths.certbot_live_dir.is_dir() {
            let entries = std::fs::read_dir(&self.paths.certbot_live_dir);
            if let Ok(entries) = entries {
                for entry in entries.flatten() {
                    let domain = entry.file_name().to_string_lossy().to_string();
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
                        continue;
                    }

                    // Read real expiry via openssl. Degrades to is_valid=false
                    // on any failure (missing openssl, parse error) — never
                    // panics.
                    let now = SystemTime::now();
                    let expiry = read_cert_expiry(&cert_path, self.runner, now)
                        .unwrap_or_else(|_| crate::certs_parse::CertExpiry::unknown());

                    let cert_info = crate::report::CertInfo::new(
                        domain.clone(),
                        "Let's Encrypt",
                        "",
                        &expiry.not_after,
                        expiry.days_remaining,
                    );
                    certs_out.push(cert_info.clone());

                    // Emit a finding for certs that are expired or expiring
                    // soon (<= 30 days), so the doctor surfaces them even if a
                    // caller only reads findings.
                    if !expiry.is_valid && expiry.days_remaining <= 0 {
                        findings.push(
                            DoctorFinding::new(
                                format!("cert.expired.{domain}"),
                                DoctorSeverity::Error,
                                format!("Certificate for {domain} has expired"),
                            )
                            .detail(format!(
                                "notAfter: {} ({} days remaining)",
                                expiry.not_after, expiry.days_remaining
                            ))
                            .fix("Renew the certificate: certbot renew"),
                        );
                    } else if expiry.is_valid && expiry.days_remaining <= 30 {
                        findings.push(
                            DoctorFinding::new(
                                format!("cert.expiring-soon.{domain}"),
                                DoctorSeverity::Warning,
                                format!("Certificate for {domain} expires soon"),
                            )
                            .detail(format!(
                                "{} days remaining (notAfter: {})",
                                expiry.days_remaining, expiry.not_after
                            ))
                            .fix("Renew the certificate before it expires"),
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

        findings
    }

    /// Parse the nginx config into server blocks and populate the report's
    /// `server_blocks` field, so it reflects the on-disk configuration instead
    /// of staying empty. Resilient: a parse failure is logged, not propagated.
    #[cfg(feature = "config")]
    fn collect_server_blocks(&self, report: &mut ProxyReport) {
        use crate::config::ConfigManager;

        let mgr = ConfigManager::new(self.paths);
        match mgr.parse_nginx_server_blocks() {
            Ok(parsed) => {
                for p in parsed {
                    // Each ParsedServerBlock may declare multiple server_names;
                    // promote the first name (or a placeholder) into a typed
                    // ServerBlock so the report carries real listen ports and
                    // TLS state.
                    let names = p.server_names();
                    let server_name = names.first().copied().unwrap_or("_").to_string();
                    let listen_port = p.listen_port().unwrap_or(80);
                    let upstream = p
                        .find("location")
                        .and_then(|loc| loc.children.iter().find(|d| d.name == "proxy_pass"))
                        .and_then(|pp| pp.args.first())
                        .and_then(|s| {
                            // proxy_pass http://host:port; -> host:port
                            s.trim_start_matches("http://")
                                .trim_end_matches(';')
                                .to_string()
                                .into()
                        })
                        .unwrap_or_else(|| "127.0.0.1:80".to_string());

                    let mut block =
                        crate::spec::ServerBlock::new(server_name, listen_port, upstream);
                    if p.has_ssl() {
                        // We do not synthesize cert paths here — the cert check
                        // owns TLS expiry. Mark TLS presence via an extra
                        // directive so the report still distinguishes TLS blocks.
                        block = block.with_directive("# tls enabled (listen ... ssl)");
                    }
                    report.server_blocks.push(block);
                }
            }
            Err(e) => {
                tracing::debug!("doctor: could not parse nginx config for server blocks: {e}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn doctor_finding_builder() {
        let finding = DoctorFinding::new("test.finding", DoctorSeverity::Warning, "Test finding")
            .detail("Some detail")
            .fix("Some fix");

        assert_eq!(finding.id, "test.finding");
        assert_eq!(finding.severity, DoctorSeverity::Warning);
        assert_eq!(finding.fix, Some("Some fix".into()));
    }

    /// When the certbot live dir holds a cert whose openssl reports a real
    /// future expiry, the doctor must populate report.certificates (previously
    /// dead) with a CertInfo whose days_remaining is positive.
    #[cfg(feature = "config")]
    #[test]
    fn doctor_populates_certificates_with_real_expiry() {
        use crate::certs_parse::CertExpiry;
        use std::time::SystemTime;

        let dir = assert_fs::TempDir::new().unwrap();
        let paths = ProxyPaths::with_root(dir.path());

        // Seed a cert dir + fullchain.pem so the scan finds it.
        let cert_dir = paths.cert_live_path("example.com");
        std::fs::create_dir_all(&cert_dir).unwrap();
        std::fs::write(cert_dir.join("fullchain.pem"), "fake pem\n").unwrap();

        // FakeRunner answers the openssl enddate probe with a far-future date.
        // Certificates scope only runs the cert check (no service/version/test),
        // so a single response suffices.
        let fake = toride_runner::FakeRunner::new()
            // openssl x509 -enddate for example.com
            .push_response(toride_runner::CommandOutput::from_stdout(
                "notAfter=Jan  1 00:00:00 2099 GMT\n",
            ));

        let doc = Doctor::new(&fake, &paths);
        let report = doc.run(&DoctorScope::Certificates).unwrap();

        assert_eq!(report.certificates.len(), 1);
        let cert = &report.certificates[0];
        assert_eq!(cert.domain, "example.com");
        assert!(cert.days_remaining > 10_000, "got {}", cert.days_remaining);
        assert!(cert.is_valid);
        assert!(!report.has_expired_certs());

        // Sanity: the from_not_after helper agrees.
        let exp = CertExpiry::from_not_after("Jan  1 00:00:00 2099 GMT", SystemTime::now());
        assert!(exp.is_valid);
    }

    /// An expired cert must set is_valid=false and surface an Error finding,
    /// and has_expired_certs() must return true.
    #[cfg(feature = "config")]
    #[test]
    fn doctor_flags_expired_certificate() {
        let dir = assert_fs::TempDir::new().unwrap();
        let paths = ProxyPaths::with_root(dir.path());
        let cert_dir = paths.cert_live_path("expired.com");
        std::fs::create_dir_all(&cert_dir).unwrap();
        std::fs::write(cert_dir.join("fullchain.pem"), "fake pem\n").unwrap();

        let fake = toride_runner::FakeRunner::new().push_response(
            toride_runner::CommandOutput::from_stdout("notAfter=Jan  1 00:00:00 2001 GMT\n"),
        );

        let doc = Doctor::new(&fake, &paths);
        let report = doc.run(&DoctorScope::Certificates).unwrap();

        assert_eq!(report.certificates.len(), 1);
        assert!(!report.certificates[0].is_valid);
        assert!(report.has_expired_certs());
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.id == "cert.expired.expired.com")
        );
    }

    /// With the `config` feature, the All-scope report must populate
    /// report.server_blocks from the on-disk nginx.conf.
    #[cfg(feature = "config")]
    #[test]
    fn doctor_populates_server_blocks_from_config() {
        let dir = assert_fs::TempDir::new().unwrap();
        let paths = ProxyPaths::with_root(dir.path());

        // Write a minimal nginx.conf with one server block.
        std::fs::create_dir_all(paths.nginx_conf.parent().unwrap()).unwrap();
        std::fs::write(
            &paths.nginx_conf,
            "http {\n\
             server {\n\
             listen 443 ssl http2;\n\
             server_name secure.example.com;\n\
             location / {\n\
             proxy_pass http://127.0.0.1:3000;\n\
             }\n\
             }\n\
             }\n",
        )
        .unwrap();

        // FakeRunner: systemctl status, nginx -v, nginx -t, then (no certs).
        let fake = toride_runner::FakeRunner::new()
            .push_response(toride_runner::CommandOutput::from_stdout(
                "Active: active (running)\nMain PID: 42 (nginx)\n",
            ))
            .push_response(toride_runner::CommandOutput::from_stderr(
                "nginx version: nginx/1.24.0\n",
                0,
            ))
            .push_response(toride_runner::CommandOutput::from_stdout("syntax is ok\n"));

        let doc = Doctor::new(&fake, &paths);
        let report = doc.run(&DoctorScope::All).unwrap();

        assert_eq!(report.server_blocks.len(), 1);
        let block = &report.server_blocks[0];
        assert_eq!(block.server_name, "secure.example.com");
        assert_eq!(block.listen_port, 443);
        assert_eq!(block.upstream, "127.0.0.1:3000");
    }
}
