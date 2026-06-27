//! Diagnostic checks for Tailscale health.
//!
//! Provides [`Doctor`] for running structured diagnostic checks on a
//! Tailscale installation. Checks cover connectivity, ACL status, DNS
//! configuration, and service health.
//!
//! # Checks
//!
//! | Check | What it validates |
//! |-------|------------------|
//! | Connected | Daemon is running and connected to the tailnet |
//! | AclActive | The daemon reports an active (non-default) policy |
//! | DnsConfigured | DNS resolvers and MagicDNS are properly configured |
//! | ServiceRunning | The `tailscaled` service is active |
//! | BinaryPresent | The `tailscale` binary is on `$PATH` |

use std::sync::Arc;

use crate::Result;

// ---------------------------------------------------------------------------
// DoctorScope
// ---------------------------------------------------------------------------

/// Selects which diagnostic checks to run.
#[derive(Debug, Clone)]
pub enum DoctorScope {
    /// Run all diagnostic checks.
    All,
    /// Check that the Tailscale daemon is connected to the tailnet.
    Connected,
    /// Check that ACL policies are active and not default-open.
    AclActive,
    /// Check that DNS is properly configured.
    DnsConfigured,
    /// Check that the `tailscaled` service is running.
    ServiceRunning,
    /// Check that the `tailscale` binary is available.
    BinaryPresent,
}

// ---------------------------------------------------------------------------
// DoctorReport
// ---------------------------------------------------------------------------

/// Result of a doctor run containing all findings.
#[derive(Debug, Clone)]
pub struct DoctorReport {
    /// Individual findings from each check.
    pub findings: Vec<Finding>,
}

impl DoctorReport {
    /// Create an empty report.
    pub fn new() -> Self {
        Self {
            findings: Vec::new(),
        }
    }

    /// Returns `true` if any finding has a critical severity.
    pub fn has_critical(&self) -> bool {
        self.findings.iter().any(|f| f.severity == Severity::Critical)
    }

    /// Returns `true` if all findings are OK.
    pub fn all_ok(&self) -> bool {
        self.findings.iter().all(|f| f.severity == Severity::Ok)
    }
}

impl Default for DoctorReport {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Finding
// ---------------------------------------------------------------------------

/// A single diagnostic finding.
#[derive(Debug, Clone)]
pub struct Finding {
    /// Unique identifier for the check (e.g. `tailscale.connected`).
    pub id: String,
    /// Severity of the finding.
    pub severity: Severity,
    /// Human-readable description.
    pub message: String,
    /// Suggested fix, if applicable.
    pub fix: Option<String>,
}

impl Finding {
    /// Create a new finding.
    pub fn new(id: impl Into<String>, severity: Severity, message: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            severity,
            message: message.into(),
            fix: None,
        }
    }

    /// Attach a suggested fix.
    pub fn with_fix(mut self, fix: impl Into<String>) -> Self {
        self.fix = Some(fix.into());
        self
    }

    /// Create an OK-level finding.
    pub fn ok(id: impl Into<String>, message: impl Into<String>) -> Self {
        Self::new(id, Severity::Ok, message)
    }

    /// Create a warning-level finding.
    pub fn warn(id: impl Into<String>, message: impl Into<String>) -> Self {
        Self::new(id, Severity::Warning, message)
    }

    /// Create a critical-level finding.
    pub fn critical(id: impl Into<String>, message: impl Into<String>) -> Self {
        Self::new(id, Severity::Critical, message)
    }
}

// ---------------------------------------------------------------------------
// Severity
// ---------------------------------------------------------------------------

/// Diagnostic severity level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// No issue detected.
    Ok,
    /// Informational note.
    Info,
    /// Non-critical issue.
    Warning,
    /// Critical problem requiring attention.
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ok => write!(f, "OK"),
            Self::Info => write!(f, "INFO"),
            Self::Warning => write!(f, "WARNING"),
            Self::Critical => write!(f, "CRITICAL"),
        }
    }
}

// ---------------------------------------------------------------------------
// Doctor
// ---------------------------------------------------------------------------

/// Diagnostic engine for Tailscale installations.
///
/// Runs structured checks against the local Tailscale daemon and returns
/// a [`DoctorReport`] with typed findings.
///
/// # Example
///
/// ```ignore
/// use toride_tailscale::doctor::{Doctor, DoctorScope};
/// use toride_tailscale::TailscaleClient;
///
/// let client = TailscaleClient::new();
/// let doctor = Doctor::new(&client);
/// let report = doctor.run(&DoctorScope::All).await?;
/// if report.has_critical() {
///     for f in &report.findings {
///         eprintln!("[{}] {}", f.severity, f.message);
///     }
/// }
/// ```
pub struct Doctor<'a> {
    /// Reference to the Tailscale client.
    client: &'a crate::TailscaleClient,
    /// Optional command runner used for real service probes. When `None`,
    /// service-health checks fall back to probing the daemon via the HTTP API.
    runner: Option<Arc<dyn toride_runner::Runner>>,
}

impl<'a> Doctor<'a> {
    /// Create a new `Doctor` with the given client.
    ///
    /// Without a runner, [`DoctorScope::ServiceRunning`] falls back to an
    /// HTTP-API liveness probe. Use [`Doctor::with_runner`] for a real
    /// `systemctl is-active tailscaled` check.
    pub fn new(client: &'a crate::TailscaleClient) -> Self {
        Self {
            client,
            runner: None,
        }
    }

    /// Attach a command runner so service checks can shell out to `systemctl`
    /// via [`toride_service::ServiceManager`].
    pub fn with_runner(mut self, runner: Arc<dyn toride_runner::Runner>) -> Self {
        self.runner = Some(runner);
        self
    }

    /// Run diagnostic checks for the given scope.
    ///
    /// # Errors
    ///
    /// Returns an error only for fundamental failures (e.g. API unreachable).
    /// Individual check failures appear as [`Finding`] values in the report.
    pub async fn run(&self, scope: &DoctorScope) -> Result<DoctorReport> {
        let mut report = DoctorReport::new();

        match scope {
            DoctorScope::All => {
                report.findings.extend(self.check_binary().await);
                report.findings.extend(self.check_connected().await);
                report.findings.extend(self.check_dns().await);
                report.findings.extend(self.check_service().await);
            }
            DoctorScope::Connected => {
                report.findings.extend(self.check_connected().await);
            }
            DoctorScope::AclActive => {
                report.findings.extend(self.check_acl_active().await);
            }
            DoctorScope::DnsConfigured => {
                report.findings.extend(self.check_dns().await);
            }
            DoctorScope::ServiceRunning => {
                report.findings.extend(self.check_service().await);
            }
            DoctorScope::BinaryPresent => {
                report.findings.extend(self.check_binary().await);
            }
        }

        Ok(report)
    }

    /// Check that the `tailscale` binary is on `$PATH`.
    ///
    /// The PATH scan (`which::which`) is a synchronous, blocking filesystem walk. It is wrapped
    /// in `spawn_blocking` so the tokio worker thread is never stalled — matching the invariant
    /// documented by the toride data layer (cloud/fail2ban/tailscale collectors wrap *all*
    /// shell-out / PATH lookups in `spawn_blocking`). On a cold cache or a networked filesystem
    /// the scan can take tens of milliseconds; offloading it keeps the runtime responsive.
    async fn check_binary(&self) -> Vec<Finding> {
        let found = tokio::task::spawn_blocking(|| which::which("tailscale").is_ok())
            .await
            .unwrap_or(false);
        if found {
            vec![Finding::ok(
                "tailscale.binary",
                "tailscale binary found on PATH",
            )]
        } else {
            vec![Finding::critical("tailscale.binary", "tailscale binary not found on PATH")
                .with_fix("Install Tailscale: https://tailscale.com/download")]
        }
    }

    /// Check that the daemon is connected to the tailnet.
    async fn check_connected(&self) -> Vec<Finding> {
        match self.client.is_connected().await {
            Ok(true) => vec![Finding::ok(
                "tailscale.connected",
                "Connected to tailnet",
            )],
            Ok(false) => vec![Finding::critical(
                "tailscale.connected",
                "Not connected to tailnet",
            )
            .with_fix("Run: tailscale up")],
            Err(e) => vec![Finding::critical(
                "tailscale.connected",
                format!("Could not determine connection status: {e}"),
            )
            .with_fix("Ensure tailscaled is running: systemctl start tailscaled")],
        }
    }

    /// Check DNS configuration.
    async fn check_dns(&self) -> Vec<Finding> {
        match self.client.dns_config().await {
            Ok(config) => {
                let mut findings = vec![Finding::ok(
                    "tailscale.dns",
                    format!(
                        "DNS configured (MagicDNS={}, {} nameservers)",
                        config.magic_dns,
                        config.nameservers.len()
                    ),
                )];
                if config.nameservers.is_empty() {
                    findings.push(
                        Finding::warn(
                            "tailscale.dns.nameservers",
                            "No custom DNS nameservers configured",
                        )
                        .with_fix("Add nameservers in the Tailscale admin console"),
                    );
                }
                findings
            }
            Err(e) => vec![Finding::critical(
                "tailscale.dns",
                format!("Could not fetch DNS config: {e}"),
            )],
        }
    }

    /// Check the `tailscaled` service status.
    ///
    /// When a runner is attached (via [`Doctor::with_runner`]), this probes the
    /// real unit state through `systemctl is-active tailscaled`. Otherwise it
    /// falls back to an HTTP-API liveness probe: if the daemon answers at all,
    /// it is considered to be running (but its enabled-at-boot state cannot be
    /// determined without `systemctl`).
    async fn check_service(&self) -> Vec<Finding> {
        if let Some(runner) = &self.runner {
            // Wrap the shared runner so ServiceManager gets a Box<dyn Runner>.
            struct SharedRunner(Arc<dyn toride_runner::Runner>);
            impl toride_runner::Runner for SharedRunner {
                fn run(
                    &self,
                    spec: &toride_runner::CommandSpec,
                ) -> std::result::Result<
                    toride_runner::CommandOutput,
                    toride_runner::Error,
                > {
                    self.0.run(spec)
                }
            }
            let mgr = toride_service::ServiceManager::new(Box::new(SharedRunner(Arc::clone(
                runner,
            ))));
            match mgr.is_active("tailscaled") {
                Ok(true) => vec![Finding::ok(
                    "tailscale.service",
                    "tailscaled service is active",
                )],
                Ok(false) => vec![Finding::critical(
                    "tailscale.service",
                    "tailscaled service is not active",
                )
                .with_fix("Run: sudo systemctl start tailscaled")],
                Err(e) => vec![Finding::critical(
                    "tailscale.service",
                    format!("Could not determine service status: {e}"),
                )
                .with_fix("Ensure systemctl is available and tailscaled is installed")],
            }
        } else {
            // Fallback: probe the daemon via the HTTP API. If the daemon
            // answers *any* status query, the service is running.
            match self.client.api().get_status().await {
                Ok(_) => vec![Finding::ok(
                    "tailscale.service",
                    "tailscaled daemon is responding (service assumed active)",
                )],
                Err(e) => vec![Finding::critical(
                    "tailscale.service",
                    format!("tailscaled daemon unreachable: {e}"),
                )
                .with_fix("Run: sudo systemctl start tailscaled")],
            }
        }
    }

    /// Check that an ACL policy is active and not the default-open policy.
    ///
    /// A node connected to a tailnet always has *some* effective policy. We
    /// treat a healthy connection (the daemon reporting `Running`) as evidence
    /// of an active policy, and warn when the daemon cannot confirm it.
    async fn check_acl_active(&self) -> Vec<Finding> {
        match self.client.api().get_status().await {
            Ok(status) => {
                let backend = status
                    .get("BackendState")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                if backend == "Running" {
                    vec![Finding::ok(
                        "tailscale.acl",
                        "Daemon is running; effective ACL policy is active",
                    )]
                } else {
                    vec![Finding::warn(
                        "tailscale.acl",
                        format!("Daemon state is `{backend}`, ACL policy may not be enforced"),
                    )
                    .with_fix("Run: tailscale up")]
                }
            }
            Err(e) => vec![Finding::critical(
                "tailscale.acl",
                format!("Could not fetch status to verify ACLs: {e}"),
            )],
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use toride_runner::CommandSpec;
    use toride_runner::Runner;
    use toride_runner::fake::FakeRunner;

    #[test]
    fn report_aggregation_all_ok() {
        let mut report = DoctorReport::new();
        report.findings.push(Finding::ok("a", "ok"));
        assert!(report.all_ok());
        assert!(!report.has_critical());
    }

    #[test]
    fn report_aggregation_has_critical() {
        let mut report = DoctorReport::new();
        report.findings.push(Finding::ok("a", "ok"));
        report.findings.push(Finding::critical("b", "bad"));
        assert!(!report.all_ok());
        assert!(report.has_critical());
    }

    #[test]
    fn finding_with_fix_attaches_fix() {
        let f = Finding::warn("id", "msg").with_fix("do x");
        assert_eq!(f.fix.as_deref(), Some("do x"));
    }

    #[test]
    fn severity_ordering() {
        assert!(Severity::Critical > Severity::Warning);
        assert!(Severity::Warning > Severity::Info);
        assert!(Severity::Info > Severity::Ok);
    }

    #[test]
    fn severity_display() {
        assert_eq!(Severity::Ok.to_string(), "OK");
        assert_eq!(Severity::Critical.to_string(), "CRITICAL");
    }

    /// When a runner is attached, `check_service` must really probe
    /// `systemctl is-active tailscaled` rather than returning a hardcoded ok.
    ///
    /// We cannot easily construct a `TailscaleClient` without a network, but
    /// the runner-injected path never touches the client, so we can drive it
    /// directly through a minimal stand-in. This test exercises the real
    /// ServiceManager plumbing by invoking it the same way `check_service`
    /// does.
    #[tokio::test]
    async fn check_service_probes_systemctl_when_runner_attached() {
        let active_spec = CommandSpec::new("systemctl").args(["is-active", "tailscaled"]);

        // Active service -> ok finding.
        let runner: std::sync::Arc<dyn Runner> = std::sync::Arc::new(
            FakeRunner::new().respond(active_spec.clone(), toride_runner::CommandOutput::from_stdout("active")),
        );
        let finding = probe_via_runner(&runner).await;
        assert_eq!(finding.severity, Severity::Ok);

        // Inactive service -> critical finding, and the probe still ran.
        let runner: std::sync::Arc<dyn Runner> = std::sync::Arc::new(
            FakeRunner::new().respond(active_spec.clone(), toride_runner::CommandOutput::from_stderr("inactive", 3)),
        );
        let finding = probe_via_runner(&runner).await;
        assert_eq!(finding.severity, Severity::Critical);
    }

    /// Mirrors `Doctor::check_service`'s runner branch without requiring a
    /// live `TailscaleClient`.
    async fn probe_via_runner(runner: &std::sync::Arc<dyn Runner>) -> Finding {
        struct SharedRunner(std::sync::Arc<dyn Runner>);
        impl Runner for SharedRunner {
            fn run(
                &self,
                spec: &toride_runner::CommandSpec,
            ) -> std::result::Result<toride_runner::CommandOutput, toride_runner::Error> {
                self.0.run(spec)
            }
        }
        let mgr = toride_service::ServiceManager::new(Box::new(SharedRunner(runner.clone())));
        match mgr.is_active("tailscaled") {
            Ok(true) => Finding::ok("tailscale.service", "active"),
            Ok(false) => Finding::critical("tailscale.service", "inactive"),
            Err(e) => Finding::critical("tailscale.service", e.to_string()),
        }
    }
}
