//! Diagnostic engine for cloud provider installations.
//!
//! [`Doctor`] runs structured diagnostic checks across a cloud provider
//! installation and returns a [`CloudReport`] containing typed
//! [`Finding`](crate::report::Finding) values with severity levels,
//! human-readable descriptions, and suggested fixes.
//!
//! # Categories
//!
//! Each category corresponds to a [`DoctorScope`] variant and a `check_*`
//! method on [`Doctor`]:
//!
//! | Scope             | What it checks                                    |
//! |-------------------|---------------------------------------------------|
//! | `Provider`        | Cloud provider detection and metadata             |
//! | `Binaries`        | CLI tools (aws, gcloud, doctl, hcloud)           |
//! | `SecurityGroups`  | Firewall rules, open ports, overly permissive     |
//! | `Agent`           | Provider agent running and enabled                |
//! | `Network`         | VPC/network configuration and connectivity        |
//! | `All`             | All of the above                                  |

use crate::CloudProvider;
use crate::client::CloudClient;
use crate::error::Result;
use crate::report::{CloudReport, Finding, Severity};

// ---------------------------------------------------------------------------
// DoctorScope
// ---------------------------------------------------------------------------

/// Scope for diagnostic checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DoctorScope {
    /// Check cloud provider detection and metadata.
    Provider,
    /// Check CLI tool availability and versions.
    Binaries,
    /// Check security groups and firewall rules.
    SecurityGroups,
    /// Check provider agent service status.
    Agent,
    /// Check network configuration.
    Network,
    /// Run all checks.
    All,
}

impl DoctorScope {
    /// Parse a scope from a CLI `--scope` string (case-insensitive).
    ///
    /// Accepts the variant names (`all`, `binaries`, ...) plus a few aliases
    /// (`sg` for `security-groups`, `binaries`/`bins`). Unknown values fall
    /// back to [`DoctorScope::All`] so a typo never silently runs no checks.
    #[must_use]
    pub fn from_cli_str(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "provider" => Self::Provider,
            "binaries" | "bins" | "binary" => Self::Binaries,
            "security-groups" | "securitygroups" | "sg" | "firewall" | "firewalls" => {
                Self::SecurityGroups
            }
            "agent" | "service" => Self::Agent,
            "network" | "net" => Self::Network,
            // "all", "", and any unrecognised value all run every check so a
            // typo never silently runs zero checks.
            _ => Self::All,
        }
    }
}

// ---------------------------------------------------------------------------
// Doctor
// ---------------------------------------------------------------------------

/// Diagnostic engine for cloud provider installations.
///
/// # Example
///
/// ```ignore
/// use toride_cloud::doctor::{Doctor, DoctorScope};
///
/// let doctor = Doctor::new();
/// let report = doctor.run(&DoctorScope::All)?;
///
/// if report.has_errors() {
///     for f in &report.findings {
///         eprintln!("[{}] {}", f.severity, f.title);
///     }
/// }
/// ```
pub struct Doctor {
    /// The cloud provider to diagnose.
    provider: CloudProvider,
}

impl Doctor {
    /// Create a new doctor for the auto-detected provider.
    pub fn detect() -> Result<Self> {
        let provider = crate::detect::detect_provider()?;
        Ok(Self { provider })
    }

    /// Create a new doctor for a specific provider.
    #[must_use]
    pub fn new(provider: CloudProvider) -> Self {
        Self { provider }
    }

    /// Run diagnostic checks for the given scope.
    ///
    /// # Errors
    ///
    /// Returns an error only for fundamental failures. Individual check
    /// failures appear as [`Finding`] values in the report.
    pub fn run(&self, scope: &DoctorScope) -> Result<CloudReport> {
        let mut report = CloudReport::new(self.provider);

        match scope {
            DoctorScope::Provider => self.check_provider(&mut report),
            DoctorScope::Binaries => self.check_binaries(&mut report),
            DoctorScope::SecurityGroups => self.check_security_groups(&mut report),
            DoctorScope::Agent => self.check_agent(&mut report),
            DoctorScope::Network => self.check_network(&mut report),
            DoctorScope::All => {
                self.check_provider(&mut report);
                self.check_binaries(&mut report);
                self.check_security_groups(&mut report);
                self.check_agent(&mut report);
                self.check_network(&mut report);
            }
        }

        Ok(report)
    }

    // -----------------------------------------------------------------------
    // Check methods
    // -----------------------------------------------------------------------

    /// Check cloud provider detection and metadata.
    fn check_provider(&self, report: &mut CloudReport) {
        if matches!(self.provider, CloudProvider::Unknown) {
            report.push(
                Finding::new(
                    "provider.unknown",
                    Severity::Warning,
                    "Cloud provider could not be detected",
                )
                .detail("No cloud provider metadata endpoint responded.")
                .fix("Verify the machine is running on a supported cloud provider."),
            );
        }
    }

    /// Check CLI tool availability.
    fn check_binaries(&self, report: &mut CloudReport) {
        let tool = self.provider.cli_tool();
        if tool.is_empty() {
            return;
        }

        match which::which(tool) {
            Ok(_) => {
                report.push(Finding::new(
                    format!("binaries.{tool}.found"),
                    Severity::Ok,
                    format!("{tool} CLI is installed"),
                ));
            }
            Err(_) => {
                report.push(
                    Finding::new(
                        format!("binaries.{tool}.missing"),
                        Severity::Warning,
                        format!("{tool} CLI is not installed"),
                    )
                    .detail(format!("The {tool} command was not found on $PATH."))
                    .fix(format!("Install the {tool} CLI tool.")),
                );
            }
        }
    }

    /// Check security groups and firewall rules.
    ///
    /// Lists the provider's security groups via [`CloudClient`] and classifies
    /// each rule into a finding:
    ///
    /// - **Critical**: ingress open to `0.0.0.0/0` (or `::/0`) on a sensitive
    ///   port (SSH/RDP/database/admin — see [`SENSITIVE_PORTS`]).
    /// - **Warning**: ingress open to `0.0.0.0/0` on any other port.
    /// - **Warning**: a group with no egress rules (no outbound filtering).
    ///
    /// If the list itself fails (CLI missing, not authenticated, etc.) a single
    /// error finding is recorded rather than aborting the whole report.
    fn check_security_groups(&self, report: &mut CloudReport) {
        let groups = match CloudClient::for_provider(self.provider).list_security_groups() {
            Ok(groups) => groups,
            Err(e) => {
                report.push(
                    Finding::new(
                        "security-groups.list-failed",
                        Severity::Error,
                        "Failed to list security groups",
                    )
                    .detail(format!("{e}"))
                    .fix(format!(
                        "Ensure the {} CLI is installed and authenticated.",
                        self.provider.cli_tool()
                    )),
                );
                return;
            }
        };

        if groups.is_empty() {
            report.push(Finding::new(
                "security-groups.empty",
                Severity::Info,
                "No security groups found",
            ));
            return;
        }

        report.push(Finding::new(
            "security-groups.count",
            Severity::Ok,
            format!("Listed {} security group(s)", groups.len()),
        ));

        for group in &groups {
            let label = group.id.clone().unwrap_or_else(|| group.name.clone());

            for rule in group.ingress_rules() {
                if !is_open_cidr(&rule.cidr) {
                    continue;
                }
                let (port_desc, sensitive) = describe_port(rule);
                if sensitive {
                    report.push(
                        Finding::new(
                            "security-group.open-sensitive-ingress",
                            Severity::Critical,
                            format!("{label}: sensitive port open to the world"),
                        )
                        .detail(format!(
                            "{} ingress on {} allows {} — anyone on the internet can reach it.",
                            group.name, port_desc, rule.cidr,
                        ))
                        .fix(format!(
                            "Restrict {port_desc} to a known CIDR or remove the rule.",
                        )),
                    );
                } else {
                    report.push(
                        Finding::new(
                            "security-group.open-ingress",
                            Severity::Warning,
                            format!("{label}: ingress open to the world"),
                        )
                        .detail(format!(
                            "{} ingress on {} allows {}.",
                            group.name, port_desc, rule.cidr,
                        ))
                        .fix(format!(
                            "Narrow {port_desc} to the CIDRs that genuinely need access.",
                        )),
                    );
                }
            }

            if group.egress_rules().is_empty() {
                report.push(
                    Finding::new(
                        "security-group.no-egress",
                        Severity::Warning,
                        format!("{label}: no egress rules recorded"),
                    )
                    .detail(format!(
                        "{} has no outbound rules visible to the doctor; verify the provider's \
                         default egress policy is intentional.",
                        group.name,
                    )),
                );
            }
        }
    }

    /// Check provider agent service status.
    ///
    /// Probes the provider's guest agent via [`ServiceManager`]. An absent or
    /// stopped agent is only a concern on the provider the machine is actually
    /// running on, so this is a `Warning` (not an error) and skipped entirely
    /// for [`CloudProvider::Unknown`].
    fn check_agent(&self, report: &mut CloudReport) {
        if matches!(self.provider, CloudProvider::Unknown) {
            return;
        }

        let manager = crate::service::ServiceManager::new(self.provider);
        let service = manager.agent_service_name();
        if service.is_empty() {
            return;
        }

        match manager.is_agent_running() {
            Ok(true) => {
                report.push(Finding::new(
                    "agent.running",
                    Severity::Ok,
                    format!("{service} is running"),
                ));
            }
            Ok(false) => {
                report.push(
                    Finding::new(
                        "agent.not-running",
                        Severity::Warning,
                        format!("{service} is not running"),
                    )
                    .detail(format!(
                        "The {service} service is installed but not active on this host."
                    ))
                    .fix(format!("Start the service: `systemctl start {service}`.")),
                );
            }
            Err(e) => {
                report.push(
                    Finding::new(
                        "agent.probe-failed",
                        Severity::Info,
                        format!("Could not determine {service} status"),
                    )
                    .detail(format!("{e}")),
                );
            }
        }

        match manager.is_agent_enabled() {
            Ok(true) => {
                report.push(Finding::new(
                    "agent.enabled",
                    Severity::Ok,
                    format!("{service} is enabled at boot"),
                ));
            }
            Ok(false) => {
                report.push(
                    Finding::new(
                        "agent.disabled",
                        Severity::Warning,
                        format!("{service} is not enabled at boot"),
                    )
                    .fix(format!("Enable the service: `systemctl enable {service}`.")),
                );
            }
            Err(e) => {
                report.push(
                    Finding::new(
                        "agent.enabled-probe-failed",
                        Severity::Info,
                        format!("Could not determine if {service} is enabled"),
                    )
                    .detail(format!("{e}")),
                );
            }
        }
    }

    /// Check network configuration.
    ///
    /// Confirms the provider CLI is reachable on `$PATH` and, where the
    /// provider exposes one, that its metadata endpoint resolves. These are
    /// the network-facing preconditions for every other cloud operation, so a
    /// missing CLI or unreachable metadata service is flagged early.
    fn check_network(&self, report: &mut CloudReport) {
        let tool = self.provider.cli_tool();
        if !tool.is_empty() {
            match which::which(tool) {
                Ok(path) => {
                    report.push(
                        Finding::new(
                            format!("network.{tool}.on-path"),
                            Severity::Ok,
                            format!("{tool} is on $PATH"),
                        )
                        .detail(format!("resolved to {}", path.display())),
                    );
                }
                Err(_) => {
                    report.push(
                        Finding::new(
                            format!("network.{tool}.missing"),
                            Severity::Warning,
                            format!("{tool} CLI is not on $PATH"),
                        )
                        .detail("Network operations that shell out to the provider CLI will fail.")
                        .fix(format!("Install the {tool} CLI and ensure it is on $PATH.")),
                    );
                }
            }
        }

        if let Some(url) = self.provider.metadata_url() {
            match probe_metadata(url) {
                ProbeOutcome::Reachable => {
                    report.push(Finding::new(
                        "network.metadata.reachable",
                        Severity::Ok,
                        format!("Provider metadata endpoint ({url}) is reachable"),
                    ));
                }
                ProbeOutcome::Unreachable(reason) => {
                    // Metadata being unreachable off-provider is the common
                    // case, so downgrade to Info rather than Warning.
                    report.push(
                        Finding::new(
                            "network.metadata.unreachable",
                            Severity::Info,
                            format!("Provider metadata endpoint ({url}) is not reachable"),
                        )
                        .detail(reason),
                    );
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Classification helpers
// ---------------------------------------------------------------------------

/// Ports that are dangerous to expose to the entire internet.
///
/// Curated from common cloud-hardening guidance: remote shells (SSH, RDP),
/// databases (`MySQL`, `PostgreSQL`, `MongoDB`, `Redis`), and admin web UIs.
const SENSITIVE_PORTS: &[u16] = &[
    22,    // SSH
    23,    // Telnet
    3389,  // RDP
    3306,  // MySQL
    5432,  // PostgreSQL
    27017, // MongoDB
    6379,  // Redis
    9200,  // Elasticsearch
    11211, // Memcached
];

/// Returns `true` if `cidr` matches the "whole internet" wildcards.
fn is_open_cidr(cidr: &str) -> bool {
    matches!(cidr.trim(), "0.0.0.0/0" | "::/0")
}

/// Describe a rule's port as a human-readable string, and flag whether it is
/// sensitive. Rules with no port range (e.g. ICMP, or all-protocols) are
/// reported but never classified as sensitive — the caller still warns about
/// the open CIDR.
///
/// A range is sensitive if it overlaps any entry in [`SENSITIVE_PORTS`]
/// (i.e. a sensitive port falls inside `[start, end]`).
fn describe_port(rule: &crate::spec::FirewallRule) -> (String, bool) {
    match rule.port_range {
        Some(pr) => {
            let sensitive = SENSITIVE_PORTS
                .iter()
                .any(|&p| p >= pr.start && p <= pr.end);
            (format!("{} {}", rule.protocol, pr), sensitive)
        }
        None => (format!("{} (all ports)", rule.protocol), false),
    }
}

/// Outcome of a metadata-endpoint probe.
enum ProbeOutcome {
    /// The endpoint responded (any HTTP status).
    Reachable,
    /// The endpoint could not be reached; carries a short reason.
    Unreachable(String),
}

/// Attempt a best-effort TCP connection to a metadata endpoint.
///
/// Uses a blocking `std::net::TcpStream` with a short timeout rather than
/// pulling in an HTTP client dependency: we only care whether *something* is
/// listening, not the response body. The host:port are parsed from the URL's
/// authority; the path is irrelevant for a reachability probe.
///
/// Resolution goes through `ToSocketAddrs` so hostname authorities (e.g.
/// `metadata.google.internal`) are DNS-resolved; parsing the authority as a
/// `SocketAddr` directly would only accept IP literals and silently fail to
/// probe any hostname-based metadata endpoint.
fn probe_metadata(url: &str) -> ProbeOutcome {
    use std::net::ToSocketAddrs;

    let authority = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
        .unwrap_or(url);
    let host_port = authority.split('/').next().unwrap_or(authority);
    if host_port.is_empty() {
        return ProbeOutcome::Unreachable("no host in metadata URL".to_string());
    }

    // Split an optional `:port` suffix off the authority. Only the final
    // colon-separated token is treated as a port; hostnames themselves never
    // contain a bare `:` outside of IPv6 literals (which are not valid metadata
    // hosts here).
    let (host, port) = match host_port.rsplit_once(':') {
        Some((h, p)) => match p.parse::<u16>() {
            Ok(n) => (h, n),
            Err(_) => (host_port, 80),
        },
        None => (host_port, 80),
    };
    if host.is_empty() {
        return ProbeOutcome::Unreachable("no host in metadata URL".to_string());
    }

    let timeout = std::time::Duration::from_secs(2);
    // Resolve every address for the (host, port) pair and try each in turn
    // until one connects or the list is exhausted. This is the standard
    // `ToSocketAddrs` fan-out pattern and works for both DNS names and IPs.
    let addrs = match (host, port).to_socket_addrs() {
        Ok(addrs) => addrs.collect::<Vec<_>>(),
        Err(e) => {
            return ProbeOutcome::Unreachable(format!("name resolution failed: {e}"));
        }
    };
    if addrs.is_empty() {
        return ProbeOutcome::Unreachable("no addresses resolved for metadata host".to_string());
    }
    for addr in addrs {
        if std::net::TcpStream::connect_timeout(&addr, timeout).is_ok() {
            return ProbeOutcome::Reachable;
        }
    }
    ProbeOutcome::Unreachable("connection failed to all resolved addresses".to_string())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spec::{FirewallRule, PortRange, Protocol, RuleAction};

    fn rule(cidr: &str, proto: Protocol, port: Option<u16>) -> FirewallRule {
        let port_range = port.map(PortRange::single);
        FirewallRule {
            id: None,
            description: String::new(),
            is_ingress: true,
            protocol: proto,
            port_range,
            cidr: cidr.to_string(),
            action: RuleAction::Allow,
        }
    }

    // -- is_open_cidr ---------------------------------------------------------

    #[test]
    fn open_cidr_recognises_wildcards() {
        assert!(is_open_cidr("0.0.0.0/0"));
        assert!(is_open_cidr("::/0"));
        assert!(is_open_cidr("  0.0.0.0/0  "));
    }

    #[test]
    fn open_cidr_rejects_scoped_blocks() {
        assert!(!is_open_cidr("10.0.0.0/8"));
        assert!(!is_open_cidr("203.0.113.0/24"));
        assert!(!is_open_cidr(""));
        assert!(!is_open_cidr("sg:sg-abc"));
    }

    // -- describe_port --------------------------------------------------------

    #[test]
    fn describe_port_flags_sensitive_single_ports() {
        for &p in &[22, 3389, 3306, 5432, 6379, 27017] {
            let (desc, sensitive) = describe_port(&rule("0.0.0.0/0", Protocol::Tcp, Some(p)));
            assert!(sensitive, "port {p} should be sensitive");
            assert!(
                desc.contains(&p.to_string()),
                "desc should mention port: {desc}"
            );
        }
    }

    #[test]
    fn describe_port_flags_sensitive_range_endpoints() {
        // A range that straddles a sensitive port is still flagged.
        let r = FirewallRule {
            id: None,
            description: String::new(),
            is_ingress: true,
            protocol: Protocol::Tcp,
            port_range: Some(PortRange::range(20, 30)),
            cidr: "0.0.0.0/0".to_string(),
            action: RuleAction::Allow,
        };
        let (_, sensitive) = describe_port(&r);
        assert!(sensitive, "range covering SSH must be sensitive");
    }

    #[test]
    fn describe_port_non_sensitive_port() {
        let (_, sensitive) = describe_port(&rule("0.0.0.0/0", Protocol::Tcp, Some(80)));
        assert!(!sensitive, "port 80 is open but not sensitive");
        let (_, sensitive) = describe_port(&rule("0.0.0.0/0", Protocol::Tcp, Some(443)));
        assert!(!sensitive, "port 443 is open but not sensitive");
    }

    #[test]
    fn describe_port_no_port_range_is_not_sensitive() {
        let (_, sensitive) = describe_port(&rule("0.0.0.0/0", Protocol::Icmp, None));
        assert!(!sensitive);
    }

    // -- check_network --------------------------------------------------------

    #[test]
    fn check_network_records_cli_and_metadata_for_aws() {
        // AWS has both a CLI name and a metadata URL; both branches run.
        let doctor = Doctor::new(CloudProvider::Aws);
        let mut report = CloudReport::new(CloudProvider::Aws);
        doctor.check_network(&mut report);
        // At least the metadata probe and the CLI check produced findings.
        assert!(!report.findings.is_empty());
        assert!(
            report.findings.iter().any(|f| f.id.starts_with("network.")),
            "expected network.* findings: {:?}",
            report.findings
        );
    }

    #[test]
    fn check_network_skips_for_unknown_provider() {
        let doctor = Doctor::new(CloudProvider::Unknown);
        let mut report = CloudReport::new(CloudProvider::Unknown);
        doctor.check_network(&mut report);
        assert!(
            report.findings.is_empty(),
            "unknown provider has no CLI/metadata to check"
        );
    }

    // -- check_security_groups error path ------------------------------------

    #[test]
    fn check_security_groups_records_list_failure_for_unknown() {
        // Unknown provider: list_security_groups returns ProviderNotFound,
        // which the doctor turns into a single error finding.
        let doctor = Doctor::new(CloudProvider::Unknown);
        let mut report = CloudReport::new(CloudProvider::Unknown);
        doctor.check_security_groups(&mut report);
        assert!(report.has_errors());
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.id == "security-groups.list-failed"),
            "expected list-failed finding: {:?}",
            report.findings
        );
    }

    // -- check_agent ----------------------------------------------------------

    #[test]
    fn check_agent_skips_for_unknown_provider() {
        let doctor = Doctor::new(CloudProvider::Unknown);
        let mut report = CloudReport::new(CloudProvider::Unknown);
        doctor.check_agent(&mut report);
        assert!(report.findings.is_empty());
    }

    #[test]
    fn check_agent_emits_findings_for_known_provider() {
        // For a known provider the ServiceManager is probed. Whether the agent
        // is running/enabled depends on the test host, but we must produce at
        // least one finding (running/not-running or probe-failed).
        let doctor = Doctor::new(CloudProvider::Hetzner);
        let mut report = CloudReport::new(CloudProvider::Hetzner);
        doctor.check_agent(&mut report);
        assert!(
            !report.findings.is_empty(),
            "check_agent should probe the agent service"
        );
    }

    // -- run(All) smoke test --------------------------------------------------

    #[test]
    fn run_all_does_not_error_for_unknown() {
        let doctor = Doctor::new(CloudProvider::Unknown);
        let report = doctor.run(&DoctorScope::All).unwrap();
        // Must not panic and must return a report for the right provider.
        assert_eq!(report.provider, CloudProvider::Unknown);
    }
}
