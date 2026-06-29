//! Doctor module — structured diagnostic checks for UFW.
//!
//! Returns `Vec<Finding>` rather than just text. Each finding has an ID,
//! severity, title, detail, and optional fix suggestion.

use crate::Ufw;
use crate::error::Result;
use crate::spec::{DoctorScope, Finding, ParsedRule, Severity};

/// Run doctor checks and return findings.
pub fn doctor(ufw: &Ufw, scope: DoctorScope) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();

    match scope {
        DoctorScope::All => {
            findings.extend(check_binaries(ufw));
            findings.extend(check_service(ufw));
            findings.extend(check_config(ufw));
            findings.extend(check_policy(ufw));
            findings.extend(check_rules(ufw));
            findings.extend(check_ssh(ufw));
            findings.extend(check_ipv6(ufw));
            findings.extend(check_logging(ufw));
            findings.extend(check_app_profiles(ufw));
            findings.extend(check_permissions(ufw));
            findings.extend(check_docker(ufw));
            findings.extend(check_reverse_proxy(ufw));
            findings.extend(check_routing(ufw));
            #[cfg(feature = "framework")]
            findings.extend(check_framework(ufw));
        }
        DoctorScope::Binaries => findings.extend(check_binaries(ufw)),
        DoctorScope::Service => findings.extend(check_service(ufw)),
        DoctorScope::Policy => findings.extend(check_policy(ufw)),
        DoctorScope::Rules => findings.extend(check_rules(ufw)),
        DoctorScope::Ssh => findings.extend(check_ssh(ufw)),
        DoctorScope::Ipv6 => findings.extend(check_ipv6(ufw)),
        DoctorScope::Logging => findings.extend(check_logging(ufw)),
        DoctorScope::AppProfiles => findings.extend(check_app_profiles(ufw)),
        DoctorScope::Permissions => findings.extend(check_permissions(ufw)),
        DoctorScope::Docker => findings.extend(check_docker(ufw)),
        DoctorScope::Routing => findings.extend(check_routing(ufw)),
    }

    Ok(findings)
}

/// Check that required binaries exist.
#[allow(clippy::too_many_lines)]
fn check_binaries(ufw: &Ufw) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Check ufw binary
    if ufw.find_ufw().is_ok() {
        findings.push(Finding {
            id: "bin:ufw:exists",
            severity: Severity::Ok,
            title: "UFW binary found".into(),
            detail: "The ufw binary is available on this system.".into(),
            fix: None,
        });
    } else {
        findings.push(Finding {
            id: "bin:ufw:missing",
            severity: Severity::Critical,
            title: "UFW binary not found".into(),
            detail: "The ufw binary is not installed or not in PATH.".into(),
            fix: Some(
                "Install ufw: sudo apt install ufw (Debian/Ubuntu) or sudo pacman -S ufw (Arch)"
                    .into(),
            ),
        });
        return findings; // No point checking further
    }

    // Check ufw version
    match ufw.version() {
        Ok(ver) => findings.push(Finding {
            id: "bin:ufw:version",
            severity: Severity::Ok,
            title: "UFW version detected".into(),
            detail: format!("UFW version: {ver}"),
            fix: None,
        }),
        Err(_) => findings.push(Finding {
            id: "bin:ufw:version-fail",
            severity: Severity::Warning,
            title: "Could not read UFW version".into(),
            detail: "ufw --version returned an unexpected response.".into(),
            fix: None,
        }),
    }

    // Check iptables
    let runner = ufw.runner();
    if runner.binary_exists("iptables") {
        findings.push(Finding {
            id: "bin:iptables:exists",
            severity: Severity::Ok,
            title: "iptables binary found".into(),
            detail: "The iptables binary is available on this system.".into(),
            fix: None,
        });
    } else {
        findings.push(Finding {
            id: "bin:iptables:missing",
            severity: Severity::Critical,
            title: "iptables binary not found".into(),
            detail: "The iptables binary is not installed or not in PATH. UFW depends on iptables."
                .into(),
            fix: Some("Install iptables: sudo apt install iptables (Debian/Ubuntu)".into()),
        });
    }

    // Check ip6tables
    if runner.binary_exists("ip6tables") {
        findings.push(Finding {
            id: "bin:ip6tables:exists",
            severity: Severity::Ok,
            title: "ip6tables binary found".into(),
            detail: "The ip6tables binary is available on this system.".into(),
            fix: None,
        });
    } else {
        findings.push(Finding {
            id: "bin:ip6tables:missing",
            severity: Severity::Warning,
            title: "ip6tables binary not found".into(),
            detail: "The ip6tables binary is not installed. IPv6 firewall rules may not function."
                .into(),
            fix: Some(
                "Install iptables for IPv6: sudo apt install iptables (Debian/Ubuntu)".into(),
            ),
        });
    }

    // Check nft (info level — not critical for UFW)
    if runner.binary_exists("nft") {
        findings.push(Finding {
            id: "bin:nft:exists",
            severity: Severity::Info,
            title: "nftables binary found".into(),
            detail:
                "The nft binary is available. Not required for UFW but good for modern systems."
                    .into(),
            fix: None,
        });
    } else {
        findings.push(Finding {
            id: "bin:nft:missing",
            severity: Severity::Info,
            title: "nftables binary not found".into(),
            detail: "The nft binary is not installed. Not required for UFW but useful on modern systems.".into(),
            fix: None,
        });
    }

    // Check systemctl
    if runner.binary_exists("systemctl") {
        findings.push(Finding {
            id: "bin:systemctl:exists",
            severity: Severity::Ok,
            title: "systemctl binary found".into(),
            detail: "The systemctl binary is available on this system.".into(),
            fix: None,
        });
    } else {
        findings.push(Finding {
            id: "bin:systemctl:missing",
            severity: Severity::Warning,
            title: "systemctl binary not found".into(),
            detail:
                "The systemctl binary is not installed. Service management checks will be limited."
                    .into(),
            fix: None,
        });
    }

    findings
}

/// Check UFW service status.
fn check_service(ufw: &Ufw) -> Vec<Finding> {
    let mut findings = Vec::new();

    let status_result = ufw.status();

    match status_result {
        Ok(status) => {
            let ufw_active = status.active;

            if ufw_active {
                findings.push(Finding {
                    id: "svc:ufw:active",
                    severity: Severity::Ok,
                    title: "UFW is active".into(),
                    detail: "The UFW firewall is currently active.".into(),
                    fix: None,
                });
            } else {
                findings.push(Finding {
                    id: "svc:ufw:inactive",
                    severity: Severity::Warning,
                    title: "UFW is inactive".into(),
                    detail: "The UFW firewall is not currently active.".into(),
                    fix: Some("Enable UFW with: ufw enable (after ensuring SSH is allowed)".into()),
                });
            }

            // Check consistency with systemctl
            let runner = ufw.runner();
            if runner.binary_exists("systemctl") {
                let svc_active = crate::service::is_active(runner).ok();
                if let Some(svc) = svc_active {
                    if ufw_active && !svc {
                        findings.push(Finding {
                            id: "svc:ufw:inconsistent",
                            severity: Severity::Warning,
                            title: "UFW status inconsistency detected".into(),
                            detail: "UFW reports active but systemctl reports the service is not active.".into(),
                            fix: Some("Restart the UFW service: sudo systemctl restart ufw".into()),
                        });
                    } else if !ufw_active && svc {
                        findings.push(Finding {
                            id: "svc:systemd:inconsistent",
                            severity: Severity::Warning,
                            title: "UFW status inconsistency detected".into(),
                            detail:
                                "UFW reports inactive but systemctl reports the service is active."
                                    .into(),
                            fix: Some("Check UFW status: sudo ufw status verbose".into()),
                        });
                    }
                }

                // Check if service is enabled (boot-time start)
                let svc_enabled = crate::service::is_enabled(runner).ok();
                if let Some(enabled) = svc_enabled {
                    if ufw_active && !enabled {
                        findings.push(Finding {
                            id: "svc:ufw:not-enabled",
                            severity: Severity::Warning,
                            title: "UFW service not enabled at boot".into(),
                            detail: "UFW is active but the service is not enabled. It may not start after reboot.".into(),
                            fix: Some("Enable the service: sudo systemctl enable ufw".into()),
                        });
                    }
                }

                // Check if boot integration is set up (ufw.service or ufw-enabled.service symlink)
                check_boot_integration(&mut findings);
            }

            // Check default incoming policy and warn if allow
            if let Some(policy) = &status.default_incoming {
                if matches!(policy, crate::spec::Policy::Allow) {
                    findings.push(Finding {
                        id: "svc:pol:incoming-allow",
                        severity: Severity::Warning,
                        title: "Default incoming policy is ALLOW while checking service".into(),
                        detail: "The default incoming policy is set to allow, which is too permissive for most servers.".into(),
                        fix: Some("Set default incoming to deny: sudo ufw default deny incoming".into()),
                    });
                }
            }
        }
        Err(e) => findings.push(Finding {
            id: "svc:ufw:status-fail",
            severity: Severity::Important,
            title: "Could not read UFW status".into(),
            detail: format!("Failed to read UFW status: {e}"),
            fix: Some("Check that ufw is installed and you have sufficient permissions.".into()),
        }),
    }

    findings
}

/// Check UFW configuration files.
#[allow(clippy::too_many_lines)]
fn check_config(ufw: &Ufw) -> Vec<Finding> {
    let mut findings = Vec::new();

    let config_files = [
        "/etc/default/ufw",
        "/etc/ufw/ufw.conf",
        "/etc/ufw/sysctl.conf",
        "/etc/ufw/before.rules",
        "/etc/ufw/after.rules",
    ];

    for path in &config_files {
        if std::path::Path::new(path).exists() {
            findings.push(Finding {
                id: Box::leak(format!("cfg:{}:exists", path.replace('/', ":")).into_boxed_str()),
                severity: Severity::Ok,
                title: format!("{path} exists"),
                detail: format!("Configuration file {path} is present."),
                fix: None,
            });
        } else {
            findings.push(Finding {
                id: Box::leak(format!("cfg:{}:missing", path.replace('/', ":")).into_boxed_str()),
                severity: Severity::Warning,
                title: format!("{path} missing"),
                detail: format!("Configuration file {path} does not exist."),
                fix: Some(format!("Reinstall ufw or create {path} manually.")),
            });
        }
    }

    // Parse /etc/default/ufw using the config module for structured checks
    let default_ufw_config = read_default_ufw_config();
    let ipv6_enabled = default_ufw_config.ipv6.unwrap_or(false);

    // Parse /etc/ufw/ufw.conf using the config module
    let ufw_conf = read_ufw_conf();

    // Check ENABLED consistency between /etc/default/ufw and /etc/ufw/ufw.conf
    if let (Some(default_enabled), Some(conf_enabled)) =
        (default_ufw_config.enabled, ufw_conf.enabled)
    {
        if default_enabled != conf_enabled {
            findings.push(Finding {
                id: "cfg:enabled:inconsistent",
                severity: Severity::Warning,
                title: "ENABLED value inconsistent between config files".into(),
                detail: format!(
                    "/etc/default/ufw has ENABLED={}, but /etc/ufw/ufw.conf has ENABLED={}. \
                     These should agree.",
                    if default_enabled { "yes" } else { "no" },
                    if conf_enabled { "yes" } else { "no" }
                ),
                fix: Some(
                    "Align the ENABLED values in /etc/default/ufw and /etc/ufw/ufw.conf.".into(),
                ),
            });
        }
    }

    // Check that LOGLEVEL in ufw.conf is a valid value
    if let Some(ref level) = ufw_conf.loglevel {
        let valid_levels = ["off", "low", "medium", "high", "full", "on"];
        if !valid_levels.contains(&level.to_lowercase().as_str()) {
            findings.push(Finding {
                id: "cfg:loglevel:invalid",
                severity: Severity::Warning,
                title: "Invalid LOGLEVEL in ufw.conf".into(),
                detail: format!(
                    "LOGLEVEL is set to '{level}' in /etc/ufw/ufw.conf, which is not a recognized value. \
                     Valid values: off, low, medium, high, full, on."
                ),
                fix: Some("Set LOGLEVEL to a valid value in /etc/ufw/ufw.conf.".into()),
            });
        }
    }

    // When IPv6 is enabled, check IPv6-specific files exist
    if ipv6_enabled {
        let ipv6_files = ["/etc/ufw/before6.rules", "/etc/ufw/after6.rules"];
        for path in &ipv6_files {
            if std::path::Path::new(path).exists() {
                findings.push(Finding {
                    id: Box::leak(
                        format!("cfg:{}:exists", path.replace('/', ":")).into_boxed_str(),
                    ),
                    severity: Severity::Ok,
                    title: format!("{path} exists"),
                    detail: format!("IPv6 framework file {path} is present."),
                    fix: None,
                });
            } else {
                findings.push(Finding {
                    id: Box::leak(
                        format!("cfg:{}:missing", path.replace('/', ":")).into_boxed_str(),
                    ),
                    severity: Severity::Warning,
                    title: format!("{path} missing"),
                    detail: format!("IPv6 is enabled but {path} does not exist."),
                    fix: Some(format!(
                        "Reinstall ufw or create {path} to enable IPv6 rules."
                    )),
                });
            }
        }
    }

    // Check that generated app profiles have managed header
    let app_dir = std::path::Path::new("/etc/ufw/applications.d");
    if app_dir.exists() {
        if let Ok(entries) = std::fs::read_dir(app_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    if let Ok(content) = std::fs::read_to_string(&path) {
                        let name = path.file_name().unwrap_or_default().to_string_lossy();
                        // Check if this looks like a generated profile (has [Section] header)
                        let has_section = content
                            .lines()
                            .any(|l| l.trim().starts_with('[') && l.trim().ends_with(']'));
                        if has_section && !content.contains("Managed by ufw-kit") {
                            findings.push(Finding {
                                id: Box::leak(format!("cfg:app:{name}:no-managed-header").into_boxed_str()),
                                severity: Severity::Info,
                                title: format!("App profile {name} lacks managed header"),
                                detail: format!("The app profile at {} has a section header but no 'Managed by ufw-kit' header.", path.display()),
                                fix: None,
                            });
                        }
                    }
                }
            }
        }
    }

    // Silence unused parameter warning — ufw is used for future extensibility
    let _ = ufw;

    findings
}

/// Check default policies.
fn check_policy(ufw: &Ufw) -> Vec<Finding> {
    let mut findings = Vec::new();

    match ufw.status_verbose() {
        Ok(status) => {
            // Check incoming policy
            if let Some(policy) = &status.default_incoming {
                match policy {
                    crate::spec::Policy::Allow => {
                        findings.push(Finding {
                            id: "pol:incoming:allow",
                            severity: Severity::Critical,
                            title: "Incoming allow is dangerously permissive".into(),
                            detail: "The default incoming policy is ALLOW, which means all inbound traffic \
                                     is permitted by default. This effectively disables the firewall for \
                                     incoming connections.".into(),
                            fix: Some("Set default incoming to deny: sudo ufw default deny incoming".into()),
                        });
                    }
                    crate::spec::Policy::Deny | crate::spec::Policy::Reject => {
                        findings.push(Finding {
                            id: "pol:incoming:deny",
                            severity: Severity::Ok,
                            title: "Default incoming policy is secure".into(),
                            detail: format!("Default incoming policy: {policy}"),
                            fix: None,
                        });
                    }
                }
            }

            // Check outgoing policy
            if let Some(policy) = &status.default_outgoing {
                match policy {
                    crate::spec::Policy::Deny | crate::spec::Policy::Reject => {
                        findings.push(Finding {
                            id: "pol:outgoing:deny",
                            severity: Severity::Warning,
                            title: "Default outgoing policy is restrictive".into(),
                            detail: "Outgoing deny can break DNS, NTP, and package updates.".into(),
                            fix: Some("Ensure DNS (53/udp), NTP (123/udp), and HTTPS (443/tcp) are allowed.".into()),
                        });

                        // When outgoing is deny/reject, check if DNS/NTP/HTTPS rules exist
                        check_essential_outgoing_rules(ufw, &mut findings);
                    }
                    crate::spec::Policy::Allow => {
                        findings.push(Finding {
                            id: "pol:outgoing:allow",
                            severity: Severity::Ok,
                            title: "Default outgoing policy is allow".into(),
                            detail: "Default outgoing policy: allow".into(),
                            fix: None,
                        });
                    }
                }
            }

            // Check routed/forwarded policy
            if let Some(policy) = &status.default_routed {
                match policy {
                    crate::spec::Policy::Allow => {
                        findings.push(Finding {
                            id: "pol:routed:allow",
                            severity: Severity::Warning,
                            title: "Default routed policy is ALLOW (accept)".into(),
                            detail:
                                "The default routed/forwarded policy is accept. This can expose \
                                     internal networks if forwarding is enabled."
                                    .into(),
                            fix: Some(
                                "Set default routed to deny: sudo ufw default deny routed".into(),
                            ),
                        });
                    }
                    crate::spec::Policy::Deny | crate::spec::Policy::Reject => {
                        findings.push(Finding {
                            id: "pol:routed:deny",
                            severity: Severity::Ok,
                            title: "Default routed policy is secure".into(),
                            detail: format!("Default routed/forwarded policy: {policy}"),
                            fix: None,
                        });
                    }
                }
            } else {
                // Routed policy not explicitly set — report as info
                findings.push(Finding {
                    id: "pol:routed:unset",
                    severity: Severity::Info,
                    title: "Default routed policy not set".into(),
                    detail: "The default routed/forwarded policy is not explicitly configured."
                        .into(),
                    fix: None,
                });
            }
        }
        Err(e) => findings.push(Finding {
            id: "pol:status-fail",
            severity: Severity::Important,
            title: "Could not check policies".into(),
            detail: format!("Failed to read verbose status: {e}"),
            fix: None,
        }),
    }

    findings
}

/// Check that essential outgoing rules (DNS, NTP, HTTPS) exist when outgoing policy is deny.
fn check_essential_outgoing_rules(ufw: &Ufw, findings: &mut Vec<Finding>) {
    if let Ok(status) = ufw.status() {
        let rules_text: String = status
            .rules
            .iter()
            .map(|r| r.raw.to_lowercase())
            .collect::<Vec<_>>()
            .join("\n");

        // DNS (53)
        let has_dns = rules_text.contains("53")
            && (rules_text.contains("udp")
                || rules_text.contains("53/udp")
                || rules_text.contains("domain"));
        if !has_dns {
            findings.push(Finding {
                id: "pol:outgoing:no-dns",
                severity: Severity::Warning,
                title: "No DNS rule with restrictive outgoing policy".into(),
                detail: "Outgoing traffic is denied but no DNS (53/udp) allow rule was found. DNS resolution will fail.".into(),
                fix: Some("Add a DNS allow rule: ufw allow out 53/udp".into()),
            });
        }

        // NTP (123)
        let has_ntp = rules_text.contains("123")
            && (rules_text.contains("udp")
                || rules_text.contains("123/udp")
                || rules_text.contains("ntp"));
        if !has_ntp {
            findings.push(Finding {
                id: "pol:outgoing:no-ntp",
                severity: Severity::Warning,
                title: "No NTP rule with restrictive outgoing policy".into(),
                detail: "Outgoing traffic is denied but no NTP (123/udp) allow rule was found. Clock sync will fail.".into(),
                fix: Some("Add an NTP allow rule: ufw allow out 123/udp".into()),
            });
        }

        // HTTPS (443)
        let has_https = rules_text.contains("443")
            && (rules_text.contains("tcp")
                || rules_text.contains("443/tcp")
                || rules_text.contains("https"));
        if !has_https {
            findings.push(Finding {
                id: "pol:outgoing:no-https",
                severity: Severity::Warning,
                title: "No HTTPS rule with restrictive outgoing policy".into(),
                detail: "Outgoing traffic is denied but no HTTPS (443/tcp) allow rule was found. Package updates and API calls will fail.".into(),
                fix: Some("Add an HTTPS allow rule: ufw allow out 443/tcp".into()),
            });
        }
    }
}

/// Check rules for safety issues.
fn check_rules(ufw: &Ufw) -> Vec<Finding> {
    let mut findings = Vec::new();

    match ufw.status() {
        Ok(status) => {
            // Check for dangerous ports
            for rule in &status.rules {
                let raw = rule.raw.to_lowercase();
                for &(port, name) in crate::net::DANGEROUS_PORTS {
                    if raw.contains(&port.to_string()) && raw.contains("allow") {
                        findings.push(Finding {
                            id: Box::leak(format!("rule:dangerous:{port}").into_boxed_str()),
                            severity: Severity::Warning,
                            title: format!("Port {port} ({name}) is exposed"),
                            detail: format!("Rule exposes port {port} ({name}): {}", rule.raw),
                            fix: Some(format!(
                                "Consider restricting access to port {port} from trusted IPs only."
                            )),
                        });
                    }
                }
            }

            // Check for broad allow rules
            for rule in &status.rules {
                let raw = rule.raw.to_lowercase();
                if raw.contains("allow") && raw.contains("anywhere") {
                    findings.push(Finding {
                        id: "rule:broad:allow-anywhere",
                        severity: Severity::Info,
                        title: "Broad allow rule detected".into(),
                        detail: format!("Rule allows traffic from anywhere: {}", rule.raw),
                        fix: Some(
                            "Consider restricting source to specific IPs or CIDR ranges.".into(),
                        ),
                    });
                }
            }

            // Detect duplicate rules (same raw text appearing twice)
            let mut seen_raw: std::collections::HashMap<&str, usize> =
                std::collections::HashMap::new();
            for rule in &status.rules {
                let count = seen_raw.entry(&rule.raw).or_insert(0);
                *count += 1;
                if *count == 2 {
                    // Only report on the second occurrence
                    findings.push(Finding {
                        id: "rule:duplicate",
                        severity: Severity::Warning,
                        title: "Duplicate rule detected".into(),
                        detail: format!("Rule appears more than once: {}", rule.raw),
                        fix: Some("Remove the duplicate rule: ufw delete 'the rule'".into()),
                    });
                }
            }

            // Check for rules without comments
            for rule in &status.rules {
                if rule.comment.is_none()
                    || rule.comment.as_deref().is_none_or(|c| c.trim().is_empty())
                {
                    findings.push(Finding {
                        id: "rule:no-comment",
                        severity: Severity::Info,
                        title: "Rule without comment".into(),
                        detail: format!("Rule has no comment annotation: {}", rule.raw),
                        fix: Some(
                            "Consider adding a comment: ufw ... comment 'description'".into(),
                        ),
                    });
                }
            }

            // Check managed comment prefix validation
            for rule in &status.rules {
                if let Some(comment) = &rule.comment {
                    if comment.contains("managed:") {
                        // Validate the managed prefix format
                        let parts: Vec<&str> = comment.splitn(2, ':').collect();
                        if parts.len() < 2 || parts[1].trim().is_empty() {
                            findings.push(Finding {
                                id: "rule:managed:bad-prefix",
                                severity: Severity::Info,
                                title: "Managed rule has empty prefix label".into(),
                                detail: format!("Rule comment '{comment}' has a managed: prefix but no label."),
                                fix: Some("Update the rule comment with a descriptive label after 'managed:'.".into()),
                            });
                        }
                    }
                }
            }

            // Check for shadowed rules: if an earlier allow and a later deny target
            // the same port/direction, the deny is shadowed and never fires.
            check_shadowed_rules(&status.rules, &mut findings);

            // Check for IPv4/IPv6 dual-stack coverage
            check_dual_stack_coverage(&status.rules, &mut findings);
        }
        Err(e) => findings.push(Finding {
            id: "rule:status-fail",
            severity: Severity::Important,
            title: "Could not check rules".into(),
            detail: format!("Failed to read status: {e}"),
            fix: None,
        }),
    }

    findings
}

/// Check SSH access safety.
fn check_ssh(ufw: &Ufw) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Check if running over an active SSH connection
    if is_active_ssh_session() {
        findings.push(Finding {
            id: "ssh:active-session",
            severity: Severity::Info,
            title: "Active SSH session detected".into(),
            detail: "An active SSH connection was detected (SSH_CONNECTION env var is set). \
                     Be careful when modifying firewall rules — an incorrect change could \
                     lock you out of this session."
                .into(),
            fix: None,
        });
    }

    if let Ok(status) = ufw.status() {
        let ssh_rules: Vec<_> = status
            .rules
            .iter()
            .filter(|rule| {
                let raw = rule.raw.to_lowercase();
                raw.contains("22") || raw.contains("ssh")
            })
            .collect();

        let has_ssh_rule = !ssh_rules.is_empty();

        if status.active {
            if has_ssh_rule {
                findings.push(Finding {
                    id: "ssh:allowed",
                    severity: Severity::Ok,
                    title: "SSH access is allowed".into(),
                    detail: "An SSH allow rule exists in the firewall.".into(),
                    fix: None,
                });
                analyze_ssh_rule_details(&ssh_rules, &mut findings);
            } else {
                findings.push(Finding {
                    id: "ssh:no-rule",
                    severity: Severity::Critical,
                    title: "No SSH allow rule found".into(),
                    detail: "UFW is active but no SSH allow rule exists. This may lock you out."
                        .into(),
                    fix: Some("Add SSH allow rule: ufw allow 22/tcp".into()),
                });
            }
        }
    }

    findings
}

/// Inspect an SSH allow rule for rate-limiting, interface scoping, source
/// exposure, and VPN binding — appending one `Finding` per detected property.
fn analyze_ssh_rule_details(ssh_rules: &[&ParsedRule], findings: &mut Vec<Finding>) {
    // Check if SSH rule uses "limit" action (good practice)
    let uses_limit = ssh_rules
        .iter()
        .any(|rule| rule.raw.to_lowercase().contains("limit"));
    if uses_limit {
        findings.push(Finding {
            id: "ssh:limit",
            severity: Severity::Ok,
            title: "SSH uses rate limiting".into(),
            detail: "The SSH rule uses the 'limit' action, which provides brute-force protection."
                .into(),
            fix: None,
        });
    }

    // Check if SSH rule is scoped to a specific interface (info)
    let scoped_to_interface = ssh_rules.iter().any(|rule| {
        let raw = rule.raw.to_lowercase();
        raw.contains("on ") || raw.contains("in on ") || raw.contains("out on ")
    });
    if scoped_to_interface {
        findings.push(Finding {
            id: "ssh:interface-scoped",
            severity: Severity::Info,
            title: "SSH rule is interface-scoped".into(),
            detail: "At least one SSH rule is scoped to a specific network interface.".into(),
            fix: None,
        });
    }

    // Check if SSH rule allows from anywhere (warning)
    let allows_anywhere = ssh_rules.iter().any(|rule| {
        let raw = rule.raw.to_lowercase();
        (raw.contains("anywhere") || raw.contains("0.0.0.0") || raw.contains("::/0"))
            && raw.contains("allow")
    });
    if allows_anywhere {
        findings.push(Finding {
            id: "ssh:allow-anywhere",
            severity: Severity::Warning,
            title: "SSH allows from any source".into(),
            detail: "An SSH rule allows connections from any source address. \
                     This exposes SSH to brute-force attacks from the entire internet."
                .into(),
            fix: Some(
                "Restrict SSH to trusted IPs: sudo ufw allow from <trusted-ip> to any port 22 proto tcp"
                    .into(),
            ),
        });
    }

    // Check if Tailscale or WireGuard interface is present in SSH rules
    let vpn_interfaces = ["tailscale", "wg", "wg0", "wg1", "tailscale0"];
    let has_vpn = ssh_rules.iter().any(|rule| {
        let raw = rule.raw.to_lowercase();
        vpn_interfaces.iter().any(|iface| raw.contains(iface))
    });
    if has_vpn {
        findings.push(Finding {
            id: "ssh:vpn-interface",
            severity: Severity::Info,
            title: "SSH rule references VPN interface".into(),
            detail: "At least one SSH rule is scoped to a Tailscale or WireGuard interface, \
                     which restricts SSH access to VPN peers."
                .into(),
            fix: None,
        });
    }
}

/// Check IPv6 configuration.
#[allow(clippy::too_many_lines)]
fn check_ipv6(ufw: &Ufw) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Read /etc/default/ufw using the config module instead of raw fs::read
    let ipv6_enabled = read_ipv6_enabled_from_config();

    if ipv6_enabled {
        findings.push(Finding {
            id: "ipv6:enabled",
            severity: Severity::Ok,
            title: "IPv6 is enabled in UFW".into(),
            detail: "IPV6=yes is set in /etc/default/ufw.".into(),
            fix: None,
        });

        // Check for IPv6 rules
        if let Ok(status) = ufw.status() {
            let ipv6_rules: Vec<_> = status.rules.iter().filter(|r| r.ipv6).collect();
            if ipv6_rules.is_empty() {
                findings.push(Finding {
                    id: "ipv6:no-rules",
                    severity: Severity::Info,
                    title: "No IPv6-specific rules".into(),
                    detail: "IPv6 is enabled but no IPv6-specific rules were found.".into(),
                    fix: Some("Consider adding IPv6 rules for dual-stack coverage.".into()),
                });
            } else {
                findings.push(Finding {
                    id: "ipv6:rules-found",
                    severity: Severity::Ok,
                    title: "IPv6 rules present".into(),
                    detail: format!("Found {} IPv6-specific rule(s).", ipv6_rules.len()),
                    fix: None,
                });
            }
        }

        // Check IPv6 default policies match IPv4
        if let Ok(status) = ufw.status_verbose() {
            let v4_incoming = status.default_incoming;
            // Read the config file to get the configured IPv6 policy
            let config = read_default_ufw_config();

            if let (Some(v4_pol), Some(ipv6_pol_str)) = (&v4_incoming, &config.default_input_policy)
            {
                let v4_str = v4_pol.to_string().to_lowercase();
                if v4_str != ipv6_pol_str.to_lowercase() {
                    findings.push(Finding {
                        id: "ipv6:policy-mismatch",
                        severity: Severity::Warning,
                        title: "IPv6 input policy differs from IPv4".into(),
                        detail: format!("IPv4 incoming policy is {v4_str} but IPv6 (DEFAULT_INPUT_POLICY) is set to {ipv6_pol_str}."),
                        fix: Some("Align IPv6 policy with IPv4 in /etc/default/ufw.".into()),
                    });
                }
            }

            // Check IPv6 routed/forward policy matches IPv4
            let v4_routed = status.default_routed;
            if let (Some(v4_pol), Some(ipv6_fwd_str)) = (&v4_routed, &config.default_forward_policy)
            {
                let v4_str = v4_pol.to_string().to_lowercase();
                if v4_str != ipv6_fwd_str.to_lowercase() {
                    findings.push(Finding {
                        id: "ipv6:forward-policy-mismatch",
                        severity: Severity::Warning,
                        title: "IPv6 forward policy differs from IPv4 routed".into(),
                        detail: format!("IPv4 routed policy is {v4_str} but IPv6 DEFAULT_FORWARD_POLICY is set to {ipv6_fwd_str}."),
                        fix: Some("Align IPv6 forward policy with IPv4 routed in /etc/default/ufw.".into()),
                    });
                }
            }
        }

        // Check for IPv6 route rules
        if let Ok(status) = ufw.status() {
            let ipv6_route_rules: Vec<_> = status
                .rules
                .iter()
                .filter(|r| r.ipv6 && r.is_route)
                .collect();
            if !ipv6_route_rules.is_empty() {
                findings.push(Finding {
                    id: "ipv6:route-rules",
                    severity: Severity::Info,
                    title: "IPv6 route rules present".into(),
                    detail: format!(
                        "Found {} IPv6 route/forward rule(s). Ensure they match your network topology.",
                        ipv6_route_rules.len()
                    ),
                    fix: None,
                });
            }
        }

        // Check for IPv6 listening ports exposure via firewall show listening
        if let Ok(listening_output) = ufw.show(crate::spec::UfwReport::Listening) {
            let ipv6_listening: Vec<_> = listening_output
                .lines()
                .filter(|l| l.contains("[::]") || l.contains(":::"))
                .collect();
            if !ipv6_listening.is_empty() {
                findings.push(Finding {
                    id: "ipv6:listening-exposed",
                    severity: Severity::Info,
                    title: "Services listening on IPv6".into(),
                    detail: format!(
                        "Found {} service(s) listening on IPv6 wildcard addresses ([::] or :::port). \
                         Ensure IPv6 firewall rules restrict access as needed.",
                        ipv6_listening.len()
                    ),
                    fix: None,
                });
            }
        }
    } else {
        findings.push(Finding {
            id: "ipv6:disabled",
            severity: Severity::Info,
            title: "IPv6 is disabled in UFW".into(),
            detail: "IPV6 is not set to 'yes' in /etc/default/ufw.".into(),
            fix: Some("Enable IPv6 if your VPS has a public IPv6 address.".into()),
        });
    }

    findings
}

/// Check logging configuration.
fn check_logging(ufw: &Ufw) -> Vec<Finding> {
    let mut findings = Vec::new();

    if let Ok(status) = ufw.status_verbose() {
        if let Some(level) = &status.logging_level {
            match level {
                crate::spec::LoggingLevel::Off => {
                    findings.push(Finding {
                        id: "log:off",
                        severity: Severity::Warning,
                        title: "Logging is disabled".into(),
                        detail:
                            "UFW logging is currently off. This makes troubleshooting difficult."
                                .into(),
                        fix: Some("Enable logging: ufw logging on".into()),
                    });
                }
                crate::spec::LoggingLevel::High | crate::spec::LoggingLevel::Full => {
                    findings.push(Finding {
                        id: "log:high",
                        severity: Severity::Warning,
                        title: "Logging level is high/full".into(),
                        detail: format!("Logging level: {level}. This can generate significant disk I/O."),
                        fix: Some("Consider using 'low' or 'medium' logging, or per-rule logging instead.".into()),
                    });
                }
                crate::spec::LoggingLevel::Low
                | crate::spec::LoggingLevel::Medium
                | crate::spec::LoggingLevel::On => {
                    findings.push(Finding {
                        id: "log:ok",
                        severity: Severity::Ok,
                        title: "Logging level is reasonable".into(),
                        detail: format!("Logging level: {level}"),
                        fix: None,
                    });
                }
            }
        } else {
            // No logging level reported
            findings.push(Finding {
                id: "log:unknown",
                severity: Severity::Info,
                title: "Logging level unknown".into(),
                detail: "Could not determine the UFW logging level.".into(),
                fix: None,
            });
        }
    }

    // Check if UFW log file exists and its size
    let log_paths = ["/var/log/ufw.log", "/var/log/syslog", "/var/log/kern.log"];
    for log_path in &log_paths {
        if let Ok(meta) = std::fs::metadata(log_path) {
            let nbytes = meta.len();
            check_log_file_size(log_path, nbytes, &mut findings);
            // Only report on the first log file found
            break;
        }
    }

    findings
}

/// Check application profiles.
fn check_app_profiles(ufw: &Ufw) -> Vec<Finding> {
    let mut findings = Vec::new();

    match ufw.app_list() {
        Ok(list) => {
            if list.trim().is_empty() || list.contains("No profiles") {
                findings.push(Finding {
                    id: "app:none",
                    severity: Severity::Info,
                    title: "No application profiles".into(),
                    detail: "No UFW application profiles are installed.".into(),
                    fix: None,
                });
            } else {
                findings.push(Finding {
                    id: "app:exists",
                    severity: Severity::Ok,
                    title: "Application profiles found".into(),
                    detail: format!("Installed profiles:\n{list}"),
                    fix: None,
                });

                // Validate each profile by trying to get info
                for line in list.lines() {
                    let trimmed = line.trim();
                    // Skip header lines
                    if trimmed.is_empty() || trimmed.starts_with("Available") {
                        continue;
                    }
                    // Extract profile name (strip leading whitespace/bullets)
                    let name = trimmed
                        .trim_start_matches(|c: char| c.is_whitespace() || c == '*' || c == '-');

                    // Check app name validity
                    if let Err(e) = validate_app_name_for_doctor(name) {
                        findings.push(Finding {
                            id: Box::leak(format!("app:name-invalid:{name}").into_boxed_str()),
                            severity: Severity::Warning,
                            title: format!("Invalid app profile name: {name}"),
                            detail: format!("App profile name '{name}' is invalid: {e}"),
                            fix: Some("Rename the profile to use only alphanumeric characters, hyphens, and underscores.".into()),
                        });
                        continue;
                    }

                    // Try to get info about the profile to validate it
                    match ufw.app_info(name) {
                        Ok(info) => {
                            // Check port specs in the info output
                            if let Some(ports_line) = info.lines().find(|l| l.contains("Port")) {
                                if let Some(ports_str) = ports_line.split(':').nth(1) {
                                    for port_spec in ports_str.split(',') {
                                        let port_spec = port_spec.trim();
                                        if !port_spec.is_empty() && !is_valid_port_spec(port_spec) {
                                            findings.push(Finding {
                                                id: Box::leak(format!("app:port-invalid:{name}:{port_spec}").into_boxed_str()),
                                                severity: Severity::Warning,
                                                title: format!("Invalid port spec in profile {name}"),
                                                detail: format!("Port spec '{port_spec}' in profile '{name}' does not match expected format (port/proto)."),
                                                fix: Some("Fix the port specification in the profile file.".into()),
                                            });
                                        }
                                    }
                                }
                            }
                        }
                        Err(_) => {
                            findings.push(Finding {
                                id: Box::leak(format!("app:info-fail:{name}").into_boxed_str()),
                                severity: Severity::Info,
                                title: format!("Could not read info for profile {name}"),
                                detail: format!("Failed to parse app profile '{name}'."),
                                fix: None,
                            });
                        }
                    }
                }
            }
        }
        Err(e) => findings.push(Finding {
            id: "app:list-fail",
            severity: Severity::Warning,
            title: "Could not list app profiles".into(),
            detail: format!("Failed to list app profiles: {e}"),
            fix: None,
        }),
    }

    // Cross-reference: check if any rules reference app profiles that do not exist
    check_app_profile_references(ufw, &mut findings);

    // Check if any app profiles have ports that conflict with each other
    check_app_profile_port_conflicts(ufw, &mut findings);

    findings
}

/// Check file permissions.
fn check_permissions(ufw: &Ufw) -> Vec<Finding> {
    let mut findings = Vec::new();

    let paths_to_check = [
        "/etc/ufw",
        "/etc/default/ufw",
        "/etc/ufw/applications.d",
        // Backup directory (typically /etc/ufw/.bak or similar)
        "/etc/ufw/user.rules",
        "/etc/ufw/user6.rules",
        // Framework files
        "/etc/ufw/before.rules",
        "/etc/ufw/after.rules",
    ];

    for path in &paths_to_check {
        check_path_permissions(path, &mut findings);
    }

    // Check app profile directory separately for non-world-readable
    check_path_permissions("/etc/ufw/applications.d", &mut findings);

    // Check file ownership: /etc/ufw and its contents should be owned by root
    check_file_ownership(&mut findings);

    // Check for secrets in rule comments (cross-reference with spec validation)
    check_secrets_in_comments(ufw, &mut findings);

    findings
}

/// Check permissions on a single path and push findings.
fn check_path_permissions(path: &str, findings: &mut Vec<Finding>) {
    match std::fs::metadata(path) {
        Ok(meta) => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = meta.permissions().mode();
                if mode & 0o002 != 0 {
                    findings.push(Finding {
                        id: Box::leak(
                            format!("perm:{}:world-writable", path.replace('/', ":"))
                                .into_boxed_str(),
                        ),
                        severity: Severity::Warning,
                        title: format!("{path} is world-writable"),
                        detail: format!(
                            "{path} has permissions {:o}, which is world-writable.",
                            mode & 0o777
                        ),
                        fix: Some(format!("Fix permissions: sudo chmod o-w {path}")),
                    });
                } else {
                    findings.push(Finding {
                        id: Box::leak(
                            format!("perm:{}:ok", path.replace('/', ":")).into_boxed_str(),
                        ),
                        severity: Severity::Ok,
                        title: format!("{path} permissions OK"),
                        detail: format!("{path} has permissions {:o}.", mode & 0o777),
                        fix: None,
                    });
                }
            }
            #[cfg(not(unix))]
            {
                findings.push(Finding {
                    id: Box::leak(format!("perm:{}:skip", path.replace('/', ":")).into_boxed_str()),
                    severity: Severity::Info,
                    title: format!("Cannot check {path} permissions"),
                    detail: "Permission checks require Unix.".into(),
                    fix: None,
                });
            }
        }
        Err(_) => {
            findings.push(Finding {
                id: Box::leak(format!("perm:{}:missing", path.replace('/', ":")).into_boxed_str()),
                severity: Severity::Info,
                title: format!("{path} not found"),
                detail: format!("{path} does not exist."),
                fix: None,
            });
        }
    }
}

// ── Helper functions ──────────────────────────────────────────────

/// Check log file size and add findings if too large.
fn check_log_file_size(log_path: &str, nbytes: u64, findings: &mut Vec<Finding>) {
    const HUNDRED_MB: u64 = 100 * 1024 * 1024;
    // Precision loss from u64->f64 is acceptable for display purposes;
    // file sizes beyond 2^53 bytes (8 PB) will not be encountered.
    #[allow(clippy::cast_precision_loss)]
    let megabytes = nbytes as f64 / (1024.0 * 1024.0);
    #[allow(clippy::cast_precision_loss)]
    let kilobytes = nbytes as f64 / 1024.0;

    if nbytes > HUNDRED_MB {
        findings.push(Finding {
            id: Box::leak(
                format!("log:{}:large", log_path.replace('/', ":"))
                    .into_boxed_str(),
            ),
            severity: Severity::Warning,
            title: format!("{log_path} is very large ({megabytes:.1} MB)"),
            detail: format!(
                "{log_path} is {megabytes:.1} MB, which could fill disk space. Consider rotating logs."
            ),
            fix: Some("Set up log rotation or reduce logging level. \
                      You can also truncate: sudo truncate -s 0 {log_path}".into()),
        });
    } else {
        findings.push(Finding {
            id: Box::leak(format!("log:{}:ok", log_path.replace('/', ":")).into_boxed_str()),
            severity: Severity::Ok,
            title: format!("{log_path} exists ({kilobytes:.1} KB)"),
            detail: format!("Log file {log_path} is {kilobytes:.1} KB."),
            fix: None,
        });
    }
}

/// Read whether IPv6 is enabled from /etc/default/ufw using the config module.
fn read_ipv6_enabled_from_config() -> bool {
    read_default_ufw_config().ipv6.unwrap_or(false)
}

/// Check if the current process is running over an SSH connection.
///
/// Detects SSH by checking the `SSH_CONNECTION` environment variable,
/// which is set by the SSH daemon for interactive sessions.
fn is_active_ssh_session() -> bool {
    std::env::var("SSH_CONNECTION").is_ok()
}

/// Detect SSH listening port from `ss` output or common defaults.
///
/// Returns a list of ports that SSH appears to be listening on.
#[allow(dead_code)]
fn detect_ssh_ports(runner: &dyn crate::command::CommandRunner) -> Vec<u16> {
    let mut ports = vec![22]; // Default

    let spec = crate::spec::CommandSpec {
        program: "ss".into(),
        args: vec!["-tlnp".into()],
        timeout: Some(std::time::Duration::from_secs(5)),
        requires_root: false,
        force_c_locale: true,
        redact_logs: false,
    };

    if let Ok(result) = runner.run(&spec) {
        if result.exit_code == Some(0) {
            for line in result.stdout.lines() {
                let lower = line.to_ascii_lowercase();
                if lower.contains("ssh") {
                    // Extract port from address like "0.0.0.0:22" or "[::]:22"
                    if let Some(addr_part) = lower.rsplit(':').next() {
                        if let Ok(port) = addr_part.trim().parse::<u16>() {
                            if !ports.contains(&port) {
                                ports.push(port);
                            }
                        }
                    }
                }
            }
        }
    }

    ports
}

/// Read and parse /etc/default/ufw using the config module.
fn read_default_ufw_config() -> crate::spec::UfwConfig {
    std::fs::read_to_string("/etc/default/ufw")
        .ok()
        .map(|content| crate::config::parse_default_ufw(&content))
        .unwrap_or_default()
}

/// Read and parse /etc/ufw/ufw.conf using the config module.
fn read_ufw_conf() -> crate::spec::UfwConf {
    std::fs::read_to_string("/etc/ufw/ufw.conf")
        .ok()
        .map(|content| crate::config::parse_ufw_conf(&content))
        .unwrap_or_default()
}

/// Validate an app name for doctor purposes.
/// Returns Ok if the name is valid, Err with a description otherwise.
fn validate_app_name_for_doctor(name: &str) -> std::result::Result<(), String> {
    if name.is_empty() {
        return Err("empty name".into());
    }
    if name.contains('\n') {
        return Err("contains newline".into());
    }
    if name.contains("..") || name.contains('/') {
        return Err("contains path traversal".into());
    }
    // Check for valid characters: alphanumeric, hyphens, underscores, spaces
    if !name
        .chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == ' ' || c == '.')
    {
        return Err("contains special characters".into());
    }
    Ok(())
}

/// Check if a port spec string is valid (e.g., "80/tcp", "443/udp", "8080:8081/tcp").
fn is_valid_port_spec(spec: &str) -> bool {
    let spec = spec.trim();
    if spec.is_empty() {
        return false;
    }

    // Must contain a / separating port from protocol
    let parts: Vec<&str> = spec.rsplitn(2, '/').collect();
    if parts.len() != 2 {
        return false;
    }

    let proto = parts[0].trim(); // after rsplit, proto comes first
    let port = parts[1].trim(); // port comes second

    // Validate protocol
    if proto != "tcp" && proto != "udp" {
        return false;
    }

    // Validate port part: single port, range, or list
    // Single port
    if let Ok(p) = port.parse::<u16>() {
        return p > 0;
    }

    // Range (e.g., "8000:9000")
    if port.contains(':') {
        let range_parts: Vec<&str> = port.split(':').collect();
        if range_parts.len() == 2 {
            if let (Ok(s), Ok(e)) = (range_parts[0].parse::<u16>(), range_parts[1].parse::<u16>()) {
                return s > 0 && e > 0 && s <= e;
            }
        }
    }

    true // Allow named ports and other formats we can't easily validate
}

/// Check if boot integration is set up (ufw.service or ufw-enabled.service).
fn check_boot_integration(findings: &mut Vec<Finding>) {
    let systemd_paths = [
        "/etc/systemd/system/ufw.service",
        "/lib/systemd/system/ufw.service",
        "/etc/systemd/system/multi-user.target.wants/ufw.service",
    ];

    let found = systemd_paths
        .iter()
        .any(|p| std::path::Path::new(p).exists());

    if found {
        findings.push(Finding {
            id: "svc:boot:integrated",
            severity: Severity::Ok,
            title: "UFW boot integration is set up".into(),
            detail: "A systemd unit file for UFW was found. UFW will start at boot.".into(),
            fix: None,
        });
    } else {
        findings.push(Finding {
            id: "svc:boot:no-unit",
            severity: Severity::Info,
            title: "No UFW systemd unit file found".into(),
            detail: "No ufw.service unit file was found in standard systemd paths. \
                     UFW may rely on its own init script instead of systemd."
                .into(),
            fix: None,
        });
    }
}

/// Detect shadowed rules: if an earlier allow and a later deny target the same
/// port and direction, the deny is shadowed and will never fire.
fn check_shadowed_rules(rules: &[crate::spec::ParsedRule], findings: &mut Vec<Finding>) {
    // Build a list of (index, direction, port_str, is_allow) from raw text.
    let mut parsed: Vec<(usize, Option<crate::spec::Direction>, String, bool)> = Vec::new();

    for (i, rule) in rules.iter().enumerate() {
        let raw_lower = rule.raw.to_lowercase();
        let is_allow = raw_lower.contains("allow") || raw_lower.contains("limit");
        let is_deny = raw_lower.contains("deny") || raw_lower.contains("reject");

        if !is_allow && !is_deny {
            continue;
        }

        // Extract a port identifier from the raw text.
        // Look for patterns like "22/tcp", "443", "8080/tcp", etc.
        let port_str = extract_port_from_raw(&raw_lower);
        if port_str.is_empty() {
            continue;
        }

        parsed.push((i, rule.direction, port_str, is_allow));
    }

    // For each deny rule, check if there's an earlier allow with the same port and direction.
    for (idx, dir, port, is_allow) in &parsed {
        if *is_allow {
            continue;
        }

        let is_shadowed = parsed.iter().any(
            |(earlier_idx, earlier_dir, earlier_port, earlier_is_allow)| {
                *earlier_idx < *idx
                    && *earlier_is_allow
                    && earlier_port == port
                    && (earlier_dir == dir || earlier_dir.is_none() || dir.is_none())
            },
        );

        if is_shadowed {
            let rule_text = &rules[*idx].raw;
            findings.push(Finding {
                id: "rule:shadowed",
                severity: Severity::Warning,
                title: "Shadowed deny/reject rule detected".into(),
                detail: format!(
                    "Rule at position {} ('{}') is shadowed by an earlier allow rule \
                     on the same port. The deny/reject will never match.",
                    idx + 1,
                    rule_text
                ),
                fix: Some(
                    "Reorder rules so the deny/reject comes before the allow, \
                     or remove the shadowed rule."
                        .into(),
                ),
            });
        }
    }
}

/// Extract a port identifier from raw rule text (lowercase).
fn extract_port_from_raw(raw_lower: &str) -> String {
    // Look for patterns: "NNNN/tcp", "NNNN/udp", or a standalone number
    // in the first few whitespace-separated tokens (the "To" column).
    for token in raw_lower.split_whitespace().take(3) {
        // "22/tcp", "443/tcp", etc.
        if let Some(slash_pos) = token.find('/') {
            let port_part = &token[..slash_pos];
            if port_part.parse::<u16>().is_ok() {
                return token.to_string();
            }
        }
        // Standalone number (e.g., "22" in "22 ALLOW IN")
        if token.parse::<u16>().is_ok() {
            return token.to_string();
        }
    }
    String::new()
}

/// Check for IPv4/IPv6 dual-stack coverage: if there are IPv4 rules but no
/// corresponding IPv6 rules (or vice versa), suggest dual-stack coverage.
fn check_dual_stack_coverage(rules: &[crate::spec::ParsedRule], findings: &mut Vec<Finding>) {
    let ipv4_rules: Vec<_> = rules.iter().filter(|r| !r.ipv6).collect();
    let ipv6_rules: Vec<_> = rules.iter().filter(|r| r.ipv6).collect();

    if ipv4_rules.is_empty() && ipv6_rules.is_empty() {
        return;
    }

    // If there are IPv4 rules but no IPv6 rules (or vice versa), note it.
    if !ipv4_rules.is_empty() && ipv6_rules.is_empty() {
        findings.push(Finding {
            id: "rule:ipv4-only",
            severity: Severity::Info,
            title: "Rules exist only for IPv4".into(),
            detail: format!(
                "Found {} IPv4 rule(s) but no IPv6 rules. If IPv6 is enabled, \
                 consider adding equivalent IPv6 rules for dual-stack coverage.",
                ipv4_rules.len()
            ),
            fix: Some(
                "Add IPv6 equivalents of your IPv4 rules, or use UFW's dual-stack support.".into(),
            ),
        });
    } else if ipv4_rules.is_empty() && !ipv6_rules.is_empty() {
        findings.push(Finding {
            id: "rule:ipv6-only",
            severity: Severity::Info,
            title: "Rules exist only for IPv6".into(),
            detail: format!(
                "Found {} IPv6 rule(s) but no IPv4 rules. Most services also need IPv4 rules.",
                ipv6_rules.len()
            ),
            fix: Some("Add IPv4 equivalents of your IPv6 rules.".into()),
        });
    }
}

/// Check file ownership: /etc/ufw and key config files should be owned by root.
fn check_file_ownership(findings: &mut Vec<Finding>) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        let paths = ["/etc/ufw", "/etc/default/ufw", "/etc/ufw/ufw.conf"];
        for path in &paths {
            if let Ok(meta) = std::fs::metadata(path) {
                let uid = meta.uid();
                if uid != 0 {
                    findings.push(Finding {
                        id: Box::leak(
                            format!("perm:{}:not-root-owned", path.replace('/', ":"))
                                .into_boxed_str(),
                        ),
                        severity: Severity::Warning,
                        title: format!("{path} is not owned by root"),
                        detail: format!(
                            "{path} is owned by UID {uid} instead of root (UID 0). \
                             UFW config files should be owned by root to prevent tampering.",
                        ),
                        fix: Some(format!("Fix ownership: sudo chown root:root {path}")),
                    });
                }
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = findings;
    }
}

/// Check for secrets in rule comments (cross-reference with spec validation).
fn check_secrets_in_comments(ufw: &Ufw, findings: &mut Vec<Finding>) {
    if let Ok(status) = ufw.status() {
        for rule in &status.rules {
            if let Some(comment) = &rule.comment {
                // Reuse the spec validation logic for secret detection
                if crate::spec::validate_comment_for_secrets_doctor(comment) {
                    findings.push(Finding {
                        id: "perm:rule:secret-in-comment",
                        severity: Severity::Warning,
                        title: "Rule comment may contain a secret".into(),
                        detail: format!(
                            "Rule '{}' has a comment that appears to contain a secret: '{}'. \
                             Secrets should not be stored in firewall rule comments.",
                            rule.raw, comment
                        ),
                        fix: Some(
                            "Remove the secret from the rule comment and store it in a \
                             proper secrets manager. Then recreate the rule without the secret."
                                .into(),
                        ),
                    });
                }
            }
        }
    }
}

/// Cross-reference: check if any rules reference app profiles that do not exist.
fn check_app_profile_references(ufw: &Ufw, findings: &mut Vec<Finding>) {
    // Get the list of known profiles
    let known_profiles: Vec<String> = match ufw.app_list() {
        Ok(list) => list
            .lines()
            .filter(|l| !l.starts_with("Available") && !l.trim().is_empty())
            .map(|l| {
                l.trim()
                    .trim_start_matches(|c: char| c.is_whitespace() || c == '*')
                    .to_string()
            })
            .filter(|l| !l.is_empty())
            .collect(),
        Err(_) => return,
    };

    // Check rules for app profile references (rules that don't match port patterns
    // but reference a profile name).
    if let Ok(status) = ufw.status() {
        for rule in &status.rules {
            let raw_lower = rule.raw.to_lowercase();

            // Skip rules that clearly have port numbers
            if raw_lower
                .split_whitespace()
                .take(2)
                .any(|t| t.parse::<u16>().is_ok())
            {
                continue;
            }

            // Check if the first token looks like a profile name that's not in the list
            let first_token = raw_lower.split_whitespace().next().unwrap_or("");
            if first_token.is_empty() {
                continue;
            }

            // If it's not a well-known keyword and not in the profiles list, flag it
            let is_keyword = matches!(
                first_token,
                "allow" | "deny" | "reject" | "limit" | "anywhere"
            );
            if !is_keyword
                && first_token.parse::<u16>().is_err()
                && !known_profiles
                    .iter()
                    .any(|p| p.to_lowercase() == first_token)
            {
                // Check if the raw text contains a known profile name elsewhere
                let found_in_raw = known_profiles
                    .iter()
                    .any(|p| raw_lower.contains(&p.to_lowercase()));
                if !found_in_raw && raw_lower.contains("allow") {
                    // Possible dangling app profile reference
                    findings.push(Finding {
                        id: "app:rule:unknown-profile-ref",
                        severity: Severity::Info,
                        title: "Rule may reference unknown app profile".into(),
                        detail: format!(
                            "Rule '{}' references '{}' which is not a known app profile.",
                            rule.raw, first_token
                        ),
                        fix: Some("Check the rule and profile name. Install the missing profile or fix the rule.".into()),
                    });
                }
            }
        }
    }
}

/// Check if any app profiles have ports that conflict with each other.
fn check_app_profile_port_conflicts(ufw: &Ufw, findings: &mut Vec<Finding>) {
    // Collect (profile_name, ports_string) from app info
    let profiles = match ufw.app_list() {
        Ok(list) => list
            .lines()
            .filter(|l| !l.starts_with("Available") && !l.trim().is_empty())
            .map(|l| {
                l.trim()
                    .trim_start_matches(|c: char| c.is_whitespace() || c == '*')
                    .to_string()
            })
            .filter(|l| !l.is_empty())
            .collect::<Vec<_>>(),
        Err(_) => return,
    };

    let mut profile_ports: Vec<(String, Vec<String>)> = Vec::new();

    for name in &profiles {
        if let Ok(info) = ufw.app_info(name) {
            if let Some(ports_line) = info.lines().find(|l| l.contains("Port")) {
                if let Some(ports_str) = ports_line.split(':').nth(1) {
                    let ports: Vec<String> = ports_str
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect();
                    profile_ports.push((name.clone(), ports));
                }
            }
        }
    }

    // Check for overlapping ports between profiles
    for i in 0..profile_ports.len() {
        for j in (i + 1)..profile_ports.len() {
            let (ref name_a, ref ports_a) = profile_ports[i];
            let (ref name_b, ref ports_b) = profile_ports[j];

            let conflicts: Vec<_> = ports_a.iter().filter(|p| ports_b.contains(p)).collect();

            if !conflicts.is_empty() {
                let conflict_list: String = conflicts
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(", ");
                findings.push(Finding {
                    id: Box::leak(format!("app:conflict:{name_a}:{name_b}").into_boxed_str()),
                    severity: Severity::Info,
                    title: format!("App profiles {name_a} and {name_b} share ports"),
                    detail: format!(
                        "Profiles '{name_a}' and '{name_b}' both define port(s): {conflict_list}. \
                         This can cause conflicts when both are used in rules."
                    ),
                    fix: Some(
                        "Review the profile definitions and remove duplicate port declarations, \
                         or avoid using both profiles simultaneously."
                            .into(),
                    ),
                });
            }
        }
    }
}

// ── Docker checks ──────────────────────────────────────────────────

/// Check Docker-related firewall issues.
fn check_docker(ufw: &Ufw) -> Vec<Finding> {
    crate::docker::check_docker(ufw.runner())
}

// ── Reverse proxy checks ───────────────────────────────────────────

/// Check reverse proxy configuration.
fn check_reverse_proxy(ufw: &Ufw) -> Vec<Finding> {
    crate::docker::check_reverse_proxy(ufw.runner())
}

// ── Routing/forwarding checks ──────────────────────────────────────

/// Check routing/forwarding configuration.
fn check_routing(ufw: &Ufw) -> Vec<Finding> {
    crate::docker::check_routing(ufw.runner())
}

// ── Framework checks ───────────────────────────────────────────────

/// Check framework files for issues (managed blocks, COMMIT lines, etc.).
///
/// Only runs when the `framework` feature is enabled. Validates managed
/// blocks, COMMIT lines, IPv4/IPv6 separation, and NAT block placement.
#[cfg(feature = "framework")]
fn check_framework(ufw: &Ufw) -> Vec<Finding> {
    let mut findings = Vec::new();
    let paths = crate::paths::UfwPaths::default();

    // Check before.rules
    check_framework_file(&paths.before_rules, "before.rules", false, &mut findings);
    // Check after.rules
    check_framework_file(&paths.after_rules, "after.rules", false, &mut findings);

    // Check IPv6 files if IPv6 is enabled
    let ipv6_enabled = read_ipv6_enabled_from_config();
    if ipv6_enabled {
        check_framework_file(&paths.before6_rules, "before6.rules", true, &mut findings);
        check_framework_file(&paths.after6_rules, "after6.rules", true, &mut findings);
    }

    let _ = ufw; // Runner not needed for file checks
    findings
}

#[cfg(feature = "framework")]
#[allow(clippy::too_many_lines)]
fn check_framework_file(
    path: &std::path::Path,
    name: &str,
    is_ipv6: bool,
    findings: &mut Vec<Finding>,
) {
    let content = match crate::framework::read_framework_file(path) {
        Ok(c) if c.is_empty() => {
            findings.push(Finding {
                id: Box::leak(format!("fw:{name}:empty").into_boxed_str()),
                severity: Severity::Warning,
                title: format!("{name} is empty or missing"),
                detail: format!("Framework file {name} is empty or does not exist."),
                fix: Some(format!("Restore {name} from a backup or reinstall ufw.")),
            });
            return;
        }
        Ok(c) => c,
        Err(e) => {
            findings.push(Finding {
                id: Box::leak(format!("fw:{name}:read-error").into_boxed_str()),
                severity: Severity::Warning,
                title: format!("Cannot read {name}"),
                detail: format!("Failed to read {name}: {e}"),
                fix: None,
            });
            return;
        }
    };

    // Check for COMMIT lines in *filter and *nat tables
    if content.contains("*filter") && !content.contains("COMMIT") {
        findings.push(Finding {
            id: Box::leak(format!("fw:{name}:no-commit-filter").into_boxed_str()),
            severity: Severity::Important,
            title: format!("{name} filter table missing COMMIT"),
            detail: format!(
                "{name} has a *filter table but no COMMIT line. \
                 This will cause iptables-restore to fail."
            ),
            fix: Some(format!(
                "Add a COMMIT line at the end of the *filter table in {name}."
            )),
        });
    }

    if content.contains("*nat") && !content.matches("COMMIT").count() >= 2 {
        // *nat table should have its own COMMIT
        let has_nat_commit = content
            .split("*nat")
            .nth(1)
            .is_some_and(|after_nat| after_nat.contains("COMMIT"));
        if !has_nat_commit {
            findings.push(Finding {
                id: Box::leak(format!("fw:{name}:no-commit-nat").into_boxed_str()),
                severity: Severity::Important,
                title: format!("{name} NAT table missing COMMIT"),
                detail: format!(
                    "{name} has a *nat table but no COMMIT line after it. \
                     This will cause iptables-restore to fail."
                ),
                fix: Some(format!(
                    "Add a COMMIT line at the end of the *nat table in {name}."
                )),
            });
        }
    }

    // Check for managed blocks
    let blocks = crate::framework::list_blocks(&content);
    if !blocks.is_empty() {
        findings.push(Finding {
            id: Box::leak(format!("fw:{name}:managed-blocks").into_boxed_str()),
            severity: Severity::Info,
            title: format!("{name} has {} managed block(s)", blocks.len()),
            detail: format!("Found managed blocks in {name}: {}", blocks.join(", ")),
            fix: None,
        });

        // Check for duplicate block IDs (should never happen, but validate)
        let mut seen = std::collections::HashSet::new();
        for block_id in &blocks {
            if !seen.insert(block_id.clone()) {
                findings.push(Finding {
                    id: Box::leak(format!("fw:{name}:duplicate-block").into_boxed_str()),
                    severity: Severity::Important,
                    title: format!("Duplicate managed block '{block_id}' in {name}"),
                    detail: format!(
                        "Managed block '{block_id}' appears more than once in {name}. \
                         This indicates corruption or a write race."
                    ),
                    fix: Some("Remove the duplicate block and keep only one.".into()),
                });
            }
        }
    }

    // Check IPv4/IPv6 consistency
    if !is_ipv6 && content.contains("ip6tables") {
        findings.push(Finding {
            id: Box::leak(format!("fw:{name}:ipv6-in-ipv4").into_boxed_str()),
            severity: Severity::Warning,
            title: format!("{name} contains ip6tables rules but is an IPv4 file"),
            detail: format!(
                "{name} is an IPv4 framework file but contains ip6tables rules. \
                 These should be in the corresponding IPv6 file (before6.rules/after6.rules)."
            ),
            fix: Some("Move ip6tables rules to the IPv6 framework file.".into()),
        });
    }

    // NAT block placement check
    if content.contains("*nat") {
        let lines: Vec<&str> = content.lines().collect();
        let nat_start = lines.iter().position(|l| l.trim() == "*nat");
        let commit_after_nat =
            nat_start.is_some_and(|start| lines[start..].iter().any(|l| l.trim() == "COMMIT"));

        if commit_after_nat {
            findings.push(Finding {
                id: Box::leak(format!("fw:{name}:nat-block").into_boxed_str()),
                severity: Severity::Info,
                title: format!("{name} has a NAT table"),
                detail: format!(
                    "{name} contains a *nat table. Ensure the NAT rules are correct \
                     and DEFAULT_FORWARD_POLICY is appropriate."
                ),
                fix: None,
            });
        }
    }

    // Log a generic OK if no issues
    if !findings
        .iter()
        .any(|f| f.id.starts_with("fw:") && f.severity >= Severity::Warning)
    {
        findings.push(Finding {
            id: Box::leak(format!("fw:{name}:ok").into_boxed_str()),
            severity: Severity::Ok,
            title: format!("{name} looks valid"),
            detail: format!("Framework file {name} passed all validation checks."),
            fix: None,
        });
    }
}

#[cfg(test)]
#[path = "doctor.test.rs"]
mod tests;
