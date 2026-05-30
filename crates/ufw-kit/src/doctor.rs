//! Doctor module — structured diagnostic checks for UFW.
//!
//! Returns `Vec<Finding>` rather than just text. Each finding has an ID,
//! severity, title, detail, and optional fix suggestion.

use crate::error::Result;
use crate::spec::{DoctorScope, Finding, Severity};
use crate::Ufw;

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
    }

    Ok(findings)
}

/// Check that required binaries exist.
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
            fix: Some("Install ufw: sudo apt install ufw (Debian/Ubuntu) or sudo pacman -S ufw (Arch)".into()),
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

    findings
}

/// Check UFW service status.
fn check_service(ufw: &Ufw) -> Vec<Finding> {
    let mut findings = Vec::new();

    match ufw.status() {
        Ok(status) => {
            if status.active {
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
        }
        Err(e) => findings.push(Finding {
            id: "svc:ufw:status-fail",
            severity: Severity::Error,
            title: "Could not read UFW status".into(),
            detail: format!("Failed to read UFW status: {e}"),
            fix: Some("Check that ufw is installed and you have sufficient permissions.".into()),
        }),
    }

    findings
}

/// Check UFW configuration files.
fn check_config(_ufw: &Ufw) -> Vec<Finding> {
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
                            severity: Severity::Warning,
                            title: "Default incoming policy is ALLOW".into(),
                            detail: "Servers should typically have incoming DENY or REJECT as default.".into(),
                            fix: Some("Set default incoming to deny: ufw default deny incoming".into()),
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
        }
        Err(e) => findings.push(Finding {
            id: "pol:status-fail",
            severity: Severity::Error,
            title: "Could not check policies".into(),
            detail: format!("Failed to read verbose status: {e}"),
            fix: None,
        }),
    }

    findings
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
                            id: Box::leak(
                                format!("rule:dangerous:{port}")
                                    .into_boxed_str(),
                            ),
                            severity: Severity::Warning,
                            title: format!("Port {port} ({name}) is exposed"),
                            detail: format!(
                                "Rule exposes port {port} ({name}): {}",
                                rule.raw
                            ),
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
                        fix: Some("Consider restricting source to specific IPs or CIDR ranges.".into()),
                    });
                }
            }
        }
        Err(e) => findings.push(Finding {
            id: "rule:status-fail",
            severity: Severity::Error,
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

    if let Ok(status) = ufw.status() {
        let has_ssh_rule = status.rules.iter().any(|rule| {
            let raw = rule.raw.to_lowercase();
            raw.contains("22") || raw.contains("ssh")
        });

        if status.active {
            if has_ssh_rule {
                findings.push(Finding {
                    id: "ssh:allowed",
                    severity: Severity::Ok,
                    title: "SSH access is allowed".into(),
                    detail: "An SSH allow rule exists in the firewall.".into(),
                    fix: None,
                });
            } else {
                findings.push(Finding {
                    id: "ssh:no-rule",
                    severity: Severity::Critical,
                    title: "No SSH allow rule found".into(),
                    detail: "UFW is active but no SSH allow rule exists. This may lock you out.".into(),
                    fix: Some("Add SSH allow rule: ufw allow 22/tcp".into()),
                });
            }
        }
    }

    findings
}

/// Check IPv6 configuration.
fn check_ipv6(ufw: &Ufw) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Check if IPv6 is enabled in UFW config
    let ufw_default = std::fs::read_to_string("/etc/default/ufw").unwrap_or_default();
    let ipv6_enabled = ufw_default
        .lines()
        .any(|line| line.trim() == "IPV6=yes");

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
                        severity: Severity::Info,
                        title: "Logging is disabled".into(),
                        detail: "UFW logging is currently off.".into(),
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
                _ => {
                    findings.push(Finding {
                        id: "log:ok",
                        severity: Severity::Ok,
                        title: "Logging level is reasonable".into(),
                        detail: format!("Logging level: {level}"),
                        fix: None,
                    });
                }
            }
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

    findings
}

/// Check file permissions.
fn check_permissions(_ufw: &Ufw) -> Vec<Finding> {
    let mut findings = Vec::new();

    let paths_to_check = [
        "/etc/ufw",
        "/etc/default/ufw",
        "/etc/ufw/applications.d",
    ];

    for path in &paths_to_check {
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
                            fix: Some(format!(
                                "Fix permissions: sudo chmod o-w {path}"
                            )),
                        });
                    } else {
                        findings.push(Finding {
                            id: Box::leak(
                                format!("perm:{}:ok", path.replace('/', ":"))
                                    .into_boxed_str(),
                            ),
                            severity: Severity::Ok,
                            title: format!("{path} permissions OK"),
                            detail: format!(
                                "{path} has permissions {:o}.",
                                mode & 0o777
                            ),
                            fix: None,
                        });
                    }
                }
                #[cfg(not(unix))]
                {
                    findings.push(Finding {
                        id: Box::leak(
                            format!("perm:{}:skip", path.replace('/', ":"))
                                .into_boxed_str(),
                        ),
                        severity: Severity::Info,
                        title: format!("Cannot check {path} permissions"),
                        detail: "Permission checks require Unix.".into(),
                        fix: None,
                    });
                }
            }
            Err(_) => {
                findings.push(Finding {
                    id: Box::leak(
                        format!("perm:{}:missing", path.replace('/', ":"))
                            .into_boxed_str(),
                    ),
                    severity: Severity::Info,
                    title: format!("{path} not found"),
                    detail: format!("{path} does not exist."),
                    fix: None,
                });
            }
        }
    }

    findings
}

#[cfg(test)]
#[path = "doctor.test.rs"]
mod tests;
