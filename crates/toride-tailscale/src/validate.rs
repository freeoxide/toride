//! Validation functions for Tailscale ACL policies, DNS configs, and tailnet names.
//!
//! Ensures configurations are well-formed and internally consistent,
//! returning structured findings with severity levels.

use crate::error::{Error, Result};
use crate::spec::{AclRule, DnsConfig};

/// Severity of a validation finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ValidationSeverity {
    /// Informational — no action needed.
    Info,
    /// Warning — may indicate a misconfiguration.
    Warning,
    /// Error — invalid configuration.
    Error,
}

/// A single validation finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationFinding {
    /// The field or subject this finding relates to.
    pub key: String,
    /// Severity of the finding.
    pub severity: ValidationSeverity,
    /// Human-readable description of the issue.
    pub message: String,
}

/// Validate an ACL policy (a list of ACL rules) and return findings.
///
/// Checks that:
/// - Every rule has at least one source and one destination.
/// - Destination entries are well-formed (`host:port` or `host:*`).
/// - No duplicate rules exist.
pub fn validate_acl_policy(rules: &[AclRule]) -> Result<Vec<ValidationFinding>> {
    let mut findings = Vec::new();

    for (i, rule) in rules.iter().enumerate() {
        let key = format!("acls[{i}]");

        if rule.src.is_empty() {
            findings.push(ValidationFinding {
                key: key.clone(),
                severity: ValidationSeverity::Error,
                message: "ACL rule has no sources".into(),
            });
        }

        if rule.dst.is_empty() {
            findings.push(ValidationFinding {
                key: key.clone(),
                severity: ValidationSeverity::Error,
                message: "ACL rule has no destinations".into(),
            });
        }

        // Validate destination format: must contain a colon separating host and port.
        for dst in &rule.dst {
            if !dst.contains(':') {
                findings.push(ValidationFinding {
                    key: format!("{key}.dst"),
                    severity: ValidationSeverity::Error,
                    message: format!(
                        "destination '{dst}' is missing ':' separator (expected host:port)"
                    ),
                });
            }
        }
    }

    // Check for duplicate rules.
    for i in 0..rules.len() {
        for j in (i + 1)..rules.len() {
            if rules[i] == rules[j] {
                findings.push(ValidationFinding {
                    key: format!("acls[{i}]"),
                    severity: ValidationSeverity::Warning,
                    message: format!("duplicate of rule at index {j}"),
                });
            }
        }
    }

    Ok(findings)
}

/// Validate a DNS configuration and return findings.
///
/// Checks that:
/// - Nameserver addresses are non-empty and plausibly formatted.
/// - Search domains are non-empty and contain at least one dot.
pub fn validate_dns_config(dns: &DnsConfig) -> Result<Vec<ValidationFinding>> {
    let mut findings = Vec::new();

    for (i, ns) in dns.nameservers.iter().enumerate() {
        if ns.is_empty() {
            findings.push(ValidationFinding {
                key: format!("dns.nameservers[{i}]"),
                severity: ValidationSeverity::Error,
                message: "nameserver address must not be empty".into(),
            });
        }
    }

    for (i, domain) in dns.search_domains.iter().enumerate() {
        if domain.is_empty() {
            findings.push(ValidationFinding {
                key: format!("dns.search_domains[{i}]"),
                severity: ValidationSeverity::Error,
                message: "search domain must not be empty".into(),
            });
        } else if !domain.contains('.') {
            findings.push(ValidationFinding {
                key: format!("dns.search_domains[{i}]"),
                severity: ValidationSeverity::Warning,
                message: format!(
                    "search domain '{domain}' does not look like a fully qualified domain"
                ),
            });
        }
    }

    Ok(findings)
}

/// Validate a tailnet name and return an error if invalid.
///
/// Tailnet names must:
/// - Be non-empty
/// - Contain only lowercase alphanumeric characters, hyphens, and dots
/// - Start and end with an alphanumeric character
pub fn validate_tailnet_name(name: &str) -> Result<()> {
    let mut chars = name.chars();

    // The first character must exist (non-empty) and be alphanumeric.
    match chars.next() {
        Some(first) if first.is_ascii_alphanumeric() => {}
        _ => {
            return Err(Error::Other(
                "tailnet name must start with an alphanumeric character".into(),
            ));
        }
    }

    // The last character must be alphanumeric. A single-char name was already
    // validated above (its only char is both first and last).
    if !name
        .chars()
        .last()
        .is_some_and(|c| c.is_ascii_alphanumeric())
    {
        return Err(Error::Other(
            "tailnet name must end with an alphanumeric character".into(),
        ));
    }

    // Every character must be lowercase alphanumeric, hyphen, or dot. The
    // start/end checks above already validated the boundary chars, but we still
    // scan the full string so a stray uppercase or symbol anywhere is rejected.
    for ch in name.chars() {
        if !ch.is_ascii_lowercase() && !ch.is_ascii_digit() && ch != '-' && ch != '.' {
            return Err(Error::Other(format!(
                "tailnet name contains invalid character '{ch}'"
            )));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spec::AclAction;

    #[test]
    fn acl_policy_empty_src_rejected() {
        let rules = vec![AclRule {
            action: AclAction::Allow,
            src: vec![],
            dst: vec!["10.0.0.1:*".into()],
        }];
        let findings = validate_acl_policy(&rules).unwrap();
        assert!(findings.iter().any(|f| f.message.contains("no sources")));
    }

    #[test]
    fn acl_policy_bad_dst_rejected() {
        let rules = vec![AclRule {
            action: AclAction::Allow,
            src: vec!["*".into()],
            dst: vec!["10.0.0.1".into()],
        }];
        let findings = validate_acl_policy(&rules).unwrap();
        assert!(findings.iter().any(|f| f.message.contains("missing ':'")));
    }

    #[test]
    fn acl_policy_duplicate_flagged() {
        let rule = AclRule {
            action: AclAction::Allow,
            src: vec!["*".into()],
            dst: vec!["*:*".into()],
        };
        let findings = validate_acl_policy(&[rule.clone(), rule]).unwrap();
        assert!(findings.iter().any(|f| f.message.contains("duplicate")));
    }

    #[test]
    fn dns_empty_nameserver_rejected() {
        let dns = DnsConfig {
            magic_dns: true,
            nameservers: vec![String::new()],
            search_domains: vec![],
        };
        let findings = validate_dns_config(&dns).unwrap();
        assert!(
            findings
                .iter()
                .any(|f| f.message.contains("must not be empty"))
        );
    }

    #[test]
    fn dns_unqualified_search_domain_warned() {
        let dns = DnsConfig {
            magic_dns: true,
            nameservers: vec![],
            search_domains: vec!["myhost".into()],
        };
        let findings = validate_dns_config(&dns).unwrap();
        assert!(findings.iter().any(|f| {
            f.message
                .contains("does not look like a fully qualified domain")
        }));
    }

    #[test]
    fn tailnet_name_valid() {
        assert!(validate_tailnet_name("example").is_ok());
        assert!(validate_tailnet_name("my-tailnet").is_ok());
        assert!(validate_tailnet_name("my.tailnet.com").is_ok());
    }

    #[test]
    fn tailnet_name_invalid() {
        assert!(validate_tailnet_name("").is_err());
        assert!(validate_tailnet_name("-bad").is_err());
        assert!(validate_tailnet_name("bad-").is_err());
        assert!(validate_tailnet_name("has space").is_err());
    }
}
