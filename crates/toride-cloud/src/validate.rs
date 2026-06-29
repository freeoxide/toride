//! Validation functions for firewall rules and CIDR notation.
//!
//! Every firewall rule is validated before being applied to a cloud provider.
//! This ensures that invalid rules are caught early with clear error messages
//! rather than producing cryptic provider API errors.

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::error::{Error, Result};
use crate::spec::{FirewallRule, SecurityGroup};

// ---------------------------------------------------------------------------
// CIDR validation
// ---------------------------------------------------------------------------

/// Validate a CIDR notation string (e.g. `"0.0.0.0/0"`, `"10.0.0.0/8"`).
///
/// Checks that the string parses as a valid IPv4 or IPv6 CIDR and that the
/// prefix length is within range.
///
/// # Errors
///
/// Returns [`Error::ConfigParse`] if the CIDR is invalid.
pub fn validate_cidr(cidr: &str) -> Result<()> {
    if cidr.contains(':') {
        // IPv6 CIDR
        validate_cidr_v6(cidr)
    } else {
        // IPv4 CIDR
        validate_cidr_v4(cidr)
    }
}

fn validate_cidr_v4(cidr: &str) -> Result<()> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return Err(Error::ConfigParse(format!(
            "invalid CIDR notation (missing /): {cidr}"
        )));
    }

    let ip: Ipv4Addr = parts[0]
        .parse()
        .map_err(|_| Error::ConfigParse(format!("invalid IPv4 address in CIDR: {}", parts[0])))?;

    let prefix: u8 = parts[1]
        .parse()
        .map_err(|_| Error::ConfigParse(format!("invalid prefix length in CIDR: {}", parts[1])))?;

    if prefix > 32 {
        return Err(Error::ConfigParse(format!(
            "IPv4 prefix length must be 0-32, got {prefix}"
        )));
    }

    let _ = ip;
    Ok(())
}

fn validate_cidr_v6(cidr: &str) -> Result<()> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return Err(Error::ConfigParse(format!(
            "invalid CIDR notation (missing /): {cidr}"
        )));
    }

    let ip: Ipv6Addr = parts[0]
        .parse()
        .map_err(|_| Error::ConfigParse(format!("invalid IPv6 address in CIDR: {}", parts[0])))?;

    let prefix: u8 = parts[1]
        .parse()
        .map_err(|_| Error::ConfigParse(format!("invalid prefix length in CIDR: {}", parts[1])))?;

    if prefix > 128 {
        return Err(Error::ConfigParse(format!(
            "IPv6 prefix length must be 0-128, got {prefix}"
        )));
    }

    let _ = ip;
    Ok(())
}

// ---------------------------------------------------------------------------
// Firewall rule validation
// ---------------------------------------------------------------------------

/// Validate a single firewall rule.
///
/// Checks:
/// - CIDR is valid
/// - Port range is valid (if present)
/// - Protocol is specified
/// - Description is present (warning if empty)
///
/// # Errors
///
/// Returns [`Error::ConfigParse`] if the rule fails validation.
pub fn validate_firewall_rule(rule: &FirewallRule) -> Result<()> {
    // Validate CIDR
    validate_cidr(&rule.cidr)?;

    // Validate port range
    if let Some(pr) = &rule.port_range {
        if pr.start == 0 {
            return Err(Error::ConfigParse("port number 0 is not valid".to_string()));
        }
        if pr.end < pr.start {
            return Err(Error::ConfigParse(format!(
                "port range end ({}) must be >= start ({})",
                pr.end, pr.start
            )));
        }
    }

    // Warn about missing description
    if rule.description.is_empty() {
        tracing::warn!(
            "firewall rule has no description; adding one is recommended for maintainability"
        );
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Security group validation
// ---------------------------------------------------------------------------

/// Validate an entire security group.
///
/// Validates each rule and checks for duplicate rules.
///
/// # Errors
///
/// Returns [`Error::ConfigParse`] if any rule fails validation or if
/// duplicates are found.
pub fn validate_security_group(group: &SecurityGroup) -> Result<()> {
    for rule in &group.rules {
        validate_firewall_rule(rule)?;
    }

    // Check for duplicate rules
    for i in 0..group.rules.len() {
        for j in (i + 1)..group.rules.len() {
            if rules_are_equivalent(&group.rules[i], &group.rules[j]) {
                return Err(Error::ConfigParse(format!(
                    "duplicate firewall rules at indices {i} and {j}"
                )));
            }
        }
    }

    Ok(())
}

/// Check if two firewall rules are functionally equivalent.
fn rules_are_equivalent(a: &FirewallRule, b: &FirewallRule) -> bool {
    a.is_ingress == b.is_ingress
        && a.protocol == b.protocol
        && a.port_range == b.port_range
        && a.cidr == b.cidr
        && a.action == b.action
}

// ---------------------------------------------------------------------------
// Port validation
// ---------------------------------------------------------------------------

/// Validate that a port number is in the valid range (1-65535).
///
/// # Errors
///
/// Returns [`Error::ConfigParse`] if the port is out of range.
pub fn validate_port(port: u16) -> Result<()> {
    if port == 0 {
        return Err(Error::ConfigParse("port 0 is not valid".to_string()));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spec::{FirewallRule, PortRange, Protocol, RuleAction, SecurityGroup};

    // -- validate_cidr -------------------------------------------------------

    #[test]
    fn validate_cidr_open_ipv4() {
        assert!(validate_cidr("0.0.0.0/0").is_ok());
    }

    #[test]
    fn validate_cidr_private_ipv4() {
        assert!(validate_cidr("10.0.0.0/8").is_ok());
    }

    #[test]
    fn validate_cidr_missing_prefix_returns_err() {
        assert!(validate_cidr("10.0.0.0").is_err());
    }

    #[test]
    fn validate_cidr_invalid_ip_returns_err() {
        assert!(validate_cidr("not-an-ip/8").is_err());
    }

    #[test]
    fn validate_cidr_valid_ipv6() {
        assert!(validate_cidr("::1/128").is_ok());
        assert!(validate_cidr("fe80::/10").is_ok());
    }

    #[test]
    fn validate_cidr_prefix_too_large_ipv4() {
        assert!(validate_cidr("10.0.0.0/33").is_err());
    }

    // -- validate_port -------------------------------------------------------

    #[test]
    fn validate_port_zero_returns_err() {
        assert!(validate_port(0).is_err());
    }

    #[test]
    fn validate_port_one_returns_ok() {
        assert!(validate_port(1).is_ok());
    }

    #[test]
    fn validate_port_max_returns_ok() {
        assert!(validate_port(65535).is_ok());
    }

    // -- validate_firewall_rule ----------------------------------------------

    fn valid_rule() -> FirewallRule {
        FirewallRule {
            id: None,
            description: "Allow HTTP".to_string(),
            is_ingress: true,
            protocol: Protocol::Tcp,
            port_range: Some(PortRange::single(80)),
            cidr: "0.0.0.0/0".to_string(),
            action: RuleAction::Allow,
        }
    }

    #[test]
    fn validate_firewall_rule_valid() {
        assert!(validate_firewall_rule(&valid_rule()).is_ok());
    }

    #[test]
    fn validate_firewall_rule_invalid_cidr() {
        let mut rule = valid_rule();
        rule.cidr = "not-valid".to_string();
        assert!(validate_firewall_rule(&rule).is_err());
    }

    #[test]
    fn validate_firewall_rule_port_zero() {
        let mut rule = valid_rule();
        rule.port_range = Some(PortRange::single(0));
        assert!(validate_firewall_rule(&rule).is_err());
    }

    #[test]
    fn validate_firewall_rule_inverted_range() {
        let mut rule = valid_rule();
        rule.port_range = Some(PortRange::range(100, 50));
        assert!(validate_firewall_rule(&rule).is_err());
    }

    // -- validate_security_group ---------------------------------------------

    #[test]
    fn validate_security_group_valid() {
        let group = SecurityGroup {
            id: None,
            name: "test-sg".to_string(),
            description: "Test".to_string(),
            provider: crate::CloudProvider::Aws,
            rules: vec![valid_rule()],
            tags: vec![],
        };
        assert!(validate_security_group(&group).is_ok());
    }

    #[test]
    fn validate_security_group_detects_duplicates() {
        let rule = valid_rule();
        let group = SecurityGroup {
            id: None,
            name: "dup-sg".to_string(),
            description: "Duplicate test".to_string(),
            provider: crate::CloudProvider::Aws,
            rules: vec![rule.clone(), rule.clone()],
            tags: vec![],
        };
        let result = validate_security_group(&group);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("duplicate"),
            "Error message should mention duplicates: {err_msg}"
        );
    }

    #[test]
    fn validate_security_group_empty_rules_is_ok() {
        let group = SecurityGroup {
            id: None,
            name: "empty-sg".to_string(),
            description: String::new(),
            provider: crate::CloudProvider::Aws,
            rules: vec![],
            tags: vec![],
        };
        assert!(validate_security_group(&group).is_ok());
    }
}
