//! Validation functions for sysctl keys, values, and specs.
//!
//! Ensures keys are well-formed, values are within expected ranges,
//! and complete specs are internally consistent.

use crate::error::{Error, Result};
use crate::spec::HardenSpec;

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
    /// The sysctl key this finding relates to.
    pub key: String,
    /// Severity of the finding.
    pub severity: ValidationSeverity,
    /// Human-readable description of the issue.
    pub message: String,
}

/// Validate that a sysctl key is well-formed.
///
/// Keys must:
/// - Be non-empty
/// - Contain only lowercase alphanumeric characters, dots, slashes, and underscores
/// - Start with a recognized top-level domain (kernel, net, fs, vm, etc.)
pub fn validate_sysctl_key(key: &str) -> Result<()> {
    if key.is_empty() {
        return Err(Error::SysctlParse("sysctl key must not be empty".into()));
    }

    // Validate characters
    for ch in key.chars() {
        if !ch.is_ascii_lowercase()
            && !ch.is_ascii_digit()
            && ch != '.'
            && ch != '/'
            && ch != '_'
            && ch != '-'
        {
            return Err(Error::SysctlParse(format!(
                "sysctl key contains invalid character '{ch}' in: {key}"
            )));
        }
    }

    // Validate top-level domain
    let top_level = key.split('.').next().unwrap_or(key);
    let valid_tops = [
        "kernel", "net", "fs", "vm", "dev", "proc", "debug", "user", "abi",
    ];
    if !valid_tops.contains(&top_level) {
        return Err(Error::SysctlParse(format!(
            "sysctl key has unrecognized top-level domain '{top_level}': {key}"
        )));
    }

    Ok(())
}

/// Validate that a sysctl value is acceptable for a given key.
///
/// Performs key-specific validation for well-known parameters.
/// Unknown keys accept any non-empty value.
pub fn validate_sysctl_value(key: &str, value: &str) -> Result<()> {
    if value.is_empty() {
        return Err(Error::SysctlParse(format!(
            "sysctl value must not be empty for key: {key}"
        )));
    }

    // Key-specific validation
    if let Some(expected) = expected_values(key) {
        if !expected.contains(&value) {
            return Err(Error::SysctlParse(format!(
                "sysctl key {key} expects one of [{}] but got: {value}",
                expected.join(", ")
            )));
        }
    }

    // Numeric range validation for known numeric keys
    if let Some((min, max)) = numeric_range(key) {
        if let Ok(num) = value.parse::<i64>() {
            if num < min || num > max {
                return Err(Error::SysctlParse(format!(
                    "sysctl key {key} value {value} outside range [{min}, {max}]"
                )));
            }
        }
    }

    Ok(())
}

/// Validate a complete hardening spec and return any findings.
pub fn validate_spec(spec: &HardenSpec) -> Result<Vec<ValidationFinding>> {
    let mut findings = Vec::new();

    for param in &spec.parameters {
        // Validate key format
        if let Err(e) = validate_sysctl_key(&param.key) {
            findings.push(ValidationFinding {
                key: param.key.clone(),
                severity: ValidationSeverity::Error,
                message: e.to_string(),
            });
            continue;
        }

        // Validate value
        if let Err(e) = validate_sysctl_value(&param.key, &param.value) {
            findings.push(ValidationFinding {
                key: param.key.clone(),
                severity: ValidationSeverity::Error,
                message: e.to_string(),
            });
        }
    }

    // Check for duplicate keys
    let mut seen = std::collections::HashSet::new();
    for param in &spec.parameters {
        if !seen.insert(&param.key) {
            findings.push(ValidationFinding {
                key: param.key.clone(),
                severity: ValidationSeverity::Warning,
                message: format!("Duplicate key: {}", param.key),
            });
        }
    }

    Ok(findings)
}

/// Return expected values for well-known boolean-like sysctl keys.
fn expected_values(key: &str) -> Option<Vec<&'static str>> {
    match key {
        "kernel.kptr_restrict" | "kernel.dmesg_restrict" | "kernel.yama.ptrace_scope" => {
            Some(vec!["0", "1", "2", "3"])
        }
        "net.ipv4.ip_forward" | "net.ipv6.conf.all.forwarding" => Some(vec!["0", "1"]),
        "net.ipv4.conf.all.accept_redirects"
        | "net.ipv4.conf.default.accept_redirects"
        | "net.ipv6.conf.all.accept_redirects" => Some(vec!["0", "1"]),
        "net.ipv4.conf.all.send_redirects" | "net.ipv4.conf.default.send_redirects" => {
            Some(vec!["0", "1"])
        }
        "net.ipv4.conf.all.accept_source_route" | "net.ipv4.conf.default.accept_source_route" => {
            Some(vec!["0", "1"])
        }
        "fs.protected_hardlinks"
        | "fs.protected_symlinks"
        | "fs.protected_fifos"
        | "fs.protected_regular" => Some(vec!["0", "1", "2"]),
        "kernel.randomize_va_space" => Some(vec!["0", "1", "2"]),
        _ => None,
    }
}

/// Return numeric range for known numeric sysctl keys.
fn numeric_range(key: &str) -> Option<(i64, i64)> {
    match key {
        "kernel.kptr_restrict" => Some((0, 1)),
        "kernel.dmesg_restrict" => Some((0, 1)),
        "kernel.randomize_va_space" => Some((0, 2)),
        "kernel.yama.ptrace_scope" => Some((0, 3)),
        "vm.swappiness" => Some((0, 100)),
        "net.core.somaxconn" => Some((1, 4294967295)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spec::SysctlParam;

    #[test]
    fn valid_keys_accepted() {
        assert!(validate_sysctl_key("kernel.kptr_restrict").is_ok());
        assert!(validate_sysctl_key("net.ipv4.ip_forward").is_ok());
        assert!(validate_sysctl_key("fs.protected_hardlinks").is_ok());
    }

    #[test]
    fn invalid_keys_rejected() {
        assert!(validate_sysctl_key("").is_err());
        assert!(validate_sysctl_key("INVALID").is_err());
        assert!(validate_sysctl_key("fake.key").is_err());
    }

    #[test]
    fn valid_values_accepted() {
        assert!(validate_sysctl_value("kernel.kptr_restrict", "1").is_ok());
        assert!(validate_sysctl_value("kernel.randomize_va_space", "2").is_ok());
    }

    #[test]
    fn invalid_values_rejected() {
        assert!(validate_sysctl_value("kernel.kptr_restrict", "5").is_err());
        assert!(validate_sysctl_value("kernel.kptr_restrict", "").is_err());
    }

    #[test]
    fn unknown_key_accepts_any_nonempty() {
        assert!(validate_sysctl_value("kernel.unknown_param", "42").is_ok());
        assert!(validate_sysctl_value("kernel.unknown_param", "").is_err());
    }

    #[test]
    fn validate_spec_catches_duplicates() {
        let spec = HardenSpec::builder()
            .param(SysctlParam::new("kernel.kptr_restrict", "1", ""))
            .param(SysctlParam::new("kernel.kptr_restrict", "0", ""))
            .build();
        let findings = validate_spec(&spec).unwrap();
        assert!(findings.iter().any(|f| f.message.contains("Duplicate")));
    }
}
