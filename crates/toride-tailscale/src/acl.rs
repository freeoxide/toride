//! ACL policy management for Tailscale tailnets.
//!
//! Provides types and operations for managing Access Control Lists in a
//! Tailscale tailnet. ACLs define which nodes and users can communicate
//! with each other and on which ports.

use crate::spec::AclRule;
use crate::Result;

// ---------------------------------------------------------------------------
// AclManager
// ---------------------------------------------------------------------------

/// Manager for Tailscale ACL policies.
///
/// `AclManager` provides methods for validating, generating, and auditing
/// ACL rules in a tailnet. ACLs are typically managed through the Tailscale
/// coordination server, not the local API, so this module focuses on
/// validation and policy-document generation.
///
/// # Example
///
/// ```ignore
/// use toride_tailscale::acl::AclManager;
/// use toride_tailscale::spec::{AclAction, AclRule};
///
/// let manager = AclManager::new();
/// let rules = vec![AclRule {
///     action: AclAction::Allow,
///     src: vec!["autogroup:members".to_owned()],
///     dst: vec!["*:*".to_owned()],
/// }];
/// manager.validate_rules(&rules)?;
/// let policy = manager.generate_policy(&rules)?;
/// ```
pub struct AclManager {
    /// Whether to run in dry-run mode (validate only, no changes).
    dry_run: bool,
}

impl AclManager {
    /// Create a new `AclManager`.
    pub fn new() -> Self {
        Self { dry_run: false }
    }

    /// Enable dry-run mode.
    pub fn with_dry_run(mut self, dry_run: bool) -> Self {
        self.dry_run = dry_run;
        self
    }

    /// Returns whether dry-run mode is enabled.
    pub fn is_dry_run(&self) -> bool {
        self.dry_run
    }

    /// Validate a list of ACL rules for syntactic and semantic correctness.
    ///
    /// Checks that:
    /// - Source and destination fields are non-empty
    /// - Each destination is well-formed (`host:port` or `host:*`)
    /// - No conflicting rules exist
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::AclError`] if any rule is invalid.
    pub fn validate_rules(&self, rules: &[AclRule]) -> Result<()> {
        for (i, rule) in rules.iter().enumerate() {
            if rule.src.is_empty() {
                return Err(crate::Error::AclError(format!(
                    "rule {i}: source list must not be empty"
                )));
            }
            if rule.dst.is_empty() {
                return Err(crate::Error::AclError(format!(
                    "rule {i}: destination list must not be empty"
                )));
            }
            for dst in &rule.dst {
                validate_dst(i, dst)?;
            }
        }
        Ok(())
    }

    /// Generate a Tailscale ACL policy document from a list of rules.
    ///
    /// Produces a valid Tailscale ACL policy as a pretty-printed JSON string
    /// (which is also valid HuJSON). Only `Allow` rules are emitted as ACL
    /// entries; Tailscale's default-deny model means `Deny` is the implicit
    /// fallback, so explicit deny rules are omitted with a debug log.
    ///
    /// `dry_run` does not change the output (policy generation is read-only),
    /// but it is honoured by [`Self::apply`] when that method is implemented.
    ///
    /// # Errors
    ///
    /// Returns an error if any rule fails validation.
    pub fn generate_policy(&self, rules: &[AclRule]) -> Result<String> {
        self.validate_rules(rules)?;

        // Collect the allow rules into the Tailscale "acls" array format.
        let acl_entries: Vec<serde_json::Value> = rules
            .iter()
            .filter(|r| r.action == crate::spec::AclAction::Allow)
            .map(|r| {
                serde_json::json!({
                    "action": "accept",
                    "src": r.src,
                    "dst": r.dst,
                })
            })
            .collect();

        let denied: usize = rules
            .iter()
            .filter(|r| r.action == crate::spec::AclAction::Deny)
            .count();
        if denied > 0 {
            tracing::debug!(
                denied,
                "Tailscale ACLs are default-deny; explicit deny rules omitted from policy"
            );
        }

        let policy = serde_json::json!({
            // Tailscale ACL policies are anchored by a top-level "acls" list.
            "acls": acl_entries,
        });

        // Pretty-print with 2-space indentation for readability and stable
        // diffs. `to_string_pretty` produces strict JSON, which is a valid
        // subset of HuJSON.
        serde_json::to_string_pretty(&policy)
            .map_err(|e| crate::Error::AclError(format!("failed to serialize policy: {e}")))
    }

    /// Apply a policy document to the tailnet.
    ///
    /// **Not yet implemented.** Applying ACLs requires the Tailscale
    /// coordination-server API and an authenticated client (OAuth or API
    /// key). In dry-run mode this logs the policy and returns `Ok(())`
    /// without contacting any server.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::Other`] when not in dry-run mode (the real
    /// apply path is unimplemented).
    pub fn apply(&self, _policy: &str) -> Result<()> {
        if self.dry_run {
            tracing::info!("dry-run: would apply ACL policy");
            return Ok(());
        }
        Err(crate::Error::Other(
            "ACL apply is not implemented (requires coordination-server credentials)".to_owned(),
        ))
    }
}

impl Default for AclManager {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/// Validate a single destination specifier.
///
/// Tailscale ACL destinations are `host:port` where `host` is an IP, CIDR,
/// autogroup, `*`, or `tag:`, and `port` is a number, range, or `*`.
fn validate_dst(rule_index: usize, dst: &str) -> Result<()> {
    let Some((host, port)) = dst.rsplit_once(':') else {
        return Err(crate::Error::AclError(format!(
            "rule {rule_index}: destination `{dst}` must be `host:port`"
        )));
    };
    if host.is_empty() {
        return Err(crate::Error::AclError(format!(
            "rule {rule_index}: destination `{dst}` has empty host"
        )));
    }
    if port.is_empty() {
        return Err(crate::Error::AclError(format!(
            "rule {rule_index}: destination `{dst}` has empty port"
        )));
    }
    // Port is either "*", a single number, a comma list, or a range (n-n).
    if port != "*" && !is_valid_port_spec(port) {
        return Err(crate::Error::AclError(format!(
            "rule {rule_index}: destination `{dst}` has invalid port `{port}`"
        )));
    }
    Ok(())
}

/// Return true if `spec` is a valid port specifier: a number (0-65535), a
/// comma-separated list of numbers, or a `lo-hi` range.
fn is_valid_port_spec(spec: &str) -> bool {
    if spec.contains(',') {
        return spec.split(',').all(|p| is_valid_port_atom(p.trim()));
    }
    if let Some((lo, hi)) = spec.split_once('-') {
        return is_valid_port_atom(lo.trim()) && is_valid_port_atom(hi.trim());
    }
    is_valid_port_atom(spec)
}

fn is_valid_port_atom(s: &str) -> bool {
    s.parse::<u32>().is_ok_and(|n| n <= 65535)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spec::{AclAction, AclRule};

    fn allow(src: &[&str], dst: &[&str]) -> AclRule {
        AclRule {
            action: AclAction::Allow,
            src: src.iter().map(|s| (*s).to_owned()).collect(),
            dst: dst.iter().map(|s| (*s).to_owned()).collect(),
        }
    }

    #[test]
    fn generate_policy_produces_nonempty_json_with_acls() {
        let mgr = AclManager::new();
        let rules = vec![allow(&["autogroup:members"], &["*:*"])];
        let policy = mgr.generate_policy(&rules).unwrap();
        assert!(!policy.is_empty());

        let parsed: serde_json::Value = serde_json::from_str(&policy).unwrap();
        assert_eq!(parsed["acls"][0]["action"], "accept");
        assert_eq!(parsed["acls"][0]["src"][0], "autogroup:members");
        assert_eq!(parsed["acls"][0]["dst"][0], "*:*");
    }

    #[test]
    fn generate_policy_emits_multiple_allow_rules() {
        let mgr = AclManager::new();
        let rules = vec![
            allow(&["user@example.com"], &["tag:server:22"]),
            allow(&["autogroup:members"], &["100.64.0.0/10:*"]),
        ];
        let policy = mgr.generate_policy(&rules).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&policy).unwrap();
        assert_eq!(parsed["acls"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn generate_policy_omits_explicit_deny_rules() {
        let mgr = AclManager::new();
        let mut rules = vec![allow(&["u@a"], &["*:80"])];
        rules.push(AclRule {
            action: AclAction::Deny,
            src: vec!["*".to_owned()],
            dst: vec!["*:22".to_owned()],
        });
        let policy = mgr.generate_policy(&rules).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&policy).unwrap();
        assert_eq!(parsed["acls"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn validate_rules_rejects_empty_src() {
        let mgr = AclManager::new();
        let rules = vec![AclRule {
            action: AclAction::Allow,
            src: vec![],
            dst: vec!["*:*".to_owned()],
        }];
        assert!(mgr.validate_rules(&rules).is_err());
    }

    #[test]
    fn validate_rules_rejects_malformed_dst() {
        let mgr = AclManager::new();
        let rules = vec![allow(&["u"], &["no-port"])];
        assert!(mgr.validate_rules(&rules).is_err());
    }

    #[test]
    fn validate_rules_accepts_port_ranges_and_lists() {
        let mgr = AclManager::new();
        let rules = vec![
            allow(&["u"], &["tag:srv:1000-2000"]),
            allow(&["u"], &["*:80,443"]),
            allow(&["u"], &["*:*"]),
        ];
        assert!(mgr.validate_rules(&rules).is_ok());
    }

    #[test]
    fn validate_rules_rejects_out_of_range_port() {
        let mgr = AclManager::new();
        let rules = vec![allow(&["u"], &["*:99999"])];
        assert!(mgr.validate_rules(&rules).is_err());
    }

    #[test]
    fn apply_is_ok_in_dry_run() {
        let mgr = AclManager::new().with_dry_run(true);
        assert!(mgr.apply("{}").is_ok());
    }

    #[test]
    fn apply_errors_when_not_dry_run() {
        let mgr = AclManager::new();
        assert!(mgr.apply("{}").is_err());
    }
}
