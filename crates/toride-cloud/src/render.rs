//! Rendering functions for firewall rules and security groups.
//!
//! Converts typed domain objects into human-readable or provider-specific
//! formats for display, logging, or configuration file generation.

use crate::spec::{FirewallRule, SecurityGroup};
use std::fmt::Write as _;

// ---------------------------------------------------------------------------
// Human-readable rendering
// ---------------------------------------------------------------------------

/// Render a single firewall rule as a human-readable string.
///
/// Format: `INGRESS  tcp  0.0.0.0/0  80  allow  "HTTP traffic"`
pub fn render_firewall_rule(rule: &FirewallRule) -> String {
    let direction = if rule.is_ingress { "INGRESS" } else { "EGRESS" };
    let port = match &rule.port_range {
        Some(pr) => pr.to_string(),
        None => "all".to_string(),
    };
    let action = rule.action;
    let desc = if rule.description.is_empty() {
        String::new()
    } else {
        format!("  \"{}\"", rule.description)
    };
    format!(
        "{direction}  {proto}  {cidr}  {port}  {action}{desc}",
        proto = rule.protocol,
        cidr = rule.cidr,
        action = action,
    )
}

/// Render a security group as a human-readable table.
///
/// Includes a header with the group name, description, and rule count,
/// followed by each rule rendered via [`render_firewall_rule`].
pub fn render_security_group(group: &SecurityGroup) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "Security Group: {}", group.name);
    if !group.description.is_empty() {
        let _ = writeln!(out, "  Description: {}", group.description);
    }
    let _ = writeln!(out, "  Provider: {}", group.provider);
    let _ = writeln!(out, "  Rules: {}", group.rules.len());

    if !group.rules.is_empty() {
        out.push('\n');
        for rule in &group.rules {
            let _ = writeln!(out, "  {}", render_firewall_rule(rule));
        }
    }

    out
}

/// Render a collection of firewall rules as a table.
///
/// Returns a string with one rule per line, sorted by direction (ingress first),
/// then protocol, then port.
pub fn render_firewall_rules(rules: &[FirewallRule]) -> String {
    let mut sorted: Vec<&FirewallRule> = rules.iter().collect();
    sorted.sort_by(|a, b| {
        a.is_ingress
            .cmp(&b.is_ingress)
            .reverse()
            .then_with(|| a.protocol.to_string().cmp(&b.protocol.to_string()))
            .then_with(|| {
                a.port_range
                    .map(|p| p.start)
                    .cmp(&b.port_range.map(|p| p.start))
            })
    });

    sorted
        .iter()
        .map(|r| render_firewall_rule(r))
        .collect::<Vec<_>>()
        .join("\n")
}

// ---------------------------------------------------------------------------
// Provider-specific rendering
// ---------------------------------------------------------------------------

/// Render a firewall rule as an AWS CLI `--ip-permissions` argument.
///
/// This is a skeleton; full implementation would produce JSON for
/// `aws ec2 authorize-security-group-ingress`.
pub fn render_aws_rule(rule: &FirewallRule) -> String {
    let _ = rule;
    // TODO: Implement AWS CLI argument rendering.
    String::new()
}

/// Render a firewall rule as a GCP `gcloud compute firewall-rules create` argument.
///
/// This is a skeleton; full implementation would produce the full command line.
pub fn render_gcp_rule(rule: &FirewallRule) -> String {
    let _ = rule;
    // TODO: Implement GCP CLI argument rendering.
    String::new()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spec::{PortRange, Protocol, RuleAction};

    fn sample_ingress_rule() -> FirewallRule {
        FirewallRule {
            id: None,
            description: "HTTP traffic".to_string(),
            is_ingress: true,
            protocol: Protocol::Tcp,
            port_range: Some(PortRange::single(80)),
            cidr: "0.0.0.0/0".to_string(),
            action: RuleAction::Allow,
        }
    }

    fn sample_egress_rule() -> FirewallRule {
        FirewallRule {
            id: None,
            description: "Outbound HTTPS".to_string(),
            is_ingress: false,
            protocol: Protocol::Tcp,
            port_range: Some(PortRange::single(443)),
            cidr: "0.0.0.0/0".to_string(),
            action: RuleAction::Allow,
        }
    }

    // -- render_firewall_rule ------------------------------------------------

    #[test]
    fn render_firewall_rule_ingress() {
        let rule = sample_ingress_rule();
        let rendered = render_firewall_rule(&rule);
        assert!(rendered.starts_with("INGRESS"));
        assert!(rendered.contains("tcp"));
        assert!(rendered.contains("0.0.0.0/0"));
        assert!(rendered.contains("80"));
        assert!(rendered.contains("allow"));
        assert!(rendered.contains("HTTP traffic"));
    }

    #[test]
    fn render_firewall_rule_egress() {
        let rule = sample_egress_rule();
        let rendered = render_firewall_rule(&rule);
        assert!(rendered.starts_with("EGRESS"));
        assert!(rendered.contains("443"));
        assert!(rendered.contains("Outbound HTTPS"));
    }

    #[test]
    fn render_firewall_rule_no_port_shows_all() {
        let rule = FirewallRule {
            id: None,
            description: String::new(),
            is_ingress: true,
            protocol: Protocol::All,
            port_range: None,
            cidr: "10.0.0.0/8".to_string(),
            action: RuleAction::Allow,
        };
        let rendered = render_firewall_rule(&rule);
        assert!(rendered.contains("all"));
    }

    #[test]
    fn render_firewall_rule_no_description() {
        let rule = FirewallRule {
            id: None,
            description: String::new(),
            is_ingress: true,
            protocol: Protocol::Tcp,
            port_range: Some(PortRange::single(22)),
            cidr: "10.0.0.0/8".to_string(),
            action: RuleAction::Deny,
        };
        let rendered = render_firewall_rule(&rule);
        assert!(!rendered.contains('"'));
    }

    // -- render_security_group -----------------------------------------------

    #[test]
    fn render_security_group_includes_metadata() {
        let group = crate::spec::SecurityGroup {
            id: None,
            name: "web-sg".to_string(),
            description: "Web security group".to_string(),
            provider: crate::CloudProvider::Aws,
            rules: vec![sample_ingress_rule()],
            tags: vec![],
        };
        let rendered = render_security_group(&group);
        assert!(rendered.contains("web-sg"));
        assert!(rendered.contains("Web security group"));
        assert!(rendered.contains("aws"));
        assert!(rendered.contains("Rules: 1"));
    }

    #[test]
    fn render_security_group_no_description_omits_line() {
        let group = crate::spec::SecurityGroup {
            id: None,
            name: "empty-sg".to_string(),
            description: String::new(),
            provider: crate::CloudProvider::Gcp,
            rules: vec![],
            tags: vec![],
        };
        let rendered = render_security_group(&group);
        assert!(!rendered.contains("Description:"));
    }

    // -- render_firewall_rules -----------------------------------------------

    #[test]
    fn render_firewall_rules_ingress_before_egress() {
        let egress = sample_egress_rule();
        let ingress = sample_ingress_rule();
        let rendered = render_firewall_rules(&[egress, ingress]);
        let ingress_pos = rendered.find("INGRESS").unwrap();
        let egress_pos = rendered.find("EGRESS").unwrap();
        assert!(
            ingress_pos < egress_pos,
            "INGRESS rules should appear before EGRESS rules"
        );
    }

    #[test]
    fn render_firewall_rules_empty_vec() {
        let rendered = render_firewall_rules(&[]);
        assert!(rendered.is_empty());
    }
}
