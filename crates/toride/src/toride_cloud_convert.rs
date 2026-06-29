//! Convert `toride-cloud` library types to UI presentation types.
//!
//! This is the ONLY module in the `toride` crate that imports `toride_cloud`
//! types — mirroring [`fail2ban_convert`](crate::fail2ban_convert)'s role as
//! the single boundary between backend and presentation. Each function handles
//! errors gracefully: malformed input (empty ids / titles, unparseable ports,
//! unknown protocols) is skipped with a `tracing::warn!` and a placeholder,
//! never propagated (the read-only Cloud section must never crash the TUI).

use crate::ui::screens::toride_cloud::{
    CloudFindingEntry, FirewallRuleEntry, ProviderInfo, SecurityGroupEntry,
};

/// Map a backend [`toride_cloud::report::Severity`] to a lowercase string used
/// by the presentation layer: `"ok" | "info" | "warning" | "error" |
/// "critical"`. Kept here so the TUI never imports the Severity enum directly
/// (mirrors `fail2ban_convert::severity_str`).
fn severity_str(s: toride_cloud::report::Severity) -> &'static str {
    use toride_cloud::report::Severity;
    match s {
        Severity::Ok => "ok",
        Severity::Info => "info",
        Severity::Warning => "warning",
        Severity::Error => "error",
        Severity::Critical => "critical",
    }
}

/// Format a detected [`toride_cloud::CloudProvider`] as a human-friendly label.
///
/// `Unknown` becomes `"none"` so the UI can render "provider: none" on a dev
/// box that is not running on a cloud VM — clearer than the literal "unknown",
/// which reads as an error state rather than the expected no-cloud case.
pub fn format_provider(provider: toride_cloud::CloudProvider) -> &'static str {
    match provider {
        toride_cloud::CloudProvider::Aws => "AWS",
        toride_cloud::CloudProvider::Gcp => "GCP",
        toride_cloud::CloudProvider::DigitalOcean => "DigitalOcean",
        toride_cloud::CloudProvider::Hetzner => "Hetzner",
        toride_cloud::CloudProvider::Unknown => "none",
    }
}

/// Build the presentation [`ProviderInfo`] for a detected provider.
///
/// `cli_tool` is the empty string for `Unknown` (see
/// [`CloudProvider::cli_tool`]); the presentation layer renders "—" for it.
pub fn convert_provider(provider: toride_cloud::CloudProvider) -> ProviderInfo {
    ProviderInfo {
        provider: format_provider(provider).to_string(),
        cli_tool: if provider.cli_tool().is_empty() {
            None
        } else {
            Some(provider.cli_tool().to_string())
        },
        metadata_url: provider.metadata_url().map(String::from),
    }
}

/// Convert backend doctor/client findings to UI entries.
///
/// Every finding maps 1:1. An empty `id` or `title` is logged and the entry is
/// still produced with a placeholder so the row count matches the backend (the
/// operator can see "something" even if the finding is malformed). Mirrors
/// `fail2ban_convert::convert_findings` exactly.
pub fn convert_findings(findings: Vec<toride_cloud::report::Finding>) -> Vec<CloudFindingEntry> {
    findings
        .into_iter()
        .map(|f| {
            if f.id.is_empty() || f.title.is_empty() {
                tracing::warn!(
                    "cloud finding with empty id/title: id={:?} title={:?}",
                    f.id,
                    f.title
                );
            }
            CloudFindingEntry {
                id: if f.id.is_empty() {
                    "(unknown)".into()
                } else {
                    f.id
                },
                severity: severity_str(f.severity).to_string(),
                title: if f.title.is_empty() {
                    "(no title)".into()
                } else {
                    f.title
                },
                detail: f.detail,
                fix: f.fix,
            }
        })
        .collect()
}

/// Convert a backend [`toride_cloud::spec::Protocol`] to a short display
/// string (`"tcp" | "udp" | "icmp" | "all" | "<n>"`). Mirrors the backend's own
/// `Display` impl but kept self-contained so the convert layer never leaks the
/// enum into presentation.
fn format_protocol(p: toride_cloud::spec::Protocol) -> String {
    use toride_cloud::spec::Protocol;
    match p {
        Protocol::Tcp => "tcp".into(),
        Protocol::Udp => "udp".into(),
        Protocol::Icmp => "icmp".into(),
        Protocol::All => "all".into(),
        Protocol::Other(n) => n.to_string(),
    }
}

/// Convert a single backend [`toride_cloud::spec::FirewallRule`] to a UI row.
///
/// Malformed rules (empty CIDR with no port, or a protocol that renders blank)
/// are logged and still produced with a placeholder so the rule count matches
/// the backend — the operator can see the row exists even if its fields are
/// unusual.
fn convert_rule(rule: toride_cloud::spec::FirewallRule) -> FirewallRuleEntry {
    let protocol = format_protocol(rule.protocol);
    if protocol.is_empty() {
        tracing::warn!("cloud firewall rule with blank protocol: id={:?}", rule.id);
    }
    let cidr = if rule.cidr.is_empty() {
        "(any)".into()
    } else {
        rule.cidr
    };
    let port = rule.port_range.map(|pr| {
        if pr.is_single() {
            pr.start.to_string()
        } else {
            format!("{}-{}", pr.start, pr.end)
        }
    });
    FirewallRuleEntry {
        direction: if rule.is_ingress { "ingress" } else { "egress" }.into(),
        protocol,
        port,
        cidr,
        action: match rule.action {
            toride_cloud::spec::RuleAction::Allow => "allow",
            toride_cloud::spec::RuleAction::Deny => "deny",
        }
        .into(),
        description: rule.description,
    }
}

/// Convert backend security groups to UI rows.
///
/// Each group is mapped 1:1; an empty group name is logged and replaced with a
/// placeholder so the row is still visible. The rule list per group is
/// converted via [`convert_rule`] (best-effort; malformed rules keep their
/// row with placeholders). The ingress/egress counts are derived from the
/// converted rule list so they always agree with what is rendered.
pub fn convert_security_groups(
    groups: Vec<toride_cloud::spec::SecurityGroup>,
) -> Vec<SecurityGroupEntry> {
    groups
        .into_iter()
        .map(|g| {
            if g.name.is_empty() {
                tracing::warn!("cloud security group with empty name: id={:?}", g.id);
            }
            let rules: Vec<FirewallRuleEntry> = g.rules.into_iter().map(convert_rule).collect();
            let ingress_count = rules.iter().filter(|r| r.direction == "ingress").count();
            let egress_count = rules.iter().filter(|r| r.direction == "egress").count();
            SecurityGroupEntry {
                name: if g.name.is_empty() {
                    "(unnamed)".into()
                } else {
                    g.name
                },
                description: g.description,
                rules,
                ingress_count,
                egress_count,
            }
        })
        .collect()
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use toride_cloud::CloudProvider;
    use toride_cloud::report::{Finding, Severity};
    use toride_cloud::spec::{FirewallRule, PortRange, Protocol, RuleAction, SecurityGroup};

    // ── format_provider / convert_provider ───────────────────────────────────

    #[test]
    fn format_provider_known() {
        assert_eq!(format_provider(CloudProvider::Aws), "AWS");
        assert_eq!(format_provider(CloudProvider::Gcp), "GCP");
        assert_eq!(format_provider(CloudProvider::DigitalOcean), "DigitalOcean");
        assert_eq!(format_provider(CloudProvider::Hetzner), "Hetzner");
    }

    #[test]
    fn format_provider_unknown_is_none_not_unknown() {
        // On a dev box with no cloud VM, "none" reads as the expected state,
        // not an error. The literal "unknown" would look like a bug.
        assert_eq!(format_provider(CloudProvider::Unknown), "none");
    }

    #[test]
    fn convert_provider_includes_cli_tool_when_known() {
        let info = convert_provider(CloudProvider::Aws);
        assert_eq!(info.provider, "AWS");
        assert_eq!(info.cli_tool.as_deref(), Some("aws"));
        assert!(info.metadata_url.is_some());
    }

    #[test]
    fn convert_provider_unknown_has_no_cli_tool() {
        let info = convert_provider(CloudProvider::Unknown);
        assert_eq!(info.provider, "none");
        assert!(info.cli_tool.is_none());
        assert!(info.metadata_url.is_none());
    }

    // ── convert_findings ─────────────────────────────────────────────────────

    #[test]
    fn convert_findings_empty() {
        assert!(convert_findings(Vec::new()).is_empty());
    }

    #[test]
    fn convert_findings_maps_severity() {
        let findings = vec![
            Finding::new("a", Severity::Critical, "t1"),
            Finding::new("b", Severity::Error, "t2"),
            Finding::new("c", Severity::Warning, "t3"),
            Finding::new("d", Severity::Info, "t4"),
            Finding::new("e", Severity::Ok, "t5"),
        ];
        let entries = convert_findings(findings);
        assert_eq!(entries.len(), 5);
        assert_eq!(entries[0].severity, "critical");
        assert_eq!(entries[1].severity, "error");
        assert_eq!(entries[2].severity, "warning");
        assert_eq!(entries[3].severity, "info");
        assert_eq!(entries[4].severity, "ok");
    }

    #[test]
    fn convert_findings_preserves_detail_and_fix() {
        let f = Finding::new("id", Severity::Warning, "title")
            .detail("the detail")
            .fix("the fix");
        let entries = convert_findings(vec![f]);
        assert_eq!(entries[0].detail, "the detail");
        assert_eq!(entries[0].fix.as_deref(), Some("the fix"));
    }

    #[test]
    fn convert_findings_placeholder_for_empty_fields() {
        let f = Finding::new("", Severity::Ok, "");
        let entries = convert_findings(vec![f]);
        assert_eq!(entries[0].id, "(unknown)");
        assert_eq!(entries[0].title, "(no title)");
    }

    // ── convert_security_groups ──────────────────────────────────────────────

    #[test]
    fn convert_security_groups_empty() {
        assert!(convert_security_groups(Vec::new()).is_empty());
    }

    #[test]
    fn convert_security_groups_maps_name_and_counts() {
        let mut g = SecurityGroup::new("web-sg", CloudProvider::Aws);
        g.rules.push(FirewallRule {
            id: None,
            description: String::new(),
            is_ingress: true,
            protocol: Protocol::Tcp,
            port_range: Some(PortRange::single(443)),
            cidr: "0.0.0.0/0".into(),
            action: RuleAction::Allow,
        });
        g.rules.push(FirewallRule {
            id: None,
            description: String::new(),
            is_ingress: false,
            protocol: Protocol::All,
            port_range: None,
            cidr: "0.0.0.0/0".into(),
            action: RuleAction::Allow,
        });
        let entries = convert_security_groups(vec![g]);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "web-sg");
        assert_eq!(entries[0].ingress_count, 1);
        assert_eq!(entries[0].egress_count, 1);
        assert_eq!(entries[0].rules[0].direction, "ingress");
        assert_eq!(entries[0].rules[0].protocol, "tcp");
        assert_eq!(entries[0].rules[0].port.as_deref(), Some("443"));
        assert_eq!(entries[0].rules[0].cidr, "0.0.0.0/0");
        assert_eq!(entries[0].rules[0].action, "allow");
        assert_eq!(entries[0].rules[1].direction, "egress");
        assert_eq!(entries[0].rules[1].protocol, "all");
        assert!(entries[0].rules[1].port.is_none());
    }

    #[test]
    fn convert_security_groups_empty_name_gets_placeholder() {
        let g = SecurityGroup::new("", CloudProvider::Unknown);
        let entries = convert_security_groups(vec![g]);
        assert_eq!(entries[0].name, "(unnamed)");
    }

    #[test]
    fn convert_security_groups_port_range_renders_range() {
        let mut g = SecurityGroup::new("sg", CloudProvider::Gcp);
        g.rules.push(FirewallRule {
            id: None,
            description: String::new(),
            is_ingress: true,
            protocol: Protocol::Tcp,
            port_range: Some(PortRange::range(8000, 8100)),
            cidr: "10.0.0.0/8".into(),
            action: RuleAction::Allow,
        });
        let entries = convert_security_groups(vec![g]);
        assert_eq!(entries[0].rules[0].port.as_deref(), Some("8000-8100"));
    }

    #[test]
    fn convert_security_groups_empty_cidr_becomes_any() {
        let mut g = SecurityGroup::new("sg", CloudProvider::Hetzner);
        g.rules.push(FirewallRule {
            id: None,
            description: String::new(),
            is_ingress: true,
            protocol: Protocol::Icmp,
            port_range: None,
            cidr: String::new(),
            action: RuleAction::Deny,
        });
        let entries = convert_security_groups(vec![g]);
        assert_eq!(entries[0].rules[0].cidr, "(any)");
        assert_eq!(entries[0].rules[0].action, "deny");
        assert_eq!(entries[0].rules[0].protocol, "icmp");
    }

    // Finding 1: Protocol::Other(N) must render as the raw number string and
    // must NOT trip the blank-protocol warning path. SCTP is protocol 132.
    #[test]
    fn convert_security_groups_other_protocol_renders_number() {
        let mut g = SecurityGroup::new("sctp-sg", CloudProvider::Aws);
        g.rules.push(FirewallRule {
            id: None,
            description: String::new(),
            is_ingress: true,
            protocol: Protocol::Other(132),
            port_range: None,
            cidr: "0.0.0.0/0".into(),
            action: RuleAction::Allow,
        });
        let entries = convert_security_groups(vec![g]);
        assert_eq!(entries[0].rules[0].protocol, "132");
        // A valid Other value is non-empty, so the entry is produced normally
        // (no placeholder substitution happens for protocol).
        assert_eq!(entries[0].rules[0].direction, "ingress");
        assert_eq!(entries[0].rules[0].action, "allow");
        assert!(entries[0].rules[0].port.is_none());
    }

    // Finding 2a: A SecurityGroup with no rules must yield zero ingress/egress
    // counts and an empty rule list — guards against a future refactor that
    // initializes counts to a non-zero default.
    #[test]
    fn convert_security_groups_empty_rules_yield_zero_counts() {
        let g = SecurityGroup::new("empty-sg", CloudProvider::Aws);
        let entries = convert_security_groups(vec![g]);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "empty-sg");
        assert_eq!(entries[0].ingress_count, 0);
        assert_eq!(entries[0].egress_count, 0);
        assert!(entries[0].rules.is_empty());
    }

    // Finding 2b: A degenerate PortRange::range where start > end still has
    // is_single() == false (start != end), so it takes the range branch and
    // renders literally as "90-80". Asserting the exact rendered string pins
    // current behavior so a future change to the range branch is noticed.
    #[test]
    fn convert_security_groups_degenerate_range_renders_verbatim() {
        let mut g = SecurityGroup::new("sg", CloudProvider::Gcp);
        g.rules.push(FirewallRule {
            id: None,
            description: String::new(),
            is_ingress: true,
            protocol: Protocol::Tcp,
            port_range: Some(PortRange::range(90, 80)),
            cidr: "0.0.0.0/0".into(),
            action: RuleAction::Allow,
        });
        let entries = convert_security_groups(vec![g]);
        assert_eq!(entries[0].rules[0].port.as_deref(), Some("90-80"));
    }
}
