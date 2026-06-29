//! Convert `ufw-kit` library types to UI presentation types.
//!
//! This is the ONLY module in the `toride` crate that imports `ufw_kit` types
//! — mirroring `fail2ban_convert.rs`'s role as the single boundary between
//! backend and presentation. Each function handles errors gracefully: malformed
//! input is skipped with a `tracing::warn!` and a placeholder, never propagated
//! (the read-only section must never crash the TUI).

use crate::ui::screens::ufw_kit::{FindingEntry, RuleEntry};

/// Map a backend [`ufw_kit::spec::Severity`] (re-exported from
/// `toride_diagnostic_types::Severity`) to a lowercase string used by the
/// presentation layer: `"ok" | "info" | "warning" | "important" | "critical"`.
/// Kept here so the TUI never imports the Severity enum directly.
fn severity_str(s: ufw_kit::spec::Severity) -> &'static str {
    use ufw_kit::spec::Severity;
    match s {
        Severity::Ok => "ok",
        Severity::Info => "info",
        Severity::Warning => "warning",
        Severity::Important => "important",
        Severity::Critical => "critical",
    }
}

/// Convert backend doctor findings to UI entries.
///
/// Every finding maps 1:1. An empty `title` is logged and the entry is still
/// produced with a placeholder so the row count matches the backend (the
/// operator can see "something" even if the finding is malformed). The backend
/// `id` is `&'static str`, so an empty id becomes `"(unknown)"`.
pub fn convert_findings(findings: Vec<ufw_kit::spec::Finding>) -> Vec<FindingEntry> {
    findings
        .into_iter()
        .map(|f| {
            if f.id.is_empty() || f.title.is_empty() {
                tracing::warn!(
                    "ufw finding with empty id/title: id={:?} title={:?}",
                    f.id,
                    f.title
                );
            }
            FindingEntry {
                id: if f.id.is_empty() {
                    "(unknown)".into()
                } else {
                    f.id.to_string()
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

/// Map a backend [`ufw_kit::spec::Action`] to a lowercase string:
/// `"allow" | "deny" | "reject" | "limit"`. Returns `"(unknown)"` only if the
/// backend parser left the action unset (it is always set in practice).
fn action_str(a: Option<ufw_kit::spec::Action>) -> String {
    use ufw_kit::spec::Action;
    match a {
        Some(Action::Allow) => "allow",
        Some(Action::Deny) => "deny",
        Some(Action::Reject) => "reject",
        Some(Action::Limit) => "limit",
        None => "(unknown)",
    }
    .to_string()
}

/// Map a backend [`ufw_kit::spec::Direction`] to a lowercase string:
/// `"in" | "out" | "routed"`. Returns `"(unknown)"` when the direction was not
/// parsed (UFW omits direction for simple inbound rules).
fn direction_str(d: Option<ufw_kit::spec::Direction>) -> String {
    use ufw_kit::spec::Direction;
    match d {
        Some(Direction::In) => "in",
        Some(Direction::Out) => "out",
        Some(Direction::Routed) => "routed",
        None => "(unknown)",
    }
    .to_string()
}

/// Convert backend parsed rules to UI rows.
///
/// Every rule maps 1:1. The `raw` text is the canonical UFW output and is the
/// most reliable field for display; `action/direction/ipv6/is_route` are parsed
/// best-effort by the backend and surfaced as lowercase labels.
pub fn convert_rules(rules: Vec<ufw_kit::spec::ParsedRule>) -> Vec<RuleEntry> {
    rules
        .into_iter()
        .map(|r| RuleEntry {
            number: r.number,
            action: action_str(r.action),
            direction: direction_str(r.direction),
            ipv6: r.ipv6,
            is_route: r.is_route,
            raw: r.raw,
        })
        .collect()
}

/// Map a backend [`ufw_kit::spec::Policy`] to a lowercase string label.
fn policy_str(p: ufw_kit::spec::Policy) -> &'static str {
    use ufw_kit::spec::Policy;
    match p {
        Policy::Allow => "allow",
        Policy::Deny => "deny",
        Policy::Reject => "reject",
    }
}

/// Map a backend [`ufw_kit::spec::LoggingLevel`] to a lowercase string label.
fn logging_str(l: ufw_kit::spec::LoggingLevel) -> &'static str {
    use ufw_kit::spec::LoggingLevel;
    match l {
        LoggingLevel::Off => "off",
        LoggingLevel::On => "on",
        LoggingLevel::Low => "low",
        LoggingLevel::Medium => "medium",
        LoggingLevel::High => "high",
        LoggingLevel::Full => "full",
    }
}

/// Map a backend [`ufw_kit::spec::Policy`] to its lowercase label, boxed.
#[must_use]
pub fn policy_to_string(p: ufw_kit::spec::Policy) -> String {
    policy_str(p).to_string()
}

/// Map a backend [`ufw_kit::spec::LoggingLevel`] to its lowercase label, boxed.
#[must_use]
pub fn logging_to_string(l: ufw_kit::spec::LoggingLevel) -> String {
    logging_str(l).to_string()
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ufw_kit::spec::{Action, Direction, Finding, LoggingLevel, ParsedRule, Policy, Severity};

    // ── convert_findings ──────────────────────────────────────────────────────

    #[test]
    fn convert_findings_empty() {
        assert!(convert_findings(Vec::new()).is_empty());
    }

    #[test]
    fn convert_findings_maps_severity() {
        let findings = vec![
            Finding {
                id: "a",
                severity: Severity::Critical,
                title: "t1".into(),
                detail: String::new(),
                fix: None,
            },
            Finding {
                id: "b",
                severity: Severity::Important,
                title: "t2".into(),
                detail: String::new(),
                fix: None,
            },
            Finding {
                id: "c",
                severity: Severity::Warning,
                title: "t3".into(),
                detail: String::new(),
                fix: None,
            },
            Finding {
                id: "d",
                severity: Severity::Info,
                title: "t4".into(),
                detail: String::new(),
                fix: None,
            },
            Finding {
                id: "e",
                severity: Severity::Ok,
                title: "t5".into(),
                detail: String::new(),
                fix: None,
            },
        ];
        let entries = convert_findings(findings);
        assert_eq!(entries.len(), 5);
        assert_eq!(entries[0].severity, "critical");
        assert_eq!(entries[1].severity, "important");
        assert_eq!(entries[2].severity, "warning");
        assert_eq!(entries[3].severity, "info");
        assert_eq!(entries[4].severity, "ok");
    }

    #[test]
    fn convert_findings_preserves_detail_and_fix() {
        let f = Finding {
            id: "id",
            severity: Severity::Warning,
            title: "title".into(),
            detail: "the detail".into(),
            fix: Some("the fix".into()),
        };
        let entries = convert_findings(vec![f]);
        assert_eq!(entries[0].detail, "the detail");
        assert_eq!(entries[0].fix.as_deref(), Some("the fix"));
    }

    #[test]
    fn convert_findings_placeholder_for_empty_fields() {
        let f = Finding {
            id: "",
            severity: Severity::Ok,
            title: String::new(),
            detail: String::new(),
            fix: None,
        };
        let entries = convert_findings(vec![f]);
        assert_eq!(entries[0].id, "(unknown)");
        assert_eq!(entries[0].title, "(no title)");
    }

    #[test]
    fn convert_findings_static_str_id_becomes_owned() {
        // Backend id is &'static str; the convert layer must produce an owned String.
        let f = Finding {
            id: "binary.ufw.found",
            severity: Severity::Ok,
            title: "found".into(),
            detail: String::new(),
            fix: None,
        };
        let entries = convert_findings(vec![f]);
        assert_eq!(entries[0].id, "binary.ufw.found");
    }

    // ── convert_rules ─────────────────────────────────────────────────────────

    #[test]
    fn convert_rules_empty() {
        assert!(convert_rules(Vec::new()).is_empty());
    }

    #[test]
    fn convert_rules_maps_action_and_direction() {
        let rules = vec![ParsedRule {
            number: Some(3),
            raw: "22/tcp ALLOW IN Anywhere".into(),
            action: Some(Action::Allow),
            direction: Some(Direction::In),
            protocol: None,
            from: None,
            to: None,
            comment: None,
            ipv6: false,
            is_route: false,
        }];
        let entries = convert_rules(rules);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].number, Some(3));
        assert_eq!(entries[0].action, "allow");
        assert_eq!(entries[0].direction, "in");
        assert_eq!(entries[0].raw, "22/tcp ALLOW IN Anywhere");
        assert!(!entries[0].ipv6);
        assert!(!entries[0].is_route);
    }

    #[test]
    fn convert_rules_unknown_action_and_direction() {
        // Backend parser leaves action/direction as None when it cannot parse.
        let rules = vec![ParsedRule {
            number: None,
            raw: "weird line".into(),
            action: None,
            direction: None,
            protocol: None,
            from: None,
            to: None,
            comment: None,
            ipv6: false,
            is_route: false,
        }];
        let entries = convert_rules(rules);
        assert_eq!(entries[0].action, "(unknown)");
        assert_eq!(entries[0].direction, "(unknown)");
    }

    #[test]
    fn convert_rules_maps_all_action_and_direction_variants() {
        // Pin every match arm of action_str / direction_str through the convert
        // layer. `convert_rules_maps_action_and_direction` only covers the
        // Allow/In happy path; this guards Deny/Reject/Limit and Out so a
        // regression in those arms cannot slip past the convert unit tests.
        let rules = vec![
            ParsedRule {
                number: None,
                raw: "DENY OUT".into(),
                action: Some(Action::Deny),
                direction: Some(Direction::Out),
                protocol: None,
                from: None,
                to: None,
                comment: None,
                ipv6: false,
                is_route: false,
            },
            ParsedRule {
                number: None,
                raw: "REJECT IN".into(),
                action: Some(Action::Reject),
                direction: Some(Direction::In),
                protocol: None,
                from: None,
                to: None,
                comment: None,
                ipv6: false,
                is_route: false,
            },
            ParsedRule {
                number: None,
                raw: "LIMIT IN".into(),
                action: Some(Action::Limit),
                direction: Some(Direction::In),
                protocol: None,
                from: None,
                to: None,
                comment: None,
                ipv6: false,
                is_route: false,
            },
        ];
        let entries = convert_rules(rules);
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].action, "deny");
        assert_eq!(entries[0].direction, "out");
        assert_eq!(entries[1].action, "reject");
        assert_eq!(entries[1].direction, "in");
        assert_eq!(entries[2].action, "limit");
        assert_eq!(entries[2].direction, "in");
    }

    #[test]
    fn convert_rules_ipv6_and_route_flags() {
        let rules = vec![
            ParsedRule {
                number: None,
                raw: "x ALLOW IN Anywhere (v6)".into(),
                action: Some(Action::Allow),
                direction: Some(Direction::In),
                protocol: None,
                from: None,
                to: None,
                comment: None,
                ipv6: true,
                is_route: false,
            },
            ParsedRule {
                number: None,
                raw: "y ROUTE ALLOW IN".into(),
                action: Some(Action::Allow),
                direction: Some(Direction::Routed),
                protocol: None,
                from: None,
                to: None,
                comment: None,
                ipv6: false,
                is_route: true,
            },
        ];
        let entries = convert_rules(rules);
        assert!(entries[0].ipv6);
        assert!(!entries[0].is_route);
        assert!(!entries[1].ipv6);
        assert!(entries[1].is_route);
        assert_eq!(entries[1].direction, "routed");
    }

    // ── policy / logging string helpers ───────────────────────────────────────

    #[test]
    fn policy_labels() {
        assert_eq!(policy_to_string(Policy::Allow), "allow");
        assert_eq!(policy_to_string(Policy::Deny), "deny");
        assert_eq!(policy_to_string(Policy::Reject), "reject");
    }

    #[test]
    fn logging_labels() {
        assert_eq!(logging_to_string(LoggingLevel::Off), "off");
        assert_eq!(logging_to_string(LoggingLevel::On), "on");
        assert_eq!(logging_to_string(LoggingLevel::Low), "low");
        assert_eq!(logging_to_string(LoggingLevel::Medium), "medium");
        assert_eq!(logging_to_string(LoggingLevel::High), "high");
        assert_eq!(logging_to_string(LoggingLevel::Full), "full");
    }
}
