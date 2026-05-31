use super::*;
use crate::spec::{Action, PortSpec, ProtocolFilter};

// ---------------------------------------------------------------------------
// ssh preset
// ---------------------------------------------------------------------------

#[test]
fn ssh_preset_has_one_rule_with_limit_action() {
    let p = ssh();
    assert_eq!(p.id, "ssh");
    assert_eq!(p.rules.len(), 1);
    assert_eq!(p.rules[0].action, Action::Limit);
}

// ---------------------------------------------------------------------------
// web_public preset
// ---------------------------------------------------------------------------

#[test]
fn web_public_preset_has_three_rules() {
    let p = web_public();
    assert_eq!(p.id, "web-public");
    assert_eq!(p.rules.len(), 3);
}

// ---------------------------------------------------------------------------
// tailscale preset
// ---------------------------------------------------------------------------

#[test]
fn tailscale_preset_has_two_rules_with_udp() {
    let p = tailscale();
    assert_eq!(p.id, "tailscale");
    assert_eq!(p.rules.len(), 2);

    let udp_rule = p
        .rules
        .iter()
        .find(|r| matches!(r.protocol, ProtocolFilter::Specific(Protocol::Udp)))
        .expect("should have a UDP rule");
    assert!(matches!(udp_rule.to_port, PortSpec::Single(41641)));
}

// ---------------------------------------------------------------------------
// wireguard preset
// ---------------------------------------------------------------------------

#[test]
fn wireguard_preset_has_two_rules_with_port_51820() {
    let p = wireguard();
    assert_eq!(p.id, "wireguard");
    assert_eq!(p.rules.len(), 2);

    let vpn_rule = p
        .rules
        .iter()
        .find(|r| matches!(r.to_port, PortSpec::Single(51820)))
        .expect("should have a rule for port 51820");
    assert!(matches!(
        vpn_rule.protocol,
        ProtocolFilter::Specific(Protocol::Udp)
    ));
}

// ---------------------------------------------------------------------------
// database preset
// ---------------------------------------------------------------------------

#[test]
fn database_preset_with_mysql_port() {
    let p = database(3306);
    assert_eq!(p.id, "database");
    assert_eq!(p.rules.len(), 2);
    assert!(p.description.contains("3306"));

    let db_rule = p
        .rules
        .iter()
        .find(|r| matches!(r.to_port, PortSpec::Single(3306)))
        .expect("should have a rule for MySQL port 3306");
    assert_eq!(db_rule.action, Action::Allow);
}

// ---------------------------------------------------------------------------
// monitoring preset
// ---------------------------------------------------------------------------

#[test]
fn monitoring_preset_has_four_rules() {
    let p = monitoring();
    assert_eq!(p.id, "monitoring");
    assert_eq!(p.rules.len(), 4);
}

// ---------------------------------------------------------------------------
// all_default_presets
// ---------------------------------------------------------------------------

#[test]
fn all_default_presets_returns_seven_presets() {
    let presets = all_default_presets();
    assert_eq!(presets.len(), 7);
}

// ---------------------------------------------------------------------------
// comments all start with "preset:"
// ---------------------------------------------------------------------------

#[test]
fn every_rule_comment_starts_with_preset_prefix() {
    for p in all_default_presets() {
        for rule in &p.rules {
            let comment = rule
                .comment
                .as_deref()
                .unwrap_or_else(|| panic!("rule in preset '{}' has no comment", p.id));
            assert!(
                comment.starts_with("preset:"),
                "comment '{}' in preset '{}' should start with 'preset:'",
                comment,
                p.id,
            );
        }
    }
}

// ---------------------------------------------------------------------------
// all rules validate successfully
// ---------------------------------------------------------------------------

#[test]
fn every_rule_in_every_preset_validates() {
    for p in all_default_presets() {
        for (i, rule) in p.rules.iter().enumerate() {
            assert!(
                rule.validate().is_ok(),
                "rule {i} in preset '{}' failed validation: {:?}",
                p.id,
                rule.validate(),
            );
        }
    }
}

// ---------------------------------------------------------------------------
// database preset with custom port also validates
// ---------------------------------------------------------------------------

#[test]
fn database_preset_with_custom_port_validates() {
    let p = database(3306);
    for rule in &p.rules {
        assert!(rule.validate().is_ok());
    }
}
