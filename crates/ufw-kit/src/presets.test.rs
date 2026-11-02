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
    let p = database(3306).unwrap();
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
fn all_default_presets_returns_twelve_presets() {
    let presets = all_default_presets();
    assert_eq!(presets.len(), 12);
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
    let p = database(3306).unwrap();
    for rule in &p.rules {
        assert!(rule.validate().is_ok());
    }
}

// ---------------------------------------------------------------------------
// tailscale_interface preset
// ---------------------------------------------------------------------------

#[test]
fn tailscale_interface_preset_has_ssh_scoped_to_iface() {
    let p = tailscale_interface();
    assert_eq!(p.id, "tailscale-interface");
    assert_eq!(p.rules.len(), 2);

    let ssh_rule = p
        .rules
        .iter()
        .find(|r| matches!(r.to_port, PortSpec::Single(22)))
        .expect("should have SSH rule");
    assert_eq!(
        ssh_rule.interface.as_deref(),
        Some("tailscale0"),
        "SSH should be scoped to tailscale0 interface"
    );
}

// ---------------------------------------------------------------------------
// wireguard_interface preset
// ---------------------------------------------------------------------------

#[test]
fn wireguard_interface_preset_has_ssh_scoped_to_wg0() {
    let p = wireguard_interface();
    assert_eq!(p.id, "wireguard-interface");
    assert_eq!(p.rules.len(), 2);

    let ssh_rule = p
        .rules
        .iter()
        .find(|r| matches!(r.to_port, PortSpec::Single(22)))
        .expect("should have SSH rule");
    assert_eq!(
        ssh_rule.interface.as_deref(),
        Some("wg0"),
        "SSH should be scoped to wg0 interface"
    );
}

// ---------------------------------------------------------------------------
// cloudflare_allowlist preset
// ---------------------------------------------------------------------------

#[test]
fn cloudflare_allowlist_has_ssh_and_http_per_cf_range() {
    let p = cloudflare_allowlist();
    assert_eq!(p.id, "cloudflare-allowlist");

    // 1 SSH rule + 15 CF ranges * 2 (http + https) = 31 rules
    assert_eq!(p.rules.len(), 31);

    // First rule should be SSH
    assert!(matches!(p.rules[0].action, Action::Limit));
}

// ---------------------------------------------------------------------------
// traefik_dokploy preset
// ---------------------------------------------------------------------------

#[test]
fn traefik_dokploy_has_ssh_http_https() {
    let p = traefik_dokploy();
    assert_eq!(p.id, "traefik-dokploy");
    assert_eq!(p.rules.len(), 3); // SSH + HTTP + HTTPS

    let ports: Vec<u16> = p
        .rules
        .iter()
        .filter_map(|r| match r.to_port {
            PortSpec::Single(p) => Some(p),
            _ => None,
        })
        .collect();
    assert!(ports.contains(&22));
    assert!(ports.contains(&80));
    assert!(ports.contains(&443));
}

// ---------------------------------------------------------------------------
// monitoring_private preset
// ---------------------------------------------------------------------------

#[test]
fn monitoring_private_restricts_to_trusted_cidr() {
    let p = monitoring_private("10.0.0.0/8").unwrap();
    assert_eq!(p.id, "monitoring-private");
    assert_eq!(p.rules.len(), 4); // SSH + Grafana + Prometheus + Node Exporter

    // Monitoring rules should have source address restrictions
    let grafana = p
        .rules
        .iter()
        .find(|r| matches!(r.to_port, PortSpec::Single(3000)))
        .expect("should have Grafana rule");
    assert!(
        !matches!(grafana.from_addr, crate::spec::Address::Any),
        "Grafana should be restricted to trusted CIDR"
    );
}

// ---------------------------------------------------------------------------
// Constructor rejection (no panics on caller-supplied input)
// ---------------------------------------------------------------------------

#[test]
fn monitoring_private_should_reject_invalid_cidr() {
    // Regression: this constructor panicked via .expect on caller input.
    let result = monitoring_private("not-a-cidr");
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        matches!(err, crate::Error::Validation(_)),
        "expected Error::Validation, got: {err:?}"
    );
}

#[test]
fn database_should_reject_port_zero() {
    // Regression: db_port 0 panicked via the builder's expect; spec
    // validation rejects port 0.
    let result = database(0);
    assert!(result.is_err(), "port 0 must be rejected, not panicked on");
}
