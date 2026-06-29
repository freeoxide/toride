//! Comprehensive tests for the render module.
//!
//! Covers managed_header, render_jail_local, render_filter_local,
//! render_action_local, filename helpers, and snapshot-based output
//! verification using insta.

use super::*;
use std::collections::HashMap;
use std::path::Path;
use std::str::FromStr;
use std::time::Duration;

use crate::spec::*;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Minimal jail spec with only required fields filled in.
fn minimal_jail() -> JailSpec {
    JailSpec::builder()
        .name(JailName::new("myapp").unwrap())
        .filter(
            FilterSpec::builder()
                .name(FilterName::new("myapp-auth").unwrap())
                .failregex(vec![
                    RegexLine::new("^Authentication failure <HOST>$").unwrap(),
                ])
                .build(),
        )
        .bantime(DurationSpec::new("10m").unwrap())
        .findtime(DurationSpec::new("10m").unwrap())
        .log_paths(vec![LogPath::new(Path::new("/tmp/auth.log")).unwrap()])
        .build()
}

/// Full-featured jail spec exercising every optional field.
fn full_jail() -> JailSpec {
    let mut action_params = HashMap::new();
    action_params.insert("name".into(), "ssh".into());
    action_params.insert("port".into(), "ssh".into());

    let mut extras = HashMap::new();
    extras.insert("zz_custom".into(), "value".into());
    extras.insert("aa_custom".into(), "value".into());

    JailSpec::builder()
        .name(JailName::new("ssh").unwrap())
        .enabled(false)
        .filter(
            FilterSpec::builder()
                .name(FilterName::new("sshd").unwrap())
                .failregex(vec![RegexLine::new("^Failed <HOST>$").unwrap()])
                .mode(Some("aggressive".into()))
                .build(),
        )
        .backend(Backend::Systemd)
        .log_paths(vec![
            LogPath::new(Path::new("/var/log/auth.log")).unwrap(),
            LogPath::new(Path::new("/var/log/auth.log.1")).unwrap(),
        ])
        .journal_matches(vec![
            JournalMatch::new("_SYSTEMD_UNIT=sshd.service").unwrap(),
            JournalMatch::new("_SYSTEMD_UNIT=sshd-extra.service").unwrap(),
        ])
        .ports(vec![PortSpec::new(22), PortSpec::new(80)])
        .protocol(Protocol::Both)
        .bantime(DurationSpec::new("1h").unwrap())
        .findtime(DurationSpec::new("10m").unwrap())
        .maxretry(3)
        .usedns(UseDns::Warn)
        .ignore_ips(IgnoreIpList::new(vec![
            IpOrCidr::from_str("127.0.0.1/8").unwrap(),
            IpOrCidr::from_str("::1").unwrap(),
        ]))
        .maxlines(Some(10))
        .actions(vec![
            ActionSpec::stock("nftables-multiport").unwrap(),
            ActionSpec::builder()
                .name(ActionName::new("iptables-custom").unwrap())
                .kind(ActionKind::Stock)
                .stock_name(Some("iptables-multiport".into()))
                .parameters(action_params)
                .build(),
        ])
        .extra_options(extras)
        .build()
}

// ===========================================================================
// managed_header
// ===========================================================================

#[test]
fn managed_header_returns_expected_string() {
    let header = managed_header();
    assert!(header.contains("Managed by fail2ban-kit"));
    assert!(header.contains("Do not edit manually"));
}

#[test]
fn managed_header_starts_with_hash() {
    assert!(managed_header().starts_with('#'));
}

#[test]
fn managed_header_is_static_str() {
    // Ensure the function returns &'static str, not a String.
    let _static_ref: &'static str = managed_header();
}

// ===========================================================================
// render_jail_local — snapshot tests
// ===========================================================================

#[test]
fn snapshot_jail_local_minimal() {
    let jail = minimal_jail();
    let out = render_jail_local(&jail, "managed-by-fail2ban-kit");
    insta::assert_snapshot!("jail_local_minimal", out);
}

#[test]
fn snapshot_jail_local_full() {
    let jail = full_jail();
    let out = render_jail_local(&jail, "ns");
    insta::assert_snapshot!("jail_local_full", out);
}

// ===========================================================================
// render_jail_local — structural assertions
// ===========================================================================

#[test]
fn jail_local_includes_managed_header() {
    let jail = minimal_jail();
    let out = render_jail_local(&jail, "ns");
    assert!(out.starts_with("# Managed by fail2ban-kit"));
}

#[test]
fn jail_local_section_header_matches_name() {
    let jail = minimal_jail();
    let out = render_jail_local(&jail, "ns");
    assert!(out.contains("[myapp]"));
}

#[test]
fn jail_local_always_emits_enabled() {
    let jail = minimal_jail();
    let out = render_jail_local(&jail, "ns");
    assert!(out.contains("enabled = true"));
}

#[test]
fn jail_local_always_emits_bantime_and_findtime() {
    let jail = minimal_jail();
    let out = render_jail_local(&jail, "ns");
    assert!(out.contains("bantime = 10m"));
    assert!(out.contains("findtime = 10m"));
}

#[test]
fn jail_local_emits_filter_without_mode_when_none() {
    let jail = minimal_jail();
    let out = render_jail_local(&jail, "ns");
    assert!(out.contains("filter = myapp-auth"));
    assert!(!out.contains("filter = myapp-auth[mode="));
}

#[test]
fn jail_local_emits_filter_with_mode_when_set() {
    let jail = JailSpec::builder()
        .name(JailName::new("ssh").unwrap())
        .filter(
            FilterSpec::builder()
                .name(FilterName::new("sshd").unwrap())
                .failregex(vec![RegexLine::new("^Failed <HOST>$").unwrap()])
                .mode(Some("aggressive".into()))
                .build(),
        )
        .bantime(DurationSpec::new("1h").unwrap())
        .findtime(DurationSpec::new("10m").unwrap())
        .log_paths(vec![LogPath::new(Path::new("/tmp/auth.log")).unwrap()])
        .build();

    let out = render_jail_local(&jail, "ns");
    assert!(out.contains("filter = sshd[mode=aggressive]"));
}

// ===========================================================================
// render_jail_local — optional field omission
// ===========================================================================

#[test]
fn jail_local_omits_default_backend() {
    let jail = minimal_jail();
    let out = render_jail_local(&jail, "ns");
    assert!(!out.contains("backend = auto"));
}

#[test]
fn jail_local_omits_default_protocol() {
    let jail = minimal_jail();
    let out = render_jail_local(&jail, "ns");
    assert!(!out.contains("protocol = tcp"));
}

#[test]
fn jail_local_omits_default_usedns() {
    let jail = minimal_jail();
    let out = render_jail_local(&jail, "ns");
    assert!(!out.contains("usedns = no"));
}

#[test]
fn jail_local_omits_default_maxretry() {
    let jail = minimal_jail();
    let out = render_jail_local(&jail, "ns");
    assert!(!out.contains("maxretry ="));
}

#[test]
fn jail_local_omits_empty_ignore_ips() {
    let jail = minimal_jail();
    let out = render_jail_local(&jail, "ns");
    assert!(!out.contains("ignoreip"));
}

#[test]
fn jail_local_omits_none_maxlines() {
    let jail = minimal_jail();
    let out = render_jail_local(&jail, "ns");
    assert!(!out.contains("maxlines"));
}

#[test]
fn jail_local_omits_empty_journal_matches() {
    let jail = minimal_jail();
    let out = render_jail_local(&jail, "ns");
    assert!(!out.contains("journalmatch"));
}

#[test]
fn jail_local_omits_empty_ports() {
    let jail = minimal_jail();
    let out = render_jail_local(&jail, "ns");
    assert!(!out.contains("port ="));
}

#[test]
fn jail_local_omits_empty_actions() {
    let jail = minimal_jail();
    let out = render_jail_local(&jail, "ns");
    assert!(!out.contains("action ="));
}

// ===========================================================================
// render_jail_local — non-default values are emitted
// ===========================================================================

#[test]
fn jail_local_emits_systemd_backend() {
    let jail = JailSpec::builder()
        .name(JailName::new("sd").unwrap())
        .filter(
            FilterSpec::builder()
                .name(FilterName::new("f").unwrap())
                .failregex(vec![RegexLine::new("^fail <HOST>$").unwrap()])
                .build(),
        )
        .bantime(DurationSpec::new("10m").unwrap())
        .findtime(DurationSpec::new("10m").unwrap())
        .backend(Backend::Systemd)
        .journal_matches(vec![JournalMatch::new("_SYSTEMD_UNIT=x.service").unwrap()])
        .build();

    let out = render_jail_local(&jail, "ns");
    assert!(out.contains("backend = systemd"));
}

#[test]
fn jail_local_emits_polling_backend() {
    let jail = JailSpec::builder()
        .name(JailName::new("poll").unwrap())
        .filter(
            FilterSpec::builder()
                .name(FilterName::new("f").unwrap())
                .failregex(vec![RegexLine::new("^fail <HOST>$").unwrap()])
                .build(),
        )
        .bantime(DurationSpec::new("10m").unwrap())
        .findtime(DurationSpec::new("10m").unwrap())
        .backend(Backend::Polling)
        .log_paths(vec![LogPath::new(Path::new("/tmp/a.log")).unwrap()])
        .build();

    let out = render_jail_local(&jail, "ns");
    assert!(out.contains("backend = polling"));
}

#[test]
fn jail_local_emits_custom_maxretry() {
    let jail = JailSpec::builder()
        .name(JailName::new("x").unwrap())
        .filter(
            FilterSpec::builder()
                .name(FilterName::new("f").unwrap())
                .failregex(vec![RegexLine::new("^fail <HOST>$").unwrap()])
                .build(),
        )
        .bantime(DurationSpec::new("10m").unwrap())
        .findtime(DurationSpec::new("10m").unwrap())
        .log_paths(vec![LogPath::new(Path::new("/tmp/a.log")).unwrap()])
        .maxretry(10)
        .build();

    let out = render_jail_local(&jail, "ns");
    assert!(out.contains("maxretry = 10"));
}

#[test]
fn jail_local_emits_usedns_warn() {
    let jail = JailSpec::builder()
        .name(JailName::new("x").unwrap())
        .filter(
            FilterSpec::builder()
                .name(FilterName::new("f").unwrap())
                .failregex(vec![RegexLine::new("^fail <HOST>$").unwrap()])
                .build(),
        )
        .bantime(DurationSpec::new("10m").unwrap())
        .findtime(DurationSpec::new("10m").unwrap())
        .log_paths(vec![LogPath::new(Path::new("/tmp/a.log")).unwrap()])
        .usedns(UseDns::Warn)
        .build();

    let out = render_jail_local(&jail, "ns");
    assert!(out.contains("usedns = warn"));
}

#[test]
fn jail_local_emits_usedns_yes() {
    let jail = JailSpec::builder()
        .name(JailName::new("x").unwrap())
        .filter(
            FilterSpec::builder()
                .name(FilterName::new("f").unwrap())
                .failregex(vec![RegexLine::new("^fail <HOST>$").unwrap()])
                .build(),
        )
        .bantime(DurationSpec::new("10m").unwrap())
        .findtime(DurationSpec::new("10m").unwrap())
        .log_paths(vec![LogPath::new(Path::new("/tmp/a.log")).unwrap()])
        .usedns(UseDns::Yes)
        .build();

    let out = render_jail_local(&jail, "ns");
    assert!(out.contains("usedns = yes"));
}

#[test]
fn jail_local_emits_protocol_udp() {
    let jail = JailSpec::builder()
        .name(JailName::new("x").unwrap())
        .filter(
            FilterSpec::builder()
                .name(FilterName::new("f").unwrap())
                .failregex(vec![RegexLine::new("^fail <HOST>$").unwrap()])
                .build(),
        )
        .bantime(DurationSpec::new("10m").unwrap())
        .findtime(DurationSpec::new("10m").unwrap())
        .log_paths(vec![LogPath::new(Path::new("/tmp/a.log")).unwrap()])
        .protocol(Protocol::Udp)
        .build();

    let out = render_jail_local(&jail, "ns");
    assert!(out.contains("protocol = udp"));
}

#[test]
fn jail_local_emits_protocol_both() {
    let jail = JailSpec::builder()
        .name(JailName::new("x").unwrap())
        .filter(
            FilterSpec::builder()
                .name(FilterName::new("f").unwrap())
                .failregex(vec![RegexLine::new("^fail <HOST>$").unwrap()])
                .build(),
        )
        .bantime(DurationSpec::new("10m").unwrap())
        .findtime(DurationSpec::new("10m").unwrap())
        .log_paths(vec![LogPath::new(Path::new("/tmp/a.log")).unwrap()])
        .protocol(Protocol::Both)
        .build();

    let out = render_jail_local(&jail, "ns");
    assert!(out.contains("protocol = both"));
}

#[test]
fn jail_local_emits_ignore_ips() {
    let jail = JailSpec::builder()
        .name(JailName::new("x").unwrap())
        .filter(
            FilterSpec::builder()
                .name(FilterName::new("f").unwrap())
                .failregex(vec![RegexLine::new("^fail <HOST>$").unwrap()])
                .build(),
        )
        .bantime(DurationSpec::new("10m").unwrap())
        .findtime(DurationSpec::new("10m").unwrap())
        .log_paths(vec![LogPath::new(Path::new("/tmp/a.log")).unwrap()])
        .ignore_ips(IgnoreIpList::new(vec![
            IpOrCidr::from_str("127.0.0.1/8").unwrap(),
            IpOrCidr::from_str("::1").unwrap(),
            IpOrCidr::from_str("10.0.0.0/8").unwrap(),
        ]))
        .build();

    let out = render_jail_local(&jail, "ns");
    assert!(out.contains("ignoreip = 127.0.0.1/8 ::1/128 10.0.0.0/8"));
}

#[test]
fn jail_local_emits_maxlines() {
    let jail = JailSpec::builder()
        .name(JailName::new("x").unwrap())
        .filter(
            FilterSpec::builder()
                .name(FilterName::new("f").unwrap())
                .failregex(vec![RegexLine::new("^fail <HOST>$").unwrap()])
                .build(),
        )
        .bantime(DurationSpec::new("10m").unwrap())
        .findtime(DurationSpec::new("10m").unwrap())
        .log_paths(vec![LogPath::new(Path::new("/tmp/a.log")).unwrap()])
        .maxlines(Some(10))
        .build();

    let out = render_jail_local(&jail, "ns");
    assert!(out.contains("maxlines = 10"));
}

// ===========================================================================
// render_jail_local — multiple log_paths (multi-line format)
// ===========================================================================

#[test]
fn jail_local_single_log_path() {
    let jail = JailSpec::builder()
        .name(JailName::new("x").unwrap())
        .filter(
            FilterSpec::builder()
                .name(FilterName::new("f").unwrap())
                .failregex(vec![RegexLine::new("^fail <HOST>$").unwrap()])
                .build(),
        )
        .bantime(DurationSpec::new("10m").unwrap())
        .findtime(DurationSpec::new("10m").unwrap())
        .log_paths(vec![LogPath::new(Path::new("/tmp/a.log")).unwrap()])
        .build();

    let out = render_jail_local(&jail, "ns");
    assert!(out.contains("logpath = /tmp/a.log\n"));
}

#[test]
fn jail_local_multiple_log_paths_uses_continuation() {
    let jail = JailSpec::builder()
        .name(JailName::new("x").unwrap())
        .filter(
            FilterSpec::builder()
                .name(FilterName::new("f").unwrap())
                .failregex(vec![RegexLine::new("^fail <HOST>$").unwrap()])
                .build(),
        )
        .bantime(DurationSpec::new("10m").unwrap())
        .findtime(DurationSpec::new("10m").unwrap())
        .log_paths(vec![
            LogPath::new(Path::new("/var/log/a.log")).unwrap(),
            LogPath::new(Path::new("/var/log/b.log")).unwrap(),
            LogPath::new(Path::new("/var/log/c.log")).unwrap(),
        ])
        .build();

    let out = render_jail_local(&jail, "ns");
    assert!(
        out.contains("logpath = /var/log/a.log\n        /var/log/b.log\n        /var/log/c.log")
    );
}

// ===========================================================================
// render_jail_local — multiple actions (multi-line format)
// ===========================================================================

#[test]
fn jail_local_single_action() {
    let jail = JailSpec::builder()
        .name(JailName::new("x").unwrap())
        .filter(
            FilterSpec::builder()
                .name(FilterName::new("f").unwrap())
                .failregex(vec![RegexLine::new("^fail <HOST>$").unwrap()])
                .build(),
        )
        .bantime(DurationSpec::new("10m").unwrap())
        .findtime(DurationSpec::new("10m").unwrap())
        .log_paths(vec![LogPath::new(Path::new("/tmp/a.log")).unwrap()])
        .actions(vec![ActionSpec::stock("nftables-multiport").unwrap()])
        .build();

    let out = render_jail_local(&jail, "ns");
    assert!(out.contains("action = nftables-multiport\n"));
    // Should not have continuation lines for a single action.
    assert!(!out.contains("        nftables"));
}

#[test]
fn jail_local_multiple_actions_uses_continuation() {
    let jail = JailSpec::builder()
        .name(JailName::new("x").unwrap())
        .filter(
            FilterSpec::builder()
                .name(FilterName::new("f").unwrap())
                .failregex(vec![RegexLine::new("^fail <HOST>$").unwrap()])
                .build(),
        )
        .bantime(DurationSpec::new("10m").unwrap())
        .findtime(DurationSpec::new("10m").unwrap())
        .log_paths(vec![LogPath::new(Path::new("/tmp/a.log")).unwrap()])
        .actions(vec![
            ActionSpec::stock("nftables-multiport").unwrap(),
            ActionSpec::stock("sendmail").unwrap(),
            ActionSpec::stock("iptables-multiport").unwrap(),
        ])
        .build();

    let out = render_jail_local(&jail, "ns");
    assert!(
        out.contains("action = nftables-multiport\n        sendmail\n        iptables-multiport"),
        "multi-action output should use continuation lines"
    );
}

#[test]
fn jail_local_action_with_sorted_parameters() {
    let mut params = HashMap::new();
    params.insert("name".into(), "myapp".into());
    params.insert("port".into(), "http,https".into());

    let jail = JailSpec::builder()
        .name(JailName::new("x").unwrap())
        .filter(
            FilterSpec::builder()
                .name(FilterName::new("f").unwrap())
                .failregex(vec![RegexLine::new("^fail <HOST>$").unwrap()])
                .build(),
        )
        .bantime(DurationSpec::new("10m").unwrap())
        .findtime(DurationSpec::new("10m").unwrap())
        .log_paths(vec![LogPath::new(Path::new("/tmp/a.log")).unwrap()])
        .actions(vec![
            ActionSpec::builder()
                .name(ActionName::new("nft").unwrap())
                .kind(ActionKind::Stock)
                .stock_name(Some("nftables-multiport".into()))
                .parameters(params)
                .build(),
        ])
        .build();

    let out = render_jail_local(&jail, "ns");
    // Parameters are sorted alphabetically: name before port.
    assert!(out.contains("action = nftables-multiport[name=myapp, port=http,https]"));
}

#[test]
fn jail_local_custom_action_uses_name_not_stock() {
    let mut params = HashMap::new();
    params.insert("chain".into(), "INPUT".into());

    let jail = JailSpec::builder()
        .name(JailName::new("x").unwrap())
        .filter(
            FilterSpec::builder()
                .name(FilterName::new("f").unwrap())
                .failregex(vec![RegexLine::new("^fail <HOST>$").unwrap()])
                .build(),
        )
        .bantime(DurationSpec::new("10m").unwrap())
        .findtime(DurationSpec::new("10m").unwrap())
        .log_paths(vec![LogPath::new(Path::new("/tmp/a.log")).unwrap()])
        .actions(vec![
            ActionSpec::builder()
                .name(ActionName::new("my-custom-action").unwrap())
                .kind(ActionKind::Custom)
                .parameters(params)
                .build(),
        ])
        .build();

    let out = render_jail_local(&jail, "ns");
    // Custom action should use its own name, not a stock name.
    assert!(out.contains("action = my-custom-action[chain=INPUT]"));
}

// ===========================================================================
// render_jail_local — extra_options sorted deterministically
// ===========================================================================

#[test]
fn jail_local_extra_options_sorted_alphabetically() {
    let mut extras = HashMap::new();
    extras.insert("zebra_key".into(), "z".into());
    extras.insert("alpha_key".into(), "a".into());
    extras.insert("middle_key".into(), "m".into());

    let jail = JailSpec::builder()
        .name(JailName::new("x").unwrap())
        .filter(
            FilterSpec::builder()
                .name(FilterName::new("f").unwrap())
                .failregex(vec![RegexLine::new("^fail <HOST>$").unwrap()])
                .build(),
        )
        .bantime(DurationSpec::new("10m").unwrap())
        .findtime(DurationSpec::new("10m").unwrap())
        .log_paths(vec![LogPath::new(Path::new("/tmp/a.log")).unwrap()])
        .extra_options(extras)
        .build();

    let out = render_jail_local(&jail, "ns");
    let alpha_pos = out.find("alpha_key").unwrap();
    let middle_pos = out.find("middle_key").unwrap();
    let zebra_pos = out.find("zebra_key").unwrap();
    assert!(
        alpha_pos < middle_pos,
        "extra_options should be sorted alphabetically"
    );
    assert!(
        middle_pos < zebra_pos,
        "extra_options should be sorted alphabetically"
    );
}

// ===========================================================================
// render_jail_local — enabled = false
// ===========================================================================

#[test]
fn jail_local_enabled_false() {
    let jail = JailSpec::builder()
        .name(JailName::new("disabled-jail").unwrap())
        .enabled(false)
        .filter(
            FilterSpec::builder()
                .name(FilterName::new("f").unwrap())
                .failregex(vec![RegexLine::new("^fail <HOST>$").unwrap()])
                .build(),
        )
        .bantime(DurationSpec::new("10m").unwrap())
        .findtime(DurationSpec::new("10m").unwrap())
        .log_paths(vec![LogPath::new(Path::new("/tmp/a.log")).unwrap()])
        .build();

    let out = render_jail_local(&jail, "ns");
    assert!(out.contains("enabled = false"));
}

// ===========================================================================
// render_jail_local — journal_matches multi-line
// ===========================================================================

#[test]
fn jail_local_journal_matches_multiline() {
    let jail = JailSpec::builder()
        .name(JailName::new("journald").unwrap())
        .filter(
            FilterSpec::builder()
                .name(FilterName::new("f").unwrap())
                .failregex(vec![RegexLine::new("^fail <HOST>$").unwrap()])
                .build(),
        )
        .bantime(DurationSpec::new("10m").unwrap())
        .findtime(DurationSpec::new("10m").unwrap())
        .backend(Backend::Systemd)
        .journal_matches(vec![
            JournalMatch::new("_SYSTEMD_UNIT=sshd.service").unwrap(),
            JournalMatch::new("_SYSTEMD_UNIT=extra.service").unwrap(),
        ])
        .build();

    let out = render_jail_local(&jail, "ns");
    assert!(out.contains(
        "journalmatch = _SYSTEMD_UNIT=sshd.service\n               _SYSTEMD_UNIT=extra.service"
    ));
}

// ===========================================================================
// render_jail_local — ports
// ===========================================================================

#[test]
fn jail_local_ports_comma_separated() {
    let jail = JailSpec::builder()
        .name(JailName::new("x").unwrap())
        .filter(
            FilterSpec::builder()
                .name(FilterName::new("f").unwrap())
                .failregex(vec![RegexLine::new("^fail <HOST>$").unwrap()])
                .build(),
        )
        .bantime(DurationSpec::new("10m").unwrap())
        .findtime(DurationSpec::new("10m").unwrap())
        .log_paths(vec![LogPath::new(Path::new("/tmp/a.log")).unwrap()])
        .ports(vec![
            PortSpec::new(80),
            PortSpec::new(443),
            PortSpec::new(8080),
        ])
        .build();

    let out = render_jail_local(&jail, "ns");
    assert!(out.contains("port = 80, 443, 8080"));
}

// ===========================================================================
// render_jail_local — field ordering stability
// ===========================================================================

#[test]
fn jail_local_field_ordering_is_stable() {
    let jail = full_jail();
    let out = render_jail_local(&jail, "ns");

    let enabled_pos = out.find("enabled =").unwrap();
    let filter_pos = out.find("filter =").unwrap();
    let logpath_pos = out.find("logpath =").unwrap();
    let bantime_pos = out.find("bantime =").unwrap();
    let action_pos = out.find("action =").unwrap();

    assert!(
        enabled_pos < filter_pos,
        "enabled should come before filter"
    );
    assert!(
        filter_pos < logpath_pos,
        "filter should come before logpath"
    );
    assert!(
        logpath_pos < bantime_pos,
        "logpath should come before bantime"
    );
    assert!(
        bantime_pos < action_pos,
        "bantime should come before action"
    );
}

// ===========================================================================
// render_filter_local — snapshot tests
// ===========================================================================

#[test]
fn snapshot_filter_local_minimal() {
    let filter = FilterSpec::builder()
        .name(FilterName::new("myapp-auth").unwrap())
        .failregex(vec![
            RegexLine::new("^Authentication failure from <HOST>$").unwrap(),
        ])
        .build();

    let out = render_filter_local(&filter, "ns");
    insta::assert_snapshot!("filter_local_minimal", out);
}

#[test]
fn snapshot_filter_local_full() {
    let filter = FilterSpec::builder()
        .name(FilterName::new("full-filter").unwrap())
        .prefregex(Some("^<F-MLFID>.*</F-MLFID>".into()))
        .failregex(vec![
            RegexLine::new("^Authentication failure from <HOST>$").unwrap(),
            RegexLine::new("^Invalid user .* from <HOST>$").unwrap(),
        ])
        .ignoreregex(vec!["^known-good.*$".into(), "^health-check.*$".into()])
        .datepattern(Some("{^LN-BEG}".into()))
        .journalmatch(Some(JournalMatch::new("_SYSTEMD_UNIT=my.service").unwrap()))
        .mode(Some("aggressive".into()))
        .extra_options({
            let mut m = HashMap::new();
            m.insert("zz_extra".into(), "zv".into());
            m.insert("aa_extra".into(), "av".into());
            m
        })
        .build();

    let out = render_filter_local(&filter, "ns");
    insta::assert_snapshot!("filter_local_full", out);
}

// ===========================================================================
// render_filter_local — structural assertions
// ===========================================================================

#[test]
fn filter_local_includes_managed_header() {
    let filter = FilterSpec::builder()
        .name(FilterName::new("f").unwrap())
        .failregex(vec![RegexLine::new("^fail <HOST>$").unwrap()])
        .build();

    let out = render_filter_local(&filter, "ns");
    assert!(out.starts_with("# Managed by fail2ban-kit"));
}

#[test]
fn filter_local_section_header_matches_name() {
    let filter = FilterSpec::builder()
        .name(FilterName::new("myapp-auth").unwrap())
        .failregex(vec![RegexLine::new("^fail <HOST>$").unwrap()])
        .build();

    let out = render_filter_local(&filter, "ns");
    assert!(out.contains("[myapp-auth]"));
}

#[test]
fn filter_local_single_failregex() {
    let filter = FilterSpec::builder()
        .name(FilterName::new("f").unwrap())
        .failregex(vec![RegexLine::new("^fail <HOST>$").unwrap()])
        .build();

    let out = render_filter_local(&filter, "ns");
    assert!(out.contains("failregex = ^fail <HOST>$"));
}

#[test]
fn filter_local_multiple_failregex_uses_continuation() {
    let filter = FilterSpec::builder()
        .name(FilterName::new("f").unwrap())
        .failregex(vec![
            RegexLine::new("^Authentication failure from <HOST>$").unwrap(),
            RegexLine::new("^Invalid user .* from <HOST>$").unwrap(),
        ])
        .build();

    let out = render_filter_local(&filter, "ns");
    assert!(
        out.contains("failregex = ^Authentication failure from <HOST>$\n            ^Invalid user .* from <HOST>$")
    );
}

#[test]
fn filter_local_emits_prefregex() {
    let filter = FilterSpec::builder()
        .name(FilterName::new("f").unwrap())
        .failregex(vec![RegexLine::new("^fail <HOST>$").unwrap()])
        .prefregex(Some("^<F-MLFID>.*</F-MLFID>".into()))
        .build();

    let out = render_filter_local(&filter, "ns");
    assert!(out.contains("prefregex = ^<F-MLFID>.*</F-MLFID>"));
}

#[test]
fn filter_local_emits_ignoreregex_continuation() {
    let filter = FilterSpec::builder()
        .name(FilterName::new("f").unwrap())
        .failregex(vec![RegexLine::new("^fail <HOST>$").unwrap()])
        .ignoreregex(vec!["^known-good.*$".into(), "^health-check.*$".into()])
        .build();

    let out = render_filter_local(&filter, "ns");
    assert!(out.contains("ignoreregex = ^known-good.*$\n             ^health-check.*$"));
}

#[test]
fn filter_local_emits_datepattern() {
    let filter = FilterSpec::builder()
        .name(FilterName::new("f").unwrap())
        .failregex(vec![RegexLine::new("^fail <HOST>$").unwrap()])
        .datepattern(Some("{^LN-BEG}".into()))
        .build();

    let out = render_filter_local(&filter, "ns");
    assert!(out.contains("datepattern = {^LN-BEG}"));
}

#[test]
fn filter_local_emits_journalmatch() {
    let filter = FilterSpec::builder()
        .name(FilterName::new("f").unwrap())
        .failregex(vec![RegexLine::new("^fail <HOST>$").unwrap()])
        .journalmatch(Some(JournalMatch::new("_SYSTEMD_UNIT=my.service").unwrap()))
        .build();

    let out = render_filter_local(&filter, "ns");
    assert!(out.contains("journalmatch = _SYSTEMD_UNIT=my.service"));
}

#[test]
fn filter_local_emits_mode() {
    let filter = FilterSpec::builder()
        .name(FilterName::new("f").unwrap())
        .failregex(vec![RegexLine::new("^fail <HOST>$").unwrap()])
        .mode(Some("aggressive".into()))
        .build();

    let out = render_filter_local(&filter, "ns");
    assert!(out.contains("mode = aggressive"));
}

#[test]
fn filter_local_extra_options_sorted() {
    let mut extras = HashMap::new();
    extras.insert("zz_key".into(), "zv".into());
    extras.insert("aa_key".into(), "av".into());

    let filter = FilterSpec::builder()
        .name(FilterName::new("f").unwrap())
        .failregex(vec![RegexLine::new("^fail <HOST>$").unwrap()])
        .extra_options(extras)
        .build();

    let out = render_filter_local(&filter, "ns");
    let aa_pos = out.find("aa_key").unwrap();
    let zz_pos = out.find("zz_key").unwrap();
    assert!(aa_pos < zz_pos, "extra_options in filter should be sorted");
}

// ===========================================================================
// render_filter_local — omission of unset fields
// ===========================================================================

#[test]
fn filter_local_omits_unset_prefregex() {
    let filter = FilterSpec::builder()
        .name(FilterName::new("f").unwrap())
        .failregex(vec![RegexLine::new("^fail <HOST>$").unwrap()])
        .build();
    let out = render_filter_local(&filter, "ns");
    assert!(!out.contains("prefregex"));
}

#[test]
fn filter_local_omits_empty_ignoreregex() {
    let filter = FilterSpec::builder()
        .name(FilterName::new("f").unwrap())
        .failregex(vec![RegexLine::new("^fail <HOST>$").unwrap()])
        .build();
    let out = render_filter_local(&filter, "ns");
    assert!(!out.contains("ignoreregex"));
}

#[test]
fn filter_local_omits_unset_datepattern() {
    let filter = FilterSpec::builder()
        .name(FilterName::new("f").unwrap())
        .failregex(vec![RegexLine::new("^fail <HOST>$").unwrap()])
        .build();
    let out = render_filter_local(&filter, "ns");
    assert!(!out.contains("datepattern"));
}

#[test]
fn filter_local_omits_unset_journalmatch() {
    let filter = FilterSpec::builder()
        .name(FilterName::new("f").unwrap())
        .failregex(vec![RegexLine::new("^fail <HOST>$").unwrap()])
        .build();
    let out = render_filter_local(&filter, "ns");
    assert!(!out.contains("journalmatch"));
}

#[test]
fn filter_local_omits_unset_mode() {
    let filter = FilterSpec::builder()
        .name(FilterName::new("f").unwrap())
        .failregex(vec![RegexLine::new("^fail <HOST>$").unwrap()])
        .build();
    let out = render_filter_local(&filter, "ns");
    assert!(!out.contains("mode ="));
}

#[test]
fn filter_local_omits_empty_extra_options() {
    let filter = FilterSpec::builder()
        .name(FilterName::new("f").unwrap())
        .failregex(vec![RegexLine::new("^fail <HOST>$").unwrap()])
        .build();
    let out = render_filter_local(&filter, "ns");
    // Only lines should be header, section, and failregex.
    let non_empty_lines: Vec<&str> = out.lines().filter(|l| !l.is_empty()).collect();
    assert!(
        non_empty_lines.len() == 4,
        "minimal filter should have header (2 lines) + section + failregex, got: {non_empty_lines:?}"
    );
}

// ===========================================================================
// render_filter_local — namespace is unused (reserved)
// ===========================================================================

#[test]
fn filter_local_ignores_namespace() {
    let filter = FilterSpec::builder()
        .name(FilterName::new("f").unwrap())
        .failregex(vec![RegexLine::new("^fail <HOST>$").unwrap()])
        .build();

    let out_a = render_filter_local(&filter, "ns-a");
    let out_b = render_filter_local(&filter, "ns-b");
    assert_eq!(out_a, out_b, "filter output should not depend on namespace");
}

// ===========================================================================
// render_action_local — snapshot tests
// ===========================================================================

#[test]
fn snapshot_action_local_custom_full() {
    let action = ActionSpec::builder()
        .name(ActionName::new("my-hook").unwrap())
        .kind(ActionKind::Custom)
        .actionstart(Some("/usr/local/bin/f2b-hook start".into()))
        .actionstop(Some("/usr/local/bin/f2b-hook stop".into()))
        .actioncheck(Some("/usr/local/bin/f2b-hook check".into()))
        .actionban(Some("/usr/local/bin/f2b-hook ban <ip>".into()))
        .actionunban(Some("/usr/local/bin/f2b-hook unban <ip>".into()))
        .timeout(Some(Duration::from_secs(30)))
        .build();

    let out = render_action_local(&action, "ns");
    insta::assert_snapshot!("action_local_custom_full", out);
}

#[test]
fn snapshot_action_local_stock_minimal() {
    let action = ActionSpec::stock("nftables-multiport").unwrap();
    let out = render_action_local(&action, "ns");
    insta::assert_snapshot!("action_local_stock_minimal", out);
}

// ===========================================================================
// render_action_local — structural assertions
// ===========================================================================

#[test]
fn action_local_includes_managed_header() {
    let action = ActionSpec::stock("nftables").unwrap();
    let out = render_action_local(&action, "ns");
    assert!(out.starts_with("# Managed by fail2ban-kit"));
}

#[test]
fn action_local_section_header_matches_name() {
    let action = ActionSpec::stock("nftables-multiport").unwrap();
    let out = render_action_local(&action, "ns");
    assert!(out.contains("[nftables-multiport]"));
}

#[test]
fn action_local_stock_no_commands_no_output_lines() {
    let action = ActionSpec::stock("nftables-multiport").unwrap();
    let out = render_action_local(&action, "ns");
    assert!(!out.contains("actionstart"));
    assert!(!out.contains("actionstop"));
    assert!(!out.contains("actioncheck"));
    assert!(!out.contains("actionban"));
    assert!(!out.contains("actionunban"));
    assert!(!out.contains("timeout"));
}

#[test]
fn action_local_emits_all_commands() {
    let action = ActionSpec::builder()
        .name(ActionName::new("hook").unwrap())
        .kind(ActionKind::Custom)
        .actionstart(Some("/bin/start".into()))
        .actionstop(Some("/bin/stop".into()))
        .actioncheck(Some("/bin/check".into()))
        .actionban(Some("/bin/ban <ip>".into()))
        .actionunban(Some("/bin/unban <ip>".into()))
        .build();

    let out = render_action_local(&action, "ns");
    assert!(out.contains("actionstart = /bin/start"));
    assert!(out.contains("actionstop = /bin/stop"));
    assert!(out.contains("actioncheck = /bin/check"));
    assert!(out.contains("actionban = /bin/ban <ip>"));
    assert!(out.contains("actionunban = /bin/unban <ip>"));
}

#[test]
fn action_local_emits_timeout() {
    let action = ActionSpec::builder()
        .name(ActionName::new("hook").unwrap())
        .kind(ActionKind::Custom)
        .timeout(Some(Duration::from_secs(60)))
        .build();

    let out = render_action_local(&action, "ns");
    assert!(out.contains("timeout = 60"));
}

#[test]
fn action_local_parameters_sorted() {
    let mut params = HashMap::new();
    params.insert("zebra".into(), "z".into());
    params.insert("alpha".into(), "a".into());
    params.insert("middle".into(), "m".into());

    let action = ActionSpec::builder()
        .name(ActionName::new("x").unwrap())
        .kind(ActionKind::Stock)
        .parameters(params)
        .build();

    let out = render_action_local(&action, "ns");
    let alpha_pos = out.find("alpha").unwrap();
    let middle_pos = out.find("middle").unwrap();
    let zebra_pos = out.find("zebra").unwrap();
    assert!(alpha_pos < middle_pos, "action parameters should be sorted");
    assert!(middle_pos < zebra_pos, "action parameters should be sorted");
}

#[test]
fn action_local_omits_unset_commands() {
    let action = ActionSpec::builder()
        .name(ActionName::new("hook").unwrap())
        .kind(ActionKind::Custom)
        .actionban(Some("/bin/ban <ip>".into()))
        .build();

    let out = render_action_local(&action, "ns");
    assert!(out.contains("actionban = /bin/ban <ip>"));
    assert!(!out.contains("actionstart"));
    assert!(!out.contains("actionstop"));
    assert!(!out.contains("actioncheck"));
    assert!(!out.contains("actionunban"));
}

#[test]
fn action_local_omits_unset_timeout() {
    let action = ActionSpec::stock("nftables").unwrap();
    let out = render_action_local(&action, "ns");
    assert!(!out.contains("timeout"));
}

// ===========================================================================
// render_action_local — namespace is unused (reserved)
// ===========================================================================

#[test]
fn action_local_ignores_namespace() {
    let action = ActionSpec::stock("nftables").unwrap();
    let out_a = render_action_local(&action, "ns-a");
    let out_b = render_action_local(&action, "ns-b");
    assert_eq!(out_a, out_b, "action output should not depend on namespace");
}

// ===========================================================================
// Filename helpers
// ===========================================================================

#[test]
fn render_jail_filename_standard() {
    assert_eq!(
        render_jail_filename("myapp", "managed-by-fail2ban-kit"),
        "managed-by-fail2ban-kit-myapp.local"
    );
}

#[test]
fn render_filter_filename_standard() {
    assert_eq!(
        render_filter_filename("myapp-auth", "managed-by-fail2ban-kit"),
        "managed-by-fail2ban-kit-myapp-auth.local"
    );
}

#[test]
fn render_action_filename_standard() {
    assert_eq!(
        render_action_filename("my-hook", "managed-by-fail2ban-kit"),
        "managed-by-fail2ban-kit-my-hook.local"
    );
}

#[test]
fn render_jail_filename_namespaced() {
    assert_eq!(render_jail_filename("ssh", "toride"), "toride-ssh.local");
}

#[test]
fn render_filter_filename_namespaced() {
    assert_eq!(
        render_filter_filename("sshd", "toride"),
        "toride-sshd.local"
    );
}

#[test]
fn render_action_filename_namespaced() {
    assert_eq!(
        render_action_filename("nftables", "toride"),
        "toride-nftables.local"
    );
}

#[test]
fn all_filename_helpers_use_same_pattern() {
    let name = "test";
    let ns = "ns";
    assert_eq!(
        render_jail_filename(name, ns),
        render_filter_filename(name, ns),
    );
    assert_eq!(
        render_filter_filename(name, ns),
        render_action_filename(name, ns),
    );
}

#[test]
fn filename_ends_with_dot_local() {
    assert!(render_jail_filename("x", "ns").ends_with(".local"));
    assert!(render_filter_filename("x", "ns").ends_with(".local"));
    assert!(render_action_filename("x", "ns").ends_with(".local"));
}

// ===========================================================================
// No empty lines for unset optional fields
// ===========================================================================

#[test]
fn jail_local_no_blank_lines_between_set_fields() {
    let jail = minimal_jail();
    let out = render_jail_local(&jail, "ns");
    // Remove the header block and check the INI body has no consecutive blank lines.
    let body = out.split_once("\n\n").unwrap_or(("", &out)).1;
    assert!(
        !body.contains("\n\n"),
        "jail output should not contain consecutive blank lines in the INI body"
    );
}

#[test]
fn filter_local_no_blank_lines_between_set_fields() {
    let filter = FilterSpec::builder()
        .name(FilterName::new("f").unwrap())
        .failregex(vec![RegexLine::new("^fail <HOST>$").unwrap()])
        .build();

    let out = render_filter_local(&filter, "ns");
    let body = out.split_once("\n\n").unwrap_or(("", &out)).1;
    assert!(
        !body.contains("\n\n"),
        "filter output should not contain consecutive blank lines in the INI body"
    );
}

#[test]
fn action_local_no_blank_lines_between_set_fields() {
    let action = ActionSpec::builder()
        .name(ActionName::new("hook").unwrap())
        .kind(ActionKind::Custom)
        .actionban(Some("/bin/ban <ip>".into()))
        .build();

    let out = render_action_local(&action, "ns");
    let body = out.split_once("\n\n").unwrap_or(("", &out)).1;
    assert!(
        !body.contains("\n\n"),
        "action output should not contain consecutive blank lines in the INI body"
    );
}

// ===========================================================================
// Property-based tests (proptest)
// ===========================================================================

#[cfg(test)]
mod proptests {
    use super::*;
    use crate::spec::*;
    use proptest::prelude::*;

    // -- Strategies ----------------------------------------------------------

    /// Strategy for valid name strings (alphanumeric + hyphens + underscores).
    fn valid_name_strategy() -> impl Strategy<Value = String> {
        let ch = prop::sample::select(
            &[
                'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', '0', '1', '2', '3', '-',
                '_', '.', 'x', 'y', 'z',
            ][..],
        );
        prop::collection::vec(ch, 1..=20)
            .prop_filter("no consecutive dots", |chars| {
                let s: String = chars.iter().collect();
                !s.is_empty() && !s.contains("..") && s.trim() == s
            })
            .prop_map(|chars| chars.into_iter().collect())
    }

    /// Strategy for valid humantime duration strings.
    fn humantime_strategy() -> impl Strategy<Value = String> {
        let unit = prop::sample::select(&["s", "m", "h", "d"][..]);
        let value = 1u64..=10000u64;
        (value, unit).prop_map(|(v, u)| format!("{v}{u}"))
    }

    /// Strategy for a minimal JailSpec with a random valid name.
    fn jail_spec_strategy() -> impl Strategy<Value = JailSpec> {
        (
            valid_name_strategy(),
            valid_name_strategy(),
            humantime_strategy(),
            humantime_strategy(),
        )
            .prop_map(|(jail_name, filter_name, bantime, findtime)| {
                JailSpec::builder()
                    .name(JailName::new(&jail_name).unwrap())
                    .filter(
                        FilterSpec::builder()
                            .name(FilterName::new(&filter_name).unwrap())
                            .failregex(vec![RegexLine::new("^fail <HOST>$").unwrap()])
                            .build(),
                    )
                    .bantime(DurationSpec::new(&bantime).unwrap())
                    .findtime(DurationSpec::new(&findtime).unwrap())
                    .log_paths(vec![LogPath::new(Path::new("/tmp/test.log")).unwrap()])
                    .build()
            })
    }

    /// Strategy for a minimal FilterSpec with a random valid name.
    fn filter_spec_strategy() -> impl Strategy<Value = FilterSpec> {
        valid_name_strategy().prop_map(|name| {
            FilterSpec::builder()
                .name(FilterName::new(&name).unwrap())
                .failregex(vec![RegexLine::new("^fail <HOST>$").unwrap()])
                .build()
        })
    }

    // -- render_jail_local proptests -----------------------------------------

    proptest! {
        #[test]
        fn jail_local_always_contains_managed_header(jail in jail_spec_strategy()) {
            let out = render_jail_local(&jail, "test-ns");
            prop_assert!(
                out.starts_with("# Managed by fail2ban-kit"),
                "output should start with managed header"
            );
        }

        #[test]
        fn jail_local_always_contains_section_header(jail in jail_spec_strategy()) {
            let out = render_jail_local(&jail, "test-ns");
            let expected = format!("[{}]", jail.name.as_str());
            prop_assert!(
                out.contains(&expected),
                "output should contain section header [{}]",
                jail.name.as_str()
            );
        }

        #[test]
        fn jail_local_always_contains_enabled(jail in jail_spec_strategy()) {
            let out = render_jail_local(&jail, "test-ns");
            prop_assert!(
                out.contains("enabled = true") || out.contains("enabled = false"),
                "output should contain 'enabled = true' or 'enabled = false'"
            );
        }

        #[test]
        fn jail_local_always_contains_bantime_and_findtime(
            jail in jail_spec_strategy()
        ) {
            let out = render_jail_local(&jail, "test-ns");
            prop_assert!(
                out.contains(&format!("bantime = {}", jail.bantime.as_str())),
                "output should contain bantime"
            );
            prop_assert!(
                out.contains(&format!("findtime = {}", jail.findtime.as_str())),
                "output should contain findtime"
            );
        }
    }

    // -- render_filter_local proptests ---------------------------------------

    proptest! {
        #[test]
        fn filter_local_always_contains_managed_header(filter in filter_spec_strategy()) {
            let out = render_filter_local(&filter, "test-ns");
            prop_assert!(
                out.starts_with("# Managed by fail2ban-kit"),
                "output should start with managed header"
            );
        }

        #[test]
        fn filter_local_always_contains_section_header(filter in filter_spec_strategy()) {
            let out = render_filter_local(&filter, "test-ns");
            let expected = format!("[{}]", filter.name.as_str());
            prop_assert!(
                out.contains(&expected),
                "output should contain section header [{}]",
                filter.name.as_str()
            );
        }

        #[test]
        fn filter_local_always_contains_failregex(filter in filter_spec_strategy()) {
            let out = render_filter_local(&filter, "test-ns");
            prop_assert!(
                out.contains("failregex"),
                "output should contain 'failregex' key"
            );
        }
    }
}
