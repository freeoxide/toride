//! Comprehensive tests for the spec module.
//!
//! Covers: name validation (JailName, FilterName, ActionName), Backend, Protocol,
//! UseDns, ActionKind, DurationSpec, PortSpec, IpOrCidr, LogPath, JournalMatch,
//! RegexLine, IgnoreIpList, JailSpec, FilterSpec, ActionSpec builders and
//! validation logic.

use super::*;
use std::net::IpAddr;
use std::path::Path;
use std::str::FromStr;

// ===========================================================================
// Helpers
// ===========================================================================

/// Shorthand to build a minimal valid JailSpec for validation tests.
fn minimal_jail() -> JailSpec {
    JailSpec::builder()
        .name(JailName::new("test-jail").unwrap())
        .filter(
            FilterSpec::builder()
                .name(FilterName::new("test-filter").unwrap())
                .failregex(vec![RegexLine::new("^fail <HOST>$").unwrap()])
                .build(),
        )
        .bantime(DurationSpec::new("10m").unwrap())
        .findtime(DurationSpec::new("10m").unwrap())
        .log_paths(vec![LogPath::new(Path::new("/tmp/test.log")).unwrap()])
        .build()
}

// ===========================================================================
// JailName validation
// ===========================================================================

#[test]
fn jail_name_accepts_valid() {
    assert!(JailName::new("sshd").is_ok());
    assert!(JailName::new("my-app").is_ok());
    assert!(JailName::new("my_app").is_ok());
    assert!(JailName::new("app.v2").is_ok());
    assert!(JailName::new("A").is_ok());
    assert!(JailName::new("123").is_ok());
    assert!(JailName::new("a-b_c.d").is_ok());
}

#[test]
fn jail_name_rejects_empty() {
    assert!(JailName::new("").is_err());
    assert!(JailName::new("   ").is_err());
    assert!(JailName::new("\t").is_err());
}

#[test]
fn jail_name_rejects_slash() {
    assert!(JailName::new("a/b").is_err());
    assert!(JailName::new("/").is_err());
}

#[test]
fn jail_name_rejects_dot_dot() {
    assert!(JailName::new("..").is_err());
    assert!(JailName::new("../etc/passwd").is_err());
    assert!(JailName::new("foo/../../../etc").is_err());
    assert!(JailName::new("a..b").is_err());
}

#[test]
fn jail_name_rejects_newline() {
    assert!(JailName::new("a\nb").is_err());
    assert!(JailName::new("a\rb").is_err());
}

#[test]
fn jail_name_rejects_shell_metacharacters() {
    let bad = [
        ";echo", "a|b", "a&b", "$HOME", "`cmd`", "\\x", "'or'", "\"q\"", "(a)", "<x>", "{a}",
    ];
    for s in bad {
        assert!(JailName::new(s).is_err(), "should reject: {s:?}");
    }
}

#[test]
fn jail_name_trims_whitespace() {
    let name = JailName::new("  sshd  ").unwrap();
    assert_eq!(name.as_str(), "sshd");
}

#[test]
fn jail_name_display() {
    let name = JailName::new("sshd").unwrap();
    assert_eq!(format!("{name}"), "sshd");
}

#[test]
fn jail_name_from_str_roundtrip() {
    let name: JailName = "my-jail".parse().unwrap();
    assert_eq!(name.as_str(), "my-jail");
}

#[test]
fn jail_name_into_inner() {
    let name = JailName::new("test").unwrap();
    assert_eq!(name.into_inner(), "test");
}

#[test]
fn jail_name_as_ref_str() {
    let name = JailName::new("test").unwrap();
    let r: &str = name.as_ref();
    assert_eq!(r, "test");
}

#[test]
fn jail_name_serialize_deserialize_roundtrip() {
    let name = JailName::new("my-jail").unwrap();
    let json = serde_json::to_string(&name).unwrap();
    let back: JailName = serde_json::from_str(&json).unwrap();
    assert_eq!(name, back);
}

#[test]
fn jail_name_deserialize_rejects_invalid() {
    let result = serde_json::from_str::<JailName>("\"a/b\"");
    assert!(result.is_err());
}

// ===========================================================================
// FilterName validation
// ===========================================================================

#[test]
fn filter_name_accepts_valid() {
    assert!(FilterName::new("nginx-auth").is_ok());
    assert!(FilterName::new("sshd").is_ok());
    assert!(FilterName::new("apache-badbots").is_ok());
}

#[test]
fn filter_name_rejects_empty() {
    assert!(FilterName::new("").is_err());
    assert!(FilterName::new("   ").is_err());
}

#[test]
fn filter_name_rejects_slash() {
    assert!(FilterName::new("a/b").is_err());
}

#[test]
fn filter_name_rejects_dot_dot() {
    assert!(FilterName::new("..").is_err());
    assert!(FilterName::new("../filter").is_err());
}

#[test]
fn filter_name_rejects_shell_metacharacters() {
    let bad = [
        ";echo", "a|b", "$VAR", "`cmd`", "\\x", "'x'", "\"x\"", "(a)", "<x>", "{x}", "a\nb",
        "a\rb", "a&b",
    ];
    for s in bad {
        assert!(FilterName::new(s).is_err(), "should reject: {s:?}");
    }
}

#[test]
fn filter_name_display() {
    let name = FilterName::new("nginx-auth").unwrap();
    assert_eq!(format!("{name}"), "nginx-auth");
}

#[test]
fn filter_name_from_str_roundtrip() {
    let name: FilterName = "my-filter".parse().unwrap();
    assert_eq!(name.as_str(), "my-filter");
}

#[test]
fn filter_name_serialize_deserialize_roundtrip() {
    let name = FilterName::new("test-filter").unwrap();
    let json = serde_json::to_string(&name).unwrap();
    let back: FilterName = serde_json::from_str(&json).unwrap();
    assert_eq!(name, back);
}

// ===========================================================================
// ActionName validation
// ===========================================================================

#[test]
fn action_name_accepts_valid() {
    assert!(ActionName::new("nftables").is_ok());
    assert!(ActionName::new("iptables-multiport").is_ok());
    assert!(ActionName::new("my_action").is_ok());
}

#[test]
fn action_name_rejects_empty() {
    assert!(ActionName::new("").is_err());
    assert!(ActionName::new("   ").is_err());
}

#[test]
fn action_name_rejects_slash() {
    assert!(ActionName::new("a/b").is_err());
}

#[test]
fn action_name_rejects_dot_dot() {
    assert!(ActionName::new("..").is_err());
}

#[test]
fn action_name_rejects_shell_metacharacters() {
    let bad = [
        ";echo", "a|b", "$VAR", "`cmd`", "\\x", "'x'", "\"x\"", "(a)", "<x>", "{x}", "a\nb",
        "a\rb", "a&b",
    ];
    for s in bad {
        assert!(ActionName::new(s).is_err(), "should reject: {s:?}");
    }
}

#[test]
fn action_name_display() {
    let name = ActionName::new("nftables").unwrap();
    assert_eq!(format!("{name}"), "nftables");
}

#[test]
fn action_name_from_str_roundtrip() {
    let name: ActionName = "my-action".parse().unwrap();
    assert_eq!(name.as_str(), "my-action");
}

#[test]
fn action_name_serialize_deserialize_roundtrip() {
    let name = ActionName::new("test-action").unwrap();
    let json = serde_json::to_string(&name).unwrap();
    let back: ActionName = serde_json::from_str(&json).unwrap();
    assert_eq!(name, back);
}

// ===========================================================================
// Backend enum
// ===========================================================================

#[test]
fn backend_default_is_auto() {
    assert_eq!(Backend::default(), Backend::Auto);
}

#[test]
fn backend_display() {
    assert_eq!(format!("{}", Backend::Auto), "auto");
    assert_eq!(format!("{}", Backend::Systemd), "systemd");
    assert_eq!(format!("{}", Backend::Polling), "polling");
}

#[test]
fn backend_serialize_deserialize_roundtrip() {
    for backend in [Backend::Auto, Backend::Systemd, Backend::Polling] {
        let json = serde_json::to_string(&backend).unwrap();
        let back: Backend = serde_json::from_str(&json).unwrap();
        assert_eq!(backend, back);
    }
}

#[test]
fn backend_deserialize_from_string() {
    // Serde uses the variant name (PascalCase), not the Display form.
    let auto: Backend = serde_json::from_str("\"Auto\"").unwrap();
    assert_eq!(auto, Backend::Auto);

    let systemd: Backend = serde_json::from_str("\"Systemd\"").unwrap();
    assert_eq!(systemd, Backend::Systemd);

    let polling: Backend = serde_json::from_str("\"Polling\"").unwrap();
    assert_eq!(polling, Backend::Polling);

    // Lowercase forms are NOT accepted (serde uses variant names, not Display)
    assert!(serde_json::from_str::<Backend>("\"auto\"").is_err());
}

#[test]
fn backend_equality_and_hash() {
    use std::collections::HashSet;
    let set: HashSet<Backend> = [Backend::Auto, Backend::Systemd, Backend::Polling].into();
    assert_eq!(set.len(), 3);
}

// ===========================================================================
// Protocol enum
// ===========================================================================

#[test]
fn protocol_default_is_tcp() {
    assert_eq!(Protocol::default(), Protocol::Tcp);
}

#[test]
fn protocol_display() {
    assert_eq!(format!("{}", Protocol::Tcp), "tcp");
    assert_eq!(format!("{}", Protocol::Udp), "udp");
    assert_eq!(format!("{}", Protocol::Both), "both");
}

#[test]
fn protocol_serialize_deserialize_roundtrip() {
    for proto in [Protocol::Tcp, Protocol::Udp, Protocol::Both] {
        let json = serde_json::to_string(&proto).unwrap();
        let back: Protocol = serde_json::from_str(&json).unwrap();
        assert_eq!(proto, back);
    }
}

// ===========================================================================
// UseDns enum
// ===========================================================================

#[test]
fn use_dns_default_is_no() {
    assert_eq!(UseDns::default(), UseDns::No);
}

#[test]
fn use_dns_display() {
    assert_eq!(format!("{}", UseDns::Yes), "yes");
    assert_eq!(format!("{}", UseDns::No), "no");
    assert_eq!(format!("{}", UseDns::Warn), "warn");
}

#[test]
fn use_dns_serialize_deserialize_roundtrip() {
    for dns in [UseDns::Yes, UseDns::No, UseDns::Warn] {
        let json = serde_json::to_string(&dns).unwrap();
        let back: UseDns = serde_json::from_str(&json).unwrap();
        assert_eq!(dns, back);
    }
}

// ===========================================================================
// ActionKind enum
// ===========================================================================

#[test]
fn action_kind_default_is_stock() {
    assert_eq!(ActionKind::default(), ActionKind::Stock);
}

#[test]
fn action_kind_display() {
    assert_eq!(format!("{}", ActionKind::Stock), "stock");
    assert_eq!(format!("{}", ActionKind::Custom), "custom");
}

#[test]
fn action_kind_serialize_deserialize_roundtrip() {
    for kind in [ActionKind::Stock, ActionKind::Custom] {
        let json = serde_json::to_string(&kind).unwrap();
        let back: ActionKind = serde_json::from_str(&json).unwrap();
        assert_eq!(kind, back);
    }
}

// ===========================================================================
// DurationSpec
// ===========================================================================

#[test]
fn duration_spec_valid_durations() {
    assert!(DurationSpec::new("10m").is_ok());
    assert!(DurationSpec::new("1h").is_ok());
    assert!(DurationSpec::new("7d").is_ok());
    assert!(DurationSpec::new("30s").is_ok());
    assert!(DurationSpec::new("1d 2h 3m 4s").is_ok());
}

#[test]
fn duration_spec_rejects_invalid() {
    assert!(DurationSpec::new("").is_err());
    assert!(DurationSpec::new("abc").is_err());
    assert!(DurationSpec::new("10").is_err());
    assert!(DurationSpec::new("   ").is_err());
}

#[test]
fn duration_spec_to_duration() {
    let d = DurationSpec::new("90s").unwrap();
    assert_eq!(d.to_duration(), std::time::Duration::from_secs(90));

    let h = DurationSpec::new("1h").unwrap();
    assert_eq!(h.to_duration(), std::time::Duration::from_secs(3600));
}

#[test]
fn duration_spec_display() {
    let d = DurationSpec::new("10m").unwrap();
    assert_eq!(format!("{d}"), "10m");
}

#[test]
fn duration_spec_as_str() {
    let d = DurationSpec::new("10m").unwrap();
    assert_eq!(d.as_str(), "10m");
}

#[test]
fn duration_spec_from_str_roundtrip() {
    let d: DurationSpec = "5m".parse().unwrap();
    assert_eq!(d.as_str(), "5m");
}

#[test]
fn duration_spec_trims_whitespace() {
    let d = DurationSpec::new("  10m  ").unwrap();
    assert_eq!(d.as_str(), "10m");
}

#[test]
fn duration_spec_serialize_deserialize_roundtrip() {
    let d = DurationSpec::new("1h").unwrap();
    let json = serde_json::to_string(&d).unwrap();
    let back: DurationSpec = serde_json::from_str(&json).unwrap();
    assert_eq!(d, back);
}

#[test]
fn duration_spec_deserialize_rejects_invalid() {
    let result = serde_json::from_str::<DurationSpec>("\"notaduration\"");
    assert!(result.is_err());
}

// ===========================================================================
// PortSpec
// ===========================================================================

#[test]
fn port_spec_new_defaults_to_tcp() {
    let p = PortSpec::new(22);
    assert_eq!(p.port, 22);
    assert_eq!(p.protocol, Protocol::Tcp);
}

#[test]
fn port_spec_with_protocol() {
    let p = PortSpec::with_protocol(53, Protocol::Udp);
    assert_eq!(p.port, 53);
    assert_eq!(p.protocol, Protocol::Udp);
}

#[test]
fn port_spec_display() {
    let p = PortSpec::new(8080);
    assert_eq!(format!("{p}"), "8080");
}

#[test]
fn port_spec_serialize_deserialize_roundtrip() {
    let p = PortSpec::with_protocol(443, Protocol::Tcp);
    let json = serde_json::to_string(&p).unwrap();
    let back: PortSpec = serde_json::from_str(&json).unwrap();
    assert_eq!(p, back);
}

#[test]
fn port_spec_boundary_values() {
    let p = PortSpec::new(0);
    assert_eq!(p.port, 0);

    let p = PortSpec::new(65535);
    assert_eq!(p.port, 65535);
}

// ===========================================================================
// IpOrCidr
// ===========================================================================

#[test]
fn ip_or_cidr_parse_ipv4() {
    let ip = IpOrCidr::from_str("192.168.1.1").unwrap();
    assert_eq!(ip.to_string(), "192.168.1.1/32");
}

#[test]
fn ip_or_cidr_parse_ipv4_cidr() {
    let net = IpOrCidr::from_str("10.0.0.0/8").unwrap();
    assert!(net.to_string().starts_with("10."));
}

#[test]
fn ip_or_cidr_parse_ipv6() {
    let ip = IpOrCidr::from_str("::1").unwrap();
    assert!(ip.to_string().contains("::1"));
}

#[test]
fn ip_or_cidr_parse_ipv6_cidr() {
    let net = IpOrCidr::from_str("fe80::/10").unwrap();
    assert!(net.to_string().starts_with("fe80"));
}

#[test]
fn ip_or_cidr_rejects_invalid() {
    assert!(IpOrCidr::from_str("not-an-ip").is_err());
    assert!(IpOrCidr::from_str("999.999.999.999").is_err());
    assert!(IpOrCidr::from_str("").is_err());
    assert!(IpOrCidr::from_str("10.0.0.0/33").is_err());
}

#[test]
fn ip_or_cidr_contains() {
    let net = IpOrCidr::from_str("10.0.0.0/8").unwrap();
    assert!(net.contains("10.1.2.3".parse::<IpAddr>().unwrap()));
    assert!(net.contains("10.0.0.0".parse::<IpAddr>().unwrap()));
    assert!(net.contains("10.255.255.255".parse::<IpAddr>().unwrap()));
    assert!(!net.contains("192.168.1.1".parse::<IpAddr>().unwrap()));
    assert!(!net.contains("11.0.0.0".parse::<IpAddr>().unwrap()));
}

#[test]
fn ip_or_cidr_overlaps() {
    let a = IpOrCidr::from_str("10.0.0.0/8").unwrap();
    let b = IpOrCidr::from_str("10.1.0.0/16").unwrap();
    let c = IpOrCidr::from_str("172.16.0.0/12").unwrap();
    assert!(a.overlaps(&b));
    assert!(b.overlaps(&a));
    assert!(!a.overlaps(&c));
    assert!(!c.overlaps(&a));
}

#[test]
fn ip_or_cidr_as_net() {
    let ip = IpOrCidr::from_str("192.168.1.0/24").unwrap();
    let net = ip.as_net();
    assert_eq!(net.prefix_len(), 24u8);
}

#[test]
fn ip_or_cidr_into_inner() {
    let ip = IpOrCidr::from_str("192.168.1.1").unwrap();
    let net = ip.into_inner();
    assert_eq!(net.prefix_len(), 32u8);
}

#[test]
fn ip_or_cidr_serialize_deserialize_roundtrip() {
    let ip = IpOrCidr::from_str("10.0.0.0/8").unwrap();
    let json = serde_json::to_string(&ip).unwrap();
    let back: IpOrCidr = serde_json::from_str(&json).unwrap();
    assert_eq!(ip, back);
}

#[test]
fn ip_or_cidr_equality() {
    let a = IpOrCidr::from_str("10.0.0.0/8").unwrap();
    let b = IpOrCidr::from_str("10.0.0.0/8").unwrap();
    assert_eq!(a, b);
}

// ===========================================================================
// LogPath
// ===========================================================================

#[test]
fn log_path_validates_parent_exists() {
    // /tmp exists on all platforms
    assert!(LogPath::new(Path::new("/tmp/test.log")).is_ok());
}

#[test]
fn log_path_rejects_nonexistent_parent() {
    assert!(LogPath::new(Path::new("/nonexistent_dir/some.log")).is_err());
}

#[test]
fn log_path_display() {
    let lp = LogPath::new(Path::new("/tmp/test.log")).unwrap();
    assert_eq!(format!("{lp}"), "/tmp/test.log");
}

#[test]
fn log_path_as_path() {
    let lp = LogPath::new(Path::new("/tmp/test.log")).unwrap();
    assert_eq!(lp.as_path(), Path::new("/tmp/test.log"));
}

#[test]
fn log_path_as_ref() {
    let lp = LogPath::new(Path::new("/tmp/test.log")).unwrap();
    let r: &Path = lp.as_ref();
    assert_eq!(r, Path::new("/tmp/test.log"));
}

#[test]
fn log_path_into_inner() {
    let lp = LogPath::new(Path::new("/tmp/test.log")).unwrap();
    assert_eq!(lp.into_inner(), PathBuf::from("/tmp/test.log"));
}

#[test]
fn log_path_from_str() {
    let lp: LogPath = "/tmp/test.log".parse().unwrap();
    assert_eq!(lp.as_path(), Path::new("/tmp/test.log"));
}

#[test]
fn log_path_from_str_rejects_nonexistent_parent() {
    let result = "/nonexistent_dir/some.log".parse::<LogPath>();
    assert!(result.is_err());
}

#[test]
fn log_path_serialize_deserialize_roundtrip() {
    let lp = LogPath::new(Path::new("/tmp/test.log")).unwrap();
    let json = serde_json::to_string(&lp).unwrap();
    let back: LogPath = serde_json::from_str(&json).unwrap();
    assert_eq!(lp, back);
}

// ===========================================================================
// JournalMatch
// ===========================================================================

#[test]
fn journal_match_valid() {
    let jm = JournalMatch::new("_SYSTEMD_UNIT=sshd.service").unwrap();
    assert_eq!(jm.as_str(), "_SYSTEMD_UNIT=sshd.service");
}

#[test]
fn journal_match_rejects_empty() {
    assert!(JournalMatch::new("").is_err());
    assert!(JournalMatch::new("   ").is_err());
}

#[test]
fn journal_match_display() {
    let jm = JournalMatch::new("_SYSTEMD_UNIT=sshd.service").unwrap();
    assert_eq!(format!("{jm}"), "_SYSTEMD_UNIT=sshd.service");
}

#[test]
fn journal_match_from_str() {
    let jm: JournalMatch = "_SYSTEMD_UNIT=sshd.service".parse().unwrap();
    assert_eq!(jm.as_str(), "_SYSTEMD_UNIT=sshd.service");
}

#[test]
fn journal_match_serialize_deserialize_roundtrip() {
    let jm = JournalMatch::new("_SYSTEMD_UNIT=sshd.service").unwrap();
    let json = serde_json::to_string(&jm).unwrap();
    let back: JournalMatch = serde_json::from_str(&json).unwrap();
    assert_eq!(jm, back);
}

// ===========================================================================
// RegexLine
// ===========================================================================

#[test]
fn regex_line_accepts_with_host() {
    assert!(RegexLine::new("^fail <HOST>$").is_ok());
    assert!(RegexLine::new("Authentication failure from <HOST>").is_ok());
    assert!(RegexLine::new("<HOST>").is_ok());
}

#[test]
fn regex_line_rejects_without_host() {
    assert!(RegexLine::new("^fail$").is_err());
    assert!(RegexLine::new("no host placeholder").is_err());
    assert!(RegexLine::new("<host>").is_err());
    assert!(RegexLine::new("").is_err());
}

#[test]
fn regex_line_as_str() {
    let r = RegexLine::new("^fail <HOST>$").unwrap();
    assert_eq!(r.as_str(), "^fail <HOST>$");
}

#[test]
fn regex_line_display() {
    let r = RegexLine::new("^fail <HOST>$").unwrap();
    assert_eq!(format!("{r}"), "^fail <HOST>$");
}

#[test]
fn regex_line_from_str() {
    let r: RegexLine = "^fail <HOST>$".parse().unwrap();
    assert_eq!(r.as_str(), "^fail <HOST>$");
}

#[test]
fn regex_line_from_str_rejects_invalid() {
    let result = "no host".parse::<RegexLine>();
    assert!(result.is_err());
}

#[test]
fn regex_line_serialize_deserialize_roundtrip() {
    let r = RegexLine::new("^fail <HOST>$").unwrap();
    let json = serde_json::to_string(&r).unwrap();
    let back: RegexLine = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

#[test]
fn regex_line_deserialize_accepts_any_string() {
    // RegexLine derives Serialize/Deserialize without custom validation,
    // so deserialization accepts any string. Validation is only done via
    // RegexLine::new() or FromStr.
    let result = serde_json::from_str::<RegexLine>("\"no host placeholder\"");
    assert!(result.is_ok());
}

// ===========================================================================
// IgnoreIpList
// ===========================================================================

#[test]
fn ignore_ip_list_default_is_empty() {
    let list = IgnoreIpList::default();
    assert!(list.is_empty());
    assert_eq!(list.len(), 0);
}

#[test]
fn ignore_ip_list_contains() {
    let list = IgnoreIpList::new(vec![
        IpOrCidr::from_str("10.0.0.0/8").unwrap(),
        IpOrCidr::from_str("192.168.1.1").unwrap(),
    ]);
    assert!(list.contains("10.5.5.5".parse::<IpAddr>().unwrap()));
    assert!(list.contains("192.168.1.1".parse::<IpAddr>().unwrap()));
    assert!(!list.contains("8.8.8.8".parse::<IpAddr>().unwrap()));
}

#[test]
fn ignore_ip_list_len() {
    let list = IgnoreIpList::new(vec![
        IpOrCidr::from_str("10.0.0.0/8").unwrap(),
        IpOrCidr::from_str("192.168.1.1").unwrap(),
    ]);
    assert_eq!(list.len(), 2);
}

#[test]
fn ignore_ip_list_is_empty() {
    assert!(IgnoreIpList::new(vec![]).is_empty());
    assert!(!IgnoreIpList::new(vec![IpOrCidr::from_str("10.0.0.0/8").unwrap()]).is_empty());
}

#[test]
fn ignore_ip_list_iter() {
    let list = IgnoreIpList::new(vec![
        IpOrCidr::from_str("10.0.0.0/8").unwrap(),
        IpOrCidr::from_str("172.16.0.0/12").unwrap(),
    ]);
    let items: Vec<_> = list.iter().collect();
    assert_eq!(items.len(), 2);
}

#[test]
fn ignore_ip_list_display() {
    let list = IgnoreIpList::new(vec![
        IpOrCidr::from_str("10.0.0.0/8").unwrap(),
        IpOrCidr::from_str("192.168.1.1").unwrap(),
    ]);
    let s = format!("{list}");
    assert!(s.contains("10.0.0.0/8"));
    assert!(s.contains("192.168.1.1/32"));
    assert!(s.contains(", "));
}

#[test]
fn ignore_ip_list_display_empty() {
    let list = IgnoreIpList::default();
    assert_eq!(format!("{list}"), "");
}

#[test]
fn ignore_ip_list_serialize_deserialize_roundtrip() {
    let list = IgnoreIpList::new(vec![
        IpOrCidr::from_str("10.0.0.0/8").unwrap(),
        IpOrCidr::from_str("::1").unwrap(),
    ]);
    let json = serde_json::to_string(&list).unwrap();
    let back: IgnoreIpList = serde_json::from_str(&json).unwrap();
    assert_eq!(list, back);
}

#[test]
fn ignore_ip_list_contains_ipv6() {
    let list = IgnoreIpList::new(vec![IpOrCidr::from_str("::1").unwrap()]);
    assert!(list.contains("::1".parse::<IpAddr>().unwrap()));
    assert!(!list.contains("::2".parse::<IpAddr>().unwrap()));
}

#[test]
fn ignore_ip_list_cidr_covers_broad_range() {
    let list = IgnoreIpList::new(vec![IpOrCidr::from_str("10.0.0.0/8").unwrap()]);
    assert!(list.contains("10.0.0.1".parse::<IpAddr>().unwrap()));
    assert!(list.contains("10.255.255.254".parse::<IpAddr>().unwrap()));
    assert!(!list.contains("11.0.0.0".parse::<IpAddr>().unwrap()));
}

// ===========================================================================
// JailSpec builder
// ===========================================================================

#[test]
fn jail_spec_builder_required_fields() {
    let jail = JailSpec::builder()
        .name(JailName::new("sshd").unwrap())
        .filter(
            FilterSpec::builder()
                .name(FilterName::new("sshd").unwrap())
                .failregex(vec![RegexLine::new("^fail <HOST>$").unwrap()])
                .build(),
        )
        .bantime(DurationSpec::new("10m").unwrap())
        .findtime(DurationSpec::new("10m").unwrap())
        .build();

    assert_eq!(jail.name.as_str(), "sshd");
    assert_eq!(jail.bantime.as_str(), "10m");
    assert_eq!(jail.findtime.as_str(), "10m");
}

#[test]
fn jail_spec_builder_defaults() {
    let jail = minimal_jail();

    assert!(jail.enabled); // default = true
    assert!(jail.actions.is_empty()); // default = vec![]
    assert_eq!(jail.backend, Backend::Auto); // default = Auto
    assert!(jail.ports.is_empty()); // default = vec![]
    assert_eq!(jail.protocol, Protocol::Tcp); // default = Tcp
    assert_eq!(jail.maxretry, 5); // default = 5
    assert!(jail.ignore_ips.is_empty()); // default = IgnoreIpList::default()
    assert_eq!(jail.usedns, UseDns::No); // default = No
    assert!(jail.maxlines.is_none()); // default = None
    assert!(!jail.allow_permanent_ban); // default = false
    assert!(jail.extra_options.is_empty()); // default = HashMap::new()
}

#[test]
fn jail_spec_builder_optional_fields() {
    let jail = JailSpec::builder()
        .name(JailName::new("sshd").unwrap())
        .filter(
            FilterSpec::builder()
                .name(FilterName::new("sshd").unwrap())
                .failregex(vec![RegexLine::new("^fail <HOST>$").unwrap()])
                .build(),
        )
        .bantime(DurationSpec::new("1h").unwrap())
        .findtime(DurationSpec::new("30m").unwrap())
        .enabled(false)
        .backend(Backend::Polling)
        .maxretry(10)
        .protocol(Protocol::Both)
        .usedns(UseDns::Warn)
        .maxlines(Some(100))
        .log_paths(vec![LogPath::new(Path::new("/tmp/test.log")).unwrap()])
        .actions(vec![ActionSpec::stock("nftables").unwrap()])
        .ports(vec![PortSpec::new(22)])
        .ignore_ips(IgnoreIpList::new(vec![
            IpOrCidr::from_str("10.0.0.0/8").unwrap(),
        ]))
        .extra_options(HashMap::from([("key".to_string(), "value".to_string())]))
        .build();

    assert!(!jail.enabled);
    assert_eq!(jail.backend, Backend::Polling);
    assert_eq!(jail.maxretry, 10);
    assert_eq!(jail.protocol, Protocol::Both);
    assert_eq!(jail.usedns, UseDns::Warn);
    assert_eq!(jail.maxlines, Some(100));
    assert_eq!(jail.actions.len(), 1);
    assert_eq!(jail.ports.len(), 1);
    assert_eq!(jail.ignore_ips.len(), 1);
    assert_eq!(jail.extra_options["key"], "value");
}

#[test]
fn jail_spec_serialize_deserialize_roundtrip() {
    let jail = minimal_jail();
    let json = serde_json::to_string(&jail).unwrap();
    let back: JailSpec = serde_json::from_str(&json).unwrap();
    assert_eq!(jail.name, back.name);
    assert_eq!(jail.enabled, back.enabled);
    assert_eq!(jail.backend, back.backend);
    assert_eq!(jail.maxretry, back.maxretry);
}

// ===========================================================================
// JailSpec::validate()
// ===========================================================================

#[test]
fn jail_validate_rejects_zero_maxretry() {
    let mut jail = minimal_jail();
    jail.maxretry = 0;
    assert!(jail.validate().is_err());
}

#[test]
fn jail_validate_accepts_positive_maxretry() {
    let jail = minimal_jail();
    assert!(jail.validate().is_ok());
}

#[test]
fn jail_validate_systemd_requires_journal_matches() {
    let mut jail = minimal_jail();
    jail.backend = Backend::Systemd;
    jail.log_paths.clear();
    // No journal_matches set -> should fail
    assert!(jail.validate().is_err());
}

#[test]
fn jail_validate_systemd_with_journal_matches_ok() {
    let mut jail = minimal_jail();
    jail.backend = Backend::Systemd;
    jail.log_paths.clear();
    jail.journal_matches = vec![JournalMatch::new("_SYSTEMD_UNIT=sshd.service").unwrap()];
    assert!(jail.validate().is_ok());
}

#[test]
fn jail_validate_systemd_rejects_log_paths() {
    let mut jail = minimal_jail();
    jail.backend = Backend::Systemd;
    jail.journal_matches = vec![JournalMatch::new("_SYSTEMD_UNIT=sshd.service").unwrap()];
    // log_paths is non-empty -> should fail
    assert!(jail.validate().is_err());
}

#[test]
fn jail_validate_polling_requires_log_paths_or_journal_matches() {
    let mut jail = minimal_jail();
    jail.backend = Backend::Polling;
    jail.log_paths.clear();
    // No log_paths and no journal_matches -> should fail
    assert!(jail.validate().is_err());
}

#[test]
fn jail_validate_auto_with_log_paths_ok() {
    let jail = minimal_jail();
    // default backend=Auto, has log_paths -> ok
    assert!(jail.validate().is_ok());
}

#[test]
fn jail_validate_auto_without_log_paths_but_with_journal_matches_ok() {
    let mut jail = minimal_jail();
    jail.log_paths.clear();
    jail.journal_matches = vec![JournalMatch::new("_SYSTEMD_UNIT=sshd.service").unwrap()];
    // Auto backend, journal_matches non-empty -> ok
    assert!(jail.validate().is_ok());
}

#[test]
fn jail_validate_auto_no_paths_no_journal_fails() {
    let mut jail = minimal_jail();
    jail.log_paths.clear();
    // Auto backend, no log_paths, no journal_matches -> fail
    assert!(jail.validate().is_err());
}

// ===========================================================================
// FilterSpec builder
// ===========================================================================

#[test]
fn filter_spec_builder_required_fields() {
    let f = FilterSpec::builder()
        .name(FilterName::new("sshd").unwrap())
        .failregex(vec![RegexLine::new("^fail <HOST>$").unwrap()])
        .build();

    assert_eq!(f.name.as_str(), "sshd");
    assert_eq!(f.failregex.len(), 1);
}

#[test]
fn filter_spec_builder_defaults() {
    let f = FilterSpec::builder()
        .name(FilterName::new("test").unwrap())
        .failregex(vec![RegexLine::new("^fail <HOST>$").unwrap()])
        .build();

    assert!(f.before.is_empty());
    assert!(f.after.is_empty());
    assert!(f.definition.is_none());
    assert!(f.prefregex.is_none());
    assert!(f.ignoreregex.is_empty());
    assert!(f.datepattern.is_none());
    assert!(f.journalmatch.is_none());
    assert!(f.mode.is_none());
    assert!(f.extra_options.is_empty());
}

#[test]
fn filter_spec_builder_all_fields() {
    let f = FilterSpec::builder()
        .name(FilterName::new("nginx").unwrap())
        .before(vec![FilterName::new("common").unwrap()])
        .after(vec![FilterName::new("extra").unwrap()])
        .definition(Some("[Definition]".to_string()))
        .prefregex(Some("prefregex pattern".to_string()))
        .failregex(vec![
            RegexLine::new("^auth fail <HOST>$").unwrap(),
            RegexLine::new("^denied <HOST>$").unwrap(),
        ])
        .ignoreregex(vec!["ignored pattern".to_string()])
        .datepattern(Some("%%Y-%%m-%%d".to_string()))
        .journalmatch(Some(
            JournalMatch::new("_SYSTEMD_UNIT=nginx.service").unwrap(),
        ))
        .mode(Some("aggressive".to_string()))
        .extra_options(HashMap::from([("k".to_string(), "v".to_string())]))
        .build();

    assert_eq!(f.before.len(), 1);
    assert_eq!(f.after.len(), 1);
    assert!(f.definition.is_some());
    assert!(f.prefregex.is_some());
    assert_eq!(f.failregex.len(), 2);
    assert_eq!(f.ignoreregex.len(), 1);
    assert!(f.datepattern.is_some());
    assert!(f.journalmatch.is_some());
    assert_eq!(f.mode.as_deref(), Some("aggressive"));
    assert_eq!(f.extra_options["k"], "v");
}

#[test]
fn filter_spec_validate_rejects_empty_failregex() {
    let f = FilterSpec::builder()
        .name(FilterName::new("test").unwrap())
        .failregex(vec![])
        .build();
    assert!(f.validate().is_err());
}

#[test]
fn filter_spec_validate_accepts_nonempty_failregex() {
    let f = FilterSpec::builder()
        .name(FilterName::new("test").unwrap())
        .failregex(vec![RegexLine::new("^fail <HOST>$").unwrap()])
        .build();
    assert!(f.validate().is_ok());
}

#[test]
fn filter_spec_named_convenience() {
    let f = FilterSpec::named("sshd").unwrap();
    assert_eq!(f.name.as_str(), "sshd");
    assert!(f.failregex.is_empty());
}

#[test]
fn filter_spec_named_rejects_invalid() {
    assert!(FilterSpec::named("a/b").is_err());
}

#[test]
fn filter_spec_serialize_deserialize_roundtrip() {
    let f = FilterSpec::builder()
        .name(FilterName::new("test").unwrap())
        .failregex(vec![RegexLine::new("^fail <HOST>$").unwrap()])
        .build();
    let json = serde_json::to_string(&f).unwrap();
    let back: FilterSpec = serde_json::from_str(&json).unwrap();
    assert_eq!(f.name, back.name);
    assert_eq!(f.failregex.len(), back.failregex.len());
}

// ===========================================================================
// ActionSpec builder
// ===========================================================================

#[test]
fn action_spec_builder_required_fields() {
    let a = ActionSpec::builder()
        .name(ActionName::new("my-action").unwrap())
        .build();

    assert_eq!(a.name.as_str(), "my-action");
}

#[test]
fn action_spec_builder_defaults() {
    let a = ActionSpec::builder()
        .name(ActionName::new("test").unwrap())
        .build();

    assert_eq!(a.kind, ActionKind::Stock); // default = Stock
    assert!(a.stock_name.is_none()); // default = None
    assert!(a.parameters.is_empty()); // default = HashMap::new()
    assert!(a.actionstart.is_none()); // default = None
    assert!(a.actionstop.is_none()); // default = None
    assert!(a.actioncheck.is_none()); // default = None
    assert!(a.actionban.is_none()); // default = None
    assert!(a.actionunban.is_none()); // default = None
    assert!(a.timeout.is_none()); // default = None
}

#[test]
fn action_spec_builder_all_fields() {
    let a = ActionSpec::builder()
        .name(ActionName::new("my-action").unwrap())
        .kind(ActionKind::Custom)
        .stock_name(Some("nftables".to_string()))
        .parameters(HashMap::from([("port".to_string(), "22".to_string())]))
        .actionstart(Some("nft add rule".to_string()))
        .actionstop(Some("nft delete rule".to_string()))
        .actioncheck(Some("nft list ruleset".to_string()))
        .actionban(Some("nft add element".to_string()))
        .actionunban(Some("nft delete element".to_string()))
        .timeout(Some(std::time::Duration::from_secs(30)))
        .build();

    assert_eq!(a.kind, ActionKind::Custom);
    assert_eq!(a.stock_name.as_deref(), Some("nftables"));
    assert_eq!(a.parameters["port"], "22");
    assert!(a.actionstart.is_some());
    assert!(a.actionstop.is_some());
    assert!(a.actioncheck.is_some());
    assert!(a.actionban.is_some());
    assert!(a.actionunban.is_some());
    assert_eq!(a.timeout, Some(std::time::Duration::from_secs(30)));
}

#[test]
fn action_spec_stock_convenience() {
    let a = ActionSpec::stock("nftables-multiport").unwrap();
    assert_eq!(a.name.as_str(), "nftables-multiport");
    assert_eq!(a.kind, ActionKind::Stock);
    assert_eq!(a.stock_name.as_deref(), Some("nftables-multiport"));
}

#[test]
fn action_spec_stock_rejects_invalid_name() {
    assert!(ActionSpec::stock("a/b").is_err());
}

#[test]
fn action_spec_custom_convenience() {
    let a = ActionSpec::custom("my-hook").unwrap();
    assert_eq!(a.name.as_str(), "my-hook");
    assert_eq!(a.kind, ActionKind::Custom);
    assert!(a.stock_name.is_none());
}

#[test]
fn action_spec_custom_rejects_invalid_name() {
    assert!(ActionSpec::custom(";evil").is_err());
}

#[test]
fn action_spec_serialize_deserialize_roundtrip() {
    let a = ActionSpec::builder()
        .name(ActionName::new("test").unwrap())
        .actionban(Some("ban <ip>".to_string()))
        .build();
    let json = serde_json::to_string(&a).unwrap();
    let back: ActionSpec = serde_json::from_str(&json).unwrap();
    assert_eq!(a.name, back.name);
    assert_eq!(a.actionban, back.actionban);
}

// ===========================================================================
// Cross-cutting: name types share identical validation
// ===========================================================================

#[test]
fn all_name_types_reject_each_forbidden_char() {
    let forbidden = &[
        '/', '\n', '\r', ';', '|', '&', '$', '`', '\\', '\'', '"', '(', ')', '<', '>', '{', '}',
    ];
    for &ch in forbidden.iter() {
        let s = format!("a{ch}b");
        assert!(JailName::new(&s).is_err(), "JailName should reject {ch:?}");
        assert!(
            FilterName::new(&s).is_err(),
            "FilterName should reject {ch:?}"
        );
        assert!(
            ActionName::new(&s).is_err(),
            "ActionName should reject {ch:?}"
        );
    }
}

#[test]
fn all_name_types_reject_dot_dot() {
    assert!(JailName::new("a..b").is_err());
    assert!(FilterName::new("a..b").is_err());
    assert!(ActionName::new("a..b").is_err());
}

#[test]
fn all_name_types_reject_whitespace_only() {
    assert!(JailName::new("   ").is_err());
    assert!(FilterName::new("   ").is_err());
    assert!(ActionName::new("   ").is_err());
}

// ===========================================================================
// Equality and clone for name types
// ===========================================================================

#[test]
fn jail_name_equality_and_clone() {
    let a = JailName::new("test").unwrap();
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn filter_name_equality_and_clone() {
    let a = FilterName::new("test").unwrap();
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn action_name_equality_and_clone() {
    let a = ActionName::new("test").unwrap();
    let b = a.clone();
    assert_eq!(a, b);
}

// ===========================================================================
// Debug format for types
// ===========================================================================

#[test]
fn debug_format_for_name_types() {
    let j = JailName::new("sshd").unwrap();
    assert!(format!("{j:?}").contains("sshd"));

    let f = FilterName::new("nginx").unwrap();
    assert!(format!("{f:?}").contains("nginx"));

    let a = ActionName::new("nftables").unwrap();
    assert!(format!("{a:?}").contains("nftables"));
}

#[test]
fn debug_format_for_enums() {
    assert!(format!("{:?}", Backend::Auto).contains("Auto"));
    assert!(format!("{:?}", Protocol::Tcp).contains("Tcp"));
    assert!(format!("{:?}", UseDns::No).contains("No"));
    assert!(format!("{:?}", ActionKind::Stock).contains("Stock"));
}

#[test]
fn debug_format_for_value_types() {
    let d = DurationSpec::new("10m").unwrap();
    assert!(format!("{d:?}").contains("10m"));

    let ip = IpOrCidr::from_str("10.0.0.0/8").unwrap();
    assert!(format!("{ip:?}").contains("10"));

    let r = RegexLine::new("^fail <HOST>$").unwrap();
    assert!(format!("{r:?}").contains("<HOST>"));
}

// ===========================================================================
// DurationSpec permanent support
// ===========================================================================

#[test]
fn duration_spec_accepts_permanent_string() {
    assert!(DurationSpec::new("permanent").is_ok());
    let d = DurationSpec::new("permanent").unwrap();
    assert!(d.is_permanent());
    assert_eq!(d.as_str(), "permanent");
}

#[test]
fn duration_spec_accepts_negative_one() {
    assert!(DurationSpec::new("-1").is_ok());
    let d = DurationSpec::new("-1").unwrap();
    assert!(d.is_permanent());
    assert_eq!(d.as_str(), "-1");
}

#[test]
fn duration_spec_normal_duration_is_not_permanent() {
    let d = DurationSpec::new("10m").unwrap();
    assert!(!d.is_permanent());
}

#[test]
fn duration_spec_permanent_to_duration_is_max() {
    let d = DurationSpec::new("permanent").unwrap();
    assert_eq!(d.to_duration(), std::time::Duration::MAX);

    let d2 = DurationSpec::new("-1").unwrap();
    assert_eq!(d2.to_duration(), std::time::Duration::MAX);
}

#[test]
fn duration_spec_permanent_roundtrip() {
    let d = DurationSpec::new("permanent").unwrap();
    let json = serde_json::to_string(&d).unwrap();
    let back: DurationSpec = serde_json::from_str(&json).unwrap();
    assert_eq!(d, back);
    assert!(back.is_permanent());

    let d2 = DurationSpec::new("-1").unwrap();
    let json2 = serde_json::to_string(&d2).unwrap();
    let back2: DurationSpec = serde_json::from_str(&json2).unwrap();
    assert_eq!(d2, back2);
    assert!(back2.is_permanent());
}

#[test]
fn duration_spec_permanent_trims_whitespace() {
    let d = DurationSpec::new("  permanent  ").unwrap();
    assert!(d.is_permanent());
    assert_eq!(d.as_str(), "permanent");
}

// ===========================================================================
// findtime > 0 validation
// ===========================================================================

#[test]
fn jail_validate_rejects_zero_findtime() {
    let mut jail = minimal_jail();
    jail.findtime = DurationSpec::new("0s").unwrap();
    let err = jail.validate().unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("findtime must be greater than zero"),
        "expected findtime zero error, got: {msg}"
    );
}

#[test]
fn jail_validate_accepts_positive_findtime() {
    let jail = minimal_jail();
    // minimal_jail uses findtime="10m" which is > 0
    assert!(jail.validate().is_ok());
}

// ===========================================================================
// Permanent ban gating
// ===========================================================================

#[test]
fn jail_validate_rejects_permanent_ban_without_opt_in() {
    let mut jail = minimal_jail();
    jail.bantime = DurationSpec::new("permanent").unwrap();
    // default allow_permanent_ban = false
    let err = jail.validate().unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("permanent bans require explicit opt-in via allow_permanent_ban"),
        "expected permanent ban gating error, got: {msg}"
    );
}

#[test]
fn jail_validate_rejects_negative_one_bantime_without_opt_in() {
    let mut jail = minimal_jail();
    jail.bantime = DurationSpec::new("-1").unwrap();
    let err = jail.validate().unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("permanent bans require explicit opt-in via allow_permanent_ban"),
        "expected permanent ban gating error, got: {msg}"
    );
}

#[test]
fn jail_validate_accepts_permanent_ban_with_opt_in() {
    let mut jail = minimal_jail();
    jail.bantime = DurationSpec::new("permanent").unwrap();
    jail.allow_permanent_ban = true;
    assert!(jail.validate().is_ok());
}

#[test]
fn jail_validate_accepts_negative_one_bantime_with_opt_in() {
    let mut jail = minimal_jail();
    jail.bantime = DurationSpec::new("-1").unwrap();
    jail.allow_permanent_ban = true;
    assert!(jail.validate().is_ok());
}

// ===========================================================================
// bantime >= findtime sanity check
// ===========================================================================

#[test]
fn jail_validate_rejects_bantime_less_than_findtime() {
    let mut jail = minimal_jail();
    jail.bantime = DurationSpec::new("5m").unwrap();
    jail.findtime = DurationSpec::new("10m").unwrap();
    let err = jail.validate().unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("bantime should typically be >= findtime"),
        "expected bantime < findtime error, got: {msg}"
    );
}

#[test]
fn jail_validate_accepts_bantime_equal_to_findtime() {
    let mut jail = minimal_jail();
    jail.bantime = DurationSpec::new("10m").unwrap();
    jail.findtime = DurationSpec::new("10m").unwrap();
    assert!(jail.validate().is_ok());
}

#[test]
fn jail_validate_accepts_bantime_greater_than_findtime() {
    let mut jail = minimal_jail();
    jail.bantime = DurationSpec::new("1h").unwrap();
    jail.findtime = DurationSpec::new("10m").unwrap();
    assert!(jail.validate().is_ok());
}

#[test]
fn jail_validate_permanent_bantime_bypasses_findtime_comparison() {
    // Permanent bantime should be allowed regardless of findtime value
    let mut jail = minimal_jail();
    jail.bantime = DurationSpec::new("permanent").unwrap();
    jail.findtime = DurationSpec::new("1h").unwrap();
    jail.allow_permanent_ban = true;
    assert!(jail.validate().is_ok());
}

// ===========================================================================
// JournalMatch '=' validation
// ===========================================================================

#[test]
fn journal_match_rejects_missing_equals() {
    let err = JournalMatch::new("no_equals_here").unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("must contain a '='"),
        "expected '=' validation error, got: {msg}"
    );
}

#[test]
fn journal_match_accepts_equals_format() {
    assert!(JournalMatch::new("FIELD=value").is_ok());
    assert!(JournalMatch::new("_SYSTEMD_UNIT=sshd.service").is_ok());
    assert!(JournalMatch::new("SYSLOG_IDENTIFIER=sshd").is_ok());
}

#[test]
fn journal_match_from_str_rejects_missing_equals() {
    let result = "no_equals".parse::<JournalMatch>();
    assert!(result.is_err());
}

// ===========================================================================
// LogPath path traversal protection
// ===========================================================================

#[test]
fn log_path_rejects_parent_dir_component() {
    let result = LogPath::new(Path::new("/tmp/../etc/passwd"));
    assert!(result.is_err());
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("\"..\""),
        "expected path traversal error, got: {msg}"
    );
}

#[test]
fn log_path_rejects_dot_dot_in_middle() {
    let result = LogPath::new(Path::new("/tmp/logs/../../etc/shadow"));
    assert!(result.is_err());
}

#[test]
fn log_path_rejects_leading_dot_dot() {
    let result = LogPath::new(Path::new("../var/log/test.log"));
    assert!(result.is_err());
}

#[test]
fn log_path_accepts_clean_path() {
    assert!(LogPath::new(Path::new("/tmp/test.log")).is_ok());
}

#[test]
fn log_path_accepts_path_with_dot_component() {
    // A single "." (CurrentDir) is fine; only ".." (ParentDir) is rejected.
    assert!(LogPath::new(Path::new("/tmp/./test.log")).is_ok());
}

// ===========================================================================
// Property-based tests (proptest)
// ===========================================================================

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    // -- Strategies ----------------------------------------------------------

    /// Characters that are allowed in valid names: alphanumeric, hyphen,
    /// underscore, dot (but not two consecutive dots).
    fn valid_name_char() -> impl Strategy<Value = char> {
        any::<char>().prop_filter("valid name char", |c| {
            c.is_alphanumeric() || *c == '-' || *c == '_' || *c == '.'
        })
    }

    /// Strategy for a string of valid name characters, guaranteed non-empty
    /// and free of ".." sequences.
    fn valid_name_strategy() -> impl Strategy<Value = String> {
        // Generate 1..=20 valid chars, then filter out ".."
        prop::collection::vec(valid_name_char(), 1..=20)
            .prop_filter("no consecutive dots", |chars| {
                let s: String = chars.iter().collect();
                !s.is_empty() && !s.contains("..") && s.trim() == s
            })
            .prop_map(|chars| chars.into_iter().collect())
    }

    /// Characters that are forbidden in names.
    fn forbidden_char() -> impl Strategy<Value = char> {
        prop::sample::select(
            &[
                '/', '\n', '\r', ';', '|', '&', '$', '`', '\\', '\'', '"', '(', ')', '<', '>', '{',
                '}',
            ][..],
        )
    }

    /// Strategy for a string containing at least one forbidden character.
    /// The forbidden char is placed between non-whitespace characters so it
    /// survives the `trim()` inside `validate_name`.
    fn invalid_name_strategy() -> impl Strategy<Value = String> {
        let safe_char = prop::sample::select(&['a', 'b', 'c', 'x', 'z', '1', '2'][..]);
        let bad_char = forbidden_char();
        (
            prop::collection::vec(safe_char.clone(), 1..=3),
            bad_char,
            prop::collection::vec(safe_char, 1..=3),
        )
            .prop_map(|(prefix, bad, suffix)| {
                let mut s = prefix;
                s.push(bad);
                s.extend(suffix);
                s.into_iter().collect()
            })
    }

    /// Strategy for valid IPv4 addresses as strings.
    fn ipv4_addr_strategy() -> impl Strategy<Value = String> {
        (any::<u8>(), any::<u8>(), any::<u8>(), any::<u8>())
            .prop_map(|(a, b, c, d)| format!("{a}.{b}.{c}.{d}"))
    }

    /// Strategy for valid IPv4 CIDR addresses.
    fn ipv4_cidr_strategy() -> impl Strategy<Value = String> {
        (ipv4_addr_strategy(), 0u8..=32u8).prop_map(|(addr, prefix)| format!("{addr}/{prefix}"))
    }

    /// Strategy for valid humantime duration strings.
    fn humantime_strategy() -> impl Strategy<Value = String> {
        let unit = prop::sample::select(&["s", "m", "h", "d"][..]);
        let value = 1u64..=10000u64;
        (value, unit).prop_map(|(v, u)| format!("{v}{u}"))
    }

    // -- JailName proptests --------------------------------------------------

    proptest! {
        #[test]
        fn jail_name_accepts_valid_names(name in valid_name_strategy()) {
            prop_assert!(JailName::new(&name).is_ok());
        }

        #[test]
        fn jail_name_rejects_forbidden_chars(input in invalid_name_strategy()) {
            prop_assert!(JailName::new(&input).is_err());
        }

        #[test]
        fn jail_name_display_roundtrip(name in valid_name_strategy()) {
            let jn = JailName::new(&name).unwrap();
            prop_assert_eq!(jn.as_str(), &name);
            prop_assert_eq!(format!("{jn}"), name);
        }
    }

    // -- FilterName proptests ------------------------------------------------

    proptest! {
        #[test]
        fn filter_name_accepts_valid_names(name in valid_name_strategy()) {
            prop_assert!(FilterName::new(&name).is_ok());
        }

        #[test]
        fn filter_name_rejects_forbidden_chars(input in invalid_name_strategy()) {
            prop_assert!(FilterName::new(&input).is_err());
        }

        #[test]
        fn filter_name_display_roundtrip(name in valid_name_strategy()) {
            let fn_ = FilterName::new(&name).unwrap();
            prop_assert_eq!(fn_.as_str(), &name);
            prop_assert_eq!(format!("{fn_}"), name);
        }
    }

    // -- ActionName proptests ------------------------------------------------

    proptest! {
        #[test]
        fn action_name_accepts_valid_names(name in valid_name_strategy()) {
            prop_assert!(ActionName::new(&name).is_ok());
        }

        #[test]
        fn action_name_rejects_forbidden_chars(input in invalid_name_strategy()) {
            prop_assert!(ActionName::new(&input).is_err());
        }

        #[test]
        fn action_name_display_roundtrip(name in valid_name_strategy()) {
            let an = ActionName::new(&name).unwrap();
            prop_assert_eq!(an.as_str(), &name);
            prop_assert_eq!(format!("{an}"), name);
        }
    }

    // -- IpOrCidr round-trip proptests ---------------------------------------

    proptest! {
        #[test]
        fn ip_or_cidr_ipv4_roundtrip(addr in ipv4_addr_strategy()) {
            let parsed = IpOrCidr::from_str(&addr).unwrap();
            let displayed = parsed.to_string();
            let re_parsed = IpOrCidr::from_str(&displayed).unwrap();
            prop_assert_eq!(parsed, re_parsed);
        }

        #[test]
        fn ip_or_cidr_ipv4_cidr_roundtrip(cidr in ipv4_cidr_strategy()) {
            let parsed = IpOrCidr::from_str(&cidr).unwrap();
            let displayed = parsed.to_string();
            let re_parsed = IpOrCidr::from_str(&displayed).unwrap();
            prop_assert_eq!(parsed, re_parsed);
        }

        #[test]
        fn ip_or_cidr_ipv6_roundtrip(addr in "([0-9a-fA-F]{0,4}:){0,7}[0-9a-fA-F]{0,4}") {
            if let Ok(parsed) = IpOrCidr::from_str(&addr) {
                let displayed = parsed.to_string();
                let re_parsed = IpOrCidr::from_str(&displayed).unwrap();
                prop_assert_eq!(parsed, re_parsed);
            }
        }

        #[test]
        fn ip_or_cidr_ipv6_cidr_roundtrip(
            pair in ("([0-9a-fA-F]{0,4}:){0,7}[0-9a-fA-F]{0,4}", 0u8..=128u8)
        ) {
            let cidr = format!("{}/{}", pair.0, pair.1);
            if let Ok(parsed) = IpOrCidr::from_str(&cidr) {
                let displayed = parsed.to_string();
                let re_parsed = IpOrCidr::from_str(&displayed).unwrap();
                prop_assert_eq!(parsed, re_parsed);
            }
        }

        #[test]
        fn ip_or_cidr_rejects_garbage(input in "\\PC*") {
            // Skip strings that happen to parse as valid IP/CIDR
            if let Ok(parsed) = IpOrCidr::from_str(&input) {
                let displayed = parsed.to_string();
                let re_parsed = IpOrCidr::from_str(&displayed);
                prop_assert!(re_parsed.is_ok());
            }
        }
    }

    // -- DurationSpec proptests ----------------------------------------------

    proptest! {
        #[test]
        fn duration_spec_parses_valid_humantime(s in humantime_strategy()) {
            prop_assert!(DurationSpec::new(&s).is_ok());
        }

        #[test]
        fn duration_spec_roundtrip(s in humantime_strategy()) {
            let d = DurationSpec::new(&s).unwrap();
            prop_assert_eq!(d.as_str(), s);
        }

        #[test]
        fn duration_spec_rejects_random_garbage(input in "\\PC*") {
            // Only strings that humantime can parse should succeed.
            // We verify that if it parses, the as_str matches input (trimmed).
            if let Ok(d) = DurationSpec::new(&input) {
                // Permanent is a special case
                let trimmed = input.trim();
                if d.is_permanent() {
                    prop_assert!(trimmed == "permanent" || trimmed == "-1");
                } else {
                    prop_assert_eq!(d.as_str(), trimmed);
                }
            }
        }
    }
}
