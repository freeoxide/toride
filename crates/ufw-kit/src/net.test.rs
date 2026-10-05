use super::*;
use crate::spec::*;

// ---------------------------------------------------------------------------
// Private IP detection
// ---------------------------------------------------------------------------

#[test]
fn is_private_ip_should_detect_10_network() {
    assert!(is_private_ip("10.0.0.1".parse().unwrap()));
}

#[test]
fn is_private_ip_should_detect_172_16_network() {
    assert!(is_private_ip("172.16.0.1".parse().unwrap()));
}

#[test]
fn is_private_ip_should_detect_192_168_network() {
    assert!(is_private_ip("192.168.1.1".parse().unwrap()));
}

#[test]
fn is_private_ip_should_detect_loopback() {
    assert!(is_private_ip("127.0.0.1".parse().unwrap()));
    assert!(is_private_ip("::1".parse().unwrap()));
}

#[test]
fn is_private_ip_should_detect_link_local() {
    assert!(is_private_ip("169.254.1.1".parse().unwrap()));
    assert!(is_private_ip("fe80::1".parse().unwrap()));
}

#[test]
fn is_private_ip_should_detect_unique_local_v6() {
    assert!(is_private_ip("fc00::1".parse().unwrap()));
}

#[test]
fn is_private_ip_should_reject_public_ip() {
    assert!(!is_private_ip("8.8.8.8".parse().unwrap()));
    assert!(!is_private_ip("1.1.1.1".parse().unwrap()));
}

// ---------------------------------------------------------------------------
// Link-local detection
// ---------------------------------------------------------------------------

#[test]
fn is_link_local_v4_should_detect_169_254() {
    assert!(is_link_local_v4("169.254.0.1".parse().unwrap()));
    assert!(!is_link_local_v4("10.0.0.1".parse().unwrap()));
}

#[test]
fn is_link_local_v6_should_detect_fe80() {
    assert!(is_link_local_v6("fe80::1".parse().unwrap()));
    assert!(!is_link_local_v6("fc00::1".parse().unwrap()));
}

// ---------------------------------------------------------------------------
// Unique-local detection
// ---------------------------------------------------------------------------

#[test]
fn is_unique_local_v6_should_detect_fc00() {
    assert!(is_unique_local_v6("fc00::1".parse().unwrap()));
    assert!(is_unique_local_v6("fd00::1".parse().unwrap()));
    assert!(!is_unique_local_v6("fe80::1".parse().unwrap()));
}

// ---------------------------------------------------------------------------
// Public IP detection
// ---------------------------------------------------------------------------

#[test]
fn is_public_ip_should_detect_public() {
    assert!(is_public_ip("8.8.8.8".parse().unwrap()));
    assert!(is_public_ip("1.1.1.1".parse().unwrap()));
}

#[test]
fn is_public_ip_should_reject_private() {
    assert!(!is_public_ip("10.0.0.1".parse().unwrap()));
    assert!(!is_public_ip("192.168.1.1".parse().unwrap()));
}

#[test]
fn is_public_ip_should_reject_loopback() {
    assert!(!is_public_ip("127.0.0.1".parse().unwrap()));
}

#[test]
fn is_public_ip_should_reject_multicast() {
    assert!(!is_public_ip("224.0.0.1".parse().unwrap()));
}

#[test]
fn is_public_ip_should_reject_unspecified() {
    assert!(!is_public_ip("0.0.0.0".parse().unwrap()));
}

// ---------------------------------------------------------------------------
// IPv4/IPv6 detection on Address
// ---------------------------------------------------------------------------

#[test]
fn is_ipv6_should_detect_ipv6_address() {
    assert!(is_ipv6(&Address::Ip("::1".parse().unwrap())));
    assert!(is_ipv6(&Address::Net("fe80::/10".parse().unwrap())));
}

#[test]
fn is_ipv6_should_reject_ipv4() {
    assert!(!is_ipv6(&Address::Ip("10.0.0.1".parse().unwrap())));
    assert!(!is_ipv6(&Address::Any));
}

#[test]
fn is_ipv4_should_detect_ipv4_address() {
    assert!(is_ipv4(&Address::Ip("10.0.0.1".parse().unwrap())));
    assert!(is_ipv4(&Address::Net("10.0.0.0/8".parse().unwrap())));
}

#[test]
fn is_ipv4_should_reject_ipv6() {
    assert!(!is_ipv4(&Address::Ip("::1".parse().unwrap())));
    assert!(!is_ipv4(&Address::Any));
}

// ---------------------------------------------------------------------------
// Rule safety helpers
// ---------------------------------------------------------------------------

#[test]
fn rule_exposes_port_should_detect_port() {
    let spec = RuleSpec {
        from_addr: Address::Any,
        to_port: PortSpec::Single(22),
        ..Default::default()
    };
    assert!(rule_exposes_port(&spec, 22));
    assert!(!rule_exposes_port(&spec, 443));
}

#[test]
fn rule_exposes_port_should_detect_range() {
    let spec = RuleSpec {
        from_addr: Address::Any,
        to_port: PortSpec::Range {
            start: 8000,
            end: 9000,
        },
        ..Default::default()
    };
    assert!(rule_exposes_port(&spec, 8500));
    assert!(!rule_exposes_port(&spec, 7999));
}

#[test]
fn rule_exposes_port_should_detect_list() {
    let spec = RuleSpec {
        from_addr: Address::Any,
        to_port: PortSpec::List(vec![PortSpec::Single(80), PortSpec::Single(443)]),
        ..Default::default()
    };
    assert!(rule_exposes_port(&spec, 80));
    assert!(rule_exposes_port(&spec, 443));
    assert!(!rule_exposes_port(&spec, 22));
}

#[test]
fn rule_exposes_port_should_not_expose_from_specific_addr() {
    let spec = RuleSpec {
        from_addr: Address::Ip("10.0.0.1".parse().unwrap()),
        to_port: PortSpec::Single(22),
        ..Default::default()
    };
    assert!(!rule_exposes_port(&spec, 22));
}

#[test]
fn rule_allows_from_anywhere_should_detect_any() {
    let spec = RuleSpec {
        from_addr: Address::Any,
        ..Default::default()
    };
    assert!(rule_allows_from_anywhere(&spec));
}

#[test]
fn rule_allows_from_anywhere_should_reject_specific() {
    let spec = RuleSpec {
        from_addr: Address::Ip("10.0.0.1".parse().unwrap()),
        ..Default::default()
    };
    assert!(!rule_allows_from_anywhere(&spec));
}

// ---------------------------------------------------------------------------
// IPv4/IPv6 mismatch
// ---------------------------------------------------------------------------

#[test]
fn is_ipv4_ipv6_mismatch_should_detect_mismatch() {
    let v4 = Address::Ip("10.0.0.1".parse().unwrap());
    let v6 = Address::Ip("::1".parse().unwrap());
    assert!(is_ipv4_ipv6_mismatch(&v4, &v6));
    assert!(is_ipv4_ipv6_mismatch(&v6, &v4));
}

#[test]
fn is_ipv4_ipv6_mismatch_should_not_mismatch_same_family() {
    let v4a = Address::Ip("10.0.0.1".parse().unwrap());
    let v4b = Address::Ip("10.0.0.2".parse().unwrap());
    assert!(!is_ipv4_ipv6_mismatch(&v4a, &v4b));
}

// ---------------------------------------------------------------------------
// Dangerous ports
// ---------------------------------------------------------------------------

#[test]
fn check_dangerous_ports_should_find_ssh() {
    let spec = RuleSpec {
        from_addr: Address::Any,
        to_port: PortSpec::Single(22),
        ..Default::default()
    };
    let dangerous = check_dangerous_ports(&spec);
    assert!(dangerous.iter().any(|(port, _)| *port == 22));
}

#[test]
fn check_dangerous_ports_should_not_find_safe_port() {
    let spec = RuleSpec {
        from_addr: Address::Any,
        to_port: PortSpec::Single(8443),
        ..Default::default()
    };
    let dangerous = check_dangerous_ports(&spec);
    assert_eq!(dangerous, [] as [(u16, &str); 0]);
}

// ---------------------------------------------------------------------------
// Parsing helpers
// ---------------------------------------------------------------------------

#[test]
fn parse_ip_should_parse_valid_ip() {
    assert!(parse_ip("10.0.0.1").is_ok());
    assert!(parse_ip("::1").is_ok());
}

#[test]
fn parse_ip_should_reject_invalid() {
    assert!(parse_ip("not-an-ip").is_err());
}

#[test]
fn parse_cidr_should_parse_valid_cidr() {
    assert!(parse_cidr("10.0.0.0/8").is_ok());
    assert!(parse_cidr("fe80::/10").is_ok());
}

#[test]
fn parse_cidr_should_reject_invalid() {
    assert!(parse_cidr("not-a-cidr").is_err());
}

// ---------------------------------------------------------------------------
// Edge-case tests
// ---------------------------------------------------------------------------

#[test]
fn rule_exposes_port_should_handle_any_port() {
    let spec = RuleSpec {
        from_addr: Address::Any,
        to_port: PortSpec::Any,
        ..Default::default()
    };
    assert!(!rule_exposes_port(&spec, 22));
}

#[test]
fn rule_exposes_port_should_handle_service_name() {
    let spec = RuleSpec {
        from_addr: Address::Any,
        to_port: PortSpec::ServiceName("ssh".into()),
        ..Default::default()
    };
    assert!(!rule_exposes_port(&spec, 22));
}

// ---------------------------------------------------------------------------
// Weird edge-case tests
// ---------------------------------------------------------------------------

#[test]
fn is_private_ip_should_handle_broadcast() {
    assert!(!is_private_ip("255.255.255.255".parse().unwrap()));
}

#[test]
fn is_public_ip_should_reject_multicast_v6() {
    assert!(!is_public_ip("ff02::1".parse().unwrap()));
}

#[test]
fn rule_exposes_port_should_handle_nested_list() {
    let spec = RuleSpec {
        from_addr: Address::Any,
        to_port: PortSpec::List(vec![
            PortSpec::Range {
                start: 8000,
                end: 8100,
            },
            PortSpec::Single(9090),
        ]),
        ..Default::default()
    };
    assert!(rule_exposes_port(&spec, 8050));
    assert!(rule_exposes_port(&spec, 9090));
    assert!(!rule_exposes_port(&spec, 7999));
}

// ---------------------------------------------------------------------------
// Production-grade weird edge cases
// ---------------------------------------------------------------------------

#[test]
fn is_private_ip_should_handle_0_0_0_0() {
    assert!(!is_private_ip("0.0.0.0".parse().unwrap()));
}

#[test]
fn is_link_local_v6_should_handle_various_fe80() {
    assert!(is_link_local_v6("fe80::abcd:1234".parse().unwrap()));
    assert!(is_link_local_v6("fe80::1".parse().unwrap()));
    assert!(!is_link_local_v6("fe00::1".parse().unwrap()));
}

#[test]
fn check_dangerous_ports_should_find_multiple() {
    let spec = RuleSpec {
        from_addr: Address::Any,
        to_port: PortSpec::List(vec![
            PortSpec::Single(22),
            PortSpec::Single(5432),
            PortSpec::Single(6379),
        ]),
        ..Default::default()
    };
    let dangerous = check_dangerous_ports(&spec);
    assert_eq!(dangerous.len(), 3);
}
