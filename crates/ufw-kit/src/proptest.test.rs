//! Property-based tests using proptest.

use proptest::prelude::*;
use crate::spec::{Action, Direction, Protocol, PortSpec, LoggingLevel, RuleSpec, ProtocolFilter};

// --- Strategies ---

fn valid_port() -> impl Strategy<Value = u16> {
    1u16..=65535
}

fn ordered_port_range() -> impl Strategy<Value = (u16, u16)> {
    (1u16..=65534u16).prop_flat_map(move |s| (Just(s), s..=65535u16))
}

fn reversed_port_range() -> impl Strategy<Value = (u16, u16)> {
    (2u16..=65535u16).prop_flat_map(move |s| (Just(s), 1..=s - 1))
}

fn action_strategy() -> impl Strategy<Value = Action> {
    proptest::sample::select(vec![Action::Allow, Action::Deny, Action::Reject, Action::Limit])
}

fn direction_strategy() -> impl Strategy<Value = Direction> {
    proptest::sample::select(vec![Direction::In, Direction::Out, Direction::Routed])
}

fn protocol_strategy() -> impl Strategy<Value = Protocol> {
    proptest::sample::select(vec![
        Protocol::Tcp, Protocol::Udp, Protocol::Ah, Protocol::Esp,
        Protocol::Gre, Protocol::Ipv6, Protocol::Igmp,
    ])
}

fn port_protocol_strategy() -> impl Strategy<Value = Protocol> {
    proptest::sample::select(vec![Protocol::Tcp, Protocol::Udp])
}

fn logging_level_strategy() -> impl Strategy<Value = LoggingLevel> {
    proptest::sample::select(vec![
        LoggingLevel::Off, LoggingLevel::On, LoggingLevel::Low,
        LoggingLevel::Medium, LoggingLevel::High, LoggingLevel::Full,
    ])
}

fn non_port_protocol_strategy() -> impl Strategy<Value = Protocol> {
    proptest::sample::select(vec![
        Protocol::Ah, Protocol::Esp, Protocol::Gre, Protocol::Ipv6, Protocol::Igmp,
    ])
}

// --- Property: Display always produces non-empty strings ---

proptest! {
    #[test]
    fn action_display_is_nonempty(action in action_strategy()) {
        let s = action.to_string();
        assert!(!s.is_empty(), "Action display should not be empty");
    }
}

proptest! {
    #[test]
    fn direction_display_is_nonempty(dir in direction_strategy()) {
        let s = dir.to_string();
        assert!(!s.is_empty(), "Direction display should not be empty");
    }
}

proptest! {
    #[test]
    fn protocol_display_is_nonempty(proto in protocol_strategy()) {
        let s = proto.to_string();
        assert!(!s.is_empty(), "Protocol display should not be empty");
    }
}

proptest! {
    #[test]
    fn logging_level_display_is_nonempty(level in logging_level_strategy()) {
        let s = level.to_string();
        assert!(!s.is_empty(), "LoggingLevel display should not be empty");
    }
}

// --- Property: Display produces known lowercase values ---

proptest! {
    #[test]
    fn action_display_is_lowercase(action in action_strategy()) {
        let s = action.to_string();
        assert_eq!(s, s.to_lowercase(), "Action display should be lowercase");
    }
}

proptest! {
    #[test]
    fn direction_display_is_lowercase(dir in direction_strategy()) {
        let s = dir.to_string();
        assert_eq!(s, s.to_lowercase(), "Direction display should be lowercase");
    }
}

proptest! {
    #[test]
    fn protocol_display_is_lowercase(proto in protocol_strategy()) {
        let s = proto.to_string();
        assert_eq!(s, s.to_lowercase(), "Protocol display should be lowercase");
    }
}

proptest! {
    #[test]
    fn logging_level_display_is_lowercase(level in logging_level_strategy()) {
        let s = level.to_string();
        assert_eq!(s, s.to_lowercase(), "LoggingLevel display should be lowercase");
    }
}

// --- Property: Display produces deterministic output (idempotent) ---

proptest! {
    #[test]
    fn action_display_is_deterministic(action in action_strategy()) {
        let first = action.to_string();
        let second = action.to_string();
        assert_eq!(first, second);
    }
}

proptest! {
    #[test]
    fn protocol_display_is_deterministic(proto in protocol_strategy()) {
        let first = proto.to_string();
        let second = proto.to_string();
        assert_eq!(first, second);
    }
}

// --- Property: PortSpec validation ---

proptest! {
    #[test]
    fn port_single_valid(port in valid_port()) {
        let spec = PortSpec::Single(port);
        assert!(spec.validate().is_ok(), "port {port} should be valid");
    }
}

proptest! {
    #[test]
    fn port_single_zero_rejected(port in 0u16..=0u16) {
        let spec = PortSpec::Single(port);
        assert!(spec.validate().is_err(), "port 0 should be rejected");
    }
}

proptest! {
    #[test]
    fn port_range_ordered(pr in ordered_port_range()) {
        let (start, end) = pr;
        let spec = PortSpec::Range { start, end };
        assert!(
            spec.validate().is_ok(),
            "port range {start}:{end} should be valid"
        );
    }
}

proptest! {
    #[test]
    fn port_range_reversed_rejected(pr in reversed_port_range()) {
        let (start, end) = pr;
        let spec = PortSpec::Range { start, end };
        assert!(
            spec.validate().is_err(),
            "reversed port range {start}:{end} should be rejected"
        );
    }
}

proptest! {
    #[test]
    fn port_range_equal_is_valid(port in valid_port()) {
        let spec = PortSpec::Range { start: port, end: port };
        assert!(
            spec.validate().is_ok(),
            "equal port range {port}:{port} should be valid"
        );
    }
}

// --- Property: Port ranges always require a protocol ---

proptest! {
    #[test]
    fn port_range_requires_protocol(pr in ordered_port_range()) {
        let (start, end) = pr;
        let spec = PortSpec::Range { start, end };
        assert!(spec.requires_protocol(), "port range {start}:{end} should require protocol");
    }
}

proptest! {
    #[test]
    fn port_single_does_not_require_protocol(port in valid_port()) {
        let spec = PortSpec::Single(port);
        assert!(!spec.requires_protocol(), "single port {port} should not require protocol");
    }
}

// --- Property: Protocol rejects_ports is consistent ---

proptest! {
    #[test]
    fn port_protocols_do_not_reject_ports(proto in port_protocol_strategy()) {
        assert!(!proto.rejects_ports(), "{proto} should not reject ports");
    }
}

proptest! {
    #[test]
    fn non_port_protocols_reject_ports(proto in non_port_protocol_strategy()) {
        assert!(proto.rejects_ports(), "{proto} should reject ports");
    }
}

// --- Property: valid rules always validate ---

proptest! {
    #[test]
    fn valid_simple_rule_validates(
        action in action_strategy(),
        proto in port_protocol_strategy(),
        port in valid_port(),
    ) {
        let rule = RuleSpec::builder(action)
            .proto(proto)
            .to_port(port)
            .build();
        assert!(rule.is_ok(), "simple rule with {action}/{proto}/{port} should be valid");
    }
}

proptest! {
    #[test]
    fn valid_simple_rule_with_direction_validates(
        action in action_strategy(),
        dir in direction_strategy(),
        proto in port_protocol_strategy(),
        port in valid_port(),
    ) {
        let rule = RuleSpec::builder(action)
            .direction(dir)
            .proto(proto)
            .to_port(port)
            .build();
        assert!(
            rule.is_ok(),
            "rule with {action}/{dir}/{proto}/{port} should be valid"
        );
    }
}

proptest! {
    #[test]
    fn default_rule_always_validates(action in action_strategy()) {
        let rule = RuleSpec { action, ..RuleSpec::default() };
        assert!(rule.validate().is_ok(), "default rule with {action} should validate");
    }
}

proptest! {
    #[test]
    fn non_port_protocol_with_port_is_rejected(
        action in action_strategy(),
        proto in non_port_protocol_strategy(),
        port in valid_port(),
    ) {
        let rule = RuleSpec {
            action,
            protocol: ProtocolFilter::Specific(proto),
            to_port: PortSpec::Single(port),
            ..RuleSpec::default()
        };
        assert!(
            rule.validate().is_err(),
            "rule with {proto} and port {port} should be rejected"
        );
    }
}

// --- Property: Display output for PortSpec matches expected format ---

proptest! {
    #[test]
    fn port_single_display_matches_number(port in valid_port()) {
        let spec = PortSpec::Single(port);
        assert_eq!(spec.to_string(), port.to_string());
    }
}

proptest! {
    #[test]
    fn port_range_display_is_colon_separated(start in 1u16..=65534u16) {
        let end = start + 1;
        let spec = PortSpec::Range { start, end };
        assert_eq!(spec.to_string(), format!("{start}:{end}"));
    }
}

// --- Property: Comments with newlines are always rejected ---

proptest! {
    #[test]
    fn comment_with_newline_rejected(prefix in ".*", suffix in ".*") {
        let comment = format!("{prefix}\n{suffix}");
        let rule = RuleSpec {
            comment: Some(comment),
            ..RuleSpec::default()
        };
        assert!(rule.validate().is_err(), "comment with newline should be rejected");
    }
}

// --- Property: PortSpec::Any always validates and never requires protocol ---

#[test]
fn port_any_validates_ok() {
    assert!(PortSpec::Any.validate().is_ok());
    assert!(!PortSpec::Any.requires_protocol());
}
