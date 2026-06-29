use super::*;
use crate::spec::*;

// ---------------------------------------------------------------------------
// Basic rule rendering
// ---------------------------------------------------------------------------

#[test]
fn render_rule_args_should_produce_allow_22_tcp() {
    let spec = RuleSpec::builder(Action::Allow)
        .to_port(22)
        .proto(Protocol::Tcp)
        .build_unchecked();

    let args = render_rule_args(&spec);
    assert_eq!(
        args,
        vec!["allow", "proto", "tcp", "to", "any", "port", "22"]
    );
}

#[test]
fn render_rule_args_should_produce_deny_from_address() {
    let spec = RuleSpec::builder(Action::Deny)
        .from(Address::Ip("203.0.113.10".parse().unwrap()))
        .build_unchecked();

    let args = render_rule_args(&spec);
    assert_eq!(args, vec!["deny", "from", "203.0.113.10"]);
}

#[test]
fn render_rule_args_should_produce_allow_in_on_eth0() {
    let spec = RuleSpec::builder(Action::Allow)
        .direction(Direction::In)
        .on_interface("eth0")
        .proto(Protocol::Tcp)
        .to_port(443)
        .build_unchecked();

    let args = render_rule_args(&spec);
    assert_eq!(
        args,
        vec![
            "allow", "in", "on", "eth0", "proto", "tcp", "to", "any", "port", "443"
        ]
    );
}

#[test]
fn render_rule_args_should_produce_full_syntax() {
    let spec = RuleSpec::builder(Action::Allow)
        .direction(Direction::In)
        .on_interface("eth0")
        .proto(Protocol::Tcp)
        .from(Address::Net("10.0.0.0/8".parse().unwrap()))
        .to(Address::Any)
        .to_port(443)
        .comment("managed:web")
        .build_unchecked();

    let args = render_rule_args(&spec);
    assert_eq!(
        args,
        vec![
            "allow",
            "in",
            "on",
            "eth0",
            "proto",
            "tcp",
            "from",
            "10.0.0.0/8",
            "to",
            "any",
            "port",
            "443",
            "comment",
            "managed:web"
        ]
    );
}

// ---------------------------------------------------------------------------
// Logging rendering
// ---------------------------------------------------------------------------

#[test]
fn render_rule_args_should_include_log() {
    let spec = RuleSpec::builder(Action::Allow)
        .logging(RuleLogging::Log)
        .to_port(443)
        .build_unchecked();

    let args = render_rule_args(&spec);
    assert!(args.contains(&"log".to_string()));
}

#[test]
fn render_rule_args_should_include_log_all() {
    let spec = RuleSpec::builder(Action::Deny)
        .logging(RuleLogging::LogAll)
        .build_unchecked();

    let args = render_rule_args(&spec);
    assert!(args.contains(&"log-all".to_string()));
}

// ---------------------------------------------------------------------------
// Position rendering
// ---------------------------------------------------------------------------

#[test]
fn render_rule_args_should_include_prepend() {
    let spec = RuleSpec::builder(Action::Allow)
        .position(RulePosition::Prepend)
        .from(Address::Ip("10.0.0.1".parse().unwrap()))
        .build_unchecked();

    let args = render_rule_args(&spec);
    assert_eq!(args[0], "prepend");
}

#[test]
fn render_rule_args_should_include_insert() {
    let spec = RuleSpec::builder(Action::Deny)
        .position(RulePosition::Insert(1))
        .from(Address::Ip("203.0.113.10".parse().unwrap()))
        .build_unchecked();

    let args = render_rule_args(&spec);
    assert_eq!(args[0], "insert");
    assert_eq!(args[1], "1");
}

// ---------------------------------------------------------------------------
// Delete rendering
// ---------------------------------------------------------------------------

#[test]
fn render_delete_args_should_prefix_with_delete() {
    let spec = RuleSpec::builder(Action::Allow)
        .to_port(22)
        .proto(Protocol::Tcp)
        .build_unchecked();

    let args = render_delete_args(&spec);
    assert_eq!(args[0], "delete");
}

#[test]
fn render_delete_number_args_should_produce_delete_number() {
    let opts = DeleteOptions {
        allow_numbered_delete: true,
    };
    let args = render_delete_number_args(3, &opts);
    assert_eq!(args, vec!["delete", "3"]);
}

// ---------------------------------------------------------------------------
// App profile rendering
// ---------------------------------------------------------------------------

#[test]
fn render_rule_args_should_use_app_keyword() {
    let spec = RuleSpec::builder(Action::Allow)
        .app("MyApp")
        .build_unchecked();

    let args = render_rule_args(&spec);
    assert!(args.contains(&"app".to_string()));
    assert!(args.contains(&"MyApp".to_string()));
}

// ---------------------------------------------------------------------------
// Route rule rendering
// ---------------------------------------------------------------------------

#[test]
fn render_route_rule_args_should_produce_basic_route() {
    let spec = RouteRuleSpec::builder(Action::Allow)
        .in_interface("eth1")
        .out_interface("eth2")
        .build()
        .unwrap();

    let args = render_route_rule_args(&spec);
    assert_eq!(
        args,
        vec!["route", "allow", "in", "on", "eth1", "out", "on", "eth2"]
    );
}

#[test]
fn render_route_rule_args_should_include_proto_and_port() {
    let spec = RouteRuleSpec::builder(Action::Allow)
        .in_interface("eth0")
        .out_interface("eth1")
        .to(Address::Ip("12.34.45.67".parse().unwrap()))
        .to_port(80)
        .proto(Protocol::Tcp)
        .build()
        .unwrap();

    let args = render_route_rule_args(&spec);
    assert_eq!(
        args,
        vec![
            "route",
            "allow",
            "in",
            "on",
            "eth0",
            "out",
            "on",
            "eth1",
            "proto",
            "tcp",
            "to",
            "12.34.45.67",
            "port",
            "80"
        ]
    );
}

#[test]
fn render_route_rule_args_should_include_comment() {
    let spec = RouteRuleSpec::builder(Action::Allow)
        .in_interface("wg0")
        .out_interface("eth0")
        .comment("managed:wg-nat")
        .build()
        .unwrap();

    let args = render_route_rule_args(&spec);
    assert!(args.contains(&"comment".to_string()));
    assert!(args.contains(&"managed:wg-nat".to_string()));
}

#[test]
fn render_route_rule_args_delete_should_prefix_delete() {
    let spec = RouteRuleSpec::builder(Action::Allow)
        .in_interface("eth0")
        .out_interface("eth1")
        .delete()
        .build()
        .unwrap();

    let args = render_route_rule_args(&spec);
    assert_eq!(args[0], "delete");
}

// ---------------------------------------------------------------------------
// Default policy rendering
// ---------------------------------------------------------------------------

#[test]
fn render_default_policy_args_should_produce_correct_args() {
    let args = render_default_policy_args(Direction::In, Policy::Deny);
    assert_eq!(args, vec!["default", "in", "deny"]);
}

#[test]
fn render_default_policy_args_should_handle_outgoing_allow() {
    let args = render_default_policy_args(Direction::Out, Policy::Allow);
    assert_eq!(args, vec!["default", "out", "allow"]);
}

// ---------------------------------------------------------------------------
// Logging args rendering
// ---------------------------------------------------------------------------

#[test]
fn render_logging_args_should_produce_correct_args() {
    let args = render_logging_args(LoggingLevel::Low);
    assert_eq!(args, vec!["logging", "low"]);
}

#[test]
fn render_logging_args_should_handle_off() {
    let args = render_logging_args(LoggingLevel::Off);
    assert_eq!(args, vec!["logging", "off"]);
}

// ---------------------------------------------------------------------------
// App default args rendering
// ---------------------------------------------------------------------------

#[test]
fn render_app_default_args_should_produce_correct_args() {
    let args = render_app_default_args(AppDefaultPolicy::Skip);
    assert_eq!(args, vec!["app", "default", "skip"]);
}

// ---------------------------------------------------------------------------
// Simple rule rendering
// ---------------------------------------------------------------------------

#[test]
fn render_simple_rule_should_produce_two_args() {
    let args = render_simple_rule(Action::Allow, "22/tcp");
    assert_eq!(args, vec!["allow", "22/tcp"]);
}

#[test]
fn render_simple_rule_should_handle_limit() {
    let args = render_simple_rule(Action::Limit, "ssh/tcp");
    assert_eq!(args, vec!["limit", "ssh/tcp"]);
}

// ---------------------------------------------------------------------------
// Edge-case tests
// ---------------------------------------------------------------------------

#[test]
fn render_rule_args_should_omit_from_when_any() {
    let spec = RuleSpec::builder(Action::Allow)
        .from(Address::Any)
        .to_port(443)
        .build_unchecked();

    let args = render_rule_args(&spec);
    // "from any" should not appear when source is default
    assert!(!args.contains(&"from".to_string()));
}

#[test]
fn render_rule_args_should_include_from_when_specific() {
    let spec = RuleSpec::builder(Action::Allow)
        .from(Address::Ip("10.0.0.1".parse().unwrap()))
        .to_port(443)
        .build_unchecked();

    let args = render_rule_args(&spec);
    assert!(args.contains(&"from".to_string()));
    assert!(args.contains(&"10.0.0.1".to_string()));
}

#[test]
fn render_rule_args_should_omit_direction_when_none() {
    let spec = RuleSpec::builder(Action::Allow)
        .to_port(443)
        .build_unchecked();

    let args = render_rule_args(&spec);
    assert!(!args.contains(&"in".to_string()));
    assert!(!args.contains(&"out".to_string()));
}

// ---------------------------------------------------------------------------
// Weird edge-case tests
// ---------------------------------------------------------------------------

#[test]
fn render_rule_args_limit_with_direction_and_interface() {
    let spec = RuleSpec::builder(Action::Limit)
        .direction(Direction::In)
        .on_interface("eth0")
        .proto(Protocol::Tcp)
        .to_port(22)
        .comment("ufw-kit:ssh")
        .build_unchecked();

    let args = render_rule_args(&spec);
    assert_eq!(
        args,
        vec![
            "limit",
            "in",
            "on",
            "eth0",
            "proto",
            "tcp",
            "to",
            "any",
            "port",
            "22",
            "comment",
            "ufw-kit:ssh"
        ]
    );
}

// ---------------------------------------------------------------------------
// Production-grade weird edge cases
// ---------------------------------------------------------------------------

#[test]
fn render_route_rule_args_with_all_fields() {
    let spec = RouteRuleSpec::builder(Action::Allow)
        .in_interface("wg0")
        .out_interface("eth0")
        .proto(Protocol::Udp)
        .from(Address::Net("10.0.0.0/24".parse().unwrap()))
        .to(Address::Ip("8.8.8.8".parse().unwrap()))
        .to_port(53)
        .comment("dns-forward")
        .build()
        .unwrap();

    let args = render_route_rule_args(&spec);
    assert!(args.contains(&"route".to_string()));
    assert!(args.contains(&"in".to_string()));
    assert!(args.contains(&"wg0".to_string()));
    assert!(args.contains(&"out".to_string()));
    assert!(args.contains(&"eth0".to_string()));
    assert!(args.contains(&"proto".to_string()));
    assert!(args.contains(&"udp".to_string()));
    assert!(args.contains(&"from".to_string()));
    assert!(args.contains(&"10.0.0.0/24".to_string()));
    assert!(args.contains(&"to".to_string()));
    assert!(args.contains(&"8.8.8.8".to_string()));
    assert!(args.contains(&"port".to_string()));
    assert!(args.contains(&"53".to_string()));
    assert!(args.contains(&"comment".to_string()));
    assert!(args.contains(&"dns-forward".to_string()));
}
