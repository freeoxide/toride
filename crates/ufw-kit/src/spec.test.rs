use super::*;

// ---------------------------------------------------------------------------
// Action display
// ---------------------------------------------------------------------------

#[test]
fn action_display_should_render_lowercase() {
    assert_eq!(Action::Allow.to_string(), "allow");
    assert_eq!(Action::Deny.to_string(), "deny");
    assert_eq!(Action::Reject.to_string(), "reject");
    assert_eq!(Action::Limit.to_string(), "limit");
}

// ---------------------------------------------------------------------------
// Direction display
// ---------------------------------------------------------------------------

#[test]
fn direction_display_should_render_lowercase() {
    assert_eq!(Direction::In.to_string(), "in");
    assert_eq!(Direction::Out.to_string(), "out");
    assert_eq!(Direction::Routed.to_string(), "routed");
}

// ---------------------------------------------------------------------------
// Policy display
// ---------------------------------------------------------------------------

#[test]
fn policy_display_should_render_lowercase() {
    assert_eq!(Policy::Allow.to_string(), "allow");
    assert_eq!(Policy::Deny.to_string(), "deny");
    assert_eq!(Policy::Reject.to_string(), "reject");
}

// ---------------------------------------------------------------------------
// Protocol
// ---------------------------------------------------------------------------

#[test]
fn protocol_display_should_render_lowercase() {
    assert_eq!(Protocol::Tcp.to_string(), "tcp");
    assert_eq!(Protocol::Udp.to_string(), "udp");
    assert_eq!(Protocol::Ah.to_string(), "ah");
    assert_eq!(Protocol::Esp.to_string(), "esp");
}

#[test]
fn protocol_rejects_ports_should_be_true_for_non_port_protocols() {
    assert!(!Protocol::Tcp.rejects_ports());
    assert!(!Protocol::Udp.rejects_ports());
    assert!(Protocol::Ah.rejects_ports());
    assert!(Protocol::Esp.rejects_ports());
    assert!(Protocol::Gre.rejects_ports());
    assert!(Protocol::Ipv6.rejects_ports());
    assert!(Protocol::Igmp.rejects_ports());
}

// ---------------------------------------------------------------------------
// ProtocolFilter
// ---------------------------------------------------------------------------

#[test]
fn protocol_filter_any_should_render_empty() {
    assert_eq!(ProtocolFilter::Any.to_string(), "");
}

#[test]
fn protocol_filter_specific_should_render_protocol() {
    assert_eq!(ProtocolFilter::Specific(Protocol::Tcp).to_string(), "tcp");
}

// ---------------------------------------------------------------------------
// LoggingLevel
// ---------------------------------------------------------------------------

#[test]
fn logging_level_display_should_render_lowercase() {
    assert_eq!(LoggingLevel::Off.to_string(), "off");
    assert_eq!(LoggingLevel::On.to_string(), "on");
    assert_eq!(LoggingLevel::Low.to_string(), "low");
    assert_eq!(LoggingLevel::Medium.to_string(), "medium");
    assert_eq!(LoggingLevel::High.to_string(), "high");
    assert_eq!(LoggingLevel::Full.to_string(), "full");
}

// ---------------------------------------------------------------------------
// RuleLogging
// ---------------------------------------------------------------------------

#[test]
fn rule_logging_display_should_render_correctly() {
    assert_eq!(RuleLogging::None.to_string(), "");
    assert_eq!(RuleLogging::Log.to_string(), "log");
    assert_eq!(RuleLogging::LogAll.to_string(), "log-all");
}

// ---------------------------------------------------------------------------
// AppDefaultPolicy
// ---------------------------------------------------------------------------

#[test]
fn app_default_policy_display_should_render_lowercase() {
    assert_eq!(AppDefaultPolicy::Skip.to_string(), "skip");
    assert_eq!(AppDefaultPolicy::Allow.to_string(), "allow");
    assert_eq!(AppDefaultPolicy::Deny.to_string(), "deny");
}

// ---------------------------------------------------------------------------
// Address
// ---------------------------------------------------------------------------

#[test]
fn address_display_should_render_correctly() {
    assert_eq!(Address::Any.to_string(), "any");
    assert_eq!(
        Address::Ip("10.0.0.1".parse().unwrap()).to_string(),
        "10.0.0.1"
    );
    assert_eq!(
        Address::Net("10.0.0.0/8".parse().unwrap()).to_string(),
        "10.0.0.0/8"
    );
}

// ---------------------------------------------------------------------------
// PortSpec
// ---------------------------------------------------------------------------

#[test]
fn port_spec_single_should_render_number() {
    assert_eq!(PortSpec::Single(443).to_string(), "443");
}

#[test]
fn port_spec_range_should_render_colon_separated() {
    assert_eq!(
        PortSpec::Range {
            start: 8000,
            end: 9000
        }
        .to_string(),
        "8000:9000"
    );
}

#[test]
fn port_spec_list_should_render_comma_separated() {
    let ports = PortSpec::List(vec![PortSpec::Single(80), PortSpec::Single(443)]);
    assert_eq!(ports.to_string(), "80,443");
}

#[test]
fn port_spec_service_name_should_render_name() {
    assert_eq!(PortSpec::ServiceName("ssh".into()).to_string(), "ssh");
}

#[test]
fn port_spec_validate_should_reject_zero_port() {
    assert!(PortSpec::Single(0).validate().is_err());
}

#[test]
fn port_spec_validate_should_accept_valid_port() {
    assert!(PortSpec::Single(22).validate().is_ok());
    assert!(PortSpec::Single(65535).validate().is_ok());
}

#[test]
fn port_spec_validate_should_reject_reversed_range() {
    assert!(
        PortSpec::Range {
            start: 9000,
            end: 8000
        }
        .validate()
        .is_err()
    );
}

#[test]
fn port_spec_validate_should_accept_valid_range() {
    assert!(
        PortSpec::Range {
            start: 8000,
            end: 9000
        }
        .validate()
        .is_ok()
    );
}

#[test]
fn port_spec_validate_should_reject_zero_in_range() {
    assert!(PortSpec::Range { start: 0, end: 100 }.validate().is_err());
}

#[test]
fn port_spec_requires_protocol_should_be_true_for_ranges() {
    assert!(
        PortSpec::Range {
            start: 8000,
            end: 9000
        }
        .requires_protocol()
    );
    assert!(PortSpec::List(vec![PortSpec::Single(80), PortSpec::Single(443)]).requires_protocol());
    assert!(!PortSpec::Single(80).requires_protocol());
    assert!(!PortSpec::Any.requires_protocol());
}

// ---------------------------------------------------------------------------
// Edge-case tests
// ---------------------------------------------------------------------------

#[test]
fn port_spec_validate_should_reject_zero_in_list() {
    let ports = PortSpec::List(vec![PortSpec::Single(80), PortSpec::Single(0)]);
    assert!(ports.validate().is_err());
}

#[test]
fn port_spec_any_should_validate_ok() {
    assert!(PortSpec::Any.validate().is_ok());
}

#[test]
fn port_spec_service_name_should_validate_ok() {
    assert!(PortSpec::ServiceName("http".into()).validate().is_ok());
}

#[test]
fn port_spec_validate_should_reject_reversed_range_in_list() {
    let ports = PortSpec::List(vec![PortSpec::Range {
        start: 9000,
        end: 8000,
    }]);
    assert!(ports.validate().is_err());
}

// ---------------------------------------------------------------------------
// Weird edge-case tests
// ---------------------------------------------------------------------------

#[test]
fn port_spec_display_empty_list_should_render_empty() {
    let ports = PortSpec::List(vec![]);
    assert_eq!(ports.to_string(), "");
}

#[test]
fn port_spec_single_max_port_should_render() {
    assert_eq!(PortSpec::Single(65535).to_string(), "65535");
}

#[test]
fn port_spec_single_min_port_should_render() {
    assert_eq!(PortSpec::Single(1).to_string(), "1");
}

#[test]
fn address_ipv6_should_render_correctly() {
    assert_eq!(Address::Ip("::1".parse().unwrap()).to_string(), "::1");
}

#[test]
fn address_ipv6_net_should_render_correctly() {
    assert_eq!(
        Address::Net("fe80::/10".parse().unwrap()).to_string(),
        "fe80::/10"
    );
}

// ---------------------------------------------------------------------------
// RuleSpec validation
// ---------------------------------------------------------------------------

#[test]
fn rule_spec_validate_should_pass_for_default() {
    let spec = RuleSpec::default();
    assert!(spec.validate().is_ok());
}

#[test]
fn rule_spec_validate_should_reject_comment_with_newline() {
    let spec = RuleSpec {
        comment: Some("bad\ncomment".into()),
        ..Default::default()
    };
    assert!(spec.validate().is_err());
}

#[test]
fn rule_spec_validate_should_reject_interface_with_whitespace() {
    let spec = RuleSpec {
        interface: Some("eth 0".into()),
        ..Default::default()
    };
    assert!(spec.validate().is_err());
}

#[test]
fn rule_spec_validate_should_reject_interface_with_shell_metachar() {
    let spec = RuleSpec {
        interface: Some("eth0;rm -rf /".into()),
        ..Default::default()
    };
    assert!(spec.validate().is_err());
}

#[test]
fn rule_spec_validate_should_reject_app_profile_with_protocol() {
    let spec = RuleSpec {
        app_profile: Some("MyApp".into()),
        protocol: ProtocolFilter::Specific(Protocol::Tcp),
        ..Default::default()
    };
    assert!(spec.validate().is_err());
}

#[test]
fn rule_spec_validate_should_reject_app_profile_with_port() {
    let spec = RuleSpec {
        app_profile: Some("MyApp".into()),
        to_port: PortSpec::Single(443),
        ..Default::default()
    };
    assert!(spec.validate().is_err());
}

#[test]
fn rule_spec_validate_should_reject_path_traversal_in_app_name() {
    let spec = RuleSpec {
        app_profile: Some("../etc/passwd".into()),
        ..Default::default()
    };
    assert!(spec.validate().is_err());
}

#[test]
fn rule_spec_validate_should_reject_newline_in_app_name() {
    let spec = RuleSpec {
        app_profile: Some("App\nEvil".into()),
        ..Default::default()
    };
    assert!(spec.validate().is_err());
}

#[test]
fn rule_spec_validate_should_reject_esp_with_ports() {
    let spec = RuleSpec {
        protocol: ProtocolFilter::Specific(Protocol::Esp),
        to_port: PortSpec::Single(443),
        ..Default::default()
    };
    assert!(spec.validate().is_err());
}

// ---------------------------------------------------------------------------
// Protocol required for port ranges / port lists
// ---------------------------------------------------------------------------

#[test]
fn rule_spec_validate_should_reject_port_range_without_protocol() {
    let spec = RuleSpec {
        to_port: PortSpec::Range {
            start: 8000,
            end: 9000,
        },
        ..Default::default()
    };
    assert!(spec.validate().is_err());
}

#[test]
fn rule_spec_validate_should_accept_port_range_with_protocol() {
    let spec = RuleSpec {
        protocol: ProtocolFilter::Specific(Protocol::Tcp),
        to_port: PortSpec::Range {
            start: 8000,
            end: 9000,
        },
        ..Default::default()
    };
    assert!(spec.validate().is_ok());
}

#[test]
fn rule_spec_validate_should_reject_port_list_without_protocol() {
    let spec = RuleSpec {
        to_port: PortSpec::List(vec![PortSpec::Single(80), PortSpec::Single(443)]),
        ..Default::default()
    };
    assert!(spec.validate().is_err());
}

#[test]
fn rule_spec_validate_should_accept_port_any_without_protocol() {
    let spec = RuleSpec {
        to_port: PortSpec::Any,
        ..Default::default()
    };
    assert!(spec.validate().is_ok());
}

#[test]
fn rule_spec_validate_should_reject_from_port_range_without_protocol() {
    let spec = RuleSpec {
        from_port: PortSpec::Range {
            start: 8000,
            end: 9000,
        },
        ..Default::default()
    };
    assert!(spec.validate().is_err());
}

// ---------------------------------------------------------------------------
// Production-grade weird edge cases
// ---------------------------------------------------------------------------

#[test]
fn rule_spec_validate_should_accept_very_long_comment() {
    // Use words with spaces to avoid triggering hex/base64 secret detection.
    let long_comment = "managed by ops team - standard allow rule. ".repeat(25);
    let spec = RuleSpec {
        comment: Some(long_comment),
        ..Default::default()
    };
    assert!(spec.validate().is_ok());
}

#[test]
fn rule_spec_validate_should_accept_max_length_interface() {
    let spec = RuleSpec {
        interface: Some("a".repeat(15)),
        ..Default::default()
    };
    assert!(spec.validate().is_ok());
}

#[test]
fn rule_spec_validate_should_reject_too_long_interface() {
    let spec = RuleSpec {
        interface: Some("a".repeat(16)),
        ..Default::default()
    };
    assert!(spec.validate().is_err());
}

#[test]
fn rule_spec_builder_should_build_valid_spec() {
    let spec = RuleSpec::builder(Action::Allow)
        .direction(Direction::In)
        .proto(Protocol::Tcp)
        .to_port(443)
        .comment("managed:https")
        .build()
        .unwrap();

    assert_eq!(spec.action, Action::Allow);
    assert_eq!(spec.direction, Some(Direction::In));
    assert_eq!(spec.protocol, ProtocolFilter::Specific(Protocol::Tcp));
    assert_eq!(spec.to_port, PortSpec::Single(443));
    assert_eq!(spec.comment, Some("managed:https".into()));
}

#[test]
fn rule_spec_builder_should_build_with_app_profile() {
    let spec = RuleSpec::builder(Action::Allow)
        .app("MyApp")
        .build()
        .unwrap();

    assert_eq!(spec.app_profile, Some("MyApp".into()));
}

// ---------------------------------------------------------------------------
// PortSpec conversions
// ---------------------------------------------------------------------------

#[test]
fn port_spec_from_u16_should_create_single() {
    let port: PortSpec = 443u16.into();
    assert_eq!(port, PortSpec::Single(443));
}

#[test]
fn port_spec_from_tuple_should_create_range() {
    let port: PortSpec = (8000u16, 9000u16).into();
    assert_eq!(
        port,
        PortSpec::Range {
            start: 8000,
            end: 9000
        }
    );
}

#[test]
fn port_spec_from_string_should_create_service_name() {
    let port: PortSpec = "ssh".into();
    assert_eq!(port, PortSpec::ServiceName("ssh".into()));
}

// ---------------------------------------------------------------------------
// AppProfileSpec
// ---------------------------------------------------------------------------

#[test]
fn app_profile_spec_render_should_produce_ini() {
    let spec = AppProfileSpec {
        name: "MyApp".into(),
        title: "My Application".into(),
        description: "A test app".into(),
        ports: vec![
            AppPort {
                port: "80".into(),
                protocol: "tcp".into(),
            },
            AppPort {
                port: "443".into(),
                protocol: "tcp".into(),
            },
        ],
    };

    let rendered = spec.render();
    assert!(rendered.contains("[MyApp]"));
    assert!(rendered.contains("title=My Application"));
    assert!(rendered.contains("description=A test app"));
    assert!(rendered.contains("ports=80/tcp|443/tcp"));
    assert!(rendered.contains("Managed by ufw-kit"));
}

#[test]
fn app_profile_spec_validate_should_reject_empty_name() {
    let spec = AppProfileSpec {
        name: String::new(),
        title: "Test".into(),
        description: "Test".into(),
        ports: vec![AppPort {
            port: "80".into(),
            protocol: "tcp".into(),
        }],
    };
    assert!(spec.validate().is_err());
}

#[test]
fn app_profile_spec_validate_should_reject_empty_ports() {
    let spec = AppProfileSpec {
        name: "Test".into(),
        title: "Test".into(),
        description: "Test".into(),
        ports: vec![],
    };
    assert!(spec.validate().is_err());
}

#[test]
fn app_profile_spec_validate_should_reject_path_traversal() {
    let spec = AppProfileSpec {
        name: "../evil".into(),
        title: "Test".into(),
        description: "Test".into(),
        ports: vec![AppPort {
            port: "80".into(),
            protocol: "tcp".into(),
        }],
    };
    assert!(spec.validate().is_err());
}

// ---------------------------------------------------------------------------
// CommandSpec
// ---------------------------------------------------------------------------

#[test]
fn command_spec_ufw_should_create_correctly() {
    let spec = CommandSpec::ufw(vec!["status".into(), "verbose".into()]);
    assert_eq!(spec.program, "ufw");
    assert_eq!(spec.args, vec!["status", "verbose"]);
    assert!(!spec.requires_root);
    assert!(spec.force_c_locale);
    assert!(spec.timeout.is_some());
}

#[test]
fn command_spec_ufw_root_should_require_root() {
    let spec = CommandSpec::ufw_root(vec!["enable".into()]);
    assert!(spec.requires_root);
}

// ---------------------------------------------------------------------------
// UfwReport
// ---------------------------------------------------------------------------

#[test]
fn ufw_report_display_should_render_correctly() {
    assert_eq!(UfwReport::Raw.to_string(), "raw");
    assert_eq!(UfwReport::Listening.to_string(), "listening");
    assert_eq!(UfwReport::Added.to_string(), "added");
    assert_eq!(UfwReport::UserRules.to_string(), "user-rules");
    assert_eq!(UfwReport::BeforeRules.to_string(), "before-rules");
    assert_eq!(UfwReport::AfterRules.to_string(), "after-rules");
}

// ---------------------------------------------------------------------------
// Severity ordering
// ---------------------------------------------------------------------------

#[test]
fn severity_should_be_orderable() {
    assert!(Severity::Ok < Severity::Info);
    assert!(Severity::Info < Severity::Warning);
    assert!(Severity::Warning < Severity::Important);
    assert!(Severity::Important < Severity::Critical);
}

// ---------------------------------------------------------------------------
// Default options
// ---------------------------------------------------------------------------

#[test]
fn enable_options_default_should_require_ssh_check() {
    let opts = EnableOptions::default();
    assert!(opts.require_ssh_allow_rule);
    assert_eq!(opts.ssh_ports, vec![22]);
    assert!(!opts.allow_force);
}

#[test]
fn disable_options_default_should_not_require_confirmation() {
    let opts = DisableOptions::default();
    assert!(!opts.require_explicit_confirmation);
}

#[test]
fn reset_options_default_should_require_force_and_backup() {
    let opts = ResetOptions::default();
    assert!(!opts.force);
    assert!(opts.backup_first);
}

#[test]
fn delete_options_default_should_disallow_numbered() {
    let opts = DeleteOptions::default();
    assert!(!opts.allow_numbered_delete);
}
