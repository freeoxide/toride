use super::*;

// ---------------------------------------------------------------------------
// parse_status
// ---------------------------------------------------------------------------

#[test]
fn parse_status_should_detect_active() {
    let output = "Status: active\n";
    let status = parse_status(output).unwrap();
    assert!(status.active);
}

#[test]
fn parse_status_should_detect_inactive() {
    let output = "Status: inactive\n";
    let status = parse_status(output).unwrap();
    assert!(!status.active);
}

#[test]
fn parse_status_should_parse_rules() {
    let output = "\
Status: active

To                         Action      From
--                         ------      ----
22/tcp                     ALLOW       Anywhere
443/tcp                    ALLOW       Anywhere
";
    let status = parse_status(output).unwrap();
    assert!(status.active);
    assert_eq!(status.rules.len(), 2);
}

// ---------------------------------------------------------------------------
// parse_status_verbose
// ---------------------------------------------------------------------------

#[test]
fn parse_status_verbose_should_parse_defaults() {
    let output = "\
Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), disabled (routed)
New profiles: skip

To                         Action      From
--                         ------      ----
22/tcp                     ALLOW       Anywhere
";
    let status = parse_status_verbose(output).unwrap();
    assert!(status.active);
    assert_eq!(status.default_incoming, Some(Policy::Deny));
    assert_eq!(status.default_outgoing, Some(Policy::Allow));
    assert_eq!(status.default_routed, None);
    assert_eq!(status.logging_level, Some(LoggingLevel::Low));
    assert_eq!(status.new_app_profiles, Some(AppDefaultPolicy::Skip));
}

#[test]
fn parse_status_verbose_should_parse_logging_levels() {
    for (input, expected) in [
        ("on (low)", Some(LoggingLevel::Low)),
        ("on (medium)", Some(LoggingLevel::Medium)),
        ("on (high)", Some(LoggingLevel::High)),
        ("on (full)", Some(LoggingLevel::Full)),
        ("on", Some(LoggingLevel::On)),
        ("off", Some(LoggingLevel::Off)),
    ] {
        let output = format!("Status: active\nLogging: {input}\n");
        let status = parse_status_verbose(&output).unwrap();
        assert_eq!(status.logging_level, expected, "for input: {input}");
    }
}

// ---------------------------------------------------------------------------
// parse_status_numbered
// ---------------------------------------------------------------------------

#[test]
fn parse_status_numbered_should_parse_rule_numbers() {
    let output = "\
Status: active

     To                         Action      From
     --                         ------      ----
[ 1] 22/tcp                     ALLOW IN    Anywhere
[ 2] 443/tcp                    ALLOW IN    Anywhere
";
    let status = parse_status_numbered(output).unwrap();
    assert_eq!(status.rules.len(), 2);
    assert_eq!(status.rules[0].number, Some(1));
    assert_eq!(status.rules[1].number, Some(2));
}

// ---------------------------------------------------------------------------
// Rule parsing
// ---------------------------------------------------------------------------

#[test]
fn parse_rule_line_should_parse_allow() {
    let rule = parse_rule_line("ALLOW       Anywhere", false).unwrap();
    assert_eq!(rule.action, Some(Action::Allow));
}

#[test]
fn parse_rule_line_should_parse_deny() {
    let rule = parse_rule_line("DENY        203.0.113.10", false).unwrap();
    assert_eq!(rule.action, Some(Action::Deny));
}

#[test]
fn parse_rule_line_should_parse_reject() {
    let rule = parse_rule_line("REJECT      Anywhere", false).unwrap();
    assert_eq!(rule.action, Some(Action::Reject));
}

#[test]
fn parse_rule_line_should_parse_limit() {
    let rule = parse_rule_line("LIMIT       Anywhere", false).unwrap();
    assert_eq!(rule.action, Some(Action::Limit));
}

#[test]
fn parse_rule_line_should_parse_direction_in() {
    let rule = parse_rule_line("ALLOW IN    Anywhere", false).unwrap();
    assert_eq!(rule.direction, Some(Direction::In));
}

#[test]
fn parse_rule_line_should_parse_direction_out() {
    let rule = parse_rule_line("DENY OUT    Anywhere", false).unwrap();
    assert_eq!(rule.direction, Some(Direction::Out));
}

#[test]
fn parse_rule_line_should_extract_comment() {
    let rule = parse_rule_line("ALLOW IN    Anywhere comment managed:https", false).unwrap();
    assert_eq!(rule.comment, Some("managed:https".to_string()));
}

#[test]
fn parse_rule_line_should_detect_ipv6() {
    let rule = parse_rule_line("ALLOW       Anywhere (v6)", false).unwrap();
    assert!(rule.ipv6);
}

// ---------------------------------------------------------------------------
// Numbered rule parsing
// ---------------------------------------------------------------------------

#[test]
fn parse_numbered_rule_line_should_extract_number() {
    let rule = parse_numbered_rule_line("[ 1] ALLOW IN    Anywhere").unwrap();
    assert_eq!(rule.number, Some(1));
    assert_eq!(rule.action, Some(Action::Allow));
}

#[test]
fn parse_numbered_rule_line_should_handle_double_digits() {
    let rule = parse_numbered_rule_line("[10] DENY        Anywhere").unwrap();
    assert_eq!(rule.number, Some(10));
}

#[test]
fn parse_numbered_rule_line_should_handle_non_numbered() {
    let rule = parse_numbered_rule_line("ALLOW IN    Anywhere");
    // Should fall through to parse_rule_line
    assert!(rule.is_some());
}

// ---------------------------------------------------------------------------
// Edge-case tests
// ---------------------------------------------------------------------------

#[test]
fn parse_status_should_skip_separator_lines() {
    let output = "\
Status: active

To                         Action      From
--                         ------      ----
22/tcp                     ALLOW       Anywhere
";
    let status = parse_status(output).unwrap();
    // Should not include the header or separator as rules
    assert_eq!(status.rules.len(), 1);
}

#[test]
fn parse_status_verbose_should_handle_missing_fields() {
    let output = "Status: active\n";
    let status = parse_status_verbose(output).unwrap();
    assert!(status.active);
    assert!(status.default_incoming.is_none());
    assert!(status.logging_level.is_none());
}

// ---------------------------------------------------------------------------
// Weird edge-case tests
// ---------------------------------------------------------------------------

#[test]
fn parse_status_should_handle_empty_output() {
    let status = parse_status("").unwrap();
    assert!(!status.active);
    assert!(status.rules.is_empty());
}

#[test]
fn parse_status_verbose_should_handle_unknown_policy() {
    let output = "Status: active\nDefault: foo (incoming)\n";
    let status = parse_status_verbose(output).unwrap();
    assert!(status.default_incoming.is_none());
}

#[test]
fn parse_status_verbose_should_handle_unknown_logging() {
    let output = "Status: active\nLogging: super-custom\n";
    let status = parse_status_verbose(output).unwrap();
    // Falls through to "off" by default
    assert_eq!(status.logging_level, Some(LoggingLevel::Off));
}

// ---------------------------------------------------------------------------
// Production-grade weird edge cases
// ---------------------------------------------------------------------------

#[test]
fn parse_status_should_handle_extra_whitespace() {
    let output = "  Status:   active  \n";
    let status = parse_status(output).unwrap();
    assert!(status.active);
}

#[test]
fn parse_rule_line_should_handle_empty_string() {
    let rule = parse_rule_line("", false);
    assert!(rule.is_none());
}

#[test]
fn parse_numbered_rule_line_should_handle_no_bracket() {
    let rule = parse_numbered_rule_line("just some text");
    assert!(rule.is_some());
}

#[test]
fn parse_status_verbose_should_parse_routed_policy() {
    let output = "Status: active\nDefault: deny (incoming), allow (outgoing), deny (routed)\n";
    let status = parse_status_verbose(output).unwrap();
    assert_eq!(status.default_routed, Some(Policy::Deny));
}

#[test]
fn parse_status_verbose_should_parse_accept_as_allow() {
    let output = "Status: active\nDefault: accept (incoming), accept (outgoing)\n";
    let status = parse_status_verbose(output).unwrap();
    assert_eq!(status.default_incoming, Some(Policy::Allow));
    assert_eq!(status.default_outgoing, Some(Policy::Allow));
}

// ---------------------------------------------------------------------------
// Realistic UFW output (action token mid-line, not at line start)
// ---------------------------------------------------------------------------

#[test]
fn parse_rule_line_should_parse_action_after_target_column() {
    // Real `ufw status` output is column-oriented: the port/target ("22/tcp")
    // appears first, then the action token. The parser must locate the action
    // token regardless of leading column width.
    let rule = parse_rule_line("22/tcp                     ALLOW       Anywhere", false).unwrap();
    assert_eq!(rule.action, Some(Action::Allow));
    assert_eq!(rule.direction, None); // non-numbered output has no IN/OUT
    assert!(rule.raw.contains("22/tcp"));
}

#[test]
fn parse_rule_line_should_parse_direction_after_action() {
    // Numbered/verbose output like "22/tcp ALLOW IN Anywhere".
    let rule = parse_rule_line("22/tcp ALLOW IN    Anywhere", false).unwrap();
    assert_eq!(rule.action, Some(Action::Allow));
    assert_eq!(rule.direction, Some(Direction::In));
}

#[test]
fn parse_status_numbered_should_parse_realistic_numbered_output() {
    // Regression: realistic `ufw status numbered` output. The action token
    // follows the destination port, not the leading "[ N ]" marker.
    let output = "\
Status: active

     To                         Action      From
     --                         ------      ----
[ 1] 22/tcp                     ALLOW IN    Anywhere
[ 2] 443/tcp                    ALLOW IN    Anywhere
[ 3] 80/tcp                     DENY        Anywhere
";
    let status = parse_status_numbered(output).unwrap();
    assert_eq!(status.rules.len(), 3);
    assert_eq!(status.rules[0].number, Some(1));
    assert_eq!(status.rules[0].action, Some(Action::Allow));
    assert_eq!(status.rules[0].direction, Some(Direction::In));
    assert_eq!(status.rules[2].action, Some(Action::Deny));
}

#[test]
fn parse_status_should_extract_action_from_realistic_columns() {
    let output = "\
Status: active

To                         Action      From
--                         ------      ----
22/tcp                     ALLOW       Anywhere
53/udp                     DENY        Anywhere
";
    let status = parse_status(output).unwrap();
    assert_eq!(status.rules.len(), 2);
    assert_eq!(status.rules[0].action, Some(Action::Allow));
    assert_eq!(status.rules[1].action, Some(Action::Deny));
}

// ---------------------------------------------------------------------------
// parse_show_listening
// ---------------------------------------------------------------------------

#[test]
fn parse_show_listening_should_parse_empty_input() {
    let ports = parse_show_listening("");
    assert!(ports.is_empty());
}

#[test]
fn parse_show_listening_should_parse_header_only() {
    let output = "Listening:\n";
    let ports = parse_show_listening(output);
    assert!(ports.is_empty());
}

#[test]
fn parse_show_listening_should_parse_multiple_entries() {
    let output = "\
Listening:
 tcp 0.0.0.0:22
 tcp [::]:22
 tcp 0.0.0.0:80
 udp 0.0.0.0:68
";
    let ports = parse_show_listening(output);
    assert_eq!(ports.len(), 4);
    assert_eq!(ports[0].proto, "tcp");
    assert_eq!(ports[0].address, "0.0.0.0:22");
    assert_eq!(ports[1].proto, "tcp");
    assert_eq!(ports[1].address, "[::]:22");
    assert_eq!(ports[2].proto, "tcp");
    assert_eq!(ports[2].address, "0.0.0.0:80");
    assert_eq!(ports[3].proto, "udp");
    assert_eq!(ports[3].address, "0.0.0.0:68");
}

#[test]
fn parse_show_listening_should_skip_malformed_lines() {
    let output = "\
Listening:
 tcp 0.0.0.0:22

 tcp
 0.0.0.0:80

unknown
 tcp [::]:443
";
    let ports = parse_show_listening(output);
    // "tcp" (no address), "0.0.0.0:80" (no proto), "unknown" (no address) skipped
    assert_eq!(ports.len(), 2);
    assert_eq!(ports[0].address, "0.0.0.0:22");
    assert_eq!(ports[1].address, "[::]:443");
}

#[test]
fn parse_show_listening_should_ignore_text_before_header() {
    let output = "\
some noise
more noise
Listening:
 tcp 0.0.0.0:22
";
    let ports = parse_show_listening(output);
    assert_eq!(ports.len(), 1);
    assert_eq!(ports[0].proto, "tcp");
    assert_eq!(ports[0].address, "0.0.0.0:22");
}

// ---------------------------------------------------------------------------
// parse_show_added
// ---------------------------------------------------------------------------

#[test]
fn parse_show_added_should_parse_empty_input() {
    let rules = parse_show_added("");
    assert!(rules.is_empty());
}

#[test]
fn parse_show_added_should_parse_header_only() {
    let output = "Added user rules (see 'ufw status'):\n";
    let rules = parse_show_added(output);
    assert!(rules.is_empty());
}

#[test]
fn parse_show_added_should_parse_multiple_entries() {
    let output = "\
Added user rules (see 'ufw status'):
allow 22/tcp
allow 80/tcp
deny 53/udp
allow in on eth0 proto tcp from any to any port 443 comment managed:https
";
    let rules = parse_show_added(output);
    assert_eq!(rules.len(), 4);
    assert_eq!(rules[0].raw, "allow 22/tcp");
    assert_eq!(rules[1].raw, "allow 80/tcp");
    assert_eq!(rules[2].raw, "deny 53/udp");
    assert_eq!(
        rules[3].raw,
        "allow in on eth0 proto tcp from any to any port 443 comment managed:https"
    );
}

#[test]
fn parse_show_added_should_skip_blank_lines() {
    let output = "\
Added user rules (see 'ufw status'):

allow 22/tcp

deny 53/udp

";
    let rules = parse_show_added(output);
    assert_eq!(rules.len(), 2);
    assert_eq!(rules[0].raw, "allow 22/tcp");
    assert_eq!(rules[1].raw, "deny 53/udp");
}

#[test]
fn parse_show_added_should_ignore_text_before_header() {
    let output = "\
noise
Added user rules (see 'ufw status'):
allow 22/tcp
";
    let rules = parse_show_added(output);
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].raw, "allow 22/tcp");
}
