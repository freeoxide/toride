use super::*;

#[test]
fn parse_options_should_return_defaults_when_input_is_empty() {
    let opts = parse_options("").unwrap();
    assert!(opts.command.is_none());
    assert!(opts.from.is_empty());
    assert!(!opts.no_pty);
}

#[test]
fn parse_options_should_recognize_all_boolean_flags() {
    let opts =
        parse_options("no-pty,no-port-forwarding,no-X11-forwarding,no-agent-forwarding,no-user-rc")
            .unwrap();
    assert!(opts.no_pty);
    assert!(opts.no_port_forwarding);
    assert!(opts.no_x11_forwarding);
    assert!(opts.no_agent_forwarding);
    assert!(opts.no_user_rc);
}

#[test]
fn parse_options_should_extract_command_value() {
    let opts = parse_options("command=\"/usr/bin/true\"").unwrap();
    assert_eq!(opts.command.as_deref(), Some("/usr/bin/true"));
}

#[test]
fn parse_options_should_parse_mixed_flags_and_values() {
    let opts = parse_options("no-pty,command=\"/bin/bash\",from=\"10.0.0.*\"").unwrap();
    assert!(opts.no_pty);
    assert_eq!(opts.command.as_deref(), Some("/bin/bash"));
    assert_eq!(opts.from, vec!["10.0.0.*"]);
}

#[test]
fn parse_options_should_recognize_cert_authority_flag() {
    let opts = parse_options("cert-authority").unwrap();
    assert!(opts.cert_authority);
}

#[test]
fn parse_options_should_parse_environment_key_value() {
    let opts = parse_options("environment=\"FOO=bar\"").unwrap();
    assert_eq!(
        opts.environment,
        vec![("FOO".to_string(), "bar".to_string())]
    );
}

#[test]
fn parse_options_should_parse_permit_open_value() {
    let opts = parse_options("permit-open=\"host:22\"").unwrap();
    assert_eq!(opts.permit_open, vec!["host:22"]);
}

#[test]
fn parse_options_should_preserve_custom_options() {
    let opts = parse_options("custom-flag,custom-value=\"hello\"").unwrap();
    assert_eq!(opts.custom.len(), 2);
    assert_eq!(opts.custom[0], ("custom-flag".to_string(), None));
    assert_eq!(
        opts.custom[1],
        ("custom-value".to_string(), Some("hello".to_string()))
    );
}

#[test]
fn parse_options_should_recognize_restrict_flag() {
    let opts = parse_options("restrict").unwrap();
    assert!(opts.restrict);
}

#[test]
fn parse_options_should_parse_principals_value() {
    let opts = parse_options("principals=\"admin,deploy\"").unwrap();
    assert_eq!(opts.principals, vec!["admin,deploy"]);
}

#[test]
fn parse_options_should_parse_expiry_time_value() {
    let opts = parse_options("expiry-time=\"20250101T000000\"").unwrap();
    assert_eq!(opts.expiry_time.as_deref(), Some("20250101T000000"));
}

#[test]
fn parse_options_should_recognize_perferrp_flag() {
    let opts = parse_options("perferrp").unwrap();
    assert!(opts.perferrp);
}

#[test]
fn parse_options_should_allow_empty_command_value() {
    let opts = parse_options("command=\"\"").unwrap();
    assert_eq!(opts.command.as_deref(), Some(""));
}

#[test]
fn parse_options_should_unescape_quotes_in_values() {
    let opts = parse_options("command=\"echo \\\"hello\\\"\"").unwrap();
    assert_eq!(opts.command.as_deref(), Some("echo \"hello\""));
}

#[test]
fn parse_options_should_unescape_backslashes_in_values() {
    let opts = parse_options("command=\"path\\\\to\\\\file\"").unwrap();
    assert_eq!(opts.command.as_deref(), Some("path\\to\\file"));
}

#[test]
fn parse_options_should_treat_single_quotes_as_literal() {
    let opts = parse_options("command=\"echo 'hello'\"").unwrap();
    assert_eq!(opts.command.as_deref(), Some("echo 'hello'"));
}

#[test]
fn parse_options_should_handle_commas_inside_quoted_values() {
    let opts = parse_options("command=\"a,b\",no-pty").unwrap();
    assert_eq!(opts.command.as_deref(), Some("a,b"));
    assert!(opts.no_pty);
}

#[test]
fn unescape_should_convert_escaped_quote_to_literal() {
    assert_eq!(unescape("hello\\\"world"), "hello\"world");
}

#[test]
fn unescape_should_convert_escaped_backslash_to_literal() {
    assert_eq!(unescape("hello\\\\world"), "hello\\world");
}

#[test]
fn unescape_should_preserve_trailing_backslash() {
    assert_eq!(unescape("hello\\"), "hello\\");
}

// ---------------------------------------------------------------------------
// Edge-case tests for comma-separated from/permit-open
// ---------------------------------------------------------------------------

#[test]
fn parse_options_from_comma_separated() {
    let opts = parse_options("from=\"host1,host2,host3\"").unwrap();
    assert_eq!(opts.from, vec!["host1", "host2", "host3"]);
}

#[test]
fn parse_options_from_comma_separated_with_spaces() {
    let opts = parse_options("from=\"host1, host2 , host3\"").unwrap();
    assert_eq!(opts.from, vec!["host1", "host2", "host3"]);
}

#[test]
fn parse_options_from_single_value() {
    let opts = parse_options("from=\"host1\"").unwrap();
    assert_eq!(opts.from, vec!["host1"]);
}

#[test]
fn parse_options_from_empty_string() {
    let opts = parse_options("from=\"\"").unwrap();
    assert!(opts.from.is_empty());
}

#[test]
fn parse_options_permit_open_comma_separated() {
    let opts = parse_options("permit-open=\"host1:22,host2:22,host3:22\"").unwrap();
    assert_eq!(opts.permit_open, vec!["host1:22", "host2:22", "host3:22"]);
}

#[test]
fn parse_options_permit_open_comma_separated_with_spaces() {
    let opts = parse_options("permit-open=\"host1:22, host2:22\"").unwrap();
    assert_eq!(opts.permit_open, vec!["host1:22", "host2:22"]);
}

#[test]
fn parse_options_permit_open_empty_string() {
    let opts = parse_options("permit-open=\"\"").unwrap();
    assert!(opts.permit_open.is_empty());
}

#[test]
fn parse_options_multiple_from_directives() {
    // Each from="..." occurrence should push entries
    let opts = parse_options("from=\"host1\",from=\"host2\"").unwrap();
    assert_eq!(opts.from, vec!["host1", "host2"]);
}

#[test]
fn parse_options_environment_without_equals() {
    // environment="VAR" (no = in value) should set empty value
    let opts = parse_options("environment=\"VAR\"").unwrap();
    assert_eq!(opts.environment, vec![("VAR".to_string(), String::new())]);
}

#[test]
fn parse_options_whitespace_only() {
    let opts = parse_options("   ").unwrap();
    assert!(opts.command.is_none());
    assert!(opts.from.is_empty());
    assert!(!opts.no_pty);
}

#[test]
fn parse_options_trailing_comma() {
    let opts = parse_options("no-pty,").unwrap();
    assert!(opts.no_pty);
}

#[test]
fn parse_options_leading_comma() {
    let opts = parse_options(",no-pty").unwrap();
    assert!(opts.no_pty);
}

// ---------------------------------------------------------------------------
// Weird edge-case tests
// ---------------------------------------------------------------------------

#[test]
fn parse_options_from_only_commas() {
    let opts = parse_options("from=\",,,\"").unwrap();
    // All empty segments should be filtered out
    assert!(opts.from.is_empty());
}

#[test]
fn parse_options_permit_open_only_commas() {
    let opts = parse_options("permit-open=\",,,\"").unwrap();
    assert!(opts.permit_open.is_empty());
}

#[test]
fn parse_options_from_with_whitespace_segments() {
    let opts = parse_options("from=\"  ,  ,  \"").unwrap();
    // Whitespace-only segments should be filtered out
    assert!(opts.from.is_empty());
}

#[test]
fn parse_options_nested_single_quotes_in_double() {
    let opts = parse_options("command=\"echo 'hello world'\"").unwrap();
    assert_eq!(opts.command.as_deref(), Some("echo 'hello world'"));
}

#[test]
fn parse_options_escaped_backslash_before_quote() {
    // command="path\\\"file" should become path\"file
    let opts = parse_options("command=\"path\\\\\\\"file\"").unwrap();
    assert_eq!(opts.command.as_deref(), Some("path\\\"file"));
}

#[test]
fn parse_options_very_long_value() {
    let long_val = "x".repeat(10000);
    let opts = parse_options(&format!("command=\"{long_val}\"")).unwrap();
    assert_eq!(opts.command.as_deref(), Some(long_val.as_str()));
}

#[test]
fn parse_options_multiple_commands() {
    // Multiple command= options - last wins per OpenSSH spec
    let opts = parse_options("command=\"first\",command=\"second\"").unwrap();
    assert_eq!(opts.command.as_deref(), Some("second"));
}

#[test]
fn parse_options_restrict_with_permit() {
    // restrict disables everything, permit-pty re-enables pty
    let opts = parse_options("restrict,permit-pty").unwrap();
    assert!(opts.restrict);
    // Note: permit-pty is not a recognized option in our parser,
    // so it goes to custom
}

#[test]
fn parse_options_environment_multiple() {
    let opts = parse_options("environment=\"A=1\",environment=\"B=2\"").unwrap();
    assert_eq!(opts.environment.len(), 2);
    assert_eq!(opts.environment[0], ("A".to_string(), "1".to_string()));
    assert_eq!(opts.environment[1], ("B".to_string(), "2".to_string()));
}

#[test]
fn parse_options_empty_key_name() {
    // Options like ="value" should be handled gracefully
    let result = parse_options("=\"value\"");
    // This should either parse or error, not panic
    let _ = result;
}

#[test]
fn parse_options_backslash_at_end_of_value() {
    // Trailing backslash should be preserved
    let opts = parse_options("command=\"path\\\\\"").unwrap();
    assert_eq!(opts.command.as_deref(), Some("path\\"));
}

#[test]
fn parse_options_quote_in_middle_of_unquoted_value() {
    // This is technically malformed but should not panic
    let result = parse_options("from=host\"name");
    let _ = result;
}

#[test]
fn parse_options_all_options_combined() {
    let opts = parse_options(
        "command=\"/bin/bash\",from=\"10.0.0.*\",no-pty,no-port-forwarding,\
         no-X11-forwarding,no-agent-forwarding,no-user-rc,restrict,\
         permit-open=\"host:22\",environment=\"FOO=bar\",tunnel=\"eth0\",\
         cert-authority,principals=\"admin\",expiry-time=\"20250101T000000\",\
         perferrp",
    )
    .unwrap();
    assert_eq!(opts.command.as_deref(), Some("/bin/bash"));
    assert_eq!(opts.from, vec!["10.0.0.*"]);
    assert!(opts.no_pty);
    assert!(opts.no_port_forwarding);
    assert!(opts.no_x11_forwarding);
    assert!(opts.no_agent_forwarding);
    assert!(opts.no_user_rc);
    assert!(opts.restrict);
    assert_eq!(opts.permit_open, vec!["host:22"]);
    assert_eq!(
        opts.environment,
        vec![("FOO".to_string(), "bar".to_string())]
    );
    assert_eq!(opts.tunnel.as_deref(), Some("eth0"));
    assert!(opts.cert_authority);
    assert_eq!(opts.principals, vec!["admin"]);
    assert_eq!(opts.expiry_time.as_deref(), Some("20250101T000000"));
    assert!(opts.perferrp);
}

// ---------------------------------------------------------------------------
// Production-grade weird edge cases
// ---------------------------------------------------------------------------

#[test]
fn parse_options_unmatched_quote_at_end() {
    // Missing closing quote — should not panic
    let result = parse_options("command=\"test");
    // May error or return partial result
    let _ = result;
}

#[test]
fn parse_options_unmatched_quote_at_start() {
    // Missing opening quote — should not panic
    let result = parse_options("command=test\"");
    let _ = result;
}

#[test]
fn parse_options_backslash_at_very_end() {
    // Backslash at end of quoted value
    let opts = parse_options("command=\"path\\\\\"").unwrap();
    assert_eq!(opts.command.as_deref(), Some("path\\"));
}

#[test]
fn parse_options_empty_option_name() {
    // Options like ="value" or ",value"
    let result = parse_options("=\"value\"");
    let _ = result;
}

#[test]
fn parse_options_only_commas() {
    let opts = parse_options(",,,").unwrap();
    assert!(opts.command.is_none());
    assert!(opts.from.is_empty());
}

#[test]
fn parse_options_whitespace_only_between_commas() {
    let opts = parse_options(" , , , ").unwrap();
    assert!(opts.command.is_none());
}

#[test]
fn parse_options_from_with_empty_segments() {
    let opts = parse_options("from=\"host1,,host2,,\"").unwrap();
    assert_eq!(opts.from, vec!["host1", "host2"]);
}

#[test]
fn parse_options_permit_open_with_empty_segments() {
    let opts = parse_options("permit-open=\"host:22,,host:80,,\"").unwrap();
    assert_eq!(opts.permit_open, vec!["host:22", "host:80"]);
}

#[test]
fn parse_options_environment_with_empty_value() {
    let opts = parse_options("environment=\"VAR=\"").unwrap();
    assert_eq!(opts.environment, vec![("VAR".to_string(), String::new())]);
}

#[test]
fn parse_options_environment_with_equals_in_value() {
    let opts = parse_options("environment=\"PATH=/usr/bin:/bin\"").unwrap();
    assert_eq!(
        opts.environment,
        vec![("PATH".to_string(), "/usr/bin:/bin".to_string())]
    );
}

#[test]
fn parse_options_very_long_option_name() {
    let long_name = "a".repeat(1000);
    let opts = parse_options(&format!("{long_name}=\"value\"")).unwrap();
    assert_eq!(opts.custom.len(), 1);
    assert_eq!(opts.custom[0].0, long_name);
}

#[test]
fn parse_options_very_many_options() {
    let many_opts = vec!["no-pty"; 100].join(",");
    let opts = parse_options(&many_opts).unwrap();
    assert!(opts.no_pty);
}

#[test]
fn parse_options_command_with_newline_in_value() {
    // Newline inside quoted value — should be preserved or handled
    let opts = parse_options("command=\"line1\\nline2\"").unwrap();
    // The \n is literal backslash-n, not a newline
    assert!(opts.command.is_some());
}

#[test]
fn parse_options_command_with_tab_in_value() {
    let opts = parse_options("command=\"col1\\tcol2\"").unwrap();
    assert!(opts.command.is_some());
}

#[test]
fn parse_options_restrict_with_multiple_permits() {
    let opts = parse_options("restrict,permit-pty,permit-port-forwarding").unwrap();
    assert!(opts.restrict);
    // permit-pty and permit-port-forwarding go to custom
    assert_eq!(opts.custom.len(), 2);
}

// ---------------------------------------------------------------------------
// Workflow-discovered edge cases
// ---------------------------------------------------------------------------

#[test]
fn parse_options_newline_injection_in_command() {
    // Newline in command value should be preserved (it's the caller's job to reject)
    let opts = parse_options("command=\"line1\nline2\"");
    // The parser may handle this differently depending on implementation
    let _ = opts;
}

#[test]
fn parse_options_newline_injection_in_from() {
    // Newline in from value should be preserved (it's the caller's job to reject)
    let opts = parse_options("from=\"host1\nhost2\"");
    let _ = opts;
}

#[test]
fn parse_options_carriage_return_in_value() {
    // CR in value
    let opts = parse_options("command=\"test\rvalue\"");
    let _ = opts;
}

#[test]
fn parse_options_null_byte_in_value() {
    // Null byte in value should not panic
    let opts = parse_options("command=\"test\0value\"");
    let _ = opts;
}
