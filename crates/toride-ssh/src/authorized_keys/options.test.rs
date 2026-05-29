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
    let opts = parse_options(
        "no-pty,no-port-forwarding,no-X11-forwarding,no-agent-forwarding,no-user-rc",
    )
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
