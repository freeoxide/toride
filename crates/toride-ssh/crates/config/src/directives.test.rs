use super::*;
use crate::ast::{ConfigAst, parse as parse_ast};

fn make_ast(input: &str) -> ConfigAst {
    parse_ast(input)
}

#[test]
fn get_directive_finds_hostname() {
    let ast = make_ast(
        "\
Host example
    HostName example.com
    User alice
",
    );
    let val = get_directive(&ast, "example", "HostName");
    assert_eq!(val, Some("example.com".to_owned()));
}

#[test]
fn get_directive_case_insensitive_key() {
    let ast = make_ast(
        "\
Host example
    hostname example.com
",
    );
    let val = get_directive(&ast, "example", "HOSTNAME");
    assert_eq!(val, Some("example.com".to_owned()));
}

#[test]
fn get_directive_wildcard_match() {
    let ast = make_ast(
        "\
Host *
    User default
",
    );
    let val = get_directive(&ast, "anything", "User");
    assert_eq!(val, Some("default".to_owned()));
}

#[test]
fn get_directive_negation() {
    let ast = make_ast(
        "\
Host * !badhost
    User default
",
    );
    let val = get_directive(&ast, "goodhost", "User");
    assert_eq!(val, Some("default".to_owned()));

    let val = get_directive(&ast, "badhost", "User");
    assert_eq!(val, None);
}

#[test]
fn glob_matches_works() {
    assert!(glob_matches("example.com", "example.com"));
    assert!(glob_matches("anything", "*"));
    assert!(glob_matches("foo.example.com", "*.example.com"));
    assert!(glob_matches("a", "?"));
    assert!(!glob_matches("example.com", "other.com"));
    assert!(!glob_matches("example.com", "*.org"));
}

#[test]
fn glob_wildcard_excludes_bare_domain() {
    assert!(!glob_matches("example.com", "*.example.com"));
    assert!(glob_matches("sub.example.com", "*.example.com"));
}

#[test]
fn glob_matches_case_insensitive() {
    assert!(host_matches_patterns(
        "Example.COM",
        &["example.com".to_owned()]
    ));
}

#[test]
fn accumulative_directives_collected_across_blocks() {
    let ast = make_ast(
        "\
Host myhost
    IdentityFile ~/.ssh/id_ed25519

Host *
    IdentityFile ~/.ssh/id_rsa
",
    );
    let vals = get_accumulative_directive(&ast, "myhost", "IdentityFile");
    assert_eq!(vals.len(), 2);
    assert_eq!(vals[0], "~/.ssh/id_ed25519");
    assert_eq!(vals[1], "~/.ssh/id_rsa");
}

#[test]
fn is_accumulative_known_directives() {
    assert!(is_accumulative("identityfile"));
    assert!(is_accumulative("certificatefile"));
    // ProxyJump uses first-match-wins per OpenSSH ssh_config(5), NOT accumulative.
    assert!(!is_accumulative("proxyjump"));
    // ForwardAgent is first-match-wins per OpenSSH ssh_config(5).
    assert!(!is_accumulative("forwardagent"));
    assert!(!is_accumulative("hostname"));
    assert!(!is_accumulative("user"));
    assert!(!is_accumulative("port"));
    // First-match-wins: identityagent, addkeystoagent, usekeychain,
    // controlmaster, controlpath, controlpersist.
    assert!(!is_accumulative("identityagent"));
    assert!(!is_accumulative("addkeystoagent"));
    assert!(!is_accumulative("usekeychain"));
    assert!(!is_accumulative("controlmaster"));
    assert!(!is_accumulative("controlpath"));
    assert!(!is_accumulative("controlpersist"));
    // Accumulative forwarding directives.
    assert!(is_accumulative("localforward"));
    assert!(is_accumulative("remoteforward"));
    assert!(is_accumulative("dynamicforward"));
}

// ---------------------------------------------------------------------------
// Edge-case tests for glob and pattern matching
// ---------------------------------------------------------------------------

#[test]
fn glob_matches_empty_text_and_pattern() {
    assert!(glob_matches("", ""));
    assert!(glob_matches("", "*"));
    assert!(!glob_matches("", "?"));
    assert!(!glob_matches("", "a"));
}

#[test]
fn glob_matches_question_mark_edge_cases() {
    assert!(glob_matches("a", "?"));
    assert!(!glob_matches("", "?"));
    assert!(glob_matches("ab", "??"));
    assert!(!glob_matches("a", "??"));
}

#[test]
fn glob_matches_multiple_stars() {
    assert!(glob_matches("anything", "**"));
    assert!(glob_matches("anything", "***"));
    assert!(glob_matches("a.b.c", "*.*.*"));
    assert!(!glob_matches("ab", "*.*.*"));
}

#[test]
fn glob_matches_star_at_start() {
    assert!(glob_matches("example.com", "*.com"));
    assert!(!glob_matches("com", "*.com"));
}

#[test]
fn glob_matches_star_in_middle() {
    assert!(glob_matches("sub.example.com", "sub.*.com"));
    assert!(!glob_matches("sub.example.org", "sub.*.com"));
}

#[test]
fn host_matches_patterns_empty_patterns() {
    assert!(!host_matches_patterns("example.com", &[] as &[&str]));
}

#[test]
fn host_matches_patterns_only_negation() {
    // Only negation patterns with no positive match should return false
    let patterns = vec!["!badhost".to_string()];
    assert!(!host_matches_patterns("goodhost", &patterns));
    assert!(!host_matches_patterns("badhost", &patterns));
}

#[test]
fn host_matches_patterns_negation_overrides_positive() {
    let patterns = vec!["*".to_string(), "!badhost".to_string()];
    assert!(host_matches_patterns("goodhost", &patterns));
    assert!(!host_matches_patterns("badhost", &patterns));
}

#[test]
fn host_matches_patterns_case_insensitive() {
    assert!(host_matches_patterns(
        "EXAMPLE.COM",
        &["example.com".to_string()]
    ));
    assert!(host_matches_patterns(
        "example.com",
        &["EXAMPLE.COM".to_string()]
    ));
}

#[test]
fn host_matches_patterns_wildcard_all() {
    let patterns = vec!["*".to_string()];
    assert!(host_matches_patterns("anything", &patterns));
    assert!(host_matches_patterns("", &patterns));
}

#[test]
fn host_matches_patterns_empty_host() {
    assert!(host_matches_patterns("", &["*".to_string()]));
    assert!(!host_matches_patterns("", &["example.com".to_string()]));
}

#[test]
fn get_directive_no_matching_host() {
    let ast = make_ast("Host other\n    User alice\n");
    let val = get_directive(&ast, "example", "User");
    assert_eq!(val, None);
}

#[test]
fn get_directive_empty_ast() {
    let ast = make_ast("");
    let val = get_directive(&ast, "example", "User");
    assert_eq!(val, None);
}

#[test]
fn get_directive_first_match_wins() {
    let ast = make_ast(
        "\
Host *
    User first

Host *
    User second
",
    );
    let val = get_directive(&ast, "anything", "User");
    assert_eq!(val, Some("first".to_owned()));
}

#[test]
fn get_accumulative_directive_no_match() {
    let ast = make_ast("Host other\n    IdentityFile ~/.ssh/id_rsa\n");
    let vals = get_accumulative_directive(&ast, "example", "IdentityFile");
    assert!(vals.is_empty());
}

#[test]
fn set_directive_creates_new_block() {
    let mut ast = make_ast("Host example\n    User alice\n");
    set_directive(&mut ast, "example", "HostName", "example.com").unwrap();
    let val = get_directive(&ast, "example", "HostName");
    assert_eq!(val, Some("example.com".to_owned()));
}

#[test]
fn set_directive_updates_existing() {
    let mut ast = make_ast("Host example\n    HostName old.com\n");
    set_directive(&mut ast, "example", "HostName", "new.com").unwrap();
    let val = get_directive(&ast, "example", "HostName");
    assert_eq!(val, Some("new.com".to_owned()));
}

#[test]
fn set_directive_host_not_found() {
    let mut ast = make_ast("");
    assert!(set_directive(&mut ast, "missing", "User", "alice").is_err());
}

// ---------------------------------------------------------------------------
// Weird edge-case tests for glob and pattern matching
// ---------------------------------------------------------------------------

#[test]
fn glob_matches_consecutive_stars() {
    // ** should match anything (same as *)
    assert!(glob_matches("anything", "**"));
    assert!(glob_matches("", "**"));
    assert!(glob_matches("a.b.c", "**"));
}

#[test]
fn glob_matches_star_at_end() {
    assert!(glob_matches("prefix", "prefix*"));
    assert!(glob_matches("prefix-extra", "prefix*"));
    assert!(!glob_matches("pre", "prefix*"));
}

#[test]
fn glob_matches_star_at_start_and_end() {
    assert!(glob_matches("middle", "*middle*"));
    assert!(glob_matches("a-middle-b", "*middle*"));
    assert!(!glob_matches("midle", "*middle*"));
}

#[test]
fn glob_matches_question_marks_sequence() {
    assert!(glob_matches("abc", "???"));
    assert!(!glob_matches("ab", "???"));
    assert!(!glob_matches("abcd", "???"));
}

#[test]
fn glob_matches_mixed_wildcards() {
    assert!(glob_matches("test.conf", "test.*"));
    assert!(glob_matches("test.conf", "te?t.*"));
    // t??? matches "test" (t + 3 chars), .* matches ".conf"
    assert!(glob_matches("test.conf", "t???.*"));
}

#[test]
fn host_matches_patterns_leading_dot() {
    // Leading dot is a valid hostname pattern in some contexts
    assert!(host_matches_patterns(
        ".example.com",
        &[".example.com".to_string()]
    ));
}

#[test]
fn host_matches_patterns_trailing_dot() {
    // Trailing dot is valid FQDN notation
    assert!(host_matches_patterns(
        "example.com.",
        &["example.com.".to_string()]
    ));
}

#[test]
fn host_matches_patterns_consecutive_dots() {
    // Unusual but should not panic
    assert!(!host_matches_patterns(
        "example.com",
        &["..example.com".to_string()]
    ));
}

#[test]
fn host_matches_patterns_very_long() {
    let long_host = "a".repeat(256);
    let patterns = vec![long_host.clone()];
    assert!(host_matches_patterns(&long_host, &patterns));
    assert!(!host_matches_patterns("short", &patterns));
}

#[test]
fn host_matches_patterns_unicode() {
    // Unicode hostnames (IDN) - should work with ASCII lowercase
    assert!(host_matches_patterns("höst", &["höst".to_string()]));
}

#[test]
fn get_directive_multiple_hosts_same_name() {
    // Two Host blocks with the same name - first wins
    let ast = make_ast("Host dup\n    User first\nHost dup\n    User second\n");
    let val = get_directive(&ast, "dup", "User");
    assert_eq!(val, Some("first".to_owned()));
}

#[test]
fn get_directive_host_with_equals_separator() {
    let ast = make_ast("Host=example\n    User=alice\n");
    let val = get_directive(&ast, "example", "User");
    // The value includes the = separator
    assert!(val.is_some());
}

#[test]
fn set_directive_preserves_other_directives() {
    let mut ast = make_ast("Host example\n    User alice\n    Port 22\n");
    set_directive(&mut ast, "example", "HostName", "example.com").unwrap();
    let user = get_directive(&ast, "example", "User");
    let port = get_directive(&ast, "example", "Port");
    assert_eq!(user, Some("alice".to_owned()));
    assert_eq!(port, Some("22".to_owned()));
}

#[test]
fn set_directive_overwrites_value() {
    let mut ast = make_ast("Host example\n    HostName old.com\n");
    set_directive(&mut ast, "example", "HostName", "new.com").unwrap();
    set_directive(&mut ast, "example", "HostName", "final.com").unwrap();
    let val = get_directive(&ast, "example", "HostName");
    assert_eq!(val, Some("final.com".to_owned()));
}

// ---------------------------------------------------------------------------
// Production-grade weird edge cases
// ---------------------------------------------------------------------------

#[test]
fn host_matches_patterns_only_negation_multiple() {
    // Multiple negation patterns with no positive match
    let patterns = vec!["!a".to_string(), "!b".to_string(), "!c".to_string()];
    assert!(!host_matches_patterns("d", &patterns));
    assert!(!host_matches_patterns("a", &patterns));
}

#[test]
fn host_matches_patterns_negation_of_wildcard() {
    // * matches everything, !specific negates it
    let patterns = vec!["*".to_string(), "!specific".to_string()];
    assert!(host_matches_patterns("anything", &patterns));
    assert!(!host_matches_patterns("specific", &patterns));
}

#[test]
fn host_matches_patterns_empty_string_patterns() {
    let patterns = vec![String::new()];
    // Empty pattern matches empty host
    assert!(host_matches_patterns("", &patterns));
    assert!(!host_matches_patterns("host", &patterns));
}

#[test]
fn glob_matches_only_question_marks() {
    assert!(glob_matches("abc", "???"));
    assert!(!glob_matches("abcd", "???"));
    assert!(!glob_matches("ab", "???"));
    assert!(!glob_matches("", "???"));
}

#[test]
fn glob_matches_star_matches_empty() {
    // * should match empty string
    assert!(glob_matches("", "*"));
    assert!(glob_matches("", "**"));
    assert!(glob_matches("", "***"));
}

#[test]
fn glob_matches_pattern_longer_than_text() {
    assert!(!glob_matches("ab", "abcde"));
    assert!(!glob_matches("a", "ab*"));
}

#[test]
fn glob_matches_text_with_special_chars() {
    // Text containing glob characters
    assert!(glob_matches("test*file", "test*file"));
    assert!(glob_matches("test?file", "test?file"));
}

#[test]
fn get_directive_from_match_block() {
    let ast = make_ast("Match host web\n    User admin\n");
    // get_directive only looks at Host blocks, not Match blocks
    let val = get_directive(&ast, "web", "User");
    assert_eq!(val, None);
}

#[test]
fn get_all_directives_empty_ast() {
    let ast = make_ast("");
    let dirs = get_all_directives(&ast, "host");
    assert!(dirs.is_empty());
}

#[test]
fn get_all_directives_no_match() {
    let ast = make_ast("Host other\n    User alice\n");
    let dirs = get_all_directives(&ast, "host");
    assert!(dirs.is_empty());
}

#[test]
fn set_directive_on_wildcard_host() {
    let mut ast = make_ast("Host *\n    User alice\n");
    set_directive(&mut ast, "anything", "Port", "22").unwrap();
    let val = get_directive(&ast, "anything", "Port");
    assert_eq!(val, Some("22".to_owned()));
}

#[test]
fn get_directive_with_empty_value() {
    let ast = make_ast("Host example\n    HostName\n");
    let val = get_directive(&ast, "example", "HostName");
    assert_eq!(val, Some(String::new()));
}

// ---------------------------------------------------------------------------
// Workflow-discovered edge cases
// ---------------------------------------------------------------------------

#[test]
fn crlf_in_host_pattern_breaks_matching() {
    let input = "Host example\r\n    User alice\r\n";
    let ast = crate::ast::parse(input);
    let val = get_directive(&ast, "example", "User");
    // CRLF \r should be stripped by trim(), so host matching should work
    assert!(val.is_some(), "CRLF should not break host matching");
    assert_eq!(val.unwrap(), "alice");
}

#[test]
fn crlf_in_directive_value_clean() {
    let input = "Host example\r\n    HostName myhost.com\r\n";
    let ast = crate::ast::parse(input);
    let val = get_directive(&ast, "example", "HostName");
    if let Some(ref v) = val {
        assert!(!v.contains('\r'), "\\r leaked into value: {v:?}");
    }
    assert_eq!(val.as_deref(), Some("myhost.com"));
}

// ---------------------------------------------------------------------------
// Config typed directives: certificate_files, identity_agent, etc.
// ---------------------------------------------------------------------------

#[test]
fn certificate_file_accumulated_across_blocks() {
    let ast = make_ast(
        "\
Host myhost
    CertificateFile ~/.ssh/id_ed25519-cert.pub

Host *
    CertificateFile ~/.ssh/id_rsa-cert.pub
",
    );
    let vals = get_accumulative_directive(&ast, "myhost", "CertificateFile");
    assert_eq!(vals.len(), 2);
    assert_eq!(vals[0], "~/.ssh/id_ed25519-cert.pub");
    assert_eq!(vals[1], "~/.ssh/id_rsa-cert.pub");
}

#[test]
fn identity_agent_directive_found() {
    let ast = make_ast(
        "\
Host myhost
    IdentityAgent /run/user/1000/ssh-agent.sock
",
    );
    let val = get_directive(&ast, "myhost", "IdentityAgent");
    assert_eq!(val, Some("/run/user/1000/ssh-agent.sock".into()));
}

#[test]
fn identity_agent_from_wildcard() {
    let ast = make_ast(
        "\
Host *
    IdentityAgent /tmp/agent.sock
",
    );
    let val = get_directive(&ast, "anything", "IdentityAgent");
    assert_eq!(val, Some("/tmp/agent.sock".into()));
}

#[test]
fn proxy_jump_accumulated_across_blocks() {
    let ast = make_ast(
        "\
Host target
    ProxyJump jump1

Host *
    ProxyJump jump2
",
    );
    let vals = get_accumulative_directive(&ast, "target", "ProxyJump");
    assert_eq!(vals.len(), 2);
    assert_eq!(vals[0], "jump1");
    assert_eq!(vals[1], "jump2");
}

#[test]
fn forward_agent_accumulated() {
    let ast = make_ast(
        "\
Host myhost
    ForwardAgent yes
",
    );
    let vals = get_accumulative_directive(&ast, "myhost", "ForwardAgent");
    assert_eq!(vals, vec!["yes"]);
}

#[test]
fn send_env_accumulated() {
    let ast = make_ast(
        "\
Host myhost
    SendEnv LANG
    SendEnv LC_*
",
    );
    let vals = get_accumulative_directive(&ast, "myhost", "SendEnv");
    assert_eq!(vals.len(), 2);
    assert_eq!(vals[0], "LANG");
    assert_eq!(vals[1], "LC_*");
}

#[test]
fn set_env_accumulated() {
    let ast = make_ast(
        "\
Host myhost
    SetEnv FOO=bar
    SetEnv BAZ=qux
",
    );
    let vals = get_accumulative_directive(&ast, "myhost", "SetEnv");
    assert_eq!(vals.len(), 2);
    assert_eq!(vals[0], "FOO=bar");
    assert_eq!(vals[1], "BAZ=qux");
}

#[test]
fn is_accumulative_certificate_file() {
    assert!(is_accumulative("certificatefile"));
}

#[test]
fn is_accumulative_identity_agent_not_accumulative() {
    // IdentityAgent is NOT accumulative (first-match-wins).
    assert!(!is_accumulative("identityagent"));
}

#[test]
fn get_all_directives_mixed_accumulative_and_first_match() {
    let ast = make_ast(
        "\
Host myhost
    HostName example.com
    User alice
    IdentityFile ~/.ssh/id_ed25519
    CertificateFile ~/.ssh/id_ed25519-cert.pub
",
    );
    let dirs = get_all_directives(&ast, "myhost");
    let keys: Vec<&str> = dirs.iter().map(|(k, _)| k.as_str()).collect();
    assert!(keys.contains(&"HostName"));
    assert!(keys.contains(&"User"));
    assert!(keys.contains(&"IdentityFile"));
    assert!(keys.contains(&"CertificateFile"));
}

#[test]
fn get_all_directives_first_match_wins_for_non_accumulative() {
    let ast = make_ast(
        "\
Host *
    User default

Host myhost
    User specific
",
    );
    let dirs = get_all_directives(&ast, "myhost");
    // First-match-wins: "default" from Host * is seen first and kept.
    let user_vals: Vec<&str> = dirs
        .iter()
        .filter(|(k, _)| k == "User")
        .map(|(_, v)| v.as_str())
        .collect();
    assert_eq!(user_vals, vec!["default"]);
}

#[test]
fn get_all_directives_forward_agent_first_match_wins() {
    let ast = make_ast(
        "\
Host *
    ForwardAgent no

Host myhost
    ForwardAgent yes
",
    );
    let dirs = get_all_directives(&ast, "myhost");
    let fa_vals: Vec<&str> = dirs
        .iter()
        .filter(|(k, _)| k == "ForwardAgent")
        .map(|(_, v)| v.as_str())
        .collect();
    assert_eq!(
        fa_vals,
        vec!["no"],
        "ForwardAgent should use first-match-wins"
    );
}

#[test]
fn get_all_directives_forwarding_accumulated() {
    let ast = make_ast(
        "\
Host myhost
    LocalForward 8080 localhost:80
    RemoteForward 9090 localhost:90
    DynamicForward 1080
",
    );
    let dirs = get_all_directives(&ast, "myhost");
    let keys: Vec<&str> = dirs.iter().map(|(k, _)| k.as_str()).collect();
    assert!(keys.contains(&"LocalForward"));
    assert!(keys.contains(&"RemoteForward"));
    assert!(keys.contains(&"DynamicForward"));
}

#[test]
fn is_accumulative_forwarding_directives() {
    assert!(is_accumulative("localforward"));
    assert!(is_accumulative("remoteforward"));
    assert!(is_accumulative("dynamicforward"));
    assert!(is_accumulative("identityfile"));
    assert!(is_accumulative("certificatefile"));
}

#[test]
fn is_accumulative_first_match_wins_directives() {
    assert!(!is_accumulative("identityagent"));
    assert!(!is_accumulative("forwardagent"));
    assert!(!is_accumulative("addkeystoagent"));
    assert!(!is_accumulative("usekeychain"));
    assert!(!is_accumulative("controlmaster"));
    assert!(!is_accumulative("controlpath"));
    assert!(!is_accumulative("controlpersist"));
}
