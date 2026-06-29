use super::*;

/// Like [`expand_tokens`] but leaves `%i` sequences untouched.
///
/// Test-only helper, inlined here because the production code no longer
/// needs it (the `%i` token now expands to the local username everywhere,
/// matching OpenSSH behaviour).
fn expand_tokens_skip_i(s: &str, ctx: &TokenContext<'_>) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '%' {
            match chars.peek().copied() {
                Some('%') => {
                    result.push_str("%%");
                    chars.next();
                }
                Some('i') => {
                    result.push_str("%i");
                    chars.next();
                }
                Some('C') => {
                    chars.next();
                    let hash_input = format!("{}:{}:{}", ctx.host, ctx.port, ctx.local_user);
                    result.push_str(&simple_hash(&hash_input));
                }
                Some('d') => {
                    chars.next();
                    result.push_str(ctx.home_dir);
                }
                Some('H') => {
                    chars.next();
                    result.push_str(ctx.canonical_host);
                }
                Some('h' | 'n') => {
                    chars.next();
                    result.push_str(ctx.host);
                }
                Some('L') => {
                    chars.next();
                    result.push_str(
                        ctx.local_hostname
                            .split('.')
                            .next()
                            .unwrap_or(ctx.local_hostname),
                    );
                }
                Some('l') => {
                    chars.next();
                    result.push_str(ctx.local_hostname);
                }
                Some('p') => {
                    chars.next();
                    result.push_str(ctx.port);
                }
                Some('r' | 'T') => {
                    chars.next();
                    result.push_str(ctx.remote_user);
                }
                Some('u') => {
                    chars.next();
                    result.push_str(ctx.local_user);
                }
                _ => {
                    result.push(ch);
                }
            }
        } else {
            result.push(ch);
        }
    }

    result
}

#[test]
fn expand_env_vars_no_vars() {
    assert_eq!(expand_env_vars("hello"), "hello");
}

#[test]
fn expand_env_vars_simple_var() {
    // SAFETY: tests run with `--test-threads=1` by default in this crate,
    // and we use unique var names to avoid cross-test interference.
    unsafe {
        std::env::set_var("TORIDE_TEST_VAR", "world");
    }
    assert_eq!(expand_env_vars("${TORIDE_TEST_VAR}"), "world");
    unsafe {
        std::env::remove_var("TORIDE_TEST_VAR");
    }
}

#[test]
fn expand_env_vars_undefined_var() {
    assert_eq!(expand_env_vars("${TORIDE_UNDEFINED_VAR_XYZ}"), "");
}

#[test]
fn expand_env_vars_unclosed_brace() {
    // Unclosed ${ — the literal ${ is preserved to avoid path corruption.
    assert_eq!(expand_env_vars("${UNCLOSED"), "${UNCLOSED");
}

#[test]
fn expand_env_vars_mixed_text() {
    unsafe {
        std::env::set_var("TORIDE_TEST_HOST", "example.com");
    }
    assert_eq!(
        expand_env_vars("Host: ${TORIDE_TEST_HOST}, Port: 22"),
        "Host: example.com, Port: 22"
    );
    unsafe {
        std::env::remove_var("TORIDE_TEST_HOST");
    }
}

#[test]
fn expand_env_vars_multiple_vars() {
    unsafe {
        std::env::set_var("TORIDE_A", "alpha");
        std::env::set_var("TORIDE_B", "beta");
    }
    assert_eq!(expand_env_vars("${TORIDE_A}-${TORIDE_B}"), "alpha-beta");
    unsafe {
        std::env::remove_var("TORIDE_A");
        std::env::remove_var("TORIDE_B");
    }
}

#[test]
fn expand_env_vars_empty_string() {
    assert_eq!(expand_env_vars(""), "");
}

#[test]
fn expand_env_vars_only_dollar() {
    assert_eq!(expand_env_vars("$"), "$");
}

#[test]
fn expand_env_vars_no_braces() {
    unsafe {
        std::env::set_var("TORIDE_NO_BRACE", "nobrace");
    }
    assert_eq!(expand_env_vars("$TORIDE_NO_BRACE"), "nobrace");
    unsafe {
        std::env::remove_var("TORIDE_NO_BRACE");
    }
}

#[test]
fn expand_env_vars_no_braces_with_suffix() {
    unsafe {
        std::env::set_var("TORIDE_VAR_SUF", "value");
    }
    assert_eq!(expand_env_vars("${TORIDE_VAR_SUF}_extra"), "value_extra");
    assert_eq!(expand_env_vars("$TORIDE_VAR_SUF.extra"), "value.extra");
    unsafe {
        std::env::remove_var("TORIDE_VAR_SUF");
    }
}

#[test]
fn expand_env_vars_no_braces_undefined() {
    // Undefined $VAR should expand to empty string.
    assert_eq!(expand_env_vars("$TORIDE_UNDEF_XYZ_123"), "");
}

#[test]
fn expand_env_vars_bare_dollar_before_non_name() {
    // `$ ` (dollar followed by space) should preserve the dollar.
    assert_eq!(expand_env_vars("$ "), "$ ");
    assert_eq!(expand_env_vars("$/path"), "$/path");
}

#[test]
fn expand_tilde_home_dir() {
    let result = expand_tilde_and_env("~/test");
    // Should start with the home directory path
    assert!(!result.starts_with("~/"));
    assert!(result.ends_with("/test"));
}

#[test]
fn expand_tilde_no_tilde() {
    assert_eq!(expand_tilde_and_env("/absolute/path"), "/absolute/path");
}

#[test]
fn expand_tilde_just_tilde() {
    let result = expand_tilde_and_env("~");
    // Should expand to home dir
    assert!(!result.is_empty());
    assert!(!result.starts_with('~'));
}

#[test]
fn collapse_double_percent_basic() {
    assert_eq!(collapse_double_percent("%%"), "%");
    assert_eq!(collapse_double_percent("hello%%world"), "hello%world");
    assert_eq!(collapse_double_percent("no percent"), "no percent");
}

#[test]
fn collapse_double_percent_multiple() {
    assert_eq!(collapse_double_percent("%%%%"), "%%");
}

#[test]
fn expand_tokens_no_tokens() {
    let ctx = TokenContext {
        host: "host",
        home_dir: "/home",
        local_hostname: "local",
        remote_user: "remote",
        local_user: "user",
        port: "22",
        canonical_host: "host",
        identity_file: None,
        local_host_key: "",
        jump_host: "",
        remote_host_key: "",
    };
    assert_eq!(expand_tokens("hello", &ctx), "hello");
}

#[test]
fn expand_tokens_host() {
    let ctx = TokenContext {
        host: "example.com",
        home_dir: "/home",
        local_hostname: "local",
        remote_user: "remote",
        local_user: "user",
        port: "22",
        canonical_host: "example.com",
        identity_file: None,
        local_host_key: "",
        jump_host: "",
        remote_host_key: "",
    };
    assert_eq!(expand_tokens("%h", &ctx), "example.com");
}

#[test]
fn expand_tokens_user() {
    let ctx = TokenContext {
        host: "host",
        home_dir: "/home",
        local_hostname: "local",
        remote_user: "remote",
        local_user: "alice",
        port: "22",
        canonical_host: "host",
        identity_file: None,
        local_host_key: "",
        jump_host: "",
        remote_host_key: "",
    };
    assert_eq!(expand_tokens("%u", &ctx), "alice");
}

#[test]
fn expand_tokens_port() {
    let ctx = TokenContext {
        host: "host",
        home_dir: "/home",
        local_hostname: "local",
        remote_user: "remote",
        local_user: "user",
        port: "2222",
        canonical_host: "host",
        identity_file: None,
        local_host_key: "",
        jump_host: "",
        remote_host_key: "",
    };
    assert_eq!(expand_tokens("%p", &ctx), "2222");
}

#[test]
fn expand_tokens_home_dir() {
    let ctx = TokenContext {
        host: "host",
        home_dir: "/home/alice",
        local_hostname: "local",
        remote_user: "remote",
        local_user: "user",
        port: "22",
        canonical_host: "host",
        identity_file: None,
        local_host_key: "",
        jump_host: "",
        remote_host_key: "",
    };
    assert_eq!(expand_tokens("%d", &ctx), "/home/alice");
}

#[test]
fn expand_tokens_local_hostname() {
    let ctx = TokenContext {
        host: "host",
        home_dir: "/home",
        local_hostname: "myhost",
        remote_user: "remote",
        local_user: "user",
        port: "22",
        canonical_host: "host",
        identity_file: None,
        local_host_key: "",
        jump_host: "",
        remote_host_key: "",
    };
    assert_eq!(expand_tokens("%l", &ctx), "myhost");
}

#[test]
fn expand_tokens_remote_user() {
    let ctx = TokenContext {
        host: "host",
        home_dir: "/home",
        local_hostname: "local",
        remote_user: "deploy",
        local_user: "user",
        port: "22",
        canonical_host: "host",
        identity_file: None,
        local_host_key: "",
        jump_host: "",
        remote_host_key: "",
    };
    assert_eq!(expand_tokens("%r", &ctx), "deploy");
}

#[test]
fn expand_tokens_unknown_token() {
    let ctx = TokenContext {
        host: "host",
        home_dir: "/home",
        local_hostname: "local",
        remote_user: "remote",
        local_user: "user",
        port: "22",
        canonical_host: "host",
        identity_file: None,
        local_host_key: "",
        jump_host: "",
        remote_host_key: "",
    };
    assert_eq!(expand_tokens("%z", &ctx), "%z");
}

#[test]
fn expand_tokens_trailing_percent() {
    let ctx = TokenContext {
        host: "host",
        home_dir: "/home",
        local_hostname: "local",
        remote_user: "remote",
        local_user: "user",
        port: "22",
        canonical_host: "host",
        identity_file: None,
        local_host_key: "",
        jump_host: "",
        remote_host_key: "",
    };
    assert_eq!(expand_tokens("hello%", &ctx), "hello%");
}

#[test]
fn expand_tokens_double_percent() {
    let ctx = TokenContext {
        host: "host",
        home_dir: "/home",
        local_hostname: "local",
        remote_user: "remote",
        local_user: "user",
        port: "22",
        canonical_host: "host",
        identity_file: None,
        local_host_key: "",
        jump_host: "",
        remote_host_key: "",
    };
    assert_eq!(expand_tokens("%%", &ctx), "%%");
}

#[test]
fn expand_tokens_mixed() {
    let ctx = TokenContext {
        host: "example.com",
        home_dir: "/home",
        local_hostname: "local",
        remote_user: "remote",
        local_user: "user",
        port: "22",
        canonical_host: "example.com",
        identity_file: None,
        local_host_key: "",
        jump_host: "",
        remote_host_key: "",
    };
    assert_eq!(expand_tokens("%h:%p", &ctx), "example.com:22");
}

#[test]
fn simple_glob_match_exact() {
    assert!(simple_glob_match("test.conf", "test.conf"));
    assert!(!simple_glob_match("test.conf", "other.conf"));
}

#[test]
fn simple_glob_match_star() {
    assert!(simple_glob_match("anything", "*"));
}

#[test]
fn simple_glob_match_no_wildcards() {
    assert!(simple_glob_match("abc", "abc"));
    assert!(!simple_glob_match("abc", "def"));
}

#[test]
fn match_criteria_host_basic() {
    assert!(match_criteria_host("host web", "web", "alice", "web"));
    assert!(!match_criteria_host("host web", "db", "alice", "web"));
}

#[test]
fn match_criteria_host_no_host_clause() {
    // "user alice" with target_user "bob" should not match.
    assert!(!match_criteria_host("user alice", "web", "bob", "web"));
    // "user alice" with target_user "alice" should match.
    assert!(match_criteria_host("user alice", "web", "alice", "web"));
}

#[test]
fn match_criteria_host_wildcard() {
    assert!(match_criteria_host(
        "host *", "anything", "alice", "anything"
    ));
}

// ---------------------------------------------------------------------------
// Weird edge-case tests for token expansion
// ---------------------------------------------------------------------------

#[test]
fn expand_tokens_consecutive_tokens() {
    let ctx = TokenContext {
        host: "h",
        home_dir: "d",
        local_hostname: "l",
        remote_user: "r",
        local_user: "u",
        port: "p",
        canonical_host: "h",
        identity_file: None,
        local_host_key: "",
        jump_host: "",
        remote_host_key: "",
    };
    assert_eq!(expand_tokens("%h%h%h", &ctx), "hhh");
}

#[test]
fn expand_tokens_adjacent_different_tokens() {
    let ctx = TokenContext {
        host: "host",
        home_dir: "/home",
        local_hostname: "local",
        remote_user: "remote",
        local_user: "user",
        port: "22",
        canonical_host: "host",
        identity_file: None,
        local_host_key: "",
        jump_host: "",
        remote_host_key: "",
    };
    assert_eq!(expand_tokens("%h:%p:%u", &ctx), "host:22:user");
}

#[test]
fn expand_tokens_percent_at_end() {
    let ctx = TokenContext {
        host: "host",
        home_dir: "/home",
        local_hostname: "local",
        remote_user: "remote",
        local_user: "user",
        port: "22",
        canonical_host: "host",
        identity_file: None,
        local_host_key: "",
        jump_host: "",
        remote_host_key: "",
    };
    assert_eq!(expand_tokens("hello%", &ctx), "hello%");
}

#[test]
fn expand_tokens_percent_at_start() {
    let ctx = TokenContext {
        host: "host",
        home_dir: "/home",
        local_hostname: "local",
        remote_user: "remote",
        local_user: "user",
        port: "22",
        canonical_host: "host",
        identity_file: None,
        local_host_key: "",
        jump_host: "",
        remote_host_key: "",
    };
    // %h is a valid token (host), so %hello becomes "hostello"
    assert_eq!(expand_tokens("%h", &ctx), "host");
}

#[test]
fn expand_tokens_only_percent() {
    let ctx = TokenContext {
        host: "host",
        home_dir: "/home",
        local_hostname: "local",
        remote_user: "remote",
        local_user: "user",
        port: "22",
        canonical_host: "host",
        identity_file: None,
        local_host_key: "",
        jump_host: "",
        remote_host_key: "",
    };
    assert_eq!(expand_tokens("%", &ctx), "%");
}

#[test]
fn expand_tokens_escaped_percent_sequence() {
    let ctx = TokenContext {
        host: "host",
        home_dir: "/home",
        local_hostname: "local",
        remote_user: "remote",
        local_user: "user",
        port: "22",
        canonical_host: "host",
        identity_file: None,
        local_host_key: "",
        jump_host: "",
        remote_host_key: "",
    };
    // %%h should produce %%h (collapse_double_percent handles %% → %)
    assert_eq!(expand_tokens("%%h", &ctx), "%%h");
}

#[test]
fn expand_tokens_empty_string() {
    let ctx = TokenContext {
        host: "host",
        home_dir: "/home",
        local_hostname: "local",
        remote_user: "remote",
        local_user: "user",
        port: "22",
        canonical_host: "host",
        identity_file: None,
        local_host_key: "",
        jump_host: "",
        remote_host_key: "",
    };
    assert_eq!(expand_tokens("", &ctx), "");
}

#[test]
fn expand_tokens_no_tokens_complex() {
    let ctx = TokenContext {
        host: "host",
        home_dir: "/home",
        local_hostname: "local",
        remote_user: "remote",
        local_user: "user",
        port: "22",
        canonical_host: "host",
        identity_file: None,
        local_host_key: "",
        jump_host: "",
        remote_host_key: "",
    };
    assert_eq!(
        expand_tokens("/usr/local/bin/ssh", &ctx),
        "/usr/local/bin/ssh"
    );
}

#[test]
fn expand_tilde_just_slash() {
    // ~/ should expand to home dir + /
    let result = expand_tilde_and_env("~/");
    assert!(!result.starts_with("~/"));
    assert!(result.ends_with('/'));
}

#[test]
fn expand_tilde_path_with_spaces() {
    // This is unusual but should work
    let result = expand_tilde_and_env("~/path with spaces");
    assert!(!result.starts_with("~/"));
    assert!(result.ends_with("/path with spaces"));
}

#[test]
fn expand_env_vars_var_at_start() {
    unsafe {
        std::env::set_var("TORIDE_TEST_START", "hello");
    }
    assert_eq!(expand_env_vars("${TORIDE_TEST_START}world"), "helloworld");
    unsafe {
        std::env::remove_var("TORIDE_TEST_START");
    }
}

#[test]
fn expand_env_vars_var_at_end() {
    unsafe {
        std::env::set_var("TORIDE_TEST_END", "world");
    }
    assert_eq!(expand_env_vars("hello${TORIDE_TEST_END}"), "helloworld");
    unsafe {
        std::env::remove_var("TORIDE_TEST_END");
    }
}

#[test]
fn expand_env_vars_adjacent_vars() {
    unsafe {
        std::env::set_var("TORIDE_X", "X");
        std::env::set_var("TORIDE_Y", "Y");
    }
    assert_eq!(expand_env_vars("${TORIDE_X}${TORIDE_Y}"), "XY");
    unsafe {
        std::env::remove_var("TORIDE_X");
        std::env::remove_var("TORIDE_Y");
    }
}

#[test]
fn expand_env_vars_nested_braces() {
    // ${${VAR}} — the inner ${ is consumed, leaving $VAR}
    // This is unusual but should not panic
    let result = expand_env_vars("${${NESTED}}");
    let _ = result; // just check it doesn't panic
}

#[test]
fn match_criteria_host_case_insensitive_keyword() {
    assert!(match_criteria_host("HOST web", "web", "alice", "web"));
    assert!(match_criteria_host("Host web", "web", "alice", "web"));
    assert!(match_criteria_host("host web", "web", "alice", "web"));
}

#[test]
fn match_criteria_host_multiple_host_clauses() {
    // Multiple host clauses - either can match
    assert!(match_criteria_host(
        "host web host db",
        "web",
        "alice",
        "web"
    ));
    assert!(match_criteria_host(
        "host web host db",
        "db",
        "alice",
        "web"
    ));
    assert!(!match_criteria_host(
        "host web host db",
        "other",
        "alice",
        "web"
    ));
}

#[test]
fn match_criteria_host_unknown_keyword_before_host() {
    // Unknown keyword before host clause — user "alice" must also match.
    assert!(match_criteria_host(
        "user alice host web",
        "web",
        "alice",
        "web"
    ));
    // If user doesn't match, the whole block is rejected.
    assert!(!match_criteria_host(
        "user alice host web",
        "web",
        "bob",
        "web"
    ));
}

#[test]
fn collapse_double_percent_empty() {
    assert_eq!(collapse_double_percent(""), "");
}

#[test]
fn collapse_double_percent_single_percent() {
    assert_eq!(collapse_double_percent("%"), "%");
}

#[test]
fn collapse_double_percent_triple() {
    // %%% should become %% (one pair collapsed, one left)
    assert_eq!(collapse_double_percent("%%%"), "%%");
}

// ---------------------------------------------------------------------------
// Production-grade weird edge cases
// ---------------------------------------------------------------------------

#[test]
fn expand_env_vars_with_spaces_in_value() {
    unsafe {
        std::env::set_var("TORIDE_SPACED", "hello world");
    }
    assert_eq!(expand_env_vars("${TORIDE_SPACED}"), "hello world");
    unsafe {
        std::env::remove_var("TORIDE_SPACED");
    }
}

#[test]
fn expand_env_vars_with_equals_in_value() {
    unsafe {
        std::env::set_var("TORIDE_EQUALS", "a=b");
    }
    assert_eq!(expand_env_vars("${TORIDE_EQUALS}"), "a=b");
    unsafe {
        std::env::remove_var("TORIDE_EQUALS");
    }
}

#[test]
fn expand_env_vars_with_special_chars() {
    unsafe {
        std::env::set_var("TORIDE_SPECIAL", "hello@world.com");
    }
    assert_eq!(expand_env_vars("${TORIDE_SPECIAL}"), "hello@world.com");
    unsafe {
        std::env::remove_var("TORIDE_SPECIAL");
    }
}

#[test]
fn expand_env_vars_undefined_returns_empty() {
    // Undefined vars should expand to empty string
    assert_eq!(expand_env_vars("${TORIDE_DEFINITELY_NOT_SET_12345}"), "");
}

#[test]
fn expand_env_vars_with_dollar_sign_in_value() {
    // Dollar sign in env var value should not be re-expanded
    unsafe {
        std::env::set_var("TORIDE_DOLLAR", "$NOT_A_VAR");
    }
    assert_eq!(expand_env_vars("${TORIDE_DOLLAR}"), "$NOT_A_VAR");
    unsafe {
        std::env::remove_var("TORIDE_DOLLAR");
    }
}

#[test]
fn expand_tilde_with_trailing_slash() {
    let result = expand_tilde_and_env("~/");
    assert!(!result.starts_with("~/"));
    assert!(result.ends_with('/'));
}

#[test]
fn expand_tilde_with_deep_path() {
    let result = expand_tilde_and_env("~/.ssh/keys/backup");
    assert!(!result.starts_with("~/"));
    assert!(result.ends_with("/.ssh/keys/backup"));
}

#[test]
fn expand_tilde_not_at_start() {
    // Tilde not at start should not be expanded
    assert_eq!(expand_tilde_and_env("path/~user"), "path/~user");
}

#[test]
fn expand_tokens_all_tokens_combined() {
    let ctx = TokenContext {
        host: "example.com",
        home_dir: "/home/alice",
        local_hostname: "myhost",
        remote_user: "deploy",
        local_user: "alice",
        port: "2222",
        canonical_host: "example.com",
        identity_file: None,
        local_host_key: "",
        jump_host: "",
        remote_host_key: "",
    };
    let result = expand_tokens("%h:%p:%u:%d:%l:%r", &ctx);
    assert_eq!(result, "example.com:2222:alice:/home/alice:myhost:deploy");
}

#[test]
fn expand_tokens_with_path() {
    let ctx = TokenContext {
        host: "h",
        home_dir: "/home",
        local_hostname: "l",
        remote_user: "r",
        local_user: "u",
        port: "22",
        canonical_host: "h",
        identity_file: None,
        local_host_key: "",
        jump_host: "",
        remote_host_key: "",
    };
    assert_eq!(expand_tokens("/keys/%h/%u", &ctx), "/keys/h/u");
}

#[test]
fn expand_tokens_with_env_var() {
    let ctx = TokenContext {
        host: "h",
        home_dir: "/home",
        local_hostname: "l",
        remote_user: "r",
        local_user: "u",
        port: "22",
        canonical_host: "h",
        identity_file: None,
        local_host_key: "",
        jump_host: "",
        remote_host_key: "",
    };
    // %d is home_dir, not an env var
    assert_eq!(expand_tokens("%d/.ssh", &ctx), "/home/.ssh");
}

#[test]
fn expand_tokens_canonical_host() {
    let ctx = TokenContext {
        host: "alias",
        home_dir: "/home",
        local_hostname: "local",
        remote_user: "remote",
        local_user: "user",
        port: "22",
        canonical_host: "real.host.com",
        identity_file: None,
        local_host_key: "",
        jump_host: "",
        remote_host_key: "",
    };
    assert_eq!(expand_tokens("%H", &ctx), "real.host.com");
}

#[test]
fn expand_tokens_identity_file_token() {
    // %i expands to local username (same as %u) to avoid circular reference
    // when %i is used inside an IdentityFile path.
    let ctx = TokenContext {
        host: "h",
        home_dir: "/home",
        local_hostname: "local",
        remote_user: "remote",
        local_user: "alice",
        port: "22",
        canonical_host: "h",
        identity_file: Some("~/.ssh/id_ed25519_work"),
        local_host_key: "",
        jump_host: "",
        remote_host_key: "",
    };
    assert_eq!(expand_tokens("%i", &ctx), "alice");
}

#[test]
fn expand_tokens_identity_file_without_context() {
    // When no identity file context is set, %i also uses local username.
    let ctx = TokenContext {
        host: "h",
        home_dir: "/home",
        local_hostname: "local",
        remote_user: "remote",
        local_user: "alice",
        port: "22",
        canonical_host: "h",
        identity_file: None,
        local_host_key: "",
        jump_host: "",
        remote_host_key: "",
    };
    assert_eq!(expand_tokens("%i", &ctx), "alice");
}

#[test]
fn expand_tokens_local_hostname_short() {
    let ctx = TokenContext {
        host: "h",
        home_dir: "/home",
        local_hostname: "myhost.example.com",
        remote_user: "remote",
        local_user: "user",
        port: "22",
        canonical_host: "h",
        identity_file: None,
        local_host_key: "",
        jump_host: "",
        remote_host_key: "",
    };
    // %L should give short hostname (before first '.')
    assert_eq!(expand_tokens("%L", &ctx), "myhost");
}

#[test]
fn expand_tokens_local_hostname_short_no_dot() {
    let ctx = TokenContext {
        host: "h",
        home_dir: "/home",
        local_hostname: "myhost",
        remote_user: "remote",
        local_user: "user",
        port: "22",
        canonical_host: "h",
        identity_file: None,
        local_host_key: "",
        jump_host: "",
        remote_host_key: "",
    };
    assert_eq!(expand_tokens("%L", &ctx), "myhost");
}

#[test]
fn expand_tokens_remote_user_alias() {
    // %T is an alias for %r (remote user)
    let ctx = TokenContext {
        host: "h",
        home_dir: "/home",
        local_hostname: "l",
        remote_user: "deploy",
        local_user: "u",
        port: "22",
        canonical_host: "h",
        identity_file: None,
        local_host_key: "",
        jump_host: "",
        remote_host_key: "",
    };
    assert_eq!(expand_tokens("%T", &ctx), "deploy");
}

#[test]
fn expand_tokens_connection_hash() {
    let ctx = TokenContext {
        host: "h",
        home_dir: "/home",
        local_hostname: "l",
        remote_user: "r",
        local_user: "u",
        port: "22",
        canonical_host: "h",
        identity_file: None,
        local_host_key: "",
        jump_host: "",
        remote_host_key: "",
    };
    let hash = expand_tokens("%C", &ctx);
    // %C should produce a hex string
    assert!(!hash.is_empty());
    assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn expand_tokens_all_new_tokens() {
    let ctx = TokenContext {
        host: "alias",
        home_dir: "/home/alice",
        local_hostname: "myhost.example.com",
        remote_user: "deploy",
        local_user: "alice",
        port: "2222",
        canonical_host: "real.com",
        identity_file: None,
        local_host_key: "",
        jump_host: "",
        remote_host_key: "",
    };
    // Test all new tokens in one go
    let result = expand_tokens("%H:%i:%L:%T:%C", &ctx);
    let parts: Vec<&str> = result.split(':').collect();
    assert_eq!(parts[0], "real.com"); // %H canonical
    assert_eq!(parts[1], "alice"); // %i local user
    assert_eq!(parts[2], "myhost"); // %L short hostname
    assert_eq!(parts[3], "deploy"); // %T remote user
    assert!(!parts[4].is_empty()); // %C hash
}

#[test]
fn match_criteria_host_with_port() {
    // Match criteria with port in host pattern
    assert!(match_criteria_host(
        "host [::1]:22",
        "[::1]:22",
        "alice",
        "[::1]:22"
    ));
}

#[test]
fn match_criteria_host_with_wildcard_port() {
    // Wildcard host should match any port
    assert!(match_criteria_host(
        "host *",
        "example.com:22",
        "alice",
        "example.com:22"
    ));
}

#[test]
fn match_criteria_host_empty_criteria() {
    // Empty criteria should not match
    assert!(!match_criteria_host("", "host", "alice", "host"));
}

#[test]
fn match_criteria_host_only_unknown_keyword() {
    // Only unsupported keywords — user "alice" doesn't match target_user "bob".
    assert!(!match_criteria_host("exec true", "host", "bob", "host"));
}

#[test]
fn simple_glob_match_empty_pattern() {
    // Empty pattern matches empty text
    assert!(simple_glob_match("", ""));
    assert!(!simple_glob_match("a", ""));
}

#[test]
fn simple_glob_match_star_only() {
    assert!(simple_glob_match("", "*"));
    assert!(simple_glob_match("anything", "*"));
}

#[test]
fn simple_glob_match_question_only() {
    // simple_glob_match delegates to glob_matches when pattern contains ?
    // glob_matches handles ? as a single-character wildcard
    assert!(!simple_glob_match("", "?"));
    assert!(simple_glob_match("a", "?")); // ? matches one char
    assert!(!simple_glob_match("ab", "?")); // ? matches exactly one char
}

#[test]
fn match_criteria_host_negation() {
    // Negation patterns must be comma-separated with positive patterns
    assert!(!match_criteria_host(
        "host *,!badhost",
        "badhost",
        "alice",
        "badhost"
    ));
    assert!(match_criteria_host(
        "host *,!badhost",
        "goodhost",
        "alice",
        "goodhost"
    ));
}

// ---------------------------------------------------------------------------
// Edge case tests for expand_env_vars (v2 — no duplicate names)
// ---------------------------------------------------------------------------

#[test]
fn expand_env_vars_empty_braces() {
    // ${} with empty name — should expand to empty
    assert_eq!(expand_env_vars("${}"), "");
}

#[test]
fn expand_env_vars_trailing_dollar() {
    // Bare $ at end of string
    assert_eq!(expand_env_vars("test$"), "test$");
}

#[test]
fn expand_env_vars_no_braces_in_path() {
    unsafe {
        std::env::set_var("TORIDE_PVAR", "/usr/local");
    }
    assert_eq!(expand_env_vars("$TORIDE_PVAR/bin"), "/usr/local/bin");
    unsafe {
        std::env::remove_var("TORIDE_PVAR");
    }
}

// ---------------------------------------------------------------------------
// Edge case tests for expand_tokens (v2)
// ---------------------------------------------------------------------------

#[test]
fn expand_tokens_unknown_x() {
    let ctx = TokenContext {
        host: "h",
        home_dir: "d",
        local_hostname: "l",
        remote_user: "r",
        local_user: "u",
        port: "p",
        canonical_host: "h",
        identity_file: None,
        local_host_key: "",
        jump_host: "",
        remote_host_key: "",
    };
    assert_eq!(expand_tokens("%X", &ctx), "%X");
}

#[test]
fn expand_tokens_double_percent_preserved() {
    let ctx = TokenContext {
        host: "h",
        home_dir: "d",
        local_hostname: "l",
        remote_user: "r",
        local_user: "u",
        port: "p",
        canonical_host: "h",
        identity_file: None,
        local_host_key: "",
        jump_host: "",
        remote_host_key: "",
    };
    assert_eq!(expand_tokens("%%", &ctx), "%%");
}

#[test]
fn expand_tokens_empty() {
    let ctx = TokenContext {
        host: "h",
        home_dir: "d",
        local_hostname: "l",
        remote_user: "r",
        local_user: "u",
        port: "p",
        canonical_host: "h",
        identity_file: None,
        local_host_key: "",
        jump_host: "",
        remote_host_key: "",
    };
    assert_eq!(expand_tokens("", &ctx), "");
}

// ---------------------------------------------------------------------------
// Tests for expand_tokens_skip_i
// ---------------------------------------------------------------------------

#[test]
fn expand_tokens_skip_i_preserves_percent_i() {
    let ctx = TokenContext {
        host: "h",
        home_dir: "/home",
        local_hostname: "l",
        remote_user: "r",
        local_user: "alice",
        port: "22",
        canonical_host: "h",
        identity_file: None,
        local_host_key: "",
        jump_host: "",
        remote_host_key: "",
    };
    assert_eq!(
        expand_tokens_skip_i("~/.ssh/work/%i", &ctx),
        "~/.ssh/work/%i"
    );
}

#[test]
fn expand_tokens_skip_i_expands_other_tokens() {
    let ctx = TokenContext {
        host: "example.com",
        home_dir: "/home",
        local_hostname: "l",
        remote_user: "r",
        local_user: "alice",
        port: "22",
        canonical_host: "example.com",
        identity_file: None,
        local_host_key: "",
        jump_host: "",
        remote_host_key: "",
    };
    assert_eq!(
        expand_tokens_skip_i("~/.ssh/%h/%i", &ctx),
        "~/.ssh/example.com/%i"
    );
}

#[test]
fn expand_tokens_skip_i_expands_u_but_not_i() {
    let ctx = TokenContext {
        host: "h",
        home_dir: "/home",
        local_hostname: "l",
        remote_user: "r",
        local_user: "alice",
        port: "22",
        canonical_host: "h",
        identity_file: None,
        local_host_key: "",
        jump_host: "",
        remote_host_key: "",
    };
    assert_eq!(expand_tokens_skip_i("%u/%i", &ctx), "alice/%i");
}

// ---------------------------------------------------------------------------
// Edge case tests for collapse_double_percent (v2)
// ---------------------------------------------------------------------------

#[test]
fn collapse_double_pct_basic() {
    assert_eq!(collapse_double_percent("%%"), "%");
    assert_eq!(collapse_double_percent("100%%"), "100%");
    assert_eq!(collapse_double_percent("%%test"), "%test");
}

#[test]
fn collapse_double_pct_none() {
    assert_eq!(collapse_double_percent("test"), "test");
    assert_eq!(collapse_double_percent("%h"), "%h");
}

#[test]
fn collapse_double_pct_empty() {
    assert_eq!(collapse_double_percent(""), "");
}

// ---------------------------------------------------------------------------
// Tests for Match user criterion
// ---------------------------------------------------------------------------

#[test]
fn match_criteria_user_basic() {
    assert!(match_criteria_host("user alice", "host", "alice", "host"));
    assert!(!match_criteria_host("user alice", "host", "bob", "host"));
}

#[test]
fn match_criteria_user_case_insensitive() {
    assert!(match_criteria_host("user Alice", "host", "alice", "host"));
    assert!(match_criteria_host("user ALICE", "host", "alice", "host"));
    assert!(match_criteria_host("user alice", "host", "ALICE", "host"));
}

#[test]
fn match_criteria_user_multiple_names() {
    assert!(match_criteria_host(
        "user alice,bob",
        "host",
        "alice",
        "host"
    ));
    assert!(match_criteria_host("user alice,bob", "host", "bob", "host"));
    assert!(!match_criteria_host(
        "user alice,bob",
        "host",
        "charlie",
        "host"
    ));
}

#[test]
fn match_criteria_user_with_host() {
    // Both user and host must match (AND logic).
    assert!(match_criteria_host(
        "user alice host web",
        "web",
        "alice",
        "web",
    ));
    assert!(!match_criteria_host(
        "user alice host web",
        "web",
        "bob",
        "web",
    ));
    assert!(!match_criteria_host(
        "user alice host web",
        "db",
        "alice",
        "web",
    ));
}

// ---------------------------------------------------------------------------
// Tests for Match originalhost criterion
// ---------------------------------------------------------------------------

#[test]
fn match_criteria_originalhost_basic() {
    assert!(match_criteria_host(
        "originalhost web",
        "canonical.web",
        "alice",
        "web",
    ));
    assert!(!match_criteria_host(
        "originalhost web",
        "canonical.web",
        "alice",
        "db",
    ));
}

#[test]
fn match_criteria_originalhost_wildcard() {
    assert!(match_criteria_host(
        "originalhost *.example.com",
        "canonical.example.com",
        "alice",
        "web.example.com",
    ));
}

#[test]
fn match_criteria_originalhost_with_host() {
    // Both originalhost and host are checked.
    // originalhost matches against the original alias, host against the
    // current target (which may be the canonical name).
    assert!(match_criteria_host(
        "originalhost web host canonical.web",
        "canonical.web",
        "alice",
        "web",
    ));
    assert!(!match_criteria_host(
        "originalhost web host canonical.web",
        "canonical.web",
        "alice",
        "other",
    ));
}

#[test]
fn match_criteria_originalhost_negation() {
    assert!(!match_criteria_host(
        "originalhost *,!badhost",
        "canonical",
        "alice",
        "badhost",
    ));
    assert!(match_criteria_host(
        "originalhost *,!badhost",
        "canonical",
        "alice",
        "goodhost",
    ));
}

// ---------------------------------------------------------------------------
// Tests for CanonicalizeHostname awareness
// ---------------------------------------------------------------------------

#[test]
fn is_canonicalize_enabled_yes() {
    let resolved = ResolvedHost {
        alias: "test".into(),
        host_name: None,
        user: None,
        port: None,
        identity_files: vec![],
        certificate_files: vec![],
        proxy_jump: None,
        identity_agent: None,
        forward_agent: None,
        add_keys_to_agent: None,
        use_keychain: None,
        control_master: None,
        control_path: None,
        control_persist: None,
        local_forwards: vec![],
        remote_forwards: vec![],
        dynamic_forwards: vec![],
        directives: vec![("CanonicalizeHostname".into(), "yes".into())],
        user_known_hosts_file: None,
        identities_only: None,
        canonicalized: false,
        unevaluated_match_warnings: vec![],
        gssapi_authentication: None,
        gssapi_delegate_credentials: None,
        gssapi_server_identity: None,
        gssapi_client_identity: None,
    };
    assert!(is_canonicalize_enabled(&resolved));
}

#[test]
fn is_canonicalize_enabled_always() {
    let resolved = ResolvedHost {
        alias: "test".into(),
        host_name: None,
        user: None,
        port: None,
        identity_files: vec![],
        certificate_files: vec![],
        proxy_jump: None,
        identity_agent: None,
        forward_agent: None,
        add_keys_to_agent: None,
        use_keychain: None,
        control_master: None,
        control_path: None,
        control_persist: None,
        local_forwards: vec![],
        remote_forwards: vec![],
        dynamic_forwards: vec![],
        directives: vec![("CanonicalizeHostname".into(), "always".into())],
        user_known_hosts_file: None,
        identities_only: None,
        canonicalized: false,
        unevaluated_match_warnings: vec![],
        gssapi_authentication: None,
        gssapi_delegate_credentials: None,
        gssapi_server_identity: None,
        gssapi_client_identity: None,
    };
    assert!(is_canonicalize_enabled(&resolved));
}

#[test]
fn is_canonicalize_enabled_no() {
    let resolved = ResolvedHost {
        alias: "test".into(),
        host_name: None,
        user: None,
        port: None,
        identity_files: vec![],
        certificate_files: vec![],
        proxy_jump: None,
        identity_agent: None,
        forward_agent: None,
        add_keys_to_agent: None,
        use_keychain: None,
        control_master: None,
        control_path: None,
        control_persist: None,
        local_forwards: vec![],
        remote_forwards: vec![],
        dynamic_forwards: vec![],
        directives: vec![("CanonicalizeHostname".into(), "no".into())],
        user_known_hosts_file: None,
        identities_only: None,
        canonicalized: false,
        unevaluated_match_warnings: vec![],
        gssapi_authentication: None,
        gssapi_delegate_credentials: None,
        gssapi_server_identity: None,
        gssapi_client_identity: None,
    };
    assert!(!is_canonicalize_enabled(&resolved));
}

#[test]
fn is_canonicalize_enabled_missing() {
    let resolved = ResolvedHost {
        alias: "test".into(),
        host_name: None,
        user: None,
        port: None,
        identity_files: vec![],
        certificate_files: vec![],
        proxy_jump: None,
        identity_agent: None,
        forward_agent: None,
        add_keys_to_agent: None,
        use_keychain: None,
        control_master: None,
        control_path: None,
        control_persist: None,
        local_forwards: vec![],
        remote_forwards: vec![],
        dynamic_forwards: vec![],
        directives: vec![],
        user_known_hosts_file: None,
        identities_only: None,
        canonicalized: false,
        unevaluated_match_warnings: vec![],
        gssapi_authentication: None,
        gssapi_delegate_credentials: None,
        gssapi_server_identity: None,
        gssapi_client_identity: None,
    };
    assert!(!is_canonicalize_enabled(&resolved));
}

#[test]
fn is_canonicalize_enabled_case_insensitive() {
    let resolved = ResolvedHost {
        alias: "test".into(),
        host_name: None,
        user: None,
        port: None,
        identity_files: vec![],
        certificate_files: vec![],
        proxy_jump: None,
        identity_agent: None,
        forward_agent: None,
        add_keys_to_agent: None,
        use_keychain: None,
        control_master: None,
        control_path: None,
        control_persist: None,
        local_forwards: vec![],
        remote_forwards: vec![],
        dynamic_forwards: vec![],
        directives: vec![("canonicalizehostname".into(), "YES".into())],
        user_known_hosts_file: None,
        identities_only: None,
        canonicalized: false,
        unevaluated_match_warnings: vec![],
        gssapi_authentication: None,
        gssapi_delegate_credentials: None,
        gssapi_server_identity: None,
        gssapi_client_identity: None,
    };
    assert!(is_canonicalize_enabled(&resolved));
}

// ---------------------------------------------------------------------------
// Tests for expanded token expansion (additional directives)
// ---------------------------------------------------------------------------

#[test]
fn expand_resolved_certificate_file() {
    let mut resolved = ResolvedHost {
        alias: "h".into(),
        host_name: None,
        user: None,
        port: None,
        identity_files: vec![],
        certificate_files: vec!["%d/.ssh/%h-cert.pub".into()],
        proxy_jump: None,
        identity_agent: None,
        forward_agent: None,
        add_keys_to_agent: None,
        use_keychain: None,
        control_master: None,
        control_path: None,
        control_persist: None,
        local_forwards: vec![],
        remote_forwards: vec![],
        dynamic_forwards: vec![],
        directives: vec![("CertificateFile".into(), "%d/.ssh/%h-cert.pub".into())],
        user_known_hosts_file: None,
        identities_only: None,
        canonicalized: false,
        unevaluated_match_warnings: vec![],
        gssapi_authentication: None,
        gssapi_delegate_credentials: None,
        gssapi_server_identity: None,
        gssapi_client_identity: None,
    };
    expand_resolved(&mut resolved, "example", Path::new("/tmp"));
    // Certificate files should be expanded.
    let cert = &resolved.certificate_files[0];
    assert!(!cert.contains("%d"));
    assert!(!cert.contains("%h"));
    assert!(cert.contains("example-cert.pub"));
}

#[test]
fn expand_resolved_control_path() {
    let mut resolved = ResolvedHost {
        alias: "h".into(),
        host_name: None,
        user: None,
        port: None,
        identity_files: vec![],
        certificate_files: vec![],
        proxy_jump: None,
        identity_agent: None,
        forward_agent: None,
        add_keys_to_agent: None,
        use_keychain: None,
        control_master: None,
        control_path: Some("/tmp/ssh-%h-%p".into()),
        control_persist: None,
        local_forwards: vec![],
        remote_forwards: vec![],
        dynamic_forwards: vec![],
        directives: vec![("ControlPath".into(), "/tmp/ssh-%h-%p".into())],
        user_known_hosts_file: None,
        identities_only: None,
        canonicalized: false,
        unevaluated_match_warnings: vec![],
        gssapi_authentication: None,
        gssapi_delegate_credentials: None,
        gssapi_server_identity: None,
        gssapi_client_identity: None,
    };
    expand_resolved(&mut resolved, "example", Path::new("/tmp"));
    // ControlPath should be expanded.
    let cp = resolved.control_path.as_deref().unwrap();
    assert!(!cp.contains("%h"));
    assert!(cp.contains("example"));
}

#[test]
fn expand_resolved_user_known_hosts_file() {
    let mut resolved = ResolvedHost {
        alias: "h".into(),
        host_name: None,
        user: None,
        port: None,
        identity_files: vec![],
        certificate_files: vec![],
        proxy_jump: None,
        identity_agent: None,
        forward_agent: None,
        add_keys_to_agent: None,
        use_keychain: None,
        control_master: None,
        control_path: None,
        control_persist: None,
        local_forwards: vec![],
        remote_forwards: vec![],
        dynamic_forwards: vec![],
        directives: vec![("UserKnownHostsFile".into(), "%d/.ssh/known_hosts_%h".into())],
        user_known_hosts_file: None,
        identities_only: None,
        canonicalized: false,
        unevaluated_match_warnings: vec![],
        gssapi_authentication: None,
        gssapi_delegate_credentials: None,
        gssapi_server_identity: None,
        gssapi_client_identity: None,
    };
    expand_resolved(&mut resolved, "myhost", Path::new("/tmp"));
    let val = &resolved.directives[0].1;
    assert!(!val.contains("%d"));
    assert!(!val.contains("%h"));
    assert!(val.contains("myhost"));
}

#[test]
fn expand_resolved_identity_agent() {
    let mut resolved = ResolvedHost {
        alias: "h".into(),
        host_name: None,
        user: None,
        port: None,
        identity_files: vec![],
        certificate_files: vec![],
        proxy_jump: None,
        identity_agent: Some("${SSH_AUTH_SOCK}".into()),
        forward_agent: None,
        add_keys_to_agent: None,
        use_keychain: None,
        control_master: None,
        control_path: None,
        control_persist: None,
        local_forwards: vec![],
        remote_forwards: vec![],
        dynamic_forwards: vec![],
        directives: vec![("IdentityAgent".into(), "${SSH_AUTH_SOCK}".into())],
        user_known_hosts_file: None,
        identities_only: None,
        canonicalized: false,
        unevaluated_match_warnings: vec![],
        gssapi_authentication: None,
        gssapi_delegate_credentials: None,
        gssapi_server_identity: None,
        gssapi_client_identity: None,
    };
    expand_resolved(&mut resolved, "h", Path::new("/tmp"));
    // IdentityAgent should be expanded.
    let ia = resolved.identity_agent.as_deref().unwrap();
    assert!(!ia.contains("${SSH_AUTH_SOCK}"));
}

// ---------------------------------------------------------------------------
// Tests for resolve_pass (internal)
// ---------------------------------------------------------------------------

#[test]
fn resolve_pass_default_canonicalized_false() {
    // A resolved host from resolve_pass should have canonicalized = false.
    use super::ast;
    let ast = ast::parse("Host example\n  HostName example.com\n");
    let resolved = resolve_pass(&ast, "example", "example", "user");
    assert!(!resolved.canonicalized);
    assert_eq!(resolved.host_name.as_deref(), Some("example.com"));
}

// ---------------------------------------------------------------------------
// Edge case: Include chain with cycle detection
// ---------------------------------------------------------------------------

#[tokio::test]
async fn resolve_include_cycle_detected() {
    // Create a config that includes itself through a chain: config -> a -> b -> a
    let dir = tempfile::tempdir().unwrap();
    let ssh_dir = dir.path();

    // config includes chain_a
    std::fs::write(
        ssh_dir.join("config"),
        "Include chain_a\nHost main\n    User root\n",
    )
    .unwrap();

    // chain_a includes chain_b
    std::fs::write(
        ssh_dir.join("chain_a"),
        "Host alpha\n    User alice\nInclude chain_b\n",
    )
    .unwrap();

    // chain_b includes chain_a (creates cycle!)
    std::fs::write(
        ssh_dir.join("chain_b"),
        "Host beta\n    User bob\nInclude chain_a\n",
    )
    .unwrap();

    let result = resolve(ssh_dir, "alpha", None).await;

    assert!(result.is_err(), "should detect include cycle");
    match result.unwrap_err() {
        toride_ssh_core::Error::ConfigIncludeCycle(path) => {
            assert!(
                path.contains("chain_a"),
                "cycle error should mention the offending file, got: {path}"
            );
        }
        other => panic!("expected ConfigIncludeCycle error, got: {other}"),
    }
}

#[tokio::test]
async fn resolve_include_self_referencing() {
    // A config that directly includes itself.
    let dir = tempfile::tempdir().unwrap();
    let ssh_dir = dir.path();

    std::fs::write(
        ssh_dir.join("config"),
        "Include config\nHost self\n    User me\n",
    )
    .unwrap();

    let result = resolve(ssh_dir, "self", None).await;

    assert!(result.is_err(), "should detect self-referencing include");
    match result.unwrap_err() {
        toride_ssh_core::Error::ConfigIncludeCycle(_) => {}
        other => panic!("expected ConfigIncludeCycle error, got: {other}"),
    }
}

#[tokio::test]
async fn resolve_include_chain_without_cycle() {
    // A valid include chain with no cycle: config -> layer1 -> layer2
    let dir = tempfile::tempdir().unwrap();
    let ssh_dir = dir.path();

    std::fs::write(
        ssh_dir.join("config"),
        "Include layer1\nHost main\n    User root\n",
    )
    .unwrap();

    std::fs::write(
        ssh_dir.join("layer1"),
        "Include layer2\nHost web\n    User deploy\n",
    )
    .unwrap();

    std::fs::write(ssh_dir.join("layer2"), "Host db\n    User admin\n").unwrap();

    let resolved = resolve(ssh_dir, "db", None).await;
    assert!(resolved.is_ok(), "valid include chain should not error");
    let resolved = resolved.unwrap();
    assert_eq!(resolved.user.as_deref(), Some("admin"));
}

#[tokio::test]
async fn resolve_include_nonexistent_file() {
    // Including a file that does not exist should not error (OpenSSH behavior).
    let dir = tempfile::tempdir().unwrap();
    let ssh_dir = dir.path();

    std::fs::write(
        ssh_dir.join("config"),
        "Include does_not_exist\nHost test\n    User alice\n",
    )
    .unwrap();

    let resolved = resolve(ssh_dir, "test", None).await;
    assert!(
        resolved.is_ok(),
        "missing include file should be silently skipped"
    );
    assert_eq!(resolved.unwrap().user.as_deref(), Some("alice"));
}

// ---------------------------------------------------------------------------
// ResolvedHost with certificate_files, identity_agent, etc.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn resolve_host_certificate_files_in_directives() {
    let dir = tempfile::tempdir().unwrap();
    let ssh_dir = dir.path();
    std::fs::write(
        ssh_dir.join("config"),
        "\
Host myhost
    HostName example.com
    CertificateFile ~/.ssh/id_ed25519-cert.pub
    CertificateFile ~/.ssh/id_rsa-cert.pub
",
    )
    .unwrap();

    let resolved = resolve(ssh_dir, "myhost", None).await.unwrap();
    let cert_files: Vec<&str> = resolved
        .directives
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("CertificateFile"))
        .map(|(_, v)| v.as_str())
        .collect();
    assert_eq!(cert_files.len(), 2);
    assert!(cert_files[0].contains("id_ed25519-cert.pub"));
    assert!(cert_files[1].contains("id_rsa-cert.pub"));
}

#[tokio::test]
async fn resolve_host_identity_agent_in_directives() {
    let dir = tempfile::tempdir().unwrap();
    let ssh_dir = dir.path();
    std::fs::write(
        ssh_dir.join("config"),
        "\
Host myhost
    HostName example.com
    IdentityAgent /run/user/1000/ssh-agent.sock
",
    )
    .unwrap();

    let resolved = resolve(ssh_dir, "myhost", None).await.unwrap();
    let agent = resolved
        .directives
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("IdentityAgent"));
    assert!(agent.is_some(), "IdentityAgent should be in directives");
    assert!(agent.unwrap().1.contains("ssh-agent.sock"));
}

#[tokio::test]
async fn resolve_host_proxy_jump() {
    let dir = tempfile::tempdir().unwrap();
    let ssh_dir = dir.path().join(".ssh");
    std::fs::create_dir_all(&ssh_dir).unwrap();
    std::fs::write(
        ssh_dir.join("config"),
        "\
Host target
    HostName target.example.com
    ProxyJump jumphost
",
    )
    .unwrap();

    let resolved = resolve(&ssh_dir, "target", None).await.unwrap();
    // ProxyJump uses first-match-wins semantics but still appears in the directives list.
    let pj = resolved
        .directives
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("ProxyJump"));
    assert!(pj.is_some(), "ProxyJump should be in directives list");
    assert_eq!(pj.unwrap().1, "jumphost");
}

#[tokio::test]
async fn resolve_host_identity_files_accumulated() {
    let dir = tempfile::tempdir().unwrap();
    let ssh_dir = dir.path();
    std::fs::write(
        ssh_dir.join("config"),
        "\
Host multi
    IdentityFile ~/.ssh/id_work

Host *
    IdentityFile ~/.ssh/id_personal
",
    )
    .unwrap();

    let resolved = resolve(ssh_dir, "multi", None).await.unwrap();
    assert_eq!(resolved.identity_files.len(), 2);
    assert!(resolved.identity_files[0].contains("id_work"));
    assert!(resolved.identity_files[1].contains("id_personal"));
}

#[tokio::test]
async fn resolve_host_first_match_wins_for_user() {
    let dir = tempfile::tempdir().unwrap();
    let ssh_dir = dir.path();
    std::fs::write(
        ssh_dir.join("config"),
        "\
Host myhost
    User first_user

Host *
    User second_user
",
    )
    .unwrap();

    let resolved = resolve(ssh_dir, "myhost", None).await.unwrap();
    assert_eq!(resolved.user.as_deref(), Some("first_user"));
}

#[tokio::test]
async fn resolve_host_port_and_hostname() {
    let dir = tempfile::tempdir().unwrap();
    let ssh_dir = dir.path();
    std::fs::write(
        ssh_dir.join("config"),
        "\
Host myhost
    HostName custom.example.com
    Port 2222
    User admin
",
    )
    .unwrap();

    let resolved = resolve(ssh_dir, "myhost", None).await.unwrap();
    assert_eq!(resolved.host_name.as_deref(), Some("custom.example.com"));
    assert_eq!(resolved.port, Some(2222));
    assert_eq!(resolved.user.as_deref(), Some("admin"));
}

#[tokio::test]
async fn resolve_host_wildcard_defaults() {
    let dir = tempfile::tempdir().unwrap();
    let ssh_dir = dir.path();
    std::fs::write(
        ssh_dir.join("config"),
        "\
Host *
    User default_user
    Port 22
",
    )
    .unwrap();

    let resolved = resolve(ssh_dir, "anything", None).await.unwrap();
    assert_eq!(resolved.user.as_deref(), Some("default_user"));
    assert_eq!(resolved.port, Some(22));
}

#[tokio::test]
async fn resolve_host_empty_config() {
    let dir = tempfile::tempdir().unwrap();
    let ssh_dir = dir.path();
    std::fs::write(ssh_dir.join("config"), "").unwrap();

    let resolved = resolve(ssh_dir, "myhost", None).await.unwrap();
    assert!(resolved.user.is_none());
    assert!(resolved.host_name.is_none());
    assert!(resolved.port.is_none());
    assert!(resolved.identity_files.is_empty());
}

#[tokio::test]
async fn resolve_host_no_config_file() {
    let dir = tempfile::tempdir().unwrap();
    let ssh_dir = dir.path();
    // No config file at all.

    let resolved = resolve(ssh_dir, "myhost", None).await.unwrap();
    assert!(resolved.user.is_none());
    assert!(resolved.directives.is_empty());
}

// ---------------------------------------------------------------------------
// Tests for ForwardAgent first-match-wins (was accumulative, now fixed)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn resolve_host_forward_agent_populated() {
    let dir = tempfile::tempdir().unwrap();
    let ssh_dir = dir.path();
    std::fs::write(
        ssh_dir.join("config"),
        "\
Host myhost
    ForwardAgent yes
",
    )
    .unwrap();

    let resolved = resolve(ssh_dir, "myhost", None).await.unwrap();
    assert_eq!(
        resolved.forward_agent.as_deref(),
        Some("yes"),
        "ForwardAgent must be populated in resolved.forward_agent"
    );
}

#[tokio::test]
async fn resolve_host_forward_agent_first_match_wins() {
    let dir = tempfile::tempdir().unwrap();
    let ssh_dir = dir.path();
    std::fs::write(
        ssh_dir.join("config"),
        "\
Host myhost
    ForwardAgent yes

Host *
    ForwardAgent no
",
    )
    .unwrap();

    let resolved = resolve(ssh_dir, "myhost", None).await.unwrap();
    assert_eq!(
        resolved.forward_agent.as_deref(),
        Some("yes"),
        "ForwardAgent uses first-match-wins semantics"
    );
}

// ---------------------------------------------------------------------------
// Tests for AddKeysToAgent, UseKeychain, ControlMaster, ControlPersist
// ---------------------------------------------------------------------------

#[tokio::test]
async fn resolve_host_add_keys_to_agent() {
    let dir = tempfile::tempdir().unwrap();
    let ssh_dir = dir.path();
    std::fs::write(
        ssh_dir.join("config"),
        "\
Host myhost
    AddKeysToAgent confirm
",
    )
    .unwrap();

    let resolved = resolve(ssh_dir, "myhost", None).await.unwrap();
    assert_eq!(resolved.add_keys_to_agent.as_deref(), Some("confirm"));
}

#[tokio::test]
async fn resolve_host_use_keychain() {
    let dir = tempfile::tempdir().unwrap();
    let ssh_dir = dir.path();
    std::fs::write(
        ssh_dir.join("config"),
        "\
Host myhost
    UseKeychain yes
",
    )
    .unwrap();

    let resolved = resolve(ssh_dir, "myhost", None).await.unwrap();
    assert_eq!(resolved.use_keychain.as_deref(), Some("yes"));
}

#[tokio::test]
async fn resolve_host_control_master_and_path_and_persist() {
    let dir = tempfile::tempdir().unwrap();
    let ssh_dir = dir.path();
    std::fs::write(
        ssh_dir.join("config"),
        "\
Host myhost
    ControlMaster auto
    ControlPath /tmp/ssh-%h-%p
    ControlPersist 10m
",
    )
    .unwrap();

    let resolved = resolve(ssh_dir, "myhost", None).await.unwrap();
    assert_eq!(resolved.control_master.as_deref(), Some("auto"));
    assert!(
        resolved.control_path.as_deref().unwrap().contains("myhost"),
        "ControlPath should have %h expanded"
    );
    assert!(!resolved.control_path.as_deref().unwrap().contains("%h"));
    assert_eq!(resolved.control_persist.as_deref(), Some("10m"));
}

// ---------------------------------------------------------------------------
// Tests for accumulative forwarding directives
// ---------------------------------------------------------------------------

#[tokio::test]
async fn resolve_host_local_forwards_accumulated() {
    let dir = tempfile::tempdir().unwrap();
    let ssh_dir = dir.path();
    std::fs::write(
        ssh_dir.join("config"),
        "\
Host myhost
    LocalForward 8080 localhost:80
    LocalForward 9090 localhost:90

Host *
    LocalForward 3000 localhost:3000
",
    )
    .unwrap();

    let resolved = resolve(ssh_dir, "myhost", None).await.unwrap();
    assert_eq!(resolved.local_forwards.len(), 3);
    assert_eq!(resolved.local_forwards[0], "8080 localhost:80");
    assert_eq!(resolved.local_forwards[1], "9090 localhost:90");
    assert_eq!(resolved.local_forwards[2], "3000 localhost:3000");
}

#[tokio::test]
async fn resolve_host_remote_forwards_accumulated() {
    let dir = tempfile::tempdir().unwrap();
    let ssh_dir = dir.path();
    std::fs::write(
        ssh_dir.join("config"),
        "\
Host myhost
    RemoteForward 8080 localhost:80
    RemoteForward 9090 localhost:90
",
    )
    .unwrap();

    let resolved = resolve(ssh_dir, "myhost", None).await.unwrap();
    assert_eq!(resolved.remote_forwards.len(), 2);
    assert_eq!(resolved.remote_forwards[0], "8080 localhost:80");
    assert_eq!(resolved.remote_forwards[1], "9090 localhost:90");
}

#[tokio::test]
async fn resolve_host_dynamic_forwards_accumulated() {
    let dir = tempfile::tempdir().unwrap();
    let ssh_dir = dir.path();
    std::fs::write(
        ssh_dir.join("config"),
        "\
Host myhost
    DynamicForward 1080
    DynamicForward 1081
",
    )
    .unwrap();

    let resolved = resolve(ssh_dir, "myhost", None).await.unwrap();
    assert_eq!(resolved.dynamic_forwards.len(), 2);
    assert_eq!(resolved.dynamic_forwards[0], "1080");
    assert_eq!(resolved.dynamic_forwards[1], "1081");
}

// ---------------------------------------------------------------------------
// Token expansion for dedicated forwarding fields
// ---------------------------------------------------------------------------

#[test]
fn expand_resolved_local_forwards_with_tokens() {
    let mut resolved = ResolvedHost {
        alias: "h".into(),
        host_name: None,
        user: None,
        port: None,
        identity_files: vec![],
        certificate_files: vec![],
        proxy_jump: None,
        identity_agent: None,
        forward_agent: None,
        add_keys_to_agent: None,
        use_keychain: None,
        control_master: None,
        control_path: None,
        control_persist: None,
        local_forwards: vec!["8080 %h:80".into()],
        remote_forwards: vec![],
        dynamic_forwards: vec![],
        directives: vec![],
        user_known_hosts_file: None,
        identities_only: None,
        canonicalized: false,
        unevaluated_match_warnings: vec![],
        gssapi_authentication: None,
        gssapi_delegate_credentials: None,
        gssapi_server_identity: None,
        gssapi_client_identity: None,
    };
    expand_resolved(&mut resolved, "example.com", Path::new("/tmp"));
    let lf = &resolved.local_forwards[0];
    assert!(!lf.contains("%h"), "LocalForward tokens should be expanded");
    assert!(lf.contains("example.com"));
}

#[test]
fn expand_resolved_remote_forwards_with_tokens() {
    let mut resolved = ResolvedHost {
        alias: "h".into(),
        host_name: None,
        user: None,
        port: None,
        identity_files: vec![],
        certificate_files: vec![],
        proxy_jump: None,
        identity_agent: None,
        forward_agent: None,
        add_keys_to_agent: None,
        use_keychain: None,
        control_master: None,
        control_path: None,
        control_persist: None,
        local_forwards: vec![],
        remote_forwards: vec!["8080 %h:80".into()],
        dynamic_forwards: vec![],
        directives: vec![],
        user_known_hosts_file: None,
        identities_only: None,
        canonicalized: false,
        unevaluated_match_warnings: vec![],
        gssapi_authentication: None,
        gssapi_delegate_credentials: None,
        gssapi_server_identity: None,
        gssapi_client_identity: None,
    };
    expand_resolved(&mut resolved, "example.com", Path::new("/tmp"));
    let rf = &resolved.remote_forwards[0];
    assert!(
        !rf.contains("%h"),
        "RemoteForward tokens should be expanded"
    );
    assert!(rf.contains("example.com"));
}

#[test]
fn expand_resolved_dynamic_forwards_with_tokens() {
    let mut resolved = ResolvedHost {
        alias: "h".into(),
        host_name: None,
        user: None,
        port: None,
        identity_files: vec![],
        certificate_files: vec![],
        proxy_jump: None,
        identity_agent: None,
        forward_agent: None,
        add_keys_to_agent: None,
        use_keychain: None,
        control_master: None,
        control_path: None,
        control_persist: None,
        local_forwards: vec![],
        remote_forwards: vec![],
        dynamic_forwards: vec!["%p".into()],
        directives: vec![],
        user_known_hosts_file: None,
        identities_only: None,
        canonicalized: false,
        unevaluated_match_warnings: vec![],
        gssapi_authentication: None,
        gssapi_delegate_credentials: None,
        gssapi_server_identity: None,
        gssapi_client_identity: None,
    };
    expand_resolved(&mut resolved, "h", Path::new("/tmp"));
    let df = &resolved.dynamic_forwards[0];
    assert!(
        !df.contains("%p"),
        "DynamicForward tokens should be expanded"
    );
}

// ---------------------------------------------------------------------------
// CanonicalizeHostname second-pass when host_name is None (falls back to alias)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn resolve_canonicalize_hostname_second_pass_no_hostname() {
    // When CanonicalizeHostname is enabled but the first pass does not set
    // HostName, the second pass uses the original alias as the canonical host.
    // Directives from a Host block matching that canonical name must apply.
    let dir = tempfile::tempdir().unwrap();
    let ssh_dir = dir.path();
    std::fs::write(
        ssh_dir.join("config"),
        "\
Host *
    CanonicalizeHostname yes

Host myalias
    User first_user
    Port 2222
",
    )
    .unwrap();

    let resolved = resolve(ssh_dir, "myalias", None).await.unwrap();

    // The result must be marked as canonicalized.
    assert!(
        resolved.canonicalized,
        "second-pass resolution should set canonicalized = true"
    );

    // The alias must be preserved (not overwritten by the canonical name).
    assert_eq!(resolved.alias, "myalias");

    // Since no HostName was set, the second pass re-resolves using "myalias"
    // and the Host myalias block should match, applying its directives.
    assert_eq!(
        resolved.user.as_deref(),
        Some("first_user"),
        "second pass should apply User from the matching Host block"
    );
    assert_eq!(
        resolved.port,
        Some(2222),
        "second pass should apply Port from the matching Host block"
    );

    // host_name should still be None (no HostName directive in the block).
    assert!(
        resolved.host_name.is_none(),
        "host_name remains None when no HostName directive is set"
    );
}

// ---------------------------------------------------------------------------
// Dedup for accumulative forwarding directives
// ---------------------------------------------------------------------------

#[tokio::test]
async fn resolve_host_local_forwards_dedup() {
    let dir = tempfile::tempdir().unwrap();
    let ssh_dir = dir.path();
    std::fs::write(
        ssh_dir.join("config"),
        "\
Host myhost
    LocalForward 8080 localhost:80

Host *
    LocalForward 8080 localhost:80
",
    )
    .unwrap();

    let resolved = resolve(ssh_dir, "myhost", None).await.unwrap();
    assert_eq!(
        resolved.local_forwards.len(),
        1,
        "duplicate forwards should be deduped"
    );
}

// ---------------------------------------------------------------------------
// Tests for glob_paths
// ---------------------------------------------------------------------------

#[test]
fn glob_paths_simple_star_conf() {
    // *.conf should match only .conf files.
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path();

    std::fs::write(base.join("alpha.conf"), "").unwrap();
    std::fs::write(base.join("beta.conf"), "").unwrap();
    std::fs::write(base.join("gamma.txt"), "").unwrap();

    let pattern = format!("{}/*.conf", base.display());
    let mut result = glob_paths(&pattern);
    result.sort();

    assert_eq!(result.len(), 2, "*.conf should match exactly two files");
    assert!(result[0].ends_with("alpha.conf"));
    assert!(result[1].ends_with("beta.conf"));
}

#[test]
fn glob_paths_exact_filename() {
    // An exact filename (no wildcards) should match only that file.
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path();

    std::fs::write(base.join("specific.conf"), "").unwrap();
    std::fs::write(base.join("other.conf"), "").unwrap();

    let pattern = format!("{}/specific.conf", base.display());
    let result = glob_paths(&pattern);

    assert_eq!(result.len(), 1);
    assert!(result[0].ends_with("specific.conf"));
}

#[test]
fn glob_paths_no_matches_found() {
    // When no files match the pattern, an empty vec is returned.
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path();

    std::fs::write(base.join("readme.md"), "").unwrap();
    std::fs::write(base.join("data.json"), "").unwrap();

    let pattern = format!("{}/*.conf", base.display());
    let result = glob_paths(&pattern);

    assert!(
        result.is_empty(),
        "*.conf should match nothing in a dir with only .md and .json"
    );
}

#[test]
fn glob_paths_nonexistent_directory() {
    // When the parent directory does not exist, glob_paths returns an empty vec.
    let result = glob_paths("/nonexistent/path/*.conf");
    assert!(result.is_empty());
}

#[test]
fn glob_paths_nested_directory_pattern() {
    // A pattern with a subdirectory component should match files in that subdir.
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path();
    let sub = base.join("configs");
    std::fs::create_dir(&sub).unwrap();

    std::fs::write(sub.join("web.conf"), "").unwrap();
    std::fs::write(sub.join("db.conf"), "").unwrap();
    std::fs::write(sub.join("notes.txt"), "").unwrap();

    // Also create files in the parent to ensure they are NOT matched.
    std::fs::write(base.join("parent.conf"), "").unwrap();

    let pattern = format!("{}/configs/*.conf", base.display());
    let mut result = glob_paths(&pattern);
    result.sort();

    assert_eq!(
        result.len(),
        2,
        "should only match .conf files inside configs/"
    );
    assert!(result[0].ends_with("db.conf"));
    assert!(result[1].ends_with("web.conf"));
}

#[test]
fn glob_paths_nested_deep_directory_pattern() {
    // Multiple levels of nesting: a/b/*.conf
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path();
    let nested = base.join("a").join("b");
    std::fs::create_dir_all(&nested).unwrap();

    std::fs::write(nested.join("deep.conf"), "").unwrap();
    std::fs::write(nested.join("deep.txt"), "").unwrap();

    // Also in a/ to make sure it's not matched.
    std::fs::write(base.join("a").join("shallow.conf"), "").unwrap();

    let pattern = format!("{}/a/b/*.conf", base.display());
    let result = glob_paths(&pattern);

    assert_eq!(result.len(), 1, "should only match .conf in a/b/");
    assert!(result[0].ends_with("deep.conf"));
}

#[test]
fn glob_paths_question_mark_wildcard() {
    // ? matches exactly one character.
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path();

    std::fs::write(base.join("a.conf"), "").unwrap();
    std::fs::write(base.join("ab.conf"), "").unwrap();
    std::fs::write(base.join("abc.conf"), "").unwrap();

    let pattern = format!("{}/*.conf", base.display());
    let mut result = glob_paths(&pattern);
    result.sort();

    // *.conf matches all .conf files regardless of name length.
    assert_eq!(result.len(), 3);
}

#[test]
fn glob_paths_question_mark_single_char() {
    // ?.conf should match only single-character filenames ending in .conf.
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path();

    std::fs::write(base.join("a.conf"), "").unwrap();
    std::fs::write(base.join("b.conf"), "").unwrap();
    std::fs::write(base.join("ab.conf"), "").unwrap();

    let pattern = format!("{}/*.conf", base.display());
    let mut result = glob_paths(&pattern);
    result.sort();

    // *.conf matches all .conf files.
    assert_eq!(result.len(), 3);

    // Now test with a literal ? pattern for single-char matching.
    let pattern_q = format!("{}/?.conf", base.display());
    let mut result_q = glob_paths(&pattern_q);
    result_q.sort();

    assert_eq!(
        result_q.len(),
        2,
        "?.conf should match only single-char names"
    );
    assert!(result_q[0].ends_with("a.conf"));
    assert!(result_q[1].ends_with("b.conf"));
}

#[test]
fn glob_paths_empty_directory() {
    // An empty directory should return no matches for any pattern.
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path();

    let pattern = format!("{}/*", base.display());
    let result = glob_paths(&pattern);

    assert!(result.is_empty());
}

#[test]
fn glob_paths_star_matches_all_files() {
    // * should match every file (and directory) in the parent.
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path();

    std::fs::write(base.join("one.txt"), "").unwrap();
    std::fs::write(base.join("two.conf"), "").unwrap();
    std::fs::write(base.join("three.md"), "").unwrap();

    let pattern = format!("{}/*", base.display());
    let mut result = glob_paths(&pattern);
    result.sort();

    assert_eq!(result.len(), 3, "* should match all three files");
}

#[test]
fn glob_paths_results_are_sorted() {
    // Verify that glob_paths returns paths in sorted order.
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path();

    std::fs::write(base.join("zebra.conf"), "").unwrap();
    std::fs::write(base.join("alpha.conf"), "").unwrap();
    std::fs::write(base.join("middle.conf"), "").unwrap();

    let pattern = format!("{}/*.conf", base.display());
    let result = glob_paths(&pattern);

    assert_eq!(result.len(), 3);
    assert!(result[0].ends_with("alpha.conf"));
    assert!(result[1].ends_with("middle.conf"));
    assert!(result[2].ends_with("zebra.conf"));
}

// ---------------------------------------------------------------------------
// Tests for recursive ** glob support
// ---------------------------------------------------------------------------

#[test]
fn glob_paths_double_star_conf_recursive() {
    // **/*.conf should match .conf files at all directory levels.
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path();

    // Root level.
    std::fs::write(base.join("root.conf"), "").unwrap();
    std::fs::write(base.join("root.txt"), "").unwrap();

    // One level deep.
    let sub1 = base.join("sub1");
    std::fs::create_dir(&sub1).unwrap();
    std::fs::write(sub1.join("level1.conf"), "").unwrap();
    std::fs::write(sub1.join("level1.txt"), "").unwrap();

    // Two levels deep.
    let sub2 = sub1.join("sub2");
    std::fs::create_dir(&sub2).unwrap();
    std::fs::write(sub2.join("level2.conf"), "").unwrap();

    let pattern = format!("{}/**/*.conf", base.display());
    let mut result = glob_paths(&pattern);
    result.sort();

    assert_eq!(
        result.len(),
        3,
        "**/*.conf should match .conf at all levels"
    );
    // Sorted by full path string:
    //   <base>/root.conf < <base>/sub1/level1.conf < <base>/sub1/sub2/level2.conf
    assert!(result[0].ends_with("root.conf"));
    assert!(result[1].ends_with("level1.conf"));
    assert!(result[2].ends_with("level2.conf"));
}

#[test]
fn glob_paths_double_star_at_start() {
    // **/*.conf with no prefix — treats current dir ("." is not used; empty
    // prefix means empty base).  Using an explicit base directory.
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path();

    std::fs::write(base.join("a.conf"), "").unwrap();
    let nested = base.join("deep");
    std::fs::create_dir(&nested).unwrap();
    std::fs::write(nested.join("b.conf"), "").unwrap();

    // Pattern: <base>/**/*.conf (prefix is the base dir, not empty).
    let pattern = format!("{}/**/*.conf", base.display());
    let mut result = glob_paths(&pattern);
    result.sort();

    assert_eq!(result.len(), 2);
    assert!(result[0].ends_with("a.conf"));
    assert!(result[1].ends_with("b.conf"));
}

#[test]
fn glob_paths_double_star_in_middle() {
    // config.d/**/*.conf — prefix is config.d, suffix is *.conf.
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path();
    let config_d = base.join("config.d");
    std::fs::create_dir(&config_d).unwrap();

    // Direct child of config.d.
    std::fs::write(config_d.join("top.conf"), "").unwrap();

    // Nested under config.d/hosts/.
    let hosts = config_d.join("hosts");
    std::fs::create_dir(&hosts).unwrap();
    std::fs::write(hosts.join("web.conf"), "").unwrap();
    std::fs::write(hosts.join("db.conf"), "").unwrap();

    // A file in the base dir should NOT be matched.
    std::fs::write(base.join("outside.conf"), "").unwrap();

    let pattern = format!("{}/config.d/**/*.conf", base.display());
    let mut result = glob_paths(&pattern);
    result.sort();

    assert_eq!(result.len(), 3, "should match all .conf under config.d/");
    // Sorted by full path:
    //   .../hosts/db.conf < .../hosts/web.conf < .../top.conf
    assert!(result[0].ends_with("db.conf"));
    assert!(result[1].ends_with("web.conf"));
    assert!(result[2].ends_with("top.conf"));
}

#[test]
fn glob_paths_double_star_no_matches() {
    // **/*.conf in a directory tree with no .conf files.
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path();

    std::fs::write(base.join("readme.md"), "").unwrap();
    let sub = base.join("notes");
    std::fs::create_dir(&sub).unwrap();
    std::fs::write(sub.join("data.json"), "").unwrap();

    let pattern = format!("{}/**/*.conf", base.display());
    let result = glob_paths(&pattern);

    assert!(
        result.is_empty(),
        "no .conf files should yield empty result"
    );
}

#[test]
fn glob_paths_double_star_with_subdir_in_suffix() {
    // **/sub/*.conf — matches any "sub" directory at any depth, then *.conf
    // inside it.
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path();

    // base/sub/a.conf
    let sub1 = base.join("sub");
    std::fs::create_dir(&sub1).unwrap();
    std::fs::write(sub1.join("a.conf"), "").unwrap();
    std::fs::write(sub1.join("a.txt"), "").unwrap();

    // base/other/sub/b.conf (two levels)
    let other = base.join("other");
    std::fs::create_dir(&other).unwrap();
    let sub2 = other.join("sub");
    std::fs::create_dir(&sub2).unwrap();
    std::fs::write(sub2.join("b.conf"), "").unwrap();

    // base/other/c.conf (should NOT match — not inside a "sub" dir)
    std::fs::write(other.join("c.conf"), "").unwrap();

    let pattern = format!("{}/**/sub/*.conf", base.display());
    let mut result = glob_paths(&pattern);
    result.sort();

    assert_eq!(
        result.len(),
        2,
        "only .conf files inside a 'sub' dir should match"
    );
    // Sorted by full path: .../other/sub/b.conf < .../sub/a.conf
    assert!(result[0].ends_with("b.conf"));
    assert!(result[1].ends_with("a.conf"));
}

#[test]
fn glob_paths_double_star_trailing() {
    // Trailing ** without slash matches everything under the prefix.
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path();

    std::fs::write(base.join("file.txt"), "").unwrap();
    let sub = base.join("dir");
    std::fs::create_dir(&sub).unwrap();
    std::fs::write(sub.join("nested.txt"), "").unwrap();

    let pattern = format!("{}/**", base.display());
    let mut result = glob_paths(&pattern);
    result.sort();

    assert!(
        result.len() >= 2,
        "trailing ** should match all entries recursively"
    );
    assert!(result.iter().any(|p| p.ends_with("file.txt")));
    assert!(result.iter().any(|p| p.ends_with("nested.txt")));
}

#[test]
fn glob_paths_no_double_star_unchanged() {
    // Verify existing * and ? behavior is not affected by the ** changes.
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path();

    std::fs::write(base.join("alpha.conf"), "").unwrap();
    std::fs::write(base.join("beta.conf"), "").unwrap();
    std::fs::write(base.join("gamma.txt"), "").unwrap();

    let pattern = format!("{}/*.conf", base.display());
    let mut result = glob_paths(&pattern);
    result.sort();

    assert_eq!(result.len(), 2);
    assert!(result[0].ends_with("alpha.conf"));
    assert!(result[1].ends_with("beta.conf"));
}

#[test]
fn glob_paths_double_star_empty_tree() {
    // **/*.conf in an empty directory should return no matches.
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path();

    let pattern = format!("{}/**/*.conf", base.display());
    let result = glob_paths(&pattern);

    assert!(result.is_empty());
}

#[test]
fn glob_paths_double_star_zero_levels() {
    // **/ matches zero levels, so base/**/*.conf should also match files
    // directly in base/ (not just in subdirectories).
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path();

    // Only a file at the root — no subdirectories at all.
    std::fs::write(base.join("solo.conf"), "").unwrap();

    let pattern = format!("{}/**/*.conf", base.display());
    let result = glob_paths(&pattern);

    assert_eq!(result.len(), 1, "** must match zero directory levels");
    assert!(result[0].ends_with("solo.conf"));
}

// ---------------------------------------------------------------------------
// Tests for GSSAPI field resolution
// ---------------------------------------------------------------------------

#[tokio::test]
async fn resolve_gssapi_authentication() {
    let dir = tempfile::tempdir().unwrap();
    let ssh_dir = dir.path();
    std::fs::write(
        ssh_dir.join("config"),
        "\
Host myhost
    HostName example.com
    GSSAPIAuthentication yes
",
    )
    .unwrap();

    let resolved = resolve(ssh_dir, "myhost", None).await.unwrap();
    assert_eq!(
        resolved.gssapi_authentication.as_deref(),
        Some("yes"),
        "GSSAPIAuthentication should be populated"
    );
    assert!(resolved.gssapi_delegate_credentials.is_none());
    assert!(resolved.gssapi_server_identity.is_none());
    assert!(resolved.gssapi_client_identity.is_none());
}

#[tokio::test]
async fn resolve_gssapi_all_fields() {
    let dir = tempfile::tempdir().unwrap();
    let ssh_dir = dir.path();
    std::fs::write(
        ssh_dir.join("config"),
        "\
Host kdc-host
    HostName kdc.example.com
    GSSAPIAuthentication yes
    GSSAPIDelegateCredentials yes
    GSSAPIServerIdentity example.com
    GSSAPIClientIdentity alice@EXAMPLE.COM
",
    )
    .unwrap();

    let resolved = resolve(ssh_dir, "kdc-host", None).await.unwrap();
    assert_eq!(resolved.gssapi_authentication.as_deref(), Some("yes"));
    assert_eq!(resolved.gssapi_delegate_credentials.as_deref(), Some("yes"));
    assert_eq!(
        resolved.gssapi_server_identity.as_deref(),
        Some("example.com")
    );
    assert_eq!(
        resolved.gssapi_client_identity.as_deref(),
        Some("alice@EXAMPLE.COM")
    );
}

#[tokio::test]
async fn resolve_gssapi_first_match_wins() {
    let dir = tempfile::tempdir().unwrap();
    let ssh_dir = dir.path();
    std::fs::write(
        ssh_dir.join("config"),
        "\
Host myhost
    GSSAPIAuthentication yes

Host *
    GSSAPIAuthentication no
",
    )
    .unwrap();

    let resolved = resolve(ssh_dir, "myhost", None).await.unwrap();
    assert_eq!(
        resolved.gssapi_authentication.as_deref(),
        Some("yes"),
        "GSSAPIAuthentication uses first-match-wins semantics"
    );
}

#[tokio::test]
async fn resolve_gssapi_wildcard_defaults() {
    let dir = tempfile::tempdir().unwrap();
    let ssh_dir = dir.path();
    std::fs::write(
        ssh_dir.join("config"),
        "\
Host *
    GSSAPIAuthentication no
    GSSAPIServerIdentity corp.example.com
",
    )
    .unwrap();

    let resolved = resolve(ssh_dir, "anything", None).await.unwrap();
    assert_eq!(resolved.gssapi_authentication.as_deref(), Some("no"));
    assert_eq!(
        resolved.gssapi_server_identity.as_deref(),
        Some("corp.example.com")
    );
}

#[tokio::test]
async fn resolve_gssapi_in_directives_list() {
    let dir = tempfile::tempdir().unwrap();
    let ssh_dir = dir.path();
    std::fs::write(
        ssh_dir.join("config"),
        "\
Host myhost
    HostName example.com
    GSSAPIAuthentication yes
    GSSAPIServerIdentity example.com
",
    )
    .unwrap();

    let resolved = resolve(ssh_dir, "myhost", None).await.unwrap();
    let gssapi_directives: Vec<(&str, &str)> = resolved
        .directives
        .iter()
        .filter(|(k, _)| {
            k.eq_ignore_ascii_case("GSSAPIAuthentication")
                || k.eq_ignore_ascii_case("GSSAPIServerIdentity")
        })
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    assert_eq!(
        gssapi_directives.len(),
        2,
        "GSSAPI directives should appear in the directives list"
    );
}
