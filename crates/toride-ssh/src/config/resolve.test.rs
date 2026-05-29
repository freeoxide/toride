use super::*;

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
    assert_eq!(
        expand_env_vars("${TORIDE_A}-${TORIDE_B}"),
        "alpha-beta"
    );
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
    assert!(!result.starts_with("~"));
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
    let ctx = TokenContext { host: "host", home_dir: "/home", local_hostname: "local", remote_user: "remote", local_user: "user", port: "22" };
    assert_eq!(expand_tokens("hello", &ctx), "hello");
}

#[test]
fn expand_tokens_host() {
    let ctx = TokenContext { host: "example.com", home_dir: "/home", local_hostname: "local", remote_user: "remote", local_user: "user", port: "22" };
    assert_eq!(expand_tokens("%h", &ctx), "example.com");
}

#[test]
fn expand_tokens_user() {
    let ctx = TokenContext { host: "host", home_dir: "/home", local_hostname: "local", remote_user: "remote", local_user: "alice", port: "22" };
    assert_eq!(expand_tokens("%u", &ctx), "alice");
}

#[test]
fn expand_tokens_port() {
    let ctx = TokenContext { host: "host", home_dir: "/home", local_hostname: "local", remote_user: "remote", local_user: "user", port: "2222" };
    assert_eq!(expand_tokens("%p", &ctx), "2222");
}

#[test]
fn expand_tokens_home_dir() {
    let ctx = TokenContext { host: "host", home_dir: "/home/alice", local_hostname: "local", remote_user: "remote", local_user: "user", port: "22" };
    assert_eq!(expand_tokens("%d", &ctx), "/home/alice");
}

#[test]
fn expand_tokens_local_hostname() {
    let ctx = TokenContext { host: "host", home_dir: "/home", local_hostname: "myhost", remote_user: "remote", local_user: "user", port: "22" };
    assert_eq!(expand_tokens("%l", &ctx), "myhost");
}

#[test]
fn expand_tokens_remote_user() {
    let ctx = TokenContext { host: "host", home_dir: "/home", local_hostname: "local", remote_user: "deploy", local_user: "user", port: "22" };
    assert_eq!(expand_tokens("%r", &ctx), "deploy");
}

#[test]
fn expand_tokens_unknown_token() {
    let ctx = TokenContext { host: "host", home_dir: "/home", local_hostname: "local", remote_user: "remote", local_user: "user", port: "22" };
    assert_eq!(expand_tokens("%z", &ctx), "%z");
}

#[test]
fn expand_tokens_trailing_percent() {
    let ctx = TokenContext { host: "host", home_dir: "/home", local_hostname: "local", remote_user: "remote", local_user: "user", port: "22" };
    assert_eq!(expand_tokens("hello%", &ctx), "hello%");
}

#[test]
fn expand_tokens_double_percent() {
    let ctx = TokenContext { host: "host", home_dir: "/home", local_hostname: "local", remote_user: "remote", local_user: "user", port: "22" };
    assert_eq!(expand_tokens("%%", &ctx), "%%");
}

#[test]
fn expand_tokens_mixed() {
    let ctx = TokenContext { host: "example.com", home_dir: "/home", local_hostname: "local", remote_user: "remote", local_user: "user", port: "22" };
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
    assert!(match_criteria_host("host web", "web"));
    assert!(!match_criteria_host("host web", "db"));
}

#[test]
fn match_criteria_host_no_host_clause() {
    assert!(!match_criteria_host("user alice", "web"));
}

#[test]
fn match_criteria_host_wildcard() {
    assert!(match_criteria_host("host *", "anything"));
}

// ---------------------------------------------------------------------------
// Weird edge-case tests for token expansion
// ---------------------------------------------------------------------------

#[test]
fn expand_tokens_consecutive_tokens() {
    let ctx = TokenContext { host: "h", home_dir: "d", local_hostname: "l", remote_user: "r", local_user: "u", port: "p" };
    assert_eq!(expand_tokens("%h%h%h", &ctx), "hhh");
}

#[test]
fn expand_tokens_adjacent_different_tokens() {
    let ctx = TokenContext { host: "host", home_dir: "/home", local_hostname: "local", remote_user: "remote", local_user: "user", port: "22" };
    assert_eq!(expand_tokens("%h:%p:%u", &ctx), "host:22:user");
}

#[test]
fn expand_tokens_percent_at_end() {
    let ctx = TokenContext { host: "host", home_dir: "/home", local_hostname: "local", remote_user: "remote", local_user: "user", port: "22" };
    assert_eq!(expand_tokens("hello%", &ctx), "hello%");
}

#[test]
fn expand_tokens_percent_at_start() {
    let ctx = TokenContext { host: "host", home_dir: "/home", local_hostname: "local", remote_user: "remote", local_user: "user", port: "22" };
    // %h is a valid token (host), so %hello becomes "hostello"
    assert_eq!(expand_tokens("%h", &ctx), "host");
}

#[test]
fn expand_tokens_only_percent() {
    let ctx = TokenContext { host: "host", home_dir: "/home", local_hostname: "local", remote_user: "remote", local_user: "user", port: "22" };
    assert_eq!(expand_tokens("%", &ctx), "%");
}

#[test]
fn expand_tokens_escaped_percent_sequence() {
    let ctx = TokenContext { host: "host", home_dir: "/home", local_hostname: "local", remote_user: "remote", local_user: "user", port: "22" };
    // %%h should produce %%h (collapse_double_percent handles %% → %)
    assert_eq!(expand_tokens("%%h", &ctx), "%%h");
}

#[test]
fn expand_tokens_empty_string() {
    let ctx = TokenContext { host: "host", home_dir: "/home", local_hostname: "local", remote_user: "remote", local_user: "user", port: "22" };
    assert_eq!(expand_tokens("", &ctx), "");
}

#[test]
fn expand_tokens_no_tokens_complex() {
    let ctx = TokenContext { host: "host", home_dir: "/home", local_hostname: "local", remote_user: "remote", local_user: "user", port: "22" };
    assert_eq!(expand_tokens("/usr/local/bin/ssh", &ctx), "/usr/local/bin/ssh");
}

#[test]
fn expand_tilde_just_slash() {
    // ~/ should expand to home dir + /
    let result = expand_tilde_and_env("~/");
    assert!(!result.starts_with("~/"));
    assert!(result.ends_with("/"));
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
    unsafe { std::env::set_var("TORIDE_TEST_START", "hello"); }
    assert_eq!(expand_env_vars("${TORIDE_TEST_START}world"), "helloworld");
    unsafe { std::env::remove_var("TORIDE_TEST_START"); }
}

#[test]
fn expand_env_vars_var_at_end() {
    unsafe { std::env::set_var("TORIDE_TEST_END", "world"); }
    assert_eq!(expand_env_vars("hello${TORIDE_TEST_END}"), "helloworld");
    unsafe { std::env::remove_var("TORIDE_TEST_END"); }
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
    assert!(match_criteria_host("HOST web", "web"));
    assert!(match_criteria_host("Host web", "web"));
    assert!(match_criteria_host("host web", "web"));
}

#[test]
fn match_criteria_host_multiple_host_clauses() {
    // Multiple host clauses - either can match
    assert!(match_criteria_host("host web host db", "web"));
    assert!(match_criteria_host("host web host db", "db"));
    assert!(!match_criteria_host("host web host db", "other"));
}

#[test]
fn match_criteria_host_unknown_keyword_before_host() {
    // Unknown keyword before host clause
    assert!(match_criteria_host("user alice host web", "web"));
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
    unsafe { std::env::set_var("TORIDE_SPACED", "hello world"); }
    assert_eq!(expand_env_vars("${TORIDE_SPACED}"), "hello world");
    unsafe { std::env::remove_var("TORIDE_SPACED"); }
}

#[test]
fn expand_env_vars_with_equals_in_value() {
    unsafe { std::env::set_var("TORIDE_EQUALS", "a=b"); }
    assert_eq!(expand_env_vars("${TORIDE_EQUALS}"), "a=b");
    unsafe { std::env::remove_var("TORIDE_EQUALS"); }
}

#[test]
fn expand_env_vars_with_special_chars() {
    unsafe { std::env::set_var("TORIDE_SPECIAL", "hello@world.com"); }
    assert_eq!(expand_env_vars("${TORIDE_SPECIAL}"), "hello@world.com");
    unsafe { std::env::remove_var("TORIDE_SPECIAL"); }
}

#[test]
fn expand_env_vars_undefined_returns_empty() {
    // Undefined vars should expand to empty string
    assert_eq!(expand_env_vars("${TORIDE_DEFINITELY_NOT_SET_12345}"), "");
}

#[test]
fn expand_env_vars_with_dollar_sign_in_value() {
    // Dollar sign in env var value should not be re-expanded
    unsafe { std::env::set_var("TORIDE_DOLLAR", "$NOT_A_VAR"); }
    assert_eq!(expand_env_vars("${TORIDE_DOLLAR}"), "$NOT_A_VAR");
    unsafe { std::env::remove_var("TORIDE_DOLLAR"); }
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
    };
    let result = expand_tokens("%h:%p:%u:%d:%l:%r", &ctx);
    assert_eq!(result, "example.com:2222:alice:/home/alice:myhost:deploy");
}

#[test]
fn expand_tokens_with_path() {
    let ctx = TokenContext { host: "h", home_dir: "/home", local_hostname: "l", remote_user: "r", local_user: "u", port: "22" };
    assert_eq!(expand_tokens("/keys/%h/%u", &ctx), "/keys/h/u");
}

#[test]
fn expand_tokens_with_env_var() {
    let ctx = TokenContext { host: "h", home_dir: "/home", local_hostname: "l", remote_user: "r", local_user: "u", port: "22" };
    // %d is home_dir, not an env var
    assert_eq!(expand_tokens("%d/.ssh", &ctx), "/home/.ssh");
}

#[test]
fn match_criteria_host_with_port() {
    // Match criteria with port in host pattern
    assert!(match_criteria_host("host [::1]:22", "[::1]:22"));
}

#[test]
fn match_criteria_host_with_wildcard_port() {
    // Wildcard host should match any port
    assert!(match_criteria_host("host *", "example.com:22"));
}

#[test]
fn match_criteria_host_empty_criteria() {
    // Empty criteria should not match
    assert!(!match_criteria_host("", "host"));
}

#[test]
fn match_criteria_host_only_unknown_keyword() {
    // Only unsupported keywords
    assert!(!match_criteria_host("user alice", "host"));
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
    assert!(simple_glob_match("a", "?"));  // ? matches one char
    assert!(!simple_glob_match("ab", "?")); // ? matches exactly one char
}

#[test]
fn match_criteria_host_negation() {
    // Negation patterns must be comma-separated with positive patterns
    assert!(!match_criteria_host("host *,!badhost", "badhost"));
    assert!(match_criteria_host("host *,!badhost", "goodhost"));
}
