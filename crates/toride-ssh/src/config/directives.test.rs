use super::*;
use crate::config::ast::{parse as parse_ast, ConfigAst};

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
    assert!(host_matches_patterns("Example.COM", &["example.com".to_owned()]));
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
    assert!(is_accumulative("proxyjump"));
    assert!(is_accumulative("forwardagent"));
    assert!(!is_accumulative("hostname"));
    assert!(!is_accumulative("user"));
    assert!(!is_accumulative("port"));
}
