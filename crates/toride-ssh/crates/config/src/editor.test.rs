use super::*;
use crate::ast::{ConfigAst, ConfigNode, parse as parse_ast};

fn make_ast() -> ConfigAst {
    parse_ast(
        "\
Host existing
    HostName existing.com
    User alice

Host other
    HostName other.com
",
    )
}

#[test]
fn add_host_appends_block() {
    let mut ast = make_ast();
    add_host(
        &mut ast,
        "newhost",
        vec![
            ("HostName".to_owned(), "new.com".to_owned()),
            ("User".to_owned(), "bob".to_owned()),
        ],
    )
    .unwrap();

    let found = ast.nodes.iter().find(|n| {
        matches!(n, ConfigNode::HostBlock(b)
            if b.patterns.contains(&"newhost".to_owned())
        )
    });
    assert!(found.is_some());
}

#[test]
fn add_host_rejects_duplicate() {
    let mut ast = make_ast();
    let result = add_host(&mut ast, "existing", vec![]);
    assert!(matches!(
        result,
        Err(toride_ssh_core::Error::DuplicateHost(_))
    ));
}

#[test]
fn remove_host_works() {
    let mut ast = make_ast();
    remove_host(&mut ast, "existing").unwrap();
    assert!(find_host_index(&ast, "existing").is_none());
}

#[test]
fn remove_host_not_found() {
    let mut ast = make_ast();
    let result = remove_host(&mut ast, "nonexistent");
    assert!(matches!(
        result,
        Err(toride_ssh_core::Error::HostNotFound(_))
    ));
}

#[test]
fn rename_host_works() {
    let mut ast = make_ast();
    rename_host(&mut ast, "existing", "renamed").unwrap();
    assert!(find_host_index(&ast, "existing").is_none());
    assert!(find_host_index(&ast, "renamed").is_some());
}

#[test]
fn rename_host_not_found() {
    let mut ast = make_ast();
    let result = rename_host(&mut ast, "nonexistent", "new");
    assert!(matches!(
        result,
        Err(toride_ssh_core::Error::HostNotFound(_))
    ));
}

#[test]
fn rename_host_duplicate_target() {
    let mut ast = make_ast();
    let result = rename_host(&mut ast, "existing", "other");
    assert!(matches!(
        result,
        Err(toride_ssh_core::Error::DuplicateHost(_))
    ));
}

#[test]
fn add_directive_to_host_works() {
    let mut ast = make_ast();
    add_directive_to_host(&mut ast, "existing", "Port", "2222").unwrap();
    let (_patterns, nodes) = ast.nodes[find_host_index(&ast, "existing").unwrap()]
        .as_host_block()
        .unwrap();
    assert!(nodes.iter().any(|n| {
        n.as_directive()
            .is_some_and(|(k, v)| k == "Port" && v == "2222")
    }));
}

#[test]
fn add_directive_to_host_not_found() {
    let mut ast = make_ast();
    let result = add_directive_to_host(&mut ast, "nonexistent", "Port", "22");
    assert!(matches!(
        result,
        Err(toride_ssh_core::Error::HostNotFound(_))
    ));
}

#[test]
fn remove_directive_from_host_works() {
    let mut ast = make_ast();
    remove_directive_from_host(&mut ast, "existing", "User").unwrap();
    let (_patterns, nodes) = ast.nodes[find_host_index(&ast, "existing").unwrap()]
        .as_host_block()
        .unwrap();
    assert!(
        !nodes
            .iter()
            .any(|n| n.as_directive().is_some_and(|(k, _)| k == "User"))
    );
}

#[test]
fn remove_directive_from_host_case_insensitive() {
    let mut ast = make_ast();
    remove_directive_from_host(&mut ast, "existing", "hostname").unwrap();
    let (_patterns, nodes) = ast.nodes[find_host_index(&ast, "existing").unwrap()]
        .as_host_block()
        .unwrap();
    assert!(
        !nodes
            .iter()
            .any(|n| n.as_directive().is_some_and(|(k, _)| k == "HostName"))
    );
}

#[test]
fn remove_directive_from_host_not_found() {
    let mut ast = make_ast();
    let result = remove_directive_from_host(&mut ast, "nonexistent", "Port");
    assert!(matches!(
        result,
        Err(toride_ssh_core::Error::HostNotFound(_))
    ));
}

#[test]
fn add_host_inserts_blank_line_separator() {
    let mut ast = make_ast();
    add_host(
        &mut ast,
        "newhost",
        vec![("HostName".to_owned(), "new.com".to_owned())],
    )
    .unwrap();
    let output = ast.to_string_lossless();
    // There should be a blank line before the new host
    assert!(output.contains("\n\nHost newhost"));
}

#[test]
fn add_host_after_match_block() {
    let mut ast = parse_ast(
        "\
Match exec \"test -f /tmp/x\"
    SetEnv FOO=bar
",
    );
    add_host(
        &mut ast,
        "newhost",
        vec![("HostName".to_owned(), "new.com".to_owned())],
    )
    .unwrap();
    // The Host block should be after the Match block
    let output = ast.to_string_lossless();
    let match_pos = output.find("Match").unwrap();
    let host_pos = output.find("Host newhost").unwrap();
    assert!(host_pos > match_pos);
}
