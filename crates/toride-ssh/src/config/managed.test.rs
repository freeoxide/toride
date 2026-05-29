use super::*;
use crate::config::ast::{parse as parse_ast, ConfigAst};

fn make_ast_with_managed() -> ConfigAst {
    parse_ast(
        "\
Host existing
    HostName existing.com

# >>> toride test-block
    HostName managed.com
    User managed
# <<< toride test-block

Host other
    HostName other.com
",
    )
}

#[test]
fn extract_managed_block_works() {
    let ast = make_ast_with_managed();
    let block = extract_managed_block(&ast, "test-block");
    assert!(block.is_some());
    let block = block.unwrap();
    assert_eq!(block.name, "test-block");
    assert_eq!(block.nodes.len(), 2);
}

#[test]
fn extract_missing_returns_none() {
    let ast = make_ast_with_managed();
    let block = extract_managed_block(&ast, "nonexistent");
    assert!(block.is_none());
}

#[test]
fn list_managed_blocks_works() {
    let ast = make_ast_with_managed();
    let names = list_managed_blocks(&ast);
    assert_eq!(names, vec!["test-block"]);
}

#[test]
fn upsert_new_block_appends() {
    let mut ast = parse_ast("Host foo\n    HostName foo.com\n");
    upsert_managed_block(
        &mut ast,
        "myblock",
        vec![("HostName".to_owned(), "new.com".to_owned())],
    );

    assert!(has_managed_block(&ast, "myblock"));
    let block = extract_managed_block(&ast, "myblock").unwrap();
    assert_eq!(block.nodes.len(), 1);
}

#[test]
fn upsert_replaces_existing() {
    let mut ast = make_ast_with_managed();
    upsert_managed_block(
        &mut ast,
        "test-block",
        vec![("HostName".to_owned(), "replaced.com".to_owned())],
    );

    let block = extract_managed_block(&ast, "test-block").unwrap();
    assert_eq!(block.nodes.len(), 1);
    assert_eq!(
        block.nodes[0].as_directive().unwrap().1,
        "replaced.com"
    );
}

#[test]
fn remove_managed_block_works() {
    let mut ast = make_ast_with_managed();
    remove_managed_block(&mut ast, "test-block").unwrap();
    assert!(!has_managed_block(&ast, "test-block"));
}
