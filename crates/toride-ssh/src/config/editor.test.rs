use super::*;
use crate::config::ast::{parse as parse_ast, ConfigAst, ConfigNode};

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

    let found = ast
        .nodes
        .iter()
        .find(|n| matches!(n, ConfigNode::HostBlock { .. } if {
            if let ConfigNode::HostBlock { patterns, .. } = n {
                patterns.contains(&"newhost".to_owned())
            } else {
                false
            }
        }));
    assert!(found.is_some());
}

#[test]
fn add_host_rejects_duplicate() {
    let mut ast = make_ast();
    let result = add_host(&mut ast, "existing", vec![]);
    assert!(matches!(result, Err(crate::Error::DuplicateHost(_))));
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
    assert!(matches!(result, Err(crate::Error::HostNotFound(_))));
}
