use std::path::Path;
use std::sync::Arc;
use std::time::SystemTime;

use super::{clear_cache_for_tests, load_cached_ast, load_cached_content};

fn rewrite_with_new_stamp(path: &Path, previous: SystemTime, content: &str) {
    loop {
        std::fs::write(path, content).expect("write fixture");
        let now = std::fs::metadata(path)
            .expect("stat fixture")
            .modified()
            .expect("mtime");
        if now != previous {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
}

fn mtime_of(path: &Path) -> SystemTime {
    std::fs::metadata(path)
        .expect("stat fixture")
        .modified()
        .expect("mtime")
}

#[test]
fn missing_file_returns_not_found_like_read_to_string() {
    let dir = tempfile::tempdir().expect("tempdir");
    let missing = dir.path().join("config");
    clear_cache_for_tests(&missing);
    let err = load_cached_ast(&missing).expect_err("missing config must err");
    assert_eq!(
        err.kind(),
        std::io::ErrorKind::NotFound,
        "error kind must match read_to_string semantics"
    );
}

#[test]
fn unchanged_file_shares_one_ast() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("config");
    clear_cache_for_tests(&path);
    std::fs::write(&path, "Host alpha\n    User alice\n").expect("write fixture");

    let first = load_cached_ast(&path).expect("parse");
    let second = load_cached_ast(&path).expect("parse");
    assert!(
        Arc::ptr_eq(&first, &second),
        "an unchanged file must serve the same Arc (no re-parse)"
    );
    assert_eq!(first.nodes.len(), 1);
}

#[test]
fn changed_file_reparses() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("config");
    clear_cache_for_tests(&path);
    std::fs::write(&path, "Host alpha\n    User alice\n").expect("write fixture");

    let first = load_cached_ast(&path).expect("parse");
    rewrite_with_new_stamp(&path, mtime_of(&path), "Host alpha\nHost beta\n");
    let second = load_cached_ast(&path).expect("re-parse");

    assert!(
        !Arc::ptr_eq(&first, &second),
        "a rewrite must miss the cache"
    );
    assert_eq!(second.nodes.len(), 2, "the new content must be parsed");
}

#[test]
fn same_length_rewrite_reparses() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("config");
    clear_cache_for_tests(&path);
    std::fs::write(&path, "Host alpha\n").expect("write fixture");
    let first = load_cached_ast(&path).expect("parse");
    assert_eq!(first.nodes.len(), 1);

    rewrite_with_new_stamp(&path, mtime_of(&path), "Host bravo\n");
    let second = load_cached_ast(&path).expect("re-parse");
    let second_host = second
        .nodes
        .iter()
        .find_map(|n| match n {
            crate::ast::ConfigNode::HostBlock(b) => b.patterns.first().cloned(),
            _ => None,
        })
        .expect("host block present");
    assert_eq!(
        second_host, "bravo",
        "same-length rewrite must be re-parsed"
    );
}

#[test]
fn distinct_paths_cache_independently() {
    let dir = tempfile::tempdir().expect("tempdir");
    let a = dir.path().join("config_a");
    let b = dir.path().join("config_b");
    clear_cache_for_tests(&a);
    clear_cache_for_tests(&b);
    std::fs::write(&a, "Host a\n").expect("write a");
    std::fs::write(&b, "Host b\n").expect("write b");

    let ast_a = load_cached_ast(&a).expect("parse a");
    let ast_b = load_cached_ast(&b).expect("parse b");
    assert!(!Arc::ptr_eq(&ast_a, &ast_b));
}

#[test]
fn content_load_shares_one_buffer_for_unchanged_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("config");
    clear_cache_for_tests(&path);
    std::fs::write(&path, "Host alpha\n    VerifyHostKeyDNS yes\n").expect("write fixture");

    let first = load_cached_content(&path).expect("content load");
    let second = load_cached_content(&path).expect("content load");
    assert!(
        Arc::ptr_eq(&first, &second),
        "an unchanged file must serve the same shared content"
    );
    assert!(first.contains("VerifyHostKeyDNS yes"));
}

#[test]
fn ast_after_content_parses_cached_bytes_without_reread() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("config");
    clear_cache_for_tests(&path);
    std::fs::write(&path, "Host alpha\nHost beta\n").expect("write fixture");

    let content = load_cached_content(&path).expect("content load");
    let ast = load_cached_ast(&path).expect("ast load after content");
    assert_eq!(
        ast.nodes.len(),
        2,
        "AST must be parsed from the cached content"
    );
    let content_again = load_cached_content(&path).expect("content reload");
    assert!(
        Arc::ptr_eq(&content, &content_again),
        "the AST fill must not replace the shared content buffer"
    );
    let ast_again = load_cached_ast(&path).expect("ast reload");
    assert!(Arc::ptr_eq(&ast, &ast_again));
}

#[test]
fn content_after_ast_shares_the_same_entry() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("config");
    clear_cache_for_tests(&path);
    std::fs::write(&path, "Host alpha\n").expect("write fixture");

    let ast = load_cached_ast(&path).expect("ast load");
    let content = load_cached_content(&path).expect("content load");
    assert_eq!(ast.nodes.len(), 1);
    assert_eq!(content.as_str(), "Host alpha\n");
}

#[test]
fn changed_file_invalidates_content_too() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("config");
    clear_cache_for_tests(&path);
    std::fs::write(&path, "Host alpha\n").expect("write fixture");
    let first = load_cached_content(&path).expect("content load");

    rewrite_with_new_stamp(&path, mtime_of(&path), "Host bravo\n");
    let second = load_cached_content(&path).expect("content reload");
    assert!(
        !Arc::ptr_eq(&first, &second),
        "a rewrite must invalidate the memoized content"
    );
    assert_eq!(second.as_str(), "Host bravo\n");
}
