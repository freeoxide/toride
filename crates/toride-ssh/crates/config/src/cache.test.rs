//! Tests for the mtime-keyed config AST cache.

use std::path::Path;
use std::sync::Arc;
use std::time::SystemTime;

use super::{clear_cache_for_tests, load_cached_ast};

/// Rewrite `path` with `content`, spinning until the file's mtime differs
/// from `previous`.
///
/// Filesystems with coarse mtime granularity could land a rewrite in the
/// same nanosecond stamp as the earlier write — a legitimate cache hit.
/// Tests that assert invalidation need a distinguishable stamp, so we keep
/// rewriting until the mtime actually moves.
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

/// Read the current mtime of a fixture.
fn mtime_of(path: &Path) -> SystemTime {
    std::fs::metadata(path)
        .expect("stat fixture")
        .modified()
        .expect("mtime")
}

#[test]
fn missing_file_returns_not_found_like_read_to_string() {
    clear_cache_for_tests();
    let dir = tempfile::tempdir().expect("tempdir");
    let missing = dir.path().join("config");
    let err = load_cached_ast(&missing).expect_err("missing config must err");
    assert_eq!(
        err.kind(),
        std::io::ErrorKind::NotFound,
        "error kind must match read_to_string semantics"
    );
}

#[test]
fn unchanged_file_shares_one_ast() {
    clear_cache_for_tests();
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("config");
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
    clear_cache_for_tests();
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("config");
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
    // A same-length rewrite still changes mtime, so the (mtime, len) stamp
    // must miss. This pins that content edits which do not change the
    // length are never served stale.
    clear_cache_for_tests();
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("config");
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
    clear_cache_for_tests();
    let dir = tempfile::tempdir().expect("tempdir");
    let a = dir.path().join("config_a");
    let b = dir.path().join("config_b");
    std::fs::write(&a, "Host a\n").expect("write a");
    std::fs::write(&b, "Host b\n").expect("write b");

    let ast_a = load_cached_ast(&a).expect("parse a");
    let ast_b = load_cached_ast(&b).expect("parse b");
    assert!(!Arc::ptr_eq(&ast_a, &ast_b));
}
