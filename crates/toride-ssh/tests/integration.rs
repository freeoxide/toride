//! Integration tests for `toride-ssh`.
//!
//! These tests exercise the public API surface of the crate end-to-end,
//! using fixture files in `tests/fixtures/` and temporary directories.
//!
//! Tests that require file-based SSH operations (config resolution, diagnose,
//! `known_hosts` parsing) manipulate the HOME environment variable to redirect
//! the library to a temporary directory. A global mutex serializes these tests
//! to avoid cross-contamination.

#![allow(
    clippy::significant_drop_tightening,
    clippy::await_holding_lock
)] // Test code with HOME manipulation

use std::path::Path;
use std::sync::{Mutex, PoisonError};

/// Global mutex to serialize tests that manipulate the HOME environment variable.
static HOME_MUTEX: Mutex<()> = Mutex::new(());

/// Helper: read a fixture file by name.
fn fixture(name: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("failed to read fixture {name}: {e}"))
}

// ---------------------------------------------------------------------------
// test_config_ast_roundtrip
// ---------------------------------------------------------------------------

#[test]
fn test_config_ast_roundtrip() {
    let input = fixture("config_basic.txt");
    let ast1 = toride_ssh::config::ast::parse(&input);

    assert!(!ast1.nodes.is_empty(), "parsed AST should have nodes");

    // Serialize back to string.
    let output = ast1.to_string_lossless();

    // Parse again.
    let ast2 = toride_ssh::config::ast::parse(&output);

    // The two ASTs must have the same node count.
    assert_eq!(ast1.nodes.len(), ast2.nodes.len(), "node count mismatch after roundtrip");

    // Serialize again -- must be identical to the first serialization.
    let output2 = ast2.to_string_lossless();
    assert_eq!(output, output2, "roundtrip serialization is not idempotent");

    // Verify that all Host blocks survived the roundtrip.
    let host_count = ast1
        .nodes
        .iter()
        .filter(|n| matches!(n, toride_ssh::config::ast::ConfigNode::HostBlock(_)))
        .count();
    assert_eq!(host_count, 4, "expected 4 Host blocks in config_basic.txt");

    // Verify specific Host block patterns survived.
    let host_patterns: Vec<&str> = ast1
        .nodes
        .iter()
        .filter_map(|n| {
            if let toride_ssh::config::ast::ConfigNode::HostBlock(b) = n {
                Some(b.patterns[0].as_str())
            } else {
                None
            }
        })
        .collect();
    assert_eq!(host_patterns, vec!["web", "db", "bastion", "*"]);
}

#[test]
fn test_config_ast_roundtrip_preserves_comments() {
    let input = fixture("config_conflicts.txt");
    let ast1 = toride_ssh::config::ast::parse(&input);
    let output = ast1.to_string_lossless();
    let ast2 = toride_ssh::config::ast::parse(&output);
    let output2 = ast2.to_string_lossless();
    assert_eq!(output, output2, "conflicts config roundtrip should be idempotent");

    // Verify the comment line survived.
    let has_comment = ast1.nodes.iter().any(|n| {
        matches!(n, toride_ssh::config::ast::ConfigNode::Comment { text, .. } if text.contains("ProxyCommand"))
    });
    assert!(has_comment, "comment about ProxyCommand should survive roundtrip");
}

// ---------------------------------------------------------------------------
// test_config_diagnose_conflicts
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_config_diagnose_conflicts() {
    let _lock = HOME_MUTEX.lock().unwrap_or_else(PoisonError::into_inner);

    let dir = tempfile::tempdir().expect("tempdir");
    let ssh_dir = dir.path().join(".ssh");
    std::fs::create_dir_all(&ssh_dir).unwrap();
    std::fs::write(ssh_dir.join("config"), fixture("config_conflicts.txt")).unwrap();

    let old_home = std::env::var("HOME").ok();
    unsafe { std::env::set_var("HOME", dir.path()); }

    let manager = toride_ssh::SshManager::new().expect("SshManager::new");
    let result = manager.config().diagnose().await;

    if let Some(ref h) = old_home {
        unsafe { std::env::set_var("HOME", h.as_str()); }
    } else {
        unsafe { std::env::remove_var("HOME"); }
    }

    let diags = result.expect("diagnose should succeed");

    // Should detect one ProxyCommand/ProxyJump conflict.
    let proxy_conflicts: Vec<_> = diags
        .iter()
        .filter(|d| d.id == "config_proxy_conflict")
        .collect();
    assert_eq!(proxy_conflicts.len(), 1, "expected one proxy conflict diagnostic");
    assert_eq!(proxy_conflicts[0].severity, toride_ssh::Severity::Warning);
    assert!(proxy_conflicts[0].message.contains("bastion"));
    assert!(proxy_conflicts[0].hint.is_some());

    // Should detect one duplicate alias "dup".
    let duplicates: Vec<_> = diags
        .iter()
        .filter(|d| d.id == "config_duplicate_alias")
        .collect();
    assert_eq!(duplicates.len(), 1, "expected one duplicate alias diagnostic");
    assert!(duplicates[0].message.contains("'dup'"));
}

// ---------------------------------------------------------------------------
// test_config_resolve_tokens
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_config_resolve_tokens() {
    let _lock = HOME_MUTEX.lock().unwrap_or_else(PoisonError::into_inner);

    let dir = tempfile::tempdir().expect("tempdir");
    let ssh_dir = dir.path().join(".ssh");
    std::fs::create_dir_all(&ssh_dir).unwrap();
    std::fs::write(ssh_dir.join("config"), fixture("config_tokens.txt")).unwrap();

    let old_home = std::env::var("HOME").ok();
    unsafe { std::env::set_var("HOME", dir.path()); }

    let manager = toride_ssh::SshManager::new().expect("SshManager::new");

    // Resolve "staging" host.
    let resolved = manager
        .config()
        .resolve_host("staging")
        .await
        .expect("resolve staging should succeed");

    assert_eq!(resolved.alias, "staging");
    assert_eq!(resolved.host_name.as_deref(), Some("staging.example.com"));
    assert_eq!(resolved.user.as_deref(), Some("deploy"));

    // IdentityFile should have %h expanded to "staging".
    assert!(
        resolved.identity_files.iter().any(|f| f.contains("staging")),
        "IdentityFile should have %h expanded, got: {:?}",
        resolved.identity_files
    );

    // ControlPath should have %h and %r expanded.
    let control_path = resolved
        .directives
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("controlpath"))
        .map(|(_, v)| v.as_str());
    if let Some(cp) = control_path {
        assert!(!cp.contains("%h"), "ControlPath should have %h expanded: {cp}");
        assert!(!cp.contains("%r"), "ControlPath should have %r expanded: {cp}");
        assert!(cp.contains("staging"), "ControlPath should contain host name: {cp}");
    }

    // Resolve "production" host.
    let resolved_prod = manager
        .config()
        .resolve_host("production")
        .await
        .expect("resolve production should succeed");

    assert_eq!(resolved_prod.host_name.as_deref(), Some("prod.example.com"));
    assert_eq!(resolved_prod.user.as_deref(), Some("ops"));

    // ProxyCommand should have %h expanded.
    let proxy_cmd = resolved_prod
        .directives
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("proxycommand"))
        .map(|(_, v)| v.as_str());
    if let Some(pc) = proxy_cmd {
        assert!(!pc.contains("%h"), "ProxyCommand should have %h expanded: {pc}");
    }

    // UserKnownHostsFile should have %d and %h expanded.
    let ukhf = resolved_prod
        .directives
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("userknownhostsfile"))
        .map(|(_, v)| v.as_str());
    if let Some(path) = ukhf {
        assert!(!path.contains("%d"), "UserKnownHostsFile should have %d expanded: {path}");
        assert!(!path.contains("%h"), "UserKnownHostsFile should have %h expanded: {path}");
        assert!(path.contains("production"), "UserKnownHostsFile should contain host: {path}");
    }

    if let Some(ref h) = old_home {
        unsafe { std::env::set_var("HOME", h.as_str()); }
    } else {
        unsafe { std::env::remove_var("HOME"); }
    }
}

// ---------------------------------------------------------------------------
// test_config_resolve_identity_file_token
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_config_resolve_identity_file_token() {
    let _lock = HOME_MUTEX.lock().unwrap_or_else(PoisonError::into_inner);

    let dir = tempfile::tempdir().expect("tempdir");
    let ssh_dir = dir.path().join(".ssh");
    std::fs::create_dir_all(&ssh_dir).unwrap();
    // Config with %u token in IdentityFile (not %i, which is the same as %u)
    std::fs::write(
        ssh_dir.join("config"),
        "Host work\n    IdentityFile ~/.ssh/work/%u\n",
    )
    .unwrap();

    let old_home = std::env::var("HOME").ok();
    unsafe { std::env::set_var("HOME", dir.path()); }

    let manager = toride_ssh::SshManager::new().expect("SshManager::new");
    let resolved = manager
        .config()
        .resolve_host("work")
        .await
        .expect("resolve should succeed");

    if let Some(ref h) = old_home {
        unsafe { std::env::set_var("HOME", h.as_str()); }
    } else {
        unsafe { std::env::remove_var("HOME"); }
    }

    // %u should expand to the local username.
    let id_file = resolved
        .identity_files
        .first()
        .expect("should have identity file");

    assert!(
        !id_file.contains("%u"),
        "%u token should have been expanded, got: {id_file}"
    );

    // The expanded path should contain a real username (not a token).
    // We can't easily get the username in tests, but we can verify the
    // tilde was expanded and %u was replaced with something.
    assert!(
        !id_file.contains('~'),
        "tilde should have been expanded, got: {id_file}"
    );
    assert!(
        id_file.ends_with("/work") || !id_file.contains("%"),
        "all tokens should have been expanded, got: {id_file}"
    );
}

// ---------------------------------------------------------------------------
// test_known_hosts_parse_markers
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_known_hosts_parse_markers() {
    let _lock = HOME_MUTEX.lock().unwrap_or_else(PoisonError::into_inner);

    let dir = tempfile::tempdir().expect("tempdir");
    let ssh_dir = dir.path().join(".ssh");
    std::fs::create_dir_all(&ssh_dir).unwrap();
    // Write an empty config so SshPaths::new -> ConfigService doesn't complain.
    std::fs::write(ssh_dir.join("config"), "").unwrap();
    std::fs::write(ssh_dir.join("known_hosts"), fixture("known_hosts_markers.txt")).unwrap();

    let old_home = std::env::var("HOME").ok();
    unsafe { std::env::set_var("HOME", dir.path()); }

    let manager = toride_ssh::SshManager::new().expect("SshManager::new");
    let result = manager.known_hosts().list().await;

    if let Some(ref h) = old_home {
        unsafe { std::env::set_var("HOME", h.as_str()); }
    } else {
        unsafe { std::env::remove_var("HOME"); }
    }

    let entries = result.expect("list should succeed");

    // The fixture has 9 non-comment, non-blank lines.
    assert_eq!(entries.len(), 9, "expected 9 entries, got {}", entries.len());

    // Verify standard entry.
    let standard = &entries[0];
    assert!(standard.markers.is_empty());
    assert_eq!(standard.hosts, vec!["github.com"]);
    assert_eq!(standard.key_type, "ssh-ed25519");
    assert!(standard.comment.is_none());

    // Verify entry with trailing comment.
    let commented = &entries[1];
    assert_eq!(commented.hosts, vec!["gitlab.com"]);
    assert_eq!(commented.comment.as_deref(), Some("user@host"));

    // Verify @cert-authority with wildcard host.
    let ca_wildcard = &entries[2];
    assert_eq!(ca_wildcard.markers, vec!["@cert-authority"]);
    assert_eq!(ca_wildcard.hosts, vec!["*.example.com"]);

    // Verify @cert-authority with specific host and RSA key.
    let ca_specific = &entries[3];
    assert_eq!(ca_specific.markers, vec!["@cert-authority"]);
    assert_eq!(ca_specific.hosts, vec!["ca.example.com"]);
    assert_eq!(ca_specific.key_type, "ssh-rsa");

    // Verify @revoked entry.
    let revoked = &entries[4];
    assert_eq!(revoked.markers, vec!["@revoked"]);
    assert_eq!(revoked.hosts, vec!["revoked.example.com"]);

    // Verify hashed hostname entry.
    let hashed = &entries[5];
    assert!(hashed.hosts[0].starts_with("|1|"), "hashed host should start with |1|");

    // Verify bracketed host:port.
    let bracketed = &entries[6];
    assert_eq!(bracketed.hosts, vec!["[custom.example.com]:2222"]);

    // Verify comma-separated hosts.
    let multi_host = &entries[7];
    assert_eq!(multi_host.hosts, vec!["host1.example.com", "host2.example.com"]);
    assert_eq!(multi_host.key_type, "ssh-rsa");

    // Verify ECDSA key type.
    let ecdsa = &entries[8];
    assert_eq!(ecdsa.hosts, vec!["ecdsa-host.example.com"]);
    assert_eq!(ecdsa.key_type, "ecdsa-sha2-nistp256");

    // Verify line numbers are tracked correctly.
    assert_eq!(standard.line_number, 4, "standard entry should be on line 4");
    assert_eq!(revoked.line_number, 16, "revoked entry should be on line 16");
    assert_eq!(ecdsa.line_number, 28, "ecdsa entry should be on line 28");
}
