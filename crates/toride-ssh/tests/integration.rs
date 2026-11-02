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
    clippy::await_holding_lock,
    reason = "tests hold the HOME lock across awaits by design"
)]

use std::path::Path;
use std::sync::{Mutex, PoisonError};

static HOME_MUTEX: Mutex<()> = Mutex::new(());

fn fixture(name: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("failed to read fixture {name}: {e}"))
}

#[test]
fn test_config_ast_roundtrip() {
    let input = fixture("config_basic.txt");
    let ast1 = toride_ssh::config::ast::parse(&input);

    assert!(!ast1.nodes.is_empty(), "parsed AST should have nodes");

    let output = ast1.to_string_lossless();
    let ast2 = toride_ssh::config::ast::parse(&output);

    assert_eq!(
        ast1.nodes.len(),
        ast2.nodes.len(),
        "node count mismatch after roundtrip"
    );

    let output2 = ast2.to_string_lossless();
    assert_eq!(output, output2, "roundtrip serialization is not idempotent");

    let host_count = ast1
        .nodes
        .iter()
        .filter(|n| matches!(n, toride_ssh::config::ast::ConfigNode::HostBlock(_)))
        .count();
    assert_eq!(host_count, 4, "expected 4 Host blocks in config_basic.txt");

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
    assert_eq!(
        output, output2,
        "conflicts config roundtrip should be idempotent"
    );

    let has_comment = ast1.nodes.iter().any(|n| {
        matches!(n, toride_ssh::config::ast::ConfigNode::Comment { text, .. } if text.contains("ProxyCommand"))
    });
    assert!(
        has_comment,
        "comment about ProxyCommand should survive roundtrip"
    );
}

#[tokio::test]
async fn test_config_diagnose_conflicts() {
    let _lock = HOME_MUTEX.lock().unwrap_or_else(PoisonError::into_inner);

    let dir = tempfile::tempdir().expect("tempdir");
    let ssh_dir = dir.path().join(".ssh");
    std::fs::create_dir_all(&ssh_dir).unwrap();
    std::fs::write(ssh_dir.join("config"), fixture("config_conflicts.txt")).unwrap();

    let old_home = std::env::var("HOME").ok();
    unsafe {
        std::env::set_var("HOME", dir.path());
    }

    let manager = toride_ssh::SshManager::new().expect("SshManager::new");
    let result = manager.config().diagnose().await;

    if let Some(ref h) = old_home {
        unsafe {
            std::env::set_var("HOME", h.as_str());
        }
    } else {
        unsafe {
            std::env::remove_var("HOME");
        }
    }

    let diags = result.expect("diagnose should succeed");

    let proxy_conflicts: Vec<_> = diags
        .iter()
        .filter(|d| d.id == "config_proxy_conflict")
        .collect();
    assert_eq!(
        proxy_conflicts.len(),
        1,
        "expected one proxy conflict diagnostic"
    );
    assert_eq!(
        proxy_conflicts[0].severity,
        toride_ssh::DiagnosticSeverity::Warning
    );
    assert!(proxy_conflicts[0].message.contains("bastion"));
    assert!(proxy_conflicts[0].hint.is_some());

    let duplicates: Vec<_> = diags
        .iter()
        .filter(|d| d.id == "config_duplicate_alias")
        .collect();
    assert_eq!(
        duplicates.len(),
        1,
        "expected one duplicate alias diagnostic"
    );
    assert!(duplicates[0].message.contains("'dup'"));
}

#[tokio::test]
async fn test_config_resolve_tokens() {
    let _lock = HOME_MUTEX.lock().unwrap_or_else(PoisonError::into_inner);

    let dir = tempfile::tempdir().expect("tempdir");
    let ssh_dir = dir.path().join(".ssh");
    std::fs::create_dir_all(&ssh_dir).unwrap();
    std::fs::write(ssh_dir.join("config"), fixture("config_tokens.txt")).unwrap();

    let old_home = std::env::var("HOME").ok();
    unsafe {
        std::env::set_var("HOME", dir.path());
    }

    let manager = toride_ssh::SshManager::new().expect("SshManager::new");

    let resolved = manager
        .config()
        .resolve_host("staging")
        .await
        .expect("resolve staging should succeed");

    assert_eq!(resolved.alias, "staging");
    assert_eq!(resolved.host_name.as_deref(), Some("staging.example.com"));
    assert_eq!(resolved.user.as_deref(), Some("deploy"));

    assert!(
        resolved
            .identity_files
            .iter()
            .any(|f| f.contains("staging")),
        "Identity_files should have %h expanded, got: {:?}",
        resolved.identity_files
    );

    let control_path = directive(&resolved, "controlpath");
    assert!(
        !control_path.contains("%h"),
        "ControlPath should have %h expanded: {control_path}"
    );
    assert!(
        !control_path.contains("%r"),
        "ControlPath should have %r expanded: {control_path}"
    );
    assert!(
        control_path.contains("staging"),
        "ControlPath should contain host name: {control_path}"
    );

    let resolved_prod = manager
        .config()
        .resolve_host("production")
        .await
        .expect("resolve production should succeed");

    assert_eq!(resolved_prod.host_name.as_deref(), Some("prod.example.com"));
    assert_eq!(resolved_prod.user.as_deref(), Some("ops"));

    let proxy_cmd = directive(&resolved_prod, "proxycommand");
    assert!(
        !proxy_cmd.contains("%h"),
        "ProxyCommand should have %h expanded: {proxy_cmd}"
    );

    let ukhf = directive(&resolved_prod, "userknownhostsfile");
    assert!(
        !ukhf.contains("%d"),
        "UserKnownHostsFile should have %d expanded: {ukhf}"
    );
    assert!(
        !ukhf.contains("%h"),
        "UserKnownHostsFile should have %h expanded: {ukhf}"
    );
    assert!(
        ukhf.contains("production"),
        "UserKnownHostsFile should contain host: {ukhf}"
    );

    if let Some(ref h) = old_home {
        unsafe {
            std::env::set_var("HOME", h.as_str());
        }
    } else {
        unsafe {
            std::env::remove_var("HOME");
        }
    }
}

fn directive(resolved: &toride_ssh::config::ResolvedHost, keyword: &str) -> String {
    let (_, value) = resolved
        .directives
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(keyword))
        .unwrap_or_else(|| panic!("resolved host must carry a {keyword} directive"));
    value.as_str().to_owned()
}

#[tokio::test]
async fn test_config_resolve_identity_file_token() {
    let _lock = HOME_MUTEX.lock().unwrap_or_else(PoisonError::into_inner);

    let dir = tempfile::tempdir().expect("tempdir");
    let ssh_dir = dir.path().join(".ssh");
    std::fs::create_dir_all(&ssh_dir).unwrap();
    std::fs::write(
        ssh_dir.join("config"),
        "Host work\n    IdentityFile ~/.ssh/work/%u\n",
    )
    .unwrap();

    let old_home = std::env::var("HOME").ok();
    unsafe {
        std::env::set_var("HOME", dir.path());
    }

    let manager = toride_ssh::SshManager::new().expect("SshManager::new");
    let resolved = manager
        .config()
        .resolve_host("work")
        .await
        .expect("resolve should succeed");

    if let Some(ref h) = old_home {
        unsafe {
            std::env::set_var("HOME", h.as_str());
        }
    } else {
        unsafe {
            std::env::remove_var("HOME");
        }
    }

    let id_file = resolved
        .identity_files
        .first()
        .expect("should have identity file");

    assert!(
        !id_file.contains("%u"),
        "%u token should have been expanded, got: {id_file}"
    );
    // The username is environment-dependent, so the assertion can only pin
    // that no token and no tilde survived the expansion.
    assert!(
        !id_file.contains('~'),
        "tilde should have been expanded, got: {id_file}"
    );
    assert!(
        id_file.ends_with("/work") || !id_file.contains('%'),
        "all tokens should have been expanded, got: {id_file}"
    );
}

#[cfg(feature = "known-hosts")]
#[tokio::test]
async fn test_known_hosts_parse_markers() {
    let _lock = HOME_MUTEX.lock().unwrap_or_else(PoisonError::into_inner);

    let dir = tempfile::tempdir().expect("tempdir");
    let ssh_dir = dir.path().join(".ssh");
    std::fs::create_dir_all(&ssh_dir).unwrap();
    std::fs::write(ssh_dir.join("config"), "").unwrap();
    std::fs::write(
        ssh_dir.join("known_hosts"),
        fixture("known_hosts_markers.txt"),
    )
    .unwrap();

    let old_home = std::env::var("HOME").ok();
    unsafe {
        std::env::set_var("HOME", dir.path());
    }

    let manager = toride_ssh::SshManager::new().expect("SshManager::new");
    let result = manager.known_hosts().list().await;

    if let Some(ref h) = old_home {
        unsafe {
            std::env::set_var("HOME", h.as_str());
        }
    } else {
        unsafe {
            std::env::remove_var("HOME");
        }
    }

    let entries = result.expect("list should succeed");

    assert_eq!(entries.len(), 9, "expected 9 entries");

    let standard = &entries[0];
    assert_eq!(standard.markers, Vec::<String>::new());
    assert_eq!(standard.hosts, vec!["github.com"]);
    assert_eq!(standard.key_type, "ssh-ed25519");
    assert!(standard.comment.is_none());

    let commented = &entries[1];
    assert_eq!(commented.hosts, vec!["gitlab.com"]);
    assert_eq!(commented.comment.as_deref(), Some("user@host"));

    let ca_wildcard = &entries[2];
    assert_eq!(ca_wildcard.markers, vec!["@cert-authority"]);
    assert_eq!(ca_wildcard.hosts, vec!["*.example.com"]);

    let ca_specific = &entries[3];
    assert_eq!(ca_specific.markers, vec!["@cert-authority"]);
    assert_eq!(ca_specific.hosts, vec!["ca.example.com"]);
    assert_eq!(ca_specific.key_type, "ssh-rsa");

    let revoked = &entries[4];
    assert_eq!(revoked.markers, vec!["@revoked"]);
    assert_eq!(revoked.hosts, vec!["revoked.example.com"]);

    let hashed = &entries[5];
    assert!(
        hashed.hosts[0].starts_with("|1|"),
        "hashed host should start with |1|"
    );

    let bracketed = &entries[6];
    assert_eq!(bracketed.hosts, vec!["[custom.example.com]:2222"]);

    let multi_host = &entries[7];
    assert_eq!(
        multi_host.hosts,
        vec!["host1.example.com", "host2.example.com"]
    );
    assert_eq!(multi_host.key_type, "ssh-rsa");

    let ecdsa = &entries[8];
    assert_eq!(ecdsa.hosts, vec!["ecdsa-host.example.com"]);
    assert_eq!(ecdsa.key_type, "ecdsa-sha2-nistp256");

    assert_eq!(
        standard.line_number, 4,
        "standard entry should be on line 4"
    );
    assert_eq!(
        revoked.line_number, 16,
        "revoked entry should be on line 16"
    );
    assert_eq!(ecdsa.line_number, 28, "ecdsa entry should be on line 28");
}
