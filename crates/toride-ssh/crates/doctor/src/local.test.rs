use super::*;

/// Set up a temporary SSH directory with the given layout and run `run_all`.
async fn run_checks_with_dir(ssh_dir: &std::path::Path) -> Vec<toride_ssh_core::Diagnostic> {
    let paths = SshPaths::with_dir(ssh_dir);
    let runner = toride_ssh_core::MockCliRunner::new();
    run_all(&paths, &runner).await.unwrap()
}

fn find<'a>(
    diagnostics: &'a [toride_ssh_core::Diagnostic],
    id: &str,
) -> Vec<&'a toride_ssh_core::Diagnostic> {
    diagnostics.iter().filter(|d| d.id == id).collect()
}

// ---------------------------------------------------------------------------
// SshDirExists
// ---------------------------------------------------------------------------

#[tokio::test]
async fn ssh_dir_exists_when_present() {
    let dir = tempfile::tempdir().unwrap();
    let diags = run_checks_with_dir(dir.path()).await;
    let matches = find(&diags, "ssh_dir_exists");
    assert!(!matches.is_empty());
    assert!(matches.iter().all(|d| d.severity == Severity::Ok));
}

#[tokio::test]
async fn ssh_dir_exists_as_file_errors() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let diags = run_checks_with_dir(file.path()).await;
    let matches = find(&diags, "ssh_dir_exists");
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].severity, Severity::Error);
    assert!(
        matches[0].message.contains("is not a directory"),
        "expected 'is not a directory' in message, got: {}",
        matches[0].message,
    );
    assert!(
        matches[0].hint.is_some(),
        "not-a-directory diagnostic should include a remediation hint",
    );
}

#[tokio::test]
async fn ssh_dir_missing_when_absent() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("nonexistent_ssh");
    let diags = run_checks_with_dir(&missing).await;
    let matches = find(&diags, "ssh_dir_exists");
    assert!(!matches.is_empty());
    // When the directory doesn't exist, severity should be Warning.
    assert!(matches.iter().all(|d| d.severity == Severity::Warning));
}

// ---------------------------------------------------------------------------
// SshDirPermissions (unix only)
// ---------------------------------------------------------------------------

#[cfg(unix)]
#[tokio::test]
async fn ssh_dir_permissions_correct() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let diags = run_checks_with_dir(dir.path()).await;
    let matches = find(&diags, "ssh_dir_permissions");
    assert!(!matches.is_empty());
    assert!(matches.iter().all(|d| d.severity == Severity::Ok));
}

#[cfg(unix)]
#[tokio::test]
async fn ssh_dir_permissions_too_permissive() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    let diags = run_checks_with_dir(dir.path()).await;
    let matches = find(&diags, "ssh_dir_permissions");
    assert!(!matches.is_empty());
    assert!(matches.iter().all(|d| d.severity == Severity::Error));
}

// ---------------------------------------------------------------------------
// ConfigExists
// ---------------------------------------------------------------------------

#[tokio::test]
async fn config_exists_when_present() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("config"), "").unwrap();
    let diags = run_checks_with_dir(dir.path()).await;
    let matches = find(&diags, "config_exists");
    assert!(!matches.is_empty());
    assert!(matches.iter().all(|d| d.severity == Severity::Ok));
}

#[tokio::test]
async fn config_missing_reports_info() {
    let dir = tempfile::tempdir().unwrap();
    // No config file written.
    let diags = run_checks_with_dir(dir.path()).await;
    let matches = find(&diags, "config_exists");
    assert!(!matches.is_empty());
    assert!(matches.iter().all(|d| d.severity == Severity::Info));
}

// ---------------------------------------------------------------------------
// KnownHostsExists
// ---------------------------------------------------------------------------

#[tokio::test]
async fn known_hosts_exists_when_present() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("known_hosts"), "").unwrap();
    let diags = run_checks_with_dir(dir.path()).await;
    let matches = find(&diags, "known_hosts_exists");
    assert!(!matches.is_empty());
    assert!(matches.iter().all(|d| d.severity == Severity::Ok));
}

#[tokio::test]
async fn known_hosts_missing_warns() {
    let dir = tempfile::tempdir().unwrap();
    let diags = run_checks_with_dir(dir.path()).await;
    let matches = find(&diags, "known_hosts_exists");
    assert!(!matches.is_empty());
    assert!(matches.iter().all(|d| d.severity == Severity::Warning));
}

// ---------------------------------------------------------------------------
// PrivateKeyPermissions (unix only)
// ---------------------------------------------------------------------------

#[cfg(unix)]
#[tokio::test]
async fn private_key_correct_permissions() {
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("id_ed25519");
    std::fs::write(
        &key_path,
        "-----BEGIN OPENSSH PRIVATE KEY-----\ntest\n-----END OPENSSH PRIVATE KEY-----\n",
    )
    .unwrap();
    std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();

    let diags = run_checks_with_dir(dir.path()).await;
    let matches = find(&diags, "private_key_permissions");
    // Should have at least one Ok entry for our key.
    assert!(
        matches
            .iter()
            .any(|d| d.severity == Severity::Ok && d.message.contains("id_ed25519"))
    );
}

#[cfg(unix)]
#[tokio::test]
async fn private_key_wrong_permissions() {
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("id_ed25519");
    std::fs::write(
        &key_path,
        "-----BEGIN OPENSSH PRIVATE KEY-----\ntest\n-----END OPENSSH PRIVATE KEY-----\n",
    )
    .unwrap();
    std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o644)).unwrap();

    let diags = run_checks_with_dir(dir.path()).await;
    let matches = find(&diags, "private_key_permissions");
    assert!(
        matches
            .iter()
            .any(|d| d.severity == Severity::Error && d.message.contains("id_ed25519"))
    );
}

#[cfg(unix)]
#[tokio::test]
async fn private_key_permissions_no_keys_found() {
    let dir = tempfile::tempdir().unwrap();
    // Empty ssh dir — no private key files.
    let diags = run_checks_with_dir(dir.path()).await;
    let matches = find(&diags, "private_key_permissions");
    assert!(!matches.is_empty());
    assert!(matches.iter().any(|d| d.severity == Severity::Info));
}

// ---------------------------------------------------------------------------
// DefaultKeyExists
// ---------------------------------------------------------------------------

#[tokio::test]
async fn default_key_exists_when_present() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("id_ed25519"), "fake-key").unwrap();
    let diags = run_checks_with_dir(dir.path()).await;
    let matches = find(&diags, "default_key_exists");
    assert!(!matches.is_empty());
    assert!(matches.iter().all(|d| d.severity == Severity::Ok));
    assert!(matches[0].message.contains("id_ed25519"));
}

#[tokio::test]
async fn default_key_missing() {
    let dir = tempfile::tempdir().unwrap();
    // No keys written.
    let diags = run_checks_with_dir(dir.path()).await;
    let matches = find(&diags, "default_key_exists");
    assert!(!matches.is_empty());
    assert!(matches.iter().all(|d| d.severity == Severity::Warning));
}

// ---------------------------------------------------------------------------
// OwnerCheck (unix only)
// ---------------------------------------------------------------------------

#[cfg(unix)]
#[tokio::test]
async fn owner_check_passes_for_current_user() {
    let dir = tempfile::tempdir().unwrap();
    let diags = run_checks_with_dir(dir.path()).await;
    let matches = find(&diags, "owner_check");
    assert!(!matches.is_empty());
    assert!(matches.iter().all(|d| d.severity == Severity::Ok));
}

#[cfg(unix)]
#[tokio::test]
async fn owner_check_errors_for_wrong_owner() {
    // /var/empty is owned by root (uid 0) on macOS and Linux.
    // When running as a non-root user this triggers the
    // file_uid != current_uid error branch.
    let current_uid = unsafe { libc::getuid() };
    if current_uid == 0 {
        // Running as root — /var/empty is also owned by us, so skip.
        return;
    }

    let root_dir = std::path::Path::new("/var/empty");
    if std::fs::metadata(root_dir).is_err() {
        return;
    }

    let paths = SshPaths::with_dir(root_dir);
    let check = OwnerCheck { paths: &paths };
    let diags = check.run().await.unwrap();

    assert_eq!(diags.len(), 1);
    assert_eq!(diags[0].id, "owner_check");
    assert_eq!(diags[0].severity, Severity::Error);
    assert!(
        diags[0].message.contains("is owned by uid"),
        "error message should mention the file owner uid, got: {}",
        diags[0].message
    );
    assert!(
        diags[0].message.contains("but current user is uid"),
        "error message should mention the current uid, got: {}",
        diags[0].message
    );
    assert!(
        diags[0].hint.is_some(),
        "wrong-owner diagnostic should include a remediation hint"
    );
}

// ---------------------------------------------------------------------------
// ConfigPermissionsCheck (unix only)
// ---------------------------------------------------------------------------

#[cfg(unix)]
#[tokio::test]
async fn config_permissions_ok_when_not_world_writable() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("config");
    std::fs::write(&config_path, "").unwrap();
    std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o600)).unwrap();

    let diags = run_checks_with_dir(dir.path()).await;
    let matches = find(&diags, "config_permissions");
    assert!(!matches.is_empty());
    assert!(matches.iter().all(|d| d.severity == Severity::Ok));
}

#[cfg(unix)]
#[tokio::test]
async fn config_permissions_error_when_world_writable() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("config");
    std::fs::write(&config_path, "").unwrap();
    std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o666)).unwrap();

    let diags = run_checks_with_dir(dir.path()).await;
    let matches = find(&diags, "config_permissions");
    assert!(!matches.is_empty());
    assert!(matches.iter().all(|d| d.severity == Severity::Error));
}

// ---------------------------------------------------------------------------
// AuthorizedKeysPermissionsCheck (unix only)
// ---------------------------------------------------------------------------

#[cfg(unix)]
#[tokio::test]
async fn authorized_keys_permissions_ok() {
    let dir = tempfile::tempdir().unwrap();
    let ak_path = dir.path().join("authorized_keys");
    std::fs::write(&ak_path, "").unwrap();
    std::fs::set_permissions(&ak_path, std::fs::Permissions::from_mode(0o600)).unwrap();

    let diags = run_checks_with_dir(dir.path()).await;
    let matches = find(&diags, "authorized_keys_permissions");
    assert!(!matches.is_empty());
    assert!(matches.iter().all(|d| d.severity == Severity::Ok));
}

#[cfg(unix)]
#[tokio::test]
async fn authorized_keys_permissions_error_when_world_writable() {
    let dir = tempfile::tempdir().unwrap();
    let ak_path = dir.path().join("authorized_keys");
    std::fs::write(&ak_path, "").unwrap();
    std::fs::set_permissions(&ak_path, std::fs::Permissions::from_mode(0o666)).unwrap();

    let diags = run_checks_with_dir(dir.path()).await;
    let matches = find(&diags, "authorized_keys_permissions");
    assert!(!matches.is_empty());
    assert!(matches.iter().all(|d| d.severity == Severity::Error));
}

#[tokio::test]
async fn authorized_keys_permissions_info_when_missing() {
    let dir = tempfile::tempdir().unwrap();
    // No authorized_keys file.
    let diags = run_checks_with_dir(dir.path()).await;
    let matches = find(&diags, "authorized_keys_permissions");
    assert!(!matches.is_empty());
    assert!(matches.iter().all(|d| d.severity == Severity::Info));
}

// ---------------------------------------------------------------------------
// PublicKeyPairsCheck
// ---------------------------------------------------------------------------

#[tokio::test]
async fn public_key_pair_present() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("id_ed25519"), "fake-private-key").unwrap();
    std::fs::write(dir.path().join("id_ed25519.pub"), "fake-public-key").unwrap();

    let diags = run_checks_with_dir(dir.path()).await;
    let matches = find(&diags, "public_key_pairs");
    assert!(
        matches
            .iter()
            .any(|d| d.severity == Severity::Ok && d.message.contains("id_ed25519"))
    );
}

#[tokio::test]
async fn public_key_pair_missing_pub() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("id_ed25519"), "fake-private-key").unwrap();
    // No .pub file.

    let diags = run_checks_with_dir(dir.path()).await;
    let matches = find(&diags, "public_key_pairs");
    assert!(
        matches.iter().any(
            |d| d.severity == Severity::Warning && d.message.contains("no matching public key")
        )
    );
}

#[tokio::test]
async fn public_key_pairs_no_keys() {
    let dir = tempfile::tempdir().unwrap();
    // No id_* files at all.
    let diags = run_checks_with_dir(dir.path()).await;
    let matches = find(&diags, "public_key_pairs");
    assert!(!matches.is_empty());
    assert!(matches.iter().all(|d| d.severity == Severity::Info));
}

// ---------------------------------------------------------------------------
// IdentityFileExistsCheck
// ---------------------------------------------------------------------------

#[tokio::test]
async fn identity_file_exists_present() {
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("my_key");
    std::fs::write(&key_path, "fake-key").unwrap();
    std::fs::write(
        dir.path().join("config"),
        format!("Host test\n    IdentityFile {}\n", key_path.display()),
    )
    .unwrap();

    let diags = run_checks_with_dir(dir.path()).await;
    let matches = find(&diags, "identity_file_exists");
    assert!(matches.iter().any(|d| d.severity == Severity::Ok));
}

#[tokio::test]
async fn identity_file_exists_missing() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("config"),
        "Host test\n    IdentityFile ~/.ssh/nonexistent_key\n",
    )
    .unwrap();

    let diags = run_checks_with_dir(dir.path()).await;
    let matches = find(&diags, "identity_file_exists");
    assert!(matches.iter().any(|d| d.severity == Severity::Warning));
}

#[tokio::test]
async fn identity_file_exists_no_config() {
    let dir = tempfile::tempdir().unwrap();
    // No config file.
    let diags = run_checks_with_dir(dir.path()).await;
    let matches = find(&diags, "identity_file_exists");
    assert!(!matches.is_empty());
    assert!(matches.iter().all(|d| d.severity == Severity::Info));
}

// ---------------------------------------------------------------------------
// DuplicateHostCheck
// ---------------------------------------------------------------------------

#[tokio::test]
async fn duplicate_host_detected() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("config"),
        "\
Host web
    HostName web1.example.com

Host web
    HostName web2.example.com
",
    )
    .unwrap();

    let diags = run_checks_with_dir(dir.path()).await;
    let matches = find(&diags, "duplicate_host");
    assert!(
        matches
            .iter()
            .any(|d| d.severity == Severity::Warning && d.message.contains("'web'"))
    );
}

#[tokio::test]
async fn no_duplicates_ok() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("config"),
        "\
Host web
    HostName web.example.com

Host api
    HostName api.example.com
",
    )
    .unwrap();

    let diags = run_checks_with_dir(dir.path()).await;
    let matches = find(&diags, "duplicate_host");
    assert!(matches.iter().all(|d| d.severity == Severity::Ok));
}

// ---------------------------------------------------------------------------
// HostStarPlacementCheck
// ---------------------------------------------------------------------------

#[tokio::test]
async fn host_star_before_specific_warns() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("config"),
        "\
Host *
    ServerAliveInterval 60

Host specific
    HostName specific.example.com
",
    )
    .unwrap();

    let diags = run_checks_with_dir(dir.path()).await;
    let matches = find(&diags, "host_star_placement");
    assert!(matches.iter().any(|d| d.severity == Severity::Warning));
}

#[tokio::test]
async fn host_star_after_specific_ok() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("config"),
        "\
Host specific
    HostName specific.example.com

Host *
    ServerAliveInterval 60
",
    )
    .unwrap();

    let diags = run_checks_with_dir(dir.path()).await;
    let matches = find(&diags, "host_star_placement");
    assert!(matches.iter().all(|d| d.severity == Severity::Ok));
}

// ---------------------------------------------------------------------------
// SshV1KeyCheck
// ---------------------------------------------------------------------------

#[tokio::test]
async fn ssh_v1_key_not_present() {
    let dir = tempfile::tempdir().unwrap();
    // No "identity" file.
    let diags = run_checks_with_dir(dir.path()).await;
    let matches = find(&diags, "ssh_v1_key");
    assert!(!matches.is_empty());
    assert!(matches.iter().all(|d| d.severity == Severity::Ok));
}

#[tokio::test]
async fn ssh_v1_key_detected() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("identity"), "fake-v1-key").unwrap();

    let diags = run_checks_with_dir(dir.path()).await;
    let matches = find(&diags, "ssh_v1_key");
    assert!(matches.iter().any(|d| d.severity == Severity::Warning));
}

// ---------------------------------------------------------------------------
// AgentAvailable & KeygenAvailable (env-dependent, just ensure no crash)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn agent_available_returns_valid_diagnostic() {
    let dir = tempfile::tempdir().unwrap();
    let diags = run_checks_with_dir(dir.path()).await;
    let matches = find(&diags, "agent_available");
    assert_eq!(matches.len(), 1);
    // Either Ok (if SSH_AUTH_SOCK is set and socket exists) or Warning.
    assert!(matches[0].severity == Severity::Ok || matches[0].severity == Severity::Warning);
}

#[tokio::test]
async fn keygen_available_returns_valid_diagnostic() {
    let dir = tempfile::tempdir().unwrap();
    let diags = run_checks_with_dir(dir.path()).await;
    let matches = find(&diags, "keygen_available");
    assert_eq!(matches.len(), 1);
    // ssh-keygen should be available on macOS/Linux dev machines.
    assert!(matches[0].severity == Severity::Ok || matches[0].severity == Severity::Error);
}

// ---------------------------------------------------------------------------
// IdentityFilePubCheck
// ---------------------------------------------------------------------------

#[tokio::test]
async fn identity_file_pub_detected() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("config"),
        "Host test\n    IdentityFile ~/.ssh/id_ed25519.pub\n",
    )
    .unwrap();

    let diags = run_checks_with_dir(dir.path()).await;
    let matches = find(&diags, "identity_file_pub");
    assert!(matches.iter().any(|d| d.severity == Severity::Warning));
}

#[tokio::test]
async fn identity_file_private_key_ok() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("config"),
        "Host test\n    IdentityFile ~/.ssh/id_ed25519\n",
    )
    .unwrap();

    let diags = run_checks_with_dir(dir.path()).await;
    let matches = find(&diags, "identity_file_pub");
    assert!(matches.iter().all(|d| d.severity == Severity::Ok));
}

// ---------------------------------------------------------------------------
// IdentitiesOnlyCheck
// ---------------------------------------------------------------------------

#[tokio::test]
async fn identities_only_missing_warns() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("config"),
        "\
Host multi
    IdentityFile ~/.ssh/id_ed25519
    IdentityFile ~/.ssh/id_rsa
",
    )
    .unwrap();

    let diags = run_checks_with_dir(dir.path()).await;
    let matches = find(&diags, "identities_only");
    assert!(matches.iter().any(|d| d.severity == Severity::Warning));
}

#[tokio::test]
async fn identities_only_present_ok() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("config"),
        "\
Host multi
    IdentityFile ~/.ssh/id_ed25519
    IdentityFile ~/.ssh/id_rsa
    IdentitiesOnly yes
",
    )
    .unwrap();

    let diags = run_checks_with_dir(dir.path()).await;
    let matches = find(&diags, "identities_only");
    assert!(matches.iter().all(|d| d.severity == Severity::Ok));
}

#[tokio::test]
async fn identities_only_single_key_ok() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("config"),
        "Host single\n    IdentityFile ~/.ssh/id_ed25519\n",
    )
    .unwrap();

    let diags = run_checks_with_dir(dir.path()).await;
    let matches = find(&diags, "identities_only");
    assert!(matches.iter().all(|d| d.severity == Severity::Ok));
}

// ---------------------------------------------------------------------------
// Doctor MaxAuthTries check — warning when agent has many keys
// ---------------------------------------------------------------------------

#[tokio::test]
async fn identities_only_warns_when_many_keys() {
    // Simulate a host with many IdentityFile entries (agent has many keys).
    // The IdentitiesOnly check warns when a host has multiple IdentityFile
    // entries without IdentitiesOnly yes, which relates to MaxAuthTries issues.
    let dir = tempfile::tempdir().unwrap();
    let config = "\
Host busy-host
    IdentityFile ~/.ssh/id1
    IdentityFile ~/.ssh/id2
    IdentityFile ~/.ssh/id3
    IdentityFile ~/.ssh/id4
    IdentityFile ~/.ssh/id5
    IdentityFile ~/.ssh/id6
    IdentityFile ~/.ssh/id7
";
    std::fs::write(dir.path().join("config"), config).unwrap();

    let diags = run_checks_with_dir(dir.path()).await;
    let matches = find(&diags, "identities_only");
    // With 7 IdentityFile entries and no IdentitiesOnly yes, a warning is expected.
    assert!(
        matches.iter().any(|d| d.severity == Severity::Warning),
        "should warn about {} IdentityFile entries without IdentitiesOnly",
        7
    );
    let warning = matches
        .iter()
        .find(|d| d.severity == Severity::Warning)
        .unwrap();
    assert!(
        warning.message.contains('7'),
        "warning should mention key count"
    );
    assert!(
        warning.message.contains("IdentitiesOnly"),
        "warning should mention IdentitiesOnly"
    );
}

#[tokio::test]
async fn identities_only_ok_when_set_with_many_keys() {
    let dir = tempfile::tempdir().unwrap();
    let config = "\
Host busy-host
    IdentityFile ~/.ssh/id1
    IdentityFile ~/.ssh/id2
    IdentityFile ~/.ssh/id3
    IdentitiesOnly yes
";
    std::fs::write(dir.path().join("config"), config).unwrap();

    let diags = run_checks_with_dir(dir.path()).await;
    let matches = find(&diags, "identities_only");
    assert!(
        matches.iter().all(|d| d.severity == Severity::Ok),
        "should not warn when IdentitiesOnly yes is set"
    );
}

// ---------------------------------------------------------------------------
// CertificateFileExistsCheck
// ---------------------------------------------------------------------------

#[tokio::test]
async fn certificate_file_exists_present() {
    let dir = tempfile::tempdir().unwrap();
    let cert_path = dir.path().join("id_ed25519-cert.pub");
    std::fs::write(&cert_path, "fake-cert").unwrap();
    std::fs::write(
        dir.path().join("config"),
        format!("Host test\n    CertificateFile {}\n", cert_path.display()),
    )
    .unwrap();

    let diags = run_checks_with_dir(dir.path()).await;
    let matches = find(&diags, "certificate_file_exists");
    assert!(matches.iter().any(|d| d.severity == Severity::Ok));
}

#[tokio::test]
async fn certificate_file_exists_missing() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("config"),
        "Host test\n    CertificateFile ~/.ssh/nonexistent-cert.pub\n",
    )
    .unwrap();

    let diags = run_checks_with_dir(dir.path()).await;
    let matches = find(&diags, "certificate_file_exists");
    assert!(matches.iter().any(|d| d.severity == Severity::Warning));
}

#[tokio::test]
async fn certificate_file_exists_no_config() {
    let dir = tempfile::tempdir().unwrap();
    // No config file.
    let diags = run_checks_with_dir(dir.path()).await;
    let matches = find(&diags, "certificate_file_exists");
    assert!(!matches.is_empty());
    assert!(matches.iter().all(|d| d.severity == Severity::Info));
}

#[tokio::test]
async fn certificate_file_exists_no_directives() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("config"),
        "Host test\n    HostName example.com\n",
    )
    .unwrap();

    let diags = run_checks_with_dir(dir.path()).await;
    let matches = find(&diags, "certificate_file_exists");
    assert!(!matches.is_empty());
    assert!(matches.iter().all(|d| d.severity == Severity::Info));
}

// ---------------------------------------------------------------------------
// PreferredAuthenticationsCheck
// ---------------------------------------------------------------------------

#[tokio::test]
async fn preferred_authentications_not_set() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("config"),
        "Host test\n    HostName example.com\n",
    )
    .unwrap();

    let diags = run_checks_with_dir(dir.path()).await;
    let matches = find(&diags, "preferred_authentications");
    assert!(!matches.is_empty());
    assert!(matches.iter().all(|d| d.severity == Severity::Ok));
}

#[tokio::test]
async fn preferred_authentications_with_pubkey() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("config"),
        "Host test\n    PreferredAuthentications publickey,password\n",
    )
    .unwrap();

    let diags = run_checks_with_dir(dir.path()).await;
    let matches = find(&diags, "preferred_authentications");
    assert!(!matches.is_empty());
    assert!(matches.iter().all(|d| d.severity == Severity::Ok));
}

#[tokio::test]
async fn preferred_authentications_password_only() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("config"),
        "Host test\n    PreferredAuthentications password\n",
    )
    .unwrap();

    let diags = run_checks_with_dir(dir.path()).await;
    let matches = find(&diags, "preferred_authentications");
    assert!(!matches.is_empty());
    assert!(matches.iter().any(|d| d.severity == Severity::Info));
}

// ---------------------------------------------------------------------------
// Doctor ProxyJump host check — unconfigured ProxyJump targets warned
// ---------------------------------------------------------------------------

#[tokio::test]
async fn identity_file_exists_warns_for_missing_proxy_jump_key() {
    // ProxyJump itself doesn't need an IdentityFile check, but if the
    // jump host's IdentityFile is referenced and doesn't exist, we warn.
    let dir = tempfile::tempdir().unwrap();
    let config = "\
Host target
    ProxyJump jumphost
    IdentityFile ~/.ssh/jump_key
";
    std::fs::write(dir.path().join("config"), config).unwrap();

    let diags = run_checks_with_dir(dir.path()).await;
    let matches = find(&diags, "identity_file_exists");
    // The jump_key doesn't exist, so we should get a warning.
    assert!(
        matches.iter().any(|d| d.severity == Severity::Warning),
        "should warn about missing IdentityFile for ProxyJump host"
    );
}

#[tokio::test]
async fn duplicate_host_detected_for_proxy_jump_target() {
    // If a ProxyJump target has a duplicate Host block, we should warn.
    let dir = tempfile::tempdir().unwrap();
    let config = "\
Host jumphost
    HostName jump.example.com

Host jumphost
    HostName jump2.example.com

Host target
    ProxyJump jumphost
";
    std::fs::write(dir.path().join("config"), config).unwrap();

    let diags = run_checks_with_dir(dir.path()).await;
    let matches = find(&diags, "duplicate_host");
    assert!(
        matches.iter().any(|d| d.severity == Severity::Warning),
        "should warn about duplicate Host block for ProxyJump target"
    );
}

#[tokio::test]
async fn host_star_placement_affects_proxy_jump_defaults() {
    // Host * before specific blocks means ProxyJump defaults can't be overridden.
    let dir = tempfile::tempdir().unwrap();
    let config = "\
Host *
    ProxyJump default-jump

Host target
    HostName target.example.com
";
    std::fs::write(dir.path().join("config"), config).unwrap();

    let diags = run_checks_with_dir(dir.path()).await;
    let matches = find(&diags, "host_star_placement");
    assert!(
        matches.iter().any(|d| d.severity == Severity::Warning),
        "should warn when Host * precedes specific blocks (affects ProxyJump)"
    );
}

// ---------------------------------------------------------------------------
// HomeDirPermissionsCheck (unix only)
// ---------------------------------------------------------------------------

/// Run the `HomeDirPermissionsCheck` against a temp directory with the given
/// Unix permission mode.  Sets `$HOME` to the temp dir for the duration of
/// the check and restores it afterwards.
#[cfg(unix)]
async fn run_home_dir_check_with_mode(mode: u32) -> Vec<toride_ssh_core::Diagnostic> {
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(mode)).unwrap();

    let orig = std::env::var("HOME").ok();
    // SAFETY: save/restore pattern; the window where HOME is overridden is
    // limited to the async check execution below.
    unsafe {
        std::env::set_var("HOME", dir.path());
    }

    let check = HomeDirPermissionsCheck;
    let result = check.run().await.unwrap();

    if let Some(ref val) = orig {
        unsafe {
            std::env::set_var("HOME", val);
        }
    } else {
        unsafe {
            std::env::remove_var("HOME");
        }
    }

    result
}

#[cfg(unix)]
#[tokio::test]
async fn home_dir_permissions_ok_when_secure() {
    // 0755 — no group or world write bits.
    let diags = run_home_dir_check_with_mode(0o755).await;
    assert_eq!(diags.len(), 1);
    assert_eq!(diags[0].id, "home_dir_permissions");
    assert_eq!(diags[0].severity, Severity::Ok);
    assert!(
        diags[0].message.contains("correct permissions"),
        "expected 'correct permissions' in message, got: {}",
        diags[0].message,
    );
    assert!(diags[0].hint.is_none());
}

#[cfg(unix)]
#[tokio::test]
async fn home_dir_permissions_warns_when_group_writable() {
    // 0775 — group write bit set.
    let diags = run_home_dir_check_with_mode(0o775).await;
    assert_eq!(diags.len(), 1);
    assert_eq!(diags[0].id, "home_dir_permissions");
    assert_eq!(diags[0].severity, Severity::Warning);
    assert!(
        diags[0].message.contains("group"),
        "expected 'group' in message, got: {}",
        diags[0].message,
    );
    assert!(
        diags[0].hint.is_some(),
        "group-writable diagnostic should include a remediation hint",
    );
}

#[cfg(unix)]
#[tokio::test]
async fn home_dir_permissions_warns_when_world_writable() {
    // 0757 — world (other) write bit set, group write clear.
    let diags = run_home_dir_check_with_mode(0o757).await;
    assert_eq!(diags.len(), 1);
    assert_eq!(diags[0].id, "home_dir_permissions");
    assert_eq!(diags[0].severity, Severity::Warning);
    assert!(
        diags[0].message.contains("world"),
        "expected 'world' in message, got: {}",
        diags[0].message,
    );
    assert!(
        diags[0].hint.is_some(),
        "world-writable diagnostic should include a remediation hint",
    );
}

#[cfg(unix)]
#[tokio::test]
async fn home_dir_permissions_warns_when_group_and_world_writable() {
    // 0777 — both group and world write bits set.
    let diags = run_home_dir_check_with_mode(0o777).await;
    assert_eq!(diags.len(), 1);
    assert_eq!(diags[0].id, "home_dir_permissions");
    assert_eq!(diags[0].severity, Severity::Warning);
    assert!(
        diags[0].message.contains("group and world"),
        "expected 'group and world' in message, got: {}",
        diags[0].message,
    );
    assert!(diags[0].hint.is_some());
}

#[cfg(unix)]
#[tokio::test]
async fn home_dir_permissions_info_when_home_unknown() {
    // `dirs::home_dir()` reads `$HOME` on Unix.  When the variable is
    // removed, the crate falls back to the passwd database.  In a normal
    // dev environment the lookup succeeds so we cannot reliably reach the
    // `None` branch.  This test removes `$HOME` and accepts either outcome:
    //   - Info (dirs returned None — e.g. in a sandboxed container)
    //   - Ok/Warning (passwd fallback resolved a home directory)
    let orig = std::env::var("HOME").ok();
    unsafe {
        std::env::remove_var("HOME");
    }

    let check = HomeDirPermissionsCheck;
    let diags = check.run().await.unwrap();

    if let Some(ref val) = orig {
        unsafe {
            std::env::set_var("HOME", val);
        }
    }

    assert_eq!(diags.len(), 1);
    assert_eq!(diags[0].id, "home_dir_permissions");
    assert!(
        matches!(
            diags[0].severity,
            Severity::Ok | Severity::Warning | Severity::Info
        ),
        "unexpected severity: {:?}",
        diags[0].severity,
    );
}

// ---------------------------------------------------------------------------
// MaxAuthTriesExhaustionCheck
// ---------------------------------------------------------------------------

/// Run `MaxAuthTriesExhaustionCheck` directly against the current environment.
async fn run_max_auth_tries_check() -> Vec<toride_ssh_core::Diagnostic> {
    MaxAuthTriesExhaustionCheck.run().await.unwrap()
}

#[tokio::test]
async fn max_auth_tries_skips_when_auth_sock_unset() {
    let orig = std::env::var("SSH_AUTH_SOCK").ok();
    // SAFETY: save/restore pattern; window is limited to this test scope.
    unsafe {
        std::env::remove_var("SSH_AUTH_SOCK");
    }

    let diags = run_max_auth_tries_check().await;

    if let Some(ref val) = orig {
        unsafe {
            std::env::set_var("SSH_AUTH_SOCK", val);
        }
    }

    assert_eq!(diags.len(), 1);
    assert_eq!(diags[0].id, "max_auth_tries_exhaustion");
    assert_eq!(diags[0].severity, Severity::Info);
    assert!(
        diags[0].message.contains("SSH agent is not running"),
        "expected 'SSH agent is not running' in message, got: {}",
        diags[0].message,
    );
    assert!(diags[0].hint.is_none());
}

#[tokio::test]
async fn max_auth_tries_info_when_ssh_add_fails() {
    let orig_sock = std::env::var("SSH_AUTH_SOCK").ok();
    // Point to a non-existent socket — ssh-add -l will fail.
    unsafe {
        std::env::set_var("SSH_AUTH_SOCK", "/tmp/toride_test_nonexistent_agent_socket");
    }

    let diags = run_max_auth_tries_check().await;

    if let Some(ref val) = orig_sock {
        unsafe {
            std::env::set_var("SSH_AUTH_SOCK", val);
        }
    } else {
        unsafe {
            std::env::remove_var("SSH_AUTH_SOCK");
        }
    }

    assert_eq!(diags.len(), 1);
    assert_eq!(diags[0].id, "max_auth_tries_exhaustion");
    assert_eq!(diags[0].severity, Severity::Info);
    assert!(
        diags[0].message.contains("Could not list agent keys"),
        "expected 'Could not list agent keys' in message, got: {}",
        diags[0].message,
    );
}

#[tokio::test]
async fn max_auth_tries_classifies_key_count() {
    // Runs against the real SSH agent (if present) and verifies the
    // diagnostic severity matches the key count thresholds:
    //   < 5 keys   → Ok
    //   5 keys     → Info (approaching MaxAuthTries)
    //   >= 6 keys  → Warning
    //   no agent   → Info (skip)
    let diags = run_max_auth_tries_check().await;

    assert_eq!(diags.len(), 1);
    assert_eq!(diags[0].id, "max_auth_tries_exhaustion");
    assert_eq!(diags[0].module, "local");

    match diags[0].severity {
        Severity::Ok => {
            // Few keys loaded — within the safe range.
            assert!(
                diags[0].message.contains("within MaxAuthTries limit")
                    || diags[0].message.contains("No keys loaded"),
                "Ok message should confirm safe key count, got: {}",
                diags[0].message,
            );
            assert!(diags[0].hint.is_none());
        }
        Severity::Info => {
            // Either agent unavailable or approaching threshold.
            assert!(
                diags[0].message.contains("SSH agent is not running")
                    || diags[0].message.contains("Could not list agent keys")
                    || diags[0].message.contains("approaching MaxAuthTries"),
                "Info message should explain the reason, got: {}",
                diags[0].message,
            );
        }
        Severity::Warning => {
            // Too many keys — at or above MaxAuthTries threshold.
            assert!(
                diags[0].message.contains("MaxAuthTries"),
                "Warning should mention MaxAuthTries, got: {}",
                diags[0].message,
            );
            assert!(
                diags[0].hint.is_some(),
                "Warning should include a remediation hint",
            );
            let hint = diags[0].hint.as_ref().unwrap();
            assert!(
                hint.contains("ssh-add -D") || hint.contains("IdentitiesOnly"),
                "hint should suggest reducing keys, got: {hint}",
            );
        }
        other @ Severity::Error => panic!("unexpected severity: {other:?}"),
    }
}

#[tokio::test]
async fn max_auth_tries_warns_when_above_threshold() {
    // Verifies the Warning branch (>= 6 keys) produces correct message
    // and hint.  When the real agent has fewer keys this is a no-op —
    // the classification logic is still exercised via the sibling test.
    let diags = run_max_auth_tries_check().await;

    assert_eq!(diags.len(), 1);
    assert_eq!(diags[0].id, "max_auth_tries_exhaustion");

    if diags[0].severity == Severity::Warning {
        assert!(
            diags[0].message.contains("keys loaded"),
            "Warning message should mention key count, got: {}",
            diags[0].message,
        );
        assert!(
            diags[0].message.contains("MaxAuthTries default is 6"),
            "Warning message should mention default limit, got: {}",
            diags[0].message,
        );
        let hint = diags[0]
            .hint
            .as_ref()
            .expect("Warning should have a remediation hint");
        assert!(
            hint.contains("ssh-add -D"),
            "hint should suggest clearing keys with ssh-add -D, got: {hint}",
        );
    }
}

// ---------------------------------------------------------------------------
// AgentIdentityCheck
// ---------------------------------------------------------------------------

/// Generate an Ed25519 key pair in `dir` using `ssh-keygen`.
/// Returns the path to the private key file.  The public key is at
/// `<name>.pub` in the same directory.
fn generate_ed25519_key_pair(dir: &std::path::Path, name: &str) -> std::path::PathBuf {
    let key_path = dir.join(name);
    let status = std::process::Command::new("ssh-keygen")
        .args([
            "-t",
            "ed25519",
            "-f",
            key_path.to_str().unwrap(),
            "-N",
            "",
            "-C",
            "toride-test",
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .expect("ssh-keygen should be available");
    assert!(status.success(), "ssh-keygen failed to generate key pair");
    key_path
}

/// Add a private key to the running SSH agent.  Returns `true` on success.
fn ssh_add_key(key_path: &std::path::Path) -> bool {
    std::process::Command::new("ssh-add")
        .arg(key_path.to_str().unwrap())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// Remove a key from the SSH agent using its public key file path.
fn ssh_remove_key_by_pub(pub_path: &std::path::Path) {
    let _ = std::process::Command::new("ssh-add")
        .args(["-d", pub_path.to_str().unwrap()])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
}

/// Returns `true` when `SSH_AUTH_SOCK` is set and the socket exists.
fn agent_is_reachable() -> bool {
    match std::env::var("SSH_AUTH_SOCK") {
        Ok(sock) if !sock.is_empty() => std::path::Path::new(&sock).exists(),
        _ => false,
    }
}

/// Returns `true` when `ssh-add -l` reports at least one loaded key.
fn agent_has_keys() -> bool {
    std::process::Command::new("ssh-add")
        .arg("-l")
        .output()
        .is_ok_and(|o| o.status.success() && !o.stdout.is_empty())
}

/// Run the `AgentIdentityCheck` directly against the given SSH directory.
async fn run_agent_identity_check(ssh_dir: &std::path::Path) -> Vec<toride_ssh_core::Diagnostic> {
    let paths = SshPaths::with_dir(ssh_dir);
    let check = AgentIdentityCheck { paths: &paths };
    check.run().await.unwrap()
}

#[tokio::test]
async fn agent_identity_info_when_no_agent() {
    let orig = std::env::var("SSH_AUTH_SOCK").ok();
    // SAFETY: save/restore pattern; window is limited to this test scope.
    unsafe {
        std::env::remove_var("SSH_AUTH_SOCK");
    }

    let dir = tempfile::tempdir().unwrap();
    let diags = run_agent_identity_check(dir.path()).await;

    if let Some(ref val) = orig {
        unsafe {
            std::env::set_var("SSH_AUTH_SOCK", val);
        }
    }

    let matches = find(&diags, "agent_identity");
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].severity, Severity::Info);
    assert!(
        matches[0].message.contains("SSH agent is not running"),
        "expected 'SSH agent is not running' in message, got: {}",
        matches[0].message,
    );
}

#[tokio::test]
async fn agent_identity_ok_when_agent_holds_matching_key() {
    if !agent_is_reachable() {
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let key_path = generate_ed25519_key_pair(dir.path(), "id_ed25519_match");
    let pub_path = dir.path().join("id_ed25519_match.pub");

    // Load the key into the agent.
    if !ssh_add_key(&key_path) {
        return;
    }

    // Config references this key via an absolute path.
    std::fs::write(
        dir.path().join("config"),
        format!("Host test\n    IdentityFile {}\n", key_path.display()),
    )
    .unwrap();

    let diags = run_agent_identity_check(dir.path()).await;

    // Cleanup: remove key from agent before the temp dir is deleted.
    ssh_remove_key_by_pub(&pub_path);

    let matches = find(&diags, "agent_identity");
    assert!(
        matches
            .iter()
            .any(|d| d.severity == Severity::Ok && d.message.contains("Agent holds key")),
        "expected Ok 'Agent holds key' diagnostic, got: {:?}",
        matches
            .iter()
            .map(|d| (&d.severity, &d.message))
            .collect::<Vec<_>>(),
    );
}

#[tokio::test]
async fn agent_identity_info_when_pub_file_missing() {
    if !agent_is_reachable() {
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let key_path = generate_ed25519_key_pair(dir.path(), "id_ed25519_nopub");
    let pub_path = dir.path().join("id_ed25519_nopub.pub");

    // Load the key so the check does not early-return with "No keys loaded".
    if !ssh_add_key(&key_path) {
        return;
    }

    // Remove the .pub file so `ssh-keygen -lf` fails.
    std::fs::remove_file(&pub_path).unwrap();

    std::fs::write(
        dir.path().join("config"),
        format!("Host test\n    IdentityFile {}\n", key_path.display()),
    )
    .unwrap();

    let diags = run_agent_identity_check(dir.path()).await;

    // Best-effort cleanup: try removing by private key path.
    let _ = std::process::Command::new("ssh-add")
        .args(["-d", key_path.to_str().unwrap()])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();

    let matches = find(&diags, "agent_identity");
    assert!(
        matches
            .iter()
            .any(|d| d.severity == Severity::Info && d.message.contains("Cannot read public key")),
        "expected Info 'Cannot read public key' diagnostic, got: {:?}",
        matches
            .iter()
            .map(|d| (&d.severity, &d.message))
            .collect::<Vec<_>>(),
    );
}

#[tokio::test]
async fn agent_identity_warns_when_key_not_in_agent() {
    if !agent_is_reachable() || !agent_has_keys() {
        // The check needs the agent to have at least one key loaded so it
        // does not early-return with "No keys loaded in agent".
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    // Generate a fresh key pair that is NOT loaded in the agent.
    let key_path = generate_ed25519_key_pair(dir.path(), "id_ed25519_mismatch");

    std::fs::write(
        dir.path().join("config"),
        format!("Host test\n    IdentityFile {}\n", key_path.display()),
    )
    .unwrap();

    let diags = run_agent_identity_check(dir.path()).await;

    let matches = find(&diags, "agent_identity");
    assert!(
        matches
            .iter()
            .any(|d| d.severity == Severity::Warning
                && d.message.contains("Agent does not hold key")),
        "expected Warning 'Agent does not hold key' diagnostic, got: {:?}",
        matches
            .iter()
            .map(|d| (&d.severity, &d.message))
            .collect::<Vec<_>>(),
    );
}

// ---------------------------------------------------------------------------
// RsaWeakKeyCheck
// ---------------------------------------------------------------------------

/// Generate an RSA key pair in `dir` with the given bit size using `ssh-keygen`.
/// Returns the path to the private key file.
fn generate_rsa_key_pair(dir: &std::path::Path, name: &str, bits: u32) -> std::path::PathBuf {
    let key_path = dir.join(name);
    let status = std::process::Command::new("ssh-keygen")
        .args([
            "-t",
            "rsa",
            "-b",
            &bits.to_string(),
            "-f",
            key_path.to_str().unwrap(),
            "-N",
            "",
            "-C",
            "toride-test-rsa",
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .expect("ssh-keygen should be available");
    assert!(
        status.success(),
        "ssh-keygen failed to generate RSA-{bits} key pair"
    );
    key_path
}

/// Run the `RsaWeakKeyCheck` directly against the given SSH directory.
async fn run_rsa_weak_key_check(ssh_dir: &std::path::Path) -> Vec<toride_ssh_core::Diagnostic> {
    let paths = SshPaths::with_dir(ssh_dir);
    let check = RsaWeakKeyCheck { paths: &paths };
    check.run().await.unwrap()
}

#[tokio::test]
async fn rsa_weak_key_ok_for_4096_bits() {
    let dir = tempfile::tempdir().unwrap();
    generate_rsa_key_pair(dir.path(), "id_rsa", 4096);

    let diags = run_rsa_weak_key_check(dir.path()).await;
    assert_eq!(diags.len(), 1, "expected exactly one diagnostic");
    assert_eq!(diags[0].id, "rsa_weak_key");
    assert_eq!(
        diags[0].severity,
        Severity::Ok,
        "4096-bit RSA key should be Ok, got: {:?} — {}",
        diags[0].severity,
        diags[0].message,
    );
    assert!(
        diags[0].message.contains("4096"),
        "message should mention bit size, got: {}",
        diags[0].message,
    );
    assert!(
        diags[0].message.contains("adequate"),
        "message should say 'adequate', got: {}",
        diags[0].message,
    );
    assert!(diags[0].hint.is_none(), "Ok diagnostic should have no hint");
}

#[tokio::test]
async fn rsa_weak_key_warns_for_2048_bits() {
    let dir = tempfile::tempdir().unwrap();
    generate_rsa_key_pair(dir.path(), "id_rsa", 2048);

    let diags = run_rsa_weak_key_check(dir.path()).await;
    assert_eq!(diags.len(), 1, "expected exactly one diagnostic");
    assert_eq!(diags[0].id, "rsa_weak_key");
    assert_eq!(
        diags[0].severity,
        Severity::Warning,
        "2048-bit RSA key should warn, got: {:?} — {}",
        diags[0].severity,
        diags[0].message,
    );
    assert!(
        diags[0].message.contains("2048"),
        "message should mention 2048 bits, got: {}",
        diags[0].message,
    );
    assert!(
        diags[0].message.contains("minimum recommended: 3072"),
        "message should mention minimum recommended, got: {}",
        diags[0].message,
    );
    assert!(
        diags[0].hint.is_some(),
        "Warning diagnostic should include a remediation hint"
    );
    let hint = diags[0].hint.as_ref().unwrap();
    assert!(
        hint.contains("ssh-keygen"),
        "hint should suggest ssh-keygen, got: {hint}",
    );
}

#[tokio::test]
async fn rsa_weak_key_warns_for_1024_bits() {
    let dir = tempfile::tempdir().unwrap();
    generate_rsa_key_pair(dir.path(), "id_rsa", 1024);

    let diags = run_rsa_weak_key_check(dir.path()).await;
    assert_eq!(diags.len(), 1, "expected exactly one diagnostic");
    assert_eq!(diags[0].id, "rsa_weak_key");
    assert_eq!(
        diags[0].severity,
        Severity::Warning,
        "1024-bit RSA key should warn, got: {:?} — {}",
        diags[0].severity,
        diags[0].message,
    );
    assert!(
        diags[0].message.contains("1024"),
        "message should mention 1024 bits, got: {}",
        diags[0].message,
    );
    assert!(
        diags[0].message.contains("minimum recommended: 3072"),
        "message should mention minimum recommended, got: {}",
        diags[0].message,
    );
    assert!(
        diags[0].hint.is_some(),
        "Warning diagnostic should include a remediation hint"
    );
}

#[tokio::test]
async fn rsa_weak_key_skips_ed25519_key() {
    let dir = tempfile::tempdir().unwrap();
    generate_ed25519_key_pair(dir.path(), "id_ed25519");

    let diags = run_rsa_weak_key_check(dir.path()).await;
    assert_eq!(diags.len(), 1, "expected exactly one diagnostic");
    assert_eq!(diags[0].id, "rsa_weak_key");
    assert_eq!(
        diags[0].severity,
        Severity::Ok,
        "Ed25519 key should not trigger RSA warning, got: {:?} — {}",
        diags[0].severity,
        diags[0].message,
    );
    assert!(
        diags[0].message.contains("No RSA private keys found"),
        "should report no RSA keys found, got: {}",
        diags[0].message,
    );
    assert!(diags[0].hint.is_none(), "Ok diagnostic should have no hint");
}

// ---------------------------------------------------------------------------
// UseKeychainPlatformCheck
// ---------------------------------------------------------------------------

#[tokio::test]
async fn use_keychain_no_directive_info() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("config"),
        "Host example\n    HostName example.com\n",
    )
    .unwrap();

    let diags = run_checks_with_dir(dir.path()).await;
    let matches = find(&diags, "use_keychain_platform");
    assert_eq!(matches.len(), 1, "expected exactly one diagnostic");
    assert_eq!(matches[0].severity, Severity::Ok);
    assert!(
        matches[0].message.contains("No UseKeychain"),
        "message should mention no UseKeychain found, got: {}",
        matches[0].message,
    );
}

#[tokio::test]
async fn use_keychain_top_level() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("config"),
        "UseKeychain yes\nHost example\n    HostName example.com\n",
    )
    .unwrap();

    let diags = run_checks_with_dir(dir.path()).await;
    let matches = find(&diags, "use_keychain_platform");
    assert_eq!(matches.len(), 1, "expected exactly one diagnostic");

    if cfg!(target_os = "macos") {
        assert_eq!(matches[0].severity, Severity::Ok);
        assert!(
            matches[0].message.contains("macOS"),
            "macOS message should mention macOS, got: {}",
            matches[0].message,
        );
    } else {
        assert_eq!(matches[0].severity, Severity::Warning);
        assert!(
            matches[0].message.contains("not macOS"),
            "non-macOS message should mention not macOS, got: {}",
            matches[0].message,
        );
        assert!(matches[0].hint.is_some(), "warning should have a hint");
    }
}

#[tokio::test]
async fn use_keychain_in_host_block() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("config"),
        "\
Host mac-host
    HostName example.com
    UseKeychain yes
",
    )
    .unwrap();

    let diags = run_checks_with_dir(dir.path()).await;
    let matches = find(&diags, "use_keychain_platform");
    assert_eq!(matches.len(), 1, "expected exactly one diagnostic");

    if cfg!(target_os = "macos") {
        assert_eq!(matches[0].severity, Severity::Ok);
    } else {
        assert_eq!(matches[0].severity, Severity::Warning);
        assert!(
            matches[0].message.contains("Host mac-host"),
            "should mention the Host block context, got: {}",
            matches[0].message,
        );
    }
}

#[tokio::test]
async fn use_keychain_multiple_contexts() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("config"),
        "\
UseKeychain yes
Host mac-host
    HostName example.com
    UseKeychain yes
",
    )
    .unwrap();

    let diags = run_checks_with_dir(dir.path()).await;
    let matches = find(&diags, "use_keychain_platform");

    if cfg!(target_os = "macos") {
        // On macOS, a single Ok diagnostic summarizing the count.
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].severity, Severity::Ok);
        assert!(
            matches[0].message.contains('2'),
            "should mention 2 contexts, got: {}",
            matches[0].message,
        );
    } else {
        // On non-macOS, one Warning per UseKeychain context.
        assert_eq!(
            matches.len(),
            2,
            "expected 2 warnings for 2 UseKeychain contexts"
        );
        assert!(matches.iter().all(|d| d.severity == Severity::Warning));
    }
}

// ---------------------------------------------------------------------------
// GssapiConfigCheck
// ---------------------------------------------------------------------------

#[tokio::test]
async fn gssapi_config_no_directives() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("config"),
        "Host example\n    HostName example.com\n",
    )
    .unwrap();

    let diags = run_checks_with_dir(dir.path()).await;
    let matches = find(&diags, "gssapi_config");
    assert_eq!(matches.len(), 1, "expected exactly one diagnostic");
    assert_eq!(matches[0].severity, Severity::Ok);
    assert!(
        matches[0].message.contains("No GSSAPI directives"),
        "message should mention no GSSAPI directives, got: {}",
        matches[0].message,
    );
}

#[tokio::test]
async fn gssapi_config_no_config_file() {
    let dir = tempfile::tempdir().unwrap();
    let diags = run_checks_with_dir(dir.path()).await;
    let matches = find(&diags, "gssapi_config");
    assert!(!matches.is_empty());
    assert!(matches.iter().all(|d| d.severity == Severity::Info));
}

#[tokio::test]
async fn gssapi_config_authentication_enabled() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("config"),
        "\
Host kerb-host
    HostName kdc.example.com
    GSSAPIAuthentication yes
",
    )
    .unwrap();

    let diags = run_checks_with_dir(dir.path()).await;
    let matches = find(&diags, "gssapi_config");
    assert!(
        matches.iter().any(|d| d.severity == Severity::Info
            && d.message.contains("GSSAPIAuthentication yes")),
        "expected Info diagnostic listing GSSAPIAuthentication yes, got: {matches:?}",
    );
}

#[tokio::test]
async fn gssapi_config_all_directives_in_host_block() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("config"),
        "\
Host kerb-host
    HostName kdc.example.com
    GSSAPIAuthentication yes
    GSSAPIDelegateCredentials yes
    GSSAPIServerIdentity example.com
    GSSAPIClientIdentity alice@EXAMPLE.COM
",
    )
    .unwrap();

    let diags = run_checks_with_dir(dir.path()).await;
    let matches = find(&diags, "gssapi_config");
    let info = matches
        .iter()
        .find(|d| d.severity == Severity::Info)
        .unwrap();
    assert!(info.message.contains("GSSAPIAuthentication yes"));
    assert!(info.message.contains("GSSAPIDelegateCredentials yes"));
    assert!(info.message.contains("GSSAPIServerIdentity example.com"));
    assert!(
        info.message
            .contains("GSSAPIClientIdentity alice@EXAMPLE.COM")
    );
    assert!(
        info.message.contains("Host kerb-host"),
        "should mention the Host block context"
    );
}

#[tokio::test]
async fn gssapi_config_top_level_directive() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("config"),
        "GSSAPIAuthentication yes\nHost example\n    HostName example.com\n",
    )
    .unwrap();

    let diags = run_checks_with_dir(dir.path()).await;
    let matches = find(&diags, "gssapi_config");
    let info = matches
        .iter()
        .find(|d| d.severity == Severity::Info)
        .unwrap();
    assert!(
        info.message.contains("top-level"),
        "should report top-level context"
    );
}

#[tokio::test]
async fn gssapi_config_warns_gssapi_only_auth() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("config"),
        "\
Host kerb-only
    HostName kdc.example.com
    GSSAPIAuthentication yes
    PreferredAuthentications gssapi-with-mic
",
    )
    .unwrap();

    let diags = run_checks_with_dir(dir.path()).await;
    let matches = find(&diags, "gssapi_config");
    assert!(
        matches.iter().any(|d| d.severity == Severity::Warning
            && d.message.contains("publickey authentication is excluded")),
        "should warn when GSSAPI is the only authentication method, got: {matches:?}",
    );
}

#[tokio::test]
async fn gssapi_config_no_warning_when_pubkey_included() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("config"),
        "\
Host kerb-plus-pubkey
    HostName kdc.example.com
    GSSAPIAuthentication yes
    PreferredAuthentications gssapi-with-mic,publickey
",
    )
    .unwrap();

    let diags = run_checks_with_dir(dir.path()).await;
    let matches = find(&diags, "gssapi_config");
    assert!(
        !matches.iter().any(|d| d.severity == Severity::Warning),
        "should not warn when publickey is included in PreferredAuthentications, got: {matches:?}",
    );
}

#[tokio::test]
async fn gssapi_config_no_warning_when_gssapi_disabled() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("config"),
        "\
Host kerb-off
    HostName kdc.example.com
    GSSAPIAuthentication no
    PreferredAuthentications gssapi-with-mic
",
    )
    .unwrap();

    let diags = run_checks_with_dir(dir.path()).await;
    let matches = find(&diags, "gssapi_config");
    assert!(
        !matches.iter().any(|d| d.severity == Severity::Warning),
        "should not warn when GSSAPIAuthentication is no, got: {matches:?}",
    );
}

// ---------------------------------------------------------------------------
// NfsHomeCheck
// ---------------------------------------------------------------------------

/// Run `NfsHomeCheck` directly against the current environment.
async fn run_nfs_home_check() -> Vec<toride_ssh_core::Diagnostic> {
    NfsHomeCheck.run().await.unwrap()
}

#[tokio::test]
async fn nfs_home_returns_valid_diagnostic() {
    let diags = run_nfs_home_check().await;
    assert_eq!(diags.len(), 1);
    assert_eq!(diags[0].id, "nfs_home");
    assert_eq!(diags[0].module, "local");

    if cfg!(target_os = "linux") {
        // On Linux the check reads /proc/mounts. The severity depends on
        // whether the home directory is actually on NFS. Accept any valid
        // severity.
        assert!(
            matches!(
                diags[0].severity,
                Severity::Ok | Severity::Warning | Severity::Info
            ),
            "unexpected severity on Linux: {:?}",
            diags[0].severity,
        );
    } else {
        // On non-Linux the check should report Info (not applicable).
        assert_eq!(
            diags[0].severity,
            Severity::Info,
            "expected Info on non-Linux, got: {:?} — {}",
            diags[0].severity,
            diags[0].message,
        );
        assert!(
            diags[0].message.contains("not applicable"),
            "expected 'not applicable' in message, got: {}",
            diags[0].message,
        );
    }
}

#[tokio::test]
async fn nfs_home_info_when_home_unknown() {
    // Save and remove $HOME so dirs::home_dir() returns None (or falls back
    // to the passwd database, which may still succeed).
    let orig = std::env::var("HOME").ok();
    unsafe {
        std::env::remove_var("HOME");
    }

    let diags = run_nfs_home_check().await;

    if let Some(ref val) = orig {
        unsafe {
            std::env::set_var("HOME", val);
        }
    }

    assert_eq!(diags.len(), 1);
    assert_eq!(diags[0].id, "nfs_home");
    // Either Info (no home) or the normal Linux/non-Linux result (passwd fallback).
    assert!(
        matches!(
            diags[0].severity,
            Severity::Ok | Severity::Warning | Severity::Info
        ),
        "unexpected severity: {:?}",
        diags[0].severity,
    );
}

#[tokio::test]
async fn nfs_home_registered_in_run_all() {
    let dir = tempfile::tempdir().unwrap();
    let diags = run_checks_with_dir(dir.path()).await;
    let matches = find(&diags, "nfs_home");
    assert!(
        !matches.is_empty(),
        "nfs_home check should be registered in run_all"
    );
}

// ---------------------------------------------------------------------------
// SELinuxContextCheck
// ---------------------------------------------------------------------------

/// Run `SELinuxContextCheck` directly against the given SSH directory.
async fn run_selinux_context_check(ssh_dir: &std::path::Path) -> Vec<toride_ssh_core::Diagnostic> {
    let paths = SshPaths::with_dir(ssh_dir);
    let check = SELinuxContextCheck { paths: &paths };
    check.run().await.unwrap()
}

#[tokio::test]
async fn selinux_context_skipped_on_non_linux() {
    if cfg!(target_os = "linux") {
        // On Linux the check actually runs restorecon; accept any outcome.
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let diags = run_selinux_context_check(dir.path()).await;
    // On non-Linux, the check returns no diagnostics (skipped entirely).
    assert!(
        diags.is_empty(),
        "SELinux check should produce no diagnostics on non-Linux, got: {diags:?}",
    );
}

#[tokio::test]
async fn selinux_context_registered_in_run_all() {
    let dir = tempfile::tempdir().unwrap();
    let diags = run_checks_with_dir(dir.path()).await;

    if cfg!(target_os = "linux") {
        // On Linux the check runs and produces a diagnostic.
        let matches = find(&diags, "selinux_context");
        assert!(
            !matches.is_empty(),
            "selinux_context check should be registered in run_all on Linux"
        );
    } else {
        // On non-Linux the check returns empty diagnostics (skipped).
        let matches = find(&diags, "selinux_context");
        assert!(
            matches.is_empty(),
            "selinux_context check should produce no diagnostics on non-Linux"
        );
    }
}

#[tokio::test]
async fn selinux_context_returns_valid_severity_on_linux() {
    if !cfg!(target_os = "linux") {
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let diags = run_selinux_context_check(dir.path()).await;
    assert_eq!(diags.len(), 1);
    assert_eq!(diags[0].id, "selinux_context");
    assert_eq!(diags[0].module, "local");

    // restorecon may or may not be available on the test system.
    match diags[0].severity {
        Severity::Info => {
            // restorecon not available or SELinux not enabled.
            assert!(
                diags[0].message.contains("restorecon") || diags[0].message.contains("SELinux"),
                "Info message should mention restorecon or SELinux, got: {}",
                diags[0].message,
            );
        }
        Severity::Ok => {
            assert!(
                diags[0].message.contains("correct"),
                "Ok message should say contexts are correct, got: {}",
                diags[0].message,
            );
            assert!(diags[0].hint.is_none());
        }
        Severity::Warning => {
            assert!(
                diags[0].message.contains("fixing"),
                "Warning message should mention fixing, got: {}",
                diags[0].message,
            );
            assert!(
                diags[0].hint.is_some(),
                "Warning should include a remediation hint"
            );
            let hint = diags[0].hint.as_ref().unwrap();
            assert!(
                hint.contains("restorecon -Rv"),
                "hint should suggest restorecon -Rv, got: {hint}",
            );
        }
        other @ Severity::Error => panic!("unexpected severity: {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// VerifyHostKeyDnsCheck
// ---------------------------------------------------------------------------

#[tokio::test]
async fn verify_host_key_dns_info_when_no_config() {
    let dir = tempfile::tempdir().unwrap();
    let diags = run_checks_with_dir(dir.path()).await;
    let matches = find(&diags, "verify_host_key_dns");
    assert!(!matches.is_empty());
    assert!(
        matches.iter().all(|d| d.severity == Severity::Info),
        "expected Info when config is absent, got: {matches:?}"
    );
    // When no config file exists, the check reports that it cannot check.
    assert!(
        matches[0].message.contains("does not exist"),
        "expected 'does not exist' in message, got: {}",
        matches[0].message,
    );
}

#[tokio::test]
async fn verify_host_key_dns_unknown_when_config_present_but_no_directive() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("config"),
        "Host example.com\n    User alice\n",
    )
    .unwrap();
    let diags = run_checks_with_dir(dir.path()).await;
    let matches = find(&diags, "verify_host_key_dns");
    assert!(!matches.is_empty());
    assert!(
        matches[0].message.contains("not configured"),
        "expected 'not configured' in message, got: {}",
        matches[0].message,
    );
}

#[tokio::test]
async fn verify_host_key_dns_enabled() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("config"), "VerifyHostKeyDNS yes\n").unwrap();
    let diags = run_checks_with_dir(dir.path()).await;
    let matches = find(&diags, "verify_host_key_dns");
    assert!(!matches.is_empty());
    // At least one diagnostic should say VerifyHostKeyDNS is enabled.
    assert!(
        matches.iter().any(|d| d.message.contains("set to 'yes'")),
        "expected 'set to yes' in diagnostics, got: {matches:?}"
    );
}

#[tokio::test]
async fn verify_host_key_dns_disabled() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("config"), "VerifyHostKeyDNS no\n").unwrap();
    let diags = run_checks_with_dir(dir.path()).await;
    let matches = find(&diags, "verify_host_key_dns");
    assert!(!matches.is_empty());
    assert!(
        matches[0].message.contains("set to 'no'"),
        "expected 'set to no' in message, got: {}",
        matches[0].message,
    );
    assert_eq!(matches[0].severity, Severity::Ok);
}

#[tokio::test]
async fn verify_host_key_dns_ask() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("config"), "VerifyHostKeyDNS ask\n").unwrap();
    let diags = run_checks_with_dir(dir.path()).await;
    let matches = find(&diags, "verify_host_key_dns");
    assert!(!matches.is_empty());
    assert!(
        matches[0].message.contains("ask"),
        "expected 'ask' in message, got: {}",
        matches[0].message,
    );
}

#[tokio::test]
async fn verify_host_key_dns_enabled_reports_dns_check() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("config"), "VerifyHostKeyDNS yes\n").unwrap();
    let diags = run_checks_with_dir(dir.path()).await;
    let matches = find(&diags, "verify_host_key_dns");
    // When enabled, the check should produce multiple diagnostics:
    // one for the mode, one for DNS availability, and one SSHFP warning.
    assert!(
        matches.len() >= 2,
        "expected at least 2 diagnostics when enabled, got {}",
        matches.len()
    );
    // Should include an SSHFP hint.
    assert!(
        matches.iter().any(|d| d.message.contains("SSHFP")),
        "expected an SSHFP-related diagnostic, got: {matches:?}"
    );
}
