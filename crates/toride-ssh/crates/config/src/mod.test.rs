use super::*;
use toride_ssh_core::DiagnosticSeverity;

/// Helper: write a config string to a temp dir and return the `ConfigService`.
fn setup_config(config_content: &str) -> (tempfile::TempDir, ConfigService<'static>) {
    let dir = tempfile::tempdir().expect("tempdir");
    let ssh_dir = dir.path();
    std::fs::create_dir_all(ssh_dir).unwrap();
    std::fs::write(ssh_dir.join("config"), config_content).unwrap();

    // We need a 'static SshPaths so ConfigService can borrow it.
    // Safety: the TempDir is kept alive for the duration of the test.
    let paths = Box::leak(Box::new(crate::SshPaths::with_dir(ssh_dir)));
    let svc = ConfigService::new(paths);
    (dir, svc)
}

// ---------------------------------------------------------------------------
// diagnose() tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn diagnose_proxy_command_and_proxy_jump_conflict() {
    let (dir, svc) = setup_config(
        "\
Host bastion
    ProxyCommand ssh -W %h:%p gateway
    ProxyJump jump.example.com
    HostName bastion.example.com
",
    );

    let diags = svc.diagnose().await.unwrap();
    let conflicts: Vec<_> = diags
        .iter()
        .filter(|d| d.id == "config_proxy_conflict")
        .collect();

    assert_eq!(
        conflicts.len(),
        1,
        "expected exactly one proxy conflict diagnostic"
    );
    assert_eq!(conflicts[0].severity, DiagnosticSeverity::Warning);
    assert!(conflicts[0].message.contains("bastion"));
    assert!(conflicts[0].hint.is_some());

    drop(dir);
}

#[tokio::test]
async fn diagnose_duplicate_host_aliases() {
    let (dir, svc) = setup_config(
        "\
Host web
    HostName web1.example.com

Host web
    HostName web2.example.com
",
    );

    let diags = svc.diagnose().await.unwrap();
    let dupes: Vec<_> = diags
        .iter()
        .filter(|d| d.id == "config_duplicate_alias")
        .collect();

    assert_eq!(
        dupes.len(),
        1,
        "expected exactly one duplicate alias diagnostic"
    );
    assert_eq!(dupes[0].severity, DiagnosticSeverity::Warning);
    assert!(dupes[0].message.contains("'web'"));

    drop(dir);
}

#[tokio::test]
async fn diagnose_host_star_before_specific() {
    let (dir, svc) = setup_config(
        "\
Host *
    ServerAliveInterval 60

Host specific
    HostName specific.example.com
",
    );

    let diags = svc.diagnose().await.unwrap();
    let star: Vec<_> = diags
        .iter()
        .filter(|d| d.id == "config_host_star_placement")
        .collect();

    assert_eq!(star.len(), 1, "expected Host * placement diagnostic");
    assert_eq!(star[0].severity, DiagnosticSeverity::Warning);
    assert!(star[0].message.contains("Host *"));

    drop(dir);
}

#[tokio::test]
async fn diagnose_host_star_after_specific_is_ok() {
    let (dir, svc) = setup_config(
        "\
Host specific
    HostName specific.example.com

Host *
    ServerAliveInterval 60
",
    );

    let diags = svc.diagnose().await.unwrap();
    let star: Vec<_> = diags
        .iter()
        .filter(|d| d.id == "config_host_star_placement")
        .collect();

    assert!(
        star.is_empty(),
        "Host * after specific blocks should not trigger a warning"
    );

    drop(dir);
}

#[tokio::test]
async fn diagnose_clean_config_returns_empty() {
    let dir = tempfile::tempdir().expect("tempdir");
    let ssh_dir = dir.path();
    std::fs::create_dir_all(ssh_dir).unwrap();

    // Create a real private key file and reference it by absolute path so the
    // diagnose IdentityFile-existence check is hermetic: it must NOT depend on
    // the developer's real `~/.ssh/id_ed25519` existing. (`expand_path` passes
    // absolute paths through unchanged.)
    let key_file = ssh_dir.join("id_ed25519");
    std::fs::write(&key_file, b"dummy private key").unwrap();

    let config = format!(
        "\
Host production
    HostName prod.example.com
    User deploy
    IdentityFile {key}

Host staging
    HostName staging.example.com
    User deploy

Host *
    ServerAliveInterval 60
",
        key = key_file.display()
    );
    std::fs::write(ssh_dir.join("config"), config).unwrap();

    // Keep the TempDir (and the leaked SshPaths borrow into it) alive for the
    // duration of the test.
    let paths = Box::leak(Box::new(crate::SshPaths::with_dir(ssh_dir)));
    let svc = ConfigService::new(paths);

    let diags = svc.diagnose().await.unwrap();

    // No warnings or errors expected: the config is well-formed and the
    // referenced IdentityFile exists on disk.
    let warnings: Vec<_> = diags
        .iter()
        .filter(|d| d.severity == DiagnosticSeverity::Warning)
        .collect();

    assert!(
        warnings.is_empty(),
        "clean config should produce no warnings, got: {warnings:?}",
    );

    drop(dir);
}

#[tokio::test]
async fn diagnose_identity_file_points_to_pub() {
    let (dir, svc) = setup_config(
        "\
Host bad
    IdentityFile ~/.ssh/id_ed25519.pub
",
    );

    let diags = svc.diagnose().await.unwrap();
    let pub_warns: Vec<_> = diags
        .iter()
        .filter(|d| d.id == "config_identity_pub")
        .collect();

    assert_eq!(pub_warns.len(), 1);
    assert_eq!(pub_warns[0].severity, DiagnosticSeverity::Warning);
    assert!(pub_warns[0].message.contains(".pub"));

    drop(dir);
}

#[tokio::test]
async fn diagnose_empty_config_returns_empty() {
    let (dir, svc) = setup_config("");

    let diags = svc.diagnose().await.unwrap();
    assert!(
        diags.is_empty(),
        "empty config should produce no diagnostics"
    );

    drop(dir);
}

#[tokio::test]
async fn save_writes_0600_and_leaves_no_temp() {
    let dir = tempfile::tempdir().unwrap();
    let paths = SshPaths::with_dir(dir.path());
    let service = ConfigService::new(&paths);

    service
        .edit(|ast| {
            ConfigService::add_host(
                ast,
                "locked",
                vec![("HostName".to_owned(), "locked.example.com".to_owned())],
            )
        })
        .await
        .unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(paths.config_path())
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "config must be saved 0o600");
    }
    let leftovers: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(std::result::Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with(".config.tmp"))
        .collect();
    assert!(
        leftovers.is_empty(),
        "temp files left behind: {leftovers:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_edits_do_not_lose_writes() {
    let dir = tempfile::tempdir().unwrap();
    let paths = SshPaths::with_dir(dir.path());

    // Warm the file so every racer starts from a real load.
    ConfigService::new(&paths)
        .edit(|ast| {
            ConfigService::add_host(
                ast,
                "seed",
                vec![("HostName".to_owned(), "seed.example.com".to_owned())],
            )
        })
        .await
        .unwrap();

    let mut handles = Vec::new();
    for i in 0..8 {
        let paths = SshPaths::with_dir(dir.path());
        handles.push(tokio::spawn(async move {
            let service = ConfigService::new(&paths);
            let name = format!("racer{i}");
            service
                .edit(|ast| {
                    ConfigService::add_host(
                        ast,
                        &name,
                        vec![("HostName".to_owned(), format!("r{i}.example.com"))],
                    )
                })
                .await
        }));
    }
    for handle in handles {
        handle.await.unwrap().unwrap();
    }

    let content = std::fs::read_to_string(dir.path().join("config")).unwrap();
    for i in 0..8 {
        assert!(
            content.contains(&format!("Host racer{i}\n")),
            "racer{i} lost to a concurrent edit:\n{content}"
        );
    }
    assert!(content.contains("Host seed\n"));
}
