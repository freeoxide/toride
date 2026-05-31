use super::*;
use crate::types::Severity;

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

    assert_eq!(conflicts.len(), 1, "expected exactly one proxy conflict diagnostic");
    assert_eq!(conflicts[0].severity, Severity::Warning);
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

    assert_eq!(dupes.len(), 1, "expected exactly one duplicate alias diagnostic");
    assert_eq!(dupes[0].severity, Severity::Warning);
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
    assert_eq!(star[0].severity, Severity::Warning);
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
    let (dir, svc) = setup_config(
        "\
Host production
    HostName prod.example.com
    User deploy
    IdentityFile ~/.ssh/id_ed25519

Host staging
    HostName staging.example.com
    User deploy

Host *
    ServerAliveInterval 60
",
    );

    let diags = svc.diagnose().await.unwrap();

    // No warnings or errors expected — all diagnostics should be absent.
    // (IdentityFile existence is not checked by config diagnose, only .pub suffix.)
    let warnings: Vec<_> = diags
        .iter()
        .filter(|d| d.severity == Severity::Warning)
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
    assert_eq!(pub_warns[0].severity, Severity::Warning);
    assert!(pub_warns[0].message.contains(".pub"));

    drop(dir);
}

#[tokio::test]
async fn diagnose_empty_config_returns_empty() {
    let (dir, svc) = setup_config("");

    let diags = svc.diagnose().await.unwrap();
    assert!(diags.is_empty(), "empty config should produce no diagnostics");

    drop(dir);
}
