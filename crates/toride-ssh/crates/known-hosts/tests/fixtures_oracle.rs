use toride_ssh_core::{MockCliRunner, SshPaths};
use toride_ssh_known_hosts::KnownHostEntry;
use toride_ssh_known_hosts::KnownHostsService;

const FIXTURE: &str = include_str!("../../../tests/fixtures/known_hosts_markers.txt");

async fn parse_fixture() -> Vec<KnownHostEntry> {
    let dir = tempfile::tempdir().expect("temp dir");
    std::fs::write(dir.path().join("known_hosts"), FIXTURE).expect("write fixture");
    let paths = SshPaths::with_dir(dir.path());
    let runner = MockCliRunner::new();
    KnownHostsService::new(&paths, &runner)
        .list()
        .await
        .expect("fixture must parse")
}

#[tokio::test]
async fn fixture_yields_nine_entries() {
    let entries = parse_fixture().await;
    assert_eq!(entries.len(), 9, "entry count changed");
}

#[tokio::test]
async fn marker_counts_are_stable() {
    let entries = parse_fixture().await;
    let cert_authority = entries
        .iter()
        .filter(|e| e.markers == vec!["@cert-authority".to_owned()])
        .count();
    let revoked = entries
        .iter()
        .filter(|e| e.markers == vec!["@revoked".to_owned()])
        .count();
    let unmarked = entries.iter().filter(|e| e.markers.is_empty()).count();
    assert_eq!(cert_authority, 2, "@cert-authority count changed");
    assert_eq!(revoked, 1, "@revoked count changed");
    assert_eq!(unmarked, 6, "unmarked entry count changed");
}

#[tokio::test]
async fn all_ed25519_entries_share_one_fingerprint() {
    let entries = parse_fixture().await;
    let ed25519: Vec<&KnownHostEntry> = entries
        .iter()
        .filter(|e| e.key_type == "ssh-ed25519")
        .collect();
    assert_eq!(ed25519.len(), 6, "ed25519 entry count changed");

    let blobs: std::collections::HashSet<&str> =
        ed25519.iter().map(|e| e.public_key.as_str()).collect();
    assert_eq!(
        blobs.len(),
        1,
        "fixture ed25519 blobs are no longer uniform"
    );

    let hashes: std::collections::HashSet<String> = ed25519
        .iter()
        .map(|e| {
            e.fingerprint()
                .expect("every ed25519 entry must fingerprint")
                .hash
        })
        .collect();
    assert_eq!(hashes.len(), 1, "identical blobs produced different hashes");
}

#[tokio::test]
async fn truncated_rsa_blobs_fail_to_fingerprint() {
    let entries = parse_fixture().await;
    let rsa: Vec<&KnownHostEntry> = entries.iter().filter(|e| e.key_type == "ssh-rsa").collect();
    assert_eq!(rsa.len(), 2, "ssh-rsa entry count changed");
    for entry in rsa {
        assert!(
            entry.fingerprint().is_err(),
            "truncated rsa blob on line {} unexpectedly fingerprinted",
            entry.line_number
        );
    }
}

#[tokio::test]
async fn fingerprint_pass_succeeds_for_exactly_the_ed25519_entries() {
    let entries = parse_fixture().await;
    let successes = entries
        .iter()
        .filter(|e| e.key_type != "ecdsa-sha2-nistp256" && e.fingerprint().is_ok())
        .count();
    assert_eq!(successes, 6, "ed25519 fingerprint success count changed");
}
