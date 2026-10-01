use toride_ssh_authorized_keys::Entry;
use toride_ssh_authorized_keys::parse::parse_authorized_keys;

const FIXTURE: &str = include_str!("../tests/fixtures/authorized_keys.txt");

async fn parse_fixture() -> Vec<Entry> {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("authorized_keys");
    std::fs::write(&path, FIXTURE).expect("write fixture");
    parse_authorized_keys(&path)
        .await
        .expect("fixture must parse")
}

#[tokio::test]
async fn fixture_yields_six_entries() {
    let entries = parse_fixture().await;
    assert_eq!(entries.len(), 6, "entry count changed");
    let by_type: Vec<&str> = entries.iter().map(|e| e.key_type.as_str()).collect();
    assert_eq!(
        by_type,
        vec![
            "ssh-ed25519",
            "ssh-ed25519",
            "ssh-rsa",
            "ssh-ed25519",
            "ssh-ed25519",
            "ecdsa-sha2-nistp256",
        ],
        "key type order changed"
    );
}

#[tokio::test]
async fn every_entry_fingerprints() {
    let entries = parse_fixture().await;
    let hashes: Vec<Option<String>> = entries.iter().map(Entry::fingerprint).collect();
    assert!(
        hashes.iter().all(Option::is_some),
        "some entries failed to fingerprint: {hashes:?}"
    );
}

#[tokio::test]
async fn shared_blobs_share_fingerprints() {
    let entries = parse_fixture().await;
    let fp = |i: usize| {
        entries[i]
            .fingerprint()
            .unwrap_or_else(|| panic!("entry {i} must fingerprint"))
    };
    assert_eq!(fp(0), fp(3), "entries 0 and 3 share a blob");
    assert_eq!(fp(1), fp(4), "entries 1 and 4 share a blob");
    assert_ne!(fp(0), fp(1), "distinct ed25519 blobs must differ");
    assert_ne!(fp(0), fp(2), "ed25519 and rsa blobs must differ");
}

#[tokio::test]
async fn quoted_command_options_decode() {
    let entries = parse_fixture().await;
    let entry = &entries[3];
    let options = entry.options.as_ref().expect("entry 3 carries options");
    assert!(options.no_pty, "no-pty flag lost");
    assert!(options.no_agent_forwarding, "no-agent-forwarding flag lost");
    assert_eq!(
        options.command.as_deref(),
        Some("/usr/bin/rrsync --readonly /srv/backup,extra"),
        "quoted command value (spaces + comma) corrupted"
    );
    assert_eq!(entry.comment.as_deref(), Some("backup@host"));
}

#[tokio::test]
async fn restrict_and_from_options_decode() {
    let entries = parse_fixture().await;
    let entry = &entries[4];
    let options = entry.options.as_ref().expect("entry 4 carries options");
    assert!(options.restrict, "restrict flag lost");
    assert_eq!(
        options.from,
        vec!["10.0.0.*".to_owned(), "192.168.1.0/24".to_owned()],
        "quoted from pattern list corrupted"
    );
}
