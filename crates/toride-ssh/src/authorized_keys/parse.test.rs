use super::*;
use std::io::Write as IoWrite;

#[test]
fn find_key_type_offset_should_return_zero_when_no_options_present() {
    assert_eq!(find_key_type_offset("ssh-rsa AAAAB3Nz..."), Some(0));
}

#[test]
fn find_key_type_offset_should_skip_past_options() {
    let line = "command=\"true\" ssh-ed25519 AAAAC3Nz...";
    let offset = find_key_type_offset(line).unwrap();
    assert!(line[offset..].starts_with("ssh-ed25519 "));
}

#[test]
fn find_key_type_offset_should_handle_spaces_in_quoted_values() {
    let line = "command=\"echo hello world\" ssh-ed25519 AAAAC3Nz...";
    let offset = find_key_type_offset(line).unwrap();
    assert!(line[offset..].starts_with("ssh-ed25519 "));
}

#[test]
fn find_key_type_offset_should_handle_escaped_quotes_in_values() {
    let line = "command=\"echo \\\"hello\\\"\" ssh-ed25519 AAAAC3Nz...";
    let offset = find_key_type_offset(line).unwrap();
    assert!(line[offset..].starts_with("ssh-ed25519 "));
}

#[test]
fn find_key_type_offset_should_return_none_when_no_key_type_found() {
    assert_eq!(find_key_type_offset("just some random text"), None);
}

#[test]
fn find_key_type_offset_should_ignore_key_type_prefix_inside_quotes() {
    // "ssh-ed25519" inside a quoted value must NOT be detected as key type
    let line = "command=\"ssh-ed25519 is cool\" ssh-rsa AAAAB3Nz...";
    let offset = find_key_type_offset(line).unwrap();
    assert_eq!(&line[offset..offset + 7], "ssh-rsa");
}

#[tokio::test]
async fn parse_authorized_keys_should_return_empty_vec_for_empty_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("authorized_keys");
    std::fs::write(&path, "").unwrap();
    let entries = parse_authorized_keys(&path).await.unwrap();
    assert!(entries.is_empty());
}

#[tokio::test]
async fn parse_authorized_keys_should_skip_comments_and_blank_lines() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("authorized_keys");
    let mut f = std::fs::File::create(&path).unwrap();
    writeln!(f, "# this is a comment").unwrap();
    writeln!(f).unwrap();
    writeln!(f, "  ").unwrap();
    let entries = parse_authorized_keys(&path).await.unwrap();
    assert!(entries.is_empty());
}
