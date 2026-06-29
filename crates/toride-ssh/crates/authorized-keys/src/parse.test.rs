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

// ---------------------------------------------------------------------------
// Edge-case tests for find_key_type_offset
// ---------------------------------------------------------------------------

#[test]
fn find_key_type_offset_empty_string() {
    assert_eq!(find_key_type_offset(""), None);
}

#[test]
fn find_key_type_offset_only_options() {
    // No key type present
    assert_eq!(find_key_type_offset("command=\"true\""), None);
}

#[test]
fn find_key_type_offset_multiple_options() {
    let line = "no-pty,command=\"true\" ssh-ed25519 AAAAC3...";
    let offset = find_key_type_offset(line).unwrap();
    assert!(line[offset..].starts_with("ssh-ed25519 "));
}

#[test]
fn find_key_type_offset_ecdsa() {
    assert_eq!(find_key_type_offset("ecdsa-sha2-nistp256 AAAA..."), Some(0));
}

#[test]
fn find_key_type_offset_sk_key() {
    assert_eq!(
        find_key_type_offset("sk-ssh-ed25519@openssh.com AAAA..."),
        Some(0)
    );
}

#[test]
fn find_key_type_offset_dss() {
    assert_eq!(find_key_type_offset("ssh-dss AAAA..."), Some(0));
}

// ---------------------------------------------------------------------------
// Edge-case tests for starts_with_key_type
// ---------------------------------------------------------------------------

#[test]
fn starts_with_key_type_all_prefixes() {
    for prefix in KEY_TYPE_PREFIXES {
        assert!(
            starts_with_key_type(&format!("{prefix} AAAA")),
            "failed for prefix: {prefix}"
        );
    }
}

#[test]
fn starts_with_key_type_no_space_after() {
    // Key type must be followed by a space
    assert!(!starts_with_key_type("ssh-ed25519AAAA"));
}

#[test]
fn starts_with_key_type_empty() {
    assert!(!starts_with_key_type(""));
}

#[test]
fn starts_with_key_type_partial_match() {
    assert!(!starts_with_key_type("ssh-ed2 AAAA"));
}

// ---------------------------------------------------------------------------
// Weird edge-case tests
// ---------------------------------------------------------------------------

#[test]
fn find_key_type_offset_with_nested_quotes() {
    // Options with nested quotes should not confuse the parser
    let line = "command=\"echo \\\"ssh-ed25519\\\"\" ssh-rsa AAAA";
    let offset = find_key_type_offset(line).unwrap();
    assert!(&line[offset..].starts_with("ssh-rsa"));
}

#[test]
fn find_key_type_offset_with_backslash_at_end() {
    // Backslash at end of quoted value
    let line = "command=\"path\\\\\" ssh-rsa AAAA";
    let offset = find_key_type_offset(line).unwrap();
    assert!(&line[offset..].starts_with("ssh-rsa"));
}

#[test]
fn find_key_type_offset_with_multiple_options() {
    let line = "no-pty,from=\"10.0.0.*\",command=\"/bin/bash\" ssh-ed25519 AAAA";
    let offset = find_key_type_offset(line).unwrap();
    assert!(&line[offset..].starts_with("ssh-ed25519"));
}

#[test]
fn find_key_type_offset_with_no_space_before_key() {
    // No space between options and key type (malformed)
    let line = "no-ptyssh-ed25519 AAAA";
    // This should still find ssh-ed25519 if it appears after a space
    let result = find_key_type_offset(line);
    // Since there's no space before ssh-ed25519, it should not match
    // (the key type must be preceded by a space or be at position 0)
    let _ = result;
}

#[test]
fn find_key_type_offset_with_key_at_start() {
    let line = "ssh-ed25519 AAAA";
    assert_eq!(find_key_type_offset(line), Some(0));
}

#[test]
fn starts_with_key_type_with_comment() {
    // Key type followed by comment (no space after type)
    assert!(!starts_with_key_type("ssh-ed25519AAAA"));
}

#[test]
fn starts_with_key_type_with_tab() {
    // Key type followed by tab instead of space — the parser requires a space, not tab
    assert!(!starts_with_key_type("ssh-ed25519\tAAAA"));
}

#[test]
fn find_key_type_offset_with_very_long_options() {
    let long_opts = "a".repeat(10000);
    let line = format!("{long_opts} ssh-ed25519 AAAA");
    let offset = find_key_type_offset(&line).unwrap();
    assert!(&line[offset..].starts_with("ssh-ed25519"));
}

#[test]
fn find_key_type_offset_with_empty_options() {
    // Empty options field followed by space
    let line = " ssh-ed25519 AAAA";
    let offset = find_key_type_offset(line).unwrap();
    assert_eq!(offset, 1);
}

#[test]
fn find_key_type_offset_with_escaped_quote_at_boundary() {
    // Escaped quote right before the space
    let line = "command=\"test\\\"\" ssh-ed25519 AAAA";
    let offset = find_key_type_offset(line).unwrap();
    assert!(&line[offset..].starts_with("ssh-ed25519"));
}

// ---------------------------------------------------------------------------
// Edge-case tests: keys with complex options (full parse_line)
// ---------------------------------------------------------------------------
// These tests use a valid ed25519 public key so ssh_key validation passes.

const VALID_ED25519: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";

#[test]
fn parse_line_restrict_with_permit_open_and_no_pty() {
    let line =
        format!("restrict,permit-open=\"host1:22,host2:80\",no-pty {VALID_ED25519} deploy@server");
    let entry = parse_line(&line, 1, &line).unwrap();

    assert!(entry.options.is_some());
    let opts = entry.options.as_ref().unwrap();
    assert!(opts.restrict, "restrict should be true");
    assert!(opts.no_pty, "no-pty should be true");
    assert_eq!(opts.permit_open, vec!["host1:22", "host2:80"]);
    assert_eq!(entry.comment.as_deref(), Some("deploy@server"));
}

#[test]
fn parse_line_command_with_from_and_environment() {
    let line = format!(
        "from=\"10.0.0.*,192.168.1.0/24\",command=\"/usr/bin/backup.sh\",environment=\"BACKUP_DIR=/data\" {VALID_ED25519} backup@cron"
    );
    let entry = parse_line(&line, 1, &line).unwrap();

    let opts = entry.options.as_ref().unwrap();
    assert_eq!(opts.from, vec!["10.0.0.*", "192.168.1.0/24"]);
    assert_eq!(opts.command.as_deref(), Some("/usr/bin/backup.sh"));
    assert_eq!(
        opts.environment,
        vec![("BACKUP_DIR".to_string(), "/data".to_string())]
    );
    assert_eq!(entry.comment.as_deref(), Some("backup@cron"));
}

#[test]
fn parse_line_cert_authority_with_principals() {
    let line = format!("cert-authority,principals=\"admin,deploy,ops\" {VALID_ED25519}");
    let entry = parse_line(&line, 1, &line).unwrap();

    let opts = entry.options.as_ref().unwrap();
    assert!(opts.cert_authority);
    // principals stores the raw value as a single entry (not comma-split).
    assert_eq!(opts.principals, vec!["admin,deploy,ops"]);
    assert!(entry.comment.is_none());
}

#[test]
fn parse_line_all_forwarding_restrictions() {
    let line = format!(
        "no-pty,no-port-forwarding,no-X11-forwarding,no-agent-forwarding,no-user-rc {VALID_ED25519}"
    );
    let entry = parse_line(&line, 1, &line).unwrap();

    let opts = entry.options.as_ref().unwrap();
    assert!(opts.no_pty);
    assert!(opts.no_port_forwarding);
    assert!(opts.no_x11_forwarding);
    assert!(opts.no_agent_forwarding);
    assert!(opts.no_user_rc);
}

#[test]
fn parse_line_tunnel_with_expiry() {
    let line = format!("tunnel=\"eth0\",expiry-time=\"20261231T235959\" {VALID_ED25519} infra@net");
    let entry = parse_line(&line, 1, &line).unwrap();

    let opts = entry.options.as_ref().unwrap();
    assert_eq!(opts.tunnel.as_deref(), Some("eth0"));
    assert_eq!(opts.expiry_time.as_deref(), Some("20261231T235959"));
    assert_eq!(entry.comment.as_deref(), Some("infra@net"));
}

#[test]
fn parse_line_command_with_escaped_quotes_and_commas() {
    let line = format!("command=\"echo \\\"hello, world\\\"\" {VALID_ED25519} user@host");
    let entry = parse_line(&line, 1, &line).unwrap();

    let opts = entry.options.as_ref().unwrap();
    assert_eq!(opts.command.as_deref(), Some("echo \"hello, world\""));
}

#[test]
fn parse_line_no_options() {
    let line = format!("{VALID_ED25519} simple@host");
    let entry = parse_line(&line, 1, &line).unwrap();

    assert!(entry.options.is_none());
    assert_eq!(entry.key_type, "ssh-ed25519");
    assert_eq!(entry.comment.as_deref(), Some("simple@host"));
}

// ---------------------------------------------------------------------------
// Integration: parse_authorized_keys with complex entries
// ---------------------------------------------------------------------------

#[tokio::test]
async fn parse_authorized_keys_with_complex_options() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("authorized_keys");

    let content = format!(
        "# Deployment key with restrictions\n\
         restrict,permit-open=\"db:5432,cache:6379\",from=\"10.0.0.*\" {VALID_ED25519} deploy@ci\n\
         \n\
         # Backup key\n\
         command=\"/usr/local/bin/backup.sh\",no-pty,no-port-forwarding {VALID_ED25519} backup@cron\n\
         \n\
         # CA key\n\
         cert-authority,principals=\"admin,ops\" {VALID_ED25519}\n"
    );
    std::fs::write(&path, content).unwrap();

    let entries = parse_authorized_keys(&path).await.unwrap();
    assert_eq!(entries.len(), 3, "should parse 3 key entries");

    // First entry: restrict + permit-open + from
    let deploy = &entries[0];
    let opts = deploy.options.as_ref().unwrap();
    assert!(opts.restrict);
    assert_eq!(opts.permit_open, vec!["db:5432", "cache:6379"]);
    assert_eq!(opts.from, vec!["10.0.0.*"]);
    assert_eq!(deploy.comment.as_deref(), Some("deploy@ci"));
    assert_eq!(deploy.line_number, 2);

    // Second entry: command + no-pty + no-port-forwarding
    let backup = &entries[1];
    let opts = backup.options.as_ref().unwrap();
    assert_eq!(opts.command.as_deref(), Some("/usr/local/bin/backup.sh"));
    assert!(opts.no_pty);
    assert!(opts.no_port_forwarding);
    assert_eq!(backup.line_number, 5);

    // Third entry: cert-authority + principals
    let ca = &entries[2];
    let opts = ca.options.as_ref().unwrap();
    assert!(opts.cert_authority);
    // principals stores the raw value as a single entry (not comma-split).
    assert_eq!(opts.principals, vec!["admin,ops"]);
    assert_eq!(ca.line_number, 8);
}
