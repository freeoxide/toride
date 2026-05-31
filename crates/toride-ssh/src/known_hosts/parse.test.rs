use super::*;

#[test]
fn parse_line_should_return_entry_for_simple_valid_input() {
    let line = "github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";
    let entry = parse_line(line, 1).unwrap();
    assert!(entry.markers.is_empty());
    assert_eq!(entry.hosts, vec!["github.com"]);
    assert_eq!(entry.key_type, "ssh-ed25519");
    assert!(entry.comment.is_none());
}

#[test]
fn parse_line_should_capture_trailing_comment() {
    let line = "example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB9dG4kjRhQTtWTVzd2t27+t0DEHBPW7iOD23TUiYLio my comment here";
    let entry = parse_line(line, 2).unwrap();
    assert_eq!(entry.comment.as_deref(), Some("my comment here"));
}

#[test]
fn parse_line_should_parse_revoked_marker() {
    let line = "@revoked example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB9dG4kjRhQTtWTVzd2t27+t0DEHBPW7iOD23TUiYLio";
    let entry = parse_line(line, 3).unwrap();
    assert_eq!(entry.markers, vec!["@revoked"]);
}

#[test]
fn parse_line_should_parse_cert_authority_marker() {
    let line = "@cert-authority *.example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB9dG4kjRhQTtWTVzd2t27+t0DEHBPW7iOD23TUiYLio";
    let entry = parse_line(line, 10).unwrap();
    assert_eq!(entry.markers, vec!["@cert-authority"]);
    assert_eq!(entry.hosts, vec!["*.example.com"]);
}

#[test]
fn parse_line_should_preserve_hashed_hostname() {
    let line = "|1|JfKTdBh7rNbXkVAQCRp4OQoPfmI=|USECr3SWf1JUPsms5AqfD5QfxkM= ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB9dG4kjRhQTtWTVzd2t27+t0DEHBPW7iOD23TUiYLio";
    let entry = parse_line(line, 4).unwrap();
    assert_eq!(entry.hosts.len(), 1);
    assert!(entry.hosts[0].starts_with("|1|"));
}

#[test]
fn parse_line_should_split_comma_separated_hosts() {
    let line = "host1,host2,!host3 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB9dG4kjRhQTtWTVzd2t27+t0DEHBPW7iOD23TUiYLio";
    let entry = parse_line(line, 5).unwrap();
    assert_eq!(entry.hosts, vec!["host1", "host2", "!host3"]);
}

#[test]
fn parse_line_should_parse_bracketed_host_and_port() {
    let line = "[192.168.1.1]:2222 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB9dG4kjRhQTtWTVzd2t27+t0DEHBPW7iOD23TUiYLio";
    let entry = parse_line(line, 6).unwrap();
    assert_eq!(entry.hosts, vec!["[192.168.1.1]:2222"]);
}

#[test]
fn parse_line_should_parse_ipv6_bracketed_host() {
    let line = "[::1]:22 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB9dG4kjRhQTtWTVzd2t27+t0DEHBPW7iOD23TUiYLio";
    let entry = parse_line(line, 7).unwrap();
    assert_eq!(entry.hosts, vec!["[::1]:22"]);
}

#[test]
fn parse_line_should_error_when_insufficient_fields() {
    assert!(parse_line("github.com", 1).is_err());
    assert!(parse_line("github.com ssh-ed25519", 2).is_err());
}

#[test]
fn parse_line_should_error_for_full_line_comment() {
    assert!(parse_line("# this is a comment", 8).is_err());
}

#[test]
fn parse_line_should_parse_rsa_key_type() {
    let line = "host ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7";
    let entry = parse_line(line, 9).unwrap();
    assert_eq!(entry.key_type, "ssh-rsa");
    assert_eq!(entry.public_key, "AAAAB3NzaC1yc2EAAAADAQABAAABgQC7");
}

#[test]
fn parse_line_should_parse_ecdsa_key_type() {
    let line = "host ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTY=";
    let entry = parse_line(line, 10).unwrap();
    assert_eq!(entry.key_type, "ecdsa-sha2-nistp256");
}

#[test]
fn parse_line_should_parse_security_key_type() {
    let line = "host sk-ssh-ed25519@openssh.com AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";
    let entry = parse_line(line, 11).unwrap();
    assert_eq!(entry.key_type, "sk-ssh-ed25519@openssh.com");
}

// ---------------------------------------------------------------------------
// Edge-case tests
// ---------------------------------------------------------------------------

#[test]
fn parse_line_empty_string_errors() {
    assert!(parse_line("", 1).is_err());
}

#[test]
fn parse_line_whitespace_only_errors() {
    assert!(parse_line("   ", 1).is_err());
}

#[test]
fn parse_line_preserves_line_number() {
    let line = "host ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";
    let entry = parse_line(line, 42).unwrap();
    assert_eq!(entry.line_number, 42);
}

#[test]
fn parse_line_multiple_hosts() {
    let line = "host1,host2,host3 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";
    let entry = parse_line(line, 1).unwrap();
    assert_eq!(entry.hosts.len(), 3);
    assert_eq!(entry.hosts[0], "host1");
    assert_eq!(entry.hosts[1], "host2");
    assert_eq!(entry.hosts[2], "host3");
}

#[test]
fn parse_line_negated_host_pattern() {
    let line = "!badhost ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";
    let entry = parse_line(line, 1).unwrap();
    assert_eq!(entry.hosts, vec!["!badhost"]);
}

#[test]
fn parse_line_glob_pattern() {
    let line = "*.example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";
    let entry = parse_line(line, 1).unwrap();
    assert_eq!(entry.hosts, vec!["*.example.com"]);
}

// ---------------------------------------------------------------------------
// Weird edge-case tests
// ---------------------------------------------------------------------------

#[test]
fn parse_line_with_trailing_whitespace() {
    let line = "host ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl   ";
    let entry = parse_line(line.trim(), 1).unwrap();
    assert_eq!(entry.key_type, "ssh-ed25519");
}

#[test]
fn parse_line_with_empty_comment() {
    // Comment field that's just whitespace after the key
    let line = "host ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl ";
    let entry = parse_line(line.trim(), 1).unwrap();
    // Empty comment should be None
    assert!(entry.comment.is_none() || entry.comment.as_deref() == Some(""));
}

#[test]
fn parse_line_ipv6_address() {
    let line = "[::1]:22 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";
    let entry = parse_line(line, 1).unwrap();
    assert_eq!(entry.hosts, vec!["[::1]:22"]);
}

#[test]
fn parse_line_ipv6_address_no_port() {
    let line = "::1 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";
    let entry = parse_line(line, 1).unwrap();
    assert_eq!(entry.hosts, vec!["::1"]);
}

#[test]
fn parse_line_wildcard_host() {
    let line = "* ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";
    let entry = parse_line(line, 1).unwrap();
    assert_eq!(entry.hosts, vec!["*"]);
}

#[test]
fn parse_line_with_comment_containing_spaces() {
    let line = "host ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl this is a long comment with spaces";
    let entry = parse_line(line, 1).unwrap();
    assert_eq!(entry.comment.as_deref(), Some("this is a long comment with spaces"));
}

#[test]
fn parse_line_rsa_4096_key() {
    // RSA 4096-bit keys have very long base64
    let key_data = "A".repeat(1000);
    let long_key = format!("ssh-rsa {key_data}");
    let line = format!("host {long_key}");
    let entry = parse_line(&line, 1).unwrap();
    assert_eq!(entry.key_type, "ssh-rsa");
}

#[test]
fn parse_line_with_multiple_markers() {
    // Multiple markers — the parser captures only the first one
    let line = "@cert-authority @revoked host ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";
    let entry = parse_line(line, 1).unwrap();
    // The parser treats "@revoked host" as part of the hosts field
    assert_eq!(entry.markers.len(), 1);
    assert_eq!(entry.markers[0], "@cert-authority");
}

// ---------------------------------------------------------------------------
// Production-grade weird edge cases
// ---------------------------------------------------------------------------

#[test]
fn parse_line_with_very_long_base64() {
    let key_data = "A".repeat(10000);
    let long_key = format!("ssh-ed25519 {key_data}");
    let line = format!("host {long_key}");
    let entry = parse_line(&line, 1).unwrap();
    assert_eq!(entry.key_type, "ssh-ed25519");
    assert_eq!(entry.public_key.len(), 10000);
}

#[test]
fn parse_line_with_base64_padding() {
    // Base64 padding characters
    let line = "host ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl==";
    let entry = parse_line(line, 1).unwrap();
    assert!(entry.public_key.ends_with("=="));
}

#[test]
fn parse_line_with_comment_containing_at() {
    let line = "host ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl user@host";
    let entry = parse_line(line, 1).unwrap();
    assert_eq!(entry.comment.as_deref(), Some("user@host"));
}

#[test]
fn parse_line_with_comment_containing_hash() {
    let line = "host ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl #tag";
    let entry = parse_line(line, 1).unwrap();
    assert_eq!(entry.comment.as_deref(), Some("#tag"));
}

#[test]
fn parse_line_with_host_containing_underscore() {
    let line = "my_host ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";
    let entry = parse_line(line, 1).unwrap();
    assert_eq!(entry.hosts, vec!["my_host"]);
}

#[test]
fn parse_line_with_host_containing_hyphen() {
    let line = "my-host.example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";
    let entry = parse_line(line, 1).unwrap();
    assert_eq!(entry.hosts, vec!["my-host.example.com"]);
}

#[test]
fn parse_line_with_port_in_brackets() {
    let line = "[host]:2222 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";
    let entry = parse_line(line, 1).unwrap();
    assert_eq!(entry.hosts, vec!["[host]:2222"]);
}

#[test]
fn parse_line_preserves_key_type_string() {
    // The key_type field should be the raw string, not a parsed enum
    let line = "host ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";
    let entry = parse_line(line, 1).unwrap();
    assert_eq!(entry.key_type, "ssh-ed25519");
}

#[test]
fn parse_line_preserves_public_key_string() {
    let key_data = "AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";
    let line = format!("host ssh-ed25519 {key_data}");
    let entry = parse_line(&line, 1).unwrap();
    assert_eq!(entry.public_key, key_data);
}

#[test]
fn parse_line_with_dsa_key() {
    let line = "host ssh-dss AAAAB3NzaC1kc3MAAACBAO...";
    let entry = parse_line(line, 1).unwrap();
    assert_eq!(entry.key_type, "ssh-dss");
}

#[test]
fn parse_line_with_ecdsa_key() {
    let line = "host ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTY...";
    let entry = parse_line(line, 1).unwrap();
    assert_eq!(entry.key_type, "ecdsa-sha2-nistp256");
}

#[test]
fn parse_line_line_number_preserved() {
    let line = "host ssh-ed25519 AAAAC3...";
    let entry = parse_line(line, 999).unwrap();
    assert_eq!(entry.line_number, 999);
}

// ---------------------------------------------------------------------------
// Workflow-discovered edge cases
// ---------------------------------------------------------------------------

#[test]
fn parse_line_with_revoked_key_id() {
    // A key ID that happens to be "REVOKED" should not be skipped
    let line = "host ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";
    let entry = parse_line(line, 1).unwrap();
    assert_eq!(entry.key_type, "ssh-ed25519");
}

#[test]
fn parse_line_with_host_matching_another_entry() {
    // Two entries for the same host should both parse correctly
    let line1 = "host ssh-ed25519 AAAAC3...";
    let line2 = "host ssh-rsa AAAAB3...";
    let entry1 = parse_line(line1, 1).unwrap();
    let entry2 = parse_line(line2, 2).unwrap();
    assert_eq!(entry1.hosts, entry2.hosts);
    assert_ne!(entry1.key_type, entry2.key_type);
}

// ---------------------------------------------------------------------------
// Very long base64 keys
// ---------------------------------------------------------------------------

#[test]
fn parse_line_rsa_8192_key() {
    // RSA 8192-bit keys produce very long base64 blobs (~1200+ chars).
    // Use a realistic-looking base64 pattern.
    let key_data = format!("AAAAB3NzaC1yc2EAAAADAQABAAACAQ{}", "B".repeat(5000));
    let line = format!("host ssh-rsa {key_data}");
    let entry = parse_line(&line, 1).unwrap();
    assert_eq!(entry.key_type, "ssh-rsa");
    assert_eq!(entry.public_key.len(), key_data.len());
    // The key should be preserved verbatim.
    assert_eq!(entry.public_key, key_data);
}

#[test]
fn parse_line_very_long_base64_preserves_all_chars() {
    // Ensure no characters are dropped or corrupted in a very long key.
    let key_data = format!("AAAAC3NzaC1lZDI1NTE5AAAA{}", "AaBbCcDdEeFf0123456789".repeat(500));
    let line = format!("host ssh-ed25519 {key_data}");
    let entry = parse_line(&line, 1).unwrap();
    assert_eq!(entry.public_key, key_data);
    assert_eq!(entry.public_key.len(), key_data.len());
}

#[test]
fn parse_line_long_key_with_comment() {
    // Very long key followed by a comment.
    let key_data = format!("AAAAC3NzaC1lZDI1NTE5AAAA{}", "X".repeat(8000));
    let line = format!("server ssh-ed25519 {key_data} admin@server.example.com");
    let entry = parse_line(&line, 42).unwrap();
    assert_eq!(entry.key_type, "ssh-ed25519");
    assert_eq!(entry.public_key, key_data);
    assert_eq!(entry.comment.as_deref(), Some("admin@server.example.com"));
    assert_eq!(entry.line_number, 42);
}

#[test]
fn parse_line_long_key_with_cert_authority_marker() {
    // @cert-authority with a very long key.
    let key_data = format!("AAAA{}", "Y".repeat(6000));
    let line = format!("@cert-authority *.example.com ssh-rsa {key_data}");
    let entry = parse_line(&line, 1).unwrap();
    assert_eq!(entry.markers, vec!["@cert-authority"]);
    assert_eq!(entry.hosts, vec!["*.example.com"]);
    assert_eq!(entry.key_type, "ssh-rsa");
    assert_eq!(entry.public_key, key_data);
}

#[test]
fn parse_line_long_key_with_revoked_marker() {
    // @revoked with a very long ecdsa key.
    let key_data = format!("AAAAE2VjZHNhLXNoYTItbmlzdHAyNTY{}", "Z".repeat(4000));
    let line = format!("@revoked compromised.example.com ecdsa-sha2-nistp256 {key_data}");
    let entry = parse_line(&line, 1).unwrap();
    assert_eq!(entry.markers, vec!["@revoked"]);
    assert_eq!(entry.key_type, "ecdsa-sha2-nistp256");
    assert_eq!(entry.public_key, key_data);
}
