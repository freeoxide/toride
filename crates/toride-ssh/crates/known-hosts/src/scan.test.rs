use super::*;

#[test]
fn parse_keyscan_line_should_return_key_for_valid_input() {
    let line = "example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";
    let key = parse_keyscan_line("example.com", line).unwrap();
    assert_eq!(key.host, "example.com");
    assert_eq!(key.raw_host, "example.com");
    assert_eq!(key.key_type, "ssh-ed25519");
    assert_eq!(
        key.public_key,
        "AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
    );
}

#[test]
fn parse_keyscan_line_should_preserve_original_host_for_hashed_input() {
    let line = "|1|JfKTdBh7rNbXkVAQCRp4OQoPfmI=|USECr3SWf1JUPsms5AqfD5QfxkM= ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";
    let key = parse_keyscan_line("example.com", line).unwrap();
    assert_eq!(key.host, "example.com");
    assert_eq!(
        key.raw_host,
        "|1|JfKTdBh7rNbXkVAQCRp4OQoPfmI=|USECr3SWf1JUPsms5AqfD5QfxkM="
    );
}

#[test]
fn parse_keyscan_line_should_error_for_malformed_input() {
    assert!(parse_keyscan_line("host", "only-one-field").is_err());
    assert!(parse_keyscan_line("host", "two fields").is_err());
}

// ---------------------------------------------------------------------------
// Edge-case tests
// ---------------------------------------------------------------------------

#[test]
fn parse_keyscan_line_empty_string() {
    assert!(parse_keyscan_line("host", "").is_err());
}

#[test]
fn parse_keyscan_line_whitespace_only() {
    assert!(parse_keyscan_line("host", "   ").is_err());
}

#[test]
fn parse_keyscan_line_preserves_original_host() {
    let line = "scanned-host ssh-rsa AAAAB3...";
    let key = parse_keyscan_line("original-host", line).unwrap();
    assert_eq!(key.host, "original-host");
    assert_eq!(key.raw_host, "scanned-host");
}

#[test]
fn parse_keyscan_line_with_comment() {
    let line = "host ssh-ed25519 AAAAC3... optional-comment";
    let key = parse_keyscan_line("host", line).unwrap();
    // Comment is not captured by parse_keyscan_line
    assert_eq!(key.key_type, "ssh-ed25519");
}

#[test]
fn parse_keyscan_line_rsa() {
    let line = "host ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7";
    let key = parse_keyscan_line("host", line).unwrap();
    assert_eq!(key.key_type, "ssh-rsa");
}

#[test]
fn parse_keyscan_line_ecdsa() {
    let line = "host ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTY=";
    let key = parse_keyscan_line("host", line).unwrap();
    assert_eq!(key.key_type, "ecdsa-sha2-nistp256");
}

#[test]
fn parse_keyscan_output_empty() {
    let keys = parse_keyscan_output("host", "");
    assert!(keys.is_empty());
}

#[test]
fn parse_keyscan_output_only_comments() {
    let output = "# comment 1\n# comment 2\n";
    let keys = parse_keyscan_output("host", output);
    assert!(keys.is_empty());
}

#[test]
fn parse_keyscan_output_skips_empty_lines() {
    let output = "\n\nhost ssh-ed25519 AAAAC3...\n\n";
    let keys = parse_keyscan_output("host", output);
    assert_eq!(keys.len(), 1);
}

#[test]
fn parse_keyscan_output_multiple_keys() {
    let output = "host ssh-ed25519 AAAAC3...\nhost ssh-rsa AAAAB3...\n";
    let keys = parse_keyscan_output("host", output);
    assert_eq!(keys.len(), 2);
}

#[test]
fn parse_keyscan_output_malformed_lines_skipped() {
    let output = "host ssh-ed25519 AAAAC3...\nmalformed\nhost ssh-rsa AAAAB3...\n";
    let keys = parse_keyscan_output("host", output);
    assert_eq!(keys.len(), 2); // malformed line is skipped
}
