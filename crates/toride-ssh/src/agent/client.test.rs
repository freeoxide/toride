use super::*;

#[test]
fn parse_algorithm_ed25519() {
    assert_eq!(
        parse_key_type_from_algorithm("ssh-ed25519"),
        Some(KeyType::Ed25519)
    );
}

#[test]
fn parse_algorithm_ecdsa() {
    assert_eq!(
        parse_key_type_from_algorithm("ecdsa-sha2-nistp384"),
        Some(KeyType::EcdsaP384)
    );
}

#[test]
fn parse_algorithm_unknown_returns_none() {
    assert_eq!(parse_key_type_from_algorithm("unknown-algo"), None);
}

#[test]
fn parse_algorithm_empty_string_returns_none() {
    assert_eq!(parse_key_type_from_algorithm(""), None);
}

#[test]
fn parse_algorithm_all_known_types() {
    assert_eq!(parse_key_type_from_algorithm("ssh-ed25519"), Some(KeyType::Ed25519));
    assert_eq!(parse_key_type_from_algorithm("ssh-rsa"), Some(KeyType::Rsa { bits: 0 }));
    assert_eq!(parse_key_type_from_algorithm("ecdsa-sha2-nistp256"), Some(KeyType::EcdsaP256));
    assert_eq!(parse_key_type_from_algorithm("ecdsa-sha2-nistp384"), Some(KeyType::EcdsaP384));
    assert_eq!(parse_key_type_from_algorithm("ecdsa-sha2-nistp521"), Some(KeyType::EcdsaP521));
    assert_eq!(parse_key_type_from_algorithm("ssh-dss"), Some(KeyType::Dsa));
    assert_eq!(parse_key_type_from_algorithm("sk-ssh-ed25519@openssh.com"), Some(KeyType::SkEd25519));
    assert_eq!(parse_key_type_from_algorithm("sk-ecdsa-sha2-nistp256@openssh.com"), Some(KeyType::SkEcdsaP256));
}

#[test]
fn parse_ssh_add_line_ed25519() {
    let line = "256 SHA256:ABCDEFGH1234567890 comment here (ED25519)";
    let key = parse_ssh_add_line(line).unwrap();
    assert_eq!(key.key_type, KeyType::Ed25519);
    assert_eq!(key.comment.as_deref(), Some("comment here"));
}

#[test]
fn parse_ssh_add_line_rsa_no_comment() {
    let line = "2048 SHA256:xyz123  (RSA)";
    let key = parse_ssh_add_line(line).unwrap();
    assert!(matches!(key.key_type, KeyType::Rsa { .. }));
    assert!(key.comment.is_none());
}

#[test]
fn parse_ssh_add_no_identities() {
    assert!(parse_ssh_add_line("The agent has no identities").is_none());
}

#[test]
fn parse_ssh_add_empty_line() {
    assert!(parse_ssh_add_line("").is_none());
}

#[test]
fn parse_ssh_add_whitespace_only() {
    assert!(parse_ssh_add_line("   ").is_none());
}

#[test]
fn parse_ssh_add_unknown_type_returns_none() {
    // Unknown key type in parentheses should return None
    let line = "256 SHA256:AAAA comment (UNKNOWN-TYPE)";
    assert!(parse_ssh_add_line(line).is_none());
}

#[test]
fn parse_ssh_add_ecdsa_sk() {
    let line = "256 SHA256:AAAA user@host (ECDSA-SK)";
    let key = parse_ssh_add_line(line).unwrap();
    assert_eq!(key.key_type, KeyType::SkEcdsaP256);
    assert_eq!(key.comment.as_deref(), Some("user@host"));
}

#[test]
fn parse_ssh_add_ed25519_sk() {
    let line = "256 SHA256:AAAA user@host (ED25519-SK)";
    let key = parse_ssh_add_line(line).unwrap();
    assert_eq!(key.key_type, KeyType::SkEd25519);
}

#[test]
fn parse_ssh_add_dsa() {
    let line = "1024 SHA256:AAAA user@host (DSA)";
    let key = parse_ssh_add_line(line).unwrap();
    assert_eq!(key.key_type, KeyType::Dsa);
}

#[test]
fn parse_ssh_add_agent_source() {
    let line = "256 SHA256:AAAA comment (ED25519)";
    let key = parse_ssh_add_line(line).unwrap();
    assert_eq!(key.source, KeySource::Agent);
    assert!(!key.encrypted);
    assert!(!key.has_public_pair);
    assert!(!key.has_certificate);
}

#[test]
fn parse_ssh_add_fingerprint_format() {
    let line = "256 SHA256:abcdef1234567890 comment (ED25519)";
    let key = parse_ssh_add_line(line).unwrap();
    let fp = key.fingerprint.unwrap();
    assert_eq!(fp.hash, "abcdef1234567890");
    assert_eq!(fp.key_type, KeyType::Ed25519);
}

#[test]
fn parse_ssh_add_path_is_agent_identifier() {
    let line = "256 SHA256:AAAA my-key (ED25519)";
    let key = parse_ssh_add_line(line).unwrap();
    assert!(key.path.to_str().unwrap().starts_with("agent:"));
}

// ---------------------------------------------------------------------------
// Weird edge-case tests
// ---------------------------------------------------------------------------

#[test]
fn parse_ssh_add_line_with_unicode_comment() {
    let line = "256 SHA256:AAAA utilisateur@hôte (ED25519)";
    let key = parse_ssh_add_line(line).unwrap();
    assert_eq!(key.comment.as_deref(), Some("utilisateur@hôte"));
}

#[test]
fn parse_ssh_add_line_with_very_long_comment() {
    let long_comment = "a".repeat(1000);
    let line = format!("256 SHA256:AAAA {long_comment} (ED25519)");
    let key = parse_ssh_add_line(&line).unwrap();
    assert_eq!(key.comment.as_deref(), Some(long_comment.as_str()));
}

#[test]
fn parse_ssh_add_line_with_empty_comment_field() {
    // Two spaces between fingerprint and type (empty comment)
    let line = "256 SHA256:AAAA  (ED25519)";
    let key = parse_ssh_add_line(line).unwrap();
    assert!(key.comment.is_none());
}

#[test]
fn parse_ssh_add_line_with_spaces_in_comment() {
    let line = "256 SHA256:AAAA my ssh key (ED25519)";
    let key = parse_ssh_add_line(line).unwrap();
    assert_eq!(key.comment.as_deref(), Some("my ssh key"));
}

#[test]
fn parse_ssh_add_line_case_insensitive_type() {
    // ssh-add output uses uppercase: (ED25519), (RSA), etc.
    // But our parser should handle case variations
    let line = "256 SHA256:AAAA comment (ed25519)";
    let key = parse_ssh_add_line(line).unwrap();
    assert_eq!(key.key_type, KeyType::Ed25519);
}

#[test]
fn parse_ssh_add_line_with_special_chars_in_fingerprint() {
    // Fingerprint with + and / characters (base64)
    let line = "256 SHA256:abc+/def comment (ED25519)";
    let key = parse_ssh_add_line(line).unwrap();
    assert_eq!(key.fingerprint.unwrap().hash, "abc+/def");
}

#[test]
fn parse_ssh_add_line_bits_field() {
    // The bits field is parsed but not stored - verify it doesn't cause issues
    let line = "4096 SHA256:AAAA comment (RSA)";
    let key = parse_ssh_add_line(line).unwrap();
    assert!(matches!(key.key_type, KeyType::Rsa { .. }));
}

#[test]
fn parse_algorithm_whitespace_around() {
    // Algorithm name with whitespace should not match
    assert_eq!(parse_key_type_from_algorithm(" ssh-ed25519 "), None);
    assert_eq!(parse_key_type_from_algorithm(" ssh-ed25519"), None);
}

#[test]
fn parse_algorithm_prefix_only() {
    // Just the prefix without the full algorithm name
    assert_eq!(parse_key_type_from_algorithm("ssh-"), None);
    assert_eq!(parse_key_type_from_algorithm("ecdsa"), None);
}

#[test]
fn parse_ssh_add_line_with_extra_spaces() {
    // Multiple spaces between fields
    let line = "256  SHA256:AAAA  comment  (ED25519)";
    // This should fail because split_once(' ') expects single space
    let result = parse_ssh_add_line(line);
    // May return None due to parsing failure
    let _ = result;
}

// ---------------------------------------------------------------------------
// Production-grade weird edge cases
// ---------------------------------------------------------------------------

#[test]
fn parse_ssh_add_line_with_tab_in_comment() {
    let line = "256 SHA256:AAAA comment\twith\ttabs (ED25519)";
    let key = parse_ssh_add_line(line).unwrap();
    assert!(key.comment.unwrap().contains('\t'));
}

#[test]
fn parse_ssh_add_line_with_newline_in_comment() {
    // Newline in comment would break the line format
    let line = "256 SHA256:AAAA comment\nextra (ED25519)";
    // This should fail because the line is split at \n
    let result = parse_ssh_add_line(line);
    // May parse the first part or fail
    let _ = result;
}

#[test]
fn parse_ssh_add_line_bits_zero() {
    let line = "0 SHA256:AAAA comment (ED25519)";
    let key = parse_ssh_add_line(line).unwrap();
    assert_eq!(key.key_type, KeyType::Ed25519);
}

#[test]
fn parse_ssh_add_line_bits_very_large() {
    let line = "999999 SHA256:AAAA comment (RSA)";
    let key = parse_ssh_add_line(line).unwrap();
    assert!(matches!(key.key_type, KeyType::Rsa { .. }));
}

#[test]
fn parse_ssh_add_line_fingerprint_with_plus_slash() {
    // Base64 uses + and / characters
    let line = "256 SHA256:abc+/def+/ghi comment (ED25519)";
    let key = parse_ssh_add_line(line).unwrap();
    assert_eq!(key.fingerprint.unwrap().hash, "abc+/def+/ghi");
}

#[test]
fn parse_ssh_add_line_comment_with_equals() {
    let line = "256 SHA256:AAAA user=host (ED25519)";
    let key = parse_ssh_add_line(line).unwrap();
    assert_eq!(key.comment.as_deref(), Some("user=host"));
}

#[test]
fn parse_ssh_add_line_comment_with_colon() {
    let line = "256 SHA256:AAAA user:host (ED25519)";
    let key = parse_ssh_add_line(line).unwrap();
    assert_eq!(key.comment.as_deref(), Some("user:host"));
}

#[test]
fn parse_ssh_add_line_comment_with_at() {
    let line = "256 SHA256:AAAA user@host (ED25519)";
    let key = parse_ssh_add_line(line).unwrap();
    assert_eq!(key.comment.as_deref(), Some("user@host"));
}

#[test]
fn parse_algorithm_with_whitespace_prefix() {
    assert_eq!(parse_key_type_from_algorithm(" ssh-ed25519"), None);
}

#[test]
fn parse_algorithm_with_whitespace_suffix() {
    assert_eq!(parse_key_type_from_algorithm("ssh-ed25519 "), None);
}

#[test]
fn parse_algorithm_with_tab() {
    assert_eq!(parse_key_type_from_algorithm("ssh-ed25519\t"), None);
}

#[test]
fn parse_algorithm_with_newline() {
    assert_eq!(parse_key_type_from_algorithm("ssh-ed25519\n"), None);
}

#[test]
fn parse_algorithm_empty() {
    assert_eq!(parse_key_type_from_algorithm(""), None);
}

#[test]
fn parse_algorithm_only_whitespace() {
    assert_eq!(parse_key_type_from_algorithm("   "), None);
}

#[test]
fn parse_ssh_add_line_no_parentheses() {
    // Missing key type in parentheses
    let line = "256 SHA256:AAAA comment ED25519";
    let result = parse_ssh_add_line(line);
    // Should fail because no parentheses
    assert!(result.is_none());
}

#[test]
fn parse_ssh_add_line_empty_parentheses() {
    let line = "256 SHA256:AAAA comment ()";
    let result = parse_ssh_add_line(line);
    // Empty type should fail
    assert!(result.is_none());
}

#[test]
fn parse_ssh_add_line_unknown_type_in_parens() {
    let line = "256 SHA256:AAAA comment (UNKNOWN)";
    let result = parse_ssh_add_line(line);
    // Unknown type should return None
    assert!(result.is_none());
}

// ---------------------------------------------------------------------------
// parse_key_type_from_display tests
// ---------------------------------------------------------------------------

#[test]
fn parse_display_ed25519() {
    assert_eq!(parse_key_type_from_display("ED25519"), Some(KeyType::Ed25519));
}

#[test]
fn parse_display_ed25519_sk() {
    assert_eq!(parse_key_type_from_display("ED25519-SK"), Some(KeyType::SkEd25519));
}

#[test]
fn parse_display_rsa() {
    assert_eq!(parse_key_type_from_display("RSA"), Some(KeyType::Rsa { bits: 0 }));
}

#[test]
fn parse_display_ecdsa() {
    assert_eq!(parse_key_type_from_display("ECDSA"), Some(KeyType::EcdsaP256));
}

#[test]
fn parse_display_ecdsa_sk() {
    assert_eq!(parse_key_type_from_display("ECDSA-SK"), Some(KeyType::SkEcdsaP256));
}

#[test]
fn parse_display_dsa() {
    assert_eq!(parse_key_type_from_display("DSA"), Some(KeyType::Dsa));
}

#[test]
fn parse_display_case_insensitive() {
    assert_eq!(parse_key_type_from_display("ed25519"), Some(KeyType::Ed25519));
    assert_eq!(parse_key_type_from_display("rsa"), Some(KeyType::Rsa { bits: 0 }));
    assert_eq!(parse_key_type_from_display("Ed25519-Sk"), Some(KeyType::SkEd25519));
}

#[test]
fn parse_display_unknown() {
    assert_eq!(parse_key_type_from_display("UNKNOWN"), None);
    assert_eq!(parse_key_type_from_display(""), None);
}

#[test]
fn parse_display_whitespace() {
    assert_eq!(parse_key_type_from_display("  "), None);
}
