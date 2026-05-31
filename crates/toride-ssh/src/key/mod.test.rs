use super::*;

#[test]
fn validate_key_name_empty() {
    assert!(validate_key_name("").is_err());
}

#[test]
fn validate_key_name_slash() {
    assert!(validate_key_name("../etc/passwd").is_err());
}

#[test]
fn validate_key_name_backslash() {
    assert!(validate_key_name("..\\etc\\passwd").is_err());
}

#[test]
fn validate_key_name_dot_dot() {
    assert!(validate_key_name("../../etc/passwd").is_err());
}

#[test]
fn validate_key_name_dot_dot_in_middle() {
    assert!(validate_key_name("foo/../bar").is_err());
}

#[test]
fn validate_key_name_valid() {
    assert!(validate_key_name("id_ed25519").is_ok());
    assert!(validate_key_name("my-key").is_ok());
    assert!(validate_key_name("key_with_underscores").is_ok());
}

#[test]
fn validate_key_name_dot_file() {
    // Dot files like ".ssh" should be valid (no path traversal)
    assert!(validate_key_name(".hidden").is_ok());
}

#[test]
fn validate_key_name_unicode() {
    // Unicode names should be valid as long as no path traversal
    assert!(validate_key_name("clé").is_ok());
}

#[test]
fn validate_key_name_just_dot_dot() {
    assert!(validate_key_name("..").is_err());
}

// ---------------------------------------------------------------------------
// Production-grade weird edge cases
// ---------------------------------------------------------------------------

#[test]
fn validate_key_name_with_spaces() {
    // Spaces in key name are unusual but not a security issue
    assert!(validate_key_name("my key").is_ok());
}

#[test]
fn validate_key_name_with_tabs() {
    assert!(validate_key_name("my\tkey").is_ok());
}

#[test]
fn validate_key_name_with_null_byte() {
    // Null bytes are now rejected to prevent path truncation attacks
    assert!(validate_key_name("my\0key").is_err());
}

#[test]
fn validate_key_name_with_control_chars() {
    assert!(validate_key_name("my\x01key").is_ok()); // Not explicitly blocked
}

#[test]
fn validate_key_name_very_long() {
    // Names up to 255 bytes are OK (filesystem limit).
    let name_255 = "a".repeat(255);
    assert!(validate_key_name(&name_255).is_ok());

    // Names over 255 bytes are rejected.
    let name_256 = "a".repeat(256);
    assert!(validate_key_name(&name_256).is_err());
}

#[test]
fn validate_key_name_exactly_255_bytes_accepted() {
    // The maximum valid key name length: exactly 255 bytes.
    let name = "k".repeat(255);
    assert_eq!(name.len(), 255);
    let result = validate_key_name(&name);
    assert!(result.is_ok(), "255-byte name should be accepted: {result:?}");
}

#[test]
fn validate_key_name_exactly_256_bytes_rejected() {
    // One byte over the limit: must be rejected.
    let name = "k".repeat(256);
    assert_eq!(name.len(), 256);
    let result = validate_key_name(&name);
    assert!(result.is_err(), "256-byte name should be rejected");
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("255"),
        "error should mention the 255-byte limit: {err_msg}",
    );
}

#[test]
fn validate_key_name_with_equals() {
    assert!(validate_key_name("my=key").is_ok());
}

#[test]
fn validate_key_name_with_colon() {
    assert!(validate_key_name("my:key").is_ok());
}

#[test]
fn validate_key_name_with_semicolon() {
    assert!(validate_key_name("my;key").is_ok());
}

#[test]
fn validate_key_name_with_pipe() {
    assert!(validate_key_name("my|key").is_ok());
}

#[test]
fn validate_key_name_with_ampersand() {
    assert!(validate_key_name("my&key").is_ok());
}

#[test]
fn validate_key_name_with_dollar() {
    assert!(validate_key_name("my$key").is_ok());
}

#[test]
fn validate_key_name_with_backtick() {
    assert!(validate_key_name("my`key").is_ok());
}

#[test]
fn validate_key_name_with_single_quote() {
    assert!(validate_key_name("my'key").is_ok());
}

#[test]
fn validate_key_name_with_double_quote() {
    assert!(validate_key_name("my\"key").is_ok());
}

#[test]
fn validate_key_name_with_angle_brackets() {
    assert!(validate_key_name("my<key>").is_ok());
}

#[test]
fn validate_key_name_with_square_brackets() {
    assert!(validate_key_name("my[key]").is_ok());
}

#[test]
fn validate_key_name_with_curly_braces() {
    assert!(validate_key_name("my{key}").is_ok());
}

#[test]
fn validate_key_name_with_hash() {
    assert!(validate_key_name("my#key").is_ok());
}

#[test]
fn validate_key_name_with_percent() {
    assert!(validate_key_name("my%key").is_ok());
}

#[test]
fn validate_key_name_with_at() {
    assert!(validate_key_name("my@key").is_ok());
}

#[test]
fn validate_key_name_with_exclamation() {
    assert!(validate_key_name("my!key").is_ok());
}

#[test]
fn validate_key_name_with_tilde() {
    // Tilde at start could be expanded by shell
    assert!(validate_key_name("~key").is_ok());
}

#[test]
fn validate_key_name_with_glob_chars() {
    assert!(validate_key_name("my*key").is_ok());
    assert!(validate_key_name("my?key").is_ok());
}

#[test]
fn validate_key_name_with_path_traversal_variants() {
    // Various path traversal attempts
    assert!(validate_key_name("../key").is_err());
    assert!(validate_key_name("key/..").is_err());
    assert!(validate_key_name("key/../key").is_err());
    assert!(validate_key_name("key/..").is_err());
}

#[test]
fn validate_key_name_with_backslash_traversal() {
    assert!(validate_key_name("..\\key").is_err());
    assert!(validate_key_name("key\\..").is_err());
}

// ---------------------------------------------------------------------------
// Workflow-discovered edge cases
// ---------------------------------------------------------------------------

#[test]
fn validate_key_name_null_byte_rejected() {
    // Null bytes can cause path truncation via C-level APIs
    assert!(validate_key_name("evil\0safe").is_err());
}

#[test]
fn validate_key_name_null_byte_at_start() {
    assert!(validate_key_name("\0key").is_err());
}

#[test]
fn validate_key_name_null_byte_at_end() {
    assert!(validate_key_name("key\0").is_err());
}

#[test]
fn validate_key_name_multiple_null_bytes() {
    assert!(validate_key_name("key\0\0\0").is_err());
}
