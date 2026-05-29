use super::*;

#[test]
fn parse_keyscan_line_should_return_key_for_valid_input() {
    let line = "example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";
    let key = parse_keyscan_line("example.com", line).unwrap();
    assert_eq!(key.host, "example.com");
    assert_eq!(key.raw_host, "example.com");
    assert_eq!(key.key_type, "ssh-ed25519");
    assert_eq!(key.public_key, "AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl");
}

#[test]
fn parse_keyscan_line_should_preserve_original_host_for_hashed_input() {
    let line = "|1|JfKTdBh7rNbXkVAQCRp4OQoPfmI=|USECr3SWf1JUPsms5AqfD5QfxkM= ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";
    let key = parse_keyscan_line("example.com", line).unwrap();
    assert_eq!(key.host, "example.com");
    assert_eq!(key.raw_host, "|1|JfKTdBh7rNbXkVAQCRp4OQoPfmI=|USECr3SWf1JUPsms5AqfD5QfxkM=");
}

#[test]
fn parse_keyscan_line_should_error_for_malformed_input() {
    assert!(parse_keyscan_line("host", "only-one-field").is_err());
    assert!(parse_keyscan_line("host", "two fields").is_err());
}
