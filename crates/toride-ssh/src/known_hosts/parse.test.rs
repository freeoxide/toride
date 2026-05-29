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
