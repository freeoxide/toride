use super::*;

#[test]
fn extract_host_from_cm_pattern() {
    let path = PathBuf::from("/home/user/.ssh/cm-root@server.example.com:22");
    assert_eq!(
        extract_host_from_socket_path(&path),
        "root@server.example.com"
    );
}

#[test]
fn extract_host_from_ctrl_pattern() {
    let path = PathBuf::from("/home/user/.ssh/ctrl-abc123def");
    assert_eq!(extract_host_from_socket_path(&path), "abc123def");
}

#[test]
fn extract_host_from_ssh_tmp_pattern() {
    let path = PathBuf::from("/tmp/ssh-deploy@web01:22-mUXnBz");
    assert_eq!(extract_host_from_socket_path(&path), "deploy@web01");
}

#[test]
fn extract_host_no_prefix() {
    let path = PathBuf::from("/home/user/.ssh/some-host:22");
    assert_eq!(extract_host_from_socket_path(&path), "some-host");
}

// ---------------------------------------------------------------------------
// Edge-case tests
// ---------------------------------------------------------------------------

#[test]
fn extract_host_mux_prefix() {
    let path = PathBuf::from("/home/user/.ssh/mux-user@bastion:22");
    assert_eq!(extract_host_from_socket_path(&path), "user@bastion");
}

#[test]
fn extract_host_no_at_no_port() {
    let path = PathBuf::from("/home/user/.ssh/cm-hostname");
    assert_eq!(extract_host_from_socket_path(&path), "hostname");
}

#[test]
fn extract_host_at_no_port() {
    let path = PathBuf::from("/home/user/.ssh/cm-user@host");
    assert_eq!(extract_host_from_socket_path(&path), "user@host");
}

#[test]
fn extract_host_ssh_tmp_pattern_no_port() {
    let path = PathBuf::from("/tmp/ssh-deploy@web01-mUXnBz");
    assert_eq!(extract_host_from_socket_path(&path), "deploy@web01");
}

#[test]
fn extract_host_only_filename() {
    let path = PathBuf::from("cm-root@server:22");
    assert_eq!(extract_host_from_socket_path(&path), "root@server");
}

// ---------------------------------------------------------------------------
// Weird edge-case tests
// ---------------------------------------------------------------------------

#[test]
fn extract_host_with_very_long_hostname() {
    let long_host = "a".repeat(256);
    let path = PathBuf::from(format!("cm-user@{long_host}:22"));
    let result = extract_host_from_socket_path(&path);
    // Should contain the long hostname (may include user@ prefix)
    assert!(result.contains(&long_host));
}

#[test]
fn extract_host_with_multiple_at_signs() {
    // user@host@extra - first @ is the separator
    let path = PathBuf::from("cm-user@host@extra:22");
    let host = extract_host_from_socket_path(&path);
    // Should take after first @ up to :port
    assert!(host.contains("host"));
}

#[test]
fn extract_host_with_no_colon_after_at() {
    let path = PathBuf::from("cm-user@host");
    assert_eq!(extract_host_from_socket_path(&path), "user@host");
}

#[test]
fn extract_host_with_empty_filename() {
    let path = PathBuf::from("");
    let host = extract_host_from_socket_path(&path);
    assert_eq!(host, "unknown");
}

#[test]
fn extract_host_with_dot_prefix() {
    let path = PathBuf::from(".cm-host:22");
    let host = extract_host_from_socket_path(&path);
    // Should strip known prefixes, but .cm- is not a known prefix
    assert_eq!(host, ".cm-host");
}

#[test]
fn extract_host_ssh_pattern_with_hash() {
    let path = PathBuf::from("/tmp/ssh-abc123def456-48291");
    let host = extract_host_from_socket_path(&path);
    assert_eq!(host, "abc123def456-48291");
}

#[test]
fn extract_host_with_unicode_in_hostname() {
    let path = PathBuf::from("cm-user@höst:22");
    let host = extract_host_from_socket_path(&path);
    // Unicode hostname should be handled
    assert!(host.contains("höst") || host.contains("host"));
}
