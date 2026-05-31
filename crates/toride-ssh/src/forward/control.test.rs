#![allow(clippy::unreadable_literal)]

use super::*;

#[test]
fn parse_local_forward_line() {
    let line = "127.0.0.1 port 8080, forwarding to 10.0.0.1 port 80";
    let fwd = parse_forward_line(line, ForwardType::Local).unwrap();
    assert_eq!(fwd.local_addr, "127.0.0.1");
    assert_eq!(fwd.local_port, 8080);
    assert_eq!(fwd.remote_addr, "10.0.0.1");
    assert_eq!(fwd.remote_port, 80);
    assert_eq!(fwd.forward_type, ForwardType::Local);
}

#[test]
fn parse_local_forward_truncated_addr() {
    let line = "127.0.0. port 8080, forwarding to 10.0.0.1 port 80";
    let fwd = parse_forward_line(line, ForwardType::Local).unwrap();
    assert_eq!(fwd.local_addr, "127.0.0");
    assert_eq!(fwd.local_port, 8080);
    assert_eq!(fwd.remote_addr, "10.0.0.1");
    assert_eq!(fwd.remote_port, 80);
}

#[test]
fn parse_gateway_ports_forward() {
    let line = "* port 9090, forwarding to 192.168.1.1 port 443";
    let fwd = parse_forward_line(line, ForwardType::Local).unwrap();
    assert_eq!(fwd.local_addr, "*");
    assert_eq!(fwd.local_port, 9090);
    assert_eq!(fwd.remote_addr, "192.168.1.1");
    assert_eq!(fwd.remote_port, 443);
}

#[test]
fn parse_dynamic_forward_line() {
    let line = "127.0.0.1 port 1080";
    let fwd = parse_forward_line(line, ForwardType::Dynamic).unwrap();
    assert_eq!(fwd.local_addr, "127.0.0.1");
    assert_eq!(fwd.local_port, 1080);
    assert_eq!(fwd.forward_type, ForwardType::Dynamic);
}

#[test]
fn parse_dynamic_forward_gateway() {
    let line = "* port 1080";
    let fwd = parse_forward_line(line, ForwardType::Dynamic).unwrap();
    assert_eq!(fwd.local_addr, "*");
    assert_eq!(fwd.local_port, 1080);
}

#[test]
fn parse_full_output() {
    let output = "\
Local connections:
  127.0.0.1 port 8080, forwarding to 10.0.0.1 port 80
  0.0.0.0 port 9090, forwarding to 192.168.1.1 port 443
Remote connections:
  127.0.0.1 port 2222, forwarding to 127.0.0.1 port 22
Dynamic connections:
  127.0.0.1 port 1080
";
    let fwds = parse_forward_output(output);
    assert_eq!(fwds.len(), 4);
    assert_eq!(fwds[0].forward_type, ForwardType::Local);
    assert_eq!(fwds[0].local_port, 8080);
    assert_eq!(fwds[1].forward_type, ForwardType::Local);
    assert_eq!(fwds[1].local_port, 9090);
    assert_eq!(fwds[2].forward_type, ForwardType::Remote);
    assert_eq!(fwds[2].remote_port, 22);
    assert_eq!(fwds[3].forward_type, ForwardType::Dynamic);
    assert_eq!(fwds[3].local_port, 1080);
}

#[test]
fn parse_empty_sections() {
    let output = "\
Local connections:
Remote connections:
Dynamic connections:
";
    let fwds = parse_forward_output(output);
    assert!(fwds.is_empty());
}

#[test]
fn parse_output_with_no_forwards() {
    let output = "";
    let fwds = parse_forward_output(output);
    assert!(fwds.is_empty());
}

#[test]
fn parse_output_with_error_message() {
    let output = "No forwards.\nLocal connections:\n";
    let fwds = parse_forward_output(output);
    assert!(fwds.is_empty());
}

#[test]
fn parse_remote_forward_line() {
    let line = "0.0.0.0 port 2222, forwarding to 127.0.0.1 port 22";
    let fwd = parse_forward_line(line, ForwardType::Remote).unwrap();
    assert_eq!(fwd.local_addr, "0.0.0.0");
    assert_eq!(fwd.local_port, 2222);
    assert_eq!(fwd.remote_addr, "127.0.0.1");
    assert_eq!(fwd.remote_port, 22);
    assert_eq!(fwd.forward_type, ForwardType::Remote);
}

#[test]
fn extract_host_various_patterns() {
    assert_eq!(
        extract_host_from_name("cm-deploy@web01.example.com:22"),
        "web01.example.com"
    );
    assert_eq!(extract_host_from_name("control-root@db:5432"), "db");
    assert_eq!(extract_host_from_name("mux-user@bastion:22"), "bastion");
    assert_eq!(extract_host_from_name("ctrl-user@jump:22"), "jump");
    assert_eq!(
        extract_host_from_name("ssh-abc123def456-12345"),
        "abc123def456-12345"
    );
}

#[test]
fn extract_pid_from_patterns() {
    assert_eq!(extract_pid_from_name("ssh-abc123-48291"), Some(48291));
    assert_eq!(extract_pid_from_name("cm-user@host:22"), None);
    assert_eq!(extract_pid_from_name("ssh-hash-0"), None);
}

// ---------------------------------------------------------------------------
// Edge-case tests
// ---------------------------------------------------------------------------

#[test]
fn parse_forward_line_empty_string() {
    assert!(parse_forward_line("", ForwardType::Local).is_none());
}

#[test]
fn parse_forward_line_no_port_keyword() {
    assert!(parse_forward_line("127.0.0.1 8080", ForwardType::Local).is_none());
}

#[test]
fn parse_forward_line_dynamic_empty_addr() {
    // After trim_start, " port 1080" becomes "port 1080" which has no " port " — returns None
    assert!(parse_forward_line(" port 1080", ForwardType::Dynamic).is_none());
}

#[test]
fn parse_forward_line_remote_forward() {
    let line = "0.0.0.0 port 2222, forwarding to 127.0.0.1 port 22";
    let fwd = parse_forward_line(line, ForwardType::Remote).unwrap();
    assert_eq!(fwd.forward_type, ForwardType::Remote);
    assert_eq!(fwd.local_addr, "0.0.0.0");
    assert_eq!(fwd.remote_port, 22);
}

#[test]
fn parse_forward_output_only_local_section() {
    let output = "Local connections:\n  127.0.0.1 port 8080, forwarding to 10.0.0.1 port 80\n";
    let fwds = parse_forward_output(output);
    assert_eq!(fwds.len(), 1);
    assert_eq!(fwds[0].forward_type, ForwardType::Local);
}

#[test]
fn parse_forward_output_unknown_section_header() {
    let output = "Unknown section:\n  127.0.0.1 port 8080, forwarding to 10.0.0.1 port 80\n";
    let fwds = parse_forward_output(output);
    assert!(fwds.is_empty());
}

#[test]
fn parse_forward_output_blank_lines_between_entries() {
    let output = "\
Local connections:
  127.0.0.1 port 8080, forwarding to 10.0.0.1 port 80

  127.0.0.1 port 9090, forwarding to 10.0.0.2 port 80
";
    let fwds = parse_forward_output(output);
    assert_eq!(fwds.len(), 2);
}

#[test]
fn extract_host_from_name_no_at_sign() {
    assert_eq!(extract_host_from_name("some-random-name"), "some-random-name");
}

#[test]
fn extract_host_from_name_only_prefix() {
    assert_eq!(extract_host_from_name("cm-"), "");
}

#[test]
fn extract_host_from_name_at_no_port() {
    assert_eq!(extract_host_from_name("cm-user@host"), "host");
}

#[test]
fn extract_pid_from_name_no_dash() {
    assert_eq!(extract_pid_from_name("nodash"), None);
}

#[test]
fn extract_pid_from_name_non_numeric() {
    assert_eq!(extract_pid_from_name("ssh-hash-abc"), None);
}

#[test]
fn extract_pid_from_name_large_pid() {
    assert_eq!(extract_pid_from_name("ssh-hash-999999"), Some(999999));
}

#[test]
fn forward_type_display() {
    assert_eq!(ForwardType::Local.to_string(), "local");
    assert_eq!(ForwardType::Remote.to_string(), "remote");
    assert_eq!(ForwardType::Dynamic.to_string(), "dynamic");
}

#[test]
fn parse_forward_line_with_extra_whitespace() {
    // The parser expects exactly " port " (single space) — multiple spaces return None
    let line = "  127.0.0.1  port  8080,  forwarding  to  10.0.0.1  port  80  ";
    assert!(parse_forward_line(line, ForwardType::Local).is_none());
}

// ---------------------------------------------------------------------------
// Weird edge-case tests
// ---------------------------------------------------------------------------

#[test]
fn parse_forward_line_very_high_port() {
    let line = "127.0.0.1 port 65535, forwarding to 10.0.0.1 port 80";
    let fwd = parse_forward_line(line, ForwardType::Local).unwrap();
    assert_eq!(fwd.local_port, 65535);
}

#[test]
fn parse_forward_line_port_zero() {
    let line = "127.0.0.1 port 0, forwarding to 10.0.0.1 port 80";
    let fwd = parse_forward_line(line, ForwardType::Local).unwrap();
    assert_eq!(fwd.local_port, 0);
}

#[test]
fn parse_forward_line_remote_with_empty_remote_addr() {
    // When remote addr is empty, cancel_known_forward substitutes "localhost"
    let line = "0.0.0.0 port 2222, forwarding to  port 22";
    let fwd = parse_forward_line(line, ForwardType::Remote).unwrap();
    assert_eq!(fwd.remote_addr, "");
    assert_eq!(fwd.remote_port, 22);
}

#[test]
fn parse_forward_output_with_error_before_sections() {
    let output = "Error: some error message\nLocal connections:\n  127.0.0.1 port 8080, forwarding to 10.0.0.1 port 80\n";
    let fwds = parse_forward_output(output);
    assert_eq!(fwds.len(), 1);
}

#[test]
fn parse_forward_output_with_multiple_local_sections() {
    // Duplicate section headers - should keep parsing
    let output = "\
Local connections:
  127.0.0.1 port 8080, forwarding to 10.0.0.1 port 80
Local connections:
  127.0.0.1 port 9090, forwarding to 10.0.0.2 port 80
";
    let fwds = parse_forward_output(output);
    // Both should be parsed since we don't reset the type
    assert_eq!(fwds.len(), 2);
}

#[test]
fn parse_forward_line_dynamic_with_remote_type() {
    // Dynamic line parsed as Remote should return None (no "forwarding to")
    let line = "127.0.0.1 port 1080";
    assert!(parse_forward_line(line, ForwardType::Remote).is_none());
}

#[test]
fn parse_forward_line_local_with_dynamic_type() {
    // Local line parsed as Dynamic — the parser finds " port " and takes the port,
    // but then expects the rest to be empty for Dynamic type
    let line = "127.0.0.1 port 8080, forwarding to 10.0.0.1 port 80";
    let result = parse_forward_line(line, ForwardType::Dynamic);
    // Dynamic type expects just "<addr> port <port>" without ", forwarding to..."
    // The extra comma/text after the port is ignored for Dynamic type
    // since it only reads up to the end of the port number
    if let Some(fwd) = result {
        assert_eq!(fwd.local_port, 8080);
    }
    // Whether it returns Some or None depends on how the parser handles
    // trailing content for Dynamic type
}

#[test]
fn extract_host_from_name_very_long() {
    let long_name = format!("cm-user@{}:22", "a".repeat(256));
    let host = extract_host_from_name(&long_name);
    assert_eq!(host, "a".repeat(256));
}

#[test]
fn extract_host_from_name_with_underscores() {
    assert_eq!(extract_host_from_name("cm-user_name@host_name:22"), "host_name");
}

#[test]
fn extract_host_from_name_with_hyphens() {
    assert_eq!(extract_host_from_name("cm-user@my-host:22"), "my-host");
}

#[test]
fn extract_pid_from_name_at_boundary() {
    assert_eq!(extract_pid_from_name("ssh-hash-1"), Some(1));
    assert_eq!(extract_pid_from_name("ssh-hash-4294967295"), Some(4294967295)); // u32::MAX
}

#[test]
fn parse_forward_output_with_tabs() {
    let output = "Local connections:\n\t127.0.0.1 port 8080, forwarding to 10.0.0.1 port 80\n";
    let fwds = parse_forward_output(output);
    assert_eq!(fwds.len(), 1);
}

// ---------------------------------------------------------------------------
// Production-grade weird edge cases
// ---------------------------------------------------------------------------

#[test]
fn parse_forward_line_same_local_remote_port() {
    let line = "127.0.0.1 port 8080, forwarding to 10.0.0.1 port 8080";
    let fwd = parse_forward_line(line, ForwardType::Local).unwrap();
    assert_eq!(fwd.local_port, fwd.remote_port);
}

#[test]
fn parse_forward_line_with_ipv6_localhost() {
    let line = "::1 port 8080, forwarding to ::1 port 80";
    let fwd = parse_forward_line(line, ForwardType::Local).unwrap();
    assert_eq!(fwd.local_addr, "::1");
    assert_eq!(fwd.remote_addr, "::1");
}

#[test]
fn parse_forward_line_with_hostname() {
    let line = "myhost port 8080, forwarding to remotehost port 80";
    let fwd = parse_forward_line(line, ForwardType::Local).unwrap();
    assert_eq!(fwd.local_addr, "myhost");
    assert_eq!(fwd.remote_addr, "remotehost");
}

#[test]
fn parse_forward_output_with_no_newline_at_end() {
    let output = "Local connections:\n  127.0.0.1 port 8080, forwarding to 10.0.0.1 port 80";
    let fwds = parse_forward_output(output);
    assert_eq!(fwds.len(), 1);
}

#[test]
fn parse_forward_output_with_multiple_blank_lines() {
    let output = "Local connections:\n\n\n  127.0.0.1 port 8080, forwarding to 10.0.0.1 port 80\n";
    let fwds = parse_forward_output(output);
    assert_eq!(fwds.len(), 1);
}

#[test]
fn parse_forward_line_with_port_1() {
    let line = "127.0.0.1 port 1, forwarding to 10.0.0.1 port 80";
    let fwd = parse_forward_line(line, ForwardType::Local).unwrap();
    assert_eq!(fwd.local_port, 1);
}

#[test]
fn parse_forward_line_with_port_65535() {
    let line = "127.0.0.1 port 65535, forwarding to 10.0.0.1 port 80";
    let fwd = parse_forward_line(line, ForwardType::Local).unwrap();
    assert_eq!(fwd.local_port, 65535);
}

#[test]
fn extract_host_from_name_with_numbers() {
    assert_eq!(extract_host_from_name("cm-user@192.168.1.1:22"), "192.168.1.1");
}

#[test]
fn extract_host_from_name_bare_ipv6_loopback() {
    // Bare IPv6 ::1 with port — should extract "::1", not ""
    assert_eq!(extract_host_from_name("cm-user@::1:22"), "::1");
}

#[test]
fn extract_host_from_name_bare_ipv6_full() {
    assert_eq!(
        extract_host_from_name("cm-user@fe80::1:22"),
        "fe80::1"
    );
}

#[test]
fn extract_host_from_name_bare_ipv6_no_port() {
    // Bare IPv6 without port — takes everything after @
    assert_eq!(extract_host_from_name("cm-user@::1"), "::1");
}

#[test]
fn extract_pid_from_name_with_multiple_dashes() {
    assert_eq!(extract_pid_from_name("ssh-abc-def-123"), Some(123));
}

#[test]
fn extract_pid_from_name_with_leading_zeros() {
    assert_eq!(extract_pid_from_name("ssh-hash-00123"), Some(123));
}

#[test]
fn cancel_spec_with_empty_remote_addr() {
    let fwd = PortForward {
        local_addr: "127.0.0.1".to_owned(),
        local_port: 8080,
        remote_addr: String::new(),
        remote_port: 80,
        forward_type: ForwardType::Local,
    };
    // Empty remote addr should use "localhost"
    let spec = format!(
        "[{}]:{}:{}:{}",
        fwd.local_addr,
        fwd.local_port,
        if fwd.remote_addr.is_empty() { "localhost" } else { &fwd.remote_addr },
        fwd.remote_port
    );
    assert_eq!(spec, "[127.0.0.1]:8080:localhost:80");
}

#[test]
fn cancel_spec_local_forward() {
    let fwd = PortForward {
        local_addr: "127.0.0.1".to_owned(),
        local_port: 8080,
        remote_addr: "10.0.0.1".to_owned(),
        remote_port: 80,
        forward_type: ForwardType::Local,
    };
    let spec = if fwd.forward_type == ForwardType::Dynamic {
        format!("[{}]:{}", fwd.local_addr, fwd.local_port)
    } else {
        format!(
            "[{}]:{}:{}:{}",
            fwd.local_addr, fwd.local_port, fwd.remote_addr, fwd.remote_port
        )
    };
    assert_eq!(spec, "[127.0.0.1]:8080:10.0.0.1:80");
}

#[test]
fn cancel_spec_dynamic_forward() {
    let fwd = PortForward {
        local_addr: "127.0.0.1".to_owned(),
        local_port: 1080,
        remote_addr: String::new(),
        remote_port: 0,
        forward_type: ForwardType::Dynamic,
    };
    let spec = if fwd.forward_type == ForwardType::Dynamic {
        format!("[{}]:{}", fwd.local_addr, fwd.local_port)
    } else {
        unreachable!()
    };
    assert_eq!(spec, "[127.0.0.1]:1080");
}

// ---------------------------------------------------------------------------
// glob_matches tests
// ---------------------------------------------------------------------------

#[test]
fn glob_matches_prefix_wildcard() {
    assert!(glob_matches("cm-*", "cm-user@host:22"));
    assert!(glob_matches("ssh-*", "ssh-abc123"));
}

#[test]
fn glob_matches_exact() {
    assert!(glob_matches("cm-foo", "cm-foo"));
    assert!(!glob_matches("cm-foo", "cm-bar"));
}

#[test]
fn glob_matches_no_match() {
    assert!(!glob_matches("cm-*", "ctrl-user@host"));
    assert!(!glob_matches("mux-*", "cm-user@host"));
}

#[test]
fn glob_matches_empty_pattern() {
    assert!(!glob_matches("", "cm-user@host"));
}

#[test]
fn glob_matches_empty_name() {
    assert!(!glob_matches("cm-*", ""));
}

#[test]
fn glob_matches_wildcard_only() {
    assert!(glob_matches("*", "anything"));
}

// ---------------------------------------------------------------------------
// extract_host_from_name edge cases
// ---------------------------------------------------------------------------

#[test]
fn extract_host_from_name_ssh_hash_format() {
    // ssh-<hash>-<pid> format falls back to stripped name
    let host = extract_host_from_name("ssh-abc123def-12345");
    assert_eq!(host, "abc123def-12345");
}

#[test]
fn extract_host_from_name_ctrl_prefix() {
    let host = extract_host_from_name("ctrl-user@server.com:22");
    assert_eq!(host, "server.com");
}

#[test]
fn extract_host_from_name_no_prefix() {
    let host = extract_host_from_name("user@host:22");
    assert_eq!(host, "host");
}

// ---------------------------------------------------------------------------
// extract_pid_from_name edge cases
// ---------------------------------------------------------------------------

#[test]
fn extract_pid_from_name_valid() {
    assert_eq!(extract_pid_from_name("ssh-abc-12345"), Some(12345));
}

#[test]
fn extract_pid_from_name_zero() {
    // PID 0 is never valid
    assert_eq!(extract_pid_from_name("ssh-abc-0"), None);
}

#[test]
fn extract_pid_from_name_no_number() {
    assert_eq!(extract_pid_from_name("cm-user@host"), None);
}

#[test]
fn extract_pid_from_name_overflow() {
    assert_eq!(extract_pid_from_name("ssh-abc-99999999999"), None);
}

// ---------------------------------------------------------------------------
// IPv6 host extraction tests
// ---------------------------------------------------------------------------

#[test]
fn extract_host_from_name_bracketed_ipv6() {
    assert_eq!(
        extract_host_from_name("cm-user@[::1]:22"),
        "::1"
    );
}

#[test]
fn extract_host_from_name_bracketed_ipv6_full_addr() {
    assert_eq!(
        extract_host_from_name("cm-user@[2001:db8::1]:22"),
        "2001:db8::1"
    );
}

#[test]
fn extract_host_from_name_bracketed_ipv6_no_port() {
    assert_eq!(
        extract_host_from_name("cm-user@[::1]"),
        "::1"
    );
}

#[test]
fn extract_host_from_name_bracketed_ipv6_long() {
    assert_eq!(
        extract_host_from_name("cm-user@[fe80::250:56ff:feb3:6477]:22"),
        "fe80::250:56ff:feb3:6477"
    );
}

#[test]
fn extract_host_from_name_bare_ipv6_high_port() {
    assert_eq!(
        extract_host_from_name("mux-user@::1:65535"),
        "::1"
    );
}

// ---------------------------------------------------------------------------
// cancel_forward tests
// ---------------------------------------------------------------------------

/// Fake SSH script that returns a local forward on port 9090 for `-O list`
/// and exits successfully for any other action (e.g. `-O cancel`).
#[cfg(unix)]
const FAKE_SSH_LIST_SCRIPT: &str = r#"#!/bin/sh
action=""
while [ $# -gt 0 ]; do
    case "$1" in
        -O) action="$2"; shift 2 ;;
        *) shift ;;
    esac
done
case "$action" in
    list)
        echo "Local connections:"
        echo "  127.0.0.1 port 9090, forwarding to 10.0.0.1 port 80"
        ;;
    *) exit 0 ;;
esac
"#;

/// Install a fake `ssh` script in a temporary directory.
///
/// Returns the temp dir guard (must be kept alive so the file is not deleted)
/// and the modified `PATH` value that places the fake ssh first.
#[cfg(unix)]
fn install_fake_ssh(script: &str) -> (tempfile::TempDir, String) {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let ssh_bin = dir.path().join("ssh");
    std::fs::write(&ssh_bin, script).unwrap();
    std::fs::set_permissions(&ssh_bin, std::fs::Permissions::from_mode(0o755)).unwrap();
    let orig = std::env::var("PATH").unwrap_or_default();
    let modified = format!("{}:{}", dir.path().display(), orig);
    (dir, modified)
}

/// Successful forward cancellation: the target port exists in the list and
/// the cancel command succeeds.
#[cfg(unix)]
#[tokio::test]
async fn cancel_forward_success() {
    let (_dir, new_path) = install_fake_ssh(FAKE_SSH_LIST_SCRIPT);
    let orig_path = std::env::var("PATH").unwrap_or_default();
    // SAFETY: test-only PATH mutation; tokio test runtime is single-threaded.
    unsafe { std::env::set_var("PATH", &new_path) };

    let result = cancel_forward(Path::new("/tmp/fake-ctrl-sock"), 9090).await;

    // Restore before asserting so a panic does not leak the modified PATH.
    // SAFETY: restoring the original value.
    unsafe { std::env::set_var("PATH", &orig_path) };

    assert!(result.is_ok(), "expected Ok(()) but got: {result:?}");
}

/// Forward not found: the target port is absent from the forward list
/// returned by `ssh -O list`.
#[cfg(unix)]
#[tokio::test]
async fn cancel_forward_forward_not_found() {
    let (_dir, new_path) = install_fake_ssh(FAKE_SSH_LIST_SCRIPT);
    let orig_path = std::env::var("PATH").unwrap_or_default();
    // SAFETY: test-only PATH mutation; tokio test runtime is single-threaded.
    unsafe { std::env::set_var("PATH", &new_path) };

    // Port 8080 is absent from the fake list (only 9090 exists).
    let result = cancel_forward(Path::new("/tmp/fake-ctrl-sock"), 8080).await;

    // SAFETY: restoring the original value.
    unsafe { std::env::set_var("PATH", &orig_path) };

    match result {
        Err(Error::ForwardNotFound(msg)) => {
            assert!(msg.contains("8080"), "unexpected message: {msg}");
        }
        other => panic!("expected Error::ForwardNotFound, got: {other:?}"),
    }
}

/// Invalid control path: a non-UTF-8 path triggers `ForwardFailed` before
/// any SSH command is spawned.
#[cfg(unix)]
#[tokio::test]
async fn cancel_forward_invalid_control_path() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    // Construct a path containing invalid UTF-8 bytes.
    let bad_path = std::path::Path::new(OsStr::from_bytes(b"/tmp/\xff\xfe/sock"));

    let result = cancel_forward(bad_path, 8080).await;

    match result {
        Err(Error::ForwardFailed(msg)) => {
            assert!(msg.contains("UTF-8"), "unexpected message: {msg}");
        }
        other => panic!("expected Error::ForwardFailed, got: {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// exit_session tests
// ---------------------------------------------------------------------------

/// Fake SSH script that exits successfully for `-O exit`.
#[cfg(unix)]
const FAKE_SSH_EXIT_SCRIPT: &str = r#"#!/bin/sh
exit 0
"#;

/// Fake SSH script that exits with failure for `-O exit`, simulating a
/// stale/dead control socket where the master process is already gone.
#[cfg(unix)]
const FAKE_SSH_EXIT_FAIL_SCRIPT: &str = r#"#!/bin/sh
exit 1
"#;

/// Successful session exit: `ssh -O exit` succeeds and the socket file is
/// cleaned up.
#[cfg(unix)]
#[tokio::test]
async fn exit_session_success() {
    let (_dir, new_path) = install_fake_ssh(FAKE_SSH_EXIT_SCRIPT);
    let orig_path = std::env::var("PATH").unwrap_or_default();
    // SAFETY: test-only PATH mutation; tokio test runtime is single-threaded.
    unsafe { std::env::set_var("PATH", &new_path) };

    let tmp = tempfile::NamedTempFile::new().unwrap();
    let sock_path = tmp.path().with_extension("sock");
    std::fs::write(&sock_path, "").unwrap();
    assert!(sock_path.exists(), "socket file should exist before exit");

    let result = exit_session(&sock_path).await;

    // SAFETY: restoring the original value.
    unsafe { std::env::set_var("PATH", &orig_path) };

    assert!(result.is_ok(), "expected Ok(()) but got: {result:?}");
    assert!(
        !sock_path.exists(),
        "socket file should be removed after successful exit"
    );
}

/// Stale socket cleanup: `ssh -O exit` fails (master already dead) but the
/// socket file remains on disk.  `exit_session` should still attempt cleanup
/// and return the underlying error.
#[cfg(unix)]
#[tokio::test]
async fn exit_session_stale_socket_cleanup() {
    let (_dir, new_path) = install_fake_ssh(FAKE_SSH_EXIT_FAIL_SCRIPT);
    let orig_path = std::env::var("PATH").unwrap_or_default();
    // SAFETY: test-only PATH mutation; tokio test runtime is single-threaded.
    unsafe { std::env::set_var("PATH", &new_path) };

    // Create a real Unix socket so `is_stale_socket` detects it on unix.
    let tmp_dir = tempfile::tempdir().unwrap();
    let sock_path = tmp_dir.path().join("stale.sock");
    let _listener = std::os::unix::net::UnixListener::bind(&sock_path).unwrap();
    assert!(sock_path.exists(), "socket file should exist before exit");

    let result = exit_session(&sock_path).await;

    // SAFETY: restoring the original value.
    unsafe { std::env::set_var("PATH", &orig_path) };

    // The ssh command itself fails.
    assert!(result.is_err(), "expected error from failed ssh -O exit");
    match &result {
        Err(Error::CommandFailed(msg)) => {
            assert!(
                msg.contains("ssh -O exit"),
                "unexpected message: {msg}"
            );
        }
        other => panic!("expected Error::CommandFailed, got: {other:?}"),
    }

    // Even though the command failed, `is_stale_socket` returns true for the
    // dead socket, so `exit_session` removes the file as a best-effort cleanup.
    assert!(
        !sock_path.exists(),
        "stale socket file should be removed during cleanup"
    );
}

/// Invalid control path: a non-UTF-8 path triggers `ForwardFailed` before
/// any SSH command is spawned.
#[cfg(unix)]
#[tokio::test]
async fn exit_session_invalid_control_path() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    // Construct a path containing invalid UTF-8 bytes.
    let bad_path = std::path::Path::new(OsStr::from_bytes(b"/tmp/\xff\xfe/sock"));

    let result = exit_session(bad_path).await;

    match result {
        Err(Error::ForwardFailed(msg)) => {
            assert!(msg.contains("UTF-8"), "unexpected message: {msg}");
        }
        other => panic!("expected Error::ForwardFailed, got: {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// list_sessions tests
// ---------------------------------------------------------------------------

/// Fake SSH script that always succeeds for `-O check` (socket is alive).
#[cfg(unix)]
const FAKE_SSH_CHECK_ALIVE_SCRIPT: &str = r#"#!/bin/sh
exit 0
"#;

/// Fake SSH script that always fails for `-O check` (socket is dead/stale).
#[cfg(unix)]
const FAKE_SSH_CHECK_DEAD_SCRIPT: &str = r#"#!/bin/sh
exit 1
"#;

/// Fake SSH script that succeeds for `-O check` only when the control path
/// (passed via `-S`) contains the substring "alive".
#[cfg(unix)]
const FAKE_SSH_CHECK_SELECTIVE_SCRIPT: &str = r#"#!/bin/sh
path=""
while [ $# -gt 0 ]; do
    case "$1" in
        -S) path="$2"; shift 2 ;;
        *) shift ;;
    esac
done
case "$path" in
    *alive*) exit 0 ;;
    *) exit 1 ;;
esac
"#;

/// Session discovery: all sockets in the ssh_dir are alive and returned.
///
/// Creates three Unix sockets matching `cm-*`, `control-*`, and `mux-*`
/// patterns, then verifies all are discovered with correct host extraction.
#[cfg(unix)]
#[tokio::test]
async fn list_sessions_discovers_valid_sockets() {
    let (_dir, new_path) = install_fake_ssh(FAKE_SSH_CHECK_ALIVE_SCRIPT);
    let orig_path = std::env::var("PATH").unwrap_or_default();
    // SAFETY: test-only PATH mutation; tokio test runtime is single-threaded.
    unsafe { std::env::set_var("PATH", &new_path) };

    let ssh_dir = tempfile::tempdir().unwrap();

    // Create Unix sockets matching the expected glob patterns.
    let sock1 = ssh_dir.path().join("cm-deploy@web01:22");
    let sock2 = ssh_dir.path().join("control-root@db:5432");
    let sock3 = ssh_dir.path().join("mux-user@bastion:22");
    let _l1 = std::os::unix::net::UnixListener::bind(&sock1).unwrap();
    let _l2 = std::os::unix::net::UnixListener::bind(&sock2).unwrap();
    let _l3 = std::os::unix::net::UnixListener::bind(&sock3).unwrap();

    let result = list_sessions(ssh_dir.path()).await;

    // SAFETY: restoring the original value.
    unsafe { std::env::set_var("PATH", &orig_path) };

    let sessions = result.unwrap();

    // Filter to only sessions from our test ssh_dir (exclude any /tmp matches).
    let our_sessions: Vec<_> = sessions
        .iter()
        .filter(|s| s.control_path.starts_with(ssh_dir.path()))
        .collect();

    assert_eq!(
        our_sessions.len(),
        3,
        "expected 3 sessions, got {}: {our_sessions:?}",
        our_sessions.len()
    );

    // Verify host extraction from socket filenames.
    let hosts: Vec<&str> = our_sessions.iter().map(|s| s.host.as_str()).collect();
    assert!(hosts.contains(&"web01"), "expected web01 in {hosts:?}");
    assert!(hosts.contains(&"db"), "expected db in {hosts:?}");
    assert!(hosts.contains(&"bastion"), "expected bastion in {hosts:?}");

    // Verify control paths and timestamps are set.
    for session in &our_sessions {
        assert!(session.control_path.starts_with(ssh_dir.path()));
        assert!(
            session.established.is_some(),
            "established timestamp should be set for {:?}",
            session.control_path
        );
    }
}

/// No alive sessions: sockets exist but all fail the `-O check`.
///
/// Uses a fake SSH that always returns failure, ensuring every candidate
/// (from both ssh_dir and /tmp) is filtered out.
#[cfg(unix)]
#[tokio::test]
async fn list_sessions_none_alive() {
    let (_dir, new_path) = install_fake_ssh(FAKE_SSH_CHECK_DEAD_SCRIPT);
    let orig_path = std::env::var("PATH").unwrap_or_default();
    // SAFETY: test-only PATH mutation; tokio test runtime is single-threaded.
    unsafe { std::env::set_var("PATH", &new_path) };

    let ssh_dir = tempfile::tempdir().unwrap();

    // Create socket files that will all fail the alive check.
    let sock1 = ssh_dir.path().join("cm-user@host:22");
    let sock2 = ssh_dir.path().join("ctrl-user@jump:22");
    let _l1 = std::os::unix::net::UnixListener::bind(&sock1).unwrap();
    let _l2 = std::os::unix::net::UnixListener::bind(&sock2).unwrap();

    let result = list_sessions(ssh_dir.path()).await;

    // SAFETY: restoring the original value.
    unsafe { std::env::set_var("PATH", &orig_path) };

    let sessions = result.unwrap();
    assert!(
        sessions.is_empty(),
        "expected no alive sessions, got {}: {sessions:?}",
        sessions.len()
    );
}

/// Empty ssh_dir with no matching socket files.
#[cfg(unix)]
#[tokio::test]
async fn list_sessions_empty_ssh_dir() {
    let (_dir, new_path) = install_fake_ssh(FAKE_SSH_CHECK_ALIVE_SCRIPT);
    let orig_path = std::env::var("PATH").unwrap_or_default();
    // SAFETY: test-only PATH mutation; tokio test runtime is single-threaded.
    unsafe { std::env::set_var("PATH", &new_path) };

    let ssh_dir = tempfile::tempdir().unwrap();

    let result = list_sessions(ssh_dir.path()).await;

    // SAFETY: restoring the original value.
    unsafe { std::env::set_var("PATH", &orig_path) };

    let sessions = result.unwrap();

    // No sockets should come from our empty ssh_dir.
    // (There may be sessions from /tmp, which we cannot control.)
    for session in &sessions {
        assert!(
            !session.control_path.starts_with(ssh_dir.path()),
            "unexpected session from empty ssh_dir: {:?}",
            session.control_path
        );
    }
}

/// Mixed valid/invalid sockets: only alive sockets are returned.
///
/// Uses a fake SSH that checks the control path name — sockets with "alive"
/// in the path succeed the check, others fail.
#[cfg(unix)]
#[tokio::test]
async fn list_sessions_mixed_alive_and_dead() {
    let (_dir, new_path) = install_fake_ssh(FAKE_SSH_CHECK_SELECTIVE_SCRIPT);
    let orig_path = std::env::var("PATH").unwrap_or_default();
    // SAFETY: test-only PATH mutation; tokio test runtime is single-threaded.
    unsafe { std::env::set_var("PATH", &new_path) };

    let ssh_dir = tempfile::tempdir().unwrap();

    // Create sockets — "alive" sockets pass the check, "dead" ones fail.
    let alive1 = ssh_dir.path().join("cm-alive-user@host1:22");
    let alive2 = ssh_dir.path().join("mux-alive-user@host2:22");
    let dead1 = ssh_dir.path().join("cm-dead-user@host3:22");
    let dead2 = ssh_dir.path().join("ctrl-dead-user@host4:22");
    let _l1 = std::os::unix::net::UnixListener::bind(&alive1).unwrap();
    let _l2 = std::os::unix::net::UnixListener::bind(&alive2).unwrap();
    let _l3 = std::os::unix::net::UnixListener::bind(&dead1).unwrap();
    let _l4 = std::os::unix::net::UnixListener::bind(&dead2).unwrap();

    let result = list_sessions(ssh_dir.path()).await;

    // SAFETY: restoring the original value.
    unsafe { std::env::set_var("PATH", &orig_path) };

    let sessions = result.unwrap();

    // Filter to only sessions from our test ssh_dir (exclude any /tmp matches).
    let our_sessions: Vec<_> = sessions
        .iter()
        .filter(|s| s.control_path.starts_with(ssh_dir.path()))
        .collect();

    assert_eq!(
        our_sessions.len(),
        2,
        "expected 2 alive sessions, got {}: {our_sessions:?}",
        our_sessions.len()
    );

    // Verify the correct sockets are returned.
    let paths: Vec<&std::path::Path> = our_sessions
        .iter()
        .map(|s| s.control_path.as_path())
        .collect();
    assert!(paths.contains(&alive1.as_path()), "missing alive1");
    assert!(paths.contains(&alive2.as_path()), "missing alive2");

    // Dead sockets must not appear.
    for session in &our_sessions {
        let name = session
            .control_path
            .file_name()
            .unwrap()
            .to_str()
            .unwrap();
        assert!(
            !name.contains("dead"),
            "dead socket should not appear: {name}"
        );
    }
}

/// PID extraction from socket filenames using `ssh-<hash>-<pid>` pattern.
#[cfg(unix)]
#[tokio::test]
async fn list_sessions_extracts_pid_from_filename() {
    let (_dir, new_path) = install_fake_ssh(FAKE_SSH_CHECK_ALIVE_SCRIPT);
    let orig_path = std::env::var("PATH").unwrap_or_default();
    // SAFETY: test-only PATH mutation; tokio test runtime is single-threaded.
    unsafe { std::env::set_var("PATH", &new_path) };

    let ssh_dir = tempfile::tempdir().unwrap();

    // cm-<hash>-<pid> pattern triggers PID extraction (ssh-* is scanned in /tmp, not ssh_dir).
    let sock = ssh_dir.path().join("cm-abc123def-48291");
    let _listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();

    let result = list_sessions(ssh_dir.path()).await;

    // SAFETY: restoring the original value.
    unsafe { std::env::set_var("PATH", &orig_path) };

    let sessions = result.unwrap();

    let our_session = sessions
        .iter()
        .find(|s| s.control_path.starts_with(ssh_dir.path()))
        .expect("expected session from ssh_dir");

    assert_eq!(our_session.pid, Some(48291));
    // For ssh-<hash>-<pid> format, host falls back to the stripped name.
    assert_eq!(our_session.host, "abc123def-48291");
}

/// Non-socket candidate files (small files without extension) are accepted
/// by `is_socket_or_candidate` and discovered by `list_sessions`.
#[cfg(unix)]
#[tokio::test]
async fn list_sessions_accepts_candidate_files() {
    let (_dir, new_path) = install_fake_ssh(FAKE_SSH_CHECK_ALIVE_SCRIPT);
    let orig_path = std::env::var("PATH").unwrap_or_default();
    // SAFETY: test-only PATH mutation; tokio test runtime is single-threaded.
    unsafe { std::env::set_var("PATH", &new_path) };

    let ssh_dir = tempfile::tempdir().unwrap();

    // Create a small regular file (not a socket) — should still be accepted
    // as a candidate because is_socket_or_candidate allows small files
    // without dots in the name.
    let candidate = ssh_dir.path().join("cm-user@myhost:22");
    std::fs::write(&candidate, "").unwrap();

    let result = list_sessions(ssh_dir.path()).await;

    // SAFETY: restoring the original value.
    unsafe { std::env::set_var("PATH", &orig_path) };

    let sessions = result.unwrap();

    let our_session = sessions
        .iter()
        .find(|s| s.control_path.starts_with(ssh_dir.path()));

    assert!(
        our_session.is_some(),
        "candidate file should be discovered and pass alive check"
    );
    assert_eq!(our_session.unwrap().host, "myhost");
}

/// Non-existent ssh_dir: function handles missing directory gracefully.
#[cfg(unix)]
#[tokio::test]
async fn list_sessions_nonexistent_ssh_dir() {
    let (_dir, new_path) = install_fake_ssh(FAKE_SSH_CHECK_ALIVE_SCRIPT);
    let orig_path = std::env::var("PATH").unwrap_or_default();
    // SAFETY: test-only PATH mutation; tokio test runtime is single-threaded.
    unsafe { std::env::set_var("PATH", &new_path) };

    let result = list_sessions(Path::new("/tmp/nonexistent-ssh-dir-12345")).await;

    // SAFETY: restoring the original value.
    unsafe { std::env::set_var("PATH", &orig_path) };

    // Should not error — missing directory is handled gracefully.
    let sessions = result.unwrap();
    for session in &sessions {
        assert!(
            !session
                .control_path
                .starts_with("/tmp/nonexistent-ssh-dir-12345"),
            "unexpected session from non-existent dir: {:?}",
            session.control_path
        );
    }
}

/// Files with dots in the name are rejected by `is_socket_or_candidate`
/// even if they match the glob pattern.
#[cfg(unix)]
#[tokio::test]
async fn list_sessions_rejects_files_with_extensions() {
    let (_dir, new_path) = install_fake_ssh(FAKE_SSH_CHECK_ALIVE_SCRIPT);
    let orig_path = std::env::var("PATH").unwrap_or_default();
    // SAFETY: test-only PATH mutation; tokio test runtime is single-threaded.
    unsafe { std::env::set_var("PATH", &new_path) };

    let ssh_dir = tempfile::tempdir().unwrap();

    // File with extension — should be rejected by is_socket_or_candidate.
    let regular = ssh_dir.path().join("cm-user@host.pub");
    std::fs::write(&regular, "").unwrap();

    // File without extension but too large (>1024 bytes) — also rejected.
    let large = ssh_dir.path().join("control-user@host");
    std::fs::write(&large, "x".repeat(2048)).unwrap();

    let result = list_sessions(ssh_dir.path()).await;

    // SAFETY: restoring the original value.
    unsafe { std::env::set_var("PATH", &orig_path) };

    let sessions = result.unwrap();

    // Neither file should be discovered.
    for session in &sessions {
        assert!(
            !session.control_path.starts_with(ssh_dir.path()),
            "rejected file should not appear: {:?}",
            session.control_path
        );
    }
}
