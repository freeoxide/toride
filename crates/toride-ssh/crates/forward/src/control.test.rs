#![allow(clippy::unreadable_literal)]

use super::*;
#[cfg(unix)]
use serial_test::serial;

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
    assert_eq!(
        extract_host_from_name("some-random-name"),
        "some-random-name"
    );
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
    let line = "  127.0.0.1  port  8080,  forwarding  to  10.0.0.1  port  80  ";
    assert!(parse_forward_line(line, ForwardType::Local).is_none());
}

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
    let output = "\
Local connections:
  127.0.0.1 port 8080, forwarding to 10.0.0.1 port 80
Local connections:
  127.0.0.1 port 9090, forwarding to 10.0.0.2 port 80
";
    let fwds = parse_forward_output(output);
    assert_eq!(fwds.len(), 2);
}

#[test]
fn parse_forward_line_dynamic_with_remote_type() {
    let line = "127.0.0.1 port 1080";
    assert!(parse_forward_line(line, ForwardType::Remote).is_none());
}

#[test]
fn parse_forward_line_local_with_dynamic_type() {
    let line = "127.0.0.1 port 8080, forwarding to 10.0.0.1 port 80";
    let result = parse_forward_line(line, ForwardType::Dynamic);
    if let Some(fwd) = result {
        assert_eq!(fwd.local_port, 8080);
    }
}

#[test]
fn extract_host_from_name_very_long() {
    let long_name = format!("cm-user@{}:22", "a".repeat(256));
    let host = extract_host_from_name(&long_name);
    assert_eq!(host, "a".repeat(256));
}

#[test]
fn extract_host_from_name_with_underscores() {
    assert_eq!(
        extract_host_from_name("cm-user_name@host_name:22"),
        "host_name"
    );
}

#[test]
fn extract_host_from_name_with_hyphens() {
    assert_eq!(extract_host_from_name("cm-user@my-host:22"), "my-host");
}

#[test]
fn extract_pid_from_name_at_boundary() {
    assert_eq!(extract_pid_from_name("ssh-hash-1"), Some(1));
    assert_eq!(
        extract_pid_from_name("ssh-hash-4294967295"),
        Some(4294967295)
    );
}

#[test]
fn parse_forward_output_with_tabs() {
    let output = "Local connections:\n\t127.0.0.1 port 8080, forwarding to 10.0.0.1 port 80\n";
    let fwds = parse_forward_output(output);
    assert_eq!(fwds.len(), 1);
}

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
    assert_eq!(
        extract_host_from_name("cm-user@192.168.1.1:22"),
        "192.168.1.1"
    );
}

#[test]
fn extract_host_from_name_bare_ipv6_loopback() {
    assert_eq!(extract_host_from_name("cm-user@::1:22"), "::1");
}

#[test]
fn extract_host_from_name_bare_ipv6_full() {
    assert_eq!(extract_host_from_name("cm-user@fe80::1:22"), "fe80::1");
}

#[test]
fn extract_host_from_name_bare_ipv6_no_port() {
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
    let spec = format!(
        "[{}]:{}:{}:{}",
        fwd.local_addr,
        fwd.local_port,
        if fwd.remote_addr.is_empty() {
            "localhost"
        } else {
            &fwd.remote_addr
        },
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

#[cfg(unix)]
fn make_socket_file(path: &std::path::Path) {
    use std::os::unix::net::UnixListener;
    let listener = UnixListener::bind(path).expect("bind test socket");
    std::mem::forget(listener);
}

#[cfg(unix)]
#[test]
fn collect_matching_any_finds_all_four_prefixes_in_one_pass() {
    let dir = tempfile::tempdir().expect("tempdir");
    make_socket_file(&dir.path().join("cm-alice@host:22"));
    make_socket_file(&dir.path().join("control-bob@host:22"));
    make_socket_file(&dir.path().join("mux-carol@host:22"));
    make_socket_file(&dir.path().join("ctrl-dave@host:22"));

    let mut found = collect_matching_any(dir.path(), SSH_DIR_PREFIXES);
    found.sort();
    assert_eq!(found.len(), 4, "all four prefixes must match in one pass");
    assert!(found.iter().all(|p| p.starts_with(dir.path())));
}

#[cfg(unix)]
#[test]
fn collect_matching_any_excludes_non_candidates() {
    let dir = tempfile::tempdir().expect("tempdir");
    make_socket_file(&dir.path().join("cm-keep@host:22"));
    make_socket_file(&dir.path().join("ssh-other-hash-1"));
    std::fs::write(dir.path().join("known_hosts"), b"").expect("write junk");
    std::fs::write(dir.path().join("id_ed25519"), b"not a socket").expect("write junk");

    let found = collect_matching_any(dir.path(), SSH_DIR_PREFIXES);
    assert_eq!(
        found.len(),
        1,
        "only the cm- candidate may be returned: found {found:?}"
    );
    assert!(found[0].ends_with("cm-keep@host:22"));
}

#[test]
fn collect_matching_any_missing_dir_is_empty() {
    let dir = tempfile::tempdir().expect("tempdir");
    let missing = dir.path().join("does-not-exist");
    assert_eq!(
        collect_matching_any(&missing, SSH_DIR_PREFIXES),
        Vec::<std::path::PathBuf>::new()
    );
}

#[cfg(unix)]
#[test]
fn collect_matching_any_tmp_prefix() {
    let dir = tempfile::tempdir().expect("tempdir");
    make_socket_file(&dir.path().join("ssh-abcdefghij-4242"));

    let found = collect_matching_any(dir.path(), &["ssh-"]);
    assert_eq!(found.len(), 1);
    assert!(found[0].ends_with("ssh-abcdefghij-4242"));
}

#[test]
fn extract_host_from_name_ssh_hash_format() {
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

#[test]
fn extract_pid_from_name_valid() {
    assert_eq!(extract_pid_from_name("ssh-abc-12345"), Some(12345));
}

#[test]
fn extract_pid_from_name_zero() {
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

#[test]
fn extract_host_from_name_bracketed_ipv6() {
    assert_eq!(extract_host_from_name("cm-user@[::1]:22"), "::1");
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
    assert_eq!(extract_host_from_name("cm-user@[::1]"), "::1");
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
    assert_eq!(extract_host_from_name("mux-user@::1:65535"), "::1");
}

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

#[cfg(unix)]
#[tokio::test]
#[serial]
async fn cancel_forward_success() {
    let (_dir, new_path) = install_fake_ssh(FAKE_SSH_LIST_SCRIPT);
    let orig_path = std::env::var("PATH").unwrap_or_default();
    // SAFETY: test-only PATH mutation; tokio test runtime is single-threaded.
    unsafe { std::env::set_var("PATH", &new_path) };

    let result = cancel_forward(Path::new("/tmp/fake-ctrl-sock"), 9090).await;

    // SAFETY: restoring the original value.
    unsafe { std::env::set_var("PATH", &orig_path) };

    assert!(result.is_ok(), "expected Ok(()) but got: {result:?}");
}

#[cfg(unix)]
#[tokio::test]
#[serial]
async fn cancel_forward_forward_not_found() {
    let (_dir, new_path) = install_fake_ssh(FAKE_SSH_LIST_SCRIPT);
    let orig_path = std::env::var("PATH").unwrap_or_default();
    // SAFETY: test-only PATH mutation; tokio test runtime is single-threaded.
    unsafe { std::env::set_var("PATH", &new_path) };

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

#[cfg(unix)]
#[tokio::test]
async fn cancel_forward_invalid_control_path() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    let bad_path = std::path::Path::new(OsStr::from_bytes(b"/tmp/\xff\xfe/sock"));

    let result = cancel_forward(bad_path, 8080).await;

    match result {
        Err(Error::ForwardFailed(msg)) => {
            assert!(msg.contains("UTF-8"), "unexpected message: {msg}");
        }
        other => panic!("expected Error::ForwardFailed, got: {other:?}"),
    }
}

#[cfg(unix)]
const FAKE_SSH_EXIT_SCRIPT: &str = r"#!/bin/sh
exit 0
";

#[cfg(unix)]
const FAKE_SSH_EXIT_FAIL_SCRIPT: &str = r"#!/bin/sh
exit 1
";

#[cfg(unix)]
#[tokio::test]
#[serial]
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

#[cfg(unix)]
#[tokio::test]
#[serial]
async fn exit_session_stale_socket_cleanup() {
    let (_dir, new_path) = install_fake_ssh(FAKE_SSH_EXIT_FAIL_SCRIPT);
    let orig_path = std::env::var("PATH").unwrap_or_default();
    // SAFETY: test-only PATH mutation; tokio test runtime is single-threaded.
    unsafe { std::env::set_var("PATH", &new_path) };

    let tmp_dir = tempfile::tempdir().unwrap();
    let sock_path = tmp_dir.path().join("stale.sock");
    let _listener = std::os::unix::net::UnixListener::bind(&sock_path).unwrap();
    assert!(sock_path.exists(), "socket file should exist before exit");

    let result = exit_session(&sock_path).await;

    // SAFETY: restoring the original value.
    unsafe { std::env::set_var("PATH", &orig_path) };

    assert!(result.is_err(), "expected error from failed ssh -O exit");
    match &result {
        Err(Error::CommandFailed(msg)) => {
            assert!(msg.contains("ssh -O exit"), "unexpected message: {msg}");
        }
        other => panic!("expected Error::CommandFailed, got: {other:?}"),
    }

    assert!(
        !sock_path.exists(),
        "stale socket file should be removed during cleanup"
    );
}

#[cfg(unix)]
#[tokio::test]
#[serial]
async fn exit_session_invalid_control_path() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    let bad_path = std::path::Path::new(OsStr::from_bytes(b"/tmp/\xff\xfe/sock"));

    let result = exit_session(bad_path).await;

    match result {
        Err(Error::ForwardFailed(msg)) => {
            assert!(msg.contains("UTF-8"), "unexpected message: {msg}");
        }
        other => panic!("expected Error::ForwardFailed, got: {other:?}"),
    }
}

#[cfg(unix)]
const FAKE_SSH_CHECK_ALIVE_SCRIPT: &str = r"#!/bin/sh
exit 0
";

#[cfg(unix)]
const FAKE_SSH_CHECK_DEAD_SCRIPT: &str = r"#!/bin/sh
exit 1
";

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

#[cfg(unix)]
#[tokio::test]
#[serial]
async fn list_sessions_discovers_valid_sockets() {
    let (_dir, new_path) = install_fake_ssh(FAKE_SSH_CHECK_ALIVE_SCRIPT);
    let orig_path = std::env::var("PATH").unwrap_or_default();
    // SAFETY: test-only PATH mutation; tokio test runtime is single-threaded.
    unsafe { std::env::set_var("PATH", &new_path) };

    let ssh_dir = tempfile::tempdir().unwrap();

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

    let hosts: Vec<&str> = our_sessions.iter().map(|s| s.host.as_str()).collect();
    assert!(hosts.contains(&"web01"), "expected web01 in {hosts:?}");
    assert!(hosts.contains(&"db"), "expected db in {hosts:?}");
    assert!(hosts.contains(&"bastion"), "expected bastion in {hosts:?}");

    for session in &our_sessions {
        assert!(session.control_path.starts_with(ssh_dir.path()));
        assert!(
            session.established.is_some(),
            "established timestamp should be set for {:?}",
            session.control_path
        );
    }
}

#[cfg(unix)]
#[tokio::test]
#[serial]
async fn list_sessions_none_alive() {
    let (_dir, new_path) = install_fake_ssh(FAKE_SSH_CHECK_DEAD_SCRIPT);
    let orig_path = std::env::var("PATH").unwrap_or_default();
    // SAFETY: test-only PATH mutation; tokio test runtime is single-threaded.
    unsafe { std::env::set_var("PATH", &new_path) };

    let ssh_dir = tempfile::tempdir().unwrap();

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

#[cfg(unix)]
#[tokio::test]
#[serial]
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

    for session in &sessions {
        assert!(
            !session.control_path.starts_with(ssh_dir.path()),
            "unexpected session from empty ssh_dir: {:?}",
            session.control_path
        );
    }
}

#[cfg(unix)]
#[tokio::test]
#[serial]
async fn list_sessions_mixed_alive_and_dead() {
    let (_dir, new_path) = install_fake_ssh(FAKE_SSH_CHECK_SELECTIVE_SCRIPT);
    let orig_path = std::env::var("PATH").unwrap_or_default();
    // SAFETY: test-only PATH mutation; tokio test runtime is single-threaded.
    unsafe { std::env::set_var("PATH", &new_path) };

    let ssh_dir = tempfile::tempdir().unwrap();

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

    let paths: Vec<&std::path::Path> = our_sessions
        .iter()
        .map(|s| s.control_path.as_path())
        .collect();
    assert!(paths.contains(&alive1.as_path()), "missing alive1");
    assert!(paths.contains(&alive2.as_path()), "missing alive2");

    for session in &our_sessions {
        let name = session.control_path.file_name().unwrap().to_str().unwrap();
        assert!(
            !name.contains("dead"),
            "dead socket should not appear: {name}"
        );
    }
}

#[cfg(unix)]
#[tokio::test]
#[serial]
async fn list_sessions_extracts_pid_from_filename() {
    let (_dir, new_path) = install_fake_ssh(FAKE_SSH_CHECK_ALIVE_SCRIPT);
    let orig_path = std::env::var("PATH").unwrap_or_default();
    // SAFETY: test-only PATH mutation; tokio test runtime is single-threaded.
    unsafe { std::env::set_var("PATH", &new_path) };

    let ssh_dir = tempfile::tempdir().unwrap();

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
    assert_eq!(our_session.host, "abc123def-48291");
}

#[cfg(unix)]
#[tokio::test]
#[serial]
async fn list_sessions_accepts_candidate_files() {
    let (_dir, new_path) = install_fake_ssh(FAKE_SSH_CHECK_ALIVE_SCRIPT);
    let orig_path = std::env::var("PATH").unwrap_or_default();
    // SAFETY: test-only PATH mutation; tokio test runtime is single-threaded.
    unsafe { std::env::set_var("PATH", &new_path) };

    let ssh_dir = tempfile::tempdir().unwrap();

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

#[cfg(unix)]
#[tokio::test]
#[serial]
async fn list_sessions_nonexistent_ssh_dir() {
    let (_dir, new_path) = install_fake_ssh(FAKE_SSH_CHECK_ALIVE_SCRIPT);
    let orig_path = std::env::var("PATH").unwrap_or_default();
    // SAFETY: test-only PATH mutation; tokio test runtime is single-threaded.
    unsafe { std::env::set_var("PATH", &new_path) };

    let result = list_sessions(Path::new("/tmp/nonexistent-ssh-dir-12345")).await;

    // SAFETY: restoring the original value.
    unsafe { std::env::set_var("PATH", &orig_path) };

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

#[cfg(unix)]
#[tokio::test]
#[serial]
async fn list_sessions_rejects_files_with_extensions() {
    let (_dir, new_path) = install_fake_ssh(FAKE_SSH_CHECK_ALIVE_SCRIPT);
    let orig_path = std::env::var("PATH").unwrap_or_default();
    // SAFETY: test-only PATH mutation; tokio test runtime is single-threaded.
    unsafe { std::env::set_var("PATH", &new_path) };

    let ssh_dir = tempfile::tempdir().unwrap();

    let regular = ssh_dir.path().join("cm-user@host.pub");
    std::fs::write(&regular, "").unwrap();

    let large = ssh_dir.path().join("control-user@host");
    std::fs::write(&large, "x".repeat(2048)).unwrap();

    let result = list_sessions(ssh_dir.path()).await;

    // SAFETY: restoring the original value.
    unsafe { std::env::set_var("PATH", &orig_path) };

    let sessions = result.unwrap();

    for session in &sessions {
        assert!(
            !session.control_path.starts_with(ssh_dir.path()),
            "rejected file should not appear: {:?}",
            session.control_path
        );
    }
}

const THROTTLE_TASKS: usize = 24;
const THROTTLE_LIMIT: usize = 4;

#[tokio::test]
async fn join_all_bounded_caps_in_flight_and_preserves_order() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let in_flight = std::sync::Arc::new(AtomicUsize::new(0));
    let max_in_flight = std::sync::Arc::new(AtomicUsize::new(0));

    let futs = (0..THROTTLE_TASKS).map(|i| {
        let in_flight = std::sync::Arc::clone(&in_flight);
        let max_in_flight = std::sync::Arc::clone(&max_in_flight);
        async move {
            let cur = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
            max_in_flight.fetch_max(cur, Ordering::SeqCst);
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            in_flight.fetch_sub(1, Ordering::SeqCst);
            i
        }
    });

    let out = join_all_bounded(THROTTLE_LIMIT, futs).await;
    assert_eq!(
        out,
        (0..THROTTLE_TASKS).collect::<Vec<_>>(),
        "input order must be preserved so callers can zip against sessions"
    );
    assert!(
        max_in_flight.load(Ordering::SeqCst) <= THROTTLE_LIMIT,
        "concurrency cap violated: max in flight {} > {THROTTLE_LIMIT}",
        max_in_flight.load(Ordering::SeqCst)
    );
    assert!(
        max_in_flight.load(Ordering::SeqCst) > 1,
        "futures must actually overlap (sequential execution would defeat the fix)"
    );
}

#[tokio::test]
async fn join_all_bounded_sibling_failure_does_not_cancel_siblings() {
    let futs: Vec<std::pin::Pin<Box<dyn std::future::Future<Output = bool>>>> = vec![
        Box::pin(async { false }),
        Box::pin(async { true }),
        Box::pin(async { false }),
        Box::pin(async { true }),
    ];
    let out = join_all_bounded(2, futs).await;
    assert_eq!(out, vec![false, true, false, true]);
}

#[cfg(unix)]
#[tokio::test]
#[serial]
async fn list_forwards_bounded_yields_one_result_per_input_even_on_failure() {
    let dir = tempfile::tempdir().expect("tempdir");
    let paths: Vec<std::path::PathBuf> = (0..5)
        .map(|i| dir.path().join(format!("no-such-control-socket-{i}")))
        .collect();

    let results = list_forwards_bounded(paths.clone()).await;
    assert_eq!(
        results.len(),
        paths.len(),
        "isolation: every input yields exactly one result"
    );
    assert!(
        results.iter().all(std::result::Result::is_err),
        "a nonexistent control socket must error, not hang or vanish: {results:?}"
    );
}
