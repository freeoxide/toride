#![allow(clippy::unreadable_literal)]

use super::*;
#[cfg(unix)]
use serial_test::serial;

#[test]
fn forward_type_display() {
    assert_eq!(ForwardType::Local.to_string(), "local");
    assert_eq!(ForwardType::Remote.to_string(), "remote");
    assert_eq!(ForwardType::Dynamic.to_string(), "dynamic");
}

#[cfg(unix)]
#[test]
fn ssh_dir_scan_excludes_the_tmp_prefix() {
    use toride_ssh_core::control_master::collect_control_candidates;

    let dir = tempfile::tempdir().expect("tempdir");
    let keep = dir.path().join("cm-keep@host:22");
    let listener = std::os::unix::net::UnixListener::bind(&keep).expect("bind socket");
    let tmp_shaped = dir.path().join("ssh-other-hash-1");
    let listener2 = std::os::unix::net::UnixListener::bind(&tmp_shaped).expect("bind socket");
    std::mem::forget((listener, listener2));

    let found = collect_control_candidates(dir.path(), SSH_DIR_PREFIXES, true).expect("collect");
    assert_eq!(
        found.len(),
        1,
        "the ssh- prefix belongs to the /tmp scan only: {found:?}"
    );
    assert!(found[0].path.ends_with("cm-keep@host:22"));
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
async fn cancel_known_forward_invalid_control_path() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    let bad_path = std::path::Path::new(OsStr::from_bytes(b"/tmp/\xff\xfe/sock"));
    let forward = PortForward {
        local_addr: "127.0.0.1".to_owned(),
        local_port: 8080,
        remote_addr: "10.0.0.1".to_owned(),
        remote_port: 80,
        forward_type: ForwardType::Local,
    };

    let result = cancel_known_forward(bad_path, &forward).await;

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
    let listener = std::os::unix::net::UnixListener::bind(&sock_path).unwrap();
    drop(listener);
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
const FAKE_SSH_EXIT_FAIL_CHECK_ALIVE_SCRIPT: &str = r#"#!/bin/sh
action=""
while [ $# -gt 0 ]; do
    case "$1" in
        -O) action="$2"; shift 2 ;;
        *) shift ;;
    esac
done
case "$action" in
    check) exit 0 ;;
    *) exit 1 ;;
esac
"#;

#[cfg(unix)]
#[tokio::test]
#[serial]
async fn exit_session_live_master_socket_survives_failed_exit() {
    let (_dir, new_path) = install_fake_ssh(FAKE_SSH_EXIT_FAIL_CHECK_ALIVE_SCRIPT);
    let orig_path = std::env::var("PATH").unwrap_or_default();
    // SAFETY: test-only PATH mutation; tokio test runtime is single-threaded.
    unsafe { std::env::set_var("PATH", &new_path) };

    let tmp_dir = tempfile::tempdir().unwrap();
    let sock_path = tmp_dir.path().join("live.sock");
    let _listener = std::os::unix::net::UnixListener::bind(&sock_path).unwrap();
    assert!(sock_path.exists(), "socket file should exist before exit");

    let result = exit_session(&sock_path).await;

    // SAFETY: restoring the original value.
    unsafe { std::env::set_var("PATH", &orig_path) };

    assert!(
        result.is_err(),
        "expected error from failed ssh -O exit: {result:?}"
    );
    assert!(
        sock_path.exists(),
        "a live master's socket must not be unlinked when the exit command fails"
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
