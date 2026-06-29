use super::*;
use crate::command::FakeRunner;

// ---------------------------------------------------------------------------
// is_active
// ---------------------------------------------------------------------------

#[test]
fn is_active_should_return_true_when_active() {
    let runner = FakeRunner::new().respond_ok("systemctl", &["is-active", "ufw"], "active\n");
    assert!(is_active(&runner).unwrap());
}

#[test]
fn is_active_should_return_false_when_inactive() {
    let runner = FakeRunner::new().respond_ok("systemctl", &["is-active", "ufw"], "inactive\n");
    assert!(!is_active(&runner).unwrap());
}

// ---------------------------------------------------------------------------
// is_enabled
// ---------------------------------------------------------------------------

#[test]
fn is_enabled_should_return_true_when_enabled() {
    let runner = FakeRunner::new().respond_ok("systemctl", &["is-enabled", "ufw"], "enabled\n");
    assert!(is_enabled(&runner).unwrap());
}

#[test]
fn is_enabled_should_return_false_when_disabled() {
    let runner = FakeRunner::new().respond_ok("systemctl", &["is-enabled", "ufw"], "disabled\n");
    assert!(!is_enabled(&runner).unwrap());
}

// ---------------------------------------------------------------------------
// Edge-case tests
// ---------------------------------------------------------------------------

#[test]
fn is_active_should_handle_extra_whitespace() {
    let runner = FakeRunner::new().respond_ok("systemctl", &["is-active", "ufw"], "  active  \n");
    assert!(is_active(&runner).unwrap());
}

// ---------------------------------------------------------------------------
// Weird edge-case tests
// ---------------------------------------------------------------------------

#[test]
fn is_active_should_handle_failed_command() {
    let runner = FakeRunner::new().respond_err("systemctl", &["is-active", "ufw"], "not found", 4);
    // The command runs but returns non-"active"
    assert!(!is_active(&runner).unwrap());
}

// ---------------------------------------------------------------------------
// reload
// ---------------------------------------------------------------------------

#[test]
fn reload_should_succeed_on_zero_exit() {
    let runner = FakeRunner::new().respond_ok("systemctl", &["reload", "ufw"], "");
    assert!(reload(&runner).is_ok());
}

#[test]
fn reload_should_fail_on_nonzero_exit() {
    let runner = FakeRunner::new().respond_err("systemctl", &["reload", "ufw"], "failed", 1);
    let err = reload(&runner).unwrap_err();
    assert!(err.to_string().contains("failed to reload ufw"));
}

// ---------------------------------------------------------------------------
// journal_tail
// ---------------------------------------------------------------------------

#[test]
fn journal_tail_should_return_stdout() {
    let runner = FakeRunner::new().respond_ok(
        "journalctl",
        &["-u", "ufw", "--no-pager", "-n", "50"],
        "log line 1\nlog line 2\n",
    );
    let output = journal_tail(&runner, 50).unwrap();
    assert_eq!(output, "log line 1\nlog line 2\n");
}

#[test]
fn journal_tail_should_fail_on_nonzero_exit() {
    let runner = FakeRunner::new().respond_err(
        "journalctl",
        &["-u", "ufw", "--no-pager", "-n", "10"],
        "no journal",
        1,
    );
    let err = journal_tail(&runner, 10).unwrap_err();
    assert!(err.to_string().contains("failed to read ufw journal"));
}
