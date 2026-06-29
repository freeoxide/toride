//! Comprehensive tests for the [`service::ServiceManager`] module.
//!
//! Every test uses [`FakeRunner`] so no real `systemctl` or `journalctl`
//! invocations occur.  The tests cover construction, query operations,
//! lifecycle commands, journal access, and error handling.

use super::*;
use crate::command::{CommandOutput, FakeRunner};

use crate::Error;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// A successful command output with empty stdout/stderr and exit code 0.
fn ok_output() -> CommandOutput {
    CommandOutput {
        stdout: String::new(),
        stderr: String::new(),
        exit_code: Some(0),
        success: true,
    }
}

/// A failed command output that mimics `systemctl is-active` for an inactive
/// unit (exit code 3).
fn fail_output() -> CommandOutput {
    CommandOutput {
        stdout: "inactive".to_owned(),
        stderr: String::new(),
        exit_code: Some(3),
        success: false,
    }
}

/// A failed command output that includes stderr text (e.g. a permission error
/// from systemctl).
fn fail_output_with_stderr() -> CommandOutput {
    CommandOutput {
        stdout: String::new(),
        stderr: "Failed to start fail2ban.service: Access denied".to_owned(),
        exit_code: Some(1),
        success: false,
    }
}

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

#[test]
fn new_uses_default_service_name() {
    let fake = FakeRunner::new();
    let svc = ServiceManager::new(&fake);
    assert_eq!(svc.service_name, "fail2ban");
}

#[test]
fn with_service_name_sets_custom_name() {
    let fake = FakeRunner::new();
    let svc = ServiceManager::with_service_name(&fake, "f2b-custom");
    assert_eq!(svc.service_name, "f2b-custom");
}

#[test]
fn with_service_name_empty_string_is_accepted() {
    let fake = FakeRunner::new();
    let svc = ServiceManager::with_service_name(&fake, "");
    assert_eq!(svc.service_name, "");
}

// ---------------------------------------------------------------------------
// is_active
// ---------------------------------------------------------------------------

#[test]
fn is_active_returns_true_for_exit_code_0() {
    let mut fake = FakeRunner::new();
    fake.with_response("systemctl", &["is-active", "fail2ban"], ok_output());
    let svc = ServiceManager::new(&fake);
    assert!(svc.is_active().unwrap());
}

#[test]
fn is_active_returns_false_for_nonzero_exit_code() {
    let mut fake = FakeRunner::new();
    fake.with_response("systemctl", &["is-active", "fail2ban"], fail_output());
    let svc = ServiceManager::new(&fake);
    assert!(!svc.is_active().unwrap());
}

#[test]
fn is_active_uses_custom_service_name() {
    let mut fake = FakeRunner::new();
    fake.with_response("systemctl", &["is-active", "my-unit"], ok_output());
    let svc = ServiceManager::with_service_name(&fake, "my-unit");
    assert!(svc.is_active().unwrap());
    let calls = fake.calls();
    assert_eq!(calls[0].0, "systemctl");
    assert_eq!(calls[0].1, vec!["is-active", "my-unit"]);
}

// ---------------------------------------------------------------------------
// is_enabled
// ---------------------------------------------------------------------------

#[test]
fn is_enabled_returns_true_for_exit_code_0() {
    let mut fake = FakeRunner::new();
    fake.with_response("systemctl", &["is-enabled", "fail2ban"], ok_output());
    let svc = ServiceManager::new(&fake);
    assert!(svc.is_enabled().unwrap());
}

#[test]
fn is_enabled_returns_false_for_nonzero_exit_code() {
    let mut fake = FakeRunner::new();
    fake.with_response("systemctl", &["is-enabled", "fail2ban"], fail_output());
    let svc = ServiceManager::new(&fake);
    assert!(!svc.is_enabled().unwrap());
}

#[test]
fn is_enabled_uses_custom_service_name() {
    let mut fake = FakeRunner::new();
    fake.with_response("systemctl", &["is-enabled", "custom-svc"], ok_output());
    let svc = ServiceManager::with_service_name(&fake, "custom-svc");
    assert!(svc.is_enabled().unwrap());
    let calls = fake.calls();
    assert_eq!(calls[0].1, vec!["is-enabled", "custom-svc"]);
}

// ---------------------------------------------------------------------------
// start
// ---------------------------------------------------------------------------

#[test]
fn start_succeeds_on_zero_exit() {
    let mut fake = FakeRunner::new();
    fake.with_response("systemctl", &["start", "fail2ban"], ok_output());
    let svc = ServiceManager::new(&fake);
    assert!(svc.start().is_ok());
}

#[test]
fn start_fails_on_nonzero_exit() {
    let mut fake = FakeRunner::new();
    fake.with_response("systemctl", &["start", "fail2ban"], fail_output());
    let svc = ServiceManager::new(&fake);
    let err = svc.start().unwrap_err();
    assert!(matches!(err, Error::CommandFailed(_)));
}

#[test]
fn start_error_includes_exit_code() {
    let mut fake = FakeRunner::new();
    fake.with_response("systemctl", &["start", "fail2ban"], fail_output());
    let svc = ServiceManager::new(&fake);
    let err = svc.start().unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("exit 3"),
        "error message should mention exit code: {msg}"
    );
}

#[test]
fn start_error_includes_stderr_when_present() {
    let mut fake = FakeRunner::new();
    fake.with_response(
        "systemctl",
        &["start", "fail2ban"],
        fail_output_with_stderr(),
    );
    let svc = ServiceManager::new(&fake);
    let err = svc.start().unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("Access denied"),
        "error message should include stderr text: {msg}",
    );
}

// ---------------------------------------------------------------------------
// stop
// ---------------------------------------------------------------------------

#[test]
fn stop_succeeds_on_zero_exit() {
    let mut fake = FakeRunner::new();
    fake.with_response("systemctl", &["stop", "fail2ban"], ok_output());
    let svc = ServiceManager::new(&fake);
    assert!(svc.stop().is_ok());
}

#[test]
fn stop_fails_on_nonzero_exit() {
    let mut fake = FakeRunner::new();
    fake.with_response("systemctl", &["stop", "fail2ban"], fail_output());
    let svc = ServiceManager::new(&fake);
    let err = svc.stop().unwrap_err();
    assert!(matches!(err, Error::CommandFailed(_)));
}

#[test]
fn stop_error_includes_subcommand_name() {
    let mut fake = FakeRunner::new();
    fake.with_response(
        "systemctl",
        &["stop", "fail2ban"],
        fail_output_with_stderr(),
    );
    let svc = ServiceManager::new(&fake);
    let err = svc.stop().unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("stop"),
        "error message should mention the subcommand: {msg}"
    );
}

// ---------------------------------------------------------------------------
// restart
// ---------------------------------------------------------------------------

#[test]
fn restart_succeeds_on_zero_exit() {
    let mut fake = FakeRunner::new();
    fake.with_response("systemctl", &["restart", "fail2ban"], ok_output());
    let svc = ServiceManager::new(&fake);
    assert!(svc.restart().is_ok());
}

#[test]
fn restart_fails_on_nonzero_exit() {
    let mut fake = FakeRunner::new();
    fake.with_response("systemctl", &["restart", "fail2ban"], fail_output());
    let svc = ServiceManager::new(&fake);
    let err = svc.restart().unwrap_err();
    assert!(matches!(err, Error::CommandFailed(_)));
}

#[test]
fn restart_error_includes_service_name() {
    let mut fake = FakeRunner::new();
    fake.with_response(
        "systemctl",
        &["restart", "fail2ban"],
        fail_output_with_stderr(),
    );
    let svc = ServiceManager::new(&fake);
    let err = svc.restart().unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("fail2ban"),
        "error message should include service name: {msg}"
    );
}

// ---------------------------------------------------------------------------
// reload_or_restart
// ---------------------------------------------------------------------------

#[test]
fn reload_or_restart_succeeds_on_zero_exit() {
    let mut fake = FakeRunner::new();
    fake.with_response("systemctl", &["reload-or-restart", "fail2ban"], ok_output());
    let svc = ServiceManager::new(&fake);
    assert!(svc.reload_or_restart().is_ok());
}

#[test]
fn reload_or_restart_fails_on_nonzero_exit() {
    let mut fake = FakeRunner::new();
    fake.with_response(
        "systemctl",
        &["reload-or-restart", "fail2ban"],
        fail_output(),
    );
    let svc = ServiceManager::new(&fake);
    let err = svc.reload_or_restart().unwrap_err();
    assert!(matches!(err, Error::CommandFailed(_)));
}

#[test]
fn reload_or_restart_error_mentions_subcommand() {
    let mut fake = FakeRunner::new();
    fake.with_response(
        "systemctl",
        &["reload-or-restart", "fail2ban"],
        fail_output_with_stderr(),
    );
    let svc = ServiceManager::new(&fake);
    let err = svc.reload_or_restart().unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("reload-or-restart"),
        "error message should mention the subcommand: {msg}",
    );
}

// ---------------------------------------------------------------------------
// journal_tail
// ---------------------------------------------------------------------------

#[test]
fn journal_tail_returns_stdout_on_success() {
    let mut fake = FakeRunner::new();
    let journal_output = CommandOutput {
        stdout: "line1\nline2\nline3\n".to_owned(),
        stderr: String::new(),
        exit_code: Some(0),
        success: true,
    };
    fake.with_response(
        "journalctl",
        &["-u", "fail2ban", "-n", "3", "--no-pager"],
        journal_output,
    );
    let svc = ServiceManager::new(&fake);
    let result = svc.journal_tail(3).unwrap();
    assert_eq!(result, "line1\nline2\nline3\n");
}

#[test]
fn journal_tail_passes_correct_line_count() {
    let mut fake = FakeRunner::new();
    fake.with_response(
        "journalctl",
        &["-u", "fail2ban", "-n", "50", "--no-pager"],
        ok_output(),
    );
    let svc = ServiceManager::new(&fake);
    let _ = svc.journal_tail(50);
    let calls = fake.calls();
    assert_eq!(calls[0].0, "journalctl");
    assert_eq!(calls[0].1, vec!["-u", "fail2ban", "-n", "50", "--no-pager"]);
}

#[test]
fn journal_tail_fails_on_nonzero_exit() {
    let mut fake = FakeRunner::new();
    fake.with_response(
        "journalctl",
        &["-u", "fail2ban", "-n", "10", "--no-pager"],
        fail_output(),
    );
    let svc = ServiceManager::new(&fake);
    assert!(svc.journal_tail(10).is_err());
}

#[test]
fn journal_tail_uses_custom_service_name() {
    let mut fake = FakeRunner::new();
    fake.with_response(
        "journalctl",
        &["-u", "my-unit", "-n", "5", "--no-pager"],
        ok_output(),
    );
    let svc = ServiceManager::with_service_name(&fake, "my-unit");
    let _ = svc.journal_tail(5);
    let calls = fake.calls();
    assert_eq!(calls[0].1, vec!["-u", "my-unit", "-n", "5", "--no-pager"]);
}

#[test]
fn journal_tail_error_includes_context() {
    let mut fake = FakeRunner::new();
    let fail = CommandOutput {
        stdout: String::new(),
        stderr: "Cannot access journal".to_owned(),
        exit_code: Some(1),
        success: false,
    };
    fake.with_response(
        "journalctl",
        &["-u", "fail2ban", "-n", "20", "--no-pager"],
        fail,
    );
    let svc = ServiceManager::new(&fake);
    let err = svc.journal_tail(20).unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("journalctl"),
        "error should mention journalctl: {msg}"
    );
    assert!(
        msg.contains("Cannot access journal"),
        "error should include stderr: {msg}"
    );
}

// ---------------------------------------------------------------------------
// Custom service name propagation
// ---------------------------------------------------------------------------

#[test]
fn custom_service_name_propagates_to_all_commands() {
    let mut fake = FakeRunner::new();

    // Register responses for "custom" instead of the default "fail2ban".
    fake.with_response("systemctl", &["is-active", "custom"], ok_output());
    fake.with_response("systemctl", &["is-enabled", "custom"], ok_output());
    fake.with_response("systemctl", &["start", "custom"], ok_output());
    fake.with_response("systemctl", &["stop", "custom"], ok_output());
    fake.with_response("systemctl", &["restart", "custom"], ok_output());
    fake.with_response("systemctl", &["reload-or-restart", "custom"], ok_output());
    fake.with_response(
        "journalctl",
        &["-u", "custom", "-n", "1", "--no-pager"],
        ok_output(),
    );

    let svc = ServiceManager::with_service_name(&fake, "custom");

    // Execute every method so we can verify the recorded args.
    assert!(svc.is_active().unwrap());
    assert!(svc.is_enabled().unwrap());
    assert!(svc.start().is_ok());
    assert!(svc.stop().is_ok());
    assert!(svc.restart().is_ok());
    assert!(svc.reload_or_restart().is_ok());
    assert!(svc.journal_tail(1).is_ok());

    let calls = fake.calls();
    assert_eq!(calls.len(), 7, "expected exactly 7 recorded calls");

    // Verify each call targets the custom service name.
    for (_program, args) in &calls {
        assert!(
            args.iter().any(|a| a == "custom"),
            "all calls should target the custom unit: {args:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// Error handling for failed commands
// ---------------------------------------------------------------------------

#[test]
fn error_message_format_without_stderr() {
    let mut fake = FakeRunner::new();
    let fail = CommandOutput {
        stdout: String::new(),
        stderr: String::new(),
        exit_code: Some(1),
        success: false,
    };
    fake.with_response("systemctl", &["start", "fail2ban"], fail);
    let svc = ServiceManager::new(&fake);
    let err = svc.start().unwrap_err();
    let msg = format!("{err}");
    // When stderr is empty the message should not have a trailing colon.
    assert!(
        !msg.contains("): "),
        "error message should not have dangling stderr separator when stderr is empty: {msg}",
    );
    assert!(
        msg.contains("systemctl"),
        "error should mention program: {msg}"
    );
    assert!(
        msg.contains("start"),
        "error should mention subcommand: {msg}"
    );
    assert!(
        msg.contains("fail2ban"),
        "error should mention service: {msg}"
    );
    assert!(
        msg.contains("exit 1"),
        "error should mention exit code: {msg}"
    );
}

#[test]
fn error_message_format_with_stderr() {
    let mut fake = FakeRunner::new();
    let fail = CommandOutput {
        stdout: String::new(),
        stderr: "  Unit fail2ban.service not found.  ".to_owned(),
        exit_code: Some(5),
        success: false,
    };
    fake.with_response("systemctl", &["start", "fail2ban"], fail);
    let svc = ServiceManager::new(&fake);
    let err = svc.start().unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("exit 5"),
        "error should mention exit code: {msg}"
    );
    // stderr is trimmed in the error message.
    assert!(
        msg.contains("Unit fail2ban.service not found."),
        "error should include trimmed stderr: {msg}",
    );
}

#[test]
fn error_message_for_signal_termination() {
    let mut fake = FakeRunner::new();
    let fail = CommandOutput {
        stdout: String::new(),
        stderr: String::new(),
        exit_code: None,
        success: false,
    };
    fake.with_response("systemctl", &["start", "fail2ban"], fail);
    let svc = ServiceManager::new(&fake);
    let err = svc.start().unwrap_err();
    let msg = format!("{err}");
    // When exit_code is None the helper uses "signal".
    assert!(
        msg.contains("signal"),
        "error should mention signal when exit_code is None: {msg}"
    );
}

#[test]
fn lifecycle_methods_return_command_failed_variant() {
    let mut fake = FakeRunner::new();
    fake.with_response("systemctl", &["start", "fail2ban"], fail_output());
    fake.with_response("systemctl", &["stop", "fail2ban"], fail_output());
    fake.with_response("systemctl", &["restart", "fail2ban"], fail_output());
    fake.with_response(
        "systemctl",
        &["reload-or-restart", "fail2ban"],
        fail_output(),
    );
    fake.with_response(
        "journalctl",
        &["-u", "fail2ban", "-n", "1", "--no-pager"],
        fail_output(),
    );

    let svc = ServiceManager::new(&fake);

    // Lifecycle methods return Result<()> on failure.
    for result in [
        svc.start(),
        svc.stop(),
        svc.restart(),
        svc.reload_or_restart(),
    ] {
        let err = result.unwrap_err();
        assert!(
            matches!(err, Error::CommandFailed(_)),
            "expected CommandFailed variant, got: {err:?}",
        );
    }

    // journal_tail returns Result<String> on failure but same error variant.
    let journal_err = svc.journal_tail(1).unwrap_err();
    assert!(
        matches!(journal_err, Error::CommandFailed(_)),
        "expected CommandFailed variant for journal_tail, got: {journal_err:?}",
    );
}

#[test]
fn query_methods_never_return_err_on_nonzero() {
    // is_active and is_enabled return Ok(bool) even on non-zero exit.
    let mut fake = FakeRunner::new();
    fake.with_response("systemctl", &["is-active", "fail2ban"], fail_output());
    fake.with_response("systemctl", &["is-enabled", "fail2ban"], fail_output());
    let svc = ServiceManager::new(&fake);

    assert!(
        svc.is_active().is_ok(),
        "is_active should not return Err on non-zero"
    );
    assert!(
        !svc.is_active().unwrap(),
        "is_active should return Ok(false)"
    );

    assert!(
        svc.is_enabled().is_ok(),
        "is_enabled should not return Err on non-zero"
    );
    assert!(
        !svc.is_enabled().unwrap(),
        "is_enabled should return Ok(false)"
    );
}
