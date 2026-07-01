use super::*;

// ---------------------------------------------------------------------------
// FakeRunner basics
// ---------------------------------------------------------------------------

#[test]
fn fake_runner_should_respond_to_registered_command() {
    let runner = FakeRunner::new().respond_ok("ufw", &["--version"], "ufw 0.36.1");

    let spec = CommandSpec::ufw(vec!["--version".into()]);
    let result = runner.run(&spec).unwrap();
    assert_eq!(result.stdout, "ufw 0.36.1");
    assert_eq!(result.exit_code, Some(0));
}

#[test]
fn fake_runner_should_return_error_for_unregistered_command() {
    let runner = FakeRunner::new();

    let spec = CommandSpec::ufw(vec!["status".into()]);
    let result = runner.run(&spec);
    assert!(result.is_err());
}

#[test]
fn fake_runner_should_log_commands() {
    let runner = FakeRunner::new()
        .respond_ok("ufw", &["--version"], "v1")
        .respond_ok("ufw", &["status"], "active");

    let spec1 = CommandSpec::ufw(vec!["--version".into()]);
    let spec2 = CommandSpec::ufw(vec!["status".into()]);

    runner.run(&spec1).unwrap();
    runner.run(&spec2).unwrap();

    let log = runner.command_log();
    assert_eq!(log.len(), 2);
    assert_eq!(log[0].program, "ufw");
    assert_eq!(log[0].args, vec!["--version"]);
    assert_eq!(log[1].program, "ufw");
    assert_eq!(log[1].args, vec!["status"]);
}

#[test]
fn fake_runner_command_count_should_track_executions() {
    let runner = FakeRunner::new().respond_ok("ufw", &["--version"], "v1");

    assert_eq!(runner.command_count(), 0);

    let spec = CommandSpec::ufw(vec!["--version".into()]);
    runner.run(&spec).unwrap();

    assert_eq!(runner.command_count(), 1);
}

#[test]
fn fake_runner_clear_log_should_reset() {
    let runner = FakeRunner::new().respond_ok("ufw", &["--version"], "v1");

    let spec = CommandSpec::ufw(vec!["--version".into()]);
    runner.run(&spec).unwrap();
    assert_eq!(runner.command_count(), 1);

    runner.clear_log();
    assert_eq!(runner.command_count(), 0);
}

#[test]
fn fake_runner_respond_err_should_return_failure() {
    let runner = FakeRunner::new().respond_err("ufw", &["enable"], "permission denied", 1);

    let spec = CommandSpec::ufw(vec!["enable".into()]);
    let result = runner.run(&spec).unwrap();
    assert_eq!(result.stderr, "permission denied");
    assert_eq!(result.exit_code, Some(1));
}

// ---------------------------------------------------------------------------
// FakeRunner binary_exists
// ---------------------------------------------------------------------------

#[test]
fn fake_runner_binary_exists_should_return_true_for_ufw() {
    let runner = FakeRunner::new();
    assert!(runner.binary_exists("ufw"));
    assert!(runner.binary_exists("iptables"));
    assert!(runner.binary_exists("systemctl"));
}

#[test]
fn fake_runner_binary_exists_should_return_false_for_unknown() {
    let runner = FakeRunner::new();
    assert!(!runner.binary_exists("some-unknown-tool"));
}

// ---------------------------------------------------------------------------
// Edge-case tests
// ---------------------------------------------------------------------------

#[test]
fn fake_runner_should_match_with_args() {
    let runner = FakeRunner::new()
        .respond_ok("ufw", &["status", "verbose"], "verbose output")
        .respond_ok("ufw", &["status"], "simple output");

    let spec_verbose = CommandSpec::ufw(vec!["status".into(), "verbose".into()]);
    let spec_simple = CommandSpec::ufw(vec!["status".into()]);

    assert_eq!(runner.run(&spec_verbose).unwrap().stdout, "verbose output");
    assert_eq!(runner.run(&spec_simple).unwrap().stdout, "simple output");
}

#[test]
fn fake_runner_respond_should_return_error_result() {
    let runner = FakeRunner::new().respond(
        "ufw",
        &["status"],
        Err(Error::UfwNotFound("not found".into())),
    );

    let spec = CommandSpec::ufw(vec!["status".into()]);
    let result = runner.run(&spec);
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// Weird edge-case tests
// ---------------------------------------------------------------------------

#[test]
fn fake_runner_should_handle_empty_args() {
    let runner = FakeRunner::new().respond_ok("ufw", &[], "usage: ufw");

    let spec = CommandSpec::ufw(vec![]);
    let result = runner.run(&spec).unwrap();
    assert_eq!(result.stdout, "usage: ufw");
}

#[test]
fn fake_runner_log_should_record_all_args() {
    let runner = FakeRunner::new().respond_ok("ufw", &["a", "b", "c"], "ok");

    let spec = CommandSpec::ufw(vec!["a".into(), "b".into(), "c".into()]);
    runner.run(&spec).unwrap();

    let log = runner.command_log();
    assert_eq!(log[0].args, vec!["a", "b", "c"]);
}

// ---------------------------------------------------------------------------
// Production-grade weird edge cases
// ---------------------------------------------------------------------------

#[test]
fn fake_runner_multiple_runs_should_all_be_logged() {
    let runner = FakeRunner::new().respond_ok("ufw", &["status"], "active");

    let spec = CommandSpec::ufw(vec!["status".into()]);
    for _ in 0..100 {
        runner.run(&spec).unwrap();
    }

    assert_eq!(runner.command_count(), 100);
}

#[test]
fn fake_runner_should_handle_stderr_with_newlines() {
    let runner = FakeRunner::new().respond_err("ufw", &["enable"], "line1\nline2\nline3", 1);

    let spec = CommandSpec::ufw(vec!["enable".into()]);
    let result = runner.run(&spec).unwrap();
    assert_eq!(result.stderr, "line1\nline2\nline3");
}

#[test]
fn fake_runner_should_handle_large_stdout() {
    let large_output = "x".repeat(1_000_000);
    let runner = FakeRunner::new().respond(
        "ufw",
        &["show", "raw"],
        Ok(CommandResult {
            stdout: large_output.clone(),
            stderr: String::new(),
            exit_code: Some(0),
        }),
    );

    let spec = CommandSpec::ufw(vec!["show".into(), "raw".into()]);
    let result = runner.run(&spec).unwrap();
    assert_eq!(result.stdout.len(), 1_000_000);
}

// ---------------------------------------------------------------------------
// redact_args — secret masking for command-log output
// ---------------------------------------------------------------------------

fn redact(args: &[&str]) -> String {
    redact_args(&args.iter().map(|s| (*s).to_string()).collect::<Vec<_>>())
}

#[test]
fn redact_args_should_mask_trailing_value() {
    // --password <value> (space separator): the next arg is the secret.
    let out = redact(&["--password", "s3cr3t"]);
    assert!(out.contains("***"), "expected a redacted marker, got {out:?}");
    assert!(!out.contains("s3cr3t"), "secret value leaked into output: {out:?}");
}

#[test]
fn redact_args_should_mask_inline_equal_value() {
    // --api-key=value (inline `=`): the value half is redacted.
    let out = redact(&["--api-key=abc123"]);
    assert!(out.contains("--api-key=***"), "expected --api-key=***, got {out:?}");
    assert!(!out.contains("abc123"), "secret value leaked into output: {out:?}");
}

#[test]
fn redact_args_should_mask_password_inline_equal() {
    let out = redact(&["--password=hunter2"]);
    assert!(out.contains("--password=***"), "got {out:?}");
    assert!(!out.contains("hunter2"), "got {out:?}");
}

#[test]
fn redact_args_should_be_case_insensitive() {
    // Uppercase/mixed-case flag forms are also masked.
    let out = redact(&["--PASSWORD", "hunter2"]);
    assert!(out.contains("***"), "got {out:?}");
    assert!(!out.contains("hunter2"), "got {out:?}");

    let out_eq = redact(&["--Token=xyz"]);
    assert!(out_eq.contains("--Token=***"), "got {out_eq:?}");
    assert!(!out_eq.contains("xyz"), "got {out_eq:?}");
}

#[test]
fn redact_args_should_pass_through_non_sensitive_flags() {
    // A plain flag with a non-sensitive following arg is left intact.
    let out = redact(&["--verbose", "--host", "example.com", "--port", "443"]);
    assert!(out.contains("example.com"), "got {out:?}");
    assert!(out.contains("443"), "got {out:?}");
    assert!(!out.contains("***"), "non-sensitive arg was masked: {out:?}");
}

#[test]
fn redact_args_should_mask_all_sensitive_flags() {
    // Every entry in REDACT_FLAGS should mask its trailing value.
    for flag in &[
        "--password",
        "--passwd",
        "--secret",
        "--token",
        "--key",
        "--api-key",
        "--api_key",
        "--auth",
        "--credentials",
    ] {
        let out = redact(&[flag, "leak"]);
        assert!(out.contains("***"), "flag {flag} did not redact: {out:?}");
        assert!(!out.contains("leak"), "flag {flag} leaked value: {out:?}");
    }
}

#[test]
fn redact_args_exact_match_gap_is_pinned() {
    // REDACT_FLAGS requires an EXACT lowercased match, so these look-alike
    // flags are intentionally NOT redacted. This test pins that behavior so a
    // future loosening (e.g. switching to `starts_with`) is a deliberate,
    // reviewed change.
    let out = redact(&["--apikey", "not-redacted"]);
    assert!(!out.contains("***"), "--apikey was unexpectedly redacted (exact-match gap): {out:?}");
    assert!(out.contains("not-redacted"), "got {out:?}");

    let out2 = redact(&["--new-password", "x"]);
    assert!(!out2.contains("***"), "--new-password redacted: {out2:?}");

    let out3 = redact(&["--ssh-key-file", "y"]);
    assert!(!out3.contains("***"), "--ssh-key-file redacted: {out3:?}");
}

#[test]
fn redact_args_should_not_mask_a_lone_flag_with_no_value() {
    // A redactable flag at the very end (no following arg) just passes
    // through; nothing to mask.
    let out = redact(&["--password"]);
    assert!(out.contains("--password"), "got {out:?}");
    assert!(!out.contains("***"), "got {out:?}");
}

#[test]
fn redact_args_should_mask_two_consecutive_secrets() {
    let out = redact(&["--password", "pw1", "--token", "tok2"]);
    assert!(out.matches("***").count() >= 2, "got {out:?}");
    assert!(!out.contains("pw1"), "got {out:?}");
    assert!(!out.contains("tok2"), "got {out:?}");
}
