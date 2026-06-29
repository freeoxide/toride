use super::*;
use std::os::unix::process::ExitStatusExt;
use std::time::Duration;

// ---------------------------------------------------------------------------
// DuctRunner::new / with_timeout
// ---------------------------------------------------------------------------

#[test]
fn duct_runner_new_creates_with_default_30s_timeout() {
    let runner = DuctRunner::new();
    assert_eq!(runner.default_timeout, Duration::from_secs(30));
    assert!(!runner.dry_run);
}

#[test]
fn duct_runner_with_timeout_sets_custom_timeout() {
    let runner = DuctRunner::with_timeout(Duration::from_secs(60));
    assert_eq!(runner.default_timeout, Duration::from_secs(60));
    assert!(!runner.dry_run);
}

#[test]
fn duct_runner_default_trait_matches_new() {
    let explicit = DuctRunner::new();
    let default = DuctRunner::default();
    assert_eq!(explicit.default_timeout, default.default_timeout);
    assert_eq!(explicit.dry_run, default.dry_run);
}

// ---------------------------------------------------------------------------
// DuctRunner implements Runner
// ---------------------------------------------------------------------------

#[test]
fn duct_runner_dry_run_mode_returns_success_without_execution() {
    let mut runner = DuctRunner::new();
    runner.set_dry_run(true);
    assert!(runner.dry_run());

    // This binary does not exist; in dry-run mode it should still succeed.
    let out = runner
        .run("this-binary-does-not-exist-at-all-xyz", &[])
        .unwrap();
    assert!(out.success);
    assert!(out.stdout.is_empty());
    assert!(out.stderr.is_empty());
    assert_eq!(out.exit_code, Some(0));
}

#[test]
fn duct_runner_dry_run_with_timeout_returns_success() {
    let mut runner = DuctRunner::new();
    runner.set_dry_run(true);

    let out = runner
        .run_with_timeout("nonexistent-binary", &["arg"], Duration::from_secs(5))
        .unwrap();
    assert!(out.success);
    assert!(out.stdout.is_empty());
}

#[test]
fn duct_runner_set_dry_run_toggles() {
    let mut runner = DuctRunner::new();
    assert!(!runner.dry_run());
    runner.set_dry_run(true);
    assert!(runner.dry_run());
    runner.set_dry_run(false);
    assert!(!runner.dry_run());
}

#[test]
fn duct_runner_runs_true_successfully() {
    let runner = DuctRunner::new();
    let out = runner.run("true", &[]).unwrap();
    assert!(out.success);
    assert_eq!(out.exit_code, Some(0));
}

#[test]
fn duct_runner_captures_stdout() {
    let runner = DuctRunner::new();
    let out = runner.run("echo", &["hello world"]).unwrap();
    assert!(out.success);
    assert_eq!(out.stdout.trim(), "hello world");
}

#[test]
fn duct_runner_captures_stderr() {
    let runner = DuctRunner::new();
    // `sh -c` writes to stderr via `1>&2`
    let out = runner.run("sh", &["-c", "echo err-msg >&2"]).unwrap();
    assert!(out.success);
    assert!(out.stderr.trim().contains("err-msg"));
}

#[test]
fn duct_runner_reports_non_zero_exit() {
    let runner = DuctRunner::new();
    let out = runner.run("false", &[]).unwrap();
    assert!(!out.success);
    assert_eq!(out.exit_code, Some(1));
}

#[test]
fn duct_runner_run_with_timeout_executes_command() {
    let runner = DuctRunner::new();
    let out = runner
        .run_with_timeout("echo", &["timed"], Duration::from_secs(10))
        .unwrap();
    assert!(out.success);
    assert_eq!(out.stdout.trim(), "timed");
}

#[test]
fn duct_runner_spawn_failure_returns_command_failed_error() {
    let runner = DuctRunner::new();
    let result = runner.run("/definitely/not/a/real/binary", &[]);
    assert!(result.is_err());
    match result.unwrap_err() {
        Error::CommandFailed(msg) => {
            assert!(msg.contains("failed to spawn"), "unexpected msg: {msg}");
        }
        other => panic!("expected CommandFailed, got: {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// FakeRunner::new / basics
// ---------------------------------------------------------------------------

#[test]
fn fake_runner_new_creates_empty_runner() {
    let fake = FakeRunner::new();
    assert!(fake.calls().is_empty());
    assert!(!fake.dry_run());
}

#[test]
fn fake_runner_default_matches_new() {
    let explicit = FakeRunner::new();
    let default = FakeRunner::default();
    assert_eq!(explicit.calls(), default.calls());
    assert_eq!(explicit.dry_run(), default.dry_run());
}

// ---------------------------------------------------------------------------
// FakeRunner records calls
// ---------------------------------------------------------------------------

#[test]
fn fake_runner_records_single_call() {
    let fake = FakeRunner::new();
    let _ = fake.run("echo", &["hello"]);
    let calls = fake.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0, "echo");
    assert_eq!(calls[0].1, vec!["hello"]);
}

#[test]
fn fake_runner_records_multiple_calls_in_order() {
    let fake = FakeRunner::new();
    let _ = fake.run("cmd-a", &["arg1"]);
    let _ = fake.run("cmd-b", &["arg2", "arg3"]);
    let _ = fake.run("cmd-c", &[]);

    let calls = fake.calls();
    assert_eq!(calls.len(), 3);

    assert_eq!(calls[0].0, "cmd-a");
    assert_eq!(calls[0].1, vec!["arg1"]);

    assert_eq!(calls[1].0, "cmd-b");
    assert_eq!(calls[1].1, vec!["arg2", "arg3"]);

    assert_eq!(calls[2].0, "cmd-c");
    assert!(calls[2].1.is_empty());
}

#[test]
fn fake_runner_run_with_timeout_records_calls() {
    let fake = FakeRunner::new();
    let _ = fake.run_with_timeout("cmd", &["arg"], Duration::from_secs(5));
    let calls = fake.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0, "cmd");
    assert_eq!(calls[0].1, vec!["arg"]);
}

// ---------------------------------------------------------------------------
// FakeRunner returns configured responses
// ---------------------------------------------------------------------------

#[test]
fn fake_runner_returns_configured_response() {
    let mut fake = FakeRunner::new();
    let response = CommandOutput::new("pong".to_string(), String::new(), Some(0));
    fake.with_response("fail2ban-client", &["ping"], response);

    let out = fake.run("fail2ban-client", &["ping"]).unwrap();
    assert!(out.success);
    assert_eq!(out.stdout, "pong");
}

#[test]
fn fake_runner_returns_default_for_unknown_commands() {
    let fake = FakeRunner::new();
    let out = fake.run("unknown-cmd", &["--flag"]).unwrap();
    assert!(out.success);
    assert!(out.stdout.is_empty());
    assert!(out.stderr.is_empty());
    assert_eq!(out.exit_code, Some(0));
}

#[test]
fn fake_runner_with_response_chains() {
    let mut fake = FakeRunner::new();
    fake.with_response(
        "cmd1",
        &["a"],
        CommandOutput::new("out1".to_string(), String::new(), Some(0)),
    )
    .with_response(
        "cmd2",
        &["b"],
        CommandOutput::new("out2".to_string(), String::new(), Some(1)),
    );

    let out1 = fake.run("cmd1", &["a"]).unwrap();
    assert_eq!(out1.stdout, "out1");
    assert!(out1.success);

    let out2 = fake.run("cmd2", &["b"]).unwrap();
    assert_eq!(out2.stdout, "out2");
    assert!(!out2.success);
    assert_eq!(out2.exit_code, Some(1));
}

#[test]
fn fake_runner_can_return_failure_response() {
    let mut fake = FakeRunner::new();
    fake.with_response(
        "fail2ban-client",
        &["status", "sshd"],
        CommandOutput::new(String::new(), "No jail found".to_string(), Some(1)),
    );

    let out = fake.run("fail2ban-client", &["status", "sshd"]).unwrap();
    assert!(!out.success);
    assert_eq!(out.stderr, "No jail found");
}

// ---------------------------------------------------------------------------
// FakeRunner dry-run mode
// ---------------------------------------------------------------------------

#[test]
fn fake_runner_set_dry_run_toggles() {
    let mut fake = FakeRunner::new();
    assert!(!fake.dry_run());
    fake.set_dry_run(true);
    assert!(fake.dry_run());
    fake.set_dry_run(false);
    assert!(!fake.dry_run());
}

// Note: FakeRunner does NOT skip recording in dry-run mode -- it always
// records.  Dry-run semantics are handled by DuctRunner.  Verify that
// FakeRunner still records even when dry_run is true.
#[test]
fn fake_runner_records_even_in_dry_run_mode() {
    let mut fake = FakeRunner::new();
    fake.set_dry_run(true);
    let _ = fake.run("echo", &["hello"]);
    let calls = fake.calls();
    assert_eq!(calls.len(), 1);
}

// ---------------------------------------------------------------------------
// FakeRunner calls() returns snapshot
// ---------------------------------------------------------------------------

#[test]
fn fake_runner_calls_returns_snapshot_not_live_reference() {
    let fake = FakeRunner::new();
    let _ = fake.run("echo", &["a"]);
    let snap = fake.calls();
    let _ = fake.run("echo", &["b"]);
    // snap is a snapshot; it should still have length 1
    assert_eq!(snap.len(), 1);
    // A fresh call should show 2
    assert_eq!(fake.calls().len(), 2);
}

// ---------------------------------------------------------------------------
// find_binary
// ---------------------------------------------------------------------------

#[test]
fn find_binary_locates_common_binary_ls() {
    let result = find_binary("ls");
    assert!(result.is_ok(), "expected to find 'ls' on PATH");
    let path = result.unwrap();
    assert!(
        path.to_string_lossy().contains("ls"),
        "path should contain 'ls': {}",
        path.display()
    );
}

#[test]
fn find_binary_locates_common_binary_echo() {
    let result = find_binary("echo");
    assert!(result.is_ok(), "expected to find 'echo' on PATH");
}

#[test]
fn find_binary_returns_not_found_for_nonexistent() {
    let result = find_binary("no-such-binary-xyz-12345");
    assert!(result.is_err());
    match result.unwrap_err() {
        Error::NotFound(name) => {
            assert_eq!(name, "no-such-binary-xyz-12345");
        }
        other => panic!("expected NotFound, got: {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// CommandOutput
// ---------------------------------------------------------------------------

#[test]
fn command_output_new_success() {
    let out = CommandOutput::new(String::new(), String::new(), Some(0));
    assert!(out.success);
    assert_eq!(out.exit_code, Some(0));
    assert!(out.stdout.is_empty());
    assert!(out.stderr.is_empty());
}

#[test]
fn command_output_from_raw_output_captures_fields() {
    use std::process::Output;
    let raw = Output {
        status: std::process::ExitStatus::from_raw(0),
        stdout: b"hello\n".to_vec(),
        stderr: b"".to_vec(),
    };
    let out = CommandOutput::new(
        String::from_utf8_lossy(&raw.stdout).into_owned(),
        String::from_utf8_lossy(&raw.stderr).into_owned(),
        raw.status.code(),
    );
    assert!(out.success);
    assert_eq!(out.exit_code, Some(0));
    assert_eq!(out.stdout, "hello\n");
    assert!(out.stderr.is_empty());
}

#[test]
fn command_output_from_raw_output_nonzero() {
    use std::process::Output;
    let raw = Output {
        status: std::process::ExitStatus::from_raw(256), // exit code 1 on unix
        stdout: b"".to_vec(),
        stderr: b"error msg\n".to_vec(),
    };
    let out = CommandOutput::new(
        String::from_utf8_lossy(&raw.stdout).into_owned(),
        String::from_utf8_lossy(&raw.stderr).into_owned(),
        raw.status.code(),
    );
    assert!(!out.success);
    assert_eq!(out.exit_code, Some(1));
    assert_eq!(out.stderr, "error msg\n");
}

// ---------------------------------------------------------------------------
// Redacted logging
// ---------------------------------------------------------------------------

#[test]
fn redacted_cmd_str_masks_sensitive_values() {
    let result = redacted_cmd_str("cmd", &["--token=abc123", "--verbose", "--key=secret"]);
    assert_eq!(result, "cmd *** --verbose ***");
}

#[test]
fn redacted_cmd_str_passes_non_sensitive_through() {
    let result = redacted_cmd_str("echo", &["hello", "world"]);
    assert_eq!(result, "echo hello world");
}

#[test]
fn redacted_cmd_str_is_case_insensitive() {
    let result = redacted_cmd_str("cmd", &["--PASSWORD=x"]);
    assert_eq!(result, "cmd ***");
}

#[test]
fn redacted_cmd_str_redacts_password_keyword() {
    let result = redacted_cmd_str("app", &["--password=mypass"]);
    assert_eq!(result, "app ***");
}

#[test]
fn redacted_cmd_str_redacts_secret_keyword() {
    let result = redacted_cmd_str("app", &["--secret=value"]);
    assert_eq!(result, "app ***");
}

#[test]
fn redacted_cmd_str_redacts_key_keyword() {
    let result = redacted_cmd_str("app", &["--api-key=abc"]);
    assert_eq!(result, "app ***");
}

#[test]
fn redacted_cmd_str_handles_empty_args() {
    let result = redacted_cmd_str("prog", &[]);
    assert_eq!(result, "prog");
}

#[test]
fn redacted_cmd_str_handles_no_program_args() {
    let result = redacted_cmd_str("true", &[]);
    assert_eq!(result, "true");
}

// ---------------------------------------------------------------------------
// Runner trait is dyn-compatible (object-safe check)
// ---------------------------------------------------------------------------

#[test]
fn runner_trait_is_dyn_compatible() {
    let _boxed: Box<dyn Runner> = Box::new(DuctRunner::new());
    let _fake_boxed: Box<dyn Runner> = Box::new(FakeRunner::new());
}

// ===========================================================================
// Property-based tests (proptest)
// ===========================================================================

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    /// Strategy that produces a string containing one of the sensitive keywords
    /// as a substring (case-insensitive).
    fn sensitive_arg_strategy() -> impl Strategy<Value = String> {
        let keyword = prop::sample::select(
            &[
                "password", "token", "key", "secret", "PASSWORD", "TOKEN", "KEY", "SECRET",
                "Password", "Token", "Key", "Secret",
            ][..],
        );
        (keyword, "\\PC*", "\\PC*").prop_map(|(kw, pre, suf)| format!("{pre}{kw}{suf}"))
    }

    /// Strategy for a non-sensitive argument (no sensitive keywords).
    fn safe_arg_strategy() -> impl Strategy<Value = String> {
        "\\PC*".prop_filter(
            "must not contain sensitive keywords or redaction marker",
            |s| {
                let lower = s.to_ascii_lowercase();
                !lower.contains("password")
                    && !lower.contains("token")
                    && !lower.contains("key")
                    && !lower.contains("secret")
                    && !s.contains("***")
            },
        )
    }

    proptest! {
        #[test]
        fn redacted_cmd_str_masks_sensitive_args(arg in sensitive_arg_strategy()) {
            let result = redacted_cmd_str("cmd", &[&arg]);
            prop_assert!(
                !result.contains(&arg),
                "sensitive argument should be redacted, but found: {arg:?}"
            );
            prop_assert!(
                result.contains("***"),
                "redacted output should contain '***'"
            );
        }

        #[test]
        fn redacted_cmd_str_preserves_safe_args(arg in safe_arg_strategy()) {
            let result = redacted_cmd_str("cmd", &[&arg]);
            if !arg.is_empty() {
                prop_assert!(
                    result.contains(&arg),
                    "safe argument should be preserved, but was redacted: {arg:?}"
                );
            }
            prop_assert!(
                !result.contains("***"),
                "safe argument should not be redacted"
            );
        }

        #[test]
        fn redacted_cmd_str_sensitive_keyword_case_insensitive(
            keyword in prop::sample::select(&["password", "PASSWORD", "Password", "ToKeN", "SECRET", "Key"][..]),
            value in ".+"
        ) {
            let arg = format!("--{keyword}={value}");
            let result = redacted_cmd_str("app", &[&arg]);
            prop_assert!(
                result.contains("***"),
                "argument with keyword '{}' should be redacted",
                keyword
            );
            prop_assert!(
                !result.contains(&format!("={value}")),
                "sensitive value should not appear as a flag value in output"
            );
        }

        #[test]
        fn redacted_cmd_str_always_starts_with_program(
            program in "[a-zA-Z][a-zA-Z0-9_-]{0,20}",
            args in prop::collection::vec("\\PC*", 0..=5)
        ) {
            let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
            let result = redacted_cmd_str(&program, &arg_refs);
            prop_assert!(
                result.starts_with(&program),
                "output should start with program name"
            );
        }
    }
}
