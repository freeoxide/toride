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
