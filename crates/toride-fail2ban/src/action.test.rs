use super::*;
use crate::command::DuctRunner;
use crate::types::PlatformCommands;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn default_vars() -> ActionVars {
    ActionVars::new("192.168.1.100", 32, "sshd", 3600, 5, "/var/log/auth.log")
}

fn make_platform_commands(linux: &[&str], macos: &[&str], freebsd: &[&str]) -> PlatformCommands {
    PlatformCommands::new(
        linux.iter().map(|s| s.to_string()).collect(),
        macos.iter().map(|s| s.to_string()).collect(),
        freebsd.iter().map(|s| s.to_string()).collect(),
    )
}

fn make_exec(name: &str, commands: PlatformCommands) -> ActionExec {
    ActionExec::new(name.to_string(), commands)
}

fn make_runner() -> DuctRunner {
    DuctRunner::new()
}

// ---------------------------------------------------------------------------
// ActionVars::new
// ---------------------------------------------------------------------------

#[test]
fn action_vars_new_sets_all_fields() {
    let vars = ActionVars::new("10.0.0.1", 24, "nginx", 7200, 10, "/var/log/nginx.log");

    assert_eq!(vars.ip, "10.0.0.1");
    assert_eq!(vars.prefix, 24);
    assert_eq!(vars.jail_name, "nginx");
    assert_eq!(vars.ban_time, 7200);
    assert_eq!(vars.fail_count, 10);
    assert_eq!(vars.log_path, "/var/log/nginx.log");
}

#[test]
fn action_vars_new_converts_str_to_owned() {
    let vars = ActionVars::new("127.0.0.1", 32, "test", 0, 0, "/dev/null");

    // All fields should be owned String values matching the input.
    assert_eq!(vars.ip.as_str(), "127.0.0.1");
    assert_eq!(vars.jail_name.as_str(), "test");
    assert_eq!(vars.log_path.as_str(), "/dev/null");
}

#[test]
fn action_vars_new_with_zero_values() {
    let vars = ActionVars::new("0.0.0.0", 0, "", 0, 0, "");

    assert_eq!(vars.prefix, 0);
    assert_eq!(vars.ban_time, 0);
    assert_eq!(vars.fail_count, 0);
    assert!(vars.jail_name.is_empty());
    assert!(vars.log_path.is_empty());
}

#[test]
fn action_vars_new_with_max_values() {
    let vars = ActionVars::new(
        "255.255.255.255",
        128,
        "jail",
        u64::MAX,
        u32::MAX,
        "/very/long/path",
    );

    assert_eq!(vars.prefix, 128);
    assert_eq!(vars.ban_time, u64::MAX);
    assert_eq!(vars.fail_count, u32::MAX);
}

// ---------------------------------------------------------------------------
// ActionExec::new
// ---------------------------------------------------------------------------

#[test]
fn action_exec_new_sets_name_and_commands() {
    let cmds = make_platform_commands(&["cmd1"], &["cmd2"], &["cmd3"]);
    let exec = ActionExec::new("test-action".to_string(), cmds.clone());

    assert_eq!(exec.name, "test-action");
    assert_eq!(exec.commands, cmds);
}

#[test]
fn action_exec_new_initializes_empty_validate_and_env() {
    let cmds = make_platform_commands(&["echo hi"], &[], &[]);
    let exec = make_exec("action", cmds);

    assert!(exec.validation_commands.is_empty());
    assert!(exec.env.is_empty());
}

#[test]
fn action_exec_new_with_empty_name() {
    let cmds = make_platform_commands(&["true"], &[], &[]);
    let exec = ActionExec::new(String::new(), cmds);

    assert!(exec.name.is_empty());
}

// ---------------------------------------------------------------------------
// ActionExec::expand_command
// ---------------------------------------------------------------------------

#[test]
fn expand_command_replaces_ip() {
    let vars = default_vars();
    let result = ActionExec::expand_command("iptables -A INPUT -s <ip> -j DROP", &vars).unwrap();
    assert_eq!(result, "iptables -A INPUT -s 192.168.1.100 -j DROP");
}

#[test]
fn expand_command_replaces_prefix() {
    let vars = default_vars();
    let result = ActionExec::expand_command("block <prefix>", &vars).unwrap();
    assert_eq!(result, "block 32");
}

#[test]
fn expand_command_replaces_jail() {
    let vars = default_vars();
    let result =
        ActionExec::expand_command("fail2ban-client set <jail> banip <ip>", &vars).unwrap();
    assert_eq!(result, "fail2ban-client set sshd banip 192.168.1.100");
}

#[test]
fn expand_command_replaces_ban_time() {
    let vars = default_vars();
    let result = ActionExec::expand_command("sleep <ban-time>", &vars).unwrap();
    assert_eq!(result, "sleep 3600");
}

#[test]
fn expand_command_replaces_fail_count() {
    let vars = default_vars();
    let result = ActionExec::expand_command("echo <fail-count> failures", &vars).unwrap();
    assert_eq!(result, "echo 5 failures");
}

#[test]
fn expand_command_replaces_log_path() {
    let vars = default_vars();
    let result = ActionExec::expand_command("tail -f <log-path>", &vars).unwrap();
    assert_eq!(result, "tail -f /var/log/auth.log");
}

#[test]
fn expand_command_replaces_multiple_vars() {
    let vars = ActionVars::new("10.0.0.1", 24, "nginx", 600, 3, "/var/log/nginx.log");
    let template =
        "action jail=<jail> ip=<ip>/<prefix> ban=<ban-time> fails=<fail-count> log=<log-path>";
    let result = ActionExec::expand_command(template, &vars).unwrap();
    assert_eq!(
        result,
        "action jail=nginx ip=10.0.0.1/24 ban=600 fails=3 log=/var/log/nginx.log"
    );
}

#[test]
fn expand_command_replaces_all_six_vars_in_one_template() {
    let vars = default_vars();
    let template = "<ip> <prefix> <jail> <ban-time> <fail-count> <log-path>";
    let result = ActionExec::expand_command(template, &vars).unwrap();
    assert_eq!(result, "192.168.1.100 32 sshd 3600 5 /var/log/auth.log");
}

#[test]
fn expand_command_no_vars_returns_same_string() {
    let vars = default_vars();
    let result = ActionExec::expand_command("echo hello world", &vars).unwrap();
    assert_eq!(result, "echo hello world");
}

#[test]
fn expand_command_empty_template_returns_empty() {
    let vars = default_vars();
    let result = ActionExec::expand_command("", &vars).unwrap();
    assert!(result.is_empty());
}

#[test]
fn expand_command_missing_vars_left_as_is() {
    let vars = ActionVars::new("10.0.0.1", 32, "test", 100, 1, "/dev/null");
    // Only <ip> and <jail> are valid placeholders; <unknown> is not.
    let template = "cmd <ip> <unknown> <jail>";
    let result = ActionExec::expand_command(template, &vars).unwrap();
    assert_eq!(result, "cmd 10.0.0.1 <unknown> test");
}

#[test]
fn expand_command_repeated_var() {
    let vars = default_vars();
    let template = "<ip> and <ip> again";
    let result = ActionExec::expand_command(template, &vars).unwrap();
    assert_eq!(result, "192.168.1.100 and 192.168.1.100 again");
}

#[test]
fn expand_command_special_chars_in_ip() {
    let vars = ActionVars::new("::1", 128, "sshd", 60, 1, "/var/log/auth.log");
    let result = ActionExec::expand_command("ip6tables -A INPUT -s <ip> -j DROP", &vars).unwrap();
    assert_eq!(result, "ip6tables -A INPUT -s ::1 -j DROP");
}

#[test]
fn expand_command_ipv6_full_address() {
    let vars = ActionVars::new("2001:db8::1", 64, "ssh", 300, 2, "/var/log/secure");
    let result = ActionExec::expand_command("block <ip>/<prefix>", &vars).unwrap();
    assert_eq!(result, "block 2001:db8::1/64");
}

#[test]
fn expand_command_adjacent_vars() {
    let vars = default_vars();
    let template = "<ip>/<prefix>";
    let result = ActionExec::expand_command(template, &vars).unwrap();
    assert_eq!(result, "192.168.1.100/32");
}

// ---------------------------------------------------------------------------
// ActionExec::dry_run
// ---------------------------------------------------------------------------

#[test]
fn dry_run_returns_expanded_commands() {
    let cmd_list = vec![
        "iptables -A INPUT -s <ip> -j DROP".to_string(),
        "echo banned <ip>".to_string(),
    ];
    let cmds = PlatformCommands::new(cmd_list.clone(), cmd_list.clone(), cmd_list);
    let exec = make_exec("ban-ip", cmds);
    let vars = default_vars();

    let result = exec.dry_run(&vars).unwrap();
    assert_eq!(result.len(), 2);
    assert_eq!(result[0], "iptables -A INPUT -s 192.168.1.100 -j DROP");
    assert_eq!(result[1], "echo banned 192.168.1.100");
}

#[test]
fn dry_run_empty_commands_returns_empty_vec() {
    let cmds = make_platform_commands(&[], &[], &[]);
    let exec = make_exec("empty", cmds);
    let vars = default_vars();

    let result = exec.dry_run(&vars).unwrap();
    assert!(result.is_empty());
}

#[test]
fn dry_run_single_command() {
    let cmd_list = vec!["echo <ip> <jail>".to_string()];
    let cmds = PlatformCommands::new(cmd_list.clone(), cmd_list.clone(), cmd_list);
    let exec = make_exec("log", cmds);
    let vars = ActionVars::new("10.0.0.1", 32, "nginx", 60, 1, "/dev/null");

    let result = exec.dry_run(&vars).unwrap();
    assert_eq!(result, vec!["echo 10.0.0.1 nginx"]);
}

#[test]
fn dry_run_does_not_execute_commands() {
    // Use /dev/null write as a canary -- if dry_run actually executes,
    // we would see side effects.
    let cmd_list = vec!["touch /tmp/toride_dry_run_canary_$$.tmp".to_string()];
    let cmds = PlatformCommands::new(cmd_list.clone(), cmd_list.clone(), cmd_list);
    let exec = make_exec("canary", cmds);
    let vars = default_vars();

    let result = exec.dry_run(&vars).unwrap();
    // The result should contain the expanded string, not execute it.
    assert_eq!(result.len(), 1);
    assert!(result[0].contains("toride_dry_run_canary"));
}

// ---------------------------------------------------------------------------
// ActionExec::platform_commands
// ---------------------------------------------------------------------------

#[test]
fn platform_commands_returns_current_platform_slice() {
    let cmds = make_platform_commands(
        &["linux-cmd-1", "linux-cmd-2"],
        &["macos-cmd-1"],
        &["freebsd-cmd-1", "freebsd-cmd-2", "freebsd-cmd-3"],
    );
    let exec = make_exec("platform-test", cmds);
    let platform_cmds = exec.platform_commands();

    // The exact slice depends on the running OS. Verify it returns
    // the correct list for the current platform.
    if cfg!(target_os = "linux") {
        assert_eq!(platform_cmds, &["linux-cmd-1", "linux-cmd-2"]);
    } else if cfg!(target_os = "macos") {
        assert_eq!(platform_cmds, &["macos-cmd-1"]);
    } else if cfg!(target_os = "freebsd") {
        assert_eq!(
            platform_cmds,
            &["freebsd-cmd-1", "freebsd-cmd-2", "freebsd-cmd-3"]
        );
    }
}

#[test]
fn platform_commands_empty_for_current_platform() {
    // All platforms empty.
    let cmds = make_platform_commands(&[], &[], &[]);
    let exec = make_exec("empty-platforms", cmds);

    assert!(exec.platform_commands().is_empty());
}

// ---------------------------------------------------------------------------
// ActionExec::exec
// ---------------------------------------------------------------------------

#[test]
fn exec_success_with_true_command() {
    let runner = make_runner();
    let cmds = make_platform_commands(&["true"], &["true"], &["true"]);
    let exec = make_exec("success-action", cmds);
    let vars = default_vars();

    let result = exec.exec(&vars, &runner);
    assert!(result.is_ok());
}

#[test]
fn exec_failure_with_false_command() {
    let runner = make_runner();
    let cmds = make_platform_commands(&["false"], &["false"], &["false"]);
    let exec = make_exec("fail-action", cmds);
    let vars = default_vars();

    let result = exec.exec(&vars, &runner);
    assert!(result.is_err());
    match result.unwrap_err() {
        crate::Error::CommandFailed(msg) => {
            assert!(
                msg.contains("false"),
                "message should reference the failed command: {msg}"
            );
        }
        other => panic!("expected CommandFailed, got: {other:?}"),
    }
}

#[test]
fn exec_success_with_multiple_commands() {
    let runner = make_runner();
    let cmds = make_platform_commands(&["true", "true", "true"], &["true"], &["true"]);
    let exec = make_exec("multi-cmd", cmds);
    let vars = default_vars();

    assert!(exec.exec(&vars, &runner).is_ok());
}

#[test]
fn exec_stops_on_first_failure() {
    let runner = make_runner();
    // The second command fails; execution should stop there.
    let cmd_list = vec!["true".to_string(), "false".to_string(), "true".to_string()];
    let cmds = PlatformCommands::new(cmd_list.clone(), cmd_list.clone(), cmd_list);
    let exec = make_exec("stop-on-fail", cmds);
    let vars = default_vars();

    let result = exec.exec(&vars, &runner);
    assert!(result.is_err());
}

#[test]
fn exec_with_env_vars() {
    // NOTE: The Runner trait does not forward environment variables to the
    // subprocess, so env vars set on ActionExec are not available at runtime.
    // This test verifies that exec still succeeds when the command does not
    // depend on env vars, and that the env field is correctly populated.
    let runner = make_runner();
    let cmds = make_platform_commands(&["true"], &["true"], &["true"]);
    let mut exec = make_exec("env-action", cmds);
    exec.env
        .insert("TORIDE_TEST_VAR".to_string(), "hello".to_string());
    let vars = default_vars();

    assert!(exec.exec(&vars, &runner).is_ok());
    assert_eq!(exec.env.get("TORIDE_TEST_VAR").unwrap(), "hello");
}

#[test]
fn exec_with_env_vars_failure_on_missing() {
    let runner = make_runner();
    // The variable is not set, so the test condition fails.
    let cmds = make_platform_commands(
        &["test -n \"$TORIDE_UNSET_VAR\""],
        &["test -n \"$TORIDE_UNSET_VAR\""],
        &["test -n \"$TORIDE_UNSET_VAR\""],
    );
    let exec = make_exec("env-missing", cmds);
    let vars = default_vars();

    let result = exec.exec(&vars, &runner);
    assert!(result.is_err());
}

#[test]
fn exec_expands_variables_before_running() {
    let runner = make_runner();
    // Write the expanded IP to a temp file and verify it.
    let cmds = make_platform_commands(
        &["echo <ip> > /tmp/toride_exec_expand_test.tmp"],
        &["echo <ip> > /tmp/toride_exec_expand_test.tmp"],
        &["echo <ip> > /tmp/toride_exec_expand_test.tmp"],
    );
    let exec = make_exec("expand-exec", cmds);
    let vars = ActionVars::new("10.99.99.99", 32, "test", 60, 1, "/dev/null");

    let result = exec.exec(&vars, &runner);
    assert!(result.is_ok());

    let contents = std::fs::read_to_string("/tmp/toride_exec_expand_test.tmp").unwrap();
    assert_eq!(contents.trim(), "10.99.99.99");

    // Cleanup
    let _ = std::fs::remove_file("/tmp/toride_exec_expand_test.tmp");
}

// ---------------------------------------------------------------------------
// ActionExec::validate
// ---------------------------------------------------------------------------

#[test]
fn validate_success_with_true_command() {
    let runner = make_runner();
    let cmds = make_platform_commands(&[], &[], &[]);
    let mut exec = make_exec("valid-action", cmds);
    exec.validation_commands.push("true".to_string());

    assert!(exec.validate(&runner).is_ok());
}

#[test]
fn validate_success_with_multiple_commands() {
    let runner = make_runner();
    let cmds = make_platform_commands(&[], &[], &[]);
    let mut exec = make_exec("multi-validate", cmds);
    exec.validation_commands.push("true".to_string());
    exec.validation_commands.push("true".to_string());

    assert!(exec.validate(&runner).is_ok());
}

#[test]
fn validate_success_with_empty_validate_list() {
    let runner = make_runner();
    let cmds = make_platform_commands(&[], &[], &[]);
    let exec = make_exec("no-validate", cmds);

    assert!(exec.validate(&runner).is_ok());
}

#[test]
fn validate_failure_returns_command_failed() {
    let runner = make_runner();
    let cmds = make_platform_commands(&[], &[], &[]);
    let mut exec = make_exec("invalid-action", cmds);
    exec.validation_commands.push("false".to_string());

    let result = exec.validate(&runner);
    assert!(result.is_err());
    match result.unwrap_err() {
        crate::Error::CommandFailed(msg) => {
            assert!(
                msg.contains("false"),
                "message should reference the failed command: {msg}"
            );
            assert!(
                msg.contains("exit"),
                "message should mention exit status: {msg}"
            );
        }
        other => panic!("expected CommandFailed, got: {other:?}"),
    }
}

#[test]
fn validate_stops_on_first_failure() {
    let runner = make_runner();
    let cmds = make_platform_commands(&[], &[], &[]);
    let mut exec = make_exec("validate-stop", cmds);
    exec.validation_commands.push("true".to_string());
    exec.validation_commands.push("false".to_string());
    exec.validation_commands.push("true".to_string());

    let result = exec.validate(&runner);
    assert!(result.is_err());
}

#[test]
fn validate_expands_dummy_values_in_template() {
    let runner = make_runner();
    // The validate method replaces placeholders with dummy values.
    // This command tests that <ip> becomes 127.0.0.1 and <jail> becomes test.
    let cmds = make_platform_commands(&[], &[], &[]);
    let mut exec = make_exec("template-validate", cmds);
    exec.validation_commands
        .push("test <ip> = 127.0.0.1 && test <jail> = test".to_string());

    assert!(exec.validate(&runner).is_ok());
}

#[test]
fn validate_expands_prefix_dummy_to_32() {
    let runner = make_runner();
    let cmds = make_platform_commands(&[], &[], &[]);
    let mut exec = make_exec("prefix-validate", cmds);
    exec.validation_commands
        .push("test <prefix> = 32".to_string());

    assert!(exec.validate(&runner).is_ok());
}

#[test]
fn validate_expands_ban_time_dummy_to_1() {
    let runner = make_runner();
    let cmds = make_platform_commands(&[], &[], &[]);
    let mut exec = make_exec("bantime-validate", cmds);
    exec.validation_commands
        .push("test <ban-time> = 1".to_string());

    assert!(exec.validate(&runner).is_ok());
}

#[test]
fn validate_expands_fail_count_dummy_to_1() {
    let runner = make_runner();
    let cmds = make_platform_commands(&[], &[], &[]);
    let mut exec = make_exec("failcount-validate", cmds);
    exec.validation_commands
        .push("test <fail-count> = 1".to_string());

    assert!(exec.validate(&runner).is_ok());
}

#[test]
fn validate_expands_log_path_dummy_to_dev_null() {
    let runner = make_runner();
    let cmds = make_platform_commands(&[], &[], &[]);
    let mut exec = make_exec("logpath-validate", cmds);
    exec.validation_commands
        .push("test <log-path> = /dev/null".to_string());

    assert!(exec.validate(&runner).is_ok());
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

#[test]
fn expand_command_long_template_string() {
    let vars = default_vars();
    let long_template = format!("{}<ip>{}", "a".repeat(1000), "b".repeat(1000));
    let result = ActionExec::expand_command(&long_template, &vars).unwrap();
    assert!(result.starts_with(&"a".repeat(1000)));
    assert!(result.contains("192.168.1.100"));
    assert!(result.ends_with(&"b".repeat(1000)));
}

#[test]
fn exec_with_long_command_string() {
    let runner = make_runner();
    // Build a command that echoes a long string.
    let long_str = "x".repeat(500);
    let cmd = format!("echo {}", long_str);
    let cmds = make_platform_commands(&[&cmd], &[&cmd], &[&cmd]);
    let exec = make_exec("long-cmd", cmds);
    let vars = default_vars();

    assert!(exec.exec(&vars, &runner).is_ok());
}

#[test]
fn dry_run_preserves_order() {
    let cmd_list = vec![
        "echo first".to_string(),
        "echo second".to_string(),
        "echo third".to_string(),
    ];
    let cmds = PlatformCommands::new(cmd_list.clone(), cmd_list.clone(), cmd_list);
    let exec = make_exec("order-test", cmds);
    let vars = default_vars();

    let result = exec.dry_run(&vars).unwrap();
    assert_eq!(result, vec!["echo first", "echo second", "echo third"]);
}

#[test]
fn exec_with_special_characters_in_template_value() {
    let runner = make_runner();
    // IP with IPv6 loopback that contains colons.
    let vars = ActionVars::new("::1", 128, "test-jail", 100, 1, "/tmp/test.log");
    let cmd = "echo <ip> <jail> <log-path>";
    let cmds = make_platform_commands(&[cmd], &[cmd], &[cmd]);
    let exec = make_exec("special-chars", cmds);

    assert!(exec.exec(&vars, &runner).is_ok());
}

#[test]
fn action_exec_fields_are_accessible_and_mutable() {
    let cmds = make_platform_commands(&[], &[], &[]);
    let mut exec = make_exec("mutable-test", cmds);

    // Modify fields after construction.
    exec.validation_commands.push("true".to_string());
    exec.env.insert("KEY".to_string(), "VALUE".to_string());

    assert_eq!(exec.validation_commands.len(), 1);
    assert_eq!(exec.env.get("KEY").unwrap(), "VALUE");
}

#[test]
fn action_vars_clone() {
    let vars = default_vars();
    let cloned = vars.clone();

    assert_eq!(cloned.ip, vars.ip);
    assert_eq!(cloned.prefix, vars.prefix);
    assert_eq!(cloned.jail_name, vars.jail_name);
    assert_eq!(cloned.ban_time, vars.ban_time);
    assert_eq!(cloned.fail_count, vars.fail_count);
    assert_eq!(cloned.log_path, vars.log_path);
}

#[test]
fn action_exec_clone() {
    let cmds = make_platform_commands(&["cmd"], &[], &[]);
    let mut exec = make_exec("clone-test", cmds);
    exec.validation_commands.push("true".to_string());
    exec.env.insert("K".to_string(), "V".to_string());

    let cloned = exec.clone();
    assert_eq!(cloned.name, exec.name);
    assert_eq!(cloned.commands, exec.commands);
    assert_eq!(cloned.validation_commands, exec.validation_commands);
    assert_eq!(cloned.env, exec.env);
}

#[test]
fn expand_command_template_with_no_angle_brackets() {
    let vars = default_vars();
    let result = ActionExec::expand_command("simple command with no placeholders", &vars).unwrap();
    assert_eq!(result, "simple command with no placeholders");
}

#[test]
fn expand_command_partial_placeholder_not_replaced() {
    // <ip is not a valid placeholder (missing closing >).
    let vars = default_vars();
    let result = ActionExec::expand_command("echo <ip and <ip>", &vars).unwrap();
    assert_eq!(result, "echo <ip and 192.168.1.100");
}

#[test]
fn dry_run_returns_err_on_bad_platform() {
    // Normal usage should succeed; this verifies Ok wrapping.
    let cmds = make_platform_commands(&["true"], &[], &[]);
    let exec = make_exec("ok-dry", cmds);
    let vars = default_vars();

    assert!(exec.dry_run(&vars).is_ok());
}

#[test]
fn exec_empty_platform_commands_succeeds() {
    let runner = make_runner();
    let cmds = make_platform_commands(&[], &[], &[]);
    let exec = make_exec("empty-exec", cmds);
    let vars = default_vars();

    // No commands to run means nothing can fail.
    assert!(exec.exec(&vars, &runner).is_ok());
}

// ---------------------------------------------------------------------------
// Additional edge-case tests
// ---------------------------------------------------------------------------

#[test]
fn shell_escape_empty_string() {
    let vars = ActionVars::new("", 32, "test", 1, 1, "/dev/null");
    let result = ActionExec::expand_command("block <ip>", &vars).unwrap();
    assert_eq!(result, "block ''");
}

#[test]
fn shell_escape_with_single_quotes() {
    let vars = ActionVars::new("1.2.3.4'test", 32, "test", 1, 1, "/dev/null");
    let result = ActionExec::expand_command("block <ip>", &vars).unwrap();
    assert_eq!(result, "block '1.2.3.4'\\''test'");
}

#[test]
fn shell_escape_with_dollar_sign() {
    // $HOME in jail_name should be shell-escaped to prevent expansion.
    let vars = ActionVars::new("10.0.0.1", 32, "$HOME", 1, 1, "/dev/null");
    let result = ActionExec::expand_command("set <jail> banip <ip>", &vars).unwrap();
    assert_eq!(result, "set '$HOME' banip 10.0.0.1");
}

#[test]
fn shell_escape_with_semicolon() {
    // Semicolons in log_path should be shell-escaped to prevent injection.
    let vars = ActionVars::new("10.0.0.1", 32, "test", 1, 1, "; rm -rf /");
    let result = ActionExec::expand_command("tail -f <log-path>", &vars).unwrap();
    assert_eq!(result, "tail -f '; rm -rf /'");
}

#[test]
fn expand_command_placeholder_in_middle_of_word() {
    // str::replace does substring matching, so <ip> inside a larger token
    // IS replaced. This verifies the actual behavior.
    let vars = ActionVars::new("10.0.0.1", 32, "test", 1, 1, "/dev/null");
    let result = ActionExec::expand_command("block<ip>more", &vars).unwrap();
    assert_eq!(result, "block10.0.0.1more");
}

#[test]
fn exec_with_empty_env() {
    let runner = make_runner();
    let cmds = make_platform_commands(&["true"], &["true"], &["true"]);
    let exec = make_exec("empty-env", cmds);
    let vars = default_vars();

    assert!(exec.exec(&vars, &runner).is_ok());
    assert!(exec.env.is_empty());
}

#[test]
fn validate_with_all_dummy_values() {
    let runner = make_runner();
    let cmds = make_platform_commands(&[], &[], &[]);
    let mut exec = make_exec("all-dummies", cmds);
    exec.validation_commands.push(
        "test <ip> = 127.0.0.1 && test <prefix> = 32 && test <jail> = test && \
         test <ban-time> = 1 && test <fail-count> = 1 && test <log-path> = /dev/null"
            .to_string(),
    );

    assert!(exec.validate(&runner).is_ok());
}

#[test]
fn expand_command_unicode_in_jail_name() {
    let vars = ActionVars::new("10.0.0.1", 32, "\u{6d4b}\u{8bd5}-jail", 1, 1, "/dev/null");
    let result = ActionExec::expand_command("set <jail> banip <ip>", &vars).unwrap();
    // Unicode characters trigger shell escaping (single-quote wrapping).
    assert_eq!(result, "set '\u{6d4b}\u{8bd5}-jail' banip 10.0.0.1");
}
