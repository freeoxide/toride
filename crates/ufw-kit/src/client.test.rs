use super::*;
use crate::command::FakeRunner;
use crate::spec::*;

fn make_ufw(stdout: &str) -> Ufw {
    let runner = FakeRunner::new().respond_ok("ufw", &[], stdout);
    Ufw::with_runner(runner)
}

fn make_ufw_with_status(status_output: &str) -> Ufw {
    let runner = FakeRunner::new().respond_ok("ufw", &["status"], status_output);
    Ufw::with_runner(runner)
}

fn make_ufw_with_verbose(verbose_output: &str) -> Ufw {
    let runner = FakeRunner::new()
        .respond_ok("ufw", &["status"], "Status: active\n")
        .respond_ok("ufw", &["status", "verbose"], verbose_output);
    Ufw::with_runner(runner)
}

// ---------------------------------------------------------------------------
// Version
// ---------------------------------------------------------------------------

#[test]
fn version_should_return_version_string() {
    let ufw = make_ufw("ufw 0.36.1\n");
    let ver = ufw.version().unwrap();
    assert_eq!(ver, "ufw 0.36.1");
}

// ---------------------------------------------------------------------------
// Status
// ---------------------------------------------------------------------------

#[test]
fn status_should_parse_active() {
    let ufw = make_ufw_with_status("Status: active\n");
    let status = ufw.status().unwrap();
    assert!(status.active);
}

#[test]
fn status_should_parse_inactive() {
    let ufw = make_ufw_with_status("Status: inactive\n");
    let status = ufw.status().unwrap();
    assert!(!status.active);
}

// ---------------------------------------------------------------------------
// Status verbose
// ---------------------------------------------------------------------------

#[test]
fn status_verbose_should_parse_defaults() {
    let output = "\
Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing)
";
    let ufw = make_ufw_with_verbose(output);
    let status = ufw.status_verbose().unwrap();
    assert!(status.active);
    assert_eq!(status.default_incoming, Some(Policy::Deny));
    assert_eq!(status.logging_level, Some(LoggingLevel::Low));
}

// ---------------------------------------------------------------------------
// Enable
// ---------------------------------------------------------------------------

#[test]
fn enable_should_succeed_when_already_active() {
    let runner = FakeRunner::new().respond_ok("ufw", &["status"], "Status: active\n");
    let ufw = Ufw::with_runner(runner);
    let opts = EnableOptions::default();
    assert!(ufw.enable(&opts).is_ok());
}

#[test]
fn enable_should_succeed_with_allow_force() {
    let runner = FakeRunner::new()
        .respond_ok("ufw", &["status"], "Status: inactive\n")
        .respond_ok(
            "ufw",
            &["--force", "enable"],
            "Firewall is active and enabled on system startup\n",
        );
    let ufw = Ufw::with_runner(runner);
    let opts = EnableOptions {
        require_ssh_allow_rule: false,
        allow_force: true,
        ..Default::default()
    };
    assert!(ufw.enable(&opts).is_ok());
}

#[test]
fn enable_should_fail_on_ssh_lockout() {
    let runner = FakeRunner::new().respond_ok("ufw", &["status"], "Status: inactive\n");
    let ufw = Ufw::with_runner(runner);
    let opts = EnableOptions {
        require_ssh_allow_rule: true,
        allow_force: false,
        ..Default::default()
    };
    let result = ufw.enable(&opts);
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), Error::SshLockoutRisk(_)));
}

#[test]
fn enable_should_pass_when_ssh_rule_exists() {
    let runner = FakeRunner::new()
        .respond_ok(
            "ufw",
            &["status"],
            "Status: inactive\n\nTo                         Action      From\n--                         ------      ----\n22/tcp                     ALLOW       Anywhere\n",
        )
        .respond_ok("ufw", &["enable"], "Firewall is active\n");
    let ufw = Ufw::with_runner(runner);
    let opts = EnableOptions {
        require_ssh_allow_rule: true,
        allow_force: false,
        ..Default::default()
    };
    assert!(ufw.enable(&opts).is_ok());
}

#[test]
fn force_enable_should_succeed_when_inactive() {
    // force_enable() must STILL perform the SSH lockout safety check, so we
    // provide an incoming SSH allow rule in the status output.
    let runner = FakeRunner::new()
        .respond_ok(
            "ufw",
            &["status"],
            "Status: inactive\n\nTo                         Action      From\n--                         ------      ----\n22/tcp                     ALLOW       Anywhere\n",
        )
        .respond_ok(
            "ufw",
            &["--force", "enable"],
            "Firewall is active and enabled on system startup\n",
        );
    let ufw = Ufw::with_runner(runner);
    assert!(ufw.force_enable().is_ok());
}

#[test]
fn force_enable_should_succeed_when_already_active() {
    let runner = FakeRunner::new().respond_ok("ufw", &["status"], "Status: active\n");
    let ufw = Ufw::with_runner(runner);
    assert!(ufw.force_enable().is_ok());
}

#[test]
fn force_enable_should_still_trigger_lockout_check() {
    // Regression: force_enable() must NOT bypass the SSH lockout check.
    // With no incoming SSH allow rule, it must fail with SshLockoutRisk even
    // though allow_force is true (the --force flag only skips UFW's
    // interactive prompt, not this library's lockout protection).
    let runner = FakeRunner::new().respond_ok("ufw", &["status"], "Status: inactive\n");
    let ufw = Ufw::with_runner(runner);
    let result = ufw.force_enable();
    assert!(result.is_err());
    assert!(
        matches!(result.unwrap_err(), Error::SshLockoutRisk(_)),
        "force_enable() must still perform the SSH lockout check"
    );
}

// ---------------------------------------------------------------------------
// Disable
// ---------------------------------------------------------------------------

#[test]
fn disable_should_fail_without_confirmation() {
    let ufw = make_ufw("");
    let opts = DisableOptions {
        require_explicit_confirmation: false,
    };
    let result = ufw.disable(&opts);
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        Error::Validation(msg) if msg.contains("explicit confirmation")
    ));
}

#[test]
fn disable_should_succeed_with_confirmation() {
    let runner = FakeRunner::new().respond_ok(
        "ufw",
        &["disable"],
        "Firewall stopped and disabled on system startup\n",
    );
    let ufw = Ufw::with_runner(runner);
    let opts = DisableOptions {
        require_explicit_confirmation: true,
    };
    assert!(ufw.disable(&opts).is_ok());
}

#[test]
fn disable_should_fail_with_default_options() {
    let ufw = make_ufw("");
    let opts = DisableOptions::default();
    let result = ufw.disable(&opts);
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// Reset
// ---------------------------------------------------------------------------

#[test]
fn reset_should_fail_without_force() {
    let ufw = make_ufw("");
    let opts = ResetOptions {
        force: false,
        backup_first: true,
    };
    let result = ufw.reset(&opts);
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), Error::ResetRequiresForce));
}

#[test]
fn reset_should_succeed_with_force() {
    let runner =
        FakeRunner::new().respond_ok("ufw", &["--force", "reset"], "Resetting all rules\n");
    let ufw = Ufw::with_runner(runner);
    // backup_first disabled here so the test is hermetic: reset() backs up via
    // UfwPaths::default() (real /etc/ufw), whose root-owned files are unreadable
    // by a non-root test process. Backup behaviour itself is covered in
    // backup.test.rs against temp paths.
    let opts = ResetOptions {
        force: true,
        backup_first: false,
    };
    let result = ufw.reset(&opts);
    assert!(
        result.is_ok(),
        "reset with force failed: {:?}",
        result.err()
    );
}

// ---------------------------------------------------------------------------
// Set default policy
// ---------------------------------------------------------------------------

#[test]
fn set_default_policy_should_call_ufw() {
    let runner = FakeRunner::new()
        .respond_ok("ufw", &["status"], "Status: active\n\nTo                         Action      From\n--                         ------      ----\n22/tcp                     ALLOW       Anywhere\n")
        .respond_ok("ufw", &["default", "in", "deny"], "Default incoming policy changed\n");
    let ufw = Ufw::with_runner(runner);
    assert!(ufw.set_default_policy(Direction::In, Policy::Deny).is_ok());
}

#[test]
fn set_default_policy_should_reject_deny_incoming_without_ssh() {
    let runner = FakeRunner::new()
        .respond_ok("ufw", &["status"], "Status: active\n\nTo                         Action      From\n--                         ------      ----\n443/tcp                     ALLOW       Anywhere\n");
    let ufw = Ufw::with_runner(runner);
    let result = ufw.set_default_policy(Direction::In, Policy::Deny);
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), Error::SshLockoutRisk(_)));
}

#[test]
fn set_default_policy_should_reject_reject_incoming_without_ssh() {
    let runner = FakeRunner::new()
        .respond_ok("ufw", &["status"], "Status: active\n\nTo                         Action      From\n--                         ------      ----\n443/tcp                     ALLOW       Anywhere\n");
    let ufw = Ufw::with_runner(runner);
    let result = ufw.set_default_policy(Direction::In, Policy::Reject);
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), Error::SshLockoutRisk(_)));
}

#[test]
fn set_default_policy_should_allow_deny_outgoing_without_ssh_check() {
    let runner = FakeRunner::new().respond_ok(
        "ufw",
        &["default", "out", "deny"],
        "Default outgoing policy changed\n",
    );
    let ufw = Ufw::with_runner(runner);
    assert!(ufw.set_default_policy(Direction::Out, Policy::Deny).is_ok());
}

#[test]
fn set_default_policy_should_allow_allow_incoming_without_ssh_check() {
    let runner = FakeRunner::new().respond_ok(
        "ufw",
        &["default", "in", "allow"],
        "Default incoming policy changed\n",
    );
    let ufw = Ufw::with_runner(runner);
    assert!(ufw.set_default_policy(Direction::In, Policy::Allow).is_ok());
}

// ---------------------------------------------------------------------------
// Set logging
// ---------------------------------------------------------------------------

#[test]
fn set_logging_should_call_ufw() {
    let runner = FakeRunner::new().respond_ok("ufw", &["logging", "low"], "Logging enabled\n");
    let ufw = Ufw::with_runner(runner);
    assert!(ufw.set_logging(LoggingLevel::Low).is_ok());
}

// ---------------------------------------------------------------------------
// Add rule
// ---------------------------------------------------------------------------

#[test]
fn add_rule_should_call_ufw() {
    let runner = FakeRunner::new().respond_ok("ufw", &[], "Rule added\n");
    let ufw = Ufw::with_runner(runner);
    let spec = RuleSpec::builder(Action::Allow)
        .to_port(443)
        .proto(Protocol::Tcp)
        .build()
        .unwrap();
    assert!(ufw.add_rule(&spec).is_ok());
}

// ---------------------------------------------------------------------------
// Delete rule
// ---------------------------------------------------------------------------

#[test]
fn delete_rule_should_call_ufw() {
    let runner = FakeRunner::new().respond_ok("ufw", &[], "Rule deleted\n");
    let ufw = Ufw::with_runner(runner);
    let spec = RuleSpec::builder(Action::Allow)
        .to_port(443)
        .proto(Protocol::Tcp)
        .build()
        .unwrap();
    assert!(ufw.delete_rule(&spec).is_ok());
}

#[test]
fn delete_rule_number_should_fail_without_opt_in() {
    let ufw = make_ufw("");
    let opts = DeleteOptions {
        allow_numbered_delete: false,
    };
    let result = ufw.delete_rule_number(1, &opts);
    assert!(result.is_err());
}

#[test]
fn delete_rule_number_should_succeed_with_opt_in() {
    let runner = FakeRunner::new().respond_ok("ufw", &["delete", "1"], "Rule deleted\n");
    let ufw = Ufw::with_runner(runner);
    let opts = DeleteOptions {
        allow_numbered_delete: true,
    };
    assert!(ufw.delete_rule_number(1, &opts).is_ok());
}

// ---------------------------------------------------------------------------
// Reload
// ---------------------------------------------------------------------------

#[test]
fn reload_should_call_ufw() {
    let runner = FakeRunner::new().respond_ok("ufw", &["reload"], "Reloaded\n");
    let ufw = Ufw::with_runner(runner);
    assert!(ufw.reload().is_ok());
}

// ---------------------------------------------------------------------------
// Show report
// ---------------------------------------------------------------------------

#[test]
fn show_should_return_report_output() {
    let runner = FakeRunner::new().respond_ok(
        "ufw",
        &["show", "listening"],
        "tcp  0.0.0.0:22  0.0.0.0:*  sshd\n",
    );
    let ufw = Ufw::with_runner(runner);
    let output = ufw.show(UfwReport::Listening).unwrap();
    assert!(output.contains("sshd"));
}

// ---------------------------------------------------------------------------
// App operations
// ---------------------------------------------------------------------------

#[test]
fn app_list_should_return_output() {
    let runner = FakeRunner::new().respond_ok(
        "ufw",
        &["app", "list"],
        "Available applications:\n  OpenSSH\n",
    );
    let ufw = Ufw::with_runner(runner);
    let list = ufw.app_list().unwrap();
    assert!(list.contains("OpenSSH"));
}

#[test]
fn app_info_should_return_output() {
    let runner = FakeRunner::new().respond_ok(
        "ufw",
        &["app", "info", "OpenSSH"],
        "Profile: OpenSSH\nPorts: 22/tcp\n",
    );
    let ufw = Ufw::with_runner(runner);
    let info = ufw.app_info("OpenSSH").unwrap();
    assert!(info.contains("OpenSSH"));
}

#[test]
fn app_update_all_should_call_ufw() {
    let runner = FakeRunner::new().respond_ok(
        "ufw",
        &["app", "update", "all"],
        "Updated all application profiles\n",
    );
    let ufw = Ufw::with_runner(runner);
    assert!(ufw.app_update_all().is_ok());
}

// ---------------------------------------------------------------------------
// Edge-case tests
// ---------------------------------------------------------------------------

#[test]
fn find_ufw_should_error_when_not_found() {
    struct NoBinaryRunner;
    impl CommandRunner for NoBinaryRunner {
        fn run(&self, _: &CommandSpec) -> Result<CommandResult> {
            panic!("NoBinaryRunner::run should not be called")
        }
        fn binary_exists(&self, _: &str) -> bool {
            false
        }
    }

    let ufw = Ufw::with_runner(NoBinaryRunner);
    assert!(ufw.find_ufw().is_err());
}

// ---------------------------------------------------------------------------
// Weird edge-case tests
// ---------------------------------------------------------------------------

#[test]
fn enable_should_handle_stderr_gracefully() {
    let runner = FakeRunner::new()
        .respond_ok("ufw", &["status"], "Status: inactive\n")
        .respond_err("ufw", &["enable"], "ERROR: Could not enable firewall", 1);
    let ufw = Ufw::with_runner(runner);
    let opts = EnableOptions {
        require_ssh_allow_rule: false,
        allow_force: false,
        ..Default::default()
    };
    let result = ufw.enable(&opts);
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// Production-grade weird edge cases
// ---------------------------------------------------------------------------

#[test]
fn add_route_rule_should_call_ufw() {
    let runner = FakeRunner::new().respond_ok("ufw", &[], "Rule added\n");
    let ufw = Ufw::with_runner(runner);
    let spec = RouteRuleSpec::builder(Action::Allow)
        .in_interface("eth0")
        .out_interface("eth1")
        .build()
        .unwrap();
    assert!(ufw.add_route_rule(&spec).is_ok());
}

#[test]
fn delete_route_rule_should_call_ufw() {
    let runner = FakeRunner::new().respond_ok("ufw", &[], "Rule deleted\n");
    let ufw = Ufw::with_runner(runner);
    let spec = RouteRuleSpec::builder(Action::Allow)
        .in_interface("eth0")
        .out_interface("eth1")
        .build()
        .unwrap();
    assert!(ufw.delete_route_rule(&spec).is_ok());
}

#[test]
fn app_default_should_call_ufw() {
    let runner = FakeRunner::new().respond_ok(
        "ufw",
        &["app", "default", "skip"],
        "Default application policy changed\n",
    );
    let ufw = Ufw::with_runner(runner);
    assert!(ufw.app_default(AppDefaultPolicy::Skip).is_ok());
}

// ---------------------------------------------------------------------------
// Dry-run tests
// ---------------------------------------------------------------------------

#[test]
fn dry_run_should_return_output() {
    let runner = FakeRunner::new().respond_ok("ufw", &[], "Dry run output\n");
    let ufw = Ufw::with_runner(runner);
    let output = ufw.dry_run(&["allow", "443/tcp"]).unwrap();
    assert!(output.contains("Dry run"));
}

#[test]
fn dry_run_should_fail_on_error() {
    let runner = FakeRunner::new().respond_err("ufw", &[], "ERROR: invalid rule", 1);
    let ufw = Ufw::with_runner(runner);
    let result = ufw.dry_run(&["invalid"]);
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// apply_rule tests
// ---------------------------------------------------------------------------

#[test]
fn apply_rule_should_dry_run_then_execute() {
    let runner = FakeRunner::new().respond_ok("ufw", &[], "Rules updated\n");
    let ufw = Ufw::with_runner(runner);
    let spec = RuleSpec::builder(Action::Allow)
        .to_port(443)
        .proto(Protocol::Tcp)
        .build()
        .unwrap();
    let report = ufw.apply_rule(&spec).unwrap();
    assert!(report.success);
    assert!(report.dry_run_output.is_some());
}

// ---------------------------------------------------------------------------
// ensure_rule tests
// ---------------------------------------------------------------------------

#[test]
fn ensure_rule_should_add_when_no_existing() {
    let runner = FakeRunner::new()
        .respond_ok("ufw", &["status", "numbered"], "Status: active\n\nTo                         Action      From\n--                         ------      ----\n")
        .respond_ok("ufw", &[], "Rule added\n");
    let ufw = Ufw::with_runner(runner);
    let spec = RuleSpec::builder(Action::Allow)
        .to_port(443)
        .proto(Protocol::Tcp)
        .comment("managed:https")
        .build()
        .unwrap();
    let report = ufw.ensure_rule(&spec).unwrap();
    assert!(report.success);
    assert!(report.action.contains("add rule"));
}

#[test]
fn ensure_rule_should_skip_when_comment_exists() {
    let runner = FakeRunner::new()
        .respond_ok("ufw", &["status", "numbered"], "Status: active\n\nTo                         Action      From\n--                         ------      ----\n[ 1] 443/tcp ALLOW IN Anywhere comment managed:https\n");
    let ufw = Ufw::with_runner(runner);
    let spec = RuleSpec::builder(Action::Allow)
        .to_port(443)
        .proto(Protocol::Tcp)
        .comment("managed:https")
        .build()
        .unwrap();
    let report = ufw.ensure_rule(&spec).unwrap();
    assert!(report.success);
    assert!(report.action.contains("already exists"));
}

#[test]
fn ensure_rule_should_add_when_no_comment() {
    let runner = FakeRunner::new().respond_ok("ufw", &[], "Rule added\n");
    let ufw = Ufw::with_runner(runner);
    let spec = RuleSpec::builder(Action::Allow)
        .to_port(443)
        .proto(Protocol::Tcp)
        .build()
        .unwrap();
    let report = ufw.ensure_rule(&spec).unwrap();
    assert!(report.success);
}

#[test]
fn ensure_rule_should_replace_when_comment_matches_but_rule_differs() {
    // Existing rule allows port 80 with comment "managed:web",
    // but we want port 443. Should delete old and add new.
    let runner = FakeRunner::new()
        // status numbered — one existing rule with port 80
        .respond_ok("ufw", &["status", "numbered"],
            "Status: active\n\nTo                         Action      From\n--                         ------      ----\n[ 1] 80/tcp ALLOW IN Anywhere comment managed:web\n")
        // delete rule 1
        .respond_ok("ufw", &["delete", "1"], "Deleting:\n allow 80/tcp\nRule deleted\n")
        // dry-run + add new rule
        .respond_ok("ufw", &[], "Rule added\n");
    let ufw = Ufw::with_runner(runner);
    let spec = RuleSpec::builder(Action::Allow)
        .to_port(443)
        .proto(Protocol::Tcp)
        .comment("managed:web")
        .build()
        .unwrap();
    let report = ufw.ensure_rule(&spec).unwrap();
    assert!(report.success);
    assert!(report.action.contains("replaced rule"));
}

// ---------------------------------------------------------------------------
// delete_rules_by_comment tests
// ---------------------------------------------------------------------------

#[test]
fn delete_rules_by_comment_should_delete_matching_rules_bottom_to_top() {
    // Three rules, two with comment "managed:staging"
    let runner = FakeRunner::new()
        .respond_ok("ufw", &["status", "numbered"],
            "Status: active\n\nTo                         Action      From\n--                         ------      ----\n\
             [ 1] 22/tcp ALLOW IN Anywhere comment managed:ssh\n\
             [ 2] 80/tcp ALLOW IN Anywhere comment managed:staging\n\
             [ 3] 443/tcp ALLOW IN Anywhere comment managed:staging\n")
        // Delete rule 3 first (highest number)
        .respond_ok("ufw", &["delete", "3"], "Deleting:\n allow 443/tcp\nRule deleted\n")
        // Then delete rule 2
        .respond_ok("ufw", &["delete", "2"], "Deleting:\n allow 80/tcp\nRule deleted\n");
    let ufw = Ufw::with_runner(runner);
    let count = ufw.delete_rules_by_comment("managed:staging").unwrap();
    assert_eq!(count, 2);
}

#[test]
fn delete_rules_by_comment_should_return_zero_when_no_matches() {
    let runner = FakeRunner::new()
        .respond_ok("ufw", &["status", "numbered"],
            "Status: active\n\nTo                         Action      From\n--                         ------      ----\n\
             [ 1] 22/tcp ALLOW IN Anywhere comment managed:ssh\n");
    let ufw = Ufw::with_runner(runner);
    let count = ufw.delete_rules_by_comment("managed:nonexistent").unwrap();
    assert_eq!(count, 0);
}

// ---------------------------------------------------------------------------
// check_ssh_lockout_structured tests
// ---------------------------------------------------------------------------

#[test]
fn check_ssh_structured_should_find_incoming_ssh_allow() {
    let runner = FakeRunner::new()
        .respond_ok("ufw", &["status"], "Status: active\n\nTo                         Action      From\n--                         ------      ----\n22/tcp                     ALLOW       Anywhere\n");
    let ufw = Ufw::with_runner(runner);
    let result = ufw.check_ssh_lockout_structured(&[22]);
    assert!(result.has_incoming_ssh_allow);
    assert_eq!(result.matching_rules.len(), 1);
    assert_eq!(result.checked_ports, vec![22]);
}

#[test]
fn check_ssh_structured_should_not_match_outgoing_ssh() {
    let runner = FakeRunner::new()
        .respond_ok("ufw", &["status"], "Status: active\n\nTo                         Action      From\n--                         ------      ----\n22/tcp                     ALLOW OUT   Anywhere\n");
    let ufw = Ufw::with_runner(runner);
    let result = ufw.check_ssh_lockout_structured(&[22]);
    // OUT direction should not count as incoming SSH
    assert!(!result.has_incoming_ssh_allow);
}

#[test]
fn check_ssh_structured_should_match_limit_action() {
    let runner = FakeRunner::new()
        .respond_ok("ufw", &["status"], "Status: active\n\nTo                         Action      From\n--                         ------      ----\n22/tcp                     LIMIT       Anywhere\n");
    let ufw = Ufw::with_runner(runner);
    let result = ufw.check_ssh_lockout_structured(&[22]);
    assert!(result.has_incoming_ssh_allow);
}

#[test]
fn check_ssh_structured_should_match_ssh_service_name() {
    let runner = FakeRunner::new()
        .respond_ok("ufw", &["status"], "Status: active\n\nTo                         Action      From\n--                         ------      ----\nssh                        ALLOW       Anywhere\n");
    let ufw = Ufw::with_runner(runner);
    let result = ufw.check_ssh_lockout_structured(&[22]);
    assert!(result.has_incoming_ssh_allow);
}

#[test]
fn check_ssh_structured_should_not_match_deny_action() {
    let runner = FakeRunner::new()
        .respond_ok("ufw", &["status"], "Status: active\n\nTo                         Action      From\n--                         ------      ----\n22/tcp                     DENY        Anywhere\n");
    let ufw = Ufw::with_runner(runner);
    let result = ufw.check_ssh_lockout_structured(&[22]);
    assert!(!result.has_incoming_ssh_allow);
}

#[test]
fn check_ssh_structured_should_detect_interface_scope() {
    let runner = FakeRunner::new()
        .respond_ok("ufw", &["status"], "Status: active\n\nTo                         Action      From\n--                         ------      ----\n22/tcp on eth0             ALLOW       Anywhere\n");
    let ufw = Ufw::with_runner(runner);
    let result = ufw.check_ssh_lockout_structured(&[22]);
    assert!(result.has_incoming_ssh_allow);
    assert!(result.interface_scoped);
}

#[test]
fn check_ssh_structured_should_return_empty_on_status_failure() {
    struct FailRunner;
    impl CommandRunner for FailRunner {
        fn run(&self, _: &CommandSpec) -> Result<CommandResult> {
            Err(Error::UfwNotFound("not found".into()))
        }
        fn binary_exists(&self, _: &str) -> bool {
            false
        }
    }
    let ufw = Ufw::with_runner(FailRunner);
    let result = ufw.check_ssh_lockout_structured(&[22]);
    assert!(!result.has_incoming_ssh_allow);
    assert!(result.matching_rules.is_empty());
    assert_eq!(result.checked_ports, vec![22]);
}

// ---------------------------------------------------------------------------
// insert_rule tests
// ---------------------------------------------------------------------------

#[test]
fn insert_rule_should_call_ufw_with_insert_position() {
    let runner = FakeRunner::new().respond_ok("ufw", &[], "Rule inserted\n");
    let ufw = Ufw::with_runner(runner);
    let spec = RuleSpec::builder(Action::Allow)
        .to_port(80)
        .proto(Protocol::Tcp)
        .build()
        .unwrap();
    assert!(ufw.insert_rule(1, &spec).is_ok());
}

#[test]
fn insert_rule_should_set_position_to_insert_n() {
    let runner = FakeRunner::new().respond_ok("ufw", &[], "Rule inserted\n");
    let ufw = Ufw::with_runner(runner);
    let spec = RuleSpec::builder(Action::Allow)
        .to_port(443)
        .proto(Protocol::Tcp)
        .build()
        .unwrap();
    assert!(ufw.insert_rule(3, &spec).is_ok());
}

// ---------------------------------------------------------------------------
// app_update tests
// ---------------------------------------------------------------------------

#[test]
fn app_update_should_call_ufw_with_app_update_name() {
    let runner =
        FakeRunner::new().respond_ok("ufw", &["app", "update", "OpenSSH"], "Profile updated\n");
    let ufw = Ufw::with_runner(runner);
    assert!(ufw.app_update("OpenSSH").is_ok());
}

#[test]
fn app_update_should_fail_on_error() {
    let runner = FakeRunner::new().respond_err(
        "ufw",
        &["app", "update", "NonExistent"],
        "ERROR: profile not found",
        1,
    );
    let ufw = Ufw::with_runner(runner);
    assert!(ufw.app_update("NonExistent").is_err());
}

// ---------------------------------------------------------------------------
// status_numbered tests
// ---------------------------------------------------------------------------

#[test]
fn status_numbered_should_parse_numbered_output() {
    let output = "Status: active\n\nTo                         Action      From\n--                         ------      ----\n[ 1] 22/tcp                     ALLOW IN    Anywhere\n[ 2] 443/tcp                    ALLOW IN    Anywhere\n";
    let runner = FakeRunner::new().respond_ok("ufw", &["status", "numbered"], output);
    let ufw = Ufw::with_runner(runner);
    let status = ufw.status_numbered().unwrap();
    assert!(status.active);
    assert_eq!(status.rules.len(), 2);
    assert_eq!(status.rules[0].number, Some(1));
    assert_eq!(status.rules[1].number, Some(2));
}

#[test]
fn status_numbered_should_parse_empty_numbered_output() {
    let output = "Status: active\n\nTo                         Action      From\n--                         ------      ----\n";
    let runner = FakeRunner::new().respond_ok("ufw", &["status", "numbered"], output);
    let ufw = Ufw::with_runner(runner);
    let status = ufw.status_numbered().unwrap();
    assert!(status.active);
    assert!(status.rules.is_empty());
}
