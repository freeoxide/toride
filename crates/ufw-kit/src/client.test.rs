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
        .respond_ok("ufw", &["--force", "enable"], "Firewall is active and enabled on system startup\n");
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
    let runner = FakeRunner::new().respond_ok(
        "ufw",
        &["status"],
        "Status: inactive\n",
    );
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

// ---------------------------------------------------------------------------
// Disable
// ---------------------------------------------------------------------------

#[test]
fn disable_should_fail_without_confirmation() {
    let ufw = make_ufw("");
    let opts = DisableOptions {
        require_explicit_confirmation: true,
    };
    let result = ufw.disable(&opts);
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        Error::DisableRequiresConfirmation
    ));
}

#[test]
fn disable_should_succeed_with_confirmation() {
    let runner = FakeRunner::new().respond_ok("ufw", &["disable"], "Firewall stopped and disabled on system startup\n");
    let ufw = Ufw::with_runner(runner);
    let opts = DisableOptions {
        require_explicit_confirmation: false,
    };
    assert!(ufw.disable(&opts).is_ok());
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
    let runner = FakeRunner::new().respond_ok("ufw", &["--force", "reset"], "Resetting all rules\n");
    let ufw = Ufw::with_runner(runner);
    let opts = ResetOptions {
        force: true,
        backup_first: true,
    };
    assert!(ufw.reset(&opts).is_ok());
}

// ---------------------------------------------------------------------------
// Set default policy
// ---------------------------------------------------------------------------

#[test]
fn set_default_policy_should_call_ufw() {
    let runner = FakeRunner::new().respond_ok("ufw", &["default", "in", "deny"], "Default incoming policy changed\n");
    let ufw = Ufw::with_runner(runner);
    assert!(ufw.set_default_policy(Direction::In, Policy::Deny).is_ok());
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
    let runner = FakeRunner::new().respond_ok("ufw", &["show", "listening"], "tcp  0.0.0.0:22  0.0.0.0:*  sshd\n");
    let ufw = Ufw::with_runner(runner);
    let output = ufw.show(UfwReport::Listening).unwrap();
    assert!(output.contains("sshd"));
}

// ---------------------------------------------------------------------------
// App operations
// ---------------------------------------------------------------------------

#[test]
fn app_list_should_return_output() {
    let runner = FakeRunner::new().respond_ok("ufw", &["app", "list"], "Available applications:\n  OpenSSH\n");
    let ufw = Ufw::with_runner(runner);
    let list = ufw.app_list().unwrap();
    assert!(list.contains("OpenSSH"));
}

#[test]
fn app_info_should_return_output() {
    let runner = FakeRunner::new().respond_ok("ufw", &["app", "info", "OpenSSH"], "Profile: OpenSSH\nPorts: 22/tcp\n");
    let ufw = Ufw::with_runner(runner);
    let info = ufw.app_info("OpenSSH").unwrap();
    assert!(info.contains("OpenSSH"));
}

// ---------------------------------------------------------------------------
// Edge-case tests
// ---------------------------------------------------------------------------

#[test]
fn find_ufw_should_error_when_not_found() {
    struct NoBinaryRunner;
    impl CommandRunner for NoBinaryRunner {
        fn run(&self, _: &CommandSpec) -> Result<CommandResult> {
            unimplemented!()
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
    let runner = FakeRunner::new().respond_ok("ufw", &["app", "default", "skip"], "Default application policy changed\n");
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
    let runner = FakeRunner::new()
        .respond_ok("ufw", &[], "Rules updated\n");
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
