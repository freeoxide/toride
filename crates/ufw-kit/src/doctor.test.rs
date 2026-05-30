use super::*;
use crate::command::FakeRunner;
use crate::spec::*;

fn make_ufw_for_doctor(status_output: &str) -> Ufw {
    let runner = FakeRunner::new()
        .respond_ok("ufw", &["--version"], "ufw 0.36.1")
        .respond_ok("ufw", &["status"], status_output)
        .respond_ok(
            "ufw",
            &["status", "verbose"],
            &format!("{status_output}\nLogging: on (low)\nDefault: deny (incoming), allow (outgoing)\n"),
        )
        .respond_ok("ufw", &["app", "list"], "Available applications:\n  OpenSSH\n");
    Ufw::with_runner(runner)
}

// ---------------------------------------------------------------------------
// Binary checks
// ---------------------------------------------------------------------------

#[test]
fn check_binaries_should_find_ufw() {
    let ufw = make_ufw_for_doctor("Status: active\n");
    let findings = check_binaries(&ufw);
    assert!(findings.iter().any(|f| f.id == "bin:ufw:exists"));
}

#[test]
fn check_binaries_should_report_version() {
    let ufw = make_ufw_for_doctor("Status: active\n");
    let findings = check_binaries(&ufw);
    assert!(findings.iter().any(|f| f.id == "bin:ufw:version"));
}

// ---------------------------------------------------------------------------
// Service checks
// ---------------------------------------------------------------------------

#[test]
fn check_service_should_detect_active() {
    let ufw = make_ufw_for_doctor("Status: active\n");
    let findings = check_service(&ufw);
    assert!(findings.iter().any(|f| f.id == "svc:ufw:active"));
}

#[test]
fn check_service_should_detect_inactive() {
    let ufw = make_ufw_for_doctor("Status: inactive\n");
    let findings = check_service(&ufw);
    assert!(findings.iter().any(|f| f.id == "svc:ufw:inactive"));
}

// ---------------------------------------------------------------------------
// Policy checks
// ---------------------------------------------------------------------------

#[test]
fn check_policy_should_warn_on_incoming_allow() {
    let output = "Status: active\nDefault: allow (incoming), allow (outgoing)\nLogging: on\n";
    let runner = FakeRunner::new()
        .respond_ok("ufw", &["--version"], "ufw 0.36.1")
        .respond_ok("ufw", &["status"], "Status: active\n")
        .respond_ok("ufw", &["status", "verbose"], output)
        .respond_ok("ufw", &["app", "list"], "");
    let ufw = Ufw::with_runner(runner);
    let findings = check_policy(&ufw);
    assert!(findings.iter().any(|f| f.id == "pol:incoming:allow"));
}

#[test]
fn check_policy_should_be_ok_on_incoming_deny() {
    let output = "Status: active\nDefault: deny (incoming), allow (outgoing)\nLogging: on\n";
    let runner = FakeRunner::new()
        .respond_ok("ufw", &["--version"], "ufw 0.36.1")
        .respond_ok("ufw", &["status"], "Status: active\n")
        .respond_ok("ufw", &["status", "verbose"], output)
        .respond_ok("ufw", &["app", "list"], "");
    let ufw = Ufw::with_runner(runner);
    let findings = check_policy(&ufw);
    assert!(findings.iter().any(|f| f.id == "pol:incoming:deny"));
}

// ---------------------------------------------------------------------------
// SSH checks
// ---------------------------------------------------------------------------

#[test]
fn check_ssh_should_warn_when_no_ssh_rule() {
    let ufw = make_ufw_for_doctor(
        "Status: active\n\nTo                         Action      From\n--                         ------      ----\n443/tcp                    ALLOW       Anywhere\n",
    );
    let findings = check_ssh(&ufw);
    assert!(findings.iter().any(|f| f.id == "ssh:no-rule"));
}

#[test]
fn check_ssh_should_be_ok_when_ssh_rule_exists() {
    let ufw = make_ufw_for_doctor(
        "Status: active\n\nTo                         Action      From\n--                         ------      ----\n22/tcp                     ALLOW       Anywhere\n",
    );
    let findings = check_ssh(&ufw);
    assert!(findings.iter().any(|f| f.id == "ssh:allowed"));
}

// ---------------------------------------------------------------------------
// App profile checks
// ---------------------------------------------------------------------------

#[test]
fn check_app_profiles_should_report_installed() {
    let ufw = make_ufw_for_doctor("Status: active\n");
    let findings = check_app_profiles(&ufw);
    assert!(findings.iter().any(|f| f.id == "app:exists"));
}

// ---------------------------------------------------------------------------
// Doctor scope
// ---------------------------------------------------------------------------

#[test]
fn doctor_all_should_run_all_checks() {
    let ufw = make_ufw_for_doctor(
        "Status: active\n\nTo                         Action      From\n--                         ------      ----\n22/tcp                     ALLOW       Anywhere\n",
    );
    let findings = doctor(&ufw, DoctorScope::All).unwrap();
    assert!(findings.len() > 5);
}

// ---------------------------------------------------------------------------
// Edge-case tests
// ---------------------------------------------------------------------------

#[test]
fn check_binaries_should_handle_missing_ufw() {
    struct NoBinaryRunner;
    impl crate::command::CommandRunner for NoBinaryRunner {
        fn run(&self, _: &CommandSpec) -> crate::error::Result<CommandResult> {
            unimplemented!()
        }
        fn binary_exists(&self, _: &str) -> bool {
            false
        }
    }

    let ufw = Ufw::with_runner(NoBinaryRunner);
    let findings = check_binaries(&ufw);
    assert!(findings.iter().any(|f| f.id == "bin:ufw:missing"));
    // Should not have version check since ufw not found
    assert!(!findings.iter().any(|f| f.id == "bin:ufw:version"));
}

// ---------------------------------------------------------------------------
// Weird edge-case tests
// ---------------------------------------------------------------------------

#[test]
fn check_rules_should_warn_on_dangerous_ports() {
    let ufw = make_ufw_for_doctor(
        "Status: active\n\nTo                         Action      From\n--                         ------      ----\n22/tcp                     ALLOW       Anywhere\n5432/tcp                   ALLOW       Anywhere\n",
    );
    let findings = check_rules(&ufw);
    assert!(findings.iter().any(|f| f.title.contains("22")));
    assert!(findings.iter().any(|f| f.title.contains("5432")));
}

#[test]
fn doctor_should_handle_empty_rules() {
    let ufw = make_ufw_for_doctor("Status: active\n\nTo                         Action      From\n--                         ------      ----\n");
    let findings = doctor(&ufw, DoctorScope::Rules).unwrap();
    assert!(findings.is_empty() || findings.iter().all(|f| f.severity <= Severity::Info));
}
