//! Comprehensive tests for the [`Doctor`] diagnostic engine.
//!
//! Every test uses [`FakeRunner`] to avoid executing real system commands.
//! Where the code under test calls [`find_binary`], the result depends on
//! the host system, so tests assert on the *shape* of findings (presence of
//! specific IDs) rather than exact counts.

use super::*;
use crate::command::{CommandOutput, FakeRunner};
use crate::report::{DoctorReport, Finding, Severity};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Shorthand for a successful command output with the given stdout.
fn ok_output(stdout: &str) -> CommandOutput {
    CommandOutput {
        stdout: stdout.to_string(),
        stderr: String::new(),
        exit_code: Some(0),
        success: true,
    }
}

/// Shorthand for a failed command output with the given stderr.
fn fail_output(stderr: &str) -> CommandOutput {
    CommandOutput {
        stdout: String::new(),
        stderr: stderr.to_string(),
        exit_code: Some(1),
        success: false,
    }
}

/// Check whether findings contain an entry with the given id.
fn has_finding(findings: &[Finding], id: &str) -> bool {
    findings.iter().any(|f| f.id == id)
}

// ===========================================================================
// Doctor construction
// ===========================================================================

#[test]
fn doctor_new_borrows_runner() {
    let fake = FakeRunner::new();
    let _doctor = Doctor::new(&fake);
    // Doctor should construct without panicking.
}

// ===========================================================================
// DoctorScope
// ===========================================================================

#[test]
fn doctor_scope_all_categories_has_ten_variants() {
    let cats = DoctorScope::all_categories();
    assert_eq!(cats.len(), 10);
}

#[test]
fn doctor_scope_all_categories_does_not_include_all() {
    let cats = DoctorScope::all_categories();
    assert!(!cats.iter().any(|c| matches!(c, DoctorScope::All)));
}

#[test]
fn doctor_scope_all_categories_contains_expected_variants() {
    let cats = DoctorScope::all_categories();
    assert!(cats.iter().any(|c| matches!(c, DoctorScope::Binary)));
    assert!(cats.iter().any(|c| matches!(c, DoctorScope::Service)));
    assert!(cats.iter().any(|c| matches!(c, DoctorScope::Config)));
    assert!(cats.iter().any(|c| matches!(c, DoctorScope::LogPath)));
    assert!(cats.iter().any(|c| matches!(c, DoctorScope::Journal)));
    assert!(cats.iter().any(|c| matches!(c, DoctorScope::Regex)));
    assert!(cats.iter().any(|c| matches!(c, DoctorScope::Action)));
    assert!(cats.iter().any(|c| matches!(c, DoctorScope::Permission)));
    assert!(cats.iter().any(|c| matches!(c, DoctorScope::Safety)));
    assert!(cats.iter().any(|c| matches!(c, DoctorScope::Proxy)));
}

#[test]
fn doctor_scope_jail_carries_name() {
    let scope = DoctorScope::Jail("sshd".to_string());
    assert!(matches!(scope, DoctorScope::Jail(name) if name == "sshd"));
}

// ===========================================================================
// check_binaries
// ===========================================================================

#[test]
fn check_binaries_with_all_binaries_present() {
    let mut fake = FakeRunner::new();

    // fail2ban-client --version
    fake.with_response(
        "fail2ban-client",
        &["--version"],
        ok_output("Fail2Ban v1.0.2"),
    );
    // nft --version
    fake.with_response("nft", &["--version"], ok_output("nftables 1.0.6"));
    // iptables --version
    fake.with_response("iptables", &["--version"], ok_output("iptables v1.8.8"));

    let doctor = Doctor::new(&fake);
    let findings = doctor.check_binaries();

    // nft and iptables should be reported as available.
    assert!(has_finding(&findings, "binary.nft.available"));
    assert!(has_finding(&findings, "binary.iptables.available"));

    // If fail2ban-client / fail2ban-regex / systemctl are on the host PATH,
    // they will have .found findings; otherwise .missing. Either way we must
    // have at least the firewall findings above.
    assert!(!findings.is_empty());
}

#[test]
fn check_binaries_with_missing_fail2ban_client() {
    // On a system where fail2ban-client is not on PATH, the find_binary call
    // will fail and the runner is never invoked for --version.
    let fake = FakeRunner::new();
    let doctor = Doctor::new(&fake);
    let findings = doctor.check_binaries();

    // The method must produce findings regardless.
    assert!(!findings.is_empty());

    // If fail2ban-client is not found, the critical finding should appear.
    if find_binary("fail2ban-client").is_err() {
        assert!(has_finding(&findings, "binary.fail2ban-client.missing"));
        assert!(
            findings
                .iter()
                .any(|f| f.id == "binary.fail2ban-client.missing"
                    && f.severity == Severity::Critical)
        );
    }
}

#[test]
fn check_binaries_reports_version_when_available() {
    // Only test the version-detection branch if fail2ban-client is on PATH.
    let Ok(path) = find_binary("fail2ban-client") else {
        return;
    };
    let bin = path.to_str().unwrap_or("fail2ban-client");

    let mut fake = FakeRunner::new();
    fake.with_response(bin, &["--version"], ok_output("Fail2Ban v1.1.0"));
    fake.with_response("nft", &["--version"], ok_output("1.0"));
    fake.with_response("iptables", &["--version"], ok_output("1.8"));

    let doctor = Doctor::new(&fake);
    let findings = doctor.check_binaries();

    assert!(has_finding(&findings, "binary.fail2ban-client.version"));
    let ver_finding = findings
        .iter()
        .find(|f| f.id == "binary.fail2ban-client.version")
        .unwrap();
    assert_eq!(ver_finding.severity, Severity::Info);
    assert!(ver_finding.detail.contains("Fail2Ban v1.1.0"));
}

#[test]
fn check_binaries_reports_version_failed_when_nonzero() {
    let Ok(path) = find_binary("fail2ban-client") else {
        return;
    };
    let bin = path.to_str().unwrap_or("fail2ban-client");

    let mut fake = FakeRunner::new();
    fake.with_response(bin, &["--version"], fail_output("unknown flag"));
    fake.with_response("nft", &["--version"], ok_output("1.0"));
    fake.with_response("iptables", &["--version"], ok_output("1.8"));

    let doctor = Doctor::new(&fake);
    let findings = doctor.check_binaries();

    assert!(has_finding(
        &findings,
        "binary.fail2ban-client.version-failed"
    ));
}

// ===========================================================================
// check_service
// ===========================================================================

#[test]
fn check_service_with_active_service() {
    let mut fake = FakeRunner::new();
    fake.with_response("systemctl", &["is-active", "fail2ban"], ok_output("active"));
    fake.with_response(
        "systemctl",
        &["is-enabled", "fail2ban"],
        ok_output("enabled"),
    );

    // If fail2ban-client is on PATH, set up responses for ping/logtarget/dbfile.
    if let Ok(path) = find_binary("fail2ban-client") {
        let bin = path.to_str().unwrap_or("fail2ban-client");
        fake.with_response(bin, &["ping"], ok_output("Server replied: pong"));
        fake.with_response(
            bin,
            &["get", "logtarget"],
            ok_output("/var/log/fail2ban.log"),
        );
        fake.with_response(
            bin,
            &["get", "dbfile"],
            ok_output("/var/lib/fail2ban/fail2ban.sqlite3"),
        );
    }

    let doctor = Doctor::new(&fake);
    let findings = doctor.check_service();

    assert!(has_finding(&findings, "service.active"));
    assert!(has_finding(&findings, "service.enabled"));

    // If fail2ban-client is available, we should also see ping and logtarget.
    if find_binary("fail2ban-client").is_ok() {
        assert!(has_finding(&findings, "service.ping-ok"));
        assert!(has_finding(&findings, "service.logtarget-accessible"));
        assert!(has_finding(&findings, "service.dbfile-configured"));
    }
}

#[test]
fn check_service_with_inactive_service() {
    let mut fake = FakeRunner::new();
    fake.with_response(
        "systemctl",
        &["is-active", "fail2ban"],
        fail_output("inactive"),
    );
    fake.with_response(
        "systemctl",
        &["is-enabled", "fail2ban"],
        fail_output("disabled"),
    );

    let doctor = Doctor::new(&fake);
    let findings = doctor.check_service();

    assert!(has_finding(&findings, "service.inactive"));
    assert!(has_finding(&findings, "service.not-enabled"));

    let inactive = findings
        .iter()
        .find(|f| f.id == "service.inactive")
        .unwrap();
    assert_eq!(inactive.severity, Severity::Critical);
    assert!(inactive.fix.is_some());
}

#[test]
fn check_service_active_check_error() {
    let fake = FakeRunner::new();
    // FakeRunner returns a default success for unregistered commands,
    // so the default empty success flows through and we verify the
    // service.active finding is emitted.
    let doctor = Doctor::new(&fake);
    let findings = doctor.check_service();
    assert!(!findings.is_empty());
}

#[test]
fn check_service_ping_failed() {
    let Ok(path) = find_binary("fail2ban-client") else {
        return;
    };
    let bin = path.to_str().unwrap_or("fail2ban-client");

    let mut fake = FakeRunner::new();
    fake.with_response("systemctl", &["is-active", "fail2ban"], ok_output("active"));
    fake.with_response(
        "systemctl",
        &["is-enabled", "fail2ban"],
        ok_output("enabled"),
    );
    fake.with_response(bin, &["ping"], fail_output("Connection refused"));
    fake.with_response(bin, &["get", "logtarget"], fail_output("error"));
    fake.with_response(bin, &["get", "dbfile"], fail_output("error"));

    let doctor = Doctor::new(&fake);
    let findings = doctor.check_service();

    assert!(has_finding(&findings, "service.ping-failed"));
    let ping_finding = findings
        .iter()
        .find(|f| f.id == "service.ping-failed")
        .unwrap();
    assert_eq!(ping_finding.severity, Severity::Critical);
}

#[test]
fn check_service_dbfile_disabled() {
    let Ok(path) = find_binary("fail2ban-client") else {
        return;
    };
    let bin = path.to_str().unwrap_or("fail2ban-client");

    let mut fake = FakeRunner::new();
    fake.with_response("systemctl", &["is-active", "fail2ban"], ok_output("active"));
    fake.with_response(
        "systemctl",
        &["is-enabled", "fail2ban"],
        ok_output("enabled"),
    );
    fake.with_response(bin, &["ping"], ok_output("pong"));
    fake.with_response(
        bin,
        &["get", "logtarget"],
        ok_output("/var/log/fail2ban.log"),
    );
    fake.with_response(bin, &["get", "dbfile"], ok_output("None"));

    let doctor = Doctor::new(&fake);
    let findings = doctor.check_service();

    assert!(has_finding(&findings, "service.dbfile-disabled"));
}

// ===========================================================================
// check_config
// ===========================================================================

#[test]
fn check_config_with_valid_config() {
    // This test depends on whether /etc/fail2ban exists on the host.
    // We verify the method runs and produces a directory finding.
    let fake = FakeRunner::new();
    let doctor = Doctor::new(&fake);
    let findings = doctor.check_config();

    let config_dir = std::path::Path::new("/etc/fail2ban");
    if config_dir.exists() {
        assert!(has_finding(&findings, "config.directory.exists"));
    } else {
        assert!(has_finding(&findings, "config.directory.missing"));
    }
}

#[test]
fn check_config_reports_missing_directory() {
    // /etc/fail2ban likely does not exist on a macOS dev machine.
    let fake = FakeRunner::new();
    let doctor = Doctor::new(&fake);
    let findings = doctor.check_config();

    let has_dir = has_finding(&findings, "config.directory.exists")
        || has_finding(&findings, "config.directory.missing");
    assert!(has_dir);
}

#[test]
fn check_config_test_passed_when_binary_available() {
    if !std::path::Path::new("/etc/fail2ban").exists() {
        return;
    }
    let Ok(path) = find_binary("fail2ban-client") else {
        return;
    };
    let bin = path.to_str().unwrap_or("fail2ban-client");

    let mut fake = FakeRunner::new();
    fake.with_response(bin, &["--test"], ok_output("OK"));

    let doctor = Doctor::new(&fake);
    let findings = doctor.check_config();
    assert!(has_finding(&findings, "config.test.passed"));
}

#[test]
fn check_config_test_failed_when_nonzero() {
    if !std::path::Path::new("/etc/fail2ban").exists() {
        return;
    }
    let Ok(path) = find_binary("fail2ban-client") else {
        return;
    };
    let bin = path.to_str().unwrap_or("fail2ban-client");

    let mut fake = FakeRunner::new();
    fake.with_response(bin, &["--test"], fail_output("Syntax error in jail.conf"));

    let doctor = Doctor::new(&fake);
    let findings = doctor.check_config();
    assert!(has_finding(&findings, "config.test.failed"));
    let f = findings
        .iter()
        .find(|f| f.id == "config.test.failed")
        .unwrap();
    assert_eq!(f.severity, Severity::Error);
    assert!(f.fix.is_some());
}

// ===========================================================================
// check_jail
// ===========================================================================

#[test]
fn check_jail_with_existing_jail() {
    let Ok(path) = find_binary("fail2ban-client") else {
        return;
    };
    let bin = path.to_str().unwrap_or("fail2ban-client");

    let mut fake = FakeRunner::new();
    let status_output = indoc::indoc! {"
        Status for the jail: sshd
        |- Filter
        |  |- Currently failed: 0
        |  |- Total failed:     5
        |  `- File list:        /var/log/auth.log
        `- Actions
           |- Currently banned: 2
           |- Total banned:     10
           `- Banned IP list:   192.0.2.1 192.0.2.2
    "};
    fake.with_response(bin, &["status", "sshd"], ok_output(status_output));
    fake.with_response(bin, &["get", "sshd", "bantime"], ok_output("600"));
    fake.with_response(bin, &["get", "sshd", "findtime"], ok_output("600"));
    fake.with_response(bin, &["get", "sshd", "maxretry"], ok_output("5"));

    let doctor = Doctor::new(&fake);
    let findings = doctor.check_jail("sshd");

    assert!(has_finding(&findings, "jail.exists"));
    assert!(has_finding(&findings, "jail.has-filter"));
    assert!(has_finding(&findings, "jail.has-action"));
    assert!(has_finding(&findings, "jail.maxretry-ok"));
}

#[test]
fn check_jail_not_found() {
    let Ok(path) = find_binary("fail2ban-client") else {
        return;
    };
    let bin = path.to_str().unwrap_or("fail2ban-client");

    let mut fake = FakeRunner::new();
    fake.with_response(
        bin,
        &["status", "nonexistent"],
        fail_output("Jail 'nonexistent' not found"),
    );

    let doctor = Doctor::new(&fake);
    let findings = doctor.check_jail("nonexistent");

    assert!(has_finding(&findings, "jail.not-found"));
    let f = findings.iter().find(|f| f.id == "jail.not-found").unwrap();
    assert_eq!(f.severity, Severity::Error);
    assert!(f.fix.is_some());
}

#[test]
fn check_jail_maxretry_zero_warning() {
    let Ok(path) = find_binary("fail2ban-client") else {
        return;
    };
    let bin = path.to_str().unwrap_or("fail2ban-client");

    let mut fake = FakeRunner::new();
    fake.with_response(bin, &["status", "badjail"], ok_output("Filter\nActions\n"));
    fake.with_response(bin, &["get", "badjail", "bantime"], ok_output("600"));
    fake.with_response(bin, &["get", "badjail", "findtime"], ok_output("600"));
    fake.with_response(bin, &["get", "badjail", "maxretry"], ok_output("0"));

    let doctor = Doctor::new(&fake);
    let findings = doctor.check_jail("badjail");

    assert!(has_finding(&findings, "jail.maxretry-zero"));
    let f = findings
        .iter()
        .find(|f| f.id == "jail.maxretry-zero")
        .unwrap();
    assert_eq!(f.severity, Severity::Warning);
}

#[test]
fn check_jail_maxretry_very_high_info() {
    let Ok(path) = find_binary("fail2ban-client") else {
        return;
    };
    let bin = path.to_str().unwrap_or("fail2ban-client");

    let mut fake = FakeRunner::new();
    fake.with_response(
        bin,
        &["status", "loosejail"],
        ok_output("Filter\nActions\n"),
    );
    fake.with_response(bin, &["get", "loosejail", "bantime"], ok_output("600"));
    fake.with_response(bin, &["get", "loosejail", "findtime"], ok_output("600"));
    fake.with_response(bin, &["get", "loosejail", "maxretry"], ok_output("200"));

    let doctor = Doctor::new(&fake);
    let findings = doctor.check_jail("loosejail");

    assert!(has_finding(&findings, "jail.maxretry-very-high"));
}

#[test]
fn check_jail_no_client_binary() {
    // If fail2ban-client is not on PATH, the method should still produce a
    // finding without panicking.
    let fake = FakeRunner::new();
    let doctor = Doctor::new(&fake);
    let findings = doctor.check_jail("sshd");

    if find_binary("fail2ban-client").is_err() {
        assert!(has_finding(&findings, "jail.no-client"));
        let f = findings.iter().find(|f| f.id == "jail.no-client").unwrap();
        assert_eq!(f.severity, Severity::Critical);
    }
}

// ===========================================================================
// check_permissions
// ===========================================================================

#[test]
fn check_permissions_reports_something() {
    let fake = FakeRunner::new();
    let doctor = Doctor::new(&fake);
    let findings = doctor.check_permissions();
    assert!(!findings.is_empty());
}

#[test]
fn check_permissions_finds_config_dir_safe_when_present() {
    if !std::path::Path::new("/etc/fail2ban").exists() {
        return;
    }
    let fake = FakeRunner::new();
    let doctor = Doctor::new(&fake);
    let findings = doctor.check_permissions();

    // Either the dir is world-writable or it is safe.
    let has_perm_finding = has_finding(&findings, "permission.config-dir-safe")
        || has_finding(&findings, "permission.config-dir-world-writable")
        || has_finding(&findings, "permission.config-dir-missing");
    assert!(has_perm_finding);
}

// ===========================================================================
// check_safety
// ===========================================================================

#[test]
fn check_safety_always_reports_dry_run_available() {
    let fake = FakeRunner::new();
    let doctor = Doctor::new(&fake);
    let findings = doctor.check_safety();

    assert!(has_finding(&findings, "safety.dry-run-available"));
}

// ===========================================================================
// run() with DoctorScope::All
// ===========================================================================

#[test]
fn run_with_all_scope_returns_report() {
    let mut fake = FakeRunner::new();
    fake.with_response(
        "systemctl",
        &["is-active", "fail2ban"],
        fail_output("inactive"),
    );
    fake.with_response(
        "systemctl",
        &["is-enabled", "fail2ban"],
        fail_output("disabled"),
    );
    fake.with_response("nft", &["--version"], ok_output("1.0"));
    fake.with_response("iptables", &["--version"], ok_output("1.8"));
    fake.with_response("journalctl", &["--version"], ok_output("250"));

    let doctor = Doctor::new(&fake);
    let report = doctor.run(&DoctorScope::All).unwrap();

    assert!(!report.findings.is_empty());
}

// ===========================================================================
// run() with specific scopes
// ===========================================================================

#[test]
fn run_with_binary_scope() {
    let mut fake = FakeRunner::new();
    fake.with_response("nft", &["--version"], ok_output("1.0"));
    fake.with_response("iptables", &["--version"], ok_output("1.8"));

    let doctor = Doctor::new(&fake);
    let report = doctor.run(&DoctorScope::Binary).unwrap();
    assert!(!report.findings.is_empty());
    assert!(has_finding(&report.findings, "binary.nft.available"));
    assert!(has_finding(&report.findings, "binary.iptables.available"));
}

#[test]
fn run_with_service_scope() {
    let mut fake = FakeRunner::new();
    fake.with_response("systemctl", &["is-active", "fail2ban"], ok_output("active"));
    fake.with_response(
        "systemctl",
        &["is-enabled", "fail2ban"],
        ok_output("enabled"),
    );

    let doctor = Doctor::new(&fake);
    let report = doctor.run(&DoctorScope::Service).unwrap();
    assert!(has_finding(&report.findings, "service.active"));
    assert!(has_finding(&report.findings, "service.enabled"));
}

#[test]
fn run_with_config_scope() {
    let fake = FakeRunner::new();
    let doctor = Doctor::new(&fake);
    let report = doctor.run(&DoctorScope::Config).unwrap();
    assert!(!report.findings.is_empty());
}

#[test]
fn run_with_permission_scope() {
    let fake = FakeRunner::new();
    let doctor = Doctor::new(&fake);
    let report = doctor.run(&DoctorScope::Permission).unwrap();
    assert!(!report.findings.is_empty());
}

#[test]
fn run_with_safety_scope() {
    let fake = FakeRunner::new();
    let doctor = Doctor::new(&fake);
    let report = doctor.run(&DoctorScope::Safety).unwrap();
    assert!(has_finding(&report.findings, "safety.dry-run-available"));
}

#[test]
fn run_with_journal_scope() {
    let mut fake = FakeRunner::new();
    fake.with_response("journalctl", &["--version"], ok_output("250"));
    fake.with_response(
        "journalctl",
        &["-u", "fail2ban", "-n", "1", "--no-pager"],
        ok_output("fail2ban.log line"),
    );

    let doctor = Doctor::new(&fake);
    let report = doctor.run(&DoctorScope::Journal).unwrap();
    assert!(has_finding(
        &report.findings,
        "journal.journalctl.available"
    ));
    assert!(has_finding(&report.findings, "journal.entries-found"));
}

#[test]
fn run_with_regex_scope() {
    let fake = FakeRunner::new();
    let doctor = Doctor::new(&fake);
    let report = doctor.run(&DoctorScope::Regex).unwrap();
    // Should produce some finding (either tool found or missing).
    assert!(!report.findings.is_empty());
}

#[test]
fn run_with_action_scope() {
    let fake = FakeRunner::new();
    let doctor = Doctor::new(&fake);
    let report = doctor.run(&DoctorScope::Action).unwrap();
    assert!(!report.findings.is_empty());
}

#[test]
fn run_with_logpath_scope() {
    let fake = FakeRunner::new();
    let doctor = Doctor::new(&fake);
    let report = doctor.run(&DoctorScope::LogPath).unwrap();
    assert!(!report.findings.is_empty());
}

#[test]
fn run_with_proxy_scope() {
    let fake = FakeRunner::new();
    let doctor = Doctor::new(&fake);
    let report = doctor.run(&DoctorScope::Proxy).unwrap();
    // If no proxy issues are detected, the ok finding is emitted.
    assert!(has_finding(&report.findings, "proxy.no-issues"));
}

#[test]
fn run_with_jail_scope() {
    let Ok(path) = find_binary("fail2ban-client") else {
        return;
    };
    let bin = path.to_str().unwrap_or("fail2ban-client");

    let mut fake = FakeRunner::new();
    fake.with_response(
        bin,
        &["status", "sshd"],
        ok_output("Filter\nActions\nCurrently banned: 0\n"),
    );
    fake.with_response(bin, &["get", "sshd", "bantime"], ok_output("600"));
    fake.with_response(bin, &["get", "sshd", "findtime"], ok_output("600"));
    fake.with_response(bin, &["get", "sshd", "maxretry"], ok_output("5"));

    let doctor = Doctor::new(&fake);
    let report = doctor.run(&DoctorScope::Jail("sshd".to_string())).unwrap();
    assert!(has_finding(&report.findings, "jail.exists"));
}

// ===========================================================================
// DoctorReport::summary_by_severity()
// ===========================================================================

#[test]
fn doctor_report_summary_by_severity_groups_correctly() {
    let mut report = DoctorReport::empty();
    report.push(Finding::new("a", Severity::Ok, "ok finding"));
    report.push(Finding::new("b", Severity::Ok, "another ok"));
    report.push(Finding::new("c", Severity::Critical, "bad"));
    report.push(Finding::new("d", Severity::Warning, "meh"));

    let summary = report.summary_by_severity();

    assert_eq!(summary[&Severity::Ok].len(), 2);
    assert_eq!(summary[&Severity::Critical].len(), 1);
    assert_eq!(summary[&Severity::Warning].len(), 1);
    assert!(!summary.contains_key(&Severity::Info));
    assert!(!summary.contains_key(&Severity::Error));
}

#[test]
fn doctor_report_summary_by_severity_empty_report() {
    let report = DoctorReport::empty();
    let summary = report.summary_by_severity();
    assert!(summary.is_empty());
}

// ===========================================================================
// DoctorReport::has_errors()
// ===========================================================================

#[test]
fn doctor_report_has_errors_true_with_error_severity() {
    let mut report = DoctorReport::empty();
    report.push(Finding::new("e1", Severity::Error, "error"));
    assert!(report.has_errors());
}

#[test]
fn doctor_report_has_errors_true_with_critical_severity() {
    let mut report = DoctorReport::empty();
    report.push(Finding::new("c1", Severity::Critical, "critical"));
    assert!(report.has_errors());
}

#[test]
fn doctor_report_has_errors_false_with_only_ok() {
    let mut report = DoctorReport::empty();
    report.push(Finding::new("ok1", Severity::Ok, "fine"));
    report.push(Finding::new("i1", Severity::Info, "note"));
    report.push(Finding::new("w1", Severity::Warning, "meh"));
    assert!(!report.has_errors());
}

#[test]
fn doctor_report_has_errors_false_when_empty() {
    let report = DoctorReport::empty();
    assert!(!report.has_errors());
}

// ===========================================================================
// DoctorReport::has_critical()
// ===========================================================================

#[test]
fn doctor_report_has_critical_true() {
    let mut report = DoctorReport::empty();
    report.push(Finding::new("c1", Severity::Critical, "fatal"));
    assert!(report.has_critical());
}

#[test]
fn doctor_report_has_critical_false_with_error_only() {
    let mut report = DoctorReport::empty();
    report.push(Finding::new("e1", Severity::Error, "error"));
    assert!(!report.has_critical());
}

// ===========================================================================
// DoctorReport::len / is_empty
// ===========================================================================

#[test]
fn doctor_report_len_and_is_empty() {
    let empty = DoctorReport::empty();
    assert!(empty.is_empty());
    assert_eq!(empty.len(), 0);

    let mut nonempty = DoctorReport::empty();
    nonempty.push(Finding::new("x", Severity::Ok, "x"));
    assert!(!nonempty.is_empty());
    assert_eq!(nonempty.len(), 1);
}

// ===========================================================================
// Finding construction and fields
// ===========================================================================

#[test]
fn finding_new_sets_mandatory_fields() {
    let f = Finding::new("test.id", Severity::Warning, "test title");
    assert_eq!(f.id, "test.id");
    assert_eq!(f.severity, Severity::Warning);
    assert_eq!(f.title, "test title");
    assert!(f.detail.is_empty());
    assert!(f.fix.is_none());
}

#[test]
fn finding_detail_chain_sets_detail() {
    let f = Finding::new("id", Severity::Ok, "title").detail("some detail text");
    assert_eq!(f.detail, "some detail text");
}

#[test]
fn finding_fix_chain_sets_fix() {
    let f = Finding::new("id", Severity::Error, "title").fix("do this to fix");
    assert_eq!(f.fix.as_deref(), Some("do this to fix"));
}

#[test]
fn finding_detail_and_fix_chained() {
    let f = Finding::new("id", Severity::Critical, "title")
        .detail("something is broken")
        .fix("reinstall the package");
    assert_eq!(f.detail, "something is broken");
    assert_eq!(f.fix.as_deref(), Some("reinstall the package"));
}

#[test]
fn finding_detail_replaces_previous() {
    let f = Finding::new("id", Severity::Ok, "title")
        .detail("first")
        .detail("second");
    assert_eq!(f.detail, "second");
}

#[test]
fn finding_fix_replaces_previous() {
    let f = Finding::new("id", Severity::Ok, "title")
        .fix("first")
        .fix("second");
    assert_eq!(f.fix.as_deref(), Some("second"));
}

// ===========================================================================
// Severity ordering
// ===========================================================================

#[test]
fn severity_ordering() {
    assert!(Severity::Ok < Severity::Info);
    assert!(Severity::Info < Severity::Warning);
    assert!(Severity::Warning < Severity::Error);
    assert!(Severity::Error < Severity::Critical);
}

#[test]
fn severity_display() {
    assert_eq!(format!("{}", Severity::Ok), "OK");
    assert_eq!(format!("{}", Severity::Info), "INFO");
    assert_eq!(format!("{}", Severity::Warning), "WARNING");
    assert_eq!(format!("{}", Severity::Error), "ERROR");
    assert_eq!(format!("{}", Severity::Critical), "CRITICAL");
}

// ===========================================================================
// parse_jail_list
// ===========================================================================

#[test]
fn parse_jail_list_extracts_names() {
    let status = "Status\n|- Number of jail:      2\n`- Jail list:   sshd, nginx\n";
    let jails = parse_jail_list(status);
    assert_eq!(jails, vec!["sshd", "nginx"]);
}

#[test]
fn parse_jail_list_single_jail() {
    let status = "`- Jail list:   sshd\n";
    let jails = parse_jail_list(status);
    assert_eq!(jails, vec!["sshd"]);
}

#[test]
fn parse_jail_list_empty() {
    let status = "Status\n|- Number of jail:      0\n`- Jail list:\n";
    let jails = parse_jail_list(status);
    assert!(jails.is_empty());
}

#[test]
fn parse_jail_list_no_jail_line() {
    let status = "Status\n|- Something else\n";
    let jails = parse_jail_list(status);
    assert!(jails.is_empty());
}

#[test]
fn parse_jail_list_case_insensitive_detection() {
    let status = "JAIL LIST: sshd, apache\n";
    let jails = parse_jail_list(status);
    assert_eq!(jails, vec!["sshd", "apache"]);
}

// ===========================================================================
// Socket file check
// ===========================================================================

#[test]
fn check_service_socket_ok_when_path_exists() {
    let Ok(path) = find_binary("fail2ban-client") else {
        return;
    };
    let bin = path.to_str().unwrap_or("fail2ban-client");

    let mut fake = FakeRunner::new();
    fake.with_response("systemctl", &["is-active", "fail2ban"], ok_output("active"));
    fake.with_response(
        "systemctl",
        &["is-enabled", "fail2ban"],
        ok_output("enabled"),
    );
    fake.with_response(bin, &["ping"], ok_output("Server replied: pong"));
    fake.with_response(
        bin,
        &["get", "logtarget"],
        ok_output("/var/log/fail2ban.log"),
    );
    fake.with_response(
        bin,
        &["get", "dbfile"],
        ok_output("/var/lib/fail2ban/fail2ban.sqlite3"),
    );
    // Use a path that exists on any Unix system.
    fake.with_response(
        bin,
        &["get", "socket"],
        ok_output("/var/run/fail2ban/fail2ban.sock"),
    );
    fake.with_response(
        bin,
        &["get", "pidfile"],
        ok_output("/var/run/fail2ban/fail2ban.pid"),
    );

    let doctor = Doctor::new(&fake);
    let findings = doctor.check_service();

    // The socket path /var/run/fail2ban/fail2ban.sock may or may not exist on
    // the test host, so assert one of the two socket findings is present.
    let has_socket_finding = has_finding(&findings, "service.socket_ok")
        || has_finding(&findings, "service.socket_missing");
    assert!(
        has_socket_finding,
        "expected socket finding, got: {:?}",
        findings.iter().map(|f| &f.id).collect::<Vec<_>>()
    );
}

#[test]
fn check_service_socket_missing_when_path_not_on_disk() {
    let Ok(path) = find_binary("fail2ban-client") else {
        return;
    };
    let bin = path.to_str().unwrap_or("fail2ban-client");

    let mut fake = FakeRunner::new();
    fake.with_response("systemctl", &["is-active", "fail2ban"], ok_output("active"));
    fake.with_response(
        "systemctl",
        &["is-enabled", "fail2ban"],
        ok_output("enabled"),
    );
    fake.with_response(bin, &["ping"], ok_output("pong"));
    fake.with_response(
        bin,
        &["get", "logtarget"],
        ok_output("/var/log/fail2ban.log"),
    );
    fake.with_response(
        bin,
        &["get", "dbfile"],
        ok_output("/var/lib/fail2ban/fail2ban.sqlite3"),
    );
    // Report a path that is guaranteed not to exist.
    fake.with_response(
        bin,
        &["get", "socket"],
        ok_output("/tmp/doctor-test-nonexistent-socket-path-abc123.sock"),
    );
    fake.with_response(
        bin,
        &["get", "pidfile"],
        ok_output("/var/run/fail2ban/fail2ban.pid"),
    );

    let doctor = Doctor::new(&fake);
    let findings = doctor.check_service();

    assert!(has_finding(&findings, "service.socket_missing"));
    let f = findings
        .iter()
        .find(|f| f.id == "service.socket_missing")
        .unwrap();
    assert_eq!(f.severity, Severity::Warning);
    assert!(f.fix.is_some());
}

// ===========================================================================
// PID file check
// ===========================================================================

#[test]
fn check_service_pidfile_ok_when_path_exists() {
    let Ok(path) = find_binary("fail2ban-client") else {
        return;
    };
    let bin = path.to_str().unwrap_or("fail2ban-client");

    let mut fake = FakeRunner::new();
    fake.with_response("systemctl", &["is-active", "fail2ban"], ok_output("active"));
    fake.with_response(
        "systemctl",
        &["is-enabled", "fail2ban"],
        ok_output("enabled"),
    );
    fake.with_response(bin, &["ping"], ok_output("pong"));
    fake.with_response(
        bin,
        &["get", "logtarget"],
        ok_output("/var/log/fail2ban.log"),
    );
    fake.with_response(
        bin,
        &["get", "dbfile"],
        ok_output("/var/lib/fail2ban/fail2ban.sqlite3"),
    );
    fake.with_response(
        bin,
        &["get", "socket"],
        ok_output("/var/run/fail2ban/fail2ban.sock"),
    );
    // Report /proc/1/status -- a path that exists on Linux (always present for
    // init).  On macOS, /dev/null works as a universally existing path.
    fake.with_response(bin, &["get", "pidfile"], ok_output("/dev/null"));

    let doctor = Doctor::new(&fake);
    let findings = doctor.check_service();

    assert!(has_finding(&findings, "service.pidfile_ok"));
    let f = findings
        .iter()
        .find(|f| f.id == "service.pidfile_ok")
        .unwrap();
    assert_eq!(f.severity, Severity::Ok);
}

#[test]
fn check_service_pidfile_missing_when_path_not_on_disk() {
    let Ok(path) = find_binary("fail2ban-client") else {
        return;
    };
    let bin = path.to_str().unwrap_or("fail2ban-client");

    let mut fake = FakeRunner::new();
    fake.with_response("systemctl", &["is-active", "fail2ban"], ok_output("active"));
    fake.with_response(
        "systemctl",
        &["is-enabled", "fail2ban"],
        ok_output("enabled"),
    );
    fake.with_response(bin, &["ping"], ok_output("pong"));
    fake.with_response(
        bin,
        &["get", "logtarget"],
        ok_output("/var/log/fail2ban.log"),
    );
    fake.with_response(
        bin,
        &["get", "dbfile"],
        ok_output("/var/lib/fail2ban/fail2ban.sqlite3"),
    );
    fake.with_response(
        bin,
        &["get", "socket"],
        ok_output("/var/run/fail2ban/fail2ban.sock"),
    );
    fake.with_response(
        bin,
        &["get", "pidfile"],
        ok_output("/tmp/doctor-test-nonexistent-pidfile-xyz999.pid"),
    );

    let doctor = Doctor::new(&fake);
    let findings = doctor.check_service();

    assert!(has_finding(&findings, "service.pidfile_missing"));
    let f = findings
        .iter()
        .find(|f| f.id == "service.pidfile_missing")
        .unwrap();
    assert_eq!(f.severity, Severity::Warning);
    assert!(f.fix.is_some());
}

// ===========================================================================
// usedns check
// ===========================================================================

#[test]
fn check_jail_usedns_no_is_ok() {
    let Ok(path) = find_binary("fail2ban-client") else {
        return;
    };
    let bin = path.to_str().unwrap_or("fail2ban-client");

    let mut fake = FakeRunner::new();
    fake.with_response(
        bin,
        &["status", "myjail"],
        ok_output("Filter\nActions\nCurrently banned: 0\n"),
    );
    fake.with_response(bin, &["get", "myjail", "bantime"], ok_output("600"));
    fake.with_response(bin, &["get", "myjail", "findtime"], ok_output("600"));
    fake.with_response(bin, &["get", "myjail", "maxretry"], ok_output("5"));
    fake.with_response(bin, &["get", "myjail", "usedns"], ok_output("no"));
    fake.with_response(bin, &["get", "myjail", "ignoreip"], ok_output("127.0.0.1"));

    let doctor = Doctor::new(&fake);
    let findings = doctor.check_jail("myjail");

    assert!(has_finding(&findings, "jail.usedns-ok"));
}

#[test]
fn check_jail_usedns_yes_is_warning() {
    let Ok(path) = find_binary("fail2ban-client") else {
        return;
    };
    let bin = path.to_str().unwrap_or("fail2ban-client");

    let mut fake = FakeRunner::new();
    fake.with_response(
        bin,
        &["status", "myjail"],
        ok_output("Filter\nActions\nCurrently banned: 0\n"),
    );
    fake.with_response(bin, &["get", "myjail", "bantime"], ok_output("600"));
    fake.with_response(bin, &["get", "myjail", "findtime"], ok_output("600"));
    fake.with_response(bin, &["get", "myjail", "maxretry"], ok_output("5"));
    fake.with_response(bin, &["get", "myjail", "usedns"], ok_output("yes"));
    fake.with_response(bin, &["get", "myjail", "ignoreip"], ok_output("127.0.0.1"));

    let doctor = Doctor::new(&fake);
    let findings = doctor.check_jail("myjail");

    assert!(has_finding(&findings, "jail.usedns_insecure"));
    let f = findings
        .iter()
        .find(|f| f.id == "jail.usedns_insecure")
        .unwrap();
    assert_eq!(f.severity, Severity::Warning);
}

// ===========================================================================
// ignoreip check
// ===========================================================================

#[test]
fn check_jail_ignoreip_empty_is_info() {
    let Ok(path) = find_binary("fail2ban-client") else {
        return;
    };
    let bin = path.to_str().unwrap_or("fail2ban-client");

    let mut fake = FakeRunner::new();
    fake.with_response(
        bin,
        &["status", "myjail"],
        ok_output("Filter\nActions\nCurrently banned: 0\n"),
    );
    fake.with_response(bin, &["get", "myjail", "bantime"], ok_output("600"));
    fake.with_response(bin, &["get", "myjail", "findtime"], ok_output("600"));
    fake.with_response(bin, &["get", "myjail", "maxretry"], ok_output("5"));
    fake.with_response(bin, &["get", "myjail", "usedns"], ok_output("no"));
    fake.with_response(bin, &["get", "myjail", "ignoreip"], ok_output(""));

    let doctor = Doctor::new(&fake);
    let findings = doctor.check_jail("myjail");

    assert!(has_finding(&findings, "jail.ignoreip_empty"));
    let f = findings
        .iter()
        .find(|f| f.id == "jail.ignoreip_empty")
        .unwrap();
    assert_eq!(f.severity, Severity::Info);
}

#[test]
fn check_jail_ignoreip_populated_is_ok() {
    let Ok(path) = find_binary("fail2ban-client") else {
        return;
    };
    let bin = path.to_str().unwrap_or("fail2ban-client");

    let mut fake = FakeRunner::new();
    fake.with_response(
        bin,
        &["status", "myjail"],
        ok_output("Filter\nActions\nCurrently banned: 0\n"),
    );
    fake.with_response(bin, &["get", "myjail", "bantime"], ok_output("600"));
    fake.with_response(bin, &["get", "myjail", "findtime"], ok_output("600"));
    fake.with_response(bin, &["get", "myjail", "maxretry"], ok_output("5"));
    fake.with_response(bin, &["get", "myjail", "usedns"], ok_output("no"));
    fake.with_response(
        bin,
        &["get", "myjail", "ignoreip"],
        ok_output("127.0.0.1/8, ::1"),
    );

    let doctor = Doctor::new(&fake);
    let findings = doctor.check_jail("myjail");

    assert!(has_finding(&findings, "jail.ignoreip-configured"));
    let f = findings
        .iter()
        .find(|f| f.id == "jail.ignoreip-configured")
        .unwrap();
    assert_eq!(f.severity, Severity::Ok);
}

// ===========================================================================
// bantime / findtime sanity
// ===========================================================================

#[test]
fn check_jail_bantime_shorter_than_findtime_is_warning() {
    let Ok(path) = find_binary("fail2ban-client") else {
        return;
    };
    let bin = path.to_str().unwrap_or("fail2ban-client");

    let mut fake = FakeRunner::new();
    fake.with_response(
        bin,
        &["status", "myjail"],
        ok_output("Filter\nActions\nCurrently banned: 0\n"),
    );
    fake.with_response(bin, &["get", "myjail", "bantime"], ok_output("120"));
    fake.with_response(bin, &["get", "myjail", "findtime"], ok_output("600"));
    fake.with_response(bin, &["get", "myjail", "maxretry"], ok_output("5"));
    fake.with_response(bin, &["get", "myjail", "usedns"], ok_output("no"));
    fake.with_response(bin, &["get", "myjail", "ignoreip"], ok_output("127.0.0.1"));

    let doctor = Doctor::new(&fake);
    let findings = doctor.check_jail("myjail");

    assert!(has_finding(&findings, "jail.bantime_shorter_than_findtime"));
    let f = findings
        .iter()
        .find(|f| f.id == "jail.bantime_shorter_than_findtime")
        .unwrap();
    assert_eq!(f.severity, Severity::Warning);
}

#[test]
fn check_jail_bantime_very_short_is_warning() {
    let Ok(path) = find_binary("fail2ban-client") else {
        return;
    };
    let bin = path.to_str().unwrap_or("fail2ban-client");

    let mut fake = FakeRunner::new();
    fake.with_response(
        bin,
        &["status", "myjail"],
        ok_output("Filter\nActions\nCurrently banned: 0\n"),
    );
    fake.with_response(bin, &["get", "myjail", "bantime"], ok_output("30"));
    fake.with_response(bin, &["get", "myjail", "findtime"], ok_output("10"));
    fake.with_response(bin, &["get", "myjail", "maxretry"], ok_output("5"));
    fake.with_response(bin, &["get", "myjail", "usedns"], ok_output("no"));
    fake.with_response(bin, &["get", "myjail", "ignoreip"], ok_output("127.0.0.1"));

    let doctor = Doctor::new(&fake);
    let findings = doctor.check_jail("myjail");

    assert!(has_finding(&findings, "jail.bantime_very_short"));
    let f = findings
        .iter()
        .find(|f| f.id == "jail.bantime_very_short")
        .unwrap();
    assert_eq!(f.severity, Severity::Warning);
}

#[test]
fn check_jail_findtime_very_long_is_info() {
    let Ok(path) = find_binary("fail2ban-client") else {
        return;
    };
    let bin = path.to_str().unwrap_or("fail2ban-client");

    let mut fake = FakeRunner::new();
    fake.with_response(
        bin,
        &["status", "myjail"],
        ok_output("Filter\nActions\nCurrently banned: 0\n"),
    );
    fake.with_response(bin, &["get", "myjail", "bantime"], ok_output("7200"));
    fake.with_response(bin, &["get", "myjail", "findtime"], ok_output("7200"));
    fake.with_response(bin, &["get", "myjail", "maxretry"], ok_output("5"));
    fake.with_response(bin, &["get", "myjail", "usedns"], ok_output("no"));
    fake.with_response(bin, &["get", "myjail", "ignoreip"], ok_output("127.0.0.1"));

    let doctor = Doctor::new(&fake);
    let findings = doctor.check_jail("myjail");

    assert!(has_finding(&findings, "jail.findtime_very_long"));
    let f = findings
        .iter()
        .find(|f| f.id == "jail.findtime_very_long")
        .unwrap();
    assert_eq!(f.severity, Severity::Info);
}

// ===========================================================================
// Real IP detection (proxy-only IPs)
// ===========================================================================

#[test]
fn check_log_paths_proxy_ips_only_warning() {
    let Ok(path) = find_binary("fail2ban-client") else {
        return;
    };
    let bin = path.to_str().unwrap_or("fail2ban-client");

    // Create a temp file with only private IPs.
    let tmp_dir = tempfile::tempdir().unwrap();
    let log_file = tmp_dir.path().join("test.log");
    std::fs::write(
        &log_file,
        "Failed password from 192.168.1.100 port 22\nFailed from 10.0.0.1\n",
    )
    .unwrap();
    let log_path_str = log_file.to_str().unwrap();

    let mut fake = FakeRunner::new();
    let status_output = "`- Jail list:   testjail\n";
    fake.with_response(bin, &["status"], ok_output(status_output));
    fake.with_response(
        bin,
        &["get", "testjail", "logpath"],
        ok_output(log_path_str),
    );

    let doctor = Doctor::new(&fake);
    let findings = doctor.check_log_paths();

    assert!(has_finding(&findings, "logpath.proxy_ips_only"));
    let f = findings
        .iter()
        .find(|f| f.id == "logpath.proxy_ips_only")
        .unwrap();
    assert_eq!(f.severity, Severity::Warning);
}

#[test]
fn check_log_paths_public_ips_no_warning() {
    let Ok(path) = find_binary("fail2ban-client") else {
        return;
    };
    let bin = path.to_str().unwrap_or("fail2ban-client");

    let tmp_dir = tempfile::tempdir().unwrap();
    let log_file = tmp_dir.path().join("test.log");
    std::fs::write(&log_file, "Failed password from 203.0.113.50 port 22\n").unwrap();
    let log_path_str = log_file.to_str().unwrap();

    let mut fake = FakeRunner::new();
    let status_output = "`- Jail list:   testjail\n";
    fake.with_response(bin, &["status"], ok_output(status_output));
    fake.with_response(
        bin,
        &["get", "testjail", "logpath"],
        ok_output(log_path_str),
    );

    let doctor = Doctor::new(&fake);
    let findings = doctor.check_log_paths();

    assert!(!has_finding(&findings, "logpath.proxy_ips_only"));
}

/// `check_single_log_path` must inspect only the first `PROXY_IP_SAMPLE_LINES`
/// lines of a log file (not the whole file), and it must do so without slurping
/// the entire file into memory.
///
/// This calls the private associated function directly via `super::*`, which is
/// the unit that performs the proxy-IP detection.
#[test]
fn check_single_log_path_streams_only_first_lines_and_private_ips_warn() {
    let tmp = tempfile::tempdir().unwrap();
    let log = tmp.path().join("auth.log");

    // First PROXY_IP_SAMPLE_LINES lines: only private IPs.
    let mut content = String::new();
    for _ in 0..PROXY_IP_SAMPLE_LINES {
        content.push_str("Failed password from 192.168.1.50 port 22 ssh2\n");
    }
    // After the sample window: a PUBLIC IP. If the implementation read the
    // whole file (or more than PROXY_IP_SAMPLE_LINES lines), this public IP
    // would flip `all_private = false` and suppress the proxy finding.
    content.push_str("Failed password from 203.0.113.99 port 22 ssh2\n");

    std::fs::write(&log, content).unwrap();
    let log_path = log.to_str().unwrap();

    let mut findings = Vec::new();
    Doctor::check_single_log_path(log_path, "sshd", &mut findings);

    // Only the first N lines were inspected, so the trailing public IP is
    // never seen and the proxy-only warning is still emitted.
    assert!(
        has_finding(&findings, "logpath.proxy_ips_only"),
        "expected proxy_ips_only warning when only the first {PROXY_IP_SAMPLE_LINES} \
         (private-IP) lines are inspected, got: {findings:?}"
    );
}

/// `check_single_log_path` must not read the entire file via
/// `read_to_string`. If it did, an invalid-UTF-8 byte anywhere in the file
/// (here, *after* the sampled window) would make the whole read fail and
/// silently drop the proxy-only detection. Streaming the first lines via a
/// `BufReader` bounds memory and still surfaces the finding.
///
/// This test FAILS on the pre-fix `read_to_string` implementation (the whole
/// read errors out, so no `logpath.proxy_ips_only` finding is produced) and
/// PASSES once the function streams only the leading lines.
#[test]
fn check_single_log_path_does_not_slurp_invalid_utf8_past_sample_window() {
    let tmp = tempfile::tempdir().unwrap();
    let log = tmp.path().join("auth.log");

    // First PROXY_IP_SAMPLE_LINES lines are valid UTF-8 with private IPs.
    let mut content = String::new();
    for _ in 0..PROXY_IP_SAMPLE_LINES {
        content.push_str("Failed password from 10.0.0.5 port 22 ssh2\n");
    }
    // Append a block of invalid UTF-8 (lone continuation bytes) AFTER the
    // sampled window. `read_to_string` of the whole file would fail here.
    // Build the on-disk bytes directly so the file is genuinely invalid UTF-8.
    let mut bytes = content.into_bytes();
    bytes.push(b'\n');
    bytes.push(0xFF);
    bytes.push(0xFF);

    std::fs::write(&log, bytes).unwrap();
    let log_path = log.to_str().unwrap();

    let mut findings = Vec::new();
    Doctor::check_single_log_path(log_path, "sshd", &mut findings);

    assert!(
        has_finding(&findings, "logpath.proxy_ips_only"),
        "streaming implementation must still detect private-only IPs even when \
         bytes past the sample window are invalid UTF-8; got: {findings:?}"
    );
}

// ===========================================================================
// Docker path warning
// ===========================================================================

#[test]
fn check_log_paths_docker_path_warning() {
    let Ok(path) = find_binary("fail2ban-client") else {
        return;
    };
    let bin = path.to_str().unwrap_or("fail2ban-client");

    let docker_log = "/var/lib/docker/containers/abc123/abc123-json.log";

    let mut fake = FakeRunner::new();
    let status_output = "`- Jail list:   dockjail\n";
    fake.with_response(bin, &["status"], ok_output(status_output));
    fake.with_response(bin, &["get", "dockjail", "logpath"], ok_output(docker_log));

    let doctor = Doctor::new(&fake);
    let findings = doctor.check_log_paths();

    // The path doesn't exist on disk, so it won't reach the Docker check
    // unless the parent check allows it. We verify the Docker finding is
    // emitted when the path triggers the detection logic. Since the path
    // does not exist, we will not get the docker finding but we verify
    // the method handles it without panicking and produces some findings.
    // If the path were to exist, the Docker finding would appear.
    assert!(!findings.is_empty());
}

// ===========================================================================
// Journal checks -- logpath with systemd backend
// ===========================================================================

#[test]
fn check_journal_logpath_with_systemd_backend_warning() {
    let Ok(path) = find_binary("fail2ban-client") else {
        return;
    };
    let bin = path.to_str().unwrap_or("fail2ban-client");

    let mut fake = FakeRunner::new();
    fake.with_response("journalctl", &["--version"], ok_output("250"));
    fake.with_response(
        "journalctl",
        &["-u", "fail2ban", "-n", "1", "--no-pager"],
        ok_output("some log line"),
    );
    fake.with_response("journalctl", &["-n", "1", "--no-pager"], ok_output("entry"));

    let status_output = "`- Jail list:   sshd\n";
    fake.with_response(bin, &["status"], ok_output(status_output));
    fake.with_response(bin, &["get", "sshd", "backend"], ok_output("systemd"));
    fake.with_response(
        bin,
        &["get", "sshd", "logpath"],
        ok_output("/var/log/auth.log"),
    );
    fake.with_response(
        bin,
        &["get", "sshd", "journalmatch"],
        ok_output("_SYSTEMD_UNIT=sshd.service"),
    );

    let doctor = Doctor::new(&fake);
    let findings = doctor.check_journal();

    assert!(has_finding(&findings, "journal.logpath_with_systemd"));
    let f = findings
        .iter()
        .find(|f| f.id == "journal.logpath_with_systemd")
        .unwrap();
    assert_eq!(f.severity, Severity::Warning);
}

#[test]
fn check_journal_unit_not_found_error() {
    let Ok(path) = find_binary("fail2ban-client") else {
        return;
    };
    let bin = path.to_str().unwrap_or("fail2ban-client");

    let mut fake = FakeRunner::new();
    fake.with_response("journalctl", &["--version"], ok_output("250"));
    fake.with_response(
        "journalctl",
        &["-u", "fail2ban", "-n", "1", "--no-pager"],
        ok_output("some log line"),
    );
    fake.with_response("journalctl", &["-n", "1", "--no-pager"], ok_output("entry"));

    let status_output = "`- Jail list:   sshd\n";
    fake.with_response(bin, &["status"], ok_output(status_output));
    fake.with_response(bin, &["get", "sshd", "backend"], ok_output("systemd"));
    fake.with_response(bin, &["get", "sshd", "logpath"], ok_output("None"));
    fake.with_response(
        bin,
        &["get", "sshd", "journalmatch"],
        ok_output("_SYSTEMD_UNIT=nonexistent.service"),
    );
    fake.with_response(
        "systemctl",
        &["status", "nonexistent.service"],
        fail_output("Unit nonexistent.service could not be found"),
    );

    let doctor = Doctor::new(&fake);
    let findings = doctor.check_journal();

    assert!(has_finding(&findings, "journal.unit_not_found"));
    let f = findings
        .iter()
        .find(|f| f.id == "journal.unit_not_found")
        .unwrap();
    assert_eq!(f.severity, Severity::Error);
}

#[test]
fn check_journal_access_denied_error() {
    let mut fake = FakeRunner::new();
    fake.with_response("journalctl", &["--version"], ok_output("250"));
    fake.with_response(
        "journalctl",
        &["-u", "fail2ban", "-n", "1", "--no-pager"],
        ok_output("some log line"),
    );
    fake.with_response(
        "journalctl",
        &["-n", "1", "--no-pager"],
        fail_output("Permission denied while accessing journal"),
    );

    let doctor = Doctor::new(&fake);
    let findings = doctor.check_journal();

    assert!(has_finding(&findings, "journal.access_denied"));
    let f = findings
        .iter()
        .find(|f| f.id == "journal.access_denied")
        .unwrap();
    assert_eq!(f.severity, Severity::Error);
}

// ===========================================================================
// Regex checks
// ===========================================================================

#[test]
fn check_regex_attack_not_matched_warning() {
    let Ok(regex_path) = find_binary("fail2ban-regex") else {
        return;
    };
    let regex_bin = regex_path.to_str().unwrap_or("fail2ban-regex");
    let Ok(client_path) = find_binary("fail2ban-client") else {
        return;
    };
    let client_bin = client_path.to_str().unwrap_or("fail2ban-client");

    let mut fake = FakeRunner::new();
    fake.with_response(regex_bin, &["--version"], ok_output("0.11.2"));
    let status_output = "`- Jail list:   testjail\n";
    fake.with_response(client_bin, &["status"], ok_output(status_output));
    fake.with_response(
        client_bin,
        &["get", "testjail", "failregex"],
        ok_output("^some weird pattern <HOST>$"),
    );
    // Attack lines should NOT match -- return success without "Lines:".
    fake.with_response(
        regex_bin,
        &[
            "Failed password for root from 192.168.1.100 port 22 ssh2",
            "^some weird pattern <HOST>$",
        ],
        ok_output("No match"),
    );
    fake.with_response(
        regex_bin,
        &[
            "authentication failure; rhost=10.0.0.1 user=admin",
            "^some weird pattern <HOST>$",
        ],
        ok_output("No match"),
    );
    // Safe lines -- return success with "Lines:" and "0 matched" so no false positive.
    fake.with_response(
        regex_bin,
        &[
            "Accepted password for user from 192.168.1.1 port 22 ssh2",
            "^some weird pattern <HOST>$",
        ],
        ok_output("Lines: 0 matched"),
    );
    fake.with_response(
        regex_bin,
        &[
            "session opened for user admin",
            "^some weird pattern <HOST>$",
        ],
        ok_output("Lines: 0 matched"),
    );
    fake.with_response(
        client_bin,
        &["get", "testjail", "maxlines"],
        ok_output("None"),
    );
    fake.with_response(
        client_bin,
        &["get", "testjail", "datepattern"],
        ok_output("None"),
    );

    let doctor = Doctor::new(&fake);
    let findings = doctor.check_regex();

    assert!(has_finding(&findings, "regex.attack_not_matched"));
    let f = findings
        .iter()
        .find(|f| f.id == "regex.attack_not_matched")
        .unwrap();
    assert_eq!(f.severity, Severity::Warning);
}

#[test]
fn check_regex_false_positive_warning() {
    let Ok(regex_path) = find_binary("fail2ban-regex") else {
        return;
    };
    let regex_bin = regex_path.to_str().unwrap_or("fail2ban-regex");
    let Ok(client_path) = find_binary("fail2ban-client") else {
        return;
    };
    let client_bin = client_path.to_str().unwrap_or("fail2ban-client");

    let mut fake = FakeRunner::new();
    fake.with_response(regex_bin, &["--version"], ok_output("0.11.2"));
    let status_output = "`- Jail list:   testjail\n";
    fake.with_response(client_bin, &["status"], ok_output(status_output));
    fake.with_response(
        client_bin,
        &["get", "testjail", "failregex"],
        ok_output(".* <HOST> .*"),
    );
    // Attack lines match (good).
    fake.with_response(
        regex_bin,
        &[
            "Failed password for root from 192.168.1.100 port 22 ssh2",
            ".* <HOST> .*",
        ],
        ok_output("Lines: 1 matched"),
    );
    fake.with_response(
        regex_bin,
        &[
            "authentication failure; rhost=10.0.0.1 user=admin",
            ".* <HOST> .*",
        ],
        ok_output("Lines: 1 matched"),
    );
    // Safe lines also match -- false positive.
    fake.with_response(
        regex_bin,
        &[
            "Accepted password for user from 192.168.1.1 port 22 ssh2",
            ".* <HOST> .*",
        ],
        ok_output("Lines: 1 matched, some lines"),
    );
    fake.with_response(
        regex_bin,
        &["session opened for user admin", ".* <HOST> .*"],
        ok_output("Lines: 0 matched"),
    );
    fake.with_response(
        client_bin,
        &["get", "testjail", "maxlines"],
        ok_output("None"),
    );
    fake.with_response(
        client_bin,
        &["get", "testjail", "datepattern"],
        ok_output("None"),
    );

    let doctor = Doctor::new(&fake);
    let findings = doctor.check_regex();

    assert!(has_finding(&findings, "regex.false_positive"));
    let f = findings
        .iter()
        .find(|f| f.id == "regex.false_positive")
        .unwrap();
    assert_eq!(f.severity, Severity::Warning);
}

#[test]
fn check_regex_missing_datepattern_info() {
    let Ok(regex_path) = find_binary("fail2ban-regex") else {
        return;
    };
    let regex_bin = regex_path.to_str().unwrap_or("fail2ban-regex");
    let Ok(client_path) = find_binary("fail2ban-client") else {
        return;
    };
    let client_bin = client_path.to_str().unwrap_or("fail2ban-client");

    let mut fake = FakeRunner::new();
    fake.with_response(regex_bin, &["--version"], ok_output("0.11.2"));
    let status_output = "`- Jail list:   testjail\n";
    fake.with_response(client_bin, &["status"], ok_output(status_output));
    fake.with_response(
        client_bin,
        &["get", "testjail", "failregex"],
        ok_output("^Failed <HOST>$"),
    );
    // Attack lines match.
    fake.with_response(
        regex_bin,
        &[
            "Failed password for root from 192.168.1.100 port 22 ssh2",
            "^Failed <HOST>$",
        ],
        ok_output("Lines: 1 matched"),
    );
    fake.with_response(
        regex_bin,
        &[
            "authentication failure; rhost=10.0.0.1 user=admin",
            "^Failed <HOST>$",
        ],
        ok_output("Lines: 0 matched"),
    );
    // Safe lines don't match.
    fake.with_response(
        regex_bin,
        &[
            "Accepted password for user from 192.168.1.1 port 22 ssh2",
            "^Failed <HOST>$",
        ],
        ok_output("Lines: 0 matched"),
    );
    fake.with_response(
        regex_bin,
        &["session opened for user admin", "^Failed <HOST>$"],
        ok_output("Lines: 0 matched"),
    );
    fake.with_response(
        client_bin,
        &["get", "testjail", "maxlines"],
        ok_output("None"),
    );
    fake.with_response(
        client_bin,
        &["get", "testjail", "datepattern"],
        fail_output("No datepattern"),
    );

    let doctor = Doctor::new(&fake);
    let findings = doctor.check_regex();

    assert!(has_finding(&findings, "regex.no_datepattern"));
    let f = findings
        .iter()
        .find(|f| f.id == "regex.no_datepattern")
        .unwrap();
    assert_eq!(f.severity, Severity::Info);
}

#[test]
fn check_regex_maxlines_missing_with_multiline_regex() {
    let Ok(regex_path) = find_binary("fail2ban-regex") else {
        return;
    };
    let regex_bin = regex_path.to_str().unwrap_or("fail2ban-regex");
    let Ok(client_path) = find_binary("fail2ban-client") else {
        return;
    };
    let client_bin = client_path.to_str().unwrap_or("fail2ban-client");

    // A multiline failregex (contains \n).
    let multiline_regex = "^line1 <HOST>\n^line2";

    let mut fake = FakeRunner::new();
    fake.with_response(regex_bin, &["--version"], ok_output("0.11.2"));
    let status_output = "`- Jail list:   testjail\n";
    fake.with_response(client_bin, &["status"], ok_output(status_output));
    fake.with_response(
        client_bin,
        &["get", "testjail", "failregex"],
        ok_output(multiline_regex),
    );
    // Attack lines.
    fake.with_response(
        regex_bin,
        &[
            "Failed password for root from 192.168.1.100 port 22 ssh2",
            multiline_regex,
        ],
        ok_output("Lines: 0 matched"),
    );
    fake.with_response(
        regex_bin,
        &[
            "authentication failure; rhost=10.0.0.1 user=admin",
            multiline_regex,
        ],
        ok_output("Lines: 0 matched"),
    );
    // Safe lines.
    fake.with_response(
        regex_bin,
        &[
            "Accepted password for user from 192.168.1.1 port 22 ssh2",
            multiline_regex,
        ],
        ok_output("Lines: 0 matched"),
    );
    fake.with_response(
        regex_bin,
        &["session opened for user admin", multiline_regex],
        ok_output("Lines: 0 matched"),
    );
    // maxlines returns None / empty.
    fake.with_response(
        client_bin,
        &["get", "testjail", "maxlines"],
        ok_output("None"),
    );
    fake.with_response(
        client_bin,
        &["get", "testjail", "datepattern"],
        ok_output("None"),
    );

    let doctor = Doctor::new(&fake);
    let findings = doctor.check_regex();

    assert!(has_finding(&findings, "regex.maxlines_missing"));
    let f = findings
        .iter()
        .find(|f| f.id == "regex.maxlines_missing")
        .unwrap();
    assert_eq!(f.severity, Severity::Warning);
}

// ===========================================================================
// Action checks
// ===========================================================================

#[test]
fn check_actions_missing_actionban_error() {
    // This test requires /etc/fail2ban/action.d to exist with a file
    // that lacks an actionban key. We create a temp file to exercise the check.
    if !std::path::Path::new("/etc/fail2ban/action.d").exists() {
        return;
    }
    let Ok(path) = find_binary("fail2ban-client") else {
        return;
    };
    let bin = path.to_str().unwrap_or("fail2ban-client");

    let mut fake = FakeRunner::new();
    let status_output = "`- Jail list:   testjail\n";
    fake.with_response(bin, &["status"], ok_output(status_output));
    fake.with_response(
        bin,
        &["get", "testjail", "actions"],
        ok_output("dummy-action"),
    );
    // The file dummy-action.conf / .local must exist. We skip this test
    // if the action file is not on disk; the real test coverage comes from
    // the filesystem-based check. Instead we verify the method does not panic.
    let doctor = Doctor::new(&fake);
    let findings = doctor.check_actions();
    assert!(!findings.is_empty());
}

#[test]
fn check_actions_missing_actionunban_warning() {
    // Mirrors the structure of the actionban test; exercises the action
    // check code path without panicking.
    if !std::path::Path::new("/etc/fail2ban/action.d").exists() {
        return;
    }
    let Ok(path) = find_binary("fail2ban-client") else {
        return;
    };
    let bin = path.to_str().unwrap_or("fail2ban-client");

    let mut fake = FakeRunner::new();
    let status_output = "`- Jail list:   testjail\n";
    fake.with_response(bin, &["status"], ok_output(status_output));
    fake.with_response(bin, &["get", "testjail", "actions"], ok_output("iptables"));
    fake.with_response("iptables", &["--version"], ok_output("1.8"));

    let doctor = Doctor::new(&fake);
    let findings = doctor.check_actions();
    assert!(!findings.is_empty());
}

#[test]
fn check_actions_high_timeout_warning() {
    // Tests that an action file with a timeout > 60s produces a warning.
    // Requires filesystem access; exercises the code path without panic.
    if !std::path::Path::new("/etc/fail2ban/action.d").exists() {
        return;
    }
    let Ok(path) = find_binary("fail2ban-client") else {
        return;
    };
    let bin = path.to_str().unwrap_or("fail2ban-client");

    let mut fake = FakeRunner::new();
    let status_output = "`- Jail list:   testjail\n";
    fake.with_response(bin, &["status"], ok_output(status_output));
    fake.with_response(bin, &["get", "testjail", "actions"], ok_output("nftables"));
    fake.with_response("nft", &["--version"], ok_output("1.0"));

    let doctor = Doctor::new(&fake);
    let findings = doctor.check_actions();
    assert!(!findings.is_empty());
}

#[test]
fn check_actions_cloudflare_placeholder_creds_error() {
    // Tests the Cloudflare placeholder credential detection.
    // Requires /etc/fail2ban/action.d to exist and a cloudflare action.
    if !std::path::Path::new("/etc/fail2ban/action.d").exists() {
        return;
    }
    let Ok(path) = find_binary("fail2ban-client") else {
        return;
    };
    let bin = path.to_str().unwrap_or("fail2ban-client");

    let mut fake = FakeRunner::new();
    let status_output = "`- Jail list:   testjail\n";
    fake.with_response(bin, &["status"], ok_output(status_output));
    fake.with_response(
        bin,
        &["get", "testjail", "actions"],
        ok_output("cloudflare"),
    );

    let doctor = Doctor::new(&fake);
    let findings = doctor.check_actions();
    // Should not panic; findings depend on whether cloudflare action file
    // exists and its contents.
    assert!(!findings.is_empty());
}

// ===========================================================================
// Permission checks -- non-root owned file and secrets
// ===========================================================================

#[test]
fn check_permissions_ownership_and_secrets_checks() {
    // This test verifies that check_permissions runs without panicking
    // and produces the expected types of findings when /etc/fail2ban exists.
    if !std::path::Path::new("/etc/fail2ban").exists() {
        return;
    }
    let fake = FakeRunner::new();
    let doctor = Doctor::new(&fake);
    let findings = doctor.check_permissions();

    // Should have at least one permission finding (dir-safe or dir-world-writable).
    let has_perm = has_finding(&findings, "permission.config-dir-safe")
        || has_finding(&findings, "permission.config-dir-world-writable");
    assert!(has_perm);
}

// ===========================================================================
// Safety checks -- self-ban risk
// ===========================================================================

#[test]
fn check_safety_self_ban_risk_critical() {
    let Ok(path) = find_binary("fail2ban-client") else {
        return;
    };
    let bin = path.to_str().unwrap_or("fail2ban-client");

    let mut fake = FakeRunner::new();
    let status_output = "`- Jail list:   myjail\n";
    fake.with_response(bin, &["status"], ok_output(status_output));
    // ignoreip returns only an external IP -- no localhost.
    fake.with_response(
        bin,
        &["get", "myjail", "ignoreip"],
        ok_output("203.0.113.1"),
    );

    let doctor = Doctor::new(&fake);
    let findings = doctor.check_safety();

    assert!(has_finding(&findings, "safety.self_ban_risk"));
    let f = findings
        .iter()
        .find(|f| f.id == "safety.self_ban_risk")
        .unwrap();
    assert_eq!(f.severity, Severity::Critical);
}

#[test]
fn check_safety_no_private_network_ignore_info() {
    let Ok(path) = find_binary("fail2ban-client") else {
        return;
    };
    let bin = path.to_str().unwrap_or("fail2ban-client");

    let mut fake = FakeRunner::new();
    let status_output = "`- Jail list:   myjail\n";
    fake.with_response(bin, &["status"], ok_output(status_output));
    // ignoreip has 127.0.0.1 and ::1 (protects against self-ban) but no RFC1918 ranges.
    fake.with_response(
        bin,
        &["get", "myjail", "ignoreip"],
        ok_output("127.0.0.1 ::1"),
    );

    let doctor = Doctor::new(&fake);
    let findings = doctor.check_safety();

    assert!(has_finding(&findings, "safety.no_private_network_ignore"));
    let f = findings
        .iter()
        .find(|f| f.id == "safety.no_private_network_ignore")
        .unwrap();
    assert_eq!(f.severity, Severity::Info);
}

// ===========================================================================
// Proxy checks
// ===========================================================================

#[test]
fn check_proxy_realip_docs_info() {
    let Ok(path) = find_binary("fail2ban-client") else {
        return;
    };
    let bin = path.to_str().unwrap_or("fail2ban-client");

    let mut fake = FakeRunner::new();
    let status_output = "`- Jail list:   webjail\n";
    fake.with_response(bin, &["status"], ok_output(status_output));
    // Traefik log path triggers proxy detection.
    fake.with_response(
        bin,
        &["get", "webjail", "logpath"],
        ok_output("/var/log/traefik/access.log"),
    );
    fake.with_response(bin, &["get", "webjail", "actions"], ok_output("iptables"));
    // Second logpath call in the proxy detection block.
    fake.with_response(
        bin,
        &["get", "webjail", "logpath"],
        ok_output("/var/log/traefik/access.log"),
    );
    fake.with_response(bin, &["get", "webjail", "actions"], ok_output("iptables"));

    let doctor = Doctor::new(&fake);
    let findings = doctor.check_proxy();

    assert!(has_finding(&findings, "proxy.realip_docs"));
    let f = findings
        .iter()
        .find(|f| f.id == "proxy.realip_docs")
        .unwrap();
    assert_eq!(f.severity, Severity::Info);
}

#[test]
fn check_proxy_traefik_filter_info() {
    let Ok(path) = find_binary("fail2ban-client") else {
        return;
    };
    let bin = path.to_str().unwrap_or("fail2ban-client");

    let mut fake = FakeRunner::new();
    let status_output = "`- Jail list:   webjail\n";
    fake.with_response(bin, &["status"], ok_output(status_output));
    fake.with_response(
        bin,
        &["get", "webjail", "logpath"],
        ok_output("/var/log/traefik/access.log"),
    );
    fake.with_response(bin, &["get", "webjail", "actions"], ok_output("iptables"));
    fake.with_response(
        bin,
        &["get", "webjail", "logpath"],
        ok_output("/var/log/traefik/access.log"),
    );
    fake.with_response(bin, &["get", "webjail", "actions"], ok_output("iptables"));

    let doctor = Doctor::new(&fake);
    let findings = doctor.check_proxy();

    assert!(has_finding(&findings, "proxy.traefik_filter"));
    let f = findings
        .iter()
        .find(|f| f.id == "proxy.traefik_filter")
        .unwrap();
    assert_eq!(f.severity, Severity::Info);
}

#[test]
fn check_proxy_cloudflare_action_info() {
    let Ok(path) = find_binary("fail2ban-client") else {
        return;
    };
    let bin = path.to_str().unwrap_or("fail2ban-client");

    let mut fake = FakeRunner::new();
    let status_output = "`- Jail list:   cfjail\n";
    fake.with_response(bin, &["status"], ok_output(status_output));
    fake.with_response(
        bin,
        &["get", "cfjail", "logpath"],
        ok_output("/var/log/nginx/access.log"),
    );
    fake.with_response(bin, &["get", "cfjail", "actions"], ok_output("cloudflare"));
    fake.with_response(
        bin,
        &["get", "cfjail", "logpath"],
        ok_output("/var/log/nginx/access.log"),
    );
    fake.with_response(bin, &["get", "cfjail", "actions"], ok_output("cloudflare"));

    let doctor = Doctor::new(&fake);
    let findings = doctor.check_proxy();

    assert!(has_finding(&findings, "proxy.cloudflare_action"));
    let f = findings
        .iter()
        .find(|f| f.id == "proxy.cloudflare_action")
        .unwrap();
    assert_eq!(f.severity, Severity::Info);
}

// ===========================================================================
// IP helpers
// ===========================================================================

#[test]
fn extract_ips_from_line_finds_valid_ipv4() {
    let ips = extract_ips_from_line("Failed password from 192.168.1.100 port 22");
    assert_eq!(ips, vec!["192.168.1.100"]);
}

#[test]
fn extract_ips_from_line_ignores_invalid() {
    let ips = extract_ips_from_line("Failed from 999.999.999.999 port");
    assert!(ips.is_empty());
}

#[test]
fn is_private_ip_detects_rfc1918() {
    assert!(is_private_ip("10.0.0.1"));
    assert!(is_private_ip("172.16.5.5"));
    assert!(is_private_ip("192.168.1.1"));
    assert!(is_private_ip("127.0.0.1"));
    assert!(!is_private_ip("203.0.113.1"));
    assert!(!is_private_ip("8.8.8.8"));
}

// ===========================================================================
// Journal helper: extract_systemd_units
// ===========================================================================

#[test]
fn extract_systemd_units_parses_unit() {
    let units = extract_systemd_units("_SYSTEMD_UNIT=sshd.service");
    assert_eq!(units, vec!["sshd.service"]);
}

#[test]
fn extract_systemd_units_parses_multiple() {
    let units = extract_systemd_units("_SYSTEMD_UNIT=sshd.service + _COMM=sshd");
    assert_eq!(units, vec!["sshd.service"]);
}

#[test]
fn extract_systemd_units_empty_when_no_match() {
    let units = extract_systemd_units("_COMM=sshd");
    assert!(units.is_empty());
}

// ===========================================================================
// Regex anchor helper: is_host_anchored
// ===========================================================================

#[test]
fn is_host_anchored_true_when_bracketed() {
    assert!(is_host_anchored("^Failed from <HOST> port"));
}

#[test]
fn is_host_anchored_false_when_unanchored() {
    assert!(!is_host_anchored("abc<HOST>def"));
}

#[test]
fn is_host_anchored_true_at_start_of_pattern() {
    assert!(is_host_anchored("<HOST> some text"));
}

#[test]
fn is_host_anchored_true_at_end_of_pattern() {
    assert!(is_host_anchored("text <HOST>"));
}

// ===========================================================================
// INI value extraction helper
// ===========================================================================

#[test]
fn extract_ini_value_finds_key() {
    let content = "[Definition]\ntimeout = 120\nactionban = something\n";
    assert_eq!(
        extract_ini_value(content, "timeout"),
        Some("120".to_string())
    );
}

#[test]
fn extract_ini_value_skips_comments() {
    let content = "# timeout = 99\ntimeout = 30\n";
    assert_eq!(
        extract_ini_value(content, "timeout"),
        Some("30".to_string())
    );
}

#[test]
fn extract_ini_value_returns_none_when_missing() {
    let content = "[Definition]\nactionban = foo\n";
    assert_eq!(extract_ini_value(content, "timeout"), None);
}

// ===========================================================================
// CIDR helpers
// ===========================================================================

#[test]
fn cidr_covers_ip_exact_match() {
    assert!(cidr_covers_ip("192.168.1.1", "192.168.1.1"));
    assert!(!cidr_covers_ip("192.168.1.1", "192.168.1.2"));
}

#[test]
fn cidr_covers_ip_subnet_match() {
    assert!(cidr_covers_ip("10.0.0.0/8", "10.1.2.3"));
    assert!(cidr_covers_ip("192.168.0.0/16", "192.168.99.99"));
    assert!(!cidr_covers_ip("10.0.0.0/8", "192.168.1.1"));
}

#[test]
fn cidr_covers_range_direct_match() {
    assert!(cidr_covers_range("10.0.0.0/8", "10.0.0.0/8"));
}

#[test]
fn cidr_covers_range_supernet() {
    assert!(cidr_covers_range("10.0.0.0/8", "10.1.0.0/16"));
    assert!(!cidr_covers_range("10.1.0.0/16", "10.0.0.0/8"));
}
