use super::*;

// ---------------------------------------------------------------------------
// Severity
// ---------------------------------------------------------------------------

#[test]
fn severity_ordering_ok_less_than_info() {
    assert!(Severity::Ok < Severity::Info);
}

#[test]
fn severity_ordering_info_less_than_warning() {
    assert!(Severity::Info < Severity::Warning);
}

#[test]
fn severity_ordering_warning_less_than_error() {
    assert!(Severity::Warning < Severity::Error);
}

#[test]
fn severity_ordering_error_less_than_critical() {
    assert!(Severity::Error < Severity::Critical);
}

#[test]
fn severity_ordering_full_chain() {
    assert!(Severity::Ok < Severity::Info);
    assert!(Severity::Info < Severity::Warning);
    assert!(Severity::Warning < Severity::Error);
    assert!(Severity::Error < Severity::Critical);
}

#[test]
fn severity_equality() {
    assert_eq!(Severity::Ok, Severity::Ok);
    assert_eq!(Severity::Critical, Severity::Critical);
    assert_ne!(Severity::Ok, Severity::Info);
}

#[test]
fn severity_display() {
    assert_eq!(format!("{}", Severity::Ok), "OK");
    assert_eq!(format!("{}", Severity::Info), "INFO");
    assert_eq!(format!("{}", Severity::Warning), "WARNING");
    assert_eq!(format!("{}", Severity::Error), "ERROR");
    assert_eq!(format!("{}", Severity::Critical), "CRITICAL");
}

#[test]
fn severity_sort_order() {
    let mut v = vec![
        Severity::Critical,
        Severity::Ok,
        Severity::Error,
        Severity::Info,
        Severity::Warning,
    ];
    v.sort();
    assert_eq!(
        v,
        vec![
            Severity::Ok,
            Severity::Info,
            Severity::Warning,
            Severity::Error,
            Severity::Critical,
        ]
    );
}

// ---------------------------------------------------------------------------
// Finding — construction
// ---------------------------------------------------------------------------

#[test]
fn finding_new_sets_mandatory_fields() {
    let f = Finding::new("test.id", Severity::Warning, "Something wrong");
    assert_eq!(f.id, "test.id");
    assert_eq!(f.severity, Severity::Warning);
    assert_eq!(f.title, "Something wrong");
}

#[test]
fn finding_new_defaults_detail_empty() {
    let f = Finding::new("id", Severity::Ok, "t");
    assert!(f.detail.is_empty());
}

#[test]
fn finding_new_defaults_fix_none() {
    let f = Finding::new("id", Severity::Ok, "t");
    assert!(f.fix.is_none());
}

#[test]
fn finding_detail_builder() {
    let f = Finding::new("id", Severity::Info, "title").detail("longer explanation");
    assert_eq!(f.detail, "longer explanation");
}

#[test]
fn finding_fix_builder() {
    let f = Finding::new("id", Severity::Error, "title").fix("do this");
    assert_eq!(f.fix.as_deref(), Some("do this"));
}

#[test]
fn finding_chained_detail_and_fix() {
    let f = Finding::new("a.b.c", Severity::Critical, "broken")
        .detail("It is very broken.")
        .fix("Reinstall everything.");
    assert_eq!(f.id, "a.b.c");
    assert_eq!(f.severity, Severity::Critical);
    assert_eq!(f.title, "broken");
    assert_eq!(f.detail, "It is very broken.");
    assert_eq!(f.fix.as_deref(), Some("Reinstall everything."));
}

#[test]
fn finding_detail_replaces_previous() {
    let f = Finding::new("id", Severity::Ok, "t")
        .detail("first")
        .detail("second");
    assert_eq!(f.detail, "second");
}

#[test]
fn finding_fix_replaces_previous() {
    let f = Finding::new("id", Severity::Ok, "t")
        .fix("first")
        .fix("second");
    assert_eq!(f.fix.as_deref(), Some("second"));
}

// ---------------------------------------------------------------------------
// ApplyReport
// ---------------------------------------------------------------------------

#[test]
fn apply_report_empty_constructor() {
    let r = ApplyReport::empty();
    assert!(r.files_written.is_empty());
    assert!(r.files_removed.is_empty());
    assert!(r.backup_paths.is_empty());
    assert!(r.test_passed);
    assert!(r.reload_result.is_none());
    assert!(r.findings.is_empty());
}

#[test]
fn apply_report_is_empty_when_truly_empty() {
    let r = ApplyReport::empty();
    assert!(r.is_empty());
}

#[test]
fn apply_report_is_not_empty_with_written_files() {
    let mut r = ApplyReport::empty();
    r.files_written
        .push("/etc/fail2ban/jail.d/test.conf".into());
    assert!(!r.is_empty());
}

#[test]
fn apply_report_is_not_empty_with_removed_files() {
    let mut r = ApplyReport::empty();
    r.files_removed.push("/etc/fail2ban/old.conf".into());
    assert!(!r.is_empty());
}

#[test]
fn apply_report_is_not_empty_with_findings() {
    let mut r = ApplyReport::empty();
    r.findings.push(Finding::new("x", Severity::Warning, "w"));
    assert!(!r.is_empty());
}

#[test]
fn apply_report_field_access() {
    let r = ApplyReport {
        files_written: vec!["a".into(), "b".into()],
        files_removed: vec!["c".into()],
        backup_paths: vec!["a.bak".into()],
        test_passed: false,
        reload_result: Some("reload failed".into()),
        findings: vec![Finding::new("f", Severity::Error, "err")],
    };
    assert_eq!(r.files_written.len(), 2);
    assert_eq!(r.files_removed.len(), 1);
    assert_eq!(r.backup_paths.len(), 1);
    assert!(!r.test_passed);
    assert_eq!(r.reload_result.as_deref(), Some("reload failed"));
    assert_eq!(r.findings.len(), 1);
}

// ---------------------------------------------------------------------------
// RollbackReport
// ---------------------------------------------------------------------------

#[test]
fn rollback_report_success() {
    let r = RollbackReport::success(vec!["jail.conf".into(), "filter.conf".into()]);
    assert_eq!(r.restored_files.len(), 2);
    assert!(r.test_passed);
    assert!(r.reload_result.is_none());
    assert!(r.findings.is_empty());
}

#[test]
fn rollback_report_success_empty() {
    let r = RollbackReport::success(vec![]);
    assert!(r.restored_files.is_empty());
    assert!(r.test_passed);
}

#[test]
fn rollback_report_manual_construction() {
    let r = RollbackReport {
        restored_files: vec!["x".into()],
        test_passed: false,
        reload_result: Some("err".into()),
        findings: vec![Finding::new("r", Severity::Warning, "w")],
    };
    assert_eq!(r.restored_files.len(), 1);
    assert!(!r.test_passed);
    assert_eq!(r.reload_result.as_deref(), Some("err"));
    assert_eq!(r.findings.len(), 1);
}

// ---------------------------------------------------------------------------
// DoctorReport
// ---------------------------------------------------------------------------

#[test]
fn doctor_report_empty() {
    let r = DoctorReport::empty();
    assert!(r.is_empty());
    assert_eq!(r.len(), 0);
}

#[test]
fn doctor_report_push() {
    let mut r = DoctorReport::empty();
    r.push(Finding::new("a", Severity::Ok, "ok"));
    assert_eq!(r.len(), 1);
    assert!(!r.is_empty());
    r.push(Finding::new("b", Severity::Info, "info"));
    assert_eq!(r.len(), 2);
}

#[test]
fn doctor_report_summary_by_severity_groups_correctly() {
    let mut r = DoctorReport::empty();
    r.push(Finding::new("a", Severity::Ok, "ok1"));
    r.push(Finding::new("b", Severity::Ok, "ok2"));
    r.push(Finding::new("c", Severity::Error, "err1"));
    r.push(Finding::new("d", Severity::Warning, "warn1"));

    let summary = r.summary_by_severity();
    assert_eq!(summary.len(), 3);
    assert_eq!(summary[&Severity::Ok].len(), 2);
    assert_eq!(summary[&Severity::Warning].len(), 1);
    assert_eq!(summary[&Severity::Error].len(), 1);
}

#[test]
fn doctor_report_summary_by_severity_empty_report() {
    let r = DoctorReport::empty();
    let summary = r.summary_by_severity();
    assert!(summary.is_empty());
}

#[test]
fn doctor_report_summary_by_severity_keys_are_ordered() {
    let mut r = DoctorReport::empty();
    r.push(Finding::new("c", Severity::Critical, "crit"));
    r.push(Finding::new("o", Severity::Ok, "ok"));
    r.push(Finding::new("e", Severity::Error, "err"));

    let summary = r.summary_by_severity();
    let keys: Vec<&Severity> = summary.keys().collect();
    assert_eq!(
        keys,
        vec![&Severity::Ok, &Severity::Error, &Severity::Critical]
    );
}

#[test]
fn doctor_report_has_errors_true_with_error() {
    let mut r = DoctorReport::empty();
    r.push(Finding::new("e", Severity::Error, "err"));
    assert!(r.has_errors());
}

#[test]
fn doctor_report_has_errors_true_with_critical() {
    let mut r = DoctorReport::empty();
    r.push(Finding::new("c", Severity::Critical, "crit"));
    assert!(r.has_errors());
}

#[test]
fn doctor_report_has_errors_false_with_only_warnings() {
    let mut r = DoctorReport::empty();
    r.push(Finding::new("w", Severity::Warning, "warn"));
    r.push(Finding::new("i", Severity::Info, "info"));
    r.push(Finding::new("o", Severity::Ok, "ok"));
    assert!(!r.has_errors());
}

#[test]
fn doctor_report_has_errors_false_when_empty() {
    let r = DoctorReport::empty();
    assert!(!r.has_errors());
}

#[test]
fn doctor_report_has_critical_true() {
    let mut r = DoctorReport::empty();
    r.push(Finding::new("ok", Severity::Ok, "ok"));
    r.push(Finding::new("crit", Severity::Critical, "critical issue"));
    assert!(r.has_critical());
}

#[test]
fn doctor_report_has_critical_false() {
    let mut r = DoctorReport::empty();
    r.push(Finding::new("e", Severity::Error, "err"));
    r.push(Finding::new("w", Severity::Warning, "warn"));
    assert!(!r.has_critical());
}

#[test]
fn doctor_report_has_critical_false_when_empty() {
    let r = DoctorReport::empty();
    assert!(!r.has_critical());
}

// ---------------------------------------------------------------------------
// RegexTestResult
// ---------------------------------------------------------------------------

#[test]
fn regex_test_result_new() {
    let r = RegexTestResult::new(5, 10, "output text", true);
    assert_eq!(r.lines_matched, 5);
    assert_eq!(r.lines_processed, 10);
    assert_eq!(r.output, "output text");
    assert!(r.success);
}

#[test]
fn regex_test_result_match_rate_normal() {
    let r = RegexTestResult::new(3, 10, "", true);
    let rate = r.match_rate();
    assert!((rate - 0.3).abs() < f64::EPSILON);
}

#[test]
fn regex_test_result_match_rate_all_matched() {
    let r = RegexTestResult::new(10, 10, "", true);
    assert!((r.match_rate() - 1.0).abs() < f64::EPSILON);
}

#[test]
fn regex_test_result_match_rate_none_matched() {
    let r = RegexTestResult::new(0, 10, "", false);
    assert!((r.match_rate() - 0.0).abs() < f64::EPSILON);
}

#[test]
fn regex_test_result_match_rate_zero_lines_processed() {
    let r = RegexTestResult::new(0, 0, "", false);
    assert!((r.match_rate() - 0.0).abs() < f64::EPSILON);
}

#[test]
fn regex_test_result_success_false() {
    let r = RegexTestResult::new(0, 5, "fail", false);
    assert!(!r.success);
}

// ---------------------------------------------------------------------------
// StatusReport
// ---------------------------------------------------------------------------

#[test]
fn status_report_stopped() {
    let r = StatusReport::stopped("sshd");
    assert_eq!(r.jail_name, "sshd");
    assert!(!r.is_running);
    assert!(r.banned_ips.is_empty());
    assert_eq!(r.file_count, 0);
    assert_eq!(r.ban_count, 0);
}

#[test]
fn status_report_has_bans_true() {
    let r = StatusReport {
        jail_name: "nginx".into(),
        is_running: true,
        banned_ips: vec!["1.2.3.4".into()],
        file_count: 2,
        ban_count: 5,
    };
    assert!(r.has_bans());
}

#[test]
fn status_report_has_bans_false() {
    let r = StatusReport {
        jail_name: "nginx".into(),
        is_running: true,
        banned_ips: vec![],
        file_count: 1,
        ban_count: 0,
    };
    assert!(!r.has_bans());
}

#[test]
fn status_report_stopped_has_no_bans() {
    let r = StatusReport::stopped("apache");
    assert!(!r.has_bans());
}

#[test]
fn status_report_full_construction() {
    let r = StatusReport {
        jail_name: "postfix".into(),
        is_running: true,
        banned_ips: vec!["10.0.0.1".into(), "10.0.0.2".into()],
        file_count: 3,
        ban_count: 42,
    };
    assert_eq!(r.jail_name, "postfix");
    assert!(r.is_running);
    assert_eq!(r.banned_ips.len(), 2);
    assert_eq!(r.file_count, 3);
    assert_eq!(r.ban_count, 42);
}

// ---------------------------------------------------------------------------
// Serialization roundtrips
// ---------------------------------------------------------------------------

#[test]
fn severity_serde_roundtrip() {
    let json = serde_json::to_string(&Severity::Critical).unwrap();
    assert_eq!(json, "\"critical\"");
    let back: Severity = serde_json::from_str(&json).unwrap();
    assert_eq!(back, Severity::Critical);
}

#[test]
fn severity_all_variants_roundtrip() {
    let variants = [
        Severity::Ok,
        Severity::Info,
        Severity::Warning,
        Severity::Error,
        Severity::Critical,
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let back: Severity = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, v);
    }
}

#[test]
fn finding_serde_roundtrip() {
    let f = Finding::new("test.id", Severity::Warning, "title")
        .detail("some detail")
        .fix("apply patch");
    let json = serde_json::to_string(&f).unwrap();
    let back: Finding = serde_json::from_str(&json).unwrap();
    assert_eq!(back.id, "test.id");
    assert_eq!(back.severity, Severity::Warning);
    assert_eq!(back.title, "title");
    assert_eq!(back.detail, "some detail");
    assert_eq!(back.fix.as_deref(), Some("apply patch"));
}

#[test]
fn finding_serde_roundtrip_no_optional_fields() {
    let f = Finding::new("id", Severity::Ok, "t");
    let json = serde_json::to_string(&f).unwrap();
    let back: Finding = serde_json::from_str(&json).unwrap();
    assert!(back.detail.is_empty());
    assert!(back.fix.is_none());
}

#[test]
fn apply_report_serde_roundtrip() {
    let r = ApplyReport {
        files_written: vec!["/etc/a".into()],
        files_removed: vec![],
        backup_paths: vec!["/bak/a".into()],
        test_passed: true,
        reload_result: Some("ok".into()),
        findings: vec![Finding::new("f", Severity::Info, "note")],
    };
    let json = serde_json::to_string(&r).unwrap();
    let back: ApplyReport = serde_json::from_str(&json).unwrap();
    assert_eq!(back.files_written, r.files_written);
    assert_eq!(back.files_removed, r.files_removed);
    assert_eq!(back.backup_paths, r.backup_paths);
    assert_eq!(back.test_passed, r.test_passed);
    assert_eq!(back.reload_result, r.reload_result);
    assert_eq!(back.findings.len(), 1);
    assert_eq!(back.findings[0].id, "f");
}

#[test]
fn rollback_report_serde_roundtrip() {
    let r = RollbackReport::success(vec!["jail.local".into()]);
    let json = serde_json::to_string(&r).unwrap();
    let back: RollbackReport = serde_json::from_str(&json).unwrap();
    assert_eq!(back.restored_files, vec!["jail.local"]);
    assert!(back.test_passed);
    assert!(back.findings.is_empty());
}

#[test]
fn doctor_report_serde_roundtrip() {
    let mut r = DoctorReport::empty();
    r.push(Finding::new("a", Severity::Error, "bad").fix("reinstall"));
    r.push(Finding::new("b", Severity::Ok, "good"));
    let json = serde_json::to_string(&r).unwrap();
    let back: DoctorReport = serde_json::from_str(&json).unwrap();
    assert_eq!(back.findings.len(), 2);
    assert_eq!(back.findings[0].severity, Severity::Error);
    assert_eq!(back.findings[1].severity, Severity::Ok);
    assert_eq!(back.findings[0].fix.as_deref(), Some("reinstall"));
}

#[test]
fn regex_test_result_serde_roundtrip() {
    let r = RegexTestResult::new(7, 20, "lines", true);
    let json = serde_json::to_string(&r).unwrap();
    let back: RegexTestResult = serde_json::from_str(&json).unwrap();
    assert_eq!(back.lines_matched, 7);
    assert_eq!(back.lines_processed, 20);
    assert_eq!(back.output, "lines");
    assert!(back.success);
    assert!((back.match_rate() - 0.35).abs() < f64::EPSILON);
}

#[test]
fn status_report_serde_roundtrip() {
    let r = StatusReport {
        jail_name: "dovecot".into(),
        is_running: true,
        banned_ips: vec!["192.168.1.1".into()],
        file_count: 1,
        ban_count: 3,
    };
    let json = serde_json::to_string(&r).unwrap();
    let back: StatusReport = serde_json::from_str(&json).unwrap();
    assert_eq!(back.jail_name, "dovecot");
    assert!(back.is_running);
    assert_eq!(back.banned_ips, vec!["192.168.1.1"]);
    assert_eq!(back.file_count, 1);
    assert_eq!(back.ban_count, 3);
}

// ---------------------------------------------------------------------------
// Empty report edge cases
// ---------------------------------------------------------------------------

#[test]
fn empty_doctor_report_summary_is_empty_map() {
    let r = DoctorReport::empty();
    assert!(r.summary_by_severity().is_empty());
}

#[test]
fn empty_doctor_report_has_no_errors_or_critical() {
    let r = DoctorReport::empty();
    assert!(!r.has_errors());
    assert!(!r.has_critical());
}

#[test]
fn empty_doctor_report_len_zero() {
    let r = DoctorReport::empty();
    assert_eq!(r.len(), 0);
}

#[test]
fn empty_apply_report_is_empty() {
    let r = ApplyReport::empty();
    assert!(r.is_empty());
}

#[test]
fn apply_report_with_only_backup_paths_still_empty() {
    let mut r = ApplyReport::empty();
    r.backup_paths.push("/bak/test".into());
    // is_empty only checks files_written, files_removed, and findings
    assert!(r.is_empty());
}

#[test]
fn apply_report_test_passed_false_still_empty() {
    let mut r = ApplyReport::empty();
    r.test_passed = false;
    // is_empty ignores test_passed
    assert!(r.is_empty());
}

#[test]
fn empty_rollback_report_findings() {
    let r = RollbackReport::success(vec![]);
    assert!(r.findings.is_empty());
}

#[test]
fn regex_test_result_zero_match_rate_on_zero_processed() {
    let r = RegexTestResult::new(0, 0, "n/a", false);
    assert!((r.match_rate()).abs() < f64::EPSILON);
}

#[test]
fn regex_test_result_partial_match_rate() {
    let r = RegexTestResult::new(1, 3, "", true);
    let expected = 1.0 / 3.0;
    assert!((r.match_rate() - expected).abs() < f64::EPSILON);
}
