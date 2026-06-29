use super::*;
use crate::command::DuctRunner;
use crate::types::ExecutionMode;
use std::io::Write;
use tempfile::{NamedTempFile, tempdir};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a `ResolvedJail` pointing at the given log path with a pattern that
/// captures an IPv4 address named group `ip`.
fn make_resolved_jail(log_path: &std::path::Path) -> crate::config::ResolvedJail {
    crate::config::ResolvedJail {
        name: "test-jail".to_string(),
        enabled: true,
        log_path: log_path.to_path_buf(),
        pattern: r"Failed login from (?P<ip>\d+\.\d+\.\d+\.\d+)".to_string(),
        find_time: 600,
        ban_time: 3600,
        max_retry: 1,
        ban_action: "ban".to_string(),
        unban_action: "unban".to_string(),
        ignore_ips: Vec::new(),
    }
}

/// Build a `ResolvedJail` with a pattern that also matches IPv6 addresses.
fn make_resolved_jail_dual(log_path: &std::path::Path) -> crate::config::ResolvedJail {
    crate::config::ResolvedJail {
        name: "test-jail".to_string(),
        enabled: true,
        log_path: log_path.to_path_buf(),
        pattern: r"Failed login from (?P<ip>[\da-fA-F:\.]+)".to_string(),
        find_time: 600,
        ban_time: 3600,
        max_retry: 1,
        ban_action: "ban".to_string(),
        unban_action: "unban".to_string(),
        ignore_ips: Vec::new(),
    }
}

/// Create a `Store` backed by a temporary directory.
fn make_store(dir: &std::path::Path) -> Store {
    Store::new(dir.join("bans.json"))
}

/// Create a fully wired test jail with a temp log file and temp store.
/// Returns `(jail, log_file, _tmpdir)` where `_tmpdir` must be kept alive.
fn setup_test_jail() -> (Jail, NamedTempFile, tempfile::TempDir) {
    let tmpdir = tempdir().expect("failed to create temp dir");
    let log_file = NamedTempFile::new_in(tmpdir.path()).expect("failed to create temp log file");
    let store = make_store(tmpdir.path());
    let config = make_resolved_jail(log_file.path());
    let jail =
        Jail::new(config, store, None, Box::new(DuctRunner::new())).expect("failed to create jail");
    (jail, log_file, tmpdir)
}

/// Same as above but with the dual-stack (v4+v6) pattern.
fn setup_test_jail_dual() -> (Jail, NamedTempFile, tempfile::TempDir) {
    let tmpdir = tempdir().expect("failed to create temp dir");
    let log_file = NamedTempFile::new_in(tmpdir.path()).expect("failed to create temp log file");
    let store = make_store(tmpdir.path());
    let config = make_resolved_jail_dual(log_file.path());
    let jail =
        Jail::new(config, store, None, Box::new(DuctRunner::new())).expect("failed to create jail");
    (jail, log_file, tmpdir)
}

// ---------------------------------------------------------------------------
// new()
// ---------------------------------------------------------------------------

#[test]
fn new_creates_jail_with_correct_name_and_log_path() {
    let (jail, log_file, _dir) = setup_test_jail();
    assert_eq!(jail.name(), "test-jail");
    assert_eq!(jail.log_path(), log_file.path());
}

#[test]
fn new_fails_with_invalid_regex_pattern() {
    let dir = tempdir().unwrap();
    let log_path = dir.path().join("auth.log");
    std::fs::write(&log_path, "").unwrap();

    let config = crate::config::ResolvedJail {
        name: "bad".to_string(),
        enabled: true,
        log_path,
        pattern: "(((".to_string(), // invalid regex
        find_time: 600,
        ban_time: 3600,
        max_retry: 1,
        ban_action: "ban".to_string(),
        unban_action: "unban".to_string(),
        ignore_ips: Vec::new(),
    };
    let store = make_store(dir.path());
    match Jail::new(config, store, None, Box::new(DuctRunner::new())) {
        Err(crate::Error::InvalidRegex(_)) => {}
        Err(other) => panic!("expected InvalidRegex, got: {other:?}"),
        Ok(_) => panic!("expected error, got Ok"),
    }
}

// ---------------------------------------------------------------------------
// with_ignore_ips()
// ---------------------------------------------------------------------------

#[test]
fn with_ignore_ips_sets_ignore_list() {
    let (jail, _log, _dir) = setup_test_jail();
    let mut jail = jail.with_ignore_ips(vec!["10.0.0.1".to_string(), "192.168.0.0/16".to_string()]);

    // ban_ip on an ignored IP should fail.
    let ip: std::net::IpAddr = "10.0.0.1".parse().unwrap();
    let result = jail.ban_ip(ip, ExecutionMode::DryRun);
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// name() / log_path()
// ---------------------------------------------------------------------------

#[test]
fn name_returns_configured_name() {
    let dir = tempdir().unwrap();
    let log_path = dir.path().join("test.log");
    std::fs::write(&log_path, "").unwrap();

    let config = crate::config::ResolvedJail {
        name: "my-custom-jail".to_string(),
        enabled: true,
        log_path,
        pattern: r"(?P<ip>\d+\.\d+\.\d+\.\d+)".to_string(),
        find_time: 300,
        ban_time: 1800,
        max_retry: 3,
        ban_action: "ban".to_string(),
        unban_action: "unban".to_string(),
        ignore_ips: Vec::new(),
    };
    let store = make_store(dir.path());
    let jail = Jail::new(config, store, None, Box::new(DuctRunner::new())).unwrap();

    assert_eq!(jail.name(), "my-custom-jail");
}

#[test]
fn log_path_returns_configured_path() {
    let dir = tempdir().unwrap();
    let log_path = dir.path().join("subdir").join("auth.log");

    let config = crate::config::ResolvedJail {
        name: "jail".to_string(),
        enabled: true,
        log_path: log_path.clone(),
        pattern: r"(?P<ip>\d+\.\d+\.\d+\.\d+)".to_string(),
        find_time: 600,
        ban_time: 3600,
        max_retry: 1,
        ban_action: "ban".to_string(),
        unban_action: "unban".to_string(),
        ignore_ips: Vec::new(),
    };
    let store = make_store(dir.path());
    let jail = Jail::new(config, store, None, Box::new(DuctRunner::new())).unwrap();

    assert_eq!(jail.log_path(), log_path.as_path());
}

// ---------------------------------------------------------------------------
// scan() -- empty log
// ---------------------------------------------------------------------------

#[test]
fn scan_empty_log_returns_zero_counts() {
    let (mut jail, mut log_file, _dir) = setup_test_jail();
    // Write nothing -- file is empty.
    log_file.flush().unwrap();

    let result = jail.scan(ExecutionMode::DryRun).unwrap();
    assert_eq!(result.lines_scanned, 0);
    assert_eq!(result.matches_found, 0);
    assert!(result.new_bans.is_empty());
}

// ---------------------------------------------------------------------------
// scan() -- matching lines
// ---------------------------------------------------------------------------

#[test]
fn scan_with_matching_lines_returns_ban_entries() {
    let (mut jail, mut log_file, _dir) = setup_test_jail();
    writeln!(log_file, "Failed login from 192.168.1.10").unwrap();
    writeln!(log_file, "some unrelated line").unwrap();
    writeln!(log_file, "Failed login from 10.0.0.5").unwrap();
    log_file.flush().unwrap();

    let result = jail.scan(ExecutionMode::DryRun).unwrap();
    assert_eq!(result.lines_scanned, 3);
    assert_eq!(result.matches_found, 2);
    assert_eq!(result.new_bans.len(), 2);

    // Verify the IPs in the ban entries.
    let ips: Vec<std::net::IpAddr> = result.new_bans.iter().map(|b| b.ip).collect();
    assert!(ips.contains(&"192.168.1.10".parse::<std::net::IpAddr>().unwrap()));
    assert!(ips.contains(&"10.0.0.5".parse::<std::net::IpAddr>().unwrap()));

    // Each entry should have the correct jail name.
    for ban in &result.new_bans {
        assert_eq!(ban.jail_name, "test-jail");
    }
}

#[test]
fn scan_no_matches_when_lines_do_not_match_pattern() {
    let (mut jail, mut log_file, _dir) = setup_test_jail();
    writeln!(log_file, "Accepted publickey for user").unwrap();
    writeln!(log_file, "Connection closed by 10.0.0.1").unwrap();
    log_file.flush().unwrap();

    let result = jail.scan(ExecutionMode::DryRun).unwrap();
    assert_eq!(result.lines_scanned, 2);
    assert_eq!(result.matches_found, 0);
    assert!(result.new_bans.is_empty());
}

// ---------------------------------------------------------------------------
// scan() -- dry_run
// ---------------------------------------------------------------------------

#[test]
fn scan_dry_run_returns_results() {
    let (mut jail, mut log_file, _dir) = setup_test_jail();
    writeln!(log_file, "Failed login from 172.16.0.1").unwrap();
    log_file.flush().unwrap();

    // Dry-run should return results (actions are no-ops since firewall commands
    // will fail silently or be empty).
    let result = jail.scan(ExecutionMode::DryRun).unwrap();
    assert_eq!(result.lines_scanned, 1);
    assert_eq!(result.matches_found, 1);
    assert_eq!(result.new_bans.len(), 1);
    assert_eq!(
        result.new_bans[0].ip,
        "172.16.0.1".parse::<std::net::IpAddr>().unwrap()
    );
}

#[test]
fn scan_dry_run_false_also_returns_results() {
    let (mut jail, mut log_file, _dir) = setup_test_jail();
    writeln!(log_file, "Failed login from 172.16.0.1").unwrap();
    log_file.flush().unwrap();

    // Non-dry-run also returns results (actions may fail but scan succeeds).
    let result = jail.scan(ExecutionMode::DryRun).unwrap();
    assert_eq!(result.new_bans.len(), 1);
}

// ---------------------------------------------------------------------------
// scan() -- ignored IPs
// ---------------------------------------------------------------------------

#[test]
fn scan_filters_out_ignored_ips() {
    let tmpdir = tempdir().unwrap();
    let log_file = NamedTempFile::new_in(tmpdir.path()).unwrap();
    let store = make_store(tmpdir.path());
    let config = make_resolved_jail(log_file.path());
    let mut jail = Jail::new(config, store, None, Box::new(DuctRunner::new()))
        .unwrap()
        .with_ignore_ips(vec!["10.0.0.5".to_string()]);

    // Write log lines: one ignored IP and one normal IP.
    let mut f = log_file.reopen().unwrap();
    writeln!(f, "Failed login from 10.0.0.5").unwrap();
    writeln!(f, "Failed login from 192.168.1.100").unwrap();
    f.flush().unwrap();

    let result = jail.scan(ExecutionMode::DryRun).unwrap();
    assert_eq!(result.matches_found, 2);
    // Only the non-ignored IP should appear in new_bans.
    assert_eq!(result.new_bans.len(), 1);
    assert_eq!(
        result.new_bans[0].ip,
        "192.168.1.100".parse::<std::net::IpAddr>().unwrap()
    );
}

#[test]
fn scan_filters_ips_in_ignored_cidr_range() {
    let tmpdir = tempdir().unwrap();
    let log_file = NamedTempFile::new_in(tmpdir.path()).unwrap();
    let store = make_store(tmpdir.path());
    let config = make_resolved_jail(log_file.path());
    let mut jail = Jail::new(config, store, None, Box::new(DuctRunner::new()))
        .unwrap()
        .with_ignore_ips(vec!["192.168.0.0/16".to_string()]);

    let mut f = log_file.reopen().unwrap();
    writeln!(f, "Failed login from 192.168.1.50").unwrap();
    writeln!(f, "Failed login from 10.0.0.1").unwrap();
    f.flush().unwrap();

    let result = jail.scan(ExecutionMode::DryRun).unwrap();
    assert_eq!(result.new_bans.len(), 1);
    assert_eq!(
        result.new_bans[0].ip,
        "10.0.0.1".parse::<std::net::IpAddr>().unwrap()
    );
}

// ---------------------------------------------------------------------------
// ban_ip()
// ---------------------------------------------------------------------------

#[test]
fn ban_ip_adds_ban_entry() {
    let (mut jail, _log, _dir) = setup_test_jail();
    let ip: std::net::IpAddr = "203.0.113.50".parse().unwrap();

    let entry = jail.ban_ip(ip, ExecutionMode::DryRun).unwrap();
    assert_eq!(entry.ip, ip);
    assert_eq!(entry.prefix, 32);
    assert_eq!(entry.jail_name, "test-jail");
    assert!(entry.expires_at.is_some());
}

#[test]
fn ban_ip_dry_run_returns_entry_without_executing() {
    let (mut jail, _log, _dir) = setup_test_jail();
    let ip: std::net::IpAddr = "203.0.113.50".parse().unwrap();

    let entry = jail.ban_ip(ip, ExecutionMode::DryRun).unwrap();
    assert_eq!(entry.ip, ip);
    assert_eq!(entry.prefix, 32);
}

#[test]
fn ban_ip_ignored_exact_returns_invalid_config() {
    let (jail, _log, _dir) = setup_test_jail();
    let mut jail = jail.with_ignore_ips(vec!["10.0.0.1".to_string()]);
    let ip: std::net::IpAddr = "10.0.0.1".parse().unwrap();

    let result = jail.ban_ip(ip, ExecutionMode::DryRun);
    assert!(result.is_err());
    match result.unwrap_err() {
        crate::Error::InvalidConfig(msg) => {
            assert!(msg.contains("10.0.0.1"));
            assert!(msg.contains("ignore list"));
        }
        other => panic!("expected InvalidConfig, got: {other:?}"),
    }
}

#[test]
fn ban_ip_ignored_cidr_returns_invalid_config() {
    let (jail, _log, _dir) = setup_test_jail();
    let mut jail = jail.with_ignore_ips(vec!["192.168.0.0/16".to_string()]);
    let ip: std::net::IpAddr = "192.168.5.10".parse().unwrap();

    let result = jail.ban_ip(ip, ExecutionMode::DryRun);
    assert!(result.is_err());
    match result.unwrap_err() {
        crate::Error::InvalidConfig(msg) => {
            assert!(msg.contains("192.168.5.10"));
        }
        other => panic!("expected InvalidConfig, got: {other:?}"),
    }
}

#[test]
fn ban_ip_already_banned_returns_already_banned() {
    let (mut jail, _log, _dir) = setup_test_jail();
    let ip: std::net::IpAddr = "10.0.0.1".parse().unwrap();

    jail.ban_ip(ip, ExecutionMode::DryRun).unwrap();
    let result = jail.ban_ip(ip, ExecutionMode::DryRun);
    assert!(result.is_err());
    match result.unwrap_err() {
        crate::Error::AlreadyBanned(_) => {}
        other => panic!("expected AlreadyBanned, got: {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// unban_ip()
// ---------------------------------------------------------------------------

#[test]
fn unban_ip_removes_ban_entry() {
    let (mut jail, _log, _dir) = setup_test_jail();
    let ip: std::net::IpAddr = "203.0.113.50".parse().unwrap();

    jail.ban_ip(ip, ExecutionMode::DryRun).unwrap();
    let entry = jail
        .unban_ip("203.0.113.50".parse().unwrap(), ExecutionMode::DryRun)
        .unwrap();
    assert_eq!(entry.ip, ip);
    assert_eq!(entry.jail_name, "test-jail");

    // Should no longer be in the ban list.
    let bans = jail.list_bans().unwrap();
    assert!(bans.is_empty());
}

#[test]
fn unban_ip_not_banned_returns_not_banned() {
    let (mut jail, _log, _dir) = setup_test_jail();

    let result = jail.unban_ip("10.0.0.99".parse().unwrap(), ExecutionMode::DryRun);
    assert!(result.is_err());
    match result.unwrap_err() {
        crate::Error::NotBanned(msg) => assert!(msg.contains("10.0.0.99")),
        other => panic!("expected NotBanned, got: {other:?}"),
    }
}

#[test]
fn unban_ip_wrong_jail_returns_not_banned() {
    let dir = tempdir().unwrap();
    let log_path = dir.path().join("test.log");
    std::fs::write(&log_path, "").unwrap();

    let store = make_store(dir.path());

    // Ban in "jail-a".
    let config_a = crate::config::ResolvedJail {
        name: "jail-a".to_string(),
        enabled: true,
        log_path: log_path.clone(),
        pattern: r"(?P<ip>\d+\.\d+\.\d+\.\d+)".to_string(),
        find_time: 600,
        ban_time: 3600,
        max_retry: 1,
        ban_action: "ban".to_string(),
        unban_action: "unban".to_string(),
        ignore_ips: Vec::new(),
    };
    let mut jail_a = Jail::new(config_a, store, None, Box::new(DuctRunner::new())).unwrap();
    let ip: std::net::IpAddr = "10.0.0.1".parse().unwrap();
    jail_a.ban_ip(ip, ExecutionMode::DryRun).unwrap();

    // Create "jail-b" sharing the same store.
    let store2 = make_store(dir.path());
    let config_b = crate::config::ResolvedJail {
        name: "jail-b".to_string(),
        enabled: true,
        log_path,
        pattern: r"(?P<ip>\d+\.\d+\.\d+\.\d+)".to_string(),
        find_time: 600,
        ban_time: 3600,
        max_retry: 1,
        ban_action: "ban".to_string(),
        unban_action: "unban".to_string(),
        ignore_ips: Vec::new(),
    };
    let mut jail_b = Jail::new(config_b, store2, None, Box::new(DuctRunner::new())).unwrap();

    // Unban from jail-b should fail since the IP is banned under jail-a.
    let result = jail_b.unban_ip("10.0.0.1".parse().unwrap(), ExecutionMode::DryRun);
    assert!(result.is_err());
    match result.unwrap_err() {
        crate::Error::NotBanned(_) => {}
        other => panic!("expected NotBanned, got: {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// list_bans()
// ---------------------------------------------------------------------------

#[test]
fn list_bans_returns_empty_when_no_bans() {
    let (jail, _log, _dir) = setup_test_jail();
    let bans = jail.list_bans().unwrap();
    assert!(bans.is_empty());
}

#[test]
fn list_bans_returns_active_bans() {
    let (mut jail, _log, _dir) = setup_test_jail();

    let ip1: std::net::IpAddr = "10.0.0.1".parse().unwrap();
    let ip2: std::net::IpAddr = "10.0.0.2".parse().unwrap();

    jail.ban_ip(ip1, ExecutionMode::DryRun).unwrap();
    jail.ban_ip(ip2, ExecutionMode::DryRun).unwrap();

    let bans = jail.list_bans().unwrap();
    assert_eq!(bans.len(), 2);
    let ips: Vec<std::net::IpAddr> = bans.iter().map(|b| b.ip).collect();
    assert!(ips.contains(&ip1));
    assert!(ips.contains(&ip2));
}

#[test]
fn list_bans_after_unban_reflects_removal() {
    let (mut jail, _log, _dir) = setup_test_jail();

    let ip1: std::net::IpAddr = "10.0.0.1".parse().unwrap();
    let ip2: std::net::IpAddr = "10.0.0.2".parse().unwrap();

    jail.ban_ip(ip1, ExecutionMode::DryRun).unwrap();
    jail.ban_ip(ip2, ExecutionMode::DryRun).unwrap();

    jail.unban_ip("10.0.0.1".parse().unwrap(), ExecutionMode::DryRun)
        .unwrap();

    let bans = jail.list_bans().unwrap();
    assert_eq!(bans.len(), 1);
    assert_eq!(bans[0].ip, ip2);
}

// ---------------------------------------------------------------------------
// is_ignored() -- tested indirectly through ban_ip
// ---------------------------------------------------------------------------

#[test]
fn is_ignored_exact_ip_match() {
    let (jail, _log, _dir) = setup_test_jail();
    let mut jail = jail.with_ignore_ips(vec!["192.0.2.1".to_string()]);

    let result = jail.ban_ip("192.0.2.1".parse().unwrap(), ExecutionMode::DryRun);
    assert!(result.is_err());

    // A different IP should not be ignored.
    let result = jail.ban_ip("192.0.2.2".parse().unwrap(), ExecutionMode::DryRun);
    assert!(result.is_ok());
}

#[test]
fn is_ignored_cidr_match() {
    let (jail, _log, _dir) = setup_test_jail();
    let mut jail = jail.with_ignore_ips(vec!["10.0.0.0/8".to_string()]);

    // Any IP in 10.0.0.0/8 should be ignored.
    let result = jail.ban_ip("10.255.255.255".parse().unwrap(), ExecutionMode::DryRun);
    assert!(result.is_err());

    // Outside the range should be fine.
    let result = jail.ban_ip("11.0.0.1".parse().unwrap(), ExecutionMode::DryRun);
    assert!(result.is_ok());
}

#[test]
fn is_ignored_not_ignored() {
    let (mut jail, _log, _dir) = setup_test_jail();
    // Empty ignore list -- nothing should be ignored.
    let result = jail.ban_ip("8.8.8.8".parse().unwrap(), ExecutionMode::DryRun);
    assert!(result.is_ok());
}

#[test]
fn is_ignored_multiple_rules_first_match_wins() {
    let (jail, _log, _dir) = setup_test_jail();
    let mut jail =
        jail.with_ignore_ips(vec!["192.168.0.0/16".to_string(), "10.0.0.0/8".to_string()]);

    assert!(
        jail.ban_ip("192.168.1.1".parse().unwrap(), ExecutionMode::DryRun)
            .is_err()
    );
    assert!(
        jail.ban_ip("10.99.99.99".parse().unwrap(), ExecutionMode::DryRun)
            .is_err()
    );
    assert!(
        jail.ban_ip("172.16.0.1".parse().unwrap(), ExecutionMode::DryRun)
            .is_ok()
    );
}

#[test]
fn is_ignored_ipv6_cidr_match() {
    let (jail, _log, _dir) = setup_test_jail();
    let mut jail = jail.with_ignore_ips(vec!["2001:db8::/32".to_string()]);

    let result = jail.ban_ip("2001:db8::1".parse().unwrap(), ExecutionMode::DryRun);
    assert!(result.is_err());

    let result = jail.ban_ip("2001:db9::1".parse().unwrap(), ExecutionMode::DryRun);
    assert!(result.is_ok());
}

// ---------------------------------------------------------------------------
// Edge case: scan after ban_ip (duplicate detection)
// ---------------------------------------------------------------------------

#[test]
fn scan_after_ban_ip_does_not_duplicate_ban() {
    let (mut jail, mut log_file, _dir) = setup_test_jail();
    let ip: std::net::IpAddr = "192.168.1.10".parse().unwrap();

    // Manually ban the IP first.
    jail.ban_ip(ip, ExecutionMode::DryRun).unwrap();
    assert_eq!(jail.list_bans().unwrap().len(), 1);

    // Now scan a log that contains the same IP. Scan persists bans, but
    // the IP is already banned so AlreadyBanned is caught and skipped.
    writeln!(log_file, "Failed login from 192.168.1.10").unwrap();
    log_file.flush().unwrap();

    let result = jail.scan(ExecutionMode::DryRun).unwrap();
    // The IP is already banned, so scan skips it (AlreadyBanned).
    assert_eq!(result.new_bans.len(), 0);

    // The manual ban should still be the only one in the store.
    let bans = jail.list_bans().unwrap();
    assert_eq!(bans.len(), 1);
    assert_eq!(bans[0].ip, ip);
}

// ---------------------------------------------------------------------------
// Edge case: multiple scans
// ---------------------------------------------------------------------------

#[test]
fn multiple_scans_incremental_reads() {
    let (mut jail, mut log_file, _dir) = setup_test_jail();

    // First scan: empty file.
    let r1 = jail.scan(ExecutionMode::DryRun).unwrap();
    assert_eq!(r1.lines_scanned, 0);

    // Append a matching line.
    writeln!(log_file, "Failed login from 10.0.0.1").unwrap();
    log_file.flush().unwrap();

    // Second scan: should read only the new line.
    let r2 = jail.scan(ExecutionMode::DryRun).unwrap();
    assert_eq!(r2.lines_scanned, 1);
    assert_eq!(r2.new_bans.len(), 1);

    // Append another line.
    writeln!(log_file, "Failed login from 10.0.0.2").unwrap();
    log_file.flush().unwrap();

    // Third scan: should only read the newly appended line.
    let r3 = jail.scan(ExecutionMode::DryRun).unwrap();
    assert_eq!(r3.lines_scanned, 1);
    assert_eq!(r3.new_bans.len(), 1);
    assert_eq!(
        r3.new_bans[0].ip,
        "10.0.0.2".parse::<std::net::IpAddr>().unwrap()
    );
}

// ---------------------------------------------------------------------------
// Edge case: IPv6 handling
// ---------------------------------------------------------------------------

#[test]
fn ban_ip_ipv6_sets_prefix_128() {
    let (mut jail, _log, _dir) = setup_test_jail();
    let ip: std::net::IpAddr = "::1".parse().unwrap();

    let entry = jail.ban_ip(ip, ExecutionMode::DryRun).unwrap();
    assert_eq!(entry.ip, ip);
    assert_eq!(entry.prefix, 128);
}

#[test]
fn scan_with_ipv6_in_log() {
    let (mut jail, log_file, _dir) = setup_test_jail_dual();

    let mut f = log_file.reopen().unwrap();
    writeln!(f, "Failed login from 2001:db8::abcd").unwrap();
    writeln!(f, "Failed login from 192.168.1.1").unwrap();
    f.flush().unwrap();

    let result = jail.scan(ExecutionMode::DryRun).unwrap();
    assert_eq!(result.matches_found, 2);
    assert_eq!(result.new_bans.len(), 2);

    let ips: Vec<std::net::IpAddr> = result.new_bans.iter().map(|b| b.ip).collect();
    assert!(ips.contains(&"2001:db8::abcd".parse::<std::net::IpAddr>().unwrap()));
    assert!(ips.contains(&"192.168.1.1".parse::<std::net::IpAddr>().unwrap()));

    // IPv6 entry should have prefix 128.
    let v6_entry = result.new_bans.iter().find(|b| b.ip.is_ipv6()).unwrap();
    assert_eq!(v6_entry.prefix, 128);
}

#[test]
fn ban_ip_ipv6_ignored_by_cidr() {
    let (jail, _log, _dir) = setup_test_jail();
    let mut jail = jail.with_ignore_ips(vec!["fe80::/10".to_string()]);

    let link_local: std::net::IpAddr = "fe80::1".parse().unwrap();
    let result = jail.ban_ip(link_local, ExecutionMode::DryRun);
    assert!(result.is_err());

    let global: std::net::IpAddr = "2001:db8::1".parse().unwrap();
    let result = jail.ban_ip(global, ExecutionMode::DryRun);
    assert!(result.is_ok());
}

// ---------------------------------------------------------------------------
// Edge case: unban then re-ban
// ---------------------------------------------------------------------------

#[test]
fn unban_then_reban_succeeds() {
    let (mut jail, _log, _dir) = setup_test_jail();
    let ip: std::net::IpAddr = "10.0.0.1".parse().unwrap();

    jail.ban_ip(ip, ExecutionMode::DryRun).unwrap();
    jail.unban_ip("10.0.0.1".parse().unwrap(), ExecutionMode::DryRun)
        .unwrap();

    // Re-banning should succeed.
    let entry = jail.ban_ip(ip, ExecutionMode::DryRun).unwrap();
    assert_eq!(entry.ip, ip);

    let bans = jail.list_bans().unwrap();
    assert_eq!(bans.len(), 1);
    assert_eq!(bans[0].ip, ip);
}

// ---------------------------------------------------------------------------
// Edge case: ban with mixed IPv4/IPv6 ignore list
// ---------------------------------------------------------------------------

#[test]
fn mixed_ignore_list_only_affects_matching_family() {
    let (jail, _log, _dir) = setup_test_jail();
    let mut jail = jail.with_ignore_ips(vec!["10.0.0.0/8".to_string(), "::1".to_string()]);

    // IPv4 in ignored range.
    assert!(
        jail.ban_ip("10.0.0.1".parse().unwrap(), ExecutionMode::DryRun)
            .is_err()
    );
    // IPv6 exact match.
    assert!(
        jail.ban_ip("::1".parse().unwrap(), ExecutionMode::DryRun)
            .is_err()
    );
    // IPv4 outside ignored range.
    assert!(
        jail.ban_ip("192.168.1.1".parse().unwrap(), ExecutionMode::DryRun)
            .is_ok()
    );
    // IPv6 outside ignored range.
    assert!(
        jail.ban_ip("2001:db8::1".parse().unwrap(), ExecutionMode::DryRun)
            .is_ok()
    );
}

// ---------------------------------------------------------------------------
// Edge case: find_time window prunes old failures
// ---------------------------------------------------------------------------

#[test]
fn test_scan_find_time_window_prunes_old_failures() {
    // With find_time=2 and max_retry=1, a single scan triggers a ban.
    // After the find_time window, a second scan should treat the IP as fresh
    // (failure_tracker was cleared when the ban triggered).
    let dir = tempdir().unwrap();
    let log_file = NamedTempFile::new_in(dir.path()).unwrap();
    let store = make_store(dir.path());
    let config = crate::config::ResolvedJail {
        name: "test-jail".to_string(),
        enabled: true,
        log_path: log_file.path().to_path_buf(),
        pattern: r"Failed login from (?P<ip>\d+\.\d+\.\d+\.\d+)".to_string(),
        find_time: 2,
        ban_time: 3600,
        max_retry: 1,
        ban_action: "ban".to_string(),
        unban_action: "unban".to_string(),
        ignore_ips: Vec::new(),
    };
    let mut jail = Jail::new(config, store, None, Box::new(DuctRunner::new())).unwrap();

    let mut f = log_file.reopen().unwrap();

    // First scan: one match -> triggers ban immediately (max_retry=1).
    writeln!(f, "Failed login from 10.0.0.1").unwrap();
    f.flush().unwrap();
    let r1 = jail.scan(ExecutionMode::DryRun).unwrap();
    assert_eq!(r1.new_bans.len(), 1);
    assert_eq!(
        r1.new_bans[0].ip,
        "10.0.0.1".parse::<std::net::IpAddr>().unwrap()
    );

    // Unban so we can test re-banning after the failure tracker resets.
    jail.unban_ip("10.0.0.1".parse().unwrap(), ExecutionMode::DryRun)
        .unwrap();

    // The failure_tracker was cleared when the ban triggered (failures.clear()).
    // A subsequent scan for the same IP starts fresh, so it should ban again.
    writeln!(f, "Failed login from 10.0.0.1").unwrap();
    f.flush().unwrap();
    let r2 = jail.scan(ExecutionMode::DryRun).unwrap();
    assert_eq!(r2.new_bans.len(), 1);
    assert_eq!(
        r2.new_bans[0].ip,
        "10.0.0.1".parse::<std::net::IpAddr>().unwrap()
    );
}

// ---------------------------------------------------------------------------
// Edge case: max_retry boundary triggers ban
// ---------------------------------------------------------------------------

#[test]
fn test_scan_max_retry_boundary_triggers_ban() {
    let dir = tempdir().unwrap();
    let log_file = NamedTempFile::new_in(dir.path()).unwrap();
    let store = make_store(dir.path());
    let config = crate::config::ResolvedJail {
        name: "test-jail".to_string(),
        enabled: true,
        log_path: log_file.path().to_path_buf(),
        pattern: r"Failed login from (?P<ip>\d+\.\d+\.\d+\.\d+)".to_string(),
        find_time: 600,
        ban_time: 3600,
        max_retry: 3,
        ban_action: "ban".to_string(),
        unban_action: "unban".to_string(),
        ignore_ips: Vec::new(),
    };
    let mut jail = Jail::new(config, store, None, Box::new(DuctRunner::new())).unwrap();

    // Write 3 matching lines for the same IP in one go.
    let mut f = log_file.reopen().unwrap();
    writeln!(f, "Failed login from 192.168.1.100").unwrap();
    writeln!(f, "Failed login from 192.168.1.100").unwrap();
    writeln!(f, "Failed login from 192.168.1.100").unwrap();
    f.flush().unwrap();

    let result = jail.scan(ExecutionMode::DryRun).unwrap();
    assert_eq!(result.lines_scanned, 3);
    assert_eq!(result.matches_found, 3);
    // Exactly 1 ban entry (3rd failure reaches the threshold).
    assert_eq!(result.new_bans.len(), 1);
    assert_eq!(
        result.new_bans[0].ip,
        "192.168.1.100".parse::<std::net::IpAddr>().unwrap()
    );
    assert_eq!(result.new_bans[0].jail_name, "test-jail");

    // Verify persisted in store.
    let bans = jail.list_bans().unwrap();
    assert_eq!(bans.len(), 1);
}

// ---------------------------------------------------------------------------
// Edge case: max_retry below threshold, no ban
// ---------------------------------------------------------------------------

#[test]
fn test_scan_max_retry_below_threshold_no_ban() {
    let dir = tempdir().unwrap();
    let log_file = NamedTempFile::new_in(dir.path()).unwrap();
    let store = make_store(dir.path());
    let config = crate::config::ResolvedJail {
        name: "test-jail".to_string(),
        enabled: true,
        log_path: log_file.path().to_path_buf(),
        pattern: r"Failed login from (?P<ip>\d+\.\d+\.\d+\.\d+)".to_string(),
        find_time: 600,
        ban_time: 3600,
        max_retry: 3,
        ban_action: "ban".to_string(),
        unban_action: "unban".to_string(),
        ignore_ips: Vec::new(),
    };
    let mut jail = Jail::new(config, store, None, Box::new(DuctRunner::new())).unwrap();

    // Write only 2 matching lines -- below the threshold of 3.
    let mut f = log_file.reopen().unwrap();
    writeln!(f, "Failed login from 192.168.1.100").unwrap();
    writeln!(f, "Failed login from 192.168.1.100").unwrap();
    f.flush().unwrap();

    let result = jail.scan(ExecutionMode::DryRun).unwrap();
    assert_eq!(result.lines_scanned, 2);
    assert_eq!(result.matches_found, 2);
    // 0 bans -- below the max_retry threshold.
    assert_eq!(result.new_bans.len(), 0);

    // Nothing persisted.
    let bans = jail.list_bans().unwrap();
    assert!(bans.is_empty());
}

// ---------------------------------------------------------------------------
// Edge case: scan multiple different IPs
// ---------------------------------------------------------------------------

#[test]
fn test_scan_multiple_different_ips() {
    let (mut jail, log_file, _dir) = setup_test_jail();

    let mut f = log_file.reopen().unwrap();
    writeln!(f, "Failed login from 10.0.0.1").unwrap();
    writeln!(f, "Failed login from 10.0.0.2").unwrap();
    writeln!(f, "Failed login from 10.0.0.3").unwrap();
    writeln!(f, "Failed login from 10.0.0.4").unwrap();
    writeln!(f, "Failed login from 10.0.0.5").unwrap();
    f.flush().unwrap();

    let result = jail.scan(ExecutionMode::DryRun).unwrap();
    assert_eq!(result.matches_found, 5);
    assert_eq!(result.new_bans.len(), 5);

    let mut ips: Vec<std::net::IpAddr> = result.new_bans.iter().map(|b| b.ip).collect();
    ips.sort();
    let expected: Vec<std::net::IpAddr> = (1..=5)
        .map(|i| format!("10.0.0.{i}").parse().unwrap())
        .collect();
    assert_eq!(ips, expected);

    // All 5 persisted.
    let bans = jail.list_bans().unwrap();
    assert_eq!(bans.len(), 5);
}

// ---------------------------------------------------------------------------
// Edge case: ban_ip then scan same IP is skipped (AlreadyBanned)
// ---------------------------------------------------------------------------

#[test]
fn test_ban_ip_then_scan_same_ip_skipped() {
    let (mut jail, log_file, _dir) = setup_test_jail();
    let ip: std::net::IpAddr = "192.168.1.10".parse().unwrap();

    // Ban the IP manually first.
    jail.ban_ip(ip, ExecutionMode::DryRun).unwrap();
    assert_eq!(jail.list_bans().unwrap().len(), 1);

    // Write the same IP to the log and scan.
    let mut f = log_file.reopen().unwrap();
    writeln!(f, "Failed login from 192.168.1.10").unwrap();
    f.flush().unwrap();

    let result = jail.scan(ExecutionMode::DryRun).unwrap();
    // AlreadyBanned is caught and skipped -- no duplicate.
    assert_eq!(result.new_bans.len(), 0);

    let bans = jail.list_bans().unwrap();
    assert_eq!(bans.len(), 1);
    assert_eq!(bans[0].ip, ip);
}

// ---------------------------------------------------------------------------
// Edge case: unban then scan re-bans the IP
// ---------------------------------------------------------------------------

#[test]
fn test_unban_then_scan_same_ip_rebanned() {
    let (mut jail, mut log_file, _dir) = setup_test_jail();
    let ip: std::net::IpAddr = "192.168.1.10".parse().unwrap();

    // Write a line, scan to ban.
    writeln!(log_file, "Failed login from 192.168.1.10").unwrap();
    log_file.flush().unwrap();
    let r1 = jail.scan(ExecutionMode::DryRun).unwrap();
    assert_eq!(r1.new_bans.len(), 1);
    assert_eq!(jail.list_bans().unwrap().len(), 1);

    // Unban it.
    jail.unban_ip(ip, ExecutionMode::DryRun).unwrap();
    assert!(jail.list_bans().unwrap().is_empty());

    // Write the same IP again and scan -- it should get re-banned.
    writeln!(log_file, "Failed login from 192.168.1.10").unwrap();
    log_file.flush().unwrap();
    let r2 = jail.scan(ExecutionMode::DryRun).unwrap();
    assert_eq!(r2.new_bans.len(), 1);
    assert_eq!(r2.new_bans[0].ip, ip);

    let bans = jail.list_bans().unwrap();
    assert_eq!(bans.len(), 1);
    assert_eq!(bans[0].ip, ip);
}

// ---------------------------------------------------------------------------
// Edge case: pattern matching everything produces matches but no bans
// ---------------------------------------------------------------------------

#[test]
fn test_scan_with_pattern_matching_everything() {
    let dir = tempdir().unwrap();
    let log_file = NamedTempFile::new_in(dir.path()).unwrap();
    let store = make_store(dir.path());
    // Pattern ".*" matches every line but has no `ip` capture group.
    let config = crate::config::ResolvedJail {
        name: "test-jail".to_string(),
        enabled: true,
        log_path: log_file.path().to_path_buf(),
        pattern: ".*".to_string(),
        find_time: 600,
        ban_time: 3600,
        max_retry: 1,
        ban_action: "ban".to_string(),
        unban_action: "unban".to_string(),
        ignore_ips: Vec::new(),
    };
    let mut jail = Jail::new(config, store, None, Box::new(DuctRunner::new())).unwrap();

    let mut f = log_file.reopen().unwrap();
    writeln!(f, "some arbitrary text").unwrap();
    writeln!(f, "another line").unwrap();
    writeln!(f, "third line").unwrap();
    f.flush().unwrap();

    let result = jail.scan(ExecutionMode::DryRun).unwrap();
    assert_eq!(result.lines_scanned, 3);
    // All 3 lines match the pattern.
    assert_eq!(result.matches_found, 3);
    // But no bans -- no IP capture group means ip is None, so no BanEntry is created.
    assert_eq!(result.new_bans.len(), 0);

    let bans = jail.list_bans().unwrap();
    assert!(bans.is_empty());
}

// ---------------------------------------------------------------------------
// Edge case: ban_ip in DryRun then Execute returns AlreadyBanned
// ---------------------------------------------------------------------------

#[test]
fn test_ban_ip_dry_run_then_execute() {
    let (mut jail, _log, _dir) = setup_test_jail();
    let ip: std::net::IpAddr = "203.0.113.50".parse().unwrap();

    // Ban in dry-run -- succeeds and persists to store.
    let entry = jail.ban_ip(ip, ExecutionMode::DryRun).unwrap();
    assert_eq!(entry.ip, ip);
    assert_eq!(entry.prefix, 32);

    // Ban the same IP in execute mode -- fails with AlreadyBanned because
    // ban_ip now persists to the store first.
    let result = jail.ban_ip(ip, ExecutionMode::Execute);
    assert!(result.is_err());

    // Verify the store still has exactly one entry (the original dry-run ban).
    let bans = jail.list_bans().unwrap();
    assert_eq!(bans.len(), 1);
    assert_eq!(bans[0].ip, ip);

    // A second dry-run attempt also fails with AlreadyBanned since the
    // store already has the entry.
    let result2 = jail.ban_ip(ip, ExecutionMode::DryRun);
    assert!(result2.is_err());
    match result2.unwrap_err() {
        crate::Error::AlreadyBanned(_) => {}
        other => panic!("expected AlreadyBanned, got: {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Edge case: list_bans preserves insertion order
// ---------------------------------------------------------------------------

#[test]
fn test_list_bans_preserves_order() {
    let (mut jail, _log, _dir) = setup_test_jail();

    let ips: Vec<std::net::IpAddr> = ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5"]
        .iter()
        .map(|s| s.parse().unwrap())
        .collect();

    for ip in &ips {
        jail.ban_ip(*ip, ExecutionMode::DryRun).unwrap();
    }

    let bans = jail.list_bans().unwrap();
    assert_eq!(bans.len(), 5);

    // Store uses a Vec, so insertion order is preserved.
    for (ban, expected_ip) in bans.iter().zip(&ips) {
        assert_eq!(ban.ip, *expected_ip);
    }
}

// ---------------------------------------------------------------------------
// Edge case: invalid entry in ignore_ips is silently skipped
// ---------------------------------------------------------------------------

#[test]
fn test_ignore_ips_with_invalid_entry_skipped() {
    let dir = tempdir().unwrap();
    let log_file = NamedTempFile::new_in(dir.path()).unwrap();
    let store = make_store(dir.path());
    let config = make_resolved_jail(log_file.path());
    let mut jail = Jail::new(config, store, None, Box::new(DuctRunner::new()))
        .unwrap()
        .with_ignore_ips(vec![
            "not-an-ip".to_string(), // invalid -- should be silently skipped
            "10.0.0.1".to_string(),  // valid -- should be ignored
        ]);

    // The valid entry should still work: 10.0.0.1 is ignored.
    let result = jail.ban_ip("10.0.0.1".parse().unwrap(), ExecutionMode::DryRun);
    assert!(result.is_err());

    // The invalid entry doesn't prevent banning other IPs.
    let result = jail.ban_ip("192.168.1.1".parse().unwrap(), ExecutionMode::DryRun);
    assert!(result.is_ok());

    // Scan should also work: 10.0.0.5 is not ignored, 10.0.0.1 is.
    let mut f = log_file.reopen().unwrap();
    writeln!(f, "Failed login from 10.0.0.1").unwrap();
    writeln!(f, "Failed login from 10.0.0.5").unwrap();
    f.flush().unwrap();

    let scan_result = jail.scan(ExecutionMode::DryRun).unwrap();
    assert_eq!(scan_result.matches_found, 2);
    // Only 10.0.0.5 should be banned (10.0.0.1 is ignored).
    assert_eq!(scan_result.new_bans.len(), 1);
    assert_eq!(
        scan_result.new_bans[0].ip,
        "10.0.0.5".parse::<std::net::IpAddr>().unwrap()
    );
}
