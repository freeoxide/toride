use super::*;
use crate::types::ExecutionMode;
use crate::config::{Fail2BanConfig, JailConfig, DefaultConfig};
use crate::paths::Fail2BanPaths;
use std::collections::HashMap;
use std::io::Write;
use tempfile::tempdir;

/// Create a log file with SSH-like auth failure lines at the given path.
fn write_sample_log(log_path: &std::path::Path) {
    let mut file = std::fs::File::create(log_path).unwrap();
    writeln!(
        file,
        "May 30 12:00:01 server sshd[1234]: Failed password for invalid user admin from 192.168.1.100 port 22 ssh2"
    )
    .unwrap();
    writeln!(
        file,
        "May 30 12:00:02 server sshd[1235]: Failed password for root from 10.0.0.50 port 22 ssh2"
    )
    .unwrap();
    writeln!(
        file,
        "May 30 12:00:03 server sshd[1236]: Connection closed by 192.168.1.200 port 22 [preauth]"
    )
    .unwrap();
    writeln!(
        file,
        "May 30 12:00:04 server sshd[1237]: Failed password for invalid user test from 172.16.0.10 port 22 ssh2"
    )
    .unwrap();
}

/// Build a `Fail2BanPaths` rooted under a temp directory.
fn make_paths(dir: &tempfile::TempDir) -> Fail2BanPaths {
    let base = dir.path();
    Fail2BanPaths {
        config_dir: base.join("config"),
        config_file: base.join("config").join("config.json"),
        data_dir: base.join("data"),
        ban_db: base.join("data").join("bans.json"),
        pid_file: base.join("data").join("fail2ban.pid"),
        log_dir: base.join("data").join("logs"),
        journal_dir: base.join("data").join("journals"),
    }
}

/// Build a `Fail2BanConfig` with a single jail pointing at the given log path.
fn make_config(log_path: &std::path::Path) -> Fail2BanConfig {
    let mut jails = HashMap::new();
    jails.insert(
        "sshd".to_string(),
        JailConfig {
            enabled: true,
            log_path: log_path.to_path_buf(),
            pattern: r"Failed password for .* from (?P<ip>\d+\.\d+\.\d+\.\d+)".to_string(),
            find_time: None,
            ban_time: None,
            max_retry: None,
            ban_action: None,
            unban_action: None,
            ignore_ips: Vec::new(),
        },
    );
    Fail2BanConfig {
        defaults: DefaultConfig::default(),
        jails,
        actions: HashMap::new(),
        global: crate::config::GlobalConfig::default(),
    }
}

/// Helper: create a temp directory with a log file, config, paths, and manager.
fn setup() -> (tempfile::TempDir, Fail2BanManager) {
    let dir = tempdir().unwrap();
    let log_path = dir.path().join("auth.log");
    write_sample_log(&log_path);
    let config = make_config(&log_path);
    let paths = make_paths(&dir);
    let manager = Fail2BanManager::new(config, paths).unwrap();
    (dir, manager)
}

// ---------- new() ----------

#[test]
fn new_creates_manager_successfully() {
    let (_dir, manager) = setup();
    // The manager was created without error and the sshd jail is loaded.
    let status = manager.status().unwrap();
    assert!(status.running);
    assert_eq!(status.jails.len(), 1);
    assert_eq!(status.jails[0].name, "sshd");
}

#[test]
fn new_loads_only_enabled_jails() {
    let dir = tempdir().unwrap();
    let log_path = dir.path().join("auth.log");
    write_sample_log(&log_path);

    let mut jails = HashMap::new();
    jails.insert(
        "sshd".to_string(),
        JailConfig {
            enabled: true,
            log_path: log_path.clone(),
            pattern: r"Failed password for .* from (?P<ip>\d+\.\d+\.\d+\.\d+)".to_string(),
            find_time: None,
            ban_time: None,
            max_retry: None,
            ban_action: None,
            unban_action: None,
            ignore_ips: Vec::new(),
        },
    );
    // This jail is disabled.
    jails.insert(
        "nginx".to_string(),
        JailConfig {
            enabled: false,
            log_path: log_path.clone(),
            pattern: r"error".to_string(),
            find_time: None,
            ban_time: None,
            max_retry: None,
            ban_action: None,
            unban_action: None,
            ignore_ips: Vec::new(),
        },
    );

    let config = Fail2BanConfig {
        defaults: DefaultConfig::default(),
        jails,
        actions: HashMap::new(),
        global: crate::config::GlobalConfig::default(),
    };
    let paths = make_paths(&dir);
    let manager = Fail2BanManager::new(config, paths).unwrap();

    let status = manager.status().unwrap();
    assert_eq!(status.jails.len(), 1);
    assert_eq!(status.jails[0].name, "sshd");
}

// ---------- add_jail() ----------

#[test]
fn add_jail_inserts_new_jail() {
    let dir = tempdir().unwrap();
    let log_path = dir.path().join("auth.log");
    write_sample_log(&log_path);
    let config = make_config(&log_path);
    let paths = make_paths(&dir);
    let mut manager = Fail2BanManager::new(config, paths).unwrap();

    let log_path2 = dir.path().join("nginx.log");
    write_sample_log(&log_path2);

    let resolved = crate::config::ResolvedJail {
        name: "nginx".to_string(),
        enabled: true,
        log_path: log_path2,
        pattern: r"error from (?P<ip>\d+\.\d+\.\d+\.\d+)".to_string(),
        find_time: 600,
        ban_time: 3600,
        max_retry: 5,
        ban_action: "ban".to_string(),
        unban_action: "unban".to_string(),
        ignore_ips: Vec::new(),
    };

    manager.add_jail("nginx", resolved).unwrap();

    let status = manager.status().unwrap();
    assert_eq!(status.jails.len(), 2);
}

#[test]
fn add_jail_duplicate_returns_already_exists() {
    let (_dir, mut manager) = setup();

    let resolved = crate::config::ResolvedJail {
        name: "sshd".to_string(),
        enabled: true,
        log_path: std::path::PathBuf::from("/dev/null"),
        pattern: r"dummy".to_string(),
        find_time: 600,
        ban_time: 3600,
        max_retry: 5,
        ban_action: "ban".to_string(),
        unban_action: "unban".to_string(),
        ignore_ips: Vec::new(),
    };

    let result = manager.add_jail("sshd", resolved);
    assert!(result.is_err());
    match result.unwrap_err() {
        crate::Error::JailAlreadyExists(name) => assert_eq!(name, "sshd"),
        other => panic!("Expected JailAlreadyExists, got: {:?}", other),
    }
}

// ---------- remove_jail() ----------

#[test]
fn remove_jail_removes_existing_jail() {
    let (_dir, mut manager) = setup();

    manager.remove_jail("sshd").unwrap();

    let status = manager.status().unwrap();
    assert_eq!(status.jails.len(), 0);
}

#[test]
fn remove_jail_nonexistent_returns_not_found() {
    let (_dir, mut manager) = setup();

    let result = manager.remove_jail("nonexistent");
    assert!(result.is_err());
    match result.unwrap_err() {
        crate::Error::JailNotFound(name) => assert_eq!(name, "nonexistent"),
        other => panic!("Expected JailNotFound, got: {:?}", other),
    }
}

// ---------- scan_all() ----------

#[test]
fn scan_all_returns_results_for_each_jail() {
    let dir = tempdir().unwrap();
    let log_path = dir.path().join("auth.log");
    write_sample_log(&log_path);

    let mut jails = HashMap::new();
    jails.insert(
        "sshd".to_string(),
        JailConfig {
            enabled: true,
            log_path: log_path.clone(),
            pattern: r"Failed password for .* from (?P<ip>\d+\.\d+\.\d+\.\d+)".to_string(),
            find_time: None,
            ban_time: None,
            max_retry: None,
            ban_action: None,
            unban_action: None,
            ignore_ips: Vec::new(),
        },
    );
    jails.insert(
        "nginx".to_string(),
        JailConfig {
            enabled: true,
            log_path: log_path.clone(),
            pattern: r"error from (?P<ip>\d+\.\d+\.\d+\.\d+)".to_string(),
            find_time: None,
            ban_time: None,
            max_retry: None,
            ban_action: None,
            unban_action: None,
            ignore_ips: Vec::new(),
        },
    );

    let config = Fail2BanConfig {
        defaults: DefaultConfig::default(),
        jails,
        actions: HashMap::new(),
        global: crate::config::GlobalConfig::default(),
    };
    let paths = make_paths(&dir);
    let mut manager = Fail2BanManager::new(config, paths).unwrap();

    let results = manager.scan_all(ExecutionMode::DryRun).unwrap();
    assert_eq!(results.len(), 2);
    assert!(results.contains_key("sshd"));
    assert!(results.contains_key("nginx"));
}

#[test]
fn scan_all_empty_jails_returns_empty_map() {
    let dir = tempdir().unwrap();
    let log_path = dir.path().join("auth.log");
    write_sample_log(&log_path);
    let config = make_config(&log_path);
    let paths = make_paths(&dir);
    let mut manager = Fail2BanManager::new(config, paths).unwrap();

    manager.remove_jail("sshd").unwrap();

    let results = manager.scan_all(ExecutionMode::DryRun).unwrap();
    assert!(results.is_empty());
}

// ---------- scan_jail() ----------

#[test]
fn scan_jail_returns_result_for_existing_jail() {
    let dir = tempdir().unwrap();
    let log_path = dir.path().join("auth.log");
    write_sample_log(&log_path);
    let config = make_config(&log_path);
    let paths = make_paths(&dir);
    let mut manager = Fail2BanManager::new(config, paths).unwrap();

    let result = manager.scan_jail("sshd", ExecutionMode::DryRun).unwrap();
    // The sample log has "Failed password" lines with IPs, so there should be matches.
    assert!(result.lines_scanned > 0);
}

#[test]
fn scan_jail_nonexistent_returns_not_found() {
    let (_dir, mut manager) = setup();

    let result = manager.scan_jail("nonexistent", ExecutionMode::DryRun);
    assert!(result.is_err());
    match result.unwrap_err() {
        crate::Error::JailNotFound(name) => assert_eq!(name, "nonexistent"),
        other => panic!("Expected JailNotFound, got: {:?}", other),
    }
}

// ---------- ban_ip() ----------

#[test]
fn ban_ip_succeeds_for_existing_jail() {
    let (_dir, manager) = setup();
    let ip: std::net::IpAddr = "192.168.1.100".parse().unwrap();

    // ban_ip with dry_run should succeed without running any commands.
    manager.ban_ip("sshd", ip, ExecutionMode::DryRun).unwrap();
}

#[test]
fn ban_ip_nonexistent_jail_returns_not_found() {
    let (_dir, manager) = setup();
    let ip: std::net::IpAddr = "192.168.1.100".parse().unwrap();

    let result = manager.ban_ip("nonexistent", ip, ExecutionMode::DryRun);
    assert!(result.is_err());
    match result.unwrap_err() {
        crate::Error::JailNotFound(name) => assert_eq!(name, "nonexistent"),
        other => panic!("Expected JailNotFound, got: {:?}", other),
    }
}

#[test]
fn ban_ip_duplicate_returns_already_banned() {
    let (_dir, manager) = setup();
    let ip: std::net::IpAddr = "192.168.1.100".parse().unwrap();

    manager.ban_ip("sshd", ip, ExecutionMode::DryRun).unwrap();
    let result = manager.ban_ip("sshd", ip, ExecutionMode::DryRun);
    assert!(result.is_err());
    match result.unwrap_err() {
        crate::Error::AlreadyBanned(_) => {}
        other => panic!("Expected AlreadyBanned, got: {:?}", other),
    }
}

// ---------- unban_ip() ----------

#[test]
fn unban_ip_succeeds_for_banned_ip() {
    let (_dir, manager) = setup();
    let ip: std::net::IpAddr = "192.168.1.100".parse().unwrap();

    manager.ban_ip("sshd", ip, ExecutionMode::DryRun).unwrap();
    manager.unban_ip("sshd", "192.168.1.100".parse().unwrap(), ExecutionMode::DryRun).unwrap();
}

#[test]
fn unban_ip_nonexistent_jail_returns_not_found() {
    let (_dir, manager) = setup();

    let result = manager.unban_ip("nonexistent", "192.168.1.100".parse().unwrap(), ExecutionMode::DryRun);
    assert!(result.is_err());
    match result.unwrap_err() {
        crate::Error::JailNotFound(name) => assert_eq!(name, "nonexistent"),
        other => panic!("Expected JailNotFound, got: {:?}", other),
    }
}

#[test]
fn unban_ip_not_banned_returns_not_banned() {
    let (_dir, manager) = setup();

    let result = manager.unban_ip("sshd", "192.168.1.100".parse().unwrap(), ExecutionMode::DryRun);
    assert!(result.is_err());
    match result.unwrap_err() {
        crate::Error::NotBanned(_) => {}
        other => panic!("Expected NotBanned, got: {:?}", other),
    }
}

// ---------- status() ----------

#[test]
fn status_returns_correct_jail_count() {
    let (_dir, manager) = setup();

    let status = manager.status().unwrap();
    assert!(status.running);
    assert_eq!(status.jails.len(), 1);
    assert_eq!(status.jails[0].name, "sshd");
    assert!(status.jails[0].active);
}

#[test]
fn status_reflects_added_and_removed_jails() {
    let dir = tempdir().unwrap();
    let log_path = dir.path().join("auth.log");
    write_sample_log(&log_path);
    let config = make_config(&log_path);
    let paths = make_paths(&dir);
    let mut manager = Fail2BanManager::new(config, paths).unwrap();

    let log_path2 = dir.path().join("nginx.log");
    write_sample_log(&log_path2);

    let resolved = crate::config::ResolvedJail {
        name: "nginx".to_string(),
        enabled: true,
        log_path: log_path2,
        pattern: r"error".to_string(),
        find_time: 600,
        ban_time: 3600,
        max_retry: 5,
        ban_action: "ban".to_string(),
        unban_action: "unban".to_string(),
        ignore_ips: Vec::new(),
    };
    manager.add_jail("nginx", resolved).unwrap();

    let status = manager.status().unwrap();
    assert_eq!(status.jails.len(), 2);

    manager.remove_jail("sshd").unwrap();
    let status = manager.status().unwrap();
    assert_eq!(status.jails.len(), 1);
    assert_eq!(status.jails[0].name, "nginx");
}

#[test]
fn status_config_path_matches_paths() {
    let dir = tempdir().unwrap();
    let log_path = dir.path().join("auth.log");
    write_sample_log(&log_path);
    let config = make_config(&log_path);
    let paths = make_paths(&dir);
    let manager = Fail2BanManager::new(config, paths).unwrap();

    let status = manager.status().unwrap();
    assert_eq!(status.config_path, dir.path().join("config").join("config.json"));
}

// ---------- jail_status() ----------

#[test]
fn jail_status_returns_status_for_existing_jail() {
    let (_dir, manager) = setup();

    let js = manager.jail_status("sshd").unwrap();
    assert_eq!(js.name, "sshd");
    assert!(js.active);
    assert!(js.banned_ips.is_empty());
}

#[test]
fn jail_status_shows_banned_ips() {
    let (_dir, manager) = setup();
    let ip: std::net::IpAddr = "192.168.1.100".parse().unwrap();

    manager.ban_ip("sshd", ip, ExecutionMode::DryRun).unwrap();

    let js = manager.jail_status("sshd").unwrap();
    assert_eq!(js.banned_ips.len(), 1);
    assert_eq!(js.banned_ips[0].ip, ip);
}

#[test]
fn jail_status_nonexistent_returns_not_found() {
    let (_dir, manager) = setup();

    let result = manager.jail_status("nonexistent");
    assert!(result.is_err());
    match result.unwrap_err() {
        crate::Error::JailNotFound(name) => assert_eq!(name, "nonexistent"),
        other => panic!("Expected JailNotFound, got: {:?}", other),
    }
}

// ---------- purge_expired() ----------

#[test]
fn purge_expired_returns_empty_when_no_expired_bans() {
    let (_dir, manager) = setup();

    let expired = manager.purge_expired().unwrap();
    assert!(expired.is_empty());
}

#[test]
fn purge_expired_removes_expired_bans() {
    let dir = tempdir().unwrap();
    let log_path = dir.path().join("auth.log");
    write_sample_log(&log_path);

    // Use a very short ban_time so the ban expires quickly.
    let mut jails = HashMap::new();
    jails.insert(
        "sshd".to_string(),
        JailConfig {
            enabled: true,
            log_path: log_path.clone(),
            pattern: r"Failed password for .* from (?P<ip>\d+\.\d+\.\d+\.\d+)".to_string(),
            find_time: Some(600),
            ban_time: Some(1),
            max_retry: Some(5),
            ban_action: None,
            unban_action: None,
            ignore_ips: Vec::new(),
        },
    );
    let config = Fail2BanConfig {
        defaults: DefaultConfig::default(),
        jails,
        actions: HashMap::new(),
        global: crate::config::GlobalConfig::default(),
    };
    let paths = make_paths(&dir);
    let manager = Fail2BanManager::new(config, paths).unwrap();

    // Manually inject an expired ban entry into the store to test purge.
    use chrono::{Duration, Utc};
    let expired_entry = crate::types::BanEntry {
        ip: "10.0.0.99".parse().unwrap(),
        prefix: 32,
        banned_at: Utc::now() - Duration::hours(2),
        expires_at: Some(Utc::now() - Duration::hours(1)),
        jail_name: "sshd".to_string(),
        fail_count: 5,
        last_fail_at: Utc::now() - Duration::hours(2),
        reason: Some("test".to_string()),
    };

    // Write the expired entry directly into the store file.
    let store_data = crate::store::StoreData {
        active_bans: vec![expired_entry],
        history: Vec::new(),
        journals: Vec::new(),
    };
    let store_json = serde_json::to_string_pretty(&store_data).unwrap();
    std::fs::write(dir.path().join("data").join("bans.json"), store_json).unwrap();

    let expired = manager.purge_expired().unwrap();
    assert_eq!(expired.len(), 1);
    assert_eq!(expired[0].ip, "10.0.0.99".parse::<std::net::IpAddr>().unwrap());
}

// ---------- firewall() ----------

#[test]
fn firewall_returns_detected_firewall() {
    let (_dir, manager) = setup();

    // On macOS this will be Pf, on Linux it will be Iptables or Nftables.
    let fw = manager.firewall();
    // Just verify it returns a valid variant (does not panic).
    let _ = format!("{:?}", fw);
}

// ---------- config() ----------

#[test]
fn config_returns_reference_to_config() {
    let dir = tempdir().unwrap();
    let log_path = dir.path().join("auth.log");
    write_sample_log(&log_path);
    let config = make_config(&log_path);
    let paths = make_paths(&dir);
    let manager = Fail2BanManager::new(config, paths).unwrap();

    let cfg = manager.config();
    assert!(cfg.jails.contains_key("sshd"));
}

// ---------- paths() ----------

#[test]
fn paths_returns_reference_to_paths() {
    let dir = tempdir().unwrap();
    let log_path = dir.path().join("auth.log");
    write_sample_log(&log_path);
    let config = make_config(&log_path);
    let paths = make_paths(&dir);
    let manager = Fail2BanManager::new(config, paths).unwrap();

    let p = manager.paths();
    assert_eq!(p.ban_db, dir.path().join("data").join("bans.json"));
    assert_eq!(p.config_file, dir.path().join("config").join("config.json"));
}

// ---------- Integration-style tests ----------

#[test]
fn ban_then_unban_reflects_in_status() {
    let (_dir, manager) = setup();
    let ip: std::net::IpAddr = "192.168.1.100".parse().unwrap();

    manager.ban_ip("sshd", ip, ExecutionMode::DryRun).unwrap();
    let js = manager.jail_status("sshd").unwrap();
    assert_eq!(js.banned_ips.len(), 1);
    assert_eq!(js.banned_ips[0].ip, ip);

    manager.unban_ip("sshd", "192.168.1.100".parse().unwrap(), ExecutionMode::DryRun).unwrap();
    let js = manager.jail_status("sshd").unwrap();
    assert!(js.banned_ips.is_empty());
}

#[test]
fn multiple_bans_in_same_jail() {
    let (_dir, manager) = setup();

    let ip1: std::net::IpAddr = "192.168.1.1".parse().unwrap();
    let ip2: std::net::IpAddr = "192.168.1.2".parse().unwrap();
    let ip3: std::net::IpAddr = "192.168.1.3".parse().unwrap();

    manager.ban_ip("sshd", ip1, ExecutionMode::DryRun).unwrap();
    manager.ban_ip("sshd", ip2, ExecutionMode::DryRun).unwrap();
    manager.ban_ip("sshd", ip3, ExecutionMode::DryRun).unwrap();

    let js = manager.jail_status("sshd").unwrap();
    assert_eq!(js.banned_ips.len(), 3);
}

#[test]
fn remove_jail_then_add_again_succeeds() {
    let dir = tempdir().unwrap();
    let log_path = dir.path().join("auth.log");
    write_sample_log(&log_path);
    let config = make_config(&log_path);
    let paths = make_paths(&dir);
    let mut manager = Fail2BanManager::new(config, paths).unwrap();

    manager.remove_jail("sshd").unwrap();

    let log_path2 = dir.path().join("auth2.log");
    write_sample_log(&log_path2);

    let resolved = crate::config::ResolvedJail {
        name: "sshd".to_string(),
        enabled: true,
        log_path: log_path2,
        pattern: r"Failed password".to_string(),
        find_time: 600,
        ban_time: 3600,
        max_retry: 5,
        ban_action: "ban".to_string(),
        unban_action: "unban".to_string(),
        ignore_ips: Vec::new(),
    };
    manager.add_jail("sshd", resolved).unwrap();

    let status = manager.status().unwrap();
    assert_eq!(status.jails.len(), 1);
    assert_eq!(status.jails[0].name, "sshd");
}
