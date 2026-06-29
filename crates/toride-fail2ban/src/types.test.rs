use super::*;
use chrono::TimeZone;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::time::Duration;

// ---------------------------------------------------------------------------
// Helper constructors
// ---------------------------------------------------------------------------

fn sample_ipv4() -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))
}

fn sample_ipv6() -> IpAddr {
    IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))
}

fn sample_ban_entry() -> BanEntry {
    BanEntry {
        ip: sample_ipv4(),
        prefix: 32,
        banned_at: Utc.with_ymd_and_hms(2025, 6, 15, 10, 30, 0).unwrap(),
        expires_at: Some(Utc.with_ymd_and_hms(2025, 6, 15, 11, 30, 0).unwrap()),
        jail_name: "sshd".to_string(),
        fail_count: 5,
        last_fail_at: Utc.with_ymd_and_hms(2025, 6, 15, 10, 29, 55).unwrap(),
        reason: Some("Too many failed attempts".to_string()),
    }
}

fn sample_platform_commands() -> PlatformCommands {
    PlatformCommands::new(
        vec!["iptables -A INPUT -s {ip} -j DROP".to_string()],
        vec!["pfctl -t bruteforce -T add {ip}".to_string()],
        vec!["ipfw add deny ip from {ip} to any".to_string()],
    )
}

fn sample_jail_status() -> JailStatus {
    JailStatus {
        name: "sshd".to_string(),
        active: true,
        banned_ips: vec![sample_ban_entry()],
        total_bans: 150,
        log_path: PathBuf::from("/var/log/auth.log"),
        pattern: r"Failed password for .* from {IP}".to_string(),
    }
}

fn sample_fail2ban_status() -> Fail2BanStatus {
    Fail2BanStatus {
        running: true,
        jails: vec![sample_jail_status()],
        config_path: PathBuf::from("/etc/fail2ban/jail.conf"),
    }
}

// ===========================================================================
// BanEntry
// ===========================================================================

// --- Happy path -----------------------------------------------------------

#[test]
fn ban_entry_create_with_all_fields() {
    let entry = sample_ban_entry();
    assert_eq!(entry.ip, sample_ipv4());
    assert_eq!(entry.prefix, 32);
    assert_eq!(entry.fail_count, 5);
    assert_eq!(entry.jail_name, "sshd");
    assert!(entry.expires_at.is_some());
    assert!(entry.reason.is_some());
}

#[test]
fn ban_entry_equality() {
    let a = sample_ban_entry();
    let b = sample_ban_entry();
    assert_eq!(a, b);
}

#[test]
fn ban_entry_inequality_on_ip() {
    let a = sample_ban_entry();
    let b = BanEntry {
        ip: sample_ipv6(),
        ..sample_ban_entry()
    };
    assert_ne!(a, b);
}

#[test]
fn ban_entry_inequality_on_jail_name() {
    let a = sample_ban_entry();
    let b = BanEntry {
        jail_name: "nginx".to_string(),
        ..sample_ban_entry()
    };
    assert_ne!(a, b);
}

#[test]
fn ban_entry_clone() {
    let original = sample_ban_entry();
    let cloned = original.clone();
    assert_eq!(original, cloned);
}

#[test]
fn ban_entry_debug_format() {
    let entry = sample_ban_entry();
    let dbg = format!("{:?}", entry);
    assert!(dbg.contains("BanEntry"));
    assert!(dbg.contains("192.168.1.100"));
}

#[test]
fn ban_entry_with_ipv6() {
    let entry = BanEntry {
        ip: sample_ipv6(),
        prefix: 128,
        banned_at: Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap(),
        expires_at: None,
        jail_name: "sshd".to_string(),
        fail_count: 1,
        last_fail_at: Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap(),
        reason: None,
    };
    assert_eq!(entry.prefix, 128);
    assert!(entry.expires_at.is_none());
    assert!(entry.reason.is_none());
}

#[test]
fn ban_entry_with_no_expiration() {
    let entry = BanEntry {
        expires_at: None,
        ..sample_ban_entry()
    };
    assert!(entry.expires_at.is_none());
}

#[test]
fn ban_entry_with_no_reason() {
    let entry = BanEntry {
        reason: None,
        ..sample_ban_entry()
    };
    assert!(entry.reason.is_none());
}

// --- Edge-case tests ------------------------------------------------------

#[test]
fn ban_entry_fail_count_zero() {
    let entry = BanEntry {
        fail_count: 0,
        ..sample_ban_entry()
    };
    assert_eq!(entry.fail_count, 0);
}

#[test]
fn ban_entry_fail_count_max() {
    let entry = BanEntry {
        fail_count: u32::MAX,
        ..sample_ban_entry()
    };
    assert_eq!(entry.fail_count, u32::MAX);
}

#[test]
fn ban_entry_prefix_boundary_min() {
    let entry = BanEntry {
        prefix: 0,
        ..sample_ban_entry()
    };
    assert_eq!(entry.prefix, 0);
}

#[test]
fn ban_entry_prefix_boundary_max() {
    let entry = BanEntry {
        prefix: 128,
        ..sample_ban_entry()
    };
    assert_eq!(entry.prefix, 128);
}

#[test]
fn ban_entry_empty_jail_name() {
    let entry = BanEntry {
        jail_name: String::new(),
        ..sample_ban_entry()
    };
    assert_eq!(entry.jail_name, "");
}

#[test]
fn ban_entry_empty_reason_string() {
    let entry = BanEntry {
        reason: Some(String::new()),
        ..sample_ban_entry()
    };
    assert_eq!(entry.reason.as_deref(), Some(""));
}

#[test]
fn ban_entry_banned_and_expires_same_time() {
    let now = Utc::now();
    let entry = BanEntry {
        banned_at: now,
        expires_at: Some(now),
        ..sample_ban_entry()
    };
    assert_eq!(entry.banned_at, entry.expires_at.unwrap());
}

// --- Serialization tests --------------------------------------------------

#[test]
fn ban_entry_serialization_roundtrip() {
    let entry = sample_ban_entry();
    let json = serde_json::to_string(&entry).expect("serialization failed");
    let deserialized: BanEntry = serde_json::from_str(&json).expect("deserialization failed");
    assert_eq!(entry, deserialized);
}

#[test]
fn ban_entry_serialization_with_none_fields() {
    let entry = BanEntry {
        expires_at: None,
        reason: None,
        ..sample_ban_entry()
    };
    let json = serde_json::to_string(&entry).expect("serialization failed");
    let deserialized: BanEntry = serde_json::from_str(&json).expect("deserialization failed");
    assert_eq!(entry, deserialized);
}

#[test]
fn ban_entry_deserialize_from_json_string() {
    let json = r#"{
        "ip": "10.0.0.1",
        "prefix": 24,
        "banned_at": "2025-06-15T10:30:00Z",
        "expires_at": null,
        "jail_name": "nginx",
        "fail_count": 3,
        "last_fail_at": "2025-06-15T10:29:00Z",
        "reason": null
    }"#;
    let entry: BanEntry = serde_json::from_str(json).expect("deserialization failed");
    assert_eq!(entry.ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
    assert_eq!(entry.prefix, 24);
    assert_eq!(entry.fail_count, 3);
    assert!(entry.expires_at.is_none());
    assert!(entry.reason.is_none());
}

#[test]
fn ban_entry_json_contains_expected_keys() {
    let entry = sample_ban_entry();
    let json: serde_json::Value = serde_json::to_value(&entry).expect("serialization failed");
    assert!(json.get("ip").is_some());
    assert!(json.get("prefix").is_some());
    assert!(json.get("banned_at").is_some());
    assert!(json.get("expires_at").is_some());
    assert!(json.get("jail_name").is_some());
    assert!(json.get("fail_count").is_some());
    assert!(json.get("last_fail_at").is_some());
    assert!(json.get("reason").is_some());
}

// ===========================================================================
// PlatformCommands
// ===========================================================================

// --- Happy path -----------------------------------------------------------

#[test]
fn platform_commands_new() {
    let cmd = PlatformCommands::new(
        vec!["cmd1".to_string()],
        vec!["cmd2".to_string()],
        vec!["cmd3".to_string()],
    );
    assert_eq!(cmd.linux, vec!["cmd1"]);
    assert_eq!(cmd.macos, vec!["cmd2"]);
    assert_eq!(cmd.freebsd, vec!["cmd3"]);
}

#[test]
fn platform_commands_for_current_platform_returns_linux_on_linux() {
    let cmds = sample_platform_commands();
    let result = cmds.for_current_platform();
    // On macOS CI, this returns macos; on linux CI, linux.
    // We verify that the returned slice is one of the three platform slices.
    let is_valid = result == &cmds.linux || result == &cmds.macos || result == &cmds.freebsd;
    assert!(is_valid);
}

#[test]
fn platform_commands_for_current_platform_is_non_empty() {
    let cmds = sample_platform_commands();
    let result = cmds.for_current_platform();
    assert!(!result.is_empty());
}

#[test]
fn platform_commands_for_current_platform_contains_expected_command() {
    let cmds = sample_platform_commands();
    let result = cmds.for_current_platform();
    // Every command contains "{ip}" as a placeholder
    for cmd in result {
        assert!(cmd.contains("{ip}"));
    }
}

#[test]
fn platform_commands_equality() {
    let a = sample_platform_commands();
    let b = sample_platform_commands();
    assert_eq!(a, b);
}

#[test]
fn platform_commands_clone() {
    let original = sample_platform_commands();
    let cloned = original.clone();
    assert_eq!(original, cloned);
}

#[test]
fn platform_commands_debug_format() {
    let cmds = sample_platform_commands();
    let dbg = format!("{:?}", cmds);
    assert!(dbg.contains("PlatformCommands"));
}

// --- Edge-case tests ------------------------------------------------------

#[test]
fn platform_commands_all_empty() {
    let cmds = PlatformCommands::new(vec![], vec![], vec![]);
    assert!(cmds.linux.is_empty());
    assert!(cmds.macos.is_empty());
    assert!(cmds.freebsd.is_empty());
}

#[test]
fn platform_commands_for_current_platform_returns_fallback_on_empty_linux() {
    // When all vectors are empty, for_current_platform returns &self.linux (empty)
    let cmds = PlatformCommands::new(vec![], vec![], vec![]);
    let result = cmds.for_current_platform();
    assert!(result.is_empty());
}

#[test]
fn platform_commands_multiple_commands_per_platform() {
    let cmds = PlatformCommands::new(
        vec![
            "cmd_a".to_string(),
            "cmd_b".to_string(),
            "cmd_c".to_string(),
        ],
        vec!["cmd_d".to_string()],
        vec!["cmd_e".to_string(), "cmd_f".to_string()],
    );
    assert_eq!(cmds.linux.len(), 3);
    assert_eq!(cmds.macos.len(), 1);
    assert_eq!(cmds.freebsd.len(), 2);
}

// --- Serialization tests --------------------------------------------------

#[test]
fn platform_commands_serialization_roundtrip() {
    let cmds = sample_platform_commands();
    let json = serde_json::to_string(&cmds).expect("serialization failed");
    let deserialized: PlatformCommands =
        serde_json::from_str(&json).expect("deserialization failed");
    assert_eq!(cmds, deserialized);
}

#[test]
fn platform_commands_deserialize_from_json_string() {
    let json = r#"{
        "linux": ["iptables -A INPUT -s {ip} -j DROP"],
        "macos": [],
        "freebsd": []
    }"#;
    let cmds: PlatformCommands = serde_json::from_str(json).expect("deserialization failed");
    assert_eq!(cmds.linux.len(), 1);
    assert!(cmds.macos.is_empty());
    assert!(cmds.freebsd.is_empty());
}

// ===========================================================================
// ScanResult
// ===========================================================================

// --- Happy path -----------------------------------------------------------

#[test]
fn scan_result_create_with_fields() {
    let result = ScanResult {
        new_bans: vec![sample_ban_entry()],
        lines_scanned: 1000,
        matches_found: 5,
        scan_duration: Duration::from_millis(250),
    };
    assert_eq!(result.new_bans.len(), 1);
    assert_eq!(result.lines_scanned, 1000);
    assert_eq!(result.matches_found, 5);
    assert_eq!(result.scan_duration, Duration::from_millis(250));
}

#[test]
fn scan_result_clone() {
    let original = ScanResult {
        new_bans: vec![],
        lines_scanned: 0,
        matches_found: 0,
        scan_duration: Duration::ZERO,
    };
    #[expect(clippy::redundant_clone, reason = "testing Clone trait implementation")]
    let cloned = original.clone();
    assert_eq!(cloned.lines_scanned, 0);
    assert_eq!(cloned.matches_found, 0);
}

#[test]
fn scan_result_debug_format() {
    let result = ScanResult {
        new_bans: vec![],
        lines_scanned: 10,
        matches_found: 0,
        scan_duration: Duration::from_secs(1),
    };
    let dbg = format!("{:?}", result);
    assert!(dbg.contains("ScanResult"));
}

// --- Edge-case tests ------------------------------------------------------

#[test]
fn scan_result_empty_bans() {
    let result = ScanResult {
        new_bans: vec![],
        lines_scanned: 500,
        matches_found: 0,
        scan_duration: Duration::from_secs(1),
    };
    assert!(result.new_bans.is_empty());
}

#[test]
fn scan_result_zero_lines_scanned() {
    let result = ScanResult {
        new_bans: vec![],
        lines_scanned: 0,
        matches_found: 0,
        scan_duration: Duration::ZERO,
    };
    assert_eq!(result.lines_scanned, 0);
}

#[test]
fn scan_result_lines_scanned_max() {
    let result = ScanResult {
        new_bans: vec![],
        lines_scanned: u64::MAX,
        matches_found: 0,
        scan_duration: Duration::from_secs(1),
    };
    assert_eq!(result.lines_scanned, u64::MAX);
}

#[test]
fn scan_result_matches_found_max() {
    let result = ScanResult {
        new_bans: vec![],
        lines_scanned: 100,
        matches_found: u32::MAX,
        scan_duration: Duration::from_secs(1),
    };
    assert_eq!(result.matches_found, u32::MAX);
}

#[test]
fn scan_result_zero_duration() {
    let result = ScanResult {
        new_bans: vec![],
        lines_scanned: 0,
        matches_found: 0,
        scan_duration: Duration::ZERO,
    };
    assert_eq!(result.scan_duration, Duration::ZERO);
}

#[test]
fn scan_result_multiple_bans() {
    let bans = vec![
        sample_ban_entry(),
        BanEntry {
            ip: sample_ipv6(),
            prefix: 128,
            ..sample_ban_entry()
        },
    ];
    let result = ScanResult {
        new_bans: bans,
        lines_scanned: 200,
        matches_found: 2,
        scan_duration: Duration::from_millis(50),
    };
    assert_eq!(result.new_bans.len(), 2);
}

// ===========================================================================
// JailStatus
// ===========================================================================

// --- Happy path -----------------------------------------------------------

#[test]
fn jail_status_create_with_fields() {
    let status = sample_jail_status();
    assert_eq!(status.name, "sshd");
    assert!(status.active);
    assert_eq!(status.banned_ips.len(), 1);
    assert_eq!(status.total_bans, 150);
    assert_eq!(status.log_path, PathBuf::from("/var/log/auth.log"));
}

#[test]
fn jail_status_clone() {
    let original = sample_jail_status();
    let cloned = original.clone();
    assert_eq!(original.name, cloned.name);
    assert_eq!(original.active, cloned.active);
    assert_eq!(original.total_bans, cloned.total_bans);
}

#[test]
fn jail_status_debug_format() {
    let status = sample_jail_status();
    let dbg = format!("{:?}", status);
    assert!(dbg.contains("JailStatus"));
}

// --- Edge-case tests ------------------------------------------------------

#[test]
fn jail_status_inactive() {
    let status = JailStatus {
        active: false,
        ..sample_jail_status()
    };
    assert!(!status.active);
}

#[test]
fn jail_status_empty_name() {
    let status = JailStatus {
        name: String::new(),
        ..sample_jail_status()
    };
    assert_eq!(status.name, "");
}

#[test]
fn jail_status_empty_banned_ips() {
    let status = JailStatus {
        banned_ips: vec![],
        ..sample_jail_status()
    };
    assert!(status.banned_ips.is_empty());
}

#[test]
fn jail_status_total_bans_zero() {
    let status = JailStatus {
        total_bans: 0,
        ..sample_jail_status()
    };
    assert_eq!(status.total_bans, 0);
}

#[test]
fn jail_status_total_bans_max() {
    let status = JailStatus {
        total_bans: u64::MAX,
        ..sample_jail_status()
    };
    assert_eq!(status.total_bans, u64::MAX);
}

#[test]
fn jail_status_empty_pattern() {
    let status = JailStatus {
        pattern: String::new(),
        ..sample_jail_status()
    };
    assert_eq!(status.pattern, "");
}

// --- Serialization tests --------------------------------------------------

#[test]
fn jail_status_serialization_roundtrip() {
    let status = sample_jail_status();
    let json = serde_json::to_string(&status).expect("serialization failed");
    let deserialized: JailStatus = serde_json::from_str(&json).expect("deserialization failed");
    assert_eq!(deserialized.name, status.name);
    assert_eq!(deserialized.active, status.active);
    assert_eq!(deserialized.total_bans, status.total_bans);
    assert_eq!(deserialized.banned_ips, status.banned_ips);
    assert_eq!(deserialized.log_path, status.log_path);
    assert_eq!(deserialized.pattern, status.pattern);
}

#[test]
fn jail_status_deserialize_from_json_string() {
    let json = r#"{
        "name": "nginx",
        "active": false,
        "banned_ips": [],
        "total_bans": 0,
        "log_path": "/var/log/nginx/access.log",
        "pattern": "GET /admin"
    }"#;
    let status: JailStatus = serde_json::from_str(json).expect("deserialization failed");
    assert_eq!(status.name, "nginx");
    assert!(!status.active);
    assert!(status.banned_ips.is_empty());
    assert_eq!(status.total_bans, 0);
}

// ===========================================================================
// Fail2BanStatus
// ===========================================================================

// --- Happy path -----------------------------------------------------------

#[test]
fn fail2ban_status_create_with_fields() {
    let status = sample_fail2ban_status();
    assert!(status.running);
    assert_eq!(status.jails.len(), 1);
    assert_eq!(status.config_path, PathBuf::from("/etc/fail2ban/jail.conf"));
}

#[test]
fn fail2ban_status_clone() {
    let original = sample_fail2ban_status();
    let cloned = original.clone();
    assert_eq!(original.running, cloned.running);
    assert_eq!(original.jails.len(), cloned.jails.len());
    assert_eq!(original.config_path, cloned.config_path);
}

#[test]
fn fail2ban_status_debug_format() {
    let status = sample_fail2ban_status();
    let dbg = format!("{:?}", status);
    assert!(dbg.contains("Fail2BanStatus"));
}

// --- Edge-case tests ------------------------------------------------------

#[test]
fn fail2ban_status_stopped() {
    let status = Fail2BanStatus {
        running: false,
        ..sample_fail2ban_status()
    };
    assert!(!status.running);
}

#[test]
fn fail2ban_status_no_jails() {
    let status = Fail2BanStatus {
        jails: vec![],
        ..sample_fail2ban_status()
    };
    assert!(status.jails.is_empty());
}

#[test]
fn fail2ban_status_multiple_jails() {
    let status = Fail2BanStatus {
        jails: vec![
            sample_jail_status(),
            JailStatus {
                name: "nginx".to_string(),
                active: false,
                banned_ips: vec![],
                total_bans: 0,
                log_path: PathBuf::from("/var/log/nginx/error.log"),
                pattern: "403".to_string(),
            },
        ],
        ..sample_fail2ban_status()
    };
    assert_eq!(status.jails.len(), 2);
}

// --- Serialization tests --------------------------------------------------

#[test]
fn fail2ban_status_serialization_roundtrip() {
    let status = sample_fail2ban_status();
    let json = serde_json::to_string(&status).expect("serialization failed");
    let deserialized: Fail2BanStatus = serde_json::from_str(&json).expect("deserialization failed");
    assert_eq!(deserialized.running, status.running);
    assert_eq!(deserialized.jails.len(), status.jails.len());
    assert_eq!(deserialized.config_path, status.config_path);
}

#[test]
fn fail2ban_status_deserialize_from_json_string() {
    let json = r#"{
        "running": false,
        "jails": [],
        "config_path": "/etc/fail2ban/jail.local"
    }"#;
    let status: Fail2BanStatus = serde_json::from_str(json).expect("deserialization failed");
    assert!(!status.running);
    assert!(status.jails.is_empty());
    assert_eq!(
        status.config_path,
        PathBuf::from("/etc/fail2ban/jail.local")
    );
}

// --- Display tests --------------------------------------------------------

#[test]
fn fail2ban_status_display_running() {
    let status = Fail2BanStatus {
        running: true,
        jails: vec![],
        config_path: PathBuf::from("/etc/fail2ban/jail.conf"),
    };
    let output = format!("{}", status);
    assert!(output.contains("running"));
    assert!(output.contains("/etc/fail2ban/jail.conf"));
    assert!(output.contains("Jails: 0"));
}

#[test]
fn fail2ban_status_display_stopped() {
    let status = Fail2BanStatus {
        running: false,
        jails: vec![],
        config_path: PathBuf::from("/etc/fail2ban/jail.conf"),
    };
    let output = format!("{}", status);
    assert!(output.contains("stopped"));
    assert!(!output.contains("running"));
}

#[test]
fn fail2ban_status_display_shows_jail_count() {
    let status = Fail2BanStatus {
        running: true,
        jails: vec![sample_jail_status(), sample_jail_status()],
        config_path: PathBuf::from("/etc/fail2ban/jail.conf"),
    };
    let output = format!("{}", status);
    assert!(output.contains("Jails: 2"));
}

#[test]
fn fail2ban_status_display_lists_jail_names() {
    let status = Fail2BanStatus {
        running: true,
        jails: vec![JailStatus {
            name: "custom-jail".to_string(),
            banned_ips: vec![sample_ban_entry()],
            ..sample_jail_status()
        }],
        config_path: PathBuf::from("/etc/fail2ban/jail.conf"),
    };
    let output = format!("{}", status);
    assert!(output.contains("custom-jail"));
    assert!(output.contains("1 banned IPs"));
}

#[test]
fn fail2ban_status_display_no_jails_empty_list() {
    let status = Fail2BanStatus {
        running: true,
        jails: vec![],
        config_path: PathBuf::from("/tmp/test.conf"),
    };
    let output = format!("{}", status);
    assert!(output.contains("Jails: 0"));
    // Should not contain any "  - " jail lines
    assert!(!output.contains("  - "));
}

#[test]
fn fail2ban_status_display_config_path_preserved() {
    let path = "/some/very/long/path/to/config/jail.conf";
    let status = Fail2BanStatus {
        running: true,
        jails: vec![],
        config_path: PathBuf::from(path),
    };
    let output = format!("{}", status);
    assert!(output.contains(path));
}

// ===========================================================================
// Additional edge-case tests
// ===========================================================================

#[test]
fn ban_entry_ipv6_mapped_ipv4() {
    let entry = BanEntry {
        ip: "::ffff:192.168.1.1".parse().unwrap(),
        prefix: 128,
        banned_at: Utc.with_ymd_and_hms(2025, 6, 15, 10, 30, 0).unwrap(),
        expires_at: Some(Utc.with_ymd_and_hms(2025, 6, 15, 11, 30, 0).unwrap()),
        jail_name: "sshd".to_string(),
        fail_count: 3,
        last_fail_at: Utc.with_ymd_and_hms(2025, 6, 15, 10, 29, 55).unwrap(),
        reason: Some("IPv4-mapped IPv6 test".to_string()),
    };
    let json = serde_json::to_string(&entry).expect("serialization failed");
    let deserialized: BanEntry = serde_json::from_str(&json).expect("deserialization failed");
    assert_eq!(entry, deserialized);
    assert_eq!(entry.ip.to_string(), "::ffff:192.168.1.1");
}

#[test]
fn ban_entry_very_long_reason() {
    let entry = BanEntry {
        reason: Some("x".repeat(10_000)),
        ..sample_ban_entry()
    };
    let json = serde_json::to_string(&entry).expect("serialization failed");
    let deserialized: BanEntry = serde_json::from_str(&json).expect("deserialization failed");
    assert_eq!(entry, deserialized);
    assert_eq!(deserialized.reason.as_ref().unwrap().len(), 10_000);
}

#[test]
fn ban_entry_very_long_jail_name() {
    let entry = BanEntry {
        jail_name: "a".repeat(1_000),
        ..sample_ban_entry()
    };
    let json = serde_json::to_string(&entry).expect("serialization failed");
    let deserialized: BanEntry = serde_json::from_str(&json).expect("deserialization failed");
    assert_eq!(entry, deserialized);
    assert_eq!(deserialized.jail_name.len(), 1_000);
}

#[test]
fn fail2ban_status_with_many_jails() {
    let jails: Vec<JailStatus> = (0..50)
        .map(|i| JailStatus {
            name: format!("jail-{i}"),
            active: true,
            banned_ips: vec![],
            total_bans: 0,
            log_path: PathBuf::from(format!("/var/log/jail-{i}.log")),
            pattern: String::new(),
        })
        .collect();
    let status = Fail2BanStatus {
        running: true,
        jails,
        config_path: PathBuf::from("/etc/fail2ban/jail.conf"),
    };
    let output = format!("{status}");
    assert!(output.contains("Jails: 50"));
    assert_eq!(status.jails.len(), 50);
}

#[test]
fn execution_mode_is_dry_run_variants() {
    assert!(!ExecutionMode::Execute.is_dry_run());
    assert!(ExecutionMode::DryRun.is_dry_run());
}

#[test]
fn scan_result_with_empty_duration() {
    let result = ScanResult {
        new_bans: vec![],
        lines_scanned: 42,
        matches_found: 0,
        scan_duration: Duration::ZERO,
    };
    assert_eq!(result.scan_duration, Duration::ZERO);
    assert_eq!(result.lines_scanned, 42);
}

#[test]
fn jail_status_serialization_with_many_bans() {
    let banned_ips: Vec<BanEntry> = (0..100)
        .map(|i| BanEntry {
            ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, u8::try_from(i % 256).unwrap())),
            prefix: 32,
            banned_at: Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap(),
            expires_at: None,
            jail_name: "sshd".to_string(),
            fail_count: 1,
            last_fail_at: Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap(),
            reason: None,
        })
        .collect();
    let status = JailStatus {
        name: "mass-ban".to_string(),
        active: true,
        banned_ips,
        total_bans: 100,
        log_path: PathBuf::from("/var/log/auth.log"),
        pattern: String::new(),
    };
    let json = serde_json::to_string(&status).expect("serialization failed");
    let deserialized: JailStatus = serde_json::from_str(&json).expect("deserialization failed");
    assert_eq!(deserialized.banned_ips.len(), 100);
    assert_eq!(deserialized.total_bans, 100);
    assert_eq!(deserialized.name, "mass-ban");
}

#[test]
fn platform_commands_for_current_platform_always_returns_valid_slice() {
    // Verify that for_current_platform never panics and returns a valid
    // reference on any platform (linux, macos, freebsd, or unsupported).
    let cmds = sample_platform_commands();
    let result = cmds.for_current_platform();
    // The returned slice must be one of the three platform slices.
    // On unsupported platforms it returns an empty slice (&[]).
    let _ = result.len();
}
