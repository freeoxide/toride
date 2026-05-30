use super::*;
use std::fs;
use tempfile::tempdir;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn sample_platform_commands() -> PlatformCommands {
    PlatformCommands::new(
        vec!["iptables -A INPUT -s <ip> -j DROP".into()],
        vec!["pfctl -t f2b -T add <ip>".into()],
        vec!["ipfw add deny ip from <ip> to any".into()],
    )
}

fn sample_jail_config(log_path: std::path::PathBuf) -> JailConfig {
    JailConfig {
        enabled: true,
        log_path,
        pattern: r#"Failed password for .* from <HOST>"#.into(),
        find_time: None,
        ban_time: None,
        max_retry: None,
        ban_action: None,
        unban_action: None,
        ignore_ips: vec!["127.0.0.1".into(), "::1".into()],
    }
}

fn sample_action_config() -> ActionConfig {
    ActionConfig {
        commands: sample_platform_commands(),
        validation_commands: vec!["which iptables".into()],
    }
}

fn make_config_with_jail(log_path: std::path::PathBuf, jail_overrides: Option<JailConfig>) -> Fail2BanConfig {
    let jail = jail_overrides.unwrap_or_else(|| sample_jail_config(log_path.clone()));
    let mut jails = HashMap::new();
    jails.insert("sshd".to_string(), jail);

    let mut actions = HashMap::new();
    actions.insert("ban".to_string(), sample_action_config());

    Fail2BanConfig {
        defaults: DefaultConfig::default(),
        jails,
        actions,
        global: GlobalConfig::default(),
    }
}

// ---------------------------------------------------------------------------
// DefaultConfig tests
// ---------------------------------------------------------------------------

#[test]
fn default_config_has_expected_values() {
    let dc = DefaultConfig::default();
    assert_eq!(dc.find_time, 600);
    assert_eq!(dc.ban_time, 3600);
    assert_eq!(dc.max_retry, 5);
    assert_eq!(dc.ban_action, "ban");
    assert_eq!(dc.unban_action, "unban");
}

#[test]
fn default_config_serialization_roundtrip() {
    let dc = DefaultConfig::default();
    let json = serde_json::to_string(&dc).unwrap();
    let restored: DefaultConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(restored.find_time, dc.find_time);
    assert_eq!(restored.ban_time, dc.ban_time);
    assert_eq!(restored.max_retry, dc.max_retry);
    assert_eq!(restored.ban_action, dc.ban_action);
    assert_eq!(restored.unban_action, dc.unban_action);
}

#[test]
fn default_config_deserializes_from_partial_json() {
    // Missing fields should be filled by serde defaults.
    let json = r#"{"find_time": 300}"#;
    let dc: DefaultConfig = serde_json::from_str(json).unwrap();
    assert_eq!(dc.find_time, 300);
    assert_eq!(dc.ban_time, 3600);
    assert_eq!(dc.max_retry, 5);
}

// ---------------------------------------------------------------------------
// GlobalConfig tests
// ---------------------------------------------------------------------------

#[test]
fn global_config_has_expected_defaults() {
    let gc = GlobalConfig::default();
    assert_eq!(gc.scan_interval, 10);
    assert_eq!(gc.log_level, "info");
    assert!(gc.pid_file.is_none());
    assert_eq!(gc.max_history, 1000);
}

#[test]
fn global_config_serialization_roundtrip() {
    let gc = GlobalConfig {
        scan_interval: 30,
        log_level: "debug".into(),
        pid_file: Some("/var/run/f2b.pid".into()),
        max_history: 500,
    };
    let json = serde_json::to_string(&gc).unwrap();
    let restored: GlobalConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(restored.scan_interval, 30);
    assert_eq!(restored.log_level, "debug");
    assert_eq!(restored.pid_file, Some(std::path::PathBuf::from("/var/run/f2b.pid")));
    assert_eq!(restored.max_history, 500);
}

// ---------------------------------------------------------------------------
// JailConfig tests
// ---------------------------------------------------------------------------

#[test]
fn jail_config_enabled_defaults_to_true() {
    // `enabled` is absent in JSON -- serde should default it to true.
    let json = r#"{
        "log_path": "/var/log/auth.log",
        "pattern": "Failed password"
    }"#;
    let jail: JailConfig = serde_json::from_str(json).unwrap();
    assert!(jail.enabled);
    assert!(jail.ignore_ips.is_empty());
}

#[test]
fn jail_config_serialization_roundtrip() {
    let jail = JailConfig {
        enabled: false,
        log_path: "/tmp/test.log".into(),
        pattern: "pattern".into(),
        find_time: Some(120),
        ban_time: Some(7200),
        max_retry: Some(3),
        ban_action: Some("custom_ban".into()),
        unban_action: Some("custom_unban".into()),
        ignore_ips: vec!["10.0.0.0/8".into()],
    };
    let json = serde_json::to_string(&jail).unwrap();
    let restored: JailConfig = serde_json::from_str(&json).unwrap();
    assert!(!restored.enabled);
    assert_eq!(restored.log_path, std::path::PathBuf::from("/tmp/test.log"));
    assert_eq!(restored.pattern, "pattern");
    assert_eq!(restored.find_time, Some(120));
    assert_eq!(restored.ban_time, Some(7200));
    assert_eq!(restored.max_retry, Some(3));
    assert_eq!(restored.ban_action.as_deref(), Some("custom_ban"));
    assert_eq!(restored.unban_action.as_deref(), Some("custom_unban"));
    assert_eq!(restored.ignore_ips, vec!["10.0.0.0/8"]);
}

// ---------------------------------------------------------------------------
// ActionConfig tests
// ---------------------------------------------------------------------------

#[test]
fn action_config_serialization_roundtrip() {
    let ac = sample_action_config();
    let json = serde_json::to_string(&ac).unwrap();
    let restored: ActionConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(restored.commands, ac.commands);
    assert_eq!(restored.validation_commands, ac.validation_commands);
}

#[test]
fn action_config_deserializes_with_empty_validate() {
    let json = r#"{
        "commands": { "linux": [], "macos": [], "freebsd": [] },
        "validate": []
    }"#;
    let ac: ActionConfig = serde_json::from_str(json).unwrap();
    assert!(ac.validation_commands.is_empty());
    assert!(ac.commands.linux.is_empty());
}

// ---------------------------------------------------------------------------
// Fail2BanConfig tests -- serialization roundtrip
// ---------------------------------------------------------------------------

#[test]
fn full_config_serialization_roundtrip() {
    let dir = tempdir().unwrap();
    let log_path = dir.path().join("auth.log");
    fs::write(&log_path, "").unwrap();

    let config = make_config_with_jail(log_path, None);
    let json = serde_json::to_string_pretty(&config).unwrap();
    let restored: Fail2BanConfig = serde_json::from_str(&json).unwrap();

    assert_eq!(restored.jails.len(), 1);
    assert!(restored.jails.contains_key("sshd"));
    assert_eq!(restored.actions.len(), 1);
    assert!(restored.actions.contains_key("ban"));
    assert_eq!(restored.defaults.find_time, 600);
    assert_eq!(restored.global.log_level, "info");
}

#[test]
fn empty_config_deserializes_with_all_defaults() {
    let json = "{}";
    let config: Fail2BanConfig = serde_json::from_str(json).unwrap();
    assert!(config.jails.is_empty());
    assert!(config.actions.is_empty());
    assert_eq!(config.defaults.find_time, 600);
    assert_eq!(config.global.scan_interval, 10);
}

// ---------------------------------------------------------------------------
// Fail2BanConfig::validate() tests
// ---------------------------------------------------------------------------

#[test]
fn validate_rejects_zero_find_time() {
    let dir = tempdir().unwrap();
    let log_path = dir.path().join("auth.log");
    fs::write(&log_path, "").unwrap();

    let jail = JailConfig {
        find_time: Some(0),
        ..sample_jail_config(log_path)
    };
    let config = make_config_with_jail(dir.path().join("auth.log"), Some(jail));
    let result = config.validate();
    assert!(result.is_err());
    let msg = format!("{}", result.unwrap_err());
    assert!(msg.contains("find_time must be > 0"), "unexpected error: {msg}");
}

#[test]
fn validate_rejects_zero_max_retry() {
    let dir = tempdir().unwrap();
    let log_path = dir.path().join("auth.log");
    fs::write(&log_path, "").unwrap();

    let jail = JailConfig {
        max_retry: Some(0),
        ..sample_jail_config(log_path)
    };
    let config = make_config_with_jail(dir.path().join("auth.log"), Some(jail));
    let result = config.validate();
    assert!(result.is_err());
    let msg = format!("{}", result.unwrap_err());
    assert!(msg.contains("max_retry must be > 0"), "unexpected error: {msg}");
}

#[test]
fn validate_rejects_missing_log_file() {
    let dir = tempdir().unwrap();
    let nonexistent = dir.path().join("does_not_exist.log");

    let jail = sample_jail_config(nonexistent);
    let config = make_config_with_jail(dir.path().join("does_not_exist.log"), Some(jail));
    let result = config.validate();
    assert!(result.is_err());
    let msg = format!("{}", result.unwrap_err());
    assert!(msg.contains("log file does not exist"), "unexpected error: {msg}");
}

#[test]
fn validate_passes_with_valid_jail() {
    let dir = tempdir().unwrap();
    let log_path = dir.path().join("auth.log");
    fs::write(&log_path, "some log content").unwrap();

    let config = make_config_with_jail(log_path, None);
    assert!(config.validate().is_ok());
}

#[test]
fn validate_passes_for_empty_config() {
    let config = Fail2BanConfig::default();
    assert!(config.validate().is_ok());
}

#[test]
fn validate_reports_first_error() {
    // Two jails, both invalid -- should report whichever is iterated first.
    let dir = tempdir().unwrap();
    let log1 = dir.path().join("a.log");
    let log2 = dir.path().join("b.log");
    fs::write(&log1, "").unwrap();
    fs::write(&log2, "").unwrap();

    let mut jails = HashMap::new();
    jails.insert(
        "jail_a".to_string(),
        JailConfig {
            find_time: Some(0),
            ..sample_jail_config(log1)
        },
    );
    jails.insert(
        "jail_b".to_string(),
        JailConfig {
            max_retry: Some(0),
            ..sample_jail_config(log2)
        },
    );

    let config = Fail2BanConfig {
        jails,
        ..Default::default()
    };
    let result = config.validate();
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// Fail2BanConfig::resolve_jail() tests
// ---------------------------------------------------------------------------

#[test]
fn resolve_jail_applies_defaults_for_none_fields() {
    let dir = tempdir().unwrap();
    let log_path = dir.path().join("auth.log");
    fs::write(&log_path, "").unwrap();

    // Jail has all optional fields as None.
    let jail = sample_jail_config(log_path.clone());
    let config = make_config_with_jail(log_path, Some(jail));

    let resolved = config.resolve_jail("sshd").unwrap();
    assert_eq!(resolved.name, "sshd");
    assert!(resolved.enabled);
    assert_eq!(resolved.find_time, 600);
    assert_eq!(resolved.ban_time, 3600);
    assert_eq!(resolved.max_retry, 5);
    assert_eq!(resolved.ban_action, "ban");
    assert_eq!(resolved.unban_action, "unban");
    assert_eq!(resolved.ignore_ips, vec!["127.0.0.1", "::1"]);
}

#[test]
fn resolve_jail_uses_overrides_when_present() {
    let dir = tempdir().unwrap();
    let log_path = dir.path().join("auth.log");
    fs::write(&log_path, "").unwrap();

    let jail = JailConfig {
        enabled: false,
        find_time: Some(60),
        ban_time: Some(120),
        max_retry: Some(10),
        ban_action: Some("custom_ban".into()),
        unban_action: Some("custom_unban".into()),
        ..sample_jail_config(log_path.clone())
    };
    let config = make_config_with_jail(log_path, Some(jail));

    let resolved = config.resolve_jail("sshd").unwrap();
    assert!(!resolved.enabled);
    assert_eq!(resolved.find_time, 60);
    assert_eq!(resolved.ban_time, 120);
    assert_eq!(resolved.max_retry, 10);
    assert_eq!(resolved.ban_action, "custom_ban");
    assert_eq!(resolved.unban_action, "custom_unban");
}

#[test]
fn resolve_jail_returns_error_for_missing_jail() {
    let config = Fail2BanConfig::default();
    let result = config.resolve_jail("nonexistent");
    assert!(result.is_err());
    let msg = format!("{}", result.unwrap_err());
    assert!(msg.contains("nonexistent"), "unexpected error: {msg}");
}

#[test]
fn resolve_jail_preserves_log_path_and_pattern() {
    let dir = tempdir().unwrap();
    let log_path = dir.path().join("custom.log");
    fs::write(&log_path, "").unwrap();

    let jail = JailConfig {
        log_path: log_path.clone(),
        pattern: r#"Invalid user .* from <HOST>"#.into(),
        ..sample_jail_config(log_path)
    };
    let config = make_config_with_jail(dir.path().join("custom.log"), Some(jail));

    let resolved = config.resolve_jail("sshd").unwrap();
    assert_eq!(resolved.log_path, std::path::PathBuf::from(dir.path().join("custom.log")));
    assert_eq!(resolved.pattern, r#"Invalid user .* from <HOST>"#);
}

// ---------------------------------------------------------------------------
// Fail2BanConfig::enabled_jails() tests
// ---------------------------------------------------------------------------

#[test]
fn enabled_jails_returns_only_enabled_jails() {
    let dir = tempdir().unwrap();
    let log_a = dir.path().join("a.log");
    let log_b = dir.path().join("b.log");
    fs::write(&log_a, "").unwrap();
    fs::write(&log_b, "").unwrap();

    let mut jails = HashMap::new();
    jails.insert(
        "active".to_string(),
        JailConfig {
            enabled: true,
            ..sample_jail_config(log_a)
        },
    );
    jails.insert(
        "disabled".to_string(),
        JailConfig {
            enabled: false,
            ..sample_jail_config(log_b)
        },
    );

    let config = Fail2BanConfig {
        jails,
        ..Default::default()
    };

    let mut enabled = config.enabled_jails();
    enabled.sort();
    assert_eq!(enabled, vec!["active"]);
}

#[test]
fn enabled_jails_returns_empty_for_no_jails() {
    let config = Fail2BanConfig::default();
    assert!(config.enabled_jails().is_empty());
}

#[test]
fn enabled_jails_returns_all_when_all_enabled() {
    let dir = tempdir().unwrap();
    let log_a = dir.path().join("a.log");
    let log_b = dir.path().join("b.log");
    fs::write(&log_a, "").unwrap();
    fs::write(&log_b, "").unwrap();

    let mut jails = HashMap::new();
    jails.insert(
        "jail1".to_string(),
        JailConfig {
            enabled: true,
            ..sample_jail_config(log_a)
        },
    );
    jails.insert(
        "jail2".to_string(),
        JailConfig {
            enabled: true,
            ..sample_jail_config(log_b)
        },
    );

    let config = Fail2BanConfig {
        jails,
        ..Default::default()
    };

    let mut enabled = config.enabled_jails();
    enabled.sort();
    assert_eq!(enabled, vec!["jail1", "jail2"]);
}

// ---------------------------------------------------------------------------
// Fail2BanConfig::save() / load() roundtrip tests
// ---------------------------------------------------------------------------

#[test]
fn save_and_load_roundtrip() {
    let dir = tempdir().unwrap();
    let log_path = dir.path().join("auth.log");
    fs::write(&log_path, "log content").unwrap();

    let config_path = dir.path().join("config.json");
    let config = make_config_with_jail(log_path, None);
    config.save(&config_path).unwrap();

    let loaded = Fail2BanConfig::load(&config_path).unwrap();
    assert_eq!(loaded.jails.len(), 1);
    assert!(loaded.jails.contains_key("sshd"));
    assert_eq!(loaded.defaults.find_time, 600);
    assert_eq!(loaded.global.log_level, "info");
}

#[test]
fn save_creates_parent_directories() {
    let dir = tempdir().unwrap();
    let nested_path = dir.path().join("a").join("b").join("config.json");
    let config = Fail2BanConfig::default();
    config.save(&nested_path).unwrap();
    assert!(nested_path.exists());
}

#[test]
fn load_returns_error_for_missing_file() {
    let dir = tempdir().unwrap();
    let missing = dir.path().join("missing.json");
    let result = Fail2BanConfig::load(&missing);
    assert!(result.is_err());
    let msg = format!("{}", result.unwrap_err());
    assert!(msg.contains("Config file not found"), "unexpected error: {msg}");
}

#[test]
fn load_returns_error_for_invalid_json() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("bad.json");
    fs::write(&path, "{not valid json!!!").unwrap();
    let result = Fail2BanConfig::load(&path);
    assert!(result.is_err());
}

#[test]
fn load_validates_after_deserialization() {
    let dir = tempdir().unwrap();
    let log_path = dir.path().join("auth.log");
    // Deliberately do NOT create the log file so validation fails.

    let json = serde_json::json!({
        "jails": {
            "sshd": {
                "log_path": log_path.to_str().unwrap(),
                "pattern": "Failed password"
            }
        }
    });
    let config_path = dir.path().join("config.json");
    fs::write(&config_path, json.to_string()).unwrap();

    let result = Fail2BanConfig::load(&config_path);
    assert!(result.is_err());
    let msg = format!("{}", result.unwrap_err());
    assert!(msg.contains("log file does not exist"), "unexpected error: {msg}");
}

#[test]
fn save_produces_valid_json() {
    let dir = tempdir().unwrap();
    let config_path = dir.path().join("config.json");
    let config = Fail2BanConfig::default();
    config.save(&config_path).unwrap();

    let content = fs::read_to_string(&config_path).unwrap();
    // Should be parseable JSON.
    let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
    assert!(parsed.is_object());
}

// ---------------------------------------------------------------------------
// Fail2BanConfig::create_default() tests
// ---------------------------------------------------------------------------

#[test]
fn create_default_writes_new_file() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("config.json");
    assert!(!path.exists());

    let config = Fail2BanConfig::create_default(&path).unwrap();
    assert!(path.exists());
    assert_eq!(config.defaults.find_time, 600);
    assert!(config.jails.is_empty());
}

#[test]
fn create_default_loads_existing_file() {
    let dir = tempdir().unwrap();
    let log_path = dir.path().join("auth.log");
    fs::write(&log_path, "").unwrap();

    let path = dir.path().join("config.json");
    let original = make_config_with_jail(log_path, None);
    original.save(&path).unwrap();

    let loaded = Fail2BanConfig::create_default(&path).unwrap();
    assert_eq!(loaded.jails.len(), 1);
    assert!(loaded.jails.contains_key("sshd"));
}

// ---------------------------------------------------------------------------
// ResolvedJail tests
// ---------------------------------------------------------------------------

#[test]
fn resolved_jail_clones_correctly() {
    let dir = tempdir().unwrap();
    let log_path = dir.path().join("auth.log");
    fs::write(&log_path, "").unwrap();

    let config = make_config_with_jail(log_path, None);
    let resolved = config.resolve_jail("sshd").unwrap();
    let cloned = resolved.clone();

    assert_eq!(resolved.name, cloned.name);
    assert_eq!(resolved.enabled, cloned.enabled);
    assert_eq!(resolved.find_time, cloned.find_time);
    assert_eq!(resolved.ban_time, cloned.ban_time);
    assert_eq!(resolved.max_retry, cloned.max_retry);
    assert_eq!(resolved.ban_action, cloned.ban_action);
    assert_eq!(resolved.unban_action, cloned.unban_action);
    assert_eq!(resolved.ignore_ips, cloned.ignore_ips);
}

// ---------------------------------------------------------------------------
// Edge case: partial overrides leave other defaults intact
// ---------------------------------------------------------------------------

#[test]
fn resolve_jail_partial_override_only_changes_specified_fields() {
    let dir = tempdir().unwrap();
    let log_path = dir.path().join("auth.log");
    fs::write(&log_path, "").unwrap();

    // Only override find_time; everything else should come from defaults.
    let jail = JailConfig {
        find_time: Some(999),
        ..sample_jail_config(log_path.clone())
    };
    let config = make_config_with_jail(log_path, Some(jail));

    let resolved = config.resolve_jail("sshd").unwrap();
    assert_eq!(resolved.find_time, 999); // overridden
    assert_eq!(resolved.ban_time, 3600); // default
    assert_eq!(resolved.max_retry, 5); // default
    assert_eq!(resolved.ban_action, "ban"); // default
    assert_eq!(resolved.unban_action, "unban"); // default
}

// ---------------------------------------------------------------------------
// Multiple jails coexistence
// ---------------------------------------------------------------------------

#[test]
fn multiple_jails_resolve_independently() {
    let dir = tempdir().unwrap();
    let log_a = dir.path().join("sshd.log");
    let log_b = dir.path().join("nginx.log");
    fs::write(&log_a, "").unwrap();
    fs::write(&log_b, "").unwrap();

    let mut jails = HashMap::new();
    jails.insert(
        "sshd".to_string(),
        JailConfig {
            find_time: Some(300),
            max_retry: Some(3),
            ..sample_jail_config(log_a)
        },
    );
    jails.insert(
        "nginx".to_string(),
        JailConfig {
            find_time: Some(60),
            max_retry: Some(10),
            ban_action: Some("nginx_block".into()),
            ..sample_jail_config(log_b)
        },
    );

    let config = Fail2BanConfig {
        jails,
        ..Default::default()
    };

    let sshd = config.resolve_jail("sshd").unwrap();
    let nginx = config.resolve_jail("nginx").unwrap();

    assert_eq!(sshd.find_time, 300);
    assert_eq!(sshd.max_retry, 3);
    assert_eq!(sshd.ban_action, "ban"); // default

    assert_eq!(nginx.find_time, 60);
    assert_eq!(nginx.max_retry, 10);
    assert_eq!(nginx.ban_action, "nginx_block"); // override
}

// ---------------------------------------------------------------------------
// Edge case: ban_time of 0 is rejected (would create instantly-expiring bans)
// ---------------------------------------------------------------------------

#[test]
fn validate_rejects_zero_ban_time() {
    let dir = tempdir().unwrap();
    let log_path = dir.path().join("auth.log");
    fs::write(&log_path, "some log content").unwrap();

    let jail = JailConfig {
        ban_time: Some(0),
        ..sample_jail_config(log_path)
    };
    let config = make_config_with_jail(dir.path().join("auth.log"), Some(jail));
    let result = config.validate();
    assert!(result.is_err());
    let msg = format!("{}", result.unwrap_err());
    assert!(msg.contains("ban_time must be > 0"), "unexpected error: {msg}");
}

// ---------------------------------------------------------------------------
// Edge case: create_default on an existing file with corrupt JSON
// ---------------------------------------------------------------------------

#[test]
fn create_default_with_corrupt_existing_file() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("config.json");
    fs::write(&path, "{{{{this is not valid json").unwrap();

    let result = Fail2BanConfig::create_default(&path);
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// Edge case: load with wrong field types in JSON
// ---------------------------------------------------------------------------

#[test]
fn load_with_malformed_field_types() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("config.json");
    // find_time is a string instead of a number.
    let json = r#"{
        "defaults": {
            "find_time": "not_a_number",
            "ban_time": 3600,
            "max_retry": 5
        }
    }"#;
    fs::write(&path, json).unwrap();

    let result = Fail2BanConfig::load(&path);
    assert!(result.is_err());
}

// ===========================================================================
// Additional edge-case tests
// ===========================================================================

#[test]
fn validate_rejects_invalid_regex_pattern() {
    let dir = tempdir().unwrap();
    let log_path = dir.path().join("auth.log");
    fs::write(&log_path, "some content").unwrap();

    let jail = JailConfig {
        pattern: "(((invalid".into(),
        ..sample_jail_config(log_path)
    };
    let config = make_config_with_jail(dir.path().join("auth.log"), Some(jail));
    let result = config.validate();
    assert!(result.is_err());
    let msg = format!("{}", result.unwrap_err());
    assert!(msg.contains("invalid regex"), "unexpected error: {msg}");
}

#[test]
fn validate_rejects_zero_defaults_find_time() {
    let dir = tempdir().unwrap();
    let log_path = dir.path().join("auth.log");
    fs::write(&log_path, "some content").unwrap();

    let config = Fail2BanConfig {
        defaults: DefaultConfig {
            find_time: 0,
            ..DefaultConfig::default()
        },
        ..make_config_with_jail(log_path, None)
    };
    let result = config.validate();
    assert!(result.is_err());
    let msg = format!("{}", result.unwrap_err());
    assert!(msg.contains("find_time"), "unexpected error: {msg}");
}

#[test]
fn validate_rejects_zero_defaults_max_retry() {
    let dir = tempdir().unwrap();
    let log_path = dir.path().join("auth.log");
    fs::write(&log_path, "some content").unwrap();

    let config = Fail2BanConfig {
        defaults: DefaultConfig {
            max_retry: 0,
            ..DefaultConfig::default()
        },
        ..make_config_with_jail(log_path, None)
    };
    let result = config.validate();
    assert!(result.is_err());
    let msg = format!("{}", result.unwrap_err());
    assert!(msg.contains("max_retry"), "unexpected error: {msg}");
}

#[test]
fn validate_rejects_zero_defaults_ban_time() {
    let dir = tempdir().unwrap();
    let log_path = dir.path().join("auth.log");
    fs::write(&log_path, "some content").unwrap();

    let config = Fail2BanConfig {
        defaults: DefaultConfig {
            ban_time: 0,
            ..DefaultConfig::default()
        },
        ..make_config_with_jail(log_path, None)
    };
    let result = config.validate();
    assert!(result.is_err());
    let msg = format!("{}", result.unwrap_err());
    assert!(msg.contains("ban_time"), "unexpected error: {msg}");
}

#[test]
fn resolve_jail_with_all_overrides() {
    let dir = tempdir().unwrap();
    let log_path = dir.path().join("auth.log");
    fs::write(&log_path, "").unwrap();

    let jail = JailConfig {
        enabled: false,
        find_time: Some(120),
        ban_time: Some(7200),
        max_retry: Some(20),
        ban_action: Some("my_ban".into()),
        unban_action: Some("my_unban".into()),
        ignore_ips: vec!["10.0.0.0/8".into(), "::1".into()],
        ..sample_jail_config(log_path.clone())
    };
    let config = make_config_with_jail(log_path, Some(jail));

    let resolved = config.resolve_jail("sshd").unwrap();
    assert!(!resolved.enabled);
    assert_eq!(resolved.find_time, 120);
    assert_eq!(resolved.ban_time, 7200);
    assert_eq!(resolved.max_retry, 20);
    assert_eq!(resolved.ban_action, "my_ban");
    assert_eq!(resolved.unban_action, "my_unban");
    assert_eq!(resolved.ignore_ips, vec!["10.0.0.0/8", "::1"]);
}

#[test]
fn enabled_jails_returns_empty_when_all_disabled() {
    let dir = tempdir().unwrap();
    let mut jails = HashMap::new();
    for name in &["jail1", "jail2", "jail3"] {
        let log_path = dir.path().join(format!("{name}.log"));
        fs::write(&log_path, "").unwrap();
        jails.insert(
            name.to_string(),
            JailConfig {
                enabled: false,
                ..sample_jail_config(log_path)
            },
        );
    }

    let config = Fail2BanConfig {
        jails,
        ..Default::default()
    };
    assert!(config.enabled_jails().is_empty());
}

#[test]
fn save_load_preserves_ignore_ips() {
    let dir = tempdir().unwrap();
    let log_path = dir.path().join("auth.log");
    fs::write(&log_path, "log content").unwrap();

    let jail = JailConfig {
        ignore_ips: vec!["10.0.0.0/8".into(), "::1".into()],
        ..sample_jail_config(log_path)
    };
    let config = make_config_with_jail(dir.path().join("auth.log"), Some(jail));
    let config_path = dir.path().join("config.json");
    config.save(&config_path).unwrap();

    let loaded = Fail2BanConfig::load(&config_path).unwrap();
    let resolved = loaded.resolve_jail("sshd").unwrap();
    assert_eq!(resolved.ignore_ips, vec!["10.0.0.0/8", "::1"]);
}

#[test]
fn config_with_extra_unknown_fields_is_ignored() {
    let dir = tempdir().unwrap();
    let config_path = dir.path().join("config.json");
    // Serde ignores unknown fields by default (no deny_unknown_fields attribute).
    let json = r#"{"unknown_field": "value", "another_extra": 42}"#;
    fs::write(&config_path, json).unwrap();

    let result = Fail2BanConfig::load(&config_path);
    assert!(result.is_ok(), "serde should ignore unknown fields");
    let config = result.unwrap();
    assert!(config.jails.is_empty());
}
