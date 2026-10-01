use super::*;
use std::fs;
use tempfile::TempDir;

#[allow(
    unsafe_code,
    reason = "edition 2024 makes set_var unsafe; tests mutate the env before spawning threads"
)]
fn with_custom_xdg() -> TempDir {
    let tmp = TempDir::new().expect("failed to create temp dir");
    let base = tmp.path();
    unsafe {
        std::env::set_var("XDG_CONFIG_HOME", base.join("config"));
        std::env::set_var("XDG_DATA_HOME", base.join("data"));
    }
    tmp
}

#[test]
fn resolve_returns_ok() {
    let _tmp = with_custom_xdg();
    let paths = Fail2BanPaths::resolve();
    assert!(paths.is_ok(), "resolve() should succeed: {:?}", paths.err());
}

#[test]
fn resolve_all_paths_contain_toride_fail2ban() {
    let _tmp = with_custom_xdg();
    let p = Fail2BanPaths::resolve().unwrap();

    for (name, path) in [
        ("config_dir", &p.config_dir),
        ("config_file", &p.config_file),
        ("data_dir", &p.data_dir),
        ("ban_db", &p.ban_db),
        ("pid_file", &p.pid_file),
        ("log_dir", &p.log_dir),
        ("journal_dir", &p.journal_dir),
    ] {
        let s = path.to_string_lossy();
        assert!(
            s.contains("toride") && s.contains("fail2ban"),
            "{name} path should contain toride/fail2ban: {s}"
        );
    }
}

#[test]
fn resolve_config_file_is_config_json_in_config_dir() {
    let _tmp = with_custom_xdg();
    let p = Fail2BanPaths::resolve().unwrap();

    assert_eq!(p.config_file, p.config_dir.join("config.json"));
}

#[test]
fn resolve_ban_db_is_bans_json_in_data_dir() {
    let _tmp = with_custom_xdg();
    let p = Fail2BanPaths::resolve().unwrap();

    assert_eq!(p.ban_db, p.data_dir.join("bans.json"));
}

#[test]
fn resolve_pid_file_is_fail2ban_pid_in_data_dir() {
    let _tmp = with_custom_xdg();
    let p = Fail2BanPaths::resolve().unwrap();

    assert_eq!(p.pid_file, p.data_dir.join("fail2ban.pid"));
}

#[test]
fn resolve_log_dir_is_logs_in_data_dir() {
    let _tmp = with_custom_xdg();
    let p = Fail2BanPaths::resolve().unwrap();

    assert_eq!(p.log_dir, p.data_dir.join("logs"));
}

#[test]
fn resolve_journal_dir_is_journals_in_data_dir() {
    let _tmp = with_custom_xdg();
    let p = Fail2BanPaths::resolve().unwrap();

    assert_eq!(p.journal_dir, p.data_dir.join("journals"));
}

#[test]
fn resolve_all_paths_are_absolute() {
    let _tmp = with_custom_xdg();
    let p = Fail2BanPaths::resolve().unwrap();

    for (name, path) in [
        ("config_dir", &p.config_dir),
        ("config_file", &p.config_file),
        ("data_dir", &p.data_dir),
        ("ban_db", &p.ban_db),
        ("pid_file", &p.pid_file),
        ("log_dir", &p.log_dir),
        ("journal_dir", &p.journal_dir),
    ] {
        assert!(path.is_absolute(), "{name} should be absolute: {path:?}");
    }
}

#[test]
fn resolve_config_dir_has_three_components() {
    let _tmp = with_custom_xdg();
    let p = Fail2BanPaths::resolve().unwrap();
    let components: Vec<_> = p.config_dir.iter().collect();
    let len = components.len();
    assert!(
        len >= 3,
        "config_dir should have at least 3 components: {components:?}"
    );
    assert_eq!(components[len - 1].to_str().unwrap(), "fail2ban");
    assert_eq!(components[len - 2].to_str().unwrap(), "toride");
}

#[test]
fn resolve_data_dir_has_three_components() {
    let _tmp = with_custom_xdg();
    let p = Fail2BanPaths::resolve().unwrap();
    let components: Vec<_> = p.data_dir.iter().collect();
    let len = components.len();
    assert!(
        len >= 3,
        "data_dir should have at least 3 components: {components:?}"
    );
    assert_eq!(components[len - 1].to_str().unwrap(), "fail2ban");
    assert_eq!(components[len - 2].to_str().unwrap(), "toride");
}

// On macOS `dirs::config_dir()` and `dirs::data_dir()` both return
// ~/Library/Application Support (docs.rs/dirs) — never assert the two differ.

#[test]
fn ensure_directories_creates_all_dirs() {
    let tmp = TempDir::new().unwrap();
    let base = tmp.path();

    let paths = Fail2BanPaths {
        config_dir: base.join("cfg"),
        config_file: base.join("cfg").join("config.json"),
        data_dir: base.join("data"),
        ban_db: base.join("data").join("bans.json"),
        pid_file: base.join("data").join("fail2ban.pid"),
        log_dir: base.join("data").join("logs"),
        journal_dir: base.join("data").join("journals"),
    };

    assert!(!paths.config_dir.exists());
    assert!(!paths.data_dir.exists());
    assert!(!paths.log_dir.exists());
    assert!(!paths.journal_dir.exists());

    paths.ensure_directories().unwrap();

    assert!(paths.config_dir.is_dir());
    assert!(paths.data_dir.is_dir());
    assert!(paths.log_dir.is_dir());
    assert!(paths.journal_dir.is_dir());
}

#[test]
fn ensure_directories_is_idempotent() {
    let tmp = TempDir::new().unwrap();
    let base = tmp.path();

    let paths = Fail2BanPaths {
        config_dir: base.join("cfg"),
        config_file: base.join("cfg").join("config.json"),
        data_dir: base.join("data"),
        ban_db: base.join("data").join("bans.json"),
        pid_file: base.join("data").join("fail2ban.pid"),
        log_dir: base.join("data").join("logs"),
        journal_dir: base.join("data").join("journals"),
    };

    paths.ensure_directories().unwrap();
    paths
        .ensure_directories()
        .expect("ensure_directories should be idempotent");

    assert!(paths.config_dir.is_dir());
    assert!(paths.data_dir.is_dir());
    assert!(paths.log_dir.is_dir());
    assert!(paths.journal_dir.is_dir());
}

#[test]
fn ensure_directories_creates_deeply_nested_paths() {
    let tmp = TempDir::new().unwrap();
    let base = tmp.path();

    let paths = Fail2BanPaths {
        config_dir: base.join("a").join("b").join("c").join("cfg"),
        config_file: base
            .join("a")
            .join("b")
            .join("c")
            .join("cfg")
            .join("config.json"),
        data_dir: base.join("x").join("y").join("z").join("data"),
        ban_db: base
            .join("x")
            .join("y")
            .join("z")
            .join("data")
            .join("bans.json"),
        pid_file: base
            .join("x")
            .join("y")
            .join("z")
            .join("data")
            .join("fail2ban.pid"),
        log_dir: base.join("x").join("y").join("z").join("data").join("logs"),
        journal_dir: base
            .join("x")
            .join("y")
            .join("z")
            .join("data")
            .join("journals"),
    };

    paths.ensure_directories().unwrap();

    assert!(paths.config_dir.is_dir());
    assert!(paths.data_dir.is_dir());
    assert!(paths.log_dir.is_dir());
    assert!(paths.journal_dir.is_dir());
}

#[test]
fn ensure_directories_with_real_resolve() {
    let _tmp = with_custom_xdg();
    let p = Fail2BanPaths::resolve().unwrap();
    p.ensure_directories().unwrap();

    assert!(p.config_dir.is_dir());
    assert!(p.data_dir.is_dir());
    assert!(p.log_dir.is_dir());
    assert!(p.journal_dir.is_dir());

    let _ = fs::remove_dir_all(&p.config_dir);
    let _ = fs::remove_dir_all(&p.data_dir);
}

#[test]
fn ensure_directories_does_not_create_file_paths() {
    let tmp = TempDir::new().unwrap();
    let base = tmp.path();

    let paths = Fail2BanPaths {
        config_dir: base.join("cfg"),
        config_file: base.join("cfg").join("config.json"),
        data_dir: base.join("data"),
        ban_db: base.join("data").join("bans.json"),
        pid_file: base.join("data").join("fail2ban.pid"),
        log_dir: base.join("data").join("logs"),
        journal_dir: base.join("data").join("journals"),
    };

    paths.ensure_directories().unwrap();

    assert!(!paths.config_file.exists());
    assert!(!paths.ban_db.exists());
    assert!(!paths.pid_file.exists());
}

#[test]
fn test_pid_file_with_override_returns_default_when_none() {
    let _tmp = with_custom_xdg();
    let p = Fail2BanPaths::resolve().unwrap();

    let result = p.pid_file_with_override(None);
    assert_eq!(result, p.pid_file);
}

#[test]
fn test_pid_file_with_override_returns_custom_when_some() {
    let _tmp = with_custom_xdg();
    let p = Fail2BanPaths::resolve().unwrap();

    let custom = std::path::Path::new("/tmp/custom-fail2ban.pid");
    let result = p.pid_file_with_override(Some(custom));
    assert_eq!(result, custom.to_path_buf());
    assert_ne!(result, p.pid_file);
}

#[test]
fn test_resolve_config_file_ends_with_json() {
    let _tmp = with_custom_xdg();
    let p = Fail2BanPaths::resolve().unwrap();

    assert!(
        p.config_file.ends_with("config.json"),
        "config_file should end with config.json: {:?}",
        p.config_file
    );
}

#[test]
fn test_resolve_ban_db_ends_with_json() {
    let _tmp = with_custom_xdg();
    let p = Fail2BanPaths::resolve().unwrap();

    assert!(
        p.ban_db.ends_with("bans.json"),
        "ban_db should end with bans.json: {:?}",
        p.ban_db
    );
}

#[test]
fn test_resolve_pid_file_ends_with_pid() {
    let _tmp = with_custom_xdg();
    let p = Fail2BanPaths::resolve().unwrap();

    assert!(
        p.pid_file.ends_with("fail2ban.pid"),
        "pid_file should end with fail2ban.pid: {:?}",
        p.pid_file
    );
}

#[test]
fn test_ensure_directories_on_existing_dirs_does_not_error() {
    let tmp = TempDir::new().unwrap();
    let base = tmp.path();

    let paths = Fail2BanPaths {
        config_dir: base.join("cfg"),
        config_file: base.join("cfg").join("config.json"),
        data_dir: base.join("data"),
        ban_db: base.join("data").join("bans.json"),
        pid_file: base.join("data").join("fail2ban.pid"),
        log_dir: base.join("data").join("logs"),
        journal_dir: base.join("data").join("journals"),
    };

    paths.ensure_directories().unwrap();
    paths.ensure_directories().unwrap();
}

#[test]
fn test_paths_struct_is_cloneable() {
    let _tmp = with_custom_xdg();
    let p = Fail2BanPaths::resolve().unwrap();

    let cloned = p.clone();
    assert_eq!(cloned.config_dir, p.config_dir);
    assert_eq!(cloned.config_file, p.config_file);
    assert_eq!(cloned.data_dir, p.data_dir);
    assert_eq!(cloned.ban_db, p.ban_db);
    assert_eq!(cloned.pid_file, p.pid_file);
    assert_eq!(cloned.log_dir, p.log_dir);
    assert_eq!(cloned.journal_dir, p.journal_dir);
}

#[test]
fn test_paths_struct_is_debug_printable() {
    let _tmp = with_custom_xdg();
    let p = Fail2BanPaths::resolve().unwrap();

    let dbg = format!("{p:?}");
    assert!(
        dbg.contains("config_dir"),
        "Debug output should contain config_dir: {dbg}"
    );
    assert!(
        dbg.contains("config_file"),
        "Debug output should contain config_file: {dbg}"
    );
    assert!(
        dbg.contains("data_dir"),
        "Debug output should contain data_dir: {dbg}"
    );
    assert!(
        dbg.contains("ban_db"),
        "Debug output should contain ban_db: {dbg}"
    );
    assert!(
        dbg.contains("pid_file"),
        "Debug output should contain pid_file: {dbg}"
    );
    assert!(
        dbg.contains("log_dir"),
        "Debug output should contain log_dir: {dbg}"
    );
    assert!(
        dbg.contains("journal_dir"),
        "Debug output should contain journal_dir: {dbg}"
    );
}

#[test]
fn test_resolve_all_paths_use_same_toride_prefix() {
    let _tmp = with_custom_xdg();
    let p = Fail2BanPaths::resolve().unwrap();

    let config_s = p.config_dir.to_string_lossy();
    let data_s = p.data_dir.to_string_lossy();

    assert!(
        config_s.contains("toride/fail2ban"),
        "config_dir should contain toride/fail2ban: {config_s}"
    );
    assert!(
        data_s.contains("toride/fail2ban"),
        "data_dir should contain toride/fail2ban: {data_s}"
    );
}

#[test]
fn test_ensure_directories_creates_journal_dir_nested() {
    let tmp = TempDir::new().unwrap();
    let base = tmp.path();

    let paths = Fail2BanPaths {
        config_dir: base.join("cfg"),
        config_file: base.join("cfg").join("config.json"),
        data_dir: base.join("data"),
        ban_db: base.join("data").join("bans.json"),
        pid_file: base.join("data").join("fail2ban.pid"),
        log_dir: base.join("data").join("logs"),
        journal_dir: base
            .join("data")
            .join("deep")
            .join("nested")
            .join("journals"),
    };

    paths.ensure_directories().unwrap();

    assert!(paths.journal_dir.is_dir());
    assert!(paths.journal_dir.parent().unwrap().is_dir());
}
