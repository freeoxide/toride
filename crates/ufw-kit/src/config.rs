//! UFW config file management (`/etc/default/ufw` and `/etc/ufw/ufw.conf`).
//!
//! Provides safe key-value editing with comment preservation and atomic writes.

use std::fmt::Write;
use std::io::Write as IoWrite;
use std::path::Path;

use tempfile::NamedTempFile;
use toride_fs::with_lock;

use crate::error::{Error, Result};
use crate::spec::{UfwConf, UfwConfig};

/// Acquire an exclusive lock on a lock file derived from `path` and run `f`
/// while the lock is held.
///
/// The lock file uses a `.lock` extension alongside the target file so the
/// actual config file is never corrupted by lock metadata.
fn with_file_lock<T>(path: &Path, f: impl FnOnce() -> Result<T>) -> Result<T> {
    let lock_path = path.with_extension("lock");
    if let Some(parent) = lock_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    with_lock(&lock_path, || {
        f().map_err(|e| toride_fs::Error::Io(std::io::Error::other(e.to_string())))
    })
    .map_err(|e| Error::Io(e.to_string()))
}

/// Parse `/etc/default/ufw` content.
pub fn parse_default_ufw(content: &str) -> UfwConfig {
    let mut config = UfwConfig::default();

    for line in content.lines() {
        let trimmed = line.trim();

        // Skip comments and empty lines
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        if let Some((key, value)) = parse_kv(trimmed) {
            let val = value.trim_matches('"').trim();
            match key {
                "IPV6" => config.ipv6 = Some(val == "yes"),
                "DEFAULT_INPUT_POLICY" => config.default_input_policy = Some(val.to_string()),
                "DEFAULT_OUTPUT_POLICY" => config.default_output_policy = Some(val.to_string()),
                "DEFAULT_FORWARD_POLICY" => config.default_forward_policy = Some(val.to_string()),
                "ENABLED" => config.enabled = Some(val == "yes"),
                "IPT_SYSCTL" => config.ipt_sysctl = Some(val.to_string()),
                "IPT_MODULES" => config.ipt_modules = Some(val.to_string()),
                "MANAGE_BUILTINS" => config.manage_builtins = Some(val == "yes"),
                _ => {}
            }
        }
    }

    config
}

/// Parse `/etc/ufw/ufw.conf` format.
///
/// The ufw.conf file uses a simpler `KEY=VALUE` format with two known keys:
/// `ENABLED` (yes/no) and `LOGLEVEL` (off/low/medium/high/full).
pub fn parse_ufw_conf(content: &str) -> UfwConf {
    let mut conf = UfwConf::default();

    for line in content.lines() {
        let trimmed = line.trim();

        // Skip comments and empty lines
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        if let Some((key, value)) = parse_kv(trimmed) {
            let val = value.trim_matches('"').trim();
            match key {
                "ENABLED" => conf.enabled = Some(val == "yes"),
                "LOGLEVEL" => conf.loglevel = Some(val.to_string()),
                _ => {}
            }
        }
    }

    conf
}

/// Update a key in `/etc/default/ufw` format content.
pub fn update_config_key(content: &str, key: &str, value: &str) -> String {
    let mut found = false;
    let mut result = String::new();

    for line in content.lines() {
        let trimmed = line.trim();

        if let Some((k, _)) = parse_kv(trimmed) {
            if k == key {
                let _ = writeln!(result, "{key}={value}");
                found = true;
                continue;
            }
        }

        result.push_str(line);
        result.push('\n');
    }

    if !found {
        let _ = writeln!(result, "{key}={value}");
    }

    result
}

/// Update a key in `/etc/ufw/ufw.conf` format content.
///
/// Same logic as [`update_config_key`] but scoped to ufw.conf keys.
/// Appends the key at the end if not found.
pub fn update_ufw_conf_key(content: &str, key: &str, value: &str) -> String {
    // The ufw.conf format is the same KEY=VALUE format so we reuse the logic.
    update_config_key(content, key, value)
}

/// Atomically write config content to a file.
///
/// 1. If `backup_dir` is `Some`, creates a backup of the existing file first.
/// 2. Writes content to a temporary file in the same directory.
/// 3. Atomically persists (renames) the temp file to the final path.
///
/// The backup is named after the target file's stem with a `.bak` suffix.
pub fn write_config_file(path: &Path, content: &str, backup_dir: Option<&Path>) -> Result<()> {
    with_file_lock(path, || {
        // Step 1: Create backup if requested and original file exists
        if let Some(backup_dir) = backup_dir {
            if path.exists() {
                std::fs::create_dir_all(backup_dir).map_err(|e| {
                    Error::ConfigWriteFailed(format!(
                        "failed to create backup directory {}: {e}",
                        backup_dir.display()
                    ))
                })?;

                let file_name = path.file_name().unwrap_or_default().to_string_lossy();
                let backup_path = backup_dir.join(format!("{file_name}.bak"));

                std::fs::copy(path, &backup_path).map_err(|e| {
                    Error::ConfigWriteFailed(format!(
                        "failed to backup {} to {}: {e}",
                        path.display(),
                        backup_path.display()
                    ))
                })?;
            }
        }

        // Step 2: Write to temp file in the same parent directory (required for
        // atomic rename on the same filesystem).
        let parent = path.parent().ok_or_else(|| {
            Error::ConfigWriteFailed(format!("path has no parent directory: {}", path.display()))
        })?;

        // Ensure parent directory exists
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|e| {
                Error::ConfigWriteFailed(format!(
                    "failed to create parent directory {}: {e}",
                    parent.display()
                ))
            })?;
        }

        let mut temp_file = NamedTempFile::new_in(parent)
            .map_err(|e| Error::ConfigWriteFailed(format!("failed to create temp file: {e}")))?;

        temp_file
            .write_all(content.as_bytes())
            .map_err(|e| Error::ConfigWriteFailed(format!("failed to write temp file: {e}")))?;

        temp_file
            .flush()
            .map_err(|e| Error::ConfigWriteFailed(format!("failed to flush temp file: {e}")))?;

        // Step 3: Atomically persist to final path
        temp_file.persist(path).map_err(|e| {
            Error::ConfigWriteFailed(format!(
                "failed to persist temp file to {}: {e}",
                path.display()
            ))
        })?;

        Ok(())
    })
}

fn parse_kv(line: &str) -> Option<(&str, &str)> {
    if line.starts_with('#') || line.starts_with(';') {
        return None;
    }

    let eq = line.find('=')?;
    let key = line[..eq].trim();
    let value = line[eq + 1..].trim();

    Some((key, value))
}

#[cfg(test)]
#[path = "config.test.rs"]
mod tests;
