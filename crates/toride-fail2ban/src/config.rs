//! Configuration types and parsing for fail2ban.

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::types::PlatformCommands;

/// Top-level fail2ban configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Fail2BanConfig {
    /// Default values applied to all jails unless overridden.
    #[serde(default)]
    pub defaults: DefaultConfig,
    /// Named jail configurations.
    #[serde(default)]
    pub jails: HashMap<String, JailConfig>,
    /// Action templates that can be referenced by jails.
    #[serde(default)]
    pub actions: HashMap<String, ActionConfig>,
    /// Global settings.
    #[serde(default)]
    pub global: GlobalConfig,
}

/// Default values for jails.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefaultConfig {
    /// Default time window for counting failures (seconds).
    #[serde(default = "default_find_time")]
    pub find_time: u64,
    /// Default ban duration (seconds).
    #[serde(default = "default_ban_time")]
    pub ban_time: u64,
    /// Default maximum failures before ban.
    #[serde(default = "default_max_retry")]
    pub max_retry: u32,
    /// Default action to take on ban.
    #[serde(default = "default_ban_action")]
    pub ban_action: String,
    /// Default action to take on unban.
    #[serde(default = "default_unban_action")]
    pub unban_action: String,
}

impl Default for DefaultConfig {
    fn default() -> Self {
        Self {
            find_time: default_find_time(),
            ban_time: default_ban_time(),
            max_retry: default_max_retry(),
            ban_action: default_ban_action(),
            unban_action: default_unban_action(),
        }
    }
}

const fn default_find_time() -> u64 {
    600
}
const fn default_ban_time() -> u64 {
    3600
}
const fn default_max_retry() -> u32 {
    5
}
fn default_ban_action() -> String {
    "ban".into()
}
fn default_unban_action() -> String {
    "unban".into()
}

/// Per-jail configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JailConfig {
    /// Whether this jail is enabled.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Path to the log file to monitor.
    pub log_path: std::path::PathBuf,
    /// Regex pattern to match against log lines.
    pub pattern: String,
    /// Time window for counting failures (seconds). Overrides default.
    pub find_time: Option<u64>,
    /// Ban duration (seconds). Overrides default.
    pub ban_time: Option<u64>,
    /// Max failures before ban. Overrides default.
    pub max_retry: Option<u32>,
    /// Action name to execute on ban. Overrides default.
    pub ban_action: Option<String>,
    /// Action name to execute on unban. Overrides default.
    pub unban_action: Option<String>,
    /// IPs that should never be banned (CIDR notation).
    #[serde(default)]
    pub ignore_ips: Vec<String>,
}

const fn default_true() -> bool {
    true
}

/// Action template configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionConfig {
    /// Commands to execute when the action fires.
    pub commands: PlatformCommands,
    /// Optional validation commands.
    #[serde(default, alias = "validate")]
    pub validation_commands: Vec<String>,
}

/// Global daemon settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalConfig {
    /// How often to scan log files (seconds).
    #[serde(default = "default_scan_interval")]
    pub scan_interval: u64,
    /// Log level for the daemon.
    #[serde(default = "default_log_level")]
    pub log_level: String,
    /// PID file path override.
    pub pid_file: Option<std::path::PathBuf>,
    /// Maximum number of bans to keep in history.
    #[serde(default = "default_max_history")]
    pub max_history: usize,
}

impl Default for GlobalConfig {
    fn default() -> Self {
        Self {
            scan_interval: default_scan_interval(),
            log_level: default_log_level(),
            pid_file: None,
            max_history: default_max_history(),
        }
    }
}

const fn default_scan_interval() -> u64 {
    10
}
fn default_log_level() -> String {
    "info".into()
}
const fn default_max_history() -> usize {
    1000
}

impl Fail2BanConfig {
    /// Load configuration from a JSON file.
    ///
    /// # Errors
    ///
    /// Returns `ConfigNotFound` if the file does not exist, `Io` on read failure,
    /// or `InvalidConfig` on parse/validation failure.
    pub fn load(path: &Path) -> crate::Result<Self> {
        let content = fs::read_to_string(path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                crate::Error::ConfigNotFound(path.display().to_string())
            } else {
                crate::Error::Io(e)
            }
        })?;
        let config: Self = serde_json::from_str(&content).map_err(|e| {
            crate::Error::InvalidConfig(format!("Failed to parse '{}': {e}", path.display()))
        })?;
        config.validate()?;
        Ok(config)
    }

    /// Save configuration to a JSON file using atomic write.
    pub fn save(&self, path: &Path) -> crate::Result<()> {
        let content = serde_json::to_string_pretty(self)
            .map_err(|e| crate::Error::InvalidConfig(format!("Failed to serialize config: {e}")))?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let tmp_path = path.with_extension(format!("json.tmp.{}", std::process::id()));
        fs::write(&tmp_path, &content)?;
        let file = fs::File::open(&tmp_path)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&tmp_path, path).map_err(|e| {
            let _ = fs::remove_file(&tmp_path);
            crate::Error::Io(e)
        })?;
        Ok(())
    }

    /// Validate configuration values.
    ///
    /// # Errors
    ///
    /// Returns `InvalidConfig` on zero `find_time`, zero `max_retry`, zero `ban_time`,
    /// invalid regex pattern, missing log file, invalid action references,
    /// invalid log level, zero scan interval, or values exceeding upper bounds.
    #[allow(
        clippy::too_many_lines,
        reason = "validation covers many distinct checks"
    )]
    pub fn validate(&self) -> crate::Result<()> {
        // Validate global settings.
        if self.global.scan_interval == 0 {
            return Err(crate::Error::InvalidConfig(
                "global: scan_interval must be greater than 0".to_string(),
            ));
        }
        let valid_levels = ["trace", "debug", "info", "warn", "error"];
        if !valid_levels.contains(&self.global.log_level.as_str()) {
            return Err(crate::Error::InvalidConfig(format!(
                "global: log_level '{}' is not valid (expected one of: {})",
                self.global.log_level,
                valid_levels.join(", ")
            )));
        }

        // Validate global defaults.
        if self.defaults.find_time == 0 {
            return Err(crate::Error::InvalidConfig(
                "defaults: find_time must be greater than 0".to_string(),
            ));
        }
        if self.defaults.max_retry == 0 {
            return Err(crate::Error::InvalidConfig(
                "defaults: max_retry must be greater than 0".to_string(),
            ));
        }
        if self.defaults.ban_time == 0 {
            return Err(crate::Error::InvalidConfig(
                "defaults: ban_time must be greater than 0".to_string(),
            ));
        }
        // Upper bounds: find_time <= 1 day, ban_time <= 1 year, max_retry <= 10000.
        if self.defaults.find_time > 86_400 {
            return Err(crate::Error::InvalidConfig(
                "defaults: find_time must not exceed 86400 (1 day)".to_string(),
            ));
        }
        if self.defaults.ban_time > 31_536_000 {
            return Err(crate::Error::InvalidConfig(
                "defaults: ban_time must not exceed 31536000 (1 year)".to_string(),
            ));
        }
        if self.defaults.max_retry > 10_000 {
            return Err(crate::Error::InvalidConfig(
                "defaults: max_retry must not exceed 10000".to_string(),
            ));
        }

        for (name, jail) in &self.jails {
            if jail.find_time == Some(0) {
                return Err(crate::Error::InvalidConfig(format!(
                    "Jail '{name}': find_time must be > 0"
                )));
            }
            if jail.max_retry == Some(0) {
                return Err(crate::Error::InvalidConfig(format!(
                    "Jail '{name}': max_retry must be > 0"
                )));
            }
            if jail.ban_time == Some(0) {
                return Err(crate::Error::InvalidConfig(format!(
                    "Jail '{name}': ban_time must be > 0"
                )));
            }
            if let Some(ft) = jail.find_time
                && ft > 86_400
            {
                return Err(crate::Error::InvalidConfig(format!(
                    "Jail '{name}': find_time must not exceed 86400 (1 day)"
                )));
            }
            if let Some(bt) = jail.ban_time
                && bt > 31_536_000
            {
                return Err(crate::Error::InvalidConfig(format!(
                    "Jail '{name}': ban_time must not exceed 31536000 (1 year)"
                )));
            }
            if let Some(mr) = jail.max_retry
                && mr > 10_000
            {
                return Err(crate::Error::InvalidConfig(format!(
                    "Jail '{name}': max_retry must not exceed 10000"
                )));
            }
            if !jail.log_path.exists() {
                return Err(crate::Error::InvalidConfig(format!(
                    "Jail '{name}': log file does not exist: {}",
                    jail.log_path.display()
                )));
            }
            // Validate regex pattern.
            if let Err(e) = regex::Regex::new(&jail.pattern) {
                return Err(crate::Error::InvalidConfig(format!(
                    "Jail '{name}': invalid regex pattern: {e}"
                )));
            }
            // Validate action references.
            if let Some(ref action_name) = jail.ban_action
                && action_name != "ban"
                && !self.actions.contains_key(action_name)
            {
                return Err(crate::Error::InvalidConfig(format!(
                    "Jail '{name}': ban_action '{action_name}' not found in actions"
                )));
            }
            if let Some(ref action_name) = jail.unban_action
                && action_name != "unban"
                && !self.actions.contains_key(action_name)
            {
                return Err(crate::Error::InvalidConfig(format!(
                    "Jail '{name}': unban_action '{action_name}' not found in actions"
                )));
            }
        }
        Ok(())
    }

    /// Get resolved jail config with defaults applied.
    ///
    /// # Errors
    ///
    /// Returns `JailNotFound` if the jail name is not in the configuration.
    pub fn resolve_jail(&self, name: &str) -> crate::Result<ResolvedJail> {
        let jail = self
            .jails
            .get(name)
            .ok_or_else(|| crate::Error::JailNotFound(name.to_string()))?;

        Ok(ResolvedJail {
            name: name.to_string(),
            enabled: jail.enabled,
            log_path: jail.log_path.clone(),
            pattern: jail.pattern.clone(),
            find_time: jail.find_time.unwrap_or(self.defaults.find_time),
            ban_time: jail.ban_time.unwrap_or(self.defaults.ban_time),
            max_retry: jail.max_retry.unwrap_or(self.defaults.max_retry),
            ban_action: jail
                .ban_action
                .as_deref()
                .unwrap_or(&self.defaults.ban_action)
                .to_string(),
            unban_action: jail
                .unban_action
                .as_deref()
                .unwrap_or(&self.defaults.unban_action)
                .to_string(),
            ignore_ips: jail.ignore_ips.clone(),
        })
    }

    /// Get all enabled jail names.
    #[must_use]
    pub fn enabled_jails(&self) -> Vec<&str> {
        self.jails
            .iter()
            .filter(|(_, j)| j.enabled)
            .map(|(name, _)| name.as_str())
            .collect()
    }

    /// Create a minimal default config file if it doesn't exist.
    pub fn create_default(path: &Path) -> crate::Result<Self> {
        if path.exists() {
            return Self::load(path);
        }
        let config = Self::default();
        config.save(path)?;
        Ok(config)
    }
}

/// Fully resolved jail configuration with defaults applied.
#[derive(Debug, Clone)]
pub struct ResolvedJail {
    /// Jail name.
    pub name: String,
    /// Whether this jail is enabled.
    pub enabled: bool,
    /// Path to the log file to monitor.
    pub log_path: std::path::PathBuf,
    /// Regex pattern to match against log lines.
    pub pattern: String,
    /// Time window for counting failures (seconds).
    pub find_time: u64,
    /// Ban duration (seconds).
    pub ban_time: u64,
    /// Max failures before ban.
    pub max_retry: u32,
    /// Action name to execute on ban.
    pub ban_action: String,
    /// Action name to execute on unban.
    pub unban_action: String,
    /// IPs that should never be banned.
    pub ignore_ips: Vec<String>,
}

#[cfg(test)]
#[path = "config.test.rs"]
mod tests;
