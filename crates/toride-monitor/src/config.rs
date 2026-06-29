//! Configuration management for toride-monitor.
//!
//! Provides [`MonitorConfig`] for loading, validating, and saving monitoring
//! specifications to disk. Uses TOML-based config files.

use std::path::Path;

use crate::spec::MonitorSpec;
use crate::validate::{validate_logging_rule, validate_threshold};
use crate::{Error, Result};

/// Configuration file manager for toride-monitor.
///
/// Handles loading and saving [`MonitorSpec`] to a TOML config file,
/// with validation on both load and save.
pub struct MonitorConfig {
    /// Path to the config file.
    path: std::path::PathBuf,
}

impl MonitorConfig {
    /// Create a new config manager pointing at the given file path.
    #[must_use]
    pub fn new(path: impl Into<std::path::PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// Create a config manager at the default XDG config location.
    ///
    /// The default path is `$XDG_CONFIG_HOME/toride/monitor.toml`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] if the XDG config directory cannot be resolved.
    pub fn default_config() -> Result<Self> {
        let config_dir = dirs::config_dir()
            .ok_or_else(|| Error::Other("cannot determine config directory".into()))?;
        Ok(Self::new(config_dir.join("toride").join("monitor.toml")))
    }

    /// Load and validate a [`MonitorSpec`] from the config file.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The file cannot be read.
    /// - The file contains invalid TOML.
    /// - Validation of rules or thresholds fails.
    pub fn load(&self) -> Result<MonitorSpec> {
        let content = std::fs::read_to_string(&self.path)?;
        let spec = parse_config(&content)?;
        validate_spec(&spec)?;
        Ok(spec)
    }

    /// Save a [`MonitorSpec`] to the config file.
    ///
    /// Validates the spec before writing.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Validation fails.
    /// - The file cannot be written.
    pub fn save(&self, spec: &MonitorSpec) -> Result<()> {
        validate_spec(spec)?;
        let content = render_config(spec)?;
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&self.path, content)?;
        Ok(())
    }

    /// Returns the config file path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Check if the config file exists on disk.
    #[must_use]
    pub fn exists(&self) -> bool {
        self.path.exists()
    }
}

/// Parse a TOML config string into a [`MonitorSpec`].
///
/// Deserializes the TOML directly into [`MonitorSpec`], whose fields carry
/// serde attributes (`#[serde(default ...)]`) so a partial config (e.g. one
/// that only overrides thresholds) still loads with sensible defaults.
///
/// # Errors
///
/// Returns [`Error::Other`] with the TOML parse error message if the content
/// is not valid TOML or does not match the expected schema.
pub fn parse_config(content: &str) -> Result<MonitorSpec> {
    toml::from_str(content).map_err(|e| Error::Other(format!("invalid monitor config: {e}")))
}

/// Render a [`MonitorSpec`] into a TOML config string.
///
/// Serializes the full spec — thresholds, logging rules, and alert targets —
/// so that saving and reloading round-trips losslessly.
///
/// # Errors
///
/// Returns [`Error::Other`] if serialization fails (e.g. a field cannot be
/// represented in TOML).
pub fn render_config(spec: &MonitorSpec) -> Result<String> {
    // Emit a leading header comment, then the serialised body. We prepend a
    // standalone comment line because toml::to_string starts directly with the
    // first key.
    let body = toml::to_string_pretty(spec)
        .map_err(|e| Error::Other(format!("failed to serialize config: {e}")))?;
    Ok(format!("# toride-monitor configuration\n\n{body}"))
}

/// Validate a complete [`MonitorSpec`].
fn validate_spec(spec: &MonitorSpec) -> Result<()> {
    validate_threshold(&spec.thresholds)?;
    for rule in &spec.logging_rules {
        validate_logging_rule(rule)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spec::{AlertTarget, LoggingRule};
    use std::time::Duration;

    fn sample_spec() -> MonitorSpec {
        MonitorSpec {
            enabled: true,
            logging_rules: vec![LoggingRule {
                name: "out-tcp".into(),
                destination: "0.0.0.0/0".into(),
                dest_port: Some(443),
                protocol: "tcp".into(),
                log_prefix: "toride-mon-out".into(),
                log_level: "info".into(),
                limit_burst: 10,
                limit_rate: "10/minute".into(),
            }],
            thresholds: crate::spec::AnomalyThreshold {
                max_connections: 42,
                max_unique_destinations: 7,
                max_bytes: 1024,
                max_packets_per_second: 5,
                window: Duration::from_secs(99),
            },
            alert_targets: vec![
                AlertTarget::Journald {
                    priority: "warning".into(),
                },
                AlertTarget::File {
                    path: "/var/log/toride.log".into(),
                },
            ],
        }
    }

    #[test]
    fn round_trip_full_spec_through_toml() {
        let spec = sample_spec();
        let rendered = render_config(&spec).unwrap();
        // Must contain alert targets (the old hand-rolled renderer omitted them).
        assert!(rendered.contains("kind = \"journald\""));
        assert!(rendered.contains("kind = \"file\""));
        assert!(rendered.contains("/var/log/toride.log"));

        let loaded = parse_config(&rendered).unwrap();
        assert_eq!(loaded.enabled, spec.enabled);
        assert_eq!(loaded.logging_rules.len(), 1);
        assert_eq!(loaded.logging_rules[0].dest_port, Some(443));
        assert_eq!(loaded.thresholds.max_connections, 42);
        assert_eq!(loaded.thresholds.window, Duration::from_secs(99));
        assert_eq!(loaded.alert_targets.len(), 2);
    }

    #[test]
    fn multi_rule_spec_round_trips() {
        // The old renderer emitted a single [[logging_rules]] header followed
        // by concatenated field blocks, producing invalid TOML for >1 rule.
        // The serde-based renderer must emit one header per rule.
        let spec = MonitorSpec {
            logging_rules: vec![
                LoggingRule {
                    name: "r1".into(),
                    destination: "10.0.0.0/8".into(),
                    dest_port: None,
                    protocol: "tcp".into(),
                    log_prefix: "toride-mon-a".into(),
                    log_level: "info".into(),
                    limit_burst: 1,
                    limit_rate: "1/minute".into(),
                },
                LoggingRule {
                    name: "r2".into(),
                    destination: "192.168.0.0/16".into(),
                    dest_port: Some(22),
                    protocol: "tcp".into(),
                    log_prefix: "toride-mon-b".into(),
                    log_level: "notice".into(),
                    limit_burst: 2,
                    limit_rate: "2/minute".into(),
                },
            ],
            ..MonitorSpec::default()
        };
        let rendered = render_config(&spec).unwrap();
        let loaded = parse_config(&rendered).unwrap();
        assert_eq!(loaded.logging_rules.len(), 2);
        assert_eq!(loaded.logging_rules[0].name, "r1");
        assert_eq!(loaded.logging_rules[1].name, "r2");
        assert_eq!(loaded.logging_rules[1].dest_port, Some(22));
    }

    #[test]
    fn partial_config_loads_with_defaults() {
        // A config that only sets thresholds should fill the rest with
        // serde-provided defaults.
        let toml = "\
enabled = false

[thresholds]
max_connections = 1
max_unique_destinations = 1
max_bytes = 1
max_packets_per_second = 1
window = 5
";
        let spec = parse_config(toml).unwrap();
        assert!(!spec.enabled);
        assert_eq!(spec.thresholds.max_connections, 1);
        assert_eq!(spec.thresholds.window, Duration::from_secs(5));
        // logging_rules and alert_targets default to empty.
        assert!(spec.logging_rules.is_empty());
        assert!(spec.alert_targets.is_empty());
    }

    #[test]
    fn invalid_toml_errors() {
        let result = parse_config("enabled = not a bool");
        assert!(result.is_err());
    }

    #[test]
    fn save_and_load_round_trip_on_disk() {
        let dir = std::env::temp_dir().join(format!(
            "toride_monitor_cfg_{}_{}",
            std::process::id(),
            "save"
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("monitor.toml");
        let cfg = MonitorConfig::new(&path);

        let spec = sample_spec();
        cfg.save(&spec).unwrap();
        assert!(path.exists());

        let loaded = cfg.load().unwrap();
        assert_eq!(loaded.thresholds.max_connections, 42);
        assert_eq!(loaded.alert_targets.len(), 2);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_rejects_invalid_threshold() {
        let dir = std::env::temp_dir().join(format!(
            "toride_monitor_cfg_{}_{}",
            std::process::id(),
            "invalid"
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("monitor.toml");
        // max_connections = 0 fails threshold validation.
        std::fs::write(
            &path,
            "[thresholds]\nmax_connections = 0\nmax_unique_destinations = 1\n\
             max_bytes = 1\nmax_packets_per_second = 1\nwindow = 1\n",
        )
        .unwrap();
        let cfg = MonitorConfig::new(&path);
        assert!(cfg.load().is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
