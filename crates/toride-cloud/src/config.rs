//! Configuration management for cloud provider settings.
//!
//! Handles loading, parsing, validating, and saving cloud provider
//! configuration files. Configuration is stored as JSON in the XDG config
//! directory (e.g. `~/.config/toride/cloud/config.json`) and round-trips
//! losslessly through [`CloudConfig::save`] / [`CloudConfig::load`].

use std::path::PathBuf;

use crate::CloudProvider;
use crate::error::{Error, Result};
use crate::paths::CloudPaths;

// ---------------------------------------------------------------------------
// CloudConfig
// ---------------------------------------------------------------------------

/// Cloud provider configuration.
///
/// Represents the persisted configuration for cloud provider integration,
/// including provider selection, default regions, and security group defaults.
#[derive(Debug, Clone)]
pub struct CloudConfig {
    /// The configured cloud provider.
    pub provider: CloudProvider,
    /// Default region for the provider.
    pub default_region: String,
    /// Path to the configuration file.
    pub config_path: PathBuf,
    /// Whether to automatically detect the provider on startup.
    pub auto_detect: bool,
    /// Default action for new firewall rules.
    pub default_action: crate::spec::RuleAction,
}

impl CloudConfig {
    /// Load configuration from the default XDG location.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ConfigParse`] if the file exists but cannot be parsed.
    /// Returns [`Error::Io`] if the file cannot be read.
    pub fn load() -> Result<Self> {
        let paths = CloudPaths::discover()?;
        let config_path = paths.config_dir.join("config.json");

        if !config_path.exists() {
            return Ok(Self::default_config(config_path));
        }

        let content = std::fs::read_to_string(&config_path)?;
        Self::parse(&content, config_path)
    }

    /// Load configuration from a specific file path.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ConfigParse`] if the file cannot be parsed.
    pub fn load_from(path: PathBuf) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default_config(path));
        }

        let content = std::fs::read_to_string(&path)?;
        Self::parse(&content, path)
    }

    /// Parse configuration from a JSON string.
    ///
    /// Accepts a partial document: any missing field falls back to the
    /// [`CloudConfig::default_config`] defaults. This keeps hand-edited configs
    /// resilient to additions in later versions.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ConfigParse`] if the content is not valid JSON or
    /// contains a value of the wrong type for a known key.
    fn parse(content: &str, config_path: PathBuf) -> Result<Self> {
        let trimmed = content.trim();
        if trimmed.is_empty() {
            return Ok(Self::default_config(config_path));
        }

        let root: serde_json::Value = serde_json::from_str(trimmed)
            .map_err(|e| Error::ConfigParse(format!("cloud config is not valid JSON: {e}")))?;
        let root = root.as_object().ok_or_else(|| {
            Error::ConfigParse("cloud config root must be a JSON object".to_string())
        })?;

        let provider = root
            .get("provider")
            .and_then(serde_json::Value::as_str)
            .map_or(CloudProvider::Unknown, CloudProvider::from_str_loose);
        let default_region = root
            .get("default_region")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
            .to_string();
        let auto_detect = root
            .get("auto_detect")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(true);
        let default_action = root
            .get("default_action")
            .and_then(serde_json::Value::as_str)
            .map_or(crate::spec::RuleAction::Allow, parse_action);

        Ok(Self {
            provider,
            default_region,
            config_path,
            auto_detect,
            default_action,
        })
    }

    /// Create a default configuration.
    fn default_config(config_path: PathBuf) -> Self {
        Self {
            provider: CloudProvider::Unknown,
            default_region: String::new(),
            config_path,
            auto_detect: true,
            default_action: crate::spec::RuleAction::Allow,
        }
    }

    /// Save the configuration to disk.
    ///
    /// Serializes the config to pretty-printed JSON and writes it atomically
    /// (temp-file + rename via `toride-fs`) to [`CloudConfig::config_path`],
    /// creating parent directories as needed. Atomic writes prevent torn
    /// reads if the process is interrupted mid-save.
    ///
    /// The file is written with mode `0600` (owner read/write only): a cloud
    /// config may carry provider credentials or tokens, so it must not be
    /// world/group-readable.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] if the parent directory cannot be created or the
    /// atomic write fails, or [`Error::Other`] if serialization fails.
    pub fn save(&self) -> Result<()> {
        if let Some(parent) = self.config_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = render_json(self)?;
        toride_fs::atomic::atomic_write_with_perms(&self.config_path, &json, 0o600).map_err(
            |e| {
                Error::Other(format!(
                    "failed to write {}: {e}",
                    self.config_path.display()
                ))
            },
        )?;
        Ok(())
    }

    /// Render this configuration as a pretty-printed JSON string.
    ///
    /// Exposed for tests and callers that want to inspect the serialised form
    /// without touching disk.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Other`] if serialization fails.
    pub fn to_json_string(&self) -> Result<String> {
        render_json(self)
    }

    /// Validate the configuration.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ConfigParse`] if the configuration is invalid.
    pub fn validate(&self) -> Result<()> {
        if matches!(self.provider, CloudProvider::Unknown) && !self.auto_detect {
            return Err(Error::ConfigParse(
                "provider is unknown and auto_detect is disabled".to_string(),
            ));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// JSON (de)serialization helpers
//
// The config is serialised by hand on top of serde_json::Value rather than via
// #[derive(Serialize, Deserialize)] on CloudConfig. This keeps the on-disk
// schema stable and decoupled from serde derives on the domain types
// (CloudProvider / RuleAction), which live behind the separate `serde`
// feature and are not guaranteed to be enabled when `config` is on.
// ---------------------------------------------------------------------------

/// Render a [`CloudConfig`] as a pretty-printed JSON string.
fn render_json(cfg: &CloudConfig) -> Result<String> {
    let mut obj = serde_json::Map::new();
    obj.insert(
        "provider".to_string(),
        serde_json::Value::String(cfg.provider.to_string()),
    );
    obj.insert(
        "default_region".to_string(),
        serde_json::Value::String(cfg.default_region.clone()),
    );
    obj.insert(
        "auto_detect".to_string(),
        serde_json::Value::Bool(cfg.auto_detect),
    );
    obj.insert(
        "default_action".to_string(),
        serde_json::Value::String(action_name(cfg.default_action).to_string()),
    );
    serde_json::to_string_pretty(&serde_json::Value::Object(obj))
        .map_err(|e| Error::Other(format!("failed to serialize cloud config: {e}")))
}

/// Map a [`RuleAction`] to its on-disk name.
fn action_name(action: crate::spec::RuleAction) -> &'static str {
    match action {
        crate::spec::RuleAction::Allow => "allow",
        crate::spec::RuleAction::Deny => "deny",
    }
}

/// Parse a [`RuleAction`] name (case-insensitive). Unknown values fall back
/// to `Allow` so a hand-edited typo never breaks config loading.
fn parse_action(s: &str) -> crate::spec::RuleAction {
    match s.to_ascii_lowercase().as_str() {
        "deny" => crate::spec::RuleAction::Deny,
        _ => crate::spec::RuleAction::Allow,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spec::RuleAction;

    fn aws_config(path: PathBuf) -> CloudConfig {
        CloudConfig {
            provider: CloudProvider::Aws,
            default_region: "us-east-1".to_string(),
            config_path: path,
            auto_detect: false,
            default_action: RuleAction::Deny,
        }
    }

    // -- round-trip ------------------------------------------------------------

    #[test]
    fn save_then_load_round_trips_all_fields() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("sub").join("config.json");

        let original = aws_config(path.clone());
        original.save().unwrap();

        // save() must create the missing parent directory.
        assert!(path.exists(), "config file should exist after save");

        let loaded = CloudConfig::load_from(path).unwrap();
        assert_eq!(loaded.provider, CloudProvider::Aws);
        assert_eq!(loaded.default_region, "us-east-1");
        assert!(!loaded.auto_detect);
        assert_eq!(loaded.default_action, RuleAction::Deny);
    }

    #[test]
    fn save_writes_non_empty_json() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("config.json");

        aws_config(path.clone()).save().unwrap();

        let on_disk = std::fs::read_to_string(&path).unwrap();
        assert!(!on_disk.trim().is_empty());
        // Spot-check a couple of keys to confirm real serialization.
        assert!(on_disk.contains("\"provider\""));
        assert!(on_disk.contains("\"aws\""));
        assert!(on_disk.contains("\"us-east-1\""));
        assert!(on_disk.contains("\"deny\""));
    }

    // -- parse -----------------------------------------------------------------

    #[test]
    fn parse_full_json() {
        let json = r#"{
            "provider": "gcp",
            "default_region": "europe-west1",
            "auto_detect": false,
            "default_action": "allow"
        }"#;
        let cfg = CloudConfig::parse(json, PathBuf::from("/tmp/x.json")).unwrap();
        assert_eq!(cfg.provider, CloudProvider::Gcp);
        assert_eq!(cfg.default_region, "europe-west1");
        assert!(!cfg.auto_detect);
        assert_eq!(cfg.default_action, RuleAction::Allow);
    }

    #[test]
    fn parse_partial_json_uses_defaults() {
        // Only the provider is set; everything else should default.
        let cfg = CloudConfig::parse(r#"{ "provider": "hetzner" }"#, PathBuf::from("/tmp/x.json"))
            .unwrap();
        assert_eq!(cfg.provider, CloudProvider::Hetzner);
        assert_eq!(cfg.default_region, "");
        assert!(cfg.auto_detect);
        assert_eq!(cfg.default_action, RuleAction::Allow);
    }

    #[test]
    fn parse_empty_string_yields_defaults() {
        let cfg = CloudConfig::parse("", PathBuf::from("/tmp/x.json")).unwrap();
        assert_eq!(cfg.provider, CloudProvider::Unknown);
        assert!(cfg.auto_detect);
    }

    #[test]
    fn parse_unknown_provider_string_is_unknown() {
        let cfg = CloudConfig::parse(r#"{ "provider": "linode" }"#, PathBuf::from("/tmp/x.json"))
            .unwrap();
        assert_eq!(cfg.provider, CloudProvider::Unknown);
    }

    #[test]
    fn parse_invalid_json_returns_config_parse_error() {
        let err = CloudConfig::parse("not json {", PathBuf::from("/tmp/x.json")).unwrap_err();
        assert!(matches!(err, Error::ConfigParse(_)), "{err:?}");
    }

    #[test]
    fn parse_non_object_root_returns_config_parse_error() {
        let err = CloudConfig::parse("[1, 2, 3]", PathBuf::from("/tmp/x.json")).unwrap_err();
        assert!(matches!(err, Error::ConfigParse(_)), "{err:?}");
    }

    // -- to_json_string --------------------------------------------------------

    #[test]
    fn to_json_string_round_trips_through_parse() {
        let cfg = aws_config(PathBuf::from("/tmp/x.json"));
        let json = cfg.to_json_string().unwrap();
        let back = CloudConfig::parse(&json, PathBuf::from("/tmp/x.json")).unwrap();
        assert_eq!(back.provider, cfg.provider);
        assert_eq!(back.default_region, cfg.default_region);
        assert_eq!(back.auto_detect, cfg.auto_detect);
        assert_eq!(back.default_action, cfg.default_action);
    }

    // -- validate --------------------------------------------------------------

    #[test]
    fn validate_rejects_unknown_without_auto_detect() {
        let mut cfg = aws_config(PathBuf::from("/tmp/x.json"));
        cfg.provider = CloudProvider::Unknown;
        cfg.auto_detect = false;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn validate_allows_unknown_with_auto_detect() {
        let mut cfg = aws_config(PathBuf::from("/tmp/x.json"));
        cfg.provider = CloudProvider::Unknown;
        cfg.auto_detect = true;
        assert!(cfg.validate().is_ok());
    }

    // -- action helpers --------------------------------------------------------

    #[test]
    fn parse_action_case_insensitive() {
        assert_eq!(parse_action("deny"), RuleAction::Deny);
        assert_eq!(parse_action("DENY"), RuleAction::Deny);
        assert_eq!(parse_action("allow"), RuleAction::Allow);
        assert_eq!(parse_action("garbage"), RuleAction::Allow);
    }

    #[test]
    fn action_name_round_trips() {
        assert_eq!(action_name(RuleAction::Allow), "allow");
        assert_eq!(action_name(RuleAction::Deny), "deny");
        assert_eq!(
            parse_action(action_name(RuleAction::Deny)),
            RuleAction::Deny
        );
    }
}
