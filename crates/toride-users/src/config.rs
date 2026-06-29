//! Config file read/write operations for user management.
//!
//! Provides functions to read and write the toride-users configuration
//! file, which stores managed user specifications and policies.

use std::path::Path;

use crate::spec::UserSpec;
use crate::{Error, Result};

/// Default config file name.
const CONFIG_FILENAME: &str = "users.json";

/// Toride-users configuration file containing managed user specs.
///
/// Requires the `serde` feature for JSON serialization.
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct UsersConfig {
    /// Managed user specifications.
    pub users: Vec<UserSpec>,
}

impl UsersConfig {
    /// Create an empty config.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Read config from a JSON file.
    ///
    /// Requires the `serde` feature.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] if the file cannot be read, or [`Error::Other`]
    /// if the JSON is malformed.
    pub fn read(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        Self::from_json(&content)
    }

    /// Parse config from a JSON string.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Other`] if the JSON is malformed.
    pub fn from_json(json: &str) -> Result<Self> {
        // The `config` feature implies `serde` (see Cargo.toml), so this branch
        // is always compiled when `UsersConfig` is in scope. The serde-off arm
        // is retained only as a compile-time fallback for hypothetical future
        // callers that construct the struct without going through the feature.
        #[cfg(feature = "serde")]
        {
            serde_json::from_str(json).map_err(|e| Error::Other(format!("config parse error: {e}")))
        }
        #[cfg(not(feature = "serde"))]
        {
            let _ = json;
            Err(Error::Other(
                "serde feature is required for config parsing (the 'config' feature implies it; \
                 enable 'config')",
            ))
        }
    }

    /// Write config to a JSON file.
    ///
    /// Creates a backup before writing. Requires the `serde` feature.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] if the file cannot be written.
    pub fn write(&self, path: &Path) -> Result<()> {
        if path.exists() {
            crate::backup::backup_file(path, None)?;
        }

        let content = self.to_json()?;

        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        std::fs::write(path, content)?;
        Ok(())
    }

    /// Serialize config to a JSON string.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Other`] if serialization fails.
    pub fn to_json(&self) -> Result<String> {
        #[cfg(feature = "serde")]
        {
            serde_json::to_string_pretty(self)
                .map_err(|e| Error::Other(format!("config serialize error: {e}")))
        }
        #[cfg(not(feature = "serde"))]
        {
            Err(Error::Other(
                "serde feature is required for config serialization (the 'config' feature implies \
                 it; enable 'config')",
            ))
        }
    }

    /// Resolve the default config path using XDG conventions.
    ///
    /// Returns `~/.config/toride/users/users.json`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Other`] if the config directory cannot be determined.
    pub fn default_path() -> Result<std::path::PathBuf> {
        let config_dir = dirs::config_dir()
            .ok_or_else(|| Error::Other("cannot determine config directory".into()))?;
        Ok(config_dir
            .join("toride")
            .join("users")
            .join(CONFIG_FILENAME))
    }

    /// Add or update a user spec in the config.
    pub fn upsert_user(&mut self, spec: UserSpec) {
        if let Some(existing) = self.users.iter_mut().find(|u| u.username == spec.username) {
            *existing = spec;
        } else {
            self.users.push(spec);
        }
    }

    /// Remove a user spec from the config.
    pub fn remove_user(&mut self, username: &str) -> bool {
        let original_len = self.users.len();
        self.users.retain(|u| u.username != username);
        self.users.len() != original_len
    }

    /// Get a user spec by username.
    #[must_use]
    pub fn get_user(&self, username: &str) -> Option<&UserSpec> {
        self.users.iter().find(|u| u.username == username)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spec::{Complexity, PasswordPolicy};
    use tempfile::TempDir;

    fn sample_spec() -> UserSpec {
        UserSpec {
            username: "deployer".to_owned(),
            shell: "/usr/bin/bash".to_owned(),
            groups: vec!["sudo".to_owned(), "docker".to_owned()],
            sudo_access: true,
            totp_enabled: false,
            password_policy: PasswordPolicy {
                max_days: 90,
                min_days: 1,
                warn_days: 7,
                complexity: Complexity::Strong,
            },
        }
    }

    /// Regression for the config/serde feature wiring gap: the `config`
    /// feature previously did NOT imply `serde`, so `UsersConfig::from_json`
    /// and `to_json` compiled but failed at runtime with "serde feature is
    /// required". Now `config` implies `serde`, so a build with just
    /// `--features config` must round-trip JSON end to end.
    #[test]
    fn config_feature_round_trips_json() {
        let mut cfg = UsersConfig::new();
        cfg.upsert_user(sample_spec());

        let json = cfg
            .to_json()
            .expect("to_json must work under config feature");
        // The user and a representative scalar survive.
        assert!(
            json.contains("\"username\""),
            "json should contain username: {json}"
        );
        assert!(
            json.contains("deployer"),
            "json should contain deployer: {json}"
        );

        let back = UsersConfig::from_json(&json).expect("from_json must work under config feature");
        assert_eq!(back.users.len(), 1);
        assert_eq!(back.users[0], sample_spec());
    }

    /// `read`/`write` against a temp file must round-trip under the `config`
    /// feature alone (no explicit `serde` flag). Before the fix, `write` -> `
    /// to_json` returned `Err(Other("serde feature is required..."))`.
    #[test]
    fn config_feature_read_write_round_trip() {
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("users.json");

        let mut cfg = UsersConfig::new();
        cfg.upsert_user(sample_spec());

        cfg.write(&path)
            .expect("write must succeed under config feature");
        assert!(path.exists(), "config file should exist after write");

        let loaded = UsersConfig::read(&path).expect("read must succeed under config feature");
        assert_eq!(loaded.users.len(), 1);
        assert_eq!(loaded.users[0].username, "deployer");
        assert_eq!(
            loaded.users[0].password_policy.complexity,
            Complexity::Strong
        );
    }

    /// Malformed JSON must surface a parse error (not a "serde feature
    /// required" stub), proving the real serde_json path is wired.
    #[test]
    fn malformed_json_returns_parse_error() {
        let err = UsersConfig::from_json("{ not json").expect_err("malformed json must error");
        assert!(
            err.to_string().contains("config parse error"),
            "expected parse error, got: {err}"
        );
    }

    /// `upsert_user` updates an existing entry in place rather than appending.
    #[test]
    fn upsert_user_replaces_existing() {
        let mut cfg = UsersConfig::new();
        cfg.upsert_user(sample_spec());
        let mut updated = sample_spec();
        updated.shell = "/usr/sbin/nologin".to_owned();
        cfg.upsert_user(updated);

        assert_eq!(cfg.users.len(), 1);
        assert_eq!(cfg.users[0].shell, "/usr/sbin/nologin");
    }

    /// `remove_user` returns whether anything was removed.
    #[test]
    fn remove_user_reports_removal() {
        let mut cfg = UsersConfig::new();
        cfg.upsert_user(sample_spec());
        assert!(cfg.remove_user("deployer"), "should report removal");
        assert!(
            !cfg.remove_user("deployer"),
            "second removal should be false"
        );
        assert!(cfg.users.is_empty());
    }
}
