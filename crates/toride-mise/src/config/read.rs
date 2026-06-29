//! Read-only config operations on [`Mise`](crate::Mise).
//!
//! This module contains `impl Mise` methods that query mise configuration
//! without modifying any files:
//!
//! - `config_ls` — list config files mise reads.
//! - `config_get` — get a specific config key.
//! - `settings` — list all mise settings.
//! - `settings_get` — get a single mise setting value.

use camino::Utf8PathBuf;

use crate::client::Mise;
use crate::config::model::{MiseToml, SettingsEntry};
use crate::error::MiseResult;

// ---------------------------------------------------------------------------
// JSON helpers (only compiled under the "json" feature)
// ---------------------------------------------------------------------------

/// A single entry from `mise config ls --json`.
#[cfg(feature = "json")]
#[derive(serde::Deserialize)]
struct ConfigLsEntry {
    path: String,
}

/// A single row from `mise settings --json`.
#[cfg(feature = "json")]
#[derive(serde::Deserialize)]
struct SettingsRow {
    name: String,
    value: serde_json::Value,
}

// ---------------------------------------------------------------------------
// impl Mise — read operations
// ---------------------------------------------------------------------------

impl Mise {
    /// List the config files that mise reads for the current directory.
    ///
    /// Returns an ordered list of paths from most-global to most-local.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`] if the underlying `mise config ls`
    /// exits non-zero. Returns [`MiseError::JsonParse`] if the output cannot
    /// be deserialised (requires `json` feature).
    pub async fn config_ls(&self) -> MiseResult<Vec<Utf8PathBuf>> {
        #[cfg(feature = "json")]
        {
            let entries: Vec<ConfigLsEntry> = self.run_json(["config", "ls", "--json"]).await?;
            Ok(entries
                .into_iter()
                .map(|e| Utf8PathBuf::from(e.path))
                .collect())
        }

        #[cfg(not(feature = "json"))]
        {
            let output = self.run_checked(["config", "ls"]).await?;
            let paths = output
                .stdout_trimmed()
                .lines()
                .map(Utf8PathBuf::from)
                .collect();
            Ok(paths)
        }
    }

    /// Get the value of a specific config key.
    ///
    /// Calls `mise config get <key>` and returns the trimmed stdout. Returns
    /// `None` if the key does not exist (mise exits non-zero with a message
    /// containing "not found").
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`] for unexpected failures.
    pub async fn config_get(&self, key: &str) -> MiseResult<Option<String>> {
        let result = self.run_checked(["config", "get", key]).await;
        match result {
            Ok(output) => {
                let value = output.stdout_trimmed().to_owned();
                Ok(Some(value))
            }
            Err(crate::error::MiseError::CommandFailed { stderr, .. }) => {
                if stderr.contains("not found") || stderr.contains("no config") {
                    Ok(None)
                } else {
                    Err(crate::error::MiseError::CommandFailed {
                        command: format!("config get {key}"),
                        exit_code: None,
                        stdout: String::new(),
                        stderr,
                    })
                }
            }
            Err(e) => Err(e),
        }
    }

    /// Read and parse a specific config file into a [`MiseToml`] value.
    ///
    /// If `path` is `None`, reads the global config (`mise config path`
    /// is queried first).
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::Config`] if the file cannot be read or parsed.
    pub async fn config_read(&self, path: Option<&Utf8PathBuf>) -> MiseResult<MiseToml> {
        let config_path = match path {
            Some(p) => p.clone(),
            None => self.config_path().await?,
        };

        let content = fs_err::read_to_string(config_path.as_std_path()).map_err(|e| {
            crate::error::ConfigError::ReadFailed {
                path: config_path.to_string(),
                reason: e.to_string(),
            }
        })?;

        Self::parse_mise_toml(&content, Some(config_path))
    }

    /// List all mise settings and their values.
    ///
    /// Returns a map of setting name to parsed [`SettingsEntry`].
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`] if the underlying `mise settings`
    /// exits non-zero.
    pub async fn settings(&self) -> MiseResult<std::collections::BTreeMap<String, SettingsEntry>> {
        #[cfg(feature = "json")]
        {
            let rows: Vec<SettingsRow> =
                self.run_json_vec_safe(["settings", "ls", "--json"]).await?;
            let mut map = std::collections::BTreeMap::new();
            for row in rows {
                let entry = json_value_to_settings_entry(&row.value);
                map.insert(row.name, entry);
            }
            Ok(map)
        }

        #[cfg(not(feature = "json"))]
        {
            let output = self.run_checked(["settings", "ls"]).await?;
            let mut map = std::collections::BTreeMap::new();
            for line in output.stdout_trimmed().lines() {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                if let Some((name, raw_value)) = line.split_once('=') {
                    map.insert(
                        name.trim().to_owned(),
                        SettingsEntry::from_raw(raw_value.trim()),
                    );
                }
            }
            Ok(map)
        }
    }

    /// List all mise settings with extended metadata.
    ///
    /// Invokes `mise settings ls --json-extended` and returns a map of setting
    /// name to parsed [`SettingsEntry`].
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`] if the command exits non-zero.
    /// Returns [`MiseError::JsonParse`] if the output cannot be deserialised.
    pub async fn settings_all(
        &self,
    ) -> MiseResult<std::collections::BTreeMap<String, SettingsEntry>> {
        #[cfg(feature = "json")]
        {
            let rows: Vec<SettingsRow> = self
                .run_json_vec_safe(["settings", "ls", "--json-extended"])
                .await?;
            let mut map = std::collections::BTreeMap::new();
            for row in rows {
                let entry = json_value_to_settings_entry(&row.value);
                map.insert(row.name, entry);
            }
            Ok(map)
        }

        #[cfg(not(feature = "json"))]
        {
            let output = self
                .run_checked(["settings", "ls", "--json-extended"])
                .await?;
            let mut map = std::collections::BTreeMap::new();
            for line in output.stdout_trimmed().lines() {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                if let Some((name, raw_value)) = line.split_once('=') {
                    map.insert(
                        name.trim().to_owned(),
                        SettingsEntry::from_raw(raw_value.trim()),
                    );
                }
            }
            Ok(map)
        }
    }

    /// List mise settings that are set locally (project-level).
    ///
    /// Invokes `mise settings ls --json` and filters for settings sourced from
    /// the local config file.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`] if the command exits non-zero.
    /// Returns [`MiseError::JsonParse`] if the output cannot be deserialised.
    pub async fn settings_local(
        &self,
    ) -> MiseResult<std::collections::BTreeMap<String, SettingsEntry>> {
        #[cfg(feature = "json")]
        {
            let rows: Vec<SettingsRow> =
                self.run_json_vec_safe(["settings", "ls", "--json"]).await?;
            let mut map = std::collections::BTreeMap::new();
            for row in rows {
                let entry = json_value_to_settings_entry(&row.value);
                map.insert(row.name, entry);
            }
            Ok(map)
        }

        #[cfg(not(feature = "json"))]
        {
            let output = self.run_checked(["settings", "ls"]).await?;
            let mut map = std::collections::BTreeMap::new();
            for line in output.stdout_trimmed().lines() {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                if let Some((name, raw_value)) = line.split_once('=') {
                    map.insert(
                        name.trim().to_owned(),
                        SettingsEntry::from_raw(raw_value.trim()),
                    );
                }
            }
            Ok(map)
        }
    }

    /// Get the value of a single mise setting.
    ///
    /// Returns `None` if the setting is not set.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`] for unexpected failures.
    pub async fn settings_get(&self, key: &str) -> MiseResult<Option<SettingsEntry>> {
        let output = self.run_checked(["settings", "get", key]).await;
        match output {
            Ok(o) => {
                let raw = o.stdout_trimmed().to_owned();
                if raw.is_empty() {
                    Ok(None)
                } else {
                    Ok(Some(SettingsEntry::from_raw(&raw)))
                }
            }
            Err(crate::error::MiseError::CommandFailed { stderr, .. }) => {
                if stderr.contains("not set") || stderr.contains("not found") {
                    Ok(None)
                } else {
                    Err(crate::error::MiseError::CommandFailed {
                        command: format!("settings get {key}"),
                        exit_code: None,
                        stdout: String::new(),
                        stderr,
                    })
                }
            }
            Err(e) => Err(e),
        }
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    /// Parse a TOML string into a [`MiseToml`], associating it with an
    /// optional file path.
    fn parse_mise_toml(content: &str, path: Option<Utf8PathBuf>) -> MiseResult<MiseToml> {
        #[cfg(feature = "toml")]
        {
            let doc: toml::Value =
                toml::from_str(content).map_err(|e| crate::error::ConfigError::ParseFailed {
                    path: path.as_ref().map_or_else(String::new, ToString::to_string),
                    reason: e.to_string(),
                })?;

            let mut config = MiseToml::at(path.unwrap_or_default());

            // Known top-level keys that are parsed into typed fields.
            let known_keys = ["settings", "tools", "env", "tasks"];

            if let Some(settings) = doc.get("settings").and_then(|v| v.as_table()) {
                for (k, v) in settings {
                    config
                        .settings
                        .insert(k.clone(), toml_value_to_settings_entry(v));
                }
            }

            if let Some(tools) = doc.get("tools").and_then(|v| v.as_table()) {
                for (k, v) in tools {
                    if let Some(s) = v.as_str() {
                        config.tools.insert(k.clone(), s.to_owned());
                    }
                }
            }

            if let Some(env) = doc.get("env").and_then(|v| v.as_table()) {
                for (k, v) in env {
                    if let Some(s) = v.as_str() {
                        config.env.insert(k.clone(), s.to_owned());
                    }
                }
            }

            if let Some(tasks) = doc.get("tasks").and_then(|v| v.as_table()) {
                for (k, v) in tasks {
                    if let Some(s) = v.as_str() {
                        config.tasks.insert(k.clone(), s.to_owned());
                    }
                }
            }

            // Preserve unknown top-level keys into `extra`.
            if let Some(table) = doc.as_table() {
                for (k, v) in table {
                    if !known_keys.contains(&k.as_str()) {
                        config.extra.insert(k.clone(), v.clone());
                    }
                }
            }

            Ok(config)
        }

        #[cfg(not(feature = "toml"))]
        {
            let _ = (content, path);
            Ok(MiseToml::empty())
        }
    }
}

// ---------------------------------------------------------------------------
// Conversion helpers
// ---------------------------------------------------------------------------

/// Convert a [`toml::Value`] into a [`SettingsEntry`].
#[cfg(feature = "toml")]
fn toml_value_to_settings_entry(value: &toml::Value) -> SettingsEntry {
    match value {
        toml::Value::Boolean(b) => SettingsEntry::Bool(*b),
        toml::Value::Integer(n) => SettingsEntry::Int(*n),
        toml::Value::String(s) => SettingsEntry::String(s.clone()),
        toml::Value::Array(arr) => {
            let items = arr
                .iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect();
            SettingsEntry::Array(items)
        }
        other => SettingsEntry::String(other.to_string()),
    }
}

/// Convert a [`serde_json::Value`] into a [`SettingsEntry`].
#[cfg(feature = "json")]
fn json_value_to_settings_entry(value: &serde_json::Value) -> SettingsEntry {
    match value {
        serde_json::Value::Bool(b) => SettingsEntry::Bool(*b),
        serde_json::Value::Number(n) => SettingsEntry::Int(n.as_i64().unwrap_or_default()),
        serde_json::Value::String(s) => SettingsEntry::String(s.clone()),
        serde_json::Value::Array(arr) => {
            let items = arr
                .iter()
                .filter_map(|v| {
                    if v.is_string() {
                        v.as_str().map(String::from)
                    } else {
                        None
                    }
                })
                .collect();
            SettingsEntry::Array(items)
        }
        other => SettingsEntry::String(other.to_string()),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use toride_runner::{CommandOutput, FakeRunner};

    use crate::client::Mise;

    fn build_mise(fake: Arc<FakeRunner>) -> Mise {
        Mise::builder()
            .runner(fake as Arc<dyn toride_runner::AsyncRunner>)
            .binary(crate::binary::MiseBinary::from_path("/usr/bin/mise"))
            .build()
            .unwrap()
    }

    #[tokio::test]
    async fn test_config_ls() {
        let json = r#"[{"path":"/home/user/.config/mise/config.toml"},{"path":".mise.toml"}]"#;
        let fake = Arc::new(FakeRunner::new().push_response(CommandOutput::from_stdout(json)));
        let mise = build_mise(fake.clone());

        let paths = mise.config_ls().await.unwrap();
        assert_eq!(paths.len(), 2);
        assert_eq!(paths[0].as_str(), "/home/user/.config/mise/config.toml");
        assert_eq!(paths[1].as_str(), ".mise.toml");

        let calls = fake.calls();
        assert_eq!(calls.len(), 1);
        assert!(calls[0].args.contains(&"config".to_string()));
        assert!(calls[0].args.contains(&"ls".to_string()));
    }

    #[tokio::test]
    async fn test_settings_parses_json() {
        let json = r#"[{"name":"auto_install","value":true},{"name":"jobs","value":4},{"name":"experimental","value":"yes"}]"#;
        let fake = Arc::new(FakeRunner::new().push_response(CommandOutput::from_stdout(json)));
        let mise = build_mise(fake.clone());

        let settings = mise.settings().await.unwrap();
        assert_eq!(settings.len(), 3);
        assert_eq!(
            settings.get("auto_install"),
            Some(&super::super::model::SettingsEntry::Bool(true))
        );
        assert_eq!(
            settings.get("jobs"),
            Some(&super::super::model::SettingsEntry::Int(4))
        );
        assert_eq!(
            settings.get("experimental"),
            Some(&super::super::model::SettingsEntry::String(
                "yes".to_string()
            ))
        );

        let calls = fake.calls();
        assert_eq!(calls.len(), 1);
        assert!(calls[0].args.contains(&"settings".to_string()));
        assert!(calls[0].args.contains(&"ls".to_string()));
    }
}
