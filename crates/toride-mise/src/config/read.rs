//! Read-only config operations on [`Mise`].
//!
//! This module contains `impl Mise` methods that query mise configuration
//! without modifying any files:
//!
//! - `config_ls`: list config files mise reads.
//! - `config_get`: get a specific config key.
//! - `settings`: list all mise settings.
//! - `settings_get`: get a single mise setting value.

use camino::Utf8PathBuf;

use crate::client::Mise;
use crate::config::model::{MiseToml, SettingsEntry, TaskEntry, ToolVersions};
use crate::error::MiseResult;

/// A single entry from `mise config ls --json`.
#[cfg(feature = "json")]
#[derive(serde::Deserialize)]
struct ConfigLsEntry {
    path: String,
}

impl Mise {
    /// List the config files that mise reads for the current directory.
    ///
    /// Returns an ordered list of paths from most-global to most-local.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`](crate::error::MiseError::CommandFailed) if the underlying `mise config ls`
    /// exits non-zero. Returns [`MiseError::JsonParse`](crate::error::MiseError::JsonParse) if the output cannot
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
    /// Returns [`MiseError::CommandFailed`](crate::error::MiseError::CommandFailed) for unexpected failures.
    pub async fn config_get(&self, key: &str) -> MiseResult<Option<String>> {
        let result = self.run_checked(["config", "get", key]).await;
        match result {
            Ok(output) => {
                let value = output.stdout_trimmed().to_owned();
                Ok(Some(value))
            }
            Err(crate::error::MiseError::CommandFailed {
                command: _,
                exit_code,
                stdout,
                stderr,
            }) => {
                if stderr.contains("not found") || stderr.contains("no config") {
                    Ok(None)
                } else {
                    Err(crate::error::MiseError::CommandFailed {
                        command: format!("config get {key}"),
                        exit_code,
                        stdout,
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
    /// Returns [`MiseError::Config`](crate::error::MiseError::Config) if the file cannot be read or parsed.
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

    /// List mise settings whose value differs from the default, with their
    /// current values.
    ///
    /// Real mise `settings ls --json` emits an object keyed by setting name
    /// (verified on mise 2026.6.14); each value becomes a [`SettingsEntry`].
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`](crate::error::MiseError::CommandFailed) if the underlying `mise settings`
    /// exits non-zero.
    pub async fn settings(&self) -> MiseResult<std::collections::BTreeMap<String, SettingsEntry>> {
        #[cfg(feature = "json")]
        {
            let output: crate::serde_utils::json_outputs::SettingsOutput =
                self.run_json(["settings", "ls", "--json"]).await?;
            Ok(output
                .iter()
                .map(|(name, value)| (name.clone(), json_value_to_settings_entry(value)))
                .collect())
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

    /// List every mise setting with its extended metadata: resolved value,
    /// type, description, and the config source that defined it.
    ///
    /// Invokes `mise settings ls -a --json-extended` (the `-a` includes
    /// settings still at their default) and returns the
    /// [`SettingsExtendedOutput`](crate::serde_utils::json_outputs::SettingsExtendedOutput)
    /// map keyed by setting name.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`](crate::error::MiseError::CommandFailed) if the command exits non-zero.
    /// Returns [`MiseError::JsonParse`](crate::error::MiseError::JsonParse) if the output cannot be deserialised.
    pub async fn settings_all(
        &self,
    ) -> MiseResult<crate::serde_utils::json_outputs::SettingsExtendedOutput> {
        #[cfg(feature = "json")]
        {
            self.run_json(["settings", "ls", "-a", "--json-extended"])
                .await
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

    /// List mise settings sourced from the local (project-level) config
    /// file, with their values.
    ///
    /// Invokes `mise settings ls --local --json-extended`: mise's own
    /// `--local` flag restricts the listing to settings whose source is the
    /// local config, and the extended payload carries that source per entry.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`](crate::error::MiseError::CommandFailed) if the command exits non-zero.
    /// Returns [`MiseError::JsonParse`](crate::error::MiseError::JsonParse) if the output cannot be deserialised.
    pub async fn settings_local(
        &self,
    ) -> MiseResult<std::collections::BTreeMap<String, SettingsEntry>> {
        #[cfg(feature = "json")]
        {
            let output: crate::serde_utils::json_outputs::SettingsExtendedOutput = self
                .run_json(["settings", "ls", "--local", "--json-extended"])
                .await?;
            Ok(output
                .iter()
                .filter_map(|(name, entry)| {
                    entry
                        .value
                        .as_ref()
                        .map(|value| (name.clone(), json_value_to_settings_entry(value)))
                })
                .collect())
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
    /// Returns [`MiseError::CommandFailed`](crate::error::MiseError::CommandFailed) for unexpected failures.
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
            Err(crate::error::MiseError::CommandFailed {
                command: _,
                exit_code,
                stdout,
                stderr,
            }) => {
                if stderr.contains("not set") || stderr.contains("not found") {
                    Ok(None)
                } else {
                    Err(crate::error::MiseError::CommandFailed {
                        command: format!("settings get {key}"),
                        exit_code,
                        stdout,
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
                    match v {
                        toml::Value::String(s) => {
                            config
                                .tools
                                .insert(k.clone(), ToolVersions::Single(s.clone()));
                        }
                        toml::Value::Array(arr) => {
                            let versions: Vec<String> = arr
                                .iter()
                                .filter_map(|item| item.as_str().map(str::to_owned))
                                .collect();
                            if !versions.is_empty() {
                                config
                                    .tools
                                    .insert(k.clone(), ToolVersions::Multiple(versions));
                            }
                        }
                        _ => {}
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
                    let entry = match v {
                        toml::Value::String(s) => TaskEntry::Command(s.clone()),
                        other => match toml::to_string(other) {
                            Ok(rendered) => TaskEntry::Table(rendered),
                            Err(_) => continue,
                        },
                    };
                    config.tasks.insert(k.clone(), entry);
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
    async fn test_settings_parses_map_shape() {
        let json = r#"{"auto_install":true,"jobs":4,"experimental":"yes"}"#;
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

    #[tokio::test]
    async fn test_settings_local_filters_to_local_config_sources() {
        let json = r#"{"all_compile":{"value":true,"type":"boolean","description":"do not use precompiled binaries","source":"/project/.mise.toml"}}"#;
        let fake = Arc::new(FakeRunner::new().push_response(CommandOutput::from_stdout(json)));
        let mise = build_mise(fake.clone());

        let settings = mise.settings_local().await.unwrap();
        assert_eq!(settings.len(), 1);
        assert_eq!(
            settings.get("all_compile"),
            Some(&super::super::model::SettingsEntry::Bool(true))
        );

        let calls = fake.calls();
        assert_eq!(calls.len(), 1);
        assert!(calls[0].args.contains(&"--local".to_string()));
        assert!(calls[0].args.contains(&"--json-extended".to_string()));
    }

    #[tokio::test]
    async fn test_settings_all_returns_extended_entries() {
        let json = r#"{"all_compile":{"value":true,"type":"boolean","description":"do not use precompiled binaries","source":"/project/.mise.toml"}}"#;
        let fake = Arc::new(FakeRunner::new().push_response(CommandOutput::from_stdout(json)));
        let mise = build_mise(fake.clone());

        let settings = mise.settings_all().await.unwrap();
        let entry = settings.get("all_compile").expect("entry present");
        assert_eq!(entry.source.as_deref(), Some("/project/.mise.toml"));

        let calls = fake.calls();
        assert_eq!(calls.len(), 1);
        assert!(calls[0].args.contains(&"-a".to_string()));
        assert!(calls[0].args.contains(&"--json-extended".to_string()));
    }

    #[cfg(feature = "toml")]
    #[test]
    fn parse_mise_toml_keeps_array_tool_versions_and_table_tasks() {
        use crate::config::model::{TaskEntry, ToolVersions};

        let content = r#"
[tools]
python = ["3.12", "3.11"]
node = "22.1.0"

[env]
FOO = "bar"

[tasks]
lint = "cargo clippy"
"#;
        let config = Mise::parse_mise_toml(content, None).unwrap();
        assert_eq!(
            config.tools.get("python"),
            Some(&ToolVersions::Multiple(vec![
                "3.12".to_owned(),
                "3.11".to_owned()
            ]))
        );
        assert_eq!(
            config.tools.get("node"),
            Some(&ToolVersions::Single("22.1.0".to_owned()))
        );
        assert_eq!(config.env.get("FOO"), Some(&"bar".to_owned()));
        assert_eq!(
            config.tasks.get("lint"),
            Some(&TaskEntry::Command("cargo clippy".to_owned()))
        );
    }

    #[cfg(feature = "toml")]
    #[test]
    fn parse_mise_toml_keeps_inline_table_tasks() {
        use crate::config::model::TaskEntry;
        let content = r#"
[tasks]
build = { run = "cargo build", depends = ["lint"] }
"#;
        let config = Mise::parse_mise_toml(content, None).unwrap();
        let TaskEntry::Table(rendered) = config.tasks.get("build").unwrap() else {
            panic!(
                "inline-table task must be preserved, got {:?}",
                config.tasks
            );
        };
        assert!(rendered.contains("run = \"cargo build\""));
        assert!(rendered.contains("depends"));
    }
}
