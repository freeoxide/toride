//! Config mutation operations on [`Mise`](crate::Mise).
//!
//! This module contains `impl Mise` methods that modify mise configuration:
//!
//! - `config_set` — set a key in a config file.
//! - `settings_set` — set a mise setting.
//! - `settings_unset` — remove a mise setting.

use camino::Utf8PathBuf;

use crate::client::Mise;
use crate::config::model::{ConfigWriteResult, SettingsEntry};
use crate::error::MiseResult;

// ---------------------------------------------------------------------------
// impl Mise — write operations
// ---------------------------------------------------------------------------

impl Mise {
    /// Set a config key in the specified config file.
    ///
    /// If `config_path` is `None`, the global config is used (as reported by
    /// [`Mise::config_path`]).
    ///
    /// Calls `mise config set <key> <value>` under the hood. If the `toml`
    /// feature is enabled and the config file does not exist, it is created.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`] if the underlying `mise config set`
    /// exits non-zero. Returns [`MiseError::Config`] if the file cannot be
    /// written when creating a new config.
    pub async fn config_set(
        &self,
        key: &str,
        value: &str,
        config_path: Option<&Utf8PathBuf>,
    ) -> MiseResult<ConfigWriteResult> {
        let path = match config_path {
            Some(p) => p.clone(),
            None => self.config_path().await?,
        };

        let existed = path.as_std_path().exists();

        // Use toml_edit for precise in-place editing when available.
        #[cfg(feature = "toml")]
        {
            Self::config_set_toml_edit(&path, key, value, existed)?;
        }

        #[cfg(not(feature = "toml"))]
        {
            self.run_checked(["config", "set", key, value]).await?;
            let _ = existed; // used below
        }

        Ok(ConfigWriteResult {
            path,
            created: !existed,
            key: Some(key.to_owned()),
            old_value: None,
            new_value: Some(value.to_owned()),
            changed: true,
        })
    }

    /// Set a mise global setting.
    ///
    /// Calls `mise settings set <key> <value>`.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`] if the command exits non-zero.
    pub async fn settings_set(
        &self,
        key: &str,
        value: &SettingsEntry,
    ) -> MiseResult<ConfigWriteResult> {
        let mise_value = value.to_mise_value();
        self.run_checked(["settings", "set", key, &mise_value])
            .await?;

        let path = self.config_path().await?;

        Ok(ConfigWriteResult {
            path,
            created: false,
            key: Some(key.to_owned()),
            old_value: None,
            new_value: Some(mise_value),
            changed: true,
        })
    }

    /// Add a setting value to a mise setting (for array / multi-value settings).
    ///
    /// Calls `mise settings add <key> <value>`.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`] if the command exits non-zero.
    pub async fn settings_add(&self, key: &str, value: &str) -> MiseResult<ConfigWriteResult> {
        self.run_checked(["settings", "add", key, value]).await?;

        let path = self.config_path().await?;

        Ok(ConfigWriteResult {
            path,
            created: false,
            key: Some(key.to_owned()),
            old_value: None,
            new_value: Some(value.to_owned()),
            changed: true,
        })
    }

    /// Remove a mise global setting.
    ///
    /// Calls `mise settings unset <key>`. Returns `Ok` even if the setting
    /// was not previously set (mise handles the idempotent case).
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`] if the command exits non-zero for
    /// a reason other than a missing key.
    pub async fn settings_unset(&self, key: &str) -> MiseResult<ConfigWriteResult> {
        let result = self.run_checked(["settings", "unset", key]).await;
        match result {
            Ok(_) => {}
            Err(crate::error::MiseError::CommandFailed { stderr, .. }) => {
                // If the key was not set, that is fine — treat as success.
                if !stderr.contains("not set") && !stderr.contains("not found") {
                    return Err(crate::error::MiseError::CommandFailed {
                        command: format!("settings unset {key}"),
                        exit_code: None,
                        stdout: String::new(),
                        stderr,
                    });
                }
            }
            Err(e) => return Err(e),
        }

        let path = self.config_path().await?;

        Ok(ConfigWriteResult {
            path,
            created: false,
            key: Some(key.to_owned()),
            old_value: None,
            new_value: None,
            changed: true,
        })
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    /// Perform a config set via `toml_edit` for lossless round-tripping.
    ///
    /// Reads the file (or creates an empty document), applies the key/value
    /// edit, and writes the result back.
    #[cfg(feature = "toml")]
    #[allow(clippy::too_many_lines)]
    fn config_set_toml_edit(
        path: &Utf8PathBuf,
        key: &str,
        value: &str,
        _existed: bool,
    ) -> MiseResult<()> {
        use crate::config::model::SettingsEntry;
        use crate::error::ConfigError;

        // Read unconditionally — handle file-not-found gracefully instead of
        // a TOCTOU-prone exists() + read() pair.
        let content = match fs_err::read_to_string(path.as_std_path()) {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(e) => {
                return Err(ConfigError::ReadFailed {
                    path: path.to_string(),
                    reason: e.to_string(),
                }
                .into());
            }
        };

        let mut doc = content.parse::<toml_edit::DocumentMut>().map_err(|e| {
            ConfigError::ParseFailed {
                path: path.to_string(),
                reason: format!(
                    "existing file could not be parsed as valid TOML and will not be overwritten: {e}"
                ),
            }
        })?;

        // Support dotted keys like "settings.python.default_packages" by
        // navigating into nested tables.
        let parts: Vec<&str> = key.split('.').collect();
        let mut table = doc.as_table_mut();

        for (i, part) in parts.iter().enumerate() {
            if i == parts.len() - 1 {
                // Leaf key — set the value with proper TOML typing.
                let entry = SettingsEntry::from_raw(value);
                let toml_value = match entry {
                    SettingsEntry::Bool(b) => toml_edit::value(b),
                    SettingsEntry::Int(n) => toml_edit::value(n),
                    SettingsEntry::String(s) => toml_edit::value(s),
                    SettingsEntry::Array(items) => {
                        let mut arr = toml_edit::Array::new();
                        for item in items {
                            arr.push(item);
                        }
                        toml_edit::Item::Value(toml_edit::Value::Array(arr))
                    }
                };
                table[*part] = toml_value;
            } else {
                // Intermediate segment — ensure a sub-table exists.
                if !table.contains_key(part) {
                    table[*part] = toml_edit::Item::Table(toml_edit::Table::new());
                }
                table = table[*part]
                    .as_table_mut()
                    .ok_or_else(|| ConfigError::WriteFailed {
                        path: path.to_string(),
                        reason: format!("key segment `{part}` is not a table"),
                    })?;
            }
        }

        // Ensure parent directory exists.
        if let Some(parent) = path.parent() {
            fs_err::create_dir_all(parent.as_std_path()).map_err(|e| ConfigError::WriteFailed {
                path: parent.to_string(),
                reason: e.to_string(),
            })?;
        }

        // Write atomically: write to a hidden tempfile in the same directory,
        // then rename over the target (atomic on POSIX).  Use a high-resolution
        // timestamp for uniqueness to avoid data races from concurrent calls.
        let content = doc.to_string();
        let parent_dir = path.parent().unwrap_or(path);
        let temp_name = format!(
            ".{}.tmp.{}.{}",
            path.file_name().unwrap_or("config"),
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        );
        let temp_path = parent_dir.join(&temp_name);

        // RAII guard to clean up the temp file on error.
        #[allow(clippy::items_after_statements)]
        struct TempGuard {
            path: Option<std::path::PathBuf>,
        }

        #[allow(clippy::items_after_statements)]
        impl Drop for TempGuard {
            fn drop(&mut self) {
                if let Some(ref p) = self.path {
                    let _ = std::fs::remove_file(p);
                }
            }
        }

        let _guard = TempGuard {
            path: Some(temp_path.as_std_path().to_owned()),
        };

        fs_err::write(temp_path.as_std_path(), &content).map_err(|e| ConfigError::WriteFailed {
            path: temp_path.to_string(),
            reason: e.to_string(),
        })?;

        fs_err::rename(temp_path.as_std_path(), path.as_std_path()).map_err(|e| {
            ConfigError::WriteFailed {
                path: path.to_string(),
                reason: e.to_string(),
            }
        })?;

        // Validate: re-parse the written file to confirm it is valid TOML.
        let written =
            fs_err::read_to_string(path.as_std_path()).map_err(|e| ConfigError::ReadFailed {
                path: path.to_string(),
                reason: e.to_string(),
            })?;
        written
            .parse::<toml_edit::DocumentMut>()
            .map_err(|e| ConfigError::ParseFailed {
                path: path.to_string(),
                reason: e.to_string(),
            })?;

        Ok(())
    }
}
