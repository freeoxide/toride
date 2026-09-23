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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(all(test, feature = "toml"))]
mod tests {
    use super::*;
    use camino::Utf8PathBuf;
    use tempfile::TempDir;

    /// Helper: run `config_set_toml_edit` against `path` (a non-existent file
    /// in a fresh temp dir) and return the written file content.
    fn write_and_read(path: &Utf8PathBuf, key: &str, value: &str) -> String {
        Mise::config_set_toml_edit(path, key, value, false)
            .expect("config_set_toml_edit should succeed");
        fs_err::read_to_string(path.as_std_path()).expect("written file should be readable")
    }

    #[test]
    fn creates_new_file_for_missing_config() {
        let dir = TempDir::new().expect("tempdir");
        let path = Utf8PathBuf::from_path_buf(dir.path().join("mise.toml")).expect("utf8 path");

        let content = write_and_read(&path, "python", "3.12");

        assert!(path.as_std_path().exists(), "file should be created");
        let doc = content
            .parse::<toml_edit::DocumentMut>()
            .expect("output should be valid TOML");
        assert_eq!(doc["python"].as_str(), Some("3.12"));
    }

    #[test]
    fn overwrites_existing_key_value() {
        let dir = TempDir::new().expect("tempdir");
        let path = Utf8PathBuf::from_path_buf(dir.path().join("mise.toml")).expect("utf8 path");

        fs_err::write(path.as_std_path(), "python = \"3.11\"\n").expect("seed write");

        let existed = path.as_std_path().exists();
        Mise::config_set_toml_edit(&path, "python", "3.12", existed).expect("edit should succeed");

        let content = fs_err::read_to_string(path.as_std_path()).expect("read");
        let doc = content
            .parse::<toml_edit::DocumentMut>()
            .expect("valid TOML");
        assert_eq!(doc["python"].as_str(), Some("3.12"));
        assert_eq!(
            doc.as_table().len(),
            1,
            "no duplicate or leftover keys expected"
        );
    }

    #[test]
    fn sets_dotted_key_into_nested_table() {
        let dir = TempDir::new().expect("tempdir");
        let path = Utf8PathBuf::from_path_buf(dir.path().join("mise.toml")).expect("utf8 path");

        // SettingsEntry::from_raw has no array parser, so array-shaped input
        // is stored verbatim as a string. Exercise the dotted-key navigation
        // with a plain string leaf and confirm it lands under [settings.python].
        let content = write_and_read(&path, "settings.python.default_packages", "pip ruff");

        let doc = content
            .parse::<toml_edit::DocumentMut>()
            .expect("valid TOML");
        // The dotted key should land under [settings.python].
        assert_eq!(
            doc["settings"]["python"]["default_packages"].as_str(),
            Some("pip ruff")
        );
    }

    #[test]
    fn adds_sibling_key_without_disturbing_existing() {
        let dir = TempDir::new().expect("tempdir");
        let path = Utf8PathBuf::from_path_buf(dir.path().join("mise.toml")).expect("utf8 path");

        // Start with an existing table.
        fs_err::write(path.as_std_path(), "[settings]\nexperimental = true\n").expect("seed");

        Mise::config_set_toml_edit(&path, "settings.color", "true", true)
            .expect("edit should succeed");

        let content = fs_err::read_to_string(path.as_std_path()).expect("read");
        let doc = content
            .parse::<toml_edit::DocumentMut>()
            .expect("valid TOML");
        assert_eq!(
            doc["settings"]["experimental"].as_bool(),
            Some(true),
            "existing key should be preserved"
        );
        assert_eq!(
            doc["settings"]["color"].as_bool(),
            Some(true),
            "new sibling key should be added"
        );
    }

    #[test]
    fn round_trip_preserves_typed_values() {
        let dir = TempDir::new().expect("tempdir");
        let path = Utf8PathBuf::from_path_buf(dir.path().join("mise.toml")).expect("utf8 path");

        // bool
        write_and_read(&path, "cd", "true");
        // int
        Mise::config_set_toml_edit(&path, "jobs", "4", true).expect("int edit");
        // string
        Mise::config_set_toml_edit(&path, "node", "20.0.0", true).expect("str edit");
        // array-shaped input falls back to a verbatim string (from_raw has no
        // array parser); assert it round-trips as a quoted string.
        Mise::config_set_toml_edit(&path, "env", "[\"FOO=1\", \"BAR=2\"]", true).expect("str edit");

        let content = fs_err::read_to_string(path.as_std_path()).expect("read");
        let doc = content
            .parse::<toml_edit::DocumentMut>()
            .expect("valid TOML after round-trip");

        assert_eq!(doc["cd"].as_bool(), Some(true));
        assert_eq!(doc["jobs"].as_integer(), Some(4));
        assert_eq!(doc["node"].as_str(), Some("20.0.0"));
        assert_eq!(
            doc["env"].as_str(),
            Some("[\"FOO=1\", \"BAR=2\"]"),
            "array-shaped input stored verbatim as a string"
        );
    }

    #[test]
    fn atomic_rename_leaves_no_temp_file_behind_on_success() {
        let dir = TempDir::new().expect("tempdir");
        let path = Utf8PathBuf::from_path_buf(dir.path().join("mise.toml")).expect("utf8 path");

        Mise::config_set_toml_edit(&path, "python", "3.12", false).expect("edit should succeed");

        // The only entry in the parent dir should be the target file itself.
        let entries: Vec<String> = fs_err::read_dir(dir.path())
            .expect("read_dir")
            .map(|e| e.expect("entry").file_name().to_string_lossy().to_string())
            .collect();
        assert_eq!(entries, ["mise.toml"], "no leftover temp files");
        assert!(path.as_std_path().exists());
    }

    #[test]
    fn parse_error_on_existing_file_does_not_clobber() {
        let dir = TempDir::new().expect("tempdir");
        let path = Utf8PathBuf::from_path_buf(dir.path().join("mise.toml")).expect("utf8 path");

        let original = "this is = = not valid toml";
        fs_err::write(path.as_std_path(), original).expect("seed");

        let result = Mise::config_set_toml_edit(&path, "python", "3.12", true);

        assert!(result.is_err(), "should refuse to edit unparseable file");
        // The original corrupt bytes must be left byte-identical.
        let after = fs_err::read_to_string(path.as_std_path()).expect("read");
        assert_eq!(after, original, "corrupt file must not be overwritten");
    }

    #[test]
    fn creates_parent_directories_when_missing() {
        let dir = TempDir::new().expect("tempdir");
        let nested = dir.path().join("nested/sub/dir/mise.toml");
        let path = Utf8PathBuf::from_path_buf(nested).expect("utf8 path");

        let content = write_and_read(&path, "python", "3.12");
        let doc = content
            .parse::<toml_edit::DocumentMut>()
            .expect("valid TOML");
        assert_eq!(doc["python"].as_str(), Some("3.12"));
    }
}
