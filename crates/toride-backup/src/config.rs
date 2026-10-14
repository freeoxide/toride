//! Configuration management for backup jobs.
//!
//! Provides loading, saving, and validation of backup configuration files.
//! Config files are stored as JSON under the XDG config directory.

use std::collections::HashMap;
use std::path::Path;

use crate::paths::BackupPaths;
use crate::spec::BackupSpec;
use crate::{Error, Result};

/// Root configuration structure for all backup jobs.
///
/// Stored as `config.json` in the backup configuration directory.
#[derive(Debug, Clone)]
pub struct BackupConfig {
    /// Named backup job specifications.
    pub jobs: HashMap<String, BackupSpec>,
    /// Default backend when not specified in a job.
    pub default_backend: crate::spec::Backend,
}

impl BackupConfig {
    /// Create an empty configuration.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            jobs: HashMap::new(),
            default_backend: crate::spec::Backend::default(),
        }
    }

    /// Load configuration from the default XDG path.
    ///
    /// A missing default-path file is a valid first-run state and yields an
    /// empty configuration; use [`BackupConfig::load_from`] for strict
    /// explicit-path semantics.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ConfigParse`] if the config file cannot be read
    /// or parsed.
    pub fn load() -> Result<Self> {
        let paths = BackupPaths::resolve()?;
        if !paths.config_file.exists() {
            return Ok(Self::empty());
        }
        Self::load_from(&paths.config_file)
    }

    /// Load configuration from an explicit file path.
    ///
    /// A missing file is an error, not an empty config: an explicit path
    /// means the caller expects that file, and silently reporting zero jobs
    /// hides typos and unexpanded `~` paths.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ConfigParse`] if the file does not exist, cannot be
    /// read, or cannot be parsed.
    pub fn load_from(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Err(Error::ConfigParse(format!(
                "config file not found: {} (an unexpanded ~ path never matches; \
                 the CLI default is the resolved XDG path)",
                path.display()
            )));
        }

        let content = std::fs::read_to_string(path)?;
        Self::parse(&content)
    }

    /// Parse configuration from a JSON string.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ConfigParse`] if the content is not valid JSON
    /// or does not match the expected structure.
    pub fn parse(content: &str) -> Result<Self> {
        #[cfg(feature = "serde")]
        {
            let config: Self = serde_json::from_str(content)?;
            Ok(config)
        }

        #[cfg(not(feature = "serde"))]
        {
            let _ = content;
            Err(Error::ConfigParse(
                "config parsing requires the 'serde' feature".into(),
            ))
        }
    }

    /// Save configuration to the default XDG path.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be written.
    pub fn save(&self) -> Result<()> {
        let paths = BackupPaths::resolve()?;
        paths.ensure_directories()?;
        self.save_to(&paths.config_file)
    }

    /// Save configuration to an explicit file path.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be written.
    pub fn save_to(&self, path: &Path) -> Result<()> {
        #[cfg(feature = "serde")]
        {
            let content = serde_json::to_string_pretty(self)?;
            std::fs::write(path, content)?;
            Ok(())
        }

        #[cfg(not(feature = "serde"))]
        {
            let _ = (self, path);
            Err(Error::ConfigParse(
                "config saving requires the 'serde' feature".into(),
            ))
        }
    }

    /// Validate all jobs in this configuration.
    ///
    /// # Errors
    ///
    /// Returns the first validation error encountered.
    pub fn validate(&self) -> Result<()> {
        for (name, spec) in &self.jobs {
            spec.validate()
                .map_err(|e| Error::ConfigParse(format!("job {name:?}: {e}")))?;
        }
        Ok(())
    }

    /// Add or replace a backup job.
    pub fn upsert_job(&mut self, spec: BackupSpec) {
        self.jobs.insert(spec.name.clone(), spec);
    }

    /// Remove a backup job by name.
    ///
    /// Returns `true` if the job was present and removed.
    pub fn remove_job(&mut self, name: &str) -> bool {
        self.jobs.remove(name).is_some()
    }

    /// Get a backup job by name.
    pub fn get_job(&self, name: &str) -> Option<&BackupSpec> {
        self.jobs.get(name)
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for BackupConfig {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut s = serializer.serialize_struct("BackupConfig", 2)?;
        s.serialize_field("default_backend", &self.default_backend.to_string())?;
        s.serialize_field("jobs", &self.jobs)?;
        s.end()
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for BackupConfig {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use std::str::FromStr;

        #[derive(serde::Deserialize)]
        #[serde(field_identifier, rename_all = "snake_case")]
        enum Field {
            DefaultBackend,
            Jobs,
        }

        struct BackupConfigVisitor;

        impl<'de> serde::de::Visitor<'de> for BackupConfigVisitor {
            type Value = BackupConfig;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("struct BackupConfig")
            }

            fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                let mut default_backend: Option<crate::spec::Backend> = None;
                let mut jobs: Option<HashMap<String, BackupSpec>> = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        Field::DefaultBackend => {
                            if default_backend.is_some() {
                                return Err(serde::de::Error::duplicate_field("default_backend"));
                            }
                            let raw: String = map.next_value()?;
                            default_backend = Some(
                                crate::spec::Backend::from_str(&raw)
                                    .map_err(serde::de::Error::custom)?,
                            );
                        }
                        Field::Jobs => {
                            if jobs.is_some() {
                                return Err(serde::de::Error::duplicate_field("jobs"));
                            }
                            jobs = Some(map.next_value()?);
                        }
                    }
                }

                Ok(BackupConfig {
                    jobs: jobs.unwrap_or_default(),
                    default_backend: default_backend.unwrap_or_default(),
                })
            }
        }

        const FIELDS: &[&str] = &["default_backend", "jobs"];
        deserializer.deserialize_struct("BackupConfig", FIELDS, BackupConfigVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_from_missing_path_is_an_error_not_an_empty_config() {
        let err = BackupConfig::load_from(Path::new("/nonexistent/toride-backup-test/config.json"))
            .expect_err("an explicit missing path must error");
        assert!(matches!(err, Error::ConfigParse(_)), "got {err:?}");
        assert!(
            format!("{err}").contains("config file not found"),
            "error must name the missing file: {err}"
        );
    }

    #[test]
    fn load_from_empty_object_is_an_empty_config() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        std::fs::write(&path, "{}").unwrap();
        let config = BackupConfig::load_from(&path).expect("empty object parses");
        assert!(config.jobs.is_empty());
    }
}
