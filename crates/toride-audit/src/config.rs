//! Configuration file management for audit subsystems.
//!
//! Provides parsing, writing, and validation for audit-related configuration
//! files including auditd.conf, AIDE configuration, and rsyslog settings.

use std::fs;

use crate::paths::{secure_dir_mode, secure_file_mode};
use crate::{AuditPaths, Error, Result};

// ---------------------------------------------------------------------------
// ConfigManager
// ---------------------------------------------------------------------------

/// Manager for audit configuration files.
///
/// Handles reading, writing, and validating configuration files for
/// the audit daemon, AIDE, rsyslog, and logrotate.
pub struct ConfigManager<'a> {
    paths: &'a AuditPaths,
}

impl<'a> ConfigManager<'a> {
    /// Create a new config manager with the given paths.
    pub fn new(paths: &'a AuditPaths) -> Self {
        Self { paths }
    }

    /// Read the auditd configuration file.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] if the file cannot be read.
    pub fn read_auditd_conf(&self) -> Result<String> {
        let path = self.paths.audit_dir.join("auditd.conf");
        fs::read_to_string(&path).map_err(Error::from)
    }

    /// Write the auditd configuration file after creating a backup.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ConfigWrite`] if the file cannot be written.
    pub fn write_auditd_conf(&self, content: &str) -> Result<()> {
        let path = self.paths.audit_dir.join("auditd.conf");

        if path.exists() {
            crate::backup::create_backup(&path)?;
        }

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
            secure_dir_mode(parent)?;
        }

        fs::write(&path, content).map_err(|e| Error::ConfigWrite(format!("{e}")))?;
        // Pin restrictive mode regardless of umask.
        secure_file_mode(&path)?;
        Ok(())
    }

    /// Read the AIDE configuration file.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] if the file cannot be read.
    pub fn read_aide_conf(&self) -> Result<String> {
        fs::read_to_string(&self.paths.aide_conf).map_err(Error::from)
    }

    /// Write the AIDE configuration file after creating a backup.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ConfigWrite`] if the file cannot be written.
    pub fn write_aide_conf(&self, content: &str) -> Result<()> {
        if self.paths.aide_conf.exists() {
            crate::backup::create_backup(&self.paths.aide_conf)?;
        }

        if let Some(parent) = self.paths.aide_conf.parent() {
            fs::create_dir_all(parent)?;
            secure_dir_mode(parent)?;
        }

        fs::write(&self.paths.aide_conf, content)
            .map_err(|e| Error::ConfigWrite(format!("{e}")))?;
        secure_file_mode(&self.paths.aide_conf)?;
        Ok(())
    }

    /// Parse a key=value configuration file into a map.
    ///
    /// Ignores comments (lines starting with `#`) and empty lines.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ConfigParse`] if a line cannot be parsed.
    pub fn parse_kv_config(content: &str) -> Result<Vec<(String, String)>> {
        let mut entries = Vec::new();

        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            if let Some((key, value)) = trimmed.split_once('=') {
                entries.push((key.trim().to_owned(), value.trim().to_owned()));
            } else {
                return Err(Error::ConfigParse(format!(
                    "invalid config line (expected key=value): {trimmed}"
                )));
            }
        }

        Ok(entries)
    }

    /// Render a key=value map into a configuration string.
    pub fn render_kv_config(entries: &[(String, String)]) -> String {
        entries
            .iter()
            .map(|(k, v)| format!("{k} = {v}"))
            .collect::<Vec<String>>()
            .join("\n")
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_kv_skips_comments_and_blanks() {
        let content = "\
# a comment
# another

foo = 1
";
        let entries = ConfigManager::parse_kv_config(content).expect("parses");
        assert_eq!(entries, vec![("foo".to_owned(), "1".to_owned())]);
    }

    #[test]
    fn parse_kv_preserves_order() {
        let content = "a = 1\nb = 2\nc = 3";
        let entries = ConfigManager::parse_kv_config(content).expect("parses");
        let keys: Vec<&str> = entries.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(keys, vec!["a", "b", "c"]);
    }

    #[test]
    fn parse_kv_round_trips_through_render() {
        let entries = vec![
            ("foo".to_owned(), "1".to_owned()),
            ("bar".to_owned(), "baz".to_owned()),
        ];
        let rendered = ConfigManager::render_kv_config(&entries);
        let reparsed = ConfigManager::parse_kv_config(&rendered).expect("re-parses");
        assert_eq!(reparsed, entries);
    }

    #[test]
    fn parse_kv_trims_whitespace_around_key_and_value() {
        let entries = ConfigManager::parse_kv_config("   foo   =   bar   ").expect("parses");
        assert_eq!(entries, vec![("foo".to_owned(), "bar".to_owned())]);
    }

    #[test]
    fn parse_kv_value_may_contain_equals() {
        let entries = ConfigManager::parse_kv_config("url = a=b").expect("parses");
        assert_eq!(entries, vec![("url".to_owned(), "a=b".to_owned())]);
    }

    #[test]
    fn parse_kv_rejects_line_without_equals() {
        let result = ConfigManager::parse_kv_config("not a kv line");
        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            Error::ConfigParse(msg) => assert!(
                msg.contains("not a kv line"),
                "error message should mention the offending line: {msg}"
            ),
            other => panic!("expected ConfigParse error, got {other:?}"),
        }
    }

    #[test]
    fn parse_kv_empty_input_yields_empty_vec() {
        let entries = ConfigManager::parse_kv_config("").expect("parses");
        assert!(entries.is_empty());
    }

    #[test]
    fn render_kv_empty_is_empty_string() {
        let rendered = ConfigManager::render_kv_config(&[]);
        assert!(rendered.is_empty());
    }

    #[test]
    fn render_kv_single_entry_has_no_trailing_newline() {
        let rendered = ConfigManager::render_kv_config(&[("k".to_owned(), "v".to_owned())]);
        assert_eq!(rendered, "k = v");
    }
}
