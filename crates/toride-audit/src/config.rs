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
