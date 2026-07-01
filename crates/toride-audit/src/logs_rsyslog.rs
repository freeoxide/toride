//! rsyslog management.
//!
//! Provides functions for managing rsyslog configuration and service
//! for audit log aggregation.

use std::fs;

use crate::paths::{secure_dir_mode, secure_file_mode, validate_name};
use crate::{AuditPaths, Error, Result};

// ---------------------------------------------------------------------------
// RsyslogConfig
// ---------------------------------------------------------------------------

/// Parsed representation of rsyslog configuration.
#[derive(Debug, Clone, Default)]
pub struct RsyslogConfig {
    /// Active rules (facility.priority -> action).
    pub rules: Vec<RsyslogRule>,
    /// Drop-in files loaded from `/etc/rsyslog.d/`.
    pub drop_in_files: Vec<String>,
}

// ---------------------------------------------------------------------------
// RsyslogRule
// ---------------------------------------------------------------------------

/// A single rsyslog rule (facility.priority action).
#[derive(Debug, Clone)]
pub struct RsyslogRule {
    /// The syslog facility (e.g. `authpriv`, `local6`, `*`).
    pub facility: String,
    /// The priority level (e.g. `*`, `info`, `warn`, `err`).
    pub priority: String,
    /// The action target (file path, `@host`, or template).
    pub action: String,
    /// Raw rule text.
    pub raw: String,
}

// ---------------------------------------------------------------------------
// Rsyslog management functions
// ---------------------------------------------------------------------------

/// Read the main rsyslog configuration file.
///
/// # Errors
///
/// Returns [`Error::Io`] if the file cannot be read.
pub fn read_config(paths: &AuditPaths) -> Result<String> {
    fs::read_to_string(&paths.rsyslog_conf).map_err(Error::from)
}

/// Write a drop-in configuration file to `/etc/rsyslog.d/`.
///
/// # Arguments
///
/// * `paths` - Audit paths containing the `rsyslog_d` directory.
/// * `name` - Drop-in file name (without `.conf` extension).
/// * `content` - Configuration content.
///
/// # Errors
///
/// Returns [`Error::ConfigWrite`] if the file cannot be written.
pub fn write_dropin(paths: &AuditPaths, name: &str, content: &str) -> Result<()> {
    validate_name(name)?;
    let path = paths.rsyslog_d.join(format!("{name}.conf"));

    if path.exists() {
        crate::backup::create_backup(&path)?;
    }

    fs::create_dir_all(&paths.rsyslog_d)?;
    secure_dir_mode(&paths.rsyslog_d)?;
    fs::write(&path, content).map_err(|e| Error::ConfigWrite(format!("{e}")))?;
    secure_file_mode(&path)?;
    Ok(())
}

/// Remove a drop-in configuration file.
///
/// Creates a backup before removing.
///
/// # Errors
///
/// Returns [`Error::Io`] if the file cannot be removed.
pub fn remove_dropin(paths: &AuditPaths, name: &str) -> Result<()> {
    validate_name(name)?;
    let path = paths.rsyslog_d.join(format!("{name}.conf"));

    if path.exists() {
        crate::backup::create_backup(&path)?;
        fs::remove_file(&path)?;
    }

    Ok(())
}

/// List all drop-in configuration files in `/etc/rsyslog.d/`.
///
/// # Errors
///
/// Returns [`Error::Io`] if the directory cannot be read.
pub fn list_dropins(paths: &AuditPaths) -> Result<Vec<String>> {
    if !paths.rsyslog_d.exists() {
        return Ok(Vec::new());
    }

    let mut files = Vec::new();
    for entry in fs::read_dir(&paths.rsyslog_d)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().is_some_and(|ext| ext == "conf") {
            files.push(
                path.file_stem()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string(),
            );
        }
    }

    files.sort();
    Ok(files)
}

/// Parse rsyslog configuration content into rules.
///
/// Ignores comments and empty lines. Only parses simple facility.priority
/// action rules.
pub fn parse_rsyslog_config(content: &str) -> Vec<RsyslogRule> {
    content
        .lines()
        .filter(|line| {
            let trimmed = line.trim();
            !trimmed.is_empty() && !trimmed.starts_with('#') && !trimmed.starts_with('$')
        })
        .filter_map(|line| {
            let parts: Vec<&str> = line.splitn(2, &[' ', '\t']).collect();
            if parts.len() < 2 {
                return None;
            }

            let fac_pri = parts[0];
            let action = parts[1].trim();

            let (facility, priority) = fac_pri.split_once('.').unwrap_or((fac_pri, "*"));

            Some(RsyslogRule {
                facility: facility.to_owned(),
                priority: priority.to_owned(),
                action: action.to_owned(),
                raw: line.to_owned(),
            })
        })
        .collect()
}
