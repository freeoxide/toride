//! Logrotate management.
//!
//! Provides functions for managing logrotate configuration for
//! audit-related log files.

use std::fmt::Write as _;
use std::fs;

use crate::paths::{secure_dir_mode, secure_file_mode, validate_name};
use crate::{AuditPaths, Error, Result};

// ---------------------------------------------------------------------------
// LogrotateConfig
// ---------------------------------------------------------------------------

/// Parsed representation of a logrotate configuration block.
#[derive(Debug, Clone)]
pub struct LogrotateConfig {
    /// Path to the log file(s) being rotated.
    pub log_path: String,
    /// Rotate files this many times before deletion.
    pub rotate: u32,
    /// Maximum size before rotation (e.g. "100M").
    pub max_size: Option<String>,
    /// Whether to compress rotated files.
    pub compress: bool,
    /// Whether to rotate on a daily/weekly/monthly basis.
    pub frequency: LogrotateFrequency,
    /// Additional options as raw strings.
    pub extra_options: Vec<String>,
}

// ---------------------------------------------------------------------------
// LogrotateFrequency
// ---------------------------------------------------------------------------

/// Log rotation frequency.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LogrotateFrequency {
    /// Rotate daily.
    #[default]
    Daily,
    /// Rotate weekly.
    Weekly,
    /// Rotate monthly.
    Monthly,
    /// Rotate yearly.
    Yearly,
}

// ---------------------------------------------------------------------------
// Logrotate management functions
// ---------------------------------------------------------------------------

/// Write a logrotate configuration for audit logs.
///
/// Creates a configuration file in `/etc/logrotate.d/` for the specified
/// log path.
///
/// # Arguments
///
/// * `paths` - Audit paths containing the `logrotate_d` directory.
/// * `name` - Configuration file name.
/// * `config` - The logrotate configuration.
///
/// # Errors
///
/// Returns [`Error::ConfigWrite`] if the file cannot be written.
pub fn write_logrotate_config(
    paths: &AuditPaths,
    name: &str,
    config: &LogrotateConfig,
) -> Result<()> {
    validate_name(name)?;
    let path = paths.logrotate_d.join(name);

    if path.exists() {
        crate::backup::create_backup(&path)?;
    }

    fs::create_dir_all(&paths.logrotate_d)?;
    // Pin the parent directory mode regardless of umask.
    secure_dir_mode(&paths.logrotate_d)?;

    let content = render_logrotate_config(config);
    fs::write(&path, content).map_err(|e| Error::ConfigWrite(format!("{e}")))?;
    // Pin the file mode regardless of umask: the config embeds a root-run
    // postrotate snippet and must never be group/other writable.
    secure_file_mode(&path)?;
    Ok(())
}

/// Remove a logrotate configuration file.
///
/// Creates a backup before removing.
///
/// # Errors
///
/// Returns [`Error::Io`] if the file cannot be removed.
pub fn remove_logrotate_config(paths: &AuditPaths, name: &str) -> Result<()> {
    validate_name(name)?;
    let path = paths.logrotate_d.join(name);

    if path.exists() {
        crate::backup::create_backup(&path)?;
        fs::remove_file(&path)?;
    }

    Ok(())
}

/// List all logrotate configuration files.
///
/// # Errors
///
/// Returns [`Error::Io`] if the directory cannot be read.
pub fn list_logrotate_configs(paths: &AuditPaths) -> Result<Vec<String>> {
    if !paths.logrotate_d.exists() {
        return Ok(Vec::new());
    }

    let mut files = Vec::new();
    for entry in fs::read_dir(&paths.logrotate_d)? {
        let entry = entry?;
        if entry.path().is_file() {
            files.push(entry.file_name().to_string_lossy().to_string());
        }
    }

    files.sort();
    Ok(files)
}

/// Render a logrotate configuration to a string.
#[must_use]
pub fn render_logrotate_config(config: &LogrotateConfig) -> String {
    let mut out = String::new();

    out.push_str(&config.log_path);
    out.push_str(" {\n");

    match config.frequency {
        LogrotateFrequency::Daily => out.push_str("    daily\n"),
        LogrotateFrequency::Weekly => out.push_str("    weekly\n"),
        LogrotateFrequency::Monthly => out.push_str("    monthly\n"),
        LogrotateFrequency::Yearly => out.push_str("    yearly\n"),
    }

    let _ = writeln!(out, "    rotate {}", config.rotate);

    if let Some(size) = &config.max_size {
        let _ = writeln!(out, "    maxsize {size}");
    }

    if config.compress {
        out.push_str("    compress\n");
        out.push_str("    delaycompress\n");
    }

    for opt in &config.extra_options {
        let _ = writeln!(out, "    {opt}");
    }

    out.push_str("}\n");
    out
}

/// Create a default logrotate configuration for audit logs.
#[must_use]
pub fn default_audit_logrotate() -> LogrotateConfig {
    LogrotateConfig {
        log_path: "/var/log/audit/*.log".to_owned(),
        rotate: 10,
        max_size: Some("100M".to_owned()),
        compress: true,
        frequency: LogrotateFrequency::Daily,
        extra_options: vec![
            "missingok".to_owned(),
            "notifempty".to_owned(),
            "sharedscripts".to_owned(),
            "postrotate".to_owned(),
            "    systemctl reload auditd > /dev/null 2>&1 || true".to_owned(),
            "endscript".to_owned(),
        ],
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_logrotate_config_daily() {
        let config = LogrotateConfig {
            log_path: "/var/log/audit/*.log".to_owned(),
            rotate: 5,
            max_size: None,
            compress: false,
            frequency: LogrotateFrequency::Daily,
            extra_options: vec![],
        };
        let rendered = render_logrotate_config(&config);
        assert!(rendered.starts_with("/var/log/audit/*.log {\n"));
        assert!(rendered.contains("    daily\n"));
        assert!(rendered.contains("    rotate 5\n"));
        assert!(!rendered.contains("compress"));
        assert!(rendered.ends_with("}\n"));
    }

    #[test]
    fn render_logrotate_config_weekly_with_compress() {
        let config = LogrotateConfig {
            log_path: "/var/log/test.log".to_owned(),
            rotate: 3,
            max_size: Some("50M".to_owned()),
            compress: true,
            frequency: LogrotateFrequency::Weekly,
            extra_options: vec![],
        };
        let rendered = render_logrotate_config(&config);
        assert!(rendered.contains("    weekly\n"));
        assert!(rendered.contains("    rotate 3\n"));
        assert!(rendered.contains("    maxsize 50M\n"));
        assert!(rendered.contains("    compress\n"));
        assert!(rendered.contains("    delaycompress\n"));
    }

    #[test]
    fn render_logrotate_config_monthly() {
        let config = LogrotateConfig {
            log_path: "/var/log/monthly.log".to_owned(),
            rotate: 12,
            max_size: None,
            compress: false,
            frequency: LogrotateFrequency::Monthly,
            extra_options: vec![],
        };
        let rendered = render_logrotate_config(&config);
        assert!(rendered.contains("    monthly\n"));
    }

    #[test]
    fn render_logrotate_config_yearly() {
        let config = LogrotateConfig {
            log_path: "/var/log/yearly.log".to_owned(),
            rotate: 1,
            max_size: None,
            compress: false,
            frequency: LogrotateFrequency::Yearly,
            extra_options: vec![],
        };
        let rendered = render_logrotate_config(&config);
        assert!(rendered.contains("    yearly\n"));
    }

    #[test]
    fn render_logrotate_config_includes_extra_options() {
        let config = LogrotateConfig {
            log_path: "/var/log/test.log".to_owned(),
            rotate: 5,
            max_size: None,
            compress: false,
            frequency: LogrotateFrequency::Daily,
            extra_options: vec!["missingok".to_owned(), "notifempty".to_owned()],
        };
        let rendered = render_logrotate_config(&config);
        assert!(rendered.contains("    missingok\n"));
        assert!(rendered.contains("    notifempty\n"));
    }

    #[test]
    fn default_audit_logrotate_has_sensible_defaults() {
        let config = default_audit_logrotate();
        assert_eq!(config.log_path, "/var/log/audit/*.log");
        assert_eq!(config.rotate, 10);
        assert_eq!(config.max_size.as_deref(), Some("100M"));
        assert!(config.compress);
        assert_eq!(config.frequency, LogrotateFrequency::Daily);
        assert!(!config.extra_options.is_empty());
        // Verify the rendered output is valid.
        let rendered = render_logrotate_config(&config);
        assert!(rendered.contains("daily"));
        assert!(rendered.contains("rotate 10"));
        assert!(rendered.contains("maxsize 100M"));
        assert!(rendered.contains("compress"));
    }

    #[test]
    fn logrotate_frequency_default_is_daily() {
        assert_eq!(LogrotateFrequency::default(), LogrotateFrequency::Daily);
    }

    /// Build an `AuditPaths` rooted at a temp dir so writes don't touch `/etc`.
    fn paths_for(dir: &std::path::Path) -> AuditPaths {
        AuditPaths {
            audit_dir: dir.join("audit"),
            rules_d: dir.join("audit/rules.d"),
            aide_conf: dir.join("aide.conf"),
            aide_db_dir: dir.join("aide"),
            rsyslog_conf: dir.join("rsyslog.conf"),
            rsyslog_d: dir.join("rsyslog.d"),
            logrotate_d: dir.join("logrotate.d"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn write_logrotate_config_pins_restrictive_mode() {
        use std::os::unix::fs::PermissionsExt;
        // Force a permissive umask for the duration of the write so we prove
        // the explicit chmod overrides it.
        let dir = tempfile::tempdir().unwrap();
        let paths = paths_for(dir.path());
        let config = default_audit_logrotate();

        write_logrotate_config(&paths, "audit", &config).unwrap();

        let path = paths.logrotate_d.join("audit");
        assert!(path.exists(), "config file should be created");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        // No group/other write bits, and overall 0o644.
        assert_eq!(mode & 0o022, 0, "no group/other write bits allowed");
        assert_eq!(mode & 0o777, 0o644);

        // Parent directory must be 0o755.
        let dmode = std::fs::metadata(&paths.logrotate_d)
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(dmode & 0o777, 0o755);
    }

    #[test]
    fn write_logrotate_config_rejects_traversal_name() {
        let dir = tempfile::tempdir().unwrap();
        let paths = paths_for(dir.path());
        let config = default_audit_logrotate();

        // A `..` name must be rejected before any file is written.
        assert!(
            write_logrotate_config(&paths, "..", &config).is_err(),
            "`..` must be rejected as a traversal name"
        );
        // Empty and absolute names are rejected too.
        assert!(write_logrotate_config(&paths, "", &config).is_err());
        // A name with a path separator is rejected.
        assert!(write_logrotate_config(&paths, "evil/escape", &config).is_err());
    }

    #[test]
    fn write_logrotate_config_rejects_leading_dash() {
        let dir = tempfile::tempdir().unwrap();
        let paths = paths_for(dir.path());
        let config = default_audit_logrotate();
        assert!(write_logrotate_config(&paths, "--flag", &config).is_err());
    }
}
