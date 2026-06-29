//! XDG-compliant path resolution for backup data and configuration.
//!
//! [`BackupPaths`] resolves the standard directory layout used by the toride
//! backup subsystem for configuration files, state, and cache data.

use std::path::PathBuf;

/// Resolved paths for backup data storage and configuration.
///
/// All paths follow XDG conventions under the `toride/backup` namespace.
#[derive(Debug, Clone)]
pub struct BackupPaths {
    /// Base configuration directory (`XDG_CONFIG_HOME/toride/backup/`).
    pub config_dir: PathBuf,
    /// Main configuration file path.
    pub config_file: PathBuf,
    /// Data directory for persistent state (`XDG_DATA_HOME/toride/backup/`).
    pub data_dir: PathBuf,
    /// Cache directory for temporary backup data (`XDG_CACHE_HOME/toride/backup/`).
    pub cache_dir: PathBuf,
    /// Restic-specific configuration directory.
    pub restic_config_dir: PathBuf,
    /// Borg-specific configuration directory.
    pub borg_config_dir: PathBuf,
    /// Schedule state directory (systemd timer drop-ins, cron files).
    pub schedule_dir: PathBuf,
    /// Restore target base directory for test restores.
    pub restore_test_dir: PathBuf,
    /// Log directory for backup operation logs.
    pub log_dir: PathBuf,
}

impl BackupPaths {
    /// Resolve paths using XDG conventions.
    ///
    /// Defaults to `~/.config/toride/backup/` for config,
    /// `~/.local/share/toride/backup/` for data, and
    /// `~/.cache/toride/backup/` for cache.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ConfigParse`](crate::Error::ConfigParse) if the
    /// system config, data, or cache directory cannot be determined.
    pub fn resolve() -> crate::Result<Self> {
        let config_dir = dirs::config_dir()
            .ok_or_else(|| {
                crate::Error::ConfigParse("Cannot determine XDG config directory".into())
            })?
            .join("toride")
            .join("backup");

        let data_dir = dirs::data_dir()
            .ok_or_else(|| crate::Error::ConfigParse("Cannot determine XDG data directory".into()))?
            .join("toride")
            .join("backup");

        let cache_dir = dirs::cache_dir()
            .ok_or_else(|| {
                crate::Error::ConfigParse("Cannot determine XDG cache directory".into())
            })?
            .join("toride")
            .join("backup");

        Ok(Self {
            restic_config_dir: config_dir.join("restic"),
            borg_config_dir: config_dir.join("borg"),
            schedule_dir: config_dir.join("schedules"),
            config_file: config_dir.join("config.json"),
            log_dir: data_dir.join("logs"),
            restore_test_dir: data_dir.join("restore-tests"),
            config_dir,
            data_dir,
            cache_dir,
        })
    }

    /// Create all directories. Idempotent.
    ///
    /// # Errors
    ///
    /// Returns an error if any directory cannot be created.
    pub fn ensure_directories(&self) -> crate::Result<()> {
        let dirs = [
            &self.config_dir,
            &self.data_dir,
            &self.cache_dir,
            &self.restic_config_dir,
            &self.borg_config_dir,
            &self.schedule_dir,
            &self.restore_test_dir,
            &self.log_dir,
        ];
        for dir in &dirs {
            std::fs::create_dir_all(dir)?;
        }
        Ok(())
    }
}
