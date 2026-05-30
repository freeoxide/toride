//! XDG-compliant path resolution for fail2ban data and configuration.

use std::path::PathBuf;

/// Resolved paths for fail2ban data storage.
#[derive(Debug, Clone)]
pub struct Fail2BanPaths {
    /// Base configuration directory (XDG_CONFIG_HOME/toride/fail2ban/).
    pub config_dir: PathBuf,
    /// Main configuration file path.
    pub config_file: PathBuf,
    /// Data directory for persistent state (XDG_DATA_HOME/toride/fail2ban/).
    pub data_dir: PathBuf,
    /// Ban database file path.
    pub ban_db: PathBuf,
    /// PID file for the daemon.
    pub pid_file: PathBuf,
    /// Log directory for fail2ban's own logs.
    pub log_dir: PathBuf,
    /// Journal directory for tracking log file positions.
    pub journal_dir: PathBuf,
}

impl Fail2BanPaths {
    /// Resolve paths using XDG conventions.
    ///
    /// Defaults to `~/.config/toride/fail2ban/` for config
    /// and `~/.local/share/toride/fail2ban/` for data.
    ///
    /// # Errors
    ///
    /// Returns `InvalidConfig` if the system config or data directory cannot be determined.
    pub fn resolve() -> crate::Result<Self> {
        let config_dir = dirs::config_dir()
            .ok_or_else(|| crate::Error::InvalidConfig("Cannot determine config directory".into()))?
            .join("toride")
            .join("fail2ban");

        let data_dir = dirs::data_dir()
            .ok_or_else(|| crate::Error::InvalidConfig("Cannot determine data directory".into()))?
            .join("toride")
            .join("fail2ban");

        Ok(Self {
            config_file: config_dir.join("config.json"),
            log_dir: data_dir.join("logs"),
            ban_db: data_dir.join("bans.json"),
            pid_file: data_dir.join("fail2ban.pid"),
            journal_dir: data_dir.join("journals"),
            config_dir,
            data_dir,
        })
    }

    /// Returns the PID file path, optionally overridden by config.
    #[must_use]
    pub fn pid_file_with_override(&self, config_pid: Option<&std::path::Path>) -> PathBuf {
        config_pid.map_or_else(|| self.pid_file.clone(), std::path::Path::to_path_buf)
    }

    /// Create all directories. Idempotent.
    pub fn ensure_directories(&self) -> crate::Result<()> {
        std::fs::create_dir_all(&self.config_dir)?;
        std::fs::create_dir_all(&self.data_dir)?;
        std::fs::create_dir_all(&self.log_dir)?;
        std::fs::create_dir_all(&self.journal_dir)?;
        Ok(())
    }
}

#[cfg(test)]
#[path = "paths.test.rs"]
mod tests;
