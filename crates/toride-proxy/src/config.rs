//! Proxy configuration file management.
//!
//! Provides reading, writing, and validation of proxy configuration files
//! with support for both Nginx and Caddy formats. Every write path creates a
//! pre-mutation backup via [`crate::backup`] before overwriting so changes can
//! be rolled back.

use crate::backup;
use crate::error::{Error, Result};
use crate::nginx_config::{parse_server_blocks, ParsedServerBlock};
use crate::paths::ProxyPaths;

/// Configuration file manager for proxy settings.
///
/// Handles reading existing configurations from disk and writing new ones,
/// with automatic backup creation before overwriting.
pub struct ConfigManager<'a> {
    paths: &'a ProxyPaths,
}

impl<'a> ConfigManager<'a> {
    /// Create a new config manager.
    pub fn new(paths: &'a ProxyPaths) -> Self {
        Self { paths }
    }

    /// Snapshot the current proxy configuration and persist it to
    /// [`ProxyPaths::backup_dir`].
    ///
    /// Shared by every write path below. Backup failures are surfaced as
    /// `Error::ConfigWrite` rather than silently swallowed, because a missing
    /// rollback point is exactly the situation operators need to know about
    /// before a destructive overwrite. Callers that want best-effort behavior
    /// can ignore the `Result`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ConfigWrite`] if the snapshot cannot be built or
    /// persisted.
    pub fn backup(&self) -> Result<()> {
        let snapshot = backup::create_backup(self.paths)
            .map_err(|e| Error::ConfigWrite(format!("create backup: {e}")))?;
        backup::save_backup_to_disk(self.paths, &snapshot)
            .map_err(|e| Error::ConfigWrite(format!("persist backup: {e}")))
    }

    /// Read the main Nginx configuration file.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read.
    pub fn read_nginx_config(&self) -> Result<String> {
        std::fs::read_to_string(&self.paths.nginx_conf).map_err(|e| {
            Error::NotFound(format!(
                "cannot read nginx.conf: {} ({})",
                self.paths.nginx_conf.display(),
                e
            ))
        })
    }

    /// Parse all server blocks from the main Nginx configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if the configuration cannot be parsed.
    pub fn parse_nginx_server_blocks(&self) -> Result<Vec<ParsedServerBlock>> {
        let content = self.read_nginx_config()?;
        parse_server_blocks(&content)
    }

    /// Read a specific site configuration file.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read.
    pub fn read_site_config(&self, domain: &str) -> Result<String> {
        let path = self.paths.nginx_site_path(domain);
        std::fs::read_to_string(&path).map_err(|e| {
            Error::NotFound(format!(
                "cannot read site config for {domain}: {} ({})",
                path.display(),
                e
            ))
        })
    }

    /// List all configured site domains in sites-available.
    ///
    /// # Errors
    ///
    /// Returns an error if the directory cannot be read.
    pub fn list_sites(&self) -> Result<Vec<String>> {
        let mut sites = Vec::new();

        if !self.paths.nginx_sites_available.is_dir() {
            return Ok(sites);
        }

        let entries = std::fs::read_dir(&self.paths.nginx_sites_available)?;
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                let name = path.file_name().unwrap_or_default().to_string_lossy().to_string();
                sites.push(name);
            }
        }

        sites.sort();
        Ok(sites)
    }

    /// List all enabled sites (symlinks in sites-enabled).
    ///
    /// # Errors
    ///
    /// Returns an error if the directory cannot be read.
    pub fn list_enabled_sites(&self) -> Result<Vec<String>> {
        let mut sites = Vec::new();

        if !self.paths.nginx_sites_enabled.is_dir() {
            return Ok(sites);
        }

        let entries = std::fs::read_dir(&self.paths.nginx_sites_enabled)?;
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() || path.is_symlink() {
                let name = path.file_name().unwrap_or_default().to_string_lossy().to_string();
                sites.push(name);
            }
        }

        sites.sort();
        Ok(sites)
    }

    /// Read the Caddyfile.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read.
    pub fn read_caddyfile(&self) -> Result<String> {
        std::fs::read_to_string(&self.paths.caddyfile).map_err(|e| {
            Error::NotFound(format!(
                "cannot read Caddyfile: {} ({})",
                self.paths.caddyfile.display(),
                e
            ))
        })
    }

    // -----------------------------------------------------------------
    // Write paths -- each creates a pre-mutation backup before overwriting
    // -----------------------------------------------------------------

    /// Write a raw Nginx site configuration for a domain.
    ///
    /// Creates a backup of the current config, ensures the sites-available
    /// directory exists, then atomically writes `content` to
    /// `<sites-available>/<domain>`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ConfigWrite`] if the backup or write fails.
    pub fn write_site_config(&self, domain: &str, content: &str) -> Result<()> {
        self.backup()?;

        let site_path = self.paths.nginx_site_path(domain);
        if let Some(parent) = site_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| Error::ConfigWrite(format!("create sites dir: {e}")))?;
        }
        toride_fs::atomic_write(&site_path, content)
            .map_err(|e| Error::ConfigWrite(format!("write site config: {e}")))?;
        tracing::info!("config: wrote site config for {domain} to {}", site_path.display());
        Ok(())
    }

    /// Overwrite the main `nginx.conf`.
    ///
    /// Creates a backup first, then atomically writes `content` to
    /// [`ProxyPaths::nginx_conf`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::ConfigWrite`] if the backup or write fails.
    pub fn write_nginx_config(&self, content: &str) -> Result<()> {
        self.backup()?;
        if let Some(parent) = self.paths.nginx_conf.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| Error::ConfigWrite(format!("create nginx dir: {e}")))?;
        }
        toride_fs::atomic_write(&self.paths.nginx_conf, content)
            .map_err(|e| Error::ConfigWrite(format!("write nginx.conf: {e}")))?;
        tracing::info!("config: wrote nginx.conf to {}", self.paths.nginx_conf.display());
        Ok(())
    }

    /// Overwrite the Caddyfile.
    ///
    /// Creates a backup first, then atomically writes `content` to
    /// [`ProxyPaths::caddyfile`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::ConfigWrite`] if the backup or write fails.
    pub fn write_caddyfile_config(&self, content: &str) -> Result<()> {
        self.backup()?;
        if let Some(parent) = self.paths.caddyfile.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| Error::ConfigWrite(format!("create caddy dir: {e}")))?;
        }
        toride_fs::atomic_write(&self.paths.caddyfile, content)
            .map_err(|e| Error::ConfigWrite(format!("write Caddyfile: {e}")))?;
        tracing::info!("config: wrote Caddyfile to {}", self.paths.caddyfile.display());
        Ok(())
    }

    /// Enable a site by creating a `sites-enabled` symlink.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the source config is missing, or
    /// [`Error::Io`] if the symlink cannot be created.
    pub fn enable_site(&self, domain: &str) -> Result<()> {
        let source = self.paths.nginx_site_path(domain);
        let link = self.paths.nginx_enabled_path(domain);

        if !source.exists() {
            return Err(Error::NotFound(format!(
                "site config not found: {}",
                source.display()
            )));
        }
        if link.exists() {
            std::fs::remove_file(&link)?;
        }
        if let Some(parent) = link.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::os::unix::fs::symlink(&source, &link)?;
        tracing::info!("config: enabled site {domain}");
        Ok(())
    }

    /// Disable a site by removing its `sites-enabled` symlink.
    ///
    /// No-op (returns `Ok`) if the symlink does not exist.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] if the symlink exists but cannot be removed.
    pub fn disable_site(&self, domain: &str) -> Result<()> {
        let link = self.paths.nginx_enabled_path(domain);
        if link.exists() {
            std::fs::remove_file(&link)?;
            tracing::info!("config: disabled site {domain}");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_sites_returns_empty_for_missing_dir() {
        let dir = assert_fs::TempDir::new().unwrap();
        let paths = ProxyPaths::with_root(dir.path());
        let mgr = ConfigManager::new(&paths);
        assert!(mgr.list_sites().unwrap().is_empty());
    }

    #[test]
    fn list_sites_finds_configs() {
        let dir = assert_fs::TempDir::new().unwrap();
        let paths = ProxyPaths::with_root(dir.path());
        let sites_dir = &paths.nginx_sites_available;
        std::fs::create_dir_all(sites_dir).unwrap();
        std::fs::write(sites_dir.join("b.com"), "config b").unwrap();
        std::fs::write(sites_dir.join("a.com"), "config a").unwrap();

        let mgr = ConfigManager::new(&paths);
        let sites = mgr.list_sites().unwrap();
        assert_eq!(sites, vec!["a.com", "b.com"]);
    }

    #[test]
    fn write_site_config_backs_up_and_writes() {
        let dir = assert_fs::TempDir::new().unwrap();
        let paths = ProxyPaths::with_root(dir.path());
        let mgr = ConfigManager::new(&paths);

        mgr.write_site_config("example.com", "server { listen 80; }")
            .unwrap();

        // File written.
        let written =
            std::fs::read_to_string(paths.nginx_site_path("example.com")).unwrap();
        assert!(written.contains("listen 80"));

        // Backup persisted to disk.
        let entries: Vec<_> = std::fs::read_dir(&paths.backup_dir).unwrap().collect();
        assert!(entries.iter().any(|e| {
            e.as_ref()
                .map(|e| e.file_name().to_string_lossy().starts_with("proxy-backup-"))
                .unwrap_or(false)
        }));
    }

    #[test]
    fn write_nginx_config_backs_up_and_writes() {
        let dir = assert_fs::TempDir::new().unwrap();
        let paths = ProxyPaths::with_root(dir.path());
        let mgr = ConfigManager::new(&paths);

        mgr.write_nginx_config("worker_processes auto;\n").unwrap();
        let written = std::fs::read_to_string(&paths.nginx_conf).unwrap();
        assert!(written.contains("worker_processes"));
        assert!(paths.backup_dir.is_dir());
    }

    #[test]
    fn enable_then_disable_site_roundtrip() {
        let dir = assert_fs::TempDir::new().unwrap();
        let paths = ProxyPaths::with_root(dir.path());
        let mgr = ConfigManager::new(&paths);

        mgr.write_site_config("example.com", "server { listen 80; }")
            .unwrap();
        mgr.enable_site("example.com").unwrap();
        assert!(paths.nginx_enabled_path("example.com").exists());

        mgr.disable_site("example.com").unwrap();
        assert!(!paths.nginx_enabled_path("example.com").exists());
    }

    #[test]
    fn enable_site_missing_source_errors() {
        let dir = assert_fs::TempDir::new().unwrap();
        let paths = ProxyPaths::with_root(dir.path());
        let mgr = ConfigManager::new(&paths);
        assert!(mgr.enable_site("nope.com").is_err());
    }
}
