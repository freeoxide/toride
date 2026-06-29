//! Proxy configuration file management.
//!
//! Provides reading, writing, and validation of proxy configuration files
//! with support for both Nginx and Caddy formats. Every write path creates a
//! pre-mutation backup via [`crate::backup`] before overwriting so changes can
//! be rolled back.

use crate::backup;
use crate::error::{Error, Result};
use crate::nginx_config::{ParsedServerBlock, parse_server_blocks};
use crate::paths::ProxyPaths;
use crate::validate::validate_site_domain;

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
                let name = path
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string();
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
                let name = path
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string();
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
        // Explicit 0o644 so the resulting config is world-readable (Nginx
        // workers need read access) regardless of the process umask, rather
        // than inheriting the 0o600 default of `atomic_write`.
        toride_fs::atomic_write_with_perms(&site_path, content, 0o644)
            .map_err(|e| Error::ConfigWrite(format!("write site config: {e}")))?;
        tracing::info!(
            "config: wrote site config for {domain} to {}",
            site_path.display()
        );
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
        // nginx.conf is daemon-readable config; write it 0o644 rather than the
        // 0o600 atomic_write default, for parity with write_site_config.
        toride_fs::atomic_write_with_perms(&self.paths.nginx_conf, content, 0o644)
            .map_err(|e| Error::ConfigWrite(format!("write nginx.conf: {e}")))?;
        tracing::info!(
            "config: wrote nginx.conf to {}",
            self.paths.nginx_conf.display()
        );
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
        // Caddy commonly drops privileges to a non-owner user, so the Caddyfile
        // must stay daemon-readable: write it 0o644, not the 0o600 default.
        toride_fs::atomic_write_with_perms(&self.paths.caddyfile, content, 0o644)
            .map_err(|e| Error::ConfigWrite(format!("write Caddyfile: {e}")))?;
        tracing::info!(
            "config: wrote Caddyfile to {}",
            self.paths.caddyfile.display()
        );
        Ok(())
    }

    /// Enable a site by creating a `sites-enabled` symlink.
    ///
    /// `domain` is validated as a single, safe path segment before it is joined
    /// onto the sites directory, so traversal-shaped inputs (`..`, absolute
    /// paths, nested segments) cannot target arbitrary files. The symlink is
    /// created atomically (temp name + `rename`) to close the TOCTOU window
    /// that a plain `symlink`-after-`remove_file` sequence leaves between the
    /// two calls.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Validation`] if `domain` is not a safe segment,
    /// [`Error::NotFound`] if the source config is missing, or [`Error::Io`]
    /// if the symlink cannot be created.
    pub fn enable_site(&self, domain: &str) -> Result<()> {
        validate_site_domain(domain)?;

        let source = self.paths.nginx_site_path(domain);
        let link = self.paths.nginx_enabled_path(domain);

        if !source.exists() {
            return Err(Error::NotFound(format!(
                "site config not found: {}",
                source.display()
            )));
        }
        if let Some(parent) = link.parent() {
            std::fs::create_dir_all(parent)?;
        }

        // Create the symlink at a unique temp name, then atomically rename it
        // into place. This removes the TOCTOU window of the previous
        // `remove_file` + `symlink` pair: the rename is atomic, so an observer
        // never sees sites-enabled without the link. Using the target's
        // directory with a distinctive suffix keeps the temp name on the same
        // filesystem as the final rename (a requirement for atomic rename).
        let link_parent = link.parent().unwrap_or(std::path::Path::new("."));
        let tmp_link = link_parent.join(format!(
            ".{}.toride-tmp",
            link.file_name()
                .map(|f| f.to_string_lossy().into_owned())
                .unwrap_or_else(|| domain.to_string())
        ));
        // Clean up any stale temp link from a previous crashed attempt, then
        // ignore the (likely) not-found error.
        let _ = std::fs::remove_file(&tmp_link);

        std::os::unix::fs::symlink(&source, &tmp_link)?;
        // Atomic publish. Overwrites an existing link on Unix.
        std::fs::rename(&tmp_link, &link).map_err(|e| {
            // Best-effort cleanup of the temp link if the rename failed, so we
            // don't leave an orphaned symlink behind.
            let _ = std::fs::remove_file(&tmp_link);
            e
        })?;

        tracing::info!("config: enabled site {domain}");
        Ok(())
    }

    /// Disable a site by removing its `sites-enabled` symlink.
    ///
    /// `domain` is validated as a single, safe path segment before joining onto
    /// the sites directory, so traversal-shaped inputs cannot delete arbitrary
    /// files via the `remove_file` call. No-op (returns `Ok`) if the symlink
    /// does not exist.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Validation`] if `domain` is not a safe segment, or
    /// [`Error::Io`] if the symlink exists but cannot be removed.
    pub fn disable_site(&self, domain: &str) -> Result<()> {
        validate_site_domain(domain)?;

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
        let written = std::fs::read_to_string(paths.nginx_site_path("example.com")).unwrap();
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

    #[test]
    fn enable_site_rejects_traversal_domains() {
        let dir = assert_fs::TempDir::new().unwrap();
        let paths = ProxyPaths::with_root(dir.path());
        let mgr = ConfigManager::new(&paths);

        // Seed a sibling file outside sites-enabled that a traversal-shaped
        // domain would otherwise let an attacker delete/replace.
        let guard = dir.path().join("guard-file");
        std::fs::write(&guard, "must not be touched").unwrap();

        for bad in ["..", "../guard-file", "/etc/passwd", "a/b", "foo\\bar"] {
            let err = mgr.enable_site(bad).unwrap_err();
            assert!(
                matches!(err, Error::Validation(_)),
                "expected Error::Validation for {bad:?}, got {err:?}"
            );
        }
        assert!(
            guard.exists(),
            "guard file must not be touched by traversal"
        );
    }

    #[test]
    fn disable_site_rejects_traversal_domains() {
        let dir = assert_fs::TempDir::new().unwrap();
        let paths = ProxyPaths::with_root(dir.path());
        let mgr = ConfigManager::new(&paths);

        let guard = dir.path().join("guard-file");
        std::fs::write(&guard, "must not be deleted").unwrap();

        for bad in ["..", "../guard-file", "/etc/passwd", "a/b"] {
            let err = mgr.disable_site(bad).unwrap_err();
            assert!(
                matches!(err, Error::Validation(_)),
                "expected Error::Validation for {bad:?}, got {err:?}"
            );
        }
        assert!(
            guard.exists(),
            "guard file must not be deleted by traversal"
        );
    }

    #[test]
    fn enable_site_is_atomic_and_overwrites_existing() {
        let dir = assert_fs::TempDir::new().unwrap();
        let paths = ProxyPaths::with_root(dir.path());
        let mgr = ConfigManager::new(&paths);

        mgr.write_site_config("example.com", "server { listen 80; }")
            .unwrap();
        mgr.enable_site("example.com").unwrap();
        let link = paths.nginx_enabled_path("example.com");
        assert!(link.exists());

        // Re-enabling must replace the existing link atomically, not error.
        mgr.enable_site("example.com").unwrap();
        assert!(link.exists());

        // No leftover temp links remain in sites-enabled.
        let leftovers: Vec<_> = std::fs::read_dir(&paths.nginx_sites_enabled)
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().contains(".toride-tmp"))
            .collect();
        assert!(leftovers.is_empty(), "temp link leaked: {leftovers:?}");
    }
}
