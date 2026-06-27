//! Nginx reverse proxy management.
//!
//! Provides high-level operations for managing Nginx configuration including
//! testing, reloading, and restarting the Nginx service.

use crate::error::{Error, Result};
use crate::nginx_headers::SecurityHeaders;
use crate::paths::ProxyPaths;
use crate::render::render_nginx_server_block_with_headers;
use crate::spec::ServerBlock;
use toride_runner::{CommandSpec, Runner};

/// Nginx management facade.
///
/// Owns a command runner and proxy paths, providing convenience methods for
/// Nginx operations like config testing, reloading, and site management.
pub struct NginxManager<'a> {
    runner: &'a dyn Runner,
    paths: &'a ProxyPaths,
}

impl<'a> NginxManager<'a> {
    /// Create a new Nginx manager.
    pub fn new(runner: &'a dyn Runner, paths: &'a ProxyPaths) -> Self {
        Self { runner, paths }
    }

    /// Test the current Nginx configuration (`nginx -t`).
    ///
    /// # Errors
    ///
    /// Returns [`Error::NginxSyntax`] if the configuration test fails.
    pub fn test_config(&self) -> Result<()> {
        let spec = CommandSpec::new("nginx").arg("-t");
        let output = self.runner.run(&spec)?;
        if !output.success {
            return Err(Error::NginxSyntax(output.stderr));
        }
        Ok(())
    }

    /// Reload Nginx configuration (`nginx -s reload`).
    ///
    /// # Errors
    ///
    /// Returns [`Error::CommandFailed`] if the reload fails.
    pub fn reload(&self) -> Result<()> {
        let spec = CommandSpec::new("nginx").args(["-s", "reload"]);
        let output = self.runner.run(&spec)?;
        if !output.success {
            return Err(Error::CommandFailed {
                program: "nginx".into(),
                code: output.exit_code,
                stderr: output.stderr,
            });
        }
        Ok(())
    }

    /// Restart the Nginx service via systemctl.
    ///
    /// # Errors
    ///
    /// Returns [`Error::CommandFailed`] if the restart fails.
    pub fn restart(&self) -> Result<()> {
        let spec = CommandSpec::new("systemctl").args(["restart", "nginx"]);
        let output = self.runner.run(&spec)?;
        if !output.success {
            return Err(Error::CommandFailed {
                program: "systemctl".into(),
                code: output.exit_code,
                stderr: output.stderr,
            });
        }
        Ok(())
    }

    /// Write a server block configuration for a domain.
    ///
    /// Renders the server block to Nginx config and writes it to
    /// `sites-available`. Optionally creates a symlink in `sites-enabled`.
    /// A pre-mutation backup of the existing config is created first via
    /// [`crate::backup::create_backup`] so the change can be rolled back.
    ///
    /// # Errors
    ///
    /// Returns an error if validation, backup, or the write fails.
    pub fn write_site(&self, block: &ServerBlock, enable: bool) -> Result<()> {
        self.write_site_with_headers(block, enable, None)
    }

    /// Write a server block configuration with optional security headers.
    ///
    /// Like [`write_site`](Self::write_site) but injects
    /// [`SecurityHeaders::to_nginx_directives`] into the rendered config when
    /// `headers` is `Some`. This is the apply path that actually emits the
    /// security headers rendered by [`crate::nginx_headers`].
    ///
    /// # Errors
    ///
    /// Returns an error if validation, backup, or the write fails.
    pub fn write_site_with_headers(
        &self,
        block: &ServerBlock,
        enable: bool,
        headers: Option<&SecurityHeaders>,
    ) -> Result<()> {
        block.validate()?;

        let config = render_nginx_server_block_with_headers(block, headers);
        let site_path = self.paths.nginx_site_path(&block.server_name);

        // Ensure the directory exists
        if let Some(parent) = site_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        // Create a pre-mutation backup before overwriting. The backup captures
        // the current sites-available directory (and nginx.conf / Caddyfile)
        // and persists it to `backup_dir` so the change can be rolled back. A
        // backup failure is non-fatal — we log and continue rather than
        // blocking a legitimate write, matching how operators expect "best
        // effort" snapshots to behave.
        match crate::backup::create_backup(self.paths) {
            Ok(snapshot) => {
                if let Err(e) = crate::backup::save_backup_to_disk(self.paths, &snapshot) {
                    tracing::warn!("nginx: persisting pre-write backup failed (continuing): {e}");
                }
            }
            Err(e) => {
                tracing::warn!("nginx: pre-write backup failed (continuing): {e}");
            }
        }

        toride_fs::atomic_write(&site_path, &config)?;

        if enable {
            self.enable_site(&block.server_name)?;
        }

        tracing::info!(
            "nginx: wrote site config for {} to {}",
            block.server_name,
            site_path.display()
        );

        Ok(())
    }

    /// Enable a site by creating a symlink in sites-enabled.
    ///
    /// # Errors
    ///
    /// Returns an error if the symlink cannot be created.
    pub fn enable_site(&self, domain: &str) -> Result<()> {
        let source = self.paths.nginx_site_path(domain);
        let link = self.paths.nginx_enabled_path(domain);

        if !source.exists() {
            return Err(Error::NotFound(format!(
                "site config not found: {}",
                source.display()
            )));
        }

        // Remove existing symlink if present
        if link.exists() {
            std::fs::remove_file(&link)?;
        }

        // Ensure sites-enabled directory exists
        if let Some(parent) = link.parent() {
            std::fs::create_dir_all(parent)?;
        }

        std::os::unix::fs::symlink(&source, &link)?;

        tracing::info!("nginx: enabled site {}", domain);
        Ok(())
    }

    /// Disable a site by removing the symlink from sites-enabled.
    ///
    /// # Errors
    ///
    /// Returns an error if the symlink cannot be removed.
    pub fn disable_site(&self, domain: &str) -> Result<()> {
        let link = self.paths.nginx_enabled_path(domain);

        if link.exists() {
            std::fs::remove_file(&link)?;
            tracing::info!("nginx: disabled site {}", domain);
        }

        Ok(())
    }

    /// Remove a site configuration file and its symlink.
    ///
    /// # Errors
    ///
    /// Returns an error if the files cannot be removed.
    pub fn remove_site(&self, domain: &str) -> Result<()> {
        self.disable_site(domain)?;

        let site_path = self.paths.nginx_site_path(domain);
        if site_path.exists() {
            std::fs::remove_file(&site_path)?;
            tracing::info!("nginx: removed site config for {}", domain);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_returns_error_on_failure() {
        let fake = toride_runner::fake::FakeRunner::new()
            .push_response(toride_runner::CommandOutput::from_stderr("syntax error", 1));

        let paths = ProxyPaths::default();
        let mgr = NginxManager::new(&fake, &paths);
        let result = mgr.test_config();
        assert!(result.is_err());
    }

    #[test]
    fn test_config_succeeds() {
        let fake = toride_runner::fake::FakeRunner::new()
            .push_response(toride_runner::CommandOutput::from_stdout("ok"));

        let paths = ProxyPaths::default();
        let mgr = NginxManager::new(&fake, &paths);
        assert!(mgr.test_config().is_ok());
    }

    #[test]
    fn write_site_with_headers_emits_security_directives() {
        let dir = assert_fs::TempDir::new().unwrap();
        let paths = ProxyPaths::with_root(dir.path());
        let fake = toride_runner::fake::FakeRunner::new();
        let mgr = NginxManager::new(&fake, &paths);

        let block = ServerBlock::new("example.com", 443, "127.0.0.1:3000");
        mgr.write_site_with_headers(&block, false, Some(&SecurityHeaders::strict()))
            .unwrap();

        let written = std::fs::read_to_string(paths.nginx_site_path("example.com")).unwrap();
        assert!(written.contains("Strict-Transport-Security"));
        assert!(written.contains("Content-Security-Policy"));
        assert!(written.contains("server_name example.com"));
    }

    #[test]
    fn write_site_creates_backup_before_overwriting() {
        let dir = assert_fs::TempDir::new().unwrap();
        let paths = ProxyPaths::with_root(dir.path());
        let sites_dir = &paths.nginx_sites_available;
        std::fs::create_dir_all(sites_dir).unwrap();
        // Seed an existing config so the backup has something to capture.
        std::fs::write(sites_dir.join("example.com"), "server { listen 80; }\n").unwrap();

        let backup_dir = &paths.backup_dir;
        assert!(!backup_dir.exists());

        let fake = toride_runner::fake::FakeRunner::new();
        let mgr = NginxManager::new(&fake, &paths);

        let block = ServerBlock::new("example.com", 443, "127.0.0.1:3000");
        mgr.write_site(&block, false).unwrap();

        // Backup directory must now exist and contain a snapshot file.
        assert!(backup_dir.is_dir());
        let entries: Vec<_> = std::fs::read_dir(backup_dir).unwrap().collect();
        assert!(
            entries.iter().any(|e| {
                e.as_ref()
                    .map(|e| e.file_name().to_string_lossy().starts_with("proxy-backup-"))
                    .unwrap_or(false)
            }),
            "expected a proxy-backup-*.txt snapshot in backup_dir"
        );

        // The site file was overwritten with the new config.
        let written = std::fs::read_to_string(sites_dir.join("example.com")).unwrap();
        assert!(written.contains("listen 443"));
    }
}
