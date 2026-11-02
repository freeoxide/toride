//! Nginx reverse proxy management.
//!
//! Provides high-level operations for managing Nginx configuration including
//! testing, reloading, and restarting the Nginx service.

use crate::error::{Error, Result};
use crate::nginx_headers::SecurityHeaders;
use crate::paths::ProxyPaths;
use crate::render::render_nginx_server_block_with_headers;
use crate::spec::ServerBlock;
use crate::validate::validate_site_domain;
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
    /// A pre-mutation backup of the existing site file is created first via
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

        if let Some(parent) = site_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        // Best-effort pre-mutation backup of exactly the file being
        // overwritten; a failure logs and continues rather than blocking the
        // write.
        match crate::backup::create_backup(&site_path) {
            Ok(snapshot) => {
                if let Err(e) = crate::backup::save_backup_to_disk(self.paths, &snapshot) {
                    tracing::warn!("nginx: persisting pre-write backup failed (continuing): {e}");
                }
            }
            Err(e) => {
                tracing::warn!("nginx: pre-write backup failed (continuing): {e}");
            }
        }

        // Site configs are read by nginx (and symlinked into sites-enabled);
        // write them 0o644, the daemon-readable convention, rather than the
        // 0o600 atomic_write default, matching ProxyConfig::write_site_config.
        toride_fs::atomic_write_with_perms(&site_path, &config, 0o644)?;

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
    /// Delegates to the shared hardened implementation in
    /// [`crate::site_links`]: it validates `domain` as a safe path segment
    /// and publishes the symlink via temp-name plus atomic rename, so
    /// re-enabling over a dangling link cannot fail EEXIST and no observer
    /// sees `sites-enabled` without the link.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Validation`] if `domain` is not a safe segment, or an
    /// error if the symlink cannot be created.
    pub fn enable_site(&self, domain: &str) -> Result<()> {
        crate::site_links::enable_site(self.paths, domain)
    }

    /// Disable a site by removing the symlink from sites-enabled.
    ///
    /// Delegates to [`crate::site_links::disable_site`], which detects the
    /// link via `symlink_metadata` so a dangling link (one whose target
    /// disappeared) is still removed.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Validation`] if `domain` is not a safe segment, or an
    /// error if the symlink cannot be removed.
    pub fn disable_site(&self, domain: &str) -> Result<()> {
        crate::site_links::disable_site(self.paths, domain)
    }

    /// Remove a site configuration file and its symlink.
    ///
    /// `domain` is validated as a single, safe path segment before joining onto
    /// the sites directory: defense-in-depth on this delete primitive, so a
    /// traversal-shaped input cannot target an arbitrary file via the
    /// `remove_file` call on `site_path`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Validation`] if `domain` is not a safe segment, or an
    /// error if the files cannot be removed.
    pub fn remove_site(&self, domain: &str) -> Result<()> {
        validate_site_domain(domain)?;

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

    #[cfg(unix)]
    #[test]
    fn enable_site_replaces_a_dangling_symlink_and_disable_removes_it() {
        let dir = assert_fs::TempDir::new().unwrap();
        let paths = ProxyPaths::with_root(dir.path());
        let fake = toride_runner::fake::FakeRunner::new();
        let mgr = NginxManager::new(&fake, &paths);

        std::fs::create_dir_all(&paths.nginx_sites_available).unwrap();
        std::fs::create_dir_all(&paths.nginx_sites_enabled).unwrap();
        std::fs::write(paths.nginx_site_path("example.com"), "server {}\n").unwrap();
        // A dangling link: `Path::exists()` follows it and reports false, so
        // the old remove-then-symlink sequence failed EEXIST here.
        std::os::unix::fs::symlink(
            dir.path().join("gone.conf"),
            paths.nginx_enabled_path("example.com"),
        )
        .unwrap();

        mgr.enable_site("example.com")
            .expect("re-enabling over a dangling link must replace it");
        assert_eq!(
            std::fs::read_link(paths.nginx_enabled_path("example.com")).unwrap(),
            paths.nginx_site_path("example.com")
        );

        // Re-point the link at a vanished target and disable: symlink_metadata
        // must still see and remove the dangling link.
        std::fs::remove_file(paths.nginx_enabled_path("example.com")).unwrap();
        std::os::unix::fs::symlink(
            dir.path().join("vanished.conf"),
            paths.nginx_enabled_path("example.com"),
        )
        .unwrap();
        mgr.disable_site("example.com")
            .expect("a dangling link must still be disabled");
        assert!(
            paths
                .nginx_enabled_path("example.com")
                .symlink_metadata()
                .is_err(),
            "the dangling link must be gone"
        );
    }

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

        // Backup directory must now exist and contain a snapshot named after
        // the mutated site file.
        assert!(backup_dir.is_dir());
        let entries: Vec<_> = std::fs::read_dir(backup_dir).unwrap().collect();
        assert!(
            entries.iter().any(|e| {
                e.as_ref()
                    .is_ok_and(|e| e.file_name().to_string_lossy().starts_with("example.com."))
            }),
            "expected an example.com.*.bak snapshot in backup_dir"
        );

        // The site file was overwritten with the new config.
        let written = std::fs::read_to_string(sites_dir.join("example.com")).unwrap();
        assert!(written.contains("listen 443"));
    }

    #[test]
    fn enable_disable_remove_reject_traversal_domains() {
        let dir = assert_fs::TempDir::new().unwrap();
        let paths = ProxyPaths::with_root(dir.path());
        let fake = toride_runner::fake::FakeRunner::new();
        let mgr = NginxManager::new(&fake, &paths);

        // A guard file outside sites-enabled that traversal would otherwise
        // let an attacker create/replace/delete.
        let guard = dir.path().join("guard-file");
        std::fs::write(&guard, "must not be touched").unwrap();

        for bad in ["..", "../guard-file", "/etc/passwd", "a/b", "foo\\bar"] {
            assert!(
                matches!(mgr.enable_site(bad).unwrap_err(), Error::Validation(_)),
                "enable_site must reject {bad:?}"
            );
            assert!(
                matches!(mgr.disable_site(bad).unwrap_err(), Error::Validation(_)),
                "disable_site must reject {bad:?}"
            );
            assert!(
                matches!(mgr.remove_site(bad).unwrap_err(), Error::Validation(_)),
                "remove_site must reject {bad:?}"
            );
        }
        assert!(
            guard.exists(),
            "guard file must not be touched by traversal"
        );
    }

    #[test]
    fn enable_disable_remove_accept_valid_domain() {
        let dir = assert_fs::TempDir::new().unwrap();
        let paths = ProxyPaths::with_root(dir.path());
        let fake = toride_runner::fake::FakeRunner::new();
        let mgr = NginxManager::new(&fake, &paths);

        // Seed a site config so enable_site has a source to point at.
        std::fs::create_dir_all(&paths.nginx_sites_available).unwrap();
        std::fs::write(
            paths.nginx_site_path("example.com"),
            "server { listen 80; }",
        )
        .unwrap();

        // Valid domains pass the gate and exercise the real primitives.
        assert!(mgr.enable_site("example.com").is_ok());
        assert!(paths.nginx_enabled_path("example.com").exists());

        assert!(mgr.disable_site("example.com").is_ok());
        assert!(!paths.nginx_enabled_path("example.com").exists());

        assert!(mgr.remove_site("example.com").is_ok());
        assert!(!paths.nginx_site_path("example.com").exists());
    }
}
