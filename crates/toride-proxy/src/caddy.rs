//! Caddyfile management for Caddy reverse proxy.
//!
//! Provides high-level operations for managing Caddy configuration.

use crate::error::{Error, Result};
use crate::paths::ProxyPaths;
use crate::render::render_caddyfile;
use crate::spec::ProxySpec;
use toride_runner::{CommandSpec, Runner};

/// Caddy management facade.
///
/// Owns a command runner and proxy paths, providing convenience methods for
/// Caddy operations like config validation, reloading, and Caddyfile management.
pub struct CaddyManager<'a> {
    runner: &'a dyn Runner,
    paths: &'a ProxyPaths,
}

impl<'a> CaddyManager<'a> {
    /// Create a new Caddy manager.
    pub fn new(runner: &'a dyn Runner, paths: &'a ProxyPaths) -> Self {
        Self { runner, paths }
    }

    /// Validate the current Caddyfile (`caddy validate`).
    ///
    /// # Errors
    ///
    /// Returns [`Error::ConfigParse`] if the configuration is invalid.
    pub fn validate_config(&self) -> Result<()> {
        let spec = CommandSpec::new("caddy")
            .args(["validate", "--config"])
            .arg(self.paths.caddyfile.to_str().unwrap_or_default());

        let output = self.runner.run(&spec)?;
        if !output.success {
            return Err(Error::ConfigParse(output.stderr));
        }
        Ok(())
    }

    /// Reload Caddy configuration (`caddy reload`).
    ///
    /// # Errors
    ///
    /// Returns [`Error::CommandFailed`] if the reload fails.
    pub fn reload(&self) -> Result<()> {
        let spec = CommandSpec::new("caddy")
            .args(["reload", "--config"])
            .arg(self.paths.caddyfile.to_str().unwrap_or_default());

        let output = self.runner.run(&spec)?;
        if !output.success {
            return Err(Error::CommandFailed {
                program: "caddy".into(),
                code: output.exit_code,
                stderr: output.stderr,
            });
        }
        Ok(())
    }

    /// Format the Caddyfile (`caddy fmt`).
    ///
    /// # Errors
    ///
    /// Returns [`Error::CommandFailed`] if formatting fails.
    pub fn format_config(&self) -> Result<String> {
        let spec = CommandSpec::new("caddy")
            .args(["fmt"])
            .arg(self.paths.caddyfile.to_str().unwrap_or_default());

        let output = self.runner.run(&spec)?;
        if !output.success {
            return Err(Error::CommandFailed {
                program: "caddy".into(),
                code: output.exit_code,
                stderr: output.stderr,
            });
        }
        Ok(output.stdout)
    }

    /// Write a Caddyfile from a [`ProxySpec`].
    ///
    /// Renders the spec to Caddyfile format and writes it to disk. A
    /// pre-mutation backup of the existing Caddyfile (and nginx config) is
    /// created first via [`crate::backup::create_backup`] so the change can be
    /// rolled back. A backup failure is logged but non-fatal.
    ///
    /// # Errors
    ///
    /// Returns an error if validation or the write fails.
    pub fn write_caddyfile(&self, spec: &ProxySpec) -> Result<()> {
        spec.validate()?;

        let content = render_caddyfile(spec);

        if let Some(parent) = self.paths.caddyfile.parent() {
            std::fs::create_dir_all(parent)?;
        }

        // Pre-mutation backup (best-effort, same policy as NginxManager): build
        // an in-memory snapshot then persist it to backup_dir.
        match crate::backup::create_backup(self.paths) {
            Ok(snapshot) => {
                if let Err(e) = crate::backup::save_backup_to_disk(self.paths, &snapshot) {
                    tracing::warn!("caddy: persisting pre-write backup failed (continuing): {e}");
                }
            }
            Err(e) => {
                tracing::warn!("caddy: pre-write backup failed (continuing): {e}");
            }
        }

        toride_fs::atomic_write(&self.paths.caddyfile, &content)?;

        tracing::info!(
            "caddy: wrote Caddyfile to {}",
            self.paths.caddyfile.display()
        );

        Ok(())
    }

    /// Read the current Caddyfile content.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read.
    pub fn read_caddyfile(&self) -> Result<String> {
        std::fs::read_to_string(&self.paths.caddyfile).map_err(|e| {
            Error::NotFound(format!(
                "cannot read Caddyfile at {}: {e}",
                self.paths.caddyfile.display()
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spec::ServerBlock;

    #[test]
    fn write_and_read_caddyfile() {
        let dir = assert_fs::TempDir::new().unwrap();
        let paths = ProxyPaths::with_root(dir.path());
        let fake = toride_runner::fake::FakeRunner::new();

        let mgr = CaddyManager::new(&fake, &paths);

        let spec = ProxySpec::builder()
            .block(ServerBlock::new("example.com", 443, "127.0.0.1:3000"))
            .build();

        mgr.write_caddyfile(&spec).unwrap();

        let content = mgr.read_caddyfile().unwrap();
        assert!(content.contains("example.com"));
        assert!(content.contains("reverse_proxy 127.0.0.1:3000"));
    }
}
