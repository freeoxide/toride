//! Proxy service management via systemd.
//!
//! Provides methods for managing the systemd service units for Nginx
//! and Caddy, issuing `systemctl` through the shared runner. Unit names
//! are hardcoded (`nginx`, `caddy`), so no name reaches argv from callers.

use crate::error::{Error, Result};
use toride_runner::{CommandSpec, Runner};

/// Service management for proxy backends.
///
/// Wraps systemctl operations specific to Nginx and Caddy service units.
pub struct ProxyServiceManager<'a> {
    runner: &'a dyn Runner,
}

impl<'a> ProxyServiceManager<'a> {
    /// Create a new proxy service manager.
    pub fn new(runner: &'a dyn Runner) -> Self {
        Self { runner }
    }

    /// Check if the Nginx service is active.
    ///
    /// # Errors
    ///
    /// Returns an error if the systemctl command fails.
    pub fn is_nginx_active(&self) -> Result<bool> {
        let spec = CommandSpec::new("systemctl").args(["is-active", "nginx"]);
        let output = self.runner.run(&spec)?;
        Ok(output.success)
    }

    /// Check if the Caddy service is active.
    ///
    /// # Errors
    ///
    /// Returns an error if the systemctl command fails.
    pub fn is_caddy_active(&self) -> Result<bool> {
        let spec = CommandSpec::new("systemctl").args(["is-active", "caddy"]);
        let output = self.runner.run(&spec)?;
        Ok(output.success)
    }

    /// Restart the Nginx service.
    ///
    /// # Errors
    ///
    /// Returns an error if the restart fails.
    pub fn restart_nginx(&self) -> Result<()> {
        let spec = CommandSpec::new("systemctl").args(["restart", "nginx"]);
        let output = self.runner.run(&spec)?;
        if !output.success {
            return Err(Error::CommandFailed {
                program: "systemctl".into(),
                code: output.exit_code,
                stderr: output.stderr,
            });
        }
        tracing::info!("service: restarted nginx");
        Ok(())
    }

    /// Restart the Caddy service.
    ///
    /// # Errors
    ///
    /// Returns an error if the restart fails.
    pub fn restart_caddy(&self) -> Result<()> {
        let spec = CommandSpec::new("systemctl").args(["restart", "caddy"]);
        let output = self.runner.run(&spec)?;
        if !output.success {
            return Err(Error::CommandFailed {
                program: "systemctl".into(),
                code: output.exit_code,
                stderr: output.stderr,
            });
        }
        tracing::info!("service: restarted caddy");
        Ok(())
    }

    /// Reload the Nginx service (graceful reload).
    ///
    /// # Errors
    ///
    /// Returns an error if the reload fails.
    pub fn reload_nginx(&self) -> Result<()> {
        let spec = CommandSpec::new("systemctl").args(["reload", "nginx"]);
        let output = self.runner.run(&spec)?;
        if !output.success {
            return Err(Error::CommandFailed {
                program: "systemctl".into(),
                code: output.exit_code,
                stderr: output.stderr,
            });
        }
        tracing::info!("service: reloaded nginx");
        Ok(())
    }

    /// Get the status of the Nginx service.
    ///
    /// # Errors
    ///
    /// Returns an error if the systemctl command fails.
    pub fn nginx_status(&self) -> Result<String> {
        let spec = CommandSpec::new("systemctl").args(["status", "nginx"]);
        let output = self.runner.run(&spec)?;
        Ok(output.stdout)
    }

    /// Get the status of the Caddy service.
    ///
    /// # Errors
    ///
    /// Returns an error if the systemctl command fails.
    pub fn caddy_status(&self) -> Result<String> {
        let spec = CommandSpec::new("systemctl").args(["status", "caddy"]);
        let output = self.runner.run(&spec)?;
        Ok(output.stdout)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_nginx_active_with_success() {
        let fake = toride_runner::fake::FakeRunner::new()
            .push_response(toride_runner::CommandOutput::from_stdout("active\n"));

        let mgr = ProxyServiceManager::new(&fake);
        assert!(mgr.is_nginx_active().unwrap());
    }

    #[test]
    fn is_nginx_active_when_stopped() {
        let fake = toride_runner::fake::FakeRunner::new()
            .push_response(toride_runner::CommandOutput::from_stderr("inactive", 3));

        let mgr = ProxyServiceManager::new(&fake);
        assert!(!mgr.is_nginx_active().unwrap());
    }
}
