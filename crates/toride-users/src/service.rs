//! Service management for user-related system daemons.
//!
//! Provides functions to check and manage the status of services that are
//! related to user authentication and access control (e.g. `sshd`).
//!
//! Standard systemctl operations (`is-active`, `restart`) are delegated to
//! [`toride_service::ServiceManager`]. Custom operations that are not covered
//! by the shared crate (e.g. `reload`) use [`toride_runner::CommandSpec`]
//! directly.

use crate::{Error, Result};

// ---------------------------------------------------------------------------
// Free functions -- thin wrappers around toride_service
// ---------------------------------------------------------------------------

/// Check if a systemd service is active.
///
/// Delegates to [`toride_service::ServiceManager::is_active`].
///
/// # Errors
///
/// - [`Error::Other`] if `systemctl` cannot be executed.
pub fn is_service_active(service: &str) -> Result<bool> {
    let mgr = new_manager()?;
    mgr.is_active(service).map_err(|e| Error::Other(e.to_string()))
}

/// Restart a systemd service.
///
/// Delegates to [`toride_service::ServiceManager::restart`].
///
/// # Errors
///
/// - [`Error::Other`] if `systemctl` returns a non-zero exit code.
pub fn restart_service(service: &str) -> Result<()> {
    let mgr = new_manager()?;
    mgr.restart(service).map_err(|e| Error::Other(e.to_string()))?;
    tracing::info!("restarted service {service}");
    Ok(())
}

/// Reload a systemd service (send SIGHUP).
///
/// Executes `systemctl reload <service>` via [`toride_runner::CommandSpec`].
/// This operation is not provided by `toride-service`, so it is implemented
/// locally using the shared runner infrastructure.
///
/// # Errors
///
/// - [`Error::Other`] if `systemctl` returns a non-zero exit code.
pub fn reload_service(service: &str) -> Result<()> {
    use toride_runner::{CommandSpec, Runner};

    let runner = toride_runner::DuctRunner;
    let spec = CommandSpec::new("systemctl").arg("reload").arg(service);
    let output = runner.run(&spec).map_err(|e| Error::Other(e.to_string()))?;

    if output.success {
        tracing::info!("reloaded service {service}");
        Ok(())
    } else {
        let stderr = output.stderr.trim();
        let detail = if stderr.is_empty() {
            format!("systemctl reload {service} failed")
        } else {
            format!("systemctl reload {service} failed: {stderr}")
        };
        Err(Error::Other(detail))
    }
}

/// Ensure `sshd` is running after PAM or authentication changes.
///
/// Checks if `sshd` is active, and if so, reloads it to pick up
/// configuration changes.
///
/// # Errors
///
/// Returns any error from service status checks or reload operations.
pub fn reload_sshd_if_active() -> Result<()> {
    if is_service_active("sshd")? {
        reload_service("sshd")?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// ServiceManager -- local facade extending the shared manager
// ---------------------------------------------------------------------------

/// Service manager handle for user-related services.
///
/// Wraps [`toride_service::ServiceManager`] for standard systemctl operations
/// and adds a `reload` method via [`toride_runner::CommandSpec`].
pub struct ServiceManager {
    inner: toride_service::ServiceManager,
    runner: toride_runner::DuctRunner,
}

impl ServiceManager {
    /// Create a new service manager.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying `toride_service::ServiceManager`
    /// cannot be constructed.
    pub fn new() -> Result<Self> {
        let inner = new_manager()?;
        Ok(Self {
            inner,
            runner: toride_runner::DuctRunner,
        })
    }

    /// Check if a service is active.
    pub fn is_active(&self, service: &str) -> Result<bool> {
        self.inner
            .is_active(service)
            .map_err(|e| Error::Other(e.to_string()))
    }

    /// Restart a service.
    pub fn restart(&self, service: &str) -> Result<()> {
        self.inner
            .restart(service)
            .map_err(|e| Error::Other(e.to_string()))
    }

    /// Reload a service (send SIGHUP).
    ///
    /// Uses [`toride_runner::CommandSpec`] directly since `reload` is not
    /// exposed by [`toride_service::ServiceManager`].
    pub fn reload(&self, service: &str) -> Result<()> {
        use toride_runner::Runner;

        let spec = toride_runner::CommandSpec::new("systemctl")
            .arg("reload")
            .arg(service);
        let output = self
            .runner
            .run(&spec)
            .map_err(|e| Error::Other(e.to_string()))?;

        if output.success {
            tracing::info!("reloaded service {service}");
            Ok(())
        } else {
            let stderr = output.stderr.trim();
            let detail = if stderr.is_empty() {
                format!("systemctl reload {service} failed")
            } else {
                format!("systemctl reload {service} failed: {stderr}")
            };
            Err(Error::Other(detail))
        }
    }
}

impl Default for ServiceManager {
    fn default() -> Self {
        Self::new().expect("failed to create ServiceManager")
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a `toride_service::ServiceManager` backed by a `DuctRunner`.
fn new_manager() -> Result<toride_service::ServiceManager> {
    let runner = Box::new(toride_runner::DuctRunner);
    Ok(toride_service::ServiceManager::new(runner))
}
