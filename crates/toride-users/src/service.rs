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
    let mgr = new_manager();
    mgr.is_active(service)
        .map_err(|e| Error::Other(e.to_string()))
}

/// Restart a systemd service.
///
/// Delegates to [`toride_service::ServiceManager::restart`].
///
/// # Errors
///
/// - [`Error::Other`] if `systemctl` returns a non-zero exit code.
pub fn restart_service(service: &str) -> Result<()> {
    let mgr = new_manager();
    mgr.restart(service)
        .map_err(|e| Error::Other(e.to_string()))?;
    tracing::info!("restarted service {service}");
    Ok(())
}

/// Reload a systemd service (send SIGHUP).
///
/// Executes `systemctl reload -- <service>` via [`toride_runner::CommandSpec`],
/// validating the name first so a leading `-` cannot become a systemctl flag.
/// This operation is not provided by `toride-service`, so it is implemented
/// locally using the shared runner infrastructure.
///
/// # Errors
///
/// - [`Error::Other`] if the name is rejected by validation or `systemctl`
///   returns a non-zero exit code.
pub fn reload_service(service: &str) -> Result<()> {
    use toride_runner::Runner;

    let runner = toride_runner::DuctRunner;
    let spec = reload_spec(service)?;
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

/// Validate a service name before handing it to `systemctl`, mirroring the
/// guard `toride-service` applies to its own verbs.
///
/// # Errors
///
/// Returns [`Error::Other`] for empty names, a leading `-` (flag injection),
/// path separators, and embedded NUL bytes.
fn validate_service_name(service: &str) -> Result<()> {
    if service.is_empty() {
        return Err(Error::Other("service name must not be empty".to_owned()));
    }
    if service.starts_with('-') {
        return Err(Error::Other(format!(
            "service name must not start with '-': {service:?}"
        )));
    }
    if service.contains('/') {
        return Err(Error::Other(format!(
            "service name must not contain a path separator: {service:?}"
        )));
    }
    if service.contains('\0') {
        return Err(Error::Other(format!(
            "service name must not contain a NUL byte: {service:?}"
        )));
    }
    Ok(())
}

/// Build the `systemctl reload -- <service>` spec after validating the name.
fn reload_spec(service: &str) -> Result<toride_runner::CommandSpec> {
    validate_service_name(service)?;
    Ok(toride_runner::CommandSpec::new("systemctl").args(["reload", "--", service]))
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
        let inner = new_manager();
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
    /// Uses [`reload_spec`] (validated name, `--`-terminated argv) since
    /// `reload` is not exposed by [`toride_service::ServiceManager`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::Other`] on a rejected name or a non-zero exit.
    pub fn reload(&self, service: &str) -> Result<()> {
        use toride_runner::Runner;

        let spec = reload_spec(service)?;
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
fn new_manager() -> toride_service::ServiceManager {
    let runner = Box::new(toride_runner::DuctRunner);
    toride_service::ServiceManager::new(runner)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reload_rejects_flag_shaped_and_invalid_names() {
        for name in ["-x", "", "../etc/passwd", "ss\0hd"] {
            let err = reload_service(name)
                .err()
                .unwrap_or_else(|| panic!("name {name:?} must be rejected"));
            assert!(
                matches!(err, Error::Other(_)),
                "expected a validation error for {name:?}, got {err:?}"
            );
        }
    }

    #[test]
    fn reload_spec_terminates_options_with_double_dash() {
        let spec = reload_spec("sshd").expect("valid name");
        assert_eq!(spec.program, "systemctl");
        assert_eq!(
            spec.args,
            vec!["reload".to_owned(), "--".to_owned(), "sshd".to_owned()]
        );
    }
}
