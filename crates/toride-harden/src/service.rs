//! Service management for sysctl via systemd integration.
//!
//! Provides functions to reload sysctl settings through systemd,
//! check service status, and manage the systemd-sysctl service.

use crate::error::{Error, Result};
use toride_runner::{CommandSpec, Runner};

/// Reload sysctl settings from all configuration files.
///
/// Executes `sysctl --system` which reads `/etc/sysctl.conf`,
/// `/etc/sysctl.d/`, `/run/sysctl.d/`, and `/usr/lib/sysctl.d/`.
///
/// # Errors
///
/// Returns [`Error::CommandFailed`] if sysctl exits non-zero.
pub fn reload_sysctl(runner: &dyn Runner) -> Result<()> {
    let spec = CommandSpec::new("sysctl").arg("--system");
    runner
        .run_checked(&spec)
        .map_err(|e| Error::SysctlWrite(format!("sysctl --system failed: {e}")))?;
    tracing::info!("service: sysctl reloaded from all configuration files");
    Ok(())
}

/// Check if the systemd-sysctl service is active.
///
/// Uses `systemctl is-active systemd-sysctl` to check service status.
///
/// # Errors
///
/// Returns an error if systemctl cannot be executed.
pub fn is_sysctl_service_active(runner: &dyn Runner) -> Result<bool> {
    let spec = CommandSpec::new("systemctl")
        .arg("is-active")
        .arg("systemd-sysctl");
    match runner.run(&spec) {
        Ok(output) => Ok(output.success),
        Err(_) => Ok(false),
    }
}

/// Restart the systemd-sysctl service.
///
/// # Errors
///
/// Returns an error if the service cannot be restarted.
pub fn restart_sysctl_service(runner: &dyn Runner) -> Result<()> {
    let spec = CommandSpec::new("systemctl")
        .arg("restart")
        .arg("systemd-sysctl");
    runner
        .run_checked(&spec)
        .map_err(|e| Error::SysctlWrite(format!("cannot restart systemd-sysctl: {e}")))?;
    tracing::info!("service: systemd-sysctl restarted");
    Ok(())
}

/// Enable the systemd-sysctl service to start at boot.
///
/// # Errors
///
/// Returns an error if the service cannot be enabled.
pub fn enable_sysctl_service(runner: &dyn Runner) -> Result<()> {
    let spec = CommandSpec::new("systemctl")
        .arg("enable")
        .arg("systemd-sysctl");
    runner
        .run_checked(&spec)
        .map_err(|e| Error::SysctlWrite(format!("cannot enable systemd-sysctl: {e}")))?;
    tracing::info!("service: systemd-sysctl enabled at boot");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use toride_runner::CommandOutput;
    use toride_runner::fake::FakeRunner;

    #[test]
    fn reload_sysctl_success() {
        let runner = FakeRunner::new().push_response(CommandOutput::from_stdout(""));
        assert!(reload_sysctl(&runner).is_ok());
    }

    #[test]
    fn is_sysctl_service_active_returns_true() {
        let runner = FakeRunner::new().push_response(CommandOutput::from_stdout("active\n"));
        assert!(is_sysctl_service_active(&runner).unwrap());
    }

    #[test]
    fn is_sysctl_service_active_returns_false() {
        let runner = FakeRunner::new().push_response(CommandOutput::from_stderr("inactive", 3));
        assert!(!is_sysctl_service_active(&runner).unwrap());
    }
}
