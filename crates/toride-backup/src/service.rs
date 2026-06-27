//! Service management layer for backup scheduling.
//!
//! Manages systemd services and timers related to backup operations.
//! Delegates to the [`toride_service`] crate for systemd interactions when
//! available.

use crate::{Error, Result};

// ---------------------------------------------------------------------------
// BackupServiceManager
// ---------------------------------------------------------------------------

/// Manages the backup-related systemd services and timers.
///
/// Provides a typed interface for starting, stopping, enabling, and
/// querying the status of backup timer units.
pub struct BackupServiceManager {
    /// The systemd unit name prefix for backup timers.
    prefix: String,
}

impl BackupServiceManager {
    /// Create a manager with the default prefix `"toride-backup-"`.
    pub fn new() -> Self {
        Self {
            prefix: "toride-backup-".to_owned(),
        }
    }

    /// Create a manager with a custom unit name prefix.
    pub fn with_prefix(prefix: &str) -> Self {
        Self {
            prefix: prefix.to_owned(),
        }
    }

    /// Build the timer unit name for a backup job.
    pub fn timer_unit(&self, name: &str) -> String {
        format!("{}{}.timer", self.prefix, name)
    }

    /// Build the service unit name for a backup job.
    pub fn service_unit(&self, name: &str) -> String {
        format!("{}{}.service", self.prefix, name)
    }

    // -----------------------------------------------------------------------
    // Lifecycle operations
    // -----------------------------------------------------------------------

    /// Start the backup timer for the given job.
    ///
    /// # Errors
    ///
    /// Returns [`Error::CommandFailed`] if systemctl fails.
    pub fn start_timer(&self, name: &str) -> Result<()> {
        let unit = self.timer_unit(name);
        tracing::info!(unit = %unit, "starting backup timer");
        crate::systemd::start_unit(&unit)
    }

    /// Stop the backup timer for the given job.
    ///
    /// # Errors
    ///
    /// Returns [`Error::CommandFailed`] if systemctl fails.
    pub fn stop_timer(&self, name: &str) -> Result<()> {
        let unit = self.timer_unit(name);
        tracing::info!(unit = %unit, "stopping backup timer");
        crate::systemd::stop_unit(&unit)
    }

    /// Enable the backup timer to start at boot.
    ///
    /// # Errors
    ///
    /// Returns [`Error::CommandFailed`] if systemctl fails.
    pub fn enable_timer(&self, name: &str) -> Result<()> {
        let unit = self.timer_unit(name);
        tracing::info!(unit = %unit, "enabling backup timer");
        crate::systemd::enable_unit(&unit)
    }

    /// Check whether the backup timer is currently active.
    ///
    /// Performs a **real** probe: it first checks that systemd is the running
    /// init system on this host (via [`crate::systemd::detect`]); if systemd is
    /// absent it honestly reports `Ok(false)` (no command is invoked). When
    /// systemd is present it checks the job's timer unit via
    /// `systemctl is-active`, and additionally reports `true` if any
    /// backup-related timer unit on the host is active (so a restic/borg
    /// timer still surfaces as active).
    ///
    /// # Errors
    ///
    /// Returns [`Error::CommandFailed`] if systemctl fails.
    pub fn is_timer_active(&self, name: &str) -> Result<bool> {
        let unit = self.timer_unit(name);
        tracing::debug!(unit = %unit, "checking timer status");

        // Honest detection: on a systemd-absent host (e.g. macOS dev box) the
        // truthful answer is "not active" with no command invoked.
        let detected = crate::systemd::detect();
        if !detected.available {
            tracing::debug!(
                note = %detected.note,
                "systemd absent; reporting timer_active=false"
            );
            return Ok(false);
        }

        // systemd is present: probe this job's timer, then fall back to
        // "any backup timer active" for hosts using restic/borg timers.
        let probe = crate::systemd::probe_timer(&unit);
        if probe.active {
            return Ok(true);
        }
        Ok(crate::systemd::any_backup_timer_active())
    }
}

impl Default for BackupServiceManager {
    fn default() -> Self {
        Self::new()
    }
}
