//! Structured status reports and diagnostic findings for the updates subsystem.
//!
//! [`UpdateStatus`] captures the current state of automatic updates on the host.
//! Doctor findings use [`toride_diagnostic_types::Finding`] for consistency
//! across the toride diagnostic framework.

// ---------------------------------------------------------------------------
// UpdateStatus
// ---------------------------------------------------------------------------

/// Current status of automatic security updates on the host.
///
/// Populated by the [`parse`](crate::parse) module from command output, or
/// by the [`client`](crate::client) module from live queries.
#[derive(Debug, Clone)]
pub struct UpdateStatus {
    /// Whether automatic updates are enabled.
    pub auto_updates_enabled: bool,
    /// Timestamp of the last successful update run (ISO 8601), if available.
    pub last_run: Option<String>,
    /// Number of pending security updates.
    pub pending_security: usize,
    /// Whether the update service (unattended-upgrades / dnf-automatic) is active.
    pub service_active: bool,
}

impl UpdateStatus {
    /// Create an empty status with safe defaults.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            auto_updates_enabled: false,
            last_run: None,
            pending_security: 0,
            service_active: false,
        }
    }

    /// Returns `true` if automatic updates are enabled and the service is active.
    #[must_use]
    pub fn is_healthy(&self) -> bool {
        self.auto_updates_enabled && self.service_active
    }
}

impl Default for UpdateStatus {
    fn default() -> Self {
        Self::empty()
    }
}

impl std::fmt::Display for UpdateStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let enabled = if self.auto_updates_enabled {
            "enabled"
        } else {
            "disabled"
        };
        let active = if self.service_active {
            "active"
        } else {
            "inactive"
        };
        match &self.last_run {
            Some(last_run) => write!(
                f,
                "auto-updates {enabled} (service {active}); last run {last_run}; \
                 {sec} pending security update(s)",
                sec = self.pending_security,
            ),
            None => write!(
                f,
                "auto-updates {enabled} (service {active}); no recorded run; \
                 {sec} pending security update(s)",
                sec = self.pending_security,
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// DoctorFinding helpers
// ---------------------------------------------------------------------------

/// Create a finding for a missing binary.
///
/// Returns a [`toride_diagnostic_types::Finding`] indicating that a required
/// binary (e.g. `unattended-upgrades`) is not installed.
pub fn finding_binary_missing(binary: &str) -> toride_diagnostic_types::Finding {
    toride_diagnostic_types::Finding::critical(
        format!("binary.{binary}.missing"),
        format!("{binary} not found"),
    )
    .detail(format!(
        "The {binary} binary could not be located on $PATH. \
         Automatic updates require this tool to be installed."
    ))
    .fix_hint(format!("Install {binary}: apt install {binary}"))
}

/// Create a finding for an inactive service.
pub fn finding_service_inactive(service: &str) -> toride_diagnostic_types::Finding {
    toride_diagnostic_types::Finding::critical(
        format!("service.{service}.inactive"),
        format!("{service} service is not running"),
    )
    .detail(format!(
        "The {service} service is not active. Automatic updates will not be applied."
    ))
    .fix_hint(format!(
        "Start and enable the service: systemctl enable --now {service}"
    ))
}

/// Create a finding for disabled auto-updates.
pub fn finding_auto_updates_disabled() -> toride_diagnostic_types::Finding {
    toride_diagnostic_types::Finding::warning(
        "config.auto-updates.disabled",
        "Automatic updates are disabled",
    )
    .detail(
        "Auto-updates are currently disabled. Security patches will not be \
         applied automatically, leaving the system vulnerable.",
    )
    .fix_hint(
        "Enable auto-updates via toride configure or edit /etc/apt/apt.conf.d/20auto-upgrades",
    )
}

/// Create a finding for a missing schedule configuration.
pub fn finding_schedule_missing() -> toride_diagnostic_types::Finding {
    toride_diagnostic_types::Finding::warning(
        "config.schedule.missing",
        "No update schedule configured",
    )
    .detail("No systemd timer or cron job is configured to trigger automatic updates.")
    .fix_hint("Configure a schedule: toride updates schedule --daily")
}

/// Create a finding for a stale last-run timestamp.
pub fn finding_stale_last_run(last_run: &str) -> toride_diagnostic_types::Finding {
    toride_diagnostic_types::Finding::warning(
        "schedule.stale-last-run",
        "Last update run was too long ago",
    )
    .detail(format!(
        "The last recorded update run was at {last_run}, which is older than expected \
         given the configured schedule."
    ))
    .fix_hint("Check the update service status and logs for errors")
}

/// Create a finding for a world-writable config directory.
pub fn finding_config_dir_world_writable(path: &str) -> toride_diagnostic_types::Finding {
    toride_diagnostic_types::Finding::critical(
        "permission.config-dir-world-writable",
        "Config directory is world-writable",
    )
    .detail(format!(
        "The directory {path} has overly permissive permissions. \
         Any user on the system can modify automatic update configuration."
    ))
    .fix_hint("Restrict permissions: chmod 755 {path}")
}

// ---------------------------------------------------------------------------
// Auto-update timer findings (honest enabled / disabled / absent reporting)
// ---------------------------------------------------------------------------

/// Outcome of probing a single auto-update timer unit via systemd.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimerState {
    /// The timer is installed and active (running).
    Active,
    /// The timer is installed but neither enabled nor active.
    Disabled,
    /// The timer unit does not exist on this host.
    Absent,
}

/// Create an info finding indicating that no auto-update manager was detected
/// on the host (no supported package manager and/or no systemd).
pub fn finding_auto_update_manager_absent() -> toride_diagnostic_types::Finding {
    toride_diagnostic_types::Finding::info(
        "auto-update.manager-not-detected",
        "Auto-update manager not detected",
    )
    .detail(
        "Neither a supported package manager (apt/dnf) nor a systemd timer for \
         automatic updates was detected on this host. Toride cannot determine \
         whether security updates are being applied automatically.",
    )
    .fix_hint("Install unattended-upgrades (Debian/Ubuntu) or dnf-automatic (Fedora/RHEL)")
}

/// Create an OK finding reporting that an auto-update timer is active.
pub fn finding_auto_update_enabled(timer: &str) -> toride_diagnostic_types::Finding {
    toride_diagnostic_types::Finding::ok(
        "auto-update.timer-active",
        format!("Auto-update timer {timer} is active"),
    )
    .detail(format!(
        "The {timer} systemd timer is enabled and active. Automatic security \
         updates are being applied on schedule."
    ))
}

/// Create a warning finding reporting that auto-updates are disabled across all
/// detected mechanisms (config file and systemd timer).
pub fn finding_auto_update_disabled() -> toride_diagnostic_types::Finding {
    toride_diagnostic_types::Finding::warning(
        "auto-update.disabled",
        "Automatic updates are disabled",
    )
    .detail(
        "Auto-updates are not enabled: the timer is not active and the \
         configuration does not enable unattended upgrades. Security patches \
         will not be applied automatically, leaving the system vulnerable.",
    )
    .fix_hint("Enable the auto-update timer: systemctl enable --now <timer>")
}

/// Create an info finding reporting that the auto-update timer unit is absent
/// from systemd (not installed), but a config was found.
pub fn finding_auto_update_timer_absent(timer: &str) -> toride_diagnostic_types::Finding {
    toride_diagnostic_types::Finding::info(
        "auto-update.timer-absent",
        format!("Auto-update timer {timer} is not installed"),
    )
    .detail(format!(
        "The {timer} systemd timer unit does not exist on this host, so \
         systemd is not driving automatic updates. The configuration file may \
         still enable updates, but nothing will trigger them without a timer."
    ))
    .fix_hint(format!(
        "Install and enable the timer: systemctl enable --now {timer}"
    ))
}
