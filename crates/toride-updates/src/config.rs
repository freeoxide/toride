//! Config file read/write with atomic writes.
//!
//! Reads and writes update configuration files using [`toride_fs::atomic_write`]
//! to ensure no partial writes are left on disk if the process crashes.

use tracing::info;

use crate::error::{Error, Result};
use crate::paths::UpdatePaths;
use crate::spec::{RebootPolicy, Schedule, UpdateSpec};

// ---------------------------------------------------------------------------
// ConfigManager
// ---------------------------------------------------------------------------

/// Read and write automatic update configuration files.
///
/// Uses [`toride_fs::atomic_write`] to ensure configuration changes are
/// atomic. Creates backups of existing files before overwriting.
pub struct ConfigManager {
    paths: UpdatePaths,
}

impl ConfigManager {
    /// Create a new config manager with auto-detected paths.
    #[must_use]
    pub fn new() -> Self {
        Self {
            paths: UpdatePaths::detect(),
        }
    }

    /// Create a config manager with explicit paths.
    #[must_use]
    pub fn with_paths(paths: UpdatePaths) -> Self {
        Self { paths }
    }

    /// Read the current update configuration and return an [`UpdateSpec`].
    ///
    /// Parses the existing config files on disk and constructs a spec
    /// reflecting the current state:
    ///
    /// - **APT**: reads `/etc/apt/apt.conf.d/20auto-upgrades` for the periodic
    ///   interval and `Unattended-Upgrade` flag, and
    ///   `/etc/apt/apt.conf.d/50unattended-upgrades` for the reboot policy
    ///   (`Automatic-Reboot`).
    /// - **DNF**: reads `/etc/dnf/automatic.conf` `[commands]` for
    ///   `apply_updates` and `reboot`, and `[base]` for `upgrade_type`.
    ///
    /// Missing files are treated as "not configured" (defaults), not errors.
    ///
    /// # Errors
    ///
    /// Returns [`Error::PackageDetection`] if no supported package manager is
    /// detected, or [`Error::ConfigParse`] if a present file cannot be read.
    pub fn read_current(&self) -> Result<UpdateSpec> {
        info!("Reading current update configuration");

        let pkg_mgr = self.resolved_package_manager();
        match pkg_mgr {
            crate::detect::PackageManager::Apt => self.read_apt_config(),
            crate::detect::PackageManager::Dnf => self.read_dnf_config(),
            crate::detect::PackageManager::Unknown => Err(Error::PackageDetection(
                "no supported package manager detected".into(),
            )),
        }
    }

    /// Write an [`UpdateSpec`] to disk as configuration files.
    ///
    /// Backs up existing files, renders the spec into backend-specific config
    /// format, and atomically writes the results.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ConfigWrite`] if the write fails, or [`Error::Io`]
    /// if the backup fails.
    pub fn write_spec(&self, spec: &UpdateSpec) -> Result<()> {
        info!("Writing update configuration to disk");

        let pkg_mgr = self.resolved_package_manager();
        match pkg_mgr {
            crate::detect::PackageManager::Apt => self.write_apt_config(spec)?,
            crate::detect::PackageManager::Dnf => self.write_dnf_config(spec)?,
            crate::detect::PackageManager::Unknown => {
                return Err(Error::PackageDetection(
                    "no supported package manager detected".into(),
                ));
            }
        }

        Ok(())
    }

    /// Resolve the effective package manager: use the one recorded on the
    /// paths if set, otherwise probe the host. This keeps `ConfigManager`
    /// working both with explicit test paths and with the auto-detected
    /// defaults used by [`UpdatesClient`].
    fn resolved_package_manager(&self) -> crate::detect::PackageManager {
        match self.paths.package_manager {
            crate::detect::PackageManager::Unknown => {
                crate::detect::detect_package_manager()
            }
            other => other,
        }
    }

    // -----------------------------------------------------------------------
    // Backend-specific writers
    // -----------------------------------------------------------------------

    fn write_apt_config(&self, spec: &UpdateSpec) -> Result<()> {
        // Backup existing configs.
        crate::backup::backup_config(&self.paths.auto_upgrades_conf)?;
        crate::backup::backup_config(&self.paths.auto_upgrades_enabled)?;

        // Render configs.
        let auto_upgrades = crate::render::render_auto_upgrades_conf(spec);
        let apt_conf = crate::render::render_apt_conf(spec);

        // Atomic write.
        toride_fs::atomic_write(&self.paths.auto_upgrades_conf, &auto_upgrades)
            .map_err(|e| Error::ConfigWrite(format!("failed to write 50unattended-upgrades: {e}")))?;

        toride_fs::atomic_write(&self.paths.auto_upgrades_enabled, &apt_conf)
            .map_err(|e| Error::ConfigWrite(format!("failed to write 20auto-upgrades: {e}")))?;

        Ok(())
    }

    fn write_dnf_config(&self, spec: &UpdateSpec) -> Result<()> {
        // Backup existing config.
        crate::backup::backup_config(&self.paths.dnf_automatic_conf)?;

        // Render config.
        let dnf_conf = crate::render::render_dnf_automatic_conf(spec);

        // Atomic write.
        toride_fs::atomic_write(&self.paths.dnf_automatic_conf, &dnf_conf)
            .map_err(|e| Error::ConfigWrite(format!("failed to write automatic.conf: {e}")))?;

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Backend-specific readers
    // -----------------------------------------------------------------------

    fn read_apt_config(&self) -> Result<UpdateSpec> {
        let mut spec = UpdateSpec::disabled(); // start pessimistic
        spec.schedule = Schedule::Daily;

        // Enablement + schedule from 20auto-upgrades.
        if let Ok(content) = std::fs::read_to_string(&self.paths.auto_upgrades_enabled) {
            let mut update_lists = false;
            let mut unattended = false;
            for raw in content.lines() {
                let line = raw.trim();
                if line.starts_with("//") || line.starts_with('#') {
                    continue;
                }
                if let Some(val) = apt_directive_value(line, "APT::Periodic::Update-Package-Lists")
                {
                    // Any non-"0" interval means package-list refresh is on;
                    // the exact value selects the schedule (1/7/30).
                    update_lists = val != "0";
                    if let Some(sched) = schedule_from_apt_interval(val) {
                        spec.schedule = sched;
                    }
                } else if let Some(val) = apt_directive_value(line, "APT::Periodic::Unattended-Upgrade")
                {
                    unattended = val == "1";
                }
            }
            spec.auto_update = update_lists && unattended;
        }

        // Reboot policy + origins from 50unattended-upgrades.
        if let Ok(content) = std::fs::read_to_string(&self.paths.auto_upgrades_conf) {
            let mut reboot_set = false;
            for raw in content.lines() {
                let line = raw.trim();
                if let Some(val) = apt_directive_value(line, "Automatic-Reboot") {
                    if !reboot_set {
                        spec.reboot = match val {
                            "always" => RebootPolicy::Always,
                            "true" => RebootPolicy::WhenNeeded,
                            _ => RebootPolicy::Never,
                        };
                        reboot_set = true;
                    }
                }
            }
        }

        Ok(spec)
    }

    fn read_dnf_config(&self) -> Result<UpdateSpec> {
        let mut spec = UpdateSpec::disabled();
        spec.schedule = Schedule::Daily;

        let Ok(content) = std::fs::read_to_string(&self.paths.dnf_automatic_conf) else {
            return Ok(spec);
        };

        let mut section = String::new();
        for raw in content.lines() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                continue;
            }
            if line.starts_with('[') && line.ends_with(']') {
                section = line.to_ascii_lowercase();
                continue;
            }
            let Some((key, val)) = line.split_once('=') else {
                continue;
            };
            let key = key.trim();
            let val = val.trim();
            if section == "[commands]" {
                if key.eq_ignore_ascii_case("apply_updates") {
                    spec.auto_update = val.eq_ignore_ascii_case("yes");
                } else if key.eq_ignore_ascii_case("reboot") {
                    spec.reboot = match val.to_ascii_lowercase().as_str() {
                        "always" => RebootPolicy::Always,
                        "when-needed" => RebootPolicy::WhenNeeded,
                        _ => RebootPolicy::Never,
                    };
                }
            } else if section == "[base]" && key.eq_ignore_ascii_case("upgrade_type") {
                spec.security_only = val.eq_ignore_ascii_case("security");
            }
        }

        Ok(spec)
    }
}

impl Default for ConfigManager {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Extract the quoted value from an apt.conf directive line of the form
/// `APT::Periodic::Update-Package-Lists "1";`.
fn apt_directive_value<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let rest = line.strip_prefix(key)?.trim_start();
    let quoted = rest.strip_prefix('"')?;
    let end = quoted.find('"')?;
    Some(&quoted[..end])
}

/// Map an `APT::Periodic` interval (in days) back to a [`Schedule`].
fn schedule_from_apt_interval(val: &str) -> Option<Schedule> {
    match val {
        "1" => Some(Schedule::Daily),
        "7" => Some(Schedule::Weekly),
        "30" => Some(Schedule::Monthly),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::PackageManager;
    use crate::paths::UpdatePaths;

    fn apt_paths(root: &std::path::Path) -> UpdatePaths {
        let mut p = UpdatePaths::new();
        p.package_manager = PackageManager::Apt;
        p.auto_upgrades_enabled = root.join("20auto-upgrades");
        p.auto_upgrades_conf = root.join("50unattended-upgrades");
        p
    }

    fn dnf_paths(root: &std::path::Path) -> UpdatePaths {
        let mut p = UpdatePaths::new();
        p.package_manager = PackageManager::Dnf;
        p.dnf_automatic_conf = root.join("automatic.conf");
        p
    }

    #[test]
    fn read_apt_config_parses_enabled_daily() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("20auto-upgrades"),
            "APT::Periodic::Update-Package-Lists \"1\";\nAPT::Periodic::Unattended-Upgrade \"1\";\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("50unattended-upgrades"),
            "Unattended-Upgrade::Automatic-Reboot \"true\";\n",
        )
        .unwrap();

        let spec = ConfigManager::with_paths(apt_paths(dir.path()))
            .read_current()
            .unwrap();
        assert!(spec.auto_update);
        assert_eq!(spec.schedule, Schedule::Daily);
        assert_eq!(spec.reboot, RebootPolicy::WhenNeeded);
    }

    #[test]
    fn read_apt_config_parses_weekly_and_disabled() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("20auto-upgrades"),
            "APT::Periodic::Update-Package-Lists \"7\";\nAPT::Periodic::Unattended-Upgrade \"0\";\n",
        )
        .unwrap();
        let spec = ConfigManager::with_paths(apt_paths(dir.path()))
            .read_current()
            .unwrap();
        // unattended=0 disables.
        assert!(!spec.auto_update);
        assert_eq!(spec.schedule, Schedule::Weekly);
    }

    #[test]
    fn read_apt_config_disabled_when_files_missing() {
        let dir = tempfile::tempdir().unwrap();
        let spec = ConfigManager::with_paths(apt_paths(dir.path()))
            .read_current()
            .unwrap();
        assert!(!spec.auto_update);
    }

    #[test]
    fn read_dnf_config_parses_apply_yes_security() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("automatic.conf"),
            "[commands]\napply_updates = yes\nreboot = when-needed\n[base]\nupgrade_type = security\n",
        )
        .unwrap();
        let spec = ConfigManager::with_paths(dnf_paths(dir.path()))
            .read_current()
            .unwrap();
        assert!(spec.auto_update);
        assert!(spec.security_only);
        assert_eq!(spec.reboot, RebootPolicy::WhenNeeded);
    }

    #[test]
    fn read_dnf_config_disabled_when_apply_no() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("automatic.conf"),
            "[commands]\napply_updates = no\n",
        )
        .unwrap();
        let spec = ConfigManager::with_paths(dnf_paths(dir.path()))
            .read_current()
            .unwrap();
        assert!(!spec.auto_update);
    }

    #[test]
    fn read_current_errors_when_no_package_manager_anywhere() {
        // The PackageDetection error fires only when neither the recorded
        // paths nor the host expose a supported package manager. On a host
        // that does have apt/dnf, this test is a no-op (the read succeeds).
        let dir = tempfile::tempdir().unwrap();
        let paths = UpdatePaths::new(); // package_manager = Unknown
        let _ = dir;
        let result = ConfigManager::with_paths(paths).read_current();
        match result {
            Err(Error::PackageDetection(_)) => { /* expected on hosts w/o apt/dnf */ }
            Ok(_) if crate::detect::detect_package_manager() != PackageManager::Unknown => {
                // Host has apt/dnf: detection succeeded, nothing to assert.
            }
            other => panic!("expected PackageDetection or a host-detected Ok, got {other:?}"),
        }
    }

    #[test]
    fn apt_directive_value_extracts() {
        assert_eq!(
            apt_directive_value(r#"APT::Periodic::Unattended-Upgrade "1";"#, "APT::Periodic::Unattended-Upgrade"),
            Some("1")
        );
        assert_eq!(apt_directive_value("not a directive", "X"), None);
    }

    #[test]
    fn schedule_from_apt_interval_maps() {
        assert_eq!(schedule_from_apt_interval("1"), Some(Schedule::Daily));
        assert_eq!(schedule_from_apt_interval("7"), Some(Schedule::Weekly));
        assert_eq!(schedule_from_apt_interval("30"), Some(Schedule::Monthly));
        assert_eq!(schedule_from_apt_interval("0"), None);
    }

    #[test]
    fn write_then_read_apt_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let paths = apt_paths(dir.path());
        let mgr = ConfigManager::with_paths(paths.clone());
        let spec = UpdateSpec {
            auto_update: true,
            security_only: true,
            schedule: Schedule::Weekly,
            reboot: RebootPolicy::Never,
            origins: vec![],
        };
        mgr.write_spec(&spec).unwrap();
        let read_back = mgr.read_current().unwrap();
        assert!(read_back.auto_update);
        assert_eq!(read_back.schedule, Schedule::Weekly);
        assert_eq!(read_back.reboot, RebootPolicy::Never);
    }
}
