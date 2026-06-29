//! Shared memory mount hardening.
//!
//! Provides functions to check and harden `/dev/shm` and other shared memory
//! mounts by ensuring they are mounted with `nosuid`, `nodev`, and `noexec`
//! options, as recommended by CIS benchmarks.

use crate::error::{Error, Result};
pub use crate::parse::MountInfo;
use crate::parse::parse_findmnt_output;
use toride_runner::{CommandSpec, Runner};

/// Expected mount options for `/dev/shm`.
const SHM_REQUIRED_OPTIONS: &[&str] = &["nosuid", "nodev", "noexec"];

/// Check shared memory mounts for security issues.
///
/// Returns a list of mount info entries for all `tmpfs` mounts that
/// appear to be shared memory mounts (`/dev/shm`, `/run/shm`, etc.).
///
/// # Errors
///
/// Returns [`Error::CommandFailed`] if `findmnt` exits non-zero.
pub fn check_shm_mounts(runner: &dyn Runner) -> Result<Vec<MountInfo>> {
    let spec = CommandSpec::new("findmnt")
        .arg("-l")
        .arg("-o")
        .arg("TARGET,SOURCE,FSTYPE,OPTIONS")
        .arg("-t")
        .arg("tmpfs");

    let output = runner.run_checked(&spec)?;
    let all_mounts = parse_findmnt_output(&output.stdout);

    // Filter to shm-like mounts
    let shm_mounts: Vec<MountInfo> = all_mounts
        .into_iter()
        .filter(|m| m.target == "/dev/shm" || m.target == "/run/shm" || m.target.contains("shm"))
        .collect();

    Ok(shm_mounts)
}

/// Check if a mount has all required security options.
///
/// Returns a list of missing security options.
pub fn missing_security_options(mount: &MountInfo) -> Vec<&'static str> {
    let opts: Vec<&str> = mount.options.split(',').collect();

    SHM_REQUIRED_OPTIONS
        .iter()
        .filter(|&&required| !opts.contains(&required))
        .copied()
        .collect()
}

/// Check if `/dev/shm` is properly hardened.
///
/// Returns `true` if the mount exists and has all required options,
/// `false` if it is missing options or not mounted as a separate mount.
pub fn is_shm_hardened(mounts: &[MountInfo]) -> bool {
    mounts
        .iter()
        .find(|m| m.target == "/dev/shm")
        .is_some_and(|m| missing_security_options(m).is_empty())
}

/// Harden shared memory mounts by remounting with security options.
///
/// This remounts `/dev/shm` with `nosuid,nodev,noexec` options.
/// Requires root privileges.
///
/// # Errors
///
/// Returns [`Error::MountFailed`] if the remount fails.
pub fn harden_shm(runner: &dyn Runner) -> Result<()> {
    tracing::info!("harden: remounting /dev/shm with nosuid,nodev,noexec");

    let spec = CommandSpec::new("mount")
        .arg("-o")
        .arg("remount,nosuid,nodev,noexec")
        .arg("/dev/shm");

    runner
        .run_checked(&spec)
        .map_err(|e| Error::MountFailed(format!("failed to remount /dev/shm: {e}")))?;

    tracing::info!("harden: /dev/shm remounted successfully");
    Ok(())
}

/// Generate an fstab entry for `/dev/shm` with hardening options.
///
/// Returns a line suitable for appending to `/etc/fstab`.
pub fn fstab_entry() -> String {
    "tmpfs\t/dev/shm\ttmpfs\tdefaults,nosuid,nodev,noexec\t0\t0".into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::MountInfo;

    #[test]
    fn missing_security_options_detects_missing() {
        let mount = MountInfo {
            target: "/dev/shm".into(),
            source: "tmpfs".into(),
            fstype: "tmpfs".into(),
            options: "rw,nosuid".into(),
        };
        let missing = missing_security_options(&mount);
        assert!(missing.contains(&"nodev"));
        assert!(missing.contains(&"noexec"));
        assert!(!missing.contains(&"nosuid"));
    }

    #[test]
    fn missing_security_options_empty_when_all_present() {
        let mount = MountInfo {
            target: "/dev/shm".into(),
            source: "tmpfs".into(),
            fstype: "tmpfs".into(),
            options: "rw,nosuid,nodev,noexec".into(),
        };
        assert!(missing_security_options(&mount).is_empty());
    }

    #[test]
    fn is_shm_hardened_true_when_secure() {
        let mounts = vec![MountInfo {
            target: "/dev/shm".into(),
            source: "tmpfs".into(),
            fstype: "tmpfs".into(),
            options: "rw,nosuid,nodev,noexec".into(),
        }];
        assert!(is_shm_hardened(&mounts));
    }

    #[test]
    fn is_shm_hardened_false_when_insecure() {
        let mounts = vec![MountInfo {
            target: "/dev/shm".into(),
            source: "tmpfs".into(),
            fstype: "tmpfs".into(),
            options: "rw".into(),
        }];
        assert!(!is_shm_hardened(&mounts));
    }

    #[test]
    fn is_shm_hardened_false_when_missing() {
        let mounts: Vec<MountInfo> = vec![];
        assert!(!is_shm_hardened(&mounts));
    }

    #[test]
    fn fstab_entry_format() {
        let entry = fstab_entry();
        assert!(entry.contains("nosuid"));
        assert!(entry.contains("nodev"));
        assert!(entry.contains("noexec"));
        assert!(entry.contains("/dev/shm"));
    }
}
