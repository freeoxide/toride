//! Package manager detection.
//!
//! Probes the system to determine which package manager is available, which
//! in turn selects the correct backend (APT or DNF) for update operations.

// ---------------------------------------------------------------------------
// PackageManager
// ---------------------------------------------------------------------------

/// The detected system package manager.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackageManager {
    /// APT (Debian, Ubuntu, and derivatives).
    Apt,
    /// DNF (Fedora, `RHEL`, `CentOS`, and derivatives).
    Dnf,
    /// Could not detect a supported package manager.
    Unknown,
}

impl std::fmt::Display for PackageManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Apt => write!(f, "apt"),
            Self::Dnf => write!(f, "dnf"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

// ---------------------------------------------------------------------------
// detect_package_manager
// ---------------------------------------------------------------------------

/// Detect the system's package manager by probing `$PATH`.
///
/// Checks for `apt-get` first (Debian/Ubuntu), then `dnf` (Fedora/RHEL).
/// Returns [`PackageManager::Unknown`] if neither is found.
///
/// # Errors
///
/// This function does not return errors, but may return
/// [`PackageManager::Unknown`] if no supported package manager is detected.
pub fn detect_package_manager() -> PackageManager {
    // Check for APT first (most common for VPS deployments).
    if which::which("apt-get").is_ok() {
        return PackageManager::Apt;
    }
    // Then check for DNF.
    if which::which("dnf").is_ok() {
        return PackageManager::Dnf;
    }
    PackageManager::Unknown
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_formats() {
        assert_eq!(PackageManager::Apt.to_string(), "apt");
        assert_eq!(PackageManager::Dnf.to_string(), "dnf");
        assert_eq!(PackageManager::Unknown.to_string(), "unknown");
    }
}
