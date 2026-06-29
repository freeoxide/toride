//! Mise capabilities detection based on version milestones.
//!
//! [`MiseCapabilities`] describes which CLI features and flags are available in
//! the installed mise binary. Capabilities are determined by parsing the output
//! of `mise --version` and comparing against known release milestones.
//!
//! # Example
//!
//! ```rust,ignore
//! use toride_mise::Mise;
//!
//! let mise = Mise::builder().build()?;
//! let caps = mise.check_capabilities().await?;
//! if caps.json_ls {
//!     // safe to use `mise ls --json`
//! }
//! ```

use crate::binary::MiseVersion;
use crate::error::MiseResult;

// ---------------------------------------------------------------------------
// MiseCapabilities
// ---------------------------------------------------------------------------

/// Feature flags describing which mise CLI capabilities are available.
///
/// Constructed via [`MiseCapabilities::from_version`] or
/// [`MiseCapabilities::unknown`]. Each field corresponds to a CLI flag or
/// subcommand whose availability depends on the installed mise version.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MiseCapabilities {
    /// `mise ls --json` is available.
    pub json_ls: bool,
    /// `mise env --json` is available.
    pub json_env: bool,
    /// `mise doctor --json` is available.
    pub json_doctor: bool,
    /// `mise tool --json` is available.
    pub json_tool: bool,
    /// `mise bin-paths --json` is available.
    pub json_bin_paths: bool,
    /// `mise settings --json` returns extended fields.
    pub json_settings_extended: bool,
    /// `mise tasks ls --json` is available.
    pub json_tasks_ls: bool,
    /// `mise tasks info --json` is available.
    pub json_tasks_info: bool,
    /// `mise tasks validate --json` is available.
    pub json_tasks_validate: bool,
    /// `mise --dry-run` reports an exit code reliably.
    pub dry_run_code: bool,
    /// Registry-based security scanning is available.
    pub registry_security: bool,
    /// `mise lock` / `--locked` lockfile support is available.
    pub lockfile: bool,
    /// `--sandbox-exec` or equivalent sandboxing is available.
    pub sandbox_exec: bool,
}

impl MiseCapabilities {
    /// Build capabilities from a parsed [`MiseVersion`].
    ///
    /// Compares the version against known mise release milestones. If the
    /// version cannot be parsed as a valid semver, all capabilities are set
    /// to `false` (conservative fallback).
    ///
    /// # Milestones (approximate)
    ///
    /// | Version | Capabilities enabled |
    /// |---------|---------------------|
    /// | 2024.1.0 | `json_ls`, `json_env` |
    /// | 2024.3.0 | `json_doctor`, `json_tool`, `json_bin_paths` |
    /// | 2024.7.0 | `json_settings_extended`, `json_tasks_ls` |
    /// | 2024.10.0 | `json_tasks_info`, `json_tasks_validate`, `dry_run_code` |
    /// | 2024.12.0 | `registry_security`, `lockfile` |
    /// | 2025.1.0 | `sandbox_exec` |
    pub fn from_version(v: &MiseVersion) -> Self {
        use semver::Version;

        let v2024_1 = Version::parse("2024.1.0").unwrap();
        let v2024_3 = Version::parse("2024.3.0").unwrap();
        let v2024_7 = Version::parse("2024.7.0").unwrap();
        let v2024_10 = Version::parse("2024.10.0").unwrap();
        let v2024_12 = Version::parse("2024.12.0").unwrap();
        let v2025_1 = Version::parse("2025.1.0").unwrap();

        Self {
            json_ls: v.is_at_least(&v2024_1),
            json_env: v.is_at_least(&v2024_1),
            json_doctor: v.is_at_least(&v2024_3),
            json_tool: v.is_at_least(&v2024_3),
            json_bin_paths: v.is_at_least(&v2024_3),
            json_settings_extended: v.is_at_least(&v2024_7),
            json_tasks_ls: v.is_at_least(&v2024_7),
            json_tasks_info: v.is_at_least(&v2024_10),
            json_tasks_validate: v.is_at_least(&v2024_10),
            dry_run_code: v.is_at_least(&v2024_10),
            registry_security: v.is_at_least(&v2024_12),
            lockfile: v.is_at_least(&v2024_12),
            sandbox_exec: v.is_at_least(&v2025_1),
        }
    }

    /// Return a capabilities set with all flags set to `false`.
    ///
    /// Useful as a safe default when the mise version is unknown or the binary
    /// cannot be queried.
    #[must_use]
    pub fn unknown() -> Self {
        Self {
            json_ls: false,
            json_env: false,
            json_doctor: false,
            json_tool: false,
            json_bin_paths: false,
            json_settings_extended: false,
            json_tasks_ls: false,
            json_tasks_info: false,
            json_tasks_validate: false,
            dry_run_code: false,
            registry_security: false,
            lockfile: false,
            sandbox_exec: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Mise client extensions
// ---------------------------------------------------------------------------

use crate::client::Mise;

impl Mise {
    /// Query the installed mise version.
    ///
    /// Runs `mise --version`, parses the output, and returns a
    /// [`MiseVersion`].
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`](crate::MiseError::CommandFailed)
    /// if the command exits non-zero.
    pub async fn version(&self) -> MiseResult<MiseVersion> {
        let output = self.run_checked(["--version"]).await?;
        Ok(MiseVersion::parse(output.stdout_trimmed()))
    }

    /// Detect which capabilities the installed mise binary supports.
    ///
    /// Runs `mise --version` to determine the version, then builds a
    /// [`MiseCapabilities`] from the result.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`](crate::MiseError::CommandFailed)
    /// if the command exits non-zero.
    pub async fn check_capabilities(&self) -> MiseResult<MiseCapabilities> {
        let version = self.version().await?;
        Ok(MiseCapabilities::from_version(&version))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_disables_everything() {
        let caps = MiseCapabilities::unknown();
        assert!(!caps.json_ls);
        assert!(!caps.json_env);
        assert!(!caps.json_doctor);
        assert!(!caps.json_tool);
        assert!(!caps.json_bin_paths);
        assert!(!caps.json_settings_extended);
        assert!(!caps.json_tasks_ls);
        assert!(!caps.json_tasks_info);
        assert!(!caps.json_tasks_validate);
        assert!(!caps.dry_run_code);
        assert!(!caps.registry_security);
        assert!(!caps.lockfile);
        assert!(!caps.sandbox_exec);
    }

    #[test]
    fn from_version_early_release() {
        let v = MiseVersion::parse("2024.1.0");
        let caps = MiseCapabilities::from_version(&v);
        assert!(caps.json_ls);
        assert!(caps.json_env);
        assert!(!caps.json_doctor);
        assert!(!caps.lockfile);
        assert!(!caps.sandbox_exec);
    }

    #[test]
    fn from_version_mid_release() {
        let v = MiseVersion::parse("2024.8.0");
        let caps = MiseCapabilities::from_version(&v);
        assert!(caps.json_ls);
        assert!(caps.json_doctor);
        assert!(caps.json_settings_extended);
        assert!(!caps.json_tasks_info);
    }

    #[test]
    fn from_version_latest() {
        let v = MiseVersion::parse("2025.2.0");
        let caps = MiseCapabilities::from_version(&v);
        assert!(caps.json_ls);
        assert!(caps.lockfile);
        assert!(caps.sandbox_exec);
    }

    #[test]
    fn from_version_unparseable_is_conservative() {
        let v = MiseVersion::parse("unknown-format");
        let caps = MiseCapabilities::from_version(&v);
        // is_at_least returns false for unparseable versions, so everything
        // stays off.
        assert!(!caps.json_ls);
    }
}
