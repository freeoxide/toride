//! High-level hardening client.
//!
//! [`HardenClient`] is the primary entry point for applying and inspecting
//! kernel hardening parameters. It wraps the lower-level modules behind
//! a convenient API.

use crate::backup::{create_backup, save_backup_to_disk};
use crate::diff::{changed_params, diff_sysctl};
use crate::error::Result;
use crate::paths::HardenPaths;
use crate::profile::HardeningProfile;
use crate::report::HardenReport;
use crate::shm;
use crate::spec::{HardenSpec, SysctlParam};
use crate::sysctl;
use toride_runner::Runner;

/// The primary client for system hardening operations.
///
/// Wraps a [`Runner`] and [`HardenPaths`] to provide a high-level API
/// for applying, inspecting, and diffing kernel security parameters.
///
/// # Example
///
/// ```rust,ignore
/// use toride_harden::HardenClient;
/// use toride_harden::profile::HardeningProfile;
///
/// let client = HardenClient::system()?;
/// let report = client.apply_profile(&HardeningProfile::Server)?;
/// println!("{}", report.to_summary());
/// ```
pub struct HardenClient {
    runner: Box<dyn Runner>,
    paths: HardenPaths,
}

impl HardenClient {
    /// Create a client using the default system paths and a duct runner.
    ///
    /// # Errors
    ///
    /// Returns an error if the `sysctl` binary cannot be found.
    pub fn system() -> Result<Self> {
        use toride_runner::DuctRunner;
        let runner = Box::new(DuctRunner);
        sysctl::find_sysctl(runner.as_ref())?;
        Ok(Self {
            runner,
            paths: HardenPaths::default(),
        })
    }

    /// Create a client with a custom runner (for testing).
    pub fn with_runner(runner: Box<dyn Runner>) -> Self {
        Self {
            runner,
            paths: HardenPaths::default(),
        }
    }

    /// Create a client with a custom runner and paths (for testing).
    pub fn with_runner_and_paths(runner: Box<dyn Runner>, paths: HardenPaths) -> Self {
        Self { runner, paths }
    }

    /// Apply a complete hardening profile.
    ///
    /// Creates a backup, applies all parameters from the profile, and
    /// returns a report of what was changed.
    pub fn apply_profile(&self, profile: &HardeningProfile) -> Result<HardenReport> {
        let params = profile.params();
        self.apply_params(&params)
    }

    /// Apply a single sysctl parameter.
    ///
    /// Returns `true` if the value was changed, `false` if it was
    /// already set.
    pub fn apply_param(&self, param: &SysctlParam) -> Result<bool> {
        sysctl::apply_if_needed(self.runner.as_ref(), &param.key, &param.value)
    }

    /// Apply a list of parameters and return a report.
    pub fn apply_params(&self, params: &[SysctlParam]) -> Result<HardenReport> {
        // Create backup before any changes
        let snapshot = create_backup(&self.paths)?;
        save_backup_to_disk(&self.paths, &snapshot)?;

        let mut applied = Vec::new();
        let mut skipped = Vec::new();

        for param in params {
            match self.apply_param(param) {
                Ok(true) => applied.push(param.clone()),
                Ok(false) => skipped.push(param.clone()),
                Err(e) => {
                    tracing::warn!("skipping {}: {e}", param.key);
                    // Continue applying other parameters
                }
            }
        }

        let current = sysctl::read_all(self.runner.as_ref()).unwrap_or_default();

        Ok(HardenReport {
            applied,
            skipped,
            current,
        })
    }

    /// Get the current status of all hardened parameters.
    ///
    /// Returns the current values of all parameters in the given spec.
    pub fn status(&self, spec: &HardenSpec) -> Result<Vec<(SysctlParam, String)>> {
        let mut results = Vec::new();

        for param in spec.all_parameters() {
            let current = sysctl::read_sysctl(self.runner.as_ref(), &param.key)
                .unwrap_or_else(|_| "<unreadable>".into());
            results.push((param.clone(), current));
        }

        Ok(results)
    }

    /// Compute a diff between current and desired state.
    ///
    /// Returns a unified diff string showing what would change.
    pub fn diff(&self, spec: &HardenSpec) -> Result<String> {
        let current = sysctl::read_all(self.runner.as_ref())?;
        let desired: Vec<SysctlParam> = spec.all_parameters().into_iter().cloned().collect();
        Ok(diff_sysctl(&current, &desired))
    }

    /// Check which parameters would change without applying them.
    pub fn check(&self, spec: &HardenSpec) -> Result<Vec<SysctlParam>> {
        let current = sysctl::read_all(self.runner.as_ref())?;
        let desired: Vec<SysctlParam> = spec.all_parameters().into_iter().cloned().collect();
        Ok(changed_params(&current, &desired)
            .into_iter()
            .cloned()
            .collect())
    }

    /// Check shared memory mounts and return their status.
    pub fn check_shm(&self) -> Result<Vec<shm::MountInfo>> {
        shm::check_shm_mounts(self.runner.as_ref())
    }

    /// Harden shared memory mounts.
    pub fn harden_shm(&self) -> Result<()> {
        shm::harden_shm(self.runner.as_ref())
    }
}
