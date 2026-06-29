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

    /// Borrow the underlying runner (used by the `cli` dispatch to drive the
    /// free `doctor::doctor` function and other runner-backed probes).
    #[cfg(feature = "cli")]
    pub(crate) fn runner(&self) -> &dyn Runner {
        self.runner.as_ref()
    }

    /// Borrow the configured paths (used by the `cli` dispatch for the
    /// `backup` / `restore` commands, which go through the free helpers in
    /// [`crate::backup`] rather than a client method).
    #[cfg(feature = "cli")]
    pub(crate) fn paths(&self) -> &HardenPaths {
        &self.paths
    }

    /// Apply a complete hardening profile.
    ///
    /// Creates a backup, applies all parameters from the profile, and
    /// returns a report of what was changed.
    pub fn apply_profile(&self, profile: &HardeningProfile) -> Result<HardenReport> {
        let params = profile.params();
        self.apply_params(&params)
    }

    /// Apply a complete hardening profile, honouring the caller's backup
    /// preference.
    ///
    /// When `skip_backup` is `true`, no pre-mutation snapshot is taken (this
    /// is the path the CLI `--no-backup` flag drives); otherwise the behaviour
    /// matches [`apply_profile`](Self::apply_profile).
    pub fn apply_profile_with_options(
        &self,
        profile: &HardeningProfile,
        skip_backup: bool,
    ) -> Result<HardenReport> {
        let params = profile.params();
        self.apply_params_with_options(&params, skip_backup)
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
        self.apply_params_with_options(params, false)
    }

    /// Apply a list of parameters and return a report, honouring the caller's
    /// backup preference.
    ///
    /// When `skip_backup` is `true`, the pre-mutation backup is skipped
    /// (the CLI `--no-backup` flag drives this); otherwise a backup is
    /// created and persisted exactly as in
    /// [`apply_params`](Self::apply_params).
    pub fn apply_params_with_options(
        &self,
        params: &[SysctlParam],
        skip_backup: bool,
    ) -> Result<HardenReport> {
        // Create backup before any changes, unless the caller opted out.
        if !skip_backup {
            let snapshot = create_backup(&self.paths)?;
            save_backup_to_disk(&self.paths, &snapshot)?;
        }

        let mut applied = Vec::new();
        let mut skipped = Vec::new();
        let mut failed = Vec::new();

        for param in params {
            match self.apply_param(param) {
                Ok(true) => applied.push(param.clone()),
                Ok(false) => skipped.push(param.clone()),
                Err(e) => {
                    // Continue applying the remaining parameters, but record
                    // the failure so it is surfaced in the report (previously
                    // it was only logged, making a partial apply look clean).
                    tracing::warn!("failed to apply {}: {e}", param.key);
                    failed.push((param.clone(), e.to_string()));
                }
            }
        }

        let current = sysctl::read_all(self.runner.as_ref()).unwrap_or_default();

        Ok(HardenReport {
            applied,
            skipped,
            failed,
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
            results.push((param, current));
        }

        Ok(results)
    }

    /// Compute a diff between current and desired state.
    ///
    /// Returns a unified diff string showing what would change.
    pub fn diff(&self, spec: &HardenSpec) -> Result<String> {
        let current = sysctl::read_all(self.runner.as_ref())?;
        let desired = spec.all_parameters();
        Ok(diff_sysctl(&current, &desired))
    }

    /// Check which parameters would change without applying them.
    pub fn check(&self, spec: &HardenSpec) -> Result<Vec<SysctlParam>> {
        let current = sysctl::read_all(self.runner.as_ref())?;
        let desired = spec.all_parameters();
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
