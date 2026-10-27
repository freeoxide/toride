//! High-level hardening client.
//!
//! [`HardenClient`] is the primary entry point for applying and inspecting
//! kernel hardening parameters. It wraps the lower-level modules behind
//! a convenient API.

use crate::backup::{create_backup_with_runtime, save_backup_to_disk};
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
    /// [`apply_params`](Self::apply_params). The snapshot records both the
    /// config files and the pre-apply runtime values of the affected keys,
    /// so a later restore also rolls the runtime values back.
    pub fn apply_params_with_options(
        &self,
        params: &[SysctlParam],
        skip_backup: bool,
    ) -> Result<HardenReport> {
        // Seed the current values with one `sysctl -a` read; per-key reads
        // remain only as the fallback for keys the aggregate output lacks.
        let current_values = sysctl::read_all_map(self.runner.as_ref());

        // Create backup before any changes, unless the caller opted out.
        if !skip_backup {
            let keys: Vec<String> = params.iter().map(|p| p.key.clone()).collect();
            let snapshot = create_backup_with_runtime(self.runner.as_ref(), &self.paths, &keys)?;
            save_backup_to_disk(&self.paths, &snapshot)?;
        }

        let mut applied = Vec::new();
        let mut skipped = Vec::new();
        let mut failed = Vec::new();

        for param in params {
            let outcome = match current_values.get(param.key.as_str()) {
                Some(current) if current.as_str() == param.value => Ok(false),
                _ => sysctl::write_sysctl(self.runner.as_ref(), &param.key, &param.value)
                    .map(|()| true),
            };
            match outcome {
                Ok(true) => applied.push(param.clone()),
                Ok(false) => skipped.push(param.clone()),
                Err(e) => {
                    // Keep applying the remaining parameters; the failure is
                    // surfaced in the report rather than aborting the apply.
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
    /// Returns the current values of all parameters in the given spec. All
    /// values come from one `sysctl -a` spawn; keys missing from that
    /// output fall back to a single per-key read.
    pub fn status(&self, spec: &HardenSpec) -> Result<Vec<(SysctlParam, String)>> {
        let params = spec.all_parameters();
        let current_values = sysctl::read_all_map(self.runner.as_ref());

        let mut results = Vec::with_capacity(params.len());
        for param in params {
            let current = match current_values.get(param.key.as_str()) {
                Some(value) => value.clone(),
                None => sysctl::read_sysctl(self.runner.as_ref(), &param.key)
                    .unwrap_or_else(|_| "<unreadable>".into()),
            };
            results.push((param, current));
        }

        Ok(results)
    }

    /// Compute a diff between current and desired state.
    ///
    /// Returns a unified diff string showing what would change. The current
    /// side is filtered to the desired keys first, mirroring
    /// [`check`](Self::check), so unrelated kernel tunables are not
    /// rendered as removed.
    pub fn diff(&self, spec: &HardenSpec) -> Result<String> {
        let all = sysctl::read_all(self.runner.as_ref())?;
        let desired = spec.all_parameters();
        let desired_keys: std::collections::HashSet<&str> =
            desired.iter().map(|p| p.key.as_str()).collect();
        let current: Vec<(String, String)> = all
            .into_iter()
            .filter(|(key, _)| desired_keys.contains(key.as_str()))
            .collect();
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spec::SysctlParam;
    use toride_runner::fake::FakeRunner;

    fn read_all_runner(output: &str) -> FakeRunner {
        FakeRunner::new().push_response(toride_runner::CommandOutput::from_stdout(output))
    }

    #[test]
    fn diff_filters_current_side_to_desired_keys() {
        // Regression: the full `sysctl -a` output rendered as the old side
        // marked every unrelated tunable as removed.
        let runner = read_all_runner(
            "kernel.kptr_restrict = 0\nvm.swappiness = 60\nnet.core.somaxconn = 4096\n",
        );
        let client = HardenClient::with_runner(Box::new(runner));
        let spec = HardenSpec::builder()
            .params(vec![SysctlParam::new(
                "kernel.kptr_restrict",
                "1",
                "Restrict kptr",
            )])
            .build();

        let diff = client.diff(&spec).unwrap();
        assert!(
            diff.contains("-kernel.kptr_restrict = 0"),
            "the changed desired key must appear: {diff}"
        );
        assert!(
            !diff.contains("vm.swappiness"),
            "unrelated keys must not be rendered as removed: {diff}"
        );
        assert!(
            !diff.contains("net.core.somaxconn"),
            "unrelated keys must not be rendered as removed: {diff}"
        );
    }

    #[test]
    fn status_reads_all_params_with_one_sysctl_spawn() {
        let all = "kernel.kptr_restrict = 1\nkernel.dmesg_restrict = 1\nnet.ipv4.ip_forward = 0\n";
        let runner = read_all_runner(all);
        let client = HardenClient::with_runner(Box::new(runner.clone()));
        let spec = HardenSpec::builder()
            .params(vec![
                SysctlParam::new("kernel.kptr_restrict", "1", ""),
                SysctlParam::new("kernel.dmesg_restrict", "1", ""),
                SysctlParam::new("net.ipv4.ip_forward", "0", ""),
            ])
            .build();

        let rows = client.status(&spec).unwrap();
        assert_eq!(rows.len(), 3);
        assert!(rows.iter().all(|(_, value)| value != "<unreadable>"));

        let spawns = runner
            .calls()
            .iter()
            .filter(|spec| spec.program == "sysctl")
            .count();
        assert_eq!(
            spawns, 1,
            "status must cover every parameter with one `sysctl -a` spawn"
        );
    }

    #[test]
    fn status_falls_back_per_key_when_read_all_lacks_a_key() {
        let runner = FakeRunner::new()
            .push_response(toride_runner::CommandOutput::from_stdout(
                "kernel.kptr_restrict = 1\n",
            ))
            .push_response(toride_runner::CommandOutput::from_stdout("0\n"));
        let client = HardenClient::with_runner(Box::new(runner));
        let spec = HardenSpec::builder()
            .params(vec![
                SysctlParam::new("kernel.kptr_restrict", "1", ""),
                SysctlParam::new("net.ipv4.ip_forward", "0", ""),
            ])
            .build();

        let rows = client.status(&spec).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[1].1, "0");
    }

    #[test]
    fn apply_params_seeds_current_values_from_one_read() {
        // Every param is already at its desired value, so apply performs the
        // single `sysctl -a` read and no `sysctl -w` writes.
        let all = "kernel.kptr_restrict = 1\nkernel.dmesg_restrict = 1\n";
        let runner = read_all_runner(all);
        let client = HardenClient::with_runner(Box::new(runner.clone()));

        let report = client
            .apply_params_with_options(
                &[
                    SysctlParam::new("kernel.kptr_restrict", "1", ""),
                    SysctlParam::new("kernel.dmesg_restrict", "1", ""),
                ],
                true,
            )
            .unwrap();
        assert_eq!(report.applied.len(), 0);
        assert_eq!(report.skipped.len(), 2);

        let writes = runner
            .calls()
            .iter()
            .any(|spec| spec.program == "sysctl" && spec.args.contains(&"-w".to_string()));
        assert!(!writes, "no write is needed when values already match");
    }
}
