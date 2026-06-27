//! Strongly typed models for hardening specifications.
//!
//! [`HardenSpec`] describes the desired state of kernel parameters,
//! and [`SysctlParam`] represents a single key-value pair with metadata.

use crate::error::Result;
use crate::profile::HardeningProfile;
use crate::validate::validate_spec;

/// A single sysctl parameter with metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SysctlParam {
    /// Sysctl key, e.g. `kernel.kptr_restrict`.
    pub key: String,
    /// Desired value, e.g. `1`.
    pub value: String,
    /// Human-readable description of what this parameter does.
    pub description: String,
}

impl SysctlParam {
    /// Create a new sysctl parameter.
    pub fn new(
        key: impl Into<String>,
        value: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        Self {
            key: key.into(),
            value: value.into(),
            description: description.into(),
        }
    }
}

impl std::fmt::Display for SysctlParam {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} = {}", self.key, self.value)
    }
}

/// A complete hardening specification.
///
/// Describes the desired state of kernel security parameters. The spec
/// can either list explicit parameters, reference a built-in profile,
/// or combine both.
///
/// # Example
///
/// ```rust
/// use toride_harden::spec::{HardenSpec, SysctlParam};
///
/// let spec = HardenSpec::builder()
///     .param(SysctlParam::new("kernel.kptr_restrict", "1", "Restrict kernel pointer exposure"))
///     .build();
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct HardenSpec {
    /// Explicitly listed parameters.
    pub parameters: Vec<SysctlParam>,
    /// Optional hardening profile for parameter expansion.
    pub profile: Option<HardeningProfile>,
}

impl HardenSpec {
    /// Start building a new spec.
    pub fn builder() -> HardenSpecBuilder {
        HardenSpecBuilder::default()
    }

    /// Validate this spec and return any findings.
    pub fn validate(&self) -> Result<Vec<crate::validate::ValidationFinding>> {
        validate_spec(self)
    }

    /// Return all parameters: the profile's defaults (if set) followed by the
    /// explicitly listed parameters, with duplicate keys collapsed so later
    /// entries win. This means a profile-only spec yields the profile's
    /// CIS/STIG parameter set, and explicit parameters override profile
    /// defaults for the same key.
    pub fn all_parameters(&self) -> Vec<SysctlParam> {
        let mut params: Vec<SysctlParam> = Vec::new();

        // Profile parameters act as defaults.
        if let Some(profile) = self.profile {
            params.extend(profile.params());
        }

        // Explicit parameters override profile defaults for the same key.
        params.extend(self.parameters.iter().cloned());

        dedup_by_key_last_wins(&mut params);
        params
    }
}

/// Collapse entries with the same `key`, keeping the *last* occurrence.
///
/// Profile parameters are appended before explicit parameters, so explicit
/// entries (which appear later) override profile defaults for the same key.
fn dedup_by_key_last_wins(params: &mut Vec<SysctlParam>) {
    // Walk back-to-front, recording the first (i.e. last) index seen per key.
    let mut keep = Vec::with_capacity(params.len());
    let mut seen = std::collections::HashSet::new();
    for (i, p) in params.iter().enumerate().rev() {
        if seen.insert(&p.key) {
            keep.push(i);
        }
    }
    keep.reverse(); // restore original order
    let next: Vec<SysctlParam> = keep.into_iter().map(|i| params[i].clone()).collect();
    *params = next;
}

/// Builder for [`HardenSpec`].
#[derive(Debug, Clone, Default)]
pub struct HardenSpecBuilder {
    spec: HardenSpec,
}

impl HardenSpecBuilder {
    /// Add a single parameter.
    pub fn param(mut self, p: SysctlParam) -> Self {
        self.spec.parameters.push(p);
        self
    }

    /// Add multiple parameters.
    pub fn params(mut self, params: impl IntoIterator<Item = SysctlParam>) -> Self {
        self.spec.parameters.extend(params);
        self
    }

    /// Set the hardening profile.
    pub fn profile(mut self, profile: HardeningProfile) -> Self {
        self.spec.profile = Some(profile);
        self
    }

    /// Build the spec.
    pub fn build(self) -> HardenSpec {
        self.spec
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sysctl_param_display() {
        let p = SysctlParam::new("kernel.kptr_restrict", "1", "Restrict kptr");
        assert_eq!(p.to_string(), "kernel.kptr_restrict = 1");
    }

    #[test]
    fn builder_adds_params() {
        let spec = HardenSpec::builder()
            .param(SysctlParam::new("a", "1", "first"))
            .param(SysctlParam::new("b", "0", "second"))
            .build();

        assert_eq!(spec.parameters.len(), 2);
        assert!(spec.profile.is_none());
    }

    #[test]
    fn all_parameters_expands_profile_only_spec() {
        // A profile-only spec used to silently yield zero parameters.
        let spec = HardenSpec::builder()
            .profile(HardeningProfile::Server)
            .build();

        let params = spec.all_parameters();
        assert!(
            !params.is_empty(),
            "profile-only spec must expand the profile's parameter set"
        );
        // Server profile hardens kptr_restrict.
        assert!(params.iter().any(|p| p.key == "kernel.kptr_restrict"));
    }

    #[test]
    fn all_parameters_merges_explicit_with_profile() {
        let spec = HardenSpec::builder()
            .profile(HardeningProfile::Desktop)
            .param(SysctlParam::new("kernel.custom_key", "7", "extra"))
            .build();

        let params = spec.all_parameters();
        // Profile params present.
        assert!(params.iter().any(|p| p.key == "kernel.kptr_restrict"));
        // Explicit param present.
        assert!(params.iter().any(|p| p.key == "kernel.custom_key"));
    }

    #[test]
    fn all_parameters_explicit_overrides_profile_for_same_key() {
        // Desktop sets kernel.yama.ptrace_scope = 1; explicit param sets 3.
        let spec = HardenSpec::builder()
            .profile(HardeningProfile::Desktop)
            .param(SysctlParam::new(
                "kernel.yama.ptrace_scope",
                "3",
                "admin override",
            ))
            .build();

        let params = spec.all_parameters();
        let ptrace = params
            .iter()
            .filter(|p| p.key == "kernel.yama.ptrace_scope")
            .collect::<Vec<_>>();
        // No duplicate after dedup.
        assert_eq!(ptrace.len(), 1);
        // Explicit value wins.
        assert_eq!(ptrace[0].value, "3");
    }

    #[test]
    fn all_parameters_no_profile_returns_explicit_only() {
        let spec = HardenSpec::builder()
            .param(SysctlParam::new("kernel.kptr_restrict", "1", ""))
            .build();

        let params = spec.all_parameters();
        assert_eq!(params.len(), 1);
        assert_eq!(params[0].key, "kernel.kptr_restrict");
    }
}
