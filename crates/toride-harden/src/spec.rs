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

    /// Return all parameters: explicit ones plus those from the profile (if set).
    pub fn all_parameters(&self) -> Vec<&SysctlParam> {
        // For now, just return the explicit parameters.
        // When a profile is set, callers should expand it via the profile module.
        self.parameters.iter().collect()
    }
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
}
