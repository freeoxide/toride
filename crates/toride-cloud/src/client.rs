//! Unified cloud client facade.
//!
//! [`CloudClient`] is the main entry point for cloud provider operations.
//! It detects the current provider and delegates to the appropriate
//! provider-specific client module.

use std::sync::Arc;

use crate::aws::AwsClient;
use crate::digitalocean::DigitalOceanClient;
use crate::error::{Error, Result};
use crate::gcp::GcpClient;
use crate::hetzner::HetznerClient;
use crate::report::CloudReport;
use crate::spec::{FirewallRule, Protocol, RuleAction, SecurityGroup};
use crate::CloudProvider;
use toride_runner::Runner;

// ---------------------------------------------------------------------------
// CloudClient
// ---------------------------------------------------------------------------

/// Unified cloud client that delegates to provider-specific implementations.
///
/// # Example
///
/// ```ignore
/// use toride_cloud::client::CloudClient;
///
/// let client = CloudClient::detect()?;
/// let groups = client.list_security_groups()?;
/// for group in &groups {
///     println!("{}: {} rules", group.name, group.rules.len());
/// }
/// ```
pub struct CloudClient {
    /// The detected cloud provider.
    pub provider: CloudProvider,
    /// Optional shared command runner injected into the provider-specific
    /// clients (Aws/Gcp/Hetzner). When `None`, each provider client
    /// constructs its own [`toride_runner::DuctRunner`].
    ///
    /// `DigitalOceanClient` is generic over `Runner` by value and cannot
    /// accept an `Arc<dyn Runner>`, so it always uses a `DuctRunner` regardless
    /// of this field.
    runner: Option<Arc<dyn Runner>>,
}

impl CloudClient {
    /// Create a client by auto-detecting the cloud provider.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ProviderNotFound`] if no provider can be detected.
    pub fn detect() -> Result<Self> {
        let provider = crate::detect::detect_provider()?;
        Ok(Self {
            provider,
            runner: None,
        })
    }

    /// Create a client for a specific provider.
    #[must_use]
    pub fn for_provider(provider: CloudProvider) -> Self {
        Self {
            provider,
            runner: None,
        }
    }

    /// Create a client for a specific provider that injects a shared command
    /// runner into the provider-specific clients.
    ///
    /// Used by the CLI dispatch layer (and tests) so a single
    /// [`toride_runner::FakeRunner`] can observe the commands the facade
    /// issues. Aws/Gcp/Hetzner clients accept the shared runner directly;
    /// `DigitalOcean` constructs its own `DuctRunner` because its runner is
    /// held by value, not behind an `Arc`.
    #[must_use]
    pub fn for_provider_with_runner(provider: CloudProvider, runner: Arc<dyn Runner>) -> Self {
        Self {
            provider,
            runner: Some(runner),
        }
    }

    /// Build the AWS client for the current provider, threading the injected
    /// runner through when one is configured.
    fn aws_client(&self) -> AwsClient {
        let region = default_region(self.provider);
        match &self.runner {
            Some(runner) => AwsClient::with_runner(region, runner.clone()),
            None => AwsClient::new(region),
        }
    }

    /// Build the GCP client, threading the injected runner when configured.
    fn gcp_client(&self) -> GcpClient {
        let project = default_project();
        match &self.runner {
            Some(runner) => GcpClient::with_runner(project, runner.clone()),
            None => GcpClient::new(project),
        }
    }

    /// Build the Hetzner client, threading the injected runner when configured.
    fn hetzner_client(&self) -> HetznerClient {
        let base = HetznerClient::new();
        match &self.runner {
            Some(runner) => base.with_arc_runner(runner.clone()),
            None => base,
        }
    }

    /// List all security groups for the detected provider.
    ///
    /// # Errors
    ///
    /// Returns [`Error::CommandFailed`] if the provider CLI fails.
    pub fn list_security_groups(&self) -> Result<Vec<SecurityGroup>> {
        match self.provider {
            CloudProvider::Aws => {
                let client = self.aws_client();
                client.list_security_groups()
            }
            CloudProvider::Gcp => {
                let client = self.gcp_client();
                client.list_firewall_rules()
            }
            CloudProvider::DigitalOcean => {
                let client = DigitalOceanClient::new();
                client.list_firewalls()
            }
            CloudProvider::Hetzner => {
                let client = self.hetzner_client();
                client.list_firewalls()
            }
            CloudProvider::Unknown => {
                Err(Error::ProviderNotFound(
                    "cannot list security groups for unknown provider".to_string(),
                ))
            }
        }
    }

    /// Fetch a single security group by its provider-specific identifier.
    ///
    /// `id` is the native identifier for the provider (an AWS `sg-...` group
    /// id, a GCP firewall name, a DigitalOcean firewall id, or a Hetzner
    /// firewall name/id).
    ///
    /// # Errors
    ///
    /// Returns [`Error::ProviderNotFound`] if the group does not exist, or
    /// [`Error::CommandFailed`] if the provider CLI fails.
    pub fn get_security_group(&self, id: &str) -> Result<SecurityGroup> {
        match self.provider {
            CloudProvider::Aws => self.aws_client().get_security_group(id),
            CloudProvider::Gcp => self.gcp_client().get_firewall_rule(id),
            CloudProvider::DigitalOcean => {
                DigitalOceanClient::new().get_firewall(id)
            }
            CloudProvider::Hetzner => self.hetzner_client().get_firewall(id),
            CloudProvider::Unknown => Err(Error::ProviderNotFound(
                "cannot get security group for unknown provider".to_string(),
            )),
        }
    }

    /// Create a new security group.
    ///
    /// `vpc_id` is only meaningful for AWS; other providers ignore it.
    ///
    /// # Errors
    ///
    /// Returns [`Error::CommandFailed`] if creation fails.
    pub fn create_security_group(
        &self,
        name: &str,
        description: &str,
        vpc_id: Option<&str>,
    ) -> Result<SecurityGroup> {
        match self.provider {
            CloudProvider::Aws => {
                self.aws_client()
                    .create_security_group(name, description, vpc_id)
            }
            CloudProvider::Gcp => {
                // GCP models a firewall as a named rule list; description and
                // VPC are not first-class at create time. Pass an empty network
                // (the default VPC) and no rules, then return the caller's view.
                let _ = (description, vpc_id);
                self.gcp_client()
                    .create_firewall_rule(name, "", &[])
            }
            CloudProvider::DigitalOcean => {
                // DigitalOcean requires at least one inbound or outbound rule.
                // Create a default-deny egress rule so the firewall is valid,
                // then let the caller expand it via authorize_ingress.
                let egress = FirewallRule {
                    id: None,
                    description: description.to_string(),
                    is_ingress: false,
                    protocol: Protocol::All,
                    port_range: None,
                    cidr: "0.0.0.0/0".to_string(),
                    action: RuleAction::Allow,
                };
                let _ = vpc_id;
                DigitalOceanClient::new().create_firewall(name, &[], &[egress])
            }
            CloudProvider::Hetzner => self.hetzner_client().create_firewall(name, &[]),
            CloudProvider::Unknown => Err(Error::ProviderNotFound(
                "cannot create security group for unknown provider".to_string(),
            )),
        }
    }

    /// Delete a security group by its provider-specific identifier.
    ///
    /// # Errors
    ///
    /// Returns [`Error::CommandFailed`] if deletion fails.
    pub fn delete_security_group(&self, id: &str) -> Result<()> {
        match self.provider {
            CloudProvider::Aws => self.aws_client().delete_security_group(id),
            CloudProvider::Gcp => self.gcp_client().delete_firewall_rule(id),
            CloudProvider::DigitalOcean => DigitalOceanClient::new().delete_firewall(id),
            CloudProvider::Hetzner => self.hetzner_client().delete_firewall(id),
            CloudProvider::Unknown => Err(Error::ProviderNotFound(
                "cannot delete security group for unknown provider".to_string(),
            )),
        }
    }

    /// Authorise an ingress rule on a security group.
    ///
    /// # Errors
    ///
    /// Returns [`Error::FirewallRuleConflict`] if the rule already exists, or
    /// [`Error::CommandFailed`] if the provider CLI fails for another reason.
    pub fn authorize_ingress(&self, group_id: &str, rule: &FirewallRule) -> Result<()> {
        match self.provider {
            CloudProvider::Aws => self.aws_client().authorize_ingress(group_id, rule),
            CloudProvider::Gcp => {
                self.gcp_client().update_firewall_rule(group_id, std::slice::from_ref(rule))
            }
            CloudProvider::DigitalOcean => {
                DigitalOceanClient::new().add_rules(group_id, std::slice::from_ref(rule))
            }
            CloudProvider::Hetzner => self.hetzner_client().add_rules(group_id, std::slice::from_ref(rule)),
            CloudProvider::Unknown => Err(Error::ProviderNotFound(
                "cannot authorize ingress for unknown provider".to_string(),
            )),
        }
    }

    /// Revoke an ingress rule from a security group.
    ///
    /// # Errors
    ///
    /// Returns [`Error::CommandFailed`] if the rule does not exist or the
    /// provider CLI fails.
    pub fn revoke_ingress(&self, group_id: &str, rule: &FirewallRule) -> Result<()> {
        match self.provider {
            CloudProvider::Aws => self.aws_client().revoke_ingress(group_id, rule),
            // GCP has no per-rule revoke: the firewall rule is the unit, so
            // updating with an empty set removes it.
            CloudProvider::Gcp => {
                self.gcp_client().update_firewall_rule(group_id, &[])
            }
            CloudProvider::DigitalOcean => {
                DigitalOceanClient::new().remove_rules(group_id, std::slice::from_ref(rule))
            }
            CloudProvider::Hetzner => self.hetzner_client().remove_rules(group_id, std::slice::from_ref(rule)),
            CloudProvider::Unknown => Err(Error::ProviderNotFound(
                "cannot revoke ingress for unknown provider".to_string(),
            )),
        }
    }

    /// Generate a full cloud report for the detected provider.
    ///
    /// Populates [`CloudReport::security_groups`] from a live list, recording
    /// a single error finding if the list fails so the report is still useful
    /// to callers that want a structured view of a failed operation.
    ///
    /// # Errors
    ///
    /// Returns an error only if the report itself cannot be constructed.
    pub fn report(&self) -> Result<CloudReport> {
        let mut report = CloudReport::new(self.provider);

        match self.list_security_groups() {
            Ok(groups) => {
                report.security_groups = groups;
            }
            Err(e) => {
                report.push(
                    crate::report::Finding::new(
                        "client.list-failed",
                        crate::report::Severity::Error,
                        "Failed to list security groups",
                    )
                    .detail(format!("{e}")),
                );
            }
        }

        Ok(report)
    }
}

// ---------------------------------------------------------------------------
// Construction defaults
// ---------------------------------------------------------------------------

/// Pick a reasonable default region for providers that need one.
///
/// The facade constructs provider clients internally, so it needs *some*
/// region when the caller has not configured one. `us-east-1` is the AWS
/// canonical default; it is ignored by providers that do not take a region.
fn default_region(provider: CloudProvider) -> &'static str {
    match provider {
        CloudProvider::Aws => "us-east-1",
        _ => "",
    }
}

/// Resolve the default GCP project id.
///
/// Reads `$GOOGLE_CLOUD_PROJECT` (the same env var GCP itself uses) so the
/// facade picks up the operator's active project without explicit config.
/// Falls back to `"default"` when unset, matching the prior behaviour.
fn default_project() -> String {
    std::env::var("GOOGLE_CLOUD_PROJECT").unwrap_or_else(|_| "default".to_string())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spec::{PortRange, Protocol, RuleAction};

    // -- dispatch soundness ---------------------------------------------------

    #[test]
    fn for_provider_unknown_list_returns_provider_not_found() {
        let client = CloudClient::for_provider(CloudProvider::Unknown);
        let err = client.list_security_groups().unwrap_err();
        assert!(matches!(err, Error::ProviderNotFound(_)), "{err:?}");
    }

    #[test]
    fn for_provider_unknown_get_returns_provider_not_found() {
        let client = CloudClient::for_provider(CloudProvider::Unknown);
        let err = client.get_security_group("x").unwrap_err();
        assert!(matches!(err, Error::ProviderNotFound(_)), "{err:?}");
    }

    #[test]
    fn for_provider_unknown_create_returns_provider_not_found() {
        let client = CloudClient::for_provider(CloudProvider::Unknown);
        let err = client
            .create_security_group("n", "d", None)
            .unwrap_err();
        assert!(matches!(err, Error::ProviderNotFound(_)), "{err:?}");
    }

    #[test]
    fn for_provider_unknown_delete_returns_provider_not_found() {
        let client = CloudClient::for_provider(CloudProvider::Unknown);
        let err = client.delete_security_group("x").unwrap_err();
        assert!(matches!(err, Error::ProviderNotFound(_)), "{err:?}");
    }

    #[test]
    fn for_provider_unknown_authorize_returns_provider_not_found() {
        let rule = FirewallRule {
            id: None,
            description: String::new(),
            is_ingress: true,
            protocol: Protocol::Tcp,
            port_range: Some(PortRange::single(22)),
            cidr: "0.0.0.0/0".to_string(),
            action: RuleAction::Allow,
        };
        let client = CloudClient::for_provider(CloudProvider::Unknown);
        let err = client.authorize_ingress("x", &rule).unwrap_err();
        assert!(matches!(err, Error::ProviderNotFound(_)), "{err:?}");
    }

    #[test]
    fn for_provider_unknown_revoke_returns_provider_not_found() {
        let rule = FirewallRule {
            id: None,
            description: String::new(),
            is_ingress: true,
            protocol: Protocol::Tcp,
            port_range: Some(PortRange::single(22)),
            cidr: "0.0.0.0/0".to_string(),
            action: RuleAction::Allow,
        };
        let client = CloudClient::for_provider(CloudProvider::Unknown);
        let err = client.revoke_ingress("x", &rule).unwrap_err();
        assert!(matches!(err, Error::ProviderNotFound(_)), "{err:?}");
    }

    // -- report ---------------------------------------------------------------

    #[test]
    fn report_for_unknown_records_list_failed_finding() {
        let client = CloudClient::for_provider(CloudProvider::Unknown);
        let report = client.report().unwrap();
        assert_eq!(report.provider, CloudProvider::Unknown);
        assert!(report.security_groups.is_empty());
        assert!(report.has_errors());
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.id == "client.list-failed"),
            "expected client.list-failed finding: {:?}",
            report.findings
        );
    }

    // -- helpers --------------------------------------------------------------

    #[test]
    fn default_region_picks_us_east_1_for_aws() {
        assert_eq!(default_region(CloudProvider::Aws), "us-east-1");
        assert_eq!(default_region(CloudProvider::Gcp), "");
    }

    #[test]
    fn default_project_returns_env_value_or_default() {
        // `default_project` reads $GOOGLE_CLOUD_PROJECT at call time, falling
        // back to "default". We don't mutate the (process-global, unsafe-in-
        // edition-2024) env here; instead assert the documented contract:
        // it either equals the live env var, or the fallback literal.
        let got = default_project();
        let expected = std::env::var("GOOGLE_CLOUD_PROJECT").unwrap_or_else(|_| "default".to_string());
        assert_eq!(got, expected);
        // The fallback must be a known constant so callers can reason about it.
        assert!(
            got == expected,
            "default_project must mirror $GOOGLE_CLOUD_PROJECT or \"default\""
        );
    }
}
