//! AWS EC2 security group management.
//!
//! Provides typed wrappers around the `aws` CLI for managing EC2 security
//! groups, ingress/egress rules, and VPC firewall configuration.
//!
//! All commands shell out through the centralised [`toride_runner::Runner`]
//! abstraction, so the client is fully testable with a [`FakeRunner`].
//!
//! # JSON shape
//!
//! `aws ec2 describe-security-groups --output json` returns:
//!
//! ```json
//! { "SecurityGroups": [ { "GroupId": "sg-...", "GroupName": "...",
//!   "Description": "...", "VpcId": "vpc-...",
//!   "IpPermissions": [ { "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
//!     "IpRanges": [ { "CidrIp": "0.0.0.0/0", "Description": "ssh" } ] } ] } ] }
//! ```
//!
//! Source: AWS CLI v2 reference,
//! <https://docs.aws.amazon.com/cli/latest/reference/ec2/describe-security-groups.html>.

use crate::CloudProvider;
use crate::error::{Error, Result};
use crate::spec::{FirewallRule, PortRange, Protocol, RuleAction, SecurityGroup};

use serde::Deserialize;
use std::fmt::Write as _;
use std::sync::Arc;
use toride_runner::spec::CommandSpec;
use toride_runner::{CommandOutput, DuctRunner, Runner};

// ---------------------------------------------------------------------------
// AwsClient
// ---------------------------------------------------------------------------

/// Client for managing AWS EC2 security groups.
///
/// Delegates command execution to the `aws` CLI. All commands go through the
/// centralised runner pattern for testability.
pub struct AwsClient {
    /// AWS region (e.g. `us-east-1`).
    pub region: String,
    /// AWS profile name (uses default profile if `None`).
    pub profile: Option<String>,
    /// Command runner used to execute the `aws` CLI.
    runner: Arc<dyn Runner>,
}

impl AwsClient {
    /// Create a new AWS client for the given region.
    ///
    /// Uses a real [`DuctRunner`] for command execution. Inject a fake runner
    /// with [`AwsClient::with_runner`] in tests.
    #[must_use]
    pub fn new(region: impl Into<String>) -> Self {
        Self::with_runner(region, Arc::new(DuctRunner))
    }

    /// Set the AWS profile.
    #[must_use]
    pub fn with_profile(mut self, profile: impl Into<String>) -> Self {
        self.profile = Some(profile.into());
        self
    }

    /// Inject a custom [`Runner`] behind an [`Arc`].
    ///
    /// The [`Arc`] lets tests retain a handle to a shared [`FakeRunner`] after
    /// handing the client a clone, so they can inspect recorded calls.
    #[must_use]
    pub fn with_runner(region: impl Into<String>, runner: Arc<dyn Runner>) -> Self {
        Self {
            region: region.into(),
            profile: None,
            runner,
        }
    }

    /// Build the common `aws ec2 ... --region <r> [--profile <p>] --output json`
    /// command prefix.
    fn base_command(&self, action: &str) -> CommandSpec {
        let mut spec = CommandSpec::new("aws")
            .arg("ec2")
            .arg(action)
            .arg("--region")
            .arg(&self.region);
        if let Some(profile) = &self.profile {
            spec = spec.arg("--profile").arg(profile);
        }
        spec.arg("--output").arg("json")
    }

    /// Run a command via the runner, mapping the runner error into the crate
    /// error type. Equivalent to `Runner::run_checked` but returns our
    /// `crate::Result`.
    fn run_checked(&self, spec: &CommandSpec) -> Result<CommandOutput> {
        Runner::run_checked(self.runner.as_ref(), spec).map_err(map_runner_error)
    }

    /// List all security groups in the current region.
    ///
    /// Runs `aws ec2 describe-security-groups --output json`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::CommandFailed`] if the `aws` CLI is not installed
    /// or returns a non-zero exit code, or [`Error::Other`] if the JSON
    /// response cannot be parsed.
    pub fn list_security_groups(&self) -> Result<Vec<SecurityGroup>> {
        let spec = self.base_command("describe-security-groups");
        let output = self.run_checked(&spec)?;
        let resp: DescribeResponse = parse_json(&output.stdout)?;
        Ok(resp
            .security_groups
            .into_iter()
            .map(RawSecurityGroup::into_security_group)
            .collect())
    }

    /// Get a security group by ID.
    ///
    /// Runs `aws ec2 describe-security-groups --group-ids <id> --output json`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ProviderNotFound`] if the group does not exist.
    pub fn get_security_group(&self, group_id: &str) -> Result<SecurityGroup> {
        let spec = self
            .base_command("describe-security-groups")
            .arg("--group-ids")
            .arg(group_id);
        let output = self.run_checked(&spec)?;
        let resp: DescribeResponse = parse_json(&output.stdout)?;
        match resp.security_groups.into_iter().next() {
            Some(g) => Ok(g.into_security_group()),
            None => Err(Error::ProviderNotFound(format!(
                "security group {group_id} not found"
            ))),
        }
    }

    /// Create a new security group.
    ///
    /// Runs `aws ec2 create-security-group --group-name <n> --description <d>
    /// [--vpc-id <v>] --output json`, which returns
    /// `{"GroupId": "sg-..."}`. The freshly created group is then fetched via
    /// [`Self::get_security_group`] so the caller receives a fully-populated
    /// [`SecurityGroup`].
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
        let mut spec = self
            .base_command("create-security-group")
            .arg("--group-name")
            .arg(name)
            .arg("--description")
            .arg(description);
        if let Some(vpc) = vpc_id {
            spec = spec.arg("--vpc-id").arg(vpc);
        }
        let output = self.run_checked(&spec)?;
        let created: CreateResponse = parse_json(&output.stdout)?;
        let group_id = created.group_id;
        // Re-fetch so the returned group carries description/rules/tags. If the
        // re-fetch fails for any reason, fall back to a minimal group so the
        // caller still has the freshly-minted ID.
        match self.get_security_group(&group_id) {
            Ok(group) => Ok(group),
            Err(_) => Ok(SecurityGroup {
                id: Some(group_id.clone()),
                name: name.to_string(),
                description: description.to_string(),
                provider: CloudProvider::Aws,
                rules: Vec::new(),
                tags: Vec::new(),
            }),
        }
    }

    /// Delete a security group by ID.
    ///
    /// Runs `aws ec2 delete-security-group --group-id <id> --output json`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::CommandFailed`] if deletion fails.
    pub fn delete_security_group(&self, group_id: &str) -> Result<()> {
        let spec = self
            .base_command("delete-security-group")
            .arg("--group-id")
            .arg(group_id);
        self.run_checked(&spec)?;
        Ok(())
    }

    /// Add an ingress rule to a security group.
    ///
    /// Runs
    /// `aws ec2 authorize-security-group-ingress --group-id <id> --ip-permissions
    /// '<json>' --output json`. The `IpPermissions` blob is built from
    /// [`FirewallRule`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::FirewallRuleConflict`] if the rule conflicts with
    /// an existing rule (the `aws` CLI exits non-zero with a
    /// `InvalidPermission.Duplicate` message in that case).
    pub fn authorize_ingress(&self, group_id: &str, rule: &FirewallRule) -> Result<()> {
        let permissions = serde_json::to_value(build_ip_permissions(rule))
            .map_err(|e| Error::Other(format!("failed to encode ip-permissions: {e}")))?;
        let spec = self
            .base_command("authorize-security-group-ingress")
            .arg("--group-id")
            .arg(group_id)
            .arg("--ip-permissions")
            .arg(permissions.to_string());
        match self.run_checked(&spec) {
            Ok(_) => Ok(()),
            Err(Error::CommandFailed { message, .. })
                if message.contains("InvalidPermission.Duplicate") =>
            {
                Err(Error::FirewallRuleConflict(message))
            }
            Err(e) => Err(e),
        }
    }

    /// Remove an ingress rule from a security group.
    ///
    /// Runs
    /// `aws ec2 revoke-security-group-ingress --group-id <id> --ip-permissions
    /// '<json>' --output json`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::CommandFailed`] if the rule does not exist.
    pub fn revoke_ingress(&self, group_id: &str, rule: &FirewallRule) -> Result<()> {
        let permissions = serde_json::to_value(build_ip_permissions(rule))
            .map_err(|e| Error::Other(format!("failed to encode ip-permissions: {e}")))?;
        let spec = self
            .base_command("revoke-security-group-ingress")
            .arg("--group-id")
            .arg(group_id)
            .arg("--ip-permissions")
            .arg(permissions.to_string());
        self.run_checked(&spec)?;
        Ok(())
    }
}

/// Map a runner error into our crate error.
///
/// `toride_runner` errors are not `From`-convertible (they live in a separate
/// crate), so we translate the variants we care about.
fn map_runner_error(e: toride_runner::Error) -> Error {
    match e {
        toride_runner::Error::BinaryNotFound(prog) => Error::BinaryNotFound(prog),
        toride_runner::Error::CommandFailed {
            program,
            args,
            exit_code,
            stderr,
        } => {
            // Fold the structured fields into a single human-readable message
            // so callers can string-match sentinels (e.g. duplicate-rule).
            let mut message = format!("args: {args}");
            if let Some(code) = exit_code {
                let _ = write!(message, "\nexit: {code}");
            }
            if !stderr.trim().is_empty() {
                let _ = write!(message, "\nstderr: {}", stderr.trim());
            }
            Error::CommandFailed { program, message }
        }
        other => Error::Other(other.to_string()),
    }
}

// ---------------------------------------------------------------------------
// JSON parsing helpers (file-local to avoid colliding with parse.rs)
// ---------------------------------------------------------------------------

/// Top-level `describe-security-groups` response.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct DescribeResponse {
    #[serde(default, rename = "SecurityGroups")]
    security_groups: Vec<RawSecurityGroup>,
}

/// A single security group as emitted by `aws ec2`.
///
/// The `IpPermissions` array holds ingress rules; `IpPermissionsEgress` holds
/// egress rules. Both map to [`FirewallRule`].
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct RawSecurityGroup {
    #[serde(default)]
    group_id: Option<String>,
    #[serde(default)]
    group_name: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    tags: Vec<RawTag>,
    #[serde(default, rename = "IpPermissions")]
    ip_permissions: Vec<RawIpPermission>,
    #[serde(default, rename = "IpPermissionsEgress")]
    ip_permissions_egress: Vec<RawIpPermission>,
}

impl RawSecurityGroup {
    fn into_security_group(self) -> SecurityGroup {
        let mut rules =
            Vec::with_capacity(self.ip_permissions.len() + self.ip_permissions_egress.len());
        for p in self.ip_permissions {
            rules.extend(p.into_rules(true));
        }
        for p in self.ip_permissions_egress {
            rules.extend(p.into_rules(false));
        }
        let tags = self.tags.into_iter().map(|t| (t.key, t.value)).collect();
        SecurityGroup {
            id: self.group_id,
            name: self.group_name,
            description: self.description,
            provider: CloudProvider::Aws,
            rules,
            tags,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct RawTag {
    #[serde(default)]
    key: String,
    #[serde(default)]
    value: String,
}

/// A single `IpPermission` entry — one protocol/port combo expanded across
/// every CIDR it covers.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct RawIpPermission {
    #[serde(default)]
    ip_protocol: String,
    #[serde(default)]
    from_port: Option<i64>,
    #[serde(default)]
    to_port: Option<i64>,
    #[serde(default, rename = "IpRanges")]
    ip_ranges: Vec<RawCidrEntry>,
    #[serde(default, rename = "Ipv6Ranges")]
    ipv6_ranges: Vec<RawCidrEntry>,
    #[serde(default, rename = "UserIdGroupPairs")]
    user_id_group_pairs: Vec<RawUserIdGroupPair>,
}

impl RawIpPermission {
    /// Expand this permission into one [`FirewallRule`] per source CIDR.
    fn into_rules(self, is_ingress: bool) -> Vec<FirewallRule> {
        let protocol = parse_protocol(&self.ip_protocol);
        let port_range = port_range_from(self.from_port, self.to_port, protocol);

        let mut entries: Vec<(String, String)> = self
            .ip_ranges
            .into_iter()
            .map(|e| (e.cidr_ip, e.description))
            .collect();
        entries.extend(
            self.ipv6_ranges
                .into_iter()
                .map(|e| (e.cidr_ipv6, e.description)),
        );
        entries.extend(
            self.user_id_group_pairs
                .into_iter()
                .map(|p| (source_sg_cidr(&p), p.description)),
        );

        if entries.is_empty() {
            // Protocols that cover all ports (`-1`) legitimately have no CIDR
            // in some outputs; still emit a rule so nothing is silently lost.
            entries.push((String::new(), String::new()));
        }

        entries
            .into_iter()
            .map(|(cidr, description)| FirewallRule {
                id: None,
                description,
                is_ingress,
                protocol,
                port_range,
                cidr,
                action: RuleAction::Allow,
            })
            .collect()
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct RawCidrEntry {
    #[serde(default, rename = "CidrIp")]
    cidr_ip: String,
    #[serde(default, rename = "CidrIpv6")]
    cidr_ipv6: String,
    #[serde(default)]
    description: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct RawUserIdGroupPair {
    #[serde(default)]
    group_id: Option<String>,
    #[serde(default)]
    description: String,
}

/// Render a security-group reference into a pseudo-CIDR so it round-trips
/// through the CIDR slot without data loss.
fn source_sg_cidr(pair: &RawUserIdGroupPair) -> String {
    match &pair.group_id {
        Some(id) => format!("sg:{id}"),
        None => String::new(),
    }
}

/// `create-security-group` returns `{"GroupId": "sg-..."}`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct CreateResponse {
    #[serde(default)]
    group_id: String,
}

/// Parse a JSON document into `T`, mapping serde errors to [`Error::Other`].
fn parse_json<T: serde::de::DeserializeOwned>(stdout: &str) -> Result<T> {
    serde_json::from_str::<T>(stdout)
        .map_err(|e| Error::Other(format!("failed to parse aws JSON: {e}")))
}

/// Translate an AWS protocol string into a [`Protocol`].
///
/// AWS uses `-1` for "all protocols" and lowercase IANA names otherwise.
fn parse_protocol(raw: &str) -> Protocol {
    let trimmed = raw.trim();
    match trimmed {
        "" | "-1" => Protocol::All,
        "tcp" => Protocol::Tcp,
        "udp" => Protocol::Udp,
        "icmp" | "icmpv6" => Protocol::Icmp,
        other => match other.parse::<u8>() {
            Ok(n) => Protocol::Other(n),
            Err(_) => Protocol::All,
        },
    }
}

/// Map AWS `FromPort`/`ToPort` onto a [`PortRange`].
///
/// When the protocol is "all" (`-1`) AWS omits ports; we leave `None`.
/// Otherwise both bounds default to each other so single-port rules work.
fn port_range_from(from: Option<i64>, to: Option<i64>, protocol: Protocol) -> Option<PortRange> {
    if matches!(protocol, Protocol::All) && from.is_none() && to.is_none() {
        return None;
    }
    let start = from.and_then(|p| u16::try_from(p.max(0)).ok()).unwrap_or(0);
    let end = to
        .and_then(|p| u16::try_from(p.max(0)).ok())
        .unwrap_or(start);
    Some(PortRange {
        start: start.min(end),
        end: start.max(end),
    })
}

/// Build the `IpPermissions` JSON value sent to
/// `authorize/revoke-security-group-ingress`.
///
/// Shape mirrors the AWS CLI reference:
/// `[{"IpProtocol":"tcp","FromPort":22,"ToPort":22,"IpRanges":[{"CidrIp":"..."}]}]`.
fn build_ip_permissions(rule: &FirewallRule) -> serde_json::Value {
    let proto = match rule.protocol {
        Protocol::Tcp => "tcp",
        Protocol::Udp => "udp",
        Protocol::Icmp => "icmp",
        Protocol::All => "-1",
        Protocol::Other(n) => {
            return serde_json::json!([{
                "IpProtocol": n.to_string(),
                "IpRanges": [cidr_object(rule)],
            }]);
        }
    };

    let mut perm = serde_json::json!({ "IpProtocol": proto });
    if let Some(range) = rule.port_range
        && !matches!(rule.protocol, Protocol::All)
    {
        perm["FromPort"] = serde_json::Value::from(i64::from(range.start));
        perm["ToPort"] = serde_json::Value::from(i64::from(range.end));
    }
    perm["IpRanges"] = serde_json::Value::Array(vec![cidr_object(rule)]);
    serde_json::Value::Array(vec![perm])
}

/// Build a single `{"CidrIp": "...", "Description": "..."}` entry.
fn cidr_object(rule: &FirewallRule) -> serde_json::Value {
    let mut obj = serde_json::json!({ "CidrIp": rule.cidr });
    if !rule.description.is_empty() {
        obj["Description"] = serde_json::Value::from(rule.description.clone());
    }
    obj
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use toride_runner::fake::FakeRunner;

    /// Real `describe-security-groups` JSON, transcribed verbatim from the
    /// AWS CLI v2 reference examples.
    ///
    /// Source: <https://docs.aws.amazon.com/cli/latest/reference/ec2/describe-security-groups.html>
    /// (Output → Example: describe a security group).
    const DESCRIBE_SAMPLE: &str = r#"{
        "SecurityGroups": [
            {
                "Description": "Allows SSH access",
                "GroupName": "ssh-allowed",
                "IpPermissions": [
                    {
                        "FromPort": 22,
                        "IpProtocol": "tcp",
                        "IpRanges": [
                            { "CidrIp": "203.0.113.0/24", "Description": "SSH from corp" }
                        ],
                        "ToPort": 22
                    }
                ],
                "OwnerId": "123456789012",
                "GroupId": "sg-903004f8",
                "IpPermissionsEgress": [
                    {
                        "IpProtocol": "-1",
                        "IpRanges": [
                            { "CidrIp": "0.0.0.0/0" }
                        ],
                        "Ipv6Ranges": [],
                        "PrefixListIds": [],
                        "UserIdGroupPairs": []
                    }
                ],
                "VpcId": "vpc-1a2b3c4d"
            }
        ]
    }"#;

    /// Real `create-security-group` JSON output.
    ///
    /// Source: <https://docs.aws.amazon.com/cli/latest/reference/ec2/create-security-group.html>
    /// (Output → Example 1).
    const CREATE_SAMPLE: &str = r#"{ "GroupId": "sg-903004f8" }"#;

    /// Build a client backed by a shared (clonable) [`FakeRunner`].
    fn client_with(runner: Arc<FakeRunner>) -> AwsClient {
        AwsClient::with_runner("us-east-1", runner)
    }

    /// Assert the runner received exactly one call matching `expected` on the
    /// command-construction fields (program, args, redact).
    fn assert_one_call(runner: &FakeRunner, expected: &CommandSpec) {
        let calls = runner.calls();
        assert_eq!(calls.len(), 1, "expected exactly one call");
        assert_eq!(calls[0].program, expected.program, "program mismatch");
        assert_eq!(calls[0].args, expected.args, "args mismatch");
        assert_eq!(calls[0].redact, expected.redact, "redact mismatch");
    }

    // ---- command construction (program + exact args) ----

    #[test]
    fn list_command_exact() {
        // Source: aws ec2 describe-security-groups --region us-east-1 --output json
        // docs: https://docs.aws.amazon.com/cli/latest/reference/ec2/describe-security-groups.html
        let runner = Arc::new(
            FakeRunner::new()
                .push_response(CommandOutput::from_stdout(r#"{"SecurityGroups": []}"#)),
        );
        let client = client_with(runner.clone());
        client.list_security_groups().unwrap();

        let expected = CommandSpec::new("aws").args([
            "ec2",
            "describe-security-groups",
            "--region",
            "us-east-1",
            "--output",
            "json",
        ]);
        assert_one_call(&runner, &expected);
    }

    #[test]
    fn list_command_with_profile_exact() {
        // With a profile the command gains `--profile <p>` before --output.
        let runner = Arc::new(
            FakeRunner::new()
                .push_response(CommandOutput::from_stdout(r#"{"SecurityGroups": []}"#)),
        );
        let client = AwsClient::with_runner("eu-west-1", runner.clone()).with_profile("prod");
        client.list_security_groups().unwrap();

        let expected = CommandSpec::new("aws").args([
            "ec2",
            "describe-security-groups",
            "--region",
            "eu-west-1",
            "--profile",
            "prod",
            "--output",
            "json",
        ]);
        assert_one_call(&runner, &expected);
    }

    #[test]
    fn get_command_exact() {
        // Source: aws ec2 describe-security-groups --group-ids sg-903004f8 --output json
        let runner =
            Arc::new(FakeRunner::new().push_response(CommandOutput::from_stdout(DESCRIBE_SAMPLE)));
        let client = client_with(runner.clone());
        client.get_security_group("sg-903004f8").unwrap();

        let expected = CommandSpec::new("aws").args([
            "ec2",
            "describe-security-groups",
            "--region",
            "us-east-1",
            "--output",
            "json",
            "--group-ids",
            "sg-903004f8",
        ]);
        assert_one_call(&runner, &expected);
    }

    #[test]
    fn create_command_exact_and_fetches_group() {
        // Source: aws ec2 create-security-group --group-name N --description D
        //         --vpc-id vpc-x --region us-east-1 --output json
        //         -> {"GroupId":"sg-903004f8"}
        // The create method then issues a describe to populate the returned group.
        let runner = Arc::new(
            FakeRunner::new()
                .push_response(CommandOutput::from_stdout(CREATE_SAMPLE))
                .push_response(CommandOutput::from_stdout(DESCRIBE_SAMPLE)),
        );
        let client = client_with(runner.clone());

        let group = client
            .create_security_group("ssh-allowed", "Allows SSH access", Some("vpc-1a2b3c4d"))
            .unwrap();
        assert_eq!(group.id.as_deref(), Some("sg-903004f8"));
        assert_eq!(group.name, "ssh-allowed");

        let calls = runner.calls();
        assert_eq!(calls.len(), 2, "create should issue create + describe");
        let create_call = &calls[0];
        assert_eq!(create_call.program, "aws");
        assert_eq!(
            create_call.args,
            [
                "ec2",
                "create-security-group",
                "--region",
                "us-east-1",
                "--output",
                "json",
                "--group-name",
                "ssh-allowed",
                "--description",
                "Allows SSH access",
                "--vpc-id",
                "vpc-1a2b3c4d",
            ]
        );
        assert!(!create_call.redact, "create command must not be redacted");
    }

    #[test]
    fn delete_command_exact() {
        // Source: aws ec2 delete-security-group --group-id sg-903004f8 --output json
        let runner = Arc::new(FakeRunner::new().push_response(CommandOutput::from_stdout("{}")));
        let client = client_with(runner.clone());
        client.delete_security_group("sg-903004f8").unwrap();

        let expected = CommandSpec::new("aws").args([
            "ec2",
            "delete-security-group",
            "--region",
            "us-east-1",
            "--output",
            "json",
            "--group-id",
            "sg-903004f8",
        ]);
        assert_one_call(&runner, &expected);
    }

    #[test]
    fn authorize_builds_ip_permissions_command() {
        // Source: aws ec2 authorize-security-group-ingress --group-id <id>
        //         --ip-permissions '<json>' --output json
        // docs: https://docs.aws.amazon.com/cli/latest/reference/ec2/authorize-security-group-ingress.html
        let rule = FirewallRule {
            id: None,
            description: "SSH from corp".to_string(),
            is_ingress: true,
            protocol: Protocol::Tcp,
            port_range: Some(PortRange::single(22)),
            cidr: "203.0.113.0/24".to_string(),
            action: RuleAction::Allow,
        };
        let runner = Arc::new(
            FakeRunner::new().push_response(CommandOutput::from_stdout(r#"{"return": true}"#)),
        );
        let client = client_with(runner.clone());

        client.authorize_ingress("sg-903004f8", &rule).unwrap();

        let calls = runner.calls();
        assert_eq!(calls.len(), 1);
        let call = &calls[0];
        assert_eq!(call.program, "aws");
        assert!(!call.redact, "authorize must not be redacted");
        let perms_idx = call
            .args
            .iter()
            .position(|a| a == "--ip-permissions")
            .unwrap();
        let payload = &call.args[perms_idx + 1];
        let v: serde_json::Value = serde_json::from_str(payload).unwrap();
        assert_eq!(v[0]["IpProtocol"], "tcp");
        assert_eq!(v[0]["FromPort"], 22);
        assert_eq!(v[0]["ToPort"], 22);
        assert_eq!(v[0]["IpRanges"][0]["CidrIp"], "203.0.113.0/24");
        assert_eq!(v[0]["IpRanges"][0]["Description"], "SSH from corp");
        assert_eq!(
            &call.args[..perms_idx],
            [
                "ec2",
                "authorize-security-group-ingress",
                "--region",
                "us-east-1",
                "--output",
                "json",
                "--group-id",
                "sg-903004f8",
            ]
        );
    }

    #[test]
    fn authorize_maps_duplicate_to_conflict() {
        // AWS CLI exits non-zero with `InvalidPermission.Duplicate` when the
        // rule already exists; map that to FirewallRuleConflict.
        // docs: https://docs.aws.amazon.com/cli/latest/reference/ec2/authorize-security-group-ingress.html
        let rule = FirewallRule {
            id: None,
            description: String::new(),
            is_ingress: true,
            protocol: Protocol::Tcp,
            port_range: Some(PortRange::single(22)),
            cidr: "0.0.0.0/0".to_string(),
            action: RuleAction::Allow,
        };
        let runner = Arc::new(FakeRunner::new().push_response(CommandOutput::from_stderr(
            "An error occurred (InvalidPermission.Duplicate) ...",
            255,
        )));
        let client = client_with(runner);
        let err = client.authorize_ingress("sg-1", &rule).unwrap_err();
        assert!(matches!(err, Error::FirewallRuleConflict(_)), "{err:?}");
    }

    #[test]
    fn revoke_builds_command() {
        // Source: aws ec2 revoke-security-group-ingress --group-id <id>
        //         --ip-permissions '<json>' --output json
        let rule = FirewallRule {
            id: None,
            description: String::new(),
            is_ingress: true,
            protocol: Protocol::Udp,
            port_range: Some(PortRange::range(1000, 2000)),
            cidr: "10.0.0.0/8".to_string(),
            action: RuleAction::Allow,
        };
        let runner = Arc::new(
            FakeRunner::new().push_response(CommandOutput::from_stdout(r#"{"return": true}"#)),
        );
        let client = client_with(runner.clone());

        client.revoke_ingress("sg-1", &rule).unwrap();

        let calls = runner.calls();
        let call = &calls[0];
        let perms_idx = call
            .args
            .iter()
            .position(|a| a == "--ip-permissions")
            .unwrap();
        let payload: serde_json::Value = serde_json::from_str(&call.args[perms_idx + 1]).unwrap();
        assert_eq!(payload[0]["IpProtocol"], "udp");
        assert_eq!(payload[0]["FromPort"], 1000);
        assert_eq!(payload[0]["ToPort"], 2000);
        assert_eq!(payload[0]["IpRanges"][0]["CidrIp"], "10.0.0.0/8");
        assert_eq!(
            &call.args[..perms_idx],
            [
                "ec2",
                "revoke-security-group-ingress",
                "--region",
                "us-east-1",
                "--output",
                "json",
                "--group-id",
                "sg-1",
            ]
        );
    }

    // ---- real-sample parsing ----

    #[test]
    fn parses_real_describe_sample() {
        // Asserts the docs-sourced describe-security-groups JSON parses into
        // SecurityGroup/FirewallRule. Source:
        // https://docs.aws.amazon.com/cli/latest/reference/ec2/describe-security-groups.html
        let runner =
            Arc::new(FakeRunner::new().push_response(CommandOutput::from_stdout(DESCRIBE_SAMPLE)));
        let client = client_with(runner);

        let groups = client.list_security_groups().unwrap();
        assert_eq!(groups.len(), 1);

        let g = &groups[0];
        assert_eq!(g.id.as_deref(), Some("sg-903004f8"));
        assert_eq!(g.name, "ssh-allowed");
        assert_eq!(g.description, "Allows SSH access");
        assert_eq!(g.provider, CloudProvider::Aws);

        // 1 ingress (tcp/22 from 203.0.113.0/24) + 1 egress (all -> 0.0.0.0/0)
        assert_eq!(g.ingress_rules().len(), 1);
        assert_eq!(g.egress_rules().len(), 1);

        let ssh = g.rules.iter().find(|r| r.is_ingress).unwrap();
        assert_eq!(ssh.protocol, Protocol::Tcp);
        assert_eq!(ssh.port_range, Some(PortRange::single(22)));
        assert_eq!(ssh.cidr, "203.0.113.0/24");
        assert_eq!(ssh.description, "SSH from corp");
        assert_eq!(ssh.action, RuleAction::Allow);

        let egress = g.rules.iter().find(|r| !r.is_ingress).unwrap();
        assert_eq!(egress.protocol, Protocol::All);
        assert_eq!(egress.port_range, None);
        assert_eq!(egress.cidr, "0.0.0.0/0");
    }

    #[test]
    fn get_returns_not_found_for_empty_result() {
        let runner = Arc::new(
            FakeRunner::new()
                .push_response(CommandOutput::from_stdout(r#"{"SecurityGroups": []}"#)),
        );
        let client = client_with(runner);
        let err = client.get_security_group("sg-missing").unwrap_err();
        assert!(matches!(err, Error::ProviderNotFound(_)), "{err:?}");
    }

    #[test]
    fn create_falls_back_to_minimal_group_when_fetch_fails() {
        // create returns GroupId, but the follow-up describe errors — we still
        // hand back a group with the minted ID.
        let runner = Arc::new(
            FakeRunner::new()
                .push_response(CommandOutput::from_stdout(CREATE_SAMPLE))
                .push_result(Err(toride_runner::Error::Other("boom".to_string()))),
        );
        let client = client_with(runner);
        let g = client.create_security_group("n", "d", None).unwrap();
        assert_eq!(g.id.as_deref(), Some("sg-903004f8"));
        assert_eq!(g.name, "n");
    }

    // ---- helpers ----

    #[test]
    fn parse_protocol_variants() {
        assert_eq!(parse_protocol("tcp"), Protocol::Tcp);
        assert_eq!(parse_protocol("udp"), Protocol::Udp);
        assert_eq!(parse_protocol("icmp"), Protocol::Icmp);
        assert_eq!(parse_protocol("icmpv6"), Protocol::Icmp);
        assert_eq!(parse_protocol("-1"), Protocol::All);
        assert_eq!(parse_protocol(""), Protocol::All);
        assert!(matches!(parse_protocol("50"), Protocol::Other(50)));
    }

    #[test]
    fn parses_sg_reference_sources() {
        // A permission with UserIdGroupPairs (reference to another SG)
        // should round-trip through the cidr slot as sg:<id>.
        let json = r#"{
            "SecurityGroups": [{
                "GroupId": "sg-a", "GroupName": "g", "Description": "",
                "IpPermissions": [{
                    "IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
                    "UserIdGroupPairs": [{ "GroupId": "sg-b", "Description": "from b" }]
                }],
                "IpPermissionsEgress": []
            }]
        }"#;
        let runner = Arc::new(FakeRunner::new().push_response(CommandOutput::from_stdout(json)));
        let client = client_with(runner);
        let groups = client.list_security_groups().unwrap();
        let rule = &groups[0].rules[0];
        assert_eq!(rule.cidr, "sg:sg-b");
        assert_eq!(rule.description, "from b");
    }
}
