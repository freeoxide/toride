//! GCP firewall rule management.
//!
//! Provides typed wrappers around the `gcloud` CLI for managing GCP firewall
//! rules and VPC network configuration.
//!
//! Each GCP VPC firewall rule is modelled as a [`SecurityGroup`] whose
//! `rules` vector holds the parsed `allowed`/`denied` protocol+port tuples.
//! Commands are built as [`toride_runner::CommandSpec`]s and executed through
//! the injected [`Runner`](toride_runner::Runner), which makes the whole
//! surface unit-testable via [`toride_runner::FakeRunner`].

use std::sync::Arc;

use serde::Deserialize;

use crate::CloudProvider;
use crate::error::{Error, Result};
use crate::spec::{FirewallRule, PortRange, Protocol, RuleAction, SecurityGroup};
use toride_runner::{CommandOutput, CommandSpec, DuctRunner, Runner};

// ---------------------------------------------------------------------------
// GcpClient
// ---------------------------------------------------------------------------

/// Client for managing GCP firewall rules.
///
/// Delegates command execution to the `gcloud` CLI through a swappable
/// [`Runner`]. Production code uses [`DuctRunner`] (the default); tests inject
/// a [`toride_runner::FakeRunner`] via [`GcpClient::with_runner`].
pub struct GcpClient {
    /// GCP project ID.
    pub project: String,
    /// GCP region or zone.
    pub region: Option<String>,
    /// The command executor used to shell out to `gcloud`.
    runner: Arc<dyn Runner>,
}

impl GcpClient {
    /// Create a new GCP client for the given project, backed by a real
    /// [`DuctRunner`].
    #[must_use]
    pub fn new(project: impl Into<String>) -> Self {
        Self {
            project: project.into(),
            region: None,
            runner: Arc::new(DuctRunner),
        }
    }

    /// Create a new GCP client for the given project with an injected runner
    /// (used by tests to feed canned `gcloud` output).
    #[must_use]
    pub fn with_runner(project: impl Into<String>, runner: Arc<dyn Runner>) -> Self {
        Self {
            project: project.into(),
            region: None,
            runner,
        }
    }

    /// Set the GCP region.
    #[must_use]
    pub fn with_region(mut self, region: impl Into<String>) -> Self {
        self.region = Some(region.into());
        self
    }

    /// Borrow the underlying runner (used by tests that keep a shared
    /// `Arc<FakeRunner>` to inspect recorded calls).
    #[must_use]
    pub fn runner(&self) -> &Arc<dyn Runner> {
        &self.runner
    }

    /// Append the global `gcloud` subcommand path shared by every operation.
    ///
    /// `sub` is the trailing verb group, e.g. `["list"]` or
    /// `["create", "my-rule"]`. The `--project` flag is appended LAST (by
    /// [`GcpClient::with_project`]) so verb-specific flags stay grouped.
    fn gcloud(sub: &[&str]) -> CommandSpec {
        let mut spec = CommandSpec::new("gcloud")
            .arg("compute")
            .arg("firewall-rules");
        for arg in sub {
            spec = spec.arg(*arg);
        }
        spec
    }

    /// Append the `--project` flag. Called after all verb-specific flags so
    /// the project argument lands at the tail of the arg list.
    fn with_project(&self, mut spec: CommandSpec) -> CommandSpec {
        spec = spec.arg("--project").arg(&self.project);
        spec
    }

    /// Run a spec through the injected runner, mapping the runner error type
    /// into the crate's [`Error`].
    fn run_checked(&self, spec: &CommandSpec) -> Result<CommandOutput> {
        self.runner
            .run_checked(spec)
            .map_err(|e| map_runner_error(&e, &spec.program))
    }

    /// List all firewall rules in the project.
    ///
    /// Runs `gcloud compute firewall-rules list --format=json`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::CommandFailed`] if the `gcloud` CLI is not installed
    /// or returns a non-zero exit code, or [`Error::ConfigParse`] if the JSON
    /// output cannot be parsed.
    pub fn list_firewall_rules(&self) -> Result<Vec<SecurityGroup>> {
        let spec = self.with_project(Self::gcloud(&["list"]).arg("--format=json"));
        let output = self.run_checked(&spec)?;
        parse_firewall_rules(&output.stdout)
    }

    /// Get a firewall rule by name.
    ///
    /// Runs `gcloud compute firewall-rules describe NAME --format=json`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ProviderNotFound`] if the rule does not exist.
    pub fn get_firewall_rule(&self, name: &str) -> Result<SecurityGroup> {
        let spec = self.with_project(Self::gcloud(&["describe", name]).arg("--format=json"));
        // Route through `run_checked` (the only provider path here) so stderr is
        // scrubbed + capped by the runner before it can reach an error variant.
        // We then inspect the already-scrubbed message to distinguish a
        // genuinely missing resource from a transient/auth failure, and never
        // re-embed raw stderr into the mapped error.
        let output = self.runner.run_checked(&spec).map_err(|e| match &e {
            toride_runner::Error::CommandFailed { stderr, .. }
                if stderr.to_lowercase().contains("not found") =>
            {
                Error::ProviderNotFound(format!("firewall rule {name} not found"))
            }
            _ => map_runner_error(&e, &spec.program),
        })?;
        let mut group = parse_one_firewall_rule(&output.stdout)?;
        group.name = name.to_string();
        Ok(group)
    }

    /// Create a new firewall rule.
    ///
    /// Runs `gcloud compute firewall-rules create NAME ...` with one
    /// `--allow`/`--action` + `--rules` pair derived from the supplied
    /// [`FirewallRule`]s. GCP models a single named rule as a list of
    /// allowed/denied protocol+port tuples, so all `rules` are folded into one
    /// create call.
    ///
    /// # Errors
    ///
    /// Returns [`Error::CommandFailed`] if creation fails.
    pub fn create_firewall_rule(
        &self,
        name: &str,
        network: &str,
        rules: &[FirewallRule],
    ) -> Result<SecurityGroup> {
        let spec = build_mutation_spec(self, "create", Some(name), Some(network), rules)?;
        self.run_checked(&spec)?;

        // Reconstruct the group from the inputs; `create` does not reliably
        // echo the numeric `id` on stdout without a format flag, and a follow-
        // up `describe` round-trip would double the CLI calls. We return the
        // caller's view of the rule.
        let mut group = SecurityGroup::new(name, CloudProvider::Gcp);
        group.description = first_description(rules);
        group.rules = rules.to_vec();
        Ok(group)
    }

    /// Delete a firewall rule by name.
    ///
    /// Runs `gcloud compute firewall-rules delete NAME`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::CommandFailed`] if deletion fails.
    pub fn delete_firewall_rule(&self, name: &str) -> Result<()> {
        let spec = self.with_project(Self::gcloud(&["delete", name]).arg("--quiet"));
        self.run_checked(&spec)?;
        Ok(())
    }

    /// Update an existing firewall rule.
    ///
    /// Runs `gcloud compute firewall-rules update NAME ...` mirroring the
    /// flag set used by [`Self::create_firewall_rule`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::CommandFailed`] if the update fails.
    pub fn update_firewall_rule(&self, name: &str, rules: &[FirewallRule]) -> Result<()> {
        let spec = build_mutation_spec(self, "update", Some(name), None, rules)?;
        self.run_checked(&spec)?;
        Ok(())
    }
}

/// Build a `create`/`update` [`CommandSpec`] from the caller's [`FirewallRule`]s.
///
/// Factored out so both mutations share identical flag rendering.
fn build_mutation_spec(
    client: &GcpClient,
    verb: &str,
    name: Option<&str>,
    network: Option<&str>,
    rules: &[FirewallRule],
) -> Result<CommandSpec> {
    let mut sub: Vec<&str> = vec![verb];
    if let Some(n) = name {
        sub.push(n);
    }
    let mut spec = GcpClient::gcloud(&sub);

    // GCP requires either `--allow` or (`--action` + `--rules`). A single
    // firewall rule can carry multiple protocol/port tuples comma-joined into
    // one value. Allow rules use `--allow`; deny rules use `--action=DENY
    // --rules` (the path the gcloud reference documents for deny).
    let allow_tokens: Vec<String> = rules
        .iter()
        .filter(|r| r.action == RuleAction::Allow)
        .map(render_protocol_port)
        .collect();
    let deny_tokens: Vec<String> = rules
        .iter()
        .filter(|r| r.action == RuleAction::Deny)
        .map(render_protocol_port)
        .collect();

    // A single GCP firewall rule has exactly one action, so mixing Allow and
    // Deny in one mutation cannot be represented in a single `create`/`update`
    // call. Reject it explicitly rather than silently dropping the Deny rules
    // (the previous behaviour lost data without warning).
    if !allow_tokens.is_empty() && !deny_tokens.is_empty() {
        return Err(Error::Other(format!(
            "GCP firewall rule {name_desc} mixes Allow and Deny actions; \
             create/update accepts only one action per rule",
            name_desc = name.unwrap_or("")
        )));
    }

    if !allow_tokens.is_empty() {
        spec = spec.arg("--allow").arg(allow_tokens.join(","));
    } else if !deny_tokens.is_empty() {
        spec = spec
            .arg("--action=DENY")
            .arg("--rules")
            .arg(deny_tokens.join(","));
    } else {
        // No protocols specified: keep the rule well-formed with the gcloud
        // default-expanding form.
        spec = spec.arg("--allow").arg("all");
    }

    if let Some(network) = network {
        spec = spec.arg("--network").arg(network);
    }

    // GCP create/update take a single direction per rule; derive it from the
    // first rule (the domain model groups rules meant to share an entry).
    if let Some(first) = rules.first() {
        let direction = if first.is_ingress {
            "INGRESS"
        } else {
            "EGRESS"
        };
        spec = spec.arg("--direction").arg(direction);

        let cidrs: Vec<&str> = rules.iter().map(|r| r.cidr.as_str()).collect();
        if first.is_ingress {
            spec = spec.arg("--source-ranges").arg(cidrs.join(","));
        } else {
            spec = spec.arg("--destination-ranges").arg(cidrs.join(","));
        }

        if let Some(desc) = rules.iter().find_map(nonempty_description) {
            spec = spec.arg("--description").arg(desc);
        }
    }

    Ok(client.with_project(spec))
}

// ---------------------------------------------------------------------------
// CLI -> domain mapping helpers (file-local to avoid parse.rs conflicts)
// ---------------------------------------------------------------------------

/// Map a runner error into the crate's error type.
///
/// `BinaryNotFound` is preserved semantically; everything else becomes a
/// [`Error::CommandFailed`] keyed on `program`.
fn map_runner_error(e: &toride_runner::Error, program: &str) -> Error {
    match e {
        toride_runner::Error::BinaryNotFound(bin) => Error::BinaryNotFound(bin.clone()),
        other => Error::CommandFailed {
            program: program.to_string(),
            message: other.to_string(),
        },
    }
}

/// Return the first non-empty description among `rules`, or `""`.
fn first_description(rules: &[FirewallRule]) -> String {
    rules
        .iter()
        .find_map(nonempty_description)
        .unwrap_or_default()
}

/// If `r.description` is non-empty, return it (owned); else `None`.
fn nonempty_description(r: &FirewallRule) -> Option<String> {
    if r.description.is_empty() {
        None
    } else {
        Some(r.description.clone())
    }
}

/// Render a [`FirewallRule`]'s protocol+port in gcloud's
/// `PROTOCOL[:PORT[-PORT]]` tuple syntax (e.g. `tcp:443`, `tcp:8000-8999`,
/// `icmp`).
fn render_protocol_port(rule: &FirewallRule) -> String {
    match (rule.protocol, rule.port_range) {
        (Protocol::All, _) => "all".to_string(),
        (proto, None) => proto.to_string(),
        (proto, Some(range)) => format!("{proto}:{range}"),
    }
}

// --- serde helper structs mirroring the gcloud --format=json shape --------
//
// Shape (per `gcloud compute firewall-rules list/describe --format=json`):
//   {
//     "id": "1234567890123456789",
//     "name": "allow-ssh",
//     "network": ".../global/networks/default",
//     "priority": 1000,
//     "direction": "INGRESS" | "EGRESS",
//     "disabled": false,
//     "description": "...",
//     "allowed": [ {"IPProtocol":"tcp","ports":["22","80-443"]} ],
//     "denied":   [ {"IPProtocol":"icmp"} ],
//     "sourceRanges": ["0.0.0.0/0"],
//     "destinationRanges": [...],
//     "targetTags": ["web"]
//   }
//
// Source: https://docs.cloud.google.com/sdk/gcloud/reference/compute/firewall-rules/list

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct RawFirewall {
    #[serde(default)]
    id: Option<String>,
    name: String,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    direction: Option<String>,
    #[serde(default)]
    allowed: Vec<RawAllow>,
    #[serde(default)]
    denied: Vec<RawAllow>,
    #[serde(default, rename = "sourceRanges")]
    source_ranges: Option<Vec<String>>,
    #[serde(default, rename = "destinationRanges")]
    destination_ranges: Option<Vec<String>>,
    #[serde(default, rename = "targetTags")]
    target_tags: Option<Vec<String>>,
    #[serde(default)]
    network: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawAllow {
    #[serde(rename = "IPProtocol")]
    ip_protocol: String,
    #[serde(default)]
    ports: Option<Vec<String>>,
}

/// Parse the JSON array emitted by `gcloud ... list --format=json`.
fn parse_firewall_rules(json: &str) -> Result<Vec<SecurityGroup>> {
    let trimmed = json.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    let raw: Vec<RawFirewall> = serde_json::from_str(trimmed).map_err(|e| {
        Error::ConfigParse(format!(
            "failed to parse gcloud firewall-rules list output: {e}"
        ))
    })?;
    Ok(raw.into_iter().map(raw_to_group).collect::<Vec<_>>())
}

/// Parse the single JSON object emitted by `gcloud ... describe --format=json`.
fn parse_one_firewall_rule(json: &str) -> Result<SecurityGroup> {
    let trimmed = json.trim();
    if trimmed.is_empty() {
        return Err(Error::ProviderNotFound(
            "firewall rule not found (empty describe output)".to_string(),
        ));
    }
    let raw: RawFirewall = serde_json::from_str(trimmed).map_err(|e| {
        Error::ConfigParse(format!(
            "failed to parse gcloud firewall-rules describe output: {e}"
        ))
    })?;
    Ok(raw_to_group(raw))
}

/// Convert a raw gcloud firewall rule into a [`SecurityGroup`].
///
/// Each `allowed`/`denied` entry fans out into one [`FirewallRule`] per
/// port (range), since the domain model carries a single port range per rule.
fn raw_to_group(raw: RawFirewall) -> SecurityGroup {
    let RawFirewall {
        id,
        name,
        description,
        direction,
        allowed,
        denied,
        source_ranges,
        destination_ranges,
        network,
        target_tags: _,
    } = raw;

    let is_ingress = direction
        .as_deref()
        .is_none_or(|d| d.eq_ignore_ascii_case("INGRESS") || d.eq_ignore_ascii_case("IN"));

    // Pick the CIDR list: ingress uses sourceRanges, egress uses
    // destinationRanges. Default to 0.0.0.0/0 only when neither was present
    // AND the rule is ingress (matching gcloud's documented default).
    let cidrs: Vec<String> = if is_ingress {
        source_ranges.unwrap_or_else(|| vec!["0.0.0.0/0".to_string()])
    } else {
        destination_ranges.unwrap_or_default()
    };

    let description_default = description.unwrap_or_default();
    let id_ref = id.as_ref();
    let desc_ref = &description_default;

    let mut rules: Vec<FirewallRule> = Vec::new();
    for entry in &allowed {
        push_rules(
            &mut rules,
            entry,
            id_ref,
            desc_ref,
            is_ingress,
            &cidrs,
            RuleAction::Allow,
        );
    }
    for entry in &denied {
        push_rules(
            &mut rules,
            entry,
            id_ref,
            desc_ref,
            is_ingress,
            &cidrs,
            RuleAction::Deny,
        );
    }

    let mut tags = Vec::new();
    if let Some(network) = &network {
        // Store the network as a ("network", value) tag for traceability
        // without inventing new public fields.
        tags.push(("network".to_string(), network.clone()));
    }

    SecurityGroup {
        id,
        name,
        description: description_default,
        provider: CloudProvider::Gcp,
        rules,
        tags,
    }
}

/// Fan one `allowed`/`denied` entry out into one or more [`FirewallRule`]s.
#[allow(clippy::too_many_arguments)]
fn push_rules(
    rules: &mut Vec<FirewallRule>,
    entry: &RawAllow,
    id: Option<&String>,
    description: &str,
    is_ingress: bool,
    cidrs: &[String],
    action: RuleAction,
) {
    let protocol = parse_protocol(&entry.ip_protocol);
    let ports = entry.ports.as_deref().unwrap_or(&[]);
    let primary_cidr = cidrs.first().cloned().unwrap_or_default();

    if ports.is_empty() {
        // No ports (e.g. icmp, or "all ports" implied). One rule covering all
        // ports -- or no port range for non-port protocols.
        rules.push(FirewallRule {
            id: id.cloned(),
            description: description.to_string(),
            is_ingress,
            protocol,
            port_range: None,
            cidr: primary_cidr,
            action,
        });
        return;
    }

    for port_token in ports {
        let port_range = parse_port_token(port_token);
        rules.push(FirewallRule {
            id: id.cloned(),
            description: description.to_string(),
            is_ingress,
            protocol,
            port_range,
            cidr: primary_cidr.clone(),
            action,
        });
    }
}

/// Parse a gcloud protocol string into [`Protocol`].
fn parse_protocol(s: &str) -> Protocol {
    match s.to_ascii_lowercase().as_str() {
        "tcp" => Protocol::Tcp,
        "udp" => Protocol::Udp,
        "icmp" => Protocol::Icmp,
        "all" => Protocol::All,
        other => match other.parse::<u8>() {
            Ok(n) => Protocol::Other(n),
            Err(_) => Protocol::All,
        },
    }
}

/// Parse a single gcloud port token (`"22"`, `"80-443"`) into a
/// [`Option<PortRange>`]. Returns `None` for malformed input rather than
/// panicking.
fn parse_port_token(token: &str) -> Option<PortRange> {
    let token = token.trim();
    if token.is_empty() {
        return None;
    }
    if let Some((start_s, end_s)) = token.split_once('-') {
        let start = start_s.trim().parse::<u16>().ok()?;
        let end = end_s.trim().parse::<u16>().ok()?;
        Some(PortRange::range(start, end))
    } else {
        let single = token.parse::<u16>().ok()?;
        Some(PortRange::single(single))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use toride_runner::FakeRunner;

    /// Real-shape JSON sample for `gcloud compute firewall-rules list
    /// --format=json`, sourced from the official gcloud reference and its
    /// documented output shape.
    ///
    /// Source: <https://docs.cloud.google.com/sdk/gcloud/reference/compute/firewall-rules/list>
    /// (field names: `allowed[].IPProtocol`, `allowed[].ports`, sourceRanges,
    ///  direction, priority, id, name, network, description)
    const LIST_JSON: &str = r#"[
      {
        "allowed": [
          {
            "IPProtocol": "tcp",
            "ports": ["22", "80", "443"]
          }
        ],
        "description": "Allow SSH, HTTP, and HTTPS",
        "direction": "INGRESS",
        "disabled": false,
        "id": "1234567890123456789",
        "kind": "compute#firewall",
        "name": "allow-ssh-http-https",
        "network": "https://www.googleapis.com/compute/v1/projects/my-project/global/networks/default",
        "priority": 1000,
        "selfLink": "https://www.googleapis.com/compute/v1/projects/my-project/global/firewalls/allow-ssh-http-https",
        "sourceRanges": ["0.0.0.0/0"],
        "targetTags": ["web"]
      },
      {
        "allowed": [
          {
            "IPProtocol": "icmp"
          },
          {
            "IPProtocol": "tcp",
            "ports": ["0-65535"]
          },
          {
            "IPProtocol": "udp",
            "ports": ["0-65535"]
          }
        ],
        "direction": "INGRESS",
        "name": "allow-internal",
        "network": "https://www.googleapis.com/compute/v1/projects/my-project/global/networks/default",
        "priority": 65534,
        "sourceRanges": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
      }
    ]"#;

    /// Real-shape JSON for `gcloud compute firewall-rules describe NAME
    /// --format=json` (same object shape, singular).
    const DESCRIBE_JSON: &str = r#"{
        "allowed": [
          {
            "IPProtocol": "tcp",
            "ports": ["443"]
          }
        ],
        "description": "Allow HTTPS",
        "direction": "INGRESS",
        "id": "42",
        "name": "allow-https",
        "network": "https://www.googleapis.com/compute/v1/projects/my-project/global/networks/default",
        "priority": 1000,
        "sourceRanges": ["0.0.0.0/0"]
      }"#;

    /// Build a client backed by a `FakeRunner` shared with the test so recorded
    /// calls can be inspected via the returned `Arc<FakeRunner>`.
    fn client_with(runner: FakeRunner) -> (GcpClient, Arc<FakeRunner>) {
        let shared = Arc::new(runner);
        let client = GcpClient::with_runner("my-project", shared.clone() as Arc<dyn Runner>);
        (client, shared)
    }

    #[test]
    fn parses_real_list_json_into_security_groups() {
        // Source: https://docs.cloud.google.com/sdk/gcloud/reference/compute/firewall-rules/list
        let runner = FakeRunner::new().strict().respond(
            CommandSpec::new("gcloud").args([
                "compute",
                "firewall-rules",
                "list",
                "--format=json",
                "--project",
                "my-project",
            ]),
            CommandOutput::from_stdout(LIST_JSON),
        );
        let (client, _) = client_with(runner);

        let groups = client.list_firewall_rules().expect("parse ok");
        assert_eq!(groups.len(), 2, "two firewall rules from sample");

        let first = &groups[0];
        assert_eq!(first.name, "allow-ssh-http-https");
        assert_eq!(first.id.as_deref(), Some("1234567890123456789"));
        assert_eq!(first.description, "Allow SSH, HTTP, and HTTPS");
        assert_eq!(first.provider, CloudProvider::Gcp);
        // ssh/http/https fan out into 3 rules.
        assert_eq!(first.rules.len(), 3);
        let ssh = first
            .rules
            .iter()
            .find(|r| r.port_range == Some(PortRange::single(22)))
            .expect("ssh rule present");
        assert_eq!(ssh.protocol, Protocol::Tcp);
        assert!(ssh.is_ingress);
        assert_eq!(ssh.cidr, "0.0.0.0/0");
        assert_eq!(ssh.action, RuleAction::Allow);

        // Second rule: icmp + tcp:0-65535 + udp:0-65535 => 3 rules.
        let second = &groups[1];
        assert_eq!(second.name, "allow-internal");
        assert_eq!(second.rules.len(), 3);
        let tcp_range = second
            .rules
            .iter()
            .find(|r| r.protocol == Protocol::Tcp)
            .expect("tcp rule present");
        assert_eq!(tcp_range.port_range, Some(PortRange::range(0, 65535)));
        // First listed CIDR is attached as the source.
        assert_eq!(tcp_range.cidr, "10.0.0.0/8");
        let icmp = second
            .rules
            .iter()
            .find(|r| r.protocol == Protocol::Icmp)
            .expect("icmp rule present");
        assert!(icmp.port_range.is_none());
    }

    #[test]
    fn parses_real_describe_json_into_security_group() {
        // Source: https://docs.cloud.google.com/sdk/gcloud/reference/compute/firewall-rules/list
        // (describe returns the same object shape, singular).
        let runner = FakeRunner::new().push_response(CommandOutput::from_stdout(DESCRIBE_JSON));
        let (client, _) = client_with(runner);

        let group = client
            .get_firewall_rule("allow-https")
            .expect("describe ok");
        assert_eq!(group.name, "allow-https");
        assert_eq!(group.id.as_deref(), Some("42"));
        assert_eq!(group.rules.len(), 1);
        let rule = &group.rules[0];
        assert_eq!(rule.protocol, Protocol::Tcp);
        assert_eq!(rule.port_range, Some(PortRange::single(443)));
        assert_eq!(rule.cidr, "0.0.0.0/0");
    }

    #[test]
    fn get_firewall_rule_maps_missing_to_provider_not_found() {
        // When `gcloud describe` exits non-zero on a nonexistent rule, the
        // runner returns a failed output; we surface ProviderNotFound.
        let runner = FakeRunner::new().push_response(CommandOutput::from_stderr(
            "ERROR: (gcloud.compute.firewall-rules.describe) Could not fetch resource: Not Found",
            1,
        ));
        let (client, _) = client_with(runner);

        let err = client
            .get_firewall_rule("nope")
            .expect_err("missing rule errors");
        assert!(
            matches!(err, Error::ProviderNotFound(ref m) if m.contains("nope")),
            "expected ProviderNotFound, got {err:?}"
        );
    }

    #[test]
    fn list_builds_exact_command() {
        // Asserts the exact program+args built for `list`.
        // Source: https://docs.cloud.google.com/sdk/gcloud/reference/compute/firewall-rules/list
        let runner = FakeRunner::new().push_response(CommandOutput::from_stdout("[]"));
        let (client, shared) = client_with(runner);

        let _ = client.list_firewall_rules();

        let calls = shared.calls();
        assert!(
            calls.iter().any(|c| c.program == "gcloud"
                && c.args
                    == [
                        "compute".to_string(),
                        "firewall-rules".to_string(),
                        "list".to_string(),
                        "--format=json".to_string(),
                        "--project".to_string(),
                        "my-project".to_string()
                    ]),
            "list command mismatch: {calls:?}"
        );
    }

    #[test]
    fn create_builds_exact_command() {
        // Asserts the exact program+args built for `create` with an ingress
        // allow rule carrying a source range.
        //
        // Source: https://docs.cloud.google.com/sdk/gcloud/reference/compute/firewall-rules/create
        //   gcloud compute firewall-rules create NAME --allow=tcp:8080 \
        //     --source-ranges=... --network=default --direction=INGRESS
        let runner = FakeRunner::new().push_response(CommandOutput::from_stdout(""));
        let (client, shared) = client_with(runner);

        let rule = FirewallRule {
            id: None,
            description: "Allow incoming traffic on TCP port 8080".to_string(),
            is_ingress: true,
            protocol: Protocol::Tcp,
            port_range: Some(PortRange::single(8080)),
            cidr: "0.0.0.0/0".to_string(),
            action: RuleAction::Allow,
        };

        let group = client
            .create_firewall_rule("example-service", "default", &[rule])
            .expect("create ok");
        assert_eq!(group.name, "example-service");
        assert_eq!(group.rules.len(), 1);

        let calls = shared.calls();
        let create_call = calls
            .iter()
            .find(|c| {
                c.args.first().is_some_and(|a| a == "compute")
                    && c.args.get(2) == Some(&"create".to_string())
            })
            .expect("a create call was made");
        assert_eq!(create_call.program, "gcloud");
        assert_eq!(
            create_call.args,
            [
                "compute".to_string(),
                "firewall-rules".to_string(),
                "create".to_string(),
                "example-service".to_string(),
                "--allow".to_string(),
                "tcp:8080".to_string(),
                "--network".to_string(),
                "default".to_string(),
                "--direction".to_string(),
                "INGRESS".to_string(),
                "--source-ranges".to_string(),
                "0.0.0.0/0".to_string(),
                "--description".to_string(),
                "Allow incoming traffic on TCP port 8080".to_string(),
                "--project".to_string(),
                "my-project".to_string(),
            ]
        );
    }

    #[test]
    fn create_deny_uses_action_flag() {
        // A Deny rule must emit --action=DENY --rules=... per the gcloud
        // create reference (which requires --action + --rules together for
        // deny).
        let runner = FakeRunner::new().push_response(CommandOutput::from_stdout(""));
        let (client, shared) = client_with(runner);

        let rule = FirewallRule {
            id: None,
            description: String::new(),
            is_ingress: true,
            protocol: Protocol::Tcp,
            port_range: Some(PortRange::single(22)),
            cidr: "10.0.0.0/8".to_string(),
            action: RuleAction::Deny,
        };

        let _ = client.create_firewall_rule("deny-ssh", "default", &[rule]);
        let calls = shared.calls();
        let create_call = calls
            .iter()
            .find(|c| c.args.get(2) == Some(&"create".to_string()))
            .expect("create call");
        assert!(
            create_call
                .args
                .windows(2)
                .any(|w| w[0] == "--action=DENY" && w[1] == "--rules"),
            "deny rule must set --action=DENY + --rules: {:?}",
            create_call.args
        );
    }

    #[test]
    fn create_with_mixed_allow_and_deny_errors() {
        // GCP can only represent one action per firewall rule, so mixing
        // Allow and Deny in a single create/update must surface an error
        // instead of silently dropping the Deny rules.
        let runner = FakeRunner::new().push_response(CommandOutput::from_stdout(""));
        let (client, _) = client_with(runner);

        let allow = FirewallRule {
            id: None,
            description: String::new(),
            is_ingress: true,
            protocol: Protocol::Tcp,
            port_range: Some(PortRange::single(22)),
            cidr: "0.0.0.0/0".to_string(),
            action: RuleAction::Allow,
        };
        let deny = FirewallRule {
            id: None,
            description: String::new(),
            is_ingress: true,
            protocol: Protocol::Tcp,
            port_range: Some(PortRange::single(23)),
            cidr: "0.0.0.0/0".to_string(),
            action: RuleAction::Deny,
        };

        let err = client
            .create_firewall_rule("mixed", "default", &[allow, deny])
            .expect_err("mixed actions must error");
        assert!(
            matches!(err, Error::Other(_)),
            "expected Other, got {err:?}"
        );
    }

    #[test]
    fn delete_builds_exact_command() {
        // Source: `gcloud compute firewall-rules delete NAME` (gcloud
        // reference, delete verb). --quiet skips the interactive prompt.
        let runner = FakeRunner::new().push_response(CommandOutput::from_stdout(""));
        let (client, shared) = client_with(runner);

        client
            .delete_firewall_rule("stale-rule")
            .expect("delete ok");

        let calls = shared.calls();
        let delete_call = calls
            .iter()
            .find(|c| c.args.get(2) == Some(&"delete".to_string()))
            .expect("delete call made");
        assert_eq!(delete_call.program, "gcloud");
        assert_eq!(
            delete_call.args,
            [
                "compute".to_string(),
                "firewall-rules".to_string(),
                "delete".to_string(),
                "stale-rule".to_string(),
                "--quiet".to_string(),
                "--project".to_string(),
                "my-project".to_string(),
            ]
        );
    }

    #[test]
    fn update_builds_exact_command() {
        // Source: `gcloud compute firewall-rules update NAME --allow=...`
        let runner = FakeRunner::new().push_response(CommandOutput::from_stdout(""));
        let (client, shared) = client_with(runner);

        let rule = FirewallRule {
            id: None,
            description: String::new(),
            is_ingress: true,
            protocol: Protocol::Tcp,
            port_range: Some(PortRange::range(8000, 8999)),
            cidr: "10.0.0.0/8".to_string(),
            action: RuleAction::Allow,
        };
        client
            .update_firewall_rule("example-service", &[rule])
            .expect("update ok");

        let calls = shared.calls();
        let update_call = calls
            .iter()
            .find(|c| c.args.get(2) == Some(&"update".to_string()))
            .expect("update call");
        assert!(
            update_call
                .args
                .windows(2)
                .any(|w| w[0] == "--allow" && w[1] == "tcp:8000-8999"),
            "update must render --allow tcp:8000-8999: {:?}",
            update_call.args
        );
        assert!(
            update_call.args.iter().any(|a| a == "--direction")
                && update_call.args.iter().any(|a| a == "INGRESS"),
            "update must set INGRESS direction: {:?}",
            update_call.args
        );
    }

    #[test]
    fn commands_are_not_redacted() {
        // gcloud reads credentials from config/env, so none of the built
        // commands should set .redact(true). specs_match now enforces redact,
        // so verifying this guards against over-redaction regressions.
        let runner = FakeRunner::new()
            .push_response(CommandOutput::from_stdout("[]"))
            .push_response(CommandOutput::from_stdout(""));
        let (client, shared) = client_with(runner);
        let _ = client.list_firewall_rules();
        let rule = FirewallRule {
            id: None,
            description: String::new(),
            is_ingress: true,
            protocol: Protocol::Tcp,
            port_range: Some(PortRange::single(22)),
            cidr: "0.0.0.0/0".to_string(),
            action: RuleAction::Allow,
        };
        let _ = client.create_firewall_rule("r", "default", &[rule]);

        for call in shared.calls() {
            assert!(
                !call.redact,
                "gcloud command should not be redacted (no inline secret): {call:?}"
            );
        }
    }

    #[test]
    fn empty_list_output_yields_empty_vec() {
        let runner = FakeRunner::new().push_response(CommandOutput::from_stdout(""));
        let (client, _) = client_with(runner);
        let groups = client.list_firewall_rules().expect("empty ok");
        assert!(groups.is_empty());
    }

    #[test]
    fn malformed_list_json_is_config_parse_error() {
        let runner = FakeRunner::new().push_response(CommandOutput::from_stdout("not json"));
        let (client, _) = client_with(runner);
        let err = client.list_firewall_rules().expect_err("bad json errors");
        assert!(matches!(err, Error::ConfigParse(_)), "got {err:?}");
    }

    #[test]
    fn render_protocol_port_covers_ranges() {
        let mk = |proto, pr: Option<PortRange>| {
            render_protocol_port(&FirewallRule {
                id: None,
                description: String::new(),
                is_ingress: true,
                protocol: proto,
                port_range: pr,
                cidr: String::new(),
                action: RuleAction::Allow,
            })
        };
        assert_eq!(mk(Protocol::Tcp, Some(PortRange::single(443))), "tcp:443");
        assert_eq!(
            mk(Protocol::Tcp, Some(PortRange::range(8000, 8999))),
            "tcp:8000-8999"
        );
        assert_eq!(mk(Protocol::Icmp, None), "icmp");
        assert_eq!(mk(Protocol::All, None), "all");
    }

    #[test]
    fn parse_port_token_handles_single_and_range() {
        assert_eq!(parse_port_token("22"), Some(PortRange::single(22)));
        assert_eq!(
            parse_port_token("8000-8999"),
            Some(PortRange::range(8000, 8999))
        );
        assert_eq!(parse_port_token(""), None);
        assert_eq!(parse_port_token("abc"), None);
    }
}
