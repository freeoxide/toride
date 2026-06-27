//! DigitalOcean firewall management.
//!
//! Provides typed wrappers around the `doctl` CLI for managing DigitalOcean
//! cloud firewalls and their rules.
//!
//! Every operation shells out via [`toride_runner::CommandSpec`] and parses the
//! provider's JSON output into the provider-agnostic
//! [`SecurityGroup`](crate::spec::SecurityGroup) /
//! [`FirewallRule`](crate::spec::FirewallRule) model.
//!
//! # CLI reference
//!
//! - list:   `doctl compute firewall list --format JSON`
//! - get:    `doctl compute firewall get <id> --format JSON`
//! - create: `doctl compute firewall create --name <n> [--inbound-rules ...] [--outbound-rules ...]`
//! - delete: `doctl compute firewall delete <id>`
//! - add:    `doctl compute firewall add-rules <id> [--inbound-rules ...] [--outbound-rules ...]`
//! - remove: `doctl compute firewall remove-rules <id> [--inbound-rules ...] [--outbound-rules ...]`

use crate::error::{Error, Result};
use crate::spec::{FirewallRule, PortRange, Protocol, RuleAction, SecurityGroup};
use crate::CloudProvider;
use toride_runner::{CommandSpec, DuctRunner, Runner};

/// Map a [`toride_runner::Error`] into the crate's [`Error`] type.
///
/// Kept file-local (rather than a blanket `From` impl on `error::Error`) so
/// the conversion stays opt-in and does not collide with sibling provider
/// modules. `CommandFailed` carrying a "conflict" message is promoted to
/// [`Error::FirewallRuleConflict`] by the callers that care.
fn map_runner_err(err: toride_runner::Error) -> Error {
    match err {
        toride_runner::Error::BinaryNotFound(name) => Error::BinaryNotFound(name),
        toride_runner::Error::Io(msg) => Error::Other(msg),
        toride_runner::Error::CommandFailed {
            program,
            stderr,
            ..
        } => Error::CommandFailed {
            program,
            message: stderr,
        },
        toride_runner::Error::CommandTimeout { program, .. } => Error::CommandFailed {
            program,
            message: "command timed out".to_string(),
        },
        toride_runner::Error::SpawnFailed { program, detail } => {
            Error::BinaryNotFound(format!("{program}: {detail}"))
        }
        other => Error::Other(other.to_string()),
    }
}

// ---------------------------------------------------------------------------
// JSON helpers (file-local to avoid collisions with parse.rs)
// ---------------------------------------------------------------------------

/// Shape of `doctl ... --format JSON` firewall output.
///
/// Source: <https://docs.digitalocean.com/reference/api/reference/firewalls/>
/// and <https://docs.digitalocean.com/reference/doctl/reference/compute/firewall/list/>
#[derive(Debug, serde::Deserialize)]
struct DoFirewall {
    id: String,
    name: String,
    #[serde(default)]
    inbound_rules: Vec<DoRule>,
    #[serde(default)]
    outbound_rules: Vec<DoRule>,
    #[serde(default)]
    droplet_ids: Vec<i64>,
    #[serde(default)]
    tags: Vec<String>,
}

/// A single DigitalOcean inbound/outbound rule.
#[derive(Debug, serde::Deserialize)]
struct DoRule {
    protocol: String,
    #[serde(default)]
    ports: String,
    #[serde(default)]
    sources: DoEndpoints,
    #[serde(default)]
    destinations: DoEndpoints,
}

/// Traffic source/destination endpoints.
///
/// Each field is optional; at least one is typically populated. Mirrors the
/// `sources` / `destinations` objects of the DigitalOcean firewall API.
/// Fields beyond `addresses` are deserialized for fidelity to the API shape
/// even when not yet surfaced into the domain model.
#[derive(Debug, Default, serde::Deserialize)]
#[allow(dead_code)]
struct DoEndpoints {
    #[serde(default)]
    addresses: Vec<String>,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    droplet_ids: Vec<i64>,
    #[serde(default)]
    load_balancer_uids: Vec<String>,
}

// ---------------------------------------------------------------------------
// DigitalOceanClient
// ---------------------------------------------------------------------------

/// Client for managing DigitalOcean firewalls.
///
/// Delegates command execution to the `doctl` CLI through an injectable
/// [`Runner`]. Production code uses [`DuctRunner`]; tests inject a
/// [`FakeRunner`](toride_runner::FakeRunner).
pub struct DigitalOceanClient<R: Runner = DuctRunner> {
    /// DigitalOcean access token (uses `doctl` config if `None`).
    pub access_token: Option<String>,
    /// Command executor used to shell out to `doctl`.
    runner: R,
}

impl DigitalOceanClient<DuctRunner> {
    /// Create a new DigitalOcean client backed by a [`DuctRunner`].
    ///
    /// Credentials are read from `doctl`'s own config unless
    /// [`with_token`](Self::with_token) supplies an access token.
    #[must_use]
    pub fn new() -> Self {
        Self {
            access_token: None,
            runner: DuctRunner,
        }
    }
}

impl Default for DigitalOceanClient<DuctRunner> {
    fn default() -> Self {
        Self::new()
    }
}

impl DigitalOceanClient<DuctRunner> {
    /// Set the access token explicitly.
    ///
    /// When set, the token is passed to `doctl` via the global `--access-token`
    /// flag on every command rather than read from config.
    #[must_use]
    pub fn with_token(mut self, token: impl Into<String>) -> Self {
        self.access_token = Some(token.into());
        self
    }
}

impl<R: Runner> DigitalOceanClient<R> {
    /// Create a client with a custom command runner (used by tests).
    #[must_use]
    pub fn with_runner(runner: R) -> Self {
        Self {
            access_token: None,
            runner,
        }
    }

    /// Replace the access token on an already-constructed client.
    #[must_use]
    pub fn set_token(mut self, token: impl Into<String>) -> Self {
        self.access_token = Some(token.into());
        self
    }

    // --- command construction ------------------------------------------------

    /// Build the `doctl` program prefix, injecting `--access-token` when one
    /// is configured. The token is a credential, so any command that carries
    /// it inline is marked `redact(true)`.
    fn base_command(&self, sub: &[&str]) -> CommandSpec {
        let mut spec = CommandSpec::new("doctl");
        if let Some(token) = &self.access_token {
            spec = spec.arg("--access-token").arg(token).redact(true);
        }
        for s in sub {
            spec = spec.arg(*s);
        }
        spec
    }

    /// `doctl compute firewall list --format JSON`.
    fn list_command(&self) -> CommandSpec {
        self.base_command(&["compute", "firewall", "list", "--format", "JSON"])
    }

    /// `doctl compute firewall get <id> --format JSON`.
    fn get_command(&self, firewall_id: &str) -> CommandSpec {
        // Positional ID directly follows the subcommand, before flags, matching
        // the documented `doctl compute firewall get <id> --format JSON`.
        self.base_command(&["compute", "firewall", "get"])
            .arg(firewall_id)
            .arg("--format")
            .arg("JSON")
    }

    /// `doctl compute firewall create ...`.
    fn create_command(
        &self,
        name: &str,
        inbound_rules: &[FirewallRule],
        outbound_rules: &[FirewallRule],
    ) -> Result<CommandSpec> {
        if inbound_rules.is_empty() && outbound_rules.is_empty() {
            return Err(Error::Other(
                "DigitalOcean firewalls require at least one inbound or outbound rule".to_string(),
            ));
        }
        let mut spec = self
            .base_command(&["compute", "firewall", "create", "--format", "JSON"])
            .arg("--name")
            .arg(name);
        if !inbound_rules.is_empty() {
            spec = spec.arg("--inbound-rules").arg(render_rules(inbound_rules, true)?);
        }
        if !outbound_rules.is_empty() {
            spec = spec
                .arg("--outbound-rules")
                .arg(render_rules(outbound_rules, false)?);
        }
        Ok(spec)
    }

    /// `doctl compute firewall delete <id>`.
    fn delete_command(&self, firewall_id: &str) -> CommandSpec {
        self.base_command(&["compute", "firewall", "delete"])
            .arg(firewall_id)
            .arg("--force")
    }

    /// `doctl compute firewall add-rules <id> ...` / `remove-rules <id> ...`.
    fn rules_command(
        &self,
        verb: &str,
        firewall_id: &str,
        rules: &[FirewallRule],
    ) -> Result<CommandSpec> {
        let (inbound, outbound): (Vec<&FirewallRule>, Vec<&FirewallRule>) =
            rules.iter().partition(|r| r.is_ingress);
        if inbound.is_empty() && outbound.is_empty() {
            return Err(Error::Other(format!(
                "no rules provided to {verb} for firewall {firewall_id}"
            )));
        }
        let mut spec = self
            .base_command(&["compute", "firewall", verb])
            .arg(firewall_id);
        if !inbound.is_empty() {
            let owned: Vec<FirewallRule> = inbound.into_iter().cloned().collect();
            spec = spec.arg("--inbound-rules").arg(render_rules(&owned, true)?);
        }
        if !outbound.is_empty() {
            let owned: Vec<FirewallRule> = outbound.into_iter().cloned().collect();
            spec = spec
                .arg("--outbound-rules")
                .arg(render_rules(&owned, false)?);
        }
        Ok(spec)
    }

    // --- public API ----------------------------------------------------------

    /// List all firewalls in the account.
    ///
    /// # Errors
    ///
    /// Returns [`Error::CommandFailed`] if the `doctl` CLI is not installed
    /// or returns a non-zero exit code, or [`Error::ConfigParse`] if the JSON
    /// output cannot be parsed.
    pub fn list_firewalls(&self) -> Result<Vec<SecurityGroup>> {
        let output = self
            .runner
            .run_checked(&self.list_command())
            .map_err(map_runner_err)?;
        parse_firewalls(&output.stdout)
    }

    /// Get a firewall by ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ProviderNotFound`] if the firewall does not exist.
    pub fn get_firewall(&self, firewall_id: &str) -> Result<SecurityGroup> {
        let output = self
            .runner
            .run_checked(&self.get_command(firewall_id))
            .map_err(map_runner_err)?;
        let groups = parse_firewalls(&output.stdout)?;
        groups
            .into_iter()
            .next()
            .ok_or_else(|| Error::ProviderNotFound(format!("firewall {firewall_id} not found")))
    }

    /// Create a new firewall.
    ///
    /// # Errors
    ///
    /// Returns [`Error::CommandFailed`] if creation fails, or [`Error::Other`]
    /// if no inbound or outbound rules are supplied (DigitalOcean requires at
    /// least one rule).
    pub fn create_firewall(
        &self,
        name: &str,
        inbound_rules: &[FirewallRule],
        outbound_rules: &[FirewallRule],
    ) -> Result<SecurityGroup> {
        let cmd = self.create_command(name, inbound_rules, outbound_rules)?;
        let output = self.runner.run_checked(&cmd).map_err(map_runner_err)?;
        let groups = parse_firewalls(&output.stdout)?;
        groups
            .into_iter()
            .next()
            .ok_or_else(|| Error::CommandFailed {
                program: "doctl".to_string(),
                message: "create returned no firewall object".to_string(),
            })
    }

    /// Delete a firewall by ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::CommandFailed`] if deletion fails.
    pub fn delete_firewall(&self, firewall_id: &str) -> Result<()> {
        let _ = self
            .runner
            .run_checked(&self.delete_command(firewall_id))
            .map_err(map_runner_err)?;
        Ok(())
    }

    /// Add rules to an existing firewall.
    ///
    /// # Errors
    ///
    /// Returns [`Error::FirewallRuleConflict`] if any rule conflicts.
    pub fn add_rules(&self, firewall_id: &str, rules: &[FirewallRule]) -> Result<()> {
        let cmd = self.rules_command("add-rules", firewall_id, rules)?;
        match self.runner.run_checked(&cmd) {
            Ok(_) => Ok(()),
            Err(toride_runner::Error::CommandFailed { stderr, .. })
                if stderr.contains("conflict") =>
            {
                Err(Error::FirewallRuleConflict(format!(
                    "rule conflict while adding rules to firewall {firewall_id}"
                )))
            }
            Err(e) => Err(map_runner_err(e)),
        }
    }

    /// Remove rules from an existing firewall.
    ///
    /// # Errors
    ///
    /// Returns [`Error::CommandFailed`] if removal fails.
    pub fn remove_rules(&self, firewall_id: &str, rules: &[FirewallRule]) -> Result<()> {
        let cmd = self.rules_command("remove-rules", firewall_id, rules)?;
        let _ = self
            .runner
            .run_checked(&cmd)
            .map_err(map_runner_err)?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// JSON parsing
// ---------------------------------------------------------------------------

/// Parse `doctl ... --format JSON` output (an array of firewall objects) into
/// [`SecurityGroup`] values.
///
/// Exposed at module scope (file-local) so it can be exercised by tests
/// without going through the runner.
fn parse_firewalls(json: &str) -> Result<Vec<SecurityGroup>> {
    let trimmed = json.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    let do_firewalls: Vec<DoFirewall> =
        serde_json::from_str(trimmed).map_err(|e| Error::ConfigParse(e.to_string()))?;
    Ok(do_firewalls.into_iter().map(firewall_to_group).collect())
}

/// Convert a provider firewall object into a [`SecurityGroup`].
fn firewall_to_group(fw: DoFirewall) -> SecurityGroup {
    let id = fw.id.clone();
    let mut group = SecurityGroup::new(fw.name, CloudProvider::DigitalOcean);
    group.id = Some(id);

    // Surface droplet_ids / tags as SecurityGroup tags for traceability.
    for did in &fw.droplet_ids {
        group.tags.push(("droplet_id".to_string(), did.to_string()));
    }
    for tag in &fw.tags {
        group.tags.push(("tag".to_string(), tag.clone()));
    }

    let mut rules = Vec::new();
    for r in fw.inbound_rules {
        for rule in expand_rule(r, true) {
            rules.push(rule);
        }
    }
    for r in fw.outbound_rules {
        for rule in expand_rule(r, false) {
            rules.push(rule);
        }
    }
    group.rules = rules;
    group
}

/// Expand a single DigitalOcean rule into one [`FirewallRule`] per source/destination
/// CIDR (the domain model carries a single CIDR per rule).
fn expand_rule(r: DoRule, is_ingress: bool) -> Vec<FirewallRule> {
    let protocol = parse_protocol(&r.protocol);
    let port_range = parse_ports(&r.ports, protocol);
    let endpoints = if is_ingress {
        r.sources
    } else {
        r.destinations
    };

    // DigitalOcean rules are always allow rules; deny is not supported.
    let cidrs: Vec<String> = if endpoints.addresses.is_empty() {
        // No explicit address: model as the implicit any-traffic scope.
        vec!["0.0.0.0/0".to_string()]
    } else {
        endpoints.addresses
    };

    cidrs
        .into_iter()
        .map(|cidr| FirewallRule {
            id: None,
            description: format!(
                "{} {} {}",
                if is_ingress { "ingress" } else { "egress" },
                protocol,
                cidr
            ),
            is_ingress,
            protocol,
            port_range,
            cidr,
            action: RuleAction::Allow,
        })
        .collect()
}

/// Parse a DigitalOcean ports string into a [`PortRange`].
///
/// `"0"`, `"all"`, or empty means all ports (mapped to the full u16 range).
/// A single number maps to a single-port range; `"8000-9000"` maps to a range.
fn parse_ports(ports: &str, protocol: Protocol) -> Option<PortRange> {
    // ICMP and "all" protocols are port-less.
    let lower = ports.trim().to_ascii_lowercase();
    if lower.is_empty() || lower == "0" || lower == "all" || matches!(protocol, Protocol::Icmp) {
        return if matches!(protocol, Protocol::Icmp) {
            None
        } else {
            Some(PortRange::range(0, 65535))
        };
    }
    if let Some((start_s, end_s)) = lower.split_once('-') {
        if let (Ok(start), Ok(end)) = (start_s.parse::<u16>(), end_s.parse::<u16>()) {
            return Some(PortRange::range(start, end));
        }
    }
    if let Ok(single) = lower.parse::<u16>() {
        return Some(PortRange::single(single));
    }
    None
}

/// Parse a DigitalOcean protocol string into a [`Protocol`].
fn parse_protocol(s: &str) -> Protocol {
    match s.trim().to_ascii_lowercase().as_str() {
        "tcp" => Protocol::Tcp,
        "udp" => Protocol::Udp,
        "icmp" => Protocol::Icmp,
        _ => Protocol::All,
    }
}

// ---------------------------------------------------------------------------
// doctl rule-string rendering
// ---------------------------------------------------------------------------

/// Render a slice of [`FirewallRule`] into the comma/space-separated
/// key-value form that `doctl`'s `--inbound-rules` / `--outbound-rules` flags
/// expect.
///
/// Per the official `doctl compute firewall create` docs:
/// > `protocol:tcp,ports:22,address:0.0.0.0/0`
///
/// Multiple rules are separated by spaces. Source key is `address`; for
/// non-ingress rules the key remains `address` (doctl uses the same key for
/// destinations).
fn render_rules(rules: &[FirewallRule], is_ingress: bool) -> Result<String> {
    let mut parts = Vec::with_capacity(rules.len());
    for r in rules {
        if r.is_ingress != is_ingress {
            continue;
        }
        let proto = r.protocol.to_string();
        let mut kv = format!("protocol:{}", proto);
        match r.port_range {
            Some(p) if !matches!(r.protocol, Protocol::Icmp) => kv.push_str(&format!(",ports:{p}")),
            _ => {}
        }
        kv.push_str(&format!(",address:{}", r.cidr));
        parts.push(kv);
    }
    if parts.is_empty() {
        return Err(Error::Other(format!(
            "no {} rules to render",
            if is_ingress { "inbound" } else { "outbound" }
        )));
    }
    Ok(parts.join(" "))
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use toride_runner::{CommandOutput, FakeRunner};

    /// Real `doctl compute firewall list --format JSON` shape.
    ///
    /// Source: DigitalOcean Firewalls API reference and doctl firewall list docs:
    /// <https://docs.digitalocean.com/reference/doctl/reference/compute/firewall/list/>
    /// <https://docs.digitalocean.com/reference/api/reference/firewalls/>
    const LIST_JSON: &str = r#"[
      {
        "id": "fe4ff2c8-8c3f-4e1e-8e7e-1a2b3c4d5e6f",
        "name": "my-firewall",
        "status": "succeeded",
        "inbound_rules": [
          {
            "protocol": "tcp",
            "ports": "22",
            "sources": {
              "addresses": ["203.0.113.1/32", "0.0.0.0/0"],
              "tags": ["frontend"],
              "droplet_ids": [123456789],
              "load_balancer_uids": ["abc-123"]
            }
          },
          {
            "protocol": "icmp",
            "ports": "0",
            "sources": { "addresses": ["0.0.0.0/0"] }
          }
        ],
        "outbound_rules": [
          {
            "protocol": "tcp",
            "ports": "443",
            "destinations": { "addresses": ["0.0.0.0/0"] }
          }
        ],
        "droplet_ids": [386734086],
        "tags": ["frontend", "backend"],
        "pending_changes": []
      }
    ]"#;

    // --- parsing tests (docs-sourced JSON) -----------------------------------

    /// A real docs-shaped JSON sample parses into the domain model with the
    /// correct provider, id, name, tags, and rule counts.
    #[test]
    fn parses_real_list_json_into_security_groups() {
        let groups = parse_firewalls(LIST_JSON).expect("must parse");
        assert_eq!(groups.len(), 1);

        let g = &groups[0];
        assert_eq!(g.provider, CloudProvider::DigitalOcean);
        assert_eq!(g.name, "my-firewall");
        assert_eq!(
            g.id.as_deref(),
            Some("fe4ff2c8-8c3f-4e1e-8e7e-1a2b3c4d5e6f")
        );

        // droplet_ids + tags are surfaced as SecurityGroup tags.
        assert!(g.tags.iter().any(|(k, v)| k == "droplet_id" && v == "386734086"));
        assert!(g.tags.iter().any(|(k, v)| k == "tag" && v == "frontend"));
        assert!(g.tags.iter().any(|(k, v)| k == "tag" && v == "backend"));

        // Two inbound tcp/icmp rules with two + one addresses => expanded rules,
        // plus one egress rule.
        let ingress = g.ingress_rules();
        let egress = g.egress_rules();
        // tcp rule has two source addresses => 2 expanded rules; icmp has 1.
        assert_eq!(ingress.len(), 3, "ingress: {ingress:?}");
        assert_eq!(egress.len(), 1);
    }

    #[test]
    fn parses_ingress_tcp_rule_fields() {
        let groups = parse_firewalls(LIST_JSON).unwrap();
        let tcp = groups[0]
            .ingress_rules()
            .into_iter()
            .find(|r| r.cidr == "203.0.113.1/32")
            .expect("tcp rule present");
        assert!(tcp.is_ingress);
        assert_eq!(tcp.protocol, Protocol::Tcp);
        assert_eq!(tcp.port_range, Some(PortRange::single(22)));
        assert_eq!(tcp.action, RuleAction::Allow);
    }

    #[test]
    fn parses_icmp_rule_as_portless() {
        let groups = parse_firewalls(LIST_JSON).unwrap();
        let icmp = groups[0]
            .ingress_rules()
            .into_iter()
            .find(|r| r.protocol == Protocol::Icmp)
            .expect("icmp rule present");
        assert_eq!(icmp.port_range, None);
        assert_eq!(icmp.cidr, "0.0.0.0/0");
    }

    #[test]
    fn parses_egress_rule_fields() {
        let groups = parse_firewalls(LIST_JSON).unwrap();
        let eg = &groups[0].egress_rules()[0];
        assert!(!eg.is_ingress);
        assert_eq!(eg.protocol, Protocol::Tcp);
        assert_eq!(eg.port_range, Some(PortRange::single(443)));
    }

    #[test]
    fn parse_empty_returns_empty_vec() {
        assert!(parse_firewalls("").unwrap().is_empty());
        assert!(parse_firewalls("   \n  ").unwrap().is_empty());
    }

    #[test]
    fn parse_invalid_returns_config_parse_error() {
        let err = parse_firewalls("{ not json").unwrap_err();
        assert!(matches!(err, Error::ConfigParse(_)), "{err:?}");
    }

    // --- command-construction tests ------------------------------------------

    /// Builds the exact `doctl compute firewall list --format JSON` command.
    ///
    /// Source: <https://docs.digitalocean.com/reference/doctl/reference/compute/firewall/list/>
    #[test]
    fn list_builds_exact_doctl_command() {
        let runner = FakeRunner::new().push_response(CommandOutput::from_stdout("[]"));
        let client = DigitalOceanClient::with_runner(runner);

        client.list_firewalls().unwrap();

        let expected = CommandSpec::new("doctl")
            .args(["compute", "firewall", "list", "--format", "JSON"]);
        client.runner.assert_called_with(&expected);
    }

    /// When an access token is configured it is injected as a global
    /// `--access-token` flag and the command is marked redacted.
    #[test]
    fn list_injects_access_token_and_redacts() {
        let runner = FakeRunner::new().push_response(CommandOutput::from_stdout("[]"));
        let client = DigitalOceanClient::with_runner(runner).set_token("tok-abc");

        client.list_firewalls().unwrap();

        let expected = CommandSpec::new("doctl")
            .arg("--access-token")
            .arg("tok-abc")
            .args(["compute", "firewall", "list", "--format", "JSON"])
            .redact(true);
        client.runner.assert_called_with(&expected);

        // Non-vacuous: prove the token VALUE is actually scrubbed from the
        // redacted display, not merely that redact==true. (Regression for the
        // REDACT_FLAGS gap that previously left --access-token unredacted, so
        // the doctl token leaked into runner logs/errors despite redact(true).)
        let display = toride_runner::display::redacted_args_display(&expected);
        assert!(
            !display.contains("tok-abc"),
            "doctl access token leaked into redacted display: {display}"
        );
    }

    /// Builds `doctl compute firewall get <id> --format JSON`.
    ///
    /// Source: <https://docs.digitalocean.com/reference/doctl/reference/compute/firewall/get/>
    #[test]
    fn get_builds_exact_doctl_command() {
        let runner =
            FakeRunner::new().push_response(CommandOutput::from_stdout(LIST_JSON));
        let client = DigitalOceanClient::with_runner(runner);

        let group = client.get_firewall("fe4ff2c8-8c3f").unwrap();
        assert_eq!(group.name, "my-firewall");

        let expected = CommandSpec::new("doctl")
            .args(["compute", "firewall", "get"])
            .arg("fe4ff2c8-8c3f")
            .args(["--format", "JSON"]);
        client.runner.assert_called_with(&expected);
    }

    #[test]
    fn get_returns_provider_not_found_when_empty() {
        let runner = FakeRunner::new().push_response(CommandOutput::from_stdout("[]"));
        let client = DigitalOceanClient::with_runner(runner);
        let err = client.get_firewall("nope").unwrap_err();
        assert!(matches!(err, Error::ProviderNotFound(_)), "{err:?}");
    }

    /// Builds `doctl compute firewall create --name <n> --inbound-rules ...
    /// --outbound-rules ... --format JSON`.
    ///
    /// Source: <https://docs.digitalocean.com/reference/doctl/reference/compute/firewall/create/>
    #[test]
    fn create_builds_exact_doctl_command() {
        let runner =
            FakeRunner::new().push_response(CommandOutput::from_stdout(LIST_JSON));
        let client = DigitalOceanClient::with_runner(runner);

        let inbound = vec![FirewallRule {
            id: None,
            description: "ssh".into(),
            is_ingress: true,
            protocol: Protocol::Tcp,
            port_range: Some(PortRange::single(22)),
            cidr: "0.0.0.0/0".into(),
            action: RuleAction::Allow,
        }];
        let outbound = vec![FirewallRule {
            id: None,
            description: "https".into(),
            is_ingress: false,
            protocol: Protocol::Tcp,
            port_range: Some(PortRange::single(443)),
            cidr: "0.0.0.0/0".into(),
            action: RuleAction::Allow,
        }];

        let created = client.create_firewall("example-firewall", &inbound, &outbound).unwrap();
        assert_eq!(created.name, "my-firewall");

        let expected = CommandSpec::new("doctl")
            .args(["compute", "firewall", "create", "--format", "JSON"])
            .arg("--name")
            .arg("example-firewall")
            .arg("--inbound-rules")
            .arg("protocol:tcp,ports:22,address:0.0.0.0/0")
            .arg("--outbound-rules")
            .arg("protocol:tcp,ports:443,address:0.0.0.0/0");
        client.runner.assert_called_with(&expected);
    }

    #[test]
    fn create_without_any_rules_errors() {
        let runner = FakeRunner::new();
        let client = DigitalOceanClient::with_runner(runner);
        let err = client.create_firewall("x", &[], &[]).unwrap_err();
        assert!(matches!(err, Error::Other(_)), "{err:?}");
    }

    /// Builds `doctl compute firewall delete <id> --force`.
    ///
    /// Source: <https://docs.digitalocean.com/reference/doctl/reference/compute/firewall/delete/>
    #[test]
    fn delete_builds_exact_doctl_command() {
        let runner = FakeRunner::new().push_response(CommandOutput::from_stdout(""));
        let client = DigitalOceanClient::with_runner(runner);

        client.delete_firewall("fe4ff2c8-8c3f").unwrap();

        let expected = CommandSpec::new("doctl")
            .args(["compute", "firewall", "delete"])
            .arg("fe4ff2c8-8c3f")
            .arg("--force");
        client.runner.assert_called_with(&expected);
    }

    /// Builds `doctl compute firewall add-rules <id> --inbound-rules ...
    /// --outbound-rules ...`.
    ///
    /// Source: <https://docs.digitalocean.com/reference/doctl/reference/compute/firewall/add-rules/>
    #[test]
    fn add_rules_builds_exact_doctl_command() {
        let runner = FakeRunner::new().push_response(CommandOutput::from_stdout(""));
        let client = DigitalOceanClient::with_runner(runner);

        let rules = vec![
            FirewallRule {
                id: None,
                description: "ssh".into(),
                is_ingress: true,
                protocol: Protocol::Tcp,
                port_range: Some(PortRange::single(22)),
                cidr: "192.0.2.0/24".into(),
                action: RuleAction::Allow,
            },
            FirewallRule {
                id: None,
                description: "https".into(),
                is_ingress: false,
                protocol: Protocol::Tcp,
                port_range: Some(PortRange::single(443)),
                cidr: "0.0.0.0/0".into(),
                action: RuleAction::Allow,
            },
        ];

        client.add_rules("f81d4fae", &rules).unwrap();

        let expected = CommandSpec::new("doctl")
            .args(["compute", "firewall", "add-rules"])
            .arg("f81d4fae")
            .arg("--inbound-rules")
            .arg("protocol:tcp,ports:22,address:192.0.2.0/24")
            .arg("--outbound-rules")
            .arg("protocol:tcp,ports:443,address:0.0.0.0/0");
        client.runner.assert_called_with(&expected);
    }

    #[test]
    fn add_rules_maps_conflict_message_to_rule_conflict_error() {
        let runner = FakeRunner::new().push_result(Err(toride_runner::Error::CommandFailed {
            program: "doctl".into(),
            args: String::new(),
            exit_code: Some(1),
            stderr: "rule conflict detected".into(),
        }));
        let client = DigitalOceanClient::with_runner(runner);

        let rule = FirewallRule {
            id: None,
            description: "ssh".into(),
            is_ingress: true,
            protocol: Protocol::Tcp,
            port_range: Some(PortRange::single(22)),
            cidr: "0.0.0.0/0".into(),
            action: RuleAction::Allow,
        };
        let err = client.add_rules("fw", std::slice::from_ref(&rule)).unwrap_err();
        assert!(matches!(err, Error::FirewallRuleConflict(_)), "{err:?}");
    }

    /// Builds `doctl compute firewall remove-rules <id> --inbound-rules ...`.
    ///
    /// Source: <https://docs.digitalocean.com/reference/doctl/reference/compute/firewall/remove-rules/>
    #[test]
    fn remove_rules_builds_exact_doctl_command() {
        let runner = FakeRunner::new().push_response(CommandOutput::from_stdout(""));
        let client = DigitalOceanClient::with_runner(runner);

        let rule = FirewallRule {
            id: None,
            description: "ssh".into(),
            is_ingress: true,
            protocol: Protocol::Tcp,
            port_range: Some(PortRange::single(22)),
            cidr: "0.0.0.0/0".into(),
            action: RuleAction::Allow,
        };

        client.remove_rules("f81d4fae", std::slice::from_ref(&rule)).unwrap();

        let expected = CommandSpec::new("doctl")
            .args(["compute", "firewall", "remove-rules"])
            .arg("f81d4fae")
            .arg("--inbound-rules")
            .arg("protocol:tcp,ports:22,address:0.0.0.0/0");
        client.runner.assert_called_with(&expected);
    }

    #[test]
    fn add_rules_with_empty_slice_errors() {
        let runner = FakeRunner::new();
        let client = DigitalOceanClient::with_runner(runner);
        let err = client.add_rules("fw", &[]).unwrap_err();
        assert!(matches!(err, Error::Other(_)), "{err:?}");
    }

    // --- rendering helper unit tests -----------------------------------------

    #[test]
    fn render_rule_matches_doc_format() {
        // doctl create docs example: protocol:tcp,ports:22,address:0.0.0.0/0
        let rule = FirewallRule {
            id: None,
            description: String::new(),
            is_ingress: true,
            protocol: Protocol::Tcp,
            port_range: Some(PortRange::single(22)),
            cidr: "0.0.0.0/0".into(),
            action: RuleAction::Allow,
        };
        let rendered = render_rules(std::slice::from_ref(&rule), true).unwrap();
        assert_eq!(rendered, "protocol:tcp,ports:22,address:0.0.0.0/0");
    }

    #[test]
    fn render_omits_ports_for_icmp() {
        let rule = FirewallRule {
            id: None,
            description: String::new(),
            is_ingress: true,
            protocol: Protocol::Icmp,
            port_range: None,
            cidr: "0.0.0.0/0".into(),
            action: RuleAction::Allow,
        };
        let rendered = render_rules(std::slice::from_ref(&rule), true).unwrap();
        assert_eq!(rendered, "protocol:icmp,address:0.0.0.0/0");
    }

    #[test]
    fn render_multiple_rules_are_space_separated() {
        let rules = [
            FirewallRule {
                id: None,
                description: String::new(),
                is_ingress: true,
                protocol: Protocol::Tcp,
                port_range: Some(PortRange::single(22)),
                cidr: "0.0.0.0/0".into(),
                action: RuleAction::Allow,
            },
            FirewallRule {
                id: None,
                description: String::new(),
                is_ingress: true,
                protocol: Protocol::Tcp,
                port_range: Some(PortRange::range(8000, 9000)),
                cidr: "10.0.0.0/8".into(),
                action: RuleAction::Allow,
            },
        ];
        let rendered = render_rules(&rules, true).unwrap();
        assert_eq!(
            rendered,
            "protocol:tcp,ports:22,address:0.0.0.0/0 protocol:tcp,ports:8000-9000,address:10.0.0.0/8"
        );
    }
}
