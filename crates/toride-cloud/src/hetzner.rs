//! Hetzner Cloud firewall management.
//!
//! Provides typed wrappers around the `hcloud` CLI for managing Hetzner Cloud
//! firewalls and their rules.
//!
//! # CLI reference
//!
//! Commands are built as [`toride_runner::CommandSpec`]s and executed through a
//! [`toride_runner::Runner`]. The `hcloud` CLI authenticates from its own
//! config/env (`HCLOUD_TOKEN`), so none of these commands carry a secret
//! inline — they are therefore not redacted.
//!
//! JSON shapes mirror the Hetzner Cloud API:
//! - `list -o=json`: an array of Firewall objects.
//! - `create`/`update`: `{"firewall": <Firewall>}`.
//! - a Firewall rule: `{direction, protocol, source_ips[], destination_ips[], port?, description?}`.
//!
//! Source: <https://docs.hetzner.cloud/reference/cloud#firewalls>

use crate::CloudProvider;
use crate::error::{Error, Result};
use crate::spec::{FirewallRule, PortRange, Protocol, RuleAction, SecurityGroup};
use std::sync::Arc;
use toride_runner::{CommandOutput, CommandSpec, DuctRunner, Runner};

// ---------------------------------------------------------------------------
// JSON deserialization helpers (file-local — do not touch parse.rs)
// ---------------------------------------------------------------------------

/// Mirrors a single Hetzner firewall rule as returned by the API/CLI.
///
/// `direction` is `"in"` (ingress) or `"out"` (egress). `port` is a free-form
/// string (`"22"` or `"8000-8080"`). `description` may be `null`.
#[derive(Debug, serde::Deserialize)]
struct HcloudRule {
    direction: String,
    protocol: String,
    #[serde(default)]
    source_ips: Vec<String>,
    #[serde(default)]
    destination_ips: Vec<String>,
    port: Option<String>,
    #[serde(default)]
    description: Option<String>,
}

/// Mirrors a Firewall object as returned by `list`/`describe`/`create`.
///
/// `id` is a JSON number in the API; we accept it as a generic value and
/// normalize it to a string.
#[derive(Debug, serde::Deserialize)]
struct HcloudFirewall {
    id: serde_json::Value,
    name: String,
    #[serde(default)]
    labels: std::collections::BTreeMap<String, String>,
    #[serde(default)]
    rules: Vec<HcloudRule>,
}

/// Wrapper for `create`/`update` responses: `{"firewall": {...}}`.
#[derive(Debug, serde::Deserialize)]
struct HcloudFirewallEnvelope {
    firewall: HcloudFirewall,
}

// ---------------------------------------------------------------------------
// HetznerClient
// ---------------------------------------------------------------------------

/// Client for managing Hetzner Cloud firewalls.
///
/// Delegates command execution to the `hcloud` CLI through a
/// [`toride_runner::Runner`]. Production usage holds a [`DuctRunner`]; tests
/// inject a [`toride_runner::FakeRunner`] via [`HetznerClient::with_runner`].
pub struct HetznerClient {
    /// Hetzner Cloud API token (uses `hcloud` config if `None`).
    ///
    /// Kept for callers that want to set `HCLOUD_TOKEN` explicitly, but is not
    /// required — `hcloud` reads its own context when unset.
    pub api_token: Option<String>,
    runner: Arc<dyn Runner>,
}

impl HetznerClient {
    /// Create a new Hetzner client backed by a real [`DuctRunner`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            api_token: None,
            runner: Arc::new(DuctRunner),
        }
    }

    /// Set the API token explicitly.
    #[must_use]
    pub fn with_token(mut self, token: impl Into<String>) -> Self {
        self.api_token = Some(token.into());
        self
    }

    /// Replace the command runner (primarily for tests).
    ///
    /// Stored as [`Arc<dyn Runner>`] so the same runner can be shared with a
    /// test harness (e.g. a `FakeRunner`) for post-call inspection without
    /// requiring `FakeRunner: Clone`.
    #[must_use]
    pub fn with_runner(mut self, runner: impl Runner + 'static) -> Self {
        self.runner = Arc::new(runner);
        self
    }

    /// Like [`HetznerClient::with_runner`], but accepts an already-shared
    /// `Arc<dyn Runner>`. Lets a test keep its own clone of the same runner
    /// (e.g. an `Arc<FakeRunner>`) for post-call assertions.
    #[must_use]
    pub fn with_arc_runner(mut self, runner: Arc<dyn Runner>) -> Self {
        self.runner = runner;
        self
    }

    /// Build a base `hcloud firewall ...` spec with `-o=json` output and, when
    /// an explicit token is set, `HCLOUD_TOKEN` injected into the child env.
    fn firewall_cmd(&self, subcommand: &str) -> CommandSpec {
        let mut spec = CommandSpec::new("hcloud")
            .arg("firewall")
            .arg(subcommand)
            .arg("-o=json");
        if let Some(token) = &self.api_token {
            spec = spec.env("HCLOUD_TOKEN", token).redact(true);
        }
        spec
    }

    /// Run a checked command, mapping runner errors into the cloud [`Error`].
    fn run(&self, cmd: &CommandSpec) -> Result<CommandOutput> {
        self.runner.run_checked(cmd).map_err(map_runner_error)
    }

    /// List all firewalls in the project.
    ///
    /// # Errors
    ///
    /// Returns [`Error::CommandFailed`] if the `hcloud` CLI is not installed
    /// or returns a non-zero exit code, or [`Error::Other`] on a parse failure.
    pub fn list_firewalls(&self) -> Result<Vec<SecurityGroup>> {
        let cmd = self.firewall_cmd("list");
        let output = self.run(&cmd)?;
        let firewalls: Vec<HcloudFirewall> = parse_json(&output, &cmd)?;
        Ok(firewalls.into_iter().map(parse_firewall).collect())
    }

    /// Get a firewall by name or ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ProviderNotFound`] if the firewall does not exist.
    pub fn get_firewall(&self, name_or_id: &str) -> Result<SecurityGroup> {
        let cmd = self.firewall_cmd("describe").arg(name_or_id);
        let output = self.run(&cmd)?;
        let firewall: HcloudFirewall = parse_json(&output, &cmd)?;
        Ok(parse_firewall(firewall))
    }

    /// Create a new firewall, optionally seeding it with `rules`.
    ///
    /// When `rules` is non-empty the rules are serialized to the API JSON shape
    /// and streamed to `hcloud` via `--rules-file -` (stdin).
    ///
    /// # Errors
    ///
    /// Returns [`Error::CommandFailed`] if creation fails.
    pub fn create_firewall(&self, name: &str, rules: &[FirewallRule]) -> Result<SecurityGroup> {
        let mut cmd = self.firewall_cmd("create").arg("--name").arg(name);
        if !rules.is_empty() {
            cmd = cmd.arg("--rules-file").arg("-").stdin(rules_payload(rules));
        }
        let output = self.run(&cmd)?;
        let envelope: HcloudFirewallEnvelope = parse_json(&output, &cmd)?;
        Ok(parse_firewall(envelope.firewall))
    }

    /// Delete a firewall by name or ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::CommandFailed`] if deletion fails.
    pub fn delete_firewall(&self, name_or_id: &str) -> Result<()> {
        let cmd = self.firewall_cmd("delete").arg("--yes").arg(name_or_id);
        self.run(&cmd)?;
        Ok(())
    }

    /// Add rules to an existing firewall.
    ///
    /// Implemented via `hcloud firewall replace-rules --rules-file -`, which is
    /// idempotent against the provider and is the supported bulk path (the CLI
    /// has no `add-rules` subcommand). The new ruleset is the existing rules
    /// plus the additions, in order.
    ///
    /// # Errors
    ///
    /// Returns [`Error::FirewallRuleConflict`] if any rule conflicts.
    pub fn add_rules(&self, firewall_name: &str, rules: &[FirewallRule]) -> Result<()> {
        let mut existing = self.get_firewall(firewall_name)?.rules;
        for new_rule in rules {
            if existing.iter().any(|r| same_effect(r, new_rule)) {
                return Err(Error::FirewallRuleConflict(format!(
                    "rule already present on firewall {firewall_name}: {new_rule:?}"
                )));
            }
            existing.push(new_rule.clone());
        }
        self.replace_rules(firewall_name, &existing)
    }

    /// Remove rules from an existing firewall (matched by effect, not id).
    ///
    /// # Errors
    ///
    /// Returns [`Error::CommandFailed`] if removal fails.
    pub fn remove_rules(&self, firewall_name: &str, rules: &[FirewallRule]) -> Result<()> {
        let existing = self.get_firewall(firewall_name)?.rules;
        let kept: Vec<FirewallRule> = existing
            .into_iter()
            .filter(|r| !rules.iter().any(|rm| same_effect(r, rm)))
            .collect();
        self.replace_rules(firewall_name, &kept)
    }

    /// Replace the full ruleset of a firewall via `replace-rules`.
    fn replace_rules(&self, firewall_name: &str, rules: &[FirewallRule]) -> Result<()> {
        let cmd = self
            .firewall_cmd("replace-rules")
            .arg(firewall_name)
            .arg("--rules-file")
            .arg("-")
            .stdin(rules_payload(rules));
        self.run(&cmd)?;
        Ok(())
    }

    /// Apply a firewall to a server resource.
    ///
    /// # Errors
    ///
    /// Returns [`Error::CommandFailed`] if the apply fails.
    pub fn apply_to_server(&self, firewall_name: &str, server_name: &str) -> Result<()> {
        let cmd = self
            .firewall_cmd("apply-to-resource")
            .arg("--type")
            .arg("server")
            .arg("--server")
            .arg(server_name)
            .arg(firewall_name);
        self.run(&cmd)?;
        Ok(())
    }

    /// Remove a firewall from a server resource.
    ///
    /// # Errors
    ///
    /// Returns [`Error::CommandFailed`] if the removal fails.
    pub fn remove_from_server(&self, firewall_name: &str, server_name: &str) -> Result<()> {
        let cmd = self
            .firewall_cmd("remove-from-resource")
            .arg("--type")
            .arg("server")
            .arg("--server")
            .arg(server_name)
            .arg(firewall_name);
        self.run(&cmd)?;
        Ok(())
    }
}

impl Default for HetznerClient {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Mapping helpers
// ---------------------------------------------------------------------------

/// Parse a JSON value from a command's stdout, surfacing a combined error
/// message that includes the program on failure.
fn parse_json<T: for<'de> serde::Deserialize<'de>>(
    output: &CommandOutput,
    cmd: &CommandSpec,
) -> Result<T> {
    serde_json::from_slice(output.stdout.as_bytes()).map_err(|e| {
        Error::Other(format!(
            "failed to parse `{}` JSON output: {e}",
            cmd.program
        ))
    })
}

/// Map a [`toride_runner::Error`] into the cloud [`Error`] enum.
///
/// Preserves the most informative variants (binary-missing, command failure,
/// timeout); falls back to [`Error::Other`] for the rest.
fn map_runner_error(err: toride_runner::Error) -> Error {
    match err {
        toride_runner::Error::BinaryNotFound(bin) => Error::BinaryNotFound(bin),
        toride_runner::Error::CommandFailed {
            program,
            stderr,
            exit_code,
            ..
        } => Error::CommandFailed {
            program,
            message: format!("exit {exit_code:?}: {stderr}"),
        },
        other => Error::Other(other.to_string()),
    }
}

/// Convert a provider [`HcloudFirewall`] into a [`SecurityGroup`].
fn parse_firewall(fw: HcloudFirewall) -> SecurityGroup {
    let rules = fw.rules.into_iter().map(parse_rule).collect();
    SecurityGroup {
        id: Some(id_to_string(fw.id)),
        name: fw.name,
        description: String::new(),
        provider: CloudProvider::Hetzner,
        rules,
        tags: fw.labels.into_iter().collect(),
    }
}

/// Normalize the provider `id` (a JSON number or string) to a [`String`].
fn id_to_string(v: serde_json::Value) -> String {
    match v {
        serde_json::Value::String(s) => s,
        serde_json::Value::Number(n) => n.to_string(),
        other => other.to_string(),
    }
}

/// Convert a provider [`HcloudRule`] into a [`FirewallRule`].
///
/// Ingress rules carry their CIDR in `source_ips[0]`; egress rules in
/// `destination_ips[0]`. Hetzner is allow-list only, so action is always
/// [`RuleAction::Allow`].
fn parse_rule(rule: HcloudRule) -> FirewallRule {
    let is_ingress = rule.direction == "in";
    let cidr_source = if is_ingress {
        &rule.source_ips
    } else {
        &rule.destination_ips
    };
    let cidr = cidr_source.first().cloned().unwrap_or_default();
    FirewallRule {
        id: None,
        description: rule.description.unwrap_or_default(),
        is_ingress,
        protocol: parse_protocol(&rule.protocol),
        port_range: rule.port.as_deref().and_then(parse_port_range),
        cidr,
        action: RuleAction::Allow,
    }
}

/// Parse a Hetzner protocol string into a [`Protocol`].
fn parse_protocol(s: &str) -> Protocol {
    match s {
        "tcp" => Protocol::Tcp,
        "udp" => Protocol::Udp,
        "icmp" => Protocol::Icmp,
        "esp" | "gre" => Protocol::Other(protocol_number(s)),
        _ => Protocol::All,
    }
}

/// IANA protocol numbers for the non-core Hetzner protocols.
fn protocol_number(s: &str) -> u8 {
    match s {
        "esp" => 50,
        "gre" => 47,
        _ => 0,
    }
}

/// Parse a Hetzner port string (`"22"` or `"8000-8080"`) into a [`PortRange`].
///
/// A reversed pair (`"8080-8000"`) is normalized by swapping so the returned
/// range always satisfies `start <= end`, matching the inclusive-range
/// contract of [`PortRange`].
fn parse_port_range(s: &str) -> Option<PortRange> {
    let (start_s, end_s) = s.split_once('-').unwrap_or((s, s));
    let start = start_s.parse::<u16>().ok()?;
    let end = end_s.parse::<u16>().ok()?;
    let (start, end) = if start <= end {
        (start, end)
    } else {
        (end, start)
    };
    Some(PortRange { start, end })
}

/// Render the provider rules payload (`--rules-file -` stdin) from our rules.
///
/// Shape matches the API: an array of `{direction, protocol, source_ips,
/// destination_ips, port?, description?}`. Egress rules emit CIDRs under
/// `destination_ips`; ingress under `source_ips`.
fn rules_payload(rules: &[FirewallRule]) -> String {
    use serde_json::{Value, json};
    let arr: Vec<Value> = rules
        .iter()
        .map(|r| {
            let (ips_key, ips): (&str, Vec<String>) = if r.is_ingress {
                ("source_ips", vec![r.cidr.clone()])
            } else {
                ("destination_ips", vec![r.cidr.clone()])
            };
            let mut obj = serde_json::Map::new();
            let _ = obj.insert(
                "direction".into(),
                json!(if r.is_ingress { "in" } else { "out" }),
            );
            let _ = obj.insert("protocol".into(), json!(r.protocol.to_string()));
            let _ = obj.insert(ips_key.into(), json!(ips));
            if r.is_ingress {
                let _ = obj.insert("destination_ips".into(), json!([]));
            } else {
                let _ = obj.insert("source_ips".into(), json!([]));
            }
            if let Some(pr) = r.port_range {
                let _ = obj.insert("port".into(), json!(pr.to_string()));
            }
            if !r.description.is_empty() {
                let _ = obj.insert("description".into(), json!(r.description));
            }
            Value::Object(obj)
        })
        .collect();
    serde_json::to_string(&arr).unwrap_or_else(|_| "[]".to_string())
}

/// Two rules have the same effect if every observable field matches.
fn same_effect(a: &FirewallRule, b: &FirewallRule) -> bool {
    a.is_ingress == b.is_ingress
        && a.protocol == b.protocol
        && a.port_range == b.port_range
        && a.cidr == b.cidr
        && a.description == b.description
        && a.action == b.action
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use toride_runner::fake::FakeRunner;

    /// Real `hcloud firewall list -o=json` output shape (single firewall with
    /// one ingress SSH rule), sourced from the Hetzner Cloud CLI test fixtures
    /// and the API reference at <https://docs.hetzner.cloud/reference/cloud#firewalls>
    const LIST_JSON: &str = r#"[
      {
        "id": 123,
        "name": "test",
        "labels": {"env": "prod"},
        "created": "2016-01-30T23:50:00Z",
        "rules": [
          {
            "direction": "in",
            "source_ips": ["0.0.0.0/0", "::/0"],
            "destination_ips": [],
            "protocol": "tcp",
            "port": "22",
            "description": "Allow SSH"
          },
          {
            "direction": "out",
            "source_ips": [],
            "destination_ips": ["28.239.13.1/32"],
            "protocol": "tcp",
            "port": "80"
          }
        ],
        "applied_to": [
          {"type": "server", "server": {"id": 1}}
        ]
      }
    ]"#;

    /// Real `hcloud firewall create --rules-file -` response shape, sourced
    /// from the hcloud CLI test fixture `firewall/testdata/create_response.json`
    /// (<https://github.com/hetznercloud/cli>). The CLI wraps the Firewall object
    /// in `{"firewall": {...}}`.
    const CREATE_JSON: &str = r#"{
      "firewall": {
        "id": 123,
        "name": "test",
        "labels": {},
        "created": "2016-01-30T23:50:00Z",
        "rules": [
          {
            "direction": "in",
            "source_ips": [],
            "destination_ips": [],
            "protocol": "tcp",
            "port": "22",
            "description": null
          }
        ],
        "applied_to": [
          {"type": "server", "server": {"id": 1}}
        ]
      }
    }"#;

    /// Build a client over a `FakeRunner` that returns `stdout` for any call.
    /// Returns a shared `Arc<FakeRunner>` pointing at the same runner the
    /// client uses, so the test can inspect recorded calls afterwards.
    fn client_returning(stdout: &str) -> (HetznerClient, Arc<FakeRunner>) {
        let runner = Arc::new(FakeRunner::new().push_response(CommandOutput::from_stdout(stdout)));
        // `with_runner` clones the Arc<dyn Runner> internally, so both the
        // client's stored Arc and the one we return reference the same FakeRunner.
        let client = HetznerClient::new().with_arc_runner(runner.clone());
        (client, runner)
    }

    #[test]
    fn list_firewalls_parses_docs_json() {
        // Source: https://docs.hetzner.cloud/reference/cloud#firewalls
        let (client, _) = client_returning(LIST_JSON);
        let groups = client.list_firewalls().expect("list should parse");

        assert_eq!(groups.len(), 1);
        let fw = &groups[0];
        assert_eq!(fw.id.as_deref(), Some("123"));
        assert_eq!(fw.name, "test");
        assert_eq!(fw.provider, CloudProvider::Hetzner);
        assert_eq!(fw.tags, vec![("env".to_string(), "prod".to_string())]);

        // Ingress SSH rule.
        let ingress = fw.ingress_rules();
        assert_eq!(ingress.len(), 1);
        let ssh = ingress[0];
        assert!(ssh.is_ingress);
        assert_eq!(ssh.protocol, Protocol::Tcp);
        assert_eq!(ssh.cidr, "0.0.0.0/0");
        assert_eq!(ssh.port_range, Some(PortRange::single(22)));
        assert_eq!(ssh.description, "Allow SSH");
        assert_eq!(ssh.action, RuleAction::Allow);

        // Egress rule.
        let egress = fw.egress_rules();
        assert_eq!(egress.len(), 1);
        let http = egress[0];
        assert!(!http.is_ingress);
        assert_eq!(http.cidr, "28.239.13.1/32");
        assert_eq!(http.port_range, Some(PortRange::single(80)));
        assert!(http.description.is_empty(), "null description -> empty");
    }

    #[test]
    fn list_firewalls_builds_correct_command() {
        let (client, runner) = client_returning(LIST_JSON);
        let _ = client.list_firewalls();
        runner.assert_called_with(
            &CommandSpec::new("hcloud")
                .arg("firewall")
                .arg("list")
                .arg("-o=json"),
        );
    }

    #[test]
    fn get_firewall_parses_single_object() {
        // `describe` returns a bare Firewall object (no envelope).
        let (client, _) = client_returning(
            r#"{
                "id": 987,
                "name": "edge",
                "labels": {},
                "rules": [
                  {
                    "direction": "in",
                    "source_ips": ["10.0.0.0/8"],
                    "destination_ips": [],
                    "protocol": "icmp",
                    "port": null,
                    "description": "ping"
                  }
                ],
                "applied_to": []
              }"#,
        );
        let fw = client.get_firewall("edge").expect("describe should parse");
        assert_eq!(fw.id.as_deref(), Some("987"));
        assert_eq!(fw.name, "edge");
        let icmp = fw.ingress_rules()[0];
        assert_eq!(icmp.protocol, Protocol::Icmp);
        assert_eq!(icmp.cidr, "10.0.0.0/8");
        assert_eq!(icmp.port_range, None);
    }

    #[test]
    fn get_firewall_builds_describe_command() {
        let (client, runner) = client_returning(LIST_JSON.trim_start_matches(['[', '\n']));
        let _ = client.get_firewall("my-fw");
        runner.assert_called_with(
            &CommandSpec::new("hcloud")
                .arg("firewall")
                .arg("describe")
                .arg("-o=json")
                .arg("my-fw"),
        );
    }

    #[test]
    fn create_firewall_parses_envelope_and_passes_rules_via_stdin() {
        // Source: hcloud CLI fixture firewall/testdata/create_response.json
        let (client, runner) = client_returning(CREATE_JSON);
        let rules = vec![FirewallRule {
            id: None,
            description: "Allow SSH".into(),
            is_ingress: true,
            protocol: Protocol::Tcp,
            port_range: Some(PortRange::single(22)),
            cidr: "0.0.0.0/0".into(),
            action: RuleAction::Allow,
        }];
        let fw = client
            .create_firewall("test", &rules)
            .expect("create should parse");
        assert_eq!(fw.id.as_deref(), Some("123"));
        assert_eq!(fw.name, "test");

        // Verify the command shape: create --name <name> --rules-file - (stdin).
        let calls = runner.calls();
        let create_call = calls
            .iter()
            .find(|c| c.args.contains(&"create".to_string()))
            .expect("create call should be recorded");
        assert_eq!(create_call.program, "hcloud");
        assert_eq!(
            create_call.args,
            vec![
                "firewall".to_string(),
                "create".to_string(),
                "-o=json".to_string(),
                "--name".to_string(),
                "test".to_string(),
                "--rules-file".to_string(),
                "-".to_string(),
            ]
        );
        // stdin must be valid JSON matching the API rules shape.
        let stdin = create_call.stdin.as_deref().expect("stdin must be set");
        let payload: serde_json::Value = serde_json::from_str(stdin).expect("stdin is JSON");
        let arr = payload.as_array().expect("rules payload is an array");
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["direction"], "in");
        assert_eq!(arr[0]["protocol"], "tcp");
        assert_eq!(arr[0]["port"], "22");
        assert_eq!(arr[0]["source_ips"][0], "0.0.0.0/0");
        assert_eq!(arr[0]["destination_ips"], serde_json::json!([]));
    }

    #[test]
    fn create_firewall_without_rules_omits_rules_file() {
        let (client, runner) = client_returning(CREATE_JSON);
        let _ = client.create_firewall("bare", &[]);
        let calls = runner.calls();
        let create_call = calls
            .iter()
            .find(|c| c.args.contains(&"create".to_string()))
            .expect("create call recorded");
        assert!(
            !create_call.args.contains(&"--rules-file".to_string()),
            "no --rules-file when rules empty"
        );
        assert!(create_call.stdin.is_none());
    }

    #[test]
    fn delete_firewall_builds_command() {
        let (client, runner) = client_returning("");
        client.delete_firewall("my-fw").expect("delete ok");
        runner.assert_called_with(
            &CommandSpec::new("hcloud")
                .arg("firewall")
                .arg("delete")
                .arg("-o=json")
                .arg("--yes")
                .arg("my-fw"),
        );
    }

    /// Build a `FakeRunner` pre-configured so that the internal `describe`
    /// call (issued by `add_rules`/`remove_rules`) returns a single `Firewall`
    /// object — the first firewall of `LIST_JSON` — while other calls fall
    /// through to a successful empty response. The returned runner is ready to
    /// share with the client via `with_arc_runner`.
    fn runner_with_describe_single() -> Arc<FakeRunner> {
        let arr: serde_json::Value = serde_json::from_str(LIST_JSON).unwrap();
        let single = serde_json::to_string(&arr[0]).unwrap();
        let runner = FakeRunner::new()
            .push_response(CommandOutput::from_stdout(""))
            .respond(
                CommandSpec::new("hcloud")
                    .arg("firewall")
                    .arg("describe")
                    .arg("-o=json")
                    .arg("test"),
                CommandOutput::from_stdout(single),
            );
        Arc::new(runner)
    }

    #[test]
    fn add_rules_appends_and_replaces() {
        // Existing firewall has one SSH ingress rule; we add HTTP.
        let runner = runner_with_describe_single();
        let client = HetznerClient::new().with_arc_runner(runner.clone());
        let http = FirewallRule {
            id: None,
            description: "Allow HTTP".into(),
            is_ingress: true,
            protocol: Protocol::Tcp,
            port_range: Some(PortRange::single(80)),
            cidr: "0.0.0.0/0".into(),
            action: RuleAction::Allow,
        };
        client.add_rules("test", &[http]).expect("add ok");

        // Should have run describe then replace-rules with the combined set.
        let replace_calls: Vec<_> = runner
            .calls()
            .into_iter()
            .filter(|c| c.args.contains(&"replace-rules".to_string()))
            .collect();
        assert_eq!(replace_calls.len(), 1);
        let stdin = replace_calls[0].stdin.as_deref().expect("stdin set");
        let arr: serde_json::Value =
            serde_json::from_str(stdin).expect("replace-rules stdin is JSON");
        assert_eq!(
            arr.as_array().unwrap().len(),
            3,
            "1 existing ingress + 1 existing egress + 1 new"
        );
    }

    #[test]
    fn add_rules_conflict_is_detected() {
        // The existing SSH rule is identical to the one we try to add.
        let runner = runner_with_describe_single();
        let client = HetznerClient::new().with_arc_runner(runner.clone());
        let dup = FirewallRule {
            id: None,
            description: "Allow SSH".into(),
            is_ingress: true,
            protocol: Protocol::Tcp,
            port_range: Some(PortRange::single(22)),
            cidr: "0.0.0.0/0".into(),
            action: RuleAction::Allow,
        };
        let err = client.add_rules("test", &[dup]).unwrap_err();
        assert!(
            matches!(err, Error::FirewallRuleConflict(_)),
            "duplicate rule must surface FirewallRuleConflict, got {err:?}"
        );
    }

    #[test]
    fn remove_rules_filters_by_effect() {
        // Removing the SSH ingress rule should leave 1 rule (egress only).
        let runner = runner_with_describe_single();
        let client = HetznerClient::new().with_arc_runner(runner.clone());
        let ssh = FirewallRule {
            id: None,
            description: "Allow SSH".into(),
            is_ingress: true,
            protocol: Protocol::Tcp,
            port_range: Some(PortRange::single(22)),
            cidr: "0.0.0.0/0".into(),
            action: RuleAction::Allow,
        };
        client.remove_rules("test", &[ssh]).expect("remove ok");
        let replace_calls: Vec<_> = runner
            .calls()
            .into_iter()
            .filter(|c| c.args.contains(&"replace-rules".to_string()))
            .collect();
        let stdin = replace_calls[0].stdin.as_deref().expect("stdin set");
        let arr: serde_json::Value =
            serde_json::from_str(stdin).expect("replace-rules stdin is JSON");
        assert_eq!(arr.as_array().unwrap().len(), 1);
        // Surviving rule is the egress one (direction out).
        assert_eq!(arr[0]["direction"], "out");
    }

    #[test]
    fn apply_to_server_builds_apply_to_resource_command() {
        // Source: hcloud CLI `firewall apply-to-resource --type server --server <server> <firewall>`
        let (client, runner) = client_returning("");
        client.apply_to_server("fw", "web-1").expect("apply ok");
        runner.assert_called_with(
            &CommandSpec::new("hcloud")
                .arg("firewall")
                .arg("apply-to-resource")
                .arg("-o=json")
                .arg("--type")
                .arg("server")
                .arg("--server")
                .arg("web-1")
                .arg("fw"),
        );
    }

    #[test]
    fn remove_from_server_builds_remove_from_resource_command() {
        let (client, runner) = client_returning("");
        client.remove_from_server("fw", "web-1").expect("remove ok");
        runner.assert_called_with(
            &CommandSpec::new("hcloud")
                .arg("firewall")
                .arg("remove-from-resource")
                .arg("-o=json")
                .arg("--type")
                .arg("server")
                .arg("--server")
                .arg("web-1")
                .arg("fw"),
        );
    }

    #[test]
    fn parse_rule_handles_port_range_and_unknown_protocol() {
        let rule = HcloudRule {
            direction: "in".into(),
            protocol: "gre".into(),
            source_ips: vec!["1.2.3.0/24".into()],
            destination_ips: vec![],
            port: Some("8000-8080".into()),
            description: Some("range".into()),
        };
        let mapped = parse_rule(rule);
        assert!(mapped.is_ingress);
        assert_eq!(mapped.protocol, Protocol::Other(47));
        assert_eq!(
            mapped.port_range,
            Some(PortRange {
                start: 8000,
                end: 8080
            })
        );
    }

    #[test]
    fn parse_port_range_normalizes_reversed_bounds() {
        // A reversed pair must be swapped so start <= end, matching the
        // inclusive-range contract of PortRange.
        assert_eq!(
            parse_port_range("8080-8000"),
            Some(PortRange {
                start: 8000,
                end: 8080
            })
        );
        // Already-ordered ranges and single ports are unchanged.
        assert_eq!(
            parse_port_range("8000-8080"),
            Some(PortRange::range(8000, 8080))
        );
        assert_eq!(parse_port_range("22"), Some(PortRange::single(22)));
    }

    #[test]
    fn command_failure_propagates() {
        // A failed `delete` must surface as a cloud Error::CommandFailed
        // (the runner's CommandFailed maps 1:1 onto the cloud variant).
        let runner = FakeRunner::new().strict().respond_err(
            CommandSpec::new("hcloud")
                .arg("firewall")
                .arg("delete")
                .arg("-o=json")
                .arg("--yes")
                .arg("nope"),
            toride_runner::Error::CommandFailed {
                program: "hcloud".into(),
                args: String::new(),
                exit_code: Some(1),
                stderr: "firewall not found".into(),
            },
        );
        let client = HetznerClient::new().with_runner(runner);
        let err = client.delete_firewall("nope").unwrap_err();
        match err {
            Error::CommandFailed { program, .. } => assert_eq!(program, "hcloud"),
            other => panic!("expected Error::CommandFailed, got {other:?}"),
        }
    }

    #[test]
    fn binary_not_found_maps_to_cloud_variant() {
        let runner = FakeRunner::new().strict().respond_err(
            CommandSpec::new("hcloud")
                .arg("firewall")
                .arg("list")
                .arg("-o=json"),
            toride_runner::Error::BinaryNotFound("hcloud".into()),
        );
        let client = HetznerClient::new().with_runner(runner);
        let err = client.list_firewalls().unwrap_err();
        assert!(
            matches!(err, Error::BinaryNotFound(ref b) if b == "hcloud"),
            "BinaryNotFound should map through, got {err:?}"
        );
    }

    #[test]
    fn with_token_sets_redacted_env() {
        // When a token is provided it travels via HCLOUD_TOKEN env, and the
        // command is redacted so the token never appears in error output.
        let (client, runner) = token_client("[]");
        let _ = client.list_firewalls();
        let call = runner
            .calls()
            .into_iter()
            .next()
            .expect("list call recorded");
        assert_eq!(
            call.env.iter().find(|(k, _)| k == "HCLOUD_TOKEN"),
            Some(&("HCLOUD_TOKEN".to_string(), "s3cret".to_string()))
        );
        assert!(call.redact, "token-bearing command must be redacted");
    }

    #[test]
    fn default_client_does_not_redact() {
        // Without a token the command reads creds from hcloud's own config, so
        // nothing secret is inline -> redact must be false (no over-redaction).
        let runner = FakeRunner::new().push_response(CommandOutput::from_stdout("[]"));
        let client = HetznerClient::new().with_runner(runner);
        let _ = client.list_firewalls();
        // runner was moved into the client; recover the recorded call by
        // rebuilding an identical client and inspecting its runner is not
        // possible (owned). Instead, assert the spec is non-redacted by
        // checking the default firewall_cmd path directly.
        let spec = HetznerClient::new().firewall_cmd("list");
        assert!(!spec.redact, "no token -> not redacted");
        assert!(spec.env.is_empty(), "no token -> no env injection");
    }

    fn token_client(stdout: &str) -> (HetznerClient, Arc<FakeRunner>) {
        let runner = Arc::new(FakeRunner::new().push_response(CommandOutput::from_stdout(stdout)));
        (
            HetznerClient::new()
                .with_token("s3cret")
                .with_arc_runner(runner.clone()),
            runner,
        )
    }
}
