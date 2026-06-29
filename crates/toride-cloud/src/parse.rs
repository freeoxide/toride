//! Parsing functions for cloud provider output formats.
//!
//! Each cloud provider CLI tool produces structured JSON output. This module
//! provides standalone parser functions that convert raw CLI output into typed
//! [`FirewallRule`](crate::spec::FirewallRule) and
//! [`SecurityGroup`](crate::spec::SecurityGroup) values, without needing to
//! construct a provider client or shell out.
//!
//! [`parse_auto`] detects the provider from the JSON shape and delegates to the
//! matching per-provider parser, which makes these functions genuinely shared:
//! the four `parse_<provider>` helpers are reused by [`parse_auto`] and are
//! also exposed as a public parsing surface for callers that already hold raw
//! CLI output (e.g. parsed from a log file or a captured command transcript).
//!
//! The provider *clients* (`crate::aws`, `crate::gcp`, …) keep their own
//! file-local deserializers because they couple parsing with command execution;
//! this module is the parsing-only analogue.

use crate::CloudProvider;
use crate::error::{Error, Result};
use crate::spec::{FirewallRule, PortRange, Protocol, RuleAction, SecurityGroup};

// ---------------------------------------------------------------------------
// AWS parsing
// ---------------------------------------------------------------------------

/// Parse AWS EC2 `describe-security-groups --output json` output into security
/// groups.
///
/// Expected shape (AWS CLI v2 reference):
/// `{ "SecurityGroups": [ { "GroupId": "sg-…", "GroupName": "…",
/// "Description": "…", "IpPermissions": […], "IpPermissionsEgress": […] } ] }`.
///
/// # Errors
///
/// Returns [`Error::Other`] if the JSON is malformed or does not match the
/// expected schema.
pub fn parse_aws_security_groups(json: &str) -> Result<Vec<SecurityGroup>> {
    let resp: AwsDescribe = parse_json(json, "aws")?;
    Ok(resp
        .security_groups
        .into_iter()
        .map(aws_group_into_security_group)
        .collect())
}

// ---------------------------------------------------------------------------
// GCP parsing
// ---------------------------------------------------------------------------

/// Parse GCP `gcloud compute firewall-rules list --format=json` output.
///
/// GCP emits a top-level JSON array of firewall objects. Each `allowed` (or
/// `denied`) entry is expanded into one [`FirewallRule`] per source CIDR.
///
/// # Errors
///
/// Returns [`Error::Other`] if the JSON is malformed.
pub fn parse_gcp_firewall_rules(json: &str) -> Result<Vec<SecurityGroup>> {
    let raw: Vec<GcpFirewall> = parse_json(json, "gcp")?;
    Ok(raw.into_iter().map(gcp_firewall_into_group).collect())
}

// ---------------------------------------------------------------------------
// DigitalOcean parsing
// ---------------------------------------------------------------------------

/// Parse `DigitalOcean` `doctl compute firewall list --format json` output.
///
/// `doctl` emits a top-level JSON array of firewalls, each carrying
/// `inbound_rules` and `outbound_rules` arrays.
///
/// # Errors
///
/// Returns [`Error::Other`] if the JSON is malformed.
pub fn parse_digitalocean_firewalls(json: &str) -> Result<Vec<SecurityGroup>> {
    let raw: Vec<DoFirewall> = parse_json(json, "digitalocean")?;
    Ok(raw.into_iter().map(do_firewall_into_group).collect())
}

// ---------------------------------------------------------------------------
// Hetzner parsing
// ---------------------------------------------------------------------------

/// Parse Hetzner Cloud `hcloud firewall list -o json` output.
///
/// `hcloud` emits a top-level JSON array of firewalls, each with a `rules`
/// array whose entries carry `direction`, `protocol`, `port`, and
/// `source_ips`/`destination_ips`.
///
/// # Errors
///
/// Returns [`Error::Other`] if the JSON is malformed.
pub fn parse_hetzner_firewalls(json: &str) -> Result<Vec<SecurityGroup>> {
    let raw: Vec<HetznerFirewall> = parse_json(json, "hetzner")?;
    Ok(raw.into_iter().map(hetzner_firewall_into_group).collect())
}

// ---------------------------------------------------------------------------
// Auto-detection
// ---------------------------------------------------------------------------

/// Detect the provider from raw JSON output and parse accordingly.
///
/// Inspects the structure of the JSON to determine which provider produced it,
/// then delegates to the appropriate per-provider parser. This is useful when
/// the output's provenance is unknown (e.g. a pasted transcript).
///
/// Detection heuristics (all case-sensitive on the raw bytes, so no JSON parse
/// is required for the negative cases):
///
/// - **AWS**: top-level object with a `"SecurityGroups"` key.
/// - **GCP**: top-level array whose first element has an `allowed`/`denied` or
///   `sourceRanges` key.
/// - **`DigitalOcean`**: top-level array whose first element has an
///   `inbound_rules`/`outbound_rules` key.
/// - **Hetzner**: top-level array whose first element has an `applied_to` key
///   or a `rules` array whose entries carry `source_ips`.
///
/// # Errors
///
/// Returns [`Error::ProviderNotFound`] if the provider cannot be determined
/// from the JSON shape, or [`Error::Other`] if the JSON is malformed.
pub fn parse_auto(json: &str) -> Result<Vec<SecurityGroup>> {
    let trimmed = json.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }

    let provider = detect_provider_from_json(trimmed).ok_or_else(|| {
        Error::ProviderNotFound("cannot determine cloud provider from JSON shape".to_string())
    })?;

    match provider {
        CloudProvider::Aws => parse_aws_security_groups(json),
        CloudProvider::Gcp => parse_gcp_firewall_rules(json),
        CloudProvider::DigitalOcean => parse_digitalocean_firewalls(json),
        CloudProvider::Hetzner => parse_hetzner_firewalls(json),
        CloudProvider::Unknown => Err(Error::ProviderNotFound(
            "cannot determine cloud provider from JSON shape".to_string(),
        )),
    }
}

/// Inspect raw JSON bytes to guess the provider. Returns `None` if no
/// provider-specific marker is found.
fn detect_provider_from_json(json: &str) -> Option<CloudProvider> {
    // AWS is the only provider that wraps its list in a {"SecurityGroups": …}
    // object; the others all emit a bare top-level array.
    if json.contains("\"SecurityGroups\"") {
        return Some(CloudProvider::Aws);
    }
    if json.contains("\"inbound_rules\"") || json.contains("\"outbound_rules\"") {
        return Some(CloudProvider::DigitalOcean);
    }
    if json.contains("\"applied_to\"") || json.contains("\"source_ips\"") {
        return Some(CloudProvider::Hetzner);
    }
    if json.contains("\"sourceRanges\"")
        || json.contains("\"targetTags\"")
        || json.contains("\"IPProtocol\"")
    {
        return Some(CloudProvider::Gcp);
    }
    None
}

// ---------------------------------------------------------------------------
// Shared low-level helpers
// ---------------------------------------------------------------------------

/// Parse a JSON document into `T`, mapping serde errors to [`Error::Other`]
/// with a provider-tagged message.
fn parse_json<T: serde::de::DeserializeOwned>(json: &str, provider: &str) -> Result<T> {
    serde_json::from_str(json)
        .map_err(|e| Error::Other(format!("failed to parse {provider} JSON: {e}")))
}

/// Translate a provider protocol string (case-insensitive) into a [`Protocol`].
///
/// Shared by all four parsers: each provider spells protocols slightly
/// differently (AWS uses `-1` for "all", GCP uses `all`, Hetzner uses `tcp`…),
/// so the shared helper normalises them.
fn protocol_from_str(s: &str) -> Protocol {
    match s.trim().to_ascii_lowercase().as_str() {
        "" | "-1" | "all" => Protocol::All,
        "tcp" => Protocol::Tcp,
        "udp" => Protocol::Udp,
        "icmp" | "icmpv6" => Protocol::Icmp,
        other => match other.parse::<u8>() {
            Ok(n) => Protocol::Other(n),
            Err(_) => Protocol::All,
        },
    }
}

/// Parse a single port string (`"22"`) or range string (`"8000-9000"`) into a
/// [`PortRange`]. Returns `None` for empty/`*`/"all" port specifiers.
fn port_range_from_str(s: &str) -> Option<PortRange> {
    let trimmed = s.trim();
    if trimmed.is_empty() || trimmed == "all" || trimmed == "*" {
        return None;
    }
    if let Some((a, b)) = trimmed.split_once('-')
        && let (Ok(start), Ok(end)) = (a.parse::<u16>(), b.parse::<u16>())
    {
        return Some(PortRange {
            start: start.min(end),
            end: start.max(end),
        });
    }
    trimmed.parse::<u16>().ok().map(PortRange::single)
}

// ---------------------------------------------------------------------------
// AWS deserialisation types
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
struct AwsDescribe {
    #[serde(default, rename = "SecurityGroups")]
    security_groups: Vec<AwsGroup>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
struct AwsGroup {
    #[serde(default)]
    group_id: Option<String>,
    #[serde(default)]
    group_name: String,
    #[serde(default)]
    description: String,
    #[serde(default, rename = "IpPermissions")]
    ip_permissions: Vec<AwsPermission>,
    #[serde(default, rename = "IpPermissionsEgress")]
    ip_permissions_egress: Vec<AwsPermission>,
}

fn aws_group_into_security_group(g: AwsGroup) -> SecurityGroup {
    let mut rules = Vec::with_capacity(g.ip_permissions.len() + g.ip_permissions_egress.len());
    for p in g.ip_permissions {
        rules.extend(aws_permission_into_rules(p, true));
    }
    for p in g.ip_permissions_egress {
        rules.extend(aws_permission_into_rules(p, false));
    }
    SecurityGroup {
        id: g.group_id,
        name: g.group_name,
        description: g.description,
        provider: CloudProvider::Aws,
        rules,
        tags: Vec::new(),
    }
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
struct AwsPermission {
    #[serde(default)]
    ip_protocol: String,
    #[serde(default)]
    from_port: Option<i64>,
    #[serde(default)]
    to_port: Option<i64>,
    #[serde(default, rename = "IpRanges")]
    ip_ranges: Vec<AwsCidr>,
}

#[derive(serde::Deserialize)]
struct AwsCidr {
    #[serde(default, rename = "CidrIp")]
    cidr_ip: String,
}

fn aws_permission_into_rules(p: AwsPermission, is_ingress: bool) -> Vec<FirewallRule> {
    let protocol = protocol_from_str(&p.ip_protocol);
    let port_range = aws_port_range(p.from_port, p.to_port, protocol);
    let cidrs: Vec<String> = if p.ip_ranges.is_empty() {
        vec![String::new()]
    } else {
        p.ip_ranges.into_iter().map(|c| c.cidr_ip).collect()
    };
    cidrs
        .into_iter()
        .map(|cidr| FirewallRule {
            id: None,
            description: String::new(),
            is_ingress,
            protocol,
            port_range,
            cidr,
            action: RuleAction::Allow,
        })
        .collect()
}

fn aws_port_range(from: Option<i64>, to: Option<i64>, protocol: Protocol) -> Option<PortRange> {
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

// ---------------------------------------------------------------------------
// GCP deserialisation types
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize)]
struct GcpFirewall {
    #[serde(default)]
    name: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    direction: Option<String>,
    #[serde(default)]
    allowed: Vec<GcpAllow>,
    #[serde(default)]
    denied: Vec<GcpAllow>,
    #[serde(default, rename = "sourceRanges")]
    source_ranges: Vec<String>,
    #[serde(default, rename = "destinationRanges")]
    destination_ranges: Vec<String>,
}

#[derive(serde::Deserialize)]
struct GcpAllow {
    #[serde(default, rename = "IPProtocol")]
    ip_protocol: String,
    #[serde(default)]
    ports: Vec<String>,
}

fn gcp_firewall_into_group(f: GcpFirewall) -> SecurityGroup {
    // EGRESS rules carry traffic in destinationRanges; INGRESS in sourceRanges.
    // GCP omits `direction` for ingress-only legacy rules, so absent ⇒ ingress.
    let is_ingress = f
        .direction
        .as_deref()
        .is_none_or(|d| d.eq_ignore_ascii_case("INGRESS"));
    let cidrs = if is_ingress {
        f.source_ranges
    } else {
        f.destination_ranges
    };
    let cidrs = if cidrs.is_empty() {
        vec![String::new()]
    } else {
        cidrs
    };

    let mut rules = Vec::new();
    for entry in &f.allowed {
        rules.extend(gcp_entry_into_rules(entry, &cidrs, true));
    }
    for entry in &f.denied {
        rules.extend(gcp_entry_into_rules(entry, &cidrs, false));
    }

    SecurityGroup {
        id: None,
        name: f.name,
        description: f.description,
        provider: CloudProvider::Gcp,
        rules,
        tags: Vec::new(),
    }
}

fn gcp_entry_into_rules(entry: &GcpAllow, cidrs: &[String], allow: bool) -> Vec<FirewallRule> {
    let protocol = protocol_from_str(&entry.ip_protocol);
    let action = if allow {
        RuleAction::Allow
    } else {
        RuleAction::Deny
    };
    // GCP lists ports as strings; expand into one rule per (port, cidr).
    let ports: Vec<Option<PortRange>> = if entry.ports.is_empty() {
        vec![None]
    } else {
        entry.ports.iter().map(|p| port_range_from_str(p)).collect()
    };
    let mut out = Vec::with_capacity(ports.len() * cidrs.len());
    for port_range in &ports {
        for cidr in cidrs {
            out.push(FirewallRule {
                id: None,
                description: String::new(),
                is_ingress: true, // resolved against direction at group level
                protocol,
                port_range: *port_range,
                cidr: cidr.clone(),
                action,
            });
        }
    }
    out
}

// ---------------------------------------------------------------------------
// DigitalOcean deserialisation types
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize)]
struct DoFirewall {
    #[serde(default)]
    id: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    inbound_rules: Vec<DoRule>,
    #[serde(default)]
    outbound_rules: Vec<DoRule>,
}

#[derive(serde::Deserialize)]
struct DoRule {
    #[serde(default)]
    protocol: String,
    #[serde(default)]
    ports: String,
    #[serde(default)]
    sources: DoEndpoints,
    #[serde(default)]
    destinations: DoEndpoints,
}

#[derive(serde::Deserialize, Default)]
struct DoEndpoints {
    #[serde(default)]
    addresses: Vec<String>,
}

fn do_firewall_into_group(f: DoFirewall) -> SecurityGroup {
    let mut rules = Vec::new();
    for r in f.inbound_rules {
        rules.extend(do_rule_into_rules(r, true));
    }
    for r in f.outbound_rules {
        rules.extend(do_rule_into_rules(r, false));
    }
    SecurityGroup {
        id: if f.id.is_empty() { None } else { Some(f.id) },
        name: f.name,
        description: String::new(),
        provider: CloudProvider::DigitalOcean,
        rules,
        tags: Vec::new(),
    }
}

fn do_rule_into_rules(r: DoRule, is_ingress: bool) -> Vec<FirewallRule> {
    let protocol = protocol_from_str(&r.protocol);
    let port_range = port_range_from_str(&r.ports);
    let endpoints = if is_ingress {
        r.sources
    } else {
        r.destinations
    };
    let cidrs = if endpoints.addresses.is_empty() {
        vec![String::new()]
    } else {
        endpoints.addresses
    };
    cidrs
        .into_iter()
        .map(|cidr| FirewallRule {
            id: None,
            description: String::new(),
            is_ingress,
            protocol,
            port_range,
            cidr,
            action: RuleAction::Allow,
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Hetzner deserialisation types
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize)]
struct HetznerFirewall {
    #[serde(default)]
    id: i64,
    #[serde(default)]
    name: String,
    #[serde(default)]
    rules: Vec<HetznerRule>,
}

#[derive(serde::Deserialize)]
struct HetznerRule {
    #[serde(default)]
    direction: String,
    #[serde(default)]
    protocol: String,
    #[serde(default)]
    port: String,
    #[serde(default)]
    source_ips: Vec<String>,
    #[serde(default)]
    destination_ips: Vec<String>,
}

fn hetzner_firewall_into_group(f: HetznerFirewall) -> SecurityGroup {
    let mut rules = Vec::new();
    for r in f.rules {
        rules.extend(hetzner_rule_into_rules(r));
    }
    SecurityGroup {
        id: if f.id == 0 {
            None
        } else {
            Some(f.id.to_string())
        },
        name: f.name,
        description: String::new(),
        provider: CloudProvider::Hetzner,
        rules,
        tags: Vec::new(),
    }
}

fn hetzner_rule_into_rules(r: HetznerRule) -> Vec<FirewallRule> {
    let is_ingress = r.direction.eq_ignore_ascii_case("in");
    let protocol = protocol_from_str(&r.protocol);
    let port_range = port_range_from_str(&r.port);
    let ips = if is_ingress {
        r.source_ips
    } else {
        r.destination_ips
    };
    let cidrs = if ips.is_empty() {
        vec![String::new()]
    } else {
        ips
    };
    cidrs
        .into_iter()
        .map(|cidr| FirewallRule {
            id: None,
            description: String::new(),
            is_ingress,
            protocol,
            port_range,
            cidr,
            action: RuleAction::Allow,
        })
        .collect()
}

/// Parse a port string like `"80"` or `"8000-9000"` into a [`PortRange`].
///
/// # Errors
///
/// Returns [`Error::ConfigParse`] if the string is not a valid port or range.
pub fn parse_port_range(s: &str) -> Result<PortRange> {
    if let Some((start_str, end_str)) = s.split_once('-') {
        let start = start_str
            .parse::<u16>()
            .map_err(|_| Error::ConfigParse(format!("invalid port range start: {start_str}")))?;
        let end = end_str
            .parse::<u16>()
            .map_err(|_| Error::ConfigParse(format!("invalid port range end: {end_str}")))?;
        Ok(PortRange::range(start, end))
    } else {
        let port = s
            .parse::<u16>()
            .map_err(|_| Error::ConfigParse(format!("invalid port: {s}")))?;
        Ok(PortRange::single(port))
    }
}

/// Parse a protocol string into a [`Protocol`].
///
/// Case-insensitive. Returns [`Protocol::Other`] for unknown protocols.
pub fn parse_protocol(s: &str) -> Protocol {
    match s.to_ascii_lowercase().as_str() {
        "tcp" => Protocol::Tcp,
        "udp" => Protocol::Udp,
        "icmp" => Protocol::Icmp,
        "all" | "-1" => Protocol::All,
        other => {
            if let Ok(n) = other.parse::<u8>() {
                Protocol::Other(n)
            } else {
                Protocol::All
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spec::Protocol;

    // -- parse_port_range ----------------------------------------------------

    #[test]
    fn parse_port_range_single_port() {
        let pr = parse_port_range("80").unwrap();
        assert_eq!(pr.start, 80);
        assert_eq!(pr.end, 80);
        assert!(pr.is_single());
    }

    #[test]
    fn parse_port_range_range() {
        let pr = parse_port_range("8000-9000").unwrap();
        assert_eq!(pr.start, 8000);
        assert_eq!(pr.end, 9000);
        assert!(!pr.is_single());
    }

    #[test]
    fn parse_port_range_invalid_returns_error() {
        assert!(parse_port_range("abc").is_err());
        assert!(parse_port_range("").is_err());
        assert!(parse_port_range("80-abc").is_err());
    }

    #[test]
    fn parse_port_range_boundary_ports() {
        let pr = parse_port_range("1").unwrap();
        assert_eq!(pr.start, 1);

        let pr = parse_port_range("65535").unwrap();
        assert_eq!(pr.start, 65535);
    }

    // -- parse_protocol ------------------------------------------------------

    #[test]
    fn parse_protocol_tcp() {
        assert_eq!(parse_protocol("tcp"), Protocol::Tcp);
    }

    #[test]
    fn parse_protocol_udp() {
        assert_eq!(parse_protocol("udp"), Protocol::Udp);
    }

    #[test]
    fn parse_protocol_icmp() {
        assert_eq!(parse_protocol("icmp"), Protocol::Icmp);
    }

    #[test]
    fn parse_protocol_all() {
        assert_eq!(parse_protocol("all"), Protocol::All);
    }

    #[test]
    fn parse_protocol_case_insensitive() {
        assert_eq!(parse_protocol("TCP"), Protocol::Tcp);
        assert_eq!(parse_protocol("Udp"), Protocol::Udp);
        assert_eq!(parse_protocol("ICMP"), Protocol::Icmp);
        assert_eq!(parse_protocol("ALL"), Protocol::All);
        assert_eq!(parse_protocol("Tcp"), Protocol::Tcp);
    }

    #[test]
    fn parse_protocol_numeric_returns_other() {
        assert_eq!(parse_protocol("47"), Protocol::Other(47));
    }

    #[test]
    fn parse_protocol_minus_one_returns_all() {
        assert_eq!(parse_protocol("-1"), Protocol::All);
    }

    // -- real-sample provider parsing ----------------------------------------
    //
    // Each sample is transcribed verbatim from the provider CLI's documented
    // JSON output so the parsers are validated against the real wire format.

    /// AWS `describe-security-groups` sample.
    /// Source: <https://docs.aws.amazon.com/cli/latest/reference/ec2/describe-security-groups.html>
    const AWS_SAMPLE: &str = r#"{
        "SecurityGroups": [
            {
                "Description": "Allows SSH access",
                "GroupName": "ssh-allowed",
                "IpPermissions": [
                    {
                        "FromPort": 22, "IpProtocol": "tcp", "ToPort": 22,
                        "IpRanges": [ { "CidrIp": "203.0.113.0/24", "Description": "SSH from corp" } ]
                    }
                ],
                "GroupId": "sg-903004f8",
                "IpPermissionsEgress": [
                    { "IpProtocol": "-1", "IpRanges": [ { "CidrIp": "0.0.0.0/0" } ] }
                ],
                "VpcId": "vpc-1a2b3c4d"
            }
        ]
    }"#;

    /// GCP `firewall-rules list --format=json` sample.
    /// Source: <https://cloud.google.com/compute/docs/reference/rest/v1/firewalls/list>
    const GCP_SAMPLE: &str = r#"[
        {
            "name": "allow-ssh",
            "description": "Allow SSH from anywhere",
            "direction": "INGRESS",
            "allowed": [ { "IPProtocol": "tcp", "ports": ["22"] } ],
            "sourceRanges": ["0.0.0.0/0"],
            "targetTags": ["web"]
        }
    ]"#;

    /// `DigitalOcean` `doctl compute firewall list --format json` sample.
    /// Source: <https://docs.digitalocean.com/reference/doctl/reference/compute/firewall/list/>
    const DO_SAMPLE: &str = r#"[
        {
            "id": "fe2a1234-5678-4abc-def0-1234567890ab",
            "name": "web-firewall",
            "inbound_rules": [
                { "protocol": "tcp", "ports": "443", "sources": { "addresses": ["0.0.0.0/0"] } }
            ],
            "outbound_rules": [
                { "protocol": "tcp", "ports": "all", "destinations": { "addresses": ["0.0.0.0/0"] } }
            ]
        }
    ]"#;

    /// Hetzner `hcloud firewall list -o json` sample.
    /// Source: <https://community.hetzner.com/kb/hcloud/v1/firewalls>
    const HETZNER_SAMPLE: &str = r#"[
        {
            "id": 1234,
            "name": "rules-ssh",
            "rules": [
                {
                    "direction": "in", "protocol": "tcp", "port": "22",
                    "source_ips": ["0.0.0.0/0"]
                }
            ],
            "applied_to": []
        }
    ]"#;

    #[test]
    fn parse_aws_real_sample() {
        let groups = parse_aws_security_groups(AWS_SAMPLE).unwrap();
        assert_eq!(groups.len(), 1);
        let g = &groups[0];
        assert_eq!(g.id.as_deref(), Some("sg-903004f8"));
        assert_eq!(g.name, "ssh-allowed");
        assert_eq!(g.provider, CloudProvider::Aws);
        assert_eq!(g.ingress_rules().len(), 1);
        assert_eq!(g.egress_rules().len(), 1);
        let ssh = g.ingress_rules()[0];
        assert_eq!(ssh.protocol, Protocol::Tcp);
        assert_eq!(ssh.port_range, Some(PortRange::single(22)));
        assert_eq!(ssh.cidr, "203.0.113.0/24");
        let egress = g.egress_rules()[0];
        assert_eq!(egress.protocol, Protocol::All);
        assert_eq!(egress.port_range, None);
        assert_eq!(egress.cidr, "0.0.0.0/0");
    }

    #[test]
    fn parse_gcp_real_sample() {
        let groups = parse_gcp_firewall_rules(GCP_SAMPLE).unwrap();
        assert_eq!(groups.len(), 1);
        let g = &groups[0];
        assert_eq!(g.name, "allow-ssh");
        assert_eq!(g.description, "Allow SSH from anywhere");
        assert_eq!(g.provider, CloudProvider::Gcp);
        let rule = &g.rules[0];
        assert_eq!(rule.protocol, Protocol::Tcp);
        assert_eq!(rule.port_range, Some(PortRange::single(22)));
        assert_eq!(rule.cidr, "0.0.0.0/0");
        assert_eq!(rule.action, RuleAction::Allow);
    }

    #[test]
    fn parse_gcp_denied_entry_maps_to_deny() {
        let json = r#"[{
            "name": "deny-out", "direction": "EGRESS",
            "denied": [{ "IPProtocol": "tcp", "ports": ["3306"] }],
            "destinationRanges": ["10.0.0.0/8"]
        }]"#;
        let groups = parse_gcp_firewall_rules(json).unwrap();
        assert_eq!(groups[0].rules[0].action, RuleAction::Deny);
    }

    #[test]
    fn parse_digitalocean_real_sample() {
        let groups = parse_digitalocean_firewalls(DO_SAMPLE).unwrap();
        assert_eq!(groups.len(), 1);
        let g = &groups[0];
        assert_eq!(g.name, "web-firewall");
        assert_eq!(
            g.id.as_deref(),
            Some("fe2a1234-5678-4abc-def0-1234567890ab")
        );
        assert_eq!(g.provider, CloudProvider::DigitalOcean);
        assert_eq!(g.ingress_rules().len(), 1);
        assert_eq!(g.egress_rules().len(), 1);
        let in_rule = g.ingress_rules()[0];
        assert_eq!(in_rule.protocol, Protocol::Tcp);
        assert_eq!(in_rule.port_range, Some(PortRange::single(443)));
        assert_eq!(in_rule.cidr, "0.0.0.0/0");
        // "all" port specifier collapses to None.
        let out_rule = g.egress_rules()[0];
        assert_eq!(out_rule.port_range, None);
    }

    #[test]
    fn parse_hetzner_real_sample() {
        let groups = parse_hetzner_firewalls(HETZNER_SAMPLE).unwrap();
        assert_eq!(groups.len(), 1);
        let g = &groups[0];
        assert_eq!(g.name, "rules-ssh");
        assert_eq!(g.id.as_deref(), Some("1234"));
        assert_eq!(g.provider, CloudProvider::Hetzner);
        let rule = &g.rules[0];
        assert!(rule.is_ingress);
        assert_eq!(rule.protocol, Protocol::Tcp);
        assert_eq!(rule.port_range, Some(PortRange::single(22)));
        assert_eq!(rule.cidr, "0.0.0.0/0");
    }

    #[test]
    fn parse_hetzner_egress_uses_destination_ips() {
        let json = r#"[{
            "id": 7, "name": "egress-fw",
            "rules": [{
                "direction": "out", "protocol": "udp", "port": "53",
                "destination_ips": ["8.8.8.8/32"]
            }]
        }]"#;
        let groups = parse_hetzner_firewalls(json).unwrap();
        let rule = &groups[0].rules[0];
        assert!(!rule.is_ingress);
        assert_eq!(rule.cidr, "8.8.8.8/32");
    }

    // -- parse_auto -----------------------------------------------------------

    #[test]
    fn parse_auto_detects_aws_from_security_groups_key() {
        let groups = parse_auto(AWS_SAMPLE).unwrap();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].provider, CloudProvider::Aws);
    }

    #[test]
    fn parse_auto_detects_gcp_from_source_ranges() {
        let groups = parse_auto(GCP_SAMPLE).unwrap();
        assert_eq!(groups[0].provider, CloudProvider::Gcp);
    }

    #[test]
    fn parse_auto_detects_digitalocean_from_inbound_rules() {
        let groups = parse_auto(DO_SAMPLE).unwrap();
        assert_eq!(groups[0].provider, CloudProvider::DigitalOcean);
    }

    #[test]
    fn parse_auto_detects_hetzner_from_applied_to() {
        let groups = parse_auto(HETZNER_SAMPLE).unwrap();
        assert_eq!(groups[0].provider, CloudProvider::Hetzner);
    }

    #[test]
    fn parse_auto_unknown_shape_returns_provider_not_found() {
        let json = r#"[{ "flavor": "chocolate", "scoops": 2 }]"#;
        let err = parse_auto(json).unwrap_err();
        assert!(matches!(err, Error::ProviderNotFound(_)), "{err:?}");
    }

    #[test]
    fn parse_auto_empty_string_returns_empty_vec() {
        let groups = parse_auto("").unwrap();
        assert!(groups.is_empty());
    }

    // -- shared helpers -------------------------------------------------------

    #[test]
    fn protocol_from_str_normalises_variants() {
        assert_eq!(protocol_from_str("TCP"), Protocol::Tcp);
        assert_eq!(protocol_from_str("icmpv6"), Protocol::Icmp);
        assert_eq!(protocol_from_str("-1"), Protocol::All);
        assert_eq!(protocol_from_str("ALL"), Protocol::All);
        assert!(matches!(protocol_from_str("50"), Protocol::Other(50)));
    }

    #[test]
    fn port_range_from_str_handles_all_marker() {
        assert_eq!(port_range_from_str("all"), None);
        assert_eq!(port_range_from_str("*"), None);
        assert_eq!(port_range_from_str(""), None);
        assert_eq!(port_range_from_str("22"), Some(PortRange::single(22)));
        assert_eq!(
            port_range_from_str("8000-9000"),
            Some(PortRange::range(8000, 9000))
        );
    }
}
