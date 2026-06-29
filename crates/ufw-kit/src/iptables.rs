//! Structured iptables-save parsing (behind `firewall-iptables` feature).
//!
//! Parses the output of `iptables-save` and `ip6tables-save` into typed
//! Rust structures for diagnostic purposes. This module does NOT write
//! or modify any firewall state.

use crate::command::CommandRunner;
use crate::error::{Error, Result};
use crate::spec::CommandSpec;
use std::time::Duration;

// ============================================================================
// Types
// ============================================================================

/// A parsed iptables ruleset.
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct IptablesRuleset {
    /// Parsed tables.
    pub tables: Vec<IptablesTable>,
}

/// A single iptables table.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct IptablesTable {
    /// Table name (e.g., "filter", "nat", "mangle", "raw").
    pub name: String,
    /// Chains within this table.
    pub chains: Vec<IptablesChain>,
}

/// A single iptables chain.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct IptablesChain {
    /// Chain name.
    pub name: String,
    /// Chain policy (ACCEPT, DROP, etc.).
    pub policy: Option<String>,
    /// Packet/byte counters.
    pub counters: Option<(u64, u64)>,
    /// Rules in this chain.
    pub rules: Vec<IptablesRule>,
    /// Whether this is a user-defined chain (no policy line).
    pub is_builtin: bool,
}

/// A single iptables rule.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct IptablesRule {
    /// Chain this rule belongs to.
    pub chain: String,
    /// Rule specification (the part after `-A CHAIN`).
    pub spec: String,
    /// Packet/byte counters.
    pub counters: Option<(u64, u64)>,
    /// Parsed rule components.
    pub components: IptablesRuleComponents,
}

/// Parsed components of an iptables rule.
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct IptablesRuleComponents {
    /// Protocol filter (e.g., "tcp", "udp").
    pub protocol: Option<String>,
    /// Source address.
    pub source: Option<String>,
    /// Destination address.
    pub destination: Option<String>,
    /// Input interface.
    pub in_interface: Option<String>,
    /// Output interface.
    pub out_interface: Option<String>,
    /// Destination port(s).
    pub dest_port: Option<String>,
    /// Source port(s).
    pub source_port: Option<String>,
    /// Target action (ACCEPT, DROP, REJECT, DNAT, SNAT, MASQUERADE, etc.).
    pub target: Option<String>,
    /// Match modules (state, conntrack, etc.).
    pub matches: Vec<String>,
    /// Whether this is a comment rule.
    pub comment: Option<String>,
}

// ============================================================================
// Parsing
// ============================================================================

/// Parse iptables-save output into a structured ruleset.
pub fn parse_iptables_save(output: &str) -> Result<IptablesRuleset> {
    let mut tables = Vec::new();
    let mut current_table: Option<IptablesTable> = None;

    for line in output.lines() {
        let trimmed = line.trim();

        // Skip empty lines and comments
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        // Table header: *filter, *nat, *mangle, *raw
        if let Some(table_name) = trimmed.strip_prefix('*') {
            // Save previous table
            if let Some(table) = current_table.take() {
                tables.push(table);
            }
            current_table = Some(IptablesTable {
                name: table_name.to_string(),
                chains: Vec::new(),
            });
            continue;
        }

        // COMMIT ends the current table
        if trimmed == "COMMIT" {
            if let Some(table) = current_table.take() {
                tables.push(table);
            }
            continue;
        }

        // Chain definition: :CHAIN_NAME POLICY [PACKETS:BYTES]
        if let Some(rest) = trimmed.strip_prefix(':') {
            if let Some(table) = &mut current_table {
                if let Some(chain) = parse_chain_definition(rest) {
                    table.chains.push(chain);
                }
            }
            continue;
        }

        // Rule: -A CHAIN [options]
        if let Some(rest) = trimmed.strip_prefix("-A ") {
            if let Some(table) = &mut current_table {
                if let Some(rule) = parse_rule_line(rest) {
                    // Add the rule to the matching chain
                    if let Some(chain) = table.chains.iter_mut().find(|c| c.name == rule.chain) {
                        chain.rules.push(rule);
                    }
                }
            }
        }
    }

    // Handle case where output doesn't end with COMMIT
    if let Some(table) = current_table.take() {
        tables.push(table);
    }

    Ok(IptablesRuleset { tables })
}

/// Parse a chain definition line like "ufw-before-input - [0:0]".
fn parse_chain_definition(line: &str) -> Option<IptablesChain> {
    // Format: "CHAIN POLICY [PACKETS:BYTES]"
    let parts: Vec<&str> = line.splitn(3, ' ').collect();
    if parts.is_empty() {
        return None;
    }

    let name = parts[0].to_string();

    // Built-in chains have a policy (ACCEPT, DROP, etc.)
    // User-defined chains have "-"
    let (policy, counters, is_builtin) = if parts.len() >= 3 {
        let policy_str = parts[1].trim();
        let counter_str = parts[2].trim();
        let counters = parse_counters(counter_str);

        if policy_str == "-" {
            (None, counters, false)
        } else {
            (Some(policy_str.to_string()), counters, true)
        }
    } else {
        (None, None, false)
    };

    Some(IptablesChain {
        name,
        policy,
        counters,
        rules: Vec::new(),
        is_builtin,
    })
}

/// Parse counters like "[12345:67890]".
fn parse_counters(s: &str) -> Option<(u64, u64)> {
    let s = s.trim().trim_start_matches('[').trim_end_matches(']');
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() == 2 {
        let packets = parts[0].parse().ok()?;
        let bytes = parts[1].parse().ok()?;
        Some((packets, bytes))
    } else {
        None
    }
}

/// Parse a rule line (after `-A `).
fn parse_rule_line(line: &str) -> Option<IptablesRule> {
    // Format: "CHAIN -s 10.0.0.0/24 -j MASQUERADE"
    let space_pos = line.find(' ')?;
    let chain = line[..space_pos].to_string();
    let spec = line[space_pos..].trim().to_string();

    // Parse counters if present: [12345:67890] -s ...
    let (counters, remaining) = if spec.starts_with('[') {
        let bracket_end = spec.find(']')?;
        let counter_str = &spec[..=bracket_end];
        let c = parse_counters(counter_str);
        let rest = spec[bracket_end + 1..].trim().to_string();
        (c, rest)
    } else {
        (None, spec.clone())
    };

    let components = parse_rule_components(&remaining);

    Some(IptablesRule {
        chain: chain.clone(),
        spec,
        counters,
        components,
    })
}

/// Parse iptables rule spec into components.
fn parse_rule_components(spec: &str) -> IptablesRuleComponents {
    let mut components = IptablesRuleComponents::default();
    let tokens: Vec<&str> = spec.split_whitespace().collect();

    let mut i = 0;
    while i < tokens.len() {
        let token = tokens[i];

        match token {
            "-p" | "--protocol" => {
                if i + 1 < tokens.len() {
                    components.protocol = Some(tokens[i + 1].to_string());
                    i += 2;
                    continue;
                }
            }
            "-s" | "--source" => {
                if i + 1 < tokens.len() {
                    components.source = Some(tokens[i + 1].to_string());
                    i += 2;
                    continue;
                }
            }
            "-d" | "--destination" => {
                if i + 1 < tokens.len() {
                    components.destination = Some(tokens[i + 1].to_string());
                    i += 2;
                    continue;
                }
            }
            "-i" | "--in-interface" => {
                if i + 1 < tokens.len() {
                    components.in_interface = Some(tokens[i + 1].to_string());
                    i += 2;
                    continue;
                }
            }
            "-o" | "--out-interface" => {
                if i + 1 < tokens.len() {
                    components.out_interface = Some(tokens[i + 1].to_string());
                    i += 2;
                    continue;
                }
            }
            "--dport" | "--destination-port" => {
                if i + 1 < tokens.len() {
                    components.dest_port = Some(tokens[i + 1].to_string());
                    i += 2;
                    continue;
                }
            }
            "--sport" | "--source-port" => {
                if i + 1 < tokens.len() {
                    components.source_port = Some(tokens[i + 1].to_string());
                    i += 2;
                    continue;
                }
            }
            "-j" | "--jump" => {
                if i + 1 < tokens.len() {
                    components.target = Some(tokens[i + 1].to_string());
                    i += 2;
                    continue;
                }
            }
            "-m" | "--match" => {
                if i + 1 < tokens.len() {
                    components.matches.push(tokens[i + 1].to_string());
                    i += 2;
                    continue;
                }
            }
            "--comment" if i + 1 < tokens.len() => {
                // Comments may be quoted
                let mut comment = tokens[i + 1].to_string();
                // Handle quoted comments that got split
                if comment.starts_with('"') && !comment.ends_with('"') {
                    let mut j = i + 2;
                    while j < tokens.len() {
                        comment.push(' ');
                        comment.push_str(tokens[j]);
                        if tokens[j].ends_with('"') {
                            break;
                        }
                        j += 1;
                    }
                }
                components.comment = Some(comment.trim_matches('"').to_string());
                i += 2;
                continue;
            }
            _ => {}
        }

        i += 1;
    }

    components
}

// ============================================================================
// Inspection
// ============================================================================

/// Inspect iptables-save output as structured data.
pub fn inspect_iptables_structured(runner: &dyn CommandRunner) -> Result<IptablesRuleset> {
    let spec = CommandSpec {
        program: "iptables-save".into(),
        args: vec![],
        timeout: Some(Duration::from_secs(10)),
        requires_root: false,
        force_c_locale: true,
        redact_logs: false,
    };

    match runner.run(&spec) {
        Ok(result) if result.exit_code == Some(0) => parse_iptables_save(&result.stdout),
        Ok(result) => Err(Error::DoctorCheckFailed(format!(
            "iptables-save failed: {}",
            result.stderr
        ))),
        Err(e) => Err(Error::DoctorCheckFailed(format!(
            "iptables-save inspection failed: {e}"
        ))),
    }
}

/// Inspect ip6tables-save output as structured data.
pub fn inspect_ip6tables_structured(runner: &dyn CommandRunner) -> Result<IptablesRuleset> {
    let spec = CommandSpec {
        program: "ip6tables-save".into(),
        args: vec![],
        timeout: Some(Duration::from_secs(10)),
        requires_root: false,
        force_c_locale: true,
        redact_logs: false,
    };

    match runner.run(&spec) {
        Ok(result) if result.exit_code == Some(0) => parse_iptables_save(&result.stdout),
        Ok(result) => Err(Error::DoctorCheckFailed(format!(
            "ip6tables-save failed: {}",
            result.stderr
        ))),
        Err(e) => Err(Error::DoctorCheckFailed(format!(
            "ip6tables-save inspection failed: {e}"
        ))),
    }
}

/// Find UFW-related chains in an iptables ruleset.
#[must_use]
pub fn find_ufw_chains(ruleset: &IptablesRuleset) -> Vec<(&IptablesTable, &IptablesChain)> {
    ruleset
        .tables
        .iter()
        .flat_map(|t| {
            t.chains
                .iter()
                .filter(|c| c.name.to_lowercase().starts_with("ufw"))
                .map(move |c| (t, c))
        })
        .collect()
}

/// Find NAT/MASQUERADE rules in the ruleset.
#[must_use]
pub fn find_masquerade_rules(ruleset: &IptablesRuleset) -> Vec<&IptablesRule> {
    ruleset
        .tables
        .iter()
        .filter(|t| t.name == "nat")
        .flat_map(|t| t.chains.iter())
        .flat_map(|c| c.rules.iter())
        .filter(|r| {
            r.components
                .target
                .as_deref()
                .is_some_and(|t| t == "MASQUERADE" || t == "SNAT")
        })
        .collect()
}

/// Find rules that ACCEPT traffic on publicly-exposed ports.
#[must_use]
pub fn find_public_accept_rules(ruleset: &IptablesRuleset) -> Vec<&IptablesRule> {
    ruleset
        .tables
        .iter()
        .filter(|t| t.name == "filter")
        .flat_map(|t| t.chains.iter())
        .flat_map(|c| c.rules.iter())
        .filter(|r| {
            let is_accept = r
                .components
                .target
                .as_deref()
                .is_some_and(|t| t == "ACCEPT");
            let has_dport = r.components.dest_port.is_some();
            is_accept && has_dport
        })
        .collect()
}

/// Count total rules across all tables.
#[must_use]
pub fn count_iptables_rules(ruleset: &IptablesRuleset) -> usize {
    ruleset
        .tables
        .iter()
        .map(|t| t.chains.iter().map(|c| c.rules.len()).sum::<usize>())
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_IPTABLES_SAVE: &str = r#"# Generated by iptables-save
*filter
:INPUT ACCEPT [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
:ufw-before-input - [0:0]
:DOCKER - [0:0]
:DOCKER-ISOLATION-STAGE-1 - [0:0]
-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 80 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 443 -j ACCEPT
-A FORWARD -i docker0 -o docker0 -j ACCEPT
-A ufw-before-input -p tcp --dport 22 -j ACCEPT --comment "ufw allow ssh"
COMMIT
*nat
:PREROUTING ACCEPT [0:0]
:INPUT ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
:DOCKER - [0:0]
-A POSTROUTING -s 172.17.0.0/16 ! -o docker0 -j MASQUERADE
-A DOCKER -i docker0 -p tcp --dport 8080 -j DNAT --to-destination 172.17.0.2:80
COMMIT
"#;

    #[test]
    fn parse_iptables_save_should_parse_tables() {
        let result = parse_iptables_save(SAMPLE_IPTABLES_SAVE).unwrap();
        assert_eq!(result.tables.len(), 2);

        let filter = result.tables.iter().find(|t| t.name == "filter").unwrap();
        assert_eq!(filter.chains.len(), 6); // INPUT, FORWARD, OUTPUT, ufw-before-input, DOCKER, DOCKER-ISOLATION-STAGE-1

        let nat = result.tables.iter().find(|t| t.name == "nat").unwrap();
        assert_eq!(nat.chains.len(), 5); // PREROUTING, INPUT, OUTPUT, POSTROUTING, DOCKER
    }

    #[test]
    fn parse_iptables_save_should_parse_chain_policies() {
        let result = parse_iptables_save(SAMPLE_IPTABLES_SAVE).unwrap();
        let filter = result.tables.iter().find(|t| t.name == "filter").unwrap();

        let input = filter.chains.iter().find(|c| c.name == "INPUT").unwrap();
        assert_eq!(input.policy.as_deref(), Some("ACCEPT"));
        assert!(input.is_builtin);

        let forward = filter.chains.iter().find(|c| c.name == "FORWARD").unwrap();
        assert_eq!(forward.policy.as_deref(), Some("DROP"));
        assert!(forward.is_builtin);

        let docker = filter.chains.iter().find(|c| c.name == "DOCKER").unwrap();
        assert_eq!(docker.policy, None);
        assert!(!docker.is_builtin);
    }

    #[test]
    fn parse_iptables_save_should_parse_rules() {
        let result = parse_iptables_save(SAMPLE_IPTABLES_SAVE).unwrap();
        let filter = result.tables.iter().find(|t| t.name == "filter").unwrap();
        let input = filter.chains.iter().find(|c| c.name == "INPUT").unwrap();

        assert_eq!(input.rules.len(), 4);

        // Check SSH rule
        let ssh_rule = input
            .rules
            .iter()
            .find(|r| r.components.dest_port.as_deref().is_some_and(|p| p == "22"));
        assert!(ssh_rule.is_some());
        let ssh = ssh_rule.unwrap();
        assert_eq!(ssh.components.protocol.as_deref(), Some("tcp"));
        assert_eq!(ssh.components.target.as_deref(), Some("ACCEPT"));
    }

    #[test]
    fn parse_iptables_save_should_parse_nat_masquerade() {
        let result = parse_iptables_save(SAMPLE_IPTABLES_SAVE).unwrap();
        let nat = result.tables.iter().find(|t| t.name == "nat").unwrap();
        let postrouting = nat.chains.iter().find(|c| c.name == "POSTROUTING").unwrap();

        assert_eq!(postrouting.rules.len(), 1);
        let masq = &postrouting.rules[0];
        assert_eq!(masq.components.target.as_deref(), Some("MASQUERADE"));
        assert_eq!(masq.components.source.as_deref(), Some("172.17.0.0/16"));
    }

    #[test]
    fn find_ufw_chains_should_find_ufw_chains() {
        let result = parse_iptables_save(SAMPLE_IPTABLES_SAVE).unwrap();
        let ufw_chains = find_ufw_chains(&result);
        assert_eq!(ufw_chains.len(), 1);
        assert_eq!(ufw_chains[0].1.name, "ufw-before-input");
    }

    #[test]
    fn find_masquerade_rules_should_find_nat_rules() {
        let result = parse_iptables_save(SAMPLE_IPTABLES_SAVE).unwrap();
        let masq_rules = find_masquerade_rules(&result);
        assert_eq!(masq_rules.len(), 1);
    }

    #[test]
    fn find_public_accept_rules_should_find_exposed_ports() {
        let result = parse_iptables_save(SAMPLE_IPTABLES_SAVE).unwrap();
        let public = find_public_accept_rules(&result);
        // Rules with ACCEPT + --dport in filter table
        assert!(!public.is_empty());
    }

    #[test]
    fn count_iptables_rules_should_sum_all() {
        let result = parse_iptables_save(SAMPLE_IPTABLES_SAVE).unwrap();
        let count = count_iptables_rules(&result);
        // 4 INPUT + 1 FORWARD + 1 ufw-before-input + 2 NAT = 8
        assert_eq!(count, 8);
    }

    #[test]
    fn parse_iptables_save_should_handle_empty() {
        let result = parse_iptables_save("").unwrap();
        assert!(result.tables.is_empty());
    }

    #[test]
    fn parse_iptables_save_should_handle_no_commit() {
        let input = "*filter\n:INPUT ACCEPT [0:0]\n-A INPUT -j ACCEPT\n";
        let result = parse_iptables_save(input).unwrap();
        assert_eq!(result.tables.len(), 1);
        assert_eq!(result.tables[0].chains[0].rules.len(), 1);
    }

    #[test]
    fn rule_components_should_parse_multi_option_rule() {
        let spec = "-p tcp -s 10.0.0.0/24 -d 192.168.1.1 --dport 443 -j ACCEPT -m conntrack --comment \"my rule\"";
        let components = parse_rule_components(spec);
        assert_eq!(components.protocol.as_deref(), Some("tcp"));
        assert_eq!(components.source.as_deref(), Some("10.0.0.0/24"));
        assert_eq!(components.destination.as_deref(), Some("192.168.1.1"));
        assert_eq!(components.dest_port.as_deref(), Some("443"));
        assert_eq!(components.target.as_deref(), Some("ACCEPT"));
        assert!(components.matches.contains(&"conntrack".to_string()));
        assert_eq!(components.comment.as_deref(), Some("my rule"));
    }
}
