//! Structured nftables JSON inspection (behind `firewall-nft` feature).
//!
//! Parses the JSON output of `nft -j list ruleset` into typed Rust structures.
//! This provides structured access to nftables rules, chains, and tables
//! for diagnostic purposes. This module does NOT write or modify any
//! firewall state.

use crate::command::CommandRunner;
use crate::error::{Error, Result};
use crate::spec::CommandSpec;
use std::time::Duration;

// ============================================================================
// Types
// ============================================================================

/// A parsed nftables ruleset.
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct NftRuleset {
    /// Parsed tables.
    pub tables: Vec<NftTable>,
}

/// A single nftables table.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct NftTable {
    /// Table family (e.g., "ip", "ip6", "inet", "bridge", "arp").
    pub family: String,
    /// Table name.
    pub name: String,
    /// Chains within this table.
    pub chains: Vec<NftChain>,
    /// Sets within this table.
    pub sets: Vec<NftSet>,
}

/// A single nftables chain.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct NftChain {
    /// Chain name.
    pub name: String,
    /// Chain type (filter, nat, route) if this is a base chain.
    pub hook_type: Option<String>,
    /// Hook priority (lower = earlier).
    pub priority: Option<i32>,
    /// Chain policy (accept, drop).
    pub policy: Option<String>,
    /// Rules in this chain.
    pub rules: Vec<NftRule>,
}

/// A single nftables rule.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct NftRule {
    /// Rule handle (unique within the chain).
    pub handle: Option<u64>,
    /// Rule comment, if any.
    pub comment: Option<String>,
    /// The raw rule expression string (simplified representation).
    pub expr: String,
}

/// A named set in nftables.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct NftSet {
    /// Set name.
    pub name: String,
    /// Set type (e.g., `"ipv4_addr"`).
    pub set_type: String,
    /// Number of elements in the set.
    pub size: Option<usize>,
}

// ============================================================================
// JSON parsing (lightweight, no serde_json dependency)
// ============================================================================

/// Parse nftables JSON output from `nft -j list ruleset`.
///
/// This is a lightweight parser that extracts the key structural elements
/// from the JSON output. It does not attempt to parse every possible
/// nftables expression; instead, it extracts table names, chain names,
/// hook info, policies, rule handles, and comments, with a simplified
/// string representation of rule expressions.
pub fn parse_nft_json(json: &str) -> Result<NftRuleset> {
    let trimmed = json.trim();
    if trimmed.is_empty() {
        return Ok(NftRuleset::default());
    }

    // The nft JSON output is: {"nftables": [{"metainfo": {...}}, {"table": {...}}, ...]}
    // We'll do a lightweight manual parse.

    let mut tables = Vec::new();

    // Find the "nftables" array
    if let Some(arr_start) = trimmed.find("\"nftables\"") {
        // Find the opening bracket of the array
        if let Some(bracket_start) = trimmed[arr_start..].find('[') {
            let arr_content_start = arr_start + bracket_start + 1;
            // Find each table object
            let rest = &trimmed[arr_content_start..];
            tables = parse_nftables_array(rest);
        }
    }

    Ok(NftRuleset { tables })
}

/// Parse the nftables array content.
fn parse_nftables_array(content: &str) -> Vec<NftTable> {
    let mut tables = Vec::new();
    let mut depth = 0;
    let mut obj_start: Option<usize> = None;

    for (i, ch) in content.char_indices() {
        match ch {
            '{' => {
                if depth == 0 {
                    obj_start = Some(i);
                }
                depth += 1;
            }
            '}' => {
                depth -= 1;
                if depth == 0 {
                    if let Some(start) = obj_start {
                        let obj = &content[start..=i];
                        // Check if this object wraps a table
                        if let Some(table_str) = extract_wrapped_value(obj, "\"table\"") {
                            let table = parse_table_object(table_str);
                            tables.push(table);
                        }
                    }
                    obj_start = None;
                }
            }
            ']' if depth == 0 => break,
            _ => {}
        }
    }

    tables
}

/// Extract a value wrapped in a JSON object key, e.g., {"table": {...}}.
fn extract_wrapped_value<'a>(obj: &'a str, key: &str) -> Option<&'a str> {
    let key_pos = obj.find(key)?;
    let after_key = &obj[key_pos + key.len()..];
    // Skip whitespace and colon
    let after_colon = after_key.trim_start().strip_prefix(':')?;
    let after_colon = after_colon.trim_start();

    if !after_colon.starts_with('{') {
        return None;
    }

    // Find matching closing brace
    let mut depth = 0;
    for (i, ch) in after_colon.char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(&after_colon[..=i]);
                }
            }
            _ => {}
        }
    }
    None
}

/// Parse a table JSON object.
fn parse_table_object(json: &str) -> NftTable {
    let family = extract_json_string(json, "\"family\"").unwrap_or_default();
    let name = extract_json_string(json, "\"name\"").unwrap_or_default();

    let mut chains = Vec::new();
    let mut sets = Vec::new();

    // Parse chains array
    if let Some(chains_str) = extract_json_array_content(json, "\"chain\"") {
        chains = parse_chains(chains_str);
    }

    // Parse sets
    if let Some(sets_str) = extract_json_array_content(json, "\"set\"") {
        sets = parse_sets(sets_str);
    }

    NftTable {
        family,
        name,
        chains,
        sets,
    }
}

/// Parse chains from JSON array content.
fn parse_chains(content: &str) -> Vec<NftChain> {
    let mut chains = Vec::new();
    let mut depth = 0;
    let mut obj_start: Option<usize> = None;

    for (i, ch) in content.char_indices() {
        match ch {
            '{' => {
                if depth == 0 {
                    obj_start = Some(i);
                }
                depth += 1;
            }
            '}' => {
                depth -= 1;
                if depth == 0 {
                    if let Some(start) = obj_start {
                        let obj = &content[start..=i];
                        let chain = parse_chain_object(obj);
                        chains.push(chain);
                    }
                    obj_start = None;
                }
            }
            ']' if depth == 0 => break,
            _ => {}
        }
    }

    chains
}

/// Parse a chain JSON object.
fn parse_chain_object(json: &str) -> NftChain {
    let name = extract_json_string(json, "\"name\"").unwrap_or_default();
    let hook_type = extract_json_string(json, "\"hook\"");
    let priority = extract_json_number(json, "\"priority\"").and_then(|p| i32::try_from(p).ok());
    let policy = extract_json_string(json, "\"policy\"");

    let mut rules = Vec::new();

    // Parse rules within the chain
    // Rules appear as {"rule": {...}} objects in the chain's array
    if let Some(rules_content) = extract_json_array_content(json, "\"rule\"") {
        rules = parse_rules(rules_content);
    }

    NftChain {
        name,
        hook_type,
        priority,
        policy,
        rules,
    }
}

/// Parse rules from JSON content.
fn parse_rules(content: &str) -> Vec<NftRule> {
    let mut rules = Vec::new();

    // Each rule is a JSON object. We extract key fields.
    let mut depth = 0;
    let mut obj_start: Option<usize> = None;

    for (i, ch) in content.char_indices() {
        match ch {
            '{' => {
                if depth == 0 {
                    obj_start = Some(i);
                }
                depth += 1;
            }
            '}' => {
                depth -= 1;
                if depth == 0 {
                    if let Some(start) = obj_start {
                        let obj = &content[start..=i];
                        let handle = extract_json_number(obj, "\"handle\"")
                            .and_then(|h| u64::try_from(h).ok());
                        let comment = extract_json_string(obj, "\"comment\"");
                        let expr = extract_expr_summary(obj);

                        rules.push(NftRule {
                            handle,
                            comment,
                            expr,
                        });
                    }
                    obj_start = None;
                }
            }
            ']' if depth == 0 => break,
            _ => {}
        }
    }

    rules
}

/// Parse sets from JSON content.
fn parse_sets(content: &str) -> Vec<NftSet> {
    let mut sets = Vec::new();
    let mut depth = 0;
    let mut obj_start: Option<usize> = None;

    for (i, ch) in content.char_indices() {
        match ch {
            '{' => {
                if depth == 0 {
                    obj_start = Some(i);
                }
                depth += 1;
            }
            '}' => {
                depth -= 1;
                if depth == 0 {
                    if let Some(start) = obj_start {
                        let obj = &content[start..=i];
                        let name = extract_json_string(obj, "\"name\"").unwrap_or_default();
                        let set_type = extract_json_string(obj, "\"type\"").unwrap_or_default();
                        let size = extract_json_number(obj, "\"size\"")
                            .and_then(|s| usize::try_from(s).ok());

                        if !name.is_empty() {
                            sets.push(NftSet {
                                name,
                                set_type,
                                size,
                            });
                        }
                    }
                    obj_start = None;
                }
            }
            ']' if depth == 0 => break,
            _ => {}
        }
    }

    sets
}

/// Extract a JSON string value for a key.
fn extract_json_string(json: &str, key: &str) -> Option<String> {
    let pos = json.find(key)?;
    let after_key = &json[pos + key.len()..];
    let after_colon = after_key.trim_start().strip_prefix(':')?;
    let after_colon = after_colon.trim_start();

    if !after_colon.starts_with('"') {
        return None;
    }

    // Find the closing quote (handle escaped quotes)
    let bytes = after_colon.as_bytes();
    let mut i = 1; // skip opening quote
    let mut result = String::new();

    while i < bytes.len() {
        match bytes[i] {
            b'\\' => {
                // Escaped character
                if i + 1 < bytes.len() {
                    result.push(bytes[i + 1] as char);
                    i += 2;
                } else {
                    break;
                }
            }
            b'"' => {
                return Some(result);
            }
            b => {
                result.push(b as char);
                i += 1;
            }
        }
    }

    None
}

/// Extract a JSON number value for a key.
fn extract_json_number(json: &str, key: &str) -> Option<i64> {
    let pos = json.find(key)?;
    let after_key = &json[pos + key.len()..];
    let after_colon = after_key.trim_start().strip_prefix(':')?;
    let after_colon = after_colon.trim_start();

    // Read digits (possibly negative)
    let num_str: String = after_colon
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '-')
        .collect();

    num_str.parse().ok()
}

/// Extract a simplified expression summary from a rule object.
fn extract_expr_summary(json: &str) -> String {
    const MAX_CHARS: usize = 200;
    // Try to extract the "expr" array and summarize it
    if let Some(expr_pos) = json.find("\"expr\"") {
        let after = &json[expr_pos..];
        // Cap at 500 CHARACTERS, not bytes: a raw `&after[..500]` would panic
        // if byte 500 lands inside a multibyte codepoint (e.g. a non-ASCII nft
        // comment), exactly the class of bug this function must avoid.
        let summary = after
            .chars()
            .take(500)
            .collect::<String>()
            .replace('\n', " ")
            .replace('\\', "");
        // Truncate to a reasonable size, on a UTF-8 char boundary, by character
        // count (never by raw byte offset).
        let char_count = summary.chars().count();
        if char_count > MAX_CHARS {
            let truncated: String = summary.chars().take(MAX_CHARS).collect();
            format!("{truncated}...")
        } else {
            summary
        }
    } else {
        String::new()
    }
}

/// Extract the content of a JSON array associated with a key.
fn extract_json_array_content<'a>(json: &'a str, key: &str) -> Option<&'a str> {
    // Look for "key": [ or {"key": {...
    // For arrays within objects like "chain": [{...}, {...}]
    let pos = json.find(key)?;
    let after_key = &json[pos + key.len()..];
    let after_colon = after_key.trim_start().strip_prefix(':')?;
    let after_colon = after_colon.trim_start();

    if after_colon.starts_with('[') {
        // Find matching bracket
        let mut depth = 0;
        for (i, ch) in after_colon.char_indices() {
            match ch {
                '[' => depth += 1,
                ']' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(&after_colon[1..i]);
                    }
                }
                _ => {}
            }
        }
    } else if after_colon.starts_with('{') {
        // Single object — return it
        let mut depth = 0;
        for (i, ch) in after_colon.char_indices() {
            match ch {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(&after_colon[1..i]);
                    }
                }
                _ => {}
            }
        }
    }

    None
}

// ============================================================================
// Inspection functions
// ============================================================================

/// Inspect nftables ruleset as structured JSON.
///
/// Runs `nft -j list ruleset` and parses the JSON output.
pub fn inspect_nft_json(runner: &dyn CommandRunner) -> Result<NftRuleset> {
    let spec = CommandSpec {
        program: "nft".into(),
        args: vec!["-j".into(), "list".into(), "ruleset".into()],
        timeout: Some(Duration::from_secs(10)),
        requires_root: false,
        force_c_locale: true,
        redact_logs: false,
    };

    match runner.run(&spec) {
        Ok(result) if result.exit_code == Some(0) => parse_nft_json(&result.stdout),
        Ok(result) => Err(Error::DoctorCheckFailed(format!(
            "nft -j list ruleset failed: {}",
            result.stderr
        ))),
        Err(e) => Err(Error::DoctorCheckFailed(format!(
            "nft inspection failed: {e}"
        ))),
    }
}

/// Find all UFW-related tables in a ruleset.
#[must_use]
pub fn find_ufw_tables(ruleset: &NftRuleset) -> Vec<&NftTable> {
    ruleset
        .tables
        .iter()
        .filter(|t| {
            t.name.to_lowercase().contains("ufw")
                || t.chains.iter().any(|c| {
                    c.name.to_lowercase().contains("ufw")
                        || c.name == "ufw-before-forward"
                        || c.name == "ufw-after-forward"
                        || c.name == "ufw-before-input"
                        || c.name == "ufw-after-input"
                        || c.name == "ufw-reject-forward"
                        || c.name == "ufw-reject-input"
                        || c.name == "ufw-track-forward"
                        || c.name == "ufw-track-input"
                        || c.name == "ufw-skip-to-policy-input"
                        || c.name == "ufw-skip-to-policy-output"
                        || c.name == "ufw-skip-to-policy-forward"
                })
        })
        .collect()
}

/// Count total rules across all tables.
#[must_use]
pub fn count_rules(ruleset: &NftRuleset) -> usize {
    ruleset
        .tables
        .iter()
        .map(|t| t.chains.iter().map(|c| c.rules.len()).sum::<usize>())
        .sum()
}

/// Find chains with a "drop" or "deny" policy.
#[must_use]
pub fn find_restrictive_chains(ruleset: &NftRuleset) -> Vec<(&NftTable, &NftChain)> {
    ruleset
        .tables
        .iter()
        .flat_map(|t| {
            t.chains
                .iter()
                .filter(|c| {
                    c.policy
                        .as_deref()
                        .is_some_and(|p| p == "drop" || p == "deny")
                })
                .map(move |c| (t, c))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_nft_json_should_handle_empty_input() {
        let result = parse_nft_json("").unwrap();
        assert!(result.tables.is_empty());
    }

    #[test]
    fn parse_nft_json_should_parse_basic_ruleset() {
        let json = r#"{"nftables": [{"metainfo": {"version": "1.0"}}, {"table": {"family": "ip", "name": "ufw", "chain": [{"name": "ufw-before-input", "hook": "input", "prio": 0, "policy": "accept", "rule": [{"handle": 1, "expr": "ct state established,related accept"}]}]}}]}"#;
        let result = parse_nft_json(json).unwrap();
        assert_eq!(result.tables.len(), 1);
        assert_eq!(result.tables[0].family, "ip");
        assert_eq!(result.tables[0].name, "ufw");
        assert_eq!(result.tables[0].chains.len(), 1);
        assert_eq!(result.tables[0].chains[0].name, "ufw-before-input");
        assert_eq!(
            result.tables[0].chains[0].hook_type.as_deref(),
            Some("input")
        );
    }

    #[test]
    fn find_ufw_tables_should_filter_by_name() {
        let ruleset = NftRuleset {
            tables: vec![
                NftTable {
                    family: "ip".into(),
                    name: "ufw".into(),
                    chains: vec![],
                    sets: vec![],
                },
                NftTable {
                    family: "ip".into(),
                    name: "other".into(),
                    chains: vec![],
                    sets: vec![],
                },
            ],
        };
        let ufw_tables = find_ufw_tables(&ruleset);
        assert_eq!(ufw_tables.len(), 1);
        assert_eq!(ufw_tables[0].name, "ufw");
    }

    #[test]
    fn count_rules_should_sum_across_tables() {
        let ruleset = NftRuleset {
            tables: vec![
                NftTable {
                    family: "ip".into(),
                    name: "t1".into(),
                    chains: vec![NftChain {
                        name: "c1".into(),
                        hook_type: None,
                        priority: None,
                        policy: None,
                        rules: vec![NftRule {
                            handle: Some(1),
                            comment: None,
                            expr: "accept".into(),
                        }],
                    }],
                    sets: vec![],
                },
                NftTable {
                    family: "ip".into(),
                    name: "t2".into(),
                    chains: vec![NftChain {
                        name: "c2".into(),
                        hook_type: None,
                        priority: None,
                        policy: None,
                        rules: vec![
                            NftRule {
                                handle: Some(2),
                                comment: None,
                                expr: "drop".into(),
                            },
                            NftRule {
                                handle: Some(3),
                                comment: None,
                                expr: "accept".into(),
                            },
                        ],
                    }],
                    sets: vec![],
                },
            ],
        };
        assert_eq!(count_rules(&ruleset), 3);
    }

    #[test]
    fn extract_json_string_should_parse_values() {
        let json = r#"{"name": "ufw", "family": "ip"}"#;
        assert_eq!(extract_json_string(json, "\"name\""), Some("ufw".into()));
        assert_eq!(extract_json_string(json, "\"family\""), Some("ip".into()));
        assert_eq!(extract_json_string(json, "\"missing\""), None);
    }

    #[test]
    fn extract_json_number_should_parse_values() {
        let json = r#"{"priority": 100, "handle": 42}"#;
        assert_eq!(extract_json_number(json, "\"priority\""), Some(100));
        assert_eq!(extract_json_number(json, "\"handle\""), Some(42));
    }

    #[test]
    fn extract_expr_summary_truncates_multibyte_without_panic() {
        // Build an expr block longer than the 200-CHAR cap where byte index
        // 200 also falls inside a multibyte (non-ASCII) codepoint. A naive
        // `&summary[..200]` byte slice would panic at that boundary; the
        // char-bounded truncation must not.
        //
        // Each "é" is 2 UTF-8 bytes; 300 of them = 600 bytes, so byte index 200
        // is mid-codepoint, and the summary's 9 + 300 + 2 = 311 chars exceed the
        // 200-char cap so the truncation path actually runs.
        let multibyte = "é".repeat(300);
        let json = format!("{{\"expr\": [{multibyte}]}}");
        // Must not panic and must be truncated to at most 200 chars + "...".
        let summary = extract_expr_summary(&json);
        assert!(
            summary.chars().count() <= 200 + "...".chars().count(),
            "summary should be char-bounded, got {} chars",
            summary.chars().count()
        );
        assert!(
            summary.ends_with("..."),
            "truncated summary should end with ..., got: {summary:?}"
        );
    }

    #[test]
    fn extract_expr_summary_keeps_short_summary_intact() {
        let json = r#"{"expr": ["drop"]}"#;
        let summary = extract_expr_summary(json);
        // Short summaries are not truncated (no trailing "...").
        assert!(!summary.ends_with("..."));
    }
}
