//! Typed accessors for SSH config directives.

use super::ast::{ConfigAst, ConfigNode};

use crate::Result;

/// Get a directive value for a host using first-match-wins semantics.
///
/// Walks the AST, finds the first `Host` block whose patterns match `host`,
/// then returns the first directive with the given key.
///
/// The key comparison is case-insensitive (SSH config keywords are
/// case-insensitive).
pub fn get_directive(ast: &ConfigAst, host: &str, key: &str) -> Result<Option<String>> {
    let key_lower = key.to_lowercase();

    for node in &ast.nodes {
        if let ConfigNode::HostBlock { patterns, nodes, .. } = node {
            if host_matches_patterns(host, patterns) {
                if let Some(val) = find_directive_in_nodes(nodes, &key_lower) {
                    return Ok(Some(val));
                }
            }
        }
    }
    Ok(None)
}

/// Get all values for a directive that accumulates (e.g. `IdentityFile`).
///
/// Unlike first-match-wins, accumulative directives collect values from all
/// matching Host blocks.
pub fn get_accumulative_directive(ast: &ConfigAst, host: &str, key: &str) -> Result<Vec<String>> {
    let key_lower = key.to_lowercase();
    let mut values = Vec::new();

    for node in &ast.nodes {
        if let ConfigNode::HostBlock { patterns, nodes, .. } = node {
            if host_matches_patterns(host, patterns) {
                collect_directives_in_nodes(nodes, &key_lower, &mut values);
            }
        }
    }
    Ok(values)
}

/// Get a directive value from any Host block by exact host name (the first
/// pattern in the block). This is a simpler lookup than pattern matching.
pub fn get_directive_by_name(ast: &ConfigAst, name: &str, key: &str) -> Result<Option<String>> {
    let key_lower = key.to_lowercase();

    for node in &ast.nodes {
        if let ConfigNode::HostBlock { patterns, nodes, .. } = node {
            // Check if the name appears in the patterns (exact or wildcard).
            if patterns.iter().any(|p| p == name || p == "*") {
                if let Some(val) = find_directive_in_nodes(nodes, &key_lower) {
                    return Ok(Some(val));
                }
            }
        }
    }
    Ok(None)
}

/// Get all directives for a host as key-value pairs.
///
/// Uses first-match-wins semantics for most directives but **accumulates**
/// values for multi-valued directives (`IdentityFile`, `CertificateFile`,
/// `ProxyJump`, `ForwardAgent`, `SendEnv`, `SetEnv`, `DynamicForward`,
/// `LocalForward`, `RemoteForward`).
pub fn get_all_directives(ast: &ConfigAst, host: &str) -> Result<Vec<(String, String)>> {
    let mut result = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for node in &ast.nodes {
        if let ConfigNode::HostBlock { patterns, nodes, .. } = node {
            if host_matches_patterns(host, patterns) {
                collect_all_directives(nodes, &mut result, &mut seen);
            }
        }
    }
    Ok(result)
}

/// Set (or update) a directive value inside the first matching Host block.
///
/// If the directive already exists, it is updated in place.
/// If not, a new directive is appended to the block.
pub fn set_directive(
    ast: &mut ConfigAst,
    host: &str,
    key: &str,
    value: &str,
) -> Result<()> {
    let key_lower = key.to_lowercase();

    for node in &mut ast.nodes {
        if let ConfigNode::HostBlock { patterns, nodes, .. } = node {
            if host_matches_patterns(host, patterns) {
                // Try to update existing directive.
                for child in nodes.iter_mut() {
                    if let ConfigNode::Directive { keyword, value: v, .. } = child {
                        if keyword.eq_ignore_ascii_case(&key_lower) {
                            *v = value.to_owned();
                            return Ok(());
                        }
                    }
                }
                // Not found — append new directive.
                nodes.push(ConfigNode::Directive {
                    keyword: key.to_owned(),
                    separator: super::ast::Separator::Space,
                    value: value.to_owned(),
                    comment: None,
                    indent: String::new(),
                });
                return Ok(());
            }
        }
    }

    Err(crate::Error::HostNotFound(host.to_owned()))
}

/// Find the first directive matching `key_lower` in a list of nodes (recursive).
fn find_directive_in_nodes(nodes: &[ConfigNode], key_lower: &str) -> Option<String> {
    for node in nodes {
        if let ConfigNode::Directive { keyword, value, .. } = node {
            if keyword.eq_ignore_ascii_case(&key_lower) {
                return Some(value.clone());
            }
        }
    }
    None
}

/// Collect all values for a directive from a list of nodes.
fn collect_directives_in_nodes(nodes: &[ConfigNode], key_lower: &str, out: &mut Vec<String>) {
    for node in nodes {
        if let ConfigNode::Directive { keyword, value, .. } = node {
            if keyword.eq_ignore_ascii_case(&key_lower) {
                out.push(value.clone());
            }
        }
    }
}

/// Collect all unique directives from a list of nodes.
///
/// For accumulative directives (see [`is_accumulative`]), multiple values are
/// collected across matching blocks. For all other directives the first value
/// wins.
fn collect_all_directives(
    nodes: &[ConfigNode],
    out: &mut Vec<(String, String)>,
    seen: &mut std::collections::HashSet<String>,
) {
    for node in nodes {
        if let ConfigNode::Directive { keyword, value, .. } = node {
            let key_lower = keyword.to_lowercase();
            if is_accumulative(&key_lower) {
                // Always append accumulative directives.
                out.push((keyword.clone(), value.clone()));
            } else if !seen.contains(&key_lower) {
                seen.insert(key_lower.clone());
                out.push((keyword.clone(), value.clone()));
            }
        }
    }
}

/// Directives that accumulate values across matching blocks (first-match-wins
/// does NOT apply to these).
pub(crate) fn is_accumulative(key_lower: &str) -> bool {
    matches!(
        key_lower,
        "identityfile"
            | "certificatefile"
            | "proxyjump"
            | "forwardagent"
            | "sendenv"
            | "setenv"
            | "dynamicforward"
            | "localforward"
            | "remoteforward"
            | "permitlocalcommand"
    )
}

/// Check if a hostname matches any of the given SSH config patterns.
///
/// Supports:
/// - Exact match: `example.com`
/// - Wildcard `*` matching any host
/// - `?` matching a single character
/// - Negation with `!`: `!example.com`
pub(crate) fn host_matches_patterns(host: &str, patterns: &[String]) -> bool {
    let host_lower = host.to_lowercase();
    let mut positive_match = false;

    for pattern in patterns {
        let pat_lower = pattern.to_lowercase();

        if pat_lower.starts_with('!') {
            // Negated pattern — if it matches, the whole result is false.
            let negated = &pat_lower[1..];
            if glob_matches(&host_lower, negated) {
                return false;
            }
        } else if glob_matches(&host_lower, &pat_lower) {
            positive_match = true;
        }
    }

    positive_match
}

/// Simple glob matching supporting `*` (any chars) and `?` (single char).
pub(crate) fn glob_matches(text: &str, pattern: &str) -> bool {
    // Single-character patterns.
    if pattern.len() == 1 {
        return match pattern {
            "*" => true,
            "?" => !text.is_empty(),
            c => text == c,
        };
    }

    // Fast path: no wildcards.
    if !pattern.contains('*') && !pattern.contains('?') {
        return text == pattern;
    }

    // Use a simple recursive matcher for glob patterns.
    glob_match_recursive(text.as_bytes(), pattern.as_bytes())
}

fn glob_match_recursive(text: &[u8], pattern: &[u8]) -> bool {
    let mut ti = 0;
    let mut pi = 0;
    let mut star_pi = None;
    let mut star_ti = 0;

    while ti < text.len() {
        if pi < pattern.len() {
            let pc = pattern[pi];
            let tc = text[ti];

            if pc == b'?' {
                pi += 1;
                ti += 1;
                continue;
            }

            if pc == b'*' {
                star_pi = Some(pi + 1);
                star_ti = ti;
                pi += 1;
                continue;
            }

            if pc == tc {
                pi += 1;
                ti += 1;
                continue;
            }
        }

        // Mismatch — backtrack to last star.
        if let Some(spi) = star_pi {
            pi = spi;
            star_ti += 1;
            ti = star_ti;
            continue;
        }

        return false;
    }

    // Consume trailing stars.
    while pi < pattern.len() && pattern[pi] == b'*' {
        pi += 1;
    }

    pi == pattern.len()
}

#[cfg(test)]
#[path = "directives.test.rs"]
mod tests;
