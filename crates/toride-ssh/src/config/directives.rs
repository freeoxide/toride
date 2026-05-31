//! Typed accessors for SSH config directives.

use super::ast::{ConfigAst, ConfigNode, DirectiveData};

use crate::Result;

/// Get a directive value for a host using first-match-wins semantics.
///
/// Walks the AST, finds the first `Host` block whose patterns match `host`,
/// then returns the first directive with the given key.
///
/// The key comparison is case-insensitive (SSH config keywords are
/// case-insensitive).
pub fn get_directive(ast: &ConfigAst, host: &str, key: &str) -> Option<String> {
    let key_lower = key.to_lowercase();

    for node in &ast.nodes {
        if let ConfigNode::HostBlock(b) = node
            && host_matches_patterns(host, &b.patterns)
            && let Some(val) = find_directive_in_nodes(&b.nodes, &key_lower)
        {
            return Some(val.to_owned());
        }
    }
    None
}

/// Get all values for a directive that accumulates (e.g. `IdentityFile`).
///
/// Unlike first-match-wins, accumulative directives collect values from all
/// matching Host blocks.
pub fn get_accumulative_directive(ast: &ConfigAst, host: &str, key: &str) -> Vec<String> {
    let key_lower = key.to_lowercase();
    let mut values = Vec::new();

    for node in &ast.nodes {
        if let ConfigNode::HostBlock(b) = node
            && host_matches_patterns(host, &b.patterns)
        {
            collect_directives_in_nodes(&b.nodes, &key_lower, &mut values);
        }
    }
    values
}

/// Get a directive value from any Host block by exact host name (the first
/// pattern in the block). This is a simpler lookup than pattern matching.
pub fn get_directive_by_name(ast: &ConfigAst, name: &str, key: &str) -> Option<String> {
    let key_lower = key.to_lowercase();

    for node in &ast.nodes {
        if let ConfigNode::HostBlock(b) = node
            && b.patterns.iter().any(|p| p == name || p == "*")
            && let Some(val) = find_directive_in_nodes(&b.nodes, &key_lower)
        {
            return Some(val.to_owned());
        }
    }
    None
}

/// Get all directives for a host as key-value pairs.
///
/// Uses first-match-wins semantics for most directives but **accumulates**
/// values for multi-valued directives (`IdentityFile`, `CertificateFile`,
/// `SendEnv`, `SetEnv`, `DynamicForward`,
/// `LocalForward`, `RemoteForward`, `PermitLocalCommand`).
pub fn get_all_directives(ast: &ConfigAst, host: &str) -> Vec<(String, String)> {
    let mut result = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for node in &ast.nodes {
        if let ConfigNode::HostBlock(b) = node
            && host_matches_patterns(host, &b.patterns)
        {
            collect_all_directives(&b.nodes, &mut result, &mut seen);
        }
    }
    result
}

/// Set (or update) a directive value inside the first matching Host block.
///
/// If the directive already exists, it is updated in place.
/// If not, a new directive is appended to the block.
///
/// # Errors
///
/// Returns [`Error::HostNotFound`] if no `Host` block matches the given
/// host alias.
pub fn set_directive(
    ast: &mut ConfigAst,
    host: &str,
    key: &str,
    value: &str,
) -> Result<()> {
    let key_lower = key.to_lowercase();

    for node in &mut ast.nodes {
        if let ConfigNode::HostBlock(b) = node
            && host_matches_patterns(host, &b.patterns)
        {
            // Try to update existing directive.
            for child in &mut b.nodes {
                if let ConfigNode::Directive(d) = child
                    && d.keyword.eq_ignore_ascii_case(&key_lower)
                {
                    value.clone_into(&mut d.value);
                    return Ok(());
                }
            }
            // Not found — append new directive.
            b.nodes.push(ConfigNode::Directive(Box::new(DirectiveData {
                keyword: key.to_owned(),
                separator: super::ast::Separator::Space,
                value: value.to_owned(),
                comment: None,
                indent: String::new(),
            })));
            return Ok(());
        }
    }

    Err(crate::Error::HostNotFound(host.to_owned()))
}

/// Find the first directive matching `key_lower` in a list of nodes.
fn find_directive_in_nodes<'a>(nodes: &'a [ConfigNode], key_lower: &str) -> Option<&'a str> {
    for node in nodes {
        if let ConfigNode::Directive(d) = node
            && d.keyword.eq_ignore_ascii_case(key_lower)
        {
            return Some(&d.value);
        }
    }
    None
}

/// Collect all values for a directive from a list of nodes.
fn collect_directives_in_nodes(nodes: &[ConfigNode], key_lower: &str, out: &mut Vec<String>) {
    for node in nodes {
        if let ConfigNode::Directive(d) = node
            && d.keyword.eq_ignore_ascii_case(key_lower)
        {
            out.push(d.value.clone());
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
        if let ConfigNode::Directive(d) = node {
            if is_accumulative(&d.keyword) {
                // Always append accumulative directives.
                out.push((d.keyword.clone(), d.value.clone()));
            } else {
                let key_lower = d.keyword.to_ascii_lowercase();
                if seen.insert(key_lower) {
                    out.push((d.keyword.clone(), d.value.clone()));
                }
            }
        }
    }
}

/// Get the `PreferredAuthentications` value for a host.
///
/// Returns the comma-separated list of authentication methods in their
/// configured order (e.g. `"publickey,keyboard-interactive,password"`),
/// or `None` if the directive is not present for the given host.
///
/// When the directive is set in multiple matching blocks, the first
/// match wins (standard SSH config semantics).
///
/// # Examples
///
/// ```text
/// Host example.com
///     PreferredAuthentications publickey,password
/// ```
///
/// Calling `get_preferred_authentications(&ast, "example.com")` returns
/// `Some("publickey,password".to_owned())`.
pub fn get_preferred_authentications(ast: &ConfigAst, host: &str) -> Option<String> {
    get_directive(ast, host, "PreferredAuthentications")
}

/// Directives that accumulate values across matching blocks (first-match-wins
/// does NOT apply to these).
///
/// `ForwardAgent` is intentionally excluded -- it uses first-match-wins
/// semantics per OpenSSH ssh_config(5).
pub(crate) fn is_accumulative(keyword: &str) -> bool {
    keyword.eq_ignore_ascii_case("identityfile")
        || keyword.eq_ignore_ascii_case("certificatefile")
        || keyword.eq_ignore_ascii_case("sendenv")
        || keyword.eq_ignore_ascii_case("setenv")
        || keyword.eq_ignore_ascii_case("dynamicforward")
        || keyword.eq_ignore_ascii_case("localforward")
        || keyword.eq_ignore_ascii_case("remoteforward")
        || keyword.eq_ignore_ascii_case("permitlocalcommand")
}

/// Check if a hostname matches any of the given SSH config patterns.
///
/// Supports:
/// - Exact match: `example.com`
/// - Wildcard `*` matching any host
/// - `?` matching a single character
/// - Negation with `!`: `!example.com`
pub(crate) fn host_matches_patterns(host: &str, patterns: &[impl AsRef<str>]) -> bool {
    // SSH hostnames and patterns are ASCII — use ASCII lowercase to avoid
    // Unicode-aware allocation overhead.
    let host_lower = host.to_ascii_lowercase();
    let mut positive_match = false;

    for pattern in patterns {
        let pat_lower = pattern.as_ref().to_ascii_lowercase();

        if let Some(negated) = pat_lower.strip_prefix('!') {
            // Negated pattern — if it matches, the whole result is false.
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
///
/// **Note:** This function is used exclusively for SSH `Host` pattern matching
/// (e.g. `Host *.example.com`).  It does NOT support `**` recursive directory
/// globbing.  File-path glob expansion for `Include` directives is handled by
/// [`super::resolve::glob_paths`] which has its own `**` implementation.
pub(crate) fn glob_matches(text: &str, pattern: &str) -> bool {
    // Single-character patterns.
    if pattern.len() == 1 {
        return match pattern {
            "*" => true,
            "?" => text.len() == 1,
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
    let mut star_text_idx = 0;

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
                star_text_idx = ti;
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
            star_text_idx += 1;
            ti = star_text_idx;
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
