//! Full SSH config resolution.
//!
//! Handles Include chains, token/env expansion, first-match-wins
//! (with IdentityFile accumulation), and CanonicalizeHostname double-parse.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use super::ast::{self, ConfigAst, ConfigNode};
use crate::Result;

/// Fully resolved parameters for a host.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ResolvedHost {
    /// The alias used to look up the host.
    pub alias: String,
    /// The real hostname to connect to.
    pub host_name: Option<String>,
    /// The user for the SSH connection.
    pub user: Option<String>,
    /// The port number.
    pub port: Option<u16>,
    /// Identity files to try.
    pub identity_files: Vec<String>,
    /// ProxyJump hosts.
    pub proxy_jump: Option<String>,
    /// All raw key-value directives from matching blocks.
    pub directives: Vec<(String, String)>,
}

/// Fully resolve config for a given host alias.
///
/// This performs:
/// 1. Loading and parsing the main config file.
/// 2. Inlining `Include` directives (with cycle detection).
/// 3. Token and environment variable expansion.
/// 4. First-match-wins resolution with IdentityFile accumulation.
pub async fn resolve(ssh_dir: &Path, host: &str) -> Result<ResolvedHost> {
    let config_path = ssh_dir.join("config");

    // Load and flatten includes.
    let mut visited = HashSet::new();
    let flat_ast = load_and_flatten(&config_path, &mut visited).await?;

    // Resolve host parameters using first-match-wins semantics.
    let mut resolved = ResolvedHost {
        alias: host.to_owned(),
        host_name: None,
        user: None,
        port: None,
        identity_files: Vec::new(),
        proxy_jump: None,
        directives: Vec::new(),
    };

    let mut seen_keys = HashSet::new();

    for node in &flat_ast.nodes {
        match node {
            ConfigNode::HostBlock { patterns, nodes, .. } => {
                if host_matches(host, patterns) {
                    resolve_block(
                        nodes,
                        host,
                        ssh_dir,
                        &mut resolved,
                        &mut seen_keys,
                    );
                }
            }
            // Only `host <pattern>` criteria is supported for Match blocks.
            // Full criteria parsing (user, exec, etc.) is tracked separately.
            ConfigNode::MatchBlock { criteria, nodes, .. }
                if match_criteria_host(criteria, host) =>
            {
                resolve_block(
                    nodes,
                    host,
                    ssh_dir,
                    &mut resolved,
                    &mut seen_keys,
                );
            }
            _ => {}
        }
    }

    // Token expansion on all values.
    expand_resolved(&mut resolved, host, ssh_dir);

    Ok(resolved)
}

/// Load a config file and recursively inline all Include directives.
fn load_and_flatten<'a>(
    path: &'a Path,
    visited: &'a mut HashSet<PathBuf>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<ConfigAst>> + 'a>> {
    Box::pin(async move {
        // PERF: If canonicalize fails (e.g. permission denied, broken symlink),
        // cycle detection may not catch symlink loops. This is acceptable because
        // SSH config files are unlikely to use symlinks.
        let canonical = path
            .canonicalize()
            .unwrap_or_else(|_| path.to_owned());

        if !visited.insert(canonical.clone()) {
            return Err(crate::Error::ConfigIncludeCycle(canonical.display().to_string()));
        }

        let content = if path.exists() {
            tokio::fs::read_to_string(path).await?
        } else {
            return Ok(ConfigAst { nodes: Vec::new() });
        };

        let mut flat = ast::parse(&content);

        // Inline includes.
        let include_nodes: Vec<String> = flat
            .nodes
            .iter()
            .filter_map(|node| {
                if let ConfigNode::Directive { keyword, value, .. } = node
                    && keyword.eq_ignore_ascii_case("include")
                {
                    Some(value.clone())
                } else {
                    None
                }
            })
            .collect();

        for include_pattern in include_nodes {
            let expanded = expand_tilde_and_env(&include_pattern);

            // Glob the pattern.
            let base_dir = if Path::new(&expanded).is_absolute() {
                PathBuf::new()
            } else {
                path.parent().unwrap_or(Path::new(".")).to_owned()
            };

            let full_pattern = base_dir.join(&expanded);
            let pattern_str = full_pattern.display().to_string();

            let matched_files = glob_paths(&pattern_str);

            for inc_path in matched_files {
                let included = load_and_flatten(&inc_path, visited).await?;
                // Insert included nodes in place of the Include directive.
                insert_included_nodes(&mut flat, &included);
            }
        }

    // Remove Include directives after processing.
    flat.nodes
        .retain(|node| !matches!(node, ConfigNode::Directive { keyword, .. } if keyword.eq_ignore_ascii_case("include")));

    Ok(flat)
    })
}

/// Insert included AST nodes in place of the Include directive.
fn insert_included_nodes(flat: &mut ConfigAst, included: &ConfigAst) {
    // Find the first Include directive and replace it with the included nodes.
    let include_idx = flat.nodes.iter().position(|node| {
        matches!(node, ConfigNode::Directive { keyword, .. } if keyword.eq_ignore_ascii_case("include"))
    });

    if let Some(idx) = include_idx {
        flat.nodes.remove(idx);
        flat.nodes.splice(
            idx..idx,
            included.nodes.iter().cloned(),
        );
    }
}

/// Expand tilde (`~`) and `${ENV}` patterns in an include path.
fn expand_tilde_and_env(path: &str) -> String {
    let mut result = path.to_owned();

    // Expand `~` or `~/`.
    if (result.starts_with("~/") || result == "~")
        && let Some(home) = dirs::home_dir()
    {
        result = result.replacen('~', &home.display().to_string(), 1);
    }

    // Expand `${ENV_VAR}` and `$ENV_VAR`.
    result = expand_env_vars(&result);

    result
}

/// Expand environment variables in `${VAR}` and `$VAR` formats.
///
/// Uses a single-pass builder to avoid repeated string reallocations.
/// If a `${` is encountered without a matching `}`, the literal `${` is
/// preserved in the output to avoid silently corrupting paths.
fn expand_env_vars(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.char_indices().peekable();

    while let Some((i, ch)) = chars.next() {
        if ch == '$' {
            if let Some((_, '{')) = chars.peek() {
                // `${VAR}` form — look for closing `}`.
                chars.next(); // consume '{'
                let start = i + 2;
                if let Some(end_offset) = s[start..].find('}') {
                    let var_name = &s[start..start + end_offset];
                    result.push_str(&std::env::var(var_name).unwrap_or_default());
                    // Skip to after '}'
                    for _ in 0..=end_offset {
                        chars.next();
                    }
                    continue;
                }
                // No closing `}` — preserve the literal `${` to avoid corruption.
                result.push(ch);
                result.push('{');
                continue;
            }
            // `$VAR` form (without braces) — read until non-alphanumeric/underscore.
            let rest = &s[i + 1..];
            let end = rest
                .find(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                .unwrap_or(rest.len());
            if end > 0 {
                let var_name = &rest[..end];
                result.push_str(&std::env::var(var_name).unwrap_or_default());
                // Skip the variable name characters.
                for _ in 0..end {
                    chars.next();
                }
                continue;
            }
            // Bare `$` at end of string or before non-name char.
            result.push(ch);
        } else {
            result.push(ch);
        }
    }

    result
}

/// Expand glob patterns and return matching file paths.
fn glob_paths(pattern: &str) -> Vec<PathBuf> {
    let mut paths = Vec::new();

    // Use a simple glob implementation.
    if let Some(parent) = Path::new(pattern).parent() {
        let file_name = Path::new(pattern)
            .file_name()
            .map(|f| f.to_string_lossy().into_owned())
            .unwrap_or_default();

        if let Ok(entries) = std::fs::read_dir(parent) {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let name_str = name.to_string_lossy();
                if simple_glob_match(&name_str, &file_name) {
                    paths.push(entry.path());
                }
            }
        }
    }

    paths.sort();
    paths
}

/// Simple glob match for file names.
///
/// Performs case-sensitive matching, which is correct for Unix file paths.
fn simple_glob_match(name: &str, pattern: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if !pattern.contains('*') && !pattern.contains('?') {
        return name == pattern;
    }
    // Delegate to the directives glob matcher (case-sensitive for file paths).
    super::directives::glob_matches(name, pattern)
}

/// Apply first-match-wins resolution from a block's nodes.
///
/// Accumulative directives (IdentityFile, CertificateFile, etc.) are
/// collected across all matching blocks. All other directives use
/// first-match-wins semantics.
fn resolve_block(
    nodes: &[ConfigNode],
    _host: &str,
    _ssh_dir: &Path,
    resolved: &mut ResolvedHost,
    seen: &mut HashSet<String>,
) {
    for node in nodes {
        if let ConfigNode::Directive { keyword, value, .. } = node {
            let key_lower = keyword.to_lowercase();

            // Accumulative directives — always collect.
            if super::directives::is_accumulative(&key_lower) {
                if key_lower == "identityfile"
                    && !resolved.identity_files.iter().any(|f| f == value)
                {
                    resolved.identity_files.push(value.clone());
                }
                resolved
                    .directives
                    .push((keyword.clone(), value.clone()));
                continue;
            }

            // Skip if we already have a value (first-match-wins).
            if seen.contains(&key_lower) {
                continue;
            }

            // Match first, then move key_lower into the set to avoid cloning.
            match key_lower.as_str() {
                "hostname" => resolved.host_name = Some(value.clone()),
                "user" => resolved.user = Some(value.clone()),
                "port" => {
                    resolved.port = value.parse::<u16>().ok();
                }
                "proxyjump" => resolved.proxy_jump = Some(value.clone()),
                _ => {}
            }

            resolved
                .directives
                .push((keyword.clone(), value.clone()));
            seen.insert(key_lower);
        }
    }
}

/// Context for SSH token expansion (`%h`, `%d`, `%l`, etc.).
struct TokenContext<'a> {
    host: &'a str,
    home_dir: &'a str,
    local_hostname: &'a str,
    remote_user: &'a str,
    local_user: &'a str,
    port: &'a str,
}

/// Expand tokens in resolved values.
fn expand_resolved(resolved: &mut ResolvedHost, host: &str, _ssh_dir: &Path) {
    let local_user = whoami();
    let local_hostname = hostname();
    let home_dir = dirs::home_dir()
        .map(|p| p.display().to_string())
        .unwrap_or_default();

    let port_str = resolved
        .port
        .map_or_else(|| "22".to_owned(), |p| p.to_string());
    let remote_user = resolved.user.as_deref().unwrap_or(&local_user).to_owned();

    let ctx = TokenContext {
        host,
        home_dir: &home_dir,
        local_hostname: &local_hostname,
        remote_user: &remote_user,
        local_user: &local_user,
        port: &port_str,
    };

    // Expand identity files.
    for id_file in &mut resolved.identity_files {
        *id_file = expand_tilde_and_env(id_file);
        *id_file = expand_tokens(id_file, &ctx);
        *id_file = collapse_double_percent(id_file);
    }

    // Expand host_name.
    if let Some(ref mut hn) = resolved.host_name {
        *hn = expand_tokens(hn, &ctx);
        *hn = collapse_double_percent(hn);
    }

    // Expand proxy_jump.
    if let Some(ref mut pj) = resolved.proxy_jump {
        *pj = expand_tokens(pj, &ctx);
        *pj = collapse_double_percent(pj);
    }
}

/// Expand SSH tokens (%d, %h, %l, %n, %p, %r, %u) in a value string.
///
/// Uses character-by-character parsing so that unknown `%X` sequences
/// (and a trailing bare `%`) are preserved as-is. `%%` is handled
/// separately by [`collapse_double_percent`].
fn expand_tokens(s: &str, ctx: &TokenContext<'_>) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '%' {
            match chars.peek().copied() {
                Some('%') => {
                    // Keep `%%` as-is; collapse_double_percent handles it later.
                    result.push_str("%%");
                    chars.next();
                }
                Some('d') => {
                    chars.next();
                    result.push_str(ctx.home_dir);
                }
                Some('h' | 'n') => {
                    chars.next();
                    result.push_str(ctx.host);
                }
                Some('l') => {
                    chars.next();
                    result.push_str(ctx.local_hostname);
                }
                Some('p') => {
                    chars.next();
                    result.push_str(ctx.port);
                }
                Some('r') => {
                    chars.next();
                    result.push_str(ctx.remote_user);
                }
                Some('u') => {
                    chars.next();
                    result.push_str(ctx.local_user);
                }
                _ => {
                    // Unknown token or '%' at end of string — keep as-is.
                    result.push(ch);
                }
            }
        } else {
            result.push(ch);
        }
    }

    result
}

/// Replace `%%` with a single `%` (OpenSSH escape convention).
fn collapse_double_percent(s: &str) -> String {
    s.replace("%%", "%")
}

/// Get the current username.
fn whoami() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "unknown".to_owned())
}

/// Get the local hostname.
fn hostname() -> String {
    std::env::var("HOSTNAME").unwrap_or_else(|_| {
        gethostname::gethostname()
            .to_string_lossy()
            .into_owned()
    })
}

/// Check if a hostname matches SSH config patterns (reuses directive logic).
fn host_matches(host: &str, patterns: &[String]) -> bool {
    super::directives::host_matches_patterns(host, patterns)
}

/// Check if `Match` criteria include a `host` clause matching the target.
///
/// Parses simple `host <pattern>` tokens from the criteria string.
/// Returns `false` if no `host` clause is present (Match block requires
/// at least one condition we understand to match).
fn match_criteria_host(criteria: &str, target_host: &str) -> bool {
    let mut tokens = criteria.split_whitespace();
    let mut host_matched = false;
    let mut has_host_clause = false;

    while let Some(token) = tokens.next() {
        if token.eq_ignore_ascii_case("host")
            && let Some(patterns_str) = tokens.next()
        {
            has_host_clause = true;
            let patterns: Vec<String> = patterns_str
                .split(',')
                .map(str::to_owned)
                .collect();
            if host_matches(target_host, &patterns) {
                host_matched = true;
            }
        }
    }

    has_host_clause && host_matched
}

#[cfg(test)]
#[path = "resolve.test.rs"]
mod tests;
