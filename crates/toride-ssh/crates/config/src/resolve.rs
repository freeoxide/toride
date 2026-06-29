//! Full SSH config resolution.
//!
//! Handles Include chains, token/env expansion, first-match-wins
//! (with `IdentityFile` accumulation), and `CanonicalizeHostname` double-parse.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use super::ast::{self, ConfigAst, ConfigNode};
use toride_ssh_core::Result;

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
    /// Certificate files (accumulative across matching blocks).
    pub certificate_files: Vec<String>,
    /// `ProxyJump` hosts.
    pub proxy_jump: Option<String>,
    /// `IdentityAgent` socket path.
    pub identity_agent: Option<String>,
    /// `ForwardAgent` setting (yes/no).
    pub forward_agent: Option<String>,
    /// `AddKeysToAgent` setting (yes/confirm/ask/no/lifetime).
    pub add_keys_to_agent: Option<String>,
    /// `UseKeychain` setting (yes/no, macOS only).
    pub use_keychain: Option<String>,
    /// `ControlMaster` setting (yes/no/auto/ask/autoask).
    pub control_master: Option<String>,
    /// `ControlPath` socket path.
    pub control_path: Option<String>,
    /// `ControlPersist` duration.
    pub control_persist: Option<String>,
    /// `LocalForward` entries (accumulative).
    pub local_forwards: Vec<String>,
    /// `RemoteForward` entries (accumulative).
    pub remote_forwards: Vec<String>,
    /// `DynamicForward` entries (accumulative).
    pub dynamic_forwards: Vec<String>,
    /// All raw key-value directives from matching blocks.
    pub directives: Vec<(String, String)>,
    /// `UserKnownHostsFile` value, if set.
    ///
    /// When `None`, the default `~/.ssh/known_hosts` is used.
    /// May contain SSH tokens (already expanded).
    pub user_known_hosts_file: Option<String>,
    /// `IdentitiesOnly` setting parsed as a boolean (`yes` / `no`).
    ///
    /// When `Some(true)`, only the identity files explicitly listed in the
    /// config (and those on the command line) are offered during
    /// authentication. When `Some(false)` or `None`, keys from the agent
    /// and default key files are also tried.
    pub identities_only: Option<bool>,
    /// Whether the config was re-resolved after `CanonicalizeHostname` took
    /// effect. When `true`, `%H` tokens expand to the canonical hostname
    /// rather than the original alias.
    pub canonicalized: bool,
    /// Warnings for Match blocks containing `exec` criteria that were not
    /// evaluated (toride does not execute arbitrary commands for security).
    pub unevaluated_match_warnings: Vec<String>,
    /// `GSSAPIAuthentication` setting (yes/no).
    pub gssapi_authentication: Option<String>,
    /// `GSSAPIDelegateCredentials` setting (yes/no).
    pub gssapi_delegate_credentials: Option<String>,
    /// `GSSAPIServerIdentity` value.
    pub gssapi_server_identity: Option<String>,
    /// `GSSAPIClientIdentity` value.
    pub gssapi_client_identity: Option<String>,
}

/// Directives whose values may contain SSH tokens (`%h`, `%d`, etc.) or
/// tilde/env expansion and should be expanded during resolution.
const TOKEN_EXPANDABLE: &[&str] = &[
    "certificatefile",
    "controlmaster",
    "controlpath",
    "controlpersist",
    "dynamicforward",
    "forwardagent",
    "identityagent",
    "knownhostscommand",
    "localforward",
    "remoteforward",
    "revokedhostkeys",
    "usekeychain",
    "userknownhostsfile",
    "proxycommand",
];

/// Fully resolve config for a given host alias.
///
/// This performs:
/// 1. Loading and parsing the main config file.
/// 2. Inlining `Include` directives (with cycle detection).
/// 3. Token and environment variable expansion.
/// 4. First-match-wins resolution with `IdentityFile` accumulation.
/// 5. If `CanonicalizeHostname` is enabled, a second resolution pass using
///    the resolved `HostName` as the lookup key.
///
/// `user` is the remote username for `Match user` criteria.  When `None`,
/// the local username is used (matching OpenSSH behaviour when no `-l`
/// flag is given).
///
/// # Errors
///
/// Returns [`Error::ConfigIncludeCycle`] if an `Include` chain contains a
/// cycle. Returns [`Error::Io`] if the config file cannot be read.
pub async fn resolve(ssh_dir: &Path, host: &str, user: Option<&str>) -> Result<ResolvedHost> {
    let config_path = ssh_dir.join("config");

    // Load and flatten includes.
    let mut visited = HashSet::new();
    let flat_ast = load_and_flatten(&config_path, &mut visited).await?;

    // First pass: resolve against the original alias.
    let local_user = user.map_or_else(whoami, str::to_owned);
    let mut resolved = resolve_pass(&flat_ast, host, host, &local_user);

    // Token expansion on first-pass values.
    expand_resolved(&mut resolved, host, ssh_dir);

    // CanonicalizeHostname: if enabled, re-resolve using the resolved HostName.
    if is_canonicalize_enabled(&resolved) {
        let canonical_host = resolved.host_name.take().unwrap_or_else(|| host.to_owned());

        let mut canon = resolve_pass(&flat_ast, &canonical_host, host, &local_user);

        // Expand tokens in the canonicalized result.
        expand_resolved(&mut canon, &canonical_host, ssh_dir);

        host.clone_into(&mut canon.alias);
        canon.canonicalized = true;
        return Ok(canon);
    }

    Ok(resolved)
}

/// Perform a single resolution pass over the flattened AST.
///
/// `target_host` is the hostname used for pattern matching (the canonical
/// name on the second pass, or the original alias on the first).
/// `original_host` is always the alias the user typed — used for
/// `Match originalhost` criteria.
fn resolve_pass(
    flat_ast: &ConfigAst,
    target_host: &str,
    original_host: &str,
    local_user: &str,
) -> ResolvedHost {
    let mut resolved = ResolvedHost {
        alias: target_host.to_owned(),
        host_name: None,
        user: None,
        port: None,
        identity_files: Vec::new(),
        certificate_files: Vec::new(),
        proxy_jump: None,
        identity_agent: None,
        forward_agent: None,
        add_keys_to_agent: None,
        use_keychain: None,
        control_master: None,
        control_path: None,
        control_persist: None,
        local_forwards: Vec::new(),
        remote_forwards: Vec::new(),
        dynamic_forwards: Vec::new(),
        directives: Vec::new(),
        user_known_hosts_file: None,
        identities_only: None,
        canonicalized: false,
        unevaluated_match_warnings: Vec::new(),
        gssapi_authentication: None,
        gssapi_delegate_credentials: None,
        gssapi_server_identity: None,
        gssapi_client_identity: None,
    };

    let mut seen_keys = HashSet::new();

    for node in &flat_ast.nodes {
        match node {
            ConfigNode::HostBlock(b) => {
                if host_matches(target_host, &b.patterns) {
                    resolve_block(&b.nodes, &mut resolved, &mut seen_keys);
                }
            }
            ConfigNode::MatchBlock(b) => {
                // Warn about `exec` criteria — we cannot evaluate them safely.
                if contains_exec_criteria(&b.criteria) {
                    let warning = format!(
                        "Match block contains 'exec' criteria which are not evaluated: {}",
                        b.criteria,
                    );
                    tracing::warn!("{}", &warning);
                    resolved.unevaluated_match_warnings.push(warning);
                }
                if match_criteria_host(&b.criteria, target_host, local_user, original_host) {
                    resolve_block(&b.nodes, &mut resolved, &mut seen_keys);
                }
            }
            _ => {}
        }
    }

    resolved
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
        let canonical = path.canonicalize().unwrap_or_else(|_| path.to_owned());

        if visited.contains(&canonical) {
            return Err(toride_ssh_core::Error::ConfigIncludeCycle(
                canonical.display().to_string(),
            ));
        }
        visited.insert(canonical);

        let content = if path.exists() {
            tokio::fs::read_to_string(path).await?
        } else {
            return Ok(ConfigAst { nodes: Vec::new() });
        };

        let mut flat = ast::parse(&content);

        // Inline includes: single-pass replacement that avoids the position-
        // shifting bug.  We walk the original nodes vec and, for each Include
        // directive, expand its glob and splice in the recursively-loaded
        // content.  Non-Include nodes are kept as-is.
        let original_nodes = std::mem::take(&mut flat.nodes);
        let mut new_nodes = Vec::with_capacity(original_nodes.len());

        for node in original_nodes {
            let pattern_value = match &node {
                ConfigNode::Directive(d) if d.keyword.eq_ignore_ascii_case("include") => {
                    Some(d.value.clone())
                }
                _ => None,
            };

            if let Some(include_pattern) = pattern_value {
                let expanded = expand_tilde_and_env(&include_pattern);

                // Glob the pattern.
                let base_dir = if Path::new(&expanded).is_absolute() {
                    PathBuf::new()
                } else {
                    path.parent().unwrap_or_else(|| Path::new(".")).to_owned()
                };

                let full_pattern = base_dir.join(&expanded);
                let pattern_str = full_pattern.display().to_string();

                let matched_files = glob_paths(&pattern_str);

                for inc_path in matched_files {
                    let included = load_and_flatten(&inc_path, visited).await?;
                    new_nodes.extend(included.nodes);
                }
            } else {
                new_nodes.push(node);
            }
        }

        flat.nodes = new_nodes;

        Ok(flat)
    })
}

/// Expand tilde (`~`) and `${ENV}` patterns in an include path.
fn expand_tilde_and_env(path: &str) -> String {
    let mut result = path.to_owned();

    // Expand `~` or `~/`.
    if (result.starts_with("~/") || result == "~")
        && let Some(home) = dirs::home_dir()
    {
        let home_str = home.display().to_string();
        result = result.replacen('~', &home_str, 1);
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
///
/// Supports `*` and `?` single-directory wildcards as well as `**` for
/// recursive directory matching:
/// - `**/` matches zero or more directory levels
/// - `dir/**/*.conf` matches all `.conf` files in `dir` and its subdirectories
/// - `dir/**/` matches all directories under `dir` (recursively)
fn glob_paths(pattern: &str) -> Vec<PathBuf> {
    // Detect recursive glob (**).
    if pattern.contains("**") {
        return glob_paths_recursive(pattern);
    }

    // Original single-directory glob logic.
    let mut paths = Vec::new();

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

/// Recursive glob expansion for patterns containing `**`.
///
/// Splits the pattern at the first occurrence of `**/` to obtain a base
/// directory (prefix) and a suffix pattern.  Walks all subdirectories under
/// the prefix and applies the suffix pattern at every level using
/// [`simple_glob_match`], matching zero or more intermediate directory
/// levels.
fn glob_paths_recursive(pattern: &str) -> Vec<PathBuf> {
    let mut paths = Vec::new();

    // Split on the first occurrence of "**/".
    if let Some(delim) = pattern.find("**/") {
        let prefix = &pattern[..delim];
        // Skip past "**/" (3 characters).
        let suffix = &pattern[delim + 3..];

        let base = if prefix.is_empty() || prefix == "/" {
            PathBuf::from(if prefix.is_empty() { "." } else { "/" })
        } else {
            PathBuf::from(prefix)
        };

        if base.is_dir() {
            collect_recursive_glob(&base, suffix, &mut paths);
        }
    } else if let Some(prefix) = pattern.strip_suffix("**") {
        // Trailing ** without trailing slash — treat as "match everything
        // under the prefix directory".
        let base = if prefix.is_empty() {
            PathBuf::from(".")
        } else {
            PathBuf::from(prefix)
        };

        if base.is_dir() {
            collect_recursive_glob(&base, "*", &mut paths);
        }
    }

    paths.sort();
    paths
}

/// Recursively walk `dir`, applying `suffix` at every directory level.
///
/// `**` matches zero or more directory levels.  This function visits every
/// subdirectory and applies the suffix pattern at each level.  The suffix
/// may itself contain additional path components separated by `/`; the first
/// component is matched against directory entries and the remainder is
/// walked normally (without `**` semantics).
fn collect_recursive_glob(dir: &Path, suffix: &str, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };

    let collected: Vec<_> = entries.flatten().collect();

    for entry in &collected {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        let path = entry.path();

        // Apply the suffix at this level.
        // Split suffix into the first path component and the rest.
        if let Some(slash) = suffix.find('/') {
            let first = &suffix[..slash];
            let rest = &suffix[slash + 1..];

            // First component must match and entry must be a directory for
            // the rest of the pattern to apply.
            if path.is_dir() && simple_glob_match(&name_str, first) {
                walk_subpath(&path, rest, out);
            }
        } else if simple_glob_match(&name_str, suffix) {
            out.push(path.clone());
        }

        // Recurse into every subdirectory (zero-or-more levels).
        if path.is_dir() {
            collect_recursive_glob(&path, suffix, out);
        }
    }
}

/// Walk a non-`**` path pattern starting from `dir`.
///
/// Each call consumes one path component from `pattern`, matching it against
/// directory entries.  When the pattern is fully consumed the matching entry
/// is added to `out`.
fn walk_subpath(dir: &Path, pattern: &str, out: &mut Vec<PathBuf>) {
    let (first, rest) = if let Some(slash) = pattern.find('/') {
        (&pattern[..slash], Some(&pattern[slash + 1..]))
    } else {
        (pattern, None)
    };

    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };

    for entry in entries.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        if !simple_glob_match(&name_str, first) {
            continue;
        }

        if let Some(remaining) = rest {
            if entry.path().is_dir() {
                walk_subpath(&entry.path(), remaining, out);
            }
        } else {
            out.push(entry.path());
        }
    }
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
/// Accumulative directives (`IdentityFile`, `CertificateFile`, etc.) are
/// collected across all matching blocks. All other directives use
/// first-match-wins semantics.
fn resolve_block(nodes: &[ConfigNode], resolved: &mut ResolvedHost, seen: &mut HashSet<String>) {
    for node in nodes {
        if let ConfigNode::Directive(d) = node {
            // Accumulative directives — collect with dedup.
            if super::directives::is_accumulative(&d.keyword) {
                if d.keyword.eq_ignore_ascii_case("identityfile")
                    && !resolved.identity_files.iter().any(|f| f == &d.value)
                {
                    resolved.identity_files.push(d.value.clone());
                    resolved
                        .directives
                        .push((d.keyword.clone(), d.value.clone()));
                } else if d.keyword.eq_ignore_ascii_case("certificatefile")
                    && !resolved.certificate_files.iter().any(|f| f == &d.value)
                {
                    resolved.certificate_files.push(d.value.clone());
                    resolved
                        .directives
                        .push((d.keyword.clone(), d.value.clone()));
                } else if d.keyword.eq_ignore_ascii_case("localforward")
                    && !resolved.local_forwards.iter().any(|f| f == &d.value)
                {
                    resolved.local_forwards.push(d.value.clone());
                    resolved
                        .directives
                        .push((d.keyword.clone(), d.value.clone()));
                } else if d.keyword.eq_ignore_ascii_case("remoteforward")
                    && !resolved.remote_forwards.iter().any(|f| f == &d.value)
                {
                    resolved.remote_forwards.push(d.value.clone());
                    resolved
                        .directives
                        .push((d.keyword.clone(), d.value.clone()));
                } else if d.keyword.eq_ignore_ascii_case("dynamicforward")
                    && !resolved.dynamic_forwards.iter().any(|f| f == &d.value)
                {
                    resolved.dynamic_forwards.push(d.value.clone());
                    resolved
                        .directives
                        .push((d.keyword.clone(), d.value.clone()));
                }
                continue;
            }

            // Skip if we already have a value (first-match-wins).
            // `insert` returns false if the key was already present.
            let key_lower = d.keyword.to_ascii_lowercase();
            if !seen.insert(key_lower) {
                continue;
            }

            // Match first, then move key_lower into the set to avoid cloning.
            if d.keyword.eq_ignore_ascii_case("hostname") {
                resolved.host_name = Some(d.value.clone());
            } else if d.keyword.eq_ignore_ascii_case("user") {
                resolved.user = Some(d.value.clone());
            } else if d.keyword.eq_ignore_ascii_case("port") {
                resolved.port = d.value.parse::<u16>().ok();
            } else if d.keyword.eq_ignore_ascii_case("proxyjump") {
                resolved.proxy_jump = Some(d.value.clone());
            } else if d.keyword.eq_ignore_ascii_case("identityagent") {
                resolved.identity_agent = Some(d.value.clone());
            } else if d.keyword.eq_ignore_ascii_case("forwardagent") {
                resolved.forward_agent = Some(d.value.clone());
            } else if d.keyword.eq_ignore_ascii_case("addkeystoagent") {
                resolved.add_keys_to_agent = Some(d.value.clone());
            } else if d.keyword.eq_ignore_ascii_case("usekeychain") {
                resolved.use_keychain = Some(d.value.clone());
            } else if d.keyword.eq_ignore_ascii_case("controlmaster") {
                resolved.control_master = Some(d.value.clone());
            } else if d.keyword.eq_ignore_ascii_case("controlpath") {
                resolved.control_path = Some(d.value.clone());
            } else if d.keyword.eq_ignore_ascii_case("controlpersist") {
                resolved.control_persist = Some(d.value.clone());
            } else if d.keyword.eq_ignore_ascii_case("userknownhostsfile") {
                resolved.user_known_hosts_file = Some(d.value.clone());
            } else if d.keyword.eq_ignore_ascii_case("identitiesonly") {
                let lv = d.value.to_ascii_lowercase();
                if lv == "yes" {
                    resolved.identities_only = Some(true);
                } else if lv == "no" {
                    resolved.identities_only = Some(false);
                }
            } else if d.keyword.eq_ignore_ascii_case("gssapiauthentication") {
                resolved.gssapi_authentication = Some(d.value.clone());
            } else if d.keyword.eq_ignore_ascii_case("gssapidelegatecredentials") {
                resolved.gssapi_delegate_credentials = Some(d.value.clone());
            } else if d.keyword.eq_ignore_ascii_case("gssapiserveridentity") {
                resolved.gssapi_server_identity = Some(d.value.clone());
            } else if d.keyword.eq_ignore_ascii_case("gssapiclientidentity") {
                resolved.gssapi_client_identity = Some(d.value.clone());
            }

            resolved
                .directives
                .push((d.keyword.clone(), d.value.clone()));
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
    /// Canonical hostname (same as host unless `CanonicalizeHostname` is enabled).
    canonical_host: &'a str,
    /// Identity file being expanded (`%i` → basename).  `None` when
    /// expanding a non-IdentityFile directive.
    #[allow(
        dead_code,
        reason = "placeholder for `%i` token expansion, not yet wired"
    )]
    identity_file: Option<&'a str>,
    /// Local host key (`%k`).
    local_host_key: &'a str,
    /// Jump host (`%j`).
    jump_host: &'a str,
    /// Remote host key (`%K`).
    remote_host_key: &'a str,
}

/// Expand tokens in resolved values.
///
/// Applies tilde, environment-variable, and SSH token expansion to all
/// directive values that may contain them — including the dedicated
/// fields (`identity_files`, `host_name`, `proxy_jump`) and every
/// entry in the raw `directives` vec whose key is listed in
/// [`TOKEN_EXPANDABLE`].
#[expect(
    clippy::too_many_lines,
    reason = "serial field-by-field expansion over ResolvedHost"
)]
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
        // On first pass canonical_host == host; second pass uses the
        // canonical name (already substituted as `host` by the caller).
        canonical_host: host,
        identity_file: None,
        // Placeholders — not yet populated from live connection state.
        local_host_key: "",
        jump_host: "",
        remote_host_key: "",
    };

    // Expand dedicated fields.
    for id_file in &mut resolved.identity_files {
        *id_file = expand_tilde_and_env(id_file);
        *id_file = expand_tokens(id_file, &ctx);
        *id_file = collapse_double_percent(id_file);
    }

    for cert_file in &mut resolved.certificate_files {
        *cert_file = expand_tilde_and_env(cert_file);
        *cert_file = expand_tokens(cert_file, &ctx);
        *cert_file = collapse_double_percent(cert_file);
    }

    if let Some(ref mut hn) = resolved.host_name {
        *hn = expand_tilde_and_env(hn);
        *hn = expand_tokens(hn, &ctx);
        *hn = collapse_double_percent(hn);
    }

    if let Some(ref mut pj) = resolved.proxy_jump {
        *pj = expand_tokens(pj, &ctx);
        *pj = collapse_double_percent(pj);
    }

    if let Some(ref mut ia) = resolved.identity_agent {
        *ia = expand_tilde_and_env(ia);
        *ia = expand_tokens(ia, &ctx);
        *ia = collapse_double_percent(ia);
    }

    if let Some(ref mut cp) = resolved.control_path {
        *cp = expand_tilde_and_env(cp);
        *cp = expand_tokens(cp, &ctx);
        *cp = collapse_double_percent(cp);
    }

    if let Some(ref mut fa) = resolved.forward_agent {
        *fa = expand_tilde_and_env(fa);
        *fa = expand_tokens(fa, &ctx);
        *fa = collapse_double_percent(fa);
    }

    if let Some(ref mut ata) = resolved.add_keys_to_agent {
        *ata = expand_tilde_and_env(ata);
        *ata = expand_tokens(ata, &ctx);
        *ata = collapse_double_percent(ata);
    }

    if let Some(ref mut uk) = resolved.use_keychain {
        *uk = expand_tilde_and_env(uk);
        *uk = expand_tokens(uk, &ctx);
        *uk = collapse_double_percent(uk);
    }

    if let Some(ref mut cm) = resolved.control_master {
        *cm = expand_tilde_and_env(cm);
        *cm = expand_tokens(cm, &ctx);
        *cm = collapse_double_percent(cm);
    }

    if let Some(ref mut cpers) = resolved.control_persist {
        *cpers = expand_tilde_and_env(cpers);
        *cpers = expand_tokens(cpers, &ctx);
        *cpers = collapse_double_percent(cpers);
    }

    for lf in &mut resolved.local_forwards {
        *lf = expand_tilde_and_env(lf);
        *lf = expand_tokens(lf, &ctx);
        *lf = collapse_double_percent(lf);
    }

    for rf in &mut resolved.remote_forwards {
        *rf = expand_tilde_and_env(rf);
        *rf = expand_tokens(rf, &ctx);
        *rf = collapse_double_percent(rf);
    }

    for df in &mut resolved.dynamic_forwards {
        *df = expand_tilde_and_env(df);
        *df = expand_tokens(df, &ctx);
        *df = collapse_double_percent(df);
    }

    // Expand all raw directive values that may contain tokens.
    for (key, value) in &mut resolved.directives {
        let key_lower = key.to_lowercase();
        if TOKEN_EXPANDABLE.contains(&key_lower.as_str())
            || key_lower == "identityfile"
            || key_lower == "hostname"
            || key_lower == "proxyjump"
        {
            let expanded = expand_tilde_and_env(value);
            let expanded = expand_tokens(&expanded, &ctx);
            *value = collapse_double_percent(&expanded);
        }
    }
}

/// Check whether `CanonicalizeHostname` is enabled in the resolved config.
///
/// OpenSSH recognises `yes`, `always`, and `no` (the default).  Any other
/// value is treated as `no`.
fn is_canonicalize_enabled(resolved: &ResolvedHost) -> bool {
    resolved
        .directives
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("canonicalizehostname"))
        .is_some_and(|(_, v)| {
            let lv = v.to_lowercase();
            lv == "yes" || lv == "always"
        })
}

/// Expand SSH tokens in a value string.
///
/// Supported tokens (matching OpenSSH `ssh_config(5)`):
/// - `%%` → literal `%`
/// - `%C` → hash of connection (host+port+user) — placeholder
/// - `%d` → home directory
/// - `%H` → canonical hostname
/// - `%h` / `%n` → remote host (alias)
/// - `%i` → local username (same as `%u`; see note in implementation)
/// - `%j` → jump host (placeholder)
/// - `%K` → remote host key (placeholder)
/// - `%k` → local host key (placeholder)
/// - `%L` → local hostname (short)
/// - `%l` → local hostname (FQDN)
/// - `%p` → remote port
/// - `%r` → remote username
/// - `%T` → remote username (same as %r)
/// - `%t` → remote port (same as %p)
/// - `%u` → local username
///
/// Unknown `%X` sequences and trailing `%` are preserved as-is.
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
                Some('C') => {
                    // Connection hash — use a simple hash of host:port:user.
                    chars.next();
                    let hash_input = format!("{}:{}:{}", ctx.host, ctx.port, ctx.local_user);
                    let hash = simple_hash(&hash_input);
                    result.push_str(&hash);
                }
                Some('d') => {
                    chars.next();
                    result.push_str(ctx.home_dir);
                }
                Some('H') => {
                    chars.next();
                    result.push_str(ctx.canonical_host);
                }
                Some('h' | 'n') => {
                    chars.next();
                    result.push_str(ctx.host);
                }
                Some('L') => {
                    // Short hostname (first component before '.').
                    chars.next();
                    let short = ctx
                        .local_hostname
                        .split('.')
                        .next()
                        .unwrap_or(ctx.local_hostname);
                    result.push_str(short);
                }
                Some('l') => {
                    chars.next();
                    result.push_str(ctx.local_hostname);
                }
                Some('p') => {
                    chars.next();
                    result.push_str(ctx.port);
                }
                Some('r' | 'T') => {
                    // %r and %T both expand to the remote username.
                    chars.next();
                    result.push_str(ctx.remote_user);
                }
                Some('i' | 'u') => {
                    // %i and %u both expand to the local username.
                    // Note: per OpenSSH, %i is the "identity file name" in some
                    // contexts, but when used in IdentityFile paths it would create
                    // a circular reference.  The local username fallback matches
                    // OpenSSH behaviour for IdentityFile and most other directives.
                    chars.next();
                    result.push_str(ctx.local_user);
                }
                Some('k') => {
                    // %k → local host key.
                    chars.next();
                    result.push_str(ctx.local_host_key);
                }
                Some('j') => {
                    // %j → jump host.
                    chars.next();
                    result.push_str(ctx.jump_host);
                }
                Some('K') => {
                    // %K → remote host key.
                    chars.next();
                    result.push_str(ctx.remote_host_key);
                }
                Some('t') => {
                    // %t → remote port (same as %p).
                    chars.next();
                    result.push_str(ctx.port);
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

/// Simple hash function for `%C` token (OpenSSH uses SHA-1 of host:port:user).
///
/// Uses a FNV-1a style hash for stability across Rust versions.  This is NOT
/// cryptographically secure — it only needs to be deterministic and collision-
/// resistant enough for socket naming.  OpenSSH uses SHA-1 here, but we avoid
/// the dependency.
fn simple_hash(s: &str) -> String {
    let bytes = s.as_bytes();
    // FNV-1a 64-bit parameters
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    let prime: u64 = 0x0100_0000_01b3;
    for &b in bytes {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(prime);
    }
    format!("{hash:016x}")
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
    std::env::var("HOSTNAME")
        .unwrap_or_else(|_| gethostname::gethostname().to_string_lossy().into_owned())
}

/// Check if a hostname matches SSH config patterns (reuses directive logic).
fn host_matches(host: &str, patterns: &[impl AsRef<str>]) -> bool {
    super::directives::host_matches_patterns(host, patterns)
}

/// Check if `Match` criteria are satisfied for the given host context.
///
/// Supported criteria keywords (case-insensitive):
/// - `host <patterns>` — matches against `target_host` (the hostname being
///   resolved, which may be the canonical name on a second pass).
/// - `originalhost <patterns>` — matches against `original_host` (the
///   alias the user typed, before any canonicalization).
/// - `user <names>` — matches against `target_user` (the remote username;
///   comma-separated, case-insensitive comparison).
/// - `localuser <names>` — matches against the local username;
///   comma-separated, case-insensitive comparison.
///
/// Multiple occurrences of the **same** keyword are OR'd (e.g.
/// `host web host db` matches either "web" or "db").  Different keywords
/// are AND'd (e.g. `user alice host web` requires both to match).
///
/// Returns `true` only when every recognized criterion type matches and at
/// least one recognized criterion is present.  Unrecognized keywords
/// (e.g. `exec`, `address`) are silently skipped.
fn match_criteria_host(
    criteria: &str,
    target_host: &str,
    target_user: &str,
    original_host: &str,
) -> bool {
    let mut tokens = criteria.split_whitespace();

    // Track per-keyword-type state: whether the type appeared and whether
    // at least one occurrence matched (OR within a type).
    let mut has_host = false;
    let mut host_matched = false;
    let mut has_originalhost = false;
    let mut originalhost_matched = false;
    let mut has_user = false;
    let mut user_matched = false;
    let mut has_localuser = false;
    let mut localuser_matched = false;

    // Determine the local username for localuser matching.
    let local_user = whoami();

    while let Some(keyword) = tokens.next() {
        if keyword.eq_ignore_ascii_case("host") {
            if let Some(patterns_str) = tokens.next() {
                has_host = true;
                let patterns: Vec<&str> = patterns_str.split(',').collect();
                if host_matches(target_host, &patterns) {
                    host_matched = true;
                }
            }
        } else if keyword.eq_ignore_ascii_case("originalhost") {
            if let Some(patterns_str) = tokens.next() {
                has_originalhost = true;
                let patterns: Vec<&str> = patterns_str.split(',').collect();
                if host_matches(original_host, &patterns) {
                    originalhost_matched = true;
                }
            }
        } else if keyword.eq_ignore_ascii_case("user") {
            if let Some(names_str) = tokens.next() {
                has_user = true;
                // OpenSSH matches user names case-insensitively.
                let names: Vec<&str> = names_str.split(',').collect();
                if names.iter().any(|n| n.eq_ignore_ascii_case(target_user)) {
                    user_matched = true;
                }
            }
        } else if keyword.eq_ignore_ascii_case("localuser") {
            if let Some(names_str) = tokens.next() {
                has_localuser = true;
                let names: Vec<&str> = names_str.split(',').collect();
                if names.iter().any(|n| n.eq_ignore_ascii_case(&local_user)) {
                    localuser_matched = true;
                }
            }
        } else if keyword.eq_ignore_ascii_case("exec") {
            // `exec` consumes the rest of the criteria string as its command
            // (it is always the last criterion on a Match line per OpenSSH).
            // We intentionally do not evaluate exec — just skip the remainder.
            break;
        } else {
            // Unknown criterion keyword — consume its value token and skip.
            // Criteria like `address` fall here.
            tokens.next();
        }
    }

    // At least one criterion type must be present.
    let any_known = has_host || has_originalhost || has_user || has_localuser;
    // All present types must have matched (AND across types).
    let all_matched = (!has_host || host_matched)
        && (!has_originalhost || originalhost_matched)
        && (!has_user || user_matched)
        && (!has_localuser || localuser_matched);

    any_known && all_matched
}

/// Check whether a Match criteria string contains an `exec` keyword.
///
/// The `exec` criterion runs an arbitrary command to determine whether
/// a Match block applies.  This is a security-sensitive operation that
/// toride intentionally does not support.
fn contains_exec_criteria(criteria: &str) -> bool {
    let mut tokens = criteria.split_whitespace();
    while let Some(keyword) = tokens.next() {
        if keyword.eq_ignore_ascii_case("exec") {
            return true;
        }
        // Each criterion keyword is followed by a value token.
        // If the keyword is unknown but not exec, just skip one value token.
        tokens.next();
    }
    false
}

#[cfg(test)]
#[path = "resolve.test.rs"]
mod tests;
