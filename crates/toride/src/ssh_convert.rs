//! Convert `toride-ssh` library types to UI presentation types.
//!
//! Standalone conversion functions that map rich library structs to the simpler
//! types used by the TUI tab renderers. Each function handles errors gracefully
//! — individual entries that fail conversion are skipped with a warning log.

use std::ffi::OsStr;
use std::time::{SystemTime, UNIX_EPOCH};

use toride_ssh::KeyType;

use crate::ui::screens::ssh::{
    AgentKeyEntry, AgentStatus, AuthorizedKeyEntry, CertificateEntry, ConfigHostEntry,
    DiagnosticEntry, ForwardEntry, ForwardSessionEntry, KnownHostEntry, SshKeyEntry,
};

// ── Known Hosts ─────────────────────────────────────────────────────────────

/// Convert library known_hosts entries to UI entries.
///
/// Groups multiple key lines for the same host into a single entry.
/// For example, if `github.com` has ed25519, ecdsa, and rsa keys,
/// they become one entry with `key_types: ["ssh-ed25519", "ecdsa-sha2-nistp256", "ssh-rsa"]`.
pub fn convert_known_hosts(
    entries: Vec<toride_ssh::known_hosts::KnownHostEntry>,
) -> Vec<KnownHostEntry> {
    // Index: sorted comma-joined host string → (key_types, fingerprints, first entry)
    let mut groups: std::collections::BTreeMap<String, GroupAccum> =
        std::collections::BTreeMap::new();

    for e in &entries {
        let is_hashed = e.hosts.iter().any(|h| h.starts_with("|1|"));
        let fingerprint = match e.fingerprint() {
            Ok(fp) => format!("{fp}"),
            Err(err) => {
                tracing::warn!(
                    "known_hosts line {}: fingerprint failed: {err}",
                    e.line_number
                );
                "(unknown)".into()
            }
        };
        // Use sorted comma-joined hosts as the grouping key so
        // ["github.com"] and ["github.com"] match even if line order differs.
        let mut host_key = e.hosts.clone();
        host_key.sort();
        let host_key = host_key.join(",");

        let acc = groups.entry(host_key).or_insert_with(|| GroupAccum {
            hosts: e.hosts.clone(),
            is_hashed,
            marker: e.markers.first().cloned(),
            comment: e.comment.clone(),
            line: e.line_number,
            source: "user".into(),
            key_types: Vec::new(),
            fingerprints: Vec::new(),
        });
        acc.key_types.push(e.key_type.clone());
        acc.fingerprints.push(fingerprint);
    }

    groups
        .into_values()
        .map(|g| {
            let key_type = g.key_types.first().cloned().unwrap_or_default();
            let fingerprint = g.fingerprints.first().cloned().unwrap_or_default();
            KnownHostEntry {
                hosts: g.hosts,
                key_type,
                key_types: g.key_types,
                fingerprint,
                fingerprints: g.fingerprints,
                is_hashed: g.is_hashed,
                marker: g.marker,
                comment: g.comment,
                line: g.line,
                source: g.source,
            }
        })
        .collect()
}

/// Accumulator for grouping known_hosts lines by host.
struct GroupAccum {
    hosts: Vec<String>,
    is_hashed: bool,
    marker: Option<String>,
    comment: Option<String>,
    line: usize,
    source: String,
    key_types: Vec<String>,
    fingerprints: Vec<String>,
}

// ── Authorized Keys ─────────────────────────────────────────────────────────

/// Convert library authorized_keys entries to UI entries.
pub fn convert_authorized_keys(
    entries: Vec<toride_ssh::authorized_keys::Entry>,
) -> Vec<AuthorizedKeyEntry> {
    entries
        .into_iter()
        .map(|e| {
            let options_str = e.options.as_ref().map(|o| format_options(o));
            let fp = e.fingerprint().unwrap_or_else(|| "(unknown)".into());
            AuthorizedKeyEntry {
                key_type: e.key_type,
                public_key: truncate_key(&e.public_key, 60),
                comment: e.comment,
                fingerprint: fp,
                options: options_str,
                line: e.line_number,
            }
        })
        .collect()
}

/// Format authorized key options back to a string representation.
fn format_options(opts: &toride_ssh::authorized_keys::Options) -> String {
    let mut parts = Vec::new();

    if let Some(ref cmd) = opts.command {
        parts.push(format!("command=\"{cmd}\""));
    }
    for from in &opts.from {
        parts.push(format!("from=\"{from}\""));
    }
    if opts.no_pty {
        parts.push("no-pty".into());
    }
    if opts.no_port_forwarding {
        parts.push("no-port-forwarding".into());
    }
    if opts.no_x11_forwarding {
        parts.push("no-X11-forwarding".into());
    }
    if opts.no_agent_forwarding {
        parts.push("no-agent-forwarding".into());
    }
    if opts.no_user_rc {
        parts.push("no-user-rc".into());
    }
    if opts.restrict {
        parts.push("restrict".into());
    }
    for addr in &opts.permit_open {
        parts.push(format!("permit-open=\"{addr}\""));
    }
    for (k, v) in &opts.environment {
        parts.push(format!("environment=\"{k}={v}\""));
    }
    if let Some(ref t) = opts.tunnel {
        parts.push(format!("tunnel=\"{t}\""));
    }
    if opts.cert_authority {
        parts.push("cert-authority".into());
    }
    for p in &opts.principals {
        parts.push(format!("principals=\"{p}\""));
    }
    if let Some(ref exp) = opts.expiry_time {
        parts.push(format!("expiry-time=\"{exp}\""));
    }
    if opts.perferrp {
        parts.push("perferrp".into());
    }
    for (name, val) in &opts.custom {
        match val {
            Some(v) => parts.push(format!("{name}=\"{v}\"")),
            None => parts.push(name.clone()),
        }
    }

    parts.join(",")
}

// ── SSH Keys ────────────────────────────────────────────────────────────────

/// Convert library SSH key entries to UI entries.
pub fn convert_keys(keys: Vec<toride_ssh::SshKey>) -> Vec<SshKeyEntry> {
    keys.into_iter()
        .map(|k| SshKeyEntry {
            name: k
                .path
                .file_name()
                .unwrap_or_else(|| OsStr::new("(unknown)"))
                .to_string_lossy()
                .into_owned(),
            key_type: format_key_type(&k.key_type),
            fingerprint: k
                .fingerprint
                .as_ref()
                .map(|fp| format!("{fp}"))
                .unwrap_or_default(),
            encrypted: k.encrypted,
            permissions: k
                .permissions
                .map(|p| format!("0{:o}", p.mode))
                .unwrap_or_default(),
            has_public: k.has_public_pair,
            has_cert: k.has_certificate,
            host_count: k.used_by_hosts.len(),
        })
        .collect()
}

/// Format a `KeyType` enum to a human-readable string.
pub fn format_key_type(kt: &KeyType) -> String {
    match kt {
        KeyType::Ed25519 => "Ed25519".into(),
        KeyType::Rsa { bits } => {
            if *bits > 0 {
                format!("RSA {bits}")
            } else {
                "RSA".into()
            }
        }
        KeyType::EcdsaP256 => "ECDSA P-256".into(),
        KeyType::EcdsaP384 => "ECDSA P-384".into(),
        KeyType::EcdsaP521 => "ECDSA P-521".into(),
        KeyType::Dsa => "DSA".into(),
        KeyType::SkEd25519 => "FIDO2 Ed25519".into(),
        KeyType::SkEcdsaP256 => "FIDO2 ECDSA P-256".into(),
    }
}

// ── Diagnostics ─────────────────────────────────────────────────────────────

/// Convert library diagnostics to UI diagnostics.
pub fn convert_diagnostics(diagnostics: Vec<toride_ssh::Diagnostic>) -> Vec<DiagnosticEntry> {
    diagnostics
        .into_iter()
        .map(|d| DiagnosticEntry {
            id: d.id.to_owned(),
            severity: format_severity(d.severity),
            module: d.module.to_owned(),
            message: d.message,
            hint: d.hint,
        })
        .collect()
}

/// Format a diagnostic severity to a string.
pub fn format_severity(s: toride_ssh::Severity) -> String {
    match s {
        toride_ssh::Severity::Ok => "ok".into(),
        toride_ssh::Severity::Info => "info".into(),
        toride_ssh::Severity::Warning => "warning".into(),
        toride_ssh::Severity::Error => "error".into(),
    }
}

// ── Config Hosts ────────────────────────────────────────────────────────────

/// Convert a parsed config AST to UI config host entries.
pub fn convert_config_ast(ast: &toride_ssh::config::ast::ConfigAst) -> Vec<ConfigHostEntry> {
    let mut entries = Vec::new();

    for node in &ast.nodes {
        let hb = match node {
            toride_ssh::config::ast::ConfigNode::HostBlock(b) => b,
            _ => continue,
        };

        let mut host_name = None;
        let mut user = None;
        let mut port = None;
        let mut identity_file = None;
        let mut proxy_jump = None;
        let mut directive_count = 0usize;

        for child in &hb.nodes {
            if let toride_ssh::config::ast::ConfigNode::Directive(d) = child {
                directive_count += 1;
                match d.keyword.to_ascii_lowercase().as_str() {
                    "hostname" => host_name = Some(d.value.clone()),
                    "user" => user = Some(d.value.clone()),
                    "port" => port = d.value.parse().ok(),
                    "identityfile" => identity_file = Some(d.value.clone()),
                    "proxyjump" => proxy_jump = Some(d.value.clone()),
                    _ => {}
                }
            }
        }

        entries.push(ConfigHostEntry {
            name: hb
                .patterns
                .first()
                .cloned()
                .unwrap_or_else(|| hb.header.clone()),
            patterns: hb.patterns.clone(),
            host_name,
            user,
            port,
            identity_file,
            proxy_jump,
            directive_count,
            has_diagnostic: false,
        });
    }

    entries
}

// ── Agent ────────────────────────────────────────────────────────────────────

/// Convert agent keys and status into UI types.
///
/// `reachable` and `socket_path` come from the collector (not from `SshKey`).
/// `is_locked` and `has_constraints` default to `false` — the current agent
/// protocol does not expose these fields.
pub fn convert_agent_keys(
    keys: Vec<toride_ssh::SshKey>,
    reachable: bool,
    socket_path: Option<String>,
) -> (AgentStatus, Vec<AgentKeyEntry>) {
    let entries: Vec<AgentKeyEntry> = keys
        .into_iter()
        .map(|k| AgentKeyEntry {
            name: k
                .comment
                .clone()
                .unwrap_or_else(|| {
                    k.path
                        .file_name()
                        .unwrap_or_else(|| OsStr::new("(unknown)"))
                        .to_string_lossy()
                        .into_owned()
                }),
            key_type: format_key_type(&k.key_type),
            fingerprint: k
                .fingerprint
                .as_ref()
                .map(|fp| format!("{fp}"))
                .unwrap_or_default(),
            is_locked: false,
            has_constraints: false,
        })
        .collect();

    let status = AgentStatus {
        reachable,
        socket_path,
        key_count: entries.len(),
    };

    (status, entries)
}

// ── Forwarding ───────────────────────────────────────────────────────────────

/// Convert forwarding sessions and their port forwards to UI types.
pub fn convert_forwarding(
    sessions: Vec<(
        toride_ssh::forward::ControlSession,
        Vec<toride_ssh::forward::PortForward>,
    )>,
) -> Vec<ForwardSessionEntry> {
    sessions
        .into_iter()
        .map(|(session, forwards)| {
            let converted_forwards: Vec<ForwardEntry> = forwards
                .into_iter()
                .map(|pf| ForwardEntry {
                    forward_type: pf.forward_type.to_string(),
                    local_addr: pf.local_addr,
                    local_port: pf.local_port,
                    remote_addr: pf.remote_addr,
                    remote_port: pf.remote_port,
                })
                .collect();
            let forward_count = converted_forwards.len();
            ForwardSessionEntry {
                host: session.host,
                control_path: session.control_path.display().to_string(),
                pid: session.pid,
                established_ago: format_duration_since(session.established),
                forwards: converted_forwards,
                forward_count,
            }
        })
        .collect()
}

// ── Certificates ─────────────────────────────────────────────────────────────

/// Convert certificate file paths and their parsed info into UI types.
pub fn convert_certificates(
    certs: Vec<(std::path::PathBuf, toride_ssh::certificate::CertificateInfo)>,
) -> Vec<CertificateEntry> {
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    certs
        .into_iter()
        .map(|(path, info)| {
            let is_valid = info.valid_after <= now_secs && now_secs < info.valid_before;
            CertificateEntry {
                name: path
                    .file_name()
                    .unwrap_or_else(|| OsStr::new("(unknown)"))
                    .to_string_lossy()
                    .into_owned(),
                cert_type: if info.is_host {
                    "Host".into()
                } else {
                    "User".into()
                },
                key_type: info.key_type,
                serial: info.serial,
                valid_from: format_unix_timestamp(info.valid_after),
                valid_to: format_unix_timestamp(info.valid_before),
                is_valid,
                ca_fingerprint: info.ca_fingerprint.unwrap_or_default(),
                key_id: info.key_id,
                principals: info.valid_principals,
            }
        })
        .collect()
}

// ── Helpers ─────────────────────────────────────────────────────────────────

/// Truncate a base64 public key for display, keeping the beginning and end.
fn truncate_key(key: &str, max_len: usize) -> String {
    if key.len() <= max_len {
        return key.to_owned();
    }
    let half = max_len / 2 - 1;
    format!("{}..{}", &key[..half], &key[key.len() - half..])
}

/// Format the duration since a `SystemTime` as a human-readable string.
///
/// Returns `"Xd Xh Xm"` with zero units omitted. Returns an empty string
/// if the time is `None` or the clock would go backwards.
fn format_duration_since(t: Option<SystemTime>) -> String {
    let established = match t {
        Some(t) => t,
        None => return String::new(),
    };
    match SystemTime::now().duration_since(established) {
        Ok(dur) => {
            let total_secs = dur.as_secs();
            let days = total_secs / 86400;
            let hours = (total_secs % 86400) / 3600;
            let mins = (total_secs % 3600) / 60;
            let mut parts = Vec::new();
            if days > 0 {
                parts.push(format!("{days}d"));
            }
            if hours > 0 {
                parts.push(format!("{hours}h"));
            }
            parts.push(format!("{mins}m"));
            parts.join(" ")
        }
        Err(_) => String::new(),
    }
}

/// Format a Unix timestamp (seconds) as a human-readable datetime string.
///
/// Returns `"forever"` for `u64::MAX`, or `"(invalid)"` if out of range.
fn format_unix_timestamp(secs: u64) -> String {
    if secs == u64::MAX {
        return "forever".into();
    }
    chrono::DateTime::from_timestamp(secs as i64, 0)
        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
        .unwrap_or_else(|| "(invalid)".into())
}
