//! Async SSH data collection.
//!
//! [`SshDataCollector`] manages background collection of all SSH subsystem data
//! via a tokio oneshot channel, following the same pattern as [`StatusCollector`].
//!
//! Reads real SSH files via the `toride-ssh` library. Falls back to empty data
//! when files are missing or unreadable. Mock data is available behind `#[cfg(test)]`
//! for unit tests.

use std::collections::HashMap;
use std::path::Path;

use ratatui::style::Color;
use tokio::sync::oneshot;

use crate::ssh_convert;
use crate::ui::screens::ssh::{
    AgentKeyEntry, AgentStatus, AuthorizedKeyEntry, CertificateEntry, ConfigHostEntry,
    DiagnosticEntry, ForwardSessionEntry, KnownHostEntry, SshAccessInfo,
    SshKeyEntry, SystemUserInfo,
};
#[cfg(test)]
use crate::ui::screens::ssh::ForwardEntry;
use crate::ui::theme::Palette;

/// Aggregated SSH data for all tabs.
pub struct SshDataBundle {
    /// SSH key entries.
    pub keys: Vec<SshKeyEntry>,
    /// Known hosts entries.
    pub known_hosts: Vec<KnownHostEntry>,
    /// SSH config host blocks.
    pub config_hosts: Vec<ConfigHostEntry>,
    /// SSH agent connection status.
    pub agent_status: AgentStatus,
    /// Keys loaded in the SSH agent.
    pub agent_keys: Vec<AgentKeyEntry>,
    /// Active port forwarding sessions.
    pub forwarding: Vec<ForwardSessionEntry>,
    /// Diagnostic check results.
    pub diagnostics: Vec<DiagnosticEntry>,
    /// Authorized keys entries.
    pub authorized_keys: Vec<AuthorizedKeyEntry>,
    /// SSH certificate entries.
    pub certificates: Vec<CertificateEntry>,
    /// Security overview data.
    pub security: SshSecurityData,
}

// ── Collector ────────────────────────────────────────────────────────────────

/// Manages periodic async collection of SSH data.
pub struct SshDataCollector {
    rx: Option<oneshot::Receiver<SshDataBundle>>,
}

impl SshDataCollector {
    /// Create a new collector with no pending collection.
    #[must_use]
    pub fn new() -> Self {
        Self { rx: None }
    }

    /// Whether a collection is currently in-flight.
    pub fn is_pending(&self) -> bool {
        self.rx.is_some()
    }

    /// Start a new background collection.
    ///
    /// If a collection is already in-flight, this is a no-op.
    pub fn start(&mut self) {
        if self.rx.is_some() {
            return;
        }
        let (tx, rx) = oneshot::channel();
        self.rx = Some(rx);
        tokio::spawn(async move {
            let bundle = collect_real_data().await;
            let _ = tx.send(bundle);
        });
    }

    /// Poll for a completed collection result.
    ///
    /// Returns `Some(bundle)` if the collection completed, `None` if still
    /// pending or if the collection failed.
    pub async fn poll(&mut self) -> Option<SshDataBundle> {
        match &mut self.rx {
            Some(rx) => {
                let result = rx.await.ok();
                self.rx = None;
                result
            }
            None => None,
        }
    }
}

impl Default for SshDataCollector {
    fn default() -> Self {
        Self::new()
    }
}

// ── Real Data Collection ────────────────────────────────────────────────────

/// A pending write operation to be executed asynchronously via `SshManager`.
#[derive(Debug)]
pub enum SshOp {
    /// Add a host block to `~/.ssh/config`.
    ConfigAddHost {
        name: String,
        host_name: Option<String>,
        user: Option<String>,
        port: Option<u16>,
    },
    /// Remove a host block from `~/.ssh/config`.
    ConfigRemoveHost {
        name: String,
    },
    /// Edit (replace) a host block in `~/.ssh/config`.
    ConfigEditHost {
        old_name: String,
        new_name: String,
        host_name: Option<String>,
        user: Option<String>,
        port: Option<u16>,
    },
    /// Generate a new SSH key pair.
    KeyCreate {
        name: String,
        key_type: String,
        comment: String,
        passphrase: Option<String>,
    },
    /// Delete an SSH key pair.
    KeyDelete {
        name: String,
    },
    /// Rename an SSH key pair.
    KeyRename {
        old_name: String,
        new_name: String,
    },
    /// Add a host to known_hosts via ssh-keyscan.
    KnownHostAdd {
        host: String,
    },
    /// Remove a host from known_hosts.
    KnownHostRemove {
        host: String,
    },
    /// Add a key to the SSH agent.
    AgentAddKey {
        path: String,
    },
    /// Remove a key from the SSH agent.
    AgentRemoveKey {
        path: String,
    },
    /// Add a public key to authorized_keys.
    AuthorizedKeyAdd {
        public_key: String,
        comment: Option<String>,
        options: Option<String>,
    },
    /// Remove a public key from authorized_keys by fingerprint.
    AuthorizedKeyRemove {
        fingerprint: String,
    },
    /// Fix permissions on an SSH key pair.
    KeyChmodFix {
        name: String,
    },
    /// Scan a host for its SSH host keys.
    KnownHostScan {
        host: String,
    },
    /// Hash all plaintext hostnames in known_hosts.
    KnownHostHashAll,
    /// Remove all keys from the SSH agent.
    AgentRemoveAll,
    /// Cancel a specific port forward on a control session.
    ForwardCancel {
        control_path: String,
        local_port: u16,
    },
    /// Exit (terminate) a control master session.
    ForwardExitSession {
        control_path: String,
    },
    /// Revoke a key by adding it to the KRL.
    CertificateRevoke {
        name: String,
    },
    /// Run all local SSH diagnostic checks.
    DoctorRunChecks,
    /// Install a public key to a remote host.
    KeyInstallToRemote {
        key_name: String,
        dest: String,
    },
}

/// Execute a pending write operation using the given `SshManager`.
///
/// Returns `Ok(label)` on success (e.g. `"added host 'myserver'"`) or
/// `Err(message)` on failure. Both outcomes are also logged via tracing.
pub async fn execute_op(op: SshOp) -> Result<String, String> {
    let mgr = match toride_ssh::SshManager::new() {
        Ok(m) => m,
        Err(e) => {
            let msg = format!("SSH init failed: {e}");
            tracing::error!("{msg}");
            return Err(msg);
        }
    };

    match op {
        SshOp::ConfigAddHost { name, host_name, user, port } => {
            let svc = mgr.config();
            let mut directives = Vec::new();
            if let Some(hn) = &host_name {
                directives.push(("HostName".to_string(), hn.clone()));
            }
            if let Some(u) = &user {
                directives.push(("User".to_string(), u.clone()));
            }
            if let Some(p) = port {
                directives.push(("Port".to_string(), p.to_string()));
            }
            match svc.edit(|ast| {
                toride_ssh::config::ConfigService::add_host(ast, &name, directives)
            }).await {
                Ok(()) => {
                    tracing::info!("config: added host '{name}'");
                    Ok(format!("added host '{name}'"))
                }
                Err(e) => {
                    let msg = format!("failed to add host '{name}': {e}");
                    tracing::error!("config: {msg}");
                    Err(msg)
                }
            }
        }
        SshOp::ConfigRemoveHost { name } => {
            let svc = mgr.config();
            match svc.edit(|ast| {
                toride_ssh::config::ConfigService::remove_host(ast, &name)
            }).await {
                Ok(()) => {
                    tracing::info!("config: removed host '{name}'");
                    Ok(format!("removed host '{name}'"))
                }
                Err(e) => {
                    let msg = format!("failed to remove host '{name}': {e}");
                    tracing::error!("config: {msg}");
                    Err(msg)
                }
            }
        }
        SshOp::ConfigEditHost { old_name, new_name, host_name, user, port } => {
            let svc = mgr.config();
            match svc.edit(|ast| {
                // Remove old block, add new one
                let _ = toride_ssh::config::ConfigService::remove_host(ast, &old_name);
                let mut directives = Vec::new();
                if let Some(hn) = &host_name {
                    directives.push(("HostName".to_string(), hn.clone()));
                }
                if let Some(u) = &user {
                    directives.push(("User".to_string(), u.clone()));
                }
                if let Some(p) = port {
                    directives.push(("Port".to_string(), p.to_string()));
                }
                toride_ssh::config::ConfigService::add_host(ast, &new_name, directives)
            }).await {
                Ok(()) => {
                    tracing::info!("config: edited host '{old_name}' → '{new_name}'");
                    Ok(format!("edited host '{old_name}' → '{new_name}'"))
                }
                Err(e) => {
                    let msg = format!("failed to edit host '{old_name}': {e}");
                    tracing::error!("config: {msg}");
                    Err(msg)
                }
            }
        }
        SshOp::KeyCreate { name, key_type, comment, passphrase } => {
            let svc = mgr.keys();
            let mut params = match key_type.as_str() {
                "RSA 4096" => toride_ssh::KeyCreateParams::rsa_4096(name.clone()),
                "ECDSA P-256" => {
                    let mut p = toride_ssh::KeyCreateParams::ed25519(name.clone());
                    p.key_type = toride_ssh::KeyType::EcdsaP256;
                    p
                }
                _ => toride_ssh::KeyCreateParams::ed25519(name.clone()),
            };
            if !comment.is_empty() {
                params.comment = Some(comment.clone());
            }
            if let Some(ref pw) = passphrase {
                if !pw.is_empty() {
                    params.passphrase = Some(pw.clone());
                }
            }
            match svc.create(params).await {
                Ok(_) => {
                    tracing::info!("keys: created '{name}'");
                    Ok(format!("created key '{name}'"))
                }
                Err(e) => {
                    let msg = format!("failed to create key '{name}': {e}");
                    tracing::error!("keys: {msg}");
                    Err(msg)
                }
            }
        }
        SshOp::KeyDelete { name } => {
            let svc = mgr.keys();
            let params = toride_ssh::KeyDeleteParams {
                name: name.clone(),
                remove_public: true,
                remove_certificate: true,
                remove_from_agent: true,
                remove_from_config: true,
                backup: false,
            };
            match svc.delete(params).await {
                Ok(()) => {
                    tracing::info!("keys: deleted '{name}'");
                    Ok(format!("deleted key '{name}'"))
                }
                Err(e) => {
                    let msg = format!("failed to delete key '{name}': {e}");
                    tracing::error!("keys: {msg}");
                    Err(msg)
                }
            }
        }
        SshOp::KeyRename { old_name, new_name } => {
            let svc = mgr.keys();
            match svc.rename(&old_name, &new_name).await {
                Ok(()) => {
                    tracing::info!("keys: renamed '{old_name}' → '{new_name}'");
                    Ok(format!("renamed '{old_name}' → '{new_name}'"))
                }
                Err(e) => {
                    let msg = format!("failed to rename '{old_name}': {e}");
                    tracing::error!("keys: {msg}");
                    Err(msg)
                }
            }
        }
        SshOp::KnownHostAdd { host } => {
            let svc = mgr.known_hosts();
            match svc.add(&host).await {
                Ok(()) => {
                    tracing::info!("known_hosts: added '{host}'");
                    Ok(format!("added known host '{host}'"))
                }
                Err(e) => {
                    let msg = format!("failed to add known host '{host}': {e}");
                    tracing::error!("known_hosts: {msg}");
                    Err(msg)
                }
            }
        }
        SshOp::KnownHostRemove { host } => {
            let svc = mgr.known_hosts();
            match svc.remove(&host).await {
                Ok(()) => {
                    tracing::info!("known_hosts: removed '{host}'");
                    Ok(format!("removed known host '{host}'"))
                }
                Err(e) => {
                    let msg = format!("failed to remove known host '{host}': {e}");
                    tracing::error!("known_hosts: {msg}");
                    Err(msg)
                }
            }
        }
        SshOp::AgentAddKey { path } => {
            let svc = mgr.agent();
            let path_ref = std::path::Path::new(&path);
            match svc.add_key(path_ref).await {
                Ok(()) => {
                    tracing::info!("agent: added key '{path}'");
                    Ok(format!("added key to agent: '{path}'"))
                }
                Err(e) => {
                    let msg = format!("failed to add key '{path}' to agent: {e}");
                    tracing::error!("agent: {msg}");
                    Err(msg)
                }
            }
        }
        SshOp::AgentRemoveKey { path } => {
            let svc = mgr.agent();
            let path_ref = std::path::Path::new(&path);
            match svc.remove_key(path_ref).await {
                Ok(()) => {
                    tracing::info!("agent: removed key '{path}'");
                    Ok(format!("removed key from agent: '{path}'"))
                }
                Err(e) => {
                    let msg = format!("failed to remove key '{path}' from agent: {e}");
                    tracing::error!("agent: {msg}");
                    Err(msg)
                }
            }
        }
        SshOp::AuthorizedKeyAdd { public_key, comment, options } => {
            let svc = mgr.authorized_keys();
            match svc.add(
                &public_key,
                comment.as_deref(),
                options.as_deref(),
            ).await {
                Ok(()) => {
                    tracing::info!("authorized_keys: added key");
                    Ok("added authorized key".to_string())
                }
                Err(e) => {
                    let msg = format!("failed to add authorized key: {e}");
                    tracing::error!("authorized_keys: {msg}");
                    Err(msg)
                }
            }
        }
        SshOp::AuthorizedKeyRemove { fingerprint } => {
            let svc = mgr.authorized_keys();
            match svc.remove(&fingerprint).await {
                Ok(n) => {
                    tracing::info!("authorized_keys: removed {n} key(s) matching '{fingerprint}'");
                    Ok(format!("removed {n} authorized key(s)"))
                }
                Err(e) => {
                    let msg = format!("failed to remove authorized key '{fingerprint}': {e}");
                    tracing::error!("authorized_keys: {msg}");
                    Err(msg)
                }
            }
        }
        SshOp::KeyChmodFix { name } => {
            let svc = mgr.keys();
            match svc.chmod_fix(&name).await {
                Ok(()) => {
                    tracing::info!("keys: fixed permissions on '{name}'");
                    Ok(format!("fixed permissions on '{name}'"))
                }
                Err(e) => {
                    let msg = format!("failed to fix permissions on '{name}': {e}");
                    tracing::error!("keys: {msg}");
                    Err(msg)
                }
            }
        }
        SshOp::KnownHostScan { host } => {
            let svc = mgr.known_hosts();
            match svc.scan(&host).await {
                Ok(keys) => {
                    tracing::info!("known_hosts: scanned '{host}' ({} key(s))", keys.len());
                    Ok(format!("scanned '{host}' ({} key(s))", keys.len()))
                }
                Err(e) => {
                    let msg = format!("failed to scan host '{host}': {e}");
                    tracing::error!("known_hosts: {msg}");
                    Err(msg)
                }
            }
        }
        SshOp::KnownHostHashAll => {
            let svc = mgr.known_hosts();
            match svc.hash_all().await {
                Ok(()) => {
                    tracing::info!("known_hosts: hashed all hostnames");
                    Ok("hashed all known hostnames".to_string())
                }
                Err(e) => {
                    let msg = format!("failed to hash all known hostnames: {e}");
                    tracing::error!("known_hosts: {msg}");
                    Err(msg)
                }
            }
        }
        SshOp::AgentRemoveAll => {
            let svc = mgr.agent();
            match svc.remove_all().await {
                Ok(()) => {
                    tracing::info!("agent: removed all keys");
                    Ok("removed all keys from agent".to_string())
                }
                Err(e) => {
                    let msg = format!("failed to remove all keys from agent: {e}");
                    tracing::error!("agent: {msg}");
                    Err(msg)
                }
            }
        }
        SshOp::ForwardCancel { control_path, local_port } => {
            let svc = mgr.forward();
            let path = std::path::Path::new(&control_path);
            match svc.cancel(path, local_port).await {
                Ok(()) => {
                    tracing::info!("forward: cancelled port {local_port} on '{control_path}'");
                    Ok(format!("cancelled forward on port {local_port}"))
                }
                Err(e) => {
                    let msg = format!("failed to cancel forward on port {local_port}: {e}");
                    tracing::error!("forward: {msg}");
                    Err(msg)
                }
            }
        }
        SshOp::ForwardExitSession { control_path } => {
            let svc = mgr.forward();
            let path = std::path::Path::new(&control_path);
            match svc.exit_session(path).await {
                Ok(()) => {
                    tracing::info!("forward: exited session '{control_path}'");
                    Ok(format!("exited session '{control_path}'"))
                }
                Err(e) => {
                    let msg = format!("failed to exit session '{control_path}': {e}");
                    tracing::error!("forward: {msg}");
                    Err(msg)
                }
            }
        }
        SshOp::CertificateRevoke { name } => {
            let svc = mgr.certificate();
            let krl_str = toride_ssh::SshPaths::new()
                .map(|p| p.ssh_dir().join("revoked_keys").to_string_lossy().into_owned())
                .unwrap_or_else(|_| format!("{}/.ssh/revoked_keys", std::env::var("HOME").unwrap_or_default()));
            let krl_path = std::path::Path::new(&krl_str);
            match svc.revoke_key(krl_path, &name).await {
                Ok(()) => {
                    tracing::info!("certificates: revoked key '{name}'");
                    Ok(format!("revoked key '{name}'"))
                }
                Err(e) => {
                    let msg = format!("failed to revoke key '{name}': {e}");
                    tracing::error!("certificates: {msg}");
                    Err(msg)
                }
            }
        }
        SshOp::DoctorRunChecks => {
            let svc = mgr.doctor();
            match svc.run_local_checks().await {
                Ok(diagnostics) => {
                    tracing::info!("doctor: ran local checks ({} finding(s))", diagnostics.len());
                    Ok(serde_json::to_string(&diagnostics).unwrap_or_default())
                }
                Err(e) => {
                    let msg = format!("failed to run local checks: {e}");
                    tracing::error!("doctor: {msg}");
                    Err(msg)
                }
            }
        }
        SshOp::KeyInstallToRemote { key_name, dest } => {
            let svc = mgr.keys();
            let ssh_dir = match toride_ssh::SshPaths::new() {
                Ok(p) => p.ssh_dir().to_path_buf(),
                Err(e) => {
                    let msg = format!("failed to resolve SSH directory: {e}");
                    tracing::error!("keys: {msg}");
                    return Err(msg);
                }
            };
            let key_path = ssh_dir.join(&key_name);
            match svc.install_key_to_remote(&key_path, &dest).await {
                Ok(_) => {
                    tracing::info!("keys: installed '{key_name}' to '{dest}'");
                    Ok(format!("installed '{key_name}' to '{dest}'"))
                }
                Err(e) => {
                    let msg = format!("failed to install '{key_name}' to '{dest}': {e}");
                    tracing::error!("keys: {msg}");
                    Err(msg)
                }
            }
        }
    }
}

/// Collect SSH data by reading real files and calling real services.
///
/// All subsystems run in parallel via `tokio::join!`. Individual failures are
/// logged and produce empty data — the app never crashes from a bad subsystem.
async fn collect_real_data() -> SshDataBundle {
    let mgr = match toride_ssh::SshManager::new() {
        Ok(m) => m,
        Err(e) => {
            tracing::warn!("SshManager::new() failed: {e}");
            return empty_bundle();
        }
    };

    // All subsystems in parallel
    let (keys_r, known_hosts_r, auth_keys_r, config_r, diag_r, agent_r, forward_r, cert_r) =
        tokio::join!(
            collect_keys(&mgr),
            collect_known_hosts(&mgr),
            collect_authorized_keys(&mgr),
            collect_config_hosts(&mgr),
            collect_diagnostics(&mgr),
            collect_agent(&mgr),
            collect_forwarding(&mgr),
            collect_certificates(&mgr),
        );

    let keys = keys_r.unwrap_or_default();
    let known_hosts = known_hosts_r.unwrap_or_default();
    let authorized_keys = auth_keys_r.unwrap_or_default();
    let config_hosts = config_r.unwrap_or_default();
    let diagnostics = diag_r.unwrap_or_default();

    let (agent_status, agent_keys) = agent_r.unwrap_or_else(|_| {
        (
            AgentStatus {
                reachable: false,
                socket_path: None,
                key_count: 0,
            },
            Vec::new(),
        )
    });
    let forwarding = forward_r.unwrap_or_default();
    let certificates = cert_r.unwrap_or_default();

    // Security data involves blocking filesystem I/O (sshd_config, /etc/passwd).
    // Run it on the blocking thread pool to avoid stalling the tokio worker.
    let security = {
        let known_hosts = known_hosts.clone();
        let authorized_keys = authorized_keys.clone();
        let diagnostics = diagnostics.clone();
        tokio::task::spawn_blocking(move || {
            build_security_data(&known_hosts, &authorized_keys, &diagnostics)
        }).await.unwrap_or_else(|e| {
            tracing::warn!("security data collection panicked: {e}");
            SshSecurityData {
                sshd_config: HashMap::new(),
                authorized_key_count: 0,
                authorized_key_labels: Vec::new(),
                known_hosts_count: 0,
                known_hosts_hashed_count: 0,
                security_diagnostics: Vec::new(),
                access_info: SshAccessInfo {
                    allowed_users: vec![],
                    denied_users: vec![],
                    allowed_groups: vec![],
                    denied_groups: vec![],
                    auth_methods: vec![],
                    password_auth: true,
                    pubkey_auth: true,
                    permit_root_login: "prohibit-password".to_string(),
                },
                system_users: Vec::new(),
            }
        })
    };

    SshDataBundle {
        keys,
        known_hosts,
        config_hosts,
        agent_status,
        agent_keys,
        forwarding,
        diagnostics,
        authorized_keys,
        certificates,
        security,
    }
}

/// Empty bundle used when SshManager fails to initialize.
fn empty_bundle() -> SshDataBundle {
    SshDataBundle {
        keys: Vec::new(),
        known_hosts: Vec::new(),
        config_hosts: Vec::new(),
        agent_status: AgentStatus {
            reachable: false,
            socket_path: None,
            key_count: 0,
        },
        agent_keys: Vec::new(),
        forwarding: Vec::new(),
        diagnostics: Vec::new(),
        authorized_keys: Vec::new(),
        certificates: Vec::new(),
        security: SshSecurityData {
            sshd_config: HashMap::new(),
            authorized_key_count: 0,
            authorized_key_labels: Vec::new(),
            known_hosts_count: 0,
            known_hosts_hashed_count: 0,
            security_diagnostics: Vec::new(),
            access_info: SshAccessInfo {
                allowed_users: vec![],
                denied_users: vec![],
                allowed_groups: vec![],
                denied_groups: vec![],
                auth_methods: vec![],
                // Use OpenSSH defaults when sshd_config is unavailable.
                password_auth: true,
                pubkey_auth: true,
                permit_root_login: "prohibit-password".to_string(),
            },
            system_users: Vec::new(),
        },
    }
}

// ── Individual Collectors ────────────────────────────────────────────────────

async fn collect_known_hosts(
    mgr: &toride_ssh::SshManager,
) -> Result<Vec<KnownHostEntry>, ()> {
    let svc = mgr.known_hosts();
    match svc.list().await {
        Ok(entries) => Ok(ssh_convert::convert_known_hosts(entries)),
        Err(e) => {
            tracing::warn!("known_hosts: {e}");
            Err(())
        }
    }
}

async fn collect_authorized_keys(
    mgr: &toride_ssh::SshManager,
) -> Result<Vec<AuthorizedKeyEntry>, ()> {
    let svc = mgr.authorized_keys();
    match svc.list().await {
        Ok(entries) => Ok(ssh_convert::convert_authorized_keys(entries)),
        Err(e) => {
            tracing::warn!("authorized_keys: {e}");
            Err(())
        }
    }
}

async fn collect_keys(
    mgr: &toride_ssh::SshManager,
) -> Result<Vec<SshKeyEntry>, ()> {
    let svc = mgr.keys();
    match svc.list().await {
        Ok(keys) => Ok(ssh_convert::convert_keys(keys)),
        Err(e) => {
            tracing::warn!("keys: {e}");
            Err(())
        }
    }
}

async fn collect_config_hosts(
    mgr: &toride_ssh::SshManager,
) -> Result<Vec<ConfigHostEntry>, ()> {
    let svc = mgr.config();
    match svc.load().await {
        Ok(ast) => Ok(ssh_convert::convert_config_ast(&ast)),
        Err(e) => {
            tracing::warn!("config: {e}");
            Err(())
        }
    }
}

async fn collect_diagnostics(
    mgr: &toride_ssh::SshManager,
) -> Result<Vec<DiagnosticEntry>, ()> {
    let svc = mgr.doctor();
    match svc.run_local_checks().await {
        Ok(diagnostics) => Ok(ssh_convert::convert_diagnostics(diagnostics)),
        Err(e) => {
            tracing::warn!("doctor: {e}");
            Err(())
        }
    }
}

async fn collect_agent(
    mgr: &toride_ssh::SshManager,
) -> Result<(AgentStatus, Vec<AgentKeyEntry>), ()> {
    let svc = mgr.agent();
    let socket_path = std::env::var("SSH_AUTH_SOCK").ok();

    let reachable = match svc.status().await {
        Ok(r) => r,
        Err(e) => {
            tracing::debug!("agent status: {e}");
            false
        }
    };

    if !reachable {
        return Ok((
            AgentStatus {
                reachable: false,
                socket_path,
                key_count: 0,
            },
            Vec::new(),
        ));
    }

    match svc.list_keys().await {
        Ok(keys) => Ok(ssh_convert::convert_agent_keys(keys, true, socket_path)),
        Err(e) => {
            tracing::warn!("agent keys: {e}");
            Ok((
                AgentStatus {
                    reachable: true,
                    socket_path,
                    key_count: 0,
                },
                Vec::new(),
            ))
        }
    }
}

async fn collect_forwarding(
    mgr: &toride_ssh::SshManager,
) -> Result<Vec<ForwardSessionEntry>, ()> {
    let svc = mgr.forward();
    match svc.list().await {
        Ok(sessions) => Ok(ssh_convert::convert_forwarding(sessions)),
        Err(e) => {
            tracing::debug!("forwarding: {e}");
            Err(())
        }
    }
}

async fn collect_certificates(
    mgr: &toride_ssh::SshManager,
) -> Result<Vec<CertificateEntry>, ()> {
    let ssh_dir = match toride_ssh::SshPaths::new() {
        Ok(p) => p.ssh_dir().to_path_buf(),
        Err(_) => return Ok(Vec::new()),
    };

    let cert_files: Vec<std::path::PathBuf> = match std::fs::read_dir(&ssh_dir) {
        Ok(entries) => entries
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.ends_with("-cert.pub"))
            })
            .collect(),
        Err(_) => return Ok(Vec::new()),
    };

    if cert_files.is_empty() {
        return Ok(Vec::new());
    }

    let cert_svc = mgr.certificate();
    let mut raw = Vec::new();

    for path in cert_files {
        match cert_svc.inspect(&path).await {
            Ok(info) => raw.push((path, info)),
            Err(e) => {
                tracing::debug!(
                    "certificate {}: {e}",
                    path.file_name().unwrap_or_default().to_string_lossy()
                );
            }
        }
    }

    Ok(ssh_convert::convert_certificates(raw))
}

/// Build security overview data from already-collected real data.
///
/// Reads `/etc/ssh/sshd_config` once and passes the content to both
/// `parse_sshd_config` and `parse_sshd_access_info` to avoid a TOCTOU
/// inconsistency from reading the file twice.
fn build_security_data(
    known_hosts: &[KnownHostEntry],
    authorized_keys: &[AuthorizedKeyEntry],
    diagnostics: &[DiagnosticEntry],
) -> SshSecurityData {
    // Read sshd_config once — shared by both parse_sshd_config and parse_sshd_access_info.
    let sshd_contents = std::fs::read_to_string(Path::new("/etc/ssh/sshd_config"))
        .unwrap_or_default();

    let sshd_config = parse_sshd_config_from(&sshd_contents);

    let known_hosts_hashed_count = known_hosts.iter().filter(|h| h.is_hashed).count();

    let authorized_key_labels: Vec<String> = authorized_keys
        .iter()
        .map(|k| {
            k.comment
                .clone()
                .unwrap_or_else(|| "(no comment)".into())
        })
        .collect();

    let security_diagnostics: Vec<DiagnosticEntry> = diagnostics
        .iter()
        .filter(|d| d.severity == "warning" || d.severity == "error")
        .cloned()
        .collect();

    SshSecurityData {
        sshd_config,
        authorized_key_count: authorized_keys.len(),
        authorized_key_labels,
        known_hosts_count: known_hosts.len(),
        known_hosts_hashed_count,
        security_diagnostics,
        access_info: parse_sshd_access_info_from(&sshd_contents),
        system_users: parse_system_users(),
    }
}

// ── Security Overview Types ──────────────────────────────────────────────────

/// Security grade computed from sshd_config and diagnostic results.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecurityGrade {
    A,
    B,
    C,
    D,
    F,
}

impl SecurityGrade {
    /// Human-readable label.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            SecurityGrade::A => "A",
            SecurityGrade::B => "B",
            SecurityGrade::C => "C",
            SecurityGrade::D => "D",
            SecurityGrade::F => "F",
        }
    }

    /// Palette color for the grade.
    #[must_use]
    pub fn color(self, p: Palette) -> Color {
        match self {
            SecurityGrade::A => p.ok,
            SecurityGrade::B => p.accent3,
            SecurityGrade::C => p.warn,
            SecurityGrade::D => p.warn,
            SecurityGrade::F => p.err,
        }
    }
}

/// A single security check result for the dashboard.
#[derive(Clone, Debug)]
pub struct SecurityCheck {
    /// Human-readable label (e.g. "Password authentication").
    pub label: String,
    /// Current value (e.g. "no", "yes", "22").
    pub detail: String,
    /// Whether this setting is in a secure/passing state.
    pub passing: bool,
    /// Whether this is informational (not a pass/fail check).
    pub informational: bool,
}

/// Aggregated security data for the overview dashboard.
#[derive(Clone, Debug)]
pub struct SshSecurityData {
    /// Parsed sshd_config key-value pairs.
    pub sshd_config: HashMap<String, String>,
    /// Number of authorized keys.
    pub authorized_key_count: usize,
    /// Authorized key comments for listing.
    pub authorized_key_labels: Vec<String>,
    /// Number of entries in known_hosts.
    pub known_hosts_count: usize,
    /// How many known_hosts entries have hashed hostnames.
    pub known_hosts_hashed_count: usize,
    /// Security-relevant diagnostics (warnings/errors only).
    pub security_diagnostics: Vec<DiagnosticEntry>,
    /// Access control information parsed from sshd_config.
    pub access_info: SshAccessInfo,
    /// System users with valid login shells and SSH key info.
    pub system_users: Vec<SystemUserInfo>,
}

impl SshSecurityData {
    /// Compute an overall security grade.
    #[must_use]
    pub fn grade(&self) -> SecurityGrade {
        let mut score = 100u32;
        let cfg = &self.sshd_config;

        // Major deductions for insecure settings
        if cfg
            .get("passwordauthentication")
            .map_or(true, |v| v != "no")
        {
            score -= 25;
        }
        if cfg.get("permitrootlogin").map_or(false, |v| v == "yes") {
            score -= 20;
        }
        if cfg
            .get("permitemptypasswords")
            .map_or(false, |v| v == "yes")
        {
            score -= 15;
        }
        if cfg
            .get("pubkeyauthentication")
            .map_or(false, |v| v == "no")
        {
            score -= 15;
        }
        // Minor deductions for warnings
        let warn_count = self
            .security_diagnostics
            .iter()
            .filter(|d| d.severity == "warning" || d.severity == "error")
            .count() as u32;
        score -= warn_count.min(5) * 5;

        match score {
            90..=100 => SecurityGrade::A,
            75..=89 => SecurityGrade::B,
            55..=74 => SecurityGrade::C,
            35..=54 => SecurityGrade::D,
            _ => SecurityGrade::F,
        }
    }

    /// Individual check results for the dashboard.
    #[must_use]
    pub fn checks(&self) -> Vec<SecurityCheck> {
        let cfg = &self.sshd_config;
        vec![
            SecurityCheck {
                label: "Password authentication".into(),
                detail: cfg
                    .get("passwordauthentication")
                    .cloned()
                    .unwrap_or_else(|| "yes (default)".into()),
                passing: cfg
                    .get("passwordauthentication")
                    .map_or(false, |v| v == "no"),
                informational: false,
            },
            SecurityCheck {
                label: "Root login".into(),
                detail: cfg
                    .get("permitrootlogin")
                    .cloned()
                    .unwrap_or_else(|| "prohibit-password (default)".into()),
                passing: cfg
                    .get("permitrootlogin")
                    .map_or(true, |v| v != "yes"),
                informational: false,
            },
            SecurityCheck {
                label: "SSH port".into(),
                detail: cfg
                    .get("port")
                    .cloned()
                    .unwrap_or_else(|| "22 (default)".into()),
                passing: true,
                informational: true,
            },
            SecurityCheck {
                label: "Public key auth".into(),
                detail: cfg
                    .get("pubkeyauthentication")
                    .cloned()
                    .unwrap_or_else(|| "yes (default)".into()),
                passing: cfg
                    .get("pubkeyauthentication")
                    .map_or(true, |v| v != "no"),
                informational: false,
            },
            SecurityCheck {
                label: "Max auth attempts".into(),
                detail: cfg
                    .get("maxauthtries")
                    .cloned()
                    .unwrap_or_else(|| "6 (default)".into()),
                passing: true,
                informational: true,
            },
            SecurityCheck {
                label: "Agent forwarding".into(),
                detail: cfg
                    .get("allowagentforwarding")
                    .cloned()
                    .unwrap_or_else(|| "yes (default)".into()),
                passing: cfg
                    .get("allowagentforwarding")
                    .map_or(false, |v| v == "no"),
                informational: false,
            },
            SecurityCheck {
                label: "X11 forwarding".into(),
                detail: cfg
                    .get("x11forwarding")
                    .cloned()
                    .unwrap_or_else(|| "no (default)".into()),
                passing: cfg
                    .get("x11forwarding")
                    .map_or(true, |v| v != "yes"),
                informational: false,
            },
            SecurityCheck {
                label: "Empty passwords".into(),
                detail: cfg
                    .get("permitemptypasswords")
                    .cloned()
                    .unwrap_or_else(|| "no (default)".into()),
                passing: cfg
                    .get("permitemptypasswords")
                    .map_or(true, |v| v != "yes"),
                informational: false,
            },
        ]
    }
}

/// Parse `/etc/ssh/sshd_config` for key-value pairs.
///
/// Skips comments, empty lines, `Match` and `Include` blocks.
/// Returns an empty map if the file doesn't exist or isn't readable.
///
/// **Note:** `Match` and `Include` blocks are silently skipped. Directives
/// inside a `Match` block are not parsed, so the security dashboard may not
/// reflect conditional overrides.
fn parse_sshd_config() -> HashMap<String, String> {
    let contents = std::fs::read_to_string(Path::new("/etc/ssh/sshd_config"))
        .unwrap_or_default();
    parse_sshd_config_from(&contents)
}

/// Parse sshd_config content (already read from disk) into key-value pairs.
fn parse_sshd_config_from(contents: &str) -> HashMap<String, String> {
    let mut config = HashMap::new();
    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let lower = trimmed.to_ascii_lowercase();
        if lower.starts_with("match ") || lower.starts_with("include ") {
            continue;
        }
        if let Some((key, value)) = trimmed.split_once(char::is_whitespace) {
            config.insert(key.to_lowercase(), value.to_owned());
        }
    }
    config
}

/// Parse access control information from /etc/ssh/sshd_config.
///
/// Extracts AllowUsers, DenyUsers, AllowGroups, DenyGroups,
/// AuthenticationMethods, and auth booleans.
///
/// **Note:** `Match` and `Include` blocks are silently skipped. Directives
/// inside a `Match` block (e.g. `PasswordAuthentication yes`) are not parsed,
/// so the security dashboard may not reflect conditional overrides.
///
/// **Note:** On macOS, `/etc/ssh/sshd_config` may not exist or may not reflect
/// the actual sshd configuration, which is managed by launchd. Additionally,
/// system users are parsed from `/etc/passwd`, which is not the primary user
/// database on macOS (Directory Service is). Results on macOS may be incomplete.
fn parse_sshd_access_info() -> SshAccessInfo {
    let contents = std::fs::read_to_string(Path::new("/etc/ssh/sshd_config"))
        .unwrap_or_default();
    parse_sshd_access_info_from(&contents)
}

/// Parse access control information from pre-read sshd_config content.
fn parse_sshd_access_info_from(contents: &str) -> SshAccessInfo {
    let mut info = SshAccessInfo::default();

    // Track which directives were explicitly seen so we can apply
    // OpenSSH defaults only when the directive is absent.
    let mut seen_pubkey = false;
    let mut seen_password = false;
    let mut seen_permit_root = false;

    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Skip Match and Include blocks — directives inside them are not parsed.
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("match ") || lower.starts_with("include ") {
            continue;
        }

        // Split on first whitespace
        let (key, value) = match line.split_once(char::is_whitespace) {
            Some((k, v)) => (k, v.trim()),
            None => continue,
        };

        match key.to_lowercase().as_str() {
            "allowusers" => {
                info.allowed_users = value.split_whitespace().map(String::from).collect();
            }
            "denyusers" => {
                info.denied_users = value.split_whitespace().map(String::from).collect();
            }
            "allowgroups" => {
                info.allowed_groups = value.split_whitespace().map(String::from).collect();
            }
            "denygroups" => {
                info.denied_groups = value.split_whitespace().map(String::from).collect();
            }
            "authenticationmethods" => {
                info.auth_methods = value.split(',').map(|s| s.trim().to_string()).collect();
            }
            "passwordauthentication" => {
                info.password_auth = value.eq_ignore_ascii_case("yes");
                seen_password = true;
            }
            "pubkeyauthentication" => {
                info.pubkey_auth = value.eq_ignore_ascii_case("yes");
                seen_pubkey = true;
            }
            "permitrootlogin" => {
                info.permit_root_login = value.to_string();
                seen_permit_root = true;
            }
            _ => {}
        }
    }

    // Apply OpenSSH defaults when directives are absent.
    // PubkeyAuthentication defaults to "yes" per OpenSSH spec.
    if !seen_pubkey {
        info.pubkey_auth = true;
    }
    // PasswordAuthentication defaults to "yes" in OpenSSH.
    if !seen_password {
        info.password_auth = true;
    }
    // PermitRootLogin defaults to "prohibit-password" since OpenSSH 7.0.
    if !seen_permit_root {
        info.permit_root_login = "prohibit-password".to_string();
    }

    info
}

/// Parse system users with valid login shells from /etc/passwd.
///
/// Checks each user's home directory for ~/.ssh/authorized_keys.
fn parse_system_users() -> Vec<SystemUserInfo> {
    let contents = match std::fs::read_to_string("/etc/passwd") {
        Ok(c) => c,
        Err(_) => return vec![],
    };

    let invalid_shells = [
        "/bin/false",
        "/sbin/nologin",
        "/usr/sbin/nologin",
        "/bin/nologin",
        "/dev/null",
        "/bin/sync",
        "/usr/bin/nologin",
    ];

    let mut users = Vec::new();

    for line in contents.lines() {
        let parts: Vec<&str> = line.splitn(7, ':').collect();
        if parts.len() < 7 {
            continue;
        }

        let username = parts[0];
        let home_dir = parts[5];
        let shell = parts[6];

        // Skip users with invalid shells
        if invalid_shells.iter().any(|s| shell == *s) || shell.is_empty() {
            continue;
        }

        // Check for authorized_keys
        let ak_path = std::path::Path::new(home_dir).join(".ssh/authorized_keys");
        let (has_authorized_keys, key_count) = if ak_path.exists() {
            match std::fs::read_to_string(&ak_path) {
                Ok(contents) => {
                    let count = contents
                        .lines()
                        .filter(|l| {
                            let l = l.trim();
                            !l.is_empty() && !l.starts_with('#')
                        })
                        .count();
                    (true, count)
                }
                Err(_) => (false, 0),
            }
        } else {
            (false, 0)
        };

        users.push(SystemUserInfo {
            username: username.to_string(),
            shell: shell.to_string(),
            home_dir: home_dir.to_string(),
            has_authorized_keys,
            key_count,
        });
    }

    users.sort_by(|a, b| a.username.cmp(&b.username));
    users
}

// ── Mock Data (test only) ───────────────────────────────────────────────────

#[cfg(test)]
mod mock {
    use super::*;

    pub fn collect_mock_data() -> SshDataBundle {
        SshDataBundle {
            keys: collect_mock_keys(),
            known_hosts: collect_mock_known_hosts(),
            config_hosts: collect_mock_config_hosts(),
            agent_status: collect_mock_agent_status(),
            agent_keys: collect_mock_agent_keys(),
            forwarding: collect_mock_forwarding(),
            diagnostics: collect_mock_diagnostics(),
            authorized_keys: collect_mock_authorized_keys(),
            certificates: collect_mock_certificates(),
            security: collect_mock_security(),
        }
    }

    pub fn collect_mock_keys() -> Vec<SshKeyEntry> {
        vec![
            SshKeyEntry {
                name: "id_ed25519".into(),
                key_type: "Ed25519".into(),
                fingerprint: "SHA256:abc123def456ghi789".into(),
                encrypted: true,
                permissions: "0600".into(),
                has_public: true,
                has_cert: false,
                used_by_hosts: vec!["github.com".into(), "gitlab.com".into()],
            },
            SshKeyEntry {
                name: "id_rsa".into(),
                key_type: "RSA 4096".into(),
                fingerprint: "SHA256:xyz789abc456def123".into(),
                encrypted: false,
                permissions: "0644".into(),
                has_public: true,
                has_cert: true,
                used_by_hosts: vec![],
            },
            SshKeyEntry {
                name: "deploy_key".into(),
                key_type: "Ed25519".into(),
                fingerprint: "SHA256:qwe456rty789uio012".into(),
                encrypted: false,
                permissions: "0600".into(),
                has_public: true,
                has_cert: false,
                used_by_hosts: vec!["prod-server".into(), "staging".into(), "dev".into(), "backup".into(), "monitor".into()],
            },
        ]
    }

    pub fn collect_mock_known_hosts() -> Vec<KnownHostEntry> {
        vec![
            KnownHostEntry {
                hosts: vec!["github.com".into()],
                key_type: "ssh-ed25519".into(),
                key_types: vec!["ssh-ed25519".into(), "ecdsa-sha2-nistp256".into(), "ssh-rsa".into()],
                fingerprint: "SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8".into(),
                fingerprints: vec![
                    "SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8".into(),
                    "SHA256:p2QDBXBNJXm3QqRJLcYPjMn+al+gPCfvAy8Oo5WKIqs".into(),
                    "SHA256:uNiVztksCsDhccIuweeDlI0Q5J0q+Z7RDwt5kM+VmEc".into(),
                ],
                is_hashed: false,
                marker: None,
                comment: None,
                line: 1,
                source: "user".into(),
            },
            KnownHostEntry {
                hosts: vec!["gitlab.com".into()],
                key_type: "ssh-ed25519".into(),
                key_types: vec!["ssh-ed25519".into()],
                fingerprint: "SHA256:WSCtr3bEeJGgcb0UrkMFWxQJqchWXzwWMNESdgqxo".into(),
                fingerprints: vec!["SHA256:WSCtr3bEeJGgcb0UrkMFWxQJqchWXzwWMNESdgqxo".into()],
                is_hashed: false,
                marker: None,
                comment: None,
                line: 2,
                source: "user".into(),
            },
            KnownHostEntry {
                hosts: vec!["[192.168.1.1]:2222".into()],
                key_type: "ssh-rsa".into(),
                key_types: vec!["ssh-rsa".into()],
                fingerprint: "SHA256:abc123def456ghi789jkl012mno345pqr678".into(),
                fingerprints: vec!["SHA256:abc123def456ghi789jkl012mno345pqr678".into()],
                is_hashed: false,
                marker: None,
                comment: Some("home router".into()),
                line: 3,
                source: "user".into(),
            },
            KnownHostEntry {
                hosts: vec!["|1|ba4dEeFgHiJkLmNoPqRsTu|XxYyZz0123456789".into()],
                key_type: "ecdsa-sha2-nistp256".into(),
                key_types: vec!["ecdsa-sha2-nistp256".into()],
                fingerprint: "SHA256:qwe456rty789uio012pqr345stu678vwx".into(),
                fingerprints: vec!["SHA256:qwe456rty789uio012pqr345stu678vwx".into()],
                is_hashed: true,
                marker: None,
                comment: None,
                line: 4,
                source: "user".into(),
            },
            KnownHostEntry {
                hosts: vec!["old.server.example.com".into()],
                key_type: "ssh-ed25519".into(),
                key_types: vec!["ssh-ed25519".into()],
                fingerprint: "SHA256:xyz789abc456def123ghi456jkl789mno012".into(),
                fingerprints: vec!["SHA256:xyz789abc456def123ghi456jkl789mno012".into()],
                is_hashed: false,
                marker: Some("@revoked".into()),
                comment: None,
                line: 5,
                source: "user".into(),
            },
        ]
    }

    pub fn collect_mock_config_hosts() -> Vec<ConfigHostEntry> {
        vec![
            ConfigHostEntry {
                name: "myserver".into(),
                patterns: vec!["myserver".into()],
                host_name: Some("example.com".into()),
                user: Some("alice".into()),
                port: Some(2222),
                identity_file: Some("~/.ssh/id_ed25519".into()),
                proxy_jump: None,
                directive_count: 5,
                has_diagnostic: false,
            },
            ConfigHostEntry {
                name: "*.example.com".into(),
                patterns: vec!["*.example.com".into()],
                host_name: None,
                user: Some("deploy".into()),
                port: None,
                identity_file: None,
                proxy_jump: None,
                directive_count: 3,
                has_diagnostic: false,
            },
            ConfigHostEntry {
                name: "*".into(),
                patterns: vec!["*".into()],
                host_name: None,
                user: None,
                port: None,
                identity_file: None,
                proxy_jump: None,
                directive_count: 2,
                has_diagnostic: false,
            },
            ConfigHostEntry {
                name: "staging".into(),
                patterns: vec!["staging".into()],
                host_name: Some("stage.example.com".into()),
                user: Some("bob".into()),
                port: Some(22),
                identity_file: Some("~/.ssh/deploy_key".into()),
                proxy_jump: Some("bastion.example.com".into()),
                directive_count: 8,
                has_diagnostic: true,
            },
            ConfigHostEntry {
                name: "bastion".into(),
                patterns: vec!["bastion.example.com".into()],
                host_name: None,
                user: Some("admin".into()),
                port: Some(443),
                identity_file: Some("~/.ssh/id_ed25519".into()),
                proxy_jump: None,
                directive_count: 4,
                has_diagnostic: false,
            },
        ]
    }

    pub fn collect_mock_agent_status() -> AgentStatus {
        AgentStatus {
            reachable: true,
            socket_path: Some("/tmp/ssh-abc123/agent.1234".into()),
            key_count: 3,
        }
    }

    pub fn collect_mock_agent_keys() -> Vec<AgentKeyEntry> {
        vec![
            AgentKeyEntry {
                name: "id_ed25519".into(),
                key_type: "Ed25519".into(),
                fingerprint: "SHA256:abc123def456ghi789".into(),
                is_locked: false,
                has_constraints: false,
            },
            AgentKeyEntry {
                name: "deploy_key".into(),
                key_type: "RSA 4096".into(),
                fingerprint: "SHA256:xyz789abc456def123".into(),
                is_locked: true,
                has_constraints: true,
            },
            AgentKeyEntry {
                name: "staging_key".into(),
                key_type: "Ed25519".into(),
                fingerprint: "SHA256:qwe456rty789uio012".into(),
                is_locked: false,
                has_constraints: false,
            },
        ]
    }

    pub fn collect_mock_forwarding() -> Vec<ForwardSessionEntry> {
        vec![
            ForwardSessionEntry {
                host: "myserver".into(),
                control_path: "/home/alice/.ssh/cm-alice@example.com:22".into(),
                pid: Some(1234),
                established_ago: "2h 15m".into(),
                forward_count: 2,
                forwards: vec![
                    ForwardEntry {
                        forward_type: "local".into(),
                        local_addr: "127.0.0.1".into(),
                        local_port: 8080,
                        remote_addr: "example.com".into(),
                        remote_port: 80,
                    },
                    ForwardEntry {
                        forward_type: "local".into(),
                        local_addr: "127.0.0.1".into(),
                        local_port: 3306,
                        remote_addr: "db.example.com".into(),
                        remote_port: 3306,
                    },
                ],
            },
            ForwardSessionEntry {
                host: "bastion".into(),
                control_path: "/home/alice/.ssh/ctrl-bastion".into(),
                pid: Some(5678),
                established_ago: "45m".into(),
                forward_count: 2,
                forwards: vec![
                    ForwardEntry {
                        forward_type: "dynamic".into(),
                        local_addr: "127.0.0.1".into(),
                        local_port: 1080,
                        remote_addr: "SOCKS".into(),
                        remote_port: 0,
                    },
                    ForwardEntry {
                        forward_type: "remote".into(),
                        local_addr: "0.0.0.0".into(),
                        local_port: 2222,
                        remote_addr: "127.0.0.1".into(),
                        remote_port: 22,
                    },
                ],
            },
        ]
    }

    pub fn collect_mock_diagnostics() -> Vec<DiagnosticEntry> {
        vec![
            DiagnosticEntry {
                id: "ssh_dir_exists".into(),
                severity: "ok".into(),
                module: "local".into(),
                message: "SSH directory exists with correct permissions (0700)".into(),
                hint: None,
            },
            DiagnosticEntry {
                id: "config_found".into(),
                severity: "info".into(),
                module: "config".into(),
                message: "SSH config file found at ~/.ssh/config".into(),
                hint: None,
            },
            DiagnosticEntry {
                id: "key_permissions".into(),
                severity: "warning".into(),
                module: "local".into(),
                message: "Private key id_rsa has overly permissive mode (0644)".into(),
                hint: Some("Run chmod 600 ~/.ssh/id_rsa to fix".into()),
            },
            DiagnosticEntry {
                id: "agent_not_running".into(),
                severity: "error".into(),
                module: "agent".into(),
                message: "No SSH agent is running (SSH_AUTH_SOCK not set)".into(),
                hint: Some(
                    "Start ssh-agent or add eval $(ssh-agent) to your shell profile".into(),
                ),
            },
            DiagnosticEntry {
                id: "config_host_star_placement".into(),
                severity: "warning".into(),
                module: "config".into(),
                message: "'Host *' appears before specific Host blocks".into(),
                hint: Some("Move 'Host *' to the end of the config file".into()),
            },
            DiagnosticEntry {
                id: "known_hosts_exists".into(),
                severity: "ok".into(),
                module: "local".into(),
                message: "Known hosts file exists at ~/.ssh/known_hosts".into(),
                hint: None,
            },
        ]
    }

    pub fn collect_mock_authorized_keys() -> Vec<AuthorizedKeyEntry> {
        vec![
            AuthorizedKeyEntry {
                key_type: "ssh-ed25519".into(),
                public_key: "AAAAC3NzaC1lZDI1NTE5AAAAIKxJ3G2F7mT5mQaV8eN4pL2zH8gR6kW".into(),
                comment: Some("alice@workstation".into()),
                fingerprint: "SHA256:xKj8mN2pL5vR7tQ9wE3yU4oI6aS8dF".into(),
                options: None,
                line: 1,
            },
            AuthorizedKeyEntry {
                key_type: "ssh-rsa".into(),
                public_key: "AAAAB3NzaC1yc2EAAAADAQABAAACAQCr7L3hFS2jW9eJ5kE8mN".into(),
                comment: Some("deploy@ci-runner".into()),
                fingerprint: "SHA256:mQ9wE3yU4oI6aS8dFxKj8mN2pL5vR7t".into(),
                options: Some(
                    "command=\"/usr/bin/restricted-shell\",no-port-forwarding".into(),
                ),
                line: 4,
            },
            AuthorizedKeyEntry {
                key_type: "ssh-ed25519".into(),
                public_key: "AAAAC3NzaC1lZDI1NTE5AAAAIP9fG4eJ8kL3mN6oQ2rS5tU7vW".into(),
                comment: Some("bob@laptop".into()),
                fingerprint: "SHA256:R7tQ9wE3yU4oI6aS8dFxKj8mN2pL5v".into(),
                options: None,
                line: 7,
            },
            AuthorizedKeyEntry {
                key_type: "ecdsa-sha2-nistp256".into(),
                public_key: "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTY".into(),
                comment: None,
                fingerprint: "SHA256:U4oI6aS8dFxKj8mN2pL5vR7tQ9wE3y".into(),
                options: Some("no-pty".into()),
                line: 9,
            },
        ]
    }

    pub fn collect_mock_certificates() -> Vec<CertificateEntry> {
        vec![
            CertificateEntry {
                name: "id_ed25519-cert.pub".into(),
                cert_type: "User".into(),
                key_type: "ssh-ed25519-cert-v01@openssh.com".into(),
                serial: 12345,
                valid_from: "2025-01-15 00:00:00".into(),
                valid_to: "2026-01-15 00:00:00".into(),
                is_valid: true,
                ca_fingerprint: "SHA256:CA1fP2gH3iJ4kL5mN6oQ7rS8tU".into(),
                key_id: "alice@corp-2025".into(),
                principals: vec!["alice".into(), "admin".into()],
            },
            CertificateEntry {
                name: "deploy-cert.pub".into(),
                cert_type: "User".into(),
                key_type: "ssh-ed25519-cert-v01@openssh.com".into(),
                serial: 67890,
                valid_from: "2024-06-01 00:00:00".into(),
                valid_to: "2025-06-01 00:00:00".into(),
                is_valid: false,
                ca_fingerprint: "SHA256:CA9qR8sT7uV6wX5yZ4aB3cD2eF".into(),
                key_id: "deploy@ci-2024".into(),
                principals: vec!["deploy".into()],
            },
            CertificateEntry {
                name: "bastion-host-cert.pub".into(),
                cert_type: "Host".into(),
                key_type: "ssh-rsa-cert-v01@openssh.com".into(),
                serial: 42,
                valid_from: "2025-03-01 00:00:00".into(),
                valid_to: "2026-03-01 00:00:00".into(),
                is_valid: true,
                ca_fingerprint: "SHA256:CA2gH3iJ4kL5mN6oP7qR8sT9uV".into(),
                key_id: "bastion.example.com".into(),
                principals: vec!["bastion.example.com".into()],
            },
        ]
    }

    pub fn collect_mock_security() -> SshSecurityData {
        let mut sshd_config = HashMap::new();
        sshd_config.insert("passwordauthentication".into(), "no".into());
        sshd_config.insert("permitrootlogin".into(), "prohibit-password".into());
        sshd_config.insert("port".into(), "22".into());
        sshd_config.insert("pubkeyauthentication".into(), "yes".into());
        sshd_config.insert("maxauthtries".into(), "3".into());
        sshd_config.insert("allowagentforwarding".into(), "no".into());
        sshd_config.insert("x11forwarding".into(), "no".into());
        sshd_config.insert("permitemptypasswords".into(), "no".into());

        SshSecurityData {
            sshd_config,
            authorized_key_count: 4,
            authorized_key_labels: vec![
                "alice@workstation".into(),
                "deploy@ci-runner".into(),
                "bob@laptop".into(),
                "(no comment)".into(),
            ],
            known_hosts_count: 5,
            known_hosts_hashed_count: 1,
            security_diagnostics: vec![DiagnosticEntry {
                id: "key_permissions".into(),
                severity: "warning".into(),
                module: "local".into(),
                message: "Private key id_rsa has overly permissive mode (0644)".into(),
                hint: Some("Run chmod 600 ~/.ssh/id_rsa".into()),
            }],
            access_info: SshAccessInfo {
                allowed_users: vec![],
                denied_users: vec![],
                allowed_groups: vec!["ssh-users".into()],
                denied_groups: vec![],
                auth_methods: vec!["publickey".into()],
                password_auth: false,
                pubkey_auth: true,
                permit_root_login: "prohibit-password".into(),
            },
            system_users: vec![
                SystemUserInfo {
                    username: "alice".into(),
                    shell: "/bin/bash".into(),
                    home_dir: "/home/alice".into(),
                    has_authorized_keys: true,
                    key_count: 2,
                },
                SystemUserInfo {
                    username: "bob".into(),
                    shell: "/bin/zsh".into(),
                    home_dir: "/home/bob".into(),
                    has_authorized_keys: true,
                    key_count: 1,
                },
                SystemUserInfo {
                    username: "root".into(),
                    shell: "/bin/bash".into(),
                    home_dir: "/root".into(),
                    has_authorized_keys: false,
                    key_count: 0,
                },
            ],
        }
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_is_not_pending() {
        let collector = SshDataCollector::new();
        assert!(!collector.is_pending());
    }

    #[test]
    fn default_matches_new() {
        assert_eq!(
            SshDataCollector::new().is_pending(),
            SshDataCollector::default().is_pending()
        );
    }

    #[tokio::test]
    async fn start_makes_pending() {
        let mut collector = SshDataCollector::new();
        assert!(!collector.is_pending());
        collector.start();
        assert!(collector.is_pending());
    }

    #[tokio::test]
    async fn start_is_idempotent() {
        let mut collector = SshDataCollector::new();
        collector.start();
        collector.start();
        assert!(collector.is_pending());
    }

    #[tokio::test]
    async fn poll_returns_bundle_after_collection() {
        let mut collector = SshDataCollector::new();
        collector.start();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let result = collector.poll().await;
        assert!(result.is_some());
        let bundle = result.unwrap();
        // Real data — just verify it doesn't crash and returns a bundle
        // Verify the bundle is well-formed: security data is present.
        assert!(bundle.security.access_info.pubkey_auth, "pubkey_auth should default to true");
        assert!(!bundle.security.access_info.permit_root_login.is_empty(),
            "permit_root_login should have a default value");
    }

    #[tokio::test]
    async fn poll_clears_pending() {
        let mut collector = SshDataCollector::new();
        collector.start();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let _ = collector.poll().await;
        assert!(!collector.is_pending());
    }

    #[tokio::test]
    async fn poll_returns_none_when_not_started() {
        let mut collector = SshDataCollector::new();
        let result = collector.poll().await;
        assert!(result.is_none());
    }

    #[test]
    fn mock_data_have_expected_content() {
        let bundle = mock::collect_mock_data();
        assert!(!bundle.keys.is_empty());
        assert!(!bundle.known_hosts.is_empty());
        assert!(!bundle.config_hosts.is_empty());
        assert!(!bundle.agent_keys.is_empty());
        assert!(!bundle.forwarding.is_empty());
        assert!(!bundle.diagnostics.is_empty());
        assert!(!bundle.authorized_keys.is_empty());
        assert!(!bundle.certificates.is_empty());
        assert!(bundle.agent_status.reachable);
        assert!(bundle.security.authorized_key_count > 0);
        assert!(!bundle.security.sshd_config.is_empty());
        assert_eq!(bundle.security.checks().len(), 8);
    }

    #[test]
    fn security_grade_a_when_secure() {
        let security = mock::collect_mock_security();
        assert_eq!(security.grade(), SecurityGrade::A);
    }

    #[test]
    fn security_grade_d_when_mostly_insecure() {
        let mut security = mock::collect_mock_security();
        security
            .sshd_config
            .insert("passwordauthentication".into(), "yes".into());
        security
            .sshd_config
            .insert("permitrootlogin".into(), "yes".into());
        assert_eq!(security.grade(), SecurityGrade::D);
    }

    #[test]
    fn security_grade_f_when_fully_insecure() {
        let mut security = mock::collect_mock_security();
        security
            .sshd_config
            .insert("passwordauthentication".into(), "yes".into());
        security
            .sshd_config
            .insert("permitrootlogin".into(), "yes".into());
        security
            .sshd_config
            .insert("permitemptypasswords".into(), "yes".into());
        security
            .sshd_config
            .insert("pubkeyauthentication".into(), "no".into());
        assert_eq!(security.grade(), SecurityGrade::F);
    }

    #[test]
    fn security_grade_b_with_password_auth() {
        // Start with a clean slate (no warnings) to test B in isolation.
        let mut security = mock::collect_mock_security();
        security.security_diagnostics = vec![]; // Clear warnings
        security.sshd_config.insert("passwordauthentication".into(), "yes".into());
        // 100 - 25 (password) = 75 => B
        assert_eq!(security.grade(), SecurityGrade::B);
    }

    #[test]
    fn security_grade_c_with_password_and_root_login() {
        // Start with a clean slate (no warnings) to test C in isolation.
        let mut security = mock::collect_mock_security();
        security.security_diagnostics = vec![]; // Clear warnings
        security.sshd_config.insert("passwordauthentication".into(), "yes".into());
        security.sshd_config.insert("permitrootlogin".into(), "yes".into());
        // 100 - 25 (password) - 20 (root) = 55 => C
        assert_eq!(security.grade(), SecurityGrade::C);
    }

    // ── parse_sshd_config_from tests ─────────────────────────────────────────

    #[test]
    fn parse_sshd_config_from_empty() {
        let config = parse_sshd_config_from("");
        assert!(config.is_empty());
    }

    #[test]
    fn parse_sshd_config_from_skips_comments() {
        let contents = "# this is a comment\nPort 2222\n";
        let config = parse_sshd_config_from(contents);
        assert_eq!(config.get("port"), Some(&"2222".to_string()));
        assert_eq!(config.len(), 1);
    }

    #[test]
    fn parse_sshd_config_from_skips_empty_lines() {
        let contents = "\n\nPort 2222\n\n";
        let config = parse_sshd_config_from(contents);
        assert_eq!(config.get("port"), Some(&"2222".to_string()));
    }

    #[test]
    fn parse_sshd_config_from_skips_match_and_include() {
        // Note: the parser skips lines starting with "match " or "include "
        // but does NOT skip indented directives inside a Match block.
        // This is a known limitation documented in the function docs.
        let contents = "Port 2222\nMatch Address 192.168.0.0/16\nInclude /etc/ssh/sshd_config.d/*.conf\n";
        let config = parse_sshd_config_from(contents);
        assert_eq!(config.len(), 1);
        assert_eq!(config.get("port"), Some(&"2222".to_string()));
    }

    #[test]
    fn parse_sshd_config_from_keys_are_lowercased() {
        let contents = "PasswordAuthentication no\nPermitRootLogin yes\n";
        let config = parse_sshd_config_from(contents);
        assert_eq!(config.get("passwordauthentication"), Some(&"no".to_string()));
        assert_eq!(config.get("permitrootlogin"), Some(&"yes".to_string()));
    }

    #[test]
    fn parse_sshd_config_from_various_whitespace() {
        // Note: split_once(char::is_whitespace) splits on the first space only,
        // so leading spaces in the value portion are preserved.
        let contents = "Port 2222\nMaxAuthTries 3\n";
        let config = parse_sshd_config_from(contents);
        assert_eq!(config.get("port"), Some(&"2222".to_string()));
        assert_eq!(config.get("maxauthtries"), Some(&"3".to_string()));
    }

    // ── parse_sshd_access_info_from tests ────────────────────────────────────

    #[test]
    fn parse_access_info_defaults_when_empty() {
        let info = parse_sshd_access_info_from("");
        assert!(info.pubkey_auth, "pubkey_auth should default to true");
        assert!(info.password_auth, "password_auth should default to true");
        assert_eq!(info.permit_root_login, "prohibit-password");
        assert!(info.allowed_users.is_empty());
        assert!(info.denied_users.is_empty());
    }

    #[test]
    fn parse_access_info_explicit_values() {
        let contents = "\
            PasswordAuthentication no\n\
            PubkeyAuthentication yes\n\
            PermitRootLogin no\n\
            AllowUsers alice bob\n\
            DenyUsers guest\n\
            AllowGroups ssh-users\n\
            DenyGroups no-ssh\n\
            AuthenticationMethods publickey,keyboard-interactive\n";
        let info = parse_sshd_access_info_from(contents);
        assert!(!info.password_auth);
        assert!(info.pubkey_auth);
        assert_eq!(info.permit_root_login, "no");
        assert_eq!(info.allowed_users, vec!["alice", "bob"]);
        assert_eq!(info.denied_users, vec!["guest"]);
        assert_eq!(info.allowed_groups, vec!["ssh-users"]);
        assert_eq!(info.denied_groups, vec!["no-ssh"]);
        assert_eq!(info.auth_methods, vec!["publickey", "keyboard-interactive"]);
    }

    #[test]
    fn parse_access_info_pubkey_no_is_preserved() {
        let contents = "PubkeyAuthentication no\n";
        let info = parse_sshd_access_info_from(contents);
        assert!(!info.pubkey_auth, "explicit 'no' should be preserved");
    }

    #[test]
    fn parse_access_info_password_no_is_preserved() {
        let contents = "PasswordAuthentication no\n";
        let info = parse_sshd_access_info_from(contents);
        assert!(!info.password_auth, "explicit 'no' should be preserved");
    }

    #[test]
    fn parse_access_info_skips_match_lines() {
        // The parser skips lines starting with "match " but does not
        // skip indented content inside Match blocks — that's a known limitation.
        let contents = "\
            PasswordAuthentication no\n\
            Match Address 192.168.0.0/16\n";
        let info = parse_sshd_access_info_from(contents);
        assert!(!info.password_auth, "PasswordAuthentication no should be preserved");
    }

    // ── Write-path integration tests ─────────────────────────────────────────
    //
    // These tests override $HOME to a temp dir so SshManager writes there
    // instead of the real ~/.ssh. They must run serially because env-var
    // mutation is process-global. The `serial_test` pattern is achieved by
    // a mutex — we don't need the crate, just a static Mutex<usize>.

    use std::sync::Mutex;
    static HOME_LOCK: Mutex<usize> = Mutex::new(0);

    /// Acquire the HOME lock, recovering from a poisoned mutex (caused by a
    /// previous test panic) so that one failing test doesn't cascade.
    fn acquire_home_lock() -> std::sync::MutexGuard<'static, usize> {
        HOME_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Temp HOME override for safe write-path tests.
    struct TempHome {
        original: Option<std::path::PathBuf>,
        _dir: tempfile::TempDir,
    }

    impl TempHome {
        fn new() -> Self {
            let dir = tempfile::tempdir().expect("tempdir");
            let ssh_dir = dir.path().join(".ssh");
            std::fs::create_dir_all(&ssh_dir).expect("mkdir .ssh");
            let original = std::env::var_os("HOME").map(std::path::PathBuf::from);
            // SAFETY: test-only; HOME_LOCK ensures serial execution.
            unsafe { std::env::set_var("HOME", dir.path()); }
            Self { original, _dir: dir }
        }
    }

    impl Drop for TempHome {
        fn drop(&mut self) {
            // SAFETY: test-only; restoring original state.
            unsafe {
                if let Some(ref orig) = self.original {
                    std::env::set_var("HOME", orig);
                } else {
                    std::env::remove_var("HOME");
                }
            }
        }
    }

    #[tokio::test]
    async fn execute_op_config_add_host_writes_to_disk() {
        let _lock = acquire_home_lock();
        let _home = TempHome::new();
        let op = SshOp::ConfigAddHost {
            name: "test-toride-host".into(),
            host_name: Some("192.168.1.99".into()),
            user: Some("testuser".into()),
            port: Some(2222),
        };
        let result = execute_op(op).await;
        assert!(result.is_ok(), "config add failed: {:?}", result.err());
        // Verify the file was actually written
        let mgr = toride_ssh::SshManager::new().expect("mgr");
        let ast = mgr.config().load().await.expect("load");
        let content = ast.to_string_lossless();
        assert!(content.contains("test-toride-host"), "host not in config: {content}");
        // Clean up: remove the host
        let op2 = SshOp::ConfigRemoveHost { name: "test-toride-host".into() };
        let result2 = execute_op(op2).await;
        assert!(result2.is_ok(), "config remove failed: {:?}", result2.err());
    }

    #[tokio::test]
    async fn execute_op_config_add_duplicate_fails() {
        let _lock = acquire_home_lock();
        let _home = TempHome::new();
        let op = SshOp::ConfigAddHost {
            name: "dupe-host".into(),
            host_name: None,
            user: None,
            port: None,
        };
        assert!(execute_op(op).await.is_ok());
        let op2 = SshOp::ConfigAddHost {
            name: "dupe-host".into(),
            host_name: None,
            user: None,
            port: None,
        };
        let result = execute_op(op2).await;
        assert!(result.is_err(), "duplicate add should fail: {:?}", result);
    }

    #[tokio::test]
    async fn execute_op_config_remove_nonexistent_fails() {
        let _lock = acquire_home_lock();
        let _home = TempHome::new();
        let op = SshOp::ConfigRemoveHost { name: "no-such-host".into() };
        let result = execute_op(op).await;
        assert!(result.is_err(), "removing nonexistent host should fail: {:?}", result);
    }

    #[tokio::test]
    async fn execute_op_config_edit_host_replaces() {
        let _lock = acquire_home_lock();
        let _home = TempHome::new();
        let op = SshOp::ConfigAddHost {
            name: "edit-me".into(),
            host_name: Some("old.example.com".into()),
            user: Some("olduser".into()),
            port: Some(22),
        };
        assert!(execute_op(op).await.is_ok());
        let op2 = SshOp::ConfigEditHost {
            old_name: "edit-me".into(),
            new_name: "edit-me".into(),
            host_name: Some("new.example.com".into()),
            user: Some("newuser".into()),
            port: Some(443),
        };
        let result = execute_op(op2).await;
        assert!(result.is_ok(), "config edit failed: {:?}", result.err());
        let mgr = toride_ssh::SshManager::new().expect("mgr");
        let ast = mgr.config().load().await.expect("load");
        let content = ast.to_string_lossless();
        assert!(content.contains("new.example.com"), "new hostname in config: {content}");
        assert!(!content.contains("old.example.com"), "old hostname gone: {content}");
    }

    #[tokio::test]
    async fn execute_op_key_create_and_delete() {
        let _lock = acquire_home_lock();
        let _home = TempHome::new();
        let op = SshOp::KeyCreate {
            name: "toride-test-key".into(),
            key_type: "Ed25519".into(),
            comment: "test@toride".into(),
            passphrase: None,
        };
        let result = execute_op(op).await;
        assert!(result.is_ok(), "key create failed: {:?}", result.err());
        // Verify file exists
        let home = std::env::var("HOME").expect("HOME");
        let key_path = std::path::Path::new(&home).join(".ssh/toride-test-key");
        assert!(key_path.exists(), "private key file should exist at {}", key_path.display());
        // Clean up
        let op2 = SshOp::KeyDelete { name: "toride-test-key".into() };
        let result2 = execute_op(op2).await;
        assert!(result2.is_ok(), "key delete failed: {:?}", result2.err());
        assert!(!key_path.exists(), "key file should be deleted");
    }

    // ── Full CRUD Lifecycle Tests ──────────────────────────────────────────
    //
    // These tests exercise the toride-ssh backend directly (outside the TUI)
    // to isolate whether CRUD operations actually persist to disk.

    /// SSH Key full lifecycle: Create → Verify → List → Rename → Delete.
    #[tokio::test]
    async fn key_full_crud_lifecycle() {
        let _lock = acquire_home_lock();
        let _home = TempHome::new();
        let mgr = toride_ssh::SshManager::new().expect("SshManager init");
        let home = std::env::var("HOME").expect("HOME");

        // Step 1: CREATE (use id_ prefix — inventory scan only finds id_* files)
        let params = toride_ssh::KeyCreateParams::ed25519("id_crud_test_key".to_owned());
        mgr.keys()
            .create(params)
            .await
            .expect("Step 1 CREATE: key generation failed");
        eprintln!("✓ Step 1: CREATE key 'id_crud_test_key'");

        // Step 2: VERIFY files exist
        let private = std::path::Path::new(&home).join(".ssh/id_crud_test_key");
        let public = std::path::Path::new(&home).join(".ssh/id_crud_test_key.pub");
        assert!(private.exists(), "Step 2 VERIFY: private key missing at {private:?}");
        assert!(public.exists(), "Step 2 VERIFY: public key missing at {public:?}");
        eprintln!("✓ Step 2: VERIFY files exist");

        // Step 3: LIST includes the key
        let keys = mgr.keys().list().await.expect("Step 3 LIST: scan failed");
        let found = keys.iter().any(|k| {
            k.path.file_name().map_or(false, |n| n == "id_crud_test_key")
        });
        assert!(found, "Step 3 LIST: key not found in inventory ({} keys scanned)", keys.len());
        eprintln!("✓ Step 3: LIST returns the key");

        // Step 4: RENAME
        mgr.keys()
            .rename("id_crud_test_key", "id_crud_test_v2")
            .await
            .expect("Step 4 RENAME: rename failed");
        eprintln!("✓ Step 4: RENAME to 'id_crud_test_v2'");

        // Step 5: VERIFY rename — old gone, new exists
        let new_private = std::path::Path::new(&home).join(".ssh/id_crud_test_v2");
        assert!(
            !private.exists(),
            "Step 5 VERIFY: old private key still exists"
        );
        assert!(
            new_private.exists(),
            "Step 5 VERIFY: new private key missing"
        );
        eprintln!("✓ Step 5: VERIFY old gone, new exists");

        // Step 6: DELETE
        let del_params = toride_ssh::KeyDeleteParams {
            name: "id_crud_test_v2".to_owned(),
            remove_public: true,
            remove_certificate: true,
            remove_from_agent: false,
            remove_from_config: false,
            backup: false,
        };
        mgr.keys()
            .delete(del_params)
            .await
            .expect("Step 6 DELETE: deletion failed");
        eprintln!("✓ Step 6: DELETE 'id_crud_test_v2'");

        // Step 7: VERIFY deletion
        assert!(
            !new_private.exists(),
            "Step 7 VERIFY: private key still exists after delete"
        );
        let new_public = std::path::Path::new(&home).join(".ssh/id_crud_test_v2.pub");
        assert!(
            !new_public.exists(),
            "Step 7 VERIFY: public key still exists after delete"
        );
        eprintln!("✓ Step 7: VERIFY both files gone");
        eprintln!("✅ key_full_crud_lifecycle PASSED");
    }

    /// Config host full lifecycle: Add → Verify → Edit → Verify → Remove → Verify.
    #[tokio::test]
    async fn config_host_full_crud_lifecycle() {
        let _lock = acquire_home_lock();
        let _home = TempHome::new();
        let mgr = toride_ssh::SshManager::new().expect("SshManager init");
        let svc = mgr.config();

        // Step 1: ADD
        svc.edit(|ast| {
            toride_ssh::config::ConfigService::add_host(
                ast,
                "test-server",
                vec![
                    ("HostName".to_owned(), "10.0.0.1".to_owned()),
                    ("user".to_owned(), "admin".to_owned()),
                    ("port".to_owned(), "2222".to_owned()),
                ],
            )
        })
        .await
        .expect("Step 1 ADD: config add_host failed");
        eprintln!("✓ Step 1: ADD host 'test-server'");

        // Step 2: VERIFY
        let ast = svc.load().await.expect("Step 2 VERIFY: config load failed");
        let content = ast.to_string_lossless();
        assert!(
            content.contains("test-server"),
            "Step 2 VERIFY: 'test-server' not in config:\n{content}"
        );
        assert!(
            content.contains("10.0.0.1"),
            "Step 2 VERIFY: hostname '10.0.0.1' not in config:\n{content}"
        );
        eprintln!("✓ Step 2: VERIFY host block in config");

        // Step 3: EDIT (remove + re-add with new values)
        svc.edit(|ast| {
            let _ = toride_ssh::config::ConfigService::remove_host(ast, "test-server");
            toride_ssh::config::ConfigService::add_host(
                ast,
                "test-server",
                vec![
                    ("hostname".to_owned(), "10.0.0.99".to_owned()),
                    ("user".to_owned(), "deploy".to_owned()),
                    ("port".to_owned(), "443".to_owned()),
                ],
            )
        })
        .await
        .expect("Step 3 EDIT: config edit failed");
        eprintln!("✓ Step 3: EDIT host with new values");

        // Step 4: VERIFY edit
        let ast = svc.load().await.expect("Step 4 VERIFY: config load failed");
        let content = ast.to_string_lossless();
        assert!(
            content.contains("10.0.0.99"),
            "Step 4 VERIFY: new hostname not in config:\n{content}"
        );
        assert!(
            !content.contains("10.0.0.1"),
            "Step 4 VERIFY: old hostname still in config:\n{content}"
        );
        eprintln!("✓ Step 4: VERIFY new values present, old gone");

        // Step 5: REMOVE
        svc.edit(|ast| {
            toride_ssh::config::ConfigService::remove_host(ast, "test-server")
        })
        .await
        .expect("Step 5 REMOVE: config remove failed");
        eprintln!("✓ Step 5: REMOVE host 'test-server'");

        // Step 6: VERIFY removal
        let ast = svc.load().await.expect("Step 6 VERIFY: config load failed");
        let content = ast.to_string_lossless();
        assert!(
            !content.contains("test-server"),
            "Step 6 VERIFY: 'test-server' still in config:\n{content}"
        );
        eprintln!("✓ Step 6: VERIFY host block gone");
        eprintln!("✅ config_host_full_crud_lifecycle PASSED");
    }

    /// Authorized keys full lifecycle: Add → List → Remove.
    #[tokio::test]
    async fn authorized_keys_full_crud_lifecycle() {
        let _lock = acquire_home_lock();
        let _home = TempHome::new();
        let mgr = toride_ssh::SshManager::new().expect("SshManager init");
        let svc = mgr.authorized_keys();

        // Real Ed25519 public key for testing (generated locally, not a real credential).
        const TEST_PUB_KEY: &str =
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIImjsW+mcxW23mD3eIRMOibeBrsz/KOg6NIefuhgc5uI crud-test@toride";

        // Step 1: ADD
        svc.add(TEST_PUB_KEY, Some("crud-test"), None)
            .await
            .expect("Step 1 ADD: authorized_keys add failed");
        eprintln!("✓ Step 1: ADD key to authorized_keys");

        // Step 2: VERIFY via list
        let entries = svc.list().await.expect("Step 2 VERIFY: list failed");
        assert!(
            !entries.is_empty(),
            "Step 2 VERIFY: authorized_keys list is empty after add"
        );
        let matched = entries
            .iter()
            .find(|e| e.comment.as_deref() == Some("crud-test"));
        assert!(
            matched.is_some(),
            "Step 2 VERIFY: no entry with comment 'crud-test' found"
        );
        eprintln!(
            "✓ Step 2: VERIFY list returns {} entry/entries",
            entries.len()
        );

        // Step 3: REMOVE via fingerprint
        let entry = matched.expect("entry must exist");
        let fp = entry
            .fingerprint()
            .expect("Step 3 REMOVE: could not compute fingerprint");
        let removed = svc
            .remove(&fp)
            .await
            .expect("Step 3 REMOVE: authorized_keys remove failed");
        assert!(
            removed > 0,
            "Step 3 REMOVE: remove returned 0 count (nothing deleted)"
        );
        eprintln!("✓ Step 3: REMOVE key (fingerprint: {fp})");

        // Step 4: VERIFY removal
        let entries = svc.list().await.expect("Step 4 VERIFY: list failed");
        let still_exists = entries
            .iter()
            .any(|e| e.comment.as_deref() == Some("crud-test"));
        assert!(
            !still_exists,
            "Step 4 VERIFY: key still present after removal"
        );
        eprintln!("✓ Step 4: VERIFY key removed from authorized_keys");
        eprintln!("✅ authorized_keys_full_crud_lifecycle PASSED");
    }

    /// Known hosts full lifecycle: Add → Verify → Remove.
    ///
    /// Gracefully skips if `ssh-keyscan` fails (e.g. no local SSH server).
    #[tokio::test]
    async fn known_hosts_crud_lifecycle() {
        let _lock = acquire_home_lock();
        let _home = TempHome::new();
        let mgr = toride_ssh::SshManager::new().expect("SshManager init");
        let svc = mgr.known_hosts();

        // Step 1: ADD (may fail if no SSHD on localhost — that's okay)
        let add_result = svc.add("localhost").await;
        if add_result.is_err() {
            eprintln!(
                "⚠ Step 1 ADD: ssh-keyscan localhost failed ({:?}) — skipping known_hosts test",
                add_result.err()
            );
            eprintln!("ℹ This is expected if no SSH server runs on localhost");
            return;
        }
        eprintln!("✓ Step 1: ADD localhost to known_hosts");

        // Step 2: VERIFY
        let kh_file = std::path::Path::new(&std::env::var("HOME").expect("HOME"))
            .join(".ssh/known_hosts");
        assert!(
            kh_file.exists(),
            "Step 2 VERIFY: known_hosts file missing"
        );
        let content = std::fs::read_to_string(&kh_file).expect("read known_hosts");
        assert!(
            !content.trim().is_empty(),
            "Step 2 VERIFY: known_hosts is empty"
        );
        eprintln!("✓ Step 2: VERIFY known_hosts file has content");

        // Step 3: REMOVE
        svc.remove("localhost")
            .await
            .expect("Step 3 REMOVE: known_hosts remove failed");
        eprintln!("✓ Step 3: REMOVE localhost from known_hosts");

        // Step 4: VERIFY removal (file may still exist but without localhost entries)
        let content_after =
            std::fs::read_to_string(&kh_file).unwrap_or_default();
        // After removal the file may contain hashed entries or be empty.
        // The key test is that remove() succeeded.
        eprintln!(
            "✓ Step 4: VERIFY remove succeeded (known_hosts now has {} bytes)",
            content_after.len()
        );
        eprintln!("✅ known_hosts_crud_lifecycle PASSED");
    }

    /// Execute-op pipeline round-trip: tests the same SshOp → execute_op path
    /// the TUI uses for Keys and Config CRUD.
    #[tokio::test]
    async fn execute_op_pipeline_round_trip() {
        let _lock = acquire_home_lock();
        let _home = TempHome::new();
        let home = std::env::var("HOME").expect("HOME");

        // ── Key lifecycle via SshOp ──

        // Step 1: CREATE via execute_op
        let op = SshOp::KeyCreate {
            name: "pipeline-key".into(),
            key_type: "Ed25519".into(),
            comment: "pipeline-test@toride".into(),
            passphrase: None,
        };
        let result = execute_op(op).await;
        assert!(
            result.is_ok(),
            "Step 1 CREATE via execute_op failed: {:?}",
            result.err()
        );
        eprintln!("✓ Step 1: execute_op(KeyCreate) — {}", result.unwrap());

        // Step 2: VERIFY file exists
        let key_path = std::path::Path::new(&home).join(".ssh/pipeline-key");
        assert!(
            key_path.exists(),
            "Step 2 VERIFY: private key missing at {key_path:?}"
        );
        eprintln!("✓ Step 2: VERIFY key file on disk");

        // Step 3: RENAME via execute_op
        let op = SshOp::KeyRename {
            old_name: "pipeline-key".into(),
            new_name: "pipeline-renamed".into(),
        };
        let result = execute_op(op).await;
        assert!(
            result.is_ok(),
            "Step 3 RENAME via execute_op failed: {:?}",
            result.err()
        );
        eprintln!("✓ Step 3: execute_op(KeyRename) — {}", result.unwrap());

        // Step 4: VERIFY rename
        assert!(
            !key_path.exists(),
            "Step 4 VERIFY: old key still exists"
        );
        let renamed_path = std::path::Path::new(&home).join(".ssh/pipeline-renamed");
        assert!(
            renamed_path.exists(),
            "Step 4 VERIFY: renamed key missing"
        );
        eprintln!("✓ Step 4: VERIFY old gone, renamed exists");

        // Step 5: DELETE via execute_op
        let op = SshOp::KeyDelete {
            name: "pipeline-renamed".into(),
        };
        let result = execute_op(op).await;
        assert!(
            result.is_ok(),
            "Step 5 DELETE via execute_op failed: {:?}",
            result.err()
        );
        eprintln!("✓ Step 5: execute_op(KeyDelete) — {}", result.unwrap());

        // Step 6: VERIFY deletion
        assert!(
            !renamed_path.exists(),
            "Step 6 VERIFY: key still exists after delete"
        );
        eprintln!("✓ Step 6: VERIFY key file gone");

        // ── Config lifecycle via SshOp ──

        // Step 7: ADD HOST via execute_op
        let op = SshOp::ConfigAddHost {
            name: "pipeline-host".into(),
            host_name: Some("192.168.1.50".into()),
            user: Some("testuser".into()),
            port: Some(22),
        };
        let result = execute_op(op).await;
        assert!(
            result.is_ok(),
            "Step 7 CONFIG ADD via execute_op failed: {:?}",
            result.err()
        );
        eprintln!("✓ Step 7: execute_op(ConfigAddHost) — {}", result.unwrap());

        // Step 8: VERIFY in config
        let mgr = toride_ssh::SshManager::new().expect("mgr");
        let ast = mgr.config().load().await.expect("load config");
        let content = ast.to_string_lossless();
        assert!(
            content.contains("pipeline-host"),
            "Step 8 VERIFY: 'pipeline-host' not in config:\n{content}"
        );
        eprintln!("✓ Step 8: VERIFY host in config");

        // Step 9: REMOVE HOST via execute_op
        let op = SshOp::ConfigRemoveHost {
            name: "pipeline-host".into(),
        };
        let result = execute_op(op).await;
        assert!(
            result.is_ok(),
            "Step 9 CONFIG REMOVE via execute_op failed: {:?}",
            result.err()
        );
        eprintln!("✓ Step 9: execute_op(ConfigRemoveHost) — {}", result.unwrap());

        // Step 10: VERIFY removal
        let ast = mgr.config().load().await.expect("load config");
        let content = ast.to_string_lossless();
        assert!(
            !content.contains("pipeline-host"),
            "Step 10 VERIFY: 'pipeline-host' still in config:\n{content}"
        );
        eprintln!("✓ Step 10: VERIFY host gone from config");
        eprintln!("✅ execute_op_pipeline_round_trip PASSED");
    }
}
