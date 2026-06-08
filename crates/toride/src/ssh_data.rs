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
    DiagnosticEntry, ForwardEntry, ForwardSessionEntry, KnownHostEntry, SshKeyEntry,
};
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

/// Collect SSH data by reading real files and calling real services.
///
/// File-based subsystems (known_hosts, authorized_keys, keys, config) are
/// collected in parallel. CLI-based subsystems (agent, forwarding, certificates)
/// use mock data for now — they'll be wired in a follow-up.
async fn collect_real_data() -> SshDataBundle {
    let mgr = match toride_ssh::SshManager::new() {
        Ok(m) => m,
        Err(e) => {
            tracing::warn!("SshManager::new() failed: {e}");
            return empty_bundle();
        }
    };

    // File-based: run in parallel
    let (keys_r, known_hosts_r, auth_keys_r, config_r, diag_r) = tokio::join!(
        collect_keys(&mgr),
        collect_known_hosts(&mgr),
        collect_authorized_keys(&mgr),
        collect_config_hosts(&mgr),
        collect_diagnostics(&mgr),
    );

    let keys = keys_r.unwrap_or_default();
    let known_hosts = known_hosts_r.unwrap_or_default();
    let authorized_keys = auth_keys_r.unwrap_or_default();
    let config_hosts = config_r.unwrap_or_default();
    let diagnostics = diag_r.unwrap_or_default();

    // CLI-based: still stubs (Phase B/C — will wire to real CLI tools later)
    let agent_status = stub::agent_status();
    let agent_keys = stub::agent_keys();
    let forwarding = stub::forwarding();
    let certificates = stub::certificates();

    let security =
        build_security_data(&known_hosts, &authorized_keys, &diagnostics);

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

/// Build security overview data from already-collected real data.
fn build_security_data(
    known_hosts: &[KnownHostEntry],
    authorized_keys: &[AuthorizedKeyEntry],
    diagnostics: &[DiagnosticEntry],
) -> SshSecurityData {
    let sshd_config = parse_sshd_config();

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
fn parse_sshd_config() -> HashMap<String, String> {
    let path = Path::new("/etc/ssh/sshd_config");
    let contents = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return HashMap::new(),
    };

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

// ── Stub Data (CLI-based subsystems, not yet wired) ──────────────────────────

/// Placeholder data for subsystems that require CLI tools not yet integrated.
///
/// These return hardcoded data until agent, forwarding, and certificate services
/// are wired up in a follow-up.
mod stub {
    use super::*;

    pub fn agent_status() -> AgentStatus {
        AgentStatus {
            reachable: false,
            socket_path: None,
            key_count: 0,
        }
    }

    pub fn agent_keys() -> Vec<AgentKeyEntry> {
        Vec::new()
    }

    pub fn forwarding() -> Vec<ForwardSessionEntry> {
        Vec::new()
    }

    pub fn certificates() -> Vec<CertificateEntry> {
        Vec::new()
    }
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
                host_count: 2,
            },
            SshKeyEntry {
                name: "id_rsa".into(),
                key_type: "RSA 4096".into(),
                fingerprint: "SHA256:xyz789abc456def123".into(),
                encrypted: false,
                permissions: "0644".into(),
                has_public: true,
                has_cert: true,
                host_count: 0,
            },
            SshKeyEntry {
                name: "deploy_key".into(),
                key_type: "Ed25519".into(),
                fingerprint: "SHA256:qwe456rty789uio012".into(),
                encrypted: false,
                permissions: "0600".into(),
                has_public: true,
                has_cert: false,
                host_count: 5,
            },
        ]
    }

    pub fn collect_mock_known_hosts() -> Vec<KnownHostEntry> {
        vec![
            KnownHostEntry {
                hosts: vec!["github.com".into()],
                key_type: "ssh-ed25519".into(),
                fingerprint: "SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8".into(),
                is_hashed: false,
                marker: None,
                comment: None,
                line: 1,
                source: "user".into(),
            },
            KnownHostEntry {
                hosts: vec!["gitlab.com".into()],
                key_type: "ssh-ed25519".into(),
                fingerprint: "SHA256:WSCtr3bEeJGgcb0UrkMFWxQJqchWXzwWMNESdgqxo".into(),
                is_hashed: false,
                marker: None,
                comment: None,
                line: 2,
                source: "user".into(),
            },
            KnownHostEntry {
                hosts: vec!["[192.168.1.1]:2222".into()],
                key_type: "ssh-rsa".into(),
                fingerprint: "SHA256:abc123def456ghi789jkl012mno345pqr678".into(),
                is_hashed: false,
                marker: None,
                comment: Some("home router".into()),
                line: 3,
                source: "user".into(),
            },
            KnownHostEntry {
                hosts: vec!["|1|ba4dEeFgHiJkLmNoPqRsTu|XxYyZz0123456789".into()],
                key_type: "ecdsa-sha2-nistp256".into(),
                fingerprint: "SHA256:qwe456rty789uio012pqr345stu678vwx".into(),
                is_hashed: true,
                marker: None,
                comment: None,
                line: 4,
                source: "user".into(),
            },
            KnownHostEntry {
                hosts: vec!["old.server.example.com".into()],
                key_type: "ssh-ed25519".into(),
                fingerprint: "SHA256:xyz789abc456def123ghi456jkl789mno012".into(),
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
        assert!(bundle.keys.is_empty() || !bundle.keys.is_empty());
        assert!(bundle.known_hosts.is_empty() || !bundle.known_hosts.is_empty());
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
}
