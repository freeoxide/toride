//! The SSH screen: a tab bar over security, keys, known hosts, config,
//! agent, forwarding, diagnostics, authorized keys, and certificates.

use std::time::Instant;

use crossterm::event::{KeyCode, MouseButton, MouseEvent, MouseEventKind};
use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::Paragraph,
};

use crate::action::Action;
use crate::data::SshSection;
use crate::ssh_data::SshOp;
use crate::ui::theme::Palette;

use self::agent_tab::AgentTab;
use self::authorized_keys_tab::AuthorizedKeysTab;
use self::certificates_tab::CertificatesTab;
use self::config_tab::ConfigTab;
use self::diagnostics_tab::DiagnosticsTab;
use self::forwarding_tab::ForwardingTab;
use self::keys_tab::KeysTab;
use self::known_hosts_tab::KnownHostsTab;
use self::security_tab::SecurityTab;

pub mod agent_tab;
pub mod authorized_keys_tab;
pub mod certificates_tab;
pub mod config_tab;
pub mod diagnostics_tab;
pub mod forwarding_tab;
pub mod keys_tab;
pub mod known_hosts_tab;
pub mod security_tab;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Focus {
    TabBar,
    List,
}

/// The SSH screen content: tab bar, per-tab state, and the pending-op queue.
pub struct SshContent {
    tab: SshSection,
    focus: Focus,
    security: SecurityTab,
    keys: KeysTab,
    known_hosts: KnownHostsTab,
    config: ConfigTab,
    agent: AgentTab,
    forwarding: ForwardingTab,
    diagnostics: DiagnosticsTab,
    authorized_keys: AuthorizedKeysTab,
    certificates: CertificatesTab,
    tab_hitboxes: Vec<Rect>,
    hovered_tab: Option<usize>,
    pending_ops: Vec<SshOp>,
    last_error: Option<(String, Instant)>,
    ssh_loading: bool,
    ssh_ops_in_flight: usize,
    loading_start: Instant,
}

impl SshContent {
    /// Create SSH content with the Security tab active.
    #[must_use]
    pub fn new() -> Self {
        Self {
            tab: SshSection::Security,
            focus: Focus::List,
            security: SecurityTab::new(),
            keys: KeysTab::new(),
            known_hosts: KnownHostsTab::new(),
            config: ConfigTab::new(),
            agent: AgentTab::new(),
            forwarding: ForwardingTab::new(),
            diagnostics: DiagnosticsTab::new(),
            authorized_keys: AuthorizedKeysTab::new(),
            certificates: CertificatesTab::new(),
            tab_hitboxes: Vec::new(),
            hovered_tab: None,
            pending_ops: Vec::new(),
            last_error: None,
            ssh_loading: false,
            ssh_ops_in_flight: 0,
            loading_start: Instant::now(),
        }
    }

    /// The active tab.
    #[must_use]
    pub fn tab(&self) -> SshSection {
        self.tab
    }

    /// Whether the active tab has a modal open.
    #[must_use]
    pub fn has_modal(&self) -> bool {
        self.active_tab().has_modal()
    }

    /// Queue an SSH op for the app loop to execute.
    pub fn push_op(&mut self, op: SshOp) {
        self.pending_ops.push(op);
    }

    /// Take every pending op, leaving the queue empty.
    pub fn drain_pending_ops(&mut self) -> Vec<SshOp> {
        std::mem::take(&mut self.pending_ops)
    }

    /// Re-queues drained ops at the front so a batch already in-flight never
    /// spawns a second task and the user's original ordering is preserved.
    pub fn queue_ops_front(&mut self, mut ops: Vec<SshOp>) {
        ops.append(&mut self.pending_ops);
        self.pending_ops = ops;
    }

    fn collect_ops(&mut self) {
        let ops = self.active_tab_mut().drain_ops();
        self.pending_ops.extend(ops);
    }

    /// Show an error toast for 5s.
    pub fn push_error(&mut self, msg: String) {
        self.last_error = Some((msg, Instant::now()));
    }

    fn clear_expired_error(&mut self) {
        if let Some((_, ts)) = &self.last_error
            && ts.elapsed().as_secs() >= 5
        {
            self.last_error = None;
        }
    }

    /// Whether the error toast is shown; its 5s TTL is enforced only at
    /// draw time, so the app loop uses this to schedule the clearing redraw.
    #[must_use]
    pub fn error_showing(&self) -> bool {
        self.last_error.is_some()
    }

    /// Whether the error notification has hit its 5s TTL (the next draw clears it).
    #[must_use]
    pub fn error_expired(&self) -> bool {
        self.last_error
            .as_ref()
            .is_some_and(|(_, ts)| ts.elapsed().as_secs() >= 5)
    }

    /// Whether fingerprint computation is still pending for some keys.
    #[must_use]
    pub fn has_pending_fingerprints(&self) -> bool {
        self.keys.has_pending_fingerprints()
    }

    /// Set the loading state and in-flight op count.
    pub fn set_loading(&mut self, loading: bool, count: usize) {
        if loading && !self.ssh_loading {
            self.loading_start = Instant::now();
        }
        self.ssh_loading = loading;
        self.ssh_ops_in_flight = count;
    }

    /// Whether SSH ops are in flight (input is suppressed).
    #[must_use]
    pub fn is_loading(&self) -> bool {
        self.ssh_loading
    }

    #[expect(
        clippy::cast_possible_truncation,
        reason = "spinner arithmetic bounded"
    )]
    #[expect(
        clippy::cast_sign_loss,
        reason = "elapsed spinner product is non-negative"
    )]
    fn render_loading_bar(&self, frame: &mut Frame, area: Rect, p: Palette) {
        use rattles::Rattle;
        use rattles::presets::braille::WaveRows;

        let frames = WaveRows::FRAMES;
        let interval_ms = WaveRows::INTERVAL.as_millis() as u32;
        let elapsed = self.loading_start.elapsed().as_secs_f32();
        let idx = if p.reduced_motion {
            0
        } else {
            (elapsed * 1000.0) as u32 / interval_ms.max(1)
        };
        let braille = frames[idx as usize % frames.len()];
        let spinner = braille.first().map_or("·", |s| *s);

        let mut spans = vec![
            Span::styled(
                format!(" {spinner} "),
                Style::new().fg(p.accent).add_modifier(Modifier::BOLD),
            ),
            Span::styled("applying changes...", Style::new().fg(p.text_dim)),
        ];
        if self.ssh_ops_in_flight > 1 {
            spans.push(Span::styled(
                format!(" ({} remaining)", self.ssh_ops_in_flight),
                Style::new().fg(p.text_muted),
            ));
        }
        frame.render_widget(
            Paragraph::new(Line::from(spans)).style(Style::new().bg(p.panel)),
            area,
        );
    }

    /// Replace the keys tab's data.
    pub fn set_keys(&mut self, keys: Vec<SshKeyEntry>) {
        self.keys.set_keys(keys);
    }

    /// Replace the known-hosts tab's data.
    pub fn set_known_hosts(&mut self, hosts: Vec<KnownHostEntry>) {
        self.known_hosts.set_hosts(hosts);
    }

    /// Replace the config tab's host list.
    pub fn set_config_hosts(&mut self, hosts: Vec<ConfigHostEntry>) {
        self.config.set_hosts(hosts);
    }

    /// Replace the agent tab's data.
    pub fn set_agent_data(&mut self, status: AgentStatus, keys: Vec<AgentKeyEntry>) {
        self.agent.set_data(status, keys);
    }

    /// Replace the forwarding tab's sessions.
    pub fn set_forwarding(&mut self, sessions: Vec<ForwardSessionEntry>) {
        self.forwarding.set_sessions(sessions);
    }

    /// Replace the diagnostics tab's entries.
    pub fn set_diagnostics(&mut self, entries: std::sync::Arc<Vec<DiagnosticEntry>>) {
        self.diagnostics.set_entries(entries);
    }

    /// Replace the authorized-keys tab's entries.
    pub fn set_authorized_keys(&mut self, entries: Vec<AuthorizedKeyEntry>) {
        self.authorized_keys.set_entries(entries);
    }

    /// Replace the certificates tab's entries.
    pub fn set_certificates(&mut self, entries: Vec<CertificateEntry>) {
        self.certificates.set_entries(entries);
    }

    /// Replace the security tab's data.
    pub fn set_security(&mut self, data: crate::ssh_data::SshSecurityData) {
        self.security.set_data(data);
    }

    /// Handle a key press. Returns `Some(Action)` for navigation, `None` if consumed.
    pub fn handle_key(&mut self, code: KeyCode) -> Option<Action> {
        if self.active_tab().has_modal() {
            let action = self.active_tab_mut().handle_key(code);
            self.collect_ops();
            return action;
        }

        if self.ssh_loading {
            return None;
        }

        let action = match self.focus {
            Focus::TabBar => self.handle_tab_bar_key(code),
            Focus::List => self.handle_list_key(code),
        };
        self.collect_ops();
        action
    }

    fn handle_tab_bar_key(&mut self, code: KeyCode) -> Option<Action> {
        match code {
            KeyCode::Left | KeyCode::Char('h') => {
                self.tab = self.tab.prev();
                None
            }
            KeyCode::Right | KeyCode::Char('l') => {
                self.tab = self.tab.next();
                None
            }
            KeyCode::Down
            | KeyCode::Char('j')
            | KeyCode::Tab
            | KeyCode::Enter
            | KeyCode::BackTab => {
                self.focus = Focus::List;
                None
            }
            KeyCode::Esc => Some(Action::Back),
            _ => None,
        }
    }

    fn handle_list_key(&mut self, code: KeyCode) -> Option<Action> {
        match code {
            KeyCode::Up | KeyCode::Char('k' | 'j') | KeyCode::Down => {
                self.active_tab_mut().handle_key(code)
            }
            KeyCode::Tab | KeyCode::BackTab => {
                self.focus = Focus::TabBar;
                None
            }
            KeyCode::Esc => Some(Action::Back),
            _ => self.active_tab_mut().handle_key(code),
        }
    }

    /// Handle a mouse event: tab clicks, hover, and the active tab's events.
    pub fn handle_mouse(&mut self, mouse: MouseEvent) -> Option<Action> {
        if self.active_tab().has_modal() {
            self.active_tab_mut().handle_mouse(mouse);
            self.collect_ops();
            return None;
        }

        if self.ssh_loading {
            return None;
        }

        match mouse.kind {
            MouseEventKind::Moved | MouseEventKind::Drag(_) => {
                self.hovered_tab = self.tab_at(mouse.column, mouse.row);
                self.active_tab_mut().handle_mouse(mouse);
            }
            MouseEventKind::Down(MouseButton::Left) => {
                if let Some(idx) = self.tab_at(mouse.column, mouse.row) {
                    self.tab = SshSection::all()[idx];
                    self.focus = Focus::TabBar;
                } else {
                    self.focus = Focus::List;
                    self.active_tab_mut().handle_mouse(mouse);
                }
            }
            MouseEventKind::ScrollDown | MouseEventKind::ScrollUp | MouseEventKind::Up(_) => {
                self.active_tab_mut().handle_mouse(mouse);
            }
            _ => {}
        }
        self.collect_ops();
        None
    }

    fn tab_at(&self, col: u16, row: u16) -> Option<usize> {
        self.tab_hitboxes.iter().position(|rect| {
            col >= rect.x && col < rect.right() && row >= rect.y && row < rect.bottom()
        })
    }

    fn active_tab(&self) -> &dyn SshTab {
        match self.tab {
            SshSection::Security => &self.security,
            SshSection::Keys => &self.keys,
            SshSection::KnownHosts => &self.known_hosts,
            SshSection::Config => &self.config,
            SshSection::Agent => &self.agent,
            SshSection::Forwarding => &self.forwarding,
            SshSection::Diagnostics => &self.diagnostics,
            SshSection::AuthorizedKeys => &self.authorized_keys,
            SshSection::Certificates => &self.certificates,
        }
    }

    fn active_tab_mut(&mut self) -> &mut dyn SshTab {
        match self.tab {
            SshSection::Security => &mut self.security,
            SshSection::Keys => &mut self.keys,
            SshSection::KnownHosts => &mut self.known_hosts,
            SshSection::Config => &mut self.config,
            SshSection::Agent => &mut self.agent,
            SshSection::Forwarding => &mut self.forwarding,
            SshSection::Diagnostics => &mut self.diagnostics,
            SshSection::AuthorizedKeys => &mut self.authorized_keys,
            SshSection::Certificates => &mut self.certificates,
        }
    }

    /// Render the tab bar, loading/error lines, and the active tab.
    pub fn view(&mut self, frame: &mut Frame, area: Rect, p: Palette) {
        self.clear_expired_error();

        let loading_h = u16::from(self.ssh_loading);
        let error_h = u16::from(self.last_error.is_some());

        let mut constraints = vec![Constraint::Length(1), Constraint::Length(1)];
        if loading_h > 0 {
            constraints.push(Constraint::Length(loading_h));
        }
        if error_h > 0 {
            constraints.push(Constraint::Length(error_h));
        }
        constraints.push(Constraint::Min(0));

        let rects = Layout::vertical(constraints).split(area);
        let mut i = 0;

        let tab_bar_area = rects[i];
        i += 1;
        let _ = rects[i];
        i += 1;

        if loading_h > 0 {
            let loading_area = rects[i];
            i += 1;
            self.render_loading_bar(frame, loading_area, p);
        }

        if error_h > 0 {
            let error_area = rects[i];
            i += 1;
            if let Some((msg, _)) = &self.last_error {
                let error_line = Line::from(vec![
                    Span::styled(" ⚠ ", Style::new().fg(p.err).add_modifier(Modifier::BOLD)),
                    Span::styled(
                        truncate_error(msg, error_area.width.saturating_sub(3) as usize),
                        Style::new().fg(p.err),
                    ),
                ]);
                frame.render_widget(Paragraph::new(error_line), error_area);
            }
        }

        let content_area = rects[i];
        self.render_tab_bar(frame, tab_bar_area, p);
        self.active_tab_mut().view(frame, content_area, p);
    }

    #[expect(
        clippy::cast_possible_truncation,
        reason = "terminal cols/rows are bounded < u16::MAX"
    )]
    fn render_tab_bar(&mut self, frame: &mut Frame, area: Rect, p: Palette) {
        self.tab_hitboxes.clear();
        let tabs = SshSection::all();
        let mut x = area.x;

        for (i, tab) in tabs.iter().enumerate() {
            let is_active = *tab == self.tab;
            let is_focused = self.focus == Focus::TabBar && is_active;
            let is_hovered = self.hovered_tab == Some(i);

            if i > 0 {
                x += 2;
            }

            let label = format!(" {} ", tab.label());
            let label_w = label.len() as u16;

            self.tab_hitboxes.push(Rect::new(x, area.y, label_w, 1));

            let style = if is_active && (is_focused || is_hovered) {
                Style::new()
                    .fg(p.bg)
                    .bg(p.accent)
                    .add_modifier(Modifier::BOLD)
            } else if is_hovered {
                Style::new().fg(p.accent)
            } else if is_active {
                Style::new().fg(p.accent).add_modifier(Modifier::BOLD)
            } else {
                Style::new().fg(p.text_dim)
            };

            let tab_area = Rect::new(x, area.y, label_w, 1);
            frame.render_widget(
                Paragraph::new(Line::from(Span::styled(label, style))),
                tab_area,
            );

            x += label_w;
        }
    }
}

impl Default for SshContent {
    fn default() -> Self {
        Self::new()
    }
}

trait SshTab {
    fn handle_key(&mut self, code: KeyCode) -> Option<Action>;
    fn handle_mouse(&mut self, _mouse: MouseEvent) -> Option<Action> {
        None
    }
    fn view(&mut self, frame: &mut Frame, area: Rect, p: Palette);
    fn has_modal(&self) -> bool {
        false
    }
    #[allow(dead_code)]
    fn close_modal(&mut self) {}
    fn drain_ops(&mut self) -> Vec<SshOp> {
        Vec::new()
    }
}

/// One key file in `~/.ssh`.
#[derive(Clone, Debug)]
pub struct SshKeyEntry {
    /// Key file name (e.g. `id_ed25519`).
    pub name: String,
    /// Key type label (e.g. "Ed25519", "RSA 4096").
    pub key_type: String,
    /// SHA-256 fingerprint (truncated for display).
    pub fingerprint: String,
    /// Whether the private key is passphrase-encrypted.
    pub encrypted: bool,
    /// Octal permissions string (e.g. "0600").
    pub permissions: String,
    /// Whether a matching `.pub` file exists.
    pub has_public: bool,
    /// Whether a matching `-cert.pub` file exists.
    pub has_cert: bool,
    /// Host aliases in ~/.ssh/config that reference this key via `IdentityFile`.
    pub used_by_hosts: Vec<String>,
}

impl SshKeyEntry {
    /// Number of host aliases referencing this key.
    #[must_use]
    pub fn host_count(&self) -> usize {
        self.used_by_hosts.len()
    }
}

/// One `known_hosts` entry; multiple key lines for the same host are
/// grouped (see `key_types` / `fingerprints`).
#[derive(Clone, Debug)]
pub struct KnownHostEntry {
    /// All hostname patterns (e.g. `["github.com", "gh.com"]`).
    pub hosts: Vec<String>,
    /// Key type of the first line (used as primary label).
    pub key_type: String,
    /// All key types for this host (e.g. `["ssh-ed25519", "ecdsa-sha2-nistp256", "ssh-rsa"]`).
    pub key_types: Vec<String>,
    /// SHA-256 fingerprint of the first key.
    pub fingerprint: String,
    /// All fingerprints, one per key type (same order as `key_types`).
    pub fingerprints: Vec<String>,
    /// Whether the hostname is hashed (`|1|...`).
    pub is_hashed: bool,
    /// Optional marker (e.g. "@cert-authority", "@revoked").
    pub marker: Option<String>,
    /// Trailing comment on the line, when present.
    pub comment: Option<String>,
    /// 1-based line number in the `known_hosts` file (first occurrence).
    pub line: usize,
    /// Source file: "user" or "global".
    pub source: String,
}

impl KnownHostEntry {
    /// Primary host name (first pattern, or "(hashed)" if all are hashed).
    #[must_use]
    pub fn primary_host(&self) -> &str {
        self.hosts.first().map_or("(hashed)", |s| s.as_str())
    }
}

/// One `Host` block from the SSH config.
#[derive(Clone, Debug)]
pub struct ConfigHostEntry {
    /// Primary Host name / pattern (e.g. "myserver", "*.example.com").
    pub name: String,
    /// All Host patterns in the block.
    pub patterns: Vec<String>,
    /// `HostName` directive value, when set.
    pub host_name: Option<String>,
    /// `User` directive value, when set.
    pub user: Option<String>,
    /// `Port` directive value, when set.
    pub port: Option<u16>,
    /// `IdentityFile` directive value, when set.
    pub identity_file: Option<String>,
    /// `ProxyJump` directive value, when set.
    pub proxy_jump: Option<String>,
    /// Number of directives in the block.
    pub directive_count: usize,
    /// Whether the config doctor flagged this block.
    pub has_diagnostic: bool,
}

/// One key held by the ssh-agent.
#[derive(Clone, Debug)]
pub struct AgentKeyEntry {
    /// Key file name or comment.
    pub name: String,
    /// Key type label (e.g. "Ed25519", "RSA 4096").
    pub key_type: String,
    /// SHA-256 fingerprint.
    pub fingerprint: String,
    /// Whether the key is locked.
    pub is_locked: bool,
    /// Whether the key was added with constraints.
    pub has_constraints: bool,
}

/// ssh-agent reachability and contents.
#[derive(Clone, Debug)]
pub struct AgentStatus {
    /// Whether the agent socket answers.
    pub reachable: bool,
    /// Agent socket path; `None` when not found.
    pub socket_path: Option<String>,
    /// Number of keys the agent holds.
    pub key_count: usize,
}

/// One `ControlMaster` session and its forwards.
#[derive(Clone, Debug)]
pub struct ForwardSessionEntry {
    /// Remote host label.
    pub host: String,
    /// Control socket path.
    pub control_path: String,
    /// Master process PID, when known.
    pub pid: Option<u32>,
    /// Time since the session was established (e.g. "2h 15m").
    pub established_ago: String,
    /// Active forwards.
    pub forwards: Vec<ForwardEntry>,
    /// Total forward count.
    pub forward_count: usize,
}

/// One active port forward.
#[derive(Clone, Debug)]
pub struct ForwardEntry {
    /// Forward type: "local", "remote", or "dynamic".
    pub forward_type: String,
    /// Local bind address.
    pub local_addr: String,
    /// Local port.
    pub local_port: u16,
    /// Remote target address (or "SOCKS" for dynamic).
    pub remote_addr: String,
    /// Remote port.
    pub remote_port: u16,
}

/// One SSH doctor diagnostic.
#[derive(Clone, Debug)]
pub struct DiagnosticEntry {
    /// Diagnostic id.
    pub id: String,
    /// Severity level: "ok", "info", "warning", "error".
    pub severity: String,
    /// Source module (e.g. "local", "config", "agent").
    pub module: String,
    /// Human-readable message.
    pub message: String,
    /// Optional fix hint.
    pub hint: Option<String>,
}

/// One `authorized_keys` line.
#[derive(Clone, Debug)]
pub struct AuthorizedKeyEntry {
    /// Key type (e.g. "ssh-ed25519", "ssh-rsa").
    pub key_type: String,
    /// Public key data (truncated for display).
    pub public_key: String,
    /// Key comment, when present.
    pub comment: Option<String>,
    /// SHA-256 fingerprint.
    pub fingerprint: String,
    /// Parsed options string (e.g. 'command="...",no-port-forwarding').
    pub options: Option<String>,
    /// 1-based line number in the file.
    pub line: usize,
}

/// One SSH certificate.
#[derive(Clone, Debug)]
pub struct CertificateEntry {
    /// Certificate file name.
    pub name: String,
    /// Certificate type ("User" or "Host").
    pub cert_type: String,
    /// Key type (e.g. "ssh-ed25519-cert-v01@openssh.com").
    pub key_type: String,
    /// Certificate serial number.
    pub serial: u64,
    /// Valid from (ISO 8601-ish).
    pub valid_from: String,
    /// Valid to (ISO 8601-ish).
    pub valid_to: String,
    /// Whether now is inside the validity window.
    pub is_valid: bool,
    /// SHA-256 fingerprint of the signing CA.
    pub ca_fingerprint: String,
    /// Certificate key id.
    pub key_id: String,
    /// Valid principals.
    pub principals: Vec<String>,
}

/// Parsed `sshd_config` access policy.
#[derive(Debug, Clone, Default)]
pub struct SshAccessInfo {
    /// Whether `sshd_config` was readable; when `false` every other field is
    /// a default, not a real observation.
    pub available: bool,
    /// Users allowed via `AllowUsers` (empty = all allowed).
    pub allowed_users: Vec<String>,
    /// Users denied via `DenyUsers`.
    pub denied_users: Vec<String>,
    /// Groups allowed via `AllowGroups` (empty = all allowed).
    pub allowed_groups: Vec<String>,
    /// Groups denied via `DenyGroups`.
    pub denied_groups: Vec<String>,
    /// Allowed authentication methods.
    pub auth_methods: Vec<String>,
    /// Whether password authentication is enabled.
    pub password_auth: bool,
    /// Whether public-key authentication is enabled.
    pub pubkey_auth: bool,
    /// Root login policy (yes/no/prohibit-password/forced-commands-only).
    pub permit_root_login: String,
}

/// One system user with SSH-relevant details.
#[derive(Debug, Clone)]
pub struct SystemUserInfo {
    /// User name.
    pub username: String,
    /// Login shell.
    pub shell: String,
    /// Home directory.
    pub home_dir: String,
    /// Key count in the user's `~/.ssh`.
    pub ssh_key_count: usize,
    /// Line count of the user's `authorized_keys`.
    pub authorized_key_count: usize,
    /// Preview `authorized_keys` entries for the detail modal; empty when
    /// unreadable (e.g. another user's file without root).
    pub authorized_keys_preview: Vec<AuthorizedKeyPreview>,
}

/// Preview of one `authorized_keys` line for the detail modal.
#[derive(Debug, Clone)]
pub struct AuthorizedKeyPreview {
    /// Key type (e.g. `ssh-ed25519`).
    pub key_type: String,
    /// Trailing comment, when present.
    pub comment: Option<String>,
    /// SHA-256 fingerprint of the public key.
    pub fingerprint: String,
    /// 1-based line number in the `authorized_keys` file.
    pub line: usize,
}

pub(crate) fn char_to_keycode(c: char) -> KeyCode {
    match c {
        '\r' => KeyCode::Enter,
        '\x1b' => KeyCode::Esc,
        c => KeyCode::Char(c),
    }
}

fn truncate_error(msg: &str, max_width: usize) -> String {
    if msg.chars().count() <= max_width {
        msg.to_string()
    } else if max_width > 2 {
        let truncated: String = msg.chars().take(max_width.saturating_sub(2)).collect();
        format!("{truncated}..")
    } else {
        String::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_expiry_truth_table() {
        let mut content = SshContent::new();
        assert!(!content.error_showing());
        assert!(!content.error_expired());

        content.push_error("write failed".into());
        assert!(content.error_showing());
        assert!(!content.error_expired(), "a fresh toast is not expired");

        if let Some(ts) = Instant::now().checked_sub(std::time::Duration::from_secs(6)) {
            content.last_error = Some(("write failed".into(), ts));
            assert!(
                content.error_showing(),
                "the toast stays shown until a draw clears it"
            );
            assert!(
                content.error_expired(),
                "past the TTL it must report expired"
            );
        }
    }

    #[test]
    fn pending_fingerprints_flag_follows_key_rows() {
        let mut content = SshContent::new();
        assert!(
            !content.has_pending_fingerprints(),
            "no keys → no spinner rows"
        );
        content.set_keys(vec![SshKeyEntry {
            name: "id_ed25519".into(),
            key_type: "Ed25519".into(),
            fingerprint: "SHA256:abc123".into(),
            encrypted: false,
            permissions: "0600".into(),
            has_public: true,
            has_cert: false,
            used_by_hosts: Vec::new(),
        }]);
        assert!(
            !content.has_pending_fingerprints(),
            "a filled fingerprint renders text, not a spinner"
        );
        content.set_keys(vec![SshKeyEntry {
            name: "id_new".into(),
            key_type: "Ed25519".into(),
            fingerprint: String::new(),
            encrypted: false,
            permissions: "0600".into(),
            has_public: false,
            has_cert: false,
            used_by_hosts: Vec::new(),
        }]);
        assert!(
            content.has_pending_fingerprints(),
            "an empty fingerprint row spins"
        );
    }

    #[test]
    fn new_defaults_to_security_tab() {
        let content = SshContent::new();
        assert_eq!(content.tab(), SshSection::Security);
    }

    #[test]
    fn default_matches_new() {
        let from_new = SshContent::new();
        let from_default = SshContent::default();
        assert_eq!(from_new.tab(), from_default.tab());
    }

    #[test]
    fn render_snapshot() {
        use crate::ui::theme::CHARM;
        use ratatui::{Terminal, backend::TestBackend};

        let mut content = SshContent::new();
        let mut terminal = Terminal::new(TestBackend::new(120, 36)).unwrap();
        terminal.draw(|f| content.view(f, f.area(), CHARM)).unwrap();
        let output = terminal.backend().to_string();
        assert!(output.contains("Security"), "tab bar visible: {output}");
    }

    #[test]
    fn render_snapshot_with_keys() {
        use crate::ui::theme::CHARM;
        use ratatui::{Terminal, backend::TestBackend};

        let mut content = SshContent::new();
        content.tab = SshSection::Keys;
        content.set_keys(vec![SshKeyEntry {
            name: "id_ed25519".into(),
            key_type: "Ed25519".into(),
            fingerprint: "SHA256:abc123".into(),
            encrypted: true,
            permissions: "0600".into(),
            has_public: true,
            has_cert: false,
            used_by_hosts: vec!["github.com".into(), "gh.com".into()],
        }]);
        let mut terminal = Terminal::new(TestBackend::new(120, 36)).unwrap();
        terminal.draw(|f| content.view(f, f.area(), CHARM)).unwrap();
        let output = terminal.backend().to_string();
        assert!(output.contains("id_ed25519"), "key name visible: {output}");
    }

    #[test]
    fn tab_cycling_left_right() {
        let mut content = SshContent::new();
        content.focus = Focus::TabBar;
        assert_eq!(content.tab(), SshSection::Security);
        content.handle_key(KeyCode::Right);
        assert_eq!(content.tab(), SshSection::Keys);
        content.handle_key(KeyCode::Right);
        assert_eq!(content.tab(), SshSection::KnownHosts);
        content.handle_key(KeyCode::Left);
        assert_eq!(content.tab(), SshSection::Keys);
    }

    #[test]
    fn tab_bar_to_list_on_down() {
        let mut content = SshContent::new();
        content.focus = Focus::TabBar;
        content.handle_key(KeyCode::Down);
        assert_eq!(content.focus, Focus::List);
    }

    #[test]
    fn list_to_tab_bar_on_tab() {
        let mut content = SshContent::new();
        content.focus = Focus::List;
        content.handle_key(KeyCode::Tab);
        assert_eq!(content.focus, Focus::TabBar);
    }

    #[test]
    fn all_tabs_render_without_panic() {
        use crate::ui::theme::CHARM;
        use ratatui::{Terminal, backend::TestBackend};

        for section in SshSection::all() {
            let mut content = SshContent::new();
            content.tab = *section;
            let mut terminal = Terminal::new(TestBackend::new(120, 36)).unwrap();
            terminal.draw(|f| content.view(f, f.area(), CHARM)).unwrap();
        }
    }

    #[test]
    fn queue_ops_front_preserves_held_order_ahead_of_new() {
        let mut content = SshContent::new();
        content.push_op(SshOp::SshdAllowUser {
            username: "held-first".into(),
        });

        let drained = content.drain_pending_ops();
        assert_eq!(drained.len(), 1);
        content.push_op(SshOp::SshdDenyUser {
            username: "queued-later".into(),
        });

        content.queue_ops_front(drained);

        let order = content
            .drain_pending_ops()
            .into_iter()
            .map(|op| match op {
                SshOp::SshdAllowUser { username } | SshOp::SshdDenyUser { username } => username,
                other => format!("unexpected:{other:?}"),
            })
            .collect::<Vec<_>>();
        assert_eq!(
            order,
            vec!["held-first".to_string(), "queued-later".to_string()],
            "held ops must drain ahead of newly-queued ops"
        );
    }
}
