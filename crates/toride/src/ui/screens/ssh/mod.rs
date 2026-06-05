//! SSH management content area.
//!
//! Renders inside the dashboard's content region when [`Section::Ssh`](crate::data::Section)
//! is the active sidebar section. Provides a horizontal sub-tab bar for each SSH
//! subsystem and delegates rendering and input handling to the active tab.

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
use crate::ui::theme::Palette;
use crate::ui::widgets::render_panel;

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

// ── Focus ────────────────────────────────────────────────────────────────────

/// Which region currently has keyboard focus within the SSH content area.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Focus {
    /// The sub-tab bar at the top.
    TabBar,
    /// The main content list below the tab bar.
    List,
}

// ── SshContent ───────────────────────────────────────────────────────────────

/// SSH management content rendered inside the dashboard content area.
///
/// Owns all sub-tab state and delegates rendering/input to the active tab.
pub struct SshContent {
    /// Currently active sub-tab.
    tab: SshSection,
    /// Which region has keyboard focus.
    focus: Focus,
    /// Security overview sub-tab state.
    security: SecurityTab,
    /// Keys sub-tab state.
    keys: KeysTab,
    /// Known hosts sub-tab state.
    known_hosts: KnownHostsTab,
    /// Config sub-tab state.
    config: ConfigTab,
    /// Agent sub-tab state.
    agent: AgentTab,
    /// Forwarding sub-tab state.
    forwarding: ForwardingTab,
    /// Diagnostics sub-tab state.
    diagnostics: DiagnosticsTab,
    /// Authorized keys sub-tab state.
    authorized_keys: AuthorizedKeysTab,
    /// Certificates sub-tab state.
    certificates: CertificatesTab,
    /// Hitbox rects for tab bar labels (rebuilt each frame).
    tab_hitboxes: Vec<Rect>,
    /// Which tab is hovered by the mouse.
    hovered_tab: Option<usize>,
}

impl SshContent {
    /// Create a new SSH content area with default state.
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
        }
    }

    /// Currently active sub-tab.
    #[must_use]
    pub fn tab(&self) -> SshSection {
        self.tab
    }

    /// Whether the active sub-tab has a modal currently open.
    #[must_use]
    pub fn has_modal(&self) -> bool {
        self.active_tab().has_modal()
    }

    // ── Data setters ─────────────────────────────────────────────────────────

    /// Provide live SSH key data (called from the data collector).
    pub fn set_keys(&mut self, keys: Vec<SshKeyEntry>) {
        self.keys.set_keys(keys);
    }

    /// Provide known hosts data.
    pub fn set_known_hosts(&mut self, hosts: Vec<KnownHostEntry>) {
        self.known_hosts.set_hosts(hosts);
    }

    /// Provide SSH config host entries.
    pub fn set_config_hosts(&mut self, hosts: Vec<ConfigHostEntry>) {
        self.config.set_hosts(hosts);
    }

    /// Provide SSH agent status and loaded keys.
    pub fn set_agent_data(&mut self, status: AgentStatus, keys: Vec<AgentKeyEntry>) {
        self.agent.set_data(status, keys);
    }

    /// Provide forwarding session data.
    pub fn set_forwarding(&mut self, sessions: Vec<ForwardSessionEntry>) {
        self.forwarding.set_sessions(sessions);
    }

    /// Provide diagnostic entries.
    pub fn set_diagnostics(&mut self, entries: Vec<DiagnosticEntry>) {
        self.diagnostics.set_entries(entries);
    }

    /// Provide authorized keys data.
    pub fn set_authorized_keys(&mut self, entries: Vec<AuthorizedKeyEntry>) {
        self.authorized_keys.set_entries(entries);
    }

    /// Provide certificate data.
    pub fn set_certificates(&mut self, entries: Vec<CertificateEntry>) {
        self.certificates.set_entries(entries);
    }

    /// Provide security overview data.
    pub fn set_security(&mut self, data: crate::ssh_data::SshSecurityData) {
        self.security.set_data(data);
    }

    // ── Input handling ──────────────────────────────────────────────────────

    /// Handle a key press. Returns `Some(Action)` for navigation, `None` if consumed.
    pub fn handle_key(&mut self, code: KeyCode) -> Option<Action> {
        // If the active tab has a modal open, route input there first.
        if self.active_tab().has_modal() {
            return self.active_tab_mut().handle_key(code);
        }

        match self.focus {
            Focus::TabBar => self.handle_tab_bar_key(code),
            Focus::List => self.handle_list_key(code),
        }
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
            KeyCode::Down | KeyCode::Char('j') | KeyCode::Tab => {
                self.focus = Focus::List;
                None
            }
            KeyCode::Enter => {
                self.focus = Focus::List;
                None
            }
            KeyCode::Esc => return Some(Action::Back),
            _ => None,
        }
    }

    fn handle_list_key(&mut self, code: KeyCode) -> Option<Action> {
        match code {
            KeyCode::Up | KeyCode::Char('k') | KeyCode::Down | KeyCode::Char('j') => {
                // Delegate up/down to the active tab's handle_key
                self.active_tab_mut().handle_key(code)
            }
            KeyCode::Tab => {
                self.focus = Focus::TabBar;
                None
            }
            KeyCode::Esc => return Some(Action::Back),
            // Delegate remaining keys to the active tab.
            _ => self.active_tab_mut().handle_key(code),
        }
    }

    /// Handle a mouse event for the SSH content area.
    pub fn handle_mouse(&mut self, mouse: MouseEvent) -> Option<Action> {
        // If the active tab has a modal open, delegate to it for
        // click-outside detection.
        if self.active_tab().has_modal() {
            self.active_tab_mut().handle_mouse(mouse);
            return None;
        }

        match mouse.kind {
            MouseEventKind::Moved | MouseEventKind::Drag(_) => {
                self.hovered_tab = self.tab_at(mouse.column, mouse.row);
                self.active_tab_mut().handle_mouse(mouse);
            }
            MouseEventKind::Down(MouseButton::Left) => {
                // Tab bar click takes priority.
                if let Some(idx) = self.tab_at(mouse.column, mouse.row) {
                    self.tab = SshSection::all()[idx];
                    self.focus = Focus::TabBar;
                } else {
                    // Delegate to active tab for list area interaction.
                    self.focus = Focus::List;
                    self.active_tab_mut().handle_mouse(mouse);
                }
            }
            MouseEventKind::ScrollDown | MouseEventKind::ScrollUp => {
                self.active_tab_mut().handle_mouse(mouse);
            }
            _ => {}
        }
        None
    }

    /// Check if a screen coordinate falls within a tab bar label hitbox.
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

    // ── Rendering ───────────────────────────────────────────────────────────

    /// Render the full SSH content area.
    pub fn view(&mut self, frame: &mut Frame, area: Rect, p: Palette) {
        let inner = render_panel(frame, area, None, p.text, p.border, p.bg);

        // Split into tab bar + content area
        let [tab_bar_area, _, content_area] = Layout::vertical([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Min(0),
        ])
        .areas(inner);

        self.render_tab_bar(frame, tab_bar_area, p);
        self.active_tab_mut().view(frame, content_area, p);
    }

    fn render_tab_bar(&mut self, frame: &mut Frame, area: Rect, p: Palette) {
        self.tab_hitboxes.clear();
        let tabs = SshSection::all();
        let mut x = area.x;

        for (i, tab) in tabs.iter().enumerate() {
            let is_active = *tab == self.tab;
            let is_focused = self.focus == Focus::TabBar && is_active;
            let is_hovered = self.hovered_tab == Some(i);

            if i > 0 {
                x += 2; // gap between tabs
            }

            let label = format!(" {} ", tab.label());
            let label_w = label.len() as u16;

            // Record hitbox for mouse detection.
            self.tab_hitboxes.push(Rect::new(x, area.y, label_w, 1));

            let style = if is_active && (is_focused || is_hovered) {
                Style::new()
                    .fg(p.bg)
                    .bg(p.accent)
                    .add_modifier(Modifier::BOLD)
            } else if is_hovered {
                Style::new().fg(p.accent)
            } else if is_active {
                Style::new()
                    .fg(p.accent)
                    .add_modifier(Modifier::BOLD)
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

// ── SshTab trait ─────────────────────────────────────────────────────────────

/// Interface shared by all SSH sub-tabs.
trait SshTab {
    /// Handle a tab-specific key press (including scroll).
    fn handle_key(&mut self, code: KeyCode) -> Option<Action>;
    /// Handle a tab-specific mouse event.
    fn handle_mouse(&mut self, _mouse: MouseEvent) -> Option<Action> {
        None
    }
    /// Render the tab content.
    fn view(&mut self, frame: &mut Frame, area: Rect, p: Palette);
    /// Whether this tab currently has a modal open.
    fn has_modal(&self) -> bool {
        false
    }
    /// Close any open modal on this tab.
    fn close_modal(&mut self) {}
}

// ── Data entry structs ───────────────────────────────────────────────────────

/// Lightweight presentation model for an SSH key row in the Keys tab.
#[derive(Clone, Debug)]
pub struct SshKeyEntry {
    /// File name (e.g. "id_ed25519").
    pub name: String,
    /// Key type label (e.g. "Ed25519", "RSA 4096").
    pub key_type: String,
    /// SHA-256 fingerprint (truncated for display).
    pub fingerprint: String,
    /// Whether the private key is passphrase-encrypted.
    pub encrypted: bool,
    /// Octal permissions string (e.g. "0600").
    pub permissions: String,
    /// Whether the public key file (.pub) exists.
    pub has_public: bool,
    /// Whether a certificate is associated.
    pub has_cert: bool,
    /// Number of config hosts referencing this key.
    pub host_count: usize,
}

/// Presentation model for a known_hosts entry in the Hosts tab.
#[derive(Clone, Debug)]
pub struct KnownHostEntry {
    /// All hostname patterns (e.g. `["github.com", "gh.com"]`).
    pub hosts: Vec<String>,
    /// Key type (e.g. "ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256").
    pub key_type: String,
    /// SHA-256 fingerprint.
    pub fingerprint: String,
    /// Whether the hostname is hashed (`|1|...`).
    pub is_hashed: bool,
    /// Optional marker (e.g. "@cert-authority", "@revoked").
    pub marker: Option<String>,
    /// Actual comment text from the entry.
    pub comment: Option<String>,
    /// 1-based line number in the known_hosts file.
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

/// Presentation model for an SSH config Host block in the Config tab.
#[derive(Clone, Debug)]
pub struct ConfigHostEntry {
    /// Primary Host name / pattern (e.g. "myserver", "*.example.com").
    pub name: String,
    /// All Host patterns in the block.
    pub patterns: Vec<String>,
    /// HostName directive value, if set.
    pub host_name: Option<String>,
    /// User directive value, if set.
    pub user: Option<String>,
    /// Port directive value, if set.
    pub port: Option<u16>,
    /// IdentityFile directive value, if set.
    pub identity_file: Option<String>,
    /// ProxyJump directive value, if set.
    pub proxy_jump: Option<String>,
    /// Total number of directives in the block.
    pub directive_count: usize,
    /// Whether `ssh_config diagnose()` flagged this block.
    pub has_diagnostic: bool,
}

/// Presentation model for a key loaded in the SSH agent.
#[derive(Clone, Debug)]
pub struct AgentKeyEntry {
    /// Key name / comment.
    pub name: String,
    /// Key type label (e.g. "Ed25519", "RSA 4096").
    pub key_type: String,
    /// SHA-256 fingerprint.
    pub fingerprint: String,
    /// Whether the key requires confirmation to use.
    pub is_locked: bool,
    /// Whether the key has constraints (destination, lifetime, confirm).
    pub has_constraints: bool,
}

/// Agent connection status.
#[derive(Clone, Debug)]
pub struct AgentStatus {
    /// Whether the SSH agent is reachable.
    pub reachable: bool,
    /// Agent socket path, if available.
    pub socket_path: Option<String>,
    /// Number of keys loaded in the agent.
    pub key_count: usize,
}

/// Presentation model for an active port-forwarding session.
#[derive(Clone, Debug)]
pub struct ForwardSessionEntry {
    /// Connected host alias or name.
    pub host: String,
    /// ControlMaster socket path.
    pub control_path: String,
    /// Process ID of the SSH session.
    pub pid: Option<u32>,
    /// Time since the session was established (e.g. "2h 15m").
    pub established_ago: String,
    /// Active port forwards in this session.
    pub forwards: Vec<ForwardEntry>,
    /// Number of active forwards (convenience for display).
    pub forward_count: usize,
}

/// A single port forward within a session.
#[derive(Clone, Debug)]
pub struct ForwardEntry {
    /// Forward type: "local", "remote", or "dynamic".
    pub forward_type: String,
    /// Local bind address.
    pub local_addr: String,
    /// Local port number.
    pub local_port: u16,
    /// Remote target address (or "SOCKS" for dynamic).
    pub remote_addr: String,
    /// Remote port number.
    pub remote_port: u16,
}

/// Presentation model for a diagnostic check result.
#[derive(Clone, Debug)]
pub struct DiagnosticEntry {
    /// Check identifier (e.g. "ssh_dir_permissions").
    pub id: String,
    /// Severity level: "ok", "info", "warning", "error".
    pub severity: String,
    /// Source module (e.g. "local", "config", "agent").
    pub module: String,
    /// Human-readable finding message.
    pub message: String,
    /// Suggested fix, if applicable.
    pub hint: Option<String>,
}

/// Presentation model for an `authorized_keys` entry.
#[derive(Clone, Debug)]
pub struct AuthorizedKeyEntry {
    /// Key type (e.g. "ssh-ed25519", "ssh-rsa").
    pub key_type: String,
    /// Public key data (truncated for display).
    pub public_key: String,
    /// Associated comment / identifier.
    pub comment: Option<String>,
    /// SHA-256 fingerprint.
    pub fingerprint: String,
    /// Parsed options string (e.g. 'command="...",no-port-forwarding').
    pub options: Option<String>,
    /// Line number in the authorized_keys file.
    pub line: usize,
}

/// Presentation model for an SSH certificate.
#[derive(Clone, Debug)]
pub struct CertificateEntry {
    /// Associated key file name (e.g. "id_ed25519-cert.pub").
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
    /// Whether the certificate is currently valid.
    pub is_valid: bool,
    /// CA fingerprint that signed this cert.
    pub ca_fingerprint: String,
    /// Key ID string embedded in the certificate.
    pub key_id: String,
    /// Principals allowed by this certificate.
    pub principals: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

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
        terminal
            .draw(|f| content.view(f, f.area(), CHARM))
            .unwrap();
        let output = terminal.backend().to_string();
        assert!(output.contains("Security"), "tab bar visible: {output}");
    }

    #[test]
    fn render_snapshot_with_keys() {
        use crate::ui::theme::CHARM;
        use ratatui::{Terminal, backend::TestBackend};

        let mut content = SshContent::new();
        content.tab = SshSection::Keys;
        content.set_keys(vec![
            SshKeyEntry {
                name: "id_ed25519".into(),
                key_type: "Ed25519".into(),
                fingerprint: "SHA256:abc123".into(),
                encrypted: true,
                permissions: "0600".into(),
                has_public: true,
                has_cert: false,
                host_count: 2,
            },
        ]);
        let mut terminal = Terminal::new(TestBackend::new(120, 36)).unwrap();
        terminal
            .draw(|f| content.view(f, f.area(), CHARM))
            .unwrap();
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
            terminal
                .draw(|f| content.view(f, f.area(), CHARM))
                .unwrap();
        }
    }
}
