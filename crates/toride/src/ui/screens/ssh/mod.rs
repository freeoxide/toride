//! SSH management content area.
//!
//! Renders inside the dashboard's content region when [`Section::Ssh`](crate::data::Section)
//! is the active sidebar section. Provides a horizontal sub-tab bar for each SSH
//! subsystem and delegates rendering and input handling to the active tab.

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
    /// Pending write operations to be executed by the app's event loop.
    pending_ops: Vec<SshOp>,
    /// Last write error message + timestamp, shown as a notification bar.
    last_error: Option<(String, Instant)>,
    /// Whether SSH write operations are in-flight (drives spinner overlay).
    ssh_loading: bool,
    /// Number of SSH ops currently in-flight (displayed in loading bar).
    ssh_ops_in_flight: usize,
    /// Timestamp when loading started (drives braille spinner animation).
    loading_start: Instant,
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
            pending_ops: Vec::new(),
            last_error: None,
            ssh_loading: false,
            ssh_ops_in_flight: 0,
            loading_start: Instant::now(),
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

    /// Push a pending write operation to be executed by the app's event loop.
    pub fn push_op(&mut self, op: SshOp) {
        self.pending_ops.push(op);
    }

    /// Drain all pending write operations, transferring them to the caller.
    pub fn drain_pending_ops(&mut self) -> Vec<SshOp> {
        std::mem::take(&mut self.pending_ops)
    }

    /// Re-queue write operations at the FRONT of the pending queue.
    ///
    /// The app's serialized write loop drains ops into a background task and,
    /// while that task is in-flight, may drain again (e.g. a confirm-modal 'y'
    /// lands during a write). To avoid spawning a second concurrent task, it
    /// calls this to hand the ops back. Placing them ahead of any ops the UI
    /// queues in the meantime keeps the user's original ordering intact.
    pub fn queue_ops_front(&mut self, mut ops: Vec<SshOp>) {
        ops.append(&mut self.pending_ops);
        self.pending_ops = ops;
    }

    /// Drain ops from the active tab and forward them to our `pending_ops`.
    fn collect_ops(&mut self) {
        let ops = self.active_tab_mut().drain_ops();
        self.pending_ops.extend(ops);
    }

    /// Push a write error to be shown as a notification bar.
    pub fn push_error(&mut self, msg: String) {
        self.last_error = Some((msg, Instant::now()));
    }

    /// Clear the error notification if it's been shown for more than 5 seconds.
    fn clear_expired_error(&mut self) {
        if let Some((_, ts)) = &self.last_error
            && ts.elapsed().as_secs() >= 5
        {
            self.last_error = None;
        }
    }

    /// Update the loading state from the app's in-flight counter.
    pub fn set_loading(&mut self, loading: bool, count: usize) {
        if loading && !self.ssh_loading {
            self.loading_start = Instant::now();
        }
        self.ssh_loading = loading;
        self.ssh_ops_in_flight = count;
    }

    /// Whether SSH write ops are currently in-flight.
    #[must_use]
    pub fn is_loading(&self) -> bool {
        self.ssh_loading
    }

    /// Render the loading spinner bar.
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
        // Freeze the spinner frame under reduced motion — the bar still signals
        // "applying changes…" (and the remaining-op count) without per-frame cycling.
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
        // A modal (detail / confirm) must ALWAYS be closable — even while a
        // write is in flight — otherwise the user is frozen out of the modal
        // they just opened. Route modal input (Esc to close, action keys)
        // BEFORE the loading gate; the gate only applies to non-modal list
        // navigation below.
        if self.active_tab().has_modal() {
            let action = self.active_tab_mut().handle_key(code);
            self.collect_ops();
            return action;
        }

        // No modal: block non-modal list navigation while SSH write ops are
        // in-flight (the list is being mutated optimistically; the loading
        // spinner overlay reflects this).
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
                // Delegate up/down to the active tab's handle_key
                self.active_tab_mut().handle_key(code)
            }
            KeyCode::Tab | KeyCode::BackTab => {
                self.focus = Focus::TabBar;
                None
            }
            KeyCode::Esc => Some(Action::Back),
            // Delegate remaining keys to the active tab.
            _ => self.active_tab_mut().handle_key(code),
        }
    }

    /// Handle a mouse event for the SSH content area.
    pub fn handle_mouse(&mut self, mouse: MouseEvent) -> Option<Action> {
        // A modal must always be interactable (click-outside-to-close, confirm
        // button clicks) — route modal input BEFORE the loading gate so a write
        // in flight can't freeze the user inside a modal.
        if self.active_tab().has_modal() {
            self.active_tab_mut().handle_mouse(mouse);
            self.collect_ops();
            return None;
        }

        // No modal: block non-modal interaction while SSH write ops are in-flight.
        if self.ssh_loading {
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
            MouseEventKind::ScrollDown | MouseEventKind::ScrollUp | MouseEventKind::Up(_) => {
                self.active_tab_mut().handle_mouse(mouse);
            }
            _ => {}
        }
        self.collect_ops();
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
        self.clear_expired_error();

        let loading_h = u16::from(self.ssh_loading);
        let error_h = u16::from(self.last_error.is_some());

        // Split into tab bar + optional loading bar + optional error bar + content area
        let mut constraints = vec![
            Constraint::Length(1), // tab bar
            Constraint::Length(1), // gap
        ];
        if loading_h > 0 {
            constraints.push(Constraint::Length(loading_h)); // loading bar
        }
        if error_h > 0 {
            constraints.push(Constraint::Length(error_h)); // error bar
        }
        constraints.push(Constraint::Min(0)); // content

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
    #[allow(dead_code)]
    fn close_modal(&mut self) {}
    /// Drain pending write operations queued by this tab.
    fn drain_ops(&mut self) -> Vec<SshOp> {
        Vec::new()
    }
}

// ── Data entry structs ───────────────────────────────────────────────────────

/// Lightweight presentation model for an SSH key row in the Keys tab.
#[derive(Clone, Debug)]
pub struct SshKeyEntry {
    /// File name (e.g. "`id_ed25519`").
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
    /// Host aliases in ~/.ssh/config that reference this key via `IdentityFile`.
    pub used_by_hosts: Vec<String>,
}

impl SshKeyEntry {
    /// Number of config hosts referencing this key.
    ///
    /// Computed from `used_by_hosts.len()` to avoid denormalization drift.
    #[must_use]
    pub fn host_count(&self) -> usize {
        self.used_by_hosts.len()
    }
}

/// Presentation model for a `known_hosts` entry in the Hosts tab.
///
/// Multiple key lines for the same host are **grouped** into a single entry
/// with `key_types` listing all algorithms and `fingerprints` the matching FP.
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
    /// Actual comment text from the entry.
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

/// Presentation model for an SSH config Host block in the Config tab.
#[derive(Clone, Debug)]
pub struct ConfigHostEntry {
    /// Primary Host name / pattern (e.g. "myserver", "*.example.com").
    pub name: String,
    /// All Host patterns in the block.
    pub patterns: Vec<String>,
    /// `HostName` directive value, if set.
    pub host_name: Option<String>,
    /// User directive value, if set.
    pub user: Option<String>,
    /// Port directive value, if set.
    pub port: Option<u16>,
    /// `IdentityFile` directive value, if set.
    pub identity_file: Option<String>,
    /// `ProxyJump` directive value, if set.
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
    /// `ControlMaster` socket path.
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
    /// Check identifier (e.g. "`ssh_dir_permissions`").
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
    /// Line number in the `authorized_keys` file.
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

/// SSH server access control information parsed from `sshd_config`.
#[derive(Debug, Clone, Default)]
pub struct SshAccessInfo {
    /// Whether `sshd_config` was found and readable on this machine.
    /// When false, all other fields are defaults — the UI should hide
    /// sections that depend on server config rather than showing
    /// misleading empty states.
    pub available: bool,
    /// Users allowed via `AllowUsers` (empty = all allowed).
    pub allowed_users: Vec<String>,
    /// Users denied via `DenyUsers`.
    pub denied_users: Vec<String>,
    /// Groups allowed via `AllowGroups` (empty = all allowed).
    pub allowed_groups: Vec<String>,
    /// Groups denied via `DenyGroups`.
    pub denied_groups: Vec<String>,
    /// Authentication methods from `AuthenticationMethods` directive.
    pub auth_methods: Vec<String>,
    /// Whether password authentication is enabled.
    pub password_auth: bool,
    /// Whether public key authentication is enabled.
    pub pubkey_auth: bool,
    /// Root login policy (yes/no/prohibit-password/forced-commands-only).
    pub permit_root_login: String,
}

/// A system user with SSH-relevant information.
#[derive(Debug, Clone)]
pub struct SystemUserInfo {
    /// Username.
    pub username: String,
    /// Login shell path.
    pub shell: String,
    /// Home directory path.
    pub home_dir: String,
    /// Number of SSH key pairs (private keys like `id_ed25519`, `id_rsa`) in ~/.ssh/.
    pub ssh_key_count: usize,
    /// Number of entries in `authorized_keys` (keys that can log in as this user).
    pub authorized_key_count: usize,
    /// Up to a handful of `authorized_keys` entries for the user detail modal.
    /// Empty when unreadable (e.g. another user's file without root).
    pub authorized_keys_preview: Vec<AuthorizedKeyPreview>,
}

/// A compact view of one `authorized_keys` entry, for the user detail modal.
#[derive(Debug, Clone)]
pub struct AuthorizedKeyPreview {
    /// Key type (e.g. `ssh-ed25519`).
    pub key_type: String,
    /// Trailing comment, if any.
    pub comment: Option<String>,
    /// SHA-256 fingerprint of the public key.
    pub fingerprint: String,
    /// 1-based line number in the `authorized_keys` file.
    pub line: usize,
}

/// Convert a footer-button action char back to the corresponding [`KeyCode`].
///
/// Footer buttons use `char` as their action type.  This maps the char to the
/// `KeyCode` that the tab's `handle_key` already knows how to process.
pub(crate) fn char_to_keycode(c: char) -> KeyCode {
    match c {
        '\r' => KeyCode::Enter,
        '\x1b' => KeyCode::Esc,
        c => KeyCode::Char(c),
    }
}

/// Truncate an error message to fit within `max_width` characters.
/// Uses character-based truncation to avoid panicking on multi-byte UTF-8.
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
        // The serialized write loop hands ops back to the front of the queue
        // when a batch is already in-flight. The held ops must come back out
        // FIRST (preserving the user's original ordering), ahead of anything
        // the UI queued in the meantime.
        let mut content = SshContent::new();
        content.push_op(SshOp::SshdAllowUser {
            username: "held-first".into(),
        });

        let drained = content.drain_pending_ops();
        assert_eq!(drained.len(), 1);
        // Simulate the UI queuing a new op while the batch is in-flight.
        content.push_op(SshOp::SshdDenyUser {
            username: "queued-later".into(),
        });

        // App hands the held ops back to the front.
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
