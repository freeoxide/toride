//! User & access-control management content area (live READ-ONLY).
//!
//! Renders inside the dashboard's content region when
//! [`Section::Users`](crate::data::Section) is the active sidebar section. This
//! mirrors the read-only fail2ban template: there is no write path, no
//! optimistic update, no cooldown, and no loading spinner — every line is a
//! pure read.
//!
//! Layout (single scrollable pane, no sub-tab bar):
//! 1. Overview — passwd parse note (completeness caveat on macOS).
//! 2. Users table — name, uid, shell, sudo, locked, totp.
//! 3. Groups — name, gid, member count.
//! 4. Sudoers — parsed rules (who / runas / commands / NOPASSWD).
//! 5. Doctor findings — grouped by severity (Critical > Error > Warning > Info).

use crossterm::event::{KeyCode, MouseEvent, MouseEventKind};
use ratatui::{
    Frame,
    layout::Rect,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Paragraph, Wrap},
};

use crate::action::Action;
use crate::ui::responsive::truncate_str;
use crate::ui::theme::Palette;
use crate::ui::widgets::render_titled_panel;

// ── Presentation types ──────────────────────────────────────────────────────

/// A single user row (parsed from `/etc/passwd`, enriched by probes).
#[derive(Clone, Debug)]
pub struct UserEntry {
    /// Login name.
    pub username: String,
    /// User ID (UID).
    pub uid: u32,
    /// Primary group ID (GID).
    pub gid: u32,
    /// GECOS comment field.
    pub gecos: String,
    /// Home directory path.
    pub home: String,
    /// Login shell.
    pub shell: String,
    /// Whether the user has sudo access (`None` if the probe failed).
    pub sudo: Option<bool>,
    /// Whether the account is locked (`None` if the probe failed).
    pub locked: Option<bool>,
    /// Whether TOTP/2FA is configured for the user (`None` if the probe failed).
    pub totp: Option<bool>,
}

/// A single group row (parsed from `/etc/group`).
#[derive(Clone, Debug)]
pub struct GroupEntry {
    /// Group name.
    pub name: String,
    /// Group ID (GID).
    pub gid: u32,
    /// Supplementary member usernames.
    pub members: Vec<String>,
}

/// A parsed sudoers rule.
#[derive(Clone, Debug)]
pub struct SudoersEntry {
    /// Who the rule applies to (user or `%group`).
    pub who: String,
    /// Which hosts the rule applies to (typically `ALL`).
    pub hosts: String,
    /// Which commands the rule applies to.
    pub commands: String,
    /// Whether `NOPASSWD` is set for this rule.
    pub nopasswd: bool,
    /// Optional run-as user (the `(root)` part).
    pub runas: Option<String>,
}

/// A single doctor finding.
#[derive(Clone, Debug)]
pub struct UserFindingEntry {
    /// Machine-readable dot-separated id (e.g. `user.root-login.ssh-enabled`).
    pub id: String,
    /// Severity as a lowercase string: `"ok" | "info" | "warning" | "error" | "critical"`.
    pub severity: String,
    /// Short human-readable title.
    pub title: String,
    /// Longer description (may be empty).
    pub detail: String,
    /// Suggested remediation, if any.
    pub fix: Option<String>,
}

// ── UsersContent ────────────────────────────────────────────────────────────

/// User & access-control content rendered inside the dashboard content area.
///
/// READ-ONLY: there are no write operations, no optimistic updates, no loading
/// spinner, no cooldown. Data arrives via [`UsersContent::set_*`] setters
/// driven by [`UsersCollector`](crate::toride_users_data::UsersCollector).
#[expect(
    clippy::struct_excessive_bools,
    reason = "independent per-file read-success flags"
)]
pub struct UsersContent {
    /// Whether the users backend produced any data at all. `false` only when a
    /// collection task panicked (`JoinError`) — partial reads (some files
    /// missing, e.g. on macOS) keep `available == true` with empty fields.
    available: bool,
    /// Whether `/etc/passwd` was read successfully. Used to render the
    /// completeness caveat: on macOS `/etc/passwd` exists but is NOT the real
    /// account database (Directory Service is), so the table is incomplete.
    passwd_read: bool,
    /// Whether `/etc/shadow` was read successfully (drives the locked badge).
    shadow_read: bool,
    /// Whether `/etc/sudoers` (or a drop-in) was read successfully.
    sudoers_read: bool,
    /// Whether the PAM config for the probed service was read successfully.
    pam_read: bool,
    /// Parsed user rows.
    users: Vec<UserEntry>,
    /// Parsed group rows.
    groups: Vec<GroupEntry>,
    /// Parsed sudoers rules.
    sudoers: Vec<SudoersEntry>,
    /// Doctor findings (cached for 60s between collections).
    findings: Vec<UserFindingEntry>,
    /// Human-readable reason the backend was unreachable, surfaced in the
    /// degraded panel. Populated only when a collection task panicked.
    unavailable_reason: Option<String>,
    /// Vertical scroll offset over the whole pane.
    scroll: usize,
}

impl Default for UsersContent {
    fn default() -> Self {
        Self::new()
    }
}

impl UsersContent {
    /// Create a new empty content area.
    #[must_use]
    pub fn new() -> Self {
        Self {
            available: false,
            passwd_read: false,
            shadow_read: false,
            sudoers_read: false,
            pam_read: false,
            users: Vec::new(),
            groups: Vec::new(),
            sudoers: Vec::new(),
            findings: Vec::new(),
            unavailable_reason: None,
            scroll: 0,
        }
    }

    /// Whether the section has a modal open. Read-only section → never.
    #[must_use]
    pub fn has_modal(&self) -> bool {
        false
    }

    /// Live user count for the sidebar badge. `None` when the backend is
    /// unavailable so the badge stays honestly empty.
    #[must_use]
    pub fn badge_count(&self) -> Option<usize> {
        if self.available {
            Some(self.users.len())
        } else {
            None
        }
    }

    // ── Data setters ─────────────────────────────────────────────────────────

    /// Replace the users list and clamp scroll.
    pub fn set_users(&mut self, users: Vec<UserEntry>) {
        self.users = users;
        self.clamp_scroll();
    }

    /// Replace the groups list and clamp scroll.
    pub fn set_groups(&mut self, groups: Vec<GroupEntry>) {
        self.groups = groups;
        self.clamp_scroll();
    }

    /// Replace the sudoers list and clamp scroll.
    pub fn set_sudoers(&mut self, sudoers: Vec<SudoersEntry>) {
        self.sudoers = sudoers;
        self.clamp_scroll();
    }

    /// Replace the findings list and clamp scroll.
    pub fn set_findings(&mut self, findings: Vec<UserFindingEntry>) {
        self.findings = findings;
        self.clamp_scroll();
    }

    /// Replace the per-file read-success flags (drives the completeness caveat).
    #[expect(
        clippy::fn_params_excessive_bools,
        reason = "one flag per source file, set 1:1"
    )]
    pub fn set_read_flags(
        &mut self,
        passwd_read: bool,
        shadow_read: bool,
        sudoers_read: bool,
        pam_read: bool,
    ) {
        self.passwd_read = passwd_read;
        self.shadow_read = shadow_read;
        self.sudoers_read = sudoers_read;
        self.pam_read = pam_read;
    }

    /// Set the overall availability flag (false → degraded panel).
    pub fn set_available(&mut self, available: bool) {
        self.available = available;
    }

    /// Set the human-readable reason the backend was unreachable. Cleared
    /// (`None`) whenever availability flips back to `true` so a stale panic
    /// message can't linger after recovery.
    pub fn set_unavailable_reason(&mut self, reason: Option<String>) {
        self.unavailable_reason = if self.available { None } else { reason };
    }

    // ── Input ────────────────────────────────────────────────────────────────

    /// Handle a key press. Returns `Some(Action)` only for navigation keys
    /// (Esc → Back); scroll keys are consumed here.
    pub fn handle_key(&mut self, code: KeyCode) -> Option<Action> {
        match code {
            KeyCode::Down | KeyCode::Char('j') => {
                self.scroll = self.scroll.saturating_add(1);
                None
            }
            KeyCode::Up | KeyCode::Char('k') => {
                self.scroll = self.scroll.saturating_sub(1);
                None
            }
            KeyCode::PageDown => {
                self.scroll = self.scroll.saturating_add(8);
                None
            }
            KeyCode::PageUp => {
                self.scroll = self.scroll.saturating_sub(8);
                None
            }
            KeyCode::Esc => Some(Action::Back),
            _ => None,
        }
    }

    /// Handle a mouse event (scroll wheel only — no click targets).
    pub fn handle_mouse(&mut self, mouse: MouseEvent) -> Option<Action> {
        match mouse.kind {
            MouseEventKind::ScrollDown => {
                self.scroll = self.scroll.saturating_add(1);
                None
            }
            MouseEventKind::ScrollUp => {
                self.scroll = self.scroll.saturating_sub(1);
                None
            }
            _ => None,
        }
    }

    /// Clamp scroll against a (post-layout) max. Called by the render path
    /// once the visible row count is known, since `view` is the only place
    /// that knows the inner pane height.
    fn clamp_scroll_to(&mut self, max_scroll: usize) {
        if self.scroll > max_scroll {
            self.scroll = max_scroll;
        }
    }

    /// Generic clamp after a data setter (defensive — the real clamp happens
    /// at render time once the pane height is known).
    #[expect(
        clippy::unused_self,
        reason = "API symmetry with other scrollable panes"
    )]
    fn clamp_scroll(&mut self) {
        // No-op body: scroll is clamped against visible rows during render.
    }

    // ── Rendering ───────────────────────────────────────────────────────────

    /// Render the full users content area.
    pub fn view(&mut self, frame: &mut Frame, area: Rect, p: Palette) {
        if !self.available {
            self.render_unavailable(frame, area, p);
            return;
        }

        let inner = render_titled_panel(
            frame,
            area,
            p,
            &format!(
                " USERS · {} user(s) · {} group(s) · {} sudoer(s) · {} finding(s) ",
                self.users.len(),
                self.groups.len(),
                self.sudoers.len(),
                self.findings.len(),
            ),
            p.accent,
            true,
        );

        if inner.height == 0 {
            return;
        }

        // Build the full content as a Vec<Line> then render only the visible
        // window (mirrors the SSH/fail2ban tabs' manual-scroll approach).
        let lines = self.build_lines(p);

        let visible = inner.height as usize;
        let max_scroll = lines.len().saturating_sub(visible);
        self.clamp_scroll_to(max_scroll);
        let start = self.scroll.min(max_scroll);

        for (row, line) in lines.iter().skip(start).take(visible).enumerate() {
            let y = inner.y + u16::try_from(row).unwrap_or(u16::MAX);
            if y >= inner.bottom() {
                break;
            }
            let row_area = Rect::new(inner.x, y, inner.width, 1);
            frame.render_widget(Paragraph::new(line.clone()), row_area);
        }
    }

    /// Render the degraded state when the users backend panicked.
    ///
    /// `available == false` is only ever set when a collection task returned an
    /// empty bundle, which today happens exclusively when the `spawn_blocking`
    /// task PANICS (`JoinError`) — not when individual files are missing (a
    /// missing file degrades that field to empty but keeps `available == true`
    /// so the operator sees the partial table). The reason string is surfaced
    /// here so the operator can see what actually panicked.
    fn render_unavailable(&self, frame: &mut Frame, area: Rect, p: Palette) {
        let inner = render_titled_panel(frame, area, p, " USERS ", p.text_dim, false);
        let msg = Line::from(vec![
            Span::styled("✦ ", Style::new().fg(p.warn)),
            Span::styled(
                "users unavailable",
                Style::new().fg(p.text).add_modifier(Modifier::BOLD),
            ),
        ]);
        let detail_text = self
            .unavailable_reason
            .clone()
            .unwrap_or_else(|| "user data could not be collected on this host".to_string());
        let detail = Line::from(Span::styled(detail_text, Style::new().fg(p.text_dim)));
        let centered_msg = Rect::new(
            inner.x,
            inner.y + inner.height.saturating_sub(3) / 2,
            inner.width,
            1,
        );
        let centered_detail = Rect::new(
            inner.x,
            inner.y + inner.height.saturating_sub(3) / 2 + 1,
            inner.width,
            1,
        );
        frame.render_widget(Paragraph::new(msg).centered(), centered_msg);
        frame.render_widget(
            Paragraph::new(detail).centered().wrap(Wrap { trim: false }),
            centered_detail,
        );
    }

    /// Build the complete content as a flat list of lines (overview, users,
    /// groups, sudoers, findings). Scrolling operates over this list.
    fn build_lines(&self, p: Palette) -> Vec<Line<'static>> {
        let mut lines: Vec<Line<'static>> = Vec::new();

        self.push_overview_lines(&mut lines, p);
        lines.push(Line::raw(""));
        self.push_users_lines(&mut lines, p);
        lines.push(Line::raw(""));
        self.push_groups_lines(&mut lines, p);
        lines.push(Line::raw(""));
        self.push_sudoers_lines(&mut lines, p);
        lines.push(Line::raw(""));
        self.push_findings_lines(&mut lines, p);

        lines
    }

    fn push_overview_lines(&self, lines: &mut Vec<Line<'static>>, p: Palette) {
        lines.push(Line::from(Span::styled(
            "Overview",
            Style::new().fg(p.accent).add_modifier(Modifier::BOLD),
        )));

        // passwd — note incompleteness on macOS.
        let (icon, text, color) = read_badge(self.passwd_read, p);
        lines.push(Line::from(vec![
            Span::styled("  passwd   ", Style::new().fg(p.text_muted)),
            Span::styled(format!("{icon} {text}"), Style::new().fg(color)),
        ]));

        // shadow (locked badge source).
        let (icon, text, color) = read_badge(self.shadow_read, p);
        lines.push(Line::from(vec![
            Span::styled("  shadow   ", Style::new().fg(p.text_muted)),
            Span::styled(format!("{icon} {text}"), Style::new().fg(color)),
        ]));

        // sudoers.
        let (icon, text, color) = read_badge(self.sudoers_read, p);
        lines.push(Line::from(vec![
            Span::styled("  sudoers  ", Style::new().fg(p.text_muted)),
            Span::styled(format!("{icon} {text}"), Style::new().fg(color)),
        ]));

        // pam.
        let (icon, text, color) = read_badge(self.pam_read, p);
        lines.push(Line::from(vec![
            Span::styled("  pam.d    ", Style::new().fg(p.text_muted)),
            Span::styled(format!("{icon} {text}"), Style::new().fg(color)),
        ]));

        // Completeness caveat when passwd was read but is known to be partial.
        // On Linux, /etc/passwd IS the authoritative account database, so no
        // caveat is warranted. The text below is only meaningful on macOS, where
        // the real account DB lives in OpenDirectory and /etc/passwd is a sparse
        // fallback — gate the warning accordingly.
        if self.passwd_read && cfg!(target_os = "macos") {
            lines.push(Line::from(Span::styled(
                "  note: /etc/passwd parsed — on macOS this is NOT the real account DB",
                Style::new().fg(p.warn),
            )));
        }
    }

    fn push_users_lines(&self, lines: &mut Vec<Line<'static>>, p: Palette) {
        let header = format!("Users ({})", self.users.len());
        lines.push(Line::from(Span::styled(
            header,
            Style::new().fg(p.accent).add_modifier(Modifier::BOLD),
        )));

        if self.users.is_empty() {
            lines.push(Line::from(Span::styled(
                "  no users parsed",
                Style::new().fg(p.text_dim),
            )));
            return;
        }

        for u in &self.users {
            let name = truncate_str(&u.username, 16);
            let sudo = bool_span(u.sudo, "sudo", p);
            let locked = bool_span(u.locked, "lock", p);
            let totp = bool_span(u.totp, "totp", p);
            let shell = truncate_str(&u.shell, 16);
            lines.push(Line::from(vec![
                Span::styled(
                    format!("{name:<16} "),
                    Style::new().fg(p.text).add_modifier(Modifier::BOLD),
                ),
                Span::styled(format!("uid {}  ", u.uid), Style::new().fg(p.text_muted)),
                Span::styled(format!("{shell:<16} "), Style::new().fg(p.text_muted)),
                sudo,
                Span::raw(" "),
                locked,
                Span::raw(" "),
                totp,
            ]));
        }
    }

    fn push_groups_lines(&self, lines: &mut Vec<Line<'static>>, p: Palette) {
        let header = format!("Groups ({})", self.groups.len());
        lines.push(Line::from(Span::styled(
            header,
            Style::new().fg(p.accent).add_modifier(Modifier::BOLD),
        )));

        if self.groups.is_empty() {
            lines.push(Line::from(Span::styled(
                "  no groups parsed",
                Style::new().fg(p.text_dim),
            )));
            return;
        }

        for g in &self.groups {
            let name = truncate_str(&g.name, 16);
            lines.push(Line::from(vec![
                Span::styled(
                    format!("{name:<16} "),
                    Style::new().fg(p.text).add_modifier(Modifier::BOLD),
                ),
                Span::styled(format!("gid {}  ", g.gid), Style::new().fg(p.text_muted)),
                Span::styled(
                    format!("{} member(s)", g.members.len()),
                    Style::new().fg(p.text_dim),
                ),
            ]));
        }
    }

    fn push_sudoers_lines(&self, lines: &mut Vec<Line<'static>>, p: Palette) {
        let header = format!("Sudoers ({})", self.sudoers.len());
        lines.push(Line::from(Span::styled(
            header,
            Style::new().fg(p.accent).add_modifier(Modifier::BOLD),
        )));

        if self.sudoers.is_empty() {
            lines.push(Line::from(Span::styled(
                "  no sudoers rules parsed",
                Style::new().fg(p.text_dim),
            )));
            return;
        }

        for s in &self.sudoers {
            let who = truncate_str(&s.who, 16);
            let nopasswd = if s.nopasswd {
                Span::styled(
                    " NOPASSWD",
                    Style::new().fg(p.err).add_modifier(Modifier::BOLD),
                )
            } else {
                Span::raw("")
            };
            let runas = match &s.runas {
                Some(r) => format!(" ({r})"),
                None => String::new(),
            };
            let commands = truncate_str(&s.commands, 24);
            lines.push(Line::from(vec![
                Span::styled(
                    format!("{who:<16} "),
                    Style::new().fg(p.text).add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!("={runas} {commands}"),
                    Style::new().fg(p.text_muted),
                ),
                nopasswd,
            ]));
        }
    }

    fn push_findings_lines(&self, lines: &mut Vec<Line<'static>>, p: Palette) {
        // Group by severity: Critical > Error > Warning > Info > Ok.
        const ORDER: &[&str] = &["critical", "error", "warning", "info", "ok"];
        crate::ui::screens::findings::push_findings_grouped(
            lines,
            p,
            &self.findings,
            ORDER,
            crate::ui::screens::findings::severity_style_full,
            crate::ui::screens::findings::FindingWidths::TITLE_60,
        );
    }
}

/// Build a read-status badge for an `/etc` file probe.
fn read_badge(read: bool, p: Palette) -> (&'static str, &'static str, ratatui::style::Color) {
    if read {
        ("✓", "read", p.ok)
    } else {
        ("✗", "missing", p.warn)
    }
}

/// Build a colored yes/no/unknown span for a tri-state boolean probe.
fn bool_span(v: Option<bool>, label: &str, p: Palette) -> Span<'static> {
    let (icon, text, color) = match v {
        Some(true) => ("✓", "yes", p.ok),
        Some(false) => ("✗", "no", p.err),
        None => ("?", "n/a", p.text_dim),
    };
    Span::styled(format!("{icon} {label}:{text}"), Style::new().fg(color))
}

impl crate::ui::screens::section_overview::SectionOverview for UsersContent {
    fn available(&self) -> bool {
        self.available
    }

    fn status_label(&self) -> &'static str {
        crate::ui::screens::section_overview::status_label_for(
            self.available,
            self.findings.iter().map(|f| f.severity.as_str()),
        )
    }

    fn detail(&self) -> Option<String> {
        if !self.available {
            return None;
        }
        Some(format!(
            "{} user(s) · {} group(s)",
            self.users.len(),
            self.groups.len()
        ))
    }

    fn findings_count(&self) -> usize {
        self.findings.len()
    }
}

impl crate::ui::screens::findings::Finding for UserFindingEntry {
    fn severity(&self) -> &str {
        &self.severity
    }
    fn title(&self) -> &str {
        &self.title
    }
    fn detail(&self) -> Option<&str> {
        Some(&self.detail)
    }
    fn fix(&self) -> Option<&str> {
        self.fix.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::theme::CHARM;
    use ratatui::{Terminal, backend::TestBackend};

    fn sample_users() -> Vec<UserEntry> {
        vec![
            UserEntry {
                username: "root".into(),
                uid: 0,
                gid: 0,
                gecos: "root".into(),
                home: "/root".into(),
                shell: "/bin/bash".into(),
                sudo: Some(true),
                locked: Some(false),
                totp: None,
            },
            UserEntry {
                username: "deployer".into(),
                uid: 1001,
                gid: 1001,
                gecos: "Deploy".into(),
                home: "/home/deployer".into(),
                shell: "/bin/bash".into(),
                sudo: Some(true),
                locked: Some(false),
                totp: Some(true),
            },
        ]
    }

    fn sample_groups() -> Vec<GroupEntry> {
        vec![GroupEntry {
            name: "sudo".into(),
            gid: 27,
            members: vec!["deployer".into()],
        }]
    }

    fn sample_sudoers() -> Vec<SudoersEntry> {
        vec![SudoersEntry {
            who: "%sudo".into(),
            hosts: "ALL".into(),
            commands: "ALL".into(),
            nopasswd: false,
            runas: Some("ALL".into()),
        }]
    }

    fn sample_findings() -> Vec<UserFindingEntry> {
        vec![
            UserFindingEntry {
                id: "pam.sshd.no-totp".into(),
                severity: "warning".into(),
                title: "TOTP/2FA not configured for SSH".into(),
                detail: String::new(),
                fix: Some("Install libpam-google-authenticator.".into()),
            },
            UserFindingEntry {
                id: "password.empty.root".into(),
                severity: "critical".into(),
                title: "User 'root' has an empty password".into(),
                detail: String::new(),
                fix: None,
            },
        ]
    }

    /// Render a content area to a string (snapshot pattern from fail2ban).
    fn render_to_string(content: &mut UsersContent, w: u16, h: u16) -> String {
        let mut terminal = Terminal::new(TestBackend::new(w, h)).unwrap();
        terminal.draw(|f| content.view(f, f.area(), CHARM)).unwrap();
        terminal.backend().to_string()
    }

    #[test]
    fn new_is_unavailable_and_empty() {
        let c = UsersContent::new();
        assert!(!c.available);
        assert!(c.users.is_empty());
        assert!(c.groups.is_empty());
        assert!(c.sudoers.is_empty());
        assert!(c.findings.is_empty());
        assert!(!c.has_modal());
    }

    #[test]
    fn default_matches_new() {
        let from_new = UsersContent::new();
        let from_default = UsersContent::default();
        assert_eq!(from_new.available, from_default.available);
    }

    #[test]
    fn render_unavailable_when_not_available() {
        let mut c = UsersContent::new();
        let out = render_to_string(&mut c, 100, 24);
        assert!(out.contains("users unavailable"), "degraded panel: {out}");
    }

    #[test]
    fn render_overview_panel() {
        let mut c = UsersContent::new();
        c.set_available(true);
        c.set_read_flags(true, false, true, false);
        let out = render_to_string(&mut c, 110, 30);
        assert!(out.contains("passwd"), "passwd row: {out}");
        assert!(out.contains("shadow"), "shadow row: {out}");
        // The "NOT the real account DB" caveat is macOS-only: on Linux,
        // /etc/passwd IS the authoritative account DB and the warning would be
        // misleading. Tests run on Linux, so it must NOT appear here.
        if cfg!(target_os = "macos") {
            assert!(
                out.contains("NOT the real account DB"),
                "macOS caveat: {out}"
            );
        } else {
            assert!(
                !out.contains("NOT the real account DB"),
                "non-macOS should not show the macOS-only caveat: {out}"
            );
        }
    }

    #[test]
    fn render_users_table() {
        let mut c = UsersContent::new();
        c.set_available(true);
        c.set_users(sample_users());
        let out = render_to_string(&mut c, 110, 40);
        assert!(out.contains("root"), "user root: {out}");
        assert!(out.contains("deployer"), "user deployer: {out}");
        assert!(out.contains("uid 0"), "uid: {out}");
    }

    #[test]
    fn render_groups_list() {
        let mut c = UsersContent::new();
        c.set_available(true);
        c.set_groups(sample_groups());
        let out = render_to_string(&mut c, 110, 30);
        assert!(out.contains("sudo"), "group name: {out}");
        assert!(out.contains("member"), "member count: {out}");
    }

    #[test]
    fn render_sudoers_list() {
        let mut c = UsersContent::new();
        c.set_available(true);
        c.set_sudoers(sample_sudoers());
        let out = render_to_string(&mut c, 110, 30);
        assert!(out.contains("%sudo"), "sudoer who: {out}");
    }

    #[test]
    fn render_findings_grouped_by_severity() {
        let mut c = UsersContent::new();
        c.set_available(true);
        c.set_findings(sample_findings());
        let out = render_to_string(&mut c, 110, 50);
        assert!(out.contains("CRITICAL"), "severity group header: {out}");
        assert!(out.contains("empty password"), "finding title: {out}");
        assert!(out.contains("google-authenticator"), "fix hint: {out}");
    }

    #[test]
    fn scroll_down_consumed_and_returns_none() {
        let mut c = UsersContent::new();
        c.set_available(true);
        assert!(c.handle_key(KeyCode::Down).is_none());
        assert_eq!(c.scroll, 1);
    }

    #[test]
    fn scroll_up_at_zero_stays_zero() {
        let mut c = UsersContent::new();
        c.set_available(true);
        c.handle_key(KeyCode::Up);
        assert_eq!(c.scroll, 0);
    }

    #[test]
    fn esc_returns_back_action() {
        let mut c = UsersContent::new();
        assert_eq!(c.handle_key(KeyCode::Esc), Some(Action::Back));
    }

    #[test]
    fn mouse_scroll_wheel_adjusts_scroll() {
        let mut c = UsersContent::new();
        let down = MouseEvent {
            kind: MouseEventKind::ScrollDown,
            column: 0,
            row: 0,
            modifiers: crossterm::event::KeyModifiers::empty(),
        };
        c.handle_mouse(down);
        assert_eq!(c.scroll, 1);
    }

    #[test]
    fn tiny_terminal_does_not_panic() {
        let mut c = UsersContent::new();
        c.set_available(true);
        c.set_users(sample_users());
        c.set_findings(sample_findings());
        // 20x5 — well below comfortable, must not panic.
        let _ = render_to_string(&mut c, 20, 5);
    }

    #[test]
    fn tiny_terminal_unavailable_does_not_panic() {
        // Companion to `tiny_terminal_does_not_panic`: lock the degraded
        // render_unavailable path against future edits too. The saturating
        // math in render_unavailable (inner.height.saturating_sub(3)/2 plus
        // bounded u16 offsets) must stay panic-free at tiny dimensions.
        let mut c = UsersContent::new();
        c.set_available(false);
        c.set_unavailable_reason(Some("collector task panicked".into()));
        // 20x5 — well below comfortable, must not panic.
        let _ = render_to_string(&mut c, 20, 5);
    }

    #[test]
    fn empty_states_render_without_panic() {
        let mut c = UsersContent::new();
        c.set_available(true);
        let out = render_to_string(&mut c, 100, 30);
        assert!(out.contains("no users parsed"), "empty users: {out}");
        assert!(out.contains("no groups parsed"), "empty groups: {out}");
        assert!(out.contains("no findings"), "empty findings: {out}");
    }

    #[test]
    fn set_findings_replaces_and_keeps_scroll_finite() {
        let mut c = UsersContent::new();
        c.scroll = 1_000_000;
        c.set_findings(sample_findings());
        // After a render the scroll is clamped to the visible window.
        let _ = render_to_string(&mut c, 100, 30);
        // The render did not panic.
    }

    #[test]
    fn page_down_advances_by_eight() {
        let mut c = UsersContent::new();
        c.set_available(true);
        c.handle_key(KeyCode::PageDown);
        assert_eq!(c.scroll, 8);
        c.handle_key(KeyCode::PageUp);
        assert_eq!(c.scroll, 0);
    }
}
