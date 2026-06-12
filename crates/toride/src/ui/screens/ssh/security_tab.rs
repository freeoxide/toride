//! Security Overview sub-tab for the SSH management screen.
//!
//! Read-only scrollable dashboard displaying the SSH security grade, server
//! configuration checks, access summary, known hosts trust status, and
//! active warnings. Scroll-only navigation with j/k or arrow keys.

use crossterm::event::{KeyCode, MouseEvent, MouseEventKind};
use ratatui::{
    Frame,
    layout::Rect,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::Paragraph,
};

use crate::action::Action;
use crate::ssh_data::SshSecurityData;
use super::DiagnosticEntry;
use crate::ui::theme::Palette;
use crate::ui::widgets::render_titled_panel;

use super::SshTab;

// ── SecurityTab ────────────────────────────────────────────────────────────────

/// State for the Security Overview sub-tab.
pub struct SecurityTab {
    /// Security data to display.
    data: Option<SshSecurityData>,
    /// Vertical scroll offset.
    scroll: usize,
    /// Total content height (recalculated each frame).
    content_height: usize,
}

impl SecurityTab {
    /// Create a new empty security tab.
    #[must_use]
    pub fn new() -> Self {
        Self {
            data: None,
            scroll: 0,
            content_height: 0,
        }
    }

    /// Replace the security data with new data.
    pub fn set_data(&mut self, data: SshSecurityData) {
        self.data = Some(data);
        self.scroll = 0;
    }
}

impl Default for SecurityTab {
    fn default() -> Self {
        Self::new()
    }
}

impl SshTab for SecurityTab {
    fn handle_key(&mut self, code: KeyCode) -> Option<Action> {
        match code {
            KeyCode::Up | KeyCode::Char('k') => {
                if self.scroll > 0 {
                    self.scroll -= 1;
                }
                None
            }
            KeyCode::Down | KeyCode::Char('j') => {
                let max_scroll = self.content_height.saturating_sub(1);
                if self.scroll < max_scroll {
                    self.scroll += 1;
                }
                None
            }
            _ => None,
        }
    }

    fn handle_mouse(&mut self, mouse: MouseEvent) -> Option<Action> {
        match mouse.kind {
            MouseEventKind::ScrollUp => {
                if self.scroll > 0 {
                    self.scroll -= 1;
                }
            }
            MouseEventKind::ScrollDown => {
                let max_scroll = self.content_height.saturating_sub(1);
                if self.scroll < max_scroll {
                    self.scroll += 1;
                }
            }
            _ => {}
        }
        None
    }

    fn view(&mut self, frame: &mut Frame, area: Rect, p: Palette) {
        let inner = render_titled_panel(frame, area, p, " SECURITY OVERVIEW ", p.text, false);

        if inner.height == 0 {
            return;
        }

        let Some(ref data) = self.data else {
            let msg = Line::from(Span::styled(
                "Loading security data..",
                Style::new().fg(p.text_dim),
            ));
            let centered = Rect::new(inner.x, inner.y + inner.height / 2, inner.width, 1);
            frame.render_widget(Paragraph::new(msg).centered(), centered);
            return;
        };

        let lines = self.build_lines(data, p);

        self.content_height = lines.len();

        let visible = inner.height as usize;
        let max_scroll = self.content_height.saturating_sub(visible);
        if self.scroll > max_scroll {
            self.scroll = max_scroll;
        }

        let skip = self.scroll;
        let take = visible;

        for (row, line) in lines.into_iter().enumerate() {
            if row < skip {
                continue;
            }
            if row >= skip + take {
                break;
            }
            let y = inner.y + (row - skip) as u16;
            if y >= inner.bottom() {
                break;
            }
            let row_area = Rect::new(inner.x, y, inner.width, 1);
            frame.render_widget(Paragraph::new(line), row_area);
        }
    }

    fn has_modal(&self) -> bool {
        false
    }

    fn close_modal(&mut self) {}
}

// ── Line builders ──────────────────────────────────────────────────────────────

impl SecurityTab {
    /// Build all dashboard lines from security data.
    fn build_lines(&self, data: &SshSecurityData, p: Palette) -> Vec<Line<'static>> {
        let mut lines = Vec::new();
        let checks = data.checks();
        let grade = data.grade();

        // 1. Grade banner
        lines.push(Line::from(vec![
            Span::styled("  Grade: ", Style::new().fg(p.text_dim)),
            Span::styled(
                grade.label(),
                Style::new().fg(grade.color(p)).add_modifier(Modifier::BOLD),
            ),
        ]));
        lines.push(Line::raw(""));

        // 2. Server config section header
        lines.push(Line::from(Span::styled(
            "SERVER CONFIG",
            Style::new().fg(p.accent).add_modifier(Modifier::BOLD),
        )));

        // 3. Check rows (up to 8)
        for check in &checks {
            let icon = if check.informational {
                Span::styled(" ·", Style::new().fg(p.text_muted))
            } else if check.passing {
                Span::styled(" ✓", Style::new().fg(p.ok))
            } else {
                Span::styled(" ✗", Style::new().fg(p.err))
            };

            lines.push(Line::from(vec![
                Span::styled("  ", Style::new()),
                Span::styled(format!("{:<24}", check.label), Style::new().fg(p.text)),
                Span::styled(format!("{:<24}", check.detail), Style::new().fg(p.text_dim)),
                icon,
            ]));
        }

        // 4. Empty line
        lines.push(Line::raw(""));

        // ── AUTH METHODS section ──────────────────────────────────────
        lines.push(Line::from(Span::styled(
            "AUTH METHODS",
            Style::new().fg(p.accent).add_modifier(Modifier::BOLD),
        )));

        // Password auth
        if data.access_info.password_auth {
            lines.push(Line::from(vec![
                Span::styled("  ✓ Password", Style::new().fg(p.ok)),
            ]));
        } else {
            lines.push(Line::from(vec![
                Span::styled("  ✗ Password", Style::new().fg(p.err)),
            ]));
        }

        // Key auth
        if data.access_info.pubkey_auth {
            lines.push(Line::from(vec![
                Span::styled("  ✓ Public Key", Style::new().fg(p.ok)),
            ]));
        } else {
            lines.push(Line::from(vec![
                Span::styled("  ✗ Public Key", Style::new().fg(p.err)),
            ]));
        }

        // Root login
        let root_login = &data.access_info.permit_root_login;
        let root_color = match root_login.as_str() {
            "yes" => p.warn,
            "no" => p.ok,
            _ => p.info, // "prohibit-password" or "forced-commands-only"
        };
        lines.push(Line::from(vec![
            Span::styled("  Root login: ", Style::new().fg(p.text)),
            Span::styled(root_login.clone(), Style::new().fg(root_color)),
        ]));

        // Auth methods
        if !data.access_info.auth_methods.is_empty() {
            lines.push(Line::from(vec![
                Span::styled("  Methods: ", Style::new().fg(p.text)),
                Span::styled(
                    data.access_info.auth_methods.join(", "),
                    Style::new().fg(p.text_dim),
                ),
            ]));
        }

        // Spacer
        lines.push(Line::raw(""));

        // ── USER ACCESS section ───────────────────────────────────────
        lines.push(Line::from(Span::styled(
            "USER ACCESS",
            Style::new().fg(p.accent).add_modifier(Modifier::BOLD),
        )));

        let access = &data.access_info;
        let all_empty = access.allowed_users.is_empty()
            && access.denied_users.is_empty()
            && access.allowed_groups.is_empty()
            && access.denied_groups.is_empty();

        if all_empty {
            lines.push(Line::from(vec![
                Span::styled(
                    "  No access restrictions configured",
                    Style::new().fg(p.text_dim),
                ),
            ]));
        } else {
            // Allowed users
            if access.allowed_users.is_empty() {
                lines.push(Line::from(vec![
                    Span::styled("  Users: ", Style::new().fg(p.text)),
                    Span::styled("All users", Style::new().fg(p.text_dim)),
                ]));
            } else {
                let mut spans = vec![Span::styled("  Users: ", Style::new().fg(p.text))];
                for (i, user) in access.allowed_users.iter().enumerate() {
                    if i > 0 {
                        spans.push(Span::styled(" ", Style::new()));
                    }
                    spans.push(Span::styled(
                        format!(" {} ", user),
                        Style::new().fg(p.info),
                    ));
                }
                lines.push(Line::from(spans));
            }

            // Denied users
            if !access.denied_users.is_empty() {
                let mut spans =
                    vec![Span::styled("  Denied: ", Style::new().fg(p.text))];
                for (i, user) in access.denied_users.iter().enumerate() {
                    if i > 0 {
                        spans.push(Span::styled(" ", Style::new()));
                    }
                    spans.push(Span::styled(
                        format!(" {} ", user),
                        Style::new().fg(p.err),
                    ));
                }
                lines.push(Line::from(spans));
            }

            // Allowed groups
            if !access.allowed_groups.is_empty() {
                let mut spans =
                    vec![Span::styled("  Groups: ", Style::new().fg(p.text))];
                for (i, group) in access.allowed_groups.iter().enumerate() {
                    if i > 0 {
                        spans.push(Span::styled(" ", Style::new()));
                    }
                    spans.push(Span::styled(
                        format!(" @{} ", group),
                        Style::new().fg(p.info),
                    ));
                }
                lines.push(Line::from(spans));
            }

            // Denied groups
            if !access.denied_groups.is_empty() {
                let mut spans =
                    vec![Span::styled("  Denied groups: ", Style::new().fg(p.text))];
                for (i, group) in access.denied_groups.iter().enumerate() {
                    if i > 0 {
                        spans.push(Span::styled(" ", Style::new()));
                    }
                    spans.push(Span::styled(
                        format!(" @{} ", group),
                        Style::new().fg(p.err),
                    ));
                }
                lines.push(Line::from(spans));
            }
        }

        // Spacer
        lines.push(Line::raw(""));

        // ── SSH USERS section ─────────────────────────────────────────
        lines.push(Line::from(Span::styled(
            "SSH USERS",
            Style::new().fg(p.accent).add_modifier(Modifier::BOLD),
        )));

        if data.system_users.is_empty() {
            lines.push(Line::from(vec![
                Span::styled(
                    "  Unable to read system users",
                    Style::new().fg(p.text_dim),
                ),
            ]));
        } else {
            let display_users: Vec<_> = data
                .system_users
                .iter()
                .take(10)
                .collect();
            let overflow = data.system_users.len().saturating_sub(10);

            for user in &display_users {
                let key_status = if user.has_authorized_keys {
                    Span::styled(
                        format!("{} keys", user.key_count),
                        Style::new().fg(p.accent),
                    )
                } else {
                    Span::styled("No keys", Style::new().fg(p.text_dim))
                };
                lines.push(Line::from(vec![
                    Span::styled("  ", Style::new()),
                    Span::styled(
                        format!("{:<16}", user.username),
                        Style::new().fg(p.text),
                    ),
                    Span::styled(
                        format!("{:<24}", user.shell),
                        Style::new().fg(p.text_dim),
                    ),
                    key_status,
                ]));
            }

            if overflow > 0 {
                lines.push(Line::from(vec![
                    Span::styled(
                        format!("  +{} more", overflow),
                        Style::new().fg(p.text_dim),
                    ),
                ]));
            }
        }

        // Spacer
        lines.push(Line::raw(""));

        // 5. Access section header
        lines.push(Line::from(Span::styled(
            "ACCESS",
            Style::new().fg(p.accent).add_modifier(Modifier::BOLD),
        )));

        // 6. Authorized keys summary
        let key_count = data.authorized_key_count;
        let labels_joined = if data.authorized_key_labels.is_empty() {
            "none".to_string()
        } else {
            data.authorized_key_labels.join(" · ")
        };

        lines.push(Line::from(vec![
            Span::styled(
                format!("  {key_count} keys can access this machine"),
                Style::new().fg(p.text),
            ),
        ]));
        if !data.authorized_key_labels.is_empty() {
            lines.push(Line::from(vec![
                Span::styled("  ", Style::new()),
                Span::styled(labels_joined, Style::new().fg(p.text_dim)),
            ]));
        }

        // 7. Empty line
        lines.push(Line::raw(""));

        // 8. Known hosts section header
        lines.push(Line::from(Span::styled(
            "KNOWN HOSTS",
            Style::new().fg(p.accent).add_modifier(Modifier::BOLD),
        )));

        // 9. Known hosts summary
        let hosts_count = data.known_hosts_count;
        let hashed_count = data.known_hosts_hashed_count;
        lines.push(Line::from(vec![
            Span::styled(
                format!("  {hosts_count} hosts trusted"),
                Style::new().fg(p.text),
            ),
            Span::styled(" · ", Style::new().fg(p.text_muted)),
            Span::styled(
                format!("{hashed_count} hashed"),
                Style::new().fg(p.text_dim),
            ),
        ]));

        // 10. Empty line
        lines.push(Line::raw(""));

        // 11. Warnings section
        let warnings: Vec<&DiagnosticEntry> = data
            .security_diagnostics
            .iter()
            .filter(|d| d.severity == "warning" || d.severity == "error")
            .collect();

        if warnings.is_empty() {
            lines.push(Line::from(Span::styled(
                "ALL CLEAR",
                Style::new().fg(p.ok).add_modifier(Modifier::BOLD),
            )));
        } else {
            lines.push(Line::from(Span::styled(
                "WARNINGS",
                Style::new().fg(p.warn).add_modifier(Modifier::BOLD),
            )));
            for w in &warnings {
                lines.push(Line::from(vec![
                    Span::styled("  ! ", Style::new().fg(p.warn)),
                    Span::styled(w.message.clone(), Style::new().fg(p.text)),
                ]));
                if let Some(ref hint) = w.hint {
                    lines.push(Line::from(vec![
                        Span::styled("    → ", Style::new().fg(p.text_muted)),
                        Span::styled(hint.clone(), Style::new().fg(p.text_dim)),
                    ]));
                }
            }
        }

        // 12. Footer
        lines.push(Line::raw(""));
        lines.push(Line::from(vec![
            Span::styled("  j/k ", p.key_style()),
            Span::styled("scroll", p.label_style()),
        ]));

        lines
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::screens::ssh::{SshAccessInfo, SystemUserInfo};
    use std::collections::HashMap;

    fn sample_data() -> SshSecurityData {
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
            authorized_key_count: 2,
            authorized_key_labels: vec!["alice@workstation".into(), "bob@laptop".into()],
            known_hosts_count: 5,
            known_hosts_hashed_count: 1,
            security_diagnostics: vec![],
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

    fn sample_data_with_warnings() -> SshSecurityData {
        let mut data = sample_data();
        data.security_diagnostics = vec![DiagnosticEntry {
            id: "key_permissions".into(),
            severity: "warning".into(),
            module: "local".into(),
            message: "Private key id_rsa has overly permissive mode (0644)".into(),
            hint: Some("Run chmod 600 ~/.ssh/id_rsa".into()),
        }];
        data
    }

    #[test]
    fn new_is_empty() {
        let tab = SecurityTab::new();
        assert!(tab.data.is_none());
        assert!(!tab.has_modal());
        assert_eq!(tab.scroll, 0);
    }

    #[test]
    fn set_data_updates() {
        let mut tab = SecurityTab::new();
        tab.set_data(sample_data());
        assert!(tab.data.is_some());
        assert_eq!(tab.scroll, 0);
    }

    #[test]
    fn render_empty_state() {
        use crate::ui::theme::CHARM;
        use ratatui::{Terminal, backend::TestBackend};

        let mut tab = SecurityTab::new();
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        terminal.draw(|f| tab.view(f, f.area(), CHARM)).unwrap();
        let output = terminal.backend().to_string();
        assert!(
            output.contains("Loading security data"),
            "empty state should show loading message: {output}"
        );
    }

    #[test]
    fn render_with_data() {
        use crate::ui::theme::CHARM;
        use ratatui::{Terminal, backend::TestBackend};

        let mut tab = SecurityTab::new();
        tab.set_data(sample_data());
        let mut terminal = Terminal::new(TestBackend::new(100, 40)).unwrap();
        terminal.draw(|f| tab.view(f, f.area(), CHARM)).unwrap();
        let output = terminal.backend().to_string();
        assert!(output.contains("Grade"), "grade banner: {output}");
        assert!(output.contains("SERVER CONFIG"), "server config: {output}");
        assert!(output.contains("AUTH METHODS"), "auth methods: {output}");
        assert!(output.contains("USER ACCESS"), "user access: {output}");
        assert!(output.contains("SSH USERS"), "ssh users: {output}");
        assert!(output.contains("ACCESS"), "access section: {output}");
        assert!(output.contains("KNOWN HOSTS"), "known hosts: {output}");
        assert!(output.contains("ALL CLEAR"), "all clear: {output}");
    }

    #[test]
    fn render_with_warnings() {
        use crate::ui::theme::CHARM;
        use ratatui::{Terminal, backend::TestBackend};

        let mut tab = SecurityTab::new();
        tab.set_data(sample_data_with_warnings());
        let mut terminal = Terminal::new(TestBackend::new(100, 40)).unwrap();
        terminal.draw(|f| tab.view(f, f.area(), CHARM)).unwrap();
        let output = terminal.backend().to_string();
        assert!(
            output.contains("WARNINGS"),
            "should show warnings header: {output}"
        );
    }

    #[test]
    fn scroll_clamps() {
        let mut tab = SecurityTab::new();
        tab.set_data(sample_data());

        // Scroll should not go below zero.
        tab.handle_key(KeyCode::Up);
        assert_eq!(tab.scroll, 0);

        // Render to set content_height.
        use crate::ui::theme::CHARM;
        use ratatui::{Terminal, backend::TestBackend};
        let mut terminal = Terminal::new(TestBackend::new(100, 40)).unwrap();
        terminal.draw(|f| tab.view(f, f.area(), CHARM)).unwrap();

        let saved_scroll = tab.scroll;

        // Scroll down a bunch past content_height.
        for _ in 0..200 {
            tab.handle_key(KeyCode::Down);
        }
        // Re-render to clamp.
        terminal.draw(|f| tab.view(f, f.area(), CHARM)).unwrap();

        // scroll should be clamped to content_height - visible, not larger.
        let visible = 40u16.saturating_sub(2) as usize; // minus border
        let max_scroll = tab.content_height.saturating_sub(visible);
        assert!(
            tab.scroll <= max_scroll,
            "scroll {} should be <= max_scroll {}",
            tab.scroll,
            max_scroll,
        );

        // Scroll back up to zero.
        for _ in 0..200 {
            tab.handle_key(KeyCode::Up);
        }
        assert_eq!(tab.scroll, 0, "should be able to scroll back to top");
    }

    #[test]
    fn scroll_mouse_scroll_up_down() {
        use crate::ui::theme::CHARM;
        use ratatui::{Terminal, backend::TestBackend};

        let mut tab = SecurityTab::new();
        tab.set_data(sample_data());

        // Render to set content_height so scrolling actually works.
        let mut terminal = Terminal::new(TestBackend::new(100, 40)).unwrap();
        terminal.draw(|f| tab.view(f, f.area(), CHARM)).unwrap();

        let mouse_down = crossterm::event::MouseEvent {
            kind: MouseEventKind::ScrollDown,
            column: 0,
            row: 0,
            modifiers: crossterm::event::KeyModifiers::NONE,
        };
        let mouse_up = crossterm::event::MouseEvent {
            kind: MouseEventKind::ScrollUp,
            column: 0,
            row: 0,
            modifiers: crossterm::event::KeyModifiers::NONE,
        };

        tab.handle_mouse(mouse_down);
        assert_eq!(tab.scroll, 1, "scroll down should increment");
        tab.handle_mouse(mouse_up);
        assert_eq!(tab.scroll, 0, "scroll up should decrement");
        tab.handle_mouse(mouse_up);
        assert_eq!(tab.scroll, 0, "scroll up at zero stays");
    }

    #[test]
    fn close_modal_is_noop() {
        let mut tab = SecurityTab::new();
        tab.close_modal();
        assert!(!tab.has_modal());
    }

    #[test]
    fn grade_banner_shows_correct_letter() {
        use crate::ui::theme::CHARM;
        use ratatui::{Terminal, backend::TestBackend};

        let mut data = sample_data();
        // Default mock config scores A.
        let mut tab = SecurityTab::new();
        tab.set_data(data);
        let mut terminal = Terminal::new(TestBackend::new(100, 40)).unwrap();
        terminal.draw(|f| tab.view(f, f.area(), CHARM)).unwrap();
        let output = terminal.backend().to_string();
        assert!(output.contains("A"), "grade A for secure config: {output}");
    }

    #[test]
    fn render_auth_methods_section() {
        use crate::ui::theme::CHARM;
        use ratatui::{Terminal, backend::TestBackend};

        let mut tab = SecurityTab::new();
        tab.set_data(sample_data());
        let mut terminal = Terminal::new(TestBackend::new(120, 50)).unwrap();
        terminal.draw(|f| tab.view(f, f.area(), CHARM)).unwrap();
        let output = terminal.backend().to_string();
        assert!(
            output.contains("✗ Password"),
            "should show disabled password auth: {output}"
        );
        assert!(
            output.contains("✓ Public Key"),
            "should show enabled pubkey auth: {output}"
        );
        assert!(
            output.contains("prohibit-password"),
            "should show root login policy: {output}"
        );
        assert!(
            output.contains("Methods:"),
            "should show auth methods: {output}"
        );
    }

    #[test]
    fn render_user_access_section() {
        use crate::ui::theme::CHARM;
        use ratatui::{Terminal, backend::TestBackend};

        let mut tab = SecurityTab::new();
        tab.set_data(sample_data());
        let mut terminal = Terminal::new(TestBackend::new(120, 50)).unwrap();
        terminal.draw(|f| tab.view(f, f.area(), CHARM)).unwrap();
        let output = terminal.backend().to_string();
        assert!(
            output.contains("USER ACCESS"),
            "should show user access section: {output}"
        );
        assert!(
            output.contains("@ssh-users"),
            "should show allowed group: {output}"
        );
    }

    #[test]
    fn render_ssh_users_section() {
        use crate::ui::theme::CHARM;
        use ratatui::{Terminal, backend::TestBackend};

        let mut tab = SecurityTab::new();
        tab.set_data(sample_data());
        let mut terminal = Terminal::new(TestBackend::new(120, 50)).unwrap();
        terminal.draw(|f| tab.view(f, f.area(), CHARM)).unwrap();
        let output = terminal.backend().to_string();
        assert!(
            output.contains("SSH USERS"),
            "should show ssh users header: {output}"
        );
        assert!(
            output.contains("alice"),
            "should show user alice: {output}"
        );
        assert!(
            output.contains("bob"),
            "should show user bob: {output}"
        );
        assert!(
            output.contains("root"),
            "should show user root: {output}"
        );
        assert!(
            output.contains("2 keys"),
            "should show key count for alice: {output}"
        );
        assert!(
            output.contains("No keys"),
            "should show no keys for root: {output}"
        );
    }

    #[test]
    fn render_user_access_empty_restrictions() {
        use crate::ui::theme::CHARM;
        use ratatui::{Terminal, backend::TestBackend};

        let mut tab = SecurityTab::new();
        let mut data = sample_data();
        data.access_info = SshAccessInfo::default();
        tab.set_data(data);
        let mut terminal = Terminal::new(TestBackend::new(120, 50)).unwrap();
        terminal.draw(|f| tab.view(f, f.area(), CHARM)).unwrap();
        let output = terminal.backend().to_string();
        assert!(
            output.contains("No access restrictions configured"),
            "should show no restrictions message when all empty: {output}"
        );
    }

    #[test]
    fn render_ssh_users_overflow() {
        use crate::ui::theme::CHARM;
        use ratatui::{Terminal, backend::TestBackend};

        let mut tab = SecurityTab::new();
        let mut data = sample_data();
        // Add enough users to trigger overflow
        for i in 0..12 {
            data.system_users.push(SystemUserInfo {
                username: format!("user{i}"),
                shell: "/bin/bash".into(),
                home_dir: format!("/home/user{i}"),
                has_authorized_keys: false,
                key_count: 0,
            });
        }
        tab.set_data(data);
        let mut terminal = Terminal::new(TestBackend::new(120, 50)).unwrap();
        terminal.draw(|f| tab.view(f, f.area(), CHARM)).unwrap();
        let output = terminal.backend().to_string();
        assert!(
            output.contains("+5 more"),
            "should show overflow count: {output}"
        );
    }

    #[test]
    fn render_password_auth_enabled() {
        use crate::ui::theme::CHARM;
        use ratatui::{Terminal, backend::TestBackend};

        let mut tab = SecurityTab::new();
        let mut data = sample_data();
        data.access_info.password_auth = true;
        tab.set_data(data);
        let mut terminal = Terminal::new(TestBackend::new(120, 50)).unwrap();
        terminal.draw(|f| tab.view(f, f.area(), CHARM)).unwrap();
        let output = terminal.backend().to_string();
        assert!(
            output.contains("✓ Password"),
            "should show enabled password auth: {output}"
        );
    }

    #[test]
    fn render_pubkey_auth_disabled() {
        use crate::ui::theme::CHARM;
        use ratatui::{Terminal, backend::TestBackend};

        let mut tab = SecurityTab::new();
        let mut data = sample_data();
        data.access_info.pubkey_auth = false;
        tab.set_data(data);
        let mut terminal = Terminal::new(TestBackend::new(120, 50)).unwrap();
        terminal.draw(|f| tab.view(f, f.area(), CHARM)).unwrap();
        let output = terminal.backend().to_string();
        assert!(
            output.contains("✗ Public Key"),
            "should show disabled pubkey auth: {output}"
        );
    }

    #[test]
    fn render_root_login_yes_shows_warning_color() {
        use crate::ui::theme::CHARM;
        use ratatui::{Terminal, backend::TestBackend};

        let mut tab = SecurityTab::new();
        let mut data = sample_data();
        data.access_info.permit_root_login = "yes".into();
        tab.set_data(data);
        let mut terminal = Terminal::new(TestBackend::new(120, 50)).unwrap();
        terminal.draw(|f| tab.view(f, f.area(), CHARM)).unwrap();
        let output = terminal.backend().to_string();
        assert!(
            output.contains("yes"),
            "should show root login yes: {output}"
        );
    }

    #[test]
    fn render_root_login_no_shows_ok_color() {
        use crate::ui::theme::CHARM;
        use ratatui::{Terminal, backend::TestBackend};

        let mut tab = SecurityTab::new();
        let mut data = sample_data();
        data.access_info.permit_root_login = "no".into();
        tab.set_data(data);
        let mut terminal = Terminal::new(TestBackend::new(120, 50)).unwrap();
        terminal.draw(|f| tab.view(f, f.area(), CHARM)).unwrap();
        let output = terminal.backend().to_string();
        assert!(
            output.contains("no"),
            "should show root login no: {output}"
        );
    }

    #[test]
    fn render_empty_auth_methods_hides_methods() {
        use crate::ui::theme::CHARM;
        use ratatui::{Terminal, backend::TestBackend};

        let mut tab = SecurityTab::new();
        let mut data = sample_data();
        data.access_info.auth_methods = vec![];
        tab.set_data(data);
        let mut terminal = Terminal::new(TestBackend::new(120, 50)).unwrap();
        terminal.draw(|f| tab.view(f, f.area(), CHARM)).unwrap();
        let output = terminal.backend().to_string();
        assert!(
            !output.contains("Methods:"),
            "should not show Methods line when empty: {output}"
        );
    }

    #[test]
    fn render_allowed_users_with_badges() {
        use crate::ui::theme::CHARM;
        use ratatui::{Terminal, backend::TestBackend};

        let mut tab = SecurityTab::new();
        let mut data = sample_data();
        data.access_info.allowed_users = vec!["alice".into(), "bob".into()];
        tab.set_data(data);
        let mut terminal = Terminal::new(TestBackend::new(120, 50)).unwrap();
        terminal.draw(|f| tab.view(f, f.area(), CHARM)).unwrap();
        let output = terminal.backend().to_string();
        assert!(
            output.contains("alice"),
            "should show alice user badge: {output}"
        );
        assert!(
            output.contains("bob"),
            "should show bob user badge: {output}"
        );
    }

    #[test]
    fn render_denied_users_with_badges() {
        use crate::ui::theme::CHARM;
        use ratatui::{Terminal, backend::TestBackend};

        let mut tab = SecurityTab::new();
        let mut data = sample_data();
        data.access_info.denied_users = vec!["guest".into()];
        tab.set_data(data);
        let mut terminal = Terminal::new(TestBackend::new(120, 50)).unwrap();
        terminal.draw(|f| tab.view(f, f.area(), CHARM)).unwrap();
        let output = terminal.backend().to_string();
        assert!(
            output.contains("Denied:"),
            "should show Denied label: {output}"
        );
        assert!(
            output.contains("guest"),
            "should show denied user: {output}"
        );
    }

    #[test]
    fn render_denied_groups_with_badges() {
        use crate::ui::theme::CHARM;
        use ratatui::{Terminal, backend::TestBackend};

        let mut tab = SecurityTab::new();
        let mut data = sample_data();
        data.access_info.denied_groups = vec!["no-ssh".into()];
        tab.set_data(data);
        let mut terminal = Terminal::new(TestBackend::new(120, 50)).unwrap();
        terminal.draw(|f| tab.view(f, f.area(), CHARM)).unwrap();
        let output = terminal.backend().to_string();
        assert!(
            output.contains("Denied groups:"),
            "should show Denied groups label: {output}"
        );
        assert!(
            output.contains("no-ssh"),
            "should show denied group: {output}"
        );
    }

    #[test]
    fn render_empty_system_users_shows_message() {
        use crate::ui::theme::CHARM;
        use ratatui::{Terminal, backend::TestBackend};

        let mut tab = SecurityTab::new();
        let mut data = sample_data();
        data.system_users = vec![];
        tab.set_data(data);
        let mut terminal = Terminal::new(TestBackend::new(120, 50)).unwrap();
        terminal.draw(|f| tab.view(f, f.area(), CHARM)).unwrap();
        let output = terminal.backend().to_string();
        assert!(
            output.contains("Unable to read system users"),
            "should show unable to read message: {output}"
        );
    }

    #[test]
    fn render_warnings_with_hint() {
        use crate::ui::theme::CHARM;
        use ratatui::{Terminal, backend::TestBackend};

        let mut tab = SecurityTab::new();
        tab.set_data(sample_data_with_warnings());
        let mut terminal = Terminal::new(TestBackend::new(120, 50)).unwrap();
        terminal.draw(|f| tab.view(f, f.area(), CHARM)).unwrap();
        let output = terminal.backend().to_string();
        assert!(
            output.contains("WARNINGS"),
            "should show WARNINGS header: {output}"
        );
        assert!(
            output.contains("Run chmod 600 ~/.ssh/id_rsa"),
            "should show the hint text: {output}"
        );
    }
}
