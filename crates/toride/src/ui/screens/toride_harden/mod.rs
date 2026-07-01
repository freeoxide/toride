//! Kernel-hardening management content area (live READ-ONLY).
//!
//! Renders inside the dashboard's content region when
//! [`Section::Harden`](crate::data::Section) is the active sidebar section. This
//! integration mirrors the fail2ban / ufw-kit templates (`Fail2banContent` /
//! `FirewallContent`) WITHOUT any write path — every line is read-only.
//!
//! Layout (single scrollable pane, no sub-tab bar):
//! 1. Status panel — selected profile + parameter pass/fail summary.
//! 2. Sysctl parameter table — key, current vs desired, pass/fail.
//! 3. Shared-memory mounts — target + options + hardened flag.
//! 4. Doctor findings — grouped by severity (Critical > Important > Warning > Info > Ok).

use std::collections::BTreeMap;

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

/// A single sysctl parameter row in the status/diff table.
#[derive(Clone, Debug)]
pub struct SysctlRow {
    /// Sysctl key, e.g. `kernel.kptr_restrict`.
    pub key: String,
    /// Desired value from the active profile.
    pub desired: String,
    /// Live value read via `sysctl -n <key>` (or `"<unreadable>"`).
    pub current: String,
    /// Human-readable description from the profile.
    pub description: String,
    /// Whether `current` matches `desired`.
    pub pass: bool,
}

/// A single shared-memory mount row.
#[derive(Clone, Debug)]
pub struct MountEntry {
    /// Mount target path, e.g. `/dev/shm`.
    pub target: String,
    /// Source device, e.g. `tmpfs`.
    pub source: String,
    /// Filesystem type, e.g. `tmpfs`.
    pub fstype: String,
    /// Mount options as a comma-separated string.
    pub options: String,
    /// Whether the mount carries `nosuid`, `nodev`, AND `noexec`.
    pub hardened: bool,
}

/// A single doctor finding.
#[derive(Clone, Debug)]
pub struct FindingEntry {
    /// Machine-readable id (e.g. "kernel.aslr.disabled").
    pub id: String,
    /// Severity as a lowercase string: "ok" | "info" | "warning" | "important" | "critical".
    pub severity: String,
    /// Short human-readable title.
    pub title: String,
    /// Longer description (may be empty).
    pub detail: String,
    /// Suggested remediation, if any.
    pub fix: Option<String>,
}

/// A selectable hardening profile in the profile selector.
#[derive(Clone, Debug)]
pub struct HardenProfileEntry {
    /// Machine-readable profile name (e.g. "server").
    pub name: String,
    /// Title-cased display label (e.g. "Server").
    pub label: String,
    /// Number of parameters the profile would apply.
    pub param_count: usize,
}

// ── HardenContent ───────────────────────────────────────────────────────────

/// Kernel-hardening management content rendered inside the dashboard content
/// area.
///
/// READ-ONLY: there are no write operations, no optimistic updates, no loading
/// spinner, no cooldown. Data arrives via [`HardenContent::set_*`] setters
/// driven by [`HardenCollector`](crate::toride_harden_data::HardenCollector).
pub struct HardenContent {
    /// Whether the harden backend was reachable at all (`sysctl` binary
    /// present). `false` means the section renders a degraded "unavailable"
    /// panel instead of live data.
    available: bool,
    /// Available hardening profiles for the selector (always populated, even
    /// when `available == false`, so the desired state is still described).
    profiles: Vec<HardenProfileEntry>,
    /// Index into `profiles` of the currently selected profile.
    selected_profile: usize,
    /// Sysctl parameter rows (current vs desired) for EVERY profile, keyed by
    /// profile name. The visible table is looked up from
    /// [`Self::visible_sysctl_rows`] using `selected_profile`, so cycling the
    /// selector with Left/Right actually swaps the table. Previously the table
    /// was a single flat `Vec` built only for profile 0, so the selector
    /// advanced the header ("Desktop" → "Server") while the rows stayed pinned
    /// to Desktop — wrong count, wrong desired values, wrong pass/fail.
    sysctl_rows_by_profile: BTreeMap<String, Vec<SysctlRow>>,
    /// Shared-memory mounts.
    mounts: Vec<MountEntry>,
    /// Doctor findings.
    findings: Vec<FindingEntry>,
    /// Human-readable reason the backend was unreachable, surfaced in the
    /// degraded panel. Populated only when a collection task panicked.
    unavailable_reason: Option<String>,
    /// Vertical scroll offset over the whole pane.
    scroll: usize,
}

impl Default for HardenContent {
    fn default() -> Self {
        Self::new()
    }
}

impl HardenContent {
    /// Create a new empty content area.
    #[must_use]
    pub fn new() -> Self {
        Self {
            available: false,
            profiles: Vec::new(),
            selected_profile: 0,
            sysctl_rows_by_profile: BTreeMap::new(),
            mounts: Vec::new(),
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

    /// Live shared-memory mount count for the sidebar badge. `None` when the
    /// backend is unavailable so the badge stays honestly empty. (Sysctl param
    /// counts are profile-dependent and already surfaced via the Managed
    /// Services grid's `findings_count`, so the badge uses the distinct mounts
    /// count to avoid redundancy.)
    #[must_use]
    pub fn badge_count(&self) -> Option<usize> {
        if self.available {
            Some(self.mounts.len())
        } else {
            None
        }
    }

    // ── Data setters ─────────────────────────────────────────────────────────

    /// Replace the available profiles list and clamp the selection.
    pub fn set_profiles(&mut self, profiles: Vec<HardenProfileEntry>) {
        if self.selected_profile >= profiles.len() {
            self.selected_profile = 0;
        }
        self.profiles = profiles;
        self.clamp_scroll();
    }

    /// Replace the per-profile sysctl parameter rows and clamp scroll. Keys are
    /// profile names matching [`HardenProfileEntry::name`].
    pub fn set_sysctl_rows_by_profile(&mut self, rows: BTreeMap<String, Vec<SysctlRow>>) {
        self.sysctl_rows_by_profile = rows;
        self.clamp_scroll();
    }

    /// The sysctl rows for the currently selected profile (empty when the
    /// profile is absent from the map or has no params). This is the single
    /// source of truth the render path reads, so cycling `selected_profile`
    /// via Left/Right immediately re-derives the visible table.
    fn visible_sysctl_rows(&self) -> &[SysctlRow] {
        self.profiles
            .get(self.selected_profile)
            .and_then(|entry| self.sysctl_rows_by_profile.get(&entry.name))
            .map_or(&[], Vec::as_slice)
    }

    /// Replace the mounts list and clamp scroll.
    pub fn set_mounts(&mut self, mounts: Vec<MountEntry>) {
        self.mounts = mounts;
        self.clamp_scroll();
    }

    /// Replace the findings list and clamp scroll.
    pub fn set_findings(&mut self, findings: Vec<FindingEntry>) {
        self.findings = findings;
        self.clamp_scroll();
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

    /// Select the next profile (wraps). Resets scroll to the top so the
    /// operator sees the newly-selected profile's table from its first row
    /// rather than a mid-table view of a different-length table.
    fn profile_next(&mut self) {
        if self.profiles.is_empty() {
            return;
        }
        self.selected_profile = (self.selected_profile + 1) % self.profiles.len();
        self.scroll = 0;
    }

    /// Select the previous profile (wraps). Resets scroll to the top (see
    /// [`Self::profile_next`]).
    fn profile_prev(&mut self) {
        if self.profiles.is_empty() {
            return;
        }
        let len = self.profiles.len();
        self.selected_profile = (self.selected_profile + len - 1) % len;
        self.scroll = 0;
    }

    // ── Input ────────────────────────────────────────────────────────────────

    /// Handle a key press. Returns `Some(Action)` only for navigation keys
    /// (Esc → Back); scroll keys and Left/Right profile cycling are consumed
    /// here.
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
            // Left/Right cycle the profile selector (mirrors a sub-tab bar).
            KeyCode::Right | KeyCode::Char('l') => {
                self.profile_next();
                None
            }
            KeyCode::Left | KeyCode::Char('h') => {
                self.profile_prev();
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
        reason = "API symmetry with fail2ban/ufw-kit tabs"
    )]
    fn clamp_scroll(&mut self) {
        // No-op body: scroll is clamped against visible rows during render.
        // Kept for API symmetry with the fail2ban / ufw-kit tabs.
    }

    // ── Rendering ───────────────────────────────────────────────────────────

    /// Render the full harden content area.
    pub fn view(&mut self, frame: &mut Frame, area: Rect, p: Palette) {
        if !self.available {
            self.render_unavailable(frame, area, p);
            return;
        }

        let sysctl_rows = self.visible_sysctl_rows();
        let pass_count = sysctl_rows.iter().filter(|r| r.pass).count();
        let inner = render_titled_panel(
            frame,
            area,
            p,
            &format!(
                " HARDEN · {}/{} params · {} mount(s) · {} finding(s) ",
                pass_count,
                sysctl_rows.len(),
                self.mounts.len(),
                self.findings.len(),
            ),
            p.accent,
            true,
        );

        if inner.height == 0 {
            return;
        }

        // Build the full content as a Vec<Line> then render only the visible
        // window (mirrors the fail2ban / ufw-kit tabs' manual-scroll approach).
        let lines = self.build_lines(p, inner.width);

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

    /// Render the degraded state when the harden backend is unavailable on this
    /// host.
    ///
    /// `available == false` is set when construction failed (`HardenClient::system()`
    /// returns `Err(BinaryNotFound("sysctl"))` on macOS) OR when a collection
    /// task panicked (`JoinError`). The profiles selector is still rendered so the
    /// operator can see the DESIRED state even when the live state is unreadable.
    fn render_unavailable(&self, frame: &mut Frame, area: Rect, p: Palette) {
        let inner = render_titled_panel(frame, area, p, " HARDEN ", p.text_dim, false);
        if inner.height < 2 {
            return;
        }
        let msg = Line::from(vec![
            Span::styled("✦ ", Style::new().fg(p.warn)),
            Span::styled(
                "Harden unavailable",
                Style::new().fg(p.text).add_modifier(Modifier::BOLD),
            ),
        ]);
        // Prefer the construction/panic reason from the bundle; otherwise a
        // generic message accurate for both the macOS/sysctl-missing case and
        // the pre-first-poll state.
        let detail_text = self.unavailable_reason.clone().unwrap_or_else(|| {
            "sysctl / harden data could not be collected on this host".to_string()
        });
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
        // Wrap so a long reason wraps within the panel instead of clipping.
        frame.render_widget(
            Paragraph::new(detail).centered().wrap(Wrap { trim: false }),
            centered_detail,
        );
    }

    /// Build the complete content as a flat list of lines (status, sysctl
    /// table, mounts, findings). Scrolling operates over this list.
    fn build_lines(&self, p: Palette, inner_width: u16) -> Vec<Line<'static>> {
        let mut lines: Vec<Line<'static>> = Vec::new();

        self.push_status_lines(&mut lines, p);
        lines.push(Line::raw(""));
        self.push_sysctl_lines(&mut lines, p, inner_width);
        lines.push(Line::raw(""));
        self.push_mounts_lines(&mut lines, p);
        lines.push(Line::raw(""));
        self.push_findings_lines(&mut lines, p);

        lines
    }

    fn push_status_lines(&self, lines: &mut Vec<Line<'static>>, p: Palette) {
        lines.push(Line::from(Span::styled(
            "Profile",
            Style::new().fg(p.accent).add_modifier(Modifier::BOLD),
        )));

        // Selected profile name + param count. Even when the live sysctl table
        // is empty (backend unreadable mid-render but available==true), the
        // profile name surfaces so the operator knows the desired baseline.
        let (name, count) = self
            .profiles
            .get(self.selected_profile)
            .map_or(("(none)", 0), |entry| {
                (entry.label.as_str(), entry.param_count)
            });
        lines.push(Line::from(vec![
            Span::styled("  active   ", Style::new().fg(p.text_muted)),
            Span::styled(
                format!("{name} ({count} params)"),
                Style::new().fg(p.text).add_modifier(Modifier::BOLD),
            ),
        ]));

        // Pass/fail summary across the visible (selected-profile) sysctl table.
        let sysctl_rows = self.visible_sysctl_rows();
        let total = sysctl_rows.len();
        let pass = sysctl_rows.iter().filter(|r| r.pass).count();
        let fail = total.saturating_sub(pass);
        let (summary_label, summary_color) = if total == 0 {
            ("—", p.text_dim)
        } else if fail == 0 {
            ("✓ all passing", p.ok)
        } else {
            ("! some failing", p.warn)
        };
        lines.push(Line::from(vec![
            Span::styled("  audit    ", Style::new().fg(p.text_muted)),
            Span::styled(
                format!("{summary_label}  ({pass}/{total})"),
                Style::new().fg(summary_color),
            ),
        ]));

        // Hint that Left/Right cycle the profile.
        lines.push(Line::from(vec![
            Span::styled("  hint     ", Style::new().fg(p.text_muted)),
            Span::styled("← → cycle profile", Style::new().fg(p.text_dim)),
        ]));
    }

    fn push_sysctl_lines(&self, lines: &mut Vec<Line<'static>>, p: Palette, inner_width: u16) {
        // Fixed-width prefix: "  " (2) + key(34) + " "(1) + cur(8) + " "(1) + des(8) + " "(1) = 55.
        // The description fills the remainder, scaled to the viewport.
        const PREFIX_WIDTH: usize = 55;
        const FALLBACK_DESC: usize = 30;
        let sysctl_rows = self.visible_sysctl_rows();
        let header = format!("Sysctl Parameters ({})", sysctl_rows.len());
        lines.push(Line::from(Span::styled(
            header,
            Style::new().fg(p.accent).add_modifier(Modifier::BOLD),
        )));

        if sysctl_rows.is_empty() {
            lines.push(Line::from(Span::styled(
                "  no parameters for this profile",
                Style::new().fg(p.text_dim),
            )));
            return;
        }

        let desc_max = if inner_width as usize >= PREFIX_WIDTH {
            let scaled = inner_width as usize - PREFIX_WIDTH;
            if scaled >= 1 { scaled } else { FALLBACK_DESC }
        } else {
            FALLBACK_DESC
        };

        for row in sysctl_rows {
            let (icon, color) = if row.pass {
                ("✓", p.ok)
            } else {
                ("✗", p.err)
            };
            let key = truncate_str(&row.key, 34);
            let current = truncate_str(&row.current, 8);
            let desired = truncate_str(&row.desired, 8);
            let desc = truncate_str(&row.description, desc_max);
            lines.push(Line::from(vec![
                Span::styled(format!("{icon} "), Style::new().fg(color)),
                Span::styled(format!("{key:<34}"), Style::new().fg(p.text)),
                Span::styled(
                    format!(" {current:<8}"),
                    Style::new().fg(if row.pass { p.text_dim } else { p.warn }),
                ),
                Span::styled(format!(" {desired:<8}"), Style::new().fg(p.text_muted)),
                Span::styled(format!(" {desc}"), Style::new().fg(p.text_dim)),
            ]));
        }
    }

    fn push_mounts_lines(&self, lines: &mut Vec<Line<'static>>, p: Palette) {
        let header = format!("Shared Memory Mounts ({})", self.mounts.len());
        lines.push(Line::from(Span::styled(
            header,
            Style::new().fg(p.accent).add_modifier(Modifier::BOLD),
        )));

        if self.mounts.is_empty() {
            lines.push(Line::from(Span::styled(
                "  no shm mounts found",
                Style::new().fg(p.text_dim),
            )));
            return;
        }

        for mount in &self.mounts {
            let (icon, color) = if mount.hardened {
                ("✓", p.ok)
            } else {
                ("✗", p.warn)
            };
            let target = truncate_str(&mount.target, 20);
            let opts = truncate_str(&mount.options, 40);
            lines.push(Line::from(vec![
                Span::styled(format!("{icon} "), Style::new().fg(color)),
                Span::styled(
                    format!("{target:<20}"),
                    Style::new().fg(p.text).add_modifier(Modifier::BOLD),
                ),
                Span::styled(format!(" {opts}"), Style::new().fg(p.text_muted)),
            ]));
        }
    }

    fn push_findings_lines(&self, lines: &mut Vec<Line<'static>>, p: Palette) {
        // Group by severity: Critical > Important > Warning > Info > Ok.
        const ORDER: &[&str] = &["critical", "important", "warning", "info", "ok"];
        crate::ui::screens::findings::push_findings_grouped(
            lines,
            p,
            &self.findings,
            ORDER,
            crate::ui::screens::findings::severity_style_with_important_err,
            crate::ui::screens::findings::FindingWidths::TITLE_60,
        );
    }
}

impl crate::ui::screens::section_overview::SectionOverview for HardenContent {
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
            "{} profile(s) · {} mount(s)",
            self.profiles.len(),
            self.mounts.len()
        ))
    }

    fn findings_count(&self) -> usize {
        self.findings.len()
    }
}

impl crate::ui::screens::findings::Finding for FindingEntry {
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

    fn sample_profiles() -> Vec<HardenProfileEntry> {
        vec![
            HardenProfileEntry {
                name: "desktop".into(),
                label: "Desktop".into(),
                param_count: 15,
            },
            HardenProfileEntry {
                name: "server".into(),
                label: "Server".into(),
                param_count: 24,
            },
            HardenProfileEntry {
                name: "router".into(),
                label: "Router".into(),
                param_count: 26,
            },
        ]
    }

    fn sample_sysctl_rows() -> Vec<SysctlRow> {
        vec![
            SysctlRow {
                key: "kernel.randomize_va_space".into(),
                desired: "2".into(),
                current: "2".into(),
                description: "Enable full ASLR".into(),
                pass: true,
            },
            SysctlRow {
                key: "kernel.kptr_restrict".into(),
                desired: "1".into(),
                current: "0".into(),
                description: "Restrict kernel pointers".into(),
                pass: false,
            },
        ]
    }

    /// Per-profile rows fixture for the profile-selector tests: each profile
    /// gets a distinct row set so a selector switch is observable in the
    /// rendered output (Desktop = 1 row, Server = 2 rows, Router = 3 rows).
    fn sample_sysctl_rows_by_profile() -> BTreeMap<String, Vec<SysctlRow>> {
        let mut map = BTreeMap::new();
        map.insert(
            "desktop".into(),
            vec![SysctlRow {
                key: "kernel.desktop_only".into(),
                desired: "1".into(),
                current: "1".into(),
                description: "desktop-only param".into(),
                pass: true,
            }],
        );
        map.insert(
            "server".into(),
            vec![
                SysctlRow {
                    key: "kernel.server_a".into(),
                    desired: "1".into(),
                    current: "0".into(),
                    description: "server param a".into(),
                    pass: false,
                },
                SysctlRow {
                    key: "kernel.server_b".into(),
                    desired: "2".into(),
                    current: "2".into(),
                    description: "server param b".into(),
                    pass: true,
                },
            ],
        );
        map.insert(
            "router".into(),
            vec![
                SysctlRow {
                    key: "net.router_a".into(),
                    desired: "1".into(),
                    current: "1".into(),
                    description: "router param a".into(),
                    pass: true,
                },
                SysctlRow {
                    key: "net.router_b".into(),
                    desired: "0".into(),
                    current: "0".into(),
                    description: "router param b".into(),
                    pass: true,
                },
                SysctlRow {
                    key: "net.router_c".into(),
                    desired: "1".into(),
                    current: "0".into(),
                    description: "router param c".into(),
                    pass: false,
                },
            ],
        );
        map
    }

    fn sample_mounts() -> Vec<MountEntry> {
        vec![MountEntry {
            target: "/dev/shm".into(),
            source: "tmpfs".into(),
            fstype: "tmpfs".into(),
            options: "rw,nosuid,nodev,noexec".into(),
            hardened: true,
        }]
    }

    fn sample_findings() -> Vec<FindingEntry> {
        // Ids mirror the real toride-harden backend (`crates/toride-harden/src/doctor.rs`):
        // dot-separated, `<domain>.<check>[.<state>]`.
        vec![
            FindingEntry {
                id: "kernel.aslr".into(),
                severity: "ok".into(),
                title: "ASLR is fully enabled (level 2)".into(),
                detail: "kernel.randomize_va_space = 2: full ASLR is active.".into(),
                fix: None,
            },
            FindingEntry {
                id: "kernel.kptr-restrict.disabled".into(),
                severity: "important".into(),
                title: "kptr_restrict is disabled".into(),
                detail: String::new(),
                fix: Some("sysctl -w kernel.kptr_restrict=1".into()),
            },
        ]
    }

    /// The `FindingEntry::id` doc-comment promises dot-separated ids that mirror
    /// the toride-harden backend (`crates/toride-harden/src/doctor.rs`). Pin that
    /// contract so a future edit that reverts to colon-separated ids (or drifts
    /// the fixture away from production data) fails loudly.
    #[test]
    fn finding_id_format_matches_harden_backend() {
        // Must be dot-separated (the harden backend emits dots, NOT colons —
        // unlike ufw-kit / fail2ban which use colons).
        for f in sample_findings() {
            assert!(
                f.id.contains('.'),
                "id '{}' must be dot-separated (harden backend emits dots)",
                f.id
            );
            assert!(
                !f.id.contains(':'),
                "id '{}' must NOT be colon-separated (harden backend emits dots)",
                f.id
            );
        }
        // Spot-check the exact real-backend ids are present in the fixture so a
        // silent rename in `doctor.rs` surfaces here too.
        let findings = sample_findings();
        let ids: Vec<&str> = findings.iter().map(|f| f.id.as_str()).collect();
        assert!(ids.contains(&"kernel.aslr"), "missing kernel.aslr: {ids:?}");
        assert!(
            ids.contains(&"kernel.kptr-restrict.disabled"),
            "missing kernel.kptr-restrict.disabled: {ids:?}"
        );
    }

    /// Render a content area to a string (snapshot pattern from `fail2ban/ufw_kit`).
    fn render_to_string(content: &mut HardenContent, w: u16, h: u16) -> String {
        let mut terminal = Terminal::new(TestBackend::new(w, h)).unwrap();
        terminal.draw(|f| content.view(f, f.area(), CHARM)).unwrap();
        terminal.backend().to_string()
    }

    #[test]
    fn new_is_unavailable_and_empty() {
        let c = HardenContent::new();
        assert!(!c.available);
        assert!(c.profiles.is_empty());
        assert!(c.sysctl_rows_by_profile.is_empty());
        assert!(c.mounts.is_empty());
        assert!(c.findings.is_empty());
        assert!(!c.has_modal());
    }

    #[test]
    fn default_matches_new() {
        let from_new = HardenContent::new();
        let from_default = HardenContent::default();
        assert_eq!(from_new.available, from_default.available);
    }

    #[test]
    fn render_unavailable_when_not_available() {
        let mut c = HardenContent::new();
        let out = render_to_string(&mut c, 100, 24);
        assert!(out.contains("Harden unavailable"), "degraded panel: {out}");
    }

    #[test]
    fn render_unavailable_at_degenerate_height_does_not_panic() {
        let mut c = HardenContent::new();
        c.set_unavailable_reason(Some("spawn_blocking panicked".into()));
        // 20x5 — below the saturating_sub(3) threshold once the titled panel's
        // border/insets are accounted for. The render path wraps the reason,
        // so assert the leading token appears rather than the full string.
        let out = render_to_string(&mut c, 20, 5);
        assert!(
            out.contains("spawn_blocking"),
            "unavailable reason should surface: {out}"
        );
    }

    #[test]
    fn render_unavailable_skips_message_at_degenerate_inner_height() {
        let mut c = HardenContent::new();
        c.set_unavailable_reason(Some("spawn_blocking panicked".into()));
        // Area height 1 → border consumes the only row → inner.height == 0.
        let out_h1 = render_to_string(&mut c, 40, 1);
        assert!(
            !out_h1.contains("Harden unavailable"),
            "inner.height == 0 must early-return: {out_h1}"
        );
        // Area height 2 → inner.height == 1, still below the `< 2` threshold.
        let out_h2 = render_to_string(&mut c, 40, 2);
        assert!(
            !out_h2.contains("Harden unavailable"),
            "inner.height == 1 must early-return: {out_h2}"
        );
    }

    #[test]
    fn render_status_panel_with_profile_and_audit() {
        let mut c = HardenContent::new();
        c.set_available(true);
        c.set_profiles(sample_profiles());
        let mut rows = BTreeMap::new();
        rows.insert("desktop".into(), sample_sysctl_rows());
        c.set_sysctl_rows_by_profile(rows);
        let out = render_to_string(&mut c, 110, 40);
        assert!(out.contains("Desktop"), "profile label: {out}");
        assert!(out.contains("1/2"), "pass/total summary: {out}");
        assert!(out.contains("cycle profile"), "hint: {out}");
    }

    #[test]
    fn render_sysctl_table_with_pass_and_fail_rows() {
        let mut c = HardenContent::new();
        c.set_available(true);
        c.set_profiles(sample_profiles());
        let mut rows = BTreeMap::new();
        rows.insert("desktop".into(), sample_sysctl_rows());
        c.set_sysctl_rows_by_profile(rows);
        let out = render_to_string(&mut c, 120, 40);
        assert!(
            out.contains("kernel.randomize_va_space"),
            "pass row key: {out}"
        );
        assert!(out.contains("kernel.kptr_restrict"), "fail row key: {out}");
    }

    #[test]
    fn render_mounts_list() {
        let mut c = HardenContent::new();
        c.set_available(true);
        c.set_mounts(sample_mounts());
        let out = render_to_string(&mut c, 100, 30);
        assert!(out.contains("/dev/shm"), "mount target: {out}");
        assert!(out.contains("nosuid"), "mount options: {out}");
    }

    #[test]
    fn render_findings_grouped_by_severity() {
        let mut c = HardenContent::new();
        c.set_available(true);
        c.set_findings(sample_findings());
        let out = render_to_string(&mut c, 110, 40);
        assert!(out.contains("IMPORTANT"), "severity group header: {out}");
        assert!(
            out.contains("kptr_restrict is disabled"),
            "finding title: {out}"
        );
        assert!(
            out.contains("sysctl -w kernel.kptr_restrict=1"),
            "fix hint: {out}"
        );
    }

    #[test]
    fn scroll_down_consumed_and_returns_none() {
        let mut c = HardenContent::new();
        c.set_available(true);
        assert!(c.handle_key(KeyCode::Down).is_none());
        assert_eq!(c.scroll, 1);
    }

    #[test]
    fn scroll_up_at_zero_stays_zero() {
        let mut c = HardenContent::new();
        c.set_available(true);
        c.handle_key(KeyCode::Up);
        assert_eq!(c.scroll, 0);
    }

    #[test]
    fn left_right_cycle_profiles() {
        let mut c = HardenContent::new();
        c.set_available(true);
        c.set_profiles(sample_profiles());
        assert_eq!(c.selected_profile, 0);
        c.handle_key(KeyCode::Right);
        assert_eq!(c.selected_profile, 1);
        c.handle_key(KeyCode::Right);
        assert_eq!(c.selected_profile, 2);
        c.handle_key(KeyCode::Right); // wraps to 0
        assert_eq!(c.selected_profile, 0);
        c.handle_key(KeyCode::Left); // wraps back to 2
        assert_eq!(c.selected_profile, 2);
    }

    /// Regression test for the profile-selector bug: pressing Right must swap
    /// the RENDERED sysctl table to the newly-selected profile, not just
    /// advance the header label while leaving the rows pinned to Desktop.
    /// Previously the collector built `sysctl_rows` only for profile 0, so the
    /// header advertised "Server (24 params)" while the table still showed the
    /// 15 Desktop rows. Now rows are keyed per-profile and the render path
    /// re-derives the visible table from `selected_profile`.
    #[test]
    fn right_arrow_swaps_rendered_sysctl_table_to_selected_profile() {
        let mut c = HardenContent::new();
        c.set_available(true);
        c.set_profiles(sample_profiles());
        c.set_sysctl_rows_by_profile(sample_sysctl_rows_by_profile());

        // Desktop (profile 0) is rendered initially: exactly 1 row.
        let out_desktop = render_to_string(&mut c, 120, 40);
        assert!(
            out_desktop.contains("kernel.desktop_only"),
            "Desktop row must render at profile 0: {out_desktop}"
        );
        assert!(
            !out_desktop.contains("kernel.server_a"),
            "Server row must NOT render at profile 0: {out_desktop}"
        );

        // Press Right → Server (profile 1). The header now says Server and the
        // table must show Server's rows (2 of them), NOT Desktop's.
        c.handle_key(KeyCode::Right);
        assert_eq!(c.selected_profile, 1);
        let out_server = render_to_string(&mut c, 120, 40);
        assert!(
            out_server.contains("Server"),
            "header must advertise Server after Right: {out_server}"
        );
        assert!(
            out_server.contains("kernel.server_a"),
            "Server row must render at profile 1: {out_server}"
        );
        assert!(
            out_server.contains("kernel.server_b"),
            "second Server row must render at profile 1: {out_server}"
        );
        assert!(
            !out_server.contains("kernel.desktop_only"),
            "Desktop row must NOT render at profile 1: {out_server}"
        );

        // Press Right again → Router (profile 2, 3 rows).
        c.handle_key(KeyCode::Right);
        assert_eq!(c.selected_profile, 2);
        let out_router = render_to_string(&mut c, 120, 40);
        assert!(
            out_router.contains("net.router_a"),
            "Router row must render at profile 2: {out_router}"
        );
        assert!(
            out_router.contains("net.router_c"),
            "third Router row must render at profile 2: {out_router}"
        );
        assert!(
            !out_router.contains("kernel.server_a"),
            "Server row must NOT render at profile 2: {out_router}"
        );

        // Press Left → back to Server. Confirms both directions swap the table.
        c.handle_key(KeyCode::Left);
        assert_eq!(c.selected_profile, 1);
        let out_back = render_to_string(&mut c, 120, 40);
        assert!(
            out_back.contains("kernel.server_a"),
            "Server row must render again after Left: {out_back}"
        );
    }

    /// The header's pass/total counter must reflect the SELECTED profile's row
    /// count, not a stale Desktop count. Server fixture has 1 pass / 2 total.
    #[test]
    fn profile_switch_updates_pass_total_counter() {
        let mut c = HardenContent::new();
        c.set_available(true);
        c.set_profiles(sample_profiles());
        c.set_sysctl_rows_by_profile(sample_sysctl_rows_by_profile());

        let out_desktop = render_to_string(&mut c, 120, 40);
        assert!(
            out_desktop.contains("1/1"),
            "Desktop pass/total must be 1/1: {out_desktop}"
        );

        c.handle_key(KeyCode::Right); // → Server
        let out_server = render_to_string(&mut c, 120, 40);
        assert!(
            out_server.contains("1/2"),
            "Server pass/total must be 1/2: {out_server}"
        );
    }

    #[test]
    fn esc_returns_back_action() {
        let mut c = HardenContent::new();
        assert_eq!(c.handle_key(KeyCode::Esc), Some(Action::Back));
    }

    #[test]
    fn mouse_scroll_wheel_adjusts_scroll() {
        let mut c = HardenContent::new();
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
    fn set_profiles_clamps_selection() {
        let mut c = HardenContent::new();
        c.set_profiles(sample_profiles());
        c.selected_profile = 2;
        c.set_profiles(vec![sample_profiles().remove(0)]); // shrink to 1
        assert_eq!(c.selected_profile, 0);
    }

    #[test]
    fn tiny_terminal_does_not_panic() {
        let mut c = HardenContent::new();
        c.set_available(true);
        c.set_profiles(sample_profiles());
        let mut rows = BTreeMap::new();
        rows.insert("desktop".into(), sample_sysctl_rows());
        c.set_sysctl_rows_by_profile(rows);
        c.set_mounts(sample_mounts());
        c.set_findings(sample_findings());
        // 20x5 — well below comfortable, must not panic.
        let _ = render_to_string(&mut c, 20, 5);
    }

    #[test]
    fn set_findings_replaces_and_keeps_scroll_finite() {
        let mut c = HardenContent::new();
        c.scroll = 1_000_000;
        c.set_findings(sample_findings());
        // After a render the scroll is clamped to the visible window.
        let _ = render_to_string(&mut c, 100, 30);
        // The important property is the render did not panic.
    }

    #[test]
    fn empty_states_render_without_panic() {
        let mut c = HardenContent::new();
        c.set_available(true);
        let out = render_to_string(&mut c, 100, 30);
        assert!(
            out.contains("no parameters for this profile"),
            "empty sysctl: {out}"
        );
        assert!(out.contains("no shm mounts found"), "empty mounts: {out}");
        assert!(out.contains("no findings"), "empty findings: {out}");
    }

    // ── Full-screen insta snapshots ─────────────────────────────────────────
    //
    // Pin the full rendered output at fixed terminal sizes, mirroring the
    // fail2ban / ufw-kit snapshot tests so a layout regression (column widths,
    // severity-group indentation, empty-state text, the titled-panel header
    // counters) cannot slip past the contains-assertions silently.

    #[test]
    fn harden_content_snapshot_120x40() {
        let mut c = HardenContent::new();
        c.set_available(true);
        c.set_profiles(sample_profiles());
        let mut rows = BTreeMap::new();
        rows.insert("desktop".into(), sample_sysctl_rows());
        c.set_sysctl_rows_by_profile(rows);
        c.set_mounts(sample_mounts());
        c.set_findings(sample_findings());
        let out = render_to_string(&mut c, 120, 40);
        insta::assert_snapshot!("harden_content_120x40", out);
    }

    #[test]
    fn harden_content_snapshot_unavailable_100x24() {
        let mut c = HardenContent::new();
        c.set_unavailable_reason(Some("BinaryNotFound: sysctl".into()));
        let out = render_to_string(&mut c, 100, 24);
        insta::assert_snapshot!("harden_content_unavailable_100x24", out);
    }
}
