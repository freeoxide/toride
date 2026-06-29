//! About-toride content area (live READ-ONLY).
//!
//! Renders inside the dashboard's content region when
//! [`Section::About`](crate::data::Section) is the active sidebar section. This
//! integration mirrors the harden / tailscale / fail2ban templates
//! (`HardenContent` / `TailscaleContent` / `Fail2banContent`) WITHOUT any write
//! path — every line is read-only.
//!
//! Layout (single scrollable pane, no sub-tab bar, no sub-selector):
//! 1. APP — compile-time build metadata (name, version, profile, homepage,
//!    authors).
//! 2. SYSTEM — live host identity (hostname, os, kernel, arch, cpu, cores, mem,
//!    uptime, load) derived from [`crate::status::TorideStatus`].
//! 3. RUNTIME — environment context (terminal, shell, user, lang, home, cwd,
//!    config/data dir, log path).
//!
//! The data has no "findings" concept (it is identity metadata, not a health
//! check), so the [`SectionOverview`] impl reports `findings_count == 0` and the
//! collector uses the SIMPLE variant (no 60s findings cache).

use crossterm::event::{KeyCode, MouseEvent, MouseEventKind};
use ratatui::{
    Frame,
    layout::Rect,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Paragraph, Wrap},
};

use crate::action::Action;
use crate::ui::theme::Palette;
use crate::ui::widgets::render_titled_panel;

// ── Presentation types ──────────────────────────────────────────────────────
//
// These structs are referenced by BOTH the data bundle (`about_data`) and the
// convert layer (`about_convert`), exactly like the harden screen's
// `SysctlRow` / `FindingEntry` / `MountEntry` / `HardenProfileEntry`. Defining
// them here (in the screen module) and re-importing them in the data file keeps
// the convert layer importing from the screen module — the single boundary
// between backend and presentation lives in `about_convert`.

/// Live host/system identity derived from [`crate::status::TorideStatus`].
///
/// Every field is a pre-formatted display string so the render path is pure
/// layout. Unreadable probes degrade a field to a placeholder
/// (`"(unknown)"` / `"(none)"`) rather than aborting the whole bundle —
/// mirroring the harden / tailscale graceful-degradation contract.
#[derive(Clone, Debug)]
pub struct AboutSystem {
    /// Hostname (e.g. `"edge-prod-01"`).
    pub hostname: String,
    /// OS name + version (e.g. `"Ubuntu 24.04 LTS"`).
    pub os: String,
    /// Kernel version string (e.g. `"6.8.0"`).
    pub kernel: String,
    /// CPU architecture (e.g. `"x86_64"`, `"aarch64"`).
    pub arch: String,
    /// CPU brand string (e.g. `"Intel Xeon E5-2680 v4"`).
    pub cpu_brand: String,
    /// Physical core count as a display string (e.g. `"4"`).
    pub cores: String,
    /// Total memory, human-readable (e.g. `"16.0 GiB"`).
    pub mem_total: String,
    /// Uptime, human-readable (e.g. `"1h 0m 0s"`).
    pub uptime: String,
    /// Load average (1/5/15-minute), e.g. `"1.50 1.20 1.00"`.
    pub load: String,
}

/// Compile-time application build metadata sourced from `Cargo.toml` and
/// `cfg!(debug_assertions)`.
#[derive(Clone, Debug)]
pub struct AboutApp {
    /// Package name (`CARGO_PKG_NAME`).
    pub name: String,
    /// Package version (`CARGO_PKG_VERSION`).
    pub version: String,
    /// Build profile: `"debug"` or `"release"`.
    pub profile: String,
    /// Package homepage (`CARGO_PKG_HOMEPAGE`).
    pub homepage: String,
    /// Package authors (`CARGO_PKG_AUTHORS`), comma-joined.
    pub authors: String,
}

/// Runtime environment context gathered from `std::env` and the `dirs` crate.
#[derive(Clone, Debug)]
pub struct AboutRuntime {
    /// `$TERM` (e.g. `"xterm-256color"`).
    pub term: String,
    /// `$TERM_PROGRAM` (e.g. `"iTerm.app"`).
    pub term_program: String,
    /// `$SHELL` (e.g. `"/bin/zsh"`).
    pub shell: String,
    /// `$USER` / `$LOGNAME`.
    pub user: String,
    /// `$LANG` / `$LC_ALL`.
    pub lang: String,
    /// `$HOME`.
    pub home: String,
    /// `$PWD` / current working directory.
    pub cwd: String,
    /// Per-user config directory via `dirs::config_dir`.
    pub config_dir: String,
    /// Per-user data directory via `dirs::data_dir`.
    pub data_dir: String,
    /// Resolved toride log file path (same resolution as the Logs screen).
    pub log_path: String,
}

// ── AboutContent ────────────────────────────────────────────────────────────

/// About-toride content rendered inside the dashboard content area.
///
/// READ-ONLY: there are no write operations, no optimistic updates, no loading
/// spinner, no cooldown. Data arrives via [`AboutContent::set_*`] setters driven
/// by [`AboutCollector`](crate::about_data::AboutCollector).
pub struct AboutContent {
    /// Whether the About bundle was collected at all. `false` means the section
    /// renders a degraded "unavailable" panel instead of live identity data.
    available: bool,
    /// Live host/system identity.
    system: AboutSystem,
    /// Compile-time app build metadata.
    app: AboutApp,
    /// Runtime environment context.
    runtime: AboutRuntime,
    /// Human-readable reason the bundle was unavailable, surfaced in the
    /// degraded panel. Populated only when a collection task panicked.
    unavailable_reason: Option<String>,
    /// Vertical scroll offset over the whole pane.
    scroll: usize,
}

impl Default for AboutContent {
    fn default() -> Self {
        Self::new()
    }
}

impl AboutContent {
    /// Create a new empty content area.
    #[must_use]
    pub fn new() -> Self {
        Self {
            available: false,
            system: AboutSystem::empty(),
            app: AboutApp::empty(),
            runtime: AboutRuntime::empty(),
            unavailable_reason: None,
            scroll: 0,
        }
    }

    /// Whether the section has a modal open. Read-only section → never.
    #[must_use]
    pub fn has_modal(&self) -> bool {
        false
    }

    // ── Data setters ─────────────────────────────────────────────────────────

    /// Replace the host/system identity block.
    pub fn set_system(&mut self, system: AboutSystem) {
        self.system = system;
    }

    /// Replace the app build-metadata block.
    pub fn set_app(&mut self, app: AboutApp) {
        self.app = app;
    }

    /// Replace the runtime environment block.
    pub fn set_runtime(&mut self, runtime: AboutRuntime) {
        self.runtime = runtime;
    }

    /// Set the overall availability flag (false → degraded panel).
    pub fn set_available(&mut self, available: bool) {
        self.available = available;
    }

    /// Set the human-readable reason the bundle was unavailable. Cleared
    /// (`None`) whenever availability flips back to `true` so a stale panic
    /// message can't linger after recovery.
    pub fn set_unavailable_reason(&mut self, reason: Option<String>) {
        self.unavailable_reason = if self.available { None } else { reason };
    }

    // ── Input ────────────────────────────────────────────────────────────────

    /// Handle a key press. Returns `Some(Action)` only for Esc → Back; scroll
    /// keys are consumed here. About has no sub-selector, so Left/Right are
    /// NOT consumed (they fall through to the shell focus manager).
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

    // ── Rendering ───────────────────────────────────────────────────────────

    /// Render the full About content area.
    pub fn view(&mut self, frame: &mut Frame, area: Rect, p: Palette) {
        if !self.available {
            self.render_unavailable(frame, area, p);
            return;
        }

        let inner = render_titled_panel(
            frame,
            area,
            p,
            &format!(" ABOUT · toride v{} ", self.app.version),
            p.accent,
            true,
        );

        if inner.height == 0 {
            return;
        }

        // Build the full content as a Vec<Line> then render only the visible
        // window (mirrors the harden / fail2ban / ufw-kit manual-scroll
        // approach).
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

    /// Render the degraded state when the About bundle could not be collected.
    ///
    /// `available == false` is set ONLY when a collection task panicked
    /// (`JoinError`) — the underlying `TorideStatus::collect` / env reads cannot
    /// realistically fail wholesale, so this branch is rare in practice.
    fn render_unavailable(&self, frame: &mut Frame, area: Rect, p: Palette) {
        let inner = render_titled_panel(frame, area, p, " ABOUT ", p.text_dim, false);
        if inner.height < 2 {
            return;
        }
        let msg = Line::from(vec![
            Span::styled("◇ ", Style::new().fg(p.warn)),
            Span::styled(
                "About unavailable",
                Style::new().fg(p.text).add_modifier(Modifier::BOLD),
            ),
        ]);
        // Prefer the panic reason from the bundle; otherwise a generic message
        // accurate for both the collection-failure case and the pre-first-poll
        // state.
        let detail_text = self
            .unavailable_reason
            .clone()
            .unwrap_or_else(|| "system / app identity could not be collected".to_string());
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

    /// Build the complete content as a flat list of lines (APP, SYSTEM,
    /// RUNTIME sections). Scrolling operates over this list.
    fn build_lines(&self, p: Palette) -> Vec<Line<'static>> {
        let mut lines: Vec<Line<'static>> = Vec::new();

        self.push_app_lines(&mut lines, p);
        lines.push(Line::raw(""));
        self.push_system_lines(&mut lines, p);
        lines.push(Line::raw(""));
        self.push_runtime_lines(&mut lines, p);

        lines
    }

    fn push_app_lines(&self, lines: &mut Vec<Line<'static>>, p: Palette) {
        lines.push(Line::from(Span::styled(
            "APP",
            Style::new().fg(p.accent).add_modifier(Modifier::BOLD),
        )));
        kv(lines, p, "name", &self.app.name);
        kv(lines, p, "version", &self.app.version);
        kv(lines, p, "profile", &self.app.profile);
        kv(lines, p, "homepage", &self.app.homepage);
        kv(lines, p, "authors", &self.app.authors);
    }

    fn push_system_lines(&self, lines: &mut Vec<Line<'static>>, p: Palette) {
        lines.push(Line::from(Span::styled(
            "SYSTEM",
            Style::new().fg(p.accent).add_modifier(Modifier::BOLD),
        )));
        kv(lines, p, "hostname", &self.system.hostname);
        kv(lines, p, "os", &self.system.os);
        kv(lines, p, "kernel", &self.system.kernel);
        kv(lines, p, "arch", &self.system.arch);
        kv(lines, p, "cpu", &self.system.cpu_brand);
        kv(lines, p, "cores", &self.system.cores);
        kv(lines, p, "memory", &self.system.mem_total);
        kv(lines, p, "uptime", &self.system.uptime);
        kv(lines, p, "load", &self.system.load);
    }

    fn push_runtime_lines(&self, lines: &mut Vec<Line<'static>>, p: Palette) {
        lines.push(Line::from(Span::styled(
            "RUNTIME",
            Style::new().fg(p.accent).add_modifier(Modifier::BOLD),
        )));
        kv(lines, p, "term", &self.runtime.term);
        kv(lines, p, "term_program", &self.runtime.term_program);
        kv(lines, p, "shell", &self.runtime.shell);
        kv(lines, p, "user", &self.runtime.user);
        kv(lines, p, "lang", &self.runtime.lang);
        kv(lines, p, "home", &self.runtime.home);
        kv(lines, p, "cwd", &self.runtime.cwd);
        kv(lines, p, "config_dir", &self.runtime.config_dir);
        kv(lines, p, "data_dir", &self.runtime.data_dir);
        kv(lines, p, "log_path", &self.runtime.log_path);
    }
}

impl crate::ui::screens::section_overview::SectionOverview for AboutContent {
    fn available(&self) -> bool {
        self.available
    }

    fn status_label(&self) -> &'static str {
        // About carries no findings; status is active vs offline only.
        crate::ui::screens::section_overview::status_label_for(self.available, [] as [&str; 0])
    }

    fn detail(&self) -> Option<String> {
        if !self.available {
            return None;
        }
        Some(format!("toride v{}", self.app.version))
    }

    fn findings_count(&self) -> usize {
        0
    }
}

/// Push a labeled key:value line. The label is right-aligned in a fixed-width
/// column (`text_muted`) and the value follows (text). Empty values fall back to
/// the `"(none)"` placeholder so a blank row is never ambiguous.
fn kv(lines: &mut Vec<Line<'static>>, p: Palette, label: &str, value: &str) {
    let value_str = if value.is_empty() {
        "(none)".to_string()
    } else {
        value.to_string()
    };
    lines.push(Line::from(vec![
        Span::styled(format!("  {label:<12}"), Style::new().fg(p.text_muted)),
        Span::styled(value_str, Style::new().fg(p.text)),
    ]));
}

impl AboutSystem {
    /// All-placeholder identity block (used by [`AboutContent::new`] and the
    /// degraded bundle).
    fn empty() -> Self {
        Self::empty_for_bundle()
    }

    /// All-placeholder identity block, exposed publicly so the data bundle
    /// (`about_data::empty_bundle`) can construct a degraded bundle without
    /// duplicating the field list. Every field is `String::new()`; the render
    /// path substitutes `"(none)"` for blanks.
    pub fn empty_for_bundle() -> Self {
        Self {
            hostname: String::new(),
            os: String::new(),
            kernel: String::new(),
            arch: String::new(),
            cpu_brand: String::new(),
            cores: String::new(),
            mem_total: String::new(),
            uptime: String::new(),
            load: String::new(),
        }
    }
}

impl AboutApp {
    /// All-placeholder app block.
    fn empty() -> Self {
        Self::empty_for_bundle()
    }

    /// All-placeholder app block, exposed publicly for `about_data::empty_bundle`.
    pub fn empty_for_bundle() -> Self {
        Self {
            name: String::new(),
            version: String::new(),
            profile: String::new(),
            homepage: String::new(),
            authors: String::new(),
        }
    }
}

impl AboutRuntime {
    /// All-placeholder runtime block.
    fn empty() -> Self {
        Self::empty_for_bundle()
    }

    /// All-placeholder runtime block, exposed publicly for
    /// `about_data::empty_bundle`.
    pub fn empty_for_bundle() -> Self {
        Self {
            term: String::new(),
            term_program: String::new(),
            shell: String::new(),
            user: String::new(),
            lang: String::new(),
            home: String::new(),
            cwd: String::new(),
            config_dir: String::new(),
            data_dir: String::new(),
            log_path: String::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::screens::section_overview::SectionOverview;
    use crate::ui::theme::CHARM;
    use ratatui::{Terminal, backend::TestBackend};

    fn sample_app() -> AboutApp {
        AboutApp {
            name: "toride".into(),
            version: "0.1.0".into(),
            profile: "release".into(),
            homepage: "https://github.com/hmziq/toride".into(),
            authors: "hmziqrs".into(),
        }
    }

    fn sample_system() -> AboutSystem {
        AboutSystem {
            hostname: "edge-prod-01".into(),
            os: "Ubuntu 24.04 LTS".into(),
            kernel: "6.8.0".into(),
            arch: "x86_64".into(),
            cpu_brand: "Intel Xeon E5-2680 v4".into(),
            cores: "4".into(),
            mem_total: "16.0 GiB".into(),
            uptime: "1h 0m 0s".into(),
            load: "1.50 1.20 1.00".into(),
        }
    }

    fn sample_runtime() -> AboutRuntime {
        AboutRuntime {
            term: "xterm-256color".into(),
            term_program: "iTerm.app".into(),
            shell: "/bin/zsh".into(),
            user: "ops".into(),
            lang: "en_US.UTF-8".into(),
            home: "/home/ops".into(),
            cwd: "/home/ops".into(),
            config_dir: "/home/ops/.config".into(),
            data_dir: "/home/ops/.local/share".into(),
            log_path: "/home/ops/.cache/toride/toride.log".into(),
        }
    }

    /// Render a content area to a string (snapshot pattern from harden/fail2ban).
    fn render_to_string(content: &mut AboutContent, w: u16, h: u16) -> String {
        let mut terminal = Terminal::new(TestBackend::new(w, h)).unwrap();
        terminal.draw(|f| content.view(f, f.area(), CHARM)).unwrap();
        terminal.backend().to_string()
    }

    #[test]
    fn new_is_unavailable_and_empty() {
        let c = AboutContent::new();
        assert!(!c.available);
        assert!(c.system.hostname.is_empty());
        assert!(c.app.name.is_empty());
        assert!(c.runtime.shell.is_empty());
        assert!(!c.has_modal());
    }

    #[test]
    fn default_matches_new() {
        let from_new = AboutContent::new();
        let from_default = AboutContent::default();
        assert_eq!(from_new.available, from_default.available);
    }

    #[test]
    fn render_unavailable_when_not_available() {
        let mut c = AboutContent::new();
        let out = render_to_string(&mut c, 100, 24);
        assert!(out.contains("About unavailable"), "degraded panel: {out}");
    }

    #[test]
    fn render_unavailable_at_degenerate_height_does_not_panic() {
        let mut c = AboutContent::new();
        c.set_unavailable_reason(Some("spawn_blocking panicked".into()));
        // 20x5 — below the saturating_sub(3) threshold once the titled panel's
        // border/insets are accounted for.
        let _ = render_to_string(&mut c, 20, 5);
    }

    #[test]
    fn render_unavailable_skips_message_at_degenerate_inner_height() {
        let mut c = AboutContent::new();
        c.set_unavailable_reason(Some("spawn_blocking panicked".into()));
        // Area height 1 → border consumes the only row → inner.height == 0.
        let out_h1 = render_to_string(&mut c, 40, 1);
        assert!(
            !out_h1.contains("About unavailable"),
            "inner.height == 0 must early-return: {out_h1}"
        );
        // Area height 2 → inner.height == 1, still below the `< 2` threshold.
        let out_h2 = render_to_string(&mut c, 40, 2);
        assert!(
            !out_h2.contains("About unavailable"),
            "inner.height == 1 must early-return: {out_h2}"
        );
    }

    #[test]
    fn render_app_section_fields() {
        let mut c = AboutContent::new();
        c.set_available(true);
        c.set_app(sample_app());
        let out = render_to_string(&mut c, 100, 30);
        assert!(out.contains("toride"), "app name: {out}");
        assert!(out.contains("0.1.0"), "app version: {out}");
        assert!(out.contains("release"), "profile: {out}");
        assert!(out.contains("hmziqrs"), "authors: {out}");
    }

    #[test]
    fn render_system_section_fields() {
        let mut c = AboutContent::new();
        c.set_available(true);
        c.set_system(sample_system());
        let out = render_to_string(&mut c, 100, 40);
        assert!(out.contains("edge-prod-01"), "hostname: {out}");
        assert!(out.contains("Ubuntu 24.04 LTS"), "os: {out}");
        assert!(out.contains("Intel Xeon"), "cpu brand: {out}");
        assert!(out.contains("16.0 GiB"), "memory: {out}");
    }

    #[test]
    fn render_runtime_section_fields() {
        let mut c = AboutContent::new();
        c.set_available(true);
        c.set_runtime(sample_runtime());
        let out = render_to_string(&mut c, 100, 40);
        assert!(out.contains("/bin/zsh"), "shell: {out}");
        assert!(out.contains("iTerm.app"), "term_program: {out}");
        assert!(out.contains("toride.log"), "log_path: {out}");
    }

    #[test]
    fn render_header_carries_version() {
        let mut c = AboutContent::new();
        c.set_available(true);
        c.set_app(sample_app());
        let out = render_to_string(&mut c, 100, 30);
        assert!(out.contains("toride v0.1.0"), "titled panel header: {out}");
    }

    #[test]
    fn empty_value_renders_none_placeholder() {
        let mut c = AboutContent::new();
        c.set_available(true);
        // App block with an empty homepage → "(none)" placeholder.
        let mut app = sample_app();
        app.homepage.clear();
        c.set_app(app);
        let out = render_to_string(&mut c, 100, 30);
        assert!(out.contains("(none)"), "empty value placeholder: {out}");
    }

    #[test]
    fn scroll_down_consumed_and_returns_none() {
        let mut c = AboutContent::new();
        c.set_available(true);
        assert!(c.handle_key(KeyCode::Down).is_none());
        assert_eq!(c.scroll, 1);
    }

    #[test]
    fn scroll_up_at_zero_stays_zero() {
        let mut c = AboutContent::new();
        c.set_available(true);
        c.handle_key(KeyCode::Up);
        assert_eq!(c.scroll, 0);
    }

    #[test]
    fn page_scroll_jumps_eight() {
        let mut c = AboutContent::new();
        c.set_available(true);
        c.handle_key(KeyCode::PageDown);
        assert_eq!(c.scroll, 8);
        c.handle_key(KeyCode::PageUp);
        assert_eq!(c.scroll, 0);
    }

    #[test]
    fn left_right_are_not_consumed() {
        // About has no sub-selector: Left/Right fall through to the shell focus
        // manager (return None without mutating scroll).
        let mut c = AboutContent::new();
        c.set_available(true);
        assert!(c.handle_key(KeyCode::Left).is_none());
        assert!(c.handle_key(KeyCode::Right).is_none());
        assert_eq!(c.scroll, 0);
    }

    #[test]
    fn esc_returns_back_action() {
        let mut c = AboutContent::new();
        assert_eq!(c.handle_key(KeyCode::Esc), Some(Action::Back));
    }

    #[test]
    fn mouse_scroll_wheel_adjusts_scroll() {
        let mut c = AboutContent::new();
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
    fn section_overview_findings_count_is_zero() {
        let c = AboutContent::new();
        assert_eq!(c.findings_count(), 0);
    }

    #[test]
    fn section_overview_detail_includes_version_when_available() {
        let mut c = AboutContent::new();
        c.set_available(true);
        c.set_app(sample_app());
        assert_eq!(c.detail().as_deref(), Some("toride v0.1.0"));
    }

    #[test]
    fn section_overview_detail_none_when_unavailable() {
        let c = AboutContent::new();
        assert!(c.detail().is_none());
    }

    #[test]
    fn section_overview_status_label_offline_when_unavailable() {
        let c = AboutContent::new();
        assert_eq!(c.status_label(), "offline");
    }

    #[test]
    fn section_overview_status_label_active_when_available() {
        let mut c = AboutContent::new();
        c.set_available(true);
        assert_eq!(c.status_label(), "active");
    }

    #[test]
    fn set_unavailable_reason_clears_when_available() {
        let mut c = AboutContent::new();
        c.set_unavailable_reason(Some("boom".into()));
        assert_eq!(c.unavailable_reason.as_deref(), Some("boom"));
        // Flipping available to true must clear the reason so a stale panic
        // message cannot linger after recovery.
        c.set_available(true);
        c.set_unavailable_reason(Some("boom".into()));
        assert!(c.unavailable_reason.is_none());
    }

    #[test]
    fn tiny_terminal_does_not_panic() {
        let mut c = AboutContent::new();
        c.set_available(true);
        c.set_app(sample_app());
        c.set_system(sample_system());
        c.set_runtime(sample_runtime());
        // 20x5 — well below comfortable, must not panic.
        let _ = render_to_string(&mut c, 20, 5);
    }

    #[test]
    fn scroll_clamped_at_render_time_does_not_panic() {
        let mut c = AboutContent::new();
        c.set_available(true);
        c.set_app(sample_app());
        c.scroll = 1_000_000;
        // After a render the scroll is clamped to the visible window.
        let _ = render_to_string(&mut c, 100, 30);
        // The important property is the render did not panic.
    }

    #[test]
    fn empty_states_render_without_panic() {
        let mut c = AboutContent::new();
        c.set_available(true);
        // No set_* calls → every value is "" → "(none)" placeholders.
        let out = render_to_string(&mut c, 100, 40);
        assert!(out.contains("(none)"), "empty-value placeholder: {out}");
    }

    // ── Full-screen insta snapshots ─────────────────────────────────────────
    //
    // Pin the full rendered output at fixed terminal sizes so a layout
    // regression (column widths, section headers, the titled-panel header
    // version) cannot slip past the contains-assertions silently.

    #[test]
    fn about_content_snapshot_120x40() {
        let mut c = AboutContent::new();
        c.set_available(true);
        c.set_app(sample_app());
        c.set_system(sample_system());
        c.set_runtime(sample_runtime());
        let out = render_to_string(&mut c, 120, 40);
        insta::assert_snapshot!("about_content_120x40", out);
    }

    #[test]
    fn about_content_snapshot_unavailable_100x24() {
        let mut c = AboutContent::new();
        c.set_unavailable_reason(Some("spawn_blocking panicked".into()));
        let out = render_to_string(&mut c, 100, 24);
        insta::assert_snapshot!("about_content_unavailable_100x24", out);
    }
}
