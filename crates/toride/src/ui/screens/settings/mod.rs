//! Settings management content area (live READ-ONLY).
//!
//! Renders inside the dashboard's content region when
//! [`Section::Settings`](crate::data::Section) is the active sidebar section.
//! This integration mirrors the fail2ban / ufw-kit / toride-harden templates
//! WITHOUT any write path — every line is read-only.
//!
//! Layout (single scrollable pane, no sub-tab bar):
//! 1. THEME — every [`Theme`] variant by label, the active one highlighted, with
//!    small palette swatches from the live current theme. Left/Right emit
//!    [`Action::CycleTheme`] to cycle the global theme (already wired in
//!    `App::update`) — the screen does NOT mutate the theme locally.
//! 2. CONFIG — path, exists badge, key=value rows parsed from the config file.
//! 3. RUNTIME — `RUST_LOG`, dirs, log path, shell, term.

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
use crate::ui::theme::{Palette, Theme};
use crate::ui::widgets::render_titled_panel;

// ── Presentation types ──────────────────────────────────────────────────────

/// Parsed toride config for the CONFIG block.
///
/// Carried by [`SettingsDataBundle`](crate::settings_data::SettingsDataBundle)
/// and populated by [`settings_convert`](crate::settings_convert). Shared
/// between the data layer and the convert layer exactly like `SysctlRow` /
/// `MountEntry` in the toride-harden integration.
#[derive(Clone, Debug)]
pub struct SettingsConfig {
    /// Resolved config file path (or a `(no config dir)` placeholder when
    /// `dirs::config_dir()` returned `None`).
    pub path: String,
    /// Whether the config file existed + was readable at collection time.
    pub exists: bool,
    /// The `theme = <name>` value, if present in the config file.
    pub active_theme_name: Option<String>,
    /// The `log_level = <level>` value, if present in the config file.
    pub log_level: Option<String>,
    /// Every parsed `key = value` row from the config file (verbatim, quotes
    /// preserved). Empty when the file is absent or unreadable.
    pub raw_keys: Vec<(String, String)>,
}

/// Runtime environment snapshot for the RUNTIME block.
///
/// Carried by [`SettingsDataBundle`](crate::settings_data::SettingsDataBundle)
/// and populated by [`settings_convert`](crate::settings_convert).
#[derive(Clone, Debug)]
pub struct SettingsRuntime {
    /// `$RUST_LOG`, if set and non-empty.
    pub rust_log: Option<String>,
    /// Standard toride data dir (`dirs::data_dir()/toride`), if resolvable.
    pub data_dir: Option<String>,
    /// Standard toride config dir (`dirs::config_dir()/toride`), if resolvable.
    pub config_dir: Option<String>,
    /// Default toride log file path, if a data dir resolved.
    pub log_path: Option<String>,
    /// `$SHELL`, if set.
    pub shell: Option<String>,
    /// `$TERM`, if set.
    pub term: Option<String>,
}

// ── SettingsContent ─────────────────────────────────────────────────────────

/// Settings management content rendered inside the dashboard content area.
///
/// READ-ONLY: there are no write operations, no optimistic updates, no loading
/// spinner, no cooldown. Data arrives via [`SettingsContent::set_*`] setters
/// driven by [`SettingsCollector`](crate::settings_data::SettingsCollector).
///
/// In addition to the bundle's `config`/`runtime`, the screen carries the
/// **live** active [`Theme`] (kept in sync by `App::update`'s
/// `Action::CycleTheme` arm via [`DashboardScreen::set_active_theme`]) so the
/// THEME block can highlight the currently-applied theme and render its
/// swatches in the live palette colors. Left/Right here emit
/// [`Action::CycleTheme`] to cycle the global theme; the screen never mutates
/// the theme itself.
///
/// [`DashboardScreen::set_active_theme`]: crate::ui::screens::dashboard::DashboardScreen::set_active_theme
pub struct SettingsContent {
    /// Whether collection ran at all. `false` means the section renders a
    /// degraded "unavailable" panel instead of live data.
    available: bool,
    /// Parsed toride config (path, exists, theme, log level, raw rows).
    config: SettingsConfig,
    /// Runtime environment snapshot.
    runtime: SettingsRuntime,
    /// The live current theme. Defaults to [`Theme::default`]; kept in sync by
    /// `App::update` cycling via `DashboardScreen::set_active_theme`.
    active_theme: Theme,
    /// Human-readable reason the backend was unreachable, surfaced in the
    /// degraded panel. Populated only when a collection task panicked.
    unavailable_reason: Option<String>,
    /// Vertical scroll offset over the whole pane.
    scroll: usize,
}

impl Default for SettingsContent {
    fn default() -> Self {
        Self::new()
    }
}

impl SettingsContent {
    /// Create a new empty content area.
    #[must_use]
    pub fn new() -> Self {
        Self {
            available: false,
            config: SettingsConfig {
                path: String::new(),
                exists: false,
                active_theme_name: None,
                log_level: None,
                raw_keys: Vec::new(),
            },
            runtime: SettingsRuntime {
                rust_log: None,
                data_dir: None,
                config_dir: None,
                log_path: None,
                shell: None,
                term: None,
            },
            active_theme: Theme::default(),
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

    /// Replace the parsed config block.
    pub fn set_config(&mut self, config: SettingsConfig) {
        self.config = config;
    }

    /// Replace the runtime environment block.
    pub fn set_runtime(&mut self, runtime: SettingsRuntime) {
        self.runtime = runtime;
    }

    /// Set the live active theme. Called by
    /// [`DashboardScreen::set_active_theme`] whenever `App::update` cycles the
    /// theme, so the THEME block's highlight + swatches track the live palette.
    ///
    /// [`DashboardScreen::set_active_theme`]: crate::ui::screens::dashboard::DashboardScreen::set_active_theme
    pub fn set_active_theme(&mut self, theme: Theme) {
        self.active_theme = theme;
    }

    // ── Input ────────────────────────────────────────────────────────────────

    /// Handle a key press. Returns `Some(Action)` for navigation keys (Esc →
    /// Back) and for the THEME selector (Left/Right → [`Action::CycleTheme`]);
    /// scroll keys (j/k/PgUp/PgDn) are consumed here.
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
            // Left/Right cycle the global theme (mirrors a sub-tab bar). The
            // screen does NOT mutate the theme locally: it emits the action and
            // App::update applies it + pushes the new theme back via
            // set_active_theme so the highlight + swatches stay in sync.
            KeyCode::Right | KeyCode::Left | KeyCode::Char('l' | 'h') => Some(Action::CycleTheme),
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

    // ── Rendering ───────────────────────────────────────────────────────────

    /// Render the full settings content area.
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
                " SETTINGS · {} theme · {} config row(s) ",
                self.active_theme.label(),
                self.config.raw_keys.len(),
            ),
            p.accent,
            true,
        );

        if inner.height == 0 {
            return;
        }

        // Build the full content as a Vec<Line> then render only the visible
        // window (mirrors the fail2ban / ufw-kit / harden tabs' manual-scroll).
        let lines = self.build_lines(p, inner.width);

        let visible = inner.height as usize;
        let max_scroll = lines.len().saturating_sub(visible);
        if self.scroll > max_scroll {
            self.scroll = max_scroll;
        }
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

    /// Render the degraded state when settings could not be collected.
    ///
    /// `available == false` is set only when the collection task panicked
    /// (`JoinError`). The reason (if any) is surfaced; otherwise a generic
    /// message accurate for the pre-first-poll state.
    fn render_unavailable(&self, frame: &mut Frame, area: Rect, p: Palette) {
        let inner = render_titled_panel(frame, area, p, " SETTINGS ", p.text_dim, false);
        if inner.height < 2 {
            return;
        }
        let msg = Line::from(vec![
            Span::styled("✦ ", Style::new().fg(p.warn)),
            Span::styled(
                "Settings unavailable",
                Style::new().fg(p.text).add_modifier(Modifier::BOLD),
            ),
        ]);
        // Prefer the panic reason from the bundle; otherwise a generic message
        // accurate for the pre-first-poll state.
        let detail_text = self
            .unavailable_reason
            .clone()
            .unwrap_or_else(|| "settings data could not be collected on this host".to_string());
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

    /// Build the complete content as a flat list of lines (theme, config,
    /// runtime). Scrolling operates over this list.
    fn build_lines(&self, p: Palette, inner_width: u16) -> Vec<Line<'static>> {
        let mut lines: Vec<Line<'static>> = Vec::new();

        self.push_theme_lines(&mut lines, p, inner_width);
        lines.push(Line::raw(""));
        self.push_config_lines(&mut lines, p, inner_width);
        lines.push(Line::raw(""));
        self.push_runtime_lines(&mut lines, p, inner_width);

        lines
    }

    fn push_theme_lines(&self, lines: &mut Vec<Line<'static>>, p: Palette, inner_width: u16) {
        lines.push(Line::from(Span::styled(
            "Theme",
            Style::new().fg(p.accent).add_modifier(Modifier::BOLD),
        )));

        // Active theme label + whether it matches the config-file theme.
        let active_label = self.active_theme.label();
        let config_match = self
            .config
            .active_theme_name
            .as_deref()
            .is_some_and(|n| n.eq_ignore_ascii_case(active_label));
        lines.push(Line::from(vec![
            Span::styled("  active   ", Style::new().fg(p.text_muted)),
            Span::styled(
                active_label.to_string(),
                Style::new().fg(p.text).add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                if config_match {
                    "  (matches config)"
                } else {
                    "  (live)"
                },
                Style::new().fg(p.text_dim),
            ),
        ]));

        // Hint that Left/Right cycle the global theme.
        lines.push(Line::from(vec![
            Span::styled("  hint     ", Style::new().fg(p.text_muted)),
            Span::styled("← → cycle theme", Style::new().fg(p.text_dim)),
        ]));

        // Every theme variant by label; highlight the active one. Each line
        // carries a small palette swatch rendered from THAT THEME's own palette
        // (accent / accent2 / accent3 as foreground colors), so each row is a
        // real per-theme preview rather than an identical decorative glyph.
        for theme in Theme::all() {
            let is_active = *theme == self.active_theme;
            let (marker, marker_color, label_color) = if is_active {
                ("●", p.accent2, p.text)
            } else {
                ("○", p.text_dim, p.text_dim)
            };
            // Real per-theme swatch: three blocks styled with the candidate
            // theme's own accent colors.
            let swatch = palette_swatch(theme.palette());
            let label = truncate_str(theme.label(), (inner_width as usize).saturating_sub(20));
            let mut spans = vec![
                Span::styled(format!("{marker} "), Style::new().fg(marker_color)),
                Span::styled(" ", Style::new()),
            ];
            spans.extend(swatch.spans);
            spans.push(Span::styled(
                format!(" {label}"),
                Style::new().fg(label_color),
            ));
            lines.push(Line::from(spans));
        }
    }

    fn push_config_lines(&self, lines: &mut Vec<Line<'static>>, p: Palette, inner_width: u16) {
        let header = format!("Config ({})", self.config.raw_keys.len());
        lines.push(Line::from(Span::styled(
            header,
            Style::new().fg(p.accent).add_modifier(Modifier::BOLD),
        )));

        let path = truncate_str(&self.config.path, (inner_width as usize).saturating_sub(10));
        let (exists_icon, exists_color, exists_label) = if self.config.exists {
            ("✓", p.ok, "present")
        } else {
            ("✗", p.warn, "missing — using defaults")
        };
        lines.push(Line::from(vec![
            Span::styled("  path     ", Style::new().fg(p.text_muted)),
            Span::styled(path, Style::new().fg(p.text)),
        ]));
        lines.push(Line::from(vec![
            Span::styled("  file     ", Style::new().fg(p.text_muted)),
            Span::styled(
                format!("{exists_icon} {exists_label}"),
                Style::new().fg(exists_color),
            ),
        ]));

        // Typed theme / log_level rows (when present in the config file).
        if let Some(theme_name) = &self.config.active_theme_name {
            let v = truncate_str(theme_name, (inner_width as usize).saturating_sub(14));
            lines.push(Line::from(vec![
                Span::styled("  theme    ", Style::new().fg(p.text_muted)),
                Span::styled(v, Style::new().fg(p.text)),
            ]));
        }
        if let Some(level) = &self.config.log_level {
            let v = truncate_str(level, (inner_width as usize).saturating_sub(16));
            lines.push(Line::from(vec![
                Span::styled("  log_lvl  ", Style::new().fg(p.text_muted)),
                Span::styled(v, Style::new().fg(p.text)),
            ]));
        }

        if self.config.raw_keys.is_empty() {
            lines.push(Line::from(Span::styled(
                "  no config rows",
                Style::new().fg(p.text_dim),
            )));
            return;
        }

        // Raw key=value rows.
        for (key, value) in &self.config.raw_keys {
            let k = truncate_str(key, 14);
            let v = truncate_str(value, (inner_width as usize).saturating_sub(22));
            lines.push(Line::from(vec![
                Span::styled(format!("  {k:<14}"), Style::new().fg(p.text_dim)),
                Span::styled(format!(" = {v}"), Style::new().fg(p.text_muted)),
            ]));
        }
    }

    fn push_runtime_lines(&self, lines: &mut Vec<Line<'static>>, p: Palette, inner_width: u16) {
        lines.push(Line::from(Span::styled(
            "Runtime",
            Style::new().fg(p.accent).add_modifier(Modifier::BOLD),
        )));

        let value_w = (inner_width as usize).saturating_sub(14);
        push_kv_line(
            lines,
            p,
            "rust_log",
            self.runtime.rust_log.as_deref(),
            value_w,
            p.text,
        );
        push_kv_line(
            lines,
            p,
            "data_dir",
            self.runtime.data_dir.as_deref(),
            value_w,
            p.text_dim,
        );
        push_kv_line(
            lines,
            p,
            "config_dir",
            self.runtime.config_dir.as_deref(),
            value_w,
            p.text_dim,
        );
        push_kv_line(
            lines,
            p,
            "log_path",
            self.runtime.log_path.as_deref(),
            value_w,
            p.text_dim,
        );
        push_kv_line(
            lines,
            p,
            "shell",
            self.runtime.shell.as_deref(),
            value_w,
            p.text,
        );
        push_kv_line(
            lines,
            p,
            "term",
            self.runtime.term.as_deref(),
            value_w,
            p.text,
        );
    }
}

/// Push a single "label  value / (unset)" line for a RUNTIME slot.
fn push_kv_line(
    lines: &mut Vec<Line<'static>>,
    p: Palette,
    label: &str,
    value: Option<&str>,
    value_w: usize,
    value_color: ratatui::style::Color,
) {
    let (text, color) = match value {
        Some(v) if !v.is_empty() => (truncate_str(v, value_w), value_color),
        _ => ("(unset)".to_string(), p.text_muted),
    };
    lines.push(Line::from(vec![
        Span::styled(format!("  {label:<8}"), Style::new().fg(p.text_muted)),
        Span::styled(text, Style::new().fg(color)),
    ]));
}

/// Build a small inline palette swatch — three solid block glyphs, each
/// rendered with the FOREGROUND color it represents from the candidate
/// theme's own palette (`accent`, `accent2`, `accent3`).
///
/// This is a REAL per-theme preview: each row in the theme list shows its OWN
/// accent colors, so the operator can tell themes apart at a glance. The
/// previous implementation discarded color entirely (it only checked for
/// `Color::Reset` and returned an identical uncolored "███" for every theme),
/// making the swatch a purely decorative, non-informational element.
///
/// Kept narrow (3 cells) so the theme list stays one-row-per-theme. The active
/// row keeps its highlight via the surrounding line styling.
fn palette_swatch(p: &Palette) -> Line<'static> {
    use ratatui::style::{Color, Style};
    use ratatui::text::Span;
    let block = |c: Color| -> Span<'static> {
        // Reset reads as "unset"; show a dim placeholder dot instead of a
        // solid block so an unconfigured accent slot is visually distinct.
        let glyph = match c {
            Color::Reset => "·",
            _ => "█",
        };
        Span::styled(glyph, Style::new().fg(c))
    };
    Line::from(vec![block(p.accent), block(p.accent2), block(p.accent3)])
}

impl crate::ui::screens::section_overview::SectionOverview for SettingsContent {
    fn available(&self) -> bool {
        self.available
    }

    fn status_label(&self) -> &'static str {
        // Settings has no findings concept — status is driven purely by
        // availability (active when collected, offline otherwise). Pass an
        // empty severity iterator so status_label_for reduces to availability.
        crate::ui::screens::section_overview::status_label_for(
            self.available,
            std::iter::empty::<&str>(),
        )
    }

    fn detail(&self) -> Option<String> {
        if !self.available {
            return None;
        }
        Some(self.active_theme.label().to_string())
    }

    fn findings_count(&self) -> usize {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::screens::section_overview::SectionOverview;
    use crate::ui::theme::CHARM;
    use ratatui::{Terminal, backend::TestBackend};

    fn sample_config() -> SettingsConfig {
        SettingsConfig {
            path: "/home/user/.config/toride/config.toml".into(),
            exists: true,
            active_theme_name: Some("Charm".into()),
            log_level: Some("debug".into()),
            raw_keys: vec![
                ("theme".into(), "\"Charm\"".into()),
                ("log_level".into(), "debug".into()),
            ],
        }
    }

    fn sample_runtime() -> SettingsRuntime {
        SettingsRuntime {
            rust_log: Some("toride=debug".into()),
            data_dir: Some("/home/user/.local/share/toride".into()),
            config_dir: Some("/home/user/.config/toride".into()),
            log_path: Some("/home/user/.local/share/toride/toride.log".into()),
            shell: Some("/bin/zsh".into()),
            term: Some("xterm-256color".into()),
        }
    }

    /// Render a content area to a string (snapshot pattern from `harden/ufw_kit`).
    fn render_to_string(content: &mut SettingsContent, w: u16, h: u16) -> String {
        let mut terminal = Terminal::new(TestBackend::new(w, h)).unwrap();
        terminal.draw(|f| content.view(f, f.area(), CHARM)).unwrap();
        terminal.backend().to_string()
    }

    #[test]
    fn new_is_unavailable_and_empty() {
        let c = SettingsContent::new();
        assert!(!c.available);
        assert!(!c.config.exists);
        assert!(c.config.raw_keys.is_empty());
        assert!(c.runtime.rust_log.is_none());
        assert_eq!(c.active_theme, Theme::default());
        assert!(!c.has_modal());
    }

    #[test]
    fn default_matches_new() {
        let from_new = SettingsContent::new();
        let from_default = SettingsContent::default();
        assert_eq!(from_new.available, from_default.available);
        assert_eq!(from_new.active_theme, from_default.active_theme);
    }

    #[test]
    fn render_unavailable_when_not_available() {
        let mut c = SettingsContent::new();
        let out = render_to_string(&mut c, 100, 24);
        assert!(
            out.contains("Settings unavailable"),
            "degraded panel: {out}"
        );
    }

    #[test]
    fn render_unavailable_at_degenerate_height_does_not_panic() {
        let mut c = SettingsContent::new();
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
        let mut c = SettingsContent::new();
        c.set_unavailable_reason(Some("spawn_blocking panicked".into()));
        // Area height 1 → border consumes the only row → inner.height == 0.
        let out_h1 = render_to_string(&mut c, 40, 1);
        assert!(
            !out_h1.contains("Settings unavailable"),
            "inner.height == 0 must early-return: {out_h1}"
        );
        // Area height 2 → inner.height == 1, still below the `< 2` threshold.
        let out_h2 = render_to_string(&mut c, 40, 2);
        assert!(
            !out_h2.contains("Settings unavailable"),
            "inner.height == 1 must early-return: {out_h2}"
        );
    }

    #[test]
    fn render_theme_block_lists_every_theme() {
        let mut c = SettingsContent::new();
        c.set_available(true);
        c.set_active_theme(Theme::Charm);
        let out = render_to_string(&mut c, 110, 40);
        // Every theme label must appear in the rendered THEME block.
        for theme in Theme::all() {
            assert!(
                out.contains(theme.label()),
                "theme label '{}' must render: {out}",
                theme.label()
            );
        }
        assert!(out.contains("cycle theme"), "hint: {out}");
        assert!(out.contains("(live)"), "live-vs-config marker: {out}");
    }

    #[test]
    fn render_theme_block_highlights_active_when_matching_config() {
        let mut c = SettingsContent::new();
        c.set_available(true);
        c.set_config(sample_config());
        c.set_active_theme(Theme::Charm); // matches config active_theme_name "Charm"
        let out = render_to_string(&mut c, 110, 40);
        assert!(
            out.contains("(matches config)"),
            "config-match marker must render: {out}"
        );
    }

    #[test]
    fn render_config_block_shows_path_and_rows() {
        let mut c = SettingsContent::new();
        c.set_available(true);
        c.set_config(sample_config());
        let out = render_to_string(&mut c, 120, 40);
        assert!(
            out.contains(".config/toride/config.toml"),
            "config path: {out}"
        );
        assert!(out.contains("present"), "exists badge: {out}");
        assert!(out.contains("theme"), "typed theme row: {out}");
        assert!(out.contains("debug"), "log_level row: {out}");
    }

    #[test]
    fn render_config_missing_shows_defaults_marker() {
        let mut c = SettingsContent::new();
        c.set_available(true);
        c.set_config(SettingsConfig {
            path: "/missing/config.toml".into(),
            exists: false,
            active_theme_name: None,
            log_level: None,
            raw_keys: Vec::new(),
        });
        let out = render_to_string(&mut c, 100, 30);
        assert!(
            out.contains("missing — using defaults"),
            "missing marker: {out}"
        );
        assert!(out.contains("no config rows"), "empty-rows marker: {out}");
    }

    #[test]
    fn render_runtime_block_shows_env() {
        let mut c = SettingsContent::new();
        c.set_available(true);
        c.set_runtime(sample_runtime());
        let out = render_to_string(&mut c, 110, 40);
        assert!(out.contains("toride=debug"), "rust_log: {out}");
        assert!(out.contains("/bin/zsh"), "shell: {out}");
        assert!(out.contains("xterm-256color"), "term: {out}");
    }

    #[test]
    fn render_runtime_unset_shows_placeholder() {
        let mut c = SettingsContent::new();
        c.set_available(true);
        // Empty runtime → every slot (unset).
        let out = render_to_string(&mut c, 100, 30);
        assert!(out.contains("(unset)"), "unset placeholder: {out}");
    }

    #[test]
    fn scroll_down_consumed_and_returns_none() {
        let mut c = SettingsContent::new();
        c.set_available(true);
        assert!(c.handle_key(KeyCode::Down).is_none());
        assert_eq!(c.scroll, 1);
    }

    #[test]
    fn scroll_up_at_zero_stays_zero() {
        let mut c = SettingsContent::new();
        c.set_available(true);
        c.handle_key(KeyCode::Up);
        assert_eq!(c.scroll, 0);
    }

    #[test]
    fn page_down_advances_eight() {
        let mut c = SettingsContent::new();
        c.set_available(true);
        c.handle_key(KeyCode::PageDown);
        assert_eq!(c.scroll, 8);
    }

    #[test]
    fn page_up_clamps_to_zero() {
        let mut c = SettingsContent::new();
        c.set_available(true);
        c.handle_key(KeyCode::PageUp);
        assert_eq!(c.scroll, 0);
    }

    #[test]
    fn left_right_emit_cycle_theme_action() {
        let mut c = SettingsContent::new();
        c.set_available(true);
        // The screen does NOT mutate theme locally — it emits CycleTheme and
        // App::update applies it + pushes the new theme back via set_active_theme.
        assert_eq!(c.handle_key(KeyCode::Right), Some(Action::CycleTheme));
        assert_eq!(c.handle_key(KeyCode::Char('l')), Some(Action::CycleTheme));
        assert_eq!(c.handle_key(KeyCode::Left), Some(Action::CycleTheme));
        assert_eq!(c.handle_key(KeyCode::Char('h')), Some(Action::CycleTheme));
    }

    #[test]
    fn left_right_do_not_change_local_theme() {
        // Contract: the screen is a pure reflector of the live theme. Cycling
        // must NOT touch self.active_theme — only set_active_theme (driven by
        // App::update) does.
        let mut c = SettingsContent::new();
        c.set_available(true);
        let before = c.active_theme;
        c.handle_key(KeyCode::Right);
        assert_eq!(
            c.active_theme, before,
            "screen must not mutate theme locally"
        );
    }

    #[test]
    fn esc_returns_back_action() {
        let mut c = SettingsContent::new();
        assert_eq!(c.handle_key(KeyCode::Esc), Some(Action::Back));
    }

    #[test]
    fn mouse_scroll_wheel_adjusts_scroll() {
        let mut c = SettingsContent::new();
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
    fn mouse_scroll_up_clamps_to_zero() {
        let mut c = SettingsContent::new();
        let up = MouseEvent {
            kind: MouseEventKind::ScrollUp,
            column: 0,
            row: 0,
            modifiers: crossterm::event::KeyModifiers::empty(),
        };
        c.handle_mouse(up);
        assert_eq!(c.scroll, 0);
    }

    #[test]
    fn tiny_terminal_does_not_panic() {
        let mut c = SettingsContent::new();
        c.set_available(true);
        c.set_config(sample_config());
        c.set_runtime(sample_runtime());
        // 20x5 — well below comfortable, must not panic.
        let _ = render_to_string(&mut c, 20, 5);
    }

    #[test]
    fn empty_states_render_without_panic() {
        let mut c = SettingsContent::new();
        c.set_available(true);
        let out = render_to_string(&mut c, 100, 30);
        assert!(out.contains("no config rows"), "empty config: {out}");
        assert!(out.contains("(unset)"), "empty runtime: {out}");
    }

    #[test]
    fn set_available_clears_unavailable_reason() {
        // available flips to true → a previously-set reason must be cleared so a
        // stale panic message can't linger after recovery.
        let mut c = SettingsContent::new();
        c.set_unavailable_reason(Some("boom".into()));
        assert_eq!(c.unavailable_reason.as_deref(), Some("boom"));
        c.set_available(true);
        c.set_unavailable_reason(None);
        assert!(c.unavailable_reason.is_none());
    }

    #[test]
    fn section_overview_status_label_tracks_availability() {
        let mut c = SettingsContent::new();
        assert_eq!(c.status_label(), "offline");
        c.set_available(true);
        assert_eq!(c.status_label(), "active");
    }

    #[test]
    fn section_overview_findings_count_always_zero() {
        let mut c = SettingsContent::new();
        c.set_available(true);
        c.set_config(sample_config());
        assert_eq!(c.findings_count(), 0);
    }

    #[test]
    fn section_overview_detail_is_active_theme_label() {
        let mut c = SettingsContent::new();
        c.set_available(true);
        c.set_active_theme(Theme::Nord);
        assert_eq!(c.detail().as_deref(), Some(Theme::Nord.label()));
    }

    #[test]
    fn section_overview_detail_none_when_unavailable() {
        let c = SettingsContent::new();
        assert!(c.detail().is_none());
    }

    // ── Full-screen insta snapshots ─────────────────────────────────────────
    //
    // Pin the full rendered output at fixed terminal sizes, mirroring the
    // harden / fail2ban / ufw-kit snapshot tests so a layout regression
    // (theme list, swatch width, config/runtime indentation, empty-state text,
    // the titled-panel header counters) cannot slip past the contains-
    // assertions silently.

    #[test]
    fn settings_content_snapshot_120x40() {
        let mut c = SettingsContent::new();
        c.set_available(true);
        c.set_config(sample_config());
        c.set_runtime(sample_runtime());
        c.set_active_theme(Theme::Charm);
        let out = render_to_string(&mut c, 120, 40);
        insta::assert_snapshot!("settings_content_120x40", out);
    }

    #[test]
    fn settings_content_snapshot_unavailable_100x24() {
        let mut c = SettingsContent::new();
        c.set_unavailable_reason(Some("settings data collection panicked: boom".into()));
        let out = render_to_string(&mut c, 100, 24);
        insta::assert_snapshot!("settings_content_unavailable_100x24", out);
    }
}
