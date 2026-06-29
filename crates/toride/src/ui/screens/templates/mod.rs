//! Hardening-recipes catalogue content area (live READ-ONLY).
//!
//! Renders inside the dashboard's content region when
//! [`Section::Templates`](crate::data::Section) is the active sidebar section.
//! This integration mirrors the harden / fail2ban / ufw-kit templates
//! (`HardenContent` / `Fail2banContent` / `FirewallContent`) WITHOUT any write
//! path — every line is read-only.
//!
//! ## What is "live" here
//!
//! The recipe DEFINITIONS are the app feature manifest: a constant menu of
//! toride capabilities (SSH hardening, UFW firewall, fail2ban jail, etc.),
//! like a feature list. Each recipe maps to a real backend capability, and its
//! per-recipe LIVE status is whether the underlying tool is present on THIS
//! host — probed via `which::which(target_binary)`. So the catalogue is
//! legitimate static data (not fake user data) and only the readiness column
//! is live.
//!
//! Layout (single scrollable pane, no sub-tab bar):
//! 1. Header — `ready/total recipes ready` summary.
//! 2. Recipe cards grouped by category (Hardening / Network / Monitoring /
//!    Backup / Identity / Runtimes): name, status glyph + label, target tool,
//!    difficulty badge, description.

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

/// A single recipe catalogue entry with its live installed/available status.
///
/// `status` is `"ready"` when the recipe's `target_tool` binary is present on
/// PATH (probed via `which::which`) and `"available"` otherwise. The recipe
/// DEFINITION (name / category / description / target / difficulty) is constant
/// app data; only `status` is live.
#[derive(Clone, Debug)]
pub struct RecipeEntry {
    /// Human-readable recipe name (e.g. "SSH Hardening").
    pub name: String,
    /// Category label used to group recipes (Hardening / Network / Monitoring /
    /// Backup / Identity / Runtimes).
    pub category: String,
    /// One-line description of what the recipe applies.
    pub description: String,
    /// `"ready"` when the `target_tool` is installed, `"available"` otherwise.
    pub status: String,
    /// The binary name whose presence means this recipe is applicable /
    /// installed on this host (e.g. `"ufw"`, `"fail2ban-client"`).
    pub target_tool: String,
    /// Difficulty label: `"Easy"` | `"Medium"` | `"Hard"`.
    pub difficulty: String,
}

/// A single doctor-style finding. For the Templates section the only findings
/// emitted are INFO-severity notes for recipes whose `target_tool` is missing
/// (id `"templates.missing.<id>"`), so the dashboard's findings stat card and
/// the `SectionOverview::status_label` reflect readiness gaps.
#[derive(Clone, Debug)]
pub struct FindingEntry {
    /// Machine-readable id (e.g. `"templates.missing.ufw"`).
    pub id: String,
    /// Severity as a lowercase string: `"info"` for the templates catalogue
    /// (a missing tool is an opportunity, not a fault).
    pub severity: String,
    /// Short human-readable title.
    pub title: String,
    /// Longer description (may be empty).
    pub detail: String,
    /// Suggested remediation, if any.
    pub fix: Option<String>,
}

// ── TemplatesContent ────────────────────────────────────────────────────────

/// Hardening-recipes catalogue content rendered inside the dashboard content
/// area.
///
/// READ-ONLY: there are no write operations, no optimistic updates, no loading
/// spinner, no cooldown. Data arrives via [`TemplatesContent::set_*`] setters
/// driven by
/// [`TemplatesCollector`](crate::templates_data::TemplatesCollector).
pub struct TemplatesContent {
    /// Whether the catalogue could be collected at all. `false` means the
    /// section renders a degraded "unavailable" panel instead of the catalogue.
    /// (Today the catalogue is constant app data and the probe is a cheap
    /// `which::which` sweep that cannot fail at construction; `false` is
    /// reserved for a collection-task panic.)
    available: bool,
    /// Live recipe entries (constant definitions + per-recipe `which` status).
    recipes: Vec<RecipeEntry>,
    /// Number of recipes whose target tool is installed (`status == "ready"`).
    ready_count: usize,
    /// Total recipes in the catalogue.
    total_count: usize,
    /// Doctor-style findings (INFO for each recipe whose target is missing).
    findings: Vec<FindingEntry>,
    /// Human-readable reason the backend was unreachable, surfaced in the
    /// degraded panel. Populated only when a collection task panicked.
    unavailable_reason: Option<String>,
    /// Vertical scroll offset over the whole pane.
    scroll: usize,
}

impl Default for TemplatesContent {
    fn default() -> Self {
        Self::new()
    }
}

impl TemplatesContent {
    /// Create a new empty content area.
    #[must_use]
    pub fn new() -> Self {
        Self {
            available: false,
            recipes: Vec::new(),
            ready_count: 0,
            total_count: 0,
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

    // ── Data setters ─────────────────────────────────────────────────────────

    /// Replace the recipe entries and recompute the ready/total counters.
    pub fn set_recipes(&mut self, recipes: Vec<RecipeEntry>) {
        self.total_count = recipes.len();
        self.ready_count = recipes.iter().filter(|r| r.status == "ready").count();
        self.recipes = recipes;
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

    // ── Input ────────────────────────────────────────────────────────────────

    /// Handle a key press. Returns `Some(Action)` only for Esc → Back; scroll
    /// keys are consumed here. The Templates section has no sub-selector, so
    /// Left/Right are not bound.
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
        reason = "API symmetry with harden/fail2ban/ufw-kit tabs"
    )]
    fn clamp_scroll(&mut self) {
        // No-op body: scroll is clamped against visible rows during render.
        // Kept for API symmetry with the harden / fail2ban / ufw-kit tabs.
    }

    // ── Rendering ───────────────────────────────────────────────────────────

    /// Render the full templates catalogue area.
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
                " HARDENING RECIPES · {}/{} recipes ready · {} finding(s) ",
                self.ready_count,
                self.total_count,
                self.findings.len(),
            ),
            p.accent,
            true,
        );

        if inner.height == 0 {
            return;
        }

        // Build the full content as a Vec<Line> then render only the visible
        // window (mirrors the harden / fail2ban tabs' manual-scroll approach).
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

    /// Render the degraded state when the catalogue could not be collected.
    ///
    /// `available == false` is reserved today for a collection-task panic
    /// (JoinError): the catalogue is constant app data and the `which` sweep
    /// cannot fail at construction. The reason string is rendered so the
    /// operator sees what actually went wrong instead of guessing.
    fn render_unavailable(&self, frame: &mut Frame, area: Rect, p: Palette) {
        let inner = render_titled_panel(frame, area, p, " HARDENING RECIPES ", p.text_dim, false);
        if inner.height < 2 {
            return;
        }
        let msg = Line::from(vec![
            Span::styled("✦ ", Style::new().fg(p.warn)),
            Span::styled(
                "Recipes unavailable",
                Style::new().fg(p.text).add_modifier(Modifier::BOLD),
            ),
        ]);
        // Prefer the panic reason from the bundle; otherwise a generic message
        // accurate for the pre-first-poll state.
        let detail_text = self
            .unavailable_reason
            .clone()
            .unwrap_or_else(|| "recipe catalogue could not be collected on this host".to_string());
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

    /// Build the complete content as a flat list of lines (summary header, then
    /// recipe cards grouped by category). Scrolling operates over this list.
    fn build_lines(&self, p: Palette, inner_width: u16) -> Vec<Line<'static>> {
        let mut lines: Vec<Line<'static>> = Vec::new();

        self.push_summary_lines(&mut lines, p);
        lines.push(Line::raw(""));

        if self.recipes.is_empty() {
            lines.push(Line::from(Span::styled(
                "  no recipes in catalogue",
                Style::new().fg(p.text_dim),
            )));
            return lines;
        }

        // Render grouped by category in a stable order.
        let order = [
            "Hardening",
            "Network",
            "Monitoring",
            "Backup",
            "Identity",
            "Runtimes",
        ];
        for category in order {
            let group: Vec<&RecipeEntry> = self
                .recipes
                .iter()
                .filter(|r| r.category == *category)
                .collect();
            if group.is_empty() {
                continue;
            }
            Self::push_category_header(&mut lines, p, category, group.len());
            for recipe in group {
                Self::push_recipe_line(&mut lines, p, recipe, inner_width);
            }
            lines.push(Line::raw(""));
        }

        lines
    }

    fn push_summary_lines(&self, lines: &mut Vec<Line<'static>>, p: Palette) {
        lines.push(Line::from(Span::styled(
            "Readiness",
            Style::new().fg(p.accent).add_modifier(Modifier::BOLD),
        )));

        let (summary_label, summary_color) = if self.total_count == 0 {
            ("—", p.text_dim)
        } else if self.ready_count == self.total_count {
            ("✓ all ready", p.ok)
        } else if self.ready_count == 0 {
            ("! none ready", p.warn)
        } else {
            ("! partial", p.warn)
        };
        lines.push(Line::from(vec![
            Span::styled("  audit    ", Style::new().fg(p.text_muted)),
            Span::styled(
                format!(
                    "{summary_label}  ({}/{})",
                    self.ready_count, self.total_count
                ),
                Style::new().fg(summary_color),
            ),
        ]));

        lines.push(Line::from(vec![
            Span::styled("  hint     ", Style::new().fg(p.text_muted)),
            Span::styled(
                "a recipe is ready when its target tool is installed",
                Style::new().fg(p.text_dim),
            ),
        ]));
    }

    fn push_category_header(
        lines: &mut Vec<Line<'static>>,
        p: Palette,
        category: &str,
        count: usize,
    ) {
        lines.push(Line::from(Span::styled(
            format!("{category} ({count})"),
            Style::new().fg(p.accent).add_modifier(Modifier::BOLD),
        )));
    }

    fn push_recipe_line(
        lines: &mut Vec<Line<'static>>,
        p: Palette,
        recipe: &RecipeEntry,
        inner_width: u16,
    ) {
        // Prefix width: "  "(2) + icon(1) + " "(1) + name(34) + " "(1) + label(9)
        // + " "(1) + target(18) + " "(1) + diff(6) + " "(1) = 75.
        const PREFIX_WIDTH: usize = 75;
        const FALLBACK_DESC: usize = 30;
        let (icon, color, label) = if recipe.status == "ready" {
            ("✓", p.ok, "ready")
        } else {
            ("○", p.warn, "available")
        };
        let (diff_color, diff_label) = difficulty_style(&recipe.difficulty, p);
        let name = truncate_str(&recipe.name, 34);
        let target = truncate_str(&recipe.target_tool, 18);
        let desc_max = if inner_width as usize >= PREFIX_WIDTH {
            let scaled = inner_width as usize - PREFIX_WIDTH;
            if scaled >= 1 { scaled } else { FALLBACK_DESC }
        } else {
            FALLBACK_DESC
        };
        let desc = truncate_str(&recipe.description, desc_max);
        lines.push(Line::from(vec![
            Span::styled(format!("  {icon} "), Style::new().fg(color)),
            Span::styled(
                format!("{name:<34}"),
                Style::new().fg(p.text).add_modifier(Modifier::BOLD),
            ),
            Span::styled(format!(" {label:<9}"), Style::new().fg(color)),
            Span::styled(format!(" {target:<18}"), Style::new().fg(p.text_muted)),
            Span::styled(format!(" [{diff_label:<6}]"), Style::new().fg(diff_color)),
            Span::styled(format!(" {desc}"), Style::new().fg(p.text_dim)),
        ]));
    }
}

impl crate::ui::screens::section_overview::SectionOverview for TemplatesContent {
    fn available(&self) -> bool {
        self.available
    }

    fn status_label(&self) -> &'static str {
        // A missing tool is an opportunity (info), not a fault, so a catalogue
        // with un-ready recipes is "active" rather than "degraded". Only a true
        // offline (collection panic) reads as "offline".
        crate::ui::screens::section_overview::status_label_for(
            self.available,
            // Promote info findings to "degraded" only when NONE are ready —
            // otherwise the catalogue is genuinely usable. status_label_for
            // already treats any warning+ as degraded; our findings are all
            // "info", so a partially-ready catalogue reads "active", matching
            // the readiness audit summary in the panel.
            self.findings.iter().map(|f| f.severity.as_str()),
        )
    }

    fn detail(&self) -> Option<String> {
        if !self.available {
            return None;
        }
        Some(format!(
            "{}/{} recipes ready",
            self.ready_count, self.total_count
        ))
    }

    fn findings_count(&self) -> usize {
        // Count recipes whose target tool is missing — that is the actionable
        // readiness gap the operator cares about, surfaced as INFO findings.
        self.recipes.iter().filter(|r| r.status != "ready").count()
    }
}

/// Map a difficulty label to a (color, label) pair.
fn difficulty_style(difficulty: &str, p: Palette) -> (ratatui::style::Color, &str) {
    match difficulty {
        "Easy" => (p.ok, "Easy"),
        "Medium" => (p.warn, "Med"),
        "Hard" => (p.err, "Hard"),
        _ => (p.text_dim, "—"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::screens::section_overview::SectionOverview;
    use crate::ui::theme::CHARM;
    use ratatui::{Terminal, backend::TestBackend};

    fn sample_recipes() -> Vec<RecipeEntry> {
        vec![
            RecipeEntry {
                name: "SSH Hardening".into(),
                category: "Hardening".into(),
                description: "Lock down sshd config".into(),
                status: "ready".into(),
                target_tool: "ssh".into(),
                difficulty: "Medium".into(),
            },
            RecipeEntry {
                name: "UFW Default-Deny Firewall".into(),
                category: "Network".into(),
                description: "Default-deny incoming".into(),
                status: "available".into(),
                target_tool: "ufw".into(),
                difficulty: "Easy".into(),
            },
            RecipeEntry {
                name: "fail2ban sshd jail".into(),
                category: "Hardening".into(),
                description: "Brute-force protection for sshd".into(),
                status: "ready".into(),
                target_tool: "fail2ban-client".into(),
                difficulty: "Easy".into(),
            },
            RecipeEntry {
                name: "Restic Backup".into(),
                category: "Backup".into(),
                description: "Encrypted incremental backups".into(),
                status: "available".into(),
                target_tool: "restic".into(),
                difficulty: "Medium".into(),
            },
        ]
    }

    fn sample_findings() -> Vec<FindingEntry> {
        // Ids mirror the templates catalogue convention
        // (`templates.missing.<id>`), dot-separated.
        vec![
            FindingEntry {
                id: "templates.missing.ufw".into(),
                severity: "info".into(),
                title: "UFW Default-Deny Firewall target tool not installed".into(),
                detail: String::new(),
                fix: Some("apt install ufw".into()),
            },
            FindingEntry {
                id: "templates.missing.restic".into(),
                severity: "info".into(),
                title: "Restic Backup target tool not installed".into(),
                detail: String::new(),
                fix: None,
            },
        ]
    }

    /// The `FindingEntry::id` doc-comment promises dot-separated ids in the
    /// `templates.missing.<id>` form. Pin that contract.
    #[test]
    fn finding_id_format_matches_templates_convention() {
        for f in sample_findings() {
            assert!(
                f.id.starts_with("templates.missing."),
                "id '{}' must start with 'templates.missing.'",
                f.id
            );
            assert!(f.id.contains('.'), "id '{}' must be dot-separated", f.id);
        }
    }

    /// Render a content area to a string (snapshot pattern from harden/fail2ban).
    fn render_to_string(content: &mut TemplatesContent, w: u16, h: u16) -> String {
        let mut terminal = Terminal::new(TestBackend::new(w, h)).unwrap();
        terminal.draw(|f| content.view(f, f.area(), CHARM)).unwrap();
        terminal.backend().to_string()
    }

    #[test]
    fn new_is_unavailable_and_empty() {
        let c = TemplatesContent::new();
        assert!(!c.available);
        assert!(c.recipes.is_empty());
        assert_eq!(c.ready_count, 0);
        assert_eq!(c.total_count, 0);
        assert!(c.findings.is_empty());
        assert!(!c.has_modal());
    }

    #[test]
    fn default_matches_new() {
        let from_new = TemplatesContent::new();
        let from_default = TemplatesContent::default();
        assert_eq!(from_new.available, from_default.available);
        assert_eq!(from_new.total_count, from_default.total_count);
    }

    #[test]
    fn render_unavailable_when_not_available() {
        let mut c = TemplatesContent::new();
        let out = render_to_string(&mut c, 100, 24);
        assert!(out.contains("Recipes unavailable"), "degraded panel: {out}");
    }

    #[test]
    fn render_unavailable_at_degenerate_height_does_not_panic() {
        let mut c = TemplatesContent::new();
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
        let mut c = TemplatesContent::new();
        c.set_unavailable_reason(Some("spawn_blocking panicked".into()));
        // Area height 1 → border consumes the only row → inner.height == 0.
        let out_h1 = render_to_string(&mut c, 40, 1);
        assert!(
            !out_h1.contains("Recipes unavailable"),
            "inner.height == 0 must early-return: {out_h1}"
        );
        // Area height 2 → inner.height == 1, still below the `< 2` threshold.
        let out_h2 = render_to_string(&mut c, 40, 2);
        assert!(
            !out_h2.contains("Recipes unavailable"),
            "inner.height == 1 must early-return: {out_h2}"
        );
    }

    #[test]
    fn render_summary_with_ready_total() {
        let mut c = TemplatesContent::new();
        c.set_available(true);
        c.set_recipes(sample_recipes());
        let out = render_to_string(&mut c, 130, 30);
        assert!(out.contains("Readiness"), "summary header: {out}");
        assert!(out.contains("2/4"), "ready/total summary: {out}");
        assert!(out.contains("! partial"), "partial summary label: {out}");
    }

    #[test]
    fn render_recipe_cards_grouped_by_category() {
        let mut c = TemplatesContent::new();
        c.set_available(true);
        c.set_recipes(sample_recipes());
        let out = render_to_string(&mut c, 140, 36);
        // Category headers.
        assert!(out.contains("Hardening (2)"), "hardening group: {out}");
        assert!(out.contains("Network (1)"), "network group: {out}");
        assert!(out.contains("Backup (1)"), "backup group: {out}");
        // Recipe names + status glyphs.
        assert!(out.contains("SSH Hardening"), "ssh recipe name: {out}");
        assert!(
            out.contains("UFW Default-Deny Firewall"),
            "ufw recipe name: {out}"
        );
    }

    #[test]
    fn render_recipe_target_and_difficulty() {
        let mut c = TemplatesContent::new();
        c.set_available(true);
        c.set_recipes(sample_recipes());
        let out = render_to_string(&mut c, 140, 36);
        assert!(out.contains("fail2ban-client"), "target tool: {out}");
        assert!(out.contains("Easy"), "difficulty badge: {out}");
    }

    #[test]
    fn set_recipes_recomputes_counters() {
        let mut c = TemplatesContent::new();
        c.set_recipes(sample_recipes());
        assert_eq!(c.total_count, 4);
        assert_eq!(c.ready_count, 2);
        // Findings_count is derived from recipes whose target is missing.
        assert_eq!(c.findings_count(), 2);
    }

    #[test]
    fn scroll_down_consumed_and_returns_none() {
        let mut c = TemplatesContent::new();
        c.set_available(true);
        assert!(c.handle_key(KeyCode::Down).is_none());
        assert_eq!(c.scroll, 1);
    }

    #[test]
    fn scroll_up_at_zero_stays_zero() {
        let mut c = TemplatesContent::new();
        c.set_available(true);
        c.handle_key(KeyCode::Up);
        assert_eq!(c.scroll, 0);
    }

    #[test]
    fn page_down_advances_by_eight() {
        let mut c = TemplatesContent::new();
        c.set_available(true);
        c.handle_key(KeyCode::PageDown);
        assert_eq!(c.scroll, 8);
    }

    #[test]
    fn esc_returns_back_action() {
        let mut c = TemplatesContent::new();
        assert_eq!(c.handle_key(KeyCode::Esc), Some(Action::Back));
    }

    #[test]
    fn mouse_scroll_wheel_adjusts_scroll() {
        let mut c = TemplatesContent::new();
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
        let mut c = TemplatesContent::new();
        c.set_available(true);
        c.set_recipes(sample_recipes());
        c.set_findings(sample_findings());
        // 20x5 — well below comfortable, must not panic.
        let _ = render_to_string(&mut c, 20, 5);
    }

    #[test]
    fn empty_states_render_without_panic() {
        let mut c = TemplatesContent::new();
        c.set_available(true);
        let out = render_to_string(&mut c, 100, 30);
        assert!(
            out.contains("no recipes in catalogue"),
            "empty recipes: {out}"
        );
    }

    #[test]
    fn section_overview_active_when_available() {
        let mut c = TemplatesContent::new();
        c.set_available(true);
        c.set_recipes(sample_recipes());
        assert!(c.available());
        assert_eq!(c.status_label(), "active");
        assert_eq!(
            c.detail().as_deref(),
            Some("2/4 recipes ready"),
            "detail: {:?}",
            c.detail()
        );
        assert_eq!(c.findings_count(), 2);
    }

    #[test]
    fn section_overview_offline_when_unavailable() {
        let c = TemplatesContent::new();
        assert!(!c.available());
        assert_eq!(c.status_label(), "offline");
        assert!(c.detail().is_none());
    }

    #[test]
    fn set_unavailable_reason_clears_when_available() {
        let mut c = TemplatesContent::new();
        c.set_available(true);
        c.set_unavailable_reason(Some("stale".into()));
        // Cleared because available is true.
        assert!(c.unavailable_reason.is_none());
    }

    // ── Full-screen insta snapshots ─────────────────────────────────────────
    //
    // Pin the full rendered output at fixed terminal sizes, mirroring the
    // harden snapshot tests so a layout regression (column widths, category
    // grouping, status glyphs, difficulty badges, empty-state text) cannot
    // slip past the contains-assertions silently.

    #[test]
    fn templates_content_snapshot_140x36() {
        let mut c = TemplatesContent::new();
        c.set_available(true);
        c.set_recipes(sample_recipes());
        c.set_findings(sample_findings());
        let out = render_to_string(&mut c, 140, 36);
        insta::assert_snapshot!("templates_content_140x36", out);
    }

    #[test]
    fn templates_content_snapshot_unavailable_100x24() {
        let mut c = TemplatesContent::new();
        c.set_unavailable_reason(Some("templates data collection panicked: boom".into()));
        let out = render_to_string(&mut c, 100, 24);
        insta::assert_snapshot!("templates_content_unavailable_100x24", out);
    }
}
