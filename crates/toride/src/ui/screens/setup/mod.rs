//! Setup suggestions content area (read-only).
//!
//! Renders inside the dashboard content region when
//! [`Section::Setup`](crate::data::Section) is the active sidebar section,
//! mirroring `ToolsContent`: `set_*` setters fed by
//! [`SetupCollector`](crate::setup_data::SetupCollector), no host writes.
//!
//! Layout (single scrollable pane, no sub-tab bar):
//! 1. List view — one heading per offered bundle, one row per recommendation:
//!    selection marker, tool title, license badge, rationale.
//! 2. Detail view — the selected row's license label (summary, terms URL,
//!    verified date), its FOSS alternative, and its ordered actions.
//!
//! Consent gate: Enter on a row whose license is not
//! [`LicenseKind::Free`] opens the terms modal, and the row is approved for
//! install only once that modal is accepted in this session. Verdicts and
//! approvals live in memory only.

use std::collections::HashSet;

use crossterm::event::{KeyCode, MouseEvent, MouseEventKind};
use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Paragraph, Wrap},
};
use toride_apps::InstallMethod;

use crate::action::Action;
use crate::setup_bundles::{
    Consent, InstallAction, LicenseKind, Recommendation, SetupOffers, require_consent,
};
use crate::ui::components::{ButtonRow, interactive_button::InteractiveButton};
use crate::ui::responsive::{Viewport, truncate_str};
use crate::ui::screens::tools::FindingEntry;
use crate::ui::theme::Palette;
use crate::ui::widgets::{InteractiveModal, ModalEvent, render_titled_panel, tag_badge};

/// License-badge text width; rows pad the title column to this.
const TITLE_W: usize = 18;

/// Consent modal dimensions (clamped to the terminal at render time).
const MODAL_WIDTH: u16 = 56;
const MODAL_HEIGHT: u16 = 16;

/// Badge label for a license kind — the commercial-use fact in two words.
fn kind_label(kind: LicenseKind) -> &'static str {
    match kind {
        LicenseKind::Free => "free",
        LicenseKind::FreePersonal => "personal use only",
        LicenseKind::PaidForCommercial => "paid for commercial use",
        LicenseKind::FreeWithTerms => "free with terms",
    }
}

/// Badge colour for a license kind: consent-gated kinds tint, Free stays mute.
fn kind_color(kind: LicenseKind, p: Palette) -> Color {
    match kind {
        LicenseKind::Free => p.text_muted,
        LicenseKind::FreePersonal | LicenseKind::FreeWithTerms => p.info,
        LicenseKind::PaidForCommercial => p.warn,
    }
}

fn method_label(method: &InstallMethod) -> &'static str {
    match method {
        InstallMethod::Homebrew { cask: true, .. } => "brew cask",
        InstallMethod::Homebrew { .. } => "brew",
        InstallMethod::Cargo { .. } => "cargo",
        InstallMethod::Npm { .. } => "npm",
        InstallMethod::Pipx { .. } => "pipx",
        InstallMethod::Uv { .. } => "uv",
        InstallMethod::Mise { .. } => "mise",
        InstallMethod::Distro { .. } => "distro package",
        _ => "install",
    }
}

fn action_text(action: &InstallAction) -> String {
    match action {
        InstallAction::Install(spec) => {
            format!("install {} ({})", spec.name, method_label(&spec.method))
        }
        InstallAction::Hint(hint) => format!("config hint {}: {}", hint.path, hint.title),
        InstallAction::Manual { instructions } => format!("manual: {instructions}"),
    }
}

/// The canonical suggestion id (plan §9 shape) — one key space shared by
/// `dismissed`, `findings_count`, and the collector's `to_findings` feed.
pub(crate) fn suggest_id(bundle_id: &str, rec: &Recommendation) -> String {
    format!("setup.suggest.{bundle_id}.{}", rec.id)
}

// ── SetupContent ────────────────────────────────────────────────────────────

/// Setup suggestions content rendered inside the dashboard content area.
///
/// READ-ONLY: nothing here touches the host. Offers arrive via
/// [`SetupContent::set_offers`]; consent verdicts and dismissals are
/// session-scoped UI state.
pub struct SetupContent {
    /// Whether the presence walk ran. `false` means the section renders a
    /// degraded "unavailable" panel instead of live data.
    available: bool,
    /// Human-readable reason collection failed, surfaced in the degraded
    /// panel. Populated only when a collection task panicked.
    unavailable_reason: Option<String>,
    /// Evaluated offers for this host; `None` until the first bundle lands.
    offers: Option<SetupOffers>,
    /// Info-level suggestion findings (`setup.suggest.*` ids).
    findings: Vec<FindingEntry>,
    /// Suggestion ids dismissed this session, keyed by the namespaced
    /// [`suggest_id`] form (`setup.suggest.<bundle>.<rec>`) so the same set
    /// filters offered rows and the findings feed; they re-enter nothing
    /// until restart and survive offer refreshes.
    dismissed: HashSet<String>,
    /// In-session consent verdict per recommendation id.
    consent: std::collections::HashMap<&'static str, Consent>,
    /// Rows whose install intent passed the consent gate this session.
    approved: Vec<&'static str>,
    /// Selected row position over the undismissed rows.
    sel: usize,
    /// Whether the detail view replaces the list.
    detail_open: bool,
    /// Position of the row whose consent modal is open.
    pending_consent: Option<usize>,
    /// Terms modal; buttons default-focus `decline` so a bare Enter never
    /// accepts terms.
    consent_modal: InteractiveModal<Consent>,
    /// Vertical scroll offset over the whole pane.
    scroll: usize,
}

impl Default for SetupContent {
    fn default() -> Self {
        Self::new()
    }
}

impl SetupContent {
    /// Create a new empty content area.
    #[must_use]
    pub fn new() -> Self {
        Self {
            available: false,
            unavailable_reason: None,
            offers: None,
            findings: Vec::new(),
            dismissed: HashSet::new(),
            consent: std::collections::HashMap::new(),
            approved: Vec::new(),
            sel: 0,
            detail_open: false,
            pending_consent: None,
            consent_modal: InteractiveModal::with_buttons(
                "License terms",
                ButtonRow::new(
                    vec![
                        InteractiveButton::new("decline", "esc", Consent::Refused),
                        InteractiveButton::new("accept", "↵", Consent::Accepted),
                    ],
                    vec![2, 0],
                ),
            )
            .dimensions(MODAL_WIDTH, MODAL_HEIGHT),
            scroll: 0,
        }
    }

    /// Whether the consent modal is open.
    #[must_use]
    pub fn has_modal(&self) -> bool {
        self.consent_modal.is_visible()
    }

    // ── Data setters ─────────────────────────────────────────────────────────

    /// Set the overall availability flag (false → degraded panel).
    pub fn set_available(&mut self, available: bool) {
        self.available = available;
    }

    /// Set the human-readable reason collection failed. Cleared (`None`)
    /// whenever availability flips back to `true`.
    pub fn set_unavailable_reason(&mut self, reason: Option<String>) {
        self.unavailable_reason = if self.available { None } else { reason };
    }

    /// Replace the evaluated offers and reset the selection to the first
    /// bundle's `default_pick` (falling back to its first `Free` row when the
    /// pick was suppressed). Dismissals, verdicts, and approvals survive.
    pub fn set_offers(&mut self, offers: SetupOffers) {
        self.offers = Some(offers);
        self.detail_open = false;
        self.sel = self.default_selection();
    }

    /// Replace the suggestion findings list.
    pub fn set_findings(&mut self, findings: Vec<FindingEntry>) {
        self.findings = findings;
    }

    // ── Reads (tests + phase-4 wiring) ───────────────────────────────────────

    /// Undismissed offered rows, in bundle display order.
    #[must_use]
    pub fn suggestion_count(&self) -> usize {
        self.visible_rows().len()
    }

    /// The in-session consent verdict for `id`; [`Consent::Pending`] before
    /// the modal answers.
    #[must_use]
    pub fn consent_for(&self, id: &str) -> Consent {
        self.consent.get(id).copied().unwrap_or(Consent::Pending)
    }

    /// Rows whose install intent passed the consent gate this session, in
    /// approval order. Nothing executes from this slice in phase 3 — it is
    /// the seam an executor consumes later.
    #[must_use]
    pub fn approved(&self) -> &[&'static str] {
        &self.approved
    }

    // ── Input ────────────────────────────────────────────────────────────────

    /// Handle a key press. Returns `Some(Action)` only for Esc in the list
    /// view (Back); everything else is consumed here.
    pub fn handle_key(&mut self, code: KeyCode) -> Option<Action> {
        if self.consent_modal.is_visible() {
            match self.consent_modal.handle_key(code) {
                ModalEvent::Button(verdict) => self.apply_consent(verdict),
                ModalEvent::Closed => self.close_consent(),
                ModalEvent::Consumed => {}
            }
            return None;
        }
        if self.detail_open {
            match code {
                KeyCode::Enter => self.request_install(),
                KeyCode::Esc | KeyCode::Backspace | KeyCode::Char('h') => {
                    self.detail_open = false;
                }
                _ => {}
            }
            return None;
        }
        let rows = self.visible_rows().len();
        match code {
            KeyCode::Down | KeyCode::Char('j') => {
                self.sel = (self.sel + 1).min(rows.saturating_sub(1));
            }
            KeyCode::Up | KeyCode::Char('k') => self.sel = self.sel.saturating_sub(1),
            KeyCode::PageDown => self.sel = (self.sel + 8).min(rows.saturating_sub(1)),
            KeyCode::PageUp => self.sel = self.sel.saturating_sub(8),
            KeyCode::Enter => {
                if self.row_at(self.sel).is_some() {
                    self.detail_open = true;
                }
            }
            KeyCode::Char('x') => self.dismiss_selected(),
            KeyCode::Esc => return Some(Action::Back),
            _ => {}
        }
        None
    }

    /// Handle a mouse event: the modal first, then scroll wheel only.
    pub fn handle_mouse(&mut self, mouse: MouseEvent) -> Option<Action> {
        if self.consent_modal.is_visible() {
            match self.consent_modal.handle_mouse(&mouse) {
                ModalEvent::Button(verdict) => self.apply_consent(verdict),
                ModalEvent::Closed => self.close_consent(),
                ModalEvent::Consumed => {}
            }
            return None;
        }
        match mouse.kind {
            MouseEventKind::ScrollDown => self.scroll = self.scroll.saturating_add(1),
            MouseEventKind::ScrollUp => self.scroll = self.scroll.saturating_sub(1),
            _ => {}
        }
        None
    }

    // ── Selection / gate internals ───────────────────────────────────────────

    fn visible_rows(&self) -> Vec<(usize, usize)> {
        let Some(offers) = &self.offers else {
            return Vec::new();
        };
        let mut rows = Vec::new();
        for (bi, bundle) in offers.bundles.iter().enumerate() {
            for (ri, rec) in bundle.recommendations.iter().enumerate() {
                if !self.dismissed.contains(&suggest_id(bundle.id, rec)) {
                    rows.push((bi, ri));
                }
            }
        }
        rows
    }

    fn row_parts(
        &self,
        pos: usize,
    ) -> Option<(&crate::setup_bundles::SetupBundle, &Recommendation)> {
        let &(bi, ri) = self.visible_rows().get(pos)?;
        let offers = self.offers.as_ref()?;
        let bundle = &offers.bundles[bi];
        Some((bundle, &bundle.recommendations[ri]))
    }

    fn row_at(&self, pos: usize) -> Option<&Recommendation> {
        self.row_parts(pos).map(|(_, rec)| rec)
    }

    /// Index of the first offered bundle's `default_pick` row; the bundle's
    /// first `Free` row when the pick is absent. Falls back to row 0.
    fn default_selection(&self) -> usize {
        let rows = self.visible_rows();
        let Some(offers) = &self.offers else {
            return 0;
        };
        if let Some(&(first_bundle, _)) = rows.first() {
            let pick = offers.bundles[first_bundle].default_pick;
            let in_first_bundle = |pos: &(usize, usize)| pos.0 == first_bundle;
            if let Some(pos) = rows.iter().position(|p| {
                in_first_bundle(p) && offers.bundles[p.0].recommendations[p.1].id == pick
            }) {
                return pos;
            }
            if let Some(pos) = rows.iter().position(|p| {
                in_first_bundle(p)
                    && offers.bundles[p.0].recommendations[p.1].license.kind == LicenseKind::Free
            }) {
                return pos;
            }
        }
        0
    }

    fn request_install(&mut self) {
        let Some(rec) = self.row_at(self.sel) else {
            return;
        };
        let id = rec.id;
        if require_consent(rec, self.consent_for(id)).is_ok() {
            if !self.approved.contains(&id) {
                self.approved.push(id);
            }
            return;
        }
        self.pending_consent = Some(self.sel);
        self.consent_modal.open();
    }

    fn apply_consent(&mut self, verdict: Consent) {
        let id = self
            .pending_consent
            .take()
            .and_then(|pos| self.row_at(pos))
            .map(|rec| rec.id);
        self.consent_modal.close();
        let Some(id) = id else {
            return;
        };
        self.consent.insert(id, verdict);
        if verdict == Consent::Accepted && !self.approved.contains(&id) {
            self.approved.push(id);
        }
    }

    fn close_consent(&mut self) {
        self.pending_consent = None;
        self.consent_modal.close();
    }

    fn dismiss_selected(&mut self) {
        let Some((bundle, rec)) = self.row_parts(self.sel) else {
            return;
        };
        let key = suggest_id(bundle.id, rec);
        self.dismissed.insert(key);
        let rows = self.visible_rows().len();
        self.sel = self.sel.min(rows.saturating_sub(1));
    }

    // ── Rendering ────────────────────────────────────────────────────────────

    /// Render the full setup content area, consent modal last (it overlays).
    pub fn view(&mut self, frame: &mut Frame, area: Rect, p: Palette) {
        if !self.available {
            self.render_unavailable(frame, area, p);
            return;
        }

        let inner = render_titled_panel(frame, area, p, &self.panel_title(), p.accent, true);
        if inner.height == 0 {
            return;
        }

        let lines = if self.detail_open {
            self.detail_lines(p, inner.width)
        } else {
            self.list_lines(p, inner.width)
        };

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

        if self.consent_modal.is_visible()
            && let Some(rec) = self
                .pending_consent
                .and_then(|pos| self.row_at(pos))
                .cloned()
        {
            self.consent_modal
                .render_with_extracted_buttons(frame, p, |frame, marea, buttons| {
                    render_consent_content(frame, marea, p, &rec, buttons);
                });
        }
    }

    fn panel_title(&self) -> String {
        let bundles = self.offers.as_ref().map_or(0, |o| o.bundles.len());
        format!(
            " SETUP · {} suggestions · {bundles} bundles ",
            self.suggestion_count()
        )
    }

    fn render_unavailable(&self, frame: &mut Frame, area: Rect, p: Palette) {
        let inner = render_titled_panel(frame, area, p, " SETUP ", p.text_dim, false);
        if inner.height < 2 {
            return;
        }
        let msg = Line::from(vec![
            Span::styled("▣ ", Style::new().fg(p.warn)),
            Span::styled(
                "Setup unavailable",
                Style::new().fg(p.text).add_modifier(Modifier::BOLD),
            ),
        ]);
        let detail_text = self
            .unavailable_reason
            .clone()
            .unwrap_or_else(|| "setup collection could not run on this host".to_string());
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

    fn list_lines(&self, p: Palette, width: u16) -> Vec<Line<'static>> {
        let mut lines: Vec<Line<'static>> = Vec::new();
        let Some(offers) = &self.offers else {
            return lines;
        };
        let rows = self.visible_rows();

        if rows.is_empty() {
            let text = self.empty_state_text();
            lines.push(Line::from(Span::styled(text, Style::new().fg(p.ok))));
        } else {
            lines.push(Line::from(vec![
                Span::styled(
                    rows.len().to_string(),
                    Style::new().fg(p.text).add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!(" suggestions across {} bundles", offers.bundles.len()),
                    Style::new().fg(p.text_dim),
                ),
            ]));
        }
        let dismissed = self.dismissed.len();
        if dismissed > 0 {
            lines.push(Line::from(Span::styled(
                format!("{dismissed} dismissed this session"),
                Style::new().fg(p.text_muted),
            )));
        }
        lines.push(Line::raw(""));

        let mut current_bundle: Option<usize> = None;
        for (pos, &(bi, ri)) in rows.iter().enumerate() {
            if current_bundle != Some(bi) {
                if current_bundle.is_some() {
                    lines.push(Line::raw(""));
                }
                current_bundle = Some(bi);
                lines.push(Line::from(Span::styled(
                    offers.bundles[bi].title.to_string(),
                    Style::new().fg(p.accent).add_modifier(Modifier::BOLD),
                )));
            }
            lines.push(self.row_line(pos, bi, ri, p, width));
        }
        lines
    }

    /// Honest empty-state line: why the pane has no rows.
    fn empty_state_text(&self) -> String {
        let Some(offers) = &self.offers else {
            return "collecting setup offers".to_string();
        };
        if self.dismissed.is_empty() {
            if offers.satisfied.is_empty() {
                "nothing to suggest on this host".to_string()
            } else {
                format!(
                    "all {} suggested tools are already installed",
                    offers.satisfied.len()
                )
            }
        } else {
            "every suggestion is dismissed this session".to_string()
        }
    }

    fn row_line(&self, pos: usize, bi: usize, ri: usize, p: Palette, width: u16) -> Line<'static> {
        let offers = self.offers.as_ref();
        let Some(rec) = offers.map(|o| &o.bundles[bi].recommendations[ri]) else {
            return Line::raw("");
        };
        let kind = rec.license.kind;
        let selected = pos == self.sel;
        let (marker, marker_color) = if self.approved.contains(&rec.id) {
            ("✓", p.ok)
        } else {
            ("·", p.text_dim)
        };
        let title = truncate_str(rec.title, TITLE_W);
        let used = 2 + 2 + TITLE_W + 1 + kind_label(kind).len() + 2 + 1;
        let rationale_max = (width as usize).saturating_sub(used);
        Line::from(vec![
            Span::styled(
                if selected { "▸ " } else { "  " },
                Style::new().fg(p.accent),
            ),
            Span::styled(format!("{marker} "), Style::new().fg(marker_color)),
            Span::styled(
                format!("{title:<TITLE_W$}"),
                Style::new().fg(p.text).add_modifier(if selected {
                    Modifier::BOLD
                } else {
                    Modifier::empty()
                }),
            ),
            tag_badge(kind_label(kind), kind_color(kind, p), p),
            Span::styled(
                format!(" {}", truncate_str(rec.rationale, rationale_max)),
                Style::new().fg(p.text_muted),
            ),
        ])
    }

    fn detail_lines(&self, p: Palette, width: u16) -> Vec<Line<'static>> {
        let mut lines: Vec<Line<'static>> = Vec::new();
        let Some(rec) = self.row_at(self.sel) else {
            return lines;
        };
        let kind = rec.license.kind;
        lines.push(Line::from(vec![
            Span::styled(
                format!("{} ", rec.title),
                Style::new().fg(p.text).add_modifier(Modifier::BOLD),
            ),
            tag_badge(kind_label(kind), kind_color(kind, p), p),
        ]));
        lines.push(Line::from(Span::styled(
            rec.rationale.to_string(),
            Style::new().fg(p.text_dim),
        )));
        lines.push(Line::raw(""));
        lines.push(kv_line("license", rec.license.summary, p, width));
        lines.push(kv_line("terms", rec.license.terms_url, p, width));
        lines.push(kv_line("verified", rec.license.verified, p, width));
        if let Some(alt) = rec.alternative {
            let title = self.lookup_title(alt).unwrap_or(alt);
            lines.push(Line::from(Span::styled(
                format!("  free alternative {title}"),
                Style::new().fg(p.ok),
            )));
        }
        lines.push(Line::raw(""));
        lines.push(Line::from(Span::styled(
            "actions",
            Style::new().fg(p.accent).add_modifier(Modifier::BOLD),
        )));
        for (i, action) in rec.actions.iter().enumerate() {
            lines.push(Line::from(Span::styled(
                format!("  {}. {}", i + 1, action_text(action)),
                Style::new().fg(p.text),
            )));
        }
        lines.push(Line::raw(""));
        lines.push(Line::from(Span::styled(
            "enter: install   esc: back",
            Style::new().fg(p.text_muted),
        )));
        lines
    }

    fn lookup_title(&self, id: &str) -> Option<&'static str> {
        let offers = self.offers.as_ref()?;
        offers
            .bundles
            .iter()
            .flat_map(|b| b.recommendations.iter())
            .find(|rec| rec.id == id)
            .map(|rec| rec.title)
    }
}

fn kv_line(label: &str, value: &str, p: Palette, width: u16) -> Line<'static> {
    let prefix = format!("  {label:<9}");
    let value_max = (width as usize).saturating_sub(prefix.len());
    Line::from(vec![
        Span::styled(prefix, Style::new().fg(p.text_dim)),
        Span::styled(truncate_str(value, value_max), Style::new().fg(p.text)),
    ])
}

/// Modal interior: row title + badge, wrapped license summary, terms URL,
/// verified date, and the decline/accept button row.
fn render_consent_content(
    frame: &mut Frame,
    area: Rect,
    p: Palette,
    rec: &Recommendation,
    buttons: Option<&mut ButtonRow<Consent>>,
) {
    let [
        head,
        _blank1,
        summary,
        _blank2,
        terms,
        verified,
        _fill,
        btns,
        _pad,
    ] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(4),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Min(0),
        Constraint::Length(1),
        Constraint::Length(1),
    ])
    .areas(area);

    let kind = rec.license.kind;
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(
                format!("{}  ", rec.title),
                Style::new().fg(p.text).add_modifier(Modifier::BOLD),
            ),
            tag_badge(kind_label(kind), kind_color(kind, p), p),
        ])),
        head,
    );
    frame.render_widget(
        Paragraph::new(rec.license.summary)
            .style(Style::new().fg(p.text))
            .wrap(Wrap { trim: false }),
        summary,
    );
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("terms    ", Style::new().fg(p.text_dim)),
            Span::styled(rec.license.terms_url.to_string(), Style::new().fg(p.info)),
        ])),
        terms,
    );
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("verified ", Style::new().fg(p.text_dim)),
            Span::styled(rec.license.verified.to_string(), Style::new().fg(p.text)),
        ])),
        verified,
    );
    if let Some(row) = buttons {
        let viewport = Viewport::from_area(frame.area());
        row.render(frame.buffer_mut(), btns, p, viewport);
    }
}

impl crate::ui::screens::section_overview::SectionOverview for SetupContent {
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
        Some(format!("{} suggestions", self.suggestion_count()))
    }

    fn findings_count(&self) -> usize {
        self.findings
            .iter()
            .filter(|f| {
                f.severity == "info"
                    && f.id.starts_with("setup.suggest.")
                    && !self.dismissed.contains(&f.id)
            })
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::setup_bundles::ToolPresence;
    use crate::ui::screens::section_overview::SectionOverview;
    use crate::ui::theme::CHARM;
    use ratatui::{Terminal, backend::TestBackend};
    use toride_apps::{Arch, Os, Target};

    struct NoPresence;

    impl ToolPresence for NoPresence {
        fn is_present(&self, _binaries: &[&str]) -> bool {
            false
        }
    }

    fn mac_offers() -> SetupOffers {
        crate::setup_bundles::evaluate(&Target::new(Os::MacOs, Arch::Aarch64), &NoPresence)
    }

    fn populated() -> SetupContent {
        let mut c = SetupContent::new();
        c.set_available(true);
        c.set_offers(mac_offers());
        c
    }

    fn select(c: &mut SetupContent, id: &str) {
        for pos in 0..c.visible_rows().len() {
            if c.row_at(pos).map(|rec| rec.id) == Some(id) {
                c.sel = pos;
                return;
            }
        }
        panic!("row {id} not offered");
    }

    fn render_to_string(content: &mut SetupContent, w: u16, h: u16) -> String {
        let mut terminal = Terminal::new(TestBackend::new(w, h)).unwrap();
        terminal.draw(|f| content.view(f, f.area(), CHARM)).unwrap();
        terminal.backend().to_string()
    }

    #[test]
    fn new_is_unavailable_and_empty() {
        let c = SetupContent::new();
        assert!(!c.available);
        assert!(c.offers.is_none());
        assert!(c.findings.is_empty());
        assert_eq!(c.approved, [] as [&str; 0]);
        assert!(!c.has_modal());
    }

    #[test]
    fn default_matches_new() {
        let from_new = SetupContent::new();
        let from_default = SetupContent::default();
        assert_eq!(from_new.available, from_default.available);
        assert_eq!(from_new.sel, from_default.sel);
    }

    #[test]
    fn default_selection_is_first_bundle_default_pick() {
        let c = populated();
        let id = c.row_at(c.sel).expect("selection resolves").id;
        let first_bundle = &c.offers.as_ref().unwrap().bundles[0];
        assert_eq!(id, first_bundle.default_pick, "default pick is selected");
        assert_eq!(id, "rust-sccache");
    }

    #[test]
    fn default_selection_falls_back_to_first_free_row() {
        let mut offers = mac_offers();
        let rust = offers
            .bundles
            .iter_mut()
            .find(|b| b.id == "rust")
            .expect("rust bundle offered");
        rust.recommendations
            .retain(|rec| rec.id != rust.default_pick);
        let mut c = SetupContent::new();
        c.set_available(true);
        c.set_offers(offers);
        let id = c.row_at(c.sel).expect("selection resolves").id;
        assert_eq!(id, "rust-lld", "first offered Free row of the bundle wins");
    }

    #[test]
    fn enter_from_list_opens_detail() {
        let mut c = populated();
        assert!(c.handle_key(KeyCode::Enter).is_none());
        assert!(c.detail_open);
        assert!(!c.has_modal(), "detail view is not a modal");
    }

    #[test]
    fn detail_view_shows_license_badge_terms_and_verified_date() {
        let mut c = populated();
        select(&mut c, "containers-orbstack");
        c.detail_open = true;
        let out = render_to_string(&mut c, 120, 40);
        assert!(out.contains("OrbStack"), "row title: {out}");
        assert!(out.contains("paid for commercial use"), "badge: {out}");
        assert!(out.contains("https://orbstack.dev/pricing"), "terms: {out}");
        assert!(out.contains("2026-10-12"), "verified date: {out}");
    }

    #[test]
    fn free_row_install_is_approved_without_modal() {
        let mut c = populated();
        select(&mut c, "containers-colima");
        c.detail_open = true;
        assert!(c.handle_key(KeyCode::Enter).is_none());
        assert!(!c.has_modal(), "Free rows never open the terms modal");
        assert_eq!(c.approved(), &["containers-colima"]);
    }

    #[test]
    fn non_free_row_install_is_blocked_until_consent() {
        let mut c = populated();
        select(&mut c, "containers-orbstack");
        c.detail_open = true;
        assert!(c.handle_key(KeyCode::Enter).is_none());
        assert!(c.has_modal(), "terms modal must gate the install");
        assert!(
            c.approved().is_empty(),
            "no install approval before the modal answers"
        );
        assert_eq!(c.consent_for("containers-orbstack"), Consent::Pending);
    }

    #[test]
    fn consent_default_focus_is_decline() {
        let mut c = populated();
        select(&mut c, "containers-orbstack");
        c.detail_open = true;
        c.handle_key(KeyCode::Enter);
        // Bare Enter hits the default-focused button: decline.
        assert!(c.handle_key(KeyCode::Enter).is_none());
        assert!(!c.has_modal());
        assert_eq!(c.consent_for("containers-orbstack"), Consent::Refused);
        assert!(c.approved().is_empty(), "refused terms never approve");
    }

    #[test]
    fn consent_accept_approves_install_in_session() {
        let mut c = populated();
        select(&mut c, "containers-orbstack");
        c.detail_open = true;
        c.handle_key(KeyCode::Enter);
        c.handle_key(KeyCode::Tab);
        c.handle_key(KeyCode::Enter);
        assert!(!c.has_modal());
        assert_eq!(c.consent_for("containers-orbstack"), Consent::Accepted);
        assert_eq!(c.approved(), &["containers-orbstack"]);
        // The verdict sticks: a second install intent skips the modal.
        c.handle_key(KeyCode::Enter);
        assert!(!c.has_modal());
        assert_eq!(c.approved().len(), 1, "approval recorded once");
    }

    #[test]
    fn consent_esc_records_no_verdict() {
        let mut c = populated();
        select(&mut c, "containers-orbstack");
        c.detail_open = true;
        c.handle_key(KeyCode::Enter);
        assert!(c.handle_key(KeyCode::Esc).is_none());
        assert!(!c.has_modal());
        assert_eq!(c.consent_for("containers-orbstack"), Consent::Pending);
        assert_eq!(c.approved(), [] as [&str; 0]);
        // The gate still holds on retry.
        c.handle_key(KeyCode::Enter);
        assert!(c.has_modal());
    }

    #[test]
    fn dismiss_hides_row_and_survives_offer_refresh() {
        let mut c = populated();
        let before = c.suggestion_count();
        select(&mut c, "containers-orbstack");
        assert!(c.handle_key(KeyCode::Char('x')).is_none());
        assert_eq!(c.suggestion_count(), before - 1);
        c.set_offers(mac_offers());
        assert_eq!(
            c.suggestion_count(),
            before - 1,
            "dismissal survives a collector refresh"
        );
        for pos in 0..c.visible_rows().len() {
            assert_ne!(c.row_at(pos).expect("row").id, "containers-orbstack");
        }
    }

    #[test]
    fn dismiss_stores_the_namespaced_finding_id() {
        let mut c = populated();
        select(&mut c, "containers-orbstack");
        assert!(c.handle_key(KeyCode::Char('x')).is_none());
        let dismissed = &c.dismissed;
        assert!(
            dismissed.contains("setup.suggest.containers.containers-orbstack"),
            "canonical key is setup.suggest.<bundle>.<rec>: {dismissed:?}"
        );
        assert!(
            !dismissed.contains("containers-orbstack"),
            "a bare rec id must never enter the dismissed set"
        );
    }

    #[test]
    fn dismissed_row_suppresses_its_matching_finding() {
        let mut c = populated();
        select(&mut c, "containers-orbstack");
        c.handle_key(KeyCode::Char('x'));
        c.set_findings(sample_findings());
        assert_eq!(
            c.findings_count(),
            1,
            "the dismissed row's own finding must not count"
        );
    }

    #[test]
    fn esc_from_list_returns_back() {
        let mut c = populated();
        assert_eq!(c.handle_key(KeyCode::Esc), Some(Action::Back));
    }

    #[test]
    fn render_unavailable_when_not_available() {
        let mut c = SetupContent::new();
        let out = render_to_string(&mut c, 100, 24);
        assert!(out.contains("Setup unavailable"), "degraded panel: {out}");
    }

    #[test]
    fn list_view_renders_bundles_badges_and_counts() {
        let mut c = populated();
        let out = render_to_string(&mut c, 120, 40);
        assert!(out.contains("suggestions across"), "summary line: {out}");
        assert!(out.contains("Rust build tools"), "bundle heading: {out}");
        assert!(out.contains("sccache"), "row title: {out}");
        assert!(out.contains("paid for commercial use"), "badge: {out}");
    }

    #[test]
    fn dismissed_rows_leave_the_rendered_list() {
        let mut c = populated();
        select(&mut c, "containers-orbstack");
        c.handle_key(KeyCode::Char('x'));
        let out = render_to_string(&mut c, 120, 100);
        assert!(out.contains("dismissed this session"), "marker: {out}");
        assert!(!out.contains("OrbStack"), "row must vanish: {out}");
    }

    #[test]
    fn consent_modal_shows_price_terms_and_buttons() {
        let mut c = populated();
        select(&mut c, "containers-orbstack");
        c.detail_open = true;
        c.handle_key(KeyCode::Enter);
        let out = render_to_string(&mut c, 120, 40);
        assert!(out.contains("License terms"), "modal title: {out}");
        assert!(out.contains("$8/user/mo"), "price fact: {out}");
        assert!(
            out.contains("https://orbstack.dev/pricing"),
            "terms URL: {out}"
        );
        assert!(out.contains("decline"), "decline button: {out}");
        assert!(out.contains("accept"), "accept button: {out}");
    }

    #[test]
    fn section_overview_offline_when_unavailable() {
        let c = SetupContent::new();
        assert_eq!(c.status_label(), "offline");
        assert_eq!(c.detail(), None);
    }

    #[test]
    fn section_overview_degrades_only_on_elevated_severity() {
        let mut c = populated();
        c.set_findings(sample_findings());
        assert_eq!(
            c.status_label(),
            "degraded",
            "the shared helper degrades on any warning"
        );
        assert_eq!(
            c.detail().as_deref(),
            Some(format!("{} suggestions", c.suggestion_count())).as_deref()
        );
        assert_eq!(c.findings_count(), 2, "only setup.suggest. info counts");
    }

    #[test]
    fn section_overview_active_with_only_info_findings() {
        let mut c = populated();
        c.set_findings(
            sample_findings()
                .into_iter()
                .filter(|f| f.severity == "info")
                .collect(),
        );
        assert_eq!(c.status_label(), "active", "info never degrades");
        assert_eq!(c.findings_count(), 2);
    }

    #[test]
    fn findings_count_excludes_dismissed_and_foreign_ids() {
        let mut c = populated();
        c.set_findings(sample_findings());
        c.dismissed
            .insert("setup.suggest.containers.containers-orbstack".to_string());
        assert_eq!(c.findings_count(), 1);
    }

    fn sample_findings() -> Vec<FindingEntry> {
        vec![
            FindingEntry {
                id: "setup.suggest.containers.containers-orbstack".into(),
                severity: "info".into(),
                title: "OrbStack: Docker engine and Linux VMs for macOS".into(),
            },
            FindingEntry {
                id: "setup.suggest.rust.rust-sccache".into(),
                severity: "info".into(),
                title: "sccache: caches Rust compilations across projects.".into(),
            },
            FindingEntry {
                id: "tools.missing.vim".into(),
                severity: "warning".into(),
                title: "missing expected tool: vim".into(),
            },
        ]
    }

    #[test]
    fn tiny_terminal_does_not_panic() {
        let mut c = populated();
        select(&mut c, "containers-orbstack");
        c.detail_open = true;
        c.handle_key(KeyCode::Enter);
        let _ = render_to_string(&mut c, 20, 5);
    }

    #[test]
    fn scroll_never_panics_after_refresh() {
        let mut c = populated();
        c.scroll = 1_000_000;
        let _ = render_to_string(&mut c, 100, 30);
    }

    #[test]
    fn mouse_scroll_wheel_adjusts_scroll() {
        let mut c = SetupContent::new();
        let down = MouseEvent {
            kind: MouseEventKind::ScrollDown,
            column: 0,
            row: 0,
            modifiers: crossterm::event::KeyModifiers::empty(),
        };
        c.handle_mouse(down);
        assert_eq!(c.scroll, 1);
    }

    // ── Full-screen insta snapshots ─────────────────────────────────────────
    //
    // One per phase-3 view state (list, detail, consent modal, dismissed),
    // mirroring the tools/harden snapshot pattern. Reviewed by hand, not
    // blind-approved.

    #[test]
    fn setup_content_snapshot_list_120x40() {
        let mut c = populated();
        let out = render_to_string(&mut c, 120, 40);
        insta::assert_snapshot!("setup_content_list_120x40", out);
    }

    #[test]
    fn setup_content_snapshot_detail_120x40() {
        let mut c = populated();
        select(&mut c, "containers-orbstack");
        c.detail_open = true;
        let out = render_to_string(&mut c, 120, 40);
        insta::assert_snapshot!("setup_content_detail_120x40", out);
    }

    #[test]
    fn setup_content_snapshot_consent_modal_120x40() {
        let mut c = populated();
        select(&mut c, "containers-orbstack");
        c.detail_open = true;
        c.handle_key(KeyCode::Enter);
        let out = render_to_string(&mut c, 120, 40);
        insta::assert_snapshot!("setup_content_consent_modal_120x40", out);
    }

    #[test]
    fn setup_content_snapshot_dismissed_120x40() {
        let mut c = populated();
        select(&mut c, "containers-orbstack");
        c.handle_key(KeyCode::Char('x'));
        let out = render_to_string(&mut c, 120, 40);
        insta::assert_snapshot!("setup_content_dismissed_120x40", out);
    }

    #[test]
    fn setup_content_snapshot_unavailable_100x24() {
        let mut c = SetupContent::new();
        c.set_unavailable_reason(Some("setup data collection panicked: boom".into()));
        let out = render_to_string(&mut c, 100, 24);
        insta::assert_snapshot!("setup_content_unavailable_100x24", out);
    }

    #[test]
    fn empty_states_render_honest_lines() {
        let mut c = SetupContent::new();
        c.set_available(true);
        c.set_offers(SetupOffers {
            bundles: Vec::new(),
            satisfied: vec!["rust-sccache", "python-uv"],
        });
        let out = render_to_string(&mut c, 80, 20);
        assert!(
            out.contains("all 2 suggested tools are already installed"),
            "presence-suppressed empty state: {out}"
        );

        let mut all_dismissed = populated();
        while all_dismissed.suggestion_count() > 0 {
            all_dismissed.handle_key(KeyCode::Char('x'));
        }
        let out = render_to_string(&mut all_dismissed, 80, 20);
        assert!(
            out.contains("every suggestion is dismissed this session"),
            "all-dismissed empty state: {out}"
        );
    }

    #[test]
    fn unavailable_reason_surfaces_when_collection_panics() {
        let mut c = SetupContent::new();
        c.set_unavailable_reason(Some("spawn_blocking panicked".into()));
        let out = render_to_string(&mut c, 60, 8);
        assert!(
            out.contains("spawn_blocking"),
            "reason should surface: {out}"
        );
        c.set_available(true);
        c.set_unavailable_reason(Some("stale".into()));
        assert!(
            c.unavailable_reason.is_none(),
            "reason clears when available"
        );
    }
}
