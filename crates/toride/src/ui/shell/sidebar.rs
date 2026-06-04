//! Left sidebar: a numbered, collapsible module navigation list with an SSH
//! connection footer.
//!
//! [`Sidebar`] owns only interaction state (selection index + collapsed flag);
//! the item list is passed at [`render`](Sidebar::render) time so the screen
//! remains the single owner of the data.

use std::time::Instant;

use ratatui::{
    Frame,
    layout::Rect,
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
};

use crate::data::SidebarItem;
use crate::ui::helpers::color::{lerp_color, to_rgb};
use crate::ui::responsive::truncate_str;
use crate::ui::theme::Palette;

/// Expanded sidebar width.
pub const SIDEBAR_W: u16 = 30;
/// Collapsed (icon-rail) sidebar width.
pub const SIDEBAR_W_COLLAPSED: u16 = 6;
/// Rows consumed per expanded item (one content row + one padding row).
const ROW_STEP: u16 = 2;
/// Seconds for a highlight to fully fade in / out.
const ANIM_SECS: f32 = 0.15;
/// Highlight strength applied to a hovered (but unselected) item.
const HOVER_STRENGTH: f32 = 0.5;
/// Below this strength the pill / border are skipped (effectively invisible).
const VISIBLE_EPS: f32 = 0.01;

/// Sidebar interaction state.
pub struct Sidebar {
    selected: usize,
    collapsed: bool,
    len: usize,
    /// Index of the item currently under the mouse, if any.
    hovered: Option<usize>,
    /// Per-item highlight strength (0 = none, 1 = fully selected), animated.
    anim: Vec<f32>,
    /// Clickable rect for each item, refreshed every render (index = item).
    hitboxes: Vec<Rect>,
    /// Timestamp of the last animation tick.
    last_tick: Instant,
}

impl Sidebar {
    /// Create a sidebar for `len` items with the first item selected.
    #[must_use]
    pub fn new(len: usize) -> Self {
        let n = len.max(1);
        let mut anim = vec![0.0_f32; n];
        anim[0] = 1.0;
        Self {
            selected: 0,
            collapsed: false,
            len: n,
            hovered: None,
            anim,
            hitboxes: Vec::new(),
            last_tick: Instant::now(),
        }
    }

    /// Set (or clear) the hovered item.
    pub fn set_hovered(&mut self, hovered: Option<usize>) {
        self.hovered = hovered;
    }

    /// Hit-test a screen coordinate against the last-rendered item rects.
    #[must_use]
    pub fn item_at(&self, col: u16, row: u16) -> Option<usize> {
        self.hitboxes
            .iter()
            .position(|r| col >= r.x && col < r.right() && row >= r.y && row < r.bottom())
    }

    /// Advance the per-item highlight animation toward each item's target.
    fn tick_anim(&mut self) {
        let now = Instant::now();
        let dt = now.duration_since(self.last_tick).as_secs_f32();
        self.last_tick = now;
        let step = (dt / ANIM_SECS).min(1.0);
        for i in 0..self.anim.len() {
            let target = if i == self.selected {
                1.0
            } else if self.hovered == Some(i) {
                HOVER_STRENGTH
            } else {
                0.0
            };
            let cur = self.anim[i];
            let diff = target - cur;
            if diff.abs() <= step {
                self.anim[i] = target;
            } else {
                self.anim[i] = cur + step * diff.signum();
            }
        }
    }

    /// Currently selected item index.
    #[must_use]
    pub fn selected(&self) -> usize {
        self.selected
    }

    /// Whether the sidebar is collapsed to an icon rail.
    #[must_use]
    pub fn is_collapsed(&self) -> bool {
        self.collapsed
    }

    /// Current rendered width.
    #[must_use]
    pub fn width(&self) -> u16 {
        if self.collapsed {
            SIDEBAR_W_COLLAPSED
        } else {
            SIDEBAR_W
        }
    }

    /// Move the selection down one item, wrapping at the end.
    pub fn select_next(&mut self) {
        self.selected = (self.selected + 1) % self.len;
    }

    /// Move the selection up one item, wrapping at the start.
    pub fn select_prev(&mut self) {
        self.selected = (self.selected + self.len - 1) % self.len;
    }

    /// Select a specific item index (clamped to range).
    pub fn select_to(&mut self, idx: usize) {
        self.selected = idx.min(self.len - 1);
    }

    /// Toggle the collapsed icon-rail state.
    pub fn toggle_collapse(&mut self) {
        self.collapsed = !self.collapsed;
    }

    /// Force the collapsed state (used for responsive auto-collapse).
    pub fn set_collapsed(&mut self, collapsed: bool) {
        self.collapsed = collapsed;
    }

    /// Render the sidebar.
    ///
    /// `active` is the index of the currently active section (highlighted even
    /// when not selected); `focused` controls whether the selection uses the
    /// strong selection background. `collapsed` is the *effective* collapsed
    /// state for this frame (manual toggle OR responsive auto-collapse), passed
    /// in so the screen can override the manual flag on narrow terminals.
    #[expect(clippy::too_many_arguments, reason = "shell render needs full context")]
    pub fn render(
        &mut self,
        frame: &mut Frame,
        area: Rect,
        p: Palette,
        items: &[SidebarItem],
        _active: usize,
        focused: bool,
        collapsed: bool,
        ssh_target: &str,
    ) {
        let block = Block::default()
            .borders(Borders::RIGHT)
            .border_style(Style::new().fg(p.border))
            .style(Style::new().bg(p.bg_alt));
        let inner = block.inner(area);
        frame.render_widget(block, area);

        if inner.width == 0 || inner.height == 0 {
            return;
        }

        // Header label "MODULES" (only when expanded and there's room).
        let mut list_top = inner.y;
        if !collapsed {
            let header = Line::from(Span::styled(
                " MODULES",
                Style::new().fg(p.text_muted).bold(),
            ));
            frame.render_widget(
                Paragraph::new(header),
                Rect::new(inner.x, inner.y, inner.width, 1),
            );
            list_top = inner.y + 2;
        }

        // Reserve two rows at the bottom for the SSH footer.
        let footer_h: u16 = if collapsed { 1 } else { 2 };
        let list_bottom = inner.bottom().saturating_sub(footer_h + 1);
        let foot_y = inner.bottom().saturating_sub(footer_h);

        // Each item gets a blank row beneath it for vertical breathing room.
        let step: u16 = if collapsed { 1 } else { ROW_STEP };

        // Advance the highlight animation and refresh hit-test rects.
        self.tick_anim();
        self.hitboxes.clear();

        // Highlight target colours (depend on focus state).
        let h_bg = if focused { p.sel_bg } else { p.bg_inset };
        let h_text = if focused { p.accent } else { p.text };
        let h_border = if focused { p.accent } else { p.text_muted };

        for (i, item) in items.iter().enumerate() {
            let Ok(idx) = u16::try_from(i) else { break };
            let y = list_top + idx * step;
            if y > list_bottom {
                break;
            }
            let row = Rect::new(inner.x, y, inner.width, 1);
            self.hitboxes.push(row);

            // Interpolated colours for this item's current highlight strength.
            let s = self.anim.get(i).copied().unwrap_or(0.0);
            let row_bg = lerp_color(p.bg_alt, h_bg, s);
            let border = lerp_color(p.bg_alt, h_border, s);

            // Padded pill caps fade in along with the background.
            if s > VISIBLE_EPS && !collapsed {
                Self::render_pill_caps(frame, inner, p, row_bg, border, y, foot_y);
            }
            frame.render_widget(
                Paragraph::new(Self::item_line(i, item, p, s, h_text, collapsed))
                    .style(Style::new().bg(row_bg)),
                row,
            );
            // Left border = first cell recoloured toward the accent.
            if s > VISIBLE_EPS {
                frame.render_widget(
                    Paragraph::new(Span::styled(" ", Style::new().bg(border))),
                    Rect::new(inner.x, y, 1, 1),
                );
            }
        }

        // ── SSH footer ──────────────────────────────────────────────────────
        let dot = Span::styled(" ● ", Style::new().fg(p.ok));
        if collapsed {
            frame.render_widget(
                Paragraph::new(Line::from(dot)),
                Rect::new(inner.x, foot_y, inner.width, 1),
            );
        } else {
            let status = Line::from(vec![
                dot,
                Span::styled("SSH connected", Style::new().fg(p.text_dim)),
            ]);
            let target = Line::from(Span::styled(
                format!("   {}", truncate_str(ssh_target, inner.width.saturating_sub(3) as usize)),
                Style::new().fg(p.text_muted),
            ));
            frame.render_widget(
                Paragraph::new(status),
                Rect::new(inner.x, foot_y, inner.width, 1),
            );
            frame.render_widget(
                Paragraph::new(target),
                Rect::new(inner.x, foot_y + 1, inner.width, 1),
            );
        }
    }

    /// Render the quarter-cell "caps" above and below a selected item so the
    /// highlight reads as a padded pill rather than a thin one-row band.
    ///
    /// The cap above fills the bottom quarter of its cell; the cap below fills
    /// the top quarter — both in the selection background `bg`. The first cell
    /// of each cap is recoloured to `bar` so the left border keeps the same
    /// rounded silhouette as the highlight.
    fn render_pill_caps(
        frame: &mut Frame,
        inner: Rect,
        p: Palette,
        bg: ratatui::style::Color,
        bar: ratatui::style::Color,
        y: u16,
        foot_y: u16,
    ) {
        let w = usize::from(inner.width);

        if y > inner.y {
            let top = Rect::new(inner.x, y - 1, inner.width, 1);
            frame.render_widget(
                Paragraph::new(Line::from(Span::styled(
                    "▂".repeat(w),
                    Style::new().fg(bg).bg(p.bg_alt),
                ))),
                top,
            );
            frame.render_widget(
                Paragraph::new(Span::styled("▂", Style::new().fg(bar).bg(p.bg_alt))),
                Rect::new(inner.x, y - 1, 1, 1),
            );
        }

        if y + 1 < foot_y {
            let bottom = Rect::new(inner.x, y + 1, inner.width, 1);
            frame.render_widget(
                Paragraph::new(Line::from(Span::styled(
                    "▆".repeat(w),
                    Style::new().fg(p.bg_alt).bg(bg),
                ))),
                bottom,
            );
            frame.render_widget(
                Paragraph::new(Span::styled("▆", Style::new().fg(p.bg_alt).bg(bar))),
                Rect::new(inner.x, y + 1, 1, 1),
            );
        }
    }

    /// Build the styled line for a single sidebar item.
    ///
    /// Icon and label colours are interpolated from their base toward `accent`
    /// by the highlight `strength`, giving an animated fade. Column 0 is left
    /// blank — the selection border is painted separately by recolouring that
    /// cell (see `render` / `render_pill_caps`).
    fn item_line(
        i: usize,
        item: &SidebarItem,
        p: Palette,
        strength: f32,
        accent: Color,
        collapsed: bool,
    ) -> Line<'static> {
        let num_style = Style::new().fg(p.text_muted);
        let icon_color = lerp_color(p.text_dim, accent, strength);
        let label_color = lerp_color(p.text, accent, strength);
        let bar = Span::raw(" ");

        if collapsed {
            return Line::from(vec![
                bar,
                Span::styled(format!("{:>2} ", i + 1), num_style),
                Span::styled(item.icon, Style::new().fg(icon_color)),
            ]);
        }

        let mut spans = vec![
            bar,
            Span::styled(format!(" {:>2} ", i + 1), num_style),
            Span::styled(format!("{} ", item.icon), Style::new().fg(icon_color)),
            Span::styled(item.section.label().to_string(), Style::new().fg(label_color)),
        ];
        if let Some(badge) = &item.badge {
            spans.push(Span::styled(
                format!("  {badge}"),
                Style::new().fg(p.text_muted),
            ));
        }
        Line::from(spans)
    }
}

/// Linearly interpolate between two colours (`t` clamped to `0..=1`).
/// Non-RGB inputs are treated as black.
#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "blended channel is 0..=255 and fits in u8"
)]
fn lerp_color(a: Color, b: Color, t: f32) -> Color {
    let t = t.clamp(0.0, 1.0);
    let (ar, ag, ab) = to_rgb(a);
    let (br, bg, bb) = to_rgb(b);
    let mix = |x: u8, y: u8| (f32::from(x) + (f32::from(y) - f32::from(x)) * t).round() as u8;
    Color::Rgb(mix(ar, br), mix(ag, bg), mix(ab, bb))
}

/// Extract RGB channels, defaulting non-RGB colours to black.
fn to_rgb(c: Color) -> (u8, u8, u8) {
    match c {
        Color::Rgb(r, g, b) => (r, g, b),
        _ => (0, 0, 0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn select_next_wraps() {
        let mut s = Sidebar::new(3);
        assert_eq!(s.selected(), 0);
        s.select_next();
        assert_eq!(s.selected(), 1);
        s.select_next();
        s.select_next();
        assert_eq!(s.selected(), 0, "should wrap to start");
    }

    #[test]
    fn select_prev_wraps() {
        let mut s = Sidebar::new(3);
        s.select_prev();
        assert_eq!(s.selected(), 2, "should wrap to end");
    }

    #[test]
    fn toggle_collapse_flips_and_changes_width() {
        let mut s = Sidebar::new(3);
        assert!(!s.is_collapsed());
        assert_eq!(s.width(), SIDEBAR_W);
        s.toggle_collapse();
        assert!(s.is_collapsed());
        assert_eq!(s.width(), SIDEBAR_W_COLLAPSED);
    }

    #[test]
    fn empty_len_does_not_divide_by_zero() {
        let mut s = Sidebar::new(0);
        s.select_next();
        assert_eq!(s.selected(), 0);
    }
}
