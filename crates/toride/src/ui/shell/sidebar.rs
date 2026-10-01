//! Sidebar module navigation list. [`Sidebar`] owns only interaction state;
//! the item list is passed at [`render`](Sidebar::render) time.

use ratatui::{
    Frame,
    layout::Rect,
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
};

use crate::data::SidebarItem;
use crate::ui::helpers::anim::AnimatedFloats;
use crate::ui::helpers::color::lerp_color;
use crate::ui::theme::Palette;

/// Sidebar width in columns when expanded.
pub const SIDEBAR_W: u16 = 30;
/// Sidebar width in columns when collapsed to icons.
pub const SIDEBAR_W_COLLAPSED: u16 = 6;
const ROW_STEP: u16 = 2;
const ANIM_SECS: f32 = 0.15;
const HOVER_STRENGTH: f32 = 0.5;
const VISIBLE_EPS: f32 = 0.01;

/// Sidebar navigation list; owns interaction state only, the item list is
/// supplied at render time.
pub struct Sidebar {
    selected: usize,
    collapsed: bool,
    len: usize,
    hovered: Option<usize>,
    anim: AnimatedFloats,
    hitboxes: Vec<Rect>,
    scroll_offset: usize,
    last_visible: usize,
}

impl Sidebar {
    /// Create a sidebar for `len` items with the first item selected.
    #[must_use]
    pub fn new(len: usize) -> Self {
        let n = len.max(1);
        let mut anim = AnimatedFloats::new(n, 0.0);
        anim.set(0, 1.0);
        Self {
            selected: 0,
            collapsed: false,
            len: n,
            hovered: None,
            anim,
            hitboxes: Vec::new(),
            scroll_offset: 0,
            last_visible: 0,
        }
    }

    /// Set (or clear) the hovered item; returns whether it actually changed.
    pub fn set_hovered(&mut self, hovered: Option<usize>) -> bool {
        if self.hovered == hovered {
            return false;
        }
        self.hovered = hovered;
        true
    }

    /// Hit-test a screen coordinate against the last-rendered item rects.
    #[must_use]
    pub fn item_at(&self, col: u16, row: u16) -> Option<usize> {
        self.hitboxes
            .iter()
            .position(|r| col >= r.x && col < r.right() && row >= r.y && row < r.bottom())
            .map(|visible_idx| self.scroll_offset + visible_idx)
    }

    fn highlight_targets(&self) -> Vec<f32> {
        (0..self.anim.len())
            .map(|i| {
                if i == self.selected {
                    1.0
                } else if self.hovered == Some(i) {
                    HOVER_STRENGTH
                } else {
                    0.0
                }
            })
            .collect()
    }

    fn tick_anim(&mut self) {
        let targets = self.highlight_targets();
        self.anim.tick(&targets, ANIM_SECS);
    }

    fn snap_anim(&mut self) {
        let targets = self.highlight_targets();
        self.anim.snap_to_targets(&targets);
    }

    /// Whether the highlight animation is still settling.
    #[must_use]
    pub fn is_animating(&self) -> bool {
        let targets = self.highlight_targets();
        !self.anim.is_settled(&targets, VISIBLE_EPS)
    }

    /// The selected item index.
    #[must_use]
    pub fn selected(&self) -> usize {
        self.selected
    }

    /// Whether the sidebar is collapsed to icons.
    #[must_use]
    pub fn is_collapsed(&self) -> bool {
        self.collapsed
    }

    /// Current sidebar width in columns.
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
        self.clamp_scroll_to_selection(self.last_visible);
    }

    /// Move the selection up one item, wrapping at the start.
    pub fn select_prev(&mut self) {
        self.selected = (self.selected + self.len - 1) % self.len;
        self.clamp_scroll_to_selection(self.last_visible);
    }

    /// Select a specific item index (clamped to range).
    pub fn select_to(&mut self, idx: usize) {
        self.selected = idx.min(self.len - 1);
        self.clamp_scroll_to_selection(self.last_visible);
    }

    /// Scroll the viewport by `delta` items (positive = down); does not move
    /// the selection.
    pub fn scroll(&mut self, delta: i32) {
        let visible = self.last_visible;
        if visible == 0 || self.len <= visible {
            return;
        }
        let max_offset = self.len - visible;
        let new = if delta >= 0 {
            let up = u32::try_from(delta).unwrap_or(u32::MAX);
            self.scroll_offset.saturating_add(up as usize)
        } else {
            let down = delta.unsigned_abs();
            self.scroll_offset.saturating_sub(down as usize)
        };
        self.scroll_offset = new.min(max_offset);
    }

    /// Current viewport scroll offset (index of the topmost visible item).
    #[must_use]
    pub fn scroll_offset(&self) -> usize {
        self.scroll_offset
    }

    fn clamp_scroll_to_selection(&mut self, visible: usize) {
        if visible == 0 {
            return;
        }
        self.clamp_scroll_bounds(visible);
        if self.selected < self.scroll_offset {
            self.scroll_offset = self.selected;
        } else if self.selected >= self.scroll_offset + visible {
            self.scroll_offset = self.selected - visible + 1;
        }
    }

    fn clamp_scroll_bounds(&mut self, visible: usize) {
        if visible == 0 || self.len <= visible {
            self.scroll_offset = 0;
            return;
        }
        let max_offset = self.len - visible;
        self.scroll_offset = self.scroll_offset.min(max_offset);
    }

    /// Toggle the collapsed state.
    pub fn toggle_collapse(&mut self) {
        self.collapsed = !self.collapsed;
    }

    /// Force the collapsed state to `collapsed`.
    pub fn set_collapsed(&mut self, collapsed: bool) {
        self.collapsed = collapsed;
    }

    /// Render the sidebar; `collapsed` is the effective state for this frame,
    /// overriding the manual toggle.
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

        let footer_h: u16 = 0;
        let list_bottom = inner.bottom().saturating_sub(footer_h + 1);
        let foot_y = inner.bottom().saturating_sub(footer_h);

        let step: u16 = if collapsed { 1 } else { ROW_STEP };

        let list_rows = list_bottom.saturating_sub(list_top) as usize;
        let visible = if step > 0 {
            list_rows / step as usize
        } else {
            0
        };
        self.last_visible = visible;
        self.clamp_scroll_bounds(visible);

        if p.reduced_motion {
            self.snap_anim();
        } else {
            self.tick_anim();
        }
        self.hitboxes.clear();

        let h_bg = if focused { p.sel_bg } else { p.bg_inset };
        let h_text = if focused { p.accent } else { p.text };
        let h_border = if focused { p.accent } else { p.text_muted };

        for (i, item) in items.iter().enumerate() {
            if i < self.scroll_offset {
                continue;
            }
            let Ok(idx) = u16::try_from(i - self.scroll_offset) else {
                break;
            };
            let y = list_top + idx * step;
            if y > list_bottom {
                break;
            }
            let row = Rect::new(inner.x, y, inner.width, 1);
            self.hitboxes.push(row);

            let s = self.anim.get(i);
            let row_bg = lerp_color(p.bg_alt, h_bg, s);
            let border = lerp_color(p.bg_alt, h_border, s);

            if s > VISIBLE_EPS && !collapsed {
                Self::render_pill_caps(frame, inner, p, row_bg, border, y, foot_y);
            }
            frame.render_widget(
                Paragraph::new(Self::item_line(i, item, p, s, h_text, collapsed))
                    .style(Style::new().bg(row_bg)),
                row,
            );
            if s > VISIBLE_EPS {
                frame.render_widget(
                    Paragraph::new(Span::styled(" ", Style::new().bg(border))),
                    Rect::new(inner.x, y, 1, 1),
                );
            }
        }
    }

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
            Span::styled(
                item.section.label().to_string(),
                Style::new().fg(label_color),
            ),
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
    fn set_hovered_reports_whether_it_changed() {
        let mut s = Sidebar::new(3);
        assert!(s.set_hovered(Some(1)), "first hover is a change");
        assert!(!s.set_hovered(Some(1)), "same item again is not");
        assert!(s.set_hovered(Some(2)), "different item is");
        assert!(s.set_hovered(None), "clearing is");
        assert!(!s.set_hovered(None), "clearing again is not");
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

    #[test]
    fn item_at_returns_scrolled_item_index() {
        let mut s = Sidebar::new(20);
        s.last_visible = 3;
        s.scroll(5);
        s.hitboxes = vec![
            Rect::new(0, 2, 10, 1),
            Rect::new(0, 3, 10, 1),
            Rect::new(0, 4, 10, 1),
        ];

        assert_eq!(s.scroll_offset(), 5);
        assert_eq!(s.item_at(1, 2), Some(5));
        assert_eq!(s.item_at(1, 3), Some(6));
        assert_eq!(s.item_at(1, 4), Some(7));
    }

    #[test]
    fn render_bounds_clamp_does_not_anchor_to_selection() {
        let mut s = Sidebar::new(20);
        s.last_visible = 3;
        s.select_to(1);
        s.scroll(8);

        s.clamp_scroll_bounds(3);

        assert_eq!(s.selected(), 1);
        assert_eq!(s.scroll_offset(), 8);
    }

    #[test]
    fn selection_change_keeps_selected_item_visible() {
        let mut s = Sidebar::new(20);
        s.last_visible = 3;
        s.select_to(8);

        assert_eq!(s.selected(), 8);
        assert_eq!(s.scroll_offset(), 6);
    }

    fn sidebar_items(n: usize) -> Vec<SidebarItem> {
        use crate::data::Section;
        let sections = [
            Section::Dashboard,
            Section::Tools,
            Section::Templates,
            Section::Ssh,
            Section::Firewall,
            Section::Tailscale,
            Section::Harden,
            Section::WireGuard,
            Section::Updates,
            Section::Users,
            Section::Audit,
            Section::Monitor,
        ];
        (0..n)
            .map(|i| SidebarItem {
                icon: "◆",
                section: sections[i % sections.len()],
                badge: None,
            })
            .collect()
    }

    #[test]
    fn render_computes_visible_window_and_hitboxes() {
        use ratatui::{Terminal, backend::TestBackend};

        use crate::ui::theme::CHARM;

        let items = sidebar_items(20);
        let mut s = Sidebar::new(items.len());

        let area = Rect::new(0, 0, SIDEBAR_W, 20);
        let mut terminal = Terminal::new(TestBackend::new(SIDEBAR_W, 20)).unwrap();
        terminal
            .draw(|f| {
                s.render(f, area, CHARM, &items, 0, true, false);
            })
            .unwrap();

        let block = Block::default().borders(Borders::RIGHT);
        let inner = block.inner(area);
        let list_top = inner.y + 2;
        let list_bottom = inner.bottom().saturating_sub(1);
        let expected_visible = usize::from(list_bottom.saturating_sub(list_top)) / 2;
        assert_eq!(s.last_visible, expected_visible);

        assert!(!s.hitboxes.is_empty(), "render should push hitboxes");
        for (i, r) in s.hitboxes.iter().enumerate() {
            assert_eq!(r.height, 1, "hitbox[{i}] height");
            assert!(r.x == inner.x, "hitbox[{i}] x inside inner");
            assert!(
                r.y >= inner.y && r.y < inner.bottom(),
                "hitbox[{i}] y {r:?} outside inner {inner:?}"
            );
        }

        let first = s.hitboxes[0];
        assert_eq!(s.item_at(first.x, first.y), Some(0));
    }

    #[test]
    fn render_collapsed_uses_step_one() {
        use ratatui::{Terminal, backend::TestBackend};

        use crate::ui::theme::CHARM;

        let items = sidebar_items(20);
        let mut s = Sidebar::new(items.len());

        let area = Rect::new(0, 0, SIDEBAR_W_COLLAPSED, 20);
        let mut terminal = Terminal::new(TestBackend::new(SIDEBAR_W_COLLAPSED, 20)).unwrap();
        terminal
            .draw(|f| {
                s.render(f, area, CHARM, &items, 0, true, true);
            })
            .unwrap();

        let block = Block::default().borders(Borders::RIGHT);
        let inner = block.inner(area);
        let list_top = inner.y;
        let list_bottom = inner.bottom().saturating_sub(1);
        let expected_visible = usize::from(list_bottom.saturating_sub(list_top));
        assert_eq!(s.last_visible, expected_visible);
        assert!(s.hitboxes.len() >= 2);
        for w in s.hitboxes.windows(2) {
            assert_eq!(w[1].y - w[0].y, 1, "collapsed hitboxes must be 1 row apart");
        }
    }

    #[test]
    fn render_scroll_offset_skips_top_items() {
        use ratatui::{Terminal, backend::TestBackend};

        use crate::ui::theme::CHARM;

        let items = sidebar_items(20);
        let mut s = Sidebar::new(items.len());

        let area = Rect::new(0, 0, SIDEBAR_W, 14);
        let mut terminal = Terminal::new(TestBackend::new(SIDEBAR_W, 14)).unwrap();
        terminal
            .draw(|f| {
                s.render(f, area, CHARM, &items, 0, true, false);
            })
            .unwrap();
        let visible = s.last_visible;
        assert!(visible > 0);
        s.scroll(3);
        assert_eq!(s.scroll_offset(), 3);

        terminal
            .draw(|f| {
                s.render(f, area, CHARM, &items, 0, true, false);
            })
            .unwrap();

        let first = s.hitboxes[0];
        assert_eq!(s.item_at(first.x, first.y), Some(3));
    }
}
