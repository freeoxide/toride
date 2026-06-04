//! Left sidebar: a numbered, collapsible module navigation list with an SSH
//! connection footer.
//!
//! [`Sidebar`] owns only interaction state (selection index + collapsed flag);
//! the item list is passed at [`render`](Sidebar::render) time so the screen
//! remains the single owner of the data.

use ratatui::{
    Frame,
    layout::Rect,
    style::Style,
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
};

use crate::data::SidebarItem;
use crate::ui::responsive::truncate_str;
use crate::ui::theme::Palette;

/// Expanded sidebar width.
pub const SIDEBAR_W: u16 = 30;
/// Collapsed (icon-rail) sidebar width.
pub const SIDEBAR_W_COLLAPSED: u16 = 6;
/// Rows consumed per expanded item (one content row + one padding row).
const ROW_STEP: u16 = 2;

/// Sidebar interaction state.
pub struct Sidebar {
    selected: usize,
    collapsed: bool,
    len: usize,
}

impl Sidebar {
    /// Create a sidebar for `len` items with the first item selected.
    #[must_use]
    pub fn new(len: usize) -> Self {
        Self {
            selected: 0,
            collapsed: false,
            len: len.max(1),
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
        &self,
        frame: &mut Frame,
        area: Rect,
        p: Palette,
        items: &[SidebarItem],
        active: usize,
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

        for (i, item) in items.iter().enumerate() {
            let Ok(idx) = u16::try_from(i) else { break };
            let y = list_top + idx * step;
            if y > list_bottom {
                break;
            }
            let row = Rect::new(inner.x, y, inner.width, 1);
            let is_sel = i == self.selected;
            let is_active = i == active;

            // Selection highlight: a padded "pill" that bleeds a quarter-cell
            // into the blank rows above and below (expanded mode only).
            if is_sel {
                let bg = if focused { p.sel_bg } else { p.bg_inset };
                let bar = if focused { p.accent } else { p.text_muted };
                if !collapsed {
                    Self::render_pill_caps(frame, inner, p, bg, bar, y, foot_y);
                }
                frame.render_widget(
                    Paragraph::new(Self::item_line(
                        i, item, p, is_active, is_sel, focused, collapsed,
                    ))
                    .style(Style::new().bg(bg)),
                    row,
                );
                // Border = the first cell recoloured to the accent.
                frame.render_widget(
                    Paragraph::new(Span::styled(" ", Style::new().bg(bar))),
                    Rect::new(inner.x, y, 1, 1),
                );
            } else {
                frame.render_widget(
                    Paragraph::new(Self::item_line(
                        i, item, p, is_active, is_sel, focused, collapsed,
                    )),
                    row,
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
    /// The selection highlight is a left-edge bar (`▌`) rather than a full-row
    /// background; it is bright when the sidebar is focused and dim otherwise.
    #[expect(
        clippy::fn_params_excessive_bools,
        reason = "item render state: active/selected/focused/collapsed"
    )]
    fn item_line(
        i: usize,
        item: &SidebarItem,
        p: Palette,
        is_active: bool,
        is_selected: bool,
        focused: bool,
        collapsed: bool,
    ) -> Line<'static> {
        let _ = (is_selected, focused);
        let num_style = Style::new().fg(p.text_muted);
        let highlight = is_active || is_selected;
        let (icon_color, label_color) = if highlight {
            (p.accent, p.accent)
        } else {
            (p.text_dim, p.text)
        };

        // Column 0 is reserved for the selection border, which is painted
        // separately by recolouring that cell — see `render` / `render_pill_caps`.
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
