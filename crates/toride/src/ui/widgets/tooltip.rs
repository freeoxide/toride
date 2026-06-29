//! Reusable anchored tooltip widget and line-building helpers.
//!
//! Renders a small floating card anchored below an on-screen element.
//! Unlike [`Modal`](super::Modal), the tooltip has no scrim, no title in
//! the border, and positions itself relative to an anchor rect rather than
//! centered.
//!
//! # Example
//!
//! ```ignore
//! use crate::ui::widgets::tooltip::{Tooltip, title_line, kv, kv_with_suffix};
//!
//! let lines = vec![
//!     title_line("CPU", p),
//!     kv("Usage", &format!("{pct:.0}%"), p),
//! ];
//! let rect = Tooltip::new(&lines)
//!     .anchor(hitbox)
//!     .render(frame, p);
//! ```

use ratatui::{
    Frame,
    layout::Rect,
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Clear, Paragraph},
};

use super::panel::render_panel;
use crate::ui::theme::Palette;

/// Padding (left + right) and border columns added to content width.
const H_PAD: u16 = 4;
/// Border rows added to content height.
const V_PAD: u16 = 2;

// ── Line-building helpers ──────────────────────────────────────────────────────

/// Build a tooltip title line: the name in bold accent.
#[must_use]
pub fn title_line(name: &str, p: Palette) -> Line<'static> {
    Line::from(Span::styled(
        name.to_string(),
        Style::new().fg(p.accent).bold(),
    ))
}

/// Build a tooltip title line with a dimmed detail suffix (e.g. CPU brand, disk name).
///
/// If `detail` is empty, returns just the bold-accent title.
#[must_use]
pub fn title_line_with_detail(name: &str, detail: &str, p: Palette) -> Line<'static> {
    if detail.is_empty() {
        return title_line(name, p);
    }
    Line::from(vec![
        Span::styled(name.to_string(), Style::new().fg(p.accent).bold()),
        Span::styled(format!("  \u{b7}  {detail}"), Style::new().fg(p.text_dim)),
    ])
}

/// Build a key-value row: right-padded label in `text_muted`, value in `text`.
///
/// The label is right-padded to 7 characters for column alignment.
#[must_use]
pub fn kv(label: &str, value: &str, p: Palette) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("{label:<7}"), Style::new().fg(p.text_muted)),
        Span::styled(value.to_string(), Style::new().fg(p.text)),
    ])
}

/// Build a key-value row with a colored suffix (e.g. a percentage indicator).
///
/// Label is right-padded to 7 chars; suffix is appended after the value.
#[must_use]
pub fn kv_with_suffix(
    label: &str,
    value: &str,
    suffix: &str,
    suffix_color: Color,
    p: Palette,
) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("{label:<7}"), Style::new().fg(p.text_muted)),
        Span::styled(value.to_string(), Style::new().fg(p.text)),
        Span::styled(suffix.to_string(), Style::new().fg(suffix_color)),
    ])
}

// ── Tooltip widget ─────────────────────────────────────────────────────────────

/// A reusable anchored tooltip widget.
///
/// Computes its own size from content lines, positions itself below an
/// anchor rect (centered horizontally, clamped to frame), clears for opacity,
/// and renders a bordered panel.
///
/// Construct with [`Tooltip::new`] and optional builder methods, then call
/// [`Tooltip::render`].
pub struct Tooltip<'a> {
    lines: &'a [Line<'a>],
    anchor: Rect,
}

impl<'a> Tooltip<'a> {
    /// Create a new tooltip with the given content lines.
    #[must_use]
    pub fn new(lines: &'a [Line<'a>]) -> Self {
        Self {
            lines,
            anchor: Rect::default(),
        }
    }

    /// Set the anchor rect the tooltip positions itself below.
    ///
    /// The tooltip is centered horizontally below the anchor and placed at
    /// `anchor.bottom()`.
    #[must_use]
    pub fn anchor(mut self, anchor: Rect) -> Self {
        self.anchor = anchor;
        self
    }

    /// Render the tooltip and return its rect, or `None` if it doesn't fit.
    ///
    /// This performs the full pipeline:
    /// 1. Computes size from the widest content line
    /// 2. Positions below the anchor, centered horizontally, clamped to frame
    /// 3. Clears for opacity
    /// 4. Renders a bordered panel
    /// 5. Renders content paragraph
    pub fn render(self, frame: &mut Frame, p: Palette) -> Option<Rect> {
        let max_w = self.lines.iter().map(Line::width).max().unwrap_or(10);
        let w = u16::try_from(max_w).unwrap_or(20).saturating_add(H_PAD);
        let h = u16::try_from(self.lines.len())
            .unwrap_or(1)
            .saturating_add(V_PAD);

        let frame_area = frame.area();
        let x = (self.anchor.x + self.anchor.width / 2)
            .saturating_sub(w / 2)
            .max(frame_area.x)
            .min(frame_area.right().saturating_sub(w));
        let y = self.anchor.bottom();

        if y + h > frame_area.bottom() || x + w > frame_area.right() {
            return None;
        }

        let rect = Rect::new(x, y, w, h);

        frame.render_widget(Clear, rect);
        let inner = render_panel(frame, rect, None, p.text, p.border_hi, p.panel);
        frame.render_widget(Paragraph::new(self.lines.to_vec()), inner);

        Some(rect)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_palette() -> Palette {
        crate::ui::theme::CHARM
    }

    #[test]
    fn new_sets_defaults() {
        let lines: Vec<Line<'_>> = vec![];
        let tooltip = Tooltip::new(&lines);
        assert_eq!(tooltip.anchor, Rect::default());
    }

    #[test]
    fn anchor_overrides() {
        let lines: Vec<Line<'_>> = vec![];
        let anchor = Rect::new(10, 5, 20, 3);
        let tooltip = Tooltip::new(&lines).anchor(anchor);
        assert_eq!(tooltip.anchor, anchor);
    }

    #[test]
    fn kv_pads_label_to_seven() {
        let p = test_palette();
        let line = kv("CPU", "100%", p);
        let spans = line.spans;
        // First span content should be "CPU    " (7 chars, right-padded)
        assert_eq!(spans[0].content, "CPU    ");
        assert_eq!(spans[0].style.fg, Some(p.text_muted));
    }

    #[test]
    fn kv_has_two_spans() {
        let p = test_palette();
        let line = kv("Free", "12 GB", p);
        assert_eq!(line.spans.len(), 2);
    }

    #[test]
    fn kv_with_suffix_has_three_spans() {
        let p = test_palette();
        let line = kv_with_suffix("Used", "8 GB", " (87%)", Color::Red, p);
        let spans = &line.spans;
        assert_eq!(spans.len(), 3);
        assert_eq!(spans[2].content, " (87%)");
        assert_eq!(spans[2].style.fg, Some(Color::Red));
    }

    #[test]
    fn title_line_is_bold_accent() {
        let p = test_palette();
        let line = title_line("Network", p);
        let span = &line.spans[0];
        assert_eq!(span.content, "Network");
        assert_eq!(span.style.fg, Some(p.accent));
        assert!(
            span.style
                .add_modifier
                .contains(ratatui::style::Modifier::BOLD)
        );
    }

    #[test]
    fn title_line_with_detail_has_two_spans() {
        let p = test_palette();
        let line = title_line_with_detail("CPU", "Apple M2", p);
        assert_eq!(line.spans.len(), 2);
    }

    #[test]
    fn title_line_with_detail_empty_falls_back() {
        let p = test_palette();
        let line = title_line_with_detail("CPU", "", p);
        assert_eq!(line.spans.len(), 1);
    }
}
