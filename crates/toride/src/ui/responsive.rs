use std::borrow::Cow;

use ratatui::{
    Frame,
    layout::{Constraint, Rect},
    style::Style,
    text::{Line, Span},
    widgets::Paragraph,
};
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

use super::theme::Palette;

// ── Breakpoints ──────────────────────────────────────────────────────────────

/// Minimum terminal width (columns) below which the layout collapses to `TooSmall`.
pub const MIN_WIDTH: u16 = 30;
/// Minimum terminal height (rows) below which the layout collapses to `TooSmall`.
pub const MIN_HEIGHT: u16 = 10;

const FULL_W: u16 = 72;
const FULL_H: u16 = 24;
const COMPACT_W: u16 = 50;
const COMPACT_H: u16 = 16;

/// Terminal size category for adaptive layouts.
///
/// Derives `PartialOrd` / `Ord` by declaration order — variants are ordered
/// smallest-to-largest so that `vp >= Viewport::Compact` means "at least Compact".
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Viewport {
    /// < 30 x 10 — too small to render anything useful
    TooSmall,
    /// >= 30 x 10 — abbreviated text, no labels
    Minimal,
    /// >= 50 x 16 — reduced spacing, truncated content
    Compact,
    /// >= 72 x 24 — full chrome, generous spacing
    Full,
}

impl Viewport {
    /// Classify a terminal area into a [`Viewport`] size category.
    #[must_use]
    pub fn from_area(area: Rect) -> Self {
        let (w, h) = (area.width, area.height);
        if w < MIN_WIDTH || h < MIN_HEIGHT {
            Self::TooSmall
        } else if w >= FULL_W && h >= FULL_H {
            Self::Full
        } else if w >= COMPACT_W && h >= COMPACT_H {
            Self::Compact
        } else {
            Self::Minimal
        }
    }
}

// ── Layout helpers ───────────────────────────────────────────────────────────

/// Center column constraint — caps at 72 columns but shrinks on narrow terminals.
#[must_use]
pub fn center_column() -> Constraint {
    Constraint::Max(FULL_W)
}

// ── Fallback rendering ───────────────────────────────────────────────────────

/// Render a centered "terminal too small" message.
/// Returns `true` when the terminal is too small — callers should early-return.
pub fn render_too_small(frame: &mut Frame, p: Palette) -> bool {
    let vp = Viewport::from_area(frame.area());
    if vp != Viewport::TooSmall {
        return false;
    }

    let area = frame.area();
    let msg = format!("Terminal too small — need at least {MIN_WIDTH}x{MIN_HEIGHT}");
    let line = Line::from(Span::styled(msg, Style::new().fg(p.text_dim)));
    frame.render_widget(Paragraph::new(line).centered(), area);
    true
}

/// Compute the centered content column area from the full frame area.
pub fn center_area(area: Rect) -> Rect {
    let [_, center, _] = ratatui::layout::Layout::horizontal([
        ratatui::layout::Constraint::Fill(1),
        center_column(),
        ratatui::layout::Constraint::Fill(1),
    ])
    .flex(ratatui::layout::Flex::Center)
    .areas(area);
    center
}

// ── Content truncation ───────────────────────────────────────────────────────

/// Truncate a string to `max_width` Unicode-width columns, appending ".." if it
/// doesn't fit.
#[must_use]
pub fn truncate_str(s: &str, max_width: usize) -> String {
    if max_width < 2 {
        return String::new();
    }

    if UnicodeWidthStr::width(s) <= max_width {
        return s.to_owned();
    }

    let mut width = 0usize;
    for (i, ch) in s.char_indices() {
        let cw = ch.width().unwrap_or(1);
        if width + cw > max_width - 2 {
            return format!("{}..", &s[..i]);
        }
        width += cw;
    }

    s.to_owned()
}

/// Truncate each line of a logo (array of `&str`) to `max_width`, appending ".."
/// when a row overflows. Returns styled `Line`s — borrows the original slice when
/// no truncation is needed, avoiding allocation.
#[must_use]
pub fn truncate_logo<'a>(rows: &[&'a str], max_width: u16, style: Style) -> Vec<Line<'a>> {
    let mw = max_width as usize;
    rows.iter()
        .map(|row| {
            let text = if UnicodeWidthStr::width(*row) <= mw {
                Cow::Borrowed(*row)
            } else {
                Cow::Owned(truncate_str(row, mw))
            };
            Line::from(Span::styled(text, style))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::layout::Rect;

    // ── Viewport::from_area ─────────────────────────────────────────────────────

    fn rect(w: u16, h: u16) -> Rect {
        Rect::new(0, 0, w, h)
    }

    #[test]
    fn viewport_too_small_width() {
        assert_eq!(Viewport::from_area(rect(29, 24)), Viewport::TooSmall);
    }

    #[test]
    fn viewport_too_small_height() {
        assert_eq!(Viewport::from_area(rect(72, 9)), Viewport::TooSmall);
    }

    #[test]
    fn viewport_too_small_both() {
        assert_eq!(Viewport::from_area(rect(20, 5)), Viewport::TooSmall);
    }

    #[test]
    fn viewport_minimal_boundary() {
        // Exactly 30x10
        assert_eq!(Viewport::from_area(rect(30, 10)), Viewport::Minimal);
    }

    #[test]
    fn viewport_minimal_between_breakpoints() {
        // 40x12 — between Minimal and Compact
        assert_eq!(Viewport::from_area(rect(40, 12)), Viewport::Minimal);
    }

    #[test]
    fn viewport_compact_boundary() {
        // Exactly 50x16
        assert_eq!(Viewport::from_area(rect(50, 16)), Viewport::Compact);
    }

    #[test]
    fn viewport_compact_between_breakpoints() {
        // 60x20 — between Compact and Full
        assert_eq!(Viewport::from_area(rect(60, 20)), Viewport::Compact);
    }

    #[test]
    fn viewport_full_boundary() {
        // Exactly 72x24
        assert_eq!(Viewport::from_area(rect(72, 24)), Viewport::Full);
    }

    #[test]
    fn viewport_full_large() {
        // Larger than full
        assert_eq!(Viewport::from_area(rect(120, 40)), Viewport::Full);
    }

    #[test]
    fn viewport_ordering() {
        assert!(Viewport::Full > Viewport::Compact);
        assert!(Viewport::Compact > Viewport::Minimal);
        assert!(Viewport::Minimal > Viewport::TooSmall);
    }

    #[test]
    fn viewport_compact_wide_but_short() {
        // Wide enough for compact but too short
        assert_eq!(Viewport::from_area(rect(50, 14)), Viewport::Minimal);
    }

    #[test]
    fn viewport_compact_tall_but_narrow() {
        // Tall enough for compact but too narrow
        assert_eq!(Viewport::from_area(rect(48, 16)), Viewport::Minimal);
    }

    // ── truncate_str ────────────────────────────────────────────────────────────

    #[test]
    fn truncate_str_short_string_fits() {
        assert_eq!(truncate_str("hi", 10), "hi");
    }

    #[test]
    fn truncate_str_exact_fit() {
        assert_eq!(truncate_str("hello", 5), "hello");
    }

    #[test]
    fn truncate_str_needs_truncation() {
        let result = truncate_str("hello world", 8);
        assert_eq!(result, "hello ..");
    }

    #[test]
    fn truncate_str_max_width_one() {
        // max_width < 2 returns empty
        assert_eq!(truncate_str("hello", 1), "");
    }

    #[test]
    fn truncate_str_max_width_zero() {
        assert_eq!(truncate_str("hello", 0), "");
    }

    #[test]
    fn truncate_str_empty_input() {
        assert_eq!(truncate_str("", 10), "");
    }

    #[test]
    fn truncate_str_unicode_wide_chars() {
        // Each CJK char is width 2
        let result = truncate_str("你好世界", 6);
        assert!(
            result.ends_with(".."),
            "truncated string should end with ..: {result}"
        );
        // The result should be 6 columns wide: 2+2+".." = 6
        assert_eq!(UnicodeWidthStr::width(result.as_str()), 6);
    }

    #[test]
    fn truncate_str_unicode_exact_fit() {
        // 4 CJK chars = 8 columns, fits exactly
        assert_eq!(truncate_str("你好世界", 8), "你好世界");
    }

    #[test]
    fn truncate_str_two_char_min_width() {
        // max_width = 2: max_width-2=0, first char 'a' has cw=1 > 0,
        // so the loop produces empty prefix + ".."
        let result = truncate_str("abc", 2);
        assert_eq!(result, "..");
    }

    #[test]
    fn viewport_boundary_29x9() {
        assert_eq!(Viewport::from_area(rect(29, 9)), Viewport::TooSmall);
    }

    #[test]
    fn viewport_boundary_29x10() {
        assert_eq!(Viewport::from_area(rect(29, 10)), Viewport::TooSmall);
    }

    #[test]
    fn viewport_boundary_30x9() {
        assert_eq!(Viewport::from_area(rect(30, 9)), Viewport::TooSmall);
    }

    #[test]
    fn viewport_boundary_49x16() {
        assert_eq!(Viewport::from_area(rect(49, 16)), Viewport::Minimal);
    }

    #[test]
    fn viewport_boundary_71x24() {
        assert_eq!(Viewport::from_area(rect(71, 24)), Viewport::Compact);
    }

    #[test]
    fn truncate_str_hello_fits_width_10() {
        assert_eq!(truncate_str("hello", 10), "hello");
    }

    #[test]
    fn truncate_str_hello_world_width_8() {
        assert_eq!(truncate_str("hello world", 8), "hello ..");
    }

    #[test]
    fn truncate_str_empty_string() {
        assert_eq!(truncate_str("", 10), "");
    }

    #[test]
    fn truncate_str_unicode_cjk_small_width() {
        // "日本語テスト" — each CJK char is width 2, total width = 10
        // With max_width=6: first 2 CJK chars (width 4) fit, third would make 6
        // but 6+2 > 6-2=4, so truncate after 2 chars: "日本.."
        let result = truncate_str("日本語テスト", 6);
        assert!(result.ends_with(".."), "should end with ..: {result}");
        assert_eq!(UnicodeWidthStr::width(result.as_str()), 6);
    }

    // ── truncate_logo ───────────────────────────────────────────────────────────

    #[test]
    fn truncate_logo_no_truncation_needed() {
        let style = Style::default();
        let rows = &["hello", "world"];
        let lines = truncate_logo(rows, 10, style);
        assert_eq!(lines.len(), 2);
    }

    #[test]
    fn truncate_logo_truncates_long_rows() {
        let style = Style::default();
        let rows = &["hello world", "hi"];
        let lines = truncate_logo(rows, 8, style);
        assert_eq!(lines.len(), 2);
        // First row should be truncated
    }
}
