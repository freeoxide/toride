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

pub const MIN_WIDTH: u16 = 30;
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
    let msg = format!(
        "Terminal too small — need at least {MIN_WIDTH}x{MIN_HEIGHT}"
    );
    let line = Line::from(Span::styled(msg, Style::new().fg(p.text_dim)));
    frame.render_widget(Paragraph::new(line).centered(), area);
    true
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
