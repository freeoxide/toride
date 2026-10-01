//! Small "pill" badge spans for inline status chips, counts and buttons.
//!
//! A badge is a short label rendered with a filled background and a little
//! horizontal padding, e.g. ` active `, ` apt `, ` install all `. These are
//! plain [`Span`]s so they compose into any `Line`.

use ratatui::style::{Color, Style};
use ratatui::text::Span;

use crate::ui::theme::Palette;

/// Build a badge [`Span`] with the given foreground/background colours.
///
/// The label is wrapped in single spaces so the background reads as a pill.
#[must_use]
pub fn badge(label: &str, fg: Color, bg: Color) -> Span<'static> {
    Span::styled(format!(" {label} "), Style::new().fg(fg).bg(bg))
}

/// A muted/neutral badge using the palette's selection background — used for
/// counts and version chips (e.g. `12`, `v0.18`).
#[must_use]
pub fn neutral_badge(label: &str, p: Palette) -> Span<'static> {
    badge(label, p.text_dim, p.sel_bg)
}

/// An accent badge filled with `accent` — used for primary tags / buttons
/// (e.g. `install all`).
#[must_use]
pub fn accent_badge(label: &str, p: Palette) -> Span<'static> {
    badge(label, p.bg, p.accent)
}

/// An outlined-style tag badge that tints the foreground with `color` over the
/// selection background — used for update source tags (`apt`, `curl`).
#[must_use]
pub fn tag_badge(label: &str, color: Color, p: Palette) -> Span<'static> {
    badge(label, color, p.sel_bg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::theme::CHARM;

    #[test]
    fn badge_wraps_with_spaces() {
        let span = badge("ok", CHARM.bg, CHARM.accent);
        assert_eq!(span.content, " ok ");
    }

    #[test]
    fn neutral_badge_uses_sel_bg() {
        let span = neutral_badge("12", CHARM);
        assert_eq!(span.style.bg, Some(CHARM.sel_bg));
    }

    #[test]
    fn accent_badge_fills_accent() {
        let span = accent_badge("install all", CHARM);
        assert_eq!(span.style.bg, Some(CHARM.accent));
    }
}
