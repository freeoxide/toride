//! Rounded, optionally-focusable card widget.
//!
//! A [`Card`] is a rounded-border panel with a solid background and a body of
//! pre-built [`Line`]s. When focused, its border switches from the palette's
//! `border` colour to `border_hi`. Used for the dashboard stat cards and the
//! module-grid cards.

use ratatui::{
    Frame,
    layout::Rect,
    style::{Color, Style},
    text::Line,
    widgets::{Block, BorderType, Borders, Padding, Paragraph},
};

use crate::ui::theme::Palette;

/// A rounded, focusable content card.
pub struct Card<'a> {
    body: Vec<Line<'a>>,
    focused: bool,
    border_color: Option<Color>,
}

impl<'a> Card<'a> {
    /// Create a card with the given body lines.
    #[must_use]
    pub fn new(body: Vec<Line<'a>>) -> Self {
        Self {
            body,
            focused: false,
            border_color: None,
        }
    }

    /// Mark the card focused (uses `border_hi` for the border).
    #[must_use]
    pub fn focused(mut self, focused: bool) -> Self {
        self.focused = focused;
        self
    }

    /// Override the (unfocused) border colour.
    #[must_use]
    pub fn border_color(mut self, color: Color) -> Self {
        self.border_color = Some(color);
        self
    }

    /// Render the card into `area`.
    pub fn render(self, frame: &mut Frame, area: Rect, p: Palette) {
        let border_color = if self.focused {
            p.border_hi
        } else {
            self.border_color.unwrap_or(p.border)
        };

        let block = Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::new().fg(border_color))
            .style(Style::new().bg(p.panel))
            .padding(Padding::horizontal(1));

        frame.render_widget(Paragraph::new(self.body).block(block), area);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::theme::CHARM;
    use ratatui::{Terminal, backend::TestBackend};

    fn render(card: Card<'_>, w: u16, h: u16) -> String {
        let mut terminal = Terminal::new(TestBackend::new(w, h)).unwrap();
        terminal.draw(|f| card.render(f, f.area(), CHARM)).unwrap();
        terminal.backend().to_string()
    }

    #[test]
    fn renders_rounded_corners() {
        let out = render(Card::new(vec![Line::from("hi")]), 10, 4);
        // Rounded border type uses ╭ ╮ ╰ ╯ corners.
        assert!(out.contains('╭'), "expected rounded corner: {out}");
    }

    #[test]
    fn renders_body_text() {
        let out = render(Card::new(vec![Line::from("body")]), 12, 4);
        assert!(out.contains("body"), "expected body text: {out}");
    }
}
