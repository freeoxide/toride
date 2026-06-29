use crossterm::event::KeyCode;
use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    style::Style,
    text::{Line, Span},
    widgets::Paragraph,
};

use crate::action::Action;
use crate::ui::responsive::Viewport;
use crate::ui::theme::Palette;

/// Lightweight help modal content renderer.
///
/// No longer a navigable screen — rendered as an overlay on top of the active
/// screen when `App::help_visible` is `true`.
pub struct HelpScreen;

impl Default for HelpScreen {
    fn default() -> Self {
        Self::new()
    }
}

impl HelpScreen {
    /// Construct a new help screen renderer.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Handle a key press while the help modal is open.
    pub fn handle_key(code: KeyCode) -> Option<Action> {
        match code {
            KeyCode::Char('b' | '?') | KeyCode::Esc => Some(Action::CloseHelp),
            KeyCode::Char('q') => Some(Action::Quit),
            _ => None,
        }
    }

    /// Render help content into the given area (inside the modal border).
    pub fn render(frame: &mut Frame, content_area: Rect, p: Palette, viewport: Viewport) {
        // Vertical layout within content area
        let [
            _top,
            title_area,
            _g1,
            bindings_area,
            _g2,
            keys_area,
            _bottom,
        ] = Layout::vertical([
            Constraint::Fill(1),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(7),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Fill(1),
        ])
        .areas(content_area);

        // ── Title ───────────────────────────────────────────────────────
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                "Help",
                Style::new().fg(p.accent).bold(),
            )))
            .centered(),
            title_area,
        );

        // ── Keybindings ─────────────────────────────────────────────────
        let key_style = p.key_style();
        let lbl_style = p.label_style();

        let entries: Vec<Line<'_>> = if viewport >= Viewport::Compact {
            vec![
                keybinding_line("Tab", "Cycle focus region", key_style, lbl_style),
                keybinding_line("j / k", "Move / scroll", key_style, lbl_style),
                keybinding_line("Enter", "Open / select", key_style, lbl_style),
                keybinding_line("1–9", "Jump to section", key_style, lbl_style),
                keybinding_line("\\", "Collapse sidebar", key_style, lbl_style),
                keybinding_line("? / Esc", "Toggle help / back", key_style, lbl_style),
                keybinding_line("q", "Quit", key_style, lbl_style),
            ]
        } else {
            vec![
                keybinding_line("Tab", "Focus", key_style, lbl_style),
                keybinding_line("j/k", "Move", key_style, lbl_style),
                keybinding_line("Enter", "Open", key_style, lbl_style),
                keybinding_line("\\", "Collapse", key_style, lbl_style),
                keybinding_line("q", "Quit", key_style, lbl_style),
            ]
        };

        frame.render_widget(Paragraph::new(entries).centered(), bindings_area);

        // ── Close hint ──────────────────────────────────────────────────
        let close_line = Line::from(vec![
            Span::styled(" Esc ", key_style),
            Span::raw(" "),
            Span::styled("close", Style::new().fg(p.text_muted)),
        ]);
        frame.render_widget(Paragraph::new(close_line).centered(), keys_area);
    }
}

fn keybinding_line<'a>(key: &str, desc: &str, key_style: Style, lbl_style: Style) -> Line<'a> {
    Line::from(vec![
        Span::styled(format!(" {key} "), key_style),
        Span::raw("  "),
        Span::styled(desc.to_string(), lbl_style),
    ])
}

#[cfg(test)]
mod tests {
    use crossterm::event::KeyCode;

    use super::HelpScreen;
    use crate::action::Action;

    #[test]
    fn new_creates_screen() {
        let _screen = HelpScreen::new();
    }

    #[test]
    fn handle_key_close_help_on_b() {
        assert_eq!(
            HelpScreen::handle_key(KeyCode::Char('b')),
            Some(Action::CloseHelp)
        );
    }

    #[test]
    fn handle_key_close_help_on_esc() {
        assert_eq!(
            HelpScreen::handle_key(KeyCode::Esc),
            Some(Action::CloseHelp)
        );
    }

    #[test]
    fn handle_key_close_help_on_question_mark() {
        assert_eq!(
            HelpScreen::handle_key(KeyCode::Char('?')),
            Some(Action::CloseHelp)
        );
    }

    #[test]
    fn handle_key_quit_on_q() {
        assert_eq!(
            HelpScreen::handle_key(KeyCode::Char('q')),
            Some(Action::Quit)
        );
    }

    #[test]
    fn handle_key_none_for_other_keys() {
        assert_eq!(HelpScreen::handle_key(KeyCode::Char('a')), None);
        assert_eq!(HelpScreen::handle_key(KeyCode::Enter), None);
        assert_eq!(HelpScreen::handle_key(KeyCode::Up), None);
    }
}
