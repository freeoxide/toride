use ratatui::{
    Frame,
    layout::{Constraint, Layout},
    style::Style,
    text::{Line, Span},
    widgets::Paragraph,
};

use crate::action::Action;
use crate::ui::gradient::GradientCache;
use crate::ui::responsive::{self, Viewport};
use crate::ui::theme::{self, Palette};

pub struct HelpScreen {
    gradient_cache: GradientCache,
}

impl Default for HelpScreen {
    fn default() -> Self {
        Self::new()
    }
}

impl HelpScreen {
    pub fn new() -> Self {
        Self {
            gradient_cache: GradientCache::new(),
        }
    }

    pub fn invalidate_cache(&mut self) {
        self.gradient_cache.invalidate();
    }

    pub fn handle_key(&self, code: ratatui::crossterm::event::KeyCode) -> Option<Action> {
        use ratatui::crossterm::event::KeyCode;
        match code {
            KeyCode::Char('b') | KeyCode::Esc => Some(Action::Back),
            KeyCode::Char('q') => Some(Action::Quit),
            _ => None,
        }
    }

    pub fn view(&mut self, frame: &mut Frame) {
        self.view_with_palette(frame, theme::CHARM, false);
    }

    pub fn view_foreground(&mut self, frame: &mut Frame) {
        self.view_with_palette(frame, theme::CHARM, true);
    }

    fn view_with_palette(&mut self, frame: &mut Frame, p: Palette, skip_bg: bool) {
        let area = frame.area();
        let viewport = Viewport::from_area(area);

        if responsive::render_too_small(frame, p) {
            return;
        }

        // Gradient background
        if !skip_bg {
            let buf = frame.buffer_mut();
            self.gradient_cache.render_or_copy(buf, area, p);
        }

        // Adaptive center column
        let center = responsive::center_area(area);

        // Vertical layout
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
        .areas(center);

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
                keybinding_line("Enter", "Show system status", key_style, lbl_style),
                keybinding_line("?", "Show this help", key_style, lbl_style),
                keybinding_line("q", "Quit", key_style, lbl_style),
                keybinding_line("j / Down", "Scroll down", key_style, lbl_style),
                keybinding_line("k / Up", "Scroll up", key_style, lbl_style),
                keybinding_line("b / Esc", "Back to welcome", key_style, lbl_style),
            ]
        } else {
            vec![
                keybinding_line("Enter", "Status", key_style, lbl_style),
                keybinding_line("?", "Help", key_style, lbl_style),
                keybinding_line("q", "Quit", key_style, lbl_style),
                keybinding_line("j/k", "Scroll", key_style, lbl_style),
                keybinding_line("b", "Back", key_style, lbl_style),
            ]
        };

        frame.render_widget(Paragraph::new(entries).centered(), bindings_area);

        // ── Back hint ───────────────────────────────────────────────────
        let back_line = Line::from(vec![
            Span::styled(" b ", key_style),
            Span::raw(" "),
            Span::styled("back", Style::new().fg(p.text_muted)),
        ]);
        frame.render_widget(Paragraph::new(back_line).centered(), keys_area);
    }
}

fn keybinding_line<'a>(
    key: &str,
    desc: &str,
    key_style: Style,
    lbl_style: Style,
) -> Line<'a> {
    Line::from(vec![
        Span::styled(format!(" {key} "), key_style),
        Span::raw("  "),
        Span::styled(desc.to_string(), lbl_style),
    ])
}
