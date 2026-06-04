//! Bottom footer key-bar.

use ratatui::{
    Frame,
    layout::Rect,
    style::Style,
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
};

use crate::ui::theme::Palette;

/// Render the footer key-bar into `area`.
///
/// `keys` is a list of `(key, label)` pairs rendered left-to-right; a
/// right-aligned `? help` hint is always appended on the right.
pub fn render_footer(frame: &mut Frame, area: Rect, p: Palette, keys: &[(&str, &str)]) {
    let block = Block::default()
        .borders(Borders::BOTTOM)
        .border_style(Style::new().fg(p.border))
        .style(Style::new().bg(p.bg_alt));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let key_style = p.key_style();
    let lbl_style = p.label_style();

    let mut spans = vec![Span::raw(" ")];
    for (key, label) in keys {
        spans.push(Span::styled(format!(" {key} "), key_style));
        spans.push(Span::raw(" "));
        spans.push(Span::styled((*label).to_string(), lbl_style));
        spans.push(Span::raw("    "));
    }
    frame.render_widget(Paragraph::new(Line::from(spans)), inner);

    let help = Line::from(vec![
        Span::styled(" ? ", key_style),
        Span::raw(" "),
        Span::styled("help ", lbl_style),
    ]);
    frame.render_widget(Paragraph::new(help).right_aligned(), inner);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::theme::CHARM;
    use ratatui::{Terminal, backend::TestBackend};

    #[test]
    fn renders_keys_and_help() {
        let mut terminal = Terminal::new(TestBackend::new(60, 2)).unwrap();
        terminal
            .draw(|f| {
                render_footer(f, f.area(), CHARM, &[("↑↓", "move"), ("↵", "open")]);
            })
            .unwrap();
        let out = terminal.backend().to_string();
        assert!(out.contains("move"), "move label: {out}");
        assert!(out.contains("help"), "help hint: {out}");
    }
}
