use ratatui::{
    Frame,
    layout::{Constraint, Flex, Layout},
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
};

use crate::action::Action;

const VERSION: &str = "0.4.1";
const EDITION: &str = "SINGLE-HOST";

const LOGO: &[&str] = &[
    "████████ ████████ ████████ ████████ ████████ ████████",
    "    ██  ██    ██ ██    ██     ██  ██    ██ ██      ",
    "    ██  ████████ ██    ██     ██  ██    ██ ██      ",
    "    ██  ██    ██ ████████     ██  ████████ ████████",
    "    ██  ██    ██ ██  ██      ██  ██    ██ ██      ",
    "    ██  ██    ██ ██   ██     ██  ██    ██ ██      ",
    "    ██  ████████ ██    ██ ████  ██    ██ ████████",
];

const STATUS_MESSAGES: &[(&str, &str)] = &[
    ("ok", "loaded /etc/toride/config.toml"),
    ("ok", "verifying SSH keypair (ed25519)"),
    ("ok", "apt available · 218 pkgs known"),
    ("ok", "docker engine 27.4.1 detected"),
    ("ok", "network: cloudflare 1.1.1.1 reachable"),
    ("ok", "ratatui v0.29.0 rendering · 60 fps"),
    ("--", "ready."),
];

pub struct WelcomeScreen;

impl WelcomeScreen {
    pub fn handle_key(&self, code: ratatui::crossterm::event::KeyCode) -> Option<Action> {
        use ratatui::crossterm::event::KeyCode;
        match code {
            KeyCode::Char('q') | KeyCode::Esc => Some(Action::Quit),
            KeyCode::Char('?') => Some(Action::Help),
            KeyCode::Enter | KeyCode::Char(' ') => Some(Action::Continue),
            _ => Some(Action::Continue),
        }
    }

    pub fn render(&self, frame: &mut Frame) {
        let area = frame.area();

        let [_, center, _] = Layout::horizontal([
            Constraint::Fill(1),
            Constraint::Length(72),
            Constraint::Fill(1),
        ])
        .flex(Flex::Center)
        .areas(area);

        let [
            top_pad,
            ver_area,
            prompt_area,
            logo_area,
            panel_area,
            keys_area,
            _,
        ] = Layout::vertical([
            Constraint::Fill(1),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(16),
            Constraint::Length(10),
            Constraint::Length(2),
            Constraint::Fill(1),
        ])
        .areas(center);

        let _ = top_pad;

        let version_line = Line::from(vec![
            Span::styled("⚡", Style::new().fg(Color::Magenta)),
            Span::raw(" · "),
            Span::styled(VERSION, Style::new().fg(Color::Magenta).bold()),
            Span::raw(" · "),
            Span::styled(EDITION, Style::new().fg(Color::Magenta).bold()),
        ]);
        frame.render_widget(Paragraph::new(version_line).centered(), ver_area);

        let prompt_line = Line::from(Span::styled(
            "Press any key, or click anywhere, to enter.",
            Style::new().fg(Color::DarkGray),
        ));
        frame.render_widget(Paragraph::new(prompt_line).centered(), prompt_area);

        let shadow_color = Color::Rgb(60, 15, 90);
        let main_color = Color::Magenta;
        let main_width = LOGO[0].len();
        let center_width = center.width as usize;
        let h_pad = center_width.saturating_sub(main_width) / 2;

        let mut logo_lines: Vec<Line> = Vec::new();
        for line in LOGO {
            let main_text = format!("{}{}", " ".repeat(h_pad), line);
            logo_lines.push(Line::from(Span::styled(
                main_text,
                Style::new().fg(main_color).bold(),
            )));
            let shadow_text = format!("{}  {}", " ".repeat(h_pad), line);
            logo_lines.push(Line::from(Span::styled(
                shadow_text,
                Style::new().fg(shadow_color),
            )));
        }
        frame.render_widget(Paragraph::new(logo_lines), logo_area);

        let status_lines: Vec<Line> = STATUS_MESSAGES
            .iter()
            .map(|(tag, msg)| {
                let tag_style = if *tag == "ok" {
                    Style::new().fg(Color::Green).bold()
                } else {
                    Style::new().fg(Color::Blue).bold()
                };
                Line::from(vec![
                    Span::styled(format!("[{}]", tag), tag_style),
                    Span::raw(" "),
                    Span::styled(*msg, Style::new().fg(Color::White)),
                ])
            })
            .collect();

        let panel = Paragraph::new(status_lines).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::new().fg(Color::Rgb(60, 60, 80)))
                .border_type(ratatui::widgets::BorderType::Rounded),
        );
        frame.render_widget(panel, panel_area);

        let keybindings = Line::from(vec![
            Span::styled(" ↵ ", Style::new().fg(Color::Cyan).bold()),
            Span::styled("continue ", Style::new().fg(Color::DarkGray)),
            Span::styled(" ? ", Style::new().fg(Color::Cyan).bold()),
            Span::styled("help ", Style::new().fg(Color::DarkGray)),
            Span::styled(" q ", Style::new().fg(Color::Cyan).bold()),
            Span::styled("quit", Style::new().fg(Color::DarkGray)),
        ]);
        frame.render_widget(Paragraph::new(keybindings).centered(), keys_area);
    }
}
