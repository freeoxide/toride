use color_eyre::eyre::Result;
use crossterm::event::{Event, EventStream, KeyEventKind};
use futures::StreamExt;
use ratatui::{DefaultTerminal, Frame};
use tokio::select;

use crate::action::Action;
use crate::ui::welcome::WelcomeScreen;

pub struct App {
    welcome: WelcomeScreen,
    should_quit: bool,
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}

impl App {
    pub fn new() -> Self {
        Self {
            welcome: WelcomeScreen::new(),
            should_quit: false,
        }
    }

    fn update(&mut self, action: Action) {
        match action {
            Action::Quit => self.should_quit = true,
            Action::Help => {} // TODO: help screen
            Action::Continue => {}
        }
    }

    fn view(&mut self, frame: &mut Frame) {
        self.welcome.view(frame);
    }

    pub async fn run(mut self, mut terminal: DefaultTerminal) -> Result<()> {
        let mut events = EventStream::new();

        loop {
            terminal.draw(|f| self.view(f))?;

            select! {
                Some(Ok(event)) = events.next() => {
                    if let Event::Key(key) = event
                        && key.kind == KeyEventKind::Press
                        && let Some(action) = self.welcome.handle_key(key.code)
                    {
                        self.update(action);
                    }
                }
            }

            if self.should_quit {
                break;
            }
        }

        Ok(())
    }
}
