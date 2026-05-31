use color_eyre::eyre::Result;
use crossterm::event::{Event, EventStream, KeyEventKind};
use futures::StreamExt;
use ratatui::{DefaultTerminal, Frame};

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
            // TODO: help screen
            Action::Help | Action::Continue => {}
        }
    }

    fn view(&mut self, frame: &mut Frame) {
        self.welcome.view(frame);
    }

    pub async fn run(mut self, mut terminal: DefaultTerminal) -> Result<()> {
        let mut events = EventStream::new();

        loop {
            terminal.draw(|f| self.view(f))?;

            let event = events.next().await;
            match event {
                Some(Ok(event)) => match event {
                    Event::Key(key) if key.kind == KeyEventKind::Press => {
                        if let Some(action) = self.welcome.handle_key(key.code) {
                            self.update(action);
                        }
                    }
                    Event::Resize(..) => {
                        self.welcome.invalidate_cache();
                    }
                    _ => {}
                },
                Some(Err(e)) => {
                    return Err(e.into());
                }
                None => {
                    // Event stream ended (terminal disconnected)
                    break;
                }
            }

            if self.should_quit {
                break;
            }
        }

        Ok(())
    }
}
