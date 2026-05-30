use color_eyre::eyre::Result;
use crossterm::event::{Event, EventStream, KeyCode, KeyEventKind};
use futures::StreamExt;
use ratatui::{DefaultTerminal, Frame};
use tokio::select;
use tokio::sync::oneshot;

use crate::action::Action;
use crate::status::TorideStatus;
use crate::ui::help::HelpScreen;
use crate::ui::status::StatusScreen;
use crate::ui::welcome::WelcomeScreen;

enum Screen {
    Welcome,
    Status,
    Help,
}

pub struct App {
    screen: Screen,
    welcome: WelcomeScreen,
    status: StatusScreen,
    help: HelpScreen,
    should_quit: bool,
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}

impl App {
    #[must_use]
    pub fn new() -> Self {
        Self {
            screen: Screen::Welcome,
            welcome: WelcomeScreen::new(),
            status: StatusScreen::new(),
            help: HelpScreen::new(),
            should_quit: false,
        }
    }

    fn update(&mut self, action: Action) {
        match action {
            Action::Quit => self.should_quit = true,
            Action::Continue => {
                self.screen = Screen::Status;
                self.status.invalidate_cache();
            }
            Action::Help => {
                self.screen = Screen::Help;
                self.help.invalidate_cache();
            }
            Action::Back => {
                self.screen = Screen::Welcome;
                self.welcome.invalidate_cache();
            }
        }
    }

    fn view(&mut self, frame: &mut Frame) {
        match self.screen {
            Screen::Welcome => self.welcome.view(frame),
            Screen::Status => self.status.view(frame),
            Screen::Help => self.help.view(frame),
        }
    }

    fn handle_key(&self, code: KeyCode) -> Option<Action> {
        match self.screen {
            Screen::Welcome => self.welcome_handle_key(code),
            Screen::Status => self.status_handle_key(code),
            Screen::Help => self.help.handle_key(code),
        }
    }

    fn welcome_handle_key(&self, code: KeyCode) -> Option<Action> {
        match code {
            KeyCode::Char('q') | KeyCode::Esc => Some(Action::Quit),
            KeyCode::Char('?') => Some(Action::Help),
            KeyCode::Enter | KeyCode::Char(' ') => Some(Action::Continue),
            _ => None,
        }
    }

    fn status_handle_key(&self, code: KeyCode) -> Option<Action> {
        match code {
            KeyCode::Char('b') | KeyCode::Esc => Some(Action::Back),
            KeyCode::Char('q') => Some(Action::Quit),
            _ => None,
        }
    }

    /// Run the main event loop.
    ///
    /// # Errors
    ///
    /// Returns an error if the terminal draw fails or the event stream encounters an error.
    pub async fn run(mut self, mut terminal: DefaultTerminal) -> Result<()> {
        let mut events = EventStream::new();
        let mut status_rx: Option<oneshot::Receiver<TorideStatus>> = None;
        let refresh_interval = tokio::time::interval(std::time::Duration::from_secs(2));
        tokio::pin!(refresh_interval);

        loop {
            terminal.draw(|f| self.view(f))?;

            select! {
                // Prioritize terminal events and status results over timer
                biased;

                Some(Ok(event)) = events.next() => {
                    let action = match event {
                        Event::Key(key) if key.kind == KeyEventKind::Press => {
                            self.handle_key(key.code)
                        }
                        Event::Resize(..) => {
                            self.welcome.invalidate_cache();
                            self.status.invalidate_cache();
                            self.help.invalidate_cache();
                            None
                        }
                        _ => None,
                    };
                    if let Some(action) = action {
                        self.update(action);
                    }
                }

                // Receive collected status data
                result = async {
                    match &mut status_rx {
                        Some(rx) => rx.await.ok(),
                        None => None,
                    }
                }, if status_rx.is_some() => {
                    if let Some(status) = result {
                        self.status.set_status(status);
                    }
                    status_rx = None;
                }

                // Periodic status refresh
                _ = refresh_interval.tick() => {
                    if matches!(self.screen, Screen::Status) && status_rx.is_none() {
                        let (tx, rx) = oneshot::channel();
                        status_rx = Some(rx);
                        tokio::spawn(async move {
                            let status = tokio::task::spawn_blocking(|| {
                                TorideStatus::collect()
                            })
                            .await
                            .unwrap_or_else(|_| TorideStatus::collect());
                            let _ = tx.send(status);
                        });
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
