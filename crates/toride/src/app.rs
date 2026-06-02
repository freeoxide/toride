use color_eyre::eyre::Result;
use crossterm::event::{Event, EventStream, KeyCode, KeyEventKind, MouseEvent, MouseEventKind};
use futures::StreamExt;
use ratatui::{DefaultTerminal, Frame};
use tachyonfx::Interpolation;
use tokio::select;
use tokio::sync::oneshot;

use crate::action::Action;
use crate::status::TorideStatus;
use crate::ui::help::HelpScreen;
use crate::ui::status::StatusScreen;
use crate::ui::transition::{TransitionCache, TransitionState};
use crate::ui::welcome::WelcomeScreen;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Screen {
    Welcome,
    Status,
    Help,
}

impl Screen {
    fn key(self) -> u8 {
        self as u8
    }

    #[allow(
        clippy::wildcard_in_or_patterns,
        clippy::match_same_arms,
        reason = "fallback for unknown screen keys"
    )]
    fn from_key(key: u8) -> Self {
        match key {
            0 => Screen::Welcome,
            1 => Screen::Status,
            2 => Screen::Help,
            _ => Screen::Welcome,
        }
    }
}

pub struct App {
    screen: Screen,
    welcome: WelcomeScreen,
    status: StatusScreen,
    help: HelpScreen,
    should_quit: bool,
    transition: Option<TransitionState>,
    transition_cache: TransitionCache,
    nav_stack: Vec<Screen>,
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
            transition: None,
            transition_cache: TransitionCache::new(),
            nav_stack: vec![Screen::Welcome],
        }
    }

    fn update(&mut self, action: Action) {
        // During transition, ignore all actions
        if self.transition.is_some() {
            return;
        }

        match action {
            Action::Quit => self.should_quit = true,
            Action::Continue => self.start_transition(Screen::Status),
            Action::Help => self.start_transition(Screen::Help),
            Action::Back => self.go_back(),
        }
    }

    fn start_transition(&mut self, to: Screen) {
        let from = self.screen;
        let state = TransitionState::new(from.key(), to.key(), &mut self.transition_cache, false);
        self.transition = Some(state);
        // Don't change self.screen yet — that happens when transition completes
    }

    fn go_back(&mut self) {
        if self.nav_stack.len() <= 1 {
            return;
        }
        let from = self.screen;
        self.nav_stack.pop(); // remove current
        let to = *self.nav_stack.last().unwrap();
        let state = TransitionState::new(from.key(), to.key(), &mut self.transition_cache, true);
        self.transition = Some(state);
    }

    fn view(&mut self, frame: &mut Frame) {
        if let Some(ts) = self.transition.take() {
            let raw_progress = ts.progress();
            let eased = Interpolation::CubicInOut.alpha(raw_progress);

            // Determine which screen to show foreground for
            let show_to = if ts.reverse {
                raw_progress > 0.5
            } else {
                raw_progress >= 0.5
            };

            // Render transition gradient
            let area = frame.area();
            let p = crate::ui::theme::CHARM;
            #[allow(clippy::cast_lossless, reason = "eased is f32 from tachyonfx, offset needs f64")]
            let offset = if ts.reverse {
                // Reverse: offset decreases back to zero
                (
                    ts.params.center_offset.0 * (1.0 - eased as f64),
                    ts.params.center_offset.1 * (1.0 - eased as f64),
                )
            } else {
                (
                    ts.params.center_offset.0 * eased as f64,
                    ts.params.center_offset.1 * eased as f64,
                )
            };
            crate::ui::gradient::render_transition_gradient(
                frame.buffer_mut(),
                area,
                p,
                offset,
                ts.params.edge_delta,
                ts.params.brightness_dip,
                eased,
            );

            // Render foreground of appropriate screen
            if show_to {
                let to_screen = Screen::from_key(ts.to);
                self.view_screen_foreground(to_screen, frame);
            } else {
                self.view_screen_foreground(self.screen, frame);
            }

            // Check completion — reconstitute transition only if not done
            if ts.is_done() {
                let to_screen = Screen::from_key(ts.to);
                self.screen = to_screen;
                if !ts.reverse {
                    self.nav_stack.push(to_screen);
                }
                // Invalidate the target screen's gradient cache
                self.invalidate_screen_cache(to_screen);
                self.transition = None;
            } else {
                self.transition = Some(ts);
            }
        } else {
            match self.screen {
                Screen::Welcome => self.welcome.view(frame),
                Screen::Status => self.status.view(frame),
                Screen::Help => self.help.view(frame),
            }
        }
    }

    fn view_screen_foreground(&mut self, screen: Screen, frame: &mut Frame) {
        match screen {
            Screen::Welcome => self.welcome.view_foreground(frame),
            Screen::Status => self.status.view_foreground(frame),
            Screen::Help => self.help.view_foreground(frame),
        }
    }

    fn invalidate_screen_cache(&mut self, screen: Screen) {
        match screen {
            Screen::Welcome => self.welcome.invalidate_cache(),
            Screen::Status => self.status.invalidate_cache(),
            Screen::Help => self.help.invalidate_cache(),
        }
    }

    fn handle_key(&mut self, code: KeyCode) -> Option<Action> {
        if self.transition.is_some() {
            return None;
        }
        match self.screen {
            Screen::Welcome => self.welcome.handle_key(code),
            Screen::Status => self.status_handle_key(code),
            Screen::Help => self.help.handle_key(code),
        }
    }

    fn status_handle_key(&mut self, code: KeyCode) -> Option<Action> {
        match code {
            KeyCode::Char('j') | KeyCode::Down => {
                self.status.scroll_down();
                None
            }
            KeyCode::Char('k') | KeyCode::Up => {
                self.status.scroll_up();
                None
            }
            _ => self.status.handle_key(code),
        }
    }

    fn handle_mouse(&mut self, mouse: MouseEvent) -> Option<Action> {
        if self.transition.is_some() {
            return None;
        }
        match mouse.kind {
            MouseEventKind::Down(_)
                | MouseEventKind::Up(_)
                | MouseEventKind::Moved
                | MouseEventKind::Drag(..)
                if matches!(self.screen, Screen::Welcome) =>
            {
                self.welcome.handle_mouse(mouse)
            }
            MouseEventKind::ScrollDown if matches!(self.screen, Screen::Status) => {
                self.status.scroll_down();
                None
            }
            MouseEventKind::ScrollUp if matches!(self.screen, Screen::Status) => {
                self.status.scroll_up();
                None
            }
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
        let anim_tick = tokio::time::interval(std::time::Duration::from_millis(33)); // ~30fps
        tokio::pin!(refresh_interval);
        tokio::pin!(anim_tick);

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
                        Event::Mouse(mouse) => self.handle_mouse(mouse),
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

                // Animation tick (~30fps for shimmer, border, spinner, and transitions)
                _ = anim_tick.tick(), if self.transition.is_some() || matches!(self.screen, Screen::Welcome | Screen::Status) => {}
            }

            if self.should_quit {
                break;
            }
        }

        Ok(())
    }
}
