use color_eyre::eyre::{Result, WrapErr};
use crossterm::{execute, terminal};
use ratatui::{
    Terminal,
    backend::CrosstermBackend,
    crossterm::event::{self, Event},
};
use std::io::stdout;

use toride::action::Action;
use toride::ui::welcome::WelcomeScreen;

fn main() -> Result<()> {
    color_eyre::install()?;

    terminal::enable_raw_mode()
        .wrap_err("Failed to enable raw mode — are you running in a TTY?")?;
    execute!(stdout(), terminal::EnterAlternateScreen)
        .wrap_err("Failed to enter alternate screen")?;

    let backend = CrosstermBackend::new(stdout());
    let mut terminal = Terminal::new(backend).wrap_err("Failed to create terminal")?;

    let result = run(&mut terminal);

    let _ = terminal::disable_raw_mode();
    let _ = execute!(stdout(), terminal::LeaveAlternateScreen);

    result
}

fn run(terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>) -> Result<()> {
    let welcome = WelcomeScreen;

    loop {
        terminal.draw(|frame| welcome.render(frame))?;

        if let Event::Key(key) = event::read()?
            && let Some(Action::Quit) = welcome.handle_key(key.code)
        {
            break;
        }
    }

    Ok(())
}
