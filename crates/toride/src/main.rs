use color_eyre::eyre::{Result, WrapErr};
use crossterm::{execute, terminal};
use std::io::stdout;

use toride::app::App;

fn main() -> Result<()> {
    color_eyre::install()?;

    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        let _ = terminal::disable_raw_mode();
        let _ = execute!(stdout(), terminal::LeaveAlternateScreen);
        original_hook(panic_info);
    }));

    terminal::enable_raw_mode()
        .wrap_err("Failed to enable raw mode — are you running in a TTY?")?;
    execute!(stdout(), terminal::EnterAlternateScreen)
        .wrap_err("Failed to enter alternate screen")?;

    let backend = ratatui::backend::CrosstermBackend::new(stdout());
    let terminal = ratatui::Terminal::new(backend).wrap_err("Failed to create terminal")?;

    let result = tokio::runtime::Runtime::new()
        .wrap_err("Failed to create tokio runtime")?
        .block_on(App::new().run(terminal));

    let _ = terminal::disable_raw_mode();
    let _ = execute!(stdout(), terminal::LeaveAlternateScreen);

    result
}
