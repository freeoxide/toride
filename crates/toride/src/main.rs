use color_eyre::eyre::{Result, WrapErr};
use crossterm::{
    event::{DisableMouseCapture, EnableMouseCapture},
    execute, terminal,
};
use std::io::stdout;
use tracing_subscriber::EnvFilter;

use toride::app::App;

/// Resolve the tracing log file path.
///
/// Order: `$TORIDE_LOG_FILE`, else the OS cache dir (`~/Library/Caches/toride`
/// on macOS, `~/.cache/toride` on Linux). Returns `None` only if neither the
/// env var nor a cache dir is available.
fn log_file_path() -> Option<std::path::PathBuf> {
    if let Ok(p) = std::env::var("TORIDE_LOG_FILE") {
        return Some(std::path::PathBuf::from(p));
    }
    dirs::cache_dir().map(|d| d.join("toride").join("toride.log"))
}

fn main() -> Result<()> {
    // Route tracing to a LOG FILE, never stderr. The TUI renders into the
    // alternate screen on stdout; any stderr write (collector warnings when a
    // backend binary is absent on macOS, SSH write errors, panics) would be
    // sprayed over the live display and make the app unreadable. The guard is
    // held for the whole process so the non-blocking appender flushes on exit.
    // Default level `warn` (failures); override with `RUST_LOG`.
    #[expect(
        clippy::single_match_else,
        reason = "both arms perform real tracing-subscriber setup; an if/else over the let-binding reads worse"
    )]
    let _log_guard = match log_file_path() {
        Some(path) => {
            let parent = path.parent().unwrap_or(std::path::Path::new("."));
            let _ = std::fs::create_dir_all(parent);
            let file_name = path.file_name().map_or_else(
                || std::ffi::OsString::from("toride.log"),
                std::ffi::OsStr::to_owned,
            );
            let appender = tracing_appender::rolling::never(parent, file_name);
            let (writer, guard) = tracing_appender::non_blocking(appender);
            tracing_subscriber::fmt()
                .with_writer(writer)
                .with_target(false)
                .with_ansi(false)
                .with_env_filter(
                    EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn")),
                )
                .init();
            // Logged to the file (not the TUI) so the path is discoverable.
            tracing::info!("toride log file: {}", path.display());
            Some(guard)
        }
        None => {
            // No cache dir / env override — fall back to stderr (rare). This can
            // still corrupt the TUI, but only when there's nowhere else to write.
            tracing_subscriber::fmt()
                .with_writer(std::io::stderr)
                .with_target(false)
                .with_ansi(false)
                .with_env_filter(
                    EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn")),
                )
                .init();
            None
        }
    };

    color_eyre::install()?;

    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        let _ = terminal::disable_raw_mode();
        let _ = execute!(
            stdout(),
            terminal::LeaveAlternateScreen,
            DisableMouseCapture
        );
        original_hook(panic_info);
    }));

    terminal::enable_raw_mode()
        .wrap_err("Failed to enable raw mode — are you running in a TTY?")?;
    execute!(stdout(), terminal::EnterAlternateScreen, EnableMouseCapture)
        .wrap_err("Failed to enter alternate screen")?;

    let backend = ratatui::backend::CrosstermBackend::new(stdout());
    let terminal = ratatui::Terminal::new(backend).wrap_err("Failed to create terminal")?;

    let result = tokio::runtime::Runtime::new()
        .wrap_err("Failed to create tokio runtime")?
        .block_on(App::new().run(terminal));

    let _ = terminal::disable_raw_mode();
    let _ = execute!(
        stdout(),
        terminal::LeaveAlternateScreen,
        DisableMouseCapture
    );

    result
}
