# Ratatui Best Practices: State Management, Lifecycle, and Async

## Dependencies

```toml
[dependencies]
ratatui = "0.30"
crossterm = { version = "0.29", features = ["event-stream"] }
color-eyre = "0.6"
tokio = { version = "1", features = ["full"] }
futures = "0.3"
```

## 1) State Management Model (Core Pattern)

Ratatui is render-focused and intentionally does not provide a full app framework. Treat your app as:

1. `App` state struct (domain + UI state)
2. `update()` (event/action → state mutation)
3. `draw()` (state → widgets)

```rust
struct App {
    items: Vec<String>,
    list_state: ListState,   // widget state
    should_quit: bool,
}

enum Action { Quit, MoveUp, MoveDown }

impl App {
    fn update(&mut self, action: Action) {
        match action {
            Action::Quit => self.should_quit = true,
            Action::MoveDown => self.list_state.select_next(),
            Action::MoveUp => self.list_state.select_previous(),
        }
    }

    fn draw(&mut self, frame: &mut Frame) {
        let list = List::new(self.items.clone())
            .highlight_style(Style::new().bold().cyan());
        frame.render_stateful_widget(list, frame.area(), &mut self.list_state);
    }
}
```

- Keep widget state (`ListState`, `TableState`, `ScrollbarState`) inside `App`, not inside `draw()`.
- Keep domain state and widget state as separate fields.
- Do not mutate state while building widget definitions.

## 2) Lifecycle and Terminal Discipline

```rust
use color_eyre::eyre::Result;
use crossterm::{execute, terminal};

fn main() -> Result<()> {
    color_eyre::install()?;

    // Restore terminal on panic
    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = terminal::disable_raw_mode();
        let _ = execute!(std::io::stdout(), terminal::LeaveAlternateScreen);
        original_hook(info);
    }));

    terminal::enable_raw_mode()?;
    execute!(std::io::stdout(), terminal::EnterAlternateScreen)?;

    let result = run();

    terminal::disable_raw_mode()?;
    execute!(std::io::stdout(), terminal::LeaveAlternateScreen)?;

    result
}
```

- Always call `color_eyre::install()?` first in `main()`.
- Always restore terminal on both normal exit and panic.
- Keep run-loop lifecycle explicit: init → event loop → graceful shutdown.

## 3) Async Event Architecture

Use `EventStream` from crossterm (requires `event-stream` feature) rather than raw `mpsc` channels.

```rust
use crossterm::event::{Event, EventStream, KeyCode, KeyEvent};
use futures::StreamExt;
use tokio::select;

async fn run(mut app: App, mut terminal: Terminal<impl Backend>) -> Result<()> {
    let mut events = EventStream::new();

    loop {
        terminal.draw(|f| app.draw(f))?;

        select! {
            Some(Ok(event)) = events.next() => {
                if let Some(action) = map_event_to_action(&app, event) {
                    app.update(action);
                }
            }
            result = app.background_task() => {
                app.handle_task_result(result);
            }
        }

        if app.should_quit { break; }
    }
    Ok(())
}
```

Recommended architecture:
1. `EventStream` yields crossterm `Event`s (keyboard, mouse, resize).
2. Map `Event` → `Action` via `map_event_to_action`.
3. `app.update(action)` mutates state.
4. `terminal.draw(|f| app.draw(f))` renders.

- Separate `Event` (external/input) from `Action` (domain intent).
- For async jobs (network/fs), spawn tasks and feed results back via channels into `select!`.
- Use cancellation tokens for long-running tasks.

## 4) Background Tasks

```rust
use tokio::{sync::mpsc, task::JoinHandle};
use tokio_util::sync::CancellationToken;

struct App {
    tx: mpsc::Sender<AppEvent>,
    cancel: CancellationToken,
}

impl App {
    fn spawn_fetch(&self, url: String) {
        let tx = self.tx.clone();
        let cancel = self.cancel.clone();
        tokio::spawn(async move {
            select! {
                result = fetch(url) => { let _ = tx.send(AppEvent::FetchDone(result)).await; }
                _ = cancel.cancelled() => {}
            }
        });
    }
}
```

- Never block the event loop with long synchronous operations.
- Keep mutation serialized in the main update loop.
- Use message passing, not shared `Arc<Mutex<_>>`, between tasks.
- Ensure spawned tasks can be shut down cleanly via cancellation tokens.

## 5) Error Handling

```rust
use color_eyre::{eyre::Result, eyre::WrapErr};

fn load_config(path: &Path) -> Result<Config> {
    let text = std::fs::read_to_string(path)
        .wrap_err_with(|| format!("Failed to read config at {}", path.display()))?;
    toml::from_str(&text).wrap_err("Failed to parse config")
}

// Convert task failures into app events so the UI stays alive
enum AppEvent {
    FetchDone(Result<Data>),
}

impl App {
    fn handle_event(&mut self, event: AppEvent) {
        match event {
            AppEvent::FetchDone(Err(e)) => self.error = Some(e.to_string()),
            AppEvent::FetchDone(Ok(data)) => self.data = data,
        }
    }
}
```

- Use `color-eyre` for rich error context; install it first in `main()`.
- Convert task failures into `AppEvent::Error` and show recoverable UI state.
- Never leave the terminal in raw/alternate mode after an error.

## 6) Performance and Rendering

```rust
struct App {
    dirty: bool,
}

// Only redraw when state changed
loop {
    if app.dirty {
        terminal.draw(|f| app.draw(f))?;
        app.dirty = false;
    }
    // ... handle events
}
```

- Keep `draw()` pure and fast; precompute expensive view-model data in `update()`, not in `draw()`.
- Use stateful widgets correctly to preserve selection/offset across frames.
- Cap render FPS and separate tick rate from render rate.
- Set `app.dirty = true` in `update()` when state actually changes.

## Pre-Ship Checklist

- [ ] `cargo fmt`
- [ ] `cargo clippy --all-features` clean
- [ ] No `unwrap()` outside tests
- [ ] `color_eyre::install()` is first call in `main()`
- [ ] Panic hook restores terminal
- [ ] `cargo build --release` succeeds
- [ ] Test on target terminal(s)

## Primary Sources

- Ratatui Concepts: <https://ratatui.rs/concepts/>
- Event Handling Concepts: <https://ratatui.rs/concepts/event-handling/>
- Raw Mode: <https://ratatui.rs/concepts/backends/raw-mode/>
- Async Counter Tutorial: <https://ratatui.rs/tutorials/counter-async-app/>
- Async Event Stream: <https://ratatui.rs/tutorials/counter-async-app/async-event-stream/>
- Full Async Events: <https://ratatui.rs/tutorials/counter-async-app/full-async-events/>
- Full Async Actions: <https://ratatui.rs/tutorials/counter-async-app/full-async-actions/>
- Ratatui crate docs: <https://docs.rs/ratatui/latest/ratatui/>
- Widgets module (`Widget` / `StatefulWidget`): <https://docs.rs/ratatui/latest/ratatui/widgets/>
