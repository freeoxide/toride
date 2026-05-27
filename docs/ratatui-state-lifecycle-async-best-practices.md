# Ratatui Best Practices: State Management, Lifecycle, and Async

## Dependencies

```toml
[package]
name = "my-tui"
version = "0.1.0"
edition = "2024"

[dependencies]
ratatui = "0.30"
crossterm = { version = "0.29", features = ["event-stream"] }
color-eyre = "0.6"
tokio = { version = "1", features = ["full"] }
tokio-util = { version = "0.7", features = ["rt"] }
futures = "0.3"
textwrap = "0.16"

# Optional: image support
ratatui-image = { version = "5", features = ["chafa-static"] }
```

## 1) State Management Model (Core Pattern)

Ratatui is render-focused and intentionally does not provide a full app framework. Treat your app as:

1. `App` state struct (domain + UI state)
2. `update()` (event/action → state mutation)
3. `draw()` (state → widgets)

```rust
struct App {
    items: Vec<String>,
    list_state: ListState,
    should_quit: bool,
    dirty: bool,
}

enum Action { Quit, MoveUp, MoveDown }

impl App {
    fn update(&mut self, action: Action) {
        match action {
            Action::Quit => self.should_quit = true,
            Action::MoveDown => self.list_state.select_next(),
            Action::MoveUp => self.list_state.select_previous(),
        }
        self.dirty = true;
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
- Set `dirty = true` in `update()` so the event loop knows to redraw.

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

Use `EventStream` from crossterm (requires `event-stream` feature) with a background task channel.

```rust
use crossterm::event::{Event, EventStream, KeyCode};
use futures::StreamExt;
use tokio::{select, sync::mpsc};

async fn run(mut app: App, mut terminal: Terminal<impl Backend>) -> Result<()> {
    let mut events = EventStream::new();
    let (tx, mut rx) = mpsc::channel::<AppEvent>(32);

    loop {
        if app.dirty {
            terminal.draw(|f| app.draw(f))?;
            app.dirty = false;
        }

        select! {
            Some(Ok(event)) = events.next() => {
                if let Some(action) = map_event_to_action(&app, event) {
                    app.update(action);
                }
            }
            Some(event) = rx.recv() => {
                app.handle_event(event);
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
3. Background tasks send results back through an `mpsc::Receiver` in the same `select!`.
4. `terminal.draw(|f| app.draw(f))` renders only when dirty.

## 4) Background Tasks

```rust
use tokio::{select, sync::mpsc};
use tokio_util::sync::CancellationToken;

enum AppEvent { FetchDone(Result<String, String>) }

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
                result = reqwest::get(&url) => {
                    let payload = result
                        .map(|_| url)
                        .map_err(|e| e.to_string());
                    let _ = tx.send(AppEvent::FetchDone(payload)).await;
                }
                _ = cancel.cancelled() => {}
            }
        });
    }

    fn handle_event(&mut self, event: AppEvent) {
        match event {
            AppEvent::FetchDone(Ok(data)) => { /* update state */ }
            AppEvent::FetchDone(Err(e)) => self.error = Some(e),
        }
        self.dirty = true;
    }
}
```

- Never block the event loop with long synchronous operations.
- Keep mutation serialized in the main update loop via channel messages.
- Use `CancellationToken` (from `tokio-util`) so tasks shut down cleanly on quit.
- Use message passing, not shared `Arc<Mutex<_>>`, between tasks.

## 5) Image Integration

```rust
use ratatui_image::{picker::Picker, Resize, StatefulImage};
use std::thread;

// Query terminal protocol support once at startup — not per frame
let mut picker = Picker::from_query_stdio()?;

// Offload resize/encode to a background thread
let (tx, rx) = std::sync::mpsc::channel();
thread::spawn(move || {
    let dyn_img = image::open("photo.png").unwrap();
    let protocol = picker.new_protocol(dyn_img, area.into(), Resize::Fit(None));
    tx.send(protocol).unwrap();
});

// In the event loop, receive when ready
if let Ok(protocol) = rx.try_recv() {
    app.image_state = Some(protocol);
}

// In draw(), use StatefulImage to avoid re-encoding on redraws
if let Some(ref mut img) = app.image_state {
    frame.render_stateful_widget(StatefulImage::default(), image_area, img);
}
```

- Add `ratatui-image = { version = "5", features = ["chafa-static"] }` for portable binaries.
- Query the terminal protocol once; reusing `Picker` across frames is safe.
- Always offload image loading and encoding to a thread — never in `draw()`.

## 6) Error Handling

```rust
use color_eyre::{eyre::Result, eyre::WrapErr};

fn load_config(path: &Path) -> Result<Config> {
    let text = std::fs::read_to_string(path)
        .wrap_err_with(|| format!("Failed to read config at {}", path.display()))?;
    toml::from_str(&text).wrap_err("Failed to parse config")
}
```

- Use `color-eyre` for rich error context; install it first in `main()`.
- Convert task failures into app events (see Section 4) so the UI stays alive.
- Never leave the terminal in raw/alternate mode after an error.

## 7) Text Wrapping

```rust
use textwrap::wrap;
use ratatui::text::Line;

let wrapped: Vec<Line> = wrap(&long_text, area.width as usize)
    .into_iter()
    .map(|cow| Line::from(cow.into_owned()))
    .collect();
frame.render_widget(Paragraph::new(wrapped), area);
```

Precompute wrapped lines in `update()` when the content changes, not inside `draw()`.

## 8) Release Optimization

```toml
[profile.release]
lto = true
codegen-units = 1
panic = "abort"
strip = true
opt-level = "z"  # optimize for binary size
```

## Pre-Ship Checklist

- [ ] `cargo fmt`
- [ ] `cargo clippy --all-features` clean
- [ ] No `unwrap()` outside tests
- [ ] `color_eyre::install()` is first call in `main()`
- [ ] Panic hook restores terminal
- [ ] All spawned tasks use `CancellationToken` and are joined on quit
- [ ] `cargo build --release` with the release profile above succeeds
- [ ] Test on target terminal(s)

## Primary Sources

- Ratatui Concepts: <https://ratatui.rs/concepts/>
- Event Handling Concepts: <https://ratatui.rs/concepts/event-handling/>
- Raw Mode: <https://ratatui.rs/concepts/backends/raw-mode/>
- Async Counter Tutorial: <https://ratatui.rs/tutorials/counter-async-app/>
- Async Event Stream: <https://ratatui.rs/tutorials/counter-async-app/async-event-stream/>
- Full Async Events: <https://ratatui.rs/tutorials/counter-async-app/full-async-events/>
- Full Async Actions: <https://ratatui.rs/tutorials/counter-async-app/full-async-actions/>
- ratatui-image crate: <https://docs.rs/ratatui-image/latest/ratatui_image/>
- Ratatui crate docs: <https://docs.rs/ratatui/latest/ratatui/>
- Widgets module (`Widget` / `StatefulWidget`): <https://docs.rs/ratatui/latest/ratatui/widgets/>
