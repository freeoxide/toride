# Ratatui Best Practices

Reference notes for the `crates/toride` TUI (ratatui 0.30 / ratatui-interact).
Merged 2026-10-10 from the former focus-keyboard-vim-layout and
state-lifecycle-async notes; git history holds the originals.

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
textwrap = "0.16"
tokio = { version = "1", features = ["full"] }
tokio-util = "0.7"
futures = "0.3"
image = "0.25"
reqwest = { version = "1", features = ["json"] }
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }

# Optional: image support
ratatui-image = { version = "5", features = ["chafa-static"] }
```

## Part I — Focus, Keyboard Shortcuts, Vim Actions, Layout, and Flex

## 1) Focus Model in Ratatui

Ratatui has no built-in focus system. Model focus explicitly in app state.

```rust
#[derive(Copy, Clone, PartialEq)]
enum Pane { Sidebar, Main, Footer }

#[derive(Default, Copy, Clone, PartialEq)]
enum Mode {
    #[default]
    Normal,
    Insert,
    Visual,
    Command,
}

struct App {
    focused_pane: Pane,
    mode: Mode,
    should_quit: bool,
    sidebar_items: Vec<String>,
    sidebar_state: ListState,
    main_state: TableState,
}
```

- Route key events based on `focused_pane` + `mode`.
- Only mutate the active widget's state object on navigation keys.
- Keep per-widget state (`ListState`, `TableState`) in `App`, not inside `draw()`.

## 2) Keyboard Shortcuts Architecture

Use a typed action enum as a semantic layer between raw keys and state mutations.

```rust
#[derive(Copy, Clone)]
enum Action {
    Quit,
    MoveUp,
    MoveDown,
    FocusNext,
    Select,
    EnterInsert,
    Escape,
}

fn map_key_to_action(mode: Mode, pane: Pane, key: KeyCode) -> Option<Action> {
    match (mode, pane, key) {
        (Mode::Normal, _, KeyCode::Char('q')) => Some(Action::Quit),
        (Mode::Normal, _, KeyCode::Char('i')) => Some(Action::EnterInsert),
        (Mode::Normal, _, KeyCode::Char('j') | KeyCode::Down) => Some(Action::MoveDown),
        (Mode::Normal, _, KeyCode::Char('k') | KeyCode::Up) => Some(Action::MoveUp),
        (Mode::Normal, _, KeyCode::Tab) => Some(Action::FocusNext),
        // Context-sensitive: Enter only selects when focus is on Sidebar
        (Mode::Normal, Pane::Sidebar, KeyCode::Enter) => Some(Action::Select),
        (Mode::Insert, _, KeyCode::Esc) => Some(Action::Escape),
        _ => None,
    }
}
```

Recommended flow:
1. `Event::Key(KeyEvent)`
2. `map_key_to_action(app.mode, app.focused_pane, key.code)`
3. `app.update(action)`
4. Rerender

## 3) Vim-Style Modal Input

```rust
impl App {
    fn update(&mut self, action: Action) {
        match (self.mode, action) {
            (Mode::Normal, Action::EnterInsert) => self.mode = Mode::Insert,
            (Mode::Insert, Action::Escape) => self.mode = Mode::Normal,
            (Mode::Normal, Action::MoveDown) => self.move_down(),
            (Mode::Normal, Action::MoveUp) => self.move_up(),
            (Mode::Normal, Action::Quit) => self.should_quit = true,
            _ => {}
        }
    }
}
```

- Store mode in `App`; apply mode-specific keymaps in `map_key_to_action`.
- Display mode indicator in status bar (see Section 7).
- Keep mode transitions atomic — update mode, cursor, focus, and selection together.

Anti-pattern: large nested `match` trees without a keymap abstraction.

## 4) Layout and Flex Patterns

```rust
use ratatui::layout::{Constraint, Flex, Layout};

fn draw(app: &mut App, frame: &mut Frame) {
    let [header, body, footer] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Fill(1),
        Constraint::Length(1),
    ]).areas(frame.area());

    let [sidebar, main] = Layout::horizontal([
        Constraint::Length(24),
        Constraint::Fill(1),
    ]).areas(body);

    // Center a fixed-width element using Flex
    let [_, _content, _] = Layout::horizontal([
        Constraint::Fill(1),
        Constraint::Length(60),
        Constraint::Fill(1),
    ]).flex(Flex::Center).areas(body);

    app.draw_sidebar(frame, sidebar);
    app.draw_main(frame, main);
    app.draw_status(frame, footer);
}
```

- Use `Flex` (`Start`, `Center`, `End`, `SpaceBetween`, `SpaceAround`, `SpaceEvenly`) to control excess space behavior.
- Keep constraints stable and data-driven for predictable resizing.

## 5) Stateful Widgets as Focus Targets

```rust
impl App {
    fn move_down(&mut self) {
        match self.focused_pane {
            Pane::Sidebar => self.sidebar_state.select_next(),
            Pane::Main => {
                let i = self.main_state.selected().map(|i| i + 1).unwrap_or(0);
                // saturating_sub prevents usize underflow panic when list is empty
                self.main_state.select(Some(i.min(self.sidebar_items.len().saturating_sub(1))));
            }
            _ => {}
        }
    }

    fn move_up(&mut self) {
        match self.focused_pane {
            Pane::Sidebar => self.sidebar_state.select_previous(),
            Pane::Main => {
                let i = self.main_state.selected().unwrap_or(0).saturating_sub(1);
                self.main_state.select(Some(i));
            }
            _ => {}
        }
    }

    fn draw_sidebar(&mut self, frame: &mut Frame, area: Rect) {
        // Avoid cloning large item lists in draw(). For large datasets:
        // let list = List::new(self.sidebar_items.iter().map(|s| s.as_str()));
        let list = List::new(self.sidebar_items.clone())
            .highlight_style(Style::new().bold().cyan());
        frame.render_stateful_widget(list, area, &mut self.sidebar_state);
    }
}
```

- Move selection/offset in update logic, not in rendering code.
- `frame.render_stateful_widget(widget, area, &mut state)` — always pass state as `&mut`.

## 6) Styling with the Stylize Trait

```rust
use ratatui::style::Stylize;

// Preferred
"NORMAL".bold().on_cyan()
"item text".dim()
"error".red().bold()
"selected".cyan()
"warning".yellow()

// Avoid
Style::default().fg(Color::White)
Style::new().add_modifier(Modifier::BOLD)
```

Color palette:
- Primary: `.cyan()`, `.green()`
- Error: `.red()`
- Warning: `.yellow()` (sparingly)
- Muted: `.dim()`, `.dark_gray()`
- Accent: `.magenta()`

## 7) Status Bar

```rust
fn draw_status(&self, frame: &mut Frame, area: Rect) {
    let mode_label = match self.mode {
        Mode::Normal  => " NORMAL ".bold().on_cyan(),
        Mode::Insert  => " INSERT ".bold().on_green(),
        Mode::Visual  => " VISUAL ".bold().on_magenta(),
        Mode::Command => " COMMAND ".bold().on_yellow(),
    };

    let status = Line::from(vec![
        mode_label.into(),
        format!(" {} items ", self.sidebar_items.len()).dim().into(),
    ]);
    frame.render_widget(Paragraph::new(status), area);
}
```

## 8) Key Bindings Display

```rust
let help = Line::from(vec![
    " q ".bold().cyan(),
    "quit ".dim(),
    " ↑↓ ".bold().cyan(),
    "navigate ".dim(),
    " Tab ".bold().cyan(),
    "focus ".dim(),
]);
frame.render_widget(Paragraph::new(help), footer_area);
```

## 9) Text Wrapping

```rust
use textwrap::wrap;
use ratatui::text::Line;

let wrapped: Vec<Line> = wrap(&long_text, area.width as usize)
    .into_iter()
    .map(|cow| Line::from(cow.into_owned()))
    .collect();
frame.render_widget(Paragraph::new(wrapped), area);
```

## 10) Centered Popup

```rust
fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    let [_, center, _] = Layout::vertical([
        Constraint::Percentage((100 - percent_y) / 2),
        Constraint::Percentage(percent_y),
        Constraint::Percentage((100 - percent_y) / 2),
    ]).areas(area);

    let [_, center, _] = Layout::horizontal([
        Constraint::Percentage((100 - percent_x) / 2),
        Constraint::Percentage(percent_x),
        Constraint::Percentage((100 - percent_x) / 2),
    ]).areas(center);

    center
}
```

## 11) Template Guidance

For apps with focus, modes, and multiple panes, use the `component-app` template:

```bash
cp -r ~/.agents/skills/ratatui-tui-blacktop/assets/templates/component-app/* .
# or with pedronauck skill:
cp -r ~/.claude/skills/ratatui-tui-pedronauck/assets/templates/component-app/* .
```

Structure:
- `app.rs` — `App` state, `update()` logic
- `action.rs` — `Action` enum (place `Action` and `Mode` here)
- `event.rs` — event handling, `map_key_to_action`
- `ui.rs` — all rendering
- `tui.rs` — terminal setup/teardown

### Modern Terminal Init (ratatui 0.29+)

Prefer the ratatui convenience helpers over manual crossterm calls:

```rust
#[tokio::main]
async fn main() -> color_eyre::Result<()> {
    color_eyre::install()?;
    let mut terminal = ratatui::init();       // sets raw mode + alternate screen
    let result = run(&mut terminal).await;
    ratatui::restore();                        // always restores, even on panic
    result
}
```

`ratatui::init()` / `ratatui::restore()` are equivalent to the full crossterm setup/teardown block but require no manual panic hook. Use the manual crossterm approach only when you need fine-grained control over the hook.

### Logging in TUI Apps

`println!` and `eprintln!` are broken while in alternate screen / raw mode — output is invisible or corrupts the display. Use `tracing` with a file appender instead:

```rust
use tracing_subscriber::{fmt, EnvFilter};

fn init_logging() {
    let file = std::fs::File::create("/tmp/my-tui.log").unwrap();
    fmt()
        .with_writer(file)
        .with_env_filter(EnvFilter::from_default_env())
        .init();
}
// Then: tracing::debug!("pane = {:?}", app.focused_pane);
```

Anti-pattern: `println!("{:?}", state)` inside a raw-mode loop — use `tracing::debug!` or `tracing::trace!` instead.

## 12) Component Trait (Large Apps)

When multiple panes grow independently, encapsulate each behind a `Component` trait:

```rust
use crossterm::event::KeyEvent;

pub enum EventResult {
    Consumed,
    Ignored,
    Action(Action),
}

pub trait Component {
    fn handle_key(&mut self, key: KeyEvent) -> EventResult;
    fn render(&self, frame: &mut Frame, area: Rect);
    fn focus(&mut self) {}
    fn blur(&mut self) {}
}
```

Usage in `App::update`:

```rust
let result = match self.focused_pane {
    Pane::Sidebar => self.sidebar.handle_key(key),
    Pane::Main    => self.main.handle_key(key),
    Pane::Footer  => EventResult::Ignored,
};
if let EventResult::Action(action) = result {
    self.update(action);
}
```

- Each component owns its `ListState`/`TableState` and focus flag.
- Parent routes keys; components return `Action` for app-level effects.
- Prefer this over a single giant `match (pane, mode, key)` once panes have 5+ bindings each.

## 13) Testing Targets

- Focus routing across panes/widgets.
- Mode switching correctness (Normal/Insert/etc.).
- Shortcut conflicts and precedence.
- Layout behavior under terminal resize.
- Stateful widget selection persistence after redraw.

## Primary Sources

- Layout Concepts: <https://ratatui.rs/concepts/layout/>
- Flex enum docs: <https://docs.rs/ratatui/latest/ratatui/layout/enum.Flex.html>
- Layout examples: <https://ratatui.rs/examples/layout/>
- Flex example: <https://ratatui.rs/examples/layout/flex/>
- Event handling concepts: <https://ratatui.rs/concepts/event-handling/>
- Widgets and StatefulWidget docs: <https://docs.rs/ratatui/latest/ratatui/widgets/>
- `StatefulWidget` trait: <https://docs.rs/ratatui/latest/ratatui/widgets/trait.StatefulWidget.html>
- `ListState`: <https://docs.rs/ratatui/latest/ratatui/widgets/struct.ListState.html>
- `TableState`: <https://docs.rs/ratatui/latest/ratatui/widgets/struct.TableState.html>

## Part II — State Management, Lifecycle, and Async

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
    error: Option<String>,
}

impl Default for App {
    fn default() -> Self {
        Self {
            dirty: true,  // force first render immediately
            items: Vec::new(),
            list_state: ListState::default(),
            should_quit: false,
            error: None,
        }
    }
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

### Preferred: ratatui::init() / ratatui::restore() (ratatui 0.29+)

```rust
use color_eyre::eyre::Result;

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;

    let mut terminal = ratatui::init();   // raw mode + alternate screen + panic hook
    let result = run(&mut terminal).await;
    ratatui::restore();                    // always restores, even after panic

    result
}
```

`ratatui::init()` handles the panic hook internally. This is the recommended approach for new apps.

### Manual: crossterm setup/teardown

Use this when you need fine-grained panic hook control (e.g., logging the panic info before restoring):

```rust
use color_eyre::eyre::Result;
use crossterm::{execute, terminal};

#[tokio::main]
async fn main() -> Result<()> {
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

    let result = run().await;

    terminal::disable_raw_mode()?;
    execute!(std::io::stdout(), terminal::LeaveAlternateScreen)?;

    result
}
```

- Always call `color_eyre::install()?` first in `main()`.
- Always restore terminal on both normal exit and panic.

## 3) Async Event Architecture

Use `EventStream` from crossterm (requires `event-stream` feature) with a background task channel.

```rust
use crossterm::event::{Event, EventStream, KeyCode};
use futures::StreamExt;
use ratatui::{Terminal, backend::Backend};
use tokio::{select, sync::mpsc};

async fn run(terminal: &mut Terminal<impl Backend>) -> Result<()> {
    let mut app = App::default();
    let mut events = EventStream::new();
    // Use mpsc::unbounded_channel() if back-pressure is not a concern
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
4. `terminal.draw(|f| app.draw(f))` renders only when `dirty`.

### Tick Timer (animations / polling)

Add a periodic tick arm to `select!` for animations or timed refreshes:

```rust
use tokio::time::{interval, Duration};

let mut tick = interval(Duration::from_millis(250));

select! {
    Some(Ok(event)) = events.next() => { /* key/mouse/resize */ }
    _ = tick.tick() => {
        app.on_tick();  // advance animation frames, poll external state
        app.dirty = true;
    }
    Some(event) = rx.recv() => { app.handle_event(event); }
}
```

### Debouncing Input (search-as-you-type)

```rust
use tokio::time::{Instant, Duration};

struct App {
    search_query: String,
    last_input: Option<Instant>,  // None until first keystroke
    pending_search: bool,
    // ...
}

impl App {
    fn on_search_key(&mut self, c: char) {
        self.search_query.push(c);
        self.last_input = Some(Instant::now());
        self.pending_search = true;
    }

    fn on_tick(&mut self, tx: &mpsc::Sender<AppEvent>) {
        if self.pending_search {
            if self.last_input.map_or(false, |t| t.elapsed() > Duration::from_millis(300)) {
                self.pending_search = false;
                self.spawn_search(tx.clone());
            }
        }
    }
}
```

### EventHandler Module (component-app scale)

For larger apps, extract event dispatching into its own struct so `run()` stays clean:

```rust
// event.rs
use crossterm::event::{Event, EventStream, KeyEvent};
use futures::StreamExt;
use tokio::{select, sync::mpsc, time::{sleep, Duration}};

pub enum AppEvent {
    Key(KeyEvent),
    Resize(u16, u16),
    Tick,
    Background(BackgroundResult),
}

pub struct EventHandler {
    events: EventStream,
    tick_rate: Duration,
    rx: mpsc::Receiver<BackgroundResult>,
}

impl EventHandler {
    pub async fn next(&mut self) -> AppEvent {
        let tick = sleep(self.tick_rate);
        select! {
            Some(Ok(Event::Key(k))) = self.events.next() => AppEvent::Key(k),
            Some(Ok(Event::Resize(w, h))) = self.events.next() => AppEvent::Resize(w, h),
            Some(r) = self.rx.recv() => AppEvent::Background(r),
            _ = tick => AppEvent::Tick,
        }
    }
}
```

## 4) Background Tasks

```rust
use tokio::{select, sync::mpsc};
use tokio_util::sync::CancellationToken;

enum AppEvent { FetchDone(Result<String, String>) }

impl App {
    fn spawn_fetch(&self, tx: mpsc::Sender<AppEvent>, cancel: CancellationToken, url: String) {
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
            AppEvent::FetchDone(Ok(data)) => self.items.push(data),
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
use image::open as open_image;
use ratatui_image::{picker::Picker, protocol::StatefulProtocol, Resize, StatefulImage};
use std::thread;

struct App {
    picker: Picker,
    image_state: Option<StatefulProtocol>,
    // ...
}
```

### Picker initialization with fallback

```rust
use ratatui_image::picker::{Picker, ProtocolType};

fn make_picker() -> Picker {
    Picker::from_query_stdio().unwrap_or_else(|_| {
        Picker::new(ProtocolType::Halfblocks)  // safe fallback for all terminals
    })
}
```

### Background thread loading (std::thread)

```rust
// Capture area before spawning — Rect is Copy
let image_area = Rect::new(0, 0, 40, 20);
let picker = app.picker.clone();
let (tx, rx) = std::sync::mpsc::channel::<StatefulProtocol>();
thread::spawn(move || {
    let dyn_img = open_image("photo.png").unwrap();
    let protocol = picker.new_protocol(dyn_img, image_area.into(), Resize::Fit(None));
    tx.send(protocol).unwrap();
});

// In the event loop, receive when ready
if let Ok(protocol) = rx.try_recv() {
    app.image_state = Some(protocol);
    app.dirty = true;
}

// In draw(), use StatefulImage to avoid re-encoding on redraws
if let Some(ref mut img) = app.image_state {
    frame.render_stateful_widget(StatefulImage::default(), image_area, img);
}
```

### Async loading (tokio context — preferred in async apps)

Use `spawn_blocking` instead of `std::thread::spawn` when inside a tokio runtime — it integrates with tokio's task scheduler and thread pool:

```rust
use tokio::task::spawn_blocking;

async fn load_image(
    picker: Picker,
    area: Rect,
    tx: mpsc::Sender<AppEvent>,
) {
    let result = spawn_blocking(move || {
        let dyn_img = open_image("photo.png")?;
        Ok::<_, image::ImageError>(picker.new_protocol(dyn_img, area.into(), Resize::Fit(None)))
    }).await;

    match result {
        Ok(Ok(protocol)) => { tx.send(AppEvent::ImageLoaded(protocol)).await.ok(); }
        Ok(Err(e)) => { tx.send(AppEvent::Error(e.to_string())).await.ok(); }
        Err(e) => { tx.send(AppEvent::Error(e.to_string())).await.ok(); }
    }
}
```

### Re-encode on terminal resize

```rust
fn handle_resize(&mut self, new_area: Rect) {
    if self.original_image_path.is_some() {
        self.image_state = None;  // invalidate; reload with new area
        self.dirty = true;
    }
}
```

- `Rect` is `Copy` — always capture it by value before spawning.
- Query the terminal protocol once at startup; reuse `Picker` across the app lifetime.
- Store `StatefulProtocol` (not `DynamicImage`) to avoid re-encoding on redraws.
- Use `chafa-static` feature for portable binaries that don't require chafa to be installed.
- Re-encode when the terminal resizes — the existing protocol encodes for a fixed cell size.

## 6) Logging in TUI Apps

`println!` and `eprintln!` are broken while in raw mode / alternate screen — output is invisible or corrupts the display. Use `tracing` with a file writer:

```rust
use tracing_subscriber::{fmt, EnvFilter};

fn init_logging() -> color_eyre::Result<()> {
    let log_file = std::fs::File::create("/tmp/my-tui.log")?;
    fmt()
        .with_writer(log_file)
        .with_env_filter(EnvFilter::from_default_env())
        .init();
    Ok(())
}

// Call before ratatui::init():
// init_logging()?;
// tracing::debug!("app started, {} items loaded", items.len());
```

Anti-pattern: `println!("{:?}", state)` inside a running TUI loop — crashes output or shows garbage on exit.

## 7) Error Handling

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

## 8) Text Wrapping

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

## 9) Release Optimization

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
- [ ] `ratatui::restore()` (or manual teardown) called on all exit paths including panic
- [ ] `App::default()` sets `dirty: true` so first frame renders immediately
- [ ] All spawned tasks use `CancellationToken` and are joined on quit
- [ ] Logging uses `tracing` to a file, never `println!` in raw mode
- [ ] Image picker uses fallback (`Halfblocks`) when `from_query_stdio()` fails
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
