# Ratatui Best Practices: Focus, Keyboard Shortcuts, Vim Actions, Layout, and Flex

## Dependencies

```toml
[package]
name = "my-tui"
version = "0.1.0"
edition = "2024"

[dependencies]
ratatui = "0.30"
crossterm = "0.29"
color-eyre = "0.6"
textwrap = "0.16"
```

## 1) Focus Model in Ratatui

Ratatui has no built-in focus system. Model focus explicitly in app state.

```rust
#[derive(Copy, Clone, PartialEq)]
enum Pane { Sidebar, Main, Footer }

struct App {
    focused_pane: Pane,
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

#[derive(Copy, Clone, PartialEq)]
enum Mode { Normal, Insert, Visual, Command }

fn map_key_to_action(mode: Mode, pane: Pane, key: KeyCode) -> Option<Action> {
    match (mode, key) {
        (Mode::Normal, KeyCode::Char('q')) => Some(Action::Quit),
        (Mode::Normal, KeyCode::Char('i')) => Some(Action::EnterInsert),
        (Mode::Normal, KeyCode::Char('j') | KeyCode::Down) => Some(Action::MoveDown),
        (Mode::Normal, KeyCode::Char('k') | KeyCode::Up) => Some(Action::MoveUp),
        (Mode::Normal, KeyCode::Tab) => Some(Action::FocusNext),
        (Mode::Normal, KeyCode::Enter) => Some(Action::Select),
        (Mode::Insert, KeyCode::Esc) => Some(Action::Escape),
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
    let [_, content, _] = Layout::horizontal([
        Constraint::Fill(1),
        Constraint::Length(60),
        Constraint::Fill(1),
    ]).flex(Flex::Center).areas(body);
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
                let next = self.main_state.selected().map(|i| i + 1).unwrap_or(0);
                self.main_state.select(Some(next.min(self.items.len() - 1)));
            }
            _ => {}
        }
    }
}

// In draw(), pass state by mutable ref
fn draw(app: &mut App, frame: &mut Frame) {
    let list = List::new(app.sidebar_items.clone())
        .highlight_style(Style::new().bold().cyan());
    frame.render_stateful_widget(list, sidebar_area, &mut app.sidebar_state);
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

// Avoid
Style::default().fg(Color::White)
Style::new().add_modifier(Modifier::BOLD)
```

Color palette:
- Primary: `.cyan()`, `.green()`
- Error: `.red()`
- Muted: `.dim()`, `.dark_gray()`
- Accent: `.magenta()`

## 7) Status Bar

```rust
let mode_label = match app.mode {
    Mode::Normal => " NORMAL ".bold().on_cyan(),
    Mode::Insert => " INSERT ".bold().on_green(),
    Mode::Visual => " VISUAL ".bold().on_magenta(),
    Mode::Command => " COMMAND ".bold().on_yellow(),
};

let status = Line::from(vec![
    mode_label.into(),
    format!(" {} items ", app.items.len()).dim().into(),
]);
frame.render_widget(Paragraph::new(status), footer_area);
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
```

Structure:
- `app.rs` — `App` state, `update()` logic
- `action.rs` — `Action` enum (place `Action` and `Mode` here)
- `event.rs` — event handling, `map_key_to_action`
- `ui.rs` — all rendering
- `tui.rs` — terminal setup/teardown

## 12) Testing Targets

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
