# Ratatui Best Practices: Focus, Keyboard Shortcuts, Vim Actions, Layout, and Flex

This document audits interaction and layout patterns using Ratatui official docs and examples.

## 1) Focus Model in Ratatui (Important)

Ratatui does not provide a built-in focus-node system like many GUI frameworks.
You should model focus explicitly in app state.

Recommended pattern:
- Add `focused_pane`, `focused_widget`, and optional `mode` fields to `App`.
- Route key events based on focus + mode.
- Keep per-widget state (`ListState`, `TableState`) in `App` and only mutate active target.

## 2) Keyboard Shortcuts Architecture

Best practices:
- Use a typed command/action enum as semantic layer (`Action::Quit`, `Action::MoveUp`, etc.).
- Parse raw keys once, then map to actions by current mode/context.
- Centralize keymap tables to avoid duplicate logic.
- Reserve global shortcuts (`q`, `Ctrl+C`) and keep others context-sensitive.

Recommended flow:
1. `Event::Key(KeyEvent)`
2. `map_key_to_action(app.mode, app.focus, key)`
3. `update(app, action)`
4. Optional rerender trigger

## 3) Vim-Style Modal Input

Ratatui is well-suited for Vim-like behavior when modeled explicitly.

Best practices:
- Store mode enum: `Normal | Insert | Visual | Command`.
- Apply mode-specific keymaps.
- Display mode indicator in status bar.
- Keep mode transitions atomic (mode + cursor/selection/focus updates together).

Anti-pattern:
- Large nested `match` trees without a keymap abstraction.

## 4) Layout and Flex Patterns

Ratatui layout is constraint-driven and supports modern `Flex` alignment.

Best practices:
- Use `Layout::{horizontal, vertical}` with clear constraints (`Length`, `Min`, `Fill`, `Percentage`, `Ratio`).
- Use `Flex` (`Start`, `Center`, `End`, `SpaceBetween`, `SpaceAround`, `SpaceEvenly`) to control excess space behavior.
- Build nested layout shells: header/body/footer, then split body into panes.
- Keep constraints stable and data-driven for predictable resizing.

## 5) Stateful Widgets as Focus Targets

Treat stateful widgets as the practical “focus particles” of a TUI:
- `List + ListState`
- `Table + TableState`
- `Scrollbar + ScrollbarState`

Best practices:
- Persist state objects across renders.
- Move selection/offset in update logic, not in rendering code.
- Couple focused widget routing with its state object mutation.

## 6) Cross-Match: “Focus Nodes/Actions/Flex” Expectations

- Focus nodes: not built-in; implement in app state.
- Keyboard action registry: not built-in framework-wide; implement action enums and mapping.
- Vim actions: first-class feasible via modal state + keymap tables.
- Flex/layout: first-class via Ratatui `Layout` + `Flex` and recipes/examples.

## 7) Testing Targets

Regression tests should cover:
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
