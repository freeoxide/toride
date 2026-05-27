# Ratatui Best Practices: State Management, Lifecycle, and Async

This is a Ratatui-focused audit based on official Ratatui docs/tutorials and docs.rs APIs.

## 1) State Management Model (Core Pattern)

Ratatui is render-focused and intentionally does not provide a full app framework. Treat your app as:

1. `App` state struct (domain + UI state)
2. `update()` (event/action -> state mutation)
3. `draw()` (state -> widgets)

Best practices:
- Keep widget state (`ListState`, `TableState`, `ScrollbarState`) inside `App`, not inside `draw()`.
- Keep domain state and widget state separate fields.
- Use small feature modules with local state + reducer/update methods.
- Do not mutate state while building widget definitions except via explicit stateful widget APIs.

## 2) Lifecycle and Terminal Discipline

Best practices:
- Enter alternate screen + raw mode on startup, and always restore terminal on exit/panic paths.
- Keep run-loop lifecycle explicit: init -> event loop -> graceful shutdown.
- Avoid rendering on every tiny event when not needed; consider render throttling.

Why:
- Raw mode changes terminal input semantics (per-key handling), so robust setup/teardown is mandatory.

## 3) Async/Event Architecture

Ratatui guidance aligns with event channels and dedicated event tasks.

Recommended architecture:
1. Event task gathers crossterm input + ticks (+ optional render interval).
2. Sends typed `Event` enum through `mpsc`.
3. Main loop receives events, maps to `Action`, updates state.
4. Render when needed (either on `Render` event or dirty flag).

Best practices:
- Use `tokio::select!` for multi-source async event streams.
- Split `Event` (external/input/time) from `Action` (domain intent).
- For async jobs (network/fs), spawn tasks and feed results back as events/actions.
- Apply cancellation tokens for long-running tasks.

## 4) Concurrency Safety Rules

- Never block the render/event loop with long synchronous operations.
- Keep mutation serialized in one place (main update loop) where possible.
- Use message passing instead of shared mutable state between tasks.
- Ensure event producers can be shut down cleanly (task handles/cancellation).

## 5) Error Handling

- Use typed app errors or unified error crates (`color-eyre` is common in official tutorials).
- Convert task failures into `Event::Error`/`Action::Error` and show recoverable UI state.
- Never leave terminal in raw/alternate mode after errors.

## 6) Performance and Scalability

- Keep `draw()` pure and fast; precompute expensive view-model data outside draw when possible.
- Use stateful widgets correctly to preserve selection/offset across frames.
- Cap render FPS and separate tick rate from render rate.
- Redraw only when necessary in async architectures.

## 7) Deep Cross-Match Against Prior GPUI-Style Guidance

- Entity-based state ownership -> Ratatui equivalent: explicit `App` struct + module-level state ownership.
- Lifecycle hooks -> Ratatui equivalent: explicit run-loop and terminal enter/exit boundaries.
- App/window async context validity checks -> Ratatui equivalent: task cancellation + channel closure checks.
- UI actions/key contexts framework -> Ratatui equivalent: user-defined `Event`/`Action` layering.

Conclusion:
- The same architectural goals apply, but Ratatui expects you to implement app framework conventions yourself.

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
