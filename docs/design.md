# Design

Companion to `raw-plan.md`. Defines state architecture, UI design system, animation/interaction model, keyboard map, and engineering conventions. Forward references like `src/tui/...` are intended paths; the code does not yet exist.

Stack: `ratatui` + `crossterm` (`event-stream`) + `tokio`. UI follows TEA (The Elm Architecture).

---

# State Architecture

## Pattern

Single root `Model`. All mutation flows through a pure `update(&mut Model, Action) -> Vec<Effect>`. The renderer reads from `Model` only and never mutates during draw.

```rust
struct Model {
    screen_stack: Vec<Screen>,        // back-nav stack; overlays included
    system: SystemInfo,               // OS, IP, RAM, disk, existing tooling
    profile: Profile,                 // Basic | Sandbox | Custom
    modules: BTreeMap<ModuleId, ModuleState>,
    selection: SelectionState,
    forms: HashMap<FormId, FormState>,
    plan: Option<Plan>,
    run: Option<RunState>,            // active apply
    log: RingBuffer<LogLine>,         // capped at 5000
    toasts: VecDeque<Toast>,
    palette: PaletteState,
    help: HelpState,
    theme: Theme,
    animations: AnimationRegistry,
    focus: FocusId,                   // currently-focused pane within screen
    should_quit: bool,
}
```

## Action enum (UI)

Distinct from the install-time `Action` defined in `raw-plan.md` (rename that to `InstallAction` if both live in the same crate).

```rust
enum Action {
    // lifecycle
    Init,
    Tick,                             // 4 Hz logical tick (timers, GC)
    Render,                           // 60 Hz render tick
    Quit,

    // input
    Key(KeyEvent),
    Resize(u16, u16),
    FocusGained,
    FocusLost,
    Paste(String),

    // navigation
    Push(Screen),
    Pop,
    Replace(Screen),

    // selection
    ToggleModule(ModuleId),
    SelectAll,
    SelectNone,
    InvertSelection,
    ResetProfileDefaults,

    // forms
    FormFieldChanged(FormId, FieldId, String),
    FormSubmit(FormId),

    // overlays
    OpenSearch,
    SearchInput(String),
    OpenPalette,
    PaletteInput(String),
    PaletteExec(PaletteCmd),
    OpenHelp,
    CloseOverlay,

    // results from background effects
    OsDetected(SystemInfo),
    PlanReady(Plan),
    InstallProgress(ProgressEvent),
    InstallDone(Outcome),
    Error(AppError),
    Toast(Toast),
}
```

## Effects

`update` returns `Vec<Effect>` — declarative side-effect descriptions. The runtime executes them on tokio tasks and posts results back as `Action`s. The reducer never spawns tasks itself, which keeps it pure and testable.

```rust
enum Effect {
    DetectSystem,
    GeneratePlan(Selection),
    RunInstall(Plan),
    CancelInstall,
    WriteConfig(PathBuf),
    LoadConfig(PathBuf),
    OpenUrl(String),
    Sleep(Duration, Action),          // delayed action: toasts, animation chains
}
```

## Event loop (`src/tui/runtime.rs`)

```rust
let (action_tx, mut action_rx) = mpsc::unbounded_channel::<Action>();
let cancel = CancellationToken::new();

spawn_terminal_events(action_tx.clone(), cancel.clone(), tick_hz: 4.0, render_hz: 60.0);

let mut model = Model::initial();
action_tx.send(Action::Init).ok();

loop {
    let Some(action) = action_rx.recv().await else { break };
    if matches!(action, Action::Render) {
        terminal.draw(|f| view(f, &model))?;
        continue;
    }
    let effects = update(&mut model, action);
    for eff in effects { spawn_effect(eff, action_tx.clone(), cancel.clone()); }
    if model.should_quit { break; }
}
```

Render is just another action so coalescing/throttling is uniform.

## Screen stack

`screen_stack: Vec<Screen>` with `Push` / `Pop` / `Replace`. `Esc` always maps to `Pop`. Overlays (Help, Palette, Search) are screens with `Screen::overlay() == true` — drawn on top of the previous frame without unmounting it.

## Background tasks

Long-running work (apt install, downloads) runs on tokio tasks holding `action_tx` and emit `Action::InstallProgress(...)`. They check `cancel.is_cancelled()` between awaits. `Action::CancelInstall` triggers `cancel.cancel()`; the runtime allocates a fresh token for the next run.

## Persistence

* In-memory by default.
* `Ctrl+S` → `Effect::WriteConfig` serializes `Model::selection` + `Model::forms` to `toride.toml`.
* `--config path.toml` on startup hydrates state and skips the Profile screen.

---

# UI Design System

## Theme

Two built-in themes: `dark` (default), `light`. Custom themes under `~/.config/toride/theme.toml`. All color access goes through semantic tokens — never raw `Color` in components.

```rust
enum SemanticToken {
    BgBase, BgRaised, BgOverlay,
    FgPrimary, FgSecondary, FgMuted, FgInverse,
    Accent, AccentDim,
    Success, Warning, Danger, Info,
    Border, BorderFocus,
    SelectionBg, SelectionFg,
    SpinnerActive, ProgressFill, ProgressTrack,
}
```

Default dark palette (`src/tui/theme.rs`):

```
BgBase       #0b0e14
BgRaised     #11151c
BgOverlay    #161b22
FgPrimary    #e6edf3
FgSecondary  #b1bac4
FgMuted      #6e7681
Accent       #7aa2f7
AccentDim    #3d4a6b
Success      #9ece6a
Warning      #e0af68
Danger       #f7768e
Info         #7dcfff
Border       #30363d
BorderFocus  #7aa2f7
```

24-bit color when supported; downgrade to ANSI 256 at startup (detect via `COLORTERM=truecolor`). `NO_COLOR=1` disables theming entirely.

## Glyphs

Unicode budget (ASCII fallback on `LANG=C` or `TERM=linux`):

```
Borders     ┌ ┐ └ ┘ ─ │ ╭ ╮ ╯ ╰
Selection   ●  ○  ☑  ☐
Status      ✓ ✗ ⚠ ⋯
Arrows      › ‹ ↑ ↓
Spinner     ⠋ ⠙ ⠹ ⠸ ⠼ ⠴ ⠦ ⠧ ⠇ ⠏
Bars        ▏ ▎ ▍ ▌ ▋ ▊ ▉ █
Sparkline   ▁ ▂ ▃ ▄ ▅ ▆ ▇ █
```

`Theme::glyph(g)` returns Unicode or ASCII fallback.

## Layout

* App: 3 rows — Header (1) / Body (flex) / StatusBar (1).
* Body: 2 columns on width ≥ 100 (Sidebar 24 cols + Content), single column otherwise.
* Minimum terminal: 80×24. Below that, render a "please resize" placeholder.
* Padding via `Spacing { Xs=1, Sm=1, Md=2, Lg=3 }` for consistent density.

## Components (`src/tui/widgets/`)

* `header.rs` — app name, breadcrumb, host badge (OS + IP), clock
* `sidebar.rs` — category tree with counts and focus indicator on the left edge
* `module_list.rs` — virtualized checklist, grouped, inline status icons
* `module_card.rs` — expanded module detail with description, deps, conflicts, options form
* `status_bar.rs` — context-aware keybinding hints (left), mode chip (right)
* `progress_panel.rs` — per-step rows: spinner / progress / log tail
* `log_view.rs` — autoscrolling log with filter
* `toast.rs` — bottom-right notification stack
* `palette.rs` — command palette modal
* `help.rs` — keybinding cheat sheet modal
* `splash.rs` — startup animation

Each component: `render(area, frame, &Model)`. No state lives inside components.

---

# Animations & Micro-interactions

## Frame model

Render at 60 FPS regardless of input. Animations are time-driven state machines keyed by id. View code derives the displayed value from elapsed time — no per-frame mutation.

```rust
struct Animation<T: Lerp> {
    from: T,
    to: T,
    started_at: Instant,
    duration: Duration,
    easing: Easing,
}

enum Easing { Linear, EaseOutCubic, EaseInOutCubic, EaseOutBack, Spring(f32) }

impl<T: Lerp> Animation<T> {
    fn value(&self, now: Instant) -> T {
        let t = ((now - self.started_at).as_secs_f32() / self.duration.as_secs_f32()).clamp(0.0, 1.0);
        T::lerp(&self.from, &self.to, self.easing.apply(t))
    }
    fn done(&self, now: Instant) -> bool { now - self.started_at >= self.duration }
}
```

`AnimationRegistry` holds animations by `AnimationId(&'static str, ScopeKey)`. Garbage-collected on completion or when their scope leaves the screen stack.

## Catalog

| Id                       | Trigger                          | Dur    | Easing         |
|--------------------------|----------------------------------|--------|----------------|
| `splash.fade_in`         | App start                        | 600ms  | EaseOutCubic   |
| `splash.fade_out`        | Splash dismiss                   | 250ms  | EaseInOutCubic |
| `screen.slide_in`        | `Push(screen)`                   | 220ms  | EaseOutCubic   |
| `screen.slide_out`       | `Pop`                            | 180ms  | EaseInOutCubic |
| `list.focus_indicator`   | Focus move                       | 120ms  | EaseOutCubic   |
| `checkbox.toggle`        | `ToggleModule`                   | 140ms  | EaseOutBack    |
| `card.expand`            | Enter on module                  | 180ms  | EaseOutCubic   |
| `card.collapse`          | Esc from module                  | 140ms  | EaseInOutCubic |
| `spinner.rotate`         | Step in `Running`                | 80ms/frame, linear |
| `progress.fill`          | Progress update                  | 200ms  | EaseOutCubic   |
| `progress.success_pulse` | Step succeeds                    | 600ms  | EaseOutCubic   |
| `progress.shake`         | Step fails                       | 300ms  | Spring(0.45)   |
| `toast.slide_up`         | Toast enqueue                    | 180ms  | EaseOutCubic   |
| `toast.slide_down`       | Toast dismiss                    | 140ms  | EaseInOutCubic |
| `palette.scale_in`       | Open palette                     | 160ms  | EaseOutBack    |
| `help.fade_in`           | `?` pressed                      | 120ms  | EaseOutCubic   |
| `tab.underline_slide`    | Tab change                       | 180ms  | EaseOutCubic   |
| `search.cursor_blink`    | Search input focused             | 500ms loop, square wave |

## Specifics

### Spinner (braille)
8 frames `⠋⠙⠹⠸⠼⠴⠦⠧`. Frame index `(elapsed_ms / 80) % 8`. Color: `SpinnerActive` (Accent).

### Progress bar
Block fractionals `▏▎▍▌▋▊▉█` give 8 sub-cells. A 20-cell bar has 160 discrete positions. Interpolate fill between previous and current percentage with `EaseOutCubic` 200ms. Track color `ProgressTrack`, fill `ProgressFill`.

### Focus indicator
Left-edge bar `▌` in `Accent`. Position interpolates between rows over 120ms with `EaseOutCubic`. During motion, render both the old row (fading out via background blend) and new row (fading in).

### Checkbox toggle
Glyph swaps `☐ → ☑`. The cell flashes `Success` for the first 80ms then settles to `FgPrimary`. EaseOutBack overshoot is communicated via a single extra "bold" frame at t=0.7.

### Card expand
Selected row height interpolates from 1 to panel height; rows below shift down with same easing. Suppress card body text rendering during first 50% of animation to avoid jitter.

### Toast
Slides up from the bottom-right. Stack depth 3. Lifetime 4s, then `slide_down` 140ms. Manual dismiss `Ctrl+T`.

### Success pulse
Row background flashes `Success` blended at 30% over the base, decaying to base over 600ms (`EaseOutCubic`).

### Shake
On failure, row x-offset oscillates ±1 cell with damped sine over 300ms. Implemented by adjusting render x-origin per frame.

### Splash
ASCII logo fades in via `FgMuted → FgPrimary` color interpolation, holds 400ms, then dismisses.

### Reduced motion
`TORIDE_NO_ANIM=1` and `--no-animations` collapse all `Animation<T>::value()` calls to their `to` value immediately. Transitions become instant but state machines still fire (so chained `Effect::Sleep` actions still resolve).

---

# Keyboard Map

Conventions:

* All bindings work on every screen unless listed as screen-local.
* `Esc` pops one level (close overlay → exit search → back one screen).
* Vim and arrow keys are aliases everywhere.
* No multi-key chords in v0.1. Namespace `g g`, `g e`, ... is reserved.
* The keybinding registry (`src/tui/keymap.rs`) is the single source of truth; the status bar and help overlay read from it at runtime.

## Global

| Key            | Action                                |
|----------------|---------------------------------------|
| `q`            | Quit (confirm if `RunState::Active`)  |
| `Ctrl+C`       | Cancel current op / quit              |
| `?` / `F1`     | Toggle help overlay                   |
| `:`            | Open command palette                  |
| `/`            | Open search (when list focused)       |
| `Esc`          | Pop screen / close overlay            |
| `Tab`          | Next pane                             |
| `Shift+Tab`    | Previous pane                         |
| `Ctrl+S`       | Save selection to `toride.toml`       |
| `Ctrl+L`       | Toggle log panel                      |
| `Ctrl+T`       | Dismiss top toast                     |
| `Ctrl+R`       | Reload config from disk               |
| `F2`           | Cycle theme                           |

## Navigation (lists, trees)

| Key                | Action                  |
|--------------------|-------------------------|
| `j` / `↓`          | Next item               |
| `k` / `↑`          | Previous item           |
| `h` / `←`          | Collapse / parent       |
| `l` / `→` / `Enter`| Expand / drill in       |
| `g g`              | First item (reserved)   |
| `G`                | Last item               |
| `Ctrl+D`           | Half page down          |
| `Ctrl+U`           | Half page up            |
| `PageDown`         | Page down               |
| `PageUp`           | Page up                 |
| `Home` / `End`     | First / last item       |

## Module selection (screen-local)

| Key       | Action                                    |
|-----------|-------------------------------------------|
| `Space`   | Toggle module                             |
| `Enter`   | Expand module card / open configuration   |
| `a`       | Select all visible                        |
| `n`       | Select none                               |
| `i`       | Invert selection                          |
| `r`       | Reset to profile defaults                 |
| `c`       | Toggle category collapsed                 |
| `p`       | Preview plan                              |
| `d`       | Toggle dry-run mode                       |
| `x`       | Proceed to preflight                      |

## Forms

| Key                  | Action                       |
|----------------------|------------------------------|
| `Tab` / `Shift+Tab`  | Next / previous field        |
| `Enter`              | Submit (last field) / next   |
| `Esc`                | Cancel and revert            |
| `Ctrl+W`             | Delete previous word         |
| `Ctrl+U`             | Clear field                  |
| Standard editing     | Arrow keys, Home, End, etc.  |

## Apply screen

| Key       | Action                                 |
|-----------|----------------------------------------|
| `j` / `k` | Focus next / previous step row         |
| `Enter`   | Expand step log                        |
| `f`       | Toggle follow-tail                     |
| `Ctrl+C`  | Cancel running plan (confirm)          |
| `s`       | Skip current step (only if `Failed`)   |
| `R`       | Retry current step                     |

## Palette

| Key       | Action                       |
|-----------|------------------------------|
| Type      | Fuzzy filter commands        |
| `↑` / `↓` | Navigate matches             |
| `Enter`   | Execute selected command     |
| `Esc`     | Close palette                |

Initial commands:

```
:plan                    Preview plan
:apply                   Run apply
:dry-run                 Run in dry-run mode
:save <path>             Save config
:load <path>             Load config
:reset                   Reset to profile defaults
:theme dark|light|<name> Switch theme
:log                     Toggle log panel
:export json|toml <path> Export plan
:quit                    Quit
```

## Help overlay

| Key                | Action               |
|--------------------|----------------------|
| `?` / `Esc` / `q`  | Close overlay        |
| `/`                | Search bindings      |
| `j` / `k`          | Scroll               |

---

# Best Practices

## Error handling

* `color-eyre::Result<T>` at the app boundary.
* `thiserror`-derived domain errors at module boundaries (`ModuleError`, `IoError`, `NetworkError`).
* No `unwrap()` outside `main` and tests. `expect()` only with a `// invariant:` comment explaining why.
* A custom panic hook restores the terminal before printing the backtrace (`initialize_panic_handler` per ratatui docs).

## Async hygiene

* Never hold a `Mutex` / `RwLock` across `.await`. Use message passing or short critical sections.
* Every background task owns a `CancellationToken` clone and checks it between awaits.
* `mpsc::unbounded_channel` for action dispatch (no backpressure needed). Bounded channels only for subprocess byte streams.
* `tokio::process::Command` with `stdout(Stdio::piped())`, `BufReader::lines()`, forward each line as `Action::InstallProgress`.

## Module conventions

* One module = one file under `src/modules/`.
* Each module exports a zero-sized `pub struct ModuleX;` implementing `SetupModule`.
* Ids are kebab-case strings: `"ssh-hardening"`, `"docker"`, `"mise"`.
* Dependencies are validated against the registry at startup; missing-id is a startup error, not a runtime one.

## Testing

* `update()` is pure: golden-file tests with `(Model, Action) → (Model, Vec<Effect>)`.
* Effects are mocked: `Effect::RunInstall(plan)` records the plan in tests rather than executing it.
* Layout regressions: `insta` snapshots of `TestBackend` frame buffers.
* Module subprocess tests use a `Sandbox` trait selecting `RealExec` or `FakeExec` at construction — no ad-hoc mocking.

## Rendering rules

* No allocation in `view()` hot path beyond what ratatui itself does. Pre-allocate styled-string buffers in `Model`.
* Cache static-panel layouts by `(area, model_hash)`.
* All text rendered via `Theme::style(token)` — never inline `Color::Rgb(...)` in components.
* Widgets must be deterministic functions of `(area, &Model)`.

## Logging vs UI logs

* `tracing` writes structured events to disk (`/var/log/toride/setup.log`, `actions.jsonl`).
* UI log is a separate `RingBuffer<LogLine>` capped at 5000, populated by `Action::InstallProgress`.
* Neither blocks the reducer. If the disk writer falls behind, drop and increment a `dropped_lines` counter shown in the status bar.

## Accessibility & degradation

* `--no-animations` / `TORIDE_NO_ANIM=1` collapses all animations to final state.
* `--no-color` / `NO_COLOR=1` disables all theming (white-on-default).
* ASCII glyph fallbacks for `LANG=C` and `TERM=linux`.
* Default themes meet WCAG AA contrast against background; CI snapshot verifies.

## Performance budgets

* Cold start to first paint: < 60ms.
* Reducer + view per action: p50 < 1ms, p99 < 5ms on a 4-core VPS.
* Render frame budget: 16ms (60 FPS). Exceeding logs a warning to the trace stream.

## Code structure (forward reference)

```
src/tui/
├─ runtime.rs        // event loop, effect spawner
├─ model.rs          // Model + initial state
├─ update.rs         // pure reducer
├─ effects.rs        // Effect runner
├─ view.rs           // root view fn
├─ theme.rs          // tokens, themes, palette
├─ glyphs.rs         // unicode + ascii fallbacks
├─ animation.rs      // Animation<T>, Easing, registry
├─ keymap.rs         // KeyMap + binding registry
└─ widgets/
   ├─ header.rs
   ├─ sidebar.rs
   ├─ module_list.rs
   ├─ module_card.rs
   ├─ status_bar.rs
   ├─ progress_panel.rs
   ├─ log_view.rs
   ├─ toast.rs
   ├─ palette.rs
   ├─ help.rs
   └─ splash.rs
```

## Conventions for future contributors

* New screen: extend `Screen`, add `view_<screen>`, register keybindings in `keymap.rs`, add at least one snapshot test.
* New module: file under `src/modules/`, register in `modules/mod.rs`, declare deps/conflicts, write a `to_shell_preview` test per `Action` variant emitted.
* New animation: pick a stable `AnimationId`, choose from existing `Easing` variants (no ad-hoc curves), append to the catalog table in this doc.
* New keybinding: register in `keymap.rs`, add to the relevant section here, do not duplicate in help — the overlay reads from the registry.
