# Toride — Architecture Reference

> Concise map of the TUI codebase. Each section lists **where** things live and **how** they connect. Read the source for implementation details.

---

## Architecture

Elm-inspired: `App` owns all state → `Action` enum describes intents → `update()` mutates → `view()` renders.

```
Event → handle_key()/handle_mouse() (app/input.rs) → Option<Action>
  → App::update() (app/mod.rs) → mutate state → terminal.draw(view)
```

| File | Role |
|------|------|
| `src/app/mod.rs` | `App` struct, `update()`, event loop (`select!`) |
| `src/app/input.rs` | `handle_key()`, `handle_mouse()` — routes to screens |
| `src/app/render.rs` | `view()` — renders screen + overlays |
| `src/action.rs` | `Action` enum — all semantic user intents |
| `src/navigation/mod.rs` | `Navigator` — screen stack + forward/back routing |
| `src/ui/screens/mod.rs` | `AppScreen` trait — shared screen interface |

**Event loop** (`App::run`): tokio `select!` with biased priority:
1. Terminal events (key/mouse/resize)
2. `StatusCollector` / `SshDataCollector` — async data results
3. 2s refresh interval — triggers data collection
4. 33ms animation tick — shimmer, borders, spinners, transitions

---

## Theme & Colors

**File:** `src/ui/theme.rs` — `Palette` struct (19 semantic color slots), 6 built-in themes (Charm default).

Key helpers:
- `p.key_style()` / `p.label_style()` — badge/label styles for keybinding hints
- `KEY_BG` const — badge background color

---

## Color & Format Helpers

**File:** `src/ui/helpers/color.rs` — `lerp_color`, `dim_color`, `to_rgb`
**File:** `src/ui/helpers/format.rs` — `format_bytes`, `format_duration`, `percent_color` (70/90 thresholds → ok/warn/err)
**File:** `src/ui/responsive.rs` — `Viewport` enum (TooSmall/Minimal/Compact/Full), `truncate_str`, `center_area`

---

## Widget Catalog

All in `src/ui/widgets/`. Re-exported from `mod.rs`.

| Widget | File | Purpose |
|--------|------|---------|
| **Modal** | `modal.rs` | Centered overlay with dimmed scrim, 7 border variants. Builder: `Modal::new("title").dimensions(w,h).border(variant).render(frame, p, \|f,area\| {...})` |
| **Tooltip** | `tooltip.rs` | Anchored floating card below a hitbox. Helpers: `title_line`, `kv`, `kv_with_suffix` |
| **Card** | `card.rs` | Rounded-border panel, `focused(bool)` swaps border color |
| **Panel** | `panel.rs` | `render_panel()`, `render_titled_panel(frame, area, p, title, color, focused)`, `render_titled_panel_bg()` |
| **Badge** | `badge.rs` | `badge()`, `neutral_badge()`, `accent_badge()`, `tag_badge()` — pill-shaped spans |
| **TextInput** | `text_input.rs` | Editable single-line input. `handle_key()` → `InputAction` enum. Supports: cursor, scroll, secret mode, placeholder, UTF-8 |
| **Dropdown** | `dropdown.rs` | Inline cycle-selector. Up/Down cycle options. Shows `▲▼` arrows |
| **ConfirmModal** | `confirm.rs` | Confirm/Cancel dialog. `handle_key()` → `Option<ConfirmResult>`. y/n/Esc shortcuts, Tab button cycling |
| **FormModal** | `form.rs` | Multi-field form (TextInput + Dropdown). Tab/BackTab field cycling, `handle_key()` → `FormResult` |
| **Gradient** | `gradient.rs` | `GradientCache` (radial bg), `AnimatedBorder` (color-cycling perimeter), transition gradient |

---

## Interactive Buttons

**File:** `src/ui/components/interactive_button.rs` — `InteractiveButton<A>` with 4 visual states: Default→KEY_BG, Focused→accent, Hovered→sel_bg, Pressed→accent2. Mouse hit-testing via stored `Rect`.

**File:** `src/ui/components/button_row.rs` — `ButtonRow<A>` auto-centers buttons, Tab/BackTab focus cycling via `ratatui_interact::FocusManager`.

---

## Screen System

**`AppScreen` trait** (`src/ui/screens/mod.rs`): `handle_key`, `handle_mouse`, `handle_action`, `view`, `view_foreground`, `invalidate_cache`, `needs_animation`.

**`ScreenBase`** (`src/ui/screens/base.rs`): shared gradient background, `guard_too_small()`.

**`Navigator`** (`src/navigation/mod.rs`): `Screen` enum (Welcome=0, Dashboard=1), forward/back with animated transitions.

**Current screens:**
| Screen | File | Notes |
|--------|------|-------|
| Welcome | `screens/welcome.rs` | Splash, shimmer, button row |
| Dashboard | `screens/dashboard.rs` | Shell layout, module grid, sidebar-driven sections. Routes to `SshContent` when `Section::Ssh` active |
| Help | `screens/help.rs` | Modal overlay (not navigable) |
| Quit | `screens/quit.rs` | Confirm modal |

---

## Shell Layout

**File:** `src/ui/shell/mod.rs` — `shell_layout(area, sidebar_w) → ShellAreas { header, sidebar, content, footer }`

| Component | File | Key details |
|-----------|------|-------------|
| **Header** | `header.rs` | Logo shimmer, CPU/RAM/Disk/Net gauges, braille spinner, clock. `gauge_hitboxes()` for mouse |
| **Sidebar** | `sidebar.rs` | 9 sections, animated pill highlight (AnimatedFloats), collapsible (30→6 cols), mouse hit-testing |
| **Footer** | `footer.rs` | Keybinding hints bar, `? help` right-aligned |

---

## Overlay & Input Priority

**File:** `src/app/input.rs`

Layers (last wins for rendering, first intercepts for input):
1. Screen content / transition gradient
2. Help modal
3. Quit modal

Input routing: quit modal → help modal → transitions (block all) → global keys (Ctrl+T, ?, q) → current screen.

---

## Transitions

**File:** `src/ui/transition.rs` — `TransitionState` (400ms, CubicInOut), `TransitionCache` (deterministic seeds), `TransitionParams` (center offset, edge delta, brightness dip). Midpoint swaps foreground screen.

---

## Animation

- **AnimatedFloats** (`src/ui/helpers/anim.rs`): constant-speed lerp, used for sidebar highlight
- **Easing** via `tachyonfx::Interpolation` — CubicInOut (transitions), SineOut (tooltips), ExpoOut (borders)
- **Braille spinner** via `rattles` crate (`src/ui/shell/header.rs`)
- **Animation tick gate**: 33ms fires only when transition active, redraw needed, or screen `needs_animation()`

---

## Scrollable Areas

Manual `usize` scroll offsets everywhere — no ratatui `Scrollbar`.

- **Dashboard lists**: `list_rows(inner, scroll, len)` helper (see `dashboard.rs`)
- **Sidebar**: `clamp_scroll_to_selection()` keeps selected visible
- **TextInput**: `clamp_scroll()` after every edit, keeps cursor visible
- **Module grid**: row-page scroll, keeps selected module in view

---

## SSH Management

**Files:** `src/ui/screens/ssh/`

Renders inside the dashboard content area when `Section::Ssh` is active (no separate `Screen` variant needed).

| Component | File | Purpose |
|-----------|------|---------|
| `SshContent` | `ssh/mod.rs` | Tab bar (6 tabs), focus management, routes to active tab |
| `KeysTab` | `ssh/keys_tab.rs` | SSH key list with badges, detail modal, CRUD action stubs |
| `SshSection` | `data/mod.rs` | Enum: Keys, KnownHosts, Config, Agent, Forwarding, Diagnostics |

**Data collection:** `src/ssh_data.rs` — `SshDataCollector` (same pattern as `StatusCollector`). Currently returns mock data; will be wired to `toride-ssh` backend.

---

## Action Enum

**File:** `src/action.rs`

```rust
pub enum Action {
    Continue, Help, CloseHelp, Back,
    ConfirmQuit, DismissQuit, Quit,
    ScrollDown, ScrollUp, CycleTheme,
}
```

All `Copy + Clone + Debug + PartialEq + Eq`.

---

## Key Dependencies

| Crate | Purpose |
|-------|---------|
| `ratatui` 0.30 | Terminal UI framework |
| `ratatui_interact` | Button, ButtonState, FocusManager |
| `tachyonfx` | Color interpolation, effects, easing |
| `rattles` | Braille spinner presets |
| `crossterm` 0.29 | Terminal events |
| `tokio` | Async runtime, `select!` |
| `color_eyre` | Error handling |
| `insta` | Snapshot testing |
| `unicode_width` | CJK/wide character width |
| `toride-ssh` | SSH backend (10 sub-crates: key, config, agent, known_hosts, authorized_keys, doctor, forward, certificate) |

---

## Testing

Snapshot tests via `insta` + `TestBackend`. Pattern in `src/ui/screens/mod.rs`:
```rust
fn render_to_string<S: AppScreen>(screen: &mut S, w: u16, h: u16) -> String
```
Each module has `#[cfg(test)] mod tests` at bottom.

---

## Icons

| Icon | Section | Icon | Meaning |
|------|---------|------|---------|
| `◑` Dashboard | `◆` SSH | `✓` OK | `▮` Gauge fill |
| `▣` Tools | `▦` Firewall | `!` Warning | `●` Connected |
| `▲` Templates | `✦` Fail2ban | `↻` In progress | `·` Spinner fallback |
| `≡` Logs | `◇` About | `⚙` Settings | `砦` App logo |

---

## Project Structure

```
crates/toride/src/
  app/             # App orchestrator (mod, input, render)
  ui/
    theme.rs       # Palette (19 slots), 6 themes
    responsive.rs  # Viewport breakpoints, truncation
    transition.rs  # Screen transition animation
    helpers/       # anim.rs, color.rs, format.rs
    widgets/       # modal, tooltip, card, panel, badge, text_input, dropdown, confirm, form, gradient
    components/    # interactive_button, button_row
    screens/       # AppScreen trait, base, welcome, dashboard, help, quit, ssh/
    shell/         # header, sidebar, footer
  data/mod.rs      # DashboardData, Section, SshSection, Module, SidebarItem
  action.rs        # Action enum
  navigation/      # Navigator, Screen enum
  status_collector.rs
  ssh_data.rs      # SshDataCollector
```
