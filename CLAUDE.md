# Toride: Architecture Reference

> Concise map of the TUI codebase. Each section lists **where** things live and **how** they connect. Read the source for implementation details.
>
> Regenerated per release; drift between releases means this file is stale, not the code.

---

## Architecture

Elm-inspired: `App` owns all state → `Action` enum describes intents → `update()` mutates → `view()` renders.

```
Event → handle_key()/handle_mouse() (app/input.rs) → Option<Action>
  → App::update() (app/mod.rs) → mutate state → terminal.draw(view)
```

| File | Role |
|------|------|
| `src/app/mod.rs` | `App` struct, `update()`, event loop (`select!`), collector gating |
| `src/app/input.rs` | `handle_key()`, `handle_mouse()`: routes to screens |
| `src/app/render.rs` | `view()`: renders screen + overlays |
| `src/action.rs` | `Action` enum: all semantic user intents |
| `src/navigation/mod.rs` | `Navigator`: screen stack + forward/back routing |
| `src/ui/screens/mod.rs` | `AppScreen` trait: shared screen interface |
| `src/test_env.rs` | `#[cfg(test)]` crate-wide env-mutation lock |

**Event loop** (`App::run`): tokio `select!` with biased priority over 28 sources:
1. Terminal events (key/mouse/resize)
2. 21 collector poll arms (`status_collector.rs` + 20 per-section `*_data.rs` collectors)
3. 2 mpsc channels: SSH op errors (`ssh_error_rx`), SSH op completion (`ssh_op_done_rx`)
4. 4 intervals: 2s refresh, 33ms animation tick, 250ms shimmer tick, 250ms toast expiry

The 2s refresh arm calls `App::start_section_collectors`: the status collector always runs; every section collector runs while the Dashboard section is active (its managed-services cards and sidebar badges read them all) and for `DASHBOARD_GRACE_TICKS` (2) ticks after leaving it; otherwise only the active section's collector runs (`app/mod.rs`).

---

## Theme & Colors

**File:** `src/ui/theme.rs`: `Palette` struct (17 semantic color slots plus the `reduced_motion: bool` flag), 6 built-in themes (Charm default).

Key helpers:
- `p.key_style()` / `p.label_style()`: badge/label styles for keybinding hints
- `KEY_BG` const: badge background color

---

## Color & Format Helpers

**File:** `src/ui/helpers/color.rs`: `lerp_color`, `dim_color`, `to_rgb`
**File:** `src/ui/helpers/format.rs`: `format_bytes`, `format_duration`, `percent_color` (70/90 thresholds → ok/warn/err)
**File:** `src/ui/responsive.rs`: `Viewport` enum (TooSmall/Minimal/Compact/Full), `truncate_str`, `center_area`

---

## Widget Catalog

All in `src/ui/widgets/`. Re-exported from `mod.rs`.

| Widget | File | Purpose |
|--------|------|---------|
| **Modal** | `modal.rs` | Centered overlay with dimmed scrim, 7 border variants. Builder: `Modal::new("title").dimensions(w,h).border(variant).render(frame, p, \|f,area\| {...})` |
| **InteractiveModal** | `interactive_modal.rs` | Modal with an embedded `ButtonRow`; emits `ModalEvent` on button activation. Used for the help overlay and the module detail modal |
| **Tooltip** | `tooltip.rs` | Anchored floating card below a hitbox. Helpers: `title_line`, `kv`, `kv_with_suffix` |
| **Card** | `card.rs` | Rounded-border panel, `focused(bool)` swaps border color |
| **Panel** | `panel.rs` | `render_panel()`, `render_titled_panel(frame, area, p, title, color, focused)`, `render_titled_panel_bg()` |
| **Badge** | `badge.rs` | `badge()`, `neutral_badge()`, `accent_badge()`, `tag_badge()`: pill-shaped spans |
| **TextInput** | `text_input.rs` | Editable single-line input. `handle_key()` → `InputAction` enum. Supports: cursor, scroll, secret mode, placeholder, UTF-8 |
| **Dropdown** | `dropdown.rs` | Inline cycle-selector. Up/Down cycle options. Shows `▲▼` arrows |
| **ConfirmModal** | `confirm.rs` | Confirm/Cancel dialog. `handle_key()` → `Option<ConfirmResult>`. y/n/Esc shortcuts, Tab button cycling |
| **FormModal** | `form.rs` | Multi-field form (TextInput + Dropdown). Tab/BackTab field cycling, `handle_key()` → `FormResult` |
| **Validate** | `validate.rs` | Field validation helpers backing FormModal |
| **Gradient** | `gradient.rs` | `GradientCache` (radial bg), `AnimatedBorder` (color-cycling perimeter), transition gradient |

---

## Interactive Buttons

**File:** `src/ui/components/interactive_button.rs`: `InteractiveButton<A>` with 4 visual states: Default→KEY_BG, Focused→accent, Hovered→sel_bg, Pressed→accent2. Mouse hit-testing via stored `Rect`.

**File:** `src/ui/components/button_row.rs`: `ButtonRow<A>` auto-centers buttons, Tab/BackTab focus cycling via `ratatui_interact::FocusManager`.

---

## Screen System

**`AppScreen` trait** (`src/ui/screens/mod.rs`): `handle_key`, `handle_mouse`, `handle_action`, `view`, `view_foreground`, `invalidate_cache`, `needs_animation`, `has_modal` (suppresses global shortcuts), `needs_fast_frames` (~30fps vs ~4fps shimmer cadence; never consulted under `reduced_motion`).

**`ScreenBase`** (`src/ui/screens/base.rs`): shared gradient background, `guard_too_small()`.

**`Navigator`** (`src/navigation/mod.rs`): `Screen` enum (Welcome=0, Dashboard=1), forward/back with animated transitions.

**Current screens:**
| Screen | File | Notes |
|--------|------|-------|
| Welcome | `screens/welcome.rs` | Splash, shimmer, button row |
| Dashboard | `screens/dashboard.rs` | Shell layout, managed-services grid, sidebar-driven sections. Routes to the active section's `ContentPanel` |
| Help | `screens/help.rs` | Modal overlay (not navigable); lists `Ctrl+T` / `Ctrl+Shift+A` |
| Quit | `screens/quit.rs` | Confirm modal |

**Content panels** (`impl ContentPanel` in `dashboard.rs`): one per sidebar section (20 panels), each in `src/ui/screens/<section>/`.

---

## Shell Layout

**File:** `src/ui/shell/mod.rs`: `shell_layout(area, sidebar_w) → ShellAreas { header, sidebar, content, footer }`

| Component | File | Key details |
|-----------|------|-------------|
| **Header** | `header.rs` | Logo shimmer, CPU/RAM/Disk/Net gauges, braille spinner, clock. `gauge_hitboxes()` for mouse |
| **Sidebar** | `sidebar.rs` | 21 sections, animated pill highlight (AnimatedFloats), collapsible (30→6 cols), mouse hit-testing |
| **Footer** | `footer.rs` | Keybinding hints bar, `? help` right-aligned |

---

## Overlay & Input Priority

**File:** `src/app/input.rs`

Layers (last wins for rendering, first intercepts for input):
1. Screen content / transition gradient
2. Help modal
3. Quit modal

Input routing: quit modal → help modal → transitions (block all) → global keys (Ctrl+T theme, Ctrl+Shift+A animations, ?, q) → current screen.

---

## Transitions

**File:** `src/ui/transition.rs`: `TransitionState` (400ms, CubicInOut), `TransitionCache` (deterministic seeds), `TransitionParams` (center offset, edge delta, brightness dip). Midpoint swaps foreground screen.

---

## Animation

- **AnimatedFloats** (`src/ui/helpers/anim.rs`): constant-speed lerp, used for sidebar highlight
- **Easing** via `tachyonfx::Interpolation`: CubicInOut (transitions), SineOut (tooltips), ExpoOut (borders)
- **Braille spinner** via `rattles` crate (`src/ui/shell/header.rs`)
- **Animation tick gate**: 33ms fires only when transition active, redraw needed, or screen `needs_animation()`

---

## Scrollable Areas

Manual `usize` scroll offsets everywhere: no ratatui `Scrollbar`.

- **Dashboard lists**: `list_rows(inner, scroll, len)` helper (see `dashboard.rs`)
- **Sidebar**: `clamp_scroll_to_selection()` keeps selected visible
- **TextInput**: `clamp_scroll()` after every edit, keeps cursor visible
- **Module grid**: row-page scroll, keeps selected module in view
- **Logs view**: builds only the visible window of rows per frame (`LogsContent::line_at`)

---

## Data Collectors

One `*_data.rs` collector per section (`fail2ban_data.rs`, `toride_harden_data.rs`, ...), each following the `StatusCollector` oneshot pattern: `start()` spawns, `poll()` delivers. Bundles cross through `dashboard.set_*_data` setters.

Caching layers:
- **Status**: delivered as `Arc<TorideStatus>`; the app shares one refcount between the dashboard and the About collector (`about_data.rs`).
- **Section collectors**: 60s TTL caches over doctor findings (fail2ban, harden, audit, ...); AIDE integrity 300s.
- **Logs**: 6s TTL (three refresh ticks); within the window `start()` re-ships the cached bundle and spawns nothing.
- **SSH** (`ssh_data.rs`): `SshStateCache` stamps known_hosts, authorized_keys, certificates, per-user `~/.ssh` scans, the key inventory, the config host blocks, candidate control sockets, and the parsed `sshd_config`/access snapshot; an unchanged stamp re-ships cached entries without reparsing or spawning `ssh -O` checks.

---

## SSH Management

**Files:** `src/ui/screens/ssh/` (9 tabs), `src/ssh_data.rs`

Renders inside the dashboard content area when `Section::Ssh` is active. `SshSection` tabs: Security, Keys, KnownHosts, Config, Agent, Forwarding, Diagnostics, AuthorizedKeys, Certificates. The `SshTab` trait (`ssh/mod.rs`) covers `handle_key`, `handle_mouse`, `view`, `has_modal`, `drain_ops`.

**Data collection:** `src/ssh_data.rs`: `SshDataCollector` runs `collect_real_data` (keys, known_hosts, authorized_keys, config hosts, agent, forwarding, certificates, diagnostics, security) against `toride-ssh`. The mock bundle (`mod mock`) is test fixture only. `sshd_config` grading and the Security tab's ACCESS card both derive from one include-expanded, first-obtained-wins walk (`merge_sshd_directives`).

**Writes:** `SshOp` variants execute through `execute_op` with lockout guards (`would_lock_out`), optimistic UI updates, and revert-on-failure toasts.

---

## Action Enum

**File:** `src/action.rs`

```rust
pub enum Action {
    Continue, Help, CloseHelp, Back,
    ConfirmQuit, DismissQuit, Quit,
    ScrollDown, ScrollUp, CycleTheme,
    ToggleAnimations, Redraw,
}
```

All `Copy + Clone + Debug + PartialEq + Eq`.

---

## Persistence

**File:** `src/persistence/mod.rs`: theme and animation preference in `<config_dir>/toride/config.toml`, round-tripped through a TOML table, written atomically at 0600; concurrent saves serialize on a process-wide mutex. Saves are dispatched fire-and-forget through `spawn_blocking` (`PersistOp` in `app/mod.rs`).

---

## Setup Bundles

**Files:** `src/setup_bundles.rs`, `src/setup_bundles/hints.rs`, `src/ui/screens/setup/`

Read-only recommendation layer: license-labeled bundles, consent modal, in-session approval (`approved()`); no install executes (divergence D10 in `docs/setup-bundles-plan.md`). Config hints apply with an `O_EXCL` create so an existing file is never replaced.

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
| `color-eyre` | Error handling |
| `insta` | Snapshot testing |
| `unicode_width` | CJK/wide character width |
| `toride-ssh` | SSH backend (11 sub-crates: core, config, key, agent, known_hosts, authorized_keys, doctor, forward, certificate, exec, upload; the TUI enables all except exec/upload) |
| `toride-status` ... `ufw-kit` | Per-section live-data backends (see each `*_data.rs`) |

---

## Testing

Snapshot tests via `insta` + `TestBackend`. Pattern in `src/ui/screens/mod.rs`:
```rust
fn render_to_string<S: AppScreen>(screen: &mut S, w: u16, h: u16) -> String
```
Each module has `#[cfg(test)] mod tests` at bottom. Every test that mutates a process env var acquires the single crate lock `crate::test_env` (sync tests use `lock_blocking`, async tests `lock_async`). Criterion benches live in `benches/`: `dashboard_render`, `logs_render`, `status_clone`, `collector_tick_churn` (spawn count per refresh tick), `collector_cache_hit` (steady-state start+poll per collector).

---

## Icons

Sidebar glyphs (all 21 distinct):
| Icon | Section | Icon | Section | Icon | Section |
|------|---------|------|---------|------|---------|
| `◑` Dashboard | `▣` Tools | `▲` Templates |
| `◆` SSH | `▦` Firewall | `✦` Fail2ban |
| `⛓` Tailscale | `⛨` Harden | `◇` WireGuard |
| `↻` Updates | `◉` Users | `⚖` Audit |
| `◎` Monitor | `▤` Backup | `⊕` Proxy |
| `☁` Cloud | `Ⓜ` Mise | `≡` Logs |
| `◍` About | `⚙` Settings | `⚒` Setup |

Status glyphs: `✓` OK, `!` warning, `↻` in progress, `●` connected, `▮` gauge fill, `·` spinner fallback, `砦` app logo.

---

## Project Structure

```
crates/toride/src/
  app/             # App orchestrator (mod, input, render)
  config/          # config-file surface for the Settings section
  navigation/      # Navigator, Screen enum
  persistence/     # theme/animation persistence (config.toml)
  prediction/      # resource trend prediction
  setup_bundles/   # hint application (the only setup write path)
  ui/
    theme.rs       # Palette (17 slots + reduced_motion), 6 themes
    responsive.rs  # Viewport breakpoints, truncation
    transition.rs  # Screen transition animation
    helpers/       # anim.rs, color.rs, format.rs
    widgets/       # modal, interactive_modal, tooltip, card, panel, badge,
                    # text_input, dropdown, confirm, form, validate, gradient
    components/    # interactive_button, button_row
    screens/       # AppScreen trait, base, welcome, dashboard, help, quit,
                    # section_overview, findings + one dir per section:
                    # ssh/ (9 tabs), fail2ban/, ufw_kit/, toride_harden/,
                    # toride_wireguard/, toride_updates/, toride_users/,
                    # toride_audit/, toride_monitor/, toride_backup/,
                    # toride_proxy/, toride_cloud/, toride_tailscale/,
                    # toride_mise/, tools/, templates/, logs/, about/,
                    # settings/, setup/
    shell/         # header, sidebar, footer
  data/mod.rs      # DashboardData, Section (21), SshSection (9), Module, SidebarItem
  action.rs        # Action enum (12 variants)
  status_collector.rs  # Arc<TorideStatus> collection
  about_{data,convert}.rs  logs_{data,convert}.rs
  settings_{data,convert}.rs  setup_data.rs  templates_{data,convert}.rs
  tools_{data,convert}.rs  ssh_{data,convert}.rs
  fail2ban_{data,convert}.rs  ufw_kit_{data,convert}.rs
  toride_{audit,backup,cloud,harden,mise,monitor,proxy,tailscale,updates,users,wireguard}_{data,convert}.rs
  test_env.rs      # #[cfg(test)] shared env lock
  version.rs  virt_detect.rs  main.rs  lib.rs
```
