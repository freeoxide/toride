# toride

Terminal user interface (TUI) for hardened Linux host management. Implements the Elm-inspired TUI app: an `app::App` orchestrator that owns all screen instances and drives the main event loop, plus the rendering widgets, themes, and per-section data collectors that back each dashboard panel.

Part of the [toride](https://github.com/freeoxide/toride) workspace.

## Usage

Build and launch from a checkout of the workspace:

```sh
cargo run -p toride
```

The binary is also installable through cargo once published: `cargo install toride`.

Press `?` for the keybinding list. `Ctrl+T` cycles the theme, `Ctrl+Shift+A` cycles the animation preference (auto, on, off) and persists both to the OS config dir as `<config_dir>/toride/config.toml` (written by `src/persistence/mod.rs`). Number keys `1`-`9` jump between sidebar sections, `j`/`k` scroll, `q` quits.

Platform statement: toride targets Linux; the collectors read `/proc`, `/sys`, and `/etc/ssh/sshd_config` through the sibling crates, and the security view's `Include` handling follows `sshd_config.d` drop-ins.

## Reading and writing

The 21 sidebar sections split by what they can do to the machine:

| Writes | Reads |
|--------|-------|
| SSH: edits `~/.ssh/config`, manages keys and the agent, edits `sshd_config` through sudo | Dashboard gauges, Logs (journalctl and file tails), Monitor, Updates |
| Settings: persists theme and animation preference to `config.toml` | Firewall, Fail2ban, Harden, Audit, Backup, Proxy, Cloud, Tailscale, WireGuard, Users, Tools, Templates, Mise, About |

Setup records approvals only: the detail footer says "enter: approve for install" and no install executes in this version (`docs/setup-bundles-plan.md`, divergence D10).

## License

MIT
