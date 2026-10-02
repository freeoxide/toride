# toride-apps

The app install/uninstall **execution** layer over `toride-registry`: it
turns each registry `InstallMethod` into a concrete, backend-routed
operation and runs it on the host, recording every mutation in an install
manifest.

- A pure planner (`plan_install`, `plan_uninstall`) deriving exact
  manager argv from a registry `App` plus a host `Target` — no I/O,
  fixture-testable.
- The `Backend` trait with executed implementations for Homebrew,
  Flatpak, distro managers (apt, dnf, pacman, apk), npm, cargo, pipx,
  uv, mise-delegated tools, and direct downloads — install, uninstall,
  update, status, version queries, and pinning.
- The `Apps` facade: ensure-installed (optionally at a version),
  uninstall, update with dry-run, status, search, adopt, and
  available-version listing — all manifest-recorded, with a typed
  `Version` newtype for the manager's native version spelling.
- Multi-source detection across `$PATH`, mise shims, and backend
  listing probes, merged by canonical path.
- A sync execution path: `AppsBlocking` (via `Apps::blocking`) drives
  the same lifecycle verbs with no tokio anywhere in the default
  dependency graph.

## Feature flags

| Feature        | Default | Pulls in                        | What it gates                                    |
|----------------|:-------:|---------------------------------|--------------------------------------------------|
| `tokio`        | No      | tokio                           | `spawn_blocking` offload for the async facade    |
| `registry-http`| No      | `toride-registry/http`          | Registering the concrete fetch adapters          |
| `direct`       | No      | `toride-installer`, `tokio`     | Direct-download installs (verified pipeline)     |
| `mise`         | No      | `toride-mise`                   | The mise-delegated language backend              |

```toml
[dependencies]
toride-apps = "0.1"
```

[Changelog](CHANGELOG.md) · [Source](https://github.com/freeoxide/toride/tree/master/crates/toride-apps)
