# Changelog

All notable changes to this crate are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the crate
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-10-12

### Added

- Snap backend: `SnapInstall`/`SnapUninstall`/`SnapUpdate` plan
  operations, a `SnapBackend` executing them (listings via `SnapEntry`),
  `BackendId::Snap`/`NativeIds::Snap` native-id mapping, and
  `SnapBackend::detect` wiring — the builder auto-attaches a detected
  snap backend and the facade registers it behind a probe gate.
- Snap surface documented, with the read-only snap live probes gated
  behind `TORIDE_APPS_INTEGRATION=1`.

### Changed

- Snap default-channel resolution stated exactly; the README's pinning
  claim scoped to Homebrew.
- Release hygiene: keywords and categories metadata added across the
  publish set's crate manifests.

## [0.1.0] - 2026-10-02

Initial crates.io release.

### Added

- Pure planner turning registry `App`s plus a host `Target` into
  `InstallPlan`/`UninstallPlan`/`UpdatePlan` with canonical `Operation`
  argv for homebrew, flatpak, distro managers (apt, dnf, pacman, apk),
  npm, cargo, pipx, uv, mise, and direct downloads.
- `Backend` trait (async plus `_sync` twins) and executed backends:
  Homebrew, Flatpak, Distro, Npm, Cargo, Pipx, Uv, Mise (feature
  `mise`), and Direct (feature `direct`), all through the injectable
  `CommandRunner` seam with `FakeRunner` tests.
- `Apps` facade: ensure-installed (with version selection), uninstall,
  update with dry-run previews, status, search, adopt for unrecorded
  installs, available-version listing, and pin/unpin.
- Install manifest record store with quarantine-instead-of-halt recovery
  for corrupt prior documents, plus an injectable `RecordStore` seam.
- Multi-source `Detector` merging `$PATH`, mise-shim, and backend
  listing probes by canonical path with shadow/broken/arch flags.
- Sync `AppsBlocking` facade; the default dependency graph carries no
  tokio (`tokio`, `registry-http`, `direct`, and `mise` are all
  non-default features).

[Unreleased]: https://github.com/freeoxide/toride/compare/toride-apps-v0.2.0...HEAD
[0.2.0]: https://github.com/freeoxide/toride/releases/tag/toride-apps-v0.2.0
[0.1.0]: https://github.com/freeoxide/toride/releases/tag/toride-apps-v0.1.0
