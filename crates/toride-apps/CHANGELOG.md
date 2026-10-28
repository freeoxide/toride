# Changelog

All notable changes to this crate are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the crate
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-10-12

### Added

- Snap backend: `SnapInstall`/`SnapUninstall`/`SnapUpdate` plan
  operations, a `SnapBackend` executing them (listings via `SnapEntry`),
  `BackendId::Snap`/`NativeIds::Snap` native-id mapping, and
  `SnapBackend::detect` wiring: the builder auto-attaches a detected
  snap backend and the facade registers it behind a probe gate.
- Snap surface documented, with the read-only snap live probes gated
  behind `TORIDE_APPS_INTEGRATION=1`.

### Changed

- Snap default-channel resolution stated exactly; the README's pinning
  claim scoped to Homebrew.
- Release hygiene: keywords and categories metadata added across the
  publish set's crate manifests.
- `Target::host()` refuses to compile on CPU architectures `Arch`
  cannot spell (riscv64, ppc64le, s390x, loongarch64, ...) instead of
  silently planning them as x86_64.
- Install records are keyed under the caller's requested id even when
  adapter resolution returns an app with a different id, so
  `status`/`uninstall` on the requested id read the record back.
- Exactly one presence probe per install: the backend's own post-install
  version evidence stands in for the facade's verify probe whenever it
  reports a version.
- Homebrew status answers through the kind-scoped
  `brew list --formula|--cask --versions` probes instead of the full
  `brew info --json=v2 --installed` store listing per query.
- The flatpak backend memoizes confirmed-present remotes per
  (installation, remote), so repeated installs in one process probe
  `flatpak remotes` at most once per pair.
- `update` consults snap's `refresh --list` stale signal (alongside
  brew's kind-scoped `outdated`) before deciding a record is current.
- Manifest saves serialize straight from the borrowed record snapshot;
  the two intermediate ledger deep clones per save are gone.
- `merge_by_canonical_path` computes each merge key once per detection
  instead of once per comparison (O(n) `fs::canonicalize` calls, was
  O(n^2)).
- The batch install verbs (`ensure_installed_many` and its blocking
  twin) share one foreign-presence listing per listing-backed backend
  (flatpak, npm, cargo, pipx, uv, mise) across the whole batch, so N
  unrecorded items pay one full listing instead of N; homebrew, snap,
  and distro keep their cheaper per-id probes.
- `RecordStore::save` takes the borrowed records map instead of a
  `&RecordSnapshot`, so the blocking facade's per-mutation save
  serializes straight from the working ledger with no snapshot clone
  (the `tokio` path keeps exactly the one clone it moves into the
  blocking task).
- Consumer-facing docs swept for em dashes and filler words.

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
