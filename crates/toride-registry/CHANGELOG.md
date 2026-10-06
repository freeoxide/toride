# Changelog

All notable changes to this crate are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the crate
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Lifecycle argv renders beside `Registry::plan`: `plan_update` and
  `plan_uninstall` mirror toride-apps' `Operation::argv` spellings
  (`brew upgrade/uninstall [--cask]`, `flatpak update/uninstall --user`,
  the per-family distro update/uninstall verbs, and the language
  managers' own verbs); updates keep install's gates minus the
  direct-download fallback, uninstalls skip the install-only claim gate,
  and `Direct` methods render `Unsupported` for both.
- The alias index (DESIGN.md §5, offline subset): `AliasIndex` maps the
  canonical id to per-source `SourceRef` rows (JSON-serializable,
  preloadable via `RegistryBuilder::with_alias_index`); `search` merges
  same-app hits across adapters into one row carrying every source's
  refs and records it, and `resolve` consults the index when every
  primary lookup misses.

## [0.1.0] - 2026-10-02

Initial crates.io release.

### Added

- Normalized `App` model with `TorideId`, `SourceRef`, platform claims,
  checksummed `Artifact`s, and `InstallMethod` descriptors.
- `Adapter` trait with a strict parse/fetch split: pure `&str` → `App`
  parsers (fixture-tested offline) and thin fetch clients.
- Source adapters for Homebrew (formula + cask, with a cached catalog
  index for search), Flathub, AppStream/DEP-11, and a parse-only
  Repology alias oracle.
- `Registry` facade: search fan-out with per-source error tolerance,
  resolve merging `SourceRef` rows, and per-platform `PlannedOp`
  rendering.
- Alias layer deriving the canonical `TorideId` and mapping it to
  per-source ids through the Repology-backed alias index.
- Sha256 and sha512 checksum modeling plus per-source verification
  policies marking unverifiable artifacts explicitly.
- The `http` feature carrying the fetch engine (reqwest, gzip, tokio) is
  off the default feature set; the default build is the pure parse half.

[Unreleased]: https://github.com/freeoxide/toride/compare/toride-registry-v0.1.0...HEAD
[0.1.0]: https://github.com/freeoxide/toride/releases/tag/toride-registry-v0.1.0
