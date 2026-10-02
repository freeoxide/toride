# Changelog

All notable changes to this crate are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the crate
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
