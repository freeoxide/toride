# Changelog

All notable changes to this crate are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the crate
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-10-02

Initial crates.io release.

### Added

- `Mise` client with `MiseBuilder` injection of the runner seam; all
  operations require a mise binary on the host and degrade to typed
  errors otherwise.
- Tool lifecycle: install (with version pinning and options), upgrade
  (dry-run and bump flags), uninstall, outdated queries, and installed
  listings.
- `ToolSpec`/`VersionRequest` addressing, `ToolSpec::parse` for
  `tool@version` strings, per-language helpers under `languages`.
- Project support: `MiseProject`, `RuntimeManager`, lockfile and
  `mise.toml` config parsing, env/export state, and `exec` streaming.
- `MiseBinary`/`MiseVersion` discovery plus optional mise bootstrap via
  toride-installer behind the non-default `bootstrap` feature.
- Feature set: `json`, `toml`, `diagnostics` by default; `tracing`,
  `bootstrap`, `miette`, and `blocking` off the default set.

[Unreleased]: https://github.com/freeoxide/toride/compare/toride-mise-v0.1.0...HEAD
