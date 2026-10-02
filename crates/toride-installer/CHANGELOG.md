# Changelog

All notable changes to this crate are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the crate
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-10-02

Initial crates.io release.

### Added

- Declarative `Tool` config plus the `ReleaseResolver` trait mapping
  `(Target, version)` to an artifact URL; `tools::mise` is the wired
  concrete tool.
- `Installer` engine: capped reqwest download, digest verification
  (sha256, and sha512 for 128-hex digests) with a documented size-floor
  fallback, gzip/xz tarball extraction and binary placement, atomic
  `0o755` install.
- `Verifier::Strict`/`Verifier::Lenient` checksum policy over
  checksum-file parsing.
- Offline detection: `Detector`, `ToolVersion`, `Freshness`, and the
  `latest`/`LatestCache` probes with TTL caching.
- The `http` feature carrying the install engine is off the default
  feature set; the default build is detection-only with no C build
  scripts in its dependency graph.

[Unreleased]: https://github.com/freeoxide/toride/compare/toride-installer-v0.1.0...HEAD
