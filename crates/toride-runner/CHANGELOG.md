# Changelog

All notable changes to this crate are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the crate
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-10-02

Initial crates.io release.

### Added

- Sync `Runner` trait with a `duct`-backed implementation (feature
  `duct-runner`, on by default) and injectable `FakeRunner` for tests
  (feature `fake`).
- `CommandSpec` command description with env, cwd, stdin, and timeout
  support, plus spec-level policy knobs for embedder postures:
  `EnvPrecedence` (explicit vs removal precedence), `PathResolution`
  (parent vs child-env PATH lookup, no working-directory search),
  `ArgvPolicy` (shell-metacharacter rejection), and `OutputCap`
  (opt-in bounded capture with kill-and-reap on breach).
- Async `AsyncRunner` trait and `TokioRunner` implementation behind the
  non-default `tokio-runner` feature; streaming output reads behind
  `stream`.
- Argument redaction for sensitive flags and PATH-based binary discovery.
- Serde support for the spec and output types behind the non-default
  `serde` feature.

[Unreleased]: https://github.com/freeoxide/toride/compare/toride-runner-v0.1.0...HEAD
[0.1.0]: https://github.com/freeoxide/toride/releases/tag/toride-runner-v0.1.0
