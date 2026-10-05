# Changelog

All notable changes to this crate are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the crate
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-10-02

Initial crates.io release.

### Added

- Atomic file writes (`atomic_write`, `atomic_write_bytes`,
  `atomic_write_with_perms`) with temp-file-plus-rename semantics and
  explicit POSIX modes on Unix.
- Cross-process file locking over `fd-lock` (`with_lock`,
  `with_lock_path`).
- Optional reads (`read_optional`, `read_optional_bytes`) where a missing
  file is `None` rather than an error.
- Path expansion (`expand_tilde`, `expand_path`).
- Unix permission audits (`check_not_world_writable`,
  `check_owner_is_root`).

[Unreleased]: https://github.com/freeoxide/toride/compare/toride-fs-v0.1.0...HEAD
[0.1.0]: https://github.com/freeoxide/toride/releases/tag/toride-fs-v0.1.0
