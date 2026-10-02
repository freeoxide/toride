# toride-fs

Small filesystem utilities shared by the toride crates: atomic writes,
fd-based locking, path expansion, and permission audits. No features, no
optional dependencies.

- `atomic_write` / `atomic_write_bytes` / `atomic_write_with_perms` —
  temp-file-plus-rename writes with explicit POSIX modes on Unix.
- `with_lock` / `with_lock_path` — cross-process `fd-lock` coordination.
- `read_optional` / `read_optional_bytes` — missing file is `None`, not
  an error.
- `expand_tilde` / `expand_path` — `~` and `$VAR` path expansion.
- `check_not_world_writable` / `check_owner_is_root` — Unix permission
  audits.

```toml
[dependencies]
toride-fs = "0.1"
```

[Changelog](CHANGELOG.md) · [Source](https://github.com/freeoxide/toride/tree/master/crates/toride-fs)
