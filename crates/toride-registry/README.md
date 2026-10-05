# toride-registry

Normalizes external package registries — Homebrew (formulae.brew.sh),
Flathub, AppStream/DEP-11 distro catalogs, and Repology — into one `App`
model behind per-source `Adapter`s. Search, resolve, alias handling, and
install planning downstream see only `App`, `TorideId`, `SourceRef`, and
`InstallMethod`; all source-specific knowledge stays inside its adapter.

The `Registry` facade fans search out across the registered adapters
with per-source error tolerance, merges `SourceRef` rows on resolve, and
renders per-platform `PlannedOp`s. A Repology-backed alias index maps the
canonical toride id to per-source ids.

Artifacts carry sha256/sha512 digests where upstream publishes them, and
sources that cannot verify carry an explicit verification-policy marker
instead of an empty list — the signal an embedder needs to demand an
out-of-band digest.

The `http` feature is **off the default set**: it carries the fetch
clients (reqwest, gzip, and the tokio they ride). The default build is
the pure parse half — adapters fed with fixture or cached text, zero
network, zero tokio.

```toml
[dependencies]
toride-registry = { version = "0.1", features = ["http"] }
```

Design notes: [DESIGN.md](DESIGN.md).

[Changelog](CHANGELOG.md) · [Source](https://github.com/freeoxide/toride/tree/master/crates/toride-registry)
