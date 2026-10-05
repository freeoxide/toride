# toride-installer

Tool-agnostic release-artifact installer: given a `Tool` description and
a target platform, it resolves the artifact URL, downloads it with a
byte cap, verifies the published digest (sha256 or sha512), extracts
gzip/xz tarballs or places binaries, and installs atomically with mode
`0o755`. No `curl | sh`.

The offline half — `Detector`, `ToolVersion`, `Freshness`, and the
`latest`/`LatestCache` probes — answers what is installed and how stale
it is without any network.

The `http` feature is **off the default set**: it carries the install
engine and everything needing reqwest, sha2, or gzip/xz extraction.
The default build is detection-only and free of C build scripts.

```toml
[dependencies]
toride-installer = { version = "0.1", features = ["http"] }
```

[Changelog](CHANGELOG.md) · [Source](https://github.com/freeoxide/toride/tree/master/crates/toride-installer)
