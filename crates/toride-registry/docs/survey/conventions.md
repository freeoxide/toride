# toride workspace conventions — survey brief

Scope: what a new crate in this workspace should look like, derived from the
root `Cargo.toml` and two sibling crates (`toride-installer`, `toride-mise`).
Every claim cites the file it was read from.

## 1. Crate skeleton (Cargo.toml)

Reference shapes: `crates/toride-installer/Cargo.toml`, `crates/toride-mise/Cargo.toml`.

Section order in both siblings:

1. `[package]` — `name`, then the workspace-inherited fields by reference:
   `version.workspace = true`, `edition.workspace = true`,
   `license.workspace = true`, `repository.workspace = true`
   (installer Cargo.toml:2-8; mise Cargo.toml:1-7). `description` is written
   per crate (one line). `rust-version` is optional: toride-installer pins
   `rust-version = "1.91"` (installer Cargo.toml:5), toride-mise omits it.
2. `[features]` — `default = [...]` first, then one line per feature. Feature
   gates pull optional deps with `dep:` syntax and carry a comment explaining
   *why* the gate exists (installer's `http` feature, Cargo.toml:10-20, exists
   so offline consumers avoid the C-build-script deps reqwest/ring and
   xz2/lzma-sys; mise gates `json`/`toml`/`diagnostics`/`tracing`/`bootstrap`/
   `miette`/`blocking`, mise Cargo.toml:9-17).
3. `[dependencies]` — workspace-managed deps are declared as
   `name = { workspace = true }` (e.g. `thiserror`, `camino`, `tokio`,
   installer Cargo.toml:23-40). Versions/features live centrally in the root
   `[workspace.dependencies]` (root Cargo.toml:12-46: serde with `derive`,
   tokio `full`, reqwest `default-features = false` + `json` + `rustls-tls`,
   etc.). Non-workspace or optional deps are pinned inline with a comment
   (`sha2 = { version = "0.10", optional = true }`, installer Cargo.toml:35).
   Sibling crates are path deps **with** an explicit version and the exact
   features needed: `toride-runner = { path = "../toride-runner",
   version = "0.1.0", features = ["duct-runner"] }` (installer Cargo.toml:34);
   `default-features = false` when the sibling's engine is unwanted
   (mise's `toride-installer` dep, mise Cargo.toml:26).
4. `[dev-dependencies]` — test-only; may re-enable features the normal build
   excludes (installer re-declares `toride-runner` with `"fake"`,
   Cargo.toml:42-46; mise dev-deps: `tempfile`, `insta`, `tokio`,
   mise Cargo.toml:47-51).
5. `[lints]` — always last, always exactly:

   ```toml
   [lints]
   workspace = true
   ```

   (installer Cargo.toml:48-49; mise Cargo.toml:53-54). The workspace defines
   `[workspace.lints.clippy]` as `pedantic = { level = "warn", priority = -1 }`
   plus `missing_docs_in_private_items = "allow"` (root Cargo.toml:48-50).

Workspace membership is the glob `members = ["crates/*", "crates/toride-ssh/crates/*"]`
(root Cargo.toml:2), so a new crate under `crates/` needs **no** root edit.
There is no `rustfmt.toml` or `clippy.toml` at the repo root (verified with
`ls`) — default rustfmt formatting, ~100-col budget (a test comment in
`crates/toride-installer/src/tools/mise.rs:507-508` explicitly works around
"the 100-column budget" using `concat!`).

## 2. Crate-level attribute block

Both crates open with the same block, immediately after the module `//!` docs:

```rust
#![deny(unsafe_code)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::module_name_repetitions)]
```

(`crates/toride-installer/src/lib.rs:97-101`). toride-mise adds one more,
`#![allow(clippy::return_self_not_must_use)]`
(`crates/toride-mise/src/lib.rs:23-28`) — its consume-and-return builders
return `Self` heavily. A new crate should copy the installer four and add the
fifth only if it has fluent builders.

## 3. Error module pattern

`src/error.rs` opens with `//! Error types for the <crate> crate.` (installer
error.rs:1; mise error.rs:1).

- **Alias + enum naming.** toride-installer uses the unprefixed pair —
  `pub type Result<T> = std::result::Result<T, Error>;` and `pub enum Error`
  (installer error.rs:4,14; re-exported as the crate's `Error`/`Result` at
  lib.rs:115). toride-mise, which has several error enums, prefixes: `MiseResult<T>`,
  `MiseError`, plus `ToolInstallError` and `ConfigError` (mise error.rs:112,116,227,287).
  Rule of thumb: one error enum → `Error`/`Result`; multiple → prefix with the
  crate noun.
- **Derives and attributes.** `#[derive(Debug, thiserror::Error)]`; one
  `#[error("...")]` per variant; `#[source]` for wrapped causes,
  `#[from]`/`#[error(transparent)]` for auto-conversions (installer
  error.rs:12-13,52-59,168-169; mise error.rs:158-159,221-222). Struct
  variants with named fields; **every field gets its own `///` doc**
  (installer error.rs:19-24). toride-installer's top-level `Error` is
  `#[non_exhaustive]` (error.rs:13); mise's are not — mirror whichever error
  surface you promise to keep stable.
- **Variant docs** name the pipeline stage and cross-link crate items with
  intra-doc links (`[`crate::Tool`]`, `[`crate::Installer::install`]`,
  installer error.rs:6-11). Variants may be `#[cfg(feature = "http")]`-gated
  when only the gated engine can produce them (installer error.rs:51).
- **Support machinery lives in the same module**: `From` impls grouped under a
  banner comment (mise error.rs:332-370), error-classification helpers
  (`FailureKind`, `classify_stderr`, mise error.rs:8-109), and methods on the
  error type (`MiseError::classify`, mise error.rs:376-393).
- Fallible public functions carry a `# Errors` doc section naming the concrete
  variants (mise tool/install.rs:283-286; installer tools/mise.rs:249-254).

## 4. Module organization

- `lib.rs` = crate docs → attribute block → `pub mod` declarations → re-export
  block. toride-installer declares flat file modules, feature-gating the ones
  that need the engine: `#[cfg(feature = "http")] pub mod extract;`
  (lib.rs:103-112), then a `// Re-exports — the public API surface.` section
  (lib.rs:114-131) flattening the API: `pub use error::{Error, Result};` etc.
- toride-mise groups declarations under `// ---` banner comments: "file
  modules" then "directory modules" then "Re-exports" (lib.rs:30-71).
- Directory modules have `mod.rs` plus one file per verb/domain
  (`src/tool/{install,registry,remote,uninstall,upgrade,…}.rs`,
  `src/languages/{node,python,…}.rs`) — listing verified with `ls -R`.
- Feature-gated items repeat `#[cfg(feature = "http")]` on every item (struct,
  impl block, helper fn) rather than relying on module gating alone
  (installer tools/mise.rs:37-52,112,208,229,255).
- Registry files (`src/tools.rs`, installer tools.rs:1-9) are thin `pub mod`
  lists with a `//!` doc explaining how a new entry wires in.

Inside long files, sections are delimited with the banner idiom:

```rust
// ---------------------------------------------------------------------------
// SectionName
// ---------------------------------------------------------------------------
```

(mise client.rs:29-33, tool/install.rs:11-14, error.rs:3-5).

## 5. Doc-comment style and density

- **Every `pub` item is documented** (pedantic is `warn`, and only private-item
  docs are allowed to be missing). Private consts with non-obvious rationale
  are documented too (installer installer.rs:92-93 `PROGRESS_EMIT_STEP`).
- **Module-level `//!` docs** follow a template: `# <Crate/Module name>` title,
  prose summary, a bulleted "split / provides" list, `## Design` or
  `## Pipeline` (numbered stage list), and a `## Quick start` / `# Quick start`
  section with a fenced doctest marked `rust,ignore` (installer lib.rs:1-95 —
  five numbered pipeline stages; mise tools/mise.rs:1-35; mise client.rs:1-15).
  Doctests that would need the real `mise` binary or network are
  `rust,ignore`, not compiled.
- Function docs: one-line summary, then paragraphs explaining *why* and
  behaviour contracts; `# Errors` sections; `# Example` blocks. `#[must_use]`
  on pure constructors (`mise_tool`, tools/mise.rs:91).
- Inline `//` comments record *evidence and rationale*, including live
  verification ("verified against the live v2026.9.15 release",
  tools/mise.rs:10-12) and ordering constraints (mise error.rs:97-98).
- Constants get docs that state units/policy, not just the value
  (installer installer.rs:54-83: `DEFAULT_MAX_BYTES`, size floor, three
  timeout consts each with a why-paragraph).

## 6. Builder patterns in use

- **Hand-rolled consume-and-return builders** are the default. `MiseBuilder`
  states the pattern in its module doc ("each setter consumes `self`, applies
  the configuration, and returns a new `Self`", mise builder.rs:5-8);
  `InstallerBuilder` is a tiny private-field struct (`max_bytes`, `min_bytes`,
  `verifier`) with `new()` + chained setters + `build()`
  (installer installer.rs:830-848); `DetectorBuilder` is reached via
  `Detector::builder()` (installer status.rs:321-324, used at
  tools/mise.rs:310-314).
- **Request structs** for CLI-shaped operations: plain
  `#[derive(Debug, Clone, Default)]` struct with public fields, a
  `new(impl IntoIterator<Item = impl Into<String>>)` constructor that fills the
  rest from `..Self::default()`, and one fluent consuming setter per field
  (`InstallRequest`, `UseRequest` in mise tool/install.rs:33-139,177-269).
  Bool-heavy request structs carry
  `#[allow(clippy::struct_excessive_bools)]` (tool/install.rs:36,148;
  client.rs:118).
- `typed-builder` exists in `[workspace.dependencies]` (root Cargo.toml:44) and
  is used for compile-time-checked builders in `toride-fail2ban`
  (`crates/toride-fail2ban/src/spec.rs:628`), but **neither surveyed crate uses
  it** — prefer the hand-rolled pattern for new crates unless compile-time
  required-field checking is needed.

## 7. Test style

- **Inline `#[cfg(test)] mod tests` at the bottom of each source file** is the
  primary style (installer tools/mise.rs:335; mise tool/install.rs:482; mise
  error.rs:399 — note non-`tests` names like `failure_kind_tests` are fine).
  Large modules split by feature gate: installer installer.rs:905
  `mod tests` (ungated) and :1080 `mod engine_tests`; mise.rs adds
  `#[cfg(all(test, feature = "http"))] mod resolver_tests` (tools/mise.rs:359).
  Tests use `#[tokio::test]` for async, plain `#[test]` for sync;
  `.unwrap()`/`.expect()` are normal inside tests.
- **`tests/` directory** holds cross-unit and gated suites. toride-mise:
  `tests/{fixtures.rs,integration.rs,snapshots.rs,expensive.rs}` with a
  crate-root `fixtures/` dir and `tests/snapshots/` for insta snapshots
  (`fixtures__env_basic_json.snap` naming). toride-installer: a single
  `tests/integration.rs`.
- **Fixtures are loaded at runtime via `env!("CARGO_MANIFEST_DIR")`**, not
  `include_str!`: a `fixtures_dir()` helper built from
  `Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures"))` plus panicking
  `read_fixture` / `parse_fixture::<T: DeserializeOwned>` helpers
  (mise tests/fixtures.rs:18-38). No `include_str!` fixture loading was found
  in either crate (grep across both crates). Follow this shape for the
  registry crate: a crate-root `fixtures/` dir (toride-registry already has
  `tests/fixtures/homebrew/*.json`) + a manifest-dir-anchored helper.
- **Snapshot tests** use `insta` (workspace dep, root Cargo.toml:26); each test
  parses a fixture and asserts a snapshot (mise tests/fixtures.rs doc, :1-6).
- **Env-gated network tests**: `<CRATE>_INTEGRATION=1` —
  `TORIDE_INSTALLER_INTEGRATION` and `TORIDE_MISE_INTEGRATION`. The pattern:
  file-level `#![cfg(feature = "http")]` (installer tests/integration.rs:16),
  a `should_run()` helper `matches!(env::var("TORIDE_MISE_INTEGRATION")
  .as_deref(), Ok("1"))` (mise tests/integration.rs:23-28; installer
  tests/integration.rs:26-28), and a per-test early return that
  `eprintln!`s a skip notice (installer tests/integration.rs:61-64; inline at
  installer installer.rs:1255-1261). The `//!` module docs document the exact
  run command (`TORIDE_INSTALLER_INTEGRATION=1 cargo test -p toride-installer
  --test integration`, tests/integration.rs:6-8) and any PATH-scrubbing
  caveat (:151-155). Known-good pinned versions are named consts
  (`PINNED_VERSION = "2026.6.14"`, tests/integration.rs:102).
- **Fake-runner tests**: mise tests build the client with
  `toride_runner::FakeRunner` — `push_response(CommandOutput::from_stdout(..))`
  for loose matching, or `.strict().respond(spec, output)` plus
  `assert_no_unmatched_calls()` / `assert_called_with(&spec)` for exact
  command assertions (mise tool/install.rs:490-508,591-631). A local
  `build_mise(Arc<FakeRunner>)` helper constructs the unit under test
  (:490-496).
- **Test names** are snake_case behaviour sentences
  (`pinned_version_resolves_to_direct_url_no_network`, tools/mise.rs:571;
  `lockfile_not_found_classified_correctly`, mise error.rs:515). mise's
  install tests prefix `test_` (tool/install.rs:499) — both styles are
  accepted; keep one per module.

## 8. Naming conventions

- Crates `toride-<domain>` under `crates/` (ls of `crates/`); lib targets
  snake_case. Repo `README`/CLAUDE.md confirm the workspace split.
- Errors: `Error`/`Result` (single-enum crate) or `<Noun>Error`/`<Noun>Result`
  (`MiseError`, `MiseResult`); sub-errors are specific
  (`ToolInstallError`, `ConfigError`).
- Constants `SCREAMING_SNAKE_CASE`, documented (`MISE_REPO`, `MISE_BIN_NAME`,
  `SHASUMS_FILE`, tools/mise.rs:55-80); `cfg`-split consts for
  platform differences (`#[cfg(windows)] MISE_BIN_NAME = "mise.exe"`,
  tools/mise.rs:62-68).
- Constructors `new()`; builder entry `builder()`; per-tool convenience verbs
  `<verb>_<tool>` (`install_mise`, `ensure_mise`, `mise_tool`,
  tools/mise.rs:92,256,303).
- Features lowercase single words (`http`, `json`, `toml`, `bootstrap`,
  `blocking`).
- Public path APIs use `camino::Utf8PathBuf`, not `std::path::PathBuf`
  (both crates' signatures, e.g. tools/mise.rs:256).
- Flexible params: `impl Into<String>`, `impl Into<Utf8PathBuf>`,
  `impl IntoIterator<Item = impl Into<String>>` (tool/install.rs:67,99,179).
- Edition-2024 idioms in use: let-chains
  (`if let Some(ref x) = req.env_name && !matches!(...)`, tool/install.rs:391-393),
  `concat!(.., env!("CARGO_PKG_VERSION"))` user agents (tools/mise.rs:80,
  installer installer.rs:107), format-string captures (`{url}`, `{tool}`).
- `#[non_exhaustive]` on the public error enum when variants may grow
  (installer error.rs:13).
