# Setup Bundles — declarative, OS-conditional, license-labeled toolchain setup recommendations

Status: PLAN — not yet implemented. Authored 2026-10-12 from the
`.z-flashflow` research pass (web evidence in
`.z-flashflow/evidence/research/*.md`, every ecosystem/license claim carries
a source URL + verified date) and the repo-grounding pass
(`.z-flashflow/evidence/repo/interface-notes.md`, 260 `path:LINE` citations,
gate-verified 260/260 rounds r2–r3).

Machine gate for this document (run from repo root; read-only):
`bash scripts/check_plan_citations.sh` — verifies every `crates/*.rs|toml:LINE`
citation resolves, the license table is complete, and every section below is
present.

The feature: when a user opens the Setup section, toride proposes curated
per-ecosystem tool bundles (Rust companions, Node, Python, Ruby/PHP/Go,
containers, IaC, QoL CLI, version managers). Seed examples that motivate the
shape: sccache offered next to a Rust setup (with its `rustc-wrapper`
config step), and on macOS OrbStack offered over Docker Desktop **with
explicit paid-for-commercial labeling**. Every recommendation carries a
machine-readable license label whose load-bearing axis is commercial use;
nothing non-free installs without consent; the FOSS alternative is the
default pick.

## 1. Goal and non-goals

### Goals

- G1 — Curated opt-in suggestions: a static, compiled-in bundle registry
  (8 bundles) evaluated against the live host; suggestions are separate
  from, and never conflated with, the expected-tool doctor findings.
- G2 — License labeling as a first-class type: `LicenseKind` with
  commercial-use as the deciding axis; `requires_consent` on anything that
  is not `Free`; consent dialog links the terms/pricing URL and shows the
  verified date per entry.
- G3 — FOSS-default: inside each bundle the default-selected
  recommendation is the free/open-source one (colima/Podman over OrbStack,
  OpenTofu over Terraform); non-free rows are opt-in by explicit click.
- G4 — OS- and state-conditional: conditions evaluate at plan time from
  `Target::host()` plus tool-presence results; already-present tools are
  never offered.
- G5 — Everything routes through existing machinery: plans are built with
  toride-apps' planner, executed by existing backends, and recorded in
  `InstallManifest` so later update/uninstall work. Config-only steps go
  through toride-fs atomic writes, shown before anything is written.
- G6 — Recommendation-vs-finding separation: expected-tool findings stay
  warn-level; bundle hints are info-level, dismissible.

### Non-goals

- N1 — No new install backend. `BackendId` already spans
  brew/flatpak/snap/distro/npm/cargo/pipx/uv/mise/direct
  (`crates/toride-apps/src/backend.rs:44`, `#[non_exhaustive]`).
- N2 — No auto-install, no background daemons, no auto-sudo. Backends
  refuse elevated work unless the request explicitly grants it
  (`crates/toride-apps/src/backend.rs:109`); nothing in this feature
  flips that.
- N3 — No license counseling beyond label + terms URL + consent gate.
- N4 — No corepack-based Node setup: corepack is not bundled in Node ≥ 25
  and mise installs package managers itself
  (https://raw.githubusercontent.com/nodejs/corepack/main/README.md and
  https://mise.jdx.dev/lang/node.html, both verified 2026-10-12).
- N5 — No volta anywhere (README states "Volta is unmaintained";
  https://github.com/volta-cli/volta, verified 2026-10-12). No tfsec
  (deprecated, consolidated into Trivy;
  https://github.com/aquasecurity/tfsec, verified 2026-10-12). No sold
  (mold's archived Mach-O fork;
  https://api.github.com/repos/bluewhalesystems/sold, archived, verified
  2026-10-12).
- N6 — No mold on macOS: mold is ELF/Linux in practice; the macOS
  fast-linker advice is Xcode 15+'s default linker or lld
  (https://raw.githubusercontent.com/rui314/mold/main/README.md, verified
  2026-10-12).
- N7 — No wholesale edits to existing user config files in v1 (see
  `ConfigHint::on_exists` — skip-and-show, never overwrite or append).
- N8 — No Windows recommendations in v1 (mise's own Windows story is
  native-only-for-supported-tools; bundle tables stay macOS+Linux).

## 2. Survey checklist — verified repo facts

Every line below was verified in the working tree on 2026-10-12 via
`.z-flashflow/evidence/repo/interface-notes.md` (gate: 260/260). Facts are
grouped by the subsystem the plan builds on.

### 2.1 Tool catalogue + collector (the pattern to mirror)

- `crates/toride/src/tools_convert.rs:27` — `ToolSpec` struct (`Clone, Debug`); fields name/category/binaries/expected.
- `crates/toride/src/tools_convert.rs:33` — binaries: alias list tried in order, first PATH hit wins.
- `crates/toride/src/tools_convert.rs:49` — `catalogue()` -> `Vec<ToolSpec>`, runtime-built (`Vec<String>` needs allocation, not const).
- `crates/toride/src/tools_convert.rs:109` — `expected: true` is hardcoded for every catalogue entry today.
- `crates/toride/src/tools_convert.rs:134` — finding id built as `tools.missing.<name>` (dot-separated, canonical name).
- `crates/toride/src/tools_convert.rs:136` — severity is the literal string `"warning"` (not an enum) on every tools finding.
- `crates/toride/src/tools_data.rs:38` — `ToolsCollector`: oneshot rx + cached_bundle + bundle_fresh_at.
- `crates/toride/src/tools_data.rs:44` — `SWEEP_TTL` = 60s; the whole sweep (rows+counts+findings) is cached.
- `crates/toride/src/tools_data.rs:141` — `collect_real_tools` runs the catalogue walk inside `spawn_blocking`.
- `crates/toride/src/tools_data.rs:152` — `Detector::builder().probe_timeout(VERSION_TIMEOUT).build()` — how the collector invokes toride-installer's Detector.
- `crates/toride/src/tools_data.rs:192` — `VERSION_TIMEOUT` = 800ms per-probe cap.
- `crates/toride/src/tools_data.rs:202` — detect_entry tries `spec.binaries` in order, calling detector.detect per alias.

### 2.2 Planner, Target, plans

- `crates/toride-apps/src/plan.rs:104` — `Target { os, arch, distro: Option<DistroFamily> }` — the host descriptor.
- `crates/toride-apps/src/plan.rs:151` — `host()` derives os/arch from compile-time cfg; distro stays None (backend fills from os-release).
- `crates/toride-apps/src/plan.rs:285` — `Operation` enum, `#[non_exhaustive]`: Brew/Flatpak/Snap/Distro/Npm/Cargo/Pipx/Uv/Mise/Direct Install+Uninstall (+Update verbs).
- `crates/toride-apps/src/plan.rs:528` — `Operation::argv()` renders the canonical command, program first.
- `crates/toride-apps/src/plan.rs:755` — `InstallOptions { version: Option<Version> }`; version spells into native addressing.
- `crates/toride-apps/src/plan.rs:793` — `InstallPlan { app, backend, operation, dry_run, requires_elevation }`, Eq+Serialize.
- `crates/toride-apps/src/plan.rs:802` — `dry_run: true` makes every backend refuse execution.
- `crates/toride-apps/src/plan.rs:806` — `requires_elevation`: distro managers only; toride never auto-sudoes.
- `crates/toride-apps/src/plan.rs:829` — `summary(&self)` human dry-run line (`[backend] desc (would run: …)`).
- `crates/toride-apps/src/plan.rs:1000` — `plan_install(&App, &Target, &InstallOptions) -> Result<InstallPlan>`: availability gate + platform-claims gate, then method routing; all refusals at plan time.
- `crates/toride-apps/src/plan.rs:915` — `UpdatePlan` is built from the manifest record's identifiers, never re-planned from registry data.

### 2.3 Manifest (the recording surface)

- `crates/toride-apps/src/manifest.rs:265` — `InstallRecord { backend, ids, version, installed_at, plan }`.
- `crates/toride-apps/src/manifest.rs:290` — `new(plan:, ids, version)` post-verify constructor; derives backend from ids.
- `crates/toride-apps/src/manifest.rs:305` — `adopted(ids:, version)` records a claimed-not-executed install (plan: None).
- `crates/toride-apps/src/manifest.rs:367` — `InstallManifest { path, entries: BTreeMap<TorideId, InstallRecord> }` — deterministic id order.
- `crates/toride-apps/src/manifest.rs:394` — `default_path()` = data_dir/toride/apps-manifest.json.
- `crates/toride-apps/src/manifest.rs:469` — `record(&mut self, id, record)` insert-or-replace keyed by explicit TorideId.
- `crates/toride-apps/src/manifest.rs:475` — `remove(&mut self, id)` post-uninstall bookkeeping.
- `crates/toride-apps/src/manifest.rs:514` — `save()` is atomic (temp-file-in-same-dir + rename) but lock-free (last-rename-wins).

### 2.4 Detection — two Detectors, one name collision (must-qualify)

- `crates/toride-installer/src/status.rs:351` — toride-installer `Detector::detect(&self, tool: &Tool) -> ToolStatus`; $PATH first, then managed install dir; never errors, never network.
- `crates/toride-installer/src/status.rs:179` — installer `ToolStatus` enum: NotInstalled | OnPath | Managed.
- `crates/toride-installer/src/status.rs:212` — `is_installed(&self) -> bool`.
- `crates/toride-installer/src/status.rs:313` — `with_runner(runner)` — the injection seam used by tests (FakeRunner).
- `crates/toride-installer/src/status.rs:42` — documented name collision: toride-mise exports its own `ToolStatus` with a different meaning; qualify imports.
- `crates/toride-apps/src/detect.rs:161` — toride-apps `trait Detector { detect(&self, target: &str) -> Vec<Detection> }` — DISTINCT trait, different crate, different signature.

The TUI side of the house uses the toride-installer Detector
(`crates/toride/src/tools_data.rs:152`); setup bundles use exactly that one
and never toride-apps' multi-source Detector in the UI path.

### 2.5 Backends + registry (routing + the license gap)

- `crates/toride-apps/src/backend.rs:44` — `BackendId` enum, `#[non_exhaustive]`, Clone+Copy+Serialize+Deserialize.
- `crates/toride-apps/src/backend.rs:46` — Homebrew variant (casks + formulae).
- `crates/toride-apps/src/backend.rs:98` — `InstallRequest<'a>` (Copy): plan + target + elevated.
- `crates/toride-apps/src/backend.rs:328` — `Backend` trait: Send + Sync, `#[async_trait]`, mandatory _sync twins.
- `crates/toride-apps/src/backend.rs:635` — `ensure_install_allowed`: refuses DryRun, then ElevationRequired (no auto-sudo).
- `crates/toride-apps/src/backends/homebrew.rs:431` — `BackendId::Homebrew` routing id (note: the file is `backends/homebrew.rs`, there is no `brew.rs`).
- `crates/toride-apps/src/backends/mise.rs:83` — helper.install(version) then use_global — install + `mise use --global`.
- `crates/toride-apps/src/backends/mod.rs:14` — homebrew module registered (flat pub mod + re-export registry; a new backend would wire in here).
- `crates/toride-registry/src/model.rs:139` — `App` struct — the only normalized shape the planner accepts (plan_install takes `&App`).
- `crates/toride-registry/src/model.rs:154` — `license: Option<String>` — SPDX where the source publishes one.
- `crates/toride-registry/src/model.rs:160` — `binaries: Vec<String>` — the tool-detection join key.
- `crates/toride-registry/src/model.rs:171` — `install: InstallMethod` — primary install descriptor the planner routes on.
- `crates/toride-registry/src/model.rs:513` — `InstallMethod::Mise`'s `tool` field documents backend-prefix addressing (`node`, `npm:prettier`, `cargo:ripgrep`).
- `crates/toride-registry/src/sources/repology.rs:126` — repology lists licenses among wire fields but does NOT map them into `App::license` — repology-only apps carry no license.

That last line is why the license label is a curated static field on the
bundle row, not a join against `App::license`.

### 2.6 fs helpers (ConfigHint application surface)

- `crates/toride-fs/src/atomic.rs:50` — `atomic_write(path, content)` — atomic + fsynced text write.
- `crates/toride-fs/src/expand.rs:29` — `expand_tilde(path)` — leading-`~` expansion.
- `crates/toride-fs/src/read.rs:21` — `read_optional(path)` — missing file = None, not error.
- `crates/toride-fs/src/lock.rs:30` — `with_lock(path, f)` — file-locked critical section (available if v2 ever appends).

### 2.7 UI wiring — Sections, not Screens

- `crates/toride/src/data/mod.rs:85` — `Section` enum — the sidebar registry that switches dashboard content areas.
- `crates/toride/src/data/mod.rs:131` — `label(self)` — the sidebar label match to extend.
- `crates/toride/src/navigation/mod.rs:13` — `Screen` enum: today only Welcome=0 and Dashboard=1 — sections are NOT screens.
- `crates/toride/src/ui/screens/mod.rs:46` — `AppScreen` trait (handle_key/handle_mouse/view/…) — Dashboard implements it; content structs do not.
- `crates/toride/src/ui/screens/tools/mod.rs:66` — `ToolsContent` — THE pattern: read-only content struct, `set_*` setters fed by a collector, no writes.
- `crates/toride/src/ui/screens/tools/mod.rs:48` — `FindingEntry { id, severity, title }` (plain strings; Clone+Debug).
- `crates/toride/src/ui/screens/tools/mod.rs:328` — tools screen filters findings with `starts_with("tools.missing.")`.
- `crates/toride/src/ui/screens/tools/mod.rs:407` — `SectionOverview for ToolsContent` — in-module overview impl.
- `crates/toride/src/ui/screens/section_overview.rs:39` — `SectionOverview` trait — uniform read over read-only section content.
- `crates/toride/src/ui/screens/section_overview.rs:50` — `findings_count(&self)` — sidebar badge consumption.
- `crates/toride/src/ui/screens/section_overview.rs:60` — `status_label_for` — shared severity->label mapping.
- `crates/toride/src/ui/screens/dashboard.rs:854` — `set_tools_data(&mut self, b: ToolsDataBundle)` — how a data bundle reaches dashboard content structs.
- `crates/toride/src/app/mod.rs:605` — `tools_collector.poll()` matched in the App event loop.
- `crates/toride/src/app/mod.rs:606` — `dashboard.set_tools_data(b)` on completion.
- `crates/toride/src/app/mod.rs:678` — `tools_collector.start()` on section entry — the kickoff a Setup section mirrors.
- `crates/toride/src/ui/widgets/mod.rs:15` — badge helpers incl. `tag_badge` (license badges fit it).
- `crates/toride/src/ui/widgets/modal.rs:78` — `Modal` struct (consent dialog).
- `crates/toride/src/ui/widgets/mod.rs:21` — `InteractiveModal`, `ModalEvent` exported from interactive_modal.
- `crates/toride/src/action.rs:5` — `Action` enum (Copy) — semantic intents; no new variants expected for v1.

### 2.8 Workspace / Cargo shape

- `crates/toride/Cargo.toml:45` — toride-fs dependency (already present in the TUI crate).
- `crates/toride/Cargo.toml:62` — toride-mise dependency with features json,toml,diagnostics,tracing.
- `crates/toride/Cargo.toml:71` — toride-installer dependency (the Detector the catalogue already uses).
- `crates/toride/Cargo.toml:73` — `[dev-dependencies]` section starts here (insta, tempfile, toride-runner `fake` already dev-pinned below it).
- `crates/toride-apps/Cargo.toml:17` — `tokio = ["dep:tokio"]` optional feature.
- `crates/toride-apps/Cargo.toml:24` — `direct = ["dep:toride-installer", "tokio"]` feature.
- `crates/toride-apps/Cargo.toml:28` — `mise = ["dep:toride-mise", "toride-runner/tokio-runner"]` feature (carries tokio).
- `crates/toride-apps/src/apps.rs:621` — `Apps` facade struct (builder + blocking twin) — the high-level entry for executing installs.
- `crates/toride-apps/src/lib.rs:177` — apps module list (apps/backend/backends/detect/error/manifest/plan/runner/status/store).

Hard constraint honored by this plan: **crates/toride has NO toride-apps
dependency today** and toride-apps' default feature set is tokio-free —
adding the dep is a deliberate decision made in §5 below, not an accident.

## 3. Decision — placement, API shape, rejected alternatives

### 3.1 Placement

**Decision: the bundle registry and evaluation live in the toride crate, as
two new modules following the house `*_convert`/`*_data` pairing:**

- `crates/toride/src/setup_bundles.rs` — the static registry + data model +
  evaluation + consent gate + ConfigHint application (pure logic; the only
  I/O is hint application through toride-fs).
- `crates/toride/src/setup_data.rs` — `SetupCollector` (mirrors
  `ToolsCollector`: oneshot rx + 60s-cached bundle, spawn_blocking walk)
  and the conversion of offers into info-level `FindingEntry`s.

The TUI surface is a `Section::Setup` variant + `SetupContent` struct
rendered inside DashboardScreen (the `ToolsContent` pattern) — NOT a new
`Screen` variant, which today holds only Welcome/Dashboard.

Rejected alternatives:

1. **Put bundles in toride-apps.** Rejected: bundles are product/UX data
   (labels, consent, dismissibility, curated rationale) and would drag UI
   vocabulary into the install library whose default graph is deliberately
   tokio-free. The types are `Serialize`, so a later move into a shared
   crate is mechanical if a CLI frontend ever wants the same registry.
2. **New `toride-bundles` workspace crate.** Rejected: single consumer, no
   reuse; every existing per-feature data layer lives inside the toride
   crate as `*_convert`/`*_data` pairs (see §2.1, §2.8).
3. **Derive labels from `App::license` at runtime.** Rejected: repology
   (a registry source) maps no license into `App::license`, so coverage is
   source-dependent and not guaranteed offline-present; the label is
   load-bearing (it gates installs) so it must be a curated, dated, static
   field. `App::license` may be displayed as corroboration when present,
   never as the source of truth.
4. **A new AppScreen for setup.** Rejected: the Screen enum has exactly two
   variants and every feature area (Tools, Ssh, Mise, …) is a Section
   variant + content struct; a new screen would fork navigation.
5. **Merge bundle suggestions into the tools findings stream as warnings.**
   Rejected: `expected: true` is hardcoded across the catalogue and its
   findings are literally `"warning"` severity with `tools.missing.*` ids;
   bundling opt-in suggestions into that stream would break the "expected"
   contract and spam every doctor consumer. Suggestions get their own
   `setup.suggest.*` id space at info severity, dismissible.

### 3.2 Type disambiguation (the two-Detectors / ToolStatus problem)

- Bundle evaluation uses ONLY `toride_installer::status::Detector` (the
  `Tool -> ToolStatus` offline detector the catalogue already drives).
  `toride_apps::detect::Detector` (`&str -> Vec<Detection>`, multi-source)
  is out of scope for the UI path.
- Every import is qualified at use sites:
  `use toride_installer::status::{Detector as InstallerDetector, ToolStatus as InstallerToolStatus};`
  — toride-mise also exports a `ToolStatus` (different meaning) and toride
  already depends on toride-mise; the collision is documented at
  `crates/toride-installer/src/status.rs:42`.

### 3.3 The license axis (centerpiece)

`LicenseKind` classifies along **commercial use**, not copyleft-vs-
permissive (GPL tools are free for commercial use — they get `Free` with a
distribution-obligations note). Verified 2026-10-12 anchors:

- **OrbStack**: proprietary freemium; free for personal/non-commercial use;
  commercial requires Pro at $8/user/mo ($96/yr)
  (https://orbstack.dev/pricing) → `PaidForCommercial`. This is the row the
  user's seed example demanded be labeled loudly.
- **Docker Desktop**: free only while the business has fewer than 250
  employees AND less than $10M annual revenue
  (https://docs.docker.com/subscription/desktop-license/) →
  `FreeWithTerms` with the thresholds in the summary string. Note the
  asymmetry the labels must surface: Docker Desktop is free for many small
  businesses where OrbStack is already paid.
- **Terraform**: BUSL 1.1 since 1.6.0 (licensor IBM); production use
  allowed, competing hosted/embedded offerings forbidden
  (https://raw.githubusercontent.com/hashicorp/terraform/main/LICENSE);
  **OpenTofu** is the MPL-2.0 Linux-Foundation fork
  (https://github.com/opentofu/opentofu) → OpenTofu is the bundle's
  default pick; Terraform is `FreeWithTerms` + consent.
- **mold**: MIT since 2.0, ELF/Linux only
  (https://github.com/rui314/mold) → Linux-only recommendation, `Free`.
- **cargo-binstall / fnm / golangci-lint**: GPL-3.0(-only), commercial use
  unrestricted (https://crates.io/api/v1/crates/cargo-binstall,
  https://github.com/Schniz/fnm, https://github.com/golangci/golangci-lint)
  → `Free`, with the distribution-obligations note.

Every row of the table in §4.7 carries its terms URL + verified date; the
consent dialog renders exactly those.

### 3.4 Install routing decisions

- Actions are **backend-native identifiers** (brew cask/formula token,
  npm package, cargo crate, distro package, `InstallMethod::Mise` tool
  string) — verifiable from the row itself. mise **registry shorthand**
  existence (`sccache`, `mold`, `uv`, …) was audit-scoped as
  UNVERIFIED-BY-AUDIT in the research pass; where a mise route is used it
  must be re-verified at implementation time (Risk R6), and backend-prefix
  addressing (`cargo:sccache`) is preferred over shorthand claims because
  the prefix syntax is documented on the method itself
  (`crates/toride-registry/src/model.rs:513`).
- Per-OS route splits are separate recommendations with their own
  conditions (macOS brew vs Linux distro/mise), never one row with
  hidden per-OS branching — keeps consent and dismissal per visible row.
- Routes research explicitly fixed: cargo-nextest has no mise shorthand
  (brew `cargo-nextest` or `cargo:` prefix); composer is not mise-managed
  (Linux distro package only in v1; macOS route unverified → excluded);
  gopls/Go CLIs should route through mise's `go:` backend because
  `go install` binaries die with the Go toolchain
  (https://mise.jdx.dev/lang/go.html, verified 2026-10-12).

## 4. Public API (Rust sketches)

All in `crates/toride/src/setup_bundles.rs` unless noted. Edition-2024
idioms, workspace clippy pedantic; serde on the data types so the registry
can later move or persist; `&'static str` for all curated strings (the
registry is compiled in, mirroring `ToolSpec`'s `&'static str` fields).

### 4.1 LicenseKind + LicenseInfo

```rust
/// Commercial-use axis of a tool's license — the load-bearing label.
/// Anything that is not [`LicenseKind::Free`] sets `requires_consent()`
/// and blocks install until the user accepts the linked terms.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
pub enum LicenseKind {
    /// Unrestricted commercial use. GPL tools land here too — distribution
    /// obligations exist, use does not. `LicenseInfo.note` says so.
    Free,
    /// Free for personal/non-commercial use only.
    FreePersonal,
    /// Requires payment for ANY commercial use (OrbStack Pro: $8/user/mo).
    PaidForCommercial,
    /// Free for commercial use under stated conditions (Docker Desktop
    /// head-count/revenue thresholds; Terraform BUSL competing-offering ban).
    FreeWithTerms,
}

impl LicenseKind {
    /// The single gate the install path consults.
    #[must_use]
    pub const fn requires_consent(self) -> bool {
        !matches!(self, Self::Free)
    }
}

/// The full label rendered by the consent dialog.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LicenseInfo {
    pub kind: LicenseKind,
    /// SPDX expression where the project publishes one (`None` for
    /// proprietary rows); mirrors `App::license`'s shape but is curated,
    /// never joined at runtime.
    pub spdx: Option<&'static str>,
    /// Human one-liner incl. the exact condition ("free < 250 employees
    /// AND < $10M annual revenue").
    pub summary: &'static str,
    /// Terms/pricing page the consent dialog links.
    pub terms_url: &'static str,
    /// `YYYY-MM-DD` the classification was last verified against the URL.
    pub verified: &'static str,
}
```

### 4.2 Condition (plan-time, host + presence)

```rust
/// When a recommendation applies. Evaluated eagerly at plan time — the
/// registry holds data, not closures, so evaluation is snapshot-testable.
/// `Os`/`DistroFamily` are the very enums `Target` carries
/// (toride-apps plan.rs:104; `Os::{MacOs, Linux, Windows}` per the
/// registry model), reached through whatever toride-apps re-exports.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
pub enum Condition {
    /// Host OS gate (e.g. macOS for the containers bundle's GUI rows).
    Os(Os),
    /// Linux host of this distro family (`Target::distro`, filled by the
    /// distro backend from os-release — None means unknown).
    Distro(DistroFamily),
    /// The named tool's binaries were not found by the presence check.
    Missing { tool: &'static str },
    /// Every sub-condition holds.
    All(Vec<Condition>),
}

impl Condition {
    #[must_use]
    pub fn holds(&self, target: &Target, presence: &dyn ToolPresence) -> bool;
}
```

### 4.3 ToolPresence — the testable seam

```rust
/// Answers "is this tool already on the machine?" so evaluation never
/// touches $PATH in unit tests. Production impl walks the candidate
/// binaries in order through the toride-installer Detector, exactly as
/// the catalogue's detect_entry does.
pub trait ToolPresence: Send + Sync {
    fn is_present(&self, binaries: &[&str]) -> bool;
}

/// Production impl over the installer Detector (qualified import!):
///
/// use toride_installer::status::Detector as InstallerDetector;
///
/// detect() returns NotInstalled/OnPath/Managed; is_present() is
/// `!matches!(status, InstallerToolStatus::NotInstalled)`.
pub struct DetectorPresence(InstallerDetector);
```

### 4.4 SetupBundle / Recommendation / InstallAction / ConfigHint

```rust
#[derive(Clone, Debug, serde::Serialize)]
pub struct SetupBundle {
    /// Stable slug ("rust", "containers-macos", "iac", …).
    pub id: &'static str,
    pub title: &'static str,
    /// Id of the default-selected recommendation — always the Free/FOSS one.
    pub default_pick: &'static str,
    pub recommendations: Vec<Recommendation>,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct Recommendation {
    /// "<bundle>-<tool>[-<route>]", unique across the registry.
    pub id: &'static str,
    pub title: &'static str,
    /// One sentence shown under the title ("Caches compilations; pairs
    /// with any Rust toolchain").
    pub rationale: &'static str,
    pub license: LicenseInfo,
    pub condition: Condition,
    /// Alias candidates for the presence check (first hit wins, like
    /// ToolSpec.binaries).
    pub binaries: &'static [&'static str],
    /// Ordered steps: installs first, trailing config hints.
    pub actions: Vec<InstallAction>,
    /// Id of the FOSS alternative this row defers to; the UI shows the
    /// defer link when this row is not Free.
    pub alternative: Option<&'static str>,
}

#[derive(Clone, Debug, serde::Serialize)]
#[non_exhaustive]
pub enum InstallAction {
    /// Package install: the row's method, planned through toride-apps.
    Install(InstallSpec),
    /// Config-only step; written only after the user sees the exact bytes
    /// and accepts.
    Hint(ConfigHint),
    /// Deliberate manual step for routes no backend expresses in v1
    /// (e.g. `rustup component add rust-analyzer`).
    Manual { instructions: &'static str },
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct InstallSpec {
    /// Canonical id for the manifest + plan (TorideId::slugify of `name`).
    pub name: &'static str,
    pub method: InstallMethod,
}

/// A config-only step. `path` may start with `~` (expanded via
/// toride-fs::expand_tilde). `on_exists` is `Skip` in v1: if
/// `read_optional` says the file exists, applying reports
/// `SkippedExisting` and the UI shows the snippet for the user to add by
/// hand — toride never overwrites or appends to an existing user file.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ConfigHint {
    /// Stable id ("sccache-cargo-wrapper", "direnv-hook").
    pub id: &'static str,
    pub title: &'static str,
    /// Exact bytes that would be written, rendered in the confirm dialog.
    pub content: &'static str,
    pub path: &'static str,
    pub on_exists: OnExists,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
pub enum OnExists {
    /// v1 only mode: never touch an existing file.
    Skip,
}
```

### 4.5 Registry + evaluation

```rust
/// The compiled-in registry. Runtime-built (String-bearing InstallMethod
/// fields need allocation — same rationale as catalogue()).
#[must_use]
pub fn bundles() -> Vec<SetupBundle>;

/// What evaluation hands the UI: only rows whose condition holds today.
#[derive(Clone, Debug)]
pub struct SetupOffers {
    /// Offers grouped by bundle, bundle order = registry order.
    pub bundles: Vec<SetupBundle>,
    /// Recommendation ids suppressed because the tool is already present.
    pub satisfied: Vec<&'static str>,
}

/// Evaluate every bundle against host + presence. Never errors; rows whose
/// condition fails are simply absent.
#[must_use]
pub fn evaluate(target: &Target, presence: &dyn ToolPresence) -> SetupOffers;
```

### 4.6 Consent gate + planning

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Consent {
    Pending,
    Accepted,
    Refused,
}

/// The gate every non-Free row must pass before any action runs.
pub fn require_consent(rec: &Recommendation, consent: Consent) -> Result<(), ConsentRequired>;

/// Plan the row's install actions at plan time through
/// `toride_apps::plan::plan_install` (availability + platform gates are
/// plan-time there by design). Each row builds its registry `App` inline:
/// TorideId::slugify(name), `install: method`, empty `platforms` (the
/// planner skips the claim check for empty platforms and the method's own
/// scope governs), `availability: Available`. Planner refusals
/// (UnsupportedMethod, PlatformMismatch, …) degrade to `Err` per action —
/// surfaced as a note on the row, never a panic.
pub fn plan_row(
    rec: &Recommendation,
    target: &Target,
) -> Vec<Result<InstallPlan, toride_apps::Error>>;
```

Execution (phase 3) hands accepted plans to the `Apps` facade; successful
installs are recorded with `InstallManifest::record` +
`InstallRecord::new(plan, ids, version)` so `UpdatePlan`/uninstall keep
working later; the manifest's `save()` is atomic. Pre-existing tools are
never silently adopted in v1 (`InstallRecord::adopted` stays reserved —
open question OQ3).

### 4.7 The license table (verified 2026-10-12 — the labeling sheet)

`FFC` = free for commercial use. `kind` is the `LicenseKind`; `consent` is
`requires_consent()`. Every value below traces to
`.z-flashflow/evidence/research/licenses.md` (and the per-topic research
files), which carries the full fetch provenance.

| tool | license | kind | consent | terms URL | verified |
|---|---|---|---|---|---|
| sccache | Apache-2.0 | Free | no | https://github.com/mozilla/sccache | 2026-10-12 |
| mold | MIT since 2.0 (ELF/Linux only — never the macOS pick) | Free | no | https://github.com/rui314/mold | 2026-10-12 |
| lld | Apache-2.0 WITH LLVM-exception | Free | no | https://raw.githubusercontent.com/llvm/llvm-project/main/LICENSE.TXT | 2026-10-12 |
| cargo-nextest | MIT OR Apache-2.0 | Free | no | https://github.com/nextest-rs/nextest | 2026-10-12 |
| cargo-binstall | GPL-3.0-only (FFC; distribution obligations) | Free | no | https://crates.io/api/v1/crates/cargo-binstall | 2026-10-12 |
| rust-analyzer | MIT OR Apache-2.0 | Free | no | https://github.com/rust-lang/rust-analyzer | 2026-10-12 |
| pnpm | MIT (CLI); repo pnpr/ dir = PolyForm Shield 1.0.0 | Free | no | https://github.com/pnpm/pnpm | 2026-10-12 |
| tsx | MIT | Free | no | https://github.com/privatenumber/tsx | 2026-10-12 |
| fnm | GPL-3.0 (FFC; distribution obligations) | Free | no | https://github.com/Schniz/fnm | 2026-10-12 |
| uv | MIT OR Apache-2.0 | Free | no | https://github.com/astral-sh/uv | 2026-10-12 |
| ruff | MIT | Free | no | https://github.com/astral-sh/ruff | 2026-10-12 |
| pipx | MIT | Free | no | https://github.com/pypa/pipx | 2026-10-12 |
| bundler | MIT | Free | no | https://raw.githubusercontent.com/rubygems/bundler/master/LICENSE.md | 2026-10-12 |
| composer | MIT | Free | no | https://getcomposer.org/ | 2026-10-12 |
| golangci-lint | GPL-3.0 (FFC; distribution obligations) | Free | no | https://github.com/golangci/golangci-lint | 2026-10-12 |
| gofumpt | BSD-3-Clause | Free | no | https://github.com/mvdan/gofumpt | 2026-10-12 |
| colima | MIT | Free | no | https://github.com/abiosoft/colima | 2026-10-12 |
| Podman | Apache-2.0 | Free | no | https://github.com/containers/podman | 2026-10-12 |
| Podman Desktop | Apache-2.0 | Free | no | https://github.com/containers/podman-desktop | 2026-10-12 |
| Lima | Apache-2.0 | Free | no | https://github.com/lima-vm/lima | 2026-10-12 |
| OrbStack | proprietary freemium: personal/non-commercial free; commercial requires Pro $8/user/mo ($96/yr) | PaidForCommercial | YES | https://orbstack.dev/pricing | 2026-10-12 |
| Docker Desktop (docker-desktop) | proprietary, Docker Subscription Service Agreement: free only under 250 employees AND under $10M annual revenue | FreeWithTerms | YES | https://docs.docker.com/subscription/desktop-license/ | 2026-10-12 |
| Terraform | BUSL 1.1 (1.6.0+; ≤1.5 MPL-2.0), licensor IBM: production OK, no competing hosted/embedded offering | FreeWithTerms | YES | https://raw.githubusercontent.com/hashicorp/terraform/main/LICENSE | 2026-10-12 |
| OpenTofu | MPL-2.0 (Linux Foundation) | Free | no | https://github.com/opentofu/opentofu | 2026-10-12 |
| tflint | MPL-2.0 mostly; some terraform-pkg files BUSL 1.1 → binaries bound by both (FFC) | FreeWithTerms | YES | https://github.com/terraform-linters/tflint | 2026-10-12 |
| trivy | Apache-2.0 (successor to deprecated tfsec) | Free | no | https://api.github.com/repos/aquasecurity/trivy | 2026-10-12 |
| terragrunt | MIT | Free | no | https://github.com/gruntwork-io/terragrunt | 2026-10-12 |
| direnv | MIT | Free | no | https://formulae.brew.sh/api/formula/direnv.json | 2026-10-12 |
| starship | ISC | Free | no | https://formulae.brew.sh/api/formula/starship.json | 2026-10-12 |
| zoxide | MIT | Free | no | https://formulae.brew.sh/api/formula/zoxide.json | 2026-10-12 |
| fzf | MIT | Free | no | https://formulae.brew.sh/api/formula/fzf.json | 2026-10-12 |
| ripgrep | MIT OR Unlicense (brew API lists Unlicense) | Free | no | https://formulae.brew.sh/api/formula/ripgrep.json | 2026-10-12 |
| fd | MIT OR Apache-2.0 | Free | no | https://formulae.brew.sh/api/formula/fd.json | 2026-10-12 |
| lazygit | MIT | Free | no | https://formulae.brew.sh/api/formula/lazygit.json | 2026-10-12 |
| git-delta | MIT | Free | no | https://formulae.brew.sh/api/formula/git-delta.json | 2026-10-12 |
| jq | MIT | Free | no | https://formulae.brew.sh/api/formula/jq.json | 2026-10-12 |
| yq | MIT | Free | no | https://formulae.brew.sh/api/formula/yq.json | 2026-10-12 |
| mise | MIT | Free | no | https://github.com/jdx/mise | 2026-10-12 |
| asdf | MIT | Free | no | https://github.com/asdf-vm/asdf | 2026-10-12 |
| volta | NOASSERTION — README states unmaintained: EXCLUDED from bundles | excluded | n/a | https://github.com/volta-cli/volta | 2026-10-12 |
| sold | MIT but repo ARCHIVED Nov 2024: EXCLUDED (not a bundle candidate) | excluded | n/a | https://raw.githubusercontent.com/bluewhalesystems/sold/main/LICENSE.md | 2026-10-12 |
| tfsec | MIT but deprecated → part of Trivy: EXCLUDED | excluded | n/a | https://github.com/aquasecurity/tfsec | 2026-10-12 |

GPL rows are `Free` on this axis on purpose: the decision the UI needs is
"can I use this at work without paying/talking to legal", and the answer
for GPL tools is yes (obligations attach to distribution, which `note`
states). The three consent rows are exactly the ones whose *terms* — not
license text alone — decide commercial use.

### 4.8 The two seeded ConfigHints

1. **sccache → cargo rustc-wrapper** (`id: "sccache-cargo-wrapper"`):
   target `~/.cargo/config.toml`, content
   `[build]\nrustc-wrapper = "sccache"\n` — offered only when the file is
   absent (`OnExists::Skip` otherwise, snippet shown for manual merge).
   Source recipe: https://github.com/mozilla/sccache (verified 2026-10-12).
2. **direnv hook** (`id: "direnv-hook"`): target the user's shell rc
   (`~/.zshrc` on macOS default, `~/.bashrc` on Linux), content
   `eval "$(direnv hook zsh)"` / `eval "$(direnv hook bash)"` — same
   skip-if-exists contract. Because rc files virtually always exist, the
   common path is show-the-snippet, which is the intended v1 behavior.

Both flow: `read_optional` (exists?) → confirm dialog (exact bytes) →
`expand_tilde` → `atomic_write` → report `Written{path}` /
`SkippedExisting{path}`. No append mode in v1 (`with_lock` remains
available for a v2 anchored-append design).

## 5. Registration and Cargo shape

`crates/toride/Cargo.toml` `[dependencies]`, after the toride-installer
line, matching the sibling path-dep style:

```toml
# Setup bundles (setup_bundles): plan-time evaluation builds InstallPlans
# through toride-apps. Features chosen deliberately — this is the TUI
# crate's FIRST toride-apps dependency: mise enables BackendId::Mise +
# Operation twins (pulls toride-mise, already a direct dep here, plus
# toride-runner's tokio path); direct enables BackendId::Direct. The TUI
# already runs tokio, so the tokio-carrying features cost no new runtime.
toride-apps = { path = "../toride-apps", version = "0.2.0", features = ["mise", "direct"] }
```

- Rejected: gating the dep behind a new `toride` cargo feature to stay
  tokio-free-by-default — the TUI binary already links tokio and
  toride-mise unconditionally, so the feature would be dead weight with one
  always-on consumer. Revisit only if a tokio-free toride lib build becomes
  a real goal.
- No new workspace pins needed: serde/insta/tempfile are already
  workspace-pinned and the toride crate already dev-depends on insta,
  tempfile, and toride-runner with `fake`.
- `crates/toride/src/lib.rs`: add `pub mod setup_bundles;` +
  `pub mod setup_data;` in the existing alphabetical `pub mod` list.

## 6. File-by-file change list

Phase-ordered; (new) marks new files.

1. `crates/toride/src/setup_bundles.rs` (new) — types (§4.1–4.4),
   registry tables (§4.7 rows materialized as recommendations),
   `evaluate`, `require_consent`, `plan_row`, `apply_hint`; inline
   `#[cfg(test)] mod tests`.
2. `crates/toride/src/setup_data.rs` (new) — `SetupCollector`
   (oneshot rx + 60s TTL cache + spawn_blocking presence walk),
   `to_findings` (info-level `FindingEntry`s with `setup.suggest.*` ids);
   inline tests.
3. `crates/toride/src/lib.rs` — the two `pub mod` lines.
4. `crates/toride/Cargo.toml` — the toride-apps dependency (§5).
5. `crates/toride/src/data/mod.rs` — `Section::Setup` variant + `label()`
   arm ("Setup").
6. `crates/toride/src/ui/screens/setup/mod.rs` (new) — `SetupContent`
   (read-only, `set_offers`/`set_findings` setters), license badges via
   `tag_badge`, consent modal (`Modal`/`InteractiveModal`), dismiss
   handling; `SectionOverview` impl; inline tests + insta snapshots.
7. `crates/toride/src/ui/screens/dashboard.rs` — route `Section::Setup`
   to `SetupContent`; `set_setup_offers(...)` setter mirroring
   `set_tools_data`.
8. `crates/toride/src/app/mod.rs` — `setup_collector.poll()` arm in the
   event loop next to the tools arm; `start()` on section entry.
9. `crates/toride/src/action.rs` — no change expected in v1; only touch if
   a genuinely new semantic intent emerges (e.g. `DismissSuggestion`) —
   prefer content-struct key handling first.

## 7. Phased milestones

### Phase 0 — data model + registry (headless)

Ship `setup_bundles.rs` types + full registry + the table-consistency
invariants. No evaluation, no I/O.

Acceptance criteria:
- Every recommendation id is unique; every `alternative` id resolves; every
  `default_pick` resolves; every row has `license.terms_url` non-empty and
  `license.verified = "2026-10-12"` — all asserted by a unit test that
  walks `bundles()`.
- `LicenseKind::requires_consent` is true exactly for
  FreePersonal/PaidForCommercial/FreeWithTerms (exhaustive match test).
- The nine gate tools (sccache, mold, orbstack, docker, colima, podman,
  uv, opentofu, terraform) each appear in at least one recommendation —
  asserted by test; the doc-level gate is `scripts/check_plan_citations.sh`.
- `cargo test -p toride setup_bundles` green; `cargo clippy -p toride
  --all-targets` adds zero new pedantic warnings; `cargo fmt --check` clean.

### Phase 1 — evaluation + planning (headless)

`ToolPresence`/`DetectorPresence`, `evaluate`, `plan_row`, consent gate,
manifest recording helpers.

Acceptance criteria:
- With a `FixedPresence` test seam: on `Target::new(Os::MacOs, …)` the
  containers bundle offers colima (default_pick, Free) + podman +
  OrbStack (PaidForCommercial) + Docker Desktop (FreeWithTerms), and
  hides mold; on Linux the mold row appears and the macOS rows vanish.
- `plan_row` for the OrbStack row returns an `Ok(InstallPlan)` whose
  operation renders (via `summary()`) a `brew install --cask orbstack`
  argv; the OpenTofu row routes per its declared method; planner refusals
  come back as `Err` values, never panics.
- `require_consent` refuses `Consent::Pending` on the three consent rows
  and passes every `Free` row regardless of consent.
- A dry-run smoke: accepted plans with `dry_run` semantics are refused by
  `ensure_install_allowed` (contract test against the backend guard).

### Phase 2 — ConfigHint application

Acceptance criteria:
- `apply_hint` on a temp HOME writes the exact bytes atomically and
  reports `Written{path}`; with the file pre-existing it writes nothing
  and reports `SkippedExisting{path}` (asserted byte-for-byte with
  tempfile — the pre-existing file is untouched, including its mode).
- `~` paths expand via toride-fs; no path outside the expansion is ever
  created; no append path exists (grep-level guarantee: only
  `atomic_write` is called).

### Phase 3 — TUI adoption (Section + SetupContent + collector)

Acceptance criteria:
- `Section::Setup` appears in the sidebar with label "Setup"; entering it
  starts the collector; leaving and re-entering within 60s serves the
  cached bundle (collector contract tests).
- insta snapshots (TestBackend, the `render_to_string` house pattern):
  bundle list, a detail view with license badge + verified date, the
  consent modal for OrbStack showing "$8/user/mo commercial" + terms URL,
  and the dismissed-state view. Snapshots reviewed, not blind-approved.
- Non-Free rows cannot reach an install action without the consent modal
  being accepted in the same session (UI-level test); default-selected row
  is always the bundle's `default_pick` (FOSS).
- `cargo test -p toride` green including snapshots; no existing snapshot
  files change (tools/dashboard regression check).

### Phase 4 — doctor/tools-screen adoption + polish

Acceptance criteria:
- Tools screen unaffected: its findings filter still counts only
  `tools.missing.*` warnings; existing tools snapshots unchanged.
- Setup section's `SectionOverview::findings_count` counts undismissed
  `setup.suggest.*` info items only; sidebar badge reflects it.
- Dismissal persists for the session (in-memory), and dismissed ids never
  re-enter the findings list until restart.
- Doctor output (`tools.missing.<name>` warnings) is byte-identical to
  pre-feature behavior on a fixture host.

## 8. Test plan

Conventions: inline `#[cfg(test)] mod tests` at the bottom of every new
module (house style), descriptive test names, one behavior per test,
`?`-style Result tests where fallible.

- **Table-consistency tests (Phase 0)** — walk `bundles()` asserting the
  invariants listed in Phase 0's AC. These are the Rust-side twin of
  `scripts/check_plan_citations.sh`: the script guards the document, the
  tests guard the code, and the license table above is the shared source.
- **LicenseKind tests** — exhaustive `requires_consent` mapping; serde
  round-trip of `LicenseInfo` (serde_json is a dev-dep).
- **Condition tests** — `FixedPresence` (a `Vec<&str>` membership map)
  drives `holds()` for every condition shape: OS gates on both
  `Target::new(Os::MacOs, Arch::Aarch64)` and Linux targets, distro-family
  gating, `Missing` presence, `All` composition.
- **DetectorPresence tests** — real `InstallerDetector` with
  `with_runner(Arc<FakeRunner>)` (the documented seam; toride already
  dev-depends on toride-runner `fake`): assert presence resolution against
  the fake runner's scripted outputs, and that absence yields
  `NotInstalled` → `is_present == false`.
- **plan_row tests** — fake-presence + fixed `Target`s; assert argv
  rendering via `Operation::argv`/`summary()` (brew cask vs formula,
  distro family routing, mise tool addressing); assert every planner error
  variant surfaces as `Err` and the row stays renderable.
- **Consent gate tests** — Pending/Refused/Accepted × Free/non-Free
  matrix.
- **apply_hint tests** — tempfile dirs; exact-bytes assertion; skip-
  if-exists assertion (write a sentinel file, apply, assert bytes and
  permissions unchanged).
- **Collector tests (Phase 3)** — mirror the ToolsCollector contract
  tests: idempotent start while pending, fresh-cache-within-TTL behavior,
  no rescan on cache hit.
- **insta snapshots (Phase 3)** — one per view state (list, detail,
  consent modal, dismissed); reviewed via `cargo insta`; no snapshot
  accepted with a "maybe" — either it renders the intended content or the
  content is wrong.
- **Regression fences** — the full existing toride suite plus snapshots
  must stay untouched; run `cargo test -p toride` per phase.

Deliberately out: property-based tests (the registry is static data; the
invariants are enumerable), criterion benches (no hot path).

## 9. Doctor and tools-screen adoption

- Expected-tool findings keep their current contract: catalogue entries
  are all `expected: true`, ids are `tools.missing.<name>`, severity is
  the literal `"warning"`. The Setup feature changes none of that.
- Bundle suggestions are emitted as `FindingEntry`s with id
  `setup.suggest.<bundle>.<recommendation>`, severity `"info"`, title
  "<tool> — <rationale clause>" — reusing the existing plain-string
  finding shape so every section consumer keeps one type.
- The tools screen keeps filtering with `starts_with("tools.missing.")`,
  so info suggestions never inflate the tools badge or its missing-count.
- The Setup screen filters `setup.suggest.`; dismissal is session-scoped
  state on `SetupContent` (persisted dismissal = OQ1).
- Sidebar badge: `SectionOverview::findings_count` for `SetupContent`
  returns the undismissed suggestion count; `status_label_for` maps the
  section's offline/degraded/active states exactly like ToolsContent's
  overview impl does.

## 10. Risks and open questions

### Risks

- R1 — **License data drift.** Prices and thresholds change (OrbStack
  pricing, Docker thresholds, BUSL scope). Mitigation: `verified` date per
  row rendered in the UI; the doc gate keeps the table complete; a dated
  re-verification pass (same research pipeline) before any release that
  touches these rows. The gate cannot detect staleness — only re-checks
  can.
- R2 — **TUI dependency weight.** Adding toride-apps with `mise`+`direct`
  pulls the tokio-carrying runner path into the toride graph. Mitigation:
  `cargo tree -p toride -i tokio` before/after in Phase 1; the escape
  hatch (feature-gate the dep) is documented in §5.
- R3 — **Destructive-config risk.** Mitigated by construction: `OnExists::
  Skip` only, exact bytes shown before writing, atomic writes, no append
  in v1.
- R4 — **Name collisions.** Two `Detector` traits and three-way
  `ToolStatus` collision (installer/mise). Mitigated by §3.2's qualified
  imports, asserted in review; a compile-time `use … as …` convention
  makes accidental cross-crate use obvious.
- R5 — **Consent fatigue / wrong default.** If the default pick were
  OrbStack, users would consent-click past a paywall. Mitigation:
  `default_pick` is always the FOSS row, enforced by a Phase 0 test
  (default_pick's license kind must be `Free`).
- R6 — **mise-route claims.** Research mise-registry shorthand entries in
  the f–t region were audit-scoped UNVERIFIED-BY-AUDIT. Mitigation: prefer
  backend-native identifiers; any mise `tool:` string used in a bundle row
  must be re-verified at implementation time and carries a table comment
  naming its source.
- R7 — **Plan-time refusals UX.** `plan_install` refuses at plan time
  (disabled app, platform mismatch, unsupported method). Mitigation:
  refusals render as per-row notes ("not available on this host"), never
  errors, never empty sections.

### Open questions

- OQ1 — Persisted dismissal of suggestions: session-only (v1) vs a
  toride-managed settings file. Deciding factor: whether dismissal is
  per-machine (file) or per-session (memory). v1 ships memory-only.
- OQ2 — Anchored append for existing config files (e.g. merging
  `rustc-wrapper` into an existing `~/.cargo/config.toml`). Needs a
  marker-comment design + `with_lock`; v2 candidate, not v1.
- OQ3 — Adopting pre-existing installs into the manifest
  (`InstallRecord::adopted`) so bundle rows can show "managed by toride"
  for tools the user installed themselves. Deferred: adoption writes
  plan-less records; decide when update flows need them.
- OQ4 — Execution path: `Apps` facade vs direct planner+backend calls.
  Leaning `Apps` facade (it wraps builder/blocking twins); confirm during
  Phase 3 when the confirm-modal wiring lands.
- OQ5 — Windows bundles (mise runs natively for supported tools; winget
  is registry wave-2). Out of scope v1; revisit after wave-2 registry
  support.
