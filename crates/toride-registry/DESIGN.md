# toride-registry — Repo → Toride normalization design

Status: design, wave 1. Grounded in the survey briefs under `docs/survey/`
(homebrew, flathub, appstream, repology, ecosystems, conventions) and the
fixtures under `tests/fixtures/`. Every external repository has its own
structure; each is normalized by exactly one **adapter** into the single
normalized model below. The adapter is the **only** place source-specific
knowledge lives — search, resolve, alias handling and install planning
downstream see only `App`.

## 0. Evidence base (what this design is grounded in)

- **Surveys** (all dated 2026-09-28): `docs/survey/homebrew.md`,
  `flathub.md`, `appstream.md`, `repology.md`, `ecosystems.md`,
  `conventions.md`.
- **Fixtures inspected this session**:
  `tests/fixtures/homebrew/cask-brave-browser.json` (token/url/sha256/
  variations/artifacts as surveyed, homebrew.md §3–§5),
  `tests/fixtures/homebrew/formula-ripgrep.json` (`versions.stable`,
  `bottle.stable.files` per-platform sha256, `executables: ["rg"]`),
  `tests/fixtures/flathub/search-brave-browser.json` (Meilisearch envelope,
  `main_categories` a bare string, hit `id` underscored vs `app_id` dotted),
  `tests/fixtures/flathub/appstream-com.brave.Browser.json` (`releases[0].
  version = "1.96.59"`, `bundle.value = "app/com.brave.Browser/x86_64/stable"`),
  `tests/fixtures/appstream/debian-sid-main-amd64.yml` (verbatim DEP-11
  header `Origin: debian-sid-main` + 3 real components),
  `tests/fixtures/repology/project-brave-browser.json` (synthetic, 5 repo
  entries, `origversion ≠ version`, `families` present but never relied on).
- **Reachability re-verified this session** (`curl -s -m 10 -o /dev/null -w
  "%{http_code}"`): `https://formulae.brew.sh/api/formula/ripgrep.json` →
  **200**; `https://flathub.org/api/v2/appstream/com.brave.Browser` → **200**;
  `https://deb.debian.org/debian/dists/sid/main/dep11/Components-amd64.yml.gz`
  → **200**; `https://repology.org/api/v1/project/brave-browser` → **000**
  (connection refused — DNS pinned, same as reported in repology.md §pre).
  Consequence: **repology ships parse-only in wave 1** against its synthetic
  fixture; its fetch client compiles and is exercised only by env-gated
  network tests.

## 1. Architecture

```
             ┌──────────────────────────── toride-registry ───────────────────────────┐
 formulae.brew.sh ─▶ HomebrewAdapter ─┐                                             │
 flathub.org      ─▶ FlathubAdapter ─┼──▶ normalize ─▶ App (the ONE model) ─▶ search │
 deb.debian.org   ─▶ AppstreamAdapter┤    (inside       ▲                        resolve │
 repology.org     ─▶ RepologyOracle ─┘    adapters)    └── AliasIndex (toride id       install
                                                       ↔ per-source ids)        planning
             └────────────────────────────────────────────────────────────────────────┘
```

- One adapter per source; each adapter owns its wire structs (serde payload
  types), its parse functions, and its thin fetch client.
- `App` is the only type that crosses the adapter boundary outward.
- `AliasIndex` maps the canonical toride id to per-source ids; Repology is
  the oracle that fills it (§5).
- Installation itself is out of scope here: `InstallMethod` describes *what*
  to run/fetch; execution stays with toride-installer / the host.

## 2. Normalized model (`src/model.rs`)

Seven core types plus leaf enums. Everything is `serde`-serializable (the
normalized model is the cache and UI format too) and `#[non_exhaustive]`
where the set may grow (new sources, new distro families, Windows later).

```rust
/// Canonical toride app id — the slug every downstream subsystem keys on.
///
/// Rules: lowercase ASCII `[a-z0-9]` + `-`; no leading/trailing/double
/// hyphen; whitespace, `_` and `.` collapse to `-`. Derived (§5):
/// slugify(repology canonical project name) when the oracle knows the app,
/// else slugify(the first source id that produced the record).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct TorideId(String);

impl TorideId {
    /// Deterministic slug from any source id or display name.
    pub fn slugify(input: &str) -> Self;
    /// Validated constructor (rejects anything `slugify` wouldn't emit).
    pub fn parse(input: &str) -> Result<Self>;
    pub fn as_str(&self) -> &str;
}

/// One normalized registry entry — the ONLY shape downstream ever sees.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct App {
    pub id: TorideId,
    /// Display name (C/default locale).
    pub name: String,
    /// Alternative names: cask `name[1..]`, formula `aliases`, cask
    /// `old_tokens` (renames). Search matching uses these too.
    pub aliases: Vec<String>,
    /// One-liner (cask `desc`, flathub hit `summary`, DEP-11 `Summary: C:`).
    pub summary: Option<String>,
    /// Long form, HTML stripped to plain text by the adapter.
    pub description: Option<String>,
    pub homepage: Option<String>,
    /// SPDX expression where the source publishes one.
    pub license: Option<String>,
    pub developer: Option<String>,
    /// Executable names the app puts on PATH (formula `executables`,
    /// DEP-11 `Provides.binaries`). The join key for tool detection
    /// (appstream.md §5) — kept in the model for exactly that consumer.
    pub binaries: Vec<String>,
    /// Best-known version from this app's own sources.
    pub latest: Option<Version>,
    /// Where this app applies. Empty = the source declares nothing
    /// (treat as "unknown", NOT "universal"). `plan()` reconciles the
    /// two: empty platforms SKIPS the claim check instead of refusing
    /// (§3.3) — the install method's own scope governs.
    pub platforms: Vec<Platform>,
    /// Published downloads with checksums where the source publishes them.
    pub artifacts: Vec<Artifact>,
    /// Primary install descriptor (§2 `InstallMethod`).
    pub install: InstallMethod,
    /// Per-source identity rows — this is the alias table's payload
    /// (§5); a merged App carries one entry per source that knows it.
    pub sources: Vec<SourceRef>,
    /// Lifecycle: homebrew cask/formula `deprecated`/`disabled`
    /// (homebrew.md §3: "deprecated: true warns before install",
    /// disabled = cannot install). Everything else → `Available`.
    pub availability: Availability,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum Availability { #[default] Available, Deprecated, Disabled }

/// A version as an opaque string plus the extras sources publish.
/// Deliberately no semver parsing in wave 1 (repology `origversion`
/// suffixes like `1.79.126-1` / `1.83.120-r0` are not semver).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Version {
    /// Sanitized version (`version`, flathub `releases[0].version`,
    /// repology `version`).
    pub value: String,
    /// Repo-native spelling with distro suffixes (repology `origversion`).
    pub original: Option<String>,
    /// Release time, unix seconds, when published (flathub release
    /// `timestamp`, DEP-11 `Releases[].unix-timestamp`).
    pub published_unix: Option<i64>,
}

/// Which external source a [`SourceRef`] belongs to — one variant per
/// adapter (the surveyed adapter keys).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum SourceKind {
    /// Homebrew cask (GUI apps); id = cask token (`brave-browser`).
    HomebrewCask,
    /// Homebrew formula (CLI tools); id = formula name (`ripgrep`).
    HomebrewFormula,
    /// Flathub; id = dotted reverse-DNS app id (`com.brave.Browser`).
    Flathub,
    /// Distro catalog (AppStream/DEP-11 wave 1); id = package name,
    /// scoped by `repo` (DEP-11 header `Origin`, e.g. `debian-sid-main`).
    Distro,
    /// Repology project; id = canonical project name (`brave-browser`).
    Repology,
}

/// One per-source identity: the join key between the toride world and a
/// source's native naming. Also the row format of the AliasIndex.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceRef {
    pub source: SourceKind,
    /// Cask token / formula name / flatpak app id / distro package name /
    /// repology project name.
    pub id: String,
    /// Source-native repo scope where the source has more than one:
    /// DEP-11 `Origin` (`debian-sid-main`), repology repo id
    /// (`debian_13`, `fedora_rawhide`, `arch`, `alpine_edge`, `homebrew`).
    /// `None` for homebrew (token is unique) and flathub (app_id is unique).
    pub repo: Option<String>,
    /// The version this source currently reports, when captured.
    pub version: Option<Version>,
    /// True when this row was minted from a fallback rather than parsed
    /// from the source's own catalog — today only repology-minted
    /// `Distro` descriptors for families with no adapter (§5). Persists
    /// through the AliasIndex's JSON serialization; `#[serde(default)]`
    /// keeps older caches deserializable.
    #[serde(default)]
    pub provisional: bool,
}

/// Platform applicability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Os { MacOs, Linux, Windows }
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Arch { X86_64, Aarch64, X86 }

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Platform {
    pub os: Os,
    /// `None` = arch-independent / undeclared (flathub `arches: null`).
    pub arch: Option<Arch>,
    /// Minimum OS release the source declares — cask
    /// `depends_on.macos.{">=":["13"]}` → `Some("13")` (brave fixture).
    pub min_release: Option<String>,
}

/// A published download. Wave-1 sources publish sha256 only; Sha512 is
/// modeled so a source that publishes one needs no model change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ChecksumAlgo { Sha256, Sha512 }

/// Whether a source publishes checksums at all — the per-source
/// verification policy (plan §3.12): `OutOfBand` is the explicit marker
/// that an empty `artifacts` list means "unverifiable", telling an
/// embedder to demand an out-of-band digest rather than trust a size
/// floor.
pub enum VerificationPolicy { Inline, OutOfBand }

impl SourceKind { pub fn verification_policy(self) -> VerificationPolicy }

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checksum { pub algo: ChecksumAlgo, /// lowercase hex pub digest: String }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArtifactKind {
    /// OS package/installer container (cask `url`: dmg/pkg).
    Package,
    /// Prebuilt binary (formula bottle blob from ghcr.io).
    Bottle,
    /// Source archive (formula `urls.stable`).
    Source,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Artifact {
    pub url: String,
    pub checksum: Option<Checksum>,
    pub os: Option<Os>,
    pub arch: Option<Arch>,
    pub kind: ArtifactKind,
}

/// How to install — the descriptor install planning consumes. One variant
/// per install technology, exactly the ask's set: brew token / flatpak ref /
/// distro package per family / direct URL.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum InstallMethod {
    /// `brew install --cask <token>` (`cask: true`) or
    /// `brew install <name>` (`cask: false`).
    Homebrew { cask: bool, token: String },
    /// `flatpak install <remote> <app_id>`; remote is `"flathub"` for the
    /// Flathub adapter (remote configured once from `flathub.flatpakrepo`).
    Flatpak { app_id: String, remote: String },
    /// `<family>'s manager install <package>` scoped by repo; the family
    /// picks the manager (apt / dnf / pacman / apk). `repo` = DEP-11
    /// `Origin` (`debian-sid-main`) or repology subrepo where known.
    Distro { family: DistroFamily, repo: Option<String>, package: String },
    /// Direct download + checksum verify for hosts without the native
    /// manager. No wave-1 adapter emits this variant: it is constructed at
    /// PLAN time by `App::direct_fallback(os, arch)` picking a matching
    /// checksummed `artifacts` entry (§3.3 `Plan::DirectDownload`); a
    /// stored Direct method on an `App` is a wave-2 decision.
    Direct { url: String, checksum: Option<Checksum>, arch: Option<Arch> },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum DistroFamily { Debian, Ubuntu, Fedora, Arch, Alpine }
```

Design notes:

- **What is deliberately NOT in the model**: categories/icons/screenshots/
  verification badges (flathub `verification_verified` — the publisher
  identity flag, distinct from the modeled `VerificationPolicy` of the
  checksums note below)/popularity (flathub `trending`,
  `installs_last_month`, homebrew `analytics`), local-state echoes
  (`installed`, `outdated`,
  `pinned` — all null server-side per homebrew.md §3), repology
  `maintainers`, per-repo `status` (lives at parse level in the oracle;
  see §5). Categories may be added when a browse UI needs them; they are
  not needed by search/resolve/install.
- **Checksums**: wave-1 reality is sha256-only, published directly by
  homebrew (cask `sha256` + per-variation, formula bottle files) —
  verified in both homebrew fixtures. Flathub publishes **no** checksums
  (flathub.md §Limitations: "No sha256 anywhere in the API" — verified);
  its `artifacts` is empty and integrity is delegated to the flatpak
  client's GPG-based OSTree layer. DEP-11 publishes none either. The
  `Option<Checksum>` is the honest encoding of that asymmetry, and it maps
  1:1 onto toride-installer's existing `Checksum::Digest(String)`
  (installer `src/tool.rs:67-86`). Sha512 is modeled for sources that
  publish it (none in wave 1); toride-installer verifies it by digest
  hex length (128), same as its checksum-file parser. The per-source
  `VerificationPolicy` (`SourceKind::verification_policy()`, plan §3.12)
  marks checksum-less sources `OutOfBand` — the explicit marker that an
  empty `artifacts` list means "unverifiable, demand an out-of-band
  digest", not "no downloads exist".
- **Versions stay strings**: repology `origversion` (`1.83.112-1.fc44`,
  `1.83.120-r0`) and flathub `"51.0"` development releases are not
  semver; comparison across sources is the oracle's job, not the model's.

## 3. Adapter trait and the strict parse/fetch split (`src/adapter.rs`)

House style: `#[async_trait::async_trait]` + `Send + Sync` bound, matching
`toride-installer`'s `ReleaseResolver` (`crates/toride-installer/src/tool.rs:92-102`).

```rust
/// Normalizes one external repository into [`App`]s.
///
/// Contract: ALL source-specific knowledge lives in the implementing
/// module — wire structs, endpoints, quirk handling. Callers see only
/// `App` and [`SourceRef`].
#[async_trait::async_trait]
pub trait Adapter: Send + Sync {
    /// Which source this adapter normalizes.
    fn source(&self) -> SourceKind;

    /// Look up one app by its source-native id (cask token, formula
    /// name, flatpak app id, distro package + repo). `Ok(None)` = the
    /// source has no such entry.
    ///
    /// # Errors
    /// Transport or payload-parse failures (`Error::Http`, `Error::Parse`).
    async fn lookup(&self, id: &SourceRef) -> Result<Option<App>>;

    /// Free-text search. Returns normalized stubs — enough for a result
    /// list (`id`, `name`, `summary`, `install`, `platforms`); heavy
    /// fields (`artifacts`, full `description`) may require `lookup`.
    async fn search(&self, query: &str) -> Result<Vec<App>>;
}
```

### 3.1 The split

Every adapter module has two strictly separated halves; only the fetch
half touches the network, only the parse half is fixture-tested offline:

```rust
// ---- parse (pure, `&str` in → `App` out, no clock/no network/no client) --
pub fn parse_cask_json(payload: &str) -> Result<App>;            // homebrew
pub fn parse_formula_json(payload: &str) -> Result<App>;         // homebrew
pub fn parse_search_envelope(payload: &str) -> Result<Vec<App>>; // flathub
pub fn parse_appstream_detail(payload: &str) -> Result<App>;     // flathub
pub fn parse_dep11_catalog(payload: &str) -> Result<Dep11Catalog>; // appstream
                                                                 //  (header + components)
pub fn parse_repology_project(payload: &str) -> Result<Vec<AliasCandidate>>; // repology

// ---- fetch (thin client beside the parsers) ------------------------------
pub struct HomebrewClient { client: reqwest::Client }
impl HomebrewClient {
    /// GET https://formulae.brew.sh/api/cask/{token}.json → body text
    pub async fn fetch_cask(&self, token: &str) -> Result<String>;
    /// GET https://formulae.brew.sh/api/formula/{name}.json → body text
    pub async fn fetch_formula(&self, name: &str) -> Result<String>;
}
// FlathubClient: POST /api/v2/search {"query": …} ;
//               GET /api/v2/appstream/{app_id}
// AppstreamClient: GET dists/{suite}/{component}/dep11/Components-{arch}.yml.gz
//               — streams the .yml.gz DOWNLOAD to the disk cache (flate2
//               write-through; 8.7 MB gz for sid/main), then hands the
//               fully decompressed ~27 MB text to the pure parser. "Never
//               buffer whole" applies to the download only: the parse
//               signature `(&str)` requires the whole text in memory —
//               acceptable at 27 MB; the lighter CID-Index is the fallback
//               if that ever isn't (appstream.md §3/§7)
// RepologyClient: GET /api/v1/project/{name}; GET /tools/project-by?…
//               (serialized ≥1 req/s — repology.md §4 fair-use policy)
```

Fetch returns **raw body text**, not deserialized values: the parse
signature is exactly what the fixtures exercise. Live regression tests
(env-gated, §9) therefore NEVER diff field-for-field against the frozen
fixtures — equality would break on the first upstream move (cask
`version`/`generated_date`, flathub `releases[0].version`, DEP-11
catalogs republished ~daily per appstream.md §3). The compared invariant
set is: (1) the same fields populated/absent, (2) the same artifact count
and `ArtifactKind` multiset, (3) the same `InstallMethod` variant with its
identifying payload (token/app_id/package), (4) the same `SourceRef` set
(source kind + id + repo).

Two parse signatures return non-`App` types; both are declared here so
the implementer does not invent them:

```rust
/// One repology project entry → AliasIndex row input. Owned by
/// `src/alias.rs` (alias-layer type, deliberately NOT in model.rs — it
/// never crosses the adapter boundary to downstream);
/// `sources/repology.rs` produces it.
pub struct AliasCandidate {
    /// Repology repo id (`homebrew`, `debian_13`, `fedora_rawhide`,
    /// `arch`, `alpine_edge`).
    pub repo: String,
    /// Entry-level: every name below shares this version.
    pub version: Version,
    /// Raw `status` (`newest`, `outdated`, `devel`, …); the `is_ignored`
    /// set is dropped at index-build time, not at parse time.
    pub status: String,
    pub summary: Option<String>,
    /// ONE repology entry yields ONE candidate even when both name slots
    /// are set (fixture `project-brave-browser.json`, arch entry:
    /// srcname `brave-browser` + binname `brave` → one candidate). Both
    /// are kept so the index can be rebuilt under a different selection
    /// rule without re-fetching. AliasIndex insertion picks ONE
    /// `SourceRef.id` per candidate by repo class: source-based repos
    /// (`debian_*`, `fedora_*`, `homebrew`) prefer `srcname`;
    /// binary-install repos (`arch`, `alpine_*`) prefer `binname` —
    /// each falling back to the other when one is `None` (repology.md §3).
    pub srcname: Option<String>,
    pub binname: Option<String>,
}

/// DEP-11 multi-document parse result. Owned by
/// `src/sources/appstream.rs` (wire-level, source-specific; model.rs
/// stays clean). Locale maps are `HashMap<String, String>` with the
/// mandatory `C` key; every field `#[serde(default)]` (§4.4 strictness).
pub struct Dep11Catalog { pub header: Dep11Header, pub components: Vec<Dep11Component> }
pub struct Dep11Header {   // first YAML document
    pub file: Option<String>,        // "DEP-11"
    pub version: Option<String>,     // "1.0"
    pub origin: Option<String>,      // "debian-sid-main" → SourceRef.repo
    pub media_base_url: Option<String>,
    pub time: Option<String>,
    pub architecture: Option<String>,
}
pub struct Dep11Component {
    pub type_: Option<String>,             // "desktop-application", …
    pub id: Option<String>,
    pub package: Option<String>,
    pub name: LocaleMap,
    pub summary: LocaleMap,
    pub description: LocaleMap,
    pub project_license: Option<String>,
    pub developer: Option<Dep11Developer>, // { id: Option<String>, name: LocaleMap }
    pub releases: Vec<Dep11Release>,       // { version, type_, unix_timestamp: Option<i64> }
    pub provides: Option<Dep11Provides>,   // { binaries: Vec<String>, mediatypes: Vec<String>, … }
    pub launchable: Option<Dep11Launchable>, // { desktop_id: Vec<String> }
    pub categories: Vec<String>,
}
```

### 3.2 HTTP client construction

One shared `build_http_client(per_source_ua)` mirroring
`toride-installer`'s (`crates/toride-installer/src/installer.rs:105-114`):
`user_agent(concat!("toride-registry/", source-key, "/", env!("CARGO_PKG_VERSION")))`
(descriptive UA is *mandatory* posture for repology, repology.md §4),
`.redirect(Policy::limited(10))` (repology's reverse oracle is a redirect
endpoint; flathub/homebrew also redirect), an overall timeout and a
connect timeout (reqwest has none by default — installer.rs:95-103
rationale; registry payloads are small JSON, so shorter than the
installer's download budgets: 30 s overall / 15 s connect, named consts
with why-docs per conventions.md §5).

### 3.3 Facade

`Registry` holds `Vec<Box<dyn Adapter>>` (wave 1: homebrew, flathub,
appstream), fans `search` out concurrently (`tokio::join!`), merges
same-app results via the alias rules (§5), and exposes:

```rust
/// Per-source ids for a canonical id (AliasIndex lookup; empty = unknown).
pub fn resolve(&self, id: &TorideId) -> Result<Vec<SourceRef>>;

/// Turn an install descriptor into concrete steps for the host platform.
///
/// - Homebrew/Flatpak/Distro → `Plan::Command` (the flatpak variant
///   includes the one-time `remote-add` from `flathub.flatpakrepo`).
/// - When the host lacks the native manager → `Plan::DirectDownload`,
///   derived at PLAN TIME via `App::direct_fallback(os, arch)` (below);
///   the url+checksum pair is what toride-installer consumes.
/// - Method names a platform the app doesn't claim → `Plan::Unsupported`.
/// - `app.platforms` EMPTY ("unknown" per §2 — NOT "universal") → the
///   claim check is SKIPPED and the method's own scope governs (a Distro
///   method is scoped by family/repo, a Homebrew method by the source's
///   availability data). "Unknown never refuses to plan" is the
///   reconciliation of that rule with this one. Wave-1 mappings populate
///   platforms for all three adapters (§4.1, §4.2, §4.4), so the
///   empty-platforms path is reached only by unknown-declaring sources
///   (flathub `arches: null`) or provisional repology-minted methods.
pub fn plan(&self, app: &App, host: &Platform) -> Result<Plan>;

pub enum Plan {
    /// argv for the native manager (`brew`, `flatpak`, `apt`, …).
    Command { program: String, args: Vec<String> },
    /// Host lacks the native manager; download + checksum-verify.
    DirectDownload { url: String, checksum: Option<Checksum> },
    /// The app doesn't claim the host platform.
    Unsupported,
}
```

```rust
impl App {
    /// Plan-time fallback: pick the best checksummed artifact for (os,
    /// arch) — exact arch match preferred, `arch: None` as wildcard —
    /// and wrap it as `InstallMethod::Direct`. `None` when no checksummed
    /// artifact matches (flathub apps never qualify: no checksums).
    pub fn direct_fallback(&self, os: Os, arch: Arch) -> Option<InstallMethod>;
}
```

**Who constructs `InstallMethod::Direct`**: no wave-1 adapter does (§4
maps never emit it; a cask's dmg stays an `Artifact`, never a second
install method). The variant exists in the model as the target type for
`direct_fallback`/`Plan::DirectDownload`; persisting a Direct method on an
`App` is a wave-2 decision. The Repology oracle is *not* an `Adapter`
impl — it has no search/browse surface worth exposing and installs
nothing; it feeds the AliasIndex.

**As built (plan 3.8, wave 4 — `src/adapter.rs`)**: the facade holds
`Vec<Arc<dyn Adapter>>` (an `Arc` so the toride-apps facade shares its
adapters with a `Registry`), and three of the sketch's details above
landed differently, deliberately:

- fan-out is **sequential in registration order**, not `tokio::join!` —
  a dynamic adapter vec has no `join_all` without adding `futures-util`
  or hand-rolling a combinator, and `tokio::spawn` would force a tokio
  runtime onto a facade the crate compiles without tokio (the `http`
  feature owns it). Per-source error tolerance, hit order, and the
  per-request timeouts are unaffected; only a slow source's latency
  serializes onto later sources.
- `PlannedOp::Command` stays a single `program` + `args` pair, so the
  flatpak one-time `remote-add` is **omitted** and stated as omitted in
  the variant's contract — the executor layers it, exactly like the
  suppression flags toride-apps adds at execution time; `plan` is an
  associated (pure) function, not a `&self` method.
- same-app **merging via the §5 alias rules landed in wave 5** (see the
  as-built note at the end of §5): `search` merges hits through the
  alias rules and records every merged row into the `AliasIndex` the
  facade owns; `resolve` keeps merging every hit's
  `sources` rows, deduplicated, and additionally consults that index
  when every primary lookup misses.
- `plan` gained lifecycle siblings in wave 5 — `plan_update` and
  `plan_uninstall`, still associated pure functions, mirroring
  toride-apps' `Operation::argv` spellings exactly: `brew
  upgrade/uninstall [--cask] <token>`, `flatpak update/uninstall --user
  <app_id>`, the per-family distro verbs (incl. apt's `install
  --only-upgrade` and pacman's `--sync --refresh`), and the language
  managers' own verbs (`npm update/uninstall -g`, `cargo install
  --force` / `cargo uninstall`, `pipx upgrade/uninstall`, `uv tool
  upgrade/uninstall`, `mise upgrade/uninstall`). Updates keep install's
  claim+manager gates minus the direct-download fallback; uninstalls
  skip the claim gate (claims are an install-only gate); `Direct`
  methods render `Unsupported` for both — a direct uninstall replays the
  manifest record's path, and a direct update is a fresh install
  decision, not a manager verb. The manager OS gate is cask-aware:
  Homebrew casks are macOS-only (toride-apps' `resolve_homebrew`
  refuses them elsewhere for every action) while formulae also plan
  under Linuxbrew.

## 4. Field mappings (source → normalized)

Verified against the named fixtures; `—` = dropped (documented, not lost:
the adapter's wire structs keep them if a later wave needs them).

### 4.1 Homebrew cask — `parse_cask_json` (fixtures `cask-brave-browser.json`, `cask-visual-studio-code.json`)

| Source field | Normalized |
|---|---|
| `token` | `install = Homebrew{cask:true, token}`; `sources[] += {HomebrewCask, token, repo:None}`; primary slugify input (§5) |
| `name[0]` | `name` (cask `name` is an array — homebrew.md §3) |
| `name[1..]`, `old_tokens[]` | `aliases` |
| `desc` | `summary` |
| `homepage` | `homepage` |
| `version` | `latest.value` — the top-level (API-default-platform) version only. Per-variation `version` overrides are NOT folded into `latest` (vscode's `big_sur`/`arm64_big_sur` carry 1.106.3 vs top-level 1.139.1 — a documented wave-1 loss; `Artifact` has no version field to carry them) |
| `url` + `sha256` (top level = the API's default platform — **the payload never names it**) | one `Artifact{url, checksum:Sha256, os:MacOs, arch:None, kind:Package}`; `arch: None` = undeclared (both fixtures' default URLs are arm64-macOS, but that is inference from the URL string, not contract) |
| `variations` — **pure-parser contract: no host parameter**. Each key shallow-merges over the top-level triple; key → (os, arch): `{release}` → (MacOs, X86_64), `arm64_{release}` → (MacOs, Aarch64), `{arch}_linux` → (Linux, arch); an explicit `"key": null` means "not available for this platform" (homebrew.md §4). Collapsed into one `Artifact` per **distinct (os, arch, url, sha256) tuple** across all available platforms | merged `sha256: null` → platform unavailable: no artifact, NOT claimed in `platforms` (brave `x86_64_linux`+`arm64_linux`, vscode `x86_64_linux`+`arm64_linux` — all four carry explicit `"sha256": null`, so NEITHER fixture claims Linux). Available variations with identical (url, sha256) dedupe: brave's 5 Intel-release keys → one (MacOs, X86_64) artifact |
| `supported_platforms` (10–14 release tags) ∪ claimed variation keys | `platforms`, deduped to distinct (os, arch) `Platform` values — the per-macOS-release dimension is dropped by the collapse (brave: 10 tags → 2 values, (MacOs, Aarch64) + (MacOs, X86_64), both `min_release: Some("13")` from `depends_on.macos.>=`; vscode: 14 tags → 2 values). Platform claims and artifacts are counted separately: (os, arch) claims dedupe, artifact tuples do not. Insta snapshots (§9) assert: brave 2 platforms / 2 artifacts (default + collapsed Intel); **vscode 2 platforms / 4 artifacts** (default + collapsed Intel 1.139.1 + `big_sur` 1.106.3 + `arm64_big_sur` — `big_sur` is a distinct (MacOs, X86_64, url, sha256) tuple from the collapsed Intel, so the tuple rule keeps it; its per-release version is dropped, see caveat 1) |
| `deprecated` / `disabled` | `availability` |
| `artifacts[]` (`app`/`binary`/`zap`…) | wave 1: install steps not modeled (install is delegated to `brew`). `binaries` extraction is PINNED: for every `binary` artifact, take the basename (text after the final `/`) of each payload string, deduplicated, in payload order — vscode → `["code", "code-tunnel"]` (payloads `$APPDIR/…/bin/code`, `$APPDIR/…/bin/code-tunnel`), brave → `[]` (no `binary` artifact). Same rule if derived from `target` (`$HOMEBREW_PREFIX/bin/code`) — both agree on the fixtures |
| `analytics`, `generated_date`, `installed`, `outdated`, `pinned`, `tap_git_head`, `ruby_source_*` | — (local-state echoes are always null server-side, homebrew.md §3) |

Cask-variation caveats, stated so the implementer cannot guess wrong:

1. The collapse is lossy on versions only, not on artifacts: vscode's `big_sur`/`arm64_big_sur` override `version` to 1.106.3; those per-release versions are dropped (no `version` on `Artifact`, and `latest` stays 1.139.1) while their artifacts are KEPT as distinct (os, arch, url, sha256) tuples — vscode ends with 4 artifacts against only 2 platform claims. The alternative "newest-version override wins per (os, arch)" drop rule was rejected because picking the newest requires version ordering, which §2 excludes for wave 1 (versions are opaque strings). A future per-platform-version need is a model change, not a parser tweak.
2. vscode's linux variation URLs are darwin-path placeholders (`…/update.code.visualstudio.com//darwin/stable`, empty version segment) — moot in wave 1 because their explicit `"sha256": null` makes Linux unavailable under the rule above. No URL-vs-os validation is performed; a validator is a wave-2 refinement.
3. Absent vs null matters: a missing key inherits the top-level value; an explicit `null` marks unavailability. Wire structs must distinguish the two — model override fields as `Option<Option<String>>` (e.g. `#[serde(default, deserialize_with = "...double option...")]`) or inspect key presence on the raw map.

### 4.2 Homebrew formula — `parse_formula_json` (fixture `formula-ripgrep.json`)

| Source field | Normalized |
|---|---|
| `name` / `full_name` | `install = Homebrew{cask:false, token:name}`; `sources[] += {HomebrewFormula, name}` |
| `aliases[]`, `oldnames[]` | `aliases` |
| `desc` / `homepage` / `license` | `summary` / `homepage` / `license` |
| `versions.stable` | `latest.value` (head/bottle flags ignored) |
| `bottle.stable.files.{platform}` (`arm64_golden_gate`, `sonoma`, `arm64_linux`, `x86_64_linux`, …) → `{url, sha256}` | one `Artifact{kind:Bottle, checksum, arch, os}` per file; platform tag decoded: `*_{linux}` → Linux, `arm64_*` → Aarch64, else X86_64 |
| `bottle.stable.files` platform tags (same decode) | `platforms` = one (os, arch) `Platform` per distinct tag — formula Apps are never `platforms: []` (fixture `ripgrep`: 7 tags → 4 values, (MacOs, Aarch64) + (MacOs, X86_64) + (Linux, Aarch64) + (Linux, X86_64); `min_release: None` — bottles declare no minimum release). A formula with `bottle: false` (source-only) gets `platforms = []` (unknown) |
| `urls.stable.{url,checksum}` | `Artifact{kind:Source}` |
| `executables` (`["rg"]`) | `binaries` |
| `dependencies` | — (dependency graph is a later wave) |
| `deprecated`/`disabled` | `availability` |

### 4.3 Flathub — `parse_search_envelope` + `parse_appstream_detail` (fixtures `search-brave-browser.json`, `appstream-com.visualstudio.code.json`, `appstream-com.brave.Browser.json`)

| Source field | Normalized |
|---|---|
| hit `app_id` (dotted — **not** `id`, which is the underscored Meilisearch key, flathub.md §app_id) | `install = Flatpak{app_id, remote:"flathub"}`; `sources[] += {Flathub, app_id, repo:None}` |
| `name` | `name` |
| `summary` / detail `summary` | `summary` |
| hit `description` (plain/markdown) / detail `description` (**HTML** — strip tags) | `description` |
| `project_license` | `license` |
| `developer_name` | `developer` |
| `arches` (nullable) | `platforms` = Linux × each arch; `null`/empty → `platforms = []` (unknown) |
| detail `releases[0].version` + `timestamp` | `latest` (`releases[0]` is current — flathub.md §app detail). **Wire gotcha**: `timestamp` is a string-encoded int (`"1790208000"` in both detail fixtures) against `Version::published_unix: Option<i64>` — the serde wire struct needs a string-or-int deserializer, the same defensive treatment §4.3 already prescribes for `main_categories` |
| detail `bundle.value` (`app/com.brave.Browser/x86_64/stable`) | confirms `install`; arch cross-check against `arches` |
| detail `urls.homepage` | `homepage` |
| `verification_*`, `trending`, `installs_last_month`, `favorites_count`, `categories`/`main_categories`, icons, screenshots, `runtime`, `kudos` | — (search envelope leaks Meilisearch internals; treat as unstable, flathub.md §Limitations) |
| checksums | **none exist** (verified absent across API, flatpakref, OpenAPI — flathub.md §Limitations) → `artifacts = []`; `InstallMethod::Flatpak` delegates integrity to the flatpak client |
| `main_categories` | parsed defensively: `anyOf[string, string[]]` (bare string in both live fixtures) |

### 4.4 AppStream / DEP-11 — `parse_dep11_catalog` (fixture `debian-sid-main-amd64.yml`; header + 3 components verified verbatim)

| Source field | Normalized |
|---|---|
| header `Origin` (`debian-sid-main`) + URL path | `sources[].repo`; `InstallMethod::Distro{family, repo}` — family decoded from origin/URL layout (`debian*` → Debian, `noble`/`questing`… → Ubuntu; layouts verified identical, appstream.md §3) |
| catalog filename `Components-<arch>.yml.gz` (the fetch URL, not a YAML field) | `platforms` = `[(Linux, arch)]` — `amd64` → X86_64, `arm64` → Aarch64 (fixture filename `…-amd64.yml` → (Linux, X86_64)); a catalog with no decodable arch → `platforms = []` (unknown). Distro Apps are thus never claim-less for the arch the catalog was fetched for |
| `ID` (`firefox-esr.desktop`, `org.gnome.TextEditor` — both ID styles coexist, appstream.md §4) | `sources[] += {Distro, Package, repo:Origin}`; slugify input |
| `Name.C` / `Summary.C` | `name` / `summary` (dict maps with mandatory `C` key) |
| `Description.C` (HTML) | `description` (stripped) |
| `Package` (near-universal: 2,626/2,627 in sid/main) | `install.package`; `sources[] += {Distro, package}` when it differs from `ID` |
| `ProjectLicense` | `license` |
| `Developer` — dict `{id, name:{locales}}` (fixture `org.gnome.TextEditor`; 942/2,627 components live per appstream.md §4) | `developer` = `Developer.name.C`, falling back to `Developer.id`; absent → `None` (previously silently unmapped) |
| `Releases[0].version` + `unix-timestamp` | `latest` (optional — only 854/2,627 have Releases) |
| `Provides.binaries` (`binaries: [amsynth]`) | `binaries` (the tool-detection join key, appstream.md §5); `Provides.mediatypes` — |
| `Launchable.desktop-id`, `Categories`, `Icon`, `Screenshots`, `Keywords`, `ContentRating`, `Requires/Supports/Branding` | — |
| parse strictness | `#[serde(default)]` + ignore-unknown everywhere ("fields not mentioned … are not recognized by DEP-11 parsers", appstream.md §4); every field `Option` (brief's frequency table: even `Package` is missing once) |

**Coverage honesty note on `Provides.binaries`**: no fixture component
exercises it — all three components in
`tests/fixtures/appstream/debian-sid-main-amd64.yml` carry only
`Provides.mediatypes`; the `binaries: [amsynth]` example exists only in
the live catalog (appstream.md §4). The primary tool-detection join key
(`App.binaries`) therefore has **zero offline test coverage** until the
fixture gains a binaries-bearing component. Adding one (verbatim from the
live catalog, documented in the fixture's `_meta.json`) is an explicit
implementation-step follow-up — see §7, appstream entry. This sandbox's
rules made DESIGN.md the only editable file, so the fixture was not
extended here.

Filter to `Type: desktop-application` (+ `console-application` for CLI).
Matching fallback chain (appstream.md §7): `Provides.binaries` → `Package`
exact → `Launchable.desktop-id`/`ID` basename.

### 4.5 Repology — `parse_repology_project` (fixture `project-brave-browser.json`, **synthetic** — host unreachable, meta records why)

| Source field | Normalized |
|---|---|
| `repo` (`homebrew`, `debian_13`, `fedora_rawhide`, `arch`, `alpine_edge` — all verified-real repo ids) | `AliasCandidate.repo` → `SourceRef.repo` |
| `srcname` / `binname` | candidate per-source ids (prefer `srcname` for source-based repos, `binname` for binary lookup — repology.md §3); arch `binname` `brave` ≠ project name is exactly the case this oracle exists for |
| `version` / `origversion` | candidate `Version{value, original}` |
| `status` (`newest`/`outdated`/`devel`/`ignored`/…) | candidate quality filter (skip the `is_ignored` set, repology.md §2); not surfaced on `App` |
| `summary` | fills a missing `summary` on merge only |
| `name` | tolerated via `#[serde(default)]` — serialized only ≤2023 (repology.md §2 era drift) |
| `families` | parsed-but-ignored: **never** serialized upstream in any era (repology.md §2); present in the fixture only per assignment spec |

## 5. Alias strategy: toride id ↔ per-source ids

**Canonical id derivation** (deterministic, in priority order):

1. If the Repology oracle knows the app → `TorideId::slugify(repology
   project name)` — Repology's rule-driven canonicalization
   (repology-rules) is maintained upstream and coalesces differently
   named packages ("project has its own name … to coalesce differently
   named packages", repology.md §3).
2. Else → `TorideId::slugify(first source id)`.

**Collision policy**: same slug + same homepage/developer → same app,
merge `sources`. Same slug + different homepage → suffix the source key
(`brave-browser-flathub`) — rare, since Repology names are global.

**The AliasIndex** is `HashMap<TorideId, Vec<SourceRef>>`, persisted as
JSON (serde), built from three inputs:

1. **Repology forward oracle** (canonical → per-repo names): `GET
   /api/v1/project/<name>` → filter entries by tracked repos (`homebrew`,
   `debian_*`, `fedora_*`, `arch`, `alpine_edge`) → `srcname`/`binname` →
   `SourceRef{Distro, id, repo}` per entry. One request, no auth.
2. **Repology reverse oracle** (per-source name → canonical): `GET
   /tools/project-by?repo=<repo>&name_type=srcname|binname&name=<id>&target_page=api_v1_project`
   → **302** Location names the project; **300** JSON `{"targets": …}` =
   ambiguous (record all candidates, decide by homepage match later);
   **404** = unknown → fall back to rule 2 of derivation. Behavior
   verified against `tools.py:77-139` in repology.md §3.
3. **Local discovery**: every adapter `lookup`/`search` result carries its
   own `SourceRef`, and cross-source merging matches on repology-given
   names first, then normalized-name equality + platform overlap, then
   homepage equality.

**Flathub bridging (honest scope note)**: the survey verified Repology
repo ids for homebrew + four distro families but found **no** verified
flathub repo id in `repos.d` (repology.md §1) — reverse-DNS flatpak ids
are therefore bridged into the alias table by name-based Flathub search
(prefer exact `name` match, `verification_verified: true`) and persisted
once resolved; no repology-mediated flathub aliasing is claimed in wave 1.

**Repology client policy** (repology.md §4, docs verbatim): ≤ 1 req/s
sustained (serialized in `RepologyClient`), descriptive User-Agent,
aggressive caching (alias data is slow-moving; cache TTL ≥ 1 day),
single-project lookups are the cheap path, bulk sweeps use the dump
service not the API. Parse tolerantly: "API stability is currently not
guaranteed".

**Repology as fallback install hint**: where a distro family has no
adapter yet (Arch, Alpine), a repology row for that family can be minted
into a *provisional* `InstallMethod::Distro{family, repo, package}`
(binname/srcname is the package name the family's manager knows).
Provisional is REPRESENTED, not prose: the minted `SourceRef` carries
`provisional: true` (`#[serde(default)]`, §2) — it survives the index's
JSON persistence and any real adapter that later parses the family's own
catalog replaces the row with `provisional: false`.

**As built (wave 5 — `src/alias.rs`)**: the index is a `BTreeMap`
(the JSON serialization is deterministic), owned by the `Registry`
facade behind a `Mutex` and preloadable through
`RegistryBuilder::with_alias_index`; `search` records every merged row
into it and `resolve` consults it when every primary lookup misses. The
merge implements the **offline subset** of the rules above only — the
Repology forward/reverse oracle fill (inputs 1–2) is still future work,
so `same_app` joins on: no homepage/developer conflict (the collision
policy's guard), then a shared canonical slug, an explicitly equal
homepage, or any shared alias-name slug (`slugify` of `name` or an
`aliases` entry, the degenerate `unnamed` slug excluded). The
normalized-name **platform-overlap** conjunction is deliberately not
required: a cask claims macOS and its flatpak twin claims Linux, so
per-source platform carving is exactly the case the merge exists for.
The registration-first row is the survivor — its id, name, install
method, and availability govern; a merged hit only unions its
`SourceRef`s and `aliases` in and backfills the survivor's unset
descriptive fields (`summary`, `description`, `homepage`, `license`,
`developer`, `latest`). Merging is **across adapters only**:
`merge_hits` buckets hits per adapter and never joins two rows from
the same bucket, so two distinct same-named apps one source returns
stay separate result rows. The collision policy's suffix branch is
implemented there too: a hit whose canonical slug is already taken by
a non-joinable row (conflicting homepage/developer, or the same
adapter's second row) gets its source key appended — `notes` from
flathub vs a conflicting cask `notes` → `notes-flathub` — repeated
while the suffixed id is also taken, so no two result rows share one
`TorideId` and the index's per-id rows stay unambiguous; a row
carrying no `SourceRef` cannot be suffixed and keeps the colliding
id.

## 6. Coverage matrix

| System / stack | Wave 1 (this run) | Install path | Wave 2+ |
|---|---|---|---|
| macOS — GUI apps | ✅ Homebrew casks | `brew install --cask <token>` (+ `Direct` artifact fallback with published sha256) | — |
| macOS — CLI tools | ✅ Homebrew formulae (bottles for arm64/x86_64 macOS + Linux) | `brew install <name>` | nixpkgs / mise-registry as alternates |
| macOS — Apple silicon + Intel | ✅ (cask `variations`, formula bottle files both carry per-arch payloads) | as above | — |
| Linux — GUI apps, any distro with flatpak | ✅ Flathub | `flatpak install flathub <app_id>` | — |
| Debian + derivatives | ✅ DEP-11 catalogs (Debian sid layout verified live; Ubuntu `archive.ubuntu.com` layout verified identical, appstream.md §3) | `apt install <package>` | — |
| Ubuntu | ✅ (same DEP-11 layout) | `apt install <package>` | — |
| Fedora | ❌ **not covered in wave 1** — verified: no URL-addressable GUI-app catalog on Fedora mirrors (no appstream repodata type; the `fedora-appstream-metadata` RPM is a ~12 KB stub), appstream.md §3 | — | RPM primary-repodata adapter (roadmap §8) |
| Arch / Alpine | ⚠️ alias names + provisional `Distro` install descriptors via Repology only (no catalog search) | provisional `pacman -S` / `apk add` | per-distro adapters |
| Windows | ❌ | — | winget (roadmap §8) |
| Cross-source aliasing | ✅ Repology oracle (parse-only wave 1: synthetic fixture; live client env-gated) | — | enable live once reachable |

Honest gaps: repology.org was unreachable from this sandbox at design time
(`curl` → `000`, §0), so every repology claim rests on upstream docs +
source, and its fixture is synthetic. Fedora coverage requires a *new*
adapter kind (RPM repodata) that no surveyed brief covers yet.

## 7. Work breakdown — wave 1 (now)

Each entry: adapter name (surveyed keys), scope, fixtures its tests must
parse, priority. Fixture paths are workspace-relative.

- **homebrew** — priority: **now**.
  Scope: implement `HomebrewAdapter` + `HomebrewClient` against
  formulae.brew.sh per-item endpoints (`/api/cask/{token}.json`,
  `/api/formula/{name}.json`; catalogs are tens of MB — per-item only in
  wave 1, homebrew.md §1–§2). Pure parsers `parse_cask_json` /
  `parse_formula_json` with `#[serde(default)]` wire structs (docs promise
  no stability guarantees; analytics/generated_date are per-item-only).
  Cask path implements the §4.1 variations contract — pure collapse into
  one `Artifact` per distinct (os, arch, url, sha256) tuple, explicit
  `null` overrides = platform unavailable (no host parameter, absent-vs-
  null distinction per §4.1 caveat 3) — plus `platforms` dedupe,
  artifacts, availability.
  Formula path implements bottle-file → per-platform `Artifact` decoding
  and `executables` → `binaries`. Emits `InstallMethod::Homebrew` plus
  `Package`/`Bottle`/`Source` artifacts with published sha256.
- **flathub** — priority: **now**.
  Scope: implement `FlathubAdapter` + `FlathubClient` (`POST /api/v2/
  search`, `GET /api/v2/appstream/{app_id}`; the v1 API and `/app/{id}`
  REST routes are verified-gone, flathub.md §API surface). Parsers handle
  the Meilisearch envelope (unstable facet keys ignored), `main_categories`
  string-or-array, hit `id` vs `app_id` distinction, HTML→text detail
  descriptions, `releases[0]` → `latest` (string-encoded `timestamp` →
  `published_unix` via a string-or-int deserializer). `artifacts` stays
  empty (no checksums exist anywhere in the API — verified); install is
  `InstallMethod::Flatpak{remote:"flathub"}`. Also parse the `.flatpakref`
  pointer into `FlatpakRef { name, branch, title, url, suggest_remote_name,
  gpg_key, runtime_repo }` (§4.3) for the remote-setup flow.
- **appstream** — priority: **now**.
  Scope: implement `AppstreamAdapter` + `AppstreamClient` for the
  Debian/Ubuntu DEP-11 layout (`dists/<suite>/<component>/dep11/
  Components-<arch>.yml.gz`) — stream the .yml.gz download to the disk
  cache, then hand the fully decompressed ~27 MB text to the pure parser
  (§3.1). Parse with serde_yaml + `#[serde(default)]` (§4.4 strictness
  note); emit `Distro{family, repo, package}` installs scoped by `Origin`;
  `Provides.binaries` → `binaries` with the Package/ID fallback chain.
  Filter `desktop-application` + `console-application`. Implementation
  follow-up: extend `debian-sid-main-amd64.yml` with one binaries-bearing
  component (verbatim from the live catalog, documented in its
  `_meta.json`) so `Provides.binaries` gains offline coverage (§4.4 note).
  The `fedora-43-os-metainfo.xml` fixture is REFERENCE-ONLY — no wave-1
  parser reads it (it is metainfo XML, not DEP-11 YAML; see the §7
  fixture tables); Fedora catalog coverage is explicitly NOT in scope
  (verified absent, appstream.md §3).
- **repology** — priority: **now** (parse-only; live client behind
  `TORIDE_REGISTRY_INTEGRATION=1`).
  Scope: implement `parse_repology_project` over `/api/v1/project/<name>`
  payloads (bare JSON array; mandatory fields only `repo`+`version`,
  everything else optional/era-dependent — parse with defaults, never
  rely on `name`/`families`), plus `RepologyClient` (`fetch_project`,
  `resolve_by_name` via `/tools/project-by` handling 302/300/404, ≥1 s
  request spacing, descriptive UA). Output feeds `AliasIndex`
  (`AliasCandidate`), not the `Adapter` search surface. Wave-1 tests run
  exclusively against the synthetic fixture; the host is unreachable
  (verified, §0) so any live test is env-gated and skipped by default.
- **ecosystems** — priority: **later** (roadmap §8; listed here because it
  is a surveyed key).
  Scope: umbrella for winget-pkgs, nixpkgs, mise-registry, AppImage
  catalog — brief-only survey exists (ecosystems.md), no adapter and NO
  parsers in this wave; none of the four unblocks wave 1 (Windows-only
  payloads, unofficial endpoint, redundant with toride-mise,
  metadata-only feed). Its fixture files are RESERVED for wave-2
  parse-only tests — see the wave-2 table below; no wave-1 test touches
  them.

Wave-1 fixture files per adapter (wave-1 tests must parse exactly these):

| adapter | fixtures |
|---|---|
| homebrew | `crates/toride-registry/tests/fixtures/homebrew/cask-brave-browser.json`, `crates/toride-registry/tests/fixtures/homebrew/cask-visual-studio-code.json`, `crates/toride-registry/tests/fixtures/homebrew/formula-ripgrep.json` |
| flathub | `crates/toride-registry/tests/fixtures/flathub/search-brave-browser.json`, `crates/toride-registry/tests/fixtures/flathub/search-visual-studio-code.json`, `crates/toride-registry/tests/fixtures/flathub/appstream-com.brave.Browser.json`, `crates/toride-registry/tests/fixtures/flathub/appstream-com.visualstudio.code.json`, `crates/toride-registry/tests/fixtures/flathub/com.brave.Browser.flatpakref` |
| appstream | `crates/toride-registry/tests/fixtures/appstream/debian-sid-main-amd64.yml` |

Reference-only fixture (NO wave-1 parser reads it — kept for provenance
and the wave-2 Fedora work): `fedora-43-os-metainfo.xml` is metainfo XML
(`<?xml … <component type="operating-system">`), not DEP-11 YAML, so
`parse_dep11_catalog` cannot read it and §3.1 deliberately defines no
metainfo-XML parser; Fedora coverage stays out of scope (§6).
| repology | `crates/toride-registry/tests/fixtures/repology/project-brave-browser.json` (synthetic) |

Wave-2 reserved fixtures (NO wave-1 parser reads these; writing parsers
for them now is out of scope — they belong to the roadmap-§8 adapters):

| future adapter | fixtures |
|---|---|
| ecosystems (winget) | `crates/toride-registry/tests/fixtures/ecosystems/winget/Brave.Brave.yaml`, `crates/toride-registry/tests/fixtures/ecosystems/winget/Brave.Brave.installer.yaml`, `crates/toride-registry/tests/fixtures/ecosystems/winget/Brave.Brave.locale.en-US.yaml` |
| ecosystems (nixpkgs) | `crates/toride-registry/tests/fixtures/ecosystems/nixpkgs/search-hello-26.05.json` |
| ecosystems (mise-registry) | `crates/toride-registry/tests/fixtures/ecosystems/mise/ripgrep.toml` |
| ecosystems (appimage) | `crates/toride-registry/tests/fixtures/ecosystems/appimage/feed-trimmed.json` |

## 8. Roadmap (later waves — design intent only, no wave-1 work)

- **winget** (ecosystems/winget fixtures): multi-file manifests per
  version dir under `manifests/<letter>/<Publisher>/<Package>/`;
  `defaultLocale` → name/license/description, `Installers[]` → per
  (arch × scope) `Artifact{Package}` **with published sha256**;
  `InstallMethod` needs a `Winget{package_id}` variant + `Os::Windows`
  becomes real. Windows hosts only.
- **nixpkgs** (ecosystems/nixpkgs fixture): search.nixos.org backend —
  unofficial Elasticsearch behind credentials scraped from the frontend
  bundle; schema-versioned index name needs a discovery step. One query
  spans macOS+Linux (`package_platforms`); install is
  `nix profile install nixpkgs#<attr>` — no URLs/hashes published.
  High coverage, fragile contract.
- **mise-registry** (ecosystems/mise fixture): per-tool TOMLs in jdx/mise
  `registry/`; `backends[]`/`bins`/`aliases` map CLI short-names to
  backends. Cheapest later item and mostly redundant with the existing
  `toride-mise` runtime integration (`mise registry --json`); valuable
  only for hosts without mise.
- **appimage** (ecosystems/appimage fixture): JSON Feed v1 metadata-only
  (no versions/checksums); `links[GitHub]` second hop needed for assets.
  ~1.6k desktop-oriented entries; marginal vs Flathub.
- **Fedora RPM repodata**: new adapter kind — primary.xml repodata
  (`requires`/`provides`) replaces the AppStream catalog Fedora does not
  publish; fills the one verified wave-1 Linux gap (§6).
- **Repology live**: flip the env-gated network tests on once the host is
  reachable; add the `distromap` bulk alternative for repo→repo naming.

## 9. Crate shape, dependencies, testing

Layout follows conventions.md §1–§4 (`[lints] workspace = true` last,
installer's four crate attributes, single error enum → unprefixed
`Error`/`Result`, `//!` module docs with `rust,ignore` doctests):

```
crates/toride-registry/src/
  lib.rs        crate docs + attribute block + pub mod + re-exports
  model.rs      §2 types
  error.rs      Error/Result (Parse/Http/UnsupportedSource variants)
  adapter.rs    Adapter trait, Registry facade
  http.rs       build_http_client + timeout consts (§3.2)
  alias.rs      TorideId derivation, AliasIndex, AliasCandidate (§3.1), oracle glue
  sources/{homebrew,flathub,appstream,repology}.rs
tests/          fixture suites + TORIDE_REGISTRY_INTEGRATION=1 network tests
```

Dependencies: workspace-managed `serde`, `serde_json`, `thiserror`,
`async-trait`, `camino`, `reqwest` (workspace shape already
`rustls-tls`+`json`), `tokio`; inline-pinned with comments per
conventions.md §1.3: `serde_yaml = "0.9"` (DEP-11; the survey's
recommendation, appstream.md §6 — note upstream serde_yaml is archived;
if that blocks, swap the YAML backend behind the parser signature,
which stays `&str → Result<Dep11Catalog>`), `flate2 = "1"` (optional,
`http` feature — same C-free story as installer's gzip support).
Feature `http` (default on, mirroring installer's `default =
["http"]`, installer Cargo.toml:11-20) gates reqwest/flate2 + the
clients so parsers build fully offline.

Testing (conventions.md §7): inline `#[cfg(test)]` parser tests parsing
the §7 fixtures via an `env!("CARGO_MANIFEST_DIR")`-anchored helper (no
`include_str!`); insta snapshots of normalized `App` output per fixture,
asserting the deduped tuples §4.1 pins down (brave: 2 platforms / 2
artifacts; vscode: 2 platforms / 4 artifacts — default + collapsed Intel
+ `big_sur` + `arm64_big_sur`; artifact tuples dedupe, platform claims
dedupe separately);
`TORIDE_REGISTRY_INTEGRATION=1` network tests that live-fetch one cask /
one flathub app / one DEP-11 catalog and assert the §3.1 compared
invariant set (same fields populated, artifact count + kinds,
install-method variant + identifying payload, `SourceRef` set) — never
field-for-field equality against the fixtures frozen 2026-09-28, which
upstream drift (cask `version`/`generated_date`, flathub
`releases[0].version`, DEP-11 republication ~daily) would break
immediately (repology test stays skip-by-default; host unreachable
here — §0).

## 10. Open risks

1. **Repology is dual-sourced**: synthetic fixture + docs-derived field
   set. First live contact must re-verify the §4.5 mapping (fixture meta
   says exactly which fields were invented).
2. **formulae.brew.sh publishes no stability guarantees** (homebrew.md
   §1) — the `#[serde(default)]` wire structs are the mitigation; new
   required keys upstream must degrade to `None`, never error.
3. **Flathub versions are query-time only** (`releases[0]`, ≤4 kept,
   no older-version endpoint) — `latest` is advisory; pinning a flathub
   version is impossible via API (flathub.md §Limitations).
4. **DEP-11 catalogs are big** (8.7 MB gz / ~27 MB decompressed for
   sid/main): streamed download to the disk cache is a wave-1
   requirement, and the pure parse holds the whole decompressed text in
   memory (§3.1); the lighter `CID-Index-<arch>.json.gz` is the fallback
   if that proves too heavy.
5. **Fedora remains uncovered** until the RPM-repodata adapter exists —
   stated in §6 rather than papered over.
