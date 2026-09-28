//! Repology oracle — resolves toride ids ↔ per-source ids and quality-
//! filters repology project data. Parse-only in wave 1: it is NOT an
//! [`Adapter`](crate::adapter::Adapter) impl (no search/browse surface,
//! installs nothing); its output feeds the alias index (DESIGN.md §5).
//!
//! The module is split per the house parse/fetch rule (DESIGN.md §3.1):
//!
//! - **Parse half** (pure, `&str` in → candidates out, fixture-tested
//!   offline): [`parse_repology_project`] over `/api/v1/project/<name>`
//!   payloads — bare JSON arrays whose only mandatory fields are `repo`
//!   and `version`; everything else is parsed with defaults and never
//!   relied on (`name` was serialized only ≤2023, `families` is never
//!   serialized upstream — both are tolerated as ignored keys).
//!   [`select_source_id`] states the repo-class id rule the alias index's
//!   insertion applies, and [`status_is_ignored`] names the statuses the
//!   index drops at build time.
//! - **Fetch half** (thin client, `http`-feature-gated):
//!   [`RepologyClient::fetch_project`] and
//!   [`RepologyClient::resolve_by_name`] (the `/tools/project-by` reverse
//!   oracle, 302/300/404), serialized to ≥1 request/second with a
//!   descriptive User-Agent and an aggressive cache per the upstream
//!   fair-use policy (repology.md §4).
//!
//! repology.org is unreachable from the wave-1 sandbox (re-verified
//! 2026-09-28: `curl -s -m 10` → HTTP 000, exit 7, connection refused —
//! DNS pinned; DESIGN.md §0), so offline tests run exclusively against the
//! synthetic fixture `tests/fixtures/repology/project-brave-browser.json`
//! (provenance in its sibling `_meta.json`). Live tests are gated behind
//! `TORIDE_REGISTRY_INTEGRATION=1` AND the `http` feature and are skipped
//! by default:
//!
//! ```sh
//! TORIDE_REGISTRY_INTEGRATION=1 cargo test -p toride-registry --lib
//! ```
//!
//! ## Design
//!
//! 1. **Parse** — one [`AliasCandidate`] per payload entry, even when both
//!    name slots are set (the fixture's `arch` entry carries
//!    `srcname brave-browser` + `binname brave` and yields ONE candidate).
//!    Both names are kept so the index can be rebuilt under a different
//!    selection rule without re-fetching. (Wave-1 deviation, recorded for
//!    the gate phase: DESIGN.md §3.1 places [`AliasCandidate`] in
//!    `src/alias.rs`, which the scaffold never created, so it is defined
//!    here next to its only producer — see its struct docs.)
//! 2. **Classify** — the alias index (not this module) inserts rows; this
//!    module owns the repology-specific rules it applies: which of
//!    `srcname`/`binname` keys the row per repo class, which
//!    [`DistroFamily`] a repo id maps to, whether that family's row is
//!    provisional (only Arch and Alpine have no wave-1 adapter — DESIGN.md
//!    §5), and which statuses are ignorable.
//! 3. **Fetch** — the client returns raw body text, so live payloads and
//!    the fixture flow through the same parse signature. All requests
//!    share one rate-limit gate; payloads and resolutions are cached for
//!    [`CACHE_TTL`] (≥ 1 day, DESIGN.md §5).

use crate::error::{Error, Result};
use crate::model::{DistroFamily, Version};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

// Fetch-half imports; every item below that needs them repeats
// `#[cfg(feature = "http")]` (conventions.md §4).
#[cfg(feature = "http")]
use reqwest::StatusCode;
#[cfg(feature = "http")]
use std::collections::HashMap;
#[cfg(feature = "http")]
use std::sync::{Mutex, PoisonError};
#[cfg(feature = "http")]
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// Parse half — pure, no clock/no network/no client (DESIGN.md §3.1)
// ---------------------------------------------------------------------------

/// One repology project entry → alias-index row input.
///
/// DESIGN.md §3.1 declares this as an alias-layer type owned by
/// `src/alias.rs` (deliberately NOT in `model.rs` — it never crosses the
/// adapter boundary to downstream), with `sources/repology.rs` as its only
/// producer. The scaffold phase never created `src/alias.rs`, so wave 1
/// defines it here, next to that producer; the post-join alias/gate phase
/// should move it (or `pub use` it from the alias module) when the alias
/// index lands.
///
/// ONE repology entry yields ONE candidate even when both name slots are
/// set (the fixture's `arch` entry: `srcname brave-browser` +
/// `binname brave`). Both names are kept so the index can be rebuilt under
/// a different selection rule without re-fetching; [`select_source_id`]
/// states the repo-class rule the index's insertion applies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AliasCandidate {
    /// Repology repo id (`homebrew`, `debian_13`, `fedora_rawhide`,
    /// `arch`, `alpine_edge` — all verified-real repo ids) →
    /// `SourceRef.repo`.
    pub repo: String,
    /// Entry-level: every name below shares this version.
    pub version: Version,
    /// Raw `status` (`newest`, `outdated`, `devel`, …); the
    /// [`status_is_ignored`] set is dropped at index-build time, not at
    /// parse time.
    pub status: String,
    /// Fills a missing `summary` on merge only (DESIGN.md §4.5).
    pub summary: Option<String>,
    /// Source-package name, where the repo publishes one.
    pub srcname: Option<String>,
    /// Binary-package name, where the repo publishes one (`arch`:
    /// `brave` ≠ the project name `brave-browser` — the case this oracle
    /// exists for).
    pub binname: Option<String>,
}

/// `id` filler for [`Error::Parse`] raised by [`parse_repology_project`].
///
/// The declared parse signature takes only the payload text, so a
/// structurally broken payload cannot name the project it came from; the
/// endpoint shape stands in (diagnostic only — the caller that fetched the
/// payload knows the project name).
const PARSE_ERROR_ID: &str = "(repology project payload)";

/// Wire shape of one `/api/v1/project/<name>` entry (repology.md §2).
///
/// Upstream marks only `repo` and `version` mandatory; the 2017→master
/// serializer also emitted `subrepo`, `visiblename`, `categories`,
/// `licenses`, `maintainers`, `vulnerable`, plus era-dependent `name`
/// (≤2023) and long-gone `keyname`/`www`/`downloads`. All of those — and
/// `families`, which no serializer revision ever serialized into an entry —
/// are tolerated by serde's default ignore-unknown behavior and
/// deliberately not modeled: parse with defaults, rely on neither
/// (`#[serde(default)]` on the struct makes every field optional, the
/// era-drift mitigation the survey prescribes).
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct RepologyEntry {
    /// Repology repo id (`homebrew`, `debian_13`, `fedora_rawhide`,
    /// `arch`, `alpine_edge`). Mandatory upstream, yet only serialized
    /// when truthy — `None` marks an entry the contract violated.
    repo: Option<String>,
    /// Source-package name, where the repo has one.
    srcname: Option<String>,
    /// Binary-package name, where the repo has one (`arch`:
    /// `brave` ≠ project name `brave-browser` — the case this oracle
    /// exists for).
    binname: Option<String>,
    /// Sanitized version. Mandatory upstream, same truthy-only caveat as
    /// [`RepologyEntry::repo`].
    version: Option<String>,
    /// Repo-native spelling with distro suffixes (`1.79.126-1`,
    /// `1.83.112-1.fc44`, `1.83.120-r0`); `null` upstream when equal to
    /// `version`.
    origversion: Option<String>,
    /// Raw package status; upstream serializes it unconditionally, but
    /// `Option` keeps an absent OR null field from being fatal
    /// (`#[serde(default)]` covers absent keys only) — it defaults to the
    /// empty string in the candidate. Quality filtering happens at
    /// index-build time via [`status_is_ignored`], not here.
    status: Option<String>,
    /// One-line description; fills a missing `summary` on merge only
    /// (DESIGN.md §4.5).
    summary: Option<String>,
}

/// Parse one `/api/v1/project/<name>` payload into alias candidates.
///
/// The payload is a bare JSON **array** of package entries (repology.md
/// §1). One entry yields one [`AliasCandidate`] even when both name
/// slots are set — the fixture's `arch` entry (`srcname brave-browser` +
/// `binname brave`) is ONE candidate; the alias index later picks a single
/// id per candidate via [`select_source_id`]. Each candidate's
/// [`Version`](crate::model::Version) carries `version` as
/// `Version::value` and `origversion` as `Version::original`
/// (`Version::published_unix` stays `None` — repology publishes no
/// per-entry timestamps).
///
/// Entries violating the mandatory-field contract (no `repo`, no
/// `version`, or empty either) are **skipped, not fatal**: upstream only
/// serializes those fields when truthy and promises no API stability, and
/// one malformed entry must not discard a whole project's alias data.
///
/// # Errors
///
/// [`Error::Parse`] when the payload is not a JSON array of objects — an
/// HTML error page, or the `/api/v1/projects/` envelope (a JSON *object*,
/// a different endpoint).
///
/// # Example
///
/// ```
/// use toride_registry::sources::repology::{parse_repology_project, select_source_id};
///
/// let candidates = parse_repology_project(
///     r#"[{"repo": "arch", "version": "1.83.112",
///          "srcname": "brave-browser", "binname": "brave"}]"#,
/// )?;
/// assert_eq!(candidates.len(), 1);
/// // Binary-install repos key on the name the family's manager knows.
/// assert_eq!(select_source_id(&candidates[0]).as_deref(), Some("brave"));
/// # Ok::<(), toride_registry::Error>(())
/// ```
pub fn parse_repology_project(payload: &str) -> Result<Vec<AliasCandidate>> {
    let entries: Vec<RepologyEntry> =
        serde_json::from_str(payload).map_err(|error| Error::Parse {
            kind: "json",
            id: PARSE_ERROR_ID.to_owned(),
            message: error.to_string(),
        })?;
    Ok(entries
        .into_iter()
        .filter_map(candidate_from_entry)
        .collect())
}

/// The documented wire shape of a 300 body from `/tools/project-by`
/// (repology.md §3, `tools.py:108-120`): the candidate `project → url`
/// map rides in a `targets` key next to the `_comment` note.
#[derive(Debug, Deserialize)]
struct AmbiguousRedirectBody {
    /// Every matching `project → url` binding; required — a body without
    /// it is not the documented shape.
    targets: BTreeMap<String, String>,
}

/// Parse a `300 Multiple Choices` body from `/tools/project-by` into the
/// sorted candidate project names (DESIGN.md §5: record all candidates,
/// decide by homepage match later). Pure parse-half fn so live payloads
/// and offline tests flow through one signature.
///
/// # Errors
///
/// [`Error::Parse`] when the body is not the documented `{"targets": …}`
/// object (a bare top-level candidate map, an HTML error page, …).
pub fn parse_ambiguous_redirect(payload: &str) -> Result<Vec<String>> {
    let body: AmbiguousRedirectBody =
        serde_json::from_str(payload).map_err(|error| Error::Parse {
            kind: "json",
            id: PARSE_ERROR_ID.to_owned(),
            message: format!(
                "ambiguous-redirect body was not the documented \
                 {{\"targets\": {{…}}}} object: {error}"
            ),
        })?;
    Ok(body.targets.into_keys().collect())
}

/// Convert one wire entry into a candidate, or `None` when it violates the
/// mandatory-field contract (skip-tolerant; see [`parse_repology_project`]).
fn candidate_from_entry(entry: RepologyEntry) -> Option<AliasCandidate> {
    let repo = entry.repo.filter(|repo| !repo.is_empty())?;
    let version = entry.version.filter(|version| !version.is_empty())?;
    Some(AliasCandidate {
        repo,
        version: Version {
            value: version,
            original: entry.origversion,
            published_unix: None,
        },
        status: entry.status.unwrap_or_default(),
        summary: entry.summary,
        srcname: entry.srcname,
        binname: entry.binname,
    })
}

// ---------------------------------------------------------------------------
// Repology-side alias classification — the rules the AliasIndex insertion
// applies to a candidate (repology.md §3; DESIGN.md §3.1, §5)
// ---------------------------------------------------------------------------

/// Whether `repo` installs prebuilt binaries only (`arch`, `alpine_*` —
/// pacman/apk know the binary package name), as opposed to source-based
/// repos (`homebrew`, `debian_*`, `fedora_*`, …).
///
/// Any repo id this crate has not classified defaults to `false`:
/// repology adds repos continuously, and source-first is the safe default
/// (with `binname` as the fallback — see [`select_source_id`]).
fn repo_prefers_binname(repo: &str) -> bool {
    repo == "arch" || repo.starts_with("alpine_")
}

/// Pick the per-source id the alias index inserts for `candidate` — ONE
/// `SourceRef.id` per candidate, chosen by repo class (DESIGN.md §3.1):
///
/// - source-based repos (`debian_*`, `fedora_*`, `homebrew`, and any
///   unclassified id) prefer `srcname` — the name the source catalog
///   publishes is the stable join key;
/// - binary-install repos (`arch`, `alpine_*`) prefer `binname` — the only
///   name the family's manager knows (arch: `brave`, not the project name
///   `brave-browser`);
/// - each falls back to the other when its preferred slot is `None`.
///
/// `None` when the entry carries neither name: such a candidate is still
/// parsed (parse is faithful to the payload), but the index has no id to
/// insert and must skip it.
pub fn select_source_id(candidate: &AliasCandidate) -> Option<String> {
    let (preferred, fallback) = if repo_prefers_binname(&candidate.repo) {
        (&candidate.binname, &candidate.srcname)
    } else {
        (&candidate.srcname, &candidate.binname)
    };
    preferred.clone().or_else(|| fallback.clone())
}

/// Map a repology repo id to the [`DistroFamily`] whose manager installs
/// its packages (`debian_*` → apt, `fedora_*` → dnf, `arch` → pacman,
/// `alpine_*` → apk).
///
/// `homebrew` maps to `None` — not a distro; the Homebrew adapters mint
/// those identity rows themselves. `ubuntu_*` → [`DistroFamily::Ubuntu`]
/// is included for forward compatibility although the wave-1 tracked-repo
/// list (DESIGN.md §5) does not track it. Any other id (flathub has no
/// verified repology repo id — DESIGN.md §5 bridging note) is `None`.
pub fn repo_distro_family(repo: &str) -> Option<DistroFamily> {
    if repo == "arch" {
        Some(DistroFamily::Arch)
    } else if repo.starts_with("alpine_") {
        Some(DistroFamily::Alpine)
    } else if repo.starts_with("debian_") {
        Some(DistroFamily::Debian)
    } else if repo.starts_with("fedora_") {
        Some(DistroFamily::Fedora)
    } else if repo.starts_with("ubuntu_") {
        Some(DistroFamily::Ubuntu)
    } else {
        None
    }
}

/// Whether a repology-minted [`Distro`](crate::model::SourceKind::Distro)
/// row for `family` is *provisional* — minted from repology because the
/// family has no adapter of its own, and to be replaced by
/// `provisional: false` rows once a real adapter parses that family's own
/// catalog (DESIGN.md §5).
///
/// Wave 1 pins this to [`DistroFamily::Arch`] and [`DistroFamily::Alpine`]
/// (DESIGN.md §5): every other family either has a wave-1 adapter
/// (Debian/Ubuntu via `AppStream`) or is wave-2 work with a different story.
/// (Tension noted for review: DESIGN.md §6 also lists Fedora as uncovered
/// in wave 1, but both §5 and the assignment name exactly (Arch, Alpine),
/// so Fedora rows minted from repology count as non-provisional here.)
pub fn family_row_is_provisional(family: DistroFamily) -> bool {
    matches!(family, DistroFamily::Arch | DistroFamily::Alpine)
}

/// Whether `status` is one of repology's "ignored-ish" values —
/// `ignored`, `incorrect`, `untrusted`, `noscheme`, `rolling`
/// (`package.py::is_ignored`, repology.md §2).
///
/// Parse keeps every status ([`parse_repology_project`] is faithful); the
/// alias index drops ignored candidates at index-build time, not at parse
/// time (DESIGN.md §3.1). `newest`/`outdated`/`devel`/`unique`/`legacy`
/// are not ignored.
pub fn status_is_ignored(status: &str) -> bool {
    matches!(
        status,
        "ignored" | "incorrect" | "untrusted" | "noscheme" | "rolling"
    )
}

// ---------------------------------------------------------------------------
// Fetch half — thin client (DESIGN.md §3.1/§3.2; fair-use: repology.md §4)
// ---------------------------------------------------------------------------

/// Base URL of the Repology API.
#[cfg(feature = "http")]
const API_BASE: &str = "https://repology.org";

/// Descriptive User-Agent, per the upstream terms of use (repology.md §4,
/// verbatim): "Bulk clients must identify themselves with a custom
/// user-agent, referring to a description of the client and a way to
/// report misbehavior (such as GitHub repository with an issue tracker)."
#[cfg(feature = "http")]
const USER_AGENT: &str = concat!(
    "toride-registry/repology/",
    env!("CARGO_PKG_VERSION"),
    " (+https://github.com/freeoxide/toride)"
);

/// Minimum spacing between two consecutive Repology requests: 1 second.
///
/// Upstream fair-use policy (repology.md §4, verbatim): "Bulk clients must
/// not do more than one request per second. Miscomplying clients will be
/// blocked." [`RepologyClient`] serializes every request behind one gate
/// and stamps the gate *after* completion — the conservative reading, so a
/// slow response delays the next request further. 403/429 responses mean
/// the client was blocked: surface as [`Error::Http`], there is no
/// documented Retry-After to honor.
#[cfg(feature = "http")]
const MIN_REQUEST_INTERVAL: Duration = Duration::from_secs(1);

/// Cache lifetime for fetched payloads and alias resolutions: 24 hours.
///
/// "Aggressive caching" is mandated by the fair-use policy (repology.md
/// §4) and DESIGN.md §5 pins the TTL at ≥ 1 day: alias data is
/// slow-moving, and single-project lookups are the cheap path (bulk sweeps
/// belong on the dump service, not the API).
#[cfg(feature = "http")]
const CACHE_TTL: Duration = Duration::from_hours(24);

/// Which name slot of a repology entry a reverse lookup addresses — the
/// exact `name_type` options of `/tools/project-by`
/// (`templates/tools/project-by.html:43-44`, repology.md §3).
#[cfg(feature = "http")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NameType {
    /// Source-package name (`srcname`).
    Srcname,
    /// Binary-package name (`binname`).
    Binname,
}

#[cfg(feature = "http")]
impl NameType {
    /// The wire spelling the `/tools/project-by` endpoint expects.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Srcname => "srcname",
            Self::Binname => "binname",
        }
    }
}

/// Outcome of a `/tools/project-by` reverse lookup (repology.md §3,
/// `views/tools.py:77-139`).
#[cfg(feature = "http")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProjectResolution {
    /// 302 — an unambiguous project. The client's redirect policy follows
    /// the redirect to `target_page=api_v1_project`, so the project name
    /// is read off the final URL; the project payload itself is *not*
    /// returned here (call [`RepologyClient::fetch_project`] for it —
    /// `resolve_by_name` stores the followed payload in the client's
    /// payload cache, so that fetch hits the cache instead of the
    /// network).
    Resolved {
        /// Canonical repology project name (the `/api/v1/project/<name>`
        /// input).
        project: String,
    },
    /// 300 — ambiguous: multiple projects match the name. All candidate
    /// project names, sorted; decide by homepage match later (DESIGN.md
    /// §5). Only reachable when upstream emits 300 despite autoresolve
    /// (the client does not pass `noautoresolve`, but the arm is handled
    /// per DESIGN.md §5).
    Ambiguous {
        /// Every matching project name, sorted for determinism.
        candidates: Vec<String>,
    },
    /// 404 — unknown repo or no match; the caller falls back to rule 2 of
    /// the canonical-id derivation (DESIGN.md §5).
    Unknown,
}

/// One cache slot: when the value was fetched plus the value itself.
#[cfg(feature = "http")]
#[derive(Debug, Clone)]
struct CacheEntry<T> {
    /// Completion instant of the request that produced `value`.
    at: Instant,
    /// Cached body or resolution.
    value: T,
}

/// Keyed cache table shared by the payload and resolution caches.
#[cfg(feature = "http")]
type CacheMap<T> = Mutex<HashMap<String, CacheEntry<T>>>;

/// Thin fetch client for the Repology oracle (DESIGN.md §3.1).
///
/// Returns raw body text — never deserialized values — so live payloads
/// and the frozen fixture flow through the same parse signature
/// ([`parse_repology_project`]). All requests are serialized behind one
/// rate-limit gate ([`MIN_REQUEST_INTERVAL`]) and every payload/resolution
/// is cached for [`CACHE_TTL`]; both are fair-use policy, not optimization.
///
/// The client follows redirects (`Policy::limited(10)`, DESIGN.md §3.2):
/// repology's reverse oracle is a redirect endpoint whose
/// `target_page=api_v1_project` target is itself a JSON API response.
#[cfg(feature = "http")]
#[derive(Debug)]
pub struct RepologyClient {
    /// Shared reqwest client (descriptive UA, redirect + timeout policy).
    client: reqwest::Client,
    /// Serialization + rate-limit gate: completion instant of the most
    /// recent request, or `None` before the first one.
    gate: tokio::sync::Mutex<Option<Instant>>,
    /// Forward-oracle cache: project name → payload text.
    payloads: CacheMap<String>,
    /// Reverse-oracle cache: `repo\0name_type\0name` → resolution.
    resolutions: CacheMap<ProjectResolution>,
}

#[cfg(feature = "http")]
impl RepologyClient {
    /// Build a client with the shared HTTP posture (descriptive UA,
    /// redirects, timeouts — DESIGN.md §3.2, shared via `crate::http`)
    /// and empty caches.
    #[must_use]
    pub fn new() -> Self {
        Self {
            client: crate::http::build_http_client(USER_AGENT),
            gate: tokio::sync::Mutex::new(None),
            payloads: Mutex::new(HashMap::new()),
            resolutions: Mutex::new(HashMap::new()),
        }
    }

    /// GET `{API_BASE}/api/v1/project/{project}` → raw body text.
    ///
    /// `project` is a canonical repology project name (lowercase slug);
    /// unknown names yield upstream 404 → [`Error::Http`]. Cached for
    /// [`CACHE_TTL`].
    ///
    /// # Errors
    ///
    /// [`Error::Http`] on transport failure, timeout, or a non-success
    /// status (403/429 = blocked per repology.md §4 — back off hard, there
    /// is no documented Retry-After).
    pub async fn fetch_project(&self, project: &str) -> Result<String> {
        if let Some(hit) = Self::cache_get(&self.payloads, project) {
            return Ok(hit);
        }
        let url = format!("{API_BASE}/api/v1/project/{project}");
        let response = self.send(&url, |client| client.get(&url)).await?;
        let status = response.status();
        if !status.is_success() {
            return Err(Error::Http {
                url,
                message: format!("unexpected status {status}"),
            });
        }
        let body = response.text().await.map_err(|error| Error::Http {
            url: url.clone(),
            message: error.to_string(),
        })?;
        Self::cache_store(&self.payloads, project.to_owned(), body.clone());
        Ok(body)
    }

    /// Reverse oracle: which repology project does the per-repo name
    /// `(repo, name_type, name)` belong to? (DESIGN.md §5 input 2.)
    ///
    /// Calls `GET /tools/project-by?…&target_page=api_v1_project`. Because
    /// the client follows redirects, upstream's 302 surfaces as a `200`
    /// whose final URL names the project ([`ProjectResolution::Resolved`]);
    /// 300 surfaces as [`ProjectResolution::Ambiguous`] and 404 as
    /// [`ProjectResolution::Unknown`]. Cached for [`CACHE_TTL`].
    ///
    /// # Errors
    ///
    /// [`Error::Http`] on transport failure, a non-302/300/404 status, or
    /// a redirect that lands outside `/api/v1/project/`. [`Error::Parse`]
    /// when a 300 body is not the documented `{"targets": …}` object
    /// ([`parse_ambiguous_redirect`]).
    pub async fn resolve_by_name(
        &self,
        repo: &str,
        name_type: NameType,
        name: &str,
    ) -> Result<ProjectResolution> {
        let key = format!("{repo}\u{0}{}\u{0}{name}", name_type.as_str());
        if let Some(hit) = Self::cache_get(&self.resolutions, &key) {
            return Ok(hit);
        }
        let url = format!("{API_BASE}/tools/project-by");
        let response = self
            .send(&url, |client| {
                client.get(&url).query(&[
                    ("repo", repo),
                    ("name_type", name_type.as_str()),
                    ("name", name),
                    ("target_page", "api_v1_project"),
                ])
            })
            .await?;
        let status = response.status();
        let resolution = match status {
            StatusCode::OK => {
                // The 302 was followed transparently (target_page pins the
                // landing page to the JSON API), so the final URL IS the
                // answer: …/api/v1/project/<name>.
                let project = project_from_api_url(response.url()).ok_or_else(|| Error::Http {
                    url: response.url().to_string(),
                    message: "project-by redirect landed outside /api/v1/project/".to_owned(),
                })?;
                // The followed response IS the `/api/v1/project/<name>`
                // payload a follow-up [`Self::fetch_project`] would request
                // — store it so that call hits the payload cache instead
                // of spending a second rate-limited request (repology.md §4).
                let final_url = response.url().to_string();
                let body = response.text().await.map_err(|error| Error::Http {
                    url: final_url,
                    message: error.to_string(),
                })?;
                Self::cache_store(&self.payloads, project.clone(), body);
                ProjectResolution::Resolved { project }
            }
            StatusCode::MULTIPLE_CHOICES => {
                let body = response.text().await.map_err(|error| Error::Http {
                    url: url.clone(),
                    message: error.to_string(),
                })?;
                ProjectResolution::Ambiguous {
                    candidates: parse_ambiguous_redirect(&body)?,
                }
            }
            StatusCode::NOT_FOUND => ProjectResolution::Unknown,
            _ => {
                return Err(Error::Http {
                    url,
                    message: format!("unexpected status {status}"),
                });
            }
        };
        Self::cache_store(&self.resolutions, key, resolution.clone());
        Ok(resolution)
    }

    /// Send one request through the rate-limit gate: wait until
    /// [`MIN_REQUEST_INTERVAL`] has passed since the previous request
    /// completed, then send, then stamp the gate.
    ///
    /// Holding the gate across the send is the point — requests are fully
    /// serialized, which is both the fair-use requirement and protection
    /// against duplicate concurrent fetches.
    async fn send(
        &self,
        url: &str,
        build: impl FnOnce(&reqwest::Client) -> reqwest::RequestBuilder,
    ) -> Result<reqwest::Response> {
        let mut last = self.gate.lock().await;
        if let Some(at) = *last {
            // The guard doubles as the checked-subtraction guard: sleep
            // only the remainder that is actually left of the interval.
            if let Some(remaining) = MIN_REQUEST_INTERVAL.checked_sub(at.elapsed()) {
                tokio::time::sleep(remaining).await;
            }
        }
        let response = build(&self.client)
            .send()
            .await
            .map_err(|error| Error::Http {
                url: error
                    .url()
                    .map_or_else(|| url.to_owned(), ToString::to_string),
                message: error.to_string(),
            })?;
        *last = Some(Instant::now());
        Ok(response)
    }

    /// Cached value for `key`, or `None` when absent/expired (expired
    /// entries are dropped on read).
    fn cache_get<T: Clone>(cache: &CacheMap<T>, key: &str) -> Option<T> {
        let mut map = cache.lock().unwrap_or_else(PoisonError::into_inner);
        let entry = map.get(key)?;
        if entry.at.elapsed() >= CACHE_TTL {
            map.remove(key);
            return None;
        }
        Some(entry.value.clone())
    }

    /// Insert into a cache, opportunistically dropping expired entries so
    /// the aggressively-cached tables stay bounded in long-lived processes.
    fn cache_store<T>(cache: &CacheMap<T>, key: String, value: T) {
        let mut map = cache.lock().unwrap_or_else(PoisonError::into_inner);
        map.retain(|_, entry| entry.at.elapsed() < CACHE_TTL);
        map.insert(
            key,
            CacheEntry {
                at: Instant::now(),
                value,
            },
        );
    }
}

#[cfg(feature = "http")]
impl Default for RepologyClient {
    fn default() -> Self {
        Self::new()
    }
}

/// Extract the canonical project name from a final
/// `/api/v1/project/<name>` URL (the followed redirect target).
///
/// No percent-decoding: project names are `[a-z0-9-]` slugs, so the last
/// path segment passes through verbatim.
#[cfg(feature = "http")]
fn project_from_api_url(url: &reqwest::Url) -> Option<String> {
    if !url.path().starts_with("/api/v1/project/") {
        return None;
    }
    let last = url.path_segments()?.next_back()?;
    (!last.is_empty()).then(|| last.to_owned())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{
        family_row_is_provisional, parse_ambiguous_redirect, parse_repology_project,
        repo_distro_family, select_source_id, status_is_ignored,
    };
    use crate::error::Error;
    use crate::model::DistroFamily;

    /// Fixture path helper — manifest-dir anchored so tests are
    /// cwd-independent (conventions.md §7; DESIGN.md §9).
    fn fixture_path(rel: &str) -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(rel)
    }

    /// Read a fixture to text, panicking with the path on failure.
    fn read_fixture(rel: &str) -> String {
        let path = fixture_path(rel);
        std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("read fixture {}: {error}", path.display()))
    }

    /// Parse an inline payload, panicking on structural failure.
    fn parse_inline(json: &str) -> Vec<super::AliasCandidate> {
        parse_repology_project(json).expect("inline payload parses")
    }

    #[test]
    fn ambiguous_redirect_body_unwraps_the_targets_object() {
        // The documented 300 wire shape, verbatim from repology.md §3
        // (tools.py:108-120): the candidate map rides in `targets` next to
        // the `_comment` note (DESIGN.md §5: record all candidates).
        let body = r#"{
            "_comment": "Ambiguous redirect, multiple target projects are possible",
            "targets": {
                "brave": "https://repology.org/project/brave",
                "brave-browser": "https://repology.org/project/brave-browser"
            }
        }"#;
        let candidates = parse_ambiguous_redirect(body).expect("documented 300 body parses");
        assert_eq!(
            candidates,
            ["brave", "brave-browser"],
            "sorted project names"
        );
    }

    #[test]
    fn ambiguous_redirect_body_rejects_a_bare_candidate_map() {
        // The pre-fix bug's input: the unwrapped map is NOT the documented
        // shape and must be a parse error, never silently accepted.
        let bare = r#"{"brave": "https://repology.org/project/brave"}"#;
        let error = parse_ambiguous_redirect(bare).expect_err("bare map is not the 300 shape");
        assert!(
            matches!(error, Error::Parse { kind: "json", .. }),
            "{error:?}"
        );
    }

    #[test]
    fn synthetic_fixture_yields_one_candidate_per_entry() {
        let candidates =
            parse_repology_project(&read_fixture("repology/project-brave-browser.json"))
                .expect("synthetic fixture parses");
        assert_eq!(candidates.len(), 5, "one candidate per entry, in order");
        let repos: Vec<&str> = candidates.iter().map(|c| c.repo.as_str()).collect();
        assert_eq!(
            repos,
            [
                "homebrew",
                "debian_13",
                "fedora_rawhide",
                "arch",
                "alpine_edge"
            ],
        );
    }

    #[test]
    fn arch_entry_is_one_candidate_even_with_both_names_set() {
        let candidates = parse_inline(
            r#"[{"repo": "arch", "version": "1.83.112",
                 "srcname": "brave-browser", "binname": "brave"}]"#,
        );
        assert_eq!(candidates.len(), 1, "ONE candidate, not one per name");
        let arch = &candidates[0];
        assert_eq!(arch.srcname.as_deref(), Some("brave-browser"));
        assert_eq!(arch.binname.as_deref(), Some("brave"));
    }

    #[test]
    fn version_carries_origversion_when_present() {
        let candidates =
            parse_repology_project(&read_fixture("repology/project-brave-browser.json"))
                .expect("fixture parses");
        let by_repo = |repo: &str| {
            candidates
                .iter()
                .find(|c| c.repo == repo)
                .unwrap_or_else(|| panic!("no {repo} entry"))
        };
        // origversion ≠ version exactly where the fixture says so.
        let homebrew = by_repo("homebrew");
        assert_eq!(homebrew.version.value, "1.83.112");
        assert_eq!(homebrew.version.original, None);
        let debian = by_repo("debian_13");
        assert_eq!(debian.version.value, "1.79.126");
        assert_eq!(debian.version.original.as_deref(), Some("1.79.126-1"));
        let fedora = by_repo("fedora_rawhide");
        assert_eq!(fedora.version.original.as_deref(), Some("1.83.112-1.fc44"));
        let alpine = by_repo("alpine_edge");
        assert_eq!(alpine.version.value, "1.83.120");
        assert_eq!(alpine.version.original.as_deref(), Some("1.83.120-r0"));
        // Repology publishes no per-entry timestamps.
        assert!(
            candidates
                .iter()
                .all(|c| c.version.published_unix.is_none())
        );
    }

    #[test]
    fn status_and_summary_flow_through() {
        let candidates =
            parse_repology_project(&read_fixture("repology/project-brave-browser.json"))
                .expect("fixture parses");
        let statuses: Vec<&str> = candidates.iter().map(|c| c.status.as_str()).collect();
        assert_eq!(
            statuses,
            ["newest", "outdated", "newest", "newest", "devel"]
        );
        assert!(candidates.iter().all(|c| c.summary.is_some()));
        // Absent optional fields default, never fail.
        let bare = parse_inline(r#"[{"repo": "arch", "version": "1.0"}]"#);
        assert_eq!(bare[0].status, "");
        assert_eq!(bare[0].summary, None);
        // An explicit `null` status is tolerated exactly like an absent one
        // (struct-level `#[serde(default)]` covers absent keys only).
        let null_status = parse_inline(r#"[{"repo": "arch", "version": "1.0", "status": null}]"#);
        assert_eq!(null_status[0].status, "");
    }

    #[test]
    fn era_drift_and_unknown_fields_are_tolerated() {
        // `name` (serialized only ≤2023) and `families` (never serialized
        // into entries) are present in the fixture itself; every other
        // unknown key must be ignored the same way.
        let candidates = parse_inline(
            r#"[{"repo": "homebrew", "srcname": "brave-browser", "name": "brave-browser",
                 "version": "1.83.112", "origversion": null, "status": "newest",
                 "families": 40, "subrepo": "main", "visiblename": "brave-browser",
                 "categories": ["web"], "licenses": ["MPL-2.0"],
                 "maintainers": ["brave-packagers@lists.debian.org"], "vulnerable": false,
                 "keyname": "brave-browser", "www": "https://brave.com"}]"#,
        );
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].repo, "homebrew");
        assert_eq!(candidates[0].version.value, "1.83.112");
    }

    #[test]
    fn entries_missing_mandatory_fields_are_skipped_not_fatal() {
        let candidates = parse_inline(
            r#"[{"srcname": "no-repo"},
                {"repo": "alpine_edge"},
                {"repo": "", "version": "1.0"},
                {"repo": "arch", "srcname": "no-version"},
                {"repo": "arch", "version": "1.0", "binname": "brave"}]"#,
        );
        assert_eq!(candidates.len(), 1, "only the contract-abiding entry");
        assert_eq!(candidates[0].repo, "arch");
    }

    #[test]
    fn non_array_payload_is_a_parse_error() {
        // The /api/v1/projects/ envelope is an object — a different
        // endpoint; an HTML error page likewise. Both must Err, not
        // silently produce zero candidates.
        for payload in [r#"{"brave-browser": [{"repo": "arch"}]}"#, "not json", ""] {
            let Err(error) = parse_repology_project(payload) else {
                panic!("expected Error::Parse for {payload:?}");
            };
            assert!(
                matches!(error, Error::Parse { kind, .. } if kind == "json"),
                "expected Error::Parse for {payload:?}",
            );
        }
    }

    #[test]
    fn select_source_id_prefers_srcname_for_source_based_repos() {
        for repo in [
            "homebrew",
            "debian_13",
            "fedora_rawhide",
            "some_future_repo",
        ] {
            let candidates = parse_inline(&format!(
                r#"[{{"repo": "{repo}", "version": "1.0",
                     "srcname": "brave-browser", "binname": "brave"}}]"#
            ));
            assert_eq!(
                select_source_id(&candidates[0]).as_deref(),
                Some("brave-browser"),
                "{repo} is source-based",
            );
        }
        // Fallback: a source-based entry with only binname still yields it.
        let only_bin = parse_inline(
            r#"[{"repo": "debian_13", "version": "1.0", "binname": "brave-browser"}]"#,
        );
        assert_eq!(
            select_source_id(&only_bin[0]).as_deref(),
            Some("brave-browser")
        );
    }

    #[test]
    fn select_source_id_prefers_binname_for_binary_repos() {
        // The fixture's arch entry (srcname brave-browser + binname brave)
        // keys on `brave` — the name pacman knows.
        let candidates =
            parse_repology_project(&read_fixture("repology/project-brave-browser.json"))
                .expect("fixture parses");
        let arch = candidates.iter().find(|c| c.repo == "arch").unwrap();
        assert_eq!(select_source_id(arch).as_deref(), Some("brave"));
        // Alpine carries only srcname in the fixture → falls back to it.
        let alpine = candidates.iter().find(|c| c.repo == "alpine_edge").unwrap();
        assert_eq!(select_source_id(alpine).as_deref(), Some("brave-browser"));
        // A binary repo with only binname keeps it.
        let only_bin =
            parse_inline(r#"[{"repo": "alpine_edge", "version": "1.0", "binname": "brave"}]"#);
        assert_eq!(select_source_id(&only_bin[0]).as_deref(), Some("brave"));
    }

    #[test]
    fn select_source_id_is_none_without_any_name() {
        let bare = parse_inline(r#"[{"repo": "arch", "version": "1.0"}]"#);
        assert_eq!(select_source_id(&bare[0]), None);
    }

    #[test]
    fn repo_distro_family_maps_tracked_repos() {
        assert_eq!(repo_distro_family("debian_13"), Some(DistroFamily::Debian));
        assert_eq!(
            repo_distro_family("fedora_rawhide"),
            Some(DistroFamily::Fedora)
        );
        assert_eq!(repo_distro_family("arch"), Some(DistroFamily::Arch));
        assert_eq!(
            repo_distro_family("alpine_edge"),
            Some(DistroFamily::Alpine)
        );
        // Forward-compatibility generalization (not in the wave-1 tracked set).
        assert_eq!(
            repo_distro_family("ubuntu_24.04"),
            Some(DistroFamily::Ubuntu)
        );
        // Not a distro: the Homebrew adapters mint their own rows.
        assert_eq!(repo_distro_family("homebrew"), None);
        assert_eq!(repo_distro_family("freebsd"), None);
    }

    #[test]
    fn only_unadapted_families_mint_provisional_rows() {
        assert!(family_row_is_provisional(DistroFamily::Arch));
        assert!(family_row_is_provisional(DistroFamily::Alpine));
        assert!(!family_row_is_provisional(DistroFamily::Debian));
        assert!(!family_row_is_provisional(DistroFamily::Ubuntu));
        assert!(!family_row_is_provisional(DistroFamily::Fedora));
    }

    #[test]
    fn ignored_statuses_match_the_documented_set() {
        for ignored in ["ignored", "incorrect", "untrusted", "noscheme", "rolling"] {
            assert!(status_is_ignored(ignored), "{ignored} is ignored-ish");
        }
        for kept in ["newest", "outdated", "devel", "unique", "legacy"] {
            assert!(!status_is_ignored(kept), "{kept} is kept");
        }
    }
}

// ---------------------------------------------------------------------------
// Live tests — env-gated AND http-gated, skipped by default (DESIGN.md §0,
// §9: repology.org unreachable from the wave-1 sandbox)
// ---------------------------------------------------------------------------

#[cfg(all(test, feature = "http"))]
mod integration_tests {
    use super::{NameType, RepologyClient, parse_repology_project, select_source_id};

    /// Returns `true` when `TORIDE_REGISTRY_INTEGRATION` is exactly `1`
    /// (conventions.md §7 gate pattern).
    fn should_run() -> bool {
        matches!(
            std::env::var("TORIDE_REGISTRY_INTEGRATION").as_deref(),
            Ok("1"),
        )
    }

    /// The documented status set (`PackageStatus::as_string`,
    /// repology.md §2): every live status must be one of these.
    const KNOWN_STATUSES: [&str; 10] = [
        "newest",
        "outdated",
        "ignored",
        "unique",
        "devel",
        "legacy",
        "incorrect",
        "untrusted",
        "noscheme",
        "rolling",
    ];

    #[tokio::test]
    async fn live_fetch_project_preserves_the_compared_invariants() {
        if !should_run() {
            eprintln!("TORIDE_REGISTRY_INTEGRATION not set; skipping live repology test");
            return;
        }
        let client = RepologyClient::new();
        let body = client
            .fetch_project("brave-browser")
            .await
            .expect("live fetch of /api/v1/project/brave-browser");
        let candidates =
            parse_repology_project(&body).expect("live payload parses as a JSON array");

        // §3.1 compared invariant set, adapted to oracle output (candidates
        // are AliasIndex inputs, not Apps) — NEVER field-for-field equality
        // against the synthetic fixture, whose values are invented.
        assert!(!candidates.is_empty(), "live project has entries");
        for candidate in &candidates {
            // (1) the mandatory fields are populated;
            assert!(!candidate.repo.is_empty());
            assert!(!candidate.version.value.is_empty());
            // (2) the index can insert — an id is selectable per entry;
            assert!(
                select_source_id(candidate).is_some(),
                "entry for {} carries neither srcname nor binname",
                candidate.repo,
            );
            // (3) status is drawn from the documented set;
            assert!(
                KNOWN_STATUSES.contains(&candidate.status.as_str()),
                "undocumented status {:?}",
                candidate.status,
            );
        }
        // (4) the selection rule splits by repo class as documented.
        for candidate in &candidates {
            if candidate.repo == "arch" {
                assert_eq!(
                    select_source_id(candidate).as_deref(),
                    candidate.binname.as_deref(),
                    "arch must key on binname",
                );
            }
        }
    }

    #[tokio::test]
    async fn live_resolve_by_name_handles_302_and_404() {
        if !should_run() {
            eprintln!("TORIDE_REGISTRY_INTEGRATION not set; skipping live repology test");
            return;
        }
        let client = RepologyClient::new();
        // A known homebrew srcname resolves through the 302 to the project.
        let resolved = client
            .resolve_by_name("homebrew", NameType::Srcname, "brave-browser")
            .await
            .expect("project-by lookup");
        let project = match resolved {
            super::ProjectResolution::Resolved { project } => project,
            other => panic!("expected Resolved, got {other:?}"),
        };
        assert!(!project.is_empty());
        // An unknown name 404s into the documented Unknown fallback.
        let unknown = client
            .resolve_by_name("homebrew", NameType::Srcname, "no-such-toride-package-xyz")
            .await
            .expect("404 is a resolution, not an error");
        assert_eq!(unknown, super::ProjectResolution::Unknown);
    }

    #[test]
    fn project_name_extraction_reads_the_final_url() {
        let url: reqwest::Url = "https://repology.org/api/v1/project/brave-browser"
            .parse()
            .expect("static url");
        assert_eq!(
            super::project_from_api_url(&url).as_deref(),
            Some("brave-browser"),
        );
        let html: reqwest::Url = "https://repology.org/project/brave-browser"
            .parse()
            .expect("static url");
        assert_eq!(super::project_from_api_url(&html), None, "non-API landing");
    }
}
