//! # Flathub adapter
//!
//! Normalizes flathub.org into [`App`]s (DESIGN.md §4.3; survey:
//! `docs/survey/flathub.md`). Flathub is the Linux GUI-app catalog for the
//! Flatpak ecosystem; its web API is discovery + metadata only — the
//! payload itself is delivered by the `flatpak` CLI against the Flathub
//! `OSTree` remote, so [`InstallMethod::Flatpak`] delegates both transfer and
//! integrity (GPG at the `OSTree` layer) to that client.
//!
//! ## Split
//!
//! - **Parse half** (pure, `&str` in → normalized out, no clock, no
//!   network, no client): [`parse_search_envelope`] over the `Meilisearch`
//!   envelope of `POST /api/v2/search` (unstable facet keys are ignored),
//!   [`parse_appstream_detail`] over `GET /api/v2/appstream/{app_id}`
//!   (HTML description stripped to plain text), and [`parse_flatpakref`]
//!   for the per-app `.flatpakref` pointer file consumed by the one-time
//!   `flatpak remote-add` setup flow.
//! - **Fetch half** (thin, raw body text out — never deserialized values,
//!   DESIGN.md §3.1): `FlathubClient` and the `FlathubAdapter` that
//!   binds it to the [`Adapter`](crate::adapter::Adapter) trait. Both live
//!   behind the crate's `http` feature so the parsers build fully offline
//!   (DESIGN.md §9).
//!
//! The v1 API and the `/app/{id}` REST routes are verified gone (404, live,
//! flathub.md §API surface); only the two v2 routes above are used.
//!
//! ## Field-mapping notes
//!
//! - The search-hit `id` (`com_brave_Browser`, the `Meilisearch` document
//!   key) is **not** the app id — identity is the dotted `app_id`
//!   (`com.brave.Browser`) everywhere: [`InstallMethod::Flatpak`],
//!   [`SourceRef`], and the `appstream/{app_id}` path (flathub.md
//!   §`app_id` convention).
//! - `platforms` = Linux × each `arches` entry; `arches: null` / empty →
//!   `platforms: []` = "unknown", which install planning treats as
//!   claim-check-skipped rather than refusing (DESIGN.md §3.3). The
//!   appstream detail carries no `arches` key (verified against the
//!   `DesktopAppstream` schema in the `openapi-v2.json` fixture), so the
//!   detail parser falls back to the single arch named in
//!   `bundle.value` (`app/{app_id}/{arch}/stable` — flathub.md §`app_id`),
//!   and to `[]` when that is missing too.
//! - `releases[0]` is the current release; its wire `timestamp` is a
//!   *string-encoded* int (`"1790208000"`) and is deserialized through a
//!   string-or-int deserializer into [`Version::published_unix`].
//! - `artifacts` stays empty: no sha256 exists anywhere in the API,
//!   `.flatpakref`, or `OpenAPI` spec (verified, flathub.md §Limitations).
//! - `main_categories` is `anyOf[string, string[]]` on the wire (bare
//!   string in both live samples) and is deserialized defensively; the
//!   model itself drops categories (DESIGN.md §2).
//!
//! ## Quick start
//!
//! ```rust,ignore
//! use toride_registry::sources::flathub::{
//!     parse_appstream_detail, parse_flatpakref, parse_search_envelope, FlathubAdapter,
//!     FlathubClient,
//! };
//!
//! // Fetch half returns raw body text; the pure parse half consumes it.
//! let client = FlathubClient::new();
//! let hits = parse_search_envelope(&client.search("brave browser").await?)?;
//! let detail = parse_appstream_detail(
//!     &client.fetch_appstream("com.brave.Browser").await?.expect("app exists"),
//! )?;
//!
//! // The `.flatpakref` pointer (fetched from
//! // https://dl.flathub.org/repo/appstream/{app_id}.flatpakref) feeds the
//! // one-time remote setup:
//! // `flatpak remote-add --if-not-exists <SuggestRemoteName> <flathub.flatpakrepo-url>`.
//! let reference = parse_flatpakref(&pointer_file_text)?;
//! ```

use crate::error::{Error, Result};
use crate::model::{
    App, Arch, Availability, InstallMethod, Os, Platform, SourceKind, SourceRef, TorideId, Version,
};
use serde::Deserialize;

/// Flathub web-API origin — everything the fetch half talks to lives under
/// this base (flathub.md §API surface; the `OSTree` payload host
/// `dl.flathub.org` is only reached by the `flatpak` client, not by us).
pub const API_BASE: &str = "https://flathub.org";

/// Flatpak remote name this adapter installs from — the name
/// `flatpak remote-add` is documented to configure (flathub.md §Installing)
/// and the `remote` half of every [`InstallMethod::Flatpak`] this module
/// emits.
pub const REMOTE_NAME: &str = "flathub";

// ---------------------------------------------------------------------------
// Parse half — pure, `&str` in → normalized out
// ---------------------------------------------------------------------------

/// `POST /api/v2/search` request body (`SearchQuery` in the `OpenAPI` spec;
/// `query` is the only key this client sends).
#[cfg(feature = "http")]
#[derive(Debug, serde::Serialize)]
struct SearchRequestBody {
    /// Free-text query echoed into the `Meilisearch` index.
    query: String,
}

/// One search hit — the `AppsIndex` schema subset this adapter consumes
/// (flathub.md §Search). Unknown keys (`verification_*`, `trending`,
/// `installs_last_month`, `keywords`, `runtime`, `icons`, …) are ignored:
/// `serde` skips them and the model deliberately drops them (DESIGN.md §2).
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct SearchHit {
    /// Dotted reverse-DNS app id — the identity field.
    app_id: String,
    /// Underscored `Meilisearch` document key (`com_brave_Browser`). Parsed
    /// to prove the id-vs-`app_id` distinction survives the wire; never
    /// used for identity (flathub.md §`app_id`). Test-only reads otherwise.
    #[serde(rename = "id")]
    #[allow(dead_code)] // identity lives in `app_id`; kept + asserted for the quirk
    meilisearch_id: String,
    /// Display name.
    name: String,
    /// One-liner → `App::summary`.
    summary: String,
    /// Long form, plain/markdown on this endpoint → `App::description`
    /// verbatim (only the appstream detail serves HTML).
    description: String,
    /// SPDX expression → `App::license`.
    project_license: Option<String>,
    /// Developer/publisher → `App::developer`.
    developer_name: Option<String>,
    /// Nullable arch list; `None`/empty → `platforms: []` (unknown).
    arches: Option<Vec<String>>,
    /// `anyOf[string, string[]]` on the wire (bare string in both live
    /// samples) — deserialized defensively; the model drops categories, so
    /// this is kept on the wire only (asserted by tests).
    #[serde(deserialize_with = "string_or_list_opt")]
    #[allow(dead_code)] // proves the anyOf parse; the model has no categories field
    main_categories: Option<Vec<String>>,
}

/// The `Meilisearch` search envelope. Only `hits` is consumed — the
/// envelope leaks index internals (`processingTimeMs`,
/// `facetDistribution`, `facetStats`, paging) that flathub.md §Limitations
/// flags as unstable; serde ignores them.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct SearchEnvelope {
    /// Ranked hits, order preserved into the returned `Vec<App>`.
    hits: Vec<SearchHit>,
}

/// One entry of the detail's `releases[]` — most recent first, only the
/// first ~4 kept upstream (flathub.md §app detail).
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct Release {
    /// Sanitized version string (`"1.96.59"`).
    version: Option<String>,
    /// Release time, unix seconds — **string-encoded** on the wire
    /// (`"1790208000"`); deserialized through [`string_or_int_unix`].
    #[serde(deserialize_with = "string_or_int_unix")]
    timestamp: Option<i64>,
}

/// The detail's `bundle` object.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct Bundle {
    /// `"app/{app_id}/{arch}/stable"` — the single stable branch per arch;
    /// the middle segment is the detail payload's only arch declaration.
    value: Option<String>,
}

/// The detail's `urls` object (help/faq/contact/… all exist upstream; only
/// the homepage crosses the adapter boundary, DESIGN.md §4.3).
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct Urls {
    /// Project homepage → `App::homepage`.
    homepage: Option<String>,
}

/// `GET /api/v2/appstream/{app_id}` response — the `DesktopAppstream`
/// subset this adapter consumes (flathub.md §app detail). Unknown keys
/// (icons, screenshots, branding, metadata, kudos, …) are ignored.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct AppstreamDetail {
    /// Dotted reverse-DNS app id — identity (unlike the search hit's `id`).
    id: String,
    /// Display name.
    name: String,
    /// One-liner → `App::summary`.
    summary: String,
    /// Long form, **HTML** on this endpoint → stripped by [`html_to_text`].
    description: String,
    /// Developer/publisher → `App::developer`.
    developer_name: Option<String>,
    /// SPDX expression → `App::license`.
    project_license: Option<String>,
    /// NOT in the `DesktopAppstream` schema today (verified in the
    /// `openapi-v2.json` fixture); optional defensively so a future arches
    /// key wins over the [`Bundle`] fallback without a parser change.
    arches: Option<Vec<String>>,
    /// Recent releases, most recent first; `releases[0]` is current.
    releases: Vec<Release>,
    /// Installable-bundle descriptor; its arch segment backs `platforms`.
    bundle: Option<Bundle>,
    /// Link table; only `urls.homepage` is mapped.
    urls: Option<Urls>,
}

/// Wire value that may be a bare JSON int or a string-encoded int —
/// flathub's release `timestamp` is `"1790208000"` (string) in both detail
/// fixtures while the survey table types it as int elsewhere.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum StringOrInt {
    /// JSON number.
    Int(i64),
    /// String-encoded number.
    Text(String),
}

/// Deserializes an `Option<i64>` from a JSON int or a string-encoded int;
/// anything else (explicit `null`, wrong type, unparsable text) degrades
/// to `None` — flathub.md §Limitations: "required = key present, not
/// non-null", so parse permissively.
///
/// `#[allow(clippy::unnecessary_wraps)]`: serde's `deserialize_with`
/// contract requires the `Result` return even though this implementation
/// never fails.
#[allow(clippy::unnecessary_wraps)]
fn string_or_int_unix<'de, D>(deserializer: D) -> std::result::Result<Option<i64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    match StringOrInt::deserialize(deserializer) {
        Ok(StringOrInt::Int(unix)) => Ok(Some(unix)),
        Ok(StringOrInt::Text(text)) => Ok(text.trim().parse::<i64>().ok()),
        // `null` (and any other surprise shape) → no timestamp, never a
        // hard parse failure for one field.
        Err(_) => Ok(None),
    }
}

/// Wire value that may be a bare string or a string list.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum StringOrList {
    /// Bare string form (both live fixtures).
    One(String),
    /// Array form (`anyOf`'s other arm).
    List(Vec<String>),
}

/// Deserializes an `Option<Vec<String>>` from `anyOf[string, string[]]`;
/// anything else degrades to `None` (same permissive posture as
/// [`string_or_int_unix`], and the same serde-mandated `Result` signature —
/// hence the same `unnecessary_wraps` allowance).
#[allow(clippy::unnecessary_wraps)]
fn string_or_list_opt<'de, D>(deserializer: D) -> std::result::Result<Option<Vec<String>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    match StringOrList::deserialize(deserializer) {
        Ok(StringOrList::One(value)) => Ok(Some(vec![value])),
        Ok(StringOrList::List(values)) => Ok(Some(values)),
        Err(_) => Ok(None),
    }
}

/// Parses a `POST /api/v2/search` response body into normalized search
/// stubs, preserving hit order. A hit with an empty `app_id` is skipped
/// rather than normalized into an `App` whose install descriptor names no
/// app; everything else maps 1:1 (see the module docs for the quirks).
///
/// # Errors
///
/// [`Error::Parse`] when the payload is not the expected JSON envelope.
pub fn parse_search_envelope(payload: &str) -> Result<Vec<App>> {
    let envelope: SearchEnvelope = serde_json::from_str(payload).map_err(|e| Error::Parse {
        kind: "json",
        id: "<search envelope>".to_owned(),
        message: e.to_string(),
    })?;
    Ok(envelope.hits.iter().filter_map(hit_to_app).collect())
}

/// Parses a `GET /api/v2/appstream/{app_id}` response body into one
/// normalized `App` — the heavy counterpart to the search stub: HTML
/// description stripped, `releases[0]` → [`App::latest`], homepage mapped.
///
/// # Errors
///
/// [`Error::Parse`] when the payload is not the expected JSON detail.
pub fn parse_appstream_detail(payload: &str) -> Result<App> {
    let detail: AppstreamDetail = serde_json::from_str(payload).map_err(|e| Error::Parse {
        kind: "json",
        id: "<appstream detail>".to_owned(),
        message: e.to_string(),
    })?;
    Ok(detail_to_app(detail))
}

/// The per-app `.flatpakref` pointer file
/// (`https://dl.flathub.org/repo/appstream/{app_id}.flatpakref`) — INI-style
/// `[Flatpak Ref]` `key=value` pairs. Consumed only for the one-time
/// `flatpak remote-add` setup flow; never normalized into [`App`]
/// (DESIGN.md §4.3). Exactly the seven fields DESIGN.md §7 pins; other
/// keys (`IsRuntime`, …) are ignored.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FlatpakRef {
    /// `Name=` — the dotted app id (`com.brave.Browser`).
    pub name: Option<String>,
    /// `Branch=` — the single stable branch (`stable`).
    pub branch: Option<String>,
    /// `Title=` — human label (`com.brave.Browser from flathub`).
    pub title: Option<String>,
    /// `Url=` — the `OSTree` repo base (`https://dl.flathub.org/repo/`).
    pub url: Option<String>,
    /// `SuggestRemoteName=` — remote name to configure (`flathub`).
    pub suggest_remote_name: Option<String>,
    /// `GPGKey=` — armoured repo signing key for the remote-add flow.
    pub gpg_key: Option<String>,
    /// `RuntimeRepo=` — the `.flatpakrepo` the runtimes come from
    /// (`https://dl.flathub.org/repo/flathub.flatpakrepo`).
    pub runtime_repo: Option<String>,
}

/// Parses a `.flatpakref` pointer file (INI-style `[Flatpak Ref]`
/// `key=value`). Missing keys deserialize to `None`; the `[Flatpak Ref]`
/// section header is mandatory — it is the format marker that separates a
/// real pointer file from arbitrary text.
///
/// # Errors
///
/// [`Error::Parse`] when the payload carries no `[Flatpak Ref]` header.
pub fn parse_flatpakref(payload: &str) -> Result<FlatpakRef> {
    let mut reference = FlatpakRef::default();
    let mut header_seen = false;
    for raw_line in payload.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            header_seen |= line.eq_ignore_ascii_case("[flatpak ref]");
            continue;
        }
        // Split on the FIRST `=`: the `GPGKey` base64 may itself end in `=`.
        if let Some((key, value)) = line.split_once('=') {
            let value = value.trim().to_owned();
            match key.trim() {
                "Name" => reference.name = Some(value),
                "Branch" => reference.branch = Some(value),
                "Title" => reference.title = Some(value),
                "Url" => reference.url = Some(value),
                "SuggestRemoteName" => reference.suggest_remote_name = Some(value),
                "GPGKey" => reference.gpg_key = Some(value),
                "RuntimeRepo" => reference.runtime_repo = Some(value),
                // `IsRuntime` and any other key: ignored (DESIGN.md §7 pins
                // exactly the seven fields above).
                _ => {}
            }
        }
    }
    if !header_seen {
        return Err(Error::Parse {
            kind: "flatpakref",
            id: reference
                .name
                .clone()
                .unwrap_or_else(|| "<unnamed>".to_owned()),
            message: "missing `[Flatpak Ref]` section header".to_owned(),
        });
    }
    Ok(reference)
}

/// Converts one search hit into a normalized search stub. `None` when the
/// hit carries no usable `app_id` (see [`parse_search_envelope`]).
fn hit_to_app(hit: &SearchHit) -> Option<App> {
    let app_id = hit.app_id.trim();
    if app_id.is_empty() {
        return None;
    }
    let app_id = app_id.to_owned();
    Some(App {
        // DESIGN.md §5 rule 2: slugify the source id when no repology
        // canonical name is known (`com.brave.Browser` → `com-brave-browser`).
        id: TorideId::slugify(&app_id),
        name: hit.name.clone(),
        aliases: Vec::new(),
        summary: non_empty(hit.summary.clone()),
        // Search descriptions are plain/markdown — mapped verbatim; only
        // the appstream detail serves HTML (flathub.md §app detail).
        description: non_empty(hit.description.clone()),
        homepage: None, // hits carry no homepage; `lookup` fills it
        license: non_empty_opt(hit.project_license.clone()),
        developer: non_empty_opt(hit.developer_name.clone()),
        binaries: Vec::new(),
        latest: None, // hits carry no releases; `lookup` fills it
        platforms: platforms_from_arches(hit.arches.as_deref().unwrap_or(&[])),
        artifacts: Vec::new(), // no checksums anywhere in the API (verified)
        install: flatpak_install(&app_id),
        sources: vec![flathub_source(app_id, None)],
        availability: Availability::Available,
    })
}

/// Converts the parsed detail wire struct into the normalized `App`.
fn detail_to_app(detail: AppstreamDetail) -> App {
    let latest = detail
        .releases
        .iter()
        // `releases[0]` is current; a leading release without a version
        // string is malformed upstream — skip to the next rather than
        // minting an empty-string version.
        .find(|release| {
            release
                .version
                .as_deref()
                .is_some_and(|v| !v.trim().is_empty())
        })
        .map(|release| Version {
            value: release.version.clone().unwrap_or_default(),
            original: None,
            published_unix: release.timestamp,
        });
    let platforms = detail_platforms(detail.arches.as_deref(), detail.bundle.as_ref());
    let app_id = detail.id.clone();
    App {
        id: TorideId::slugify(&detail.id),
        name: detail.name,
        aliases: Vec::new(),
        summary: non_empty(detail.summary),
        description: non_empty(html_to_text(&detail.description)),
        homepage: non_empty_opt(detail.urls.and_then(|urls| urls.homepage)),
        license: non_empty_opt(detail.project_license),
        developer: non_empty_opt(detail.developer_name),
        binaries: Vec::new(),
        latest: latest.clone(),
        platforms,
        artifacts: Vec::new(), // no checksums anywhere in the API (verified)
        install: flatpak_install(&detail.id),
        sources: vec![flathub_source(app_id, latest)],
        availability: Availability::Available,
    }
}

/// `platforms` for a payload's arch list: Linux × each entry, first-seen
/// order preserved. An empty list — including `arches: null` — yields
/// `[]` = "unknown", the claim-check-skipped case of DESIGN.md §3.3.
/// Arch spellings outside [`decode_arch`] are skipped.
fn platforms_from_arches(arches: &[String]) -> Vec<Platform> {
    let mut platforms = Vec::with_capacity(arches.len());
    for raw in arches {
        if let Some(arch) = decode_arch(raw) {
            platforms.push(Platform {
                os: Os::Linux,
                arch: Some(arch),
                min_release: None,
            });
        }
    }
    platforms
}

/// `platforms` for the appstream detail: its `arches` key when present
/// (not in today's schema — optional defensively), else the single arch
/// named in `bundle.value` (`app/{app_id}/{arch}/stable`, the detail
/// payload's only arch declaration), else `[]` = unknown.
fn detail_platforms(arches: Option<&[String]>, bundle: Option<&Bundle>) -> Vec<Platform> {
    if let Some(arches) = arches
        && !arches.is_empty()
    {
        return platforms_from_arches(arches);
    }
    if let Some(arch) = bundle
        .and_then(|bundle| bundle.value.as_deref())
        .and_then(bundle_arch)
    {
        return vec![Platform {
            os: Os::Linux,
            arch: Some(arch),
            min_release: None,
        }];
    }
    Vec::new()
}

/// Decodes a flathub arch spelling into [`Arch`]. Observed on the wire:
/// `x86_64`, `aarch64`; the remaining spellings are accepted defensively.
fn decode_arch(raw: &str) -> Option<Arch> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "x86_64" | "amd64" | "x64" => Some(Arch::X86_64),
        "aarch64" | "arm64" => Some(Arch::Aarch64),
        "x86" | "i386" | "i686" => Some(Arch::X86),
        _ => None,
    }
}

/// Extracts the arch segment of a `bundle.value`
/// (`app/{app_id}/{arch}/stable` → arch).
fn bundle_arch(bundle_value: &str) -> Option<Arch> {
    let segments: Vec<&str> = bundle_value.split('/').collect();
    if segments.len() < 3 {
        return None;
    }
    decode_arch(segments[2])
}

/// The install descriptor every flathub `App` carries.
fn flatpak_install(app_id: &str) -> InstallMethod {
    InstallMethod::Flatpak {
        app_id: app_id.to_owned(),
        remote: REMOTE_NAME.to_owned(),
    }
}

/// The per-source identity row for the alias index — `repo: None` because
/// the dotted app id is globally unique (DESIGN.md §2 `SourceRef::repo`).
fn flathub_source(app_id: String, version: Option<Version>) -> SourceRef {
    SourceRef {
        source: SourceKind::Flathub,
        id: app_id,
        repo: None,
        version,
        provisional: false,
    }
}

/// `Some(text)` unless the string is empty/whitespace — the permissive
/// encoding for fields upstream types as required-but-nullable.
fn non_empty(text: String) -> Option<String> {
    non_empty_opt(Some(text))
}

/// [`non_empty`] for an already-optional value.
fn non_empty_opt(text: Option<String>) -> Option<String> {
    let text = text?;
    if text.trim().is_empty() {
        None
    } else {
        Some(text)
    }
}

/// Strips HTML markup to plain text — the appstream detail description is
/// HTML while the search hit's is plain/markdown (flathub.md §app detail).
///
/// Block-level tags become line breaks, all other tags are dropped, the
/// common named/numeric entities are decoded (`&amp;` last, so
/// `&amp;lt;` stays the literal text `&lt;`), and whitespace runs collapse
/// (a run containing a newline → one newline, otherwise one space) to undo
/// the source indentation the markup carries.
fn html_to_text(html: &str) -> String {
    // Pass 1 — tags: everything between `<` and `>` is markup. A block
    // boundary emits a newline; an unterminated `<` is literal text, not
    // the start of a swallowed region.
    let mut stripped = String::with_capacity(html.len());
    let mut rest = html;
    while let Some(open) = rest.find('<') {
        stripped.push_str(&rest[..open]);
        let after = &rest[open..];
        if let Some(close) = after.find('>') {
            if is_block_tag(&after[1..close]) {
                stripped.push('\n');
            }
            rest = &after[close + 1..];
        } else {
            stripped.push_str(after);
            rest = "";
        }
    }
    stripped.push_str(rest);

    // Pass 2 — entities, `&amp;` deliberately last.
    let mut text = stripped
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&#39;", "'")
        .replace("&nbsp;", " ");
    if text.contains("&amp;") {
        text = text.replace("&amp;", "&");
    }

    // Pass 3 — whitespace collapse.
    let mut out = String::with_capacity(text.len());
    let mut pending_break = false;
    let mut pending_space = false;
    for ch in text.chars() {
        if ch.is_whitespace() {
            pending_break |= ch == '\n';
            pending_space = true;
        } else {
            if pending_break && !out.ends_with('\n') {
                out.push('\n');
            } else if pending_space && !out.is_empty() && !out.ends_with('\n') {
                out.push(' ');
            }
            pending_break = false;
            pending_space = false;
            out.push(ch);
        }
    }
    out.trim().to_owned()
}

/// Whether an HTML tag (`p`, `/p`, `br/`, …) is a block-level boundary —
/// i.e. whether stripping it should break the line rather than vanish.
fn is_block_tag(tag: &str) -> bool {
    let name: String = tag
        .trim_end_matches('/')
        .chars()
        .take_while(char::is_ascii_alphanumeric)
        .map(|ch| ch.to_ascii_lowercase())
        .collect();
    matches!(
        name.as_str(),
        "p" | "br"
            | "div"
            | "li"
            | "ul"
            | "ol"
            | "pre"
            | "blockquote"
            | "hr"
            | "table"
            | "tr"
            | "td"
            | "th"
            | "h1"
            | "h2"
            | "h3"
            | "h4"
            | "h5"
            | "h6"
    )
}

// ---------------------------------------------------------------------------
// Fetch half — thin client + adapter (crate `http` feature, DESIGN.md §9)
// ---------------------------------------------------------------------------

/// Descriptive User-Agent (DESIGN.md §3.2: `toride-registry/<source>/<version>`).
#[cfg(feature = "http")]
const USER_AGENT: &str = concat!("toride-registry/flathub/", env!("CARGO_PKG_VERSION"));

/// `POST /api/v2/search` — the only write-shaped route this client uses
/// (it is a read; the body is the query).
#[cfg(feature = "http")]
const SEARCH_PATH: &str = "/api/v2/search";

/// `GET /api/v2/appstream/{app_id}` path prefix; the dotted app id is
/// appended (reverse-DNS ids are URL-safe).
#[cfg(feature = "http")]
const APPSTREAM_PATH: &str = "/api/v2/appstream";

/// Thin fetch client for flathub.org. Every method returns the **raw body
/// text** so live payloads and frozen fixtures flow through the same pure
/// parse signatures (DESIGN.md §3.1). Gated behind the crate's `http`
/// feature (DESIGN.md §9).
#[cfg(feature = "http")]
#[derive(Debug, Clone)]
pub struct FlathubClient {
    /// Shared reqwest handle built by the shared `crate::http`
    /// builder.
    client: reqwest::Client,
}

#[cfg(feature = "http")]
impl FlathubClient {
    /// Client with the crate-standard UA, redirect policy, and timeouts
    /// (`crate::http::HTTP_TIMEOUT` / `HTTP_CONNECT_TIMEOUT`).
    pub fn new() -> Self {
        Self {
            client: crate::http::build_http_client(USER_AGENT),
        }
    }

    /// `POST /api/v2/search` with `{"query": …}` → raw response body.
    ///
    /// # Errors
    ///
    /// [`Error::Http`] on transport failure or a non-success status.
    pub async fn search(&self, query: &str) -> Result<String> {
        let url = format!("{API_BASE}{SEARCH_PATH}");
        let body = SearchRequestBody {
            query: query.to_owned(),
        };
        let response = self
            .client
            .post(&url)
            .json(&body)
            .send()
            .await
            .map_err(|e| http_error(&url, &e))?;
        let response = response
            .error_for_status()
            .map_err(|e| http_error(&url, &e))?;
        response.text().await.map_err(|e| http_error(&url, &e))
    }

    /// `GET /api/v2/appstream/{app_id}` → raw response body.
    ///
    /// `Ok(None)` is the documented 404 shape — the source has no app with
    /// that id — and is exactly the [`Adapter::lookup`](crate::adapter::Adapter::lookup)
    /// "no such entry" case; every other non-success status is an error.
    ///
    /// # Errors
    ///
    /// [`Error::Http`] on transport failure or a non-success, non-404
    /// status.
    pub async fn fetch_appstream(&self, app_id: &str) -> Result<Option<String>> {
        let url = format!("{API_BASE}{APPSTREAM_PATH}/{app_id}");
        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| http_error(&url, &e))?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let response = response
            .error_for_status()
            .map_err(|e| http_error(&url, &e))?;
        response
            .text()
            .await
            .map_err(|e| http_error(&url, &e))
            .map(Some)
    }
}

#[cfg(feature = "http")]
impl Default for FlathubClient {
    fn default() -> Self {
        Self::new()
    }
}

/// [`Adapter`](crate::adapter::Adapter) impl over the two verified v2
/// routes: search stubs come from [`parse_search_envelope`], full records
/// from [`parse_appstream_detail`] (the `.flatpakref` pointer is parsed by
/// [`parse_flatpakref`] for the remote-setup flow, not surfaced here).
/// Gated behind the crate's `http` feature (DESIGN.md §9).
#[cfg(feature = "http")]
#[derive(Debug, Clone, Default)]
pub struct FlathubAdapter {
    /// Fetch half; the parse half is free functions below it.
    client: FlathubClient,
}

#[cfg(feature = "http")]
#[async_trait::async_trait]
impl crate::adapter::Adapter for FlathubAdapter {
    fn source(&self) -> SourceKind {
        SourceKind::Flathub
    }

    async fn lookup(&self, id: &SourceRef) -> Result<Option<App>> {
        if id.source != SourceKind::Flathub {
            return Err(Error::UnsupportedSource {
                kind: id.source,
                id: id.id.clone(),
            });
        }
        match self.client.fetch_appstream(&id.id).await? {
            Some(payload) => parse_appstream_detail(&payload).map(Some),
            None => Ok(None),
        }
    }

    async fn search(&self, query: &str) -> Result<Vec<App>> {
        let payload = self.client.search(query).await?;
        parse_search_envelope(&payload)
    }
}

/// Maps a reqwest failure onto [`Error::Http`] (the cause rides in
/// `message` as text — the crate's `Error::Http` carries no typed source
/// field yet, error.rs).
#[cfg(feature = "http")]
fn http_error(url: &str, error: &reqwest::Error) -> Error {
    Error::Http {
        url: url.to_owned(),
        message: error.to_string(),
    }
}

// ---------------------------------------------------------------------------
// Tests — pure parse half against the frozen offline fixtures
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Availability, VerificationPolicy};

    /// Manifest-dir-anchored fixture root (conventions.md §7: fixtures are
    /// loaded at runtime, never `include_str!`).
    fn fixtures_dir() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/flathub")
    }

    /// Reads one fixture, panicking with the path on failure.
    fn read_fixture(name: &str) -> String {
        std::fs::read_to_string(fixtures_dir().join(name))
            .unwrap_or_else(|e| panic!("read fixture {name}: {e}"))
    }

    /// The (`app_id`, `remote`) pair of a `Flatpak` install descriptor.
    fn flatpak_of(app: &App) -> (&str, &str) {
        match &app.install {
            InstallMethod::Flatpak { app_id, remote } => (app_id, remote),
            other => panic!("expected Flatpak install, got {other:?}"),
        }
    }

    #[test]
    fn search_envelope_parses_brave_hits() {
        let apps = parse_search_envelope(&read_fixture("search-brave-browser.json"))
            .expect("brave search envelope parses");
        assert_eq!(apps.len(), 13, "13 hits in the brave fixture");

        let brave = &apps[0];
        assert_eq!(brave.id.as_str(), "com-brave-browser");
        assert_eq!(brave.name, "Brave");
        assert_eq!(brave.summary.as_deref(), Some("Fast Internet, AI, Adblock"));
        // Search descriptions are plain/markdown — verbatim, not stripped.
        assert!(
            brave
                .description
                .as_deref()
                .is_some_and(|d| d.contains("safer, faster"))
        );
        assert_eq!(brave.license.as_deref(), Some("MPL-2.0"));
        assert_eq!(brave.developer.as_deref(), Some("Brave Software"));
        assert_eq!(brave.homepage, None, "search hits carry no homepage");
        assert_eq!(brave.latest, None, "search hits carry no releases");
        assert_eq!(brave.binaries, Vec::<String>::new());
        assert_eq!(
            brave.artifacts,
            Vec::new(),
            "flathub publishes no checksums"
        );
        assert_eq!(brave.availability, Availability::Available);
        assert_eq!(flatpak_of(brave), ("com.brave.Browser", "flathub"));
        assert_eq!(
            brave.platforms,
            vec![
                Platform {
                    os: Os::Linux,
                    arch: Some(Arch::Aarch64),
                    min_release: None
                },
                Platform {
                    os: Os::Linux,
                    arch: Some(Arch::X86_64),
                    min_release: None
                },
            ]
        );
        assert_eq!(
            brave.sources,
            vec![SourceRef {
                source: SourceKind::Flathub,
                id: "com.brave.Browser".to_owned(),
                repo: None,
                version: None,
                provisional: false,
            }]
        );
    }

    #[test]
    fn search_and_detail_apps_carry_the_out_of_band_marker() {
        let apps = parse_search_envelope(&read_fixture("search-brave-browser.json"))
            .expect("brave search envelope parses");
        assert_eq!(
            apps[0].artifacts,
            Vec::new(),
            "flathub publishes no checksums"
        );
        assert_eq!(
            apps[0].sources[0].source.verification_policy(),
            VerificationPolicy::OutOfBand,
            "the empty artifact list means unverifiable, not no downloads"
        );

        let detail = parse_appstream_detail(&read_fixture("appstream-com.brave.Browser.json"))
            .expect("brave detail parses");
        assert_eq!(detail.artifacts, Vec::new());
        assert_eq!(
            detail.sources[0].source.verification_policy(),
            VerificationPolicy::OutOfBand
        );
    }

    #[test]
    fn search_envelope_parses_vscode_hits() {
        let apps = parse_search_envelope(&read_fixture("search-visual-studio-code.json"))
            .expect("vscode search envelope parses");
        // The envelope reports 30 total hits but serves 21 per page.
        assert_eq!(apps.len(), 21, "21 hits per the Meilisearch page size");

        let vscode = &apps[0];
        assert_eq!(
            vscode.id.as_str(),
            TorideId::slugify("com.visualstudio.code").as_str()
        );
        assert_eq!(vscode.name, "Visual Studio Code");
        assert_eq!(vscode.summary.as_deref(), Some("Code editing. Redefined."));
        assert_eq!(
            vscode.license.as_deref(),
            Some("LicenseRef-proprietary=https://code.visualstudio.com/license")
        );
        assert_eq!(vscode.developer.as_deref(), Some("Microsoft Corporation"));
        assert_eq!(flatpak_of(vscode), ("com.visualstudio.code", "flathub"));
        assert_eq!(vscode.platforms.len(), 2, "aarch64 + x86_64");
    }

    #[test]
    fn hit_id_stays_a_meilisearch_key_not_identity() {
        // The hit's `id` is the underscored Meilisearch document key; the
        // dotted `app_id` is the identity everywhere downstream.
        let envelope: SearchEnvelope =
            serde_json::from_str(&read_fixture("search-brave-browser.json"))
                .expect("envelope parses");
        assert_eq!(envelope.hits[0].meilisearch_id, "com_brave_Browser");

        let apps = parse_search_envelope(&read_fixture("search-brave-browser.json")).expect("apps");
        assert_eq!(
            flatpak_of(&apps[0]).0,
            "com.brave.Browser",
            "dotted app id, not the PK"
        );
        assert_eq!(apps[0].sources[0].id, "com.brave.Browser");
    }

    #[test]
    fn meilisearch_facet_keys_are_ignored() {
        // Both fixtures leak facetDistribution / facetStats /
        // processingTimeMs — flagged unstable by flathub.md §Limitations.
        // A clean parse proves they are tolerated and dropped.
        let apps = parse_search_envelope(&read_fixture("search-brave-browser.json"))
            .expect("facet-bearing envelope parses");
        assert!(!apps.is_empty());
    }

    #[test]
    fn main_categories_bare_string_and_array_both_parse() {
        // Bare string form (both live fixtures ship this shape).
        let envelope: SearchEnvelope =
            serde_json::from_str(&read_fixture("search-brave-browser.json")).expect("parses");
        assert_eq!(
            envelope.hits[0].main_categories,
            Some(vec!["network".to_owned()])
        );

        // Array form (the anyOf's other arm).
        let array_form = r#"{"hits":[{"app_id":"org.example.App","name":"Example",
            "summary":"s","description":"d","main_categories":["network","web"]}]}"#;
        let envelope: SearchEnvelope = serde_json::from_str(array_form).expect("parses");
        assert_eq!(
            envelope.hits[0].main_categories,
            Some(vec!["network".to_owned(), "web".to_owned()])
        );
    }

    #[test]
    fn arches_null_or_empty_means_unknown_platforms() {
        // `arches: null` — the DESIGN.md §3.3 claim-check-skipped case.
        let null_arches = r#"{"hits":[{"app_id":"org.example.App","name":"Example",
            "summary":"s","description":"d","arches":null}]}"#;
        let apps = parse_search_envelope(null_arches).expect("parses");
        assert!(
            apps[0].platforms.is_empty(),
            "null arches = unknown platforms"
        );

        let empty_arches = r#"{"hits":[{"app_id":"org.example.App","name":"Example",
            "summary":"s","description":"d","arches":[]}]}"#;
        let apps = parse_search_envelope(empty_arches).expect("parses");
        assert!(
            apps[0].platforms.is_empty(),
            "empty arches = unknown platforms"
        );

        let one_arch = r#"{"hits":[{"app_id":"org.example.App","name":"Example",
            "summary":"s","description":"d","arches":["x86_64"]}]}"#;
        let apps = parse_search_envelope(one_arch).expect("parses");
        assert_eq!(
            apps[0].platforms,
            vec![Platform {
                os: Os::Linux,
                arch: Some(Arch::X86_64),
                min_release: None
            }]
        );
    }

    #[test]
    fn unknown_arch_spellings_are_skipped() {
        let payload = r#"{"hits":[{"app_id":"org.example.App","name":"Example",
            "summary":"s","description":"d","arches":["riscv64","x86_64"]}]}"#;
        let apps = parse_search_envelope(payload).expect("parses");
        assert_eq!(
            apps[0].platforms,
            vec![Platform {
                os: Os::Linux,
                arch: Some(Arch::X86_64),
                min_release: None
            }],
            "riscv64 has no Arch variant and is dropped"
        );
    }

    #[test]
    fn appstream_detail_parses_brave() {
        let app = parse_appstream_detail(&read_fixture("appstream-com.brave.Browser.json"))
            .expect("brave detail parses");

        // releases[0] → latest; the wire timestamp is a *string*.
        let latest = app.latest.as_ref().expect("brave has releases");
        assert_eq!(latest.value, "1.96.59");
        assert_eq!(latest.original, None);
        assert_eq!(
            latest.published_unix,
            Some(1_790_208_000),
            "string-encoded int decoded"
        );

        // HTML description stripped to plain text: tags gone, source
        // indentation collapsed, paragraph breaks kept (hard line wraps
        // inside a paragraph survive as newlines, per `html_to_text`).
        let description = app.description.as_deref().expect("brave describes itself");
        assert!(
            !description.contains('<'),
            "no tags survive: {description:?}"
        );
        assert!(
            description.contains("safer, faster and better browsing"),
            "indentation whitespace collapsed: {description:?}"
        );
        assert!(
            description.contains("of rewards.\nBrowse faster"),
            "paragraph break kept"
        );

        assert_eq!(app.id.as_str(), "com-brave-browser");
        assert_eq!(app.name, "Brave");
        assert_eq!(app.summary.as_deref(), Some("Fast Internet, AI, Adblock"));
        assert_eq!(app.homepage.as_deref(), Some("https://brave.com"));
        assert_eq!(app.license.as_deref(), Some("MPL-2.0"));
        assert_eq!(app.developer.as_deref(), Some("Brave Software"));
        assert_eq!(app.artifacts, Vec::new());
        assert_eq!(flatpak_of(&app), ("com.brave.Browser", "flathub"));

        // No `arches` key in the detail schema → the bundle arch
        // (app/com.brave.Browser/x86_64/stable) claims the platform.
        assert_eq!(
            app.platforms,
            vec![Platform {
                os: Os::Linux,
                arch: Some(Arch::X86_64),
                min_release: None
            }]
        );

        // The detail captured the version, so the SourceRef row carries it.
        assert_eq!(
            app.sources,
            vec![SourceRef {
                source: SourceKind::Flathub,
                id: "com.brave.Browser".to_owned(),
                repo: None,
                version: Some(Version {
                    value: "1.96.59".to_owned(),
                    original: None,
                    published_unix: Some(1_790_208_000),
                }),
                provisional: false,
            }]
        );
    }

    #[test]
    fn appstream_detail_parses_vscode() {
        let app = parse_appstream_detail(&read_fixture("appstream-com.visualstudio.code.json"))
            .expect("vscode detail parses");

        let latest = app.latest.as_ref().expect("vscode has releases");
        assert_eq!(latest.value, "1.138.0");
        assert_eq!(latest.published_unix, Some(1_789_516_800));

        // Markdown inside the HTML survives; the HTML itself does not.
        let description = app.description.as_deref().expect("vscode describes itself");
        assert!(!description.contains('<'));
        assert!(description.contains("**NOTE: This is the proprietary Microsoft build"));

        assert_eq!(app.id.as_str(), "com-visualstudio-code");
        assert_eq!(app.name, "Visual Studio Code");
        assert_eq!(
            app.homepage.as_deref(),
            Some("https://code.visualstudio.com")
        );
        assert_eq!(
            app.license.as_deref(),
            Some("LicenseRef-proprietary=https://code.visualstudio.com/license")
        );
        assert_eq!(app.developer.as_deref(), Some("Microsoft Corporation"));
        assert_eq!(flatpak_of(&app), ("com.visualstudio.code", "flathub"));
        assert_eq!(
            app.platforms,
            vec![Platform {
                os: Os::Linux,
                arch: Some(Arch::X86_64),
                min_release: None
            }]
        );
    }

    #[test]
    fn int_timestamp_and_leading_release_win_latest() {
        // The deserializer must also accept a JSON int timestamp, and
        // releases[] is most-recent-first so releases[0] wins.
        let payload = r#"{"id":"org.example.App","name":"Example","summary":"s",
            "description":"d",
            "releases":[{"version":"2.0","timestamp":1790208000},
                        {"version":"1.0","timestamp":"1000000000"}]}"#;
        let app = parse_appstream_detail(payload).expect("parses");
        let latest = app.latest.as_ref().expect("latest");
        assert_eq!(latest.value, "2.0", "releases[0] is current");
        assert_eq!(
            latest.published_unix,
            Some(1_790_208_000),
            "int form accepted"
        );

        let source = &app.sources[0];
        assert_eq!(
            source.version.as_ref().map(|v| v.value.as_str()),
            Some("2.0")
        );
    }

    #[test]
    fn detail_without_bundle_or_arches_yields_unknown_platforms() {
        // No arches key (today's schema), no bundle, no releases.
        let payload = r#"{"id":"org.example.App","name":"Example","summary":"s",
            "description":"<p>body</p>"}"#;
        let app = parse_appstream_detail(payload).expect("parses");
        assert!(app.platforms.is_empty(), "no arch declaration = unknown");
        assert_eq!(app.latest, None, "no releases = no latest");
        assert_eq!(app.description.as_deref(), Some("body"));

        // A bundle whose arch segment does not decode also stays unknown.
        let payload = r#"{"id":"org.example.App","name":"Example","summary":"s",
            "description":"d","bundle":{"value":"app/org.example.App/riscv64/stable"}}"#;
        let app = parse_appstream_detail(payload).expect("parses");
        assert!(app.platforms.is_empty());
    }

    #[test]
    fn flatpakref_parses_brave_pointer() {
        let reference = parse_flatpakref(&read_fixture("com.brave.Browser.flatpakref"))
            .expect("brave flatpakref parses");
        assert_eq!(reference.name.as_deref(), Some("com.brave.Browser"));
        assert_eq!(reference.branch.as_deref(), Some("stable"));
        assert_eq!(
            reference.title.as_deref(),
            Some("com.brave.Browser from flathub")
        );
        assert_eq!(
            reference.url.as_deref(),
            Some("https://dl.flathub.org/repo/")
        );
        assert_eq!(reference.suggest_remote_name.as_deref(), Some("flathub"));
        assert!(
            reference
                .gpg_key
                .as_deref()
                .is_some_and(|key| key.starts_with("mQINBFlD2sABEAD")),
            "armoured GPG key parsed whole"
        );
        assert_eq!(
            reference.runtime_repo.as_deref(),
            Some("https://dl.flathub.org/repo/flathub.flatpakrepo")
        );
    }

    #[test]
    fn flatpakref_without_header_is_rejected() {
        // Arbitrary key=value text is not a flatpakref: the section header
        // is the format marker.
        let err = parse_flatpakref("Name=org.example.App\nUrl=https://example.invalid/repo/\n")
            .expect_err("header-less payload rejected");
        assert!(
            matches!(
                err,
                Error::Parse {
                    kind: "flatpakref",
                    ..
                }
            ),
            "{err:?}"
        );

        // Missing keys tolerate to None; unknown keys (IsRuntime) ignored.
        let reference = parse_flatpakref("[Flatpak Ref]\nName=org.example.App\nIsRuntime=false\n")
            .expect("parses");
        assert_eq!(reference.name.as_deref(), Some("org.example.App"));
        assert_eq!(reference.branch, None);
        assert_eq!(reference.url, None);
    }

    #[test]
    fn html_to_text_decodes_entities_and_block_tags() {
        let html = "<p>a &amp; b</p><ul><li>x &lt;y&gt; &#39;quoted&#39;</li></ul><br/>tail";
        assert_eq!(html_to_text(html), "a & b\nx <y> 'quoted'\ntail");
        // `&amp;lt;` must stay the literal text `&lt;`, not become a tag.
        assert_eq!(html_to_text("<p>&amp;lt;tag&amp;gt;</p>"), "&lt;tag&gt;");
        // An unterminated `<` is literal text, not a swallowed region.
        assert_eq!(html_to_text("a < b"), "a < b");
    }

    #[test]
    fn hit_without_app_id_is_skipped() {
        let payload = r#"{"hits":[
            {"app_id":"","name":"No id","summary":"s","description":"d"},
            {"app_id":"org.example.App","name":"Example","summary":"s","description":"d"}]}"#;
        let apps = parse_search_envelope(payload).expect("parses");
        assert_eq!(apps.len(), 1, "the app_id-less hit is dropped");
        assert_eq!(apps[0].name, "Example");
    }
}
