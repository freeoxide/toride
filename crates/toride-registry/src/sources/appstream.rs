//! `AppStream` / DEP-11 adapter — normalizes Debian/Ubuntu distro catalogs
//! into [`App`]s.
//!
//! Debian, Ubuntu and derivatives publish one DEP-11 YAML catalog per
//! suite × component × arch at
//! `dists/<suite>/<component>/dep11/Components-<arch>.yml.gz` (layout
//! verified identical on both, `docs/survey/appstream.md` §3; Fedora
//! publishes no URL-addressable catalog and stays out of scope — the
//! `fedora-43-os-metainfo.xml` fixture is reference-only wave-2 material,
//! no parser here reads it). The adapter implements DESIGN.md §4.4:
//!
//! - the wire structs [`Dep11Catalog`]/[`Dep11Header`]/[`Dep11Component`]
//!   declared in DESIGN.md §3.1, parsed with `serde_yaml` and
//!   `#[serde(default)]` + ignore-unknown everywhere (spec §4: "fields not
//!   mentioned … are not recognized by DEP-11 parsers");
//! - the pure parse half [`parse_dep11_catalog`] (`&str` in →
//!   [`Dep11Catalog`] out: header document + component documents);
//! - the fetch half [`AppstreamClient`] — serves repeat calls from an
//!   mtime-keyed TTL cache (zero network inside the window), revalidates
//!   stale entries with a conditional `If-None-Match`/`If-Modified-Since`
//!   GET, and only then streams the `.yml.gz` download to the disk cache
//!   through flate2 write-through (8.7 MB gz for sid/main), handing the
//!   fully decompressed ~27 MB text to the pure parser ("never buffer
//!   whole" applies to the download only; the lighter
//!   `CID-Index-<arch>.json.gz` is the documented fallback if that ever
//!   proves too heavy, appstream.md §7);
//! - [`AppstreamAdapter`], which emits
//!   [`InstallMethod::Distro`]`{family,
//!   repo, package}` scoped by the header `Origin`, claims
//!   `[(Linux, arch)]` decoded from the catalog filename (`amd64` →
//!   `X86_64`, `arm64` → `Aarch64`; REVIEW addition — Distro Apps are
//!   never claim-less for the fetched arch, so apt installs are
//!   plannable), maps `Provides.binaries` → [`App::binaries`] with the
//!   Package/ID fallback chain (the tool-detection join key,
//!   appstream.md §5), and `Developer.name.C` (else `Developer.id`) →
//!   [`App::developer`].
//!
//! ## Pipeline
//!
//! 1. **Fetch** — [`AppstreamClient::fetch_catalog`] answers from the
//!    cached `<cache>/appstream/<suite>-<component>-Components-<arch>.yml.gz`
//!    while it is younger than [`CATALOG_CACHE_TTL`] (mtime-keyed, no
//!    network); a stale or missing copy is revalidated with a conditional
//!    GET and only re-downloaded on change or missing validators,
//!    streaming write-through into the cache (buffered, one chunk at a
//!    time) and decompressing from disk.
//! 2. **Parse** — [`parse_dep11_catalog`] splits the multi-document YAML
//!    stream (header first, one document per component; stray empty
//!    documents are skipped) with every field defaulted, never erroring
//!    on unknown keys.
//! 3. **Normalize** — [`AppstreamAdapter`] filters to
//!    `Type: desktop-application` + `console-application` and emits one
//!    [`App`] per remaining component.
//! 4. **Plan** — downstream, `apt install <package>` follows from the
//!    emitted [`InstallMethod::Distro`].
//!
//! ## Quick start
//!
//! Parsing a catalog excerpt offline (the fixture flow; no network):
//!
//! ```
//! use toride_registry::sources::appstream::{decode_catalog_arch, parse_dep11_catalog};
//!
//! let text = concat!(
//!     "%YAML 1.2\n",
//!     "---\n",
//!     "File: DEP-11\n",
//!     "Version: '1.0'\n",
//!     "Origin: debian-sid-main\n",
//!     "---\n",
//!     "Type: console-application\n",
//!     "ID: rg.desktop\n",
//!     "Package: ripgrep\n",
//!     "Name:\n",
//!     "  C: ripgrep\n",
//!     "Provides:\n",
//!     "  binaries:\n",
//!     "  - rg\n",
//! );
//! let catalog = parse_dep11_catalog(text).unwrap();
//! assert_eq!(catalog.header.origin.as_deref(), Some("debian-sid-main"));
//! assert_eq!(catalog.components.len(), 1);
//! assert_eq!(catalog.components[0].provides.as_ref().unwrap().binaries, ["rg"]);
//! // The arch claim comes from the catalog FILENAME, not a YAML field.
//! assert_eq!(decode_catalog_arch("Components-amd64.yml.gz"), Some(toride_registry::Arch::X86_64));
//! ```
//!
//! The full fetch → parse flow (network + `http` feature; ignored here —
//! catalogs are republished ~daily so only the invariant set is asserted,
//! see the `TORIDE_REGISTRY_INTEGRATION` test at the bottom of this file):
//!
//! ```rust,ignore
//! let client = AppstreamClient::new(cache_dir);
//! let text = client.fetch_catalog(DEBIAN_BASE_URL, "sid", "main", "amd64").await?;
//! let adapter = AppstreamAdapter::from_text(&text, decode_catalog_arch("Components-amd64.yml.gz"))?;
//! let hits = adapter.search("firefox").await?;
//! ```

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::adapter::Adapter;
use crate::error::{Error, Result};
use crate::model::{
    App, Arch, Availability, DistroFamily, InstallMethod, Os, Platform, SourceKind, SourceRef,
    TorideId, Version,
};

#[cfg(feature = "http")]
use std::io::{Read, Write};
#[cfg(feature = "http")]
use std::time::{Duration, SystemTime};

// ---------------------------------------------------------------------------
// Wire structs (DESIGN.md §3.1 — declared, not invented)
// ---------------------------------------------------------------------------

/// A DEP-11 localized text field: locale → text, the `C` key being the
/// mandatory default locale (spec §3.2). Values are always text — numeric-
/// looking scalars (`Name: {C: 2048}`) are coerced, see the deserializers
/// below.
pub type LocaleMap = HashMap<String, String>;

/// The `C` locale key — the mandatory default locale of every DEP-11
/// localized field.
const C_LOCALE: &str = "C";

/// Component types the adapter normalizes (DESIGN.md §4.4): GUI
/// applications plus CLI applications. Everything else (`generic`, `addon`,
/// `codec`, `font`, `firmware`, …) is skipped at [`App`]
/// emission time.
const APP_COMPONENT_TYPES: [&str; 2] = ["desktop-application", "console-application"];

/// One DEP-11 catalog: the multi-document YAML stream's header document
/// plus one entry per component document. Component order preserves the
/// catalog's.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Dep11Catalog {
    /// The first YAML document — the catalog header.
    pub header: Dep11Header,
    /// One entry per component document, in catalog order.
    pub components: Vec<Dep11Component>,
}

/// The DEP-11 header document (first document of the stream; spec §3.2).
/// Every field is optional on the wire — `#[serde(default)]` everywhere
/// per DESIGN.md §4.4 strictness.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Dep11Header {
    /// `File: DEP-11` — format marker.
    #[serde(rename = "File", default)]
    pub file: Option<String>,
    /// `Version` — `AppStream` spec version targeted (`"1.0"` in the
    /// fixture). Tolerated as a bare number on the wire (unquoted `1.0`
    /// would otherwise parse as a float and fail the whole catalog).
    #[serde(rename = "Version", default, deserialize_with = "de_opt_text")]
    pub version: Option<String>,
    /// `Origin: debian-sid-main` — the repo identity: [`SourceRef::repo`]
    /// and the [`InstallMethod::Distro`] scope.
    #[serde(rename = "Origin", default)]
    pub origin: Option<String>,
    /// `MediaBaseUrl` — base URL for relative icon/screenshot media URLs.
    #[serde(rename = "MediaBaseUrl", default)]
    pub media_base_url: Option<String>,
    /// `Time` — catalog generation timestamp (ISO-8601 or basic-format;
    /// kept as the source spells it).
    #[serde(rename = "Time", default)]
    pub time: Option<String>,
    /// `Architecture` — optional multiarch disambiguator.
    #[serde(rename = "Architecture", default)]
    pub architecture: Option<String>,
}

/// One DEP-11 component document (spec §3.2). Every field optional — even
/// `Package` is missing once in sid/main's 2,627 components
/// (appstream.md §4 frequency table). Unknown fields (spec evolves;
/// `Keywords`, `Icon`, `Screenshots`, `Url`, `ContentRating`, … are
/// deliberately dropped in wave 1 per DESIGN.md §4.4) are ignored.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Dep11Component {
    /// `Type` — `desktop-application`, `console-application`, `generic`,
    /// `addon`, … Only the two `APP_COMPONENT_TYPES` become
    /// [`App`]s.
    #[serde(rename = "Type", default)]
    pub type_: Option<String>,
    /// `ID` — component id; legacy `.desktop`-suffixed and modern
    /// reverse-DNS styles coexist in the same catalog (appstream.md §4).
    #[serde(rename = "ID", default)]
    pub id: Option<String>,
    /// `Package` — the distro package name `apt` knows; tolerated as a
    /// bare number on the wire (a package literally named `2048`).
    #[serde(rename = "Package", default, deserialize_with = "de_opt_text")]
    pub package: Option<String>,
    /// `Name` — localized display name, `C` mandatory.
    #[serde(rename = "Name", default, deserialize_with = "de_locale_map")]
    pub name: LocaleMap,
    /// `Summary` — localized one-liner, `C` mandatory.
    #[serde(rename = "Summary", default, deserialize_with = "de_locale_map")]
    pub summary: LocaleMap,
    /// `Description` — localized HTML (machine-generated; single-line or
    /// `|-` block scalars in the live catalog).
    #[serde(rename = "Description", default, deserialize_with = "de_locale_map")]
    pub description: LocaleMap,
    /// `ProjectLicense` — SPDX expression (`GPL-3.0-or-later`).
    #[serde(rename = "ProjectLicense", default)]
    pub project_license: Option<String>,
    /// `Developer` — `{id, name:{locales}}`; present for 942/2,627
    /// sid/main components.
    #[serde(rename = "Developer", default)]
    pub developer: Option<Dep11Developer>,
    /// `Releases` — newest first per spec; only 854/2,627 carry any.
    #[serde(rename = "Releases", default)]
    pub releases: Vec<Dep11Release>,
    /// `Provides` — typed capabilities; `binaries` is the tool-detection
    /// join key.
    #[serde(rename = "Provides", default)]
    pub provides: Option<Dep11Provides>,
    /// `Launchable` — `desktop-id` entries that launch the app.
    #[serde(rename = "Launchable", default)]
    pub launchable: Option<Dep11Launchable>,
    /// `Categories` — freedesktop menu categories (`Network`, `Utility`).
    #[serde(rename = "Categories", default)]
    pub categories: Vec<String>,
}

/// `Developer` dict — upstream developer identity.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Dep11Developer {
    /// `id` — reverse-DNS developer id (`org.gnome`).
    #[serde(default)]
    pub id: Option<String>,
    /// `name` — localized developer name (`C`: "The GNOME Project").
    #[serde(default, deserialize_with = "de_locale_map")]
    pub name: LocaleMap,
}

/// `Releases` entry — one published release. Optional because only ~⅓ of
/// components carry releases at all.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Dep11Release {
    /// `version` — release version string; tolerated as a bare number.
    #[serde(default, deserialize_with = "de_opt_text")]
    pub version: Option<String>,
    /// `type` — `stable` / `development`.
    #[serde(rename = "type", default)]
    pub type_: Option<String>,
    /// `unix-timestamp` — release time, unix seconds.
    #[serde(
        rename = "unix-timestamp",
        default,
        deserialize_with = "de_opt_unix_timestamp"
    )]
    pub unix_timestamp: Option<i64>,
}

/// `Provides` dict — only the wave-1-relevant lists are modeled; the
/// other spec keys (`libraries`, `fonts`, `modaliases`, `firmware`,
/// `python3`, `dbus`, `ids`) are ignored.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Dep11Provides {
    /// `binaries` — executable names the package puts on PATH; the
    /// tool-detection join key (appstream.md §5).
    #[serde(default)]
    pub binaries: Vec<String>,
    /// `mediatypes` — MIME/scheme handlers (weaker signal; not mapped).
    #[serde(default)]
    pub mediatypes: Vec<String>,
}

/// `Launchable` dict.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Dep11Launchable {
    /// `desktop-id` — `.desktop` ids launching the app.
    #[serde(rename = "desktop-id", default)]
    pub desktop_id: Vec<String>,
}

// ---------------------------------------------------------------------------
// Tolerant deserializers (DESIGN.md §4.4 strictness: degrade, never error)
// ---------------------------------------------------------------------------

/// Coerce a YAML scalar into its text form. DEP-11 emits machine-quoted
/// YAML, but third-party catalogs can spell `Version: 1.0` or
/// `Name: {C: 2048}` bare — a number there must degrade to text, not fail
/// the whole 26 MB catalog. `serde_yaml::Number`'s `Display` keeps float
/// spelling (`1.0` → `"1.0"`, verified this session).
fn yaml_scalar_as_text(value: &serde_yaml::Value) -> Option<String> {
    match value {
        serde_yaml::Value::String(text) => Some(text.clone()),
        serde_yaml::Value::Number(number) => Some(number.to_string()),
        serde_yaml::Value::Bool(flag) => Some(flag.to_string()),
        _ => None,
    }
}

/// `Option<String>` tolerating bare numbers/bools (and explicit null).
fn de_opt_text<'de, D>(deserializer: D) -> std::result::Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    match Option::<serde_yaml::Value>::deserialize(deserializer)? {
        None | Some(serde_yaml::Value::Null) => Ok(None),
        Some(value) => yaml_scalar_as_text(&value)
            .map(Some)
            .ok_or_else(|| <D::Error as serde::de::Error>::custom("expected a text scalar")),
    }
}

/// `Option<i64>` tolerating string-encoded integers on the wire.
fn de_opt_unix_timestamp<'de, D>(deserializer: D) -> std::result::Result<Option<i64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let Some(value) = Option::<serde_yaml::Value>::deserialize(deserializer)? else {
        return Ok(None);
    };
    match value {
        serde_yaml::Value::Null => Ok(None),
        serde_yaml::Value::Number(number) => number
            .as_i64()
            .or_else(|| number.as_u64().and_then(|u| i64::try_from(u).ok()))
            .map(Some)
            .ok_or_else(|| {
                <D::Error as serde::de::Error>::custom("unix-timestamp outside i64 range")
            }),
        serde_yaml::Value::String(text) => text.parse::<i64>().map(Some).map_err(|_| {
            <D::Error as serde::de::Error>::custom(format!("unix-timestamp not an integer: {text}"))
        }),
        _ => Err(<D::Error as serde::de::Error>::custom(
            "unix-timestamp must be an integer",
        )),
    }
}

/// A localized dict whose values may arrive as bare scalars.
fn de_locale_map<'de, D>(deserializer: D) -> std::result::Result<LocaleMap, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let raw = HashMap::<String, serde_yaml::Value>::deserialize(deserializer)?;
    let mut map = LocaleMap::with_capacity(raw.len());
    for (locale, value) in raw {
        match yaml_scalar_as_text(&value) {
            Some(text) => {
                map.insert(locale, text);
            }
            None => {
                return Err(<D::Error as serde::de::Error>::custom(format!(
                    "locale value for `{locale}` is not a text scalar"
                )));
            }
        }
    }
    Ok(map)
}

// ---------------------------------------------------------------------------
// Pure parse half (no clock / no network / no client)
// ---------------------------------------------------------------------------

/// Parse a DEP-11 multi-document YAML stream into its header and
/// components. The first non-empty document is the header, every
/// subsequent non-empty document is one component (stray empty documents
/// between `---` markers are skipped, verified against `serde_yaml`
/// this session). Component order preserves the stream's.
///
/// # Errors
///
/// [`Error::Parse`] (kind `yaml`) when the payload is not parseable YAML
/// or contains no documents at all; a malformed header or component
/// document names the failure. Unknown fields never error (spec §4).
pub fn parse_dep11_catalog(payload: &str) -> Result<Dep11Catalog> {
    let mut header = Dep11Header::default();
    let mut components = Vec::new();
    let mut saw_header = false;
    for document in serde_yaml::Deserializer::from_str(payload) {
        if saw_header {
            match Option::<Dep11Component>::deserialize(document) {
                Ok(Some(component)) => components.push(component),
                // An empty document (a stray `---` marker) deserializes
                // to `None` and is skipped.
                Ok(None) => {}
                Err(error) => {
                    return Err(Error::Parse {
                        kind: "yaml",
                        id: "<component>".to_owned(),
                        message: error.to_string(),
                    });
                }
            }
        } else {
            // Spec §3.2: the first document is the header.
            match Option::<Dep11Header>::deserialize(document) {
                Ok(Some(parsed)) => {
                    header = parsed;
                    saw_header = true;
                }
                Ok(None) => {}
                Err(error) => {
                    return Err(Error::Parse {
                        kind: "yaml",
                        id: "<header>".to_owned(),
                        message: error.to_string(),
                    });
                }
            }
        }
    }
    if !saw_header {
        return Err(Error::Parse {
            kind: "yaml",
            id: "<catalog>".to_owned(),
            message: "no DEP-11 header document found".to_owned(),
        });
    }
    Ok(Dep11Catalog { header, components })
}

/// Strip HTML down to plain text: drop `<…>` tags, decode the XML
/// entities DEP-11 descriptions actually use, collapse whitespace runs
/// (block-scalar descriptions arrive multi-line). Content is
/// machine-generated, well-formed XML, so a bare unpaired `<` in text is
/// not a real-world case.
#[must_use]
fn strip_html(html: &str) -> String {
    let mut tagged_free = String::with_capacity(html.len());
    let mut in_tag = false;
    for character in html.chars() {
        match character {
            '<' => in_tag = true,
            '>' => in_tag = false,
            plain if !in_tag => tagged_free.push(plain),
            _ => {}
        }
    }
    // `&amp;` last, so `&amp;lt;` decodes to `&lt;` and not `<`.
    let decoded = tagged_free
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&nbsp;", " ")
        .replace("&amp;", "&");
    decoded.split_whitespace().collect::<Vec<_>>().join(" ")
}

// ---------------------------------------------------------------------------
// Filename / origin decoding
// ---------------------------------------------------------------------------

/// Decode the `Platform` arch from a DEP-11 catalog filename or URL — the
/// catalog names no arch in YAML; it lives in the fetch path
/// (`Components-<arch>.yml.gz`). REVIEW addition per DESIGN.md §4.4: the
/// decoded arch becomes the emitted `[(Linux, arch)]` claim so Distro
/// Apps are never claim-less for the arch the catalog was fetched for.
///
/// Accepted spellings: `amd64`/`x86_64`/`x86-64` → [`Arch::X86_64`],
/// `arm64`/`aarch64` → [`Arch::Aarch64`], `i386`/`x86` → [`Arch::X86`].
/// Works on both canonical (`Components-amd64.yml.gz`) and fixture-style
/// (`debian-sid-main-amd64.yml`) names. `None` = no decodable arch → the
/// adapter emits `platforms = []` (unknown, NOT universal).
#[must_use]
pub fn decode_catalog_arch(filename_or_url: &str) -> Option<Arch> {
    let filename = filename_or_url.rsplit('/').next().unwrap_or_default();
    // First dot-segment: strips `.yml`, `.yml.gz`, `.xz`, …
    let stem = filename.split('.').next().unwrap_or_default();
    let token = match stem.strip_prefix("Components-") {
        Some(rest) => rest,
        // Fixture-style: the arch is the last dash-segment.
        None => stem.rsplit('-').next().unwrap_or_default(),
    };
    match token {
        "amd64" | "x86_64" | "x86-64" => Some(Arch::X86_64),
        "arm64" | "aarch64" => Some(Arch::Aarch64),
        "i386" | "x86" => Some(Arch::X86),
        _ => None,
    }
}

/// Ubuntu release codenames accepted as a family hint when an `Origin`
/// lacks the `ubuntu-` prefix. Verified live this session:
/// `archive.ubuntu.com` noble/main carries `Origin: ubuntu-noble-main`;
/// the codename list is the fallback for catalogs that spell it
/// differently.
const UBUNTU_CODENAMES: [&str; 6] = ["noble", "questing", "jammy", "focal", "bionic", "plucky"];

/// Decode the [`DistroFamily`] from the DEP-11 header `Origin` (or URL
/// layout — both verified identical across Debian/Ubuntu, appstream.md
/// §3): `debian*` → [`DistroFamily::Debian`], `ubuntu*` (or a known
/// Ubuntu codename) → [`DistroFamily::Ubuntu`].
///
/// The documented default for an undecodable origin is
/// [`DistroFamily::Debian`]: DEP-11 YAML is a Debian-family publication
/// format ("primarily used by Debian and its derivatives", appstream.md
/// §1), so the manager guess is `apt`; the `repo` scope still carries the
/// verbatim origin.
#[must_use]
pub fn decode_family(origin: Option<&str>) -> DistroFamily {
    let Some(origin) = origin else {
        return DistroFamily::Debian;
    };
    let origin = origin.to_ascii_lowercase();
    if origin.starts_with("debian") {
        DistroFamily::Debian
    } else if origin.starts_with("ubuntu")
        || UBUNTU_CODENAMES.iter().any(|code| origin.contains(code))
    {
        DistroFamily::Ubuntu
    } else {
        DistroFamily::Debian
    }
}

// ---------------------------------------------------------------------------
// AppstreamAdapter — the normalized-model half
// ---------------------------------------------------------------------------

/// The `AppStream`/DEP-11 [`Adapter`] (DESIGN.md §4.4).
///
/// Holds one parsed catalog in memory (~27 MB of YAML text becomes much
/// smaller typed data) plus the scope decoded from its fetch: the header
/// `Origin` (`repo`/family) and the filename arch (`platforms` claim).
/// There is deliberately no `Default`: an adapter without a catalog has
/// nothing to answer with — construct it via [`AppstreamAdapter::from_text`]
/// (offline/fixture flow) or from an
/// [`AppstreamClient::fetch_catalog`]
/// result.
#[derive(Debug, Clone, PartialEq)]
pub struct AppstreamAdapter {
    /// The parsed catalog this adapter serves search/lookup from.
    catalog: Dep11Catalog,
    /// Family decoded from the header `Origin`.
    family: DistroFamily,
    /// Verbatim header `Origin` (`debian-sid-main`) — the
    /// [`SourceRef::repo`] scope and the `Distro` install's `repo`.
    repo: Option<String>,
    /// Arch decoded from the catalog filename; `None` → emitted Apps have
    /// `platforms = []` (unknown).
    arch: Option<Arch>,
}

impl AppstreamAdapter {
    /// Build an adapter over an already-parsed catalog.
    ///
    /// `arch` is what [`decode_catalog_arch`] extracted from the
    /// catalog's filename (the YAML itself names no arch).
    #[must_use]
    pub fn new(catalog: Dep11Catalog, arch: Option<Arch>) -> Self {
        let repo = catalog.header.origin.clone();
        let family = decode_family(catalog.header.origin.as_deref());
        Self {
            catalog,
            family,
            repo,
            arch,
        }
    }

    /// Parse catalog text (raw, decompressed — what
    /// [`AppstreamClient::fetch_catalog`] returns) into an adapter.
    ///
    /// # Errors
    ///
    /// [`Error::Parse`] when [`parse_dep11_catalog`] rejects the payload.
    pub fn from_text(text: &str, arch: Option<Arch>) -> Result<Self> {
        Ok(Self::new(parse_dep11_catalog(text)?, arch))
    }

    /// The parsed catalog (header + all components, unfiltered).
    #[must_use]
    pub fn catalog(&self) -> &Dep11Catalog {
        &self.catalog
    }

    /// Normalize one component into an [`App`] — `None` for
    /// components outside [`APP_COMPONENT_TYPES`]. Mapping per
    /// DESIGN.md §4.4:
    ///
    /// - `Name.C` / `Summary.C` → name/summary; `Description.C` HTML →
    ///   stripped text;
    /// - `ProjectLicense` → license; `Developer.name.C`, falling back to
    ///   `Developer.id` (review addition) → developer;
    /// - `Releases[0]` → latest; `Provides.binaries`, falling back to
    ///   `Package`, then to `Launchable.desktop-id`/`ID` basename →
    ///   binaries (the tool-detection join key);
    /// - identity rows: `{Distro, package}` first (the apt-installable
    ///   name and the slugify input), plus `{Distro, ID}` when it
    ///   differs — both scoped by the header `Origin`;
    /// - `platforms = [(Linux, arch)]` from the catalog filename; no
    ///   decodable arch → `[]` (unknown, per the model's contract).
    fn component_to_app(&self, component: &Dep11Component) -> Option<App> {
        if !is_app_component(component) {
            return None;
        }
        let without_desktop_suffix =
            |id: &str| id.strip_suffix(".desktop").unwrap_or(id).to_owned();
        let component_id = component.id.clone();
        // `Package` is the apt-installable identity (2,626/2,627 in
        // sid/main); the `.desktop`-stripped ID stands in for the one
        // component that lacks it.
        let package = match (component.package.clone(), component_id.as_deref()) {
            (Some(package), _) => package,
            (None, Some(id)) => without_desktop_suffix(id),
            (None, None) => return None,
        };
        let name = match (component.name.get(C_LOCALE), component_id.as_deref()) {
            (Some(name), _) => name.clone(),
            (None, Some(id)) => without_desktop_suffix(id),
            (None, None) => package.clone(),
        };
        let summary = component.summary.get(C_LOCALE).cloned();
        let description = component
            .description
            .get(C_LOCALE)
            .map(String::as_str)
            .map(strip_html);
        // Review addition: `Developer.name.C`, falling back to
        // `Developer.id`; absent → `None`.
        let developer = component.developer.as_ref().and_then(|developer| {
            developer
                .name
                .get(C_LOCALE)
                .cloned()
                .or_else(|| developer.id.clone())
        });
        let first_release = component.releases.first();
        let latest = first_release.and_then(|release| {
            release.version.as_ref().map(|value| Version {
                value: value.clone(),
                original: None,
                published_unix: release.unix_timestamp,
            })
        });
        let binaries = component_binaries(component);
        let platforms = self
            .arch
            .map(|arch| {
                vec![Platform {
                    os: Os::Linux,
                    arch: Some(arch),
                    min_release: None,
                }]
            })
            .unwrap_or_default();
        // `Url.homepage` is deliberately unmapped in wave 1 (DESIGN.md
        // §4.4 keeps it in the dropped row; the declared wire struct has
        // no Url field).
        let sources = self.identity_rows(component_id.as_deref(), &package, latest.as_ref());
        Some(App {
            id: TorideId::slugify(&package),
            name,
            aliases: Vec::new(),
            summary,
            description,
            homepage: None,
            license: component.project_license.clone(),
            developer,
            binaries,
            latest,
            platforms,
            artifacts: Vec::new(),
            install: InstallMethod::Distro {
                family: self.family,
                repo: self.repo.clone(),
                package,
            },
            sources,
            // DEP-11 declares no deprecation lifecycle.
            availability: Availability::Available,
        })
    }

    /// The component's [`SourceRef`] rows: `{Distro, package}` first
    /// (the slugify input, DESIGN.md §5 rule 2), plus `{Distro, ID}` when
    /// the ID differs — both scoped by the header `Origin`, carrying the
    /// captured version, never provisional.
    fn identity_rows(
        &self,
        component_id: Option<&str>,
        package: &str,
        latest: Option<&Version>,
    ) -> Vec<SourceRef> {
        let mut rows = vec![SourceRef {
            source: SourceKind::Distro,
            id: package.to_owned(),
            repo: self.repo.clone(),
            version: latest.cloned(),
            provisional: false,
        }];
        if let Some(id) = component_id
            && id != package
        {
            rows.push(SourceRef {
                source: SourceKind::Distro,
                id: id.to_owned(),
                repo: self.repo.clone(),
                version: latest.cloned(),
                provisional: false,
            });
        }
        rows
    }
}

/// True when the component's `Type` is one the adapter normalizes.
fn is_app_component(component: &Dep11Component) -> bool {
    component
        .type_
        .as_deref()
        .is_some_and(|type_| APP_COMPONENT_TYPES.contains(&type_))
}

/// The `binaries` fallback chain (appstream.md §7, DESIGN.md §4.4):
/// `Provides.binaries` → `Package` exact → `Launchable.desktop-id`/`ID`
/// basename (the `.desktop` suffix stripped). First available level wins;
/// the fixture's three components exercise the second level — all carry
/// only `Provides.mediatypes`.
#[must_use]
fn component_binaries(component: &Dep11Component) -> Vec<String> {
    if let Some(provides) = &component.provides
        && !provides.binaries.is_empty()
    {
        return provides.binaries.clone();
    }
    if let Some(package) = &component.package {
        return vec![package.clone()];
    }
    let without_desktop_suffix = |id: &str| id.strip_suffix(".desktop").unwrap_or(id).to_owned();
    let mut binaries: Vec<String> = Vec::new();
    let mut push = |name: String| {
        if !binaries.contains(&name) {
            binaries.push(name);
        }
    };
    if let Some(launchable) = &component.launchable {
        launchable
            .desktop_id
            .iter()
            .for_each(|id| push(without_desktop_suffix(id)));
    }
    if let Some(id) = &component.id {
        push(without_desktop_suffix(id));
    }
    binaries
}

/// Free-text match for [`AppstreamAdapter::search`]: case-insensitive
/// substring over the component's names, summary, id, package,
/// categories, binaries, and desktop ids.
fn component_matches(component: &Dep11Component, needle: &str) -> bool {
    let locale_hit = |map: &LocaleMap| {
        map.values()
            .any(|text| text.to_lowercase().contains(needle))
    };
    let list_hit = |values: &[String]| {
        values
            .iter()
            .any(|value| value.to_lowercase().contains(needle))
    };
    locale_hit(&component.name)
        || locale_hit(&component.summary)
        || component
            .id
            .as_deref()
            .is_some_and(|id| id.to_lowercase().contains(needle))
        || component
            .package
            .as_deref()
            .is_some_and(|id| id.to_lowercase().contains(needle))
        || component
            .categories
            .iter()
            .any(|category| category.to_lowercase().contains(needle))
        || component
            .provides
            .as_ref()
            .is_some_and(|provides| list_hit(&provides.binaries) || list_hit(&provides.mediatypes))
        || component
            .launchable
            .as_ref()
            .is_some_and(|launchable| list_hit(&launchable.desktop_id))
}

#[async_trait::async_trait]
impl Adapter for AppstreamAdapter {
    fn source(&self) -> SourceKind {
        SourceKind::Distro
    }

    /// Look up one app by package name or component ID (both
    /// [`SourceRef`] row styles this adapter emits, §4.4).
    ///
    /// # Errors
    ///
    /// [`Error::UnsupportedSource`] when the row names a non-`Distro`
    /// source. A row whose `repo` scope differs from this catalog's
    /// `Origin` is simply not here: `Ok(None)`.
    async fn lookup(&self, id: &SourceRef) -> Result<Option<App>> {
        if id.source != SourceKind::Distro {
            return Err(Error::UnsupportedSource {
                kind: id.source,
                id: id.id.clone(),
            });
        }
        if let (Some(wanted), Some(have)) = (&id.repo, &self.repo)
            && wanted != have
        {
            return Ok(None);
        }
        let wanted = id.id.as_str();
        let found = self.catalog.components.iter().find(|component| {
            component.package.as_deref() == Some(wanted) || component.id.as_deref() == Some(wanted)
        });
        Ok(found.and_then(|component| self.component_to_app(component)))
    }

    /// Case-insensitive substring search over the app-typed components
    /// (`desktop-application` + `console-application` only), in catalog
    /// order. An empty/whitespace query returns no hits.
    ///
    /// # Errors
    ///
    /// Never in wave 1 (the catalog is already in memory); kept
    /// `Result` for the [`Adapter`] contract.
    async fn search(&self, query: &str) -> Result<Vec<App>> {
        let needle = query.trim().to_lowercase();
        if needle.is_empty() {
            return Ok(Vec::new());
        }
        Ok(self
            .catalog
            .components
            .iter()
            .filter(|component| component_matches(component, &needle))
            .filter_map(|component| self.component_to_app(component))
            .collect())
    }
}

// ---------------------------------------------------------------------------
// Fetch half (thin client; `http` feature)
// ---------------------------------------------------------------------------

/// Descriptive User-Agent (DESIGN.md §3.2: `toride-registry/<source>/<version>`;
/// mirrors filter by UA, so descriptive is mandatory posture here too).
#[cfg(feature = "http")]
const USER_AGENT: &str = concat!("toride-registry/appstream/", env!("CARGO_PKG_VERSION"));

/// Debian mirror root (verified reachable: `dists/sid/main/dep11/
/// Components-amd64.yml.gz` → HTTP 200, DESIGN.md §0).
#[cfg(feature = "http")]
pub const DEBIAN_BASE_URL: &str = "https://deb.debian.org/debian";

/// Ubuntu archive root (verified reachable: `dists/noble/main/dep11/
/// Components-amd64.yml.gz` → HTTP 200, appstream.md §3).
#[cfg(feature = "http")]
pub const UBUNTU_BASE_URL: &str = "https://archive.ubuntu.com/ubuntu";

/// Build the DEP-11 catalog URL for one suite × component × arch — the
/// layout is identical across Debian and Ubuntu (verified live,
/// appstream.md §3):
/// `{base_url}/dists/{suite}/{component}/dep11/Components-{arch}.yml.gz`.
#[must_use]
pub fn catalog_url(base_url: &str, suite: &str, component: &str, arch: &str) -> String {
    format!("{base_url}/dists/{suite}/{component}/dep11/Components-{arch}.yml.gz")
}

/// Thin fetch client for the Debian/Ubuntu DEP-11 layout (DESIGN.md
/// §3.1). Streams the `.yml.gz` DOWNLOAD to the disk cache write-through
/// (buffered, one chunk at a time — the 8.7 MB sid/main archive is never
/// held in memory whole), then decompresses the cached file and returns
/// the ~27 MB YAML text for [`parse_dep11_catalog`] /
/// [`AppstreamAdapter::from_text`] ("never buffer whole" applies to the
/// download only, §3.1).
///
/// The cache is an mtime-keyed TTL cache plus conditional-GET
/// revalidation — the freshness policy this client's own doc once
/// deferred to a later wave, now decided (F14): a cached copy younger
/// than [`CATALOG_CACHE_TTL`] is decompressed from disk with **no
/// network at all**; a stale or missing copy is fetched *conditionally*
/// (`If-None-Match`/`If-Modified-Since`, from the server's
/// `ETag`/`Last-Modified` kept in a `<catalog>.validators` sidecar), so
/// an unchanged catalog costs a `304 Not Modified` header exchange
/// instead of the 8.7 MB re-download + 27 MB re-decompression. All
/// file-system and gzip work (probe, part-file open, finalize,
/// decompress) runs on [`tokio::task::spawn_blocking`]; only the
/// response chunk loop stays on the async task.
#[cfg(feature = "http")]
pub struct AppstreamClient {
    http: reqwest::Client,
    /// Directory under which the `appstream/` cache subtree is kept.
    cache_dir: camino::Utf8PathBuf,
}

/// How long a cached catalog is served with no network round-trip at all.
///
/// The freshness key is the cache file's **mtime** — probed by
/// [`AppstreamClient::fetch_catalog`], and restarted (touched) whenever a
/// conditional GET answers `304 Not Modified`. Conservative by design
/// against the ~daily republish cadence (appstream.md §3): six hours
/// bound the worst-case staleness inside a long-lived process, while a
/// hot process still performs at most four revalidations a day — each
/// usually a cheap `304` once the validators are cached.
#[cfg(feature = "http")]
pub const CATALOG_CACHE_TTL: Duration = Duration::from_hours(6);

#[cfg(feature = "http")]
impl AppstreamClient {
    /// A client caching catalogs under `cache_dir/appstream/`, with the
    /// house HTTP posture (descriptive UA — mandatory posture for
    /// mirrors that filter, redirects followed, overall + connect
    /// timeouts; DESIGN.md §3.2).
    pub fn new(cache_dir: impl Into<camino::Utf8PathBuf>) -> Self {
        Self {
            http: crate::http::build_http_client(USER_AGENT),
            cache_dir: cache_dir.into(),
        }
    }

    /// Fetch and decompress one catalog. `base_url` is
    /// [`DEBIAN_BASE_URL`] or [`UBUNTU_BASE_URL`]; the returned text is
    /// exactly what [`AppstreamAdapter::from_text`] consumes.
    ///
    /// Freshness ladder (F14): a cached copy within [`CATALOG_CACHE_TTL`]
    /// is decompressed from disk with zero network; a stale or missing
    /// copy is fetched — conditionally, with the cached `ETag`/
    /// `Last-Modified` validators — replacing the cached file atomically
    /// via rename. A `304 Not Modified` restarts the cache's TTL clock
    /// and again serves the cached bytes, unchanged.
    ///
    /// # Errors
    ///
    /// [`Error::Http`] for transport failures, non-success statuses, and
    /// cache/decompression I/O failures (the error enum's shared variants
    /// are fixed; I/O during fetch+cache is transport-adjacent, so it
    /// carries its detail in the `message` field).
    pub async fn fetch_catalog(
        &self,
        base_url: &str,
        suite: &str,
        component: &str,
        arch: &str,
    ) -> Result<String> {
        let url = catalog_url(base_url, suite, component, arch);
        let final_path = self.cache_path(suite, component, arch);
        let part_path = camino::Utf8PathBuf::from(format!("{final_path}.part"));
        // TTL probe off the async thread: one stat plus, on a hit, the
        // full gzip decompression of the cached copy (the fs+gzip block
        // must not run on an async worker — toride-apps' `save_manifest`
        // precedent).
        let probe_path = final_path.clone();
        let probe = tokio::task::spawn_blocking(move || {
            probe_cache(&probe_path, CATALOG_CACHE_TTL, SystemTime::now())
        })
        .await
        .map_err(|error| http_error(&url, "cache probe join", &error.to_string()))?;
        match probe {
            CacheProbe::Fresh(text) => Ok(text),
            CacheProbe::Stale {
                etag,
                last_modified,
            } => {
                let result = self
                    .download_and_decompress(
                        &url,
                        &part_path,
                        &final_path,
                        etag.as_deref(),
                        last_modified.as_deref(),
                    )
                    .await;
                if result.is_err() {
                    // Best-effort cleanup of the aborted write-through —
                    // off the async thread like every other fs step.
                    let cleanup = part_path.clone();
                    let _ =
                        tokio::task::spawn_blocking(move || std::fs::remove_file(cleanup)).await;
                }
                result
            }
        }
    }

    /// The decompressed cached catalog for one scope, when a copy exists —
    /// the offline/fixture seam over exactly the work a TTL-hit
    /// [`AppstreamClient::fetch_catalog`] performs. No freshness check
    /// and no network: `Ok(None)` means no cached copy exists yet.
    ///
    /// Synchronous by design — disk I/O plus the gzip inflate run on the
    /// caller's thread; `fetch_catalog` wraps the identical
    /// decompression step in `spawn_blocking` on its async path.
    ///
    /// # Errors
    ///
    /// [`Error::Http`] when a cached copy exists but cannot be read or
    /// decompressed (the `url` field carries the cache path — I/O during
    /// fetch+cache is transport-adjacent, so detail lives in `message`).
    pub fn cached_catalog(
        &self,
        suite: &str,
        component: &str,
        arch: &str,
    ) -> Result<Option<String>> {
        let path = self.cache_path(suite, component, arch);
        if !path.exists() {
            return Ok(None);
        }
        decompress_cached(&path)
            .map(Some)
            .map_err(|error| http_error(path.as_str(), "decompress", &error.to_string()))
    }

    /// Cache location for one catalog: `<cache_dir>/appstream/<suite>-
    /// <component>-Components-<arch>.yml.gz` (path segments sanitized).
    fn cache_path(&self, suite: &str, component: &str, arch: &str) -> camino::Utf8PathBuf {
        let sanitize = |segment: &str| segment.replace('/', "_");
        self.cache_dir.join(format!(
            "appstream/{}-{}-Components-{}.yml.gz",
            sanitize(suite),
            sanitize(component),
            sanitize(arch)
        ))
    }

    /// Revalidate, and if needed re-download, one catalog: a conditional
    /// GET with the cached validators, then either serve the revalidated
    /// cache (`304`) or stream the response into `part_path`
    /// (write-through, buffered), rename it over `final_path`, and
    /// decompress it. Every fs/gzip step outside the awaited chunk loop
    /// runs under `spawn_blocking`.
    async fn download_and_decompress(
        &self,
        url: &str,
        part_path: &camino::Utf8Path,
        final_path: &camino::Utf8Path,
        etag: Option<&str>,
        last_modified: Option<&str>,
    ) -> Result<String> {
        let mut request = self.http.get(url);
        for (name, value) in conditional_headers(etag, last_modified) {
            request = request.header(name, value);
        }
        let response = request
            .send()
            .await
            .map_err(|error| http_error(url, "send", &error.to_string()))?;
        if response.status() == reqwest::StatusCode::NOT_MODIFIED {
            // Revalidated: restart the cache's TTL clock and serve the
            // cached bytes — by definition of a 304 the validators
            // themselves are unchanged, so the sidecar stays as-is.
            let revalidated = final_path.to_owned();
            let url_owned = url.to_owned();
            return tokio::task::spawn_blocking(move || {
                refresh_mtime(&revalidated).map_err(|error| {
                    http_error(&url_owned, "refresh cache mtime", &error.to_string())
                })?;
                decompress_cached(&revalidated)
                    .map_err(|error| http_error(&url_owned, "decompress", &error.to_string()))
            })
            .await
            .map_err(|error| http_error(url, "revalidate join", &error.to_string()))?;
        }
        if !response.status().is_success() {
            return Err(http_error(url, "status", &response.status().to_string()));
        }
        let etag = response_header(&response, reqwest::header::ETAG);
        let last_modified = response_header(&response, reqwest::header::LAST_MODIFIED);
        // Open the part file off the async thread (mkdir -p + create are fs
        // work; the crate-family `spawn_blocking` convention — fs never on
        // an async worker).
        let open_path = part_path.to_owned();
        let part = tokio::task::spawn_blocking(move || {
            std::fs::create_dir_all(open_path.parent().unwrap_or(open_path.as_path()))
                .and_then(|()| std::fs::File::create(&open_path))
        })
        .await
        .map_err(|error| http_error(url, "open join", &error.to_string()))?
        .map_err(|error| http_error(url, "create cache file", &error.to_string()))?;
        let mut response = response;
        // BufWriter: the chunk loop must stay on the async task (it awaits
        // the stream), so its writes coalesce into buffer-sized syscalls.
        let mut part = std::io::BufWriter::new(part);
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|error| http_error(url, "read stream", &error.to_string()))?
        {
            part.write_all(chunk.as_ref())
                .map_err(|error| http_error(url, "write cache", &error.to_string()))?;
        }
        // Flush, finalize, and decompress: all blocking, all off the async
        // task in one blocking task (the crate-family `spawn_blocking`
        // precedent — fs+gzip must never run on an async worker).
        let finalized = final_path.to_owned();
        let part_final = part_path.to_owned();
        let url_owned = url.to_owned();
        tokio::task::spawn_blocking(move || {
            part.flush()
                .map_err(|error| http_error(&url_owned, "flush cache", &error.to_string()))?;
            drop(part);
            // Same-directory rename: atomic on the cache filesystem.
            std::fs::rename(&part_final, &finalized)
                .map_err(|error| http_error(&url_owned, "finalize cache", &error.to_string()))?;
            // Best-effort validators sidecar: a failed write only costs
            // the next stale fetch an unconditional GET (the pre-F14
            // behavior), never a failed catalog fetch.
            let _ = write_validators(&finalized, etag.as_deref(), last_modified.as_deref());
            decompress_cached(&finalized)
                .map_err(|error| http_error(&url_owned, "decompress", &error.to_string()))
        })
        .await
        .map_err(|error| http_error(url, "finalize join", &error.to_string()))?
    }
}

/// What the cache probe decided for one catalog path: serve the cached
/// bytes, or revalidate with the stored validators.
#[cfg(feature = "http")]
#[derive(Debug, Clone, PartialEq, Eq)]
enum CacheProbe {
    /// The cached copy is within [`CATALOG_CACHE_TTL`] and already fully
    /// decompressed — no network needed.
    Fresh(String),
    /// Missing, stale, or unreadable cache; these are the validators to
    /// send with the conditional GET (`None`/`None` = unconditional).
    Stale {
        /// Cached `ETag` validator, when one was stored.
        etag: Option<String>,
        /// Cached `Last-Modified` validator, when one was stored.
        last_modified: Option<String>,
    },
}

/// Probe one cached catalog — the mtime-keyed TTL decision (F14). The
/// file's modification time IS the freshness clock: younger than `ttl`
/// at `now` → the fully decompressed copy; older, missing, or
/// undecompressable → the stored validators for a conditional GET.
///
/// Infallible by design: a corrupt or unreadable cache degrades to a
/// miss with the validators dropped (forcing the full re-download that
/// replaces the bad file), never to an error that would brick fetches
/// for a whole TTL window.
#[cfg(feature = "http")]
fn probe_cache(path: &camino::Utf8Path, ttl: Duration, now: SystemTime) -> CacheProbe {
    let fresh = std::fs::metadata(path)
        .ok()
        .and_then(|metadata| metadata.modified().ok())
        .and_then(|mtime| now.duration_since(mtime).ok())
        .is_some_and(|age| age < ttl);
    if !fresh {
        let (etag, last_modified) = read_validators(path);
        return CacheProbe::Stale {
            etag,
            last_modified,
        };
    }
    match decompress_cached(path) {
        Ok(text) => CacheProbe::Fresh(text),
        // Corrupt cache: drop the validators too, so revalidation is a
        // full GET that overwrites the bad copy (a 304 would keep it).
        Err(_) => CacheProbe::Stale {
            etag: None,
            last_modified: None,
        },
    }
}

/// Decompress one cached `.yml.gz` catalog fully — the fs+gzip block
/// that must run under `spawn_blocking` on any async path. Returns the
/// raw I/O error; callers attach the fetch URL (or cache path, for the
/// offline seam) when mapping it.
#[cfg(feature = "http")]
fn decompress_cached(path: &camino::Utf8Path) -> std::io::Result<String> {
    let compressed = std::fs::File::open(path)?;
    let mut text = String::new();
    flate2::read::GzDecoder::new(compressed).read_to_string(&mut text)?;
    Ok(text)
}

/// The conditional-GET request headers for the cached validators:
/// `If-None-Match: <etag>` and `If-Modified-Since: <last-modified>`,
/// each emitted only when that validator was cached (`None` in → header
/// out). Values are verbatim echoes of what the server previously sent —
/// no date reformatting, so the validation round-trip stays exact.
#[cfg(feature = "http")]
#[must_use]
fn conditional_headers(
    etag: Option<&str>,
    last_modified: Option<&str>,
) -> Vec<(&'static str, String)> {
    let mut headers = Vec::new();
    if let Some(etag) = etag {
        headers.push((reqwest::header::IF_NONE_MATCH.as_str(), etag.to_owned()));
    }
    if let Some(last_modified) = last_modified {
        headers.push((
            reqwest::header::IF_MODIFIED_SINCE.as_str(),
            last_modified.to_owned(),
        ));
    }
    headers
}

/// One response header as an owned string, when present and UTF-8 —
/// validators are optional, so a missing or non-UTF-8 header is simply
/// `None`.
#[cfg(feature = "http")]
#[must_use]
fn response_header(
    response: &reqwest::Response,
    name: reqwest::header::HeaderName,
) -> Option<String> {
    response
        .headers()
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

/// The validators sidecar path for one cached catalog:
/// `<catalog>.validators`.
#[cfg(feature = "http")]
#[must_use]
fn validators_path(path: &camino::Utf8Path) -> camino::Utf8PathBuf {
    camino::Utf8PathBuf::from(format!("{path}.validators"))
}

/// Read the cached validators from the sidecar (line 1 = `ETag`, line 2 =
/// `Last-Modified`; an empty line = no validator). A missing or
/// malformed sidecar reads as `(None, None)` — the next stale fetch is
/// then an unconditional GET, exactly the pre-validator behavior (e.g. a
/// cache written by an older build).
#[cfg(feature = "http")]
#[must_use]
fn read_validators(path: &camino::Utf8Path) -> (Option<String>, Option<String>) {
    let Ok(text) = std::fs::read_to_string(validators_path(path)) else {
        return (None, None);
    };
    let mut lines = text.lines();
    let non_empty = |line: Option<&str>| line.filter(|line| !line.is_empty()).map(str::to_owned);
    (non_empty(lines.next()), non_empty(lines.next()))
}

/// Store the validators sidecar next to a finalized catalog.
#[cfg(feature = "http")]
fn write_validators(
    path: &camino::Utf8Path,
    etag: Option<&str>,
    last_modified: Option<&str>,
) -> std::io::Result<()> {
    std::fs::write(
        validators_path(path),
        format!("{}\n{}\n", etag.unwrap_or(""), last_modified.unwrap_or("")),
    )
}

/// Restart the TTL clock for a revalidated cache entry: the mtime IS the
/// freshness key, so a `304 Not Modified` (cache confirmed current)
/// touches it to now.
#[cfg(feature = "http")]
fn refresh_mtime(path: &camino::Utf8Path) -> std::io::Result<()> {
    std::fs::OpenOptions::new()
        .write(true)
        .open(path)?
        .set_modified(SystemTime::now())
}

/// [`Error::Http`] constructor for the client's transport-adjacent
/// failures.
#[cfg(feature = "http")]
fn http_error(url: &str, stage: &str, detail: &str) -> Error {
    Error::Http {
        url: url.to_owned(),
        message: format!("{stage}: {detail}"),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Synchronous search helper for the plain `#[test]` fns: the `Adapter`
/// methods are async per the house trait style, but every path here is
/// pure in-memory work, so a minimal current-thread runtime is enough.
#[cfg(test)]
fn block_on_search(adapter: &AppstreamAdapter, query: &str) -> Vec<App> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime")
        .block_on(async { adapter.search(query).await.expect("search ok") })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Synthetic DEP-11 excerpt exercising the wire edges the live-fetched
    /// fixture does not carry: a non-app `Type`, unquoted numeric scalars,
    /// an unknown spec field, stray empty documents, and the full
    /// `binaries` fallback chain. Kept inline (not in `fixtures/`) so every
    /// file under `tests/fixtures/appstream/` stays live-fetched or
    /// documented there.
    const SYNTHETIC_CATALOG: &str = "%YAML 1.2
---
File: DEP-11
Version: 0.14
Origin: debian-bookworm-contrib
---
Type: generic
ID: org.example.Library
Package: libexample0
Name:
  C: Example Library
---
Type: console-application
ID: rg.desktop
Package: ripgrep
Name:
  C: ripgrep
Provides:
  binaries:
  - rg
---
Type: desktop-application
ID: org.example.TwoThousandFortyEight
Package: 2048
Name:
  C: 2048
---
---

Type: desktop-application
ID: only-desktop-id.desktop
FutureField: ignored
Launchable:
  desktop-id:
  - only-desktop-id.desktop
";

    /// Live-fetched DEP-11 subset — the wave-1 fixture (DESIGN.md §7);
    /// verbatim header `Origin: debian-sid-main` + 3 real components.
    /// Loaded at runtime (conventions.md §7 — `env!("CARGO_MANIFEST_DIR")`
    /// anchor, deliberately not `include_str!`, like the sibling modules).
    fn fixture() -> String {
        let path = std::path::Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/appstream"
        ))
        .join("debian-sid-main-amd64.yml");
        std::fs::read_to_string(&path)
            .unwrap_or_else(|err| panic!("failed to read fixture `{}`: {err}", path.display()))
    }

    /// Adapter over the fixture, arch decoded from the fixture filename
    /// (the REVIEW addition's `platforms` path).
    fn fixture_adapter() -> AppstreamAdapter {
        AppstreamAdapter::from_text(&fixture(), decode_catalog_arch("debian-sid-main-amd64.yml"))
            .expect("fixture parses")
    }

    /// Adapter over the synthetic edge-case catalog.
    fn synthetic_adapter() -> AppstreamAdapter {
        AppstreamAdapter::from_text(SYNTHETIC_CATALOG, Some(Arch::X86_64))
            .expect("synthetic parses")
    }

    #[test]
    fn fixture_header_parses_verbatim() {
        let catalog = parse_dep11_catalog(&fixture()).expect("fixture parses");
        assert_eq!(catalog.header.file.as_deref(), Some("DEP-11"));
        assert_eq!(catalog.header.version.as_deref(), Some("1.0"));
        assert_eq!(catalog.header.origin.as_deref(), Some("debian-sid-main"));
        assert_eq!(
            catalog.header.media_base_url.as_deref(),
            Some("https://appstream.debian.org/media/sid")
        );
        assert_eq!(catalog.header.time.as_deref(), Some("2026-09-27T20:10:17Z"));
        assert_eq!(catalog.header.architecture, None);
        assert_eq!(catalog.components.len(), 3);
        assert_eq!(
            catalog.components[0].id.as_deref(),
            Some("firefox-esr.desktop")
        );
        assert_eq!(catalog.components[1].id.as_deref(), Some("firefox.desktop"));
        assert_eq!(
            catalog.components[2].id.as_deref(),
            Some("org.gnome.TextEditor")
        );
    }

    #[test]
    fn fixture_components_parse_with_defaults_and_c_locales() {
        let catalog = parse_dep11_catalog(&fixture()).expect("fixture parses");
        let firefox_esr = &catalog.components[0];
        assert_eq!(firefox_esr.type_.as_deref(), Some("desktop-application"));
        assert_eq!(firefox_esr.package.as_deref(), Some("firefox-esr"));
        assert_eq!(
            firefox_esr.name.get(C_LOCALE).map(String::as_str),
            Some("Firefox ESR")
        );
        assert_eq!(
            firefox_esr.name.get("fr").map(String::as_str),
            Some("Firefox ESR")
        );
        assert_eq!(
            firefox_esr.summary.get(C_LOCALE).map(String::as_str),
            Some("Browse the World Wide Web")
        );
        // `ProjectLicense` / `Developer` / `Releases` are optional (fixture
        // firefox-esr carries none of them).
        assert_eq!(firefox_esr.project_license, None);
        assert_eq!(firefox_esr.developer, None);
        assert!(firefox_esr.releases.is_empty());
        // `Provides` carries only mediatypes here — the documented zero
        // `binaries` coverage of the fixture (DESIGN.md §4.4 note).
        let provides = firefox_esr.provides.as_ref().expect("mediatypes present");
        assert!(provides.binaries.is_empty());
        assert_eq!(provides.mediatypes.len(), 12);
        assert!(
            provides
                .mediatypes
                .contains(&"x-scheme-handler/https".to_owned())
        );
        assert_eq!(
            firefox_esr
                .launchable
                .as_ref()
                .map(|launchable| &launchable.desktop_id),
            Some(&vec!["firefox-esr.desktop".to_owned()])
        );
        assert_eq!(firefox_esr.categories, ["Network", "WebBrowser"]);
        // org.gnome.TextEditor: modern reverse-DNS ID, license, releases.
        let text_editor = &catalog.components[2];
        assert_eq!(text_editor.package.as_deref(), Some("gnome-text-editor"));
        assert_eq!(
            text_editor.project_license.as_deref(),
            Some("GPL-3.0-or-later")
        );
        let release = &text_editor.releases[0];
        assert_eq!(release.version.as_deref(), Some("51.0"));
        assert_eq!(release.type_.as_deref(), Some("development"));
        assert_eq!(release.unix_timestamp, Some(1_789_344_000));
    }

    #[test]
    fn developer_prefers_name_c_over_id() {
        // Review addition: `Developer.name.C`, falling back to `Developer.id`.
        let adapter = fixture_adapter();
        let apps = block_on_search(&adapter, "gnome-text-editor");
        assert_eq!(apps.len(), 1);
        assert_eq!(apps[0].developer.as_deref(), Some("The GNOME Project"));
    }

    #[test]
    fn description_html_is_stripped() {
        let adapter = fixture_adapter();
        let apps = block_on_search(&adapter, "Firefox ESR");
        let firefox_esr = apps
            .iter()
            .find(|app| app.id.as_str() == "firefox-esr")
            .expect("firefox-esr found");
        assert_eq!(
            firefox_esr.description.as_deref(),
            Some(
                "Firefox ESR is a powerful, extensible web browser with support \
                 for modern web application technologies."
            )
        );
    }

    #[test]
    fn fixture_component_emits_distro_app_scoped_by_origin() {
        let adapter = fixture_adapter();
        let apps = block_on_search(&adapter, "Firefox ESR");
        let firefox_esr = apps
            .iter()
            .find(|app| app.id.as_str() == "firefox-esr")
            .expect("firefox-esr found");
        assert_eq!(firefox_esr.name, "Firefox ESR");
        assert_eq!(
            firefox_esr.summary.as_deref(),
            Some("Browse the World Wide Web")
        );
        assert_eq!(
            firefox_esr.homepage, None,
            "Url is deliberately unmapped in wave 1"
        );
        assert_eq!(firefox_esr.license, None);
        assert_eq!(
            firefox_esr.binaries,
            ["firefox-esr"],
            "Package fallback chain"
        );
        assert_eq!(firefox_esr.latest, None, "firefox-esr carries no Releases");
        assert_eq!(
            firefox_esr.platforms,
            [Platform {
                os: Os::Linux,
                arch: Some(Arch::X86_64),
                min_release: None
            }]
        );
        assert!(
            firefox_esr.artifacts.is_empty(),
            "DEP-11 publishes no checksums"
        );
        assert_eq!(
            firefox_esr.install,
            InstallMethod::Distro {
                family: DistroFamily::Debian,
                repo: Some("debian-sid-main".to_owned()),
                package: "firefox-esr".to_owned(),
            }
        );
        // Identity rows: `{Distro, package}` first, plus `{Distro, ID}`
        // because `firefox-esr.desktop` differs.
        assert_eq!(firefox_esr.sources.len(), 2);
        assert_eq!(firefox_esr.sources[0].id, "firefox-esr");
        assert_eq!(firefox_esr.sources[0].source, SourceKind::Distro);
        assert_eq!(
            firefox_esr.sources[0].repo.as_deref(),
            Some("debian-sid-main")
        );
        assert!(!firefox_esr.sources[0].provisional);
        assert_eq!(firefox_esr.sources[1].id, "firefox-esr.desktop");
        assert_eq!(firefox_esr.availability, Availability::Available);
    }

    #[test]
    fn releases_emit_latest_version_and_timestamp() {
        let adapter = fixture_adapter();
        let apps = block_on_search(&adapter, "Text Editor");
        let text_editor = apps
            .iter()
            .find(|app| app.id.as_str() == "gnome-text-editor")
            .expect("text editor found");
        assert_eq!(
            text_editor.latest,
            Some(Version {
                value: "51.0".to_owned(),
                original: None,
                published_unix: Some(1_789_344_000)
            })
        );
        assert_eq!(text_editor.binaries, ["gnome-text-editor"]);
    }

    #[tokio::test]
    async fn lookup_by_package_row_and_by_id_row() {
        let adapter = fixture_adapter();
        let by_package = SourceRef {
            source: SourceKind::Distro,
            id: "firefox-esr".to_owned(),
            repo: Some("debian-sid-main".to_owned()),
            version: None,
            provisional: false,
        };
        assert!(
            adapter
                .lookup(&by_package)
                .await
                .expect("lookup ok")
                .is_some()
        );
        // The second identity row style: the component ID.
        let by_id = SourceRef {
            id: "firefox-esr.desktop".to_owned(),
            ..by_package.clone()
        };
        assert!(adapter.lookup(&by_id).await.expect("lookup ok").is_some());
        // A row scoped to another repo cannot be in this catalog.
        let other_repo = SourceRef {
            repo: Some("ubuntu-noble-main".to_owned()),
            ..by_package.clone()
        };
        assert_eq!(adapter.lookup(&other_repo).await.expect("lookup ok"), None);
        // Unknown package → Ok(None).
        let unknown = SourceRef {
            id: "not-a-debian-package".to_owned(),
            repo: None,
            ..by_package
        };
        assert_eq!(adapter.lookup(&unknown).await.expect("lookup ok"), None);
    }

    #[tokio::test]
    async fn lookup_rejects_foreign_source_rows() {
        let adapter = fixture_adapter();
        let flathub_row = SourceRef {
            source: SourceKind::Flathub,
            id: "com.brave.Browser".to_owned(),
            repo: None,
            version: None,
            provisional: false,
        };
        assert!(matches!(
            adapter.lookup(&flathub_row).await,
            Err(Error::UnsupportedSource {
                kind: SourceKind::Flathub,
                ..
            })
        ));
    }

    #[tokio::test]
    async fn search_matches_names_summaries_and_filters_types() {
        let adapter = fixture_adapter();
        // Name hit ("Text Editor" ⊂ name C) finds exactly the GNOME app.
        let hits = adapter.search("text editor").await.expect("search ok");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].id.as_str(), "gnome-text-editor");
        // Package hit finds the ESR build; both firefox components share
        // the summary, so a summary hit finds both.
        assert_eq!(
            adapter
                .search("firefox-esr")
                .await
                .expect("search ok")
                .len(),
            1
        );
        assert_eq!(
            adapter
                .search("browse the world")
                .await
                .expect("search ok")
                .len(),
            2
        );
        // No hit → empty; empty query → empty.
        assert!(
            adapter
                .search("zzz-no-such-app")
                .await
                .expect("search ok")
                .is_empty()
        );
        assert!(adapter.search("   ").await.expect("search ok").is_empty());
    }

    #[test]
    fn synthetic_catalog_skips_empty_documents_and_filters_types() {
        let adapter = synthetic_adapter();
        // Header + 4 real component documents; the stray empty document
        // between the `---` markers is skipped.
        assert_eq!(adapter.catalog().components.len(), 4);
        // `Type: generic` is filtered out of the app surface...
        assert!(block_on_search(&adapter, "Example Library").is_empty());
        // ...while console-application passes the filter.
        let hits = block_on_search(&adapter, "ripgrep");
        assert_eq!(hits.len(), 1);
        assert_eq!(
            hits[0].install,
            InstallMethod::Distro {
                family: DistroFamily::Debian,
                repo: Some("debian-bookworm-contrib".to_owned()),
                package: "ripgrep".to_owned(),
            }
        );
    }

    #[test]
    fn binaries_fall_back_to_package_then_id_basename() {
        let adapter = synthetic_adapter();
        let by_binaries = block_on_search(&adapter, "ripgrep");
        assert_eq!(by_binaries[0].binaries, ["rg"], "Provides.binaries wins");
        let by_package = block_on_search(&adapter, "2048");
        assert_eq!(by_package.len(), 1);
        assert_eq!(by_package[0].binaries, ["2048"], "Package fallback");
        let by_id = block_on_search(&adapter, "only-desktop-id");
        assert_eq!(by_id.len(), 1);
        assert_eq!(
            by_id[0].binaries,
            ["only-desktop-id"],
            "desktop-id/ID basename fallback (`.desktop` stripped)"
        );
    }

    #[test]
    fn numeric_looking_scalars_survive_as_text() {
        let adapter = synthetic_adapter();
        // Header `Version: 0.14` unquoted (a float on the wire) and the
        // component named/packaged `2048` (an integer on the wire) must
        // degrade to text, never fail the catalog.
        assert_eq!(adapter.catalog().header.version.as_deref(), Some("0.14"));
        let apps = block_on_search(&adapter, "2048");
        assert_eq!(apps.len(), 1);
        assert_eq!(apps[0].name, "2048");
        assert_eq!(
            apps[0].install,
            InstallMethod::Distro {
                family: DistroFamily::Debian,
                repo: Some("debian-bookworm-contrib".to_owned()),
                package: "2048".to_owned(),
            }
        );
        assert_eq!(apps[0].id.as_str(), "2048");
    }

    #[test]
    fn malformed_payload_is_a_parse_error() {
        let error = parse_dep11_catalog("this: [unclosed").expect_err("malformed");
        assert!(matches!(error, Error::Parse { kind: "yaml", .. }));
        assert!(parse_dep11_catalog("").is_err(), "no header document");
        assert!(
            parse_dep11_catalog("---\n---\n").is_err(),
            "only empty documents"
        );
    }

    #[test]
    fn catalog_arch_decodes_from_filename() {
        assert_eq!(
            decode_catalog_arch("Components-amd64.yml.gz"),
            Some(Arch::X86_64)
        );
        assert_eq!(
            decode_catalog_arch("Components-arm64.yml.gz"),
            Some(Arch::Aarch64)
        );
        assert_eq!(
            decode_catalog_arch("Components-i386.yml.gz"),
            Some(Arch::X86)
        );
        assert_eq!(
            decode_catalog_arch(
                "https://deb.debian.org/debian/dists/sid/main/dep11/Components-amd64.yml.gz"
            ),
            Some(Arch::X86_64),
            "works on full URLs"
        );
        // Fixture-style name (the REVIEW addition's example).
        assert_eq!(
            decode_catalog_arch("debian-sid-main-amd64.yml"),
            Some(Arch::X86_64)
        );
        // No decodable arch → unknown.
        assert_eq!(decode_catalog_arch("Components-riscv64.yml.gz"), None);
        assert_eq!(decode_catalog_arch("catalog.yml"), None);
    }

    #[test]
    fn undecodable_arch_yields_unknown_platforms() {
        let adapter = AppstreamAdapter::from_text(&fixture(), None).expect("fixture parses");
        let apps = block_on_search(&adapter, "Firefox");
        assert!(!apps.is_empty());
        for app in apps {
            assert!(app.platforms.is_empty(), "no arch → platforms [] = unknown");
        }
    }

    #[test]
    fn family_decodes_from_origin() {
        // Verified live this session: deb.debian.org sid/main →
        // `Origin: debian-sid-main`; archive.ubuntu.com noble/main →
        // `Origin: ubuntu-noble-main`.
        assert_eq!(decode_family(Some("debian-sid-main")), DistroFamily::Debian);
        assert_eq!(
            decode_family(Some("ubuntu-noble-main")),
            DistroFamily::Ubuntu
        );
        assert_eq!(
            decode_family(Some("archive-jammy-main")),
            DistroFamily::Ubuntu
        );
        // Documented default: DEP-11 YAML is a Debian-family format.
        assert_eq!(decode_family(Some("mystery-os-main")), DistroFamily::Debian);
        assert_eq!(decode_family(None), DistroFamily::Debian);
    }

    #[test]
    fn catalog_url_matches_the_dep11_layout() {
        assert_eq!(
            catalog_url("https://deb.debian.org/debian", "sid", "main", "amd64"),
            "https://deb.debian.org/debian/dists/sid/main/dep11/Components-amd64.yml.gz"
        );
        assert_eq!(
            catalog_url(
                "https://archive.ubuntu.com/ubuntu",
                "noble",
                "main",
                "amd64"
            ),
            "https://archive.ubuntu.com/ubuntu/dists/noble/main/dep11/Components-amd64.yml.gz"
        );
    }
}

/// Client-layer unit tests (compile- and run-offline; only the gated
/// feature is exercised, never the network). The F14 freshness rig lives
/// here: the mtime-keyed TTL probe, the validators sidecar, the
/// conditional-GET headers, and cached-vs-fresh parity at the offline
/// seam.
#[cfg(all(test, feature = "http"))]
mod client_tests {
    use super::*;

    /// Tiny DEP-11 excerpt for the cache probes (header + one component;
    /// the parse-half wire edges are pinned by `tests` above).
    const PROBE_CATALOG: &str = "%YAML 1.2
---
File: DEP-11
Origin: debian-sid-main
---
Type: console-application
ID: rg.desktop
Package: ripgrep
Name:
  C: ripgrep
";

    /// One `If-None-Match`/`If-Modified-Since` validator pair used across
    /// the probes.
    const ETAG: &str = "\"dep11-v1\"";
    const LAST_MODIFIED: &str = "Wed, 01 Jan 2026 00:00:00 GMT";

    /// Unique scratch dir for one test (the `network_tests` temp-dir
    /// precedent, plus best-effort cleanup so reruns start empty).
    fn scratch(name: &str) -> camino::Utf8PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "toride-registry-appstream-client-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch dir creatable");
        camino::Utf8PathBuf::from_path_buf(dir).expect("temp path is UTF-8")
    }

    /// Gzip `text` into `path` — exactly the bytes a fresh download
    /// leaves behind in the cache (parent dirs created, as a fetch would).
    fn seed_gz(path: &camino::Utf8Path, text: &str) {
        std::fs::create_dir_all(path.parent().unwrap_or(path)).expect("seed dir creatable");
        let file = std::fs::File::create(path).expect("seed file creatable");
        let mut encoder = flate2::write::GzEncoder::new(file, flate2::Compression::default());
        encoder
            .write_all(text.as_bytes())
            .expect("seed content writable");
        encoder.finish().expect("seed gzip finishable");
    }

    /// Pin a file's mtime to an explicit instant (the TTL's clock).
    fn set_mtime(path: &camino::Utf8Path, at: SystemTime) {
        std::fs::OpenOptions::new()
            .write(true)
            .open(path)
            .expect("open for mtime")
            .set_modified(at)
            .expect("set mtime");
    }

    #[test]
    fn cache_path_is_layout_shaped() {
        let client = AppstreamClient::new("/var/cache/toride");
        assert_eq!(
            client.cache_path("sid", "main", "amd64").as_str(),
            "/var/cache/toride/appstream/sid-main-Components-amd64.yml.gz"
        );
        // Path segments from callers are sanitized.
        assert_eq!(
            client.cache_path("si/d", "ma/in", "amd64").as_str(),
            "/var/cache/toride/appstream/si_d-ma_in-Components-amd64.yml.gz"
        );
    }

    #[test]
    fn cache_probe_is_mtime_keyed() {
        let dir = scratch("probe");
        let path = dir.join("sid-main-Components-amd64.yml.gz");
        // Missing cache: an unconditional revalidation.
        assert_eq!(
            probe_cache(&path, CATALOG_CACHE_TTL, SystemTime::now()),
            CacheProbe::Stale {
                etag: None,
                last_modified: None
            }
        );
        seed_gz(&path, PROBE_CATALOG);
        write_validators(&path, Some(ETAG), Some(LAST_MODIFIED)).expect("sidecar writable");
        // A fixed mtime makes the TTL boundary deterministic.
        let mtime = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        set_mtime(&path, mtime);
        // One second inside the window: the fresh hit carries the fully
        // decompressed copy — the zero-network serving path.
        assert_eq!(
            probe_cache(
                &path,
                CATALOG_CACHE_TTL,
                mtime + CATALOG_CACHE_TTL - Duration::from_secs(1)
            ),
            CacheProbe::Fresh(PROBE_CATALOG.to_owned())
        );
        // At the boundary and beyond: stale, with the sidecar validators
        // for the conditional GET.
        assert_eq!(
            probe_cache(&path, CATALOG_CACHE_TTL, mtime + CATALOG_CACHE_TTL),
            CacheProbe::Stale {
                etag: Some(ETAG.to_owned()),
                last_modified: Some(LAST_MODIFIED.to_owned())
            }
        );
    }

    #[test]
    fn corrupt_cache_degrades_to_an_unconditional_miss() {
        let dir = scratch("corrupt");
        let path = dir.join("sid-main-Components-amd64.yml.gz");
        std::fs::write(&path, b"not gzip").expect("garbage seedable");
        write_validators(&path, Some(ETAG), None).expect("sidecar writable");
        // A fresh-but-undecompressable cache must neither error (bricking
        // fetches for a whole TTL window) nor send validators that could
        // 304 and keep the bad copy: it forces the full re-download.
        assert_eq!(
            probe_cache(&path, CATALOG_CACHE_TTL, SystemTime::now()),
            CacheProbe::Stale {
                etag: None,
                last_modified: None
            }
        );
    }

    #[test]
    fn validators_sidecar_round_trips() {
        let dir = scratch("validators");
        let path = dir.join("sid-main-Components-amd64.yml.gz");
        std::fs::write(&path, b"gz").expect("cache file seedable");
        // No sidecar (a cache from the pre-validator build): none.
        assert_eq!(read_validators(&path), (None, None));
        write_validators(&path, Some(ETAG), Some(LAST_MODIFIED)).expect("sidecar writable");
        assert_eq!(
            read_validators(&path),
            (Some(ETAG.to_owned()), Some(LAST_MODIFIED.to_owned()))
        );
        // Either validator alone survives the two-line format.
        write_validators(&path, None, Some(LAST_MODIFIED)).expect("sidecar rewritable");
        assert_eq!(
            read_validators(&path),
            (None, Some(LAST_MODIFIED.to_owned()))
        );
        write_validators(&path, Some(ETAG), None).expect("sidecar rewritable");
        assert_eq!(read_validators(&path), (Some(ETAG.to_owned()), None));
        // Both absent: empty lines read back as no validators.
        write_validators(&path, None, None).expect("sidecar rewritable");
        assert_eq!(read_validators(&path), (None, None));
    }

    #[test]
    fn conditional_headers_mirror_cached_validators() {
        assert_eq!(
            conditional_headers(Some(ETAG), Some(LAST_MODIFIED)),
            vec![
                ("if-none-match", ETAG.to_owned()),
                ("if-modified-since", LAST_MODIFIED.to_owned()),
            ]
        );
        assert_eq!(
            conditional_headers(Some(ETAG), None),
            vec![("if-none-match", ETAG.to_owned())]
        );
        assert_eq!(
            conditional_headers(None, Some(LAST_MODIFIED)),
            vec![("if-modified-since", LAST_MODIFIED.to_owned())]
        );
        // No cached validators: an unconditional GET, exactly the
        // pre-F14 request shape.
        assert!(conditional_headers(None, None).is_empty());
    }

    #[test]
    fn cached_catalog_serves_the_seeded_copy_with_parse_parity() {
        let client = AppstreamClient::new(scratch("cached-catalog"));
        // Nothing cached for the scope yet: an honest None, not an error.
        assert_eq!(
            client
                .cached_catalog("sid", "main", "amd64")
                .expect("uncached scope reads clean"),
            None
        );
        // Seed exactly what a fresh download leaves behind...
        seed_gz(&client.cache_path("sid", "main", "amd64"), PROBE_CATALOG);
        let cached = client
            .cached_catalog("sid", "main", "amd64")
            .expect("cached copy decompresses")
            .expect("cached copy exists");
        // ...then the cached read must be byte-identical to the source and
        // normalize identically (cached-vs-fresh parity, the F14 oracle:
        // a TTL hit may never diverge from what a fresh fetch parses).
        assert_eq!(cached, PROBE_CATALOG);
        let from_cache =
            AppstreamAdapter::from_text(&cached, Some(Arch::X86_64)).expect("cached text parses");
        let from_source = AppstreamAdapter::from_text(PROBE_CATALOG, Some(Arch::X86_64))
            .expect("source text parses");
        assert_eq!(from_cache, from_source);
    }

    #[test]
    fn refresh_mtime_restarts_the_ttl_clock() {
        let dir = scratch("refresh");
        let path = dir.join("sid-main-Components-amd64.yml.gz");
        seed_gz(&path, PROBE_CATALOG);
        let ancient = SystemTime::UNIX_EPOCH + Duration::from_secs(60);
        set_mtime(&path, ancient);
        assert!(
            matches!(
                probe_cache(&path, CATALOG_CACHE_TTL, SystemTime::now()),
                CacheProbe::Stale { .. }
            ),
            "an aged-out cache revalidates"
        );
        // The 304 arm's touch: the same cache is fresh again.
        refresh_mtime(&path).expect("mtime refreshable");
        assert_eq!(
            probe_cache(&path, CATALOG_CACHE_TTL, SystemTime::now()),
            CacheProbe::Fresh(PROBE_CATALOG.to_owned())
        );
    }
}

/// Live-network coverage, gated exactly like toride-installer's
/// integration suite (conventions.md §7). Run with:
/// `TORIDE_REGISTRY_INTEGRATION=1 cargo test -p toride-registry --lib appstream`.
///
/// Asserts the DESIGN.md §3.1 compared-invariant set — same fields
/// populated, same install-method variant with its identifying payload,
/// same `SourceRef` set — never field-for-field equality: DEP-11
/// catalogs republish ~daily (appstream.md §3).
#[cfg(all(test, feature = "http"))]
mod network_tests {
    use super::*;

    /// Skip-by-default gate (conventions.md §7 pattern).
    fn integration_enabled() -> bool {
        matches!(
            std::env::var("TORIDE_REGISTRY_INTEGRATION").as_deref(),
            Ok("1")
        )
    }

    #[tokio::test]
    async fn live_catalog_matches_fetch_invariants() {
        if !integration_enabled() {
            eprintln!("skipping live DEP-11 fetch: set TORIDE_REGISTRY_INTEGRATION=1 to run");
            return;
        }
        // Per-run scratch dir: every invocation starts with an empty cache
        // so the first fetch below exercises the true full-download path.
        let cache_dir = camino::Utf8PathBuf::from(
            std::env::temp_dir()
                .join(format!("toride-registry-appstream-{}", std::process::id()))
                .to_string_lossy()
                .into_owned(),
        );
        let _ = std::fs::remove_dir_all(&cache_dir);
        let client = AppstreamClient::new(&cache_dir);
        let text = client
            .fetch_catalog(DEBIAN_BASE_URL, "sid", "main", "amd64")
            .await
            .expect("live sid/main catalog fetch");
        // F14 freshness parity, live: an immediate second fetch is a
        // TTL hit (mtime-keyed, no network) and must be byte-identical.
        let ttl_hit = client
            .fetch_catalog(DEBIAN_BASE_URL, "sid", "main", "amd64")
            .await
            .expect("ttl-hit catalog serve");
        assert_eq!(
            ttl_hit, text,
            "a TTL hit must serve the cached bytes verbatim"
        );
        // Aging the cache past the TTL forces the conditional GET — 304
        // or 200, the served text must still match what was fetched.
        let cached_path = client.cache_path("sid", "main", "amd64");
        std::fs::OpenOptions::new()
            .write(true)
            .open(&cached_path)
            .expect("cache file openable")
            .set_modified(std::time::SystemTime::UNIX_EPOCH)
            .expect("cache mtime agable");
        let revalidated = client
            .fetch_catalog(DEBIAN_BASE_URL, "sid", "main", "amd64")
            .await
            .expect("revalidated catalog fetch");
        assert_eq!(
            revalidated, text,
            "a conditional-GET fetch (304 or 200) must serve the same catalog"
        );
        let adapter =
            AppstreamAdapter::from_text(&text, decode_catalog_arch("Components-amd64.yml.gz"))
                .expect("live catalog parses");
        // Invariant: header populated, Origin names the Debian repo scope.
        assert_eq!(adapter.catalog().header.file.as_deref(), Some("DEP-11"));
        let origin = adapter
            .catalog()
            .header
            .origin
            .as_deref()
            .expect("live Origin");
        assert!(origin.starts_with("debian"), "unexpected Origin: {origin}");
        // Invariants: every hit keeps the Distro install variant with its
        // identifying payload, the (Linux, amd64) claim, and Distro-scoped
        // identity rows.
        let hits = adapter.search("firefox").await.expect("search ok");
        assert!(!hits.is_empty(), "firefox should exist in sid/main");
        for app in hits {
            let InstallMethod::Distro {
                family,
                repo,
                package,
            } = &app.install
            else {
                panic!("expected a Distro install method, got {:?}", app.install);
            };
            assert_eq!(family, &DistroFamily::Debian);
            assert_eq!(repo.as_deref(), Some(origin));
            assert!(!package.is_empty());
            assert_eq!(
                app.platforms,
                [Platform {
                    os: Os::Linux,
                    arch: Some(Arch::X86_64),
                    min_release: None
                }]
            );
            assert!(
                app.sources.iter().all(|row| {
                    row.source == SourceKind::Distro && row.repo.as_deref() == Some(origin)
                }),
                "identity rows must be Distro-scoped by the fetched Origin"
            );
        }
    }
}
