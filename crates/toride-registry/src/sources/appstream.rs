//! `AppStream` / DEP-11 adapter — normalizes Debian/Ubuntu distro catalogs
//! into [`App`]s.
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
//! assert_eq!(decode_catalog_arch("Components-amd64.yml.gz"), Some(toride_registry::Arch::X86_64));
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

/// A DEP-11 localized text field: locale → text; the `C` key is the
/// mandatory default locale, and numeric-looking scalars coerce to text.
pub type LocaleMap = HashMap<String, String>;

const C_LOCALE: &str = "C";

const APP_COMPONENT_TYPES: [&str; 2] = ["desktop-application", "console-application"];

/// One DEP-11 catalog: the stream's header document plus one entry per
/// component document, in catalog order.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Dep11Catalog {
    /// The first YAML document — the catalog header.
    pub header: Dep11Header,
    /// One entry per component document, in catalog order.
    pub components: Vec<Dep11Component>,
}

/// The DEP-11 header document (the stream's first); every field is
/// optional on the wire.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Dep11Header {
    /// `File: DEP-11` — format marker.
    #[serde(rename = "File", default)]
    pub file: Option<String>,
    /// `Version` — spec version targeted; a bare number on the wire is
    /// tolerated (coerced to text).
    #[serde(rename = "Version", default, deserialize_with = "de_opt_text")]
    pub version: Option<String>,
    /// `Origin` — repo identity; scopes the emitted `Distro` install rows.
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

/// One DEP-11 component document; every field is optional and unknown
/// fields are ignored.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Dep11Component {
    /// `Type` — only `desktop-application` and `console-application`
    /// components become [`App`]s.
    #[serde(rename = "Type", default)]
    pub type_: Option<String>,
    /// `ID` — component id; legacy `.desktop`-suffixed and reverse-DNS
    /// styles coexist.
    #[serde(rename = "ID", default)]
    pub id: Option<String>,
    /// `Package` — the distro package name `apt` knows; a bare number on
    /// the wire is tolerated.
    #[serde(rename = "Package", default, deserialize_with = "de_opt_text")]
    pub package: Option<String>,
    /// `Name` — localized display name, `C` mandatory.
    #[serde(rename = "Name", default, deserialize_with = "de_locale_map")]
    pub name: LocaleMap,
    /// `Summary` — localized one-liner, `C` mandatory.
    #[serde(rename = "Summary", default, deserialize_with = "de_locale_map")]
    pub summary: LocaleMap,
    /// `Description` — localized HTML; stripped to plain text at emission.
    #[serde(rename = "Description", default, deserialize_with = "de_locale_map")]
    pub description: LocaleMap,
    /// `ProjectLicense` — SPDX expression (`GPL-3.0-or-later`).
    #[serde(rename = "ProjectLicense", default)]
    pub project_license: Option<String>,
    /// `Developer` — `{id, name:{locales}}`; optional.
    #[serde(rename = "Developer", default)]
    pub developer: Option<Dep11Developer>,
    /// `Releases` — newest first per spec; often absent.
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

/// One published release.
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

/// `Provides` dict — only `binaries` and `mediatypes` are modeled; the
/// other spec keys are ignored.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Dep11Provides {
    /// `binaries` — executables the package installs on PATH; the
    /// tool-detection join key.
    #[serde(default)]
    pub binaries: Vec<String>,
    /// `mediatypes` — MIME/scheme handlers; not mapped to [`App`].
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

fn yaml_scalar_as_text(value: &serde_yaml::Value) -> Option<String> {
    match value {
        serde_yaml::Value::String(text) => Some(text.clone()),
        serde_yaml::Value::Number(number) => Some(number.to_string()),
        serde_yaml::Value::Bool(flag) => Some(flag.to_string()),
        _ => None,
    }
}

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

/// Parse a DEP-11 multi-document YAML stream into its header and
/// components, skipping stray empty documents; order is preserved.
///
/// # Errors
///
/// [`Error::Parse`] (kind `yaml`) on unparseable YAML or no documents;
/// unknown fields never error.
pub fn parse_dep11_catalog(payload: &str) -> Result<Dep11Catalog> {
    let mut header = Dep11Header::default();
    let mut components = Vec::new();
    let mut saw_header = false;
    for document in serde_yaml::Deserializer::from_str(payload) {
        if saw_header {
            match Option::<Dep11Component>::deserialize(document) {
                Ok(Some(component)) => components.push(component),
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
    let decoded = tagged_free
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&nbsp;", " ")
        .replace("&amp;", "&");
    decoded.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Decode the [`Arch`] from a DEP-11 catalog filename or URL — the YAML
/// names no arch. `None` → emitted Apps carry `platforms = []`.
#[must_use]
pub fn decode_catalog_arch(filename_or_url: &str) -> Option<Arch> {
    let filename = filename_or_url.rsplit('/').next().unwrap_or_default();
    let stem = filename.split('.').next().unwrap_or_default();
    let token = match stem.strip_prefix("Components-") {
        Some(rest) => rest,
        None => stem.rsplit('-').next().unwrap_or_default(),
    };
    match token {
        "amd64" | "x86_64" | "x86-64" => Some(Arch::X86_64),
        "arm64" | "aarch64" => Some(Arch::Aarch64),
        "i386" | "x86" => Some(Arch::X86),
        _ => None,
    }
}

const UBUNTU_CODENAMES: [&str; 6] = ["noble", "questing", "jammy", "focal", "bionic", "plucky"];

/// Decode the [`DistroFamily`] from the header `Origin` (`debian*` →
/// Debian, `ubuntu*`/codename → Ubuntu); undecodable/missing → Debian.
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

/// The `AppStream`/DEP-11 [`Adapter`]: one parsed catalog plus the scope
/// decoded from its fetch (header `Origin`, filename arch).
#[derive(Debug, Clone, PartialEq)]
pub struct AppstreamAdapter {
    catalog: Dep11Catalog,
    family: DistroFamily,
    repo: Option<String>,
    arch: Option<Arch>,
}

impl AppstreamAdapter {
    /// Build an adapter over an already-parsed catalog; `arch` is what
    /// [`decode_catalog_arch`] extracted from the catalog's filename.
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

    fn component_to_app(&self, component: &Dep11Component) -> Option<App> {
        if !is_app_component(component) {
            return None;
        }
        let without_desktop_suffix =
            |id: &str| id.strip_suffix(".desktop").unwrap_or(id).to_owned();
        let component_id = component.id.clone();
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
            availability: Availability::Available,
        })
    }

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

fn is_app_component(component: &Dep11Component) -> bool {
    component
        .type_
        .as_deref()
        .is_some_and(|type_| APP_COMPONENT_TYPES.contains(&type_))
}

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

    /// Look up one app by package name or component ID; a row scoped to
    /// a different repo is simply not here (`Ok(None)`).
    ///
    /// # Errors
    ///
    /// [`Error::UnsupportedSource`] when the row names a non-`Distro`
    /// source.
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

    /// Case-insensitive substring search over app-typed components in
    /// catalog order; an empty/whitespace query returns no hits.
    ///
    /// # Errors
    ///
    /// Never — the catalog is already in memory; `Result` per the
    /// [`Adapter`] contract.
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

#[cfg(feature = "http")]
const USER_AGENT: &str = concat!("toride-registry/appstream/", env!("CARGO_PKG_VERSION"));

/// Debian mirror root.
#[cfg(feature = "http")]
pub const DEBIAN_BASE_URL: &str = "https://deb.debian.org/debian";

/// Ubuntu archive root.
#[cfg(feature = "http")]
pub const UBUNTU_BASE_URL: &str = "https://archive.ubuntu.com/ubuntu";

/// Build the DEP-11 catalog URL for one suite × component × arch:
/// `{base_url}/dists/{suite}/{component}/dep11/Components-{arch}.yml.gz`.
#[must_use]
pub fn catalog_url(base_url: &str, suite: &str, component: &str, arch: &str) -> String {
    format!("{base_url}/dists/{suite}/{component}/dep11/Components-{arch}.yml.gz")
}

/// Thin fetch client for the Debian/Ubuntu DEP-11 layout: streams the
/// `.yml.gz` download to a disk cache, then returns the decompressed text.
#[cfg(feature = "http")]
pub struct AppstreamClient {
    http: reqwest::Client,
    cache_dir: camino::Utf8PathBuf,
}

/// How long a cached catalog is served with no network round-trip at all;
/// the freshness key is the cache file's mtime.
#[cfg(feature = "http")]
pub const CATALOG_CACHE_TTL: Duration = Duration::from_hours(6);

#[cfg(feature = "http")]
impl AppstreamClient {
    /// A client caching catalogs under `cache_dir/appstream/` (descriptive
    /// UA, redirects followed, timeouts).
    pub fn new(cache_dir: impl Into<camino::Utf8PathBuf>) -> Self {
        Self {
            http: crate::http::build_http_client(USER_AGENT),
            cache_dir: cache_dir.into(),
        }
    }

    /// Fetch and decompress one catalog for [`AppstreamAdapter::from_text`];
    /// within [`CATALOG_CACHE_TTL`] serves the cache with zero network.
    ///
    /// # Errors
    ///
    /// [`Error::Http`] for transport failures, non-success statuses, and
    /// cache/decompression I/O failures.
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
                    let cleanup = part_path.clone();
                    let _ =
                        tokio::task::spawn_blocking(move || std::fs::remove_file(cleanup)).await;
                }
                result
            }
        }
    }

    /// The decompressed cached catalog for one scope, when a copy exists —
    /// no freshness check, no network; `Ok(None)` = nothing cached yet.
    ///
    /// # Errors
    ///
    /// [`Error::Http`] when a cached copy exists but cannot be read or
    /// decompressed.
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

    fn cache_path(&self, suite: &str, component: &str, arch: &str) -> camino::Utf8PathBuf {
        let sanitize = |segment: &str| segment.replace('/', "_");
        self.cache_dir.join(format!(
            "appstream/{}-{}-Components-{}.yml.gz",
            sanitize(suite),
            sanitize(component),
            sanitize(arch)
        ))
    }

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
        let open_path = part_path.to_owned();
        let part = tokio::task::spawn_blocking(move || {
            std::fs::create_dir_all(open_path.parent().unwrap_or(open_path.as_path()))
                .and_then(|()| std::fs::File::create(&open_path))
        })
        .await
        .map_err(|error| http_error(url, "open join", &error.to_string()))?
        .map_err(|error| http_error(url, "create cache file", &error.to_string()))?;
        let mut response = response;
        let mut part = std::io::BufWriter::new(part);
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|error| http_error(url, "read stream", &error.to_string()))?
        {
            part.write_all(chunk.as_ref())
                .map_err(|error| http_error(url, "write cache", &error.to_string()))?;
        }
        let finalized = final_path.to_owned();
        let part_final = part_path.to_owned();
        let url_owned = url.to_owned();
        tokio::task::spawn_blocking(move || {
            part.flush()
                .map_err(|error| http_error(&url_owned, "flush cache", &error.to_string()))?;
            drop(part);
            std::fs::rename(&part_final, &finalized)
                .map_err(|error| http_error(&url_owned, "finalize cache", &error.to_string()))?;
            let _ = write_validators(&finalized, etag.as_deref(), last_modified.as_deref());
            decompress_cached(&finalized)
                .map_err(|error| http_error(&url_owned, "decompress", &error.to_string()))
        })
        .await
        .map_err(|error| http_error(url, "finalize join", &error.to_string()))?
    }
}

#[cfg(feature = "http")]
#[derive(Debug, Clone, PartialEq, Eq)]
enum CacheProbe {
    Fresh(String),
    Stale {
        etag: Option<String>,
        last_modified: Option<String>,
    },
}

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
        Err(_) => CacheProbe::Stale {
            etag: None,
            last_modified: None,
        },
    }
}

#[cfg(feature = "http")]
fn decompress_cached(path: &camino::Utf8Path) -> std::io::Result<String> {
    let compressed = std::fs::File::open(path)?;
    let mut text = String::new();
    flate2::read::GzDecoder::new(compressed).read_to_string(&mut text)?;
    Ok(text)
}

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

#[cfg(feature = "http")]
#[must_use]
fn validators_path(path: &camino::Utf8Path) -> camino::Utf8PathBuf {
    camino::Utf8PathBuf::from(format!("{path}.validators"))
}

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

#[cfg(feature = "http")]
fn refresh_mtime(path: &camino::Utf8Path) -> std::io::Result<()> {
    std::fs::OpenOptions::new()
        .write(true)
        .open(path)?
        .set_modified(SystemTime::now())
}

#[cfg(feature = "http")]
fn http_error(url: &str, stage: &str, detail: &str) -> Error {
    Error::Http {
        url: url.to_owned(),
        message: format!("{stage}: {detail}"),
    }
}

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

    fn fixture() -> String {
        let path = std::path::Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/appstream"
        ))
        .join("debian-sid-main-amd64.yml");
        std::fs::read_to_string(&path)
            .unwrap_or_else(|err| panic!("failed to read fixture `{}`: {err}", path.display()))
    }

    fn fixture_adapter() -> AppstreamAdapter {
        AppstreamAdapter::from_text(&fixture(), decode_catalog_arch("debian-sid-main-amd64.yml"))
            .expect("fixture parses")
    }

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
        assert_eq!(firefox_esr.project_license, None);
        assert_eq!(firefox_esr.developer, None);
        assert!(firefox_esr.releases.is_empty());
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
        let by_id = SourceRef {
            id: "firefox-esr.desktop".to_owned(),
            ..by_package.clone()
        };
        assert!(adapter.lookup(&by_id).await.expect("lookup ok").is_some());
        let other_repo = SourceRef {
            repo: Some("ubuntu-noble-main".to_owned()),
            ..by_package.clone()
        };
        assert_eq!(adapter.lookup(&other_repo).await.expect("lookup ok"), None);
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
        let hits = adapter.search("text editor").await.expect("search ok");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].id.as_str(), "gnome-text-editor");
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
        assert_eq!(adapter.catalog().components.len(), 4);
        assert!(block_on_search(&adapter, "Example Library").is_empty());
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
        assert_eq!(
            decode_catalog_arch("debian-sid-main-amd64.yml"),
            Some(Arch::X86_64)
        );
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
        assert_eq!(decode_family(Some("debian-sid-main")), DistroFamily::Debian);
        assert_eq!(
            decode_family(Some("ubuntu-noble-main")),
            DistroFamily::Ubuntu
        );
        assert_eq!(
            decode_family(Some("archive-jammy-main")),
            DistroFamily::Ubuntu
        );
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

#[cfg(all(test, feature = "http"))]
mod client_tests {
    use super::*;

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

    const ETAG: &str = "\"dep11-v1\"";
    const LAST_MODIFIED: &str = "Wed, 01 Jan 2026 00:00:00 GMT";

    fn scratch(name: &str) -> camino::Utf8PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "toride-registry-appstream-client-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch dir creatable");
        camino::Utf8PathBuf::from_path_buf(dir).expect("temp path is UTF-8")
    }

    fn seed_gz(path: &camino::Utf8Path, text: &str) {
        std::fs::create_dir_all(path.parent().unwrap_or(path)).expect("seed dir creatable");
        let file = std::fs::File::create(path).expect("seed file creatable");
        let mut encoder = flate2::write::GzEncoder::new(file, flate2::Compression::default());
        encoder
            .write_all(text.as_bytes())
            .expect("seed content writable");
        encoder.finish().expect("seed gzip finishable");
    }

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
        assert_eq!(
            client.cache_path("si/d", "ma/in", "amd64").as_str(),
            "/var/cache/toride/appstream/si_d-ma_in-Components-amd64.yml.gz"
        );
    }

    #[test]
    fn cache_probe_is_mtime_keyed() {
        let dir = scratch("probe");
        let path = dir.join("sid-main-Components-amd64.yml.gz");
        assert_eq!(
            probe_cache(&path, CATALOG_CACHE_TTL, SystemTime::now()),
            CacheProbe::Stale {
                etag: None,
                last_modified: None
            }
        );
        seed_gz(&path, PROBE_CATALOG);
        write_validators(&path, Some(ETAG), Some(LAST_MODIFIED)).expect("sidecar writable");
        let mtime = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        set_mtime(&path, mtime);
        assert_eq!(
            probe_cache(
                &path,
                CATALOG_CACHE_TTL,
                mtime + CATALOG_CACHE_TTL - Duration::from_secs(1)
            ),
            CacheProbe::Fresh(PROBE_CATALOG.to_owned())
        );
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
        assert_eq!(read_validators(&path), (None, None));
        write_validators(&path, Some(ETAG), Some(LAST_MODIFIED)).expect("sidecar writable");
        assert_eq!(
            read_validators(&path),
            (Some(ETAG.to_owned()), Some(LAST_MODIFIED.to_owned()))
        );
        write_validators(&path, None, Some(LAST_MODIFIED)).expect("sidecar rewritable");
        assert_eq!(
            read_validators(&path),
            (None, Some(LAST_MODIFIED.to_owned()))
        );
        write_validators(&path, Some(ETAG), None).expect("sidecar rewritable");
        assert_eq!(read_validators(&path), (Some(ETAG.to_owned()), None));
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
        assert!(conditional_headers(None, None).is_empty());
    }

    #[test]
    fn cached_catalog_serves_the_seeded_copy_with_parse_parity() {
        let client = AppstreamClient::new(scratch("cached-catalog"));
        assert_eq!(
            client
                .cached_catalog("sid", "main", "amd64")
                .expect("uncached scope reads clean"),
            None
        );
        seed_gz(&client.cache_path("sid", "main", "amd64"), PROBE_CATALOG);
        let cached = client
            .cached_catalog("sid", "main", "amd64")
            .expect("cached copy decompresses")
            .expect("cached copy exists");
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
        refresh_mtime(&path).expect("mtime refreshable");
        assert_eq!(
            probe_cache(&path, CATALOG_CACHE_TTL, SystemTime::now()),
            CacheProbe::Fresh(PROBE_CATALOG.to_owned())
        );
    }
}

#[cfg(all(test, feature = "http"))]
mod network_tests {
    use super::*;

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
        let ttl_hit = client
            .fetch_catalog(DEBIAN_BASE_URL, "sid", "main", "amd64")
            .await
            .expect("ttl-hit catalog serve");
        assert_eq!(
            ttl_hit, text,
            "a TTL hit must serve the cached bytes verbatim"
        );
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
        assert_eq!(adapter.catalog().header.file.as_deref(), Some("DEP-11"));
        let origin = adapter
            .catalog()
            .header
            .origin
            .as_deref()
            .expect("live Origin");
        assert!(origin.starts_with("debian"), "unexpected Origin: {origin}");
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
