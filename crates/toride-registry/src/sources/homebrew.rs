//! # Homebrew adapter
//!
//! Normalizes formulae.brew.sh casks (GUI apps) and formulae (CLI tools)
//! into [`App`]s. Grounded in
//! `docs/survey/homebrew.md` (§1–§2 endpoints, §3–§5 cask fields,
//! §7 formula fields) and DESIGN.md §4.1–§4.2 (field mappings).
//!
//! The module keeps the house parse/fetch split (DESIGN.md §3.1) strictly
//! separated:
//!
//! - **Parse half (pure, always compiled, offline-fixture-tested):**
//!   [`parse_cask_json`] and [`parse_formula_json`] take the raw JSON body
//!   text and return a normalized [`App`]. The wire
//!   structs below are `#[serde(default)]` end to end — formulae.brew.sh
//!   promises no stability guarantees (homebrew.md §1), so any key going
//!   missing or `null` upstream must degrade to `None`, never error.
//! - **Fetch half (thin client, gated behind the crate's `http` feature so
//!   the parsers build fully offline, DESIGN.md §9):**
//!   [`HomebrewClient`] GETs the two per-item endpoints and returns raw
//!   body text; [`HomebrewAdapter`] implements
//!   [`Adapter`](crate::adapter::Adapter) over them — `lookup` per-item,
//!   search over the two full catalog indexes cached for one
//!   [`INDEX_CACHE_TTL`] window and parsed through the same
//!   normalization ([`search_index`]).
//!
//! ## Cask `variations` contract (DESIGN.md §4.1)
//!
//! The top-level `url`/`sha256` describe the API's default platform (the
//! payload never names which). Each `variations` key is a platform tag
//! (e.g. `sonoma`, `arm64_big_sur`, `x86_64_linux`) whose object
//! shallow-merges over the top-level triple. This parser is **pure** — it
//! takes no host parameter — and collapses every available platform into
//! one [`Artifact`] per **distinct
//! (os, arch, url, sha256) tuple**:
//!
//! - an **absent** override key inherits the top-level value;
//! - an **explicit `null`** override (the absent-vs-`null` distinction is
//!   read off the raw JSON map, per §4.1 caveat 3) marks the platform
//!   **unavailable**: no artifact, and no `platforms` claim. All four
//!   `*_linux` keys in the two cask fixtures carry `"sha256": null`, so
//!   neither fixture claims Linux;
//! - identical tuples dedupe (brave's 5 Intel-release keys → one
//!   (`MacOs`, `X86_64`) artifact), while distinct tuples are kept even when a
//!   newer top-level version exists (vscode's `big_sur`/`arm64_big_sur`
//!   carry 1.106.3 payloads against a 1.139.1 top level — the per-release
//!   version is dropped because `Artifact` has no version field and wave 1
//!   has no version ordering, DESIGN.md §4.1 caveat 1);
//! - `platforms` claims come from `supported_platforms` tags ∪ available
//!   variation keys, deduped to distinct (os, arch) — artifact tuples and
//!   platform claims dedupe **separately** (vscode ends with 2 platforms /
//!   4 artifacts).
//!
//! ## Quick start
//!
//! ```rust,ignore
//! use toride_registry::model::SourceRef;
//! use toride_registry::sources::homebrew::{parse_cask_json, HomebrewAdapter};
//!
//! // Fetch half: thin client returning raw body text (feature `http`).
//! let adapter = HomebrewAdapter::default();
//! let row = SourceRef {
//!     source: toride_registry::SourceKind::HomebrewCask,
//!     id: "brave-browser".into(),
//!     repo: None,
//!     version: None,
//!     provisional: false,
//! };
//! let app = adapter.lookup(&row).await?.expect("cask exists");
//!
//! // Parse half: the same signature the offline fixtures exercise.
//! let app = parse_cask_json(&std::fs::read_to_string("cask.json")?)?;
//! ```

use crate::error::{Error, Result};
use crate::model::{
    App, Arch, Artifact, ArtifactKind, Availability, Checksum, ChecksumAlgo, InstallMethod, Os,
    Platform, SourceKind, SourceRef, TorideId, Version,
};
use serde::Deserialize;
use serde_json::{Map, Value};
use std::collections::BTreeMap;
#[cfg(feature = "http")]
use std::sync::Arc;
#[cfg(feature = "http")]
use std::time::{Duration, SystemTime};

// ---------------------------------------------------------------------------
// Wire structs — cask (parse half)
// ---------------------------------------------------------------------------

/// The subset of the formulae.brew.sh cask object this parser consumes
/// (homebrew.md §3). Every field defaults: unknown keys are ignored and any
/// known key may be absent or `null` upstream without breaking the parse.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct CaskPayload {
    /// Cask token — `brew install --cask <token>`, the source id and the
    /// slugify input.
    token: String,
    /// Display names; `name[0]` is the display name, `name[1..]` aliases.
    name: Vec<String>,
    /// Renamed-from tokens (redirect aliases).
    old_tokens: Vec<String>,
    /// One-liner description → `App::summary`.
    desc: Option<String>,
    /// Project URL → `App::homepage`.
    homepage: Option<String>,
    /// Upstream version of the API's default platform → `App::latest`.
    version: Option<String>,
    /// Download URL of the API's default platform.
    url: Option<String>,
    /// sha256 of the `url` artifact (default platform).
    sha256: Option<String>,
    /// Ordered install/uninstall steps; only `binary` stanzas are read
    /// (→ `App::binaries`), the rest are wave-1-dropped install steps —
    /// installing is delegated to `brew` (DESIGN.md §4.1).
    artifacts: Vec<CaskArtifactEntry>,
    /// Dependency declarations; only `macos.{">=":[…]}` is read
    /// (→ `Platform::min_release`).
    depends_on: Option<CaskDependsOn>,
    /// Cask deprecated (still installable, warns first).
    deprecated: bool,
    /// Cask fully disabled (cannot install).
    disabled: bool,
    /// Expanded macOS release tags the cask supports
    /// (e.g. `sonoma`, `arm64_sequoia`) → platform claims.
    supported_platforms: Vec<String>,
    /// Per-platform override objects keyed by platform tag
    /// (§4.1 variations contract). Values are kept as raw JSON maps so the
    /// absent-vs-`null` distinction survives deserialization and unused
    /// upstream fields (`version`, `skip_livecheck`, …) remain available to
    /// a later wave.
    variations: BTreeMap<String, Map<String, Value>>,
}

/// One entry of the cask `artifacts` list — an ordered single-key step
/// object (`{"binary": […]}` / `{"app": […]}` / `{"zap": {…}}`, homebrew.md
/// §5). Only `binary` payloads are read; every other step (and its
/// `target` sibling key) is ignored, which is also why the struct has no
/// other fields.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct CaskArtifactEntry {
    /// Payload items of a `binary` stanza, kept raw: the live catalog
    /// ships plain path strings (`$APPDIR/…`, `$HOMEBREW_PREFIX/…`) and
    /// `{"target": …}` link maps in one array.
    binary: Vec<Value>,
}

/// The cask `depends_on` object. Only the `macos` comparison map is read;
/// `arch`/`formula`/`cask` keys are ignored (wave 1).
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct CaskDependsOn {
    /// Either `{}` or a comparison map such as `{">=": ["13"]}` — kept raw
    /// because the API has shipped both shapes.
    macos: Option<Value>,
}

// ---------------------------------------------------------------------------
// Wire structs — formula (parse half)
// ---------------------------------------------------------------------------

/// The subset of the formulae.brew.sh formula object this parser consumes
/// (homebrew.md §7). Same `#[serde(default)]` strictness as
/// [`CaskPayload`].
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct FormulaPayload {
    /// Formula name — `brew install <name>`, the source id and slugify
    /// input.
    name: String,
    /// Fully-qualified name; fallback when `name` is missing.
    full_name: String,
    /// Alternate names (e.g. ripgrep → `["rg"]`).
    aliases: Vec<String>,
    /// Renamed-from names.
    oldnames: Vec<String>,
    /// One-liner description → `App::summary`.
    desc: Option<String>,
    /// Project URL → `App::homepage`.
    homepage: Option<String>,
    /// License string (SPDX-style where upstream publishes one).
    license: Option<String>,
    /// Version block; `stable` is the release version (`head`/`bottle`
    /// flags ignored).
    versions: Option<FormulaVersions>,
    /// URL block; `stable` is the source archive → one `ArtifactKind::Source`.
    urls: Option<FormulaUrls>,
    /// Bottle block; `stable.files` maps platform tags to prebuilt blobs.
    bottle: Option<FormulaBottle>,
    /// Executables the formula puts on PATH → `App::binaries`.
    executables: Vec<String>,
    /// Formula deprecated (still installable, warns first).
    deprecated: bool,
    /// Formula fully disabled (cannot install).
    disabled: bool,
}

/// The formula `versions` object.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct FormulaVersions {
    /// Stable release version (`head` and the `bottle` flag are ignored).
    stable: Option<String>,
}

/// The formula `urls` object.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct FormulaUrls {
    /// The stable source archive (`head` ignored).
    stable: Option<FormulaUrl>,
}

/// One formula URL entry — the stable source tarball plus its checksum.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct FormulaUrl {
    /// Archive URL.
    url: Option<String>,
    /// sha256 of the archive (upstream field name: `checksum`).
    checksum: Option<String>,
}

/// The formula `bottle` field. Upstream serializes it either as the
/// stable-bottle object (`{"stable": {"files": {…}}}` — fixture ripgrep)
/// or as a bare `false` when the formula ships no bottles at all; both
/// shapes occur in `brew info --json` output, so both are tolerated (the
/// boolean shape simply yields no bottles).
#[derive(Debug, Deserialize)]
#[serde(untagged)]
#[allow(dead_code)] // `Bool`'s payload is a JSON-shape discriminator only
enum FormulaBottle {
    /// The object shape: `{"stable": {"files": {…}}}`.
    Stable(FormulaBottleStable),
    /// The boolean shape (`false`, source-only formula; `true` is treated
    /// the same — no file map to read).
    Bool(bool),
}

/// Payload of the object shape of the formula `bottle` field.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct FormulaBottleStable {
    /// The stable bottles (`rebuild`/`root_url` ignored).
    stable: Option<BottleStable>,
}

/// The `bottle.stable` object.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct BottleStable {
    /// Platform tag → prebuilt blob (`arm64_golden_gate`, `sonoma`,
    /// `arm64_linux`, `x86_64_linux`, …).
    files: Option<BTreeMap<String, BottleFile>>,
}

/// One bottle file — a prebuilt binary blob for one platform tag.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct BottleFile {
    /// ghcr.io blob URL.
    url: Option<String>,
    /// sha256 of the blob.
    sha256: Option<String>,
}

// ---------------------------------------------------------------------------
// Shared parse helpers
// ---------------------------------------------------------------------------

/// How one variation key treats one top-level field (§4.1 caveat 3):
/// `Absent` inherits the top-level value, `Null` marks the platform
/// unavailable, `Set` overrides it. Reading this off the raw JSON map (not
/// `Option<Option<T>>`) is what keeps absent and `null` distinct — serde's
/// own `Option` impl collapses both to `None`.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Override {
    /// Key missing from the variation object → inherit the top level.
    Absent,
    /// Key present as explicit `null` → platform unavailable.
    Null,
    /// Key present with a string value → override.
    Set(String),
}

/// Reads one override slot out of a raw variation object. A present
/// non-string value cannot occur upstream (homebrew.md §4); it is treated
/// as [`Override::Absent`] rather than inventing an unavailable marking.
fn override_of(variation: &Map<String, Value>, key: &str) -> Override {
    match variation.get(key) {
        Some(Value::Null) => Override::Null,
        Some(Value::String(s)) => Override::Set(s.clone()),
        // Key missing, or a non-string value (cannot occur upstream per
        // homebrew.md §4): inherit the top-level value.
        _ => Override::Absent,
    }
}

/// Effective (url, sha256) for one variation key: shallow-merge the
/// override object over the top-level pair. `None` = platform unavailable
/// (an explicit `null` in either slot) or no usable URL at all.
fn effective_url_sha(
    base_url: Option<&str>,
    base_sha: Option<&str>,
    variation: &Map<String, Value>,
) -> Option<(String, Option<String>)> {
    let url = match override_of(variation, "url") {
        Override::Null => return None,
        Override::Set(s) => Some(s),
        Override::Absent => base_url.map(str::to_owned),
    };
    let sha = match override_of(variation, "sha256") {
        Override::Null => return None,
        Override::Set(s) => Some(s),
        Override::Absent => base_sha.map(str::to_owned),
    };
    Some((url?, sha))
}

/// Dedup key of the §4.1 artifact collapse: the (os, arch, url, sha256)
/// tuple — one `Artifact` per distinct key, keep-first.
type ArtifactKey = (Option<Os>, Option<Arch>, String, Option<String>);

/// Decodes a Homebrew platform tag to its (os, arch) pair — shared by cask
/// `variations`/`supported_platforms` keys and formula bottle-file tags.
///
/// `…_linux` → [`Os::Linux`] with the arch decoded from the prefix
/// (`arm64_linux`, `x86_64_linux`, `x86_linux`); everything else is a
/// macOS release tag → [`Os::MacOs`] where `arm64_…` is Apple silicon and
/// the bare release name is Intel. `None` = un-decodable tag (skipped —
/// homebrew.md documents exactly this vocabulary, so anything else is
/// upstream drift, not data).
fn decode_platform_tag(tag: &str) -> Option<(Os, Arch)> {
    if let Some(base) = tag.strip_suffix("_linux") {
        let arch = match base {
            "arm64" => Arch::Aarch64,
            "x86_64" => Arch::X86_64,
            "x86" => Arch::X86,
            _ => return None,
        };
        return Some((Os::Linux, arch));
    }
    let arch = if tag.starts_with("arm64_") {
        Arch::Aarch64
    } else {
        Arch::X86_64
    };
    Some((Os::MacOs, arch))
}

/// Deterministic platform order: `MacOs` < `Linux` < `Windows`, then
/// arch-undeclared < `X86_64` < `Aarch64` < `X86`. `App::platforms` is a plain
/// `Vec`, so the parser fixes one stable order instead of leaking the
/// iteration order of a JSON map (`serde_json` maps are `BTreeMap`s — sorted,
/// but the sort key would be the *tag string*, which is not a meaningful
/// platform order).
fn platform_rank(os: Os, arch: Option<Arch>) -> (u8, u8) {
    let os = match os {
        Os::MacOs => 0,
        Os::Linux => 1,
        Os::Windows => 2,
    };
    let arch = match arch {
        None => 0,
        Some(Arch::X86_64) => 1,
        Some(Arch::Aarch64) => 2,
        Some(Arch::X86) => 3,
    };
    (os, arch)
}

/// Dedupes collected (os, arch) claims into sorted `Platform` values.
/// `min_release` is attached to macOS claims only — it comes from the cask
/// `depends_on.macos` map and says nothing about Linux.
fn dedupe_platforms(
    claims: &mut Vec<(Os, Arch)>,
    macos_min_release: Option<&str>,
) -> Vec<Platform> {
    claims.sort_by_key(|&(os, arch)| platform_rank(os, Some(arch)));
    claims.dedup();
    claims
        .iter()
        .map(|&(os, arch)| Platform {
            os,
            arch: Some(arch),
            min_release: if os == Os::MacOs {
                macos_min_release.map(str::to_owned)
            } else {
                None
            },
        })
        .collect()
}

/// Extracts the minimum macOS release from `depends_on.macos`. The API
/// ships either a comparison map (`{">=": ["13"]}` — brave fixture) or an
/// empty object / bare release string; anything unparseable degrades to
/// `None`.
fn macos_min_release(depends_on: Option<&CaskDependsOn>) -> Option<String> {
    let macos = depends_on?.macos.as_ref()?;
    match macos {
        Value::Object(map) => map
            .get(">=")
            .and_then(Value::as_array)
            .and_then(|bounds| bounds.first())
            .and_then(Value::as_str)
            .map(str::to_owned),
        Value::String(release) => Some(release.clone()),
        _ => None,
    }
}

/// Basename of a cask payload path — the text after the final `/`, or the
/// whole string when it has none (DESIGN.md §4.1 pins `binaries` to this
/// rule).
fn path_basename(path: &str) -> &str {
    match path.rfind('/') {
        Some(idx) => &path[idx + 1..],
        None => path,
    }
}

/// The `binaries` extraction pinned by DESIGN.md §4.1: for every `binary`
/// stanza, the basename of each payload string — or of a `{"target": …}`
/// payload's target, same rule — deduplicated, in payload order.
fn binaries_from_cask_artifacts(entries: &[CaskArtifactEntry]) -> Vec<String> {
    let mut binaries: Vec<String> = Vec::new();
    for entry in entries {
        for payload in &entry.binary {
            let name = match payload {
                Value::String(path) => path_basename(path),
                Value::Object(map) => match map.get("target") {
                    Some(Value::String(target)) => path_basename(target),
                    _ => continue,
                },
                _ => continue,
            };
            if !binaries.iter().any(|known| known == name) {
                binaries.push(name.to_owned());
            }
        }
    }
    binaries
}

/// Deserializes one wire payload, mapping failures to
/// [`Error::Parse`] with a best-effort source-native id: on failure the raw
/// text is re-scanned for the first id field that yields a string, so the
/// error names the cask/formula it came from even when the payload itself
/// is malformed.
fn parse_wire<T: serde::de::DeserializeOwned>(payload: &str, id_keys: &[&str]) -> Result<T> {
    serde_json::from_str(payload).map_err(|err| {
        let id = serde_json::from_str::<Value>(payload)
            .ok()
            .and_then(|value| {
                id_keys
                    .iter()
                    .find_map(|key| value.get(*key).and_then(Value::as_str).map(str::to_owned))
            })
            .unwrap_or_default();
        Error::Parse {
            kind: "json",
            id,
            message: err.to_string(),
        }
    })
}

// ---------------------------------------------------------------------------
// Cask parse (§4.1)
// ---------------------------------------------------------------------------

/// Normalizes one formulae.brew.sh cask payload (`/api/cask/{token}.json`,
/// homebrew.md §3) into an [`App`].
///
/// Implements the §4.1 variations contract: the top-level
/// `url`/`sha256` become the default-platform `ArtifactKind::Package`
/// (`arch: None` — the payload never names the default platform), and each
/// `variations` entry shallow-merges over that triple, collapsing into one
/// artifact per distinct (os, arch, url, sha256) tuple. An explicit
/// `null` override means the platform is unavailable: no artifact and no
/// `platforms` claim. `binaries` are the basenames of `binary` artifact
/// payloads (vscode → `["code", "code-tunnel"]`).
///
/// # Errors
///
/// [`Error::Parse`] when the payload is not a cask JSON object (the
/// id field carries the cask `token` when one is readable).
pub fn parse_cask_json(payload: &str) -> Result<App> {
    let cask: CaskPayload = parse_wire(payload, &["token"])?;
    Ok(app_from_cask(cask))
}

fn app_from_cask(cask: CaskPayload) -> App {
    let token = cask.token;
    let name = cask.name.first().cloned().unwrap_or_else(|| token.clone());
    let aliases: Vec<String> = cask
        .name
        .iter()
        .skip(1)
        .cloned()
        .chain(cask.old_tokens)
        .collect();
    let latest = cask.version.map(|value| Version {
        value,
        original: None,
        published_unix: None,
    });
    let min_release = macos_min_release(cask.depends_on.as_ref());

    let mut artifacts: Vec<Artifact> = Vec::new();
    let mut seen: Vec<ArtifactKey> = Vec::new();
    let mut push = |os: Option<Os>, arch: Option<Arch>, url: String, sha: Option<String>| {
        let key = (os, arch, url.clone(), sha.clone());
        if seen.contains(&key) {
            return;
        }
        seen.push(key);
        artifacts.push(Artifact {
            url,
            checksum: sha.map(|digest| Checksum {
                algo: ChecksumAlgo::Sha256,
                digest,
            }),
            os,
            arch,
            kind: ArtifactKind::Package,
        });
    };
    if let Some(url) = cask.url.as_deref() {
        push(Some(Os::MacOs), None, url.to_owned(), cask.sha256.clone());
    }
    let mut claims: Vec<(Os, Arch)> = Vec::new();
    for (tag, variation) in &cask.variations {
        let Some((os, arch)) = decode_platform_tag(tag) else {
            continue;
        };
        let Some((url, sha)) =
            effective_url_sha(cask.url.as_deref(), cask.sha256.as_deref(), variation)
        else {
            continue;
        };
        push(Some(os), Some(arch), url, sha);
        claims.push((os, arch));
    }
    claims.extend(
        cask.supported_platforms
            .iter()
            .filter_map(|tag| decode_platform_tag(tag)),
    );

    let availability = if cask.disabled {
        Availability::Disabled
    } else if cask.deprecated {
        Availability::Deprecated
    } else {
        Availability::Available
    };

    App {
        id: TorideId::slugify(&token),
        name,
        aliases,
        summary: cask.desc,
        description: None,
        homepage: cask.homepage,
        license: None,
        developer: None,
        binaries: binaries_from_cask_artifacts(&cask.artifacts),
        latest: latest.clone(),
        platforms: dedupe_platforms(&mut claims, min_release.as_deref()),
        artifacts,
        install: InstallMethod::Homebrew {
            cask: true,
            token: token.clone(),
        },
        sources: vec![SourceRef {
            source: SourceKind::HomebrewCask,
            id: token,
            repo: None,
            version: latest,
            provisional: false,
        }],
        availability,
    }
}

/// Normalizes a full cask catalog (`/api/cask.json`) — one [`App`] per
/// cask in payload order, entries with no readable token skipped.
/// Errors: [`Error::Parse`] on a non-array or non-cask payload.
pub fn parse_cask_index(payload: &str) -> Result<Vec<App>> {
    let casks: Vec<CaskPayload> =
        serde_json::from_str(payload).map_err(|error| index_parse_error("cask-index", &error))?;
    Ok(casks
        .into_iter()
        .filter(|cask| !cask.token.is_empty())
        .map(app_from_cask)
        .collect())
}

// ---------------------------------------------------------------------------
// Formula parse (§4.2)
// ---------------------------------------------------------------------------

/// Normalizes one formulae.brew.sh formula payload
/// (`/api/formula/{name}.json`, homebrew.md §7) into an
/// [`App`].
///
/// `bottle.stable.files` platform tags decode to one
/// [`ArtifactKind::Bottle`] artifact each (ghcr.io blob + published
/// sha256) and, deduped, to the `platforms` claims — `arm64_golden_gate` →
/// (`MacOs`, Aarch64), `sonoma` → (`MacOs`, `X86_64`), `arm64_linux` →
/// (Linux, Aarch64). A source-only formula (`bottle: false`) gets
/// `platforms = []` (unknown, per the model's contract — not universal).
/// `urls.stable` becomes one [`ArtifactKind::Source`] artifact and
/// `executables` becomes `App::binaries`.
///
/// # Errors
///
/// [`Error::Parse`] when the payload is not a formula JSON object (the
/// id field carries the formula `name` when one is readable).
pub fn parse_formula_json(payload: &str) -> Result<App> {
    let formula: FormulaPayload = parse_wire(payload, &["name", "full_name"])?;
    Ok(app_from_formula(formula))
}

#[allow(
    clippy::too_many_lines,
    reason = "one linear parse->normalize pipeline; a split at the 100-line threshold is artificial"
)]
fn app_from_formula(formula: FormulaPayload) -> App {
    let name = if formula.name.is_empty() {
        formula.full_name.clone()
    } else {
        formula.name.clone()
    };
    let aliases: Vec<String> = formula
        .aliases
        .iter()
        .chain(&formula.oldnames)
        .cloned()
        .collect();
    let latest = formula
        .versions
        .and_then(|versions| versions.stable)
        .map(|value| Version {
            value,
            original: None,
            published_unix: None,
        });

    let mut artifacts: Vec<Artifact> = Vec::new();
    let mut claims: Vec<(Os, Arch)> = Vec::new();
    let files = formula.bottle.as_ref().and_then(|bottle| match bottle {
        FormulaBottle::Stable(stable) => stable
            .stable
            .as_ref()
            .and_then(|bottle_stable| bottle_stable.files.as_ref()),
        FormulaBottle::Bool(_) => None,
    });
    if let Some(files) = files {
        for (tag, file) in files {
            let Some((os, arch)) = decode_platform_tag(tag) else {
                continue;
            };
            artifacts.push(Artifact {
                url: file.url.clone().unwrap_or_default(),
                checksum: file.sha256.clone().map(|digest| Checksum {
                    algo: ChecksumAlgo::Sha256,
                    digest,
                }),
                os: Some(os),
                arch: Some(arch),
                kind: ArtifactKind::Bottle,
            });
            claims.push((os, arch));
        }
    }
    if let Some(url) = formula
        .urls
        .as_ref()
        .and_then(|urls| urls.stable.as_ref())
        .and_then(|stable| stable.url.clone())
    {
        let checksum = formula
            .urls
            .as_ref()
            .and_then(|urls| urls.stable.as_ref())
            .and_then(|stable| stable.checksum.clone())
            .map(|digest| Checksum {
                algo: ChecksumAlgo::Sha256,
                digest,
            });
        artifacts.push(Artifact {
            url,
            checksum,
            os: None,
            arch: None,
            kind: ArtifactKind::Source,
        });
    }

    let availability = if formula.disabled {
        Availability::Disabled
    } else if formula.deprecated {
        Availability::Deprecated
    } else {
        Availability::Available
    };

    App {
        id: TorideId::slugify(&name),
        name: name.clone(),
        aliases,
        summary: formula.desc,
        description: None,
        homepage: formula.homepage,
        license: formula.license,
        developer: None,
        binaries: formula.executables,
        latest: latest.clone(),
        platforms: dedupe_platforms(&mut claims, None),
        artifacts,
        install: InstallMethod::Homebrew {
            cask: false,
            token: name.clone(),
        },
        sources: vec![SourceRef {
            source: SourceKind::HomebrewFormula,
            id: name,
            repo: None,
            version: latest,
            provisional: false,
        }],
        availability,
    }
}

/// Normalizes a full formula catalog (`/api/formula.json`) — one [`App`]
/// per formula in payload order, nameless entries skipped. Errors:
/// [`Error::Parse`] on a non-array or non-formula payload.
pub fn parse_formula_index(payload: &str) -> Result<Vec<App>> {
    let formulae: Vec<FormulaPayload> = serde_json::from_str(payload)
        .map_err(|error| index_parse_error("formula-index", &error))?;
    Ok(formulae
        .into_iter()
        .filter(|formula| !formula.name.is_empty() || !formula.full_name.is_empty())
        .map(app_from_formula)
        .collect())
}

fn index_parse_error(id: &str, error: &serde_json::Error) -> Error {
    Error::Parse {
        kind: "json",
        id: id.to_owned(),
        message: error.to_string(),
    }
}

/// The hit cap [`search_index`] serves one query with.
pub const MAX_SEARCH_HITS: usize = 50;

/// Case-insensitive free-text search by token, name, aliases, and
/// summary — every whitespace-separated word must match, a hit ranks by
/// its worst word (exact < prefix < substring), capped, empty → none.
#[must_use]
pub fn search_index(apps: &[App], query: &str) -> Vec<App> {
    let words: Vec<String> = query.split_whitespace().map(str::to_lowercase).collect();
    if words.is_empty() {
        return Vec::new();
    }
    let mut hits: Vec<(u8, &App)> = apps
        .iter()
        .filter_map(|app| {
            let rank = words.iter().try_fold(0u8, |worst, word| {
                match_tier(app, word).map(|tier| worst.max(tier))
            })?;
            Some((rank, app))
        })
        .collect();
    hits.sort_by(|left, right| {
        left.0
            .cmp(&right.0)
            .then_with(|| left.1.id.as_str().cmp(right.1.id.as_str()))
    });
    hits.into_iter()
        .take(MAX_SEARCH_HITS)
        .map(|(_, app)| app.clone())
        .collect()
}

fn match_tier(app: &App, needle: &str) -> Option<u8> {
    let token = match &app.install {
        InstallMethod::Homebrew { token, .. } => token.to_lowercase(),
        _ => app.id.as_str().to_lowercase(),
    };
    let name = app.name.to_lowercase();
    if token == needle || name == needle {
        return Some(0);
    }
    if token.starts_with(needle) || name.starts_with(needle) {
        return Some(1);
    }
    let matched = token.contains(needle)
        || name.contains(needle)
        || app
            .aliases
            .iter()
            .any(|alias| alias.to_lowercase().contains(needle))
        || app
            .summary
            .as_deref()
            .is_some_and(|summary| summary.to_lowercase().contains(needle));
    matched.then_some(2)
}

// ---------------------------------------------------------------------------
// Fetch half (feature `http`) — thin client + adapter
// ---------------------------------------------------------------------------

/// Descriptive User-Agent (DESIGN.md §3.2: `toride-registry/<source>/<version>`).
#[cfg(feature = "http")]
const USER_AGENT: &str = concat!("toride-registry/homebrew/", env!("CARGO_PKG_VERSION"));

/// formulae.brew.sh origin — every wave-1 endpoint hangs off
/// `{API_BASE}/api/{cask,formula}/{token}.json` (homebrew.md §1).
#[cfg(feature = "http")]
const API_BASE: &str = "https://formulae.brew.sh";

/// Thin fetch client for formulae.brew.sh (DESIGN.md §3.1): raw body
/// text only, so live and fixture payloads flow through the same parse
/// signatures. The catalog-index fetches cache under
/// `{cache_dir}/homebrew/` for [`INDEX_CACHE_TTL`].
#[cfg(feature = "http")]
pub struct HomebrewClient {
    http: reqwest::Client,
    cache_dir: Option<camino::Utf8PathBuf>,
}

/// How long a cached catalog index is served with no network round-trip;
/// the catalogs republish continuously, so the window trades freshness
/// for the tens-of-MB re-download.
#[cfg(feature = "http")]
pub const INDEX_CACHE_TTL: Duration = Duration::from_hours(1);

/// Per-request timeout for the catalog-index downloads (tens of MB);
/// the shared client default budgets per-item payloads of a few KB.
#[cfg(feature = "http")]
pub const INDEX_FETCH_TIMEOUT: Duration = Duration::from_secs(600);

#[cfg(feature = "http")]
impl HomebrewClient {
    /// Builds a client caching under the platform cache dir when one
    /// resolves (no caching otherwise).
    #[must_use]
    pub fn new() -> Self {
        Self {
            http: crate::http::build_http_client(USER_AGENT),
            cache_dir: default_cache_dir(),
        }
    }

    /// Builds a client caching index payloads under
    /// `cache_dir/homebrew/`.
    #[must_use]
    pub fn with_cache_dir(cache_dir: impl Into<camino::Utf8PathBuf>) -> Self {
        Self {
            http: crate::http::build_http_client(USER_AGENT),
            cache_dir: Some(cache_dir.into()),
        }
    }

    /// `GET /api/cask.json` — the full cask catalog, served from a fresh
    /// cache entry when one exists. Errors: [`Error::Http`].
    pub async fn fetch_cask_index(&self) -> Result<String> {
        self.fetch_index_cached(&format!("{API_BASE}/api/cask.json"), "cask.json")
            .await
    }

    /// `GET /api/formula.json` — the full formula catalog, served from a
    /// fresh cache entry when one exists. Errors: [`Error::Http`].
    pub async fn fetch_formula_index(&self) -> Result<String> {
        self.fetch_index_cached(&format!("{API_BASE}/api/formula.json"), "formula.json")
            .await
    }

    async fn fetch_index_cached(&self, url: &str, cache_file: &str) -> Result<String> {
        let cache_path = self
            .cache_dir
            .as_ref()
            .map(|dir| dir.join(format!("homebrew/{cache_file}")));
        if let Some(path) = &cache_path {
            let probe_path = path.clone();
            let probed = tokio::task::spawn_blocking(move || {
                probe_index_cache(&probe_path, INDEX_CACHE_TTL, SystemTime::now())
            })
            .await
            .map_err(|error| Error::Http {
                url: url.to_owned(),
                message: format!("cache probe join: {error}"),
            })?;
            if let Some(text) = probed {
                return Ok(text);
            }
        }
        let body = self
            .fetch_body_with_timeout(url, INDEX_FETCH_TIMEOUT)
            .await?
            .ok_or_else(|| Error::Http {
                url: url.to_owned(),
                message: "HTTP 404: catalog index missing".to_owned(),
            })?;
        let Some(path) = cache_path else {
            return Ok(body);
        };
        tokio::task::spawn_blocking(move || {
            let _ = write_index_cache(&path, &body);
            body
        })
        .await
        .map_err(|error| Error::Http {
            url: url.to_owned(),
            message: format!("cache write join: {error}"),
        })
    }
}

#[cfg(feature = "http")]
fn probe_index_cache(path: &camino::Utf8Path, ttl: Duration, now: SystemTime) -> Option<String> {
    let fresh = std::fs::metadata(path)
        .ok()
        .and_then(|metadata| metadata.modified().ok())
        .and_then(|mtime| now.duration_since(mtime).ok())
        .is_some_and(|age| age < ttl);
    if fresh {
        std::fs::read_to_string(path).ok()
    } else {
        None
    }
}

#[cfg(feature = "http")]
fn part_path(path: &camino::Utf8Path) -> camino::Utf8PathBuf {
    static SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let unique = SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    camino::Utf8PathBuf::from(format!("{path}.{}.{}.part", std::process::id(), unique))
}

#[cfg(feature = "http")]
fn write_index_cache(path: &camino::Utf8Path, body: &str) -> std::io::Result<()> {
    let part = part_path(path);
    let outcome = write_body_via_part(&part, path, body);
    if outcome.is_err() {
        let _ = std::fs::remove_file(&part);
    }
    outcome
}

#[cfg(feature = "http")]
fn write_body_via_part(
    part: &camino::Utf8Path,
    path: &camino::Utf8Path,
    body: &str,
) -> std::io::Result<()> {
    std::fs::create_dir_all(part.parent().unwrap_or(part))?;
    std::fs::write(part, body)?;
    std::fs::rename(part, path)
}

#[cfg(feature = "http")]
fn default_cache_dir() -> Option<camino::Utf8PathBuf> {
    dirs::cache_dir().and_then(|dir| camino::Utf8PathBuf::from_path_buf(dir).ok())
}

#[cfg(feature = "http")]
impl Default for HomebrewClient {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "http")]
impl HomebrewClient {
    /// GETs `https://formulae.brew.sh/api/cask/{token}.json` and returns
    /// the response body text.
    ///
    /// # Errors
    ///
    /// [`Error::Http`] on transport failures and non-success statuses —
    /// including 404, which means "no such cask".
    pub async fn fetch_cask(&self, token: &str) -> Result<String> {
        let url = format!("{API_BASE}/api/cask/{token}.json");
        self.fetch_body(&url).await?.ok_or_else(|| Error::Http {
            url: url.clone(),
            message: format!("HTTP 404: no cask named `{token}`"),
        })
    }

    /// GETs `https://formulae.brew.sh/api/formula/{name}.json` and returns
    /// the response body text.
    ///
    /// # Errors
    ///
    /// [`Error::Http`] on transport failures and non-success statuses —
    /// including 404, which means "no such formula".
    pub async fn fetch_formula(&self, name: &str) -> Result<String> {
        let url = format!("{API_BASE}/api/formula/{name}.json");
        self.fetch_body(&url).await?.ok_or_else(|| Error::Http {
            url: url.clone(),
            message: format!("HTTP 404: no formula named `{name}`"),
        })
    }

    /// 404-aware variant of [`Self::fetch_cask`] for [`HomebrewAdapter`]:
    /// `Ok(None)` = no such cask (an absent entry is a normal lookup
    /// outcome, not a failure). Private because the pinned public surface
    /// of the client is the `Result<String>` pair above (DESIGN.md §3.1).
    async fn fetch_cask_optional(&self, token: &str) -> Result<Option<String>> {
        self.fetch_body(&format!("{API_BASE}/api/cask/{token}.json"))
            .await
    }

    /// 404-aware variant of [`Self::fetch_formula`] — see
    /// [`Self::fetch_cask_optional`].
    async fn fetch_formula_optional(&self, name: &str) -> Result<Option<String>> {
        self.fetch_body(&format!("{API_BASE}/api/formula/{name}.json"))
            .await
    }

    /// Fetches one URL, mapping a 404 to `Ok(None)` and every other
    /// non-success status or transport error to [`Error::Http`]. The
    /// current [`Error::Http`] carries the cause as text in `message`
    /// (error.rs documents the future typed `#[source]` upgrade).
    async fn fetch_body(&self, url: &str) -> Result<Option<String>> {
        self.fetch_body_with_timeout(url, crate::http::HTTP_TIMEOUT)
            .await
    }

    async fn fetch_body_with_timeout(
        &self,
        url: &str,
        timeout: Duration,
    ) -> Result<Option<String>> {
        let http_err = |message: String| Error::Http {
            url: url.to_owned(),
            message,
        };
        let response = self
            .http
            .get(url)
            .timeout(timeout)
            .send()
            .await
            .map_err(|err| http_err(err.to_string()))?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let response = response
            .error_for_status()
            .map_err(|err| http_err(err.to_string()))?;
        let body = response
            .text()
            .await
            .map_err(|err| http_err(err.to_string()))?;
        Ok(Some(body))
    }
}

/// The Homebrew adapter: one [`Adapter`](crate::adapter::Adapter)
/// implementation over the two per-item endpoints, serving both
/// [`SourceKind::HomebrewCask`] and [`SourceKind::HomebrewFormula`] rows —
/// [`Adapter::lookup`](crate::adapter::Adapter::lookup) dispatches on the
/// row's kind, and a cask-kind row whose token no cask answers falls
/// through to the formula lookup (brew's own token namespace is unified).
/// Gated behind the crate's `http` feature together with
/// [`HomebrewClient`] (DESIGN.md §9: the parsers build fully offline).
#[cfg(feature = "http")]
pub struct HomebrewAdapter {
    client: HomebrewClient,
    index: tokio::sync::Mutex<Option<Arc<Vec<App>>>>,
}

#[cfg(feature = "http")]
impl HomebrewAdapter {
    /// Builds an adapter with a default-constructed [`HomebrewClient`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            client: HomebrewClient::new(),
            index: tokio::sync::Mutex::new(None),
        }
    }

    /// Builds an adapter caching its catalog indexes under
    /// `cache_dir/homebrew/` (see [`HomebrewClient::with_cache_dir`]).
    #[must_use]
    pub fn with_cache_dir(cache_dir: impl Into<camino::Utf8PathBuf>) -> Self {
        Self {
            client: HomebrewClient::with_cache_dir(cache_dir),
            index: tokio::sync::Mutex::new(None),
        }
    }

    async fn index_apps(&self) -> Result<Arc<Vec<App>>> {
        let mut guard = self.index.lock().await;
        if let Some(apps) = guard.as_ref() {
            return Ok(Arc::clone(apps));
        }
        let casks = parse_cask_index(&self.client.fetch_cask_index().await?)?;
        let formulae = parse_formula_index(&self.client.fetch_formula_index().await?)?;
        let apps = Arc::new(formulae.into_iter().chain(casks).collect::<Vec<App>>());
        *guard = Some(Arc::clone(&apps));
        Ok(apps)
    }
}

#[cfg(feature = "http")]
impl Default for HomebrewAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "http")]
#[async_trait::async_trait]
impl crate::adapter::Adapter for HomebrewAdapter {
    fn source(&self) -> SourceKind {
        // The adapter serves both Homebrew kinds; this names the primary
        // one, while `lookup` dispatches on the SourceRef's own kind.
        SourceKind::HomebrewCask
    }

    async fn lookup(&self, id: &SourceRef) -> Result<Option<App>> {
        match id.source {
            SourceKind::HomebrewCask => match self.client.fetch_cask_optional(&id.id).await? {
                Some(body) => parse_cask_json(&body).map(Some),
                None => match self.client.fetch_formula_optional(&id.id).await? {
                    Some(body) => parse_formula_json(&body).map(Some),
                    None => Ok(None),
                },
            },
            SourceKind::HomebrewFormula => {
                match self.client.fetch_formula_optional(&id.id).await? {
                    None => Ok(None),
                    Some(body) => parse_formula_json(&body).map(Some),
                }
            }
            other => Err(Error::UnsupportedSource {
                kind: other,
                id: id.id.clone(),
            }),
        }
    }

    /// Searches the cached cask+formula index through [`search_index`] —
    /// the first search pays the catalog download, later ones are
    /// in-memory. Errors: [`Error::Http`] / [`Error::Parse`].
    async fn search(&self, query: &str) -> Result<Vec<App>> {
        let index = self.index_apps().await?;
        Ok(search_index(&index, query))
    }
}

// ---------------------------------------------------------------------------
// Tests — parse half against the frozen fixtures (offline)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Manifest-dir-anchored fixture loading (conventions.md §7 — runtime
    /// read via `env!("CARGO_MANIFEST_DIR")`, deliberately not
    /// `include_str!`).
    fn read_fixture(name: &str) -> String {
        let path = std::path::Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/homebrew"
        ))
        .join(name);
        std::fs::read_to_string(&path)
            .unwrap_or_else(|err| panic!("failed to read fixture `{}`: {err}", path.display()))
    }

    fn sha(digest: &str) -> Checksum {
        Checksum {
            algo: ChecksumAlgo::Sha256,
            digest: digest.to_owned(),
        }
    }

    fn platform(os: Os, arch: Arch, min_release: Option<&str>) -> Platform {
        Platform {
            os,
            arch: Some(arch),
            min_release: min_release.map(str::to_owned),
        }
    }

    fn artifact(
        url: &str,
        digest: Option<&str>,
        os: Option<Os>,
        arch: Option<Arch>,
        kind: ArtifactKind,
    ) -> Artifact {
        Artifact {
            url: url.to_owned(),
            checksum: digest.map(sha),
            os,
            arch,
            kind,
        }
    }

    #[test]
    fn brave_cask_yields_two_platforms_and_two_artifacts() {
        let app = parse_cask_json(&read_fixture("cask-brave-browser.json"))
            .expect("brave fixture must parse");

        // Identity + install descriptor.
        assert_eq!(app.id.as_str(), "brave-browser");
        assert_eq!(app.name, "Brave");
        assert!(app.aliases.is_empty());
        assert_eq!(
            app.summary.as_deref(),
            Some("Web browser focusing on privacy")
        );
        assert_eq!(app.homepage.as_deref(), Some("https://brave.com/"));
        assert_eq!(
            app.install,
            InstallMethod::Homebrew {
                cask: true,
                token: "brave-browser".to_owned()
            }
        );
        assert_eq!(
            app.latest.as_ref().map(|v| v.value.as_str()),
            Some("1.96.59.0")
        );
        assert_eq!(app.availability, Availability::Available);
        assert_eq!(
            app.sources,
            vec![SourceRef {
                source: SourceKind::HomebrewCask,
                id: "brave-browser".to_owned(),
                repo: None,
                version: app.latest.clone(),
                provisional: false,
            }]
        );

        // Platforms: 10 supported_platforms tags → 2 distinct (os, arch),
        // both carrying the depends_on.macos >= "13" floor; the two
        // *_linux keys carry explicit "sha256": null → NOT claimed.
        assert_eq!(
            app.platforms,
            vec![
                platform(Os::MacOs, Arch::X86_64, Some("13")),
                platform(Os::MacOs, Arch::Aarch64, Some("13")),
            ]
        );

        // Artifacts: the arm64 default + the 5 identical Intel-release
        // keys collapsed into one tuple = 2.
        assert_eq!(
            app.artifacts,
            vec![
                artifact(
                    "https://updates-cdn.bravesoftware.com/sparkle/Brave-Browser/stable-arm64/196.59/Brave-Browser-arm64.dmg",
                    Some("57690cf24e5ce5e15768b220d46621e575e0caabd3d651bdad5afc2b184f118a"),
                    Some(Os::MacOs),
                    None,
                    ArtifactKind::Package,
                ),
                artifact(
                    "https://updates-cdn.bravesoftware.com/sparkle/Brave-Browser/stable/196.59/Brave-Browser-x64.dmg",
                    Some("fbeca8107c308993d343cd33857f40ab1812d51ee0502ac86872aaf7e7f5bdd8"),
                    Some(Os::MacOs),
                    Some(Arch::X86_64),
                    ArtifactKind::Package,
                ),
            ]
        );

        // brave has no `binary` artifact stanza → no PATH binaries.
        assert!(app.binaries.is_empty());
    }

    #[test]
    fn vscode_cask_keeps_big_sur_tuples_and_collapses_to_four_artifacts() {
        let app = parse_cask_json(&read_fixture("cask-visual-studio-code.json"))
            .expect("vscode fixture must parse");

        assert_eq!(app.id.as_str(), "visual-studio-code");
        assert_eq!(app.name, "Microsoft Visual Studio Code");
        assert_eq!(app.aliases, vec!["VS Code".to_owned()]);
        assert_eq!(
            app.install,
            InstallMethod::Homebrew {
                cask: true,
                token: "visual-studio-code".to_owned()
            }
        );
        // Per-release versions (1.106.3 under big_sur/arm64_big_sur) are
        // dropped; latest stays the top-level default-platform version.
        assert_eq!(
            app.latest.as_ref().map(|v| v.value.as_str()),
            Some("1.139.1")
        );

        // Platforms: 14 tags → 2 claims; depends_on.macos is {} → no
        // min_release; both *_linux keys are sha256:null → not claimed.
        assert_eq!(
            app.platforms,
            vec![
                platform(Os::MacOs, Arch::X86_64, None),
                platform(Os::MacOs, Arch::Aarch64, None),
            ]
        );

        // 4 artifacts: default + arm64_big_sur (1.106.3, distinct tuple) +
        // big_sur (1.106.3, distinct X86_64 tuple) + the 6 identical
        // current Intel keys collapsed to one. The tuple rule keeps the
        // two 1.106.3 payloads even though 1.139.1 is "newer" (no version
        // ordering in wave 1, DESIGN.md §4.1 caveat 1).
        assert_eq!(
            app.artifacts,
            vec![
                artifact(
                    "https://update.code.visualstudio.com/1.139.1/darwin-arm64/stable",
                    Some("923080bebc194ec178c2a06b61bcb138376776406c23b8bd3e4fc3286f91cba2"),
                    Some(Os::MacOs),
                    None,
                    ArtifactKind::Package,
                ),
                artifact(
                    "https://update.code.visualstudio.com/1.106.3/darwin-arm64/stable",
                    Some("35dd438808dde1dd1f65490ffe7713ed64102324c0809efbec0b4eb2809b218b"),
                    Some(Os::MacOs),
                    Some(Arch::Aarch64),
                    ArtifactKind::Package,
                ),
                artifact(
                    "https://update.code.visualstudio.com/1.106.3/darwin/stable",
                    Some("c41872149a205f3a3be3e5d3a8f04920407a0762531e607f78dc93f4d4813cda"),
                    Some(Os::MacOs),
                    Some(Arch::X86_64),
                    ArtifactKind::Package,
                ),
                artifact(
                    "https://update.code.visualstudio.com/1.139.1/darwin/stable",
                    Some("7818d91a5cca2b7ae1557954923e8975cd6393526f9361091e40de02c2e2e58f"),
                    Some(Os::MacOs),
                    Some(Arch::X86_64),
                    ArtifactKind::Package,
                ),
            ]
        );

        // `binary` stanza payloads collapse to basenames, deduped, in
        // payload order.
        assert_eq!(
            app.binaries,
            vec!["code".to_owned(), "code-tunnel".to_owned()]
        );
    }

    #[test]
    fn ripgrep_formula_decodes_bottles_to_four_platforms_and_eight_artifacts() {
        let app = parse_formula_json(&read_fixture("formula-ripgrep.json"))
            .expect("ripgrep fixture must parse");

        assert_eq!(app.id.as_str(), "ripgrep");
        assert_eq!(app.name, "ripgrep");
        assert_eq!(app.aliases, vec!["rg".to_owned()]);
        assert_eq!(
            app.summary.as_deref(),
            Some("Search tool like grep and The Silver Searcher")
        );
        assert_eq!(app.license.as_deref(), Some("Unlicense"));
        assert_eq!(
            app.latest.as_ref().map(|v| v.value.as_str()),
            Some("15.2.0")
        );
        assert_eq!(
            app.install,
            InstallMethod::Homebrew {
                cask: false,
                token: "ripgrep".to_owned()
            }
        );
        assert_eq!(
            app.sources,
            vec![SourceRef {
                source: SourceKind::HomebrewFormula,
                id: "ripgrep".to_owned(),
                repo: None,
                version: app.latest.clone(),
                provisional: false,
            }]
        );

        // 7 bottle tags → 4 distinct (os, arch) claims; bottles declare no
        // minimum release.
        assert_eq!(
            app.platforms,
            vec![
                platform(Os::MacOs, Arch::X86_64, None),
                platform(Os::MacOs, Arch::Aarch64, None),
                platform(Os::Linux, Arch::X86_64, None),
                platform(Os::Linux, Arch::Aarch64, None),
            ]
        );

        // 7 bottle artifacts (one per tag) + 1 source archive.
        assert_eq!(app.artifacts.len(), 8);
        assert_eq!(
            app.artifacts
                .iter()
                .filter(|a| a.kind == ArtifactKind::Bottle)
                .count(),
            7
        );
        let sonoma = app
            .artifacts
            .iter()
            .find(|a| a.os == Some(Os::MacOs) && a.arch == Some(Arch::X86_64))
            .expect("Intel macOS bottle");
        assert_eq!(
            sonoma.url,
            "https://ghcr.io/v2/homebrew/core/ripgrep/blobs/sha256:9dd76bad725daf9ad1d4c983419e79ec92aefdae0cc9c92d465b424c8aea4808"
        );
        assert_eq!(
            sonoma.checksum,
            Some(sha(
                "9dd76bad725daf9ad1d4c983419e79ec92aefdae0cc9c92d465b424c8aea4808"
            ))
        );
        let arm64_linux = app
            .artifacts
            .iter()
            .find(|a| a.os == Some(Os::Linux) && a.arch == Some(Arch::Aarch64))
            .expect("arm64 Linux bottle");
        assert_eq!(arm64_linux.kind, ArtifactKind::Bottle);
        let source = app
            .artifacts
            .iter()
            .find(|a| a.kind == ArtifactKind::Source)
            .expect("source archive");
        assert_eq!(
            source.url,
            "https://github.com/BurntSushi/ripgrep/archive/refs/tags/15.2.0.tar.gz"
        );
        assert_eq!(
            source.checksum,
            Some(sha(
                "7605249d3eb0d5f170e3414498e3344e26b1e7a147aec518b57090b80036a562"
            ))
        );
        assert_eq!(source.os, None);
        assert_eq!(source.arch, None);

        // executables → binaries.
        assert_eq!(app.binaries, vec!["rg".to_owned()]);
    }

    #[test]
    fn absent_variation_keys_inherit_while_explicit_null_marks_unavailable() {
        // `sonoma` overrides only sha256 (url inherited), `ventura` is
        // explicitly null (unavailable), `big_sur` overrides nothing at
        // all — the absent-vs-null crux of §4.1 caveat 3.
        let payload = r#"{
            "token": "t", "name": ["T"], "version": "1.0",
            "url": "https://example.com/t.dmg", "sha256": "top",
            "supported_platforms": ["sonoma"],
            "variations": {
                "sonoma": {"sha256": "sonoma-sha"},
                "ventura": {"sha256": null},
                "big_sur": {}
            }
        }"#;
        let app = parse_cask_json(payload).expect("synthetic cask must parse");

        // Claims: supported_platforms ("sonoma") ∪ available keys
        // ("big_sur", "sonoma") → the single (MacOs, X86_64); "ventura" is
        // null → not claimed, and no artifact.
        assert_eq!(app.platforms, vec![platform(Os::MacOs, Arch::X86_64, None)]);
        assert_eq!(
            app.artifacts,
            vec![
                artifact(
                    "https://example.com/t.dmg",
                    Some("top"),
                    Some(Os::MacOs),
                    None,
                    ArtifactKind::Package,
                ),
                // big_sur {} inherits the whole triple → same url as the
                // default but a different (os, arch) → distinct tuple.
                artifact(
                    "https://example.com/t.dmg",
                    Some("top"),
                    Some(Os::MacOs),
                    Some(Arch::X86_64),
                    ArtifactKind::Package,
                ),
                // sonoma keeps the inherited url but overrides sha256 →
                // yet another distinct tuple.
                artifact(
                    "https://example.com/t.dmg",
                    Some("sonoma-sha"),
                    Some(Os::MacOs),
                    Some(Arch::X86_64),
                    ArtifactKind::Package,
                ),
            ]
        );
    }

    #[test]
    fn cask_binaries_are_deduped_basenames_in_payload_order() {
        let payload = r#"{
            "token": "b", "name": ["B"], "version": "1",
            "url": "https://example.com/b", "sha256": "x",
            "artifacts": [
                {"binary": ["$APPDIR/App.app/bin/code", "$APPDIR/App.app/bin/code",
                            "$APPDIR/App.app/bin/code-tunnel"]},
                {"app": ["B.app"], "target": "/Applications/B.app"},
                {"binary": ["plainbin"]},
                {"zap": [{"trash": ["~/Library/B"]}]}
            ]
        }"#;
        let app = parse_cask_json(payload).expect("synthetic cask must parse");
        assert_eq!(
            app.binaries,
            vec![
                "code".to_owned(),
                "code-tunnel".to_owned(),
                "plainbin".to_owned()
            ]
        );
    }

    #[test]
    fn cask_binary_stanzas_parse_the_live_string_and_target_map_shapes() {
        let payload = r#"{
            "token": "alacritty", "name": ["Alacritty"], "version": "1",
            "url": "https://example.com/a", "sha256": "x",
            "artifacts": [
                {"app": ["Alacritty.app"]},
                {"binary": ["$APPDIR/Alacritty.app/Contents/MacOS/alacritty",
                            {"target": "~/.terminfo/61/alacritty"}]},
                {"binary": [{"target": "/opt/homebrew/bin/extra"}, 42,
                            {"target": 7}, {"unrelated": "map"}]}
            ]
        }"#;
        let app = parse_cask_json(payload).expect("the live mixed shapes must parse");
        assert_eq!(
            app.binaries,
            vec!["alacritty".to_owned(), "extra".to_owned(),],
            "string payloads and target-map payloads yield basenames; \
             non-string targets and other values are skipped"
        );

        let index = format!("[{payload}]");
        let apps = parse_cask_index(&index).expect("the live shapes parse in the index too");
        assert_eq!(apps.len(), 1);
        assert_eq!(apps[0].binaries, app.binaries);
    }

    #[test]
    fn formula_without_bottle_has_unknown_platforms_and_only_a_source_artifact() {
        let payload = r#"{
            "name": "tiny", "versions": {"stable": "0.1.0"},
            "urls": {"stable": {"url": "https://example.com/tiny-0.1.0.tar.gz",
                                "checksum": "ab"}},
            "bottle": false, "executables": ["tiny"]
        }"#;
        let app = parse_formula_json(payload).expect("synthetic formula must parse");
        assert!(
            app.platforms.is_empty(),
            "bottle: false → platforms [] (unknown)"
        );
        assert_eq!(
            app.artifacts,
            vec![artifact(
                "https://example.com/tiny-0.1.0.tar.gz",
                Some("ab"),
                None,
                None,
                ArtifactKind::Source,
            )]
        );
        assert_eq!(app.latest.as_ref().map(|v| v.value.as_str()), Some("0.1.0"));
        assert_eq!(app.binaries, vec!["tiny".to_owned()]);
    }

    #[test]
    fn formula_source_row_keys_on_name_not_tap_qualified_full_name() {
        // DESIGN.md §4.2 pins `sources[] += {HomebrewFormula, name}`: the
        // row id is what `lookup` feeds to /api/formula/{id}.json, so a
        // tap-qualified `full_name` there would 404 the round-trip. The
        // frozen fixture has name == full_name, so pin the divergence
        // synthetically.
        let payload = r#"{
            "name": "tiny", "full_name": "user/tap/tiny",
            "versions": {"stable": "0.1.0"}
        }"#;
        let app = parse_formula_json(payload).expect("synthetic formula must parse");
        assert_eq!(app.sources[0].id, "tiny", "row id = `name`, not full_name");
        assert_eq!(app.id.as_str(), "tiny");
        assert_eq!(
            app.install,
            InstallMethod::Homebrew {
                cask: false,
                token: "tiny".to_owned(),
            },
            "install token keys on `name` too"
        );
    }

    #[test]
    fn deprecated_and_disabled_flags_map_to_availability() {
        let base = |extra: &str| {
            format!(
                r#"{{"token":"d","name":["D"],"version":"1",
                    "url":"https://example.com/d","sha256":"x"{extra}}}"#
            )
        };
        let available = parse_cask_json(&base("")).expect("parses");
        assert_eq!(available.availability, Availability::Available);

        let deprecated = parse_cask_json(&base(r#","deprecated":true"#)).expect("parses");
        assert_eq!(deprecated.availability, Availability::Deprecated);

        // `disabled` wins: a disabled cask cannot be installed at all.
        let disabled =
            parse_cask_json(&base(r#","deprecated":true,"disabled":true"#)).expect("parses");
        assert_eq!(disabled.availability, Availability::Disabled);
    }

    #[test]
    fn malformed_payloads_are_parse_errors_naming_the_source_id() {
        let err = parse_cask_json("{ definitely not json").expect_err("must fail");
        match err {
            Error::Parse { kind, id, .. } => {
                assert_eq!(kind, "json");
                assert_eq!(id, "", "no token is readable from garbage");
            }
            other => panic!("expected Error::Parse, got {other:?}"),
        }

        // A well-formed object with a readable token still names it.
        let err = parse_cask_json(r#"{"token":"known-token","artifacts":"not-a-list"}"#)
            .expect_err("type mismatch must fail");
        match err {
            Error::Parse { id, .. } => assert_eq!(id, "known-token"),
            other => panic!("expected Error::Parse, got {other:?}"),
        }

        // Wrong JSON types for the whole payload are errors. (Note serde's
        // derived struct visitor also accepts sequences positionally, so
        // `"[]"` would parse to an all-defaults struct rather than error —
        // tolerable, but not an error case.)
        assert!(parse_formula_json("42").is_err());
        assert!(parse_formula_json("\"a string\"").is_err());
    }

    #[test]
    fn platform_tags_decode_across_the_surveyed_vocabulary() {
        use decode_platform_tag as decode;
        assert_eq!(decode("sonoma"), Some((Os::MacOs, Arch::X86_64)));
        assert_eq!(decode("golden_gate"), Some((Os::MacOs, Arch::X86_64)));
        assert_eq!(
            decode("arm64_golden_gate"),
            Some((Os::MacOs, Arch::Aarch64))
        );
        assert_eq!(decode("arm64_big_sur"), Some((Os::MacOs, Arch::Aarch64)));
        assert_eq!(decode("x86_64_linux"), Some((Os::Linux, Arch::X86_64)));
        assert_eq!(decode("arm64_linux"), Some((Os::Linux, Arch::Aarch64)));
        assert_eq!(decode("x86_linux"), Some((Os::Linux, Arch::X86)));
        assert_eq!(decode("mips_linux"), None, "undecodable arch → skipped");
    }

    fn index_app(token: &str, name: &str, aliases: &[&str], summary: Option<&str>) -> App {
        App {
            id: TorideId::slugify(token),
            name: name.to_owned(),
            aliases: aliases.iter().map(|alias| (*alias).to_owned()).collect(),
            summary: summary.map(str::to_owned),
            description: None,
            homepage: None,
            license: None,
            developer: None,
            binaries: Vec::new(),
            latest: None,
            platforms: Vec::new(),
            artifacts: Vec::new(),
            install: InstallMethod::Homebrew {
                cask: false,
                token: token.to_owned(),
            },
            sources: Vec::new(),
            availability: Availability::Available,
        }
    }

    fn install_tokens(apps: &[App]) -> Vec<String> {
        apps.iter()
            .map(|app| match &app.install {
                InstallMethod::Homebrew { token, .. } => token.clone(),
                other => panic!("expected a homebrew install method, got {other:?}"),
            })
            .collect()
    }

    #[test]
    fn cask_index_parse_matches_the_per_item_parser() {
        let brave = read_fixture("cask-brave-browser.json");
        let vscode = read_fixture("cask-visual-studio-code.json");
        let index = format!("[{},{}]", brave.trim(), vscode.trim());
        let apps = parse_cask_index(&index).expect("index of fixtures parses");
        assert_eq!(
            apps,
            vec![
                parse_cask_json(&brave).expect("brave parses"),
                parse_cask_json(&vscode).expect("vscode parses"),
            ]
        );
    }

    #[test]
    fn formula_index_parse_matches_the_per_item_parser() {
        let ripgrep = read_fixture("formula-ripgrep.json");
        let index = format!("[{}]", ripgrep.trim());
        let apps = parse_formula_index(&index).expect("index of fixtures parses");
        assert_eq!(
            apps,
            vec![parse_formula_json(&ripgrep).expect("ripgrep parses")]
        );
    }

    #[test]
    fn index_parse_skips_entries_without_a_readable_id() {
        let casks = parse_cask_index(r#"[{"token":"real","name":["Real"]},{"name":["Ghost"]}]"#)
            .expect("synthetic cask index parses");
        assert_eq!(install_tokens(&casks), ["real".to_owned()]);

        let formulae = parse_formula_index(
            r#"[{"name":"real"},{"full_name":""},{"versions":{"stable":"1"}}]"#,
        )
        .expect("synthetic formula index parses");
        assert_eq!(install_tokens(&formulae), ["real".to_owned()]);
    }

    #[test]
    fn index_parse_errors_name_the_index() {
        let error = parse_cask_index("{ definitely not json").expect_err("must fail");
        match error {
            Error::Parse { kind, id, .. } => {
                assert_eq!(kind, "json");
                assert_eq!(id, "cask-index");
            }
            other => panic!("expected Error::Parse, got {other:?}"),
        }
        let error = parse_formula_index("42").expect_err("must fail");
        match error {
            Error::Parse { id, .. } => assert_eq!(id, "formula-index"),
            other => panic!("expected Error::Parse, got {other:?}"),
        }
    }

    #[test]
    fn search_ranks_exact_prefix_then_substring_with_id_ties() {
        let apps = vec![
            index_app("ripgrep", "ripgrep", &["rg"], Some("Search tool like grep")),
            index_app(
                "visual-studio-code",
                "Microsoft Visual Studio Code",
                &[],
                None,
            ),
            index_app("grep", "grep", &[], None),
            index_app("code", "Code", &[], None),
        ];
        assert_eq!(
            install_tokens(&search_index(&apps, "code")),
            ["code".to_owned(), "visual-studio-code".to_owned()],
            "exact token first, then the substring hit"
        );
        assert_eq!(
            install_tokens(&search_index(&apps, "RIP")),
            ["ripgrep".to_owned()],
            "prefix matches are case-insensitive"
        );
        assert_eq!(
            install_tokens(&search_index(&apps, "rg")),
            ["ripgrep".to_owned()],
            "aliases match at the substring tier"
        );
        assert_eq!(
            install_tokens(&search_index(&apps, "search tool like grep")),
            ["ripgrep".to_owned()],
            "summaries match at the substring tier"
        );
        assert!(search_index(&apps, "nothing-matches").is_empty());
        assert!(search_index(&apps, "").is_empty());
        assert!(search_index(&apps, "   ").is_empty());
    }

    #[test]
    fn search_matches_free_text_queries_word_by_word() {
        let apps = vec![
            index_app(
                "firefox",
                "Mozilla Firefox",
                &[],
                Some("The fast, private web browser"),
            ),
            index_app("code", "Code", &[], None),
            index_app(
                "visual-studio-code",
                "Microsoft Visual Studio Code",
                &[],
                None,
            ),
        ];
        assert_eq!(
            install_tokens(&search_index(&apps, "firefox browser")),
            ["firefox".to_owned()],
            "each word matches a different field of the same app"
        );
        assert_eq!(
            install_tokens(&search_index(&apps, "VISUAL   studio\tcode")),
            ["visual-studio-code".to_owned()],
            "whitespace-separated words, any casing"
        );
        assert!(
            search_index(&apps, "firefox spreadsheet").is_empty(),
            "every word must match — one unmatched word excludes the app"
        );
        assert_eq!(
            install_tokens(&search_index(&apps, "studio code")),
            ["visual-studio-code".to_owned()],
            "'code' alone matches the bare code app, but 'studio' excludes it"
        );
    }

    #[test]
    fn search_caps_at_max_hits() {
        let apps: Vec<App> = (0..60)
            .map(|number| index_app(&format!("tool-{number:02}"), "Synthetic Tool", &[], None))
            .collect();
        let hits = search_index(&apps, "tool");
        assert_eq!(hits.len(), MAX_SEARCH_HITS);
        assert_eq!(install_tokens(&hits)[0], "tool-00".to_owned());
    }
}

#[cfg(all(test, feature = "http"))]
mod index_cache_tests {
    use super::{
        HomebrewAdapter, INDEX_CACHE_TTL, part_path, probe_index_cache, write_index_cache,
    };
    use crate::adapter::Adapter as _;

    const SYNTHETIC_CASK_INDEX: &str = r#"[{"token":"toride-probe-cask","name":["Toride Probe Cask"],"version":"1.0","desc":"Synthetic cask for offline cache tests","artifacts":[{"binary":["$APPDIR/Probe.app/Contents/MacOS/toride-probe-bin",{"target":"/opt/homebrew/bin/toride-probe-target"}]}]}]"#;
    const SYNTHETIC_FORMULA_INDEX: &str = r#"[{"name":"toride-probe-formula","versions":{"stable":"0.1.0"},"desc":"Synthetic formula for offline cache tests"}]"#;

    fn scratch(label: &str) -> camino::Utf8PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "toride-registry-homebrew-{}-{label}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch dir creatable");
        camino::Utf8PathBuf::from_path_buf(dir).expect("temp path is UTF-8")
    }

    fn seed(dir: &camino::Utf8PathBuf) {
        std::fs::create_dir_all(dir.join("homebrew")).expect("cache dir creatable");
        std::fs::write(dir.join("homebrew/cask.json"), SYNTHETIC_CASK_INDEX)
            .expect("cask index seedable");
        std::fs::write(dir.join("homebrew/formula.json"), SYNTHETIC_FORMULA_INDEX)
            .expect("formula index seedable");
    }

    #[tokio::test]
    async fn search_serves_a_fresh_seeded_cache_with_no_network() {
        let dir = scratch("serve");
        seed(&dir);
        let adapter = HomebrewAdapter::with_cache_dir(&dir);
        let hits = adapter
            .search("probe")
            .await
            .expect("cache serves the query");
        let ids: Vec<&str> = hits.iter().map(|app| app.id.as_str()).collect();
        assert_eq!(
            ids,
            ["toride-probe-cask", "toride-probe-formula"],
            "only the seeded synthetic index can answer with these tokens"
        );
        assert_eq!(
            hits[0].binaries,
            [
                "toride-probe-bin".to_owned(),
                "toride-probe-target".to_owned()
            ],
            "the seeded mixed string/target-map binary stanza parses through the cache path"
        );
    }

    #[tokio::test]
    async fn search_keeps_answering_from_memory_after_the_cache_dir_is_deleted() {
        let dir = scratch("memo");
        seed(&dir);
        let adapter = HomebrewAdapter::with_cache_dir(&dir);
        let first: Vec<String> = adapter
            .search("probe")
            .await
            .expect("first search loads the index")
            .iter()
            .map(|app| app.id.as_str().to_owned())
            .collect();
        std::fs::remove_dir_all(&dir).expect("scratch dir removable");
        let second: Vec<String> = adapter
            .search("probe")
            .await
            .expect("second search serves memory")
            .iter()
            .map(|app| app.id.as_str().to_owned())
            .collect();
        assert_eq!(first, second, "the in-memory index outlives the disk cache");
    }

    #[test]
    fn probe_is_mtime_keyed() {
        let dir = scratch("probe");
        let path = dir.join("cask.json");
        assert_eq!(
            probe_index_cache(&path, INDEX_CACHE_TTL, std::time::SystemTime::now()),
            None,
            "nothing cached yet"
        );
        std::fs::write(&path, "body").expect("probe file writable");
        let mtime = std::fs::metadata(&path)
            .and_then(|metadata| metadata.modified())
            .expect("mtime readable");
        assert_eq!(
            probe_index_cache(&path, INDEX_CACHE_TTL, mtime),
            Some("body".to_owned()),
            "a zero-age entry is fresh"
        );
        assert_eq!(
            probe_index_cache(&path, INDEX_CACHE_TTL, mtime + INDEX_CACHE_TTL),
            None,
            "an entry as old as the TTL is stale"
        );
    }

    #[test]
    fn write_creates_parents_and_leaves_no_part_file() {
        let dir = scratch("write");
        let path = dir.join("nested/homebrew/cask.json");
        write_index_cache(&path, "[]").expect("cache write succeeds");
        assert_eq!(
            std::fs::read_to_string(&path).expect("written payload readable"),
            "[]"
        );
        let leftovers: Vec<String> = std::fs::read_dir(path.parent().expect("parent exists"))
            .expect("cache dir listable")
            .filter_map(std::result::Result::ok)
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| name.contains(".part"))
            .collect();
        assert!(
            leftovers.is_empty(),
            "the atomic rename consumed the part file: {leftovers:?}"
        );
    }

    #[test]
    fn part_paths_differ_per_call_so_processes_never_share_one() {
        let dir = scratch("parts");
        let path = dir.join("homebrew/cask.json");
        let first = part_path(&path);
        let second = part_path(&path);
        assert_ne!(first, second, "each write gets its own part file");
        assert!(first.file_name().unwrap().contains(".part"));
    }

    #[test]
    fn concurrent_writers_each_publish_a_whole_body() {
        let dir = scratch("writers");
        std::fs::create_dir_all(&dir).expect("scratch dir creatable");
        let path = dir.join("homebrew/cask.json");
        let body = "[".to_owned() + &"x".repeat(100_000) + "]";
        let writers: Vec<_> = (0..4)
            .map(|_| {
                let path = path.clone();
                let body = body.clone();
                std::thread::spawn(move || {
                    for _ in 0..8 {
                        write_index_cache(&path, &body).expect("each write publishes");
                    }
                })
            })
            .collect();
        for writer in writers {
            writer.join().expect("writer finishes");
        }
        let published = std::fs::read_to_string(&path).expect("a whole body is published");
        assert_eq!(
            published.len(),
            body.len(),
            "interleaved writers must never publish a mixed body"
        );
        let leftovers: Vec<String> = std::fs::read_dir(dir.join("homebrew"))
            .expect("cache dir listable")
            .filter_map(std::result::Result::ok)
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| name.contains(".part"))
            .collect();
        assert!(leftovers.is_empty(), "failed writes clean their parts");
    }
}

// ---------------------------------------------------------------------------
// Tests — fetch half, env-gated live round-trip (DESIGN.md §9)
// ---------------------------------------------------------------------------

#[cfg(all(test, feature = "http"))]
mod integration_tests {
    use super::*;
    use crate::adapter::Adapter as _;
    use crate::model::SourceKind;

    /// Live network tests run only under `TORIDE_REGISTRY_INTEGRATION=1`
    /// (conventions.md §7):
    /// `TORIDE_REGISTRY_INTEGRATION=1 cargo test -p toride-registry
    /// --features http`
    fn should_run() -> bool {
        matches!(
            std::env::var("TORIDE_REGISTRY_INTEGRATION").as_deref(),
            Ok("1")
        )
    }

    #[tokio::test]
    async fn live_cask_lookup_matches_the_frozen_invariant_set() {
        if !should_run() {
            eprintln!(
                "skipping live formulae.brew.sh test (set TORIDE_REGISTRY_INTEGRATION=1 to run)"
            );
            return;
        }
        let adapter = HomebrewAdapter::default();
        let row = SourceRef {
            source: SourceKind::HomebrewCask,
            id: "brave-browser".to_owned(),
            repo: None,
            version: None,
            provisional: false,
        };
        let app = adapter
            .lookup(&row)
            .await
            .expect("fetch must succeed")
            .expect("brave-browser exists upstream");

        // Invariant set of DESIGN.md §3.1 — never field-for-field equality
        // against the fixture frozen 2026-09-28 (cask `version` /
        // `generated_date` drift upstream immediately).
        assert_eq!(app.id.as_str(), "brave-browser");
        assert_eq!(app.name, "Brave");
        assert!(app.summary.is_some(), "desc stays populated");
        assert!(app.homepage.is_some(), "homepage stays populated");
        assert!(app.latest.is_some(), "version stays populated");
        assert_eq!(
            app.install,
            InstallMethod::Homebrew {
                cask: true,
                token: "brave-browser".to_owned()
            }
        );
        assert!(
            !app.artifacts.is_empty(),
            "the default-platform dmg stays published"
        );
        assert!(
            app.artifacts
                .iter()
                .all(|a| a.kind == ArtifactKind::Package),
            "cask artifacts are all dmg/pkg containers"
        );
        assert!(
            !app.platforms.is_empty(),
            "supported_platforms stays populated"
        );
        assert_eq!(
            app.sources,
            vec![SourceRef {
                source: SourceKind::HomebrewCask,
                id: "brave-browser".to_owned(),
                repo: None,
                version: app.latest.clone(),
                provisional: false,
            }]
        );

        // And the unknown-token path is `Ok(None)`, not an error.
        let missing = adapter
            .lookup(&SourceRef {
                source: SourceKind::HomebrewCask,
                id: "no-such-cask-toride-probe".to_owned(),
                repo: None,
                version: None,
                provisional: false,
            })
            .await
            .expect("404 must not error");
        assert!(missing.is_none());

        // A formula-only slug under the adapter's primary (cask) kind
        // falls through to the formula endpoint — the cask namespace miss
        // is not a source miss.
        let formula = adapter
            .lookup(&SourceRef {
                source: SourceKind::HomebrewCask,
                id: "ripgrep".to_owned(),
                repo: None,
                version: None,
                provisional: false,
            })
            .await
            .expect("fetch must succeed")
            .expect("the ripgrep formula answers the cask-kind ref");
        assert!(matches!(
            formula.install,
            crate::model::InstallMethod::Homebrew { cask: false, .. }
        ));
    }

    #[tokio::test]
    async fn live_search_finds_the_ripgrep_formula_through_the_cached_index() {
        if !should_run() {
            eprintln!(
                "skipping live formulae.brew.sh test (set TORIDE_REGISTRY_INTEGRATION=1 to run)"
            );
            return;
        }
        let dir = std::env::temp_dir().join(format!(
            "toride-registry-homebrew-live-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let cache_dir =
            camino::Utf8PathBuf::from_path_buf(dir.clone()).expect("temp path is UTF-8");
        let adapter = HomebrewAdapter::with_cache_dir(cache_dir);
        let hits = adapter
            .search("ripgrep")
            .await
            .expect("catalog indexes fetch");
        let ripgrep = hits
            .iter()
            .find(|app| app.id.as_str() == "ripgrep")
            .expect("the ripgrep formula is in the catalog");
        assert_eq!(
            ripgrep.install,
            crate::model::InstallMethod::Homebrew {
                cask: false,
                token: "ripgrep".to_owned()
            }
        );
        assert!(
            ripgrep.latest.is_some(),
            "the index carries the formula's version"
        );
        assert!(
            dir.join("homebrew/cask.json").exists() && dir.join("homebrew/formula.json").exists(),
            "both catalog payloads landed in the cache dir"
        );

        let browser_hits = adapter
            .search("firefox browser")
            .await
            .expect("the in-memory index serves follow-up searches");
        assert!(
            browser_hits.iter().any(|app| app.id.as_str() == "firefox"),
            "a free-text query matches per word across the cask's fields"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
