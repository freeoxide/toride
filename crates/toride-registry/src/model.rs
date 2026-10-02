//! # Normalized model
//!
//! The single shape downstream ever sees (DESIGN.md §2): [`App`] plus its
//! leaf types. Every external repository — Homebrew, Flathub,
//! `AppStream`/DEP-11, Repology — is squashed into these types by exactly one adapter,
//! so search, resolve, alias handling and install planning never touch a
//! source-specific wire struct.
//!
//! Everything here is `serde`-serializable (the normalized model doubles as
//! the cache and UI format) and `#[non_exhaustive]` where the set may grow
//! (new sources, new distro families, Windows later).
//!
//! Deliberately NOT in the model: categories/icons/screenshots/
//! verification badges (flathub `verification_verified` — distinct from
//! the modeled [`VerificationPolicy`])/popularity, local-state echoes
//! (`installed`, `outdated`, `pinned`), and
//! repology per-repo `status` (lives at parse level in the oracle). Versions
//! stay opaque strings — repology `origversion` suffixes and flathub
//! development releases are not semver, and cross-source comparison is the
//! oracle's job, not the model's.

use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};

/// Canonical toride app id — the slug every downstream subsystem keys on.
///
/// Rules: lowercase ASCII `[a-z0-9]` plus `-`; no leading, trailing, or
/// double hyphen; whitespace, `_`, and `.` collapse to `-`. Derived
/// (DESIGN.md §5) from `slugify(repology canonical project name)` when the
/// oracle knows the app, else `slugify` of the first source id that
/// produced the record.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct TorideId(String);

impl TorideId {
    /// Deterministic slug from any source id or display name: every
    /// character outside `[a-z0-9]` (including non-ASCII) becomes a
    /// separator, separators collapse, and leading/trailing separators
    /// are trimmed. Input with no ASCII alphanumeric at all (empty,
    /// punctuation-only, non-ASCII-only) falls back to the crate's
    /// degenerate-id marker `unnamed` — the alias layer's collision
    /// policy (DESIGN.md §5: same slug → merge/suffix by source) is what
    /// disambiguates distinct degenerate inputs. `slugify(s).parse()` is
    /// always `Ok`.
    ///
    /// # Examples
    ///
    /// ```
    /// use toride_registry::TorideId;
    ///
    /// assert_eq!(TorideId::slugify("Brave Browser").as_str(), "brave-browser");
    /// assert_eq!(TorideId::slugify("com.brave.Browser").as_str(), "com-brave-browser");
    /// // Leading/trailing separators are trimmed, never emitted:
    /// assert_eq!(TorideId::slugify("--brave--").as_str(), "brave");
    /// // No ASCII alphanumeric anywhere → the documented fallback:
    /// assert_eq!(TorideId::slugify("///").as_str(), "unnamed");
    /// ```
    #[must_use]
    pub fn slugify(input: &str) -> Self {
        let mut slug = String::with_capacity(input.len());
        for ch in input.chars() {
            match ch {
                'a'..='z' | '0'..='9' => slug.push(ch),
                'A'..='Z' => slug.push(ch.to_ascii_lowercase()),
                // Whitespace, `_`, `.`, and every other non-alphanumeric
                // collapse to the separator. The `is_empty()` guard trims
                // leading separators (nothing to separate yet); the
                // `ends_with('-')` guard collapses separator runs.
                _ => {
                    if !slug.is_empty() && !slug.ends_with('-') {
                        slug.push('-');
                    }
                }
            }
        }
        if slug.ends_with('-') {
            slug.pop();
        }
        // All-separator input trims to the empty id, which `parse`
        // (rightly) rejects; fall back so the parse-Ok invariant holds
        // for every input.
        if slug.is_empty() {
            slug.push_str("unnamed");
        }
        Self(slug)
    }

    /// Validated constructor — accepts exactly what [`TorideId::slugify`]
    /// would emit: non-empty, only `[a-z0-9-]`, no leading/trailing
    /// hyphen, no double hyphen. Use [`TorideId::slugify`] to normalize
    /// arbitrary input first.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidTorideId`] naming the first grammar rule
    /// the input violates.
    pub fn parse(input: &str) -> Result<Self> {
        let invalid = |reason: String| Error::InvalidTorideId {
            input: input.to_owned(),
            reason,
        };
        if input.is_empty() {
            return Err(invalid("empty".to_owned()));
        }
        if let Some(ch) = input
            .chars()
            .find(|ch| !matches!(ch, 'a'..='z' | '0'..='9' | '-'))
        {
            return Err(invalid(format!(
                "illegal character `{ch}`; allowed: a-z, 0-9, `-`"
            )));
        }
        if input.starts_with('-') {
            return Err(invalid("leading hyphen".to_owned()));
        }
        if input.ends_with('-') {
            return Err(invalid("trailing hyphen".to_owned()));
        }
        if input.contains("--") {
            return Err(invalid("double hyphen".to_owned()));
        }
        Ok(Self(input.to_owned()))
    }

    /// The canonical slug.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One normalized registry entry — the ONLY shape downstream ever sees.
///
/// Adapters emit one `App` per source record; the cross-source merge (same
/// slug + same homepage/developer → same app, merge [`App::sources`]) is
/// the alias layer's job (DESIGN.md §5), downstream of the adapter
/// boundary.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct App {
    /// Canonical toride id — the slug downstream subsystems key on.
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
    /// Project homepage.
    pub homepage: Option<String>,
    /// SPDX expression where the source publishes one.
    pub license: Option<String>,
    /// Developer/publisher, where the source names one.
    pub developer: Option<String>,
    /// Executable names the app puts on PATH (formula `executables`, DEP-11
    /// `Provides.binaries`). The join key for tool detection
    /// (appstream.md §5) — kept in the model for exactly that consumer.
    pub binaries: Vec<String>,
    /// Best-known version from this app's own sources.
    pub latest: Option<Version>,
    /// Where this app applies. Empty = the source declares nothing
    /// (treat as "unknown", NOT "universal"): install planning SKIPS the
    /// claim check for empty platforms instead of refusing, and the
    /// install method's own scope governs (DESIGN.md §3.3).
    pub platforms: Vec<Platform>,
    /// Published downloads with checksums where the source publishes them.
    pub artifacts: Vec<Artifact>,
    /// Primary install descriptor (see [`InstallMethod`]).
    pub install: InstallMethod,
    /// Per-source identity rows — the alias table's payload (DESIGN.md
    /// §5); a merged App carries one entry per source that knows it.
    pub sources: Vec<SourceRef>,
    /// Lifecycle: homebrew cask/formula `deprecated`/`disabled`
    /// (deprecated warns before install; disabled cannot install).
    /// Everything else → [`Availability::Available`].
    pub availability: Availability,
}

/// Lifecycle state declared by the source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum Availability {
    /// Installable; the default for every source that declares nothing.
    #[default]
    Available,
    /// The source warns before install (homebrew `deprecated: true`).
    Deprecated,
    /// The source refuses install (homebrew `disabled: true`).
    Disabled,
}

impl App {
    /// The best checksummed artifact for `os`/`arch` wrapped as an
    /// [`InstallMethod::Direct`] — exact (os, arch) match preferred,
    /// undeclared slots (`None`) as wildcards; `None` when no checksummed
    /// artifact matches (DESIGN.md §3.3).
    #[must_use]
    pub fn direct_fallback(&self, os: Os, arch: Option<Arch>) -> Option<InstallMethod> {
        let mut best: Option<(u8, &Artifact)> = None;
        for artifact in &self.artifacts {
            if artifact.checksum.is_none() {
                continue;
            }
            let os_rank = match artifact.os {
                Some(claimed) if claimed == os => 0,
                None => 1,
                Some(_) => continue,
            };
            let arch_rank = match (artifact.arch, arch) {
                (Some(claimed), Some(wanted)) if claimed == wanted => 0,
                (None, _) | (_, None) => 1,
                (Some(_), Some(_)) => continue,
            };
            let rank = os_rank + arch_rank;
            if best.is_none_or(|(best_rank, _)| rank < best_rank) {
                best = Some((rank, artifact));
            }
        }
        best.map(|(_, artifact)| InstallMethod::Direct {
            url: artifact.url.clone(),
            checksum: artifact.checksum.clone(),
            arch: artifact.arch,
        })
    }
}

/// A version as an opaque string plus the extras sources publish.
///
/// Deliberately no semver parsing in wave 1 (repology `origversion`
/// suffixes like `1.79.126-1` / `1.83.120-r0` are not semver); comparison
/// across sources is the oracle's job, not the model's.
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

/// Whether a source publishes checksums for the downloads it lists
/// (plan gap 3.12): `OutOfBand` marks an empty [`App::artifacts`] list
/// as unverifiable — demand an out-of-band digest, never a size floor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum VerificationPolicy {
    /// The source publishes a checksum beside its artifacts (homebrew
    /// sha256); an artifact with `checksum: None` here is an upstream gap
    /// for that one artifact, not a source-wide hole.
    Inline,
    /// The source publishes no checksums anywhere (flathub, DEP-11;
    /// repology lists no artifacts at all): every download from it is
    /// unverifiable against publisher material.
    OutOfBand,
}

impl SourceKind {
    /// The verification policy of every record this source publishes —
    /// a fact about the source, not about any one app.
    ///
    /// ```
    /// use toride_registry::{SourceKind, VerificationPolicy};
    ///
    /// assert_eq!(
    ///     SourceKind::HomebrewCask.verification_policy(),
    ///     VerificationPolicy::Inline
    /// );
    /// assert_eq!(
    ///     SourceKind::Flathub.verification_policy(),
    ///     VerificationPolicy::OutOfBand
    /// );
    /// ```
    #[must_use]
    pub const fn verification_policy(self) -> VerificationPolicy {
        match self {
            Self::HomebrewCask | Self::HomebrewFormula => VerificationPolicy::Inline,
            Self::Flathub | Self::Distro | Self::Repology => VerificationPolicy::OutOfBand,
        }
    }
}

/// One per-source identity: the join key between the toride world and a
/// source's native naming. Also the row format of the alias index
/// (DESIGN.md §5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceRef {
    /// Which adapter this row belongs to.
    pub source: SourceKind,
    /// Cask token / formula name / flatpak app id / distro package name /
    /// repology project name.
    pub id: String,
    /// Source-native repo scope where the source has more than one:
    /// DEP-11 `Origin` (`debian-sid-main`), repology repo id
    /// (`debian_13`, `fedora_rawhide`, `arch`, `alpine_edge`, `homebrew`).
    /// `None` for homebrew (token is unique) and flathub (`app_id` is
    /// unique).
    pub repo: Option<String>,
    /// The version this source currently reports, when captured.
    pub version: Option<Version>,
    /// True when this row was minted from a fallback rather than parsed
    /// from the source's own catalog — today only repology-minted
    /// `Distro` descriptors for families with no adapter (DESIGN.md §5).
    /// Persists through the alias index's JSON serialization;
    /// `#[serde(default)]` keeps older caches deserializable.
    #[serde(default)]
    pub provisional: bool,
}

/// Operating system applicability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Os {
    /// macOS (homebrew casks/formulae).
    MacOs,
    /// Linux (flathub, distro catalogs, formula bottles).
    Linux,
    /// Windows (wave 2 — winget).
    Windows,
}

/// CPU architecture applicability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Arch {
    /// amd64 / `x86_64`.
    X86_64,
    /// arm64 / aarch64 (Apple silicon, arm64 Linux bottles).
    Aarch64,
    /// 32-bit x86 (cask `variations` key `x86`).
    X86,
}

/// Platform applicability: an `(os, arch, min_release)` claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Platform {
    /// Operating system claimed.
    pub os: Os,
    /// `None` = arch-independent / undeclared (flathub `arches: null`).
    pub arch: Option<Arch>,
    /// Minimum OS release the source declares — cask
    /// `depends_on.macos.{">=":["13"]}` → `Some("13")` (brave fixture).
    pub min_release: Option<String>,
}

/// Hash algorithm of a published checksum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ChecksumAlgo {
    /// sha256, lowercase hex — the only algorithm any wave-1 source
    /// publishes (homebrew cask `sha256` + per-variation, formula bottle
    /// files; flathub and DEP-11 publish none at all).
    Sha256,
    /// sha512, lowercase hex — modeled so a source that publishes one
    /// needs no model change; no wave-1 adapter emits it yet.
    Sha512,
}

impl ChecksumAlgo {
    /// The exact hex length [`ChecksumAlgo::is_valid_digest`] demands:
    /// 64 for sha256, 128 for sha512.
    #[must_use]
    pub const fn digest_hex_len(self) -> usize {
        match self {
            Self::Sha256 => 64,
            Self::Sha512 => 128,
        }
    }

    /// True iff `digest` is exactly [`ChecksumAlgo::digest_hex_len`] hex
    /// digits (case-insensitive) — the same shape rule toride-installer's
    /// checksum-file parser applies. Store normalized to lowercase.
    #[must_use]
    pub fn is_valid_digest(self, digest: &str) -> bool {
        digest.len() == self.digest_hex_len() && digest.bytes().all(|b| b.is_ascii_hexdigit())
    }
}

/// A published checksum.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checksum {
    /// Which algorithm produced [`Checksum::digest`].
    pub algo: ChecksumAlgo,
    /// Lowercase hex digest.
    pub digest: String,
}

/// What kind of download an [`Artifact`] is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArtifactKind {
    /// OS package/installer container (cask `url`: dmg/pkg).
    Package,
    /// Prebuilt binary (formula bottle blob from ghcr.io).
    Bottle,
    /// Source archive (formula `urls.stable`).
    Source,
}

/// A published download, with a checksum where the source publishes one.
///
/// The `Option<Checksum>` is the honest encoding of wave-1 asymmetry:
/// homebrew publishes sha256 directly, flathub and DEP-11 publish none.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Artifact {
    /// Download URL.
    pub url: String,
    /// Checksum, when the source publishes one.
    pub checksum: Option<Checksum>,
    /// OS the artifact targets, when declared or decodable.
    pub os: Option<Os>,
    /// Arch the artifact targets; `None` = undeclared/arch-independent.
    pub arch: Option<Arch>,
    /// What kind of download this is.
    pub kind: ArtifactKind,
}

/// How to install — the descriptor install planning consumes. One variant
/// per install technology: brew token / flatpak ref / distro package per
/// family / direct URL / the language-ecosystem managers (npm, cargo, pipx,
/// uv, mise).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum InstallMethod {
    /// `brew install --cask <token>` (`cask: true`) or
    /// `brew install <name>` (`cask: false`).
    Homebrew {
        /// `true` for casks (`--cask`), `false` for formulae.
        cask: bool,
        /// Cask token or formula name.
        token: String,
    },
    /// `flatpak install <remote> <app_id>`; remote is `"flathub"` for the
    /// Flathub adapter (remote configured once from `flathub.flatpakrepo`).
    Flatpak {
        /// Dotted reverse-DNS app id (`com.brave.Browser`).
        app_id: String,
        /// Flatpak remote name (`"flathub"`).
        remote: String,
    },
    /// `<family>'s manager install <package>` scoped by repo; the family
    /// picks the manager (apt / dnf / pacman / apk). `repo` = DEP-11
    /// `Origin` (`debian-sid-main`) or repology subrepo where known.
    Distro {
        /// Distro family, which selects the manager.
        family: DistroFamily,
        /// Repo scope (`debian-sid-main`), when known.
        repo: Option<String>,
        /// Package name the family's manager knows.
        package: String,
    },
    /// Direct download + checksum verify for hosts without the native
    /// manager. No wave-1 adapter emits this variant: it is constructed at
    /// PLAN time by the `App::direct_fallback` helper (DESIGN.md §3.3)
    /// picking a matching checksummed `App::artifacts` entry; a stored
    /// Direct method on an `App` is a wave-2 decision.
    Direct {
        /// Download URL.
        url: String,
        /// Published checksum, when the artifact carries one.
        checksum: Option<Checksum>,
        /// Arch the artifact targets, when known.
        arch: Option<Arch>,
    },
    /// `npm install -g <package>[@<version>]` — the global CLI-tool scope.
    Npm {
        /// npm package name.
        package: String,
        /// Exact version pin; `None` takes the registry's current.
        version: Option<String>,
    },
    /// `cargo install [--version <v>] <crate>`.
    Cargo {
        /// Crate name as published on crates.io.
        crate_: String,
        /// Exact version pin; `None` takes the latest release.
        version: Option<String>,
    },
    /// `pipx install <package>` (pipx takes no version operand).
    Pipx {
        /// Python package name.
        package: String,
    },
    /// `uv tool install <package>[==<version>]`.
    Uv {
        /// Python package name.
        package: String,
        /// Exact version pin; `None` takes the latest release.
        version: Option<String>,
    },
    /// `mise install <tool>[@<version>]` plus `mise use --global`.
    Mise {
        /// mise tool name (`node`, `npm:prettier`, `cargo:ripgrep`).
        tool: String,
        /// Version constraint; `None` addresses `@latest`.
        version: Option<String>,
    },
}

/// Distro family — selects the native package manager for
/// [`InstallMethod::Distro`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum DistroFamily {
    /// Debian (apt; DEP-11 origin `debian*`).
    Debian,
    /// Ubuntu (apt; DEP-11 layout verified identical to Debian's).
    Ubuntu,
    /// Fedora (dnf; no wave-1 catalog adapter — DESIGN.md §6).
    Fedora,
    /// Arch (pacman; provisional repology-minted descriptors only).
    Arch,
    /// Alpine (apk; provisional repology-minted descriptors only).
    Alpine,
}

#[cfg(test)]
mod tests {
    use super::{
        App, Arch, Artifact, ArtifactKind, Checksum, ChecksumAlgo, InstallMethod, Os, SourceKind,
        TorideId, VerificationPolicy,
    };

    fn artifact(url: &str, digest: Option<&str>, os: Option<Os>, arch: Option<Arch>) -> Artifact {
        Artifact {
            url: url.to_owned(),
            checksum: digest.map(|digest| Checksum {
                algo: ChecksumAlgo::Sha256,
                digest: digest.to_owned(),
            }),
            os,
            arch,
            kind: ArtifactKind::Package,
        }
    }

    fn app_with(artifacts: Vec<Artifact>) -> App {
        App {
            id: TorideId::slugify("fixture"),
            name: "fixture".to_owned(),
            aliases: Vec::new(),
            summary: None,
            description: None,
            homepage: None,
            license: None,
            developer: None,
            binaries: Vec::new(),
            latest: None,
            platforms: Vec::new(),
            artifacts,
            install: InstallMethod::Homebrew {
                cask: false,
                token: "fixture".to_owned(),
            },
            sources: Vec::new(),
            availability: super::Availability::Available,
        }
    }

    #[test]
    fn direct_fallback_prefers_the_exact_os_and_arch_artifact() {
        let app = app_with(vec![
            artifact("https://example.com/any", Some("wild"), None, None),
            artifact(
                "https://example.com/mac-arm",
                Some("exact"),
                Some(Os::MacOs),
                Some(Arch::Aarch64),
            ),
            artifact(
                "https://example.com/mac",
                Some("os-only"),
                Some(Os::MacOs),
                None,
            ),
            artifact(
                "https://example.com/linux",
                Some("wrong-os"),
                Some(Os::Linux),
                Some(Arch::Aarch64),
            ),
        ]);
        assert_eq!(
            app.direct_fallback(Os::MacOs, Some(Arch::Aarch64)),
            Some(InstallMethod::Direct {
                url: "https://example.com/mac-arm".to_owned(),
                checksum: Some(Checksum {
                    algo: ChecksumAlgo::Sha256,
                    digest: "exact".to_owned(),
                }),
                arch: Some(Arch::Aarch64),
            })
        );
    }

    #[test]
    fn direct_fallback_uses_wildcards_when_no_exact_artifact_exists() {
        let app = app_with(vec![
            artifact(
                "https://example.com/no-sha",
                None,
                Some(Os::MacOs),
                Some(Arch::Aarch64),
            ),
            artifact(
                "https://example.com/os-any-arch",
                Some("os"),
                Some(Os::MacOs),
                None,
            ),
        ]);
        assert_eq!(
            app.direct_fallback(Os::MacOs, Some(Arch::Aarch64))
                .map(|method| match method {
                    InstallMethod::Direct { url, .. } => url,
                    other => panic!("expected Direct, got {other:?}"),
                }),
            Some("https://example.com/os-any-arch".to_owned())
        );
        assert!(
            app.direct_fallback(Os::Linux, Some(Arch::Aarch64))
                .is_none(),
            "no artifact claims or wildcards Linux"
        );
    }

    #[test]
    fn direct_fallback_skips_checksum_less_artifacts() {
        let app = app_with(vec![artifact(
            "https://example.com/unsigned",
            None,
            Some(Os::MacOs),
            Some(Arch::Aarch64),
        )]);
        assert_eq!(app.direct_fallback(Os::MacOs, Some(Arch::Aarch64)), None);
    }

    fn hex_row(ch: char, len: usize) -> String {
        std::iter::repeat_n(ch, len).collect()
    }

    #[test]
    fn digest_hex_len_matches_each_algo() {
        assert_eq!(ChecksumAlgo::Sha256.digest_hex_len(), 64);
        assert_eq!(ChecksumAlgo::Sha512.digest_hex_len(), 128);
    }

    #[test]
    fn digest_hex_len_is_pinned_to_the_installer_contract() {
        assert_eq!(
            ChecksumAlgo::Sha256.digest_hex_len(),
            toride_installer::SHA256_HEX_LEN,
            "the model and the installer parser/verifier must agree on sha256"
        );
        assert_eq!(
            ChecksumAlgo::Sha512.digest_hex_len(),
            toride_installer::SHA512_HEX_LEN,
            "the model and the installer parser/verifier must agree on sha512"
        );
    }

    #[test]
    fn is_valid_digest_accepts_exact_length_hex_either_case() {
        let hex_64 = hex_row('1', 64);
        let hex_128 = hex_row('2', 128);
        assert!(ChecksumAlgo::Sha256.is_valid_digest(&hex_64));
        assert!(ChecksumAlgo::Sha512.is_valid_digest(&hex_128));
        assert!(ChecksumAlgo::Sha256.is_valid_digest(&hex_64.to_uppercase()));
    }

    #[test]
    fn is_valid_digest_rejects_wrong_length_non_hex_and_empty() {
        let hex_63 = hex_row('1', 63);
        let hex_64 = hex_row('1', 64);
        let hex_129 = hex_row('2', 129);
        assert!(!ChecksumAlgo::Sha256.is_valid_digest(&hex_64.replace('1', "z")));
        assert!(!ChecksumAlgo::Sha256.is_valid_digest(""));
        assert!(!ChecksumAlgo::Sha256.is_valid_digest(&hex_63));
        assert!(!ChecksumAlgo::Sha512.is_valid_digest(&hex_129));
    }

    #[test]
    fn checksum_algo_serde_round_trips_both_variants() {
        for (algo, spelling) in [
            (ChecksumAlgo::Sha256, "\"Sha256\""),
            (ChecksumAlgo::Sha512, "\"Sha512\""),
        ] {
            assert_eq!(serde_json::to_string(&algo).unwrap(), spelling);
            let back: ChecksumAlgo = serde_json::from_str(spelling).unwrap();
            assert_eq!(back, algo);
        }
    }

    #[test]
    fn verification_policy_marks_checksum_publishers_inline() {
        assert_eq!(
            SourceKind::HomebrewCask.verification_policy(),
            VerificationPolicy::Inline
        );
        assert_eq!(
            SourceKind::HomebrewFormula.verification_policy(),
            VerificationPolicy::Inline
        );
    }

    #[test]
    fn verification_policy_marks_checksum_less_sources_out_of_band() {
        for source in [
            SourceKind::Flathub,
            SourceKind::Distro,
            SourceKind::Repology,
        ] {
            assert_eq!(
                source.verification_policy(),
                VerificationPolicy::OutOfBand,
                "{source:?} publishes no checksums"
            );
        }
    }

    #[test]
    fn verification_policy_serde_round_trips() {
        assert_eq!(
            serde_json::to_string(&VerificationPolicy::Inline).unwrap(),
            "\"Inline\""
        );
        let back: VerificationPolicy = serde_json::from_str("\"OutOfBand\"").unwrap();
        assert_eq!(back, VerificationPolicy::OutOfBand);
    }

    #[test]
    fn install_method_serde_round_trips_every_variant() {
        for (method, json) in [
            (
                InstallMethod::Homebrew {
                    cask: false,
                    token: "ripgrep".to_owned(),
                },
                r#"{"Homebrew":{"cask":false,"token":"ripgrep"}}"#,
            ),
            (
                InstallMethod::Flatpak {
                    app_id: "com.brave.Browser".to_owned(),
                    remote: "flathub".to_owned(),
                },
                r#"{"Flatpak":{"app_id":"com.brave.Browser","remote":"flathub"}}"#,
            ),
            (
                InstallMethod::Distro {
                    family: super::DistroFamily::Debian,
                    repo: None,
                    package: "firefox".to_owned(),
                },
                r#"{"Distro":{"family":"Debian","repo":null,"package":"firefox"}}"#,
            ),
            (
                InstallMethod::Direct {
                    url: "https://example.com/rg".to_owned(),
                    checksum: None,
                    arch: None,
                },
                r#"{"Direct":{"url":"https://example.com/rg","checksum":null,"arch":null}}"#,
            ),
            (
                InstallMethod::Npm {
                    package: "typescript".to_owned(),
                    version: Some("5.4.5".to_owned()),
                },
                r#"{"Npm":{"package":"typescript","version":"5.4.5"}}"#,
            ),
            (
                InstallMethod::Cargo {
                    crate_: "ripgrep".to_owned(),
                    version: None,
                },
                r#"{"Cargo":{"crate_":"ripgrep","version":null}}"#,
            ),
            (
                InstallMethod::Pipx {
                    package: "black".to_owned(),
                },
                r#"{"Pipx":{"package":"black"}}"#,
            ),
            (
                InstallMethod::Uv {
                    package: "ruff".to_owned(),
                    version: Some("0.6.0".to_owned()),
                },
                r#"{"Uv":{"package":"ruff","version":"0.6.0"}}"#,
            ),
            (
                InstallMethod::Mise {
                    tool: "node".to_owned(),
                    version: Some("22.1.0".to_owned()),
                },
                r#"{"Mise":{"tool":"node","version":"22.1.0"}}"#,
            ),
        ] {
            assert_eq!(serde_json::to_string(&method).unwrap(), json);
            let back: InstallMethod = serde_json::from_str(json).unwrap();
            assert_eq!(back, method);
        }
    }

    #[test]
    fn install_method_reads_pre_language_variant_documents_identically() {
        let legacy: [(&str, InstallMethod); 4] = [
            (
                r#"{"Homebrew":{"cask":true,"token":"firefox"}}"#,
                InstallMethod::Homebrew {
                    cask: true,
                    token: "firefox".to_owned(),
                },
            ),
            (
                r#"{"Flatpak":{"app_id":"com.brave.Browser","remote":"flathub"}}"#,
                InstallMethod::Flatpak {
                    app_id: "com.brave.Browser".to_owned(),
                    remote: "flathub".to_owned(),
                },
            ),
            (
                r#"{"Distro":{"family":"Alpine","repo":"alpine-edge-main","package":"ripgrep"}}"#,
                InstallMethod::Distro {
                    family: super::DistroFamily::Alpine,
                    repo: Some("alpine-edge-main".to_owned()),
                    package: "ripgrep".to_owned(),
                },
            ),
            (
                r#"{"Direct":{"url":"https://example.com/rg","checksum":null,"arch":null}}"#,
                InstallMethod::Direct {
                    url: "https://example.com/rg".to_owned(),
                    checksum: None,
                    arch: None,
                },
            ),
        ];
        for (json, method) in legacy {
            let back: InstallMethod = serde_json::from_str(json).unwrap();
            assert_eq!(back, method, "{json}");
        }
    }

    #[test]
    fn slugify_trims_leading_and_trailing_separators() {
        assert_eq!(TorideId::slugify("--brave").as_str(), "brave");
        assert_eq!(TorideId::slugify(" brave ").as_str(), "brave");
        assert_eq!(TorideId::slugify("...brave...").as_str(), "brave");
        assert_eq!(
            TorideId::slugify("::Brave::Browser::").as_str(),
            "brave-browser"
        );
    }

    #[test]
    fn slugify_all_separator_input_falls_back_to_unnamed() {
        assert_eq!(TorideId::slugify("///").as_str(), "unnamed");
        assert_eq!(TorideId::slugify("日本語").as_str(), "unnamed");
        assert_eq!(TorideId::slugify("").as_str(), "unnamed");
    }

    #[test]
    fn slugify_output_always_parses() {
        // The documented invariant (`slugify(s).parse()` is always `Ok`;
        // error.rs: `slugify` never produces `InvalidTorideId`) over the
        // inputs that used to violate it: leading separators,
        // all-separator, non-ASCII-only, and empty.
        for input in ["--brave", "///", "日本語", "", "   ", "-.-", ":::"] {
            let id = TorideId::slugify(input);
            TorideId::parse(id.as_str()).unwrap_or_else(|error| {
                panic!("slugify({input:?}) = {:?} must parse: {error}", id.as_str())
            });
        }
    }
}
