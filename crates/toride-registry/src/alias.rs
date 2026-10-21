//! The alias layer (DESIGN.md §5): cross-source [`App`] merging by alias
//! and the canonical-id → per-source-rows [`AliasIndex`] that resolve
//! falls back on when primary lookups miss.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::model::{App, SourceKind, SourceRef, TorideId};

/// The alias table (DESIGN.md §5): one row set per canonical [`TorideId`],
/// persisted as JSON (a `BTreeMap`, so the serialization is deterministic).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AliasIndex {
    rows: BTreeMap<TorideId, Vec<SourceRef>>,
}

impl AliasIndex {
    /// An empty index.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The rows recorded for `id`: empty when the index never saw it.
    #[must_use]
    pub fn get(&self, id: &TorideId) -> &[SourceRef] {
        self.rows.get(id).map_or(&[], Vec::as_slice)
    }

    /// Union `rows` into `id`'s entry, deduplicated by
    /// `(source, id, repo)`.
    pub fn insert(&mut self, id: &TorideId, rows: impl IntoIterator<Item = SourceRef>) {
        union_rows(self.rows.entry(id.clone()).or_default(), rows);
    }

    /// Record `app`'s own [`App::sources`] rows under its canonical id.
    pub fn record(&mut self, app: &App) {
        self.insert(&app.id, app.sources.iter().cloned());
    }

    /// How many canonical ids the index carries rows for.
    #[must_use]
    pub fn len(&self) -> usize {
        self.rows.len()
    }

    /// Whether the index carries no rows at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }
}

/// One surviving row inside [`merge_hits`]: its bucket origin, the row
/// itself, and its lazily-memoized slugified name set. The memo is built on
/// first name comparison and invalidated only when `absorb` actually grows
/// the alias set, so join decisions stay identical to recomputing per pair
/// while the pairing loop stops re-slugifying names it never compares.
struct MergedRow {
    origin: usize,
    app: App,
    names: Option<Vec<TorideId>>,
}

pub(crate) fn merge_hits(buckets: impl IntoIterator<Item = Vec<App>>) -> Vec<App> {
    let mut merged: Vec<MergedRow> = Vec::new();
    for (origin, bucket) in buckets.into_iter().enumerate() {
        for mut hit in bucket {
            let mut hit_names: Option<Vec<TorideId>> = None;
            let joinable = merged.iter_mut().position(|row| {
                if row.origin == origin {
                    return false;
                }
                match join_preface(&row.app, &hit) {
                    JoinPreface::Joined => true,
                    JoinPreface::Apart => false,
                    JoinPreface::ByName => {
                        let names = hit_names.get_or_insert_with(|| join_names(&hit));
                        row.names
                            .get_or_insert_with(|| join_names(&row.app))
                            .iter()
                            .any(|name| names.contains(name))
                    }
                }
            });
            if let Some(index) = joinable {
                if absorb(&mut merged[index].app, hit) {
                    merged[index].names = None;
                }
            } else {
                disambiguate(&mut hit, &merged);
                merged.push(MergedRow {
                    origin,
                    app: hit,
                    names: hit_names,
                });
            }
        }
    }
    merged.into_iter().map(|row| row.app).collect()
}

fn disambiguate(hit: &mut App, merged: &[MergedRow]) {
    let Some(key) = source_key(hit) else {
        return;
    };
    while merged.iter().any(|row| row.app.id == hit.id) {
        let suffixed = format!("{}-{key}", hit.id.as_str());
        hit.id = TorideId::slugify(&suffixed);
    }
}

fn source_key(app: &App) -> Option<&'static str> {
    app.sources.first().map(|row| source_kind_key(row.source))
}

fn source_kind_key(source: SourceKind) -> &'static str {
    match source {
        SourceKind::HomebrewCask => "cask",
        SourceKind::HomebrewFormula => "formula",
        SourceKind::Flathub => "flathub",
        SourceKind::Distro => "distro",
        SourceKind::Repology => "repology",
    }
}

#[cfg(test)]
pub(crate) fn same_app(left: &App, right: &App) -> bool {
    let left_names = join_names(left);
    let right_names = join_names(right);
    match join_preface(left, right) {
        JoinPreface::Joined => true,
        JoinPreface::Apart => false,
        JoinPreface::ByName => left_names.iter().any(|name| right_names.contains(name)),
    }
}

/// The cheap guards of a join decision, ahead of the name-slug comparison:
/// an identity conflict rules the pair apart, a shared canonical id or an
/// equal homepage joins it outright, and only the remainder needs the
/// slugified name sets.
enum JoinPreface {
    Joined,
    Apart,
    ByName,
}

fn join_preface(left: &App, right: &App) -> JoinPreface {
    if text_conflict(left.homepage.as_deref(), right.homepage.as_deref())
        || text_conflict(left.developer.as_deref(), right.developer.as_deref())
    {
        return JoinPreface::Apart;
    }
    if left.id == right.id
        || matches!((&left.homepage, &right.homepage), (Some(l), Some(r)) if l == r)
    {
        return JoinPreface::Joined;
    }
    JoinPreface::ByName
}

fn text_conflict(left: Option<&str>, right: Option<&str>) -> bool {
    matches!((left, right), (Some(l), Some(r)) if l != r)
}

fn join_names(app: &App) -> Vec<TorideId> {
    std::iter::once(app.name.as_str())
        .chain(app.aliases.iter().map(String::as_str))
        .map(TorideId::slugify)
        .filter(|slug| slug.as_str() != "unnamed")
        .collect()
}

/// Union `hit` into the surviving `row`. Returns `true` when the alias set
/// grew (the only change that can alter the row's slugified name set, so
/// callers know when to invalidate a memoized copy).
fn absorb(row: &mut App, hit: App) -> bool {
    row.summary = row.summary.take().or(hit.summary);
    row.description = row.description.take().or(hit.description);
    row.homepage = row.homepage.take().or(hit.homepage);
    row.license = row.license.take().or(hit.license);
    row.developer = row.developer.take().or(hit.developer);
    row.latest = row.latest.take().or(hit.latest);
    let mut aliases_grew = false;
    for alias in hit.aliases {
        if !row.aliases.contains(&alias) {
            row.aliases.push(alias);
            aliases_grew = true;
        }
    }
    for binary in hit.binaries {
        if !row.binaries.contains(&binary) {
            row.binaries.push(binary);
        }
    }
    for platform in hit.platforms {
        if !row.platforms.contains(&platform) {
            row.platforms.push(platform);
        }
    }
    for artifact in hit.artifacts {
        if !row.artifacts.contains(&artifact) {
            row.artifacts.push(artifact);
        }
    }
    union_rows(&mut row.sources, hit.sources);
    aliases_grew
}

pub(crate) fn union_rows(rows: &mut Vec<SourceRef>, extra: impl IntoIterator<Item = SourceRef>) {
    for row in extra {
        let known = rows.iter().any(|existing| {
            existing.source == row.source && existing.id == row.id && existing.repo == row.repo
        });
        if !known {
            rows.push(row);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Availability, InstallMethod, SourceKind};

    fn row(source: SourceKind, id: &str) -> SourceRef {
        SourceRef {
            source,
            id: id.to_owned(),
            repo: None,
            version: None,
            provisional: false,
        }
    }

    fn app(id: &str, name: &str, source: SourceKind) -> App {
        App {
            id: TorideId::slugify(id),
            name: name.to_owned(),
            aliases: Vec::new(),
            summary: None,
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
                token: id.to_owned(),
            },
            sources: vec![row(source, id)],
            availability: Availability::Available,
        }
    }

    #[test]
    fn same_app_joins_on_a_shared_alias_name_slug() {
        let mut cask = app("brave-browser", "Brave Browser", SourceKind::HomebrewCask);
        cask.aliases = vec!["Brave".to_owned()];
        let mut flathub = app("com-brave-browser", "Brave Browser", SourceKind::Flathub);
        flathub.aliases = vec!["Brave Browser 2".to_owned()];
        assert!(same_app(&cask, &flathub));
    }

    #[test]
    fn same_app_joins_on_an_equal_homepage() {
        let mut left = app("brave-browser", "Brave", SourceKind::HomebrewCask);
        left.homepage = Some("https://brave.com/".to_owned());
        let mut right = app("com-brave-browser", "Brave Browser", SourceKind::Flathub);
        right.homepage = Some("https://brave.com/".to_owned());
        assert!(same_app(&left, &right));
    }

    #[test]
    fn same_app_joins_on_the_canonical_slug_when_identities_stay_silent() {
        let left = app("brave", "Left", SourceKind::Distro);
        let right = app("brave", "Right Name", SourceKind::Flathub);
        assert!(same_app(&left, &right));
    }

    #[test]
    fn same_app_refuses_a_homepage_conflict_even_on_a_shared_slug() {
        let mut left = app("brave", "Brave", SourceKind::HomebrewCask);
        left.homepage = Some("https://brave.com/".to_owned());
        let mut right = app("brave", "Brave", SourceKind::Flathub);
        right.homepage = Some("https://example.com/".to_owned());
        assert!(!same_app(&left, &right));
    }

    #[test]
    fn same_app_refuses_a_developer_conflict() {
        let mut left = app("notes", "Notes", SourceKind::HomebrewCask);
        left.developer = Some("Alice".to_owned());
        let mut right = app("notes-app", "Notes", SourceKind::Flathub);
        right.developer = Some("Bob".to_owned());
        assert!(!same_app(&left, &right));
    }

    #[test]
    fn same_app_ignores_the_degenerate_unnamed_slug() {
        let left = app("left", "///", SourceKind::Distro);
        let right = app("right", "日", SourceKind::Flathub);
        assert!(!same_app(&left, &right));
    }

    #[test]
    fn merge_hits_presents_one_row_carrying_both_sources_refs() {
        let mut cask = app("brave-browser", "Brave Browser", SourceKind::HomebrewCask);
        cask.homepage = Some("https://brave.com/".to_owned());
        cask.install = InstallMethod::Homebrew {
            cask: true,
            token: "brave-browser".to_owned(),
        };
        let mut flathub = app("com-brave-browser", "Brave Browser", SourceKind::Flathub);
        flathub.install = InstallMethod::Flatpak {
            app_id: "com.brave.Browser".to_owned(),
            remote: "flathub".to_owned(),
        };
        flathub.sources = vec![row(SourceKind::Flathub, "com.brave.Browser")];
        flathub.summary = Some("Privacy browser".to_owned());

        let merged = merge_hits([vec![cask], vec![flathub]]);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].id.as_str(), "brave-browser");
        assert_eq!(
            merged[0]
                .sources
                .iter()
                .map(|row| (row.source, row.id.as_str()))
                .collect::<Vec<_>>(),
            [
                (SourceKind::HomebrewCask, "brave-browser"),
                (SourceKind::Flathub, "com.brave.Browser"),
            ]
        );
        assert_eq!(
            merged[0].summary.as_deref(),
            Some("Privacy browser"),
            "the later hit backfills the unset field"
        );
        assert!(
            matches!(
                merged[0].install,
                InstallMethod::Homebrew { cask: true, .. }
            ),
            "the registration-first row's install method governs"
        );
    }

    #[test]
    fn merge_hits_keeps_conflicting_rows_apart() {
        let mut left = app("notes", "Notes", SourceKind::HomebrewCask);
        left.homepage = Some("https://notes.a/".to_owned());
        let mut right = app("notes-app", "Notes", SourceKind::Flathub);
        right.homepage = Some("https://notes.b/".to_owned());
        assert_eq!(merge_hits([vec![left], vec![right]]).len(), 2);
    }

    #[test]
    fn merge_hits_keeps_same_named_apps_from_one_adapter_apart() {
        let left = app("notes-a", "Notes", SourceKind::HomebrewCask);
        let right = app("notes-b", "Notes", SourceKind::HomebrewCask);
        let merged = merge_hits([vec![left, right]]);
        assert_eq!(
            merged.iter().map(|row| row.id.as_str()).collect::<Vec<_>>(),
            ["notes-a", "notes-b"],
            "the merge joins hits across adapters, never within one source's own hits"
        );
    }

    #[test]
    fn merge_hits_suffixes_the_source_key_on_a_same_slug_identity_conflict() {
        let mut cask = app("notes", "Notes", SourceKind::HomebrewCask);
        cask.homepage = Some("https://notes.a/".to_owned());
        let mut flathub = app("notes", "Notes", SourceKind::Flathub);
        flathub.homepage = Some("https://notes.b/".to_owned());
        flathub.sources = vec![row(SourceKind::Flathub, "com.example.Notes")];
        let merged = merge_hits([vec![cask], vec![flathub]]);
        assert_eq!(
            merged.iter().map(|row| row.id.as_str()).collect::<Vec<_>>(),
            ["notes", "notes-flathub"],
            "DESIGN.md §5's collision policy: same slug + conflicting identity → suffix the source key"
        );
        assert_eq!(
            merged[1].sources,
            vec![row(SourceKind::Flathub, "com.example.Notes")],
            "the row's per-source identity is untouched: only the canonical id diverges"
        );
    }

    #[test]
    fn merge_hits_suffixes_again_when_the_suffixed_id_is_also_taken() {
        let mut cask = app("notes", "Notes", SourceKind::HomebrewCask);
        cask.homepage = Some("https://notes.a/".to_owned());
        let mut native = app("notes-flathub", "Notes Flathub", SourceKind::Distro);
        native.homepage = Some("https://notes.c/".to_owned());
        let mut flathub = app("notes", "Notes", SourceKind::Flathub);
        flathub.homepage = Some("https://notes.b/".to_owned());
        let merged = merge_hits([vec![cask, native], vec![flathub]]);
        assert_eq!(
            merged.iter().map(|row| row.id.as_str()).collect::<Vec<_>>(),
            ["notes", "notes-flathub", "notes-flathub-flathub"]
        );
    }

    #[test]
    fn merge_hits_deduplicates_an_identical_source_row() {
        let mut left = app("brave", "Brave", SourceKind::HomebrewCask);
        left.sources = vec![
            row(SourceKind::HomebrewCask, "brave-browser"),
            row(SourceKind::Repology, "brave-browser"),
        ];
        let mut right = app("brave-browser", "Brave", SourceKind::Distro);
        right.sources = vec![
            row(SourceKind::HomebrewCask, "brave-browser"),
            row(SourceKind::Flathub, "com.brave.Browser"),
        ];
        let merged = merge_hits([vec![left], vec![right]]);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].sources.len(), 3);
    }

    #[test]
    fn merge_hits_unions_aliases_without_duplicates() {
        let mut left = app("brave", "Brave", SourceKind::HomebrewCask);
        left.aliases = vec!["Brave Browser".to_owned()];
        let mut right = app("brave-browser", "Brave", SourceKind::Flathub);
        right.aliases = vec!["Brave Browser".to_owned(), "Brave Web Browser".to_owned()];
        let merged = merge_hits([vec![left], vec![right]]);
        assert_eq!(
            merged[0].aliases,
            ["Brave Browser".to_owned(), "Brave Web Browser".to_owned()]
        );
    }

    #[test]
    fn merge_hits_unions_platforms_artifacts_and_binaries() {
        use crate::model::{Arch, Artifact, ArtifactKind, Checksum, ChecksumAlgo, Os, Platform};

        let mut cask = app("brave-browser", "Brave Browser", SourceKind::HomebrewCask);
        cask.platforms = vec![Platform {
            os: Os::MacOs,
            arch: Some(Arch::X86_64),
            min_release: None,
        }];
        cask.binaries = vec!["brave".to_owned()];

        let mut flathub = app("com-brave-browser", "Brave Browser", SourceKind::Flathub);
        flathub.platforms = vec![
            Platform {
                os: Os::Linux,
                arch: None,
                min_release: None,
            },
            Platform {
                os: Os::MacOs,
                arch: Some(Arch::X86_64),
                min_release: None,
            },
        ];
        flathub.artifacts = vec![Artifact {
            url: "https://flathub/repo/brave".to_owned(),
            checksum: Some(Checksum {
                algo: ChecksumAlgo::Sha256,
                digest: "a".repeat(64),
            }),
            os: Some(Os::Linux),
            arch: None,
            kind: ArtifactKind::Package,
        }];
        flathub.binaries = vec!["brave".to_owned(), "brave-browser".to_owned()];

        let merged = merge_hits([vec![cask], vec![flathub]]);
        assert_eq!(merged.len(), 1);
        assert_eq!(
            merged[0]
                .platforms
                .iter()
                .map(|claim| claim.os)
                .collect::<Vec<_>>(),
            [Os::MacOs, Os::Linux],
            "the flathub Linux claim must survive the cask-first merge"
        );
        assert_eq!(merged[0].platforms.len(), 2, "duplicate claims dedupe");
        assert_eq!(merged[0].artifacts.len(), 1);
        assert_eq!(
            merged[0].binaries,
            ["brave".to_owned(), "brave-browser".to_owned()],
            "binaries union without duplicates"
        );
    }

    #[test]
    fn alias_index_records_and_returns_rows_deduplicated() {
        let mut index = AliasIndex::new();
        assert!(index.is_empty());
        let id = TorideId::slugify("brave-browser");
        index.insert(&id, vec![row(SourceKind::HomebrewCask, "brave-browser")]);
        index.insert(
            &id,
            vec![
                row(SourceKind::HomebrewCask, "brave-browser"),
                row(SourceKind::Flathub, "com.brave.Browser"),
            ],
        );
        assert_eq!(index.len(), 1);
        assert_eq!(index.get(&id).len(), 2);
        assert_eq!(index.get(&TorideId::slugify("unknown")), []);
    }

    #[test]
    fn alias_index_serde_round_trips_deterministically() {
        let mut index = AliasIndex::new();
        let brave = TorideId::slugify("brave-browser");
        index.insert(
            &brave,
            vec![
                row(SourceKind::HomebrewCask, "brave-browser"),
                row(SourceKind::Flathub, "com.brave.Browser"),
            ],
        );
        index.insert(
            &TorideId::slugify("ripgrep"),
            vec![row(SourceKind::HomebrewFormula, "ripgrep")],
        );
        let json = serde_json::to_string(&index).expect("index serializes");
        let back: AliasIndex = serde_json::from_str(&json).expect("index deserializes");
        assert_eq!(back, index);
        assert_eq!(
            serde_json::to_string(&back).expect("reserializes"),
            json,
            "BTreeMap keys keep the persisted form deterministic"
        );
    }

    #[test]
    fn alias_index_records_an_app_under_its_canonical_id() {
        let mut index = AliasIndex::new();
        index.record(&app("brave-browser", "Brave", SourceKind::HomebrewCask));
        assert_eq!(
            index.get(&TorideId::slugify("brave-browser")),
            [row(SourceKind::HomebrewCask, "brave-browser")]
        );
    }
}
