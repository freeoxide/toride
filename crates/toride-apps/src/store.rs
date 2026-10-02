//! # Record stores
//!
//! [`RecordStore`] is the persistence seam under the [`Apps`] facade: the
//! durable ownership ledger of what toride installed, exchanged as whole
//! portable [`RecordSnapshot`]s. The default [`JsonRecordStore`] is the
//! crate's JSON manifest document; embedders supply their own through
//! [`AppsBuilder::with_record_store`] (an embedder keeping its own
//! receipts as source of truth mirrors or supplies them here, so
//! uninstall-ownership refusals stay consistent across both layers).
//!
//! ## Quarantine, not hard stop
//!
//! A corrupt manifest document — above all one written by a newer toride
//! — does not fail the build and does not get saved over: the JSON store
//! moves it aside to a `.corrupt-`-suffixed sibling and answers an empty
//! snapshot, so the facade keeps operating, the next save starts a fresh
//! document, and the unreadable bytes stay on disk for inspection
//! ([`StoreLoad::quarantined`] names the moved file). Only a quarantine
//! that cannot happen (the rename itself fails) is an error.
//!
//! [`Apps`]: crate::Apps
//! [`AppsBuilder::with_record_store`]: crate::AppsBuilder::with_record_store

use std::sync::atomic::{AtomicU64, Ordering};

use camino::Utf8PathBuf;

use crate::manifest::{InstallManifest, ManifestError, ManifestResult, RecordSnapshot, corrupt};

/// What one [`RecordStore`] load answered: the records, plus where a
/// corrupt prior document was moved when recovery quarantined one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreLoad {
    /// The loaded records.
    pub snapshot: RecordSnapshot,
    /// The path a corrupt prior document was quarantined to; `None` when
    /// nothing needed recovering.
    pub quarantined: Option<Utf8PathBuf>,
}

/// The durable ownership ledger under the [`Apps`] facade — what toride
/// installed, exchanged as whole [`RecordSnapshot`]s.
///
/// Implementations must be callable from any thread (`Send + Sync`); the
/// facade loads once at build and saves after each successful mutation,
/// off the async runtime. Errors are the manifest layer's own
/// ([`ManifestError`]).
///
/// [`Apps`]: crate::Apps
pub trait RecordStore: Send + Sync {
    /// Read every record. A store holding nothing answers an empty
    /// snapshot, never an error; how (or whether) to recover from
    /// unreadable prior state is the store's own choice — the default
    /// JSON store quarantines (see the module docs).
    ///
    /// # Errors
    ///
    /// [`ManifestError`] when the store cannot be read at all.
    fn load(&self) -> ManifestResult<StoreLoad>;

    /// Persist `snapshot` as the store's entire contents, replacing what
    /// was there before.
    ///
    /// # Errors
    ///
    /// [`ManifestError`] when the write fails.
    fn save(&self, snapshot: &RecordSnapshot) -> ManifestResult<()>;
}

/// The default [`RecordStore`]: the crate's JSON manifest document at
/// `path` — written atomically, loaded strictly, recovered by quarantine.
#[derive(Debug)]
pub struct JsonRecordStore {
    path: Utf8PathBuf,
    quarantine_counter: AtomicU64,
}

impl JsonRecordStore {
    /// A store over the manifest document at `path` (created on first
    /// save; a missing file loads as empty).
    #[must_use]
    pub fn at(path: impl Into<Utf8PathBuf>) -> Self {
        Self {
            path: path.into(),
            quarantine_counter: AtomicU64::new(0),
        }
    }

    /// The manifest path this store reads and writes.
    #[must_use]
    pub fn path(&self) -> &Utf8PathBuf {
        &self.path
    }

    /// Where a corrupt document moves aside to: a sibling of the manifest
    /// carrying `.corrupt-<pid>-<n>` — unique per process and per store
    /// instance, so repeated recoveries never overwrite each other.
    fn quarantine_path(&self) -> ManifestResult<Utf8PathBuf> {
        let Some(name) = self.path.file_name() else {
            return Err(ManifestError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("manifest path `{}` has no file name", self.path),
            )));
        };
        let unique = self.quarantine_counter.fetch_add(1, Ordering::Relaxed);
        Ok(self
            .path
            .with_file_name(format!("{name}.corrupt-{}-{unique}", std::process::id())))
    }
}

impl RecordStore for JsonRecordStore {
    fn load(&self) -> ManifestResult<StoreLoad> {
        match InstallManifest::load(&self.path) {
            Ok(manifest) => Ok(StoreLoad {
                snapshot: manifest.snapshot(),
                quarantined: None,
            }),
            Err(ManifestError::Corrupt(source)) => {
                let quarantined = self.quarantine_path()?;
                match std::fs::rename(&self.path, &quarantined) {
                    Ok(()) => Ok(StoreLoad {
                        snapshot: RecordSnapshot::empty(),
                        quarantined: Some(quarantined),
                    }),
                    Err(io) => Err(corrupt(format!(
                        "manifest at {} is corrupt ({source}) and quarantining it to \
                         {quarantined} failed: {io}",
                        self.path
                    ))),
                }
            }
            Err(error) => Err(error),
        }
    }

    fn save(&self, snapshot: &RecordSnapshot) -> ManifestResult<()> {
        InstallManifest::from_snapshot(self.path.clone(), snapshot.clone()).save()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{InstallRecord, NativeIds};
    use crate::plan::{FlatpakInstallation, Operation};
    use std::collections::BTreeMap;
    use toride_registry::{DistroFamily, TorideId};

    static DIR_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temp_store_path(label: &str) -> Utf8PathBuf {
        let unique = DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "toride-apps-store-{}-{unique}-{label}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("unique temp dir is creatable");
        Utf8PathBuf::from_path_buf(dir.join("apps-manifest.json"))
            .expect("system temp dir is valid UTF-8")
    }

    fn app_id(slug: &str) -> TorideId {
        TorideId::slugify(slug)
    }

    fn cask_record(token: &str) -> InstallRecord {
        InstallRecord::new(
            crate::plan::InstallPlan {
                app: app_id("brave"),
                backend: crate::backend::BackendId::Homebrew,
                operation: Operation::BrewInstall {
                    cask: true,
                    token: token.to_owned(),
                },
                dry_run: false,
                requires_elevation: false,
            },
            NativeIds::Homebrew {
                token: token.to_owned(),
                cask: true,
            },
            Some("1.0".to_owned()),
        )
        .with_installed_at(1_700_000_000)
    }

    fn adopted_record() -> InstallRecord {
        InstallRecord::adopted(
            NativeIds::Distro {
                package: "brave-browser".to_owned(),
                family: DistroFamily::Debian,
            },
            None,
        )
        .with_installed_at(1_700_000_001)
    }

    // --- load ---------------------------------------------------------------

    #[test]
    fn load_answers_an_empty_snapshot_for_a_missing_file() {
        let store = JsonRecordStore::at(temp_store_path("missing"));
        let load = store.load().unwrap();
        assert_eq!(load.snapshot, RecordSnapshot::empty());
        assert_eq!(load.quarantined, None);
    }

    #[test]
    fn load_returns_the_documents_records() {
        let path = temp_store_path("records");
        let mut manifest = InstallManifest::at(&path);
        manifest.record(&app_id("brave"), cask_record("brave-browser"));
        manifest.record(&app_id("adopted"), adopted_record());
        manifest.save().unwrap();

        let load = JsonRecordStore::at(&path).load().unwrap();
        assert_eq!(load.snapshot.records.len(), 2);
        assert_eq!(
            load.snapshot.records.get(&app_id("brave")),
            manifest.get(&app_id("brave"))
        );
        assert_eq!(load.quarantined, None);
    }

    #[test]
    fn load_quarantines_a_corrupt_document_preserving_its_bytes() {
        let path = temp_store_path("corrupt");
        let garbage = "definitely { not json";
        std::fs::write(path.as_std_path(), garbage).unwrap();
        let store = JsonRecordStore::at(&path);

        let load = store.load().unwrap();
        assert_eq!(load.snapshot, RecordSnapshot::empty(), "a fresh start");
        let quarantined = load.quarantined.expect("the corrupt file moved aside");
        assert_ne!(quarantined, path);
        assert!(
            quarantined
                .file_name()
                .is_some_and(|name| name.contains(".corrupt-")),
            "recognizable quarantine name: {quarantined}"
        );
        assert_eq!(
            std::fs::read_to_string(quarantined.as_std_path()).unwrap(),
            garbage,
            "the unreadable bytes stay on disk"
        );
        assert!(
            !path.as_std_path().exists(),
            "the original slot is free for the next save"
        );
    }

    #[test]
    fn load_quarantines_a_newer_schema_document_not_loads_it() {
        let path = temp_store_path("newer-schema");
        let future_doc = r#"{"version":99,"entries":{"brave":{"something":"new"}}}"#;
        std::fs::write(path.as_std_path(), future_doc).unwrap();

        let load = JsonRecordStore::at(&path).load().unwrap();
        assert_eq!(load.snapshot, RecordSnapshot::empty());
        let quarantined = load.quarantined.expect("quarantined, not hard-stopped");
        assert_eq!(
            std::fs::read_to_string(quarantined.as_std_path()).unwrap(),
            future_doc
        );
    }

    #[test]
    fn repeated_corruptions_quarantine_to_distinct_names() {
        let path = temp_store_path("repeat");
        std::fs::write(path.as_std_path(), "first garbage").unwrap();
        let store = JsonRecordStore::at(&path);
        let first = store.load().unwrap().quarantined.unwrap();
        std::fs::write(path.as_std_path(), "second garbage").unwrap();
        let second = store.load().unwrap().quarantined.unwrap();
        assert_ne!(first, second);
        assert!(first.as_std_path().is_file() && second.as_std_path().is_file());
    }

    #[test]
    fn load_maps_io_failures_through_unchanged() {
        let dir = temp_store_path("io-failure");
        std::fs::create_dir_all(dir.as_std_path()).unwrap();
        let error = JsonRecordStore::at(&dir).load().unwrap_err();
        assert!(matches!(error, ManifestError::Io(_)), "{error:?}");
    }

    #[test]
    fn a_failed_quarantine_rename_errors_and_preserves_the_corrupt_file() {
        let path = temp_store_path("rename-blocked");
        std::fs::write(path.as_std_path(), "garbage").unwrap();
        let store = JsonRecordStore::at(&path);
        let blocked = path.with_file_name(format!(
            "apps-manifest.json.corrupt-{}-0",
            std::process::id()
        ));
        std::fs::create_dir_all(blocked.as_std_path()).unwrap();

        let error = store.load().unwrap_err();
        assert!(matches!(error, ManifestError::Corrupt(_)), "{error:?}");
        assert!(
            error.to_string().contains("quarantining"),
            "the message names the failed recovery: {error}"
        );
        assert_eq!(
            std::fs::read_to_string(path.as_std_path()).unwrap(),
            "garbage",
            "the corrupt document is never saved over"
        );
    }

    // --- save ---------------------------------------------------------------

    #[test]
    fn save_writes_the_document_the_strict_loader_reads_back() {
        let path = temp_store_path("save-load");
        let mut records = BTreeMap::new();
        records.insert(app_id("brave"), cask_record("brave-browser"));
        records.insert(app_id("adopted"), adopted_record());
        let store = JsonRecordStore::at(&path);

        store.save(&RecordSnapshot::from(records)).unwrap();
        let reloaded = InstallManifest::load(&path).unwrap();
        assert_eq!(reloaded.len(), 2);
        assert_eq!(
            reloaded
                .get(&app_id("adopted"))
                .and_then(|record| record.plan.as_ref()),
            None,
            "adopted records persist plan-less"
        );
    }

    #[test]
    fn save_after_a_quarantine_starts_a_fresh_document_at_the_original_path() {
        let path = temp_store_path("recover");
        std::fs::write(path.as_std_path(), "garbage").unwrap();
        let store = JsonRecordStore::at(&path);
        let quarantined = store.load().unwrap().quarantined.unwrap();

        let mut records = BTreeMap::new();
        records.insert(app_id("brave"), cask_record("brave-browser"));
        store.save(&RecordSnapshot::from(records)).unwrap();

        let load = JsonRecordStore::at(&path).load().unwrap();
        assert_eq!(load.quarantined, None, "the fresh document loads cleanly");
        assert_eq!(load.snapshot.records.len(), 1);
        assert_eq!(
            std::fs::read_to_string(quarantined.as_std_path()).unwrap(),
            "garbage",
            "the quarantined bytes survive the recovery untouched"
        );
    }

    #[test]
    fn save_replaces_the_stores_entire_contents() {
        let path = temp_store_path("replace");
        let store = JsonRecordStore::at(&path);
        let mut records = BTreeMap::new();
        records.insert(app_id("brave"), cask_record("brave-browser"));
        store.save(&RecordSnapshot::from(records)).unwrap();
        store.save(&RecordSnapshot::empty()).unwrap();
        let load = store.load().unwrap();
        assert_eq!(load.snapshot, RecordSnapshot::empty());
    }

    #[test]
    fn the_trait_is_object_safe_behind_an_arc() {
        let store: std::sync::Arc<dyn RecordStore> =
            std::sync::Arc::new(JsonRecordStore::at(temp_store_path("object-safe")));
        assert_eq!(store.load().unwrap().snapshot, RecordSnapshot::empty());
        let records = BTreeMap::from([(
            app_id("brave"),
            InstallRecord::adopted(
                NativeIds::Flatpak {
                    app_id: "com.brave.Browser".to_owned(),
                    app_ref: None,
                    installation: FlatpakInstallation::User,
                },
                None,
            ),
        )]);
        store.save(&RecordSnapshot::from(records)).unwrap();
        assert_eq!(store.load().unwrap().snapshot.records.len(), 1);
    }
}
