//! # Install manifest
//!
//! [`InstallManifest`] is the durable record of **what toride installed on
//! this host**: one [`InstallRecord`] per app, keyed by [`TorideId`],
//! carrying the backend that installed it, the backend-native identifiers
//! **as actually installed** (never re-planned — see [`NativeIds`]), the
//! version the backend reported after the install, a wall-clock epoch
//! stamp, and the plan that was executed (the source note the record is
//! answerable to).
//!
//! The manifest is the source of truth the status layer
//! ([`crate::status`](crate::status)) and the facade (A6) consult to tell
//! "toride installed this" apart from "the user installed this some other
//! way" (`Foreign`), and to uninstall later without re-deriving identifiers
//! the planner would guess at (the A1 round-1 flatpak-ref finding: an app
//! installed under one arch must uninstall even when re-planning would
//! spell a different ref).
//!
//! ## Storage
//!
//! A JSON document at a [`dirs`]-resolved path —
//! [`default_path`](default_path) is `dirs::data_dir()` (`$XDG_DATA_HOME`
//! or `~/.local/share` on Linux, `~/Library/Application Support` on macOS)
//! joined with `toride/apps-manifest.json`. The path is injectable
//! ([`InstallManifest::at`]) so every operation is testable offline; a
//! host with no resolvable data directory (or a non-UTF-8 one — paths are
//! [`camino`] UTF-8 paths per house convention) yields `None` from
//! [`default_path`](default_path) and callers decide how to surface that.
//!
//! ## Durability
//!
//! Writes are atomic: serialize, create parent directories, write a unique
//! temp file **in the manifest's own directory**, then `rename` over the
//! target (same-directory rename is atomic, so a crash mid-save leaves
//! either the previous document or the complete new one — never a torn
//! file). The temp name carries the pid plus a process-local counter, so
//! two toride processes never share a temp file; a failed write removes
//! its temp file instead of littering. Concurrent *writers* are still
//! last-rename-wins (no file locking) — acceptable for a single-user CLI
//! tool, and the atomic rename means the losing write never corrupts the
//! winner's document. In-process, `record`/`remove` need `&mut self`, so
//! no aliasing hazards exist there.
//!
//! ## Tolerance
//!
//! Loading a **missing** file is an empty manifest (fresh hosts are the
//! normal case, not an error). A file that exists but does not parse is
//! [`ManifestError::Corrupt`] — typed, never a panic; a hand-edited
//! manifest the reader cannot interpret fails loudly instead of silently
//! resetting the record.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use camino::Utf8PathBuf;
use serde::{Deserialize, Serialize};
use toride_registry::{DistroFamily, TorideId};

use crate::backend::BackendId;
use crate::plan::{FlatpakInstallation, InstallPlan};

/// Directory under the platform data dir that holds toride's state.
pub const MANIFEST_DIR: &str = "toride";

/// File name of the install manifest inside [`MANIFEST_DIR`].
pub const MANIFEST_FILE: &str = "apps-manifest.json";

/// Schema version written into the document. This reader accepts any
/// document that parses into the current shape (serde ignores unknown
/// fields, so an additive future schema still loads); a future
/// *incompatible* schema fails as [`ManifestError::Corrupt`] — loud, not a
/// silent reset — and its migration step will key off this field.
const SCHEMA_VERSION: u32 = 1;

/// Convenience alias for results of manifest persistence operations.
pub type ManifestResult<T> = std::result::Result<T, ManifestError>;

/// Failures of the install manifest's persistence operations. Deliberately
/// a manifest-local enum (not a variant on the crate's execution
/// [`Error`](crate::Error)): the manifest fails in ways the execution
/// backends never do (corrupt local document), and error.rs belongs to the
/// A1 core surface.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ManifestError {
    /// Reading or writing the manifest file failed — missing permissions,
    /// a path that is a directory, or a failed temp-then-rename step.
    /// A *missing* file is not this: [`InstallManifest::load`] treats it
    /// as an empty manifest.
    #[error("manifest file I/O failed: {0}")]
    Io(#[from] std::io::Error),

    /// The manifest document exists but is not a well-formed manifest.
    /// Raised by loading (corrupt or hand-mangled file) and — theoretical
    /// only, these types serialize unconditionally — by saving.
    #[error("manifest file is corrupt: {0}")]
    Corrupt(#[from] serde_json::Error),
}

// ---------------------------------------------------------------------------
// Records
// ---------------------------------------------------------------------------

/// The backend-native identifiers of **what was actually installed**, one
/// variant per backend family. Recorded verbatim at install time and
/// replayed verbatim from the manifest — never re-derived by re-planning,
/// which is the whole point of the manifest (A1 round-1 finding: a
/// re-planned flatpak ref guesses the planning target's arch, not the
/// installed one).
///
/// Doubles as the lookup key the status layer probes with: a record's ids
/// answer "is what toride installed still there", and a caller-supplied
/// set (derived from the registry app's install method) answers "is this
/// app present through its native backend at all" ([`Foreign`]).
///
/// The homebrew arm mirrors the plan model's `cask: bool` (the same
/// spelling `InstallMethod::Homebrew` and `Operation::BrewInstall` use)
/// rather than re-using `BrewKind`, which carries no serde derives in its
/// home module.
///
/// [`Foreign`]: crate::AppStatus::Foreign
/// [`InstallMethod::Homebrew`]: toride_registry::InstallMethod::Homebrew
/// [`Operation::BrewInstall`]: crate::Operation::BrewInstall
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum NativeIds {
    /// A homebrew cask (`cask: true`) or formula, by token.
    Homebrew {
        /// Cask token or formula name as installed.
        token: String,
        /// `true` when a cask was installed, `false` for a formula — the
        /// kind scopes the backend's version probes.
        cask: bool,
    },
    /// A flatpak app, by app id and the ref that landed.
    Flatpak {
        /// Dotted reverse-DNS app id (`com.brave.Browser`) — the id the
        /// scoped listings report.
        app_id: String,
        /// The ref flatpak actually installed (`app/<id>/<arch>/stable`)
        /// as a [`Some`] on records written at install time; `None` when
        /// a caller knows the app id but not the installed ref (status
        /// probes from registry data).
        app_ref: Option<String>,
        /// Installation the app lives in — scopes every probe.
        installation: FlatpakInstallation,
    },
    /// A distro package, by package name on a manager family.
    Distro {
        /// Package name the manager knows.
        package: String,
        /// Family whose manager installed it — selects the manager and
        /// gates probing to a matching backend.
        family: DistroFamily,
    },
}

impl NativeIds {
    /// The backend these identifiers belong to — the same value the
    /// owning record carries in [`InstallRecord::backend`].
    #[must_use]
    pub fn backend(&self) -> BackendId {
        match self {
            Self::Homebrew { .. } => BackendId::Homebrew,
            Self::Flatpak { .. } => BackendId::Flatpak,
            Self::Distro { family, .. } => BackendId::Distro(*family),
        }
    }
}

/// One app's entry in the [`InstallManifest`]: what toride installed, how,
/// when, and with which version the backend confirmed afterwards.
///
/// Field-by-field, all recorded **post-verify** at install time:
/// the identifiers and plan are the executed ones (source of truth), the
/// version is what the backend's post-install probe reported (`None` when
/// the backend could not report one), the timestamp is a Unix-epoch
/// seconds stamp (chrono is not a workspace dep; epoch seconds are
/// serde-trivial and human-readable on demand).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstallRecord {
    /// Backend that performed the install. Always equal to
    /// [`InstallRecord::ids`]'s own backend mapping; stored explicitly so
    /// the record reads without dereferencing the ids.
    pub backend: BackendId,
    /// The actually-installed identifiers — see [`NativeIds`].
    pub ids: NativeIds,
    /// Version the backend reported after the install, when it reported
    /// one (`None` = no version observable, not "unknown app").
    pub version: Option<String>,
    /// Install time as Unix epoch seconds (`SystemTime::now` since
    /// `UNIX_EPOCH`; a clock before 1970 records `0`).
    pub installed_at: u64,
    /// The executed plan, verbatim — the record's source note. Persists
    /// through the plan's serde round-trip the A1 interface notes
    /// sanctioned for the manifest layer.
    pub plan: InstallPlan,
}

impl InstallRecord {
    /// Record `plan` as executed with `ids` and the post-verify `version`,
    /// stamped with the current epoch seconds. Derives `backend` from the
    /// ids so the two can never disagree.
    #[must_use]
    pub fn new(plan: InstallPlan, ids: NativeIds, version: Option<String>) -> Self {
        Self {
            backend: ids.backend(),
            ids,
            version,
            installed_at: epoch_now(),
            plan,
        }
    }

    /// Override the epoch stamp (deterministic tests, imports from other
    /// tooling) — consume-and-return.
    #[must_use]
    pub const fn with_installed_at(mut self, installed_at: u64) -> Self {
        self.installed_at = installed_at;
        self
    }
}

/// Current Unix epoch seconds; `0` when the clock reads before 1970 (the
/// only failure mode, and an honest floor rather than an error).
fn epoch_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

// ---------------------------------------------------------------------------
// Manifest
// ---------------------------------------------------------------------------

/// The durable record of what toride installed: entries keyed by
/// [`TorideId`], persisted as JSON at `path`.
///
/// Entries live in a `BTreeMap`, so listings and the written document are
/// deterministically ordered by app id.
///
/// # Example
///
/// ```rust,ignore
/// use toride_apps::manifest::{InstallManifest, InstallRecord, NativeIds};
///
/// # fn demo(plan: toride_apps::InstallPlan) -> toride_apps::manifest::ManifestResult<()> {
/// let mut manifest = InstallManifest::load("…/apps-manifest.json")?; // missing file = empty
/// manifest.record(InstallRecord::new(plan, NativeIds::Homebrew {
///     token: "firefox".to_owned(),
///     cask: true,
/// }, Some("138.0".to_owned())));
/// manifest.save()?; // atomic: temp file + rename, parents created
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct InstallManifest {
    /// Where [`InstallManifest::save`] writes and [`InstallManifest::load`]
    /// read from.
    path: Utf8PathBuf,
    /// Entries keyed by app id, id-ordered for deterministic output.
    entries: BTreeMap<TorideId, InstallRecord>,
}

impl InstallManifest {
    /// An empty manifest bound to `path` — no I/O. Use
    /// [`InstallManifest::load`] to read an existing document.
    #[must_use]
    pub fn at(path: impl Into<Utf8PathBuf>) -> Self {
        Self {
            path: path.into(),
            entries: BTreeMap::new(),
        }
    }

    /// The manifest's default location:
    /// `dirs::data_dir()`/`toride`/`apps-manifest.json` (`None` when no
    /// data directory resolves, or it is not valid UTF-8).
    ///
    /// `dirs::data_dir()` resolves `$XDG_DATA_HOME` else `~/.local/share`
    /// on Linux, `~/Library/Application Support` on macOS — the correct
    /// per-platform state location for a durable, user-scoped record.
    #[must_use]
    pub fn default_path() -> Option<Utf8PathBuf> {
        dirs::data_dir()
            .and_then(|base| Utf8PathBuf::from_path_buf(base).ok())
            .map(|base| base.join(MANIFEST_DIR).join(MANIFEST_FILE))
    }

    /// Read the manifest at `path`. A missing file is an **empty**
    /// manifest (fresh hosts are normal); an unparseable file is
    /// [`ManifestError::Corrupt`]; anything else that goes wrong reading
    /// is [`ManifestError::Io`]. The returned manifest stays bound to
    /// `path` for later [`InstallManifest::save`] calls.
    ///
    /// # Errors
    ///
    /// [`ManifestError::Corrupt`] when the document does not parse as a
    /// manifest; [`ManifestError::Io`] for every other read failure.
    pub fn load(path: impl Into<Utf8PathBuf>) -> ManifestResult<Self> {
        let path = path.into();
        let contents = match std::fs::read_to_string(&path) {
            Ok(contents) => contents,
            // Absent file: the honest empty manifest, not an error — a
            // host where toride never installed anything has no file.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self::at(path));
            }
            Err(error) => return Err(ManifestError::Io(error)),
        };
        let document: ManifestFile =
            serde_json::from_str(&contents).map_err(ManifestError::Corrupt)?;
        Ok(Self {
            path,
            entries: document.apps,
        })
    }

    /// The path this manifest saves to (and was loaded from).
    #[must_use]
    pub fn path(&self) -> &Utf8PathBuf {
        &self.path
    }

    /// Record (insert or replace) `record`, keyed by its app id.
    /// Returns the displaced record when one existed for the same app —
    /// a re-install replaces its own earlier record.
    pub fn record(&mut self, record: InstallRecord) -> Option<InstallRecord> {
        self.entries.insert(record.plan.app.clone(), record)
    }

    /// Remove and return the record for `id` (post-uninstall bookkeeping).
    /// `None` when toride has no record for the app.
    pub fn remove(&mut self, id: &TorideId) -> Option<InstallRecord> {
        self.entries.remove(id)
    }

    /// The record for `id`, when toride installed it.
    #[must_use]
    pub fn get(&self, id: &TorideId) -> Option<&InstallRecord> {
        self.entries.get(id)
    }

    /// All records, ordered by app id.
    #[must_use]
    pub fn list(&self) -> Vec<&InstallRecord> {
        self.entries.values().collect()
    }

    /// Number of records.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the manifest holds no records.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Persist the manifest at its path, atomically: serialize, create
    /// parent directories, write a unique temp file in the manifest's own
    /// directory, then rename it over the target. A crash mid-save leaves
    /// the previous document intact; a failed save removes its temp file.
    ///
    /// # Errors
    ///
    /// [`ManifestError::Io`] when any filesystem step fails (including a
    /// path with no file name — nothing to rename onto);
    /// [`ManifestError::Corrupt`] only in the unreachable-in-practice case
    /// these guaranteed-serializable types fail to serialize.
    pub fn save(&self) -> ManifestResult<()> {
        let document = ManifestFile {
            version: SCHEMA_VERSION,
            apps: self.entries.clone(),
        };
        // These types have no non-string map keys and no floats, so this
        // cannot fail in practice — mapped, never panicked on.
        let json = serde_json::to_string_pretty(&document).map_err(ManifestError::Corrupt)?;

        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent).map_err(ManifestError::Io)?;
        }
        let temp = self.temp_path()?;
        let write_and_rename = || -> std::io::Result<()> {
            std::fs::write(&temp, json.as_bytes()).and_then(|()| std::fs::rename(&temp, &self.path))
        };
        let result = write_and_rename();
        if result.is_err() {
            // Best-effort cleanup so a failed save leaves no temp litter;
            // the original error is the one worth reporting.
            let _ = std::fs::remove_file(&temp);
        }
        result.map_err(ManifestError::Io)
    }

    /// The temp-file path for this save: hidden, in the manifest's own
    /// directory (same-filesystem rename is atomic), unique per process
    /// and per save so concurrent writers never share one.
    fn temp_path(&self) -> ManifestResult<Utf8PathBuf> {
        /// Distinguishes concurrent saves within one process.
        static SAVE_COUNTER: AtomicU64 = AtomicU64::new(0);
        let Some(name) = self.path.file_name() else {
            return Err(ManifestError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("manifest path `{}` has no file name", self.path),
            )));
        };
        let unique = SAVE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let temp_name = format!(".{name}.tmp-{}-{unique}", std::process::id());
        Ok(self.path.with_file_name(temp_name))
    }
}

/// The on-disk document: schema version plus the id-keyed records. A raw
/// shadow of [`InstallManifest`] (which also carries the path) — the house
/// raw-shape pattern from the backend parsers.
#[derive(Serialize, Deserialize)]
struct ManifestFile {
    /// Schema version of the writer; see [`SCHEMA_VERSION`]. Defaults on
    /// read so hand-trimmed documents still load.
    #[serde(default = "default_schema_version")]
    version: u32,
    /// The records, keyed by app id. Defaults so an empty `{}` document
    /// loads as an empty manifest.
    #[serde(default)]
    apps: BTreeMap<TorideId, InstallRecord>,
}

/// The schema version this reader writes (also the serde default when a
/// document omits the field).
fn default_schema_version() -> u32 {
    SCHEMA_VERSION
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plan::{Operation, PackageManager};
    use std::sync::atomic::AtomicU64;

    /// Distinguishes test temp dirs within one process.
    static DIR_COUNTER: AtomicU64 = AtomicU64::new(0);

    /// A unique, never-before-used manifest path under the system temp
    /// dir (per the round rules: `std::env::temp_dir()` + unique suffix),
    /// with its parent directory already created so tests can pre-seed
    /// the file directly.
    fn temp_manifest_path(label: &str) -> Utf8PathBuf {
        let unique = DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "toride-apps-manifest-{}-{unique}-{label}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("unique temp dir is creatable");
        Utf8PathBuf::from_path_buf(dir.join(MANIFEST_FILE)).expect("system temp dir is valid UTF-8")
    }

    fn app_id(slug: &str) -> TorideId {
        TorideId::slugify(slug)
    }

    /// A minimal executable-looking install plan for `slug` over the given
    /// operation (hand-built — the manifest must not care how the plan was
    /// derived, only that it round-trips).
    fn plan_for(slug: &str, operation: Operation) -> InstallPlan {
        InstallPlan {
            app: app_id(slug),
            backend: BackendId::Homebrew,
            operation,
            dry_run: false,
            requires_elevation: false,
        }
    }

    /// A cask record fixture with a deterministic epoch stamp.
    fn cask_record(slug: &str, token: &str, version: Option<&str>) -> InstallRecord {
        InstallRecord::new(
            plan_for(
                slug,
                Operation::BrewInstall {
                    cask: true,
                    token: token.to_owned(),
                },
            ),
            NativeIds::Homebrew {
                token: token.to_owned(),
                cask: true,
            },
            version.map(str::to_owned),
        )
        .with_installed_at(1_700_000_000)
    }

    // --- load tolerance --------------------------------------------------------

    #[test]
    fn load_returns_an_empty_manifest_when_the_file_is_missing() {
        let path = temp_manifest_path("missing");
        let manifest = InstallManifest::load(&path).unwrap();
        assert!(manifest.is_empty());
        assert_eq!(
            manifest.path(),
            &path,
            "the manifest stays bound to the path"
        );
    }

    #[test]
    fn load_maps_a_corrupt_document_to_the_corrupt_error() {
        let path = temp_manifest_path("corrupt");
        std::fs::write(path.as_std_path(), "definitely { not json").unwrap();
        let error = InstallManifest::load(&path).unwrap_err();
        assert!(matches!(error, ManifestError::Corrupt(_)), "{error:?}");
    }

    #[test]
    fn load_maps_a_wellformed_json_document_of_the_wrong_shape_to_corrupt() {
        // Valid JSON, not a manifest document: still corrupt — a
        // hand-mangled file must fail loudly, not silently reset.
        let path = temp_manifest_path("wrong-shape");
        std::fs::write(path.as_std_path(), r#"["not", "a", "manifest"]"#).unwrap();
        let error = InstallManifest::load(&path).unwrap_err();
        assert!(matches!(error, ManifestError::Corrupt(_)), "{error:?}");
    }

    #[test]
    fn load_maps_an_unreadable_path_to_the_io_error() {
        // A directory: exists, so not "missing", but cannot be read as a
        // file — surfaces as Io, not as a panic or an empty manifest.
        let dir = temp_manifest_path("unreadable-dir");
        std::fs::create_dir_all(dir.as_std_path()).unwrap();
        let error = InstallManifest::load(&dir).unwrap_err();
        assert!(matches!(error, ManifestError::Io(_)), "{error:?}");
    }

    #[test]
    fn load_accepts_an_empty_object_document_as_an_empty_manifest() {
        let path = temp_manifest_path("empty-object");
        std::fs::write(path.as_std_path(), "{}").unwrap();
        let manifest = InstallManifest::load(&path).unwrap();
        assert!(manifest.is_empty());
    }

    // --- record/remove/get/list semantics -------------------------------------

    #[test]
    fn record_then_get_round_trips_the_entry_under_its_app_id() {
        let mut manifest = InstallManifest::at(temp_manifest_path("record-get"));
        let record = cask_record("brave-browser", "brave-browser", Some("1.96.59"));
        manifest.record(record.clone());
        assert_eq!(manifest.get(&app_id("brave-browser")), Some(&record));
    }

    #[test]
    fn record_keys_the_entry_by_the_plan_app_not_the_token() {
        // The join key against the outside world is the TorideId; a token
        // differing from the slug must not create a second identity.
        let mut manifest = InstallManifest::at(temp_manifest_path("keying"));
        manifest.record(cask_record("brave-browser", "different-token", None));
        assert!(manifest.get(&app_id("different-token")).is_none());
        assert!(manifest.get(&app_id("brave-browser")).is_some());
    }

    #[test]
    fn record_replaces_an_existing_entry_and_returns_the_displaced_one() {
        let mut manifest = InstallManifest::at(temp_manifest_path("replace"));
        manifest.record(cask_record("brave", "brave-browser", Some("1.0")));
        let second = cask_record("brave", "brave-browser", Some("2.0"));
        let displaced = manifest.record(second.clone());
        assert_eq!(
            displaced.as_ref().map(|r| r.version.as_deref()),
            Some(Some("1.0"))
        );
        assert_eq!(manifest.get(&app_id("brave")), Some(&second));
        assert_eq!(manifest.len(), 1, "a re-install replaces, never duplicates");
    }

    #[test]
    fn remove_returns_the_record_and_clears_the_slot() {
        let mut manifest = InstallManifest::at(temp_manifest_path("remove"));
        manifest.record(cask_record("brave", "brave-browser", None));
        let removed = manifest.remove(&app_id("brave"));
        assert!(removed.is_some());
        assert!(manifest.get(&app_id("brave")).is_none());
        assert!(manifest.is_empty());
    }

    #[test]
    fn remove_of_an_unrecorded_app_returns_none() {
        let mut manifest = InstallManifest::at(temp_manifest_path("remove-none"));
        assert!(manifest.remove(&app_id("ghost")).is_none());
    }

    #[test]
    fn list_returns_all_records_ordered_by_app_id() {
        let mut manifest = InstallManifest::at(temp_manifest_path("list"));
        // Inserted out of id order on purpose.
        manifest.record(cask_record("zed", "zed", None));
        manifest.record(cask_record("alpha", "alpha", None));
        manifest.record(cask_record("mid", "mid", None));
        let ids: Vec<String> = manifest
            .list()
            .into_iter()
            .map(|record| record.plan.app.as_str().to_owned())
            .collect();
        assert_eq!(ids, ["alpha", "mid", "zed"]);
    }

    // --- persistence round-trips -------------------------------------------------

    #[test]
    fn save_then_load_round_trips_every_backend_kind_of_record() {
        let path = temp_manifest_path("round-trip");
        let mut manifest = InstallManifest::at(&path);
        let flatpak_plan = InstallPlan {
            app: app_id("brave-flatpak"),
            backend: BackendId::Flatpak,
            operation: Operation::FlatpakInstall {
                remote: "flathub".to_owned(),
                app_ref: "app/com.brave.Browser/x86_64/stable".to_owned(),
                installation: FlatpakInstallation::User,
            },
            dry_run: false,
            requires_elevation: false,
        };
        let distro_plan = InstallPlan {
            app: app_id("brave-distro"),
            backend: BackendId::Distro(DistroFamily::Debian),
            operation: Operation::DistroInstall {
                manager: PackageManager::Apt,
                package: "brave-browser".to_owned(),
            },
            dry_run: false,
            requires_elevation: true,
        };
        manifest.record(cask_record(
            "brave-browser",
            "brave-browser",
            Some("1.96.59"),
        ));
        manifest.record(
            InstallRecord::new(
                flatpak_plan,
                NativeIds::Flatpak {
                    app_id: "com.brave.Browser".to_owned(),
                    app_ref: Some("app/com.brave.Browser/x86_64/stable".to_owned()),
                    installation: FlatpakInstallation::User,
                },
                None, // version-less flatpak installs are legitimate
            )
            .with_installed_at(1_700_000_001),
        );
        manifest.record(
            InstallRecord::new(
                distro_plan,
                NativeIds::Distro {
                    package: "brave-browser".to_owned(),
                    family: DistroFamily::Debian,
                },
                Some("1:138.0-1".to_owned()),
            )
            .with_installed_at(1_700_000_002),
        );
        manifest.save().unwrap();

        let reloaded = InstallManifest::load(&path).unwrap();
        assert_eq!(reloaded.len(), 3);
        assert_eq!(
            reloaded.get(&app_id("brave-browser")),
            manifest.get(&app_id("brave-browser"))
        );
        assert_eq!(
            reloaded.get(&app_id("brave-flatpak")),
            manifest.get(&app_id("brave-flatpak"))
        );
        assert_eq!(
            reloaded.get(&app_id("brave-distro")),
            manifest.get(&app_id("brave-distro"))
        );
    }

    #[test]
    fn the_written_document_carries_the_schema_version_and_an_apps_wrapper() {
        let path = temp_manifest_path("document-shape");
        let mut manifest = InstallManifest::at(&path);
        manifest.record(cask_record("brave-browser", "brave-browser", None));
        manifest.save().unwrap();

        let document: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(path.as_std_path()).unwrap()).unwrap();
        assert_eq!(document["version"], serde_json::json!(SCHEMA_VERSION));
        assert_eq!(
            document["apps"]["brave-browser"]["ids"]["Homebrew"]["token"],
            serde_json::json!("brave-browser"),
            "records nest under their app id; ids render as the tagged enum shape serde emits"
        );
    }

    #[test]
    fn save_overwrites_the_previous_document_state() {
        let path = temp_manifest_path("overwrite");
        let mut manifest = InstallManifest::at(&path);
        manifest.record(cask_record("brave-browser", "brave-browser", None));
        manifest.save().unwrap();
        manifest.remove(&app_id("brave-browser"));
        manifest.record(cask_record("firefox", "firefox", None));
        manifest.save().unwrap();

        let reloaded = InstallManifest::load(&path).unwrap();
        assert!(reloaded.get(&app_id("brave-browser")).is_none());
        assert!(reloaded.get(&app_id("firefox")).is_some());
    }

    // --- atomic-write behavior -------------------------------------------------

    #[test]
    fn save_leaves_no_temporary_file_behind_on_success() {
        let path = temp_manifest_path("no-litter");
        let parent = path.parent().unwrap().to_owned();
        let mut manifest = InstallManifest::at(&path);
        manifest.record(cask_record("brave-browser", "brave-browser", None));
        manifest.save().unwrap();

        let mut entries: Vec<String> = std::fs::read_dir(parent.as_std_path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        entries.sort();
        assert_eq!(
            entries,
            [MANIFEST_FILE.to_owned()],
            "only the manifest itself"
        );
    }

    #[test]
    fn save_removes_the_temp_file_when_the_rename_cannot_succeed() {
        // Deterministic rename failure: the target path is a directory,
        // so the temp file is written beside it and the rename onto it
        // fails (POSIX: a file never renames onto a directory). The
        // best-effort cleanup must then leave the directory without
        // temp litter, and the error is Io.
        let parent = temp_manifest_path("rename-fail").with_file_name("dir");
        std::fs::create_dir_all(parent.as_std_path()).unwrap();
        let target = parent.join(MANIFEST_FILE);
        std::fs::create_dir(target.as_std_path()).unwrap();

        let manifest = InstallManifest::at(&target);
        let error = manifest.save().unwrap_err();
        assert!(matches!(error, ManifestError::Io(_)), "{error:?}");
        let mut entries: Vec<String> = std::fs::read_dir(parent.as_std_path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        entries.sort();
        assert_eq!(
            entries,
            [MANIFEST_FILE.to_owned()],
            "only the (pre-existing) target directory remains — the failed temp was removed"
        );
    }

    #[test]
    fn save_fails_before_creating_anything_when_the_parent_is_a_regular_file() {
        // A parent path occupied by a file: create_dir_all fails before a
        // temp file is ever written.
        let blocker = temp_manifest_path("blocker");
        std::fs::write(blocker.as_std_path(), b"i am a file").unwrap();
        let nested = blocker.join("nested").join(MANIFEST_FILE);
        let manifest = InstallManifest::at(&nested);
        let error = manifest.save().unwrap_err();
        assert!(matches!(error, ManifestError::Io(_)), "{error:?}");
        assert_eq!(
            std::fs::read(blocker.as_std_path()).unwrap(),
            b"i am a file",
            "the blocker file is untouched"
        );
    }

    #[test]
    fn save_refuses_a_path_with_no_file_name() {
        let manifest = InstallManifest::at("/");
        let error = manifest.save().unwrap_err();
        assert!(matches!(error, ManifestError::Io(_)), "{error:?}");
    }

    #[test]
    fn save_creates_missing_parent_directories() {
        let path = temp_manifest_path("parents").join("deep").join("nested");
        let mut manifest = InstallManifest::at(&path);
        manifest.record(cask_record("brave-browser", "brave-browser", None));
        manifest.save().unwrap();
        assert!(
            path.as_std_path().is_file(),
            "the manifest landed at the nested path"
        );
    }

    #[test]
    fn temp_paths_are_unique_across_saves_of_one_manifest() {
        // Two saves from one manifest must not target the same temp file —
        // the uniqueness counter is what concurrent in-process saves rely on.
        let manifest = InstallManifest::at(temp_manifest_path("temp-uniqueness"));
        let first = manifest.temp_path().unwrap();
        let second = manifest.temp_path().unwrap();
        assert_ne!(first, second);
        assert_eq!(
            first.parent(),
            manifest.path().parent(),
            "temp files live in the manifest's own directory (same-fs rename)"
        );
        let name = second.file_name().unwrap();
        assert!(name.starts_with('.'), "temp files are hidden: {name}");
        assert!(
            name.contains(".tmp-"),
            "temp files are recognizable: {name}"
        );
    }

    // --- record construction ------------------------------------------------------

    #[test]
    fn install_record_new_derives_the_backend_from_the_ids() {
        let record = InstallRecord::new(
            plan_for(
                "brave-distro",
                Operation::DistroInstall {
                    manager: PackageManager::Apt,
                    package: "brave-browser".to_owned(),
                },
            ),
            NativeIds::Distro {
                package: "brave-browser".to_owned(),
                family: DistroFamily::Debian,
            },
            None,
        );
        assert_eq!(record.backend, BackendId::Distro(DistroFamily::Debian));
    }

    #[test]
    fn install_record_new_stamps_a_current_epoch_seconds() {
        let record = cask_record("brave", "brave", None);
        // `with_installed_at` in the fixture pins 1_700_000_000; assert
        // the raw constructor stamps something sane instead.
        let fresh = InstallRecord::new(record.plan.clone(), record.ids.clone(), None);
        assert!(
            fresh.installed_at >= 1_700_000_000,
            "a sane current epoch, got {}",
            fresh.installed_at
        );
    }

    // --- native id mapping --------------------------------------------------------

    #[test]
    fn native_ids_map_to_their_backend_ids() {
        assert_eq!(
            NativeIds::Homebrew {
                token: "firefox".to_owned(),
                cask: true
            }
            .backend(),
            BackendId::Homebrew
        );
        assert_eq!(
            NativeIds::Flatpak {
                app_id: "com.brave.Browser".to_owned(),
                app_ref: None,
                installation: FlatpakInstallation::System,
            }
            .backend(),
            BackendId::Flatpak
        );
        assert_eq!(
            NativeIds::Distro {
                package: "firefox".to_owned(),
                family: DistroFamily::Fedora
            }
            .backend(),
            BackendId::Distro(DistroFamily::Fedora)
        );
    }

    // --- default location ----------------------------------------------------------

    #[test]
    fn default_path_lives_under_the_platform_data_dir() {
        // Option-aware: hosts without a resolvable data dir (or a
        // non-UTF-8 one) honestly report None.
        if let Some(path) = InstallManifest::default_path() {
            assert!(
                path.ends_with("toride/apps-manifest.json"),
                "unexpected default path {path}"
            );
        }
    }
}
