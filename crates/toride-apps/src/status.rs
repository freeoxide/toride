//! # App status detection
//!
//! [`app_status`] answers "where does this app stand on this host" for one
//! [`TorideId`], combining the two sources the crate keeps:
//!
//! - the **install manifest** ([`InstallManifest`]) — the source of truth
//!   for what *toride* installed: a record's identifiers are probed
//!   verbatim, never re-planned (the A1 round-1 flatpak-ref finding);
//! - the **backends** ([`BackendSet`]) — each backend present on the host
//!   confirms or refutes presence with its kind-aware offline probe.
//!
//! ## The three answers
//!
//! - [`AppStatus::Installed`] — the manifest has a record and the recorded
//!   backend confirms the recorded identifiers are still present (with the
//!   version its probe reports now, not the stale recorded one).
//! - [`AppStatus::Foreign`] — no manifest record, but the app's
//!   backend-native identifiers (supplied by the caller from the registry
//!   app's install method, since a bare `TorideId` carries none) are
//!   present through that backend: installed by someone else — the user,
//!   the distro image, another tool.
//! - [`AppStatus::NotInstalled`] — neither: no record, or the recorded
//!   backend no longer (or never could) report the identifiers.
//!
//! ## Absent backends are answers, not errors
//!
//! A backend missing from the set — no brew on this Linux box, no flatpak
//! on that macOS one — is simply skipped: the app cannot be installed via
//! a backend that is not here, so a record under it reads `NotInstalled`
//! and a `Foreign` probe under it contributes nothing. Only a backend that
//! *is* present failing its probe (brew crashing, unparseable listing) is
//! an [`Error`].
//!
//! ## Probe choice, per backend
//!
//! Kind-aware, per the A2–A4 interface notes:
//!
//! - homebrew records probe [`HomebrewBackend::installed_version`] with
//!   the recorded cask/formula kind — `Ok(None)` is the documented
//!   not-installed signal (exit-gated silent failure or marker line);
//! - distro records probe [`Backend::status`] presence — apk's listing
//!   reports installed packages with no version, so
//!   [`DistroBackend::installed_version`]'s `Ok(None)` cannot distinguish
//!   absent from present-without-a-version;
//! - flatpak records deliberately probe the **scoped listing**
//!   ([`FlatpakBackend::list_entries`]) rather than
//!   [`FlatpakBackend::installed_version`]: flatpak reports apps without
//!   appdata version metadata as an empty version cell, so
//!   `installed_version`'s `Ok(None)` cannot distinguish "absent" from
//!   "present without a version" — the listing row can;
//! - `Foreign` probes (no record, so no recorded kind or scope) ride the
//!   trait's [`Backend::status`] presence lookup: kind-agnostic for brew,
//!   all-installations for flatpak, a single package query for distro.
//!
//! [`Error`]: crate::Error
//! [`HomebrewBackend::installed_version`]: crate::backends::homebrew::HomebrewBackend::installed_version
//! [`FlatpakBackend::installed_version`]: crate::backends::flatpak::FlatpakBackend::installed_version
//! [`FlatpakBackend::list_entries`]: crate::backends::flatpak::FlatpakBackend::list_entries
//! [`DistroBackend::installed_version`]: crate::backends::distro::DistroBackend::installed_version

use toride_registry::TorideId;

use crate::backend::{Backend, BackendId, BackendStatus, StatusQuery};
use crate::backends::flatpak::FlatpakListScope;
use crate::backends::homebrew::BrewKind;
use crate::backends::{DistroBackend, FlatpakBackend, HomebrewBackend};
use crate::error::Result;
use crate::manifest::{InstallManifest, InstallRecord, NativeIds};

/// Where one app stands on this host, relative to toride's own record.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum AppStatus {
    /// Toride's manifest records the app **and** the recorded backend
    /// confirms its recorded identifiers are still installed.
    Installed {
        /// Backend the (still-present) record names.
        backend: BackendId,
        /// Version the backend's probe reports *now* (`None` when the
        /// backend confirms presence but reports no version — e.g. a
        /// flatpak app without appdata metadata).
        version: Option<String>,
    },
    /// The app is installed on this host, but **not by toride** — the
    /// manifest has no record for it and a backend reports its native
    /// identifiers present.
    Foreign {
        /// Backend that reports the app present.
        backend: BackendId,
        /// Human-readable evidence (native id, reported version) — the
        /// UI-facing "someone else installed this" note.
        detail: String,
    },
    /// Neither: no manifest record with a confirming backend, and no
    /// backend reporting the app's identifiers present.
    NotInstalled,
}

/// The backends available on this host for a status lookup — one optional
/// slot per install technology. An absent slot is a skipped backend (see
/// the module docs), never an error; an empty set answers `NotInstalled`
/// for everything.
///
/// # Example
///
/// ```rust,ignore
/// use toride_apps::status::BackendSet;
/// # let (brew, flat, distro) = unimplemented!();
/// // let (brew, flat, distro) = …detected backends…;
/// let set = BackendSet::new().homebrew(&brew).flatpak(&flat).distro(&distro);
/// ```
#[derive(Clone, Copy, Default)]
pub struct BackendSet<'a> {
    /// Homebrew backend, when brew is usable on this host.
    homebrew: Option<&'a HomebrewBackend>,
    /// Flatpak backend, when flatpak is usable on this host.
    flatpak: Option<&'a FlatpakBackend>,
    /// Distro backend, when a family manager is usable on this host.
    distro: Option<&'a DistroBackend>,
}

/// Debug prints slot occupancy, not the backends (they are not `Debug` —
/// their seam carries an unprintable runner handle).
impl std::fmt::Debug for BackendSet<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BackendSet")
            .field("homebrew", &self.homebrew.is_some())
            .field("flatpak", &self.flatpak.is_some())
            .field("distro", &self.distro.is_some())
            .finish()
    }
}

impl<'a> BackendSet<'a> {
    /// The empty set — every backend absent, nothing probed.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Attach the homebrew backend — consume-and-return.
    #[must_use]
    pub const fn homebrew(mut self, backend: &'a HomebrewBackend) -> Self {
        self.homebrew = Some(backend);
        self
    }

    /// Attach the flatpak backend — consume-and-return.
    #[must_use]
    pub const fn flatpak(mut self, backend: &'a FlatpakBackend) -> Self {
        self.flatpak = Some(backend);
        self
    }

    /// Attach the distro backend — consume-and-return.
    #[must_use]
    pub const fn distro(mut self, backend: &'a DistroBackend) -> Self {
        self.distro = Some(backend);
        self
    }
}

/// Resolve `id`'s standing on this host.
///
/// Precedence: the manifest record (if any) is probed with its own
/// recorded identifiers — the source of truth, never the caller's
/// re-derived ones. Without a record, `native` (the registry app's
/// backend-native identifiers, when the caller knows them) is probed for
/// `Foreign` presence; without either, the answer is `NotInstalled`.
///
/// # Errors
///
/// [`Error::Command`](crate::Error::Command) when a backend that *is* in
/// the set fails its probe. An absent backend is never an error — it is
/// skipped.
pub async fn app_status(
    id: &TorideId,
    native: Option<&NativeIds>,
    manifest: &InstallManifest,
    backends: &BackendSet<'_>,
) -> Result<AppStatus> {
    if let Some(record) = manifest.get(id) {
        return toride_recorded_status(record, backends).await;
    }
    match native {
        Some(native) => foreign_status(native, backends).await,
        // No record and no native identifiers to probe: nothing on this
        // host can be asked about the app.
        None => Ok(AppStatus::NotInstalled),
    }
}

/// Confirm or refute one toride-installed record with its own backend:
/// the recorded identifiers, verbatim, against the recorded backend when
/// that backend is present on this host.
async fn toride_recorded_status(
    record: &InstallRecord,
    backends: &BackendSet<'_>,
) -> Result<AppStatus> {
    match &record.ids {
        NativeIds::Homebrew { token, cask } => {
            let Some(backend) = backends.homebrew else {
                // Brew is not on this host: nothing it installed is here.
                return Ok(AppStatus::NotInstalled);
            };
            let kind = if *cask {
                BrewKind::Cask
            } else {
                BrewKind::Formula
            };
            // The A2 contract: Ok(None) is the not-installed signal for
            // the kind-scoped probe (brew's `list --versions` always
            // carries a version for a present item).
            Ok(match backend.installed_version(kind, token).await? {
                Some(version) => AppStatus::Installed {
                    backend: BackendId::Homebrew,
                    version: Some(version),
                },
                None => AppStatus::NotInstalled,
            })
        }
        NativeIds::Flatpak {
            app_id,
            installation,
            ..
        } => {
            let Some(backend) = backends.flatpak else {
                return Ok(AppStatus::NotInstalled);
            };
            // Scoped listing, not `installed_version`: flatpak reports
            // apps without appdata metadata as an empty version cell, so
            // presence and version must be read from the row.
            let entries = backend
                .list_entries(FlatpakListScope::from(*installation))
                .await?;
            Ok(
                match entries.iter().find(|entry| &entry.application == app_id) {
                    Some(entry) => AppStatus::Installed {
                        backend: BackendId::Flatpak,
                        version: entry.version.clone(),
                    },
                    None => AppStatus::NotInstalled,
                },
            )
        }
        NativeIds::Distro { package, family } => {
            // Only a backend serving the recorded family can have the
            // package; a foreign-family backend on this host (unlikely
            // but constructible) reports nothing for it.
            let Some(backend) = backends.distro else {
                return Ok(AppStatus::NotInstalled);
            };
            if backend.family() != *family {
                return Ok(AppStatus::NotInstalled);
            }
            // Presence, not version: apk's listing reports installed
            // packages with no version at all, so `installed_version`'s
            // Ok(None) cannot distinguish absent from present-without-a-
            // version — the same reason the flatpak arm reads the row.
            Ok(match backend.status(StatusQuery::new(package)).await? {
                BackendStatus::Installed { version } => AppStatus::Installed {
                    backend: BackendId::Distro(*family),
                    version,
                },
                BackendStatus::NotInstalled => AppStatus::NotInstalled,
            })
        }
    }
}

/// Probe the caller-known native identifiers for presence without a
/// manifest record: a hit is `Foreign` (installed, but not by toride).
async fn foreign_status(native: &NativeIds, backends: &BackendSet<'_>) -> Result<AppStatus> {
    match native {
        NativeIds::Homebrew { token, .. } => {
            let Some(backend) = backends.homebrew else {
                return Ok(AppStatus::NotInstalled);
            };
            // Kind-agnostic presence, deliberately: the caller's
            // cask/formula kind is destructured away on purpose — whoever
            // installed this app may have used the OTHER kind than the
            // registry method names (user installed the cask, method
            // says formula, or vice versa), and presence of either kind
            // makes the app Foreign. The info listing covers both kinds.
            let status = backend.status(StatusQuery::new(token)).await?;
            Ok(foreign_from(
                BackendId::Homebrew,
                &format!("brew token `{token}`"),
                status,
            ))
        }
        NativeIds::Flatpak { app_id, .. } => {
            let Some(backend) = backends.flatpak else {
                return Ok(AppStatus::NotInstalled);
            };
            // All installations (trait default), deliberately: the
            // caller's installation scope is destructured away on purpose
            // — a foreign install may live in the other installation
            // (user-installed under --system while toride plans --user),
            // and presence in either makes the app Foreign.
            let status = backend.status(StatusQuery::new(app_id)).await?;
            Ok(foreign_from(
                BackendId::Flatpak,
                &format!("flatpak app id `{app_id}`"),
                status,
            ))
        }
        NativeIds::Distro { package, family } => {
            let Some(backend) = backends.distro else {
                return Ok(AppStatus::NotInstalled);
            };
            if backend.family() != *family {
                return Ok(AppStatus::NotInstalled);
            }
            let status = backend.status(StatusQuery::new(package)).await?;
            Ok(foreign_from(
                BackendId::Distro(*family),
                &format!("package `{package}`"),
                status,
            ))
        }
    }
}

/// Turn a backend's presence answer into the `Foreign`/`NotInstalled`
/// verdict, wording the detail from what the backend reported.
fn foreign_from(backend: BackendId, subject: &str, status: BackendStatus) -> AppStatus {
    match status {
        BackendStatus::Installed { version } => AppStatus::Foreign {
            backend,
            detail: match version {
                Some(version) => {
                    format!("{subject} is installed at version {version}, but not by toride")
                }
                None => format!("{subject} is installed, but not by toride"),
            },
        },
        BackendStatus::NotInstalled => AppStatus::NotInstalled,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::InstallRecord;
    use crate::plan::{FlatpakInstallation, Operation, PackageManager};
    use crate::runner::{CommandRunner, command};
    use camino::Utf8PathBuf;
    use std::sync::Arc;
    use toride_registry::DistroFamily;
    use toride_runner::CommandOutput;
    use toride_runner::fake::FakeRunner;

    // --- test helpers ----------------------------------------------------------

    fn app_id(slug: &str) -> TorideId {
        TorideId::slugify(slug)
    }

    /// An empty manifest at a never-used temp path (no I/O happens — the
    /// status layer only reads the in-memory entries).
    fn empty_manifest() -> InstallManifest {
        let path = Utf8PathBuf::from_path_buf(std::env::temp_dir().join("toride-apps-status.json"))
            .expect("system temp dir is valid UTF-8");
        InstallManifest::at(path)
    }

    /// A minimal brew-cask install plan for the slug.
    fn cask_plan(slug: &str, token: &str) -> crate::plan::InstallPlan {
        crate::plan::InstallPlan {
            app: app_id(slug),
            backend: BackendId::Homebrew,
            operation: Operation::BrewInstall {
                cask: true,
                token: token.to_owned(),
            },
            dry_run: false,
            requires_elevation: false,
        }
    }

    /// A recorded brew cask, at a deterministic epoch.
    fn cask_record(slug: &str, token: &str) -> InstallRecord {
        InstallRecord::new(
            cask_plan(slug, token),
            NativeIds::Homebrew {
                token: token.to_owned(),
                cask: true,
            },
            Some("recorded-but-stale".to_owned()),
        )
        .with_installed_at(1_700_000_000)
    }

    /// A recorded flatpak app in `installation`.
    fn flatpak_record(
        slug: &str,
        app_id_str: &str,
        installation: FlatpakInstallation,
    ) -> InstallRecord {
        InstallRecord::new(
            crate::plan::InstallPlan {
                app: app_id(slug),
                backend: BackendId::Flatpak,
                operation: Operation::FlatpakInstall {
                    remote: "flathub".to_owned(),
                    app_ref: format!("app/{app_id_str}/x86_64/stable"),
                    installation,
                },
                dry_run: false,
                requires_elevation: false,
            },
            NativeIds::Flatpak {
                app_id: app_id_str.to_owned(),
                app_ref: Some(format!("app/{app_id_str}/x86_64/stable")),
                installation,
            },
            None,
        )
        .with_installed_at(1_700_000_000)
    }

    /// A recorded distro package on `family`.
    fn distro_record(slug: &str, package: &str, family: DistroFamily) -> InstallRecord {
        InstallRecord::new(
            crate::plan::InstallPlan {
                app: app_id(slug),
                backend: BackendId::Distro(family),
                operation: Operation::DistroInstall {
                    manager: PackageManager::Apt,
                    package: package.to_owned(),
                },
                dry_run: false,
                requires_elevation: true,
            },
            NativeIds::Distro {
                package: package.to_owned(),
                family,
            },
            None,
        )
        .with_installed_at(1_700_000_000)
    }

    fn homebrew_backend(fake: &FakeRunner) -> HomebrewBackend {
        HomebrewBackend::new(CommandRunner::new(Arc::new(fake.clone())))
    }

    fn flatpak_backend(fake: &FakeRunner) -> FlatpakBackend {
        FlatpakBackend::new(CommandRunner::new(Arc::new(fake.clone())))
    }

    fn distro_backend(family: DistroFamily, fake: &FakeRunner) -> DistroBackend {
        DistroBackend::new(family, CommandRunner::new(Arc::new(fake.clone())))
    }

    /// The exact `brew list` spec the kind-scoped version probe runs.
    fn brew_versions_spec(kind: BrewKind, token: &str) -> toride_runner::CommandSpec {
        command("brew", ["list", kind.flag(), "--versions", token])
    }

    /// The exact `brew info` spec the trait-default presence status runs.
    fn brew_info_spec() -> toride_runner::CommandSpec {
        command("brew", ["info", "--json=v2", "--installed"])
    }

    /// The exact `flatpak list` spec the scoped listing runs.
    fn flatpak_list_spec(scope: FlatpakListScope) -> toride_runner::CommandSpec {
        let mut args = vec!["list"];
        if let Some(flag) = scope.flag() {
            args.push(flag);
        }
        args.push("--app");
        args.push("--columns=application,version,origin,installation");
        command("flatpak", args)
    }

    /// The exact dpkg-query spec the single-package probe runs.
    fn dpkg_query_spec(package: &str) -> toride_runner::CommandSpec {
        command(
            "dpkg-query",
            [
                "--show",
                "--showformat=${db:Status-Abbrev}${Package}\\t${Version}\\n",
                package,
            ],
        )
        .env("LC_ALL", "C")
    }

    /// The exact pacman query spec the single-package probe runs.
    fn pacman_query_spec(package: &str) -> toride_runner::CommandSpec {
        command("pacman", ["--query", package]).env("LC_ALL", "C")
    }

    /// The exact apk listing spec the single-package probe runs.
    fn apk_query_spec(package: &str) -> toride_runner::CommandSpec {
        command("apk", ["list", "--installed", package]).env("LC_ALL", "C")
    }

    /// The `brew info` document carrying one installed cask.
    fn brew_cask_installed_document(token: &str, version: &str) -> String {
        format!(
            r#"{{"formulae": [], "casks": [{{"token": "{token}", "name": ["Cask"], "version": "{version}", "installed": "{version}"}}]}}"#
        )
    }

    /// One flatpak listing row (tab-separated, four columns).
    fn flatpak_row(app_id: &str, version: &str, installation: &str) -> String {
        format!("{app_id}\t{version}\tflathub\t{installation}\n")
    }

    // --- Installed: manifest hit, backend confirms ---------------------------

    #[tokio::test]
    async fn manifest_hit_brew_record_with_present_cask_reports_installed_with_current_version() {
        let fake = FakeRunner::new().strict().respond(
            brew_versions_spec(BrewKind::Cask, "firefox"),
            CommandOutput::from_stdout("firefox 138.0\n"),
        );
        let brew = homebrew_backend(&fake);
        let backends = BackendSet::new().homebrew(&brew);
        let mut manifest = empty_manifest();
        manifest.record(cask_record("firefox", "firefox"));
        let status = app_status(&app_id("firefox"), None, &manifest, &backends)
            .await
            .unwrap();
        assert_eq!(
            status,
            AppStatus::Installed {
                backend: BackendId::Homebrew,
                version: Some("138.0".to_owned()),
            },
            "the live probe's version, not the stale recorded one"
        );
        fake.assert_no_unmatched_calls();
    }

    #[tokio::test]
    async fn manifest_hit_brew_record_probes_with_the_recorded_kind() {
        // A formula record must probe `--formula`, never the cask flag.
        let fake = FakeRunner::new().strict().respond(
            brew_versions_spec(BrewKind::Formula, "ripgrep"),
            CommandOutput::from_stdout("ripgrep 14.1.0\n"),
        );
        let brew = homebrew_backend(&fake);
        let backends = BackendSet::new().homebrew(&brew);
        let mut manifest = empty_manifest();
        manifest.record(InstallRecord::new(
            cask_plan("ripgrep", "ripgrep"),
            NativeIds::Homebrew {
                token: "ripgrep".to_owned(),
                cask: false,
            },
            None,
        ));
        let status = app_status(&app_id("ripgrep"), None, &manifest, &backends)
            .await
            .unwrap();
        assert_eq!(
            status,
            AppStatus::Installed {
                backend: BackendId::Homebrew,
                version: Some("14.1.0".to_owned()),
            }
        );
        fake.assert_no_unmatched_calls();
    }

    #[tokio::test]
    async fn manifest_hit_brew_record_when_brew_no_longer_has_it_reports_not_installed() {
        // The recorded silent not-installed signal: exit 1, empty stderr.
        let fake = FakeRunner::new().strict().respond(
            brew_versions_spec(BrewKind::Cask, "firefox"),
            CommandOutput::from_stderr("", 1),
        );
        let brew = homebrew_backend(&fake);
        let backends = BackendSet::new().homebrew(&brew);
        let mut manifest = empty_manifest();
        manifest.record(cask_record("firefox", "firefox"));
        let status = app_status(&app_id("firefox"), None, &manifest, &backends)
            .await
            .unwrap();
        assert_eq!(status, AppStatus::NotInstalled);
        fake.assert_no_unmatched_calls();
    }

    #[tokio::test]
    async fn manifest_hit_flatpak_record_reports_installed_with_the_listed_version() {
        let fake = FakeRunner::new().strict().respond(
            flatpak_list_spec(FlatpakListScope::User),
            CommandOutput::from_stdout(flatpak_row("com.brave.Browser", "1.96.59", "user")),
        );
        let flatpak = flatpak_backend(&fake);
        let backends = BackendSet::new().flatpak(&flatpak);
        let mut manifest = empty_manifest();
        manifest.record(flatpak_record(
            "brave-browser",
            "com.brave.Browser",
            FlatpakInstallation::User,
        ));
        let status = app_status(&app_id("brave-browser"), None, &manifest, &backends)
            .await
            .unwrap();
        assert_eq!(
            status,
            AppStatus::Installed {
                backend: BackendId::Flatpak,
                version: Some("1.96.59".to_owned()),
            }
        );
        fake.assert_no_unmatched_calls();
    }

    #[tokio::test]
    async fn manifest_hit_flatpak_record_without_a_version_still_reports_installed() {
        // The empty-version row (flatpak apps without appdata metadata) —
        // the exact case that rules out `installed_version`, whose
        // Ok(None) cannot tell this apart from absence.
        let fake = FakeRunner::new().strict().respond(
            flatpak_list_spec(FlatpakListScope::User),
            CommandOutput::from_stdout(flatpak_row(
                "io.gitlab.adwcustomizer.AdwCustomizer",
                "",
                "user",
            )),
        );
        let flatpak = flatpak_backend(&fake);
        let backends = BackendSet::new().flatpak(&flatpak);
        let mut manifest = empty_manifest();
        manifest.record(flatpak_record(
            "adwcustomizer",
            "io.gitlab.adwcustomizer.AdwCustomizer",
            FlatpakInstallation::User,
        ));
        let status = app_status(&app_id("adwcustomizer"), None, &manifest, &backends)
            .await
            .unwrap();
        assert_eq!(
            status,
            AppStatus::Installed {
                backend: BackendId::Flatpak,
                version: None,
            }
        );
        fake.assert_no_unmatched_calls();
    }

    #[tokio::test]
    async fn manifest_hit_flatpak_record_probes_the_recorded_installation_scope() {
        // A system-scope record must list --system, not --user.
        let spec = flatpak_list_spec(FlatpakListScope::System);
        let fake = FakeRunner::new().strict().respond(
            spec.clone(),
            CommandOutput::from_stdout(flatpak_row("org.mozilla.firefox", "141.0.3", "system")),
        );
        let flatpak = flatpak_backend(&fake);
        let backends = BackendSet::new().flatpak(&flatpak);
        let mut manifest = empty_manifest();
        manifest.record(flatpak_record(
            "firefox",
            "org.mozilla.firefox",
            FlatpakInstallation::System,
        ));
        let status = app_status(&app_id("firefox"), None, &manifest, &backends)
            .await
            .unwrap();
        assert_eq!(
            status,
            AppStatus::Installed {
                backend: BackendId::Flatpak,
                version: Some("141.0.3".to_owned()),
            }
        );
        fake.assert_called_with(&spec);
        fake.assert_no_unmatched_calls();
    }

    #[tokio::test]
    async fn manifest_hit_flatpak_record_absent_from_the_scoped_listing_reports_not_installed() {
        // The target lives only in the user installation; the --system
        // scoped listing flatpak would run here lists *other* apps, never
        // a user row — so the scoped probe must not find it.
        let fake = FakeRunner::new().strict().respond(
            flatpak_list_spec(FlatpakListScope::System),
            CommandOutput::from_stdout(flatpak_row("org.gnome.Calculator", "47.1", "system")),
        );
        let flatpak = flatpak_backend(&fake);
        let backends = BackendSet::new().flatpak(&flatpak);
        let mut manifest = empty_manifest();
        manifest.record(flatpak_record(
            "firefox",
            "org.mozilla.firefox",
            FlatpakInstallation::System,
        ));
        let status = app_status(&app_id("firefox"), None, &manifest, &backends)
            .await
            .unwrap();
        assert_eq!(status, AppStatus::NotInstalled);
        fake.assert_no_unmatched_calls();
    }

    #[tokio::test]
    async fn manifest_hit_distro_record_reports_installed_with_the_queried_version() {
        let fake = FakeRunner::new().strict().respond(
            dpkg_query_spec("firefox-esr"),
            CommandOutput::from_stdout("ii firefox-esr\t128.0esr-1\n"),
        );
        let distro = distro_backend(DistroFamily::Debian, &fake);
        let backends = BackendSet::new().distro(&distro);
        let mut manifest = empty_manifest();
        manifest.record(distro_record(
            "firefox-esr",
            "firefox-esr",
            DistroFamily::Debian,
        ));
        let status = app_status(&app_id("firefox-esr"), None, &manifest, &backends)
            .await
            .unwrap();
        assert_eq!(
            status,
            AppStatus::Installed {
                backend: BackendId::Distro(DistroFamily::Debian),
                version: Some("128.0esr-1".to_owned()),
            }
        );
        fake.assert_no_unmatched_calls();
    }

    #[tokio::test]
    async fn manifest_hit_distro_record_when_dpkg_reports_not_found_reports_not_installed() {
        // The real not-found wording (live-verified in A4): exit 1 plus
        // the marker line classifies as Ok(None) = not installed.
        let fake = FakeRunner::new().strict().respond(
            dpkg_query_spec("firefox-esr"),
            CommandOutput::from_stderr("dpkg-query: no packages found matching firefox-esr\n", 1),
        );
        let distro = distro_backend(DistroFamily::Debian, &fake);
        let backends = BackendSet::new().distro(&distro);
        let mut manifest = empty_manifest();
        manifest.record(distro_record(
            "firefox-esr",
            "firefox-esr",
            DistroFamily::Debian,
        ));
        let status = app_status(&app_id("firefox-esr"), None, &manifest, &backends)
            .await
            .unwrap();
        assert_eq!(status, AppStatus::NotInstalled);
        fake.assert_no_unmatched_calls();
    }

    #[tokio::test]
    async fn manifest_hit_apk_record_without_a_version_still_reports_installed() {
        // apk's listing carries no version at all (src/app_list.c) — the
        // exact case that rules out `installed_version` for distro records.
        let fake = FakeRunner::new().strict().respond(
            apk_query_spec("brave-browser"),
            CommandOutput::from_stdout("brave-browser\n"),
        );
        let distro = distro_backend(DistroFamily::Alpine, &fake);
        let backends = BackendSet::new().distro(&distro);
        let mut manifest = empty_manifest();
        manifest.record(distro_record(
            "brave",
            "brave-browser",
            DistroFamily::Alpine,
        ));
        let status = app_status(&app_id("brave"), None, &manifest, &backends)
            .await
            .unwrap();
        assert_eq!(
            status,
            AppStatus::Installed {
                backend: BackendId::Distro(DistroFamily::Alpine),
                version: None,
            }
        );
        fake.assert_no_unmatched_calls();
    }

    #[tokio::test]
    async fn manifest_hit_pacman_record_when_the_package_is_missing_reports_not_installed() {
        // pacman's not-found answer: exit 1 with the marker line on stderr.
        let fake = FakeRunner::new().strict().respond(
            pacman_query_spec("firefox"),
            CommandOutput::from_stderr("error: package 'firefox' was not found\n", 1),
        );
        let distro = distro_backend(DistroFamily::Arch, &fake);
        let backends = BackendSet::new().distro(&distro);
        let mut manifest = empty_manifest();
        manifest.record(distro_record("firefox", "firefox", DistroFamily::Arch));
        let status = app_status(&app_id("firefox"), None, &manifest, &backends)
            .await
            .unwrap();
        assert_eq!(status, AppStatus::NotInstalled);
        fake.assert_no_unmatched_calls();
    }

    #[tokio::test]
    async fn manifest_hit_distro_record_on_a_foreign_family_backend_reports_not_installed() {
        // A Debian record against a Fedora backend: the family gate must
        // skip the probe entirely — nothing dispatched.
        let fake = FakeRunner::new().strict();
        let distro = distro_backend(DistroFamily::Fedora, &fake);
        let backends = BackendSet::new().distro(&distro);
        let mut manifest = empty_manifest();
        manifest.record(distro_record(
            "firefox-esr",
            "firefox-esr",
            DistroFamily::Debian,
        ));
        let status = app_status(&app_id("firefox-esr"), None, &manifest, &backends)
            .await
            .unwrap();
        assert_eq!(status, AppStatus::NotInstalled);
        fake.assert_no_unmatched_calls();
    }

    #[tokio::test]
    async fn manifest_hit_ignores_caller_supplied_native_ids() {
        // The record is the source of truth: caller-supplied ids for the
        // same app must never be probed when a record exists.
        let fake = FakeRunner::new().strict().respond(
            brew_versions_spec(BrewKind::Cask, "recorded-token"),
            CommandOutput::from_stdout("recorded-token 1.0\n"),
        );
        let brew = homebrew_backend(&fake);
        let backends = BackendSet::new().homebrew(&brew);
        let mut manifest = empty_manifest();
        manifest.record(cask_record("brave", "recorded-token"));
        let native = NativeIds::Homebrew {
            token: "caller-guess".to_owned(),
            cask: true,
        };
        let status = app_status(&app_id("brave"), Some(&native), &manifest, &backends)
            .await
            .unwrap();
        assert_eq!(
            status,
            AppStatus::Installed {
                backend: BackendId::Homebrew,
                version: Some("1.0".to_owned()),
            }
        );
        fake.assert_no_unmatched_calls();
    }

    // --- NotInstalled: absent backends are answers, not errors -----------------

    #[tokio::test]
    async fn manifest_hit_with_the_recorded_backend_absent_reports_not_installed() {
        // No brew on this host (empty set): its records read NotInstalled,
        // and no error is raised for the absent backend.
        let mut manifest = empty_manifest();
        manifest.record(cask_record("firefox", "firefox"));
        let status = app_status(&app_id("firefox"), None, &manifest, &BackendSet::new())
            .await
            .unwrap();
        assert_eq!(status, AppStatus::NotInstalled);
    }

    #[tokio::test]
    async fn manifest_miss_without_native_ids_reports_not_installed() {
        let status = app_status(
            &app_id("ghost"),
            None,
            &empty_manifest(),
            &BackendSet::new(),
        )
        .await
        .unwrap();
        assert_eq!(status, AppStatus::NotInstalled);
    }

    #[tokio::test]
    async fn manifest_miss_with_native_ids_for_an_absent_backend_reports_not_installed() {
        // Flatpak ids, but no flatpak in the set (e.g. a macOS host).
        let native = NativeIds::Flatpak {
            app_id: "com.brave.Browser".to_owned(),
            app_ref: None,
            installation: FlatpakInstallation::User,
        };
        let status = app_status(
            &app_id("brave-browser"),
            Some(&native),
            &empty_manifest(),
            &BackendSet::new(),
        )
        .await
        .unwrap();
        assert_eq!(status, AppStatus::NotInstalled);
    }

    // --- Foreign: backend present, manifest empty ------------------------------

    #[tokio::test]
    async fn manifest_miss_with_brew_listing_the_token_reports_foreign() {
        let fake = FakeRunner::new().strict().respond(
            brew_info_spec(),
            CommandOutput::from_stdout(brew_cask_installed_document("firefox", "138.0")),
        );
        let brew = homebrew_backend(&fake);
        let backends = BackendSet::new().homebrew(&brew);
        let native = NativeIds::Homebrew {
            token: "firefox".to_owned(),
            cask: true,
        };
        let status = app_status(
            &app_id("firefox"),
            Some(&native),
            &empty_manifest(),
            &backends,
        )
        .await
        .unwrap();
        match status {
            AppStatus::Foreign { backend, detail } => {
                assert_eq!(backend, BackendId::Homebrew);
                assert!(detail.contains("firefox"), "{detail}");
                assert!(detail.contains("138.0"), "{detail}");
                assert!(detail.contains("not by toride"), "{detail}");
            }
            other => panic!("expected Foreign, got {other:?}"),
        }
        fake.assert_no_unmatched_calls();
    }

    #[tokio::test]
    async fn manifest_miss_with_flatpak_listing_the_app_id_reports_foreign() {
        // The Foreign probe is unscoped: a system-install hits too.
        let fake = FakeRunner::new().strict().respond(
            flatpak_list_spec(FlatpakListScope::All),
            CommandOutput::from_stdout(flatpak_row("org.mozilla.firefox", "141.0.3", "system")),
        );
        let flatpak = flatpak_backend(&fake);
        let backends = BackendSet::new().flatpak(&flatpak);
        let native = NativeIds::Flatpak {
            app_id: "org.mozilla.firefox".to_owned(),
            app_ref: None,
            installation: FlatpakInstallation::User,
        };
        let status = app_status(
            &app_id("firefox"),
            Some(&native),
            &empty_manifest(),
            &backends,
        )
        .await
        .unwrap();
        match status {
            AppStatus::Foreign { backend, detail } => {
                assert_eq!(backend, BackendId::Flatpak);
                assert!(detail.contains("org.mozilla.firefox"), "{detail}");
            }
            other => panic!("expected Foreign, got {other:?}"),
        }
        fake.assert_no_unmatched_calls();
    }

    #[tokio::test]
    async fn manifest_miss_with_dpkg_listing_the_package_reports_foreign() {
        let fake = FakeRunner::new().strict().respond(
            dpkg_query_spec("firefox-esr"),
            CommandOutput::from_stdout("ii firefox-esr\t128.0esr-1\n"),
        );
        let distro = distro_backend(DistroFamily::Debian, &fake);
        let backends = BackendSet::new().distro(&distro);
        let native = NativeIds::Distro {
            package: "firefox-esr".to_owned(),
            family: DistroFamily::Debian,
        };
        let status = app_status(
            &app_id("firefox-esr"),
            Some(&native),
            &empty_manifest(),
            &backends,
        )
        .await
        .unwrap();
        match status {
            AppStatus::Foreign { backend, detail } => {
                assert_eq!(backend, BackendId::Distro(DistroFamily::Debian));
                assert!(detail.contains("firefox-esr"), "{detail}");
                assert!(detail.contains("128.0esr-1"), "{detail}");
            }
            other => panic!("expected Foreign, got {other:?}"),
        }
        fake.assert_no_unmatched_calls();
    }

    #[tokio::test]
    async fn manifest_miss_when_the_backend_does_not_carry_the_id_reports_not_installed() {
        // Brew lists other things, not this token.
        let fake = FakeRunner::new().strict().respond(
            brew_info_spec(),
            CommandOutput::from_stdout(brew_cask_installed_document("something-else", "1.0")),
        );
        let brew = homebrew_backend(&fake);
        let backends = BackendSet::new().homebrew(&brew);
        let native = NativeIds::Homebrew {
            token: "firefox".to_owned(),
            cask: true,
        };
        let status = app_status(
            &app_id("firefox"),
            Some(&native),
            &empty_manifest(),
            &backends,
        )
        .await
        .unwrap();
        assert_eq!(status, AppStatus::NotInstalled);
        fake.assert_no_unmatched_calls();
    }

    #[tokio::test]
    async fn manifest_miss_with_distro_ids_for_a_foreign_family_reports_not_installed() {
        // Fedora package ids against a Debian backend: skipped, nothing
        // dispatched (no rpm probe is even attempted).
        let fake = FakeRunner::new().strict();
        let distro = distro_backend(DistroFamily::Debian, &fake);
        let backends = BackendSet::new().distro(&distro);
        let native = NativeIds::Distro {
            package: "firefox".to_owned(),
            family: DistroFamily::Fedora,
        };
        let status = app_status(
            &app_id("firefox"),
            Some(&native),
            &empty_manifest(),
            &backends,
        )
        .await
        .unwrap();
        assert_eq!(status, AppStatus::NotInstalled);
        fake.assert_no_unmatched_calls();
    }

    // --- errors propagate -------------------------------------------------------

    #[tokio::test]
    async fn a_backend_that_fails_its_probe_surfaces_the_command_error() {
        // Only failures of *present* backends are errors: brew is here,
        // and its probe dies (binary vanished between detection and use).
        let spec = brew_versions_spec(BrewKind::Cask, "firefox");
        let fake = FakeRunner::new()
            .strict()
            .respond_err(spec, toride_runner::Error::BinaryNotFound("brew".into()));
        let brew = homebrew_backend(&fake);
        let backends = BackendSet::new().homebrew(&brew);
        let mut manifest = empty_manifest();
        manifest.record(cask_record("firefox", "firefox"));
        let error = app_status(&app_id("firefox"), None, &manifest, &backends)
            .await
            .unwrap_err();
        assert!(
            matches!(error, crate::error::Error::Command(_)),
            "{error:?}"
        );
        fake.assert_no_unmatched_calls();
    }
}
