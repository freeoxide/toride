//! # App status detection
//!
//! [`app_status`] answers "where does this app stand on this host" for one
//! [`TorideId`], combining the two sources the crate keeps:
//!
//! - the **install records** ([`InstallRecord`], the caller holds the
//!   record the store loaded) — the source of truth for what *toride*
//!   installed: a record's identifiers are probed verbatim, never
//!   re-planned (the A1 round-1 flatpak-ref finding);
//! - the **backends** ([`BackendSet`]) — each backend present on the host
//!   confirms or refutes presence with its kind-aware offline probe.
//!
//! ## The three answers
//!
//! - [`AppStatus::Installed`] — a record was supplied and the recorded
//!   backend confirms the recorded identifiers are still present (with
//!   the version its probe reports now, not the stale recorded one).
//! - [`AppStatus::Foreign`] — no record, but the app's backend-native
//!   identifiers (supplied by the caller from the registry app's install
//!   method, since a bare `TorideId` carries none) are present through
//!   that backend: installed by someone else — the user, the distro
//!   image, another tool.
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
//! [`TorideId`]: toride_registry::TorideId
//! [`HomebrewBackend::installed_version`]: crate::backends::homebrew::HomebrewBackend::installed_version
//! [`FlatpakBackend::installed_version`]: crate::backends::flatpak::FlatpakBackend::installed_version
//! [`FlatpakBackend::list_entries`]: crate::backends::flatpak::FlatpakBackend::list_entries
//! [`DistroBackend::installed_version`]: crate::backends::distro::DistroBackend::installed_version

use crate::backend::{Backend, BackendId, BackendStatus, StatusQuery};
#[cfg(feature = "direct")]
use crate::backends::DirectBackend;
#[cfg(feature = "mise")]
use crate::backends::MiseBackend;
use crate::backends::flatpak::FlatpakListScope;
use crate::backends::homebrew::BrewKind;
use crate::backends::{
    CargoBackend, DistroBackend, FlatpakBackend, HomebrewBackend, NpmBackend, PipxBackend,
    UvBackend,
};
use crate::error::Result;
use crate::manifest::{InstallRecord, NativeIds};

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
    /// Direct-download backend, when attached (the `direct` feature).
    #[cfg(feature = "direct")]
    direct: Option<&'a DirectBackend>,
    /// npm backend, when attached.
    npm: Option<&'a NpmBackend>,
    /// cargo backend, when attached.
    cargo: Option<&'a CargoBackend>,
    /// pipx backend, when attached.
    pipx: Option<&'a PipxBackend>,
    /// uv backend, when attached.
    uv: Option<&'a UvBackend>,
    /// mise backend, when attached (the `mise` feature).
    #[cfg(feature = "mise")]
    mise: Option<&'a MiseBackend>,
}

/// Debug prints slot occupancy, not the backends (they are not `Debug` —
/// their seam carries an unprintable runner handle).
impl std::fmt::Debug for BackendSet<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut builder = f.debug_struct("BackendSet");
        builder
            .field("homebrew", &self.homebrew.is_some())
            .field("flatpak", &self.flatpak.is_some())
            .field("distro", &self.distro.is_some())
            .field("npm", &self.npm.is_some())
            .field("cargo", &self.cargo.is_some())
            .field("pipx", &self.pipx.is_some())
            .field("uv", &self.uv.is_some());
        #[cfg(feature = "direct")]
        builder.field("direct", &self.direct.is_some());
        #[cfg(feature = "mise")]
        builder.field("mise", &self.mise.is_some());
        builder.finish()
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

    /// Attach the direct-download backend — consume-and-return (the
    /// `direct` feature).
    #[cfg(feature = "direct")]
    #[must_use]
    pub const fn direct(mut self, backend: &'a DirectBackend) -> Self {
        self.direct = Some(backend);
        self
    }

    /// Attach the npm backend — consume-and-return.
    #[must_use]
    pub const fn npm(mut self, backend: &'a NpmBackend) -> Self {
        self.npm = Some(backend);
        self
    }

    /// Attach the cargo backend — consume-and-return.
    #[must_use]
    pub const fn cargo(mut self, backend: &'a CargoBackend) -> Self {
        self.cargo = Some(backend);
        self
    }

    /// Attach the pipx backend — consume-and-return.
    #[must_use]
    pub const fn pipx(mut self, backend: &'a PipxBackend) -> Self {
        self.pipx = Some(backend);
        self
    }

    /// Attach the uv backend — consume-and-return.
    #[must_use]
    pub const fn uv(mut self, backend: &'a UvBackend) -> Self {
        self.uv = Some(backend);
        self
    }

    /// Attach the mise backend — consume-and-return (the `mise` feature).
    #[cfg(feature = "mise")]
    #[must_use]
    pub const fn mise(mut self, backend: &'a MiseBackend) -> Self {
        self.mise = Some(backend);
        self
    }
}

/// The language-ecosystem slot a set of ids routes to — the one seam all
/// five share (their trait `status` presence probe over the listing);
/// `None` when that backend is not attached.
fn language_backend<'a>(set: &BackendSet<'a>, ids: &NativeIds) -> Option<&'a dyn Backend> {
    let backend: Option<&'a dyn Backend> = match ids {
        NativeIds::Npm { .. } => set.npm.map(|backend| backend as &dyn Backend),
        NativeIds::Cargo { .. } => set.cargo.map(|backend| backend as &dyn Backend),
        NativeIds::Pipx { .. } => set.pipx.map(|backend| backend as &dyn Backend),
        NativeIds::Uv { .. } => set.uv.map(|backend| backend as &dyn Backend),
        #[cfg(feature = "mise")]
        NativeIds::Mise { .. } => set.mise.map(|backend| backend as &dyn Backend),
        NativeIds::Homebrew { .. } | NativeIds::Flatpak { .. } | NativeIds::Distro { .. } => {
            return None;
        }
        #[cfg(feature = "direct")]
        NativeIds::Direct { .. } => return None,
    };
    backend
}

/// The language-ecosystem native id a presence probe keys on.
fn language_native_id(ids: &NativeIds) -> &str {
    match ids {
        NativeIds::Npm { package } | NativeIds::Pipx { package } | NativeIds::Uv { package } => {
            package
        }
        NativeIds::Cargo { crate_ } => crate_,
        #[cfg(feature = "mise")]
        NativeIds::Mise { tool } => tool,
        NativeIds::Homebrew { .. } | NativeIds::Flatpak { .. } | NativeIds::Distro { .. } => "",
        #[cfg(feature = "direct")]
        NativeIds::Direct { .. } => "",
    }
}

/// Resolve one app's standing on this host.
///
/// Precedence: `record` (the manifest's record for the app, when the
/// caller holds one) is probed with its own recorded identifiers — the
/// source of truth, never the caller's re-derived ones. Without a record,
/// `native` (the registry app's backend-native identifiers, when the
/// caller knows them) is probed for `Foreign` presence; without either,
/// the answer is `NotInstalled`.
///
/// # Errors
///
/// [`Error::Command`](crate::Error::Command) when a backend that *is* in
/// the set fails its probe. An absent backend is never an error — it is
/// skipped.
pub async fn app_status(
    record: Option<&InstallRecord>,
    native: Option<&NativeIds>,
    backends: &BackendSet<'_>,
) -> Result<AppStatus> {
    if let Some(record) = record {
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
            Ok(match backend.status(StatusQuery::new(package)).await? {
                BackendStatus::Installed { version } => AppStatus::Installed {
                    backend: BackendId::Distro(*family),
                    version,
                },
                BackendStatus::NotInstalled => AppStatus::NotInstalled,
            })
        }
        #[cfg(feature = "direct")]
        NativeIds::Direct { bin_path, .. } => {
            let Some(backend) = backends.direct else {
                return Ok(AppStatus::NotInstalled);
            };
            Ok(match backend.status(StatusQuery::new(bin_path)).await? {
                BackendStatus::Installed { version } => AppStatus::Installed {
                    backend: BackendId::Direct,
                    version,
                },
                BackendStatus::NotInstalled => AppStatus::NotInstalled,
            })
        }
        ids @ (NativeIds::Npm { .. }
        | NativeIds::Cargo { .. }
        | NativeIds::Pipx { .. }
        | NativeIds::Uv { .. }) => {
            let Some(backend) = language_backend(backends, ids) else {
                return Ok(AppStatus::NotInstalled);
            };
            recorded_via_status(backend, language_native_id(ids), ids.backend()).await
        }
        #[cfg(feature = "mise")]
        ids @ NativeIds::Mise { .. } => {
            let Some(backend) = language_backend(backends, ids) else {
                return Ok(AppStatus::NotInstalled);
            };
            recorded_via_status(backend, language_native_id(ids), ids.backend()).await
        }
    }
}

/// The recorded-status answer for every backend whose presence rides the
/// trait's own `status` probe (the language ecosystems).
async fn recorded_via_status(
    backend: &dyn Backend,
    native: &str,
    backend_id: BackendId,
) -> Result<AppStatus> {
    Ok(match backend.status(StatusQuery::new(native)).await? {
        BackendStatus::Installed { version } => AppStatus::Installed {
            backend: backend_id,
            version,
        },
        BackendStatus::NotInstalled => AppStatus::NotInstalled,
    })
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
        #[cfg(feature = "direct")]
        NativeIds::Direct { bin_path, .. } => {
            let Some(backend) = backends.direct else {
                return Ok(AppStatus::NotInstalled);
            };
            let status = backend.status(StatusQuery::new(bin_path)).await?;
            Ok(foreign_from(
                BackendId::Direct,
                &format!("direct binary `{bin_path}`"),
                status,
            ))
        }
        ids @ (NativeIds::Npm { .. }
        | NativeIds::Cargo { .. }
        | NativeIds::Pipx { .. }
        | NativeIds::Uv { .. }) => {
            let Some(backend) = language_backend(backends, ids) else {
                return Ok(AppStatus::NotInstalled);
            };
            let status = backend
                .status(StatusQuery::new(language_native_id(ids)))
                .await?;
            Ok(foreign_from(ids.backend(), &language_subject(ids), status))
        }
        #[cfg(feature = "mise")]
        ids @ NativeIds::Mise { .. } => {
            let Some(backend) = language_backend(backends, ids) else {
                return Ok(AppStatus::NotInstalled);
            };
            let status = backend
                .status(StatusQuery::new(language_native_id(ids)))
                .await?;
            Ok(foreign_from(ids.backend(), &language_subject(ids), status))
        }
    }
}

/// The subject wording for a language-ecosystem `Foreign` hit.
fn language_subject(ids: &NativeIds) -> String {
    match ids {
        NativeIds::Npm { package } => format!("npm package `{package}`"),
        NativeIds::Cargo { crate_ } => format!("cargo crate `{crate_}`"),
        NativeIds::Pipx { package } => format!("pipx package `{package}`"),
        NativeIds::Uv { package } => format!("uv tool `{package}`"),
        #[cfg(feature = "mise")]
        NativeIds::Mise { tool } => format!("mise tool `{tool}`"),
        NativeIds::Homebrew { .. } | NativeIds::Flatpak { .. } | NativeIds::Distro { .. } => {
            String::new()
        }
        #[cfg(feature = "direct")]
        NativeIds::Direct { .. } => String::new(),
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

/// The sync twin of [`app_status`]: same precedence, same probe choices,
/// same absent-backend-is-an-answer rule — the probes run on the calling
/// thread through the backends' sync twins.
///
/// # Errors
///
/// [`Error::Command`](crate::Error::Command) when a backend that *is* in
/// the set fails its probe. An absent backend is never an error.
pub fn app_status_sync(
    record: Option<&InstallRecord>,
    native: Option<&NativeIds>,
    backends: &BackendSet<'_>,
) -> Result<AppStatus> {
    if let Some(record) = record {
        return toride_recorded_status_sync(record, backends);
    }
    match native {
        Some(native) => foreign_status_sync(native, backends),
        None => Ok(AppStatus::NotInstalled),
    }
}

/// The sync twin of [`toride_recorded_status`].
fn toride_recorded_status_sync(
    record: &InstallRecord,
    backends: &BackendSet<'_>,
) -> Result<AppStatus> {
    match &record.ids {
        NativeIds::Homebrew { token, cask } => {
            let Some(backend) = backends.homebrew else {
                return Ok(AppStatus::NotInstalled);
            };
            let kind = if *cask {
                BrewKind::Cask
            } else {
                BrewKind::Formula
            };
            Ok(match backend.installed_version_sync(kind, token)? {
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
            let entries = backend.list_entries_sync(FlatpakListScope::from(*installation))?;
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
            let Some(backend) = backends.distro else {
                return Ok(AppStatus::NotInstalled);
            };
            if backend.family() != *family {
                return Ok(AppStatus::NotInstalled);
            }
            Ok(match backend.status_sync(StatusQuery::new(package))? {
                BackendStatus::Installed { version } => AppStatus::Installed {
                    backend: BackendId::Distro(*family),
                    version,
                },
                BackendStatus::NotInstalled => AppStatus::NotInstalled,
            })
        }
        #[cfg(feature = "direct")]
        NativeIds::Direct { bin_path, .. } => {
            let Some(backend) = backends.direct else {
                return Ok(AppStatus::NotInstalled);
            };
            Ok(match backend.status_sync(StatusQuery::new(bin_path))? {
                BackendStatus::Installed { version } => AppStatus::Installed {
                    backend: BackendId::Direct,
                    version,
                },
                BackendStatus::NotInstalled => AppStatus::NotInstalled,
            })
        }
        ids @ (NativeIds::Npm { .. }
        | NativeIds::Cargo { .. }
        | NativeIds::Pipx { .. }
        | NativeIds::Uv { .. }) => {
            let Some(backend) = language_backend(backends, ids) else {
                return Ok(AppStatus::NotInstalled);
            };
            recorded_via_status_sync(backend, language_native_id(ids), ids.backend())
        }
        #[cfg(feature = "mise")]
        ids @ NativeIds::Mise { .. } => {
            let Some(backend) = language_backend(backends, ids) else {
                return Ok(AppStatus::NotInstalled);
            };
            recorded_via_status_sync(backend, language_native_id(ids), ids.backend())
        }
    }
}

/// The sync twin of [`recorded_via_status`].
fn recorded_via_status_sync(
    backend: &dyn Backend,
    native: &str,
    backend_id: BackendId,
) -> Result<AppStatus> {
    Ok(match backend.status_sync(StatusQuery::new(native))? {
        BackendStatus::Installed { version } => AppStatus::Installed {
            backend: backend_id,
            version,
        },
        BackendStatus::NotInstalled => AppStatus::NotInstalled,
    })
}

/// The sync twin of [`foreign_status`].
fn foreign_status_sync(native: &NativeIds, backends: &BackendSet<'_>) -> Result<AppStatus> {
    match native {
        NativeIds::Homebrew { token, .. } => {
            let Some(backend) = backends.homebrew else {
                return Ok(AppStatus::NotInstalled);
            };
            let status = backend.status_sync(StatusQuery::new(token))?;
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
            let status = backend.status_sync(StatusQuery::new(app_id))?;
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
            let status = backend.status_sync(StatusQuery::new(package))?;
            Ok(foreign_from(
                BackendId::Distro(*family),
                &format!("package `{package}`"),
                status,
            ))
        }
        #[cfg(feature = "direct")]
        NativeIds::Direct { bin_path, .. } => {
            let Some(backend) = backends.direct else {
                return Ok(AppStatus::NotInstalled);
            };
            let status = backend.status_sync(StatusQuery::new(bin_path))?;
            Ok(foreign_from(
                BackendId::Direct,
                &format!("direct binary `{bin_path}`"),
                status,
            ))
        }
        ids @ (NativeIds::Npm { .. }
        | NativeIds::Cargo { .. }
        | NativeIds::Pipx { .. }
        | NativeIds::Uv { .. }) => {
            let Some(backend) = language_backend(backends, ids) else {
                return Ok(AppStatus::NotInstalled);
            };
            let status = backend.status_sync(StatusQuery::new(language_native_id(ids)))?;
            Ok(foreign_from(ids.backend(), &language_subject(ids), status))
        }
        #[cfg(feature = "mise")]
        ids @ NativeIds::Mise { .. } => {
            let Some(backend) = language_backend(backends, ids) else {
                return Ok(AppStatus::NotInstalled);
            };
            let status = backend.status_sync(StatusQuery::new(language_native_id(ids)))?;
            Ok(foreign_from(ids.backend(), &language_subject(ids), status))
        }
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
    use std::sync::Arc;
    use toride_registry::{DistroFamily, TorideId};
    use toride_runner::CommandOutput;
    use toride_runner::fake::FakeRunner;

    // --- test helpers ----------------------------------------------------------

    fn app_id(slug: &str) -> TorideId {
        TorideId::slugify(slug)
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

    fn pacman_query_spec(package: &str) -> toride_runner::CommandSpec {
        command("pacman", ["--query", package]).env("LC_ALL", "C")
    }

    fn apk_query_spec(package: &str) -> toride_runner::CommandSpec {
        command("apk", ["list", "--installed", "--quiet", package]).env("LC_ALL", "C")
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
        let record = cask_record("firefox", "firefox");
        let status = app_status(Some(&record), None, &backends).await.unwrap();
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
        let record = InstallRecord::new(
            cask_plan("ripgrep", "ripgrep"),
            NativeIds::Homebrew {
                token: "ripgrep".to_owned(),
                cask: false,
            },
            None,
        );
        let status = app_status(Some(&record), None, &backends).await.unwrap();
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
        let record = cask_record("firefox", "firefox");
        let status = app_status(Some(&record), None, &backends).await.unwrap();
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
        let record = flatpak_record(
            "brave-browser",
            "com.brave.Browser",
            FlatpakInstallation::User,
        );
        let status = app_status(Some(&record), None, &backends).await.unwrap();
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
        let record = flatpak_record(
            "adwcustomizer",
            "io.gitlab.adwcustomizer.AdwCustomizer",
            FlatpakInstallation::User,
        );
        let status = app_status(Some(&record), None, &backends).await.unwrap();
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
        let record = flatpak_record(
            "firefox",
            "org.mozilla.firefox",
            FlatpakInstallation::System,
        );
        let status = app_status(Some(&record), None, &backends).await.unwrap();
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
        let record = flatpak_record(
            "firefox",
            "org.mozilla.firefox",
            FlatpakInstallation::System,
        );
        let status = app_status(Some(&record), None, &backends).await.unwrap();
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
        let record = distro_record("firefox-esr", "firefox-esr", DistroFamily::Debian);
        let status = app_status(Some(&record), None, &backends).await.unwrap();
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
        let record = distro_record("firefox-esr", "firefox-esr", DistroFamily::Debian);
        let status = app_status(Some(&record), None, &backends).await.unwrap();
        assert_eq!(status, AppStatus::NotInstalled);
        fake.assert_no_unmatched_calls();
    }

    #[tokio::test]
    async fn manifest_hit_apk_record_without_a_version_still_reports_installed() {
        let fake = FakeRunner::new().strict().respond(
            apk_query_spec("brave-browser"),
            CommandOutput::from_stdout("brave-browser\n"),
        );
        let distro = distro_backend(DistroFamily::Alpine, &fake);
        let backends = BackendSet::new().distro(&distro);
        let record = distro_record("brave", "brave-browser", DistroFamily::Alpine);
        let status = app_status(Some(&record), None, &backends).await.unwrap();
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
        let fake = FakeRunner::new().strict().respond(
            pacman_query_spec("firefox"),
            CommandOutput::from_stderr("error: package 'firefox' was not found\n", 1),
        );
        let distro = distro_backend(DistroFamily::Arch, &fake);
        let backends = BackendSet::new().distro(&distro);
        let record = distro_record("firefox", "firefox", DistroFamily::Arch);
        let status = app_status(Some(&record), None, &backends).await.unwrap();
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
        let record = distro_record("firefox-esr", "firefox-esr", DistroFamily::Debian);
        let status = app_status(Some(&record), None, &backends).await.unwrap();
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
        let record = cask_record("brave", "recorded-token");
        let native = NativeIds::Homebrew {
            token: "caller-guess".to_owned(),
            cask: true,
        };
        let status = app_status(Some(&record), Some(&native), &backends)
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
        let record = cask_record("firefox", "firefox");
        let status = app_status(Some(&record), None, &BackendSet::new())
            .await
            .unwrap();
        assert_eq!(status, AppStatus::NotInstalled);
    }

    #[tokio::test]
    async fn manifest_miss_without_native_ids_reports_not_installed() {
        let status = app_status(None, None, &BackendSet::new()).await.unwrap();
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
        let status = app_status(None, Some(&native), &BackendSet::new())
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
        let status = app_status(None, Some(&native), &backends).await.unwrap();
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
        let status = app_status(None, Some(&native), &backends).await.unwrap();
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
        let status = app_status(None, Some(&native), &backends).await.unwrap();
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
        let status = app_status(None, Some(&native), &backends).await.unwrap();
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
        let status = app_status(None, Some(&native), &backends).await.unwrap();
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
        let record = cask_record("firefox", "firefox");
        let error = app_status(Some(&record), None, &backends)
            .await
            .unwrap_err();
        assert!(
            matches!(error, crate::error::Error::Command(_)),
            "{error:?}"
        );
        fake.assert_no_unmatched_calls();
    }

    #[test]
    fn sync_manifest_hit_brew_record_reports_the_probed_version() {
        let fake = FakeRunner::new().strict().respond(
            brew_versions_spec(BrewKind::Cask, "firefox"),
            CommandOutput::from_stdout("firefox 138.0\n"),
        );
        let brew = homebrew_backend(&fake);
        let backends = BackendSet::new().homebrew(&brew);
        let record = cask_record("firefox", "firefox");
        let status = app_status_sync(Some(&record), None, &backends).unwrap();
        assert_eq!(
            status,
            AppStatus::Installed {
                backend: BackendId::Homebrew,
                version: Some("138.0".to_owned()),
            }
        );
        fake.assert_no_unmatched_calls();
    }

    #[test]
    fn sync_manifest_hit_flatpak_record_without_a_version_still_reports_installed() {
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
        let record = flatpak_record(
            "adwcustomizer",
            "io.gitlab.adwcustomizer.AdwCustomizer",
            FlatpakInstallation::User,
        );
        let status = app_status_sync(Some(&record), None, &backends).unwrap();
        assert_eq!(
            status,
            AppStatus::Installed {
                backend: BackendId::Flatpak,
                version: None,
            }
        );
        fake.assert_no_unmatched_calls();
    }

    #[test]
    fn sync_manifest_miss_with_brew_listing_the_token_reports_foreign() {
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
        let status = app_status_sync(None, Some(&native), &backends).unwrap();
        assert!(
            matches!(
                status,
                AppStatus::Foreign {
                    backend: BackendId::Homebrew,
                    ..
                }
            ),
            "{status:?}"
        );
        fake.assert_no_unmatched_calls();
    }

    #[test]
    fn sync_absent_backends_answer_not_installed_without_dispatching() {
        let record = cask_record("firefox", "firefox");
        let status = app_status_sync(Some(&record), None, &BackendSet::new()).unwrap();
        assert_eq!(status, AppStatus::NotInstalled);
        let status = app_status_sync(None, None, &BackendSet::new()).unwrap();
        assert_eq!(status, AppStatus::NotInstalled);
    }

    fn npm_backend(fake: &FakeRunner) -> NpmBackend {
        NpmBackend::new(CommandRunner::new(Arc::new(fake.clone())))
    }

    fn npm_list_spec() -> toride_runner::CommandSpec {
        command("npm", ["list", "--global", "--depth=0", "--json"])
    }

    fn npm_record(slug: &str, package: &str) -> InstallRecord {
        InstallRecord::new(
            crate::plan::InstallPlan {
                app: app_id(slug),
                backend: BackendId::Npm,
                operation: Operation::NpmInstall {
                    package: package.to_owned(),
                    version: None,
                    global: true,
                },
                dry_run: false,
                requires_elevation: false,
            },
            NativeIds::Npm {
                package: package.to_owned(),
            },
            None,
        )
        .with_installed_at(1_700_000_000)
    }

    #[tokio::test]
    async fn manifest_hit_npm_record_reports_installed_from_the_listing() {
        let fake = FakeRunner::new().strict().respond(
            npm_list_spec(),
            CommandOutput::from_stdout(r#"{"dependencies": {"typescript": {"version": "5.4.5"}}}"#),
        );
        let npm = npm_backend(&fake);
        let backends = BackendSet::new().npm(&npm);
        let status = app_status(
            Some(&npm_record("typescript", "typescript")),
            None,
            &backends,
        )
        .await
        .unwrap();
        assert_eq!(
            status,
            AppStatus::Installed {
                backend: BackendId::Npm,
                version: Some("5.4.5".to_owned()),
            }
        );
        fake.assert_no_unmatched_calls();
    }

    #[tokio::test]
    async fn manifest_hit_npm_record_absent_from_the_listing_reports_not_installed() {
        let fake = FakeRunner::new()
            .strict()
            .respond(npm_list_spec(), CommandOutput::from_stdout("{}"));
        let npm = npm_backend(&fake);
        let backends = BackendSet::new().npm(&npm);
        let status = app_status(
            Some(&npm_record("typescript", "typescript")),
            None,
            &backends,
        )
        .await
        .unwrap();
        assert_eq!(status, AppStatus::NotInstalled);
        fake.assert_no_unmatched_calls();
    }

    #[tokio::test]
    async fn manifest_miss_with_npm_listing_the_package_reports_foreign() {
        let fake = FakeRunner::new().strict().respond(
            npm_list_spec(),
            CommandOutput::from_stdout(r#"{"dependencies": {"typescript": {"version": "5.4.5"}}}"#),
        );
        let npm = npm_backend(&fake);
        let backends = BackendSet::new().npm(&npm);
        let native = NativeIds::Npm {
            package: "typescript".to_owned(),
        };
        let status = app_status(None, Some(&native), &backends).await.unwrap();
        match status {
            AppStatus::Foreign { backend, detail } => {
                assert_eq!(backend, BackendId::Npm);
                assert!(detail.contains("npm package `typescript`"), "{detail}");
                assert!(detail.contains("5.4.5"), "{detail}");
                assert!(detail.contains("not by toride"), "{detail}");
            }
            other => panic!("expected Foreign, got {other:?}"),
        }
        fake.assert_no_unmatched_calls();
    }

    #[tokio::test]
    async fn an_absent_language_slot_skips_the_probe_entirely() {
        let fake = FakeRunner::new().strict();
        let backends = BackendSet::new();
        assert_eq!(
            app_status(
                Some(&npm_record("typescript", "typescript")),
                None,
                &backends
            )
            .await
            .unwrap(),
            AppStatus::NotInstalled
        );
        let native = NativeIds::Npm {
            package: "typescript".to_owned(),
        };
        assert_eq!(
            app_status(None, Some(&native), &backends).await.unwrap(),
            AppStatus::NotInstalled
        );
        fake.assert_no_unmatched_calls();
    }

    #[test]
    fn sync_npm_record_and_foreign_mirror_the_async_probes() {
        let fake = FakeRunner::new()
            .strict()
            .respond(
                npm_list_spec(),
                CommandOutput::from_stdout(
                    r#"{"dependencies": {"typescript": {"version": "5.4.5"}}}"#,
                ),
            )
            .respond(
                npm_list_spec(),
                CommandOutput::from_stdout(
                    r#"{"dependencies": {"typescript": {"version": "5.4.5"}}}"#,
                ),
            );
        let npm = npm_backend(&fake);
        let backends = BackendSet::new().npm(&npm);
        assert_eq!(
            app_status_sync(
                Some(&npm_record("typescript", "typescript")),
                None,
                &backends
            )
            .unwrap(),
            AppStatus::Installed {
                backend: BackendId::Npm,
                version: Some("5.4.5".to_owned()),
            }
        );
        let native = NativeIds::Npm {
            package: "typescript".to_owned(),
        };
        assert!(
            matches!(
                app_status_sync(None, Some(&native), &backends).unwrap(),
                AppStatus::Foreign {
                    backend: BackendId::Npm,
                    ..
                }
            ),
            "the sync Foreign probe mirrors the async one"
        );
        fake.assert_no_unmatched_calls();
    }

    #[tokio::test]
    async fn manifest_miss_with_cargo_listing_the_crate_reports_foreign() {
        let fake = FakeRunner::new().strict().respond(
            command("cargo", ["install", "--list"]),
            CommandOutput::from_stdout("ripgrep v14.1.0:\n    rg\n"),
        );
        let cargo = CargoBackend::new(CommandRunner::new(Arc::new(fake.clone())));
        let backends = BackendSet::new().cargo(&cargo);
        let native = NativeIds::Cargo {
            crate_: "ripgrep".to_owned(),
        };
        let status = app_status(None, Some(&native), &backends).await.unwrap();
        match status {
            AppStatus::Foreign { backend, detail } => {
                assert_eq!(backend, BackendId::Cargo);
                assert!(detail.contains("cargo crate `ripgrep`"), "{detail}");
                assert!(detail.contains("14.1.0"), "{detail}");
            }
            other => panic!("expected Foreign, got {other:?}"),
        }
        fake.assert_no_unmatched_calls();
    }

    #[cfg(feature = "direct")]
    mod direct {
        use super::*;

        fn temp_dir(label: &str) -> String {
            let dir = std::env::temp_dir().join(format!(
                "toride-apps-status-direct-{}-{label}",
                std::process::id()
            ));
            std::fs::create_dir_all(&dir).expect("unique temp dir is creatable");
            dir.to_string_lossy().into_owned()
        }

        fn direct_record(bin_path: String) -> InstallRecord {
            InstallRecord::adopted(
                NativeIds::Direct {
                    url: "https://example.com/rg".to_owned(),
                    checksum: None,
                    bin_path,
                },
                None,
            )
        }

        #[tokio::test]
        async fn manifest_hit_with_the_binary_present_reports_installed_without_a_version() {
            let dir = temp_dir("hit");
            let bin_path = format!("{dir}/rg");
            std::fs::write(&bin_path, b"x").unwrap();
            let backend = DirectBackend::at(&dir);
            let backends = BackendSet::new().direct(&backend);
            let status = app_status(Some(&direct_record(bin_path.clone())), None, &backends)
                .await
                .unwrap();
            assert_eq!(
                status,
                AppStatus::Installed {
                    backend: BackendId::Direct,
                    version: None,
                }
            );
        }

        #[tokio::test]
        async fn manifest_hit_with_the_binary_gone_reports_not_installed() {
            let dir = temp_dir("gone");
            let backend = DirectBackend::at(&dir);
            let backends = BackendSet::new().direct(&backend);
            let status = app_status(Some(&direct_record(format!("{dir}/rg"))), None, &backends)
                .await
                .unwrap();
            assert_eq!(status, AppStatus::NotInstalled);
        }

        #[tokio::test]
        async fn manifest_miss_with_a_present_binary_reports_foreign() {
            let dir = temp_dir("foreign");
            let bin_path = format!("{dir}/rg");
            std::fs::write(&bin_path, b"someone-elses").unwrap();
            let backend = DirectBackend::at(&dir);
            let backends = BackendSet::new().direct(&backend);
            let native = NativeIds::Direct {
                url: "https://example.com/rg".to_owned(),
                checksum: None,
                bin_path: bin_path.clone(),
            };
            let status = app_status(None, Some(&native), &backends).await.unwrap();
            match status {
                AppStatus::Foreign { backend, detail } => {
                    assert_eq!(backend, BackendId::Direct);
                    assert!(detail.contains(&bin_path), "{detail}");
                    assert!(detail.contains("not by toride"), "{detail}");
                }
                other => panic!("expected Foreign, got {other:?}"),
            }
        }

        #[tokio::test]
        async fn an_absent_direct_slot_skips_the_probe_entirely() {
            let dir = temp_dir("no-slot");
            let bin_path = format!("{dir}/rg");
            std::fs::write(&bin_path, b"x").unwrap();
            let status = app_status(
                Some(&direct_record(bin_path.clone())),
                None,
                &BackendSet::new(),
            )
            .await
            .unwrap();
            assert_eq!(status, AppStatus::NotInstalled);
        }

        #[test]
        fn sync_manifest_hit_and_foreign_mirror_the_async_probes() {
            let dir = temp_dir("sync");
            let bin_path = format!("{dir}/rg");
            std::fs::write(&bin_path, b"x").unwrap();
            let backend = DirectBackend::at(&dir);
            let backends = BackendSet::new().direct(&backend);
            assert_eq!(
                app_status_sync(Some(&direct_record(bin_path.clone())), None, &backends).unwrap(),
                AppStatus::Installed {
                    backend: BackendId::Direct,
                    version: None,
                }
            );
            let native = NativeIds::Direct {
                url: "https://example.com/rg".to_owned(),
                checksum: None,
                bin_path,
            };
            assert!(matches!(
                app_status_sync(None, Some(&native), &backends).unwrap(),
                AppStatus::Foreign {
                    backend: BackendId::Direct,
                    ..
                }
            ));
        }
    }
}
