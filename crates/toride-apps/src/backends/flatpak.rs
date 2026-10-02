//! # Flatpak backend (`flatpak`)
//!
//! [`FlatpakBackend`] is the [`Backend`] implementation for Flatpak on
//! Linux: it executes the planner's [`Operation::FlatpakInstall`] /
//! [`Operation::FlatpakUninstall`] operations through the shared
//! [`CommandRunner`] seam — ensuring the flathub remote exists first — and
//! answers list/status queries from `flatpak list` column output.
//!
//! ## Real-CLI semantics (verified against flatpak(1) man pages and source)
//!
//! - **Version** — `flatpak --version` prints `PACKAGE_STRING`
//!   (`Flatpak 1.16.0`, capital F — meson.build's quoted `PACKAGE_STRING`).
//! - **Remote ensure** — `flatpak remotes --user --columns=name` probes the
//!   remotes of one installation (unscoped `remotes` shows *both*
//!   configurations); a missing flathub is added with `flatpak remote-add
//!   --user --if-not-exists flathub <url>` — the `NAME LOCATION` operand
//!   order of remote-add(1), with the URL flathub's own setup page tells
//!   users (the signed `.flatpakrepo` descriptor, see
//!   [`FLATHUB_REPO_URL`]). `--if-not-exists` makes the add idempotent even
//!   under a race.
//! - **Install** — `flatpak install --user --or-update --noninteractive
//!   flathub app/<id>/<arch>/stable`. The plan's ref is a full
//!   `(app|runtime)/ID/ARCH/BRANCH` identifier *containing slashes*, which
//!   flatpak-install(1) treats as an exact ref (fuzzy matching is disabled
//!   the moment a REF carries slashes or periods) — so toride installs the
//!   arch it planned, never a fuzzy near-match. `--or-update` is always
//!   added: bare install would *ignore* an already-installed ref with a
//!   warning and exit 0, while `--or-update` turns it into an update —
//!   exactly the ensure-installed semantics the facade (A6) wants.
//! - **Uninstall** — `flatpak uninstall --user --noninteractive <app-id>`.
//!   The plan carries the *bare app id* (a partial ref), which flatpak
//!   resolves against the **installed** refs — toride never re-derives the
//!   ref from the planning target's arch (the manifest is the source of
//!   truth for what was actually installed).
//! - **Update** — `flatpak update --user --noninteractive <app-id>`: the
//!   same bare-id resolution against installed refs, with
//!   `--noninteractive` layered on at execution like install/uninstall.
//! - **Listing** — `flatpak list --app
//!   --columns=application,version,origin,installation`. With captured
//!   (non-TTY) output, flatpak's table printer emits **tab-separated,
//!   untruncated** rows and **no header line** (the header prints only in
//!   fancy/TTY mode — app/flatpak-table-printer.c). Unscoped `list` covers
//!   **both** the per-user and the system-wide installations
//!   (flatpak-list(1): "By default, both per-user and system-wide
//!   installations are shown"), with the `installation` column
//!   disambiguating; flatpak's own `--all` flag is deliberately **not**
//!   used — it unhides locale/debug extension refs, it does not select
//!   installations. See [`FlatpakListScope`].
//!
//! ## Split
//!
//! - **Detection surface** — [`FlatpakBackend::detect`] (PATH check via
//!   `toride-runner`'s discovery helpers, no command executed),
//!   [`FlatpakBackend::version`] (`flatpak --version`),
//!   [`FlatpakBackend::ensure_remote`] (probe + conditional add).
//! - **Trait operations** — install/uninstall/update/list/status per the
//!   [`Backend`] contract (guard-first, seam-only execution), plus the
//!   installation-scoped [`FlatpakBackend::installed_version`] probe, the
//!   richer [`FlatpakBackend::list_entries`], and the branch listing
//!   [`FlatpakBackend::available_versions`] (flatpak's installable
//!   "versions" are the remote's branches — the ref segment a
//!   version-pinned install selects).
//! - **Column parsing** — the tab-separated listings (`list`, `remote-ls`)
//!   parsed into typed rows. Per-row tolerance: a malformed row (wrong cell
//!   count, empty application cell) is skipped, never fatal to the whole
//!   listing; a non-empty document where *nothing* parses is treated as
//!   unparseable output, not as an empty host.
//!
//! ## Conventions honored
//!
//! - [`ensure_install_allowed`] / [`ensure_uninstall_allowed`] /
//!   [`ensure_update_allowed`] are the first statement of the trait's
//!   mutating operations (dry-run refusal + no auto-sudo) — before even
//!   the remote-ensure probe runs.
//! - Interactivity: flatpak's install/uninstall/update prompt on
//!   questions, so unlike homebrew the executed argv layers runtime flags
//!   onto the plan's canonical argv — `--noninteractive` ("produce minimal
//!   output and avoid most questions", flatpak-install(1)) on every
//!   mutating command, plus `--or-update` on install (see above). These
//!   are execution-time ergonomics and stay **out** of the plan's argv;
//!   every command is unambiguous anyway (a full ref + a named remote
//!   leave nothing to search or choose). The `-y`/`--assumeyes` flag is
//!   not used: it answers questions with "yes" rather than avoiding them.
//! - Error mapping: non-zero exits surface as
//!   [`Error::Command`] carrying flatpak's stderr.
//!   One classification: a failed uninstall whose stderr carries flatpak's
//!   own typed not-installed error (exit 1, an `error:` line matching the
//!   markers — flatpak's `FLATPAK_ERROR_NOT_INSTALLED`, wording "No
//!   installed refs found for …") becomes a success noting the app was
//!   already absent, keeping manifest-driven uninstalls idempotent. See
//!   `NOT_INSTALLED_MARKERS`.
//!
//! [`Operation::FlatpakInstall`]: crate::Operation::FlatpakInstall
//! [`Operation::FlatpakUninstall`]: crate::Operation::FlatpakUninstall
//! [`ensure_install_allowed`]: crate::backend::ensure_install_allowed
//! [`ensure_uninstall_allowed`]: crate::backend::ensure_uninstall_allowed
//! [`ensure_update_allowed`]: crate::backend::ensure_update_allowed

use async_trait::async_trait;
use toride_registry::Os;

use crate::backend::{
    Backend, BackendId, InstallOutcome, InstallRequest, InstalledApp, ListQuery, UninstallOutcome,
    UninstallRequest, UpdateRequest, Version, ensure_install_allowed, ensure_uninstall_allowed,
    ensure_update_allowed,
};
use crate::error::{Error, Result};
use crate::plan::{FlatpakInstallation, Operation, Target};
use crate::runner::{CommandRunner, command};

/// The Flatpak CLI binary every command in this module targets.
const FLATPAK: &str = "flatpak";

/// The remote name toride's registry data uses for Flathub.
pub const FLATHUB_REMOTE_NAME: &str = "flathub";

/// The Flathub repository descriptor `remote-add` consumes — the signed
/// `.flatpakrepo` file (URL + GPG key), not the bare repo URL: flathub's own
/// setup page remote-adds exactly this URL, and the descriptor's `Url=` key
/// (verified against the copied fixture `tests/fixtures/flatpak/
/// flathub.flatpakrepo`) is the repo underneath it.
pub const FLATHUB_REPO_URL: &str = "https://dl.flathub.org/repo/flathub.flatpakrepo";

/// The listing's `--columns` argument: four columns, one tab-separated cell
/// each in non-TTY output (see the module docs for the printer details).
const LIST_COLUMNS_ARG: &str = "--columns=application,version,origin,installation";

/// How many tab-separated cells a well-formed listing row carries (the
/// number of requested columns).
const LIST_COLUMN_COUNT: usize = 4;

/// The `flatpak remote-ls` `--columns` argument: the app id and its branch —
/// the branch is flatpak's installable "version" (the ref segment a
/// version-pinned install selects).
const REMOTE_LS_COLUMNS_ARG: &str = "--columns=application,branch";

/// Markers whose presence on a flatpak **`error:` line** classifies a failed
/// uninstall as "the app is simply not installed" rather than a real error.
/// The current wording (app/flatpak-builtins-uninstall.c) is
/// `No installed refs found for '<id>'` — typed
/// `FLATPAK_ERROR_NOT_INSTALLED`, exit code 1, printed as `error: …`; the
/// quotes in the real message are Unicode curly quotes, so the markers
/// deliberately stop short of them. The second marker covers older
/// flatpaks and adjacent paths sharing the "… is not installed" wording.
/// Matched case-insensitively against `error:`-prefixed lines only, and
/// gated on exit code 1 — anything unrecognized stays a real error.
const NOT_INSTALLED_MARKERS: [&str; 2] = [
    // `error: No installed refs found for ‘<id>’` (single-REF uninstall,
    // nothing installed matches)
    "no installed refs found",
    // `error: <ref> is not installed` (older flatpak / other paths)
    "is not installed",
];

// ---------------------------------------------------------------------------
// Backend
// ---------------------------------------------------------------------------

/// Flatpak [`Backend`]: ensures the flathub remote, executes flatpak
/// install/uninstall plans, and answers list/status queries from `flatpak
/// list` column output.
///
/// # Example
///
/// ```rust,ignore
/// use toride_apps::CommandRunner;
/// use toride_apps::backends::flatpak::{FlatpakBackend, FlatpakListScope};
///
/// # async fn demo() -> toride_apps::Result<()> {
/// let runner = CommandRunner::builder().build();
/// let backend = FlatpakBackend::detect(runner)?; // flatpak must be on PATH
/// let entries = backend.list_entries(FlatpakListScope::All).await?;
/// # let _ = entries;
/// # Ok(())
/// # }
/// ```
pub struct FlatpakBackend {
    /// The seam every flatpak command flows through.
    runner: CommandRunner,
}

impl FlatpakBackend {
    /// Create the backend over an explicit seam, with no host assumptions.
    ///
    /// This is the test-friendly constructor: the seam's runner is
    /// injectable, so every command the backend issues is fake-able.
    #[must_use]
    pub fn new(runner: CommandRunner) -> Self {
        Self { runner }
    }

    /// Create the backend after verifying `flatpak` is on the host `$PATH`
    /// (via `toride-runner`'s discovery helpers — no command is executed).
    ///
    /// Use this in production entry points; use [`FlatpakBackend::new`]
    /// under a fake runner, where the real PATH is irrelevant.
    ///
    /// # Errors
    ///
    /// [`Error::Command`] wrapping `BinaryNotFound` when `flatpak` is not
    /// on the PATH.
    pub fn detect(runner: CommandRunner) -> Result<Self> {
        let _path = toride_runner::discovery::find_binary(FLATPAK)?;
        Ok(Self::new(runner))
    }

    /// The installed flatpak's version, from `flatpak --version`.
    ///
    /// Parses the output's first line (`Flatpak 1.16.0` → `1.16.0`); any
    /// extra version suffix is kept verbatim.
    ///
    /// # Errors
    ///
    /// [`Error::Command`] when the probe fails or its output does not
    /// carry the `Flatpak ` version prefix.
    pub async fn version(&self) -> Result<String> {
        let output = self
            .runner
            .run_checked(command(FLATPAK, ["--version"]))
            .await?;
        parse_version_output(&output.stdout)
    }

    /// Ensure a remote named `name` exists in `installation`, adding it from
    /// `url` (a repo URL or `.flatpakrepo` descriptor) when missing.
    ///
    /// Returns `true` when the remote was added now, `false` when it was
    /// already configured. The probe is scoped to `installation`
    /// (`flatpak remotes --user|--system --columns=name` — unscoped it
    /// would mix both configurations' remotes); the add carries
    /// `--if-not-exists`, so a remote added by a concurrent process still
    /// succeeds.
    ///
    /// # Errors
    ///
    /// [`Error::Command`] when either command fails.
    pub async fn ensure_remote(
        &self,
        installation: FlatpakInstallation,
        name: &str,
        url: &str,
    ) -> Result<bool> {
        let probe = command(FLATPAK, ["remotes", installation.flag(), "--columns=name"]);
        let output = self.runner.run_checked(probe).await?;
        let remotes = parse_remote_names(&output.stdout);
        if remotes.iter().any(|remote| remote == name) {
            return Ok(false);
        }
        let add = command(
            FLATPAK,
            [
                "remote-add",
                installation.flag(),
                "--if-not-exists",
                name,
                url,
            ],
        );
        self.runner.run_checked(add).await?;
        Ok(true)
    }

    /// The full typed listing for one scope: installed applications with
    /// app id, version, origin remote, and installation (`user`/`system`).
    ///
    /// Richer than the trait's [`Backend::list_installed`] (which maps
    /// these entries to plain [`InstalledApp`]s) so callers that need the
    /// per-installation detail can take it directly. An app installed in
    /// both installations yields two rows.
    ///
    /// # Errors
    ///
    /// [`Error::Command`] when the listing command fails or its output is
    /// non-empty yet contains no parseable row (malformed *rows* are
    /// skipped, not fatal).
    pub async fn list_entries(&self, scope: FlatpakListScope) -> Result<Vec<FlatpakEntry>> {
        let spec = command(FLATPAK, list_args(scope));
        let output = self.runner.run_checked(spec).await?;
        parse_list_output(&output.stdout)
    }

    /// The installed version of one app id in one installation, from the
    /// scoped listing.
    ///
    /// `Ok(None)` covers both "not installed there" and "installed without
    /// a reported version" — installation-scoped, so a user-install answer
    /// is never mistaken for a system one (or vice versa).
    ///
    /// # Errors
    ///
    /// [`Error::Command`] when the scoped listing fails.
    pub async fn installed_version(
        &self,
        app_id: &str,
        installation: FlatpakInstallation,
    ) -> Result<Option<String>> {
        let entries = self
            .list_entries(FlatpakListScope::from(installation))
            .await?;
        Ok(entries
            .into_iter()
            .find(|entry| entry.application == app_id)
            .and_then(|entry| entry.version))
    }

    /// The branches flathub offers for `app_id` — the installable
    /// "versions" a version-pinned flatpak install selects between
    /// (`flatpak remote-ls <installation-flag> --app --columns=… flathub`,
    /// the same tab-separated headerless printer the installed listing
    /// rides). Scoped to `installation` because remotes are configured per
    /// installation; an app absent from the remote yields an empty vec.
    ///
    /// The remote is flathub deliberately: it is the only remote toride
    /// knows by name (see [`FLATHUB_REMOTE_NAME`]), and
    /// [`NativeIds::Flatpak`](crate::NativeIds::Flatpak) records no
    /// origin, so a record-driven ask cannot name another one — an app
    /// whose registry method names a different remote lists empty here,
    /// not its own remote's branches. Unlike the install path this query
    /// never configures the remote: a host without flathub in the probed
    /// `installation` fails with flatpak's own remote-not-found error
    /// instead of self-healing the way
    /// [`FlatpakBackend::ensure_remote`] does — queries stay read-only.
    ///
    /// # Errors
    ///
    /// [`Error::Command`] when the listing fails or its output is
    /// non-empty yet contains no parseable row.
    pub async fn available_versions(
        &self,
        app_id: &str,
        installation: FlatpakInstallation,
    ) -> Result<Vec<Version>> {
        let spec = command(
            FLATPAK,
            [
                "remote-ls",
                installation.flag(),
                "--app",
                REMOTE_LS_COLUMNS_ARG,
                FLATHUB_REMOTE_NAME,
            ],
        );
        let output = self.runner.run_checked(spec).await?;
        parse_remote_branches(&output.stdout, app_id)
    }

    /// Ensure the flathub remote exists in `installation` (see
    /// [`FLATHUB_REMOTE_NAME`] / [`FLATHUB_REPO_URL`]).
    ///
    /// # Errors
    ///
    /// [`Error::Command`] when either command fails.
    async fn ensure_flathub_remote(&self, installation: FlatpakInstallation) -> Result<()> {
        self.ensure_remote(installation, FLATHUB_REMOTE_NAME, FLATHUB_REPO_URL)
            .await
            .map(|_| ())
    }
}

#[async_trait]
impl Backend for FlatpakBackend {
    fn id(&self) -> BackendId {
        BackendId::Flatpak
    }

    fn supports(&self, target: &Target) -> bool {
        // Flatpak runs on Linux; the planner refuses flatpak methods for
        // other OSes before this backend is ever selected.
        target.os == Os::Linux
    }

    async fn install(&self, request: InstallRequest<'_>) -> Result<InstallOutcome> {
        ensure_install_allowed(&request)?;
        let Operation::FlatpakInstall {
            remote,
            app_ref,
            installation,
        } = &request.plan.operation
        else {
            return Err(misrouted_operation(&request.plan.operation));
        };
        // Remote ensure: toride knows the repo descriptor URL only for
        // flathub (the registry's remote name for Flathub data). A plan
        // naming any other remote is executed as-is — flatpak itself will
        // fail with "Remote ... not found" if it is genuinely unconfigured,
        // which is the honest error.
        if remote == FLATHUB_REMOTE_NAME {
            self.ensure_flathub_remote(*installation).await?;
        }
        let spec = command(
            FLATPAK,
            [
                "install",
                installation.flag(),
                "--or-update",
                "--noninteractive",
                remote.as_str(),
                app_ref.as_str(),
            ],
        );
        self.runner.run_checked(spec).await?;
        // Post-verify: ask the scoped listing what version landed, for the
        // manifest record. The install already succeeded, so a failing
        // probe degrades to "no version reported" instead of failing the
        // outcome.
        let version = match app_id_from_ref(app_ref) {
            Some(app_id) => self
                .installed_version(app_id, *installation)
                .await
                .ok()
                .flatten(),
            None => None,
        };
        Ok(InstallOutcome {
            version,
            detail: request.plan.operation.description(),
        })
    }

    async fn uninstall(&self, request: UninstallRequest<'_>) -> Result<UninstallOutcome> {
        ensure_uninstall_allowed(&request)?;
        let Operation::FlatpakUninstall {
            app_id,
            installation,
        } = &request.plan.operation
        else {
            return Err(misrouted_operation(&request.plan.operation));
        };
        let spec = command(
            FLATPAK,
            [
                "uninstall",
                installation.flag(),
                "--noninteractive",
                app_id.as_str(),
            ],
        );
        match self.runner.run_checked(spec).await {
            Ok(_) => Ok(UninstallOutcome {
                detail: request.plan.operation.description(),
            }),
            // "Not installed" is flatpak's own typed answer for removing an
            // absent app (exit 1 + an `error:` line matching the markers);
            // the desired end state already holds, so the outcome is a
            // success noting the absence. The exit-code gate keeps signal
            // kills and other failures as real errors.
            Err(Error::Command(toride_runner::Error::CommandFailed {
                stderr, exit_code, ..
            })) if exit_code == Some(1) && stderr_says_not_installed(&stderr) => {
                Ok(UninstallOutcome {
                    detail: format!("{} (already absent)", request.plan.operation.description()),
                })
            }
            Err(error) => Err(error),
        }
    }

    async fn update(&self, request: UpdateRequest<'_>) -> Result<()> {
        ensure_update_allowed(&request)?;
        let Operation::FlatpakUpdate {
            app_id,
            installation,
        } = &request.plan.operation
        else {
            return Err(misrouted_operation(&request.plan.operation));
        };
        let spec = command(
            FLATPAK,
            [
                "update",
                installation.flag(),
                "--noninteractive",
                app_id.as_str(),
            ],
        );
        self.runner.run_checked(spec).await?;
        Ok(())
    }

    async fn list_installed(&self, query: ListQuery) -> Result<Vec<InstalledApp>> {
        let entries = self.list_entries(FlatpakListScope::All).await?;
        Ok(entries
            .into_iter()
            .filter(|entry| query.ids.is_empty() || query.ids.contains(&entry.application))
            .map(|entry| InstalledApp {
                id: entry.application,
                version: entry.version,
            })
            .collect())
    }

    async fn available_versions(&self, id: &str) -> Result<Vec<Version>> {
        self.available_versions(id, FlatpakInstallation::User).await
    }

    // `status` keeps the trait's default list-derived implementation: one
    // unscoped listing covers both installations (an app may live in
    // either), and a not-found id is `NotInstalled`, never an error — the
    // listing command itself failing is the only error path. Callers that
    // know the installation (plan operations, manifest records) should
    // call `installed_version(app_id, installation)` directly.
}

// ---------------------------------------------------------------------------
// Typed query results
// ---------------------------------------------------------------------------

/// Which installations a listing covers. `All` is flatpak's *unscoped*
/// default — "both per-user and system-wide installations are shown"
/// (flatpak-list(1)) — realized by passing **no** installation flag. It is
/// deliberately not flatpak's `--all` flag: that unhides locale/debug
/// extension refs, it does not select installations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FlatpakListScope {
    /// Every installation (user + system): no installation flag.
    #[default]
    All,
    /// The per-user installation only (`--user`).
    User,
    /// The default system-wide installation only (`--system`).
    System,
}

impl FlatpakListScope {
    /// The `flatpak list` flag selecting this scope (`None` for all — the
    /// unscoped command already covers every installation).
    #[must_use]
    pub const fn flag(self) -> Option<&'static str> {
        match self {
            Self::All => None,
            Self::User => Some("--user"),
            Self::System => Some("--system"),
        }
    }
}

impl From<FlatpakInstallation> for FlatpakListScope {
    fn from(installation: FlatpakInstallation) -> Self {
        match installation {
            FlatpakInstallation::User => Self::User,
            FlatpakInstallation::System => Self::System,
        }
    }
}

/// One row of `flatpak list --app --columns=…`: the typed, backend-native
/// view behind the trait's plain [`InstalledApp`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlatpakEntry {
    /// Dotted reverse-DNS app id (`com.brave.Browser`) — the backend-native
    /// id and the join key against plan operations and manifest records.
    pub application: String,
    /// Installed version when the listing reports one (apps without appdata
    /// version metadata report an empty cell).
    pub version: Option<String>,
    /// Origin remote name (`flathub`).
    pub origin: String,
    /// Installation the app lives in (`user` / `system` / a named
    /// installation's name).
    pub installation: String,
}

// ---------------------------------------------------------------------------
// Output parsing
// ---------------------------------------------------------------------------

/// Build the `flatpak list` argv for a scope: verb, installation flag,
/// `--app`, columns — options before the (empty) operand list.
fn list_args(scope: FlatpakListScope) -> Vec<&'static str> {
    let mut args = vec!["list"];
    if let Some(flag) = scope.flag() {
        args.push(flag);
    }
    args.push("--app");
    args.push(LIST_COLUMNS_ARG);
    args
}

/// Parse `flatpak --version` output: first non-empty line, `Flatpak `
/// prefix stripped, remainder trimmed (`1.16.0`).
///
/// # Errors
///
/// [`Error::Command`] wrapping `OutputParse` when the prefix is missing or
/// no version follows it.
fn parse_version_output(stdout: &str) -> Result<String> {
    let first = stdout.lines().find(|line| !line.trim().is_empty());
    let version = first
        .and_then(|line| line.trim().strip_prefix("Flatpak "))
        .map(str::trim)
        .filter(|version| !version.is_empty());
    version.map_or_else(
        || {
            Err(output_parse_error(
                "flatpak --version",
                format!("no `Flatpak <version>` line in {stdout:?}"),
            ))
        },
        |version| Ok(version.to_owned()),
    )
}

/// Parse `flatpak remotes --columns=name` output: one remote name per
/// non-empty line.
fn parse_remote_names(stdout: &str) -> Vec<String> {
    stdout
        .lines()
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
        .collect()
}

/// Parse the tab-separated `flatpak list --app --columns=…` listing into
/// typed entries, skipping malformed rows (anything that is not exactly the
/// requested number of tab-separated cells with a non-empty application).
///
/// A non-empty document where no row parses is an error, not an empty
/// host: every row being malformed means the output shape is not what was
/// requested (a future flatpak changing columns), which must surface
/// loudly rather than read as "nothing installed".
///
/// # Errors
///
/// [`Error::Command`] wrapping `OutputParse` for the no-parseable-rows
/// case above.
fn parse_list_output(stdout: &str) -> Result<Vec<FlatpakEntry>> {
    let mut entries = Vec::new();
    for line in stdout.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let cells: Vec<&str> = line.split('\t').collect();
        if cells.len() != LIST_COLUMN_COUNT {
            continue;
        }
        let application = cells[0].trim();
        if application.is_empty() {
            continue;
        }
        entries.push(FlatpakEntry {
            application: application.to_owned(),
            version: non_empty(cells[1].trim()),
            origin: cells[2].trim().to_owned(),
            installation: cells[3].trim().to_owned(),
        });
    }
    if !stdout.trim().is_empty() && entries.is_empty() {
        return Err(output_parse_error(
            "flatpak list --columns=application,version,origin,installation",
            format!("no parseable tab-separated rows in {stdout:?}"),
        ));
    }
    Ok(entries)
}

/// Parse the tab-separated `flatpak remote-ls --app --columns=…` listing
/// into the branches offered for `app_id`, skipping malformed rows and
/// rows naming other apps, deduplicated in first-seen order (the listing
/// emits one row per ref, so a multi-arch app repeats each branch). Same
/// tolerance shape as [`parse_list_output`]: a non-empty document where no
/// row parses is an error, not an empty offering.
///
/// # Errors
///
/// [`Error::Command`] wrapping `OutputParse` for the no-parseable-rows
/// case above.
fn parse_remote_branches(stdout: &str, app_id: &str) -> Result<Vec<Version>> {
    let mut branches = Vec::new();
    let mut well_formed = 0;
    for line in stdout.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let Some((application, branch)) = line.split_once('\t') else {
            continue;
        };
        if application.trim().is_empty() {
            continue;
        }
        well_formed += 1;
        let branch = branch.trim();
        if application.trim() == app_id && !branch.is_empty() {
            let version = Version::new(branch);
            if !branches.contains(&version) {
                branches.push(version);
            }
        }
    }
    if !stdout.trim().is_empty() && well_formed == 0 {
        return Err(output_parse_error(
            "flatpak remote-ls --columns=application,branch",
            format!("no parseable tab-separated rows in {stdout:?}"),
        ));
    }
    Ok(branches)
}

/// The app id segment of an install ref (`app/<id>/<arch>/<branch>` → the
/// id). `None` for refs without the `app/` prefix (runtime refs, bare ids,
/// garbage) — callers degrade rather than mis-verify.
fn app_id_from_ref(app_ref: &str) -> Option<&str> {
    let mut parts = app_ref.split('/');
    if parts.next()? != "app" {
        return None;
    }
    parts.next().filter(|id| !id.is_empty())
}

/// Whether flatpak stderr says the uninstalled ref was not installed (see
/// [`NOT_INSTALLED_MARKERS`]): markers are matched only on `error:`-prefixed
/// lines (flatpak's error prefix; progress/warning lines may mention other
/// packages' install states), so multi-line stderr does not misclassify.
/// Callers must additionally gate on the exit code (1) — this helper alone
/// would misread a signal-killed run that had already printed the line.
fn stderr_says_not_installed(stderr: &str) -> bool {
    stderr
        .lines()
        .map(str::trim_start)
        .filter(|line| line.to_ascii_lowercase().starts_with("error:"))
        .any(|error_line| {
            let lower = error_line.to_ascii_lowercase();
            NOT_INSTALLED_MARKERS
                .iter()
                .any(|marker| lower.contains(marker))
        })
}

/// `""` → `None`, anything else → `Some(owned)`.
fn non_empty(cell: &str) -> Option<String> {
    Some(cell.to_owned()).filter(|value| !value.is_empty())
}

/// The error for a plan operation this backend cannot execute (a non-flatpak
/// operation routed to the flatpak backend).
fn misrouted_operation(operation: &Operation) -> Error {
    Error::Command(toride_runner::Error::Other(format!(
        "flatpak backend cannot execute non-flatpak operation: {operation:?}"
    )))
}

/// Build the unparseable-output error, naming the flatpak command and the
/// cause.
fn output_parse_error(flatpak_command: &str, cause: impl std::fmt::Display) -> Error {
    Error::Command(toride_runner::Error::OutputParse(format!(
        "{flatpak_command}: {cause}"
    )))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::{BackendStatus, StatusQuery};
    use crate::plan::{
        InstallOptions, InstallPlan, UninstallOptions, UninstallPlan, plan_install, plan_uninstall,
    };
    use std::path::Path;
    use std::sync::Arc;
    use toride_registry::{App, Arch, Availability, DistroFamily, InstallMethod, TorideId};
    use toride_runner::fake::FakeRunner;

    // --- test helpers ----------------------------------------------------------

    /// Root of this crate's fixture tree (runtime reads, not `include_str!`
    /// — the house pattern from conventions.md §7).
    fn fixtures_dir() -> &'static Path {
        Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures"))
    }

    /// Read a fixture file as a UTF-8 string, relative to the fixtures dir.
    fn read_fixture(relative: &str) -> String {
        let path = fixtures_dir().join(relative);
        std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("failed to read fixture {relative}: {error}"))
    }

    /// A registry `App` fixture with the given install method.
    fn app_with(method: InstallMethod) -> App {
        App {
            id: TorideId::slugify("brave-browser"),
            name: "Brave Browser".to_owned(),
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
            install: method,
            sources: Vec::new(),
            availability: Availability::Available,
        }
    }

    fn flatpak_method() -> InstallMethod {
        InstallMethod::Flatpak {
            app_id: "com.brave.Browser".to_owned(),
            remote: "flathub".to_owned(),
        }
    }

    fn linux_target() -> Target {
        Target::linux(Arch::X86_64, DistroFamily::Debian)
    }

    /// A backend over a strict fake runner (unmatched dispatches fail).
    fn backend(fake: &FakeRunner) -> FlatpakBackend {
        FlatpakBackend::new(CommandRunner::new(Arc::new(fake.clone())))
    }

    fn install_plan_for() -> InstallPlan {
        plan_install(
            &app_with(flatpak_method()),
            &linux_target(),
            &InstallOptions::default(),
        )
        .unwrap()
    }

    fn uninstall_plan_for() -> UninstallPlan {
        plan_uninstall(
            &app_with(flatpak_method()),
            &linux_target(),
            &UninstallOptions::default(),
        )
        .unwrap()
    }

    /// A flatpak-backend install plan carrying a hand-picked operation
    /// (system installations, custom remotes, non-flatpak operations for
    /// misrouting tests).
    fn manual_install_plan(operation: Operation) -> InstallPlan {
        InstallPlan {
            app: TorideId::slugify("brave-browser"),
            backend: BackendId::Flatpak,
            operation,
            dry_run: false,
            requires_elevation: false,
        }
    }

    /// A flatpak-backend uninstall plan carrying a hand-picked operation.
    fn manual_uninstall_plan(operation: Operation) -> UninstallPlan {
        UninstallPlan {
            app: TorideId::slugify("brave-browser"),
            backend: BackendId::Flatpak,
            operation,
            dry_run: false,
            requires_elevation: false,
        }
    }

    /// A flatpak-backend update plan carrying a hand-picked operation.
    fn manual_update_plan(operation: Operation) -> crate::plan::UpdatePlan {
        crate::plan::UpdatePlan {
            app: TorideId::slugify("brave-browser"),
            backend: BackendId::Flatpak,
            operation,
            dry_run: false,
            requires_elevation: false,
        }
    }

    /// The exact spec the remote probe runs for one installation.
    fn remotes_spec(installation: FlatpakInstallation) -> toride_runner::CommandSpec {
        command(FLATPAK, ["remotes", installation.flag(), "--columns=name"])
    }

    /// The exact spec the listing runs for one scope.
    fn list_spec(scope: FlatpakListScope) -> toride_runner::CommandSpec {
        command(FLATPAK, list_args(scope))
    }

    /// The fixture listing's contents, ready to serve as stdout.
    fn listing_output() -> String {
        read_fixture("flatpak/list-apps.tsv")
    }

    // --- version probe parsing ---------------------------------------------------

    #[test]
    fn parse_version_output_strips_the_flatpak_prefix_and_trims() {
        let version = parse_version_output("Flatpak 1.16.0\n").unwrap();
        assert_eq!(version, "1.16.0");
    }

    #[test]
    fn parse_version_output_keeps_extra_version_suffixes_verbatim() {
        let version = parse_version_output("Flatpak 1.19.2-91-gdeadbee\n").unwrap();
        assert_eq!(version, "1.19.2-91-gdeadbee");
    }

    #[test]
    fn parse_version_output_rejects_output_without_the_prefix() {
        let error = parse_version_output("flatpak 1.16.0\n").unwrap_err();
        assert!(
            matches!(error, Error::Command(toride_runner::Error::OutputParse(_))),
            "{error:?}"
        );
    }

    #[test]
    fn parse_version_output_rejects_empty_output() {
        assert!(parse_version_output("").is_err());
    }

    // --- remote-name parsing -----------------------------------------------------

    #[test]
    fn parse_remote_names_takes_non_empty_trimmed_lines() {
        let names = parse_remote_names("flathub\n\n  flathub-beta  \n");
        assert_eq!(names, ["flathub", "flathub-beta"]);
    }

    // --- listing parsing -----------------------------------------------------------

    #[test]
    fn parse_list_output_reads_entries_from_the_fixture_in_column_order() {
        let entries = parse_list_output(&listing_output()).unwrap();
        assert_eq!(entries.len(), 5, "{entries:?}");
        assert_eq!(
            entries[0],
            FlatpakEntry {
                application: "com.brave.Browser".to_owned(),
                version: Some("1.96.59".to_owned()),
                origin: "flathub".to_owned(),
                installation: "user".to_owned(),
            }
        );
    }

    #[test]
    fn parse_list_output_maps_an_empty_version_cell_to_none() {
        let entries = parse_list_output(&listing_output()).unwrap();
        // The AdwCustomizer row carries an empty version cell (no appdata
        // version metadata) — installed, version unknown.
        let entry = entries
            .iter()
            .find(|entry| entry.application == "io.gitlab.adwcustomizer.AdwCustomizer")
            .unwrap();
        assert_eq!(entry.version, None);
    }

    #[test]
    fn parse_list_output_covers_both_installations() {
        let entries = parse_list_output(&listing_output()).unwrap();
        let installations: Vec<&str> = entries.iter().map(|e| e.installation.as_str()).collect();
        assert!(installations.contains(&"user"), "{installations:?}");
        assert!(installations.contains(&"system"), "{installations:?}");
    }

    #[test]
    fn parse_list_output_skips_malformed_rows_without_failing_the_listing() {
        let raw = read_fixture("flatpak/list-apps-malformed.tsv");
        let entries = parse_list_output(&raw).unwrap();
        // The malformed fixture carries one row per failure mode (no tabs,
        // empty application, extra cell) plus two valid rows.
        let ids: Vec<&str> = entries.iter().map(|e| e.application.as_str()).collect();
        assert_eq!(
            ids,
            ["com.brave.Browser", "org.gnome.Calculator"],
            "{entries:?}"
        );
    }

    #[test]
    fn parse_list_output_returns_an_empty_listing_for_empty_output() {
        assert!(parse_list_output("").unwrap().is_empty());
        assert!(parse_list_output("  \n\n").unwrap().is_empty());
    }

    #[test]
    fn parse_list_output_errors_when_nothing_in_a_non_empty_document_parses() {
        // Every row malformed means the output shape is wrong (a future
        // flatpak changing columns) — that must not read as "nothing
        // installed".
        let error = parse_list_output("totally garbage\nnot a listing\n").unwrap_err();
        assert!(
            matches!(error, Error::Command(toride_runner::Error::OutputParse(_))),
            "{error:?}"
        );
    }

    // --- stderr classification ------------------------------------------------------

    #[test]
    fn stderr_classification_matches_each_not_installed_marker() {
        // The current flatpak wording uses Unicode curly quotes around the
        // id; the markers deliberately stop short of them.
        for stderr in [
            "error: No installed refs found for \u{2018}com.brave.Browser\u{2019}",
            "error: com.brave.Browser is not installed",
        ] {
            assert!(stderr_says_not_installed(stderr), "{stderr}");
        }
    }

    #[test]
    fn stderr_classification_ignores_markers_outside_error_lines() {
        // A warning mentioning a not-installed package plus an unrelated
        // error must not classify.
        assert!(!stderr_says_not_installed(
            "Warning: com.brave.Browser is not installed\nerror: Unable to connect to system bus"
        ));
    }

    #[test]
    fn stderr_classification_rejects_unrelated_failures() {
        assert!(!stderr_says_not_installed(
            "error: Remote \u{2018}flathub\u{2019} not found in the configured remotes"
        ));
    }

    // --- ref helpers -------------------------------------------------------------

    #[test]
    fn app_id_from_ref_extracts_the_id_segment() {
        assert_eq!(
            app_id_from_ref("app/com.brave.Browser/x86_64/stable"),
            Some("com.brave.Browser")
        );
    }

    #[test]
    fn app_id_from_ref_rejects_refs_without_the_app_prefix() {
        assert_eq!(
            app_id_from_ref("runtime/org.gnome.Platform/x86_64/48"),
            None
        );
        assert_eq!(app_id_from_ref("com.brave.Browser"), None);
        assert_eq!(app_id_from_ref("app//x86_64/stable"), None);
    }

    // --- flatpak constants ----------------------------------------------------------

    #[test]
    fn flathub_remote_url_is_derived_from_the_official_flatpakrepo_fixture() {
        // The remote-add URL is the signed descriptor flathub's setup page
        // publishes; pin it against the copied official fixture (the
        // descriptor's Url= key is the repo underneath).
        let raw = read_fixture("flatpak/flathub.flatpakrepo");
        let repo_url = raw
            .lines()
            .find_map(|line| line.strip_prefix("Url="))
            .unwrap_or_else(|| panic!("fixture carries no Url= line"));
        assert_eq!(FLATHUB_REPO_URL, format!("{repo_url}flathub.flatpakrepo"));
    }

    // --- list scope mapping -----------------------------------------------------------

    #[test]
    fn list_scope_flags_select_the_installations() {
        assert_eq!(FlatpakListScope::All.flag(), None);
        assert_eq!(FlatpakListScope::User.flag(), Some("--user"));
        assert_eq!(FlatpakListScope::System.flag(), Some("--system"));
    }

    #[test]
    fn list_scope_derives_from_the_plan_installation() {
        assert_eq!(
            FlatpakListScope::from(FlatpakInstallation::User),
            FlatpakListScope::User
        );
        assert_eq!(
            FlatpakListScope::from(FlatpakInstallation::System),
            FlatpakListScope::System
        );
    }

    // --- detection probes through the seam --------------------------------------------

    #[tokio::test]
    async fn version_probes_flatpak_version_with_exact_argv() {
        let spec = command(FLATPAK, ["--version"]);
        let fake = FakeRunner::new().strict().respond(
            spec.clone(),
            toride_runner::CommandOutput::from_stdout("Flatpak 1.16.0\n"),
        );
        let backend = backend(&fake);
        assert_eq!(backend.version().await.unwrap(), "1.16.0");
        fake.assert_called_with(&spec);
    }

    #[tokio::test]
    async fn ensure_remote_skips_remote_add_when_the_remote_is_already_configured() {
        let fake = FakeRunner::new().strict().respond(
            remotes_spec(FlatpakInstallation::User),
            toride_runner::CommandOutput::from_stdout("flathub\nflathub-beta\n"),
        );
        let backend = backend(&fake);
        let added = backend
            .ensure_remote(FlatpakInstallation::User, "flathub", FLATHUB_REPO_URL)
            .await
            .unwrap();
        assert!(!added, "remote already present, nothing to add");
        assert_eq!(fake.calls().len(), 1, "only the probe may run");
    }

    #[tokio::test]
    async fn ensure_remote_adds_a_missing_remote_with_if_not_exists_argv() {
        let add_spec = command(
            FLATPAK,
            [
                "remote-add",
                "--user",
                "--if-not-exists",
                "flathub",
                FLATHUB_REPO_URL,
            ],
        );
        let fake = FakeRunner::new()
            .strict()
            .respond(
                remotes_spec(FlatpakInstallation::User),
                toride_runner::CommandOutput::from_stdout(""),
            )
            .respond(
                add_spec.clone(),
                toride_runner::CommandOutput::from_stdout(""),
            );
        let backend = backend(&fake);
        let added = backend
            .ensure_remote(FlatpakInstallation::User, "flathub", FLATHUB_REPO_URL)
            .await
            .unwrap();
        assert!(added);
        fake.assert_called_with(&add_spec);
    }

    #[tokio::test]
    async fn ensure_remote_scopes_probe_and_add_to_the_requested_installation() {
        let add_spec = command(
            FLATPAK,
            [
                "remote-add",
                "--system",
                "--if-not-exists",
                "flathub",
                FLATHUB_REPO_URL,
            ],
        );
        let fake = FakeRunner::new()
            .strict()
            .respond(
                remotes_spec(FlatpakInstallation::System),
                toride_runner::CommandOutput::from_stdout(""),
            )
            .respond(
                add_spec.clone(),
                toride_runner::CommandOutput::from_stdout(""),
            );
        let backend = backend(&fake);
        backend
            .ensure_remote(FlatpakInstallation::System, "flathub", FLATHUB_REPO_URL)
            .await
            .unwrap();
        fake.assert_called_with(&remotes_spec(FlatpakInstallation::System));
        fake.assert_called_with(&add_spec);
    }

    #[tokio::test]
    async fn ensure_remote_maps_a_failing_probe_to_command_error() {
        let fake = FakeRunner::new().strict().respond(
            remotes_spec(FlatpakInstallation::User),
            toride_runner::CommandOutput::from_stderr("error: Failed to init config", 1),
        );
        let backend = backend(&fake);
        let error = backend
            .ensure_remote(FlatpakInstallation::User, "flathub", FLATHUB_REPO_URL)
            .await
            .unwrap_err();
        assert!(
            matches!(
                error,
                Error::Command(toride_runner::Error::CommandFailed { .. })
            ),
            "{error:?}"
        );
    }

    #[tokio::test]
    async fn ensure_remote_maps_a_failing_remote_add_to_command_error() {
        let add_spec = command(
            FLATPAK,
            [
                "remote-add",
                "--user",
                "--if-not-exists",
                "flathub",
                FLATHUB_REPO_URL,
            ],
        );
        let fake = FakeRunner::new()
            .strict()
            .respond(
                remotes_spec(FlatpakInstallation::User),
                toride_runner::CommandOutput::from_stdout(""),
            )
            .respond(
                add_spec,
                toride_runner::CommandOutput::from_stderr("error: Can't load remote", 1),
            );
        let backend = backend(&fake);
        let error = backend
            .ensure_remote(FlatpakInstallation::User, "flathub", FLATHUB_REPO_URL)
            .await
            .unwrap_err();
        assert!(
            matches!(
                error,
                Error::Command(toride_runner::Error::CommandFailed { .. })
            ),
            "{error:?}"
        );
    }

    // --- install ----------------------------------------------------------------

    #[tokio::test]
    async fn install_refuses_dry_run_plans_without_touching_the_runner() {
        let fake = FakeRunner::new().strict();
        let backend = backend(&fake);
        let plan = install_plan_for().dry_run(true);
        let target = linux_target();
        let error = backend
            .install(InstallRequest::new(&plan, &target))
            .await
            .unwrap_err();
        assert!(matches!(error, Error::DryRun { .. }), "{error:?}");
        assert!(fake.calls().is_empty(), "no flatpak command may run");
    }

    #[tokio::test]
    async fn install_refuses_elevation_requiring_plans_without_a_grant() {
        let fake = FakeRunner::new().strict();
        let backend = backend(&fake);
        let mut plan = install_plan_for();
        plan.requires_elevation = true;
        let target = linux_target();
        let error = backend
            .install(InstallRequest::new(&plan, &target))
            .await
            .unwrap_err();
        assert!(
            matches!(error, Error::ElevationRequired { .. }),
            "{error:?}"
        );
        assert!(fake.calls().is_empty(), "no flatpak command may run");
    }

    #[tokio::test]
    async fn install_rejects_non_flatpak_operations() {
        let fake = FakeRunner::new().strict();
        let backend = backend(&fake);
        let plan = manual_install_plan(Operation::DistroInstall {
            manager: crate::plan::PackageManager::Apt,
            package: "brave-browser".to_owned(),
        });
        let target = linux_target();
        let error = backend
            .install(InstallRequest::new(&plan, &target))
            .await
            .unwrap_err();
        assert!(
            matches!(error, Error::Command(toride_runner::Error::Other(_))),
            "{error:?}"
        );
    }

    #[tokio::test]
    async fn install_executes_the_plans_canonical_argv_plus_runtime_flags_only() {
        let plan = install_plan_for();
        // The plan's own argv stays free of runtime flags (the contract) —
        // the backend layers them on at execution.
        assert_eq!(
            plan.operation.argv(),
            [
                "flatpak",
                "install",
                "--user",
                "flathub",
                "app/com.brave.Browser/x86_64/stable"
            ]
        );
        let install_spec = command(
            FLATPAK,
            [
                "install",
                "--user",
                "--or-update",
                "--noninteractive",
                "flathub",
                "app/com.brave.Browser/x86_64/stable",
            ],
        );
        let fake = FakeRunner::new()
            .strict()
            .respond(
                remotes_spec(FlatpakInstallation::User),
                toride_runner::CommandOutput::from_stdout("flathub\n"),
            )
            .respond(
                install_spec.clone(),
                toride_runner::CommandOutput::from_stdout(""),
            )
            .respond(
                list_spec(FlatpakListScope::User),
                toride_runner::CommandOutput::from_stdout(""),
            );
        let backend = backend(&fake);
        let target = linux_target();
        backend
            .install(InstallRequest::new(&plan, &target))
            .await
            .unwrap();
        fake.assert_called_with(&install_spec);
    }

    #[tokio::test]
    async fn install_ensures_the_flathub_remote_before_installing_when_it_is_missing() {
        let add_spec = command(
            FLATPAK,
            [
                "remote-add",
                "--user",
                "--if-not-exists",
                "flathub",
                FLATHUB_REPO_URL,
            ],
        );
        let install_spec = command(
            FLATPAK,
            [
                "install",
                "--user",
                "--or-update",
                "--noninteractive",
                "flathub",
                "app/com.brave.Browser/x86_64/stable",
            ],
        );
        let fake = FakeRunner::new()
            .strict()
            .respond(
                remotes_spec(FlatpakInstallation::User),
                toride_runner::CommandOutput::from_stdout(""),
            )
            .respond(
                add_spec.clone(),
                toride_runner::CommandOutput::from_stdout(""),
            )
            .respond(
                install_spec.clone(),
                toride_runner::CommandOutput::from_stdout(""),
            )
            .respond(
                list_spec(FlatpakListScope::User),
                toride_runner::CommandOutput::from_stdout(""),
            );
        let backend = backend(&fake);
        let plan = install_plan_for();
        let target = linux_target();
        backend
            .install(InstallRequest::new(&plan, &target))
            .await
            .unwrap();
        fake.assert_called_with(&add_spec);
        fake.assert_called_with(&install_spec);
    }

    #[tokio::test]
    async fn install_skips_the_remote_ensure_for_non_flathub_remotes() {
        // A remote toride has no descriptor URL for is used as-is: only the
        // install and the post-verify listing may run (the strict fake has
        // no response for any remotes probe, so a probe would fail).
        let install_spec = command(
            FLATPAK,
            [
                "install",
                "--user",
                "--or-update",
                "--noninteractive",
                "gnome-nightly",
                "app/org.gnome.Calculator/x86_64/stable",
            ],
        );
        let fake = FakeRunner::new()
            .strict()
            .respond(
                install_spec.clone(),
                toride_runner::CommandOutput::from_stdout(""),
            )
            .respond(
                list_spec(FlatpakListScope::User),
                toride_runner::CommandOutput::from_stdout(""),
            );
        let backend = backend(&fake);
        let plan = manual_install_plan(Operation::FlatpakInstall {
            remote: "gnome-nightly".to_owned(),
            app_ref: "app/org.gnome.Calculator/x86_64/stable".to_owned(),
            installation: FlatpakInstallation::User,
        });
        let target = linux_target();
        backend
            .install(InstallRequest::new(&plan, &target))
            .await
            .unwrap();
        fake.assert_called_with(&install_spec);
    }

    #[tokio::test]
    async fn install_honors_the_system_installation_flag() {
        let install_spec = command(
            FLATPAK,
            [
                "install",
                "--system",
                "--or-update",
                "--noninteractive",
                "flathub",
                "app/com.brave.Browser/x86_64/stable",
            ],
        );
        let fake = FakeRunner::new()
            .strict()
            .respond(
                remotes_spec(FlatpakInstallation::System),
                toride_runner::CommandOutput::from_stdout("flathub\n"),
            )
            .respond(
                install_spec.clone(),
                toride_runner::CommandOutput::from_stdout(""),
            )
            .respond(
                list_spec(FlatpakListScope::System),
                toride_runner::CommandOutput::from_stdout(""),
            );
        let backend = backend(&fake);
        let plan = manual_install_plan(Operation::FlatpakInstall {
            remote: "flathub".to_owned(),
            app_ref: "app/com.brave.Browser/x86_64/stable".to_owned(),
            installation: FlatpakInstallation::System,
        });
        let target = linux_target();
        backend
            .install(InstallRequest::new(&plan, &target))
            .await
            .unwrap();
        fake.assert_called_with(&remotes_spec(FlatpakInstallation::System));
        fake.assert_called_with(&install_spec);
        fake.assert_called_with(&list_spec(FlatpakListScope::System));
    }

    #[tokio::test]
    async fn install_reports_the_version_from_the_post_install_listing() {
        let install_spec = command(
            FLATPAK,
            [
                "install",
                "--user",
                "--or-update",
                "--noninteractive",
                "flathub",
                "app/com.brave.Browser/x86_64/stable",
            ],
        );
        let fake = FakeRunner::new()
            .strict()
            .respond(
                remotes_spec(FlatpakInstallation::User),
                toride_runner::CommandOutput::from_stdout("flathub\n"),
            )
            .respond(install_spec, toride_runner::CommandOutput::from_stdout(""))
            .respond(
                list_spec(FlatpakListScope::User),
                toride_runner::CommandOutput::from_stdout(listing_output()),
            );
        let backend = backend(&fake);
        let plan = install_plan_for();
        let target = linux_target();
        let outcome = backend
            .install(InstallRequest::new(&plan, &target))
            .await
            .unwrap();
        assert_eq!(outcome.version.as_deref(), Some("1.96.59"));
        assert!(
            outcome.detail.contains("app/com.brave.Browser"),
            "{}",
            outcome.detail
        );
    }

    #[tokio::test]
    async fn install_degrades_to_no_version_when_the_post_verify_listing_fails() {
        let install_spec = command(
            FLATPAK,
            [
                "install",
                "--user",
                "--or-update",
                "--noninteractive",
                "flathub",
                "app/com.brave.Browser/x86_64/stable",
            ],
        );
        let fake = FakeRunner::new()
            .strict()
            .respond(
                remotes_spec(FlatpakInstallation::User),
                toride_runner::CommandOutput::from_stdout("flathub\n"),
            )
            .respond(install_spec, toride_runner::CommandOutput::from_stdout(""))
            .respond(
                list_spec(FlatpakListScope::User),
                toride_runner::CommandOutput::from_stderr("error: listing failed", 1),
            );
        let backend = backend(&fake);
        let plan = install_plan_for();
        let target = linux_target();
        let outcome = backend
            .install(InstallRequest::new(&plan, &target))
            .await
            .unwrap();
        assert_eq!(outcome.version, None, "the install itself succeeded");
    }

    #[tokio::test]
    async fn install_maps_nonzero_exit_to_command_error_carrying_stderr() {
        let install_spec = command(
            FLATPAK,
            [
                "install",
                "--user",
                "--or-update",
                "--noninteractive",
                "flathub",
                "app/com.not.Available/x86_64/stable",
            ],
        );
        let fake = FakeRunner::new()
            .strict()
            .respond(
                remotes_spec(FlatpakInstallation::User),
                toride_runner::CommandOutput::from_stdout("flathub\n"),
            )
            .respond(
                install_spec,
                toride_runner::CommandOutput::from_stderr(
                    "error: app/com.not.Available/x86_64/stable not available in remote flathub",
                    1,
                ),
            );
        let backend = backend(&fake);
        let plan = manual_install_plan(Operation::FlatpakInstall {
            remote: "flathub".to_owned(),
            app_ref: "app/com.not.Available/x86_64/stable".to_owned(),
            installation: FlatpakInstallation::User,
        });
        let target = linux_target();
        let error = backend
            .install(InstallRequest::new(&plan, &target))
            .await
            .unwrap_err();
        assert!(
            matches!(
                error,
                Error::Command(toride_runner::Error::CommandFailed { .. })
            ),
            "{error:?}"
        );
        assert!(
            error.to_string().contains("not available in remote"),
            "stderr tail must travel with the error: {error}"
        );
    }

    // --- uninstall ----------------------------------------------------------------

    #[tokio::test]
    async fn uninstall_refuses_dry_run_plans_without_touching_the_runner() {
        let fake = FakeRunner::new().strict();
        let backend = backend(&fake);
        let plan = uninstall_plan_for().dry_run(true);
        let target = linux_target();
        let error = backend
            .uninstall(UninstallRequest::new(&plan, &target))
            .await
            .unwrap_err();
        assert!(matches!(error, Error::DryRun { .. }), "{error:?}");
        assert!(fake.calls().is_empty(), "no flatpak command may run");
    }

    #[tokio::test]
    async fn uninstall_executes_the_bare_app_id_with_noninteractive() {
        let spec = command(
            FLATPAK,
            [
                "uninstall",
                "--user",
                "--noninteractive",
                "com.brave.Browser",
            ],
        );
        let fake = FakeRunner::new()
            .strict()
            .respond(spec.clone(), toride_runner::CommandOutput::from_stdout(""));
        let backend = backend(&fake);
        let plan = uninstall_plan_for();
        let target = linux_target();
        let outcome = backend
            .uninstall(UninstallRequest::new(&plan, &target))
            .await
            .unwrap();
        assert!(
            outcome.detail.contains("com.brave.Browser"),
            "{}",
            outcome.detail
        );
        assert!(
            !outcome.detail.contains("already absent"),
            "a real uninstall happened: {outcome:?}"
        );
        fake.assert_called_with(&spec);
    }

    #[tokio::test]
    async fn uninstall_treats_the_not_installed_error_as_an_already_absent_success() {
        let spec = command(
            FLATPAK,
            [
                "uninstall",
                "--user",
                "--noninteractive",
                "com.brave.Browser",
            ],
        );
        // flatpak's own wording for a single-REF uninstall of an absent app
        // (typed FLATPAK_ERROR_NOT_INSTALLED, exit 1, curly-quoted id).
        let fake = FakeRunner::new().strict().respond(
            spec,
            toride_runner::CommandOutput::from_stderr(
                "error: No installed refs found for \u{2018}com.brave.Browser\u{2019}",
                1,
            ),
        );
        let backend = backend(&fake);
        let plan = uninstall_plan_for();
        let target = linux_target();
        let outcome = backend
            .uninstall(UninstallRequest::new(&plan, &target))
            .await
            .unwrap();
        assert!(outcome.detail.contains("already absent"), "{outcome:?}");
    }

    #[tokio::test]
    async fn uninstall_requires_exit_one_for_the_not_installed_classification() {
        // A signal-killed flatpak (exit 130) that had already printed the
        // not-installed line is a real error — the silent-signal and
        // marker gates must BOTH hold.
        let spec = command(
            FLATPAK,
            [
                "uninstall",
                "--user",
                "--noninteractive",
                "com.brave.Browser",
            ],
        );
        let fake = FakeRunner::new().strict().respond(
            spec,
            toride_runner::CommandOutput::from_stderr(
                "error: No installed refs found for \u{2018}com.brave.Browser\u{2019}",
                130,
            ),
        );
        let backend = backend(&fake);
        let plan = uninstall_plan_for();
        let target = linux_target();
        let error = backend
            .uninstall(UninstallRequest::new(&plan, &target))
            .await
            .unwrap_err();
        assert!(
            matches!(
                error,
                Error::Command(toride_runner::Error::CommandFailed { .. })
            ),
            "{error:?}"
        );
    }

    #[tokio::test]
    async fn uninstall_maps_unrelated_failures_to_command_error() {
        let spec = command(
            FLATPAK,
            [
                "uninstall",
                "--user",
                "--noninteractive",
                "com.brave.Browser",
            ],
        );
        let fake = FakeRunner::new().strict().respond(
            spec,
            toride_runner::CommandOutput::from_stderr("error: Permission denied", 1),
        );
        let backend = backend(&fake);
        let plan = uninstall_plan_for();
        let target = linux_target();
        let error = backend
            .uninstall(UninstallRequest::new(&plan, &target))
            .await
            .unwrap_err();
        assert!(
            matches!(
                error,
                Error::Command(toride_runner::Error::CommandFailed { .. })
            ),
            "{error:?}"
        );
    }

    #[tokio::test]
    async fn uninstall_honors_the_system_installation_flag() {
        let spec = command(
            FLATPAK,
            [
                "uninstall",
                "--system",
                "--noninteractive",
                "com.brave.Browser",
            ],
        );
        let fake = FakeRunner::new()
            .strict()
            .respond(spec.clone(), toride_runner::CommandOutput::from_stdout(""));
        let backend = backend(&fake);
        let plan = manual_uninstall_plan(Operation::FlatpakUninstall {
            app_id: "com.brave.Browser".to_owned(),
            installation: FlatpakInstallation::System,
        });
        let target = linux_target();
        backend
            .uninstall(UninstallRequest::new(&plan, &target))
            .await
            .unwrap();
        fake.assert_called_with(&spec);
    }

    fn update_spec(flag: &str, app_id: &str) -> toride_runner::CommandSpec {
        command(FLATPAK, ["update", flag, "--noninteractive", app_id])
    }

    #[tokio::test]
    async fn update_refuses_dry_run_plans_without_touching_the_runner() {
        let fake = FakeRunner::new().strict();
        let backend = backend(&fake);
        let plan = manual_update_plan(Operation::FlatpakUpdate {
            app_id: "com.brave.Browser".to_owned(),
            installation: FlatpakInstallation::User,
        })
        .dry_run(true);
        let target = linux_target();
        let error = backend
            .update(UpdateRequest::new(&plan, &target))
            .await
            .unwrap_err();
        assert!(matches!(error, Error::DryRun { .. }), "{error:?}");
        assert!(fake.calls().is_empty(), "no flatpak command may run");
    }

    #[tokio::test]
    async fn update_refuses_elevation_requiring_plans_without_a_grant() {
        let fake = FakeRunner::new().strict();
        let backend = backend(&fake);
        let mut plan = manual_update_plan(Operation::FlatpakUpdate {
            app_id: "com.brave.Browser".to_owned(),
            installation: FlatpakInstallation::User,
        });
        plan.requires_elevation = true;
        let target = linux_target();
        let error = backend
            .update(UpdateRequest::new(&plan, &target))
            .await
            .unwrap_err();
        assert!(
            matches!(error, Error::ElevationRequired { .. }),
            "{error:?}"
        );
        assert!(fake.calls().is_empty(), "no flatpak command may run");
    }

    #[tokio::test]
    async fn update_rejects_non_flatpak_operations() {
        let fake = FakeRunner::new().strict();
        let backend = backend(&fake);
        let plan = manual_update_plan(Operation::BrewUpgrade {
            cask: true,
            token: "brave-browser".to_owned(),
        });
        let target = linux_target();
        let error = backend
            .update(UpdateRequest::new(&plan, &target))
            .await
            .unwrap_err();
        assert!(
            matches!(error, Error::Command(toride_runner::Error::Other(_))),
            "{error:?}"
        );
        assert!(fake.calls().is_empty());
    }

    #[tokio::test]
    async fn update_executes_the_user_installation_with_noninteractive() {
        let spec = update_spec("--user", "com.brave.Browser");
        let fake = FakeRunner::new()
            .strict()
            .respond(spec.clone(), toride_runner::CommandOutput::from_stdout(""));
        let backend = backend(&fake);
        let plan = manual_update_plan(Operation::FlatpakUpdate {
            app_id: "com.brave.Browser".to_owned(),
            installation: FlatpakInstallation::User,
        });
        let target = linux_target();
        backend
            .update(UpdateRequest::new(&plan, &target))
            .await
            .unwrap();
        fake.assert_called_with(&spec);
        fake.assert_no_unmatched_calls();
    }

    #[tokio::test]
    async fn update_honors_the_system_installation_flag() {
        let spec = update_spec("--system", "com.brave.Browser");
        let fake = FakeRunner::new()
            .strict()
            .respond(spec.clone(), toride_runner::CommandOutput::from_stdout(""));
        let backend = backend(&fake);
        let plan = manual_update_plan(Operation::FlatpakUpdate {
            app_id: "com.brave.Browser".to_owned(),
            installation: FlatpakInstallation::System,
        });
        let target = linux_target();
        backend
            .update(UpdateRequest::new(&plan, &target))
            .await
            .unwrap();
        fake.assert_called_with(&spec);
        fake.assert_no_unmatched_calls();
    }

    #[tokio::test]
    async fn update_maps_nonzero_exit_to_command_error_carrying_stderr() {
        let spec = update_spec("--user", "com.not.Installed");
        let fake = FakeRunner::new().strict().respond(
            spec,
            toride_runner::CommandOutput::from_stderr(
                "error: No installed refs found for \u{2018}com.not.Installed\u{2019}",
                1,
            ),
        );
        let backend = backend(&fake);
        let plan = manual_update_plan(Operation::FlatpakUpdate {
            app_id: "com.not.Installed".to_owned(),
            installation: FlatpakInstallation::User,
        });
        let target = linux_target();
        let error = backend
            .update(UpdateRequest::new(&plan, &target))
            .await
            .unwrap_err();
        assert!(
            matches!(
                error,
                Error::Command(toride_runner::Error::CommandFailed { .. })
            ),
            "{error:?}"
        );
        assert!(
            error.to_string().contains("No installed refs found"),
            "stderr tail must travel with the error: {error}"
        );
    }

    // --- listing + status ----------------------------------------------------------

    #[tokio::test]
    async fn list_installed_runs_the_unscoped_all_installations_listing_argv() {
        let spec = list_spec(FlatpakListScope::All);
        assert_eq!(
            spec.args,
            [
                "list",
                "--app",
                "--columns=application,version,origin,installation"
            ]
        );
        let fake = FakeRunner::new()
            .strict()
            .respond(spec.clone(), toride_runner::CommandOutput::from_stdout(""));
        let backend = backend(&fake);
        backend.list_installed(ListQuery::all()).await.unwrap();
        fake.assert_called_with(&spec);
    }

    #[tokio::test]
    async fn list_installed_maps_and_filters_entries() {
        // Two listings run (the all-query, then the filtered re-query), so
        // the exact response is registered for both dispatches.
        let fake = FakeRunner::new()
            .strict()
            .respond(
                list_spec(FlatpakListScope::All),
                toride_runner::CommandOutput::from_stdout(listing_output()),
            )
            .respond(
                list_spec(FlatpakListScope::All),
                toride_runner::CommandOutput::from_stdout(listing_output()),
            );
        let backend = backend(&fake);
        let apps = backend.list_installed(ListQuery::all()).await.unwrap();
        assert_eq!(apps.len(), 5, "{apps:?}");
        assert_eq!(apps[0].id, "com.brave.Browser");
        assert_eq!(apps[0].version.as_deref(), Some("1.96.59"));
        let scoped = backend
            .list_installed(ListQuery::id("org.mozilla.firefox"))
            .await
            .unwrap();
        assert_eq!(scoped.len(), 1, "{scoped:?}");
        assert_eq!(scoped[0].id, "org.mozilla.firefox");
    }

    #[tokio::test]
    async fn list_installed_maps_nonzero_exit_to_command_error() {
        let fake = FakeRunner::new().strict().respond(
            list_spec(FlatpakListScope::All),
            toride_runner::CommandOutput::from_stderr("error: Failed to read installations", 1),
        );
        let backend = backend(&fake);
        let error = backend.list_installed(ListQuery::all()).await.unwrap_err();
        assert!(
            matches!(
                error,
                Error::Command(toride_runner::Error::CommandFailed { .. })
            ),
            "{error:?}"
        );
    }

    #[tokio::test]
    async fn list_scopes_the_listing_argv_to_the_user_installation() {
        let spec = list_spec(FlatpakListScope::User);
        assert_eq!(
            spec.args,
            [
                "list",
                "--user",
                "--app",
                "--columns=application,version,origin,installation"
            ]
        );
        let fake = FakeRunner::new()
            .strict()
            .respond(spec.clone(), toride_runner::CommandOutput::from_stdout(""));
        let backend = backend(&fake);
        backend.list_entries(FlatpakListScope::User).await.unwrap();
        fake.assert_called_with(&spec);
    }

    #[tokio::test]
    async fn list_scopes_the_listing_argv_to_the_system_installation() {
        let spec = list_spec(FlatpakListScope::System);
        assert_eq!(
            spec.args,
            [
                "list",
                "--system",
                "--app",
                "--columns=application,version,origin,installation"
            ]
        );
        let fake = FakeRunner::new()
            .strict()
            .respond(spec.clone(), toride_runner::CommandOutput::from_stdout(""));
        let backend = backend(&fake);
        backend
            .list_entries(FlatpakListScope::System)
            .await
            .unwrap();
        fake.assert_called_with(&spec);
    }

    #[tokio::test]
    async fn status_derives_the_installed_version_from_the_listing() {
        // No status override exists: one unscoped listing covers both
        // installations; not-found is NotInstalled, never an error.
        let fake = FakeRunner::new().strict().respond(
            list_spec(FlatpakListScope::All),
            toride_runner::CommandOutput::from_stdout(listing_output()),
        );
        let backend = backend(&fake);
        let status = backend
            .status(StatusQuery::new("org.mozilla.firefox"))
            .await
            .unwrap();
        assert_eq!(
            status,
            BackendStatus::Installed {
                version: Some("141.0.3".to_owned())
            }
        );
        fake.assert_called_with(&list_spec(FlatpakListScope::All));
    }

    #[tokio::test]
    async fn status_reports_not_installed_for_ids_absent_from_the_listing() {
        let fake = FakeRunner::new().strict().respond(
            list_spec(FlatpakListScope::All),
            toride_runner::CommandOutput::from_stdout(listing_output()),
        );
        let backend = backend(&fake);
        let status = backend
            .status(StatusQuery::new("org.absent.App"))
            .await
            .unwrap();
        assert_eq!(status, BackendStatus::NotInstalled);
    }

    #[tokio::test]
    async fn installed_version_scopes_the_listing_to_the_requested_installation() {
        let fake = FakeRunner::new().strict().respond(
            list_spec(FlatpakListScope::System),
            toride_runner::CommandOutput::from_stdout(
                "org.mozilla.firefox\t141.0.3\tflathub\tsystem\n",
            ),
        );
        let backend = backend(&fake);
        assert_eq!(
            backend
                .installed_version("org.mozilla.firefox", FlatpakInstallation::System)
                .await
                .unwrap(),
            Some("141.0.3".to_owned())
        );
        fake.assert_called_with(&list_spec(FlatpakListScope::System));
    }

    #[tokio::test]
    async fn installed_version_returns_none_for_ids_missing_from_the_scoped_listing() {
        let fake = FakeRunner::new().strict().respond(
            list_spec(FlatpakListScope::User),
            toride_runner::CommandOutput::from_stdout(""),
        );
        let backend = backend(&fake);
        assert_eq!(
            backend
                .installed_version("org.mozilla.firefox", FlatpakInstallation::User)
                .await
                .unwrap(),
            None
        );
    }

    // --- available-version listing ---------------------------------------------

    #[tokio::test]
    async fn available_versions_lists_the_remotes_branches_for_the_app() {
        let spec = command(
            FLATPAK,
            [
                "remote-ls",
                "--user",
                "--app",
                "--columns=application,branch",
                "flathub",
            ],
        );
        let rows = "org.mozilla.firefox\tstable\n\
                    com.brave.Browser\tstable\n\
                    com.brave.Browser\tbeta\n";
        let fake = FakeRunner::new().strict().respond(
            spec.clone(),
            toride_runner::CommandOutput::from_stdout(rows.to_owned()),
        );
        let backend = backend(&fake);
        assert_eq!(
            backend
                .available_versions("com.brave.Browser", FlatpakInstallation::User)
                .await
                .unwrap(),
            vec![Version::new("stable"), Version::new("beta")],
            "the app's rows only, remote order"
        );
        fake.assert_called_with(&spec);
        fake.assert_no_unmatched_calls();
    }

    #[tokio::test]
    async fn available_versions_scopes_the_listing_to_the_system_installation() {
        let spec = command(
            FLATPAK,
            [
                "remote-ls",
                "--system",
                "--app",
                "--columns=application,branch",
                "flathub",
            ],
        );
        let fake = FakeRunner::new().strict().respond(
            spec.clone(),
            toride_runner::CommandOutput::from_stdout("com.brave.Browser\tstable\n".to_owned()),
        );
        let backend = backend(&fake);
        assert_eq!(
            backend
                .available_versions("com.brave.Browser", FlatpakInstallation::System)
                .await
                .unwrap(),
            vec![Version::new("stable")]
        );
        fake.assert_called_with(&spec);
    }

    #[tokio::test]
    async fn available_versions_is_empty_for_an_app_absent_from_the_remote() {
        let spec = command(
            FLATPAK,
            [
                "remote-ls",
                "--user",
                "--app",
                "--columns=application,branch",
                "flathub",
            ],
        );
        let fake = FakeRunner::new().strict().respond(
            spec,
            toride_runner::CommandOutput::from_stdout("org.mozilla.firefox\tstable\n".to_owned()),
        );
        let backend = backend(&fake);
        assert!(
            backend
                .available_versions("com.brave.Browser", FlatpakInstallation::User)
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn trait_available_versions_rides_the_user_installation() {
        let spec = command(
            FLATPAK,
            [
                "remote-ls",
                "--user",
                "--app",
                "--columns=application,branch",
                "flathub",
            ],
        );
        let fake = FakeRunner::new().strict().respond(
            spec.clone(),
            toride_runner::CommandOutput::from_stdout("com.brave.Browser\tstable\n".to_owned()),
        );
        let backend = backend(&fake);
        let dyn_backend: &dyn Backend = &backend;
        assert_eq!(
            dyn_backend
                .available_versions("com.brave.Browser")
                .await
                .unwrap(),
            vec![Version::new("stable")]
        );
        fake.assert_called_with(&spec);
    }

    #[test]
    fn parse_remote_branches_skips_malformed_rows_and_empty_branch_cells() {
        let rows = "com.brave.Browser\tstable\n\
                    no-tab-row\n\
                    \t1.0\n\
                    com.brave.Browser\t\n\
                    com.brave.Browser\tbeta\n";
        assert_eq!(
            parse_remote_branches(rows, "com.brave.Browser").unwrap(),
            vec![Version::new("stable"), Version::new("beta")]
        );
        assert_eq!(
            parse_remote_branches("", "com.brave.Browser").unwrap(),
            Vec::<Version>::new()
        );
    }

    #[test]
    fn parse_remote_branches_dedupes_the_per_arch_ref_rows() {
        // One row per ref: a multi-arch app repeats each branch.
        let rows = "com.brave.Browser\tstable\n\
                    com.brave.Browser\tstable\n\
                    com.brave.Browser\tbeta\n\
                    com.brave.Browser\tstable\n";
        assert_eq!(
            parse_remote_branches(rows, "com.brave.Browser").unwrap(),
            vec![Version::new("stable"), Version::new("beta")],
            "first-seen order, one entry per branch"
        );
    }

    #[test]
    fn parse_remote_branches_rejects_a_non_empty_document_with_no_parseable_rows() {
        let error = parse_remote_branches("garbage without tabs", "com.brave.Browser").unwrap_err();
        assert!(
            matches!(error, Error::Command(toride_runner::Error::OutputParse(_))),
            "{error:?}"
        );
    }

    // --- identity ----------------------------------------------------------------

    #[test]
    fn id_is_flatpak_and_supports_linux_targets_only() {
        let backend = backend(&FakeRunner::new().strict());
        assert_eq!(backend.id(), BackendId::Flatpak);
        assert!(backend.supports(&linux_target()));
        assert!(!backend.supports(&Target::macos(Arch::X86_64)));
        assert!(!backend.supports(&Target::new(Os::Windows, Arch::X86_64)));
    }
}
