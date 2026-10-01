//! # Distro backend (`apt-get` / `dnf` / `pacman` / `apk`)
//!
//! [`DistroBackend`] is the [`Backend`] implementation for a Linux distro's
//! native package manager: it executes the planner's
//! [`Operation::DistroInstall`] / [`Operation::DistroUninstall`] operations
//! through the shared [`CommandRunner`] seam and answers list/status queries
//! from the distro's package database. One backend instance serves one
//! [`DistroFamily`]; every family the registry names executes its manager's
//! stable, scriptable CLI — `apt-get` (Debian/Ubuntu), `dnf` (Fedora),
//! `pacman` (Arch), `apk` (Alpine).
//!
//! ## Real-CLI semantics (verified against the shipped man pages and source)
//!
//! - **Install** — `apt-get install -y <pkg>` / `dnf install -y <pkg>` /
//!   `pacman --sync --noconfirm <pkg>` / `apk add <pkg>`. Interactivity
//!   suppression is per manager, never a shared `-y`: `-y` is apt-get's
//!   `--yes, --assume-yes` ("Automatic yes to prompts; assume \"yes\" as
//!   answer to all prompts and run non-interactively", apt-get(8)) and dnf's
//!   `-y, --assumeyes` ("Automatically answer yes for all questions",
//!   dnf(8)); pacman's assume-yes spelling is `--noconfirm` ("Bypass any and
//!   all 'Are you sure?' messages", pacman(8)) because pacman's `-y` is
//!   `--refresh`, the download-a-fresh-copy-of-the-package-databases flag,
//!   which belongs to a future update verb and never to install; apk takes
//!   no flag at all ("By default apk is non-interactive", apk(8) — asking is
//!   opt-in via `--interactive`, and apk has no `-y`, so `apk add -y` is an
//!   unrecognized-option error). The apt arm additionally carries
//!   `DEBIAN_FRONTEND=noninteractive` (the debconf frontend selector,
//!   debconf(7)) so configure scripts never try to prompt. Why `apt-get` and
//!   not the `apt` the plan's canonical argv names: apt(8) itself warns that
//!   the `apt` CLI "is designed for end users" and may change between
//!   versions — scripts are told to use `apt-get`. The plan carries the
//!   family's manager name and verb (A1's canonical `apt install <pkg>`,
//!   `pacman --sync <pkg>`, `apk add <pkg>`); execution uses the scriptable
//!   program and the per-manager suppression flags, both runtime ergonomics
//!   that stay out of the plan's argv by contract.
//! - **Uninstall** — `apt-get remove -y <pkg>` / `dnf remove -y <pkg>` /
//!   `pacman --remove --noconfirm <pkg>` / `apk del <pkg>`.
//!   Purging config files (`apt-get remove --purge`, apt-get(8)) is a
//!   deliberate non-goal: the plan's [`UninstallOptions`] carries no purge
//!   slot, and inventing an execution-time knob the planner never planned
//!   would break the plan-is-the-record invariant. `dnf remove` removes
//!   dependent packages along with the named one (dnf(8)) — that is dnf's
//!   own dependency semantics, not something toride opts into.
//! - **Queries** — Debian-like state comes from `dpkg-query --show
//!   --showformat=${db:Status-Abbrev}${Package}\t${Version}\n <pkg...>`
//!   (dpkg-query(1); the `\t`/`\n` escapes are dpkg's own format escapes,
//!   the argv carries them literally). The status-abbrev column is prepended
//!   deliberately: dpkg's database keeps removed-but-configured packages
//!   (`rc ` abbrev), which are **not** installed — rows whose status
//!   character is not `i` are dropped. With no package operand the same
//!   command lists the whole database. Fedora-like state comes from
//!   `rpm --query --queryformat %{NAME}\t%{VERSION}\n <pkg...>`
//!   (rpm(8) `--queryformat QUERYFMT`, tags per rpm-queryformat(7), which
//!   supports the C `\t`/`\n` escapes); the all-listing adds `--all`
//!   ("Query all installed packages", rpm(8)) because a bare `rpm --query`
//!   with no operand reads package names from stdin. Arch state comes from
//!   `pacman --query <pkg...>` ("If no package names are provided in the
//!   command line, all installed packages will be queried", pacman(8)), one
//!   `name version` row per package — the space-separated `printf` shape of
//!   pacman's own query loop (`src/pacman/query.c`; pacman disables its
//!   color escapes when stdout is not a tty — `src/pacman/conf.c` — so the
//!   captured rows toride reads are plain text, `--color always` aside).
//!   Alpine state comes from
//!   `apk list --installed <pkg...>` (apk-list(8): patterns are fnmatch(3),
//!   no pattern matches everything, and `--installed` restricts the query to
//!   the local database), which at apk's default verbosity prints one bare
//!   package name per line (`src/app_list.c`). Every apk spelling that carries
//!   a version glues it to the name (`apk list -v`'s `name-version`) or
//!   needs apk-tools 3.x (`apk list --manifest`), so Alpine rows report
//!   `version: None` rather than splitting a glued token by guesswork.
//! - **Not installed is an answer, not an error** — `dpkg-query` exits 1
//!   with `dpkg-query: no packages found matching <pkg>` on stderr
//!   (dpkg-query(1): exit 1 = "the requested query failed either fully or
//!   partially, due to no file or package being found"; exit 2 = fatal);
//!   `rpm --query` prints `package <pkg> is not installed` (rpm source,
//!   lib/query.cc, `RPMLOG_NOTICE`) and exits with the **count** of failed
//!   lookups (lib/query.cc sums per-operand failures), so two missing
//!   packages exit 2, not 1. `pacman --query` exits 1 with `error: package
//!   '<pkg>' was not found` (`src/pacman/query.c`) while still printing the
//!   found operands' rows. All three signals map to `Ok(None)` /
//!   [`BackendStatus::NotInstalled`](crate::BackendStatus::NotInstalled) —
//!   never an error. `apk list` cannot fail on a no-match (its `list_main`
//!   returns unconditionally, `src/app_list.c`): an empty answer with exit 0
//!   is apk's not-found signal, so a nonzero apk exit is always a real
//!   error. Those markers are the programs' C-locale wording — dpkg-query,
//!   rpm, and pacman all translate their stderr (pacman's German po renders
//!   the not-found line as `Paket »…« wurde nicht gefunden`), so every
//!   query spec pins `LC_ALL=C`; without the pin, a localized host would
//!   turn a simply-absent package into [`Error::Command`]. Partial results
//!   survive: dpkg-query prints found packages on stdout while reporting the
//!   missing ones on stderr, and the classification keeps the stdout rows.
//! - **Failures surface with their stderr tail** — apt-get fails at exit
//!   100 ("returns zero on normal operation, decimal 100 on error",
//!   apt-get(8)) with the dpkg lock complaint in stderr (`E: Could not get
//!   lock /var/lib/dpkg/lock-frontend ...`); dnf's lock problems are their
//!   own exit class (dnf(8): 200, "There was a problem with acquiring or
//!   releasing of locks"). Without a dedicated error variant (the crate's
//!   error enum is fixed), these classify as [`Error::Command`] carrying the
//!   manager's own wording — the lock-held diagnosis travels verbatim.
//!   Unlike the flatpak backend, a failed uninstall of a *missing* package
//!   is **not** reclassified as success: apt-get remove is natively lenient
//!   about absent packages, and dnf's not-found wording differs between
//!   dnf4 and dnf5, so marker-matching there would be guesswork — the
//!   facade (A6) post-verifies instead.
//! - **Family detection** — [`parse_distro_family`] reads an os-release(5)
//!   document (`ID`, then `ID_LIKE` as the ancestor fallback, first known
//!   ancestor wins: Rocky's `ID="rocky" ID_LIKE="rhel fedora"` is Fedora
//!   because `fedora` is the first entry the registry knows, and Mint's
//!   `ID_LIKE="ubuntu debian"` is Ubuntu). [`DistroBackend::detect`] reads
//!   the real os-release(5) locations — [`OS_RELEASE_PATH`] first, then
//!   [`OS_RELEASE_FALLBACK_PATH`] when it is absent, the spec's mandated
//!   two-path check — and PATH-checks both the manager and the query
//!   program; [`detect_family_from`] is the injectable-reader seam the
//!   fixture tests ride.
//!
//! ## Elevation
//!
//! Every distro plan carries `requires_elevation: true` (A1 planner), and
//! this backend never acquires root itself: without an explicit
//! `elevated(true)` grant on the request, [`ensure_install_allowed`] /
//! [`ensure_uninstall_allowed`] refuse with [`Error::ElevationRequired`]
//! before any command is built — the caller arranges privileges (toride
//! never constructs `sudo`).
//!
//! [`Operation::DistroInstall`]: crate::Operation::DistroInstall
//! [`Operation::DistroUninstall`]: crate::Operation::DistroUninstall
//! [`UninstallOptions`]: crate::UninstallOptions
//! [`ensure_install_allowed`]: crate::backend::ensure_install_allowed
//! [`ensure_uninstall_allowed`]: crate::backend::ensure_uninstall_allowed

use async_trait::async_trait;
use toride_registry::{DistroFamily, Os};
use toride_runner::CommandOutput;

use crate::backend::{
    Backend, BackendId, InstallOutcome, InstallRequest, InstalledApp, ListQuery, UninstallOutcome,
    UninstallRequest, ensure_install_allowed, ensure_uninstall_allowed,
};
use crate::error::{Error, Result};
use crate::plan::{Operation, PackageManager, Target};
use crate::runner::{CommandRunner, command};

/// The primary os-release(5) location, read first by
/// [`DistroBackend::detect`] and [`detect_host_family`]. `/etc/os-release`
/// is the administrator-owned file — normally a symlink into the OS
/// vendor's `/usr` tree, which is why it usually wins by existing.
pub const OS_RELEASE_PATH: &str = "/etc/os-release";

/// The os-release(5) fallback location, consulted only when
/// [`OS_RELEASE_PATH`] is absent. The spec **mandates** this explicit
/// two-path check rather than relying on the `/etc` symlink: the symlink
/// is the common arrangement on complete systems, not a guarantee — a
/// stripped-down container can lack it while the vendor's file remains.
pub const OS_RELEASE_FALLBACK_PATH: &str = "/usr/lib/os-release";

/// The debconf frontend selector applied to every mutating apt command, so
/// package configuration scripts never prompt (debconf(7); apt-get's `-y`
/// alone covers apt's own prompts, not debconf's).
const DEBIAN_FRONTEND_ENV: (&str, &str) = ("DEBIAN_FRONTEND", "noninteractive");

const QUERY_LOCALE_ENV: (&str, &str) = ("LC_ALL", "C");

/// The dpkg-query showformat: a three-character status abbrev
/// (`ii ` = installed) glued in front of `<package>\t<version>`, one row per
/// line. The literal `\t`/`\n` are dpkg's own format escapes — the argv
/// carries them as two characters, exactly as the shell passes
/// `'${Package}\t${Version}\n'` in single quotes.
const DPKG_QUERY_FORMAT: &str = "${db:Status-Abbrev}${Package}\\t${Version}\\n";

/// The rpm queryformat: `<name>\t<version>`, one row per line, with C-style
/// `\t`/`\n` escapes rpm-queryformat(7) documents. `%{VERSION}` is the
/// upstream version — the distro release suffix lives in the separate
/// `%{RELEASE}` tag and stays out of the version toride records.
const RPM_QUERY_FORMAT: &str = "%{NAME}\\t%{VERSION}\\n";

/// The second character of the dpkg status abbrev — the package's current
/// state (dpkg-query(1), the `--list` legend): `i` in every installed state
/// (`ii ` installed, `hi ` held-installed), never in `rc ` (removed,
/// config-files left), `un ` (not installed) or the mid-install states
/// (`iU` unpacked, `iH` half-installed, …).
const DPKG_INSTALLED_STATUS_CHAR: u8 = b'i';

// ---------------------------------------------------------------------------
// Executors
// ---------------------------------------------------------------------------

/// The concrete command family one [`DistroFamily`] executes: the mutating
/// program plus the package-database query program for that family. Every
/// family the registry names routes to one of four executors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DistroExecutor {
    /// Debian-like — `apt-get` mutates, `dpkg-query` reads.
    Apt,
    /// Fedora-like — `dnf` mutates, `rpm` reads.
    Dnf,
    /// Arch — `pacman` mutates and reads.
    Pacman,
    /// Alpine — `apk` mutates and reads.
    Apk,
}

impl DistroExecutor {
    /// The executor a distro family routes to. `None` only for a family a
    /// future registry release adds (`DistroFamily` is `non_exhaustive`
    /// upstream): the backend answers those with an honest error instead of
    /// guessing at a CLI it does not implement.
    #[must_use]
    pub const fn for_family(family: DistroFamily) -> Option<Self> {
        match family {
            DistroFamily::Debian | DistroFamily::Ubuntu => Some(Self::Apt),
            DistroFamily::Fedora => Some(Self::Dnf),
            DistroFamily::Arch => Some(Self::Pacman),
            DistroFamily::Alpine => Some(Self::Apk),
            _ => None,
        }
    }

    /// The executor a planned [`PackageManager`] routes to — the inverse of
    /// [`DistroExecutor::manager`]. Every manager this crate plans routes to
    /// one: the match is exhaustive, so a future [`PackageManager`] variant
    /// fails compilation here instead of executing wrongly.
    #[must_use]
    pub const fn for_manager(manager: PackageManager) -> Self {
        match manager {
            PackageManager::Apt => Self::Apt,
            PackageManager::Dnf => Self::Dnf,
            PackageManager::Pacman => Self::Pacman,
            PackageManager::Apk => Self::Apk,
        }
    }

    /// The A1 [`PackageManager`] whose plan operations this executor runs —
    /// the router cross-checks a plan's manager against this before
    /// executing.
    #[must_use]
    pub const fn manager(self) -> PackageManager {
        match self {
            Self::Apt => PackageManager::Apt,
            Self::Dnf => PackageManager::Dnf,
            Self::Pacman => PackageManager::Pacman,
            Self::Apk => PackageManager::Apk,
        }
    }

    /// The mutating program, in its scriptable spelling (`apt-get`, not the
    /// end-user `apt` — see the module docs).
    #[must_use]
    pub const fn program(self) -> &'static str {
        match self {
            Self::Apt => "apt-get",
            Self::Dnf => "dnf",
            Self::Pacman => "pacman",
            Self::Apk => "apk",
        }
    }

    /// The package-database query program for the same family (`pacman` and
    /// `apk` read through the same program they mutate with).
    #[must_use]
    pub const fn query_program(self) -> &'static str {
        match self {
            Self::Apt => "dpkg-query",
            Self::Dnf => "rpm",
            Self::Pacman | Self::Apk => self.program(),
        }
    }

    const fn not_found_markers(self) -> &'static [&'static str] {
        match self {
            Self::Apt => &["no packages found matching"],
            Self::Dnf => &["is not installed"],
            Self::Pacman => &["was not found"],
            Self::Apk => &[],
        }
    }

    const fn assume_yes_flag(self) -> Option<&'static str> {
        match self {
            Self::Apt | Self::Dnf => Some("-y"),
            Self::Pacman => Some("--noconfirm"),
            Self::Apk => None,
        }
    }

    const fn noninteractive_env(self) -> Option<(&'static str, &'static str)> {
        match self {
            Self::Apt => Some(DEBIAN_FRONTEND_ENV),
            Self::Dnf | Self::Pacman | Self::Apk => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Family detection
// ---------------------------------------------------------------------------

/// Parse an os-release(5) document into the registry [`DistroFamily`].
///
/// `ID` is matched first; an unrecognized `ID` falls back to `ID_LIKE`,
/// taking the **first** ancestor the registry knows (derivatives list their
/// ancestors most-specific first: `ID_LIKE="rhel fedora"` → Fedora).
/// Quoted values (single or double, os-release(5) permits double quotes and
/// systemd's parser both) are unquoted. `None` means unknown — no parseable
/// `ID`, or neither the id nor any ancestor maps to a known family.
#[must_use]
pub fn parse_distro_family(os_release: &str) -> Option<DistroFamily> {
    let id = os_release_value(os_release, "ID")?;
    if let Some(family) = family_for_id(&id) {
        return Some(family);
    }
    os_release_value(os_release, "ID_LIKE")
        .and_then(|like| like.split_whitespace().find_map(family_for_id))
}

/// Detect the family through an injected os-release reader — the seam the
/// fixture tests ride. The reader is called with each of
/// [`OS_RELEASE_PATH`] and [`OS_RELEASE_FALLBACK_PATH`] in spec order;
/// the first document it reads is authoritative even when its family does
/// not parse (the fallback is for an *absent* `/etc` file, not for a
/// foreign one), and unreadable paths mean an undetectable family (`None`),
/// not an error.
#[must_use]
pub fn detect_family_from(
    mut read_os_release: impl FnMut(&str) -> std::io::Result<String>,
) -> Option<DistroFamily> {
    for path in [OS_RELEASE_PATH, OS_RELEASE_FALLBACK_PATH] {
        // First readable document wins — a present-but-unknown
        // /etc/os-release must not be second-guessed against a stale
        // /usr/lib copy.
        if let Ok(content) = read_os_release(path) {
            return parse_distro_family(&content);
        }
    }
    None
}

/// Detect this host's family from the real os-release(5) locations:
/// [`OS_RELEASE_PATH`] first, [`OS_RELEASE_FALLBACK_PATH`] only when it is
/// absent (os-release(5) mandates the two-path check rather than reliance
/// on the `/etc` symlink). `None` when both are absent or the authoritative
/// document names no known family.
#[must_use]
pub fn detect_host_family() -> Option<DistroFamily> {
    detect_family_from(|path| std::fs::read_to_string(path))
}

/// The registry family an os-release id (or `ID_LIKE` entry) names. Ids the
/// registry has no family for (`gentoo`, `rhel`, …) return `None` — either
/// an unknown distro or a pointer onward through `ID_LIKE`.
fn family_for_id(id: &str) -> Option<DistroFamily> {
    match id {
        "debian" => Some(DistroFamily::Debian),
        "ubuntu" => Some(DistroFamily::Ubuntu),
        "fedora" => Some(DistroFamily::Fedora),
        "arch" => Some(DistroFamily::Arch),
        "alpine" => Some(DistroFamily::Alpine),
        _ => None,
    }
}

/// Read one `KEY=VALUE` pair out of an os-release(5) document: the first
/// matching assignment wins, `#` comment lines are skipped, and the value
/// is trimmed and unquoted.
fn os_release_value(os_release: &str, key: &str) -> Option<String> {
    os_release.lines().find_map(|line| {
        let line = line.trim();
        if line.starts_with('#') {
            return None;
        }
        let (parsed_key, value) = line.split_once('=')?;
        (parsed_key.trim() == key).then(|| unquote(value.trim()))
    })
}

/// Strip one pair of matching surrounding quotes, if present.
fn unquote(value: &str) -> String {
    let quoted =
        matches!(value.as_bytes(), [b'"', .., b'"'] | [b'\'', .., b'\'']) && value.len() >= 2;
    if quoted {
        value[1..value.len() - 1].to_owned()
    } else {
        value.to_owned()
    }
}

// ---------------------------------------------------------------------------
// Backend
// ---------------------------------------------------------------------------

/// Distro-manager [`Backend`]: executes apt-get/dnf install/remove plans for
/// one family and answers list/status queries from that family's package
/// database.
///
/// # Example
///
/// ```rust,ignore
/// use toride_apps::CommandRunner;
/// use toride_apps::backends::distro::DistroBackend;
///
/// # async fn demo() -> toride_apps::Result<()> {
/// let runner = CommandRunner::builder().build();
/// let backend = DistroBackend::detect(runner)?; // reads /etc/os-release
/// let version = backend.installed_version("bash").await?;
/// # let _ = version;
/// # Ok(())
/// # }
/// ```
pub struct DistroBackend {
    /// The family this backend serves — picks the executor, doubles as the
    /// [`BackendId`].
    family: DistroFamily,
    /// The seam every manager command flows through.
    runner: CommandRunner,
}

impl DistroBackend {
    /// Create the backend for `family` over an explicit seam, with no host
    /// assumptions. This is the test-friendly constructor: the family is
    /// injectable and the seam's runner is fake-able. A family a future
    /// registry release adds (one with no [`DistroExecutor`]) is
    /// constructible — its id is a real routing target — but every operation
    /// answers with the honest `Self::executor` error.
    #[must_use]
    pub const fn new(family: DistroFamily, runner: CommandRunner) -> Self {
        Self { family, runner }
    }

    /// Create the backend for this host: read the os-release(5) locations
    /// ([`OS_RELEASE_PATH`], then [`OS_RELEASE_FALLBACK_PATH`] when it is
    /// absent), refuse unknown families, and PATH-check both the manager and
    /// its query program (via toride-runner's discovery helpers — no command
    /// is executed).
    ///
    /// # Errors
    ///
    /// [`Error::Command`] wrapping `Other` when both paths are absent or
    /// name no known family (or the family has no executor), and
    /// `BinaryNotFound` when a program is missing from the PATH.
    pub fn detect(runner: CommandRunner) -> Result<Self> {
        let family = detect_host_family().ok_or_else(|| {
            Error::Command(toride_runner::Error::Other(format!(
                "could not detect a known distro family from {OS_RELEASE_PATH} \
                 or {OS_RELEASE_FALLBACK_PATH}"
            )))
        })?;
        let backend = Self::new(family, runner);
        let executor = backend.executor()?;
        toride_runner::discovery::require_binary(executor.program())?;
        toride_runner::discovery::require_binary(executor.query_program())?;
        Ok(backend)
    }

    /// The family this backend serves (its [`BackendId`] payload).
    #[must_use]
    pub const fn family(&self) -> DistroFamily {
        self.family
    }

    fn executor(&self) -> Result<DistroExecutor> {
        DistroExecutor::for_family(self.family)
            .ok_or_else(|| executor_missing_for_family(self.family))
    }

    fn executor_for(&self, manager: PackageManager) -> Result<DistroExecutor> {
        let executor = DistroExecutor::for_manager(manager);
        let family_executor = self.executor()?;
        if executor != family_executor {
            return Err(Error::Command(toride_runner::Error::Other(format!(
                "manager `{}` does not match this backend's family {:?} (executes `{}`)",
                executor.program(),
                self.family,
                family_executor.program()
            ))));
        }
        Ok(executor)
    }

    /// The installed version of one package, from the family's query
    /// program (`Ok(None)` = not installed / no version reported). This is
    /// the kind-aware probe for the manifest (A5) and post-verify (A6);
    /// removed-but-configured dpkg packages count as not installed.
    ///
    /// # Errors
    ///
    /// [`Error::Command`] when the query fails for a reason other than
    /// "not found", or its output cannot be parsed.
    pub async fn installed_version(&self, package: &str) -> Result<Option<String>> {
        let executor = self.executor()?;
        let packages = [package.to_owned()];
        let apps = self.query_packages(executor, &packages).await?;
        Ok(apps
            .into_iter()
            .find(|app| app.id == package)
            .and_then(|app| app.version))
    }

    /// Query the family's package database for `packages` (all packages
    /// when empty) and parse the rows. A not-found exit (see the module
    /// docs) is an empty or partial answer, never an error; rows are
    /// further exact-filtered by callers when they carry ids.
    async fn query_packages(
        &self,
        executor: DistroExecutor,
        packages: &[String],
    ) -> Result<Vec<InstalledApp>> {
        let spec = query_spec(executor, packages);
        let output = self.runner.run(spec.clone()).await?;
        if output.success || query_reports_not_found(executor, &output) {
            return parse_query_output(executor, &output.stdout);
        }
        Err(command_failed_error(&spec, &output))
    }
}

#[async_trait]
impl Backend for DistroBackend {
    fn id(&self) -> BackendId {
        BackendId::Distro(self.family)
    }

    fn supports(&self, target: &Target) -> bool {
        // The backend executes its own family's manager, on Linux, after
        // the planner's family-match rule already routed the plan here; an
        // undetected family (`distro: None`) is not a target this backend
        // can vouch for — callers fill it via detection first.
        self.executor().is_ok() && target.os == Os::Linux && target.distro == Some(self.family)
    }

    async fn install(&self, request: InstallRequest<'_>) -> Result<InstallOutcome> {
        ensure_install_allowed(&request)?;
        let Operation::DistroInstall { manager, package } = &request.plan.operation else {
            return Err(misrouted_operation(&request.plan.operation));
        };
        let executor = self.executor_for(*manager)?;
        self.runner
            .run_checked(mutating_spec(executor, manager.install_verb(), package))
            .await?;
        // Post-verify: ask the package database what version landed, for
        // the manifest record. The install already succeeded, so a failing
        // probe degrades to "no version reported" instead of failing the
        // outcome.
        let version = self.installed_version(package).await.ok().flatten();
        Ok(InstallOutcome {
            version,
            detail: request.plan.operation.description(),
        })
    }

    async fn uninstall(&self, request: UninstallRequest<'_>) -> Result<UninstallOutcome> {
        ensure_uninstall_allowed(&request)?;
        let Operation::DistroUninstall { manager, package } = &request.plan.operation else {
            return Err(misrouted_operation(&request.plan.operation));
        };
        let executor = self.executor_for(*manager)?;
        self.runner
            .run_checked(mutating_spec(executor, manager.uninstall_verb(), package))
            .await?;
        Ok(UninstallOutcome {
            detail: request.plan.operation.description(),
        })
    }

    async fn list_installed(&self, query: ListQuery) -> Result<Vec<InstalledApp>> {
        let executor = self.executor()?;
        self.query_packages(executor, &query.ids).await.map(|apps| {
            // The manager operands are glob-capable (dpkg-query(1)
            // patterns; rpm matches patterns too), so a queried id must
            // still be exact-matched against the returned rows.
            apps.into_iter()
                .filter(|app| query.ids.is_empty() || query.ids.contains(&app.id))
                .collect()
        })
    }

    // `status` keeps the trait's default list-derived implementation: one
    // single-package query answers it, and not-found is NotInstalled, never
    // an error — the classification lives in `query_packages`. Callers that
    // want the raw probe call `installed_version(package)` directly.
}

// ---------------------------------------------------------------------------
// Command construction
// ---------------------------------------------------------------------------

fn mutating_spec(
    executor: DistroExecutor,
    verb: &str,
    package: &str,
) -> toride_runner::CommandSpec {
    let spec = match executor.assume_yes_flag() {
        Some(flag) => command(executor.program(), [verb, flag, package]),
        None => command(executor.program(), [verb, package]),
    };
    match executor.noninteractive_env() {
        Some((key, value)) => spec.env(key, value),
        None => spec,
    }
}

fn query_spec(executor: DistroExecutor, packages: &[String]) -> toride_runner::CommandSpec {
    let spec = match executor {
        DistroExecutor::Apt => {
            let showformat = format!("--showformat={DPKG_QUERY_FORMAT}");
            let mut args = vec!["--show", showformat.as_str()];
            args.extend(packages.iter().map(String::as_str));
            command(executor.query_program(), args)
        }
        DistroExecutor::Dnf => {
            let mut args = vec!["--query"];
            if packages.is_empty() {
                args.push("--all");
            }
            args.push("--queryformat");
            args.push(RPM_QUERY_FORMAT);
            args.extend(packages.iter().map(String::as_str));
            command(executor.query_program(), args)
        }
        DistroExecutor::Pacman => {
            let mut args = vec!["--query"];
            args.extend(packages.iter().map(String::as_str));
            command(executor.query_program(), args)
        }
        DistroExecutor::Apk => {
            let mut args = vec!["list", "--installed"];
            args.extend(packages.iter().map(String::as_str));
            command(executor.query_program(), args)
        }
    };
    spec.env(QUERY_LOCALE_ENV.0, QUERY_LOCALE_ENV.1)
}

// ---------------------------------------------------------------------------
// Output parsing and failure classification
// ---------------------------------------------------------------------------

/// What one row of a query document parsed into.
enum QueryRow {
    /// A well-formed row in the installed state.
    Installed(InstalledApp),
    /// A well-formed dpkg row in a non-installed state (`rc ` leftovers of
    /// removed packages, mid-install states) — seen, not kept.
    NonInstalledState,
    /// A row that does not match the expected shape — skipped.
    Malformed,
}

/// Parse the query program's stdout into installed-package rows.
///
/// Per-row tolerance: malformed rows are skipped, never fatal. A non-empty
/// document where **no** row is well-formed is an error, not an empty
/// answer — that means the format string no longer matches the program's
/// output shape and must surface loudly. (A document of only non-installed
/// dpkg states is well-formed and legitimately yields no rows.)
///
/// # Errors
///
/// [`Error::Command`] wrapping `OutputParse` for the no-well-formed-rows
/// case above.
fn parse_query_output(executor: DistroExecutor, stdout: &str) -> Result<Vec<InstalledApp>> {
    let mut apps = Vec::new();
    let mut well_formed = 0;
    for line in stdout.lines() {
        if line.trim().is_empty() {
            continue;
        }
        match parse_query_row(executor, line) {
            QueryRow::Installed(app) => {
                well_formed += 1;
                apps.push(app);
            }
            QueryRow::NonInstalledState => well_formed += 1,
            QueryRow::Malformed => {}
        }
    }
    if !stdout.trim().is_empty() && well_formed == 0 {
        return Err(output_parse_error(
            executor.query_program(),
            format!("no parseable rows in {stdout:?}"),
        ));
    }
    Ok(apps)
}

fn parse_query_row(executor: DistroExecutor, line: &str) -> QueryRow {
    match executor {
        DistroExecutor::Apt => {
            // `${db:Status-Abbrev}` is exactly three characters (`ii `)
            // glued in front of the package name: desired char, status
            // char, err char. Shape first (abbrev, tab, name), state after
            // — garbage without a tab is malformed, never a state.
            let Some((abbrev, rest)) = line.split_at_checked(3) else {
                return QueryRow::Malformed;
            };
            let Some((name, version)) = rest.split_once('\t') else {
                return QueryRow::Malformed;
            };
            if name.is_empty() {
                return QueryRow::Malformed;
            }
            if abbrev.as_bytes().get(1) != Some(&DPKG_INSTALLED_STATUS_CHAR) {
                return QueryRow::NonInstalledState;
            }
            QueryRow::Installed(InstalledApp {
                id: name.to_owned(),
                version: non_empty(version),
            })
        }
        DistroExecutor::Dnf => {
            let Some((name, version)) = line.split_once('\t') else {
                return QueryRow::Malformed;
            };
            if name.is_empty() {
                return QueryRow::Malformed;
            }
            QueryRow::Installed(InstalledApp {
                id: name.to_owned(),
                version: non_empty(version),
            })
        }
        DistroExecutor::Pacman => {
            let Some((name, version)) = line.split_once(' ') else {
                return QueryRow::Malformed;
            };
            if name.is_empty() {
                return QueryRow::Malformed;
            }
            QueryRow::Installed(InstalledApp {
                id: name.to_owned(),
                version: non_empty(version),
            })
        }
        DistroExecutor::Apk => {
            if line.is_empty() || line.chars().any(char::is_whitespace) {
                return QueryRow::Malformed;
            }
            QueryRow::Installed(InstalledApp {
                id: line.to_owned(),
                version: None,
            })
        }
    }
}

fn query_reports_not_found(executor: DistroExecutor, output: &CommandOutput) -> bool {
    let exit_is_not_found_class = match executor {
        DistroExecutor::Apt | DistroExecutor::Pacman => output.exit_code == Some(1),
        DistroExecutor::Dnf => output.exit_code.is_some(),
        DistroExecutor::Apk => false,
    };
    exit_is_not_found_class && stderr_all_not_found(executor, &output.stderr)
}

/// Whether every non-empty stderr line carries a not-found marker (at least
/// one marker line must exist — an exit-1 with empty stderr is not the
/// programs' not-found signal, which always prints its line).
fn stderr_all_not_found(executor: DistroExecutor, stderr: &str) -> bool {
    let mut marker_lines = 0;
    for line in stderr.lines().map(str::trim) {
        if line.is_empty() {
            continue;
        }
        if !executor
            .not_found_markers()
            .iter()
            .any(|marker| line.contains(marker))
        {
            return false;
        }
        marker_lines += 1;
    }
    marker_lines > 0
}

/// `""` → `None`, anything else → `Some(owned)`.
fn non_empty(value: &str) -> Option<String> {
    Some(value.to_owned()).filter(|value| !value.is_empty())
}

/// The error for a failed query, mirroring the seam's `run_checked` shape
/// (program, joined args, exit code, stderr) since the raw `run` path kept
/// the stdout for parsing.
fn command_failed_error(spec: &toride_runner::CommandSpec, output: &CommandOutput) -> Error {
    Error::Command(toride_runner::Error::CommandFailed {
        program: spec.program.clone(),
        args: toride_runner::display::redacted_args_display(spec),
        exit_code: output.exit_code,
        stderr: output.stderr.clone(),
    })
}

/// Build the unparseable-output error, naming the query program and cause.
fn output_parse_error(query_program: &str, cause: impl std::fmt::Display) -> Error {
    Error::Command(toride_runner::Error::OutputParse(format!(
        "{query_program}: {cause}"
    )))
}

/// The error for a plan operation this backend cannot execute (a non-distro
/// operation routed to the distro backend).
fn misrouted_operation(operation: &Operation) -> Error {
    Error::Command(toride_runner::Error::Other(format!(
        "distro backend cannot execute non-distro operation: {operation:?}"
    )))
}

fn executor_missing_for_family(family: DistroFamily) -> Error {
    Error::Command(toride_runner::Error::Other(format!(
        "no distro executor for family {family:?}; this crate executes apt-get, dnf, \
         pacman, and apk"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::{BackendStatus, StatusQuery};
    use crate::plan::{InstallPlan, UninstallOptions, UninstallPlan, plan_install, plan_uninstall};
    use std::path::Path;
    use std::sync::Arc;
    use toride_registry::{App, Arch, Availability, InstallMethod, TorideId};
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

    fn os_release(name: &str) -> String {
        read_fixture(&format!("distro/{name}"))
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

    fn distro_method(family: DistroFamily) -> InstallMethod {
        InstallMethod::Distro {
            family,
            repo: None,
            package: "brave-browser".to_owned(),
        }
    }

    fn target(family: DistroFamily) -> Target {
        Target::linux(Arch::X86_64, family)
    }

    /// A backend for `family` over a strict fake runner (unmatched
    /// dispatches fail).
    fn backend_for(family: DistroFamily, fake: &FakeRunner) -> DistroBackend {
        DistroBackend::new(family, CommandRunner::new(Arc::new(fake.clone())))
    }

    fn install_plan_for(family: DistroFamily) -> InstallPlan {
        plan_install(&app_with(distro_method(family)), &target(family)).unwrap()
    }

    fn uninstall_plan_for(family: DistroFamily) -> UninstallPlan {
        plan_uninstall(
            &app_with(distro_method(family)),
            &target(family),
            &UninstallOptions::default(),
        )
        .unwrap()
    }

    /// A distro-backend install plan carrying a hand-picked operation
    /// (foreign managers, non-distro operations for misrouting tests).
    fn manual_install_plan(family: DistroFamily, operation: Operation) -> InstallPlan {
        InstallPlan {
            app: TorideId::slugify("brave-browser"),
            backend: BackendId::Distro(family),
            operation,
            dry_run: false,
            requires_elevation: false,
        }
    }

    /// The exact spec a mutating apt command runs.
    fn apt_get_spec(verb: &str, package: &str) -> toride_runner::CommandSpec {
        command("apt-get", [verb, "-y", package]).env(DEBIAN_FRONTEND_ENV.0, DEBIAN_FRONTEND_ENV.1)
    }

    /// The exact spec a mutating dnf command runs.
    fn dnf_spec(verb: &str, package: &str) -> toride_runner::CommandSpec {
        command("dnf", [verb, "-y", package])
    }

    /// The exact spec a dpkg-query run uses for `packages`.
    fn dpkg_query_spec(packages: &[&str]) -> toride_runner::CommandSpec {
        let showformat = format!("--showformat={DPKG_QUERY_FORMAT}");
        let mut args = vec!["--show", showformat.as_str()];
        args.extend(packages.iter().copied());
        command("dpkg-query", args).env(QUERY_LOCALE_ENV.0, QUERY_LOCALE_ENV.1)
    }

    /// The exact spec an rpm query run uses for `packages` (all when empty).
    fn rpm_query_spec(packages: &[&str]) -> toride_runner::CommandSpec {
        let mut args = vec!["--query"];
        if packages.is_empty() {
            args.push("--all");
        }
        args.push("--queryformat");
        args.push(RPM_QUERY_FORMAT);
        args.extend(packages.iter().copied());
        command("rpm", args).env(QUERY_LOCALE_ENV.0, QUERY_LOCALE_ENV.1)
    }

    /// The exact spec a mutating pacman command runs.
    fn pacman_spec(verb: &str, package: &str) -> toride_runner::CommandSpec {
        command("pacman", [verb, "--noconfirm", package])
    }

    /// The exact spec a mutating apk command runs (no suppression at all).
    fn apk_spec(verb: &str, package: &str) -> toride_runner::CommandSpec {
        command("apk", [verb, package])
    }

    /// The exact spec a pacman query run uses for `packages` (all when
    /// empty).
    fn pacman_query_spec(packages: &[&str]) -> toride_runner::CommandSpec {
        let mut args = vec!["--query"];
        args.extend(packages.iter().copied());
        command("pacman", args).env(QUERY_LOCALE_ENV.0, QUERY_LOCALE_ENV.1)
    }

    /// The exact spec an apk listing uses for `packages` (all when empty).
    fn apk_query_spec(packages: &[&str]) -> toride_runner::CommandSpec {
        let mut args = vec!["list", "--installed"];
        args.extend(packages.iter().copied());
        command("apk", args).env(QUERY_LOCALE_ENV.0, QUERY_LOCALE_ENV.1)
    }

    /// The fixture dpkg-query document's contents, ready to serve as
    /// stdout.
    fn dpkg_fixture_output() -> String {
        read_fixture("distro/dpkg-query-status.txt")
    }

    /// The fixture rpm document's contents, ready to serve as stdout.
    fn rpm_fixture_output() -> String {
        read_fixture("distro/rpm-query.txt")
    }

    /// The fixture pacman document's contents, ready to serve as stdout.
    fn pacman_fixture_output() -> String {
        read_fixture("distro/pacman-query.txt")
    }

    /// The fixture apk document's contents, ready to serve as stdout.
    fn apk_fixture_output() -> String {
        read_fixture("distro/apk-list.txt")
    }

    /// The manager's dpkg lock error, as real apt-get reports it (exit 100,
    /// stderr `E:` line — apt-get(8): "returns zero on normal operation,
    /// decimal 100 on error").
    fn apt_lock_output() -> CommandOutput {
        CommandOutput::new(
            String::new(),
            "E: Could not get lock /var/lib/dpkg/lock-frontend. It is held by process 1234 (apt)\n"
                .to_owned(),
            Some(100),
        )
    }

    // --- os-release parsing ------------------------------------------------------

    #[test]
    fn parse_distro_family_reads_debian_from_the_fixture() {
        let family = parse_distro_family(&os_release("os-release-debian")).unwrap();
        assert_eq!(family, DistroFamily::Debian);
    }

    #[test]
    fn parse_distro_family_reads_ubuntu_from_the_fixture() {
        let family = parse_distro_family(&os_release("os-release-ubuntu")).unwrap();
        assert_eq!(family, DistroFamily::Ubuntu);
    }

    #[test]
    fn parse_distro_family_reads_fedora_from_the_fixture() {
        let family = parse_distro_family(&os_release("os-release-fedora")).unwrap();
        assert_eq!(family, DistroFamily::Fedora);
    }

    #[test]
    fn parse_distro_family_reads_arch_from_the_fixture() {
        let family = parse_distro_family(&os_release("os-release-arch")).unwrap();
        assert_eq!(family, DistroFamily::Arch);
    }

    #[test]
    fn parse_distro_family_maps_rhel_derivatives_to_fedora_via_id_like() {
        // Rocky quotes both values and lists ancestors most-specific first:
        // `rhel` has no registry family, `fedora` is the first known one.
        let family = parse_distro_family(&os_release("os-release-rocky")).unwrap();
        assert_eq!(family, DistroFamily::Fedora);
    }

    #[test]
    fn parse_distro_family_maps_ubuntu_derivatives_to_ubuntu_via_id_like() {
        let family = parse_distro_family(&os_release("os-release-linuxmint")).unwrap();
        assert_eq!(family, DistroFamily::Ubuntu);
    }

    #[test]
    fn parse_distro_family_returns_none_for_unknown_ids() {
        assert_eq!(parse_distro_family(&os_release("os-release-gentoo")), None);
    }

    #[test]
    fn parse_distro_family_returns_none_for_malformed_documents() {
        // No parseable ID line; the commented-out ID must be skipped too.
        assert_eq!(
            parse_distro_family(&os_release("os-release-malformed")),
            None
        );
        assert_eq!(parse_distro_family(""), None);
    }

    #[test]
    fn parse_distro_family_prefers_the_id_over_id_like() {
        let document = "ID=fedora\nID_LIKE=debian\n";
        assert_eq!(parse_distro_family(document), Some(DistroFamily::Fedora));
    }

    #[test]
    fn parse_distro_family_falls_back_to_id_like_when_the_id_is_unknown() {
        let document = "ID=pop\nID_LIKE=\"ubuntu debian\"\n";
        assert_eq!(parse_distro_family(document), Some(DistroFamily::Ubuntu));
    }

    #[test]
    fn parse_distro_family_returns_none_when_no_ancestor_is_known() {
        // `rhel` itself has no registry family and lists no known ancestor.
        let document = "ID=rhel\nID_LIKE=\"rhel centos\"\n";
        assert_eq!(parse_distro_family(document), None);
    }

    #[test]
    fn parse_distro_family_treats_an_empty_id_like_as_no_fallback() {
        let document = "ID=gentoo\nID_LIKE=\n";
        assert_eq!(parse_distro_family(document), None);
    }

    #[test]
    fn parse_distro_family_takes_the_first_assignment_of_a_key() {
        let document = "ID=fedora\nID=arch\n";
        assert_eq!(parse_distro_family(document), Some(DistroFamily::Fedora));
    }

    #[test]
    fn parse_distro_family_unquotes_double_and_single_quoted_values() {
        assert_eq!(
            parse_distro_family("ID=\"fedora\"\n"),
            Some(DistroFamily::Fedora)
        );
        assert_eq!(
            parse_distro_family("ID='alpine'\n"),
            Some(DistroFamily::Alpine)
        );
    }

    #[test]
    fn detect_family_from_reads_through_the_injected_reader() {
        // The injector is the seam: hand it a fixture read (the same way
        // the real default hands in the os-release(5) file reads).
        let family = detect_family_from(|_| Ok(os_release("os-release-fedora"))).unwrap();
        assert_eq!(family, DistroFamily::Fedora);
    }

    #[test]
    fn detect_family_from_prefers_the_etc_os_release_document() {
        // os-release(5) precedence: /etc/os-release is authoritative when
        // present — the fallback must not even be read (a panic in the
        // fallback arm fails the test if it ever is).
        let family = detect_family_from(|path| {
            if path == OS_RELEASE_PATH {
                Ok(os_release("os-release-fedora"))
            } else {
                panic!("the fallback must not be read while /etc/os-release is present: {path}")
            }
        })
        .unwrap();
        assert_eq!(family, DistroFamily::Fedora);
    }

    #[test]
    fn detect_family_from_falls_back_to_usr_lib_when_etc_is_absent() {
        // First /etc read fails, the /usr/lib fallback answers — and both
        // paths are consulted in spec order.
        let mut reads: Vec<String> = Vec::new();
        let family = detect_family_from(|path| {
            reads.push(path.to_owned());
            if path == OS_RELEASE_FALLBACK_PATH {
                Ok(os_release("os-release-fedora"))
            } else {
                Err(std::io::Error::other("absent"))
            }
        })
        .unwrap();
        assert_eq!(family, DistroFamily::Fedora);
        assert_eq!(
            reads,
            [OS_RELEASE_PATH, OS_RELEASE_FALLBACK_PATH].map(str::to_owned),
            "the search must cover both paths in spec order"
        );
    }

    #[test]
    fn detect_family_from_returns_none_when_both_os_release_paths_are_absent() {
        let mut reads: Vec<String> = Vec::new();
        let family = detect_family_from(|path| {
            reads.push(path.to_owned());
            Err(std::io::Error::other("absent"))
        });
        assert_eq!(family, None);
        assert_eq!(
            reads,
            [OS_RELEASE_PATH, OS_RELEASE_FALLBACK_PATH].map(str::to_owned),
            "both paths must be tried before giving up"
        );
    }

    #[test]
    fn detect_family_from_does_not_fall_through_when_etc_present_but_unknown() {
        // The fallback is for an ABSENT /etc file, not a foreign one: a
        // gentoo /etc/os-release must not be second-guessed against the
        // vendor copy behind it.
        let family = detect_family_from(|path| {
            if path == OS_RELEASE_PATH {
                Ok(os_release("os-release-gentoo"))
            } else {
                panic!("a present /etc/os-release is authoritative: {path}")
            }
        });
        assert_eq!(family, None);
    }

    // --- executor mapping ----------------------------------------------------------

    #[test]
    fn executor_routes_every_family_and_manager_round_trips() {
        let cases = [
            (DistroFamily::Debian, DistroExecutor::Apt),
            (DistroFamily::Ubuntu, DistroExecutor::Apt),
            (DistroFamily::Fedora, DistroExecutor::Dnf),
            (DistroFamily::Arch, DistroExecutor::Pacman),
            (DistroFamily::Alpine, DistroExecutor::Apk),
        ];
        for (family, executor) in cases {
            assert_eq!(
                DistroExecutor::for_family(family),
                Some(executor),
                "{family:?} must route, not plan-then-refuse"
            );
            assert_eq!(DistroExecutor::for_manager(executor.manager()), executor);
        }
    }

    #[test]
    fn executor_exposes_the_scriptable_programs() {
        assert_eq!(DistroExecutor::Apt.program(), "apt-get");
        assert_eq!(DistroExecutor::Apt.query_program(), "dpkg-query");
        assert_eq!(DistroExecutor::Dnf.program(), "dnf");
        assert_eq!(DistroExecutor::Dnf.query_program(), "rpm");
        assert_eq!(DistroExecutor::Pacman.program(), "pacman");
        assert_eq!(DistroExecutor::Pacman.query_program(), "pacman");
        assert_eq!(DistroExecutor::Apk.program(), "apk");
        assert_eq!(DistroExecutor::Apk.query_program(), "apk");
    }

    #[test]
    fn executor_suppression_is_per_manager_and_apk_carries_no_flag() {
        assert_eq!(DistroExecutor::Apt.assume_yes_flag(), Some("-y"));
        assert_eq!(DistroExecutor::Dnf.assume_yes_flag(), Some("-y"));
        assert_eq!(
            DistroExecutor::Pacman.assume_yes_flag(),
            Some("--noconfirm"),
            "pacman's -y is --refresh, a database-sync flag, never suppression"
        );
        assert_eq!(
            DistroExecutor::Apk.assume_yes_flag(),
            None,
            "apk is noninteractive by default and has no -y at all"
        );
    }

    #[test]
    fn executor_carries_the_interactivity_env_for_apt_only() {
        assert_eq!(
            DistroExecutor::Apt.noninteractive_env(),
            Some(DEBIAN_FRONTEND_ENV)
        );
        assert_eq!(DistroExecutor::Dnf.noninteractive_env(), None);
        assert_eq!(DistroExecutor::Pacman.noninteractive_env(), None);
        assert_eq!(DistroExecutor::Apk.noninteractive_env(), None);
    }

    // --- install ----------------------------------------------------------------

    #[tokio::test]
    async fn install_refuses_dry_run_plans_without_touching_the_runner() {
        let fake = FakeRunner::new().strict();
        let backend = backend_for(DistroFamily::Debian, &fake);
        let plan = install_plan_for(DistroFamily::Debian).dry_run(true);
        let target = target(DistroFamily::Debian);
        let error = backend
            .install(InstallRequest::new(&plan, &target).elevated(true))
            .await
            .unwrap_err();
        assert!(matches!(error, Error::DryRun { .. }), "{error:?}");
        assert!(fake.calls().is_empty(), "no manager command may run");
    }

    #[tokio::test]
    async fn install_refuses_elevation_requiring_plans_without_a_grant() {
        // Distro plans always carry requires_elevation (A1 planner) — the
        // refusal fires before any command is built or dispatched.
        let fake = FakeRunner::new().strict();
        let backend = backend_for(DistroFamily::Debian, &fake);
        let plan = install_plan_for(DistroFamily::Debian);
        assert!(plan.requires_elevation);
        let target = target(DistroFamily::Debian);
        let error = backend
            .install(InstallRequest::new(&plan, &target))
            .await
            .unwrap_err();
        assert!(
            matches!(error, Error::ElevationRequired { .. }),
            "{error:?}"
        );
        assert!(fake.calls().is_empty(), "no manager command may run");
    }

    #[tokio::test]
    async fn install_executes_apt_get_install_y_with_the_debian_frontend_env() {
        let spec = apt_get_spec("install", "brave-browser");
        let fake = FakeRunner::new()
            .strict()
            .respond(spec.clone(), CommandOutput::from_stdout(""))
            .respond(
                dpkg_query_spec(&["brave-browser"]),
                CommandOutput::from_stdout("ii brave-browser\t1.4.2\n"),
            );
        let backend = backend_for(DistroFamily::Debian, &fake);
        let plan = install_plan_for(DistroFamily::Debian);
        let target = target(DistroFamily::Debian);
        backend
            .install(InstallRequest::new(&plan, &target).elevated(true))
            .await
            .unwrap();
        fake.assert_called_with(&spec);
    }

    #[tokio::test]
    async fn install_executes_dnf_install_y() {
        let spec = dnf_spec("install", "brave-browser");
        let fake = FakeRunner::new()
            .strict()
            .respond(spec.clone(), CommandOutput::from_stdout(""))
            .respond(
                rpm_query_spec(&["brave-browser"]),
                CommandOutput::from_stdout("brave-browser\t1.4.2\n"),
            );
        let backend = backend_for(DistroFamily::Fedora, &fake);
        let plan = install_plan_for(DistroFamily::Fedora);
        let target = target(DistroFamily::Fedora);
        backend
            .install(InstallRequest::new(&plan, &target).elevated(true))
            .await
            .unwrap();
        fake.assert_called_with(&spec);
    }

    #[tokio::test]
    async fn install_executes_pacman_sync_noconfirm_and_reports_the_version() {
        let spec = pacman_spec("--sync", "brave-browser");
        let fake = FakeRunner::new()
            .strict()
            .respond(spec.clone(), CommandOutput::from_stdout(""))
            .respond(
                pacman_query_spec(&["brave-browser"]),
                CommandOutput::from_stdout("brave-browser 1:1.4.2-1\n"),
            );
        let backend = backend_for(DistroFamily::Arch, &fake);
        let plan = install_plan_for(DistroFamily::Arch);
        let target = target(DistroFamily::Arch);
        let outcome = backend
            .install(InstallRequest::new(&plan, &target).elevated(true))
            .await
            .unwrap();
        assert_eq!(outcome.version.as_deref(), Some("1:1.4.2-1"));
        fake.assert_called_with(&spec);
        fake.assert_no_unmatched_calls();
    }

    #[tokio::test]
    async fn install_executes_apk_add_with_no_suppression_and_reports_no_version() {
        let spec = apk_spec("add", "brave-browser");
        let fake = FakeRunner::new()
            .strict()
            .respond(spec.clone(), CommandOutput::from_stdout(""))
            .respond(
                apk_query_spec(&["brave-browser"]),
                CommandOutput::from_stdout("brave-browser\n"),
            );
        let backend = backend_for(DistroFamily::Alpine, &fake);
        let plan = install_plan_for(DistroFamily::Alpine);
        let target = target(DistroFamily::Alpine);
        let outcome = backend
            .install(InstallRequest::new(&plan, &target).elevated(true))
            .await
            .unwrap();
        assert_eq!(
            outcome.version, None,
            "apk's listing reports no version (see module docs)"
        );
        fake.assert_called_with(&spec);
        fake.assert_no_unmatched_calls();
    }

    #[test]
    fn install_apt_spec_carries_the_noninteractive_debian_frontend() {
        let spec = mutating_spec(DistroExecutor::Apt, "install", "bash");
        assert_eq!(spec.program, "apt-get");
        assert_eq!(spec.args, ["install", "-y", "bash"]);
        assert!(
            spec.env
                .contains(&("DEBIAN_FRONTEND".to_owned(), "noninteractive".to_owned())),
            "apt needs the debconf frontend silenced: {spec:?}"
        );
    }

    #[test]
    fn install_dnf_spec_adds_no_environment() {
        let spec = mutating_spec(DistroExecutor::Dnf, "install", "bash");
        assert_eq!(spec.program, "dnf");
        assert_eq!(spec.args, ["install", "-y", "bash"]);
        assert!(spec.env.is_empty(), "-y is dnf's own suppression: {spec:?}");
    }

    #[test]
    fn install_pacman_spec_takes_noconfirm_and_no_environment() {
        let spec = mutating_spec(DistroExecutor::Pacman, "--sync", "bash");
        assert_eq!(spec.program, "pacman");
        assert_eq!(spec.args, ["--sync", "--noconfirm", "bash"]);
        assert!(
            spec.env.is_empty(),
            "pacman needs no env; --noconfirm is its whole suppression: {spec:?}"
        );
    }

    #[test]
    fn install_apk_spec_adds_no_flag_and_no_environment() {
        let spec = mutating_spec(DistroExecutor::Apk, "add", "bash");
        assert_eq!(spec.program, "apk");
        assert_eq!(spec.args, ["add", "bash"]);
        assert!(
            spec.env.is_empty(),
            "apk is noninteractive by default; any flag here would error: {spec:?}"
        );
    }

    #[test]
    fn pacman_and_apk_specs_never_carry_the_wrong_suppression_flags() {
        let specs = [
            mutating_spec(DistroExecutor::Pacman, "--sync", "bash"),
            mutating_spec(DistroExecutor::Pacman, "--remove", "bash"),
            mutating_spec(DistroExecutor::Apk, "add", "bash"),
            mutating_spec(DistroExecutor::Apk, "del", "bash"),
        ];
        for spec in specs {
            assert!(
                !spec.args.iter().any(|arg| arg == "-y"),
                "pacman's -y is --refresh and apk has no -y at all: {spec:?}"
            );
            assert!(
                !spec.args.iter().any(|arg| arg == "--refresh"),
                "the database sync belongs to the update verb, never install: {spec:?}"
            );
            assert!(
                !spec.args.iter().any(|arg| arg == "--noconfirm") || spec.program == "pacman",
                "--noconfirm is pacman's flag alone: {spec:?}"
            );
        }
    }

    #[test]
    fn plan_argv_stays_canonical_while_execution_layers_the_runtime_flags() {
        // The plan's argv is A1's canonical family spelling (apt, verb,
        // package) — the scriptable program and -y/env are execution-time
        // ergonomics this backend adds, never plan semantics.
        let plan = install_plan_for(DistroFamily::Debian);
        assert_eq!(plan.operation.argv(), ["apt", "install", "brave-browser"]);
        let executed = mutating_spec(DistroExecutor::Apt, "install", "brave-browser");
        assert_eq!(executed.program, "apt-get");
        assert_eq!(executed.args, ["install", "-y", "brave-browser"]);
    }

    #[test]
    fn pacman_and_apk_plan_argv_stay_canonical_while_execution_layers_suppression() {
        let pacman = install_plan_for(DistroFamily::Arch);
        assert_eq!(
            pacman.operation.argv(),
            ["pacman", "--sync", "brave-browser"]
        );
        let executed = mutating_spec(
            DistroExecutor::Pacman,
            PackageManager::Pacman.install_verb(),
            "brave-browser",
        );
        assert_eq!(executed.program, "pacman");
        assert_eq!(executed.args, ["--sync", "--noconfirm", "brave-browser"]);

        let apk = install_plan_for(DistroFamily::Alpine);
        assert_eq!(apk.operation.argv(), ["apk", "add", "brave-browser"]);
        let executed = mutating_spec(
            DistroExecutor::Apk,
            PackageManager::Apk.install_verb(),
            "brave-browser",
        );
        assert_eq!(executed.program, "apk");
        assert_eq!(executed.args, ["add", "brave-browser"]);
    }

    #[tokio::test]
    async fn install_reports_the_version_from_the_post_install_query() {
        let fake = FakeRunner::new()
            .strict()
            .respond(
                apt_get_spec("install", "brave-browser"),
                CommandOutput::from_stdout(""),
            )
            .respond(
                dpkg_query_spec(&["brave-browser"]),
                CommandOutput::from_stdout("ii brave-browser\t1.4.2-1\n"),
            );
        let backend = backend_for(DistroFamily::Debian, &fake);
        let plan = install_plan_for(DistroFamily::Debian);
        let target = target(DistroFamily::Debian);
        let outcome = backend
            .install(InstallRequest::new(&plan, &target).elevated(true))
            .await
            .unwrap();
        assert_eq!(outcome.version.as_deref(), Some("1.4.2-1"));
        assert!(
            outcome.detail.contains("brave-browser"),
            "{}",
            outcome.detail
        );
    }

    #[tokio::test]
    async fn install_degrades_to_no_version_when_the_post_install_query_fails() {
        let fake = FakeRunner::new()
            .strict()
            .respond(
                apt_get_spec("install", "brave-browser"),
                CommandOutput::from_stdout(""),
            )
            .respond(dpkg_query_spec(&["brave-browser"]), apt_lock_output());
        let backend = backend_for(DistroFamily::Debian, &fake);
        let plan = install_plan_for(DistroFamily::Debian);
        let target = target(DistroFamily::Debian);
        let outcome = backend
            .install(InstallRequest::new(&plan, &target).elevated(true))
            .await
            .unwrap();
        assert_eq!(outcome.version, None, "the install itself succeeded");
    }

    #[tokio::test]
    async fn install_maps_an_apt_get_failure_to_command_error_with_the_stderr_tail() {
        // Real apt-get lock-held shape: exit 100 with the E: line — the
        // lock diagnosis must travel with the error.
        let fake = FakeRunner::new()
            .strict()
            .respond(apt_get_spec("install", "brave-browser"), apt_lock_output());
        let backend = backend_for(DistroFamily::Debian, &fake);
        let plan = install_plan_for(DistroFamily::Debian);
        let target = target(DistroFamily::Debian);
        let error = backend
            .install(InstallRequest::new(&plan, &target).elevated(true))
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
            error.to_string().contains("Could not get lock"),
            "stderr tail must travel with the error: {error}"
        );
    }

    #[tokio::test]
    async fn install_rejects_non_distro_operations() {
        let fake = FakeRunner::new().strict();
        let backend = backend_for(DistroFamily::Debian, &fake);
        let plan = manual_install_plan(
            DistroFamily::Debian,
            Operation::FlatpakInstall {
                remote: "flathub".to_owned(),
                app_ref: "app/com.brave.Browser/x86_64/stable".to_owned(),
                installation: crate::plan::FlatpakInstallation::User,
            },
        );
        let target = target(DistroFamily::Debian);
        let error = backend
            .install(InstallRequest::new(&plan, &target))
            .await
            .unwrap_err();
        assert!(
            matches!(error, Error::Command(toride_runner::Error::Other(_))),
            "{error:?}"
        );
        assert!(fake.calls().is_empty());
    }

    #[tokio::test]
    async fn install_rejects_a_manager_foreign_to_the_backends_family() {
        // A dnf/pacman/apk operation routed to the Debian backend is a
        // misroute, not something to execute against the wrong distro.
        for manager in [
            PackageManager::Dnf,
            PackageManager::Pacman,
            PackageManager::Apk,
        ] {
            let fake = FakeRunner::new().strict();
            let backend = backend_for(DistroFamily::Debian, &fake);
            let plan = manual_install_plan(
                DistroFamily::Debian,
                Operation::DistroInstall {
                    manager,
                    package: "brave-browser".to_owned(),
                },
            );
            let target = target(DistroFamily::Debian);
            let error = backend
                .install(InstallRequest::new(&plan, &target))
                .await
                .unwrap_err();
            assert!(
                matches!(error, Error::Command(toride_runner::Error::Other(_))),
                "{error:?}"
            );
            assert!(
                error
                    .to_string()
                    .contains("does not match this backend's family"),
                "the refusal must name the misroute: {error}"
            );
            assert!(fake.calls().is_empty(), "no manager command may run");
        }
    }

    #[test]
    fn install_spec_pins_the_mutating_argv_exactly() {
        let apt = mutating_spec(DistroExecutor::Apt, "install", "bash");
        assert_eq!(apt.program, "apt-get");
        assert_eq!(apt.args, ["install", "-y", "bash"]);
        assert!(apt.stdin_null, "captured commands never inherit stdin");
        let dnf = mutating_spec(DistroExecutor::Dnf, "install", "bash");
        assert_eq!(dnf.program, "dnf");
        assert_eq!(dnf.args, ["install", "-y", "bash"]);
        let pacman = mutating_spec(DistroExecutor::Pacman, "--sync", "bash");
        assert_eq!(pacman.program, "pacman");
        assert_eq!(pacman.args, ["--sync", "--noconfirm", "bash"]);
        assert!(pacman.stdin_null);
        let apk = mutating_spec(DistroExecutor::Apk, "add", "bash");
        assert_eq!(apk.program, "apk");
        assert_eq!(apk.args, ["add", "bash"]);
        assert!(apk.stdin_null);
    }

    // --- uninstall ----------------------------------------------------------------

    #[tokio::test]
    async fn uninstall_refuses_dry_run_plans_without_touching_the_runner() {
        let fake = FakeRunner::new().strict();
        let backend = backend_for(DistroFamily::Debian, &fake);
        let plan = uninstall_plan_for(DistroFamily::Debian).dry_run(true);
        let target = target(DistroFamily::Debian);
        let error = backend
            .uninstall(UninstallRequest::new(&plan, &target).elevated(true))
            .await
            .unwrap_err();
        assert!(matches!(error, Error::DryRun { .. }), "{error:?}");
        assert!(fake.calls().is_empty(), "no manager command may run");
    }

    #[tokio::test]
    async fn uninstall_refuses_elevation_requiring_plans_without_a_grant() {
        let fake = FakeRunner::new().strict();
        let backend = backend_for(DistroFamily::Fedora, &fake);
        let plan = uninstall_plan_for(DistroFamily::Fedora);
        assert!(plan.requires_elevation);
        let target = target(DistroFamily::Fedora);
        let error = backend
            .uninstall(UninstallRequest::new(&plan, &target))
            .await
            .unwrap_err();
        assert!(
            matches!(error, Error::ElevationRequired { .. }),
            "{error:?}"
        );
        assert!(fake.calls().is_empty(), "no manager command may run");
    }

    #[tokio::test]
    async fn uninstall_executes_apt_get_remove_y() {
        let spec = apt_get_spec("remove", "brave-browser");
        let fake = FakeRunner::new()
            .strict()
            .respond(spec.clone(), CommandOutput::from_stdout(""));
        let backend = backend_for(DistroFamily::Debian, &fake);
        let plan = uninstall_plan_for(DistroFamily::Debian);
        let target = target(DistroFamily::Debian);
        backend
            .uninstall(UninstallRequest::new(&plan, &target).elevated(true))
            .await
            .unwrap();
        fake.assert_called_with(&spec);
    }

    #[tokio::test]
    async fn uninstall_executes_dnf_remove_y() {
        let spec = dnf_spec("remove", "brave-browser");
        let fake = FakeRunner::new()
            .strict()
            .respond(spec.clone(), CommandOutput::from_stdout(""));
        let backend = backend_for(DistroFamily::Fedora, &fake);
        let plan = uninstall_plan_for(DistroFamily::Fedora);
        let target = target(DistroFamily::Fedora);
        backend
            .uninstall(UninstallRequest::new(&plan, &target).elevated(true))
            .await
            .unwrap();
        fake.assert_called_with(&spec);
    }

    #[tokio::test]
    async fn uninstall_maps_manager_failures_to_command_error() {
        // Deliberate divergence from flatpak: a failed uninstall of a
        // missing package is NOT reclassified as success — apt-get remove
        // is natively lenient, dnf's not-found wording varies dnf4/dnf5,
        // and the facade (A6) post-verifies instead.
        let fake = FakeRunner::new().strict().respond(
            dnf_spec("remove", "brave-browser"),
            CommandOutput::from_stderr("Error: Unable to find a match: brave-browser\n", 1),
        );
        let backend = backend_for(DistroFamily::Fedora, &fake);
        let plan = uninstall_plan_for(DistroFamily::Fedora);
        let target = target(DistroFamily::Fedora);
        let error = backend
            .uninstall(UninstallRequest::new(&plan, &target).elevated(true))
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
    async fn uninstall_executes_pacman_remove_noconfirm() {
        let spec = pacman_spec("--remove", "brave-browser");
        let fake = FakeRunner::new()
            .strict()
            .respond(spec.clone(), CommandOutput::from_stdout(""));
        let backend = backend_for(DistroFamily::Arch, &fake);
        let plan = uninstall_plan_for(DistroFamily::Arch);
        let target = target(DistroFamily::Arch);
        backend
            .uninstall(UninstallRequest::new(&plan, &target).elevated(true))
            .await
            .unwrap();
        fake.assert_called_with(&spec);
        fake.assert_no_unmatched_calls();
    }

    #[tokio::test]
    async fn uninstall_executes_apk_del() {
        let spec = apk_spec("del", "brave-browser");
        let fake = FakeRunner::new()
            .strict()
            .respond(spec.clone(), CommandOutput::from_stdout(""));
        let backend = backend_for(DistroFamily::Alpine, &fake);
        let plan = uninstall_plan_for(DistroFamily::Alpine);
        let target = target(DistroFamily::Alpine);
        backend
            .uninstall(UninstallRequest::new(&plan, &target).elevated(true))
            .await
            .unwrap();
        fake.assert_called_with(&spec);
        fake.assert_no_unmatched_calls();
    }

    // --- query argv -----------------------------------------------------------------

    #[test]
    fn dpkg_query_spec_pins_the_show_and_showformat_argv() {
        let spec = dpkg_query_spec(&["bash", "coreutils"]);
        assert_eq!(spec.program, "dpkg-query");
        assert_eq!(
            spec.args,
            [
                "--show",
                // The format escapes travel literally — the same bytes the
                // shell passes in '--showformat=${Package}\t${Version}\n'
                // (plus the status-abbrev prefix; dpkg-query(1)).
                "--showformat=${db:Status-Abbrev}${Package}\\t${Version}\\n",
                "bash",
                "coreutils",
            ]
        );
        assert!(spec.stdin_null);
    }

    #[test]
    fn rpm_query_spec_pins_the_query_and_queryformat_argv() {
        let spec = rpm_query_spec(&["bash"]);
        assert_eq!(spec.program, "rpm");
        assert_eq!(
            spec.args,
            [
                "--query",
                "--queryformat",
                "%{NAME}\\t%{VERSION}\\n",
                "bash",
            ]
        );
        assert!(spec.stdin_null);
    }

    #[test]
    fn all_listing_specs_add_no_dpkg_operands_and_rpm_all() {
        // dpkg-query with no operand lists the whole database; rpm needs
        // --all there because a bare query would read names from stdin.
        let dpkg = dpkg_query_spec(&[]);
        assert_eq!(
            dpkg.args,
            [
                "--show",
                "--showformat=${db:Status-Abbrev}${Package}\\t${Version}\\n"
            ]
        );
        let rpm = rpm_query_spec(&[]);
        assert_eq!(
            rpm.args,
            [
                "--query",
                "--all",
                "--queryformat",
                "%{NAME}\\t%{VERSION}\\n"
            ]
        );
        // A bare pacman --query lists every installed package, and a bare
        // apk list matches everything installed — no operand needed.
        let pacman = pacman_query_spec(&[]);
        assert_eq!(pacman.args, ["--query"]);
        let apk = apk_query_spec(&[]);
        assert_eq!(apk.args, ["list", "--installed"]);
    }

    #[test]
    fn pacman_query_spec_pins_the_query_argv_and_operands() {
        let spec = pacman_query_spec(&["bash", "pacman"]);
        assert_eq!(spec.program, "pacman");
        assert_eq!(spec.args, ["--query", "bash", "pacman"]);
        assert!(spec.stdin_null);
    }

    #[test]
    fn apk_query_spec_pins_the_list_installed_argv_and_patterns() {
        let spec = apk_query_spec(&["bash", "musl"]);
        assert_eq!(spec.program, "apk");
        assert_eq!(spec.args, ["list", "--installed", "bash", "musl"]);
        assert!(spec.stdin_null);
    }

    #[test]
    fn every_query_spec_pins_the_c_locale() {
        // dpkg-query, rpm, and pacman translate their stderr (pacman's
        // German po renders the not-found line as `Paket »…« wurde nicht
        // gefunden`), so the not-found markers only match C-locale output.
        let specs = [
            dpkg_query_spec(&["bash"]),
            dpkg_query_spec(&[]),
            rpm_query_spec(&["bash"]),
            rpm_query_spec(&[]),
            pacman_query_spec(&["bash"]),
            pacman_query_spec(&[]),
            apk_query_spec(&["bash"]),
            apk_query_spec(&[]),
        ];
        for spec in specs {
            assert!(
                spec.env.contains(&("LC_ALL".to_owned(), "C".to_owned())),
                "an inherited host locale would translate the markers away: {spec:?}"
            );
        }
    }

    #[test]
    fn mutating_specs_leave_the_host_locale_alone() {
        // Only classified stderr needs the C locale: a mutating command's
        // failure wording travels verbatim to the user, in their language.
        for executor in [
            DistroExecutor::Apt,
            DistroExecutor::Dnf,
            DistroExecutor::Pacman,
            DistroExecutor::Apk,
        ] {
            let spec = mutating_spec(executor, "install", "bash");
            assert!(!spec.env.iter().any(|(key, _)| key == "LC_ALL"), "{spec:?}");
        }
    }

    // --- query output parsing ---------------------------------------------------------

    #[test]
    fn parse_query_output_reads_rows_from_the_dpkg_fixture() {
        // Captured from this host's dpkg-query with the exact argv above.
        let apps = parse_query_output(DistroExecutor::Apt, &dpkg_fixture_output()).unwrap();
        assert_eq!(apps.len(), 7, "{apps:?}");
        assert_eq!(
            apps[0],
            InstalledApp {
                id: "apt".to_owned(),
                version: Some("3.0.3".to_owned()),
            }
        );
        assert_eq!(apps[1].id, "bash");
    }

    #[test]
    fn parse_query_output_reads_rows_from_the_pacman_fixture() {
        // The documented `pacman --query` shape: one `name version` row per
        // installed package, space-separated (src/pacman/query.c).
        let apps = parse_query_output(DistroExecutor::Pacman, &pacman_fixture_output()).unwrap();
        assert_eq!(apps.len(), 4, "{apps:?}");
        assert_eq!(
            apps[0],
            InstalledApp {
                id: "bash".to_owned(),
                version: Some("5.2.037-1".to_owned()),
            }
        );
        assert_eq!(apps[1].id, "brave-browser");
    }

    #[test]
    fn parse_query_output_keeps_epoch_pacman_versions_verbatim() {
        let apps = parse_query_output(DistroExecutor::Pacman, &pacman_fixture_output()).unwrap();
        let brave = apps.iter().find(|app| app.id == "brave-browser").unwrap();
        assert_eq!(brave.version.as_deref(), Some("1:1.4.2-1"));
    }

    #[test]
    fn parse_query_output_reads_bare_names_from_the_apk_fixture() {
        // `apk list --installed` at apk's default verbosity prints one bare
        // package name per line and never a version (src/app_list.c).
        let apps = parse_query_output(DistroExecutor::Apk, &apk_fixture_output()).unwrap();
        assert_eq!(apps.len(), 4, "{apps:?}");
        assert_eq!(
            apps[0],
            InstalledApp {
                id: "alpine-baselayout".to_owned(),
                version: None,
            }
        );
        assert!(apps.iter().all(|app| app.version.is_none()), "{apps:?}");
    }

    #[test]
    fn parse_query_output_skips_malformed_pacman_and_apk_rows() {
        let pacman =
            parse_query_output(DistroExecutor::Pacman, "bash 5.2\nnot-a-query-row\n").unwrap();
        assert_eq!(pacman.len(), 1, "{pacman:?}");
        assert_eq!(pacman[0].id, "bash");
        let apk = parse_query_output(DistroExecutor::Apk, "bash\nbash 5.2\nmusl\n").unwrap();
        assert_eq!(apk.len(), 2, "{apk:?}");
        assert!(apk.iter().all(|app| app.version.is_none()), "{apk:?}");
    }

    #[test]
    fn parse_query_output_keeps_epoch_versions_verbatim() {
        let apps = parse_query_output(DistroExecutor::Apt, &dpkg_fixture_output()).unwrap();
        let bind9 = apps.iter().find(|app| app.id == "bind9-dnsutils").unwrap();
        assert_eq!(bind9.version.as_deref(), Some("1:9.20.23-1~deb13u1"));
    }

    #[test]
    fn parse_query_output_skips_rows_in_non_installed_dpkg_states() {
        // `rc ` rows (removed, config files left) are well-formed but not
        // installed — dropped without failing the document.
        let document = "ii bash\t5.2.37-2+b9\nrc removed-pkg\t1.0-1\n";
        let apps = parse_query_output(DistroExecutor::Apt, document).unwrap();
        assert_eq!(apps.len(), 1, "{apps:?}");
        assert_eq!(apps[0].id, "bash");
    }

    #[test]
    fn parse_query_output_returns_none_version_for_an_empty_version_cell() {
        let apps = parse_query_output(DistroExecutor::Apt, "ii odd\t\n").unwrap();
        assert_eq!(
            apps[0],
            InstalledApp {
                id: "odd".to_owned(),
                version: None,
            }
        );
    }

    #[test]
    fn parse_query_output_reads_rows_from_the_rpm_fixture() {
        let apps = parse_query_output(DistroExecutor::Dnf, &rpm_fixture_output()).unwrap();
        assert_eq!(apps.len(), 3, "{apps:?}");
        assert_eq!(
            apps[0],
            InstalledApp {
                id: "firefox".to_owned(),
                version: Some("141.0.2".to_owned()),
            }
        );
    }

    #[test]
    fn parse_query_output_skips_malformed_rows_without_failing_the_listing() {
        let document = "bash\t5.2\nno tab here\n\t1.0\nbash\t5.2\n";
        let apps = parse_query_output(DistroExecutor::Dnf, document).unwrap();
        assert_eq!(apps.len(), 2, "{apps:?}");
    }

    #[test]
    fn parse_query_output_returns_an_empty_listing_for_empty_output() {
        for executor in [DistroExecutor::Apt, DistroExecutor::Dnf] {
            assert!(parse_query_output(executor, "").unwrap().is_empty());
            assert!(parse_query_output(executor, "  \n\n").unwrap().is_empty());
        }
    }

    #[test]
    fn parse_query_output_errors_when_nothing_in_a_non_empty_document_parses() {
        // Every row malformed means the format string no longer matches
        // the program's output shape — that must not read as "nothing
        // installed".
        let error = parse_query_output(DistroExecutor::Apt, "totally garbage\nnot a listing\n")
            .unwrap_err();
        assert!(
            matches!(error, Error::Command(toride_runner::Error::OutputParse(_))),
            "{error:?}"
        );
    }

    #[test]
    fn parse_query_output_accepts_a_document_of_only_non_installed_states() {
        // Well-formed but all filtered: legitimately empty, not an error.
        let apps = parse_query_output(DistroExecutor::Apt, "rc one\t1.0\nrc two\t2.0\n").unwrap();
        assert!(apps.is_empty());
    }

    // --- not-found classification -------------------------------------------------------

    #[test]
    fn stderr_all_not_found_matches_each_query_programs_markers() {
        assert!(stderr_all_not_found(
            DistroExecutor::Apt,
            "dpkg-query: no packages found matching ghost"
        ));
        assert!(stderr_all_not_found(
            DistroExecutor::Dnf,
            "package ghost is not installed"
        ));
        assert!(stderr_all_not_found(
            DistroExecutor::Pacman,
            "error: package 'ghost' was not found"
        ));
        assert!(
            !stderr_all_not_found(DistroExecutor::Apk, "anything at all"),
            "apk has no not-found stderr marker: its signal is an empty exit-0 answer"
        );
    }

    #[test]
    fn stderr_all_not_found_requires_every_line_to_carry_a_marker() {
        // A real error next to a not-found line must not classify.
        assert!(!stderr_all_not_found(
            DistroExecutor::Dnf,
            "package ghost is not installed\nerror: rpmdb: unable to open database"
        ));
    }

    #[test]
    fn stderr_all_not_found_requires_at_least_one_marker_line() {
        // Exit-1 with empty stderr is not the programs' not-found signal
        // (both always print their line) — that stays a real error.
        assert!(!stderr_all_not_found(DistroExecutor::Apt, ""));
        assert!(!stderr_all_not_found(DistroExecutor::Apt, "  \n"));
    }

    #[test]
    fn query_reports_not_found_gates_dpkg_on_exit_one_only() {
        let marker = CommandOutput::from_stderr("dpkg-query: no packages found matching ghost", 1);
        assert!(query_reports_not_found(DistroExecutor::Apt, &marker));
        // Exit 2 is dpkg-query's fatal class (bad usage, database errors).
        let fatal =
            CommandOutput::from_stderr("dpkg-query: error: parsing file '/var/lib/dpkg/status'", 2);
        assert!(!query_reports_not_found(DistroExecutor::Apt, &fatal));
    }

    #[test]
    fn query_reports_not_found_gates_pacman_on_exit_one_and_the_marker() {
        let marker = CommandOutput::from_stderr("error: package 'ghost' was not found", 1);
        assert!(query_reports_not_found(DistroExecutor::Pacman, &marker));
        // A not-found wording next to a real database failure must stay an
        // error (exit class alone is not pacman's signal).
        let fatal = CommandOutput::from_stderr(
            "error: package 'ghost' was not found\nerror: failed to initialize alpm library",
            1,
        );
        assert!(!query_reports_not_found(DistroExecutor::Pacman, &fatal));
    }

    #[test]
    fn query_reports_not_found_never_classifies_an_apk_failure() {
        // apk's list cannot fail on a no-match: an empty exit-0 answer is
        // its not-found signal, so every apk failure stays a real error.
        let failed = CommandOutput::from_stderr("ERROR: unable to open database", 1);
        assert!(!query_reports_not_found(DistroExecutor::Apk, &failed));
    }

    #[test]
    fn query_reports_not_found_accepts_any_nonzero_rpm_exit() {
        // rpm's exit code counts failed lookups, so two missing packages
        // exit 2 — the stderr markers discriminate, not the exact code.
        let two_missing = CommandOutput::new(
            String::new(),
            "package ghost is not installed\npackage other is not installed\n".to_owned(),
            Some(2),
        );
        assert!(query_reports_not_found(DistroExecutor::Dnf, &two_missing));
        // A signal kill (no exit code) never classifies.
        let signalled = CommandOutput::new(
            String::new(),
            "package ghost is not installed\n".to_owned(),
            None,
        );
        assert!(!query_reports_not_found(DistroExecutor::Dnf, &signalled));
    }

    // --- query dispatch through the seam ---------------------------------------------

    #[tokio::test]
    async fn installed_version_queries_dpkg_with_the_exact_argv() {
        let spec = dpkg_query_spec(&["bash"]);
        let fake = FakeRunner::new().strict().respond(
            spec.clone(),
            CommandOutput::from_stdout(dpkg_fixture_output()),
        );
        let backend = backend_for(DistroFamily::Debian, &fake);
        assert_eq!(
            backend.installed_version("bash").await.unwrap().as_deref(),
            Some("5.2.37-2+b9")
        );
        fake.assert_called_with(&spec);
    }

    #[tokio::test]
    async fn installed_version_queries_rpm_with_the_exact_argv() {
        let spec = rpm_query_spec(&["firefox"]);
        let fake = FakeRunner::new().strict().respond(
            spec.clone(),
            CommandOutput::from_stdout(rpm_fixture_output()),
        );
        let backend = backend_for(DistroFamily::Fedora, &fake);
        assert_eq!(
            backend
                .installed_version("firefox")
                .await
                .unwrap()
                .as_deref(),
            Some("141.0.2")
        );
        fake.assert_called_with(&spec);
    }

    #[tokio::test]
    async fn installed_version_maps_dpkg_no_packages_found_to_none() {
        let fake = FakeRunner::new().strict().respond(
            dpkg_query_spec(&["ghost"]),
            CommandOutput::from_stderr("dpkg-query: no packages found matching ghost", 1),
        );
        let backend = backend_for(DistroFamily::Debian, &fake);
        assert_eq!(backend.installed_version("ghost").await.unwrap(), None);
    }

    #[tokio::test]
    async fn installed_version_maps_rpm_not_installed_to_none() {
        let fake = FakeRunner::new().strict().respond(
            rpm_query_spec(&["ghost"]),
            CommandOutput::from_stderr("package ghost is not installed", 1),
        );
        let backend = backend_for(DistroFamily::Fedora, &fake);
        assert_eq!(backend.installed_version("ghost").await.unwrap(), None);
    }

    #[tokio::test]
    async fn installed_version_queries_pacman_with_the_exact_argv() {
        let spec = pacman_query_spec(&["bash"]);
        let fake = FakeRunner::new().strict().respond(
            spec.clone(),
            CommandOutput::from_stdout(pacman_fixture_output()),
        );
        let backend = backend_for(DistroFamily::Arch, &fake);
        assert_eq!(
            backend.installed_version("bash").await.unwrap().as_deref(),
            Some("5.2.037-1")
        );
        fake.assert_called_with(&spec);
    }

    #[tokio::test]
    async fn installed_version_maps_pacman_not_found_to_none() {
        let fake = FakeRunner::new().strict().respond(
            pacman_query_spec(&["ghost"]),
            CommandOutput::from_stderr("error: package 'ghost' was not found", 1),
        );
        let backend = backend_for(DistroFamily::Arch, &fake);
        assert_eq!(backend.installed_version("ghost").await.unwrap(), None);
    }

    #[tokio::test]
    async fn installed_version_queries_apk_with_the_exact_argv_and_reports_no_version() {
        let spec = apk_query_spec(&["bash"]);
        let fake = FakeRunner::new().strict().respond(
            spec.clone(),
            CommandOutput::from_stdout(apk_fixture_output()),
        );
        let backend = backend_for(DistroFamily::Alpine, &fake);
        assert_eq!(
            backend.installed_version("bash").await.unwrap(),
            None,
            "present without a version, not absent"
        );
        fake.assert_called_with(&spec);
    }

    #[tokio::test]
    async fn installed_version_maps_an_empty_apk_answer_to_none() {
        // apk's not-found signal: an empty exit-0 listing, never an error.
        let fake = FakeRunner::new()
            .strict()
            .respond(apk_query_spec(&["ghost"]), CommandOutput::from_stdout(""));
        let backend = backend_for(DistroFamily::Alpine, &fake);
        assert_eq!(backend.installed_version("ghost").await.unwrap(), None);
    }

    #[tokio::test]
    async fn installed_version_maps_an_apk_failure_to_command_error() {
        let fake = FakeRunner::new().strict().respond(
            apk_query_spec(&["bash"]),
            CommandOutput::from_stderr("ERROR: unable to open database", 1),
        );
        let backend = backend_for(DistroFamily::Alpine, &fake);
        let error = backend.installed_version("bash").await.unwrap_err();
        assert!(
            matches!(
                error,
                Error::Command(toride_runner::Error::CommandFailed { .. })
            ),
            "{error:?}"
        );
    }

    #[tokio::test]
    async fn installed_version_returns_none_for_a_removed_but_configured_package() {
        // The `rc ` row parses but is not installed state — no version.
        let fake = FakeRunner::new().strict().respond(
            dpkg_query_spec(&["removed-pkg"]),
            CommandOutput::from_stdout("rc removed-pkg\t1.0-1\n"),
        );
        let backend = backend_for(DistroFamily::Debian, &fake);
        assert_eq!(
            backend.installed_version("removed-pkg").await.unwrap(),
            None
        );
    }

    #[tokio::test]
    async fn installed_version_scopes_to_the_exact_package_name() {
        // dpkg-query operands are glob-capable; the answer is exact-matched.
        let fake = FakeRunner::new().strict().respond(
            dpkg_query_spec(&["bash"]),
            CommandOutput::from_stdout("ii bash\t5.2\nii bash-completion\t1:2.14\n"),
        );
        let backend = backend_for(DistroFamily::Debian, &fake);
        assert_eq!(
            backend.installed_version("bash").await.unwrap().as_deref(),
            Some("5.2")
        );
    }

    #[tokio::test]
    async fn installed_version_maps_fatal_query_failures_to_command_error() {
        // dpkg-query exit 2 (fatal) even with a marker-ish stderr stays an
        // error; so does a spawn failure.
        let fatal = CommandOutput::new(
            String::new(),
            "dpkg-query: no packages found matching ghost".to_owned(),
            Some(2),
        );
        let fake = FakeRunner::new()
            .strict()
            .respond(dpkg_query_spec(&["ghost"]), fatal);
        let backend = backend_for(DistroFamily::Debian, &fake);
        let error = backend.installed_version("ghost").await.unwrap_err();
        assert!(
            matches!(
                error,
                Error::Command(toride_runner::Error::CommandFailed { .. })
            ),
            "{error:?}"
        );
    }

    #[tokio::test]
    async fn installed_version_maps_spawn_failures_to_command_error() {
        let fake = FakeRunner::new().strict().respond_err(
            dpkg_query_spec(&["bash"]),
            toride_runner::Error::BinaryNotFound("dpkg-query".to_owned()),
        );
        let backend = backend_for(DistroFamily::Debian, &fake);
        let error = backend.installed_version("bash").await.unwrap_err();
        assert!(matches!(error, Error::Command(_)), "{error:?}");
    }

    #[tokio::test]
    async fn installed_version_maps_unparseable_output_to_command_error() {
        let fake = FakeRunner::new().strict().respond(
            dpkg_query_spec(&["bash"]),
            CommandOutput::from_stdout("garbage without tabs\n"),
        );
        let backend = backend_for(DistroFamily::Debian, &fake);
        let error = backend.installed_version("bash").await.unwrap_err();
        assert!(
            matches!(error, Error::Command(toride_runner::Error::OutputParse(_))),
            "{error:?}"
        );
    }

    // --- list_installed + status -------------------------------------------------------

    #[tokio::test]
    async fn list_installed_runs_the_operand_free_dpkg_query_for_all() {
        let spec = dpkg_query_spec(&[]);
        let fake = FakeRunner::new().strict().respond(
            spec.clone(),
            CommandOutput::from_stdout(dpkg_fixture_output()),
        );
        let backend = backend_for(DistroFamily::Debian, &fake);
        let apps = backend.list_installed(ListQuery::all()).await.unwrap();
        assert_eq!(apps.len(), 7, "{apps:?}");
        fake.assert_called_with(&spec);
    }

    #[tokio::test]
    async fn list_installed_runs_rpm_query_all_for_the_whole_database() {
        let spec = rpm_query_spec(&[]);
        let fake = FakeRunner::new().strict().respond(
            spec.clone(),
            CommandOutput::from_stdout(rpm_fixture_output()),
        );
        let backend = backend_for(DistroFamily::Fedora, &fake);
        let apps = backend.list_installed(ListQuery::all()).await.unwrap();
        assert_eq!(apps.len(), 3, "{apps:?}");
        fake.assert_called_with(&spec);
    }

    #[tokio::test]
    async fn list_installed_runs_the_operand_free_pacman_query_for_all() {
        let spec = pacman_query_spec(&[]);
        let fake = FakeRunner::new().strict().respond(
            spec.clone(),
            CommandOutput::from_stdout(pacman_fixture_output()),
        );
        let backend = backend_for(DistroFamily::Arch, &fake);
        let apps = backend.list_installed(ListQuery::all()).await.unwrap();
        assert_eq!(apps.len(), 4, "{apps:?}");
        fake.assert_called_with(&spec);
    }

    #[tokio::test]
    async fn list_installed_runs_the_apk_listing_for_all() {
        let spec = apk_query_spec(&[]);
        let fake = FakeRunner::new().strict().respond(
            spec.clone(),
            CommandOutput::from_stdout(apk_fixture_output()),
        );
        let backend = backend_for(DistroFamily::Alpine, &fake);
        let apps = backend.list_installed(ListQuery::all()).await.unwrap();
        assert_eq!(apps.len(), 4, "{apps:?}");
        fake.assert_called_with(&spec);
    }

    #[tokio::test]
    async fn list_installed_passes_the_queried_ids_as_operands_and_filters_exactly() {
        // The glob-capable operands return both rows; the exact filter
        // keeps only the queried id.
        let fake = FakeRunner::new().strict().respond(
            dpkg_query_spec(&["bash"]),
            CommandOutput::from_stdout("ii bash\t5.2\nii bash-completion\t1:2.14\n"),
        );
        let backend = backend_for(DistroFamily::Debian, &fake);
        let apps = backend.list_installed(ListQuery::id("bash")).await.unwrap();
        assert_eq!(apps.len(), 1, "{apps:?}");
        assert_eq!(apps[0].id, "bash");
    }

    #[tokio::test]
    async fn list_installed_keeps_partial_results_when_some_ids_are_missing() {
        // dpkg-query exits 1 with the not-found line on stderr while the
        // found packages still land on stdout — both survive as the answer.
        let partial = CommandOutput::new(
            "ii bash\t5.2.37-2+b9\n".to_owned(),
            "dpkg-query: no packages found matching ghost".to_owned(),
            Some(1),
        );
        let fake = FakeRunner::new()
            .strict()
            .respond(dpkg_query_spec(&["bash", "ghost"]), partial);
        let backend = backend_for(DistroFamily::Debian, &fake);
        let apps = backend
            .list_installed(ListQuery {
                ids: vec!["bash".to_owned(), "ghost".to_owned()],
            })
            .await
            .unwrap();
        assert_eq!(apps.len(), 1, "{apps:?}");
        assert_eq!(apps[0].id, "bash");
    }

    #[tokio::test]
    async fn list_installed_maps_the_all_missing_answer_to_an_empty_listing() {
        let fake = FakeRunner::new().strict().respond(
            rpm_query_spec(&["ghost", "other"]),
            CommandOutput::from_stderr(
                "package ghost is not installed\npackage other is not installed\n",
                2,
            ),
        );
        let backend = backend_for(DistroFamily::Fedora, &fake);
        let apps = backend
            .list_installed(ListQuery {
                ids: vec!["ghost".to_owned(), "other".to_owned()],
            })
            .await
            .unwrap();
        assert!(apps.is_empty(), "{apps:?}");
    }

    #[tokio::test]
    async fn list_installed_maps_fatal_failures_to_command_error() {
        let fake = FakeRunner::new().strict().respond(
            dpkg_query_spec(&[]),
            CommandOutput::from_stderr("dpkg-query: error: read error", 2),
        );
        let backend = backend_for(DistroFamily::Debian, &fake);
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
    async fn status_derives_the_installed_version_from_the_single_package_query() {
        // No status override: the trait default rides list_installed,
        // which issues exactly one operand-scoped query.
        let spec = dpkg_query_spec(&["bash"]);
        let fake = FakeRunner::new().strict().respond(
            spec.clone(),
            CommandOutput::from_stdout(dpkg_fixture_output()),
        );
        let backend = backend_for(DistroFamily::Debian, &fake);
        let status = backend.status(StatusQuery::new("bash")).await.unwrap();
        assert_eq!(
            status,
            BackendStatus::Installed {
                version: Some("5.2.37-2+b9".to_owned())
            }
        );
        fake.assert_called_with(&spec);
    }

    #[tokio::test]
    async fn status_reports_not_installed_for_unknown_packages() {
        // The not-found exit is an answer, never an error.
        let fake = FakeRunner::new().strict().respond(
            dpkg_query_spec(&["ghost"]),
            CommandOutput::from_stderr("dpkg-query: no packages found matching ghost", 1),
        );
        let backend = backend_for(DistroFamily::Debian, &fake);
        let status = backend.status(StatusQuery::new("ghost")).await.unwrap();
        assert_eq!(status, BackendStatus::NotInstalled);
    }

    #[tokio::test]
    async fn status_reports_not_installed_for_removed_but_configured_packages() {
        let fake = FakeRunner::new().strict().respond(
            dpkg_query_spec(&["removed-pkg"]),
            CommandOutput::from_stdout("rc removed-pkg\t1.0-1\n"),
        );
        let backend = backend_for(DistroFamily::Debian, &fake);
        let status = backend
            .status(StatusQuery::new("removed-pkg"))
            .await
            .unwrap();
        assert_eq!(status, BackendStatus::NotInstalled);
    }

    #[tokio::test]
    async fn status_reports_pacman_installed_with_the_queried_version() {
        let spec = pacman_query_spec(&["firefox"]);
        let fake = FakeRunner::new().strict().respond(
            spec.clone(),
            CommandOutput::from_stdout("firefox 141.0.2-1\n"),
        );
        let backend = backend_for(DistroFamily::Arch, &fake);
        let status = backend.status(StatusQuery::new("firefox")).await.unwrap();
        assert_eq!(
            status,
            BackendStatus::Installed {
                version: Some("141.0.2-1".to_owned())
            }
        );
        fake.assert_called_with(&spec);
    }

    #[tokio::test]
    async fn status_reports_apk_installed_without_a_version_and_absent_for_no_match() {
        let fake = FakeRunner::new()
            .strict()
            .respond(
                apk_query_spec(&["bash"]),
                CommandOutput::from_stdout("bash\n"),
            )
            .respond(apk_query_spec(&["ghost"]), CommandOutput::from_stdout(""));
        let backend = backend_for(DistroFamily::Alpine, &fake);
        assert_eq!(
            backend.status(StatusQuery::new("bash")).await.unwrap(),
            BackendStatus::Installed { version: None }
        );
        assert_eq!(
            backend.status(StatusQuery::new("ghost")).await.unwrap(),
            BackendStatus::NotInstalled
        );
    }

    // --- identity, supports, detection ----------------------------------------------

    #[test]
    fn id_is_the_family_backend_id_and_supports_matching_linux_targets() {
        let backend = backend_for(DistroFamily::Debian, &FakeRunner::new().strict());
        assert_eq!(backend.id(), BackendId::Distro(DistroFamily::Debian));
        assert_eq!(backend.id().to_string(), "distro-debian");
        assert!(backend.supports(&target(DistroFamily::Debian)));
    }

    #[test]
    fn supports_matching_linux_targets_for_every_executable_family() {
        for family in [
            DistroFamily::Debian,
            DistroFamily::Ubuntu,
            DistroFamily::Fedora,
            DistroFamily::Arch,
            DistroFamily::Alpine,
        ] {
            let backend = backend_for(family, &FakeRunner::new().strict());
            assert!(
                backend.supports(&target(family)),
                "{family:?} executes and must vouch for its own targets"
            );
        }
        assert_eq!(
            backend_for(DistroFamily::Arch, &FakeRunner::new().strict())
                .id()
                .to_string(),
            "distro-arch"
        );
        assert_eq!(
            backend_for(DistroFamily::Alpine, &FakeRunner::new().strict())
                .id()
                .to_string(),
            "distro-alpine"
        );
    }

    #[test]
    fn supports_rejects_foreign_families_undetected_targets_and_other_oses() {
        let backend = backend_for(DistroFamily::Fedora, &FakeRunner::new().strict());
        assert!(!backend.supports(&target(DistroFamily::Debian)));
        assert!(!backend.supports(&Target::new(Os::Linux, Arch::X86_64)));
        assert!(!backend.supports(&Target::macos(Arch::X86_64)));
        // The Ubuntu backend is a distinct instance from the Debian one —
        // both execute apt, but each vouches for its own family only.
        let ubuntu = backend_for(DistroFamily::Ubuntu, &FakeRunner::new().strict());
        assert!(ubuntu.supports(&target(DistroFamily::Ubuntu)));
        assert!(!ubuntu.supports(&target(DistroFamily::Debian)));
        let arch = backend_for(DistroFamily::Arch, &FakeRunner::new().strict());
        assert!(!arch.supports(&target(DistroFamily::Alpine)));
    }

    // --- no-sudo invariant -------------------------------------------------------------

    #[test]
    fn no_constructed_spec_ever_contains_sudo() {
        // Toride never auto-elevates: neither the program nor any argument
        // of any spec this module builds may mention sudo (the elevation
        // contract is plan-requirement + caller grant, nothing executed).
        let specs = [
            mutating_spec(DistroExecutor::Apt, "install", "bash"),
            mutating_spec(DistroExecutor::Apt, "remove", "bash"),
            mutating_spec(DistroExecutor::Dnf, "install", "bash"),
            mutating_spec(DistroExecutor::Dnf, "remove", "bash"),
            mutating_spec(DistroExecutor::Pacman, "--sync", "bash"),
            mutating_spec(DistroExecutor::Pacman, "--remove", "bash"),
            mutating_spec(DistroExecutor::Apk, "add", "bash"),
            mutating_spec(DistroExecutor::Apk, "del", "bash"),
            dpkg_query_spec(&["bash"]),
            dpkg_query_spec(&[]),
            rpm_query_spec(&["bash"]),
            rpm_query_spec(&[]),
            pacman_query_spec(&["bash"]),
            pacman_query_spec(&[]),
            apk_query_spec(&["bash"]),
            apk_query_spec(&[]),
        ];
        for spec in specs {
            assert_ne!(spec.program, "sudo", "{spec:?}");
            assert!(
                spec.args.iter().all(|arg| !arg.contains("sudo")),
                "no argument may construct sudo: {spec:?}"
            );
        }
    }

    #[tokio::test]
    async fn no_dispatched_spec_ever_contains_sudo() {
        // Belt and braces: run a full install + query + uninstall flow and
        // inspect everything that actually reached the runner.
        let fake = FakeRunner::new()
            .strict()
            .respond(
                apt_get_spec("install", "brave-browser"),
                CommandOutput::from_stdout(""),
            )
            .respond(
                dpkg_query_spec(&["brave-browser"]),
                CommandOutput::from_stdout("ii brave-browser\t1.4.2\n"),
            )
            // The status probe issues the same query again after the
            // install's post-verify consumed the first exact response.
            .respond(
                dpkg_query_spec(&["brave-browser"]),
                CommandOutput::from_stdout("ii brave-browser\t1.4.2\n"),
            )
            .respond(
                apt_get_spec("remove", "brave-browser"),
                CommandOutput::from_stdout(""),
            );
        let backend = backend_for(DistroFamily::Debian, &fake);
        let target = target(DistroFamily::Debian);
        backend
            .install(
                InstallRequest::new(&install_plan_for(DistroFamily::Debian), &target)
                    .elevated(true),
            )
            .await
            .unwrap();
        backend
            .status(StatusQuery::new("brave-browser"))
            .await
            .unwrap();
        backend
            .uninstall(
                UninstallRequest::new(&uninstall_plan_for(DistroFamily::Debian), &target)
                    .elevated(true),
            )
            .await
            .unwrap();
        for call in fake.calls() {
            assert_ne!(call.program, "sudo", "{call:?}");
            assert!(
                call.args.iter().all(|arg| !arg.contains("sudo")),
                "{call:?}"
            );
        }
    }
}
