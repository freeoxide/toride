//! # Snap backend (`snap`)
//!
//! [`SnapBackend`] is the [`Backend`] implementation for Snap on Linux: it
//! executes the planner's [`Operation::SnapInstall`] /
//! [`Operation::SnapUninstall`] / [`Operation::SnapUpdate`] operations
//! through the shared [`CommandRunner`] seam and answers list/status
//! queries from snapd's space-aligned tables.
//!
//! ## Real-CLI semantics (verified against snapd 2.66.1 source)
//!
//! - **Version** — `snap version` prints one space-aligned `key  value`
//!   row each for `snap` (the client), `snapd`, `series`, the OS, and the
//!   kernel; the client `snap` row is the version this backend reports.
//! - **Install** — `snap install <name> [--channel=<track>/<risk>[/branch]]`.
//!   A snap already installed is *not* an error: snapd's
//!   snap-already-installed notice prints bare (no `error:` prefix) and the
//!   command exits 0 (cmd/snap/error.go prints it without the error
//!   prefix), so a repeat install is a successful no-op for the
//!   ensure-installed semantics the facade wants. An unknown snap fails
//!   with exit 1 and `error: snap "<name>" not found`.
//! - **Uninstall** — `snap remove <name>`: snap's own verb. Removing a
//!   snap that is not installed is likewise an exit-0 success carrying
//!   snapd's bare `snap "<name>" is not installed` notice (the CLI maps
//!   the daemon's snap-not-installed kind to a non-error for remove), so
//!   manifest-driven uninstalls stay idempotent.
//! - **Update** — `snap refresh <name>`: an up-to-date snap refreshes to
//!   an exit-0 success with a bare `snap "<name>" has no updates
//!   available` notice.
//! - **Listing** — `snap list` renders through Go's tabwriter (minwidth 5,
//!   padding 2) as a **header row plus one row per snap**, space-aligned:
//!   every column separator is two or more spaces, and single spaces stay
//!   inside cells (publisher display names carry them). The six columns
//!   are Name, Version, Rev, Tracking, Publisher, Notes; an empty version
//!   or tracking channel renders as `-`, and Notes renders `-` when
//!   nothing applies. A host with zero snaps prints the notice to stderr
//!   and nothing at all to stdout, still exiting 0.
//! - **Per-snap listing** — `snap list <name>`: the same table for one
//!   snap; a name nothing matches fails with exit 1 and
//!   `error: no matching snaps installed` (the CLI's `ErrNoMatchingSnaps`).
//! - **Outdated** — `snap refresh --list`: the same tabwriter shape with
//!   columns Name, Version, Rev, Size, Publisher, Notes, where Version is
//!   the revision snapd would move *to* (the rows come from the store's
//!   refresh listing, so the installed version is not in the table). With
//!   no refreshes pending, `All snaps up to date.` rides stderr with an
//!   empty stdout and exit 0.
//! - **Errors** — every real failure prints `error: <message>` to stderr
//!   and exits 1; snapd being down surfaces as
//!   `error: cannot communicate with server: <reason>` on every command.
//!
//! ## Split
//!
//! - **Detection surface** — [`SnapBackend::detect`] (PATH check via
//!   `toride-runner`'s discovery helpers, no command executed) and
//!   [`SnapBackend::version`] (`snap version`).
//! - **Trait operations** — install/uninstall/update/list/status per the
//!   [`Backend`] contract (guard-first, seam-only execution), plus the
//!   status override riding the cheaper per-snap listing and the outdated
//!   override parsing `snap refresh --list`.
//! - **Table parsing** — the space-aligned listings parsed into typed
//!   rows. Per-row tolerance: a malformed row (wrong cell count) is
//!   skipped, never fatal to the whole listing; a non-empty document where
//!   nothing parses is treated as unparseable output, not as an empty
//!   host.
//!
//! ## Conventions honored
//!
//! - [`ensure_install_allowed`] / [`ensure_uninstall_allowed`] /
//!   [`ensure_update_allowed`] are the first statement of the trait's
//!   mutating operations.
//! - Interactivity: unlike flatpak, snap never prompts, so the executed
//!   argv is **exactly** the plan's canonical argv — no runtime flags are
//!   layered on (there is nothing to suppress).
//! - Error mapping: non-zero exits surface as [`Error::Command`] carrying
//!   snapd's stderr. Two classifications: a `snap remove` whose stderr
//!   carries snapd's not-installed wording (exit 0 bare notice, or exit 1
//!   under an `error:` prefix) becomes a success noting the snap was
//!   already absent; an install whose stderr carries the already-installed
//!   notice is annotated in the outcome detail. Everything else — snapd
//!   unreachable, unknown snap, permission failures — stays a real error.
//!   See `NOT_INSTALLED_MARKER` / `ALREADY_INSTALLED_MARKER`.
//!
//! [`Operation::SnapInstall`]: crate::Operation::SnapInstall
//! [`Operation::SnapUninstall`]: crate::Operation::SnapUninstall
//! [`Operation::SnapUpdate`]: crate::Operation::SnapUpdate
//! [`ensure_install_allowed`]: crate::backend::ensure_install_allowed
//! [`ensure_uninstall_allowed`]: crate::backend::ensure_uninstall_allowed
//! [`ensure_update_allowed`]: crate::backend::ensure_update_allowed

use async_trait::async_trait;
use toride_registry::Os;
use toride_runner::CommandOutput;

use crate::backend::{
    Backend, BackendId, BackendStatus, InstallOutcome, InstallRequest, InstalledApp, ListQuery,
    OutdatedEntry, StatusQuery, UninstallOutcome, UninstallRequest, UpdateRequest,
    ensure_install_allowed, ensure_uninstall_allowed, ensure_update_allowed,
};
use crate::error::{Error, Result};
use crate::plan::{Operation, Target};
use crate::runner::{CommandRunner, command};

/// The snap CLI binary every command in this module targets.
const SNAP: &str = "snap";

/// How many space-aligned cells a well-formed table row carries (the fixed
/// six columns both listings render: name, version, revision, tracking or
/// size, publisher, notes).
const TABLE_COLUMN_COUNT: usize = 6;

/// Marker whose presence in a `snap remove`'s stderr classifies the outcome
/// as "the snap is simply not installed" rather than a real error.
/// snapd's wording (snap/errors.go, `NotInstalledError`) is
/// `snap "<name>" is not installed`, printed bare (no `error:` prefix) with
/// exit 0 on the remove path — cmd/snap/error.go downgrades the
/// snap-not-installed kind to a notice for remove — so the marker cannot
/// require an `error:` prefix the way flatpak's does. Matched
/// case-insensitively against any stderr line.
const NOT_INSTALLED_MARKER: &str = "is not installed";

/// Marker classifying a failed `snap list <name>` as "no such snap on this
/// host": the CLI's own `ErrNoMatchingSnaps` wording, printed under an
/// `error:` prefix with exit 1.
const NO_MATCHING_SNAPS_MARKER: &str = "no matching snaps installed";

/// Marker for snapd's already-installed notice on an exit-0 install —
/// `snap "<name>" is already installed, see 'snap help refresh'` — which
/// annotates the install outcome rather than failing it.
const ALREADY_INSTALLED_MARKER: &str = "already installed";
// ---------------------------------------------------------------------------
// Backend
// ---------------------------------------------------------------------------

/// Snap [`Backend`]: executes snap install/remove/refresh plans and answers
/// list/status queries from snapd's space-aligned tables.
///
/// # Example
///
/// ```rust,ignore
/// use toride_apps::CommandRunner;
/// use toride_apps::backends::snap::SnapBackend;
///
/// # async fn demo() -> toride_apps::Result<()> {
/// let runner = CommandRunner::builder().build();
/// let backend = SnapBackend::detect(runner)?; // snap must be on PATH
/// let entries = backend.list_entries().await?;
/// # let _ = entries;
/// # Ok(())
/// # }
/// ```
pub struct SnapBackend {
    /// The seam every snap command flows through.
    runner: CommandRunner,
}

impl SnapBackend {
    /// Create the backend over an explicit seam, with no host assumptions.
    ///
    /// This is the test-friendly constructor: the seam's runner is
    /// injectable, so every command the backend issues is fake-able.
    #[must_use]
    pub fn new(runner: CommandRunner) -> Self {
        Self { runner }
    }

    /// Create the backend after verifying `snap` is on the host `$PATH`
    /// (via `toride-runner`'s discovery helpers — no command is executed).
    ///
    /// Use this in production entry points; use [`SnapBackend::new`] under
    /// a fake runner, where the real PATH is irrelevant.
    ///
    /// # Errors
    ///
    /// [`Error::Command`] wrapping `BinaryNotFound` when `snap` is not on
    /// the PATH.
    pub fn detect(runner: CommandRunner) -> Result<Self> {
        let _path = toride_runner::discovery::find_binary(SNAP)?;
        Ok(Self::new(runner))
    }

    /// The installed snap client's version, from `snap version`.
    ///
    /// Parses the space-aligned `snap  <version>` row (the client row; the
    /// daemon's own version rides the `snapd` row); any extra version
    /// suffix is kept verbatim.
    ///
    /// # Errors
    ///
    /// [`Error::Command`] when the probe fails or its output carries no
    /// `snap <version>` row.
    pub async fn version(&self) -> Result<String> {
        let output = self.runner.run_checked(command(SNAP, ["version"])).await?;
        parse_version_output(&output.stdout)
    }

    /// The full typed listing of installed snaps: name, version,
    /// revision, and tracking channel, straight from `snap list`.
    ///
    /// Richer than the trait's [`Backend::list_installed`] (which maps
    /// these entries to plain [`InstalledApp`]s) so callers that need the
    /// revision or the tracked channel can take them directly.
    ///
    /// # Errors
    ///
    /// [`Error::Command`] when the listing command fails or its output is
    /// non-empty yet contains no parseable row (malformed *rows* are
    /// skipped, not fatal).
    pub async fn list_entries(&self) -> Result<Vec<SnapEntry>> {
        let output = self.runner.run_checked(command(SNAP, ["list"])).await?;
        parse_list_output(&output.stdout)
    }

    /// The sync twin of [`SnapBackend::list_entries`] — same listing, same
    /// parsing, executed on the calling thread.
    ///
    /// # Errors
    ///
    /// Same contract as [`SnapBackend::list_entries`].
    pub fn list_entries_sync(&self) -> Result<Vec<SnapEntry>> {
        let output = self.runner.run_checked_sync(command(SNAP, ["list"]))?;
        parse_list_output(&output.stdout)
    }

    /// The per-snap listing probe (`snap list <name>`): the typed row for
    /// `name`, or `Ok(None)` when snapd answers that nothing matches. The
    /// probe backs both the status override and the post-install verify.
    ///
    /// # Errors
    ///
    /// [`Error::Command`] when the listing fails for any reason other than
    /// no-matching-snaps, or its output is unparseable.
    async fn snap_row(&self, name: &str) -> Result<Option<SnapEntry>> {
        match self.runner.run_checked(command(SNAP, ["list", name])).await {
            Ok(output) => Ok(parse_list_output(&output.stdout)?
                .into_iter()
                .find(|entry| entry.name == name)),
            Err(Error::Command(toride_runner::Error::CommandFailed {
                stderr,
                exit_code: Some(1),
                ..
            })) if stderr_mentions(&stderr, NO_MATCHING_SNAPS_MARKER) => Ok(None),
            Err(error) => Err(error),
        }
    }

    /// The sync twin of [`SnapBackend::snap_row`].
    ///
    /// # Errors
    ///
    /// Same contract as [`SnapBackend::snap_row`].
    fn snap_row_sync(&self, name: &str) -> Result<Option<SnapEntry>> {
        match self.runner.run_checked_sync(command(SNAP, ["list", name])) {
            Ok(output) => Ok(parse_list_output(&output.stdout)?
                .into_iter()
                .find(|entry| entry.name == name)),
            Err(Error::Command(toride_runner::Error::CommandFailed {
                stderr,
                exit_code: Some(1),
                ..
            })) if stderr_mentions(&stderr, NO_MATCHING_SNAPS_MARKER) => Ok(None),
            Err(error) => Err(error),
        }
    }

    /// Post-verify: ask the per-snap listing what version landed, for the
    /// outcome record. The install already succeeded, so a failing probe
    /// degrades to "no version reported" instead of failing the outcome.
    async fn post_install_version(&self, name: &str) -> Option<String> {
        self.snap_row(name)
            .await
            .ok()
            .flatten()
            .and_then(|row| row.version)
    }

    /// The sync twin of [`SnapBackend::post_install_version`].
    fn post_install_version_sync(&self, name: &str) -> Option<String> {
        self.snap_row_sync(name)
            .ok()
            .flatten()
            .and_then(|row| row.version)
    }
}

#[async_trait]
impl Backend for SnapBackend {
    fn id(&self) -> BackendId {
        BackendId::Snap
    }

    fn supports(&self, target: &Target) -> bool {
        target.os == Os::Linux
    }

    async fn install(&self, request: InstallRequest<'_>) -> Result<InstallOutcome> {
        ensure_install_allowed(&request)?;
        let Operation::SnapInstall { name, channel } = &request.plan.operation else {
            return Err(misrouted_operation(&request.plan.operation));
        };
        let spec = snap_install_spec(name, channel.as_deref());
        let output = self.runner.run_checked(spec).await?;
        let version = self.post_install_version(name).await;
        let description = request.plan.operation.description();
        let detail = if stderr_mentions(&output.stderr, ALREADY_INSTALLED_MARKER) {
            format!("{description} (already installed)")
        } else {
            description
        };
        Ok(InstallOutcome { version, detail })
    }

    async fn uninstall(&self, request: UninstallRequest<'_>) -> Result<UninstallOutcome> {
        ensure_uninstall_allowed(&request)?;
        let Operation::SnapUninstall { name } = &request.plan.operation else {
            return Err(misrouted_operation(&request.plan.operation));
        };
        let spec = snap_remove_spec(name);
        classify_uninstall(
            self.runner.run_checked(spec).await,
            request.plan.operation.description(),
        )
    }

    async fn update(&self, request: UpdateRequest<'_>) -> Result<()> {
        ensure_update_allowed(&request)?;
        let Operation::SnapUpdate { name } = &request.plan.operation else {
            return Err(misrouted_operation(&request.plan.operation));
        };
        self.runner.run_checked(snap_refresh_spec(name)).await?;
        Ok(())
    }

    async fn list_installed(&self, query: ListQuery) -> Result<Vec<InstalledApp>> {
        let entries = self.list_entries().await?;
        Ok(entries
            .into_iter()
            .filter(|entry| query.ids.is_empty() || query.ids.contains(&entry.name))
            .map(|entry| InstalledApp {
                id: entry.name,
                version: entry.version,
            })
            .collect())
    }

    async fn status(&self, query: StatusQuery<'_>) -> Result<BackendStatus> {
        Ok(match self.snap_row(query.id).await? {
            Some(entry) => BackendStatus::Installed {
                version: entry.version,
            },
            None => BackendStatus::NotInstalled,
        })
    }

    async fn outdated(&self) -> Result<Vec<OutdatedEntry>> {
        let output = self
            .runner
            .run_checked(command(SNAP, ["refresh", "--list"]))
            .await?;
        parse_refresh_list(&output.stdout)
    }

    fn install_sync(&self, request: InstallRequest<'_>) -> Result<InstallOutcome> {
        ensure_install_allowed(&request)?;
        let Operation::SnapInstall { name, channel } = &request.plan.operation else {
            return Err(misrouted_operation(&request.plan.operation));
        };
        let spec = snap_install_spec(name, channel.as_deref());
        let output = self.runner.run_checked_sync(spec)?;
        let version = self.post_install_version_sync(name);
        let description = request.plan.operation.description();
        let detail = if stderr_mentions(&output.stderr, ALREADY_INSTALLED_MARKER) {
            format!("{description} (already installed)")
        } else {
            description
        };
        Ok(InstallOutcome { version, detail })
    }

    fn uninstall_sync(&self, request: UninstallRequest<'_>) -> Result<UninstallOutcome> {
        ensure_uninstall_allowed(&request)?;
        let Operation::SnapUninstall { name } = &request.plan.operation else {
            return Err(misrouted_operation(&request.plan.operation));
        };
        let spec = snap_remove_spec(name);
        classify_uninstall(
            self.runner.run_checked_sync(spec),
            request.plan.operation.description(),
        )
    }

    fn update_sync(&self, request: UpdateRequest<'_>) -> Result<()> {
        ensure_update_allowed(&request)?;
        let Operation::SnapUpdate { name } = &request.plan.operation else {
            return Err(misrouted_operation(&request.plan.operation));
        };
        self.runner.run_checked_sync(snap_refresh_spec(name))?;
        Ok(())
    }

    fn list_installed_sync(&self, query: ListQuery) -> Result<Vec<InstalledApp>> {
        let entries = self.list_entries_sync()?;
        Ok(entries
            .into_iter()
            .filter(|entry| query.ids.is_empty() || query.ids.contains(&entry.name))
            .map(|entry| InstalledApp {
                id: entry.name,
                version: entry.version,
            })
            .collect())
    }

    fn status_sync(&self, query: StatusQuery<'_>) -> Result<BackendStatus> {
        Ok(match self.snap_row_sync(query.id)? {
            Some(entry) => BackendStatus::Installed {
                version: entry.version,
            },
            None => BackendStatus::NotInstalled,
        })
    }

    fn outdated_sync(&self) -> Result<Vec<OutdatedEntry>> {
        let output = self
            .runner
            .run_checked_sync(command(SNAP, ["refresh", "--list"]))?;
        parse_refresh_list(&output.stdout)
    }
}
// ---------------------------------------------------------------------------
// Typed query results
// ---------------------------------------------------------------------------

/// One row of `snap list`: the typed, backend-native view behind the
/// trait's plain [`InstalledApp`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapEntry {
    /// Snap name (`firefox`) — the backend-native id and the join key
    /// against plan operations and manifest records.
    pub name: String,
    /// Installed version when the listing reports one (a snap without
    /// version metadata reports `-`, typically locally-installed ones).
    pub version: Option<String>,
    /// Store revision of the installed snap (`4842`; `x1`, `x2`, … for
    /// locally-installed revisions).
    pub rev: String,
    /// Channel the snap tracks (`latest/stable`); `-` when the snap tracks
    /// nothing (local install).
    pub tracking: String,
}
// ---------------------------------------------------------------------------
// Output parsing
// ---------------------------------------------------------------------------

/// The canonical `snap install` spec the plan's operation executes —
/// identical to the plan's argv: snap never prompts, so there are no
/// runtime flags to layer on.
fn snap_install_spec(name: &str, channel: Option<&str>) -> toride_runner::CommandSpec {
    match channel {
        Some(channel) => command(SNAP, ["install", &format!("--channel={channel}"), name]),
        None => command(SNAP, ["install", name]),
    }
}

/// The canonical `snap remove` spec the plan's operation executes.
fn snap_remove_spec(name: &str) -> toride_runner::CommandSpec {
    command(SNAP, ["remove", name])
}

/// The canonical `snap refresh` spec the plan's operation executes.
fn snap_refresh_spec(name: &str) -> toride_runner::CommandSpec {
    command(SNAP, ["refresh", name])
}

/// Classify a dispatched `snap remove`: success carries the removal
/// detail; snapd's own not-installed answer — the bare exit-0 notice, or
/// the `error:`-prefixed exit 1 — is a success noting the absence, since
/// the desired end state already holds. The exit-code gate on the error
/// path keeps signal kills and other failures as real errors.
fn classify_uninstall(
    result: Result<CommandOutput>,
    description: String,
) -> Result<UninstallOutcome> {
    match result {
        Ok(output) => Ok(UninstallOutcome {
            detail: if stderr_mentions(&output.stderr, NOT_INSTALLED_MARKER) {
                format!("{description} (already absent)")
            } else {
                description
            },
        }),
        Err(Error::Command(toride_runner::Error::CommandFailed {
            stderr,
            exit_code: Some(1),
            ..
        })) if stderr_mentions(&stderr, NOT_INSTALLED_MARKER) => Ok(UninstallOutcome {
            detail: format!("{description} (already absent)"),
        }),
        Err(error) => Err(error),
    }
}

/// Split one space-aligned table row into its cells: snapd's tabwriter
/// (minwidth 5, padding 2) pads every column with at least two spaces, so
/// runs of two or more spaces are column separators while single spaces
/// stay inside cells (publisher display names carry them).
fn split_table_row(line: &str) -> Vec<&str> {
    line.split("  ")
        .map(str::trim)
        .filter(|cell| !cell.is_empty())
        .collect()
}

/// Whether the cells are the table's header row (the fourth column is the
/// discriminator: `Tracking` for `snap list`, `Size` for
/// `snap refresh --list`).
fn is_table_header(cells: &[&str], fourth_column: &str) -> bool {
    cells.first() == Some(&"Name")
        && cells.get(1) == Some(&"Version")
        && cells.get(3) == Some(&fourth_column)
}

/// Parse the space-aligned `snap list` table into typed entries, skipping
/// the header row and malformed rows (anything that is not exactly the six
/// columns).
///
/// A non-empty document where no row parses is an error, not an empty
/// host: every row being malformed means the output shape is not what snap
/// renders, which must surface loudly rather than read as "nothing
/// installed".
///
/// # Errors
///
/// [`Error::Command`] wrapping `OutputParse` for the no-parseable-rows
/// case above.
fn parse_list_output(stdout: &str) -> Result<Vec<SnapEntry>> {
    let mut entries = Vec::new();
    for line in stdout.lines() {
        let line = line.trim_end();
        if line.is_empty() {
            continue;
        }
        let cells = split_table_row(line);
        if is_table_header(&cells, "Tracking") {
            continue;
        }
        if cells.len() != TABLE_COLUMN_COUNT {
            continue;
        }
        entries.push(SnapEntry {
            name: cells[0].to_owned(),
            version: version_cell(cells[1]),
            rev: cells[2].to_owned(),
            tracking: cells[3].to_owned(),
        });
    }
    if !stdout.trim().is_empty() && entries.is_empty() {
        return Err(output_parse_error(
            "snap list",
            format!("no parseable six-column rows in {stdout:?}"),
        ));
    }
    Ok(entries)
}

/// Parse the space-aligned `snap refresh --list` table into stale-item
/// records. The table's Version column is the revision snapd would move
/// *to*, so it fills `current_version` and `installed_versions` stays
/// empty — the refresh listing does not carry the installed revision.
/// Same tolerance shape as [`parse_list_output`].
///
/// # Errors
///
/// [`Error::Command`] wrapping `OutputParse` for a non-empty document with
/// no parseable rows.
fn parse_refresh_list(stdout: &str) -> Result<Vec<OutdatedEntry>> {
    let mut entries = Vec::new();
    for line in stdout.lines() {
        let line = line.trim_end();
        if line.is_empty() {
            continue;
        }
        let cells = split_table_row(line);
        if is_table_header(&cells, "Size") {
            continue;
        }
        if cells.len() != TABLE_COLUMN_COUNT {
            continue;
        }
        entries.push(OutdatedEntry {
            id: cells[0].to_owned(),
            installed_versions: Vec::new(),
            current_version: version_cell(cells[1]),
            pinned: false,
        });
    }
    if !stdout.trim().is_empty() && entries.is_empty() {
        return Err(output_parse_error(
            "snap refresh --list",
            format!("no parseable six-column rows in {stdout:?}"),
        ));
    }
    Ok(entries)
}

/// Parse `snap version` output: the first whitespace-split row whose key
/// is exactly `snap` (the client — `snapd` is the daemon's row) contributes
/// its value.
///
/// # Errors
///
/// [`Error::Command`] wrapping `OutputParse` when no `snap <version>` row
/// exists or the value is empty.
fn parse_version_output(stdout: &str) -> Result<String> {
    let version = stdout.lines().find_map(|line| {
        let mut cells = line.split_whitespace();
        if cells.next() == Some("snap") {
            cells.next().filter(|version| !version.is_empty())
        } else {
            None
        }
    });
    version.map_or_else(
        || {
            Err(output_parse_error(
                "snap version",
                format!("no `snap <version>` row in {stdout:?}"),
            ))
        },
        |version| Ok(version.to_owned()),
    )
}

/// Whether stderr mentions `marker` on any line, case-insensitively.
/// Unlike flatpak's sniffer this cannot gate on an `error:` prefix:
/// snapd's not-installed and already-installed notices print bare on their
/// exit-0 paths (cmd/snap/error.go prints them without the prefix).
fn stderr_mentions(stderr: &str, marker: &str) -> bool {
    stderr
        .lines()
        .any(|line| line.to_ascii_lowercase().contains(marker))
}

/// A version cell's value: `None` when snapd renders its `-` placeholder
/// (fmtVersion maps an empty version to `-`) or the cell is empty, the
/// verbatim string otherwise.
fn version_cell(cell: &str) -> Option<String> {
    Some(cell.to_owned()).filter(|value| value != "-" && !value.is_empty())
}

/// The error for a plan operation this backend cannot execute (a non-snap
/// operation routed to the snap backend).
fn misrouted_operation(operation: &Operation) -> Error {
    Error::Command(toride_runner::Error::Other(format!(
        "snap backend cannot execute non-snap operation: {operation:?}"
    )))
}

/// Build the unparseable-output error, naming the snap command and the
/// cause.
fn output_parse_error(snap_command: &str, cause: impl std::fmt::Display) -> Error {
    Error::Command(toride_runner::Error::OutputParse(format!(
        "{snap_command}: {cause}"
    )))
}
// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plan::{InstallPlan, UninstallPlan, UpdatePlan};
    use std::sync::Arc;
    use toride_registry::{Arch, DistroFamily, Os, TorideId};
    use toride_runner::fake::FakeRunner;

    // --- test helpers ----------------------------------------------------------

    /// A representative `snap list` table exactly as snapd's tabwriter
    /// emits it: header first, every column separator two or more spaces,
    /// `-` for an empty Notes cell. The rows are real store snaps (a base
    /// snap, the core runtime, an app, a GNOME platform snap with the wide
    /// cells that prove the name/version split).
    fn listing_output() -> String {
        [
            "Name           Version          Rev    Tracking        Publisher    Notes",
            "bare           1.0              5      latest/stable   Canonical✓   base",
            "core24         20240710-1       488    latest/stable   Canonical✓   base",
            "firefox        139.0.4-1        4842   latest/stable   Mozilla✓      -",
            "gnome-42-2204  0+git.ffb0376f   602    latest/stable   Canonical✓   -",
        ]
        .join("\n")
    }

    /// A representative `snap refresh --list` table (the Size column
    /// replaces Tracking; Version is the revision being moved to).
    fn refresh_output() -> String {
        [
            "Name      Version     Rev    Size    Publisher    Notes",
            "firefox   140.0-1     5000   231MB   Mozilla✓     -",
            "core24    20240801-1  490    26MB    Canonical✓   -",
        ]
        .join("\n")
    }

    /// A representative `snap version` document: one space-aligned key /
    /// value row each for the client, the daemon, the series, the OS, and
    /// the kernel.
    fn version_output() -> String {
        [
            "snap    2.66.1",
            "snapd   2.66.1",
            "series  16",
            "ubuntu  24.04",
            "kernel  6.8.0-45-generic",
        ]
        .join("\n")
    }

    fn linux_target() -> Target {
        Target::linux(Arch::X86_64, DistroFamily::Debian)
    }

    /// A backend over a strict fake runner (unmatched dispatches fail).
    fn backend(fake: &FakeRunner) -> SnapBackend {
        SnapBackend::new(CommandRunner::new(Arc::new(fake.clone())))
    }

    /// A snap-backend install plan carrying a hand-picked operation (the
    /// registry has no snap install method yet, so plans are built at the
    /// operation seam).
    fn install_plan(operation: Operation) -> InstallPlan {
        InstallPlan {
            app: TorideId::slugify("firefox"),
            backend: BackendId::Snap,
            operation,
            dry_run: false,
            requires_elevation: false,
        }
    }

    fn uninstall_plan(operation: Operation) -> UninstallPlan {
        UninstallPlan {
            app: TorideId::slugify("firefox"),
            backend: BackendId::Snap,
            operation,
            dry_run: false,
            requires_elevation: false,
        }
    }

    fn update_plan(operation: Operation) -> UpdatePlan {
        UpdatePlan {
            app: TorideId::slugify("firefox"),
            backend: BackendId::Snap,
            operation,
            dry_run: false,
            requires_elevation: false,
        }
    }

    fn default_install_plan() -> InstallPlan {
        install_plan(Operation::SnapInstall {
            name: "firefox".to_owned(),
            channel: None,
        })
    }

    fn default_uninstall_plan() -> UninstallPlan {
        uninstall_plan(Operation::SnapUninstall {
            name: "firefox".to_owned(),
        })
    }

    fn default_update_plan() -> UpdatePlan {
        update_plan(Operation::SnapUpdate {
            name: "firefox".to_owned(),
        })
    }

    /// The exact spec the install runs for a name/channel pair.
    fn install_spec(name: &str, channel: Option<&str>) -> toride_runner::CommandSpec {
        snap_install_spec(name, channel)
    }

    // --- version probe parsing ---------------------------------------------------

    #[test]
    fn parse_version_output_takes_the_snap_client_row() {
        let version = parse_version_output(&version_output()).unwrap();
        assert_eq!(version, "2.66.1");
    }

    #[test]
    fn parse_version_output_rejects_output_without_a_snap_client_row() {
        // Only the daemon's row: the client row is the contract.
        let error = parse_version_output("snapd   2.66.1\nseries  16\n").unwrap_err();
        assert!(
            matches!(error, Error::Command(toride_runner::Error::OutputParse(_))),
            "{error:?}"
        );
    }

    #[test]
    fn parse_version_output_rejects_empty_output() {
        assert!(parse_version_output("").is_err());
        assert!(parse_version_output("  \n\n").is_err());
    }

    // --- listing parsing -----------------------------------------------------------

    #[test]
    fn parse_list_output_reads_entries_from_a_representative_table() {
        let entries = parse_list_output(&listing_output()).unwrap();
        assert_eq!(entries.len(), 4, "{entries:?}");
        assert_eq!(
            entries[0],
            SnapEntry {
                name: "bare".to_owned(),
                version: Some("1.0".to_owned()),
                rev: "5".to_owned(),
                tracking: "latest/stable".to_owned(),
            }
        );
        let firefox = entries
            .iter()
            .find(|entry| entry.name == "firefox")
            .unwrap();
        assert_eq!(firefox.version.as_deref(), Some("139.0.4-1"));
        assert_eq!(firefox.rev, "4842");
    }

    #[test]
    fn parse_list_output_maps_a_dash_version_cell_to_none() {
        // A locally-installed snap renders `-` for its empty version and
        // tracking cells (snapd's fmtVersion/fmtChannel placeholders).
        let raw = "Name      Version  Rev  Tracking  Publisher  Notes\n\
                   local-snap  -      x1   -         -          -\n";
        let entries = parse_list_output(raw).unwrap();
        assert_eq!(
            entries,
            vec![SnapEntry {
                name: "local-snap".to_owned(),
                version: None,
                rev: "x1".to_owned(),
                tracking: "-".to_owned(),
            }]
        );
    }

    #[test]
    fn parse_list_output_skips_malformed_rows_without_failing_the_listing() {
        // One row per failure mode (no double-space separators at all, an
        // extra cell) plus two valid rows.
        let raw = "Name      Version  Rev  Tracking  Publisher  Notes\n\
                   no double separators at all here\n\
                   bare  1.0  5  latest/stable  Canonical✓  base  extra\n\
                   core24  20240710-1  488  latest/stable  Canonical✓  base\n\
                   firefox  139.0.4-1  4842  latest/stable  Mozilla✓  -\n";
        let entries = parse_list_output(raw).unwrap();
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, ["core24", "firefox"], "{entries:?}");
    }

    #[test]
    fn parse_list_output_returns_an_empty_listing_for_empty_output() {
        // Zero snaps installed: snapd prints its notice to stderr and
        // nothing at all to stdout, still exiting 0.
        assert_eq!(parse_list_output("").unwrap(), Vec::new());
        assert_eq!(parse_list_output("  \n\n").unwrap(), Vec::new());
    }

    #[test]
    fn parse_list_output_errors_when_nothing_in_a_non_empty_document_parses() {
        // Every row malformed means the output shape is wrong — that must
        // not read as "nothing installed".
        let error = parse_list_output("totally garbage\nnot a listing\n").unwrap_err();
        assert!(
            matches!(error, Error::Command(toride_runner::Error::OutputParse(_))),
            "{error:?}"
        );
    }

    // --- refresh-list parsing ------------------------------------------------------

    #[test]
    fn parse_refresh_list_reads_the_available_updates_from_the_table() {
        let entries = parse_refresh_list(&refresh_output()).unwrap();
        assert_eq!(
            entries,
            vec![
                OutdatedEntry {
                    id: "firefox".to_owned(),
                    installed_versions: Vec::new(),
                    current_version: Some("140.0-1".to_owned()),
                    pinned: false,
                },
                OutdatedEntry {
                    id: "core24".to_owned(),
                    installed_versions: Vec::new(),
                    current_version: Some("20240801-1".to_owned()),
                    pinned: false,
                },
            ],
            "the table's Version column is the revision snapd moves to"
        );
    }

    #[test]
    fn parse_refresh_list_returns_no_entries_for_empty_output() {
        // "All snaps up to date." rides stderr with an empty stdout.
        assert_eq!(parse_refresh_list("").unwrap(), Vec::new());
    }

    #[test]
    fn parse_refresh_list_errors_when_nothing_in_a_non_empty_document_parses() {
        let error = parse_refresh_list("garbage without columns\n").unwrap_err();
        assert!(
            matches!(error, Error::Command(toride_runner::Error::OutputParse(_))),
            "{error:?}"
        );
    }

    // --- stderr classification ------------------------------------------------------

    #[test]
    fn stderr_classification_matches_the_not_installed_notice_bare_and_prefixed() {
        // The exit-0 path prints the notice bare; an error-path rendering
        // carries the `error:` prefix — both classify.
        for stderr in [
            "snap \"firefox\" is not installed\n",
            "error: snap \"firefox\" is not installed\n",
        ] {
            assert!(stderr_mentions(stderr, NOT_INSTALLED_MARKER), "{stderr}");
        }
    }

    #[test]
    fn stderr_classification_rejects_unrelated_failures() {
        for stderr in [
            "error: cannot communicate with server: timeout exceeded while waiting for response",
            "error: snap \"nope\" not found",
            "error: access denied",
        ] {
            assert!(!stderr_mentions(stderr, NOT_INSTALLED_MARKER), "{stderr}");
            assert!(
                !stderr_mentions(stderr, NO_MATCHING_SNAPS_MARKER),
                "{stderr}"
            );
        }
    }

    #[test]
    fn stderr_classification_matches_the_already_installed_notice() {
        assert!(stderr_mentions(
            "snap \"firefox\" is already installed, see 'snap help refresh'\n",
            ALREADY_INSTALLED_MARKER
        ));
        assert!(!stderr_mentions(
            "error: snap \"nope\" not found",
            ALREADY_INSTALLED_MARKER
        ));
    }

    // --- detection probes through the seam --------------------------------------------

    #[tokio::test]
    async fn version_probes_snap_version_with_exact_argv() {
        let spec = command(SNAP, ["version"]);
        let fake = FakeRunner::new().strict().respond(
            spec.clone(),
            toride_runner::CommandOutput::from_stdout(version_output()),
        );
        let backend = backend(&fake);
        assert_eq!(backend.version().await.unwrap(), "2.66.1");
        fake.assert_called_with(&spec);
    }

    // --- install ----------------------------------------------------------------

    #[tokio::test]
    async fn install_refuses_dry_run_plans_without_touching_the_runner() {
        let fake = FakeRunner::new().strict();
        let backend = backend(&fake);
        let plan = default_install_plan().dry_run(true);
        let target = linux_target();
        let error = backend
            .install(InstallRequest::new(&plan, &target))
            .await
            .unwrap_err();
        assert!(matches!(error, Error::DryRun { .. }), "{error:?}");
        assert!(fake.calls().is_empty(), "no snap command may run");
    }

    #[tokio::test]
    async fn install_refuses_elevation_requiring_plans_without_a_grant() {
        let fake = FakeRunner::new().strict();
        let backend = backend(&fake);
        let mut plan = default_install_plan();
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
        assert!(fake.calls().is_empty(), "no snap command may run");
    }

    #[tokio::test]
    async fn install_rejects_non_snap_operations() {
        let fake = FakeRunner::new().strict();
        let backend = backend(&fake);
        let plan = install_plan(Operation::DistroInstall {
            manager: crate::plan::PackageManager::Apt,
            package: "firefox".to_owned(),
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
    async fn install_executes_the_plans_canonical_argv_exactly() {
        let plan = default_install_plan();
        // Snap never prompts, so the executed argv IS the plan's canonical
        // argv — nothing is layered on at execution.
        assert_eq!(plan.operation.argv(), ["snap", "install", "firefox"]);
        let fake = FakeRunner::new()
            .strict()
            .respond(
                install_spec("firefox", None),
                toride_runner::CommandOutput::from_stdout("firefox 139.0.4-1 installed\n"),
            )
            .respond(
                command(SNAP, ["list", "firefox"]),
                toride_runner::CommandOutput::from_stdout(
                    "Name      Version    Rev   Tracking       Publisher  Notes\n\
                     firefox   139.0.4-1  4842  latest/stable  Mozilla✓   -\n",
                ),
            );
        let backend = backend(&fake);
        let target = linux_target();
        backend
            .install(InstallRequest::new(&plan, &target))
            .await
            .unwrap();
        fake.assert_called_with(&install_spec("firefox", None));
        fake.assert_no_unmatched_calls();
    }

    #[tokio::test]
    async fn install_passes_the_planned_channel_flag() {
        let plan = install_plan(Operation::SnapInstall {
            name: "firefox".to_owned(),
            channel: Some("esr/stable".to_owned()),
        });
        assert_eq!(
            plan.operation.argv(),
            ["snap", "install", "--channel=esr/stable", "firefox"]
        );
        let fake = FakeRunner::new()
            .strict()
            .respond(
                install_spec("firefox", Some("esr/stable")),
                toride_runner::CommandOutput::from_stdout(""),
            )
            .respond(
                command(SNAP, ["list", "firefox"]),
                toride_runner::CommandOutput::from_stdout(""),
            );
        let backend = backend(&fake);
        let target = linux_target();
        backend
            .install(InstallRequest::new(&plan, &target))
            .await
            .unwrap();
        fake.assert_called_with(&install_spec("firefox", Some("esr/stable")));
    }

    #[tokio::test]
    async fn install_reports_the_version_from_the_post_install_listing() {
        let fake = FakeRunner::new()
            .strict()
            .respond(
                install_spec("firefox", None),
                toride_runner::CommandOutput::from_stdout(""),
            )
            .respond(
                command(SNAP, ["list", "firefox"]),
                toride_runner::CommandOutput::from_stdout(
                    "Name      Version    Rev   Tracking       Publisher  Notes\n\
                     firefox   139.0.4-1  4842  latest/stable  Mozilla✓   -\n",
                ),
            );
        let backend = backend(&fake);
        let plan = default_install_plan();
        let target = linux_target();
        let outcome = backend
            .install(InstallRequest::new(&plan, &target))
            .await
            .unwrap();
        assert_eq!(outcome.version.as_deref(), Some("139.0.4-1"));
        assert!(
            outcome.detail.contains("install snap `firefox`"),
            "{}",
            outcome.detail
        );
    }

    #[tokio::test]
    async fn install_notes_when_snapd_already_had_the_snap_installed() {
        // The already-installed notice rides an exit-0 run: the install is
        // a successful no-op, and the outcome says so.
        let fake = FakeRunner::new()
            .strict()
            .respond(
                install_spec("firefox", None),
                toride_runner::CommandOutput::from_stderr(
                    "snap \"firefox\" is already installed, see 'snap help refresh'\n",
                    0,
                ),
            )
            .respond(
                command(SNAP, ["list", "firefox"]),
                toride_runner::CommandOutput::from_stdout(
                    "Name      Version    Rev   Tracking       Publisher  Notes\n\
                     firefox   139.0.4-1  4842  latest/stable  Mozilla✓   -\n",
                ),
            );
        let backend = backend(&fake);
        let plan = default_install_plan();
        let target = linux_target();
        let outcome = backend
            .install(InstallRequest::new(&plan, &target))
            .await
            .unwrap();
        assert!(
            outcome.detail.contains("(already installed)"),
            "{}",
            outcome.detail
        );
        assert_eq!(outcome.version.as_deref(), Some("139.0.4-1"));
    }

    #[tokio::test]
    async fn install_degrades_to_no_version_when_the_post_verify_listing_fails() {
        let fake = FakeRunner::new()
            .strict()
            .respond(
                install_spec("firefox", None),
                toride_runner::CommandOutput::from_stdout(""),
            )
            .respond(
                command(SNAP, ["list", "firefox"]),
                toride_runner::CommandOutput::from_stderr(
                    "error: cannot communicate with server: timeout exceeded",
                    1,
                ),
            );
        let backend = backend(&fake);
        let plan = default_install_plan();
        let target = linux_target();
        let outcome = backend
            .install(InstallRequest::new(&plan, &target))
            .await
            .unwrap();
        assert_eq!(outcome.version, None);
    }

    #[tokio::test]
    async fn install_maps_unknown_snaps_to_command_error() {
        let fake = FakeRunner::new().strict().respond(
            install_spec("nope", None),
            toride_runner::CommandOutput::from_stderr("error: snap \"nope\" not found\n", 1),
        );
        let backend = backend(&fake);
        let plan = install_plan(Operation::SnapInstall {
            name: "nope".to_owned(),
            channel: None,
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
    }

    // --- uninstall ------------------------------------------------------------------

    #[tokio::test]
    async fn uninstall_refuses_dry_run_plans_without_touching_the_runner() {
        let fake = FakeRunner::new().strict();
        let backend = backend(&fake);
        let plan = default_uninstall_plan().dry_run(true);
        let target = linux_target();
        let error = backend
            .uninstall(UninstallRequest::new(&plan, &target))
            .await
            .unwrap_err();
        assert!(matches!(error, Error::DryRun { .. }), "{error:?}");
        assert!(fake.calls().is_empty(), "no snap command may run");
    }

    #[tokio::test]
    async fn uninstall_executes_snap_remove() {
        let spec = command(SNAP, ["remove", "firefox"]);
        let fake = FakeRunner::new().strict().respond(
            spec.clone(),
            toride_runner::CommandOutput::from_stdout("firefox removed\n"),
        );
        let backend = backend(&fake);
        let plan = default_uninstall_plan();
        let target = linux_target();
        backend
            .uninstall(UninstallRequest::new(&plan, &target))
            .await
            .unwrap();
        fake.assert_called_with(&spec);
        fake.assert_no_unmatched_calls();
    }

    #[tokio::test]
    async fn uninstall_reports_already_absent_when_the_exit_zero_notice_says_not_installed() {
        let spec = command(SNAP, ["remove", "firefox"]);
        let fake = FakeRunner::new().strict().respond(
            spec.clone(),
            toride_runner::CommandOutput::from_stderr("snap \"firefox\" is not installed\n", 0),
        );
        let backend = backend(&fake);
        let plan = default_uninstall_plan();
        let target = linux_target();
        let outcome = backend
            .uninstall(UninstallRequest::new(&plan, &target))
            .await
            .unwrap();
        assert!(
            outcome.detail.contains("(already absent)"),
            "{}",
            outcome.detail
        );
    }

    #[tokio::test]
    async fn uninstall_classifies_the_error_prefixed_not_installed_exit_as_already_absent() {
        let spec = command(SNAP, ["remove", "firefox"]);
        let fake = FakeRunner::new().strict().respond(
            spec.clone(),
            toride_runner::CommandOutput::from_stderr(
                "error: snap \"firefox\" is not installed\n",
                1,
            ),
        );
        let backend = backend(&fake);
        let plan = default_uninstall_plan();
        let target = linux_target();
        let outcome = backend
            .uninstall(UninstallRequest::new(&plan, &target))
            .await
            .unwrap();
        assert!(
            outcome.detail.contains("(already absent)"),
            "{}",
            outcome.detail
        );
    }

    #[tokio::test]
    async fn uninstall_keeps_snapd_unreachable_as_a_real_error() {
        let spec = command(SNAP, ["remove", "firefox"]);
        let fake = FakeRunner::new().strict().respond(
            spec,
            toride_runner::CommandOutput::from_stderr(
                "error: cannot communicate with server: dial unix /run/snapd.socket: connect: no such file or directory",
                1,
            ),
        );
        let backend = backend(&fake);
        let plan = default_uninstall_plan();
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

    // --- update --------------------------------------------------------------------

    #[tokio::test]
    async fn update_refuses_dry_run_plans_without_touching_the_runner() {
        let fake = FakeRunner::new().strict();
        let backend = backend(&fake);
        let plan = default_update_plan().dry_run(true);
        let target = linux_target();
        let error = backend
            .update(UpdateRequest::new(&plan, &target))
            .await
            .unwrap_err();
        assert!(matches!(error, Error::DryRun { .. }), "{error:?}");
        assert!(fake.calls().is_empty(), "no snap command may run");
    }

    #[tokio::test]
    async fn update_rejects_non_snap_operations() {
        let fake = FakeRunner::new().strict();
        let backend = backend(&fake);
        let plan = update_plan(Operation::FlatpakUpdate {
            app_id: "com.brave.Browser".to_owned(),
            installation: crate::plan::FlatpakInstallation::User,
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
    }

    #[tokio::test]
    async fn update_executes_snap_refresh_and_treats_up_to_date_as_success() {
        let spec = command(SNAP, ["refresh", "firefox"]);
        let fake = FakeRunner::new().strict().respond(
            spec.clone(),
            toride_runner::CommandOutput::from_stderr(
                "snap \"firefox\" has no updates available\n",
                0,
            ),
        );
        let backend = backend(&fake);
        let plan = default_update_plan();
        let target = linux_target();
        backend
            .update(UpdateRequest::new(&plan, &target))
            .await
            .unwrap();
        fake.assert_called_with(&spec);
    }

    #[tokio::test]
    async fn update_maps_a_failing_refresh_to_command_error() {
        let spec = command(SNAP, ["refresh", "firefox"]);
        let fake = FakeRunner::new().strict().respond(
            spec,
            toride_runner::CommandOutput::from_stderr(
                "error: snap \"firefox\" is not installed\n",
                1,
            ),
        );
        let backend = backend(&fake);
        let plan = default_update_plan();
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
    }

    // --- listing / status / outdated -------------------------------------------------

    #[tokio::test]
    async fn list_installed_lists_every_snap_and_filters_by_query() {
        let spec = command(SNAP, ["list"]);
        let fake = FakeRunner::new()
            .strict()
            .respond(
                spec.clone(),
                toride_runner::CommandOutput::from_stdout(listing_output()),
            )
            .respond(
                spec.clone(),
                toride_runner::CommandOutput::from_stdout(listing_output()),
            );
        let backend = backend(&fake);
        let all = backend.list_installed(ListQuery::all()).await.unwrap();
        assert_eq!(all.len(), 4, "{all:?}");
        let one = backend
            .list_installed(ListQuery::id("firefox"))
            .await
            .unwrap();
        assert_eq!(
            one,
            vec![InstalledApp {
                id: "firefox".to_owned(),
                version: Some("139.0.4-1".to_owned()),
            }]
        );
        fake.assert_called_with(&spec);
    }

    #[tokio::test]
    async fn status_reports_the_version_from_the_per_snap_listing() {
        let spec = command(SNAP, ["list", "firefox"]);
        let fake = FakeRunner::new().strict().respond(
            spec.clone(),
            toride_runner::CommandOutput::from_stdout(
                "Name      Version    Rev   Tracking       Publisher  Notes\n\
                 firefox   139.0.4-1  4842  latest/stable  Mozilla✓   -\n",
            ),
        );
        let backend = backend(&fake);
        let status = backend.status(StatusQuery::new("firefox")).await.unwrap();
        assert_eq!(
            status,
            BackendStatus::Installed {
                version: Some("139.0.4-1".to_owned())
            }
        );
        fake.assert_called_with(&spec);
    }

    #[tokio::test]
    async fn status_reports_not_installed_when_no_snaps_match() {
        let spec = command(SNAP, ["list", "firefox"]);
        let fake = FakeRunner::new().strict().respond(
            spec,
            toride_runner::CommandOutput::from_stderr("error: no matching snaps installed\n", 1),
        );
        let backend = backend(&fake);
        let status = backend.status(StatusQuery::new("firefox")).await.unwrap();
        assert_eq!(status, BackendStatus::NotInstalled);
    }

    #[tokio::test]
    async fn status_keeps_other_failures_as_errors() {
        let fake = FakeRunner::new().strict().respond(
            command(SNAP, ["list", "firefox"]),
            toride_runner::CommandOutput::from_stderr(
                "error: cannot communicate with server: timeout exceeded",
                1,
            ),
        );
        let backend = backend(&fake);
        let error = backend
            .status(StatusQuery::new("firefox"))
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
    async fn outdated_lists_the_available_refreshes() {
        let spec = command(SNAP, ["refresh", "--list"]);
        let fake = FakeRunner::new().strict().respond(
            spec.clone(),
            toride_runner::CommandOutput::from_stdout(refresh_output()),
        );
        let backend = backend(&fake);
        let entries = backend.outdated().await.unwrap();
        assert_eq!(entries.len(), 2, "{entries:?}");
        assert_eq!(entries[0].id, "firefox");
        assert_eq!(entries[0].current_version.as_deref(), Some("140.0-1"));
        fake.assert_called_with(&spec);
    }

    #[tokio::test]
    async fn outdated_reports_nothing_when_all_snaps_are_up_to_date() {
        // The notice rides stderr with an empty stdout on an exit-0 run.
        let spec = command(SNAP, ["refresh", "--list"]);
        let fake = FakeRunner::new().strict().respond(
            spec.clone(),
            toride_runner::CommandOutput::from_stderr("All snaps up to date.\n", 0),
        );
        let backend = backend(&fake);
        assert_eq!(backend.outdated().await.unwrap(), Vec::new());
        fake.assert_called_with(&spec);
    }

    // --- identity ----------------------------------------------------------------

    #[test]
    fn id_is_snap_and_supports_linux_targets_only() {
        let backend = backend(&FakeRunner::new().strict());
        assert_eq!(backend.id(), BackendId::Snap);
        assert_eq!(backend.id().to_string(), "snap");
        assert!(backend.supports(&linux_target()));
        assert!(!backend.supports(&Target::macos(Arch::X86_64)));
        assert!(!backend.supports(&Target::new(Os::Windows, Arch::X86_64)));
    }

    // --- sync twins ----------------------------------------------------------------

    #[test]
    fn install_sync_refuses_dry_run_and_elevation_without_dispatching() {
        let fake = FakeRunner::new().strict();
        let backend = backend(&fake);
        let target = linux_target();
        let error = backend
            .install_sync(InstallRequest::new(
                &default_install_plan().dry_run(true),
                &target,
            ))
            .unwrap_err();
        assert!(matches!(error, Error::DryRun { .. }), "{error:?}");
        let mut plan = default_install_plan();
        plan.requires_elevation = true;
        let error = backend
            .install_sync(InstallRequest::new(&plan, &target))
            .unwrap_err();
        assert!(
            matches!(error, Error::ElevationRequired { .. }),
            "{error:?}"
        );
        assert!(fake.calls().is_empty(), "no snap command may run");
    }

    #[test]
    fn install_sync_executes_the_plan_and_reports_the_version() {
        let fake = FakeRunner::new()
            .strict()
            .respond(
                install_spec("firefox", None),
                toride_runner::CommandOutput::from_stdout(""),
            )
            .respond(
                command(SNAP, ["list", "firefox"]),
                toride_runner::CommandOutput::from_stdout(
                    "Name      Version    Rev   Tracking       Publisher  Notes\n\
                     firefox   139.0.4-1  4842  latest/stable  Mozilla✓   -\n",
                ),
            );
        let backend = backend(&fake);
        let plan = default_install_plan();
        let target = linux_target();
        let outcome = backend
            .install_sync(InstallRequest::new(&plan, &target))
            .unwrap();
        assert_eq!(outcome.version.as_deref(), Some("139.0.4-1"));
        fake.assert_called_with(&install_spec("firefox", None));
    }

    #[test]
    fn uninstall_sync_runs_remove_and_reclassifies_already_absent() {
        let remove = command(SNAP, ["remove", "firefox"]);
        let absent = command(SNAP, ["remove", "nope"]);
        let fake = FakeRunner::new()
            .strict()
            .respond(
                remove.clone(),
                toride_runner::CommandOutput::from_stdout("firefox removed\n"),
            )
            .respond(
                absent.clone(),
                toride_runner::CommandOutput::from_stderr("snap \"nope\" is not installed\n", 0),
            );
        let backend = backend(&fake);
        let target = linux_target();
        backend
            .uninstall_sync(UninstallRequest::new(&default_uninstall_plan(), &target))
            .unwrap();
        let outcome = backend
            .uninstall_sync(UninstallRequest::new(
                &uninstall_plan(Operation::SnapUninstall {
                    name: "nope".to_owned(),
                }),
                &target,
            ))
            .unwrap();
        assert!(
            outcome.detail.contains("(already absent)"),
            "{}",
            outcome.detail
        );
        fake.assert_called_with(&remove);
        fake.assert_called_with(&absent);
    }

    #[test]
    fn update_sync_runs_refresh_exactly() {
        let spec = command(SNAP, ["refresh", "firefox"]);
        let fake = FakeRunner::new()
            .strict()
            .respond(spec.clone(), toride_runner::CommandOutput::from_stdout(""));
        let backend = backend(&fake);
        let target = linux_target();
        backend
            .update_sync(UpdateRequest::new(&default_update_plan(), &target))
            .unwrap();
        fake.assert_called_with(&spec);
        fake.assert_no_unmatched_calls();
    }

    #[test]
    fn list_entries_sync_and_status_sync_read_the_listings() {
        let fake = FakeRunner::new()
            .strict()
            .respond(
                command(SNAP, ["list"]),
                toride_runner::CommandOutput::from_stdout(listing_output()),
            )
            .respond(
                command(SNAP, ["list", "firefox"]),
                toride_runner::CommandOutput::from_stdout(
                    "Name      Version    Rev   Tracking       Publisher  Notes\n\
                     firefox   139.0.4-1  4842  latest/stable  Mozilla✓   -\n",
                ),
            );
        let backend = backend(&fake);
        let entries = backend.list_entries_sync().unwrap();
        assert_eq!(entries.len(), 4, "{entries:?}");
        assert_eq!(
            backend.status_sync(StatusQuery::new("firefox")).unwrap(),
            BackendStatus::Installed {
                version: Some("139.0.4-1".to_owned())
            }
        );
    }

    #[test]
    fn outdated_sync_reads_the_refresh_list() {
        let fake = FakeRunner::new().strict().respond(
            command(SNAP, ["refresh", "--list"]),
            toride_runner::CommandOutput::from_stdout(refresh_output()),
        );
        let backend = backend(&fake);
        let entries = backend.outdated_sync().unwrap();
        assert_eq!(entries.len(), 2, "{entries:?}");
    }
}
