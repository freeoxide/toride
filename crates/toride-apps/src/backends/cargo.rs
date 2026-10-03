//! # cargo backend (`cargo`)
//!
//! [`CargoBackend`] executes the planner's [`Operation::CargoInstall`] /
//! [`Operation::CargoUninstall`] / [`Operation::CargoUpdate`] operations
//! through the shared [`CommandRunner`] seam and answers list queries from
//! `cargo install --list`. Availability rides `cargo info --color never` —
//! the registry-index query answers the exact crate's current version (where
//! `cargo search` is relevance-ranked over the rate-limited search API), and
//! the flag keeps the name and `version:` rows parseable under a forced-color
//! `CARGO_TERM_COLOR`; the cargo CLI has no version-listing verb, so only the
//! offered latest is reported.
//!
//! [`Operation::CargoInstall`]: crate::Operation::CargoInstall
//! [`Operation::CargoUninstall`]: crate::Operation::CargoUninstall
//! [`Operation::CargoUpdate`]: crate::Operation::CargoUpdate

use async_trait::async_trait;

use crate::backend::{
    Backend, BackendId, InstallOutcome, InstallRequest, InstalledApp, ListQuery, UninstallOutcome,
    UninstallRequest, UpdateRequest, Version, ensure_install_allowed, ensure_uninstall_allowed,
    ensure_update_allowed,
};
use crate::error::{Error, Result};
use crate::plan::{Operation, Target};
use crate::runner::{CommandRunner, command};

const CARGO: &str = "cargo";

/// cargo [`Backend`]: runs cargo crate installs/uninstalls and parses the
/// `cargo install --list` and `cargo info` output shapes.
pub struct CargoBackend {
    runner: CommandRunner,
}

impl CargoBackend {
    /// Create the backend over an explicit seam, with no host assumptions —
    /// the test-friendly constructor.
    #[must_use]
    pub fn new(runner: CommandRunner) -> Self {
        Self { runner }
    }

    /// Create the backend after verifying `cargo` is on the host `$PATH` (no
    /// command is executed).
    ///
    /// # Errors
    ///
    /// [`Error::Command`] wrapping `BinaryNotFound` when `cargo` is not on
    /// the PATH.
    pub fn detect(runner: CommandRunner) -> Result<Self> {
        let _path = toride_runner::discovery::find_binary(CARGO)?;
        Ok(Self::new(runner))
    }

    async fn installed_apps(&self) -> Result<Vec<InstalledApp>> {
        let spec = command(CARGO, ["install", "--list"]);
        let output = self.runner.run_checked(spec).await?;
        parse_cargo_list(&output.stdout)
    }

    fn installed_apps_sync(&self) -> Result<Vec<InstalledApp>> {
        let spec = command(CARGO, ["install", "--list"]);
        let output = self.runner.run_checked_sync(spec)?;
        parse_cargo_list(&output.stdout)
    }
}

#[async_trait]
impl Backend for CargoBackend {
    fn id(&self) -> BackendId {
        BackendId::Cargo
    }

    fn supports(&self, _target: &Target) -> bool {
        true
    }

    async fn install(&self, request: InstallRequest<'_>) -> Result<InstallOutcome> {
        ensure_install_allowed(&request)?;
        let Operation::CargoInstall { .. } = &request.plan.operation else {
            return Err(misrouted_operation(&request.plan.operation));
        };
        self.runner
            .run_checked(request.plan.operation.command_spec())
            .await?;
        Ok(InstallOutcome {
            version: None,
            detail: request.plan.operation.description(),
        })
    }

    async fn uninstall(&self, request: UninstallRequest<'_>) -> Result<UninstallOutcome> {
        ensure_uninstall_allowed(&request)?;
        let Operation::CargoUninstall { .. } = &request.plan.operation else {
            return Err(misrouted_operation(&request.plan.operation));
        };
        self.runner
            .run_checked(request.plan.operation.command_spec())
            .await?;
        Ok(UninstallOutcome {
            detail: request.plan.operation.description(),
        })
    }

    async fn update(&self, request: UpdateRequest<'_>) -> Result<()> {
        ensure_update_allowed(&request)?;
        let Operation::CargoUpdate { .. } = &request.plan.operation else {
            return Err(misrouted_operation(&request.plan.operation));
        };
        self.runner
            .run_checked(request.plan.operation.command_spec())
            .await?;
        Ok(())
    }

    async fn list_installed(&self, query: ListQuery) -> Result<Vec<InstalledApp>> {
        Ok(self
            .installed_apps()
            .await?
            .into_iter()
            .filter(|app| query.ids.is_empty() || query.ids.contains(&app.id))
            .collect())
    }

    async fn available_version(&self, id: &str) -> Result<Option<Version>> {
        let spec = command(CARGO, ["info", "--color", "never", id]);
        let output = self.runner.run_checked(spec).await?;
        Ok(Some(parse_cargo_info(&output.stdout, id)?))
    }

    fn install_sync(&self, request: InstallRequest<'_>) -> Result<InstallOutcome> {
        ensure_install_allowed(&request)?;
        let Operation::CargoInstall { .. } = &request.plan.operation else {
            return Err(misrouted_operation(&request.plan.operation));
        };
        self.runner
            .run_checked_sync(request.plan.operation.command_spec())?;
        Ok(InstallOutcome {
            version: None,
            detail: request.plan.operation.description(),
        })
    }

    fn uninstall_sync(&self, request: UninstallRequest<'_>) -> Result<UninstallOutcome> {
        ensure_uninstall_allowed(&request)?;
        let Operation::CargoUninstall { .. } = &request.plan.operation else {
            return Err(misrouted_operation(&request.plan.operation));
        };
        self.runner
            .run_checked_sync(request.plan.operation.command_spec())?;
        Ok(UninstallOutcome {
            detail: request.plan.operation.description(),
        })
    }

    fn update_sync(&self, request: UpdateRequest<'_>) -> Result<()> {
        ensure_update_allowed(&request)?;
        let Operation::CargoUpdate { .. } = &request.plan.operation else {
            return Err(misrouted_operation(&request.plan.operation));
        };
        self.runner
            .run_checked_sync(request.plan.operation.command_spec())?;
        Ok(())
    }

    fn list_installed_sync(&self, query: ListQuery) -> Result<Vec<InstalledApp>> {
        Ok(self
            .installed_apps_sync()?
            .into_iter()
            .filter(|app| query.ids.is_empty() || query.ids.contains(&app.id))
            .collect())
    }

    fn available_version_sync(&self, id: &str) -> Result<Option<Version>> {
        let spec = command(CARGO, ["info", "--color", "never", id]);
        let output = self.runner.run_checked_sync(spec)?;
        Ok(Some(parse_cargo_info(&output.stdout, id)?))
    }
}

fn parse_cargo_list(stdout: &str) -> Result<Vec<InstalledApp>> {
    let mut apps = Vec::new();
    for line in stdout.lines() {
        if line.trim().is_empty() || line.starts_with(char::is_whitespace) {
            continue;
        }
        let mut tokens = line.split_whitespace();
        if let (Some(id), Some(raw)) = (tokens.next(), tokens.next())
            && let Some(version) = raw
                .strip_prefix('v')
                .map(|version| version.trim_end_matches(':'))
        {
            apps.push(InstalledApp {
                id: id.to_owned(),
                version: Some(version.to_owned()),
            });
        }
    }
    if !stdout.trim().is_empty() && apps.is_empty() {
        return Err(output_parse_error(
            "cargo install --list",
            format_args!("no parseable crate rows in {stdout:?}"),
        ));
    }
    Ok(apps)
}

fn parse_cargo_info(stdout: &str, crate_: &str) -> Result<Version> {
    let mut lines = stdout.lines().map(str::trim);
    if lines.next() != Some(crate_) {
        return Err(output_parse_error(
            "cargo info",
            format_args!("the leading crate row is not `{crate_}` in {stdout:?}"),
        ));
    }
    for line in lines {
        let Some(version) = line.strip_prefix("version:").map(str::trim) else {
            continue;
        };
        if version.is_empty() || version.contains(char::is_whitespace) {
            continue;
        }
        return Ok(Version::new(version));
    }
    Err(output_parse_error(
        "cargo info",
        format_args!("no `version:` row in {stdout:?}"),
    ))
}

fn misrouted_operation(operation: &Operation) -> Error {
    Error::Command(toride_runner::Error::Other(format!(
        "cargo backend cannot execute non-cargo operation: {operation:?}"
    )))
}

fn output_parse_error(cargo_command: &str, cause: impl std::fmt::Display) -> Error {
    Error::Command(toride_runner::Error::OutputParse(format!(
        "{cargo_command}: {cause}"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use toride_registry::TorideId;
    use toride_runner::fake::FakeRunner;

    fn backend(fake: &FakeRunner) -> CargoBackend {
        CargoBackend::new(CommandRunner::new(Arc::new(fake.clone())))
    }

    fn list_spec() -> toride_runner::CommandSpec {
        command(CARGO, ["install", "--list"])
    }

    fn install_plan(operation: Operation) -> crate::plan::InstallPlan {
        crate::plan::InstallPlan {
            app: TorideId::slugify("ripgrep"),
            backend: BackendId::Cargo,
            operation,
            dry_run: false,
            requires_elevation: false,
        }
    }

    fn update_plan(operation: Operation) -> crate::plan::UpdatePlan {
        crate::plan::UpdatePlan {
            app: TorideId::slugify("ripgrep"),
            backend: BackendId::Cargo,
            operation,
            dry_run: false,
            requires_elevation: false,
        }
    }

    fn target() -> Target {
        Target::host()
    }

    #[test]
    fn parse_cargo_list_reads_crate_rows_and_skips_binary_rows() {
        let apps =
            parse_cargo_list("ripgrep v14.1.0:\n    rg\nbacon v2.4.0:\n    bacon\n").unwrap();
        assert_eq!(
            apps,
            [
                InstalledApp {
                    id: "ripgrep".to_owned(),
                    version: Some("14.1.0".to_owned())
                },
                InstalledApp {
                    id: "bacon".to_owned(),
                    version: Some("2.4.0".to_owned())
                }
            ]
        );
    }

    #[test]
    fn parse_cargo_list_keeps_rows_carrying_a_source_annotation() {
        let apps = parse_cargo_list(
            "cargo-update v11.0.2 (from git+https://github.com/nabijaczleweli/cargo-update#7c2b4c1):\n    cargo-install-update\n",
        )
        .unwrap();
        assert_eq!(
            apps,
            [InstalledApp {
                id: "cargo-update".to_owned(),
                version: Some("11.0.2".to_owned())
            }],
            "a git/path-sourced install is present, never silently absent"
        );
    }

    #[test]
    fn parse_cargo_list_skips_malformed_rows_without_failing_the_listing() {
        let apps = parse_cargo_list("garbage line\nripgrep v14.1.0:\n    rg\n").unwrap();
        assert_eq!(
            apps,
            [InstalledApp {
                id: "ripgrep".to_owned(),
                version: Some("14.1.0".to_owned())
            }]
        );
    }

    #[test]
    fn parse_cargo_list_returns_an_empty_listing_for_empty_output() {
        assert_eq!(parse_cargo_list("").unwrap(), Vec::new());
    }

    #[test]
    fn parse_cargo_list_errors_when_nothing_in_a_non_empty_document_parses() {
        let error = parse_cargo_list("nothing here resembles a crate row").unwrap_err();
        assert!(
            matches!(error, Error::Command(toride_runner::Error::OutputParse(_))),
            "{error:?}"
        );
    }

    #[test]
    fn parse_cargo_info_reads_the_leading_crate_row_and_the_version_row() {
        let stdout = concat!(
            "ripgrep\n",
            "ripgrep is a line-oriented search tool that recursively searches\n",
            "version: 15.2.0\n",
            "license: MIT OR UNLICENSE\n",
        );
        assert_eq!(
            parse_cargo_info(stdout, "ripgrep").unwrap(),
            Version::new("15.2.0")
        );
    }

    #[test]
    fn parse_cargo_info_answers_after_a_description_that_names_no_version_row() {
        let stdout = concat!("ripgrep\n", "a tool that searches\n", "version: 15.2.0\n");
        assert_eq!(
            parse_cargo_info(stdout, "ripgrep").unwrap(),
            Version::new("15.2.0")
        );
    }

    #[test]
    fn parse_cargo_info_errors_on_a_leading_row_for_another_crate() {
        let error = parse_cargo_info("gist-search\nversion: 1.3.1\n", "ripgrep").unwrap_err();
        assert!(
            matches!(error, Error::Command(toride_runner::Error::OutputParse(_))),
            "{error:?}"
        );
    }

    #[test]
    fn parse_cargo_info_skips_a_description_disguised_as_the_version_row() {
        let stdout = concat!(
            "ripgrep\n",
            "version: prints file names as it goes\n",
            "version: 15.2.0\n",
        );
        assert_eq!(
            parse_cargo_info(stdout, "ripgrep").unwrap(),
            Version::new("15.2.0")
        );
    }

    #[test]
    fn parse_cargo_info_errors_when_no_version_row_exists() {
        let error = parse_cargo_info("ripgrep\njust a name\n", "ripgrep").unwrap_err();
        assert!(
            matches!(error, Error::Command(toride_runner::Error::OutputParse(_))),
            "{error:?}"
        );
    }

    #[tokio::test]
    async fn install_refuses_dry_run_plans_without_touching_the_runner() {
        let fake = FakeRunner::new().strict();
        let backend = backend(&fake);
        let plan = install_plan(Operation::CargoInstall {
            crate_: "ripgrep".to_owned(),
            version: None,
        })
        .dry_run(true);
        let error = backend
            .install(InstallRequest::new(&plan, &target()))
            .await
            .unwrap_err();
        assert!(matches!(error, Error::DryRun { .. }), "{error:?}");
        assert!(fake.calls().is_empty(), "no cargo command may run");
    }

    #[tokio::test]
    async fn install_executes_the_planned_argv_with_the_version_flag() {
        let spec = command("cargo", ["install", "--version", "14.1.0", "ripgrep"]);
        let fake = FakeRunner::new().strict().respond(
            spec.clone(),
            toride_runner::CommandOutput::from_stdout("Installed package `ripgrep`"),
        );
        let backend = backend(&fake);
        let plan = install_plan(Operation::CargoInstall {
            crate_: "ripgrep".to_owned(),
            version: Some(Version::new("14.1.0")),
        });
        backend
            .install(InstallRequest::new(&plan, &target()))
            .await
            .unwrap();
        fake.assert_called_with(&spec);
    }

    #[tokio::test]
    async fn install_rejects_non_cargo_operations() {
        let fake = FakeRunner::new().strict();
        let backend = backend(&fake);
        let plan = install_plan(Operation::NpmInstall {
            package: "typescript".to_owned(),
            version: None,
            global: true,
        });
        let error = backend
            .install(InstallRequest::new(&plan, &target()))
            .await
            .unwrap_err();
        assert!(
            matches!(error, Error::Command(toride_runner::Error::Other(_))),
            "{error:?}"
        );
    }

    #[tokio::test]
    async fn update_runs_the_force_reinstall_argv() {
        let spec = command("cargo", ["install", "--force", "ripgrep"]);
        let fake = FakeRunner::new()
            .strict()
            .respond(spec.clone(), toride_runner::CommandOutput::from_stdout(""));
        let backend = backend(&fake);
        backend
            .update(UpdateRequest::new(
                &update_plan(Operation::CargoUpdate {
                    crate_: "ripgrep".to_owned(),
                }),
                &target(),
            ))
            .await
            .unwrap();
        fake.assert_called_with(&spec);
    }

    #[tokio::test]
    async fn list_installed_parses_and_filters_the_listing() {
        let fake = FakeRunner::new()
            .strict()
            .respond(
                list_spec(),
                toride_runner::CommandOutput::from_stdout("ripgrep v14.1.0:\n    rg\n"),
            )
            .respond(
                list_spec(),
                toride_runner::CommandOutput::from_stdout("ripgrep v14.1.0:\n    rg\n"),
            );
        let backend = backend(&fake);
        assert_eq!(
            backend
                .list_installed(ListQuery::id("ripgrep"))
                .await
                .unwrap(),
            [InstalledApp {
                id: "ripgrep".to_owned(),
                version: Some("14.1.0".to_owned())
            }]
        );
        assert_eq!(
            backend
                .list_installed(ListQuery::id("absent"))
                .await
                .unwrap(),
            Vec::new()
        );
        fake.assert_called_with(&list_spec());
    }

    #[tokio::test]
    async fn available_version_probes_cargo_info() {
        let spec = command("cargo", ["info", "--color", "never", "ripgrep"]);
        let fake = FakeRunner::new().strict().respond(
            spec.clone(),
            toride_runner::CommandOutput::from_stdout(
                "ripgrep\nline-oriented search tool\nversion: 15.2.0\n",
            ),
        );
        let backend = backend(&fake);
        assert_eq!(
            backend.available_version("ripgrep").await.unwrap(),
            Some(Version::new("15.2.0"))
        );
        fake.assert_called_with(&spec);
    }

    #[test]
    fn sync_twins_run_the_planned_argv_and_probes() {
        let install_spec = command("cargo", ["install", "ripgrep"]);
        let fake = FakeRunner::new()
            .strict()
            .respond(
                install_spec.clone(),
                toride_runner::CommandOutput::from_stdout(""),
            )
            .respond(
                list_spec(),
                toride_runner::CommandOutput::from_stdout("ripgrep v14.1.0:\n"),
            )
            .respond(
                command("cargo", ["info", "--color", "never", "ripgrep"]),
                toride_runner::CommandOutput::from_stdout("ripgrep\nversion: 15.2.0\n"),
            );
        let backend = backend(&fake);
        backend
            .install_sync(InstallRequest::new(
                &install_plan(Operation::CargoInstall {
                    crate_: "ripgrep".to_owned(),
                    version: None,
                }),
                &target(),
            ))
            .unwrap();
        fake.assert_called_with(&install_spec);
        assert_eq!(
            backend.list_installed_sync(ListQuery::all()).unwrap(),
            [InstalledApp {
                id: "ripgrep".to_owned(),
                version: Some("14.1.0".to_owned())
            }]
        );
        assert_eq!(
            backend.available_version_sync("ripgrep").unwrap(),
            Some(Version::new("15.2.0"))
        );
    }
}
