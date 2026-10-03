//! # npm backend (`npm`)
//!
//! [`NpmBackend`] executes the planner's [`Operation::NpmInstall`] /
//! [`Operation::NpmUninstall`] / [`Operation::NpmUpdate`] operations through
//! the shared [`CommandRunner`] seam and answers list/version queries from
//! npm's own JSON output. The backend manages the **global** scope (`-g`) —
//! project-local dependencies belong to a project's package manager runs,
//! not to an app layer — while the operation's `global` flag stays the
//! caller's decision per operation.
//!
//! [`Operation::NpmInstall`]: crate::Operation::NpmInstall
//! [`Operation::NpmUninstall`]: crate::Operation::NpmUninstall
//! [`Operation::NpmUpdate`]: crate::Operation::NpmUpdate

use async_trait::async_trait;

use crate::backend::{
    Backend, BackendId, InstallOutcome, InstallRequest, InstalledApp, ListQuery, UninstallOutcome,
    UninstallRequest, UpdateRequest, Version, ensure_install_allowed, ensure_uninstall_allowed,
    ensure_update_allowed,
};
use crate::error::{Error, Result};
use crate::plan::{Operation, Target};
use crate::runner::{CommandRunner, command};

const NPM: &str = "npm";

/// npm [`Backend`]: runs global npm installs/uninstalls/updates and parses
/// npm's listing and registry-view JSON.
pub struct NpmBackend {
    runner: CommandRunner,
}

impl NpmBackend {
    /// Create the backend over an explicit seam, with no host assumptions —
    /// the test-friendly constructor.
    #[must_use]
    pub fn new(runner: CommandRunner) -> Self {
        Self { runner }
    }

    /// Create the backend after verifying `npm` is on the host `$PATH` (no
    /// command is executed).
    ///
    /// # Errors
    ///
    /// [`Error::Command`] wrapping `BinaryNotFound` when `npm` is not on the
    /// PATH.
    pub fn detect(runner: CommandRunner) -> Result<Self> {
        let _path = toride_runner::discovery::find_binary(NPM)?;
        Ok(Self::new(runner))
    }

    async fn installed_apps(&self) -> Result<Vec<InstalledApp>> {
        let spec = command(NPM, ["list", "--global", "--depth=0", "--json"]);
        let output = self.runner.run(spec).await?;
        listing_from_npm_output(&output)
    }

    fn installed_apps_sync(&self) -> Result<Vec<InstalledApp>> {
        let spec = command(NPM, ["list", "--global", "--depth=0", "--json"]);
        let output = self.runner.run_sync(spec)?;
        listing_from_npm_output(&output)
    }
}

#[async_trait]
impl Backend for NpmBackend {
    fn id(&self) -> BackendId {
        BackendId::Npm
    }

    fn supports(&self, _target: &Target) -> bool {
        true
    }

    async fn install(&self, request: InstallRequest<'_>) -> Result<InstallOutcome> {
        ensure_install_allowed(&request)?;
        let Operation::NpmInstall { .. } = &request.plan.operation else {
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
        let Operation::NpmUninstall { .. } = &request.plan.operation else {
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
        let Operation::NpmUpdate { .. } = &request.plan.operation else {
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

    async fn available_versions(&self, id: &str) -> Result<Vec<Version>> {
        let spec = command(NPM, ["view", id, "versions", "--json"]);
        let output = self.runner.run_checked(spec).await?;
        parse_npm_versions(&output.stdout)
    }

    async fn available_version(&self, id: &str) -> Result<Option<Version>> {
        let spec = command(NPM, ["view", id, "version"]);
        let output = self.runner.run_checked(spec).await?;
        parse_npm_latest(&output.stdout)
    }

    fn install_sync(&self, request: InstallRequest<'_>) -> Result<InstallOutcome> {
        ensure_install_allowed(&request)?;
        let Operation::NpmInstall { .. } = &request.plan.operation else {
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
        let Operation::NpmUninstall { .. } = &request.plan.operation else {
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
        let Operation::NpmUpdate { .. } = &request.plan.operation else {
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

    fn available_versions_sync(&self, id: &str) -> Result<Vec<Version>> {
        let spec = command(NPM, ["view", id, "versions", "--json"]);
        let output = self.runner.run_checked_sync(spec)?;
        parse_npm_versions(&output.stdout)
    }

    fn available_version_sync(&self, id: &str) -> Result<Option<Version>> {
        let spec = command(NPM, ["view", id, "version"]);
        let output = self.runner.run_checked_sync(spec)?;
        parse_npm_latest(&output.stdout)
    }
}

fn listing_from_npm_output(output: &toride_runner::CommandOutput) -> Result<Vec<InstalledApp>> {
    if output.stdout.trim().is_empty() {
        if output.success {
            return Ok(Vec::new());
        }
        return Err(Error::Command(toride_runner::Error::Other(format!(
            "npm list --global exited {:?} with no JSON document: {}",
            output.exit_code,
            output.stderr.trim()
        ))));
    }
    parse_npm_list(&output.stdout)
}

fn parse_npm_list(stdout: &str) -> Result<Vec<InstalledApp>> {
    if stdout.trim().is_empty() {
        return Ok(Vec::new());
    }
    let document: serde_json::Value = serde_json::from_str(stdout)
        .map_err(|error| output_parse_error("npm list --json", error))?;
    let Some(dependencies) = document
        .get("dependencies")
        .and_then(|value| value.as_object())
    else {
        return Ok(Vec::new());
    };
    Ok(dependencies
        .iter()
        .map(|(name, entry)| InstalledApp {
            id: name.clone(),
            version: entry
                .get("version")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned),
        })
        .collect())
}

fn parse_npm_versions(stdout: &str) -> Result<Vec<Version>> {
    let document: serde_json::Value = serde_json::from_str(stdout)
        .map_err(|error| output_parse_error("npm view versions --json", error))?;
    match document {
        serde_json::Value::Array(items) => Ok(items
            .into_iter()
            .filter_map(|item| item.as_str().map(Version::new))
            .collect()),
        serde_json::Value::String(version) => Ok(vec![Version::new(version)]),
        other => Err(output_parse_error(
            "npm view versions --json",
            format_args!("expected a JSON array of versions, got {other}"),
        )),
    }
}

fn parse_npm_latest(stdout: &str) -> Result<Option<Version>> {
    stdout
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .map(|line| Some(Version::new(line)))
        .ok_or_else(|| {
            output_parse_error(
                "npm view version",
                format_args!("no version line in {stdout:?}"),
            )
        })
}

fn misrouted_operation(operation: &Operation) -> Error {
    Error::Command(toride_runner::Error::Other(format!(
        "npm backend cannot execute non-npm operation: {operation:?}"
    )))
}

fn output_parse_error(npm_command: &str, cause: impl std::fmt::Display) -> Error {
    Error::Command(toride_runner::Error::OutputParse(format!(
        "{npm_command}: {cause}"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use toride_registry::TorideId;
    use toride_runner::fake::FakeRunner;

    fn backend(fake: &FakeRunner) -> NpmBackend {
        NpmBackend::new(CommandRunner::new(Arc::new(fake.clone())))
    }

    fn list_spec() -> toride_runner::CommandSpec {
        command(NPM, ["list", "--global", "--depth=0", "--json"])
    }

    fn install_plan(operation: Operation) -> crate::plan::InstallPlan {
        crate::plan::InstallPlan {
            app: TorideId::slugify("typescript"),
            backend: BackendId::Npm,
            operation,
            dry_run: false,
            requires_elevation: false,
        }
    }

    fn update_plan(operation: Operation) -> crate::plan::UpdatePlan {
        crate::plan::UpdatePlan {
            app: TorideId::slugify("typescript"),
            backend: BackendId::Npm,
            operation,
            dry_run: false,
            requires_elevation: false,
        }
    }

    fn uninstall_plan(operation: Operation) -> crate::plan::UninstallPlan {
        crate::plan::UninstallPlan {
            app: TorideId::slugify("typescript"),
            backend: BackendId::Npm,
            operation,
            dry_run: false,
            requires_elevation: false,
        }
    }

    fn target() -> Target {
        Target::host()
    }

    #[test]
    fn parse_npm_list_reads_the_dependencies_object() {
        let apps = parse_npm_list(
            r#"{
  "dependencies": {
    "typescript": { "version": "5.4.5", "resolved": "…" },
    "prettier": { "version": "3.2.5" }
  }
}"#,
        )
        .unwrap();
        assert_eq!(
            apps,
            [
                InstalledApp {
                    id: "prettier".to_owned(),
                    version: Some("3.2.5".to_owned())
                },
                InstalledApp {
                    id: "typescript".to_owned(),
                    version: Some("5.4.5".to_owned())
                }
            ],
            "the JSON object's keys arrive sorted"
        );
    }

    #[test]
    fn parse_npm_list_maps_a_missing_version_cell_to_none() {
        let apps =
            parse_npm_list(r#"{"dependencies": {"broken": {"problems": ["invalid"]}}}"#).unwrap();
        assert_eq!(
            apps,
            [InstalledApp {
                id: "broken".to_owned(),
                version: None
            }]
        );
    }

    #[test]
    fn parse_npm_list_takes_a_dependencies_free_document_as_empty() {
        assert_eq!(parse_npm_list("{}").unwrap(), Vec::new());
        assert_eq!(parse_npm_list("{\"name\":\"empty\"}").unwrap(), Vec::new());
        assert_eq!(parse_npm_list("").unwrap(), Vec::new());
    }

    #[test]
    fn parse_npm_list_errors_on_unparseable_non_empty_output() {
        let error = parse_npm_list("not json at all").unwrap_err();
        assert!(
            matches!(error, Error::Command(toride_runner::Error::OutputParse(_))),
            "{error:?}"
        );
    }

    #[test]
    fn parse_npm_versions_accepts_array_and_bare_string_shapes() {
        let versions = parse_npm_versions(r#"["5.3.3","5.4.5"]"#).unwrap();
        assert_eq!(versions, [Version::new("5.3.3"), Version::new("5.4.5")]);
        let single = parse_npm_versions("\"5.4.5\"").unwrap();
        assert_eq!(single, [Version::new("5.4.5")]);
    }

    #[test]
    fn parse_npm_versions_rejects_other_shapes() {
        let error = parse_npm_versions("{\"5.4.5\":true}").unwrap_err();
        assert!(
            matches!(error, Error::Command(toride_runner::Error::OutputParse(_))),
            "{error:?}"
        );
    }

    #[test]
    fn parse_npm_latest_takes_the_first_non_empty_line() {
        assert_eq!(
            parse_npm_latest("5.4.5\n").unwrap(),
            Some(Version::new("5.4.5"))
        );
        assert!(parse_npm_latest("  \n").is_err());
    }

    #[tokio::test]
    async fn install_refuses_dry_run_plans_without_touching_the_runner() {
        let fake = FakeRunner::new().strict();
        let backend = backend(&fake);
        let plan = install_plan(Operation::NpmInstall {
            package: "typescript".to_owned(),
            version: None,
            global: true,
        })
        .dry_run(true);
        let error = backend
            .install(InstallRequest::new(&plan, &target()))
            .await
            .unwrap_err();
        assert!(matches!(error, Error::DryRun { .. }), "{error:?}");
        assert!(fake.calls().is_empty(), "no npm command may run");
    }

    #[tokio::test]
    async fn install_executes_the_planned_argv_verbatim() {
        let spec = command("npm", ["install", "-g", "typescript@5.4.5"]);
        let fake = FakeRunner::new().strict().respond(
            spec.clone(),
            toride_runner::CommandOutput::from_stdout("added 1 package"),
        );
        let backend = backend(&fake);
        let plan = install_plan(Operation::NpmInstall {
            package: "typescript".to_owned(),
            version: Some(Version::new("5.4.5")),
            global: true,
        });
        let outcome = backend
            .install(InstallRequest::new(&plan, &target()))
            .await
            .unwrap();
        fake.assert_called_with(&spec);
        assert_eq!(outcome.version, None);
        assert!(
            outcome.detail.contains("typescript@5.4.5"),
            "{}",
            outcome.detail
        );
    }

    #[tokio::test]
    async fn install_rejects_non_npm_operations() {
        let fake = FakeRunner::new().strict();
        let backend = backend(&fake);
        let plan = install_plan(Operation::PipxInstall {
            package: "black".to_owned(),
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
    async fn uninstall_and_update_run_the_planned_argv() {
        let uninstall_spec = command("npm", ["uninstall", "-g", "typescript"]);
        let update_spec = command("npm", ["update", "-g", "typescript"]);
        let fake = FakeRunner::new()
            .strict()
            .respond(
                uninstall_spec.clone(),
                toride_runner::CommandOutput::from_stdout("removed 1 package"),
            )
            .respond(
                update_spec.clone(),
                toride_runner::CommandOutput::from_stdout(""),
            );
        let backend = backend(&fake);
        let target = target();
        backend
            .uninstall(UninstallRequest::new(
                &uninstall_plan(Operation::NpmUninstall {
                    package: "typescript".to_owned(),
                    global: true,
                }),
                &target,
            ))
            .await
            .unwrap();
        backend
            .update(UpdateRequest::new(
                &update_plan(Operation::NpmUpdate {
                    package: "typescript".to_owned(),
                    global: true,
                }),
                &target,
            ))
            .await
            .unwrap();
        fake.assert_called_with(&uninstall_spec);
        fake.assert_called_with(&update_spec);
    }

    #[tokio::test]
    async fn list_installed_parses_and_filters_the_global_listing() {
        let fake = FakeRunner::new()
            .strict()
            .respond(
                list_spec(),
                toride_runner::CommandOutput::from_stdout(
                    r#"{"dependencies": {"typescript": {"version": "5.4.5"}, "prettier": {"version": "3.2.5"}}}"#,
                ),
            )
            .respond(
                list_spec(),
                toride_runner::CommandOutput::from_stdout(
                    r#"{"dependencies": {"typescript": {"version": "5.4.5"}, "prettier": {"version": "3.2.5"}}}"#,
                ),
            );
        let backend = backend(&fake);
        let apps = backend
            .list_installed(ListQuery::id("typescript"))
            .await
            .unwrap();
        assert_eq!(
            apps,
            [InstalledApp {
                id: "typescript".to_owned(),
                version: Some("5.4.5".to_owned())
            }]
        );
        let all = backend.list_installed(ListQuery::all()).await.unwrap();
        assert_eq!(all.len(), 2);
        fake.assert_called_with(&list_spec());
    }

    #[tokio::test]
    async fn list_installed_answers_from_a_problems_tree_that_exits_one() {
        let document = r#"{
  "name": "lib",
  "problems": [
    "unmet dependency left-pad@^1.3.0"
  ],
  "dependencies": {
    "typescript": { "version": "5.4.5", "overridden": false },
    "broken": {
      "version": "1.0.0",
      "problems": ["UNMET DEPENDENCY left-pad@^1.3.0"]
    }
  }
}"#;
        let fake = FakeRunner::new()
            .strict()
            .respond(
                list_spec(),
                toride_runner::CommandOutput::new(document.to_owned(), String::new(), Some(1)),
            )
            .respond(
                list_spec(),
                toride_runner::CommandOutput::new(document.to_owned(), String::new(), Some(1)),
            );
        let backend = backend(&fake);
        let apps = backend.list_installed(ListQuery::all()).await.unwrap();
        assert_eq!(
            apps,
            [
                InstalledApp {
                    id: "broken".to_owned(),
                    version: Some("1.0.0".to_owned())
                },
                InstalledApp {
                    id: "typescript".to_owned(),
                    version: Some("5.4.5".to_owned())
                }
            ],
            "an ELSPROBLEMS exit never discards a complete document"
        );
        assert_eq!(
            backend.list_installed_sync(ListQuery::all()).unwrap(),
            apps,
            "the sync twin answers the same way"
        );
    }

    #[tokio::test]
    async fn list_installed_maps_a_failed_run_with_no_document_to_command_error() {
        let fake = FakeRunner::new().strict().respond(
            list_spec(),
            toride_runner::CommandOutput::from_stderr("npm ERR! code ELSPROBLEMS", 1),
        );
        let backend = backend(&fake);
        let error = backend.list_installed(ListQuery::all()).await.unwrap_err();
        assert!(matches!(error, Error::Command(_)), "{error:?}");
        assert!(error.to_string().contains("no JSON document"), "{error}");
    }

    #[tokio::test]
    async fn available_versions_and_version_probe_the_registry_view() {
        let versions_spec = command("npm", ["view", "typescript", "versions", "--json"]);
        let latest_spec = command("npm", ["view", "typescript", "version"]);
        let fake = FakeRunner::new()
            .strict()
            .respond(
                versions_spec.clone(),
                toride_runner::CommandOutput::from_stdout(r#"["5.3.3","5.4.5"]"#),
            )
            .respond(
                latest_spec.clone(),
                toride_runner::CommandOutput::from_stdout("5.4.5\n"),
            );
        let backend = backend(&fake);
        assert_eq!(
            backend.available_versions("typescript").await.unwrap(),
            [Version::new("5.3.3"), Version::new("5.4.5")]
        );
        assert_eq!(
            backend.available_version("typescript").await.unwrap(),
            Some(Version::new("5.4.5"))
        );
        fake.assert_called_with(&versions_spec);
        fake.assert_called_with(&latest_spec);
    }

    #[test]
    fn sync_twins_run_the_planned_argv_and_refuse_dry_runs() {
        let spec = command("npm", ["install", "-g", "typescript"]);
        let fake = FakeRunner::new().strict().respond(
            spec.clone(),
            toride_runner::CommandOutput::from_stdout("added 1 package"),
        );
        let backend = backend(&fake);
        backend
            .install_sync(InstallRequest::new(
                &install_plan(Operation::NpmInstall {
                    package: "typescript".to_owned(),
                    version: None,
                    global: true,
                }),
                &target(),
            ))
            .unwrap();
        fake.assert_called_with(&spec);

        let refusing = NpmBackend::new(CommandRunner::new(Arc::new(FakeRunner::new().strict())));
        let error = refusing
            .install_sync(InstallRequest::new(
                &install_plan(Operation::NpmInstall {
                    package: "typescript".to_owned(),
                    version: None,
                    global: true,
                })
                .dry_run(true),
                &target(),
            ))
            .unwrap_err();
        assert!(matches!(error, Error::DryRun { .. }), "{error:?}");
    }

    #[test]
    fn list_installed_sync_and_version_probes_mirror_the_async_ones() {
        let fake = FakeRunner::new()
            .strict()
            .respond(
                list_spec(),
                toride_runner::CommandOutput::from_stdout(
                    r#"{"dependencies": {"typescript": {"version": "5.4.5"}}}"#,
                ),
            )
            .respond(
                command("npm", ["view", "typescript", "versions", "--json"]),
                toride_runner::CommandOutput::from_stdout("\"5.4.5\""),
            )
            .respond(
                command("npm", ["view", "typescript", "version"]),
                toride_runner::CommandOutput::from_stdout("5.4.5\n"),
            );
        let backend = backend(&fake);
        assert_eq!(
            backend.list_installed_sync(ListQuery::all()).unwrap(),
            [InstalledApp {
                id: "typescript".to_owned(),
                version: Some("5.4.5".to_owned())
            }]
        );
        assert_eq!(
            backend.available_versions_sync("typescript").unwrap(),
            [Version::new("5.4.5")]
        );
        assert_eq!(
            backend.available_version_sync("typescript").unwrap(),
            Some(Version::new("5.4.5"))
        );
    }
}
