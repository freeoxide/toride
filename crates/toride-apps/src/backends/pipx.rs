//! # pipx backend (`pipx`)
//!
//! [`PipxBackend`] executes the planner's [`Operation::PipxInstall`] /
//! [`Operation::PipxUninstall`] / [`Operation::PipxUpdate`] operations
//! through the shared [`CommandRunner`] seam and answers list queries from
//! `pipx list --json`. pipx exposes no availability probe through its CLI,
//! so the trait's version-query defaults stand (nothing listed, unknown
//! current).
//!
//! [`Operation::PipxInstall`]: crate::Operation::PipxInstall
//! [`Operation::PipxUninstall`]: crate::Operation::PipxUninstall
//! [`Operation::PipxUpdate`]: crate::Operation::PipxUpdate

use async_trait::async_trait;

use crate::backend::{
    Backend, BackendId, InstallOutcome, InstallRequest, InstalledApp, ListQuery, UninstallOutcome,
    UninstallRequest, UpdateRequest, ensure_install_allowed, ensure_uninstall_allowed,
    ensure_update_allowed,
};
use crate::error::{Error, Result};
use crate::plan::{Operation, Target};
use crate::runner::{CommandRunner, command};

const PIPX: &str = "pipx";

/// pipx [`Backend`]: runs pipx package installs/uninstalls/upgrades and
/// parses the `pipx list --json` document.
pub struct PipxBackend {
    runner: CommandRunner,
}

impl PipxBackend {
    /// Create the backend over an explicit seam, with no host assumptions —
    /// the test-friendly constructor.
    #[must_use]
    pub fn new(runner: CommandRunner) -> Self {
        Self { runner }
    }

    /// Create the backend after verifying `pipx` is on the host `$PATH` (no
    /// command is executed).
    ///
    /// # Errors
    ///
    /// [`Error::Command`] wrapping `BinaryNotFound` when `pipx` is not on
    /// the PATH.
    pub fn detect(runner: CommandRunner) -> Result<Self> {
        let _path = toride_runner::discovery::find_binary(PIPX)?;
        Ok(Self::new(runner))
    }

    async fn installed_apps(&self) -> Result<Vec<InstalledApp>> {
        let spec = command(PIPX, ["list", "--json"]);
        let output = self.runner.run_checked(spec).await?;
        parse_pipx_list(&output.stdout)
    }

    fn installed_apps_sync(&self) -> Result<Vec<InstalledApp>> {
        let spec = command(PIPX, ["list", "--json"]);
        let output = self.runner.run_checked_sync(spec)?;
        parse_pipx_list(&output.stdout)
    }
}

#[async_trait]
impl Backend for PipxBackend {
    fn id(&self) -> BackendId {
        BackendId::Pipx
    }

    fn supports(&self, _target: &Target) -> bool {
        true
    }

    async fn install(&self, request: InstallRequest<'_>) -> Result<InstallOutcome> {
        ensure_install_allowed(&request)?;
        let Operation::PipxInstall { .. } = &request.plan.operation else {
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
        let Operation::PipxUninstall { .. } = &request.plan.operation else {
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
        let Operation::PipxUpdate { .. } = &request.plan.operation else {
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

    fn install_sync(&self, request: InstallRequest<'_>) -> Result<InstallOutcome> {
        ensure_install_allowed(&request)?;
        let Operation::PipxInstall { .. } = &request.plan.operation else {
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
        let Operation::PipxUninstall { .. } = &request.plan.operation else {
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
        let Operation::PipxUpdate { .. } = &request.plan.operation else {
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
}

fn parse_pipx_list(stdout: &str) -> Result<Vec<InstalledApp>> {
    if stdout.trim().is_empty() {
        return Ok(Vec::new());
    }
    let document: serde_json::Value = serde_json::from_str(stdout)
        .map_err(|error| output_parse_error("pipx list --json", error))?;
    let Some(venvs) = document.get("venvs").and_then(|value| value.as_object()) else {
        return Ok(Vec::new());
    };
    Ok(venvs
        .iter()
        .map(|(name, venv)| InstalledApp {
            id: name.clone(),
            version: venv
                .get("main_package")
                .and_then(|main| main.get("package_version"))
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned),
        })
        .collect())
}

fn misrouted_operation(operation: &Operation) -> Error {
    Error::Command(toride_runner::Error::Other(format!(
        "pipx backend cannot execute non-pipx operation: {operation:?}"
    )))
}

fn output_parse_error(pipx_command: &str, cause: impl std::fmt::Display) -> Error {
    Error::Command(toride_runner::Error::OutputParse(format!(
        "{pipx_command}: {cause}"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use toride_registry::TorideId;
    use toride_runner::fake::FakeRunner;

    fn backend(fake: &FakeRunner) -> PipxBackend {
        PipxBackend::new(CommandRunner::new(Arc::new(fake.clone())))
    }

    fn list_spec() -> toride_runner::CommandSpec {
        command(PIPX, ["list", "--json"])
    }

    fn install_plan(operation: Operation) -> crate::plan::InstallPlan {
        crate::plan::InstallPlan {
            app: TorideId::slugify("black"),
            backend: BackendId::Pipx,
            operation,
            dry_run: false,
            requires_elevation: false,
        }
    }

    fn target() -> Target {
        Target::host()
    }

    #[test]
    fn parse_pipx_list_reads_the_venvs_object() {
        let apps = parse_pipx_list(
            r#"{
  "pipx_spec_version": "0.3",
  "venvs": {
    "black": {
      "main_package": {
        "package": "black",
        "package_or_url": "black",
        "package_version": "24.3.0"
      }
    },
    "renamed-app": {
      "main_package": {
        "package": "real-name",
        "package_version": "1.0.0"
      }
    }
  }
}"#,
        )
        .unwrap();
        assert_eq!(
            apps,
            [
                InstalledApp {
                    id: "black".to_owned(),
                    version: Some("24.3.0".to_owned())
                },
                InstalledApp {
                    id: "renamed-app".to_owned(),
                    version: Some("1.0.0".to_owned())
                }
            ],
            "the venv key stays the id; the package name never overrides it"
        );
    }

    #[test]
    fn parse_pipx_list_takes_a_venvs_free_document_as_empty() {
        assert_eq!(
            parse_pipx_list(r#"{"pipx_spec_version":"0.3"}"#).unwrap(),
            Vec::new()
        );
        assert_eq!(parse_pipx_list("").unwrap(), Vec::new());
    }

    #[test]
    fn parse_pipx_list_errors_on_unparseable_non_empty_output() {
        let error = parse_pipx_list("venvs everywhere, none of it json").unwrap_err();
        assert!(
            matches!(error, Error::Command(toride_runner::Error::OutputParse(_))),
            "{error:?}"
        );
    }

    #[tokio::test]
    async fn install_refuses_dry_run_plans_without_touching_the_runner() {
        let fake = FakeRunner::new().strict();
        let backend = backend(&fake);
        let plan = install_plan(Operation::PipxInstall {
            package: "black".to_owned(),
        })
        .dry_run(true);
        let error = backend
            .install(InstallRequest::new(&plan, &target()))
            .await
            .unwrap_err();
        assert!(matches!(error, Error::DryRun { .. }), "{error:?}");
        assert!(fake.calls().is_empty(), "no pipx command may run");
    }

    #[tokio::test]
    async fn install_executes_the_planned_argv_verbatim() {
        let spec = command("pipx", ["install", "black"]);
        let fake = FakeRunner::new().strict().respond(
            spec.clone(),
            toride_runner::CommandOutput::from_stdout("installed black"),
        );
        let backend = backend(&fake);
        backend
            .install(InstallRequest::new(
                &install_plan(Operation::PipxInstall {
                    package: "black".to_owned(),
                }),
                &target(),
            ))
            .await
            .unwrap();
        fake.assert_called_with(&spec);
    }

    #[tokio::test]
    async fn install_rejects_non_pipx_operations() {
        let fake = FakeRunner::new().strict();
        let backend = backend(&fake);
        let plan = install_plan(Operation::UvInstall {
            package: "ruff".to_owned(),
            version: None,
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
    async fn uninstall_update_and_list_run_their_planned_argv() {
        let uninstall_spec = command("pipx", ["uninstall", "black"]);
        let update_spec = command("pipx", ["upgrade", "black"]);
        let fake = FakeRunner::new()
            .strict()
            .respond(
                uninstall_spec.clone(),
                toride_runner::CommandOutput::from_stdout(""),
            )
            .respond(
                update_spec.clone(),
                toride_runner::CommandOutput::from_stdout(""),
            )
            .respond(
                list_spec(),
                toride_runner::CommandOutput::from_stdout(
                    r#"{"venvs": {"black": {"main_package": {"package": "black", "package_version": "24.3.0"}}}}"#,
                ),
            );
        let backend = backend(&fake);
        let target = target();
        let uninstall = crate::plan::UninstallPlan {
            app: TorideId::slugify("black"),
            backend: BackendId::Pipx,
            operation: Operation::PipxUninstall {
                package: "black".to_owned(),
            },
            dry_run: false,
            requires_elevation: false,
        };
        backend
            .uninstall(UninstallRequest::new(&uninstall, &target))
            .await
            .unwrap();
        let update = crate::plan::UpdatePlan {
            app: TorideId::slugify("black"),
            backend: BackendId::Pipx,
            operation: Operation::PipxUpdate {
                package: "black".to_owned(),
            },
            dry_run: false,
            requires_elevation: false,
        };
        backend
            .update(UpdateRequest::new(&update, &target))
            .await
            .unwrap();
        fake.assert_called_with(&uninstall_spec);
        fake.assert_called_with(&update_spec);
        assert_eq!(
            backend.list_installed(ListQuery::all()).await.unwrap(),
            [InstalledApp {
                id: "black".to_owned(),
                version: Some("24.3.0".to_owned())
            }]
        );
        fake.assert_called_with(&list_spec());
    }

    #[test]
    fn sync_twins_run_the_planned_argv_and_listing() {
        let install_spec = command("pipx", ["install", "black"]);
        let fake = FakeRunner::new()
            .strict()
            .respond(
                install_spec.clone(),
                toride_runner::CommandOutput::from_stdout(""),
            )
            .respond(list_spec(), toride_runner::CommandOutput::from_stdout("{}"));
        let backend = backend(&fake);
        backend
            .install_sync(InstallRequest::new(
                &install_plan(Operation::PipxInstall {
                    package: "black".to_owned(),
                }),
                &target(),
            ))
            .unwrap();
        fake.assert_called_with(&install_spec);
        assert_eq!(
            backend.list_installed_sync(ListQuery::all()).unwrap(),
            Vec::new()
        );
    }
}
