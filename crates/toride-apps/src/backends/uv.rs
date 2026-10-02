//! # uv backend (`uv`)
//!
//! [`UvBackend`] executes the planner's [`Operation::UvInstall`] /
//! [`Operation::UvUninstall`] / [`Operation::UvUpdate`] operations through
//! the shared [`CommandRunner`] seam and answers list queries from
//! `uv tool list`. uv exposes no availability probe through its CLI, so the
//! trait's version-query defaults stand (nothing listed, unknown current).
//!
//! [`Operation::UvInstall`]: crate::Operation::UvInstall
//! [`Operation::UvUninstall`]: crate::Operation::UvUninstall
//! [`Operation::UvUpdate`]: crate::Operation::UvUpdate

use async_trait::async_trait;

use crate::backend::{
    Backend, BackendId, InstallOutcome, InstallRequest, InstalledApp, ListQuery, UninstallOutcome,
    UninstallRequest, UpdateRequest, ensure_install_allowed, ensure_uninstall_allowed,
    ensure_update_allowed,
};
use crate::error::{Error, Result};
use crate::plan::{Operation, Target};
use crate::runner::{CommandRunner, command};

const UV: &str = "uv";

/// uv [`Backend`]: runs uv tool installs/uninstalls/upgrades and parses the
/// `uv tool list` text listing.
pub struct UvBackend {
    runner: CommandRunner,
}

impl UvBackend {
    /// Create the backend over an explicit seam, with no host assumptions —
    /// the test-friendly constructor.
    #[must_use]
    pub fn new(runner: CommandRunner) -> Self {
        Self { runner }
    }

    /// Create the backend after verifying `uv` is on the host `$PATH` (no
    /// command is executed).
    ///
    /// # Errors
    ///
    /// [`Error::Command`] wrapping `BinaryNotFound` when `uv` is not on the
    /// PATH.
    pub fn detect(runner: CommandRunner) -> Result<Self> {
        let _path = toride_runner::discovery::find_binary(UV)?;
        Ok(Self::new(runner))
    }

    async fn installed_apps(&self) -> Result<Vec<InstalledApp>> {
        let spec = command(UV, ["tool", "list"]);
        let output = self.runner.run_checked(spec).await?;
        Ok(parse_uv_list(&output.stdout))
    }

    fn installed_apps_sync(&self) -> Result<Vec<InstalledApp>> {
        let spec = command(UV, ["tool", "list"]);
        let output = self.runner.run_checked_sync(spec)?;
        Ok(parse_uv_list(&output.stdout))
    }
}

#[async_trait]
impl Backend for UvBackend {
    fn id(&self) -> BackendId {
        BackendId::Uv
    }

    fn supports(&self, _target: &Target) -> bool {
        true
    }

    async fn install(&self, request: InstallRequest<'_>) -> Result<InstallOutcome> {
        ensure_install_allowed(&request)?;
        let Operation::UvInstall { .. } = &request.plan.operation else {
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
        let Operation::UvUninstall { .. } = &request.plan.operation else {
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
        let Operation::UvUpdate { .. } = &request.plan.operation else {
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
        let Operation::UvInstall { .. } = &request.plan.operation else {
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
        let Operation::UvUninstall { .. } = &request.plan.operation else {
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
        let Operation::UvUpdate { .. } = &request.plan.operation else {
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

fn parse_uv_list(stdout: &str) -> Vec<InstalledApp> {
    stdout
        .lines()
        .filter(|line| !line.starts_with(char::is_whitespace))
        .filter(|line| !line.starts_with('-'))
        .filter_map(|line| {
            let mut tokens = line.split_whitespace();
            let id = tokens.next()?;
            let version = tokens.next()?;
            if tokens.next().is_some() {
                return None;
            }
            let version = version.strip_prefix('v')?;
            Some(InstalledApp {
                id: id.to_owned(),
                version: (!version.is_empty()).then(|| version.to_owned()),
            })
        })
        .collect()
}

fn misrouted_operation(operation: &Operation) -> Error {
    Error::Command(toride_runner::Error::Other(format!(
        "uv backend cannot execute non-uv operation: {operation:?}"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::Version;
    use std::sync::Arc;
    use toride_registry::TorideId;
    use toride_runner::fake::FakeRunner;

    fn backend(fake: &FakeRunner) -> UvBackend {
        UvBackend::new(CommandRunner::new(Arc::new(fake.clone())))
    }

    fn list_spec() -> toride_runner::CommandSpec {
        command(UV, ["tool", "list"])
    }

    fn install_plan(operation: Operation) -> crate::plan::InstallPlan {
        crate::plan::InstallPlan {
            app: TorideId::slugify("ruff"),
            backend: BackendId::Uv,
            operation,
            dry_run: false,
            requires_elevation: false,
        }
    }

    fn target() -> Target {
        Target::host()
    }

    #[test]
    fn parse_uv_list_reads_tool_rows_and_skips_executable_rows() {
        let apps = parse_uv_list("ruff v0.4.4\n- ruff\npyright v1.1.360\n  - pyright\n");
        assert_eq!(
            apps,
            [
                InstalledApp {
                    id: "ruff".to_owned(),
                    version: Some("0.4.4".to_owned())
                },
                InstalledApp {
                    id: "pyright".to_owned(),
                    version: Some("1.1.360".to_owned())
                }
            ]
        );
    }

    #[test]
    fn parse_uv_list_skips_rows_without_the_version_token_shape() {
        let apps = parse_uv_list("No tools installed\nruff v0.4.4\n");
        assert_eq!(
            apps,
            [InstalledApp {
                id: "ruff".to_owned(),
                version: Some("0.4.4".to_owned())
            }],
            "uv's empty-listing wording never reads as a tool"
        );
        assert!(parse_uv_list("plain words only\n").is_empty());
        assert!(parse_uv_list("").is_empty());
    }

    #[tokio::test]
    async fn install_refuses_dry_run_plans_without_touching_the_runner() {
        let fake = FakeRunner::new().strict();
        let backend = backend(&fake);
        let plan = install_plan(Operation::UvInstall {
            package: "ruff".to_owned(),
            version: None,
        })
        .dry_run(true);
        let error = backend
            .install(InstallRequest::new(&plan, &target()))
            .await
            .unwrap_err();
        assert!(matches!(error, Error::DryRun { .. }), "{error:?}");
        assert!(fake.calls().is_empty(), "no uv command may run");
    }

    #[tokio::test]
    async fn install_executes_the_planned_argv_with_the_pinned_spec() {
        let spec = command("uv", ["tool", "install", "ruff==0.4.4"]);
        let fake = FakeRunner::new().strict().respond(
            spec.clone(),
            toride_runner::CommandOutput::from_stdout("Installed ruff"),
        );
        let backend = backend(&fake);
        backend
            .install(InstallRequest::new(
                &install_plan(Operation::UvInstall {
                    package: "ruff".to_owned(),
                    version: Some(Version::new("0.4.4")),
                }),
                &target(),
            ))
            .await
            .unwrap();
        fake.assert_called_with(&spec);
    }

    #[tokio::test]
    async fn install_rejects_non_uv_operations() {
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
    async fn uninstall_update_and_list_run_their_planned_argv() {
        let uninstall_spec = command("uv", ["tool", "uninstall", "ruff"]);
        let update_spec = command("uv", ["tool", "upgrade", "ruff"]);
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
                toride_runner::CommandOutput::from_stdout("ruff v0.4.4\n- ruff\n"),
            );
        let backend = backend(&fake);
        let target = target();
        let uninstall = crate::plan::UninstallPlan {
            app: TorideId::slugify("ruff"),
            backend: BackendId::Uv,
            operation: Operation::UvUninstall {
                package: "ruff".to_owned(),
            },
            dry_run: false,
            requires_elevation: false,
        };
        backend
            .uninstall(UninstallRequest::new(&uninstall, &target))
            .await
            .unwrap();
        let update = crate::plan::UpdatePlan {
            app: TorideId::slugify("ruff"),
            backend: BackendId::Uv,
            operation: Operation::UvUpdate {
                package: "ruff".to_owned(),
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
                id: "ruff".to_owned(),
                version: Some("0.4.4".to_owned())
            }]
        );
        fake.assert_called_with(&list_spec());
    }

    #[test]
    fn sync_twins_run_the_planned_argv_and_listing() {
        let install_spec = command("uv", ["tool", "install", "ruff"]);
        let fake = FakeRunner::new()
            .strict()
            .respond(
                install_spec.clone(),
                toride_runner::CommandOutput::from_stdout(""),
            )
            .respond(list_spec(), toride_runner::CommandOutput::from_stdout(""));
        let backend = backend(&fake);
        backend
            .install_sync(InstallRequest::new(
                &install_plan(Operation::UvInstall {
                    package: "ruff".to_owned(),
                    version: None,
                }),
                &target(),
            ))
            .unwrap();
        fake.assert_called_with(&install_spec);
        assert!(
            backend
                .list_installed_sync(ListQuery::all())
                .unwrap()
                .is_empty()
        );
    }
}
