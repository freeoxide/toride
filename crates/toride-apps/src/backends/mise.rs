//! # mise backend (`mise`, delegating)
//!
//! [`MiseBackend`] is the delegating language-ecosystem backend: its async
//! operations delegate to a toride-mise [`Mise`] client (install via
//! `mise install <tool>@<version>` plus `mise use --global`, update via
//! `mise upgrade`, listing and stale-state via mise's `--json` verbs),
//! accepting the mise-binary requirement that delegation implies. The sync
//! twins dispatch the same canonical argv through this crate's
//! [`CommandRunner`] seam, so both runtimes drive the same mise CLI.
//!
//! [`Mise`]: toride_mise::Mise

use async_trait::async_trait;
use toride_mise::Mise;
use toride_mise::serde_utils::json_outputs::{LsOutput, OutdatedOutput};

use crate::backend::{
    Backend, BackendId, InstallOutcome, InstallRequest, InstalledApp, ListQuery, OutdatedEntry,
    UninstallOutcome, UninstallRequest, UpdateRequest, Version, ensure_install_allowed,
    ensure_uninstall_allowed, ensure_update_allowed,
};
use crate::error::{Error, Result};
use crate::plan::{Operation, Target};
use crate::runner::{CommandRunner, command};

const MISE: &str = "mise";

/// mise [`Backend`] delegating to a toride-mise client: install = `mise
/// install` + `mise use --global` (the tool's shims become the active
/// global default), uninstall/update through mise's own verbs, listing and
/// stale-state from mise's JSON output.
pub struct MiseBackend {
    mise: Mise,
    runner: CommandRunner,
}

impl MiseBackend {
    /// Create the backend over a toride-mise client (the async surface) and
    /// a command seam (the sync twins) — the test-friendly constructor.
    #[must_use]
    pub fn new(mise: Mise, runner: CommandRunner) -> Self {
        Self { mise, runner }
    }

    /// Create the backend after discovering a mise binary on the host
    /// `$PATH`. The toride-mise client defaults to a tokio-backed async
    /// runner; no command executes here.
    ///
    /// # Errors
    ///
    /// [`Error::Command`] wrapping `BinaryNotFound` when mise is not on the
    /// PATH.
    pub fn detect(runner: CommandRunner) -> Result<Self> {
        let mise = Mise::builder().build().map_err(mise_error)?;
        Ok(Self::new(mise, runner))
    }
}

#[async_trait]
impl Backend for MiseBackend {
    fn id(&self) -> BackendId {
        BackendId::Mise
    }

    fn supports(&self, _target: &Target) -> bool {
        true
    }

    async fn install(&self, request: InstallRequest<'_>) -> Result<InstallOutcome> {
        ensure_install_allowed(&request)?;
        let Operation::MiseInstall { tool, version } = &request.plan.operation else {
            return Err(misrouted_operation(&request.plan.operation));
        };
        let version = version
            .as_ref()
            .map_or("latest", |version| version.as_str());
        let helper = self.mise.tool(tool);
        helper.install(version).await.map_err(mise_error)?;
        helper.use_global(version).await.map_err(mise_error)?;
        Ok(InstallOutcome {
            version: None,
            detail: request.plan.operation.description(),
        })
    }

    async fn uninstall(&self, request: UninstallRequest<'_>) -> Result<UninstallOutcome> {
        ensure_uninstall_allowed(&request)?;
        let Operation::MiseUninstall { tool } = &request.plan.operation else {
            return Err(misrouted_operation(&request.plan.operation));
        };
        self.mise.uninstall(tool).await.map_err(mise_error)?;
        Ok(UninstallOutcome {
            detail: request.plan.operation.description(),
        })
    }

    async fn update(&self, request: UpdateRequest<'_>) -> Result<()> {
        ensure_update_allowed(&request)?;
        let Operation::MiseUpdate { tool } = &request.plan.operation else {
            return Err(misrouted_operation(&request.plan.operation));
        };
        self.mise.upgrade(Some(tool)).await.map_err(mise_error)?;
        Ok(())
    }

    async fn list_installed(&self, query: ListQuery) -> Result<Vec<InstalledApp>> {
        let output: LsOutput = self
            .mise
            .run_json(["ls", "--installed", "--json"])
            .await
            .map_err(mise_error)?;
        Ok(installed_from_ls(&output)
            .into_iter()
            .filter(|app| query.ids.is_empty() || query.ids.contains(&app.id))
            .collect())
    }

    async fn outdated(&self) -> Result<Vec<OutdatedEntry>> {
        let output = self.mise.outdated_map().await.map_err(mise_error)?;
        Ok(outdated_from_map(output))
    }

    async fn available_versions(&self, id: &str) -> Result<Vec<Version>> {
        let versions = self
            .mise
            .tool(id)
            .list_versions()
            .await
            .map_err(mise_error)?;
        Ok(versions.into_iter().map(Version::new).collect())
    }

    async fn available_version(&self, id: &str) -> Result<Option<Version>> {
        let output = self
            .mise
            .run_checked(["latest", id])
            .await
            .map_err(mise_error)?;
        parse_mise_latest(&output.stdout)
    }

    fn install_sync(&self, request: InstallRequest<'_>) -> Result<InstallOutcome> {
        ensure_install_allowed(&request)?;
        let Operation::MiseInstall { tool, version } = &request.plan.operation else {
            return Err(misrouted_operation(&request.plan.operation));
        };
        let spec = crate::plan::mise_spec(tool, version.as_ref());
        self.runner
            .run_checked_sync(command(MISE, ["install", &spec]))?;
        self.runner
            .run_checked_sync(command(MISE, ["use", "--global", &spec]))?;
        Ok(InstallOutcome {
            version: None,
            detail: request.plan.operation.description(),
        })
    }

    fn uninstall_sync(&self, request: UninstallRequest<'_>) -> Result<UninstallOutcome> {
        ensure_uninstall_allowed(&request)?;
        let Operation::MiseUninstall { tool } = &request.plan.operation else {
            return Err(misrouted_operation(&request.plan.operation));
        };
        self.runner
            .run_checked_sync(command(MISE, ["uninstall", tool]))?;
        Ok(UninstallOutcome {
            detail: request.plan.operation.description(),
        })
    }

    fn update_sync(&self, request: UpdateRequest<'_>) -> Result<()> {
        ensure_update_allowed(&request)?;
        let Operation::MiseUpdate { tool } = &request.plan.operation else {
            return Err(misrouted_operation(&request.plan.operation));
        };
        self.runner
            .run_checked_sync(command(MISE, ["upgrade", tool]))?;
        Ok(())
    }

    fn list_installed_sync(&self, query: ListQuery) -> Result<Vec<InstalledApp>> {
        let spec = command(MISE, ["ls", "--installed", "--json"]);
        let output = self.runner.run_checked_sync(spec)?;
        Ok(installed_from_ls(
            &serde_json::from_str(&output.stdout)
                .map_err(|error| output_parse_error("mise ls --installed --json", error))?,
        )
        .into_iter()
        .filter(|app| query.ids.is_empty() || query.ids.contains(&app.id))
        .collect())
    }

    fn outdated_sync(&self) -> Result<Vec<OutdatedEntry>> {
        let spec = command(MISE, ["outdated", "--json"]);
        let output = self.runner.run_checked_sync(spec)?;
        let parsed: OutdatedOutput = serde_json::from_str(&output.stdout)
            .map_err(|error| output_parse_error("mise outdated --json", error))?;
        Ok(outdated_from_map(parsed))
    }

    fn available_versions_sync(&self, id: &str) -> Result<Vec<Version>> {
        let spec = command(MISE, ["ls-remote", id]);
        let output = self.runner.run_checked_sync(spec)?;
        Ok(output
            .stdout
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(Version::new)
            .collect())
    }

    fn available_version_sync(&self, id: &str) -> Result<Option<Version>> {
        let spec = command(MISE, ["latest", id]);
        let output = self.runner.run_checked_sync(spec)?;
        parse_mise_latest(&output.stdout)
    }
}

fn installed_from_ls(output: &LsOutput) -> Vec<InstalledApp> {
    output
        .iter()
        .map(|(tool, entries)| {
            let version = entries
                .iter()
                .find(|entry| entry.active == Some(true))
                .or_else(|| entries.first())
                .and_then(|entry| entry.version.clone());
            InstalledApp {
                id: tool.clone(),
                version,
            }
        })
        .collect()
}

fn outdated_from_map(output: OutdatedOutput) -> Vec<OutdatedEntry> {
    output
        .into_iter()
        .map(|(tool, entry)| OutdatedEntry {
            id: tool,
            installed_versions: entry.current.into_iter().collect(),
            current_version: entry.latest,
            pinned: false,
        })
        .collect()
}

fn parse_mise_latest(stdout: &str) -> Result<Option<Version>> {
    stdout
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .map(|line| Some(Version::new(line)))
        .ok_or_else(|| {
            output_parse_error("mise latest", format_args!("no version line in {stdout:?}"))
        })
}

fn mise_error(error: toride_mise::MiseError) -> Error {
    match error {
        toride_mise::MiseError::BinaryNotFound => {
            Error::Command(toride_runner::Error::BinaryNotFound("mise".to_owned()))
        }
        error => Error::Command(toride_runner::Error::Other(format!("mise client: {error}"))),
    }
}

fn misrouted_operation(operation: &Operation) -> Error {
    Error::Command(toride_runner::Error::Other(format!(
        "mise backend cannot execute non-mise operation: {operation:?}"
    )))
}

fn output_parse_error(mise_command: &str, cause: impl std::fmt::Display) -> Error {
    Error::Command(toride_runner::Error::OutputParse(format!(
        "{mise_command}: {cause}"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use toride_registry::TorideId;
    use toride_runner::fake::FakeRunner;

    fn backend(fake: &FakeRunner) -> MiseBackend {
        let mise = Mise::builder()
            .runner(Arc::new(fake.clone()) as Arc<dyn toride_runner::AsyncRunner>)
            .binary(toride_mise::MiseBinary::from_path("mise"))
            .build()
            .unwrap();
        MiseBackend::new(mise, CommandRunner::new(Arc::new(fake.clone())))
    }

    fn mise_async_spec(args: &[&str]) -> toride_runner::CommandSpec {
        toride_runner::CommandSpec::new("mise")
            .args(args.to_vec())
            .redact(true)
    }

    fn install_plan(operation: Operation) -> crate::plan::InstallPlan {
        crate::plan::InstallPlan {
            app: TorideId::slugify("node"),
            backend: BackendId::Mise,
            operation,
            dry_run: false,
            requires_elevation: false,
        }
    }

    fn update_plan(operation: Operation) -> crate::plan::UpdatePlan {
        crate::plan::UpdatePlan {
            app: TorideId::slugify("node"),
            backend: BackendId::Mise,
            operation,
            dry_run: false,
            requires_elevation: false,
        }
    }

    fn target() -> Target {
        Target::host()
    }

    #[test]
    fn installed_from_ls_prefers_the_active_version_and_falls_back_to_first() {
        let output: LsOutput = serde_json::from_str(
            r#"{
  "node": [
    {"version": "20.0.0"},
    {"version": "22.1.0", "active": true}
  ],
  "python": [{"version": "3.11.0", "active": false}]
}"#,
        )
        .unwrap();
        assert_eq!(
            installed_from_ls(&output),
            [
                InstalledApp {
                    id: "node".to_owned(),
                    version: Some("22.1.0".to_owned())
                },
                InstalledApp {
                    id: "python".to_owned(),
                    version: Some("3.11.0".to_owned())
                }
            ]
        );
    }

    #[test]
    fn outdated_from_map_reads_current_latest_and_never_reports_a_pin() {
        let output: OutdatedOutput = serde_json::from_str(
            r#"{"python": {"requested": "3.11", "current": "3.11.0", "latest": "3.11.1"}}"#,
        )
        .unwrap();
        assert_eq!(
            outdated_from_map(output),
            [OutdatedEntry {
                id: "python".to_owned(),
                installed_versions: vec!["3.11.0".to_owned()],
                current_version: Some("3.11.1".to_owned()),
                pinned: false,
            }]
        );
    }

    #[tokio::test]
    async fn install_refuses_dry_run_plans_without_touching_the_client() {
        let fake = FakeRunner::new().strict();
        let backend = backend(&fake);
        let plan = install_plan(Operation::MiseInstall {
            tool: "node".to_owned(),
            version: None,
        })
        .dry_run(true);
        let error = backend
            .install(InstallRequest::new(&plan, &target()))
            .await
            .unwrap_err();
        assert!(matches!(error, Error::DryRun { .. }), "{error:?}");
        assert!(fake.calls().is_empty(), "no mise command may run");
    }

    #[tokio::test]
    async fn install_delegates_install_then_use_global_through_the_mise_client() {
        let fake = FakeRunner::new()
            .strict()
            .respond(
                mise_async_spec(&["install", "node@22.1.0"]),
                toride_runner::CommandOutput::from_stdout(""),
            )
            .respond(
                mise_async_spec(&["use", "--global", "node@22.1.0"]),
                toride_runner::CommandOutput::from_stdout(""),
            );
        let backend = backend(&fake);
        let plan = install_plan(Operation::MiseInstall {
            tool: "node".to_owned(),
            version: Some(Version::new("22.1.0")),
        });
        let outcome = backend
            .install(InstallRequest::new(&plan, &target()))
            .await
            .unwrap();
        fake.assert_called_with(&mise_async_spec(&["install", "node@22.1.0"]));
        fake.assert_called_with(&mise_async_spec(&["use", "--global", "node@22.1.0"]));
        assert_eq!(outcome.version, None);
        assert!(outcome.detail.contains("node@22.1.0"), "{}", outcome.detail);
    }

    #[tokio::test]
    async fn install_without_a_version_addresses_latest() {
        let fake = FakeRunner::new()
            .strict()
            .respond(
                mise_async_spec(&["install", "node@latest"]),
                toride_runner::CommandOutput::from_stdout(""),
            )
            .respond(
                mise_async_spec(&["use", "--global", "node@latest"]),
                toride_runner::CommandOutput::from_stdout(""),
            );
        let backend = backend(&fake);
        backend
            .install(InstallRequest::new(
                &install_plan(Operation::MiseInstall {
                    tool: "node".to_owned(),
                    version: None,
                }),
                &target(),
            ))
            .await
            .unwrap();
        fake.assert_called_with(&mise_async_spec(&["install", "node@latest"]));
        fake.assert_called_with(&mise_async_spec(&["use", "--global", "node@latest"]));
    }

    #[tokio::test]
    async fn install_rejects_non_mise_operations() {
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
        assert!(fake.calls().is_empty());
    }

    #[tokio::test]
    async fn uninstall_and_update_delegate_to_the_mise_client() {
        let fake = FakeRunner::new()
            .strict()
            .respond(
                mise_async_spec(&["uninstall", "node"]),
                toride_runner::CommandOutput::from_stdout(""),
            )
            .respond(
                mise_async_spec(&["upgrade", "node"]),
                toride_runner::CommandOutput::from_stdout(""),
            );
        let backend = backend(&fake);
        let target = target();
        let uninstall = crate::plan::UninstallPlan {
            app: TorideId::slugify("node"),
            backend: BackendId::Mise,
            operation: Operation::MiseUninstall {
                tool: "node".to_owned(),
            },
            dry_run: false,
            requires_elevation: false,
        };
        backend
            .uninstall(UninstallRequest::new(&uninstall, &target))
            .await
            .unwrap();
        backend
            .update(UpdateRequest::new(
                &update_plan(Operation::MiseUpdate {
                    tool: "node".to_owned(),
                }),
                &target,
            ))
            .await
            .unwrap();
        fake.assert_called_with(&mise_async_spec(&["uninstall", "node"]));
        fake.assert_called_with(&mise_async_spec(&["upgrade", "node"]));
    }

    #[tokio::test]
    async fn list_installed_outdated_and_version_probes_delegate_to_the_client() {
        let fake = FakeRunner::new()
            .strict()
            .respond(
                mise_async_spec(&["ls", "--installed", "--json"]),
                toride_runner::CommandOutput::from_stdout(
                    r#"{"node": [{"version": "22.1.0", "active": true}]}"#,
                ),
            )
            .respond(
                mise_async_spec(&["outdated", "--json"]),
                toride_runner::CommandOutput::from_stdout(
                    r#"{"node": {"current": "22.1.0", "latest": "22.2.0"}}"#,
                ),
            )
            .respond(
                mise_async_spec(&["ls-remote", "node"]),
                toride_runner::CommandOutput::from_stdout("20.0.0\n22.1.0\n22.2.0\n"),
            )
            .respond(
                mise_async_spec(&["latest", "node"]),
                toride_runner::CommandOutput::from_stdout("22.2.0\n"),
            );
        let backend = backend(&fake);
        assert_eq!(
            backend.list_installed(ListQuery::all()).await.unwrap(),
            [InstalledApp {
                id: "node".to_owned(),
                version: Some("22.1.0".to_owned())
            }]
        );
        let outdated = backend.outdated().await.unwrap();
        assert_eq!(outdated.len(), 1);
        assert_eq!(outdated[0].id, "node");
        assert_eq!(outdated[0].current_version.as_deref(), Some("22.2.0"));
        assert_eq!(
            backend.available_versions("node").await.unwrap(),
            [
                Version::new("20.0.0"),
                Version::new("22.1.0"),
                Version::new("22.2.0")
            ]
        );
        assert_eq!(
            backend.available_version("node").await.unwrap(),
            Some(Version::new("22.2.0"))
        );
    }

    #[tokio::test]
    async fn a_failing_client_command_maps_to_the_command_error() {
        let fake = FakeRunner::new().strict().respond_err(
            mise_async_spec(&["install", "node@latest"]),
            toride_runner::Error::CommandFailed {
                program: "mise".to_owned(),
                args: "install node@latest".to_owned(),
                exit_code: Some(1),
                stderr: "mise failed".to_owned(),
            },
        );
        let backend = backend(&fake);
        let plan = install_plan(Operation::MiseInstall {
            tool: "node".to_owned(),
            version: None,
        });
        let error = backend
            .install(InstallRequest::new(&plan, &target()))
            .await
            .unwrap_err();
        assert!(matches!(error, Error::Command(_)), "{error:?}");
    }

    #[test]
    fn sync_twins_run_the_canonical_argv_through_the_seam() {
        let install = command("mise", ["install", "node@22.1.0"]);
        let use_global = command("mise", ["use", "--global", "node@22.1.0"]);
        let upgrade = command("mise", ["upgrade", "node"]);
        let fake = FakeRunner::new()
            .strict()
            .respond(
                install.clone(),
                toride_runner::CommandOutput::from_stdout(""),
            )
            .respond(
                use_global.clone(),
                toride_runner::CommandOutput::from_stdout(""),
            )
            .respond(
                upgrade.clone(),
                toride_runner::CommandOutput::from_stdout(""),
            );
        let backend = backend(&fake);
        backend
            .install_sync(InstallRequest::new(
                &install_plan(Operation::MiseInstall {
                    tool: "node".to_owned(),
                    version: Some(Version::new("22.1.0")),
                }),
                &target(),
            ))
            .unwrap();
        backend
            .update_sync(UpdateRequest::new(
                &update_plan(Operation::MiseUpdate {
                    tool: "node".to_owned(),
                }),
                &target(),
            ))
            .unwrap();
        fake.assert_called_with(&install);
        fake.assert_called_with(&use_global);
        fake.assert_called_with(&upgrade);
    }

    #[test]
    fn sync_probes_mirror_the_async_ones() {
        let fake = FakeRunner::new()
            .strict()
            .respond(
                command("mise", ["ls", "--installed", "--json"]),
                toride_runner::CommandOutput::from_stdout(
                    r#"{"node": [{"version": "22.1.0", "active": true}]}"#,
                ),
            )
            .respond(
                command("mise", ["outdated", "--json"]),
                toride_runner::CommandOutput::from_stdout("{}"),
            )
            .respond(
                command("mise", ["ls-remote", "node"]),
                toride_runner::CommandOutput::from_stdout("22.1.0\n"),
            )
            .respond(
                command("mise", ["latest", "node"]),
                toride_runner::CommandOutput::from_stdout("22.2.0\n"),
            );
        let backend = backend(&fake);
        assert_eq!(
            backend.list_installed_sync(ListQuery::all()).unwrap(),
            [InstalledApp {
                id: "node".to_owned(),
                version: Some("22.1.0".to_owned())
            }]
        );
        assert!(backend.outdated_sync().unwrap().is_empty());
        assert_eq!(
            backend.available_versions_sync("node").unwrap(),
            [Version::new("22.1.0")]
        );
        assert_eq!(
            backend.available_version_sync("node").unwrap(),
            Some(Version::new("22.2.0"))
        );
    }
}
