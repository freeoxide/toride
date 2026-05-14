use async_trait::async_trait;
use crate::modules::*;
use crate::tui::model::{Category, ModuleId};

pub struct Mise;

#[async_trait]
impl SetupModule for Mise {
    fn id(&self) -> ModuleId { ModuleId::Mise }
    fn name(&self) -> &'static str { "Language Runtimes (mise)" }
    fn description(&self) -> &'static str { "Install mise and configure Node, Bun, Deno, Go, Rust, Python" }
    fn dependencies(&self) -> Vec<ModuleId> { vec![] }
    fn conflicts(&self) -> Vec<ModuleId> { vec![] }
    fn category(&self) -> Category { Category::DeveloperRuntimes }

    async fn preflight(&self, _ctx: &Context) -> ModuleResult<PreflightResult> {
        Ok(PreflightResult::Ok)
    }

    async fn plan(&self, ctx: &Context) -> ModuleResult<Vec<InstallAction>> {
        let user = &ctx.target_user;
        let install_prefix = format!("/home/{}/.local/share/mise", user);

        let mut actions = vec![
            InstallAction::DownloadScript {
                url: "https://mise.run".into(),
                sha256: String::new(),
                run_as: user.clone(),
                env: vec![("MISE_DATA_DIR".into(), format!("{}/data", install_prefix))],
            },
        ];

        for (tool, version) in [
            ("node", "lts"),
            ("bun", "latest"),
            ("deno", "latest"),
            ("go", "latest"),
            ("rust", "stable"),
            ("python", "3.12"),
        ] {
            actions.push(InstallAction::Exec {
                cmd: format!("/home/{}/.local/bin/mise", user),
                args: vec!["install".into(), format!("{}@{}", tool, version)],
                env: vec![],
                as_user: Some(user.clone()),
            });
            actions.push(InstallAction::Exec {
                cmd: format!("/home/{}/.local/bin/mise", user),
                args: vec!["global".into(), format!("{}@{}", tool, version)],
                env: vec![],
                as_user: Some(user.clone()),
            });
        }

        // activate in shell
        actions.push(InstallAction::AppendLine {
            path: format!("/home/{}/.bashrc", user),
            line: r#"eval "$(~/.local/bin/mise activate bash)""#.into(),
            marker: "toride-mise".into(),
        });

        Ok(actions)
    }

    async fn apply(&self, ctx: &Context, tx: ProgressTx) -> ModuleResult<ApplyOutcome> {
        let actions = self.plan(ctx).await?;
        crate::executor::command::execute_actions(&actions, &tx, ctx.is_dry_run).await
    }

    async fn verify(&self, _ctx: &Context) -> ModuleResult<VerifyResult> {
        if which::which("mise").is_ok() {
            Ok(VerifyResult::Installed)
        } else {
            Ok(VerifyResult::NotInstalled)
        }
    }
}
