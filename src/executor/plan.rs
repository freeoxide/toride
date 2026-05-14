use crate::tui::model::{ModuleId, Plan, PlanAction, PlanActionStatus};
use crate::modules::registry;

pub async fn generate_plan(module_ids: &[ModuleId]) -> color_eyre::Result<Plan> {
    let reg = registry();
    let ctx = crate::modules::Context {
        is_dry_run: false,
        is_test: std::env::var("TORIDE_E2E").is_ok(),
        target_user: String::new(),
        ssh_public_key: String::new(),
    };

    let resolved = resolve_dependencies(module_ids, &reg);
    let mut actions = Vec::new();

    for id in &resolved {
        if let Some(module) = reg.get(id) {
            match module.plan(&ctx).await {
                Ok(module_actions) => {
                    for ma in module_actions {
                        actions.push(PlanAction {
                            module_id: *id,
                            label: ma.to_shell_preview(),
                            status: PlanActionStatus::Pending,
                        });
                    }
                }
                Err(e) => {
                    actions.push(PlanAction {
                        module_id: *id,
                        label: format!("ERROR: {}", e),
                        status: PlanActionStatus::Failed,
                    });
                }
            }
        }
    }

    Ok(Plan {
        actions,
        generated_at: std::time::Instant::now(),
    })
}

fn resolve_dependencies(selected: &[ModuleId], reg: &std::collections::BTreeMap<ModuleId, Box<dyn crate::modules::SetupModule>>) -> Vec<ModuleId> {
    let mut resolved = std::collections::BTreeSet::new();
    let mut queue: Vec<ModuleId> = selected.to_vec();

    while let Some(id) = queue.pop() {
        if resolved.contains(&id) {
            continue;
        }
        if let Some(module) = reg.get(&id) {
            for dep in module.dependencies() {
                if !resolved.contains(&dep) {
                    queue.push(dep);
                }
            }
        }
        resolved.insert(id);
    }

    resolved.into_iter().collect()
}

#[derive(Debug, Clone)]
pub struct PreflightWarning {
    pub message: String,
    pub severity: WarningSeverity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WarningSeverity {
    Info,
    Warning,
    Danger,
}

pub fn generate_preflight_warnings(module_ids: &[ModuleId]) -> Vec<PreflightWarning> {
    let mut warnings = Vec::new();
    let selected: std::collections::BTreeSet<ModuleId> = module_ids.iter().copied().collect();

    // SSH safety: warn if disabling password login without SSH key
    if selected.contains(&ModuleId::UserSsh) {
        warnings.push(PreflightWarning {
            message: "Password SSH login will be disabled. Ensure SSH key is configured before applying.".into(),
            severity: WarningSeverity::Danger,
        });
        warnings.push(PreflightWarning {
            message: "Root SSH login will be disabled. Verify the new user can connect before applying.".into(),
            severity: WarningSeverity::Warning,
        });
    }

    // UFW safety: warn about SSH port
    if selected.contains(&ModuleId::Ufw) {
        warnings.push(PreflightWarning {
            message: "UFW will be enabled with default deny. Only SSH (port 22) will be allowed.".into(),
            severity: WarningSeverity::Warning,
        });
    }

    // Docker requires system update for dependencies
    if selected.contains(&ModuleId::Docker) && !selected.contains(&ModuleId::SystemUpdate) {
        warnings.push(PreflightWarning {
            message: "Docker requires system packages (ca-certificates, gnupg). System Update should be included.".into(),
            severity: WarningSeverity::Info,
        });
    }

    warnings
}
