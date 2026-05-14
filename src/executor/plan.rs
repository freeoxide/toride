use crate::tui::model::{ModuleId, Plan, PlanAction, PlanActionStatus};
use crate::modules::registry;

pub async fn generate_plan(module_ids: &[ModuleId], target_user: &str, ssh_public_key: &str) -> color_eyre::Result<Plan> {
    let reg = registry();
    let ctx = crate::modules::Context {
        is_dry_run: false,
        is_test: std::env::var("TORIDE_E2E").is_ok(),
        target_user: target_user.to_string(),
        ssh_public_key: ssh_public_key.to_string(),
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

    // Cloudflare-only HTTP/S warning
    if selected.contains(&ModuleId::CloudflareHttp) {
        warnings.push(PreflightWarning {
            message: "Cloudflare-only HTTP/S will restrict ports 80/443 to Cloudflare IP ranges. Ensure DNS is proxied through Cloudflare.".into(),
            severity: WarningSeverity::Danger,
        });
    }

    // Reverse proxy conflicts
    let proxy_count = [&ModuleId::Caddy, &ModuleId::Nginx, &ModuleId::Traefik]
        .iter()
        .filter(|p| selected.contains(*p))
        .count();
    if proxy_count > 1 {
        warnings.push(PreflightWarning {
            message: "Multiple reverse proxies selected. Only one should bind ports 80/443.".into(),
            severity: WarningSeverity::Danger,
        });
    }

    // Server manager conflicts
    if selected.contains(&ModuleId::Dokploy) && selected.contains(&ModuleId::Coolify) {
        warnings.push(PreflightWarning {
            message: "Dokploy and Coolify are both selected. They conflict — pick one.".into(),
            severity: WarningSeverity::Danger,
        });
    }

    // Uptime Kuma requires Docker
    if selected.contains(&ModuleId::UptimeKuma) && !selected.contains(&ModuleId::Docker) {
        warnings.push(PreflightWarning {
            message: "Uptime Kuma requires Docker. Docker will be added as a dependency.".into(),
            severity: WarningSeverity::Info,
        });
    }

    // Tailscale install script warning
    if selected.contains(&ModuleId::Tailscale) {
        warnings.push(PreflightWarning {
            message: "Tailscale will be installed via the official install script. Review the script before applying.".into(),
            severity: WarningSeverity::Info,
        });
    }

    // nftables conflict warning before UFW enable
    if selected.contains(&ModuleId::Ufw) {
        if std::path::Path::new("/usr/sbin/nft").exists() {
            let output = std::process::Command::new("nft")
                .args(["list", "ruleset"])
                .output()
                .ok();
            if let Some(out) = output {
                let stdout = String::from_utf8_lossy(&out.stdout);
                if !stdout.trim().is_empty() {
                    warnings.push(PreflightWarning {
                        message: "Pre-existing nftables rules detected. UFW uses the nftables backend and may not see provider-loaded rules. Verify with 'nft list ruleset' before enabling UFW.".into(),
                        severity: WarningSeverity::Warning,
                    });
                }
            }
        }
    }

    // SSH port change warning
    if selected.contains(&ModuleId::UserSsh) {
        warnings.push(PreflightWarning {
            message: "SSH hardening will change authentication settings. Keep an active session open during apply.".into(),
            severity: WarningSeverity::Warning,
        });
    }

    // Reboot check
    if std::path::Path::new("/var/run/reboot-required").exists() {
        warnings.push(PreflightWarning {
            message: "A reboot is pending from a previous update. Consider rebooting before applying.".into(),
            severity: WarningSeverity::Info,
        });
    }

    warnings
}
