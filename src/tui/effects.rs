use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::tui::update::{Action, Effect};
use crate::tui::model::{ProgressEvent, SystemInfo, SshVerifyPhase};

pub fn spawn_effect(effect: Effect, tx: mpsc::UnboundedSender<Action>, cancel: CancellationToken) {
    match effect {
        Effect::DetectSystem => {
            tokio::spawn(async move {
                let info = detect_system_info().await;
                let _ = tx.send(Action::OsDetected(info));
                if let Some(os) = crate::system::os_detect::detect() {
                    if !crate::system::os_detect::is_supported(&os) {
                        let _ = tx.send(Action::Toast {
                            message: format!("Unsupported OS: {}. Toride supports Debian and Ubuntu.", os.name),
                            kind: crate::tui::model::ToastKind::Warning,
                        });
                    }
                }
            });
        }
        Effect::GeneratePlan(module_ids) => {
            tokio::spawn(async move {
                let plan = crate::executor::plan::generate_plan(&module_ids, "", "").await;
                match plan {
                    Ok(p) => {
                        let _ = tx.send(Action::PlanReady(p));
                        let warnings = crate::executor::plan::generate_preflight_warnings(&module_ids);
                        if !warnings.is_empty() {
                            let _ = tx.send(Action::PreflightWarnings(warnings));
                        }
                    }
                    Err(e) => { let _ = tx.send(Action::Error(e.to_string())); }
                }
            });
        }
        Effect::RunInstall(plan) => {
            let cancel = cancel.clone();
            tokio::spawn(async move {
                let (progress_tx, mut progress_rx) = mpsc::unbounded_channel::<ProgressEvent>();
                let plan_clone = plan.clone();
                let cancel_run = cancel.clone();

                let ctx = crate::modules::Context {
                    is_dry_run: false,
                    is_test: std::env::var("TORIDE_E2E").is_ok(),
                    target_user: String::new(),
                    ssh_public_key: String::new(),
                };

                let executor = tokio::spawn(async move {
                    crate::executor::execute_plan(&plan_clone, progress_tx, cancel_run, ctx).await
                });

                while let Some(event) = progress_rx.recv().await {
                    let _ = tx.send(Action::InstallProgress(event));
                }

                match executor.await {
                    Ok(Ok(outcome)) => { let _ = tx.send(Action::InstallDone(outcome)); }
                    Ok(Err(e)) => { let _ = tx.send(Action::Error(e.to_string())); }
                    Err(_) => { let _ = tx.send(Action::Error("Executor task panicked".into())); }
                }
            });
        }
        Effect::CancelInstall => {
            cancel.cancel();
        }
        Effect::WriteConfig(path) => {
            let tx = tx.clone();
            tokio::spawn(async move {
                let config = crate::config::schema::Config {
                    profile: String::new(),
                    user: crate::config::schema::UserConfig {
                        name: String::new(),
                        ssh_key_path: String::new(),
                        passwordless_sudo: true,
                    },
                    security: crate::config::schema::SecurityConfig::default(),
                    runtimes: crate::config::schema::RuntimesConfig::default(),
                    containers: crate::config::schema::ContainersConfig::default(),
                    swap: crate::config::schema::SwapConfig::default(),
                };
                let content = toml::to_string_pretty(&config).unwrap_or_default();
                match tokio::fs::write(&path, content.as_bytes()).await {
                    Ok(_) => {
                        let _ = tx.send(Action::Toast {
                            message: format!("Config saved to {}", path.display()),
                            kind: crate::tui::model::ToastKind::Success,
                        });
                    }
                    Err(e) => {
                        let _ = tx.send(Action::Error(format!("Failed to save config: {}", e)));
                    }
                }
            });
        }
        Effect::LoadConfig(path) => {
            let tx = tx.clone();
            tokio::spawn(async move {
                match tokio::fs::read_to_string(&path).await {
                    Ok(content) => {
                        match toml::from_str::<crate::config::schema::Config>(&content) {
                            Ok(_config) => {
                                let _ = tx.send(Action::Toast {
                                    message: format!("Config loaded from {}", path.display()),
                                    kind: crate::tui::model::ToastKind::Info,
                                });
                            }
                            Err(e) => {
                                let _ = tx.send(Action::Error(format!("Invalid config format: {}", e)));
                            }
                        }
                    }
                    Err(e) => {
                        let _ = tx.send(Action::Error(format!("Failed to load config: {}", e)));
                    }
                }
            });
        }
        Effect::OpenUrl(_url) => {}
        Effect::Sleep(duration, action) => {
            tokio::spawn(async move {
                tokio::time::sleep(duration).await;
                let _ = tx.send(*action);
            });
        }
        Effect::PushFx(_effect) => {
            // tachyonfx effect enqueueing handled in runtime
        }
        Effect::SshRunPhase(phase) => {
            tokio::spawn(async move {
                let result = run_ssh_phase(phase).await;
                match result {
                    Ok(_) => { let _ = tx.send(Action::SshPhaseDone(phase)); }
                    Err(e) => { let _ = tx.send(Action::Error(format!("SSH phase {:?} failed: {}", phase, e))); }
                }
            });
        }
    }
}

async fn detect_system_info() -> SystemInfo {
    let is_root = nix::unistd::geteuid().is_root();
    let current_user = std::env::var("USER")
        .unwrap_or_else(|_| "unknown".into());

    let os_name = std::fs::read_to_string("/etc/os-release")
        .map(|content| {
            content.lines()
                .find(|l| l.starts_with("PRETTY_NAME="))
                .and_then(|l| l.strip_prefix("PRETTY_NAME=\""))
                .and_then(|l| l.strip_suffix('"'))
                .unwrap_or("Unknown")
                .to_string()
        })
        .unwrap_or_else(|_| "Unknown".into());

    let os_version = std::fs::read_to_string("/etc/os-release")
        .map(|content| {
            content.lines()
                .find(|l| l.starts_with("VERSION_ID="))
                .and_then(|l| l.strip_prefix("VERSION_ID=\""))
                .and_then(|l| l.strip_suffix('"'))
                .unwrap_or("unknown")
                .to_string()
        })
        .unwrap_or_else(|_| "unknown".into());

    let has_systemd = std::path::Path::new("/run/systemd/system").exists();

    let mut existing_tools = Vec::new();
    for tool in &["docker", "node", "go", "cargo", "python3"] {
        if which::which(tool).is_ok() {
            existing_tools.push(tool.to_string());
        }
    }

    let public_ip = match reqwest::get("https://ifconfig.me").await {
        Ok(resp) => resp.text().await.ok()
            .map(|t| t.trim().to_string())
            .filter(|t| !t.is_empty()),
        Err(_) => None,
    };

    let memory_mb = detect_memory_mb();
    let disk_gb = detect_disk_gb();

    SystemInfo {
        os_name,
        os_version,
        is_root,
        current_user,
        public_ip,
        memory_mb,
        disk_gb,
        existing_tools,
        has_systemd,
    }
}

fn detect_memory_mb() -> u64 {
    std::fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|c| {
            c.lines()
                .find(|l| l.starts_with("MemTotal:"))
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|v| v.parse::<u64>().ok())
                .map(|kb| kb / 1024)
        })
        .unwrap_or(0)
}

fn detect_disk_gb() -> u64 {
    let output = std::process::Command::new("df")
        .args(["--output=size", "-BG", "/"])
        .output()
        .ok();
    output
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| {
            s.lines()
                .nth(1)
                .and_then(|l| l.trim().trim_end_matches('G').parse::<u64>().ok())
        })
        .unwrap_or(0)
}

async fn run_ssh_phase(phase: SshVerifyPhase) -> Result<(), String> {
    use crate::modules::{InstallAction, SetupModule};
    match phase {
        SshVerifyPhase::CreateUser => {
            let ctx = crate::modules::Context {
                is_dry_run: false,
                is_test: std::env::var("TORIDE_E2E").is_ok(),
                target_user: String::new(),
                ssh_public_key: String::new(),
            };
            let module = crate::modules::user_ssh::UserSsh;
            let actions = module.plan(&ctx).await.map_err(|e| e.to_string())?;
            // Only run UserCreate
            for action in &actions {
                if matches!(action, InstallAction::UserCreate { .. }) {
                    crate::executor::command::execute_single(action).await.map_err(|e| e.to_string())?;
                }
            }
            Ok(())
        }
        SshVerifyPhase::AddKey => {
            let ctx = crate::modules::Context {
                is_dry_run: false,
                is_test: std::env::var("TORIDE_E2E").is_ok(),
                target_user: String::new(),
                ssh_public_key: String::new(),
            };
            let module = crate::modules::user_ssh::UserSsh;
            let actions = module.plan(&ctx).await.map_err(|e| e.to_string())?;
            for action in &actions {
                if matches!(action, InstallAction::UserAddKey { .. } | InstallAction::WriteFile { .. }) {
                    crate::executor::command::execute_single(action).await.map_err(|e| e.to_string())?;
                }
            }
            Ok(())
        }
        SshVerifyPhase::TestConnect => {
            // User must manually verify — this phase waits for user confirmation
            Ok(())
        }
        SshVerifyPhase::HardenedConfig => {
            let ctx = crate::modules::Context {
                is_dry_run: false,
                is_test: std::env::var("TORIDE_E2E").is_ok(),
                target_user: String::new(),
                ssh_public_key: String::new(),
            };
            let module = crate::modules::user_ssh::UserSsh;
            let actions = module.plan(&ctx).await.map_err(|e| e.to_string())?;
            for action in &actions {
                if matches!(action,
                    InstallAction::WriteFile { path, .. } if path.contains("sshd_config"))
                    || matches!(action, InstallAction::Exec { cmd, .. } if cmd == "rm")
                {
                    crate::executor::command::execute_single(action).await.map_err(|e| e.to_string())?;
                }
            }
            Ok(())
        }
        SshVerifyPhase::ReloadSshd => {
            let action = InstallAction::Systemctl {
                unit: "ssh".into(),
                op: "reload".into(),
            };
            crate::executor::command::execute_single(&action).await.map_err(|e| e.to_string())?;
            Ok(())
        }
        SshVerifyPhase::VerifyConnect => {
            // User must manually verify — waits for user confirmation
            Ok(())
        }
        SshVerifyPhase::Complete => Ok(()),
    }
}
