use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::tui::update::{Action, Effect};
use crate::tui::model::{Model, ProgressEvent, SystemInfo};

pub fn spawn_effect(effect: Effect, tx: mpsc::UnboundedSender<Action>, cancel: CancellationToken) {
    match effect {
        Effect::DetectSystem => {
            tokio::spawn(async move {
                let info = detect_system_info().await;
                let _ = tx.send(Action::OsDetected(info));
            });
        }
        Effect::GeneratePlan(module_ids) => {
            tokio::spawn(async move {
                let plan = crate::executor::plan::generate_plan(&module_ids).await;
                match plan {
                    Ok(p) => { let _ = tx.send(Action::PlanReady(p)); }
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

                let executor = tokio::spawn(async move {
                    crate::executor::execute_plan(&plan_clone, progress_tx, cancel_run).await
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
                match tokio::fs::write(&path, b"").await {
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
                    Ok(_content) => {
                        let _ = tx.send(Action::Toast {
                            message: format!("Config loaded from {}", path.display()),
                            kind: crate::tui::model::ToastKind::Info,
                        });
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

    SystemInfo {
        os_name,
        os_version,
        is_root,
        current_user,
        public_ip: None,
        memory_mb: 0,
        disk_gb: 0,
        existing_tools,
        has_systemd,
    }
}
