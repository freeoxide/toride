use crate::modules::{ApplyOutcome, InstallAction, ModuleError, ModuleResult};
use crate::tui::model::ProgressEvent;

pub type ProgressTx = tokio::sync::mpsc::UnboundedSender<ProgressEvent>;

pub async fn execute_actions(
    actions: &[InstallAction],
    tx: &tokio::sync::mpsc::UnboundedSender<ProgressEvent>,
    dry_run: bool,
) -> ModuleResult<ApplyOutcome> {
    if dry_run {
        return Ok(ApplyOutcome::Skipped);
    }

    for (idx, action) in actions.iter().enumerate() {
        let preview = action.to_shell_preview();
        let _ = tx.send(ProgressEvent::StepLog {
            action_idx: idx,
            line: preview,
        });

        let result = execute_single(action).await;
        match result {
            Ok(output) => {
                for line in output.lines() {
                    let _ = tx.send(ProgressEvent::StepLog {
                        action_idx: idx,
                        line: line.to_string(),
                    });
                }
                let _ = tx.send(ProgressEvent::StepDone {
                    action_idx: idx,
                    exit_code: 0,
                    duration_ms: 0,
                });
            }
            Err(e) => {
                let _ = tx.send(ProgressEvent::StepFail {
                    action_idx: idx,
                    error: e.to_string(),
                });
                return Err(e);
            }
        }
    }

    Ok(ApplyOutcome::Changed)
}

pub async fn execute_single(action: &InstallAction) -> ModuleResult<String> {
    match action {
        InstallAction::AptInstall { packages } => {
            let pkg_refs: Vec<&str> = packages.iter().map(|s| s.as_str()).collect();
            let cmd = crate::system::package_manager::apt_install(&pkg_refs);
            run_cmd_from(cmd).await
        }

        InstallAction::AptRepoAdd { name, key_url, sources_line, .. } => {
            // Create keyrings dir, download key, write sources
            run_cmd("install", &["-m", "0755", "-d", "/etc/apt/keyrings"]).await.ok();

            // Download the GPG key
            let key_resp = reqwest::get(key_url).await
                .map_err(|e| ModuleError::Exec(format!("Failed to fetch repo key: {}", e)))?;
            let key_bytes = key_resp.bytes().await
                .map_err(|e| ModuleError::Exec(format!("Failed to read repo key: {}", e)))?;
            let key_path = format!("/etc/apt/keyrings/{}.asc", name);
            tokio::fs::write(&key_path, &key_bytes).await
                .map_err(|e| ModuleError::Exec(format!("Failed to write key: {}", e)))?;

            // Write sources list
            let sources_path = format!("/etc/apt/sources.list.d/{}.sources", name);
            tokio::fs::write(&sources_path, sources_line.as_bytes()).await
                .map_err(|e| ModuleError::Exec(format!("Failed to write sources: {}", e)))?;

            // Update index
            let cmd = crate::system::package_manager::apt_update();
            run_cmd_from(cmd).await
        }

        InstallAction::WriteFile { path, content, mode, backup } => {
            let path = std::path::Path::new(path);
            if *backup && path.exists() {
                let timestamp = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let backup_path = format!("/var/backups/toride/{}.{}", path.file_name().unwrap_or_default().to_string_lossy(), timestamp);
                if let Some(parent) = std::path::Path::new(&backup_path).parent() {
                    tokio::fs::create_dir_all(parent).await.ok();
                }
                tokio::fs::copy(path, &backup_path).await.ok();

                // Generate diff if original differs
                let old_content = tokio::fs::read_to_string(path).await.unwrap_or_default();
                if old_content != *content {
                    let diff = generate_diff(&old_content, content);
                    tracing::info!("Config diff for {}:\n{}", path.display(), diff);
                }
            }
            if let Some(parent) = path.parent() {
                tokio::fs::create_dir_all(parent).await
                    .map_err(|e| ModuleError::Exec(format!("Failed to create dir: {}", e)))?;
            }
            tokio::fs::write(path, content.as_bytes()).await
                .map_err(|e| ModuleError::Exec(format!("Failed to write {}: {}", path.display(), e)))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let perms = std::fs::Permissions::from_mode(*mode);
                tokio::fs::set_permissions(path, perms).await
                    .map_err(|e| ModuleError::Exec(format!("Failed to chmod: {}", e)))?;
            }
            Ok(format!("wrote {}", path.display()))
        }

        InstallAction::AppendLine { path, line, marker } => {
            let content = tokio::fs::read_to_string(path).await.unwrap_or_default();
            if content.contains(marker) {
                return Ok(format!("{} already contains marker {}", path, marker));
            }
            let tagged_line = format!("{} # {}\n", line, marker);
            let mut new_content = content;
            if !new_content.ends_with('\n') && !new_content.is_empty() {
                new_content.push('\n');
            }
            new_content.push_str(&tagged_line);
            tokio::fs::write(path, new_content.as_bytes()).await
                .map_err(|e| ModuleError::Exec(format!("Failed to append to {}: {}", path, e)))?;
            Ok(format!("appended to {}", path))
        }

        InstallAction::Systemctl { unit, op } => {
            run_cmd("systemctl", &[op.as_str(), unit.as_str()]).await
        }

        InstallAction::UfwRule { rule } => {
            let parts: Vec<&str> = rule.split_whitespace().collect();
            run_cmd("ufw", &parts).await
        }

        InstallAction::UserCreate { name, groups, shell } => {
            // Check if user already exists
            if crate::system::users::user_exists(name) {
                return Ok(format!("user {} already exists", name));
            }
            let mut args = vec!["-m".to_string(), "-s".to_string(), shell.clone()];
            if !groups.is_empty() {
                args.push("-G".to_string());
                args.push(groups.join(","));
            }
            args.push(name.clone());
            let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
            run_cmd("useradd", &arg_refs).await
        }

        InstallAction::UserAddKey { user, key } => {
            let ssh_dir = format!("/home/{}/.ssh", user);
            let auth_keys_path = format!("{}/authorized_keys", ssh_dir);

            tokio::fs::create_dir_all(&ssh_dir).await
                .map_err(|e| ModuleError::Exec(format!("Failed to create .ssh dir: {}", e)))?;

            let existing = tokio::fs::read_to_string(&auth_keys_path).await.unwrap_or_default();
            if existing.contains(key) {
                return Ok("SSH key already present".into());
            }

            let mut content = existing;
            if !content.ends_with('\n') && !content.is_empty() {
                content.push('\n');
            }
            content.push_str(key);
            content.push('\n');

            tokio::fs::write(&auth_keys_path, content.as_bytes()).await
                .map_err(|e| ModuleError::Exec(format!("Failed to write authorized_keys: {}", e)))?;

            // Set permissions
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let uid = nix::unistd::User::from_name(user).ok().flatten();
                tokio::fs::set_permissions(&ssh_dir, std::fs::Permissions::from_mode(0o700)).await.ok();
                tokio::fs::set_permissions(&auth_keys_path, std::fs::Permissions::from_mode(0o600)).await.ok();
                if let Some(u) = uid {
                    let gid_raw = nix::unistd::Group::from_gid(u.gid).ok().flatten().map(|g| g.gid.as_raw());
                    std::os::unix::fs::chown(&ssh_dir, Some(u.uid.as_raw()), gid_raw).ok();
                    std::os::unix::fs::chown(&auth_keys_path, Some(u.uid.as_raw()), gid_raw).ok();
                }
            }
            Ok(format!("SSH key added for {}", user))
        }

        InstallAction::DownloadScript { url, sha256, run_as, env } => {
            // Fetch the script
            let resp = reqwest::get(url).await
                .map_err(|e| ModuleError::Exec(format!("Failed to fetch {}: {}", url, e)))?;
            let script_bytes = resp.bytes().await
                .map_err(|e| ModuleError::Exec(format!("Failed to read response: {}", e)))?;

            // Verify SHA256 if provided
            if !sha256.is_empty() {
                use sha2::{Sha256, Digest};
                let mut hasher = Sha256::new();
                hasher.update(&script_bytes);
                let hash = hex::encode(hasher.finalize());
                if hash != *sha256 {
                    return Err(ModuleError::Exec(
                        format!("SHA256 mismatch for {}: expected {}, got {}", url, sha256, hash)
                    ));
                }
            }

            // Write to temp file
            let tmp_path = "/tmp/toride-download-script.sh";
            tokio::fs::write(tmp_path, &script_bytes).await
                .map_err(|e| ModuleError::Exec(format!("Failed to write script: {}", e)))?;

            // Execute
            let mut cmd = tokio::process::Command::new("sh");
            cmd.arg(tmp_path);
            if !env.is_empty() {
                for (k, v) in env {
                    cmd.env(k, v);
                }
            }
            if run_as != "root" {
                cmd.uid(
                    nix::unistd::User::from_name(run_as)
                        .ok().flatten()
                        .map(|u| u.uid.as_raw())
                        .unwrap_or(0)
                );
            }

            let output = cmd.output().await
                .map_err(|e| ModuleError::Exec(format!("Failed to execute script: {}", e)))?;

            if output.status.success() {
                Ok(String::from_utf8_lossy(&output.stdout).to_string())
            } else {
                Err(ModuleError::Exec(format!(
                    "Script {} failed: {}", url, String::from_utf8_lossy(&output.stderr)
                )))
            }
        }

        InstallAction::Exec { cmd, args, env, as_user } => {
            let mut command = tokio::process::Command::new(cmd);
            let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
            command.args(&arg_refs);
            for (k, v) in env {
                command.env(k, v);
            }
            if let Some(user) = as_user {
                command.uid(
                    nix::unistd::User::from_name(user)
                        .ok().flatten()
                        .map(|u| u.uid.as_raw())
                        .unwrap_or(0)
                );
            }
            let output = command.output().await
                .map_err(|e| ModuleError::Exec(format!("{}: {}", cmd, e)))?;
            if output.status.success() {
                Ok(String::from_utf8_lossy(&output.stdout).to_string())
            } else {
                Err(ModuleError::Exec(format!(
                    "{} exited with {}: {}", cmd, output.status, String::from_utf8_lossy(&output.stderr)
                )))
            }
        }
    }
}

async fn run_cmd(cmd: &str, args: &[&str]) -> ModuleResult<String> {
    let mut command = tokio::process::Command::new(cmd);
    command.args(args);
    run_cmd_inner(command).await
}

async fn run_cmd_from(mut command: std::process::Command) -> ModuleResult<String> {
    let tokio_cmd: tokio::process::Command = command.into();
    run_cmd_inner(tokio_cmd).await
}

async fn run_cmd_inner(mut child: tokio::process::Command) -> ModuleResult<String> {
    use tokio::io::AsyncBufReadExt;
    use tokio_stream::wrappers::LinesStream;
    use tokio_stream::StreamExt;

    child
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

    let mut child = child
        .spawn()
        .map_err(|e| ModuleError::Exec(e.to_string()))?;

    let stdout = child.stdout.take().expect("stdout piped");
    let stderr = child.stderr.take().expect("stderr piped");

    let stdout_lines = LinesStream::new(tokio::io::BufReader::new(stdout).lines());
    let stderr_lines = LinesStream::new(tokio::io::BufReader::new(stderr).lines());

    let mut merged = stdout_lines.merge(stderr_lines);
    let mut output = String::new();

    while let Some(Ok(line)) = merged.next().await {
        output.push_str(&line);
        output.push('\n');
    }

    let status = child.wait().await
        .map_err(|e| ModuleError::Exec(e.to_string()))?;

    if status.success() {
        Ok(output)
    } else {
        Err(ModuleError::Exec(format!("command exited with {}", status)))
    }
}

fn generate_diff(old: &str, new: &str) -> String {
    let mut diff = String::new();
    let old_lines: Vec<&str> = old.lines().collect();
    let new_lines: Vec<&str> = new.lines().collect();

    for (i, line) in old_lines.iter().enumerate() {
        if !new_lines.contains(line) {
            diff.push_str(&format!("- {} (line {})\n", line, i + 1));
        }
    }
    for (i, line) in new_lines.iter().enumerate() {
        if !old_lines.contains(line) {
            diff.push_str(&format!("+ {} (line {})\n", line, i + 1));
        }
    }

    if diff.is_empty() {
        diff.push_str("(no content changes)");
    }

    diff
}
