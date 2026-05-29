//! Local SSH diagnostic checks.

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use crate::doctor::check::Check;
use crate::paths::SshPaths;
use crate::types::{Diagnostic, Severity};
use crate::Result;

// ---------------------------------------------------------------------------
// Concrete check structs
// ---------------------------------------------------------------------------

/// Check that `~/.ssh` exists and is a directory.
struct SshDirExists {
    paths: SshPaths,
}

/// Check that `~/.ssh` has permission mode `0o700`.
#[cfg(unix)]
struct SshDirPermissions {
    paths: SshPaths,
}

/// Check that `~/.ssh/config` exists.
struct ConfigExists {
    paths: SshPaths,
}

/// Check that `~/.ssh/known_hosts` exists.
struct KnownHostsExists {
    paths: SshPaths,
}

/// Check that all private key files under `~/.ssh` have mode `0o600`.
#[cfg(unix)]
struct PrivateKeyPermissions {
    paths: SshPaths,
}

/// Check that the SSH agent socket is reachable.
struct AgentAvailable;

/// Check that `ssh-keygen` is available in `PATH`.
struct KeygenAvailable;

/// Check that at least one default key pair exists.
struct DefaultKeyExists {
    paths: SshPaths,
}

// ---------------------------------------------------------------------------
// Check implementations
// ---------------------------------------------------------------------------

impl Check for SshDirExists {
    fn id(&self) -> &'static str {
        "ssh_dir_exists"
    }
    fn module(&self) -> &'static str {
        "local"
    }
    fn run(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<Diagnostic>>> + Send + '_>>
    {
        let ssh_dir = self.paths.ssh_dir().to_path_buf();
        Box::pin(async move {
            let meta = tokio::fs::metadata(&ssh_dir).await;
            match meta {
                Ok(m) if m.is_dir() => Ok(vec![Diagnostic {
                    id: "ssh_dir_exists",
                    severity: Severity::Ok,
                    message: format!("{} exists and is a directory", ssh_dir.display()),
                    hint: None,
                    module: "local",
                }]),
                Ok(_) => Ok(vec![Diagnostic {
                    id: "ssh_dir_exists",
                    severity: Severity::Error,
                    message: format!("{} exists but is not a directory", ssh_dir.display()),
                    hint: Some("Remove the file and run `mkdir -p ~/.ssh`".into()),
                    module: "local",
                }]),
                Err(_) => Ok(vec![Diagnostic {
                    id: "ssh_dir_exists",
                    severity: Severity::Warning,
                    message: format!("{} does not exist", ssh_dir.display()),
                    hint: Some("Run `mkdir -p ~/.ssh && chmod 700 ~/.ssh`".into()),
                    module: "local",
                }]),
            }
        })
    }
}

#[cfg(unix)]
impl Check for SshDirPermissions {
    fn id(&self) -> &'static str {
        "ssh_dir_permissions"
    }
    fn module(&self) -> &'static str {
        "local"
    }
    fn run(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<Diagnostic>>> + Send + '_>>
    {
        let ssh_dir = self.paths.ssh_dir().to_path_buf();
        Box::pin(async move {
            let meta = tokio::fs::metadata(&ssh_dir).await;
            match meta {
                Ok(m) => {
                    let mode = m.permissions().mode() & 0o777;
                    if mode == 0o700 {
                        Ok(vec![Diagnostic {
                            id: "ssh_dir_permissions",
                            severity: Severity::Ok,
                            message: format!(
                                "{} has correct permissions ({:o})",
                                ssh_dir.display(),
                                mode
                            ),
                            hint: None,
                            module: "local",
                        }])
                    } else {
                        Ok(vec![Diagnostic {
                            id: "ssh_dir_permissions",
                            severity: Severity::Error,
                            message: format!(
                                "{} has overly permissive permissions ({:o}), expected 700",
                                ssh_dir.display(),
                                mode
                            ),
                            hint: Some("Run `chmod 700 ~/.ssh`".into()),
                            module: "local",
                        }])
                    }
                }
                Err(_) => Ok(vec![Diagnostic {
                    id: "ssh_dir_permissions",
                    severity: Severity::Warning,
                    message: format!(
                        "Cannot check permissions: {} does not exist",
                        ssh_dir.display()
                    ),
                    hint: Some("Run `mkdir -p ~/.ssh && chmod 700 ~/.ssh`".into()),
                    module: "local",
                }]),
            }
        })
    }
}

impl Check for ConfigExists {
    fn id(&self) -> &'static str {
        "config_exists"
    }
    fn module(&self) -> &'static str {
        "local"
    }
    fn run(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<Diagnostic>>> + Send + '_>>
    {
        let config_path = self.paths.config_path();
        Box::pin(async move {
            match tokio::fs::metadata(&config_path).await {
                Ok(_) => Ok(vec![Diagnostic {
                    id: "config_exists",
                    severity: Severity::Ok,
                    message: format!("{} exists", config_path.display()),
                    hint: None,
                    module: "local",
                }]),
                Err(_) => Ok(vec![Diagnostic {
                    id: "config_exists",
                    severity: Severity::Info,
                    message: format!("{} does not exist", config_path.display()),
                    hint: Some(
                        "An SSH config is optional but recommended. Create it with `touch ~/.ssh/config`".into(),
                    ),
                    module: "local",
                }]),
            }
        })
    }
}

impl Check for KnownHostsExists {
    fn id(&self) -> &'static str {
        "known_hosts_exists"
    }
    fn module(&self) -> &'static str {
        "local"
    }
    fn run(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<Diagnostic>>> + Send + '_>>
    {
        let kh_path = self.paths.known_hosts_path();
        Box::pin(async move {
            match tokio::fs::metadata(&kh_path).await {
                Ok(_) => Ok(vec![Diagnostic {
                    id: "known_hosts_exists",
                    severity: Severity::Ok,
                    message: format!("{} exists", kh_path.display()),
                    hint: None,
                    module: "local",
                }]),
                Err(_) => Ok(vec![Diagnostic {
                    id: "known_hosts_exists",
                    severity: Severity::Warning,
                    message: format!("{} does not exist", kh_path.display()),
                    hint: Some(
                        "Without a known_hosts file you will be prompted to verify every new host. Run `touch ~/.ssh/known_hosts`".into(),
                    ),
                    module: "local",
                }]),
            }
        })
    }
}

#[cfg(unix)]
impl Check for PrivateKeyPermissions {
    fn id(&self) -> &'static str {
        "private_key_permissions"
    }
    fn module(&self) -> &'static str {
        "local"
    }
    fn run(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<Diagnostic>>> + Send + '_>>
    {
        let ssh_dir = self.paths.ssh_dir().to_path_buf();
        Box::pin(async move {
            let mut diagnostics = Vec::new();
            let Ok(mut read_dir) = tokio::fs::read_dir(&ssh_dir).await else {
                return Ok(vec![Diagnostic {
                    id: "private_key_permissions",
                    severity: Severity::Warning,
                    message: format!(
                        "Cannot scan {}: directory does not exist",
                        ssh_dir.display()
                    ),
                    hint: None,
                    module: "local",
                }]);
            };

            while let Some(entry) = read_dir.next_entry().await? {
                let name = entry.file_name();
                let name_lossy = name.to_string_lossy();

                // Skip public keys, certificates, config files, and dotfiles.
                if name_lossy.ends_with(".pub")
                    || name_lossy.ends_with("-cert.pub")
                    || name_lossy == "config"
                    || name_lossy == "known_hosts"
                    || name_lossy == "authorized_keys"
                    || name_lossy == "authorized_keys2"
                    || name_lossy.starts_with('.')
                {
                    continue;
                }

                let path = entry.path();
                let Ok(meta) = tokio::fs::metadata(&path).await else {
                    continue;
                };

                // Only check regular files.
                if !meta.is_file() {
                    continue;
                }

                // Read only the first 4 KB to detect private key markers without
                // loading potentially large files into memory.
                let header = {
                    use tokio::io::AsyncReadExt;
                    let Ok(mut file) = tokio::fs::File::open(&path).await else {
                        continue;
                    };
                    let mut buf = [0u8; 4096];
                    let Ok(n) = file.read(&mut buf).await else {
                        continue;
                    };
                    if n < 8 {
                        continue;
                    }
                    String::from_utf8_lossy(&buf[..n]).into_owned()
                };

                if !header.contains("PRIVATE KEY") {
                    continue;
                }

                let mode = meta.permissions().mode() & 0o777;
                if mode == 0o600 {
                    diagnostics.push(Diagnostic {
                        id: "private_key_permissions",
                        severity: Severity::Ok,
                        message: format!(
                            "{} has correct permissions ({:o})",
                            path.display(),
                            mode
                        ),
                        hint: None,
                        module: "local",
                    });
                } else {
                    diagnostics.push(Diagnostic {
                        id: "private_key_permissions",
                        severity: Severity::Error,
                        message: format!(
                            "{} has overly permissive permissions ({:o}), expected 600",
                            path.display(),
                            mode
                        ),
                        hint: Some(format!("Run `chmod 600 {}`", path.display())),
                        module: "local",
                    });
                }
            }

            if diagnostics.is_empty() {
                diagnostics.push(Diagnostic {
                    id: "private_key_permissions",
                    severity: Severity::Info,
                    message: "No private key files found in ~/.ssh".into(),
                    hint: None,
                    module: "local",
                });
            }

            Ok(diagnostics)
        })
    }
}

impl Check for AgentAvailable {
    fn id(&self) -> &'static str {
        "agent_available"
    }
    fn module(&self) -> &'static str {
        "local"
    }
    fn run(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<Diagnostic>>> + Send + '_>>
    {
        Box::pin(async move {
            match std::env::var("SSH_AUTH_SOCK") {
                Ok(sock) if !sock.is_empty() => {
                    let sock_path = std::path::PathBuf::from(&sock);
                    match tokio::fs::metadata(&sock_path).await {
                        Ok(_) => Ok(vec![Diagnostic {
                            id: "agent_available",
                            severity: Severity::Ok,
                            message: "SSH agent is reachable via $SSH_AUTH_SOCK".into(),
                            hint: None,
                            module: "local",
                        }]),
                        Err(_) => Ok(vec![Diagnostic {
                            id: "agent_available",
                            severity: Severity::Warning,
                            message: format!(
                                "$SSH_AUTH_SOCK is set to {sock} but the socket does not exist",
                            ),
                            hint: Some(
                                "Start the SSH agent: `eval $(ssh-agent -s)`".into(),
                            ),
                            module: "local",
                        }]),
                    }
                }
                _ => Ok(vec![Diagnostic {
                    id: "agent_available",
                    severity: Severity::Warning,
                    message: "$SSH_AUTH_SOCK is not set — SSH agent may not be running".into(),
                    hint: Some(
                        "Start the SSH agent: `eval $(ssh-agent -s)`".into(),
                    ),
                    module: "local",
                }]),
            }
        })
    }
}

impl Check for KeygenAvailable {
    fn id(&self) -> &'static str {
        "keygen_available"
    }
    fn module(&self) -> &'static str {
        "local"
    }
    fn run(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<Diagnostic>>> + Send + '_>>
    {
        Box::pin(async move {
            if crate::runner::tool_exists("ssh-keygen") {
                Ok(vec![Diagnostic {
                    id: "keygen_available",
                    severity: Severity::Ok,
                    message: "ssh-keygen is available in PATH".into(),
                    hint: None,
                    module: "local",
                }])
            } else {
                Ok(vec![Diagnostic {
                    id: "keygen_available",
                    severity: Severity::Error,
                    message: "ssh-keygen is not found in PATH".into(),
                    hint: Some(
                        "Install OpenSSH: `brew install openssh` (macOS) or `sudo apt install openssh-client` (Linux)".into(),
                    ),
                    module: "local",
                }])
            }
        })
    }
}

impl Check for DefaultKeyExists {
    fn id(&self) -> &'static str {
        "default_key_exists"
    }
    fn module(&self) -> &'static str {
        "local"
    }
    fn run(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<Diagnostic>>> + Send + '_>>
    {
        let ssh_dir = self.paths.ssh_dir().to_path_buf();
        Box::pin(async move {
            let mut found = Vec::new();
            for name in SshPaths::default_key_names() {
                let key_path = ssh_dir.join(name);
                if tokio::fs::metadata(&key_path).await.is_ok() {
                    found.push(*name);
                }
            }

            if found.is_empty() {
                Ok(vec![Diagnostic {
                    id: "default_key_exists",
                    severity: Severity::Warning,
                    message: "No default SSH key found (checked id_rsa, id_ed25519, etc.)".into(),
                    hint: Some(
                        "Generate a key: `ssh-keygen -t ed25519 -C \"your@email.com\"`".into(),
                    ),
                    module: "local",
                }])
            } else {
                Ok(vec![Diagnostic {
                    id: "default_key_exists",
                    severity: Severity::Ok,
                    message: format!("Default key(s) found: {}", found.join(", ")),
                    hint: None,
                    module: "local",
                }])
            }
        })
    }
}

// ---------------------------------------------------------------------------
// run_all — execute every local check
// ---------------------------------------------------------------------------

/// Run all local diagnostic checks.
pub async fn run_all(paths: &SshPaths) -> Result<Vec<Diagnostic>> {
    let mut checks: Vec<Box<dyn Check>> = vec![
        Box::new(SshDirExists {
            paths: paths.clone(),
        }),
    ];

    #[cfg(unix)]
    checks.push(Box::new(SshDirPermissions {
        paths: paths.clone(),
    }));

    checks.push(Box::new(ConfigExists {
        paths: paths.clone(),
    }));
    checks.push(Box::new(KnownHostsExists {
        paths: paths.clone(),
    }));

    #[cfg(unix)]
    checks.push(Box::new(PrivateKeyPermissions {
        paths: paths.clone(),
    }));

    checks.push(Box::new(AgentAvailable));
    checks.push(Box::new(KeygenAvailable));
    checks.push(Box::new(DefaultKeyExists {
        paths: paths.clone(),
    }));

    let mut all_diagnostics = Vec::new();
    for check in &checks {
        match check.run().await {
            Ok(diagnostics) => all_diagnostics.extend(diagnostics),
            Err(e) => all_diagnostics.push(Diagnostic {
                id: check.id(),
                severity: Severity::Error,
                message: format!("Check failed: {e}"),
                hint: None,
                module: check.module(),
            }),
        }
    }
    Ok(all_diagnostics)
}
