//! Local SSH diagnostic checks.

use std::collections::HashMap;

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};

use crate::config::ast::{self, ConfigNode};
use crate::doctor::check::{Check, CheckFuture};
use crate::paths::SshPaths;
use crate::types::{Diagnostic, Severity};
use crate::Result;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Number of bytes to read from the start of a file to detect PEM private key
/// headers without loading potentially large files into memory.
const PRIVATE_KEY_HEADER_READ_SIZE: usize = 4096;

/// Minimum number of bytes required to contain a PEM header marker.
const MIN_PEM_HEADER_LENGTH: usize = 8;

/// Minimum recommended RSA key size in bits for long-term security.
/// NIST recommends 2048 through 2030, but 3072 is the widely accepted
/// minimum. OpenSSH 9.x+ warns about RSA-2048 keys.
const RECOMMENDED_RSA_BITS: u32 = 3072;

// ---------------------------------------------------------------------------
// Concrete check structs
// ---------------------------------------------------------------------------

/// Check that `~/.ssh` exists and is a directory.
struct SshDirExists<'a> {
    paths: &'a SshPaths,
}

/// Check that `~/.ssh` has permission mode `0o700` (Unix) or reports ACL info (Windows).
struct SshDirPermissions<'a> {
    paths: &'a SshPaths,
}

/// Check that `~/.ssh/config` exists.
struct ConfigExists<'a> {
    paths: &'a SshPaths,
}

/// Check that `~/.ssh/known_hosts` exists.
struct KnownHostsExists<'a> {
    paths: &'a SshPaths,
}

/// Check that all private key files under `~/.ssh` have mode `0o600` (Unix) or reports ACL info (Windows).
struct PrivateKeyPermissions<'a> {
    paths: &'a SshPaths,
}

/// Check that the SSH agent socket is reachable.
struct AgentAvailable;

/// Check that `ssh-keygen` is available in `PATH`.
struct KeygenAvailable<'a> {
    runner: &'a dyn crate::CliRunner,
}

/// Check that at least one default key pair exists.
struct DefaultKeyExists<'a> {
    paths: &'a SshPaths,
}

/// Check that `~/.ssh` is owned by the current user (Unix) or reports ACL info (Windows).
struct OwnerCheck<'a> {
    paths: &'a SshPaths,
}

/// Check that `~/.ssh/config` is not group/world writable (Unix) or reports ACL info (Windows).
struct ConfigPermissionsCheck<'a> {
    paths: &'a SshPaths,
}

/// Check that `~/.ssh/authorized_keys` has mode `0o600` or `0o644` (Unix) or reports ACL info (Windows).
struct AuthorizedKeysPermissionsCheck<'a> {
    paths: &'a SshPaths,
}

/// Check that every `id_*` private key has a matching `.pub` file.
struct PublicKeyPairsCheck<'a> {
    paths: &'a SshPaths,
}

/// Check that `IdentityFile` paths referenced in config actually exist.
struct IdentityFileExistsCheck<'a> {
    paths: &'a SshPaths,
}

/// Detect duplicate `Host` blocks with the same pattern.
struct DuplicateHostCheck<'a> {
    paths: &'a SshPaths,
}

/// Detect `Host *` appearing before specific `Host` blocks.
struct HostStarPlacementCheck<'a> {
    paths: &'a SshPaths,
}

/// Check for deprecated SSHv1 key files (`~/.ssh/identity`).
struct SshV1KeyCheck<'a> {
    paths: &'a SshPaths,
}

/// Check that `UseKeychain` is only set on macOS.
struct UseKeychainPlatformCheck<'a> {
    paths: &'a SshPaths,
}

/// Check for GSSAPI/Kerberos-related directives in SSH config.
struct GssapiConfigCheck<'a> {
    paths: &'a SshPaths,
}

/// Check for `VerifyHostKeyDNS` configuration and DNS/SSHFP readiness.
struct VerifyHostKeyDnsCheck<'a> {
    paths: &'a SshPaths,
}

// ---------------------------------------------------------------------------
// Check implementations
// ---------------------------------------------------------------------------

impl Check for SshDirExists<'_> {
    fn id(&self) -> &'static str {
        "ssh_dir_exists"
    }
    fn module(&self) -> &'static str {
        "local"
    }
    fn run(
        &self,
    ) -> CheckFuture<'_>
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
                Err(e) => Ok(vec![Diagnostic {
                    id: "ssh_dir_exists",
                    severity: Severity::Warning,
                    message: format!("{} does not exist: {e}", ssh_dir.display()),
                    hint: Some("Run `mkdir -p ~/.ssh && chmod 700 ~/.ssh`".into()),
                    module: "local",
                }]),
            }
        })
    }
}

#[cfg(unix)]
impl Check for SshDirPermissions<'_> {
    fn id(&self) -> &'static str {
        "ssh_dir_permissions"
    }
    fn module(&self) -> &'static str {
        "local"
    }
    fn run(
        &self,
    ) -> CheckFuture<'_>
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
                Err(e) => Ok(vec![Diagnostic {
                    id: "ssh_dir_permissions",
                    severity: Severity::Warning,
                    message: format!(
                        "Cannot check permissions: {}: {e}",
                        ssh_dir.display()
                    ),
                    hint: Some("Run `mkdir -p ~/.ssh && chmod 700 ~/.ssh`".into()),
                    module: "local",
                }]),
            }
        })
    }
}

impl Check for ConfigExists<'_> {
    fn id(&self) -> &'static str {
        "config_exists"
    }
    fn module(&self) -> &'static str {
        "local"
    }
    fn run(
        &self,
    ) -> CheckFuture<'_>
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

impl Check for KnownHostsExists<'_> {
    fn id(&self) -> &'static str {
        "known_hosts_exists"
    }
    fn module(&self) -> &'static str {
        "local"
    }
    fn run(
        &self,
    ) -> CheckFuture<'_>
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
impl Check for PrivateKeyPermissions<'_> {
    fn id(&self) -> &'static str {
        "private_key_permissions"
    }
    fn module(&self) -> &'static str {
        "local"
    }
    fn run(
        &self,
    ) -> CheckFuture<'_>
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
                {
                    use tokio::io::AsyncReadExt;
                    let Ok(mut file) = tokio::fs::File::open(&path).await else {
                        continue;
                    };
                    let mut buf = [0u8; PRIVATE_KEY_HEADER_READ_SIZE];
                    let Ok(n) = file.read(&mut buf).await else {
                        continue;
                    };
                    // `from_utf8_lossy` returns `Cow<str>` so no allocation
                    // occurs when the header is valid UTF-8 (always true for PEM).
                    if n < MIN_PEM_HEADER_LENGTH || !String::from_utf8_lossy(&buf[..n]).contains("PRIVATE KEY") {
                        continue;
                    }
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
    ) -> CheckFuture<'_>
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

impl Check for KeygenAvailable<'_> {
    fn id(&self) -> &'static str {
        "keygen_available"
    }
    fn module(&self) -> &'static str {
        "local"
    }
    fn run(
        &self,
    ) -> CheckFuture<'_>
    {
        Box::pin(async move {
            if self.runner.tool_exists("ssh-keygen") {
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

impl Check for DefaultKeyExists<'_> {
    fn id(&self) -> &'static str {
        "default_key_exists"
    }
    fn module(&self) -> &'static str {
        "local"
    }
    fn run(
        &self,
    ) -> CheckFuture<'_>
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
// OwnerCheck
// ---------------------------------------------------------------------------

#[cfg(unix)]
impl Check for OwnerCheck<'_> {
    fn id(&self) -> &'static str {
        "owner_check"
    }
    fn module(&self) -> &'static str {
        "local"
    }
    fn run(&self) -> CheckFuture<'_> {
        let ssh_dir = self.paths.ssh_dir().to_path_buf();
        Box::pin(async move {
            let meta = tokio::fs::metadata(&ssh_dir).await;
            match meta {
                Ok(m) => {
                    let file_uid = m.uid();
                    let current_uid = unsafe { libc::getuid() };
                    if file_uid == current_uid {
                        Ok(vec![Diagnostic {
                            id: "owner_check",
                            severity: Severity::Ok,
                            message: format!(
                                "{} is owned by current user (uid {})",
                                ssh_dir.display(),
                                current_uid
                            ),
                            hint: None,
                            module: "local",
                        }])
                    } else {
                        Ok(vec![Diagnostic {
                            id: "owner_check",
                            severity: Severity::Error,
                            message: format!(
                                "{} is owned by uid {} but current user is uid {}",
                                ssh_dir.display(),
                                file_uid,
                                current_uid
                            ),
                            hint: Some(format!(
                                "Run `sudo chown -R $(id -u) {}`",
                                ssh_dir.display()
                            )),
                            module: "local",
                        }])
                    }
                }
                Err(e) => Ok(vec![Diagnostic {
                    id: "owner_check",
                    severity: Severity::Warning,
                    message: format!(
                        "Cannot check ownership: {}: {e}",
                        ssh_dir.display()
                    ),
                    hint: Some("Run `mkdir -p ~/.ssh && chmod 700 ~/.ssh`".into()),
                    module: "local",
                }]),
            }
        })
    }
}

// ---------------------------------------------------------------------------
// ConfigPermissionsCheck
// ---------------------------------------------------------------------------

#[cfg(unix)]
impl Check for ConfigPermissionsCheck<'_> {
    fn id(&self) -> &'static str {
        "config_permissions"
    }
    fn module(&self) -> &'static str {
        "local"
    }
    fn run(&self) -> CheckFuture<'_> {
        let config_path = self.paths.config_path().to_path_buf();
        Box::pin(async move {
            let meta = tokio::fs::metadata(&config_path).await;
            match meta {
                Ok(m) => {
                    let mode = m.permissions().mode() & 0o777;
                    if mode & 0o022 == 0 {
                        Ok(vec![Diagnostic {
                            id: "config_permissions",
                            severity: Severity::Ok,
                            message: format!(
                                "{} is not group/world writable ({:o})",
                                config_path.display(),
                                mode
                            ),
                            hint: None,
                            module: "local",
                        }])
                    } else {
                        Ok(vec![Diagnostic {
                            id: "config_permissions",
                            severity: Severity::Error,
                            message: format!(
                                "{} is group/world writable ({:o}), expected no group/world write bits",
                                config_path.display(),
                                mode
                            ),
                            hint: Some(format!("Run `chmod 600 {}`", config_path.display())),
                            module: "local",
                        }])
                    }
                }
                Err(_) => Ok(vec![Diagnostic {
                    id: "config_permissions",
                    severity: Severity::Info,
                    message: format!(
                        "Cannot check permissions: {} does not exist",
                        config_path.display()
                    ),
                    hint: None,
                    module: "local",
                }]),
            }
        })
    }
}

// ---------------------------------------------------------------------------
// AuthorizedKeysPermissionsCheck
// ---------------------------------------------------------------------------

#[cfg(unix)]
impl Check for AuthorizedKeysPermissionsCheck<'_> {
    fn id(&self) -> &'static str {
        "authorized_keys_permissions"
    }
    fn module(&self) -> &'static str {
        "local"
    }
    fn run(&self) -> CheckFuture<'_> {
        let ak_path = self.paths.authorized_keys_path().to_path_buf();
        Box::pin(async move {
            let meta = tokio::fs::metadata(&ak_path).await;
            match meta {
                Ok(m) => {
                    let mode = m.permissions().mode() & 0o777;
                    if mode == 0o600 || mode == 0o644 {
                        Ok(vec![Diagnostic {
                            id: "authorized_keys_permissions",
                            severity: Severity::Ok,
                            message: format!(
                                "{} has acceptable permissions ({:o})",
                                ak_path.display(),
                                mode
                            ),
                            hint: None,
                            module: "local",
                        }])
                    } else {
                        Ok(vec![Diagnostic {
                            id: "authorized_keys_permissions",
                            severity: Severity::Error,
                            message: format!(
                                "{} has permissions {:o}, expected 600 or 644",
                                ak_path.display(),
                                mode
                            ),
                            hint: Some(format!("Run `chmod 600 {}`", ak_path.display())),
                            module: "local",
                        }])
                    }
                }
                Err(_) => Ok(vec![Diagnostic {
                    id: "authorized_keys_permissions",
                    severity: Severity::Info,
                    message: format!(
                        "Cannot check permissions: {} does not exist",
                        ak_path.display()
                    ),
                    hint: None,
                    module: "local",
                }]),
            }
        })
    }
}

// ---------------------------------------------------------------------------
// Non-Unix (Windows) stubs for permission checks
// ---------------------------------------------------------------------------

#[cfg(not(unix))]
impl Check for SshDirPermissions<'_> {
    fn id(&self) -> &'static str {
        "ssh_dir_permissions"
    }
    fn module(&self) -> &'static str {
        "local"
    }
    fn run(&self) -> CheckFuture<'_> {
        let ssh_dir = self.paths.ssh_dir().to_path_buf();
        Box::pin(async move {
            Ok(vec![Diagnostic {
                id: "ssh_dir_permissions",
                severity: Severity::Info,
                message: format!(
                    "Permission check for {} skipped (not supported on this platform)",
                    ssh_dir.display()
                ),
                hint: Some(
                    "On Windows, verify ACLs with: icacls \"%USERPROFILE%\\.ssh\"".into(),
                ),
                module: "local",
            }])
        })
    }
}

#[cfg(not(unix))]
impl Check for PrivateKeyPermissions<'_> {
    fn id(&self) -> &'static str {
        "private_key_permissions"
    }
    fn module(&self) -> &'static str {
        "local"
    }
    fn run(&self) -> CheckFuture<'_> {
        let ssh_dir = self.paths.ssh_dir().to_path_buf();
        Box::pin(async move {
            Ok(vec![Diagnostic {
                id: "private_key_permissions",
                severity: Severity::Info,
                message: format!(
                    "Private key permission check for {} skipped (not supported on this platform)",
                    ssh_dir.display()
                ),
                hint: Some(
                    "On Windows, restrict access to private key files with: icacls <keyfile> /inheritance:r /grant:r \"%USERNAME%:R\"".into(),
                ),
                module: "local",
            }])
        })
    }
}

#[cfg(not(unix))]
impl Check for OwnerCheck<'_> {
    fn id(&self) -> &'static str {
        "owner_check"
    }
    fn module(&self) -> &'static str {
        "local"
    }
    fn run(&self) -> CheckFuture<'_> {
        let ssh_dir = self.paths.ssh_dir().to_path_buf();
        Box::pin(async move {
            Ok(vec![Diagnostic {
                id: "owner_check",
                severity: Severity::Info,
                message: format!(
                    "Ownership check for {} skipped (not supported on this platform)",
                    ssh_dir.display()
                ),
                hint: Some(
                    "On Windows, verify ownership with: icacls \"%USERPROFILE%\\.ssh\"".into(),
                ),
                module: "local",
            }])
        })
    }
}

#[cfg(not(unix))]
impl Check for ConfigPermissionsCheck<'_> {
    fn id(&self) -> &'static str {
        "config_permissions"
    }
    fn module(&self) -> &'static str {
        "local"
    }
    fn run(&self) -> CheckFuture<'_> {
        let config_path = self.paths.config_path().to_path_buf();
        Box::pin(async move {
            Ok(vec![Diagnostic {
                id: "config_permissions",
                severity: Severity::Info,
                message: format!(
                    "Permission check for {} skipped (not supported on this platform)",
                    config_path.display()
                ),
                hint: Some(
                    "On Windows, restrict access to config with: icacls <configfile> /inheritance:r /grant:r \"%USERNAME%:F\"".into(),
                ),
                module: "local",
            }])
        })
    }
}

#[cfg(not(unix))]
impl Check for AuthorizedKeysPermissionsCheck<'_> {
    fn id(&self) -> &'static str {
        "authorized_keys_permissions"
    }
    fn module(&self) -> &'static str {
        "local"
    }
    fn run(&self) -> CheckFuture<'_> {
        let ak_path = self.paths.authorized_keys_path().to_path_buf();
        Box::pin(async move {
            Ok(vec![Diagnostic {
                id: "authorized_keys_permissions",
                severity: Severity::Info,
                message: format!(
                    "Permission check for {} skipped (not supported on this platform)",
                    ak_path.display()
                ),
                hint: Some(
                    "On Windows, verify ACLs with: icacls \"%USERPROFILE%\\.ssh\\authorized_keys\"".into(),
                ),
                module: "local",
            }])
        })
    }
}

// ---------------------------------------------------------------------------
// PlatformCheck
// ---------------------------------------------------------------------------

/// Report platform information: OS, architecture, SSH version, and agent type.
struct PlatformCheck;

impl Check for PlatformCheck {
    fn id(&self) -> &'static str {
        "platform_check"
    }
    fn module(&self) -> &'static str {
        "local"
    }
    fn run(&self) -> CheckFuture<'_> {
        Box::pin(async move {
            let mut diagnostics = Vec::new();

            // Report OS and architecture.
            diagnostics.push(Diagnostic {
                id: "platform_os",
                severity: Severity::Info,
                message: format!(
                    "Operating system: {} ({})",
                    std::env::consts::OS,
                    std::env::consts::ARCH
                ),
                hint: None,
                module: "local",
            });

            // Detect SSH agent type.
            #[cfg(unix)]
            {
                match std::env::var("SSH_AUTH_SOCK") {
                    Ok(sock) if !sock.is_empty() => {
                        diagnostics.push(Diagnostic {
                            id: "platform_agent_type",
                            severity: Severity::Info,
                            message: format!("SSH agent: Unix socket at {sock}"),
                            hint: None,
                            module: "local",
                        });
                    }
                    _ => {
                        diagnostics.push(Diagnostic {
                            id: "platform_agent_type",
                            severity: Severity::Info,
                            message: "SSH agent: not detected ($SSH_AUTH_SOCK not set)".into(),
                            hint: Some("Start the agent: `eval $(ssh-agent -s)`".into()),
                            module: "local",
                        });
                    }
                }
            }

            #[cfg(windows)]
            {
                if std::env::var("SSH_AUTH_SOCK").is_ok()
                    || std::env::var("SSH_AGENT_PID").is_ok()
                {
                    diagnostics.push(Diagnostic {
                        id: "platform_agent_type",
                        severity: Severity::Info,
                        message: "SSH agent: OpenSSH agent (Windows)".into(),
                        hint: None,
                        module: "local",
                    });
                } else {
                    diagnostics.push(Diagnostic {
                        id: "platform_agent_type",
                        severity: Severity::Info,
                        message: "SSH agent: not detected".into(),
                        hint: Some(
                            "Enable the OpenSSH agent: \
                             `Get-Service ssh-agent | Set-Service -StartupType Automatic`"
                                .into(),
                        ),
                        module: "local",
                    });
                }
            }

            // Run `ssh -V` to get the SSH client version.
            // `ssh -V` prints to stderr.
            let version_output = tokio::task::spawn_blocking(|| {
                duct::cmd("ssh", ["-V"])
                    .stderr_to_stdout()
                    .read()
                    .ok()
            })
            .await
            .ok()
            .flatten();

            match version_output {
                Some(v) => {
                    let version = v.trim().to_owned();
                    diagnostics.push(Diagnostic {
                        id: "platform_ssh_version",
                        severity: Severity::Ok,
                        message: format!("SSH client: {version}"),
                        hint: None,
                        module: "local",
                    });
                }
                None => {
                    diagnostics.push(Diagnostic {
                        id: "platform_ssh_version",
                        severity: Severity::Warning,
                        message: "SSH client not found in PATH".into(),
                        hint: Some(
                            "Install OpenSSH: \
                             `brew install openssh` (macOS), \
                             `sudo apt install openssh-client` (Linux), \
                             or enable the OpenSSH Client feature (Windows)"
                                .into(),
                        ),
                        module: "local",
                    });
                }
            }

            Ok(diagnostics)
        })
    }
}

// ---------------------------------------------------------------------------
// PublicKeyPairsCheck
// ---------------------------------------------------------------------------

impl Check for PublicKeyPairsCheck<'_> {
    fn id(&self) -> &'static str {
        "public_key_pairs"
    }
    fn module(&self) -> &'static str {
        "local"
    }
    fn run(&self) -> CheckFuture<'_> {
        let ssh_dir = self.paths.ssh_dir().to_path_buf();
        Box::pin(async move {
            let mut diagnostics = Vec::new();
            let Ok(mut read_dir) = tokio::fs::read_dir(&ssh_dir).await else {
                return Ok(vec![Diagnostic {
                    id: "public_key_pairs",
                    severity: Severity::Warning,
                    message: format!(
                        "Cannot scan {}: directory does not exist",
                        ssh_dir.display()
                    ),
                    hint: None,
                    module: "local",
                }]);
            };

            let mut private_keys = Vec::new();
            while let Some(entry) = read_dir.next_entry().await? {
                let name = entry.file_name();
                let name_str = name.to_string_lossy().to_string();

                // Match id_* private keys (not .pub, not -cert.pub).
                if name_str.starts_with("id_")
                    && !name_str.to_lowercase().ends_with(".pub")
                    && !name_str.to_lowercase().ends_with("-cert.pub")
                {
                    let path = entry.path();
                    let Ok(meta) = tokio::fs::metadata(&path).await else {
                        continue;
                    };
                    if meta.is_file() {
                        private_keys.push((name_str, path));
                    }
                }
            }

            if private_keys.is_empty() {
                return Ok(vec![Diagnostic {
                    id: "public_key_pairs",
                    severity: Severity::Info,
                    message: "No id_* private keys found in ~/.ssh".into(),
                    hint: None,
                    module: "local",
                }]);
            }

            for (name, path) in &private_keys {
                let pub_path = path.with_file_name(format!("{name}.pub"));
                if tokio::fs::metadata(&pub_path).await.is_ok() {
                    diagnostics.push(Diagnostic {
                        id: "public_key_pairs",
                        severity: Severity::Ok,
                        message: format!("{} has matching public key", path.display()),
                        hint: None,
                        module: "local",
                    });
                } else {
                    diagnostics.push(Diagnostic {
                        id: "public_key_pairs",
                        severity: Severity::Warning,
                        message: format!(
                            "{} has no matching public key file ({}.pub)",
                            path.display(),
                            name
                        ),
                        hint: Some(format!(
                            "Run `ssh-keygen -y -f {} > {}.pub`",
                            path.display(),
                            path.display()
                        )),
                        module: "local",
                    });
                }
            }

            Ok(diagnostics)
        })
    }
}

// ---------------------------------------------------------------------------
// CertificateFileExistsCheck
// ---------------------------------------------------------------------------

/// Check that `CertificateFile` paths referenced in config actually exist.
struct CertificateFileExistsCheck<'a> {
    paths: &'a SshPaths,
}

impl Check for CertificateFileExistsCheck<'_> {
    fn id(&self) -> &'static str {
        "certificate_file_exists"
    }
    fn module(&self) -> &'static str {
        "local"
    }
    fn run(&self) -> CheckFuture<'_> {
        let config_path = self.paths.config_path().to_path_buf();
        let ssh_dir = self.paths.ssh_dir().to_path_buf();
        Box::pin(async move {
            let Ok(content) = tokio::fs::read_to_string(&config_path).await else {
                return Ok(vec![Diagnostic {
                    id: "certificate_file_exists",
                    severity: Severity::Info,
                    message: format!(
                        "Cannot check CertificateFile directives: {} does not exist",
                        config_path.display()
                    ),
                    hint: None,
                    module: "local",
                }]);
            };

            let ast = ast::parse(&content);
            let mut cert_files: Vec<String> = Vec::new();

            // Collect CertificateFile directives from top-level and Host blocks.
            for node in &ast.nodes {
                match node {
                    ConfigNode::Directive(d) if d.keyword.eq_ignore_ascii_case("CertificateFile") => {
                        cert_files.push(d.value.clone());
                    }
                    ConfigNode::HostBlock(b) => {
                        for child in &b.nodes {
                            if let ConfigNode::Directive(d) = child
                                && d.keyword.eq_ignore_ascii_case("CertificateFile")
                            {
                                cert_files.push(d.value.clone());
                            }
                        }
                    }
                    _ => {}
                }
            }

            if cert_files.is_empty() {
                return Ok(vec![Diagnostic {
                    id: "certificate_file_exists",
                    severity: Severity::Info,
                    message: "No CertificateFile directives found in config".into(),
                    hint: None,
                    module: "local",
                }]);
            }

            let mut diagnostics = Vec::new();
            for raw_path in &cert_files {
                let expanded = crate::paths::expand_path(raw_path, &ssh_dir);

                if tokio::fs::metadata(&expanded).await.is_ok() {
                    diagnostics.push(Diagnostic {
                        id: "certificate_file_exists",
                        severity: Severity::Ok,
                        message: format!(
                            "CertificateFile {raw_path} exists ({})",
                            expanded.display()
                        ),
                        hint: None,
                        module: "local",
                    });
                } else {
                    diagnostics.push(Diagnostic {
                        id: "certificate_file_exists",
                        severity: Severity::Warning,
                        message: format!(
                            "CertificateFile {raw_path} does not exist ({})",
                            expanded.display()
                        ),
                        hint: Some(format!(
                            "Generate or copy the certificate file for {raw_path}",
                        )),
                        module: "local",
                    });
                }
            }

            Ok(diagnostics)
        })
    }
}

// ---------------------------------------------------------------------------
// IdentityFileExistsCheck
// ---------------------------------------------------------------------------

impl Check for IdentityFileExistsCheck<'_> {
    fn id(&self) -> &'static str {
        "identity_file_exists"
    }
    fn module(&self) -> &'static str {
        "local"
    }
    fn run(&self) -> CheckFuture<'_> {
        let config_path = self.paths.config_path().to_path_buf();
        let ssh_dir = self.paths.ssh_dir().to_path_buf();
        Box::pin(async move {
            let Ok(content) = tokio::fs::read_to_string(&config_path).await else {
                return Ok(vec![Diagnostic {
                    id: "identity_file_exists",
                    severity: Severity::Info,
                    message: format!(
                        "Cannot check IdentityFile directives: {} does not exist",
                        config_path.display()
                    ),
                    hint: None,
                    module: "local",
                }]);
            };

            let ast = ast::parse(&content);
            let mut identity_files: Vec<String> = Vec::new();

            // Collect IdentityFile directives from top-level and Host blocks.
            for node in &ast.nodes {
                match node {
                    ConfigNode::Directive(d) if d.keyword.eq_ignore_ascii_case("IdentityFile") => {
                        identity_files.push(d.value.clone());
                    }
                    ConfigNode::HostBlock(b) => {
                        for child in &b.nodes {
                            if let ConfigNode::Directive(d) = child
                                && d.keyword.eq_ignore_ascii_case("IdentityFile")
                            {
                                identity_files.push(d.value.clone());
                            }
                        }
                    }
                    _ => {}
                }
            }

            if identity_files.is_empty() {
                return Ok(vec![Diagnostic {
                    id: "identity_file_exists",
                    severity: Severity::Info,
                    message: "No IdentityFile directives found in config".into(),
                    hint: None,
                    module: "local",
                }]);
            }

            let mut diagnostics = Vec::new();
            for raw_path in &identity_files {
                let expanded = crate::paths::expand_path(raw_path, &ssh_dir);

                if tokio::fs::metadata(&expanded).await.is_ok() {
                    diagnostics.push(Diagnostic {
                        id: "identity_file_exists",
                        severity: Severity::Ok,
                        message: format!(
                            "IdentityFile {raw_path} exists ({})",
                            expanded.display()
                        ),
                        hint: None,
                        module: "local",
                    });
                } else {
                    diagnostics.push(Diagnostic {
                        id: "identity_file_exists",
                        severity: Severity::Warning,
                        message: format!(
                            "IdentityFile {raw_path} does not exist ({})",
                            expanded.display()
                        ),
                        hint: Some(format!(
                            "Generate the missing key or update the config entry for {raw_path}",
                        )),
                        module: "local",
                    });
                }
            }

            Ok(diagnostics)
        })
    }
}

// ---------------------------------------------------------------------------
// DuplicateHostCheck
// ---------------------------------------------------------------------------

impl Check for DuplicateHostCheck<'_> {
    fn id(&self) -> &'static str {
        "duplicate_host"
    }
    fn module(&self) -> &'static str {
        "local"
    }
    fn run(&self) -> CheckFuture<'_> {
        let config_path = self.paths.config_path().to_path_buf();
        Box::pin(async move {
            let Ok(content) = tokio::fs::read_to_string(&config_path).await else {
                return Ok(vec![Diagnostic {
                    id: "duplicate_host",
                    severity: Severity::Info,
                    message: format!(
                        "Cannot check for duplicate hosts: {} does not exist",
                        config_path.display()
                    ),
                    hint: None,
                    module: "local",
                }]);
            };

            let ast = ast::parse(&content);

            // Track each pattern and the first Host block header it appeared in.
            let mut seen: HashMap<String, String> = HashMap::new();
            let mut duplicates: Vec<(String, String, String)> = Vec::new();

            for node in &ast.nodes {
                if let ConfigNode::HostBlock(b) = node
                {
                    for pat in &b.patterns {
                        if pat == "*" {
                            // Skip wildcard for duplicate detection.
                            continue;
                        }
                        match seen.entry(pat.clone()) {
                            std::collections::hash_map::Entry::Occupied(e) => {
                                duplicates.push((pat.clone(), e.get().clone(), b.header.clone()));
                            }
                            std::collections::hash_map::Entry::Vacant(e) => {
                                e.insert(b.header.clone());
                            }
                        }
                    }
                }
            }

            if duplicates.is_empty() {
                Ok(vec![Diagnostic {
                    id: "duplicate_host",
                    severity: Severity::Ok,
                    message: "No duplicate Host patterns found in config".into(),
                    hint: None,
                    module: "local",
                }])
            } else {
                let mut diagnostics = Vec::new();
                for (pattern, first, second) in &duplicates {
                    diagnostics.push(Diagnostic {
                        id: "duplicate_host",
                        severity: Severity::Warning,
                        message: format!(
                            "Host pattern '{pattern}' appears in multiple blocks: '{first}' and '{second}'",
                        ),
                        hint: Some(format!(
                            "Merge or remove the duplicate entry for '{pattern}'",
                        )),
                        module: "local",
                    });
                }
                Ok(diagnostics)
            }
        })
    }
}

// ---------------------------------------------------------------------------
// HostStarPlacementCheck
// ---------------------------------------------------------------------------

impl Check for HostStarPlacementCheck<'_> {
    fn id(&self) -> &'static str {
        "host_star_placement"
    }
    fn module(&self) -> &'static str {
        "local"
    }
    fn run(&self) -> CheckFuture<'_> {
        let config_path = self.paths.config_path().to_path_buf();
        Box::pin(async move {
            let Ok(content) = tokio::fs::read_to_string(&config_path).await else {
                return Ok(vec![Diagnostic {
                    id: "host_star_placement",
                    severity: Severity::Info,
                    message: format!(
                        "Cannot check Host * placement: {} does not exist",
                        config_path.display()
                    ),
                    hint: None,
                    module: "local",
                }]);
            };

            let ast = ast::parse(&content);

            // Find the index of the first Host * and the last specific Host block.
            let mut star_index: Option<usize> = None;
            let mut last_specific_index: Option<usize> = None;

            for (i, node) in ast.nodes.iter().enumerate() {
                if let ConfigNode::HostBlock(b) = node {
                    if b.patterns.iter().any(|p| p == "*") {
                        if star_index.is_none() {
                            star_index = Some(i);
                        }
                    } else if !b.patterns.is_empty() {
                        last_specific_index = Some(i);
                    }
                }
            }

            match (star_index, last_specific_index) {
                (Some(star), Some(last)) if star < last => Ok(vec![Diagnostic {
                    id: "host_star_placement",
                    severity: Severity::Warning,
                    message:
                        "'Host *' appears before specific Host blocks; \
                         later Host blocks cannot override its defaults"
                            .into(),
                    hint: Some(
                        "Move 'Host *' to the end of the config file so specific \
                         blocks take precedence"
                            .into(),
                    ),
                    module: "local",
                }]),
                _ => Ok(vec![Diagnostic {
                    id: "host_star_placement",
                    severity: Severity::Ok,
                    message: "'Host *' placement is correct (after specific Host blocks, or absent)".into(),
                    hint: None,
                    module: "local",
                }]),
            }
        })
    }
}

// ---------------------------------------------------------------------------
// SshV1KeyCheck
// ---------------------------------------------------------------------------

impl Check for SshV1KeyCheck<'_> {
    fn id(&self) -> &'static str {
        "ssh_v1_key"
    }
    fn module(&self) -> &'static str {
        "local"
    }
    fn run(&self) -> CheckFuture<'_> {
        let ssh_dir = self.paths.ssh_dir().to_path_buf();
        Box::pin(async move {
            let identity_path = ssh_dir.join("identity");
            let identity_pub_path = ssh_dir.join("identity.pub");

            let has_private = tokio::fs::metadata(&identity_path).await.is_ok();
            let has_public = tokio::fs::metadata(&identity_pub_path).await.is_ok();

            if has_private || has_public {
                let mut found = Vec::new();
                if has_private {
                    found.push(identity_path.display().to_string());
                }
                if has_public {
                    found.push(identity_pub_path.display().to_string());
                }
                Ok(vec![Diagnostic {
                    id: "ssh_v1_key",
                    severity: Severity::Warning,
                    message: format!(
                        "Deprecated SSHv1 key file(s) found: {}",
                        found.join(", ")
                    ),
                    hint: Some(
                        "SSHv1 keys are insecure. Remove them and use Ed25519 or RSA keys instead: \
                         `rm ~/.ssh/identity ~/.ssh/identity.pub`"
                            .into(),
                    ),
                    module: "local",
                }])
            } else {
                Ok(vec![Diagnostic {
                    id: "ssh_v1_key",
                    severity: Severity::Ok,
                    message: "No deprecated SSHv1 key files found".into(),
                    hint: None,
                    module: "local",
                }])
            }
        })
    }
}

// ---------------------------------------------------------------------------
// UseKeychainPlatformCheck — warn if UseKeychain is set on non-macOS
// ---------------------------------------------------------------------------

impl Check for UseKeychainPlatformCheck<'_> {
    fn id(&self) -> &'static str {
        "use_keychain_platform"
    }
    fn module(&self) -> &'static str {
        "local"
    }
    fn run(&self) -> CheckFuture<'_> {
        let config_path = self.paths.config_path().to_path_buf();
        Box::pin(async move {
            let Ok(content) = tokio::fs::read_to_string(&config_path).await else {
                return Ok(vec![Diagnostic {
                    id: "use_keychain_platform",
                    severity: Severity::Info,
                    message: format!(
                        "Cannot check UseKeychain: {} does not exist",
                        config_path.display()
                    ),
                    hint: None,
                    module: "local",
                }]);
            };

            let ast = ast::parse(&content);
            let mut use_keychain_contexts: Vec<String> = Vec::new();

            // Collect UseKeychain directives from top-level and Host blocks.
            for node in &ast.nodes {
                match node {
                    ConfigNode::Directive(d) if d.keyword.eq_ignore_ascii_case("UseKeychain") => {
                        use_keychain_contexts.push("top-level".into());
                    }
                    ConfigNode::HostBlock(b) => {
                        let ctx = format!("Host {}", b.patterns.join(", "));
                        for child in &b.nodes {
                            if let ConfigNode::Directive(d) = child
                                && d.keyword.eq_ignore_ascii_case("UseKeychain")
                            {
                                use_keychain_contexts.push(ctx.clone());
                            }
                        }
                    }
                    _ => {}
                }
            }

            if use_keychain_contexts.is_empty() {
                return Ok(vec![Diagnostic {
                    id: "use_keychain_platform",
                    severity: Severity::Ok,
                    message: "No UseKeychain directive found in config".into(),
                    hint: None,
                    module: "local",
                }]);
            }

            let is_macos = cfg!(target_os = "macos");

            if is_macos {
                Ok(vec![Diagnostic {
                    id: "use_keychain_platform",
                    severity: Severity::Ok,
                    message: format!(
                        "UseKeychain is set in {} context(s) on macOS (supported)",
                        use_keychain_contexts.len()
                    ),
                    hint: None,
                    module: "local",
                }])
            } else {
                let mut diagnostics = Vec::new();
                for ctx in &use_keychain_contexts {
                    diagnostics.push(Diagnostic {
                        id: "use_keychain_platform",
                        severity: Severity::Warning,
                        message: format!(
                            "UseKeychain is set in {ctx} but this is not macOS — \
                             UseKeychain is a macOS-specific directive and will be ignored"
                        ),
                        hint: Some(
                            "Remove UseKeychain from non-macOS configs, or use a Match block \
                             to apply it only on macOS: `Match exec \"uname | grep Darwin\"`"
                                .into(),
                        ),
                        module: "local",
                    });
                }
                Ok(diagnostics)
            }
        })
    }
}

// ---------------------------------------------------------------------------
// IdentityFilePubCheck — warn if IdentityFile points to a .pub file
// ---------------------------------------------------------------------------

/// Check that `IdentityFile` directives don't accidentally point to `.pub` files.
struct IdentityFilePubCheck<'a> {
    paths: &'a SshPaths,
}

impl Check for IdentityFilePubCheck<'_> {
    fn id(&self) -> &'static str {
        "identity_file_pub"
    }
    fn module(&self) -> &'static str {
        "local"
    }
    fn run(&self) -> CheckFuture<'_> {
        let config_path = self.paths.config_path().to_path_buf();
        Box::pin(async move {
            let Ok(content) = tokio::fs::read_to_string(&config_path).await else {
                return Ok(vec![]);
            };

            let ast = ast::parse(&content);
            let mut diagnostics = Vec::new();

            let check_value = |raw: &str, diags: &mut Vec<Diagnostic>| {
                let path = std::path::Path::new(raw);
                let is_pub = path.extension().is_some_and(|ext| ext.eq_ignore_ascii_case("pub"));
                let is_cert = raw.to_lowercase().ends_with("-cert.pub");
                if is_pub || is_cert {
                    diags.push(Diagnostic {
                        id: "identity_file_pub",
                        severity: Severity::Warning,
                        message: format!(
                            "IdentityFile {raw} points to a public key file; \
                             IdentityFile should reference the private key"
                        ),
                        hint: Some("Change to the private key path (remove .pub suffix)".into()),
                        module: "local",
                    });
                }
            };

            for node in &ast.nodes {
                match node {
                    ConfigNode::Directive(d) if d.keyword.eq_ignore_ascii_case("IdentityFile") => {
                        check_value(&d.value, &mut diagnostics);
                    }
                    ConfigNode::HostBlock(b) => {
                        for child in &b.nodes {
                            if let ConfigNode::Directive(d) = child
                                && d.keyword.eq_ignore_ascii_case("IdentityFile")
                            {
                                check_value(&d.value, &mut diagnostics);
                            }
                        }
                    }
                    _ => {}
                }
            }

            if diagnostics.is_empty() {
                Ok(vec![Diagnostic {
                    id: "identity_file_pub",
                    severity: Severity::Ok,
                    message: "No IdentityFile directives point to .pub files".into(),
                    hint: None,
                    module: "local",
                }])
            } else {
                Ok(diagnostics)
            }
        })
    }
}

// ---------------------------------------------------------------------------
// IdentitiesOnlyCheck — warn when multi-key hosts lack IdentitiesOnly
// ---------------------------------------------------------------------------

/// Check that hosts with multiple `IdentityFile` entries also have
/// `IdentitiesOnly yes` to prevent the agent from offering wrong keys.
struct IdentitiesOnlyCheck<'a> {
    paths: &'a SshPaths,
}

impl Check for IdentitiesOnlyCheck<'_> {
    fn id(&self) -> &'static str {
        "identities_only"
    }
    fn module(&self) -> &'static str {
        "local"
    }
    fn run(&self) -> CheckFuture<'_> {
        let config_path = self.paths.config_path().to_path_buf();
        Box::pin(async move {
            let Ok(content) = tokio::fs::read_to_string(&config_path).await else {
                return Ok(vec![]);
            };

            let ast = ast::parse(&content);
            let mut diagnostics = Vec::new();

            for node in &ast.nodes {
                if let ConfigNode::HostBlock(b) = node {
                    let id_count = b.nodes
                        .iter()
                        .filter(|n| {
                            matches!(n, ConfigNode::Directive(d)
                                if d.keyword.eq_ignore_ascii_case("IdentityFile"))
                        })
                        .count();

                    if id_count > 1 {
                        let has_identities_only = b.nodes.iter().any(|n| {
                            matches!(n, ConfigNode::Directive(d)
                                if d.keyword.eq_ignore_ascii_case("IdentitiesOnly")
                                    && d.value.eq_ignore_ascii_case("yes"))
                        });

                        if !has_identities_only {
                            let host_str = b.patterns.join(", ");
                            diagnostics.push(Diagnostic {
                                id: "identities_only",
                                severity: Severity::Warning,
                                message: format!(
                                    "Host {host_str} has {id_count} IdentityFile entries \
                                     but no IdentitiesOnly yes"
                                ),
                                hint: Some(
                                    "Add IdentitiesOnly yes to prevent the agent from \
                                     offering keys not listed in this Host block"
                                        .into(),
                                ),
                                module: "local",
                            });
                        }
                    }
                }
            }

            if diagnostics.is_empty() {
                Ok(vec![Diagnostic {
                    id: "identities_only",
                    severity: Severity::Ok,
                    message: "No multi-key Host blocks missing IdentitiesOnly".into(),
                    hint: None,
                    module: "local",
                }])
            } else {
                Ok(diagnostics)
            }
        })
    }
}

// ---------------------------------------------------------------------------
// GssapiConfigCheck — GSSAPI/Kerberos configuration awareness
// ---------------------------------------------------------------------------

/// GSSAPI-related directive keywords to scan for.
const GSSAPI_DIRECTIVES: &[&str] = &[
    "GSSAPIAuthentication",
    "GSSAPIDelegateCredentials",
    "GSSAPIServerIdentity",
    "GSSAPIClientIdentity",
    "GSSAPIKeyExchange",
    "GSSAPIRenewalForcesRekey",
    "GSSAPIStrictAcceptorCheck",
    "GSSAPITrustDns",
];

/// Check whether `PreferredAuthentications` is set to `gssapi-with-mic` only
/// (excluding publickey) anywhere in the config AST.
fn is_preferred_gssapi_only(ast: &ast::ConfigAst) -> bool {
    let mut result = false;
    for node in &ast.nodes {
        match node {
            ConfigNode::Directive(d)
                if d.keyword.eq_ignore_ascii_case("PreferredAuthentications") =>
            {
                let methods: Vec<&str> = d.value.split(',').map(str::trim).collect();
                let has_gssapi = methods.iter().any(|m| m.eq_ignore_ascii_case("gssapi-with-mic"));
                let has_pubkey = methods.iter().any(|m| m.eq_ignore_ascii_case("publickey"));
                if has_gssapi && !has_pubkey && methods.len() == 1 {
                    result = true;
                }
            }
            ConfigNode::HostBlock(b) => {
                for child in &b.nodes {
                    if let ConfigNode::Directive(d) = child
                        && d.keyword.eq_ignore_ascii_case("PreferredAuthentications")
                    {
                        let methods: Vec<&str> = d.value.split(',').map(str::trim).collect();
                        let has_gssapi =
                            methods.iter().any(|m| m.eq_ignore_ascii_case("gssapi-with-mic"));
                        let has_pubkey = methods.iter().any(|m| m.eq_ignore_ascii_case("publickey"));
                        if has_gssapi && !has_pubkey && methods.len() == 1 {
                            result = true;
                        }
                    }
                }
            }
            _ => {}
        }
    }
    result
}

impl Check for GssapiConfigCheck<'_> {
    fn id(&self) -> &'static str {
        "gssapi_config"
    }
    fn module(&self) -> &'static str {
        "local"
    }
    fn run(&self) -> CheckFuture<'_> {
        let config_path = self.paths.config_path().to_path_buf();
        Box::pin(async move {
            let Ok(content) = tokio::fs::read_to_string(&config_path).await else {
                return Ok(vec![Diagnostic {
                    id: "gssapi_config",
                    severity: Severity::Info,
                    message: format!(
                        "Cannot check GSSAPI configuration: {} does not exist",
                        config_path.display()
                    ),
                    hint: None,
                    module: "local",
                }]);
            };

            let ast = ast::parse(&content);

            // Collect GSSAPI directives with their context (top-level or Host block).
            let mut findings: Vec<(String, String, String)> = Vec::new();

            for node in &ast.nodes {
                match node {
                    ConfigNode::Directive(d)
                        if GSSAPI_DIRECTIVES.iter().any(|kw| d.keyword.eq_ignore_ascii_case(kw)) =>
                    {
                        findings.push((d.keyword.clone(), d.value.clone(), "top-level".into()));
                    }
                    ConfigNode::HostBlock(b) => {
                        let ctx = format!("Host {}", b.patterns.join(", "));
                        for child in &b.nodes {
                            if let ConfigNode::Directive(d) = child
                                && GSSAPI_DIRECTIVES
                                    .iter()
                                    .any(|kw| d.keyword.eq_ignore_ascii_case(kw))
                            {
                                findings.push((d.keyword.clone(), d.value.clone(), ctx.clone()));
                            }
                        }
                    }
                    _ => {}
                }
            }

            if findings.is_empty() {
                return Ok(vec![Diagnostic {
                    id: "gssapi_config",
                    severity: Severity::Ok,
                    message: "No GSSAPI directives found in config".into(),
                    hint: None,
                    module: "local",
                }]);
            }

            let mut diagnostics = Vec::new();

            // Report each configured GSSAPI directive.
            let summary_parts: Vec<String> = findings
                .iter()
                .map(|(keyword, value, context)| format!("{keyword} {value} ({context})"))
                .collect();

            diagnostics.push(Diagnostic {
                id: "gssapi_config",
                severity: Severity::Info,
                message: format!("GSSAPI configuration: {}", summary_parts.join("; ")),
                hint: None,
                module: "local",
            });

            // Warn if GSSAPIAuthentication is the ONLY authentication method
            // and publickey is explicitly excluded via PreferredAuthentications.
            let gssapi_auth_yes = findings.iter().any(|(kw, val, _)| {
                kw.eq_ignore_ascii_case("GSSAPIAuthentication") && val.eq_ignore_ascii_case("yes")
            });

            if gssapi_auth_yes && is_preferred_gssapi_only(&ast) {
                diagnostics.push(Diagnostic {
                    id: "gssapi_config",
                    severity: Severity::Warning,
                    message: "GSSAPIAuthentication is enabled and PreferredAuthentications \
                              is set to gssapi-with-mic only — publickey authentication is \
                              excluded, which may reduce security"
                        .into(),
                    hint: Some(
                        "Consider adding 'publickey' to PreferredAuthentications as a \
                         fallback, e.g.: PreferredAuthentications gssapi-with-mic,publickey"
                            .into(),
                    ),
                    module: "local",
                });
            }

            Ok(diagnostics)
        })
    }
}

// ---------------------------------------------------------------------------
// VerifyHostKeyDnsCheck — VerifyHostKeyDNS configuration and SSHFP readiness
// ---------------------------------------------------------------------------

impl Check for VerifyHostKeyDnsCheck<'_> {
    fn id(&self) -> &'static str {
        "verify_host_key_dns"
    }
    fn module(&self) -> &'static str {
        "local"
    }
    #[allow(clippy::too_many_lines)]
    fn run(&self) -> CheckFuture<'_> {
        let config_path = self.paths.config_path().to_path_buf();
        Box::pin(async move {
            let Ok(content) = tokio::fs::read_to_string(&config_path).await else {
                return Ok(vec![Diagnostic {
                    id: "verify_host_key_dns",
                    severity: Severity::Info,
                    message: format!(
                        "Cannot check VerifyHostKeyDNS: {} does not exist",
                        config_path.display()
                    ),
                    hint: None,
                    module: "local",
                }]);
            };

            let status = crate::known_hosts::detect_verify_host_key_dns(&content);

            match status {
                crate::known_hosts::DnsVerifyStatus::Unknown => {
                    Ok(vec![Diagnostic {
                        id: "verify_host_key_dns",
                        severity: Severity::Info,
                        message: "VerifyHostKeyDNS is not configured (default: no)".into(),
                        hint: Some(
                            "To enable DNS-based host key verification, add \
                             'VerifyHostKeyDNS yes' to your SSH config"
                                .into(),
                        ),
                        module: "local",
                    }])
                }
                crate::known_hosts::DnsVerifyStatus::Disabled => {
                    Ok(vec![Diagnostic {
                        id: "verify_host_key_dns",
                        severity: Severity::Ok,
                        message: "VerifyHostKeyDNS is set to 'no'".into(),
                        hint: None,
                        module: "local",
                    }])
                }
                crate::known_hosts::DnsVerifyStatus::Ask => {
                    Ok(vec![Diagnostic {
                        id: "verify_host_key_dns",
                        severity: Severity::Info,
                        message: "VerifyHostKeyDNS is set to 'ask' — \
                                  host keys will be verified via SSHFP but you will \
                                  be prompted on mismatch"
                            .into(),
                        hint: None,
                        module: "local",
                    }])
                }
                crate::known_hosts::DnsVerifyStatus::Enabled => {
                    let mut diagnostics = Vec::new();

                    diagnostics.push(Diagnostic {
                        id: "verify_host_key_dns",
                        severity: Severity::Ok,
                        message: "VerifyHostKeyDNS is set to 'yes' — \
                                  host keys will be verified via SSHFP DNS records"
                            .into(),
                        hint: None,
                        module: "local",
                    });

                    // Basic DNS resolution check: try to resolve localhost
                    // as a heuristic that DNS is functional.
                    let dns_available = tokio::task::spawn_blocking(|| {
                        duct::cmd("host", ["localhost"])
                            .stderr_null()
                            .read()
                            .is_ok()
                    })
                    .await
                    .unwrap_or(false);

                    if dns_available {
                        diagnostics.push(Diagnostic {
                            id: "verify_host_key_dns",
                            severity: Severity::Ok,
                            message: "DNS resolution appears to be available".into(),
                            hint: None,
                            module: "local",
                        });
                    } else {
                        diagnostics.push(Diagnostic {
                            id: "verify_host_key_dns",
                            severity: Severity::Warning,
                            message: "VerifyHostKeyDNS is enabled but DNS resolution may \
                                      not be available — SSHFP verification will fail"
                                .into(),
                            hint: Some(
                                "Ensure DNS is configured correctly, or install bind-utils \
                                 / dnsutils for the 'host' command"
                                    .into(),
                            ),
                            module: "local",
                        });
                    }

                    // Warn about SSHFP record requirements.
                    diagnostics.push(Diagnostic {
                        id: "verify_host_key_dns",
                        severity: Severity::Info,
                        message: "SSHFP records must be published in DNS for each host. \
                                  Generate with: ssh-keygen -r <hostname>"
                            .into(),
                        hint: Some(
                            "If hosts do not have SSHFP records in their DNS zone, \
                             VerifyHostKeyDNS will not be able to verify them"
                                .into(),
                        ),
                        module: "local",
                    });

                    Ok(diagnostics)
                }
            }
        })
    }
}

// ---------------------------------------------------------------------------
// HomeDirPermissionsCheck — StrictModes full chain
// ---------------------------------------------------------------------------

/// Check that the home directory is not group/world writable (StrictModes).
#[cfg(unix)]
struct HomeDirPermissionsCheck;

#[cfg(unix)]
impl Check for HomeDirPermissionsCheck {
    fn id(&self) -> &'static str {
        "home_dir_permissions"
    }
    fn module(&self) -> &'static str {
        "local"
    }
    fn run(&self) -> CheckFuture<'_> {
        Box::pin(async move {
            let Some(home) = dirs::home_dir() else {
                return Ok(vec![Diagnostic {
                    id: "home_dir_permissions",
                    severity: Severity::Info,
                    message: "Cannot determine home directory".into(),
                    hint: None,
                    module: "local",
                }]);
            };

            let Ok(meta) = tokio::fs::metadata(&home).await else {
                return Ok(vec![Diagnostic {
                    id: "home_dir_permissions",
                    severity: Severity::Warning,
                    message: format!("Cannot read home directory: {}", home.display()),
                    hint: None,
                    module: "local",
                }]);
            };

            let mode = meta.permissions().mode();
            let group_write = mode & 0o020 != 0;
            let other_write = mode & 0o002 != 0;

            if group_write || other_write {
                let who = match (group_write, other_write) {
                    (true, true) => "group and world",
                    (true, false) => "group",
                    (false, true) => "world",
                    _ => unreachable!(),
                };
                Ok(vec![Diagnostic {
                    id: "home_dir_permissions",
                    severity: Severity::Warning,
                    message: format!(
                        "Home directory {} is {} writable — \
                         sshd StrictModes may reject authorized_keys",
                        home.display(),
                        who,
                    ),
                    hint: Some(format!(
                        "chmod g-w,o-w {}",
                        home.display(),
                    )),
                    module: "local",
                }])
            } else {
                Ok(vec![Diagnostic {
                    id: "home_dir_permissions",
                    severity: Severity::Ok,
                    message: format!(
                        "Home directory {} has correct permissions",
                        home.display()
                    ),
                    hint: None,
                    module: "local",
                }])
            }
        })
    }
}

// ---------------------------------------------------------------------------
// MaxAuthTriesExhaustionCheck — count agent keys vs MaxAuthTries
// ---------------------------------------------------------------------------

/// Count keys loaded in the SSH agent and warn if the count is close to
/// the default `MaxAuthTries` limit (6). When a client offers more keys
/// than the server allows attempts, authentication silently fails after
/// the server rejects the excess offers.
struct MaxAuthTriesExhaustionCheck;

impl Check for MaxAuthTriesExhaustionCheck {
    fn id(&self) -> &'static str {
        "max_auth_tries_exhaustion"
    }
    fn module(&self) -> &'static str {
        "local"
    }
    fn run(&self) -> CheckFuture<'_> {
        Box::pin(async move {
            // Default MaxAuthTries on most sshd installations.
            const DEFAULT_MAX_AUTH_TRIES: usize = 6;

            if std::env::var("SSH_AUTH_SOCK").map_or(true, |v| v.is_empty()) {
                return Ok(vec![Diagnostic {
                    id: "max_auth_tries_exhaustion",
                    severity: Severity::Info,
                    message: "SSH agent is not running — cannot count loaded keys".into(),
                    hint: None,
                    module: "local",
                }]);
            }

            let output = tokio::task::spawn_blocking(|| {
                duct::cmd("ssh-add", ["-l"])
                    .stderr_null()
                    .read()
                    .ok()
            })
            .await
            .ok()
            .flatten();

            let Some(output) = output else {
                return Ok(vec![Diagnostic {
                    id: "max_auth_tries_exhaustion",
                    severity: Severity::Info,
                    message: "Could not list agent keys via `ssh-add -l`".into(),
                    hint: None,
                    module: "local",
                }]);
            };

            // `ssh-add -l` exits 1 with "The agent has no identities." when
            // empty, and 2 on error. When successful it prints one key per line.
            let key_count = output.lines().filter(|l| !l.is_empty()).count();

            if key_count == 0 {
                return Ok(vec![Diagnostic {
                    id: "max_auth_tries_exhaustion",
                    severity: Severity::Ok,
                    message: "No keys loaded in agent — MaxAuthTries exhaustion not a concern".into(),
                    hint: None,
                    module: "local",
                }]);
            }

            if key_count >= DEFAULT_MAX_AUTH_TRIES {
                Ok(vec![Diagnostic {
                    id: "max_auth_tries_exhaustion",
                    severity: Severity::Warning,
                    message: format!(
                        "SSH agent has {key_count} keys loaded (MaxAuthTries default is {DEFAULT_MAX_AUTH_TRIES}). \
                         The server may reject authentication before offering the correct key"
                    ),
                    hint: Some(
                        "Reduce agent keys with `ssh-add -D` and re-add only needed keys, \
                         or increase MaxAuthTries on the server. Consider using IdentitiesOnly yes per-host"
                            .to_string(),
                    ),
                    module: "local",
                }])
            } else if key_count >= DEFAULT_MAX_AUTH_TRIES - 1 {
                Ok(vec![Diagnostic {
                    id: "max_auth_tries_exhaustion",
                    severity: Severity::Info,
                    message: format!(
                        "SSH agent has {key_count} keys loaded (approaching MaxAuthTries default of {DEFAULT_MAX_AUTH_TRIES})"
                    ),
                    hint: Some(
                        "Consider using IdentitiesOnly yes in your SSH config for hosts that use specific keys".into(),
                    ),
                    module: "local",
                }])
            } else {
                Ok(vec![Diagnostic {
                    id: "max_auth_tries_exhaustion",
                    severity: Severity::Ok,
                    message: format!(
                        "SSH agent has {key_count} keys loaded (within MaxAuthTries limit of {DEFAULT_MAX_AUTH_TRIES})"
                    ),
                    hint: None,
                    module: "local",
                }])
            }
        })
    }
}

// ---------------------------------------------------------------------------
// PreferredAuthenticationsCheck — read PreferredAuthentications from config
// ---------------------------------------------------------------------------

/// Check for `PreferredAuthentications` directives in the SSH config and
/// report the configured authentication order. This helps diagnose connection
/// issues when specific auth methods are disabled on the server.
struct PreferredAuthenticationsCheck<'a> {
    paths: &'a SshPaths,
}

impl Check for PreferredAuthenticationsCheck<'_> {
    fn id(&self) -> &'static str {
        "preferred_authentications"
    }
    fn module(&self) -> &'static str {
        "local"
    }
    fn run(&self) -> CheckFuture<'_> {
        let config_path = self.paths.config_path().to_path_buf();
        Box::pin(async move {
            let Ok(content) = tokio::fs::read_to_string(&config_path).await else {
                return Ok(vec![Diagnostic {
                    id: "preferred_authentications",
                    severity: Severity::Info,
                    message: format!(
                        "Cannot check PreferredAuthentications: {} does not exist",
                        config_path.display()
                    ),
                    hint: None,
                    module: "local",
                }]);
            };

            let ast = ast::parse(&content);
            let mut preferred: Vec<(String, String)> = Vec::new(); // (context, value)

            // Collect PreferredAuthentications from top-level and Host blocks.
            for node in &ast.nodes {
                match node {
                    ConfigNode::Directive(d) if d.keyword.eq_ignore_ascii_case("PreferredAuthentications") => {
                        preferred.push(("top-level".into(), d.value.clone()));
                    }
                    ConfigNode::HostBlock(b) => {
                        let ctx = format!("Host {}", b.patterns.join(", "));
                        for child in &b.nodes {
                            if let ConfigNode::Directive(d) = child
                                && d.keyword.eq_ignore_ascii_case("PreferredAuthentications")
                            {
                                preferred.push((ctx.clone(), d.value.clone()));
                            }
                        }
                    }
                    _ => {}
                }
            }

            if preferred.is_empty() {
                return Ok(vec![Diagnostic {
                    id: "preferred_authentications",
                    severity: Severity::Ok,
                    message: "No PreferredAuthentications directive in config (uses client default)".into(),
                    hint: None,
                    module: "local",
                }]);
            }

            let mut diagnostics = Vec::new();
            for (context, value) in &preferred {
                let methods: Vec<&str> = value.split(',').map(str::trim).collect();
                let has_pubkey = methods.iter().any(|m| m.eq_ignore_ascii_case("publickey"));
                let has_password = methods.iter().any(|m| m.eq_ignore_ascii_case("password"));

                diagnostics.push(Diagnostic {
                    id: "preferred_authentications",
                    severity: if has_pubkey { Severity::Ok } else { Severity::Info },
                    message: format!(
                        "PreferredAuthentications in {context}: {value}"
                    ),
                    hint: if !has_pubkey && has_password {
                        Some(
                            "Consider adding 'publickey' before 'password' in PreferredAuthentications \
                             for better security".into(),
                        )
                    } else {
                        None
                    },
                    module: "local",
                });
            }

            Ok(diagnostics)
        })
    }
}

// ---------------------------------------------------------------------------
// ProxyJumpHostCheck — verify ProxyJump targets exist in config
// ---------------------------------------------------------------------------

/// For every `ProxyJump` directive in the SSH config, verify that the target
/// host has a usable config entry (a `Host` block or is resolvable).
struct ProxyJumpHostCheck<'a> {
    paths: &'a SshPaths,
}

impl Check for ProxyJumpHostCheck<'_> {
    fn id(&self) -> &'static str {
        "proxy_jump_host"
    }
    fn module(&self) -> &'static str {
        "local"
    }
    #[allow(clippy::too_many_lines)]
    fn run(&self) -> CheckFuture<'_> {
        let config_path = self.paths.config_path().to_path_buf();
        Box::pin(async move {
            let Ok(content) = tokio::fs::read_to_string(&config_path).await else {
                return Ok(vec![Diagnostic {
                    id: "proxy_jump_host",
                    severity: Severity::Info,
                    message: format!(
                        "Cannot check ProxyJump targets: {} does not exist",
                        config_path.display()
                    ),
                    hint: None,
                    module: "local",
                }]);
            };

            let ast = ast::parse(&content);

            // Collect all Host block patterns for lookup.
            let mut host_patterns: Vec<String> = Vec::new();
            for node in &ast.nodes {
                if let ConfigNode::HostBlock(b) = node {
                    for pat in &b.patterns {
                        if pat != "*" {
                            host_patterns.push(pat.to_lowercase());
                        }
                    }
                }
            }

            // Collect all ProxyJump directive values (top-level and in blocks).
            let mut proxy_jumps: Vec<(String, String)> = Vec::new(); // (value, context)
            for node in &ast.nodes {
                match node {
                    ConfigNode::Directive(d) if d.keyword.eq_ignore_ascii_case("ProxyJump") => {
                        proxy_jumps.push((d.value.clone(), "top-level".into()));
                    }
                    ConfigNode::HostBlock(b) => {
                        let ctx = format!("Host {}", b.patterns.join(", "));
                        for child in &b.nodes {
                            if let ConfigNode::Directive(d) = child
                                && d.keyword.eq_ignore_ascii_case("ProxyJump")
                            {
                                proxy_jumps.push((d.value.clone(), ctx.clone()));
                            }
                        }
                    }
                    _ => {}
                }
            }

            if proxy_jumps.is_empty() {
                return Ok(vec![Diagnostic {
                    id: "proxy_jump_host",
                    severity: Severity::Ok,
                    message: "No ProxyJump directives found in config".into(),
                    hint: None,
                    module: "local",
                }]);
            }

            let mut diagnostics = Vec::new();
            for (raw_value, context) in &proxy_jumps {
                // ProxyJump values can be "none", a comma-separated list of
                // [user@]host[:port] jump specs, or "direct".
                if raw_value.eq_ignore_ascii_case("none")
                    || raw_value.eq_ignore_ascii_case("direct")
                {
                    continue;
                }

                // Each comma-separated token is a jump host.
                for token in raw_value.split(',') {
                    let token = token.trim();
                    if token.is_empty() {
                        continue;
                    }

                    // Strip [user@] prefix and [:port] suffix to get the hostname.
                    let host_part = token
                        .rsplit_once(':')
                        .map_or(token, |(h, _port)| h)
                        .split('@')
                        .next_back()
                        .unwrap_or(token)
                        .trim_matches(|c| c == '[' || c == ']');

                    // Check if the jump target has a matching Host block.
                    let lower = host_part.to_lowercase();
                    let has_config = host_patterns.iter().any(|p| {
                        if p.starts_with('!') {
                            return false;
                        }
                        // Exact match or wildcard prefix pattern (e.g. *.example.com).
                        p == &lower
                            || (p.starts_with("*.") && lower.ends_with(&p[1..]))
                    });

                    if has_config {
                        diagnostics.push(Diagnostic {
                            id: "proxy_jump_host",
                            severity: Severity::Ok,
                            message: format!(
                                "ProxyJump target '{host_part}' has a config entry ({context})"
                            ),
                            hint: None,
                            module: "local",
                        });
                    } else {
                        diagnostics.push(Diagnostic {
                            id: "proxy_jump_host",
                            severity: Severity::Warning,
                            message: format!(
                                "ProxyJump target '{host_part}' has no matching Host block in config ({context})"
                            ),
                            hint: Some(format!(
                                "Add a Host {host_part} block with HostName, User, and IdentityFile, \
                                 or ensure the hostname is directly resolvable"
                            )),
                            module: "local",
                        });
                    }
                }
            }

            if diagnostics.is_empty() {
                Ok(vec![Diagnostic {
                    id: "proxy_jump_host",
                    severity: Severity::Ok,
                    message: "All ProxyJump targets are set to 'none'".into(),
                    hint: None,
                    module: "local",
                }])
            } else {
                Ok(diagnostics)
            }
        })
    }
}

// ---------------------------------------------------------------------------
// AgentIdentityCheck — verify agent holds keys expected by config
// ---------------------------------------------------------------------------

/// Verify that the SSH agent holds keys matching the `IdentityFile` directives
/// in the config. When a configured key is not loaded in the agent, SSH falls
/// back to trying all agent keys (or fails if `IdentitiesOnly yes` is set).
struct AgentIdentityCheck<'a> {
    paths: &'a SshPaths,
}

impl Check for AgentIdentityCheck<'_> {
    fn id(&self) -> &'static str {
        "agent_identity"
    }
    fn module(&self) -> &'static str {
        "local"
    }
    #[allow(clippy::too_many_lines)]
    fn run(&self) -> CheckFuture<'_> {
        let config_path = self.paths.config_path().to_path_buf();
        Box::pin(async move {
            // First, get the agent's public key fingerprints.
            if std::env::var("SSH_AUTH_SOCK").map_or(true, |v| v.is_empty()) {
                return Ok(vec![Diagnostic {
                    id: "agent_identity",
                    severity: Severity::Info,
                    message: "SSH agent is not running — cannot verify agent holds expected keys".into(),
                    hint: None,
                    module: "local",
                }]);
            }

            let agent_output = tokio::task::spawn_blocking(|| {
                duct::cmd("ssh-add", ["-l"])
                    .stderr_null()
                    .read()
                    .ok()
            })
            .await
            .ok()
            .flatten();

            let agent_fingerprints: Vec<String> = agent_output
                .as_deref()
                .map(|o| {
                    o.lines()
                        .filter_map(|line| {
                            // Lines look like: "256 SHA256:abc... comment (ED25519)"
                            line.split_whitespace()
                                .nth(1)
                                .map(std::borrow::ToOwned::to_owned)
                        })
                        .collect()
                })
                .unwrap_or_default();

            if agent_fingerprints.is_empty() {
                return Ok(vec![Diagnostic {
                    id: "agent_identity",
                    severity: Severity::Info,
                    message: "No keys loaded in agent — cannot verify agent identity".into(),
                    hint: Some("Load keys with `ssh-add ~/.ssh/id_ed25519`".into()),
                    module: "local",
                }]);
            }

            // Read config to find IdentityFile directives.
            let Ok(content) = tokio::fs::read_to_string(&config_path).await else {
                return Ok(vec![Diagnostic {
                    id: "agent_identity",
                    severity: Severity::Info,
                    message: format!(
                        "Cannot check agent identities: {} does not exist",
                        config_path.display()
                    ),
                    hint: None,
                    module: "local",
                }]);
            };

            let ast = ast::parse(&content);
            let mut identity_files: Vec<String> = Vec::new();

            for node in &ast.nodes {
                match node {
                    ConfigNode::Directive(d) if d.keyword.eq_ignore_ascii_case("IdentityFile") => {
                        identity_files.push(d.value.clone());
                    }
                    ConfigNode::HostBlock(b) => {
                        for child in &b.nodes {
                            if let ConfigNode::Directive(d) = child
                                && d.keyword.eq_ignore_ascii_case("IdentityFile")
                            {
                                identity_files.push(d.value.clone());
                            }
                        }
                    }
                    _ => {}
                }
            }

            if identity_files.is_empty() {
                return Ok(vec![Diagnostic {
                    id: "agent_identity",
                    severity: Severity::Ok,
                    message: "No IdentityFile directives in config — agent will offer all keys".into(),
                    hint: None,
                    module: "local",
                }]);
            }

            // For each IdentityFile, check if the corresponding public key
            // fingerprint is in the agent.
            let mut diagnostics = Vec::new();
            for raw_path in &identity_files {
                let expanded = crate::paths::expand_path(raw_path, self.paths.ssh_dir());

                // Get the fingerprint of the public key file.
                let pub_path = expanded.with_file_name(format!(
                    "{}.pub",
                    expanded.file_name().unwrap_or_default().to_string_lossy()
                ));

                let fp_output = tokio::task::spawn_blocking({
                    let pub_path = pub_path.clone();
                    move || {
                        duct::cmd("ssh-keygen", ["-lf", pub_path.to_str().unwrap_or("")])
                            .stderr_null()
                            .read()
                            .ok()
                    }
                })
                .await
                .ok()
                .flatten();

                let Some(fp_output) = fp_output else {
                    diagnostics.push(Diagnostic {
                        id: "agent_identity",
                        severity: Severity::Info,
                        message: format!(
                            "Cannot read public key for {raw_path} — \
                             skipping agent identity check for this key"
                        ),
                        hint: None,
                        module: "local",
                    });
                    continue;
                };

                let key_fp = fp_output
                    .split_whitespace()
                    .nth(1)
                    .unwrap_or("")
                    .to_owned();

                if key_fp.is_empty() {
                    diagnostics.push(Diagnostic {
                        id: "agent_identity",
                        severity: Severity::Info,
                        message: format!(
                            "Could not parse fingerprint for {raw_path} — \
                             skipping agent identity check"
                        ),
                        hint: None,
                        module: "local",
                    });
                    continue;
                }

                if agent_fingerprints.iter().any(|af| af == &key_fp) {
                    diagnostics.push(Diagnostic {
                        id: "agent_identity",
                        severity: Severity::Ok,
                        message: format!(
                            "Agent holds key for {raw_path} ({key_fp})"
                        ),
                        hint: None,
                        module: "local",
                    });
                } else {
                    diagnostics.push(Diagnostic {
                        id: "agent_identity",
                        severity: Severity::Warning,
                        message: format!(
                            "Agent does not hold key for {raw_path} ({key_fp}). \
                             SSH will not be able to offer this key automatically"
                        ),
                        hint: Some(format!(
                            "Load the key: `ssh-add {}`",
                            expanded.display()
                        )),
                        module: "local",
                    });
                }
            }

            Ok(diagnostics)
        })
    }
}

// ---------------------------------------------------------------------------
// RsaWeakKeyCheck — warn about RSA keys with fewer than 3072 bits
// ---------------------------------------------------------------------------

/// Check that all RSA keys on disk have at least 3072 bits.
///
/// RSA keys with fewer than 3072 bits are considered weak by modern standards.
/// NIST recommends a minimum of 2048 bits through 2030, but 3072 bits is the
/// widely accepted minimum for long-term security.  OpenSSH itself warns about
/// RSA-2048 keys since version 9.x.
struct RsaWeakKeyCheck<'a> {
    paths: &'a SshPaths,
}

impl Check for RsaWeakKeyCheck<'_> {
    fn id(&self) -> &'static str {
        "rsa_weak_key"
    }
    fn module(&self) -> &'static str {
        "local"
    }
    #[allow(clippy::too_many_lines)]
    fn run(&self) -> CheckFuture<'_> {
        let ssh_dir = self.paths.ssh_dir().to_path_buf();
        Box::pin(async move {
            let Ok(mut read_dir) = tokio::fs::read_dir(&ssh_dir).await else {
                return Ok(vec![Diagnostic {
                    id: "rsa_weak_key",
                    severity: Severity::Info,
                    message: format!(
                        "Cannot scan {}: directory does not exist",
                        ssh_dir.display()
                    ),
                    hint: None,
                    module: "local",
                }]);
            };

            let mut diagnostics = Vec::new();

            while let Some(entry) = read_dir.next_entry().await? {
                let name = entry.file_name();
                let name_lossy = name.to_string_lossy();

                // Skip public keys, certificates, config files, and dotfiles.
                if name_lossy.ends_with(".pub")
                    || name_lossy.ends_with("-cert.pub")
                    || name_lossy == "config"
                    || name_lossy == "known_hosts"
                    || name_lossy == "authorized_keys"
                    || name_lossy.starts_with('.')
                {
                    continue;
                }

                let path = entry.path();
                let Ok(meta) = tokio::fs::metadata(&path).await else {
                    continue;
                };
                if !meta.is_file() {
                    continue;
                }

                // Quick header check: only inspect files that look like private keys.
                {
                    use tokio::io::AsyncReadExt;
                    let Ok(mut file) = tokio::fs::File::open(&path).await else {
                        continue;
                    };
                    let mut buf = [0u8; PRIVATE_KEY_HEADER_READ_SIZE];
                    let Ok(n) = file.read(&mut buf).await else {
                        continue;
                    };
                    if n < MIN_PEM_HEADER_LENGTH || !String::from_utf8_lossy(&buf[..n]).contains("PRIVATE KEY") {
                        continue;
                    }
                }

                // Try to parse the key and check RSA bit size.
                let Ok(content) = tokio::fs::read_to_string(&path).await else {
                    continue;
                };
                let Ok(pk) = ssh_key::PrivateKey::from_openssh(&content) else {
                    continue;
                };

                if !matches!(pk.algorithm(), ssh_key::Algorithm::Rsa { .. }) {
                    continue;
                }

                // Extract RSA bit size from the public key.
                let public_key = pk.public_key();
                if let Some(rsa_public) = public_key.key_data().rsa() {
                    let bits = rsa_public.key_size();
                    if bits < RECOMMENDED_RSA_BITS {
                        diagnostics.push(Diagnostic {
                            id: "rsa_weak_key",
                            severity: Severity::Warning,
                            message: format!(
                                "{} is an RSA key with only {} bits (minimum recommended: {RECOMMENDED_RSA_BITS})",
                                path.display(),
                                bits,
                            ),
                            hint: Some(format!(
                                "Replace with a stronger key: \
                                 `ssh-keygen -t rsa -b 4096 -f {}` \
                                 or switch to Ed25519: \
                                 `ssh-keygen -t ed25519 -f {}`",
                                path.display(),
                                path.display(),
                            )),
                            module: "local",
                        });
                    } else {
                        diagnostics.push(Diagnostic {
                            id: "rsa_weak_key",
                            severity: Severity::Ok,
                            message: format!(
                                "{} is an RSA key with {} bits (adequate)",
                                path.display(),
                                bits,
                            ),
                            hint: None,
                            module: "local",
                        });
                    }
                }
            }

            if diagnostics.is_empty() {
                diagnostics.push(Diagnostic {
                    id: "rsa_weak_key",
                    severity: Severity::Ok,
                    message: "No RSA private keys found in ~/.ssh".into(),
                    hint: None,
                    module: "local",
                });
            }

            Ok(diagnostics)
        })
    }
}

// ---------------------------------------------------------------------------
// NfsHomeCheck — detect NFS home directory mounts
// ---------------------------------------------------------------------------

/// Check whether the home directory resides on an NFS mount.
///
/// NFS servers commonly apply *root-squashing*, which maps root access to an
/// unprivileged user (typically `nobody`).  When `sshd` runs as root and tries
/// to read `~/.ssh/authorized_keys` on an NFS-mounted home, root-squashing can
/// silently deny access, causing public-key authentication to fail.
struct NfsHomeCheck;

impl Check for NfsHomeCheck {
    fn id(&self) -> &'static str {
        "nfs_home"
    }
    fn module(&self) -> &'static str {
        "local"
    }
    fn run(&self) -> CheckFuture<'_> {
        Box::pin(async move {
            let Some(home) = dirs::home_dir() else {
                return Ok(vec![Diagnostic {
                    id: "nfs_home",
                    severity: Severity::Info,
                    message: "Cannot determine home directory".into(),
                    hint: None,
                    module: "local",
                }]);
            };

            // On Linux, inspect /proc/mounts for NFS entries.
            if cfg!(target_os = "linux") {
                let home_str = home.to_string_lossy().to_string();

                let nfs_detected = tokio::task::spawn_blocking(move || {
                    let Ok(content) = std::fs::read_to_string("/proc/mounts") else {
                        // Cannot read mounts file — cannot determine NFS status.
                        return None::<Vec<String>>;
                    };

                    let mut matches: Vec<String> = Vec::new();
                    for line in content.lines() {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        // Format: device mount_point fs_type options ...
                        if parts.len() >= 3 {
                            let fs_type = parts[2];
                            let mount_point = parts[1];
                            if (fs_type == "nfs" || fs_type == "nfs4")
                                && home_str.starts_with(mount_point)
                            {
                                matches.push(format!(
                                    "{} on {} ({})",
                                    parts[0], mount_point, fs_type
                                ));
                            }
                        }
                    }
                    Some(matches)
                })
                .await
                .ok()
                .flatten();

                match nfs_detected {
                    Some(entries) if !entries.is_empty() => {
                        return Ok(vec![Diagnostic {
                            id: "nfs_home",
                            severity: Severity::Warning,
                            message: format!(
                                "Home directory {} is on an NFS mount ({}). \
                                 NFS root-squashing may prevent sshd from reading ~/.ssh/authorized_keys",
                                home.display(),
                                entries.join(", "),
                            ),
                            hint: Some(
                                "Ensure the NFS export allows root access (no_root_squash) \
                                 or configure sshd AuthorizedKeysFile to a non-NFS path"
                                    .into(),
                            ),
                            module: "local",
                        }]);
                    }
                    Some(_) => {
                        // No NFS mounts matching home dir.
                        return Ok(vec![Diagnostic {
                            id: "nfs_home",
                            severity: Severity::Ok,
                            message: format!(
                                "Home directory {} is not on an NFS mount",
                                home.display()
                            ),
                            hint: None,
                            module: "local",
                        }]);
                    }
                    None => {
                        // Could not read /proc/mounts.
                        return Ok(vec![Diagnostic {
                            id: "nfs_home",
                            severity: Severity::Info,
                            message: "Cannot read /proc/mounts to check for NFS home directory"
                                .into(),
                            hint: None,
                            module: "local",
                        }]);
                    }
                }
            }

            // Non-Linux: NFS check is not applicable.
            Ok(vec![Diagnostic {
                id: "nfs_home",
                severity: Severity::Info,
                message: "NFS home directory check is not applicable on this platform".into(),
                hint: None,
                module: "local",
            }])
        })
    }
}

// ---------------------------------------------------------------------------
// SELinuxContextCheck — check SELinux security contexts on ~/.ssh
// ---------------------------------------------------------------------------

/// Check SELinux security contexts for files under `~/.ssh`.
///
/// Runs `restorecon -Rvn ~/.ssh` (dry-run, non-destructive) to detect files
/// that would be relabeled. Incorrect SELinux contexts can prevent sshd from
/// reading `~/.ssh/authorized_keys`, causing public-key authentication failures
/// on SELinux-enforced systems.
struct SELinuxContextCheck<'a> {
    paths: &'a SshPaths,
}

impl Check for SELinuxContextCheck<'_> {
    fn id(&self) -> &'static str {
        "selinux_context"
    }
    fn module(&self) -> &'static str {
        "local"
    }
    fn run(&self) -> CheckFuture<'_> {
        let ssh_dir = self.paths.ssh_dir().to_path_buf();
        Box::pin(async move {
            // Only applicable on Linux; skip entirely on other platforms.
            if !cfg!(target_os = "linux") {
                return Ok(vec![]);
            }

            // Run restorecon -Rvn ~/.ssh (dry-run, verbose, no-change).
            // Output lines have the form:
            //   would relabel /home/user/.ssh/authorized_keys from ...
            let output = tokio::task::spawn_blocking({
                let ssh_dir_clone = ssh_dir.clone();
                move || {
                    duct::cmd("restorecon", ["-Rvn", ssh_dir_clone.to_str().unwrap_or("")])
                        .stderr_to_stdout()
                        .read()
                        .ok()
                }
            })
            .await
            .ok()
            .flatten();

            let Some(output) = output else {
                return Ok(vec![Diagnostic {
                    id: "selinux_context",
                    severity: Severity::Info,
                    message: "SELinux check skipped: restorecon is not available".into(),
                    hint: None,
                    module: "local",
                }]);
            };

            let relabel_lines: Vec<&str> = output
                .lines()
                .filter(|l| !l.is_empty())
                .collect();

            if relabel_lines.is_empty() {
                Ok(vec![Diagnostic {
                    id: "selinux_context",
                    severity: Severity::Ok,
                    message: format!(
                        "SELinux contexts for {} are correct",
                        ssh_dir.display()
                    ),
                    hint: None,
                    module: "local",
                }])
            } else {
                let files: Vec<&str> = relabel_lines
                    .iter()
                    .filter_map(|line| {
                        // Extract the file path from restorecon output.
                        // Typical: "would relabel /path/to/file from X to Y"
                        line.split_whitespace().nth(2)
                    })
                    .collect();

                Ok(vec![Diagnostic {
                    id: "selinux_context",
                    severity: Severity::Warning,
                    message: format!(
                        "SELinux contexts need fixing for {} file(s) under {}: {}",
                        files.len().max(relabel_lines.len()),
                        ssh_dir.display(),
                        files.iter().take(5).copied().collect::<Vec<_>>().join(", "),
                    ),
                    hint: Some(format!(
                        "Run `restorecon -Rv {}` to fix SELinux contexts",
                        ssh_dir.display()
                    )),
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
pub async fn run_all<'a>(
    paths: &'a SshPaths,
    runner: &'a dyn crate::CliRunner,
) -> Result<Vec<Diagnostic>> {
    let mut checks: Vec<Box<dyn Check + 'a>> = vec![
        Box::new(SshDirExists { paths }),
    ];

    checks.push(Box::new(SshDirPermissions { paths }));

    checks.push(Box::new(ConfigExists { paths }));
    checks.push(Box::new(KnownHostsExists { paths }));

    checks.push(Box::new(PrivateKeyPermissions { paths }));

    checks.push(Box::new(OwnerCheck { paths }));

    checks.push(Box::new(AgentAvailable));
    checks.push(Box::new(KeygenAvailable { runner }));
    checks.push(Box::new(DefaultKeyExists { paths }));

    checks.push(Box::new(ConfigPermissionsCheck { paths }));

    checks.push(Box::new(AuthorizedKeysPermissionsCheck { paths }));

    checks.push(Box::new(PublicKeyPairsCheck { paths }));
    checks.push(Box::new(IdentityFileExistsCheck { paths }));
    checks.push(Box::new(CertificateFileExistsCheck { paths }));
    checks.push(Box::new(DuplicateHostCheck { paths }));
    checks.push(Box::new(HostStarPlacementCheck { paths }));
    checks.push(Box::new(SshV1KeyCheck { paths }));
    checks.push(Box::new(UseKeychainPlatformCheck { paths }));
    checks.push(Box::new(IdentityFilePubCheck { paths }));
    checks.push(Box::new(IdentitiesOnlyCheck { paths }));
    checks.push(Box::new(MaxAuthTriesExhaustionCheck));
    checks.push(Box::new(PreferredAuthenticationsCheck { paths }));
    checks.push(Box::new(ProxyJumpHostCheck { paths }));
    checks.push(Box::new(AgentIdentityCheck { paths }));
    checks.push(Box::new(RsaWeakKeyCheck { paths }));
    checks.push(Box::new(GssapiConfigCheck { paths }));
    checks.push(Box::new(VerifyHostKeyDnsCheck { paths }));
    checks.push(Box::new(NfsHomeCheck));
    checks.push(Box::new(SELinuxContextCheck { paths }));
    #[cfg(unix)]
    checks.push(Box::new(HomeDirPermissionsCheck));
    checks.push(Box::new(PlatformCheck));

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

#[cfg(test)]
#[path = "local.test.rs"]
mod tests;
