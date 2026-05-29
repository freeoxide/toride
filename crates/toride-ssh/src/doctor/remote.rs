//! Remote SSH diagnostic checks.

use crate::paths::SshPaths;
use crate::types::{Diagnostic, Severity};
use crate::{Error, Result};

/// Check whether the remote host is reachable via SSH.
struct HostReachable {
    host: String,
}

/// Check whether the host key is present in known_hosts.
struct HostKeyKnown {
    paths: SshPaths,
    host: String,
}

/// Check whether agent forwarding works to the remote host.
struct AgentForwarding {
    host: String,
}

// ---------------------------------------------------------------------------
// Check implementations
// ---------------------------------------------------------------------------

impl HostReachable {
    async fn run_check(&self) -> Result<Vec<Diagnostic>> {
        // Verify `ssh` is available before attempting to connect.
        if !crate::runner::tool_exists("ssh") {
            return Ok(vec![Diagnostic {
                id: "host_reachable",
                severity: Severity::Error,
                message: "`ssh` is not found in PATH".into(),
                hint: Some(
                    "Install OpenSSH: `brew install openssh` (macOS) or `sudo apt install openssh-client` (Linux)".into(),
                ),
                module: "remote",
            }]);
        }

        let output = tokio::process::Command::new("ssh")
            .args([
                "-o",
                "BatchMode=yes",
                "-o",
                "ConnectTimeout=5",
                "-o",
                "StrictHostKeyChecking=accept-new",
                self.host.as_str(),
                "true",
            ])
            .output()
            .await
            .map_err(|e| Error::CommandFailed(format!("failed to execute ssh: {e}")))?;

        if output.status.success() {
            Ok(vec![Diagnostic {
                id: "host_reachable",
                severity: Severity::Ok,
                message: format!("Successfully connected to {}", self.host),
                hint: None,
                module: "remote",
            }])
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Ok(vec![Diagnostic {
                id: "host_reachable",
                severity: Severity::Error,
                message: format!("Cannot connect to {}: {}", self.host, stderr.trim()),
                hint: Some(
                    "Verify the hostname, network connectivity, and that SSH is running on the remote".into(),
                ),
                module: "remote",
            }])
        }
    }
}

impl HostKeyKnown {
    async fn run_check(&self) -> Result<Vec<Diagnostic>> {
        let kh_path = self.paths.known_hosts_path();

        match tokio::fs::read_to_string(&kh_path).await {
            Ok(content) => {
                // Check if the host appears in a known_hosts line. This is a
                // best-effort check: hashed known_hosts entries (HashKnownHosts yes)
                // cannot be matched by name and will be reported as unknown.
                let bracketed = format!("[{}]", self.host);
                let known = content.lines().any(|line| {
                    if line.is_empty() || line.starts_with('#') || line.starts_with('@') {
                        return false;
                    }
                    // The host field is the first token (comma-separated for
                    // multiple hosts, with optional patterns like *.example.com).
                    let Some(host_field) = line.split_whitespace().next() else {
                        return false;
                    };
                    // Skip hashed entries — we cannot verify them by name.
                    if host_field.starts_with('|') {
                        return false;
                    }
                    host_field
                        .split(',')
                        .any(|h| h == self.host || h == bracketed)
                });

                if known {
                    Ok(vec![Diagnostic {
                        id: "host_key_known",
                        severity: Severity::Ok,
                        message: format!("{} is present in known_hosts", self.host),
                        hint: None,
                        module: "remote",
                    }])
                } else {
                    Ok(vec![Diagnostic {
                        id: "host_key_known",
                        severity: Severity::Warning,
                        message: format!(
                            "{} is not in known_hosts — you will be prompted on first connection",
                            self.host
                        ),
                        hint: Some(format!(
                            "Run `ssh-keyscan -H {} >> ~/.ssh/known_hosts` to add it",
                            self.host
                        )),
                        module: "remote",
                    }])
                }
            }
            Err(_) => Ok(vec![Diagnostic {
                id: "host_key_known",
                severity: Severity::Warning,
                message: "known_hosts file does not exist".into(),
                hint: Some("Run `touch ~/.ssh/known_hosts`".into()),
                module: "remote",
            }]),
        }
    }
}

impl AgentForwarding {
    async fn run_check(&self) -> Result<Vec<Diagnostic>> {
        // The `-A` flag enables agent forwarding. This is safe for diagnostic
        // purposes (a brief `ssh-add -l` invocation) but note that agent
        // forwarding should not be used on untrusted remote hosts in general
        // because a compromised remote could use the forwarded agent socket.

        if std::env::var("SSH_AUTH_SOCK").map_or(true, |v| v.is_empty()) {
            return Ok(vec![Diagnostic {
                id: "agent_forwarding",
                severity: Severity::Warning,
                message: "SSH agent is not running locally — cannot test agent forwarding".into(),
                hint: Some("Start the SSH agent: `eval $(ssh-agent -s)`".into()),
                module: "remote",
            }]);
        }

        let output = tokio::process::Command::new("ssh")
            .args([
                "-o",
                "BatchMode=yes",
                "-o",
                "ConnectTimeout=5",
                "-o",
                "StrictHostKeyChecking=accept-new",
                "-A",
                self.host.as_str(),
                "ssh-add -l",
            ])
            .output()
            .await
            .map_err(|e| Error::CommandFailed(format!("failed to execute ssh: {e}")))?;

        if output.status.success() {
            Ok(vec![Diagnostic {
                id: "agent_forwarding",
                severity: Severity::Ok,
                message: format!("Agent forwarding works to {}", self.host),
                hint: None,
                module: "remote",
            }])
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Ok(vec![Diagnostic {
                id: "agent_forwarding",
                severity: Severity::Warning,
                message: format!(
                    "Agent forwarding may not work to {}: {}",
                    self.host,
                    stderr.trim()
                ),
                hint: Some(
                    "Ensure `AllowAgentForwarding yes` is set in the remote sshd_config".into(),
                ),
                module: "remote",
            }])
        }
    }
}

// ---------------------------------------------------------------------------
// run_all — execute every remote check
// ---------------------------------------------------------------------------

/// Run all remote diagnostic checks for a host.
///
/// If the host is unreachable, subsequent checks (known_hosts, agent forwarding)
/// are still run — the known_hosts check is local, and agent forwarding provides
/// a useful diagnostic regardless. However, if the host-reachability check itself
/// errors (not just returns a diagnostic), we short-circuit to avoid cascading
/// failures.
pub async fn run_all(paths: &SshPaths, host: &str) -> Result<Vec<Diagnostic>> {
    let mut all_diagnostics = Vec::new();

    // Host reachability
    let check = HostReachable {
        host: host.into(),
    };
    let host_reachable = match check.run_check().await {
        Ok(d) => {
            let was_ok = d.iter().any(|d| d.severity == Severity::Ok);
            all_diagnostics.extend(d);
            was_ok
        }
        Err(e) => {
            all_diagnostics.push(err_diagnostic("host_reachable", &e));
            false
        }
    };

    // Host key in known_hosts (local check, always runs).
    let check = HostKeyKnown {
        paths: paths.clone(),
        host: host.into(),
    };
    match check.run_check().await {
        Ok(d) => all_diagnostics.extend(d),
        Err(e) => all_diagnostics.push(err_diagnostic("host_key_known", &e)),
    }

    // Agent forwarding — skip if host is not reachable to avoid a slow timeout.
    if host_reachable {
        let check = AgentForwarding {
            host: host.into(),
        };
        match check.run_check().await {
            Ok(d) => all_diagnostics.extend(d),
            Err(e) => all_diagnostics.push(err_diagnostic("agent_forwarding", &e)),
        }
    } else {
        all_diagnostics.push(Diagnostic {
            id: "agent_forwarding",
            severity: Severity::Info,
            message: "Skipped agent forwarding check: host is not reachable".into(),
            hint: None,
            module: "remote",
        });
    }

    Ok(all_diagnostics)
}

fn err_diagnostic(id: &'static str, e: &Error) -> Diagnostic {
    Diagnostic {
        id,
        severity: Severity::Error,
        message: format!("Remote check '{id}' failed: {e}"),
        hint: None,
        module: "remote",
    }
}
