//! Remote SSH diagnostic checks.

use crate::config::resolve::resolve;
use crate::paths::SshPaths;
use crate::types::{Diagnostic, Severity};
use crate::{Error, Result};

/// Parse a host string for an optional port specification.
///
/// Supports three forms:
///   - `host` (bare hostname, no port)
///   - `host:port` (hostname with port)
///   - `[host]:port` (bracketed hostname with port, useful for IPv6 or
///     disambiguating `::` in addresses)
///
/// Returns `(bare_host, Some(port))` when a non-standard port is present,
/// or `(host, None)` when the port is absent or equals 22.
fn parse_host_port(host: &str) -> (&str, Option<u16>) {
    // Bracketed form: `[host]:port`
    if let Some(rest) = host.strip_prefix('[')
        && let Some(bracket_end) = rest.find(']')
    {
        let bare = &rest[..bracket_end];
        let after = &rest[bracket_end + 1..];
        if let Some(port_str) = after.strip_prefix(':')
            && let Ok(port) = port_str.parse::<u16>()
            && port != 22
        {
            return (bare, Some(port));
        }
        return (bare, None);
    }

    // Unbracketed form: `host:port` — only parse if there is exactly one
    // colon (so IPv6 addresses like `::1` are left alone).
    if let Some(colon_pos) = host.rfind(':')
        && !host[..colon_pos].contains(':')
        && let Ok(port) = host[colon_pos + 1..].parse::<u16>()
    {
        let bare = &host[..colon_pos];
        if port != 22 {
            return (bare, Some(port));
        }
        // Port is 22 (default) — still strip the suffix so the
        // returned host is clean.
        if !bare.is_empty() {
            return (bare, None);
        }
    }

    (host, None)
}

/// Build the common SSH connection options, an optional `-p PORT` flag, and
/// an optional `-J jump_host` flag for ProxyJump.
///
/// The host is **not** included — the caller should append it (and any
/// extra flags or the remote command) after any additional options.
///
/// Returns a `Vec<String>` suitable for passing to `Command::args(...)`.
fn ssh_connect_args(port: Option<u16>, proxy_jump: Option<&str>) -> Vec<String> {
    let mut args: Vec<String> = Vec::with_capacity(10);
    args.extend([
        "-o".into(),
        "BatchMode=yes".into(),
        "-o".into(),
        "ConnectTimeout=5".into(),
        "-o".into(),
        "StrictHostKeyChecking=accept-new".into(),
    ]);
    if let Some(p) = port {
        args.push("-p".into());
        args.push(p.to_string());
    }
    if let Some(jump) = proxy_jump {
        args.push("-J".into());
        args.push(jump.to_owned());
    }
    args
}

/// Return the host string in the format used by `known_hosts` entries.
///
/// For standard ports the host is stored bare (`hostname`), while for
/// non-standard ports it is bracketed with the port suffix (`[hostname]:port`).
fn known_hosts_host(host: &str, port: Option<u16>) -> String {
    port.map_or_else(|| host.to_string(), |p| format!("[{host}]:{p}"))
}

/// Check whether the host can be resolved via DNS.
struct HostReachabilityCheck<'a> {
    host: &'a str,
    port: Option<u16>,
}

/// Check whether the remote host is reachable via SSH.
struct HostReachable<'a> {
    host: &'a str,
    port: Option<u16>,
    proxy_jump: Option<&'a str>,
    runner: &'a dyn crate::CliRunner,
}

/// Check whether the host key is present in known_hosts.
struct HostKeyKnown<'a> {
    paths: &'a SshPaths,
    host: &'a str,
    port: Option<u16>,
}

/// Verify host keys against known_hosts to detect mismatches.
///
/// Uses `ssh-keygen -F` to look up stored keys and `ssh-keyscan` to query the
/// live host, then compares the key data. A mismatch indicates the remote host
/// key has changed since the last connection — this may signal a MITM attack or
/// a legitimate host reinstallation.
struct HostKeyVerificationCheck<'a> {
    paths: &'a SshPaths,
    host: &'a str,
    port: Option<u16>,
}

/// Check whether agent forwarding works to the remote host.
struct AgentForwarding<'a> {
    host: &'a str,
    port: Option<u16>,
    proxy_jump: Option<&'a str>,
}

/// Check that remote `~/.ssh` has restrictive permissions (should be 700).
struct RemotePermissionsCheck<'a> {
    host: &'a str,
    port: Option<u16>,
    proxy_jump: Option<&'a str>,
}

/// Check that remote `~/.ssh/authorized_keys` exists.
struct RemoteAuthorizedKeysCheck<'a> {
    host: &'a str,
    port: Option<u16>,
    proxy_jump: Option<&'a str>,
}

/// Verify that public-key authentication works to the remote host.
struct RemotePubkeyAuthCheck<'a> {
    host: &'a str,
    port: Option<u16>,
    proxy_jump: Option<&'a str>,
}

/// Check remote sshd configuration for common misconfigurations.
struct RemoteSshdConfigCheck<'a> {
    host: &'a str,
    port: Option<u16>,
    proxy_jump: Option<&'a str>,
}

/// Verify the remote home directory is accessible and exists.
struct RemoteHomeCheck<'a> {
    host: &'a str,
    port: Option<u16>,
    proxy_jump: Option<&'a str>,
}

/// Detect and report ProxyJump configuration for the target host.
///
/// Resolves the SSH config for the host and reports whether ProxyJump is
/// set, including the jump host(s) specified.
struct ProxyJumpDetectionCheck<'a> {
    paths: &'a SshPaths,
    host: &'a str,
}

/// Check whether the jump host specified by ProxyJump is reachable.
///
/// Attempts an SSH connection to the jump host to verify it is accessible
/// before the target host can be reached through it.
struct JumpHostReachableCheck<'a> {
    jump_host: &'a str,
    runner: &'a dyn crate::CliRunner,
}

// ---------------------------------------------------------------------------
// Check implementations
// ---------------------------------------------------------------------------

impl HostReachabilityCheck<'_> {
    async fn run_check(&self) -> Result<Vec<Diagnostic>> {
        // tokio::net::lookup_host requires a socket address (host:port).
        let port = self.port.unwrap_or(22);
        let lookup_target = format!("{}:{port}", self.host);

        match tokio::net::lookup_host(&lookup_target).await {
            Ok(addrs) => {
                let addr_list: Vec<String> = addrs.map(|a| a.ip().to_string()).collect();
                if addr_list.is_empty() {
                    Ok(vec![Diagnostic {
                        id: "host_resolvable",
                        severity: Severity::Warning,
                        message: format!(
                            "DNS lookup for {} returned no addresses",
                            self.host
                        ),
                        hint: Some(
                            "Verify the hostname is correct and DNS is properly configured".into(),
                        ),
                        module: "remote",
                    }])
                } else {
                    let joined = addr_list.join(", ");
                    Ok(vec![Diagnostic {
                        id: "host_resolvable",
                        severity: Severity::Ok,
                        message: format!(
                            "Host {} resolves to {}",
                            self.host, joined
                        ),
                        hint: None,
                        module: "remote",
                    }])
                }
            }
            Err(e) => Ok(vec![Diagnostic {
                id: "host_resolvable",
                severity: Severity::Error,
                message: format!(
                    "Cannot resolve host {}: {}",
                    self.host, e
                ),
                hint: Some(
                    "Check the hostname spelling and ensure DNS is working (`nslookup <host>`)".into(),
                ),
                module: "remote",
            }]),
        }
    }
}

impl HostReachable<'_> {
    async fn run_check(&self) -> Result<Vec<Diagnostic>> {
        // Verify `ssh` is available before attempting to connect.
        if !self.runner.tool_exists("ssh") {
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
            .args(ssh_connect_args(self.port, self.proxy_jump))
            .args([self.host, "true"])
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

impl HostKeyKnown<'_> {
    async fn run_check(&self) -> Result<Vec<Diagnostic>> {
        let kh_path = self.paths.known_hosts_path();

        match tokio::fs::read_to_string(&kh_path).await {
            Ok(content) => {
                // Check if the host appears in a known_hosts line. This is a
                // best-effort check: hashed known_hosts entries (HashKnownHosts yes)
                // cannot be matched by name and will be reported as unknown.
                //
                // For non-standard ports, known_hosts stores `[host]:port`.
                let bracketed = format!("[{}]", self.host);
                let port_entry = known_hosts_host(self.host, self.port);
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
                        .any(|h| h == port_entry || h == self.host || h == bracketed)
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
                    let keyscan_port_flag = self.port.map_or_else(String::new, |p| format!(" -p {p}"));
                    Ok(vec![Diagnostic {
                        id: "host_key_known",
                        severity: Severity::Warning,
                        message: format!(
                            "{} is not in known_hosts — you will be prompted on first connection",
                            self.host
                        ),
                        hint: Some(format!(
                            "Run `ssh-keyscan{keyscan_port_flag} -H {} >> ~/.ssh/known_hosts` to add it",
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

// ---------------------------------------------------------------------------
// HostKeyVerificationCheck
// ---------------------------------------------------------------------------

impl HostKeyVerificationCheck<'_> {
    #[allow(clippy::too_many_lines)]
    async fn run_check(&self) -> Result<Vec<Diagnostic>> {
        // Step 1: Look up stored keys for this host using ssh-keygen -F.
        let stored_keys = match self.lookup_stored_keys().await {
            Ok(keys) => keys,
            Err(e) => {
                return Ok(vec![Diagnostic {
                    id: "host_key_verification",
                    severity: Severity::Warning,
                    message: format!(
                        "Could not look up stored host keys for {}: {}",
                        self.host, e
                    ),
                    hint: Some(
                        "Ensure known_hosts exists and is readable".into(),
                    ),
                    module: "remote",
                }]);
            }
        };

        if stored_keys.is_empty() {
            let keyscan_port_flag = self.port.map_or_else(String::new, |p| format!(" -p {p}"));
            return Ok(vec![Diagnostic {
                id: "host_key_verification",
                severity: Severity::Info,
                message: format!(
                    "No stored host keys found for {} in known_hosts — cannot verify key integrity",
                    self.host
                ),
                hint: Some(format!(
                    "Run `ssh-keyscan{keyscan_port_flag} -H {} >> ~/.ssh/known_hosts` to record the host key",
                    self.host
                )),
                module: "remote",
            }]);
        }

        // Step 2: Scan the live host for its current keys.
        let live_keys = match self.scan_live_keys().await {
            Ok(keys) => keys,
            Err(e) => {
                return Ok(vec![Diagnostic {
                    id: "host_key_verification",
                    severity: Severity::Warning,
                    message: format!(
                        "Could not scan host keys from {}: {}",
                        self.host, e
                    ),
                    hint: Some(
                        "Ensure the host is reachable and sshd is running".into(),
                    ),
                    module: "remote",
                }]);
            }
        };

        if live_keys.is_empty() {
            return Ok(vec![Diagnostic {
                id: "host_key_verification",
                severity: Severity::Warning,
                message: format!(
                    "ssh-keyscan returned no keys from {} — host may be down or blocking key exchange",
                    self.host
                ),
                hint: Some(
                    "Verify the host is reachable and the SSH port is open".into(),
                ),
                module: "remote",
            }]);
        }

        // Step 3: Compare stored vs live keys.
        //
        // For each stored key type, check if the same key data appears in the
        // live keys. If a stored key type is present but with different data,
        // that is a mismatch (potential MITM or host reinstall). If no stored
        // key type appears in the live keys at all, that is also a mismatch.
        let stored_types: Vec<&str> = stored_keys
            .iter()
            .filter_map(|line| extract_key_type(line))
            .collect();

        let mut diagnostics = Vec::new();

        for stored_line in &stored_keys {
            let Some(stored_type) = extract_key_type(stored_line) else {
                continue;
            };
            let stored_data = extract_key_data(stored_line);

            // Check if any live key of the same type matches.
            let type_in_live = live_keys
                .iter()
                .filter(|lk| extract_key_type(lk).is_some_and(|t| t == stored_type))
                .collect::<Vec<_>>();

            if type_in_live.is_empty() {
                // The key type from known_hosts is no longer offered by the host.
                diagnostics.push(Diagnostic {
                    id: "host_key_verification",
                    severity: Severity::Warning,
                    message: format!(
                        "Host {} no longer offers {} key (was in known_hosts)",
                        self.host, stored_type
                    ),
                    hint: Some(
                        "The host may have been reconfigured. \
                         Update known_hosts: `ssh-keygen -R <host> && ssh-keyscan -H <host> >> ~/.ssh/known_hosts`"
                            .into(),
                    ),
                    module: "remote",
                });
                continue;
            }

            // Check if the stored key data matches any live key of the same type.
            let data_matches = type_in_live.iter().any(|lk| {
                extract_key_data(lk) == stored_data
            });

            if data_matches {
                diagnostics.push(Diagnostic {
                    id: "host_key_verification",
                    severity: Severity::Ok,
                    message: format!(
                        "Host {} {} key matches known_hosts",
                        self.host, stored_type
                    ),
                    hint: None,
                    module: "remote",
                });
            } else {
                diagnostics.push(Diagnostic {
                    id: "host_key_verification",
                    severity: Severity::Error,
                    message: format!(
                        "Host key MISMATCH for {} ({}) — known_hosts key does not match the live host",
                        self.host, stored_type
                    ),
                    hint: Some(
                        "POSSIBLE MITM ATTACK or host reinstallation. \
                         Verify the host identity before updating known_hosts: \
                         `ssh-keygen -R <host> && ssh-keyscan -H <host> >> ~/.ssh/known_hosts`"
                            .into(),
                    ),
                    module: "remote",
                });
            }
        }

        // Report live key types that are not in known_hosts at all.
        for live_line in &live_keys {
            let Some(live_type) = extract_key_type(live_line) else {
                continue;
            };
            if !stored_types.contains(&live_type) {
                diagnostics.push(Diagnostic {
                    id: "host_key_verification",
                    severity: Severity::Info,
                    message: format!(
                        "Host {} offers {} key not present in known_hosts",
                        self.host, live_type
                    ),
                    hint: Some(format!(
                        "To trust this key: `ssh-keyscan -H {} >> ~/.ssh/known_hosts`",
                        self.host
                    )),
                    module: "remote",
                });
            }
        }

        // Summary diagnostic when no per-key diagnostics were emitted
        // (should not happen if stored/live are non-empty, but be safe).
        if diagnostics.is_empty() {
            diagnostics.push(Diagnostic {
                id: "host_key_verification",
                severity: Severity::Ok,
                message: format!("Host key verification passed for {}", self.host),
                hint: None,
                module: "remote",
            });
        }

        Ok(diagnostics)
    }

    /// Use `ssh-keygen -F <host>` to retrieve stored key lines for this host.
    async fn lookup_stored_keys(&self) -> Result<Vec<String>> {
        let kh_path = self.paths.known_hosts_path();

        // Also check the global known_hosts.
        let global_kh = self.paths.global_known_hosts_path();

        // For non-standard ports, known_hosts stores the host as `[host]:port`.
        let lookup_host = known_hosts_host(self.host, self.port);

        let mut all_keys = Vec::new();

        for path in [kh_path, global_kh] {
            let Ok(output) = tokio::process::Command::new("ssh-keygen")
                .args(["-F", &lookup_host, "-f", path.to_str().unwrap_or_default()])
                .output()
                .await
            else {
                continue;
            };

            if !output.status.success() {
                continue;
            }

            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                // ssh-keygen -F outputs matching lines prefixed with "# Host <host> found:"
                // or blank lines as separators; skip those.
                if line.starts_with('#') || line.is_empty() {
                    continue;
                }
                all_keys.push(line.to_owned());
            }
        }

        Ok(all_keys)
    }

    /// Use `ssh-keyscan` to query the live host for its current keys.
    async fn scan_live_keys(&self) -> Result<Vec<String>> {
        let mut cmd = tokio::process::Command::new("ssh-keyscan");
        cmd.args(["-t", "rsa,ecdsa,ed25519"]);
        if let Some(p) = self.port {
            cmd.args(["-p", &p.to_string()]);
        }
        cmd.arg(self.host);
        let output = cmd
            .output()
            .await
            .map_err(|e| Error::CommandFailed(format!("failed to execute ssh-keyscan: {e}")))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Error::CommandFailed(format!(
                "ssh-keyscan failed for {}: {}",
                self.host,
                stderr.trim()
            )));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        Ok(stdout
            .lines()
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(str::to_owned)
            .collect())
    }
}

/// Extract the key type (e.g., "ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256")
/// from a known_hosts key line.
///
/// A known_hosts line has the format: `[host]:port keytype base64data [comment]`
/// or: `host keytype base64data [comment]`.
fn extract_key_type(line: &str) -> Option<&str> {
    // The key type is the second whitespace-delimited field (after the host
    // field, which may contain commas for multiple hosts).
    let mut parts = line.split_whitespace();
    let _host_field = parts.next()?;
    parts.next()
}

/// Extract the key data portion (key type + base64 blob) from a known_hosts
/// line, stripping any host field and trailing comments.
///
/// Returns the "keytype base64data" portion used for equality comparison.
fn extract_key_data(line: &str) -> String {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() >= 3 {
        // host_field key_type base64data [comment...]
        // We want "key_type base64data"
        format!("{} {}", parts[1], parts[2])
    } else {
        line.to_owned()
    }
}

impl AgentForwarding<'_> {
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
            .args(ssh_connect_args(self.port, self.proxy_jump))
            .arg("-A")
            .args([self.host, "ssh-add -l"])
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
// RemotePermissionsCheck
// ---------------------------------------------------------------------------

impl RemotePermissionsCheck<'_> {
    async fn run_check(&self) -> Result<Vec<Diagnostic>> {
        let output = tokio::process::Command::new("ssh")
            .args(ssh_connect_args(self.port, self.proxy_jump))
            .args([
                self.host,
                // Use `stat -c %a` for GNU/Linux and fall back to `stat -f %Lp` for BSD/macOS.
                // The portable idiom `$(stat -c %a . 2>/dev/null || stat -f %Lp .)` covers both.
                "stat -c '%a' ~/.ssh 2>/dev/null || stat -f '%Lp' ~/.ssh 2>/dev/null",
            ])
            .output()
            .await
            .map_err(|e| Error::CommandFailed(format!("failed to execute ssh: {e}")))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Ok(vec![Diagnostic {
                id: "remote_permissions",
                severity: Severity::Warning,
                message: format!(
                    "Could not stat remote ~/.ssh on {}: {}",
                    self.host,
                    stderr.trim()
                ),
                hint: Some("Ensure ~/.ssh exists on the remote host".into()),
                module: "remote",
            }]);
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mode = stdout.trim().trim_matches('\'');

        if mode == "700" {
            Ok(vec![Diagnostic {
                id: "remote_permissions",
                severity: Severity::Ok,
                message: format!("Remote ~/.ssh permissions are {mode} (correct)"),
                hint: None,
                module: "remote",
            }])
        } else {
            Ok(vec![Diagnostic {
                id: "remote_permissions",
                severity: Severity::Warning,
                message: format!(
                    "Remote ~/.ssh permissions are {mode} on {} (should be 700)",
                    self.host
                ),
                hint: Some("Run on the remote: `chmod 700 ~/.ssh`".into()),
                module: "remote",
            }])
        }
    }
}

// ---------------------------------------------------------------------------
// RemoteAuthorizedKeysCheck
// ---------------------------------------------------------------------------

impl RemoteAuthorizedKeysCheck<'_> {
    async fn run_check(&self) -> Result<Vec<Diagnostic>> {
        let output = tokio::process::Command::new("ssh")
            .args(ssh_connect_args(self.port, self.proxy_jump))
            .args([self.host, "test -f ~/.ssh/authorized_keys"])
            .output()
            .await
            .map_err(|e| Error::CommandFailed(format!("failed to execute ssh: {e}")))?;

        if output.status.success() {
            Ok(vec![Diagnostic {
                id: "remote_authorized_keys",
                severity: Severity::Ok,
                message: format!("~/.ssh/authorized_keys exists on {}", self.host),
                hint: None,
                module: "remote",
            }])
        } else {
            Ok(vec![Diagnostic {
                id: "remote_authorized_keys",
                severity: Severity::Warning,
                message: format!(
                    "~/.ssh/authorized_keys does not exist on {}",
                    self.host
                ),
                hint: Some(
                    "Copy your public key: `ssh-copy-id <user>@<host>` or manually create the file".into(),
                ),
                module: "remote",
            }])
        }
    }
}

// ---------------------------------------------------------------------------
// RemotePubkeyAuthCheck
// ---------------------------------------------------------------------------

impl RemotePubkeyAuthCheck<'_> {
    async fn run_check(&self) -> Result<Vec<Diagnostic>> {
        let output = tokio::process::Command::new("ssh")
            .args(ssh_connect_args(self.port, self.proxy_jump))
            .args(["-o", "PreferredAuthentications=publickey"])
            .args([self.host, "true"])
            .output()
            .await
            .map_err(|e| Error::CommandFailed(format!("failed to execute ssh: {e}")))?;

        if output.status.success() {
            Ok(vec![Diagnostic {
                id: "remote_pubkey_auth",
                severity: Severity::Ok,
                message: format!("Public-key authentication works to {}", self.host),
                hint: None,
                module: "remote",
            }])
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Ok(vec![Diagnostic {
                id: "remote_pubkey_auth",
                severity: Severity::Error,
                message: format!(
                    "Public-key authentication failed to {}: {}",
                    self.host,
                    stderr.trim()
                ),
                hint: Some(
                    "Ensure your public key is in the remote ~/.ssh/authorized_keys and the key is loaded in the agent".into(),
                ),
                module: "remote",
            }])
        }
    }
}

// ---------------------------------------------------------------------------
// RemoteSshdConfigCheck
// ---------------------------------------------------------------------------

impl RemoteSshdConfigCheck<'_> {
    async fn run_check(&self) -> Result<Vec<Diagnostic>> {
        let output = tokio::process::Command::new("ssh")
            .args(ssh_connect_args(self.port, self.proxy_jump))
            .args([self.host, "sshd -T 2>/dev/null"])
            .output()
            .await
            .map_err(|e| Error::CommandFailed(format!("failed to execute ssh: {e}")))?;

        if !output.status.success() {
            return Ok(vec![Diagnostic {
                id: "remote_sshd_config",
                severity: Severity::Info,
                message: format!(
                    "Could not read sshd config on {} (may require elevated privileges)",
                    self.host
                ),
                hint: Some(
                    "Ensure `PubkeyAuthentication yes` and `AllowAgentForwarding yes` are set in /etc/ssh/sshd_config".into(),
                ),
                module: "remote",
            }]);
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut diagnostics = Vec::new();

        check_sshd_bool_setting(
            &stdout,
            "pubkeyauthentication",
            "PubkeyAuthentication",
            self.host,
            &mut diagnostics,
        );
        check_sshd_bool_setting(
            &stdout,
            "allowagentforwarding",
            "AllowAgentForwarding",
            self.host,
            &mut diagnostics,
        );

        Ok(diagnostics)
    }
}

/// Check a boolean sshd setting and push appropriate diagnostics.
fn check_sshd_bool_setting(
    stdout: &str,
    key_lower: &str,
    display_name: &str,
    host: &str,
    diagnostics: &mut Vec<Diagnostic>,
) {
    match find_sshd_setting(stdout, key_lower).as_deref() {
        Some("yes") => {
            diagnostics.push(Diagnostic {
                id: "remote_sshd_config",
                severity: Severity::Ok,
                message: format!("sshd {display_name} is enabled on {host}"),
                hint: None,
                module: "remote",
            });
        }
        Some(other) => {
            diagnostics.push(Diagnostic {
                id: "remote_sshd_config",
                severity: Severity::Warning,
                message: format!(
                    "sshd {display_name} is '{other}' on {host} (expected 'yes')",
                ),
                hint: Some(format!(
                    "Set `{display_name} yes` in /etc/ssh/sshd_config"
                )),
                module: "remote",
            });
        }
        None => {
            diagnostics.push(Diagnostic {
                id: "remote_sshd_config",
                severity: Severity::Ok,
                message: format!(
                    "sshd {display_name} not explicitly set on {host} (defaults to yes)",
                ),
                hint: None,
                module: "remote",
            });
        }
    }
}

/// Find a setting value from `sshd -T` output (lowercased key-value pairs).
fn find_sshd_setting(config: &str, key: &str) -> Option<String> {
    for line in config.lines() {
        if let Some(rest) = line.strip_prefix(key)
            && (rest.starts_with(' ') || rest.starts_with('\t'))
        {
            return Some(rest.trim().to_lowercase());
        }
    }
    None
}

// ---------------------------------------------------------------------------
// RemoteHomeCheck
// ---------------------------------------------------------------------------

impl RemoteHomeCheck<'_> {
    async fn run_check(&self) -> Result<Vec<Diagnostic>> {
        let output = tokio::process::Command::new("ssh")
            .args(ssh_connect_args(self.port, self.proxy_jump))
            .args([self.host, "echo $HOME"])
            .output()
            .await
            .map_err(|e| Error::CommandFailed(format!("failed to execute ssh: {e}")))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Ok(vec![Diagnostic {
                id: "remote_home",
                severity: Severity::Error,
                message: format!(
                    "Could not determine remote home directory on {}: {}",
                    self.host,
                    stderr.trim()
                ),
                hint: Some("Verify the remote host is accessible and the shell is configured".into()),
                module: "remote",
            }]);
        }

        let home = String::from_utf8_lossy(&output.stdout).trim().to_string();

        if home.is_empty() {
            Ok(vec![Diagnostic {
                id: "remote_home",
                severity: Severity::Warning,
                message: format!("Remote $HOME is empty on {}", self.host),
                hint: Some("Ensure the remote user has a properly configured shell environment".into()),
                module: "remote",
            }])
        } else {
            Ok(vec![Diagnostic {
                id: "remote_home",
                severity: Severity::Ok,
                message: format!("Remote home directory is '{}' on {}", home, self.host),
                hint: None,
                module: "remote",
            }])
        }
    }
}

// ---------------------------------------------------------------------------
// RemoteAuthorizedKeysContentCheck — compare local keys vs remote authorized_keys
// ---------------------------------------------------------------------------

/// Read local public key files and compare them against the remote
/// `~/.ssh/authorized_keys` to detect missing or extra keys.
struct RemoteAuthorizedKeysContentCheck<'a> {
    paths: &'a SshPaths,
    host: &'a str,
    port: Option<u16>,
    proxy_jump: Option<&'a str>,
}

impl RemoteAuthorizedKeysContentCheck<'_> {
    #[allow(clippy::too_many_lines)]
    async fn run_check(&self) -> Result<Vec<Diagnostic>> {
        // Read local public keys.
        let ssh_dir = self.paths.ssh_dir().to_path_buf();
        let Ok(mut read_dir) = tokio::fs::read_dir(&ssh_dir).await else {
            return Ok(vec![Diagnostic {
                id: "remote_authorized_keys_content",
                severity: Severity::Info,
                message: format!(
                    "Cannot read local {} to compare with remote authorized_keys",
                    ssh_dir.display()
                ),
                hint: None,
                module: "remote",
            }]);
        };

        let mut local_pub_keys: Vec<(String, String)> = Vec::new(); // (filename, key-data)
        while let Some(entry) = read_dir.next_entry().await? {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if name_str.ends_with(".pub")
                && !name_str.ends_with("-cert.pub")
                && let Ok(content) = tokio::fs::read_to_string(entry.path()).await
            {
                for line in content.lines() {
                    let trimmed = line.trim();
                    if !trimmed.is_empty() && !trimmed.starts_with('#') {
                        local_pub_keys.push((name_str.to_string(), trimmed.to_owned()));
                    }
                }
            }
        }

        if local_pub_keys.is_empty() {
            return Ok(vec![Diagnostic {
                id: "remote_authorized_keys_content",
                severity: Severity::Info,
                message: "No local public key files found to compare with remote authorized_keys".into(),
                hint: None,
                module: "remote",
            }]);
        }

        // Read remote authorized_keys.
        let output = tokio::process::Command::new("ssh")
            .args(ssh_connect_args(self.port, self.proxy_jump))
            .args([self.host, "cat ~/.ssh/authorized_keys 2>/dev/null"])
            .output()
            .await
            .map_err(|e| Error::CommandFailed(format!("failed to execute ssh: {e}")))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Ok(vec![Diagnostic {
                id: "remote_authorized_keys_content",
                severity: Severity::Warning,
                message: format!(
                    "Could not read remote authorized_keys on {}: {}",
                    self.host,
                    stderr.trim()
                ),
                hint: Some("Ensure ~/.ssh/authorized_keys exists and is readable on the remote host".into()),
                module: "remote",
            }]);
        }

        let remote_content = String::from_utf8_lossy(&output.stdout);
        let remote_keys: Vec<&str> = remote_content
            .lines()
            .filter(|l| {
                let t = l.trim();
                !t.is_empty() && !t.starts_with('#')
            })
            .collect();

        let mut diagnostics = Vec::new();

        // Check each local key against remote authorized_keys.
        // We compare just the key type + base64 data (columns 1-2), ignoring
        // comments (column 3) which may differ between local and remote.
        for (filename, local_line) in &local_pub_keys {
            let local_parts: Vec<&str> = local_line.split_whitespace().collect();
            if local_parts.len() < 2 {
                continue;
            }
            let local_key_data = format!("{} {}", local_parts[0], local_parts[1]);

            let found = remote_keys.iter().any(|rk| {
                let rk_parts: Vec<&str> = rk.split_whitespace().collect();
                if rk_parts.len() < 2 {
                    return false;
                }
                let rk_key_data = format!("{} {}", rk_parts[0], rk_parts[1]);
                rk_key_data == local_key_data
            });

            if found {
                diagnostics.push(Diagnostic {
                    id: "remote_authorized_keys_content",
                    severity: Severity::Ok,
                    message: format!(
                        "Local key {filename} is present in remote authorized_keys on {}",
                        self.host
                    ),
                    hint: None,
                    module: "remote",
                });
            } else {
                diagnostics.push(Diagnostic {
                    id: "remote_authorized_keys_content",
                    severity: Severity::Warning,
                    message: format!(
                        "Local key {filename} is NOT in remote authorized_keys on {}",
                        self.host
                    ),
                    hint: Some(format!(
                        "Copy the key: `ssh-copy-id -i ~/.ssh/{filename} {}`",
                        self.host
                    )),
                    module: "remote",
                });
            }
        }

        Ok(diagnostics)
    }
}

// ---------------------------------------------------------------------------
// RemoteSshdAuthMethodsCheck — parse sshd -T auth method settings
// ---------------------------------------------------------------------------

/// Parse `sshd -T` output and check authentication method settings:
/// KbdInteractiveAuthentication, GSSAPIAuthentication,
/// PasswordAuthentication, HostbasedAuthentication.
struct RemoteSshdAuthMethodsCheck<'a> {
    host: &'a str,
    port: Option<u16>,
    proxy_jump: Option<&'a str>,
}

impl RemoteSshdAuthMethodsCheck<'_> {
    #[allow(clippy::too_many_lines)]
    async fn run_check(&self) -> Result<Vec<Diagnostic>> {
        let output = tokio::process::Command::new("ssh")
            .args(ssh_connect_args(self.port, self.proxy_jump))
            .args([self.host, "sshd -T 2>/dev/null"])
            .output()
            .await
            .map_err(|e| Error::CommandFailed(format!("failed to execute ssh: {e}")))?;

        if !output.status.success() {
            return Ok(vec![Diagnostic {
                id: "remote_sshd_auth_methods",
                severity: Severity::Info,
                message: format!(
                    "Could not read sshd config on {} (may require elevated privileges)",
                    self.host
                ),
                hint: Some(
                    "Run with sudo or check /etc/ssh/sshd_config for authentication method settings".into(),
                ),
                module: "remote",
            }]);
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut diagnostics = Vec::new();

        // These are the key authentication methods. If PasswordAuthentication
        // or HostbasedAuthentication is enabled, that may be a security concern
        // on internet-facing hosts.
        let auth_settings = [
            ("pubkeyauthentication", "PubkeyAuthentication"),
            ("kbdinteractiveauthentication", "KbdInteractiveAuthentication"),
            ("gssapiauthentication", "GSSAPIAuthentication"),
            ("passwordauthentication", "PasswordAuthentication"),
            ("hostbasedauthentication", "HostbasedAuthentication"),
        ];

        for (key_lower, display_name) in &auth_settings {
            match find_sshd_setting(&stdout, key_lower).as_deref() {
                Some("yes") => {
                    let severity = if *display_name == "PasswordAuthentication"
                        || *display_name == "HostbasedAuthentication"
                    {
                        Severity::Warning
                    } else {
                        Severity::Info
                    };
                    diagnostics.push(Diagnostic {
                        id: "remote_sshd_auth_methods",
                        severity,
                        message: format!(
                            "sshd {display_name} is 'yes' on {}",
                            self.host
                        ),
                        hint: if severity == Severity::Warning {
                            Some(format!(
                                "Consider disabling {display_name} for improved security: \
                                 `sudo sed -i 's/^{display_name} yes/{display_name} no/' /etc/ssh/sshd_config`"
                            ))
                        } else {
                            None
                        },
                        module: "remote",
                    });
                }
                Some("no") => {
                    diagnostics.push(Diagnostic {
                        id: "remote_sshd_auth_methods",
                        severity: Severity::Ok,
                        message: format!(
                            "sshd {display_name} is 'no' on {}",
                            self.host
                        ),
                        hint: None,
                        module: "remote",
                    });
                }
                Some(other) => {
                    diagnostics.push(Diagnostic {
                        id: "remote_sshd_auth_methods",
                        severity: Severity::Info,
                        message: format!(
                            "sshd {display_name} is '{other}' on {}",
                            self.host
                        ),
                        hint: None,
                        module: "remote",
                    });
                }
                None => {
                    diagnostics.push(Diagnostic {
                        id: "remote_sshd_auth_methods",
                        severity: Severity::Ok,
                        message: format!(
                            "sshd {display_name} not explicitly set on {} (uses compiled default)",
                            self.host
                        ),
                        hint: None,
                        module: "remote",
                    });
                }
            }
        }

        Ok(diagnostics)
    }
}

// ---------------------------------------------------------------------------
// RemoteAuthorizedKeysCommandCheck — check AuthorizedKeysCommand settings
// ---------------------------------------------------------------------------

/// Check for `AuthorizedKeysCommand` and `AuthorizedPrincipalsCommand` in
/// the remote sshd config. These are used when the server fetches keys or
/// principals from an external source (e.g., GitHub, LDAP).
struct RemoteAuthorizedKeysCommandCheck<'a> {
    host: &'a str,
    port: Option<u16>,
    proxy_jump: Option<&'a str>,
}

impl RemoteAuthorizedKeysCommandCheck<'_> {
    #[allow(clippy::too_many_lines)]
    async fn run_check(&self) -> Result<Vec<Diagnostic>> {
        let output = tokio::process::Command::new("ssh")
            .args(ssh_connect_args(self.port, self.proxy_jump))
            .args([self.host, "sshd -T 2>/dev/null"])
            .output()
            .await
            .map_err(|e| Error::CommandFailed(format!("failed to execute ssh: {e}")))?;

        if !output.status.success() {
            return Ok(vec![Diagnostic {
                id: "remote_authorized_keys_command",
                severity: Severity::Info,
                message: format!(
                    "Could not read sshd config on {} (may require elevated privileges)",
                    self.host
                ),
                hint: Some(
                    "Run with sudo or check /etc/ssh/sshd_config for AuthorizedKeysCommand settings".into(),
                ),
                module: "remote",
            }]);
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut diagnostics = Vec::new();

        // AuthorizedKeysCommand
        match find_sshd_setting(&stdout, "authorizedkeyscommand") {
            Some(value) if value != "none" && !value.is_empty() => {
                diagnostics.push(Diagnostic {
                    id: "remote_authorized_keys_command",
                    severity: Severity::Info,
                    message: format!(
                        "sshd AuthorizedKeysCommand is set to '{}' on {}",
                        value, self.host
                    ),
                    hint: Some(
                        "Keys may be fetched from an external source rather than ~/.ssh/authorized_keys".into(),
                    ),
                    module: "remote",
                });
            }
            _ => {
                diagnostics.push(Diagnostic {
                    id: "remote_authorized_keys_command",
                    severity: Severity::Ok,
                    message: format!(
                        "sshd AuthorizedKeysCommand is not set on {} (uses standard authorized_keys file)",
                        self.host
                    ),
                    hint: None,
                    module: "remote",
                });
            }
        }

        // AuthorizedPrincipalsCommand
        match find_sshd_setting(&stdout, "authorizedprincipalscommand") {
            Some(value) if value != "none" && !value.is_empty() => {
                diagnostics.push(Diagnostic {
                    id: "remote_authorized_keys_command",
                    severity: Severity::Info,
                    message: format!(
                        "sshd AuthorizedPrincipalsCommand is set to '{}' on {}",
                        value, self.host
                    ),
                    hint: Some(
                        "Certificate principals are validated by an external command".into(),
                    ),
                    module: "remote",
                });
            }
            _ => {
                diagnostics.push(Diagnostic {
                    id: "remote_authorized_keys_command",
                    severity: Severity::Ok,
                    message: format!(
                        "sshd AuthorizedPrincipalsCommand is not set on {}",
                        self.host
                    ),
                    hint: None,
                    module: "remote",
                });
            }
        }

        // AuthorizedKeysCommandUser (only relevant if the command is set)
        if let Some(cmd) = find_sshd_setting(&stdout, "authorizedkeyscommand")
            && cmd != "none" && !cmd.is_empty()
        {
            match find_sshd_setting(&stdout, "authorizedkeyscommanduser") {
                Some(user) if user != "nobody" => {
                    diagnostics.push(Diagnostic {
                        id: "remote_authorized_keys_command",
                        severity: Severity::Ok,
                        message: format!(
                            "sshd AuthorizedKeysCommandUser is '{}' on {}",
                            user, self.host
                        ),
                        hint: None,
                        module: "remote",
                    });
                }
                _ => {
                    diagnostics.push(Diagnostic {
                        id: "remote_authorized_keys_command",
                        severity: Severity::Warning,
                        message: format!(
                            "sshd AuthorizedKeysCommand is set but AuthorizedKeysCommandUser is not configured on {}",
                            self.host
                        ),
                        hint: Some(
                            "Set AuthorizedKeysCommandUser in /etc/ssh/sshd_config (e.g., 'nobody' or a dedicated user)".into(),
                        ),
                        module: "remote",
                    });
                }
            }
        }

        Ok(diagnostics)
    }
}

// ---------------------------------------------------------------------------
// RemoteStrictModesCheck — check remote StrictModes setting
// ---------------------------------------------------------------------------

/// Report where to find remote SSH logs.
///
/// Checks for the presence of common SSH log files and tools:
/// - `/var/log/auth.log` (Debian/Ubuntu)
/// - `/var/log/secure` (RHEL/CentOS)
/// - `journalctl -u sshd` (systemd-based systems)
///
/// This is an informational check that helps users locate SSH logs when
/// debugging authentication or connectivity issues on the remote host.
struct RemoteLogsHintCheck<'a> {
    host: &'a str,
    port: Option<u16>,
    proxy_jump: Option<&'a str>,
}

/// Check the remote sshd `StrictModes` setting. When StrictModes is enabled
/// (the default), sshd rejects authorized_keys if file/directory permissions
/// are too permissive. This check helps diagnose authentication failures
/// caused by permission issues on the remote.
struct RemoteStrictModesCheck<'a> {
    host: &'a str,
    port: Option<u16>,
    proxy_jump: Option<&'a str>,
}

// ---------------------------------------------------------------------------
// RemoteLogsHintCheck
// ---------------------------------------------------------------------------

impl RemoteLogsHintCheck<'_> {
    async fn run_check(&self) -> Result<Vec<Diagnostic>> {
        // Check for /var/log/auth.log (Debian/Ubuntu) and /var/log/secure (RHEL/CentOS),
        // then check whether journalctl -u sshd is available. Run all three in a
        // single SSH command to minimise round-trips.
        let cmd = "\
            echo auth_log=$(test -f /var/log/auth.log && echo yes || echo no); \
            echo secure_log=$(test -f /var/log/secure && echo yes || echo no); \
            echo journalctl=$(command -v journalctl >/dev/null 2>&1 && journalctl -u sshd --no-pager -n 1 >/dev/null 2>&1 && echo yes || echo no)";

        let output = tokio::process::Command::new("ssh")
            .args(ssh_connect_args(self.port, self.proxy_jump))
            .args([self.host, cmd])
            .output()
            .await
            .map_err(|e| Error::CommandFailed(format!("failed to execute ssh: {e}")))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Ok(vec![Diagnostic {
                id: "remote_logs_hint",
                severity: Severity::Info,
                message: format!(
                    "Could not determine remote log locations on {}: {}",
                    self.host,
                    stderr.trim()
                ),
                hint: Some(
                    "Check /var/log/auth.log (Debian/Ubuntu), /var/log/secure (RHEL/CentOS), or `journalctl -u sshd`".into(),
                ),
                module: "remote",
            }]);
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut log_sources = Vec::new();

        for line in stdout.lines() {
            let line = line.trim();
            if line == "auth_log=yes" {
                log_sources.push("/var/log/auth.log (Debian/Ubuntu)");
            } else if line == "secure_log=yes" {
                log_sources.push("/var/log/secure (RHEL/CentOS)");
            } else if line == "journalctl=yes" {
                log_sources.push("`journalctl -u sshd` (systemd)");
            }
        }

        if log_sources.is_empty() {
            Ok(vec![Diagnostic {
                id: "remote_logs_hint",
                severity: Severity::Info,
                message: format!(
                    "No standard SSH log sources found on {}",
                    self.host
                ),
                hint: Some(
                    "Check your distribution's logging configuration — SSH logs may be in a custom location or require elevated privileges".into(),
                ),
                module: "remote",
            }])
        } else {
            let joined = log_sources.join(", ");
            Ok(vec![Diagnostic {
                id: "remote_logs_hint",
                severity: Severity::Info,
                message: format!(
                    "Remote SSH logs available via: {} on {}",
                    joined, self.host
                ),
                hint: Some(format!(
                    "View SSH logs on {} using: {}",
                    self.host,
                    if log_sources.len() == 1 {
                        log_sources[0].to_string()
                    } else {
                        // Prefer auth.log/secure as a concrete file path, fall back to journalctl.
                        log_sources.iter().find(|s| s.starts_with('/')).copied()
                            .unwrap_or("journalctl -u sshd")
                            .to_string()
                    }
                )),
                module: "remote",
            }])
        }
    }
}

impl RemoteStrictModesCheck<'_> {
    async fn run_check(&self) -> Result<Vec<Diagnostic>> {
        let output = tokio::process::Command::new("ssh")
            .args(ssh_connect_args(self.port, self.proxy_jump))
            .args([self.host, "sshd -T 2>/dev/null"])
            .output()
            .await
            .map_err(|e| Error::CommandFailed(format!("failed to execute ssh: {e}")))?;

        if !output.status.success() {
            return Ok(vec![Diagnostic {
                id: "remote_strict_modes",
                severity: Severity::Info,
                message: format!(
                    "Could not read sshd config on {} (may require elevated privileges)",
                    self.host
                ),
                hint: Some(
                    "Check StrictModes setting in /etc/ssh/sshd_config on the remote host".into(),
                ),
                module: "remote",
            }]);
        }

        let stdout = String::from_utf8_lossy(&output.stdout);

        match find_sshd_setting(&stdout, "strictmodes").as_deref() {
            Some("yes") => Ok(vec![Diagnostic {
                id: "remote_strict_modes",
                severity: Severity::Ok,
                message: format!(
                    "sshd StrictModes is 'yes' on {} (permissions on ~/.ssh, authorized_keys, and home directory are checked)",
                    self.host
                ),
                hint: None,
                module: "remote",
            }]),
            Some("no") => Ok(vec![Diagnostic {
                id: "remote_strict_modes",
                severity: Severity::Warning,
                message: format!(
                    "sshd StrictModes is 'no' on {} — file permission checks are disabled",
                    self.host
                ),
                hint: Some(
                    "Consider enabling StrictModes for security: set `StrictModes yes` in /etc/ssh/sshd_config".into(),
                ),
                module: "remote",
            }]),
            Some(other) => Ok(vec![Diagnostic {
                id: "remote_strict_modes",
                severity: Severity::Info,
                message: format!(
                    "sshd StrictModes is '{other}' on {}",
                    self.host
                ),
                hint: None,
                module: "remote",
            }]),
            None => Ok(vec![Diagnostic {
                id: "remote_strict_modes",
                severity: Severity::Ok,
                message: format!(
                    "sshd StrictModes not explicitly set on {} (defaults to 'yes')",
                    self.host
                ),
                hint: None,
                module: "remote",
            }]),
        }
    }
}

// ---------------------------------------------------------------------------
// RemoteSshdFullConfigCheck — parse all relevant sshd settings
// ---------------------------------------------------------------------------

/// Parse all relevant sshd settings from `sshd -T` output:
/// AuthorizedKeysFile, RevokedKeys, TrustedUserCAKeys,
/// AuthenticationMethods, MaxAuthTries, PubkeyAuthOptions,
/// PermitRootLogin, and MaxSessions.
struct RemoteSshdFullConfigCheck<'a> {
    host: &'a str,
    port: Option<u16>,
    proxy_jump: Option<&'a str>,
}

impl RemoteSshdFullConfigCheck<'_> {
    #[allow(clippy::too_many_lines)]
    async fn run_check(&self) -> Result<Vec<Diagnostic>> {
        let output = tokio::process::Command::new("ssh")
            .args(ssh_connect_args(self.port, self.proxy_jump))
            .args([self.host, "sshd -T 2>/dev/null"])
            .output()
            .await
            .map_err(|e| Error::CommandFailed(format!("failed to execute ssh: {e}")))?;

        if !output.status.success() {
            return Ok(vec![Diagnostic {
                id: "remote_sshd_full_config",
                severity: Severity::Info,
                message: format!(
                    "Could not read sshd config on {} (may require elevated privileges)",
                    self.host
                ),
                hint: Some(
                    "Run with sudo or check /etc/ssh/sshd_config for the full configuration".into(),
                ),
                module: "remote",
            }]);
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut diagnostics = Vec::new();

        // AuthorizedKeysFile — where sshd looks for authorized keys.
        match find_sshd_setting(&stdout, "authorizedkeysfile") {
            Some(value) => {
                let is_default = value == ".ssh/authorized_keys .ssh/authorized_keys2"
                    || value == ".ssh/authorized_keys";
                diagnostics.push(Diagnostic {
                    id: "remote_sshd_full_config",
                    severity: if is_default { Severity::Ok } else { Severity::Info },
                    message: format!(
                        "sshd AuthorizedKeysFile is '{}' on {}",
                        value, self.host
                    ),
                    hint: if is_default {
                        None
                    } else {
                        Some("Custom AuthorizedKeysFile — ensure your keys are in the correct location".into())
                    },
                    module: "remote",
                });
            }
            None => {
                diagnostics.push(Diagnostic {
                    id: "remote_sshd_full_config",
                    severity: Severity::Ok,
                    message: format!(
                        "sshd AuthorizedKeysFile not set on {} (defaults to .ssh/authorized_keys)",
                        self.host
                    ),
                    hint: None,
                    module: "remote",
                });
            }
        }

        // RevokedKeys — if set, keys listed here are rejected.
        match find_sshd_setting(&stdout, "revokedkeys") {
            Some(value) if !value.is_empty() && value != "none" => {
                diagnostics.push(Diagnostic {
                    id: "remote_sshd_full_config",
                    severity: Severity::Info,
                    message: format!(
                        "sshd RevokedKeys is set to '{}' on {}",
                        value, self.host
                    ),
                    hint: Some(
                        "Keys listed in the revoked keys file will be rejected even if present in authorized_keys".into(),
                    ),
                    module: "remote",
                });
            }
            _ => {
                diagnostics.push(Diagnostic {
                    id: "remote_sshd_full_config",
                    severity: Severity::Ok,
                    message: format!(
                        "sshd RevokedKeys is not set on {}",
                        self.host
                    ),
                    hint: None,
                    module: "remote",
                });
            }
        }

        // TrustedUserCAKeys — CA certificates trusted for user authentication.
        match find_sshd_setting(&stdout, "trustedusercakeys") {
            Some(value) if !value.is_empty() && value != "none" => {
                diagnostics.push(Diagnostic {
                    id: "remote_sshd_full_config",
                    severity: Severity::Info,
                    message: format!(
                        "sshd TrustedUserCAKeys is set to '{}' on {}",
                        value, self.host
                    ),
                    hint: Some(
                        "Certificate-based authentication is configured — signed certificates are trusted".into(),
                    ),
                    module: "remote",
                });
            }
            _ => {
                diagnostics.push(Diagnostic {
                    id: "remote_sshd_full_config",
                    severity: Severity::Ok,
                    message: format!(
                        "sshd TrustedUserCAKeys is not set on {} (no CA-based auth)",
                        self.host
                    ),
                    hint: None,
                    module: "remote",
                });
            }
        }

        // AuthenticationMethods — multi-factor requirements.
        match find_sshd_setting(&stdout, "authenticationmethods") {
            Some(value) if !value.is_empty() && value != "any" => {
                diagnostics.push(Diagnostic {
                    id: "remote_sshd_full_config",
                    severity: Severity::Info,
                    message: format!(
                        "sshd AuthenticationMethods is '{}' on {} (multi-factor may be required)",
                        value, self.host
                    ),
                    hint: Some(
                        "Ensure your client can satisfy all required authentication methods".into(),
                    ),
                    module: "remote",
                });
            }
            _ => {
                diagnostics.push(Diagnostic {
                    id: "remote_sshd_full_config",
                    severity: Severity::Ok,
                    message: format!(
                        "sshd AuthenticationMethods uses default on {} (any single method accepted)",
                        self.host
                    ),
                    hint: None,
                    module: "remote",
                });
            }
        }

        // MaxAuthTries
        match find_sshd_setting(&stdout, "maxauthtries") {
            Some(value) => {
                let tries: u32 = value.parse().unwrap_or(6);
                let severity = if tries <= 3 {
                    Severity::Warning
                } else {
                    Severity::Ok
                };
                diagnostics.push(Diagnostic {
                    id: "remote_sshd_full_config",
                    severity,
                    message: format!(
                        "sshd MaxAuthTries is {} on {}",
                        tries, self.host
                    ),
                    hint: if tries <= 3 {
                        Some(format!(
                            "MaxAuthTries is low ({tries}) — clients with multiple keys may fail. \
                             Consider increasing to 6 or reducing loaded agent keys"
                        ))
                    } else {
                        None
                    },
                    module: "remote",
                });
            }
            None => {
                diagnostics.push(Diagnostic {
                    id: "remote_sshd_full_config",
                    severity: Severity::Ok,
                    message: format!(
                        "sshd MaxAuthTries not set on {} (defaults to 6)",
                        self.host
                    ),
                    hint: None,
                    module: "remote",
                });
            }
        }

        // PubkeyAuthOptions
        match find_sshd_setting(&stdout, "pubkeyauthoptions") {
            Some(value) => {
                let severity = if value.contains("no-touch-required") {
                    Severity::Info
                } else {
                    Severity::Ok
                };
                diagnostics.push(Diagnostic {
                    id: "remote_sshd_full_config",
                    severity,
                    message: format!(
                        "sshd PubkeyAuthOptions is '{}' on {}",
                        value, self.host
                    ),
                    hint: None,
                    module: "remote",
                });
            }
            None => {
                diagnostics.push(Diagnostic {
                    id: "remote_sshd_full_config",
                    severity: Severity::Ok,
                    message: format!(
                        "sshd PubkeyAuthOptions not set on {} (defaults to none)",
                        self.host
                    ),
                    hint: None,
                    module: "remote",
                });
            }
        }

        // PermitRootLogin
        match find_sshd_setting(&stdout, "permitrootlogin") {
            Some(value) => {
                let severity = if value == "yes" || value == "without-password" {
                    Severity::Warning
                } else {
                    Severity::Ok
                };
                diagnostics.push(Diagnostic {
                    id: "remote_sshd_full_config",
                    severity,
                    message: format!(
                        "sshd PermitRootLogin is '{}' on {}",
                        value, self.host
                    ),
                    hint: if severity == Severity::Warning {
                        Some(
                            "Consider disabling root login: set `PermitRootLogin no` in /etc/ssh/sshd_config".into(),
                        )
                    } else {
                        None
                    },
                    module: "remote",
                });
            }
            None => {
                diagnostics.push(Diagnostic {
                    id: "remote_sshd_full_config",
                    severity: Severity::Ok,
                    message: format!(
                        "sshd PermitRootLogin not set on {} (defaults to 'prohibit-password' in recent OpenSSH)",
                        self.host
                    ),
                    hint: None,
                    module: "remote",
                });
            }
        }

        // MaxSessions
        match find_sshd_setting(&stdout, "maxsessions") {
            Some(value) => {
                diagnostics.push(Diagnostic {
                    id: "remote_sshd_full_config",
                    severity: Severity::Ok,
                    message: format!(
                        "sshd MaxSessions is {} on {}",
                        value, self.host
                    ),
                    hint: None,
                    module: "remote",
                });
            }
            None => {
                diagnostics.push(Diagnostic {
                    id: "remote_sshd_full_config",
                    severity: Severity::Ok,
                    message: format!(
                        "sshd MaxSessions not set on {} (defaults to 10)",
                        self.host
                    ),
                    hint: None,
                    module: "remote",
                });
            }
        }

        // AuthorizedPrincipalsFile — where sshd looks for allowed principals
        // for certificate-based authentication.
        match find_sshd_setting(&stdout, "authorizedprincipalsfile") {
            Some(value) => {
                let is_default = value == "none";
                diagnostics.push(Diagnostic {
                    id: "remote_sshd_full_config",
                    severity: if is_default { Severity::Ok } else { Severity::Info },
                    message: format!(
                        "sshd AuthorizedPrincipalsFile is '{}' on {}",
                        value, self.host
                    ),
                    hint: if is_default {
                        None
                    } else {
                        Some(
                            "Certificate authentication uses principals file — \
                             ensure the file exists and contains the correct principals"
                                .into(),
                        )
                    },
                    module: "remote",
                });
            }
            None => {
                diagnostics.push(Diagnostic {
                    id: "remote_sshd_full_config",
                    severity: Severity::Ok,
                    message: format!(
                        "sshd AuthorizedPrincipalsFile not set on {} (defaults to 'none')",
                        self.host
                    ),
                    hint: None,
                    module: "remote",
                });
            }
        }

        Ok(diagnostics)
    }
}

// ---------------------------------------------------------------------------
// RemoteAuthorizedPrincipalsFileCheck — verify AuthorizedPrincipalsFile exists
// ---------------------------------------------------------------------------

/// Check that the remote `AuthorizedPrincipalsFile` exists and is readable
/// when `TrustedUserCAKeys` is configured. This is critical for certificate-
/// based authentication: if TrustedUserCAKeys is set but the principals file
/// is missing, certificate auth will silently fail.
struct RemoteAuthorizedPrincipalsFileCheck<'a> {
    host: &'a str,
    port: Option<u16>,
    proxy_jump: Option<&'a str>,
}

impl RemoteAuthorizedPrincipalsFileCheck<'_> {
    #[allow(clippy::too_many_lines)]
    async fn run_check(&self) -> Result<Vec<Diagnostic>> {
        let output = tokio::process::Command::new("ssh")
            .args(ssh_connect_args(self.port, self.proxy_jump))
            .args([self.host, "sshd -T 2>/dev/null"])
            .output()
            .await
            .map_err(|e| Error::CommandFailed(format!("failed to execute ssh: {e}")))?;

        if !output.status.success() {
            return Ok(vec![Diagnostic {
                id: "remote_authorized_principals_file",
                severity: Severity::Info,
                message: format!(
                    "Could not read sshd config on {} (may require elevated privileges)",
                    self.host
                ),
                hint: Some(
                    "Run with sudo or check /etc/ssh/sshd_config for AuthorizedPrincipalsFile".into(),
                ),
                module: "remote",
            }]);
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut diagnostics = Vec::new();

        // Only check if TrustedUserCAKeys is configured — without it,
        // AuthorizedPrincipalsFile is irrelevant.
        let has_tuak = find_sshd_setting(&stdout, "trustedusercakeys")
            .is_some_and(|v| !v.is_empty() && v != "none");

        if !has_tuak {
            return Ok(vec![Diagnostic {
                id: "remote_authorized_principals_file",
                severity: Severity::Ok,
                message: format!(
                    "TrustedUserCAKeys is not set on {} — \
                     AuthorizedPrincipalsFile is not applicable",
                    self.host
                ),
                hint: None,
                module: "remote",
            }]);
        }

        // TrustedUserCAKeys is set — check the principals file.
        match find_sshd_setting(&stdout, "authorizedprincipalsfile") {
            Some(value) if value != "none" && !value.is_empty() => {
                // Verify the file exists on the remote host.
                let test_cmd = format!("test -f {value}");
                let test_output = tokio::process::Command::new("ssh")
                    .args(ssh_connect_args(self.port, self.proxy_jump))
                    .args([self.host, test_cmd.as_str()])
                    .output()
                    .await
                    .map_err(|e| Error::CommandFailed(format!("failed to execute ssh: {e}")))?;

                if test_output.status.success() {
                    diagnostics.push(Diagnostic {
                        id: "remote_authorized_principals_file",
                        severity: Severity::Ok,
                        message: format!(
                            "AuthorizedPrincipalsFile '{}' exists on {}",
                            value, self.host
                        ),
                        hint: None,
                        module: "remote",
                    });
                } else {
                    diagnostics.push(Diagnostic {
                        id: "remote_authorized_principals_file",
                        severity: Severity::Warning,
                        message: format!(
                            "AuthorizedPrincipalsFile '{}' does not exist on {} — \
                             certificate auth may fail",
                            value, self.host
                        ),
                        hint: Some(format!(
                            "Create the file: `sudo touch {value} && sudo chmod 644 {value}`"
                        )),
                        module: "remote",
                    });
                }
            }
            Some(ref s) if s == "none" => {
                diagnostics.push(Diagnostic {
                    id: "remote_authorized_principals_file",
                    severity: Severity::Info,
                    message: format!(
                        "TrustedUserCAKeys is set but AuthorizedPrincipalsFile is 'none' on {} — \
                         all principals from CA certificates will be accepted",
                        self.host
                    ),
                    hint: Some(
                        "Consider setting AuthorizedPrincipalsFile to restrict which principals \
                         are accepted from CA-signed certificates".into(),
                    ),
                    module: "remote",
                });
            }
            _ => {
                diagnostics.push(Diagnostic {
                    id: "remote_authorized_principals_file",
                    severity: Severity::Ok,
                    message: format!(
                        "AuthorizedPrincipalsFile is set on {} (value: '{}')",
                        self.host,
                        find_sshd_setting(&stdout, "authorizedprincipalsfile").unwrap_or_default()
                    ),
                    hint: None,
                    module: "remote",
                });
            }
        }

        Ok(diagnostics)
    }
}

// ---------------------------------------------------------------------------
// ProxyJumpDetectionCheck
// ---------------------------------------------------------------------------

impl ProxyJumpDetectionCheck<'_> {
    async fn run_check(&self) -> Result<Vec<Diagnostic>> {
        let resolved = match resolve(self.paths.ssh_dir(), self.host, None).await {
            Ok(r) => r,
            Err(e) => {
                return Ok(vec![Diagnostic {
                    id: "proxy_jump_config",
                    severity: Severity::Info,
                    message: format!(
                        "Could not resolve SSH config for {}: {}",
                        self.host, e
                    ),
                    hint: Some(
                        "ProxyJump detection requires a valid SSH config. \
                         Check ~/.ssh/config for syntax errors"
                            .into(),
                    ),
                    module: "remote",
                }]);
            }
        };

        match resolved.proxy_jump {
            Some(ref jump) if jump != "none" && !jump.is_empty() => Ok(vec![Diagnostic {
                id: "proxy_jump_config",
                severity: Severity::Ok,
                message: format!(
                    "Host {} uses ProxyJump: {}",
                    self.host, jump
                ),
                hint: Some(
                    "SSH connections to this host will be tunneled through the jump host. \
                     Ensure the jump host is accessible and allows forwarding"
                        .into(),
                ),
                module: "remote",
            }]),
            Some(_) => Ok(vec![Diagnostic {
                id: "proxy_jump_config",
                severity: Severity::Ok,
                message: format!(
                    "ProxyJump is explicitly disabled for {}",
                    self.host
                ),
                hint: None,
                module: "remote",
            }]),
            None => Ok(vec![Diagnostic {
                id: "proxy_jump_config",
                severity: Severity::Ok,
                message: format!(
                    "No ProxyJump configured for {}",
                    self.host
                ),
                hint: None,
                module: "remote",
            }]),
        }
    }
}

// ---------------------------------------------------------------------------
// JumpHostReachableCheck
// ---------------------------------------------------------------------------

impl JumpHostReachableCheck<'_> {
    async fn run_check(&self) -> Result<Vec<Diagnostic>> {
        // Verify `ssh` is available before attempting to connect.
        if !self.runner.tool_exists("ssh") {
            return Ok(vec![Diagnostic {
                id: "jump_host_reachable",
                severity: Severity::Error,
                message: "`ssh` is not found in PATH".into(),
                hint: Some(
                    "Install OpenSSH: `brew install openssh` (macOS) or \
                     `sudo apt install openssh-client` (Linux)"
                        .into(),
                ),
                module: "remote",
            }]);
        }

        // Parse the jump host for optional port specification.
        let (jump_host, jump_port) = parse_host_port(self.jump_host);

        let output = tokio::process::Command::new("ssh")
            .args(ssh_connect_args(jump_port, None))
            .args([jump_host, "true"])
            .output()
            .await
            .map_err(|e| {
                Error::CommandFailed(format!("failed to execute ssh: {e}"))
            })?;

        if output.status.success() {
            Ok(vec![Diagnostic {
                id: "jump_host_reachable",
                severity: Severity::Ok,
                message: format!(
                    "Jump host {} is reachable",
                    self.jump_host
                ),
                hint: None,
                module: "remote",
            }])
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Ok(vec![Diagnostic {
                id: "jump_host_reachable",
                severity: Severity::Warning,
                message: format!(
                    "Jump host {} is not reachable: {}",
                    self.jump_host,
                    stderr.trim()
                ),
                hint: Some(
                    "Verify the jump host is accessible and SSH is running. \
                     Target host connections will fail until the jump host is reachable"
                        .into(),
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
#[allow(clippy::too_many_lines)]
pub async fn run_all(
    paths: &SshPaths,
    host: &str,
    runner: &dyn crate::CliRunner,
) -> Result<Vec<Diagnostic>> {
    // Parse the host string once to extract an optional non-standard port.
    let (host, port) = parse_host_port(host);

    let mut all_diagnostics = Vec::new();

    // ProxyJump detection — resolve SSH config to check for ProxyJump.
    // This runs early so that subsequent SSH-dependent checks can use the
    // jump host for connections.
    let proxy_jump_check = ProxyJumpDetectionCheck { paths, host };
    match proxy_jump_check.run_check().await {
        Ok(d) => all_diagnostics.extend(d),
        Err(e) => all_diagnostics.push(err_diagnostic("proxy_jump_config", &e)),
    }

    // Resolve the SSH config to extract the ProxyJump value for use by
    // all subsequent SSH-based checks.
    let proxy_jump_value: Option<String> = match resolve(paths.ssh_dir(), host, None).await {
        Ok(resolved) => resolved.proxy_jump.filter(|pj| pj != "none" && !pj.is_empty()),
        Err(_) => None,
    };
    let proxy_jump: Option<&str> = proxy_jump_value.as_deref();

    // If ProxyJump is configured, verify the jump host is reachable.
    if let Some(jump) = proxy_jump {
        // ProxyJump may specify multiple comma-separated jump hosts.
        // Check only the first (final) hop, as that is the one SSH
        // connects to directly.
        let first_jump = jump.split(',').next().unwrap_or(jump);
        let jump_check = JumpHostReachableCheck {
            jump_host: first_jump,
            runner,
        };
        match jump_check.run_check().await {
            Ok(d) => all_diagnostics.extend(d),
            Err(e) => all_diagnostics.push(err_diagnostic("jump_host_reachable", &e)),
        }
    }

    // DNS resolution — run first since it is a prerequisite for SSH connectivity.
    let check = HostReachabilityCheck { host, port };
    let host_resolved = match check.run_check().await {
        Ok(d) => {
            let was_ok = d.iter().any(|d| d.severity == Severity::Ok);
            all_diagnostics.extend(d);
            was_ok
        }
        Err(e) => {
            all_diagnostics.push(err_diagnostic("host_resolvable", &e));
            false
        }
    };

    // Host reachability — skip if DNS failed since the connection will
    // certainly fail too, and the DNS diagnostic is more actionable.
    let host_reachable = if host_resolved {
        let check = HostReachable { host, port, proxy_jump, runner };
        match check.run_check().await {
            Ok(d) => {
                let was_ok = d.iter().any(|d| d.severity == Severity::Ok);
                all_diagnostics.extend(d);
                was_ok
            }
            Err(e) => {
                all_diagnostics.push(err_diagnostic("host_reachable", &e));
                false
            }
        }
    } else {
        all_diagnostics.push(Diagnostic {
            id: "host_reachable",
            severity: Severity::Info,
            message: format!("Skipped host_reachable check: DNS resolution failed for {host}"),
            hint: None,
            module: "remote",
        });
        false
    };

    // Host key in known_hosts (local check, always runs).
    let check = HostKeyKnown { paths, host, port };
    match check.run_check().await {
        Ok(d) => all_diagnostics.extend(d),
        Err(e) => all_diagnostics.push(err_diagnostic("host_key_known", &e)),
    }

    // Host key verification — compare stored vs live keys (local + network).
    let check = HostKeyVerificationCheck { paths, host, port };
    match check.run_check().await {
        Ok(d) => all_diagnostics.extend(d),
        Err(e) => all_diagnostics.push(err_diagnostic("host_key_verification", &e)),
    }

    // Agent forwarding — skip if host is not reachable to avoid a slow timeout.
    if host_reachable {
        let check = AgentForwarding { host, port, proxy_jump };
        match check.run_check().await {
            Ok(d) => all_diagnostics.extend(d),
            Err(e) => all_diagnostics.push(err_diagnostic("agent_forwarding", &e)),
        }

        // Remote home directory
        let check = RemoteHomeCheck { host, port, proxy_jump };
        match check.run_check().await {
            Ok(d) => all_diagnostics.extend(d),
            Err(e) => all_diagnostics.push(err_diagnostic("remote_home", &e)),
        }

        // Public-key authentication
        let check = RemotePubkeyAuthCheck { host, port, proxy_jump };
        match check.run_check().await {
            Ok(d) => all_diagnostics.extend(d),
            Err(e) => all_diagnostics.push(err_diagnostic("remote_pubkey_auth", &e)),
        }

        // Remote ~/.ssh permissions
        let check = RemotePermissionsCheck { host, port, proxy_jump };
        match check.run_check().await {
            Ok(d) => all_diagnostics.extend(d),
            Err(e) => all_diagnostics.push(err_diagnostic("remote_permissions", &e)),
        }

        // Remote authorized_keys existence
        let check = RemoteAuthorizedKeysCheck { host, port, proxy_jump };
        match check.run_check().await {
            Ok(d) => all_diagnostics.extend(d),
            Err(e) => all_diagnostics.push(err_diagnostic("remote_authorized_keys", &e)),
        }

        // Remote sshd configuration
        let check = RemoteSshdConfigCheck { host, port, proxy_jump };
        match check.run_check().await {
            Ok(d) => all_diagnostics.extend(d),
            Err(e) => all_diagnostics.push(err_diagnostic("remote_sshd_config", &e)),
        }

        // Remote authorized_keys content comparison
        let check = RemoteAuthorizedKeysContentCheck { paths, host, port, proxy_jump };
        match check.run_check().await {
            Ok(d) => all_diagnostics.extend(d),
            Err(e) => all_diagnostics.push(err_diagnostic("remote_authorized_keys_content", &e)),
        }

        // Remote sshd auth methods
        let check = RemoteSshdAuthMethodsCheck { host, port, proxy_jump };
        match check.run_check().await {
            Ok(d) => all_diagnostics.extend(d),
            Err(e) => all_diagnostics.push(err_diagnostic("remote_sshd_auth_methods", &e)),
        }

        // Remote AuthorizedKeysCommand
        let check = RemoteAuthorizedKeysCommandCheck { host, port, proxy_jump };
        match check.run_check().await {
            Ok(d) => all_diagnostics.extend(d),
            Err(e) => all_diagnostics.push(err_diagnostic("remote_authorized_keys_command", &e)),
        }

        // Remote StrictModes
        let check = RemoteStrictModesCheck { host, port, proxy_jump };
        match check.run_check().await {
            Ok(d) => all_diagnostics.extend(d),
            Err(e) => all_diagnostics.push(err_diagnostic("remote_strict_modes", &e)),
        }

        // Remote sshd full config
        let check = RemoteSshdFullConfigCheck { host, port, proxy_jump };
        match check.run_check().await {
            Ok(d) => all_diagnostics.extend(d),
            Err(e) => all_diagnostics.push(err_diagnostic("remote_sshd_full_config", &e)),
        }

        // Remote AuthorizedPrincipalsFile
        let check = RemoteAuthorizedPrincipalsFileCheck { host, port, proxy_jump };
        match check.run_check().await {
            Ok(d) => all_diagnostics.extend(d),
            Err(e) => all_diagnostics.push(err_diagnostic("remote_authorized_principals_file", &e)),
        }

        // Remote SSH logs hint
        let check = RemoteLogsHintCheck { host, port, proxy_jump };
        match check.run_check().await {
            Ok(d) => all_diagnostics.extend(d),
            Err(e) => all_diagnostics.push(err_diagnostic("remote_logs_hint", &e)),
        }
    } else {
        let skipped = [
            "agent_forwarding",
            "remote_home",
            "remote_pubkey_auth",
            "remote_permissions",
            "remote_authorized_keys",
            "remote_sshd_config",
            "remote_authorized_keys_content",
            "remote_sshd_auth_methods",
            "remote_authorized_keys_command",
            "remote_strict_modes",
            "remote_sshd_full_config",
            "remote_authorized_principals_file",
            "remote_logs_hint",
        ];
        for id in skipped {
            all_diagnostics.push(Diagnostic {
                id,
                severity: Severity::Info,
                message: format!("Skipped {id} check: host is not reachable"),
                hint: None,
                module: "remote",
            });
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_sshd_setting_pubkey_authentication() {
        let config = "port 22\npubkeyauthentication yes\nhostbasedauthentication no\n";
        assert_eq!(
            find_sshd_setting(config, "pubkeyauthentication"),
            Some("yes".to_owned())
        );
    }

    #[test]
    fn find_sshd_setting_password_authentication_disabled() {
        let config = "passwordauthentication no\npubkeyauthentication yes\n";
        assert_eq!(
            find_sshd_setting(config, "passwordauthentication"),
            Some("no".to_owned())
        );
    }

    #[test]
    fn find_sshd_setting_kbd_interactive() {
        let config = "kbdinteractiveauthentication yes\n";
        assert_eq!(
            find_sshd_setting(config, "kbdinteractiveauthentication"),
            Some("yes".to_owned())
        );
    }

    #[test]
    fn find_sshd_setting_gssapi_authentication() {
        let config = "gssapiauthentication no\n";
        assert_eq!(
            find_sshd_setting(config, "gssapiauthentication"),
            Some("no".to_owned())
        );
    }

    #[test]
    fn find_sshd_setting_hostbased_authentication() {
        let config = "hostbasedauthentication no\n";
        assert_eq!(
            find_sshd_setting(config, "hostbasedauthentication"),
            Some("no".to_owned())
        );
    }

    #[test]
    fn find_sshd_setting_missing_returns_none() {
        let config = "port 22\n";
        assert_eq!(find_sshd_setting(config, "passwordauthentication"), None);
    }

    #[test]
    fn find_sshd_setting_max_auth_tries() {
        let config = "maxauthtries 6\nport 22\n";
        assert_eq!(
            find_sshd_setting(config, "maxauthtries"),
            Some("6".to_owned())
        );
    }

    #[test]
    fn find_sshd_setting_trusted_user_ca_keys() {
        let config = "trustedusercakeys /etc/ssh/trusted-user-ca-keys.pem\nport 22\n";
        assert_eq!(
            find_sshd_setting(config, "trustedusercakeys"),
            Some("/etc/ssh/trusted-user-ca-keys.pem".to_owned())
        );
    }

    #[test]
    fn find_sshd_setting_authentication_methods() {
        let config = "authenticationmethods publickey,keyboard-interactive\n";
        assert_eq!(
            find_sshd_setting(config, "authenticationmethods"),
            Some("publickey,keyboard-interactive".to_owned())
        );
    }

    #[test]
    fn find_sshd_setting_permit_root_login() {
        let config = "permitrootlogin prohibit-password\n";
        assert_eq!(
            find_sshd_setting(config, "permitrootlogin"),
            Some("prohibit-password".to_owned())
        );
    }

    #[test]
    fn find_sshd_setting_authorized_keys_file() {
        let config = "authorizedkeysfile .ssh/authorized_keys .ssh/authorized_keys2\n";
        assert_eq!(
            find_sshd_setting(config, "authorizedkeysfile"),
            Some(".ssh/authorized_keys .ssh/authorized_keys2".to_owned())
        );
    }

    #[test]
    fn find_sshd_setting_empty_config() {
        assert_eq!(find_sshd_setting("", "pubkeyauthentication"), None);
    }

    #[test]
    fn find_sshd_setting_partial_key_no_match() {
        let config = "pubkeyauthentication yes\n";
        assert_eq!(find_sshd_setting(config, "pubkeyauth"), None);
    }

    #[test]
    fn find_sshd_setting_tab_separated() {
        let config = "passwordauthentication\tyes\n";
        assert_eq!(
            find_sshd_setting(config, "passwordauthentication"),
            Some("yes".to_owned())
        );
    }

    #[test]
    fn find_sshd_setting_all_auth_methods_combined() {
        let config = "\
port 22
pubkeyauthentication yes
passwordauthentication no
kbdinteractiveauthentication no
gssapiauthentication no
hostbasedauthentication no
maxauthtries 6
authenticationmethods any
trustedusercakeys /etc/ssh/ca.pub
";
        assert_eq!(find_sshd_setting(config, "pubkeyauthentication"), Some("yes".into()));
        assert_eq!(find_sshd_setting(config, "passwordauthentication"), Some("no".into()));
        assert_eq!(find_sshd_setting(config, "kbdinteractiveauthentication"), Some("no".into()));
        assert_eq!(find_sshd_setting(config, "gssapiauthentication"), Some("no".into()));
        assert_eq!(find_sshd_setting(config, "hostbasedauthentication"), Some("no".into()));
        assert_eq!(find_sshd_setting(config, "maxauthtries"), Some("6".into()));
        assert_eq!(find_sshd_setting(config, "authenticationmethods"), Some("any".into()));
        assert_eq!(find_sshd_setting(config, "trustedusercakeys"), Some("/etc/ssh/ca.pub".into()));
    }

    #[test]
    fn ssh_copy_id_command_construction() {
        use std::path::Path;
        let pubkey = Path::new("/home/user/.ssh/id_ed25519.pub");
        let dest = "user@example.com";
        let pubkey_str = pubkey.to_str().unwrap();
        let args = vec!["-i", pubkey_str, dest];
        assert_eq!(args[0], "-i");
        assert_eq!(args[1], "/home/user/.ssh/id_ed25519.pub");
        assert_eq!(args[2], "user@example.com");
    }

    #[test]
    fn ssh_copy_id_manual_fallback_command() {
        let pubkey_path = "~/.ssh/id_ed25519.pub";
        let host = "user@example.com";
        let manual_cmd = format!(
            "cat {} | ssh {} \"mkdir -p ~/.ssh && cat >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys\"",
            pubkey_path, host
        );
        assert!(manual_cmd.contains("cat"));
        assert!(manual_cmd.contains("ssh"));
        assert!(manual_cmd.contains("authorized_keys"));
        assert!(manual_cmd.contains("chmod 600"));
    }

    #[test]
    fn find_sshd_setting_authorized_principals_file() {
        let config = "authorizedprincipalsfile /etc/ssh/authorized_principals\n";
        assert_eq!(
            find_sshd_setting(config, "authorizedprincipalsfile"),
            Some("/etc/ssh/authorized_principals".to_owned())
        );
    }

    #[test]
    fn find_sshd_setting_authorized_principals_file_none() {
        let config = "authorizedprincipalsfile none\n";
        assert_eq!(
            find_sshd_setting(config, "authorizedprincipalsfile"),
            Some("none".to_owned())
        );
    }

    // -----------------------------------------------------------------------
    // extract_key_type / extract_key_data tests
    // -----------------------------------------------------------------------

    #[test]
    fn extract_key_type_ed25519() {
        let line = "example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGrS...";
        assert_eq!(extract_key_type(line), Some("ssh-ed25519"));
    }

    #[test]
    fn extract_key_type_rsa() {
        let line = "example.com ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC...";
        assert_eq!(extract_key_type(line), Some("ssh-rsa"));
    }

    #[test]
    fn extract_key_type_ecdsa() {
        let line = "example.com ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYT...";
        assert_eq!(extract_key_type(line), Some("ecdsa-sha2-nistp256"));
    }

    #[test]
    fn extract_key_type_with_port() {
        let line = "[example.com]:2222 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI...";
        assert_eq!(extract_key_type(line), Some("ssh-ed25519"));
    }

    #[test]
    fn extract_key_type_with_comment() {
        let line = "example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGrS user@host";
        assert_eq!(extract_key_type(line), Some("ssh-ed25519"));
    }

    #[test]
    fn extract_key_type_empty_line() {
        assert_eq!(extract_key_type(""), None);
    }

    #[test]
    fn extract_key_type_single_field() {
        assert_eq!(extract_key_type("example.com"), None);
    }

    #[test]
    fn extract_key_data_ed25519() {
        let line = "example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGrS";
        assert_eq!(extract_key_data(line), "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGrS");
    }

    #[test]
    fn extract_key_data_with_comment() {
        let line = "example.com ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC user@host";
        assert_eq!(extract_key_data(line), "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC");
    }

    #[test]
    fn extract_key_data_with_port() {
        let line = "[example.com]:2222 ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYT";
        assert_eq!(extract_key_data(line), "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYT");
    }

    #[test]
    fn extract_key_data_matching_keys_different_hosts() {
        // Same key data on two different host entries should compare equal.
        let line1 = "host-a.example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGrS";
        let line2 = "host-b.example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGrS";
        assert_eq!(extract_key_data(line1), extract_key_data(line2));
    }

    #[test]
    fn extract_key_data_mismatching_keys() {
        let line1 = "example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGrS";
        let line2 = "example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDifferent";
        assert_ne!(extract_key_data(line1), extract_key_data(line2));
    }

    #[test]
    fn extract_key_data_different_types_same_host() {
        let line1 = "example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGrS";
        let line2 = "example.com ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC";
        assert_ne!(extract_key_data(line1), extract_key_data(line2));
    }

    // -----------------------------------------------------------------------
    // parse_host_port tests
    // -----------------------------------------------------------------------

    #[test]
    fn parse_host_port_bare_hostname() {
        assert_eq!(parse_host_port("example.com"), ("example.com", None));
    }

    #[test]
    fn parse_host_port_standard_port() {
        // Port 22 is the default and should be stripped.
        assert_eq!(parse_host_port("example.com:22"), ("example.com", None));
    }

    #[test]
    fn parse_host_port_nonstandard_port() {
        assert_eq!(
            parse_host_port("example.com:2222"),
            ("example.com", Some(2222))
        );
    }

    #[test]
    fn parse_host_port_bracketed_with_port() {
        assert_eq!(
            parse_host_port("[example.com]:2222"),
            ("example.com", Some(2222))
        );
    }

    #[test]
    fn parse_host_port_bracketed_standard_port() {
        assert_eq!(
            parse_host_port("[example.com]:22"),
            ("example.com", None)
        );
    }

    #[test]
    fn parse_host_port_user_at_host_with_port() {
        assert_eq!(
            parse_host_port("user@host:2222"),
            ("user@host", Some(2222))
        );
    }

    #[test]
    fn parse_host_port_ipv6_bare() {
        // An IPv6 address without brackets should not be parsed as host:port.
        assert_eq!(parse_host_port("::1"), ("::1", None));
    }

    #[test]
    fn parse_host_port_ipv6_bracketed_with_port() {
        assert_eq!(
            parse_host_port("[::1]:2222"),
            ("::1", Some(2222))
        );
    }

    #[test]
    fn parse_host_port_bracketed_without_port() {
        assert_eq!(
            parse_host_port("[example.com]"),
            ("example.com", None)
        );
    }

    #[test]
    fn parse_host_port_invalid_port_number() {
        // "notaport" is not a valid u16, so the whole string is the host.
        assert_eq!(
            parse_host_port("example.com:notaport"),
            ("example.com:notaport", None)
        );
    }

    #[test]
    fn parse_host_port_large_port_number() {
        // Port 99999 exceeds u16::MAX (65535), so the whole string is the host.
        assert_eq!(
            parse_host_port("example.com:99999"),
            ("example.com:99999", None)
        );
    }

    #[test]
    fn parse_host_port_no_host() {
        // ":2222" has an empty host part — the port is still parsed.
        assert_eq!(parse_host_port(":2222"), ("", Some(2222)));
    }

    // -----------------------------------------------------------------------
    // known_hosts_host tests
    // -----------------------------------------------------------------------

    #[test]
    fn known_hosts_host_standard_port() {
        assert_eq!(known_hosts_host("example.com", None), "example.com");
    }

    #[test]
    fn known_hosts_host_nonstandard_port() {
        assert_eq!(
            known_hosts_host("example.com", Some(2222)),
            "[example.com]:2222"
        );
    }

    // -----------------------------------------------------------------------
    // ssh_connect_args tests
    // -----------------------------------------------------------------------

    #[test]
    fn ssh_connect_args_no_port() {
        let args = ssh_connect_args(None, None);
        assert_eq!(args.len(), 6);
        assert_eq!(args[0], "-o");
        assert_eq!(args[1], "BatchMode=yes");
        assert_eq!(args[2], "-o");
        assert_eq!(args[3], "ConnectTimeout=5");
        assert_eq!(args[4], "-o");
        assert_eq!(args[5], "StrictHostKeyChecking=accept-new");
    }

    #[test]
    fn ssh_connect_args_with_port() {
        let args = ssh_connect_args(Some(2222), None);
        assert_eq!(args.len(), 8);
        assert_eq!(args[0], "-o");
        assert_eq!(args[1], "BatchMode=yes");
        assert_eq!(args[2], "-o");
        assert_eq!(args[3], "ConnectTimeout=5");
        assert_eq!(args[4], "-o");
        assert_eq!(args[5], "StrictHostKeyChecking=accept-new");
        assert_eq!(args[6], "-p");
        assert_eq!(args[7], "2222");
    }

    #[test]
    fn ssh_connect_args_with_proxy_jump() {
        let args = ssh_connect_args(None, Some("jump.example.com"));
        assert_eq!(args.len(), 8);
        assert_eq!(args[0], "-o");
        assert_eq!(args[1], "BatchMode=yes");
        assert_eq!(args[2], "-o");
        assert_eq!(args[3], "ConnectTimeout=5");
        assert_eq!(args[4], "-o");
        assert_eq!(args[5], "StrictHostKeyChecking=accept-new");
        assert_eq!(args[6], "-J");
        assert_eq!(args[7], "jump.example.com");
    }

    #[test]
    fn ssh_connect_args_with_port_and_proxy_jump() {
        let args = ssh_connect_args(Some(2222), Some("jump.example.com"));
        assert_eq!(args.len(), 10);
        assert_eq!(args[0], "-o");
        assert_eq!(args[1], "BatchMode=yes");
        assert_eq!(args[2], "-o");
        assert_eq!(args[3], "ConnectTimeout=5");
        assert_eq!(args[4], "-o");
        assert_eq!(args[5], "StrictHostKeyChecking=accept-new");
        assert_eq!(args[6], "-p");
        assert_eq!(args[7], "2222");
        assert_eq!(args[8], "-J");
        assert_eq!(args[9], "jump.example.com");
    }

    #[test]
    fn ssh_connect_args_with_chained_proxy_jump() {
        let args = ssh_connect_args(None, Some("jump1.example.com,jump2.example.com"));
        assert_eq!(args.len(), 8);
        assert_eq!(args[6], "-J");
        assert_eq!(args[7], "jump1.example.com,jump2.example.com");
    }

    #[test]
    fn ssh_connect_args_with_user_at_jump_host() {
        let args = ssh_connect_args(None, Some("admin@jump.example.com"));
        assert_eq!(args.len(), 8);
        assert_eq!(args[6], "-J");
        assert_eq!(args[7], "admin@jump.example.com");
    }
}
