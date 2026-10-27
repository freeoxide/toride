//! Known-hosts file parsing and host-key change detection.
//!
//! Reads and parses `~/.ssh/known_hosts` entries, scans remote hosts via
//! `ssh-keyscan`, and compares the two to detect key changes. Provides
//! [`KnownHostsService`], [`KnownHostEntry`], [`ScannedHostKey`], and
//! [`HostKeyChangeReport`] for diagnostics and trust management.

mod parse;
mod scan;

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use toride_ssh_core::SshPaths;
use toride_ssh_core::{Error, Result};

/// A single entry parsed from a `known_hosts` file.
pub use parse::KnownHostEntry;
/// A host key discovered by `ssh-keyscan`.
pub use scan::ScannedHostKey;

/// Report from host key change detection.
///
/// Returned by [`KnownHostsService::check_host_key_change`].  Compares the
/// keys a host currently presents (via `ssh-keyscan`) against the keys stored
/// in `known_hosts`.
#[derive(Debug, Clone)]
pub struct HostKeyChangeReport {
    /// The host that was checked.
    pub host: String,
    /// Whether any key change was detected.
    pub changed: bool,
    /// Entries stored in `known_hosts` for this host.
    pub stored_keys: Vec<KnownHostEntry>,
    /// Keys discovered by scanning the host.
    pub scanned_keys: Vec<ScannedHostKey>,
    /// Specific key changes detected.
    pub changes: Vec<KeyChange>,
}

/// A specific host key change detected during comparison.
#[derive(Debug, Clone)]
pub struct KeyChange {
    /// The key type that changed (e.g. `"ssh-ed25519"`).
    pub key_type: String,
    /// What kind of change was detected.
    pub kind: KeyChangeKind,
}

/// The kind of host key change.
#[derive(Debug, Clone)]
pub enum KeyChangeKind {
    /// A new key type appeared that was not in `known_hosts`.
    New,
    /// A stored key type is no longer presented by the host.
    Removed,
    /// Same key type but a different public key blob.
    Changed {
        /// SHA-256 fingerprint of the stored key (if computable).
        stored_fingerprint: String,
        /// SHA-256 fingerprint of the scanned key (if computable).
        scanned_fingerprint: String,
    },
}

/// Status of the `VerifyHostKeyDNS` SSH config directive.
///
/// Returned by [`KnownHostsService::verify_host_key_dns_status`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DnsVerifyStatus {
    /// `VerifyHostKeyDNS yes`, SSHFP records will be used to verify host keys.
    Enabled,
    /// `VerifyHostKeyDNS no`, DNS-based host key verification disabled.
    Disabled,
    /// `VerifyHostKeyDNS ask`, verify via SSHFP but still prompt on mismatch.
    Ask,
    /// Directive not present in config (uses the OpenSSH default: `no`).
    Unknown,
}

impl std::fmt::Display for DnsVerifyStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Enabled => write!(f, "yes"),
            Self::Disabled => write!(f, "no"),
            Self::Ask => write!(f, "ask"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

/// A single SSHFP DNS resource record for an SSH host key.
///
/// SSHFP records allow DNS-based verification of SSH host keys. They can be
/// generated with `ssh-keygen -r <hostname>` and published in the DNS zone
/// for the host.
///
/// # Record format
///
/// `hostname IN SSHFP algorithm key-type fingerprint`
///
/// Where:
/// - **algorithm**: `1` = RSA, `2` = DSA, `3` = ECDSA, `4` = Ed25519
/// - **key-type**: `1` = SHA-1, `2` = SHA-256
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SshfpRecord {
    /// The hostname these SSHFP records belong to.
    pub host: String,
    /// SSH key algorithm number (1=RSA, 2=DSA, 3=ECDSA, 4=Ed25519).
    pub algorithm: String,
    /// Fingerprint type number (1=SHA-1, 2=SHA-256).
    pub key_type: String,
    /// Hex-encoded fingerprint digest.
    pub fingerprint: String,
}

/// `known_hosts` file management.
///
/// Obtained from `SshManager::known_hosts()`.
pub struct KnownHostsService<'a> {
    paths: &'a SshPaths,
    runner: &'a dyn toride_ssh_core::CliRunner,
}

impl<'a> KnownHostsService<'a> {
    pub fn new(paths: &'a SshPaths, runner: &'a dyn toride_ssh_core::CliRunner) -> Self {
        Self { paths, runner }
    }

    /// List all known host entries.
    ///
    /// Parses `~/.ssh/known_hosts` and returns every entry found.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] if the file cannot be read, or
    /// [`Error::KnownHostsParseFailed`] if parsing fails.
    pub async fn list(&self) -> Result<Vec<KnownHostEntry>> {
        parse::parse_known_hosts(self.paths.known_hosts_path()).await
    }

    /// Scan a remote host for its public host keys.
    ///
    /// Runs `ssh-keyscan <host>` and returns the keys discovered with the
    /// plaintext hostname.  Keys are **not** added to `known_hosts`; call
    /// [`add`](Self::add) for that.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ToolNotFound`] if `ssh-keyscan` is not in `PATH`,
    /// or [`Error::CommandFailed`] if the scan fails.
    pub async fn scan(&self, host: &str) -> Result<Vec<ScannedHostKey>> {
        scan::scan_host(host, self.runner).await
    }

    /// Scan a host and add all its keys to `~/.ssh/known_hosts`.
    ///
    /// Uses `ssh-keyscan -H <host>` so that hostnames are stored in hashed
    /// form for privacy.  All keys for the host are written in a single
    /// I/O operation.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ToolNotFound`] if `ssh-keyscan` is not in `PATH`,
    /// [`Error::CommandFailed`] if scanning fails, or [`Error::Io`] if
    /// writing to the `known_hosts` file fails.
    pub async fn add(&self, host: &str) -> Result<()> {
        scan::add_host_hashed(self.paths.known_hosts_path(), host, self.runner).await
    }

    /// Remove all entries matching the given host from `~/.ssh/known_hosts`.
    ///
    /// Entries whose hostname patterns list contains an exact match for `host`
    /// are removed, including hashed entries (`|1|...`), which are matched by
    /// verifying the entry's HMAC against `host`.
    ///
    /// The removal is performed atomically (write to a temp file, then rename)
    /// so that a crash mid-write cannot corrupt the file.
    ///
    /// # Errors
    ///
    /// Returns [`Error::HostNotKnown`] if no entries match the given host,
    /// [`Error::TaskFailed`] if the background task panics, or
    /// [`Error::Io`] if file operations fail.
    pub async fn remove(&self, host: &str) -> Result<()> {
        // Allocate an owned PathBuf for use inside `spawn_blocking` (requires `'static`).
        let path = self.paths.known_hosts_path().to_path_buf();
        let host = host.to_owned();

        tokio::task::spawn_blocking(move || remove_host_sync(&path, &host))
            .await
            .map_err(|e| Error::TaskFailed(e.to_string()))?
    }

    /// Check whether a host appears in `~/.ssh/known_hosts`.
    ///
    /// Returns `true` if any entry's host pattern list contains an exact match.
    /// Both plain and bracketed (`[host]:port`) forms are checked. Hashed
    /// entries (`|1|...`) are matched by verifying the entry's HMAC against
    /// the hostname.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] or [`Error::KnownHostsParseFailed`] if the
    /// `known_hosts` file cannot be read or parsed.
    pub async fn contains(&self, host: &str) -> Result<bool> {
        let entries = self.list().await?;
        Ok(entries
            .iter()
            .any(|e| e.hosts.iter().any(|h| host_pattern_matches(h, host))))
    }

    /// Check if `UpdateHostKeys` is configured in `~/.ssh/config`.
    ///
    /// The SSH `UpdateHostKeys` directive (when set to `yes`) tells the client
    /// to automatically update `known_hosts` when the server presents new host
    /// key types.  This improves forward security by allowing servers to
    /// rotate their host keys without manual intervention.
    ///
    /// # Limitations
    ///
    /// toride does **not** currently support the `UpdateHostKeys` protocol
    /// extension.  This method detects the configuration setting so that
    /// callers can warn the user.  Future versions could implement the
    /// RFC 4252 / OpenSSH host key update protocol.
    ///
    /// Returns `true` if `UpdateHostKeys yes` appears in the config (either
    /// at top level or in any `Host` block), `false` otherwise.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] if the config file cannot be read.
    pub async fn is_update_host_keys_enabled(&self) -> Result<bool> {
        let config_path = self.paths.config_path();
        if !config_path.exists() {
            return Ok(false);
        }

        let content = tokio::fs::read_to_string(config_path).await?;

        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with('#') || trimmed.is_empty() {
                continue;
            }

            if let Some(value) = config_directive_value(trimmed, "UpdateHostKeys")
                && value.eq_ignore_ascii_case("yes")
            {
                tracing::info!(
                    "UpdateHostKeys yes found in SSH config: \
                     this feature is not yet supported by toride"
                );
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Detect the `VerifyHostKeyDNS` setting from `~/.ssh/config`.
    ///
    /// Scans the SSH config file (both global directives and `Host` blocks)
    /// for the `VerifyHostKeyDNS` directive and returns the configured mode.
    /// If the directive is not found, returns [`DnsVerifyStatus::Unknown`].
    ///
    /// This performs a lightweight config scan, it does **not** follow
    /// `Include` chains or evaluate `Match` blocks.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] if the config file exists but cannot be read.
    pub async fn verify_host_key_dns_status(&self) -> Result<DnsVerifyStatus> {
        let config_path = self.paths.config_path();
        if !config_path.exists() {
            return Ok(DnsVerifyStatus::Unknown);
        }

        let content = tokio::fs::read_to_string(config_path).await?;

        Ok(detect_verify_host_key_dns(&content))
    }

    /// Generate SSHFP DNS resource records for a host's keys.
    ///
    /// Runs `ssh-keygen -r <hostname>` to produce SSHFP records that can be
    /// published in DNS. The output format is:
    ///
    /// ```text
    /// hostname IN SSHFP algorithm key-type fingerprint
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`Error::ToolNotFound`] if `ssh-keygen` is not in `PATH`,
    /// [`Error::CommandFailed`] if `ssh-keygen -r` fails, or
    /// [`Error::CommandParseFailed`] if the output cannot be parsed.
    pub async fn generate_sshfp_records(&self, host: &str) -> Result<Vec<SshfpRecord>> {
        let host_owned = host.to_owned();
        let output = self
            .runner
            .run("ssh-keygen", vec!["-r".to_owned(), host_owned])
            .await?;

        Ok(parse_sshfp_output(host, &output))
    }

    /// Hash all hostnames in `~/.ssh/known_hosts` (`ssh-keygen -H`).
    ///
    /// This replaces plaintext hostnames with salted hashes for privacy.
    /// The file is modified in-place by `ssh-keygen`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ToolNotFound`] if `ssh-keygen` is not in `PATH`,
    /// [`Error::CommandFailed`] if hashing fails, or
    /// [`Error::TaskFailed`] if the background task panics.
    pub async fn hash_all(&self) -> Result<()> {
        let path_str = self
            .paths
            .known_hosts_path()
            .to_str()
            .ok_or_else(|| Error::CommandFailed("known_hosts path is not valid UTF-8".into()))?
            .to_owned();

        self.runner
            .run(
                "ssh-keygen",
                vec!["-H".to_owned(), "-f".to_owned(), path_str],
            )
            .await?;
        Ok(())
    }

    /// Find all `known_hosts` entries matching the given host.
    ///
    /// Uses `ssh-keygen -F <host>` which can match **hashed** hostnames
    /// (something the pure-text [`contains`](Self::contains) method cannot
    /// do).  Both the user `known_hosts` file and the global known hosts file
    /// (`/etc/ssh/ssh_known_hosts`) are searched.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ToolNotFound`] if `ssh-keygen` is not in `PATH`.
    /// A missing `known_hosts` file is treated as "no entries" rather than an
    /// error.
    pub async fn find(&self, host: &str) -> Result<Vec<KnownHostEntry>> {
        let mut entries = Vec::new();

        // 1. User known_hosts (or UserKnownHostsFile from config).
        let user_path = self.resolve_user_known_hosts_file(host).await?;
        entries.extend(self.find_in_file(host, &user_path).await?);

        // 2. Global known hosts.
        let global_path = self.paths.global_known_hosts_path();
        if global_path.exists() {
            entries.extend(self.find_in_file(host, global_path).await?);
        }

        Ok(entries)
    }

    /// Search a specific `known_hosts` file for entries matching `host`.
    ///
    /// Runs `ssh-keygen -F <host> -f <file>` and parses the output.  A
    /// missing file returns an empty vec (not an error).
    ///
    /// A genuine "host not present" result (ssh-keygen exits with code 1 and
    /// no matches) also returns an empty vec.  Any *other* failure, the
    /// `ssh-keygen` binary missing from `PATH`, a permission error, a panic
    /// in the runner task, or an unexpected non-unit exit code, is
    /// propagated as `Err` so callers can distinguish "absent" from
    /// "something went wrong".
    async fn find_in_file(&self, host: &str, path: &Path) -> Result<Vec<KnownHostEntry>> {
        if !path.exists() {
            return Ok(Vec::new());
        }

        let path_str = path
            .to_str()
            .ok_or_else(|| Error::CommandFailed("known_hosts path is not valid UTF-8".into()))?
            .to_owned();

        let host_owned = host.to_owned();
        let args = vec!["-F".to_owned(), host_owned, "-f".to_owned(), path_str];

        // ssh-keygen -F returns exit code 1 when the host is not found ,
        // that is a normal result, not an error.  Any other failure
        // (binary missing, permission denied, runner task panic, …) must be
        // surfaced so the caller can tell an absent host apart from a
        // broken lookup.
        match self.runner.run("ssh-keygen", args).await {
            Ok(raw) => Ok(parse_ssh_keygen_f_output(host, &raw)),
            Err(e) if is_host_not_found(&e) => Ok(Vec::new()),
            Err(e) => Err(e),
        }
    }

    /// List entries from the global known hosts file (`/etc/ssh/ssh_known_hosts`).
    ///
    /// Returns an empty vec if the file does not exist.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] if the file exists but cannot be read, or
    /// [`Error::KnownHostsParseFailed`] if parsing fails.
    pub async fn list_global(&self) -> Result<Vec<KnownHostEntry>> {
        let path = self.paths.global_known_hosts_path();
        if !path.exists() {
            return Ok(Vec::new());
        }
        parse::parse_known_hosts(path).await
    }

    /// List entries from **all** known hosts files.
    ///
    /// Merges entries from:
    /// 1. The user `known_hosts` file (or `UserKnownHostsFile` from config).
    /// 2. The global known hosts file (`/etc/ssh/ssh_known_hosts`).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] if any file cannot be read, or
    /// [`Error::KnownHostsParseFailed`] if parsing fails.
    pub async fn list_all(&self) -> Result<Vec<KnownHostEntry>> {
        let mut entries = self.list().await?;
        entries.extend(self.list_global().await?);
        Ok(entries)
    }

    /// Scan a host and compare its keys with what is stored in `known_hosts`.
    ///
    /// Returns a [`HostKeyChangeReport`] describing any differences:
    /// - **New** key types that the host presents but are not stored.
    /// - **Removed** key types that are stored but the host no longer presents.
    /// - **Changed** key types where the type matches but the public key blob
    ///   differs.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ToolNotFound`] if `ssh-keyscan` or `ssh-keygen` is
    /// not in `PATH`, or [`Error::CommandFailed`] if scanning fails.
    pub async fn check_host_key_change(&self, host: &str) -> Result<HostKeyChangeReport> {
        let scanned = self.scan(host).await?;
        let stored = self.find(host).await?;
        let changes = compare_host_keys(&stored, &scanned);

        Ok(HostKeyChangeReport {
            host: host.to_owned(),
            changed: !changes.is_empty(),
            stored_keys: stored,
            scanned_keys: scanned,
            changes,
        })
    }

    /// Resolve the `UserKnownHostsFile` directive from `~/.ssh/config` for
    /// the given host.
    ///
    /// If the directive is set in a matching `Host` block, returns the
    /// configured path (with `~` expanded).  If set to `"none"`, returns
    /// `None`.  Otherwise returns the default `~/.ssh/known_hosts`.
    ///
    /// This performs a lightweight config scan, it does **not** follow
    /// `Include` chains or evaluate `Match` blocks.  For full config
    /// resolution use `ConfigService::resolve_host`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] if the config file exists but cannot be read.
    pub async fn resolve_user_known_hosts_file(&self, host: &str) -> Result<PathBuf> {
        let config_path = self.paths.config_path();
        if !config_path.exists() {
            return Ok(self.paths.known_hosts_path().to_path_buf());
        }

        let content = tokio::fs::read_to_string(config_path).await?;

        if let Some(raw) = find_user_known_hosts_file_in_config(&content, host) {
            if raw.eq_ignore_ascii_case("none") {
                // "none" means no user known_hosts file, return a path that
                // will never exist so callers get an empty result.
                return Ok(PathBuf::from("/dev/null"));
            }
            return Ok(expand_known_hosts_path(&raw));
        }

        Ok(self.paths.known_hosts_path().to_path_buf())
    }
}

/// Classify an [`Error`] from `ssh-keygen -F` as a genuine "host not found".
///
/// `ssh-keygen -F <host>` exits with code 1 (and prints nothing to stdout)
/// when the host is absent from the file.  This is a *normal* outcome and
/// must be reported as an empty result rather than an error.
///
/// The [`CliRunner`](toride_ssh_core::CliRunner) trait abstracts away the raw
/// exit code, so the only signal available is the [`Error::CommandFailed`]
/// message, which the production runner formats as
/// `` `command `ssh-keygen` failed with exit Some(1): … ``.  We therefore
/// match exit code 1 inside that message.  Everything else, a missing
/// binary (also surfaced as `CommandFailed`), a `TaskFailed`, a
/// `PermissionDenied`, or a non-unit exit code, is treated as a real error
/// and propagated.
fn is_host_not_found(error: &Error) -> bool {
    let Error::CommandFailed(msg) = error else {
        return false;
    };
    // The production runner formats the exit code as `exit Some(N)` /
    // `exit None` (Debug of Option<i32>).  Exit code 1 = host not found.
    msg.contains("exit Some(1)") || msg.contains("exit status: 1")
}

/// Parse `ssh-keygen -F` output into [`KnownHostEntry`] values.
///
/// The output contains comment lines (starting with `#`) that indicate where
/// each match was found, followed by the entry line in standard `known_hosts`
/// format.  This function skips the comments and parses the entry lines.
fn parse_ssh_keygen_f_output(host: &str, raw: &str) -> Vec<KnownHostEntry> {
    let mut entries = Vec::new();
    let mut line_number = 0usize;

    for raw_line in raw.lines() {
        let trimmed = raw_line.trim();

        // Extract line number from the comment if available.
        if trimmed.starts_with('#') {
            if let Some(rest) = trimmed.strip_prefix("# Host ")
                && let Some(pos) = rest.find("found: line ")
            {
                let num_str = &rest[pos + "found: line ".len()..];
                line_number = num_str.trim().parse().unwrap_or(0);
            }
            continue;
        }

        if trimmed.is_empty() {
            continue;
        }

        match parse::parse_line(trimmed, line_number) {
            Ok(entry) => entries.push(entry),
            Err(e) => {
                tracing::warn!(
                    host,
                    error = %e,
                    "skipping unparseable ssh-keygen -F output line"
                );
            }
        }
    }

    entries
}

/// Compare stored and scanned host keys, returning a list of changes.
///
/// Entries carrying a marker (`@cert-authority`, `@revoked`) are not host
/// keys and are excluded from the comparison, so a CA line never triggers
/// a false change. Multiple entries of one key type are compared
/// per-entry: a scanned key matches when any stored entry of the same
/// type carries the same blob.
fn compare_host_keys(stored: &[KnownHostEntry], scanned: &[ScannedHostKey]) -> Vec<KeyChange> {
    let mut changes = Vec::new();

    for scanned_key in scanned {
        let key_type = scanned_key.key_type.as_str();
        let same_type: Vec<&KnownHostEntry> = stored
            .iter()
            .filter(|e| e.markers.is_empty() && e.key_type == key_type)
            .collect();

        if same_type.is_empty() {
            changes.push(KeyChange {
                key_type: key_type.to_owned(),
                kind: KeyChangeKind::New,
            });
            continue;
        }

        if same_type
            .iter()
            .any(|e| e.public_key == scanned_key.public_key)
        {
            continue;
        }

        let stored_key = same_type[0];
        let stored_fp = match parse::compute_key_fingerprint(&stored_key.public_key, key_type) {
            Ok(fp) => fp.to_string(),
            Err(_) => "(unavailable)".to_owned(),
        };
        let scanned_fp = match parse::compute_key_fingerprint(&scanned_key.public_key, key_type) {
            Ok(fp) => fp.to_string(),
            Err(_) => "(unavailable)".to_owned(),
        };
        changes.push(KeyChange {
            key_type: key_type.to_owned(),
            kind: KeyChangeKind::Changed {
                stored_fingerprint: stored_fp,
                scanned_fingerprint: scanned_fp,
            },
        });
    }

    for stored_entry in stored.iter().filter(|e| e.markers.is_empty()) {
        let key_type = stored_entry.key_type.as_str();
        if !scanned.iter().any(|s| s.key_type == key_type) {
            changes.push(KeyChange {
                key_type: key_type.to_owned(),
                kind: KeyChangeKind::Removed,
            });
        }
    }

    changes
}

/// Key types whose stored blob matched a scan, for callers that also
/// report healthy entries.
#[derive(Debug, Clone)]
pub struct HostKeyLinesComparison {
    /// Marker-free stored key types whose blob matched a scanned key.
    pub matched_types: Vec<String>,
    /// Detected changes (new, removed, changed).
    pub changes: Vec<KeyChange>,
}

/// Compare raw `known_hosts` lines (as printed by `ssh-keygen -F`) with
/// raw `ssh-keyscan` lines.
///
/// Both line sets are parsed with the crate's own parsers; unparseable
/// lines are skipped with a warning. Marker lines (`@cert-authority`,
/// `@revoked`) are excluded from the stored side, so certificate
/// authorities never surface as changed or removed host keys.
#[must_use]
pub fn compare_host_key_lines(
    stored_lines: &[String],
    scanned_lines: &[String],
) -> HostKeyLinesComparison {
    let stored: Vec<KnownHostEntry> = stored_lines
        .iter()
        .enumerate()
        .filter_map(|(idx, line)| {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                return None;
            }
            match parse::parse_line(trimmed, idx + 1) {
                Ok(entry) => Some(entry),
                Err(e) => {
                    tracing::warn!(line_number = idx + 1, error = %e, "skipping unparseable stored host key line");
                    None
                }
            }
        })
        .collect();
    let scanned: Vec<ScannedHostKey> = scanned_lines
        .iter()
        .filter_map(|line| match scan::parse_keyscan_line("", line.trim()) {
            Ok(key) => Some(key),
            Err(e) => {
                tracing::warn!(line = %line, error = %e, "skipping unparseable scanned host key line");
                None
            }
        })
        .collect();

    let changes = compare_host_keys(&stored, &scanned);

    let mut matched_types: Vec<String> = stored
        .iter()
        .filter(|e| e.markers.is_empty())
        .filter(|e| {
            scanned
                .iter()
                .any(|s| s.key_type == e.key_type && s.public_key == e.public_key)
        })
        .map(|e| e.key_type.clone())
        .collect();
    matched_types.sort();
    matched_types.dedup();

    HostKeyLinesComparison {
        matched_types,
        changes,
    }
}

/// Extract the value of `keyword` from a trimmed `ssh_config` line.
///
/// Matches the `keyword value`, `keyword<TAB>value`, and `keyword=value`
/// separators `ssh_config(5)` accepts, comparing the keyword
/// case-insensitively without allocating.
fn config_directive_value<'a>(trimmed: &'a str, keyword: &str) -> Option<&'a str> {
    if trimmed.len() <= keyword.len() {
        return None;
    }
    if !trimmed[..keyword.len()].eq_ignore_ascii_case(keyword) {
        return None;
    }
    let separator = trimmed.as_bytes()[keyword.len()];
    if separator != b' ' && separator != b'\t' && separator != b'=' {
        return None;
    }
    let rest = &trimmed[keyword.len() + 1..];
    let rest = rest.strip_prefix('=').unwrap_or(rest);
    Some(rest.trim_start_matches([' ', '\t']))
}

/// Scan SSH config for `UserKnownHostsFile` directive matching the given host.
///
/// Performs a lightweight scan: does not follow `Include` chains or `Match`
/// blocks.  Returns the raw directive value (may contain `~`).
fn find_user_known_hosts_file_in_config(config_content: &str, host: &str) -> Option<String> {
    let mut in_matching_block = false;
    let mut in_any_host_block = false;
    let mut global_value: Option<String> = None;
    let mut host_value: Option<String> = None;

    for line in config_content.lines() {
        let trimmed = line.trim();

        if trimmed.starts_with('#') || trimmed.is_empty() {
            continue;
        }

        if let Some(patterns_str) = config_directive_value(trimmed, "Host") {
            let patterns: Vec<&str> = patterns_str.split_whitespace().collect();
            in_any_host_block = true;
            in_matching_block = patterns
                .iter()
                .any(|p| *p == "*" || p.eq_ignore_ascii_case(host));
            continue;
        }

        if let Some(value) = config_directive_value(trimmed, "UserKnownHostsFile") {
            if in_matching_block && host_value.is_none() {
                host_value = Some(value.to_owned());
            } else if !in_any_host_block && global_value.is_none() {
                global_value = Some(value.to_owned());
            }
        }
    }

    host_value.or(global_value)
}

/// Expand a `UserKnownHostsFile` value to an absolute path.
///
/// Handles `~` expansion.  Relative paths are resolved against the current
/// directory (matching OpenSSH behaviour).
fn expand_known_hosts_path(raw: &str) -> PathBuf {
    if let Some(rest) = raw.strip_prefix("~/")
        && let Some(home) = dirs::home_dir()
    {
        return home.join(rest);
    } else if raw == "~"
        && let Some(home) = dirs::home_dir()
    {
        return home;
    }
    let path = Path::new(raw);
    if path.is_relative() {
        // Resolve relative to current directory.
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(path)
    } else {
        path.to_path_buf()
    }
}

/// Detect the `VerifyHostKeyDNS` setting from SSH config content.
///
/// Scans for the directive at both the global level and inside `Host`
/// blocks and returns the first recognized value. Accepts the
/// `keyword value`, `keyword<TAB>value`, and `keyword=value` separators
/// `ssh_config(5)` allows, comparing case-insensitively without
/// allocating a lowered copy of the line.
///
/// Shared scanner: `toride-ssh-doctor` routes its `VerifyHostKeyDNS`
/// check through this function instead of keeping a twin.
#[must_use]
pub fn detect_verify_host_key_dns(config_content: &str) -> DnsVerifyStatus {
    for line in config_content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') || trimmed.is_empty() {
            continue;
        }

        if let Some(value) = config_directive_value(trimmed, "VerifyHostKeyDNS") {
            if value.eq_ignore_ascii_case("yes") || value == "true" {
                return DnsVerifyStatus::Enabled;
            } else if value.eq_ignore_ascii_case("no") || value == "false" {
                return DnsVerifyStatus::Disabled;
            } else if value.eq_ignore_ascii_case("ask") {
                return DnsVerifyStatus::Ask;
            }
        }
    }

    DnsVerifyStatus::Unknown
}

/// Parse `ssh-keygen -r` output into a list of [`SshfpRecord`] values.
///
/// Expected line format:
/// ```text
/// hostname IN SSHFP algorithm key-type fingerprint
/// ```
///
/// Lines that do not match this format are silently skipped.
fn parse_sshfp_output(host: &str, output: &str) -> Vec<SshfpRecord> {
    let mut records = Vec::new();

    for line in output.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        // Expected: hostname IN SSHFP algorithm key-type fingerprint
        if parts.len() >= 6
            && parts.get(1).is_some_and(|p| p.eq_ignore_ascii_case("IN"))
            && parts
                .get(2)
                .is_some_and(|p| p.eq_ignore_ascii_case("SSHFP"))
        {
            let Some(algorithm) = parts.get(3) else {
                continue;
            };
            let Some(key_type) = parts.get(4) else {
                continue;
            };
            let Some(fingerprint) = parts.get(5) else {
                continue;
            };

            records.push(SshfpRecord {
                host: host.to_owned(),
                algorithm: (*algorithm).to_owned(),
                key_type: (*key_type).to_owned(),
                fingerprint: (*fingerprint).to_owned(),
            });
        }
    }

    records
}

/// Generate a short random hex suffix for unique temp file names.
///
/// Uses a simple counter + timestamp mix to avoid importing a full RNG crate.
/// Good enough for temp file uniqueness within a single process.
fn rand_suffix() -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    std::time::Instant::now().hash(&mut hasher);
    std::process::id().hash(&mut hasher);
    hasher.finish()
}

/// Synchronous helper: read the file, filter out matching entries, write back
/// atomically via a temp file + rename.
fn remove_host_sync(path: &Path, host: &str) -> Result<()> {
    let contents = std::fs::read_to_string(path)?;

    let mut kept = String::with_capacity(contents.len());
    let mut removed_any = false;

    for raw_line in contents.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            kept.push_str(raw_line);
            kept.push('\n');
            continue;
        }

        if line_matches_host(line, host) {
            removed_any = true;
        } else {
            kept.push_str(raw_line);
            kept.push('\n');
        }
    }

    if !removed_any {
        return Err(Error::HostNotKnown(host.to_owned()));
    }

    // Atomic write: write to a temp file in the same directory, then rename.
    let parent = path.parent().ok_or_else(|| {
        Error::KnownHostsParseFailed("known_hosts path has no parent directory".into())
    })?;
    // Use PID + nanosecond timestamp + random suffix to avoid races between
    // concurrent remove() calls within the same process.
    let tmp_path = parent.join(format!(
        ".known_hosts.tmp.{}.{}.{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos(),
        rand_suffix()
    ));
    // Use create_new to prevent symlink attacks on multi-user systems.
    {
        let mut tmp_file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp_path)?;
        std::io::Write::write_all(&mut tmp_file, kept.as_bytes())?;
    }
    // Preserve the original file permissions.
    if let Ok(original_meta) = std::fs::metadata(path) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(
                &tmp_path,
                std::fs::Permissions::from_mode(original_meta.permissions().mode()),
            );
        }
        #[cfg(not(unix))]
        {
            let _ = std::fs::set_permissions(&tmp_path, original_meta.permissions());
        }
    }
    if let Err(e) = std::fs::rename(&tmp_path, path) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(e.into());
    }
    Ok(())
}

/// Check whether a single host pattern from a `known_hosts` entry matches the
/// given target hostname.
///
/// Handles exact string match and bracketed `[host]:port` forms.
/// Does **not** expand glob patterns (`*`, `?`) or negations (`!`), those
/// require the full SSH matching algorithm.
fn host_pattern_matches(pattern: &str, target: &str) -> bool {
    // Hashed form (used by `ssh-keyscan -H` and `HashKnownHosts yes`).
    if pattern.starts_with("|1|") {
        return hashed_host_matches(pattern, target);
    }

    // Direct match.
    if pattern == target {
        return true;
    }

    if let Some((p_host, p_port)) = strip_brackets(pattern)
        && let Some((t_host, t_port)) = target.split_once(':')
        && p_host == t_host
        && p_port == t_port
    {
        return true;
    }
    if let Some((t_host, t_port)) = strip_brackets(target)
        && let Some((p_host, p_port)) = pattern.split_once(':')
        && p_host == t_host
        && p_port == t_port
    {
        return true;
    }
    false
}

/// Verify an OpenSSH hashed hostname field against `target`.
///
/// Hashed entries have the form `|1|<base64 salt>|<base64 HMAC-SHA1(salt,
/// hostname)>` (the format `ssh-keyscan -H` writes). The salt stored in the
/// entry lets us re-derive the digest for the candidate hostname and compare
/// in constant time, so hashed entries can be removed and queried without
/// ever storing the plaintext name.
fn hashed_host_matches(field: &str, target: &str) -> bool {
    use base64::Engine as _;
    use hmac::Mac as _;
    type HmacSha1 = hmac::Hmac<sha1::Sha1>;

    let Some((salt_b64, digest_b64)) = field.strip_prefix("|1|").and_then(|r| r.split_once('|'))
    else {
        return false;
    };
    let (Ok(salt), Ok(expected)) = (
        base64::engine::general_purpose::STANDARD.decode(salt_b64),
        base64::engine::general_purpose::STANDARD.decode(digest_b64),
    ) else {
        return false;
    };
    let Ok(mut mac) = HmacSha1::new_from_slice(&salt) else {
        return false;
    };
    mac.update(target.as_bytes());
    mac.verify_slice(&expected).is_ok()
}

/// Extract host and port from a bracketed `[host]:port` string.
///
/// Returns `None` if the string is not in bracketed form.
fn strip_brackets(s: &str) -> Option<(&str, &str)> {
    let inner = s.strip_prefix('[')?;
    let (host, rest) = inner.split_once("]:")?;
    Some((host, rest))
}

/// Check whether a `known_hosts` line refers to the given host.
///
/// Handles plain hostnames, comma-separated patterns, markers, and OpenSSH
/// hashed entries (`|1|<salt>|<digest>`).
fn line_matches_host(line: &str, target: &str) -> bool {
    // Skip optional marker.
    let rest = if line.starts_with('@') {
        let Some((_, r)) = line.split_once(' ') else {
            return false;
        };
        r
    } else {
        line
    };

    // The host field is the first whitespace-delimited token.
    let Some(hosts_field) = rest.split_whitespace().next() else {
        return false;
    };

    // Hashed entries, match by verifying the HMAC with the entry's salt.
    if hosts_field.starts_with("|1|") {
        return hashed_host_matches(hosts_field, target);
    }

    // Comma-separated patterns, try each one.
    hosts_field
        .split_terminator(',')
        .any(|pattern| host_pattern_matches(pattern, target))
}

#[cfg(test)]
mod tests {
    use super::*;
    use toride_ssh_core::KeyType;

    #[test]
    fn strip_brackets_valid() {
        assert_eq!(strip_brackets("[host]:22"), Some(("host", "22")));
        assert_eq!(
            strip_brackets("[192.168.1.1]:2222"),
            Some(("192.168.1.1", "2222"))
        );
    }

    #[test]
    fn strip_brackets_invalid() {
        assert_eq!(strip_brackets("host:22"), None);
        assert_eq!(strip_brackets("host"), None);
        assert_eq!(strip_brackets("[host]"), None);
        assert_eq!(strip_brackets(""), None);
    }

    #[test]
    fn host_pattern_matches_exact() {
        assert!(host_pattern_matches("example.com", "example.com"));
    }

    #[test]
    fn host_pattern_matches_no_match() {
        assert!(!host_pattern_matches("example.com", "other.com"));
    }

    #[test]
    fn host_pattern_matches_bracketed_pattern() {
        assert!(host_pattern_matches("[example.com]:22", "example.com:22"));
    }

    #[test]
    fn host_pattern_matches_bracketed_target() {
        assert!(host_pattern_matches("example.com:22", "[example.com]:22"));
    }

    #[test]
    fn host_pattern_matches_port_different() {
        assert!(!host_pattern_matches(
            "[example.com]:22",
            "example.com:2222"
        ));
    }

    #[test]
    fn line_matches_host_simple() {
        assert!(line_matches_host(
            "example.com ssh-ed25519 AAAA...",
            "example.com"
        ));
    }

    #[test]
    fn line_matches_host_comma_separated() {
        assert!(line_matches_host(
            "host1.com,host2.com ssh-ed25519 AAAA...",
            "host2.com"
        ));
    }

    #[test]
    fn line_matches_host_no_match() {
        assert!(!line_matches_host(
            "other.com ssh-ed25519 AAAA...",
            "example.com"
        ));
    }

    #[test]
    fn line_matches_host_hashed() {
        // OpenSSH hashed form: |1|<b64 salt>|<b64 HMAC-SHA1(hostname)>.
        // Vectors: salt = bytes 0..16, hosts "localhost" / "example.com".
        let localhost = "|1|AAECAwQFBgcICQoLDA0ODw==|QPxsRPrqmgtYIUn5eQ4JuxaQ0B0=";
        let example = "|1|AAECAwQFBgcICQoLDA0ODw==|WUsirEoKqUFIgxenWq6ntO/wUUg=";
        assert!(line_matches_host(
            &format!("{localhost} ssh-ed25519 AAAA..."),
            "localhost"
        ));
        assert!(!line_matches_host(
            &format!("{localhost} ssh-ed25519 AAAA..."),
            "example.com"
        ));
        assert!(line_matches_host(
            &format!("{example} ssh-ed25519 AAAA..."),
            "example.com"
        ));
        // Malformed hashed fields never match.
        assert!(!line_matches_host(
            "|1|!!!|??? ssh-ed25519 AAAA...",
            "localhost"
        ));
        assert!(!line_matches_host(
            "|1|only-two-fields ssh-ed25519 x",
            "localhost"
        ));
    }

    #[test]
    fn remove_host_sync_removes_hashed_entry() {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let path = dir.path().join("known_hosts");
        let localhost = "|1|AAECAwQFBgcICQoLDA0ODw==|QPxsRPrqmgtYIUn5eQ4JuxaQ0B0=";
        std::fs::write(
            &path,
            format!("{localhost} ssh-ed25519 AAAA...\nexample.org ssh-ed25519 BBBB...\n"),
        )
        .expect("write known_hosts");

        remove_host_sync(&path, "localhost").expect("remove should match hashed entry");

        let left = std::fs::read_to_string(&path).expect("reread");
        assert!(
            !left.contains("QPxsRPrqmgtYIUn5eQ4JuxaQ0B0="),
            "hashed localhost entry should be removed, got: {left}"
        );
        assert!(left.contains("example.org"), "other entries are kept");

        // No matching entry (hashed or otherwise) still errors.
        let result = remove_host_sync(&path, "localhost");
        assert!(matches!(result, Err(Error::HostNotKnown(_))));
    }

    #[test]
    fn line_matches_host_cert_authority_marker() {
        assert!(line_matches_host(
            "@cert-authority example.com ssh-ed25519 AAAA...",
            "example.com"
        ));
    }

    #[test]
    fn line_matches_host_revoked_marker() {
        // @revoked with exact hostname matches
        assert!(line_matches_host(
            "@revoked example.com ssh-ed25519 AAAA...",
            "example.com"
        ));
    }

    #[test]
    fn line_matches_host_revoked_no_match() {
        // @revoked with different host does not match
        assert!(!line_matches_host(
            "@revoked other.com ssh-ed25519 AAAA...",
            "example.com"
        ));
    }

    #[test]
    fn line_matches_host_marker_no_space() {
        // Malformed marker line without space after marker
        assert!(!line_matches_host("@cert-authority", "example.com"));
    }

    #[test]
    fn line_matches_host_empty() {
        assert!(!line_matches_host("", "example.com"));
    }

    #[test]
    fn line_matches_host_bracketed_port() {
        assert!(line_matches_host(
            "[example.com]:2222 ssh-ed25519 AAAA...",
            "example.com:2222"
        ));
    }

    #[tokio::test]
    async fn find_entry_by_hostname() {
        let dir = tempfile::tempdir().unwrap();
        let kh_path = dir.path().join("known_hosts");
        std::fs::write(
            &kh_path,
            "example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\n",
        )
        .unwrap();

        let paths = toride_ssh_core::SshPaths::with_dir(dir.path());
        let runner = toride_ssh_core::MockCliRunner::new();
        let svc = KnownHostsService::new(&paths, &runner);
        assert!(svc.contains("example.com").await.unwrap());
        assert!(!svc.contains("other.com").await.unwrap());
    }

    #[tokio::test]
    async fn find_entry_by_ip_address() {
        let dir = tempfile::tempdir().unwrap();
        let kh_path = dir.path().join("known_hosts");
        std::fs::write(
            &kh_path,
            "192.168.1.1 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\n",
        )
        .unwrap();

        let paths = toride_ssh_core::SshPaths::with_dir(dir.path());
        let runner = toride_ssh_core::MockCliRunner::new();
        let svc = KnownHostsService::new(&paths, &runner);
        assert!(svc.contains("192.168.1.1").await.unwrap());
        assert!(!svc.contains("10.0.0.1").await.unwrap());
    }

    #[tokio::test]
    async fn find_entry_by_bracketed_host_port() {
        let dir = tempfile::tempdir().unwrap();
        let kh_path = dir.path().join("known_hosts");
        std::fs::write(
            &kh_path,
            "[example.com]:2222 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\n",
        )
        .unwrap();

        let paths = toride_ssh_core::SshPaths::with_dir(dir.path());
        let runner = toride_ssh_core::MockCliRunner::new();
        let svc = KnownHostsService::new(&paths, &runner);
        // Target "example.com:2222" should match the bracketed pattern "[example.com]:2222".
        assert!(svc.contains("example.com:2222").await.unwrap());
        // Same host on a different port should NOT match.
        assert!(!svc.contains("example.com:22").await.unwrap());
    }

    #[tokio::test]
    async fn find_entry_by_comma_separated_hosts() {
        let dir = tempfile::tempdir().unwrap();
        let kh_path = dir.path().join("known_hosts");
        std::fs::write(
            &kh_path,
            "host1.example.com,host2.example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\n",
        )
        .unwrap();

        let paths = toride_ssh_core::SshPaths::with_dir(dir.path());
        let runner = toride_ssh_core::MockCliRunner::new();
        let svc = KnownHostsService::new(&paths, &runner);
        assert!(svc.contains("host1.example.com").await.unwrap());
        assert!(svc.contains("host2.example.com").await.unwrap());
        assert!(!svc.contains("host3.example.com").await.unwrap());
    }

    #[tokio::test]
    async fn find_entry_with_cert_authority_marker() {
        let dir = tempfile::tempdir().unwrap();
        let kh_path = dir.path().join("known_hosts");
        std::fs::write(
            &kh_path,
            "@cert-authority *.example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\n",
        )
        .unwrap();

        let paths = toride_ssh_core::SshPaths::with_dir(dir.path());
        let runner = toride_ssh_core::MockCliRunner::new();
        let svc = KnownHostsService::new(&paths, &runner);
        let entries = svc.list().await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].markers, vec!["@cert-authority"]);
        assert_eq!(entries[0].hosts, vec!["*.example.com"]);
    }

    #[test]
    fn fingerprint_display_format() {
        let fp = toride_ssh_core::Fingerprint {
            hash: "abc123def456".to_owned(),
            key_type: KeyType::Ed25519,
        };
        assert_eq!(format!("{fp}"), "SHA256:abc123def456");
    }

    #[test]
    fn fingerprint_display_rsa() {
        let fp = toride_ssh_core::Fingerprint {
            hash: "xYz789+/AbCdEf".to_owned(),
            key_type: KeyType::Rsa { bits: 4096 },
        };
        assert_eq!(format!("{fp}"), "SHA256:xYz789+/AbCdEf");
    }

    #[test]
    fn fingerprint_display_ecdsa() {
        let fp = toride_ssh_core::Fingerprint {
            hash: "nistp256hashvalue".to_owned(),
            key_type: KeyType::EcdsaP256,
        };
        assert_eq!(format!("{fp}"), "SHA256:nistp256hashvalue");
    }

    #[test]
    fn host_key_change_detection_different_key_types() {
        use super::parse::parse_line;
        use super::scan::parse_keyscan_line;

        // Stored entry: host has an ed25519 key.
        let stored = parse_line(
            "example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl",
            1,
        )
        .unwrap();

        // Scanned entry: same host now reports an rsa key instead.
        let scanned = parse_keyscan_line(
            "example.com",
            "example.com ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7",
        )
        .unwrap();

        // Key types differ, host key has changed.
        assert_ne!(stored.key_type, scanned.key_type);
    }

    #[test]
    fn host_key_change_detection_same_key_type_different_blob() {
        use super::parse::parse_line;
        use super::scan::parse_keyscan_line;

        let stored = parse_line(
            "example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl",
            1,
        )
        .unwrap();

        // Same key type but different blob.
        let scanned = parse_keyscan_line(
            "example.com",
            "example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDIFFERENTKEY0000000000000000000000000",
        )
        .unwrap();

        assert_eq!(stored.key_type, scanned.key_type);
        assert_ne!(stored.public_key, scanned.public_key);
    }

    #[test]
    fn host_key_no_change_detected() {
        use super::parse::parse_line;
        use super::scan::parse_keyscan_line;

        let key_blob = "AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";
        let stored = parse_line(&format!("example.com ssh-ed25519 {key_blob}"), 1).unwrap();

        let scanned = parse_keyscan_line(
            "example.com",
            &format!("example.com ssh-ed25519 {key_blob}"),
        )
        .unwrap();

        assert_eq!(stored.key_type, scanned.key_type);
        assert_eq!(stored.public_key, scanned.public_key);
    }

    #[tokio::test]
    async fn list_known_hosts_and_find_entry() {
        let dir = tempfile::tempdir().unwrap();
        let kh_path = dir.path().join("known_hosts");
        std::fs::write(
            &kh_path,
            "\
host-a ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl
host-b ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7
",
        )
        .unwrap();

        let paths = toride_ssh_core::SshPaths::with_dir(dir.path());
        let runner = toride_ssh_core::MockCliRunner::new();
        let svc = KnownHostsService::new(&paths, &runner);
        let entries = svc.list().await.unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].hosts, vec!["host-a"]);
        assert_eq!(entries[0].key_type, "ssh-ed25519");
        assert_eq!(entries[1].hosts, vec!["host-b"]);
        assert_eq!(entries[1].key_type, "ssh-rsa");
    }

    #[tokio::test]
    async fn remove_host_from_known_hosts() {
        let dir = tempfile::tempdir().unwrap();
        let kh_path = dir.path().join("known_hosts");
        std::fs::write(
            &kh_path,
            "\
host-a ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl
host-b ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7
",
        )
        .unwrap();

        let paths = toride_ssh_core::SshPaths::with_dir(dir.path());
        let runner = toride_ssh_core::MockCliRunner::new();
        let svc = KnownHostsService::new(&paths, &runner);
        svc.remove("host-a").await.unwrap();

        let remaining = svc.list().await.unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].hosts, vec!["host-b"]);
    }

    #[tokio::test]
    async fn remove_nonexistent_host_errors() {
        let dir = tempfile::tempdir().unwrap();
        let kh_path = dir.path().join("known_hosts");
        std::fs::write(
            &kh_path,
            "host-a ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\n",
        )
        .unwrap();

        let paths = toride_ssh_core::SshPaths::with_dir(dir.path());
        let runner = toride_ssh_core::MockCliRunner::new();
        let svc = KnownHostsService::new(&paths, &runner);
        let result = svc.remove("nonexistent").await;
        assert!(result.is_err());
    }

    #[test]
    fn parse_ssh_keygen_f_output_single_entry() {
        let raw = "\
# Host example.com found: line 3
example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl
";
        let entries = parse_ssh_keygen_f_output("example.com", raw);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].hosts, vec!["example.com"]);
        assert_eq!(entries[0].key_type, "ssh-ed25519");
        assert_eq!(entries[0].line_number, 3);
    }

    #[test]
    fn parse_ssh_keygen_f_output_multiple_entries() {
        let raw = "\
# Host example.com found: line 1
example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl
# Host example.com found: line 5
example.com ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7
";
        let entries = parse_ssh_keygen_f_output("example.com", raw);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].key_type, "ssh-ed25519");
        assert_eq!(entries[0].line_number, 1);
        assert_eq!(entries[1].key_type, "ssh-rsa");
        assert_eq!(entries[1].line_number, 5);
    }

    #[test]
    fn parse_ssh_keygen_f_output_empty() {
        let entries = parse_ssh_keygen_f_output("example.com", "");
        assert!(entries.is_empty());
    }

    #[test]
    fn parse_ssh_keygen_f_output_only_comments() {
        let raw = "# Host example.com found: line 0\n";
        let entries = parse_ssh_keygen_f_output("example.com", raw);
        assert!(entries.is_empty());
    }

    #[tokio::test]
    async fn find_returns_matching_entries() {
        let dir = tempfile::tempdir().unwrap();
        let kh_path = dir.path().join("known_hosts");
        let key_b64 = "AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";
        std::fs::write(&kh_path, format!("example.com ssh-ed25519 {key_b64}\n")).unwrap();

        let paths = toride_ssh_core::SshPaths::with_dir(dir.path());
        let runner = toride_ssh_core::MockCliRunner::new();
        runner.push_run_response(
            "ssh-keygen",
            Ok(format!(
                "# Host example.com found: line 1\nexample.com ssh-ed25519 {key_b64}\n"
            )),
        );
        let svc = KnownHostsService::new(&paths, &runner);
        let entries = svc.find("example.com").await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].hosts, vec!["example.com"]);
    }

    #[tokio::test]
    async fn find_returns_empty_when_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let kh_path = dir.path().join("known_hosts");
        std::fs::write(&kh_path, "").unwrap();

        let paths = toride_ssh_core::SshPaths::with_dir(dir.path());
        let runner = toride_ssh_core::MockCliRunner::new();
        // ssh-keygen -F returns exit code 1 for not found, mock as error.
        runner.push_run_response(
            "ssh-keygen",
            Err(crate::Error::CommandFailed("exit status: 1".into())),
        );
        let svc = KnownHostsService::new(&paths, &runner);
        let entries = svc.find("unknown.host").await.unwrap();
        assert!(entries.is_empty());
    }

    #[tokio::test]
    async fn find_searches_global_known_hosts() {
        let dir = tempfile::tempdir().unwrap();
        let kh_path = dir.path().join("known_hosts");
        let global_path = dir.path().join("ssh_known_hosts");
        let key_b64 = "AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";
        std::fs::write(&kh_path, "").unwrap();
        std::fs::write(&global_path, format!("global-host ssh-ed25519 {key_b64}\n")).unwrap();

        let paths = toride_ssh_core::SshPaths::with_dir(dir.path());
        let runner = toride_ssh_core::MockCliRunner::new();
        // First call: user known_hosts, host absent (ssh-keygen exit code 1).
        runner.push_run_response(
            "ssh-keygen",
            Err(crate::Error::CommandFailed("exit Some(1)".into())),
        );
        // Second call: global known_hosts.
        runner.push_run_response(
            "ssh-keygen",
            Ok(format!(
                "# Host global-host found: line 1\nglobal-host ssh-ed25519 {key_b64}\n"
            )),
        );
        let svc = KnownHostsService::new(&paths, &runner);
        let entries = svc.find("global-host").await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].hosts, vec!["global-host"]);
    }

    // find_in_file distinguishes a genuine "host not found" (ssh-keygen exit
    // code 1) from real errors (missing binary, task panic, permission, …).
    #[tokio::test]
    async fn find_returns_empty_for_genuine_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let kh_path = dir.path().join("known_hosts");
        std::fs::write(&kh_path, "").unwrap();

        let paths = toride_ssh_core::SshPaths::with_dir(dir.path());
        let runner = toride_ssh_core::MockCliRunner::new();
        // ssh-keygen -F returns exit code 1 when the host is absent, both
        // the production Debug formatting (`exit Some(1)`) and the
        // conventional shorthand (`exit status: 1`) must be recognised.
        runner.push_run_response(
            "ssh-keygen",
            Err(crate::Error::CommandFailed(
                "command `ssh-keygen` failed with exit Some(1): ".into(),
            )),
        );
        let svc = KnownHostsService::new(&paths, &runner);
        let entries = svc.find("unknown.host").await.unwrap();
        assert!(entries.is_empty());
    }

    #[tokio::test]
    async fn find_returns_empty_for_not_found_status_shorthand() {
        let dir = tempfile::tempdir().unwrap();
        let kh_path = dir.path().join("known_hosts");
        std::fs::write(&kh_path, "").unwrap();

        let paths = toride_ssh_core::SshPaths::with_dir(dir.path());
        let runner = toride_ssh_core::MockCliRunner::new();
        runner.push_run_response(
            "ssh-keygen",
            Err(crate::Error::CommandFailed("exit status: 1".into())),
        );
        let svc = KnownHostsService::new(&paths, &runner);
        let entries = svc.find("unknown.host").await.unwrap();
        assert!(entries.is_empty());
    }

    #[tokio::test]
    async fn find_propagates_real_error_missing_binary() {
        let dir = tempfile::tempdir().unwrap();
        let kh_path = dir.path().join("known_hosts");
        std::fs::write(&kh_path, "").unwrap();

        let paths = toride_ssh_core::SshPaths::with_dir(dir.path());
        let runner = toride_ssh_core::MockCliRunner::new();
        // The ssh-keygen binary is missing from PATH, a `CommandFailed`
        // whose message does NOT carry exit code 1.  This must NOT be
        // silently swallowed as an empty result.
        runner.push_run_response(
            "ssh-keygen",
            Err(crate::Error::ToolNotFound("ssh-keygen".into())),
        );
        let svc = KnownHostsService::new(&paths, &runner);
        let result = svc.find("example.com").await;
        assert!(
            result.is_err(),
            "missing-binary error must be propagated, not swallowed as empty"
        );
        assert!(matches!(result.unwrap_err(), crate::Error::ToolNotFound(_)));
    }

    #[tokio::test]
    async fn find_propagates_unexpected_exit_code() {
        let dir = tempfile::tempdir().unwrap();
        let kh_path = dir.path().join("known_hosts");
        std::fs::write(&kh_path, "").unwrap();

        let paths = toride_ssh_core::SshPaths::with_dir(dir.path());
        let runner = toride_ssh_core::MockCliRunner::new();
        // An exit code other than 1 (e.g. permission denied reading the
        // file surfaces as exit 2) is a real failure, not "host absent".
        runner.push_run_response(
            "ssh-keygen",
            Err(crate::Error::CommandFailed(
                "command `ssh-keygen` failed with exit Some(2): permission denied".into(),
            )),
        );
        let svc = KnownHostsService::new(&paths, &runner);
        let result = svc.find("example.com").await;
        assert!(
            result.is_err(),
            "non-unit exit code must be propagated, not swallowed as empty"
        );
    }

    #[tokio::test]
    async fn find_propagates_task_failure() {
        let dir = tempfile::tempdir().unwrap();
        let kh_path = dir.path().join("known_hosts");
        std::fs::write(&kh_path, "").unwrap();

        let paths = toride_ssh_core::SshPaths::with_dir(dir.path());
        let runner = toride_ssh_core::MockCliRunner::new();
        // A panic in the runner task is a real error, not "host absent".
        runner.push_run_response(
            "ssh-keygen",
            Err(crate::Error::TaskFailed("background task panicked".into())),
        );
        let svc = KnownHostsService::new(&paths, &runner);
        let result = svc.find("example.com").await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), crate::Error::TaskFailed(_)));
    }

    #[test]
    fn is_host_not_found_classifier() {
        // Exit code 1 (Debug formatting) and the status shorthand are not-found.
        assert!(is_host_not_found(&Error::CommandFailed(
            "command `ssh-keygen` failed with exit Some(1): ".into()
        )));
        assert!(is_host_not_found(&Error::CommandFailed(
            "exit status: 1".into()
        )));
        // Other exit codes are real errors.
        assert!(!is_host_not_found(&Error::CommandFailed(
            "command `ssh-keygen` failed with exit Some(2): perm denied".into()
        )));
        assert!(!is_host_not_found(&Error::CommandFailed(
            "command `ssh-keygen` failed with exit None: ".into()
        )));
        // Non-CommandFailed variants are real errors.
        assert!(!is_host_not_found(&Error::ToolNotFound(
            "ssh-keygen".into()
        )));
        assert!(!is_host_not_found(&Error::TaskFailed("panic".into())));
        assert!(!is_host_not_found(&Error::PermissionDenied("/x".into())));
    }

    #[test]
    fn known_host_entry_fingerprint_is_sha256() {
        let entry = parse::parse_line(
            "example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl",
            1,
        )
        .unwrap();
        let fp = entry.fingerprint().unwrap();
        let fp_str = format!("{fp}");
        assert!(
            fp_str.starts_with("SHA256:"),
            "expected SHA256 prefix, got: {fp_str}"
        );
        assert!(fp_str.len() > 8, "fingerprint too short: {fp_str}");
    }

    #[test]
    fn known_host_entry_fingerprint_rsa() {
        let entry = parse::parse_line(
            "host ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCrIILJHHxYtpVqf2rJdtFQHNlaFHE/7lXqyYoKhf9qTWO0NSDtlbbCZGqqDUsvXR2Q71A5TcyNaPPTCXaUrosEF3NeQ6901lEDnPZVsxUTzgf0DxkJ47TzyqfQbThQ8TKq+H5dV+Vxh2+jNWBo5A1jxNnh22+ZgqJNNlHA6hYdmKSLxwrfgkJMvy1rle8cK1V45EVEqwbbcDALXSOQZEqp8ZeHH0QAKcZ3pNYP8v2ZZh6ljb3jJGBusx0/iPndCovqbbYkaOBag5jDKuAehLQKZiJHAxLWfmmCAqHA54jJOaJ7U6xvuE4f8cFuQhBcstiPOu6dkAX6rOamSH2FUlvR",
            1,
        )
        .unwrap();
        let fp = entry.fingerprint().unwrap();
        assert!(matches!(fp.key_type, toride_ssh_core::KeyType::Rsa { .. }));
        assert_eq!(fp.hash, "zi9Fig+6FSOyjpL8yWyinPb4DmAJ0k73kumtOpWmJ3k");
        assert!(format!("{fp}").starts_with("SHA256:"));
    }

    #[test]
    fn scanned_host_key_fingerprint() {
        let key = scan::parse_keyscan_line(
            "example.com",
            "example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl",
        )
        .unwrap();
        let fp = key.fingerprint().unwrap();
        let fp_str = format!("{fp}");
        assert!(fp_str.starts_with("SHA256:"));
    }

    #[test]
    fn stored_and_scanned_fingerprints_match_for_same_key() {
        let key_b64 = "AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";
        let stored = parse::parse_line(&format!("example.com ssh-ed25519 {key_b64}"), 1).unwrap();
        let scanned =
            scan::parse_keyscan_line("example.com", &format!("example.com ssh-ed25519 {key_b64}"))
                .unwrap();

        let stored_fp = stored.fingerprint().unwrap();
        let scanned_fp = scanned.fingerprint().unwrap();
        assert_eq!(format!("{stored_fp}"), format!("{scanned_fp}"));
    }

    #[test]
    fn different_keys_produce_different_fingerprints() {
        // Use compare_host_keys which handles invalid key blobs gracefully.
        let stored = vec![parse::parse_line(
            "example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl",
            1,
        )
        .unwrap()];
        let scanned = vec![scan::parse_keyscan_line(
            "example.com",
            "example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJm",
        )
        .unwrap()];

        let changes = compare_host_keys(&stored, &scanned);
        assert_eq!(changes.len(), 1);
        assert!(matches!(changes[0].kind, KeyChangeKind::Changed { .. }));
    }

    #[tokio::test]
    async fn list_global_reads_global_file() {
        let dir = tempfile::tempdir().unwrap();
        let global_path = dir.path().join("ssh_known_hosts");
        std::fs::write(
            &global_path,
            "global-host ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\n",
        )
        .unwrap();

        let paths = toride_ssh_core::SshPaths::with_dir(dir.path());
        let runner = toride_ssh_core::MockCliRunner::new();
        let svc = KnownHostsService::new(&paths, &runner);
        let entries = svc.list_global().await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].hosts, vec!["global-host"]);
    }

    #[tokio::test]
    async fn list_global_returns_empty_when_file_missing() {
        let dir = tempfile::tempdir().unwrap();
        let paths = toride_ssh_core::SshPaths::with_dir(dir.path());
        let runner = toride_ssh_core::MockCliRunner::new();
        let svc = KnownHostsService::new(&paths, &runner);
        let entries = svc.list_global().await.unwrap();
        assert!(entries.is_empty());
    }

    #[tokio::test]
    async fn list_all_merges_user_and_global() {
        let dir = tempfile::tempdir().unwrap();
        let kh_path = dir.path().join("known_hosts");
        let global_path = dir.path().join("ssh_known_hosts");
        std::fs::write(
            &kh_path,
            "user-host ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\n",
        )
        .unwrap();
        std::fs::write(
            &global_path,
            "global-host ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7\n",
        )
        .unwrap();

        let paths = toride_ssh_core::SshPaths::with_dir(dir.path());
        let runner = toride_ssh_core::MockCliRunner::new();
        let svc = KnownHostsService::new(&paths, &runner);
        let entries = svc.list_all().await.unwrap();
        assert_eq!(entries.len(), 2);
        let hosts: Vec<&str> = entries
            .iter()
            .flat_map(|e| e.hosts.iter().map(std::string::String::as_str))
            .collect();
        assert!(hosts.contains(&"user-host"));
        assert!(hosts.contains(&"global-host"));
    }

    #[tokio::test]
    async fn check_host_key_change_detects_changed_key() {
        let dir = tempfile::tempdir().unwrap();
        let kh_path = dir.path().join("known_hosts");
        std::fs::write(
            &kh_path,
            "example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\n",
        )
        .unwrap();

        let paths = toride_ssh_core::SshPaths::with_dir(dir.path());
        let runner = toride_ssh_core::MockCliRunner::new();

        // Mock ssh-keygen -F for find(), return the stored entry.
        runner.push_run_response(
            "ssh-keygen",
            Ok("# Host example.com found: line 1\nexample.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\n".to_owned()),
        );

        // Mock ssh-keyscan for scan(), return a DIFFERENT key.
        runner.push_run_response(
            "ssh-keyscan",
            Ok("example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDIFFERENTKEY0000000000000000000000000\n".to_owned()),
        );

        let svc = KnownHostsService::new(&paths, &runner);
        let report = svc.check_host_key_change("example.com").await.unwrap();
        assert!(report.changed);
        assert_eq!(report.changes.len(), 1);
        assert_eq!(report.changes[0].key_type, "ssh-ed25519");
        assert!(matches!(
            report.changes[0].kind,
            KeyChangeKind::Changed { .. }
        ));
    }

    #[tokio::test]
    async fn check_host_key_change_no_change() {
        let dir = tempfile::tempdir().unwrap();
        let kh_path = dir.path().join("known_hosts");
        let key_b64 = "AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";
        std::fs::write(&kh_path, format!("example.com ssh-ed25519 {key_b64}\n")).unwrap();

        let paths = toride_ssh_core::SshPaths::with_dir(dir.path());
        let runner = toride_ssh_core::MockCliRunner::new();

        // Mock ssh-keygen -F, same key.
        runner.push_run_response(
            "ssh-keygen",
            Ok(format!(
                "# Host example.com found: line 1\nexample.com ssh-ed25519 {key_b64}\n"
            )),
        );
        // Mock ssh-keyscan, same key.
        runner.push_run_response(
            "ssh-keyscan",
            Ok(format!("example.com ssh-ed25519 {key_b64}\n")),
        );

        let svc = KnownHostsService::new(&paths, &runner);
        let report = svc.check_host_key_change("example.com").await.unwrap();
        assert!(!report.changed);
        assert!(report.changes.is_empty());
    }

    #[tokio::test]
    async fn check_host_key_change_detects_new_key_type() {
        let dir = tempfile::tempdir().unwrap();
        let kh_path = dir.path().join("known_hosts");
        let ed_key = "AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";
        let rsa_key = "AAAAB3NzaC1yc2EAAAADAQABAAABgQC7";
        std::fs::write(&kh_path, format!("example.com ssh-ed25519 {ed_key}\n")).unwrap();

        let paths = toride_ssh_core::SshPaths::with_dir(dir.path());
        let runner = toride_ssh_core::MockCliRunner::new();

        // ssh-keygen -F returns only the ed25519 key.
        runner.push_run_response(
            "ssh-keygen",
            Ok(format!(
                "# Host example.com found: line 1\nexample.com ssh-ed25519 {ed_key}\n"
            )),
        );
        // ssh-keyscan returns both ed25519 AND rsa.
        runner.push_run_response(
            "ssh-keyscan",
            Ok(format!(
                "example.com ssh-ed25519 {ed_key}\nexample.com ssh-rsa {rsa_key}\n"
            )),
        );

        let svc = KnownHostsService::new(&paths, &runner);
        let report = svc.check_host_key_change("example.com").await.unwrap();
        assert!(report.changed);
        assert_eq!(report.changes.len(), 1);
        assert_eq!(report.changes[0].key_type, "ssh-rsa");
        assert!(matches!(report.changes[0].kind, KeyChangeKind::New));
    }

    #[tokio::test]
    async fn check_host_key_change_detects_removed_key_type() {
        let dir = tempfile::tempdir().unwrap();
        let kh_path = dir.path().join("known_hosts");
        let ed_key = "AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";
        let rsa_key = "AAAAB3NzaC1yc2EAAAADAQABAAABgQC7";
        std::fs::write(
            &kh_path,
            format!("example.com ssh-ed25519 {ed_key}\nexample.com ssh-rsa {rsa_key}\n"),
        )
        .unwrap();

        let paths = toride_ssh_core::SshPaths::with_dir(dir.path());
        let runner = toride_ssh_core::MockCliRunner::new();

        // ssh-keygen -F returns both keys.
        runner.push_run_response(
            "ssh-keygen",
            Ok(format!(
                "# Host example.com found: line 1\nexample.com ssh-ed25519 {ed_key}\n\
                 # Host example.com found: line 2\nexample.com ssh-rsa {rsa_key}\n"
            )),
        );
        // ssh-keyscan returns only ed25519 (rsa removed).
        runner.push_run_response(
            "ssh-keyscan",
            Ok(format!("example.com ssh-ed25519 {ed_key}\n")),
        );

        let svc = KnownHostsService::new(&paths, &runner);
        let report = svc.check_host_key_change("example.com").await.unwrap();
        assert!(report.changed);
        assert_eq!(report.changes.len(), 1);
        assert_eq!(report.changes[0].key_type, "ssh-rsa");
        assert!(matches!(report.changes[0].kind, KeyChangeKind::Removed));
    }

    #[tokio::test]
    async fn resolve_user_known_hosts_file_default() {
        let dir = tempfile::tempdir().unwrap();
        // No config file, should return default known_hosts path.
        let paths = toride_ssh_core::SshPaths::with_dir(dir.path());
        let runner = toride_ssh_core::MockCliRunner::new();
        let svc = KnownHostsService::new(&paths, &runner);
        let result = svc
            .resolve_user_known_hosts_file("example.com")
            .await
            .unwrap();
        assert_eq!(result, dir.path().join("known_hosts"));
    }

    #[tokio::test]
    async fn resolve_user_known_hosts_file_from_config() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config");
        std::fs::write(
            &config_path,
            "Host example.com\n    UserKnownHostsFile /custom/known_hosts\n",
        )
        .unwrap();

        let paths = toride_ssh_core::SshPaths::with_dir(dir.path());
        let runner = toride_ssh_core::MockCliRunner::new();
        let svc = KnownHostsService::new(&paths, &runner);
        let result = svc
            .resolve_user_known_hosts_file("example.com")
            .await
            .unwrap();
        assert_eq!(result, PathBuf::from("/custom/known_hosts"));
    }

    #[tokio::test]
    async fn resolve_user_known_hosts_file_none() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config");
        std::fs::write(
            &config_path,
            "Host example.com\n    UserKnownHostsFile none\n",
        )
        .unwrap();

        let paths = toride_ssh_core::SshPaths::with_dir(dir.path());
        let runner = toride_ssh_core::MockCliRunner::new();
        let svc = KnownHostsService::new(&paths, &runner);
        let result = svc
            .resolve_user_known_hosts_file("example.com")
            .await
            .unwrap();
        // "none" maps to /dev/null.
        assert_eq!(result, PathBuf::from("/dev/null"));
    }

    #[tokio::test]
    async fn resolve_user_known_hosts_file_global_directive() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config");
        std::fs::write(
            &config_path,
            "UserKnownHostsFile /global/custom/known_hosts\n",
        )
        .unwrap();

        let paths = toride_ssh_core::SshPaths::with_dir(dir.path());
        let runner = toride_ssh_core::MockCliRunner::new();
        let svc = KnownHostsService::new(&paths, &runner);
        let result = svc.resolve_user_known_hosts_file("any-host").await.unwrap();
        assert_eq!(result, PathBuf::from("/global/custom/known_hosts"));
    }

    #[test]
    fn find_user_known_hosts_file_in_config_equals_and_tab_forms() {
        let equals = "Host example.com\n\tUserKnownHostsFile=/custom/equal/kh\n";
        let tabbed = "Host example.com\n\tUserKnownHostsFile\t/custom/tab/kh\n";

        assert_eq!(
            find_user_known_hosts_file_in_config(equals, "example.com").as_deref(),
            Some("/custom/equal/kh"),
            "Keyword=value must parse"
        );
        assert_eq!(
            find_user_known_hosts_file_in_config(tabbed, "example.com").as_deref(),
            Some("/custom/tab/kh"),
            "tab-separated keyword must parse"
        );
    }

    #[test]
    fn find_user_known_hosts_file_in_config_host_with_tab_separator() {
        let config = "Host\texample.com\n    UserKnownHostsFile /custom/kh\n";
        assert_eq!(
            find_user_known_hosts_file_in_config(config, "example.com").as_deref(),
            Some("/custom/kh"),
            "Host<TAB>patterns must open a block"
        );
    }

    #[test]
    fn detect_verify_host_key_dns_equals_form() {
        assert_eq!(
            detect_verify_host_key_dns("VerifyHostKeyDNS=yes"),
            DnsVerifyStatus::Enabled
        );
        assert_eq!(
            detect_verify_host_key_dns("verifyhostkeydns\tno"),
            DnsVerifyStatus::Disabled
        );
        assert_eq!(
            detect_verify_host_key_dns("VerifyHostKeyDNS = ask"),
            DnsVerifyStatus::Ask
        );
    }

    #[test]
    fn config_directive_value_rejects_prefix_without_separator() {
        assert_eq!(config_directive_value("hostname example.com", "host"), None);
        assert_eq!(config_directive_value("hostexample", "host"), None);
        assert_eq!(
            config_directive_value("Host example.com", "host"),
            Some("example.com")
        );
    }

    #[tokio::test]
    async fn is_update_host_keys_enabled_accepts_equals_and_tab_forms() {
        let dir = tempfile::tempdir().unwrap();
        for (name, line) in [
            ("equals", "UpdateHostKeys=yes\n"),
            ("tab", "UpdateHostKeys\tyes\n"),
        ] {
            let case_dir = dir.path().join(name);
            std::fs::create_dir_all(&case_dir).unwrap();
            std::fs::write(case_dir.join("config"), line).unwrap();
            let paths = toride_ssh_core::SshPaths::with_dir(&case_dir);
            let runner = toride_ssh_core::MockCliRunner::new();
            let svc = KnownHostsService::new(&paths, &runner);
            assert!(
                svc.is_update_host_keys_enabled().await.unwrap(),
                "{name} form must be detected"
            );
        }
    }

    #[test]
    fn find_user_known_hosts_file_in_config_host_specific() {
        let config = "\
Host example.com
    UserKnownHostsFile /custom/known_hosts
";
        let result = find_user_known_hosts_file_in_config(config, "example.com");
        assert_eq!(result, Some("/custom/known_hosts".to_owned()));
    }

    #[test]
    fn find_user_known_hosts_file_in_config_no_match() {
        let config = "\
Host other.com
    UserKnownHostsFile /custom/known_hosts
";
        let result = find_user_known_hosts_file_in_config(config, "example.com");
        assert_eq!(result, None);
    }

    #[test]
    fn find_user_known_hosts_file_in_config_global() {
        let config = "UserKnownHostsFile /global/known_hosts\n";
        let result = find_user_known_hosts_file_in_config(config, "any-host");
        assert_eq!(result, Some("/global/known_hosts".to_owned()));
    }

    #[test]
    fn find_user_known_hosts_file_in_config_host_takes_precedence() {
        let config = "\
UserKnownHostsFile /global/known_hosts
Host example.com
    UserKnownHostsFile /host-specific/known_hosts
";
        let result = find_user_known_hosts_file_in_config(config, "example.com");
        assert_eq!(result, Some("/host-specific/known_hosts".to_owned()));
    }

    #[test]
    fn find_user_known_hosts_file_in_config_wildcard_host() {
        let config = "\
Host *
    UserKnownHostsFile /wildcard/known_hosts
";
        let result = find_user_known_hosts_file_in_config(config, "anything");
        assert_eq!(result, Some("/wildcard/known_hosts".to_owned()));
    }

    #[test]
    fn expand_known_hosts_path_absolute() {
        assert_eq!(
            expand_known_hosts_path("/absolute/path/known_hosts"),
            PathBuf::from("/absolute/path/known_hosts")
        );
    }

    #[test]
    fn compare_host_keys_detects_new() {
        let stored = vec![];
        let scanned = vec![scan::parse_keyscan_line(
            "host",
            "host ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl",
        )
        .unwrap()];
        let changes = compare_host_keys(&stored, &scanned);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].key_type, "ssh-ed25519");
        assert!(matches!(changes[0].kind, KeyChangeKind::New));
    }

    #[test]
    fn compare_host_keys_detects_removed() {
        let stored = vec![parse::parse_line(
            "host ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl",
            1,
        )
        .unwrap()];
        let scanned = vec![];
        let changes = compare_host_keys(&stored, &scanned);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].key_type, "ssh-ed25519");
        assert!(matches!(changes[0].kind, KeyChangeKind::Removed));
    }

    #[test]
    fn compare_host_keys_detects_changed() {
        let stored = vec![parse::parse_line(
            "host ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl",
            1,
        )
        .unwrap()];
        let scanned =
            vec![scan::parse_keyscan_line(
            "host",
            "host ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDIFFERENTKEY0000000000000000000000000",
        )
        .unwrap()];
        let changes = compare_host_keys(&stored, &scanned);
        assert_eq!(changes.len(), 1);
        assert!(matches!(changes[0].kind, KeyChangeKind::Changed { .. }));
    }

    #[test]
    fn compare_host_keys_no_changes() {
        let key = "AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";
        let stored = vec![parse::parse_line(&format!("host ssh-ed25519 {key}"), 1).unwrap()];
        let scanned =
            vec![scan::parse_keyscan_line("host", &format!("host ssh-ed25519 {key}")).unwrap()];
        let changes = compare_host_keys(&stored, &scanned);
        assert!(changes.is_empty());
    }

    #[test]
    fn compare_host_keys_skips_cert_authority_marker_entries() {
        let stored = vec![parse::parse_line(
            "@cert-authority *.example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICERTAUTHORITYKEYNOTOFFEREDBYHOST0000",
            1,
        )
        .unwrap()];
        let scanned = vec![
            scan::parse_keyscan_line(
                "example.com",
                "example.com ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDaDifferentHostKey",
            )
            .unwrap(),
        ];
        let changes = compare_host_keys(&stored, &scanned);
        assert!(
            changes.iter().all(|c| c.key_type != "ssh-ed25519"
                || !matches!(
                    c.kind,
                    KeyChangeKind::Removed | KeyChangeKind::Changed { .. }
                )),
            "a @cert-authority line must not surface as a host-key change: {changes:?}"
        );
        assert_eq!(changes.len(), 1, "only the scanned ssh-rsa New remains");
        assert!(matches!(changes[0].kind, KeyChangeKind::New));
    }

    #[test]
    fn compare_host_keys_matches_per_entry_for_duplicate_types() {
        let key_a = "AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";
        let key_b = "AAAAC3NzaC1lZDI1NTE5AAAAIDifferentButAlsoStored0000000000000000000";
        let stored = vec![
            parse::parse_line(&format!("host ssh-ed25519 {key_a}"), 1).unwrap(),
            parse::parse_line(&format!("host ssh-ed25519 {key_b}"), 2).unwrap(),
        ];
        let scanned = vec![
            scan::parse_keyscan_line("host", &format!("host ssh-ed25519 {key_a}")).unwrap(),
            scan::parse_keyscan_line("host", &format!("host ssh-ed25519 {key_b}")).unwrap(),
        ];
        let changes = compare_host_keys(&stored, &scanned);
        assert!(
            changes.is_empty(),
            "both stored entries of the duplicated type match: {changes:?}"
        );
    }

    #[test]
    fn compare_host_key_lines_reports_matched_and_changes() {
        let key = "AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";
        let stored = vec![
            format!("host ssh-ed25519 {key}"),
            "@revoked host ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDRevokedKeyNotOffered".to_owned(),
        ];
        let scanned = vec![format!("host ssh-ed25519 {key}")];

        let comparison = compare_host_key_lines(&stored, &scanned);
        assert_eq!(comparison.matched_types, vec!["ssh-ed25519".to_owned()]);
        assert!(
            comparison.changes.is_empty(),
            "the @revoked entry must not count as removed: {:?}",
            comparison.changes
        );
    }

    #[test]
    fn host_key_change_report_debug() {
        let report = HostKeyChangeReport {
            host: "example.com".to_owned(),
            changed: false,
            stored_keys: vec![],
            scanned_keys: vec![],
            changes: vec![],
        };
        let debug = format!("{report:?}");
        assert!(debug.contains("example.com"));
        assert!(debug.contains("changed: false"));
    }

    #[test]
    fn key_change_kind_new_debug() {
        let kind = KeyChangeKind::New;
        assert_eq!(format!("{kind:?}"), "New");
    }

    #[test]
    fn key_change_kind_removed_debug() {
        let kind = KeyChangeKind::Removed;
        assert_eq!(format!("{kind:?}"), "Removed");
    }

    #[test]
    fn key_change_kind_changed_debug() {
        let kind = KeyChangeKind::Changed {
            stored_fingerprint: "SHA256:abc".to_owned(),
            scanned_fingerprint: "SHA256:def".to_owned(),
        };
        let debug = format!("{kind:?}");
        assert!(debug.contains("SHA256:abc"));
        assert!(debug.contains("SHA256:def"));
    }

    #[test]
    fn ssh_paths_global_known_hosts_path() {
        let dir = tempfile::tempdir().unwrap();
        let paths = toride_ssh_core::SshPaths::with_dir(dir.path());
        assert_eq!(
            paths.global_known_hosts_path(),
            dir.path().join("ssh_known_hosts")
        );
    }

    #[test]
    fn dns_verify_status_display() {
        assert_eq!(format!("{}", DnsVerifyStatus::Enabled), "yes");
        assert_eq!(format!("{}", DnsVerifyStatus::Disabled), "no");
        assert_eq!(format!("{}", DnsVerifyStatus::Ask), "ask");
        assert_eq!(format!("{}", DnsVerifyStatus::Unknown), "unknown");
    }

    #[test]
    fn detect_verify_host_key_dns_yes() {
        let config = "VerifyHostKeyDNS yes\n";
        assert_eq!(detect_verify_host_key_dns(config), DnsVerifyStatus::Enabled);
    }

    #[test]
    fn detect_verify_host_key_dns_no() {
        let config = "VerifyHostKeyDNS no\n";
        assert_eq!(
            detect_verify_host_key_dns(config),
            DnsVerifyStatus::Disabled
        );
    }

    #[test]
    fn detect_verify_host_key_dns_ask() {
        let config = "VerifyHostKeyDNS ask\n";
        assert_eq!(detect_verify_host_key_dns(config), DnsVerifyStatus::Ask);
    }

    #[test]
    fn detect_verify_host_key_dns_unknown_when_absent() {
        let config = "Host example.com\n    User alice\n";
        assert_eq!(detect_verify_host_key_dns(config), DnsVerifyStatus::Unknown);
    }

    #[test]
    fn detect_verify_host_key_dns_case_insensitive() {
        let config = "verifyhostkeydns Yes\n";
        assert_eq!(detect_verify_host_key_dns(config), DnsVerifyStatus::Enabled);
    }

    #[test]
    fn detect_verify_host_key_dns_in_host_block() {
        let config = "Host example.com\n    VerifyHostKeyDNS yes\n";
        assert_eq!(detect_verify_host_key_dns(config), DnsVerifyStatus::Enabled);
    }

    #[test]
    fn detect_verify_host_key_dns_skips_comments() {
        let config = "# VerifyHostKeyDNS yes\n";
        assert_eq!(detect_verify_host_key_dns(config), DnsVerifyStatus::Unknown);
    }

    #[test]
    fn detect_verify_host_key_dns_empty_config() {
        assert_eq!(detect_verify_host_key_dns(""), DnsVerifyStatus::Unknown);
    }

    #[test]
    fn parse_sshfp_output_single_record() {
        let output = "example.com IN SSHFP 1 1 A1B2C3D4E5F6\n";
        let records = parse_sshfp_output("example.com", output);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].host, "example.com");
        assert_eq!(records[0].algorithm, "1");
        assert_eq!(records[0].key_type, "1");
        assert_eq!(records[0].fingerprint, "A1B2C3D4E5F6");
    }

    #[test]
    fn parse_sshfp_output_multiple_records() {
        let output = "\
example.com IN SSHFP 1 1 A1B2C3D4E5F6
example.com IN SSHFP 1 2 7A8B9C0D1E2F3A4B5C6D7E8F9A0B1C2D
example.com IN SSHFP 4 2 3A4B5C6D7E8F9A0B1C2D3E4F5A6B7C8D
";
        let records = parse_sshfp_output("example.com", output);
        assert_eq!(records.len(), 3);
        assert_eq!(records[0].algorithm, "1");
        assert_eq!(records[0].key_type, "1");
        assert_eq!(records[1].algorithm, "1");
        assert_eq!(records[1].key_type, "2");
        assert_eq!(records[2].algorithm, "4");
        assert_eq!(records[2].key_type, "2");
    }

    #[test]
    fn parse_sshfp_output_skips_non_sshfp_lines() {
        let output = "\
# some comment
example.com IN TXT some-text-record
example.com IN SSHFP 4 2 DEADBEEF
random noise
";
        let records = parse_sshfp_output("example.com", output);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].fingerprint, "DEADBEEF");
    }

    #[test]
    fn parse_sshfp_output_empty() {
        let records = parse_sshfp_output("host", "");
        assert_eq!(records, [] as [SshfpRecord; 0]);
    }

    #[test]
    fn parse_sshfp_output_case_insensitive_in_sshfp() {
        let output = "example.com in sshfp 4 2 AABBCCDD\n";
        let records = parse_sshfp_output("example.com", output);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].algorithm, "4");
        assert_eq!(records[0].fingerprint, "AABBCCDD");
    }

    #[test]
    fn parse_sshfp_output_too_few_fields() {
        let output = "example.com IN SSHFP 1\n";
        let records = parse_sshfp_output("example.com", output);
        assert_eq!(records, [] as [SshfpRecord; 0]);
    }

    #[tokio::test]
    async fn verify_host_key_dns_status_unknown_when_no_config() {
        let dir = tempfile::tempdir().unwrap();
        let paths = toride_ssh_core::SshPaths::with_dir(dir.path());
        let runner = toride_ssh_core::MockCliRunner::new();
        let svc = KnownHostsService::new(&paths, &runner);
        let status = svc.verify_host_key_dns_status().await.unwrap();
        assert_eq!(status, DnsVerifyStatus::Unknown);
    }

    #[tokio::test]
    async fn verify_host_key_dns_status_enabled() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config");
        std::fs::write(&config_path, "VerifyHostKeyDNS yes\n").unwrap();

        let paths = toride_ssh_core::SshPaths::with_dir(dir.path());
        let runner = toride_ssh_core::MockCliRunner::new();
        let svc = KnownHostsService::new(&paths, &runner);
        let status = svc.verify_host_key_dns_status().await.unwrap();
        assert_eq!(status, DnsVerifyStatus::Enabled);
    }

    #[tokio::test]
    async fn verify_host_key_dns_status_ask() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config");
        std::fs::write(&config_path, "VerifyHostKeyDNS ask\n").unwrap();

        let paths = toride_ssh_core::SshPaths::with_dir(dir.path());
        let runner = toride_ssh_core::MockCliRunner::new();
        let svc = KnownHostsService::new(&paths, &runner);
        let status = svc.verify_host_key_dns_status().await.unwrap();
        assert_eq!(status, DnsVerifyStatus::Ask);
    }

    #[tokio::test]
    async fn generate_sshfp_records_parses_output() {
        let dir = tempfile::tempdir().unwrap();
        let paths = toride_ssh_core::SshPaths::with_dir(dir.path());
        let runner = toride_ssh_core::MockCliRunner::new();
        runner.push_run_response(
            "ssh-keygen",
            Ok("example.com IN SSHFP 1 1 A1B2C3D4E5F6\n\
                 example.com IN SSHFP 4 2 7A8B9C0D1E2F3A4B5C6D7E8F9A0B1C2D\n"
                .to_owned()),
        );
        let svc = KnownHostsService::new(&paths, &runner);
        let records = svc.generate_sshfp_records("example.com").await.unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].algorithm, "1");
        assert_eq!(records[0].key_type, "1");
        assert_eq!(records[1].algorithm, "4");
        assert_eq!(records[1].key_type, "2");
    }

    #[test]
    fn sshfp_record_debug() {
        let record = SshfpRecord {
            host: "example.com".into(),
            algorithm: "4".into(),
            key_type: "2".into(),
            fingerprint: "DEADBEEF".into(),
        };
        let debug = format!("{record:?}");
        assert!(debug.contains("example.com"));
        assert!(debug.contains("DEADBEEF"));
    }

    #[test]
    fn sshfp_record_serialize_deserialize() {
        let record = SshfpRecord {
            host: "example.com".into(),
            algorithm: "4".into(),
            key_type: "2".into(),
            fingerprint: "DEADBEEF".into(),
        };
        let json = serde_json::to_string(&record).unwrap();
        let deserialized: SshfpRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(record, deserialized);
    }

    #[test]
    fn dns_verify_status_serialize_deserialize() {
        for status in [
            DnsVerifyStatus::Enabled,
            DnsVerifyStatus::Disabled,
            DnsVerifyStatus::Ask,
            DnsVerifyStatus::Unknown,
        ] {
            let json = serde_json::to_string(&status).unwrap();
            let deserialized: DnsVerifyStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(status, deserialized);
        }
    }
}
