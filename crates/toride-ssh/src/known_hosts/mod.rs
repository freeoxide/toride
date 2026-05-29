mod parse;
mod scan;

use std::path::Path;

use crate::paths::SshPaths;
use crate::{Error, Result};

pub use parse::KnownHostEntry;
pub use scan::ScannedHostKey;

/// `known_hosts` file management.
pub struct KnownHostsService<'a> {
    paths: &'a SshPaths,
}

impl<'a> KnownHostsService<'a> {
    pub(crate) fn new(paths: &'a SshPaths) -> Self {
        Self { paths }
    }

    /// List all known host entries.
    ///
    /// Parses `~/.ssh/known_hosts` and returns every entry found.
    pub async fn list(&self) -> Result<Vec<KnownHostEntry>> {
        parse::parse_known_hosts(&self.paths.known_hosts_path()).await
    }

    /// Scan a remote host for its public host keys.
    ///
    /// Runs `ssh-keyscan <host>` and returns the keys discovered with the
    /// plaintext hostname.  Keys are **not** added to `known_hosts`; call
    /// [`add`](Self::add) for that.
    pub async fn scan(&self, host: &str) -> Result<Vec<ScannedHostKey>> {
        scan::scan_host(host).await
    }

    /// Scan a host and add all its keys to `~/.ssh/known_hosts`.
    ///
    /// Uses `ssh-keyscan -H <host>` so that hostnames are stored in hashed
    /// form for privacy.  All keys for the host are written in a single
    /// I/O operation.
    pub async fn add(&self, host: &str) -> Result<()> {
        scan::add_host_hashed(&self.paths.known_hosts_path(), host).await
    }

    /// Remove all entries matching the given host from `~/.ssh/known_hosts`.
    ///
    /// Entries whose hostname patterns list contains an exact match for `host`
    /// are removed.  Hashed entries (`|1|...`) cannot be matched by name and
    /// are left untouched.
    ///
    /// The removal is performed atomically (write to a temp file, then rename)
    /// so that a crash mid-write cannot corrupt the file.
    pub async fn remove(&self, host: &str) -> Result<()> {
        let path = self.paths.known_hosts_path();
        let host = host.to_owned();

        tokio::task::spawn_blocking(move || remove_host_sync(&path, &host))
            .await
            .map_err(|e| Error::KnownHostsParseFailed(e.to_string()))?
    }

    /// Check whether a host appears in `~/.ssh/known_hosts`.
    ///
    /// Returns `true` if any entry's host pattern list contains an exact match.
    /// Both plain and bracketed (`[host]:port`) forms are checked.  Hashed
    /// entries are not matched (that would require re-hashing the hostname
    /// with the stored salt).
    pub async fn contains(&self, host: &str) -> Result<bool> {
        let entries = self.list().await?;
        Ok(entries
            .iter()
            .any(|e| e.hosts.iter().any(|h| host_pattern_matches(h, host))))
    }
}

/// Synchronous helper: read the file, filter out matching entries, write back
/// atomically via a temp file + rename.
fn remove_host_sync(path: &Path, host: &str) -> Result<()> {
    let contents = std::fs::read_to_string(path)?;

    let mut kept = String::new();
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
    let tmp_path = parent.join(format!(".known_hosts.tmp.{}", std::process::id()));
    std::fs::write(&tmp_path, &kept)?;
    if let Err(e) = std::fs::rename(&tmp_path, path) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(e.into());
    }
    Ok(())
}

/// Check whether a single host pattern from a known_hosts entry matches the
/// given target hostname.
///
/// Handles exact string match and bracketed `[host]:port` forms.
/// Does **not** expand glob patterns (`*`, `?`) or negations (`!`) — those
/// require the full SSH matching algorithm.
fn host_pattern_matches(pattern: &str, target: &str) -> bool {
    // Direct match.
    if pattern == target {
        return true;
    }
    // Handle bracketed form: [host]:port should also match host:port.
    // Compare parts directly to avoid heap allocation from format!().
    fn strip_brackets(s: &str) -> Option<(&str, &str)> {
        let inner = s.strip_prefix('[')?;
        let (host, rest) = inner.split_once("]:")?;
        Some((host, rest))
    }

    if let Some((p_host, p_port)) = strip_brackets(pattern) {
        if let Some((t_host, t_port)) = target.split_once(':') {
            if p_host == t_host && p_port == t_port {
                return true;
            }
        }
    }
    if let Some((t_host, t_port)) = strip_brackets(target) {
        if let Some((p_host, p_port)) = pattern.split_once(':') {
            if p_host == t_host && p_port == t_port {
                return true;
            }
        }
    }
    false
}

/// Check whether a known_hosts line refers to the given host.
///
/// Handles plain hostnames, comma-separated patterns, and markers.
/// Does **not** attempt to match hashed entries.
fn line_matches_host(line: &str, target: &str) -> bool {
    // Skip optional marker.
    let rest = if line.starts_with('@') {
        match line.split_once(' ') {
            Some((_, r)) => r,
            None => return false,
        }
    } else {
        line
    };

    // The host field is the first whitespace-delimited token.
    let hosts_field = match rest.split_whitespace().next() {
        Some(h) => h,
        None => return false,
    };

    // Hashed entries — cannot match by name.
    if hosts_field.starts_with("|1|") {
        return false;
    }

    // Comma-separated patterns — try each one.
    hosts_field
        .split_terminator(',')
        .any(|pattern| host_pattern_matches(pattern, target))
}
