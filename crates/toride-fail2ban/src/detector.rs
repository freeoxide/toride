//! Regex-based log line matching and detection.
//!
//! Parses log files incrementally, tracking position to avoid re-reading.

use std::fs;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::net::IpAddr;
use std::path::Path;
use std::sync::LazyLock;

use chrono::Utc;
use regex::Regex;

use crate::store::JournalEntry;
use crate::types::{BanEntry, ScanResult};

/// Maximum number of bytes allowed in a single log line before the scan aborts.
/// This prevents OOM on corrupted or binary files that lack newline characters.
const MAX_LINE_BYTES: usize = 1024 * 1024; // 1 MiB

static FALLBACK_IPV4_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").expect("hardcoded regex is valid"));

static FALLBACK_IPV6_RE: LazyLock<Regex> = LazyLock::new(|| {
    // Matches full IPv6 addresses including compressed :: forms.
    // More specific alternatives (ending with a hex group) come before less
    // specific ones (ending with just `:`) so the regex engine prefers the
    // longer match.
    Regex::new(r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}\b|(?:[0-9a-fA-F]{1,4}:){1,7}:|::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}\b")
        .expect("hardcoded regex is valid")
});

/// A log detector that matches lines against a regex pattern.
#[derive(Debug)]
pub struct LogDetector {
    /// Compiled regex pattern.
    regex: Regex,
    /// Name of the jail this detector belongs to.
    jail_name: String,
    /// Path to the log file.
    log_path: std::path::PathBuf,
    /// Last known offset in the log file.
    offset: u64,
    /// Last known line number.
    line_number: u64,
}

/// Details extracted from a single regex match.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MatchDetail {
    /// Matched IP address (from named capture group `ip` or `host`).
    pub ip: Option<IpAddr>,
    /// Line number in the file.
    pub line_number: u64,
}

impl LogDetector {
    /// Create a new log detector.
    ///
    /// # Errors
    ///
    /// Returns `InvalidRegex` if the pattern is not valid regex.
    pub fn new(jail_name: &str, log_path: &Path, pattern: &str) -> crate::Result<Self> {
        let regex = Regex::new(pattern)
            .map_err(|e| crate::Error::InvalidRegex(format!("Invalid regex '{pattern}': {e}")))?;

        Ok(Self {
            regex,
            jail_name: jail_name.to_string(),
            log_path: log_path.to_path_buf(),
            offset: 0,
            line_number: 0,
        })
    }

    /// Set the starting offset and line number from a journal entry.
    pub const fn set_position(&mut self, offset: u64, line_number: u64) {
        self.offset = offset;
        self.line_number = line_number;
    }

    /// Get the current journal state.
    #[must_use]
    pub fn journal(&self) -> JournalEntry {
        JournalEntry {
            jail_name: self.jail_name.clone(),
            log_path: self.log_path.clone(),
            offset: self.offset,
            line_number: self.line_number,
            updated_at: Utc::now(),
        }
    }

    /// Scan the log file from the last known position.
    ///
    /// Uses `read_until` with UTF-8 lossy conversion to handle non-UTF-8 log files
    /// gracefully. Non-UTF-8 bytes are replaced with the Unicode replacement character.
    ///
    /// # Errors
    ///
    /// Returns `LogFileError` if the file cannot be opened, or `Io` on read/seek failure.
    pub fn scan(&mut self) -> crate::Result<ScanResult> {
        let start = std::time::Instant::now();
        let mut new_bans = Vec::new();
        let mut matches_found = 0u32;
        let mut lines_scanned = 0u64;

        let file = fs::File::open(&self.log_path).map_err(|e| {
            crate::Error::LogFileError(format!("Cannot open '{}': {}", self.log_path.display(), e))
        })?;

        // Use a 64KB buffer for better performance on large log files.
        let mut reader = BufReader::with_capacity(65536, file);

        if self.offset > 0 {
            // Detect log rotation: if the stored offset exceeds the current file
            // size, the log was likely rotated. Reset to the beginning so we
            // don't silently skip the entire new file.
            let file_size = reader.get_ref().metadata().map_or(0, |m| m.len());
            if file_size < self.offset {
                tracing::warn!(
                    jail = %self.jail_name,
                    path = %self.log_path.display(),
                    stored_offset = self.offset,
                    file_size,
                    "log file appears rotated (stored offset exceeds file size); resetting to start"
                );
                self.offset = 0;
                self.line_number = 0;
            }
            reader.seek(SeekFrom::Start(self.offset))?;
        }

        let mut raw_line = Vec::new();
        loop {
            raw_line.clear();
            let bytes = reader.read_until(b'\n', &mut raw_line)?;
            if bytes == 0 {
                break;
            }

            // Guard against unbounded lines (e.g. binary files without newlines)
            // that could exhaust memory.
            if raw_line.len() > MAX_LINE_BYTES {
                return Err(crate::Error::LogFileError(format!(
                    "log line exceeds {} bytes at offset {}; aborting to prevent OOM",
                    MAX_LINE_BYTES,
                    self.offset + raw_line.len() as u64,
                )));
            }

            // Convert to UTF-8 lossily, replacing invalid bytes with replacement char.
            let line = String::from_utf8_lossy(&raw_line);

            self.line_number += 1;
            lines_scanned += 1;
            self.offset += bytes as u64;

            if let Some(detail) = self.match_line(&line, self.line_number) {
                matches_found += 1;
                if let Some(ip) = detail.ip {
                    new_bans.push(BanEntry {
                        ip,
                        prefix: default_prefix(ip),
                        banned_at: Utc::now(),
                        expires_at: None,
                        jail_name: self.jail_name.clone(),
                        fail_count: 1,
                        last_fail_at: Utc::now(),
                        reason: Some(format!("Matched line {}", detail.line_number)),
                    });
                }
            }
        }

        let scan_duration = start.elapsed();

        Ok(ScanResult {
            new_bans,
            lines_scanned,
            matches_found,
            scan_duration,
        })
    }

    /// Match a single line against the pattern.
    pub(crate) fn match_line(&self, line: &str, line_number: u64) -> Option<MatchDetail> {
        let caps = self.regex.captures(line)?;
        let ip = Self::extract_ip_from_caps(&caps);
        Some(MatchDetail { ip, line_number })
    }

    /// Extract IP address from capture groups.
    /// Looks for `ip` or `host` named groups, falls back to first IP-like match.
    fn extract_ip_from_caps(caps: &regex::Captures) -> Option<IpAddr> {
        if let Some(ip_match) = caps.name("ip")
            && let Ok(ip) = ip_match.as_str().parse()
        {
            return Some(ip);
        }
        if let Some(host_match) = caps.name("host")
            && let Ok(ip) = host_match.as_str().parse()
        {
            return Some(ip);
        }
        // Fallback: find first IP-like pattern in the full match.
        // Try IPv4 first (more common), then IPv6.
        let full_match = caps.get(0)?.as_str();
        if let Some(ip) = FALLBACK_IPV4_RE
            .find(full_match)
            .and_then(|m| m.as_str().parse().ok())
        {
            return Some(ip);
        }
        FALLBACK_IPV6_RE
            .find(full_match)
            .and_then(|m| m.as_str().parse().ok())
    }
}

use crate::types::default_prefix;

#[cfg(test)]
#[path = "detector.test.rs"]
mod tests;
