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

static FALLBACK_IP_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").expect("hardcoded regex is valid")
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
#[derive(Debug, Clone, PartialEq)]
pub struct MatchDetail {
    /// Matched IP address (from named capture group `ip` or `host`).
    pub ip: Option<IpAddr>,
    /// The full matched line.
    pub line: String,
    /// Line number in the file.
    pub line_number: u64,
}

impl LogDetector {
    /// Create a new log detector.
    ///
    /// # Errors
    ///
    /// Returns `InvalidRegex` if the pattern is not valid regex.
    pub fn new(
        jail_name: &str,
        log_path: &Path,
        pattern: &str,
    ) -> crate::Result<Self> {
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
    pub fn set_position(&mut self, offset: u64, line_number: u64) {
        self.offset = offset;
        self.line_number = line_number;
    }

    /// Get the current journal state.
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
    /// # Errors
    ///
    /// Returns `LogFileError` if the file cannot be opened, or `Io` on read/seek failure.
    pub fn scan(&mut self) -> crate::Result<ScanResult> {
        let start = std::time::Instant::now();
        let mut new_bans = Vec::new();
        let mut matches_found = 0u32;
        let mut lines_scanned = 0u64;

        let file = fs::File::open(&self.log_path)
            .map_err(|e| crate::Error::LogFileError(format!("Cannot open '{}': {}", self.log_path.display(), e)))?;

        let mut reader = BufReader::new(file);

        if self.offset > 0 {
            reader.seek(SeekFrom::Start(self.offset))?;
        }

        let mut line = String::new();
        loop {
            line.clear();
            let bytes = reader.read_line(&mut line)?;
            if bytes == 0 {
                break;
            }

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
    pub fn match_line(&self, line: &str, line_number: u64) -> Option<MatchDetail> {
        let caps = self.regex.captures(line)?;
        let ip = Self::extract_ip_from_caps(&caps);
        Some(MatchDetail {
            ip,
            line: line.trim_end().to_string(),
            line_number,
        })
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
        // Fallback: find first IP-like pattern in the full match
        let full_match = caps.get(0)?.as_str();
        FALLBACK_IP_RE.find(full_match)
            .and_then(|m| m.as_str().parse().ok())
    }
}

fn default_prefix(ip: IpAddr) -> u8 {
    match ip {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    }
}

#[cfg(test)]
#[path = "detector.test.rs"]
mod tests;
