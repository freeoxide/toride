//! Regex-based log line matching and detection.
//!
//! Parses log files incrementally, tracking position to avoid re-reading.

use std::fs;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::net::IpAddr;
use std::path::Path;
use std::sync::LazyLock;
use std::time::Duration;

use chrono::Utc;
use regex::Regex;

use crate::store::JournalEntry;
use crate::types::normalize_ip;

/// Maximum number of bytes allowed in a single log line before the scan aborts.
/// This prevents OOM on corrupted or binary files that lack newline characters.
const MAX_LINE_BYTES: usize = 1024 * 1024;

static FALLBACK_IPV4_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").expect("hardcoded regex is valid"));

static FALLBACK_IPV6_RE: LazyLock<Regex> = LazyLock::new(|| {
    // Longer (hex-terminated) alternatives first so the engine keeps full
    // addresses; extract_ip_from_caps relies on complete candidates.
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
    /// Device id of the scanned file at the last scan (0 when unknown).
    dev: u64,
    /// Inode of the scanned file at the last scan (0 when unknown).
    ino: u64,
}

/// Outcome of one bounded line read.
enum LineRead {
    /// The line was terminated by a newline.
    Complete,
    /// EOF or the line cap was reached before a newline.
    Partial,
}

/// Details extracted from a single regex match.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MatchDetail {
    /// Matched IP address (from named capture group `ip` or `host`).
    pub ip: Option<IpAddr>,
    /// Line number in the file.
    pub line_number: u64,
}

/// A threshold-free ban candidate produced by [`LogDetector::scan`].
///
/// Carries only what the match itself establishes. The consumer
/// ([`crate::jail::Jail`]) stamps jail name, timestamps, prefix, and
/// reason when it stages a `BanEntry`, so the scan loop does not clone or
/// format them per matched line.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MatchCandidate {
    /// Extracted source address (named `ip`/`host` group, or the rightmost
    /// fallback candidate). IPv4-mapped IPv6 is normalized to IPv4.
    pub ip: IpAddr,
    /// Line number of the match.
    pub line_number: u64,
}

/// Summary of one [`LogDetector::scan`] pass.
#[derive(Debug)]
pub struct DetectorResult {
    /// One candidate per matching line that yielded an extractable IP.
    pub candidates: Vec<MatchCandidate>,
    /// Complete lines read this scan.
    pub lines_scanned: u64,
    /// Matching lines this scan, with or without an extractable IP.
    pub matches_found: u32,
    /// Wall time of the scan.
    pub scan_duration: Duration,
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
            dev: 0,
            ino: 0,
        })
    }

    /// Set the starting offset, line number, and file identity from a
    /// journal entry.
    pub const fn set_position(&mut self, offset: u64, line_number: u64, dev: u64, ino: u64) {
        self.offset = offset;
        self.line_number = line_number;
        self.dev = dev;
        self.ino = ino;
    }

    /// Get the current journal state.
    #[must_use]
    pub fn journal(&self) -> JournalEntry {
        JournalEntry {
            jail_name: self.jail_name.clone(),
            log_path: self.log_path.clone(),
            offset: self.offset,
            line_number: self.line_number,
            dev: self.dev,
            ino: self.ino,
            updated_at: Utc::now(),
        }
    }

    /// Scan the log file from the last known position.
    ///
    /// Non-UTF-8 bytes are replaced with the Unicode replacement character
    /// before matching.
    ///
    /// A trailing partial line (a write in progress at scan time) is held back:
    /// it is not matched and the offset does not advance past it, so the
    /// completed line is re-scanned whole on the next cycle.
    ///
    /// Rotation is detected by device id and inode change (falling back to a
    /// stored-offset-exceeds-file-size check for journals persisted before
    /// identity tracking); on rotation the scan restarts from byte zero.
    ///
    /// # Errors
    ///
    /// Returns `LogFileError` if the file cannot be opened or a single line
    /// exceeds [`MAX_LINE_BYTES`], or `Io` on read/seek failure.
    pub fn scan(&mut self) -> crate::Result<DetectorResult> {
        let start = std::time::Instant::now();
        let mut candidates = Vec::new();
        let mut matches_found = 0u32;
        let mut lines_scanned = 0u64;

        let file = fs::File::open(&self.log_path).map_err(|e| {
            crate::Error::LogFileError(format!("Cannot open '{}': {}", self.log_path.display(), e))
        })?;
        let metadata = file.metadata()?;
        let (dev, ino) = file_identity(&metadata);

        let mut reader = BufReader::with_capacity(65536, file);

        if self.offset > 0 {
            let identity_known = self.dev != 0 || self.ino != 0;
            let rotated = (identity_known && (self.dev, self.ino) != (dev, ino))
                || metadata.len() < self.offset;
            if rotated {
                tracing::warn!(
                    jail = %self.jail_name,
                    path = %self.log_path.display(),
                    stored_offset = self.offset,
                    file_size = metadata.len(),
                    "log file appears rotated; resetting to start"
                );
                self.offset = 0;
                self.line_number = 0;
            }
            reader.seek(SeekFrom::Start(self.offset))?;
        }
        self.dev = dev;
        self.ino = ino;

        let mut raw_line: Vec<u8> = Vec::with_capacity(512);
        loop {
            raw_line.clear();
            let status = Self::read_line_bounded(&mut reader, &mut raw_line)?;

            if raw_line.is_empty() {
                break;
            }

            if raw_line.len() > MAX_LINE_BYTES {
                return Err(crate::Error::LogFileError(format!(
                    "log line exceeds {} bytes at offset {}; aborting to prevent OOM",
                    MAX_LINE_BYTES,
                    self.offset + raw_line.len() as u64,
                )));
            }

            if !matches!(status, LineRead::Complete) {
                break;
            }

            let bytes = raw_line.len();
            let line = String::from_utf8_lossy(&raw_line);

            self.line_number += 1;
            lines_scanned += 1;
            self.offset += bytes as u64;

            if let Some(detail) = self.match_line(&line, self.line_number) {
                matches_found += 1;
                if let Some(ip) = detail.ip {
                    candidates.push(MatchCandidate {
                        ip,
                        line_number: detail.line_number,
                    });
                }
            }
        }

        let scan_duration = start.elapsed();

        Ok(DetectorResult {
            candidates,
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

    /// Read one newline-terminated line into `raw_line`, never buffering
    /// more than [`MAX_LINE_BYTES`] + 1 bytes of it.
    fn read_line_bounded(
        reader: &mut BufReader<fs::File>,
        raw_line: &mut Vec<u8>,
    ) -> std::io::Result<LineRead> {
        loop {
            let (buffered, consumed, found) = {
                let buf = reader.fill_buf()?;
                if buf.is_empty() {
                    return Ok(LineRead::Partial);
                }
                let budget = (MAX_LINE_BYTES + 1) - raw_line.len();
                let window = &buf[..buf.len().min(budget)];
                if let Some(pos) = window.iter().position(|&b| b == b'\n') {
                    raw_line.extend_from_slice(&window[..=pos]);
                    (buf.len(), pos + 1, true)
                } else {
                    let end = window.len();
                    raw_line.extend_from_slice(window);
                    (buf.len(), end, false)
                }
            };
            reader.consume(consumed);
            if found {
                return Ok(LineRead::Complete);
            }
            let cap_reached = consumed < buffered;
            if cap_reached {
                return Ok(LineRead::Partial);
            }
        }
    }

    /// Extract IP address from capture groups.
    ///
    /// Prefers the `ip` or `host` named group; the groupless fallback takes
    /// the rightmost IP-like candidate inside the matched span, because
    /// attacker-influenced fields (usernames, URLs) usually precede the
    /// source address and a first-match fallback can be aimed at a decoy.
    fn extract_ip_from_caps(caps: &regex::Captures) -> Option<IpAddr> {
        for name in ["ip", "host"] {
            if let Some(group) = caps.name(name)
                && let Ok(ip) = group.as_str().parse::<IpAddr>()
            {
                return Some(normalize_ip(ip));
            }
        }
        let full_match = caps.get(0)?.as_str();
        let mut rightmost: Option<(usize, IpAddr)> = None;
        for candidate in FALLBACK_IPV4_RE
            .find_iter(full_match)
            .chain(FALLBACK_IPV6_RE.find_iter(full_match))
        {
            if let Ok(ip) = candidate.as_str().parse::<IpAddr>()
                && rightmost
                    .as_ref()
                    .is_none_or(|(start, _)| candidate.start() >= *start)
            {
                rightmost = Some((candidate.start(), normalize_ip(ip)));
            }
        }
        rightmost.map(|(_, ip)| ip)
    }
}

#[cfg(unix)]
fn file_identity(metadata: &fs::Metadata) -> (u64, u64) {
    use std::os::unix::fs::MetadataExt;
    (metadata.dev(), metadata.ino())
}

#[cfg(not(unix))]
fn file_identity(_metadata: &fs::Metadata) -> (u64, u64) {
    (0, 0)
}

#[cfg(test)]
#[path = "detector.test.rs"]
mod tests;
