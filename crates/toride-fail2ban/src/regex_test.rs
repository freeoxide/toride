//! Wrapper around `fail2ban-regex` for filter testing.
//!
//! This module provides a typed interface to the `fail2ban-regex` command-line
//! tool for validating Fail2Ban filter patterns. It intentionally does **not**
//! use Rust's `regex` crate as the source of truth for regex validation, because
//! Fail2Ban uses Python regex syntax which differs from Rust's in several ways
//! (e.g. named groups, lookaheads, `<HOST>` interpolation).
//!
//! # Usage
//!
//! ```ignore
//! use toride_fail2ban::command::DuctRunner;
//! use toride_fail2ban::regex_test::RegexTester;
//!
//! let runner = DuctRunner::new();
//! let tester = RegexTester::new(&runner)?;
//!
//! // Test a single log line against a raw failregex
//! let result = tester.test_line(
//!     r"sshd\[\d+\]: Failed password for .* from <HOST>",
//!     "Mar  1 12:00:00 host sshd[1234]: Failed password for root from 10.0.0.1",
//! )?;
//! println!("matched {} of {} lines", result.lines_matched, result.lines_processed);
//! ```

use std::path::{Path, PathBuf};

use regex::Regex;

use crate::Result;
use crate::command::{CommandOutput, Runner};
use crate::report::RegexTestResult;

// ---------------------------------------------------------------------------
// RegexTester
// ---------------------------------------------------------------------------

/// Typed wrapper around the `fail2ban-regex` command.
///
/// Provides methods for testing Fail2Ban regex patterns against log lines,
/// log files, systemd journal queries, and ignore-regex patterns. All
/// invocations of `fail2ban-regex` go through the centralised [`Runner`]
/// trait -- no ad-hoc `std::process::Command` calls.
pub struct RegexTester<'a> {
    /// The command runner used to execute `fail2ban-regex`.
    runner: &'a dyn Runner,
    /// Absolute path to the `fail2ban-regex` binary.
    binary: PathBuf,
}

impl<'a> RegexTester<'a> {
    /// Create a new `RegexTester` by locating `fail2ban-regex` on `$PATH`.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::Error::NotFound`] if the binary cannot be
    /// found.
    pub fn new(runner: &'a dyn Runner) -> Result<Self> {
        let binary = crate::command::find_binary("fail2ban-regex")?;
        Ok(Self { runner, binary })
    }

    /// Create a `RegexTester` with an explicit binary path.
    ///
    /// Use this in environments where `fail2ban-regex` is installed at a
    /// non-standard location, or in tests that supply a fixture binary.
    pub fn with_binary(runner: &'a dyn Runner, binary: PathBuf) -> Self {
        Self { runner, binary }
    }

    /// Return a reference to the resolved binary path.
    pub fn binary_path(&self) -> &Path {
        &self.binary
    }

    // -----------------------------------------------------------------------
    // Public API
    // -----------------------------------------------------------------------

    /// Test a single log line against a raw failregex pattern.
    ///
    /// Runs `fail2ban-regex '{log_line}' '{regex}'` and parses the output for
    /// match statistics.
    ///
    /// # Arguments
    ///
    /// * `regex` - A Fail2Ban failregex string (may contain `<HOST>` etc.).
    /// * `log_line` - A single line of log text to test against.
    pub fn test_line(&self, regex: &str, log_line: &str) -> Result<RegexTestResult> {
        self.run_regex(&[log_line, regex])
    }

    /// Test a log file against a filter configuration file.
    ///
    /// Runs `fail2ban-regex {log_path} {filter_path}` and parses the output
    /// for aggregate match statistics.
    ///
    /// # Arguments
    ///
    /// * `filter_path` - Path to a Fail2Ban filter `.conf` file.
    /// * `log_path` - Path to a log file to scan.
    pub fn test_filter_file(&self, filter_path: &Path, log_path: &Path) -> Result<RegexTestResult> {
        let log_str = log_path.to_string_lossy();
        let filter_str = filter_path.to_string_lossy();
        self.run_regex(&[&log_str, &filter_str])
    }

    /// Test a systemd journal query against a filter configuration file.
    ///
    /// Runs `fail2ban-regex 'journal {journal_match}' {filter_path}` and
    /// parses the output for match statistics.
    ///
    /// # Arguments
    ///
    /// * `filter_path` - Path to a Fail2Ban filter `.conf` file.
    /// * `journal_match` - A journal match expression
    ///   (e.g. `_SYSTEMD_UNIT=sshd.service + _COMM=sshd`).
    pub fn test_journal(&self, filter_path: &Path, journal_match: &str) -> Result<RegexTestResult> {
        let journal_arg = format!("journal {journal_match}");
        let filter_str = filter_path.to_string_lossy();
        self.run_regex(&[&journal_arg, &filter_str])
    }

    /// Test whether a log line is caught by an ignore-regex pattern.
    ///
    /// Runs `fail2ban-regex --ignoreregex '{regex}' '{log_line}'` and returns
    /// whether the line was ignored.
    ///
    /// # Arguments
    ///
    /// * `regex` - A Fail2Ban ignoreregex pattern.
    /// * `log_line` - A single line of log text to test.
    ///
    /// # Returns
    ///
    /// A [`RegexTestResult`] where `lines_matched > 0` indicates the line was
    /// matched (and therefore would be **ignored** by Fail2Ban).
    pub fn test_ignoreregex(&self, regex: &str, log_line: &str) -> Result<RegexTestResult> {
        self.run_regex(&["--ignoreregex", regex, log_line])
    }

    /// Test a datepattern against a log line with a failregex.
    ///
    /// Runs `fail2ban-regex -f '<datepattern>' '<log_line>' '<regex>'` and
    /// parses the output for match statistics.
    ///
    /// # Arguments
    ///
    /// * `datepattern` - A Fail2Ban datepattern string (e.g. `{^LN-BEG}`).
    /// * `log_line` - A single line of log text to test against.
    /// * `regex` - A Fail2Ban failregex string (may contain `<HOST>` etc.).
    pub fn test_datepattern(
        &self,
        datepattern: &str,
        log_line: &str,
        regex: &str,
    ) -> Result<RegexTestResult> {
        self.run_regex(&["-f", datepattern, log_line, regex])
    }

    /// Test multi-line regex behavior with a specified maxlines count.
    ///
    /// Runs `fail2ban-regex -l <maxlines> '<log_line>' '<regex>'` and parses
    /// the output for match statistics.
    ///
    /// # Arguments
    ///
    /// * `maxlines` - Maximum number of lines to buffer for multi-line matching.
    /// * `log_line` - A single line of log text to test against.
    /// * `regex` - A Fail2Ban failregex string (may contain `<HOST>` etc.).
    pub fn test_maxlines(
        &self,
        maxlines: u32,
        log_line: &str,
        regex: &str,
    ) -> Result<RegexTestResult> {
        self.run_regex(&["-l", &maxlines.to_string(), log_line, regex])
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Execute `fail2ban-regex` with the given arguments and parse output.
    ///
    /// The output of `fail2ban-regex` is best-effort parsed for match
    /// statistics. Even when parsing fails, the raw output is preserved in
    /// [`RegexTestResult::output`] so callers can inspect it directly.
    ///
    /// Recognised output patterns:
    ///
    /// ```text
    /// Lines: 42 lines, 3 matched, 39 missed [...]
    /// ```
    ///
    /// ```text
    /// Sorry, no match
    /// ```
    ///
    /// ```text
    /// Found a match for ...
    /// ```
    fn run_regex(&self, args: &[&str]) -> Result<RegexTestResult> {
        let program = self.binary.to_string_lossy();
        let output = self.runner.run(&program, args)?;

        let combined = combine_output(&output);

        let (lines_matched, lines_processed) = parse_match_stats(&combined);

        // fail2ban-regex exits 0 even when there are no matches, so success is
        // purely based on the process exit code.
        Ok(RegexTestResult::new(
            lines_matched,
            lines_processed,
            combined,
            output.success,
        ))
    }
}

// ---------------------------------------------------------------------------
// Output parsing
// ---------------------------------------------------------------------------

/// Combine stdout and stderr into a single string for parsing.
///
/// `fail2ban-regex` may write useful information to either stream depending
/// on the version and invocation mode.
fn combine_output(output: &CommandOutput) -> String {
    if output.stderr.is_empty() {
        output.stdout.clone()
    } else if output.stdout.is_empty() {
        output.stderr.clone()
    } else {
        format!("{}\n{}", output.stdout, output.stderr)
    }
}

/// Best-effort extraction of match statistics from `fail2ban-regex` output.
///
/// Looks for patterns like:
///
/// ```text
/// Lines: 42 lines, 3 matched, 39 missed [...]
/// ```
///
/// Falls back to counting "Found a match" / "Sorry, no match" lines when the
/// summary line is not present. Returns `(0, 0)` when nothing is recognised.
fn parse_match_stats(text: &str) -> (usize, usize) {
    // Primary pattern: "Lines: X lines, Y matched, Z missed [...]"
    // Use a regex to capture total and matched directly from the summary line.
    let re = Regex::new(r"(?i)Lines:\s*(\d+)\s+lines,\s*(\d+)\s+matched")
        .expect("hardcoded regex should always compile");

    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(caps) = re.captures(trimmed) {
            let total: usize = caps[1].parse().unwrap_or(0);
            let matched: usize = caps[2].parse().unwrap_or(0);
            return (matched, total);
        }
    }

    // "Sorry, no match" / "No match found" -> no matches, one line processed.
    if text.contains("Sorry, no match") || text.contains("No match found") {
        return (0, 1);
    }

    // Fallback: count individual "Found a match" lines.
    let lines_matched = count_matches(text);
    let lines_processed = count_processed(text).unwrap_or(lines_matched);

    (lines_matched, lines_processed)
}

/// Count occurrences of "Found a match" indicators in the output.
fn count_matches(text: &str) -> usize {
    text.lines()
        .filter(|line| {
            let l = line.trim();
            l.contains("Found a match") || l.contains("found a match")
        })
        .count()
}

/// Try to determine the total number of processed lines from the output.
///
/// Falls back to the count of "Sorry, no match" lines plus matched lines when
/// a summary is absent.
fn count_processed(text: &str) -> Option<usize> {
    let matched = count_matches(text);
    let missed = text
        .lines()
        .filter(|line| {
            let l = line.trim();
            l.contains("Sorry, no match") || l.contains("no match")
        })
        .count();

    if matched > 0 || missed > 0 {
        Some(matched + missed)
    } else {
        None
    }
}

#[cfg(test)]
#[path = "regex_test.test.rs"]
mod tests;
