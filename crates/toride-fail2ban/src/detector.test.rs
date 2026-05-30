use super::*;
use std::io::Write;
use tempfile::NamedTempFile;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Create a `LogDetector` backed by a temporary file with the given content.
fn detector_with_content(content: &str, pattern: &str) -> (LogDetector, NamedTempFile) {
    let tmp = NamedTempFile::new().expect("failed to create temp file");
    let mut file = tmp.reopen().expect("failed to reopen temp file");
    file.write_all(content.as_bytes()).expect("failed to write");
    file.flush().expect("failed to flush");

    let detector = LogDetector::new("test-jail", tmp.path(), pattern)
        .expect("LogDetector::new should succeed");
    (detector, tmp)
}

// ===========================================================================
// new()
// ===========================================================================

#[test]
fn new_valid_pattern_compiles() {
    let tmp = NamedTempFile::new().unwrap();
    let result = LogDetector::new("jail", tmp.path(), r#"Failed password from (?P<ip>\S+)"#);
    assert!(result.is_ok(), "valid regex should compile");
}

#[test]
fn new_invalid_regex_returns_error() {
    let tmp = NamedTempFile::new().unwrap();
    let result = LogDetector::new("jail", tmp.path(), r#"(unclosed"#);
    assert!(result.is_err());
    match result.unwrap_err() {
        crate::Error::InvalidRegex(msg) => {
            assert!(msg.contains("(unclosed"), "error should mention the bad pattern");
        }
        other => panic!("expected InvalidRegex, got {:?}", other),
    }
}

#[test]
fn new_compiles_simple_literals() {
    let tmp = NamedTempFile::new().unwrap();
    let result = LogDetector::new("jail", tmp.path(), "error");
    assert!(result.is_ok());
}

// ===========================================================================
// match_line()
// ===========================================================================

#[test]
fn match_line_returns_detail_on_match() {
    let (detector, _tmp) = detector_with_content(
        "Failed password from 192.168.1.1\n",
        r"Failed password from (?P<ip>\S+)",
    );
    let detail = detector.match_line("Failed password from 10.0.0.1", 42);
    assert!(detail.is_some());
    let detail = detail.unwrap();
    assert_eq!(detail.ip, Some("10.0.0.1".parse().unwrap()));
    assert_eq!(detail.line, "Failed password from 10.0.0.1");
    assert_eq!(detail.line_number, 42);
}

#[test]
fn match_line_returns_none_on_no_match() {
    let (detector, _tmp) = detector_with_content(
        "irrelevant\n",
        r"Failed password from (?P<ip>\S+)",
    );
    let detail = detector.match_line("Accepted publickey for user", 1);
    assert!(detail.is_none());
}

#[test]
fn match_line_preserves_line_number() {
    let (detector, _tmp) = detector_with_content("anything\n", "anything");
    let detail = detector.match_line("anything", 999).unwrap();
    assert_eq!(detail.line_number, 999);
}

#[test]
fn match_line_trims_trailing_whitespace() {
    let (detector, _tmp) = detector_with_content("match\n", "match");
    let detail = detector.match_line("match\r\n", 5).unwrap();
    assert_eq!(detail.line, "match");
}

#[test]
fn match_line_with_no_capture_groups_still_matches() {
    let (detector, _tmp) = detector_with_content("error occurred\n", "error occurred");
    let detail = detector.match_line("error occurred", 1).unwrap();
    assert!(detail.ip.is_none());
    assert_eq!(detail.line, "error occurred");
}

// ===========================================================================
// extract_ip()
// ===========================================================================

#[test]
fn extract_ip_from_named_group_ip() {
    let (detector, _tmp) = detector_with_content(
        "anything\n",
        r"(?P<ip>\d+\.\d+\.\d+\.\d+) login failure",
    );
    let detail = detector.match_line("10.20.30.40 login failure", 1).unwrap();
    assert_eq!(detail.ip, Some("10.20.30.40".parse().unwrap()));
}

#[test]
fn extract_ip_from_named_group_host() {
    let (detector, _tmp) = detector_with_content(
        "anything\n",
        r"(?P<host>\d+\.\d+\.\d+\.\d+) auth fail",
    );
    let detail = detector.match_line("172.16.0.5 auth fail", 1).unwrap();
    assert_eq!(detail.ip, Some("172.16.0.5".parse().unwrap()));
}

#[test]
fn extract_ip_prefers_ip_over_host() {
    // Pattern has both `ip` and `host` named groups; `ip` should take priority.
    let (detector, _tmp) = detector_with_content(
        "anything\n",
        r"(?P<host>\S+) -> (?P<ip>\d+\.\d+\.\d+\.\d+)",
    );
    let detail = detector.match_line("server -> 10.0.0.99", 1).unwrap();
    assert_eq!(detail.ip, Some("10.0.0.99".parse().unwrap()));
}

#[test]
fn extract_ip_fallback_to_first_ip_pattern() {
    // No named groups; should fall back to IP-like regex.
    let (detector, _tmp) = detector_with_content("anything\n", r"connection from .* refused");
    let detail = detector
        .match_line("connection from 192.168.55.1 refused", 1)
        .unwrap();
    assert_eq!(detail.ip, Some("192.168.55.1".parse().unwrap()));
}

#[test]
fn extract_ip_returns_none_when_no_ip_present() {
    // No named groups and no IP-like string in line.
    let (detector, _tmp) = detector_with_content("anything\n", r"error.*");
    let detail = detector.match_line("error something happened", 1).unwrap();
    assert!(detail.ip.is_none());
}

#[test]
fn extract_ip_with_ipv6_via_named_group() {
    // IPv6 does not match the fallback IPv4-only regex, but named groups still work.
    let (detector, _tmp) = detector_with_content(
        "anything\n",
        r"from (?P<ip>[0-9a-fA-F:]+) port",
    );
    let detail = detector
        .match_line("from ::1 port 22", 1)
        .unwrap();
    assert_eq!(detail.ip, Some("::1".parse().unwrap()));
}

#[test]
fn extract_ip_fallback_does_not_match_ipv6() {
    // Fallback IP regex is IPv4-only; IPv6 should yield None through fallback.
    let (detector, _tmp) = detector_with_content("anything\n", r"blocked .*");
    let detail = detector
        .match_line("blocked 2001:0db8::1 request", 1)
        .unwrap();
    // The fallback regex only looks for IPv4 patterns, so no match expected.
    assert!(detail.ip.is_none());
}

// ===========================================================================
// scan()
// ===========================================================================

#[test]
fn scan_empty_file_returns_zero_counts() {
    let (mut detector, _tmp) = detector_with_content("", r"Failed.*(?P<ip>\d+\.\d+\.\d+\.\d+)");
    let result = detector.scan().expect("scan should succeed");
    assert_eq!(result.lines_scanned, 0);
    assert_eq!(result.matches_found, 0);
    assert!(result.new_bans.is_empty());
}

#[test]
fn scan_file_with_matching_lines() {
    let content = "\
Failed password from 10.0.0.1 port 22
Failed password from 10.0.0.2 port 22
";
    let (mut detector, _tmp) = detector_with_content(
        content,
        r"Failed password from (?P<ip>\d+\.\d+\.\d+\.\d+)",
    );
    let result = detector.scan().expect("scan should succeed");

    assert_eq!(result.lines_scanned, 2);
    assert_eq!(result.matches_found, 2);
    assert_eq!(result.new_bans.len(), 2);
    assert_eq!(result.new_bans[0].ip.to_string(), "10.0.0.1");
    assert_eq!(result.new_bans[1].ip.to_string(), "10.0.0.2");
}

#[test]
fn scan_file_with_no_matches() {
    let content = "\
accepted login for admin
connection established
";
    let (mut detector, _tmp) = detector_with_content(
        content,
        r"Failed password from (?P<ip>\d+\.\d+\.\d+\.\d+)",
    );
    let result = detector.scan().expect("scan should succeed");

    assert_eq!(result.lines_scanned, 2);
    assert_eq!(result.matches_found, 0);
    assert!(result.new_bans.is_empty());
}

#[test]
fn scan_incremental_from_offset() {
    let content = "\
line one\n\
line two\n\
line three\n\
";
    // First scan consumes all lines.
    let (mut detector, _tmp) = detector_with_content(content, r"line \w+");
    let first = detector.scan().expect("first scan");
    assert_eq!(first.lines_scanned, 3);
    assert_eq!(first.matches_found, 3);

    // Second scan on same file should find 0 new lines (position is past EOF).
    let second = detector.scan().expect("second scan");
    assert_eq!(second.lines_scanned, 0);
    assert_eq!(second.matches_found, 0);
    assert!(second.new_bans.is_empty());
}

#[test]
fn scan_incremental_with_appended_content() {
    let tmp = NamedTempFile::new().unwrap();
    let mut file = tmp.reopen().unwrap();
    write!(file, "line one\n").unwrap();
    file.flush().unwrap();

    let mut detector = LogDetector::new("test-jail", tmp.path(), r"line \w+").unwrap();
    let first = detector.scan().unwrap();
    assert_eq!(first.lines_scanned, 1);

    // Append a new line (must use append mode so writes go to end of file).
    let mut file = std::fs::OpenOptions::new().append(true).open(tmp.path()).unwrap();
    write!(file, "line two\n").unwrap();
    file.flush().unwrap();

    let second = detector.scan().unwrap();
    assert_eq!(second.lines_scanned, 1);
    assert_eq!(second.matches_found, 1);
}

#[test]
fn scan_multiple_matches_in_single_scan_produces_ban_entries() {
    let content = "\
Failed from 10.0.0.1
Failed from 10.0.0.1
Failed from 10.0.0.2
";
    let (mut detector, _tmp) = detector_with_content(
        content,
        r"Failed from (?P<ip>\d+\.\d+\.\d+\.\d+)",
    );
    let result = detector.scan().unwrap();
    assert_eq!(result.matches_found, 3);
    assert_eq!(result.new_bans.len(), 3);
    // Verify individual IPs (including the duplicate).
    assert_eq!(result.new_bans[0].ip.to_string(), "10.0.0.1");
    assert_eq!(result.new_bans[1].ip.to_string(), "10.0.0.1");
    assert_eq!(result.new_bans[2].ip.to_string(), "10.0.0.2");
}

#[test]
fn scan_ban_entry_has_correct_jail_name() {
    let content = "Failed from 10.0.0.1\n";
    let (mut detector, _tmp) = detector_with_content(
        content,
        r"Failed from (?P<ip>\d+\.\d+\.\d+\.\d+)",
    );
    let result = detector.scan().unwrap();
    assert_eq!(result.new_bans[0].jail_name, "test-jail");
}

#[test]
fn scan_ban_entry_prefix_is_32_for_ipv4() {
    let content = "Failed from 10.0.0.1\n";
    let (mut detector, _tmp) = detector_with_content(
        content,
        r"Failed from (?P<ip>\d+\.\d+\.\d+\.\d+)",
    );
    let result = detector.scan().unwrap();
    assert_eq!(result.new_bans[0].prefix, 32);
}

#[test]
fn scan_duration_is_accessible() {
    let content = "Failed from 10.0.0.1\n";
    let (mut detector, _tmp) = detector_with_content(
        content,
        r"Failed from (?P<ip>\d+\.\d+\.\d+\.\d+)",
    );
    let result = detector.scan().unwrap();
    // Duration can technically be zero for very fast I/O, but the field must exist.
    // Just assert we can access it without panic.
    let _ = result.scan_duration;
}

#[test]
fn scan_returns_error_for_missing_file() {
    let result = LogDetector::new("jail", std::path::Path::new("/nonexistent/path/log.txt"), "pattern");
    // new() succeeds (it doesn't check file existence).
    let mut detector = result.unwrap();
    let scan_result = detector.scan();
    assert!(scan_result.is_err());
    match scan_result.unwrap_err() {
        crate::Error::LogFileError(msg) => {
            assert!(msg.contains("Cannot open"), "error should mention open failure");
        }
        other => panic!("expected LogFileError, got {:?}", other),
    }
}

#[test]
fn scan_match_without_ip_produces_no_ban_but_counts_match() {
    let content = "error something happened\n";
    let (mut detector, _tmp) = detector_with_content(content, r"error.*");
    let result = detector.scan().unwrap();
    assert_eq!(result.matches_found, 1);
    assert!(result.new_bans.is_empty(), "no IP means no ban entry");
}

// ===========================================================================
// set_position()
// ===========================================================================

#[test]
fn set_position_updates_offset_and_line_number() {
    let (mut detector, _tmp) = detector_with_content("line\n", "line");
    detector.set_position(100, 50);
    let journal = detector.journal();
    assert_eq!(journal.offset, 100);
    assert_eq!(journal.line_number, 50);
}

#[test]
fn set_position_affects_scan_start() {
    let content = "aaa\nbbb\nccc\n";
    let tmp = NamedTempFile::new().unwrap();
    let mut file = tmp.reopen().unwrap();
    file.write_all(content.as_bytes()).unwrap();
    file.flush().unwrap();

    let mut detector = LogDetector::new("test-jail", tmp.path(), r"\w+").unwrap();

    // Set position past the first line ("aaa\n" = 4 bytes).
    detector.set_position(4, 1);

    let result = detector.scan().unwrap();
    // Should only scan "bbb" and "ccc".
    assert_eq!(result.lines_scanned, 2);
    assert_eq!(result.matches_found, 2);
}

#[test]
fn set_position_zero_resets() {
    let (mut detector, _tmp) = detector_with_content("line\n", "line");
    detector.set_position(999, 999);
    detector.set_position(0, 0);

    let journal = detector.journal();
    assert_eq!(journal.offset, 0);
    assert_eq!(journal.line_number, 0);
}

// ===========================================================================
// journal()
// ===========================================================================

#[test]
fn journal_returns_initial_state() {
    let tmp = NamedTempFile::new().unwrap();
    let detector = LogDetector::new("my-jail", tmp.path(), "pattern").unwrap();
    let journal = detector.journal();

    assert_eq!(journal.jail_name, "my-jail");
    assert_eq!(journal.log_path, tmp.path());
    assert_eq!(journal.offset, 0);
    assert_eq!(journal.line_number, 0);
}

#[test]
fn journal_reflects_scan_progress() {
    let content = "aaa\nbbb\n";
    let tmp = NamedTempFile::new().unwrap();
    let mut file = tmp.reopen().unwrap();
    file.write_all(content.as_bytes()).unwrap();
    file.flush().unwrap();

    let mut detector = LogDetector::new("j", tmp.path(), r"\w+").unwrap();
    detector.scan().unwrap();

    let journal = detector.journal();
    assert_eq!(journal.offset, content.len() as u64);
    assert_eq!(journal.line_number, 2);
}

#[test]
fn journal_reflects_set_position() {
    let (mut detector, _tmp) = detector_with_content("", "pattern");
    detector.set_position(42, 7);
    let journal = detector.journal();
    assert_eq!(journal.offset, 42);
    assert_eq!(journal.line_number, 7);
}

#[test]
fn journal_has_updated_at_timestamp() {
    let (detector, _tmp) = detector_with_content("", "pattern");
    let journal = detector.journal();
    // Should not panic; updated_at is set to Utc::now().
    let _ = journal.updated_at;
}

// ===========================================================================
// Edge cases
// ===========================================================================

#[test]
fn edge_case_very_long_line() {
    // Construct a line longer than the default BufReader buffer (8 KiB).
    let long_ip = "10.0.0.1";
    let padding = "x".repeat(16_000);
    let line = format!("Failed {} {}\n", long_ip, padding);
    let (mut detector, _tmp) = detector_with_content(
        &line,
        r"Failed (?P<ip>\d+\.\d+\.\d+\.\d+)",
    );
    let result = detector.scan().unwrap();
    assert_eq!(result.lines_scanned, 1);
    assert_eq!(result.matches_found, 1);
    assert_eq!(result.new_bans[0].ip.to_string(), "10.0.0.1");
}

#[test]
fn edge_case_no_trailing_newline_at_eof() {
    let content = "Failed from 10.0.0.1";
    let (mut detector, _tmp) = detector_with_content(
        content,
        r"Failed from (?P<ip>\d+\.\d+\.\d+\.\d+)",
    );
    let result = detector.scan().unwrap();
    // The last line without a newline should still be read.
    assert_eq!(result.lines_scanned, 1);
    assert_eq!(result.matches_found, 1);
}

#[test]
fn edge_case_pattern_with_no_capture_groups() {
    let content = "error: something failed\n";
    let (mut detector, _tmp) = detector_with_content(content, r"error: .*");
    let result = detector.scan().unwrap();
    assert_eq!(result.matches_found, 1);
    // No capture groups => no IP extraction => no ban entry.
    assert!(result.new_bans.is_empty());
}

#[test]
fn edge_case_pattern_with_multiple_named_groups() {
    // `ip` group should take priority.
    let content = "user admin from 10.0.0.1\n";
    let (mut detector, _tmp) = detector_with_content(
        content,
        r"user (?P<host>\w+) from (?P<ip>\d+\.\d+\.\d+\.\d+)",
    );
    let result = detector.scan().unwrap();
    assert_eq!(result.matches_found, 1);
    assert_eq!(result.new_bans[0].ip.to_string(), "10.0.0.1");
}

#[test]
fn edge_case_empty_lines_in_file() {
    let content = "\n\n\n";
    let (mut detector, _tmp) = detector_with_content(content, r".+");
    let result = detector.scan().unwrap();
    assert_eq!(result.lines_scanned, 3);
    assert_eq!(result.matches_found, 0, "empty lines should not match .+");
}

#[test]
fn edge_case_match_line_ip_with_invalid_octets() {
    // IP regex fallback matches 999.999.999.999 even though it's not a valid IP.
    // The scan method then tries to parse it and fails, so no ban entry.
    let content = "connection from 999.999.999.999 failed\n";
    let (mut detector, _tmp) = detector_with_content(content, r"connection from .* failed");
    let result = detector.scan().unwrap();
    assert_eq!(result.matches_found, 1);
    // 999.999.999.999 is not a valid IpAddr, so no ban entry is created.
    assert!(result.new_bans.is_empty());
}

#[test]
fn edge_case_multiple_scans_accumulate_position() {
    let tmp = NamedTempFile::new().unwrap();
    let mut file = tmp.reopen().unwrap();
    write!(file, "a\nb\n").unwrap();
    file.flush().unwrap();

    let mut detector = LogDetector::new("j", tmp.path(), r"\w+").unwrap();

    // Scan once: should read both lines.
    let r1 = detector.scan().unwrap();
    assert_eq!(r1.lines_scanned, 2);

    // Append more content (must use append mode so writes go to end of file).
    let mut file = std::fs::OpenOptions::new().append(true).open(tmp.path()).unwrap();
    write!(file, "c\n").unwrap();
    file.flush().unwrap();

    // Scan again: should only read the new line.
    let r2 = detector.scan().unwrap();
    assert_eq!(r2.lines_scanned, 1);

    let journal = detector.journal();
    assert_eq!(journal.line_number, 3);
}

#[test]
fn extract_ip_fallback_picks_first_ip_in_line() {
    let content = "proxy 10.0.0.1 forwarded to 10.0.0.2\n";
    let (detector, _tmp) = detector_with_content(content, r"proxy .* forwarded");
    let detail = detector.match_line("proxy 10.0.0.1 forwarded to 10.0.0.2", 1).unwrap();
    // Fallback regex finds the first IP-like match.
    assert_eq!(detail.ip, Some("10.0.0.1".parse().unwrap()));
}

#[test]
fn new_with_empty_pattern() {
    let tmp = NamedTempFile::new().unwrap();
    let result = LogDetector::new("jail", tmp.path(), "");
    // Empty pattern is valid in regex (matches everything).
    assert!(result.is_ok());
}

#[test]
fn scan_result_types_are_correct() {
    let content = "match\n";
    let (mut detector, _tmp) = detector_with_content(content, "match");
    let result = detector.scan().unwrap();
    // Verify the struct fields are the expected types.
    let _bans: Vec<crate::types::BanEntry> = result.new_bans;
    let _scanned: u64 = result.lines_scanned;
    let _found: u32 = result.matches_found;
    let _dur: std::time::Duration = result.scan_duration;
}

// ===========================================================================
// Additional edge-case tests
// ===========================================================================

#[test]
fn scan_regex_matching_empty_string() {
    // Pattern ".*" matches every line (including empty ones) but must not
    // cause an infinite loop inside the scanner.
    let content = "line one\n\nline three\n";
    let (mut detector, _tmp) = detector_with_content(content, ".*");
    let result = detector.scan().expect("scan should not hang or fail");
    assert_eq!(result.lines_scanned, 3);
    // ".*" matches empty strings, so all lines (including the blank one)
    // should count as matches.
    assert_eq!(result.matches_found, 3);
    assert!(result.new_bans.is_empty(), "no capture group means no bans");
}

#[test]
fn scan_non_utf8_content() {
    // Write raw binary bytes that are not valid UTF-8. read_line() returns
    // an error on non-UTF-8 data, so the scanner should propagate it.
    let tmp = NamedTempFile::new().expect("failed to create temp file");
    let mut file = tmp.reopen().expect("failed to reopen temp file");
    file.write_all(&[0xFF, 0xFE, 0x80, 0x81, b'\n']).unwrap();
    file.flush().unwrap();

    let mut detector =
        LogDetector::new("test-jail", tmp.path(), r"pattern").expect("LogDetector::new");
    let result = detector.scan();
    // read_line fails on non-UTF-8 bytes, so scan returns an error.
    assert!(result.is_err(), "scan should return error for non-UTF-8 content");
}

#[test]
fn set_position_beyond_eof() {
    // Setting the read offset past the end of the file should cause the
    // scanner to read zero lines without error.
    let content = "short\n";
    let (mut detector, _tmp) = detector_with_content(content, r"\w+");
    detector.set_position(999_999, 100);
    let result = detector.scan().expect("scan should succeed");
    assert_eq!(result.lines_scanned, 0);
    assert_eq!(result.matches_found, 0);
    assert!(result.new_bans.is_empty());
}

#[test]
fn match_line_with_host_group_containing_hostname() {
    // When the only named group is `host` and it captures a hostname
    // (not an IP address), extract_ip should return None.
    let (detector, _tmp) = detector_with_content(
        "anything\n",
        r"(?P<host>\S+) auth failure",
    );
    let detail = detector
        .match_line("example.com auth failure", 1)
        .expect("should match");
    assert!(detail.ip.is_none(), "hostname is not an IP address");
    assert_eq!(detail.line, "example.com auth failure");
}
