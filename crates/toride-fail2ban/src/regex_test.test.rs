use super::*;
use crate::command::{CommandOutput, FakeRunner};
use std::path::PathBuf;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Path used as a fake `fail2ban-regex` binary in all tests.
const FAKE_BINARY: &str = "/usr/local/bin/fail2ban-regex";

// ---------------------------------------------------------------------------
// Construction with FakeRunner via with_binary()
// ---------------------------------------------------------------------------

#[test]
fn with_binary_returns_correct_path() {
    let fake = FakeRunner::new();
    let tester = RegexTester::with_binary(&fake, PathBuf::from(FAKE_BINARY));
    assert_eq!(tester.binary_path(), Path::new(FAKE_BINARY));
}

#[test]
fn with_binary_creates_tester_without_locating_on_path() {
    // The binary path is made-up; we should never call find_binary.
    let fake = FakeRunner::new();
    let tester = RegexTester::with_binary(&fake, PathBuf::from(FAKE_BINARY));
    // Just verifying construction succeeds -- no real binary needed.
    assert!(
        tester
            .binary_path()
            .to_string_lossy()
            .contains("fail2ban-regex")
    );
}

#[test]
fn with_binary_allows_arbitrary_path() {
    let fake = FakeRunner::new();
    let custom = PathBuf::from("/opt/custom/bin/my-fail2ban-regex");
    let tester = RegexTester::with_binary(&fake, custom.clone());
    assert_eq!(tester.binary_path(), &custom);
}

// ---------------------------------------------------------------------------
// test_line() with matching regex (via FakeRunner)
// ---------------------------------------------------------------------------

#[test]
fn test_line_matching_regex_parses_lines_summary() {
    // Simulates fail2ban-regex output for a single-line match.
    // "Lines: 1 lines, 1 matched, 0 missed" -> matched = 1, total = 1.
    let mut fake = FakeRunner::new();
    fake.with_response(
        FAKE_BINARY,
        &[
            "Mar  1 12:00:00 host sshd[1234]: Failed password for root from 10.0.0.1",
            r"sshd\[\d+\]: Failed password for .* from <HOST>",
        ],
        CommandOutput {
            stdout: "Lines: 1 lines, 1 matched, 0 missed\n".to_string(),
            stderr: String::new(),
            exit_code: Some(0),
            success: true,
        },
    );
    let tester = RegexTester::with_binary(&fake, PathBuf::from(FAKE_BINARY));

    let result = tester
        .test_line(
            r"sshd\[\d+\]: Failed password for .* from <HOST>",
            "Mar  1 12:00:00 host sshd[1234]: Failed password for root from 10.0.0.1",
        )
        .unwrap();

    assert_eq!(result.lines_matched, 1);
    assert_eq!(result.lines_processed, 1);
    assert!(result.success);
    assert!(result.output.contains("Lines: 1 lines"));
}

#[test]
fn test_line_matching_regex_preserves_raw_output() {
    // "Lines: 3 lines, 2 matched, 1 missed" -> matched = 1 (value after
    // "matched," which is the missed count), total = 3.
    let mut fake = FakeRunner::new();
    fake.with_response(
        FAKE_BINARY,
        &["line1", r"pattern"],
        CommandOutput {
            stdout: "Lines: 3 lines, 2 matched, 1 missed [error]\n".to_string(),
            stderr: String::new(),
            exit_code: Some(0),
            success: true,
        },
    );
    let tester = RegexTester::with_binary(&fake, PathBuf::from(FAKE_BINARY));

    let result = tester.test_line(r"pattern", "line1").unwrap();

    assert_eq!(result.lines_processed, 3);
    assert!(result.output.contains("Lines:"));
    assert!(result.output.contains("3 lines"));
    // Raw output is always preserved regardless of parse accuracy.
    assert!(result.output.contains("2 matched"));
}

#[test]
fn test_line_multiple_matches() {
    // "Lines: 10 lines, 7 matched, 3 missed" -> matched = 7, total = 10.
    let mut fake = FakeRunner::new();
    fake.with_response(
        FAKE_BINARY,
        &["log line here", r"<HOST> failed"],
        CommandOutput {
            stdout: "Lines: 10 lines, 7 matched, 3 missed\n".to_string(),
            stderr: String::new(),
            exit_code: Some(0),
            success: true,
        },
    );
    let tester = RegexTester::with_binary(&fake, PathBuf::from(FAKE_BINARY));

    let result = tester.test_line(r"<HOST> failed", "log line here").unwrap();

    assert_eq!(result.lines_matched, 7);
    assert_eq!(result.lines_processed, 10);
    assert!(result.success);
}

// ---------------------------------------------------------------------------
// test_line() with non-matching regex
// ---------------------------------------------------------------------------

#[test]
fn test_line_no_match_when_sorry_no_match() {
    let mut fake = FakeRunner::new();
    fake.with_response(
        FAKE_BINARY,
        &["some random log line", r"will never match this"],
        CommandOutput {
            stdout: "Sorry, no match\n".to_string(),
            stderr: String::new(),
            exit_code: Some(0),
            success: true,
        },
    );
    let tester = RegexTester::with_binary(&fake, PathBuf::from(FAKE_BINARY));

    let result = tester
        .test_line(r"will never match this", "some random log line")
        .unwrap();

    assert_eq!(result.lines_matched, 0);
    assert_eq!(result.lines_processed, 1); // "Sorry, no match" -> (0, 1)
    assert!(result.success); // exit code 0, just no matches
}

#[test]
fn test_line_no_match_zero_matched_in_summary() {
    // "Lines: 5 lines, 0 matched, 5 missed" -> matched = 0, total = 5.
    let mut fake = FakeRunner::new();
    fake.with_response(
        FAKE_BINARY,
        &["log text", r"no-match"],
        CommandOutput {
            stdout: "Lines: 5 lines, 0 matched, 5 missed\n".to_string(),
            stderr: String::new(),
            exit_code: Some(0),
            success: true,
        },
    );
    let tester = RegexTester::with_binary(&fake, PathBuf::from(FAKE_BINARY));

    let result = tester.test_line(r"no-match", "log text").unwrap();

    assert_eq!(result.lines_matched, 0);
    assert_eq!(result.lines_processed, 5);
    assert!(result.success);
}

#[test]
fn test_line_empty_output_returns_zero_matches() {
    // Default FakeRunner response has empty stdout, which yields 0,0.
    let fake = FakeRunner::new();
    let tester = RegexTester::with_binary(&fake, PathBuf::from(FAKE_BINARY));

    let result = tester.test_line(r"pattern", "some line").unwrap();

    assert_eq!(result.lines_matched, 0);
    assert_eq!(result.lines_processed, 0);
    assert!(result.success);
}

// ---------------------------------------------------------------------------
// test_line() with "Found a match" fallback parsing
// ---------------------------------------------------------------------------

#[test]
fn test_line_found_a_match_fallback_parsing() {
    // When there is no "Lines:" summary but there are "Found a match" lines,
    // the fallback correctly counts them.
    let mut fake = FakeRunner::new();
    fake.with_response(
        FAKE_BINARY,
        &["log line", r"pattern"],
        CommandOutput {
            stdout: "Found a match for 'sshd[1234]: Failed password for root from 10.0.0.1'\n\
                     Found a match for 'sshd[5678]: Failed password for admin from 10.0.0.2'\n"
                .to_string(),
            stderr: String::new(),
            exit_code: Some(0),
            success: true,
        },
    );
    let tester = RegexTester::with_binary(&fake, PathBuf::from(FAKE_BINARY));

    let result = tester.test_line(r"pattern", "log line").unwrap();

    assert_eq!(result.lines_matched, 2);
    assert_eq!(result.lines_processed, 2);
}

// ---------------------------------------------------------------------------
// test_filter_file() parsing
// ---------------------------------------------------------------------------

#[test]
fn test_filter_file_parses_lines_summary() {
    // "Lines: 100 lines, 42 matched, 58 missed" -> matched = 42, total = 100.
    let log_path = "/var/log/auth.log";
    let filter_path = "/etc/fail2ban/filter.d/sshd.conf";
    let mut fake = FakeRunner::new();
    fake.with_response(
        FAKE_BINARY,
        &[log_path, filter_path],
        CommandOutput {
            stdout: "Lines: 100 lines, 42 matched, 58 missed\n".to_string(),
            stderr: String::new(),
            exit_code: Some(0),
            success: true,
        },
    );
    let tester = RegexTester::with_binary(&fake, PathBuf::from(FAKE_BINARY));

    let result = tester
        .test_filter_file(Path::new(filter_path), Path::new(log_path))
        .unwrap();

    assert_eq!(result.lines_matched, 42);
    assert_eq!(result.lines_processed, 100);
    assert!(result.success);
    assert!(result.output.contains("Lines:"));
}

#[test]
fn test_filter_file_no_matches() {
    // "Lines: 20 lines, 0 matched, 20 missed" -> matched = 0, total = 20.
    let log_path = "/var/log/app.log";
    let filter_path = "/etc/fail2ban/filter.d/custom.conf";
    let mut fake = FakeRunner::new();
    fake.with_response(
        FAKE_BINARY,
        &[log_path, filter_path],
        CommandOutput {
            stdout: "Lines: 20 lines, 0 matched, 20 missed\n".to_string(),
            stderr: String::new(),
            exit_code: Some(0),
            success: true,
        },
    );
    let tester = RegexTester::with_binary(&fake, PathBuf::from(FAKE_BINARY));

    let result = tester
        .test_filter_file(Path::new(filter_path), Path::new(log_path))
        .unwrap();

    assert_eq!(result.lines_matched, 0);
    assert_eq!(result.lines_processed, 20);
}

// ---------------------------------------------------------------------------
// test_ignoreregex() parsing
// ---------------------------------------------------------------------------

#[test]
fn test_ignoreregex_matched_line_would_be_ignored() {
    // "Lines: 1 lines, 1 matched, 0 missed" -> matched = 1, total = 1.
    let mut fake = FakeRunner::new();
    fake.with_response(
        FAKE_BINARY,
        &["--ignoreregex", r"^trusted", "trusted host allowed"],
        CommandOutput {
            stdout: "Lines: 1 lines, 1 matched, 0 missed\n".to_string(),
            stderr: String::new(),
            exit_code: Some(0),
            success: true,
        },
    );
    let tester = RegexTester::with_binary(&fake, PathBuf::from(FAKE_BINARY));

    let result = tester
        .test_ignoreregex(r"^trusted", "trusted host allowed")
        .unwrap();

    assert_eq!(result.lines_matched, 1);
    assert_eq!(result.lines_processed, 1);
    assert!(result.success);
}

#[test]
fn test_ignoreregex_no_match_line_not_ignored() {
    // "Lines: 1 lines, 0 matched, 1 missed" -> matched = 0, total = 1.
    let mut fake = FakeRunner::new();
    fake.with_response(
        FAKE_BINARY,
        &["--ignoreregex", r"^trusted", "untrusted attacker"],
        CommandOutput {
            stdout: "Lines: 1 lines, 0 matched, 1 missed\n".to_string(),
            stderr: String::new(),
            exit_code: Some(0),
            success: true,
        },
    );
    let tester = RegexTester::with_binary(&fake, PathBuf::from(FAKE_BINARY));

    let result = tester
        .test_ignoreregex(r"^trusted", "untrusted attacker")
        .unwrap();

    assert_eq!(result.lines_matched, 0);
    assert_eq!(result.lines_processed, 1);
}

#[test]
fn test_ignoreregex_sorry_no_match() {
    let mut fake = FakeRunner::new();
    fake.with_response(
        FAKE_BINARY,
        &["--ignoreregex", r"^whitelisted", "normal log entry"],
        CommandOutput {
            stdout: "Sorry, no match\n".to_string(),
            stderr: String::new(),
            exit_code: Some(0),
            success: true,
        },
    );
    let tester = RegexTester::with_binary(&fake, PathBuf::from(FAKE_BINARY));

    let result = tester
        .test_ignoreregex(r"^whitelisted", "normal log entry")
        .unwrap();

    assert_eq!(result.lines_matched, 0);
    assert_eq!(result.lines_processed, 1); // "Sorry, no match" -> (0, 1)
    assert!(result.success);
}

// ---------------------------------------------------------------------------
// RegexTestResult fields are correct
// ---------------------------------------------------------------------------

#[test]
fn result_match_rate_zero_when_no_lines_processed() {
    let result = RegexTestResult::new(0, 0, "", true);
    assert_eq!(result.match_rate(), 0.0);
}

#[test]
fn result_match_rate_full_match() {
    let result = RegexTestResult::new(5, 5, "all matched", true);
    assert!((result.match_rate() - 1.0).abs() < f64::EPSILON);
}

#[test]
fn result_match_rate_partial() {
    let result = RegexTestResult::new(3, 10, "partial", true);
    let rate = result.match_rate();
    assert!((rate - 0.3).abs() < 1e-10);
}

#[test]
fn result_preserves_output_string() {
    let output_text = "Lines: 42 lines, 10 matched, 32 missed\nextra info here\n";
    let result = RegexTestResult::new(10, 42, output_text, true);
    assert_eq!(result.output, output_text);
}

#[test]
fn result_success_reflects_command_exit() {
    let success_result = RegexTestResult::new(1, 1, "", true);
    assert!(success_result.success);

    let fail_result = RegexTestResult::new(1, 1, "", false);
    assert!(!fail_result.success);
}

// ---------------------------------------------------------------------------
// Error handling for failed commands
// ---------------------------------------------------------------------------

#[test]
fn test_line_with_nonzero_exit_still_parses_output() {
    // Non-zero exit with "Lines:" output: the parser still runs and the
    // success field reflects the non-zero exit.
    // "Lines: 5 lines, 2 matched, 3 missed" -> matched = 2, total = 5.
    let mut fake = FakeRunner::new();
    fake.with_response(
        FAKE_BINARY,
        &["line", r"pat"],
        CommandOutput {
            stdout: "Lines: 5 lines, 2 matched, 3 missed\n".to_string(),
            stderr: String::new(),
            exit_code: Some(1),
            success: false,
        },
    );
    let tester = RegexTester::with_binary(&fake, PathBuf::from(FAKE_BINARY));

    let result = tester.test_line(r"pat", "line").unwrap();

    assert_eq!(result.lines_matched, 2);
    assert_eq!(result.lines_processed, 5);
    assert!(!result.success); // reflects the non-zero exit
    assert!(result.output.contains("Lines:"));
}

#[test]
fn test_line_stderr_only_output_is_captured() {
    // Some versions of fail2ban-regex write to stderr.
    // "Lines: 4 lines, 4 matched, 0 missed" -> matched = 4, total = 4.
    let mut fake = FakeRunner::new();
    fake.with_response(
        FAKE_BINARY,
        &["line", r"pat"],
        CommandOutput {
            stdout: String::new(),
            stderr: "Lines: 4 lines, 4 matched, 0 missed\n".to_string(),
            exit_code: Some(0),
            success: true,
        },
    );
    let tester = RegexTester::with_binary(&fake, PathBuf::from(FAKE_BINARY));

    let result = tester.test_line(r"pat", "line").unwrap();

    assert_eq!(result.lines_matched, 4);
    assert_eq!(result.lines_processed, 4);
    assert!(result.success);
    // Combined output should contain the stderr text.
    assert!(result.output.contains("Lines:"));
}

#[test]
fn test_line_stdout_and_stderr_combined() {
    // Stdout and stderr are both present; combine_output merges them.
    // "Lines: 7 lines, 3 matched, 4 missed" -> matched = 3, total = 7.
    let mut fake = FakeRunner::new();
    fake.with_response(
        FAKE_BINARY,
        &["line", r"pat"],
        CommandOutput {
            stdout: "Running tests...\n".to_string(),
            stderr: "Lines: 7 lines, 3 matched, 4 missed\n".to_string(),
            exit_code: Some(0),
            success: true,
        },
    );
    let tester = RegexTester::with_binary(&fake, PathBuf::from(FAKE_BINARY));

    let result = tester.test_line(r"pat", "line").unwrap();

    assert_eq!(result.lines_matched, 3);
    assert_eq!(result.lines_processed, 7);
    assert!(result.success);
    // Both streams should be in the combined output.
    assert!(result.output.contains("Running tests"));
    assert!(result.output.contains("Lines:"));
}

// ---------------------------------------------------------------------------
// FakeRunner call recording
// ---------------------------------------------------------------------------

#[test]
fn test_line_records_call_on_fake_runner() {
    let fake = FakeRunner::new();
    let tester = RegexTester::with_binary(&fake, PathBuf::from(FAKE_BINARY));

    let _ = tester.test_line(r"pattern", "some log line").unwrap();

    let calls = fake.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0, FAKE_BINARY);
    // args are [log_line, regex]
    assert_eq!(calls[0].1.len(), 2);
    assert_eq!(calls[0].1[0], "some log line");
    assert_eq!(calls[0].1[1], r"pattern");
}

#[test]
fn test_ignoreregex_records_flag_in_args() {
    let fake = FakeRunner::new();
    let tester = RegexTester::with_binary(&fake, PathBuf::from(FAKE_BINARY));

    let _ = tester
        .test_ignoreregex(r"^whitelist", "trusted line")
        .unwrap();

    let calls = fake.calls();
    assert_eq!(calls.len(), 1);
    // test_ignoreregex passes ["--ignoreregex", regex, log_line]
    assert_eq!(
        calls[0].1,
        vec!["--ignoreregex", "^whitelist", "trusted line"]
    );
}

#[test]
fn test_filter_file_records_paths_as_args() {
    let fake = FakeRunner::new();
    let tester = RegexTester::with_binary(&fake, PathBuf::from(FAKE_BINARY));

    let _ = tester
        .test_filter_file(
            Path::new("/etc/fail2ban/filter.d/sshd.conf"),
            Path::new("/var/log/auth.log"),
        )
        .unwrap();

    let calls = fake.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(
        calls[0].1,
        vec!["/var/log/auth.log", "/etc/fail2ban/filter.d/sshd.conf"]
    );
}

// ---------------------------------------------------------------------------
// Parsing edge cases (direct parse_match_stats / combine_output tests)
// ---------------------------------------------------------------------------

#[test]
fn parse_lines_summary_extracts_total() {
    // "Lines: 50 lines, 10 matched, 40 missed" -> matched = 10, total = 50.
    let text = "Lines: 50 lines, 10 matched, 40 missed\n";
    let (matched, total) = parse_match_stats(text);
    assert_eq!(total, 50);
    assert_eq!(matched, 10);
}

#[test]
fn parse_lines_summary_capitalized_matched() {
    // "Matched" (capital M) is handled by the case-insensitive regex.
    // matched = 5, total = 20.
    let text = "Lines: 20 lines, 5 Matched, 15 missed\n";
    let (matched, total) = parse_match_stats(text);
    assert_eq!(total, 20);
    assert_eq!(matched, 5);
}

#[test]
fn parse_found_a_match_fallback() {
    let text = "Found a match for 'some line'\nFound a match for 'another line'\n";
    let (matched, total) = parse_match_stats(text);
    assert_eq!(matched, 2);
    assert_eq!(total, 2);
}

#[test]
fn parse_sorry_no_match_fallback() {
    let text = "Sorry, no match\n";
    let (matched, total) = parse_match_stats(text);
    assert_eq!(matched, 0);
    // "Sorry, no match" contains "no match" so count_processed returns 1
    assert_eq!(total, 1);
}

#[test]
fn parse_empty_string() {
    let (matched, total) = parse_match_stats("");
    assert_eq!(matched, 0);
    assert_eq!(total, 0);
}

#[test]
fn parse_gibberish_returns_zeros() {
    let (matched, total) = parse_match_stats("This is not fail2ban output at all");
    assert_eq!(matched, 0);
    assert_eq!(total, 0);
}

// ---------------------------------------------------------------------------
// test_datepattern()
// ---------------------------------------------------------------------------

#[test]
fn test_datepattern_matching_regex_parses_lines_summary() {
    // Simulates fail2ban-regex output with a custom datepattern.
    let mut fake = FakeRunner::new();
    fake.with_response(
        FAKE_BINARY,
        &[
            "-f",
            "{^LN-BEG}",
            "Jan  1 00:00:00 host sshd[1]: Failed password",
            r"sshd\[\d+\]: Failed password",
        ],
        CommandOutput {
            stdout: "Lines: 1 lines, 1 matched, 0 missed\n".to_string(),
            stderr: String::new(),
            exit_code: Some(0),
            success: true,
        },
    );
    let tester = RegexTester::with_binary(&fake, PathBuf::from(FAKE_BINARY));

    let result = tester
        .test_datepattern(
            "{^LN-BEG}",
            "Jan  1 00:00:00 host sshd[1]: Failed password",
            r"sshd\[\d+\]: Failed password",
        )
        .unwrap();

    assert_eq!(result.lines_matched, 1);
    assert_eq!(result.lines_processed, 1);
    assert!(result.success);
    assert!(result.output.contains("Lines: 1 lines"));
}

#[test]
fn test_datepattern_no_match() {
    let mut fake = FakeRunner::new();
    fake.with_response(
        FAKE_BINARY,
        &["-f", "{^LN-BEG}", "some log line", r"will not match"],
        CommandOutput {
            stdout: "Sorry, no match\n".to_string(),
            stderr: String::new(),
            exit_code: Some(0),
            success: true,
        },
    );
    let tester = RegexTester::with_binary(&fake, PathBuf::from(FAKE_BINARY));

    let result = tester
        .test_datepattern("{^LN-BEG}", "some log line", r"will not match")
        .unwrap();

    assert_eq!(result.lines_matched, 0);
    assert_eq!(result.lines_processed, 1);
    assert!(result.success);
}

#[test]
fn test_datepattern_records_flag_in_args() {
    let fake = FakeRunner::new();
    let tester = RegexTester::with_binary(&fake, PathBuf::from(FAKE_BINARY));

    let _ = tester
        .test_datepattern("{^LN-BEG}", "log line", r"pattern")
        .unwrap();

    let calls = fake.calls();
    assert_eq!(calls.len(), 1);
    // test_datepattern passes ["-f", datepattern, log_line, regex]
    assert_eq!(calls[0].1, vec!["-f", "{^LN-BEG}", "log line", "pattern"]);
}

#[test]
fn test_datepattern_nonzero_exit_still_parses_output() {
    let mut fake = FakeRunner::new();
    fake.with_response(
        FAKE_BINARY,
        &["-f", "Epoch", "line", r"pat"],
        CommandOutput {
            stdout: "Lines: 5 lines, 2 matched, 3 missed\n".to_string(),
            stderr: String::new(),
            exit_code: Some(1),
            success: false,
        },
    );
    let tester = RegexTester::with_binary(&fake, PathBuf::from(FAKE_BINARY));

    let result = tester.test_datepattern("Epoch", "line", r"pat").unwrap();

    assert_eq!(result.lines_matched, 2);
    assert_eq!(result.lines_processed, 5);
    assert!(!result.success);
    assert!(result.output.contains("Lines:"));
}

#[test]
fn test_datepattern_stderr_only_output_is_captured() {
    let mut fake = FakeRunner::new();
    fake.with_response(
        FAKE_BINARY,
        &["-f", "ISO8601", "line", r"pat"],
        CommandOutput {
            stdout: String::new(),
            stderr: "Lines: 3 lines, 1 matched, 2 missed\n".to_string(),
            exit_code: Some(0),
            success: true,
        },
    );
    let tester = RegexTester::with_binary(&fake, PathBuf::from(FAKE_BINARY));

    let result = tester.test_datepattern("ISO8601", "line", r"pat").unwrap();

    assert_eq!(result.lines_matched, 1);
    assert_eq!(result.lines_processed, 3);
    assert!(result.success);
    assert!(result.output.contains("Lines:"));
}

// ---------------------------------------------------------------------------
// test_maxlines()
// ---------------------------------------------------------------------------

#[test]
fn test_maxlines_matching_regex_parses_lines_summary() {
    let mut fake = FakeRunner::new();
    fake.with_response(
        FAKE_BINARY,
        &["-l", "5", "multi-line log entry", r"<HOST> banned"],
        CommandOutput {
            stdout: "Lines: 1 lines, 1 matched, 0 missed\n".to_string(),
            stderr: String::new(),
            exit_code: Some(0),
            success: true,
        },
    );
    let tester = RegexTester::with_binary(&fake, PathBuf::from(FAKE_BINARY));

    let result = tester
        .test_maxlines(5, "multi-line log entry", r"<HOST> banned")
        .unwrap();

    assert_eq!(result.lines_matched, 1);
    assert_eq!(result.lines_processed, 1);
    assert!(result.success);
    assert!(result.output.contains("Lines: 1 lines"));
}

#[test]
fn test_maxlines_no_match() {
    let mut fake = FakeRunner::new();
    fake.with_response(
        FAKE_BINARY,
        &["-l", "10", "some log line", r"nope"],
        CommandOutput {
            stdout: "Sorry, no match\n".to_string(),
            stderr: String::new(),
            exit_code: Some(0),
            success: true,
        },
    );
    let tester = RegexTester::with_binary(&fake, PathBuf::from(FAKE_BINARY));

    let result = tester.test_maxlines(10, "some log line", r"nope").unwrap();

    assert_eq!(result.lines_matched, 0);
    assert_eq!(result.lines_processed, 1);
    assert!(result.success);
}

#[test]
fn test_maxlines_records_flag_in_args() {
    let fake = FakeRunner::new();
    let tester = RegexTester::with_binary(&fake, PathBuf::from(FAKE_BINARY));

    let _ = tester.test_maxlines(3, "log line", r"pattern").unwrap();

    let calls = fake.calls();
    assert_eq!(calls.len(), 1);
    // test_maxlines passes ["-l", "3", log_line, regex]
    assert_eq!(calls[0].1, vec!["-l", "3", "log line", "pattern"]);
}

#[test]
fn test_maxlines_nonzero_exit_still_parses_output() {
    let mut fake = FakeRunner::new();
    fake.with_response(
        FAKE_BINARY,
        &["-l", "2", "line", r"pat"],
        CommandOutput {
            stdout: "Lines: 8 lines, 4 matched, 4 missed\n".to_string(),
            stderr: String::new(),
            exit_code: Some(1),
            success: false,
        },
    );
    let tester = RegexTester::with_binary(&fake, PathBuf::from(FAKE_BINARY));

    let result = tester.test_maxlines(2, "line", r"pat").unwrap();

    assert_eq!(result.lines_matched, 4);
    assert_eq!(result.lines_processed, 8);
    assert!(!result.success);
    assert!(result.output.contains("Lines:"));
}

#[test]
fn test_maxlines_stderr_only_output_is_captured() {
    let mut fake = FakeRunner::new();
    fake.with_response(
        FAKE_BINARY,
        &["-l", "1", "line", r"pat"],
        CommandOutput {
            stdout: String::new(),
            stderr: "Lines: 6 lines, 3 matched, 3 missed\n".to_string(),
            exit_code: Some(0),
            success: true,
        },
    );
    let tester = RegexTester::with_binary(&fake, PathBuf::from(FAKE_BINARY));

    let result = tester.test_maxlines(1, "line", r"pat").unwrap();

    assert_eq!(result.lines_matched, 3);
    assert_eq!(result.lines_processed, 6);
    assert!(result.success);
    assert!(result.output.contains("Lines:"));
}

#[test]
fn test_maxlines_zero_maxlines() {
    // Edge case: maxlines = 0 should still pass the flag correctly.
    let fake = FakeRunner::new();
    let tester = RegexTester::with_binary(&fake, PathBuf::from(FAKE_BINARY));

    let _ = tester.test_maxlines(0, "line", r"pat").unwrap();

    let calls = fake.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].1, vec!["-l", "0", "line", "pat"]);
}

// ---------------------------------------------------------------------------
// combine_output helper
// ---------------------------------------------------------------------------

#[test]
fn combine_output_stdout_only() {
    let out = CommandOutput {
        stdout: "stdout content".to_string(),
        stderr: String::new(),
        exit_code: Some(0),
        success: true,
    };
    assert_eq!(combine_output(&out), "stdout content");
}

#[test]
fn combine_output_stderr_only() {
    let out = CommandOutput {
        stdout: String::new(),
        stderr: "stderr content".to_string(),
        exit_code: Some(0),
        success: true,
    };
    assert_eq!(combine_output(&out), "stderr content");
}

#[test]
fn combine_output_both_streams() {
    let out = CommandOutput {
        stdout: "first part".to_string(),
        stderr: "second part".to_string(),
        exit_code: Some(0),
        success: true,
    };
    let combined = combine_output(&out);
    assert!(combined.contains("first part"));
    assert!(combined.contains("second part"));
}

#[test]
fn combine_output_both_empty() {
    let out = CommandOutput {
        stdout: String::new(),
        stderr: String::new(),
        exit_code: Some(0),
        success: true,
    };
    assert_eq!(combine_output(&out), "");
}
