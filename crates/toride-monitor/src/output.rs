//! iptables OUTPUT chain logging setup.
//!
//! Manages iptables rules in the OUTPUT chain that log outbound traffic
//! via the kernel `LOG` target. Rules are created with rate limiting to
//! avoid flooding the kernel log.

use crate::Result;
use crate::paths::MonitorPaths;
use crate::spec::LoggingRule;
use crate::validate::validate_logging_rule;

/// Distinctive marker that every toride-installed `LOG` rule must carry in its
/// `--log-prefix`.
///
/// Teardown is **ownership-aware**: [`OutputChain::list_rules`] only returns
/// rules whose `--log-prefix` contains this marker, and
/// [`OutputChain::remove_all`] only deletes those. This guarantees we never
/// touch a `LOG` rule installed by another tool or the administrator, even if
/// it lives in the OUTPUT chain.
pub const TORIDE_LOG_PREFIX_MARKER: &str = "toride-mon-";

/// Manages iptables OUTPUT chain logging rules.
///
/// Each rule is created in a dedicated chain to allow clean teardown.
/// Rules include rate-limiting to prevent log volume from overwhelming
/// the system.
pub struct OutputChain<'a> {
    /// Binary paths for iptables commands.
    paths: &'a MonitorPaths,
    /// Command runner used to execute iptables.
    runner: &'a dyn toride_runner::Runner,
}

impl<'a> OutputChain<'a> {
    /// Create a new `OutputChain` manager with the given paths and runner.
    #[must_use]
    pub fn new(paths: &'a MonitorPaths, runner: &'a dyn toride_runner::Runner) -> Self {
        Self { paths, runner }
    }

    /// Set up a logging rule in the OUTPUT chain.
    ///
    /// Validates the rule, then executes the appropriate `iptables` commands
    /// to install it. The rule is appended to the OUTPUT chain with a `LOG`
    /// target and rate limiting.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::CommandFailed`] if the iptables command fails, or
    /// a validation error if the rule is invalid.
    pub fn add_rule(&self, rule: &LoggingRule) -> Result<()> {
        validate_logging_rule(rule)?;
        self.run_iptables(&build_append_args(rule))?;
        Ok(())
    }

    /// Remove a logging rule from the OUTPUT chain.
    ///
    /// Uses `iptables -D` to delete the matching rule. If the rule does
    /// not exist, the error from iptables is propagated.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::CommandFailed`] if the iptables command fails.
    pub fn remove_rule(&self, rule: &LoggingRule) -> Result<()> {
        self.run_iptables(&build_delete_args(rule))?;
        Ok(())
    }

    /// List all OUTPUT chain rules installed by toride.
    ///
    /// Parses `iptables-save` output to find rules in the OUTPUT chain that
    /// carry the `LOG` target *and* toride's distinctive
    /// [`TORIDE_LOG_PREFIX_MARKER`] in their `--log-prefix`. Only rules toride
    /// installed are returned, so teardown is ownership-aware and never touches
    /// unrelated `LOG` rules.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::CommandFailed`] if `iptables-save` fails.
    pub fn list_rules(&self) -> Result<Vec<String>> {
        let output = self.run_iptables_save()?;
        let rules = output
            .stdout
            .lines()
            .filter(|line| {
                line.contains("-A OUTPUT")
                    && line.contains("-j LOG")
                    && line.contains(TORIDE_LOG_PREFIX_MARKER)
            })
            .map(String::from)
            .collect();
        Ok(rules)
    }

    /// Remove all OUTPUT chain LOG rules installed by toride.
    ///
    /// Reads the current OUTPUT rules via `iptables-save`, converts each
    /// saved rule into the equivalent `iptables -D` invocation, and runs it.
    /// A rule that was never installed (i.e. `-D` finds no match) is reported
    /// as a warning rather than aborting the whole teardown, so a partial
    /// install can still be cleaned up.
    ///
    /// # Errors
    ///
    /// Returns an error if `iptables-save` fails or if a deletion command
    /// fails for a reason other than "rule does not exist".
    pub fn remove_all(&self) -> Result<()> {
        let rules = self.list_rules()?;
        let total = rules.len();
        for (idx, rule_line) in rules.iter().enumerate() {
            match self.delete_saved_rule(rule_line) {
                Ok(()) => tracing::info!(
                    "removed toride OUTPUT LOG rule ({}/{total} cleaned)",
                    idx + 1,
                ),
                Err(crate::Error::CommandFailed(msg)) => {
                    // iptables -D exits 1 with "Rule does not exist" when the
                    // rule is already gone. Treat that as success so teardown
                    // is idempotent.
                    if msg.contains("does not exist") || msg.contains("No chain/target/match") {
                        tracing::debug!("rule already absent");
                    } else {
                        return Err(crate::Error::CommandFailed(msg));
                    }
                }
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Run an `iptables` subcommand with the given arguments.
    fn run_iptables(&self, args: &[String]) -> Result<toride_runner::CommandOutput> {
        let spec =
            toride_runner::CommandSpec::new(self.paths.iptables.to_string_lossy().into_owned())
                .args(args.iter().cloned());
        let output = self.runner.run(&spec)?;
        if !output.success {
            // Do not echo the full argv or the raw combined output into the
            // error string — they may contain sensitive values and are noisy
            // in logs. Keep only the program name, the exit code, and the
            // first line of stderr (which carries the actionable reason, e.g.
            // "Rule does not exist", relied on by [`Self::remove_all`]).
            return Err(crate::Error::CommandFailed(format!(
                "iptables failed (exit {}): {}",
                exit_label(output.exit_code),
                first_stderr_line(&output.stderr)
            )));
        }
        Ok(output)
    }

    /// Run `iptables-save` and return its captured output.
    fn run_iptables_save(&self) -> Result<toride_runner::CommandOutput> {
        let spec = toride_runner::CommandSpec::new(
            self.paths.iptables_save.to_string_lossy().into_owned(),
        );
        let output = self.runner.run(&spec)?;
        if !output.success {
            return Err(crate::Error::CommandFailed(format!(
                "iptables-save failed (exit {}): {}",
                exit_label(output.exit_code),
                first_stderr_line(&output.stderr)
            )));
        }
        Ok(output)
    }

    /// Convert a single `iptables-save` rule line into `-D` args and delete it.
    ///
    /// `iptables-save` emits rules as `-A OUTPUT <rest...>`. Flipping the
    /// leading `-A` to `-D` yields the exact deletion spec accepted by
    /// `iptables` (it matches one rule at a time).
    fn delete_saved_rule(&self, rule_line: &str) -> Result<()> {
        let tokens = shellish_split(rule_line);
        if tokens.len() < 2 {
            // Do not echo the raw rule line (it may carry network details);
            // report the parse failure generically.
            return Err(crate::Error::CommandFailed(
                "cannot parse iptables-save rule line".into(),
            ));
        }
        // tokens[0] is "-A"; replace with "-D".
        let mut delete_args = tokens.clone();
        if delete_args[0] == "-A" {
            "-D".clone_into(&mut delete_args[0]);
        } else {
            // Not a rule we recognise (e.g. a policy line); skip silently.
            return Ok(());
        }
        self.run_iptables(&delete_args)?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Argument construction
// ---------------------------------------------------------------------------

/// Build the `iptables` append (`-A`) argument vector for a logging rule.
fn build_append_args(rule: &LoggingRule) -> Vec<String> {
    let mut args = vec![
        "-A".into(),
        "OUTPUT".into(),
        "-p".into(),
        rule.protocol.clone(),
        "-d".into(),
        rule.destination.clone(),
    ];
    extend_match_and_target(&mut args, rule);
    args
}

/// Build the `iptables` delete (`-D`) argument vector for a logging rule.
///
/// For deletion iptables only needs to match enough of the original rule to
/// identify it uniquely; the full match+target is the safest spec.
fn build_delete_args(rule: &LoggingRule) -> Vec<String> {
    let mut args = vec![
        "-D".into(),
        "OUTPUT".into(),
        "-p".into(),
        rule.protocol.clone(),
        "-d".into(),
        rule.destination.clone(),
    ];
    extend_match_and_target(&mut args, rule);
    args
}

/// Append the destination-port match plus the `LOG` target and rate limit.
fn extend_match_and_target(args: &mut Vec<String>, rule: &LoggingRule) {
    if let Some(port) = rule.dest_port {
        args.extend(["--dport".into(), port.to_string()]);
    }
    args.extend([
        "-j".into(),
        "LOG".into(),
        "--log-prefix".into(),
        rule.log_prefix.clone(),
        "--log-level".into(),
        rule.log_level.clone(),
        "-m".into(),
        "limit".into(),
        "--limit".into(),
        rule.limit_rate.clone(),
        "--limit-burst".into(),
        rule.limit_burst.to_string(),
    ]);
}

/// Render an exit code as a short label for use in error messages.
fn exit_label(exit_code: Option<i32>) -> String {
    match exit_code {
        Some(c) => c.to_string(),
        None => "signal".to_owned(),
    }
}

/// Return the first non-empty line of `stderr`, or a generic placeholder.
///
/// Used to surface the actionable reason a command failed without dumping the
/// full raw output (which may be noisy or carry sensitive data) into error
/// strings and logs.
fn first_stderr_line(stderr: &str) -> String {
    match stderr.lines().find(|line| !line.trim().is_empty()) {
        Some(line) => line.to_owned(),
        None => "no diagnostic output".to_owned(),
    }
}

/// Split an `iptables-save` rule line into argv tokens, honouring double and
/// single quotes (iptables-save quotes values containing spaces, e.g.
/// `--log-prefix "toride-mon-out "`).
///
/// An unterminated quote is treated leniently: the characters accumulated so
/// far are kept as the final token's content rather than being silently
/// dropped, so the parser feeding `iptables -D` never loses a rule because of
/// a trailing, unbalanced quote.
///
/// This is a tiny, dependency-free tokenizer sufficient for iptables-save
/// output; it is intentionally not a general-purpose shell parser.
fn shellish_split(line: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let chars = line.chars();
    let mut in_token = false;
    // When inside a quote, the matching terminator we are looking for.
    let mut quote_end: Option<char> = None;

    for c in chars {
        if let Some(term) = quote_end {
            if c == term {
                // Closing quote: keep the token open in case unquoted content
                // follows on the same token (e.g. `--log-prefix "x"y`).
                quote_end = None;
            } else {
                current.push(c);
            }
            continue;
        }
        match c {
            '"' | '\'' => {
                in_token = true;
                quote_end = Some(c);
            }
            c if c.is_whitespace() => {
                if in_token {
                    tokens.push(std::mem::take(&mut current));
                    in_token = false;
                }
            }
            other => {
                in_token = true;
                current.push(other);
            }
        }
    }
    // Flush any trailing token. If the quote was never closed, the remainder
    // accumulated in `current` is still emitted (lenient unterminated-quote
    // handling) so a rule is never silently lost.
    if in_token || !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::paths::MonitorPaths;
    use std::path::PathBuf;
    use toride_runner::{CommandOutput, FakeRunner};

    fn test_paths() -> MonitorPaths {
        MonitorPaths {
            iptables: PathBuf::from("/usr/sbin/iptables"),
            iptables_save: PathBuf::from("/usr/sbin/iptables-save"),
            conntrack: PathBuf::from("/usr/sbin/conntrack"),
            ss: PathBuf::from("/usr/bin/ss"),
            journalctl: PathBuf::from("/usr/bin/journalctl"),
            systemd_cat: PathBuf::from("/usr/bin/systemd-cat"),
        }
    }

    fn sample_rule() -> LoggingRule {
        LoggingRule {
            name: "out-tcp".into(),
            destination: "0.0.0.0/0".into(),
            dest_port: Some(443),
            protocol: "tcp".into(),
            log_prefix: "toride-mon-out".into(),
            log_level: "info".into(),
            limit_burst: 10,
            limit_rate: "10/minute".into(),
        }
    }

    #[test]
    fn add_rule_builds_exact_iptables_command() {
        let runner = FakeRunner::new().push_response(CommandOutput::from_stdout(""));
        let paths = test_paths();
        let chain = OutputChain::new(&paths, &runner);

        chain.add_rule(&sample_rule()).unwrap();

        let calls = runner.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].program, "/usr/sbin/iptables");
        assert_eq!(
            calls[0].args,
            vec![
                "-A",
                "OUTPUT",
                "-p",
                "tcp",
                "-d",
                "0.0.0.0/0",
                "--dport",
                "443",
                "-j",
                "LOG",
                "--log-prefix",
                "toride-mon-out",
                "--log-level",
                "info",
                "-m",
                "limit",
                "--limit",
                "10/minute",
                "--limit-burst",
                "10",
            ]
        );
    }

    #[test]
    fn remove_rule_builds_exact_delete_command() {
        let runner = FakeRunner::new().push_response(CommandOutput::from_stdout(""));
        let paths = test_paths();
        let chain = OutputChain::new(&paths, &runner);

        chain.remove_rule(&sample_rule()).unwrap();

        let calls = runner.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].args[0], "-D");
        assert_eq!(calls[0].args[1], "OUTPUT");
    }

    #[test]
    fn list_rules_parses_iptables_save_output() {
        let canned = "\
*filter
:INPUT ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
-A OUTPUT -d 0.0.0.0/0 -p tcp --dport 443 -j LOG --log-prefix \"toride-mon-out \" --log-level info -m limit --limit 10/minute --limit-burst 10
-A INPUT -p tcp -j ACCEPT
COMMIT
";
        let runner = FakeRunner::new().push_response(CommandOutput::from_stdout(canned));
        let paths = test_paths();
        let chain = OutputChain::new(&paths, &runner);

        let rules = chain.list_rules().unwrap();
        assert_eq!(rules.len(), 1);
        assert!(rules[0].contains("-A OUTPUT"));
        assert!(rules[0].contains("-j LOG"));
    }

    #[test]
    fn remove_all_converts_saved_rules_to_delete_and_invokes_iptables() {
        // iptables-save emits a single toride OUTPUT LOG rule; teardown must
        // issue exactly one `iptables -D OUTPUT ...` call derived from it.
        let saved_rule = "-A OUTPUT -d 0.0.0.0/0 -p tcp --dport 443 -j LOG --log-prefix \"toride-mon-out \" --log-level info -m limit --limit 10/minute --limit-burst 10";
        let canned = format!("*filter\n:OUTPUT ACCEPT [0:0]\n{saved_rule}\nCOMMIT\n");

        let runner = FakeRunner::new()
            // iptables-save call.
            .push_response(CommandOutput::from_stdout(canned))
            // iptables -D call (deleting the rule above).
            .push_response(CommandOutput::from_stdout(""));

        let paths = test_paths();
        let chain = OutputChain::new(&paths, &runner);

        chain.remove_all().unwrap();

        let calls = runner.calls();
        assert_eq!(calls.len(), 2);
        // First call: iptables-save.
        assert_eq!(calls[0].program, "/usr/sbin/iptables-save");
        // Second call: iptables -D derived from the saved line.
        assert_eq!(calls[1].program, "/usr/sbin/iptables");
        assert_eq!(calls[1].args[0], "-D");
        assert_eq!(calls[1].args[1], "OUTPUT");
        // The deletion args must round-trip the match+target from the saved line.
        assert!(calls[1].args.contains(&"-j".to_owned()));
        assert!(calls[1].args.contains(&"LOG".to_owned()));
        // The quoted log-prefix value must be unquoted in the argv.
        assert!(calls[1].args.contains(&"toride-mon-out ".to_owned()));
    }

    #[test]
    fn remove_all_is_idempotent_when_rule_already_absent() {
        // iptables -D returns exit 1 with "Rule does not exist"; teardown must
        // swallow that and succeed.
        let saved_rule = "-A OUTPUT -d 0.0.0.0/0 -p tcp -j LOG --log-prefix \"toride-mon-x \"";
        let canned = format!("*filter\n{saved_rule}\nCOMMIT\n");
        let runner = FakeRunner::new()
            .push_response(CommandOutput::from_stdout(canned))
            .push_response(CommandOutput::from_stderr(
                "iptables: Rule does not exist (out of memory?).\n",
                1,
            ));
        let paths = test_paths();
        let chain = OutputChain::new(&paths, &runner);

        assert!(chain.remove_all().is_ok());
    }

    #[test]
    fn remove_all_no_rules_issues_only_iptables_save() {
        let runner =
            FakeRunner::new().push_response(CommandOutput::from_stdout("*filter\nCOMMIT\n"));
        let paths = test_paths();
        let chain = OutputChain::new(&paths, &runner);

        chain.remove_all().unwrap();

        // No LOG rules => only the iptables-save call, no deletions.
        let calls = runner.calls();
        assert_eq!(calls.len(), 1);
    }

    #[test]
    fn shellish_split_unquotes_log_prefix() {
        let line = "-A OUTPUT -j LOG --log-prefix \"toride-mon-out \" --log-level info";
        let toks = shellish_split(line);
        assert_eq!(toks[0], "-A");
        // The quoted value keeps its trailing space but loses the quotes.
        assert!(toks.iter().any(|t| t == "toride-mon-out "));
    }

    #[test]
    fn shellish_split_handles_single_quotes() {
        let line = "-A OUTPUT -j LOG --log-prefix 'abc'";
        let toks = shellish_split(line);
        assert!(toks.iter().any(|t| t == "abc"));
    }

    #[test]
    fn add_rule_propagates_iptables_failure() {
        let runner = FakeRunner::new().push_response(CommandOutput::from_stderr("nope", 2));
        let paths = test_paths();
        let chain = OutputChain::new(&paths, &runner);
        assert!(chain.add_rule(&sample_rule()).is_err());
    }

    #[test]
    fn remove_all_leaves_non_toride_log_rules_intact() {
        // Regression: teardown is ownership-aware. A LOG rule installed by
        // another tool (no `toride-mon-` prefix in its --log-prefix) must
        // survive `remove_all` — only the iptables-save enumeration call is
        // issued, with NO deletion attempted against the foreign rule.
        let foreign_rule = "-A OUTPUT -d 10.0.0.0/8 -p tcp -j LOG --log-prefix \"OTHER_TOOL \"";
        let toride_rule = "-A OUTPUT -d 0.0.0.0/0 -p tcp -j LOG --log-prefix \"toride-mon-out \"";
        let canned =
            format!("*filter\n:OUTPUT ACCEPT [0:0]\n{foreign_rule}\n{toride_rule}\nCOMMIT\n");

        let runner = FakeRunner::new()
            // iptables-save call.
            .push_response(CommandOutput::from_stdout(canned))
            // iptables -D call for the single toride rule.
            .push_response(CommandOutput::from_stdout(""));

        let paths = test_paths();
        let chain = OutputChain::new(&paths, &runner);

        chain.remove_all().unwrap();

        let calls = runner.calls();
        // iptables-save + exactly one deletion (the toride rule only).
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[1].program, "/usr/sbin/iptables");
        assert_eq!(calls[1].args[0], "-D");
        // The deletion must target the toride rule, never the foreign one.
        assert!(calls[1].args.contains(&"toride-mon-out ".to_owned()));
        assert!(!calls[1].args.iter().any(|a| a == "OTHER_TOOL "));
    }

    #[test]
    fn list_rules_excludes_non_toride_log_rules() {
        let canned = "\
*filter
:OUTPUT ACCEPT [0:0]
-A OUTPUT -j LOG --log-prefix \"NOT_OURS \"
-A OUTPUT -j LOG --log-prefix \"toride-mon-x \"
COMMIT
";
        let runner = FakeRunner::new().push_response(CommandOutput::from_stdout(canned));
        let paths = test_paths();
        let chain = OutputChain::new(&paths, &runner);

        let rules = chain.list_rules().unwrap();
        // Only the toride-prefixed rule is returned.
        assert_eq!(rules.len(), 1);
        assert!(rules[0].contains("toride-mon-"));
    }

    #[test]
    fn shellish_split_keeps_remainder_of_unterminated_quote() {
        // An unterminated trailing quote must not lose the token: the
        // remainder accumulates into the final token so the iptables -D spec
        // is never silently truncated.
        let line = "-A OUTPUT -j LOG --log-prefix \"toride-mon-x";
        let toks = shellish_split(line);
        assert_eq!(toks[0], "-A");
        // The unterminated quoted value is preserved as the final token.
        assert!(toks.iter().any(|t| t == "toride-mon-x"));
    }

    #[test]
    fn shellish_split_keeps_remainder_of_unterminated_single_quote() {
        let line = "-A OUTPUT -j LOG --log-prefix 'toride-mon-y";
        let toks = shellish_split(line);
        assert!(toks.iter().any(|t| t == "toride-mon-y"));
    }
}
