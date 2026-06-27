//! Alert dispatching for anomaly findings.
//!
//! Provides [`AlertDispatcher`] which routes anomaly alerts to configured
//! targets: journald, webhooks, and log files.

use crate::paths::MonitorPaths;
use crate::report::{AlertReport, AnomalyFinding};
use crate::spec::AlertTarget;

/// Dispatches anomaly alerts to configured targets.
///
/// Supports journald, webhook, and file-based alert targets. The dispatcher
/// is designed to be resilient: if one target fails, others are still tried.
pub struct AlertDispatcher<'a> {
    /// Binary paths for system commands.
    paths: &'a MonitorPaths,
    /// Command runner used to execute system commands (journald dispatch).
    runner: &'a dyn toride_runner::Runner,
}

impl<'a> AlertDispatcher<'a> {
    /// Create a new `AlertDispatcher` with the given paths and runner.
    #[must_use]
    pub fn new(paths: &'a MonitorPaths, runner: &'a dyn toride_runner::Runner) -> Self {
        Self { paths, runner }
    }

    /// Dispatch an anomaly finding to all configured alert targets.
    ///
    /// Each target is tried independently. Returns a report for each
    /// dispatch attempt, including any failures.
    pub fn dispatch(&self, finding: &AnomalyFinding, targets: &[AlertTarget]) -> Vec<AlertReport> {
        let mut reports = Vec::new();

        for target in targets {
            let report = match target {
                AlertTarget::Journald { priority } => {
                    self.dispatch_journald(finding, priority)
                }
                AlertTarget::Webhook { url, headers } => {
                    self.dispatch_webhook(finding, url, headers)
                }
                AlertTarget::File { path } => self.dispatch_file(finding, path),
            };

            reports.push(report);
        }

        reports
    }

    /// Dispatch an alert to the systemd journal via `systemd-cat`.
    ///
    /// `systemd-cat` is the journal *writer*: it reads a message from stdin
    /// and submits it to the journal under the given identifier and priority.
    /// (The previous implementation invoked `journalctl`, which is the journal
    /// *reader* and cannot write entries.)
    fn dispatch_journald(&self, finding: &AnomalyFinding, priority: &str) -> AlertReport {
        let message = format!(
            "[toride-monitor] {} ({}): {} — observed: {}, threshold: {}",
            finding.severity,
            finding.id,
            finding.title,
            finding.observed_value,
            finding.threshold,
        );

        let spec = toride_runner::CommandSpec::new(
            self.paths.systemd_cat.to_string_lossy().into_owned(),
        )
        .args([
            "--priority".to_owned(),
            priority.to_owned(),
            "--identifier".to_owned(),
            "toride-monitor".to_owned(),
        ])
        .stdin(message);

        match self.runner.run(&spec) {
            Ok(output) if output.success => AlertReport {
                finding: finding.clone(),
                target: format!("journald({priority})"),
                dispatched: true,
                error: None,
            },
            Ok(output) => AlertReport {
                finding: finding.clone(),
                target: format!("journald({priority})"),
                dispatched: false,
                error: Some(output.combined_output()),
            },
            Err(e) => AlertReport {
                finding: finding.clone(),
                target: format!("journald({priority})"),
                dispatched: false,
                error: Some(e.to_string()),
            },
        }
    }

    /// Dispatch an alert to a webhook endpoint via HTTP POST.
    ///
    /// POSTs a JSON-serialised finding to `url` with the caller-supplied
    /// headers. Available only when the `webhook` feature is enabled (which
    /// pulls in `reqwest`). Without the feature, the dispatch is reported as
    /// not-yet-dispatched with a clear error so callers can see the gap.
    fn dispatch_webhook(
        &self,
        finding: &AnomalyFinding,
        url: &str,
        headers: &[(String, String)],
    ) -> AlertReport {
        dispatch_webhook_impl(finding, url, headers)
    }

    /// Dispatch an alert by appending to a log file.
    fn dispatch_file(&self, finding: &AnomalyFinding, path: &str) -> AlertReport {
        use std::io::Write;

        let line = format!(
            "[{}] {} ({}): {} — observed: {}, threshold: {}",
            finding.severity,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            finding.id,
            finding.title,
            finding.observed_value,
            finding.threshold,
        );

        match std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
        {
            Ok(mut file) => match writeln!(file, "{line}") {
                Ok(()) => AlertReport {
                    finding: finding.clone(),
                    target: format!("file({path})"),
                    dispatched: true,
                    error: None,
                },
                Err(e) => AlertReport {
                    finding: finding.clone(),
                    target: format!("file({path})"),
                    dispatched: false,
                    error: Some(format!("{e}")),
                },
            },
            Err(e) => AlertReport {
                finding: finding.clone(),
                target: format!("file({path})"),
                dispatched: false,
                error: Some(format!("{e}")),
            },
        }
    }
}

// ---------------------------------------------------------------------------
// Webhook implementation (feature-gated)
// ---------------------------------------------------------------------------

/// Concrete webhook POST implementation. Feature-gated so the crate compiles
/// without `reqwest`; without the feature the dispatch is reported as failed
/// with a clear message.
#[cfg(feature = "webhook")]
fn dispatch_webhook_impl(
    finding: &AnomalyFinding,
    url: &str,
    headers: &[(String, String)],
) -> AlertReport {
    let payload = webhook_payload(finding);

    let mut req = reqwest::blocking::Client::new()
        .post(url)
        .json(&payload);
    for (key, value) in headers {
        req = req.header(key, value);
    }

    match req.send() {
        Ok(resp) if resp.status().is_success() => AlertReport {
            finding: finding.clone(),
            target: format!("webhook({url})"),
            dispatched: true,
            error: None,
        },
        Ok(resp) => AlertReport {
            finding: finding.clone(),
            target: format!("webhook({url})"),
            dispatched: false,
            error: Some(format!("HTTP {}", resp.status())),
        },
        Err(e) => AlertReport {
            finding: finding.clone(),
            target: format!("webhook({url})"),
            dispatched: false,
            error: Some(format!("{e}")),
        },
    }
}

#[cfg(not(feature = "webhook"))]
fn dispatch_webhook_impl(
    finding: &AnomalyFinding,
    url: &str,
    _headers: &[(String, String)],
) -> AlertReport {
    tracing::warn!(
        "Webhook alert target configured at {url} but the `webhook` feature is disabled; \
         not dispatching finding {}",
        finding.id
    );
    AlertReport {
        finding: finding.clone(),
        target: format!("webhook({url})"),
        dispatched: false,
        error: Some("webhook feature is not enabled".into()),
    }
}

/// Build the JSON payload for a webhook POST.
#[cfg(feature = "webhook")]
fn webhook_payload(finding: &AnomalyFinding) -> serde_json::Value {
    serde_json::json!({
        "id": finding.id,
        "severity": finding.severity.to_string(),
        "title": finding.title,
        "observed_value": finding.observed_value,
        "threshold": finding.threshold,
        "fix": finding.fix,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::paths::MonitorPaths;
    use crate::report::AnomalySeverity;
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

    fn sample_finding() -> AnomalyFinding {
        AnomalyFinding::new(
            "anomaly.connection-volume",
            AnomalySeverity::Warning,
            "Too many outbound connections",
            "650",
            "500",
        )
    }

    #[test]
    fn journald_dispatch_uses_systemd_cat_writer_with_priority() {
        // The dispatch must invoke systemd-cat (the writer), NOT journalctl.
        let runner = FakeRunner::new().push_response(CommandOutput::from_stdout(""));
        let paths = test_paths();
        let dispatcher = AlertDispatcher::new(&paths, &runner);

        let report = dispatcher.dispatch_journald(&sample_finding(), "warning");
        assert!(report.dispatched);

        let calls = runner.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].program, "/usr/bin/systemd-cat");
        assert_eq!(
            calls[0].args,
            vec![
                "--priority".to_owned(),
                "warning".to_owned(),
                "--identifier".to_owned(),
                "toride-monitor".to_owned(),
            ]
        );
        // The message must be piped to systemd-cat's stdin.
        assert!(calls[0].stdin.as_deref().unwrap_or("").contains("Too many"));
    }

    #[test]
    fn journald_dispatch_reports_failure_on_nonzero_exit() {
        let runner =
            FakeRunner::new().push_response(CommandOutput::from_stderr("boom", 1));
        let paths = test_paths();
        let dispatcher = AlertDispatcher::new(&paths, &runner);

        let report = dispatcher.dispatch_journald(&sample_finding(), "crit");
        assert!(!report.dispatched);
        assert!(report.error.unwrap_or_default().contains("boom"));
    }

    #[test]
    fn file_dispatch_appends_line() {
        let dir = std::env::temp_dir().join(format!(
            "toride_monitor_alert_{}_{}",
            std::process::id(),
            "file"
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("alerts.log");

        let runner = FakeRunner::new();
        let paths = test_paths();
        let dispatcher = AlertDispatcher::new(&paths, &runner);

        let report = dispatcher.dispatch_file(&sample_finding(), path.to_str().unwrap());
        assert!(report.dispatched);

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("Too many outbound connections"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn webhook_dispatch_without_feature_returns_clear_error() {
        // When the `webhook` feature is off, the dispatch must report failure
        // with an explanatory message rather than silently succeeding. When the
        // feature is on, the request is attempted (and fails against the
        // invalid host); either way the result must not be reported as
        // successfully dispatched.
        let runner = FakeRunner::new();
        let paths = test_paths();
        let dispatcher = AlertDispatcher::new(&paths, &runner);

        let report = dispatcher.dispatch_webhook(
            &sample_finding(),
            "https://example.invalid/hook",
            &[("X-Token".into(), "secret".into())],
        );
        assert!(
            !report.dispatched,
            "webhook dispatch to an invalid host must never succeed"
        );
        assert!(
            report.error.is_some(),
            "a failed dispatch must carry an error message"
        );
        #[cfg(not(feature = "webhook"))]
        {
            assert!(
                report
                    .error
                    .as_deref()
                    .unwrap_or_default()
                    .contains("webhook"),
                "feature-disabled dispatch must explain the feature is off"
            );
        }
    }
}
