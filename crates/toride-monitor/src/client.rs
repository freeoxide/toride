//! High-level monitoring client: [`MonitorClient`] composes the output
//! chain, conntrack reader, anomaly detector, and alert dispatcher.

use crate::Result;
use crate::alert::AlertDispatcher;
use crate::anomaly::AnomalyDetector;
use crate::conntrack::ConntrackReader;
use crate::output::OutputChain;
use crate::parse::{parse_ss_output, ss_entry_to_connection};
use crate::paths::MonitorPaths;
use crate::report::{AnomalyReport, MonitorReport};
use crate::spec::{AlertTarget, LoggingRule, MonitorSpec};

/// High-level client for outbound traffic monitoring.
/// Owns a boxed [`toride_runner::Runner`] and resolved [`MonitorPaths`].
pub struct MonitorClient {
    runner: Box<dyn toride_runner::Runner>,
    paths: MonitorPaths,
}

impl MonitorClient {
    /// Create a `MonitorClient` with paths resolved from `$PATH` and the
    /// production [`toride_runner::DuctRunner`].
    ///
    /// # Errors
    /// [`crate::Error::BinaryNotFound`] if a required binary is not on `$PATH`.
    pub fn system() -> Result<Self> {
        let paths = MonitorPaths::resolve_from_path()?;
        Ok(Self {
            runner: Box::new(toride_runner::DuctRunner),
            paths,
        })
    }

    /// Create a `MonitorClient` with explicit paths and the production runner.
    #[must_use]
    pub fn with_paths(paths: MonitorPaths) -> Self {
        Self {
            runner: Box::new(toride_runner::DuctRunner),
            paths,
        }
    }

    /// Create a `MonitorClient` with a custom runner and explicit paths
    /// (intended for tests, e.g. a fake runner with canned output).
    #[must_use]
    pub fn with_runner(runner: Box<dyn toride_runner::Runner>, paths: MonitorPaths) -> Self {
        Self { runner, paths }
    }

    /// Resolved paths to the required system binaries.
    #[must_use]
    pub fn paths(&self) -> &MonitorPaths {
        &self.paths
    }

    /// The command runner used to execute system binaries.
    #[must_use]
    pub fn runner(&self) -> &dyn toride_runner::Runner {
        self.runner.as_ref()
    }

    /// Set up iptables OUTPUT chain logging rules.
    ///
    /// # Errors
    /// If rule validation or any iptables command fails.
    pub fn setup_logging(&self, rules: &[LoggingRule]) -> Result<()> {
        let chain = OutputChain::new(&self.paths, self.runner.as_ref());
        for rule in rules {
            chain.add_rule(rule)?;
        }
        Ok(())
    }

    /// Remove all iptables OUTPUT chain logging rules.
    ///
    /// # Errors
    /// If the iptables commands fail.
    pub fn teardown_logging(&self) -> Result<()> {
        let chain = OutputChain::new(&self.paths, self.runner.as_ref());
        chain.remove_all()
    }

    /// Take a snapshot of current outbound connections: `ss` for socket state,
    /// `conntrack` for byte/packet counters, aggregated into a [`MonitorReport`].
    ///
    /// # Errors
    /// If the `ss` system command fails; conntrack failures are logged,
    /// not propagated.
    pub fn snapshot(&self) -> Result<MonitorReport> {
        let connections = self.collect_ss_connections()?;

        let total_connections = connections.len() as u64;

        let unique_destinations = {
            use std::collections::HashSet;
            connections
                .iter()
                .map(|c| c.dst)
                .collect::<HashSet<_>>()
                .len() as u64
        };

        let mut by_protocol = std::collections::HashMap::new();
        let mut by_port = std::collections::HashMap::new();
        let mut by_state = std::collections::HashMap::new();

        for conn in &connections {
            *by_protocol.entry(conn.protocol.clone()).or_insert(0u64) += 1;
            *by_port.entry(conn.dst_port).or_insert(0u64) += 1;
            *by_state.entry(conn.state.clone()).or_insert(0u64) += 1;
        }

        let (total_bytes, total_packets) = self.collect_conntrack_stats();

        Ok(MonitorReport {
            timestamp: std::time::SystemTime::now(),
            connections,
            total_connections,
            unique_destinations,
            by_protocol,
            by_port,
            by_state,
            total_bytes,
            total_packets,
        })
    }

    /// Run anomaly detection on a monitoring snapshot.
    ///
    /// # Errors
    /// Does not return errors; detection always produces a report
    /// (see [`AnomalyDetector::detect`]).
    pub fn detect(&self, report: &MonitorReport) -> Result<AnomalyReport> {
        let detector = AnomalyDetector::default_detector();
        detector.detect(report)
    }

    /// Run anomaly detection with explicit thresholds instead of the defaults.
    ///
    /// # Errors
    /// Does not return errors; detection always produces a report
    /// (see [`AnomalyDetector::detect`]).
    pub fn detect_with_thresholds(
        &self,
        report: &MonitorReport,
        thresholds: crate::spec::AnomalyThreshold,
    ) -> Result<AnomalyReport> {
        let detector = AnomalyDetector::new(thresholds);
        detector.detect(report)
    }

    /// Dispatch anomaly alerts to configured targets; individual dispatch
    /// failures appear in the returned reports rather than as errors.
    pub fn alert(
        &self,
        anomaly_report: &AnomalyReport,
        targets: &[AlertTarget],
    ) -> Vec<crate::report::AlertReport> {
        let dispatcher = AlertDispatcher::new(&self.paths, self.runner.as_ref());
        let mut all_reports = Vec::new();
        for finding in &anomaly_report.findings {
            let reports = dispatcher.dispatch(finding, targets);
            all_reports.extend(reports);
        }
        all_reports
    }

    /// Apply a complete monitoring specification: set up logging rules, run a
    /// snapshot, detect anomalies, dispatch alerts.
    ///
    /// # Errors
    /// If logging setup or snapshot collection fails; alert dispatch
    /// failures are reported, not propagated.
    pub fn apply(&self, spec: &MonitorSpec) -> Result<AnomalyReport> {
        if !spec.enabled {
            tracing::info!("Monitoring disabled in spec; skipping.");
            return Ok(AnomalyReport::empty(MonitorReport::empty()));
        }

        self.setup_logging(&spec.logging_rules)?;
        let snapshot = self.snapshot()?;
        let anomalies = self.detect_with_thresholds(&snapshot, spec.thresholds.clone())?;

        if !anomalies.is_clean() {
            let alert_reports = self.alert(&anomalies, &spec.alert_targets);
            for report in &alert_reports {
                if !report.dispatched {
                    tracing::warn!(
                        "Alert dispatch failed for {}: {:?}",
                        report.target,
                        report.error
                    );
                }
            }
        }

        Ok(anomalies)
    }

    /// List all listening TCP/UDP ports with process info, via native OS
    /// APIs (`netstat2`) — no `lsof` or `ss` required.
    ///
    /// # Errors
    /// [`Error::PortsError`](crate::error::Error::PortsError) on failure.
    pub fn list_listening_ports(&self) -> Result<Vec<crate::ports::PortEntry>> {
        crate::ports::PortReader::new(&self.paths).list_listening()
    }

    /// List all network connections (every TCP/UDP socket in any state).
    ///
    /// # Errors
    /// [`Error::PortsError`](crate::error::Error::PortsError).
    pub fn list_all_ports(&self) -> Result<Vec<crate::ports::PortEntry>> {
        crate::ports::PortReader::new(&self.paths).list_all()
    }

    /// Find what process is using a specific port.
    ///
    /// # Errors
    /// [`Error::PortsError`](crate::error::Error::PortsError).
    pub fn find_port(&self, port: u16) -> Result<Vec<crate::ports::PortEntry>> {
        crate::ports::PortReader::new(&self.paths).find_by_port(port)
    }

    /// Find all ports used by a process whose name contains `name`
    /// (case-insensitive).
    ///
    /// # Errors
    /// [`Error::PortsError`](crate::error::Error::PortsError).
    pub fn find_ports_by_process(&self, name: &str) -> Result<Vec<crate::ports::PortEntry>> {
        crate::ports::PortReader::new(&self.paths).find_by_process(name)
    }

    /// Check whether a port is free (nothing listening on it).
    ///
    /// # Errors
    /// [`Error::PortsError`](crate::error::Error::PortsError).
    pub fn is_port_free(&self, port: u16) -> Result<bool> {
        crate::ports::PortReader::new(&self.paths).is_port_free(port)
    }

    fn collect_ss_connections(&self) -> Result<Vec<crate::report::ConnectionInfo>> {
        let spec = toride_runner::CommandSpec::new(self.paths.ss.to_string_lossy().into_owned())
            .args(["-tunap"]);

        let output = self.runner.run(&spec)?;
        if !output.success {
            return Err(crate::Error::CommandFailed(format!(
                "ss -tunap failed: {}",
                output.combined_output()
            )));
        }

        let entries = parse_ss_output(&output.stdout)?;
        Ok(entries.iter().filter_map(ss_entry_to_connection).collect())
    }

    fn collect_conntrack_stats(&self) -> (Option<u64>, Option<u64>) {
        let reader = ConntrackReader::new(&self.paths, self.runner.as_ref());
        match reader.list_all() {
            Ok(entries) => {
                let total_bytes: u64 = entries.iter().filter_map(|e| e.bytes).sum();
                let total_packets: u64 = entries.iter().filter_map(|e| e.packets).sum();
                (Some(total_bytes), Some(total_packets))
            }
            Err(e) => {
                tracing::debug!("conntrack stats unavailable: {e}");
                (None, None)
            }
        }
    }
}
