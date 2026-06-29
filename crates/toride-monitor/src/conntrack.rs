//! Conntrack data parsing and connection tracking.
//!
//! Provides [`ConntrackReader`] for querying the kernel connection tracking
//! table via the `conntrack` command and converting raw output into
//! structured types.

use crate::Result;
use crate::parse::{ConntrackEntry, parse_conntrack_output};
use crate::paths::MonitorPaths;
use crate::report::ConnectionInfo;

/// Reads connection tracking data from the kernel via `conntrack`.
///
/// Wraps the `conntrack` command-line tool to list, filter, and parse
/// connection tracking entries.
pub struct ConntrackReader<'a> {
    /// Binary paths for system commands.
    paths: &'a MonitorPaths,
    /// Command runner used to execute conntrack.
    runner: &'a dyn toride_runner::Runner,
}

impl<'a> ConntrackReader<'a> {
    /// Create a new `ConntrackReader` with the given paths and runner.
    #[must_use]
    pub fn new(paths: &'a MonitorPaths, runner: &'a dyn toride_runner::Runner) -> Self {
        Self { paths, runner }
    }

    /// List all connection tracking entries.
    ///
    /// Runs `conntrack -L` and parses the output into structured entries.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::CommandFailed`] if the `conntrack` command fails,
    /// or [`crate::Error::ConntrackError`] if parsing fails.
    pub fn list_all(&self) -> Result<Vec<ConntrackEntry>> {
        let output = self.run_conntrack(&["-L".to_owned()])?;
        parse_conntrack_output(&output.stdout)
    }

    /// List connection tracking entries filtered by destination port.
    ///
    /// Runs `conntrack -L -p <proto> --dport <port>`.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::CommandFailed`] if the `conntrack` command fails.
    pub fn list_by_dport(&self, proto: &str, port: u16) -> Result<Vec<ConntrackEntry>> {
        let output = self.run_conntrack(&[
            "-L".to_owned(),
            "-p".into(),
            proto.into(),
            "--dport".into(),
            port.to_string(),
        ])?;
        parse_conntrack_output(&output.stdout)
    }

    /// Convert conntrack entries to [`ConnectionInfo`] instances.
    ///
    /// Maps raw conntrack data into the unified connection info type
    /// used by the reporting subsystem. This method does not require
    /// the `client` feature as it operates purely on in-memory data.
    pub fn to_connection_info(entries: &[ConntrackEntry]) -> Vec<ConnectionInfo> {
        entries
            .iter()
            .map(|e| ConnectionInfo {
                src: e.src,
                src_port: e.sport.unwrap_or(0),
                dst: e.dst,
                dst_port: e.dport.unwrap_or(0),
                protocol: match e.proto {
                    6 => "tcp".to_owned(),
                    17 => "udp".to_owned(),
                    1 => "icmp".to_owned(),
                    other => format!("proto-{other}"),
                },
                state: e.state.clone().unwrap_or_default(),
                bytes: e.bytes,
                packets: e.packets,
            })
            .collect()
    }

    /// Count the number of currently tracked connections.
    ///
    /// Runs `conntrack -C` to get the count directly.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::CommandFailed`] if the `conntrack` command fails.
    pub fn count(&self) -> Result<u64> {
        let output = self.run_conntrack(&["-C".to_owned()])?;
        let count: u64 = output
            .stdout
            .trim()
            .parse()
            .map_err(|e| crate::Error::ConntrackError(format!("invalid count: {e}")))?;
        Ok(count)
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Run a `conntrack` subcommand with the given arguments.
    fn run_conntrack(&self, args: &[String]) -> Result<toride_runner::CommandOutput> {
        let spec =
            toride_runner::CommandSpec::new(self.paths.conntrack.to_string_lossy().into_owned())
                .args(args.iter().cloned());
        let output = self.runner.run(&spec)?;
        if !output.success {
            return Err(crate::Error::ConntrackError(format!(
                "conntrack {} failed: {}",
                args.join(" "),
                output.combined_output()
            )));
        }
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::paths::MonitorPaths;
    use std::path::PathBuf;
    use toride_runner::{CommandOutput, CommandSpec, FakeRunner};

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

    /// `End-to-end` `FakeRunner` test for `ConntrackReader::list_all()` against a
    /// real `/proc/net/nf_conntrack` sample containing BOTH tcp and udp lines
    /// (plus sctp/dccp/icmp). This is the regression that Wave-2a found: the
    /// parser read `parts[3]` unconditionally and captured the UDP `src=` field
    /// as a bogus "state".
    ///
    /// Source: kernel conntrack textual dump layout, documented at
    ///   - <https://stackoverflow.com/questions/16034698>
    ///   - <https://unix.stackexchange.com/questions/400394>
    ///   - docs.kernel.org/netlink/specs/conntrack.html (protoinfo-tcp/-sctp/
    ///     -dccp are the only protocols that emit a state keyword)
    #[test]
    fn list_all_parses_mixed_protocols_from_real_proc_sample() {
        // Real-world sample shape. `conntrack -L` emits the same per-line
        // layout as /proc/net/nf_conntrack (minus the leading L3 family/name
        // columns, which our parser does not consume). Here we feed the
        // canonical `conntrack -L` style.
        let sample = "\
tcp      6 431998 ESTABLISHED src=10.0.2.2 dst=93.184.216.34 sport=58994 dport=443 bytes=2048 packets=12
udp      17 30 src=192.168.1.10 dst=8.8.8.8 sport=54321 dport=53 bytes=128 packets=2
sctp     132 210 ESTABLISHED src=10.0.0.7 dst=10.0.0.8 sport=3868 dport=3868 bytes=0 packets=0
dccp     33 120 REQUEST src=10.0.0.9 dst=10.0.0.10 sport=5001 dport=5001 bytes=64 packets=1
icmp     1 25 src=10.0.0.11 dst=10.0.0.12 bytes=56 packets=1
";

        let runner = FakeRunner::new().respond(
            CommandSpec::new("/usr/sbin/conntrack").args(["-L"]),
            CommandOutput::from_stdout(sample),
        );
        let paths = test_paths();
        let reader = ConntrackReader::new(&paths, &runner);

        let entries = reader.list_all().unwrap();
        assert_eq!(entries.len(), 5);

        // tcp -> state present
        assert_eq!(entries[0].proto, 6);
        assert_eq!(entries[0].state.as_deref(), Some("ESTABLISHED"));

        // udp -> NO state (the regression: previously bogus "src=...")
        assert_eq!(entries[1].proto, 17);
        assert_eq!(entries[1].state, None, "udp must report no state");
        assert_eq!(entries[1].dport, Some(53));

        // sctp / dccp -> state present
        assert_eq!(entries[2].proto, 132);
        assert_eq!(entries[2].state.as_deref(), Some("ESTABLISHED"));
        assert_eq!(entries[3].proto, 33);
        assert_eq!(entries[3].state.as_deref(), Some("REQUEST"));

        // icmp -> NO state
        assert_eq!(entries[4].proto, 1);
        assert_eq!(entries[4].state, None);

        // The reader was actually invoked with `conntrack -L` (verifies the
        // spec plumbing, not just the parser).
        runner.assert_called_with(&CommandSpec::new("/usr/sbin/conntrack").args(["-L"]));

        // Round-trip through ConnectionInfo: udp state must be empty string
        // (not the leaked src= value).
        let conns = ConntrackReader::to_connection_info(&entries);
        assert_eq!(conns[1].protocol, "udp");
        assert!(conns[1].state.is_empty(), "udp state must be empty");
    }
}
