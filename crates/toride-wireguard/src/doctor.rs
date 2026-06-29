//! Tunnel health diagnostics for WireGuard.
//!
//! Provides a diagnostic engine that checks:
//! - WireGuard binary availability
//! - Interface status and connectivity
//! - Key file permissions
//! - DNS leak detection
//! - Configuration validity

use crate::error::{Error, Result};
use crate::report::{Finding, InterfaceReport, Severity, TransferStats, WireguardReport};

use toride_runner::Runner;

// ---------------------------------------------------------------------------
// `wg show` verbose parsing (free helpers)
// ---------------------------------------------------------------------------

/// Parsed interface summary from `wg show` verbose output.
#[derive(Debug, Clone, Default)]
struct ParsedInterface {
    name: String,
    listen_port: u16,
    peer_count: usize,
    active_peers: usize,
    /// Aggregated bytes received across all peers (sum of `transfer:` rx).
    bytes_received: u64,
    /// Aggregated bytes sent across all peers (sum of `transfer:` tx).
    bytes_sent: u64,
}

/// Parse the default (verbose) output of `wg show`.
///
/// The output is grouped by `interface:` and `peer:` headers, e.g.:
///
/// ```text
/// interface: wg0
///   public key: <key>
///   private key: (hidden)
///   listening port: 51820
///
/// peer: <key>
///   endpoint: 1.2.3.4:51820
///   allowed ips: 10.0.0.2/32
///   latest handshake: 4 seconds ago
///   transfer: 1.2 KiB received, 3.4 KiB sent
/// ```
///
/// We extract interface name + listen port, count peers per interface, and
/// count peers that have completed a handshake ("latest handshake:" line).
///
/// # Errors
///
/// Returns [`Error::ConfigParse`] if no interface header is found at all.
fn parse_wg_show_verbose(output: &str) -> Result<Vec<ParsedInterface>> {
    let mut ifaces: Vec<ParsedInterface> = Vec::new();
    let mut current: Option<ParsedInterface> = None;
    // A peer is "active" if we have seen a `latest handshake:` line for it
    // since its `peer:` header. Track per current peer.
    let mut peer_active = false;

    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        if let Some(rest) = trimmed.strip_prefix("interface:") {
            if let Some(iface) = current.take() {
                ifaces.push(iface);
            }
            current = Some(ParsedInterface {
                name: rest.trim().to_owned(),
                ..Default::default()
            });
            peer_active = false;
        } else if let Some(rest) = trimmed.strip_prefix("peer:") {
            // A new peer block starts. If we're inside an interface, bump its
            // peer count and carry forward the active flag.
            if let Some(ref mut iface) = current {
                iface.peer_count += 1;
                if peer_active {
                    iface.active_peers += 1;
                }
            }
            peer_active = false;
            let _ = rest; // peer public key, not needed for counts
        } else if trimmed.starts_with("listening port:") {
            if let Some(port_str) = trimmed.split_whitespace().nth(2)
                && let Some(ref mut iface) = current
                && let Ok(port) = port_str.parse::<u16>()
            {
                iface.listen_port = port;
            }
        } else if trimmed.starts_with("latest handshake:") {
            // This peer has completed at least one handshake.
            peer_active = true;
        } else if let Some(rest) = trimmed.strip_prefix("transfer:") {
            // `wg show` prints: "transfer: <rx> received, <tx> sent"
            // where <rx>/<tx> may be a raw byte count or a humanized value
            // like "1.2 KiB". Parse both forms and accumulate per-interface.
            if let Some((rx, tx)) = parse_transfer_line(rest)
                && let Some(ref mut iface) = current
            {
                iface.bytes_received = iface.bytes_received.saturating_add(rx);
                iface.bytes_sent = iface.bytes_sent.saturating_add(tx);
            }
        }
    }

    // Flush the trailing peer's active state for the last interface.
    if let Some(ref mut iface) = current
        && peer_active
    {
        iface.active_peers += 1;
    }
    if let Some(iface) = current {
        ifaces.push(iface);
    }

    if ifaces.is_empty() && !output.trim().is_empty() {
        return Err(Error::ConfigParse(
            "no `interface:` headers found in `wg show` output".to_owned(),
        ));
    }

    Ok(ifaces)
}

/// Parse a `transfer:` line payload of the form
/// `<rx> received, <tx> sent` into `(bytes_received, bytes_sent)`.
///
/// Each value may be a raw integer (e.g. `12345`) or a humanized size with a
/// binary unit suffix (e.g. `1.23 GiB`, `500 MiB`, `3.4 KiB`, `768 B`).
/// Returns `None` if neither value can be parsed.
fn parse_transfer_line(payload: &str) -> Option<(u64, u64)> {
    let mut parts = payload.split(',');
    let rx_part = parts.next()?;
    let tx_part = parts.next()?;
    let rx = parse_byte_value(rx_part, "received")?;
    let tx = parse_byte_value(tx_part, "sent")?;
    Some((rx, tx))
}

/// Parse a single transfer field like `"1.23 KiB received"` or `"500 sent"`.
fn parse_byte_value(field: &str, keyword: &str) -> Option<u64> {
    // The field looks like "<value>[ <unit>] <keyword>". Find the keyword and
    // take the tokens before it.
    let idx = field.find(keyword)?;
    let value_part = field[..idx].trim();
    let mut tokens = value_part.split_whitespace();
    let number = tokens.next()?;
    let unit = tokens.next().unwrap_or("");
    let magnitude: f64 = number.parse().ok()?;
    let multiplier: f64 = match unit.trim_end_matches('s') {
        "B" | "" => 1.0,
        "KiB" | "K" => 1024.0,
        "MiB" | "M" => 1024.0_f64.powi(2),
        "GiB" | "G" => 1024.0_f64.powi(3),
        "TiB" | "T" => 1024.0_f64.powi(4),
        "PiB" | "P" => 1024.0_f64.powi(5),
        "EiB" | "E" => 1024.0_f64.powi(6),
        _ => {
            // Unknown unit: assume raw bytes if the token parses as a number
            // suffix was empty, else give up.
            if unit.is_empty() {
                1.0
            } else {
                return None;
            }
        }
    };
    // Byte counts are non-negative. Clamp to a finite non-negative range before
    // the f64->u64 conversion so we never truncate below zero or overflow; the
    // explicit `u64::MAX` upper bound keeps the cast in range.
    let bytes = (magnitude * multiplier).max(0.0);
    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_precision_loss,
        reason = "bytes is clamped to >= 0 and bounded by u64::MAX; the u64::MAX-as-f64 threshold is only an overflow guard where precision loss is immaterial, and the f64->u64 cast saturates safely"
    )]
    let value = if bytes >= u64::MAX as f64 {
        u64::MAX
    } else {
        bytes as u64
    };
    Some(value)
}

/// Extract the permission bits (low 12, including setuid etc.) from a
/// `Metadata` value in a platform-agnostic way using `std::os::unix`.
///
/// Some platforms return the full `st_mode` (file-type bits + permission bits)
/// from `PermissionsExt::mode()`, so we mask down to the permission bits here.
fn file_mode_bits(metadata: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o7777
}

/// Return the DNS resolver(s) configured on the tunnel, if we can determine
/// them deterministically. Reads the `DNS =` line from the first interface
/// config found in the config dir. Returns `None` if unknown.
fn first_tunnel_dns(report: &WireguardReport) -> Option<Vec<String>> {
    if !report.config_dir_exists {
        return None;
    }
    let entries = std::fs::read_dir(&report.config_dir).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().is_some_and(|ext| ext == "conf") {
            let content = std::fs::read_to_string(&path).ok()?;
            for line in content.lines() {
                let trimmed = line.trim();
                if let Some(rest) = trimmed.strip_prefix("DNS")
                    && let Some((_, value)) = rest.split_once('=')
                {
                    let dns: Vec<String> = value
                        .trim()
                        .split(',')
                        .map(|s| s.trim().to_owned())
                        .filter(|s| !s.is_empty())
                        .collect();
                    if !dns.is_empty() {
                        return Some(dns);
                    }
                }
            }
        }
    }
    None
}

/// Read the system's configured DNS resolvers from `/etc/resolv.conf`.
///
/// Returns `None` if the file cannot be read or no `nameserver` lines are
/// present, in which case the DNS-leak check stays silent.
fn read_system_dns() -> Option<Vec<String>> {
    let content = std::fs::read_to_string("/etc/resolv.conf").ok()?;
    let ns: Vec<String> = content
        .lines()
        .filter_map(|l| {
            let l = l.trim();
            l.strip_prefix("nameserver").map(|s| s.trim().to_owned())
        })
        .filter(|s| !s.is_empty())
        .collect();
    if ns.is_empty() { None } else { Some(ns) }
}

// ---------------------------------------------------------------------------
// DoctorScope
// ---------------------------------------------------------------------------

/// Scope for diagnostic checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DoctorScope {
    /// Run all available checks.
    All,
    /// Only check binary availability and basic setup.
    Setup,
    /// Only check interface status and peer connectivity.
    Connectivity,
    /// Only check key file permissions and security.
    Security,
}

// ---------------------------------------------------------------------------
// Doctor
// ---------------------------------------------------------------------------

/// Diagnostic engine for WireGuard installations.
///
/// Runs a series of health checks and collects findings into a
/// [`WireguardReport`].
///
/// All subprocess invocations (`wg show`, binary discovery) go through the
/// [`Runner`](toride_runner::Runner) trait, so diagnostics are fully testable
/// with [`FakeRunner`](toride_runner::FakeRunner).
pub struct Doctor<R: Runner + Send + Sync = toride_runner::DuctRunner> {
    runner: std::sync::Arc<R>,
}

impl Doctor<toride_runner::DuctRunner> {
    /// Create a new diagnostic engine using the default production runner.
    #[must_use]
    pub fn new() -> Self {
        Self {
            runner: std::sync::Arc::new(toride_runner::DuctRunner),
        }
    }
}

impl Default for Doctor<toride_runner::DuctRunner> {
    fn default() -> Self {
        Self::new()
    }
}

impl<R: Runner + Send + Sync> Doctor<R> {
    /// Create a diagnostic engine with a custom command runner (for testing).
    #[must_use]
    pub fn with_runner(runner: R) -> Self {
        Self {
            runner: std::sync::Arc::new(runner),
        }
    }

    /// Return a reference to the underlying runner.
    #[must_use]
    pub fn runner(&self) -> &R {
        &self.runner
    }

    /// Run diagnostics with the given scope and return a report.
    ///
    /// # Errors
    ///
    /// Returns an error only for fundamental failures (e.g. unable to run
    /// any checks). Individual check failures appear as [`Finding`] values
    /// in the report.
    pub fn run(&self, scope: &DoctorScope) -> Result<WireguardReport> {
        let mut report = WireguardReport::new();

        match scope {
            DoctorScope::All => {
                Self::check_binaries(&mut report);
                Self::check_config_dir(&mut report);
                self.check_interfaces(&mut report);
                Self::check_key_permissions(&mut report);
                Self::check_dns_leak(&mut report);
            }
            DoctorScope::Setup => {
                Self::check_binaries(&mut report);
                Self::check_config_dir(&mut report);
            }
            DoctorScope::Connectivity => {
                self.check_interfaces(&mut report);
            }
            DoctorScope::Security => {
                Self::check_key_permissions(&mut report);
            }
        }

        Ok(report)
    }

    // -----------------------------------------------------------------------
    // Individual checks
    // -----------------------------------------------------------------------

    /// Check that `wg` and `wg-quick` binaries are available.
    fn check_binaries(report: &mut WireguardReport) {
        tracing::debug!("checking WireGuard binaries");

        report.wg_binary_found = which::which("wg").is_ok();
        if !report.wg_binary_found {
            report.findings.push(
                Finding::new(
                    "wireguard.binary.wg",
                    Severity::Error,
                    "`wg` binary not found on $PATH".to_owned(),
                )
                .with_fix("Install wireguard-tools: apt install wireguard-tools".to_owned()),
            );
        }

        report.wg_quick_binary_found = which::which("wg-quick").is_ok();
        if !report.wg_quick_binary_found {
            report.findings.push(
                Finding::new(
                    "wireguard.binary.wg-quick",
                    Severity::Warning,
                    "`wg-quick` binary not found on $PATH".to_owned(),
                )
                .with_fix("Install wireguard-tools: apt install wireguard-tools".to_owned()),
            );
        }
    }

    /// Check that the WireGuard config directory exists with proper permissions.
    fn check_config_dir(report: &mut WireguardReport) {
        tracing::debug!("checking WireGuard config directory");
        report.config_dir_exists = report.config_dir.is_dir();

        if !report.config_dir_exists {
            report.findings.push(Finding::new(
                "wireguard.config-dir",
                Severity::Warning,
                format!(
                    "WireGuard config directory does not exist: {}",
                    report.config_dir.display()
                ),
            ));
        }
    }

    /// Check interface status and peer connectivity.
    ///
    /// Runs `wg show` (default verbose output) and parses it into
    /// [`InterfaceReport`] values: interface names, listen ports, configured
    /// peer counts, and how many peers have a recent handshake.
    ///
    /// If the `wg` binary is absent this emits a critical finding instead of
    /// failing the whole diagnostic run, so the user still gets a useful report.
    fn check_interfaces(&self, report: &mut WireguardReport) {
        tracing::debug!("checking WireGuard interfaces");

        if !report.wg_binary_found {
            report.findings.push(
                Finding::new(
                    "wireguard.interface.binary",
                    Severity::Error,
                    "wireguard binary not found: cannot inspect interfaces".to_owned(),
                )
                .with_fix(
                    "Install wireguard-tools (apt install wireguard-tools) and re-run".to_owned(),
                ),
            );
            return;
        }

        let output = match self.run_wg_show() {
            Ok(out) => out,
            Err(err) => {
                report.findings.push(
                    Finding::new(
                        "wireguard.interface.show",
                        Severity::Warning,
                        format!("failed to run `wg show`: {err}"),
                    )
                    .with_fix(
                        "Ensure the user has permission to run `wg` (e.g. via sudo / wireguard group)"
                            .to_owned(),
                    ),
                );
                return;
            }
        };

        if output.trim().is_empty() {
            report.findings.push(Finding::new(
                "wireguard.interface.none",
                Severity::Info,
                "no WireGuard interfaces are currently up".to_owned(),
            ));
            return;
        }

        let parsed = match parse_wg_show_verbose(&output) {
            Ok(ifaces) => ifaces,
            Err(err) => {
                report.findings.push(Finding::new(
                    "wireguard.interface.parse",
                    Severity::Warning,
                    format!("failed to parse `wg show` output: {err}"),
                ));
                return;
            }
        };

        for parsed_iface in parsed {
            report.interfaces.push(InterfaceReport {
                name: parsed_iface.name.clone(),
                is_up: true,
                peer_count: parsed_iface.peer_count,
                active_peers: parsed_iface.active_peers,
                listen_port: parsed_iface.listen_port,
                stats: TransferStats {
                    received: parsed_iface.bytes_received,
                    sent: parsed_iface.bytes_sent,
                },
            });
        }
    }

    /// Check that WireGuard config files have restrictive permissions.
    ///
    /// For each `/etc/wireguard/*.conf`, stats the file mode. A config file
    /// that contains a private key must not be group- or world-readable; the
    /// expected mode is `0600`. Permissive modes (any bit set in `0o077`)
    /// produce a warning. If no `.conf` files exist at all, an informational
    /// finding is emitted so the absence is visible rather than silent.
    fn check_key_permissions(report: &mut WireguardReport) {
        tracing::debug!("checking key file permissions");

        if !report.config_dir_exists {
            // The config-dir check already reported the missing directory.
            return;
        }

        let mut confs: Vec<std::path::PathBuf> = match std::fs::read_dir(&report.config_dir) {
            Ok(rd) => rd
                .filter_map(std::result::Result::ok)
                .map(|e| e.path())
                .filter(|p| p.extension().is_some_and(|ext| ext == "conf"))
                .collect(),
            Err(err) => {
                report.findings.push(Finding::new(
                    "wireguard.key-permissions.readdir",
                    Severity::Warning,
                    format!(
                        "cannot read WireGuard config directory {}: {err}",
                        report.config_dir.display()
                    ),
                ));
                return;
            }
        };
        confs.sort();

        if confs.is_empty() {
            report.findings.push(Finding::new(
                "wireguard.key-permissions.none",
                Severity::Info,
                format!(
                    "no WireGuard config files found in {}",
                    report.config_dir.display()
                ),
            ));
            return;
        }

        for conf in &confs {
            let mode = match std::fs::metadata(conf) {
                Ok(m) => file_mode_bits(&m),
                Err(err) => {
                    report.findings.push(Finding::new(
                        "wireguard.key-permissions.stat",
                        Severity::Warning,
                        format!("cannot stat {}: {err}", conf.display()),
                    ));
                    continue;
                }
            };

            // Group/other read/write/exec bits beyond the owner's.
            if mode & 0o077 != 0 {
                let severity = if mode & 0o022 != 0 {
                    // Group/other write -> private key is writable beyond owner.
                    Severity::Error
                } else {
                    Severity::Warning
                };
                report.findings.push(
                    Finding::new(
                        "wireguard.key-permissions.mode",
                        severity,
                        format!(
                            "WireGuard config {} is mode {:04o}; private key may be exposed to group/other",
                            conf.display(),
                            mode,
                        ),
                    )
                    .with_fix(
                        "Restrict the file: `chmod 600 <file>` (only the owner should read it)"
                            .to_owned(),
                    ),
                );
            } else if mode != 0o600 {
                // Owner-only but not exactly 0600 (e.g. 0400 or 0700). Note it.
                report.findings.push(Finding::new(
                    "wireguard.key-permissions.mode",
                    Severity::Info,
                    format!(
                        "WireGuard config {} is mode {:04o} (owner-only); 0600 is the convention",
                        conf.display(),
                        mode,
                    ),
                ));
            }
        }
    }

    /// Check for DNS leaks when the tunnel is active.
    ///
    /// Conservative, best-effort heuristic. We only emit a finding when we can
    /// *confidently* determine that the tunnel's configured DNS resolver differs
    /// from the active system resolver. If either resolver cannot be read, or
    /// they agree, or there is ambiguity, we emit nothing rather than risk a
    /// false positive.
    fn check_dns_leak(report: &mut WireguardReport) {
        tracing::debug!("checking for DNS leaks");

        let Some(tunnel_dns) = first_tunnel_dns(report) else {
            return;
        };
        let Some(system_dns) = read_system_dns() else {
            return;
        };

        if !system_dns.is_empty()
            && !tunnel_dns.is_empty()
            && !system_dns.iter().any(|s| tunnel_dns.contains(s))
        {
            report.findings.push(Finding::new(
                "wireguard.dns-leak",
                Severity::Info,
                format!(
                    "system resolvers ({}) differ from tunnel DNS ({}); queries may bypass the tunnel",
                    system_dns.join(", "),
                    tunnel_dns.join(", "),
                ),
            ));
        }
    }

    /// Run `wg show` through the injected runner and return its stdout.
    ///
    /// This routes the command through the same [`Runner`](toride_runner::Runner)
    /// abstraction the rest of the crate uses (instead of a raw
    /// `std::process::Command`), so it respects redaction, timeouts, and is
    /// testable with [`FakeRunner`](toride_runner::FakeRunner).
    fn run_wg_show(&self) -> std::result::Result<String, String> {
        use std::time::Duration;

        let spec = toride_runner::CommandSpec::new("wg")
            .arg("show")
            .timeout(Duration::from_secs(15));
        let output = self
            .runner
            .run(&spec)
            .map_err(|e| format!("failed to run `wg show`: {e}"))?;
        if !output.success {
            let stderr = output.stderr.trim();
            let detail = if stderr.is_empty() {
                format!("`wg show` exited with code {:?}", output.exit_code)
            } else {
                format!("`wg show` failed: {stderr}")
            };
            return Err(detail);
        }
        Ok(output.stdout)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_setup_scope() {
        let doc = Doctor::new();
        let report = doc.run(&DoctorScope::Setup).unwrap();
        // Binaries likely not found in test environment.
        assert!(!report.findings.is_empty() || !report.wg_binary_found);
    }

    #[test]
    fn run_all_scope() {
        let doc = Doctor::new();
        let report = doc.run(&DoctorScope::All).unwrap();
        assert!(report.config_dir.exists() || !report.config_dir_exists);
    }

    #[test]
    fn doctor_scope_variants() {
        assert_ne!(DoctorScope::All, DoctorScope::Setup);
        assert_ne!(DoctorScope::Connectivity, DoctorScope::Security);
    }

    #[test]
    fn parse_verbose_single_interface_two_peers() {
        let output = "\
interface: wg0
  public key: AAA=
  private key: (hidden)
  listening port: 51820

peer: BBB=
  endpoint: 1.2.3.4:51820
  allowed ips: 10.0.0.2/32
  latest handshake: 4 seconds ago
  transfer: 1.2 KiB received, 3.4 KiB sent

peer: CCC=
  endpoint: 5.6.7.8:51820
  allowed ips: 10.0.0.3/32
";
        let ifaces = parse_wg_show_verbose(output).unwrap();
        assert_eq!(ifaces.len(), 1);
        assert_eq!(ifaces[0].name, "wg0");
        assert_eq!(ifaces[0].listen_port, 51820);
        assert_eq!(ifaces[0].peer_count, 2);
        assert_eq!(ifaces[0].active_peers, 1);
    }

    #[test]
    fn parse_verbose_multiple_interfaces() {
        let output = "\
interface: wg0
  listening port: 51820

interface: wg1
  listening port: 51821

peer: X=
  latest handshake: 1 minute ago
";
        let ifaces = parse_wg_show_verbose(output).unwrap();
        assert_eq!(ifaces.len(), 2);
        assert_eq!(ifaces[0].peer_count, 0);
        assert_eq!(ifaces[0].active_peers, 0);
        assert_eq!(ifaces[1].peer_count, 1);
        assert_eq!(ifaces[1].active_peers, 1);
    }

    #[test]
    fn parse_verbose_empty_is_empty() {
        assert!(parse_wg_show_verbose("").unwrap().is_empty());
        assert!(parse_wg_show_verbose("   \n  \n").unwrap().is_empty());
    }

    #[test]
    fn parse_verbose_unrecognized_is_error() {
        // Non-empty but no interface header.
        assert!(parse_wg_show_verbose("just some garbage\n").is_err());
    }

    #[test]
    fn parse_transfer_line_handles_humanized_and_raw() {
        // Humanized values with binary units.
        let (rx, tx) = parse_transfer_line(" 1.2 KiB received, 3.4 KiB sent").unwrap();
        let one_point_two_kib = kib_bytes(1.2);
        let three_point_four_kib = kib_bytes(3.4);
        assert_eq!(rx, one_point_two_kib);
        assert_eq!(tx, three_point_four_kib);

        // Raw byte counts (no unit suffix).
        let (rx, tx) = parse_transfer_line(" 1024 received, 2048 sent").unwrap();
        assert_eq!(rx, 1024);
        assert_eq!(tx, 2048);

        // Larger units.
        let (rx, _tx) = parse_transfer_line(" 2.5 GiB received, 0 B sent").unwrap();
        let two_point_five_gib = gib_bytes(2.5);
        assert_eq!(rx, two_point_five_gib);
    }

    /// Test helper: convert a magnitude in KiB to whole bytes.
    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "test fixture with a small positive magnitude; cast is exact"
    )]
    fn kib_bytes(magnitude: f64) -> u64 {
        (magnitude * 1024.0) as u64
    }

    /// Test helper: convert a magnitude in GiB to whole bytes.
    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "test fixture with a small positive magnitude; cast is exact"
    )]
    fn gib_bytes(magnitude: f64) -> u64 {
        (magnitude * 1024.0_f64.powi(3)) as u64
    }

    #[test]
    fn parse_transfer_line_rejects_garbage() {
        assert!(parse_transfer_line("nothing useful here").is_none());
        assert!(parse_transfer_line("abc received, def sent").is_none());
    }

    #[test]
    fn parse_verbose_aggregates_transfer_stats() {
        let output = "\
interface: wg0
  listening port: 51820

peer: AAA=
  endpoint: 1.2.3.4:51820
  allowed ips: 10.0.0.2/32
  latest handshake: 4 seconds ago
  transfer: 1.0 KiB received, 2.0 KiB sent

peer: BBB=
  endpoint: 5.6.7.8:51820
  allowed ips: 10.0.0.3/32
  transfer: 512 B received, 256 B sent
";
        let ifaces = parse_wg_show_verbose(output).unwrap();
        assert_eq!(ifaces.len(), 1);
        // 1024 + 512 = 1536 received; 2048 + 256 = 2304 sent.
        assert_eq!(ifaces[0].bytes_received, 1536);
        assert_eq!(ifaces[0].bytes_sent, 2304);
    }

    /// The doctor routes `wg show` through the injected runner (not a raw
    /// `std::process::Command`), so a FakeRunner-backed doctor can capture the
    /// exact command and feed canned output.
    #[test]
    fn doctor_runs_wg_show_via_runner_and_populates_stats() {
        use toride_runner::fake::FakeRunner;

        let canned = "\
interface: wg0
  listening port: 51820

peer: AAA=
  latest handshake: 4 seconds ago
  transfer: 1024 received, 2048 sent
";
        let runner =
            FakeRunner::new().push_response(toride_runner::CommandOutput::from_stdout(canned));
        let doc = Doctor::with_runner(runner);

        let mut report = WireguardReport {
            wg_binary_found: true,
            ..WireguardReport::default()
        };
        doc.check_interfaces(&mut report);

        assert_eq!(report.interfaces.len(), 1);
        let iface = &report.interfaces[0];
        assert_eq!(iface.name, "wg0");
        assert_eq!(iface.peer_count, 1);
        assert_eq!(iface.active_peers, 1);
        assert_eq!(iface.stats.received, 1024);
        assert_eq!(iface.stats.sent, 2048);

        // Confirm `wg show` was the command actually issued.
        doc.runner()
            .assert_called_with(&toride_runner::CommandSpec::new("wg").arg("show"));
    }

    /// When `wg show` fails, a warning finding is emitted (not a hard error).
    #[test]
    fn doctor_emits_warning_when_wg_show_fails() {
        use toride_runner::fake::FakeRunner;

        let runner = FakeRunner::new().push_response(toride_runner::CommandOutput::from_stderr(
            "permission denied",
            1,
        ));
        let doc = Doctor::with_runner(runner);

        let mut report = WireguardReport {
            wg_binary_found: true,
            ..WireguardReport::default()
        };
        doc.check_interfaces(&mut report);

        assert!(
            report
                .findings
                .iter()
                .any(|f| f.check_id == "wireguard.interface.show")
        );
    }

    #[test]
    fn key_permissions_flags_world_readable() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let conf = dir.path().join("wg0.conf");
        std::fs::write(&conf, "[Interface]\nPrivateKey = secret\n").unwrap();
        std::fs::set_permissions(&conf, std::fs::Permissions::from_mode(0o644)).unwrap();

        let mut report = WireguardReport {
            config_dir: dir.path().to_owned(),
            config_dir_exists: true,
            ..WireguardReport::default()
        };

        Doctor::<toride_runner::DuctRunner>::check_key_permissions(&mut report);

        assert!(
            report
                .findings
                .iter()
                .any(|f| f.check_id == "wireguard.key-permissions.mode"
                    && f.severity == Severity::Warning),
            "expected a warning for world-readable conf"
        );
    }

    #[test]
    fn key_permissions_errors_on_group_writable() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let conf = dir.path().join("wg0.conf");
        std::fs::write(&conf, "[Interface]\nPrivateKey = secret\n").unwrap();
        std::fs::set_permissions(&conf, std::fs::Permissions::from_mode(0o664)).unwrap();

        let mut report = WireguardReport {
            config_dir: dir.path().to_owned(),
            config_dir_exists: true,
            ..WireguardReport::default()
        };

        Doctor::<toride_runner::DuctRunner>::check_key_permissions(&mut report);

        assert!(
            report
                .findings
                .iter()
                .any(|f| f.check_id == "wireguard.key-permissions.mode"
                    && f.severity == Severity::Error),
            "expected an error for group-writable conf"
        );
    }

    #[test]
    fn key_permissions_silent_on_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let conf = dir.path().join("wg0.conf");
        std::fs::write(&conf, "[Interface]\nPrivateKey = secret\n").unwrap();
        std::fs::set_permissions(&conf, std::fs::Permissions::from_mode(0o600)).unwrap();

        let mut report = WireguardReport {
            config_dir: dir.path().to_owned(),
            config_dir_exists: true,
            ..WireguardReport::default()
        };

        Doctor::<toride_runner::DuctRunner>::check_key_permissions(&mut report);

        assert!(
            !report
                .findings
                .iter()
                .any(|f| f.check_id == "wireguard.key-permissions.mode"),
            "0600 conf should not produce a mode finding"
        );
    }

    #[test]
    fn key_permissions_info_when_no_confs() {
        let dir = tempfile::tempdir().unwrap();
        let mut report = WireguardReport {
            config_dir: dir.path().to_owned(),
            config_dir_exists: true,
            ..WireguardReport::default()
        };

        Doctor::<toride_runner::DuctRunner>::check_key_permissions(&mut report);

        assert!(report.findings.iter().any(
            |f| f.check_id == "wireguard.key-permissions.none" && f.severity == Severity::Info
        ));
    }

    #[test]
    fn check_interfaces_critical_when_no_wg_binary() {
        let mut report = WireguardReport {
            wg_binary_found: false,
            ..WireguardReport::default()
        };

        let doc = Doctor::new();
        doc.check_interfaces(&mut report);

        assert!(
            report.findings.iter().any(
                |f| f.check_id == "wireguard.interface.binary" && f.severity == Severity::Error
            ),
            "absent wg binary should produce a critical interface finding"
        );
        assert!(report.interfaces.is_empty());
    }
}
