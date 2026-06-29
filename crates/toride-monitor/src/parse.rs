//! Parsers for iptables log output, conntrack entries, and `ss` output.
//!
//! Each parser takes raw string output from system commands and produces
//! structured data types. Parsers are intentionally lenient: unparseable lines
//! are skipped rather than causing hard errors.

use std::net::IpAddr;

use crate::Result;
use crate::report::ConnectionInfo;

// ---------------------------------------------------------------------------
// IptablesLogEntry
// ---------------------------------------------------------------------------

/// A single entry parsed from iptables LOG target output.
#[derive(Debug, Clone)]
pub struct IptablesLogEntry {
    /// Log prefix (e.g. `"toride-mon-out"`).
    pub prefix: String,
    /// Source IP address.
    pub src: IpAddr,
    /// Destination IP address.
    pub dst: IpAddr,
    /// Protocol (e.g. `"TCP"`, `"UDP"`).
    pub proto: String,
    /// Source port, if applicable.
    pub spt: Option<u16>,
    /// Destination port, if applicable.
    pub dpt: Option<u16>,
}

// ---------------------------------------------------------------------------
// ConntrackEntry
// ---------------------------------------------------------------------------

/// A single entry parsed from `conntrack -L` output.
#[derive(Debug, Clone)]
pub struct ConntrackEntry {
    /// Protocol number.
    pub proto: u8,
    /// Source IP address.
    pub src: IpAddr,
    /// Destination IP address.
    pub dst: IpAddr,
    /// Source port.
    pub sport: Option<u16>,
    /// Destination port.
    pub dport: Option<u16>,
    /// Connection state (e.g. `"ESTABLISHED"`).
    pub state: Option<String>,
    /// Bytes transferred.
    pub bytes: Option<u64>,
    /// Packets transferred.
    pub packets: Option<u64>,
}

// ---------------------------------------------------------------------------
// SsEntry
// ---------------------------------------------------------------------------

/// A single entry parsed from `ss -tunap` output.
#[derive(Debug, Clone)]
pub struct SsEntry {
    /// Network ID (e.g. `"tcp"`, `"udp"`).
    pub netid: String,
    /// Connection state (e.g. `"ESTAB"`, `"TIME-WAIT"`).
    pub state: String,
    /// Local address (IP:port).
    pub local: String,
    /// Peer address (IP:port).
    pub peer: String,
    /// Process information, if available.
    pub process: Option<String>,
}

// ---------------------------------------------------------------------------
// Parsing functions
// ---------------------------------------------------------------------------

/// Parse iptables LOG target output into structured entries.
///
/// Input is typically read from the kernel ring buffer (`dmesg` or
/// `/var/log/kern.log`) and filtered by the configured log prefix.
///
/// # Errors
///
/// Returns [`crate::Error::LoggingError`] only for fundamentally malformed input
/// (e.g. empty after stripping). Individual unparseable lines are skipped.
pub fn parse_iptables_log(input: &str, prefix: &str) -> Result<Vec<IptablesLogEntry>> {
    let mut entries = Vec::new();

    for line in input.lines() {
        if !line.contains(prefix) {
            continue;
        }

        // Attempt to extract fields from a typical iptables LOG line:
        // ... PREFIX IN= OUT=eth0 SRC=1.2.3.4 DST=5.6.7.8 PROTO=TCP SPT=12345 DPT=80
        let entry = parse_single_iptables_line(line, prefix);
        if let Some(e) = entry {
            entries.push(e);
        }
    }

    Ok(entries)
}

/// Parse a single iptables log line into an [`IptablesLogEntry`].
///
/// Returns `None` for lines that cannot be fully parsed rather than
/// producing an error.
fn parse_single_iptables_line(line: &str, _prefix: &str) -> Option<IptablesLogEntry> {
    let prefix = extract_field(line, "PREFIX=").unwrap_or_default();
    let src = extract_field(line, "SRC=")?.parse().ok()?;
    let dst = extract_field(line, "DST=")?.parse().ok()?;
    let proto = extract_field(line, "PROTO=").unwrap_or_else(|| "UNKNOWN".to_owned());
    let spt = extract_field(line, "SPT=").and_then(|s| s.parse().ok());
    let dpt = extract_field(line, "DPT=").and_then(|s| s.parse().ok());

    Some(IptablesLogEntry {
        prefix,
        src,
        dst,
        proto,
        spt,
        dpt,
    })
}

/// Parse `conntrack -L` output into structured entries.
///
/// # Errors
///
/// Returns [`crate::Error::ConntrackError`] for fundamentally malformed input.
/// Individual unparseable lines are skipped.
pub fn parse_conntrack_output(input: &str) -> Result<Vec<ConntrackEntry>> {
    let mut entries = Vec::new();

    for line in input.lines() {
        if let Some(entry) = parse_single_conntrack_line(line) {
            entries.push(entry);
        }
    }

    Ok(entries)
}

/// Parse a single conntrack line.
fn parse_single_conntrack_line(line: &str) -> Option<ConntrackEntry> {
    // /proc/net/nf_conntrack (and `conntrack -L`) line layout. The leading
    // whitespace-separated tokens are: protocol-name, protocol-number, ttl,
    // then — *only for protocols that carry a state machine* — the STATE.
    //
    //   tcp  6 431998 ESTABLISHED src=1.2.3.4 dst=5.6.7.8 sport=12345 dport=80 ...
    //   udp  17 30 src=1.2.3.4 dst=5.6.7.8 sport=12345 dport=53 ...
    //
    // Only the L4 protocols with a kernel `protoinfo-*` container emit a STATE
    // token in the textual dump: TCP, SCTP, and DCCP. UDP, ICMP, ICMPv6, and
    // GRE are tracked but have *no* state token — they only carry [UNREPLIED]/
    // [ASSURED] flags and a timeout. Reading `parts[3]` unconditionally for a
    // UDP line grabs the `src=` field and silently records it as the state.
    // Source: kernel conntrack protoinfo containers (protoinfo-tcp/-dccp/-sctp)
    // documented at docs.kernel.org/netlink/specs/conntrack.html; field layout
    // per https://stackoverflow.com/questions/16034698 and
    // https://unix.stackexchange.com/questions/400394.
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.is_empty() {
        return None;
    }

    let proto_name = parts.first().copied()?;
    let proto = proto_number(proto_name)?;
    // State lives at index 3 *only* for protocols with a real state machine.
    let state = if has_state_token(proto_name) {
        parts.get(3).map(|s| (*s).to_owned())
    } else {
        None
    };

    let src = extract_field(line, "src=")?.parse().ok()?;
    let dst = extract_field(line, "dst=")?.parse().ok()?;
    let sport = extract_field(line, "sport=").and_then(|s| s.parse().ok());
    let dport = extract_field(line, "dport=").and_then(|s| s.parse().ok());
    let bytes = extract_field(line, "bytes=").and_then(|s| s.parse().ok());
    let packets = extract_field(line, "packets=").and_then(|s| s.parse().ok());

    Some(ConntrackEntry {
        proto,
        src,
        dst,
        sport,
        dport,
        state,
        bytes,
        packets,
    })
}

/// Parse `ss -tunap` output into structured entries.
///
/// # Errors
///
/// Returns [`crate::Error::ConntrackError`] for fundamentally malformed input.
/// Individual unparseable lines are skipped.
pub fn parse_ss_output(input: &str) -> Result<Vec<SsEntry>> {
    let mut entries = Vec::new();
    let mut lines = input.lines();

    // Skip the header line.
    lines.next();

    for line in lines {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 4 {
            continue;
        }

        let netid = parts[0].to_string();
        let state = parts[1].to_string();
        let local = parts[2].to_string();
        let peer = parts[3].to_string();
        let process = parts.get(4).map(|s| (*s).to_string());

        entries.push(SsEntry {
            netid,
            state,
            local,
            peer,
            process,
        });
    }

    Ok(entries)
}

/// Convert an [`SsEntry`] into a [`ConnectionInfo`].
///
/// Returns `None` if the address cannot be parsed.
pub fn ss_entry_to_connection(entry: &SsEntry) -> Option<ConnectionInfo> {
    let (src, src_port) = parse_addr_port(&entry.local)?;
    let (dst, dst_port) = parse_addr_port(&entry.peer)?;

    Some(ConnectionInfo {
        src,
        src_port,
        dst,
        dst_port,
        protocol: entry.netid.to_lowercase(),
        state: entry.state.clone(),
        bytes: None,
        packets: None,
    })
}

/// Parse an `ip:port` or `[ipv6]:port` string.
fn parse_addr_port(s: &str) -> Option<(IpAddr, u16)> {
    let (ip_str, port_str) = if s.starts_with('[') {
        // IPv6: [::1]:12345
        let close = s.find(']')?;
        let ip = &s[1..close];
        let port = s.get(close + 2..)?;
        (ip, port)
    } else {
        // IPv4: 1.2.3.4:12345
        let colon = s.rfind(':')?;
        (&s[..colon], &s[colon + 1..])
    };

    let ip = ip_str.parse().ok()?;
    let port = port_str.parse().ok()?;
    Some((ip, port))
}

/// Map a conntrack protocol name token to its IANA protocol number.
///
/// Returns `None` for unknown protocols so the line is skipped rather than
/// misparsed.
fn proto_number(name: &str) -> Option<u8> {
    // Aliases seen in /proc/net/nf_conntrack (e.g. `icmpv6`) are mapped too.
    match name {
        "tcp" => Some(6),
        "udp" => Some(17),
        "icmp" => Some(1),
        "icmpv6" => Some(58),
        "sctp" => Some(132),
        "dccp" => Some(33),
        "gre" => Some(47),
        _ => None,
    }
}

/// Whether a conntrack protocol prints a state-machine token at `parts[3]`.
///
/// Only the L4 protocols backed by a kernel `protoinfo-*` container
/// (protoinfo-tcp, protoinfo-sctp, protoinfo-dccp) emit a state keyword in the
/// `/proc/net/nf_conntrack` / `conntrack -L` textual dump. UDP, ICMP/ICMPv6,
/// and GRE rely on [UNREPLIED]/[ASSURED] flags and a timeout instead, so they
/// have only 3 leading tokens.
fn has_state_token(proto_name: &str) -> bool {
    matches!(proto_name, "tcp" | "sctp" | "dccp")
}

/// Extract a `KEY=VALUE` field from a log line.
fn extract_field(line: &str, key: &str) -> Option<String> {
    let start = line.find(key)?;
    let remainder = &line[start + key.len()..];
    let end = remainder.find(' ').unwrap_or(remainder.len());
    Some(remainder[..end].to_owned())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_empty_input_returns_empty() {
        let entries = parse_iptables_log("", "TORIDE").unwrap();
        assert!(entries.is_empty());

        let entries = parse_conntrack_output("").unwrap();
        assert!(entries.is_empty());

        let entries = parse_ss_output("").unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn parse_addr_port_ipv4() {
        let (ip, port) = parse_addr_port("192.168.1.1:443").unwrap();
        assert_eq!(ip.to_string(), "192.168.1.1");
        assert_eq!(port, 443);
    }

    #[test]
    fn parse_addr_port_ipv6() {
        let (ip, port) = parse_addr_port("[::1]:8080").unwrap();
        assert_eq!(ip.to_string(), "::1");
        assert_eq!(port, 8080);
    }

    #[test]
    fn conntrack_state_is_fourth_token_not_protocol() {
        // Regression: the old extract_field(line, "") returned the leading
        // protocol token ("tcp") as the state. The real state is parts[3].
        let line = "tcp  6 431998 ESTABLISHED src=1.2.3.4 dst=5.6.7.8 sport=12345 dport=80 bytes=1234 packets=56";
        let entries = parse_conntrack_output(line).unwrap();
        assert_eq!(entries.len(), 1);
        let e = &entries[0];
        assert_eq!(e.proto, 6);
        assert_eq!(
            e.state.as_deref(),
            Some("ESTABLISHED"),
            "state must be ESTABLISHED, not the protocol token"
        );
        assert_eq!(e.src.to_string(), "1.2.3.4");
        assert_eq!(e.dst.to_string(), "5.6.7.8");
        assert_eq!(e.dport, Some(80));
        assert_eq!(e.bytes, Some(1234));
    }

    #[test]
    fn conntrack_multiple_lines_with_various_states() {
        let input = "\
tcp  6 100 ESTABLISHED src=10.0.0.1 dst=10.0.0.2 sport=40000 dport=22 bytes=100 packets=1
tcp  6 50 TIME_WAIT src=10.0.0.3 dst=10.0.0.4 sport=40001 dport=443 bytes=200 packets=2
udp  17 30 src=10.0.0.5 dst=10.0.0.6 sport=40002 dport=53 bytes=50 packets=1
";
        let entries = parse_conntrack_output(input).unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].state.as_deref(), Some("ESTABLISHED"));
        assert_eq!(entries[1].state.as_deref(), Some("TIME_WAIT"));
        // UDP entries have only 3 leading tokens (no state machine). The fix
        // ensures the UDP entry reports NO state rather than silently capturing
        // the `src=` field as a bogus state.
        assert_eq!(entries[2].proto, 17, "udp must still be parsed as proto 17");
        assert_eq!(
            entries[2].state, None,
            "udp entries must have NO state token"
        );
        assert_eq!(entries[2].src.to_string(), "10.0.0.5");
        assert_eq!(entries[2].dport, Some(53));
    }

    /// Real `/proc/net/nf_conntrack` sample exercising mixed protocols (tcp,
    /// udp, sctp, dccp, icmp). Sourced from kernel conntrack field layout
    /// documented at:
    ///   - <https://stackoverflow.com/questions/16034698> (field-by-field)
    ///   - <https://unix.stackexchange.com/questions/400394> (entry breakdown)
    ///   - docs.kernel.org/netlink/specs/conntrack.html (protoinfo containers:
    ///     only tcp/sctp/dccp emit a state keyword)
    ///     The state token only appears for tcp/sctp/dccp; udp/icmp must report
    ///     `state == None`. This is the exact regression the Wave-2a verify pass
    ///     found: the parser read parts[3] unconditionally and captured `src=`
    ///     as the UDP "state".
    #[test]
    fn conntrack_mixed_protocols_from_real_proc_sample() {
        let input = "\
tcp      6 431998 ESTABLISHED src=10.0.2.2 dst=93.184.216.34 sport=58994 dport=443 bytes=2048 packets=12
udp      17 30 src=192.168.1.10 dst=8.8.8.8 sport=54321 dport=53 bytes=128 packets=2
sctp     132 210 ESTABLISHED src=10.0.0.7 dst=10.0.0.8 sport=3868 dport=3868 bytes=0 packets=0
dccp     33 120 REQUEST src=10.0.0.9 dst=10.0.0.10 sport=5001 dport=5001 bytes=64 packets=1
icmp     1 25 src=10.0.0.11 dst=10.0.0.12 bytes=56 packets=1
";
        let entries = parse_conntrack_output(input).unwrap();
        assert_eq!(entries.len(), 5, "all five lines must parse");

        // tcp -> state present
        assert_eq!(entries[0].proto, 6);
        assert_eq!(entries[0].state.as_deref(), Some("ESTABLISHED"));
        assert_eq!(entries[0].dport, Some(443));

        // udp -> NO state (regression: previously captured "src=192.168.1.10")
        assert_eq!(entries[1].proto, 17);
        assert_eq!(entries[1].state, None, "udp must have no state token");
        assert_eq!(entries[1].src.to_string(), "192.168.1.10");
        assert_eq!(entries[1].dport, Some(53));

        // sctp -> state present
        assert_eq!(entries[2].proto, 132);
        assert_eq!(entries[2].state.as_deref(), Some("ESTABLISHED"));

        // dccp -> state present
        assert_eq!(entries[3].proto, 33);
        assert_eq!(entries[3].state.as_deref(), Some("REQUEST"));

        // icmp -> NO state
        assert_eq!(entries[4].proto, 1);
        assert_eq!(entries[4].state, None, "icmp must have no state token");
    }

    #[test]
    fn conntrack_empty_and_garbage_lines_skipped() {
        let entries = parse_conntrack_output("").unwrap();
        assert!(entries.is_empty());
        let entries = parse_conntrack_output("garbage line with no fields").unwrap();
        assert!(entries.is_empty());
    }
}
