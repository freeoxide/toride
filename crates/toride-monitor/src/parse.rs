//! Parsers for iptables log output, conntrack entries, and `ss` output.
//! Parsers are intentionally lenient: unparseable lines are skipped.

use std::net::IpAddr;

use crate::Result;
use crate::report::ConnectionInfo;

/// A single entry parsed from iptables LOG target output.
#[derive(Debug, Clone)]
pub struct IptablesLogEntry {
    /// LOG target prefix.
    pub prefix: String,
    /// Source address.
    pub src: IpAddr,
    /// Destination address.
    pub dst: IpAddr,
    /// Protocol name.
    pub proto: String,
    /// Source port, when present.
    pub spt: Option<u16>,
    /// Destination port, when present.
    pub dpt: Option<u16>,
}

/// A single entry parsed from `conntrack -L` output.
#[derive(Debug, Clone)]
pub struct ConntrackEntry {
    /// IP protocol number.
    pub proto: u8,
    /// Source address.
    pub src: IpAddr,
    /// Destination address.
    pub dst: IpAddr,
    /// Source port, when present.
    pub sport: Option<u16>,
    /// Destination port, when present.
    pub dport: Option<u16>,
    /// Connection state, when the protocol carries one.
    pub state: Option<String>,
    /// Byte counter, when present.
    pub bytes: Option<u64>,
    /// Packet counter, when present.
    pub packets: Option<u64>,
}

/// A single entry parsed from `ss -tunap` output.
#[derive(Debug, Clone)]
pub struct SsEntry {
    /// Network protocol identifier (e.g. `tcp`, `udp`).
    pub netid: String,
    /// Socket state (e.g. `ESTAB`, `LISTEN`).
    pub state: String,
    /// Local `address:port`.
    pub local: String,
    /// Peer `address:port`.
    pub peer: String,
    /// Process column, when present.
    pub process: Option<String>,
}

/// Parse iptables LOG target output (kernel ring buffer, filtered by
/// `prefix`) into entries. Unparseable lines are skipped.
///
/// # Errors
/// Does not return errors; unparseable lines are skipped.
pub fn parse_iptables_log(input: &str, prefix: &str) -> Result<Vec<IptablesLogEntry>> {
    let mut entries = Vec::new();

    for line in input.lines() {
        if !line.contains(prefix) {
            continue;
        }

        let entry = parse_single_iptables_line(line, prefix);
        if let Some(e) = entry {
            entries.push(e);
        }
    }

    Ok(entries)
}

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

/// Parse `conntrack -L` output into entries. Unparseable lines are skipped.
///
/// # Errors
/// Does not return errors; unparseable lines are skipped.
pub fn parse_conntrack_output(input: &str) -> Result<Vec<ConntrackEntry>> {
    let mut entries = Vec::new();

    for line in input.lines() {
        if let Some(entry) = parse_single_conntrack_line(line) {
            entries.push(entry);
        }
    }

    Ok(entries)
}

fn parse_single_conntrack_line(line: &str) -> Option<ConntrackEntry> {
    // /proc/net/nf_conntrack leading tokens: proto-name, proto-number, ttl,
    // then STATE — present only for tcp/sctp/dccp (kernel protoinfo-*
    // containers); udp/icmp/gre carry none. docs.kernel.org/netlink/specs/conntrack.html
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.is_empty() {
        return None;
    }

    let proto_name = parts.first().copied()?;
    let proto = proto_number(proto_name)?;
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

/// Parse `ss -tunap` output into entries, mapping columns by header name;
/// header-less input (e.g. `ss -H`) falls back to legacy fixed indices.
///
/// # Errors
/// Does not return errors; unparseable lines are skipped.
pub fn parse_ss_output(input: &str) -> Result<Vec<SsEntry>> {
    let mut entries = Vec::new();
    let mut lines = input.lines();

    let columns = lines.next().and_then(parse_ss_header).unwrap_or_else(|| {
        tracing::debug!("ss output had no recognizable header; using legacy fixed indices");
        SsColumns::legacy()
    });

    for line in lines {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() <= columns.peer {
            continue;
        }

        entries.push(SsEntry {
            netid: parts[columns.netid].to_string(),
            state: parts[columns.state].to_string(),
            local: parts[columns.local].to_string(),
            peer: parts[columns.peer].to_string(),
            process: columns
                .process
                .and_then(|idx| parts.get(idx))
                .map(|s| (*s).to_string()),
        });
    }

    Ok(entries)
}

#[derive(Debug, Clone, Copy)]
struct SsColumns {
    netid: usize,
    state: usize,
    local: usize,
    peer: usize,
    process: Option<usize>,
}

impl SsColumns {
    fn legacy() -> Self {
        Self {
            netid: 0,
            state: 1,
            local: 2,
            peer: 3,
            process: Some(4),
        }
    }
}

fn parse_ss_header(header: &str) -> Option<SsColumns> {
    let tokens: Vec<&str> = header.split_whitespace().collect();
    let netid = tokens.iter().position(|t| *t == "Netid")?;
    if tokens.get(netid + 1).copied() != Some("State")
        || tokens.get(netid + 2).copied() != Some("Recv-Q")
        || tokens.get(netid + 3).copied() != Some("Send-Q")
    {
        return None;
    }
    let local = netid + 4;
    let peer = local + 1;
    let process = tokens.contains(&"Process").then_some(peer + 1);
    Some(SsColumns {
        netid,
        state: netid + 1,
        local,
        peer,
        process,
    })
}

/// Convert an [`SsEntry`] into a [`ConnectionInfo`]; returns `None` if
/// either address cannot be parsed.
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

fn parse_addr_port(s: &str) -> Option<(IpAddr, u16)> {
    let (ip_str, port_str) = if s.starts_with('[') {
        let close = s.find(']')?;
        let ip = &s[1..close];
        let port = s.get(close + 2..)?;
        (ip, port)
    } else {
        let colon = s.rfind(':')?;
        (&s[..colon], &s[colon + 1..])
    };

    let ip = ip_str.parse().ok()?;
    let port = port_str.parse().ok()?;
    Some((ip, port))
}

fn proto_number(name: &str) -> Option<u8> {
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

fn has_state_token(proto_name: &str) -> bool {
    matches!(proto_name, "tcp" | "sctp" | "dccp")
}

fn extract_field(line: &str, key: &str) -> Option<String> {
    let start = line.find(key)?;
    let remainder = &line[start + key.len()..];
    let end = remainder.find(' ').unwrap_or(remainder.len());
    Some(remainder[..end].to_owned())
}

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
        assert_eq!(entries[2].proto, 17, "udp must still be parsed as proto 17");
        assert_eq!(
            entries[2].state, None,
            "udp entries must have NO state token"
        );
        assert_eq!(entries[2].src.to_string(), "10.0.0.5");
        assert_eq!(entries[2].dport, Some(53));
    }

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

        assert_eq!(entries[0].proto, 6);
        assert_eq!(entries[0].state.as_deref(), Some("ESTABLISHED"));
        assert_eq!(entries[0].dport, Some(443));

        assert_eq!(entries[1].proto, 17);
        assert_eq!(entries[1].state, None, "udp must have no state token");
        assert_eq!(entries[1].src.to_string(), "192.168.1.10");
        assert_eq!(entries[1].dport, Some(53));

        assert_eq!(entries[2].proto, 132);
        assert_eq!(entries[2].state.as_deref(), Some("ESTABLISHED"));

        assert_eq!(entries[3].proto, 33);
        assert_eq!(entries[3].state.as_deref(), Some("REQUEST"));

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

    const SS_HEADER: &str =
        "Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process";

    #[test]
    fn ss_header_columns_map_addresses_not_queues() {
        let input = format!(
            "{SS_HEADER}\nudp ESTAB 0 0 152.53.38.170:59701 46.38.252.230:53 users:((\"zcode-cli\",pid=3269808,fd=34))\ntcp LISTEN 0 5 127.0.0.1:39099 0.0.0.0:* users:((\"python3\",pid=2193247,fd=3))"
        );
        let entries = parse_ss_output(&input).unwrap();
        assert_eq!(entries.len(), 2);

        assert_eq!(entries[0].netid, "udp");
        assert_eq!(entries[0].state, "ESTAB");
        assert_eq!(
            entries[0].local, "152.53.38.170:59701",
            "local must be the Local Address:Port column, not Recv-Q"
        );
        assert_eq!(
            entries[0].peer, "46.38.252.230:53",
            "peer must be the Peer Address:Port column, not Send-Q"
        );
        assert_eq!(
            entries[0].process.as_deref(),
            Some("users:((\"zcode-cli\",pid=3269808,fd=34))")
        );
    }

    #[test]
    fn ss_row_without_process_token_still_maps() {
        let input = format!("{SS_HEADER}\ntcp ESTAB 0 0 10.0.0.5:44332 93.184.216.34:443");
        let entries = parse_ss_output(&input).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].local, "10.0.0.5:44332");
        assert_eq!(entries[0].peer, "93.184.216.34:443");
        assert_eq!(entries[0].process, None, "no Process token on the row");
    }

    #[test]
    fn ss_ipv6_rows_map() {
        let input = format!(
            "{SS_HEADER}\ntcp6 ESTAB 0 0 [::1]:54321 [2001:db8::2]:443 users:((\"app\",pid=42,fd=6))"
        );
        let entries = parse_ss_output(&input).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].netid, "tcp6");
        assert_eq!(entries[0].local, "[::1]:54321");
        assert_eq!(entries[0].peer, "[2001:db8::2]:443");
    }

    #[test]
    fn ss_established_row_converts_to_connection() {
        let input = format!(
            "{SS_HEADER}\nudp ESTAB 0 0 152.53.38.170:59701 46.38.252.230:53 users:((\"dig\",pid=99,fd=5))"
        );
        let entries = parse_ss_output(&input).unwrap();
        let conn = ss_entry_to_connection(&entries[0]).expect("ESTAB row must convert");
        assert_eq!(conn.src.to_string(), "152.53.38.170");
        assert_eq!(conn.src_port, 59701);
        assert_eq!(conn.dst.to_string(), "46.38.252.230");
        assert_eq!(conn.dst_port, 53);
        assert_eq!(conn.protocol, "udp");
        assert_eq!(conn.state, "ESTAB");
    }

    #[test]
    fn ss_listening_row_with_wildcard_peer_is_not_a_connection() {
        let input = format!(
            "{SS_HEADER}\ntcp LISTEN 0 5 127.0.0.1:39099 0.0.0.0:* users:((\"python3\",pid=2193247,fd=3))"
        );
        let entries = parse_ss_output(&input).unwrap();
        assert_eq!(entries.len(), 1, "the row still parses");
        assert!(
            ss_entry_to_connection(&entries[0]).is_none(),
            "a wildcard peer is a listening socket, not a connection"
        );
    }

    #[test]
    fn ss_header_recognition_rejects_non_header_lines() {
        assert!(
            parse_ss_header(
                "Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process"
            )
            .is_some()
        );
        assert!(parse_ss_header("garbage line").is_none());
        assert!(parse_ss_header("").is_none());
        assert!(
            parse_ss_header("Netid State NotQ Send-Q Local Address:Port Peer Address:Port Process")
                .is_none()
        );
    }

    #[test]
    fn ss_headerless_input_uses_legacy_fallback() {
        let input = "tcp ESTAB 1.2.3.4:5 5.6.7.8:6\ntcp ESTAB 9.9.9.9:7 8.8.8.8:9";
        let entries = parse_ss_output(input).unwrap();
        assert_eq!(
            entries.len(),
            1,
            "first line consumed as the header attempt"
        );
        assert_eq!(entries[0].local, "9.9.9.9:7");
        assert_eq!(entries[0].peer, "8.8.8.8:9");
    }

    #[test]
    fn ss_live_output_maps_addresses_environmental() {
        let Ok(out) = std::process::Command::new("ss").args(["-tunap"]).output() else {
            eprintln!("ss not available; skipping live parse test");
            return;
        };
        if !out.status.success() {
            eprintln!("ss -tunap failed; skipping live parse test");
            return;
        }
        let text = String::from_utf8_lossy(&out.stdout);
        let entries = parse_ss_output(&text).unwrap();
        assert!(!entries.is_empty(), "a live host always has sockets");
        for e in &entries {
            assert!(
                e.local.contains(':') && !e.local.chars().all(|c| c.is_ascii_digit()),
                "local must be an address:port token, got {:?} (queue integer leak?)",
                e.local
            );
            assert!(
                e.peer.contains(':') && !e.peer.chars().all(|c| c.is_ascii_digit()),
                "peer must be an address:port token, got {:?} (queue integer leak?)",
                e.peer
            );
        }
        let converted = entries.iter().filter_map(ss_entry_to_connection).count();
        eprintln!(
            "live ss rows: {}, converted connections: {}",
            entries.len(),
            converted
        );
    }
}
