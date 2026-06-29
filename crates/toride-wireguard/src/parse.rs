//! Parsers for WireGuard output and configuration files.
//!
//! Provides parsers for:
//! - `wg show all dump` output (machine-readable, tab-separated rows)
//! - `wg showconf` output (INI-like format)
//! - Interface `.conf` files (INI format)

use crate::error::{Error, Result};
use crate::spec::{PeerSpec, WireguardSpec};

// ---------------------------------------------------------------------------
// parse_wg_show (the `wg show all dump` format)
// ---------------------------------------------------------------------------

/// Parse the output of `wg show all dump` into a list of interface summaries.
///
/// Per the `wg`(8) man page, the machine-readable `dump` format prints one line
/// per interface followed by one line per peer, all tab-separated:
///
/// - **Interface row** (5 fields when invoked as `all dump`):
///   `interface  private-key  public-key  listen-port  fwmark`
/// - **Peer row** (9 fields when invoked as `all dump`):
///   `interface  public-key  preshared-key  endpoint  allowed-ips
///   latest-handshake  transfer-rx  transfer-tx  persistent-keepalive`
///
/// (The man page notes: "if `all` is specified, then the first field for all
/// categories of information is the interface name.") Rows are distinguished by
/// field count, so `fwmark` / `persistent-keepalive` appearing as the literal
/// `off` is handled without ambiguity. Only the interface rows contribute to
/// the returned [`WgShowEntry`] list.
///
/// # Errors
///
/// Returns [`Error::ConfigParse`] if an interface row is malformed (e.g. a
/// non-numeric listen-port).
///
/// [`wg`(8)]: https://www.mankier.com/8/wg
pub fn parse_wg_show(output: &str) -> Result<Vec<WgShowEntry>> {
    let mut entries = Vec::new();
    for line in output.lines() {
        let trimmed = line.trim_end_matches(['\n', '\r']);
        if trimmed.is_empty() {
            continue;
        }
        // The `wg` tool separates dump fields with a single tab.
        let parts: Vec<&str> = trimmed.split('\t').collect();
        // `wg show all dump` interface row (5 fields, interface name leading):
        //   [interface, private-key, public-key, listen-port, fwmark]
        // Peer rows have 9 fields and are skipped here. We require exactly 5
        // fields so a `fwmark` of `off` (or `0x1`) cannot be confused with the
        // listen-port, which sits one column to its left.
        if parts.len() != 5 {
            continue;
        }
        let interface = parts[0].to_owned();
        // parts[1] is the private key; the public key follows it.
        let public_key = parts[2].to_owned();
        // Honor the documented contract: a non-numeric (malformed / tampered)
        // listen-port is a parse error, not silently coerced to 0. Coercing to
        // 0 would mask a corrupted dump and could route traffic to the wrong
        // port (kernel auto-assign).
        let listen_port = parts[3].parse::<u16>().map_err(|_| {
            Error::ConfigParse(format!(
                "invalid listen-port in `wg show all dump` row: {}",
                parts[3]
            ))
        })?;
        entries.push(WgShowEntry {
            interface,
            public_key,
            listen_port,
        });
    }
    Ok(entries)
}

/// A simplified entry parsed from `wg show all dump` output.
#[derive(Debug, Clone)]
pub struct WgShowEntry {
    /// Interface name (e.g. `wg0`).
    pub interface: String,
    /// Public key of the interface.
    pub public_key: String,
    /// Listen port.
    pub listen_port: u16,
}

// ---------------------------------------------------------------------------
// parse_wg_showconf
// ---------------------------------------------------------------------------

/// Parse the output of `wg showconf <interface>` into a [`WireguardSpec`].
///
/// The output is in INI-like format with `[Interface]` and `[Peer]` sections.
///
/// # Errors
///
/// Returns [`Error::ConfigParse`] if the output cannot be parsed.
pub fn parse_wg_showconf(interface: &str, output: &str) -> Result<WireguardSpec> {
    parse_interface_conf(interface, output)
}

// ---------------------------------------------------------------------------
// parse_interface_conf
// ---------------------------------------------------------------------------

/// Parse an INI-format WireGuard interface config file.
///
/// Supports the standard `[Interface]` and `[Peer]` sections with their
/// respective keys: `Address`, `ListenPort`, `PrivateKey`, `DNS`,
/// `PublicKey`, `AllowedIPs`, `Endpoint`, `PersistentKeepalive`.
///
/// # Errors
///
/// Returns [`Error::ConfigParse`] if the config contains invalid syntax.
pub fn parse_interface_conf(interface_name: &str, content: &str) -> Result<WireguardSpec> {
    let mut spec = WireguardSpec::new(interface_name.to_owned(), String::new());
    let mut current_section: Option<String> = None;
    let mut current_peer: Option<PeerSpec> = None;

    for line in content.lines() {
        let trimmed = line.trim();

        // Skip blank lines and comments.
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        // Section headers.
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            // Flush any in-progress peer.
            if let Some(peer) = current_peer.take() {
                spec.peers.push(peer);
            }
            current_section = Some(trimmed[1..trimmed.len() - 1].trim().to_owned());
            if current_section.as_deref() == Some("Peer") {
                current_peer = Some(PeerSpec::new(String::new(), Vec::new()));
            }
            continue;
        }

        // Key = Value pairs.
        let (key, value) = match trimmed.split_once('=') {
            Some((k, v)) => (k.trim(), v.trim()),
            None => continue,
        };

        match current_section.as_deref() {
            Some("Interface") => match key {
                "Address" => value.clone_into(&mut spec.address),
                "ListenPort" => {
                    spec.listen_port = value
                        .parse()
                        .map_err(|_| Error::ConfigParse(format!("invalid ListenPort: {value}")))?;
                }
                "PrivateKey" => spec.private_key = Some(value.to_owned()),
                "DNS" => spec.dns = Some(value.to_owned()),
                _ => {} // ignore unknown keys
            },
            Some("Peer") => {
                if let Some(ref mut peer) = current_peer {
                    match key {
                        "PublicKey" => value.clone_into(&mut peer.public_key),
                        "AllowedIPs" => {
                            peer.allowed_ips =
                                value.split(',').map(|s| s.trim().to_owned()).collect();
                        }
                        "Endpoint" => peer.endpoint = Some(value.to_owned()),
                        "PersistentKeepalive" => {
                            peer.persistent_keepalive = Some(value.parse().map_err(|_| {
                                Error::ConfigParse(format!("invalid PersistentKeepalive: {value}"))
                            })?);
                        }
                        _ => {} // ignore unknown keys
                    }
                }
            }
            _ => {
                return Err(Error::ConfigParse(format!(
                    "key-value pair outside of section: {trimmed}"
                )));
            }
        }
    }

    // Flush the last peer if present.
    if let Some(peer) = current_peer.take() {
        spec.peers.push(peer);
    }

    Ok(spec)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_interface_conf() {
        let conf = "\
[Interface]
Address = 10.0.0.1/24
ListenPort = 51820
PrivateKey = abc123base64==
DNS = 1.1.1.1

[Peer]
PublicKey = peerpubkey==
AllowedIPs = 10.0.0.2/32
Endpoint = 203.0.113.1:51820
PersistentKeepalive = 25
";
        let spec = parse_interface_conf("wg0", conf).unwrap();
        assert_eq!(spec.name, "wg0");
        assert_eq!(spec.address, "10.0.0.1/24");
        assert_eq!(spec.listen_port, 51820);
        assert_eq!(spec.private_key.as_deref(), Some("abc123base64=="));
        assert_eq!(spec.dns.as_deref(), Some("1.1.1.1"));
        assert_eq!(spec.peers.len(), 1);
        let peer = &spec.peers[0];
        assert_eq!(peer.public_key, "peerpubkey==");
        assert_eq!(peer.allowed_ips, vec!["10.0.0.2/32"]);
        assert_eq!(peer.endpoint.as_deref(), Some("203.0.113.1:51820"));
        assert_eq!(peer.persistent_keepalive, Some(25));
    }

    #[test]
    fn parse_multiple_peers() {
        let conf = "\
[Interface]
Address = 10.0.0.1/24

[Peer]
PublicKey = key1==
AllowedIPs = 10.0.0.2/32

[Peer]
PublicKey = key2==
AllowedIPs = 10.0.0.3/32, fd00::3/128
";
        let spec = parse_interface_conf("wg0", conf).unwrap();
        assert_eq!(spec.peers.len(), 2);
        assert_eq!(spec.peers[1].allowed_ips.len(), 2);
    }

    #[test]
    fn parse_empty_conf() {
        let spec = parse_interface_conf("wg0", "").unwrap();
        assert_eq!(spec.name, "wg0");
        assert!(spec.address.is_empty());
        assert!(spec.peers.is_empty());
    }

    #[test]
    fn parse_wg_show_dump_all() {
        // Real `wg show all dump` output, faithfully reproduced from the
        // man-page-corroborated example in the Pro Custodibus monitoring guide
        // (https://www.procustodibus.com/blog/2021/01/how-to-monitor-wireguard-activity/).
        // The wg(8) man page documents this exact field layout:
        //   interface row: <iface> <private-key> <public-key> <listen-port> <fwmark>
        //   peer row:      <iface> <pub-key> <preshared-key> <endpoint> <allowed-ips>
        //                  <latest-handshake> <transfer-rx> <transfer-tx> <persistent-keepalive>
        // `fwmark` and `persistent-keepalive` render as the literal `off`.
        let output = "\
wg1\tAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEE=\t/TOE4TKtAqVsePRVR+5AA43HkAK5DSntkOCO7nYq5xU=\t51821\toff\n\
wg1\tfE/wdxzl0klVp/IR8UcaoGUMjqaWi3jAd7KzHKFS6Ds=\t(none)\t172.19.0.8:51822\t10.0.0.2/32\t1617235493\t3481633\t33460136\toff\n\
wg1\tjUd41n3XYa3yXBzyBvWqlLhYgRef5RiBD7jwo70U+Rw=\t(none)\t172.19.0.7:51823\t10.0.0.3/32\t1609974495\t1403752\t19462368\toff\n\
";
        let entries = parse_wg_show(output).unwrap();
        // Only the interface row is surfaced; the two peer rows are skipped.
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].interface, "wg1");
        assert_eq!(
            entries[0].public_key,
            "/TOE4TKtAqVsePRVR+5AA43HkAK5DSntkOCO7nYq5xU="
        );
        assert_eq!(entries[0].listen_port, 51821);
    }

    #[test]
    fn parse_wg_show_dump_multiple_interfaces() {
        // Two interfaces, each followed by its peer rows (mirrors how
        // `wg show all dump` interleaves them per the wg(8) man page).
        let output = "\
wg0\tpriv0=\tpub0=\t51820\toff\n\
wg0\tpeer0key=\t(none)\t10.0.0.2:51820\t10.0.0.2/32\t0\t0\t0\toff\n\
wg1\tpriv1=\tpub1=\t51821\t0x1\n\
wg1\tpeer1key=\t(none)\t10.0.0.3:51820\t10.0.0.3/32\t0\t0\t0\toff\n\
";
        let entries = parse_wg_show(output).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].interface, "wg0");
        assert_eq!(entries[0].listen_port, 51820);
        // fwmark="0x1" must not be mistaken for the listen-port.
        assert_eq!(entries[1].interface, "wg1");
        assert_eq!(entries[1].listen_port, 51821);
    }

    #[test]
    fn parse_wg_show_dump_skips_peer_rows_only() {
        // Output containing only peer rows (no interface row) yields nothing.
        let output = "wg0\tpeerkey=\t(none)\t1.2.3.4:51820\t10.0.0.2/32\t0\t0\t0\toff\n";
        let entries = parse_wg_show(output).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn parse_wg_show_empty_output() {
        let entries = parse_wg_show("").unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn parse_wg_show_rejects_malformed_listen_port() {
        // A 5-field interface row whose listen-port column is non-numeric must
        // surface as a parse error per the documented contract, rather than
        // being silently coerced to 0 (which could mask a tampered dump).
        let output = "wg0\tpriv0=\tpub0=\tNOTAPORT\toff\n";
        let err = parse_wg_show(output).unwrap_err();
        assert!(matches!(err, Error::ConfigParse(_)));
    }
}
