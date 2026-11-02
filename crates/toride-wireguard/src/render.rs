//! INI config rendering for WireGuard interface and peer entries.
//!
//! Renders a [`WireguardSpec`](crate::spec::WireguardSpec) into the standard WireGuard INI configuration
//! format suitable for writing to `/etc/wireguard/<interface>.conf`.

use crate::spec::{PeerSpec, WireguardSpec};

use std::fmt::Write as _;

// ---------------------------------------------------------------------------
// render_interface_conf
// ---------------------------------------------------------------------------

/// Render a [`WireguardSpec`] into a WireGuard INI config string.
///
/// The output is suitable for writing directly to
/// `/etc/wireguard/<name>.conf` and consumed by `wg-quick`. Every
/// `Address`, `DNS`, and verbatim `extra` entry of the spec is rendered, so
/// parsing a file and rendering the resulting spec reproduces all of its
/// keys.
///
/// # Example output
///
/// ```ini
/// [Interface]
/// Address = 10.0.0.1/24
/// ListenPort = 51820
/// PrivateKey = <key>
/// DNS = 1.1.1.1
///
/// [Peer]
/// PublicKey = <key>
/// AllowedIPs = 10.0.0.2/32
/// Endpoint = 203.0.113.1:51820
/// PersistentKeepalive = 25
/// ```
pub fn render_interface_conf(spec: &WireguardSpec) -> String {
    let mut out = String::new();

    // [Interface] section.
    out.push_str("[Interface]\n");
    for address in &spec.addresses {
        let _ = writeln!(out, "Address = {address}");
    }

    if spec.listen_port != 0 {
        let _ = writeln!(out, "ListenPort = {}", spec.listen_port);
    }

    if let Some(ref key) = spec.private_key {
        let _ = writeln!(out, "PrivateKey = {key}");
    }

    for dns in &spec.dns_servers {
        let _ = writeln!(out, "DNS = {dns}");
    }

    for (key, value) in &spec.extra {
        let _ = writeln!(out, "{key} = {value}");
    }

    // [Peer] sections.
    for peer in &spec.peers {
        out.push('\n');
        out.push_str(&render_peer_entry(peer));
    }

    out
}

// ---------------------------------------------------------------------------
// render_peer_entry
// ---------------------------------------------------------------------------

/// Render a single `[Peer]` section as an INI block.
///
/// This is a convenience function used by [`render_interface_conf`] but also
/// useful on its own when assembling configs incrementally. `PublicKey` is
/// omitted when empty (a `[Peer]` header carrying only verbatim `extra`
/// keys), and `extra` entries are rendered after the known keys.
pub fn render_peer_entry(peer: &PeerSpec) -> String {
    let mut out = String::new();

    out.push_str("[Peer]\n");
    if !peer.public_key.is_empty() {
        let _ = writeln!(out, "PublicKey = {}", peer.public_key);
    }

    if !peer.allowed_ips.is_empty() {
        let _ = writeln!(out, "AllowedIPs = {}", peer.allowed_ips.join(", "));
    }

    if let Some(ref endpoint) = peer.endpoint {
        let _ = writeln!(out, "Endpoint = {endpoint}");
    }

    if let Some(keepalive) = peer.persistent_keepalive {
        let _ = writeln!(out, "PersistentKeepalive = {keepalive}");
    }

    for (key, value) in &peer.extra {
        let _ = writeln!(out, "{key} = {value}");
    }

    out
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_basic_interface() {
        let spec = WireguardSpec::new("wg0".to_owned(), vec!["10.0.0.1/24".to_owned()])
            .with_listen_port(51820)
            .with_private_key("privkey==".to_owned())
            .with_dns("1.1.1.1".to_owned());

        let conf = render_interface_conf(&spec);
        assert!(conf.contains("[Interface]"));
        assert!(conf.contains("Address = 10.0.0.1/24"));
        assert!(conf.contains("ListenPort = 51820"));
        assert!(conf.contains("PrivateKey = privkey=="));
        assert!(conf.contains("DNS = 1.1.1.1"));
    }

    #[test]
    fn render_interface_with_peers() {
        let spec = WireguardSpec::new("wg0".to_owned(), vec!["10.0.0.1/24".to_owned()])
            .with_peer(
                PeerSpec::new("pubkey1==".to_owned(), vec!["10.0.0.2/32".to_owned()])
                    .with_endpoint("1.2.3.4:51820".to_owned())
                    .with_persistent_keepalive(25),
            )
            .with_peer(PeerSpec::new(
                "pubkey2==".to_owned(),
                vec!["10.0.0.3/32".to_owned()],
            ));

        let conf = render_interface_conf(&spec);
        assert!(conf.contains("[Peer]"));
        assert!(conf.contains("PublicKey = pubkey1=="));
        assert!(conf.contains("Endpoint = 1.2.3.4:51820"));
        assert!(conf.contains("PersistentKeepalive = 25"));
        assert!(conf.contains("PublicKey = pubkey2=="));
        // Second peer has no endpoint or keepalive, so those lines should not
        // appear after its PublicKey.
        let second_peer_start = conf.rfind("PublicKey = pubkey2==").unwrap();
        let rest = &conf[second_peer_start..];
        assert!(!rest.contains("Endpoint"));
    }

    #[test]
    fn render_peer_entry_standalone() {
        let peer = PeerSpec::new("key==".to_owned(), vec!["0.0.0.0/0".to_owned()])
            .with_endpoint("example.com:51820".to_owned());

        let entry = render_peer_entry(&peer);
        assert!(entry.starts_with("[Peer]"));
        assert!(entry.contains("AllowedIPs = 0.0.0.0/0"));
        assert!(entry.contains("Endpoint = example.com:51820"));
    }

    #[test]
    fn roundtrip_parse_render() {
        let original = "\
[Interface]
Address = 10.0.0.1/24
ListenPort = 51820
PrivateKey = testkey==
";
        let spec = crate::parse::parse_interface_conf("wg0", original).unwrap();
        let rendered = render_interface_conf(&spec);
        assert!(rendered.contains("Address = 10.0.0.1/24"));
        assert!(rendered.contains("ListenPort = 51820"));
        assert!(rendered.contains("PrivateKey = testkey=="));
    }

    /// The registry's lossy round-trip blocker: dual-stack `Address` lines,
    /// wg-quick keys (MTU, Table, PostUp, SaveConfig), and a peer
    /// `PresharedKey` must all survive a parse-then-render cycle verbatim.
    #[test]
    fn roundtrip_preserves_dual_stack_unknown_keys_and_preshared_key() {
        let original = "\
[Interface]
Address = 10.0.0.1/24
Address = fd00::1/64
ListenPort = 51820
PrivateKey = testkey==
MTU = 1420
Table = 123
PostUp = ip route add 10.0.0.0/24 dev wg0
SaveConfig = true

[Peer]
PublicKey = peerpub==
PresharedKey = pskbase64==
AllowedIPs = 10.0.0.2/32
Endpoint = 203.0.113.1:51820
";
        let spec = crate::parse::parse_interface_conf("wg0", original).unwrap();
        let rendered = render_interface_conf(&spec);
        for expected in [
            "Address = 10.0.0.1/24",
            "Address = fd00::1/64",
            "MTU = 1420",
            "Table = 123",
            "PostUp = ip route add 10.0.0.0/24 dev wg0",
            "SaveConfig = true",
            "PresharedKey = pskbase64==",
            "PublicKey = peerpub==",
            "Endpoint = 203.0.113.1:51820",
        ] {
            assert!(
                rendered.contains(expected),
                "round-trip dropped `{expected}`:\n{rendered}"
            );
        }
    }

    /// A `[Peer]` carrying only unrecognized keys must not render an empty
    /// `PublicKey = ` line.
    #[test]
    fn roundtrip_does_not_emit_empty_public_key_line() {
        let original = "\
[Interface]
Address = 10.0.0.1/24

[Peer]
PresharedKey = pskbase64==
";
        let spec = crate::parse::parse_interface_conf("wg0", original).unwrap();
        let rendered = render_interface_conf(&spec);
        assert!(
            !rendered.contains("PublicKey = \n") && !rendered.contains("PublicKey =\n"),
            "an empty PublicKey line must not be rendered:\n{rendered}"
        );
        assert!(rendered.contains("PresharedKey = pskbase64=="));
        assert_eq!(
            rendered.matches("PublicKey").count(),
            0,
            "no PublicKey line at all: {rendered}"
        );
    }
}
