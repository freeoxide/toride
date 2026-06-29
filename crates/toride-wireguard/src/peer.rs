//! Peer management types and operations.
//!
//! Provides types for managing the lifecycle of WireGuard peers: adding,
//! removing, and updating peers on a running interface. All operations are
//! issued as `wg set <interface> ...` commands through the
//! [`Runner`](toride_runner::Runner) trait, so they are testable with
//! [`FakeRunner`](toride_runner::FakeRunner) without root or a real tunnel.

use std::time::Duration;

use toride_runner::{CommandSpec, Runner};

use crate::error::Result;
use crate::spec::PeerSpec;
use crate::validate::{validate_allowed_ips, validate_endpoint, validate_interface_name};

/// Timeout for `wg set` / `wg show` peer operations.
const WG_PEER_TIMEOUT_SECS: u64 = 10;

// ---------------------------------------------------------------------------
// PeerChange
// ---------------------------------------------------------------------------

/// A change to apply to a peer's configuration.
#[derive(Debug, Clone)]
pub enum PeerChange {
    /// Update the allowed-ips list.
    AllowedIps(Vec<String>),
    /// Update the endpoint address.
    Endpoint(String),
    /// Update the persistent keepalive interval.
    PersistentKeepalive(u32),
    /// Remove the persistent keepalive setting.
    RemoveKeepalive,
}

// ---------------------------------------------------------------------------
// PeerManager
// ---------------------------------------------------------------------------

/// Manages peer operations on a WireGuard interface.
///
/// Carries the interface name and a [`Runner`] and delegates runtime peer
/// changes to the `wg` CLI.
///
/// # Construction
///
/// - [`PeerManager::new`] -- production runner (`DuctRunner`).
/// - [`PeerManager::with_runner`] -- inject a custom runner (for testing).
pub struct PeerManager<R: Runner> {
    interface: String,
    runner: R,
}

impl PeerManager<toride_runner::DuctRunner> {
    /// Create a new peer manager for the given interface using the default
    /// production runner.
    #[must_use]
    pub fn new(interface: &str) -> Self {
        Self {
            interface: interface.to_owned(),
            runner: toride_runner::DuctRunner,
        }
    }
}

impl<R: Runner> PeerManager<R> {
    /// Create a peer manager with a custom command runner (for testing).
    #[must_use]
    pub fn with_runner(interface: &str, runner: R) -> Self {
        Self {
            interface: interface.to_owned(),
            runner,
        }
    }

    /// Returns the interface name.
    pub fn interface(&self) -> &str {
        &self.interface
    }

    /// Build the `wg set` spec prefix for this interface.
    fn wg_set(&self) -> CommandSpec {
        CommandSpec::new("wg")
            .args(["set", self.interface.as_str()])
            .timeout(Duration::from_secs(WG_PEER_TIMEOUT_SECS))
    }

    /// Add a peer to the running interface.
    ///
    /// Executes `wg set <interface> peer <public_key> allowed-ips <ips>
    /// [endpoint <ep>] [persistent-keepalive <n>]`.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::Runner`] if the `wg set` command fails.
    pub fn add_peer(&self, peer: &PeerSpec) -> Result<()> {
        tracing::info!(
            "adding peer {} to interface {}",
            peer.public_key,
            self.interface
        );
        // Validate inputs before building the `wg` argv so a malformed
        // endpoint / allowed-ips / interface name is rejected up front rather
        // than passed to `wg set`, which would fail with a confusing message.
        validate_interface_name(&self.interface)?;
        validate_allowed_ips(&peer.allowed_ips)?;
        if let Some(ep) = &peer.endpoint {
            validate_endpoint(ep)?;
        }
        let mut spec = self
            .wg_set()
            .arg("peer")
            .arg(peer.public_key.as_str())
            .arg("allowed-ips")
            .arg(join_ips(&peer.allowed_ips));
        if let Some(ep) = &peer.endpoint {
            spec = spec.arg("endpoint").arg(ep.as_str());
        }
        if let Some(ka) = peer.persistent_keepalive {
            spec = spec.arg("persistent-keepalive").arg(ka.to_string());
        }
        let _ = self.runner.run_checked(&spec)?;
        Ok(())
    }

    /// Remove a peer from the running interface.
    ///
    /// Executes `wg set <interface> peer <public_key> remove`.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::Runner`] if the command fails.
    pub fn remove_peer(&self, public_key: &str) -> Result<()> {
        tracing::info!(
            "removing peer {} from interface {}",
            public_key,
            self.interface
        );
        let spec = self.wg_set().arg("peer").arg(public_key).arg("remove");
        let _ = self.runner.run_checked(&spec)?;
        Ok(())
    }

    /// Apply a change to an existing peer.
    ///
    /// Executes `wg set <interface> peer <public_key> <field> <value>`. For
    /// [`PeerChange::RemoveKeepalive`], the field is `persistent-keepalive 0`
    /// (the documented `wg` way to clear it).
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::Runner`] if the command fails.
    pub fn update_peer(&self, public_key: &str, change: &PeerChange) -> Result<()> {
        tracing::info!(
            "updating peer {} on interface {} ({:?})",
            public_key,
            self.interface,
            change
        );
        // Validate the interface name and the field being changed before
        // building the `wg` argv. Allowed-ips / endpoint values are checked
        // only for the variants that carry them.
        validate_interface_name(&self.interface)?;
        match change {
            PeerChange::AllowedIps(ips) => validate_allowed_ips(ips)?,
            PeerChange::Endpoint(ep) => validate_endpoint(ep)?,
            PeerChange::PersistentKeepalive(_) | PeerChange::RemoveKeepalive => {}
        }
        let mut spec = self.wg_set().arg("peer").arg(public_key);
        match change {
            PeerChange::AllowedIps(ips) => {
                spec = spec.arg("allowed-ips").arg(join_ips(ips));
            }
            PeerChange::Endpoint(ep) => {
                spec = spec.arg("endpoint").arg(ep.as_str());
            }
            PeerChange::PersistentKeepalive(n) => {
                spec = spec.arg("persistent-keepalive").arg(n.to_string());
            }
            PeerChange::RemoveKeepalive => {
                // `wg set` clears persistent-keepalive by setting it to 0.
                spec = spec.arg("persistent-keepalive").arg("0");
            }
        }
        let _ = self.runner.run_checked(&spec)?;
        Ok(())
    }

    /// List all peers on the interface.
    ///
    /// Runs `wg show <interface> peers`, which prints the configured peers'
    /// public keys as a single tab-separated line (e.g.
    /// `AAA=\tBBB=\tCCC=`), per the `wg`(8) man page's script-friendly format
    /// ("prints specified information grouped by newlines and tabs").
    ///
    /// Returns one [`PeerSpec`] per public key, with only the public key
    /// populated (no endpoint / allowed-ips). Endpoint and keepalive are
    /// fetched on demand via [`update_peer`](Self::update_peer).
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::Runner`] if `wg show` fails.
    ///
    /// [`wg`(8)]: https://www.mankier.com/8/wg
    pub fn list_peers(&self) -> Result<Vec<PeerSpec>> {
        tracing::debug!("listing peers on interface {}", self.interface);
        let spec = CommandSpec::new("wg")
            .args(["show", self.interface.as_str(), "peers"])
            .timeout(Duration::from_secs(WG_PEER_TIMEOUT_SECS));
        let output = self.runner.run_checked(&spec)?;
        // `wg show <if> peers` emits peer public keys TAB-separated on a single
        // line. split_whitespace() handles tab *and* space separation, and
        // naturally skips the empty case (no peers -> no keys).
        let public_keys: Vec<String> = output
            .stdout
            .split_whitespace()
            .map(str::to_owned)
            .collect();
        Ok(public_keys
            .into_iter()
            .map(|k| PeerSpec::new(k, Vec::new()))
            .collect())
    }

    /// Return a reference to the underlying runner.
    #[must_use]
    pub fn runner(&self) -> &R {
        &self.runner
    }
}

impl<R: Runner + Default> Default for PeerManager<R> {
    fn default() -> Self {
        Self {
            interface: "wg0".to_owned(),
            runner: R::default(),
        }
    }
}

/// Join an allowed-ips list into the comma-separated form `wg set` expects.
fn join_ips(ips: &[String]) -> String {
    ips.join(",")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use toride_runner::fake::FakeRunner;

    #[test]
    fn peer_manager_new() {
        let mgr = PeerManager::new("wg0");
        assert_eq!(mgr.interface(), "wg0");
    }

    #[test]
    fn peer_change_variants() {
        let _ = PeerChange::AllowedIps(vec!["10.0.0.2/32".to_owned()]);
        let _ = PeerChange::Endpoint("1.2.3.4:51820".to_owned());
        let _ = PeerChange::PersistentKeepalive(25);
        let _ = PeerChange::RemoveKeepalive;
    }

    #[test]
    fn add_peer_builds_wg_set_with_allowed_ips() {
        let runner = FakeRunner::new().push_response(toride_runner::CommandOutput::from_stdout(""));
        let mgr = PeerManager::with_runner("wg0", runner);
        let peer = PeerSpec::new("PUBKEY==".to_owned(), vec!["10.0.0.2/32".to_owned()]);
        mgr.add_peer(&peer).unwrap();

        mgr.runner()
            .assert_called_with(&CommandSpec::new("wg").args([
                "set",
                "wg0",
                "peer",
                "PUBKEY==",
                "allowed-ips",
                "10.0.0.2/32",
            ]));
    }

    #[test]
    fn add_peer_includes_endpoint_and_keepalive_when_present() {
        let runner = FakeRunner::new().push_response(toride_runner::CommandOutput::from_stdout(""));
        let mgr = PeerManager::with_runner("wg0", runner);
        let peer = PeerSpec::new("KEY==".to_owned(), vec!["10.0.0.2/32".to_owned()])
            .with_endpoint("1.2.3.4:51820".to_owned())
            .with_persistent_keepalive(25);
        mgr.add_peer(&peer).unwrap();

        mgr.runner()
            .assert_called_with(&CommandSpec::new("wg").args([
                "set",
                "wg0",
                "peer",
                "KEY==",
                "allowed-ips",
                "10.0.0.2/32",
                "endpoint",
                "1.2.3.4:51820",
                "persistent-keepalive",
                "25",
            ]));
    }

    #[test]
    fn remove_peer_builds_wg_set_remove() {
        let runner = FakeRunner::new().push_response(toride_runner::CommandOutput::from_stdout(""));
        let mgr = PeerManager::with_runner("wg0", runner);
        mgr.remove_peer("KEY==").unwrap();

        mgr.runner().assert_called_with(
            &CommandSpec::new("wg").args(["set", "wg0", "peer", "KEY==", "remove"]),
        );
    }

    #[test]
    fn update_peer_allowed_ips() {
        let runner = FakeRunner::new().push_response(toride_runner::CommandOutput::from_stdout(""));
        let mgr = PeerManager::with_runner("wg0", runner);
        mgr.update_peer(
            "KEY==",
            &PeerChange::AllowedIps(vec!["10.0.0.3/32".to_owned()]),
        )
        .unwrap();

        mgr.runner()
            .assert_called_with(&CommandSpec::new("wg").args([
                "set",
                "wg0",
                "peer",
                "KEY==",
                "allowed-ips",
                "10.0.0.3/32",
            ]));
    }

    #[test]
    fn update_peer_endpoint() {
        let runner = FakeRunner::new().push_response(toride_runner::CommandOutput::from_stdout(""));
        let mgr = PeerManager::with_runner("wg0", runner);
        mgr.update_peer("KEY==", &PeerChange::Endpoint("5.6.7.8:51821".to_owned()))
            .unwrap();

        mgr.runner()
            .assert_called_with(&CommandSpec::new("wg").args([
                "set",
                "wg0",
                "peer",
                "KEY==",
                "endpoint",
                "5.6.7.8:51821",
            ]));
    }

    #[test]
    fn update_peer_keepalive_and_remove() {
        let runner = FakeRunner::new().push_response(toride_runner::CommandOutput::from_stdout(""));
        let mgr = PeerManager::with_runner("wg0", runner);
        mgr.update_peer("KEY==", &PeerChange::PersistentKeepalive(25))
            .unwrap();

        mgr.runner()
            .assert_called_with(&CommandSpec::new("wg").args([
                "set",
                "wg0",
                "peer",
                "KEY==",
                "persistent-keepalive",
                "25",
            ]));

        let runner2 =
            FakeRunner::new().push_response(toride_runner::CommandOutput::from_stdout(""));
        let mgr2 = PeerManager::with_runner("wg0", runner2);
        mgr2.update_peer("KEY==", &PeerChange::RemoveKeepalive)
            .unwrap();
        mgr2.runner()
            .assert_called_with(&CommandSpec::new("wg").args([
                "set",
                "wg0",
                "peer",
                "KEY==",
                "persistent-keepalive",
                "0",
            ]));
    }

    #[test]
    fn list_peers_parses_single_line_tab_separated() {
        // `wg show <if> peers` prints peer public keys TAB-separated on a
        // SINGLE line (per wg(8)'s script-friendly format, which prints
        // "specified information grouped by newlines and tabs"). This is the
        // real CLI shape; splitting on newlines would wrongly yield one key.
        // Ref: https://www.mankier.com/8/wg
        let canned = "AAAkey==\tBBBkey==\tCCCkey==\n";
        let runner =
            FakeRunner::new().push_response(toride_runner::CommandOutput::from_stdout(canned));
        let mgr = PeerManager::with_runner("wg0", runner);
        let peers = mgr.list_peers().unwrap();
        assert_eq!(peers.len(), 3);
        assert_eq!(peers[0].public_key, "AAAkey==");
        assert_eq!(peers[1].public_key, "BBBkey==");
        assert_eq!(peers[2].public_key, "CCCkey==");

        mgr.runner()
            .assert_called_with(&CommandSpec::new("wg").args(["show", "wg0", "peers"]));
    }

    #[test]
    fn list_peers_empty_when_no_peers() {
        let runner = FakeRunner::new().push_response(toride_runner::CommandOutput::from_stdout(""));
        let mgr = PeerManager::with_runner("wg0", runner);
        let peers = mgr.list_peers().unwrap();
        assert!(peers.is_empty());
    }

    #[test]
    fn runner_accessor_exposes_underlying_runner() {
        let runner = FakeRunner::new();
        let mgr = PeerManager::with_runner("wg0", runner);
        let _ = mgr.runner();
    }

    #[test]
    fn add_peer_rejects_invalid_interface_name() {
        let runner = FakeRunner::new().push_response(toride_runner::CommandOutput::from_stdout(""));
        // An interface name that does not match the `wg<digits>` contract.
        let mgr = PeerManager::with_runner("eth0", runner);
        let peer = PeerSpec::new("KEY==".to_owned(), vec!["10.0.0.2/32".to_owned()]);
        let err = mgr.add_peer(&peer).unwrap_err();
        assert!(matches!(err, crate::error::Error::InvalidAddress(_)));
    }

    #[test]
    fn add_peer_rejects_invalid_endpoint_and_allowed_ips() {
        let runner = FakeRunner::new().push_response(toride_runner::CommandOutput::from_stdout(""));
        let mgr = PeerManager::with_runner("wg0", runner);

        // Malformed allowed-ips entry.
        let bad_ips = PeerSpec::new("KEY==".to_owned(), vec!["not-a-cidr".to_owned()]);
        assert!(mgr.add_peer(&bad_ips).is_err());

        // Malformed endpoint (missing port) on an otherwise-valid peer.
        let bad_ep = PeerSpec::new("KEY==".to_owned(), vec!["10.0.0.2/32".to_owned()])
            .with_endpoint("1.2.3.4".to_owned());
        assert!(mgr.add_peer(&bad_ep).is_err());
    }

    #[test]
    fn update_peer_rejects_invalid_endpoint_and_allowed_ips() {
        let runner = FakeRunner::new().push_response(toride_runner::CommandOutput::from_stdout(""));
        let mgr = PeerManager::with_runner("wg0", runner);
        assert!(
            mgr.update_peer("KEY==", &PeerChange::Endpoint("1.2.3.4".to_owned()))
                .is_err()
        );
        assert!(
            mgr.update_peer(
                "KEY==",
                &PeerChange::AllowedIps(vec!["not-a-cidr".to_owned()]),
            )
            .is_err()
        );
    }
}
