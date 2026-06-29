//! High-level async client for Tailscale management.
//!
//! [`TailscaleClient`] is the main entry point for the `toride-tailscale`
//! crate. It owns an HTTP API client and provides accessor methods for each
//! subsystem: status queries, peer discovery, DNS configuration, ACL
//! management, and network checks.
//!
//! # Example
//!
//! ```ignore
//! use toride_tailscale::TailscaleClient;
//!
//! let client = TailscaleClient::new();
//! let report = client.status_report().await?;
//! println!("Connected as {} in {}", report.node_name, report.tailnet);
//! ```

use crate::Result;
use crate::report::TailscaleReport;

// ---------------------------------------------------------------------------
// TailscaleClient
// ---------------------------------------------------------------------------

/// High-level async client for Tailscale mesh VPN management.
///
/// Composes the lower-level modules (`api`, `status`, `tailnet`, `dns`,
/// `acl`, `netcheck`) into a unified interface. All operations are async
/// and communicate with the local Tailscale daemon over HTTP.
///
/// # Construction
///
/// - [`TailscaleClient::new`] -- default client targeting `localhost:41642`.
/// - [`TailscaleClient::with_base_url`] -- custom API base URL.
///
/// # Subsystem accessors
///
/// Each subsystem is accessible through a method that returns a borrowed
/// handle:
///
/// - [`api`](TailscaleClient::api) -- raw HTTP API client
/// - [`status`](TailscaleClient::status) -- node status queries
/// - [`dns`](TailscaleClient::dns) -- DNS configuration
/// - [`netcheck`](TailscaleClient::netcheck) -- connectivity checks
pub struct TailscaleClient {
    /// The underlying HTTP API client.
    api: crate::api::TailscaleApi,
}

impl TailscaleClient {
    /// Create a new `TailscaleClient` with the default API endpoint.
    pub fn new() -> Self {
        Self {
            api: crate::api::TailscaleApi::new(),
        }
    }

    /// Create a new `TailscaleClient` with a custom API base URL.
    pub fn with_base_url(base_url: String) -> Self {
        Self {
            api: crate::api::TailscaleApi::with_base_url(base_url),
        }
    }

    /// Returns a reference to the underlying API client.
    pub fn api(&self) -> &crate::api::TailscaleApi {
        &self.api
    }

    /// Fetch the current node status and return a [`TailscaleReport`].
    ///
    /// This is the primary convenience method for checking whether the
    /// local Tailscale daemon is connected and what identity it holds.
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails.
    pub async fn status_report(&self) -> Result<TailscaleReport> {
        let status = crate::status::NodeStatus::from_api(&self.api).await?;
        Ok(status.to_report())
    }

    /// Check if the local node is connected to the tailnet.
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails.
    pub async fn is_connected(&self) -> Result<bool> {
        let status = crate::status::NodeStatus::from_api(&self.api).await?;
        Ok(status.connection() == crate::report::ConnectionStatus::Connected)
    }

    /// Fetch the tailnet topology including all peers.
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails.
    pub async fn topology(&self) -> Result<crate::tailnet::TailnetTopology> {
        crate::tailnet::TailnetTopology::from_api(&self.api).await
    }

    /// Run a network connectivity check.
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails.
    pub async fn netcheck(&self) -> Result<crate::report::NetcheckReport> {
        let runner = crate::netcheck::NetcheckRunner::new(&self.api);
        runner.run().await
    }

    /// Fetch the current DNS configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if the API request fails.
    pub async fn dns_config(&self) -> Result<crate::dns::DnsConfigInfo> {
        let manager = crate::dns::DnsManager::new(&self.api);
        manager.get_config().await
    }
}

impl Default for TailscaleClient {
    fn default() -> Self {
        Self::new()
    }
}
