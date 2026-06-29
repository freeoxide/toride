//! Low-level HTTP client for the Tailscale local API.
//!
//! [`TailscaleApi`] communicates with the local Tailscale daemon over
//! `http://localhost:41642` (or the Unix socket API) to query status,
//! peers, DNS, and other runtime information.
//!
//! All requests go through `reqwest` with a configurable base URL. No
//! ad-hoc HTTP calls are made outside this module.

use crate::Result;

// ---------------------------------------------------------------------------
// TailscaleApi
// ---------------------------------------------------------------------------

/// Low-level async client for the Tailscale local HTTP API.
///
/// The Tailscale daemon exposes a local HTTP server that provides status,
/// configuration, and control endpoints. `TailscaleApi` wraps these
/// endpoints with typed responses.
///
/// # Base URL
///
/// The default base URL is `http://localhost:41642`, which is the standard
/// local API address. On Linux, the API may also be accessible via a Unix
/// socket at `/var/lib/tailscale/tailscaled.sock`.
///
/// # Example
///
/// ```ignore
/// use toride_tailscale::api::TailscaleApi;
///
/// let api = TailscaleApi::new();
/// let status = api.get_status().await?;
/// ```
pub struct TailscaleApi {
    /// Base URL for the Tailscale local API.
    base_url: String,
    /// HTTP client instance.
    client: reqwest::Client,
}

impl TailscaleApi {
    /// Create a new `TailscaleApi` with the default base URL.
    pub fn new() -> Self {
        Self::with_base_url("http://localhost:41642".to_owned())
    }

    /// Create a new `TailscaleApi` with a custom base URL.
    pub fn with_base_url(base_url: String) -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .unwrap_or_default();
        Self { base_url, client }
    }

    /// Fetch the current status from the local API.
    ///
    /// Calls `GET /localapi/v0/status`.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ApiError`] if the request fails or the daemon
    /// is not running.
    pub async fn get_status(&self) -> Result<serde_json::Value> {
        let url = format!("{}/localapi/v0/status", self.base_url);
        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| crate::Error::ApiError(format!("status request failed: {e}")))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(crate::Error::ApiError(format!(
                "status request returned {status}: {body}"
            )));
        }

        response
            .json()
            .await
            .map_err(|e| crate::Error::ApiError(format!("failed to parse status response: {e}")))
    }

    /// Fetch the list of peers from the local API.
    ///
    /// Calls `GET /localapi/v0/peers`.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ApiError`] if the request fails.
    pub async fn get_peers(&self) -> Result<serde_json::Value> {
        let url = format!("{}/localapi/v0/peers", self.base_url);
        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| crate::Error::ApiError(format!("peers request failed: {e}")))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(crate::Error::ApiError(format!(
                "peers request returned {status}: {body}"
            )));
        }

        response
            .json()
            .await
            .map_err(|e| crate::Error::ApiError(format!("failed to parse peers response: {e}")))
    }

    /// Perform a network connectivity check.
    ///
    /// Calls `GET /localapi/v0/netcheck`.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ApiError`] if the request fails.
    pub async fn get_netcheck(&self) -> Result<serde_json::Value> {
        let url = format!("{}/localapi/v0/netcheck", self.base_url);
        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| crate::Error::ApiError(format!("netcheck request failed: {e}")))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(crate::Error::ApiError(format!(
                "netcheck request returned {status}: {body}"
            )));
        }

        response
            .json()
            .await
            .map_err(|e| crate::Error::ApiError(format!("failed to parse netcheck response: {e}")))
    }

    /// Fetch the current DNS configuration.
    ///
    /// Calls `GET /localapi/v0/dns-config`.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ApiError`] if the request fails.
    pub async fn get_dns_config(&self) -> Result<serde_json::Value> {
        let url = format!("{}/localapi/v0/dns-config", self.base_url);
        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| crate::Error::ApiError(format!("dns-config request failed: {e}")))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(crate::Error::ApiError(format!(
                "dns-config request returned {status}: {body}"
            )));
        }

        response.json().await.map_err(|e| {
            crate::Error::ApiError(format!("failed to parse dns-config response: {e}"))
        })
    }
}

impl Default for TailscaleApi {
    fn default() -> Self {
        Self::new()
    }
}
