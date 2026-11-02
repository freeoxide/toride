//! Low-level HTTP client for the Tailscale local API.
//!
//! [`TailscaleApi`] talks to the tailscaled LocalAPI. On Unix targets the
//! default transport is the daemon's Unix socket
//! (`/var/run/tailscale/tailscaled.sock`); URLs are still built against
//! `http://localhost` so the request carries a `Host: localhost` header,
//! which is how the LocalAPI expects direct socket clients to identify
//! themselves. `http://localhost:41642` is NOT a stock listener: 41641 is
//! the WireGuard UDP port, and a plain TCP base URL only works for exotic
//! setups via [`TailscaleApi::with_base_url`].
//!
//! All requests go through `reqwest`. No ad-hoc HTTP calls are made outside
//! this module.

use crate::Result;
use crate::models::StatusDocument;

/// Default LocalAPI Unix socket path on Linux and macOS.
pub const DEFAULT_LOCALAPI_SOCKET: &str = "/var/run/tailscale/tailscaled.sock";

/// URL host the socket transport identifies as.
const LOCALAPI_HOST: &str = "http://localhost";

// ---------------------------------------------------------------------------
// TailscaleApi
// ---------------------------------------------------------------------------

/// Low-level async client for the Tailscale local HTTP API.
///
/// The Tailscale daemon exposes the LocalAPI over a Unix socket; this client
/// wraps the endpoints used by the crate with typed responses.
///
/// # Base URL
///
/// The default constructor dials [`DEFAULT_LOCALAPI_SOCKET`] on Unix. On
/// non-Unix targets (where reqwest cannot dial a Unix socket) the default is
/// the `http://localhost` base URL, which no stock tailscaled serves: callers
/// there must provide their own transport via
/// [`TailscaleApi::with_base_url`].
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
    /// Base URL for request targets (and the `Host` header).
    base_url: String,
    /// HTTP client instance.
    client: reqwest::Client,
}

impl TailscaleApi {
    /// Create a `TailscaleApi` on the default transport: the tailscaled
    /// LocalAPI Unix socket on Unix targets.
    pub fn new() -> Self {
        Self::with_socket(std::path::Path::new(DEFAULT_LOCALAPI_SOCKET))
    }

    /// Create a `TailscaleApi` that dials `socket_path` for every request.
    ///
    /// Ignored on non-Unix targets, where the plain TCP client is used.
    pub fn with_socket(socket_path: &std::path::Path) -> Self {
        Self::with_transport(LOCALAPI_HOST.to_owned(), Some(socket_path))
    }

    /// Create a `TailscaleApi` with a custom TCP base URL, for exotic
    /// setups (e.g. a socket proxy) that forward to the LocalAPI.
    pub fn with_base_url(base_url: String) -> Self {
        Self::with_transport(base_url, None)
    }

    fn with_transport(base_url: String, socket_path: Option<&std::path::Path>) -> Self {
        let mut builder = reqwest::Client::builder().timeout(std::time::Duration::from_secs(10));
        if let Some(path) = socket_path {
            builder = attach_unix_socket(builder, path);
        }
        let client = builder.build().unwrap_or_default();
        Self { base_url, client }
    }

    /// Fetch the current status from the local API as a raw JSON value.
    ///
    /// Calls `GET /localapi/v0/status`. Prefer [`TailscaleApi::get_status_document`],
    /// which deserializes straight into the typed document this crate
    /// consumes; this raw form stays available for direct inspection.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ApiError`] if the request fails or the daemon
    /// is not running.
    pub async fn get_status(&self) -> Result<serde_json::Value> {
        self.get_json("/localapi/v0/status").await
    }

    /// Fetch the current status deserialized into the typed
    /// [`StatusDocument`], skipping the `serde_json::Value` DOM entirely.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ApiError`] if the request fails or the body
    /// does not match the status document shape.
    pub(crate) async fn get_status_document(&self) -> Result<StatusDocument> {
        let url = format!("{}/localapi/v0/status", self.base_url);
        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| crate::Error::ApiError(format!("status request failed: {e}")))?;
        check_status(response, "status")
            .await?
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
        self.get_json("/localapi/v0/peers").await
    }

    /// Perform a network connectivity check.
    ///
    /// Calls `GET /localapi/v0/netcheck`.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ApiError`] if the request fails.
    pub async fn get_netcheck(&self) -> Result<serde_json::Value> {
        self.get_json("/localapi/v0/netcheck").await
    }

    /// Fetch the current DNS configuration.
    ///
    /// Calls `GET /localapi/v0/dns-config`.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ApiError`] if the request fails.
    pub async fn get_dns_config(&self) -> Result<serde_json::Value> {
        self.get_json("/localapi/v0/dns-config").await
    }

    /// Issue a GET against `path` and parse the body as JSON.
    async fn get_json(&self, path: &str) -> Result<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        let name = path.rsplit('/').next().unwrap_or(path);
        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| crate::Error::ApiError(format!("{name} request failed: {e}")))?;
        check_status(response, name)
            .await?
            .json()
            .await
            .map_err(|e| crate::Error::ApiError(format!("failed to parse {name} response: {e}")))
    }
}

/// Fail a non-success response with its status and body, returning the
/// response on success for body extraction.
async fn check_status(response: reqwest::Response, name: &str) -> Result<reqwest::Response> {
    if response.status().is_success() {
        return Ok(response);
    }
    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    Err(crate::Error::ApiError(format!(
        "{name} request returned {status}: {body}"
    )))
}

/// Attach a Unix-socket dialer to the client builder on Unix targets.
#[cfg(unix)]
fn attach_unix_socket(
    builder: reqwest::ClientBuilder,
    path: &std::path::Path,
) -> reqwest::ClientBuilder {
    builder.unix_socket(path)
}

/// Non-Unix targets have no Unix-socket transport; the plain TCP client is
/// used and callers are expected to override the base URL.
#[cfg(not(unix))]
fn attach_unix_socket(
    builder: reqwest::ClientBuilder,
    _path: &std::path::Path,
) -> reqwest::ClientBuilder {
    builder
}

impl Default for TailscaleApi {
    fn default() -> Self {
        Self::new()
    }
}
