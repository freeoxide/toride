//! Shared HTTP client construction (DESIGN.md §3.2): one builder, one
//! timeout posture, one redirect policy. The four per-source fetch clients
//! differ only in their User-Agent, which each module supplies from its
//! own `USER_AGENT` const.

use std::time::Duration;

/// Overall per-request timeout applied to every registry fetch client.
///
/// reqwest applies no timeout by default (installer.rs:95-103
/// rationale), so without an explicit cap a stalled response would hold
/// the `lookup` future indefinitely. Registry payloads are small JSON/YAML
/// documents (a few KB per item — homebrew.md §1), so this is far below
/// toride-installer's download budgets (DESIGN.md §3.2).
pub(crate) const HTTP_TIMEOUT: Duration = Duration::from_secs(30);

/// Connect-only timeout, bounded separately from [`HTTP_TIMEOUT`] so a
/// dead or DNS-blackholed host is rejected faster than the overall
/// deadline (DESIGN.md §3.2).
pub(crate) const HTTP_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// Build the shared client for one source. `user_agent` is the complete
/// descriptive per-source UA (each source module keeps a `USER_AGENT`
/// const; descriptive UAs are *mandatory* posture for repology —
/// repology.md §4 — which appends a contact URL to the standard prefix).
///
/// Redirects are followed (`Policy::limited(10)`: the repology reverse
/// oracle is a redirect endpoint, and flathub/homebrew redirect onto
/// CDN/cache hosts — DESIGN.md §3.2), and both timeouts bound every
/// request. Client construction can only fail on TLS-backend
/// initialization, which cannot fail with the workspace's `rustls-tls`
/// shape — hence the same fall-back-to-default treatment as
/// toride-installer's builder (installer.rs:105-114).
pub(crate) fn build_http_client(user_agent: &str) -> reqwest::Client {
    reqwest::Client::builder()
        .user_agent(user_agent)
        .redirect(reqwest::redirect::Policy::limited(10))
        .timeout(HTTP_TIMEOUT)
        .connect_timeout(HTTP_CONNECT_TIMEOUT)
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}
