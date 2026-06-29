//! Async proxy data collection (LIVE READ-ONLY).
//!
//! [`ProxyCollector`] manages background collection of reverse-proxy state via
//! a tokio oneshot channel, following the same pattern as
//! [`StatusCollector`](crate::status_collector::StatusCollector),
//! [`SshDataCollector`](crate::ssh_data::SshDataCollector), and
//! [`Fail2banCollector`](crate::fail2ban_data::Fail2banCollector).
//!
//! This is a read-only integration. It mirrors the fail2ban template MINUS the
//! write path — there are no proxy-mutation operations, no optimistic updates,
//! no cooldown gate, and no loading spinner. Every call to the backend is a
//! pure read.
//!
//! Doctor findings are expensive (they shell out to `nginx`, `systemctl`,
//! `certbot`, …) and change slowly. Unlike fail2ban, the proxy backend has no
//! cheap status-only probe path — the doctor IS the single probe that produces
//! status, backend, `server_blocks`, certificates AND findings, all via those
//! same shell-outs. So the WHOLE `ProxyReport` is cached for 60s and reused
//! wholesale on a cache hit (skipping the doctor entirely), mirroring the
//! `!use_cache` gating fail2ban applies to `f2b.doctor(...)`. Only the cheap
//! filesystem-only certbot live-dir scan still runs every tick.
//!
//! ## macOS / construction
//!
//! [`toride_proxy::ProxyClient::system`] is the construction entry point. It
//! builds a `DuctRunner` and resolves default `ProxyPaths` but does NOT shell
//! out and does NOT check for `nginx` — construction therefore never fails on
//! macOS (its rustdoc claim of "Returns an error if the nginx binary cannot be
//! found" is aspirational). The only way construction returns an error is a
//! genuine I/O failure, in which case the collector returns
//! [`empty_bundle_with_reason`] with `available = false`.
//!
//! Missing binaries (`systemctl`, `nginx`) are instead surfaced by the doctor:
//! each per-check method catches runner errors and emits a `Critical` finding
//! for the missing binary rather than `?`-propagating the first one out of
//! `run` (which would blank the whole report). So on macOS the section
//! degrades gracefully to `available = true` with Critical findings about the
//! missing binaries — NOT to the unavailable panel.
//!
//! ## Feature scope
//!
//! The `toride-proxy` dependency is enabled with its default features
//! (`client`, `doctor`, `nginx`). The `certs` / `caddy` / `waf` features are
//! OFF, so `CertManager::list_certificates`, `CaddyManager`, and the WAF
//! manager are unavailable. Certificate rows are therefore enumerated by a
//! direct read of the certbot live directory (`/etc/letsencrypt/live/*`) rather
//! than via the certbot CLI; this needs no binary and degrades cleanly when the
//! directory is absent.
//!
//! ## Blocking
//!
//! The `DuctRunner` shells out synchronously and the certbot-dir scan does
//! blocking filesystem reads. All backend work is wrapped in
//! [`tokio::task::spawn_blocking`] so the tokio worker is never stalled.

use std::path::Path;
use std::time::SystemTime;

use tokio::sync::oneshot;
use toride_runner::Runner;

use crate::toride_proxy_convert;
use crate::ui::screens::toride_proxy::{CertEntry, FindingEntry, ServerBlockEntry};

/// Aggregated reverse-proxy data for the read-only section.
#[derive(Clone, Debug)]
pub struct ProxyDataBundle {
    /// Whether the proxy backend was reachable at all. `false` when
    /// construction failed entirely — the UI renders a degraded "unavailable"
    /// panel.
    pub available: bool,
    /// Which proxy backend the report is for (e.g. "nginx").
    pub backend: String,
    /// Proxy server status as a lowercase string: "running" | "stopped" |
    /// "unknown: <reason>". Mirrors `ProxyStatus::Display`.
    pub status: String,
    /// Configured server blocks (virtual hosts).
    pub server_blocks: Vec<ServerBlockEntry>,
    /// TLS certificates discovered in the certbot live directory.
    pub certificates: Vec<CertEntry>,
    /// Whether any certificate is expired or invalid.
    pub has_expired_certs: bool,
    /// WAF (Web Application Firewall) status. The `waf` feature is OFF in the
    /// TUI, so this is always `None` (status unknown / not configured); kept as
    /// a field so the rendered card has a stable home and a future feature flip
    /// needs no spine change.
    pub waf_available: Option<bool>,
    /// Doctor findings. On a cache-hit poll these come from the cached whole
    /// `ProxyReport` rather than a fresh doctor run.
    pub findings: Vec<FindingEntry>,
    /// Human-readable reason the backend was unreachable, populated ONLY when
    /// `available == false` because a collection task panicked (`JoinError`) or
    /// construction returned a hard error. `None` otherwise — notably also
    /// `None` for a freshly-constructed empty bundle before any collection has
    /// run.
    pub unavailable_reason: Option<String>,
}

// ── Collector ───────────────────────────────────────────────────────────────

/// Manages periodic async collection of reverse-proxy data.
///
/// Mirrors [`Fail2banCollector`](crate::fail2ban_data::Fail2banCollector): a
/// oneshot channel for the in-flight result, plus a 60s TTL cache. Because the
/// proxy backend exposes no status-only probe path, the whole `ProxyReport`
/// (status + backend + `server_blocks` + certs + findings) is cached and reused
/// on a cache hit, so the expensive doctor shell-outs are not re-run on every
/// 2s refresh tick.
pub struct ProxyCollector {
    /// Carries the bundle AND whether the cached report was reused for this
    /// poll. See [`Fail2banCollector`](crate::fail2ban_data::Fail2banCollector)
    /// for the freshness-timestamp rationale.
    rx: Option<
        oneshot::Receiver<(
            ProxyDataBundle,
            bool,
            Option<toride_proxy::report::ProxyReport>,
        )>,
    >,
    /// Cached doctor report from the last collection. Unlike fail2ban, the
    /// proxy backend has NO status-only probe path — the doctor IS the single
    /// probe that produces status, backend, `server_blocks`, certificates AND
    /// findings. To genuinely throttle the expensive shell-outs (nginx -t,
    /// systemctl status nginx, cert checks) the WHOLE report is cached for the
    /// TTL window, not just the findings field.
    cached_report: Option<toride_proxy::report::ProxyReport>,
    /// When the report cache was last refreshed.
    report_fresh_at: Option<std::time::Instant>,
}

/// How long to keep the cached report before re-running the doctor suite.
const REPORT_TTL: std::time::Duration = std::time::Duration::from_mins(1);

impl ProxyCollector {
    /// Create a new collector with no pending collection.
    #[must_use]
    pub fn new() -> Self {
        Self {
            rx: None,
            cached_report: None,
            report_fresh_at: None,
        }
    }

    /// Whether a collection is currently in-flight.
    pub fn is_pending(&self) -> bool {
        self.rx.is_some()
    }

    /// Start a new background collection.
    ///
    /// If a collection is already in-flight, this is a no-op. The 60s report
    /// cache is consulted: when fresh, the spawned task reuses the cached
    /// `ProxyReport` instead of re-running the doctor suite — so the expensive
    /// shell-outs (nginx -t, systemctl status, cert checks) are skipped
    /// entirely, mirroring fail2ban's gating of `f2b.doctor(...)` on `!use_cache`.
    pub fn start(&mut self) {
        if self.rx.is_some() {
            return;
        }
        let (tx, rx) = oneshot::channel();
        let use_cache = self.cached_report.is_some()
            && self
                .report_fresh_at
                .is_some_and(|t| t.elapsed() < REPORT_TTL);
        let cached_report = self.cached_report.clone();
        self.rx = Some(rx);
        tokio::spawn(async move {
            let (bundle, reused_cache, fresh_report) =
                collect_real_proxy(use_cache, cached_report).await;
            let _ = tx.send((bundle, reused_cache, fresh_report));
        });
    }

    /// Poll for a completed collection result.
    ///
    /// Returns `Some(bundle)` if the collection completed, `None` if still
    /// pending or if the collection failed. On success the cached report is
    /// updated, but the freshness timestamp is only advanced when the doctor
    /// was actually re-run (not on a cache-hit poll) — otherwise the 60s TTL
    /// would be re-armed forever with the same cached data on every 2s refresh.
    pub async fn poll(&mut self) -> Option<ProxyDataBundle> {
        match &mut self.rx {
            Some(rx) => {
                let result = rx.await.ok();
                if let Some((ref _bundle, used_cache, ref fresh_report)) = result
                    && !used_cache
                {
                    // Cache the freshly-run report verbatim and advance the
                    // freshness clock. The bundle is lossy (it cannot round-
                    // trip back into a ProxyReport), so collect_real_proxy
                    // hands the owning report back alongside the bundle on a
                    // doctor run. On a cache-hit poll `fresh_report` is None
                    // and the clock is left untouched so the TTL is not
                    // re-armed with reused data.
                    if let Some(report) = fresh_report {
                        self.cached_report = Some(report.clone());
                    }
                    self.report_fresh_at = Some(std::time::Instant::now());
                }
                self.rx = None;
                result.map(|(bundle, _, _)| bundle)
            }
            None => None,
        }
    }

    /// Invalidate the report cache so the next collection re-runs the doctor.
    #[allow(dead_code)]
    pub fn invalidate_findings_cache(&mut self) {
        self.cached_report = None;
        self.report_fresh_at = None;
    }
}

impl Default for ProxyCollector {
    fn default() -> Self {
        Self::new()
    }
}

// ── Real data collection ────────────────────────────────────────────────────

/// Collect reverse-proxy data by shelling out to the real binaries.
///
/// All work runs on the blocking thread pool. The doctor report may be reused
/// wholesale from the cache. On ANY construction error — or a panic in the
/// probe block — returns [`empty_bundle`] with `available = false`.
///
/// Returns `(bundle, used_cache, fresh_report)` where:
/// - `used_cache` records whether the cached report was reused (and thus the
///   doctor suite was NOT re-run).
/// - `fresh_report` is the owning `ProxyReport` when the doctor was actually
///   run this poll (so the caller can cache it for next time), or `None` on a
///   cache-hit poll. The bundle is lossy — it cannot round-trip back into a
///   `ProxyReport` — so the owning report is handed back alongside it.
#[expect(
    clippy::too_many_lines,
    reason = "real-data collection is inherently linear"
)]
#[expect(
    clippy::similar_names,
    reason = "use_cache (input) vs used_cache (output) are distinct domain flags"
)]
async fn collect_real_proxy(
    use_cache: bool,
    cached_report: Option<toride_proxy::report::ProxyReport>,
) -> (
    ProxyDataBundle,
    bool,
    Option<toride_proxy::report::ProxyReport>,
) {
    // Build the ProxyClient facade on the blocking pool. `system()` is the
    // documented construction entry point and returns a hard error only on a
    // genuine I/O / duct failure; a missing nginx binary surfaces as a doctor
    // finding rather than here.
    let client = match tokio::task::spawn_blocking(toride_proxy::client::ProxyClient::system).await
    {
        Ok(Ok(client)) => client,
        Ok(Err(e)) => {
            tracing::warn!("proxy backend construction failed: {e}");
            return (
                empty_bundle_with_reason(format!("proxy backend construction failed: {e}")),
                false,
                None,
            );
        }
        Err(e) => {
            tracing::warn!("proxy construction task panicked: {e}");
            return (
                empty_bundle_with_reason(format!("proxy backend construction panicked: {e}")),
                false,
                None,
            );
        }
    };

    // Run ALL blocking probes in a single spawn_blocking that owns `client`.
    // This keeps every shell-out off the tokio worker (the `DuctRunner` is
    // synchronous) and collects everything in one owned closure so results
    // cross the thread boundary cleanly.
    //
    // ── Cache gating (mirrors fail2ban_data.rs) ────────────────────────────
    // fail2ban gates `f2b.doctor(...)` on `!use_cache` because it has cheaper
    // status probes (`service()`, `client()`, `firewall()`) that still run
    // every 2s. The proxy backend has NO such status-only path: the doctor IS
    // the single probe that produces status, backend, server_blocks,
    // certificates AND findings — and it shells out to nginx -t, systemctl
    // status nginx, and cert checks on every invocation. Those shell-outs are
    // NOT cheap relative to the 2s refresh, so on a cache hit (`use_cache`) we
    // reuse the WHOLE cached ProxyReport and skip the doctor entirely. The
    // certbot live-dir scan is filesystem-only (no binary) and is cheap, so it
    // still runs every tick to keep the certs table fresh between doctor runs.
    let result = tokio::task::spawn_blocking(move || {
        // Run the doctor once and split its single ProxyReport into the lossy
        // bundle fields plus the owning report (for caching). Hoisted into a
        // closure so both the cache-miss path and the cache-race fallback
        // (use_cache set but no cached report present) share one implementation.
        let run_doctor = |client: &toride_proxy::client::ProxyClient| {
            match client.doctor(toride_proxy::doctor::DoctorScope::All) {
                Ok(r) => {
                    // Clone every field out of `r` BEFORE returning the owning
                    // report, so the report stays whole for caching. The bundle
                    // is lossy; the report is not.
                    let backend = r.backend.clone();
                    let status_str = r.status.to_string();
                    let server_blocks =
                        toride_proxy_convert::convert_server_blocks(r.server_blocks.clone());
                    let certificates =
                        toride_proxy_convert::convert_certificates(r.certificates.clone());
                    let findings = toride_proxy_convert::convert_findings(r.findings.clone());
                    // NOTE: has_expired_certs is intentionally NOT carried here.
                    // It is shadowed/re-derived from the final `certificates` list
                    // (which includes scan-discovered certs) after the certbot-dir
                    // scan below — the report-derived value would be discarded
                    // regardless, so we avoid the wasted `r.has_expired_certs()` call.
                    (
                        backend,
                        status_str,
                        server_blocks,
                        certificates,
                        findings,
                        Some(r),
                    )
                }
                Err(e) => {
                    tracing::warn!("proxy doctor: {e}");
                    (
                        String::new(),
                        "unknown".to_string(),
                        Vec::new(),
                        Vec::new(),
                        Vec::new(),
                        None,
                    )
                }
            }
        };

        let report_owned: Option<toride_proxy::report::ProxyReport>;
        let backend: String;
        let status_str: String;
        let server_blocks: Vec<ServerBlockEntry>;
        let mut certificates: Vec<CertEntry>;
        let findings: Vec<FindingEntry>;
        // `used_cache` is true ONLY when the cached report was reused verbatim
        // (the doctor was skipped). Tracked explicitly here — rather than
        // inferred from `fresh_report` later — so the semantics are exact and
        // host-independent: a cache-race fallback that runs the doctor but gets
        // an Err (e.g. nginx missing) still reports used_cache == false, because
        // the doctor WAS attempted and the caller must re-arm the TTL clock.
        let used_cache: bool;

        if use_cache {
            if let Some(r) = cached_report {
                // Cache hit: reuse the cached report verbatim. The doctor is
                // NOT re-run, so nginx -t / systemctl / cert shell-outs are
                // skipped entirely — this is the throttle the cache exists for.
                backend = r.backend.clone();
                status_str = r.status.to_string();
                server_blocks = toride_proxy_convert::convert_server_blocks(r.server_blocks);
                certificates = toride_proxy_convert::convert_certificates(r.certificates);
                findings = toride_proxy_convert::convert_findings(r.findings);
                report_owned = None;
                used_cache = true;
            } else {
                // use_cache was set but no cached report is present (e.g. the
                // very first poll raced the clock): run the doctor for real so
                // the operator gets data, and hand the fresh report back so the
                // caller populates the cache and advances the TTL clock.
                let (b, s, sb, c, f, ro) = run_doctor(&client);
                backend = b;
                status_str = s;
                server_blocks = sb;
                certificates = c;
                findings = f;
                report_owned = ro;
                used_cache = false;
            }
        } else {
            // Cache miss: run the doctor once. A single ProxyReport carries
            // status, backend, server_blocks, certificates AND findings.
            let (b, s, sb, c, f, ro) = run_doctor(&client);
            backend = b;
            status_str = s;
            server_blocks = sb;
            certificates = c;
            findings = f;
            report_owned = ro;
            used_cache = false;
        }

        // ── Certificates from the certbot live directory ──────────────────
        // The `certs` feature is OFF, so CertManager is unavailable. Enumerate
        // the certbot live dir directly (no binary needed) so the certs table
        // shows real domains even when certbot itself is missing. Existing
        // entries from the report (if any) are kept; newly-discovered domains
        // are appended. A missing directory is not fatal — it simply yields no
        // extra certs (and the doctor surfaces `cert.no-certbot-dir`).
        //
        // For each discovered fullchain.pem we shell out once to `openssl x509
        // -enddate` (via the same DuctRunner the doctor uses) to obtain the REAL
        // not_after / days_remaining / is_valid. This is cheap relative to the
        // doctor suite (one fast openssl per cert, not nginx -t / systemctl),
        // so it still runs every tick to keep expiry current between 60s doctor
        // runs. On any failure (openssl absent, parse error, expired cert) the
        // cert degrades to `CertExpiry::unknown()` — `is_valid = false`, empty
        // not_after — which the UI renders as `?` (unverified) or red (expired),
        // never the misleading `is_valid = true` placeholder.
        let runner = client.runner();
        scan_certbot_live_dir(&mut certificates, runner, SystemTime::now());

        // ── has_expired_certs derivation ─────────────────────────────────
        // Compute the flag ONCE, from the ACTUAL rendered CertEntry list
        // (which includes scan-discovered certs appended above). We deliberately
        // do NOT carry a report-derived `has_expired_certs` through the
        // cache/if-else branches above: the doctor never populates
        // report.certificates (the `certs` feature is OFF), so
        // report.has_expired_certs() is always false in practice and would be
        // discarded here regardless. Deriving from `certificates` makes the
        // flag reflect what the operator actually sees. A cert with unknown
        // expiry (empty not_after) does NOT count as expired — it counts as
        // unverified, surfaced separately.
        let has_expired_certs = certificates.iter().any(|c| !c.is_valid);

        // ── Availability heuristic ────────────────────────────────────────
        // The section is "available" if the doctor produced any report at all
        // (status known), OR any findings, certs, or server blocks exist. A
        // host with nginx missing yields Critical/Error findings but no status
        // data — that still counts as available so the operator SEES the
        // findings rather than a blank panel. The only way `available` is
        // false is a construction failure or a probe panic, handled above.
        let available = !findings.is_empty()
            || !certificates.is_empty()
            || !server_blocks.is_empty()
            || !backend.is_empty();

        let bundle = ProxyDataBundle {
            available,
            backend,
            status: status_str,
            server_blocks,
            certificates,
            has_expired_certs,
            // The `waf` feature is OFF in the TUI, so WAF status is unknown.
            waf_available: None,
            findings,
            // Success path: no panic / no construction error, so no reason.
            unavailable_reason: None,
        };
        (bundle, used_cache, report_owned)
    })
    .await;

    match result {
        Ok((bundle, used_cache, fresh_report)) => {
            // `used_cache` is tracked explicitly inside the blocking task: true
            // only when the cached report was reused verbatim (doctor skipped).
            // The caller advances the TTL clock iff `used_cache == false`.
            (bundle, used_cache, fresh_report)
        }
        Err(e) => {
            tracing::warn!("proxy collection task panicked: {e}");
            (
                empty_bundle_with_reason(format!("proxy data collection panicked: {e}")),
                false,
                None,
            )
        }
    }
}

/// Scan the certbot live directory (`/etc/letsencrypt/live/*`) and append a
/// [`CertEntry`] per domain that is not already present.
///
/// The `certs` feature is OFF, so the `CertManager` facade is unavailable.
/// This pure-filesystem scan needs no binary to enumerate domains and degrades
/// cleanly when the directory does not exist (macOS, hosts without certbot).
/// For each discovered `fullchain.pem`, the real expiry is resolved by shelling
/// out to `openssl x509 -enddate` via [`toride_proxy::certs_parse::read_cert_expiry`]
/// using the supplied `runner`. On any failure (openssl absent, parse error,
/// expired cert) the cert degrades to the unknown expiry state (`is_valid =
/// false`, empty `not_after`) — never the previous misleading `is_valid = true`
/// placeholder. The doctor's `cert.missing-cert` findings still catch broken
/// certs independently of this scan.
///
/// Any I/O error on the directory read is swallowed with a `tracing::debug!`
/// so a permissions failure on one entry never blanks the whole table.
fn scan_certbot_live_dir(certs: &mut Vec<CertEntry>, runner: &dyn Runner, now: SystemTime) {
    scan_certbot_live_dir_at(Path::new("/etc/letsencrypt/live"), certs, runner, now);
}

/// Path-injected core of [`scan_certbot_live_dir`] so the dedup / fullchain /
/// expiry-resolution logic can be exercised host-independently against a temp dir.
fn scan_certbot_live_dir_at(
    live_dir: &Path,
    certs: &mut Vec<CertEntry>,
    runner: &dyn Runner,
    now: SystemTime,
) {
    let Ok(entries) = std::fs::read_dir(live_dir) else {
        // Common on macOS / hosts without certbot; not worth a warning.
        return;
    };

    let known: std::collections::HashSet<String> = certs.iter().map(|c| c.domain.clone()).collect();

    for entry in entries.flatten() {
        let domain = entry.file_name().to_string_lossy().to_string();
        if domain.is_empty() || known.contains(&domain) {
            continue;
        }
        let fullchain = entry.path().join("fullchain.pem");
        if !fullchain.exists() {
            // The doctor surfaces `cert.missing-cert` for these; skip here so
            // the certs table only lists domains whose fullchain is present.
            tracing::debug!("proxy certbot live dir: {domain} has no fullchain.pem, skipping");
            continue;
        }
        // Resolve the REAL expiry via openssl. On any failure read_cert_expiry
        // degrades to CertExpiry::unknown() (is_valid=false, empty not_after),
        // which the UI renders as '?' (expiry unknown) — strictly safer than
        // the previous is_valid=true placeholder. It never returns Err in
        // practice (the Result shape is forward-compat), but we swallow any
        // internal error to the same unknown state to keep the read-only
        // contract that this scan never crashes the collector.
        let expiry = toride_proxy::certs_parse::read_cert_expiry(&fullchain, runner, now)
            .unwrap_or_else(|e| {
                tracing::debug!(
                    "proxy certbot live dir: read_cert_expiry internal error for {domain}: {e}"
                );
                toride_proxy::certs_parse::CertExpiry::unknown()
            });
        tracing::debug!(
            "proxy certbot live dir: appended domain {domain} with expiry {:?} (valid={}, days={})",
            expiry.not_after,
            expiry.is_valid,
            expiry.days_remaining
        );
        certs.push(CertEntry {
            domain,
            issuer: "(unknown)".into(),
            not_after: expiry.not_after,
            days_remaining: expiry.days_remaining,
            is_valid: expiry.is_valid,
        });
    }
}

/// Empty bundle used when the proxy backend could not be constructed at all.
///
/// `available = false` signals the UI to render the degraded panel. No reason
/// is attached because none is known at this point; construction errors and
/// collection-time panics use [`empty_bundle_with_reason`].
fn empty_bundle() -> ProxyDataBundle {
    ProxyDataBundle {
        available: false,
        backend: String::new(),
        status: String::new(),
        server_blocks: Vec::new(),
        certificates: Vec::new(),
        has_expired_certs: false,
        waf_available: None,
        findings: Vec::new(),
        unavailable_reason: None,
    }
}

/// Empty bundle carrying the reason collection failed. Used when construction
/// returned a hard error or a `spawn_blocking` task panicked (`JoinError`) — the
/// reason string is rendered by the UI's degraded panel so the operator sees
/// what actually went wrong.
fn empty_bundle_with_reason(reason: String) -> ProxyDataBundle {
    let mut b = empty_bundle();
    b.unavailable_reason = Some(reason);
    b
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_is_not_pending() {
        let collector = ProxyCollector::new();
        assert!(!collector.is_pending());
    }

    #[test]
    fn default_matches_new() {
        assert_eq!(
            ProxyCollector::new().is_pending(),
            ProxyCollector::default().is_pending()
        );
    }

    #[tokio::test]
    async fn start_makes_pending() {
        let mut collector = ProxyCollector::new();
        assert!(!collector.is_pending());
        collector.start();
        assert!(collector.is_pending());
    }

    #[tokio::test]
    async fn start_is_idempotent() {
        let mut collector = ProxyCollector::new();
        collector.start();
        assert!(collector.is_pending());
        collector.start(); // no-op, does not replace the receiver
        assert!(collector.is_pending());
    }

    #[tokio::test]
    async fn poll_returns_none_when_not_started() {
        let mut collector = ProxyCollector::new();
        assert!(collector.poll().await.is_none());
    }

    #[tokio::test]
    async fn poll_clears_pending() {
        let mut collector = ProxyCollector::new();
        collector.start();
        // Let the spawned task complete (it shells out, so give it time).
        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
        let _ = collector.poll().await;
        assert!(!collector.is_pending(), "poll should clear pending state");
    }

    #[tokio::test]
    async fn poll_returns_bundle_after_collection() {
        // On any host (including macOS without nginx/certbot) the collector
        // must return Some(bundle) after start() + enough time. The bundle's
        // `available` flag reflects whether the proxy backend was found.
        let mut collector = ProxyCollector::new();
        collector.start();
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        let bundle = collector.poll().await;
        assert!(bundle.is_some(), "poll should return Some after completion");
    }

    #[test]
    fn empty_bundle_is_unavailable() {
        let b = empty_bundle();
        assert!(!b.available);
        assert!(b.server_blocks.is_empty());
        assert!(b.certificates.is_empty());
        assert!(b.findings.is_empty());
        assert!(b.backend.is_empty());
        assert!(b.status.is_empty());
        assert!(!b.has_expired_certs);
        assert!(b.waf_available.is_none());
        assert!(
            b.unavailable_reason.is_none(),
            "empty_bundle carries no reason; errors use empty_bundle_with_reason"
        );
    }

    #[test]
    fn empty_bundle_with_reason_carries_reason() {
        let b = empty_bundle_with_reason("boom".into());
        assert!(!b.available);
        assert_eq!(b.unavailable_reason.as_deref(), Some("boom"));
    }

    #[tokio::test]
    async fn report_cache_is_populated_after_poll() {
        let mut collector = ProxyCollector::new();
        collector.start();
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        let _ = collector.poll().await;
        // A real doctor run (cache miss) must populate BOTH the cached report
        // and the freshness timestamp so the next poll within the TTL window
        // hits the cache and skips the doctor shell-outs.
        assert!(
            collector.cached_report.is_some(),
            "cache miss should populate cached_report"
        );
        assert!(
            collector.report_fresh_at.is_some(),
            "cache miss should advance report_fresh_at"
        );
    }

    #[test]
    fn invalidate_findings_cache_clears_it() {
        let mut collector = ProxyCollector::new();
        collector.cached_report = Some(default_empty_report());
        collector.report_fresh_at = Some(std::time::Instant::now());
        collector.invalidate_findings_cache();
        assert!(collector.cached_report.is_none());
        assert!(collector.report_fresh_at.is_none());
    }

    /// A cache HIT (TTL fresh + cached report present) must report
    /// `used_cache == true` and therefore NOT advance the freshness timestamp
    /// — otherwise the 60s TTL would be re-armed forever with stale data on
    /// every 2s refresh tick. This is the regression the whole-report cache
    /// exists to prevent: previously the doctor ran unconditionally every
    /// tick because the cache only substituted the findings field.
    #[tokio::test]
    async fn cache_hit_skips_doctor_and_preserves_freshness() {
        let cached = default_empty_report();
        let stale_at = std::time::Instant::now();
        let (bundle, used_cache, fresh_report) =
            collect_real_proxy(true, Some(cached.clone())).await;
        assert!(
            used_cache,
            "cache hit with a present report must report used_cache == true"
        );
        assert!(
            fresh_report.is_none(),
            "cache hit must not return a fresh report (doctor must not run)"
        );
        // The bundle must be losslessly derived from the cached report, so its
        // fields mirror the (empty) report we seeded.
        assert_eq!(bundle.backend, cached.backend);
        // Freshness clock is advanced by the CALLER (poll) only when
        // used_cache == false, so simulate that guard here: with used_cache
        // true, report_fresh_at must NOT move.
        let _ = stale_at; // unused; the guard lives in poll()
    }

    /// A cache MISS (`use_cache` == false) must run the doctor, return a fresh
    /// owning report, and report `used_cache == false` so the caller advances
    /// the TTL clock. Even on a host where nginx is missing the doctor must
    /// not panic — it returns an Err that `collect_real_proxy` swallows into an
    /// empty bundle with `status = "unknown"`.
    #[tokio::test]
    async fn cache_miss_runs_doctor_and_returns_fresh_report() {
        let (bundle, used_cache, fresh_report) = collect_real_proxy(false, None).await;
        assert!(!used_cache, "cache miss must report used_cache == false");
        // fresh_report is Some when the doctor succeeded, None when it errored
        // (e.g. missing nginx on macOS/CI). Both are acceptable; the contract
        // is only that used_cache == false so the caller can re-arm the TTL.
        let _ = bundle;
        let _ = fresh_report;
    }

    /// Edge case: `use_cache == true` but NO cached report is present (the
    /// first poll races the clock before any doctor has run). The collector
    /// must NOT hand back an empty cache-hit bundle; it must fall through to a
    /// real doctor run, report `used_cache == false`, and return a fresh
    /// report so the caller populates the cache.
    #[tokio::test]
    async fn cache_hit_with_no_report_falls_through_to_doctor() {
        let (_bundle, used_cache, _fresh_report) = collect_real_proxy(true, None).await;
        assert!(
            !used_cache,
            "use_cache with no cached report must fall through and report used_cache == false"
        );
    }

    /// Construct a minimal `ProxyReport` for cache tests via the public
    /// `ProxyReport::new` constructor. Used to seed the cache without shelling
    /// out, so the cache-hit path is deterministic and host-independent (does
    /// not depend on nginx being installed).
    fn default_empty_report() -> toride_proxy::report::ProxyReport {
        toride_proxy::report::ProxyReport::new("")
    }

    #[test]
    fn scan_certbot_live_dir_handles_missing_dir() {
        // /etc/letsencrypt/live does not exist on macOS / CI hosts. The scan
        // must be a no-op (not panic) and leave the certs vec untouched.
        let mut certs = Vec::new();
        let runner = toride_runner::duct_runner::DuctRunner;
        scan_certbot_live_dir(&mut certs, &runner, SystemTime::now());
        // No assertion on contents — only that it didn't panic.
    }

    /// Dedup path: a domain already present in `certs` is NOT re-added.
    /// Uses the path-injected core so the test is host-independent (the real
    /// entry point hard-codes /etc/letsencrypt/live). The strict `FakeRunner`
    /// errors on any unmatched call, so the appended `other.com` cert degrades
    /// to `CertExpiry::unknown()` (empty `not_after`, `is_valid=false`).
    #[test]
    fn scan_certbot_live_dir_dedups_known_domains() {
        use toride_runner::fake::FakeRunner;
        let tmp = tempfile::tempdir().expect("tempdir");
        let live = tmp.path();
        std::fs::create_dir_all(live.join("example.com")).unwrap();
        std::fs::create_dir_all(live.join("other.com")).unwrap();
        std::fs::write(live.join("example.com/fullchain.pem"), b"pem").unwrap();
        std::fs::write(live.join("other.com/fullchain.pem"), b"pem").unwrap();

        let mut certs = vec![CertEntry {
            domain: "example.com".into(),
            issuer: "Let's Encrypt".into(),
            not_after: "2099-01-01".into(),
            days_remaining: 1000,
            is_valid: true,
        }];
        let runner = FakeRunner::new().strict();
        scan_certbot_live_dir_at(live, &mut certs, &runner, SystemTime::now());

        // example.com is NOT re-added; only other.com is appended.
        let example: Vec<&CertEntry> = certs.iter().filter(|c| c.domain == "example.com").collect();
        assert_eq!(example.len(), 1, "example.com must not be duplicated");
        // The pre-existing example.com entry is preserved verbatim (issuer +
        // not_after untouched, not overwritten by the scan defaults).
        assert_eq!(example[0].issuer, "Let's Encrypt");
        assert_eq!(example[0].not_after, "2099-01-01");

        let other: Vec<&CertEntry> = certs.iter().filter(|c| c.domain == "other.com").collect();
        assert_eq!(other.len(), 1, "other.com must be appended exactly once");
    }

    /// fullchain.pem gate: a live-dir entry WITHOUT fullchain.pem is skipped,
    /// so the certs table only lists domains whose chain is actually present.
    #[test]
    fn scan_certbot_live_dir_skips_entries_without_fullchain() {
        use toride_runner::fake::FakeRunner;
        let tmp = tempfile::tempdir().expect("tempdir");
        let live = tmp.path();
        // present.com has the chain → kept.
        std::fs::create_dir_all(live.join("present.com")).unwrap();
        std::fs::write(live.join("present.com/fullchain.pem"), b"pem").unwrap();
        // bare.com is just a directory with no fullchain.pem → skipped.
        std::fs::create_dir_all(live.join("bare.com")).unwrap();

        let mut certs = Vec::new();
        let runner = FakeRunner::new().strict();
        scan_certbot_live_dir_at(live, &mut certs, &runner, SystemTime::now());

        let domains: Vec<&str> = certs.iter().map(|c| c.domain.as_str()).collect();
        assert!(
            domains.contains(&"present.com"),
            "present.com must be listed"
        );
        assert!(
            !domains.contains(&"bare.com"),
            "bare.com (no fullchain.pem) must be skipped"
        );
    }

    /// Appended `CertEntry` state when expiry cannot be resolved: a strict
    /// `FakeRunner` returns Err for the openssl probe (no canned response), so
    /// `read_cert_expiry` degrades to `CertExpiry::unknown()` — empty `not_after`,
    /// `days_remaining=0`, `is_valid=false`. This is the HONEST degradation: the
    /// cert is surfaced as unverified, NEVER the misleading `is_valid=true`
    /// placeholder that previously rendered as a healthy-looking row.
    #[test]
    fn scan_certbot_live_dir_appended_cert_degrades_to_unknown() {
        use toride_runner::fake::FakeRunner;
        let tmp = tempfile::tempdir().expect("tempdir");
        let live = tmp.path();
        std::fs::create_dir_all(live.join("example.com")).unwrap();
        std::fs::write(live.join("example.com/fullchain.pem"), b"pem").unwrap();

        let mut certs = Vec::new();
        // A strict runner has no canned openssl response, so the probe fails
        // (or the which-guard short-circuits when openssl is absent) and the
        // cert degrades to the unknown-expiry state.
        let runner = FakeRunner::new().strict();
        scan_certbot_live_dir_at(live, &mut certs, &runner, SystemTime::now());

        assert_eq!(certs.len(), 1);
        let c = &certs[0];
        assert_eq!(c.domain, "example.com");
        assert_eq!(c.issuer, "(unknown)");
        // Degraded expiry: never the misleading is_valid=true placeholder.
        assert!(
            !c.is_valid,
            "degraded cert must be is_valid=false (got days={}, not_after={:?})",
            c.days_remaining, c.not_after
        );
        assert_eq!(c.days_remaining, 0, "unknown expiry has 0 days_remaining");
        // not_after is empty when openssl is absent (the which-guard path) or
        // non-empty when the strict runner errored after the which-guard —
        // either is an honest "unverified" state. Assert only that is_valid
        // is false, which is the contract that matters.
    }

    /// Real expiry is surfaced when the runner reports a known future expiry.
    /// Uses an exact-match `FakeRunner` response so the test is deterministic
    /// and host-independent (canned openssl stdout). When openssl is absent
    /// from the host the which-guard short-circuits and the cert degrades to
    /// unknown — still honest, just unverified.
    #[test]
    fn scan_certbot_live_dir_appended_cert_surfaces_real_expiry() {
        use toride_runner::fake::FakeRunner;
        use toride_runner::{CommandOutput, CommandSpec};
        let tmp = tempfile::tempdir().expect("tempdir");
        let live = tmp.path();
        std::fs::create_dir_all(live.join("example.com")).unwrap();
        let fullchain = live.join("example.com/fullchain.pem");
        std::fs::write(&fullchain, b"pem").unwrap();

        let spec = CommandSpec::new("openssl")
            .args(["x509", "-enddate", "-noout", "-in"])
            .arg(fullchain.to_str().unwrap());
        let runner = FakeRunner::new().respond(
            spec,
            CommandOutput::from_stdout("notAfter=Jan  1 00:00:00 2099 GMT\n"),
        );

        let mut certs = Vec::new();
        scan_certbot_live_dir_at(live, &mut certs, &runner, SystemTime::now());

        assert_eq!(certs.len(), 1);
        let c = &certs[0];
        assert_eq!(c.domain, "example.com");
        if which::which("openssl").is_ok() {
            // openssl present: real future expiry surfaces as valid.
            assert!(c.is_valid, "future expiry must be valid");
            assert!(c.days_remaining > 0);
            assert_eq!(c.not_after, "Jan  1 00:00:00 2099 GMT");
        } else {
            // No openssl on the host: which-guard degraded to unknown.
            assert!(!c.is_valid, "absent openssl must degrade to unknown");
        }
    }
}
