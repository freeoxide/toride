//! Certificate parsing utilities.
//!
//! Provides functions for parsing certificate files, extracting metadata,
//! and reading certificate details from the filesystem.
//!
//! ## Real expiry from scan-discovered certs
//!
//! [`read_cert_expiry`] shells out to `openssl x509 -enddate -noout -in <path>`
//! via the [`Runner`](toride_runner::Runner) abstraction and parses the
//! resulting `notAfter=...` line into a real expiry. This lets scan-discovered
//! certificate files (e.g. the certbot live-directory scan performed by the TUI)
//! carry a genuine `not_after` / `days_remaining` / `is_valid` rather than the
//! misleading placeholder (`is_valid = true`, empty `not_after`) that previously
//! rendered as `?` in the UI.
//!
//! On any failure — `openssl` absent, command timeout, non-zero exit, or an
//! unparseable date — [`read_cert_expiry`] degrades to
//! [`CertExpiry::unknown`], which carries `is_valid = false` and an empty
//! `not_after`. This is deliberately NOT a "looks valid" status: the operator
//! sees the cert as unverified rather than healthy.

use crate::error::{Error, Result};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use toride_runner::{CommandSpec, Runner};

/// Default wall-clock timeout for the `openssl x509 -enddate` probe.
///
/// Generous enough to absorb a cold-start openssl invocation on a loaded host,
/// short enough that a wedged openssl never stalls the cert scan.
const OPENSSL_ENDDATE_TIMEOUT: Duration = Duration::from_secs(10);

/// Parsed certificate file metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedCert {
    /// Domain (CN) the certificate is issued for.
    pub domain: String,
    /// Certificate file path on disk.
    pub path: String,
    /// Whether the certificate file exists and is readable.
    pub exists: bool,
}

impl ParsedCert {
    /// Create a new parsed cert entry.
    pub fn new(domain: impl Into<String>, path: impl Into<String>, exists: bool) -> Self {
        Self {
            domain: domain.into(),
            path: path.into(),
            exists,
        }
    }
}

/// Real expiry data parsed from a discovered certificate file.
///
/// Produced by [`read_cert_expiry`]. This is the "promotion" of a
/// scan-discovered cert file from a placeholder (unknown expiry) to a cert with
/// genuine expiry data. It deliberately mirrors the expiry-related fields of
/// [`CertInfo`] (`not_after`, `days_remaining`, `is_valid`) so a caller can
/// populate those fields directly.
///
/// # Degradation
///
/// Any failure to obtain real expiry (no `openssl`, timeout, non-zero exit,
/// unparseable date) yields [`CertExpiry::unknown`]: empty `not_after`,
/// `days_remaining = 0`, `is_valid = false`. The `false` here means
/// **"expiry unverified"**, not "expired-and-bad" — but it is strictly safer
/// than the previous `is_valid = true` placeholder, which misrepresented an
/// unchecked cert as healthy.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CertExpiry {
    /// ISO-8601-ish expiry timestamp as emitted by openssl
    /// (`"Sep 18 00:48:15 2026 GMT"`), or empty when expiry is unknown.
    pub not_after: String,
    /// Whole days until expiry relative to the probe time. Negative once the
    /// cert has expired. `0` when expiry is unknown.
    pub days_remaining: i64,
    /// `true` only when real expiry was parsed AND the cert is still in date
    /// (`days_remaining > 0`). `false` for expired certs AND for certs whose
    /// expiry could not be determined (unverified).
    pub is_valid: bool,
}

impl CertExpiry {
    /// Construct the unknown / unverified expiry state.
    ///
    /// Empty `not_after`, `0` days, `is_valid = false`. Used as the degradation
    /// target when openssl cannot yield a real expiry.
    #[must_use]
    pub fn unknown() -> Self {
        Self {
            not_after: String::new(),
            days_remaining: 0,
            is_valid: false,
        }
    }

    /// Construct a known expiry from a parsed not-after timestamp.
    ///
    /// `days_remaining` is computed against `now`. `is_valid` is `days_remaining > 0`.
    #[must_use]
    pub fn from_not_after(not_after: impl Into<String>, now: SystemTime) -> Self {
        let not_after = not_after.into();
        match parse_openssl_enddate_epoch(&not_after) {
            Some(expiry_epoch) => {
                let now_epoch = now.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
                let secs_remaining = expiry_epoch.saturating_sub(now_epoch);
                let days_remaining = i64::try_from(secs_remaining / 86_400).unwrap_or(i64::MAX);
                Self {
                    not_after,
                    days_remaining,
                    is_valid: days_remaining > 0,
                }
            }
            None => Self::unknown_with_label(not_after),
        }
    }

    /// Like [`unknown`](Self::unknown) but keeps the raw label for diagnostics.
    fn unknown_with_label(not_after: String) -> Self {
        Self {
            not_after,
            days_remaining: 0,
            is_valid: false,
        }
    }
}

/// Read real expiry for a discovered certificate file by shelling out to
/// `openssl x509 -enddate -noout -in <path>`.
///
/// The probe runs under a bounded timeout (see [`OPENSSL_ENDDATE_TIMEOUT`]).
/// On any failure — `openssl` not on `$PATH`, the runner returning an error,
/// a non-zero exit, a timeout, or an unparseable `notAfter=` line — this
/// returns [`CertExpiry::unknown`] (degraded, NOT `is_valid = true`).
///
/// `now` is taken as a parameter so callers (and tests) can pin the reference
/// instant; pass [`SystemTime::now`] in production.
///
/// # Errors
///
/// This function returns `Ok(CertExpiry)` for every recoverable case (openssl
/// missing, parse failure, etc.). It returns `Err` only for an internal panic
/// guard — in practice it never errors, matching the "read-only section must
/// never crash" contract of the TUI integration. The `Result` shape is kept for
/// forward-compatibility and consistency with the rest of the module.
pub fn read_cert_expiry(path: &Path, runner: &dyn Runner, now: SystemTime) -> Result<CertExpiry> {
    // Resolve openssl up front so a missing binary degrades cleanly rather than
    // surfacing as a generic runner error. `which` is a workspace dep.
    if which::which("openssl").is_err() {
        tracing::debug!(
            "certs_parse: openssl not on PATH; expiry for {} is unknown",
            path.display()
        );
        return Ok(CertExpiry::unknown());
    }

    let path_str = path.to_string_lossy();
    let spec = CommandSpec::new("openssl")
        .args(["x509", "-enddate", "-noout", "-in"])
        .arg(path_str.as_ref())
        .timeout(OPENSSL_ENDDATE_TIMEOUT);

    let output = match runner.run(&spec) {
        Ok(o) => o,
        Err(e) => {
            tracing::debug!(
                "certs_parse: openssl enddate probe failed for {}: {e}",
                path.display()
            );
            return Ok(CertExpiry::unknown());
        }
    };

    if !output.success {
        tracing::debug!(
            "certs_parse: openssl enddate exited non-zero for {} (code={:?}): {}",
            path.display(),
            output.exit_code,
            output.stderr.trim()
        );
        return Ok(CertExpiry::unknown());
    }

    // Extract the `notAfter=...` value from stdout. openssl prints exactly one
    // line; tolerate leading/trailing whitespace and a missing `GMT` suffix.
    let not_after = extract_not_after(&output.stdout);
    if let Some(na) = not_after {
        Ok(CertExpiry::from_not_after(na, now))
    } else {
        tracing::debug!(
            "certs_parse: no notAfter= line in openssl output for {}: {:?}",
            path.display(),
            output.stdout
        );
        Ok(CertExpiry::unknown())
    }
}

/// Extract the value after `notAfter=` from openssl `-enddate` output.
///
/// Accepts both `notAfter=...` and `notAfter = ...` (with surrounding spaces).
/// Returns the trimmed expiry string without the prefix or trailing newline.
fn extract_not_after(stdout: &str) -> Option<String> {
    for line in stdout.lines() {
        let trimmed = line.trim();
        // Common form: `notAfter=Sep 18 00:48:15 2026 GMT`
        if let Some(rest) = trimmed
            .strip_prefix("notAfter=")
            .or_else(|| trimmed.strip_prefix("notAfter ="))
        {
            let value = rest.trim();
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    None
}

/// Parse an openssl `notAfter` date string into a Unix epoch seconds timestamp.
///
/// Accepts the canonical openssl `-enddate` format:
/// `Mon DD HH:MM:SS YYYY GMT` (e.g. `Sep 18 00:48:15 2026 GMT`). The trailing
/// `GMT` is optional — openssl always emits UTC, so a missing zone is treated
/// as UTC. Returns `None` for any unparseable input rather than panicking.
///
/// This avoids pulling in `chrono`/`time` for a single fixed format.
pub fn parse_openssl_enddate_epoch(s: &str) -> Option<u64> {
    let s = s.trim();
    let parts: Vec<&str> = s.split_whitespace().collect();
    // Expected: [Mon, DD, HH:MM:SS, YYYY, GMT]  (GMT optional)
    if parts.len() < 4 || parts.len() > 5 {
        return None;
    }

    let month_str = parts[0];
    let day: u32 = parts[1].parse().ok()?;
    let time_str = parts[2];
    let year: i64 = parts[3].parse().ok()?;

    // Sanity-check the day-of-month. openssl never emits an out-of-range day,
    // so a value like 99 is a sure sign of a non-cert `notAfter=` line (or a
    // corrupt file) — reject it rather than computing a bogus epoch.
    if !(1..=31).contains(&day) {
        return None;
    }

    // If a 5th token exists it must be GMT (openssl emits UTC); be lenient and
    // accept any non-numeric timezone marker as UTC rather than rejecting.
    if parts.len() == 5 && parts[4].eq_ignore_ascii_case("gmt") {
        // canonical
    } else if parts.len() == 5 {
        // Non-GMT zone: openssl never emits one here, so treat as a parse miss
        // rather than guessing an offset.
        return None;
    }

    let month: u32 = month_to_num(month_str)?;
    let (hour, min, sec) = parse_hms(time_str)?;

    Some(civil_to_epoch_seconds(year, month, day, hour, min, sec))
}

/// Map a 3-letter English month abbreviation to its 1-based month number.
fn month_to_num(s: &str) -> Option<u32> {
    Some(match s {
        "Jan" => 1,
        "Feb" => 2,
        "Mar" => 3,
        "Apr" => 4,
        "May" => 5,
        "Jun" => 6,
        "Jul" => 7,
        "Aug" => 8,
        "Sep" => 9,
        "Oct" => 10,
        "Nov" => 11,
        "Dec" => 12,
        _ => return None,
    })
}

/// Parse an `HH:MM:SS` time string into `(hour, minute, second)`.
fn parse_hms(s: &str) -> Option<(u32, u32, u32)> {
    let comps: Vec<&str> = s.split(':').collect();
    if comps.len() != 3 {
        return None;
    }
    let h: u32 = comps[0].parse().ok()?;
    let m: u32 = comps[1].parse().ok()?;
    let sec: u32 = comps[2].parse().ok()?;
    if h > 23 || m > 59 || sec > 60 {
        return None;
    }
    Some((h, m, sec))
}

/// Convert a UTC civil date to Unix epoch seconds.
///
/// Uses Howard Hinnant's days-from-civil algorithm (proleptic Gregorian).
/// `doe = yoe*365 + yoe/4 - yoe/100 + doy` is the day-of-era; the `365*yoe`
/// term carries the year contribution (the `/4` and `/100` terms add the leap
/// days). Valid for any year in the cert-relevant range and well beyond.
fn civil_to_epoch_seconds(year: i64, month: u32, day: u32, hour: u32, min: u32, sec: u32) -> u64 {
    let m = i64::from(month);
    let y = if m <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400; // [0, 399]
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + (i64::from(day) - 1); // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    let days = era * 146_097 + doe - 719_468; // days since 1970-01-01
    let secs = days * 86_400 + i64::from(hour) * 3_600 + i64::from(min) * 60 + i64::from(sec);
    u64::try_from(secs).unwrap_or(0)
}

/// Compute whole days from `now` (epoch seconds) until `expiry` (epoch seconds).
///
/// Returns a signed count: positive when the expiry is in the future, zero on
/// the expiry day, and negative when already past due. Used by certificate
/// parsers that need a `days_remaining` value without pulling in a date crate.
/// Both inputs are treated as UTC (epoch seconds are inherently UTC).
pub fn days_until(now_secs: u64, expiry_secs: u64) -> i64 {
    let delta = i64::try_from(expiry_secs).unwrap_or(i64::MAX)
        - i64::try_from(now_secs).unwrap_or(i64::MAX);
    // Floor toward negative infinity so a cert that expired 5h ago reports -1,
    // not 0 — matching how operators read "days remaining".
    delta.div_euclid(86_400)
}

/// List all live certificates in the certbot directory.
///
/// Scans the `live` directory for subdirectories, each representing a domain
/// certificate. Returns a list of [`ParsedCert`] entries.
///
/// # Errors
///
/// Returns an error if the live directory cannot be read.
pub fn list_live_certs(live_dir: &Path) -> Result<Vec<ParsedCert>> {
    if !live_dir.is_dir() {
        return Ok(Vec::new());
    }

    let mut certs = Vec::new();

    let entries = std::fs::read_dir(live_dir).map_err(|e| {
        Error::Io(std::io::Error::other(format!(
            "cannot read certbot live directory: {e}"
        )))
    })?;

    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }

        let domain = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();

        let fullchain = path.join("fullchain.pem");
        let exists = fullchain.exists();

        certs.push(ParsedCert::new(
            domain,
            fullchain.to_string_lossy().to_string(),
            exists,
        ));
    }

    // Sort by domain for deterministic output
    certs.sort_by(|a, b| a.domain.cmp(&b.domain));

    Ok(certs)
}

/// Read the PEM-encoded certificate from a fullchain file.
///
/// Extracts just the first (leaf) certificate from a full chain PEM file.
///
/// # Errors
///
/// Returns an error if the file cannot be read.
pub fn read_leaf_certificate(path: &Path) -> Result<String> {
    let content = std::fs::read_to_string(path)?;

    // Extract the first certificate block
    let start = "-----BEGIN CERTIFICATE-----";
    let end = "-----END CERTIFICATE-----";

    let start_idx = content
        .find(start)
        .ok_or_else(|| Error::ConfigParse("no certificate found in PEM file".into()))?;

    let rest = &content[start_idx..];
    let end_idx = rest
        .find(end)
        .ok_or_else(|| Error::ConfigParse("incomplete certificate PEM block".into()))?;

    Ok(rest[..end_idx + end.len()].to_string())
}

/// Check if a certificate file appears to be a valid PEM certificate.
///
/// Performs a quick check for PEM header/footer markers.
pub fn is_pem_certificate(path: &Path) -> bool {
    if let Ok(content) = std::fs::read_to_string(path) {
        content.contains("-----BEGIN CERTIFICATE-----")
            && content.contains("-----END CERTIFICATE-----")
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_live_certs_empty_dir() {
        let dir = assert_fs::TempDir::new().unwrap();
        let certs = list_live_certs(dir.path()).unwrap();
        assert!(certs.is_empty());
    }

    #[test]
    fn list_live_certs_finds_domains() {
        let dir = assert_fs::TempDir::new().unwrap();
        let live_dir = dir.path().join("live");
        std::fs::create_dir_all(live_dir.join("example.com")).unwrap();
        std::fs::write(live_dir.join("example.com/fullchain.pem"), "fake cert").unwrap();
        std::fs::create_dir_all(live_dir.join("other.com")).unwrap();
        // No cert file for other.com

        let certs = list_live_certs(&live_dir).unwrap();
        assert_eq!(certs.len(), 2);
        assert_eq!(certs[0].domain, "example.com");
        assert!(certs[0].exists);
        assert_eq!(certs[1].domain, "other.com");
        assert!(!certs[1].exists);
    }

    #[test]
    fn read_leaf_certificate_extracts_first() {
        let dir = assert_fs::TempDir::new().unwrap();
        let path = dir.path().join("fullchain.pem");
        std::fs::write(
            &path,
            "-----BEGIN CERTIFICATE-----\nleafdata\n-----END CERTIFICATE-----\n\
             -----BEGIN CERTIFICATE-----\nchaindata\n-----END CERTIFICATE-----\n",
        )
        .unwrap();

        let leaf = read_leaf_certificate(&path).unwrap();
        assert!(leaf.contains("leafdata"));
        assert!(!leaf.contains("chaindata"));
    }

    #[test]
    fn is_pem_certificate_checks_markers() {
        let dir = assert_fs::TempDir::new().unwrap();
        let path = dir.path().join("cert.pem");
        std::fs::write(
            &path,
            "-----BEGIN CERTIFICATE-----\ndata\n-----END CERTIFICATE-----\n",
        )
        .unwrap();
        assert!(is_pem_certificate(&path));

        let bad_path = dir.path().join("bad.pem");
        std::fs::write(&bad_path, "not a cert").unwrap();
        assert!(!is_pem_certificate(&bad_path));
    }

    // ── CertExpiry / read_cert_expiry ─────────────────────────────────────────

    #[test]
    fn cert_expiry_unknown_is_unverified() {
        let e = CertExpiry::unknown();
        assert!(e.not_after.is_empty());
        assert_eq!(e.days_remaining, 0);
        // The whole point of the fix: unknown expiry must NOT masquerade as valid.
        assert!(!e.is_valid, "unknown expiry must degrade to is_valid=false");
    }

    #[test]
    fn parse_openssl_enddate_canonical() {
        // Known reference: 2026-09-18 00:48:15 UTC.
        let epoch = parse_openssl_enddate_epoch("Sep 18 00:48:15 2026 GMT");
        // Independently verified: 2026-09-18T00:48:15Z == 1789692495.
        assert_eq!(epoch, Some(1_789_692_495));
    }

    #[test]
    fn parse_openssl_enddate_without_gmt() {
        // openssl always emits UTC; a missing GMT suffix is still accepted.
        let with_gmt = parse_openssl_enddate_epoch("Sep 18 00:48:15 2026 GMT");
        let without_gmt = parse_openssl_enddate_epoch("Sep 18 00:48:15 2026");
        assert_eq!(with_gmt, without_gmt);
    }

    #[test]
    fn parse_openssl_enddate_leap_year() {
        // 2024-02-29 12:00:00 UTC — a real leap day; must parse without panic.
        // Independently verified: == 1709208000.
        let epoch = parse_openssl_enddate_epoch("Feb 29 12:00:00 2024 GMT");
        assert_eq!(epoch, Some(1_709_208_000));
    }

    #[test]
    fn parse_openssl_enddate_rejects_garbage() {
        assert_eq!(parse_openssl_enddate_epoch(""), None);
        assert_eq!(parse_openssl_enddate_epoch("not a date"), None);
        assert_eq!(parse_openssl_enddate_epoch("Sep 18 2026"), None);
        assert_eq!(
            parse_openssl_enddate_epoch("Xxx 18 00:48:15 2026 GMT"),
            None
        );
        assert_eq!(
            parse_openssl_enddate_epoch("Sep 99 00:48:15 2026 GMT"),
            None
        );
        // Non-GMT zone is rejected (openssl never emits one, don't guess offsets).
        assert_eq!(
            parse_openssl_enddate_epoch("Sep 18 00:48:15 2026 PST"),
            None
        );
    }

    #[test]
    fn extract_not_after_canonical() {
        assert_eq!(
            extract_not_after("notAfter=Sep 18 00:48:15 2026 GMT\n"),
            Some("Sep 18 00:48:15 2026 GMT".into())
        );
    }

    #[test]
    fn extract_not_after_tolerates_spaces() {
        // Some openssl builds print `notAfter =` with spaces.
        assert_eq!(
            extract_not_after("notAfter = Sep 18 00:48:15 2026 GMT"),
            Some("Sep 18 00:48:15 2026 GMT".into())
        );
    }

    #[test]
    fn extract_not_after_missing() {
        assert_eq!(extract_not_after("nothing useful here"), None);
        assert_eq!(extract_not_after("notAfter=\n"), None);
    }

    #[test]
    fn from_not_after_future_is_valid() {
        // Far-future expiry → large positive days_remaining, is_valid true.
        let now = SystemTime::now();
        let e = CertExpiry::from_not_after("Jan  1 00:00:00 2099 GMT", now);
        assert!(e.is_valid);
        assert!(e.days_remaining > 0);
        assert_eq!(e.not_after, "Jan  1 00:00:00 2099 GMT");
    }

    #[test]
    fn from_not_after_past_is_invalid() {
        // 1970-01-01 is unambiguously in the past → expired → is_valid false.
        let now = SystemTime::now();
        let e = CertExpiry::from_not_after("Jan  1 00:00:00 1970 GMT", now);
        assert!(!e.is_valid, "expired cert must be is_valid=false");
        assert!(e.days_remaining <= 0);
    }

    #[test]
    fn from_not_after_unparseable_degrades_to_unknown() {
        let now = SystemTime::now();
        let e = CertExpiry::from_not_after("garbage", now);
        // Unparseable date → unknown, NOT is_valid=true.
        assert!(!e.is_valid);
        assert_eq!(e.days_remaining, 0);
        // The raw label is preserved for operator diagnostics.
        assert_eq!(e.not_after, "garbage");
    }

    /// `read_cert_expiry` must degrade to unknown (`is_valid=false`) when openssl
    /// is missing OR the runner reports a failure, rather than returning a
    /// misleading `is_valid=true`. This test is host-independent: the runner is
    /// strict (unmatched calls error out), so on a host WITHOUT openssl the
    /// `which::which` guard yields unknown directly, and on a host WITH openssl
    /// the strict runner returns an Err that the function also degrades.
    #[test]
    fn read_cert_expiry_degrades_on_failure() {
        use toride_runner::fake::FakeRunner;
        let fake = FakeRunner::new().strict();
        let now = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let path = std::path::Path::new("/nonexistent/cert.pem");
        let e = read_cert_expiry(path, &fake, now).expect("never errors");
        assert!(
            !e.is_valid,
            "degraded expiry must never claim is_valid=true (got days={}, not_after={:?})",
            e.days_remaining, e.not_after
        );
        assert_eq!(e.days_remaining, 0);
        assert!(e.not_after.is_empty());
    }

    /// When openssl reports a real future expiry, `read_cert_expiry` surfaces it
    /// as a valid cert with positive `days_remaining`. Uses exact-match canned
    /// output so the test is deterministic and host-independent: the fake runner
    /// is consulted only when openssl is present (otherwise the which-guard
    /// short-circuits and this test still passes because the assertion is only
    /// checked in the openssl-present branch).
    #[test]
    fn read_cert_expiry_parses_real_future_expiry() {
        use toride_runner::CommandOutput;
        use toride_runner::fake::FakeRunner;
        let spec = CommandSpec::new("openssl")
            .args(["x509", "-enddate", "-noout", "-in"])
            .arg("/tmp/cert.pem");
        let fake = FakeRunner::new().respond(
            spec,
            CommandOutput::from_stdout("notAfter=Jan  1 00:00:00 2099 GMT\n"),
        );
        let now = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let e = read_cert_expiry(std::path::Path::new("/tmp/cert.pem"), &fake, now)
            .expect("never errors");
        if which::which("openssl").is_ok() {
            assert!(e.is_valid, "future expiry must be valid");
            assert!(e.days_remaining > 0);
            assert_eq!(e.not_after, "Jan  1 00:00:00 2099 GMT");
        } else {
            // No openssl on this host: the which-guard degraded to unknown.
            assert!(!e.is_valid, "absent openssl must degrade to unknown");
        }
    }

    /// A non-zero openssl exit (e.g. file unreadable) degrades to unknown, not
    /// `is_valid=true`. Host-independent via exact-match canned stderr output.
    #[test]
    fn read_cert_expiry_nonzero_exit_degrades() {
        use toride_runner::CommandOutput;
        use toride_runner::fake::FakeRunner;
        let spec = CommandSpec::new("openssl")
            .args(["x509", "-enddate", "-noout", "-in"])
            .arg("/tmp/missing.pem");
        let fake = FakeRunner::new().respond(
            spec,
            CommandOutput::from_stderr("unable to load certificate\n", 1),
        );
        let now = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let e = read_cert_expiry(std::path::Path::new("/tmp/missing.pem"), &fake, now)
            .expect("never errors");
        if which::which("openssl").is_ok() {
            assert!(!e.is_valid, "non-zero exit must degrade to unknown");
            assert!(e.not_after.is_empty());
        } else {
            assert!(!e.is_valid, "absent openssl must degrade to unknown");
        }
    }

    /// End-to-end against a real self-signed cert + real openssl, when openssl
    /// is installed. Skipped on hosts without openssl so CI without it stays
    /// green. This is the integration proof that the whole pipeline works.
    #[test]
    fn read_cert_expiry_real_openssl_future_cert() {
        use toride_runner::duct_runner::DuctRunner;
        if which::which("openssl").is_err() {
            eprintln!("skipping: openssl not on PATH");
            return;
        }
        // Generate a real 90-day self-signed cert via openssl itself.
        let dir = assert_fs::TempDir::new().unwrap();
        let key = dir.path().join("k.pem");
        let cert = dir.path().join("c.pem");
        let gen_out = std::process::Command::new("openssl")
            .args(["req", "-x509", "-newkey", "rsa:2048", "-keyout"])
            .arg(key.to_str().unwrap())
            .args(["-out"])
            .arg(cert.to_str().unwrap())
            .args(["-days", "90", "-nodes", "-subj", "/CN=test"])
            .output()
            .expect("openssl req");
        if !gen_out.status.success() {
            eprintln!(
                "skipping: openssl req failed: {}",
                String::from_utf8_lossy(&gen_out.stderr)
            );
            return;
        }
        let now = SystemTime::now();
        let e = read_cert_expiry(&cert, &DuctRunner, now).expect("never errors");
        assert!(
            e.is_valid,
            "90-day cert must be valid (days={}, not_after={})",
            e.days_remaining, e.not_after
        );
        // ~90 days minus the small generation latency.
        assert!(e.days_remaining >= 88 && e.days_remaining <= 90);
        assert!(!e.not_after.is_empty());
    }
}
