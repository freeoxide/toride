//! Structured report types for proxy operations.
//!
//! [`ProxyReport`] captures the state of proxy configuration, certificate
//! expiry information, and diagnostic findings.

#[cfg(feature = "doctor")]
use crate::doctor::DoctorFinding;
use crate::spec::ServerBlock;

/// Certificate expiry information for a domain.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CertInfo {
    /// Domain name the certificate is issued for.
    pub domain: String,
    /// Issuer of the certificate (e.g. "Let's Encrypt Authority X3").
    pub issuer: String,
    /// ISO 8601 timestamp of when the certificate was issued.
    pub not_before: String,
    /// ISO 8601 timestamp of when the certificate expires.
    pub not_after: String,
    /// Number of days until the certificate expires.
    pub days_remaining: i64,
    /// Whether the certificate is valid (not expired and not yet invalid).
    pub is_valid: bool,
}

impl CertInfo {
    /// Create a new certificate info struct.
    pub fn new(
        domain: impl Into<String>,
        issuer: impl Into<String>,
        not_before: impl Into<String>,
        not_after: impl Into<String>,
        days_remaining: i64,
    ) -> Self {
        Self {
            domain: domain.into(),
            issuer: issuer.into(),
            not_before: not_before.into(),
            not_after: not_after.into(),
            days_remaining,
            is_valid: days_remaining > 0,
        }
    }

    /// Returns `true` if the certificate will expire within the given number of days.
    pub fn expires_within(&self, days: i64) -> bool {
        self.days_remaining >= 0 && self.days_remaining <= days
    }
}

/// Status of a reverse proxy server.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ProxyStatus {
    /// The proxy server is running.
    Running,
    /// The proxy server is stopped.
    Stopped,
    /// The proxy server status could not be determined.
    Unknown(String),
}

impl std::fmt::Display for ProxyStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Running => write!(f, "running"),
            Self::Stopped => write!(f, "stopped"),
            Self::Unknown(reason) => write!(f, "unknown: {reason}"),
        }
    }
}

/// Aggregated report of proxy configuration state.
///
/// Contains the current proxy status, configured server blocks,
/// and certificate expiry information for all TLS-enabled domains.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ProxyReport {
    /// Which proxy backend this report is for (e.g. "nginx", "caddy").
    pub backend: String,
    /// Current status of the proxy server.
    pub status: ProxyStatus,
    /// Configured server blocks.
    pub server_blocks: Vec<ServerBlock>,
    /// Certificate information for TLS-enabled domains.
    pub certificates: Vec<CertInfo>,
    /// Diagnostic findings produced by the doctor. Populated by
    /// [`Doctor::run`](crate::doctor::Doctor::run); empty when no checks
    /// emitted findings.
    #[cfg(feature = "doctor")]
    pub findings: Vec<DoctorFinding>,
}

impl ProxyReport {
    /// Create an empty report for a given backend.
    pub fn new(backend: impl Into<String>) -> Self {
        Self {
            backend: backend.into(),
            status: ProxyStatus::Unknown("not checked".into()),
            server_blocks: Vec::new(),
            certificates: Vec::new(),
            #[cfg(feature = "doctor")]
            findings: Vec::new(),
        }
    }

    /// Returns `true` if any certificate is expired or invalid.
    pub fn has_expired_certs(&self) -> bool {
        self.certificates.iter().any(|c| !c.is_valid)
    }

    /// Returns certificates that will expire within the given number of days.
    pub fn certs_expiring_within(&self, days: i64) -> Vec<&CertInfo> {
        self.certificates
            .iter()
            .filter(|c| c.expires_within(days))
            .collect()
    }

    /// Render the report as a human-readable summary.
    pub fn to_summary(&self) -> String {
        let mut lines = Vec::new();

        lines.push(format!("Proxy: {} ({})", self.backend, self.status));
        lines.push(format!("Server blocks: {}", self.server_blocks.len()));

        if self.certificates.is_empty() {
            lines.push("Certificates: none".into());
        } else {
            lines.push(format!("Certificates: {}", self.certificates.len()));
            for cert in &self.certificates {
                let status = if cert.is_valid { "valid" } else { "EXPIRED" };
                lines.push(format!(
                    "  {} - {} ({} days remaining, {})",
                    cert.domain, cert.issuer, cert.days_remaining, status
                ));
            }
        }

        lines.join("\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cert_info_expires_within() {
        let cert = CertInfo::new(
            "example.com",
            "Let's Encrypt",
            "2024-01-01",
            "2024-04-01",
            30,
        );
        assert!(cert.expires_within(60));
        assert!(cert.expires_within(30));
        assert!(!cert.expires_within(10));
    }

    #[test]
    fn proxy_report_expired_certs() {
        let report = ProxyReport {
            backend: "nginx".into(),
            status: ProxyStatus::Running,
            server_blocks: Vec::new(),
            certificates: vec![
                CertInfo::new("a.com", "LE", "2024-01-01", "2024-04-01", 30),
                CertInfo::new("b.com", "LE", "2023-01-01", "2023-04-01", -365),
            ],
            #[cfg(feature = "doctor")]
            findings: Vec::new(),
        };
        assert!(report.has_expired_certs());
        let expiring = report.certs_expiring_within(60);
        assert_eq!(expiring.len(), 1);
        assert_eq!(expiring[0].domain, "a.com");
    }

    #[test]
    fn proxy_status_display() {
        assert_eq!(ProxyStatus::Running.to_string(), "running");
        assert_eq!(ProxyStatus::Stopped.to_string(), "stopped");
    }
}
