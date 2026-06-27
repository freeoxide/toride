//! Certificate renewal utilities.
//!
//! Provides helper functions for certificate renewal scheduling, expiry
//! checking, and renewal workflow management.

use crate::report::CertInfo;

/// Default number of days before expiry to trigger renewal.
pub const DEFAULT_RENEWAL_THRESHOLD_DAYS: i64 = 30;

/// Certificate renewal check result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RenewalAction {
    /// Certificate is fine, no action needed.
    NoActionNeeded {
        /// Days until expiry.
        days_remaining: i64,
    },
    /// Certificate should be renewed soon.
    RenewalDue {
        /// Days until expiry.
        days_remaining: i64,
    },
    /// Certificate has expired and needs immediate renewal.
    Expired {
        /// Days since expiry (negative).
        days_remaining: i64,
    },
}

impl RenewalAction {
    /// Determine the renewal action for a certificate.
    pub fn from_cert_info(cert: &CertInfo) -> Self {
        Self::from_days_remaining(cert.days_remaining)
    }

    /// Determine the renewal action from days remaining.
    pub fn from_days_remaining(days_remaining: i64) -> Self {
        if days_remaining <= 0 {
            Self::Expired { days_remaining }
        } else if days_remaining <= DEFAULT_RENEWAL_THRESHOLD_DAYS {
            Self::RenewalDue { days_remaining }
        } else {
            Self::NoActionNeeded { days_remaining }
        }
    }

    /// Returns `true` if the certificate needs renewal (expired or due).
    pub fn needs_renewal(&self) -> bool {
        !matches!(self, Self::NoActionNeeded { .. })
    }
}

/// Check which certificates from a list need renewal.
///
/// Returns a list of (domain, action) pairs for certificates that
/// require attention.
pub fn check_renewal_status(certs: &[CertInfo]) -> Vec<(&str, RenewalAction)> {
    certs
        .iter()
        .map(|c| (c.domain.as_str(), RenewalAction::from_cert_info(c)))
        .collect()
}

/// Filter certificates that need renewal.
pub fn certs_needing_renewal(certs: &[CertInfo]) -> Vec<&CertInfo> {
    certs
        .iter()
        .filter(|c| RenewalAction::from_cert_info(c).needs_renewal())
        .collect()
}

/// Render a renewal status summary for human-readable output.
pub fn render_renewal_summary(certs: &[CertInfo]) -> String {
    let actions = check_renewal_status(certs);
    let mut lines = Vec::new();

    for (domain, action) in &actions {
        match action {
            RenewalAction::Expired { days_remaining } => {
                lines.push(format!(
                    "EXPIRED: {} (expired {} days ago)",
                    domain,
                    days_remaining.abs()
                ));
            }
            RenewalAction::RenewalDue { days_remaining } => {
                lines.push(format!(
                    "RENEW: {} (expires in {} days)",
                    domain, days_remaining
                ));
            }
            RenewalAction::NoActionNeeded { days_remaining } => {
                lines.push(format!("OK: {} ({} days remaining)", domain, days_remaining));
            }
        }
    }

    if lines.is_empty() {
        lines.push("No certificates found.".into());
    }

    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renewal_action_expired() {
        let action = RenewalAction::from_days_remaining(-10);
        assert!(action.needs_renewal());
        assert!(matches!(action, RenewalAction::Expired { days_remaining: -10 }));
    }

    #[test]
    fn renewal_action_due() {
        let action = RenewalAction::from_days_remaining(15);
        assert!(action.needs_renewal());
        assert!(matches!(action, RenewalAction::RenewalDue { days_remaining: 15 }));
    }

    #[test]
    fn renewal_action_ok() {
        let action = RenewalAction::from_days_remaining(60);
        assert!(!action.needs_renewal());
        assert!(matches!(action, RenewalAction::NoActionNeeded { days_remaining: 60 }));
    }

    #[test]
    fn certs_needing_renewal_filters() {
        let certs = vec![
            CertInfo::new("expired.com", "LE", "", "", -5),
            CertInfo::new("due.com", "LE", "", "", 20),
            CertInfo::new("ok.com", "LE", "", "", 60),
        ];

        let need = certs_needing_renewal(&certs);
        assert_eq!(need.len(), 2);
        assert_eq!(need[0].domain, "expired.com");
        assert_eq!(need[1].domain, "due.com");
    }

    #[test]
    fn render_renewal_summary_format() {
        let certs = vec![
            CertInfo::new("a.com", "LE", "", "", 60),
            CertInfo::new("b.com", "LE", "", "", 10),
        ];
        let summary = render_renewal_summary(&certs);
        assert!(summary.contains("OK: a.com"));
        assert!(summary.contains("RENEW: b.com"));
    }
}
