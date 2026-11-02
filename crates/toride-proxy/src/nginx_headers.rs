//! Security header templates for Nginx.
//!
//! Provides pre-built security header configurations including HSTS, CSP,
//! X-Frame-Options, and other common security headers. Always compiled
//! (not feature-gated) so header rendering is available without the `nginx`
//! feature.

/// Pre-built security header profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityHeaders {
    /// HSTS max-age in seconds (0 to disable).
    pub hsts_max_age: u64,
    /// Whether to include subdomains in HSTS.
    pub hsts_include_subdomains: bool,
    /// Whether to enable HSTS preload.
    pub hsts_preload: bool,
    /// X-Frame-Options value.
    pub x_frame_options: XFrameOptions,
    /// X-Content-Type-Options value.
    pub x_content_type_options: ContentTypeOptions,
    /// Referrer-Policy value.
    pub referrer_policy: ReferrerPolicy,
    /// Content-Security-Policy value (empty string to omit).
    pub content_security_policy: String,
    /// Permissions-Policy value (empty string to omit).
    pub permissions_policy: String,
}

/// X-Frame-Options header values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XFrameOptions {
    /// `DENY` -- page cannot be framed at all.
    Deny,
    /// `SAMEORIGIN` -- page can only be framed by same-origin pages.
    SameOrigin,
    /// Do not send X-Frame-Options header.
    None,
}

impl std::fmt::Display for XFrameOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Deny => write!(f, "DENY"),
            Self::SameOrigin => write!(f, "SAMEORIGIN"),
            Self::None => write!(f, ""),
        }
    }
}

/// X-Content-Type-Options header values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentTypeOptions {
    /// `nosniff` -- prevent MIME type sniffing.
    NoSniff,
    /// Do not send X-Content-Type-Options header.
    None,
}

impl std::fmt::Display for ContentTypeOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoSniff => write!(f, "nosniff"),
            Self::None => write!(f, ""),
        }
    }
}

/// Referrer-Policy header values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReferrerPolicy {
    /// `no-referrer`
    NoReferrer,
    /// `no-referrer-when-downgrade`
    NoReferrerWhenDowngrade,
    /// `strict-origin`
    StrictOrigin,
    /// `strict-origin-when-cross-origin` (recommended default).
    StrictOriginWhenCrossOrigin,
    /// `same-origin`
    SameOrigin,
}

impl std::fmt::Display for ReferrerPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoReferrer => write!(f, "no-referrer"),
            Self::NoReferrerWhenDowngrade => write!(f, "no-referrer-when-downgrade"),
            Self::StrictOrigin => write!(f, "strict-origin"),
            Self::StrictOriginWhenCrossOrigin => write!(f, "strict-origin-when-cross-origin"),
            Self::SameOrigin => write!(f, "same-origin"),
        }
    }
}

impl Default for SecurityHeaders {
    fn default() -> Self {
        Self {
            hsts_max_age: 31_536_000, // 1 year
            hsts_include_subdomains: true,
            hsts_preload: false,
            x_frame_options: XFrameOptions::SameOrigin,
            x_content_type_options: ContentTypeOptions::NoSniff,
            referrer_policy: ReferrerPolicy::StrictOriginWhenCrossOrigin,
            content_security_policy: String::new(),
            permissions_policy: String::new(),
        }
    }
}

impl SecurityHeaders {
    /// Create a strict security headers profile.
    pub fn strict() -> Self {
        Self {
            hsts_max_age: 63_072_000, // 2 years
            hsts_include_subdomains: true,
            hsts_preload: true,
            x_frame_options: XFrameOptions::Deny,
            x_content_type_options: ContentTypeOptions::NoSniff,
            referrer_policy: ReferrerPolicy::NoReferrer,
            content_security_policy: "default-src 'self'".into(),
            permissions_policy: "camera=(), microphone=(), geolocation=()".into(),
        }
    }

    /// Create a moderate security headers profile.
    pub fn moderate() -> Self {
        Self::default()
    }

    /// Create a minimal security headers profile (HSTS only).
    pub fn minimal() -> Self {
        Self {
            hsts_max_age: 31_536_000,
            hsts_include_subdomains: false,
            hsts_preload: false,
            x_frame_options: XFrameOptions::None,
            x_content_type_options: ContentTypeOptions::None,
            referrer_policy: ReferrerPolicy::StrictOriginWhenCrossOrigin,
            content_security_policy: String::new(),
            permissions_policy: String::new(),
        }
    }

    /// Set a custom CSP policy.
    pub fn with_csp(mut self, policy: impl Into<String>) -> Self {
        self.content_security_policy = policy.into();
        self
    }

    /// Set a custom Permissions-Policy.
    pub fn with_permissions_policy(mut self, policy: impl Into<String>) -> Self {
        self.permissions_policy = policy.into();
        self
    }

    /// Render the headers as Nginx `add_header` directives.
    pub fn to_nginx_directives(&self) -> String {
        let mut lines = Vec::new();

        // HSTS
        if self.hsts_max_age > 0 {
            let mut hsts = format!("max-age={}", self.hsts_max_age);
            if self.hsts_include_subdomains {
                hsts.push_str("; includeSubDomains");
            }
            if self.hsts_preload {
                hsts.push_str("; preload");
            }
            lines.push(format!(
                "add_header Strict-Transport-Security \"{hsts}\" always;"
            ));
        }

        // X-Frame-Options
        if self.x_frame_options != XFrameOptions::None {
            lines.push(format!(
                "add_header X-Frame-Options \"{}\" always;",
                self.x_frame_options
            ));
        }

        // X-Content-Type-Options
        if self.x_content_type_options != ContentTypeOptions::None {
            lines.push(format!(
                "add_header X-Content-Type-Options \"{}\" always;",
                self.x_content_type_options
            ));
        }

        // X-XSS-Protection (legacy, but still commonly included)
        lines.push("add_header X-XSS-Protection \"1; mode=block\" always;".into());

        // Referrer-Policy
        lines.push(format!(
            "add_header Referrer-Policy \"{}\" always;",
            self.referrer_policy
        ));

        // Content-Security-Policy
        if !self.content_security_policy.is_empty() {
            lines.push(format!(
                "add_header Content-Security-Policy \"{}\" always;",
                self.content_security_policy
            ));
        }

        // Permissions-Policy
        if !self.permissions_policy.is_empty() {
            lines.push(format!(
                "add_header Permissions-Policy \"{}\" always;",
                self.permissions_policy
            ));
        }

        lines.join("\n")
    }

    /// Render the same header set as Caddy `header` directives, mirroring
    /// [`SecurityHeaders::to_nginx_directives`] header for header so both
    /// backends ship one policy.
    pub fn to_caddyfile_directives(&self) -> String {
        let mut lines = Vec::new();

        if self.hsts_max_age > 0 {
            let mut hsts = format!("max-age={}", self.hsts_max_age);
            if self.hsts_include_subdomains {
                hsts.push_str("; includeSubDomains");
            }
            if self.hsts_preload {
                hsts.push_str("; preload");
            }
            lines.push(format!("header Strict-Transport-Security \"{hsts}\""));
        }

        if self.x_frame_options != XFrameOptions::None {
            lines.push(format!(
                "header X-Frame-Options \"{}\"",
                self.x_frame_options
            ));
        }

        if self.x_content_type_options != ContentTypeOptions::None {
            lines.push(format!(
                "header X-Content-Type-Options \"{}\"",
                self.x_content_type_options
            ));
        }

        lines.push("header X-XSS-Protection \"1; mode=block\"".into());

        lines.push(format!(
            "header Referrer-Policy \"{}\"",
            self.referrer_policy
        ));

        if !self.content_security_policy.is_empty() {
            lines.push(format!(
                "header Content-Security-Policy \"{}\"",
                self.content_security_policy
            ));
        }

        if !self.permissions_policy.is_empty() {
            lines.push(format!(
                "header Permissions-Policy \"{}\"",
                self.permissions_policy
            ));
        }

        lines.join("\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_headers_include_hsts() {
        let headers = SecurityHeaders::default();
        let directives = headers.to_nginx_directives();
        assert!(directives.contains("Strict-Transport-Security"));
        assert!(directives.contains("max-age=31536000"));
        assert!(directives.contains("includeSubDomains"));
        assert!(directives.contains("X-Frame-Options"));
        assert!(directives.contains("SAMEORIGIN"));
    }

    #[test]
    fn strict_headers_include_all() {
        let headers = SecurityHeaders::strict();
        let directives = headers.to_nginx_directives();
        assert!(directives.contains("preload"));
        assert!(directives.contains("DENY"));
        assert!(directives.contains("Content-Security-Policy"));
        assert!(directives.contains("Permissions-Policy"));
    }

    #[test]
    fn minimal_headers_skip_optional() {
        let headers = SecurityHeaders::minimal();
        let directives = headers.to_nginx_directives();
        assert!(directives.contains("Strict-Transport-Security"));
        assert!(!directives.contains("X-Frame-Options"));
        assert!(!directives.contains("Content-Security-Policy"));
    }

    #[test]
    fn custom_csp() {
        let headers = SecurityHeaders::default().with_csp("default-src 'self'; script-src 'self'");
        let directives = headers.to_nginx_directives();
        assert!(directives.contains("default-src 'self'; script-src 'self'"));
    }
}
