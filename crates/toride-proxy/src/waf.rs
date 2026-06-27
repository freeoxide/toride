//! Web Application Firewall (WAF) rule engine.
//!
//! This module provides a self-contained rule engine that evaluates incoming
//! HTTP requests against a set of signature rules and decides whether to allow,
//! log, or block them. The engine is pure-Rust and dependency-light (a single
//! `regex` for signature matching); it does NOT shell out and does not require
//! ModSecurity to be installed.
//!
//! # Design
//!
//! - [`WafRule`] carries a compiled regex pattern and a [`WafRuleType`]
//!   classification. Rules are matched against the request path, query string,
//!   selected headers, and the request body.
//! - [`WafEngine`] owns a [`WafConfig`] and performs the evaluation, returning
//!   a [`WafDecision`] (Allow / Log / Block) plus the list of [`WafMatch`]es
//!   that triggered it.
//! - In [`WafMode::Detection`] the engine records matches but never blocks
//!   (shadow mode). In [`WafMode::Prevention`] it blocks on the first match
//!   whose severity meets the configured threshold.
//!
//! The default rule set ([`WafConfig::with_default_rules`]) ships OWASP-style
//! signatures for SQL injection, cross-site scripting, path traversal, and a
//! few common protocol attacks. These are conservative signatures, not a
//! substitute for a full CRS — but they make the engine do real work rather
//! than being a type-only stub.

use crate::error::{Error, Result};
use regex::Regex;
use std::collections::HashSet;

/// WAF rule severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum WafSeverity {
    /// Debug -- debugging information. The `Default` (lowest) severity so the
    /// derive never silently escalates an uninitialized value to a block.
    #[default]
    Debug,
    /// Notice -- informational.
    Notice,
    /// Warning -- low-severity threats.
    Warning,
    /// Error -- moderate threats.
    Error,
    /// Critical -- significant threats.
    Critical,
    /// Alert -- high-severity threats.
    Alert,
    /// Emergency -- critical threats.
    Emergency,
}

/// The category of attack a rule detects. Used to group matches in the
/// decision and to render human-readable rule descriptions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WafRuleType {
    /// SQL injection (e.g. `OR 1=1`, `UNION SELECT`).
    SqlInjection,
    /// Cross-site scripting (reflected/stored).
    Xss,
    /// Path traversal (`../`, `..\\`).
    PathTraversal,
    /// Remote/local file inclusion.
    Lfi,
    /// Server-side request forgery indicators.
    Ssrf,
    /// Generic protocol anomaly or malformed input.
    ProtocolAnomaly,
    /// A user-defined custom signature.
    Custom,
}

impl std::fmt::Display for WafRuleType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::SqlInjection => "SQLi",
            Self::Xss => "XSS",
            Self::PathTraversal => "path-traversal",
            Self::Lfi => "LFI",
            Self::Ssrf => "SSRF",
            Self::ProtocolAnomaly => "protocol-anomaly",
            Self::Custom => "custom",
        };
        f.write_str(s)
    }
}

/// A compiled WAF rule.
#[derive(Debug, Clone)]
pub struct WafRule {
    /// Unique rule identifier (e.g. "900001").
    pub id: String,
    /// Rule description.
    pub description: String,
    /// Rule severity.
    pub severity: WafSeverity,
    /// The attack category this rule detects.
    pub rule_type: WafRuleType,
    /// The compiled regex pattern used to match request input.
    pattern: Regex,
    /// Whether the rule is currently enabled.
    pub enabled: bool,
}

impl WafRule {
    /// Create a new WAF rule from a regex pattern string.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Validation`] if the pattern is not a valid regex.
    pub fn new(
        id: impl Into<String>,
        description: impl Into<String>,
        severity: WafSeverity,
        rule_type: WafRuleType,
        pattern: &str,
    ) -> Result<Self> {
        let id = id.into();
        let compiled = Regex::new(pattern).map_err(|e| {
            Error::Validation(format!("invalid WAF rule pattern for {id}: {e}"))
        })?;
        Ok(Self {
            id,
            description: description.into(),
            severity,
            rule_type,
            pattern: compiled,
            enabled: true,
        })
    }

    /// Disable this rule.
    pub fn disabled(mut self) -> Self {
        self.enabled = false;
        self
    }

    /// Test whether this rule's pattern matches anywhere in `input`.
    pub fn is_match(&self, input: &str) -> bool {
        self.pattern.is_match(input)
    }

    /// Return the source pattern string.
    pub fn pattern_str(&self) -> &str {
        self.pattern.as_str()
    }
}

impl PartialEq for WafRule {
    fn eq(&self, other: &Self) -> bool {
        // Two rules are equal iff their identity (id) and signature match.
        // The compiled `Regex` is not `PartialEq`, so compare the source.
        self.id == other.id
            && self.description == other.description
            && self.severity == other.severity
            && self.rule_type == other.rule_type
            && self.pattern.as_str() == other.pattern.as_str()
            && self.enabled == other.enabled
    }
}

impl Eq for WafRule {}

/// WAF operating mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WafMode {
    /// Detection only -- log but don't block.
    #[default]
    Detection,
    /// Prevention -- log and block.
    Prevention,
}

/// WAF configuration.
#[derive(Debug, Clone, Default)]
pub struct WafConfig {
    /// Whether WAF is enabled.
    pub enabled: bool,
    /// WAF mode (detection vs. prevention).
    pub mode: WafMode,
    /// Managed rules.
    pub rules: Vec<WafRule>,
    /// The minimum severity that triggers a block in Prevention mode. Rules
    /// with a severity below this threshold are logged only. Defaults to
    /// [`WafSeverity::Warning`] (block on Warning and above).
    pub block_threshold: WafSeverity,
}

impl WafConfig {
    /// Create a new (empty, disabled) WAF configuration.
    pub fn new() -> Self {
        Self {
            enabled: false,
            mode: WafMode::Detection,
            rules: Vec::new(),
            // By default, any rule at Warning or above blocks in Prevention
            // mode. Info-only rules never block.
            block_threshold: WafSeverity::Warning,
        }
    }

    /// Enable the WAF.
    pub fn enabled(mut self) -> Self {
        self.enabled = true;
        self
    }

    /// Set the WAF mode to prevention.
    pub fn prevention(mut self) -> Self {
        self.mode = WafMode::Prevention;
        self
    }

    /// Set the block threshold (minimum severity to block in Prevention mode).
    pub fn block_threshold(mut self, severity: WafSeverity) -> Self {
        self.block_threshold = severity;
        self
    }

    /// Add a rule.
    pub fn rule(mut self, rule: WafRule) -> Self {
        self.rules.push(rule);
        self
    }

    /// Return enabled rules.
    pub fn enabled_rules(&self) -> Vec<&WafRule> {
        self.rules.iter().filter(|r| r.enabled).collect()
    }

    /// Install the default OWASP-style signature rule set.
    ///
    /// These are conservative signatures covering the most common web attacks.
    /// They are intentionally simple (no CRS-scale tuning) but make the engine
    /// perform real request filtering out of the box. The WAF is left
    /// disabled; callers opt in via [`enabled`](Self::enabled).
    ///
    /// # Errors
    ///
    /// Returns an error only if a built-in pattern fails to compile (a bug).
    pub fn with_default_rules(mut self) -> Result<Self> {
        // SQL injection: boolean tautologies, UNION SELECT, comment markers,
        // and stacked-query separators.
        self.rules.push(WafRule::new(
            "950001",
            "SQL injection: boolean/tautology",
            WafSeverity::Critical,
            WafRuleType::SqlInjection,
            r"(?i)(?:'\s*or\s*'?\d+'?\s*=\s*'?\d+|(?:or|and)\s+\d+\s*=\s*\d+|union\s+select|;\s*drop\s+table|--|/\*)",
        )?);
        // XSS: script tags, javascript: URIs, on* event handlers.
        self.rules.push(WafRule::new(
            "950002",
            "Cross-site scripting",
            WafSeverity::Critical,
            WafRuleType::Xss,
            r"(?i)(?:<\s*script\b|javascript:|on(?:error|load|click|mouseover)\s*=|<\s*img[^>]+src\s*=|<\s*iframe)",
        )?);
        // Path traversal: ../ and ..\ sequences (URL-encoded and raw).
        self.rules.push(WafRule::new(
            "950003",
            "Path traversal",
            WafSeverity::Critical,
            WafRuleType::PathTraversal,
            r"(?i)(?:\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|\.\.%2f|%2e%2e%5c)",
        )?);
        // LFI: attempts to read /etc/passwd or similar via file:// or php wrappers.
        self.rules.push(WafRule::new(
            "950004",
            "Local file inclusion",
            WafSeverity::Critical,
            WafRuleType::Lfi,
            r"(?i)(?:/etc/passwd|/etc/shadow|file://|php://filter|php://input|\.\.[\\/]\.\.[\\/]\.\.)",
        )?);
        // SSRF: internal-IP / localhost targeting in parameters.
        self.rules.push(WafRule::new(
            "950005",
            "Server-side request forgery indicator",
            WafSeverity::Error,
            WafRuleType::Ssrf,
            r"(?i)(?:127\.0\.0\.1|localhost|0\.0\.0\.0|169\.254\.169\.254|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+)",
        )?);
        // Protocol anomaly: null byte / control characters in input.
        self.rules.push(WafRule::new(
            "950006",
            "Protocol anomaly: null byte / control char",
            WafSeverity::Warning,
            WafRuleType::ProtocolAnomaly,
            r"[\x00-\x08\x0b\x0c\x0e-\x1f|%00]",
        )?);
        Ok(self)
    }

    /// Validate the WAF configuration.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Validation`] on duplicate rule IDs.
    pub fn validate(&self) -> Result<()> {
        let mut seen = HashSet::new();
        for rule in &self.rules {
            if !seen.insert(&rule.id) {
                return Err(Error::Validation(format!(
                    "duplicate WAF rule ID: {}",
                    rule.id
                )));
            }
        }
        Ok(())
    }
}

/// A minimal HTTP request snapshot subject to WAF evaluation.
///
/// Only the fields operators typically need to inspect are captured. Headers
/// are lowercased on construction so rules can match case-insensitively
/// without re-normalizing.
#[derive(Debug, Clone, Default)]
pub struct WafRequest {
    /// HTTP method (GET, POST, ...).
    pub method: String,
    /// Request path (without query string).
    pub path: String,
    /// Raw query string.
    pub query: String,
    /// Lowercased `(name, value)` header pairs.
    pub headers: Vec<(String, String)>,
    /// Request body (may be empty).
    pub body: String,
}

impl WafRequest {
    /// Create a new request builder.
    pub fn new(method: impl Into<String>, path: impl Into<String>) -> Self {
        Self {
            method: method.into(),
            path: path.into(),
            query: String::new(),
            headers: Vec::new(),
            body: String::new(),
        }
    }

    /// Set the query string.
    pub fn query(mut self, query: impl Into<String>) -> Self {
        self.query = query.into();
        self
    }

    /// Add a header (name is lowercased).
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers
            .push((name.into().to_ascii_lowercase(), value.into()));
        self
    }

    /// Set the request body.
    pub fn body(mut self, body: impl Into<String>) -> Self {
        self.body = body.into();
        self
    }

    /// Return the inputs that should be scanned: path, query, header values,
    /// and body. The method itself is deliberately NOT scanned.
    fn scanable_inputs(&self) -> Vec<&str> {
        let mut inputs: Vec<&str> = Vec::with_capacity(3 + self.headers.len());
        inputs.push(&self.path);
        if !self.query.is_empty() {
            inputs.push(&self.query);
        }
        for (_, v) in &self.headers {
            inputs.push(v.as_str());
        }
        if !self.body.is_empty() {
            inputs.push(&self.body);
        }
        inputs
    }
}

/// A single rule match against a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WafMatch {
    /// The rule that matched.
    pub rule_id: String,
    /// The attack category.
    pub rule_type: WafRuleType,
    /// The severity of the matching rule.
    pub severity: WafSeverity,
    /// Which part of the request matched (`"path"`, `"query"`, `"header"`,
    /// `"body"`).
    pub field: &'static str,
    /// The (truncated) snippet of input that matched.
    pub snippet: String,
}

/// The engine's verdict for a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WafDecision {
    /// No rule matched; the request is allowed.
    Allow,
    /// One or more rules matched but the engine is in Detection mode (or the
    /// matches were below the block threshold). The request is allowed but
    /// the matches are recorded for logging.
    Log(Vec<WafMatch>),
    /// A rule matched at/above the block threshold in Prevention mode. The
    /// request should be blocked (HTTP 403).
    Block(Vec<WafMatch>),
}

impl WafDecision {
    /// Returns `true` if the decision is `Block`.
    pub fn is_blocked(&self) -> bool {
        matches!(self, Self::Block(_))
    }

    /// Returns `true` if any rule matched (Log or Block).
    pub fn has_matches(&self) -> bool {
        matches!(self, Self::Log(_) | Self::Block(_))
    }

    /// Return the matches, if any.
    pub fn matches(&self) -> &[WafMatch] {
        match self {
            Self::Log(m) | Self::Block(m) => m,
            Self::Allow => &[],
        }
    }
}

/// The WAF rule engine. Owns a [`WafConfig`] and evaluates requests.
#[derive(Debug, Clone)]
pub struct WafEngine {
    config: WafConfig,
}

impl WafEngine {
    /// Create a new engine from a config.
    ///
    /// # Errors
    ///
    /// Returns an error if the config is invalid (duplicate rule IDs).
    pub fn new(config: WafConfig) -> Result<Self> {
        config.validate()?;
        Ok(Self { config })
    }

    /// Return a reference to the engine's config.
    pub fn config(&self) -> &WafConfig {
        &self.config
    }

    /// Evaluate a request against the rule set.
    ///
    /// Disabled rules and a disabled config short-circuit to [`WafDecision::Allow`].
    /// In [`WafMode::Detection`] every match is logged but none block. In
    /// [`WafMode::Prevention`] a match at or above the configured block
    /// threshold produces a `Block` decision.
    pub fn evaluate(&self, request: &WafRequest) -> WafDecision {
        if !self.config.enabled {
            return WafDecision::Allow;
        }

        let inputs = request.scanable_inputs();
        let mut matches: Vec<WafMatch> = Vec::new();

        for rule in self.config.enabled_rules() {
            for (idx, input) in inputs.iter().enumerate() {
                if let Some(m) = rule.pattern.find(input) {
                    let field = field_name(idx, request);
                    let snippet = truncate(&input[m.start()..m.end()], 80);
                    matches.push(WafMatch {
                        rule_id: rule.id.clone(),
                        rule_type: rule.rule_type,
                        severity: rule.severity,
                        field,
                        snippet,
                    });
                    // One match per rule is enough; stop scanning further
                    // inputs for this rule.
                    break;
                }
            }
        }

        if matches.is_empty() {
            return WafDecision::Allow;
        }

        // Decide block vs log based on mode + threshold.
        let should_block = self.config.mode == WafMode::Prevention
            && matches
                .iter()
                .any(|m| m.severity >= self.config.block_threshold);

        if should_block {
            WafDecision::Block(matches)
        } else {
            WafDecision::Log(matches)
        }
    }
}

/// Map a scanable-inputs index to a human-readable field name.
fn field_name(idx: usize, request: &WafRequest) -> &'static str {
    // inputs layout: [path, (query?), (header values...), (body?)]
    if idx == 0 {
        return "path";
    }
    let mut cursor = 1;
    if !request.query.is_empty() {
        if idx == cursor {
            return "query";
        }
        cursor += 1;
    }
    if idx >= cursor && idx < cursor + request.headers.len() {
        return "header";
    }
    "body"
}

/// Truncate a match snippet to `max` chars, appending an ellipsis if cut.
fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max).collect();
    out.push('…');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn engine(mode: WafMode) -> WafEngine {
        let config = WafConfig::new()
            .enabled()
            .with_default_rules()
            .expect("default rules compile");
        let config = if mode == WafMode::Prevention {
            config.prevention()
        } else {
            config
        };
        WafEngine::new(config).expect("valid config")
    }

    #[test]
    fn waf_config_builder() {
        let config = WafConfig::new()
            .enabled()
            .prevention()
            .rule(
                WafRule::new(
                    "900001",
                    "Block SQL injection",
                    WafSeverity::Critical,
                    WafRuleType::SqlInjection,
                    r"(?i)union\s+select",
                )
                .unwrap(),
            )
            .rule(
                WafRule::new(
                    "900002",
                    "Block XSS",
                    WafSeverity::Critical,
                    WafRuleType::Xss,
                    r"(?i)<script",
                )
                .unwrap()
                .disabled(),
            );

        assert!(config.enabled);
        assert_eq!(config.mode, WafMode::Prevention);
        assert_eq!(config.rules.len(), 2);
        assert_eq!(config.enabled_rules().len(), 1);
    }

    #[test]
    fn waf_config_rejects_duplicate_ids() {
        let config = WafConfig::new()
            .rule(
                WafRule::new(
                    "900001",
                    "Rule A",
                    WafSeverity::Critical,
                    WafRuleType::SqlInjection,
                    "a",
                )
                .unwrap(),
            )
            .rule(
                WafRule::new(
                    "900001",
                    "Rule B",
                    WafSeverity::Alert,
                    WafRuleType::SqlInjection,
                    "b",
                )
                .unwrap(),
            );

        assert!(config.validate().is_err());
    }

    #[test]
    fn default_rules_detect_sql_injection() {
        let engine = engine(WafMode::Prevention);
        let req = WafRequest::new("GET", "/login").query("u=admin'+OR+1=1--");
        let decision = engine.evaluate(&req);
        assert!(decision.is_blocked(), "expected block, got {decision:?}");
        let matches = decision.matches();
        assert!(matches.iter().any(|m| m.rule_type == WafRuleType::SqlInjection));
    }

    #[test]
    fn default_rules_detect_xss() {
        let engine = engine(WafMode::Prevention);
        let req = WafRequest::new("GET", "/search").query("q=<script>alert(1)</script>");
        let decision = engine.evaluate(&req);
        assert!(decision.is_blocked());
        assert!(decision
            .matches()
            .iter()
            .any(|m| m.rule_type == WafRuleType::Xss));
    }

    #[test]
    fn default_rules_detect_path_traversal() {
        let engine = engine(WafMode::Prevention);
        let req = WafRequest::new("GET", "/files/../../etc/passwd");
        let decision = engine.evaluate(&req);
        assert!(decision.is_blocked());
    }

    #[test]
    fn detection_mode_logs_but_does_not_block() {
        let engine = engine(WafMode::Detection);
        let req = WafRequest::new("GET", "/").query("id=1'+OR+1=1--");
        let decision = engine.evaluate(&req);
        assert!(!decision.is_blocked());
        assert!(decision.has_matches());
        assert!(matches!(decision, WafDecision::Log(_)));
    }

    #[test]
    fn benign_request_is_allowed() {
        let engine = engine(WafMode::Prevention);
        let req = WafRequest::new("GET", "/index.html").query("page=about");
        let decision = engine.evaluate(&req);
        assert_eq!(decision, WafDecision::Allow);
    }

    #[test]
    fn disabled_config_allows_everything() {
        let config = WafConfig::new().with_default_rules().unwrap(); // enabled=false
        let engine = WafEngine::new(config).unwrap();
        let req = WafRequest::new("GET", "/").query("q=<script>");
        assert_eq!(engine.evaluate(&req), WafDecision::Allow);
    }

    #[test]
    fn body_and_headers_are_scanned() {
        let engine = engine(WafMode::Prevention);
        // XSS in the body.
        let req = WafRequest::new("POST", "/comment")
            .body("text=<script>alert(1)</script>");
        let decision = engine.evaluate(&req);
        assert!(decision.is_blocked());
        assert!(decision.matches().iter().any(|m| m.field == "body"));

        // SSRF indicator in a header (X-Forwarded-Host targeting 169.254.169.254).
        let req = WafRequest::new("GET", "/")
            .header("X-Forwarded-Host", "169.254.169.254");
        let decision = engine.evaluate(&req);
        assert!(decision.is_blocked());
        assert!(decision.matches().iter().any(|m| m.field == "header"));
    }

    #[test]
    fn block_threshold_governs_prevention() {
        // Raise the threshold to Emergency so Warning-severity rules (control
        // chars) log but do not block, even in Prevention mode.
        let config = WafConfig::new()
            .enabled()
            .prevention()
            .block_threshold(WafSeverity::Emergency)
            .with_default_rules()
            .unwrap();
        let engine = WafEngine::new(config).unwrap();
        let req = WafRequest::new("GET", "/").query("x=a%00b");
        let decision = engine.evaluate(&req);
        // null-byte rule is Warning, below Emergency threshold -> Log, not Block.
        assert!(!decision.is_blocked());
        assert!(decision.has_matches());
    }

    #[test]
    fn invalid_regex_is_rejected() {
        let res = WafRule::new(
            "x",
            "bad",
            WafSeverity::Debug,
            WafRuleType::Custom,
            "(unclosed",
        );
        assert!(res.is_err());
    }

    #[test]
    fn match_snippet_is_truncated() {
        let engine = engine(WafMode::Detection);
        // A very long XSS payload to exercise snippet truncation.
        let payload = format!("<script>{}", "A".repeat(200));
        let req = WafRequest::new("GET", "/").query(format!("q={payload}"));
        let decision = engine.evaluate(&req);
        let m = decision.matches().first().expect("match present");
        // Snippet ends with the ellipsis marker when truncated.
        assert!(m.snippet.chars().count() <= 81);
    }
}
