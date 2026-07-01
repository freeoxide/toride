//! UFW client — typed wrapper around the `ufw` command.
//!
//! This is the primary API surface for the crate.

use std::sync::Arc;

use crate::command::{CommandRunner, DuctRunner};
use crate::error::{Error, Result};
use crate::rule;
use crate::spec::{
    Action, AppDefaultPolicy, CommandSpec, DeleteOptions, Direction, DisableOptions, EnableOptions,
    LoggingLevel, Policy, ResetOptions, RouteRuleSpec, RuleSpec, UfwReport, UfwStatus,
};
use crate::status;

/// The main UFW client.
///
/// Create with `Ufw::system()` for real usage, or `Ufw::with_runner()` for tests.
pub struct Ufw {
    runner: Arc<dyn CommandRunner>,
}

impl Ufw {
    /// Create a UFW client using the real system runner.
    pub fn system() -> Self {
        Self {
            runner: Arc::new(DuctRunner::new()),
        }
    }

    /// Create a UFW client with a custom command runner (for testing).
    pub fn with_runner(runner: impl CommandRunner + 'static) -> Self {
        Self {
            runner: Arc::new(runner),
        }
    }

    /// Find the UFW binary path.
    pub fn find_ufw(&self) -> Result<String> {
        if self.runner.binary_exists("ufw") {
            Ok(which::which("ufw")
                .map_or_else(|_| "ufw".into(), |p| p.to_string_lossy().into_owned()))
        } else {
            Err(Error::UfwNotFound("ufw binary not found on system".into()))
        }
    }

    /// Get UFW version.
    pub fn version(&self) -> Result<String> {
        let result = self.run_ufw(&["--version"])?;
        Ok(result.stdout.trim().to_string())
    }

    /// Get UFW status (non-verbose).
    pub fn status(&self) -> Result<UfwStatus> {
        let result = self.run_ufw(&["status"])?;
        status::parse_status(&result.stdout)
    }

    /// Get UFW verbose status (includes defaults and logging).
    pub fn status_verbose(&self) -> Result<UfwStatus> {
        let result = self.run_ufw(&["status", "verbose"])?;
        status::parse_status_verbose(&result.stdout)
    }

    /// Get UFW numbered status.
    pub fn status_numbered(&self) -> Result<UfwStatus> {
        let result = self.run_ufw(&["status", "numbered"])?;
        status::parse_status_numbered(&result.stdout)
    }

    /// Show a UFW report.
    pub fn show(&self, report: UfwReport) -> Result<String> {
        let result = self.run_ufw(&["show", &report.to_string()])?;
        Ok(result.stdout)
    }

    /// Enable UFW with safety checks.
    pub fn enable(&self, opts: &EnableOptions) -> Result<()> {
        // Check if UFW is already active
        let current = self.status()?;
        if current.active {
            tracing::info!("UFW is already active");
            return Ok(());
        }

        // SSH lockout check.
        //
        // This safety check runs whenever `require_ssh_allow_rule` is true,
        // independent of `allow_force`. `allow_force` only controls whether we
        // pass `--force` to UFW to skip its interactive confirmation prompt; it
        // must NOT bypass this library's own lockout protection (see force_enable).
        if opts.require_ssh_allow_rule {
            self.check_ssh_lockout(opts)?;
        }

        let args = if opts.allow_force {
            vec!["--force", "enable"]
        } else {
            vec!["enable"]
        };

        let result = self.run_ufw_root(&args)?;
        if !result.stdout.contains("active") && !result.stdout.contains("enabled") {
            // Check stderr for errors
            if !result.stderr.is_empty() {
                return Err(Error::EnableFailed(result.stderr));
            }
        }

        Ok(())
    }

    /// Enable UFW with `--force`, bypassing the interactive prompt.
    ///
    /// This is a convenience wrapper around [`enable`](Self::enable) that sets
    /// `allow_force: true` while still performing the SSH lockout safety check.
    pub fn force_enable(&self) -> Result<()> {
        self.enable(&EnableOptions {
            allow_force: true,
            ..EnableOptions::default()
        })
    }

    /// Disable UFW.
    pub fn disable(&self, opts: &DisableOptions) -> Result<()> {
        if !opts.require_explicit_confirmation {
            return Err(Error::Validation(
                "disable requires explicit confirmation. Set require_explicit_confirmation: true to proceed.".into(),
            ));
        }

        let result = self.run_ufw_root(&["disable"])?;
        if !result.stdout.contains("inactive") && !result.stdout.contains("disabled") {
            if !result.stderr.is_empty() {
                return Err(Error::DisableFailed(result.stderr));
            }
        }

        Ok(())
    }

    /// Reload UFW.
    pub fn reload(&self) -> Result<()> {
        let result = self.run_ufw_root(&["reload"])?;
        if !result.stderr.is_empty() && result.exit_code != Some(0) {
            return Err(Error::ReloadFailed(result.stderr));
        }
        Ok(())
    }

    /// Reset UFW (destructive!).
    ///
    /// If `backup_first` is true, creates a backup of all UFW configuration
    /// before resetting. The backup is stored in a temporary directory.
    pub fn reset(&self, opts: &ResetOptions) -> Result<()> {
        if !opts.force {
            return Err(Error::ResetRequiresForce);
        }

        // Backup before reset if requested
        if opts.backup_first {
            let paths = crate::paths::UfwPaths::default();
            let backup_dir = std::env::temp_dir().join(format!(
                "ufw-kit-backup-{}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_secs())
            ));
            let bundle = crate::backup::create_backup(&paths)
                .map_err(|e| Error::BackupFailed(format!("pre-reset backup: {e}")))?;
            crate::backup::write_backup(&bundle, &backup_dir)
                .map_err(|e| Error::BackupFailed(format!("write pre-reset backup: {e}")))?;
            tracing::info!("Backup created at {}", backup_dir.display());
        }

        let args = if opts.force {
            vec!["--force", "reset"]
        } else {
            vec!["reset"]
        };

        let result = self.run_ufw_root(&args)?;
        if !result.stderr.is_empty() && result.exit_code != Some(0) {
            return Err(Error::ResetFailed(result.stderr));
        }

        Ok(())
    }

    /// Set default policy for a direction.
    ///
    /// When changing the incoming policy to `Deny` or `Reject`, an SSH lockout
    /// safety check is performed first. If no incoming SSH allow rule exists,
    /// the operation is rejected to prevent accidental lockout.
    pub fn set_default_policy(&self, direction: Direction, policy: Policy) -> Result<()> {
        // SSH lockout safety check: if we are about to set incoming to deny/reject,
        // make sure there is an SSH allow rule.
        if direction == Direction::In && matches!(policy, Policy::Deny | Policy::Reject) {
            let check = self.check_ssh_lockout_structured(&[22]);
            if !check.has_incoming_ssh_allow {
                return Err(Error::SshLockoutRisk(
                    "no incoming SSH allow rule found; refusing to set incoming policy to deny/reject \
                     without an SSH rule. Add an allow rule for port 22 first.".into(),
                ));
            }
        }

        let args = rule::render_default_policy_args(direction, policy);
        let args_str: Vec<&str> = args.iter().map(String::as_str).collect();
        let result = self.run_ufw_root(&args_str)?;
        if !result.stderr.is_empty() && result.exit_code != Some(0) {
            return Err(Error::PolicySetFailed(result.stderr));
        }
        Ok(())
    }

    /// Set global logging level.
    pub fn set_logging(&self, level: LoggingLevel) -> Result<()> {
        let args = rule::render_logging_args(level);
        let args_str: Vec<&str> = args.iter().map(String::as_str).collect();
        let result = self.run_ufw_root(&args_str)?;
        if !result.stderr.is_empty() && result.exit_code != Some(0) {
            return Err(Error::LoggingSetFailed(result.stderr));
        }
        Ok(())
    }

    /// Add a firewall rule.
    pub fn add_rule(&self, spec: &RuleSpec) -> Result<()> {
        let args = rule::render_rule_args(spec);
        let args_str: Vec<&str> = args.iter().map(String::as_str).collect();
        let result = self.run_ufw_root(&args_str)?;
        if !result.stderr.is_empty() && result.exit_code != Some(0) {
            return Err(Error::RuleAddFailed(result.stderr));
        }
        Ok(())
    }

    /// Delete a rule by exact match.
    pub fn delete_rule(&self, spec: &RuleSpec) -> Result<()> {
        let args = rule::render_delete_args(spec);
        let args_str: Vec<&str> = args.iter().map(String::as_str).collect();
        let result = self.run_ufw_root(&args_str)?;
        if !result.stderr.is_empty() && result.exit_code != Some(0) {
            return Err(Error::RuleDeleteFailed(result.stderr));
        }
        Ok(())
    }

    /// Delete a rule by number (dangerous — numbers shift).
    pub fn delete_rule_number(&self, number: u32, opts: &DeleteOptions) -> Result<()> {
        if !opts.allow_numbered_delete {
            return Err(Error::Validation(
                "numbered delete requires allow_numbered_delete = true".into(),
            ));
        }
        let args = rule::render_delete_number_args(number, opts);
        let args_str: Vec<&str> = args.iter().map(String::as_str).collect();
        let result = self.run_ufw_root(&args_str)?;
        if !result.stderr.is_empty() && result.exit_code != Some(0) {
            return Err(Error::RuleDeleteFailed(result.stderr));
        }
        Ok(())
    }

    /// Delete all rules matching a comment, from bottom to top.
    ///
    /// Deletes rules whose comment contains the given string, starting from the
    /// highest-numbered rule to avoid index shifting during deletion.
    /// Returns the number of rules deleted.
    pub fn delete_rules_by_comment(&self, comment: &str) -> Result<u32> {
        let status = self.status_numbered()?;

        // Filter rules whose comment contains the search string
        let mut matching: Vec<u32> = status
            .rules
            .iter()
            .filter(|r| r.comment.as_deref().is_some_and(|c| c.contains(comment)))
            .filter_map(|r| r.number)
            .collect();

        // Sort descending (highest first) to avoid number shifting
        matching.sort_by(|a, b| b.cmp(a));

        let delete_opts = DeleteOptions {
            allow_numbered_delete: true,
        };

        let mut deleted = 0u32;
        for num in &matching {
            self.delete_rule_number(*num, &delete_opts)?;
            deleted += 1;
        }

        Ok(deleted)
    }

    /// Insert a rule at a specific position.
    pub fn insert_rule(&self, number: u32, spec: &RuleSpec) -> Result<()> {
        let mut spec = spec.clone();
        spec.position = crate::spec::RulePosition::Insert(number);
        self.add_rule(&spec)
    }

    /// Add a route rule.
    pub fn add_route_rule(&self, spec: &RouteRuleSpec) -> Result<()> {
        let args = rule::render_route_rule_args(spec);
        let args_str: Vec<&str> = args.iter().map(String::as_str).collect();
        let result = self.run_ufw_root(&args_str)?;
        if !result.stderr.is_empty() && result.exit_code != Some(0) {
            return Err(Error::RuleAddFailed(result.stderr));
        }
        Ok(())
    }

    /// Delete a route rule.
    pub fn delete_route_rule(&self, spec: &RouteRuleSpec) -> Result<()> {
        let mut spec = spec.clone();
        spec.delete = true;
        let args = rule::render_route_rule_args(&spec);
        let args_str: Vec<&str> = args.iter().map(String::as_str).collect();
        let result = self.run_ufw_root(&args_str)?;
        if !result.stderr.is_empty() && result.exit_code != Some(0) {
            return Err(Error::RuleDeleteFailed(result.stderr));
        }
        Ok(())
    }

    /// List application profiles.
    pub fn app_list(&self) -> Result<String> {
        let result = self.run_ufw(&["app", "list"])?;
        Ok(result.stdout)
    }

    /// Get info about an application profile.
    pub fn app_info(&self, name: &str) -> Result<String> {
        let result = self.run_ufw(&["app", "info", name])?;
        Ok(result.stdout)
    }

    /// Update an application profile.
    pub fn app_update(&self, name: &str) -> Result<()> {
        let result = self.run_ufw(&["app", "update", name])?;
        if !result.stderr.is_empty() && result.exit_code != Some(0) {
            return Err(Error::AppUpdateFailed(result.stderr));
        }
        Ok(())
    }

    /// Update all application profiles.
    pub fn app_update_all(&self) -> Result<()> {
        let result = self.run_ufw(&["app", "update", "all"])?;
        if !result.stderr.is_empty() && result.exit_code != Some(0) {
            return Err(Error::AppUpdateFailed(result.stderr));
        }
        Ok(())
    }

    /// Set default policy for new application profiles.
    pub fn app_default(&self, policy: AppDefaultPolicy) -> Result<()> {
        let args = rule::render_app_default_args(policy);
        let args_str: Vec<&str> = args.iter().map(String::as_str).collect();
        let result = self.run_ufw_root(&args_str)?;
        if !result.stderr.is_empty() && result.exit_code != Some(0) {
            return Err(Error::PolicySetFailed(result.stderr));
        }
        Ok(())
    }

    // ── Dry-run and apply ────────────────────────────────────────────

    /// Perform a dry-run of a UFW command without actually executing it.
    ///
    /// Returns the dry-run output. If the dry-run indicates an error,
    /// an error is returned.
    pub fn dry_run(&self, args: &[&str]) -> Result<String> {
        let mut dry_args = vec!["--dry-run"];
        dry_args.extend_from_slice(args);
        let result = self.run_ufw_root(&dry_args)?;
        if !result.stderr.is_empty() && result.exit_code != Some(0) {
            return Err(Error::Validation(format!(
                "dry-run failed: {}",
                result.stderr
            )));
        }
        Ok(result.stdout)
    }

    /// Add a rule with dry-run safety check.
    ///
    /// Runs `ufw --dry-run` first, then adds the rule if the dry-run succeeds.
    pub fn apply_rule(&self, spec: &RuleSpec) -> Result<crate::spec::ApplyReport> {
        let args = rule::render_rule_args(spec);
        let args_str: Vec<&str> = args.iter().map(String::as_str).collect();

        // Step 1: Dry-run
        let dry_output = self.dry_run(&args_str)?;

        // Step 2: Execute
        let result = self.run_ufw_root(&args_str)?;
        if !result.stderr.is_empty() && result.exit_code != Some(0) {
            return Err(Error::RuleAddFailed(result.stderr));
        }

        Ok(crate::spec::ApplyReport {
            success: true,
            action: format!("add rule: {}", args.join(" ")),
            dry_run_output: Some(dry_output),
            verification: None,
            warnings: Vec::new(),
        })
    }

    /// Idempotently ensure a rule exists.
    ///
    /// Checks existing rules by comment. If an exact match exists, does nothing.
    /// If a managed comment exists but the rule differs, replaces it.
    /// Otherwise, adds the new rule.
    pub fn ensure_rule(&self, spec: &RuleSpec) -> Result<crate::spec::ApplyReport> {
        let comment = spec.comment.as_deref().unwrap_or("");

        if comment.is_empty() {
            // No comment — just add directly
            return self.apply_rule(spec);
        }

        // Check existing rules
        let status = self.status_numbered()?;
        let existing: Vec<_> = status
            .rules
            .iter()
            .filter(|r| r.comment.as_deref() == Some(comment))
            .collect();

        if existing.is_empty() {
            // No existing rule with this comment — add
            return self.apply_rule(spec);
        }

        // Render the expected args for the new rule. We compare key structural
        // tokens against the existing rule's raw text to detect changes.
        // UFW output format differs from rendered args format, so we check
        // that the essential parts (action, direction, proto, port, addresses)
        // are all consistent.
        let matches = existing.iter().any(|r| rule_matches_spec(r, spec));

        if matches {
            return Ok(crate::spec::ApplyReport {
                success: true,
                action: format!("rule already exists (comment: {comment})"),
                dry_run_output: None,
                verification: None,
                warnings: Vec::new(),
            });
        }

        // Rules with the same comment exist but differ — replace them.
        // Delete old rules from bottom to top (highest number first) to avoid
        // number shifting during deletion.
        let mut numbers: Vec<u32> = existing.iter().filter_map(|r| r.number).collect();
        numbers.sort_by(|a, b| b.cmp(a)); // descending order

        let delete_opts = crate::spec::DeleteOptions {
            allow_numbered_delete: true,
        };

        for num in &numbers {
            self.delete_rule_number(*num, &delete_opts)?;
        }

        // If there were only un-numbered matches, fall back to delete by spec
        if numbers.is_empty() {
            self.delete_rule(spec)?;
        }

        // Add the new rule
        let report = self.apply_rule(spec)?;
        Ok(crate::spec::ApplyReport {
            success: true,
            action: format!("replaced rule (comment: {comment}): {}", report.action),
            dry_run_output: report.dry_run_output,
            verification: report.verification,
            warnings: report.warnings,
        })
    }

    // ── Runner access ────────────────────────────────────────────────

    /// Get a reference to the underlying command runner.
    ///
    /// This is useful for doctor checks and other diagnostics that need
    /// to query binary existence or service status directly.
    pub fn runner(&self) -> &dyn CommandRunner {
        self.runner.as_ref()
    }

    // ── Internal helpers ──────────────────────────────────────────────

    /// Run a UFW command (non-root).
    fn run_ufw(&self, args: &[&str]) -> Result<crate::spec::CommandResult> {
        let spec = CommandSpec::ufw(args.iter().map(|s| (*s).to_string()).collect::<Vec<_>>());
        self.runner.run(&spec)
    }

    /// Run a UFW command (root required).
    fn run_ufw_root(&self, args: &[&str]) -> Result<crate::spec::CommandResult> {
        let spec = CommandSpec::ufw_root(args.iter().map(|s| (*s).to_string()).collect::<Vec<_>>());
        self.runner.run(&spec)
    }

    /// Check for SSH lockout risk before enabling.
    fn check_ssh_lockout(&self, opts: &EnableOptions) -> Result<()> {
        for &port in &opts.ssh_ports {
            let result = self.check_ssh_lockout_structured(&[port]);
            if !result.has_incoming_ssh_allow {
                return Err(Error::SshLockoutRisk(format!(
                    "SSH port {port} is not allowed. \
                     Add an allow rule first or pass explicit override."
                )));
            }
        }
        Ok(())
    }

    /// Perform a structured SSH lockout check using parsed rules.
    ///
    /// Instead of searching raw rule text, this checks the structured
    /// `ParsedRule` fields for direction, action, and port.
    ///
    /// A rule is considered an incoming SSH allow if:
    /// - Its direction is `In` (or direction is not specified, which UFW
    ///   treats as inbound for simple rules).
    /// - Its action is `Allow` or `Limit`.
    /// - It targets port 22, port `ssh`, or matches any of the given ports.
    pub fn check_ssh_lockout_structured(&self, ssh_ports: &[u16]) -> crate::spec::SshCheckResult {
        // Silently return a negative result if status cannot be fetched.
        let Ok(status) = self.status() else {
            return crate::spec::SshCheckResult {
                has_incoming_ssh_allow: false,
                matching_rules: Vec::new(),
                interface_scoped: false,
                checked_ports: ssh_ports.to_vec(),
            };
        };

        let mut matching_rules = Vec::new();
        let mut interface_scoped = false;

        for rule in &status.rules {
            // Must be an Allow or Limit action
            let is_allow = matches!(rule.action, Some(Action::Allow | Action::Limit));
            if !is_allow {
                // Fall back to raw text check if action wasn't parsed
                let raw_lower = rule.raw.to_lowercase();
                if !raw_lower.contains("allow") && !raw_lower.contains("limit") {
                    continue;
                }
            }

            // Must be incoming direction. When direction is `None` (not parsed),
            // we check the raw text for explicit "OUT" to avoid false positives.
            // UFW's default for simple rules is inbound, so None without "OUT"
            // in raw text is treated as incoming.
            let is_incoming = match rule.direction {
                Some(Direction::In) => true,
                Some(Direction::Out | Direction::Routed) => false,
                None => {
                    // Not parsed — check raw text for direction markers
                    let raw_lower = rule.raw.to_lowercase();
                    !raw_lower.contains(" out ")
                        && !raw_lower.contains(" out\t")
                        && !raw_lower.contains("out on")
                }
            };
            if !is_incoming {
                continue;
            }

            // Must target SSH port
            let targets_ssh = rule_targets_ssh(rule, ssh_ports);
            if !targets_ssh {
                continue;
            }

            // Check interface scope from raw text (ParsedRule doesn't have an
            // interface field, so we inspect the raw text for "on <iface>" patterns).
            let raw_lower = rule.raw.to_lowercase();
            if raw_lower.contains(" in on ") || raw_lower.contains(" on ") {
                interface_scoped = true;
            }

            matching_rules.push(rule.clone());
        }

        let has_incoming_ssh_allow = !matching_rules.is_empty();

        crate::spec::SshCheckResult {
            has_incoming_ssh_allow,
            matching_rules,
            interface_scoped,
            checked_ports: ssh_ports.to_vec(),
        }
    }
}

/// Check whether a parsed rule targets an SSH port.
///
/// A rule targets SSH if its raw text contains any of the specified port numbers,
/// the string "ssh", or "22/tcp"/"22" patterns.
fn rule_targets_ssh(rule: &crate::spec::ParsedRule, ssh_ports: &[u16]) -> bool {
    let raw_lower = rule.raw.to_lowercase();

    // Check for the "ssh" service name
    if raw_lower.contains("ssh") {
        return true;
    }

    // Check for each specified port number
    for &port in ssh_ports {
        // Exact port patterns: "22/tcp", "22/udp", "22 " (with space after),
        // or "22" at end of a token boundary. We check common variants.
        if raw_lower.contains(&format!("{port}/tcp")) || raw_lower.contains(&format!("{port}/udp"))
        {
            return true;
        }

        // Check for bare port number with word boundaries. The port typically
        // appears at the start of the rule line in "To" column, e.g. "22   ALLOW IN".
        // We look for the port number followed by whitespace or at end of line.
        for token in raw_lower.split_whitespace() {
            if token == port.to_string() {
                return true;
            }
            // Also handle "22/tcp", "22/udp" (already checked above, but be thorough)
            if let Some(slash_pos) = token.find('/') {
                if token[..slash_pos] == port.to_string() {
                    return true;
                }
            }
        }
    }

    false
}

/// Check whether a parsed rule from `ufw status numbered` matches a `RuleSpec`.
///
/// Compares key structural fields (action, direction, protocol, port, addresses)
/// rather than raw text, because UFW's status output format differs from the
/// argument format we render.
#[allow(clippy::unnested_or_patterns)]
fn rule_matches_spec(parsed: &crate::spec::ParsedRule, spec: &RuleSpec) -> bool {
    use crate::spec::{Address, PortSpec, ProtocolFilter};

    // Action must match. In numbered output the action may appear mid-line
    // (e.g. "443/tcp ALLOW IN ...") so when parsed.action is None we fall
    // back to a substring check on the raw text.
    let action_matches = if let Some(a) = parsed.action {
        a == spec.action
    } else {
        let lower = parsed.raw.to_lowercase();
        lower.contains(&spec.action.to_string())
    };
    if !action_matches {
        return false;
    }

    // Direction must match. Similarly, fall back to raw text when not parsed.
    let dir_matches = match (parsed.direction, spec.direction) {
        (Some(d), Some(sd)) => d == sd,
        (None, None) | (Some(_), None) => true,
        (None, Some(sd)) => {
            let lower = parsed.raw.to_lowercase();
            lower.contains(&sd.to_string())
        }
    };
    if !dir_matches {
        return false;
    }

    // Protocol must match — check that the raw text contains the expected proto
    let proto_matches = match &spec.protocol {
        ProtocolFilter::Any => true, // no proto filter
        ProtocolFilter::Specific(proto) => {
            let lower = parsed.raw.to_lowercase();
            lower.contains(&proto.to_string())
        }
    };
    if !proto_matches {
        return false;
    }

    // Destination port must be present in the raw text
    let port_matches = match &spec.to_port {
        PortSpec::Any => true,
        PortSpec::Single(p) => {
            let lower = parsed.raw.to_lowercase();
            // Check for "NNNN/tcp" or "NNNN/udp" or bare "NNNN"
            lower.contains(&format!("{p}/tcp"))
                || lower.contains(&format!("{p}/udp"))
                || lower.contains(&format!("{p}"))
        }
        PortSpec::Range { start, end } => {
            let lower = parsed.raw.to_lowercase();
            lower.contains(&format!("{start}:{end}"))
        }
        PortSpec::List(ports) => {
            let lower = parsed.raw.to_lowercase();
            ports.iter().all(|p| lower.contains(&p.to_string()))
        }
        PortSpec::ServiceName(name) => {
            let lower = parsed.raw.to_lowercase();
            lower.contains(&name.to_lowercase())
        }
    };
    if !port_matches {
        return false;
    }

    // Source address check — if spec specifies a non-any source, it should appear
    let from_matches = match &spec.from_addr {
        Address::Any => true,
        addr => {
            let lower = parsed.raw.to_lowercase();
            lower.contains(&addr.to_string().to_lowercase())
        }
    };
    if !from_matches {
        return false;
    }

    // Destination address check
    let to_matches = match &spec.to_addr {
        Address::Any => true,
        addr => {
            let lower = parsed.raw.to_lowercase();
            lower.contains(&addr.to_string().to_lowercase())
        }
    };
    if !to_matches {
        return false;
    }

    true
}

#[cfg(test)]
#[path = "client.test.rs"]
mod tests;
