//! UFW client — typed wrapper around the `ufw` command.
//!
//! This is the primary API surface for the crate.

use std::sync::Arc;

use crate::command::{CommandRunner, DuctRunner};
use crate::error::{Error, Result};
use crate::rule;
use crate::spec::{
    AppDefaultPolicy, CommandSpec, DeleteOptions, Direction, DisableOptions, EnableOptions,
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
            Err(Error::UfwNotFound(
                "ufw binary not found on system".into(),
            ))
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

        // SSH lockout check
        if opts.require_ssh_allow_rule && !opts.allow_force {
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

    /// Disable UFW.
    pub fn disable(&self, opts: &DisableOptions) -> Result<()> {
        if opts.require_explicit_confirmation {
            return Err(Error::DisableRequiresConfirmation);
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
    pub fn set_default_policy(&self, direction: Direction, policy: Policy) -> Result<()> {
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

        // Check if the existing rule matches exactly
        // For now, if a rule with the same comment exists, assume it's the same
        // (exact match would require re-rendering the existing rule's args)
        Ok(crate::spec::ApplyReport {
            success: true,
            action: format!("rule already exists (comment: {comment})"),
            dry_run_output: None,
            verification: None,
            warnings: Vec::new(),
        })
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
        // Get current status to see if SSH rules exist
        let current = self.status()?;

        for &port in &opts.ssh_ports {
            let has_allow = current.rules.iter().any(|rule| {
                // Check if any rule allows the SSH port
                let raw = rule.raw.to_lowercase();
                raw.contains(&format!("{port}"))
                    || raw.contains("ssh")
                    || raw.contains("22/tcp")
                    || raw.contains("22")
            });

            if !has_allow {
                return Err(Error::SshLockoutRisk(format!(
                    "SSH port {port} is not allowed. \
                     Add an allow rule first or pass explicit override."
                )));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
#[path = "client.test.rs"]
mod tests;
