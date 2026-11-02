//! UFW client: typed wrapper around the `ufw` command. Reads are cached
//! (`status` 10 s, `--version` client lifetime); mutations invalidate status.

use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::command::{CommandRunner, DuctRunner};
use crate::error::{Error, Result};
use crate::rule;
use crate::spec::{
    AppDefaultPolicy, CommandSpec, DeleteOptions, Direction, DisableOptions, EnableOptions,
    LoggingLevel, Policy, ResetOptions, RouteRuleSpec, RuleSpec, UfwReport, UfwStatus,
};
use crate::status;

const STATUS_CACHE_TTL: Duration = Duration::from_secs(10);

#[derive(Debug, Default)]
struct DocCache {
    status_ttl_override: Option<Duration>,
    version: Option<String>,
    status: Option<(Instant, Arc<UfwStatus>)>,
    status_verbose: Option<(Instant, Arc<UfwStatus>)>,
}

impl DocCache {
    fn status_ttl(&self) -> Duration {
        self.status_ttl_override.unwrap_or(STATUS_CACHE_TTL)
    }

    fn fresh(doc: Option<&(Instant, Arc<UfwStatus>)>, ttl: Duration) -> Option<Arc<UfwStatus>> {
        doc.filter(|(fetched_at, _)| fetched_at.elapsed() < ttl)
            .map(|(_, status)| Arc::clone(status))
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CacheSlot {
    Status,
    StatusVerbose,
}

/// The main UFW client: `Ufw::system()` for real usage, `Ufw::with_runner()`
/// for tests.
pub struct Ufw {
    runner: Arc<dyn CommandRunner>,
    cache: std::sync::Mutex<DocCache>,
}

impl Ufw {
    /// Create a UFW client using the real system runner.
    pub fn system() -> Self {
        Self {
            runner: Arc::new(DuctRunner::new()),
            cache: std::sync::Mutex::new(DocCache::default()),
        }
    }

    /// Create a UFW client with a custom command runner (for testing).
    pub fn with_runner(runner: impl CommandRunner + 'static) -> Self {
        Self {
            runner: Arc::new(runner),
            cache: std::sync::Mutex::new(DocCache::default()),
        }
    }

    /// Create a UFW client with a custom command runner and a status-cache
    /// TTL override (for tests and benches that need deterministic cache
    /// behavior without waiting out the default TTL).
    #[must_use]
    pub fn with_runner_and_status_ttl(runner: impl CommandRunner + 'static, ttl: Duration) -> Self {
        let cache = DocCache {
            status_ttl_override: Some(ttl),
            ..DocCache::default()
        };
        Self {
            runner: Arc::new(runner),
            cache: std::sync::Mutex::new(cache),
        }
    }

    fn lock_cache(&self) -> std::sync::MutexGuard<'_, DocCache> {
        self.cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn cached_doc(&self, slot: CacheSlot) -> Option<Arc<UfwStatus>> {
        let cache = self.lock_cache();
        let ttl = cache.status_ttl();
        match slot {
            CacheSlot::Status => DocCache::fresh(cache.status.as_ref(), ttl),
            CacheSlot::StatusVerbose => DocCache::fresh(cache.status_verbose.as_ref(), ttl),
        }
    }

    fn store_doc(&self, slot: CacheSlot, status: UfwStatus) -> Arc<UfwStatus> {
        let arc = Arc::new(status);
        let mut cache = self.lock_cache();
        let slot_doc = match slot {
            CacheSlot::Status => &mut cache.status,
            CacheSlot::StatusVerbose => &mut cache.status_verbose,
        };
        *slot_doc = Some((Instant::now(), Arc::clone(&arc)));
        arc
    }

    fn invalidate_status_cache(&self) {
        let mut cache = self.lock_cache();
        cache.status = None;
        cache.status_verbose = None;
    }

    #[cfg(test)]
    fn set_status_ttl_for_test(&self, ttl: Duration) {
        self.lock_cache().status_ttl_override = Some(ttl);
    }

    /// Resolve the `ufw` binary name.
    ///
    /// The runner's presence probe is authoritative (an injected runner may
    /// forward to another host, where local `which` resolution is wrong), so
    /// the bare name is returned and PATH resolution happens at spawn time.
    pub fn find_ufw(&self) -> Result<String> {
        if self.runner.binary_exists("ufw") {
            Ok("ufw".into())
        } else {
            Err(Error::UfwNotFound("ufw binary not found on system".into()))
        }
    }

    /// Get UFW version; the first success is memoized for the client lifetime
    /// (failures are retried on the next call).
    pub fn version(&self) -> Result<String> {
        {
            let cache = self.lock_cache();
            if let Some(version) = &cache.version {
                return Ok(version.clone());
            }
        }
        let result = self
            .run_ufw(&["--version"])
            .map(|r| r.stdout.trim().to_string());
        if let Ok(version) = &result {
            self.lock_cache().version = Some(version.clone());
        }
        result
    }

    /// Get UFW status (non-verbose); a successful fetch is reused for 10 s and
    /// every mutating command invalidates the cache. Failures are never cached.
    pub fn status(&self) -> Result<UfwStatus> {
        self.status_arc().map(|cached| (*cached).clone())
    }

    /// Get verbose status (defaults, logging); cached independently of
    /// [`status`](Self::status) with the same TTL semantics.
    pub fn status_verbose(&self) -> Result<UfwStatus> {
        self.status_verbose_arc().map(|cached| (*cached).clone())
    }

    /// Status accessor that shares the cached document instead of cloning it.
    ///
    /// Doctor sweeps read the status repeatedly per run; this variant hands
    /// out the cached [`Arc`] so those reads do not deep-copy the ruleset.
    pub(crate) fn status_arc(&self) -> Result<Arc<UfwStatus>> {
        if let Some(cached) = self.cached_doc(CacheSlot::Status) {
            return Ok(cached);
        }
        self.run_ufw(&["status"])
            .and_then(|r| status::parse_status(&r.stdout))
            .map(|status| self.store_doc(CacheSlot::Status, status))
    }

    /// Verbose-status variant of [`status_arc`](Self::status_arc).
    pub(crate) fn status_verbose_arc(&self) -> Result<Arc<UfwStatus>> {
        if let Some(cached) = self.cached_doc(CacheSlot::StatusVerbose) {
            return Ok(cached);
        }
        self.run_ufw(&["status", "verbose"])
            .and_then(|r| status::parse_status_verbose(&r.stdout))
            .map(|status| self.store_doc(CacheSlot::StatusVerbose, status))
    }

    pub fn status_numbered(&self) -> Result<UfwStatus> {
        let result = self.run_ufw(&["status", "numbered"])?;
        status::parse_status_numbered(&result.stdout)
    }

    pub fn show(&self, report: UfwReport) -> Result<String> {
        let result = self.run_ufw(&["show", &report.to_string()])?;
        Ok(result.stdout)
    }

    /// Enable UFW with safety checks.
    pub fn enable(&self, opts: &EnableOptions) -> Result<()> {
        let current = self.status()?;
        if current.active {
            tracing::info!("UFW is already active");
            return Ok(());
        }

        if opts.require_ssh_allow_rule {
            self.check_ssh_lockout(opts)?;
        }

        let args = if opts.allow_force {
            vec!["--force", "enable"]
        } else {
            vec!["enable"]
        };

        let result = self.run_ufw_root(&args)?;
        // "inactive" contains "active", so require a positive marker that
        // cannot appear in a failure message and treat a missing exit code
        // as failure.
        let has_marker = (result.stdout.contains("is active") || result.stdout.contains("enabled"))
            && !result.stdout.contains("inactive");
        let exit_ok = result.exit_code == Some(0);
        if !has_marker || !exit_ok {
            let message = if result.stderr.is_empty() {
                format!(
                    "ufw enable did not report success (exit: {:?}, stdout: {:?})",
                    result.exit_code, result.stdout
                )
            } else {
                result.stderr
            };
            return Err(Error::EnableFailed(message));
        }

        Ok(())
    }

    /// Enable UFW with `--force`, bypassing the interactive prompt; still
    /// performs the SSH lockout safety check.
    pub fn force_enable(&self) -> Result<()> {
        self.enable(&EnableOptions {
            allow_force: true,
            ..EnableOptions::default()
        })
    }

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

    pub fn reload(&self) -> Result<()> {
        let result = self.run_ufw_root(&["reload"])?;
        if !result.stderr.is_empty() && result.exit_code != Some(0) {
            return Err(Error::ReloadFailed(result.stderr));
        }
        Ok(())
    }

    /// Reset UFW (destructive); with `backup_first`, a pre-reset backup is
    /// written under a fresh 0700 tempfile directory with an unpredictable
    /// name (persisted, not cleaned up).
    pub fn reset(&self, opts: &ResetOptions) -> Result<()> {
        if !opts.force {
            return Err(Error::ResetRequiresForce);
        }

        if opts.backup_first {
            let paths = crate::paths::UfwPaths::default();
            let backup_dir = tempfile::tempdir()
                .map_err(|e| Error::BackupFailed(format!("create backup dir: {e}")))?;
            let bundle = crate::backup::create_backup(&paths)
                .map_err(|e| Error::BackupFailed(format!("pre-reset backup: {e}")))?;
            crate::backup::write_backup(&bundle, backup_dir.path())
                .map_err(|e| Error::BackupFailed(format!("write pre-reset backup: {e}")))?;
            tracing::info!("Backup created at {}", backup_dir.path().display());
            // Persist the backup: dropping the TempDir would delete it.
            let _ = backup_dir.keep();
        }

        let args = vec!["--force", "reset"];

        let result = self.run_ufw_root(&args)?;
        if !result.stderr.is_empty() && result.exit_code != Some(0) {
            return Err(Error::ResetFailed(result.stderr));
        }

        Ok(())
    }

    /// Set default policy; setting incoming to Deny/Reject is rejected unless
    /// an incoming SSH allow rule exists.
    pub fn set_default_policy(&self, direction: Direction, policy: Policy) -> Result<()> {
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

    pub fn set_logging(&self, level: LoggingLevel) -> Result<()> {
        let args = rule::render_logging_args(level);
        let args_str: Vec<&str> = args.iter().map(String::as_str).collect();
        let result = self.run_ufw_root(&args_str)?;
        if !result.stderr.is_empty() && result.exit_code != Some(0) {
            return Err(Error::LoggingSetFailed(result.stderr));
        }
        Ok(())
    }

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

    /// Delete a rule by number (dangerous: numbers shift).
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

    /// Delete rules whose comment contains `comment`, highest number first;
    /// returns the number of rules deleted.
    pub fn delete_rules_by_comment(&self, comment: &str) -> Result<u32> {
        let status = self.status_numbered()?;

        let mut matching: Vec<u32> = status
            .rules
            .iter()
            .filter(|r| r.comment.as_deref().is_some_and(|c| c.contains(comment)))
            .filter_map(|r| r.number)
            .collect();

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

    pub fn insert_rule(&self, number: u32, spec: &RuleSpec) -> Result<()> {
        let mut spec = spec.clone();
        spec.position = crate::spec::RulePosition::Insert(number);
        self.add_rule(&spec)
    }

    pub fn add_route_rule(&self, spec: &RouteRuleSpec) -> Result<()> {
        let args = rule::render_route_rule_args(spec);
        let args_str: Vec<&str> = args.iter().map(String::as_str).collect();
        let result = self.run_ufw_root(&args_str)?;
        if !result.stderr.is_empty() && result.exit_code != Some(0) {
            return Err(Error::RuleAddFailed(result.stderr));
        }
        Ok(())
    }

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

    pub fn app_list(&self) -> Result<String> {
        let result = self.run_ufw(&["app", "list"])?;
        Ok(result.stdout)
    }

    pub fn app_info(&self, name: &str) -> Result<String> {
        let result = self.run_ufw(&["app", "info", name])?;
        Ok(result.stdout)
    }

    /// Update an application profile; does not invalidate the status caches
    /// (profile refresh only: the status documents are unchanged).
    pub fn app_update(&self, name: &str) -> Result<()> {
        let result = self.run_ufw(&["app", "update", name])?;
        if !result.stderr.is_empty() && result.exit_code != Some(0) {
            return Err(Error::AppUpdateFailed(result.stderr));
        }
        Ok(())
    }

    /// Update all application profiles; like [`app_update`](Self::app_update),
    /// does not invalidate the status caches.
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

    /// Dry-run a UFW command without executing it; returns the dry-run output,
    /// or an error if the dry-run reports one.
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

    /// Add a rule with a dry-run safety check: runs `--dry-run` first, then
    /// adds the rule if it succeeds.
    pub fn apply_rule(&self, spec: &RuleSpec) -> Result<crate::spec::ApplyReport> {
        let args = rule::render_rule_args(spec);
        let args_str: Vec<&str> = args.iter().map(String::as_str).collect();

        let dry_output = self.dry_run(&args_str)?;

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

    /// Idempotently ensure a rule exists, keyed by comment: an exact match is
    /// a no-op, a differing rule with the same comment is replaced, else added.
    pub fn ensure_rule(&self, spec: &RuleSpec) -> Result<crate::spec::ApplyReport> {
        let comment = spec.comment.as_deref().unwrap_or("");

        if comment.is_empty() {
            return self.apply_rule(spec);
        }

        let status = self.status_numbered()?;
        let existing: Vec<_> = status
            .rules
            .iter()
            .filter(|r| r.comment.as_deref() == Some(comment))
            .collect();

        if existing.is_empty() {
            return self.apply_rule(spec);
        }

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

        let mut numbers: Vec<u32> = existing.iter().filter_map(|r| r.number).collect();
        numbers.sort_by(|a, b| b.cmp(a));

        let delete_opts = crate::spec::DeleteOptions {
            allow_numbered_delete: true,
        };

        for num in &numbers {
            self.delete_rule_number(*num, &delete_opts)?;
        }

        if numbers.is_empty() {
            self.delete_rule(spec)?;
        }

        let report = self.apply_rule(spec)?;
        Ok(crate::spec::ApplyReport {
            success: true,
            action: format!("replaced rule (comment: {comment}): {}", report.action),
            dry_run_output: report.dry_run_output,
            verification: report.verification,
            warnings: report.warnings,
        })
    }

    pub fn runner(&self) -> &dyn CommandRunner {
        self.runner.as_ref()
    }

    fn run_ufw(&self, args: &[&str]) -> Result<crate::spec::CommandResult> {
        let spec = CommandSpec::ufw(args.iter().map(|s| (*s).to_string()).collect::<Vec<_>>());
        self.runner.run(&spec)
    }

    fn run_ufw_root(&self, args: &[&str]) -> Result<crate::spec::CommandResult> {
        let spec = CommandSpec::ufw_root(args.iter().map(|s| (*s).to_string()).collect::<Vec<_>>());
        let result = self.runner.run(&spec);
        self.invalidate_status_cache();
        result
    }

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

    /// Structured SSH lockout check: a rule counts when it is inbound (or
    /// direction unparsed), Allow/Limit, and its To column targets `ssh` or
    /// one of `ssh_ports` (token equality, so `8022/tcp` or a comment
    /// mentioning ssh never satisfies the guard).
    pub fn check_ssh_lockout_structured(&self, ssh_ports: &[u16]) -> crate::spec::SshCheckResult {
        let Ok(status) = self.status_arc() else {
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
            if !status::rule_is_allow(rule) || !status::rule_is_inbound(rule) {
                continue;
            }

            if !status::rule_targets_ssh(rule, ssh_ports) {
                continue;
            }

            if column_names_interface(rule.to.as_ref(), rule.from.as_ref()) {
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

/// Whether either table column carries a standalone `on <interface>` clause.
fn column_names_interface(
    to: Option<&std::sync::Arc<str>>,
    from: Option<&std::sync::Arc<str>>,
) -> bool {
    let has_on = |column: &str| {
        column
            .split_whitespace()
            .any(|t| t.eq_ignore_ascii_case("on"))
    };
    to.is_some_and(|c| has_on(c)) || from.is_some_and(|c| has_on(c))
}

/// Structural spec-vs-parsed-rule match for [`Ufw::ensure_rule`].
///
/// Ports and addresses are compared by token equality against the parsed To
/// and From columns; the raw substring scan is only a fallback for rules the
/// parser could not split into columns.
fn rule_matches_spec(parsed: &crate::spec::ParsedRule, spec: &RuleSpec) -> bool {
    use crate::spec::{Address, PortSpec};

    let action_matches = if let Some(a) = parsed.action {
        a == spec.action
    } else {
        let lower = parsed.raw.to_lowercase();
        lower.contains(&spec.action.to_string())
    };
    if !action_matches {
        return false;
    }

    let dir_matches = match (parsed.direction, spec.direction) {
        (Some(d), Some(sd)) => d == sd,
        (_, None) => true,
        (None, Some(sd)) => {
            let lower = parsed.raw.to_lowercase();
            lower.contains(&sd.to_string())
        }
    };
    if !dir_matches {
        return false;
    }

    if let Some(app) = &spec.app_profile
        && !status::rule_matches_app_profile(parsed, app)
    {
        return false;
    }

    let port_matches = match parsed.to.as_deref() {
        Some(to) => status::to_column_matches_port_spec(to, &spec.to_port, spec.protocol),
        None => match &spec.to_port {
            PortSpec::Any => true,
            PortSpec::Single(p) => parsed.raw.contains(&p.to_string()),
            PortSpec::Range { start, end } => parsed.raw.contains(&format!("{start}:{end}")),
            PortSpec::List(ports) => ports.iter().all(|p| {
                let rendered = p.to_string();
                parsed.raw.contains(&rendered)
            }),
            PortSpec::ServiceName(name) => parsed.raw.contains(name),
        },
    };
    if !port_matches {
        return false;
    }

    let from_matches = match (&spec.from_addr, parsed.from.as_deref()) {
        (Address::Any, _) => true,
        (addr, Some(column)) => status::column_matches_address(column, addr),
        (addr, None) => parsed.raw.contains(&addr.to_string()),
    };
    if !from_matches {
        return false;
    }

    let to_addr_matches = match (&spec.to_addr, parsed.to.as_deref()) {
        (Address::Any, _) => true,
        (addr, Some(column)) => status::column_matches_address(column, addr),
        (addr, None) => parsed.raw.contains(&addr.to_string()),
    };
    if !to_addr_matches {
        return false;
    }

    true
}

#[cfg(test)]
#[path = "client.test.rs"]
mod tests;
