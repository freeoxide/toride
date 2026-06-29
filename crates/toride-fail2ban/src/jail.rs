//! Jail implementation combining detector, ban manager, and actions.

use std::collections::HashMap;
use std::net::IpAddr;

use chrono::{DateTime, Duration, Utc};

use crate::action::{ActionExec, ActionVars};
use crate::ban::{BanManager, CidrBlock, CidrSet};
use crate::command::Runner;
use crate::config::{ActionConfig, ResolvedJail};
use crate::detector::LogDetector;
use crate::store::Store;
use crate::support;
use crate::types::{BanEntry, ExecutionMode, ScanResult};

/// A jail monitors a log file and bans IPs that match its pattern.
pub struct Jail {
    /// Jail configuration.
    config: ResolvedJail,
    /// Log file detector.
    detector: LogDetector,
    /// Ban manager for this jail.
    ban_manager: BanManager,
    /// Action to execute on ban.
    ban_action: ActionExec,
    /// Action to execute on unban.
    unban_action: ActionExec,
    /// IPs/CIDRs that should never be banned.
    ignore_set: CidrSet,
    /// Tracks failure timestamps per IP for find_time/max_retry logic.
    failure_tracker: HashMap<IpAddr, Vec<DateTime<Utc>>>,
    /// Command runner for executing ban/unban actions.
    runner: Box<dyn Runner>,
}

impl Jail {
    /// Create a new jail from resolved configuration.
    ///
    /// If `actions` is provided, custom action templates from the config are
    /// used instead of the default platform commands. Action names `"ban"` and
    /// `"unban"` always resolve to the default platform commands.
    ///
    /// # Errors
    ///
    /// Returns `InvalidRegex` if the config pattern is invalid.
    pub fn new(
        config: ResolvedJail,
        store: Store,
        actions: Option<&HashMap<String, ActionConfig>>,
        runner: Box<dyn Runner>,
    ) -> crate::Result<Self> {
        let detector = LogDetector::new(&config.name, &config.log_path, &config.pattern)?;

        let ban_manager = BanManager::new(store);

        let firewall = support::detect_firewall();

        // Resolve ban action: use custom action from config if available,
        // otherwise fall back to default platform commands.
        let ban_action = resolve_action(
            &config.ban_action,
            actions,
            &support::default_ban_commands(firewall),
        );
        let unban_action = resolve_action(
            &config.unban_action,
            actions,
            &support::default_unban_commands(firewall),
        );

        let ignore_set = parse_ignore_list(&config.ignore_ips);

        Ok(Self {
            config,
            detector,
            ban_manager,
            ban_action,
            unban_action,
            ignore_set,
            failure_tracker: HashMap::new(),
            runner,
        })
    }

    /// Set ignore IPs for this jail.
    #[must_use]
    #[expect(
        clippy::needless_pass_by_value,
        reason = "builder pattern takes ownership"
    )]
    pub fn with_ignore_ips(mut self, ips: Vec<String>) -> Self {
        self.ignore_set = parse_ignore_list(&ips);
        self
    }

    /// Get the jail name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.config.name
    }

    /// Get the log path.
    #[must_use]
    pub fn log_path(&self) -> &std::path::Path {
        &self.config.log_path
    }

    /// Get the regex pattern.
    #[must_use]
    pub fn pattern(&self) -> &str {
        &self.config.pattern
    }

    /// Restore the detector's scan position from the persisted journal.
    ///
    /// This should be called after constructing a jail to resume scanning
    /// from where the last run left off, rather than re-scanning from the
    /// beginning of the log file.
    ///
    /// # Errors
    ///
    /// Returns `Io` if the journal store cannot be read.
    pub fn restore_journal(&mut self) -> crate::Result<()> {
        let journal = self
            .ban_manager
            .store()
            .get_journal(&self.config.name, &self.config.log_path)?;
        if let Some(entry) = journal {
            self.detector.set_position(entry.offset, entry.line_number);
        }
        Ok(())
    }

    /// Create action variables for the given IP.
    fn make_action_vars(&self, ip: &IpAddr, prefix: u8, fail_count: u32) -> ActionVars {
        ActionVars::new(
            ip.to_string(),
            prefix,
            self.config.name.clone(),
            self.config.ban_time,
            fail_count,
            self.config.log_path.display().to_string(),
        )
    }

    /// Scan the log file and process any new matches.
    ///
    /// Applies find_time/max_retry threshold logic: only bans an IP if it has
    /// failed at least `max_retry` times within the `find_time` window.
    ///
    /// Persists bans to the store and executes firewall commands (unless dry-run).
    pub fn scan(&mut self, mode: ExecutionMode) -> crate::Result<ScanResult> {
        let mut result = self.detector.scan()?;

        let now = Utc::now();
        let find_time_secs = i64::try_from(self.config.find_time).map_err(|_| {
            crate::Error::InvalidConfig(format!(
                "find_time {} exceeds maximum",
                self.config.find_time
            ))
        })?;
        let find_time = Duration::seconds(find_time_secs);

        // Apply find_time/max_retry threshold logic.
        let mut to_ban = Vec::new();
        for entry in result.new_bans.drain(..) {
            if self.is_ignored(entry.ip) {
                continue;
            }

            // Track failure timestamp.
            let failures = self.failure_tracker.entry(entry.ip).or_default();
            failures.push(now);
            // Prune old failures outside find_time window.
            failures.retain(|t| now - *t <= find_time);

            // Only ban if we have enough failures.
            #[expect(clippy::cast_possible_truncation, reason = "failure count fits in u32")]
            if (failures.len() as u32) < self.config.max_retry {
                continue;
            }
            failures.clear(); // Reset after ban triggers.

            to_ban.push(entry);
        }

        result.new_bans = Vec::with_capacity(to_ban.len());

        for entry in to_ban {
            let BanEntry {
                ip,
                prefix,
                fail_count,
                reason,
                ..
            } = entry;
            // Persist the ban to the store.
            match self.ban_manager.ban(
                ip,
                prefix,
                &self.config.name,
                fail_count,
                self.config.ban_time,
                reason,
            ) {
                Ok(persisted) => {
                    // Execute ban action (skip in dry-run).
                    if !mode.is_dry_run() {
                        let vars = self.make_action_vars(&ip, prefix, fail_count);
                        if let Err(e) = self.ban_action.exec(&vars, self.runner.as_ref()) {
                            tracing::error!(jail = %self.config.name, ip = %ip, error = %e, "ban action failed");
                            // Rollback: remove from store since firewall command failed.
                            if let Err(e) = self.ban_manager.unban(ip, &self.config.name) {
                                tracing::error!(jail = %self.config.name, ip = %ip, error = %e,
                                    "rollback unban failed after ban action error");
                            }
                            return Err(e);
                        }
                    }
                    result.new_bans.push(persisted);
                }
                Err(crate::Error::AlreadyBanned(_)) => {
                    // Already banned, skip.
                }
                Err(e) => return Err(e),
            }
        }

        // Update journal position for scan resume.
        let journal = self.detector.journal();
        // Store journal if we have a store reference (we do via ban_manager).
        // This is a best-effort operation.
        if let Err(e) = self.ban_manager.store().update_journal(journal) {
            tracing::warn!(jail = %self.config.name, error = %e, "failed to persist journal");
        }

        Ok(result)
    }

    /// Ban a specific IP address.
    ///
    /// Persists to the store first, then executes the firewall command.
    /// If the firewall command fails, the store entry is rolled back.
    ///
    /// # Errors
    ///
    /// Returns `InvalidConfig` if the IP is in the ignore list,
    /// `AlreadyBanned` if already banned, or `CommandFailed` if the
    /// firewall command fails.
    pub fn ban_ip(&mut self, ip: IpAddr, mode: ExecutionMode) -> crate::Result<BanEntry> {
        if self.is_ignored(ip) {
            return Err(crate::Error::InvalidConfig(format!(
                "IP {ip} is in the ignore list"
            )));
        }

        let prefix = crate::types::default_prefix(ip);

        // Persist to store first.
        let entry =
            self.ban_manager
                .ban(ip, prefix, &self.config.name, 1, self.config.ban_time, None)?;

        // Execute ban action (skip in dry-run).
        if !mode.is_dry_run() {
            let vars = self.make_action_vars(&ip, prefix, 1);
            if let Err(e) = self.ban_action.exec(&vars, self.runner.as_ref()) {
                tracing::error!(jail = %self.config.name, ip = %ip, error = %e, "ban action failed");
                // Rollback: remove from store since firewall command failed.
                if let Err(rb_err) = self.ban_manager.unban(ip, &self.config.name) {
                    tracing::error!(jail = %self.config.name, ip = %ip, error = %rb_err,
                        "rollback unban failed after ban action error");
                }
                return Err(e);
            }
        }

        Ok(entry)
    }

    /// Unban a specific IP address.
    ///
    /// Removes from store first, then executes the firewall unban command.
    ///
    /// # Errors
    ///
    /// Returns `NotBanned` if the IP is not currently banned,
    /// or `CommandFailed` if the firewall command fails.
    pub fn unban_ip(&mut self, ip: IpAddr, mode: ExecutionMode) -> crate::Result<BanEntry> {
        // Verify the IP is actually banned and remove from store.
        let entry = self.ban_manager.unban(ip, &self.config.name)?;

        // Execute unban action (skip in dry-run).
        if !mode.is_dry_run() {
            let vars = self.make_action_vars(&ip, entry.prefix, entry.fail_count);
            if let Err(e) = self.unban_action.exec(&vars, self.runner.as_ref()) {
                tracing::error!(jail = %self.config.name, ip = %ip, error = %e, "unban action failed");
                return Err(e);
            }
        }

        Ok(entry)
    }

    /// List all active bans for this jail.
    pub fn list_bans(&self) -> crate::Result<Vec<BanEntry>> {
        self.ban_manager.list_bans(Some(&self.config.name))
    }

    /// Check if an IP is ignored.
    fn is_ignored(&self, ip: IpAddr) -> bool {
        self.ignore_set.contains(ip)
    }
}

/// Resolve an action by name, looking it up in the actions map or falling
/// back to default platform commands for built-in names `"ban"` / `"unban"`.
fn resolve_action(
    name: &str,
    actions: Option<&HashMap<String, ActionConfig>>,
    default_commands: &crate::types::PlatformCommands,
) -> ActionExec {
    // Built-in names always use default platform commands.
    if name == "ban" || name == "unban" {
        return ActionExec::new(name.to_string(), default_commands.clone());
    }
    // Look up custom action in the actions map.
    if let Some(action_cfg) = actions.and_then(|map| map.get(name)) {
        return ActionExec::new(name.to_string(), action_cfg.commands.clone());
    }
    // Fallback to default commands if action not found.
    ActionExec::new(name.to_string(), default_commands.clone())
}

/// Parse a list of IP/CIDR strings into a `CidrSet`.
/// Logs a warning for invalid entries and skips them.
fn parse_ignore_list(entries: &[String]) -> CidrSet {
    let mut set = CidrSet::new();
    for s in entries {
        if let Ok(ip) = s.parse::<IpAddr>() {
            let prefix = crate::types::default_prefix(ip);
            if let Ok(block) = CidrBlock::new(ip, prefix) {
                set.insert(block);
            }
        } else if let Some((addr_str, prefix_str)) = s.split_once('/') {
            if let (Ok(addr), Ok(prefix)) = (addr_str.parse::<IpAddr>(), prefix_str.parse::<u8>()) {
                if let Ok(block) = CidrBlock::new(addr, prefix) {
                    set.insert(block);
                }
            } else {
                tracing::warn!(entry = %s, "invalid ignore_ips entry, skipping");
            }
        } else {
            tracing::warn!(entry = %s, "invalid ignore_ips entry, skipping");
        }
    }
    set
}

#[cfg(test)]
#[path = "jail.test.rs"]
mod tests;
