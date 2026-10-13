//! Fail2Ban manager orchestrating multiple jails.

use std::collections::BTreeMap;
use std::collections::HashMap;
use std::net::IpAddr;

use crate::config::{Fail2BanConfig, ResolvedJail};
use crate::jail::Jail;
use crate::paths::Fail2BanPaths;
use crate::store::Store;
use crate::support::{self, Firewall};
use crate::types::{ExecutionMode, Fail2BanStatus, JailStatus};

/// Top-level manager for all fail2ban operations.
pub struct Fail2BanManager {
    /// Configuration.
    config: Fail2BanConfig,
    /// Resolved paths.
    paths: Fail2BanPaths,
    /// Persistent store.
    store: Store,
    /// Active jails.
    jails: HashMap<String, Jail>,
    /// Detected firewall.
    firewall: Firewall,
    /// Whether the manager is currently running (started).
    running: bool,
}

impl Fail2BanManager {
    /// Create a new manager from configuration.
    ///
    /// # Errors
    ///
    /// Returns `Io` if directories cannot be created, or `InvalidRegex` if
    /// any enabled jail has an invalid pattern.
    pub fn new(config: Fail2BanConfig, paths: Fail2BanPaths) -> crate::Result<Self> {
        paths.ensure_directories()?;

        let store = Store::new(paths.ban_db.clone());
        let firewall = support::detect_firewall();

        let mut manager = Self {
            config,
            paths,
            store,
            jails: HashMap::new(),
            firewall,
            running: true,
        };

        manager.load_jails()?;
        Ok(manager)
    }

    /// Load all enabled jails from configuration.
    fn load_jails(&mut self) -> crate::Result<()> {
        for name in self.config.enabled_jails() {
            let resolved = self.config.resolve_jail(name)?;
            let actions = if self.config.actions.is_empty() {
                None
            } else {
                Some(&self.config.actions)
            };
            let mut jail = Jail::new(
                resolved,
                self.store.clone(),
                actions,
                self.firewall,
                Box::new(crate::command::DuctRunner::new()),
            )?;
            // Resume scanning from the last persisted journal position.
            jail.restore_journal()?;
            self.jails.insert(name.to_string(), jail);
        }
        Ok(())
    }

    /// Add a new jail at runtime.
    ///
    /// # Errors
    ///
    /// Returns `JailAlreadyExists` if a jail with the given name already exists,
    /// or `InvalidRegex` if the jail pattern is invalid.
    pub fn add_jail(&mut self, name: &str, resolved: ResolvedJail) -> crate::Result<()> {
        if self.jails.contains_key(name) {
            return Err(crate::Error::JailAlreadyExists(name.to_string()));
        }
        let actions = if self.config.actions.is_empty() {
            None
        } else {
            Some(&self.config.actions)
        };
        let jail = Jail::new(
            resolved,
            self.store.clone(),
            actions,
            self.firewall,
            Box::new(crate::command::DuctRunner::new()),
        )?;
        self.jails.insert(name.to_string(), jail);
        Ok(())
    }

    /// Remove a jail.
    ///
    /// # Errors
    ///
    /// Returns `JailNotFound` if the jail does not exist.
    pub fn remove_jail(&mut self, name: &str) -> crate::Result<()> {
        self.jails
            .remove(name)
            .ok_or_else(|| crate::Error::JailNotFound(name.to_string()))?;
        Ok(())
    }

    /// Scan all active jails.
    ///
    /// # Errors
    ///
    /// Returns `InvalidConfig` if the manager is stopped, `LogFileError` if
    /// any log file cannot be read, or `CommandFailed` if a ban action fails
    /// during scan.
    pub fn scan_all(
        &mut self,
        mode: ExecutionMode,
    ) -> crate::Result<BTreeMap<String, crate::types::ScanResult>> {
        self.ensure_running()?;
        let mut results = BTreeMap::new();

        for (name, jail) in &mut self.jails {
            let result = jail.scan(mode)?;
            results.insert(name.clone(), result);
        }

        Ok(results)
    }

    /// Scan a specific jail.
    ///
    /// # Errors
    ///
    /// Returns `InvalidConfig` if the manager is stopped, `JailNotFound` if
    /// the jail does not exist, `LogFileError` if the log file cannot be
    /// read, or `CommandFailed` if a ban action fails.
    pub fn scan_jail(
        &mut self,
        name: &str,
        mode: ExecutionMode,
    ) -> crate::Result<crate::types::ScanResult> {
        self.ensure_running()?;
        let jail = self
            .jails
            .get_mut(name)
            .ok_or_else(|| crate::Error::JailNotFound(name.to_string()))?;
        jail.scan(mode)
    }

    /// Ban an IP in a specific jail.
    ///
    /// # Errors
    ///
    /// Returns `InvalidConfig` if the manager is stopped or the IP is in the
    /// ignore list, `JailNotFound` if the jail does not exist, `AlreadyBanned`
    /// if the IP is already banned, or `CommandFailed` if the firewall
    /// command fails.
    pub fn ban_ip(
        &mut self,
        jail_name: &str,
        ip: IpAddr,
        mode: ExecutionMode,
    ) -> crate::Result<()> {
        self.ensure_running()?;
        let jail = self
            .jails
            .get_mut(jail_name)
            .ok_or_else(|| crate::Error::JailNotFound(jail_name.to_string()))?;
        jail.ban_ip(ip, mode)?;
        Ok(())
    }

    /// Unban an IP from a specific jail.
    ///
    /// # Errors
    ///
    /// Returns `InvalidConfig` if the manager is stopped, `JailNotFound` if
    /// the jail does not exist, `NotBanned` if the IP is not currently banned,
    /// or `CommandFailed` if the firewall command fails.
    pub fn unban_ip(
        &mut self,
        jail_name: &str,
        ip: IpAddr,
        mode: ExecutionMode,
    ) -> crate::Result<()> {
        self.ensure_running()?;
        let jail = self
            .jails
            .get_mut(jail_name)
            .ok_or_else(|| crate::Error::JailNotFound(jail_name.to_string()))?;
        jail.unban_ip(ip, mode)?;
        Ok(())
    }

    /// Refuse operations while the manager is stopped.
    fn ensure_running(&self) -> crate::Result<()> {
        if self.running {
            Ok(())
        } else {
            Err(crate::Error::InvalidConfig(
                "manager is stopped; call start() before issuing commands".into(),
            ))
        }
    }

    /// Get status of all jails.
    ///
    /// # Errors
    ///
    /// Returns `Io` if the ban store cannot be read.
    pub fn status(&self) -> crate::Result<Fail2BanStatus> {
        let jail_statuses = self.jail_statuses()?;
        Ok(Fail2BanStatus {
            running: self.running,
            jails: jail_statuses,
            config_path: self.paths.config_file.clone(),
        })
    }

    /// Get status of a specific jail.
    ///
    /// # Errors
    ///
    /// Returns `JailNotFound` if the jail does not exist, or `Io` if the ban
    /// store cannot be read.
    pub fn jail_status(&self, name: &str) -> crate::Result<JailStatus> {
        let jail = self
            .jails
            .get(name)
            .ok_or_else(|| crate::Error::JailNotFound(name.to_string()))?;
        let data = self.store.load()?;
        let banned_ips = data
            .active_bans
            .iter()
            .filter(|b| b.jail_name == name)
            .cloned()
            .collect();
        let total_bans = data.history.iter().filter(|b| b.jail_name == name).count() as u64;
        Ok(JailStatus {
            name: name.to_string(),
            active: self.running,
            banned_ips,
            total_bans,
            log_path: jail.log_path().to_path_buf(),
            pattern: jail.pattern().to_string(),
        })
    }

    /// Get all jail statuses from one store read.
    fn jail_statuses(&self) -> crate::Result<Vec<JailStatus>> {
        let data = self.store.load()?;
        let mut active_by_jail: HashMap<&str, Vec<crate::types::BanEntry>> = HashMap::new();
        let mut history_counts: HashMap<&str, u64> = HashMap::new();
        for ban in &data.active_bans {
            active_by_jail
                .entry(ban.jail_name.as_str())
                .or_default()
                .push(ban.clone());
        }
        for ban in &data.history {
            *history_counts.entry(ban.jail_name.as_str()).or_default() += 1;
        }

        let mut statuses = Vec::new();
        for (name, jail) in &self.jails {
            let banned_ips = active_by_jail.remove(name.as_str()).unwrap_or_default();
            let total_bans = history_counts.get(name.as_str()).copied().unwrap_or(0);
            statuses.push(JailStatus {
                name: name.clone(),
                active: self.running,
                banned_ips,
                total_bans,
                log_path: jail.log_path().to_path_buf(),
                pattern: jail.pattern().to_string(),
            });
        }
        Ok(statuses)
    }

    /// Purge expired bans across all jails and trim history.
    ///
    /// Unless `mode` is [`ExecutionMode::DryRun`], each purged entry's jail
    /// executes its unban action so expiry also lifts the firewall block;
    /// failures are logged (the kernel rule may outlive the store entry).
    ///
    /// # Errors
    ///
    /// Returns `Io` if the ban store cannot be read or written.
    pub fn purge_expired(&self, mode: ExecutionMode) -> crate::Result<Vec<crate::types::BanEntry>> {
        let purged = self.store.clear_expired()?;
        if !mode.is_dry_run() {
            for entry in &purged {
                match self.jails.get(&entry.jail_name) {
                    Some(jail) => {
                        if let Err(e) =
                            jail.exec_unban_action(entry.ip, entry.prefix, entry.fail_count)
                        {
                            tracing::error!(
                                jail = %entry.jail_name,
                                ip = %entry.ip,
                                error = %e,
                                "unban action failed for purged ban; firewall may still block"
                            );
                        }
                    }
                    None => {
                        tracing::warn!(
                            jail = %entry.jail_name,
                            "no loaded jail for purged ban; unban action not executed"
                        );
                    }
                }
            }
        }
        // Trim history to configured max.
        if let Err(e) = self.store.trim_history(self.config.global.max_history) {
            tracing::warn!(error = %e, "failed to trim ban history");
        }
        Ok(purged)
    }

    /// Get the detected firewall type.
    #[must_use]
    pub const fn firewall(&self) -> Firewall {
        self.firewall
    }

    /// Get the configuration.
    #[must_use]
    pub const fn config(&self) -> &Fail2BanConfig {
        &self.config
    }

    /// Get the paths.
    #[must_use]
    pub const fn paths(&self) -> &Fail2BanPaths {
        &self.paths
    }

    /// Get the configured log level.
    #[must_use]
    pub fn log_level(&self) -> &str {
        &self.config.global.log_level
    }

    /// Mark the manager as running (it starts running on construction).
    ///
    /// While stopped, scan/ban/unban verbs fail with `InvalidConfig`.
    pub const fn start(&mut self) {
        self.running = true;
    }

    /// Mark the manager as stopped: scan, ban, and unban verbs refuse to run
    /// and statuses report `active: false` until [`start`](Self::start).
    pub const fn stop(&mut self) {
        self.running = false;
    }

    /// Check if the manager is currently running.
    #[must_use]
    pub const fn is_running(&self) -> bool {
        self.running
    }
}

#[cfg(test)]
#[path = "manager.test.rs"]
mod tests;
