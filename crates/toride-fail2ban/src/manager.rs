//! Fail2Ban manager orchestrating multiple jails.

use std::collections::HashMap;
use std::net::IpAddr;

use crate::config::{Fail2BanConfig, ResolvedJail};
use crate::jail::Jail;
use crate::paths::Fail2BanPaths;
use crate::store::Store;
use crate::support::{self, Firewall};
use crate::types::{Fail2BanStatus, JailStatus};

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
}

impl Fail2BanManager {
    /// Create a new manager from configuration.
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
        };

        manager.load_jails()?;
        Ok(manager)
    }

    /// Load all enabled jails from configuration.
    fn load_jails(&mut self) -> crate::Result<()> {
        for name in self.config.enabled_jails() {
            let resolved = self.config.resolve_jail(name)?;
            let jail = Jail::new(resolved, self.store.clone())?;
            self.jails.insert(name.to_string(), jail);
        }
        Ok(())
    }

    /// Add a new jail at runtime.
    pub fn add_jail(&mut self, name: &str, resolved: ResolvedJail) -> crate::Result<()> {
        if self.jails.contains_key(name) {
            return Err(crate::Error::JailAlreadyExists(name.to_string()));
        }
        let jail = Jail::new(resolved, self.store.clone())?;
        self.jails.insert(name.to_string(), jail);
        Ok(())
    }

    /// Remove a jail.
    pub fn remove_jail(&mut self, name: &str) -> crate::Result<()> {
        self.jails.remove(name).ok_or_else(|| {
            crate::Error::JailNotFound(name.to_string())
        })?;
        Ok(())
    }

    /// Scan all active jails.
    pub fn scan_all(&mut self, dry_run: bool) -> crate::Result<HashMap<String, crate::types::ScanResult>> {
        let mut results = HashMap::new();

        for (name, jail) in &mut self.jails {
            let result = jail.scan(dry_run)?;
            results.insert(name.clone(), result);
        }

        Ok(results)
    }

    /// Scan a specific jail.
    pub fn scan_jail(&mut self, name: &str, dry_run: bool) -> crate::Result<crate::types::ScanResult> {
        let jail = self.jails.get_mut(name).ok_or_else(|| {
            crate::Error::JailNotFound(name.to_string())
        })?;
        jail.scan(dry_run)
    }

    /// Ban an IP in a specific jail.
    pub fn ban_ip(&self, jail_name: &str, ip: IpAddr, dry_run: bool) -> crate::Result<()> {
        let jail = self.jails.get(jail_name).ok_or_else(|| {
            crate::Error::JailNotFound(jail_name.to_string())
        })?;
        jail.ban_ip(ip, dry_run)?;
        Ok(())
    }

    /// Unban an IP from a specific jail.
    pub fn unban_ip(&self, jail_name: &str, ip: &str, dry_run: bool) -> crate::Result<()> {
        let jail = self.jails.get(jail_name).ok_or_else(|| {
            crate::Error::JailNotFound(jail_name.to_string())
        })?;
        jail.unban_ip(ip, dry_run)?;
        Ok(())
    }

    /// Get status of all jails.
    pub fn status(&self) -> crate::Result<Fail2BanStatus> {
        let jail_statuses = self.jail_statuses()?;
        Ok(Fail2BanStatus {
            running: true,
            jails: jail_statuses,
            config_path: self.paths.config_file.clone(),
        })
    }

    /// Get status of a specific jail.
    pub fn jail_status(&self, name: &str) -> crate::Result<JailStatus> {
        let jail = self.jails.get(name).ok_or_else(|| {
            crate::Error::JailNotFound(name.to_string())
        })?;
        let bans = jail.list_bans()?;
        Ok(JailStatus {
            name: name.to_string(),
            active: true,
            banned_ips: bans,
            total_bans: 0,
            log_path: jail.log_path().to_path_buf(),
            pattern: String::new(),
        })
    }

    /// Get all jail statuses.
    fn jail_statuses(&self) -> crate::Result<Vec<JailStatus>> {
        let mut statuses = Vec::new();
        for (name, jail) in &self.jails {
            let bans = jail.list_bans()?;
            statuses.push(JailStatus {
                name: name.clone(),
                active: true,
                banned_ips: bans,
                total_bans: 0,
                log_path: jail.log_path().to_path_buf(),
                pattern: String::new(),
            });
        }
        Ok(statuses)
    }

    /// Purge expired bans across all jails.
    pub fn purge_expired(&self) -> crate::Result<Vec<crate::types::BanEntry>> {
        self.store.clear_expired()
    }

    /// Get the detected firewall type.
    pub fn firewall(&self) -> Firewall {
        self.firewall
    }

    /// Get the configuration.
    pub fn config(&self) -> &Fail2BanConfig {
        &self.config
    }

    /// Get the paths.
    pub fn paths(&self) -> &Fail2BanPaths {
        &self.paths
    }
}

#[cfg(test)]
#[path = "manager.test.rs"]
mod tests;
