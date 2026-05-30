//! Jail implementation combining detector, ban manager, and actions.

use std::net::IpAddr;

use ipnet::IpNet;

use crate::action::{ActionExec, ActionVars};
use crate::ban::BanManager;
use crate::config::ResolvedJail;
use crate::detector::LogDetector;
use crate::store::Store;
use crate::support;
use crate::types::{BanEntry, ExecutionMode, ScanResult};

/// Pre-parsed ignore entry to avoid re-parsing on every check.
#[derive(Debug, Clone)]
enum IgnoreEntry {
    Single(IpAddr),
    Cidr(IpNet),
}

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
    /// IPs that should never be banned.
    ignore_ips: Vec<IgnoreEntry>,
}

impl Jail {
    /// Create a new jail from resolved configuration.
    ///
    /// # Errors
    ///
    /// Returns `InvalidRegex` if the config pattern is invalid.
    pub fn new(config: ResolvedJail, store: Store) -> crate::Result<Self> {
        let detector = LogDetector::new(
            &config.name,
            &config.log_path,
            &config.pattern,
        )?;

        let ban_manager = BanManager::new(store);

        // Create default platform actions.
        let firewall = support::detect_firewall();
        let ban_action = ActionExec::new(
            config.ban_action.clone(),
            support::default_ban_commands(firewall),
        );
        let unban_action = ActionExec::new(
            config.unban_action.clone(),
            support::default_unban_commands(firewall),
        );

        let ignore_ips = config.ignore_ips.iter().filter_map(|s| {
            if let Ok(cidr) = s.parse::<IpNet>() {
                Some(IgnoreEntry::Cidr(cidr))
            } else if let Ok(ip) = s.parse::<IpAddr>() {
                Some(IgnoreEntry::Single(ip))
            } else {
                tracing::warn!(entry = %s, "invalid ignore_ips entry, skipping");
                None
            }
        }).collect();

        Ok(Self {
            config,
            detector,
            ban_manager,
            ban_action,
            unban_action,
            ignore_ips,
        })
    }

    /// Set ignore IPs for this jail.
    #[must_use]
    #[expect(clippy::needless_pass_by_value, reason = "builder pattern takes ownership")]
    pub fn with_ignore_ips(mut self, ips: Vec<String>) -> Self {
        self.ignore_ips = ips.iter().filter_map(|s| {
            if let Ok(cidr) = s.parse::<IpNet>() {
                Some(IgnoreEntry::Cidr(cidr))
            } else if let Ok(ip) = s.parse::<IpAddr>() {
                Some(IgnoreEntry::Single(ip))
            } else {
                None
            }
        }).collect();
        self
    }

    /// Get the jail name.
    pub fn name(&self) -> &str {
        &self.config.name
    }

    /// Get the log path.
    pub fn log_path(&self) -> &std::path::Path {
        &self.config.log_path
    }

    /// Scan the log file and process any new matches.
    pub fn scan(&mut self, mode: ExecutionMode) -> crate::Result<ScanResult> {
        let mut result = self.detector.scan()?;

        // Filter out ignored IPs.
        result.new_bans.retain(|ban| !self.is_ignored(ban.ip));

        if !mode.is_dry_run() {
            for ban in &result.new_bans {
                let vars = ActionVars::new(
                    &ban.ip.to_string(),
                    ban.prefix,
                    &self.config.name,
                    self.config.ban_time,
                    ban.fail_count,
                    &self.config.log_path.display().to_string(),
                );

                // Execute ban action.
                if let Err(e) = self.ban_action.exec(&vars) {
                    tracing::error!(jail = %self.config.name, ip = %ban.ip, error = %e, "ban action failed");
                }
            }
        }

        Ok(result)
    }

    /// Ban a specific IP address.
    ///
    /// # Errors
    ///
    /// Returns `InvalidConfig` if the IP is in the ignore list, or `AlreadyBanned` if already banned.
    pub fn ban_ip(&self, ip: IpAddr, mode: ExecutionMode) -> crate::Result<BanEntry> {
        if self.is_ignored(ip) {
            return Err(crate::Error::InvalidConfig(format!(
                "IP {ip} is in the ignore list"
            )));
        }

        let entry = self.ban_manager.ban(
            ip,
            match ip {
                IpAddr::V4(_) => 32,
                IpAddr::V6(_) => 128,
            },
            &self.config.name,
            0,
            self.config.ban_time,
            None,
        )?;

        if !mode.is_dry_run() {
            let vars = ActionVars::new(
                &ip.to_string(),
                entry.prefix,
                &self.config.name,
                self.config.ban_time,
                1,
                &self.config.log_path.display().to_string(),
            );
            if let Err(e) = self.ban_action.exec(&vars) {
                tracing::error!(jail = %self.config.name, ip = %ip, error = %e, "ban action failed");
            }
        }

        Ok(entry)
    }

    /// Unban a specific IP address.
    ///
    /// # Errors
    ///
    /// Returns `NotBanned` if the IP is not currently banned.
    pub fn unban_ip(&self, ip: IpAddr, mode: ExecutionMode) -> crate::Result<BanEntry> {
        let entry = self.ban_manager.unban(ip, &self.config.name)?;

        if !mode.is_dry_run() {
            let vars = ActionVars::new(
                &ip.to_string(),
                entry.prefix,
                &self.config.name,
                self.config.ban_time,
                entry.fail_count,
                &self.config.log_path.display().to_string(),
            );
            if let Err(e) = self.unban_action.exec(&vars) {
                tracing::error!(jail = %self.config.name, ip = %ip, error = %e, "unban action failed");
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
        self.ignore_ips.iter().any(|entry| match entry {
            IgnoreEntry::Single(ignored) => *ignored == ip,
            IgnoreEntry::Cidr(cidr) => cidr.contains(&ip),
        })
    }
}

#[cfg(test)]
#[path = "jail.test.rs"]
mod tests;
