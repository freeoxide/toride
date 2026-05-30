//! IP address parsing, subnet matching, and ban management.
//!
//! Provides `CidrSet` for efficient CIDR-based IP lookups and `BanManager`
//! for high-level ban/unban operations.

use std::collections::HashSet;
use std::net::IpAddr;

use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::store::Store;
use crate::types::BanEntry;

/// A CIDR network block.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CidrBlock {
    /// Network address.
    addr: IpAddr,
    /// Prefix length (e.g., 24 for /24).
    prefix: u8,
}

impl CidrBlock {
    /// Create a new CIDR block.
    pub fn new(addr: IpAddr, prefix: u8) -> crate::Result<Self> {
        let max_prefix = match addr {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if prefix > max_prefix {
            return Err(crate::Error::InvalidIp(format!(
                "Prefix /{prefix} exceeds maximum /{max_prefix} for {addr}"
            )));
        }
        Ok(Self { addr, prefix })
    }

    /// Get the network address.
    pub fn addr(&self) -> IpAddr { self.addr }

    /// Get the prefix length.
    pub fn prefix(&self) -> u8 { self.prefix }

    /// Check if an IP address falls within this CIDR block.
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(host)) => {
                if self.prefix == 0 {
                    return true;
                }
                let mask = !((1u32 << (32 - self.prefix)) - 1);
                let net_bits = u32::from(net) & mask;
                let host_bits = u32::from(host) & mask;
                net_bits == host_bits
            }
            (IpAddr::V6(net), IpAddr::V6(host)) => {
                let net_bits = u128::from(net);
                let host_bits = u128::from(host);
                if self.prefix == 0 {
                    return true;
                }
                let mask = !((1u128 << (128 - self.prefix)) - 1);
                (net_bits & mask) == (host_bits & mask)
            }
            _ => false, // IPv4 vs IPv6 mismatch
        }
    }
}

impl std::fmt::Display for CidrBlock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

/// A set of CIDR blocks for efficient IP containment checks.
#[derive(Debug, Clone, Default)]
pub struct CidrSet {
    v4: Vec<(u32, u32)>, // (network_bits, mask) for IPv4
    v6: Vec<(u128, u128)>, // (network_bits, mask) for IPv6
    singles_v4: HashSet<u32>,
    singles_v6: HashSet<u128>,
}

impl CidrSet {
    /// Create an empty CIDR set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a CIDR block to the set.
    pub fn insert(&mut self, block: CidrBlock) {
        match block.addr() {
            IpAddr::V4(addr) => {
                if block.prefix() == 32 {
                    self.singles_v4.insert(u32::from(addr));
                } else {
                    let mask = !((1u32 << (32 - block.prefix())) - 1);
                    let net = u32::from(addr) & mask;
                    self.v4.push((net, mask));
                }
            }
            IpAddr::V6(addr) => {
                if block.prefix() == 128 {
                    self.singles_v6.insert(u128::from(addr));
                } else {
                    let mask = if block.prefix() == 0 {
                        0
                    } else {
                        !((1u128 << (128 - block.prefix())) - 1)
                    };
                    let net = u128::from(addr) & mask;
                    self.v6.push((net, mask));
                }
            }
        }
    }

    /// Check if an IP is contained in any block in this set.
    pub fn contains(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(addr) => {
                let bits = u32::from(addr);
                if self.singles_v4.contains(&bits) {
                    return true;
                }
                self.v4.iter().any(|&(net, mask)| (bits & mask) == net)
            }
            IpAddr::V6(addr) => {
                let bits = u128::from(addr);
                if self.singles_v6.contains(&bits) {
                    return true;
                }
                self.v6.iter().any(|&(net, mask)| (bits & mask) == net)
            }
        }
    }

    /// Remove a CIDR block from the set.
    pub fn remove(&mut self, block: &CidrBlock) -> bool {
        match block.addr() {
            IpAddr::V4(addr) => {
                if block.prefix() == 32 {
                    self.singles_v4.remove(&u32::from(addr))
                } else {
                    let mask = !((1u32 << (32 - block.prefix())) - 1);
                    let net = u32::from(addr) & mask;
                    let len_before = self.v4.len();
                    self.v4.retain(|&(n, m)| !(n == net && m == mask));
                    self.v4.len() < len_before
                }
            }
            IpAddr::V6(addr) => {
                if block.prefix() == 128 {
                    self.singles_v6.remove(&u128::from(addr))
                } else {
                    let mask = if block.prefix() == 0 {
                        0
                    } else {
                        !((1u128 << (128 - block.prefix())) - 1)
                    };
                    let net = u128::from(addr) & mask;
                    let len_before = self.v6.len();
                    self.v6.retain(|&(n, m)| !(n == net && m == mask));
                    self.v6.len() < len_before
                }
            }
        }
    }

    /// Check if the set is empty.
    pub fn is_empty(&self) -> bool {
        self.v4.is_empty() && self.v6.is_empty() && self.singles_v4.is_empty() && self.singles_v6.is_empty()
    }
}

/// High-level ban manager combining storage and CIDR checking.
pub struct BanManager {
    store: Store,
}

impl BanManager {
    /// Create a new ban manager.
    pub fn new(store: Store) -> Self {
        Self { store }
    }

    /// Ban an IP address.
    ///
    /// # Errors
    ///
    /// Returns `AlreadyBanned` if the IP is already banned.
    pub fn ban(
        &self,
        ip: IpAddr,
        prefix: u8,
        jail_name: &str,
        fail_count: u32,
        ban_duration_secs: u64,
        reason: Option<String>,
    ) -> crate::Result<BanEntry> {
        let now = Utc::now();
        let entry = BanEntry {
            ip,
            prefix,
            banned_at: now,
            #[expect(clippy::cast_possible_wrap, reason = "ban duration fits in i64")]
            expires_at: Some(now + Duration::seconds(ban_duration_secs as i64)),
            jail_name: jail_name.to_string(),
            fail_count,
            last_fail_at: now,
            reason,
        };
        self.store.add_ban(entry.clone())?;
        Ok(entry)
    }

    /// Unban an IP address.
    ///
    /// # Errors
    ///
    /// Returns `NotBanned` if the IP is not currently banned.
    pub fn unban(&self, ip: IpAddr, jail_name: &str) -> crate::Result<BanEntry> {
        self.store.remove_ban(ip, jail_name)
    }

    /// Check if an IP is currently banned.
    pub fn is_banned(&self, ip: IpAddr) -> crate::Result<bool> {
        let bans = self.store.get_bans(None)?;
        Ok(bans.iter().any(|b| b.ip == ip))
    }

    /// List all active bans, optionally filtered by jail.
    pub fn list_bans(&self, jail_name: Option<&str>) -> crate::Result<Vec<BanEntry>> {
        self.store.get_bans(jail_name)
    }

    /// Purge expired bans.
    pub fn purge_expired(&self) -> crate::Result<Vec<BanEntry>> {
        self.store.clear_expired()
    }
}

#[cfg(test)]
#[path = "ban.test.rs"]
mod tests;
