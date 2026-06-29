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
    ///
    /// Host bits are normalized (zeroed) so that `PartialEq` and `Hash`
    /// behave correctly: `CidrBlock::new("192.168.1.5", 24)` equals
    /// `CidrBlock::new("192.168.1.0", 24)`.
    pub fn new(addr: IpAddr, prefix: u8) -> crate::Result<Self> {
        let max_prefix = crate::types::default_prefix(addr);
        if prefix > max_prefix {
            return Err(crate::Error::InvalidIp(format!(
                "Prefix /{prefix} exceeds maximum /{max_prefix} for {addr}"
            )));
        }
        // Normalize host bits to zero so that equality and hashing are correct.
        let normalized = match addr {
            IpAddr::V4(v4) => {
                if prefix == 0 {
                    IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
                } else if prefix == 32 {
                    addr
                } else {
                    let mask = !((1u32 << (32 - prefix)) - 1);
                    IpAddr::V4(std::net::Ipv4Addr::from(u32::from(v4) & mask))
                }
            }
            IpAddr::V6(v6) => {
                if prefix == 0 {
                    IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
                } else if prefix == 128 {
                    addr
                } else {
                    let mask = !((1u128 << (128 - prefix)) - 1);
                    IpAddr::V6(std::net::Ipv6Addr::from(u128::from(v6) & mask))
                }
            }
        };
        Ok(Self {
            addr: normalized,
            prefix,
        })
    }

    /// Get the network address.
    #[must_use]
    pub const fn addr(&self) -> IpAddr {
        self.addr
    }

    /// Get the prefix length.
    #[must_use]
    pub const fn prefix(&self) -> u8 {
        self.prefix
    }

    /// Check if an IP address falls within this CIDR block.
    #[must_use]
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

impl std::str::FromStr for CidrBlock {
    type Err = crate::Error;

    /// Parse a CIDR block from a string like `"192.168.1.0/24"` or `"::1/128"`.
    /// A plain IP address (without `/prefix`) is treated as a host block
    /// (`/32` for IPv4, `/128` for IPv6).
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some((addr_str, prefix_str)) = s.split_once('/') {
            let addr: IpAddr = addr_str.parse().map_err(|_| {
                crate::Error::InvalidIp(format!("invalid IP address in CIDR: '{addr_str}'"))
            })?;
            let prefix: u8 = prefix_str.parse().map_err(|_| {
                crate::Error::InvalidIp(format!("invalid prefix in CIDR: '{prefix_str}'"))
            })?;
            Self::new(addr, prefix)
        } else {
            let addr: IpAddr = s
                .parse()
                .map_err(|_| crate::Error::InvalidIp(format!("invalid IP address: '{s}'")))?;
            let prefix = crate::types::default_prefix(addr);
            Self::new(addr, prefix)
        }
    }
}

/// A set of CIDR blocks for efficient IP containment checks.
#[derive(Debug, Clone, Default)]
pub struct CidrSet {
    v4: Vec<(u32, u32)>,   // (network_bits, mask) for IPv4
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
                    let ip = u32::from(addr);
                    let _ = self.singles_v4.insert(ip);
                } else if block.prefix() == 0 {
                    self.v4.push((0u32, 0u32));
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
    #[must_use]
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
                } else if block.prefix() == 0 {
                    let len_before = self.v4.len();
                    self.v4.retain(|&(net, mask)| net != 0u32 || mask != 0u32);
                    self.v4.len() < len_before
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
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.v4.is_empty()
            && self.v6.is_empty()
            && self.singles_v4.is_empty()
            && self.singles_v6.is_empty()
    }
}

/// High-level ban manager combining storage and CIDR checking.
pub struct BanManager {
    store: Store,
}

impl BanManager {
    /// Create a new ban manager.
    #[must_use]
    pub const fn new(store: Store) -> Self {
        Self { store }
    }

    /// Get a reference to the underlying store.
    #[must_use]
    pub const fn store(&self) -> &Store {
        &self.store
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
        let ban_duration_i64 = i64::try_from(ban_duration_secs).map_err(|_| {
            crate::Error::InvalidConfig(format!("ban duration {ban_duration_secs} exceeds maximum"))
        })?;
        let entry = BanEntry {
            ip,
            prefix,
            banned_at: now,
            expires_at: Some(now + Duration::seconds(ban_duration_i64)),
            jail_name: jail_name.to_string(),
            fail_count,
            last_fail_at: now,
            reason,
        };
        self.store.add_ban(&entry)?;
        Ok(entry)
    }

    /// Unban an IP address.
    ///
    /// First attempts an exact IP match. If that fails, searches for a
    /// CIDR ban whose block contains the given IP (e.g., unbanning
    /// `10.1.2.3` will find and remove a `10.0.0.0/8` ban).
    ///
    /// # Errors
    ///
    /// Returns `NotBanned` if the IP is not currently banned.
    pub fn unban(&self, ip: IpAddr, jail_name: &str) -> crate::Result<BanEntry> {
        // Try exact IP match first.
        match self.store.remove_ban(ip, jail_name) {
            Ok(entry) => return Ok(entry),
            Err(crate::Error::NotBanned(_)) => {}
            Err(e) => return Err(e),
        }

        // Search for a CIDR ban that contains this IP.
        let bans = self.store.get_bans(Some(jail_name))?;
        for ban in &bans {
            if ban.prefix < crate::types::default_prefix(ban.ip)
                && let Ok(block) = CidrBlock::new(ban.ip, ban.prefix)
                && block.contains(ip)
            {
                return self.store.remove_ban(ban.ip, jail_name);
            }
        }

        Err(crate::Error::NotBanned(ip.to_string()))
    }

    /// Check if an IP is currently banned.
    ///
    /// Uses CIDR-aware matching: an IP is considered banned if it falls
    /// within any banned CIDR block (e.g., `10.1.2.3` matches a `10.0.0.0/8` ban).
    pub fn is_banned(&self, ip: IpAddr) -> crate::Result<bool> {
        let bans = self.store.get_bans(None)?;
        for ban in &bans {
            if ban.ip == ip {
                return Ok(true);
            }
            // Check CIDR containment for subnet bans.
            if ban.prefix < crate::types::default_prefix(ban.ip)
                && let Ok(block) = CidrBlock::new(ban.ip, ban.prefix)
                && block.contains(ip)
            {
                return Ok(true);
            }
        }
        Ok(false)
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
