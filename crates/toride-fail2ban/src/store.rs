//! JSON-based persistent storage for ban entries and log journals.
//!
//! Uses atomic write (temp file + rename) to prevent corruption.

use std::fs;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::types::BanEntry;

/// Persistent store for ban entries.
#[derive(Debug, Clone)]
pub struct Store {
    /// Path to the ban database file.
    path: PathBuf,
}

/// The on-disk format for the ban store.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StoreData {
    /// Currently active bans.
    pub active_bans: Vec<BanEntry>,
    /// Historical bans (expired or removed).
    pub history: Vec<BanEntry>,
    /// Journal entries tracking log file scan positions.
    pub journals: Vec<JournalEntry>,
}

/// Tracks the last-read position in a log file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct JournalEntry {
    /// Jail name this journal belongs to.
    pub jail_name: String,
    /// Path to the log file.
    pub log_path: PathBuf,
    /// Last read byte offset.
    pub offset: u64,
    /// Last read line number.
    pub line_number: u64,
    /// When this journal was last updated.
    pub updated_at: DateTime<Utc>,
}

impl Store {
    /// Open or create a store at the given path.
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    /// Load store data from disk. Returns empty data if file doesn't exist.
    pub fn load(&self) -> crate::Result<StoreData> {
        if !self.path.exists() {
            return Ok(StoreData::default());
        }
        let content = fs::read_to_string(&self.path)?;
        let data: StoreData = serde_json::from_str(&content)?;
        Ok(data)
    }

    /// Save store data to disk using atomic write.
    pub fn save(&self, data: &StoreData) -> crate::Result<()> {
        let content = serde_json::to_string_pretty(data)?;
        let tmp_path = self.path.with_extension("json.tmp");

        // Atomic write: write to temp, then rename.
        fs::write(&tmp_path, &content)?;
        fs::rename(&tmp_path, &self.path)?;
        Ok(())
    }

    /// Add a ban entry. Returns error if IP is already banned in this jail.
    pub fn add_ban(&self, entry: BanEntry) -> crate::Result<()> {
        let mut data = self.load()?;

        let already_banned = data.active_bans.iter().any(|b| {
            b.ip == entry.ip && b.jail_name == entry.jail_name
        });
        if already_banned {
            return Err(crate::Error::AlreadyBanned(entry.ip.to_string()));
        }

        data.active_bans.push(entry);
        self.save(&data)
    }

    /// Remove a ban entry. Returns the removed entry.
    pub fn remove_ban(&self, ip: &str, jail_name: &str) -> crate::Result<BanEntry> {
        let mut data = self.load()?;

        let pos = data.active_bans.iter().position(|b| {
            b.ip.to_string() == ip && b.jail_name == jail_name
        });
        let pos = pos.ok_or_else(|| crate::Error::NotBanned(ip.to_string()))?;

        let entry = data.active_bans.remove(pos);
        data.history.push(entry.clone());
        self.save(&data)?;
        Ok(entry)
    }

    /// Get all active bans, optionally filtered by jail name.
    pub fn get_bans(&self, jail_name: Option<&str>) -> crate::Result<Vec<BanEntry>> {
        let data = self.load()?;
        Ok(match jail_name {
            Some(name) => data.active_bans.into_iter().filter(|b| b.jail_name == name).collect(),
            None => data.active_bans,
        })
    }

    /// Clear expired bans and move them to history.
    pub fn clear_expired(&self) -> crate::Result<Vec<BanEntry>> {
        let mut data = self.load()?;
        let now = Utc::now();

        let (expired, active): (Vec<_>, Vec<_>) = data.active_bans.into_iter().partition(|b| {
            b.expires_at.is_some_and(|exp| exp <= now)
        });

        data.active_bans = active;
        data.history.extend(expired.clone());
        self.save(&data)?;

        Ok(expired)
    }

    /// Update journal entry for a log file scan.
    pub fn update_journal(&self, entry: JournalEntry) -> crate::Result<()> {
        let mut data = self.load()?;

        if let Some(existing) = data.journals.iter_mut().find(|j| {
            j.jail_name == entry.jail_name && j.log_path == entry.log_path
        }) {
            *existing = entry;
        } else {
            data.journals.push(entry);
        }

        self.save(&data)
    }

    /// Get journal entry for a specific jail.
    pub fn get_journal(&self, jail_name: &str, log_path: &Path) -> crate::Result<Option<JournalEntry>> {
        let data = self.load()?;
        Ok(data.journals.into_iter().find(|j| {
            j.jail_name == jail_name && j.log_path == log_path
        }))
    }

    /// Trim history to keep only the most recent entries.
    pub fn trim_history(&self, max_entries: usize) -> crate::Result<()> {
        let mut data = self.load()?;
        let len = data.history.len();
        if len > max_entries {
            data.history.drain(..len - max_entries);
            self.save(&data)?;
        }
        Ok(())
    }

    /// Get the store path.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(test)]
#[path = "store.test.rs"]
mod tests;
