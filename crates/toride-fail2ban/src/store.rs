//! JSON-based persistent storage for ban entries and log journals.
//!
//! Uses atomic write (temp file + rename) to prevent corruption.
//!
//! Design note: `Store` is intentionally stateless -- every public method reads
//! the JSON file from disk and writes it back after mutation. This keeps the
//! implementation simple and correct for a single-process tool: there is no
//! in-memory cache that can drift out of sync with the on-disk state, and
//! concurrent writers (if any) always see the latest snapshot. The trade-off is
//! that each operation pays the cost of a full deserialize/serialize round-trip,
//! which is acceptable at the expected data volumes (hundreds of bans). If
//! profiling reveals this becomes a bottleneck, interior mutability via
//! `RefCell<Option<StoreData>>` can be added behind the existing `&self` API
//! without changing callers.
//!
//! # Concurrency Warning
//!
//! `Store` is **not safe for concurrent access from multiple processes or
//! threads**. Every mutation follows a load-modify-save pattern with no file
//! locking. If two processes mutate the store simultaneously, the last writer
//! wins and the first writer's changes are silently lost. The PID file
//! singleton enforcement in [`crate::manager::Fail2BanManager`] prevents
//! multiple daemon instances from running at the same time, which is
//! sufficient for the intended single-daemon usage. For multi-process
//! scenarios, an `fd-lock` or `Mutex`-based wrapper would be required.

use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::types::BanEntry;

/// Persistent store for ban entries.
///
/// **Not safe for concurrent access.** Each operation is a standalone
/// load-modify-save cycle with no file locking. The PID file singleton in
/// [`crate::manager::Fail2BanManager`] prevents multiple daemon instances.
#[derive(Debug, Clone)]
pub struct Store {
    /// Path to the ban database file.
    path: PathBuf,
}

/// The on-disk format for the ban store.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct StoreData {
    /// Currently active bans.
    pub active_bans: Vec<BanEntry>,
    /// Historical bans (expired or removed).
    pub history: Vec<BanEntry>,
    /// Journal entries tracking log file scan positions.
    pub journals: Vec<JournalEntry>,
}

/// Tracks the last-read position in a log file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
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
    #[must_use]
    pub const fn new(path: PathBuf) -> Self {
        Self { path }
    }

    /// Load store data from disk. Returns empty data if file doesn't exist.
    pub fn load(&self) -> crate::Result<StoreData> {
        if !self.path.exists() {
            return Ok(StoreData::default());
        }
        let content = fs::read_to_string(&self.path).map_err(|e| {
            crate::Error::Io(std::io::Error::new(
                e.kind(),
                format!("Failed to read '{}': {e}", self.path.display()),
            ))
        })?;
        let data: StoreData = serde_json::from_str(&content).map_err(|e| {
            crate::Error::InvalidConfig(format!(
                "Corrupt ban database '{}': {e}",
                self.path.display()
            ))
        })?;
        Ok(data)
    }

    /// Save store data to disk using atomic write with fsync.
    pub fn save(&self, data: &StoreData) -> crate::Result<()> {
        let content = serde_json::to_string_pretty(data)?;
        let tmp_path = self
            .path
            .with_extension(format!("json.tmp.{}", std::process::id()));

        // Atomic write: write to temp, fsync, then rename.
        fs::write(&tmp_path, &content)?;
        let file = fs::File::open(&tmp_path)?;
        file.sync_all()?;
        drop(file);
        if let Err(e) = fs::rename(&tmp_path, &self.path) {
            let _ = fs::remove_file(&tmp_path);
            return Err(crate::Error::Io(std::io::Error::new(
                e.kind(),
                format!("Failed to atomically update '{}': {e}", self.path.display()),
            )));
        }
        Ok(())
    }

    /// Add a ban entry.
    ///
    /// # Errors
    ///
    /// Returns `AlreadyBanned` if the IP is already banned in this jail.
    pub fn add_ban(&self, entry: &BanEntry) -> crate::Result<()> {
        let mut data = self.load()?;

        if data
            .active_bans
            .iter()
            .any(|b| b.ip == entry.ip && b.jail_name == entry.jail_name)
        {
            return Err(crate::Error::AlreadyBanned(entry.ip.to_string()));
        }

        data.active_bans.push(entry.clone());
        self.save(&data)
    }

    /// Remove a ban entry. Returns the removed entry.
    ///
    /// # Errors
    ///
    /// Returns `NotBanned` if the IP is not found in this jail.
    pub fn remove_ban(&self, ip: IpAddr, jail_name: &str) -> crate::Result<BanEntry> {
        let mut data = self.load()?;

        let pos = data
            .active_bans
            .iter()
            .position(|b| b.ip == ip && b.jail_name == jail_name);
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
            Some(name) => data
                .active_bans
                .into_iter()
                .filter(|b| b.jail_name == name)
                .collect(),
            None => data.active_bans,
        })
    }

    /// Clear expired bans and move them to history.
    pub fn clear_expired(&self) -> crate::Result<Vec<BanEntry>> {
        let mut data = self.load()?;
        let now = Utc::now();

        // Partition active bans into expired and still-active, consuming the
        // original Vec via into_iter to avoid cloning BanEntry values.
        let active_bans = std::mem::take(&mut data.active_bans);
        let (expired, active): (Vec<_>, Vec<_>) = active_bans
            .into_iter()
            .partition(|b| b.expires_at.is_some_and(|exp| exp <= now));

        data.active_bans = active;
        // Clone each entry into history in one allocation pass, avoiding the
        // temporary Vec that `extend(expired.clone())` would create.
        data.history.extend_from_slice(&expired);
        self.save(&data)?;

        Ok(expired)
    }

    /// Update journal entry for a log file scan.
    pub fn update_journal(&self, entry: JournalEntry) -> crate::Result<()> {
        let mut data = self.load()?;

        if let Some(existing) = data
            .journals
            .iter_mut()
            .find(|j| j.jail_name == entry.jail_name && j.log_path == entry.log_path)
        {
            *existing = entry;
        } else {
            data.journals.push(entry);
        }

        self.save(&data)
    }

    /// Get journal entry for a specific jail.
    pub fn get_journal(
        &self,
        jail_name: &str,
        log_path: &Path,
    ) -> crate::Result<Option<JournalEntry>> {
        let data = self.load()?;
        Ok(data
            .journals
            .into_iter()
            .find(|j| j.jail_name == jail_name && j.log_path == log_path))
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
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Count historical bans for a specific jail.
    ///
    /// Returns 0 if the store cannot be loaded (with a logged warning).
    pub fn history_count_for_jail(&self, jail_name: &str) -> u64 {
        match self.load() {
            Ok(data) => data
                .history
                .iter()
                .filter(|b| b.jail_name == jail_name)
                .count() as u64,
            Err(e) => {
                tracing::warn!(jail = %jail_name, error = %e, "failed to load history count, returning 0");
                0
            }
        }
    }
}

#[cfg(test)]
#[path = "store.test.rs"]
mod tests;
