//! Durable ledger of completed VPS actions.
//!
//! [`ServiceManager::deploy_unit`](crate::ServiceManager::deploy_unit)
//! appends one [`ActionRecord`] after its post-start activity check
//! succeeds, so the ledger never claims a unit that failed to start.
//! [`ServiceManager::install_unit`](crate::ServiceManager::install_unit)
//! records nothing: it starts no unit and verifies no activity. Remote
//! exec and upload actions are recorded by whoever drives them, not by
//! this crate.
//!
//! # Storage
//!
//! One JSON document, by default `.toride-action-ledger.json` inside the
//! units root the manager writes to. The path is injectable through
//! [`ActionLedger::at`], so every operation is testable offline. Saves
//! are atomic (`toride-fs` temp-then-rename at mode 0600); a crash
//! mid-save leaves either the previous document or the complete new one.
//! Concurrent writers are last-rename-wins; deploys through a single
//! [`ServiceManager`](crate::ServiceManager) serialize on the units lock.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// File name of the action ledger inside a units root.
pub const LEDGER_FILE: &str = ".toride-action-ledger.json";

/// Schema version written into the document and enforced on load: a
/// document whose version differs is rejected before its body is
/// trusted, so a newer writer's ledger can never load as a silent empty
/// ledger whose next save would clobber it.
const SCHEMA_VERSION: u32 = 1;

/// Mode bits of the ledger document: owner-only, matching the secrets
/// discipline of ssh config state on the same host.
const LEDGER_MODE: u32 = 0o600;

/// Failures of the action ledger's persistence operations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum LedgerError {
    /// Reading or writing the ledger file failed. A missing file is not
    /// this: [`ActionLedger::records`] treats it as an empty ledger.
    #[error("action ledger I/O failed: {0}")]
    Io(#[from] std::io::Error),

    /// The ledger document exists but cannot be interpreted: corrupt
    /// JSON, a hand-mangled body, or an unsupported schema version.
    #[error("action ledger is corrupt: {0}")]
    Corrupt(String),

    /// An atomic write delegated to `toride-fs` failed.
    #[error("action ledger write failed: {0}")]
    Write(#[from] toride_fs::Error),
}

/// Convenience alias for results of ledger persistence operations.
pub type LedgerResult<T> = std::result::Result<T, LedgerError>;

/// The completed action kinds the ledger records.
///
/// Serialized as an internally tagged value, for example
/// `{"action":"unit_deployed","unit":"app.service"}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
#[non_exhaustive]
pub enum ActionKind {
    /// A unit installed, started, and confirmed active by one
    /// [`deploy_unit`](crate::ServiceManager::deploy_unit) call.
    UnitDeployed {
        /// The deployed unit name, as validated by the manager.
        unit: String,
    },
}

/// One completed action, serialized into the ledger document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionRecord {
    /// The action that completed, flattened so its `"action"` tag and
    /// payload fields sit beside [`Self::epoch_seconds`].
    #[serde(flatten)]
    pub action: ActionKind,
    /// Wall-clock epoch seconds at completion.
    pub epoch_seconds: u64,
}

impl ActionRecord {
    /// Record `action` stamped with the current wall clock.
    #[must_use]
    pub fn now(action: ActionKind) -> Self {
        Self {
            action,
            epoch_seconds: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.as_secs()),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct LedgerDocument {
    version: u32,
    actions: Vec<ActionRecord>,
}

impl LedgerDocument {
    fn empty() -> Self {
        Self {
            version: SCHEMA_VERSION,
            actions: Vec::new(),
        }
    }
}

#[derive(Debug, Deserialize)]
struct VersionProbe {
    version: u32,
}

/// Append-only record store backed by one JSON document.
#[derive(Debug, Clone)]
pub struct ActionLedger {
    path: PathBuf,
}

impl ActionLedger {
    /// A ledger bound to `path`.
    #[must_use]
    pub fn at(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// The ledger for `root`/[`LEDGER_FILE`], the location
    /// [`ServiceManager`](crate::ServiceManager) writes by default.
    #[must_use]
    pub fn in_root(root: &Path) -> Self {
        Self::at(root.join(LEDGER_FILE))
    }

    /// The bound ledger path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// All records in document order (oldest first).
    ///
    /// # Errors
    ///
    /// Returns [`LedgerError::Io`] when the document cannot be read and
    /// [`LedgerError::Corrupt`] when it exists but cannot be interpreted,
    /// including an unsupported schema version. A missing file is an
    /// empty ledger, never an error.
    pub fn records(&self) -> LedgerResult<Vec<ActionRecord>> {
        Ok(self.load()?.actions)
    }

    /// Append `record` and save the document atomically.
    ///
    /// # Errors
    ///
    /// Returns any error of [`ActionLedger::records`], plus
    /// [`LedgerError::Write`] when the atomic save fails. On error the
    /// document on disk is unchanged.
    pub fn append(&self, record: ActionRecord) -> LedgerResult<()> {
        let mut document = self.load()?;
        document.actions.push(record);
        let raw =
            serde_json::to_string(&document).map_err(|e| LedgerError::Corrupt(e.to_string()))?;
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        toride_fs::atomic_write_with_perms(&self.path, &raw, LEDGER_MODE)?;
        Ok(())
    }

    fn load(&self) -> LedgerResult<LedgerDocument> {
        let raw = match std::fs::read_to_string(&self.path) {
            Ok(raw) => raw,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(LedgerDocument::empty());
            }
            Err(e) => return Err(e.into()),
        };
        let probe: VersionProbe =
            serde_json::from_str(&raw).map_err(|e| LedgerError::Corrupt(e.to_string()))?;
        if probe.version != SCHEMA_VERSION {
            return Err(LedgerError::Corrupt(format!(
                "schema version {probe_version} is not the supported version {SCHEMA_VERSION}",
                probe_version = probe.version
            )));
        }
        serde_json::from_str(&raw).map_err(|e| LedgerError::Corrupt(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_ledger() -> (tempfile::TempDir, ActionLedger) {
        let dir = tempfile::tempdir().expect("temp dir creation should succeed");
        let ledger = ActionLedger::at(dir.path().join(LEDGER_FILE));
        (dir, ledger)
    }

    fn unit_deployed(name: &str) -> ActionRecord {
        ActionRecord::now(ActionKind::UnitDeployed {
            unit: name.to_owned(),
        })
    }

    #[test]
    fn missing_file_is_an_empty_ledger() {
        let (_dir, ledger) = temp_ledger();
        assert_eq!(ledger.records().unwrap(), Vec::new());
    }

    #[test]
    fn append_then_records_round_trips_in_order() {
        let (_dir, ledger) = temp_ledger();
        ledger.append(unit_deployed("a.service")).unwrap();
        ledger.append(unit_deployed("b.service")).unwrap();

        let records = ledger.records().unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(
            records[0].action,
            ActionKind::UnitDeployed {
                unit: String::from("a.service")
            }
        );
        assert_eq!(
            records[1].action,
            ActionKind::UnitDeployed {
                unit: String::from("b.service")
            }
        );
    }

    #[test]
    fn append_creates_missing_parent_directories() {
        let dir = tempfile::tempdir().expect("temp dir creation should succeed");
        let ledger = ActionLedger::at(dir.path().join("nested").join("state").join(LEDGER_FILE));

        ledger.append(unit_deployed("a.service")).unwrap();

        assert_eq!(ledger.records().unwrap().len(), 1);
    }

    #[test]
    fn corrupt_json_is_rejected() {
        let (_dir, ledger) = temp_ledger();
        std::fs::write(ledger.path(), "{ not json").unwrap();

        let err = ledger.records().unwrap_err();
        assert!(matches!(err, LedgerError::Corrupt(_)), "got {err:?}");
    }

    #[test]
    fn version_mismatch_is_rejected_before_the_body_is_trusted() {
        let (_dir, ledger) = temp_ledger();
        std::fs::write(
            ledger.path(),
            r#"{"version":2,"actions":[{"action":"unit_deployed","unit":"a.service","epoch_seconds":1}]}"#,
        )
        .unwrap();

        let err = ledger.records().unwrap_err();
        assert!(
            matches!(&err, LedgerError::Corrupt(m) if m.contains("version 2")),
            "got {err:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn failed_append_leaves_the_document_unchanged() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("temp dir creation should succeed");
        let state = dir.path().join("state");
        std::fs::create_dir(&state).unwrap();
        let ledger = ActionLedger::at(state.join(LEDGER_FILE));

        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o555)).unwrap();
        let attempted = ledger.append(unit_deployed("a.service"));
        let writable_anyway = attempted.is_ok();
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o755)).unwrap();
        if writable_anyway {
            return;
        }

        let err = attempted.expect_err("append into an unwritable directory must fail");
        assert!(matches!(err, LedgerError::Write(_)), "got {err:?}");
        assert!(
            !ledger.path().exists(),
            "the failed append must not create the document"
        );
    }

    #[test]
    fn record_serializes_as_an_internally_tagged_value() {
        let record = ActionRecord {
            action: ActionKind::UnitDeployed {
                unit: String::from("app.service"),
            },
            epoch_seconds: 1_700_000_000,
        };
        let raw = serde_json::to_string(&record).unwrap();
        assert_eq!(
            raw,
            r#"{"action":"unit_deployed","unit":"app.service","epoch_seconds":1700000000}"#
        );
        let parsed: ActionRecord = serde_json::from_str(&raw).unwrap();
        assert_eq!(parsed, record);
    }
}
