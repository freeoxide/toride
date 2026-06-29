//! INI config file manager for Fail2Ban managed snippets.
//!
//! This module handles reading and writing Fail2Ban INI config snippets with
//! atomic writes, automatic backups, managed-file headers, and namespace-based
//! file management. It is the filesystem layer between the typed spec/render
//! modules and the actual Fail2Ban config directories.
//!
//! # Managed files
//!
//! Every file written by this module carries a managed header at the top:
//!
//! ```ini
//! # Managed by fail2ban-kit.
//! # Do not edit manually unless you also disable this manager.
//! ```
//!
//! Files without this header are never overwritten or deleted, preventing
//! accidental mutation of stock or human-edited configurations.
//!
//! # Atomic writes
//!
//! All writes use `tempfile::NamedTempFile` in the target directory, followed
//! by `persist()` (atomic rename). This ensures that readers never see a
//! partially-written config file.
//!
//! # Advisory locking
//!
//! Advisory locking via `fd-lock` for coordination between concurrent processes.
//! This is **NOT** a security boundary -- it prevents conflicting writes from
//! this library, not adversarial access. Every write and remove operation
//! acquires an exclusive write lock on `{config_dir}/.fail2ban-kit.lock`
//! before proceeding. The lock is released automatically when the operation
//! completes (RAII via [`fd_lock::RwLockWriteGuard`]).
//!
//! # Backups
//!
//! Before overwriting an existing managed file, a timestamped backup is created
//! at `{original}.bak-{timestamp}`. Backups are only created for files that
//! already exist.
//!
//! # Namespace
//!
//! Files are namespaced to avoid colliding with stock or other tool-managed
//! configs. The default namespace is [`DEFAULT_NAMESPACE`]. File names follow
//! the pattern `{namespace}-{name}.local` in the appropriate `jail.d`,
//! `filter.d`, or `action.d` subdirectory.
//!
//! # Example
//!
//! ```ignore
//! use std::path::Path;
//! use toride_fail2ban::ini::IniManager;
//!
//! let mgr = IniManager::new(Path::new("/etc/fail2ban"))?;
//!
//! // Write a jail config (spec constructed elsewhere)
//! // let report = mgr.write_jail(&jail_spec)?;
//!
//! // List all managed files
//! let managed = mgr.list_managed()?;
//! for file in &managed {
//!     println!("{}: {:?}", file.kind, file.path.display());
//! }
//! ```

use std::fs::File;
use std::path::{Path, PathBuf};

use crate::render;
use crate::report::ApplyReport;
use crate::spec::*;
use crate::{Error, Result};
use fd_lock::RwLock;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default namespace prefix for managed config files.
///
/// All generated files are named `{namespace}-{name}.local` to avoid
/// colliding with stock Fail2Ban configs.
pub const DEFAULT_NAMESPACE: &str = "managed-by-fail2ban-kit";

// ---------------------------------------------------------------------------
// ManagedFile types
// ---------------------------------------------------------------------------

/// Category of a managed Fail2Ban config file.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ManagedFileKind {
    /// A jail config in `jail.d/`.
    Jail,
    /// A filter config in `filter.d/`.
    Filter,
    /// An action config in `action.d/`.
    Action,
}

impl std::fmt::Display for ManagedFileKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Jail => write!(f, "jail"),
            Self::Filter => write!(f, "filter"),
            Self::Action => write!(f, "action"),
        }
    }
}

/// A managed Fail2Ban config file discovered on disk.
#[derive(Debug, Clone)]
pub struct ManagedFile {
    /// Absolute path to the file on disk.
    pub path: PathBuf,
    /// Category of config file.
    pub kind: ManagedFileKind,
    /// Extracted name (the `{name}` portion of `{namespace}-{name}.local`).
    pub name: String,
}

// ---------------------------------------------------------------------------
// IniManager
// ---------------------------------------------------------------------------

/// Manages Fail2Ban INI config snippets on disk.
///
/// Provides atomic write, backup, removal, and query operations for jail,
/// filter, and action `.local` files within a Fail2Ban config directory tree.
///
/// # Directory layout
///
/// ```text
/// {config_dir}/
///   jail.d/{namespace}-{name}.local
///   filter.d/{namespace}-{name}.local
///   action.d/{namespace}-{name}.local
/// ```
#[derive(Debug)]
pub struct IniManager {
    /// Root Fail2Ban config directory (e.g. `/etc/fail2ban`).
    #[allow(dead_code, reason = "retained for future use and Debug output")]
    config_dir: PathBuf,
    /// Jail drop-in directory: `{config_dir}/jail.d`.
    jail_d: PathBuf,
    /// Filter drop-in directory: `{config_dir}/filter.d`.
    filter_d: PathBuf,
    /// Action drop-in directory: `{config_dir}/action.d`.
    action_d: PathBuf,
    /// Namespace prefix for all managed files.
    namespace: String,
}

impl IniManager {
    // -----------------------------------------------------------------------
    // Constructors
    // -----------------------------------------------------------------------

    /// Create a new manager for the given Fail2Ban config directory using the
    /// default namespace ([`DEFAULT_NAMESPACE`]).
    ///
    /// Validates that `config_dir` exists and is a directory.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ConfigNotFound`] if `config_dir` does not exist.
    pub fn new(config_dir: &Path) -> Result<Self> {
        Self::with_namespace(config_dir, DEFAULT_NAMESPACE)
    }

    /// Create a new manager with a custom namespace.
    ///
    /// The namespace is used as a prefix in all generated filenames:
    /// `{namespace}-{name}.local`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ConfigNotFound`] if `config_dir` does not exist.
    pub fn with_namespace(config_dir: &Path, namespace: &str) -> Result<Self> {
        if !config_dir.is_dir() {
            return Err(Error::ConfigNotFound(format!(
                "Fail2Ban config directory does not exist: {}",
                config_dir.display()
            )));
        }
        Ok(Self {
            config_dir: config_dir.to_path_buf(),
            jail_d: config_dir.join("jail.d"),
            filter_d: config_dir.join("filter.d"),
            action_d: config_dir.join("action.d"),
            namespace: namespace.to_owned(),
        })
    }

    // -----------------------------------------------------------------------
    // Path helpers
    // -----------------------------------------------------------------------

    /// Returns the path for a managed jail config file.
    ///
    /// Format: `{jail_d}/{namespace}-{name}.local`
    pub fn jail_path(&self, name: &str) -> PathBuf {
        self.jail_d
            .join(format!("{}-{}.local", self.namespace, name))
    }

    /// Returns the path for a managed filter config file.
    ///
    /// Format: `{filter_d}/{namespace}-{name}.local`
    pub fn filter_path(&self, name: &str) -> PathBuf {
        self.filter_d
            .join(format!("{}-{}.local", self.namespace, name))
    }

    /// Returns the path for a managed action config file.
    ///
    /// Format: `{action_d}/{namespace}-{name}.local`
    pub fn action_path(&self, name: &str) -> PathBuf {
        self.action_d
            .join(format!("{}-{}.local", self.namespace, name))
    }

    /// Returns a timestamped backup path for the given original file.
    ///
    /// Format: `{original}.bak-{timestamp}`
    fn backup_path(&self, original: &Path) -> PathBuf {
        let ts = chrono::Local::now().format("%Y%m%dT%H%M%S%.3f");
        PathBuf::from(format!("{}.bak-{}", original.display(), ts))
    }

    /// Returns the path to the advisory lock file used for coordinating
    /// concurrent writes.
    ///
    /// Format: `{config_dir}/.fail2ban-kit.lock`
    fn lock_file(&self) -> PathBuf {
        self.config_dir.join(".fail2ban-kit.lock")
    }

    // -----------------------------------------------------------------------
    // Write operations (Apply workflow)
    // -----------------------------------------------------------------------

    /// Write a jail config file from the given spec.
    ///
    /// Follows the apply workflow:
    /// 1. Render INI content via [`render::render_jail_local`].
    /// 2. Compute the target path.
    /// 3. If the file already exists, verify it has the managed header
    ///    (rejects unmanaged files).
    /// 4. Create a timestamped backup if the file exists.
    /// 5. Atomic write: write to a temp file, fsync, rename.
    /// 6. Return an [`ApplyReport`] summarising the operation.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The target directory cannot be created.
    /// - An existing file lacks the managed header (refused overwrite).
    /// - The backup copy fails.
    /// - The atomic write fails.
    pub fn write_jail(&self, spec: &JailSpec) -> Result<ApplyReport> {
        let content = render::render_jail_local(spec, &self.namespace);
        let path = self.jail_path(spec.name.as_str());
        self.atomic_write(&path, &content)
    }

    /// Write a filter config file from the given spec.
    ///
    /// Follows the same apply workflow as [`write_jail`](Self::write_jail).
    pub fn write_filter(&self, spec: &FilterSpec) -> Result<ApplyReport> {
        let content = render::render_filter_local(spec, &self.namespace);
        let path = self.filter_path(spec.name.as_str());
        self.atomic_write(&path, &content)
    }

    /// Write an action config file from the given spec.
    ///
    /// Follows the same apply workflow as [`write_jail`](Self::write_jail).
    pub fn write_action(&self, spec: &ActionSpec) -> Result<ApplyReport> {
        let content = render::render_action_local(spec, &self.namespace);
        let path = self.action_path(spec.name.as_str());
        self.atomic_write(&path, &content)
    }

    // -----------------------------------------------------------------------
    // Remove operations (Remove workflow)
    // -----------------------------------------------------------------------

    /// Remove a managed jail config file.
    ///
    /// Follows the remove workflow:
    /// 1. Compute the file path.
    /// 2. Verify the file has the managed header (refuse to delete unmanaged).
    /// 3. Create a timestamped backup.
    /// 4. Remove the file.
    /// 5. Return an [`ApplyReport`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the file does not exist, or
    /// [`Error::InvalidConfig`] if the file lacks the managed header.
    pub fn remove_jail(&self, name: &str) -> Result<ApplyReport> {
        let path = self.jail_path(name);
        self.managed_remove(&path)
    }

    /// Remove a managed filter config file.
    ///
    /// Follows the same remove workflow as [`remove_jail`](Self::remove_jail).
    pub fn remove_filter(&self, name: &str) -> Result<ApplyReport> {
        let path = self.filter_path(name);
        self.managed_remove(&path)
    }

    /// Remove a managed action config file.
    ///
    /// Follows the same remove workflow as [`remove_jail`](Self::remove_jail).
    pub fn remove_action(&self, name: &str) -> Result<ApplyReport> {
        let path = self.action_path(name);
        self.managed_remove(&path)
    }

    // -----------------------------------------------------------------------
    // Query operations
    // -----------------------------------------------------------------------

    /// Scan all config directories and return files that contain the managed
    /// header and match the current namespace.
    ///
    /// Scans `jail.d/`, `filter.d/`, and `action.d/` for `.local` files
    /// whose names start with `{namespace}-`.
    pub fn list_managed(&self) -> Result<Vec<ManagedFile>> {
        let mut results = Vec::new();

        let scans: &[(PathBuf, ManagedFileKind)] = &[
            (self.jail_d.clone(), ManagedFileKind::Jail),
            (self.filter_d.clone(), ManagedFileKind::Filter),
            (self.action_d.clone(), ManagedFileKind::Action),
        ];

        let prefix = format!("{}-", self.namespace);

        for (dir, kind) in scans {
            if !dir.is_dir() {
                continue;
            }
            let entries = match fs_err::read_dir(dir) {
                Ok(e) => e,
                Err(_) => continue,
            };
            for entry in entries {
                let entry = match entry {
                    Ok(e) => e,
                    Err(_) => continue,
                };
                let path = entry.path();

                // Must be a .local file with the namespace prefix.
                let fname = match path.file_name().and_then(|n| n.to_str()) {
                    Some(n) => n.to_owned(),
                    None => continue,
                };
                if !fname.starts_with(&prefix) || !fname.ends_with(".local") {
                    continue;
                }

                // Extract the name portion between prefix and ".local".
                let name = &fname[prefix.len()..fname.len() - ".local".len()];
                if name.is_empty() {
                    continue;
                }

                // Verify managed header.
                if self.has_managed_header(&path).unwrap_or(false) {
                    results.push(ManagedFile {
                        path: entry.path(),
                        kind: kind.clone(),
                        name: name.to_owned(),
                    });
                }
            }
        }

        // Sort by path for deterministic output.
        results.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(results)
    }

    /// Check whether a file starts with the managed header.
    ///
    /// Returns `false` if the file does not exist or the first line does not
    /// match the expected header marker.
    pub fn has_managed_header(&self, path: &Path) -> Result<bool> {
        if !path.is_file() {
            return Ok(false);
        }
        let content = fs_err::read_to_string(path)?;
        Ok(content.starts_with(render::managed_header().trim_end()))
    }

    /// Read the full content of a managed jail config file.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the file does not exist.
    pub fn read_jail(&self, name: &str) -> Result<String> {
        let path = self.jail_path(name);
        Self::read_file(&path)
    }

    /// Read the full content of a managed filter config file.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the file does not exist.
    pub fn read_filter(&self, name: &str) -> Result<String> {
        let path = self.filter_path(name);
        Self::read_file(&path)
    }

    /// Read the full content of a managed action config file.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the file does not exist.
    pub fn read_action(&self, name: &str) -> Result<String> {
        let path = self.action_path(name);
        Self::read_file(&path)
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Acquire an exclusive advisory write lock and run the given closure.
    ///
    /// The lock file is `{config_dir}/.fail2ban-kit.lock`. If the file does
    /// not exist it is created automatically. The lock is held for the
    /// duration of the closure and released on drop.
    ///
    /// Advisory locking via fd-lock for coordination between concurrent
    /// processes. This is NOT a security boundary -- it prevents conflicting
    /// writes from this library, not adversarial access.
    fn with_write_lock<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&Self) -> Result<T>,
    {
        let lock_path = self.lock_file();

        // Ensure the parent directory exists (it should, since config_dir
        // is validated at construction, but be defensive).
        if let Some(parent) = lock_path.parent() {
            fs_err::create_dir_all(parent)?;
        }

        let file = File::create(&lock_path).map_err(|e| {
            Error::LockFailed(format!(
                "failed to create lock file {}: {e}",
                lock_path.display()
            ))
        })?;

        let mut lock = RwLock::new(file);
        let _guard = lock.write().map_err(|e| {
            Error::LockFailed(format!(
                "failed to acquire write lock on {}: {e}",
                lock_path.display()
            ))
        })?;

        // Lock is held via `_guard`; run the operation.
        f(self)
    }

    /// Perform an atomic write of `content` to `path` under the advisory lock.
    ///
    /// Acquires an exclusive write lock before delegating to
    /// [`atomic_write_inner`].
    fn atomic_write(&self, path: &Path, content: &str) -> Result<ApplyReport> {
        let path = path.to_path_buf();
        let content = content.to_owned();
        self.with_write_lock(|mgr| mgr.atomic_write_inner(&path, &content))
    }

    /// Inner implementation of atomic write (callers must already hold the
    /// advisory lock).
    ///
    /// Creates the parent directory if needed, backs up any existing managed
    /// file, writes to a `NamedTempFile`, fsyncs, and atomically renames.
    fn atomic_write_inner(&self, path: &Path, content: &str) -> Result<ApplyReport> {
        let mut report = ApplyReport::empty();

        // Ensure parent directory exists.
        if let Some(parent) = path.parent() {
            fs_err::create_dir_all(parent)?;
        }

        // If file exists, verify managed header and create backup.
        if path.exists() {
            if !self.has_managed_header(path)? {
                return Err(Error::InvalidConfig(format!(
                    "refusing to overwrite unmanaged file: {}",
                    path.display()
                )));
            }
            let backup = self.backup_path(path);
            fs_err::copy(path, &backup)?;
            report.backup_paths.push(backup.display().to_string());
        }

        // Atomic write: NamedTempFile in same directory, then persist (rename).
        let parent = path.parent().unwrap_or(path);
        let mut tmp = tempfile::NamedTempFile::new_in(parent)?;
        use std::io::Write;
        tmp.write_all(content.as_bytes())?;
        tmp.as_file().sync_all()?;

        tmp.persist(path).map_err(|e| {
            Error::InvalidConfig(format!(
                "atomic write failed for {}: {e}",
                e.file.path().display()
            ))
        })?;

        report.files_written.push(path.display().to_string());
        Ok(report)
    }

    /// Remove a managed file under the advisory lock.
    ///
    /// Acquires an exclusive write lock before delegating to
    /// [`managed_remove_inner`].
    fn managed_remove(&self, path: &Path) -> Result<ApplyReport> {
        let path = path.to_path_buf();
        self.with_write_lock(|mgr| mgr.managed_remove_inner(&path))
    }

    /// Remove a managed file after verifying the managed header and creating
    /// a backup (callers must already hold the advisory lock).
    fn managed_remove_inner(&self, path: &Path) -> Result<ApplyReport> {
        let mut report = ApplyReport::empty();

        if !path.exists() {
            return Err(Error::NotFound(format!(
                "file does not exist: {}",
                path.display()
            )));
        }

        if !self.has_managed_header(path)? {
            return Err(Error::InvalidConfig(format!(
                "refusing to delete unmanaged file: {}",
                path.display()
            )));
        }

        // Backup before removal.
        let backup = self.backup_path(path);
        fs_err::copy(path, &backup)?;
        report.backup_paths.push(backup.display().to_string());

        fs_err::remove_file(path)?;

        report.files_removed.push(path.display().to_string());
        Ok(report)
    }

    /// Read a file's content, returning [`Error::NotFound`] if missing.
    fn read_file(path: &Path) -> Result<String> {
        if !path.exists() {
            return Err(Error::NotFound(format!(
                "config file not found: {}",
                path.display()
            )));
        }
        let content = fs_err::read_to_string(path)?;
        Ok(content)
    }
}

#[cfg(test)]
#[path = "ini.test.rs"]
mod tests;
