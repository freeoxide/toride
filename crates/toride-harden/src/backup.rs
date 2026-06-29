//! Pre-mutation backup of sysctl configuration files.
//!
//! Before applying hardening changes, this module snapshots the current
//! sysctl configuration so that changes can be rolled back if needed.

use crate::error::Result;
use crate::paths::HardenPaths;
use std::fmt::Write as _;

/// Sentinel token embedded in every section delimiter so a real sysctl.conf
/// comment of the shape `# === my section ===` cannot be mistaken for a
/// section marker (and thus corrupt the round-trip). Writers always emit
/// `# <SENTINEL> === <name> ===`; parsers only treat a line as a section
/// marker when it both starts with the section prefix AND carries this token.
const SECTION_SENTINEL: &str = "toride:backup:section";

/// File mode for restored sysctl configuration files (`/etc/sysctl.conf`,
/// `/etc/sysctl.d/*.conf`). These are world-readable system config and
/// conventionally `0644` on a stock Linux install.
const SYSCTL_CONF_MODE: u32 = 0o644;
/// File mode for persisted backup snapshots. A backup captures the host's
/// full sysctl posture, which can reveal hardening gaps; restrict to the
/// owner to avoid leaking that to other local users.
const BACKUP_FILE_MODE: u32 = 0o600;

/// A snapshot of sysctl configuration files before mutation.
#[derive(Debug, Clone)]
pub struct BackupSnapshot {
    /// Timestamp of the backup (ISO 8601).
    pub timestamp: String,
    /// Contents of `/etc/sysctl.conf` (if readable).
    pub sysctl_conf: Option<String>,
    /// Contents of `/etc/sysctl.d/` drop-in files (name, content).
    pub dropins: Vec<(String, String)>,
}

/// Create a backup of the current sysctl configuration.
///
/// Reads `/etc/sysctl.conf` and all `.conf` files in `/etc/sysctl.d/`.
/// Returns a snapshot that can be used for restoration.
///
/// # Errors
///
/// Returns an error if the backup directory cannot be created.
/// Individual file read failures are captured as `None` in the snapshot.
pub fn create_backup(paths: &HardenPaths) -> Result<BackupSnapshot> {
    // High-resolution wall-clock time plus an on-disk uniqueness guard so
    // repeated invocations never overwrite a prior backup.
    let timestamp = unique_timestamp(paths);

    // Read main sysctl.conf
    let sysctl_conf = std::fs::read_to_string(&paths.sysctl_conf).ok();

    // Read all drop-in files
    let mut dropins = Vec::new();
    if paths.sysctl_d.is_dir()
        && let Ok(entries) = std::fs::read_dir(&paths.sysctl_d)
    {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == "conf") {
                // Store the name without .conf suffix so dropin_path() works correctly
                let name = path
                    .file_stem()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string();
                if let Ok(content) = std::fs::read_to_string(&path) {
                    dropins.push((name, content));
                }
            }
        }
    }

    // Sort drop-ins for deterministic output
    dropins.sort_by(|a, b| a.0.cmp(&b.0));

    tracing::info!(
        "backup: created snapshot with {} drop-in files",
        dropins.len()
    );

    Ok(BackupSnapshot {
        timestamp,
        sysctl_conf,
        dropins,
    })
}

/// Restore sysctl configuration from a backup snapshot.
///
/// Writes back the main sysctl.conf and all drop-in files.
///
/// # Errors
///
/// Returns an error if any file cannot be written.
pub fn restore_backup(paths: &HardenPaths, snapshot: &BackupSnapshot) -> Result<()> {
    // Restore main sysctl.conf
    if let Some(content) = &snapshot.sysctl_conf {
        toride_fs::atomic_write_with_perms(&paths.sysctl_conf, content, SYSCTL_CONF_MODE)?;
        tracing::info!("backup: restored {}", paths.sysctl_conf.display());
    }

    // Restore drop-in files
    for (name, content) in &snapshot.dropins {
        if let Some(path) = paths.dropin_path(name) {
            toride_fs::atomic_write_with_perms(&path, content, SYSCTL_CONF_MODE)?;
            tracing::info!("backup: restored {}", path.display());
        }
    }

    tracing::info!("backup: restoration complete");
    Ok(())
}

/// Persist a backup snapshot to disk.
///
/// Writes the snapshot as a JSON file in the backup directory.
///
/// # Errors
///
/// Returns an error if the backup directory cannot be created or the
/// file cannot be written.
pub fn save_backup_to_disk(paths: &HardenPaths, snapshot: &BackupSnapshot) -> Result<()> {
    std::fs::create_dir_all(&paths.backup_dir)?;

    let filename = format!("sysctl-backup-{}.txt", snapshot.timestamp);
    let path = paths.backup_dir.join(&filename);

    let mut content = String::new();
    let _ = write!(content, "# Backup created: {}\n\n", snapshot.timestamp);

    if let Some(conf) = &snapshot.sysctl_conf {
        let _ = writeln!(content, "# {SECTION_SENTINEL} === /etc/sysctl.conf ===");
        content.push_str(conf);
        content.push_str("\n\n");
    }

    for (name, file_content) in &snapshot.dropins {
        let _ = writeln!(content, "# {SECTION_SENTINEL} === {name} ===");
        content.push_str(file_content);
        content.push_str("\n\n");
    }

    toride_fs::atomic_write_with_perms(&path, &content, BACKUP_FILE_MODE)?;
    tracing::info!("backup: saved to {}", path.display());
    Ok(())
}

/// Load a backup snapshot previously persisted by [`save_backup_to_disk`].
///
/// Looks up `sysctl-backup-<timestamp>.txt` in the backup directory and parses
/// it back into a [`BackupSnapshot`]. This closes the save/load round-trip so
/// that [`restore_backup`] can be driven by a timestamp alone (e.g. from the
/// CLI `Restore { timestamp }` command) rather than an in-memory snapshot.
///
/// The snapshot's `timestamp` field is taken from the persisted header line
/// (`# Backup created: <ts>`), so it round-trips even when callers pass a
/// timestamp obtained from the on-disk filename.
///
/// # Errors
///
/// Returns an error if the backup file does not exist, cannot be read, or is
/// malformed (missing or duplicated `# Backup created:` header, or a section
/// marker that is not closed).
pub fn load_backup_from_disk(paths: &HardenPaths, timestamp: &str) -> Result<BackupSnapshot> {
    // Reject anything that could escape the backup directory before touching disk.
    if timestamp.contains('/') || timestamp.contains("..") || timestamp.is_empty() {
        return Err(crate::error::Error::Io(format!(
            "invalid backup timestamp: {timestamp}"
        )));
    }

    let filename = format!("sysctl-backup-{timestamp}.txt");
    let path = paths.backup_dir.join(&filename);
    let content = std::fs::read_to_string(&path)?;

    let snapshot = parse_backup(&content)?;
    tracing::info!("backup: loaded from {}", path.display());
    Ok(snapshot)
}

/// Parse the on-disk backup text format produced by [`save_backup_to_disk`].
///
/// Format:
///
/// ```text
/// # Backup created: <timestamp>
///
/// # toride:backup:section === /etc/sysctl.conf ===
/// <sysctl.conf contents>
///
/// # toride:backup:section === <dropin name> ===
/// <dropin contents>
///
/// ```
///
/// Section delimiters carry the [`SECTION_SENTINEL`] token so a real
/// sysctl.conf comment shaped like `# === my section ===` is not mistaken for
/// a marker. For backward compatibility, the bare legacy form
/// `# === <name> ===` (written by older versions) is still recognised as a
/// marker ONLY when it appears at the very start of a line, since a genuine
/// sysctl comment would have to exactly match that shape to collide.
fn parse_backup(content: &str) -> Result<BackupSnapshot> {
    const HEADER_PREFIX: &str = "# Backup created: ";
    const SECTION_SUFFIX: &str = " ===";
    // Modern markers: `# toride:backup:section === <name> ===`
    const SENTINEL_PREFIX: &str = "# toride:backup:section === ";
    // Legacy markers (older on-disk backups): `# === <name> ===`
    const LEGACY_PREFIX: &str = "# === ";

    // Header: first line must be the `# Backup created: <ts>` marker.
    let header_end = content
        .find('\n')
        .ok_or_else(|| crate::error::Error::Io("backup file missing header line".into()))?;
    let header_line = &content[..header_end];
    if !header_line.starts_with(HEADER_PREFIX) {
        return Err(crate::error::Error::Io(format!(
            "backup file missing '# Backup created:' header; got: {header_line}"
        )));
    }
    let timestamp = header_line[HEADER_PREFIX.len()..].trim().to_string();

    let body = &content[header_end + 1..];

    let mut sysctl_conf: Option<String> = None;
    let mut dropins: Vec<(String, String)> = Vec::new();

    // Walk the body line-by-line, accumulating section content between markers.
    let mut current_section: Option<String> = None;
    let mut current_lines: Vec<&str> = Vec::new();

    for line in body.split_inclusive('\n') {
        let trimmed = line.trim_end_matches('\n');

        // Prefer the sentinel-bearing marker; fall back to the legacy form so
        // backups written by previous versions still round-trip.
        let name = if let Some(rest) = trimmed.strip_prefix(SENTINEL_PREFIX) {
            rest.strip_suffix(SECTION_SUFFIX)
        } else if let Some(rest) = trimmed.strip_prefix(LEGACY_PREFIX) {
            rest.strip_suffix(SECTION_SUFFIX)
        } else {
            None
        };

        if let Some(name) = name {
            // Flush the previous section.
            if let Some(prev) = current_section.take() {
                push_section(&mut sysctl_conf, &mut dropins, &prev, &current_lines);
                current_lines.clear();
            }
            current_section = Some(name.to_string());
        } else if current_section.is_some() {
            current_lines.push(trimmed);
        }
    }

    // Flush trailing section (the writer always appends "\n\n" after content).
    if let Some(name) = current_section {
        push_section(&mut sysctl_conf, &mut dropins, &name, &current_lines);
    }

    // Drop-ins are sorted deterministically on write; mirror that here.
    dropins.sort_by(|a, b| a.0.cmp(&b.0));

    Ok(BackupSnapshot {
        timestamp,
        sysctl_conf,
        dropins,
    })
}

/// Route a flushed section's accumulated lines into the snapshot fields.
///
/// Trims the single trailing blank line the writer appends after each section
/// (`"<content>\n\n"` produces one empty final line) so the round-tripped
/// content matches the original byte-for-byte except for a trailing newline.
fn push_section(
    sysctl_conf: &mut Option<String>,
    dropins: &mut Vec<(String, String)>,
    name: &str,
    lines: &[&str],
) {
    // Drop trailing empty line(s) introduced by the writer's "\n\n" separator.
    let mut end = lines.len();
    while end > 0 && lines[end - 1].is_empty() {
        end -= 1;
    }
    let body = lines[..end].join("\n");
    let body = if body.is_empty() {
        String::new()
    } else {
        format!("{body}\n")
    };

    if name == "/etc/sysctl.conf" {
        *sysctl_conf = Some(body);
    } else {
        dropins.push((name.to_string(), body));
    }
}

/// Generate a high-resolution timestamp string without depending on chrono.
///
/// The timestamp combines whole seconds with a zero-padded millisecond
/// component, so backups created within the same wall-clock second no longer
/// collide (the previous second-resolution format silently overwrote prior
/// backups). Callers that need a guaranteed-unique on-disk name should pass
/// the result through [`unique_timestamp`], which appends a monotonic counter
/// suffix only when an actual collision is detected on disk.
fn chrono_independent_timestamp() -> String {
    let duration = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}{:03}", duration.as_secs(), duration.subsec_millis())
}

/// Return a backup timestamp guaranteed not to collide with an existing
/// backup file under `backup_dir`.
///
/// Starts from the high-resolution wall-clock timestamp produced by
/// [`chrono_independent_timestamp`]; if `sysctl-backup-<ts>.txt` already
/// exists, appends a `-<n>` counter suffix (starting at 2) until a free name
/// is found. This is the safety net that makes repeated invocations within the
/// same millisecond non-destructive.
fn unique_timestamp(paths: &HardenPaths) -> String {
    let base = chrono_independent_timestamp();

    // Fast path: no existing backup with this name.
    let candidate = paths.backup_dir.join(format!("sysctl-backup-{base}.txt"));
    if !candidate.exists() {
        return base;
    }

    // Collision: scan for a free counter suffix.
    for n in 2..u64::MAX {
        let suffixed = format!("{base}-{n}");
        let probe = paths
            .backup_dir
            .join(format!("sysctl-backup-{suffixed}.txt"));
        if !probe.exists() {
            return suffixed;
        }
    }

    // Practically unreachable (u64::MAX attempts); fall back to the base name.
    base
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backup_captures_files() {
        let dir = assert_fs::TempDir::new().unwrap();
        let root = dir.path();

        // Create test files
        std::fs::create_dir_all(root.join("etc/sysctl.d")).unwrap();
        std::fs::write(root.join("etc/sysctl.conf"), "kernel.aslr = 2\n").unwrap();
        std::fs::write(
            root.join("etc/sysctl.d/99-test.conf"),
            "kernel.kptr_restrict = 1\n",
        )
        .unwrap();

        let paths = HardenPaths::with_root(root);
        let snapshot = create_backup(&paths).unwrap();

        assert!(snapshot.sysctl_conf.is_some());
        assert_eq!(snapshot.dropins.len(), 1);
        assert_eq!(snapshot.dropins[0].0, "99-test");
    }

    #[test]
    fn restore_writes_files_back() {
        let dir = assert_fs::TempDir::new().unwrap();
        let root = dir.path();

        std::fs::create_dir_all(root.join("etc/sysctl.d")).unwrap();

        let paths = HardenPaths::with_root(root);
        let snapshot = BackupSnapshot {
            timestamp: "12345".into(),
            sysctl_conf: Some("kernel.aslr = 2\n".into()),
            dropins: vec![("99-test".into(), "kernel.kptr_restrict = 1\n".into())],
        };

        restore_backup(&paths, &snapshot).unwrap();

        let content = std::fs::read_to_string(root.join("etc/sysctl.conf")).unwrap();
        assert!(content.contains("kernel.aslr = 2"));
    }

    #[test]
    fn save_load_round_trip_preserves_snapshot() {
        let dir = assert_fs::TempDir::new().unwrap();
        let root = dir.path();
        let paths = HardenPaths::with_root(root);

        let original = BackupSnapshot {
            timestamp: "1719400000".into(),
            sysctl_conf: Some("kernel.aslr = 2\nnet.ipv4.ip_forward = 0\n".into()),
            dropins: vec![
                ("99-hardening".into(), "kernel.kptr_restrict = 1\n".into()),
                ("zz-custom".into(), "fs.protected_hardlinks = 1\n".into()),
            ],
        };

        save_backup_to_disk(&paths, &original).unwrap();
        let loaded = load_backup_from_disk(&paths, "1719400000").unwrap();

        assert_eq!(loaded.timestamp, original.timestamp);
        assert_eq!(loaded.sysctl_conf, original.sysctl_conf);
        // Drop-ins are sorted deterministically on both write and read.
        assert_eq!(loaded.dropins, original.dropins);
    }

    #[test]
    fn save_load_round_trip_without_sysctl_conf() {
        let dir = assert_fs::TempDir::new().unwrap();
        let root = dir.path();
        let paths = HardenPaths::with_root(root);

        let original = BackupSnapshot {
            timestamp: "42".into(),
            sysctl_conf: None,
            dropins: vec![("only".into(), "vm.swappiness = 10\n".into())],
        };

        save_backup_to_disk(&paths, &original).unwrap();
        let loaded = load_backup_from_disk(&paths, "42").unwrap();

        assert_eq!(loaded.timestamp, "42");
        assert!(loaded.sysctl_conf.is_none());
        assert_eq!(loaded.dropins.len(), 1);
        assert_eq!(loaded.dropins[0].0, "only");
        assert_eq!(loaded.dropins[0].1, "vm.swappiness = 10\n");
    }

    #[test]
    fn load_backup_rejects_path_traversal() {
        let dir = assert_fs::TempDir::new().unwrap();
        let paths = HardenPaths::with_root(dir.path());

        assert!(load_backup_from_disk(&paths, "../evil").is_err());
        assert!(load_backup_from_disk(&paths, "sub/dir").is_err());
        assert!(load_backup_from_disk(&paths, "").is_err());
    }

    #[test]
    fn load_backup_missing_file_errors() {
        let dir = assert_fs::TempDir::new().unwrap();
        let paths = HardenPaths::with_root(dir.path());
        assert!(load_backup_from_disk(&paths, "never-saved").is_err());
    }

    #[test]
    fn load_backup_malformed_header_errors() {
        let dir = assert_fs::TempDir::new().unwrap();
        let root = dir.path();
        let paths = HardenPaths::with_root(root);

        // No '# Backup created:' header.
        std::fs::create_dir_all(&paths.backup_dir).unwrap();
        std::fs::write(
            paths.backup_dir.join("sysctl-backup-bad.txt"),
            "garbage content with no header\n",
        )
        .unwrap();

        assert!(load_backup_from_disk(&paths, "bad").is_err());
    }

    #[test]
    fn save_load_restore_round_trip_end_to_end() {
        // Full cycle: save -> load -> restore restores the original files.
        let dir = assert_fs::TempDir::new().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("etc/sysctl.d")).unwrap();

        let paths = HardenPaths::with_root(root);

        let original = BackupSnapshot {
            timestamp: "999".into(),
            sysctl_conf: Some("kernel.randomize_va_space = 2\n".into()),
            dropins: vec![("99-rt".into(), "kernel.dmesg_restrict = 1\n".into())],
        };

        save_backup_to_disk(&paths, &original).unwrap();
        let loaded = load_backup_from_disk(&paths, "999").unwrap();
        restore_backup(&paths, &loaded).unwrap();

        let conf = std::fs::read_to_string(root.join("etc/sysctl.conf")).unwrap();
        assert!(conf.contains("kernel.randomize_va_space = 2"));
        let dropin = std::fs::read_to_string(root.join("etc/sysctl.d/99-rt.conf")).unwrap();
        assert!(dropin.contains("kernel.dmesg_restrict = 1"));
    }
}
