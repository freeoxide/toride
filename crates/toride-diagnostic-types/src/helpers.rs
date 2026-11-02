//! Binary and filesystem permission check helpers.
//!
//! These produce [`Finding`] values suitable for inclusion in a `DoctorReport`.

use std::path::Path;

use crate::{Finding, Severity};

/// Check whether a binary exists on `$PATH`.
///
/// Returns `None` when the binary is present (no finding to report).
/// Returns `Some(Finding)` with [`Severity::Critical`] when it is missing.
#[must_use]
pub fn check_binary_exists(name: &str) -> Option<Finding> {
    match which::which(name) {
        Ok(_) => None,
        Err(_) => Some(
            Finding::new(
                format!("bin:{name}-exists"),
                Severity::Critical,
                format!("`{name}` not found on $PATH"),
            )
            .domain("system")
            .fix_hint(format!("Install `{name}` and ensure it is on your $PATH")),
        ),
    }
}

/// Check whether a file has the expected permission mode.
///
/// On Unix this compares the lower 9 bits of the mode. On non-Unix platforms
/// it always returns `None` (no finding).
///
/// Returns `Some(Finding)` with [`Severity::Warning`] when the mode differs.
#[must_use]
pub fn check_file_permissions(path: &Path, expected_mode: u32) -> Option<Finding> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        match std::fs::metadata(path) {
            Ok(meta) => {
                let actual = meta.permissions().mode() & 0o777;
                if actual == expected_mode {
                    None
                } else {
                    Some(
                        Finding::new(
                            format!("perms:{}", path.display()),
                            Severity::Warning,
                            format!(
                                "Expected mode {:o} but found {:o} for {}",
                                expected_mode,
                                actual,
                                path.display()
                            ),
                        )
                        .domain("filesystem")
                        .fix_hint(format!(
                            "chmod {:o} {}",
                            expected_mode,
                            path.display()
                        )),
                    )
                }
            }
            Err(e) => Some(
                Finding::new(
                    format!("perms:{}", path.display()),
                    Severity::Warning,
                    format!("Cannot stat {}: {e}", path.display()),
                )
                .domain("filesystem"),
            ),
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (path, expected_mode);
        None
    }
}

/// Check that a path is **not** world-writable.
///
/// Returns `Some(Finding)` with [`Severity::Important`] when `path` exists and
/// has the world-writable bit set (mode `...o+w`).
#[must_use]
pub fn check_not_world_writable(path: &Path) -> Option<Finding> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        match std::fs::metadata(path) {
            Ok(meta) => {
                let mode = meta.permissions().mode();
                if mode & 0o002 != 0 {
                    Some(
                        Finding::new(
                            format!("world-writable:{}", path.display()),
                            Severity::Important,
                            format!("{} is world-writable", path.display()),
                        )
                        .domain("filesystem")
                        .fix_hint(format!("chmod o-w {}", path.display())),
                    )
                } else {
                    None
                }
            }
            Err(_) => None, // File does not exist -- not our concern here.
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn check_binary_exists_ls() {
        assert!(check_binary_exists("ls").is_none());
    }

    #[test]
    fn check_binary_missing() {
        let f = check_binary_exists("__nonexistent_binary_12345__");
        assert!(f.is_some());
        let f = f.unwrap();
        assert_eq!(f.severity, Severity::Critical);
        assert!(f.id.contains("__nonexistent_binary_12345__"));
    }

    #[test]
    fn check_file_permissions_self() {
        let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
        let _result = check_file_permissions(&manifest, 0o644);
    }

    #[test]
    fn check_not_world_writable_cargo_toml() {
        let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
        assert!(check_not_world_writable(&manifest).is_none());
    }

    /// The mode-mismatch arm and the stat-error arm of the same check must
    /// emit the same `perms:{path}` id shape.
    #[test]
    #[cfg(unix)]
    fn check_file_permissions_finding_ids_match_across_arms() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().expect("temp dir creation should succeed");
        let file = dir.path().join("mode-mismatch.txt");
        std::fs::write(&file, "data").expect("write should succeed");

        let actual = std::fs::metadata(&file)
            .expect("metadata should be available")
            .permissions()
            .mode()
            & 0o777;
        let expected_mode = if actual == 0o600 { 0o644 } else { 0o600 };

        let mismatch = check_file_permissions(&file, expected_mode)
            .expect("a differing expected mode must find a mismatch");
        let absent = dir.path().join("absent.txt");
        let missing = check_file_permissions(&absent, expected_mode)
            .expect("a stat error must produce a finding");

        assert_eq!(mismatch.id, format!("perms:{}", file.display()));
        assert_eq!(missing.id, format!("perms:{}", absent.display()));
        assert!(!mismatch.id.contains('`'), "mismatch arm: {}", mismatch.id);
        assert!(!missing.id.contains('`'), "stat-error arm: {}", missing.id);
    }
}
