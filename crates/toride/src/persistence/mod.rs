//! Theme persistence across sessions.
//!
//! Saves and restores the user's selected [`Theme`] so the choice survives
//! restarts. The value lives in a single TOML file at the standard per-OS config
//! location — `<config_dir>/toride/config.toml` (resolved via [`dirs`]) — as a
//! `theme = "<label>"` row. The label matches [`Theme::label`], so the Settings
//! section's existing config-file reader surfaces the persisted choice directly
//! with no separate read path.
//!
//! Both entry points are best-effort and never propagate errors: a missing or
//! corrupt config file, an unwritable config dir, or an unknown theme label all
//! degrade to the [`Theme::default`] (the app must keep launching / keep running
//! even when persistence is unavailable). A read/write failure is `tracing`-debug
//! logged but otherwise swallowed.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::ui::theme::Theme;

/// Subdirectory under the OS config dir that holds toride's files.
const APP_DIR: &str = "toride";
/// Config file name within [`APP_DIR`].
const CONFIG_FILE: &str = "config.toml";

/// On-disk config representation.
///
/// Only the `theme` key is currently modeled; any other keys present in the
/// file are preserved on write (the file is round-tripped through a TOML table
/// so unrelated operator settings are never clobbered).
#[derive(Debug, Default, Serialize, Deserialize)]
struct ConfigFile {
    /// Selected theme, stored as its [`Theme::label`] (e.g. `"Charm"`).
    /// `None` / absent ⇒ fall back to the default theme.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    theme: Option<String>,
}

/// Resolve the config file path: `<config_dir>/toride/config.toml`.
///
/// Returns `None` only when [`dirs::config_dir`] cannot resolve a config dir
/// (unusual but possible on stripped-down systems); callers fall back to the
/// default theme in that case.
fn config_path() -> Option<PathBuf> {
    dirs::config_dir().map(|d| d.join(APP_DIR).join(CONFIG_FILE))
}

/// Load the persisted theme.
///
/// Reads `<config_dir>/toride/config.toml`, parses it as TOML, and resolves the
/// `theme` label via [`Theme::from_label`]. Any failure — no config dir, missing
/// file, unreadable file, malformed TOML, or an unrecognized theme label — is
/// logged at debug level and yields [`Theme::default`]. This keeps the app
/// launching normally on a fresh install or with a corrupt config.
#[must_use]
pub fn load_theme() -> Theme {
    let path = match config_path() {
        Some(p) => p,
        None => {
            tracing::debug!("persistence: dirs::config_dir() returned None");
            return Theme::default();
        }
    };
    load_theme_from(&path)
}

/// Persist the selected theme so it survives the next launch.
///
/// Writes `theme = "<label>"` to `<config_dir>/toride/config.toml`, creating the
/// `toride/` directory (and parents) if needed. Any other keys already present
/// in the file are preserved (the file is round-tripped through a TOML table).
///
/// Failures are logged but otherwise swallowed — a read-only HOME or a missing
/// config dir must never crash the running TUI; the choice simply won't persist
/// and the app reverts to the default on next launch.
pub fn save_theme(theme: Theme) {
    let path = match config_path() {
        Some(p) => p,
        None => {
            tracing::debug!("persistence: no config dir; skipping theme save");
            return;
        }
    };
    save_theme_to(&path, theme);
}

/// Load the theme from an explicit path (the testable core of [`load_theme`]).
fn load_theme_from(path: &Path) -> Theme {
    let contents = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            // Missing file is the common case on a fresh install — debug, not
            // warn. Anything else (permission denied, IO error) is warn.
            if e.kind() == std::io::ErrorKind::NotFound {
                tracing::debug!(
                    "persistence: no config at {} (using default theme)",
                    path.display()
                );
            } else {
                tracing::warn!("persistence: could not read {}: {e}", path.display());
            }
            return Theme::default();
        }
    };

    let cfg: ConfigFile = match toml::from_str(&contents) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(
                "persistence: ignoring corrupt config at {}: {e}",
                path.display()
            );
            return Theme::default();
        }
    };

    match cfg.theme.as_deref().and_then(Theme::from_label) {
        Some(theme) => theme,
        None => {
            // Present but empty/unrecognized — fall back to the default rather
            // than coercing a corrupt label into a wrong theme.
            if let Some(label) = cfg.theme.as_deref() {
                tracing::warn!(
                    "persistence: unrecognized theme {label:?} in {}; using default",
                    path.display()
                );
            }
            Theme::default()
        }
    }
}

/// Persist the theme to an explicit path (the testable core of [`save_theme`]).
///
/// Writes `theme = "<label>"`, preserving any other keys already in the file,
/// via a temp-file-then-rename so a crash mid-write cannot leave a truncated
/// config.
fn save_theme_to(path: &Path, theme: Theme) {
    // Load + merge so unrelated keys survive the write. A missing/unreadable
    // file starts from an empty config (the theme becomes the sole key).
    let mut table: toml::Table = std::fs::read_to_string(path)
        .ok()
        .and_then(|c| toml::from_str(&c).ok())
        .unwrap_or_default();

    // Always overwrite with the canonical label (this also normalizes a
    // previously-saved label that used different casing).
    table.insert(
        "theme".to_string(),
        toml::Value::String(theme.label().to_string()),
    );

    let serialized = match toml::to_string(&table) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("persistence: could not serialize theme: {e}");
            return;
        }
    };

    // Create the config dir (and parents) if it doesn't yet exist.
    if let Some(parent) = path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            tracing::warn!(
                "persistence: could not create config dir {}: {e}",
                parent.display()
            );
            return;
        }
    }

    // Write atomically: write to a sibling temp file then rename, so a crash
    // mid-write cannot leave a truncated config.toml (the rename is atomic on
    // the same filesystem).
    let tmp = path.with_extension("toml.tmp");
    if let Err(e) = std::fs::write(&tmp, &serialized) {
        tracing::warn!(
            "persistence: could not write temp config {}: {e}",
            tmp.display()
        );
        let _ = std::fs::remove_file(&tmp);
        return;
    }
    if let Err(e) = std::fs::rename(&tmp, path) {
        tracing::warn!(
            "persistence: could not rename temp config to {}: {e}",
            path.display()
        );
        let _ = std::fs::remove_file(&tmp);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::Path;

    /// Resolve a `toride/config.toml` path directly under `dir` (mirrors the
    /// real layout without touching the user's actual config dir).
    fn config_under(dir: &Path) -> PathBuf {
        dir.join(APP_DIR).join(CONFIG_FILE)
    }

    /// Write a config file under `dir` and return its full path.
    fn write_config(dir: &Path, contents: &str) -> PathBuf {
        let path = config_under(dir);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, contents).unwrap();
        path
    }

    #[test]
    fn save_then_load_round_trips_every_theme() {
        // True end-to-end: save_theme_to writes to a temp path, load_theme_from
        // reads it back and must resolve the exact same theme. Verified for
        // every theme variant so the label<->Theme mapping is fully covered.
        for &theme in Theme::all() {
            let dir = tempfile::tempdir().unwrap();
            let path = config_under(dir.path());
            // Config dir + file do not exist yet — save must create them.
            assert!(!path.exists());
            save_theme_to(&path, theme);
            assert!(path.exists(), "save created the config file");
            assert_eq!(
                load_theme_from(&path),
                theme,
                "round-trip failed for {theme:?}"
            );
        }
    }

    #[test]
    fn save_preserves_existing_unrelated_keys() {
        // A config that already has other keys must NOT lose them when the
        // theme is updated — the file is round-tripped through a TOML table.
        let dir = tempfile::tempdir().unwrap();
        let path = write_config(dir.path(), "log_level = \"debug\"\ntimeout = 30\n");
        save_theme_to(&path, Theme::Nord);

        let after = fs::read_to_string(&path).unwrap();
        assert!(
            after.contains("theme = \"Nord\""),
            "theme written: {after}"
        );
        assert!(
            after.contains("log_level = \"debug\""),
            "string key preserved: {after}"
        );
        assert!(
            after.contains("timeout = 30"),
            "non-string key preserved: {after}"
        );
        assert_eq!(
            after.matches("theme =").count(),
            1,
            "single theme key (no duplicate): {after}"
        );

        // And loading reflects the new theme.
        assert_eq!(load_theme_from(&path), Theme::Nord);
    }

    #[test]
    fn save_overwrites_previous_theme_value() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_config(dir.path(), "theme = \"Nord\"\n");
        save_theme_to(&path, Theme::Gruvbox);
        let after = fs::read_to_string(&path).unwrap();
        assert!(
            after.contains("theme = \"Gruvbox Dark\""),
            "theme overwritten: {after}"
        );
        assert!(
            !after.contains("theme = \"Nord\""),
            "old theme value gone: {after}"
        );
        assert_eq!(after.matches("theme =").count(), 1, "no duplicate: {after}");
    }

    #[test]
    fn load_missing_file_yields_default() {
        // No config file present → default theme (the common fresh-install
        // case). Must not panic.
        let dir = tempfile::tempdir().unwrap();
        let path = config_under(dir.path());
        assert!(!path.exists());
        assert_eq!(load_theme_from(&path), Theme::default());
    }

    #[test]
    fn load_corrupt_toml_yields_default() {
        // Malformed TOML must not panic; it falls back to the default theme.
        let dir = tempfile::tempdir().unwrap();
        let path = write_config(dir.path(), "this is = = not valid toml [");
        assert_eq!(load_theme_from(&path), Theme::default());
    }

    #[test]
    fn load_unknown_theme_label_yields_default() {
        // A syntactically-valid config with an unrecognized theme must fall
        // back to the default rather than coercing to a wrong variant.
        let dir = tempfile::tempdir().unwrap();
        let path = write_config(dir.path(), "theme = \"Made Up Theme\"\n");
        assert_eq!(load_theme_from(&path), Theme::default());
    }

    #[test]
    fn load_missing_theme_key_yields_default() {
        // A config with no theme key yields the default (None → default).
        let dir = tempfile::tempdir().unwrap();
        let path = write_config(dir.path(), "log_level = \"info\"\n");
        assert_eq!(load_theme_from(&path), Theme::default());
    }
}
