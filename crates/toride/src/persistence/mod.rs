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

/// User preference for UI animations, persisted as an `animations = "<mode>"`
/// row in `config.toml` (mirroring how [`Theme`] is stored as a label string).
///
/// - `Auto` (default): run the layered VM/container [`virt_detect`](crate::virt_detect)
///   probe at startup and neutralize animations when the host looks virtualized.
/// - `On` / `Off`: explicit overrides that skip detection entirely.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum AnimPref {
    /// Auto-detect: disable animations on VMs/containers/WSL, enable elsewhere.
    #[default]
    Auto,
    /// Force animations on, regardless of the host (override).
    On,
    /// Force animations off, regardless of the host (override).
    Off,
}

impl AnimPref {
    /// The TOML label written to / read from `config.toml`.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            AnimPref::Auto => "auto",
            AnimPref::On => "on",
            AnimPref::Off => "off",
        }
    }

    /// Resolve a stored label back to a preference (case-insensitive). Returns
    /// `None` for an unrecognized label so the caller can fall back to the
    /// default rather than silently coercing a corrupt entry.
    #[must_use]
    pub fn from_label(label: &str) -> Option<AnimPref> {
        match label.trim().to_ascii_lowercase().as_str() {
            "auto" => Some(AnimPref::Auto),
            "on" | "enable" | "enabled" | "true" | "yes" => Some(AnimPref::On),
            "off" | "disable" | "disabled" | "false" | "no" | "none" => Some(AnimPref::Off),
            _ => None,
        }
    }
}

/// On-disk config representation.
///
/// The `theme` and `animations` keys are modeled; any other keys present in the
/// file are preserved on write (the file is round-tripped through a TOML table
/// so unrelated operator settings are never clobbered).
#[derive(Debug, Default, Serialize, Deserialize)]
struct ConfigFile {
    /// Selected theme, stored as its [`Theme::label`] (e.g. `"Charm"`).
    /// `None` / absent ⇒ fall back to the default theme.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    theme: Option<String>,
    /// Animation preference, stored as an [`AnimPref::label`]
    /// (e.g. `"auto"`, `"on"`, `"off"`). `None` / absent ⇒ `Auto`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    animations: Option<String>,
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
    let Some(path) = config_path() else {
        tracing::debug!("persistence: dirs::config_dir() returned None");
        return Theme::default();
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
    let Some(path) = config_path() else {
        tracing::debug!("persistence: no config dir; skipping theme save");
        return;
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

    if let Some(theme) = cfg.theme.as_deref().and_then(Theme::from_label) {
        theme
    } else {
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

/// Persist the theme to an explicit path (the testable core of [`save_theme`]).
///
/// Writes `theme = "<label>"`, preserving any other keys already in the file,
/// via an atomic temp-file-then-rename (delegated to
/// [`toride_fs::atomic_write_with_perms`]) with explicit `0600` permissions so
/// the user's toride config is owner-only and a crash mid-write cannot leave a
/// truncated config.
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

    write_config_atomic(path, &serialized);
}

// ── Animations preference ────────────────────────────────────────────────────
//
// Same shape as the theme entry points above: best-effort, never propagates
// errors, round-trips through the TOML table so unrelated keys survive, and
// degrades to `Auto` on any failure so the app keeps launching normally.

/// Load the persisted animation preference.
///
/// Any failure — no config dir, missing file, unreadable file, malformed TOML,
/// or an unrecognized label — is logged at debug/warn and yields
/// [`AnimPref::Auto`] (run the virtualization probe). This keeps the app
/// launching normally on a fresh install or with a corrupt config.
#[must_use]
pub fn load_animations() -> AnimPref {
    let Some(path) = config_path() else {
        tracing::debug!("persistence: dirs::config_dir() returned None");
        return AnimPref::Auto;
    };
    load_animations_from(&path)
}

/// Persist the animation preference so it survives the next launch.
///
/// Writes `animations = "<label>"`, preserving any other keys already in the
/// file (round-tripped through a TOML table). Failures are swallowed — a
/// read-only HOME must never crash the running TUI.
pub fn save_animations(pref: AnimPref) {
    let Some(path) = config_path() else {
        tracing::debug!("persistence: no config dir; skipping animations save");
        return;
    };
    save_animations_to(&path, pref);
}

/// Load the animation preference from an explicit path (testable core).
fn load_animations_from(path: &Path) -> AnimPref {
    let contents = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            if e.kind() == std::io::ErrorKind::NotFound {
                tracing::debug!(
                    "persistence: no config at {} (using auto animations)",
                    path.display()
                );
            } else {
                tracing::warn!("persistence: could not read {}: {e}", path.display());
            }
            return AnimPref::Auto;
        }
    };

    let cfg: ConfigFile = match toml::from_str(&contents) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(
                "persistence: ignoring corrupt config at {}: {e}",
                path.display()
            );
            return AnimPref::Auto;
        }
    };

    if let Some(pref) = cfg.animations.as_deref().and_then(AnimPref::from_label) {
        pref
    } else {
        if let Some(label) = cfg.animations.as_deref() {
            tracing::warn!(
                "persistence: unrecognized animations {label:?} in {}; using auto",
                path.display()
            );
        }
        AnimPref::Auto
    }
}

/// Persist the animation preference to an explicit path (testable core).
///
/// Like [`save_theme_to`], the write is delegated to
/// [`toride_fs::atomic_write_with_perms`] with explicit `0600` permissions.
fn save_animations_to(path: &Path, pref: AnimPref) {
    let mut table: toml::Table = std::fs::read_to_string(path)
        .ok()
        .and_then(|c| toml::from_str(&c).ok())
        .unwrap_or_default();

    table.insert(
        "animations".to_string(),
        toml::Value::String(pref.label().to_string()),
    );

    let serialized = match toml::to_string(&table) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("persistence: could not serialize animations: {e}");
            return;
        }
    };

    write_config_atomic(path, &serialized);
}

/// Shared tail of [`save_theme_to`] / [`save_animations_to`]: create the config
/// dir if missing, then persist `serialized` atomically with explicit `0600`
/// permissions (owner-only) via [`toride_fs::atomic_write_with_perms`].
///
/// The atomic write fsyncs on both sides of the rename and sets the mode up
/// front (independent of umask), so a crash mid-write cannot leave a truncated
/// config and the file is never briefly world-readable. Errors are logged and
/// swallowed — a read-only HOME must never crash the running TUI.
fn write_config_atomic(path: &Path, serialized: &str) {
    // 0600: the user's toride config may carry preferences but should still be
    // owner-only (no group/other read), matching the sensitivity of a per-user
    // config file.
    const CONFIG_MODE: u32 = 0o600;

    // Create the config dir (and parents) if it doesn't yet exist.
    if let Some(parent) = path.parent()
        && let Err(e) = std::fs::create_dir_all(parent)
    {
        tracing::warn!(
            "persistence: could not create config dir {}: {e}",
            parent.display()
        );
        return;
    }

    if let Err(e) = toride_fs::atomic_write_with_perms(path, serialized, CONFIG_MODE) {
        tracing::warn!(
            "persistence: could not write config {}: {e}",
            path.display()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::Path;

    #[cfg(unix)]
    /// Read the low 9 permission bits (rwxrwxrwx) of `path` as an octal mask.
    fn file_mode(path: &Path) -> u32 {
        use std::os::unix::fs::MetadataExt;
        fs::metadata(path)
            .expect("config file should exist for mode check")
            .mode()
            & 0o777
    }

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

    #[cfg(unix)]
    #[test]
    fn save_theme_writes_with_owner_only_0600_mode() {
        // The user's config file must be owner-only (0600) — atomic_write_with_perms
        // sets the mode up front independent of umask, so this holds regardless of
        // the test environment's umask.
        let dir = tempfile::tempdir().unwrap();
        let path = config_under(dir.path());
        save_theme_to(&path, Theme::Gruvbox);
        assert!(path.exists());
        assert_eq!(
            file_mode(&path),
            0o600,
            "config.toml must be owner-only after a theme save"
        );
    }

    #[cfg(unix)]
    #[test]
    fn save_animations_preserves_0600_mode_on_overwrite() {
        use std::os::unix::fs::PermissionsExt;
        // Overwriting an existing config must reset it to 0600 even if the
        // previous file was looser (atomic_write_with_perms re-sets the mode
        // after the rename as a safety net).
        let dir = tempfile::tempdir().unwrap();
        let path = write_config(dir.path(), "theme = \"Nord\"\n");
        // Loosen the existing file to confirm the save tightens it back.
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(file_mode(&path), 0o644);

        save_animations_to(&path, AnimPref::Off);
        assert_eq!(
            file_mode(&path),
            0o600,
            "config.toml must be tightened to owner-only after an animations save"
        );
    }

    #[test]
    fn save_preserves_existing_unrelated_keys() {
        // A config that already has other keys must NOT lose them when the
        // theme is updated — the file is round-tripped through a TOML table.
        let dir = tempfile::tempdir().unwrap();
        let path = write_config(dir.path(), "log_level = \"debug\"\ntimeout = 30\n");
        save_theme_to(&path, Theme::Nord);

        let after = fs::read_to_string(&path).unwrap();
        assert!(after.contains("theme = \"Nord\""), "theme written: {after}");
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

    // ── AnimPref label round-trip ─────────────────────────────────────────

    #[test]
    fn anim_pref_label_round_trips() {
        for &pref in &[AnimPref::Auto, AnimPref::On, AnimPref::Off] {
            assert_eq!(AnimPref::from_label(pref.label()), Some(pref));
        }
    }

    #[test]
    fn anim_pref_from_label_is_case_insensitive() {
        assert_eq!(AnimPref::from_label("AUTO"), Some(AnimPref::Auto));
        assert_eq!(AnimPref::from_label("On"), Some(AnimPref::On));
        assert_eq!(AnimPref::from_label("OFF"), Some(AnimPref::Off));
    }

    #[test]
    fn anim_pref_accepts_friendly_aliases() {
        // Common spellings an operator might hand-edit into config.toml.
        assert_eq!(AnimPref::from_label("disable"), Some(AnimPref::Off));
        assert_eq!(AnimPref::from_label("enabled"), Some(AnimPref::On));
        assert_eq!(AnimPref::from_label("true"), Some(AnimPref::On));
        assert_eq!(AnimPref::from_label("false"), Some(AnimPref::Off));
    }

    #[test]
    fn anim_pref_from_label_rejects_unknown() {
        assert!(AnimPref::from_label("glacial").is_none());
        assert!(AnimPref::from_label("").is_none());
    }

    #[test]
    fn anim_pref_default_is_auto() {
        assert_eq!(AnimPref::default(), AnimPref::Auto);
    }

    // ── Animations persistence round-trip ─────────────────────────────────

    #[test]
    fn save_then_load_round_trips_every_anim_pref() {
        for &pref in &[AnimPref::Auto, AnimPref::On, AnimPref::Off] {
            let dir = tempfile::tempdir().unwrap();
            let path = config_under(dir.path());
            assert!(!path.exists());
            save_animations_to(&path, pref);
            assert!(path.exists(), "save created the config file");
            assert_eq!(load_animations_from(&path), pref, "round-trip {pref:?}");
        }
    }

    #[test]
    fn save_animations_preserves_theme_and_unrelated_keys() {
        // Animations + theme + unrelated keys must all survive a write.
        let dir = tempfile::tempdir().unwrap();
        let path = write_config(dir.path(), "theme = \"Nord\"\nlog_level = \"debug\"\n");
        save_animations_to(&path, AnimPref::Off);
        let after = fs::read_to_string(&path).unwrap();
        assert!(
            after.contains("animations = \"off\""),
            "animations written: {after}"
        );
        assert!(
            after.contains("theme = \"Nord\""),
            "theme preserved: {after}"
        );
        assert!(
            after.contains("log_level = \"debug\""),
            "unrelated key preserved: {after}"
        );
        assert_eq!(load_animations_from(&path), AnimPref::Off);
        assert_eq!(load_theme_from(&path), Theme::Nord);
    }

    #[test]
    fn load_animations_missing_file_yields_auto() {
        let dir = tempfile::tempdir().unwrap();
        let path = config_under(dir.path());
        assert!(!path.exists());
        assert_eq!(load_animations_from(&path), AnimPref::Auto);
    }

    #[test]
    fn load_animations_corrupt_toml_yields_auto() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_config(dir.path(), "this is = = not valid toml [");
        assert_eq!(load_animations_from(&path), AnimPref::Auto);
    }

    #[test]
    fn load_animations_unknown_label_yields_auto() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_config(dir.path(), "animations = \"glacial\"\n");
        assert_eq!(load_animations_from(&path), AnimPref::Auto);
    }

    #[test]
    fn load_animations_absent_key_yields_auto() {
        // A config with no animations key → Auto (None → Auto → run probe).
        let dir = tempfile::tempdir().unwrap();
        let path = write_config(dir.path(), "theme = \"Charm\"\n");
        assert_eq!(load_animations_from(&path), AnimPref::Auto);
    }
}
