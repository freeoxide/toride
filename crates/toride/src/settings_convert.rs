//! Convert local config-file + environment reads into UI presentation types.
//!
//! This is the ONLY module that knows how to read the toride config file and
//! the process environment for the Settings section — mirroring
//! `toride_harden_convert`'s role as the single boundary between source and
//! presentation. Every function degrades gracefully: an unreadable config
//! file, a missing env var, or a malformed `key = value` row is logged and
//! substituted with a placeholder / `None`, never propagated (the read-only
//! section must never crash the TUI).
//!
//! The config crate (`crate::config`) is currently a stub with no loader, so
//! the config path is resolved via [`dirs`] and the file is parsed line-by-line
//! as `key = value` (with `#`/`;` comments and `[section]` headers tolerated).
//! When the config crate grows a real loader it can be swapped in here without
//! touching the data collector or the screen.

use crate::ui::screens::settings::{SettingsConfig, SettingsRuntime};

/// Read the config file + environment off the calling (blocking) thread and
/// build a populated [`SettingsDataBundle`](crate::settings_data::SettingsDataBundle).
///
/// This is the entry point invoked inside `spawn_blocking` by
/// [`collect_real_settings`](crate::settings_data::collect_real_settings).
/// Every probe degrades independently: an absent config file →
/// `config.exists = false`, `raw_keys` empty; a missing env var → `None`.
/// Availability stays `true` whenever the task body ran (only a panic flips it
/// to `false`, handled by the outer spawn in `start()`).
#[must_use]
pub fn collect_local() -> crate::settings_data::SettingsDataBundle {
    let config = convert_config();
    let runtime = convert_runtime();

    crate::settings_data::SettingsDataBundle {
        // The task body ran without panicking → available. The config-file
        // presence only gates the CONFIG block, not availability, so a host
        // with no config file still shows the runtime + theme list.
        available: true,
        config,
        runtime,
        unavailable_reason: None,
    }
}

/// Empty [`SettingsConfig`] for the pre-first-poll / degraded bundle.
#[must_use]
pub fn empty_config() -> SettingsConfig {
    SettingsConfig {
        path: String::new(),
        exists: false,
        active_theme_name: None,
        log_level: None,
        raw_keys: Vec::new(),
    }
}

/// Empty [`SettingsRuntime`] for the pre-first-poll / degraded bundle.
#[must_use]
pub fn empty_runtime() -> SettingsRuntime {
    SettingsRuntime {
        rust_log: None,
        data_dir: None,
        config_dir: None,
        log_path: None,
        shell: None,
        term: None,
    }
}

/// Resolve the toride config file path and parse its `key = value` rows.
///
/// The path is `<config_dir>/toride/config.toml` when `dirs::config_dir`
/// resolves (standard XDG / Library/Application Support / AppData\Roaming); if
/// `dirs` cannot resolve a config dir (unusual but possible), the path is the
/// literal `(no config dir)` placeholder and `exists = false`. The file is read
/// best-effort: a missing or unreadable file yields `exists = false` + empty
/// `raw_keys`. Known keys (`theme`, `log_level`) are surfaced as dedicated
/// typed fields in addition to the raw rows; every other `key = value` row is
/// preserved verbatim so the operator sees the full on-disk state.
pub fn convert_config() -> SettingsConfig {
    let path = if let Some(d) = dirs::config_dir() {
        d.join("toride").join("config.toml")
    } else {
        tracing::debug!("settings: dirs::config_dir() returned None");
        return empty_config_with_path("(no config dir)".to_string());
    };

    let path_str = path.display().to_string();
    let contents = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(e) => {
            // Missing file is the COMMON case on a fresh install — debug, not
            // warn. Anything else (permission denied, IO error) is warn.
            if e.kind() == std::io::ErrorKind::NotFound {
                tracing::debug!("settings: no config file at {path_str} (using defaults)");
            } else {
                tracing::warn!("settings: could not read config {path_str}: {e}");
            }
            return SettingsConfig {
                path: path_str,
                exists: false,
                active_theme_name: None,
                log_level: None,
                raw_keys: Vec::new(),
            };
        }
    };

    let raw_keys = parse_kv_rows(&contents);
    let active_theme_name = lookup(&raw_keys, "theme").map(strip_quotes);
    let log_level = lookup(&raw_keys, "log_level")
        .or_else(|| lookup(&raw_keys, "log-level"))
        .map(strip_quotes);

    SettingsConfig {
        path: path_str,
        exists: true,
        active_theme_name,
        log_level,
        raw_keys,
    }
}

/// Snapshot the runtime environment for the RUNTIME block.
///
/// Reads `RUST_LOG`, the standard `dirs` data/config dirs, the configured log
/// file path, `$SHELL`, and `$TERM`. Every lookup is independent; a missing
/// value yields `None` for its slot rather than aborting the block.
pub fn convert_runtime() -> SettingsRuntime {
    let rust_log = env("RUST_LOG");
    let data_dir = dirs::data_dir().map(|d| d.join("toride").display().to_string());
    let config_dir = dirs::config_dir().map(|d| d.join("toride").display().to_string());
    let log_path =
        dirs::data_dir().map(|d| d.join("toride").join("toride.log").display().to_string());
    let shell = env("SHELL");
    let term = env("TERM");

    SettingsRuntime {
        rust_log,
        data_dir,
        config_dir,
        log_path,
        shell,
        term,
    }
}

// ── Helpers ─────────────────────────────────────────────────────────────────

/// Read an environment variable, returning `None` (debug-logged) when absent
/// or invalid UTF-8. Never panics.
fn env(name: &str) -> Option<String> {
    match std::env::var(name) {
        Ok(v) if !v.is_empty() => Some(v),
        Ok(_) => None,
        Err(e) => {
            tracing::debug!("settings: env {name} unset ({e})");
            None
        }
    }
}

/// Parse `key = value` rows out of raw config text, tolerating comments and
/// section headers. Malformed lines are skipped (debug-logged) — never panic.
///
/// - Lines starting with `#` or `;` are comments.
/// - `[section]` headers are skipped (the section name is not folded into the
///   key — the config schema today is flat; a future structured loader can
///   replace this).
/// - A line without `=` is skipped.
/// - Empty keys (e.g. `= value`) are skipped as malformed.
pub fn parse_kv_rows(contents: &str) -> Vec<(String, String)> {
    let mut rows = Vec::new();
    for (lineno, raw) in contents.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            // Section header — skip (flat schema today).
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            tracing::debug!(
                "settings: config line {} is not key=value: {raw:?}",
                lineno + 1
            );
            continue;
        };
        let key = key.trim();
        if key.is_empty() {
            tracing::warn!(
                "settings: config line {} has empty key: {raw:?}",
                lineno + 1
            );
            continue;
        }
        rows.push((key.to_string(), value.trim().to_string()));
    }
    rows
}

/// Case-insensitive value lookup for a key in the parsed rows.
fn lookup(rows: &[(String, String)], key: &str) -> Option<String> {
    rows.iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(key))
        .map(|(_, v)| v.clone())
}

/// Strip a single layer of surrounding double-quotes from a value, so
/// `theme = "Charm"` parses to `Charm`. Single-quotes and unmatched quotes are
/// left untouched (the raw row preserves the original).
fn strip_quotes(s: String) -> String {
    let len = s.len();
    if len >= 2 && s.starts_with('"') && s.ends_with('"') {
        s[1..len - 1].to_string()
    } else {
        s
    }
}

/// [`empty_config`] but carrying a concrete path string (used when `dirs`
/// itself returns `None` — the panel then shows why the path is blank).
fn empty_config_with_path(path: String) -> SettingsConfig {
    SettingsConfig {
        path,
        exists: false,
        active_theme_name: None,
        log_level: None,
        raw_keys: Vec::new(),
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_config_is_zeroed() {
        let c = empty_config();
        assert!(c.path.is_empty());
        assert!(!c.exists);
        assert!(c.active_theme_name.is_none());
        assert!(c.log_level.is_none());
        assert!(c.raw_keys.is_empty());
    }

    #[test]
    fn empty_runtime_is_zeroed() {
        let r = empty_runtime();
        assert!(r.rust_log.is_none());
        assert!(r.data_dir.is_none());
        assert!(r.shell.is_none());
    }

    #[test]
    fn parse_kv_rows_basic() {
        let rows = parse_kv_rows("theme = Charm\nlog_level = debug\n");
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0], ("theme".to_string(), "Charm".to_string()));
        assert_eq!(rows[1], ("log_level".to_string(), "debug".to_string()));
    }

    #[test]
    fn parse_kv_rows_skips_comments_and_blanks() {
        let txt = "# a comment\n\ntheme = Charm\n; semi comment\nlog = info\n";
        let rows = parse_kv_rows(txt);
        assert_eq!(rows.len(), 2);
    }

    #[test]
    fn parse_kv_rows_skips_section_headers() {
        let rows = parse_kv_rows("[ui]\ntheme = Charm\n");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].0, "theme");
    }

    #[test]
    fn parse_kv_rows_skips_malformed_lines() {
        let rows = parse_kv_rows("just a line\ntheme = Charm\n= novalue\n");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].0, "theme");
    }

    #[test]
    fn parse_kv_rows_preserves_quoted_values_verbatim() {
        // Quoting is preserved in raw_keys; the dedicated typed lookup strips
        // quotes, but the raw row shows exactly what is on disk.
        let rows = parse_kv_rows("theme = \"Charm\"\n");
        assert_eq!(rows[0].1, "\"Charm\"");
    }

    #[test]
    fn lookup_is_case_insensitive() {
        let rows = vec![("Theme".to_string(), "Charm".to_string())];
        assert_eq!(lookup(&rows, "theme").as_deref(), Some("Charm"));
        assert_eq!(lookup(&rows, "THEME").as_deref(), Some("Charm"));
        assert!(lookup(&rows, "missing").is_none());
    }

    #[test]
    fn strip_quotes_removes_surrounding_double_quotes() {
        assert_eq!(strip_quotes("\"Charm\"".into()), "Charm");
        assert_eq!(strip_quotes("Charm".into()), "Charm");
        assert_eq!(strip_quotes("\"unmatched".into()), "\"unmatched");
    }

    #[test]
    fn collect_local_returns_available_bundle() {
        // collect_local always returns available == true (the task body ran).
        // Config-file presence only gates the CONFIG block.
        let b = collect_local();
        assert!(b.available);
        assert!(b.unavailable_reason.is_none());
    }

    #[test]
    fn convert_config_path_is_nonempty_on_any_host() {
        // Either dirs resolved a real config dir (concrete path) or it returned
        // None and convert_config surfaced the "(no config dir)" placeholder.
        // Either way the path string must not be blank.
        let c = convert_config();
        assert!(!c.path.is_empty(), "config path must not be blank: {c:?}");
    }

    #[test]
    fn convert_runtime_does_not_panic() {
        // Smokes the env/dir reads; values are host-dependent so just assert no
        // panic and the block is well-formed.
        let _r = convert_runtime();
    }
}
