//! Convert `logs_data` tail results to UI presentation types.
//!
//! This is the single boundary between the [`logs_data`] collection layer and
//! the [`ui::screens::logs`] presentation layer — mirroring
//! `toride_harden_convert.rs`'s role for harden. The logs section is the one
//! read-only screen whose "backend" is already plain owned strings (decoded
//! UTF-8 file tails + journalctl output), so there is almost nothing to map:
//! the convert layer's job here is line-trimming to the viewer's budget,
//! placeholder substitution for malformed sources, and clamping the line list
//! so a misbehaving source cannot dump an unbounded tail into the TUI.
//!
//! Every function degrades gracefully: a source with an empty name gets a
//! placeholder, an oversized line list is trimmed to
//! [`MAX_VIEW_LINES`](self::MAX_VIEW_LINES), and no function ever returns
//! `Err` (the read-only section must never crash the TUI). The
//! [`LogSource`] type is re-exported here so the screen module never imports
//! [`logs_data`] directly, preserving the boundary.

// Re-export the per-source tail type so the screen module imports it from
// the convert layer (single boundary), matching how the other convert
// modules own their presentation types. `pub use` (not a private `use`) so
// the screen's `use crate::logs_convert::{convert_source, LogSource}` can
// name the type without going back to `logs_data` directly.
pub use crate::logs_data::{LogSource, LogSource as LogsSourceEntry};

/// Hard cap on the number of lines the viewer will render per source. The
/// data layer already keeps its own 200-line tail per source; this is a
/// second, defensive clamp so a future data-layer change that raises the cap
/// cannot push thousands of lines through the render path. Kept equal to the
/// data-layer cap so the convert layer is a no-op in the common case.
const MAX_VIEW_LINES: usize = 200;

/// Convert the raw per-source tails from [`logs_data`] into presentation
/// entries ready for the Logs viewer.
///
/// Each source is normalized:
/// * an empty `name` is replaced with `"(unknown)"`;
/// * an empty `path` is replaced with `"(no path)"`;
/// * `lines` longer than [`MAX_VIEW_LINES`] is trimmed to its tail and
///   `line_count` is recomputed to match;
/// * sources are kept in input order (the data layer lists toride's own log
///   first, then platform logs, then journalctl — that order is the viewer's
///   default Left/Right cycle and must not be reshuffled here).
///
/// The function never returns `Err` and never skips a source — even a
/// malformed/empty source is emitted so the operator can see that it was
/// probed. This mirrors the graceful-degradation contract of every other
/// convert module.
pub fn convert_sources(sources: Vec<LogSource>) -> Vec<LogSource> {
    sources.into_iter().map(convert_source).collect()
}

/// Convert a single source: normalize placeholders + clamp the line list.
///
/// See [`convert_sources`] for the per-field rules. `exists == false` sources
/// (permission-denied / absent-on-this-OS) pass through unchanged — the viewer
/// surfaces them with a dim row so the operator can see WHY a file is
/// missing, rather than silently dropping it.
pub fn convert_source(mut src: LogSource) -> LogSource {
    if src.name.is_empty() {
        tracing::warn!("logs source with empty name: path={:?}", src.path);
        src.name = "(unknown)".into();
    }
    if src.path.is_empty() {
        src.path = "(no path)".into();
    }

    // Defensive clamp: the data layer should already respect MAX_LINES, but
    // a future change (or a single journalctl line exceeding the budget) must
    // not be able to push an unbounded tail through the viewer. Trim to the
    // TAIL and recompute line_count so the header counter stays honest.
    if src.lines.len() > MAX_VIEW_LINES {
        let start = src.lines.len() - MAX_VIEW_LINES;
        src.lines = src.lines.split_off(start);
        src.line_count = src.lines.len();
    }

    src
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_source(name: &str, n_lines: usize) -> LogSource {
        LogSource {
            name: name.into(),
            path: format!("/var/log/{name}"),
            exists: true,
            size_bytes: 1024,
            mtime: Some("2021-01-01 00:00".into()),
            line_count: n_lines,
            lines: (0..n_lines).map(|i| format!("line {i}")).collect(),
        }
    }

    #[test]
    fn convert_sources_empty_is_empty() {
        assert!(convert_sources(Vec::new()).is_empty());
    }

    #[test]
    fn convert_sources_preserves_order() {
        let srcs = vec![
            sample_source("toride", 1),
            sample_source("syslog", 1),
            sample_source("journalctl", 1),
        ];
        let out = convert_sources(srcs);
        let names: Vec<&str> = out.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, vec!["toride", "syslog", "journalctl"]);
    }

    #[test]
    fn convert_source_replaces_empty_name() {
        let mut src = sample_source("auth", 0);
        src.name = String::new();
        let out = convert_source(src);
        assert_eq!(out.name, "(unknown)");
    }

    #[test]
    fn convert_source_replaces_empty_path() {
        let mut src = sample_source("auth", 0);
        src.path = String::new();
        let out = convert_source(src);
        assert_eq!(out.path, "(no path)");
    }

    #[test]
    fn convert_source_passes_through_unreadable_source() {
        // An exists==false / permission-denied source must NOT be dropped —
        // the viewer surfaces it so the operator sees WHY a file is missing.
        let src = LogSource {
            name: "secure (permission denied)".into(),
            path: "/var/log/secure".into(),
            exists: false,
            size_bytes: 0,
            mtime: Some("permission denied".into()),
            line_count: 0,
            lines: Vec::new(),
        };
        let out = convert_source(src.clone());
        assert_eq!(out.name, src.name);
        assert!(!out.exists);
        assert_eq!(out.mtime.as_deref(), Some("permission denied"));
    }

    #[test]
    fn convert_source_clamps_oversized_line_list() {
        // Simulate a data-layer regression that returns more than
        // MAX_VIEW_LINES lines: the convert layer must trim to the tail and
        // recompute line_count so the header counter stays honest.
        let mut src = sample_source("huge", MAX_VIEW_LINES * 3);
        // Tag the very first and very last lines so we can assert the trim
        // kept the tail (last MAX_VIEW_LINES), not the head.
        src.lines[0] = "FIRST_LINE_THAT_MUST_BE_DROPPED".into();
        let last_idx = src.lines.len() - 1;
        src.lines[last_idx] = "LAST_LINE_THAT_MUST_BE_KEPT".into();

        let out = convert_source(src);
        assert_eq!(
            out.lines.len(),
            MAX_VIEW_LINES,
            "convert_source must trim to MAX_VIEW_LINES"
        );
        assert_eq!(
            out.line_count, MAX_VIEW_LINES,
            "line_count must match the trimmed length"
        );
        assert!(
            !out.lines
                .iter()
                .any(|l| l == "FIRST_LINE_THAT_MUST_BE_DROPPED"),
            "the head must be dropped on trim"
        );
        assert!(
            out.lines.iter().any(|l| l == "LAST_LINE_THAT_MUST_BE_KEPT"),
            "the tail must be kept on trim"
        );
    }

    #[test]
    fn convert_source_does_not_trim_at_or_under_cap() {
        let src = sample_source("normal", MAX_VIEW_LINES);
        let out = convert_source(src);
        assert_eq!(out.lines.len(), MAX_VIEW_LINES);
        assert_eq!(out.line_count, MAX_VIEW_LINES);
    }

    #[test]
    fn logs_source_entry_alias_is_log_source() {
        // Pin the re-export so the screen module's `use crate::logs_convert`
        // import path stays valid: LogsSourceEntry must be the SAME type as
        // LogSource (not a newtype). A future rename of the alias would break
        // the screen module at compile time; this test makes that a loud
        // failure here instead.
        fn accept(_e: LogsSourceEntry) {}
        accept(LogSource {
            name: String::new(),
            path: String::new(),
            exists: false,
            size_bytes: 0,
            mtime: None,
            line_count: 0,
            lines: Vec::new(),
        });
    }
}
