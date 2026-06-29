//! Convert `toride-mise` library types to UI presentation types.
//!
//! This is the ONLY module in the `toride` crate that imports `toride_mise`
//! types — mirroring [`fail2ban_convert`](crate::fail2ban_convert)'s role as the
//! single boundary between backend and presentation. Each function handles
//! errors gracefully: malformed input is skipped with a `tracing::warn!` and a
//! placeholder, never propagated (the read-only section must never crash the
//! TUI).

use crate::ui::screens::toride_mise::{MiseFindingEntry, MiseOutdatedEntry, MiseToolEntry};

/// Map a backend [`toride_mise::DiagnosticKind`] to a lowercase severity string
/// used by the presentation layer. The mise backend does not carry its own
/// severity enum (the doctor report splits into `warnings` / `errors` only);
/// the kind is mapped to the closest severity band so findings can be grouped
/// by the content pane like the fail2ban / Tailscale sections.
///
/// - "error"   — `BinaryMissing`, `VersionUnsupported`, `InvalidConfig`,
///   `NetworkIssue`, `PermissionIssue` (these block mise from working).
/// - "warning" — `PathMissing`, `ConfigNotFound`, `ConfigUntrusted`,
///   `LockfileMissing`, `MissingTools`, `OutdatedTools` (advisories the
///   operator should act on but which do not block basic operation).
/// - "info"    — `Other`.
fn kind_severity(kind: &toride_mise::diagnostics::DiagnosticKind) -> &'static str {
    use toride_mise::diagnostics::DiagnosticKind;
    match kind {
        DiagnosticKind::BinaryMissing
        | DiagnosticKind::VersionUnsupported
        | DiagnosticKind::InvalidConfig
        | DiagnosticKind::NetworkIssue
        | DiagnosticKind::PermissionIssue => "error",
        DiagnosticKind::PathMissing
        | DiagnosticKind::ConfigNotFound
        | DiagnosticKind::ConfigUntrusted
        | DiagnosticKind::LockfileMissing
        | DiagnosticKind::MissingTools
        | DiagnosticKind::OutdatedTools => "warning",
        DiagnosticKind::Other => "info",
    }
}

/// Convert a backend [`toride_mise::diagnostics::Diagnostic`] to a UI finding.
///
/// An empty message is logged and replaced with a placeholder so the row count
/// matches the backend.
pub fn convert_diagnostic(d: toride_mise::diagnostics::Diagnostic) -> MiseFindingEntry {
    if d.message.is_empty() {
        tracing::warn!("mise diagnostic with empty message: kind={:?}", d.kind);
    }
    MiseFindingEntry {
        severity: kind_severity(&d.kind).to_string(),
        message: if d.message.is_empty() {
            "(no message)".into()
        } else {
            d.message
        },
        detail: d.detail,
    }
}

/// Convert a `Vec` of backend diagnostics into UI findings (1:1).
pub fn convert_diagnostics(
    diags: Vec<toride_mise::diagnostics::Diagnostic>,
) -> Vec<MiseFindingEntry> {
    diags.into_iter().map(convert_diagnostic).collect()
}

/// Convert a backend [`toride_mise::ToolStatus`] (from `mise ls --json`) to a UI
/// tool row.
///
/// An empty `name` is logged and replaced with a placeholder so the row is
/// still rendered (so the operator can see something even if the entry is
/// malformed).
pub fn convert_tool(t: toride_mise::ToolStatus) -> MiseToolEntry {
    if t.name.is_empty() {
        tracing::warn!("mise tool with empty name");
    }
    let source = t.source.and_then(|s| s.path).filter(|p| !p.is_empty());
    MiseToolEntry {
        name: if t.name.is_empty() {
            "(unknown)".into()
        } else {
            t.name
        },
        version: t.version.filter(|v| !v.is_empty()),
        active: t.active.unwrap_or(false),
        outdated: t.outdated.unwrap_or(false),
        missing: t.missing.unwrap_or(false),
        source,
    }
}

/// Convert a `Vec` of backend tool statuses into UI tool rows (1:1).
pub fn convert_tools(t: Vec<toride_mise::ToolStatus>) -> Vec<MiseToolEntry> {
    t.into_iter().map(convert_tool).collect()
}

/// Convert the canonical `mise outdated --json` output (a map keyed by tool
/// name, [`OutdatedOutput`](toride_mise::serde_utils::json_outputs::OutdatedOutput))
/// into UI outdated rows.
///
/// This is the LIVE path used by [`collect_real_mise`](crate::toride_mise_data::collect_real_mise):
/// real `mise outdated --json` emits a JSON *object*
/// `{"node":{"requested":"22","current":"22.0.0","latest":"22.1.0"}}`, NOT a
/// sequence. The map key is the tool name; the entry carries `current`,
/// `latest`, and (optionally) `backend`. Empty `current` / `latest` / `backend`
/// strings are dropped to `None` so the UI renders a blank rather than a
/// misleading empty span. A tool whose key is empty is skipped (a nameless row
/// would be meaningless).
pub fn convert_outdated_map(
    map: toride_mise::serde_utils::json_outputs::OutdatedOutput,
) -> Vec<MiseOutdatedEntry> {
    use toride_mise::serde_utils::json_outputs::OutdatedToolEntry;

    map.into_iter()
        .filter_map(|(name, entry)| {
            if name.is_empty() {
                tracing::warn!("mise outdated map entry with empty key");
                return None;
            }
            let OutdatedToolEntry {
                current,
                latest,
                backend,
                ..
            } = entry;
            Some(MiseOutdatedEntry {
                name,
                current: current.filter(|v| !v.is_empty()),
                latest: latest.filter(|v| !v.is_empty()),
                backend: backend.filter(|v| !v.is_empty()),
            })
        })
        .collect()
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use toride_mise::diagnostics::Diagnostic;
    use toride_mise::diagnostics::DiagnosticKind;

    // ── convert_diagnostic ───────────────────────────────────────────────────

    #[test]
    fn convert_diagnostics_empty() {
        assert!(convert_diagnostics(Vec::new()).is_empty());
    }

    #[test]
    fn convert_diagnostic_maps_severity() {
        let diags = vec![
            Diagnostic::new(DiagnosticKind::BinaryMissing, "no mise"),
            Diagnostic::new(DiagnosticKind::OutdatedTools, "old node"),
            Diagnostic::new(DiagnosticKind::Other, "misc"),
        ];
        let entries = convert_diagnostics(diags);
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].severity, "error");
        assert_eq!(entries[1].severity, "warning");
        assert_eq!(entries[2].severity, "info");
    }

    #[test]
    fn convert_diagnostic_preserves_detail() {
        let d = Diagnostic::new(DiagnosticKind::MissingTools, "go missing")
            .with_detail("run mise install");
        let entry = convert_diagnostic(d);
        assert_eq!(entry.message, "go missing");
        assert_eq!(entry.detail.as_deref(), Some("run mise install"));
    }

    #[test]
    fn convert_diagnostic_placeholder_for_empty_message() {
        let d = Diagnostic::new(DiagnosticKind::Other, "");
        let entry = convert_diagnostic(d);
        assert_eq!(entry.message, "(no message)");
    }

    // ── convert_tool ─────────────────────────────────────────────────────────

    #[test]
    fn convert_tool_basic() {
        let t = toride_mise::ToolStatus {
            name: "node".into(),
            version: Some("22.1.0".into()),
            source: Some(toride_mise::tool::installed::SourceInfo {
                path: Some(".mise.toml".into()),
                requested: None,
            }),
            active: Some(true),
            install_path: None,
            installed: Some(true),
            missing: Some(false),
            outdated: Some(false),
            requested: None,
        };
        let entry = convert_tool(t);
        assert_eq!(entry.name, "node");
        assert_eq!(entry.version.as_deref(), Some("22.1.0"));
        assert!(entry.active);
        assert!(!entry.outdated);
        assert_eq!(entry.source.as_deref(), Some(".mise.toml"));
    }

    #[test]
    fn convert_tool_drops_empty_version() {
        let t = toride_mise::ToolStatus {
            name: "x".into(),
            version: Some(String::new()),
            source: None,
            active: None,
            install_path: None,
            installed: None,
            missing: Some(true),
            outdated: None,
            requested: None,
        };
        let entry = convert_tool(t);
        assert!(entry.version.is_none());
        assert!(entry.missing);
    }

    #[test]
    fn convert_tool_placeholder_for_empty_name() {
        let t = toride_mise::ToolStatus {
            name: String::new(),
            version: None,
            source: None,
            active: None,
            install_path: None,
            installed: None,
            missing: None,
            outdated: None,
            requested: None,
        };
        let entry = convert_tool(t);
        assert_eq!(entry.name, "(unknown)");
    }

    #[test]
    fn convert_tool_drops_empty_source_path() {
        let t = toride_mise::ToolStatus {
            name: "x".into(),
            version: None,
            source: Some(toride_mise::tool::installed::SourceInfo {
                path: Some(String::new()),
                requested: None,
            }),
            active: None,
            install_path: None,
            installed: None,
            missing: None,
            outdated: None,
            requested: None,
        };
        let entry = convert_tool(t);
        assert!(entry.source.is_none());
    }

    // NOTE: `convert_outdated` / `convert_outdated_tools` (the legacy
    // Vec<OutdatedTool> shape) were removed — the collector has exclusively used
    // `convert_outdated_map` (the JSON-object shape emitted by
    // `mise outdated --json`) since the map-vs-array parse fix. The only tests
    // for the removed functions are deleted alongside them; the map path below
    // covers the same empty-field / empty-name edge cases.

    // ── convert_outdated_map (the LIVE path used by collect_real_mise) ───────
    //
    // Real `mise outdated --json` emits a JSON OBJECT keyed by tool name. These
    // tests exercise the canonical payload (matching
    // crates/toride-mise/fixtures/outdated/basic.json) plus the unhappy paths,
    // mirroring the bar set by fail2ban_convert's empty/malformed/degenerate
    // tests.

    fn parse_outdated_json(raw: &str) -> toride_mise::serde_utils::json_outputs::OutdatedOutput {
        // Mirror the deserialisation the backend's run_json performs, so a test
        // failure here signals the same break the collector would hit in prod.
        serde_json::from_str(raw).expect("outdated JSON must parse into OutdatedOutput")
    }

    #[test]
    fn convert_outdated_map_real_fixture_basic() {
        // Exact contents of crates/toride-mise/fixtures/outdated/basic.json:
        // {"node":{"requested":"22","current":"22.0.0","latest":"22.1.0"}}
        let raw = r#"{"node":{"requested":"22","current":"22.0.0","latest":"22.1.0"}}"#;
        let map = parse_outdated_json(raw);
        let entries = convert_outdated_map(map);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "node");
        // current must be the INSTALLED version, not the requested config pin.
        assert_eq!(entries[0].current.as_deref(), Some("22.0.0"));
        // latest must be the available upgrade, NOT the requested "22".
        assert_eq!(entries[0].latest.as_deref(), Some("22.1.0"));
        // No backend reported by this payload.
        assert!(entries[0].backend.is_none());
    }

    #[test]
    fn convert_outdated_map_multiple_tools_preserves_current_latest() {
        let raw = r#"{
            "node":{"requested":"22","current":"22.0.0","latest":"22.1.0"},
            "python":{"requested":"3.11","current":"3.11.0","latest":"3.11.1","backend":"core"}
        }"#;
        let entries = convert_outdated_map(parse_outdated_json(raw));
        assert_eq!(entries.len(), 2);
        // BTreeMap ordering -> node before python.
        assert_eq!(entries[0].name, "node");
        assert_eq!(entries[0].latest.as_deref(), Some("22.1.0"));
        assert_eq!(entries[1].name, "python");
        assert_eq!(entries[1].current.as_deref(), Some("3.11.0"));
        assert_eq!(entries[1].latest.as_deref(), Some("3.11.1"));
        assert_eq!(entries[1].backend.as_deref(), Some("core"));
    }

    #[test]
    fn convert_outdated_map_empty_object_yields_empty() {
        // `mise outdated --json` returns `{}` when nothing is outdated.
        let entries = convert_outdated_map(parse_outdated_json("{}"));
        assert!(entries.is_empty());
    }

    #[test]
    fn convert_outdated_map_drops_empty_version_strings() {
        // A degenerate entry with empty current/latest/backend must drop them
        // to None rather than rendering empty spans (mirrors
        // convert_outdated_drops_empty_fields for the map path).
        let raw = r#"{"go":{"requested":"","current":"","latest":"","backend":""}}"#;
        let entries = convert_outdated_map(parse_outdated_json(raw));
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "go");
        assert!(entries[0].current.is_none());
        assert!(entries[0].latest.is_none());
        assert!(entries[0].backend.is_none());
    }

    #[test]
    fn convert_outdated_map_skips_empty_name_key() {
        // An empty map key would produce a nameless row; the converter skips it.
        let raw = r#"{"":{"current":"1.0.0","latest":"1.0.1"}}"#;
        let entries = convert_outdated_map(parse_outdated_json(raw));
        assert!(entries.is_empty(), "empty-key entries must be dropped");
    }

    #[test]
    fn convert_outdated_map_does_not_map_latest_to_requested() {
        // Regression guard for the original bug where `latest` was mapped from
        // `requested` (the config pin) instead of the actual latest available
        // version. With requested != latest, latest MUST equal the entry's
        // `latest` field, never `requested`.
        let raw = r#"{"node":{"requested":"20","current":"20.0.0","latest":"22.1.0"}}"#;
        let entries = convert_outdated_map(parse_outdated_json(raw));
        assert_eq!(entries[0].latest.as_deref(), Some("22.1.0"));
        assert_ne!(entries[0].latest.as_deref(), Some("20"));
    }

    #[test]
    fn convert_outdated_map_parses_despite_being_a_map_not_sequence() {
        // The whole reason convert_outdated_map exists: the payload is a JSON
        // object, which the previous Vec<ToolStatus> probe could not parse.
        // Asserting the parse succeeds (and yields the expected row) guards
        // against regressing back to a sequence-expecting deserialiser.
        let raw = r#"{"node":{"requested":"22","current":"22.0.0","latest":"22.1.0"}}"#;
        let map = parse_outdated_json(raw);
        assert_eq!(map.len(), 1);
        let entries = convert_outdated_map(map);
        assert_eq!(entries[0].current.as_deref(), Some("22.0.0"));
        assert_eq!(entries[0].latest.as_deref(), Some("22.1.0"));
    }
}
