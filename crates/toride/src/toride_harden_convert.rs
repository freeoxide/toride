//! Convert `toride-harden` library types to UI presentation types.
//!
//! This is the ONLY module in the `toride` crate that imports `toride_harden`
//! types — mirroring `fail2ban_convert.rs`'s role as the single boundary between
//! backend and presentation. Each function handles errors gracefully: malformed
//! input is skipped with a `tracing::warn!` and a placeholder, never propagated
//! (the read-only section must never crash the TUI).
//!
//! The doctor findings returned by `toride_harden::doctor::doctor` use the
//! shared `toride_diagnostic_types::{Finding, Severity}` shape (re-exported at
//! the `toride_harden` crate root so this module never names the diagnostic
//! crate directly).

use crate::ui::screens::toride_harden::{FindingEntry, HardenProfileEntry, MountEntry, SysctlRow};
use toride_harden::HardeningProfile;
use toride_harden::shm::MountInfo;
use toride_harden::spec::SysctlParam;

/// Map a backend [`toride_harden::Severity`] (re-exported from
/// `toride_diagnostic_types::Severity`) to a lowercase string used by the
/// presentation layer: `"ok" | "info" | "warning" | "important" | "critical"`.
/// Kept here so the TUI never imports the Severity enum directly.
fn severity_str(s: toride_harden::Severity) -> &'static str {
    use toride_harden::Severity;
    match s {
        Severity::Ok => "ok",
        Severity::Info => "info",
        Severity::Warning => "warning",
        Severity::Important => "important",
        Severity::Critical => "critical",
    }
}

/// Convert backend doctor findings to UI entries.
///
/// Every finding maps 1:1. An empty `id` or `message` is logged and the entry is
/// still produced with a placeholder so the row count matches the backend (the
/// operator can see "something" even if the finding is malformed). The backend
/// `detail` / `fix_hint` are `Option<String>`; the UI carries `String` /
/// `Option<String>` respectively, so `None` detail flattens to an empty string
/// and `None` `fix_hint` stays `None`.
pub fn convert_findings(findings: Vec<toride_harden::Finding>) -> Vec<FindingEntry> {
    findings
        .into_iter()
        .map(|f| {
            if f.id.is_empty() || f.message.is_empty() {
                tracing::warn!(
                    "harden finding with empty id/message: id={:?} message={:?}",
                    f.id,
                    f.message
                );
            }
            FindingEntry {
                id: if f.id.is_empty() {
                    "(unknown)".into()
                } else {
                    f.id
                },
                severity: severity_str(f.severity).to_string(),
                title: if f.message.is_empty() {
                    "(no title)".into()
                } else {
                    f.message
                },
                detail: f.detail.unwrap_or_default(),
                fix: f.fix_hint,
            }
        })
        .collect()
}

/// Convert backend `SysctlParam` + current value into a UI table row.
///
/// `current` is the live `sysctl -n <key>` reading (or `"<unreadable>"` when
/// the backend could not read the key). `pass` is `true` when the live value
/// matches the desired value. The key, desired value, and description are taken
/// verbatim from the param; an empty key is replaced with a placeholder so the
/// row is still visible.
pub fn convert_sysctl_row(param: &SysctlParam, current: String) -> SysctlRow {
    if param.key.is_empty() {
        tracing::warn!(
            "harden sysctl param with empty key: value={:?}",
            param.value
        );
    }
    let pass = current.trim() == param.value.trim();
    SysctlRow {
        key: if param.key.is_empty() {
            "(unknown)".into()
        } else {
            param.key.clone()
        },
        desired: param.value.clone(),
        current,
        description: param.description.clone(),
        pass,
    }
}

/// Convert backend `MountInfo` entries to UI rows.
///
/// Every mount maps 1:1. An empty `target` is logged and replaced with a
/// placeholder. The `hardened` flag is `true` only when the mount carries all
/// three required security options (`nosuid`, `nodev`, `noexec`) — computed via
/// `toride_harden::shm::missing_security_options`.
pub fn convert_mounts(mounts: Vec<MountInfo>) -> Vec<MountEntry> {
    mounts
        .into_iter()
        .map(|m| {
            if m.target.is_empty() {
                tracing::warn!("harden mount with empty target: options={:?}", m.options);
            }
            let hardened = toride_harden::shm::missing_security_options(&m).is_empty();
            MountEntry {
                target: if m.target.is_empty() {
                    "(unknown)".into()
                } else {
                    m.target
                },
                source: m.source,
                fstype: m.fstype,
                options: m.options,
                hardened,
            }
        })
        .collect()
}

/// Build the list of available hardening profiles for the profile selector.
///
/// Uses [`HardeningProfile::all_names`] + [`HardeningProfile::from_name`] so
/// the selector never hard-codes a profile list (a future profile added to the
/// backend surfaces here automatically). Each entry carries the profile name,
/// a display label, and the number of parameters it would apply.
///
/// # Empty-input contract
///
/// [`HardeningProfile::all_names`] is guaranteed non-empty by construction
/// (it returns a static `&["desktop", "server", "router"]`), so this function
/// always yields at least one entry on a correct backend. If the backend were
/// ever changed to return an empty slice — or to advertise a name that
/// [`HardeningProfile::from_name`] rejects — this function degrades gracefully:
/// the `filter_map` silently skips unknown names and returns an empty `Vec`,
/// and the profile selector renders an empty list rather than panicking. The
/// `debug_assert!` below pins the non-empty invariant so a backend regression
/// surfaces in debug builds the moment a collection runs.
pub fn convert_profiles() -> Vec<HardenProfileEntry> {
    let names = HardeningProfile::all_names();
    // Pin the construction invariant: all_names() MUST be non-empty. A future
    // edit that empties it (or breaks from_name round-tripping for every
    // advertised name) would otherwise silently hide the entire profile
    // selector from the operator.
    debug_assert!(
        !names.is_empty(),
        "HardeningProfile::all_names() must be non-empty — an empty slice would hide the profile selector"
    );
    names
        .iter()
        .filter_map(|&name| HardeningProfile::from_name(name).map(|p| (name, p)))
        .map(|(name, p)| HardenProfileEntry {
            name: name.to_string(),
            label: capitalize(name),
            param_count: p.params().len(),
        })
        .collect()
}

/// Title-case a single lowercase word (profile name → display label).
fn capitalize(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use toride_harden::spec::SysctlParam;
    use toride_harden::{Finding, Severity};

    // ── convert_findings ──────────────────────────────────────────────────────

    #[test]
    fn convert_findings_empty() {
        assert!(convert_findings(Vec::new()).is_empty());
    }

    #[test]
    fn convert_findings_maps_severity() {
        let findings = vec![
            Finding::new("a", Severity::Critical, "t1"),
            Finding::new("b", Severity::Important, "t2"),
            Finding::new("c", Severity::Warning, "t3"),
            Finding::new("d", Severity::Info, "t4"),
            Finding::new("e", Severity::Ok, "t5"),
        ];
        let entries = convert_findings(findings);
        assert_eq!(entries.len(), 5);
        assert_eq!(entries[0].severity, "critical");
        assert_eq!(entries[1].severity, "important");
        assert_eq!(entries[2].severity, "warning");
        assert_eq!(entries[3].severity, "info");
        assert_eq!(entries[4].severity, "ok");
    }

    #[test]
    fn convert_findings_preserves_detail_and_fix() {
        let f = Finding::new("id", Severity::Warning, "title")
            .detail("the detail")
            .fix_hint("the fix");
        let entries = convert_findings(vec![f]);
        assert_eq!(entries[0].title, "title");
        assert_eq!(entries[0].detail, "the detail");
        assert_eq!(entries[0].fix.as_deref(), Some("the fix"));
    }

    #[test]
    fn convert_findings_none_detail_flattens_to_empty() {
        // detail is Option<String>; None must become "" not "(none)".
        let f = Finding::new("id", Severity::Ok, "title");
        let entries = convert_findings(vec![f]);
        assert_eq!(entries[0].detail, "");
        assert!(entries[0].fix.is_none());
    }

    #[test]
    fn convert_findings_placeholder_for_empty_fields() {
        let f = Finding::new("", Severity::Ok, "");
        let entries = convert_findings(vec![f]);
        assert_eq!(entries[0].id, "(unknown)");
        assert_eq!(entries[0].title, "(no title)");
    }

    // ── convert_sysctl_row ────────────────────────────────────────────────────

    #[test]
    fn convert_sysctl_row_pass_when_matching() {
        let p = SysctlParam::new("kernel.kptr_restrict", "1", "restrict");
        let row = convert_sysctl_row(&p, "1".into());
        assert!(row.pass);
        assert_eq!(row.key, "kernel.kptr_restrict");
        assert_eq!(row.desired, "1");
        assert_eq!(row.current, "1");
    }

    #[test]
    fn convert_sysctl_row_pass_ignores_surrounding_whitespace() {
        // sysctl -n output is trimmed by the backend, but be defensive: the
        // live value "1\n" must still match desired "1".
        let p = SysctlParam::new("k", "1", "d");
        let row = convert_sysctl_row(&p, " 1 ".into());
        assert!(row.pass);
    }

    #[test]
    fn convert_sysctl_row_fail_when_mismatched() {
        let p = SysctlParam::new("kernel.aslr", "2", "aslr");
        let row = convert_sysctl_row(&p, "0".into());
        assert!(!row.pass);
        assert_eq!(row.current, "0");
    }

    #[test]
    fn convert_sysctl_row_placeholder_for_empty_key() {
        let p = SysctlParam::new("", "1", "d");
        let row = convert_sysctl_row(&p, "1".into());
        assert_eq!(row.key, "(unknown)");
    }

    #[test]
    fn convert_sysctl_row_unreadable_value_is_fail() {
        // The backend yields "<unreadable>" when sysctl -n errors; this must
        // NOT coincidentally equal a desired value.
        let p = SysctlParam::new("k", "1", "d");
        let row = convert_sysctl_row(&p, "<unreadable>".into());
        assert!(!row.pass);
    }

    // ── convert_mounts ────────────────────────────────────────────────────────

    #[test]
    fn convert_mounts_empty() {
        assert!(convert_mounts(Vec::new()).is_empty());
    }

    #[test]
    fn convert_mounts_hardened_when_all_options_present() {
        let mounts = vec![MountInfo {
            target: "/dev/shm".into(),
            source: "tmpfs".into(),
            fstype: "tmpfs".into(),
            options: "rw,nosuid,nodev,noexec".into(),
        }];
        let entries = convert_mounts(mounts);
        assert_eq!(entries.len(), 1);
        assert!(entries[0].hardened);
        assert_eq!(entries[0].target, "/dev/shm");
    }

    #[test]
    fn convert_mounts_not_hardened_when_missing_option() {
        let mounts = vec![MountInfo {
            target: "/dev/shm".into(),
            source: "tmpfs".into(),
            fstype: "tmpfs".into(),
            options: "rw,nosuid".into(),
        }];
        let entries = convert_mounts(mounts);
        assert!(!entries[0].hardened);
    }

    #[test]
    fn convert_mounts_placeholder_for_empty_target() {
        let mounts = vec![MountInfo {
            target: String::new(),
            source: "tmpfs".into(),
            fstype: "tmpfs".into(),
            options: "rw".into(),
        }];
        let entries = convert_mounts(mounts);
        assert_eq!(entries[0].target, "(unknown)");
    }

    // ── convert_profiles ──────────────────────────────────────────────────────

    #[test]
    fn convert_profiles_returns_all_three() {
        let profiles = convert_profiles();
        assert_eq!(profiles.len(), 3);
        let names: Vec<&str> = profiles.iter().map(|p| p.name.as_str()).collect();
        assert!(names.contains(&"desktop"));
        assert!(names.contains(&"server"));
        assert!(names.contains(&"router"));
    }

    #[test]
    fn convert_profiles_capitalizes_labels() {
        let profiles = convert_profiles();
        let labels: Vec<&str> = profiles.iter().map(|p| p.label.as_str()).collect();
        assert!(labels.contains(&"Desktop"));
        assert!(labels.contains(&"Server"));
        assert!(labels.contains(&"Router"));
    }

    #[test]
    fn convert_profiles_param_counts_positive() {
        for p in convert_profiles() {
            assert!(p.param_count > 0, "{} has no params", p.name);
        }
    }

    #[test]
    fn convert_profiles_server_has_more_params_than_desktop() {
        let profiles = convert_profiles();
        let desktop = profiles
            .iter()
            .find(|p| p.name == "desktop")
            .unwrap()
            .param_count;
        let server = profiles
            .iter()
            .find(|p| p.name == "server")
            .unwrap()
            .param_count;
        assert!(server > desktop);
    }

    // ── convert_profiles: empty-input / unhappy-path coverage ────────────────
    //
    // Mirrors the `*_empty` / `*_placeholder_for_empty_*` coverage the other
    // parsers (findings, mounts, sysctl_row) already carry. The empty-input
    // path is defensive: if `all_names()` were ever empty or advertised a name
    // `from_name()` rejects, `convert_profiles` returns an empty Vec rather
    // than panicking. These tests pin both that graceful behavior AND the
    // stronger invariant the backend currently guarantees (non-empty,
    // every advertised name round-trips), so a future regression surfaces
    // loudly instead of silently hiding the profile selector.

    #[test]
    fn convert_profiles_all_names_is_non_empty() {
        // The construction invariant `convert_profiles` relies on. If a future
        // backend edit empties `all_names()` the profile selector disappears
        // from the UI; this assertion makes that breakage a test failure.
        assert!(
            !HardeningProfile::all_names().is_empty(),
            "HardeningProfile::all_names() must be non-empty"
        );
    }

    #[test]
    fn convert_profiles_every_advertised_name_round_trips() {
        // Every name in all_names() MUST resolve via from_name(). If one ever
        // stopped resolving, convert_profiles' filter_map would silently drop
        // it and the selector would show fewer profiles than the backend knows
        // about. Pin the round-trip so the mismatch surfaces here.
        for &name in HardeningProfile::all_names() {
            assert!(
                HardeningProfile::from_name(name).is_some(),
                "all_names() advertises '{name}' but from_name() rejects it"
            );
        }
    }

    #[test]
    fn convert_profiles_result_is_well_formed() {
        // The result must be well-formed for the selector to render sensibly:
        // every entry has a non-empty name, a non-empty label, and a param
        // count consistent with the backend profile's params(). Also asserts
        // the result is non-empty (the contract above).
        let profiles = convert_profiles();
        assert!(
            !profiles.is_empty(),
            "convert_profiles must yield at least one profile"
        );
        for entry in &profiles {
            assert!(
                !entry.name.is_empty(),
                "profile name must be non-empty: {entry:?}"
            );
            assert!(
                !entry.label.is_empty(),
                "profile label must be non-empty: {entry:?}"
            );
            let backend_count = HardeningProfile::from_name(&entry.name)
                .expect("advertised name must round-trip")
                .params()
                .len();
            assert_eq!(
                entry.param_count, backend_count,
                "param_count for '{}' must match backend params().len()",
                entry.name
            );
        }
    }

    #[test]
    fn convert_profiles_skips_invalid_name() {
        // Directly exercise the filter_map's defensive branch: an unknown name
        // must be silently skipped, never panic. all_names() is a static slice
        // we can't inject into, so emulate the same `from_name` rejection the
        // filter_map would see for a bogus advertised name.
        assert!(HardeningProfile::from_name("nonexistent-profile").is_none());
        // And confirm the real convert_profiles output contains NO unknown
        // names (i.e. the filter_map did not synthesize anything).
        let profiles = convert_profiles();
        for entry in &profiles {
            assert_ne!(
                entry.name, "nonexistent-profile",
                "convert_profiles must never emit an unknown name"
            );
        }
    }
}
