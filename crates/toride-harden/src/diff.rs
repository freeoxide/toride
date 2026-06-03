//! Diff utilities for comparing sysctl states.
//!
//! Provides unified diff output between current and desired sysctl
//! configurations using the `similar` crate.

use crate::spec::SysctlParam;

/// Compute a unified diff between current sysctl values and desired parameters.
///
/// Renders both sides as `key = value` lines (sorted by key) and produces
/// a unified diff showing what would change.
pub fn diff_sysctl(current: &[(String, String)], desired: &[SysctlParam]) -> String {
    let old = render_sysctl_lines(current);
    let new = render_desired_lines(desired);

    similar::TextDiff::from_lines(&old, &new)
        .unified_diff()
        .context_radius(3)
        .header("a/sysctl-current", "b/sysctl-desired")
        .to_string()
}

/// Compare current values against desired parameters and return only the
/// parameters that differ (would need to be applied).
pub fn changed_params<'a>(
    current: &[(String, String)],
    desired: &'a [SysctlParam],
) -> Vec<&'a SysctlParam> {
    let current_map: std::collections::HashMap<&str, &str> = current
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();

    desired
        .iter()
        .filter(|p| {
            let current_value = current_map.get(p.key.as_str());
            current_value.is_none_or(|&v| v != p.value)
        })
        .collect()
}

/// Render current sysctl key-value pairs as sorted lines.
fn render_sysctl_lines(pairs: &[(String, String)]) -> String {
    let mut sorted = pairs.to_vec();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));

    sorted
        .iter()
        .map(|(k, v)| format!("{k} = {v}"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Render desired parameters as sorted lines.
fn render_desired_lines(params: &[SysctlParam]) -> String {
    let mut sorted: Vec<&SysctlParam> = params.iter().collect();
    sorted.sort_by(|a, b| a.key.cmp(&b.key));

    sorted
        .iter()
        .map(|p| format!("{} = {}", p.key, p.value))
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diff_shows_additions_and_changes() {
        let current = vec![
            ("kernel.kptr_restrict".into(), "0".into()),
            ("kernel.aslr".into(), "1".into()),
        ];
        let desired = vec![
            SysctlParam::new("kernel.kptr_restrict", "1", "kptr"),
            SysctlParam::new("kernel.aslr", "1", "aslr"),
            SysctlParam::new("net.ipv4.ip_forward", "0", "forwarding"),
        ];

        let diff = diff_sysctl(&current, &desired);
        assert!(diff.contains("-kernel.kptr_restrict = 0"));
        assert!(diff.contains("+kernel.kptr_restrict = 1"));
        assert!(diff.contains("+net.ipv4.ip_forward = 0"));
    }

    #[test]
    fn changed_params_returns_only_differring() {
        let current = vec![
            ("kernel.kptr_restrict".into(), "1".into()),
            ("kernel.aslr".into(), "2".into()),
        ];
        let desired = vec![
            SysctlParam::new("kernel.kptr_restrict", "1", "already set"),
            SysctlParam::new("kernel.aslr", "1", "needs change"),
        ];

        let changed = changed_params(&current, &desired);
        assert_eq!(changed.len(), 1);
        assert_eq!(changed[0].key, "kernel.aslr");
    }

    #[test]
    fn no_changes_produces_empty_diff() {
        let current = vec![("kernel.kptr_restrict".into(), "1".into())];
        let desired = vec![SysctlParam::new("kernel.kptr_restrict", "1", "same")];

        let changed = changed_params(&current, &desired);
        assert!(changed.is_empty());
    }
}
