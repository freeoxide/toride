//! Convert raw tool-resolution results to UI presentation types.
//!
//! This is the ONLY module in the `toride` crate that owns the tool catalogue
//! — mirroring `toride_harden_convert.rs`'s role as the single boundary
//! between backend (here: the host `PATH`) and presentation. Each function
//! handles errors gracefully: malformed input is skipped with a
//! `tracing::warn!` and a placeholder, never propagated (the read-only
//! section must never crash the TUI).
//!
//! The catalogue lives here (not in the data collector) so the convert layer
//! is the single source of truth for which tools toride cares about. The data
//! collector calls [`catalogue`] and walks it; the convert layer then maps the
//! resolved `ToolEntry` rows into findings (one `tools.missing.<name>` warning
//! per MISSING expected tool).

use crate::ui::screens::tools::{FindingEntry, ToolEntry};

// ── Catalogue ───────────────────────────────────────────────────────────────

/// One entry in the curated CLI-tool catalogue.
///
/// A tool may install under several names (`binaries`); the collector tries
/// each in order and records the first that resolves on PATH (e.g. `fd`
/// resolves to `fdfind` on Debian). `expected == true` marks a tool whose
/// absence is a warning finding — toride cares about it being present.
#[derive(Clone, Debug)]
pub struct ToolSpec {
    /// Canonical name shown to the operator (e.g. `"fd"`).
    pub name: &'static str,
    /// Category for grouping in the UI (e.g. `"Search/Files"`).
    pub category: &'static str,
    /// Binary names to try, in order. The first that resolves on PATH wins.
    pub binaries: Vec<String>,
    /// Whether a missing tool is a warning finding. toride expects these on a
    /// fully-equipped host; their absence is surfaced as a `tools.missing.*`
    /// finding so the operator notices.
    pub expected: bool,
}

/// The curated catalogue of CLI tools toride cares about, grouped by category
/// in stable display order.
///
/// Categories mirror the spec's suggested grouping (Editors, Search/Files,
/// Containers, Languages/Runtimes, Network, Shell/System). Every entry is
/// `expected == true` — toride expects a fully-equipped host to carry all of
/// these; a missing one surfaces as a `tools.missing.<name>` finding. A future
/// "optional" tool can opt out by passing `expected: false` here.
#[must_use]
pub fn catalogue() -> Vec<ToolSpec> {
    // Built at runtime (not const) because `binaries: Vec<String>` requires
    // allocation. The list itself is static data; this just moves it into
    // heap-allocated Vecs once per collection.
    let raw: &[(&'static str, &'static str, &[&str])] = &[
        // ── Editors ───────────────────────────────────────────────────────
        ("vim", "Editors", &["vim", "nvim"]),
        ("nvim", "Editors", &["nvim"]),
        ("nano", "Editors", &["nano"]),
        ("code", "Editors", &["code"]),
        // ── Search / Files ───────────────────────────────────────────────
        ("fzf", "Search/Files", &["fzf"]),
        ("rg", "Search/Files", &["rg", "ripgrep"]),
        ("fd", "Search/Files", &["fd", "fdfind"]),
        ("bat", "Search/Files", &["bat", "batcat"]),
        ("eza", "Search/Files", &["eza", "exa"]),
        ("zoxide", "Search/Files", &["zoxide"]),
        ("tree", "Search/Files", &["tree"]),
        // ── Containers ───────────────────────────────────────────────────
        ("docker", "Containers", &["docker"]),
        ("podman", "Containers", &["podman"]),
        ("docker-compose", "Containers", &["docker-compose"]),
        ("kubectl", "Containers", &["kubectl"]),
        ("helm", "Containers", &["helm"]),
        // ── Languages / Runtimes ─────────────────────────────────────────
        ("python3", "Languages/Runtimes", &["python3", "python"]),
        ("node", "Languages/Runtimes", &["node"]),
        ("npm", "Languages/Runtimes", &["npm"]),
        ("bun", "Languages/Runtimes", &["bun"]),
        ("deno", "Languages/Runtimes", &["deno"]),
        ("cargo", "Languages/Runtimes", &["cargo"]),
        ("rustc", "Languages/Runtimes", &["rustc"]),
        ("go", "Languages/Runtimes", &["go"]),
        ("java", "Languages/Runtimes", &["java"]),
        // ── Network ──────────────────────────────────────────────────────
        ("curl", "Network", &["curl"]),
        ("wget", "Network", &["wget"]),
        ("jq", "Network", &["jq"]),
        ("yq", "Network", &["yq"]),
        ("ssh", "Network", &["ssh"]),
        ("git", "Network", &["git"]),
        ("gh", "Network", &["gh"]),
        ("rsync", "Network", &["rsync"]),
        // ── Shell / System ───────────────────────────────────────────────
        ("tmux", "Shell/System", &["tmux"]),
        ("btop", "Shell/System", &["btop"]),
        ("htop", "Shell/System", &["htop"]),
        ("make", "Shell/System", &["make", "gmake"]),
        ("gcc", "Shell/System", &["gcc", "cc"]),
    ];

    raw.iter()
        .map(|(name, category, binaries)| ToolSpec {
            name,
            category,
            binaries: binaries.iter().map(|s| (*s).to_string()).collect(),
            // Every catalogue entry is `expected == true` — toride expects a
            // fully-equipped host to carry all of these, and a missing one
            // surfaces as a `tools.missing.<name>` finding. A future "optional"
            // tool can opt out by passing `expected: false` here.
            expected: true,
        })
        .collect()
}

// ── Conversion ──────────────────────────────────────────────────────────────

/// Derive one `tools.missing.<name>` warning finding per MISSING expected
/// tool.
///
/// Mirrors the harden / fail2ban convert layer: malformed input (an empty
/// name) is logged and skipped, never propagated. A tool that is installed but
/// has no version is NOT a finding — presence is the source of truth.
pub fn convert_findings(tools: &[ToolEntry]) -> Vec<FindingEntry> {
    tools
        .iter()
        .filter(|t| t.expected && !t.installed)
        .map(|t| {
            if t.name.is_empty() {
                tracing::warn!("tools finding with empty name: category={:?}", t.category);
            }
            FindingEntry {
                id: if t.name.is_empty() {
                    "tools.missing.(unknown)".to_string()
                } else {
                    format!("tools.missing.{}", t.name)
                },
                severity: "warning".to_string(),
                title: if t.name.is_empty() {
                    "missing expected tool: (unknown)".to_string()
                } else {
                    format!("missing expected tool: {}", t.name)
                },
            }
        })
        .collect()
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalogue_is_non_empty() {
        let c = catalogue();
        assert!(!c.is_empty(), "catalogue must list at least one tool");
        // Every spec has at least one alias and a non-empty category.
        for spec in &c {
            assert!(!spec.binaries.is_empty(), "{} has no aliases", spec.name);
            assert!(
                !spec.category.is_empty(),
                "{} has empty category",
                spec.name
            );
        }
    }

    #[test]
    fn catalogue_has_all_suggested_categories() {
        let c = catalogue();
        let cats: Vec<&str> = c.iter().map(|s| s.category).collect();
        for expected in [
            "Editors",
            "Search/Files",
            "Containers",
            "Languages/Runtimes",
            "Network",
            "Shell/System",
        ] {
            assert!(cats.contains(&expected), "missing category {expected}");
        }
    }

    #[test]
    fn catalogue_names_are_unique() {
        // Duplicate canonical names would collide in the UI grouping and in
        // finding ids (`tools.missing.<name>`).
        let c = catalogue();
        let mut seen = std::collections::HashSet::new();
        for spec in &c {
            assert!(
                seen.insert(spec.name),
                "duplicate catalogue name: {}",
                spec.name
            );
        }
    }

    #[test]
    fn catalogue_carries_suggested_tool_names() {
        // Spot-check the headline tools from the spec so a future edit that
        // drops one surfaces here.
        let c = catalogue();
        let names: Vec<&str> = c.iter().map(|s| s.name).collect();
        for required in [
            "vim", "fzf", "rg", "fd", "docker", "cargo", "git", "curl", "tmux",
        ] {
            assert!(names.contains(&required), "catalogue missing {required}");
        }
    }

    #[test]
    fn catalogue_aliases_include_known_distro_renames() {
        // fd/fdfind, bat/batcat, eza/exa, make/gmake, gcc/cc — the catalogue
        // must try the distro-renamed alias so a Debian/macOS host resolves.
        let c = catalogue();
        let by_name = |n: &str| c.iter().find(|s| s.name == n).unwrap();
        assert!(by_name("fd").binaries.contains(&"fdfind".to_string()));
        assert!(by_name("bat").binaries.contains(&"batcat".to_string()));
        assert!(by_name("eza").binaries.contains(&"exa".to_string()));
        assert!(by_name("make").binaries.contains(&"gmake".to_string()));
        assert!(by_name("gcc").binaries.contains(&"cc".to_string()));
    }

    #[test]
    fn convert_findings_empty_when_all_installed() {
        let tools = vec![
            ToolEntry {
                name: "vim".into(),
                category: "Editors".into(),
                installed: true,
                version: Some("9.0".into()),
                path: Some("/usr/bin/vim".into()),
                expected: true,
            },
            ToolEntry {
                name: "git".into(),
                category: "Network".into(),
                installed: true,
                version: None,
                path: Some("/usr/bin/git".into()),
                expected: true,
            },
        ];
        assert!(convert_findings(&tools).is_empty());
    }

    #[test]
    fn convert_findings_one_per_missing_expected() {
        let tools = vec![
            ToolEntry {
                name: "vim".into(),
                category: "Editors".into(),
                installed: false,
                version: None,
                path: None,
                expected: true,
            },
            ToolEntry {
                name: "git".into(),
                category: "Network".into(),
                installed: true,
                version: Some("2.43".into()),
                path: Some("/usr/bin/git".into()),
                expected: true,
            },
            ToolEntry {
                name: "bun".into(),
                category: "Languages/Runtimes".into(),
                installed: false,
                version: None,
                path: None,
                expected: true,
            },
        ];
        let findings = convert_findings(&tools);
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].id, "tools.missing.vim");
        assert_eq!(findings[0].severity, "warning");
        assert_eq!(findings[0].title, "missing expected tool: vim");
        assert_eq!(findings[1].id, "tools.missing.bun");
    }

    #[test]
    fn convert_findings_skips_unexpected_missing() {
        // A tool with expected == false that is missing does NOT produce a
        // finding (it's optional).
        let tools = vec![ToolEntry {
            name: "exotic-tool".into(),
            category: "Editors".into(),
            installed: false,
            version: None,
            path: None,
            expected: false,
        }];
        assert!(convert_findings(&tools).is_empty());
    }

    #[test]
    fn convert_findings_skips_installed_even_if_expected() {
        let tools = vec![ToolEntry {
            name: "vim".into(),
            category: "Editors".into(),
            installed: true,
            version: None,
            path: None,
            expected: true,
        }];
        assert!(convert_findings(&tools).is_empty());
    }

    #[test]
    fn convert_findings_placeholder_for_empty_name() {
        let tools = vec![ToolEntry {
            name: String::new(),
            category: "Editors".into(),
            installed: false,
            version: None,
            path: None,
            expected: true,
        }];
        let findings = convert_findings(&tools);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "tools.missing.(unknown)");
        assert!(findings[0].title.contains("(unknown)"));
    }

    #[test]
    fn convert_findings_empty_input() {
        assert!(convert_findings(&[]).is_empty());
    }

    #[test]
    fn finding_ids_are_dot_separated() {
        // Finding ids must mirror the harden/backend convention
        // (`tools.missing.<name>`) so the SectionOverview status_label lookup
        // (which checks severity strings, not ids) and any future id-based
        // routing stay consistent.
        let tools = vec![ToolEntry {
            name: "vim".into(),
            category: "Editors".into(),
            installed: false,
            version: None,
            path: None,
            expected: true,
        }];
        for f in convert_findings(&tools) {
            assert!(f.id.contains('.'), "id '{}' must be dot-separated", f.id);
        }
    }
}
