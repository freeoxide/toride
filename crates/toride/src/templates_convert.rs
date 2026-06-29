//! Convert the Templates recipe catalogue (app-defined constants) to UI
//! presentation types, fusing each recipe with its live `which::which` status.
//!
//! This is the ONLY module in the `toride` crate that owns the recipe
//! DEFINITIONS — mirroring `toride_harden_convert.rs`'s role as the single
//! boundary between the static app feature manifest and the presentation
//! layer. Each function handles malformed input gracefully: empty required
//! fields are logged and replaced with a placeholder, never propagated (the
//! read-only section must never crash the TUI).
//!
//! ## What "convert" means here
//!
//! Unlike the other read-only sections whose data flows from a backend crate,
//! the Templates catalogue is the app's own feature manifest: a constant menu
//! of named hardening/service recipes toride can apply. Each recipe's LIVE
//! state is the single boolean "is the target tool installed on THIS host",
//! probed via [`which::which`]. So [`convert_recipes`] takes the per-recipe
//! `installed` booleans (gathered by the collector) and produces
//! [`RecipeEntry`] rows; [`convert_findings`] turns the missing-target recipes
//! into INFO-severity findings so the dashboard's findings stat card and the
//! `SectionOverview::status_label` reflect readiness gaps.

use crate::ui::screens::templates::{FindingEntry, RecipeEntry};

// ── Recipe catalogue (app feature manifest) ────────────────────────────────

/// A recipe DEFINITION: a named hardening/service capability toride can apply.
///
/// This is static app data — NOT live state. Each entry maps to a real backend
/// capability; the live "is this applicable here?" answer is the presence of
/// `target_binary` on PATH, probed by the collector via [`which::which`].
#[derive(Clone, Debug)]
pub struct RecipeDef {
    /// Stable id used in finding ids (`templates.missing.<id>`).
    pub id: &'static str,
    /// Human-readable recipe name.
    pub name: &'static str,
    /// Category: Hardening / Network / Monitoring / Backup / Identity / Runtimes.
    pub category: &'static str,
    /// One-line description of what the recipe applies.
    pub description: &'static str,
    /// The binary whose presence means this recipe is applicable / installed.
    pub target_binary: &'static str,
    /// Difficulty: Easy / Medium / Hard.
    pub difficulty: &'static str,
}

/// The constant catalogue of recipes toride can manage.
///
/// Each entry corresponds to a real backend capability (toride-ssh, ufw-kit,
/// toride-fail2ban, toride-harden, toride-wireguard, etc.). Adding a recipe
/// here surfaces it in the catalogue automatically; the per-recipe live status
/// is recomputed by the collector's `which::which` sweep.
///
/// Kept as a `const` (not a runtime-built `Vec`) so the catalogue is a true
/// compile-time manifest: a future recipe added here cannot accidentally
/// change ordering at runtime, and the `id` strings are verified unique by the
/// `catalogue_ids_are_unique` test.
const CATALOGUE: &[RecipeDef] = &[
    RecipeDef {
        id: "ssh-hardening",
        name: "SSH Hardening",
        category: "Hardening",
        description: "Lock down sshd: keys, ciphers, access control.",
        target_binary: "ssh",
        difficulty: "Medium",
    },
    RecipeDef {
        id: "ufw-default-deny",
        name: "UFW Default-Deny Firewall",
        category: "Network",
        description: "Default-deny incoming, allow outgoing.",
        target_binary: "ufw",
        difficulty: "Easy",
    },
    RecipeDef {
        id: "fail2ban-sshd-jail",
        name: "fail2ban sshd jail",
        category: "Hardening",
        description: "Brute-force protection for the sshd service.",
        target_binary: "fail2ban-client",
        difficulty: "Easy",
    },
    RecipeDef {
        id: "kernel-server-profile",
        name: "Kernel Server Profile",
        category: "Hardening",
        description: "Apply toride-harden sysctl baseline for servers.",
        target_binary: "sysctl",
        difficulty: "Medium",
    },
    RecipeDef {
        id: "wireguard-tunnel",
        name: "WireGuard Tunnel",
        category: "Network",
        description: "Configure a WireGuard VPN interface and peers.",
        target_binary: "wg",
        difficulty: "Hard",
    },
    RecipeDef {
        id: "unattended-upgrades",
        name: "Unattended Upgrades",
        category: "Monitoring",
        description: "Automatic security package updates.",
        target_binary: "unattended-upgrades",
        difficulty: "Easy",
    },
    RecipeDef {
        id: "auditd-aide",
        name: "Auditd + AIDE",
        category: "Monitoring",
        description: "Kernel audit rules + file integrity baseline.",
        target_binary: "auditctl",
        difficulty: "Hard",
    },
    RecipeDef {
        id: "outbound-traffic-monitor",
        name: "Outbound Traffic Monitor",
        category: "Monitoring",
        description: "Track and alert on outbound connections.",
        target_binary: "iptables",
        difficulty: "Medium",
    },
    RecipeDef {
        id: "restic-backup",
        name: "Restic Backup",
        category: "Backup",
        description: "Encrypted, deduplicated incremental backups.",
        target_binary: "restic",
        difficulty: "Medium",
    },
    RecipeDef {
        id: "nginx-reverse-proxy",
        name: "Nginx Reverse Proxy",
        category: "Network",
        description: "Reverse proxy with TLS and server blocks.",
        target_binary: "nginx",
        difficulty: "Medium",
    },
    RecipeDef {
        id: "tailscale-mesh-vpn",
        name: "Tailscale Mesh VPN",
        category: "Network",
        description: "Join the host to a Tailscale mesh tailnet.",
        target_binary: "tailscaled",
        difficulty: "Easy",
    },
    RecipeDef {
        id: "user-sudo-hardening",
        name: "User/Sudo Hardening",
        category: "Identity",
        description: "Harden users, groups, and sudoers policy.",
        target_binary: "sudo",
        difficulty: "Medium",
    },
    RecipeDef {
        id: "mise-runtimes",
        name: "Mise Runtimes",
        category: "Runtimes",
        description: "Manage language runtime versions via mise.",
        target_binary: "mise",
        difficulty: "Easy",
    },
];

/// Borrow the constant catalogue so the collector can sweep it once.
///
/// Returns the static slice directly — no allocation — so the collector's
/// `spawn_blocking` closure can iterate it without crossing the thread
/// boundary with owned data.
#[must_use]
pub fn catalogue() -> &'static [RecipeDef] {
    CATALOGUE
}

// ── Convert functions ──────────────────────────────────────────────────────

/// Build the live [`RecipeEntry`] list by fusing each catalogue definition
/// with its per-recipe `installed` flag (probed via `which::which` by the
/// collector).
///
/// `installed` MUST be in the same order and length as [`catalogue`]; the
/// collector guarantees this by zipping the two. An out-of-range index is
/// treated as `false` (degraded — the recipe reads "available") rather than
/// panicking. An empty `name` is logged and replaced with a placeholder so the
/// row is still visible.
///
/// `status` is `"ready"` when the target tool is installed and `"available"`
/// otherwise (the recipe CAN be applied — toride knows how — but the backing
/// tool is not yet present on this host).
pub fn convert_recipes(installed: &[bool]) -> Vec<RecipeEntry> {
    CATALOGUE
        .iter()
        .enumerate()
        .map(|(i, def)| {
            let is_ready = installed.get(i).copied().unwrap_or(false);
            if def.name.is_empty() {
                tracing::warn!(
                    "templates recipe with empty name: id={:?} target={:?}",
                    def.id,
                    def.target_binary
                );
            }
            RecipeEntry {
                name: if def.name.is_empty() {
                    "(unknown)".into()
                } else {
                    def.name.into()
                },
                category: def.category.into(),
                description: def.description.into(),
                status: if is_ready {
                    "ready".into()
                } else {
                    "available".into()
                },
                target_tool: if def.target_binary.is_empty() {
                    "(none)".into()
                } else {
                    def.target_binary.into()
                },
                difficulty: def.difficulty.into(),
            }
        })
        .collect()
}

/// Convert the recipes whose target tool is missing into INFO-severity
/// findings so the dashboard's findings stat card and
/// `SectionOverview::status_label` reflect readiness gaps.
///
/// Every un-ready recipe maps to one finding with id
/// `templates.missing.<recipe_id>`. A missing tool is an OPPORTUNITY, not a
/// fault, so the severity is `info` (which [`status_label_for`] does NOT count
/// as degraded) — a partially-ready catalogue reads `active`, matching the
/// panel's readiness summary.
///
/// `installed` MUST align with [`catalogue`] in order/length (same contract as
/// [`convert_recipes`]); out-of-range indices degrade to "available".
pub fn convert_findings(installed: &[bool]) -> Vec<FindingEntry> {
    CATALOGUE
        .iter()
        .enumerate()
        .filter(|(i, _)| !installed.get(*i).copied().unwrap_or(false))
        .map(|(_, def)| FindingEntry {
            id: format!("templates.missing.{}", def.id),
            severity: "info".into(),
            title: format!("{} target tool not installed", def.name),
            detail: String::new(),
            fix: Some(format!(
                "install {} to enable this recipe",
                def.target_binary
            )),
        })
        .collect()
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── catalogue ────────────────────────────────────────────────────────────

    #[test]
    fn catalogue_is_non_empty() {
        assert!(!catalogue().is_empty(), "catalogue must list recipes");
    }

    #[test]
    fn catalogue_ids_are_unique() {
        let mut ids: Vec<&str> = catalogue().iter().map(|d| d.id).collect();
        let total = ids.len();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), total, "catalogue ids must be unique");
    }

    #[test]
    fn catalogue_categories_are_known() {
        // Pin the category vocabulary the screen groups by.
        let known = [
            "Hardening",
            "Network",
            "Monitoring",
            "Backup",
            "Identity",
            "Runtimes",
        ];
        for def in catalogue() {
            assert!(
                known.contains(&def.category),
                "unknown category '{}' on recipe '{}'",
                def.category,
                def.id
            );
        }
    }

    #[test]
    fn catalogue_difficulties_are_known() {
        let known = ["Easy", "Medium", "Hard"];
        for def in catalogue() {
            assert!(
                known.contains(&def.difficulty),
                "unknown difficulty '{}' on recipe '{}'",
                def.difficulty,
                def.id
            );
        }
    }

    #[test]
    fn catalogue_includes_suggested_recipes() {
        let ids: Vec<&str> = catalogue().iter().map(|d| d.id).collect();
        for expected in [
            "ssh-hardening",
            "ufw-default-deny",
            "fail2ban-sshd-jail",
            "kernel-server-profile",
            "wireguard-tunnel",
            "unattended-upgrades",
            "auditd-aide",
            "outbound-traffic-monitor",
            "restic-backup",
            "nginx-reverse-proxy",
            "tailscale-mesh-vpn",
            "user-sudo-hardening",
            "mise-runtimes",
        ] {
            assert!(
                ids.contains(&expected),
                "catalogue must include '{expected}': {ids:?}"
            );
        }
    }

    #[test]
    fn catalogue_target_binaries_are_non_empty() {
        for def in catalogue() {
            assert!(
                !def.target_binary.is_empty(),
                "recipe '{}' must name a target binary",
                def.id
            );
        }
    }

    // ── convert_recipes ──────────────────────────────────────────────────────

    #[test]
    fn convert_recipes_length_matches_catalogue() {
        let installed: Vec<bool> = catalogue().iter().map(|_| true).collect();
        let entries = convert_recipes(&installed);
        assert_eq!(entries.len(), catalogue().len());
    }

    #[test]
    fn convert_recipes_ready_when_installed() {
        let installed: Vec<bool> = catalogue().iter().map(|_| true).collect();
        let entries = convert_recipes(&installed);
        for e in &entries {
            assert_eq!(e.status, "ready", "{} should be ready", e.name);
        }
    }

    #[test]
    fn convert_recipes_available_when_not_installed() {
        let installed: Vec<bool> = catalogue().iter().map(|_| false).collect();
        let entries = convert_recipes(&installed);
        for e in &entries {
            assert_eq!(e.status, "available", "{} should be available", e.name);
        }
    }

    #[test]
    fn convert_recipes_partial_marks_mixed_states() {
        let mut installed: Vec<bool> = vec![false; catalogue().len()];
        installed[0] = true; // first recipe ready, rest available
        let entries = convert_recipes(&installed);
        assert_eq!(entries[0].status, "ready");
        assert_eq!(entries[1].status, "available");
    }

    #[test]
    fn convert_recipes_short_installed_vec_degrades_to_available() {
        // A short slice (fewer flags than recipes) must NOT panic; the
        // trailing recipes read "available".
        let installed = vec![true];
        let entries = convert_recipes(&installed);
        assert_eq!(entries.len(), catalogue().len());
        assert_eq!(entries[0].status, "ready");
        assert_eq!(entries[1].status, "available");
    }

    #[test]
    fn convert_recipes_empty_installed_all_available() {
        let entries = convert_recipes(&[]);
        assert_eq!(entries.len(), catalogue().len());
        for e in &entries {
            assert_eq!(e.status, "available");
        }
    }

    #[test]
    fn convert_recipes_preserves_category_and_difficulty() {
        let installed: Vec<bool> = catalogue().iter().map(|_| true).collect();
        let entries = convert_recipes(&installed);
        for (def, entry) in catalogue().iter().zip(entries.iter()) {
            assert_eq!(entry.category, def.category);
            assert_eq!(entry.difficulty, def.difficulty);
            assert_eq!(entry.target_tool, def.target_binary);
        }
    }

    // ── convert_findings ─────────────────────────────────────────────────────

    #[test]
    fn convert_findings_empty_when_all_ready() {
        let installed: Vec<bool> = catalogue().iter().map(|_| true).collect();
        assert!(convert_findings(&installed).is_empty());
    }

    #[test]
    fn convert_findings_one_per_missing_target() {
        let installed: Vec<bool> = catalogue().iter().map(|_| false).collect();
        let findings = convert_findings(&installed);
        assert_eq!(findings.len(), catalogue().len());
    }

    #[test]
    fn convert_findings_ids_are_dot_separated_and_prefixed() {
        let installed: Vec<bool> = catalogue().iter().map(|_| false).collect();
        for f in convert_findings(&installed) {
            assert!(
                f.id.starts_with("templates.missing."),
                "id '{}' must be prefixed 'templates.missing.'",
                f.id
            );
        }
    }

    #[test]
    fn convert_findings_severity_is_info() {
        let installed: Vec<bool> = catalogue().iter().map(|_| false).collect();
        for f in convert_findings(&installed) {
            assert_eq!(f.severity, "info");
        }
    }

    #[test]
    fn convert_findings_partial_matches_missing_count() {
        let mut installed: Vec<bool> = vec![true; catalogue().len()];
        installed[0] = false;
        installed[1] = false;
        let findings = convert_findings(&installed);
        assert_eq!(findings.len(), 2);
    }

    #[test]
    fn convert_findings_fix_hint_names_target() {
        let installed: Vec<bool> = catalogue().iter().map(|_| false).collect();
        let findings = convert_findings(&installed);
        // Every fix hint must reference the recipe's target binary.
        for (def, f) in catalogue().iter().zip(findings.iter()) {
            assert!(
                f.fix
                    .as_deref()
                    .is_some_and(|s| s.contains(def.target_binary)),
                "fix '{:?}' must mention target '{}'",
                f.fix,
                def.target_binary
            );
        }
    }

    #[test]
    fn convert_findings_short_installed_vec_treats_trailing_as_missing() {
        // A short slice must not panic; trailing recipes are treated as
        // missing (findings emitted for them).
        let findings = convert_findings(&[true]);
        assert_eq!(
            findings.len(),
            catalogue().len() - 1,
            "only the first recipe is ready; the rest are missing"
        );
    }
}
