//! CIS and STIG benchmark presets for audit rules.
//!
//! Provides pre-built audit rule sets that comply with common security
//! benchmarks: CIS Benchmark and DISA STIG for Linux.

// ---------------------------------------------------------------------------
// Preset
// ---------------------------------------------------------------------------

/// A named preset of audit rules.
#[derive(Debug, Clone)]
pub struct AuditPreset {
    /// Preset identifier (e.g. `cis`, `stig`).
    pub id: &'static str,
    /// Human-readable preset name.
    pub name: &'static str,
    /// Description of the preset's purpose.
    pub description: &'static str,
    /// Audit rules in the preset (one per line).
    pub rules: &'static [&'static str],
}

// ---------------------------------------------------------------------------
// Built-in presets
// ---------------------------------------------------------------------------

/// CIS Level 2 Server audit rules preset.
///
/// Covers system call auditing for login, privilege escalation, file
/// modification, and other security-relevant events per CIS Benchmark
/// for Linux.
pub const CIS_LEVEL2: AuditPreset = AuditPreset {
    id: "cis-level2",
    name: "CIS Benchmark Level 2",
    description: "Audit rules for CIS Level 2 Server compliance",
    rules: &[
        // Login and logout events.
        "-w /var/log/lastlog -p wa -k logins",
        "-w /var/run/faillock -p wa -k logins",
        // Session modification.
        "-w /var/run/utmp -p wa -k session",
        // Password changes.
        "-w /etc/passwd -p wa -k identity",
        "-w /etc/group -p wa -k identity",
        "-w /etc/shadow -p wa -k identity",
        "-w /etc/gshadow -p wa -k identity",
        // SUID/SGID execution.
        "-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -k setuid",
        "-a always,exit -F arch=b32 -S execve -C uid!=euid -F euid=0 -k setuid",
        // Privilege escalation via sudo.
        "-w /etc/sudoers -p wa -k sudo",
        "-w /etc/sudoers.d -p wa -k sudo",
        // File deletion.
        "-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete",
        // Kernel module loading.
        "-a always,exit -F arch=b64 -S init_module -S delete_module -k modules",
        // System time changes.
        "-a always,exit -F arch=b64 -S settimeofday -S clock_settime -k time-change",
    ],
};

/// DISA STIG audit rules preset for RHEL-based systems.
///
/// Covers audit requirements from the DISA STIG for Linux/Unix.
pub const STIG: AuditPreset = AuditPreset {
    id: "stig",
    name: "DISA STIG",
    description: "Audit rules for DISA STIG compliance",
    rules: &[
        // Auditd startup.
        "-a always,exit -F arch=b64 -S execve -k exec",
        // File system mounts.
        "-a always,exit -F arch=b64 -S mount -S umount2 -k mounts",
        // Changes to system administration scope.
        "-w /etc/sudoers -p wa -k scope",
        "-w /etc/sudoers.d -p wa -k scope",
        // User/group modification.
        "-w /etc/passwd -p wa -k identity",
        "-w /etc/group -p wa -k identity",
        "-w /etc/shadow -p wa -k identity",
        // Network configuration changes.
        "-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale",
        // SELinux changes.
        "-w /etc/selinux -p wa -k selinux",
        // Login records.
        "-w /var/log/lastlog -p wa -k logins",
        "-w /var/run/faillock -p wa -k logins",
    ],
};

/// Minimal audit rules preset for essential security monitoring.
///
/// Covers only the most critical events: privilege escalation, identity
/// changes, and login events.
pub const MINIMAL: AuditPreset = AuditPreset {
    id: "minimal",
    name: "Minimal Security",
    description: "Essential audit rules for basic security monitoring",
    rules: &[
        "-w /etc/passwd -p wa -k identity",
        "-w /etc/shadow -p wa -k identity",
        "-w /var/log/lastlog -p wa -k logins",
        "-w /etc/sudoers -p wa -k sudo",
    ],
};

// ---------------------------------------------------------------------------
// Preset registry
// ---------------------------------------------------------------------------

/// Returns all available presets.
pub fn all_presets() -> Vec<&'static AuditPreset> {
    vec![&CIS_LEVEL2, &STIG, &MINIMAL]
}

/// Look up a preset by its ID.
pub fn find_preset(id: &str) -> Option<&'static AuditPreset> {
    all_presets().into_iter().find(|p| p.id == id)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_presets_returns_expected_presets() {
        let presets = all_presets();
        assert_eq!(presets.len(), 3);
        let ids: Vec<&str> = presets.iter().map(|p| p.id).collect();
        assert!(ids.contains(&"cis-level2"));
        assert!(ids.contains(&"stig"));
        assert!(ids.contains(&"minimal"));
    }

    #[test]
    fn find_preset_finds_known_presets() {
        assert!(find_preset("cis-level2").is_some());
        assert!(find_preset("stig").is_some());
        assert!(find_preset("minimal").is_some());
    }

    #[test]
    fn find_preset_returns_none_for_unknown() {
        assert!(find_preset("nonexistent").is_none());
        assert!(find_preset("").is_none());
    }

    #[test]
    fn each_preset_has_nonempty_rules() {
        for preset in all_presets() {
            assert!(
                !preset.rules.is_empty(),
                "preset '{}' should have at least one rule",
                preset.id
            );
        }
    }

    #[test]
    fn each_preset_has_id_name_description() {
        for preset in all_presets() {
            assert!(!preset.id.is_empty(), "preset id must not be empty");
            assert!(!preset.name.is_empty(), "preset name must not be empty");
            assert!(
                !preset.description.is_empty(),
                "preset description must not be empty"
            );
        }
    }
}
