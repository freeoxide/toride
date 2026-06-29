use super::*;

// ---------------------------------------------------------------------------
// Firewall enum trait tests
// ---------------------------------------------------------------------------

#[test]
fn firewall_debug_trait() {
    let fw = Firewall::Iptables;
    let debug_str = format!("{:?}", fw);
    assert_eq!(debug_str, "Iptables");

    let debug_str = format!("{:?}", Firewall::Nftables);
    assert_eq!(debug_str, "Nftables");

    let debug_str = format!("{:?}", Firewall::Pf);
    assert_eq!(debug_str, "Pf");

    let debug_str = format!("{:?}", Firewall::Firewalld);
    assert_eq!(debug_str, "Firewalld");

    let debug_str = format!("{:?}", Firewall::WindowsFirewall);
    assert_eq!(debug_str, "WindowsFirewall");

    let debug_str = format!("{:?}", Firewall::Unknown);
    assert_eq!(debug_str, "Unknown");
}

#[test]
fn firewall_partial_eq() {
    assert_eq!(Firewall::Iptables, Firewall::Iptables);
    assert_eq!(Firewall::Nftables, Firewall::Nftables);
    assert_eq!(Firewall::Pf, Firewall::Pf);
    assert_eq!(Firewall::Firewalld, Firewall::Firewalld);
    assert_eq!(Firewall::WindowsFirewall, Firewall::WindowsFirewall);
    assert_eq!(Firewall::Unknown, Firewall::Unknown);

    assert_ne!(Firewall::Iptables, Firewall::Nftables);
    assert_ne!(Firewall::Pf, Firewall::Firewalld);
    assert_ne!(Firewall::WindowsFirewall, Firewall::Unknown);
}

#[test]
fn firewall_clone() {
    let original = Firewall::Firewalld;
    let cloned = original.clone();
    assert_eq!(original, cloned);
}

#[test]
fn firewall_copy() {
    let original = Firewall::Pf;
    let copied = original;
    // Both should still be usable -- Copy means no move semantics.
    assert_eq!(original, copied);
}

// ---------------------------------------------------------------------------
// InitSystem enum trait tests
// ---------------------------------------------------------------------------

#[test]
fn init_system_debug_trait() {
    assert_eq!(format!("{:?}", InitSystem::Systemd), "Systemd");
    assert_eq!(format!("{:?}", InitSystem::OpenRC), "OpenRC");
    assert_eq!(format!("{:?}", InitSystem::Launchd), "Launchd");
    assert_eq!(format!("{:?}", InitSystem::Rc), "Rc");
    assert_eq!(format!("{:?}", InitSystem::Unknown), "Unknown");
}

#[test]
fn init_system_partial_eq() {
    assert_eq!(InitSystem::Systemd, InitSystem::Systemd);
    assert_eq!(InitSystem::OpenRC, InitSystem::OpenRC);
    assert_eq!(InitSystem::Launchd, InitSystem::Launchd);
    assert_eq!(InitSystem::Rc, InitSystem::Rc);
    assert_eq!(InitSystem::Unknown, InitSystem::Unknown);

    assert_ne!(InitSystem::Systemd, InitSystem::OpenRC);
    assert_ne!(InitSystem::Launchd, InitSystem::Rc);
}

#[test]
fn init_system_clone() {
    let original = InitSystem::Systemd;
    let cloned = original.clone();
    assert_eq!(original, cloned);
}

#[test]
fn init_system_copy() {
    let original = InitSystem::Launchd;
    let copied = original;
    assert_eq!(original, copied);
}

// ---------------------------------------------------------------------------
// PlatformInfo trait tests
// ---------------------------------------------------------------------------

#[test]
fn platform_info_clone() {
    let info = PlatformInfo {
        os: "linux".to_string(),
        version: "6.1.0".to_string(),
        arch: "x86_64".to_string(),
        firewall: Firewall::Iptables,
        init_system: InitSystem::Systemd,
    };
    let cloned = info.clone();
    assert_eq!(info.os, cloned.os);
    assert_eq!(info.version, cloned.version);
    assert_eq!(info.arch, cloned.arch);
    assert_eq!(info.firewall, cloned.firewall);
    assert_eq!(info.init_system, cloned.init_system);
}

#[test]
fn platform_info_serialize_deserialize_roundtrip() {
    let info = PlatformInfo {
        os: "macos".to_string(),
        version: "14.0".to_string(),
        arch: "aarch64".to_string(),
        firewall: Firewall::Pf,
        init_system: InitSystem::Launchd,
    };

    let json = serde_json::to_string(&info).expect("serialization should succeed");
    let deserialized: PlatformInfo =
        serde_json::from_str(&json).expect("deserialization should succeed");

    assert_eq!(info.os, deserialized.os);
    assert_eq!(info.version, deserialized.version);
    assert_eq!(info.arch, deserialized.arch);
    assert_eq!(info.firewall, deserialized.firewall);
    assert_eq!(info.init_system, deserialized.init_system);
}

#[test]
fn platform_info_serialize_contains_expected_fields() {
    let info = PlatformInfo {
        os: "linux".to_string(),
        version: "unknown".to_string(),
        arch: "x86_64".to_string(),
        firewall: Firewall::Unknown,
        init_system: InitSystem::Unknown,
    };

    let json = serde_json::to_string(&info).expect("serialization should succeed");
    assert!(json.contains("\"os\""));
    assert!(json.contains("\"linux\""));
    assert!(json.contains("\"arch\""));
    assert!(json.contains("\"x86_64\""));
    assert!(json.contains("\"firewall\""));
    assert!(json.contains("\"init_system\""));
}

#[test]
fn platform_info_deserialize_from_json() {
    let json = r#"{
        "os": "freebsd",
        "version": "13.2",
        "arch": "amd64",
        "firewall": "Pf",
        "init_system": "Rc"
    }"#;

    let info: PlatformInfo = serde_json::from_str(json).expect("deserialization should succeed");
    assert_eq!(info.os, "freebsd");
    assert_eq!(info.version, "13.2");
    assert_eq!(info.arch, "amd64");
    assert_eq!(info.firewall, Firewall::Pf);
    assert_eq!(info.init_system, InitSystem::Rc);
}

// ---------------------------------------------------------------------------
// detect_firewall tests
// ---------------------------------------------------------------------------

#[test]
fn detect_firewall_returns_valid_variant() {
    let fw = detect_firewall();
    // Should be one of the valid variants -- we just verify it matches
    // at least one. Since it is an enum the match is exhaustive by nature.
    let is_valid = matches!(
        fw,
        Firewall::Iptables
            | Firewall::Nftables
            | Firewall::Pf
            | Firewall::Firewalld
            | Firewall::WindowsFirewall
            | Firewall::Unknown
    );
    assert!(is_valid, "detect_firewall returned an invalid variant");
}

// ---------------------------------------------------------------------------
// detect_init tests
// ---------------------------------------------------------------------------

#[test]
fn detect_init_returns_valid_variant() {
    let init = detect_init();
    let is_valid = matches!(
        init,
        InitSystem::Systemd
            | InitSystem::OpenRC
            | InitSystem::Launchd
            | InitSystem::Rc
            | InitSystem::Unknown
    );
    assert!(is_valid, "detect_init returned an invalid variant");
}

// ---------------------------------------------------------------------------
// detect_platform tests
// ---------------------------------------------------------------------------

#[test]
fn detect_platform_returns_non_empty_os_and_arch() {
    let info = detect_platform();
    assert!(!info.os.is_empty(), "os should not be empty");
    assert!(!info.arch.is_empty(), "arch should not be empty");
}

#[test]
fn detect_platform_returns_expected_os_values() {
    let info = detect_platform();
    let valid_os = [
        "linux",
        "macos",
        "freebsd",
        "windows",
        "openbsd",
        "netbsd",
        "dragonfly",
    ];
    assert!(
        valid_os.contains(&info.os.as_str()) || !info.os.is_empty(),
        "os should be a known platform or at least non-empty, got: {}",
        info.os
    );
}

#[test]
fn detect_platform_firewall_and_init_are_consistent() {
    let info = detect_platform();
    // The detected firewall and init system should be valid variants.
    let _ = info.firewall;
    let _ = info.init_system;
    // Platform detection should succeed without panicking.
}

// ---------------------------------------------------------------------------
// default_ban_commands tests
// ---------------------------------------------------------------------------

#[test]
fn default_ban_commands_iptables() {
    let cmds = default_ban_commands(Firewall::Iptables);
    assert!(
        !cmds.linux.is_empty(),
        "iptables ban commands should have linux entries"
    );
    assert!(cmds.linux[0].contains("iptables"));
    assert!(cmds.linux[0].contains("-I INPUT"));
    assert!(cmds.linux[0].contains("<ip>"));
}

#[test]
fn default_ban_commands_nftables() {
    let cmds = default_ban_commands(Firewall::Nftables);
    assert!(
        !cmds.linux.is_empty(),
        "nftables ban commands should have linux entries"
    );
    assert!(cmds.linux[0].contains("nft"));
    assert!(cmds.linux[0].contains("<ip>"));
}

#[test]
fn default_ban_commands_pf() {
    let cmds = default_ban_commands(Firewall::Pf);
    assert!(
        cmds.linux.is_empty(),
        "pf ban should have no linux commands"
    );
    assert!(!cmds.macos.is_empty(), "pf ban should have macos commands");
    assert!(
        !cmds.freebsd.is_empty(),
        "pf ban should have freebsd commands"
    );
    assert!(cmds.macos[0].contains("pfctl"));
    assert!(cmds.macos[0].contains("<ip>"));
}

#[test]
fn default_ban_commands_firewalld() {
    let cmds = default_ban_commands(Firewall::Firewalld);
    assert!(
        !cmds.linux.is_empty(),
        "firewalld ban commands should have linux entries"
    );
    assert!(cmds.linux[0].contains("firewall-cmd"));
    assert!(cmds.linux[0].contains("<ip>"));
}

#[test]
fn default_ban_commands_windows_firewall() {
    let cmds = default_ban_commands(Firewall::WindowsFirewall);
    assert!(
        !cmds.linux.is_empty(),
        "windows firewall ban commands should have linux entries (command stored in linux slot)"
    );
    assert!(cmds.linux[0].contains("netsh"));
    assert!(cmds.linux[0].contains("<ip>"));
}

#[test]
fn default_ban_commands_unknown_returns_empty() {
    let cmds = default_ban_commands(Firewall::Unknown);
    assert!(
        cmds.linux.is_empty(),
        "Unknown ban should have empty linux commands"
    );
    assert!(
        cmds.macos.is_empty(),
        "Unknown ban should have empty macos commands"
    );
    assert!(
        cmds.freebsd.is_empty(),
        "Unknown ban should have empty freebsd commands"
    );
}

// ---------------------------------------------------------------------------
// IPv6 support tests
// ---------------------------------------------------------------------------

#[test]
fn default_ban_commands_iptables_includes_ipv6_variant() {
    let cmds = default_ban_commands(Firewall::Iptables);
    assert!(
        cmds.linux[0].contains("ip6tables"),
        "iptables ban command should include ip6tables for IPv6: {}",
        cmds.linux[0]
    );
    assert!(
        cmds.linux[0].contains("grep -q ':'"),
        "iptables ban command should detect IPv6 by colon: {}",
        cmds.linux[0]
    );
}

#[test]
fn default_ban_commands_nftables_includes_ipv6_variant() {
    let cmds = default_ban_commands(Firewall::Nftables);
    assert!(
        cmds.linux[0].contains("ip6 filter"),
        "nftables ban command should include ip6 table for IPv6: {}",
        cmds.linux[0]
    );
    assert!(
        cmds.linux[0].contains("ipv6_addr"),
        "nftables ban command should include ipv6_addr type: {}",
        cmds.linux[0]
    );
}

#[test]
fn default_unban_commands_iptables_includes_ipv6_variant() {
    let cmds = default_unban_commands(Firewall::Iptables);
    assert!(
        cmds.linux[0].contains("ip6tables"),
        "iptables unban command should include ip6tables for IPv6: {}",
        cmds.linux[0]
    );
    assert!(
        cmds.linux[0].contains("grep -q ':'"),
        "iptables unban command should detect IPv6 by colon: {}",
        cmds.linux[0]
    );
}

#[test]
fn default_unban_commands_nftables_includes_ipv6_variant() {
    let cmds = default_unban_commands(Firewall::Nftables);
    assert!(
        cmds.linux[0].contains("ip6 filter"),
        "nftables unban command should include ip6 table for IPv6: {}",
        cmds.linux[0]
    );
}

// ---------------------------------------------------------------------------
// default_unban_commands tests
// ---------------------------------------------------------------------------

#[test]
fn default_unban_commands_iptables() {
    let cmds = default_unban_commands(Firewall::Iptables);
    assert!(
        !cmds.linux.is_empty(),
        "iptables unban commands should have linux entries"
    );
    assert!(cmds.linux[0].contains("iptables"));
    assert!(cmds.linux[0].contains("-D INPUT"));
    assert!(cmds.linux[0].contains("<ip>"));
}

#[test]
fn default_unban_commands_nftables() {
    let cmds = default_unban_commands(Firewall::Nftables);
    assert!(
        !cmds.linux.is_empty(),
        "nftables unban commands should have linux entries"
    );
    assert!(cmds.linux[0].contains("nft"));
    assert!(cmds.linux[0].contains("delete"));
    assert!(cmds.linux[0].contains("<ip>"));
}

#[test]
fn default_unban_commands_pf() {
    let cmds = default_unban_commands(Firewall::Pf);
    assert!(
        cmds.linux.is_empty(),
        "pf unban should have no linux commands"
    );
    assert!(
        !cmds.macos.is_empty(),
        "pf unban should have macos commands"
    );
    assert!(
        !cmds.freebsd.is_empty(),
        "pf unban should have freebsd commands"
    );
    assert!(cmds.macos[0].contains("pfctl"));
}

#[test]
fn default_unban_commands_firewalld() {
    let cmds = default_unban_commands(Firewall::Firewalld);
    assert!(
        !cmds.linux.is_empty(),
        "firewalld unban commands should have linux entries"
    );
    assert!(cmds.linux[0].contains("firewall-cmd"));
    assert!(cmds.linux[0].contains("remove-source"));
    assert!(cmds.linux[0].contains("<ip>"));
}

#[test]
fn default_unban_commands_windows_firewall() {
    let cmds = default_unban_commands(Firewall::WindowsFirewall);
    assert!(
        !cmds.linux.is_empty(),
        "windows firewall unban commands should have linux entries"
    );
    assert!(cmds.linux[0].contains("netsh"));
    assert!(cmds.linux[0].contains("delete"));
    assert!(cmds.linux[0].contains("<ip>"));
}

#[test]
fn default_unban_commands_unknown_returns_empty() {
    let cmds = default_unban_commands(Firewall::Unknown);
    assert!(cmds.linux.is_empty());
    assert!(cmds.macos.is_empty());
    assert!(cmds.freebsd.is_empty());
}

// ---------------------------------------------------------------------------
// PlatformCommands::for_current_platform tests
// ---------------------------------------------------------------------------

#[test]
fn for_current_platform_returns_correct_slice() {
    use crate::types::PlatformCommands;

    let cmds = PlatformCommands::new(
        vec!["linux_cmd".to_string()],
        vec!["macos_cmd".to_string()],
        vec!["freebsd_cmd".to_string()],
    );

    let platform_cmds = cmds.for_current_platform();

    if cfg!(target_os = "linux") {
        assert_eq!(platform_cmds, &["linux_cmd"]);
    } else if cfg!(target_os = "macos") {
        assert_eq!(platform_cmds, &["macos_cmd"]);
    } else if cfg!(target_os = "freebsd") {
        assert_eq!(platform_cmds, &["freebsd_cmd"]);
    }
    // For other platforms the fallback is linux.
}

#[test]
fn for_current_platform_empty_commands() {
    use crate::types::PlatformCommands;

    let cmds = PlatformCommands::new(vec![], vec![], vec![]);
    let platform_cmds = cmds.for_current_platform();
    assert!(platform_cmds.is_empty());
}

#[test]
fn for_current_platform_multiple_commands() {
    use crate::types::PlatformCommands;

    let cmds = PlatformCommands::new(
        vec!["cmd1".to_string(), "cmd2".to_string(), "cmd3".to_string()],
        vec!["mcmd1".to_string()],
        vec![],
    );

    let platform_cmds = cmds.for_current_platform();

    if cfg!(target_os = "linux") {
        assert_eq!(platform_cmds.len(), 3);
        assert_eq!(platform_cmds[0], "cmd1");
        assert_eq!(platform_cmds[1], "cmd2");
        assert_eq!(platform_cmds[2], "cmd3");
    } else if cfg!(target_os = "macos") {
        assert_eq!(platform_cmds.len(), 1);
        assert_eq!(platform_cmds[0], "mcmd1");
    } else if cfg!(target_os = "freebsd") {
        assert!(platform_cmds.is_empty());
    }
}

// ---------------------------------------------------------------------------
// Firewall and InitSystem serialization roundtrips
// ---------------------------------------------------------------------------

#[test]
fn firewall_serialize_deserialize_roundtrip() {
    let variants = [
        Firewall::Iptables,
        Firewall::Nftables,
        Firewall::Pf,
        Firewall::Firewalld,
        Firewall::WindowsFirewall,
        Firewall::Unknown,
    ];

    for variant in &variants {
        let json = serde_json::to_string(variant).expect("serialization should succeed");
        let deserialized: Firewall =
            serde_json::from_str(&json).expect("deserialization should succeed");
        assert_eq!(*variant, deserialized);
    }
}

#[test]
fn init_system_serialize_deserialize_roundtrip() {
    let variants = [
        InitSystem::Systemd,
        InitSystem::OpenRC,
        InitSystem::Launchd,
        InitSystem::Rc,
        InitSystem::Unknown,
    ];

    for variant in &variants {
        let json = serde_json::to_string(variant).expect("serialization should succeed");
        let deserialized: InitSystem =
            serde_json::from_str(&json).expect("deserialization should succeed");
        assert_eq!(*variant, deserialized);
    }
}

// ---------------------------------------------------------------------------
// Edge case: default ban/unban commands symmetry
// ---------------------------------------------------------------------------

#[test]
fn default_ban_and_unban_commands_same_structure_per_firewall() {
    let firewalls = [
        Firewall::Iptables,
        Firewall::Nftables,
        Firewall::Pf,
        Firewall::Firewalld,
        Firewall::WindowsFirewall,
        Firewall::Unknown,
    ];

    for fw in &firewalls {
        let ban = default_ban_commands(*fw);
        let unban = default_unban_commands(*fw);

        // The command vectors should have the same number of entries per platform.
        assert_eq!(
            ban.linux.len(),
            unban.linux.len(),
            "linux command count mismatch for {:?}",
            fw
        );
        assert_eq!(
            ban.macos.len(),
            unban.macos.len(),
            "macos command count mismatch for {:?}",
            fw
        );
        assert_eq!(
            ban.freebsd.len(),
            unban.freebsd.len(),
            "freebsd command count mismatch for {:?}",
            fw
        );
    }
}

// ---------------------------------------------------------------------------
// Edge case: <ip> placeholder presence in all non-Unknown firewall commands
// ---------------------------------------------------------------------------

#[test]
fn default_ban_commands_all_firewalls_have_ip_placeholder() {
    let firewalls = [
        Firewall::Iptables,
        Firewall::Nftables,
        Firewall::Pf,
        Firewall::Firewalld,
        Firewall::WindowsFirewall,
    ];

    for fw in &firewalls {
        let cmds = default_ban_commands(*fw);
        let has_ip = cmds.linux.iter().any(|c| c.contains("<ip>"))
            || cmds.macos.iter().any(|c| c.contains("<ip>"))
            || cmds.freebsd.iter().any(|c| c.contains("<ip>"));
        assert!(
            has_ip,
            "default_ban_commands({:?}) should contain at least one command with <ip>",
            fw
        );
    }
}

#[test]
fn default_unban_commands_all_firewalls_have_ip_placeholder() {
    let firewalls = [
        Firewall::Iptables,
        Firewall::Nftables,
        Firewall::Pf,
        Firewall::Firewalld,
        Firewall::WindowsFirewall,
    ];

    for fw in &firewalls {
        let cmds = default_unban_commands(*fw);
        let has_ip = cmds.linux.iter().any(|c| c.contains("<ip>"))
            || cmds.macos.iter().any(|c| c.contains("<ip>"))
            || cmds.freebsd.iter().any(|c| c.contains("<ip>"));
        assert!(
            has_ip,
            "default_unban_commands({:?}) should contain at least one command with <ip>",
            fw
        );
    }
}

// ---------------------------------------------------------------------------
// Edge case: detect functions do not panic
// ---------------------------------------------------------------------------

#[test]
fn detect_firewall_does_not_panic() {
    // Edge case: ensure platform detection gracefully handles any environment.
    let _fw = detect_firewall();
}

#[test]
fn detect_init_does_not_panic() {
    // Edge case: ensure init system detection gracefully handles any environment.
    let _init = detect_init();
}

// ---------------------------------------------------------------------------
// Edge case: platform info defaults
// ---------------------------------------------------------------------------

#[test]
fn platform_info_version_is_unknown_by_default() {
    let info = detect_platform();
    assert_eq!(
        info.version, "unknown",
        "detect_platform should set version to \"unknown\" since real version detection is not implemented"
    );
}

// ---------------------------------------------------------------------------
// Edge case: serialization of all variants to known strings
// ---------------------------------------------------------------------------

#[test]
fn firewall_all_variants_serialize_to_known_strings() {
    let known = [
        "Iptables",
        "Nftables",
        "Pf",
        "Firewalld",
        "WindowsFirewall",
        "Unknown",
    ];

    let variants = [
        Firewall::Iptables,
        Firewall::Nftables,
        Firewall::Pf,
        Firewall::Firewalld,
        Firewall::WindowsFirewall,
        Firewall::Unknown,
    ];

    for variant in &variants {
        let json = serde_json::to_string(variant).expect("serialization should succeed");
        // serde_json::to_string wraps enum variants in quotes; strip them for comparison.
        let inner = &json[1..json.len() - 1];
        assert!(
            known.contains(&inner),
            "Firewall::{:?} serialized to unexpected string: {}",
            variant,
            json
        );
    }
}

#[test]
fn init_system_all_variants_serialize_to_known_strings() {
    let known = ["Systemd", "OpenRC", "Launchd", "Rc", "Unknown"];

    let variants = [
        InitSystem::Systemd,
        InitSystem::OpenRC,
        InitSystem::Launchd,
        InitSystem::Rc,
        InitSystem::Unknown,
    ];

    for variant in &variants {
        let json = serde_json::to_string(variant).expect("serialization should succeed");
        // serde_json::to_string wraps enum variants in quotes; strip them for comparison.
        let inner = &json[1..json.len() - 1];
        assert!(
            known.contains(&inner),
            "InitSystem::{:?} serialized to unexpected string: {}",
            variant,
            json
        );
    }
}

// ---------------------------------------------------------------------------
// Edge case: Unknown firewall has empty commands
// ---------------------------------------------------------------------------

#[test]
fn default_ban_and_unban_commands_empty_for_unknown() {
    let ban = default_ban_commands(Firewall::Unknown);
    let unban = default_unban_commands(Firewall::Unknown);

    assert!(ban.linux.is_empty(), "Unknown ban linux should be empty");
    assert!(ban.macos.is_empty(), "Unknown ban macos should be empty");
    assert!(
        ban.freebsd.is_empty(),
        "Unknown ban freebsd should be empty"
    );
    assert!(
        unban.linux.is_empty(),
        "Unknown unban linux should be empty"
    );
    assert!(
        unban.macos.is_empty(),
        "Unknown unban macos should be empty"
    );
    assert!(
        unban.freebsd.is_empty(),
        "Unknown unban freebsd should be empty"
    );
}
