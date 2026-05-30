use super::*;
use std::net::{IpAddr, Ipv6Addr};
use tempfile::tempdir;

// ---------------------------------------------------------------------------
// CidrBlock
// ---------------------------------------------------------------------------

#[test]
fn cidr_block_new_valid_ipv4() {
    let block = CidrBlock::new("192.168.1.0".parse().unwrap(), 24);
    assert!(block.is_ok());
    let block = block.unwrap();
    assert_eq!(block.addr(), "192.168.1.0".parse::<IpAddr>().unwrap());
    assert_eq!(block.prefix(), 24);
}

#[test]
fn cidr_block_new_valid_ipv4_slash_zero() {
    let block = CidrBlock::new("0.0.0.0".parse().unwrap(), 0);
    assert!(block.is_ok());
    assert_eq!(block.unwrap().prefix(), 0);
}

#[test]
fn cidr_block_new_valid_ipv4_slash_32() {
    let block = CidrBlock::new("10.0.0.1".parse().unwrap(), 32);
    assert!(block.is_ok());
    assert_eq!(block.unwrap().prefix(), 32);
}

#[test]
fn cidr_block_new_valid_ipv6() {
    let block = CidrBlock::new("2001:db8::".parse().unwrap(), 32);
    assert!(block.is_ok());
    let block = block.unwrap();
    assert_eq!(block.addr(), "2001:db8::".parse::<IpAddr>().unwrap());
    assert_eq!(block.prefix(), 32);
}

#[test]
fn cidr_block_new_valid_ipv6_slash_zero() {
    let block = CidrBlock::new("::".parse().unwrap(), 0);
    assert!(block.is_ok());
    assert_eq!(block.unwrap().prefix(), 0);
}

#[test]
fn cidr_block_new_valid_ipv6_slash_128() {
    let block = CidrBlock::new("::1".parse().unwrap(), 128);
    assert!(block.is_ok());
    assert_eq!(block.unwrap().prefix(), 128);
}

#[test]
fn cidr_block_new_invalid_ipv4_prefix() {
    let result = CidrBlock::new("192.168.1.0".parse().unwrap(), 33);
    assert!(result.is_err());
    match result.unwrap_err() {
        crate::Error::InvalidIp(msg) => {
            assert!(msg.contains("33"), "message should mention the bad prefix: {msg}");
            assert!(msg.contains("32"), "message should mention the max prefix: {msg}");
        }
        other => panic!("expected InvalidIp, got: {other:?}"),
    }
}

#[test]
fn cidr_block_new_invalid_ipv6_prefix() {
    let result = CidrBlock::new("::1".parse().unwrap(), 129);
    assert!(result.is_err());
    match result.unwrap_err() {
        crate::Error::InvalidIp(msg) => {
            assert!(msg.contains("129"));
            assert!(msg.contains("128"));
        }
        other => panic!("expected InvalidIp, got: {other:?}"),
    }
}

#[test]
fn cidr_block_new_ipv4_prefix_255_is_invalid() {
    let result = CidrBlock::new("1.2.3.4".parse().unwrap(), 255);
    assert!(result.is_err());
}

// -- contains ---------------------------------------------------------------

#[test]
fn cidr_block_contains_exact_match() {
    let block = CidrBlock::new("10.0.0.5".parse().unwrap(), 32).unwrap();
    assert!(block.contains("10.0.0.5".parse().unwrap()));
}

#[test]
fn cidr_block_contains_subnet_match() {
    let block = CidrBlock::new("192.168.1.0".parse().unwrap(), 24).unwrap();
    assert!(block.contains("192.168.1.1".parse().unwrap()));
    assert!(block.contains("192.168.1.254".parse().unwrap()));
    assert!(block.contains("192.168.1.0".parse().unwrap()));
    assert!(block.contains("192.168.1.255".parse().unwrap()));
}

#[test]
fn cidr_block_contains_outside_subnet() {
    let block = CidrBlock::new("192.168.1.0".parse().unwrap(), 24).unwrap();
    assert!(!block.contains("192.168.2.1".parse().unwrap()));
    assert!(!block.contains("192.168.0.1".parse().unwrap()));
    assert!(!block.contains("10.0.0.1".parse().unwrap()));
}

#[test]
fn cidr_block_contains_slash_32_only_that_ip() {
    let block = CidrBlock::new("172.16.0.1".parse().unwrap(), 32).unwrap();
    assert!(block.contains("172.16.0.1".parse().unwrap()));
    assert!(!block.contains("172.16.0.2".parse().unwrap()));
    assert!(!block.contains("172.16.0.0".parse().unwrap()));
}

#[test]
fn cidr_block_contains_slash_0_contains_everything_v4() {
    let block = CidrBlock::new("0.0.0.0".parse().unwrap(), 0).unwrap();
    assert!(block.contains("0.0.0.0".parse().unwrap()));
    assert!(block.contains("192.168.1.1".parse().unwrap()));
    assert!(block.contains("255.255.255.255".parse().unwrap()));
}

#[test]
fn cidr_block_contains_ipv6_exact() {
    let block = CidrBlock::new("2001:db8::1".parse().unwrap(), 128).unwrap();
    assert!(block.contains("2001:db8::1".parse().unwrap()));
    assert!(!block.contains("2001:db8::2".parse().unwrap()));
}

#[test]
fn cidr_block_contains_ipv6_subnet() {
    let block = CidrBlock::new("2001:db8::".parse().unwrap(), 32).unwrap();
    assert!(block.contains("2001:db8::1".parse().unwrap()));
    assert!(block.contains("2001:db8:ffff::".parse().unwrap()));
    assert!(!block.contains("2001:db9::".parse().unwrap()));
}

#[test]
fn cidr_block_contains_ipv6_slash_0() {
    let block = CidrBlock::new("::".parse().unwrap(), 0).unwrap();
    assert!(block.contains("::1".parse().unwrap()));
    assert!(block.contains("fe80::1".parse().unwrap()));
    assert!(block.contains("2001:db8::".parse().unwrap()));
}

#[test]
fn cidr_block_contains_ipv4_mapped_ipv6_mismatch() {
    // An IPv4 CIDR block must NOT match an IPv6 address, even if it
    // looks like the IPv4-mapped representation.
    let block = CidrBlock::new("192.168.1.0".parse().unwrap(), 24).unwrap();
    let mapped: IpAddr = "::ffff:192.168.1.1".parse().unwrap();
    assert!(!block.contains(mapped));
}

#[test]
fn cidr_block_contains_ipv6_does_not_match_ipv4() {
    let block = CidrBlock::new("2001:db8::".parse().unwrap(), 32).unwrap();
    assert!(!block.contains("192.168.1.1".parse().unwrap()));
}

#[test]
fn cidr_block_contains_slash_16() {
    let block = CidrBlock::new("10.0.0.0".parse().unwrap(), 16).unwrap();
    assert!(block.contains("10.0.0.1".parse().unwrap()));
    assert!(block.contains("10.0.255.255".parse().unwrap()));
    assert!(!block.contains("10.1.0.0".parse().unwrap()));
}

// -- Display ----------------------------------------------------------------

#[test]
fn cidr_block_display_ipv4() {
    let block = CidrBlock::new("192.168.1.0".parse().unwrap(), 24).unwrap();
    assert_eq!(format!("{block}"), "192.168.1.0/24");
}

#[test]
fn cidr_block_display_ipv6() {
    let block = CidrBlock::new("2001:db8::".parse().unwrap(), 32).unwrap();
    assert_eq!(format!("{block}"), "2001:db8::/32");
}

#[test]
fn cidr_block_display_slash_32() {
    let block = CidrBlock::new("10.0.0.1".parse().unwrap(), 32).unwrap();
    assert_eq!(format!("{block}"), "10.0.0.1/32");
}

#[test]
fn cidr_block_display_slash_0() {
    let block = CidrBlock::new("0.0.0.0".parse().unwrap(), 0).unwrap();
    assert_eq!(format!("{block}"), "0.0.0.0/0");
}

// ---------------------------------------------------------------------------
// CidrSet
// ---------------------------------------------------------------------------

#[test]
fn cidr_set_empty_contains_nothing() {
    let set = CidrSet::new();
    assert!(!set.contains("192.168.1.1".parse().unwrap()));
    assert!(!set.contains("::1".parse().unwrap()));
    assert!(set.is_empty());
}

#[test]
fn cidr_set_insert_and_contains_single_ip() {
    let mut set = CidrSet::new();
    let block = CidrBlock::new("10.0.0.1".parse().unwrap(), 32).unwrap();
    set.insert(block);

    assert!(set.contains("10.0.0.1".parse().unwrap()));
    assert!(!set.contains("10.0.0.2".parse().unwrap()));
    assert!(!set.is_empty());
}

#[test]
fn cidr_set_insert_and_contains_subnet() {
    let mut set = CidrSet::new();
    let block = CidrBlock::new("192.168.1.0".parse().unwrap(), 24).unwrap();
    set.insert(block);

    assert!(set.contains("192.168.1.1".parse().unwrap()));
    assert!(set.contains("192.168.1.254".parse().unwrap()));
    assert!(!set.contains("192.168.2.1".parse().unwrap()));
}

#[test]
fn cidr_set_insert_and_contains_ipv6() {
    let mut set = CidrSet::new();
    let block = CidrBlock::new("2001:db8::".parse().unwrap(), 32).unwrap();
    set.insert(block);

    assert!(set.contains("2001:db8::1".parse().unwrap()));
    assert!(!set.contains("2001:db9::1".parse().unwrap()));
}

#[test]
fn cidr_set_insert_and_contains_ipv6_single() {
    let mut set = CidrSet::new();
    let block = CidrBlock::new("::1".parse().unwrap(), 128).unwrap();
    set.insert(block);

    assert!(set.contains("::1".parse().unwrap()));
    assert!(!set.contains("::2".parse().unwrap()));
}

#[test]
fn cidr_set_remove_success() {
    let mut set = CidrSet::new();
    let block = CidrBlock::new("10.0.0.0".parse().unwrap(), 24).unwrap();
    set.insert(block);

    assert!(set.contains("10.0.0.5".parse().unwrap()));
    assert!(set.remove(&block));
    assert!(!set.contains("10.0.0.5".parse().unwrap()));
}

#[test]
fn cidr_set_remove_success_single() {
    let mut set = CidrSet::new();
    let block = CidrBlock::new("10.0.0.1".parse().unwrap(), 32).unwrap();
    set.insert(block);

    assert!(set.remove(&block));
    assert!(!set.contains("10.0.0.1".parse().unwrap()));
}

#[test]
fn cidr_set_remove_failure() {
    let mut set = CidrSet::new();
    let block = CidrBlock::new("10.0.0.0".parse().unwrap(), 24).unwrap();

    // Removing a block that was never inserted returns false.
    assert!(!set.remove(&block));
}

#[test]
fn cidr_set_remove_failure_single() {
    let mut set = CidrSet::new();
    let block = CidrBlock::new("10.0.0.1".parse().unwrap(), 32).unwrap();
    assert!(!set.remove(&block));
}

#[test]
fn cidr_set_mixed_ipv4_ipv6() {
    let mut set = CidrSet::new();
    let v4 = CidrBlock::new("192.168.0.0".parse().unwrap(), 16).unwrap();
    let v6 = CidrBlock::new("2001:db8::".parse().unwrap(), 32).unwrap();
    set.insert(v4);
    set.insert(v6);

    assert!(set.contains("192.168.1.1".parse().unwrap()));
    assert!(set.contains("2001:db8::abcd".parse().unwrap()));
    // Cross-family does not match.
    assert!(!set.contains("10.0.0.1".parse().unwrap()));
    assert!(!set.contains("fe80::1".parse().unwrap()));
}

#[test]
fn cidr_set_is_empty_initial() {
    let set = CidrSet::new();
    assert!(set.is_empty());
}

#[test]
fn cidr_set_is_empty_after_insert() {
    let mut set = CidrSet::new();
    let block = CidrBlock::new("10.0.0.1".parse().unwrap(), 32).unwrap();
    set.insert(block);
    assert!(!set.is_empty());
}

#[test]
fn cidr_set_is_empty_after_insert_and_remove() {
    let mut set = CidrSet::new();
    let block = CidrBlock::new("10.0.0.0".parse().unwrap(), 24).unwrap();
    set.insert(block);
    set.remove(&block);
    assert!(set.is_empty());
}

#[test]
fn cidr_set_multiple_subnets() {
    let mut set = CidrSet::new();
    let a = CidrBlock::new("10.0.0.0".parse().unwrap(), 8).unwrap();
    let b = CidrBlock::new("172.16.0.0".parse().unwrap(), 12).unwrap();
    let c = CidrBlock::new("192.168.0.0".parse().unwrap(), 16).unwrap();
    set.insert(a);
    set.insert(b);
    set.insert(c);

    assert!(set.contains("10.1.2.3".parse().unwrap()));
    assert!(set.contains("172.16.5.5".parse().unwrap()));
    assert!(set.contains("192.168.99.1".parse().unwrap()));
    assert!(!set.contains("8.8.8.8".parse().unwrap()));
}

// ---------------------------------------------------------------------------
// BanManager
// ---------------------------------------------------------------------------

fn setup_manager() -> (BanManager, tempfile::TempDir) {
    let dir = tempdir().expect("failed to create temp dir");
    let store_path = dir.path().join("bans.json");
    let store = Store::new(store_path);
    let manager = BanManager::new(store);
    (manager, dir)
}

#[test]
fn ban_manager_ban_adds_entry() {
    let (manager, _dir) = setup_manager();
    let ip: IpAddr = "192.168.1.100".parse().unwrap();

    let entry = manager.ban(ip, 32, "sshd", 3, 3600, Some("brute force".to_string()));
    assert!(entry.is_ok());
    let entry = entry.unwrap();
    assert_eq!(entry.ip, ip);
    assert_eq!(entry.prefix, 32);
    assert_eq!(entry.jail_name, "sshd");
    assert_eq!(entry.fail_count, 3);
    assert_eq!(entry.reason, Some("brute force".to_string()));
    assert!(entry.expires_at.is_some());
}

#[test]
fn ban_manager_ban_duplicate_returns_already_banned() {
    let (manager, _dir) = setup_manager();
    let ip: IpAddr = "10.0.0.1".parse().unwrap();

    let first = manager.ban(ip, 32, "sshd", 1, 3600, None);
    assert!(first.is_ok());

    let second = manager.ban(ip, 32, "sshd", 2, 3600, None);
    assert!(second.is_err());
    match second.unwrap_err() {
        crate::Error::AlreadyBanned(msg) => assert!(msg.contains("10.0.0.1")),
        other => panic!("expected AlreadyBanned, got: {other:?}"),
    }
}

#[test]
fn ban_manager_ban_same_ip_different_jails() {
    let (manager, _dir) = setup_manager();
    let ip: IpAddr = "10.0.0.1".parse().unwrap();

    let first = manager.ban(ip, 32, "sshd", 1, 3600, None);
    assert!(first.is_ok());

    // Same IP but different jail should succeed.
    let second = manager.ban(ip, 32, "nginx", 1, 3600, None);
    assert!(second.is_ok());
}

#[test]
fn ban_manager_unban_removes_entry() {
    let (manager, _dir) = setup_manager();
    let ip: IpAddr = "192.168.1.100".parse().unwrap();

    manager.ban(ip, 32, "sshd", 3, 3600, None).unwrap();
    assert!(manager.is_banned(ip).unwrap());

    let removed = manager.unban("192.168.1.100".parse().unwrap(), "sshd");
    assert!(removed.is_ok());
    assert_eq!(removed.unwrap().ip, ip);

    assert!(!manager.is_banned(ip).unwrap());
}

#[test]
fn ban_manager_unban_nonexistent_returns_not_banned() {
    let (manager, _dir) = setup_manager();

    let result = manager.unban("10.0.0.99".parse().unwrap(), "sshd");
    assert!(result.is_err());
    match result.unwrap_err() {
        crate::Error::NotBanned(msg) => assert!(msg.contains("10.0.0.99")),
        other => panic!("expected NotBanned, got: {other:?}"),
    }
}

#[test]
fn ban_manager_is_banned_true() {
    let (manager, _dir) = setup_manager();
    let ip: IpAddr = "10.0.0.5".parse().unwrap();

    manager.ban(ip, 32, "sshd", 5, 7200, None).unwrap();
    assert!(manager.is_banned(ip).unwrap());
}

#[test]
fn ban_manager_is_banned_false() {
    let (manager, _dir) = setup_manager();
    let ip: IpAddr = "10.0.0.5".parse().unwrap();

    assert!(!manager.is_banned(ip).unwrap());
}

#[test]
fn ban_manager_is_banned_after_unban() {
    let (manager, _dir) = setup_manager();
    let ip: IpAddr = "10.0.0.5".parse().unwrap();

    manager.ban(ip, 32, "sshd", 1, 3600, None).unwrap();
    manager.unban("10.0.0.5".parse().unwrap(), "sshd").unwrap();
    assert!(!manager.is_banned(ip).unwrap());
}

#[test]
fn ban_manager_list_bans_all() {
    let (manager, _dir) = setup_manager();

    let ip1: IpAddr = "10.0.0.1".parse().unwrap();
    let ip2: IpAddr = "10.0.0.2".parse().unwrap();

    manager.ban(ip1, 32, "sshd", 1, 3600, None).unwrap();
    manager.ban(ip2, 32, "nginx", 1, 3600, None).unwrap();

    let all = manager.list_bans(None).unwrap();
    assert_eq!(all.len(), 2);
}

#[test]
fn ban_manager_list_bans_filtered_by_jail() {
    let (manager, _dir) = setup_manager();

    let ip1: IpAddr = "10.0.0.1".parse().unwrap();
    let ip2: IpAddr = "10.0.0.2".parse().unwrap();

    manager.ban(ip1, 32, "sshd", 1, 3600, None).unwrap();
    manager.ban(ip2, 32, "nginx", 1, 3600, None).unwrap();

    let sshd_bans = manager.list_bans(Some("sshd")).unwrap();
    assert_eq!(sshd_bans.len(), 1);
    assert_eq!(sshd_bans[0].ip, ip1);
    assert_eq!(sshd_bans[0].jail_name, "sshd");

    let nginx_bans = manager.list_bans(Some("nginx")).unwrap();
    assert_eq!(nginx_bans.len(), 1);
    assert_eq!(nginx_bans[0].ip, ip2);

    let unknown_bans = manager.list_bans(Some("nonexistent")).unwrap();
    assert!(unknown_bans.is_empty());
}

#[test]
fn ban_manager_list_bans_empty() {
    let (manager, _dir) = setup_manager();
    let bans = manager.list_bans(None).unwrap();
    assert!(bans.is_empty());
}

#[test]
fn ban_manager_purge_expired_moves_expired_bans() {
    let (manager, _dir) = setup_manager();

    // Manually insert a ban that already expired (expires_at in the past).
    let past = Utc::now() - Duration::seconds(60);
    let entry = crate::types::BanEntry {
        ip: "10.0.0.1".parse().unwrap(),
        prefix: 32,
        banned_at: past - Duration::seconds(3600),
        expires_at: Some(past),
        jail_name: "sshd".to_string(),
        fail_count: 5,
        last_fail_at: past - Duration::seconds(3600),
        reason: None,
    };
    manager.store.add_ban(entry).unwrap();

    // Add a non-expired ban.
    manager
        .ban("10.0.0.2".parse().unwrap(), 32, "sshd", 1, 86400, None)
        .unwrap();

    let active_before = manager.list_bans(None).unwrap();
    assert_eq!(active_before.len(), 2);

    let purged = manager.purge_expired().unwrap();
    assert_eq!(purged.len(), 1);
    assert_eq!(purged[0].ip, "10.0.0.1".parse::<IpAddr>().unwrap());

    let active_after = manager.list_bans(None).unwrap();
    assert_eq!(active_after.len(), 1);
    assert_eq!(active_after[0].ip, "10.0.0.2".parse::<IpAddr>().unwrap());
}

#[test]
fn ban_manager_purge_expired_nothing_to_purge() {
    let (manager, _dir) = setup_manager();

    manager
        .ban("10.0.0.1".parse().unwrap(), 32, "sshd", 1, 86400, None)
        .unwrap();

    let purged = manager.purge_expired().unwrap();
    assert!(purged.is_empty());

    let active = manager.list_bans(None).unwrap();
    assert_eq!(active.len(), 1);
}

#[test]
fn ban_manager_purge_expired_empty_store() {
    let (manager, _dir) = setup_manager();

    let purged = manager.purge_expired().unwrap();
    assert!(purged.is_empty());
}

#[test]
fn ban_manager_ban_without_reason() {
    let (manager, _dir) = setup_manager();
    let ip: IpAddr = "10.0.0.1".parse().unwrap();

    let entry = manager.ban(ip, 32, "sshd", 1, 3600, None).unwrap();
    assert!(entry.reason.is_none());
}

#[test]
fn ban_manager_unban_wrong_jail_returns_not_banned() {
    let (manager, _dir) = setup_manager();
    let ip: IpAddr = "10.0.0.1".parse().unwrap();

    manager.ban(ip, 32, "sshd", 1, 3600, None).unwrap();

    // Attempting to unban from a different jail should fail.
    let result = manager.unban("10.0.0.1".parse().unwrap(), "nginx");
    assert!(result.is_err());
    match result.unwrap_err() {
        crate::Error::NotBanned(_) => {}
        other => panic!("expected NotBanned, got: {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Edge-case: ban duration boundaries
// ---------------------------------------------------------------------------

#[test]
fn ban_duration_zero_creates_instantly_expired_ban() {
    let (manager, _dir) = setup_manager();
    let ip: IpAddr = "10.0.0.1".parse().unwrap();

    let entry = manager.ban(ip, 32, "sshd", 1, 0, Some("zero duration".to_string()));
    assert!(entry.is_ok());
    let entry = entry.unwrap();
    let expires = entry.expires_at.expect("expires_at must be set");
    // A duration-0 ban should already be expired (expires_at <= now).
    assert!(
        expires <= Utc::now(),
        "expected expires_at ({expires}) to be <= now ({})",
        Utc::now()
    );
}

#[test]
fn ban_duration_max_value() {
    let (manager, _dir) = setup_manager();
    let ip: IpAddr = "10.0.0.1".parse().unwrap();

    // u64::MAX seconds is far beyond any reasonable timestamp. The i64 cast
    // inside the ban logic must not panic; it should either succeed or return
    // a domain error.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        manager.ban(ip, 32, "sshd", 1, u64::MAX, None)
    }));
    assert!(
        result.is_ok(),
        "ban with u64::MAX duration must not panic"
    );
}

// ---------------------------------------------------------------------------
// Edge-case: IPv4-mapped IPv6 and CidrSet
// ---------------------------------------------------------------------------

#[test]
fn cidr_set_contains_ipv4_mapped_ipv6() {
    let mut set = CidrSet::new();
    let block = CidrBlock::new("10.0.0.0".parse().unwrap(), 8).unwrap();
    set.insert(block);

    // The IPv4-mapped IPv6 representation of 10.0.0.1 must NOT match an
    // IPv4 CIDR block -- they are different address families.
    let mapped: IpAddr = "::ffff:10.0.0.1".parse().unwrap();
    assert!(
        !set.contains(mapped),
        "IPv4 CIDR block must not match IPv4-mapped IPv6 address"
    );
}

// ---------------------------------------------------------------------------
// Edge-case: overlapping CIDR blocks
// ---------------------------------------------------------------------------

#[test]
fn cidr_set_overlapping_blocks() {
    let mut set = CidrSet::new();
    let broad = CidrBlock::new("10.0.0.0".parse().unwrap(), 8).unwrap();
    let narrow = CidrBlock::new("10.0.1.0".parse().unwrap(), 24).unwrap();
    set.insert(broad);
    set.insert(narrow);

    // 10.0.1.1 falls inside both 10.0.0.0/8 and 10.0.1.0/24.
    assert!(
        set.contains("10.0.1.1".parse().unwrap()),
        "overlapping blocks should both match"
    );
    // Also verify the broader block still works for addresses outside /24.
    assert!(
        set.contains("10.99.99.99".parse().unwrap()),
        "broader /8 block should still match"
    );
}

// ---------------------------------------------------------------------------
// Edge-case: IPv6 link-local in CidrBlock
// ---------------------------------------------------------------------------

#[test]
fn cidr_block_contains_ipv6_link_local() {
    let block = CidrBlock::new(
        IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0)),
        10,
    )
    .unwrap();

    // fe80::1 is within fe80::/10
    assert!(
        block.contains(IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1))),
        "fe80::1 must be inside fe80::/10"
    );
    // febf:: should also be in fe80::/10 (the /10 covers fe80..febf)
    assert!(
        block.contains(IpAddr::V6(Ipv6Addr::new(0xfebf, 0, 0, 0, 0, 0, 0, 0))),
        "febf:: must be inside fe80::/10"
    );
    // fec0:: is outside fe80::/10
    assert!(
        !block.contains(IpAddr::V6(Ipv6Addr::new(0xfec0, 0, 0, 0, 0, 0, 0, 0))),
        "fec0:: must NOT be inside fe80::/10"
    );
}

// ---------------------------------------------------------------------------
// Edge-case: ban an IPv6 address via BanManager
// ---------------------------------------------------------------------------

#[test]
fn ban_manager_ban_ipv6() {
    let (manager, _dir) = setup_manager();
    let ip: IpAddr = "2001:db8::abcd".parse().unwrap();

    let entry = manager.ban(ip, 128, "sshd", 7, 3600, Some("ipv6 brute".to_string()));
    assert!(entry.is_ok());
    let entry = entry.unwrap();
    assert_eq!(entry.ip, ip);
    assert_eq!(entry.prefix, 128);
    assert_eq!(entry.jail_name, "sshd");
    assert_eq!(entry.fail_count, 7);
    assert_eq!(entry.reason, Some("ipv6 brute".to_string()));
    assert!(entry.expires_at.is_some());

    // Verify the ban is visible through is_banned.
    assert!(manager.is_banned(ip).unwrap());
}
