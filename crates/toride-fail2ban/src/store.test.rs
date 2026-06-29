use super::*;
use chrono::{Duration, Utc};
use std::net::IpAddr;
use tempfile::tempdir;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_ban(ip: &str, jail: &str) -> BanEntry {
    BanEntry {
        ip: ip.parse().unwrap(),
        prefix: 32,
        banned_at: Utc::now(),
        expires_at: None,
        jail_name: jail.to_string(),
        fail_count: 1,
        last_fail_at: Utc::now(),
        reason: None,
    }
}

fn make_ban_expiring(ip: &str, jail: &str, expires_at: Option<chrono::DateTime<Utc>>) -> BanEntry {
    BanEntry {
        ip: ip.parse().unwrap(),
        prefix: 32,
        banned_at: Utc::now(),
        expires_at,
        jail_name: jail.to_string(),
        fail_count: 1,
        last_fail_at: Utc::now(),
        reason: Some("test reason".to_string()),
    }
}

fn make_journal(jail: &str, log_path: &str, offset: u64, line_number: u64) -> JournalEntry {
    JournalEntry {
        jail_name: jail.to_string(),
        log_path: log_path.into(),
        offset,
        line_number,
        updated_at: Utc::now(),
    }
}

fn tmp_store() -> (tempfile::TempDir, Store) {
    let dir = tempdir().unwrap();
    let store = Store::new(dir.path().join("store.json"));
    (dir, store)
}

// ---------------------------------------------------------------------------
// Store::new / path()
// ---------------------------------------------------------------------------

#[test]
fn new_sets_path_correctly() {
    let dir = tempdir().unwrap();
    let p = dir.path().join("bans.json");
    let store = Store::new(p.clone());
    assert_eq!(store.path(), p.as_path());
}

// ---------------------------------------------------------------------------
// load -- nonexistent file returns default
// ---------------------------------------------------------------------------

#[test]
fn load_nonexistent_returns_default() {
    let (_dir, store) = tmp_store();
    let data = store.load().unwrap();
    assert!(data.active_bans.is_empty());
    assert!(data.history.is_empty());
    assert!(data.journals.is_empty());
}

// ---------------------------------------------------------------------------
// save / load round-trip
// ---------------------------------------------------------------------------

#[test]
fn save_load_roundtrip_empty() {
    let (_dir, store) = tmp_store();
    let data = StoreData::default();
    store.save(&data).unwrap();
    let loaded = store.load().unwrap();
    assert!(loaded.active_bans.is_empty());
    assert!(loaded.history.is_empty());
    assert!(loaded.journals.is_empty());
}

#[test]
fn save_load_roundtrip_populated() {
    let (_dir, store) = tmp_store();

    let data = StoreData {
        active_bans: vec![make_ban("10.0.0.1", "sshd"), make_ban("10.0.0.2", "sshd")],
        history: vec![make_ban("10.0.0.3", "nginx")],
        journals: vec![make_journal("sshd", "/var/log/auth.log", 1024, 50)],
    };

    store.save(&data).unwrap();
    let loaded = store.load().unwrap();

    assert_eq!(loaded.active_bans.len(), 2);
    assert_eq!(loaded.history.len(), 1);
    assert_eq!(loaded.journals.len(), 1);
    assert_eq!(
        loaded.active_bans[0].ip,
        "10.0.0.1".parse::<IpAddr>().unwrap()
    );
    assert_eq!(loaded.journals[0].offset, 1024);
}

#[test]
fn save_overwrites_existing() {
    let (_dir, store) = tmp_store();

    let data1 = StoreData {
        active_bans: vec![make_ban("10.0.0.1", "sshd")],
        history: vec![],
        journals: vec![],
    };
    store.save(&data1).unwrap();

    let data2 = StoreData::default();
    store.save(&data2).unwrap();

    let loaded = store.load().unwrap();
    assert!(loaded.active_bans.is_empty());
}

// ---------------------------------------------------------------------------
// add_ban
// ---------------------------------------------------------------------------

#[test]
fn add_ban_success() {
    let (_dir, store) = tmp_store();
    store.add_ban(&make_ban("192.168.1.1", "sshd")).unwrap();

    let bans = store.get_bans(None).unwrap();
    assert_eq!(bans.len(), 1);
    assert_eq!(bans[0].ip, "192.168.1.1".parse::<IpAddr>().unwrap());
    assert_eq!(bans[0].jail_name, "sshd");
}

#[test]
fn add_ban_duplicate_same_jail_returns_already_banned() {
    let (_dir, store) = tmp_store();
    store.add_ban(&make_ban("192.168.1.1", "sshd")).unwrap();

    let result = store.add_ban(&make_ban("192.168.1.1", "sshd"));
    assert!(result.is_err());
    match result.unwrap_err() {
        crate::Error::AlreadyBanned(ip) => assert_eq!(ip, "192.168.1.1"),
        other => panic!("expected AlreadyBanned, got: {other:?}"),
    }
}

#[test]
fn add_ban_same_ip_different_jails_allowed() {
    let (_dir, store) = tmp_store();
    store.add_ban(&make_ban("192.168.1.1", "sshd")).unwrap();
    store.add_ban(&make_ban("192.168.1.1", "nginx")).unwrap();

    let bans = store.get_bans(None).unwrap();
    assert_eq!(bans.len(), 2);
}

#[test]
fn add_ban_different_ips_same_jail_allowed() {
    let (_dir, store) = tmp_store();
    store.add_ban(&make_ban("10.0.0.1", "sshd")).unwrap();
    store.add_ban(&make_ban("10.0.0.2", "sshd")).unwrap();

    let bans = store.get_bans(None).unwrap();
    assert_eq!(bans.len(), 2);
}

#[test]
fn add_ban_with_ipv6() {
    let (_dir, store) = tmp_store();
    store.add_ban(&make_ban("::1", "sshd")).unwrap();

    let bans = store.get_bans(None).unwrap();
    assert_eq!(bans.len(), 1);
    assert_eq!(bans[0].ip, "::1".parse::<IpAddr>().unwrap());
}

// ---------------------------------------------------------------------------
// remove_ban
// ---------------------------------------------------------------------------

#[test]
fn remove_ban_success() {
    let (_dir, store) = tmp_store();
    store.add_ban(&make_ban("192.168.1.1", "sshd")).unwrap();

    let removed = store
        .remove_ban("192.168.1.1".parse().unwrap(), "sshd")
        .unwrap();
    assert_eq!(removed.ip, "192.168.1.1".parse::<IpAddr>().unwrap());
    assert_eq!(removed.jail_name, "sshd");

    // Should be gone from active bans.
    let bans = store.get_bans(None).unwrap();
    assert!(bans.is_empty());

    // Should appear in history.
    let data = store.load().unwrap();
    assert_eq!(data.history.len(), 1);
    assert_eq!(data.history[0].ip, "192.168.1.1".parse::<IpAddr>().unwrap());
}

#[test]
fn remove_ban_not_found_returns_not_banned() {
    let (_dir, store) = tmp_store();
    let result = store.remove_ban("10.0.0.99".parse().unwrap(), "sshd");
    assert!(result.is_err());
    match result.unwrap_err() {
        crate::Error::NotBanned(ip) => assert_eq!(ip, "10.0.0.99"),
        other => panic!("expected NotBanned, got: {other:?}"),
    }
}

#[test]
fn remove_ban_wrong_jail_returns_not_banned() {
    let (_dir, store) = tmp_store();
    store.add_ban(&make_ban("192.168.1.1", "sshd")).unwrap();

    let result = store.remove_ban("192.168.1.1".parse().unwrap(), "nginx");
    assert!(result.is_err());
    match result.unwrap_err() {
        crate::Error::NotBanned(_) => {}
        other => panic!("expected NotBanned, got: {other:?}"),
    }

    // Original ban should still be active.
    let bans = store.get_bans(None).unwrap();
    assert_eq!(bans.len(), 1);
}

#[test]
fn remove_ban_same_ip_different_jail_only_removes_target() {
    let (_dir, store) = tmp_store();
    store.add_ban(&make_ban("192.168.1.1", "sshd")).unwrap();
    store.add_ban(&make_ban("192.168.1.1", "nginx")).unwrap();

    store
        .remove_ban("192.168.1.1".parse().unwrap(), "sshd")
        .unwrap();

    let bans = store.get_bans(None).unwrap();
    assert_eq!(bans.len(), 1);
    assert_eq!(bans[0].jail_name, "nginx");
}

// ---------------------------------------------------------------------------
// get_bans -- with and without jail filter
// ---------------------------------------------------------------------------

#[test]
fn get_bans_no_filter_returns_all() {
    let (_dir, store) = tmp_store();
    store.add_ban(&make_ban("10.0.0.1", "sshd")).unwrap();
    store.add_ban(&make_ban("10.0.0.2", "nginx")).unwrap();
    store.add_ban(&make_ban("10.0.0.3", "sshd")).unwrap();

    let bans = store.get_bans(None).unwrap();
    assert_eq!(bans.len(), 3);
}

#[test]
fn get_bans_filter_by_jail() {
    let (_dir, store) = tmp_store();
    store.add_ban(&make_ban("10.0.0.1", "sshd")).unwrap();
    store.add_ban(&make_ban("10.0.0.2", "nginx")).unwrap();
    store.add_ban(&make_ban("10.0.0.3", "sshd")).unwrap();

    let sshd_bans = store.get_bans(Some("sshd")).unwrap();
    assert_eq!(sshd_bans.len(), 2);
    for b in &sshd_bans {
        assert_eq!(b.jail_name, "sshd");
    }

    let nginx_bans = store.get_bans(Some("nginx")).unwrap();
    assert_eq!(nginx_bans.len(), 1);
    assert_eq!(nginx_bans[0].ip, "10.0.0.2".parse::<IpAddr>().unwrap());
}

#[test]
fn get_bans_filter_nonexistent_jail_returns_empty() {
    let (_dir, store) = tmp_store();
    store.add_ban(&make_ban("10.0.0.1", "sshd")).unwrap();

    let bans = store.get_bans(Some("dovecot")).unwrap();
    assert!(bans.is_empty());
}

#[test]
fn get_bans_empty_store() {
    let (_dir, store) = tmp_store();
    let bans = store.get_bans(None).unwrap();
    assert!(bans.is_empty());

    let bans = store.get_bans(Some("sshd")).unwrap();
    assert!(bans.is_empty());
}

// ---------------------------------------------------------------------------
// clear_expired
// ---------------------------------------------------------------------------

#[test]
fn clear_expired_moves_to_history() {
    let (_dir, store) = tmp_store();

    // Already expired.
    let past = Utc::now() - Duration::hours(1);
    store
        .add_ban(&make_ban_expiring("10.0.0.1", "sshd", Some(past)))
        .unwrap();

    // Not expired (future).
    let future = Utc::now() + Duration::hours(1);
    store
        .add_ban(&make_ban_expiring("10.0.0.2", "sshd", Some(future)))
        .unwrap();

    // No expiry at all -- should NOT be cleared.
    store
        .add_ban(&make_ban_expiring("10.0.0.3", "sshd", None))
        .unwrap();

    let cleared = store.clear_expired().unwrap();
    assert_eq!(cleared.len(), 1);
    assert_eq!(cleared[0].ip, "10.0.0.1".parse::<IpAddr>().unwrap());

    // Active bans: only the non-expired ones remain.
    let active = store.get_bans(None).unwrap();
    assert_eq!(active.len(), 2);

    // History: the expired ban was moved there.
    let data = store.load().unwrap();
    assert!(
        data.history
            .iter()
            .any(|b| b.ip == "10.0.0.1".parse::<IpAddr>().unwrap())
    );
}

#[test]
fn clear_expired_no_expired_bans() {
    let (_dir, store) = tmp_store();
    let future = Utc::now() + Duration::hours(1);
    store
        .add_ban(&make_ban_expiring("10.0.0.1", "sshd", Some(future)))
        .unwrap();

    let cleared = store.clear_expired().unwrap();
    assert!(cleared.is_empty());

    let active = store.get_bans(None).unwrap();
    assert_eq!(active.len(), 1);
}

#[test]
fn clear_expired_all_expired() {
    let (_dir, store) = tmp_store();
    let past = Utc::now() - Duration::minutes(30);
    store
        .add_ban(&make_ban_expiring("10.0.0.1", "sshd", Some(past)))
        .unwrap();
    store
        .add_ban(&make_ban_expiring("10.0.0.2", "nginx", Some(past)))
        .unwrap();

    let cleared = store.clear_expired().unwrap();
    assert_eq!(cleared.len(), 2);

    let active = store.get_bans(None).unwrap();
    assert!(active.is_empty());

    let data = store.load().unwrap();
    assert_eq!(data.history.len(), 2);
}

#[test]
fn clear_expired_empty_store() {
    let (_dir, store) = tmp_store();
    let cleared = store.clear_expired().unwrap();
    assert!(cleared.is_empty());
}

// ---------------------------------------------------------------------------
// update_journal -- upsert behavior
// ---------------------------------------------------------------------------

#[test]
fn update_journal_insert() {
    let (_dir, store) = tmp_store();
    let entry = make_journal("sshd", "/var/log/auth.log", 0, 0);

    store.update_journal(entry).unwrap();

    let loaded = store
        .get_journal("sshd", "/var/log/auth.log".as_ref())
        .unwrap();
    assert!(loaded.is_some());
    let loaded = loaded.unwrap();
    assert_eq!(loaded.jail_name, "sshd");
    assert_eq!(loaded.offset, 0);
    assert_eq!(loaded.line_number, 0);
}

#[test]
fn update_journal_upsert_updates_existing() {
    let (_dir, store) = tmp_store();

    let entry1 = make_journal("sshd", "/var/log/auth.log", 100, 5);
    store.update_journal(entry1).unwrap();

    let entry2 = make_journal("sshd", "/var/log/auth.log", 500, 25);
    store.update_journal(entry2).unwrap();

    let loaded = store
        .get_journal("sshd", "/var/log/auth.log".as_ref())
        .unwrap();
    let loaded = loaded.unwrap();
    assert_eq!(loaded.offset, 500);
    assert_eq!(loaded.line_number, 25);

    // Should not have created a duplicate.
    let data = store.load().unwrap();
    let matching = data
        .journals
        .iter()
        .filter(|j| j.jail_name == "sshd" && j.log_path.to_str() == Some("/var/log/auth.log"))
        .count();
    assert_eq!(matching, 1);
}

#[test]
fn update_journal_different_jails_inserted_separately() {
    let (_dir, store) = tmp_store();

    store
        .update_journal(make_journal("sshd", "/var/log/auth.log", 100, 5))
        .unwrap();
    store
        .update_journal(make_journal("nginx", "/var/log/nginx/access.log", 200, 10))
        .unwrap();

    let data = store.load().unwrap();
    assert_eq!(data.journals.len(), 2);
}

#[test]
fn update_journal_same_jail_different_logs_inserted_separately() {
    let (_dir, store) = tmp_store();

    store
        .update_journal(make_journal("sshd", "/var/log/auth.log", 100, 5))
        .unwrap();
    store
        .update_journal(make_journal("sshd", "/var/log/secure", 200, 10))
        .unwrap();

    let data = store.load().unwrap();
    assert_eq!(data.journals.len(), 2);
}

// ---------------------------------------------------------------------------
// get_journal
// ---------------------------------------------------------------------------

#[test]
fn get_journal_found() {
    let (_dir, store) = tmp_store();
    let entry = make_journal("sshd", "/var/log/auth.log", 42, 7);
    store.update_journal(entry).unwrap();

    let result = store
        .get_journal("sshd", "/var/log/auth.log".as_ref())
        .unwrap();
    assert!(result.is_some());
    assert_eq!(result.unwrap().offset, 42);
}

#[test]
fn get_journal_not_found() {
    let (_dir, store) = tmp_store();

    let result = store
        .get_journal("sshd", "/var/log/auth.log".as_ref())
        .unwrap();
    assert!(result.is_none());
}

#[test]
fn get_journal_wrong_jail() {
    let (_dir, store) = tmp_store();
    store
        .update_journal(make_journal("sshd", "/var/log/auth.log", 100, 5))
        .unwrap();

    let result = store
        .get_journal("nginx", "/var/log/auth.log".as_ref())
        .unwrap();
    assert!(result.is_none());
}

#[test]
fn get_journal_wrong_log_path() {
    let (_dir, store) = tmp_store();
    store
        .update_journal(make_journal("sshd", "/var/log/auth.log", 100, 5))
        .unwrap();

    let result = store
        .get_journal("sshd", "/var/log/other.log".as_ref())
        .unwrap();
    assert!(result.is_none());
}

// ---------------------------------------------------------------------------
// trim_history
// ---------------------------------------------------------------------------

#[test]
fn trim_history_keeps_most_recent() {
    let (_dir, store) = tmp_store();

    // Manually populate history with 5 entries.
    let entries: Vec<BanEntry> = (0..5)
        .map(|i| make_ban(&format!("10.0.0.{i}"), "sshd"))
        .collect();

    let data = StoreData {
        active_bans: vec![],
        history: entries,
        journals: vec![],
    };
    store.save(&data).unwrap();

    store.trim_history(3).unwrap();

    let loaded = store.load().unwrap();
    assert_eq!(loaded.history.len(), 3);
    // The kept entries should be the last 3 (10.0.0.2, 10.0.0.3, 10.0.0.4).
    assert_eq!(loaded.history[0].ip, "10.0.0.2".parse::<IpAddr>().unwrap());
    assert_eq!(loaded.history[1].ip, "10.0.0.3".parse::<IpAddr>().unwrap());
    assert_eq!(loaded.history[2].ip, "10.0.0.4".parse::<IpAddr>().unwrap());
}

#[test]
fn trim_history_under_limit_noop() {
    let (_dir, store) = tmp_store();

    let entries: Vec<BanEntry> = (0..3)
        .map(|i| make_ban(&format!("10.0.0.{i}"), "sshd"))
        .collect();

    let data = StoreData {
        active_bans: vec![],
        history: entries,
        journals: vec![],
    };
    store.save(&data).unwrap();

    store.trim_history(10).unwrap();

    let loaded = store.load().unwrap();
    assert_eq!(loaded.history.len(), 3);
}

#[test]
fn trim_history_exact_limit_noop() {
    let (_dir, store) = tmp_store();

    let entries: Vec<BanEntry> = (0..5)
        .map(|i| make_ban(&format!("10.0.0.{i}"), "sshd"))
        .collect();

    let data = StoreData {
        active_bans: vec![],
        history: entries,
        journals: vec![],
    };
    store.save(&data).unwrap();

    store.trim_history(5).unwrap();

    let loaded = store.load().unwrap();
    assert_eq!(loaded.history.len(), 5);
}

#[test]
fn trim_history_zero_max_removes_all() {
    let (_dir, store) = tmp_store();

    let entries: Vec<BanEntry> = (0..5)
        .map(|i| make_ban(&format!("10.0.0.{i}"), "sshd"))
        .collect();

    let data = StoreData {
        active_bans: vec![],
        history: entries,
        journals: vec![],
    };
    store.save(&data).unwrap();

    store.trim_history(0).unwrap();

    let loaded = store.load().unwrap();
    assert!(loaded.history.is_empty());
}

#[test]
fn trim_history_empty_history() {
    let (_dir, store) = tmp_store();
    store.trim_history(10).unwrap();

    let loaded = store.load().unwrap();
    assert!(loaded.history.is_empty());
}

// ---------------------------------------------------------------------------
// Atomic write behavior
// ---------------------------------------------------------------------------

#[test]
fn atomic_write_no_temp_file_left_behind() {
    let dir = tempdir().unwrap();
    let store_path = dir.path().join("store.json");
    let store = Store::new(store_path.clone());

    store.save(&StoreData::default()).unwrap();

    // The temp file (store.json.tmp) should have been renamed away.
    let tmp_path = store_path.with_extension("json.tmp");
    assert!(!tmp_path.exists());
    assert!(store_path.exists());
}

#[test]
fn atomic_write_data_is_consistent_after_rename() {
    let dir = tempdir().unwrap();
    let store = Store::new(dir.path().join("store.json"));

    // Write a batch of data.
    let data = StoreData {
        active_bans: (0..50)
            .map(|i| make_ban(&format!("10.0.{i}.1"), "sshd"))
            .collect(),
        history: (0..50)
            .map(|i| make_ban(&format!("10.1.{i}.1"), "nginx"))
            .collect(),
        journals: vec![make_journal("sshd", "/var/log/auth.log", 999, 42)],
    };
    store.save(&data).unwrap();

    // Read it back -- it must be complete and valid JSON.
    let loaded = store.load().unwrap();
    assert_eq!(loaded.active_bans.len(), 50);
    assert_eq!(loaded.history.len(), 50);
    assert_eq!(loaded.journals.len(), 1);
    assert_eq!(loaded.journals[0].offset, 999);
}

#[test]
fn atomic_write_overwrite_is_seamless() {
    let dir = tempdir().unwrap();
    let store = Store::new(dir.path().join("store.json"));

    // Write initial data.
    let data1 = StoreData {
        active_bans: vec![make_ban("10.0.0.1", "sshd")],
        history: vec![make_ban("10.0.0.2", "nginx")],
        journals: vec![make_journal("sshd", "/var/log/auth.log", 0, 0)],
    };
    store.save(&data1).unwrap();

    // Overwrite with completely different data.
    let data2 = StoreData {
        active_bans: vec![make_ban("192.168.0.1", "dovecot")],
        history: vec![],
        journals: vec![],
    };
    store.save(&data2).unwrap();

    let loaded = store.load().unwrap();
    assert_eq!(loaded.active_bans.len(), 1);
    assert_eq!(
        loaded.active_bans[0].ip,
        "192.168.0.1".parse::<IpAddr>().unwrap()
    );
    assert!(loaded.history.is_empty());
    assert!(loaded.journals.is_empty());
}

// ---------------------------------------------------------------------------
// Edge cases: empty store operations
// ---------------------------------------------------------------------------

#[test]
fn empty_store_get_bans_none() {
    let (_dir, store) = tmp_store();
    assert!(store.get_bans(None).unwrap().is_empty());
}

#[test]
fn empty_store_get_bans_some_jail() {
    let (_dir, store) = tmp_store();
    assert!(store.get_bans(Some("sshd")).unwrap().is_empty());
}

#[test]
fn empty_store_remove_ban_errors() {
    let (_dir, store) = tmp_store();
    assert!(matches!(
        store.remove_ban("1.2.3.4".parse().unwrap(), "sshd"),
        Err(crate::Error::NotBanned(_))
    ));
}

#[test]
fn empty_store_clear_expired_returns_empty() {
    let (_dir, store) = tmp_store();
    assert!(store.clear_expired().unwrap().is_empty());
}

#[test]
fn empty_store_get_journal_returns_none() {
    let (_dir, store) = tmp_store();
    assert!(
        store
            .get_journal("sshd", "/var/log/auth.log".as_ref())
            .unwrap()
            .is_none()
    );
}

// ---------------------------------------------------------------------------
// Edge cases: multiple bans same IP different jails
// ---------------------------------------------------------------------------

#[test]
fn multiple_jails_same_ip_independent_ban_lifecycle() {
    let (_dir, store) = tmp_store();

    store.add_ban(&make_ban("192.168.1.1", "sshd")).unwrap();
    store.add_ban(&make_ban("192.168.1.1", "nginx")).unwrap();
    store.add_ban(&make_ban("192.168.1.1", "dovecot")).unwrap();

    // Remove from one jail.
    store
        .remove_ban("192.168.1.1".parse().unwrap(), "nginx")
        .unwrap();

    let bans = store.get_bans(None).unwrap();
    assert_eq!(bans.len(), 2);

    let sshd_bans = store.get_bans(Some("sshd")).unwrap();
    assert_eq!(sshd_bans.len(), 1);

    let dovecot_bans = store.get_bans(Some("dovecot")).unwrap();
    assert_eq!(dovecot_bans.len(), 1);

    let nginx_bans = store.get_bans(Some("nginx")).unwrap();
    assert!(nginx_bans.is_empty());

    // Removing from nginx again should fail.
    assert!(matches!(
        store.remove_ban("192.168.1.1".parse().unwrap(), "nginx"),
        Err(crate::Error::NotBanned(_))
    ));
}

#[test]
fn multiple_jails_same_ip_clear_expired_only_clears_expired() {
    let (_dir, store) = tmp_store();

    let past = Utc::now() - Duration::hours(1);
    let future = Utc::now() + Duration::hours(1);

    store
        .add_ban(&make_ban_expiring("192.168.1.1", "sshd", Some(past)))
        .unwrap();
    store
        .add_ban(&make_ban_expiring("192.168.1.1", "nginx", Some(future)))
        .unwrap();

    let cleared = store.clear_expired().unwrap();
    assert_eq!(cleared.len(), 1);
    assert_eq!(cleared[0].jail_name, "sshd");

    let active = store.get_bans(None).unwrap();
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].jail_name, "nginx");
}

// ---------------------------------------------------------------------------
// Edge cases: expired vs non-expired boundary
// ---------------------------------------------------------------------------

#[test]
fn clear_expired_ban_expiring_exactly_now_is_cleared() {
    let (_dir, store) = tmp_store();

    // Use a timestamp slightly in the past to avoid clock skew issues.
    let exactly_now = Utc::now() - Duration::milliseconds(1);
    store
        .add_ban(&make_ban_expiring("10.0.0.1", "sshd", Some(exactly_now)))
        .unwrap();

    let cleared = store.clear_expired().unwrap();
    assert_eq!(cleared.len(), 1);
}

#[test]
fn clear_expired_ban_without_expiry_never_cleared() {
    let (_dir, store) = tmp_store();

    store
        .add_ban(&make_ban_expiring("10.0.0.1", "sshd", None))
        .unwrap();

    let cleared = store.clear_expired().unwrap();
    assert!(cleared.is_empty());

    let active = store.get_bans(None).unwrap();
    assert_eq!(active.len(), 1);
}

// ---------------------------------------------------------------------------
// Edge case: zero max_history
// ---------------------------------------------------------------------------

#[test]
fn trim_history_zero_clears_all_history() {
    let (_dir, store) = tmp_store();

    let data = StoreData {
        active_bans: vec![],
        history: vec![
            make_ban("10.0.0.1", "sshd"),
            make_ban("10.0.0.2", "sshd"),
            make_ban("10.0.0.3", "sshd"),
        ],
        journals: vec![],
    };
    store.save(&data).unwrap();

    store.trim_history(0).unwrap();

    let loaded = store.load().unwrap();
    assert!(loaded.history.is_empty());
}

// ---------------------------------------------------------------------------
// Corrupt file handling
// ---------------------------------------------------------------------------

#[test]
fn load_corrupt_json_returns_error() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("store.json");
    std::fs::write(&path, "this is not valid json {{{").unwrap();

    let store = Store::new(path);
    let result = store.load();
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// Integration: full lifecycle
// ---------------------------------------------------------------------------

#[test]
fn full_lifecycle_ban_remove_clear_trim() {
    let (_dir, store) = tmp_store();

    // 1. Ban several IPs.
    for i in 0..10 {
        store
            .add_ban(&make_ban(&format!("10.0.0.{i}"), "sshd"))
            .unwrap();
    }
    assert_eq!(store.get_bans(None).unwrap().len(), 10);

    // 2. Remove some bans -- they move to history.
    for i in 0..5 {
        store
            .remove_ban(format!("10.0.0.{i}").parse().unwrap(), "sshd")
            .unwrap();
    }
    assert_eq!(store.get_bans(None).unwrap().len(), 5);

    let data = store.load().unwrap();
    assert_eq!(data.history.len(), 5);

    // 3. Trim history to 2.
    store.trim_history(2).unwrap();

    let data = store.load().unwrap();
    assert_eq!(data.history.len(), 2);
    // The kept entries are the last 2 of the 5 removed (i=3 and i=4).
    assert!(data.history.iter().all(|b| {
        let ip = b.ip.to_string();
        ip == "10.0.0.3" || ip == "10.0.0.4"
    }));
}

#[test]
fn full_lifecycle_with_journals() {
    let (_dir, store) = tmp_store();

    // Update journals for two jails.
    store
        .update_journal(make_journal("sshd", "/var/log/auth.log", 0, 0))
        .unwrap();
    store
        .update_journal(make_journal("nginx", "/var/log/nginx/access.log", 0, 0))
        .unwrap();

    // Simulate scanning: advance journal positions.
    store
        .update_journal(make_journal("sshd", "/var/log/auth.log", 4096, 100))
        .unwrap();
    store
        .update_journal(make_journal(
            "nginx",
            "/var/log/nginx/access.log",
            8192,
            200,
        ))
        .unwrap();

    let sshd = store
        .get_journal("sshd", "/var/log/auth.log".as_ref())
        .unwrap()
        .unwrap();
    assert_eq!(sshd.offset, 4096);
    assert_eq!(sshd.line_number, 100);

    let nginx = store
        .get_journal("nginx", "/var/log/nginx/access.log".as_ref())
        .unwrap()
        .unwrap();
    assert_eq!(nginx.offset, 8192);
    assert_eq!(nginx.line_number, 200);
}

// ---------------------------------------------------------------------------
// Edge case: non-UTF-8 file content
// ---------------------------------------------------------------------------

#[test]
fn load_with_non_utf8_content() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("store.json");

    // Write raw binary bytes that are not valid UTF-8 (lone continuation bytes).
    std::fs::write(&path, [0xFF, 0xFE, 0x80, 0x81, 0x00]).unwrap();

    let store = Store::new(path);
    let result = store.load();
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// Edge case: malformed IP string via IpAddr parse
// ---------------------------------------------------------------------------

#[test]
fn remove_ban_with_malformed_ip() {
    let malformed = &[
        "",
        "not-an-ip",
        "999.999.999.999",
        ":::1",
        "10.0.0.1/24",
        "localhost",
    ];

    for bad in malformed {
        let result: std::result::Result<IpAddr, _> = bad.parse();
        assert!(
            result.is_err(),
            "expected parse error for '{bad}', got Ok({result:?})"
        );
    }
}

// ---------------------------------------------------------------------------
// Edge case: very long jail name
// ---------------------------------------------------------------------------

#[test]
fn add_ban_with_very_long_jail_name() {
    let (_dir, store) = tmp_store();

    let long_name = "a".repeat(1000);
    let entry = BanEntry {
        ip: "10.0.0.1".parse().unwrap(),
        prefix: 32,
        banned_at: Utc::now(),
        expires_at: None,
        jail_name: long_name.clone(),
        fail_count: 1,
        last_fail_at: Utc::now(),
        reason: None,
    };
    store.add_ban(&entry).unwrap();

    let bans = store.get_bans(Some(&long_name)).unwrap();
    assert_eq!(bans.len(), 1);
    assert_eq!(bans[0].jail_name, long_name);
    assert_eq!(bans[0].ip, "10.0.0.1".parse::<IpAddr>().unwrap());
}

// ---------------------------------------------------------------------------
// Edge case: unicode jail name
// ---------------------------------------------------------------------------

#[test]
fn add_ban_with_unicode_jail_name() {
    let (_dir, store) = tmp_store();

    let entry = BanEntry {
        ip: "10.0.0.1".parse().unwrap(),
        prefix: 32,
        banned_at: Utc::now(),
        expires_at: None,
        jail_name: "测试监狱".to_string(),
        fail_count: 1,
        last_fail_at: Utc::now(),
        reason: None,
    };
    store.add_ban(&entry).unwrap();

    let bans = store.get_bans(Some("测试监狱")).unwrap();
    assert_eq!(bans.len(), 1);
    assert_eq!(bans[0].jail_name, "测试监狱");
}

// ---------------------------------------------------------------------------
// Edge case: large dataset (500 bans)
// ---------------------------------------------------------------------------

#[test]
fn get_bans_large_dataset() {
    let (_dir, store) = tmp_store();

    for i in 0..500 {
        let ip = format!("10.{}.{}.{}", (i >> 16) & 0xFF, (i >> 8) & 0xFF, i & 0xFF);
        store.add_ban(&make_ban(&ip, "sshd")).unwrap();
    }

    let bans = store.get_bans(None).unwrap();
    assert_eq!(bans.len(), 500, "should retrieve all 500 bans");
}

// ---------------------------------------------------------------------------
// Edge case: clear_expired with expires_at exactly == now
// ---------------------------------------------------------------------------

#[test]
fn clear_expired_boundary_exactly_now() {
    let (_dir, store) = tmp_store();

    // An entry whose expires_at is set to Utc::now() should be cleared
    // because the check is exp <= now.
    store
        .add_ban(&make_ban_expiring("10.0.0.1", "sshd", Some(Utc::now())))
        .unwrap();

    let cleared = store.clear_expired().unwrap();
    assert_eq!(
        cleared.len(),
        1,
        "ban expiring exactly now should be cleared"
    );
    assert_eq!(cleared[0].ip, "10.0.0.1".parse::<IpAddr>().unwrap());

    let active = store.get_bans(None).unwrap();
    assert!(active.is_empty(), "no active bans should remain");
}

// ---------------------------------------------------------------------------
// Edge case: save/load preserves timestamp nanosecond precision
// ---------------------------------------------------------------------------

#[test]
fn save_load_preserves_timestamps_precision() {
    let (_dir, store) = tmp_store();

    // Create a ban with a specific nanosecond-precision timestamp.
    let ts = DateTime::parse_from_rfc3339("2026-05-30T12:34:56.123456789Z")
        .unwrap()
        .with_timezone(&Utc);
    let entry = BanEntry {
        ip: "10.0.0.1".parse().unwrap(),
        prefix: 32,
        banned_at: ts,
        expires_at: Some(ts + Duration::seconds(3600)),
        jail_name: "sshd".to_string(),
        fail_count: 1,
        last_fail_at: ts,
        reason: Some("precision test".to_string()),
    };

    let data = StoreData {
        active_bans: vec![entry],
        history: vec![],
        journals: vec![],
    };
    store.save(&data).unwrap();

    let loaded = store.load().unwrap();
    assert_eq!(loaded.active_bans.len(), 1);
    assert_eq!(
        loaded.active_bans[0].banned_at, ts,
        "banned_at timestamp must survive save/load round-trip"
    );
    assert_eq!(
        loaded.active_bans[0].last_fail_at, ts,
        "last_fail_at timestamp must survive save/load round-trip"
    );
    assert_eq!(
        loaded.active_bans[0].expires_at.unwrap(),
        ts + Duration::seconds(3600),
        "expires_at timestamp must survive save/load round-trip"
    );
}

// ---------------------------------------------------------------------------
// Edge case: journal entry with empty jail name
// ---------------------------------------------------------------------------

#[test]
fn journal_entry_with_empty_jail_name() {
    let (_dir, store) = tmp_store();

    let entry = JournalEntry {
        jail_name: String::new(),
        log_path: "/var/log/auth.log".into(),
        offset: 0,
        line_number: 0,
        updated_at: Utc::now(),
    };
    store.update_journal(entry).unwrap();

    let loaded = store.get_journal("", "/var/log/auth.log".as_ref()).unwrap();
    assert!(
        loaded.is_some(),
        "journal with empty jail name should persist"
    );
    assert_eq!(loaded.unwrap().jail_name, "");
}
