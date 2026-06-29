//! Comprehensive tests for the ini module.
//!
//! Covers IniManager construction, path helpers, write/remove/read operations,
//! managed-header detection, list_managed, backups, atomic writes, and error
//! conditions. All file-system tests use `tempfile::tempdir()` for isolation.

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::fs;
    use std::path::Path;
    use std::str::FromStr;

    use crate::Error;
    use crate::ini::{DEFAULT_NAMESPACE, IniManager, ManagedFile, ManagedFileKind};
    use crate::render;
    use crate::spec::*;

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /// Create a temporary directory with the Fail2Ban config tree layout:
    /// `{root}/jail.d/`, `{root}/filter.d/`, `{root}/action.d/`.
    fn setup_config_dir() -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::create_dir_all(dir.path().join("jail.d")).expect("jail.d");
        fs::create_dir_all(dir.path().join("filter.d")).expect("filter.d");
        fs::create_dir_all(dir.path().join("action.d")).expect("action.d");
        dir
    }

    /// Create a manager from a temp config dir using the default namespace.
    fn manager(dir: &tempfile::TempDir) -> IniManager {
        IniManager::new(dir.path()).expect("IniManager::new")
    }

    /// Create a manager from a temp config dir with a custom namespace.
    fn manager_ns(dir: &tempfile::TempDir, ns: &str) -> IniManager {
        IniManager::with_namespace(dir.path(), ns).expect("IniManager::with_namespace")
    }

    /// Build a minimal JailSpec for testing.
    fn make_jail(name: &str) -> JailSpec {
        JailSpec::builder()
            .name(JailName::new(name).unwrap())
            .filter(
                FilterSpec::builder()
                    .name(FilterName::new("test-filter").unwrap())
                    .failregex(vec![RegexLine::new("^fail <HOST>$").unwrap()])
                    .build(),
            )
            .bantime(DurationSpec::new("10m").unwrap())
            .findtime(DurationSpec::new("10m").unwrap())
            .log_paths(vec![LogPath::new(Path::new("/tmp/auth.log")).unwrap()])
            .build()
    }

    /// Build a minimal FilterSpec for testing.
    fn make_filter(name: &str) -> FilterSpec {
        FilterSpec::builder()
            .name(FilterName::new(name).unwrap())
            .failregex(vec![
                RegexLine::new("^Authentication failure <HOST>$").unwrap(),
            ])
            .build()
    }

    /// Build a minimal ActionSpec for testing.
    fn make_action(name: &str) -> ActionSpec {
        ActionSpec::builder()
            .name(ActionName::new(name).unwrap())
            .kind(ActionKind::Custom)
            .actionban(Some("/usr/bin/ban <ip>".into()))
            .build()
    }

    /// Write a file without the managed header (simulates a stock / human-edited file).
    fn write_unmanaged_file(path: &Path, content: &str) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create parent");
        }
        fs::write(path, content).expect("write unmanaged file");
    }

    // =======================================================================
    // Constructor tests
    // =======================================================================

    #[test]
    fn new_with_valid_directory() {
        let dir = setup_config_dir();
        let mgr = IniManager::new(dir.path());
        assert!(mgr.is_ok(), "IniManager::new should succeed with valid dir");
    }

    #[test]
    fn new_rejects_nonexistent_directory() {
        let err = IniManager::new(Path::new("/no/such/directory/fail2ban"));
        assert!(err.is_err(), "should reject nonexistent directory");
        let msg = format!("{err:?}");
        assert!(
            msg.contains("does not exist"),
            "error should mention nonexistent: {msg}"
        );
    }

    #[test]
    fn new_rejects_file_instead_of_directory() {
        let file = tempfile::NamedTempFile::new().expect("tempfile");
        let err = IniManager::new(file.path());
        assert!(err.is_err(), "should reject a plain file as config dir");
    }

    #[test]
    fn with_namespace_custom() {
        let dir = setup_config_dir();
        let mgr = IniManager::with_namespace(dir.path(), "myns").unwrap();
        // Verify namespace is used in path generation.
        let p = mgr.jail_path("test");
        assert!(
            p.to_str().unwrap().contains("myns-test.local"),
            "path should use custom namespace: {:?}",
            p
        );
    }

    #[test]
    fn with_namespace_rejects_empty_namespace() {
        // An empty namespace is technically accepted but produces paths like
        // `{jail_d}/-.local`. The constructor does not validate namespace;
        // verify that the path is produced (no crash).
        let dir = setup_config_dir();
        let mgr = IniManager::with_namespace(dir.path(), "").unwrap();
        let p = mgr.jail_path("test");
        assert!(p.to_str().unwrap().contains("-test.local"));
    }

    // =======================================================================
    // Path helpers
    // =======================================================================

    #[test]
    fn jail_path_uses_namespace_and_name() {
        let dir = setup_config_dir();
        let mgr = manager(&dir);
        let p = mgr.jail_path("myapp");
        let expected = dir
            .path()
            .join("jail.d")
            .join(format!("{DEFAULT_NAMESPACE}-myapp.local"));
        assert_eq!(p, expected);
    }

    #[test]
    fn filter_path_uses_namespace_and_name() {
        let dir = setup_config_dir();
        let mgr = manager(&dir);
        let p = mgr.filter_path("nginx-auth");
        let expected = dir
            .path()
            .join("filter.d")
            .join(format!("{DEFAULT_NAMESPACE}-nginx-auth.local"));
        assert_eq!(p, expected);
    }

    #[test]
    fn action_path_uses_namespace_and_name() {
        let dir = setup_config_dir();
        let mgr = manager(&dir);
        let p = mgr.action_path("my-hook");
        let expected = dir
            .path()
            .join("action.d")
            .join(format!("{DEFAULT_NAMESPACE}-my-hook.local"));
        assert_eq!(p, expected);
    }

    #[test]
    fn path_helpers_with_custom_namespace() {
        let dir = setup_config_dir();
        let mgr = manager_ns(&dir, "ns");
        assert_eq!(mgr.jail_path("x"), dir.path().join("jail.d/ns-x.local"));
        assert_eq!(mgr.filter_path("y"), dir.path().join("filter.d/ns-y.local"));
        assert_eq!(mgr.action_path("z"), dir.path().join("action.d/ns-z.local"));
    }

    #[test]
    fn backup_path_includes_bak_and_timestamp() {
        let dir = setup_config_dir();
        let mgr = manager(&dir);
        let original = dir.path().join("jail.d/test.conf");
        let backup = mgr.backup_path(&original);

        let backup_str = backup.to_str().unwrap();
        assert!(
            backup_str.contains(".bak-"),
            "backup path should contain '.bak-': {backup_str}"
        );
        // Timestamp format is YYYYMMDDTHHMMSS.mmm (millisecond precision)
        let bak_suffix = backup_str.split(".bak-").nth(1).unwrap();
        assert!(
            bak_suffix.len() == 19,
            "timestamp should be 19 chars (YYYYMMDDTHHMMSS.mmm): {bak_suffix}"
        );
        assert!(
            bak_suffix.contains('T'),
            "timestamp should contain T separator: {bak_suffix}"
        );
    }

    // =======================================================================
    // Write operations -- jail
    // =======================================================================

    #[test]
    fn write_jail_creates_file_with_managed_header() {
        let dir = setup_config_dir();
        let mgr = manager(&dir);

        let jail = make_jail("myapp");
        let report = mgr.write_jail(&jail).expect("write_jail");

        // File should exist and start with managed header.
        let path = mgr.jail_path("myapp");
        assert!(path.exists(), "jail file should be created");

        let content = fs::read_to_string(&path).unwrap();
        assert!(
            content.starts_with(render::managed_header().trim_end()),
            "file should start with managed header"
        );
        assert!(content.contains("[myapp]"));
        assert!(content.contains("enabled = true"));
        assert!(content.contains("bantime = 10m"));

        // Report should list the written file.
        assert_eq!(report.files_written.len(), 1);
        assert!(report.files_written[0].contains("myapp"));
        // First write: no backup.
        assert!(report.backup_paths.is_empty());
    }

    #[test]
    fn write_jail_creates_backup_of_existing_file() {
        let dir = setup_config_dir();
        let mgr = manager(&dir);

        // Write once.
        let jail = make_jail("myapp");
        mgr.write_jail(&jail).expect("first write");

        // Write again (overwrite).
        let report = mgr.write_jail(&jail).expect("second write");

        // Should have created a backup.
        assert_eq!(report.backup_paths.len(), 1, "should create one backup");
        let backup_path = &report.backup_paths[0];
        assert!(
            backup_path.contains(".bak-"),
            "backup path should contain .bak-: {backup_path}"
        );

        // Backup should exist and have content.
        let backup_content = fs::read_to_string(backup_path).unwrap();
        assert!(
            backup_content.contains("[myapp]"),
            "backup should contain original content"
        );
    }

    #[test]
    fn write_jail_rejects_overwriting_unmanaged_file() {
        let dir = setup_config_dir();
        let mgr = manager(&dir);

        // Create an unmanaged file at the target path.
        let path = mgr.jail_path("myapp");
        write_unmanaged_file(&path, "[myapp]\nenabled = true\n");

        let jail = make_jail("myapp");
        let result = mgr.write_jail(&jail);

        assert!(result.is_err(), "should refuse to overwrite unmanaged file");
        let msg = format!("{result:?}");
        assert!(
            msg.contains("refusing to overwrite unmanaged"),
            "error message should explain refusal: {msg}"
        );

        // Original file should be unchanged.
        let content = fs::read_to_string(&path).unwrap();
        assert!(
            !content.contains("Managed by fail2ban-kit"),
            "unmanaged file should not be modified"
        );
    }

    // =======================================================================
    // Write operations -- filter
    // =======================================================================

    #[test]
    fn write_filter_creates_file_with_managed_header() {
        let dir = setup_config_dir();
        let mgr = manager(&dir);

        let filter = make_filter("nginx-auth");
        let report = mgr.write_filter(&filter).expect("write_filter");

        let path = mgr.filter_path("nginx-auth");
        assert!(path.exists(), "filter file should be created");

        let content = fs::read_to_string(&path).unwrap();
        assert!(content.starts_with(render::managed_header().trim_end()));
        assert!(content.contains("[nginx-auth]"));
        assert!(content.contains("failregex"));

        assert_eq!(report.files_written.len(), 1);
    }

    // =======================================================================
    // Write operations -- action
    // =======================================================================

    #[test]
    fn write_action_creates_file_with_managed_header() {
        let dir = setup_config_dir();
        let mgr = manager(&dir);

        let action = make_action("my-hook");
        let report = mgr.write_action(&action).expect("write_action");

        let path = mgr.action_path("my-hook");
        assert!(path.exists(), "action file should be created");

        let content = fs::read_to_string(&path).unwrap();
        assert!(content.starts_with(render::managed_header().trim_end()));
        assert!(content.contains("[my-hook]"));
        assert!(content.contains("actionban"));

        assert_eq!(report.files_written.len(), 1);
    }

    // =======================================================================
    // Write creates subdirectories automatically
    // =======================================================================

    #[test]
    fn write_creates_subdirectories_if_missing() {
        // Create a temp dir without the jail.d subdirectory.
        let dir = tempfile::tempdir().expect("tempdir");
        fs::create_dir_all(dir.path().join("filter.d")).expect("filter.d");
        fs::create_dir_all(dir.path().join("action.d")).expect("action.d");
        // jail.d is intentionally omitted.

        let mgr = IniManager::new(dir.path()).expect("IniManager::new");
        let jail = make_jail("auto-dir");
        let report = mgr.write_jail(&jail).expect("write_jail should create dir");

        let path = mgr.jail_path("auto-dir");
        assert!(
            path.exists(),
            "file should be created even if jail.d was missing"
        );
        assert_eq!(report.files_written.len(), 1);
    }

    // =======================================================================
    // Remove operations
    // =======================================================================

    #[test]
    fn remove_jail_removes_managed_file() {
        let dir = setup_config_dir();
        let mgr = manager(&dir);

        let jail = make_jail("myapp");
        mgr.write_jail(&jail).expect("write");
        let path = mgr.jail_path("myapp");
        assert!(path.exists(), "file should exist after write");

        let report = mgr.remove_jail("myapp").expect("remove_jail");

        assert!(!path.exists(), "file should be removed");
        assert_eq!(report.files_removed.len(), 1);
        assert!(report.files_removed[0].contains("myapp"));

        // Backup should have been created.
        assert_eq!(report.backup_paths.len(), 1);
        let backup = &report.backup_paths[0];
        assert!(Path::new(backup).exists(), "backup file should exist");
    }

    #[test]
    fn remove_jail_refuses_unmanaged_file() {
        let dir = setup_config_dir();
        let mgr = manager(&dir);

        let path = mgr.jail_path("stock-jail");
        write_unmanaged_file(&path, "[stock]\nenabled = true\n");

        let result = mgr.remove_jail("stock-jail");
        assert!(result.is_err(), "should refuse to remove unmanaged file");
        assert!(
            path.exists(),
            "unmanaged file should still exist after refusal"
        );
    }

    #[test]
    fn remove_jail_returns_not_found_for_missing_file() {
        let dir = setup_config_dir();
        let mgr = manager(&dir);

        let result = mgr.remove_jail("nonexistent");
        assert!(result.is_err(), "should return error for missing file");
        let msg = format!("{result:?}");
        assert!(
            msg.contains("does not exist"),
            "error should mention file does not exist: {msg}"
        );
    }

    #[test]
    fn remove_filter_removes_managed_file() {
        let dir = setup_config_dir();
        let mgr = manager(&dir);

        let filter = make_filter("myfilter");
        mgr.write_filter(&filter).expect("write_filter");
        let path = mgr.filter_path("myfilter");
        assert!(path.exists());

        let report = mgr.remove_filter("myfilter").expect("remove_filter");
        assert!(!path.exists());
        assert_eq!(report.files_removed.len(), 1);
    }

    #[test]
    fn remove_action_removes_managed_file() {
        let dir = setup_config_dir();
        let mgr = manager(&dir);

        let action = make_action("myaction");
        mgr.write_action(&action).expect("write_action");
        let path = mgr.action_path("myaction");
        assert!(path.exists());

        let report = mgr.remove_action("myaction").expect("remove_action");
        assert!(!path.exists());
        assert_eq!(report.files_removed.len(), 1);
    }

    // =======================================================================
    // list_managed
    // =======================================================================

    #[test]
    fn list_managed_finds_managed_files() {
        let dir = setup_config_dir();
        let mgr = manager(&dir);

        // Write a jail and a filter.
        mgr.write_jail(&make_jail("app1")).expect("write jail");
        mgr.write_filter(&make_filter("auth"))
            .expect("write filter");

        let managed = mgr.list_managed().expect("list_managed");
        assert_eq!(managed.len(), 2, "should find exactly 2 managed files");

        // Check kinds.
        let kinds: Vec<&ManagedFileKind> = managed.iter().map(|f| &f.kind).collect();
        assert!(kinds.contains(&&ManagedFileKind::Jail));
        assert!(kinds.contains(&&ManagedFileKind::Filter));
    }

    #[test]
    fn list_managed_excludes_unmanaged_files() {
        let dir = setup_config_dir();
        let mgr = manager(&dir);

        // Write a managed jail.
        mgr.write_jail(&make_jail("managed")).expect("write");

        // Write an unmanaged file in jail.d.
        write_unmanaged_file(
            &dir.path().join("jail.d/stock.conf"),
            "[stock]\nenabled = true\n",
        );

        let managed = mgr.list_managed().expect("list_managed");
        assert_eq!(managed.len(), 1, "should only find the managed file");
        assert_eq!(managed[0].name, "managed");
    }

    #[test]
    fn list_managed_excludes_wrong_namespace() {
        let dir = setup_config_dir();

        // Write a file with namespace "other-ns".
        let mgr1 = manager_ns(&dir, "other-ns");
        mgr1.write_jail(&make_jail("other-app")).expect("write");

        // List with default namespace -- should not find it.
        let mgr2 = manager(&dir);
        let managed = mgr2.list_managed().expect("list_managed");
        assert!(
            managed.is_empty(),
            "should not find files from a different namespace"
        );
    }

    #[test]
    fn list_managed_returns_empty_for_empty_dirs() {
        let dir = setup_config_dir();
        let mgr = manager(&dir);
        let managed = mgr.list_managed().expect("list_managed");
        assert!(managed.is_empty());
    }

    #[test]
    fn list_managed_extracts_name_correctly() {
        let dir = setup_config_dir();
        let mgr = manager(&dir);

        mgr.write_jail(&make_jail("my-jail")).expect("write");
        mgr.write_filter(&make_filter("my-filter"))
            .expect("write filter");
        mgr.write_action(&make_action("my-action"))
            .expect("write action");

        let managed = mgr.list_managed().expect("list_managed");
        assert_eq!(managed.len(), 3);

        let names: Vec<&str> = managed.iter().map(|f| f.name.as_str()).collect();
        assert!(names.contains(&"my-jail"));
        assert!(names.contains(&"my-filter"));
        assert!(names.contains(&"my-action"));
    }

    #[test]
    fn list_managed_results_sorted_by_path() {
        let dir = setup_config_dir();
        let mgr = manager(&dir);

        mgr.write_action(&make_action("zzz-last"))
            .expect("write action");
        mgr.write_jail(&make_jail("aaa-first")).expect("write jail");

        let managed = mgr.list_managed().expect("list_managed");
        // action.d comes before jail.d alphabetically, so action should be first.
        assert!(
            managed[0].kind == ManagedFileKind::Action,
            "action.d/a* should sort before jail.d/z*"
        );
    }

    #[test]
    fn list_managed_tolerates_missing_subdirs() {
        // Create a config dir with only jail.d (filter.d and action.d missing).
        let dir = tempfile::tempdir().expect("tempdir");
        fs::create_dir_all(dir.path().join("jail.d")).expect("jail.d");
        // filter.d and action.d intentionally omitted.

        let mgr = IniManager::new(dir.path()).expect("IniManager::new");
        let managed = mgr.list_managed().expect("list_managed");
        assert!(managed.is_empty(), "should not error on missing subdirs");
    }

    // =======================================================================
    // has_managed_header
    // =======================================================================

    #[test]
    fn has_managed_header_true_for_managed_file() {
        let dir = setup_config_dir();
        let mgr = manager(&dir);

        mgr.write_jail(&make_jail("test")).expect("write");
        let path = mgr.jail_path("test");
        assert!(mgr.has_managed_header(&path).expect("has_managed_header"));
    }

    #[test]
    fn has_managed_header_false_for_unmanaged_file() {
        let dir = setup_config_dir();
        let mgr = manager(&dir);

        let path = dir.path().join("jail.d/unmanaged.conf");
        write_unmanaged_file(&path, "[myapp]\nenabled = true\n");
        assert!(!mgr.has_managed_header(&path).expect("has_managed_header"));
    }

    #[test]
    fn has_managed_header_false_for_nonexistent_file() {
        let dir = setup_config_dir();
        let mgr = manager(&dir);

        let path = dir.path().join("jail.d/no-such-file.conf");
        assert!(!mgr.has_managed_header(&path).expect("has_managed_header"));
    }

    // =======================================================================
    // Read operations
    // =======================================================================

    #[test]
    fn read_jail_returns_written_content() {
        let dir = setup_config_dir();
        let mgr = manager(&dir);

        let jail = make_jail("myapp");
        mgr.write_jail(&jail).expect("write");

        let content = mgr.read_jail("myapp").expect("read_jail");
        assert!(content.contains("[myapp]"));
        assert!(content.contains("enabled = true"));
        assert!(content.contains("bantime = 10m"));
    }

    #[test]
    fn read_jail_returns_error_for_missing() {
        let dir = setup_config_dir();
        let mgr = manager(&dir);

        let result = mgr.read_jail("nonexistent");
        assert!(result.is_err());
    }

    #[test]
    fn read_filter_returns_written_content() {
        let dir = setup_config_dir();
        let mgr = manager(&dir);

        let filter = make_filter("nginx-auth");
        mgr.write_filter(&filter).expect("write");

        let content = mgr.read_filter("nginx-auth").expect("read_filter");
        assert!(content.contains("[nginx-auth]"));
        assert!(content.contains("failregex"));
    }

    #[test]
    fn read_filter_returns_error_for_missing() {
        let dir = setup_config_dir();
        let mgr = manager(&dir);

        let result = mgr.read_filter("nope");
        assert!(result.is_err());
    }

    #[test]
    fn read_action_returns_written_content() {
        let dir = setup_config_dir();
        let mgr = manager(&dir);

        let action = make_action("hook");
        mgr.write_action(&action).expect("write");

        let content = mgr.read_action("hook").expect("read_action");
        assert!(content.contains("[hook]"));
        assert!(content.contains("actionban"));
    }

    #[test]
    fn read_action_returns_error_for_missing() {
        let dir = setup_config_dir();
        let mgr = manager(&dir);

        let result = mgr.read_action("gone");
        assert!(result.is_err());
    }

    // =======================================================================
    // ApplyReport fields
    // =======================================================================

    #[test]
    fn apply_report_fields_on_write() {
        let dir = setup_config_dir();
        let mgr = manager(&dir);

        let jail = make_jail("report-test");
        let report = mgr.write_jail(&jail).expect("write");

        // First write: files_written has one entry, no backups, no files_removed.
        assert_eq!(report.files_written.len(), 1);
        assert!(report.files_removed.is_empty());
        assert!(report.backup_paths.is_empty());
        assert!(report.test_passed);
        assert!(report.reload_result.is_none());
        assert!(report.findings.is_empty());
    }

    #[test]
    fn apply_report_fields_on_overwrite() {
        let dir = setup_config_dir();
        let mgr = manager(&dir);

        let jail = make_jail("overwrite-test");
        mgr.write_jail(&jail).expect("first write");

        // Modify the jail slightly.
        let jail_v2 = JailSpec::builder()
            .name(JailName::new("overwrite-test").unwrap())
            .filter(
                FilterSpec::builder()
                    .name(FilterName::new("f").unwrap())
                    .failregex(vec![RegexLine::new("^fail <HOST>$").unwrap()])
                    .build(),
            )
            .bantime(DurationSpec::new("1h").unwrap())
            .findtime(DurationSpec::new("30m").unwrap())
            .log_paths(vec![LogPath::new(Path::new("/tmp/auth.log")).unwrap()])
            .build();

        let report = mgr.write_jail(&jail_v2).expect("overwrite");

        assert_eq!(report.files_written.len(), 1);
        assert_eq!(report.backup_paths.len(), 1, "should have one backup");
        assert!(report.files_removed.is_empty());

        // Verify the new content is on disk.
        let content = mgr.read_jail("overwrite-test").expect("read");
        assert!(content.contains("bantime = 1h"));
        assert!(content.contains("findtime = 30m"));
    }

    #[test]
    fn apply_report_fields_on_remove() {
        let dir = setup_config_dir();
        let mgr = manager(&dir);

        mgr.write_jail(&make_jail("removal")).expect("write");
        let report = mgr.remove_jail("removal").expect("remove");

        assert!(report.files_written.is_empty());
        assert_eq!(report.files_removed.len(), 1);
        assert_eq!(report.backup_paths.len(), 1);
        assert!(report.files_removed[0].contains("removal"));
        assert!(report.backup_paths[0].contains(".bak-"));
    }

    // =======================================================================
    // Atomic write: file is complete or unchanged
    // =======================================================================

    #[test]
    fn atomic_write_produces_complete_file() {
        let dir = setup_config_dir();
        let mgr = manager(&dir);

        let jail = JailSpec::builder()
            .name(JailName::new("atomic").unwrap())
            .filter(
                FilterSpec::builder()
                    .name(FilterName::new("f").unwrap())
                    .failregex(vec![RegexLine::new("^fail <HOST>$").unwrap()])
                    .build(),
            )
            .bantime(DurationSpec::new("10m").unwrap())
            .findtime(DurationSpec::new("10m").unwrap())
            .log_paths(vec![LogPath::new(Path::new("/tmp/auth.log")).unwrap()])
            .build();

        mgr.write_jail(&jail).expect("write");

        let path = mgr.jail_path("atomic");
        let content = fs::read_to_string(&path).unwrap();

        // The file should end with a newline (complete write).
        assert!(
            content.ends_with('\n'),
            "atomically written file should be complete (ends with newline)"
        );

        // Content should contain all expected sections.
        assert!(content.contains("[atomic]"));
        assert!(content.contains("enabled = true"));
        assert!(content.contains("filter = f"));
        assert!(content.contains("bantime = 10m"));
        assert!(content.contains("findtime = 10m"));
    }

    #[test]
    fn atomic_write_preserves_existing_file_on_unmanaged_rejection() {
        let dir = setup_config_dir();
        let mgr = manager(&dir);

        let path = mgr.jail_path("preserve-me");
        let original_content = "[preserve-me]\nenabled = true\nstock = yes\n";
        write_unmanaged_file(&path, original_content);

        let jail = make_jail("preserve-me");
        let _ = mgr.write_jail(&jail);

        // The original file must be unchanged.
        let current = fs::read_to_string(&path).unwrap();
        assert_eq!(
            current, original_content,
            "unmanaged file must be untouched"
        );
    }

    // =======================================================================
    // Overwrite cycle: write -> write -> verify backup -> remove
    // =======================================================================

    #[test]
    fn full_write_overwrite_remove_cycle() {
        let dir = setup_config_dir();
        let mgr = manager(&dir);

        // 1. Write initial.
        let jail = make_jail("cycle");
        let r1 = mgr.write_jail(&jail).expect("write 1");
        assert_eq!(r1.files_written.len(), 1);
        assert!(r1.backup_paths.is_empty());

        // 2. Overwrite.
        let jail_v2 = JailSpec::builder()
            .name(JailName::new("cycle").unwrap())
            .filter(
                FilterSpec::builder()
                    .name(FilterName::new("f2").unwrap())
                    .failregex(vec![RegexLine::new("^new <HOST>$").unwrap()])
                    .build(),
            )
            .bantime(DurationSpec::new("1d").unwrap())
            .findtime(DurationSpec::new("1h").unwrap())
            .log_paths(vec![LogPath::new(Path::new("/tmp/auth.log")).unwrap()])
            .build();
        let r2 = mgr.write_jail(&jail_v2).expect("write 2");
        assert_eq!(r2.files_written.len(), 1);
        assert_eq!(r2.backup_paths.len(), 1);

        // Backup should contain the old content.
        let backup_content = fs::read_to_string(&r2.backup_paths[0]).unwrap();
        assert!(
            backup_content.contains("bantime = 10m"),
            "backup should have old bantime"
        );

        // Current file should have new content.
        let current = mgr.read_jail("cycle").expect("read");
        assert!(
            current.contains("bantime = 1d"),
            "current file should have new bantime"
        );
        assert!(
            current.contains("filter = f2"),
            "current file should have new filter"
        );

        // 3. Remove.
        let r3 = mgr.remove_jail("cycle").expect("remove");
        assert_eq!(r3.files_removed.len(), 1);
        assert_eq!(r3.backup_paths.len(), 1);
        assert!(!mgr.jail_path("cycle").exists());

        // Read should now fail.
        assert!(mgr.read_jail("cycle").is_err());
    }

    // =======================================================================
    // Multiple concurrent files of different kinds
    // =======================================================================

    #[test]
    fn write_and_list_multiple_kinds() {
        let dir = setup_config_dir();
        let mgr = manager(&dir);

        mgr.write_jail(&make_jail("app")).expect("jail");
        mgr.write_filter(&make_filter("app-auth")).expect("filter");
        mgr.write_action(&make_action("app-hook")).expect("action");

        let managed = mgr.list_managed().expect("list");
        assert_eq!(managed.len(), 3);

        let jails: Vec<&ManagedFile> = managed
            .iter()
            .filter(|f| f.kind == ManagedFileKind::Jail)
            .collect();
        let filters: Vec<&ManagedFile> = managed
            .iter()
            .filter(|f| f.kind == ManagedFileKind::Filter)
            .collect();
        let actions: Vec<&ManagedFile> = managed
            .iter()
            .filter(|f| f.kind == ManagedFileKind::Action)
            .collect();

        assert_eq!(jails.len(), 1);
        assert_eq!(filters.len(), 1);
        assert_eq!(actions.len(), 1);
        assert_eq!(jails[0].name, "app");
        assert_eq!(filters[0].name, "app-auth");
        assert_eq!(actions[0].name, "app-hook");
    }

    // =======================================================================
    // ManagedFileKind Display
    // =======================================================================

    #[test]
    fn managed_file_kind_display() {
        assert_eq!(format!("{}", ManagedFileKind::Jail), "jail");
        assert_eq!(format!("{}", ManagedFileKind::Filter), "filter");
        assert_eq!(format!("{}", ManagedFileKind::Action), "action");
    }

    // =======================================================================
    // DEFAULT_NAMESPACE constant
    // =======================================================================

    #[test]
    fn default_namespace_value() {
        assert_eq!(DEFAULT_NAMESPACE, "managed-by-fail2ban-kit");
    }

    // =======================================================================
    // Backup is created before overwrite and before removal
    // =======================================================================

    #[test]
    fn backup_created_before_overwrite_has_original_content() {
        let dir = setup_config_dir();
        let mgr = manager(&dir);

        // Write version 1.
        let v1 = JailSpec::builder()
            .name(JailName::new("versioned").unwrap())
            .filter(
                FilterSpec::builder()
                    .name(FilterName::new("f").unwrap())
                    .failregex(vec![RegexLine::new("^v1 <HOST>$").unwrap()])
                    .build(),
            )
            .bantime(DurationSpec::new("1m").unwrap())
            .findtime(DurationSpec::new("1m").unwrap())
            .log_paths(vec![LogPath::new(Path::new("/tmp/auth.log")).unwrap()])
            .build();
        mgr.write_jail(&v1).expect("v1");

        // Write version 2.
        let v2 = JailSpec::builder()
            .name(JailName::new("versioned").unwrap())
            .filter(
                FilterSpec::builder()
                    .name(FilterName::new("f").unwrap())
                    .failregex(vec![RegexLine::new("^v2 <HOST>$").unwrap()])
                    .build(),
            )
            .bantime(DurationSpec::new("2m").unwrap())
            .findtime(DurationSpec::new("2m").unwrap())
            .log_paths(vec![LogPath::new(Path::new("/tmp/auth.log")).unwrap()])
            .build();
        let r2 = mgr.write_jail(&v2).expect("v2");
        assert_eq!(r2.backup_paths.len(), 1);

        // Backup has v1 content.
        let backup = fs::read_to_string(&r2.backup_paths[0]).unwrap();
        assert!(
            backup.contains("bantime = 1m"),
            "backup should have v1 bantime"
        );
        assert!(
            backup.contains("findtime = 1m"),
            "backup should have v1 findtime"
        );

        // Current file has v2 content.
        let current = mgr.read_jail("versioned").unwrap();
        assert!(current.contains("bantime = 2m"));
        assert!(current.contains("findtime = 2m"));
    }

    #[test]
    fn backup_created_before_removal_has_file_content() {
        let dir = setup_config_dir();
        let mgr = manager(&dir);

        let jail = make_jail("to-remove");
        mgr.write_jail(&jail).expect("write");
        let written_content = mgr.read_jail("to-remove").unwrap();

        let report = mgr.remove_jail("to-remove").expect("remove");
        assert_eq!(report.backup_paths.len(), 1);

        let backup_content = fs::read_to_string(&report.backup_paths[0]).unwrap();
        assert_eq!(
            backup_content, written_content,
            "backup should match the removed file"
        );
    }

    // =======================================================================
    // Write then read round-trip for filter and action
    // =======================================================================

    #[test]
    fn filter_write_read_round_trip() {
        let dir = setup_config_dir();
        let mgr = manager(&dir);

        let filter = FilterSpec::builder()
            .name(FilterName::new("roundtrip").unwrap())
            .failregex(vec![
                RegexLine::new("^fail1 <HOST>$").unwrap(),
                RegexLine::new("^fail2 <HOST>$").unwrap(),
            ])
            .prefregex(Some("^<F-MLFID>.*</F-MLFID>".into()))
            .ignoreregex(vec!["^known-good.*$".into()])
            .datepattern(Some("{^LN-BEG}".into()))
            .build();
        mgr.write_filter(&filter).expect("write");

        let content = mgr.read_filter("roundtrip").expect("read");
        assert!(content.contains("[roundtrip]"));
        assert!(content.contains("failregex = ^fail1 <HOST>$"));
        assert!(content.contains("            ^fail2 <HOST>$"));
        assert!(content.contains("prefregex = ^<F-MLFID>.*</F-MLFID>"));
        assert!(content.contains("ignoreregex = ^known-good.*$"));
        assert!(content.contains("datepattern = {^LN-BEG}"));
    }

    #[test]
    fn action_write_read_round_trip() {
        let dir = setup_config_dir();
        let mgr = manager(&dir);

        let mut params = HashMap::new();
        params.insert("chain".into(), "INPUT".into());
        params.insert("name".into(), "myapp".into());

        let action = ActionSpec::builder()
            .name(ActionName::new("roundtrip-action").unwrap())
            .kind(ActionKind::Custom)
            .actionstart(Some("/usr/bin/start".into()))
            .actionstop(Some("/usr/bin/stop".into()))
            .actioncheck(Some("/usr/bin/check".into()))
            .actionban(Some("/usr/bin/ban <ip>".into()))
            .actionunban(Some("/usr/bin/unban <ip>".into()))
            .timeout(Some(std::time::Duration::from_secs(60)))
            .parameters(params)
            .build();
        mgr.write_action(&action).expect("write");

        let content = mgr.read_action("roundtrip-action").expect("read");
        assert!(content.contains("[roundtrip-action]"));
        assert!(content.contains("actionstart = /usr/bin/start"));
        assert!(content.contains("actionstop = /usr/bin/stop"));
        assert!(content.contains("actioncheck = /usr/bin/check"));
        assert!(content.contains("actionban = /usr/bin/ban <ip>"));
        assert!(content.contains("actionunban = /usr/bin/unban <ip>"));
        assert!(content.contains("timeout = 60"));
        assert!(content.contains("chain = INPUT"));
        assert!(content.contains("name = myapp"));
    }

    // =======================================================================
    // Write filter/action rejects overwriting unmanaged
    // =======================================================================

    #[test]
    fn write_filter_rejects_unmanaged_file() {
        let dir = setup_config_dir();
        let mgr = manager(&dir);

        let path = mgr.filter_path("stock-filter");
        write_unmanaged_file(&path, "[stock-filter]\nfailregex = ^.*$\n");

        let filter = make_filter("stock-filter");
        let result = mgr.write_filter(&filter);
        assert!(result.is_err());

        // Original content unchanged.
        let content = fs::read_to_string(&path).unwrap();
        assert!(content.contains("^.*$"));
    }

    #[test]
    fn write_action_rejects_unmanaged_file() {
        let dir = setup_config_dir();
        let mgr = manager(&dir);

        let path = mgr.action_path("stock-action");
        write_unmanaged_file(&path, "[stock-action]\nactionban = /bin/true\n");

        let action = make_action("stock-action");
        let result = mgr.write_action(&action);
        assert!(result.is_err());

        let content = fs::read_to_string(&path).unwrap();
        assert!(content.contains("/bin/true"));
    }

    // =======================================================================
    // Remove filter/action refuse unmanaged / missing
    // =======================================================================

    #[test]
    fn remove_filter_refuses_unmanaged() {
        let dir = setup_config_dir();
        let mgr = manager(&dir);

        let path = mgr.filter_path("nope");
        write_unmanaged_file(&path, "[nope]\nfailregex = ^.*$\n");

        assert!(mgr.remove_filter("nope").is_err());
        assert!(path.exists());
    }

    #[test]
    fn remove_filter_returns_not_found_for_missing() {
        let dir = setup_config_dir();
        let mgr = manager(&dir);
        assert!(mgr.remove_filter("ghost").is_err());
    }

    #[test]
    fn remove_action_refuses_unmanaged() {
        let dir = setup_config_dir();
        let mgr = manager(&dir);

        let path = mgr.action_path("nope");
        write_unmanaged_file(&path, "[nope]\nactionban = /bin/true\n");

        assert!(mgr.remove_action("nope").is_err());
        assert!(path.exists());
    }

    #[test]
    fn remove_action_returns_not_found_for_missing() {
        let dir = setup_config_dir();
        let mgr = manager(&dir);
        assert!(mgr.remove_action("ghost").is_err());
    }

    // =======================================================================
    // Namespace isolation
    // =======================================================================

    #[test]
    fn different_namespaces_do_not_interfere() {
        let dir = setup_config_dir();
        let mgr_a = manager_ns(&dir, "ns-a");
        let mgr_b = manager_ns(&dir, "ns-b");

        mgr_a.write_jail(&make_jail("shared")).expect("a write");
        mgr_b.write_jail(&make_jail("shared")).expect("b write");

        // Both files should exist with different paths.
        assert!(mgr_a.jail_path("shared").exists());
        assert!(mgr_b.jail_path("shared").exists());
        assert_ne!(mgr_a.jail_path("shared"), mgr_b.jail_path("shared"));

        // list_managed for ns-a should only find ns-a files.
        let a_files = mgr_a.list_managed().expect("list a");
        assert_eq!(a_files.len(), 1);
        assert!(a_files[0].path.to_str().unwrap().contains("ns-a-"));

        let b_files = mgr_b.list_managed().expect("list b");
        assert_eq!(b_files.len(), 1);
        assert!(b_files[0].path.to_str().unwrap().contains("ns-b-"));

        // Removing from ns-a should not affect ns-b.
        mgr_a.remove_jail("shared").expect("remove a");
        assert!(!mgr_a.jail_path("shared").exists());
        assert!(mgr_b.jail_path("shared").exists());
    }
}
