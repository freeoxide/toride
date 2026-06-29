use super::*;
use std::path::PathBuf;

// ---------------------------------------------------------------------------
// Default paths
// ---------------------------------------------------------------------------

#[test]
fn default_paths_should_point_to_etc_ufw() {
    let paths = UfwPaths::default();
    assert_eq!(paths.default_ufw, PathBuf::from("/etc/default/ufw"));
    assert_eq!(paths.ufw_conf, PathBuf::from("/etc/ufw/ufw.conf"));
    assert_eq!(
        paths.app_profiles_dir,
        PathBuf::from("/etc/ufw/applications.d")
    );
}

// ---------------------------------------------------------------------------
// with_root
// ---------------------------------------------------------------------------

#[test]
fn with_root_should_prefix_all_paths() {
    let paths = UfwPaths::with_root(Path::new("/tmp/test"));
    assert_eq!(
        paths.default_ufw,
        PathBuf::from("/tmp/test/etc/default/ufw")
    );
    assert_eq!(paths.ufw_conf, PathBuf::from("/tmp/test/etc/ufw/ufw.conf"));
    assert_eq!(
        paths.app_profiles_dir,
        PathBuf::from("/tmp/test/etc/ufw/applications.d")
    );
}

// ---------------------------------------------------------------------------
// is_managed_path
// ---------------------------------------------------------------------------

#[test]
fn is_managed_path_should_accept_managed_paths() {
    let paths = UfwPaths::with_root(Path::new("/tmp/test"));
    assert!(paths.is_managed_path(Path::new("/tmp/test/etc/default/ufw")));
    assert!(paths.is_managed_path(Path::new("/tmp/test/etc/ufw/applications.d/myapp")));
}

#[test]
fn is_managed_path_should_reject_unmanaged_paths() {
    let paths = UfwPaths::with_root(Path::new("/tmp/test"));
    assert!(!paths.is_managed_path(Path::new("/etc/passwd")));
    assert!(!paths.is_managed_path(Path::new("/tmp")));
}

// ---------------------------------------------------------------------------
// app_profile_path
// ---------------------------------------------------------------------------

#[test]
fn app_profile_path_should_join_namespace_and_name() {
    let paths = UfwPaths::with_root(Path::new("/tmp/test"));
    let path = paths.app_profile_path("ufw-kit", "myapp");
    assert_eq!(
        path,
        PathBuf::from("/tmp/test/etc/ufw/applications.d/ufw-kit-myapp")
    );
}

// ---------------------------------------------------------------------------
// Edge-case tests
// ---------------------------------------------------------------------------

#[test]
fn is_managed_path_should_accept_framework_files() {
    let paths = UfwPaths::with_root(Path::new("/tmp/test"));
    assert!(paths.is_managed_path(Path::new("/tmp/test/etc/ufw/before.rules")));
    assert!(paths.is_managed_path(Path::new("/tmp/test/etc/ufw/after.rules")));
    assert!(paths.is_managed_path(Path::new("/tmp/test/etc/ufw/before6.rules")));
    assert!(paths.is_managed_path(Path::new("/tmp/test/etc/ufw/after6.rules")));
}

// ---------------------------------------------------------------------------
// Weird edge-case tests
// ---------------------------------------------------------------------------

#[test]
fn is_managed_path_should_reject_similar_but_wrong_path() {
    let paths = UfwPaths::with_root(Path::new("/tmp/test"));
    // Similar prefix but not managed
    assert!(!paths.is_managed_path(Path::new("/tmp/test/etc/ufw2")));
    assert!(!paths.is_managed_path(Path::new("/tmp/test/etc/ufw-applications")));
}
