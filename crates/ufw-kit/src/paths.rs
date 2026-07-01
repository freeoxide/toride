//! UFW filesystem paths.
//!
//! Centralizes all paths that UFW uses, with validation to prevent
//! writes outside UFW-managed directories.

use std::path::{Path, PathBuf};

/// UFW paths.
#[derive(Debug, Clone)]
pub struct UfwPaths {
    /// `/etc/default/ufw`
    pub default_ufw: PathBuf,
    /// `/etc/ufw/ufw.conf`
    pub ufw_conf: PathBuf,
    /// `/etc/ufw/sysctl.conf`
    pub sysctl_conf: PathBuf,
    /// `/etc/ufw/before.rules`
    pub before_rules: PathBuf,
    /// `/etc/ufw/after.rules`
    pub after_rules: PathBuf,
    /// `/etc/ufw/before6.rules`
    pub before6_rules: PathBuf,
    /// `/etc/ufw/after6.rules`
    pub after6_rules: PathBuf,
    /// `/etc/ufw/before.init`
    pub before_init: PathBuf,
    /// `/etc/ufw/after.init`
    pub after_init: PathBuf,
    /// `/etc/ufw/applications.d/`
    pub app_profiles_dir: PathBuf,
    /// `/etc/ufw/user.rules`
    pub user_rules: PathBuf,
    /// `/etc/ufw/user6.rules`
    pub user6_rules: PathBuf,
}

impl Default for UfwPaths {
    fn default() -> Self {
        Self {
            default_ufw: PathBuf::from("/etc/default/ufw"),
            ufw_conf: PathBuf::from("/etc/ufw/ufw.conf"),
            sysctl_conf: PathBuf::from("/etc/ufw/sysctl.conf"),
            before_rules: PathBuf::from("/etc/ufw/before.rules"),
            after_rules: PathBuf::from("/etc/ufw/after.rules"),
            before6_rules: PathBuf::from("/etc/ufw/before6.rules"),
            after6_rules: PathBuf::from("/etc/ufw/after6.rules"),
            before_init: PathBuf::from("/etc/ufw/before.init"),
            after_init: PathBuf::from("/etc/ufw/after.init"),
            app_profiles_dir: PathBuf::from("/etc/ufw/applications.d"),
            user_rules: PathBuf::from("/etc/ufw/user.rules"),
            user6_rules: PathBuf::from("/etc/ufw/user6.rules"),
        }
    }
}

impl UfwPaths {
    /// Create paths with a custom root (for testing).
    pub fn with_root(root: &Path) -> Self {
        Self {
            default_ufw: root.join("etc/default/ufw"),
            ufw_conf: root.join("etc/ufw/ufw.conf"),
            sysctl_conf: root.join("etc/ufw/sysctl.conf"),
            before_rules: root.join("etc/ufw/before.rules"),
            after_rules: root.join("etc/ufw/after.rules"),
            before6_rules: root.join("etc/ufw/before6.rules"),
            after6_rules: root.join("etc/ufw/after6.rules"),
            before_init: root.join("etc/ufw/before.init"),
            after_init: root.join("etc/ufw/after.init"),
            app_profiles_dir: root.join("etc/ufw/applications.d"),
            user_rules: root.join("etc/ufw/user.rules"),
            user6_rules: root.join("etc/ufw/user6.rules"),
        }
    }

    /// Check if a path is a UFW-managed path (safe to write).
    #[must_use]
    pub fn is_managed_path(&self, path: &Path) -> bool {
        let managed = [
            &self.default_ufw,
            &self.ufw_conf,
            &self.sysctl_conf,
            &self.before_rules,
            &self.after_rules,
            &self.before6_rules,
            &self.after6_rules,
            &self.before_init,
            &self.after_init,
            &self.app_profiles_dir,
        ];

        managed
            .iter()
            .any(|m| path == m.as_path() || path.starts_with(m))
    }

    /// Get the app profile path for a given namespace and name.
    ///
    /// Both `namespace` and `name` are sanitized to a safe path component: any
    /// path separators (`/`, `\`), NUL bytes, or `..` traversal segments are
    /// rejected by collapsing the component to a safe placeholder. This
    /// guarantees the resulting path stays inside `app_profiles_dir` even when
    /// a caller forwards untrusted input, preventing `../` escape.
    #[must_use]
    pub fn app_profile_path(&self, namespace: &str, name: &str) -> PathBuf {
        let namespace = sanitize_profile_component(namespace);
        let name = sanitize_profile_component(name);
        self.app_profiles_dir.join(format!("{namespace}-{name}"))
    }
}

/// Reduce a caller-supplied namespace/profile component to a safe path
/// component.
///
/// Returns the original value if it is safe (non-empty, no path separators,
/// no NUL, no `..` segment), otherwise a safe placeholder. This prevents a
/// `namespace` like `../..` from escaping `app_profiles_dir` when joined.
fn sanitize_profile_component(component: &str) -> String {
    let is_safe = !component.is_empty()
        && !component.contains('/')
        && !component.contains('\\')
        && !component.contains('\0')
        && component != ".."
        && component != "."
        && !component.split('/').any(|seg| seg == "..");
    if is_safe {
        component.to_string()
    } else {
        // Replace unsafe input with a benign placeholder rather than dropping
        // the profile silently; the file is written under a clearly-named key
        // that cannot escape the managed directory.
        "_unsafe".to_string()
    }
}

#[cfg(test)]
#[path = "paths.test.rs"]
mod tests;
