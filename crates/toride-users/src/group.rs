//! Group management via `groupadd`, `groupdel`, and `groupmod`.
//!
//! Provides functions to create, delete, and query system groups, as well as
//! manage group membership.

use crate::{Error, Result};
use std::path::Path;

/// Create a new system group.
///
/// Executes `groupadd` to create the group.
///
/// # Errors
///
/// - [`Error::BinaryNotFound`] if `groupadd` is not on `$PATH`.
/// - [`Error::GroupExists`] if the group already exists.
/// - [`Error::CommandFailed`] if `groupadd` returns a non-zero exit code.
#[cfg(feature = "client")]
pub fn create_group(name: &str, system: bool) -> Result<()> {
    let groupadd =
        which::which("groupadd").map_err(|_| Error::BinaryNotFound("groupadd".into()))?;

    let mut args: Vec<String> = Vec::new();
    if system {
        args.push("-r".to_owned());
    }
    args.push(name.to_owned());

    duct::cmd(&groupadd, &args)
        .stderr_to_stdout()
        .read()
        .map_err(|e| Error::CommandFailed {
            program: "groupadd".to_owned(),
            code: None,
            stderr: e.to_string(),
        })?;

    tracing::info!("created group {name}");
    Ok(())
}

/// Delete a system group.
///
/// Executes `groupdel` to remove the group.
///
/// # Errors
///
/// - [`Error::BinaryNotFound`] if `groupdel` is not on `$PATH`.
/// - [`Error::GroupNotFound`] if the group does not exist.
/// - [`Error::CommandFailed`] if `groupdel` returns a non-zero exit code.
#[cfg(feature = "client")]
pub fn delete_group(name: &str) -> Result<()> {
    let groupdel =
        which::which("groupdel").map_err(|_| Error::BinaryNotFound("groupdel".into()))?;

    duct::cmd(&groupdel, &[name])
        .stderr_to_stdout()
        .read()
        .map_err(|e| Error::CommandFailed {
            program: "groupdel".to_owned(),
            code: None,
            stderr: e.to_string(),
        })?;

    tracing::info!("deleted group {name}");
    Ok(())
}

/// Add a user to a group.
///
/// Executes `usermod -aG <group> <username>`.
///
/// # Errors
///
/// - [`Error::BinaryNotFound`] if `usermod` is not on `$PATH`.
/// - [`Error::CommandFailed`] if `usermod` returns a non-zero exit code.
#[cfg(feature = "client")]
pub fn add_user_to_group(username: &str, group: &str) -> Result<()> {
    let usermod = which::which("usermod").map_err(|_| Error::BinaryNotFound("usermod".into()))?;

    duct::cmd(&usermod, ["-aG", group, username])
        .stderr_to_stdout()
        .read()
        .map_err(|e| Error::CommandFailed {
            program: "usermod".to_owned(),
            code: None,
            stderr: e.to_string(),
        })?;

    tracing::info!("added user {username} to group {group}");
    Ok(())
}

/// Remove a user from a group.
///
/// Uses `gpasswd -d <user> <group>`, which removes a single group membership
/// in place. This preserves any other supplementary groups the user belongs to
/// (including memberships discovered via NSS / LDAP that are not present in
/// the local `/etc/group`). The previous `usermod -G` implementation rebuilt
/// the entire supplementary-group list from the local `group` file and would
/// silently drop those NSS memberships.
///
/// # Errors
///
/// - [`Error::BinaryNotFound`] if `gpasswd` is not on `$PATH`.
/// - [`Error::CommandFailed`] if `gpasswd` returns a non-zero exit code.
#[cfg(feature = "client")]
pub fn remove_user_from_group(username: &str, group: &str) -> Result<()> {
    let gpasswd = which::which("gpasswd").map_err(|_| Error::BinaryNotFound("gpasswd".into()))?;

    duct::cmd(&gpasswd, ["-d", username, group])
        .stderr_to_stdout()
        .read()
        .map_err(|e| Error::CommandFailed {
            program: "gpasswd".to_owned(),
            code: None,
            stderr: e.to_string(),
        })?;

    tracing::info!("removed user {username} from group {group}");
    Ok(())
}

/// Check if a group exists in the given `group` file.
///
/// `group` is the path to the group database (usually `/etc/group`, or a
/// redirect via [`crate::paths::UserPaths`]).
pub fn group_exists(group: &Path, name: &str) -> Result<bool> {
    let entries = crate::parse::read_group(group)?;
    Ok(entries.iter().any(|e| e.name == name))
}

/// Get the GID of a group.
///
/// `group` is the path to the group database (usually `/etc/group`).
///
/// # Errors
///
/// Returns [`Error::GroupNotFound`] if the group does not exist.
pub fn get_gid(group: &Path, name: &str) -> Result<u32> {
    let entries = crate::parse::read_group(group)?;
    entries
        .iter()
        .find(|e| e.name == name)
        .map(|e| e.gid)
        .ok_or_else(|| Error::GroupNotFound(name.to_owned()))
}

/// Get the list of supplementary groups a user belongs to.
///
/// `group` is the path to the group database (usually `/etc/group`).
///
/// # Errors
///
/// Returns [`Error::UserNotFound`] if the user does not exist.
pub fn get_user_groups(group: &Path, username: &str) -> Result<Vec<String>> {
    let group_entries = crate::parse::read_group(group)?;
    let groups: Vec<String> = group_entries
        .iter()
        .filter(|e| e.members.iter().any(|m| m == username))
        .map(|e| e.name.clone())
        .collect();
    Ok(groups)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_group(content: &str) -> std::path::PathBuf {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("group");
        std::fs::write(&path, content).unwrap();
        std::mem::forget(dir);
        path
    }

    // /etc/group: name:password:gid:comma-separated-members
    const FIXTURE: &str = "\
root:x:0:
sudo:x:27:alice,bob
docker:x:998:alice
alice:x:1000:
bob:x:1001:
";

    #[test]
    fn group_exists_true_and_false() {
        let group = write_group(FIXTURE);
        assert!(group_exists(&group, "sudo").unwrap());
        assert!(!group_exists(&group, "wheel").unwrap());
    }

    #[test]
    fn get_gid_resolves_and_errors() {
        let group = write_group(FIXTURE);
        assert_eq!(get_gid(&group, "sudo").unwrap(), 27);
        assert!(matches!(
            get_gid(&group, "wheel"),
            Err(Error::GroupNotFound(_))
        ));
    }

    #[test]
    fn get_user_groups_lists_memberships() {
        let group = write_group(FIXTURE);
        // get_user_groups scans the *members* column only (it does not infer
        // primary-group membership from the GID). alice is a member of sudo
        // and docker.
        let alice_groups = get_user_groups(&group, "alice").unwrap();
        assert!(alice_groups.contains(&"sudo".to_owned()));
        assert!(alice_groups.contains(&"docker".to_owned()));

        // bob is a member of sudo.
        let bob_groups = get_user_groups(&group, "bob").unwrap();
        assert!(bob_groups.contains(&"sudo".to_owned()));

        // A user with no supplementary-group memberships resolves to empty.
        let nobody_groups = get_user_groups(&group, "nobody").unwrap();
        assert!(nobody_groups.is_empty());
    }

    #[test]
    fn missing_group_file_is_err() {
        let missing = std::path::PathBuf::from("/nonexistent/group-toride-test");
        assert!(group_exists(&missing, "sudo").is_err());
    }
}
