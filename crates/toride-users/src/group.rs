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
/// This is done by re-setting the user's supplementary group list minus the
/// target group using `usermod -G`.
///
/// # Errors
///
/// - [`Error::BinaryNotFound`] if `usermod` is not on `$PATH`.
/// - [`Error::CommandFailed`] if `usermod` returns a non-zero exit code.
#[cfg(feature = "client")]
pub fn remove_user_from_group(username: &str, group: &str) -> Result<()> {
    // Get current groups for the user, filter out the target group. This
    // mutates the live system via `usermod`, so it reads the real /etc/group.
    let current = get_user_groups(std::path::Path::new("/etc/group"), username)?;
    let remaining: Vec<String> = current.into_iter().filter(|g| g != group).collect();

    let usermod = which::which("usermod").map_err(|_| Error::BinaryNotFound("usermod".into()))?;

    let groups_str = remaining.join(",");
    duct::cmd(&usermod, ["-G", &groups_str, username])
        .stderr_to_stdout()
        .read()
        .map_err(|e| Error::CommandFailed {
            program: "usermod".to_owned(),
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
