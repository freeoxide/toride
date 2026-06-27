//! User account management via `useradd`, `usermod`, and `userdel`.
//!
//! Provides functions to create, modify, and delete user accounts on the
//! system, as well as query user information from `/etc/passwd`.

use crate::{Error, Result};
use std::path::Path;

/// Create a new user account.
///
/// Executes `useradd` with the specified options. The command is run via
/// `duct` with a configurable timeout.
///
/// # Errors
///
/// - [`Error::BinaryNotFound`] if `useradd` is not on `$PATH`.
/// - [`Error::UserExists`] if the username is already taken.
/// - [`Error::CommandFailed`] if `useradd` returns a non-zero exit code.
#[cfg(feature = "client")]
pub fn create_user(
    username: &str,
    shell: &str,
    groups: &[String],
    home_dir: Option<&str>,
) -> Result<()> {
    let useradd = which::which("useradd").map_err(|_| Error::BinaryNotFound("useradd".into()))?;

    let mut args: Vec<String> = Vec::new();

    // Shell
    args.push("-s".to_owned());
    args.push(shell.to_owned());

    // Supplementary groups
    if !groups.is_empty() {
        args.push("-G".to_owned());
        args.push(groups.join(","));
    }

    // Home directory
    if let Some(home) = home_dir {
        args.push("-d".to_owned());
        args.push(home.to_owned());
        args.push("-m".to_owned()); // create home directory
    }

    // Username
    args.push(username.to_owned());

    let cmd = duct::cmd(&useradd, &args)
        .stderr_to_stdout()
        .read()
        .map_err(|e| Error::CommandFailed {
            program: "useradd".to_owned(),
            code: None,
            stderr: e.to_string(),
        })?;

    tracing::info!("created user {username}: {cmd}");
    Ok(())
}

/// Modify an existing user account.
///
/// Executes `usermod` with the specified options.
///
/// # Errors
///
/// - [`Error::BinaryNotFound`] if `usermod` is not on `$PATH`.
/// - [`Error::UserNotFound`] if the user does not exist.
/// - [`Error::CommandFailed`] if `usermod` returns a non-zero exit code.
#[cfg(feature = "client")]
pub fn modify_user(
    username: &str,
    shell: Option<&str>,
    groups: Option<&[String]>,
    append_groups: Option<&[String]>,
) -> Result<()> {
    let usermod = which::which("usermod").map_err(|_| Error::BinaryNotFound("usermod".into()))?;

    let mut args: Vec<String> = Vec::new();

    if let Some(s) = shell {
        args.push("-s".to_owned());
        args.push(s.to_owned());
    }

    if let Some(g) = groups {
        args.push("-G".to_owned());
        args.push(g.join(","));
    }

    if let Some(g) = append_groups {
        args.push("-aG".to_owned());
        args.push(g.join(","));
    }

    args.push(username.to_owned());

    duct::cmd(&usermod, &args)
        .stderr_to_stdout()
        .read()
        .map_err(|e| Error::CommandFailed {
            program: "usermod".to_owned(),
            code: None,
            stderr: e.to_string(),
        })?;

    tracing::info!("modified user {username}");
    Ok(())
}

/// Delete a user account.
///
/// Executes `userdel -r` to remove the user and their home directory.
///
/// # Errors
///
/// - [`Error::BinaryNotFound`] if `userdel` is not on `$PATH`.
/// - [`Error::UserNotFound`] if the user does not exist.
/// - [`Error::CommandFailed`] if `userdel` returns a non-zero exit code.
#[cfg(feature = "client")]
pub fn delete_user(username: &str, remove_home: bool) -> Result<()> {
    let userdel = which::which("userdel").map_err(|_| Error::BinaryNotFound("userdel".into()))?;

    let mut args: Vec<String> = Vec::new();
    if remove_home {
        args.push("-r".to_owned());
    }
    args.push(username.to_owned());

    duct::cmd(&userdel, &args)
        .stderr_to_stdout()
        .read()
        .map_err(|e| Error::CommandFailed {
            program: "userdel".to_owned(),
            code: None,
            stderr: e.to_string(),
        })?;

    tracing::info!("deleted user {username}");
    Ok(())
}

/// Check if a user exists in the given `passwd` file.
///
/// This reads the supplied path (typically `/etc/passwd`, or a redirect via
/// [`crate::paths::UserPaths`]) and checks for the given username.
/// It does not require root privileges.
pub fn user_exists(passwd: &Path, username: &str) -> Result<bool> {
    let entries = crate::parse::read_passwd(passwd)?;
    Ok(entries.iter().any(|e| e.username == username))
}

/// Get the UID of a user.
///
/// `passwd` is the path to the password database (usually `/etc/passwd`).
///
/// # Errors
///
/// Returns [`Error::UserNotFound`] if the user does not exist.
pub fn get_uid(passwd: &Path, username: &str) -> Result<u32> {
    let entries = crate::parse::read_passwd(passwd)?;
    entries
        .iter()
        .find(|e| e.username == username)
        .map(|e| e.uid)
        .ok_or_else(|| Error::UserNotFound(username.to_owned()))
}

/// Get the shell of a user.
///
/// `passwd` is the path to the password database (usually `/etc/passwd`).
///
/// # Errors
///
/// Returns [`Error::UserNotFound`] if the user does not exist.
pub fn get_shell(passwd: &Path, username: &str) -> Result<String> {
    let entries = crate::parse::read_passwd(passwd)?;
    entries
        .iter()
        .find(|e| e.username == username)
        .map(|e| e.shell.clone())
        .ok_or_else(|| Error::UserNotFound(username.to_owned()))
}
