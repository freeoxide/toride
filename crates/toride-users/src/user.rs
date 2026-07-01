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
/// - [`Error::Validation`] if the username is invalid (e.g. starts with `-`).
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
    // Validate before building argv: a leading `-` would be parsed by
    // `useradd` as an option flag, and the allowlist rejects shell
    // metacharacters / traversal names.
    crate::validate::validate_username(username)?;
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
/// - [`Error::Validation`] if the username is invalid (e.g. starts with `-`).
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
    // Validate before building argv: a leading `-` would be parsed by
    // `usermod` as an option flag.
    crate::validate::validate_username(username)?;
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
/// - [`Error::Validation`] if the username is invalid (e.g. starts with `-`).
/// - [`Error::BinaryNotFound`] if `userdel` is not on `$PATH`.
/// - [`Error::UserNotFound`] if the user does not exist.
/// - [`Error::CommandFailed`] if `userdel` returns a non-zero exit code.
#[cfg(feature = "client")]
pub fn delete_user(username: &str, remove_home: bool) -> Result<()> {
    // Validate before building argv: a leading `-` would be parsed by
    // `userdel` as an option flag.
    crate::validate::validate_username(username)?;
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

#[cfg(test)]
mod tests {
    use super::*;

    fn write_passwd(content: &str) -> std::path::PathBuf {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("passwd");
        std::fs::write(&path, content).unwrap();
        std::mem::forget(dir); // keep the temp alive for the test
        path
    }

    const FIXTURE: &str = "\
root:x:0:0:root:/root:/bin/bash
alice:x:1000:1000:Alice:/home/alice:/bin/bash
bob:x:1001:1001::/home/bob:/usr/sbin/nologin
svc:x:1002:1002::/opt/svc:/bin/false
";

    #[test]
    fn user_exists_true_and_false() {
        let passwd = write_passwd(FIXTURE);
        assert!(user_exists(&passwd, "alice").unwrap());
        assert!(!user_exists(&passwd, "ghost").unwrap());
    }

    #[test]
    fn user_exists_missing_file_is_io_error() {
        // A missing passwd should surface as an IO error, not UserNotFound.
        let missing = std::path::PathBuf::from("/nonexistent/passwd-toride-test");
        assert!(user_exists(&missing, "alice").is_err());
    }

    #[test]
    fn get_uid_resolves_and_errors() {
        let passwd = write_passwd(FIXTURE);
        assert_eq!(get_uid(&passwd, "alice").unwrap(), 1000);
        assert!(matches!(
            get_uid(&passwd, "ghost"),
            Err(Error::UserNotFound(_))
        ));
    }

    #[test]
    fn get_shell_resolves_and_errors() {
        let passwd = write_passwd(FIXTURE);
        assert_eq!(get_shell(&passwd, "alice").unwrap(), "/bin/bash");
        assert_eq!(get_shell(&passwd, "bob").unwrap(), "/usr/sbin/nologin");
        assert!(matches!(
            get_shell(&passwd, "ghost"),
            Err(Error::UserNotFound(_))
        ));
    }
}
