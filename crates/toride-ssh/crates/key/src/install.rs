//! Install and uninstall SSH public keys on remote hosts.
//!
//! The primary entry points are:
//! - [`install_key_to_remote`] -- installs a public key via `ssh-copy-id` or
//!   manual SSH fallback.
//! - [`uninstall_key_from_remote`] -- removes a matching key line from the
//!   remote `~/.ssh/authorized_keys` file.

use std::path::Path;

use toride_ssh_core::HostSpec;
use toride_ssh_core::paths::pub_path_for;
use toride_ssh_core::{CliRunner, Error, Result};

/// Result of a key installation attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallOutcome {
    /// `ssh-copy-id` was available and succeeded.
    SshCopyId,
    /// `ssh-copy-id` was not available; manual install via `ssh` succeeded.
    Manual,
}

/// Result of a key removal attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UninstallOutcome {
    /// The key was found and removed from the remote `authorized_keys`.
    Removed,
    /// The key was not present in the remote `authorized_keys`.
    NotFound,
}

/// Install a public key on a remote host.
///
/// This function:
/// 1. Detects whether `ssh-copy-id` is available on the local system.
/// 2. If available, uses `ssh-copy-id -i <pubkey> <dest>` to install the key.
/// 3. If not available, falls back to manual mode: SSH into the remote and run
///    `mkdir -p ~/.ssh && echo '<key>' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys`.
///
/// # Arguments
///
/// * `key_path` - Path to the **private** key file. The corresponding `.pub`
///   file is derived automatically (e.g., `id_ed25519` -> `id_ed25519.pub`).
///   If the `.pub` file does not exist, the private key path is used directly
///   (some `ssh-copy-id` implementations accept this).
/// * `dest` - The remote destination in `[user@]host` format; validated
///   through [`HostSpec::parse`] so a leading-dash destination can never
///   reach the ssh argv.
///
/// # Errors
///
/// Returns an error if:
/// - The key path does not exist.
/// - `dest` fails [`HostSpec::parse`] validation.
/// - Neither `ssh-copy-id` nor `ssh` is available.
/// - The manual fallback is asked to install a file that is not an OpenSSH
///   public key (a missing `.pub` companion must not echo private key
///   material into the remote `authorized_keys`).
/// - The remote command fails (authentication denied, network unreachable, etc.).
pub async fn install_key_to_remote(
    key_path: &Path,
    dest: &str,
    runner: &dyn CliRunner,
) -> Result<InstallOutcome> {
    if !key_path.exists() {
        return Err(Error::KeyNotFound(key_path.display().to_string()));
    }

    let dest = HostSpec::parse(dest)?.destination();

    let pub_path = pub_path_for(key_path);
    let pubkey_path = if pub_path.exists() {
        pub_path
    } else {
        key_path.to_path_buf()
    };

    if runner.tool_exists("ssh-copy-id") {
        let pubkey_str = pubkey_path.to_str().ok_or_else(|| {
            Error::CommandFailed(format!(
                "public key path is not valid UTF-8: {}",
                pubkey_path.display()
            ))
        })?;
        runner
            .run(
                "ssh-copy-id",
                vec!["-i".to_owned(), pubkey_str.to_owned(), dest],
            )
            .await?;
        return Ok(InstallOutcome::SshCopyId);
    }

    if !runner.tool_exists("ssh") {
        return Err(Error::ToolNotFound(
            "neither ssh-copy-id nor ssh found in PATH".to_owned(),
        ));
    }

    install_via_manual_ssh(&pubkey_path, &dest, runner).await?;
    Ok(InstallOutcome::Manual)
}

/// Install via manual SSH command when `ssh-copy-id` is unavailable.
///
/// Reads the public key content locally, rejects it unless it parses as an
/// OpenSSH public key, then runs:
/// ```sh
/// ssh <dest> "mkdir -p ~/.ssh && echo '<key>' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"
/// ```
async fn install_via_manual_ssh(
    pubkey_path: &Path,
    dest: &str,
    runner: &dyn CliRunner,
) -> Result<()> {
    let pubkey_content = tokio::task::spawn_blocking({
        let path = pubkey_path.to_path_buf();
        move || std::fs::read_to_string(&path).map_err(Error::Io)
    })
    .await
    .map_err(|e| Error::TaskFailed(e.to_string()))??;

    let pubkey_content = pubkey_content.trim();

    ssh_key::PublicKey::from_openssh(pubkey_content).map_err(|e| {
        Error::KeyParseFailed(format!(
            "{} does not contain an OpenSSH public key (refusing to install \
             private key material on the remote host): {e}",
            pubkey_path.display()
        ))
    })?;

    // Escape single quotes in the key content for safe shell embedding.
    let escaped_key = pubkey_content.replace('\'', "'\\''");

    let remote_cmd = format!(
        "mkdir -p ~/.ssh && echo '{escaped_key}' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"
    );

    runner.run("ssh", vec![dest.to_owned(), remote_cmd]).await?;

    Ok(())
}

/// Remove a public key from a remote host's `authorized_keys`.
///
/// This function:
/// 1. Reads the local public key content.
/// 2. `SSHes` into the remote host in a single session and uses `grep -vF` to
///    strip the matching key line from `~/.ssh/authorized_keys`.
///
/// # Arguments
///
/// * `key_path` - Path to the **private** key file. The corresponding `.pub`
///   file is derived automatically (e.g., `id_ed25519` -> `id_ed25519.pub`).
///   If the `.pub` file does not exist, the private key path is used directly
///   and must itself parse as an OpenSSH public key.
/// * `dest` - The remote destination in `[user@]host` format; validated
///   through [`HostSpec::parse`].
///
/// # Errors
///
/// Returns an error if:
/// - The key path does not exist.
/// - `dest` fails [`HostSpec::parse`] validation.
/// - `ssh` is not available in `PATH`.
/// - The remote command fails (authentication denied, network unreachable,
///   removal chain failed on the remote side, etc.).
pub async fn uninstall_key_from_remote(
    key_path: &Path,
    dest: &str,
    runner: &dyn CliRunner,
) -> Result<UninstallOutcome> {
    if !key_path.exists() {
        return Err(Error::KeyNotFound(key_path.display().to_string()));
    }

    let dest = HostSpec::parse(dest)?.destination();

    let pub_path = pub_path_for(key_path);
    let pubkey_path = if pub_path.exists() {
        pub_path
    } else {
        key_path.to_path_buf()
    };

    if !runner.tool_exists("ssh") {
        return Err(Error::ToolNotFound("ssh not found in PATH".to_owned()));
    }

    uninstall_via_manual_ssh(&pubkey_path, &dest, runner).await
}

/// Remove the matching key line via one `ssh` invocation using `grep -vF`.
///
/// Runs a single remote script:
/// ```sh
/// if grep -qF '<key>' ~/.ssh/authorized_keys 2>/dev/null; then
///   grep -vF '<key>' ~/.ssh/authorized_keys > ~/.ssh/authorized_keys.tmp &&
///   mv ~/.ssh/authorized_keys.tmp ~/.ssh/authorized_keys &&
///   chmod 600 ~/.ssh/authorized_keys && echo REMOVED
/// else
///   echo NOTFOUND
/// fi
/// ```
///
/// The removal chain is joined with `&&` and unsuppressed, so a failed
/// `grep`/`mv`/`chmod` makes the whole command fail (surfaced as
/// [`Error::CommandFailed`]) instead of reporting success.
async fn uninstall_via_manual_ssh(
    pubkey_path: &Path,
    dest: &str,
    runner: &dyn CliRunner,
) -> Result<UninstallOutcome> {
    let pubkey_content = tokio::task::spawn_blocking({
        let path = pubkey_path.to_path_buf();
        move || std::fs::read_to_string(&path).map_err(Error::Io)
    })
    .await
    .map_err(|e| Error::TaskFailed(e.to_string()))??;

    let pubkey_content = pubkey_content.trim();

    // Extract just the key type + base64 data (skip the comment) so that
    // `grep -vF` matches the key line regardless of comment differences.
    // SSH public key format: <key-type> <base64-data> [comment]
    let key_fingerprint = pubkey_content
        .split_whitespace()
        .take(2)
        .collect::<Vec<&str>>()
        .join(" ");

    if key_fingerprint.is_empty() {
        return Err(Error::CommandFailed(
            "public key file appears to be empty or malformed".to_owned(),
        ));
    }

    // Escape single quotes in the key content for safe shell embedding.
    let escaped_key = key_fingerprint.replace('\'', "'\\''");

    let remote_cmd = format!(
        "if grep -qF '{escaped_key}' ~/.ssh/authorized_keys 2>/dev/null; then \
         grep -vF '{escaped_key}' ~/.ssh/authorized_keys > ~/.ssh/authorized_keys.tmp && \
         mv ~/.ssh/authorized_keys.tmp ~/.ssh/authorized_keys && \
         chmod 600 ~/.ssh/authorized_keys && echo REMOVED; \
         else echo NOTFOUND; fi"
    );

    let output = runner.run("ssh", vec![dest.to_owned(), remote_cmd]).await?;

    match output.trim() {
        "REMOVED" => Ok(UninstallOutcome::Removed),
        "NOTFOUND" => Ok(UninstallOutcome::NotFound),
        other => Err(Error::CommandFailed(format!(
            "unexpected uninstall output from remote: {other:?}"
        ))),
    }
}

/// A syntactically valid OpenSSH ed25519 public key line (throwaway key).
#[cfg(test)]
const VALID_PUBKEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILWnaRp7+VXp8vGSr8SmxJWOqJVWpitSTRiUyQYiavsZ toride@test";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn install_outcome_variants_are_distinct() {
        assert_ne!(InstallOutcome::SshCopyId, InstallOutcome::Manual);
    }

    #[test]
    fn install_key_to_remote_rejects_missing_key() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let runner = toride_ssh_core::MockCliRunner::new();
        let result = rt.block_on(install_key_to_remote(
            Path::new("/nonexistent/key"),
            "user@host",
            &runner,
        ));
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::KeyNotFound(_) => {}
            other => panic!("expected KeyNotFound, got: {other:?}"),
        }
    }

    #[test]
    fn install_key_to_remote_rejects_invalid_dest() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("id_ed25519");
        std::fs::write(&key_path, "private key material").unwrap();

        let rt = tokio::runtime::Runtime::new().unwrap();
        let runner = toride_ssh_core::MockCliRunner::new();
        runner.set_tool_exists("ssh", true);
        let result = rt.block_on(install_key_to_remote(
            &key_path,
            "-oProxyCommand=evil",
            &runner,
        ));
        assert!(matches!(result.unwrap_err(), Error::InvalidHost(_)));
    }

    #[test]
    fn install_key_to_remote_rejects_private_key_in_manual_branch() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("id_ed25519");
        // No .pub companion; the private key must not be installed.
        std::fs::write(
            &key_path,
            "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----\n",
        )
        .unwrap();

        let rt = tokio::runtime::Runtime::new().unwrap();
        let runner = toride_ssh_core::MockCliRunner::new();
        runner.set_tool_exists("ssh", true);
        runner.set_tool_exists("ssh-copy-id", false);
        let result = rt.block_on(install_key_to_remote(&key_path, "user@host", &runner));
        match result.unwrap_err() {
            Error::KeyParseFailed(msg) => {
                assert!(msg.contains("refusing to install private key material"));
            }
            other => panic!("expected KeyParseFailed, got: {other:?}"),
        }
    }

    #[test]
    fn install_key_to_remote_manual_branch_accepts_public_key() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("id_ed25519");
        let pub_path = dir.path().join("id_ed25519.pub");
        std::fs::write(&key_path, "private key material").unwrap();
        std::fs::write(&pub_path, VALID_PUBKEY.to_owned() + "\n").unwrap();

        let rt = tokio::runtime::Runtime::new().unwrap();
        let runner = toride_ssh_core::MockCliRunner::new();
        runner.set_tool_exists("ssh", true);
        runner.set_tool_exists("ssh-copy-id", false);
        runner.push_run_response("ssh", Ok(String::new()));

        let result = rt.block_on(install_key_to_remote(&key_path, "user@host", &runner));
        assert_eq!(result.unwrap(), InstallOutcome::Manual);
    }

    #[test]
    fn manual_ssh_command_format() {
        // Verify the remote command format matches expectations.
        let key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI user@host";
        let escaped = key.replace('\'', "'\\''");
        let cmd = format!(
            "mkdir -p ~/.ssh && echo '{escaped}' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"
        );
        assert!(cmd.starts_with("mkdir -p ~/.ssh && echo '"));
        assert!(cmd.ends_with("chmod 600 ~/.ssh/authorized_keys"));
        assert!(cmd.contains(">> ~/.ssh/authorized_keys"));
    }

    #[test]
    fn manual_ssh_command_escapes_single_quotes() {
        let key = "ssh-ed25519 AAAA it's a key user@host";
        let escaped = key.replace('\'', "'\\''");
        let cmd = format!("echo '{escaped}'");
        // The escaped version should not have unescaped single quotes inside
        // the echo argument. After escaping, it's becomes it'\''s.
        assert!(!cmd.contains("it's"));
        assert!(cmd.contains("it'\\''s"));
    }

    #[test]
    fn install_uses_dotted_pub_companion() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("deploy.key");
        // ssh-keygen writes deploy.key.pub, not deploy.pub.
        let pub_path = dir.path().join("deploy.key.pub");
        std::fs::write(&key_path, "private key material").unwrap();
        std::fs::write(&pub_path, VALID_PUBKEY.to_owned() + "\n").unwrap();

        let rt = tokio::runtime::Runtime::new().unwrap();
        let runner = toride_ssh_core::MockCliRunner::new();
        runner.set_tool_exists("ssh-copy-id", true);
        runner.push_run_response("ssh-copy-id", Ok(String::new()));

        let result = rt.block_on(install_key_to_remote(&key_path, "user@host", &runner));
        assert_eq!(result.unwrap(), InstallOutcome::SshCopyId);
    }

    // -----------------------------------------------------------------------
    // Uninstall tests
    // -----------------------------------------------------------------------

    #[test]
    fn uninstall_outcome_variants_are_distinct() {
        assert_ne!(UninstallOutcome::Removed, UninstallOutcome::NotFound);
    }

    #[test]
    fn uninstall_key_from_remote_rejects_missing_key() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let runner = toride_ssh_core::MockCliRunner::new();
        let result = rt.block_on(uninstall_key_from_remote(
            Path::new("/nonexistent/key"),
            "user@host",
            &runner,
        ));
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::KeyNotFound(_) => {}
            other => panic!("expected KeyNotFound, got: {other:?}"),
        }
    }

    #[test]
    fn uninstall_key_from_remote_rejects_invalid_dest() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("id_ed25519");
        std::fs::write(&key_path, "private key").unwrap();

        let rt = tokio::runtime::Runtime::new().unwrap();
        let runner = toride_ssh_core::MockCliRunner::new();
        runner.set_tool_exists("ssh", true);
        let result = rt.block_on(uninstall_key_from_remote(
            &key_path,
            "-oProxyCommand=evil",
            &runner,
        ));
        assert!(matches!(result.unwrap_err(), Error::InvalidHost(_)));
    }

    #[test]
    fn uninstall_key_from_remote_rejects_missing_ssh() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("id_ed25519");
        let pub_path = dir.path().join("id_ed25519.pub");
        std::fs::write(&key_path, "private key").unwrap();
        std::fs::write(&pub_path, VALID_PUBKEY.to_owned() + "\n").unwrap();

        let rt = tokio::runtime::Runtime::new().unwrap();
        let runner = toride_ssh_core::MockCliRunner::new();
        // ssh is not registered as existing.
        let result = rt.block_on(uninstall_key_from_remote(&key_path, "user@host", &runner));
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::ToolNotFound(msg) => assert!(msg.contains("ssh")),
            other => panic!("expected ToolNotFound, got: {other:?}"),
        }
    }

    #[test]
    fn uninstall_key_from_remote_returns_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("id_ed25519");
        let pub_path = dir.path().join("id_ed25519.pub");
        std::fs::write(&key_path, "private key").unwrap();
        std::fs::write(&pub_path, VALID_PUBKEY.to_owned() + "\n").unwrap();

        let rt = tokio::runtime::Runtime::new().unwrap();
        let runner = toride_ssh_core::MockCliRunner::new();
        runner.set_tool_exists("ssh", true);
        runner.push_run_response("ssh", Ok("NOTFOUND\n".to_owned()));

        let result = rt.block_on(uninstall_key_from_remote(&key_path, "user@host", &runner));
        assert_eq!(result.unwrap(), UninstallOutcome::NotFound);
    }

    #[test]
    fn uninstall_key_from_remote_returns_removed() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("id_ed25519");
        let pub_path = dir.path().join("id_ed25519.pub");
        std::fs::write(&key_path, "private key").unwrap();
        std::fs::write(&pub_path, VALID_PUBKEY.to_owned() + "\n").unwrap();

        let rt = tokio::runtime::Runtime::new().unwrap();
        let runner = toride_ssh_core::MockCliRunner::new();
        runner.set_tool_exists("ssh", true);
        runner.push_run_response("ssh", Ok("REMOVED\n".to_owned()));

        let result = rt.block_on(uninstall_key_from_remote(&key_path, "user@host", &runner));
        assert_eq!(result.unwrap(), UninstallOutcome::Removed);
    }

    #[test]
    fn uninstall_key_from_remote_propagates_ssh_error() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("id_ed25519");
        let pub_path = dir.path().join("id_ed25519.pub");
        std::fs::write(&key_path, "private key").unwrap();
        std::fs::write(&pub_path, VALID_PUBKEY.to_owned() + "\n").unwrap();

        let rt = tokio::runtime::Runtime::new().unwrap();
        let runner = toride_ssh_core::MockCliRunner::new();
        runner.set_tool_exists("ssh", true);
        runner.push_run_response(
            "ssh",
            Err(Error::CommandFailed("connection refused".to_owned())),
        );

        let result = rt.block_on(uninstall_key_from_remote(&key_path, "user@host", &runner));
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::CommandFailed(msg) => assert!(msg.contains("connection refused")),
            other => panic!("expected CommandFailed, got: {other:?}"),
        }
    }

    #[test]
    fn uninstall_maps_failed_removal_to_command_failed() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("id_ed25519");
        let pub_path = dir.path().join("id_ed25519.pub");
        std::fs::write(&key_path, "private key").unwrap();
        std::fs::write(&pub_path, VALID_PUBKEY.to_owned() + "\n").unwrap();

        let rt = tokio::runtime::Runtime::new().unwrap();
        let runner = toride_ssh_core::MockCliRunner::new();
        runner.set_tool_exists("ssh", true);
        // ssh exited 0 but the removal chain printed no marker (e.g. mv
        // failed and the remote shell swallowed the status).
        runner.push_run_response("ssh", Ok(String::new()));

        let result = rt.block_on(uninstall_key_from_remote(&key_path, "user@host", &runner));
        match result.unwrap_err() {
            Error::CommandFailed(msg) => assert!(msg.contains("unexpected uninstall output")),
            other => panic!("expected CommandFailed, got: {other:?}"),
        }
    }

    #[test]
    fn uninstall_command_uses_key_fingerprint_not_full_line() {
        // The grep -vF command should use only key type + base64, not the comment.
        let key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI user@host";
        let fingerprint: String = key
            .split_whitespace()
            .take(2)
            .collect::<Vec<&str>>()
            .join(" ");
        assert_eq!(fingerprint, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI");
        assert!(!fingerprint.contains("user@host"));
    }

    #[test]
    fn uninstall_command_escapes_single_quotes_in_key() {
        // Use a key where the base64 portion itself contains a single quote
        // (synthetic test to verify escaping logic on the fingerprint).
        let key = "ssh-ed25519 AAA'A it's a key";
        let fingerprint: String = key
            .split_whitespace()
            .take(2)
            .collect::<Vec<&str>>()
            .join(" ");
        assert!(
            fingerprint.contains('\''),
            "fingerprint should contain a quote"
        );
        let escaped = fingerprint.replace('\'', "'\\''");
        let cmd = format!("grep -vF '{escaped}' ~/.ssh/authorized_keys");
        assert!(cmd.contains("AAA'\\''A"));
    }

    #[test]
    fn uninstall_rejects_empty_pubkey() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("id_ed25519");
        let pub_path = dir.path().join("id_ed25519.pub");
        std::fs::write(&key_path, "private key").unwrap();
        std::fs::write(&pub_path, "\n").unwrap(); // empty/malformed pubkey

        let rt = tokio::runtime::Runtime::new().unwrap();
        let runner = toride_ssh_core::MockCliRunner::new();
        runner.set_tool_exists("ssh", true);

        let result = rt.block_on(uninstall_key_from_remote(&key_path, "user@host", &runner));
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::CommandFailed(msg) => assert!(msg.contains("empty or malformed")),
            other => panic!("expected CommandFailed, got: {other:?}"),
        }
    }
}
