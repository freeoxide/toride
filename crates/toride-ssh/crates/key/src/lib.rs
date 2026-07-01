mod generate;
pub mod install;
mod inventory;
mod repair;

pub use install::InstallOutcome;
pub use install::UninstallOutcome;

use std::ffi::OsStr;

use toride_ssh_core::SshPaths;
use toride_ssh_core::{Error, KeyCreateParams, KeyDeleteParams, KeyFormat, Result, SshKey};

/// Maximum allowed key name length (typical filesystem limit).
const MAX_KEY_NAME_LENGTH: usize = 255;

/// Get Unix file permissions from metadata.
#[cfg(unix)]
pub(crate) fn get_permissions(path: &std::path::Path) -> Option<toride_ssh_core::Permissions> {
    use std::os::unix::fs::PermissionsExt;
    let metadata = std::fs::metadata(path).ok()?;
    let mode = metadata.permissions().mode();
    // Only keep the lower 12 bits (rwx + setuid/setgid/sticky)
    Some(toride_ssh_core::Permissions {
        mode: mode & 0o7777,
    })
}

#[cfg(not(unix))]
pub(crate) fn get_permissions(_path: &std::path::Path) -> Option<toride_ssh_core::Permissions> {
    None
}

/// Validate a key name to prevent path traversal attacks.
///
/// Key names must not contain path separators, `..` components, or null bytes.
/// Maximum length is 255 bytes (typical filesystem limit).
fn validate_key_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(Error::InvalidKeyName(
            "key name must not be empty".to_owned(),
        ));
    }
    if name.len() > MAX_KEY_NAME_LENGTH {
        return Err(Error::InvalidKeyName(format!(
            "key name must not exceed {MAX_KEY_NAME_LENGTH} bytes"
        )));
    }
    if name.contains('\0') {
        return Err(Error::InvalidKeyName(
            "key name must not contain null bytes".to_owned(),
        ));
    }
    if name.contains('/') || name.contains('\\') {
        return Err(Error::InvalidKeyName(
            "key name must not contain path separators".to_owned(),
        ));
    }
    if name.contains("..") {
        return Err(Error::InvalidKeyName(
            "key name must not contain '..'".to_owned(),
        ));
    }
    Ok(())
}

/// Return a unique backup path by appending a Unix timestamp suffix if the
/// path already exists.  For example, if `foo.bak` exists, returns
/// `foo.bak.1717020000`.
fn unique_backup_path(base: &std::path::Path) -> std::path::PathBuf {
    if !base.exists() {
        return base.to_path_buf();
    }
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let ext = match base.extension() {
        Some(e) => format!("{}.{}", e.to_string_lossy(), ts),
        None => ts.to_string(),
    };
    base.with_extension(ext)
}

/// Key management operations.
///
/// Obtained from [`SshManager::keys()`](crate::SshManager::keys).
pub struct KeyService<'a> {
    paths: &'a SshPaths,
    runner: &'a dyn toride_ssh_core::CliRunner,
}

impl<'a> KeyService<'a> {
    pub fn new(paths: &'a SshPaths, runner: &'a dyn toride_ssh_core::CliRunner) -> Self {
        Self { paths, runner }
    }

    /// List all SSH keys found on disk and in the agent.
    ///
    /// Scans `~/.ssh/id_*` files and queries the SSH agent via `ssh-add -l`.
    /// Keys that cannot be parsed are skipped with a warning.
    ///
    /// # Errors
    ///
    /// Returns [`Error::TaskFailed`] if the background scan task panics
    /// or is cancelled.
    pub async fn list(&self) -> Result<Vec<SshKey>> {
        inventory::scan_keys(self.paths, Some(self.runner)).await
    }

    /// Generate a new SSH key pair.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidKeyName`] if the key name is invalid
    /// (empty, contains path separators or null bytes, or exceeds 255 bytes),
    /// [`Error::ToolNotFound`] if `ssh-keygen` is not in `PATH`, or
    /// [`Error::CommandFailed`] if key generation fails.
    pub async fn create(&self, params: KeyCreateParams) -> Result<SshKey> {
        validate_key_name(&params.name)?;
        generate::generate_key(self.paths, params, self.runner).await
    }

    /// Delete a key and optionally its public pair, certificate, agent entry, and config refs.
    ///
    /// # Errors
    ///
    /// Returns [`Error::KeyNotFound`] if the key does not exist,
    /// [`Error::InvalidKeyName`] if the key name is invalid,
    /// [`Error::Io`] if file operations fail, [`Error::TaskFailed`] if
    /// the background deletion task panics, or
    /// [`Error::ConfigWriteFailed`] if config cleanup fails.
    pub async fn delete(&self, params: KeyDeleteParams) -> Result<()> {
        validate_key_name(&params.name)?;
        let private_path = self.paths.ssh_dir().join(&params.name);

        if !private_path.exists() {
            return Err(Error::KeyNotFound(params.name.clone()));
        }

        let public_path = private_path.with_extension("pub");

        let cert_path = self
            .paths
            .ssh_dir()
            .join(format!("{}-cert.pub", params.name));

        // Destructure to avoid cloning the entire params struct into spawn_blocking.
        let backup = params.backup;
        let remove_public = params.remove_public;
        let remove_certificate = params.remove_certificate;

        // Remove from agent if requested (non-fatal).
        // Must happen BEFORE the file is deleted/renamed so that ssh-add -d
        // can still reference the original path.
        if params.remove_from_agent {
            remove_key_from_agent(&self.paths.ssh_dir().join(&params.name), self.runner).await;
        }

        tokio::task::spawn_blocking(move || {
            // Backup if requested
            if backup {
                let backup_path = unique_backup_path(&private_path.with_extension("bak"));
                std::fs::rename(&private_path, &backup_path)?;

                if remove_public && public_path.exists() {
                    let stem = public_path
                        .file_stem()
                        .unwrap_or_else(|| OsStr::new(""))
                        .to_string_lossy();
                    let pub_backup_base = public_path.with_file_name(format!("{stem}.pub.bak"));
                    let pub_backup = unique_backup_path(&pub_backup_base);
                    if let Err(e) = std::fs::rename(&public_path, &pub_backup) {
                        tracing::warn!("failed to backup {}: {e}", public_path.display());
                    }
                }

                if remove_certificate && cert_path.exists() {
                    let name = cert_path
                        .file_name()
                        .unwrap_or_else(|| OsStr::new(""))
                        .to_string_lossy();
                    let cert_backup_base = cert_path.with_file_name(format!("{name}.bak"));
                    let cert_backup = unique_backup_path(&cert_backup_base);
                    if let Err(e) = std::fs::rename(&cert_path, &cert_backup) {
                        tracing::warn!("failed to backup {}: {e}", cert_path.display());
                    }
                }
            } else {
                // Remove the private key file
                std::fs::remove_file(&private_path)?;

                // Remove public key companion
                if remove_public && public_path.exists() {
                    std::fs::remove_file(&public_path)?;
                }

                // Remove certificate companion
                if remove_certificate && cert_path.exists() {
                    std::fs::remove_file(&cert_path)?;
                }
            }

            Ok::<(), Error>(())
        })
        .await
        .map_err(|e| Error::TaskFailed(format!("delete task failed: {e}")))??;

        // Remove from config if requested
        if params.remove_from_config {
            remove_from_config(self.paths, &params.name).await?;
        }

        Ok(())
    }

    /// Derive the `.pub` file from a private key.
    ///
    /// First attempts an in-process parse. For encrypted keys, falls back to
    /// `ssh-keygen -y -f <path>` to extract the public key and writes it to
    /// the corresponding `.pub` file.
    ///
    /// # Errors
    ///
    /// Returns [`Error::KeyNotFound`] if the private key does not exist,
    /// [`Error::ToolNotFound`] if `ssh-keygen` is not in `PATH`, or
    /// [`Error::CommandFailed`] if public key extraction fails (e.g.
    /// the key is encrypted and no passphrase was provided).
    pub async fn repair_public(
        &self,
        private_key_path: &std::path::Path,
        passphrase: Option<&str>,
    ) -> Result<()> {
        repair::repair_public_key(private_key_path, passphrase, self.runner).await
    }

    /// Rename a key pair (private, public, certificate).
    ///
    /// Renames `~/.ssh/<old_name>` to `~/.ssh/<new_name>` and all companion
    /// files (`.pub`, `-cert.pub`). Does NOT update config references — call
    /// `remove_from_config` for the old name and add new `IdentityFile` entries
    /// separately.
    ///
    /// If the private key rename succeeds but the public key or certificate
    /// rename fails, the operation continues with a warning. This may leave
    /// the key pair in an inconsistent state where the private key has the
    /// new name but the public key retains the old name.
    ///
    /// # Errors
    ///
    /// Returns [`Error::KeyNotFound`] if the old key does not exist,
    /// [`Error::KeyExists`] if a key with the new name already exists,
    /// [`Error::InvalidKeyName`] if either name is invalid, or
    /// [`Error::Io`] if the private key rename fails.
    pub async fn rename(&self, old_name: &str, new_name: &str) -> Result<()> {
        validate_key_name(old_name)?;
        validate_key_name(new_name)?;

        let old_private = self.paths.ssh_dir().join(old_name);
        let new_private = self.paths.ssh_dir().join(new_name);

        if !old_private.exists() {
            return Err(Error::KeyNotFound(old_name.to_owned()));
        }
        if new_private.exists() {
            return Err(Error::KeyExists(new_name.to_owned()));
        }

        let old_public = old_private.with_extension("pub");
        let new_public = new_private.with_extension("pub");
        let old_cert = self.paths.ssh_dir().join(format!("{old_name}-cert.pub"));
        let new_cert = self.paths.ssh_dir().join(format!("{new_name}-cert.pub"));

        tokio::task::spawn_blocking(move || {
            // Rename private key
            std::fs::rename(&old_private, &new_private).map_err(Error::Io)?;

            // Rename public key if it exists
            if old_public.exists()
                && let Err(e) = std::fs::rename(&old_public, &new_public)
            {
                tracing::warn!("failed to rename public key: {e}");
            }

            // Rename certificate if it exists
            if old_cert.exists()
                && let Err(e) = std::fs::rename(&old_cert, &new_cert)
            {
                tracing::warn!("failed to rename certificate: {e}");
            }

            Ok(())
        })
        .await
        .map_err(|e| Error::TaskFailed(format!("rename task failed: {e}")))?
    }

    /// Fix permissions on key files (set private keys to 0o600, public to 0o644).
    ///
    /// # Errors
    ///
    /// Returns [`Error::KeyNotFound`] if the key does not exist,
    /// [`Error::InvalidKeyName`] if the key name is invalid, or
    /// [`Error::Io`] if `chmod` fails.
    pub async fn chmod_fix(&self, key_name: &str) -> Result<()> {
        validate_key_name(key_name)?;

        let private_path = self.paths.ssh_dir().join(key_name);
        if !private_path.exists() {
            return Err(Error::KeyNotFound(key_name.to_owned()));
        }

        let public_path = private_path.with_extension("pub");

        tokio::task::spawn_blocking(move || {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&private_path, std::fs::Permissions::from_mode(0o600))
                    .map_err(Error::Io)?;

                if public_path.exists()
                    && let Err(e) = std::fs::set_permissions(
                        &public_path,
                        std::fs::Permissions::from_mode(0o644),
                    )
                {
                    tracing::warn!("failed to set public key permissions: {e}");
                }
            }
            #[cfg(not(unix))]
            {
                let _ = (private_path, public_path);
            }
            Ok(())
        })
        .await
        .map_err(|e| Error::TaskFailed(format!("chmod task failed: {e}")))?
    }

    /// Change the passphrase on an existing key (`ssh-keygen -p`).
    ///
    /// If `old_passphrase` is `None`, the key is assumed to be unencrypted.
    /// If `new_passphrase` is `None` or empty, the passphrase is removed.
    ///
    /// # Security
    ///
    /// Neither the old nor the new passphrase is ever placed on the
    /// `ssh-keygen` argv. `ssh-keygen -p` is invoked WITHOUT `-P`/`-N` so it
    /// prompts for the passphrases, and they are fed through a temporary
    /// `SSH_ASKPASS` helper script — the same approach used by
    /// [`Self::create`](Self::create)/[`generate_key`](crate::generate). The
    /// passphrase therefore never appears in `argv` or `/proc/<pid>/cmdline`,
    /// unlike the old `-P <old> -N <new>` approach which exposed it to every
    /// local user via `ps` for the lifetime of the `ssh-keygen` process.
    ///
    /// # Errors
    ///
    /// Returns [`Error::KeyNotFound`] if the key file does not exist, or
    /// [`Error::CommandFailed`] if the passphrase change fails (e.g. wrong
    /// old passphrase).
    pub async fn change_passphrase(
        &self,
        key_path: &std::path::Path,
        old_passphrase: Option<&str>,
        new_passphrase: Option<&str>,
    ) -> Result<()> {
        if !key_path.exists() {
            return Err(Error::KeyNotFound(key_path.display().to_string()));
        }

        let path_str = key_path
            .to_str()
            .ok_or_else(|| Error::CommandFailed("key path is not valid UTF-8".to_owned()))?
            .to_owned();

        let old_pass = old_passphrase.unwrap_or("").to_owned();
        let new_pass = new_passphrase.unwrap_or("").to_owned();

        // `ssh-keygen -p` (with no `-P`/`-N`) prompts THREE times when run via
        // SSH_ASKPASS: "Enter old passphrase", "Enter new passphrase", then
        // "Enter same passphrase again" (confirmation). The askpass helper is
        // invoked once per prompt, so it must answer old, new, new in order.
        // A single-value askpass (like the one used for key generation) is not
        // sufficient here.
        let askpass = MultiAskpassHandler::new(&[&old_pass, &new_pass, &new_pass])?;
        let args = vec!["-p".to_owned(), "-f".to_owned(), path_str];
        run_with_askpass(self.runner, "ssh-keygen", args, &askpass).await?;

        Ok(())
    }

    /// Change the comment on an existing key (`ssh-keygen -c`).
    ///
    /// Updates both the private and public key files.
    ///
    /// # Security
    ///
    /// When a passphrase is supplied it is fed to `ssh-keygen` through a
    /// temporary `SSH_ASKPASS` helper script (the same mechanism used by
    /// [`Self::create`](Self::create)) rather than as `-P <passphrase>` on the
    /// argv, so it never appears in `/proc/<pid>/cmdline` or `ps`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::KeyNotFound`] if the key file does not exist, or
    /// [`Error::CommandFailed`] if the comment change fails.
    pub async fn change_comment(
        &self,
        key_path: &std::path::Path,
        new_comment: &str,
        passphrase: Option<&str>,
    ) -> Result<()> {
        if !key_path.exists() {
            return Err(Error::KeyNotFound(key_path.display().to_string()));
        }

        let path_str = key_path
            .to_str()
            .ok_or_else(|| Error::CommandFailed("key path is not valid UTF-8".to_owned()))?
            .to_owned();

        let pass = passphrase.unwrap_or("");

        let args = vec![
            "-c".to_owned(),
            "-f".to_owned(),
            path_str,
            "-C".to_owned(),
            new_comment.to_owned(),
        ];

        // `ssh-keygen -c` prompts once for the passphrase when the key is
        // encrypted; a single-value askpass handler suffices.
        if pass.is_empty() {
            self.runner.run("ssh-keygen", args).await?;
        } else {
            let askpass = toride_ssh_agent::AskpassHandler::new(pass)?;
            run_with_askpass(self.runner, "ssh-keygen", args, &askpass).await?;
        }
        Ok(())
    }

    /// Convert a key between OpenSSH and PEM formats.
    ///
    /// - [`KeyFormat::Pem`]: exports the key in PEM format via `ssh-keygen -e -m PEM`.
    /// - [`KeyFormat::OpenSSH`]: imports a PEM-format key to OpenSSH format via `ssh-keygen -i -m PEM`.
    ///
    /// Returns the converted key content as a string.
    ///
    /// # Errors
    ///
    /// Returns [`Error::KeyNotFound`] if the key file does not exist,
    /// [`Error::ToolNotFound`] if `ssh-keygen` is not available, or
    /// [`Error::CommandFailed`] if the conversion command fails.
    pub async fn convert(
        &self,
        key_path: &std::path::Path,
        target_format: KeyFormat,
    ) -> Result<String> {
        if !key_path.exists() {
            return Err(Error::KeyNotFound(key_path.display().to_string()));
        }

        if !self.runner.tool_exists("ssh-keygen") {
            return Err(Error::ToolNotFound("ssh-keygen".to_owned()));
        }

        let path_str = key_path
            .to_str()
            .ok_or_else(|| Error::CommandFailed("key path is not valid UTF-8".to_owned()))?
            .to_owned();

        let args = match target_format {
            KeyFormat::Pem => vec![
                "-e".to_owned(),
                "-m".to_owned(),
                "PEM".to_owned(),
                "-f".to_owned(),
                path_str,
            ],
            KeyFormat::OpenSSH => vec![
                "-i".to_owned(),
                "-m".to_owned(),
                "PEM".to_owned(),
                "-f".to_owned(),
                path_str,
            ],
        };

        self.runner.run("ssh-keygen", args).await
    }

    /// Install a public key to a remote host's `authorized_keys`.
    ///
    /// Uses `ssh-copy-id` if available, otherwise falls back to manual SSH.
    /// See [`install::install_key_to_remote`] for details.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ToolNotFound`] if neither `ssh-copy-id` nor `ssh`
    /// is available, [`Error::CommandFailed`] if the installation command
    /// fails, or [`Error::KeyNotFound`] if the key path does not exist.
    pub async fn install_key_to_remote(
        &self,
        key_path: &std::path::Path,
        dest: &str,
    ) -> Result<install::InstallOutcome> {
        install::install_key_to_remote(key_path, dest, self.runner).await
    }

    /// Remove a public key from a remote host's `authorized_keys`.
    ///
    /// `SSHes` into the remote and uses `grep -vF` to strip the matching key
    /// line from `~/.ssh/authorized_keys`. See
    /// [`install::uninstall_key_from_remote`] for details.
    ///
    /// # Errors
    ///
    /// Returns [`Error::KeyNotFound`] if the key path does not exist,
    /// [`Error::ToolNotFound`] if `ssh` is not available, or
    /// [`Error::CommandFailed`] if the remote command fails.
    pub async fn uninstall_key_from_remote(
        &self,
        key_path: &std::path::Path,
        dest: &str,
    ) -> Result<install::UninstallOutcome> {
        install::uninstall_key_from_remote(key_path, dest, self.runner).await
    }
}

/// An `SSH_ASKPASS` helper whose lifecycle is owned by the caller.
///
/// Implementors write a temporary executable script to disk that `ssh-keygen`
/// (or another SSH tool) reads passphrases from via `SSH_ASKPASS`, and remove
/// it again on drop. The passphrase(s) are thus kept out of the child process
/// `argv` and `/proc/<pid>/cmdline`.
pub(crate) trait Askpass {
    /// Path to the on-disk askpass script.
    fn script_path(&self) -> &std::path::Path;
}

impl Askpass for toride_ssh_agent::AskpassHandler {
    fn script_path(&self) -> &std::path::Path {
        toride_ssh_agent::AskpassHandler::script_path(self)
    }
}

/// Run `cmd` with `args` and the askpass environment wired so that passphrase
/// prompts are answered by `askpass` instead of appearing on the argv.
///
/// Centralizes the `SSH_ASKPASS`/`SSH_ASKPASS_REQUIRE`/`DISPLAY` env wiring
/// shared by [`KeyService::change_passphrase`], [`KeyService::change_comment`],
/// and [`repair::repair_public_key`].
pub(crate) async fn run_with_askpass(
    runner: &dyn toride_ssh_core::CliRunner,
    cmd: &str,
    args: Vec<String>,
    askpass: &dyn Askpass,
) -> Result<String> {
    let env = vec![
        (
            "SSH_ASKPASS".to_owned(),
            askpass.script_path().to_string_lossy().into_owned(),
        ),
        ("SSH_ASKPASS_REQUIRE".to_owned(), "force".to_owned()),
        ("DISPLAY".to_owned(), ":0".to_owned()),
    ];
    runner.run_with_env(cmd, args, env).await
}

/// A multi-response `SSH_ASKPASS` handler.
///
/// [`toride_ssh_agent::AskpassHandler`] always echoes the same passphrase on
/// every invocation, which is correct for tools that prompt once (key
/// generation, `ssh-keygen -c`/`-y`). `ssh-keygen -p`, however, prompts three
/// times when driven via `SSH_ASKPASS` — old, new, new (confirmation) — so the
/// helper must answer a different value per invocation. This handler writes a
/// script that returns `responses[i]` on the `i`-th call (and the last value
/// for any subsequent call, so extra confirmation prompts are still answered).
///
/// The script is created with mode `0o700` and removed on drop, mirroring
/// [`toride_ssh_agent::AskpassHandler`].
struct MultiAskpassHandler {
    script_path: std::path::PathBuf,
}

impl MultiAskpassHandler {
    /// Create a handler that answers the `i`-th askpass invocation with
    /// `responses[i]` (clamped to the last entry).
    ///
    /// # Errors
    ///
    /// Returns [`Error::CommandFailed`] if the temporary script cannot be
    /// written or made executable.
    fn new(responses: &[&str]) -> Result<Self> {
        use std::io::Write;
        #[cfg(unix)]
        use std::os::unix::fs::OpenOptionsExt;

        // Build the script body. Each response is emitted by a dedicated
        // `case` arm keyed on the invocation counter; the fallthrough arm
        // repeats the final response so a confirmation prompt (or any future
        // extra prompt) is still answered with the new passphrase.
        //
        // The invocation counter is persisted in a sibling `.cnt` file (its
        // path is baked into the script, so no extra env wiring is needed).
        use std::fmt::Write as _;
        let mut arms = String::new();
        for (i, resp) in responses.iter().enumerate() {
            // The script increments its counter BEFORE the `case`, so the
            // first invocation is `n=1` — arm indices must be 1-based.
            let arm = i + 1;
            let escaped = resp.replace('\'', "'\\''");
            let _ = writeln!(arms, "    {arm}) echo '{escaped}';;");
        }
        let last_escaped = responses
            .last()
            .map(|r| r.replace('\'', "'\\''"))
            .unwrap_or_default();

        let dir = std::env::temp_dir();
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let pid = std::process::id();
        let tid = format!("{:?}", std::thread::current().id())
            .replace("ThreadId(", "")
            .replace(')', "");
        let filename = format!("toride-askpass-multi-{pid}-{tid}-{ts}");

        // Write via a hidden sibling + atomic rename so the published script
        // is never observed half-written or open-for-writing (avoids
        // ETXTBSY). The temp file is created with its final 0o700 mode via a
        // single O_CREAT|O_EXCL open, so there is no window in which the
        // script exists but is world-readable or non-executable.
        let tmp_path = dir.join(format!("{filename}.tmp"));
        let script_path = dir.join(&filename);
        // Sibling counter file; its path is baked into the script so no extra
        // env wiring is needed. Cleaned up alongside the script on drop.
        let count_path = dir.join(format!("{filename}.cnt"));

        let count_path_str = count_path.to_string_lossy().replace('\'', "'\\''");
        let script = format!(
            "#!/bin/sh\n\
             # Generated by toride-ssh-key: answers SSH_ASKPASS prompts in order.\n\
             n=$(cat '{count_path_str}' 2>/dev/null || echo 0)\n\
             n=$((n+1))\n\
             printf '%s' \"$n\" >'{count_path_str}'\n\
             case \"$n\" in\n\
             {arms}\
             *) echo '{last_escaped}';;\n\
             esac\n"
        );

        #[cfg(unix)]
        {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o700)
                .open(&tmp_path)
                .map_err(|e| {
                    Error::CommandFailed(format!(
                        "failed to create multi-askpass script {}: {e}",
                        tmp_path.display()
                    ))
                })?;
            file.write_all(script.as_bytes()).map_err(|e| {
                Error::CommandFailed(format!(
                    "failed to write multi-askpass script {}: {e}",
                    tmp_path.display()
                ))
            })?;
            let _ = file.sync_all();
            drop(file);
            std::fs::rename(&tmp_path, &script_path).map_err(|e| {
                let _ = std::fs::remove_file(&tmp_path);
                Error::CommandFailed(format!(
                    "failed to publish multi-askpass script {}: {e}",
                    script_path.display()
                ))
            })?;
        }

        // Non-Unix: best-effort plain write (no exec bit needed for the
        // shape of the test, and SSH_ASKPASS is Unix-only in practice).
        #[cfg(not(unix))]
        {
            std::fs::write(&script_path, script.as_bytes()).map_err(|e| {
                Error::CommandFailed(format!(
                    "failed to write multi-askpass script {}: {e}",
                    script_path.display()
                ))
            })?;
        }

        Ok(Self { script_path })
    }

    /// Path to the on-disk askpass script.
    fn script_path(&self) -> &std::path::Path {
        &self.script_path
    }
}

impl Askpass for MultiAskpassHandler {
    fn script_path(&self) -> &std::path::Path {
        self.script_path()
    }
}

impl Drop for MultiAskpassHandler {
    fn drop(&mut self) {
        if let Err(e) = std::fs::remove_file(&self.script_path) {
            tracing::warn!(
                "failed to remove multi-askpass script {}: {e}",
                self.script_path.display()
            );
        }
        // Best-effort cleanup of the sibling counter file.
        let count_path = self.script_path.with_extension("cnt");
        let _ = std::fs::remove_file(&count_path);
    }
}

/// Remove a key from the SSH agent.
///
/// This is intentionally non-fatal: the key may not be loaded in the agent,
/// which is a perfectly normal state. Errors are logged but not propagated.
async fn remove_key_from_agent(
    private_path: &std::path::Path,
    runner: &dyn toride_ssh_core::CliRunner,
) {
    let Some(path_str) = private_path.to_str().map(str::to_owned) else {
        tracing::warn!("invalid key path for ssh-add, skipping agent removal");
        return;
    };

    if let Err(e) = runner.run("ssh-add", vec!["-d".to_owned(), path_str]).await {
        tracing::warn!("ssh-add -d failed (key may not be in agent): {e}");
    }
}

/// Filter `IdentityFile`/`CertificateFile` references to `key_name` out of an
/// SSH config body.
///
/// Pure helper extracted from [`remove_from_config`] so the quote/tilde/CRLF
/// matching logic is unit-testable without a filesystem round-trip. A line is
/// dropped when its leading keyword (matched case-insensitively) is
/// `IdentityFile` (or `CertificateFile`) AND its value — after stripping one
/// layer of surrounding `"` or `'` quotes — equals one of:
///
/// - `~/.ssh/<key_name>` (tilde form) / `~/.ssh/<key_name>-cert.pub`
/// - `<ssh_dir>/<key_name>` (absolute form) / `<ssh_dir>/<key_name>-cert.pub`
/// - the bare `<key_name>` / `<key_name>-cert.pub`
///
/// The original line-ending style (`\r\n` vs `\n`) and any trailing newline
/// are preserved. Lines that merely *contain* the name as a substring, or are
/// comments, are left untouched.
fn filter_config_lines(content: &str, ssh_dir_str: &str, key_name: &str) -> String {
    let key_pattern_tilde = format!("~/.ssh/{key_name}");
    let key_pattern_abs = format!("{ssh_dir_str}/{key_name}");

    // Also match CertificateFile directives for the companion cert.
    let cert_name = format!("{key_name}-cert.pub");
    let cert_pattern_tilde = format!("~/.ssh/{cert_name}");
    let cert_pattern_abs = format!("{ssh_dir_str}/{cert_name}");

    let trailing_newline = content.ends_with('\n');
    // Preserve the original line ending style (\r\n vs \n).
    let line_ending = if content.contains("\r\n") {
        "\r\n"
    } else {
        "\n"
    };

    let new_content: String = content
        .lines()
        .filter(|line| {
            let trimmed = line.trim();
            // Extract the keyword (first whitespace-delimited token) and
            // compare case-insensitively.  This avoids matching directives
            // like "IdentityFileSomething" or comments containing the word.
            let keyword = trimmed.split_whitespace().next().unwrap_or("");

            if keyword.eq_ignore_ascii_case("IdentityFile") {
                // Extract the value (everything after the keyword).
                let value = trimmed[keyword.len()..].trim();
                // Remove quotes if present
                let value = value.trim_matches('"').trim_matches('\'');
                return value != key_pattern_tilde
                    && value != key_pattern_abs
                    && value != key_name;
            }

            if keyword.eq_ignore_ascii_case("CertificateFile") {
                // Extract the value (everything after the keyword).
                let value = trimmed[keyword.len()..].trim();
                // Remove quotes if present
                let value = value.trim_matches('"').trim_matches('\'');
                return value != cert_pattern_tilde
                    && value != cert_pattern_abs
                    && value != cert_name;
            }

            true
        })
        .collect::<Vec<&str>>()
        .join(line_ending);

    // Preserve trailing newline from the original file
    if trailing_newline && !new_content.is_empty() {
        format!("{new_content}{line_ending}")
    } else {
        new_content
    }
}

/// Remove `IdentityFile` references from `~/.ssh/config`.
///
/// This is a basic implementation that removes lines containing the key path.
/// Read errors are non-fatal (the config may be unreadable due to permissions).
async fn remove_from_config(paths: &SshPaths, key_name: &str) -> Result<()> {
    // Allocate an owned PathBuf for use inside `spawn_blocking` (requires `'static`).
    let config_path = paths.config_path().to_path_buf();

    if !config_path.exists() {
        return Ok(());
    }

    let key_name_owned = key_name.to_owned();
    let ssh_dir_str = paths
        .ssh_dir()
        .to_str()
        .ok_or_else(|| {
            Error::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "SSH directory path is not valid UTF-8: {}",
                    paths.ssh_dir().display()
                ),
            ))
        })?
        .to_owned();

    tokio::task::spawn_blocking(move || {
        let content = match std::fs::read_to_string(&config_path) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!("cannot read config for cleanup: {e}");
                return Ok(());
            }
        };

        let final_content = filter_config_lines(&content, &ssh_dir_str, &key_name_owned);

        if final_content != content {
            // Atomic write: temp file + rename to prevent corruption on crash.
            let parent = config_path
                .parent()
                .unwrap_or_else(|| std::path::Path::new("."));
            let tmp_path = parent.join(format!(
                ".config.tmp.{}.{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos()
            ));
            std::fs::write(&tmp_path, &final_content).map_err(|e| {
                Error::ConfigWriteFailed(format!("failed to write temp config: {e}"))
            })?;
            if let Err(e) = std::fs::rename(&tmp_path, &config_path) {
                let _ = std::fs::remove_file(&tmp_path);
                return Err(Error::ConfigWriteFailed(format!(
                    "failed to rename config: {e}"
                )));
            }
        }

        Ok(())
    })
    .await
    .map_err(|e| Error::TaskFailed(format!("config cleanup task failed: {e}")))?
}

#[cfg(test)]
#[path = "mod.test.rs"]
mod tests;
