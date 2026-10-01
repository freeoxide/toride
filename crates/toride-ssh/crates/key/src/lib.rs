mod generate;
pub mod install;
mod inventory;
mod repair;

pub use install::InstallOutcome;
pub use install::UninstallOutcome;

use std::ffi::OsStr;

use toride_ssh_core::SshPaths;
use toride_ssh_core::{Error, KeyCreateParams, KeyDeleteParams, KeyFormat, Result, SshKey};

const MAX_KEY_NAME_LENGTH: usize = 255;

#[cfg(unix)]
pub(crate) fn get_permissions(path: &std::path::Path) -> Option<toride_ssh_core::Permissions> {
    use std::os::unix::fs::PermissionsExt;
    let metadata = std::fs::metadata(path).ok()?;
    let mode = metadata.permissions().mode();
    Some(toride_ssh_core::Permissions {
        mode: mode & 0o7777,
    })
}

#[cfg(not(unix))]
pub(crate) fn get_permissions(_path: &std::path::Path) -> Option<toride_ssh_core::Permissions> {
    None
}

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

pub struct KeyService<'a> {
    paths: &'a SshPaths,
    runner: &'a dyn toride_ssh_core::CliRunner,
}

/// Inspect a private key file, memoized on its `(mtime, len)` stamp (rewrites re-parse).
/// # Errors
/// Same as the uncached parse; read errors are never memoized.
pub fn inspect_key_cached(path: &std::path::Path) -> Result<SshKey> {
    inventory::inspect_private_key_cached(path)
}

impl<'a> KeyService<'a> {
    pub fn new(paths: &'a SshPaths, runner: &'a dyn toride_ssh_core::CliRunner) -> Self {
        Self { paths, runner }
    }

    /// List all SSH keys on disk and in the agent; unparseable keys are skipped.
    /// # Errors
    /// [`Error::TaskFailed`] if the background scan task panics or is cancelled.
    pub async fn list(&self) -> Result<Vec<SshKey>> {
        inventory::scan_keys(self.paths, Some(self.runner)).await
    }

    /// Generate a new SSH key pair.
    /// # Errors
    /// [`Error::InvalidKeyName`] (bad name), [`Error::ToolNotFound`], [`Error::CommandFailed`].
    pub async fn create(&self, params: KeyCreateParams) -> Result<SshKey> {
        validate_key_name(&params.name)?;
        generate::generate_key(self.paths, params, self.runner).await
    }

    /// Delete a key and optionally its companions, agent entry, and config refs.
    /// # Errors
    /// [`Error::KeyNotFound`], [`Error::InvalidKeyName`], [`Error::Io`], [`Error::TaskFailed`], [`Error::ConfigWriteFailed`].
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

        let backup = params.backup;
        let remove_public = params.remove_public;
        let remove_certificate = params.remove_certificate;

        if params.remove_from_agent {
            remove_key_from_agent(&self.paths.ssh_dir().join(&params.name), self.runner).await;
        }

        tokio::task::spawn_blocking(move || {
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
                std::fs::remove_file(&private_path)?;

                if remove_public && public_path.exists() {
                    std::fs::remove_file(&public_path)?;
                }

                if remove_certificate && cert_path.exists() {
                    std::fs::remove_file(&cert_path)?;
                }
            }

            Ok::<(), Error>(())
        })
        .await
        .map_err(|e| Error::TaskFailed(format!("delete task failed: {e}")))??;

        if params.remove_from_config {
            remove_from_config(self.paths, &params.name).await?;
        }

        Ok(())
    }

    /// Derive the `.pub` from a private key (encrypted keys via `ssh-keygen -y`).
    /// # Errors
    /// [`Error::KeyNotFound`], [`Error::ToolNotFound`], or [`Error::CommandFailed`].
    pub async fn repair_public(
        &self,
        private_key_path: &std::path::Path,
        passphrase: Option<&str>,
    ) -> Result<()> {
        repair::repair_public_key(private_key_path, passphrase, self.runner).await
    }

    /// Rename a key pair and companions; config refs NOT updated; companion failures non-fatal.
    /// # Errors
    /// [`Error::KeyNotFound`], [`Error::KeyExists`], [`Error::InvalidKeyName`], [`Error::Io`].
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
            std::fs::rename(&old_private, &new_private).map_err(Error::Io)?;

            if old_public.exists()
                && let Err(e) = std::fs::rename(&old_public, &new_public)
            {
                tracing::warn!("failed to rename public key: {e}");
            }

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

    /// Fix key file permissions (private `0o600`, public `0o644`).
    /// # Errors
    /// [`Error::KeyNotFound`], [`Error::InvalidKeyName`], or [`Error::Io`].
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

    /// Change a key's passphrase (`None`/empty new removes it) via `SSH_ASKPASS`, never argv.
    /// # Errors
    /// [`Error::KeyNotFound`] or [`Error::CommandFailed`] (e.g. wrong old passphrase).
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

        let askpass = MultiAskpassHandler::new(&[&old_pass, &new_pass, &new_pass])?;
        let args = vec!["-p".to_owned(), "-f".to_owned(), path_str];
        run_with_askpass(self.runner, "ssh-keygen", args, &askpass).await?;

        Ok(())
    }

    /// Change a key's comment (`ssh-keygen -c`); a passphrase goes via `SSH_ASKPASS`, never argv.
    /// # Errors
    /// [`Error::KeyNotFound`] or [`Error::CommandFailed`].
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

        if pass.is_empty() {
            self.runner.run("ssh-keygen", args).await?;
        } else {
            let askpass = toride_ssh_agent::AskpassHandler::new(pass)?;
            run_with_askpass(self.runner, "ssh-keygen", args, &askpass).await?;
        }
        Ok(())
    }

    /// Convert a key between OpenSSH and PEM formats, returning the content.
    /// # Errors
    /// [`Error::KeyNotFound`], [`Error::ToolNotFound`], or [`Error::CommandFailed`].
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

    /// Install a public key to a remote's `authorized_keys` via `ssh-copy-id` (or plain SSH).
    /// # Errors
    /// [`Error::ToolNotFound`], [`Error::CommandFailed`], or [`Error::KeyNotFound`].
    pub async fn install_key_to_remote(
        &self,
        key_path: &std::path::Path,
        dest: &str,
    ) -> Result<install::InstallOutcome> {
        install::install_key_to_remote(key_path, dest, self.runner).await
    }

    /// Remove a public key from a remote host's `authorized_keys`.
    /// # Errors
    /// [`Error::KeyNotFound`], [`Error::ToolNotFound`], or [`Error::CommandFailed`].
    pub async fn uninstall_key_from_remote(
        &self,
        key_path: &std::path::Path,
        dest: &str,
    ) -> Result<install::UninstallOutcome> {
        install::uninstall_key_from_remote(key_path, dest, self.runner).await
    }
}

pub(crate) trait Askpass {
    fn script_path(&self) -> &std::path::Path;
}

impl Askpass for toride_ssh_agent::AskpassHandler {
    fn script_path(&self) -> &std::path::Path {
        toride_ssh_agent::AskpassHandler::script_path(self)
    }
}

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

struct MultiAskpassHandler {
    script_path: std::path::PathBuf,
}

impl MultiAskpassHandler {
    fn new(responses: &[&str]) -> Result<Self> {
        #[cfg(unix)]
        use std::io::Write;
        #[cfg(unix)]
        use std::os::unix::fs::OpenOptionsExt;

        use std::fmt::Write as _;
        let mut arms = String::new();
        for (i, resp) in responses.iter().enumerate() {
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

        // Publish via hidden temp + atomic rename: an in-place rewrite can be seen
        // half-written or open-for-writing (ETXTBSY); the single O_EXCL open carries
        // the final 0o700 mode (open(2)).
        #[cfg(unix)]
        let tmp_path = dir.join(format!("{filename}.tmp"));
        let script_path = dir.join(&filename);
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
        let count_path = self.script_path.with_extension("cnt");
        let _ = std::fs::remove_file(&count_path);
    }
}

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

fn filter_config_lines(content: &str, ssh_dir_str: &str, key_name: &str) -> String {
    let key_pattern_tilde = format!("~/.ssh/{key_name}");
    let key_pattern_abs = format!("{ssh_dir_str}/{key_name}");

    let cert_name = format!("{key_name}-cert.pub");
    let cert_pattern_tilde = format!("~/.ssh/{cert_name}");
    let cert_pattern_abs = format!("{ssh_dir_str}/{cert_name}");

    let trailing_newline = content.ends_with('\n');
    let line_ending = if content.contains("\r\n") {
        "\r\n"
    } else {
        "\n"
    };

    let new_content: String = content
        .lines()
        .filter(|line| {
            let trimmed = line.trim();
            let keyword = trimmed.split_whitespace().next().unwrap_or("");

            if keyword.eq_ignore_ascii_case("IdentityFile") {
                let value = trimmed[keyword.len()..].trim();
                let value = value.trim_matches('"').trim_matches('\'');
                return value != key_pattern_tilde && value != key_pattern_abs && value != key_name;
            }

            if keyword.eq_ignore_ascii_case("CertificateFile") {
                let value = trimmed[keyword.len()..].trim();
                let value = value.trim_matches('"').trim_matches('\'');
                return value != cert_pattern_tilde
                    && value != cert_pattern_abs
                    && value != cert_name;
            }

            true
        })
        .collect::<Vec<&str>>()
        .join(line_ending);

    if trailing_newline && !new_content.is_empty() {
        format!("{new_content}{line_ending}")
    } else {
        new_content
    }
}

async fn remove_from_config(paths: &SshPaths, key_name: &str) -> Result<()> {
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
            // `create_new` (O_EXCL) is load-bearing: the PID+nanos temp name is
            // predictable, and without O_EXCL a pre-placed symlink there would redirect
            // this write (open(2), O_EXCL symlink protection).
            #[cfg(unix)]
            {
                use std::io::Write;
                use std::os::unix::fs::OpenOptionsExt;
                let mut file = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&tmp_path)
                    .map_err(|e| {
                        Error::ConfigWriteFailed(format!(
                            "failed to create temp config {}: {e}",
                            tmp_path.display()
                        ))
                    })?;
                file.write_all(final_content.as_bytes()).map_err(|e| {
                    Error::ConfigWriteFailed(format!("failed to write temp config: {e}"))
                })?;
                let _ = file.sync_all();
                drop(file);
            }
            #[cfg(not(unix))]
            {
                use std::io::Write;
                let mut file = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&tmp_path)
                    .map_err(|e| {
                        Error::ConfigWriteFailed(format!(
                            "failed to create temp config {}: {e}",
                            tmp_path.display()
                        ))
                    })?;
                file.write_all(final_content.as_bytes()).map_err(|e| {
                    Error::ConfigWriteFailed(format!("failed to write temp config: {e}"))
                })?;
                let _ = file.sync_all();
                drop(file);
            }
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
